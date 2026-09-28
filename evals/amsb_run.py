"""AMSB benchmark run: graft the OWASP-style adapter + scoring harness onto
the governed tree's MemoryFirewall and grade it honestly.

Usage:
  TMPDIR=/tmp/gov-amsb ~/workspace/.gov-venv/bin/python evals/amsb_run.py
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-amsb2 ~/workspace/.gov-venv/bin/python evals/amsb_run.py

Runs every scenario TWICE (determinism check), writes a JSON scorecard and
a human-readable text scorecard under evals/artifacts/amsb/, and prints the
text scorecard to stdout.

Product code is untouched: this evaluates gov/ as a black box through the
public tool seam.
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evals.amsb_adapter import GovMemoryAdapter  # noqa: E402
from evals.amsb_corpus import attack_corpus, benign_corpus  # noqa: E402
from evals.amsb_harness import (run_scenario, score, scorecard_json,
                                scorecard_text)  # noqa: E402

# Scenarios whose payload is instruction-shaped per the product's own
# detector -- used for the strict D-ceiling criterion.
INSTRUCTION_SHAPED_IDS = {
    "delayed-verbatim-directive",
    "delayed-paraphrase-shaped",
    "a4-flood-evicts-poison",   # the FLOOD is instruction-shaped
    "h26-shaped-junk",
    "a1-default-off",
    "imperative-tainted",
    "session-open-flag",
    "unknown-tier-shaped",
}


def main() -> int:
    scenarios = attack_corpus() + benign_corpus()
    scratch = tempfile.mkdtemp(prefix="amsb-")
    all_results = []
    for round_no in (1, 2):
        round_results = []
        for sc in scenarios:
            res = run_scenario(sc, scratch)
            round_results.append(res)
        all_results.append(round_results)
        print("round %d: %d scenarios" % (round_no, len(round_results)),
              flush=True)

    # determinism: identical defended/breached verdicts across rounds
    for a, b in zip(all_results[0], all_results[1]):
        assert (a.scenario_id == b.scenario_id
                and a.defended == b.defended
                and a.breached == b.breached), (
            "NONDETERMINISTIC: %s round1=(%s,%s) round2=(%s,%s)" % (
                a.scenario_id, a.defended, a.breached,
                b.defended, b.breached))
    print("determinism: OK (2 rounds, identical verdicts)")

    results = all_results[0]
    card = score(results, INSTRUCTION_SHAPED_IDS)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path("evals/artifacts/amsb")
    outdir.mkdir(parents=True, exist_ok=True)
    payload = scorecard_json(card, results, GovMemoryAdapter.name,
                             GovMemoryAdapter.version,
                             GovMemoryAdapter.self_submission)
    payload["generated_at"] = stamp
    payload["determinism_rounds"] = 2
    payload["banner_aware_judgment"] = (
        "bannered delivery with a chained memory_provenance_warning counts "
        "as DEFENDED (documented p3 containment); only silent delivery "
        "counts as BREACH")
    (outdir / ("scorecard-%s.json" % stamp)).write_text(
        json.dumps(payload, indent=2))

    text = scorecard_text(card, "AMSB memory-guard scorecard (%s)" % stamp)
    detail = ["", "per-scenario:"]
    for r in results:
        detail.append(
            "  %-28s %-8s %-9s defended=%s breached=%s tier=%s banner=%s "
            "quar=%s warn=%d flags=%d%s" % (
                r.scenario_id, r.severity, r.category, r.defended,
                r.breached, r.ledger_tier, r.bannered, r.quarantined,
                r.warning_events, r.session_flags,
                ("  NOTE: " + r.notes) if r.notes else ""))
    text += "\n".join(detail) + "\n"
    (outdir / ("scorecard-%s.txt" % stamp)).write_text(text)
    print(text)
    print("wrote evals/artifacts/amsb/scorecard-%s.{json,txt}" % stamp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
