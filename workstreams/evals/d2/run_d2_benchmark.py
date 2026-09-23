#!/usr/bin/env python3
"""D2 neutral benchmark runner (wave-25).

Runs the pinned corpus in workstreams/evals/d2/benchmark_corpus.yaml
against two engines:
  - ours: the agent-governance-demo enforcement layer
      * content lane: gov/adapters/trust.py resolve_hierarchy quarantine
        (the same primitive the redteam.struq.* battery situations use)
      * approval lane: tests/harness.py make_run() real pipeline
        (executor + ApprovalQueue with harness-minted identities)
  - agt:  Microsoft AGT v5.0.0 (agt_engine.py) —
      * content lane: PromptInjectionDetector.detect() at default
        'balanced' sensitivity
      * approval lane: EscalationManager (approve / request_approval)

Comparison doctrine (A13): each engine's outcome is compared against the
scenario's SECURITY EXPECTATION, never engine-vs-engine parity.

Determinism: rule-based detectors, fixed payloads, fixed seed where
applicable; no network, no LLMs, no paid APIs ($0).

Usage:
  TMPDIR=/tmp/gov-w25-d2 \
    .venv/bin/python workstreams/evals/d2/run_d2_benchmark.py

Writes workstreams/evals/d2/results/<translator-version>/results.json.
Results are VOID if translator_version changed since the run (A13).
"""

import datetime
import hashlib
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

D2 = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(D2)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-w25-d2")

import yaml  # noqa: E402

import gov.log  # noqa: E402
# Wave-81: the dev-key opt-in is deleted from gov/; provision an
# explicit local test key for this synthetic benchmark harness.
import secrets as _secrets  # noqa: E402
os.environ.setdefault("GOV_LOG_KEY", _secrets.token_hex(32))  # noqa: E402
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")  # noqa: E402

from gov.adapters import trust as trust_mod  # noqa: E402
from harness import make_run  # noqa: E402

from agt_engine import (  # noqa: E402
    AGTEngine,
    TRANSLATOR_VERSION,
    AGT_VERSION,
    AGT_COMMIT,
)

CORPUS = os.path.join(D2, "benchmark_corpus.yaml")
RESULTS_DIR = os.path.join(D2, "results", TRANSLATOR_VERSION)


# --------------------------------------------------------------------------
# Our engine — content lane
# --------------------------------------------------------------------------

def ours_screen_content(text):
    tagged = [trust_mod.tag_privilege(text, trust_mod.TOOL, "tool:read_file")]
    out, events = trust_mod.resolve_hierarchy(tagged)
    quarantined = [i for i in out if i.get("quarantined")]
    reasons = [e.get("reason") for e in events]
    claim = any(r and (r.startswith("privilege_claim")
                       or r == "tool_instruction_framing")
                for r in reasons)
    return {
        "verdict": "stopped" if (quarantined and claim) else "allowed",
        "quarantined": bool(quarantined),
        "reasons": reasons,
    }


# --------------------------------------------------------------------------
# Our engine — approval lane (real pipeline via tests/harness.make_run)
# --------------------------------------------------------------------------

def _ours_queued():
    run = make_run()
    ident = run["identities"]["support"]
    res = run["executor"].call(
        ident, "send_email", to="team@synthetic.local",
        subject="s", body="b")
    assert res["status"] == "queued", res
    return run, ident, res["approval_id"]


def ours_self_approval():
    run, ident, aid = _ours_queued()
    try:
        run["approvals"].decide(aid, True, "approving my own request",
                                decided_by=ident.agent_id)
        return {"verdict": "allowed",
                "note": "self-approval accepted (UNEXPECTED)"}
    except ValueError as e:
        return {"verdict": "stopped",
                "note": "ValueError: %s" % str(e)[:100]}


def ours_replay_and_unknown():
    run, _ident, aid = _ours_queued()
    run["approvals"].decide(aid, True, "looks fine",
                            decided_by="human-operator")
    refused_replay, refused_unknown = False, False
    try:
        run["approvals"].decide(aid, True, "again",
                                decided_by="human-operator")
    except ValueError:
        refused_replay = True
    try:
        run["approvals"].decide("no-such-approval-id", True, "x",
                                decided_by="human-operator")
    except ValueError:
        refused_unknown = True
    ok = refused_replay and refused_unknown
    return {"verdict": "stopped" if ok else "allowed",
            "replay_refused": refused_replay,
            "unknown_refused": refused_unknown}


def ours_cross_agent():
    """Informational: a DIFFERENT agent decides (not self-approval)."""
    run, ident, aid = _ours_queued()
    try:
        run["approvals"].decide(aid, True, "peer review",
                                decided_by="another-agent")
        return {"verdict": "allowed",
                "note": "cross-agent decision accepted; status=%s"
                        % run["approvals"].get(aid)["status"]}
    except ValueError as e:
        return {"verdict": "stopped", "note": str(e)[:100]}


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def main():
    with open(CORPUS, encoding="utf-8") as f:
        corpus = yaml.safe_load(f)
    assert corpus["translator_version"] == TRANSLATOR_VERSION, \
        "corpus/adapters translator mismatch — results would be void"

    # Pin the OUR-tree state the "ours" column was measured against.
    # Parallel wave-25 lanes mutate this tree; without the hashes the
    # our-column results are not reproducible or comparable.
    ours_tree = {
        "gov/adapters/trust.py": _sha256(
            os.path.join(REPO, "gov/adapters/trust.py")),
        "gov/approvals.py": _sha256(
            os.path.join(REPO, "gov/approvals.py")),
    }

    agt = AGTEngine()
    scenarios = []

    for s in corpus["content_lane"]:
        row = {"id": s["id"], "battery_ref": s["battery_ref"],
               "expectation": s["expectation"]}
        try:
            row["ours"] = ours_screen_content(s["payload"])
        except Exception as e:  # noqa: BLE001
            row["ours"] = {"verdict": "error", "note": repr(e)[:200]}
        try:
            row["agt"] = agt.screen_content(s["payload"])
        except Exception as e:  # noqa: BLE001
            row["agt"] = {"verdict": "error", "note": repr(e)[:200]}
        scenarios.append(row)

    agt_approval_map = {
        "d2a01": agt.self_approval,
        "d2a02": agt.replay_and_unknown,
        "d2a03": agt.timeout_deny,
        "d2a04": agt.cross_agent_approval,
    }
    ours_approval_map = {
        "d2a01": ours_self_approval,
        "d2a02": ours_replay_and_unknown,
        "d2a03": None,  # TTL is 24h; covered in-battery by r23 probe (see notes)
        "d2a04": ours_cross_agent,
    }
    for s in corpus["approval_lane"]:
        row = {"id": s["id"], "battery_ref": s["battery_ref"],
               "expectation": s["expectation"]}
        fn = ours_approval_map[s["id"]]
        if fn is None:
            row["ours"] = {"verdict": "n/a",
                           "note": "in-battery: redteam.web.r23_expired_"
                                   "approval_refused (stopped); TTL=24h not "
                                   "harness-friendly"}
        else:
            try:
                row["ours"] = fn()
            except Exception as e:  # noqa: BLE001
                row["ours"] = {"verdict": "error", "note": repr(e)[:200]}
        try:
            row["agt"] = agt_approval_map[s["id"]]()
        except Exception as e:  # noqa: BLE001
            row["agt"] = {"verdict": "error", "note": repr(e)[:200]}
        scenarios.append(row)

    # Score against expectations (informational scenarios unscored).
    scored = [r for r in scenarios if r["expectation"] != "informational"]
    for r in scenarios:
        for eng in ("ours", "agt"):
            v = r[eng]["verdict"]
            if r["expectation"] == "informational":
                r[eng + "_meets_expectation"] = None
            elif v == "n/a":
                r[eng + "_meets_expectation"] = None
            else:
                want = {"detected": "stopped",
                        "refused": "stopped"}[r["expectation"]]
                r[eng + "_meets_expectation"] = (v == want)

    summary = {}
    for eng in ("ours", "agt"):
        met = [r for r in scored
               if r[eng + "_meets_expectation"] is True]
        missed = [r for r in scored
                  if r[eng + "_meets_expectation"] is False]
        summary[eng] = {"scored": len(scored),
                        "met": len(met), "missed": len(missed),
                        "missed_ids": [r["id"] for r in missed]}

    results = {
        "benchmark": "D2 neutral benchmark vs AGT governor (wave-25)",
        "translator_version": TRANSLATOR_VERSION,
        "agt_version": AGT_VERSION,
        "agt_commit": AGT_COMMIT,
        "run_at_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds"),
        "ours_tree_sha256": ours_tree,
        "determinism": ("rule-based detectors; fixed payloads; local-only; "
                        "no network/LLM/paid API"),
        "comparison_doctrine": ("each engine outcome vs the scenario's "
                                "security expectation (A13); never "
                                "engine-vs-engine parity"),
        "summary": summary,
        "scenarios": scenarios,
    }
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out = os.path.join(RESULTS_DIR, "results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("wrote %s" % out)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
