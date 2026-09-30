#!/usr/bin/env python3
"""W245-7 / W246-11 regression pin: decision-packet signature discipline
vs the probityai/agent-evidence-vectors `vectors-receipt-signature` corpus.

Runs the corpus's own harness (packaging/agent_evidence_vectors/
receiptsignature.py) with our draft-03 verifier adapter
(evals/w245_packet_conformance_verifier.py -- built on the product
primitive gov/ed25519.py plus a from-spec RFC 8785 canonicalizer) and
asserts the full corpus passes.

The corpus lives OUTSIDE this repo. Set AEV_CORPUS_DIR to the
agent-evidence-vectors checkout (v0.15.0) to run; otherwise this probe
records a skip -- it never fails closed on a missing external corpus.

Baseline recorded 2026-09-30 (wave-245 lane 7): 13/13 vectors PASS on
v0.13.0, 0 not-honouring, 0 fail.
Baseline recorded 2026-09-30 (wave-246 lane 11): 25/25 vectors PASS on
v0.15.0 (50/50 member x pass judgments), 0 not-honouring, 0 fail --
including the Section 6.7 chain-link members (chain_link_mismatch on the
wrong-previous-receipt member), the Section 6.6 signing-input family
(empty/null/string signature members refused), and the two gap members
answered with the draft's verdicts (RS-G-001 revocation, RS-G-002
commitment timing).
"""

import json
import os
import subprocess
import sys

EXPECTED_PASS = 25
EXPECTED_VECTORS = 25


def main():
    corpus_dir = os.environ.get("AEV_CORPUS_DIR")
    if not corpus_dir or not os.path.isdir(corpus_dir):
        print("SKIP: AEV_CORPUS_DIR not set or not a directory "
              "(external corpus not present)")
        return 0
    harness = os.path.join(
        corpus_dir, "packaging", "agent_evidence_vectors", "receiptsignature.py")
    suite = os.path.join(corpus_dir, "vectors-receipt-signature")
    here = os.path.dirname(os.path.abspath(__file__))
    verifier = os.path.join(here, "w245_packet_conformance_verifier.py")
    for path in (harness, suite, verifier):
        if not os.path.exists(path):
            print("SKIP: missing %s" % path)
            return 0
    report_path = os.path.join(
        os.environ.get("TMPDIR", "/tmp"), "w245-conformance-report.json")
    proc = subprocess.run(
        [sys.executable, harness, suite,
         "--verifier", "%s %s" % (sys.executable, verifier),
         "--report", report_path],
        capture_output=True, text=True, timeout=300)
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        print("FAIL: no readable harness report: %s" % (exc,))
        return 1
    totals = report.get("totals", {})
    passed = totals.get("pass")
    vectors = totals.get("vectors")
    failed = totals.get("fail")
    print("corpus pass rate: %s/%s (fail=%s)" % (passed, vectors, failed))
    if vectors != EXPECTED_VECTORS or passed != EXPECTED_PASS or failed:
        print("FAIL: expected %d/%d PASS, 0 fail" % (EXPECTED_PASS, EXPECTED_VECTORS))
        for row in report.get("vectors", []):
            if row.get("status") != "PASS":
                print("  %s %s: %s" % (row.get("id"), row.get("status"),
                                       row.get("reasons")))
        return 1
    print("HELD: %d/%d vectors PASS" % (passed, vectors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
