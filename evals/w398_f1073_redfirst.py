#!/usr/bin/env python3
"""Red-first for F1073 (wave-398 lane 3, closure verification).

Re-runs the filed shapes from evals/w397_f1073_redfirst.py and asserts
the CLOSED state: every filed carrier must ROUTE to approval (no
BREAK) and the F1024 control must still route. Capture via Python
subprocess only (wave-392 lesson).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.instruction_provenance import (  # noqa: E402
    ActionRequest,
    IngressLabeler,
    Label,
    grant_check,
)
from w397_f1073_redfirst import SHAPES, CONTROLS  # noqa: E402


def _wired(email_body):
    lab = IngressLabeler()
    unit = lab.ingest(email_body, Label.RETRIEVED_UNTRUSTED,
                      carrier="inbox-msg#9(public)")
    req = ActionRequest(action="wire_transfer",
                        args={"to_account": "987654321", "amount": 48200},
                        consequential=True,
                        driving_units=[unit.unit_id])
    d = grant_check(req, lab)
    return d.routed_to_approval


def main():
    fails = []
    for name, body in SHAPES:
        routed = _wired(body)
        print(("HELD  " if routed else "BREAK ") + name)
        if not routed:
            fails.append(name)
    for name, body, expect_routed in CONTROLS:
        routed = _wired(body)
        ok = routed == expect_routed
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES),
                                              len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
