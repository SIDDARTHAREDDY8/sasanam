#!/usr/bin/env python3
"""Red-first wrapper for F1254: fromCharCode.apply with derived array.

Delegates to the canonical attack-round-76 red-first battery
(evals/w408_f1254_redfirst.py, cited in the FINDINGS.md entry).
Prints BREAK for each filed shape on the open tree (exit 0);
any HIT/FAIL or control failure exits nonzero. Capture via
Python subprocess only (wave-392 lesson).
"""
import os
import runpy
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    path = os.path.join(REPO_ROOT, "evals", "w408_f1254_redfirst.py")
    ns = runpy.run_path(path, run_name="__w408_f1254__")
    rc = ns["main"]()
    print("w409_f1254_redfirst: delegated rc=%d" % rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
