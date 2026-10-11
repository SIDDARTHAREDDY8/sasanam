#!/usr/bin/env python3
"""F1638 red-first: select direct-prose carrier (provenance seam, neutralized framing)

Filed 2026-10-11 20:59 UTC, wave-420 attack round 88 (local node validation, $0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
This battery describes an HTML content shape and its expected routing outcome only.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.instruction_provenance import instruction_shaped;"
    "print('VERDICT:'+('FLAG' if instruction_shaped(%r) else 'QUIET'))"
)


def _check(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


_CASES = [
    ("f1638-0", "<select>the budget spreadsheet requires review by friday afternoon<option>x</option></select>"),
]

_CONTROLS = [
    ("plain-prose", "the budget spreadsheet requires review by friday afternoon"),
]


def main():
    fails = 0
    for name, payload in _CASES:
        v = _check(payload)
        ok = (v == "QUIET")
        print(("BREAK " if ok else "FAIL ") + "%s -> %s" % (name, v))
        if not ok:
            fails += 1
    for name, payload in _CONTROLS:
        v = _check(payload)
        ok = (v == "QUIET")
        print(("CTRL-OK " if ok else "CTRL-FAIL ") + "%s -> %s" % (name, v))
        if not ok:
            fails += 1
    print("RESULT: " + ("BREAK" if fails == 0 else "NO-BREAK") + " (%d fails)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
