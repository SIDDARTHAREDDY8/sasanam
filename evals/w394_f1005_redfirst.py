#!/usr/bin/env python3
"""Red-first battery for F1005 (proto-chain member reads, no gopd line).

Filed 2026-10-10 by the wave-393 lane-4 spec review as a residual of
the F1002 family: `var p={v:"A"};var o=Object.create(p);o.x="B";`
then `var RESULT=o.v+o.x;` assembles node-exactly via the prototype
chain with no getOwnPropertyDescriptor line; F1002 (CLOSED) requires
the `D=...getOwnPropertyDescriptor(Object.getPrototypeOf(o),...)`
line and misses this simpler variant.

Expected on the OPEN tree: BREAK (the credential is NOT flagged).
After a future closure: FAIL (blocked). Controls per the attack-lane
convention: junk-quiet must stay quiet; the plain fromCharCode twin
must keep blocking.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("f1005-proto-read",
     'var p={v:"%s"};var o=Object.create(p);o.x="%s";var RESULT=o.v+o.x;'
     % (_A, _B)),
    ("f1005-proto-read-40",
     'var p={v:"%s"};var o=Object.create(p);o.x="%s";var RESULT=o.v+o.x;'
     % (_F1, _F2)),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("twin-plain-fcc-blocks",
     "var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);",
     True),
]


def _check(payload, expect_block):
    hit = find_credential(payload) is not None
    return hit == expect_block, hit


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        ok = not hit
        print(("BREAK " if ok else "FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    for name, payload, expect_block in CONTROLS:
        ok, hit = _check(payload, expect_block)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
