#!/usr/bin/env python3
"""w344 red-first: F434 Array.join JS-expression DLP bypass.

Wave-344 merge filed F434 (LOW, OPEN): F430-closure residual. The Array.join
construction ['x','o','x','b','-','a','b','c','1','2','3','d','e','f','4','5','6'].join('')
evaluates to the credential in any JS engine but misses find_credential --
the F430 bounded static JS-expression decoder covers quoted '+' concatenation,
template literals, String.fromCharCode, .concat/.repeat, but not
array-literal + .join.

Expected on the OPEN tree: prints BREAK (F434 is OPEN).
After a closure (decode layer recognizes bounded static array-join
expressions or refuses obfuscation-shaped runs coded): prints HELD.

$0 SPEND BY CONSTRUCTION: canned transforms of a test credential;
no model calls here.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO = os.getcwd()
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402

_CRED = "xoxb-" + "abc123" + "def456"


def _array_join(s):
    parts = ", ".join("'%s'" % ch for ch in s)
    return "[%s].join('')" % parts


def main():
    control = dlp.find_credential(_CRED) == "dlp-slack-token"
    payload = _array_join(_CRED)
    assert _CRED not in payload, "payload smuggles plaintext"
    miss = dlp.find_credential(payload) is None
    print("array-join shape -> %s" % ("MISS" if miss else "HIT"))
    print("control (plain credential blocks) -> %s" % ("HELD" if control else "BROKEN-CONTROL"))
    if miss and control:
        print("BREAK")
        return 1
    print("HELD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
