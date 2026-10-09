#!/usr/bin/env python3
"""Red-first for F829: undefined helper escapes find_credential as NameError.

F829 (filed 2026-10-09 05:41 UTC, wave-386 lane 2 spec-axis review catch):
_js_parse_f659_yield_star_array is CALLED at gov/dlp.py:5015 but never
DEFINED -- find_credential raises NameError on yield*-array shapes instead
of failing closed. Pre-existing on the wave-385 base, not a lane
regression.

On the open tree this prints RAISED (the bug); after the fix it must
print HELD (fail closed) or decode node-exactly.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential  # noqa: E402

SHAPE = ("(function(){function* b(){yield* ['f1','f2'];}var it=b();"
         "return it.next().value+it.next().value;})()")


def main():
    try:
        r = find_credential(SHAPE)
    except NameError as e:
        print("f829-shape: RAISED NameError (%s)" % e)
        print("tally: 1 RAISED / 0 HELD")
        return 0
    except Exception as e:  # noqa: BLE001 -- loud, never silent
        print("f829-shape: RAISED %r" % e)
        print("tally: 1 RAISED / 0 HELD")
        return 0
    print("f829-shape: HELD (returned %r, no exception)" % (r,))
    print("tally: 0 RAISED / 1 HELD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
