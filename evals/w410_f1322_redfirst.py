#!/usr/bin/env python3
"""Red-first for F1322 (three-index) -- filed 2026-10-11 07:18 UTC by wave-410
lane 4 Spec review (SOFT findings verified empirically).

Proves the scanner MISSES the shape on the current tree.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _scan(payload):
    try:
        return "HIT" if dlp.find_credential(payload) is not None else "MISS"
    except Exception:
        return "ERR"


SHAPES = [
    ("f1322-s_three-index_short",
     "var C=%s;var {0:x,1:y,2:z,length:l}=C;var S=String.fromCharCode(x,y,z,...C.slice(3));var RESULT=S;" % _codes(SECRET_S)),
    ("f1322-s_three-index_long",
     "var C=%s;var {0:x,1:y,2:z,length:l}=C;var S=String.fromCharCode(x,y,z,...C.slice(3));var RESULT=S;" % _codes(SECRET_L)),
]
_CONTROLS = [
    ("ctrl-ok", "var C=[65,66];var {0:x,1:y,length:l}=C;var S=String.fromCharCode(x,y,...C.slice(2));var RESULT=S;", False),
]



def main():
    n_break, n_fail = 0, 0
    for name, payload in SHAPES:
        v = _scan(payload)
        is_break = (v == "MISS")
        print(("BREAK " if is_break else "FAIL ") + name, flush=True)
        n_break, n_fail = n_break + (1 if is_break else 0), n_fail + (0 if is_break else 1)
    for name, payload, expect_hit in _CONTROLS:
        v = _scan(payload)
        ok = ("HIT" in v) == expect_hit
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            n_fail += 1
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(_CONTROLS), n_fail))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
