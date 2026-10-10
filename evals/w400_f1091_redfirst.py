#!/usr/bin/env python3
"""Red-first for F1091: iteration-protocol staged assembly.

Five productions that stage credential assembly through the iteration
protocol over the int array, breaking the decoder's index-anchored
accumulation grammars: for-await over the array, values()-iterator
for-of, entries() destructured for-of, for-await over entries(), and
spread of the values() iterator into fromCharCode. On the open tree
find_credential MISSES each shape (prints BREAK, one scanner call per
fresh process); on the closed tree each is flagged. Controls: plain
for-of over the array blocks; plain-identifier fromCharCode.apply
twin blocks; junk stays quiet.

Filed 2026-10-10 13:29 UTC wave-400 (attack round 68, local validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
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

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "print('HIT' if find_credential(%r) else 'MISS')"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    lines = (r.stdout or "").strip().split("\n")
    return lines[-1] == "HIT" if lines and lines[-1] else False


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


_TMPLS = [
    ("forawait",
     "(async function(){{var C={I};var S={e};for await (var x of C){{S+=String.fromCharCode(x);}}globalThis.RESULT=S;}})();"),
    ("values-forof",
     "var C={I};var it=C.values();var S={e};for(var x of it){{S+=String.fromCharCode(x);}}var RESULT=S;"),
    ("entries-destr",
     "var C={I};var S={e};for(var [i,c] of C.entries()){{S+=String.fromCharCode(c);}}var RESULT=S;"),
    ("forawait-entries",
     "(async function(){{var C={I};var S={e};for await (var [i,c] of C.entries()){{S+=String.fromCharCode(c);}}globalThis.RESULT=S;}})();"),
    ("spread-values-iter",
     "var C={I};var S=String.fromCharCode(...C.values());var RESULT=S;"),
]


def _shapes():
    out = []
    for name, tmpl in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1091-%s-%s" % (tag, name),
                        tmpl.format(I=_codes(secret), e="''")))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: plain for-of over the int array is modeled -- blocks coded.
    ("aa-plain-forof-blocks",
     "var C=%s;var S='';for(var x of C){S+=String.fromCharCode(x);}var RESULT=S;" % _codes(SECRET_S),
     True),
    # AA: plain-identifier fromCharCode.apply twin blocks coded.
    ("aa-fcc-apply-blocks",
     "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;" % _codes(SECRET_S),
     True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = _scan(payload)
        print(("FAIL " if hit else "BREAK ") + name, flush=True)
        if hit:
            fails.append(name)
    for name, payload, expect_block in CONTROLS:
        hit = _scan(payload)
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
