#!/usr/bin/env python3
"""Red-first for F1090: higher-order method staged assembly.

Seven productions that stage credential assembly through an
Array.prototype higher-order method over the int array, breaking the
decoder's statement-anchored hook grammars: reduce (function + arrow),
flatMap+join, map+join, reduceRight, forEach side-effect, every
side-effect. On the open tree find_credential MISSES each shape
(prints BREAK, one scanner call per fresh process); on the closed
tree each is flagged. Controls: the Array.from mapFn twin blocks
(F1057 holds); junk stays quiet.

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
    ("reduce-fn",
     "var C={I};var S=C.reduce(function(a,c){{return a+String.fromCharCode(c);}},{e});var RESULT=S;"),
    ("reduce-arrow",
     "var C={I};var S=C.reduce((a,c)=>a+String.fromCharCode(c),{e});var RESULT=S;"),
    ("flatmap-join",
     "var C={I};var S=C.flatMap(function(c){{return [String.fromCharCode(c)];}}).join({e});var RESULT=S;"),
    ("map-join",
     "var C={I};var S=C.map(function(c){{return String.fromCharCode(c);}}).join({e});var RESULT=S;"),
    ("reduceRight",
     "var C={I};var S=C.reduceRight(function(a,c){{return String.fromCharCode(c)+a;}},{e});var RESULT=S;"),
    ("forEach-sidefx",
     "var C={I};var S={e};C.forEach(function(c){{S+=String.fromCharCode(c);}});var RESULT=S;"),
    ("every-sidefx",
     "var C={I};var S={e};C.every(function(c){{S+=String.fromCharCode(c);return true;}});var RESULT=S;"),
]


def _shapes():
    out = []
    for name, tmpl in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1090-%s-%s" % (tag, name),
                        tmpl.format(I=_codes(secret), e="''")))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: Array.from with mapFn is modeled (F1057) -- blocks coded.
    ("aa-arrayfrom-mapfn-blocks",
     "var C=%s;var S=Array.from(C,function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % _codes(SECRET_S),
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
