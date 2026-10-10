#!/usr/bin/env python3
"""Red-first for F1123: whole-text anchoring of statement decoders.

statement-sequence decoders anchor to whole-text boundaries -- any leading statement (`var x=1;`, `;`, a comment), any trailing statement, or a single wrapper level (`{...}`, `if(true){...}`, a label, a function declaration + call, an arrow IIFE, `do...while(false)`, `try...catch`) breaks every decoder hook: the canonical blocked accumulation assembles node-exactly (v24.20.0) while find_credential MISSES. 22 shapes verified (11 productions, short + 40-char).
On the open tree (base 61e348092) find_credential MISSES each shape (prints BREAK, one
scanner call per fresh process); on the closed tree each is flagged (prints FAIL).
Filed 2026-10-10 18:13 UTC wave-403 (attack round 71, local validation,
$0.00 model spend (0 paid calls)). Closed wave-404 lane 1 by
_js_f1123_unwrap (single-wrapper-level unwrap as a _decode_layer
candidate; layer-2 runs all statement decoders on it).
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
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


_TMPLS = [
    ('lead-var',
     "var x=1;var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ('lead-empty',
     ";var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ('lead-comment',
     "/*c*/var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ('trail-var',
     "var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;var z=2;"),
    ('block',
     "{var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;}"),
    ('if-wrap',
     "if(true){var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;}"),
    ('label',
     "lbl:var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ('function-decl',
     "function g(){var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}return S;}var RESULT=g();"),
    ('arrow-iife',
     "var RESULT=(()=>{var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}return S;})();"),
    ('do-while-false',
     "do{var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;}while(false);"),
    ('try-catch',
     "try{var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;}catch(e){}"),
]


def _shapes():
    out = []
    for name, t in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1123-%s-%s" % (tag, name),
                        t.replace("{{I}}", _codes(secret))))
    return out


SHAPES = _shapes()

_CONTROLS = [
    ('aa-canonical-blocks',
     "var C={{I}};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;",
     True),
    ('junk-quiet',
     "(function(){var s='ab';return s;})()",
     False),
]


def _cshapes():
    out = []
    for name, t, _ in _CONTROLS:
        out.append((name, t.replace("{{I}}", _codes(SECRET_S))))
    return out


CONTROLS = _cshapes()


def main():
    fails = []
    for name, payload in SHAPES:
        v = _scan(payload)
        hit = (v == "HIT")
        bad = hit or v == "ERR"
        print(("FAIL " if bad else "BREAK ") + name, flush=True)
        if bad:
            fails.append(name)
    for (name, _t, expect_block), (_cn, payload) in zip(_CONTROLS, CONTROLS):
        v = _scan(payload)
        hit = (v == "HIT")
        ok = (hit == expect_block) and v != "ERR"
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
