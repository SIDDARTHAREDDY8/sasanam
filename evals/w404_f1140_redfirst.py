#!/usr/bin/env python3
"""Red-first for F1140 (wave-404 lane 4): for-loop header variants.

the F1074-family hooks anchor on the exact `for(var i=0;i<C.length;i++)` header: cached-length (`n`), empty init, empty update, and post-increment-in-index variants assemble node-exactly (v24.20.0) while find_credential MISSES (`++i`, `i+=1`, `let` twins block). 8 shapes verified (4 productions, short + 40-char).
On the open tree find_credential MISSES each shape (prints BREAK, one
scanner call per fresh process); on the closed tree each is flagged.
Filed 2026-10-10 18:13 UTC wave-403 (attack round 71, local validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
Closure verification (wave-404 lane 4, 2026-10-10): prints BREAK on
the open tree (via git stash of the lane hooks) and FAIL/blocked on
the closed tree.
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
    ('cached-length',
     "var C={{I}};var S='';for(var i=0,n=C.length;i<n;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ('empty-init',
     "var C={{I}};var S='';var i=0;for(;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ('empty-update',
     "var C={{I}};var S='';for(var i=0;i<C.length;){S+=String.fromCharCode(C[i]);i++;}var RESULT=S;"),
    ('postincr-index',
     "var C={{I}};var S='';for(var i=0;i<C.length;){S+=String.fromCharCode(C[i++]);}var RESULT=S;"),
]


def _shapes():
    out = []
    for name, t in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1140-%s-%s" % (tag, name),
                        t.replace("{{I}}", _codes(secret))))
    return out


SHAPES = _shapes()

_CONTROLS = [
    ('aa-canonical-for-blocks',
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
