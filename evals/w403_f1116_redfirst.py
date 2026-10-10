#!/usr/bin/env python3
"""Red-first for F1116: reorder-staged accumulation reads.

Reordering the int array before assembly breaks the decoder's
order-anchored hooks: `R=C.slice().reverse()` then
`String.fromCharCode(...R.reverse())`, or a backwards loop over the
reversed copy, both assemble node-exactly (v24.20.0) while
find_credential MISSES. Controls: the plain `...[...C]` copy-spread twin
blocks; junk-quiet passes.
On the open tree find_credential MISSES each shape (prints BREAK, one
scanner call per fresh process); on the closed tree each is flagged.
Filed 2026-10-10 16:45 UTC wave-402 (attack round 70, local validation,
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


def _nested(s):
    return "[" + ",".join("[%d]" % ord(c) for c in s) + "]"


_TMPLS = [
    ('double-reverse',
     'var C={{I}};var R=C.slice().reverse();var S=String.fromCharCode(...R.reverse());var RESULT=S;'),
    ('reverse-backloop',
     "var C={{I}};var R=C.slice().reverse();var S='';for(var i=R.length-1;i>=0;i--){S+=String.fromCharCode(R[i]);}var RESULT=S;")
]


def _shapes():
    out = []
    for name, t in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1116-%s-%s" % (tag, name),
                        t.replace("{{I}}", _codes(secret))
                         .replace("{{N}}", _nested(secret))))
    return out


SHAPES = _shapes()

CONTROLS = [
    ("aa-plain-ident-loop-blocks",
     "var C=%s;var S='';for(var i=0;i<C.length;i++)"
     "{S+=String.fromCharCode(C[i]);}var RESULT=S;" % _codes(SECRET_S),
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
