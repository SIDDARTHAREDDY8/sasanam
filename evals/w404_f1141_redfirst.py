#!/usr/bin/env python3
"""Red-first for F1141 (wave-404 lane 4): F1119 residual -- trailing statements after the IIFE.

The F1119 hook (_js_f1119_stmt_decode) requires end-of-text after the async
IIFE, but the filed w402 shape has a trailing `var RESULT='';` statement.
Node assembles the credential into globalThis.__R70 node-exactly while
find_credential MISSES.

On the open tree find_credential MISSES each shape (prints BREAK, one
scanner call per fresh process); on the closed tree each is flagged.
Filed 2026-10-10 19:30 UTC wave-403 (merge red-first audit, $0.00 model
spend (0 paid calls)). Prints BREAK on the open tree.
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
    ('trailing-var-result',
     "(async()=>{var C={{I}};var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.__R70=S;})();var RESULT='';"),
    ('trailing-var-result-func',
     "(async function(){var C={{I}};var S='';for await(var y of C[Symbol.iterator]()){S+=String.fromCharCode(y);}globalThis.RESULT=S;})();var RESULT='';"),
]


def _shapes():
    out = []
    for name, t in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1141-%s-%s" % (tag, name),
                        t.replace("{{I}}", _codes(secret))))
    return out


SHAPES = _shapes()

CONTROLS = [
    ("aa-no-trailing-blocks",
     "(async()=>{var C=%s;var S='';for await(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}globalThis.RESULT=S;})();" % _codes(SECRET_S),
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
