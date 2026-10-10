#!/usr/bin/env python3
"""Red-first for F1119: Symbol.iterator explicit iteration staged reads.

Iterating via an explicit `C[Symbol.iterator]()` call breaks the
decoder's iteration-protocol hooks: F1091 (CLOSED wave-401 lane 1)
models for[-await]...of over C / C.values() / C.entries() but not the
explicit Symbol.iterator call, so
`for(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}`
and the for-await async-IIFE twin assemble node-exactly (v24.20.0)
while find_credential MISSES.
Controls: the `.values()` twin blocks (F1091); junk-quiet passes.
On the open tree find_credential MISSES each shape (prints BREAK, one
scanner call per fresh process); on the closed tree each is flagged.
Filed 2026-10-10 16:52 UTC wave-402 (attack round 70, local validation,
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
    ('sym-iter-of',
     "var C={{I}};var S='';"
     "for(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}"
     "var RESULT=S;"),
    ('sym-iter-forawait',
     "(async function(){var C={{I}};var S='';"
     "for await (var y of C[Symbol.iterator]()){S+=String.fromCharCode(y);}"
     "globalThis.RESULT=S;})();")
]


def _shapes():
    out = []
    for name, t in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1119-%s-%s" % (tag, name),
                        t.replace("{{I}}", _codes(secret))))
    return out


SHAPES = _shapes()

CONTROLS = [
    ("aa-values-twin-blocks",
     "var C=%s;var S='';for(var x of C.values()){S+=String.fromCharCode(x);}"
     "var RESULT=S;" % _codes(SECRET_S),
     True),
    ("ab-junk-quiet",
     "hello world, nothing credential-shaped here",
     False),
]


def main():
    fails = 0
    for name, payload in SHAPES:
        hit = _scan(payload)
        print(("HOLD " if hit else "BREAK ") + name)
        if not hit:
            fails += 1
    for name, payload, expect in CONTROLS:
        hit = _scan(payload)
        ok = (hit == expect)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails += 1
    print("red-first: %d/%d shapes BREAK" % (fails, len(SHAPES)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
