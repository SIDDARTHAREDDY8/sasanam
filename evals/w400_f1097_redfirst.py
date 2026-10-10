#!/usr/bin/env python3
"""Red-first for F1097: promise-staged assembly.

Staging the char mapping through `Promise.all(C.map(async ...))`
with a `.then` join breaks the decoder's synchronous assembly
grammars: the credential only materializes inside the promise
continuation. Node resolves it exactly (v24.20.0). On the open tree
find_credential MISSES (prints BREAK, one scanner call per fresh
process); on the closed tree it is flagged. Controls: junk and
honest async text stay quiet.

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


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        out.append(("f1097-%s-promise-all" % tag,
                    "var C=%s;Promise.all(C.map(async function(c)"
                    "{return String.fromCharCode(c);}))"
                    ".then(function(a){globalThis.RESULT=a.join('');});" % _codes(secret)))
    return out


SHAPES = _shapes()

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("honest-async-quiet",
     "async function f(){var x=await Promise.resolve(1);return x;}",
     False),
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
