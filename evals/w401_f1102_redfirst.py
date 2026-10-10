#!/usr/bin/env python3
"""Red-first for F1102: array-spread object rest source reads.

Spreading an ARRAY (not an object literal or object-typed variable)
into the rest object (`var P={...[c0,c1,...]};`,
`var A=[c0,c1,...];var P={...A};`, read back via
`String.fromCharCode(...Object.values(P))`) assembles node-exactly
(v24.20.0, integer-indexed array elements spread to integer keys, read
back in ascending order) while find_credential MISSES: the F1088 hook
models only object-literal and identifier sources. Each shape is probed
with one find_credential call per fresh process; prints BREAK when the
scanner misses (open tree), FAIL when it flags (closed tree).
Controls: the object-literal spread twin blocks coded (F1088); junk
stays quiet.

Filed 2026-10-10 13:38 UTC (wave-400 lane 2 self-file, renumbered
F1092->F1102 at wave-400 merge per wave-272; local node validation,
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
        c = _codes(secret)
        out.append((
            "f1102-%s-spread-array-lit" % tag,
            "var P={...%s};var S=String.fromCharCode(...Object.values(P));"
            "var RESULT=S;" % c))
        out.append((
            "f1102-%s-spread-array-var" % tag,
            "var A=%s;var P={...A};"
            "var S=String.fromCharCode(...Object.values(P));"
            "var RESULT=S;" % c))
    return out


SHAPES = _shapes()


def _litobj(s):
    return "{" + ",".join("%d:%d" % (i, ord(ch))
                          for i, ch in enumerate(s)) + "}"


CONTROLS = [
    # AA: the object-literal spread twin blocks coded (F1088).
    ("aa-objlit-spread-blocks",
     ("var P={...%s};"
      "var S=String.fromCharCode(...Object.values(P));"
      "var RESULT=S;") % _litobj(SECRET_S), True),
    # AA: the object-typed var-source twin blocks coded (F1088).
    ("aa-objvar-spread-blocks",
     ("var Q=%s;var P={...Q};"
      "var S=String.fromCharCode(...Object.values(P));"
      "var RESULT=S;") % _litobj(SECRET_S), True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = _scan(payload)
        print(("FAIL " if hit else "BREAK ") + name)
        if hit:
            fails.append(name)
    for name, payload, expect_block in CONTROLS:
        hit = _scan(payload)
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL"
          % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
