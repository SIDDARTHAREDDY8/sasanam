#!/usr/bin/env python3
"""Red-first for F1093: getter-chained accumulation reads (wave-401 lane 2).

Filed shapes (round 68): F1075's production with the int array behind a
getter — `var O={get v(){return C;}}` — keeps the `O.v[i]` read syntax
identical while the array is no longer statically present in the object
literal. Also covers the node-verified `O['v']` bracket twin.

Prints BREAK when the scanner misses (open), FAIL when it hits. AA +
junk controls. One find_credential call per fresh subprocess (round-60
false-miss rule). Python-subprocess capture only (wave-392 lesson).
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
        out.append(("f1093-%s-getter-read" % tag,
                    "var C=%s;var O={get v(){return C;}};var S='';"
                    "for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}"
                    "var RESULT=S;" % _codes(secret)))
        out.append(("f1093-%s-getter-bracket" % tag,
                    "var C=%s;var O={get v(){return C;}};var S='';"
                    "for(var i=0;i<O['v'].length;i++){S+=String.fromCharCode(O['v'][i]);}"
                    "var RESULT=S;" % _codes(secret)))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: F1075's data-property twin blocks coded.
    ("aa-f1075-dataprop-blocks",
     "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++)"
     "{S+=String.fromCharCode(O.v[i]);}var RESULT=S;" % _codes(SECRET_S),
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
