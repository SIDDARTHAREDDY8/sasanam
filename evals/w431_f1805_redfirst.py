#!/usr/bin/env python3
"""Red-first battery for F1805 (repeat-computed-count) — wave-431 attack round 99.

Asserts the filed shape MISSES on the open tree (BREAK), node confirms
assembly, junk stays quiet, direct control HITs.
Genuine {I} templates. Python subprocess capture only.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w431_f1805_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-" + "0123456789abcde"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TEMPLATE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length-C.length+1);var RESULT=U;"

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _node_ok(payload, secret):
    cmd = ["node", "-e",
           payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"]
    nc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


def main():
    fails = []
    # filed shapes must BREAK (node=True, scan=MISS) on both sizes
    for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
        payload = TEMPLATE.replace("{I}", _codes(secret))
        node = _node_ok(payload, secret)
        scan = _scan(payload) if node else "SKIP"
        if not (node and scan == "MISS"):
            fails.append("filed-%s: node=%s scan=%s" % (tag, node, scan))
    # junk stays quiet
    junk = _scan("var x = 'hello world'; var y = 42;")
    if junk != "MISS":
        fails.append("junk: %s" % junk)
    # direct control HITs
    ctrl = "var C=%s;var S=String.fromCharCode.apply(null,C);" % _codes(SECRET_S)
    if _scan(ctrl) != "HIT":
        fails.append("control not HIT")
    if fails:
        print("FAIL")
        for f in fails:
            print("  " + f)
        sys.exit(1)
    print("HELD")


if __name__ == "__main__":
    main()
