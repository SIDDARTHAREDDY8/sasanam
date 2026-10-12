#!/usr/bin/env python3
"""Red-first battery for F1860 (trimend-leading-pad): wave-433 attack round 101.

Prints BREAK if the scanner MISSES the filed shape on the open tree
(genuine detection gap), HELD otherwise. Genuine {I} templates.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w433_f1860_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-" + "0123456789abcde"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TEMPLATE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '.repeat(3)+T).trimStart().trimEnd();var RESULT=U;"

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


def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"


def main():
    # Filed shape must MISS on the open tree (genuine gap)
    misses = 0
    for secret in (SECRET_S, SECRET_L):
        payload = TEMPLATE.replace("{I}", _codes(secret))
        if _scan(payload) == "MISS":
            misses += 1
    # Junk-quiet: unrelated text stays quiet
    junk_hit = _scan("The quick brown fox jumps over the lazy dog.") == "HIT"
    # Direct control must HIT
    ctrl = "var C=" + _codes(SECRET_S) + ";var S=String.fromCharCode.apply(null,C);var RESULT=S;"
    ctrl_hit = _scan(ctrl) == "HIT"
    if misses == 2 and not junk_hit and ctrl_hit:
        print("BREAK")
    else:
        print("HELD (misses=%d/2 junk_hit=%s ctrl_hit=%s)" % (misses, junk_hit, ctrl_hit))


if __name__ == "__main__":
    main()
