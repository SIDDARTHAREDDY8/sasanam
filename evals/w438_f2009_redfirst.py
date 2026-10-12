#!/usr/bin/env python3
"""Red-first battery for F2009 (g5) - wave-438 attack round 106.

Prints BREAK if the scanner MISSES the filed shape on the open tree.
Genuine {I} template; junk-quiet control included.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w438_f2009_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET="xoxb-aaaa-bbbb-ccccc"

TEMPLATE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.charAt(4)==='-'){U=T;}else{U='';}var RESULT=U;"

def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"

def _scan(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.dlp import find_credential;"
        "r=find_credential(" + repr(payload) + ");"
        "print('VERDICT:'+('HIT' if r else 'MISS'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

def main():
    payload = TEMPLATE.replace("{I}", _codes(SECRET))
    v = _scan(payload)
    jv = _scan("the quick brown fox jumps over the lazy dog")
    print("F2009 filed-shape: %s (junk-quiet: %s)" % (v, jv))
    if v == "MISS" and jv == "MISS":
        print("BREAK")
    elif v == "HIT":
        print("HELD")
    else:
        print("ERROR")

if __name__ == "__main__":
    main()
