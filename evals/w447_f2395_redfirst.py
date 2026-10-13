#!/usr/bin/env python3
"""Red-first battery for F2395 (string-bracket-valueof) - wave-447 lane A (from wave-446 attack round 114 filed shapes).

Prints BREAK if the scanner MISSES the filed shape on the open tree.
Genuine {I} template; junk-quiet control included.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w447_f2395_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "a" * 35

TEMPLATES = ["var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T['valueOf']());var RESULT=U;"]

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
    results = []
    for t in TEMPLATES:
        p20 = t.replace("{I}", _codes(SECRET20))
        p40 = t.replace("{I}", _codes(SECRET40))
        v20 = _scan(p20)
        v40 = _scan(p40)
        results.append((v20, v40))
    jv = _scan("the quick brown fox jumps over the lazy dog")
    print("F2395 filed-shape: %s (junk-quiet: %s)" % (results, jv))
    if all(v == "MISS" for pair in results for v in pair) and jv == "MISS":
        print("BREAK")
    elif any(v == "HIT" for pair in results for v in pair):
        print("HELD")
    else:
        print("ERROR")

if __name__ == "__main__":
    main()
