#!/usr/bin/env python3
"""Red-first battery for F2016 (wave-439 lane E).

Statement-interaction suppression: two credential-assembly shapes that
each HIT alone (var T=C.map/join readout; var U=String.fromCharCode.apply
readout) both MISS when present in the same text, in either order.

Prints BREAK if the scanner MISSES the combined shape on the open tree.
Genuine {I} template; junk-quiet control included.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w439_f2016_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET = "xoxb-aaaa-bbbb-ccccc"

T_ASM = "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
U_ASM = "var U=String.fromCharCode.apply(null,C);"

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
    ci = _codes(SECRET)
    t_only = "var C=%s;%svar RESULT=T;" % (ci, T_ASM)
    u_only = "var C=%s;%svar RESULT=U;" % (ci, U_ASM)
    t_then_u = "var C=%s;%s%svar RESULT=U;" % (ci, T_ASM, U_ASM)
    u_then_t = "var C=%s;%s%svar RESULT=T;" % (ci, U_ASM, T_ASM)
    vt = _scan(t_only)
    vu = _scan(u_only)
    vtu = _scan(t_then_u)
    vut = _scan(u_then_t)
    jv = _scan("the quick brown fox jumps over the lazy dog")
    print("F2016 T-only: %s, U-only: %s (controls, expect HIT/HIT)" % (vt, vu))
    print("F2016 T-then-U: %s, U-then-T: %s (filed shapes, expect MISS/MISS)" % (vtu, vut))
    print("F2016 junk-quiet: %s" % jv)
    if vt == "HIT" and vu == "HIT" and vtu == "MISS" and vut == "MISS" and jv == "MISS":
        print("BREAK")
    else:
        print("HELD" if (vtu == "HIT" or vut == "HIT") else "ERROR")

if __name__ == "__main__":
    main()
