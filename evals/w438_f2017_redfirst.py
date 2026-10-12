#!/usr/bin/env python3
"""Red-first battery for F2017 (F1920 astral-pad mis-decode) - wave-438 lane B spec-review.

Prints BREAK if the scanner MIS-DECODEs the astral-pad shape on the open tree.
Genuine {I} template; junk-quiet control included.

F1920's hook uses `len(pad) != 1` which counts Python chars, not UTF-16
units. An astral pad (e.g. U+1F600, 2 UTF-16 units) passes the check,
but node produces dstr + trailing surrogate, not dstr. The hook
mis-decodes by returning dstr.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w438_f2017_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET = "xoxb-" + "0123456789abcde"

# Astral pad: U+1F600 (grinning face), 2 UTF-16 units
TEMPLATE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='\U0001F600'.concat(T).slice(1);var RESULT=U;"

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
        # For mis-decode detection, we need to check if r == SECRET (wrong)
        # vs r is None (correct fail-closed) vs r == correct (impossible here)
        "print('VERDICT:'+('HIT' if r else 'MISS'));"
        "print('VALUE:'+repr(r))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    verdict = "ERR"
    value = None
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            verdict = line[len("VERDICT:"):]
        if line.startswith("VALUE:"):
            value = line[len("VALUE:"):]
    return verdict, value

def main():
    payload = TEMPLATE.replace("{I}", _codes(SECRET))
    v, val = _scan(payload)
    jv, _ = _scan("the quick brown fox jumps over the lazy dog")
    print("F2017 astral-pad shape: %s (value=%s, junk-quiet: %s)" % (v, val, jv))
    # BREAK if the hook returns the SECRET (mis-decode).
    # The correct behavior is MISS (fail closed) because the hook
    # cannot safely decode the astral-pad shape.
    # Note: find_credential might HIT via a different (correct) path,
    # but the F1920 hook specifically mis-decodes.
    # For red-first, we check the hook directly.
    from gov.dlp import _js_f1920_stmt_decode
    hook_result = _js_f1920_stmt_decode(payload)
    if hook_result == SECRET:
        print("BREAK (hook mis-decodes astral pad as identity)")
    elif hook_result is None:
        print("HELD (hook fails closed on astral pad)")
    else:
        print("ERROR (unexpected hook result: %r)" % hook_result)

if __name__ == "__main__":
    main()
