#!/usr/bin/env python3
"""Red-first battery for F2017 (wave-439 lane E).

F1920 astral-pad mis-decode: the F1920 hook uses `len(pad) != 1` which
counts Python chars, not UTF-16 units. An astral pad (e.g. U+1F600,
2 UTF-16 units) passes the check, but node produces dstr + trailing
surrogate, not dstr. The hook mis-decodes by returning dstr.

Prints BREAK if the hook mis-decodes the astral-pad shape on the open
tree. Genuine {I} template; junk-quiet control included.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w439_f2017_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET = "xoxb-aaaa-bbbb-ccccc"

# Astral pad: U+1F600 (grinning face), 2 UTF-16 units
TEMPLATE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='\\U0001F600'.concat(T).slice(1);var RESULT=U;"

def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"

def main():
    from gov.dlp import _js_f1920_stmt_decode
    payload = TEMPLATE.replace("{I}", _codes(SECRET))
    hook_result = _js_f1920_stmt_decode(payload)
    print("F2017 astral-pad hook result: %r" % (hook_result,))
    if hook_result == SECRET:
        print("BREAK (hook mis-decodes astral pad as identity)")
    elif hook_result is None:
        print("HELD (hook fails closed on astral pad)")
    else:
        print("ERROR (unexpected hook result)")

if __name__ == "__main__":
    main()
