#!/usr/bin/env python3
"""Red-first battery for F1290: Set.forEach non-empty accumulator residual.

Verifies the scanner MISSES Set.forEach accumulation with non-empty init
on the open tree. Node v24.20.0: S='x' + forEach accumulation assembles
a credential-bearing string.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"

SHAPES = [
    ("f1290-s_nonempty_short",
     "var C=%s;var S='x';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;" % _codes(SECRET_S)),
    ("f1290-s_nonempty_long",
     "var C=%s;var S='x';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;" % _codes(SECRET_L)),
]

CONTROLS = [
    ("ctrl-empty-blocks",
     "var C=%s;var S='';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;" % _codes(SECRET_S)),
    ("ctrl-junk-quiet",
     "The quarterly financial summary shows revenue growth."),
]

def main():
    breaks = 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        status = "FAIL" if hit else "BREAK"
        if hit:
            breaks += 1
        print("%s %s" % (status, name))
    for name, payload in CONTROLS:
        if "junk" in name:
            ok = find_credential(payload) is None
        else:
            ok = find_credential(payload) is not None
        print("ctrl-%s %s" % ("ok" if ok else "FAIL", name))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), breaks))
    return 0

if __name__ == "__main__":
    sys.exit(main())
