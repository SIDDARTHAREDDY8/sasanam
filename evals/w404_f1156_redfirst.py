#!/usr/bin/env python3
"""Red-first for F1156: F1124 residual -- no-return side-effect callbacks.

The wave-404 lane-2 F1124 hook models side-effect accumulation callbacks with
an explicit never-satisfied predicate (e.g. `return false`). A callback with
NO return statement is effectively never-satisfied (returns undefined) and
assembles node-exactly, but the hook misses it.
"""
import os, sys
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from gov import dlp

def _codes(secret):
    return ",".join(str(b) for b in secret.encode())

SECRET_S = "xoxb-0123456789abcdef"
SECRET_L = "xoxb-0123456789abcdefghijklmnopqrstuvwx"

SHAPES = [
    ("f1156-s-find-noreturn",
     "var C=[%s];var S='';C.find(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("f1156-l-find-noreturn",
     "var C=[%s];var S='';C.find(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("f1156-s-some-noreturn",
     "var C=[%s];var S='';C.some(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("f1156-l-some-noreturn",
     "var C=[%s];var S='';C.some(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
]
CONTROLS = [
    ("ctrl-find-return-false-blocks",
     "var C=[%s];var S='';C.find(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
]

def main():
    n_break = 0
    for name, tmpl in SHAPES:
        secret = SECRET_L if name.startswith("f1156-l") else SECRET_S
        payload = tmpl % _codes(secret)
        hit = dlp.find_credential(payload) is not None
        print(("FAIL(BLOCKED) " if hit else "BREAK ") + name)
        if not hit:
            n_break += 1
    for name, tmpl in CONTROLS:
        payload = tmpl % _codes(SECRET_S)
        hit = dlp.find_credential(payload) is not None
        print(("HELD(control blocks) " if hit else "CONTROL-MISS ") + name)
    print("%d/%d BREAK (expected: all BREAK on open tree)" % (n_break, len(SHAPES)))

if __name__ == "__main__":
    main()
