#!/usr/bin/env python3
"""Red-first for F1157: F1127 residual -- direct-RESULT push-then-join.

The wave-404 lane-2 F1127 hook models push-then-join via an intermediate
(`var S=A.join('');var RESULT=S;`). Assigning the join directly to RESULT
(`var RESULT=A.join('');`) assembles node-exactly but the hook misses it.
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
    ("f1157-s-direct-result",
     "var C=[%s];var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var RESULT=A.join('');"),
    ("f1157-l-direct-result",
     "var C=[%s];var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var RESULT=A.join('');"),
    ("f1157-s-foreach-direct",
     "var C=[%s];var A=[];C.forEach(function(c){A.push(String.fromCharCode(c));});var RESULT=A.join('');"),
    ("f1157-l-foreach-direct",
     "var C=[%s];var A=[];C.forEach(function(c){A.push(String.fromCharCode(c));});var RESULT=A.join('');"),
]
CONTROLS = [
    ("ctrl-intermediate-S-blocks",
     "var C=[%s];var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var S=A.join('');var RESULT=S;"),
]

def main():
    n_break = 0
    for name, tmpl in SHAPES:
        secret = SECRET_L if name.startswith("f1157-l") else SECRET_S
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
