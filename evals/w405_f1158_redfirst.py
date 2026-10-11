#!/usr/bin/env python3
"""Red-first for F1158: bare-`return;` side-effect callbacks (wave-405 lane 4).

F1156 closed the no-return-statement form for find/some, but a callback
with a bare `return;` (no value) also returns undefined -- never-satisfied --
and assembles node-exactly while find_credential MISSED. Filed 2026-10-11
00:28 UTC by wave-405 lane 4 (local node validation, $0.00 model spend
(0 paid calls)). Prints BREAK on the open tree; on the closed tree each
shape is flagged.
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
    ("f1158-s-find-barereturn",
     "var C=[%s];var S='';C.find(function(c){S+=String.fromCharCode(c);return;});var RESULT=S;"),
    ("f1158-l-find-barereturn",
     "var C=[%s];var S='';C.find(function(c){S+=String.fromCharCode(c);return;});var RESULT=S;"),
    ("f1158-s-some-barereturn",
     "var C=[%s];var S='';C.some(function(c){S+=String.fromCharCode(c);return;});var RESULT=S;"),
    ("f1158-l-some-barereturn",
     "var C=[%s];var S='';C.some(function(c){S+=String.fromCharCode(c);return;});var RESULT=S;"),
]
CONTROLS = [
    ("ctrl-find-return-false-blocks",
     "var C=[%s];var S='';C.find(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    ("ctrl-find-return-undefined-misses",
     "var C=[%s];var S='';C.find(function(c){S+=String.fromCharCode(c);return undefined;});var RESULT=S;"),
]

def main():
    n_break = 0
    for name, tmpl in SHAPES:
        secret = SECRET_L if name.startswith("f1158-l") else SECRET_S
        payload = tmpl % _codes(secret)
        hit = dlp.find_credential(payload) is not None
        print(("FAIL(BLOCKED) " if hit else "BREAK ") + name)
        if not hit:
            n_break += 1
    for name, tmpl in CONTROLS:
        payload = tmpl % _codes(SECRET_S)
        hit = dlp.find_credential(payload) is not None
        if name.endswith("misses"):
            print(("HELD(control misses) " if not hit else "CONTROL-BLOCKED ") + name)
        else:
            print(("HELD(control blocks) " if hit else "CONTROL-MISS ") + name)
    print("%d/%d BREAK (expected: all BREAK on open tree)" % (n_break, len(SHAPES)))

if __name__ == "__main__":
    main()
