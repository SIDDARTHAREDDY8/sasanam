#!/usr/bin/env python3
"""F1567 red-first: Dead effect-free `for` statement breaks whole-text statement decoders.

Filed 2026-10-11 16:40 UTC, wave-418 lane-4 residual (renumbered from F1546 per
wave-272; attack-86's F1546 filed 16:12 UTC wins). Local node validation, $0.00.
`var C=[codes];var S=C.map(...).join('');for(var k=0;k<1;k++){var Z=k;}var RESULT=S;`
assembles node-exactly (v24.20.0) while find_credential MISSES:
`_js_f1540_strip_dead_stmt` only strips dead `var|let|const` declarations, not
effect-free compound statements. Distinct from F1540 (CLOSED: dead var stripping).
Prints BREAK on the open tree.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.expanduser("~/workspace/teams/wave418-merge/sasanam")

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-1234567890abcdef"
SECRET_L = "xoxb-1234567890abcdef1234567890abcdef12345678"

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _node_assembles(payload, secret):
    js = "(function(){ %s return S; })()" % payload
    r = subprocess.run(["node", "-e", "var S=%s; console.log(S===%r?'OK':'NO');" % (js, secret)],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip() == "OK"


_TMPLS = [
    ('f1567-0',
     'var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join(\'\');for(var k=0;k<1;k++){var Z=k;}var RESULT=S;'),
]

_CONTROLS = [
    ('direct-ctrl',
     'var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;'),
]


def main():
    n_break = 0
    n_total = 0
    for name, tmpl in _TMPLS:
        for sec in (SECRET_S, SECRET_L):
            payload = tmpl.replace("{I}", _codes(sec))
            n_total += 1
            if not _node_assembles(payload, sec):
                print("%s/%d: node MISASSEMBLES (shape not node-exact here)" % (name, len(sec)))
                continue
            v = _scan(payload)
            if v == "MISS":
                n_break += 1
                print("%s/%d: BREAK (scanner MISS, node-exact)" % (name, len(sec)))
            else:
                print("%s/%d: HELD (scanner %s)" % (name, len(sec), v))
    for name, tmpl in _CONTROLS:
        for sec in (SECRET_S, SECRET_L):
            v = _scan(tmpl.replace("{I}", _codes(sec)))
            print("control %s/%d: scanner %s (want HIT)" % (name, len(sec), v))
    print("BREAK %d/%d" % (n_break, n_total))
    return 0 if n_break == n_total and n_total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
