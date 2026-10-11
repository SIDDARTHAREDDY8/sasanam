#!/usr/bin/env python3
"""F1503 red-first: deep flat(2) in hybrids (wave-416 lane-4 grpD).

Payload (node v24.20.0 verified inside this battery via subprocess):
  var C=[codes];
  var E=C.flat(2);
  E.sort(function(a,b){return 0;});
  var S=String.fromCharCode.apply(null,E);
  var RESULT=S;

Open tree: find_credential MISSES (prints BREAK). After the F1384
hook extension (_js_f1384_flat_sort admits flat(2) -- node-identical
to flat(1) on a flat int array): HIT (prints GREEN). Controls:
flat()/flat(1) still HIT; flat(3) still MISSES (fail closed on depth
>2); junk-quiet still MISSES.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _node_ok(tmpl, secret):
    body = tmpl.replace("{I}", _codes(secret))
    js = ("var __R=(function(){" + body.replace("var RESULT=S;", "return S;")
          + "})();if(__R!==" + repr(secret) + "){console.log('NODE-BAD');"
          "process.exit(1);}console.log('NODE-OK');")
    r = subprocess.run(["node", "-e", js],
                       capture_output=True, text=True, timeout=30)
    return r.returncode == 0 and "NODE-OK" in (r.stdout or "")


_TMPLS = [
    ("f1503-0",
     "var C={I};var E=C.flat(2);E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]

_CONTROLS = [
    # (name, payload, expected)
    ("f1384-flat0-ctrl",
     "var C={I};var E=C.flat();E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "HIT"),
    ("f1384-flat1-ctrl",
     "var C={I};var E=C.flat(1);E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "HIT"),
    ("flat3-failclosed",
     "var C={I};var E=C.flat(3);E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "MISS"),
    ("junk-quiet",
     "var RESULT='nothing to see here, just honest text';",
     "MISS"),
]


def main():
    expect_hit = "--expect-hit" in sys.argv
    fails = 0
    breaks = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "len=21"), (SECRET_L, "len=40")):
            if not _node_ok(tmpl, secret):
                print(f"NODE-FAIL {name} {label}")
                fails += 1
                continue
            payload = tmpl.replace("{I}", _codes(secret))
            verdict = _scan(payload)
            if verdict == "HIT":
                print(f"GREEN  {name} {label} -> HIT")
            elif verdict == "MISS":
                print(f"BREAK  {name} {label} -> MISS")
                breaks += 1
            else:
                print(f"FAIL  {name} {label} -> {verdict}")
                fails += 1
    for name, tmpl2, want in _CONTROLS:
        payload = tmpl2.replace("{I}", _codes(SECRET_S))
        verdict = _scan(payload)
        if verdict == want:
            print(f"CTRL-OK {name} -> {verdict}")
        else:
            print(f"CTRL-FAIL {name} -> {verdict} (want {want})")
            fails += 1
    if fails:
        print(f"RESULT: NO-GREEN ({fails} hard fails)")
        return 1
    if breaks:
        print(f"RESULT: BREAK ({breaks} payload shapes still miss)")
        return 1 if expect_hit else 0
    print("RESULT: GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
