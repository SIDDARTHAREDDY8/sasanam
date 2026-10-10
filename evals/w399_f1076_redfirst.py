#!/usr/bin/env python3
"""Red-first battery for F1076: Function-constructor body staging (wave-399 lane 2).

Filed 2026-10-10 (wave-398 attack round 66): the accumulation loop staged
INSIDE the `new Function("C", "<body>")` body string, called with the int
array, assembles node-exactly (v24.20.0) while find_credential MISSES.
F964 (CLOSED) models only the param-passing form
`new Function('p1',...,'pn','return p1+...+pn;')`.

On the OPEN tree each filed shape prints BREAK (scanner misses, node
confirms the credential). After closure each must print HELD (blocked).
Node v24.20.0 verified. Scanner calls run one-payload-per-fresh-process
via Python subprocess (round-60 lesson). $0-spend-by-construction.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

CRED20 = "AKIAIOSFODNN7EXAMPLE"
CRED40 = CRED20 + CRED20


def _codes(s):
    return ",".join(str(ord(c)) for c in s)


F1076_BODY = ("var S='';for(var i=0;i<C.length;i++)"
              "{S+=String.fromCharCode(C[i]);}return S;")

SHAPES = [
    ("f1076-20",
     'var F=new Function("C","%s");var RESULT=F([%s]);'
     % (F1076_BODY, _codes(CRED20)),
     CRED20),
    ("f1076-40",
     'var F=new Function("C","%s");var RESULT=F([%s]);'
     % (F1076_BODY, _codes(CRED40)),
     CRED40),
]

# Controls: (name, payload, expect_blocked)
CONTROLS = [
    # F964 param-passing twin -- blocks coded (CLOSED wave-394).
    ("f964-twin-blocks",
     'var F=new Function("C","return C;");var T=F("%s");' % CRED20,
     True),
    # Junk: honest Function use -- must stay quiet.
    ("junk-quiet",
     'var F=new Function("x","return x*x;");var T=F(21);',
     False),
]

_DRIVER = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "sys.path.insert(0,%r);"
    "from gov import dlp;"
    "p=sys.stdin.read();"
    "print('HIT' if dlp.find_credential(p) else 'MISS')"
) % REPO_ROOT


def _scan(payload):
    r = subprocess.run(
        [sys.executable, "-c", _DRIVER],
        input=payload, capture_output=True, text=True,
        cwd=REPO_ROOT, timeout=120)
    return r.stdout.strip().split("\n")[-1] if r.stdout else "ERROR"


_NODE_DRIVER = (
    "let p='';process.stdin.on('data',d=>p+=d);"
    "process.stdin.on('end',()=>{"
    "try{console.log('NODE:'+eval(p+';RESULT'));}catch(e){console.log('NODE-ERR');}});"
)


def _node(payload):
    r = subprocess.run(
        ["node", "-e", _NODE_DRIVER],
        input=payload, capture_output=True, text=True,
        cwd="/tmp", timeout=60)
    out = (r.stdout or "").strip()
    return out[5:] if out.startswith("NODE:") else "NODE-ERR"


def main():
    breaks = 0
    total = 0
    for name, payload, cred in SHAPES:
        total += 1
        node_val = _node(payload)
        node_ok = cred in node_val
        verdict = _scan(payload)
        is_break = (verdict == "MISS" and node_ok)
        breaks += 1 if is_break else 0
        print("%s node_ok=%s scan=%s -> %s"
              % (name, node_ok, verdict, "BREAK" if is_break else "HELD"))
    for name, payload, expect_blocked in CONTROLS:
        total += 1
        verdict = _scan(payload)
        blocked = (verdict == "HIT")
        ok = (blocked == expect_blocked)
        print("%s control scan=%s expect_blocked=%s -> %s"
              % (name, verdict, expect_blocked, "OK" if ok else "UNEXPECTED"))
        if not ok:
            breaks += 1
    print("F1076 red-first: %d BREAK / %d" % (breaks, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
