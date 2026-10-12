#!/usr/bin/env python3
"""Wave-429 lane A red-first battery for F1759 (Array.fromAsync staging).

F1759 (filed shape, attack 96): `var C=[codes];(async function(){`
`var D=await Array.fromAsync(C);var S=String.fromCharCode.apply(null,D);})()`
No RESULT anywhere in the filed shape.

Node v24.20.0 confirms the credential assembles on 20-char and 40-char
xoxb- credentials (via a console.log probe inside the IIFE, matching the
attack's w428 battery), while find_credential MISSES the filed shape in a
fresh process (exactly one find_credential call per fresh process,
round-60 rule).

Genuine {I} templates (never vacuous {{I}}). Capture via Python
subprocess ONLY. Prints BREAK while the gap is open.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET_S = "xoxb-" + "0123456789abcde"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

PAYLOAD = ('var C={I};(async function(){var D=await Array.fromAsync(C);'
           'var S=String.fromCharCode.apply(null,D);})()')
# Node probe: console.log inside the IIFE (attack's w428 approach) to verify assembly
NODE_PROBE = ('var C={I};(async function(){var D=await Array.fromAsync(C);'
              "console.log('OUT:'+String.fromCharCode.apply(null,D));})();")
IS_ASYNC = True


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
    return "ERR:" + (r.stderr or "")[-200:]


def _node_ok(payload, secret):
    # Async IIFE: use the console.log probe inside the IIFE (attack's approach).
    # The payload arg is unused; we use NODE_PROBE for node verification.
    probe = NODE_PROBE.replace("{I}", _codes(secret))
    nc = subprocess.run(["node", "-e", probe],
                        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


def main():
    fails = 0
    for label, secret in (("short", SECRET_S), ("long", SECRET_L)):
        payload = PAYLOAD.replace("{I}", _codes(secret))
        node = _node_ok(payload, secret)
        scan = _scan(payload) if node else "SKIP(node-false)"
        ok = node and scan == "MISS"
        print(label + ": node=" + str(node) + " scan=" + scan +
              " => " + ("BREAK" if ok else "FAIL"))
        if not ok:
            fails += 1
    junk = "the quick brown fox jumps over the lazy dog 1234567890"
    js = _scan(junk)
    print("junk-quiet: scan=" + js + " => " + ("PASS" if js == "MISS" else "FAIL"))
    if js != "MISS":
        fails += 1
    print("F1759 red-first: " + ("BREAK" if fails == 0 else "FAIL"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
