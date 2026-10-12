#!/usr/bin/env python3
"""Wave-431 lane B red-first battery for F1792.

Array.from(C.values().filter(()=>true)):
var C=[codes];var D=Array.from(C.values().filter(function(){return true;}));
var S=String.fromCharCode.apply(null,D)

No filed finding covers the filter iterator-helper production. It MISSES.

Node v24.20.0 confirms the credential assembles on 20-char and 40-char
xoxb- credentials, while find_credential MISSES in a fresh process
(exactly one find_credential call per fresh process, round-60 rule).

Genuine {I} templates (never vacuous {{I}}). Capture via Python
subprocess ONLY. Prints BREAK while the gap is open, NO-BREAK once
the lane hook decodes it.
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

PAYLOADS = [
    "var C={I};var D=Array.from(C.values().filter(function(){return true;}));var S=String.fromCharCode.apply(null,D);console.log('OUT:'+S);",
]


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
    nc = subprocess.run(["node", "-e", payload],
                        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


def main():
    fails = 0
    for pi, tmpl in enumerate(PAYLOADS):
        for label, secret in (("short", SECRET_S), ("long", SECRET_L)):
            payload = tmpl.replace("{I}", _codes(secret))
            node = _node_ok(payload, secret)
            scan = _scan(payload) if node else "SKIP(node-false)"
            ok = node and scan == "MISS"
            print("shape%d %s: node=%s scan=%s => %s" % (
                pi, label, node, scan, "BREAK" if ok else "FAIL"))
            if not ok:
                fails += 1
    jq = _scan("the quick brown fox jumps over the lazy dog")
    print("junk-quiet: %s => %s" % (jq, "OK" if jq == "MISS" else "FAIL"))
    if jq != "MISS":
        fails += 1
    dc = _scan("var C=" + _codes(SECRET_S) + ";var S=String.fromCharCode.apply(null,C);")
    print("direct-control: %s => %s" % (dc, "OK" if dc == "HIT" else "FAIL"))
    if dc != "HIT":
        fails += 1
    print("RESULT: %s" % ("BREAK" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
