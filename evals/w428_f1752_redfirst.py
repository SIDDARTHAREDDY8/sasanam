#!/usr/bin/env python3
"""Wave-428 lane B red-first battery for F1752 (ArrayBuffer.transfer).

Genuine {I} templates (never vacuous {{I}}). Capture via Python subprocess ONLY.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = '/home/hatch/workspace/teams/wave428-f1752f1754close/sasanam'
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

PAYLOAD = 'var C={I};var B=new Uint8Array(C).buffer;var B2=B.transfer();var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,{r0});sys.path.insert(0,{r1});"
    "from gov.dlp import find_credential;"
    "r=find_credential({p});"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _scan(payload):
    code = _CHILD.format(
        r0=repr(REPO_ROOT),
        r1=repr(os.path.join(REPO_ROOT, "tests")),
        p=repr(payload))
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR:" + (r.stderr or "")[-200:]


def _node_ok(payload, secret):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"


def main():
    fails = 0
    for label, secret in (("short", SECRET_S), ("long", SECRET_L)):
        payload = PAYLOAD.replace("{I}", _codes(secret))
        node = _node_ok(payload, secret)
        scan = _scan(payload)
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
    ctrl = "var C=" + _codes(SECRET_S) + ";var S=String.fromCharCode.apply(null,C);"
    cs = _scan(ctrl)
    print("direct-control: scan=" + cs + " => " + ("PASS" if cs == "HIT" else "FAIL"))
    if cs != "HIT":
        fails += 1
    print("F1752 red-first: " + ("HELD" if fails == 0 else "FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
