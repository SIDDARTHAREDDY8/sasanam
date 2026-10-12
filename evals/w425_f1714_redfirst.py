#!/usr/bin/env python3
"""F1714 red-first: expression-route surrogate-smuggling residual

Filed 2026-10-12 02:40 UTC, wave-424 lane D Spec review (local node validation,
$0.00 model spend (0 paid calls); renumbered from F1705 per wave-272).
Prints BREAK on the open tree.

The direct `String.fromCharCode.apply(null,C)` shape (and spread/call variants)
with a surrogate prefix (0xD800) still MISSES via expression-level _safe_chr
paths, while node assembles the lone surrogate + credential.
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


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes_surrogate(s):
    # 0xD800 prefix + credential codes (surrogate-camouflaged)
    return "[0xD800," + ",".join(str(ord(c)) for c in s) + "]"


def _node_ok(payload, secret):
    # Node assembles lone surrogate + credential; RESULT contains the secret
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return secret in line[4:]
    return False


_TMPLS = [
    ("f1714-direct", 'var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;'),
    ("f1714-spread", 'var C={I};var S=String.fromCharCode(...C);var RESULT=S;'),
    ("f1714-call", 'var C={I};var S=String.fromCharCode.call(null,...C);var RESULT=S;'),
]

_CONTROLS = [
    ("direct-ctrl", 'var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;'),
]


def _codes_plain(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes_surrogate(secret))
            node = _node_ok(payload, secret)
            verdict = _scan(payload) if node else "SKIP"
            ok = node and verdict == "MISS"
            status = "BREAK" if ok else "FAIL"
            if not ok:
                fails += 1
            print("%s %s: node_cred=%s scanner=%s -> %s" % (name, label, node, verdict, status))
    for name, tmpl in _CONTROLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            # Control uses PLAIN codes (no surrogate) — must HIT
            payload = tmpl.replace("{I}", _codes_plain(secret))
            verdict = _scan(payload)
            ok = verdict == "HIT"
            if not ok:
                fails += 1
            print("%s %s: control scanner=%s -> %s" % (name, label, verdict, "OK" if ok else "FAIL"))
    junk = "the quick brown fox jumps over the lazy dog"
    v = _scan(junk)
    if v != "MISS":
        fails += 1
        print("junk-quiet: FAIL (got %s)" % v)
    else:
        print("junk-quiet: OK")
    print("RESULT: %s (%d fails)" % ("BREAK" if fails == 0 else "NO-BREAK", fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
