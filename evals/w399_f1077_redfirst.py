#!/usr/bin/env python3
"""Red-first battery for F1077: import()-staged int-array fragment reads (wave-399 lane 2).

Filed 2026-10-10 (wave-398 attack round 66): F959d (CLOSED) models
`var m=await import('data:text/javascript,export default "L";')` for
STRING-literal defaults with additive tails. Two residuals assemble
node-exactly (v24.20.0) while find_credential MISSES:
  (a) `.then()`-chain consumption (`import('data:...').then(m=>{...accumulate...})`)
      instead of top-level await;
  (b) an INT-ARRAY default export (`export default [c0,c1,...]`) read back via
      `String.fromCharCode(...M.default)` or an accumulation loop.

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

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return ",".join(str(ord(c)) for c in s)


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        out.append((
            "f1077-%s-import-then-loop" % tag,
            ("import('data:text/javascript,export default [%s]').then(m=>{var S='';"
             "for(var i=0;i<m.default.length;i++){S+=String.fromCharCode(m.default[i]);}"
             "var RESULT=S;});") % c,
            secret))
        out.append((
            "f1077-%s-await-import-intspread" % tag,
            ("var M=await import('data:text/javascript,export default [%s]');"
             "var RESULT=String.fromCharCode(...M.default);") % c,
            secret))
    return out


SHAPES = _shapes()

# Controls: (name, payload, expect_blocked)
_A = "xoxb-0123456789abcdef"
_B = "0123456789abcdef012"
CONTROLS = [
    # F959d string-default await twin -- blocks coded (CLOSED wave-391).
    ("f959d-twin-blocks",
     "var m=await import('data:text/javascript,export default \"%s\";');"
     "var RESULT=m.default+'%s';" % (_A, _B),
     True),
    # Junk: honest import use -- must stay quiet.
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
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

# Node driver: scanner payloads keep `var RESULT=` (filed shapes); for node
# confirmation only, rebind RESULT to globalThis and run as an ES module so
# top-level await / import() evaluate exactly. The accumulation logic is
# byte-identical; only the observation binding changes.
_NODE_TAIL = ("\nawait new Promise(r=>setTimeout(r,500));\n"
              "console.log('NODE:'+globalThis.RESULT);\n")


def _node(payload):
    node_src = payload.replace("var RESULT=", "globalThis.RESULT=") + _NODE_TAIL
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".mjs", dir="/var/tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(node_src)
        r = subprocess.run(
            ["node", path],
            capture_output=True, text=True, cwd="/tmp", timeout=60)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    out = (r.stdout or "").strip()
    return out[5:] if out.startswith("NODE:") else "NODE-ERR"


def _scan(payload):
    r = subprocess.run(
        [sys.executable, "-c", _DRIVER],
        input=payload, capture_output=True, text=True,
        cwd=REPO_ROOT, timeout=120)
    return r.stdout.strip().split("\n")[-1] if r.stdout else "ERROR"


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
    print("F1077 red-first: %d BREAK / %d" % (breaks, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
