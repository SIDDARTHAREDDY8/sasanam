"""Red-first for F1110: inline C.values() of-source evades the F1091 closure.

F1091 (CLOSED wave-401 lane 1) models iteration-protocol staged assembly
for `for[-await]...of` over C / C.values() / C.entries(), but its hook
requires the `var IT=C.values();` binding -- the inline of-source
`for(var x of C.values()){...}` (and the for-await twin) assemble
node-exactly (v24.20.0) while find_credential MISSES. Filed 2026-10-10
from the wave-401 merge Spec-axis review (HARD-1 residual).

Run: ~/workspace/.gov-venv/bin/python evals/w401_f1110_redfirst.py
Prints BREAK for each shape that still misses (open tree).
"""
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

SHORT = "xoxb-1234567890"
LONG = "xoxb-1234567890abcdefghij1234567890abcd"


def _codes(s):
    return ",".join(str(b) for b in s.encode())


def _payload(inline, await_, codes):
    if await_:
        return ("(async()=>{var C=[%s];var S='';for await(var x of %s){S+=String.fromCharCode(x);}"
                "globalThis.RESULT=S;})();" % (codes, inline))
    return ("var C=[%s];var S='';for(var x of %s){S+=String.fromCharCode(x);}"
            "var RESULT=S;" % (codes, inline))


SHAPES = []
for tag, cred in (("s", SHORT), ("l", LONG)):
    codes = _codes(cred)
    SHAPES.append(("f1110-%s-inline-values" % tag, _payload("C.values()", False, codes)))
    SHAPES.append(("f1110-%s-inline-values-await" % tag, _payload("C.values()", True, codes)))


def _misses(payload):
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r);"
         "from gov.dlp import find_credential;"
         "r = find_credential(sys.stdin.read());"
         "print('BLOCK' if r else 'MISS')" % REPO_ROOT],
        input=payload, capture_output=True, text=True, timeout=120)
    return r.stdout.strip() == "MISS"


def main():
    bad = 0
    for name, payload in SHAPES:
        if _misses(payload):
            print("BREAK %s" % name)
            bad += 1
        else:
            print("FAIL %s" % name)
    print("%d/%d BREAK" % (bad, len(SHAPES)))
    return 0 if bad else 1


if __name__ == "__main__":
    sys.exit(main())
