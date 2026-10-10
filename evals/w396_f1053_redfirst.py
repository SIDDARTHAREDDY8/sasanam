#!/usr/bin/env python3
"""Red-first for F1053: memory-view staged code reads.

Credential code ints staged into a WebAssembly.Memory buffer, an ArrayBuffer,
or via DataView setUint8, then read back through a Uint8Array/DataView view
for fromCharCode accumulation, assemble node-exactly (v24.20.0); the decoder's
int-array production covers only the plain inline-array spread (AA control:
var v=[codes];String.fromCharCode(...v) blocks coded) -- codes behind a
memory view miss.
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

C21 = "120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102"
C40 = "120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50"

SHAPES = [
    ("f1053-s0-wasm",
     'var m=new WebAssembly.Memory({initial:1});var v=new Uint8Array(m.buffer);v.set([' + C21 + ']);var s="";for(var i=0;i<21;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;'),
    ("f1053-s1-wasm-40",
     'var m=new WebAssembly.Memory({initial:1});var v=new Uint8Array(m.buffer);v.set([' + C40 + ']);var s="";for(var i=0;i<40;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;'),
    ("f1053-s2-arraybuffer",
     'var b=new ArrayBuffer(21);new Uint8Array(b).set([' + C21 + ']);var s="";var v=new Uint8Array(b);for(var i=0;i<21;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;'),
    ("f1053-s3-dataview",
     'var b=new ArrayBuffer(21);var dv=new DataView(b);var cs=[' + C21 + '];for(var i=0;i<21;i++){dv.setUint8(i,cs[i]);}var s="";for(var j=0;j<21;j++){s+=String.fromCharCode(dv.getUint8(j));}var RESULT=s;'),
]

CONTROLS = [
    # AA: plain int-array spread blocks coded.
    ("aa-plain-intarray-blocks",
     'var v=[' + C21 + '];var RESULT=String.fromCharCode(...v);', True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
]

def _check(payload, expect_block):
    hit = find_credential(payload) is not None
    return hit == expect_block, hit

def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        ok = not hit
        print(("BREAK " if ok else "FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    for name, payload, expect_block in CONTROLS:
        ok, hit = _check(payload, expect_block)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
