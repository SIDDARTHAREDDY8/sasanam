#!/usr/bin/env python3
"""Red-first for F1068: Proxy set-trap accumulation reads.

`new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}})` with
per-code `p[i]=c` writes accumulates the credential node-exactly (v24.20.0);
`Object.values(o).join('')` reassembles it. F1059 (OPEN) covers only the
get-trap production -- the decoder has no set-trap production modeled.
Filed 2026-10-10 09:55 UTC wave-397 (attack round 65, local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


SHAPES = [
    ("f1068-s-set-trap",
     "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});"
     "%s.forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');" % _codes(SECRET_S)),
    ("f1068-l-set-trap",
     "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});"
     "%s.forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');" % _codes(SECRET_L)),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("FAIL " if hit else "BREAK ") + name)
        if hit:
            fails.append(name)
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
