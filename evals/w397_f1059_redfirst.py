#!/usr/bin/env python3
"""Red-first for F1059: Proxy named-target get-trap reads (F990 residual).

F990 (CLOSED wave-393 lane 1, _js_f990_stmt_decode) models the get trap only
over an INLINE object-literal target; staging the target in a named variable
first (var t={...};var p=new Proxy(t,{get:function(o,k){return o[k];}})) and
reading p.a+p.b assembles node-exactly (v24.20.0) but misses the hook's
grammar. AA control: the inline-target twin blocks coded.
Filed 2026-10-10 08:16 UTC wave-397 lane 3 (closure of wave-396 attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1059-s0",
     'var t={a:"xoxb-01",b:"23456789abcdef"};var p=new Proxy(t,{get:function(o,k){return o[k];}});var RESULT=p.a+p.b;'),
    ("f1059-s1-40",
     'var t={a:"xox",b:"b-0123456789abcdef0123456789abcdef012"};var p=new Proxy(t,{get:function(o,k){return o[k];}});var RESULT=p.a+p.b;'),
]

CONTROLS = [
    # AA: inline-literal target is modeled by F990 -- blocks coded.
    ("aa-inline-target-blocks",
     'var p=new Proxy({a:"xoxb-01",b:"23456789abcdef"},{get:function(o,k){return o[k];}});var RESULT=p.a+p.b;', True),
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
