#!/usr/bin/env python3
"""Red-first for F1037 (wave-396 lane 1): groupBy-keyed code reassembly (Object.groupBy / Map.groupBy).

index-pair arrays partitioned by Object.groupBy / Map.groupBy, concat+sort reassembled, per-pair fromCharCode accumulation assembles node-exactly; no groupBy production modeled (distinct vs F1015 keys/map/join).
Filed 2026-10-10 06:45 UTC wave-395 (attack round 63, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), FAIL when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1037-s0-obj",
     'var g=Object.groupBy([[0,120],[1,111],[2,120],[3,98],[4,45],[5,48],[6,49],[7,50],[8,51],[9,52],[10,53],[11,54],[12,55],[13,56],[14,57],[15,97],[16,98],[17,99],[18,100],[19,101],[20,102]],function(p){return p[0]%2;});var all=g[0].concat(g[1]);all.sort(function(a,b){return a[0]-b[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'),
    ("f1037-s1-obj",
     'var g=Object.groupBy([[0,120],[1,111],[2,120],[3,98],[4,45],[5,48],[6,49],[7,50],[8,51],[9,52],[10,53],[11,54],[12,55],[13,56],[14,57],[15,97],[16,98],[17,99],[18,100],[19,101],[20,102],[21,48],[22,49],[23,50],[24,51],[25,52],[26,53],[27,54],[28,55],[29,56],[30,57],[31,97],[32,98],[33,99],[34,100],[35,101],[36,102],[37,48],[38,49],[39,50]],function(p){return p[0]%2;});var all=g[0].concat(g[1]);all.sort(function(a,b){return a[0]-b[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'),
    ("f1037-s2-map",
     'var g=Map.groupBy([[0,120],[1,111],[2,120],[3,98],[4,45],[5,48],[6,49],[7,50],[8,51],[9,52],[10,53],[11,54],[12,55],[13,56],[14,57],[15,97],[16,98],[17,99],[18,100],[19,101],[20,102]],function(p){return p[0]%2;});var all=g.get(0).concat(g.get(1));all.sort(function(a,b){return a[0]-b[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'),
    ("f1037-s3-map",
     'var g=Map.groupBy([[0,120],[1,111],[2,120],[3,98],[4,45],[5,48],[6,49],[7,50],[8,51],[9,52],[10,53],[11,54],[12,55],[13,56],[14,57],[15,97],[16,98],[17,99],[18,100],[19,101],[20,102],[21,48],[22,49],[23,50],[24,51],[25,52],[26,53],[27,54],[28,55],[29,56],[30,57],[31,97],[32,98],[33,99],[34,100],[35,101],[36,102],[37,48],[38,49],[39,50]],function(p){return p[0]%2;});var all=g.get(0).concat(g.get(1));all.sort(function(a,b){return a[0]-b[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'),
]

CONTROLS = [
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
