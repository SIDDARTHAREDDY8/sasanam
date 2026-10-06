#!/usr/bin/env python3
"""Red-first for F483: .apply/.bind dispatch (and dispatch chains) on
non-concat prototype methods. The wave-357 F478 closure models .call for
the 11 filed shapes and .apply/.bind for concat ONLY (documented
residual). The residual breaks: join/slice/filter/map/reduce via .apply
or immediate .bind recover the exact credential in node (v24.20.0) while
the decoder misses; so do dispatch chains (Function.prototype.call.call,
bind-then-call) and spread args through concat.apply. Distinct from F478
(its filed concat shapes hold).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"
FCC = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]

SHAPES = [
    ("join-apply",
     "Array.prototype.join.apply(['%s','%s'], [''])" % (A1, A2), True),
    ("slice-apply",
     "Array.prototype.slice.apply(['%s','%s'], [0,2]).join('')" % (A1, A2), True),
    ("filter-apply",
     "Array.prototype.filter.apply(['%s','%s',''], [x=>x!=='']).join('')" % (A1, A2), True),
    ("map-bind-immediate",
     "Array.prototype.map.bind(['%s','%s'], String)().join('')" % (A1, A2), True),
    ("reduce-bind-immediate",
     "Array.prototype.reduce.bind(['%s','%s'], (a,c)=>a+c, '')()" % (A1, A2), True),
    ("join-bind-immediate",
     "Array.prototype.join.bind(['%s','%s'], '')()" % (A1, A2), True),
    ("slice-bind-immediate",
     "Array.prototype.slice.bind(['%s','%s'], 0, 2)().join('')" % (A1, A2), True),
    ("filter-bind-immediate",
     "Array.prototype.filter.bind(['%s','%s',''], x=>x!=='')().join('')" % (A1, A2), True),
    ("concat-apply-spread",
     "Array.prototype.concat.apply([], [...['%s','%s']]).join('')" % (A1, A2), True),
    ("call-call-double",
     "Function.prototype.call.call(Array.prototype.concat, [], '%s','%s').join('')" % (A1, A2), True),
    ("bind-then-call",
     "String.prototype.concat.bind('%s').call(null, '%s')" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "Array.prototype.join.apply(['ab','cd'], [''])", False),
    ("neighbor-f478-apply-held",
     "Array.prototype.concat.apply([], ['%s','%s']).join('')" % (A1, A2), True),
    ("neighbor-f478-bind-held",
     "String.prototype.concat.bind('%s')('%s')" % (A1, A2), True),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
