#!/usr/bin/env python3
"""Red-first for F949 (wave-391 closure lane 1): top-level statement-scope packaging gap.

Eleven builtin classes the decoder models inside IIFE bodies miss as top-level
statement sequences because the statement sims only thread IIFE bodies:
structuredClone member reads, generator yield accumulation, manual
.next().value reads, class static blocks, class static fields,
Proxy.revocable member reads, WeakRef deref member reads, array
destructuring binds, Object.values().join, Map values spread join, and
labeled-block break assembly. Filed 2026-10-09 13:58 UTC, wave-390 attack
round 58. Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("structuredclone",
     "var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;" % (_A, _B)),
    ("structuredclone-40",
     "var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;" % (_F1, _F2)),
    ("gen-yield",
     "function*g(){yield '%s';yield '%s';}var s='';for(var p of g()){s+=p;}var RESULT=s;" % (_A, _B)),
    ("gen-next",
     "function*g(){yield '%s';yield '%s';}var gg=g();var RESULT=gg.next().value+gg.next().value;" % (_A, _B)),
    ("static-block",
     "class C{static{this.a='%s';this.b='%s';}}var RESULT=C.a+C.b;" % (_A, _B)),
    ("static-field",
     "class C{static a='%s';static b='%s';}var RESULT=C.a+C.b;" % (_A, _B)),
    ("revocable",
     "var r=Proxy.revocable({a:'%s'},{});var RESULT=r.proxy.a+'%s';" % (_A, _B)),
    ("weakref",
     "var w=new WeakRef({a:'%s'});var RESULT=w.deref().a+'%s';" % (_A, _B)),
    ("destructure",
     "var [a,b]=['%s','%s'],RESULT=a+b;" % (_A, _B)),
    ("obj-values",
     "var o={a:'%s',b:'%s'};var RESULT=Object.values(o).join('');" % (_A, _B)),
    ("map-spread",
     "var m=new Map([['a','%s'],['b','%s']]);var RESULT=[...m.values()].join('');" % (_A, _B)),
    ("labeled-block",
     "var RESULT='';lbl:{RESULT+='%s';if(1){break lbl;}RESULT+='nope';}RESULT+='%s';" % (_A, _B)),]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-iife-blocks",
     "(function(){var o=structuredClone({a:'%s',b:'%s'});return o.a+o.b;})()" % (_A, _B),
     True),
    ("coded-literal-blocks",
     "'%s' + '%s'" % (_A, _B),
     True),]


def main():
    fails = 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("HELD " if hit else "BREAK ") + name)
        if hit:
            fails += 1
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = (hit == expect_block)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails += 1
    print("%d shapes, %d controls, %d failures" % (len(SHAPES), len(CONTROLS), fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
