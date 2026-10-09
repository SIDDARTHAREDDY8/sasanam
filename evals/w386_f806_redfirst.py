#!/usr/bin/env python3
"""Red-first for F806: mixin extends-expression reads (wave-386 lane 6).

The decoder had no extends-expression production: classes extending
call-expression mixins resolve node-exactly while the decoder produced
zero variants. Closed by the F806 extension to _js_f672_parse_extends
(extends MNAME(ARGNAME) mixin application) plus the bare
function-declaration mixin production in _js_f672_top_stmt.
Filed 2026-10-09 03:25 UTC wave-385 attack round 53.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("s1",
     "(function(){function M(Base){return class extends Base{m(){return '%s';}};}class B{}class C extends M(B){}return new C().m()+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var M=function(B){return class extends B{v(){return '%s';}};};class C extends M(class{}){}return new C().v()+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
