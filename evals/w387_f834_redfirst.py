#!/usr/bin/env python3
"""Red-first for F834: method-shorthand invocation.

F834 (LOW, filed 2026-10-09 05:30 UTC, wave-386 attack round 54): the
decoder models `function f(){};f()` and `var f=function(){};f()` but not
object-literal method-shorthand calls: `var o={m(){return 'f1';}};o.m()`
resolves node-exactly while the decoder produces zero variants.
Close-when: the decoder models method-shorthand invocation node-exactly
(or refuses the laundering coded) such that find_credential flags them.
Filed shapes verified node-exact on v24.20.0.
Closed 2026-10-09 wave-387 lane 2 -- incidentally covered on the
wave-386 tree by lane 9's _js_parse_f674_this_bound_iife (verified
node-exact on the filed shapes plus this-binding generalizations).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
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
     "(function(){var o={m(){return '%s';}};return o.m()+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var o={k:'%s',m(){return this.k;}};return o.m()+'%s';})()"
     % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'",
     False),
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
