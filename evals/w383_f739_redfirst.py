#!/usr/bin/env python3
"""Red-first for F739: object-returning getters fail closed tree-wide.

Every getter route parses getter bodies with the F535 getter-value
grammar (`_js_parse_f535_getter_value` -> additive -> primary),
which cannot parse an object literal -- so a getter returning an
object fails closed while the engine evaluates member reads on
the returned object node-exactly:
`(function(){var o={get x(){return {y:'f1'};}};return
o.x.y+'f2';})()` (direct, F664's route) and the prototype-chain
twin `(function(){var o={get x(){return {y:'f1'};}};var
c=Object.create(o);return c.x.y+'f2';})()` (F723's route) both
node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. The setPrototypeOf (F724) and
defineProperty (F673) routes miss identically -- a pre-existing
tree-wide conservative boundary, not a lane-6 regression.
Distinct from F738 (`this`-dependent bodies). Filed 2026-10-08
wave-383 lane 6 (spec-review observation, local node validation,
no model calls).
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
    ("obj-direct",
     "(function(){var o={get x(){return {y:'%s'};}};"
     "return o.x.y+'%s';})()" % (_A, _B), True),
    ("obj-chain",
     "(function(){var o={get x(){return {y:'%s'};}};"
     "var c=Object.create(o);return c.x.y+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("strgetter-still-blocks",
     "(function(){var o={get x(){return '%s';}};"
     "return o.x+'%s';})()" % (_A, _B), True),
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
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
    for name, payload, recovers in CONTROLS:
        hit = find_credential(payload) is not None
        ok = (hit == recovers)
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
