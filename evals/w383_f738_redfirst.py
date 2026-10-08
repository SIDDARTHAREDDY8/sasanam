#!/usr/bin/env python3
"""Red-first for F738: `this`-dependent getter bodies through prototype chains.

F723 (CLOSED, wave-383 lane 6) models prototype-chain getter reads
and F724 (CLOSED, wave-383 lane 6) models Object.setPrototypeOf
installed getters -- but a getter whose body reads `this` escapes:
the static model evaluates getter bodies at literal-parse time,
when `this` is unbound, so the parse fails closed while the engine
invokes the getter at read time with `this` bound to the receiver:
`(function(){var o={y:'f1',get x(){return this.y;}};var
c=Object.create(o);return c.x+'f2';})()` and the setPrototypeOf
twin `(function(){var c={};var p={y:'f1',get x(){return
this.y;}};Object.setPrototypeOf(c,p);return c.x+'f2';})()` both
node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. Distinct from F723/F724 (argument-
independent getter bodies). Filed 2026-10-08 wave-383 lane 6.
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
    ("this-create",
     "(function(){var o={y:'%s',get x(){return this.y;}};"
     "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B), True),
    ("this-setproto",
     "(function(){var c={};var p={y:'%s',get x(){return this.y;}};"
     "Object.setPrototypeOf(c,p);return c.x+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("argfree-still-blocks",
     "(function(){var o={get x(){return '%s';}};"
     "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B), True),
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
