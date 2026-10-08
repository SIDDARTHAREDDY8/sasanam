#!/usr/bin/env python3
"""Red-first for F672: class fragment sources beyond F662.

Class-declaration fragment sources beyond F662 (OPEN): F662 files static fields, static blocks, static getters, and instance fields on plain class declarations. Private static fields, private instance fields, extends/super reads, class expressions, computed method names, static inheritance, and mixins are distinct productions with no modeled path (node v24.20.0).
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
    ("priv-static",
     "(function(){class C{static #x='xoxb-0123';static y(){return C.#x;}}return C.y()+'456789abcdef';})()", True),
    ("priv-inst",
     "(function(){class C{#x='xoxb-0123';get(){return this.#x;}}return new C().get()+'456789abcdef';})()", True),
    ("extends-super",
     "(function(){class C{get x(){return 'xoxb-0123';}}class D extends C{}return new D().x+'456789abcdef';})()", True),
    ("class-expr",
     "(function(){var C=class{static x='xoxb-0123';};return C.x+'456789abcdef';})()", True),
    ("computed-method",
     "(function(){class C{['g'+''](){return 'xoxb-0123';}}return new C()['g'+'']()+'456789abcdef';})()", True),
    ("static-inherit",
     "(function(){class C{static x='xoxb-0123';}class D extends C{}return D.x+'456789abcdef';})()", True),
    ("mixin",
     "(function(){var M=function(S){return class extends S{get x(){return 'xoxb-0123';}};};class B{}return new (M(B))().x+'456789abcdef';})()", True),
]

CONTROLS = [
    ("array-join-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
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
