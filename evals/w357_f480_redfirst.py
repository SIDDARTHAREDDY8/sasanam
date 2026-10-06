#!/usr/bin/env python3
"""Red-first for F480: constructor-function call/apply dispatch and
bracket-string member access on built-in call sites.

The decoder anchors modeled built-ins on dot-identifier call shapes
(Array.apply, String.fromCharCode, Object.assign, Reflect.apply,
Array.prototype.concat). Two shape classes bypass every anchor:

A. Constructor-function dispatch via Function.prototype.call/.apply --
   invoking a CONSTRUCTOR as a plain function. Distinct from F469
   (Reflect.apply -- the Reflect API) and F478 (.call/.apply/.bind on
   prototype METHODS like concat/join/slice): here the dispatch target
   is the constructor function itself (Array), not a prototype method.
   - Array.apply(Array, ['f1','f2']).join('')
   - Array['apply'](Array, ['f1','f2']).join('')
   - Array.call(Array, 'f1','f2').join('')
   - Array['call'](Array, 'f1','f2').join('')
   - [].constructor['apply']([].constructor, ['f1','f2']).join('')
   - Reflect['apply'](Array, Array, [['f1'],['f2']]).join('')

B. Bracket-string member access on modeled static methods -- the same
   built-in, reached as X['name'] instead of X.name:
   - String['fromCharCode'](120,111,...)  (F458 covers dot form only)
   - Object['assign']([], ['f1','f2'])    (F471 covers dot form only)

All shapes node-evaluate (v24.20.0) to the exact credential while the
decoder produces zero variants.

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
FCC = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
       97, 98, 99, 100, 101, 102]

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("apply-ctor-dot",
     "Array.apply(Array, ['%s','%s']).join('')" % (A1, A2), True),
    ("apply-ctor-bracket",
     "Array['apply'](Array, ['%s','%s']).join('')" % (A1, A2), True),
    ("call-ctor-dot",
     "Array.call(Array, '%s','%s').join('')" % (A1, A2), True),
    ("call-ctor-bracket",
     "Array['call'](Array, '%s','%s').join('')" % (A1, A2), True),
    ("apply-ctor-prop",
     "[].constructor['apply']([].constructor, ['%s','%s']).join('')" % (A1, A2), True),
    ("reflect-bracket",
     "Reflect['apply'](Array, Array, [['%s'],['%s']]).join('')" % (A1, A2), True),
    ("fcc-bracket",
     "String['fromCharCode'](%s)" % ",".join(str(c) for c in FCC), True),
    ("assign-bracket",
     "Object['assign']([], ['%s','%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "Array.apply(Array, ['ab','cd']).join('')", False),
    ("neighbor-f469-closed",
     "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2), True),
    ("neighbor-f458-closed",
     "String.fromCharCode(%s)" % ",".join(str(c) for c in FCC), True),
    ("neighbor-f476-closed",
     "[].constructor.of('%s','%s').join('')" % (A1, A2), True),
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
