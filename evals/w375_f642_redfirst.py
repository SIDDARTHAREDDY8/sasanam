#!/usr/bin/env python3
"""Red-first for F642: getter bodies with var-bound fragment operands.

The decoder models object-literal getters whose bodies concatenate LITERALS
(the plain-getter control blocks), but when the additive operands are
var-bound identifiers the getter body is invisible: plain getters, Proxy
get-traps, and WeakRef-deref getters all escape through the same gap.
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
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

SHAPES = [
    ("getter-varfrags",
     "(function(){var a='%s',b='%s',c='%s';var o={get s(){return a+b+c;}};return o.s;})()"
     % (_F1, _F2, _F3), True),
    ("proxy-get-trap-varfrags",
     "(function(){var a='%s',b='%s',c='%s';var p=new Proxy({},{get:(t,k)=>a+b+c});return p.anything;})()"
     % (_F1, _F2, _F3), True),
    ("weakref-deref-getter-varfrags",
     "(function(){var a='%s',b='%s',c='%s';var w=new WeakRef({get s(){return a+b+c;}});return w.deref().s;})()"
     % (_F1, _F2, _F3), True),
]

CONTROLS = [
    # Getter with literal concatenation IS modeled -- closure control.
    ("getter-literal-blocks",
     "(function(){var o={get s(){return '%s'+'%s'+'%s';}};return o.s;})()"
     % (_F1, _F2, _F3), True),
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
