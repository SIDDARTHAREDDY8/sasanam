#!/usr/bin/env python3
"""Red-first for F892: F822 residual -- non-F478-table methods via ?.

F892 (filed 2026-10-09 05:55:00 UTC, wave-386 lane 14 spec-axis
review HARD-3 on the F822 closure; renumbered from F832 at the
wave-386 merge): F822 dispatches `?.method(args)` through the F478
method table (14 methods), but the dot form's method grammar
(_JS_POSTFIX_METHOD_NAMES, 40 methods) is wider -- the 26
non-table methods (flat, split, padStart, sort, trim, charAt,
substring, case methods, match, normalize, fill, repeat, etc.)
remain bypassable via `?.`.

Wave-387 adds the full-table `?.` direct-call lookahead: on a
provably-non-null receiver `?.` is engine-identical to `.` (node
v24.20.0), so the 26 non-table methods dispatch through
_js_apply_method exactly like the dot form. The credential is
split across two literals so the raw-text strict scan cannot fire.
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
     "[['" + _A + "'],['" + _B + "']]?.flat().join('')",
     True),
    ("s2",
     "'" + _A + "," + _B + "'?.split(',').join('')",
     True),
]

CONTROLS = [
    # bracket-string form of an F478-table method (F822 closed)
    ("f822-bracket-blocks",
     "['" + _A + "','z']?.['join']('" + _B + "')",
     True),
    # dot twins block
    ("dot-flat-blocks",
     "[['" + _A + "'],['" + _B + "']].flat().join('')",
     True),
    ("dot-split-blocks",
     "'" + _A + "," + _B + "'.split(',').join('')",
     True),
    # F478-table ?. methods still block (F822 closed)
    ("f822-closed-blocks",
     "['" + _A + "','" + _B + "']?.join('')",
     True),
    # kind-mismatched ?. fails closed like the dot twin
    # (the engine throws TypeError on both)
    ("kind-mismatch-quiet",
     "'ab'?.join(',')",
     False),
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
