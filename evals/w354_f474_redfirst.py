#!/usr/bin/env python3
"""Red-first for F474: uncaught TypeError in paren .concat escapes
find_credential (robustness defect, not a recovery bypass).

('frag1').concat(['frag2']) -- the prefix -- node-evaluates to the
credential; the decoder's paren-concat branch appends the _JSArr
argument to parts without a type check, so "".join(parts) raises
"TypeError: sequence item 0: expected str instance, _JSArr found".
The spread path checks isinstance(e, str); the non-spread argument
path has no guard, so the exception escapes find_credential instead of
failing closed with _JSExprFail. Honest note: the full shape with a
trailing .join('') throws in a real engine too (TypeError: .join is not
a function -- strings have no .join), so this is NOT a credential-
recovery bypass; the defect is the uncaught exception on adversarial
input (fail-UNDEFINED, potential scan DoS). Distinct from F473
(array-RECEIVER fail-closed miss): this is the missing ARGUMENT type
guard on a string receiver.

Prints BREAK when the payload RAISES TypeError (open tree), HELD when
it fails closed or blocks without raising.
Controls: plain credential blocks coded; the string-args junk variant
is quiet and raises nothing; the F462 spread shape blocks.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "4567" + "89abcdef"

SHAPES = [
    # (name, payload) -- adversarial input exercising the missing guard
    ("strrecv-concat-arrarg",
     "('%s').concat(['%s']).join('')" % (A1, A2)),
]

CONTROLS = [
    # (name, payload, want_hit, want_raise)
    ("junk-quiet", "('ab').concat('cd').join('')", False, False),
    ("neighbor-f462-closed", "''.concat(...['%s','%s'])" % (A1, A2), True, False),
    ("plain-blocks", A1 + A2, True, False),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        try:
            hit = find_credential(payload) is not None
            raised = False
        except TypeError:
            hit, raised = False, True
        is_break = raised
        print("%s: %s" % (name, "BREAK(raises)" if is_break
                          else ("HELD(blocks)" if hit else "HELD(fail-closed)")))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit, want_raise in CONTROLS:
        try:
            hit = find_credential(payload) is not None
            raised = False
        except Exception:
            hit, raised = False, True
        ok = (hit == want_hit) and (raised == want_raise)
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
