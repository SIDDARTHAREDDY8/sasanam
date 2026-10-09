#!/usr/bin/env python3
"""Red-first for F891: Object.seal literals containing method values.

F891 (filed 2026-10-09 05:50:07 UTC, wave-386 lane 9 spec-review
residual of the F812 closure; renumbered from F830 at the wave-386
merge): F812 models Object.seal/preventExtensions as identity
builtins over F535 data literals, but a sealed literal CONTAINING
a shorthand method has no production -- the F539 literal parse
fails closed on methods, so even a pure data read on the sealed
object misses; and a method CALL on a sealed object misses because
the F812 sealed IIFE only models member reads.

Wave-387 adds the F891 method-literal grammar (data props +
zero-param shorthand methods with pure-literal bodies, node-exact
v24.20.0) and the sealed-method IIFE. The credential is split
across two literals so the raw-text strict scan cannot fire; only
a correct decode materializes the credential-shaped concatenation.
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
    # data read on a method-containing sealed literal
    ("s1",
     "(function(){var o=Object.seal({k:'%s',m(){return 'z';}});return o.k+'%s';})()" % (_A, _B),
     True),
    # zero-arg method call on a sealed object
    ("s2",
     "(function(){var o=Object.seal({m(){return '%s';}});return o.m()+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    # method-free sealed literal still blocks (F812 closed)
    ("seal-data-blocks",
     "(function(){var o=Object.seal({k:'%s'});return o.k+'%s';})()" % (_A, _B),
     True),
    # reading a method (not calling) must NOT decode the body
    # (the engine yields the function object)
    ("method-read-quiet",
     "(function(){var o=Object.seal({m(){return '%s';}});return typeof o.m;})()" % _A,
     False),
    # calling a data prop throws in the engine -> fail closed
    ("call-dataprop-quiet",
     "(function(){var o=Object.seal({k:'%s',m(){return 'z';}});return o.k();})()" % _A,
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
