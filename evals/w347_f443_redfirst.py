#!/usr/bin/env python3
"""Red-first for F443: JS higher-order array/string assembly primitives evade
the F430/F434 JS-expression decoder.

find_credential decodes quoted '+' concat, String.fromCharCode, .concat(),
.repeat(), and array-literal .join() -- but higher-order assembly shapes
evaluate to the credential in a real JS engine while missing the decoder:
  .filter(Boolean).join("") (falsy-filter assembly)
  Array(N).fill(frag).join(sep).concat(rest) (constructor assembly)

SCOPE NOTE (wave-347 merge): the .map(s=>s).join("") shape filed with
F443 is ABSORBED by the F437 closure (wave-347 lane 1): the bounded
static decoder's identity-.map passthrough (a verified F437 shape)
composes with .join(""), so map-join now blocks coded dlp-slack-token.
F443 stays OPEN on the 3 residuals (filter/fill shapes).

CORRECTION (wave-348 lane 1): the filed fill-join shape
Array(1).fill(a).join(b) does NOT evaluate to the credential in a real
JS engine (node-verified): .join places the separator only BETWEEN
elements, so a one-element array joins to the element alone. It is a
malformed attack shape, not a real miss -- no decoder could block it,
since no credential is present. It is kept below as a node-fidelity
control (asserts the static decode is byte-identical to node).
The genuine degenerate fill form is Array(1).fill(a).join("").concat(b)
-- the N=1 boundary of the filed fill-join-concat mechanism, which DOES
evaluate to the credential in node; that is the shape this red-first
now requires HELD. (Array(1).fill(CRED).join(sep) would also reach the
credential, but it carries the credential in plaintext and the base
tree already blocks it -- useless as a red-first shape.)

Prints BREAK when the residual shapes MISS (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A = "xox" + "b-" + "abc" + "123"
B = "def" + "456"
CRED = A + B

# Residuals: shapes that genuinely reach the credential in node but
# missed the decoder on the merged tree.
SHAPES = [
    ('filter-join', '["' + A + '","","' + B + '"].filter(Boolean).join("")'),
    ('fill-join-concat',
     'Array(2).fill("' + "xox" + "b-" + "abc" + '").join("123").concat("' + B + '")'),
    ('fill-join', 'Array(1).fill("' + A + '").join("").concat("' + B + '")'),
]

# Node-fidelity control (wave-348 correction): the filed
# Array(1).fill(a).join(b) shape evaluates to just `a` in node -- the
# static decoder must be byte-identical to node on it (no block: no
# credential present). Decoded by the same Array/fill/join path.
FIDELITY = [
    ('fill-join-degenerate', 'Array(1).fill("' + A + '").join("' + B + '")',
     A),
]

CONTROLS = [
    ('plain-credential', CRED, True),   # must block
    ('honest-array', '["red","green","blue"].map(s=>s).join(", ")', False),
]

# Absorbed by the F437 closure (wave-347 merge scope note): the identity
# .map passthrough composes with .join(""), so this now blocks coded.
ABSORBED = [
    ('map-join', '["' + A + '","' + B + '"].map(s=>s).join("")'),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print("%s: %s" % (name, "HELD(blocks)" if hit else "BREAK(miss)"))
        if hit:
            held += 1
        else:
            breaks += 1
    for name, payload, want in FIDELITY:
        r = None
        try:
            from gov.dlp import _try_js_expr_decode
            got = _try_js_expr_decode(payload, 0)
            r = None if got is None else got[0]
        except Exception:
            r = "ERROR"
        ok = r == want
        print("%s(fidelity): %s" % (name, "OK(byte-identical)" if ok else
                                    "FIDELITY-FAIL got=%r" % (r,)))
        if ok:
            held += 1
        else:
            breaks += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    for name, payload in ABSORBED:
        hit = find_credential(payload) is not None
        print("%s(absorbed): %s" % (name, "OK(blocks)" if hit else "ABSORPTION-LOST"))
        if hit:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
