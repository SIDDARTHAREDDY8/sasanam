#!/usr/bin/env python3
"""Red-first for F447: non-Boolean .filter(...) predicates bypass the
static JS-expression decoder.

gov/dlp.py `_js_parse_filter_callback` (F443) models only the bare
`Boolean` predicate (plus the F437 constant-true and identity forms).
Truthy-preserving predicates that are not the bare `Boolean`
identifier -- `x=>x!==''`, `x=>!!x`, `x=>x.length>0`,
`function(x){return x;}` -- fail closed, so
`['frag','frag','',''].filter(<pred>).join('')` yields no decode
variant, while node evaluates each to the credential.

Prints BREAK when the expressions MISS (open tree), HELD when blocked.
Controls: .filter(Boolean) blocks (F443 shape); a verbatim credential
blocks via the raw-text rule; an all-falsy array is quiet (no
credential present to recover).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A = "xox" + "b-abc123"
B = "def" + "456"
CRED = A + B
ARR = "['" + A + "','" + B + "','','']"

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("filter-neq-empty", ARR + ".filter(x=>x!=='').join('')", True),
    ("filter-double-neg", ARR + ".filter(x=>!!x).join('')", True),
    ("filter-length", ARR + ".filter(x=>x.length>0).join('')", True),
    ("filter-fn-truthy", ARR + ".filter(function(x){return x;}).join('')", True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("filter-boolean", "['" + A + "','','" + B + "'].filter(Boolean).join('')", True),  # F443 shape blocks
    ("filter-all-falsy", "['','',''].filter(x=>x!=='').join('')", False),  # no credential: quiet
    ("plain-credential", CRED, True),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        # BREAK = genuine miss: real engine recovers, scanner misses.
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
