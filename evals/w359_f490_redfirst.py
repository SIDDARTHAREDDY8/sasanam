#!/usr/bin/env python3
"""Red-first for F490: optional-chaining member/call spellings at dispatch targets. No filed finding covers the ?. token: Array.prototype.concat?.call, ([]?.concat)?.call, [].concat?.call, ['concat']?.call, ?.apply, nullish-coalescing picks, ([].constructor?.of), and Reflect?.apply all node-evaluate (v24.20.0) to the exact credential while the decoder produces zero variants. Distinct from F478 (plain dot dispatch) and F482 (plain bracket dispatch).
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

SHAPES = [
    ("optchain-call",
     "Array.prototype.concat?.call([], '%s','%s').join('')" % (A1, A2), True),
    ("optchain-recv",
     "([]?.concat)?.call([], '%s','%s').join('')" % (A1, A2), True),
    ("optchain-bracket-call",
     "[].concat?.call([], '%s','%s').join('')" % (A1, A2), True),
    ("optchain-bracket-key",
     "Array.prototype['concat']?.call([], '%s','%s').join('')" % (A1, A2), True),
    ("optchain-apply",
     "Array.prototype.concat?.apply([], ['%s','%s']).join('')" % (A1, A2), True),
    ("optchain-bracket-apply",
     "Array.prototype['concat']?.apply([], ['%s','%s']).join('')" % (A1, A2), True),
    ("nullish-pick",
     "(([].concat ?? Array.prototype.join).call([], '%s','%s')).join('')" % (A1, A2), True),
    ("optchain-ctor-of",
     "([].constructor?.of)('%s','%s').join('')" % (A1, A2), True),
    ("reflect-optchain",
     "Reflect?.apply(Array, null, ['%s','%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("f478-dot-held",
     "[].concat.call([], '%s','%s').join('')" % (A1, A2), True),
    ("junk-quiet",
     "Array.prototype.concat?.call([], 'ab','cd').join('')", False),
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
