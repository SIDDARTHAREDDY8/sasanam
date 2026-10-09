#!/usr/bin/env python3
"""Red-first for F946: arithmetic code arguments to fromCharCode.

String.fromCharCode with additive (n+1) or index-arithmetic code arguments
resolves node-exactly while the decoder produces zero variants. The F458
grammar covers integer-literal code spellings only.
Filed 2026-10-09 12:34 UTC wave-389 (attack round 57).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_CRED40 = "xox" + "b-" + "0123456789abcdef0123456789abcdef012"
_CODES = ",".join(str(ord(c)) for c in _CRED)
_ADD = "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1) for c in _CRED)
_ADD40 = "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1) for c in _CRED40)
# mixed-radix additive terms (hex + octal spellings), full credential
_MIX = "+".join("String.fromCharCode(0x%x+0o1)" % (ord(c) - 1) for c in _CRED)

SHAPES = [
    ("s1-additive",
     "(function(){return %s;})()" % _ADD),
    ("s2-indexed-arrayfrom",
     "(function(){var cd=[%s];return Array.from({length:cd.length},function(_,i){return String.fromCharCode(cd[i]);}).join('');})()" % _CODES),
    ("s3-40char",
     "(function(){return %s;})()" % _ADD40),
    # generalization: mixed-radix additive terms (node-identical)
    ("s4-mixed-radix",
     "(function(){return %s;})()" % _MIX),
    # generalization: arrow callback twin for the indexed Array.from
    ("s5-arrow",
     "(function(){var cd=[%s];return Array.from({length:cd.length},(_,i)=>String.fromCharCode(cd[i])).join('');})()" % _CODES),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-literal-codes-blocks",
     "(function(){return String.fromCharCode(%s);})()" % _CODES,
     True),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        is_break = not hit
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
    print("shapes %d BREAK / %d HELD; controls tallied above" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
