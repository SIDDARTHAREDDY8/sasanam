#!/usr/bin/env python3
"""Red-first for F458: `String.fromCharCode` with non-decimal/non-hex integer
literal spellings bypasses the bounded static JS-expression decoder.

"String.fromCharCode" is a claimed F430 surface and `_js_parse_number`
handles decimal and `0x` hex literals -- but JS has more integer spellings:
`0o` octal, `0b` binary, legacy octal (`0124`, sloppy mode), numeric
separators (`1_20`), and mixed-radix argument lists. All evaluate exactly
in node (node-verified) and all fail closed in the decoder ("not a number").
One coherent class: integer-literal spellings in fromCharCode arguments.
Model-adjacent (gpt-4o-mini round-19 B6 literal spellings validated
locally).

Code points are rendered at runtime from the concatenation-constructed
credential (no credential literals in this file). Prints BREAK when the
payload MISSES (open tree), HELD when blocked coded.
Controls: decimal-arg fromCharCode blocks; hex-arg fromCharCode blocks;
junk codes quiet; plain credential blocks coded.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
CRED = "xoxb-" + "0123456789abcdef"  # 21 chars


def _spell(code, style):
    if style == "oct":
        return "0o%o" % code
    if style == "bin":
        return "0b" + bin(code)[2:]
    if style == "legacy":
        return "0%o" % code
    if style == "seps":
        s = str(code)
        return s if len(s) < 3 else s[:-2] + "_" + s[-2:]
    if style == "dec":
        return str(code)
    if style == "hex":
        return hex(code)
    raise ValueError(style)


def _shape(style, mixed=False):
    codes = []
    for idx, ch in enumerate(CRED):
        code = ord(ch)
        if mixed:
            st = ("hex", "dec", "oct", "bin")[idx % 4]
        else:
            st = style
        codes.append(_spell(code, st))
    return "String.fromCharCode(%s)" % ",".join(codes)


SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("fcc-octal", _shape("oct"), True),
    ("fcc-binary", _shape("bin"), True),
    ("fcc-legacy-octal", _shape("legacy"), True),
    ("fcc-separators", _shape("seps"), True),
    ("fcc-mixed", _shape("oct", mixed=True), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("fcc-decimal", _shape("dec"), True),
    ("fcc-hex", _shape("hex"), True),
    ("fcc-junk", "String.fromCharCode(65,66)", False),
    ("plain-credential", CRED, True),
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
