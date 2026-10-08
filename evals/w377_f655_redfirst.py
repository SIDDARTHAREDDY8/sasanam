#!/usr/bin/env python3
"""Red-first for F655: statement-IIFE multi-statement fragment accumulation.

The statement-IIFE parsers model only single-declaration+return bodies. Any multi-statement accumulation body -- two declarations, decl+accum, or the same statements inside switch/do-while/with/labeled/try-finally wrappers -- assembles the credential node-exactly (v24.20.0) while the
decoder misses. Filed shapes: two-decl, decl+accum, switch-fallthrough,
try-finally, do-while, with-statement, labeled-block.
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
    ("two-declarations",
     "(function(){var a='" + _A + "';var b='" + _B + "';return a+b;})()"),
    ("decl-plus-accum",
     "(function(){var s='" + _A + "';s+='" + _B + "';return s;})()"),
    ("switch-fallthrough",
     "(function(){let s='';switch(1){case 1:s+='" + _A + "';case 2:s+='" + _B + "';}return s;})()"),
    ("try-finally",
     "(function(){let s='';try{s+='" + _A + "';}finally{s+='" + _B + "';}return s;})()"),
    ("do-while",
     "(function(){let s='';do{s+='" + _A + "';s+='" + _B + "';}while(false);return s;})()"),
    ("with-statement",
     "(function(){let s='';with({}){s+='" + _A + "';s+='" + _B + "';}return s;})()"),
    ("labeled-block",
     "(function(){let s='';blk:{s+='" + _A + "';break blk;s+='junk';}s+='" + _B + "';return s;})()"),
]

CONTROLS = [
    ("array-join-still-blocks",
     "['" + _A + "','" + _B + "'].join('')", True),
    ("single-decl-body-still-blocks",
     "(function(){var s='" + _A + "';return s+'" + _B + "';})()", True),
    ("junk-quiet",
     "(function(){var a='jx';var b='jy';return a+b;})()", False),
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
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
