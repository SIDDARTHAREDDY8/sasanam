#!/usr/bin/env python3
"""Red-first for F937: statement-level char-code accumulation loops..

statement-level char-code accumulation loops (for/while/for-of/do-while doing
s+=String.fromCharCode(codes[i])) are now modeled node-exactly: the decoder produces
the assembled credential, so find_credential flags them. Same-class: the F517 for-in
idiom blocks coded (control).
Filed 2026-10-09 12:34 UTC wave-389 (attack round 57); CLOSED 2026-10-09 wave-390 lane 1.
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
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"
_CRED = _A + _B
_CRED40 = _L1 + _L2
_CODES = ",".join(str(ord(c)) for c in _CRED)
_CODES40 = ",".join(str(ord(c)) for c in _CRED40)

SHAPES = [
    ("s1-for",
     "(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=String.fromCharCode(c[i]);}return s;})()" % _CODES),
    ("s2-while",
     "(function(){var c=[%s],s='',i=0;while(i<c.length){s+=String.fromCharCode(c[i]);i++;}return s;})()" % _CODES),
    ("s3-forof",
     "(function(){var s='';for(var x of [%s]){s+=String.fromCharCode(x);}return s;})()" % _CODES),
    ("s4-dowhile",
     "(function(){var c=[%s],s='',i=0;do{s+=String.fromCharCode(c[i]);i++;}while(i<c.length);return s;})()" % _CODES),
    ("s5-40char",
     "(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=String.fromCharCode(c[i]);}return s;})()" % _CODES40),]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-forin-idiom-blocks",
     "(function(){var A='';var O={a:\'"+_A+"\',b:\'"+_B+"\'};for(var K in O)A+=O[K];return A})()",
     True),]


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
