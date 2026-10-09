#!/usr/bin/env python3
"""Red-first for F940: reduce/reduceRight with fromCharCode-concat callbacks..

reduce/reduceRight with fromCharCode-concat callbacks are now modeled node-exactly
(function/arrow, both concat orders, both directions). The F437 closure still models
only pA+pB reduce bodies and fails closed on other reduce bodies (documented
boundary). Controls: junk-quiet passes; pA+pB reduce twin blocks coded.
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
    ("s1-reduce-fn",
     "(function(){return [%s].reduce(function(s,c){return s+String.fromCharCode(c);},'');})()" % _CODES),
    ("s2-reduce-arrow",
     "(function(){return [%s].reduce((s,c)=>s+String.fromCharCode(c),'');})()" % _CODES),
    ("s3-reduceright",
     "(function(){return [%s].reduceRight(function(s,c){return String.fromCharCode(c)+s;},'');})()" % _CODES),]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-pApB-reduce-blocks",
     "(function(){return ['"+_A+"','"+_B+"'].reduce(function(a,b){return a+b;});})()",
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
