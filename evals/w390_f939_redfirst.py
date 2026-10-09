#!/usr/bin/env python3
"""Red-first for F939: per-element String.fromCharCode transforms..

per-element String.fromCharCode transforms are now modeled node-exactly:
non-identity .map callbacks (function/arrow), Array.from with a fromCharCode mapfn,
forEach side-effect accumulation, and IIFE-per-element maps. The F437 closure still
fails closed on other non-identity map transforms (documented boundary).
Controls: junk-quiet passes; identity-map twin blocks coded.
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
    ("s1-map-fn",
     "(function(){return [%s].map(function(c){return String.fromCharCode(c);}).join('');})()" % _CODES),
    ("s2-map-arrow",
     "(function(){return [%s].map(c=>String.fromCharCode(c)).join('');})()" % _CODES),
    ("s3-arrayfrom-mapfn",
     "(function(){return Array.from([%s],function(c){return String.fromCharCode(c);}).join('');})()" % _CODES),
    ("s4-foreach",
     "(function(){var s='';[%s].forEach(function(c){s+=String.fromCharCode(c);});return s;})()" % _CODES),
    ("s5-iife-per-char",
     "(function(){var c=[%s];return c.map(function(x){return (function(){return String.fromCharCode(x);})();}).join('');})()" % _CODES),
    ("s6-40char",
     "(function(){return [%s].map(function(c){return String.fromCharCode(c);}).join('');})()" % _CODES40),]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-identity-map-blocks",
     "(function(){return ['"+_A+"','"+_B+"'].map(function(x){return x;}).join('');})()",
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
