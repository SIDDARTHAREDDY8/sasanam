#!/usr/bin/env python3
"""Red-first for F828: F781 class-ctor overstatement residual.

The wave-385 lane-10 F781 closure note claimed "empty function/class
ctor decls" are modeled, but _js_parse_f781_proto_method_iife has no
class branch: `class C{}C.prototype.m=function(){return 'f1';};` +
`new C().m()` dispatches node-exactly while the decoder produces zero
variants. Spec-axis review HARD finding; re-filed per the standing
overstatement rule (never silently patched).
Filed 2026-10-09 03:43:50 UTC, wave-385 lane 10.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
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
    ("s1",
     "(function(){class C{}C.prototype.m=function(){return '%s';};"
     "return new C().m()+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){class C{}C.prototype['m']=function(){return '%s';};"
     "var o=new C();return o['m']()+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
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
