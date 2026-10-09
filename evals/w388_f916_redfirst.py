#!/usr/bin/env python3
"""Red-first for F916: Intl.Segmenter with omitted locale.

The F857 closure (CLOSED wave-387 lane 8) requires a locale literal:
`new Intl.Segmenter().segment('f1')` (the engine defaults the locale)
resolves node-exactly while the decoder produces zero variants. Close-when:
the decoder models the omitted-locale form node-exactly (or refuses the
laundering coded) such that find_credential flags them, red-first verified,
honest text unaffected; shapes: (function(){var s=new
Intl.Segmenter().segment('f1');var r='';for(var x of s){r+=x.segment;}return
r+'f2';})()
Filed 2026-10-09 07:20 UTC wave-387 lane 8 (F857 closure residual; spec-axis
review soft note).
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
     "(function(){var s=new Intl.Segmenter().segment('%s');var r='';"
     "for(var x of s){r+=x.segment;}return r+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var s=new Intl.Segmenter().segment('%s');"
     "return Array.from(s).map(function(x){return x.segment;}).join('')"
     "+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("locale-twin",
     "(function(){var s=new Intl.Segmenter('en').segment('%s');var r='';"
     "for(var x of s){r+=x.segment;}return r+'%s';})()" % (_A, _B),
     True),
    ("junk-quiet",
     "(function(){var s=new Intl.Segmenter().segment('ab');var r='';"
     "for(var x of s){r+=x.segment;}return r;})()",
     False),
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
