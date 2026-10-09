#!/usr/bin/env python3
"""Red-first for F936: poetic acrostic multi-hop carrier.

the PoeLLM adversarial-poetry class applied to credential laundering: a benign-looking poem carries the credential as an acrostic, recovered only after the multi-hop extraction (split lines -> first-character hop -> join). All three extraction forms resolve node-exactly while the decoder produces zero variants.
Filed 2026-10-09 11:21 UTC wave-388 (attack round 56).
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

SHAPES = [
    ("s1-index",
     "(function(){var poem='xray\noscar\nxerox\nbravo\n-dash-\n0 days\n1 day\n2 days\n3 days\n4 days\n5 days\n6 days\n7 days\n8 days\n9 days\nalpha\nbeta\ncharlie\ndelta\necho\nfoxtrot';var s='';var lines=poem.split('\n');for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()",
     True),
    ("s2-forof",
     "(function(){var poem='xray\noscar\nxerox\nbravo\n-dash-\n0 days\n1 day\n2 days\n3 days\n4 days\n5 days\n6 days\n7 days\n8 days\n9 days\nalpha\nbeta\ncharlie\ndelta\necho\nfoxtrot';var s='';for(var line of poem.split('\n')){s+=line.charAt(0);}return s;})()",
     True),
    ("s3-mapjoin",
     "(function(){var poem='xray\noscar\nxerox\nbravo\n-dash-\n0 days\n1 day\n2 days\n3 days\n4 days\n5 days\n6 days\n7 days\n8 days\n9 days\nalpha\nbeta\ncharlie\ndelta\necho\nfoxtrot';return poem.split('\n').map(function(l){return l[0];}).join('');})()",
     True),
    ("s4-long",
     "(function(){var poem='xray\noscar\nxerox\nbravo\n-dash-\n0 spots\n1 spot\n2 spots\n3 spots\n4 spots\n5 spots\n6 spots\n7 spots\n8 spots\n9 spots\nalpha\nbeta\ncharlie\ndelta\necho\nfoxtrot\n0 zero\n1 one\n2 two\n3 three\n4 four\n5 five\n6 six\n7 seven\n8 eight\n9 nine\nalpha2\nbeta2\ncharlie2\ndelta2\necho2\nfoxtrot2\n0 x\n1 x\n2 x';var s='';for(var line of poem.split('\n')){s+=line.charAt(0);}return s;})()",
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
