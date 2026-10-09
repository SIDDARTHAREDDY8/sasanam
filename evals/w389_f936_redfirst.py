#!/usr/bin/env python3
"""Red-first for F936: poetic acrostic multi-hop carrier.

The PoeLLM adversarial-poetry class applied to credential laundering:
a benign-looking poem carries the credential as an acrostic, recovered
only after the multi-hop extraction (split lines -> first-character
hop -> join). All three extraction forms resolve node-exactly while
the decoder produced zero variants.
Filed 2026-10-09 11:21 UTC wave-388 (attack round 56).
Closed wave-389: _js_parse_f936_acrostic_iife computes the extraction
statically with the engine's per-form empty-line and UTF-16 code-unit
semantics.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Poems whose acrostic is the short / long credential.
_POEM_S = ("xray\\noscar\\nxerox\\nbravo\\n-dash-\\n0 days\\n1 day\\n2 days\\n"
           "3 days\\n4 days\\n5 days\\n6 days\\n7 days\\n8 days\\n9 days\\n"
           "alpha\\nbeta\\ncharlie\\ndelta\\necho\\nfoxtrot")
_POEM_L = ("xray\\noscar\\nxerox\\nbravo\\n-dash-\\n0 spots\\n1 spot\\n2 spots\\n"
           "3 spots\\n4 spots\\n5 spots\\n6 spots\\n7 spots\\n8 spots\\n9 spots\\n"
           "alpha\\nbeta\\ncharlie\\ndelta\\necho\\nfoxtrot\\n0 zero\\n1 one\\n"
           "2 two\\n3 three\\n4 four\\n5 five\\n6 six\\n7 seven\\n8 eight\\n"
           "9 nine\\nalpha2\\nbeta2\\ncharlie2\\ndelta2\\necho2\\nfoxtrot2\\n"
           "0 x\\n1 x\\n2 x")

SHAPES = [
    ("s1-index",
     "(function(){var poem='%s';var s='';var lines=poem.split('\\n');"
     "for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()" % _POEM_S,
     True),
    ("s2-forof",
     "(function(){var poem='%s';var s='';for(var line of poem.split('\\n'))"
     "{s+=line.charAt(0);}return s;})()" % _POEM_S,
     True),
    ("s3-mapjoin",
     "(function(){var poem='%s';return poem.split('\\n')"
     ".map(function(l){return l[0];}).join('');})()" % _POEM_S,
     True),
    ("s4-long",
     "(function(){var poem='%s';var s='';for(var line of poem.split('\\n'))"
     "{s+=line.charAt(0);}return s;})()" % _POEM_L,
     True),
    # Lane generalizations (node-exact, v24.20.0):
    ("g-arrow-map",
     "(function(){var poem='%s';return poem.split('\\n')"
     ".map(l=>l[0]).join('');})()" % _POEM_S,
     True),
    ("g-block-arrow-map",
     "(function(){var poem='%s';return poem.split('\\n')"
     ".map((l)=>{return l[0];}).join('');})()" % _POEM_S,
     True),
    ("g-seq-accum",
     "(function(){var poem='%s';var s='';var lines=poem.split('\\n');"
     "for(var i=0;i<lines.length;i++){s=s+lines[i][0];}return s;})()" % _POEM_S,
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
]

# Fail-closed bounds: these must NOT decode (safe misses).
BOUNDS = [
    # wrong split separator: not an acrostic
    "(function(){var poem='xray|oscar';var s='';for(var line of poem.split('|')){s+=line.charAt(0);}return s;})()",
    # second-char projection: not the filed shape
    "(function(){var poem='xray\\noscar';return poem.split('\\n').map(function(l){return l[1];}).join('');})()",
    # charAt(1): not the filed shape
    "(function(){var poem='xray\\noscar';var s='';for(var line of poem.split('\\n')){s+=line.charAt(1);}return s;})()",
    # non-empty join separator
    "(function(){var poem='xray\\noscar';return poem.split('\\n').map(function(l){return l[0];}).join(',');})()",
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
    for i, payload in enumerate(BOUNDS):
        hit = find_credential(payload) is not None
        ok = not hit
        print("bound-%d: %s" % (i, "HELD(bound-ok)" if ok else "BREAK(bound-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
