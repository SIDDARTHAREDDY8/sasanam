#!/usr/bin/env python3
"""Red-first for F475: filter over-decode on mixed-type arrays (FP direction).

The bounded static JS-expression decoder coerces numeric array elements
to strings at parse time (`str(num)` in `_js_parse_primary`), losing
type provenance. Type-dependent `.filter` predicates -- `x.length>0`
(F447 form), `x.match(/[a-z]/)` and `x.charCodeAt(IDX) OP K` (F470
forms) -- are then evaluated as if every element were a string:

  ['a',1].filter(x=>x.length>0).join('')         decoder 'a1', node 'a'
  [1,2].filter(x=>x.length>0).join('')          decoder '12', node ''
  Array(2).fill(1).filter(x=>x.length>0).join('') decoder '11', node ''
  ['a',1].filter(x=>x.match(/[a-z]/)).join('')   decoder 'a',  node THROWS
  ['a',1].filter(x=>x.charCodeAt(0)>47).join('') decoder 'a1', node THROWS

(all node ground truths verified on node v24.20.0). The decoder claims
text the real engine never produces (or produces while the engine
throws) -- a false-positive-direction over-claim. Pre-existing on the
wave-354 base (surfaced by the wave-354 merge lane, not introduced by
any closure).

Type-INDEPENDENT predicates are unaffected and stay decodable:
  ['a',1].filter(x=>x!=='').join('')  'a1' both
  ['a',1].filter(Boolean).join('')    'a1' both
  ['a','b'].filter(x=>x.length>0)     'ab' both (pure-string arrays)

Prints BREAK when the over-decode is present (open tree), HELD when the
decoder fails closed (closed tree). Controls pin the unaffected shapes.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential, _try_js_expr_decode_all  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
C9 = "xoxb-" + "a" * 9    # 9 hex chars: below the dlp-slack-token floor
C10 = "xoxb-" + "a" * 10  # 10 hex chars: credential-shaped

# Seam-level probe: (name, payload, node_quiet).
# BREAK(fp) when the scanner fires but the real engine's output text is
# NOT credential-shaped. The '1' element is dropped by node (1..length
# is undefined, undefined>0 is false) but kept by the string-coerced
# decoder, so only the decoder's over-decode reaches the 10-hex floor.
SEAM_SHAPES = [
    ("plen-fp",
     "['%s',1].filter(x=>x.length>0).join('')" % C9,
     True),  # decoder 'C9'+'1' (10 hex, fires); node 'C9' (9, quiet)
]

# Decode-divergence probes: (name, payload, node_ground_truth).
# BREAK when the decoder emits a variant for the whole expression that
# the engine would never produce (wrong text, or the engine throws).
# Node truths verified on node v24.20.0.
DECODE_SHAPES = [
    ("plen-allnum",
     "[1,2].filter(x=>x.length>0).join('')",
     ""),          # decoder '12'; node '' (both dropped)
    ("plen-fillnum",
     "Array(2).fill(1).filter(x=>x.length>0).join('')",
     ""),          # decoder '11'; node ''
    ("match-throws",
     "['a',1].filter(x=>x.match(/[a-z]/)).join('')",
     "throws"),    # decoder 'a'; node TypeError on (1).match
    ("ccmp-throws",
     "['a',1].filter(x=>x.charCodeAt(0)>47).join('')",
     "throws"),    # decoder 'a1'; node TypeError on (1).charCodeAt
]

CONTROLS = [
    # (name, payload, want_hit) -- must hold on open AND closed trees.
    # NOTE: the pure-string controls embed credential-shaped literals;
    # they fire on the raw text on both trees -- the point is the fix
    # does not regress pure-string decoding.
    ("pure-string-length-still-decodes",
     "['%s',''].filter(x=>x.length>0).join('')" % C10, True),
    ("type-independent-neq-still-decodes",
     "['%s',1].filter(x=>x!=='').join('')" % C9, True),
    ("type-independent-boolean-still-decodes",
     "['%s',1].filter(Boolean).join('')" % C10, True),
    ("junk-quiet", "['ab',1].filter(x=>x.length>0).join('')", False),
]


def main():
    breaks, held = 0, 0
    for name, payload, node_quiet in SEAM_SHAPES:
        hit = find_credential(payload) is not None
        # BREAK(fp): scanner fires where the engine yields no credential
        # text.
        is_break = hit and node_quiet
        print("%s: %s (scanner_hit=%s node_quiet=%s)" % (
            name, "BREAK(fp)" if is_break else "HELD(fail-closed)",
            hit, node_quiet))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, node_out in DECODE_SHAPES:
        decoded = _try_js_expr_decode_all(payload)
        # BREAK when the decoder emits a whole-expression variant the
        # engine would never produce (wrong text, or engine throws).
        is_break = decoded is not None
        print("%s: %s (decoded=%r node=%r)" % (
            name, "BREAK(diverges)" if is_break else "HELD(fail-closed)",
            decoded, node_out))
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
