#!/usr/bin/env python3
"""Red-first for F889: undefined helper escapes find_credential as NameError.

F889 (filed 2026-10-09 05:41 UTC, wave-386 lane 2 spec-axis review
catch; renumbered from F829 at the wave-386 merge):
_js_parse_f659_yield_star_array is CALLED inside
_js_parse_f6xx_fixed_yield_body but was never DEFINED -- every
`yield* ['LIT',...];` shape reaching it escaped find_credential as
a NameError (DoS vector: embedders calling find_credential on
untrusted text get an unhandled exception). Pre-existing on the
wave-385 base, not a lane regression.

Wave-387 defines the helper (F659 array delegation, node-exact
v24.20.0: `yield* ARR` yields each element in order). On the closed
tree this prints HELD (fails closed returning None -- the outer
`.next().value` chain is unmodeled -- or decodes node-exactly);
on the open tree it prints RAISED.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential, _decoded_variants  # noqa: E402

SHAPE = ("(function(){function* b(){yield* ['f1','f2'];}var it=b();"
         "return it.next().value+it.next().value;})()")


def main():
    breaks, held = 0, 0
    raised = None
    try:
        r = find_credential(SHAPE)
    except NameError as e:
        raised = "NameError (%s)" % e
    except Exception as e:  # noqa: BLE001 -- loud, never silent
        raised = "%r" % e
    if raised is not None:
        print("f889-shape: RAISED %s" % raised)
        breaks += 1
    else:
        print("f889-shape: HELD (returned %r, no exception)" % (r,))
        held += 1
        # The defined helper must actually parse the delegation: the
        # spread-copy route decodes the yields node-exactly.
        variants = list(_decoded_variants(
            "[...(function*(){yield* ['f1','f2'];})()].join('')"))
        spread_ok = any("f1" in v and "f2" in v for v in variants)
        print("f889-spread-decodes: %s (%d variants)"
              % ("HELD(decodes)" if spread_ok else "BREAK(miss)",
                 len(variants)))
        if spread_ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
