#!/usr/bin/env python3
"""Red-first for F616: variable-bound (non-literal) parameter names in
URLSearchParams statement-form mutations.

F599 (wave-372 lane 3, CLOSED) models append/set statement-form mutations
with LITERAL parameter names; F606 (OPEN) covers unmodeled mutation
STATEMENTS with literal names. But the NAME binding axis is unmodeled: when
the parameter name is variable-bound (`var q='q'`), the mutation model
misses: the three shapes below all node-evaluate to the exact credential
(v24.20.0) while the decoder produces zero variants. Distinct from F599
(literal names, CLOSED), F606 (statement coverage, OPEN), and F576 (.get,
CLOSED).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    ("nonliteral-append-getall",
     "(function(){var p=new URLSearchParams('');var q='q';p.append(q,'" + A1 + "');"
     "p.append(q,'" + A2 + "');return p.getAll(q).join('');})()", True),
    ("nonliteral-append-literal-getall",
     "(function(){var p=new URLSearchParams('');var q='q';p.append(q,'" + A1 + "');"
     "p.append(q,'" + A2 + "');return p.getAll('q').join('');})()", True),
    ("nonliteral-set-get",
     "(function(){var p=new URLSearchParams('q=xx');var k='q';p.set(k,'" + A1 + "');"
     "return p.get(k)+'" + A2 + "';})()", True),
]

CONTROLS = [
    ("literal-append-getall-blocked",
     "(function(){var p=new URLSearchParams('');p.append('q','" + A1 + "');"
     "p.append('q','" + A2 + "');return p.getAll('q').join('');})()", True),
    ("nonliteral-get-fails-closed",
     "(function(){var p=new URLSearchParams('q=%s%s');var k='q';"
     "return p.get(k);})()" % (A1, A2), True),
    ("junk-quiet",
     "\"(function(){var s='ab';return s;})()\"", False),
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
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
