#!/usr/bin/env python3
"""Red-first for F518: Array.prototype.reverse through .call dispatch.

F511 models splice.call/.apply dispatch. F518 (narrowed 2026-10-07,
wave-364 lane 4) covers the reverse-call shape: Array.prototype.reverse
returns the reversed array itself (node v24.20.0), so
Array.prototype.reverse.call([...]).join('') is closable without
dataflow -- and is now modeled (reverse joins _F478_ARRAY_METHODS, the
.call path routes through the existing _js_apply_method_at reverse
branch, the .apply/.bind value path is mirrored in
_js_apply_method_values). Prints BREAK when a payload MISSES (open
tree), HELD when blocked.

Scope note: the push/unshift .call shapes from the original filing are
NOT part of F518's closed scope. They require dataflow tracking (alias
resolution + mutation tracking: `var a=[...]; push.call(a,...);
a.join('')` assembles the credential in the mutated binding, exactly
like the direct form `var a=[...]; a.push(...); a.join('')` which this
battery already documents as a decoder design boundary). The dispatch
mechanism for push/unshift is deliberately not added -- node returns
the new length (a number), not the array, so modeling the call could
never flag the shapes; the dataflow requirement is a documented,
accepted decoder boundary (F306/F308 precedent). The push/unshift
probes below pin the boundary (expected miss), not a finding.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

# F518's closed scope: the reverse-call dispatch shape.
SHAPES = [
    ("reverse-call",
     "Array.prototype.reverse.call(['%s','%s']).join('')" % (A2, A1), True),
]

CONTROLS = [
    ("f511-splice-call-closed",  # F511 CLOSED wave-363 lane 4 (merge; wave-306)
     "Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (A1, A2), True),
    # Documented boundary (not filed): push/unshift .call on an aliased
    # local var needs dataflow tracking (same boundary as the direct
    # form below). Expected miss; pinned so a future change is loud.
    ("push-call-dataflow-miss",
     "var a=['%s'];Array.prototype.push.call(a,'%s');a.join('')" % (A1, A2), False),
    ("unshift-call-dataflow-miss",
     "var a=['%s'];Array.prototype.unshift.call(a,'%s');a.join('')" % (A2, A1), False),
    # NOTE: even DIRECT push on a local var misses (no dataflow tracking) --
    # that is a documented decoder boundary, not F518's dispatch scope.
    ("push-direct-dataflow-miss",
     "var a=['%s'];a.push('%s');a.join('')" % (A1, A2), False),
    ("arrlit-join-held",
     "['%s','%s'].join('')" % (A1, A2), True),
    ("junk-quiet",
     "var a=['ab'];Array.prototype.push.call(a,'cd');a.join('')", False),
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
