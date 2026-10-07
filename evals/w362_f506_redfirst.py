#!/usr/bin/env python3
"""Red-first for F506: Reflect.apply invoked through Function.prototype.call/apply
indirection. F469 models dot-form Reflect.apply(Array.prototype.concat,...), F491
models Reflect.get named reads, and F504 models bracket member access on the Reflect
namespace -- but the apply function reached through a HIGHER-ORDER dispatch
(Function.prototype.apply.call(Reflect.apply, Reflect, [...]) or
Function.prototype.call.call(Reflect.apply, Reflect, ...)) bypasses all three
anchors: the dispatch target is Function.prototype.apply/.call, not the Reflect
namespace. All shapes node-evaluate (v24.20.0) to the exact credential while the
decoder produces zero variants. Prints BREAK when a payload MISSES (open tree),
HELD when blocked.
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
    ("fn-apply-indirect",
     "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (A1, A2), True),
    ("fn-call-indirect",
     "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("dot-form-proto-held",
     "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['ab','cd']]).join('')", False),
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
