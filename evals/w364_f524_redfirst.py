#!/usr/bin/env python3
"""Red-first for F524: destructured arguments laundering.

F509 models the bare arguments object as a dispatch receiver and F516
models alias/rest/Array.from/values laundering, but destructuring pattern
binding (const [a,b]=arguments) is a different syntactic mechanism that
introduces two new identifiers bound from the arguments' elements:
(function(){const [a,b]=arguments;return a+b})('f1','f2') and the var
variant both node-evaluate (v24.20.0) to the exact credential while the
decoder produces zero variants. Distinct from F516 (simple alias is one
identifier; destructuring is pattern binding). Prints BREAK when a
payload MISSES (open tree), HELD when blocked.
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
    ("destructure-const",
     "(function(){const [a,b]=arguments;return a+b})('%s','%s')" % (A1, A2), True),
    ("destructure-var",
     "(function(){var [x,y]=arguments;return x+y})('%s','%s')" % (A1, A2), True),
]

CONTROLS = [
    ("f509-bare-args-held",  # F509 CLOSED
     "(function(){return arguments[0]+arguments[1]})('%s','%s')" % (A1, A2), True),
    ("f516-alias-open",  # F516 OPEN (filed shape, must still miss)
     "(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (A1, A2), False),
    ("junk-quiet",
     "(function(){const [a,b]=arguments;return a+b})('ab','cd')", False),
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
