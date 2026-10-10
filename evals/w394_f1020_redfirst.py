#!/usr/bin/env python3
"""Red-first for F1020: tagged-template substitution.

function t(s,v){return s[0]+v+s[1]} + t`frag${frag}` assembles
node-exactly; no tagged-template-with-substitution production was
modeled (F463 models tag templates only when literal-only -- any
${ fails closed there). Short form verified. -- unmodeled; all
shapes node-verified (v24.20.0).
Filed 2026-10-10 04:11 UTC wave-393 (attack round 61, local node validation,
$0.00 model spend (0 paid calls)).
Prints HELD when a payload is BLOCKED (closed tree), FAIL when it MISSES.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1020-s0",
     'function t(s,v){return s[0]+v+s[1]}var f="3456789abcdef";var RESULT=t`xoxb-012${f}`;'),
    ("f1020-40char",
     'function t(s,v){return s[0]+v+s[1]}var f="b-0123456789abcdef0123456789abcdef012";var RESULT=t`xox${f}`;'),
    ("f1020-litsubst",
     'function t(s,v){return s[0]+v+s[1]}var RESULT=t`xoxb-012${"3456789abcdef"}`;'),
    ("f1020-renamed",
     'function tag(a,b){return a[0]+b+a[1]}var f="3456789abcdef";var RESULT=tag`xoxb-012${f}`;'),
    ("f1020-twolit",
     'function t(s,v){return s[0]+v+s[1]}var f="3456789abcdef";var RESULT=t`xoxb-012${f}!!`;'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("plain-twin-blocks", 'var RESULT="xoxb-012"+"3456789abcdef";', True),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("HELD " if hit else "FAIL ") + name)
        if not hit:
            fails.append(name)
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
