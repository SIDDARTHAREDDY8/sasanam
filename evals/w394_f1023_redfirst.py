#!/usr/bin/env python3
"""Red-first for F1023: statement-position fragility in F974-class decoders.

The F974 getter/symbol-key decoders (and the __proto__-literal production)
required the input to be EXACTLY the shape: any extra statement -- a
leading `var q=1;`, a leading comment, a lone `;`, "use strict", or a
trailing statement -- flipped the verdict HIT->MISS on the open tree.
4 shapes verified node-exact (v24.20.0).
Filed 2026-10-10 04:11 UTC wave-393 (attack round 61, local node
validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), FAIL when blocked
(closed tree); the merge-audit criterion is 0 ^BREAK lines.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1023-s0",
     'var q=1;\nvar o={get p(){return "xoxb-012"}};var RESULT=o.p+"3456789abcdef";'),
    ("f1023-s1",
     'var o={get p(){return "xoxb-012"}};var RESULT=o.p+"3456789abcdef";\nvar q=1;'),
    ("f1023-s2",
     '// decoy\nvar k=Symbol("k");var o={};o[k]="xoxb-012";var RESULT=o[k]+"3456789abcdef";'),
    ("f1023-s3",
     'var o={__proto__:{p:"xoxb-012"}};var RESULT=o.p+"3456789abcdef";\n;'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("bare-getter-blocks", 'var o={get p(){return "xoxb-012"}};var RESULT=o.p+"3456789abcdef";', True),
]


def _check(payload, expect_block):
    hit = find_credential(payload) is not None
    return hit == expect_block, hit


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        ok = not hit
        print(("BREAK " if ok else "FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    for name, payload, expect_block in CONTROLS:
        ok, hit = _check(payload, expect_block)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS),
                                              len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
