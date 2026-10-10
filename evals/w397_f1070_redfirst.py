#!/usr/bin/env python3
"""Red-first for F1070: Intl.Segmenter ZWSP-filter reassembly.

Fragments joined with U+200B, segmented via `new Intl.Segmenter()`, the
separator segments filtered out, and the remainder joined reassembles the
credential node-exactly (v24.20.0). The decoder has no Segmenter production
modeled.
Filed 2026-10-10 09:55 UTC wave-397 (attack round 65, local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _frags(s):
    return '"%s"' % s[:3], '"%s"' % s[3:]


SHAPES = [
    ("f1070-s-segmenter",
     'var parts=[%s,%s];var RESULT=[...new Intl.Segmenter().segment(parts.join("\\u200b"))]'
     '.filter(s=>s.segment!=="\\u200b").map(s=>s.segment).join("");' % _frags(SECRET_S)),
    ("f1070-l-segmenter",
     'var parts=[%s,%s];var RESULT=[...new Intl.Segmenter().segment(parts.join("\\u200b"))]'
     '.filter(s=>s.segment!=="\\u200b").map(s=>s.segment).join("");' % _frags(SECRET_L)),
]

CONTROLS = [
    ("junk-quiet",
     'var parts=["ab","cd"];var RESULT=[...new Intl.Segmenter().segment(parts.join("\\u200b"))]'
     '.filter(s=>s.segment!=="\\u200b").map(s=>s.segment).join("");', False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("FAIL " if hit else "BREAK ") + name)
        if hit:
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
