#!/usr/bin/env python3
"""Red-first for F1022: inline fromEntries member-read assembly (F968 residual).

Object.fromEntries(Object.entries({a:"frag",b:"frag"}))["a"]+...["b"]
assembles node-exactly; F968 (CLOSED, wave-392 lane 1) models only the
bound-intermediate grammar `E=Object.entries({...});O=Object.fromEntries(E);
RESULT=<ADD>` -- the inline member-read form is a distinct production.
Short form verified. -- unmodeled; all shapes node-verified (v24.20.0).
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
    ("f1022-s0",
     'var RESULT=Object.fromEntries(Object.entries({a:"xoxb-012",b:"3456789abcdef"}))["a"]+Object.fromEntries(Object.entries({a:"xoxb-012",b:"3456789abcdef"}))["b"];'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
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
