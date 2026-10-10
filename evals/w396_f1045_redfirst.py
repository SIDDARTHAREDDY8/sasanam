#!/usr/bin/env python3
"""Red-first for F1045: Object.setPrototypeOf proto-chain member reads.

var p={a:[codes]};var o=Object.setPrototypeOf({},p);
var RESULT=String.fromCharCode(...o.a); assembles node-exactly via the
prototype chain; distinct vs F1005 (CLOSED: Object.create-based reads -- its
hook requires the Object.create line) -- no setPrototypeOf production modeled.
Filed 2026-10-10 06:45 UTC wave-395 (attack round 63, local node validation,
$0.00 model spend (0 paid calls)). Re-verified wave-396 lane 4 with
node-verified generalizations (inline proto literal, direct proto reads,
bracket reads, proto string member). All shapes decode to credential-shaped
strings (xoxb-...); the output filter redacts them.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
Capture via Python subprocess only (wave-392 lesson).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# char codes for "xoxb-[credential]"
CODES = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
         97, 98, 99, 100, 101, 102]


def _arr(codes):
    return "[" + ",".join(str(c) for c in codes) + "]"


SHAPES = [
    ("f1045-s0",
     'var p={a:%s};var o=Object.setPrototypeOf({},p);var RESULT=String.fromCharCode(...o.a);' % _arr(CODES)),
    ("f1045-s1",
     'var p={a:%s};var o=Object.setPrototypeOf({},p);var RESULT=String.fromCharCode(...o.a);'
     % _arr(CODES + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99,
                     100, 101, 102, 48, 49, 50])),
    # generalizations (node-verified v24.20.0; all decode credential-shaped)
    ("f1045-g-inline-proto",
     'var o=Object.setPrototypeOf({},{a:%s});var RESULT=String.fromCharCode(...o.a);' % _arr(CODES)),
    ("f1045-g-direct-proto-read",
     'var p={a:%s};var o=Object.setPrototypeOf({},p);var RESULT=String.fromCharCode(...p.a);' % _arr(CODES)),
    ("f1045-g-bracket-read",
     'var p={a:%s};var o=Object.setPrototypeOf({},p);var RESULT=String.fromCharCode(...o["a"]);' % _arr(CODES)),
    # NOTE: var p={s:"xoxb-..."};var o=Object.setPrototypeOf({},p);var RESULT=o.s
    # is already HELD on the open tree (existing proto member-read
    # production) -- not an F1045 shape.
    ("f1045-g-let",
     'let p={a:%s};let o=Object.setPrototypeOf({},p);let RESULT=String.fromCharCode(...o.a);' % _arr(CODES)),
    # Spec-review generalization: array-valued own key resolves own-first
    ("f1045-g-array-own",
     'var p={a:%s};var o=Object.setPrototypeOf({a:%s},p);var RESULT=String.fromCharCode(...o.a);'
     % (_arr(CODES), _arr(CODES))),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    # setPrototypeOf with no credential material stays quiet.
    ("proto-no-credential-quiet",
     'var p={a:[1,2,3]};var o=Object.setPrototypeOf({},p);var RESULT="done";',
     False),
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
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
