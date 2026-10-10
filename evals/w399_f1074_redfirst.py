#!/usr/bin/env python3
"""Red-first for F1074 (wave-399 lane 1): labeled-statement accumulation reads.

A label prefix (`lbl:`) before a for loop, a while loop, or a block breaks
the decoder's statement-anchored hook grammars: all three filed shapes
assemble node-exactly (v24.20.0) while find_credential MISSES on the open
tree. Prints BREAK per shape on the open tree; the wave-399 lane-1 closure
must flip every shape to blocked. Capture via Python subprocess only
(wave-392 lesson).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        out.append((
            "f1074-%s-label-for" % tag,
            ("var C=%s;var S='';lbl: for(var i=0;i<C.length;i++)"
             "{S+=String.fromCharCode(C[i]);}var RESULT=S;") % c))
        out.append((
            "f1074-%s-label-while" % tag,
            ("var C=%s;var S='';var i=0;lbl: while(i<C.length)"
             "{S+=String.fromCharCode(C[i]);i++;}var RESULT=S;") % c))
        out.append((
            "f1074-%s-label-block" % tag,
            ("var C=%s;var S='';lbl: {for(var i=0;i<C.length;i++)"
             "{S+=String.fromCharCode(C[i]);}}var RESULT=S;") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the unlabeled for-loop twin is modeled -- blocks coded.
    ("aa-unlabeled-for-blocks",
     ("var C=%s;var S='';for(var i=0;i<C.length;i++)"
      "{S+=String.fromCharCode(C[i]);}var RESULT=S;") % _codes(SECRET_S), True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
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
