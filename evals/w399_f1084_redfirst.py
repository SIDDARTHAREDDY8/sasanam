#!/usr/bin/env python3
"""Red-first for F1084: comma-operator chain staging reads.

Using the comma operator to chain the accumulation step breaks the
decoder's statement-anchored hook grammars: `var C=[...];var S='';var
I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I++);var RESULT=S;`
(the accumulation rides the for-update clause as a comma expression)
and the `while(I<C.length){I++,S+=String.fromCharCode(C[I-1]);}` twin
both assemble node-exactly (v24.20.0) while find_credential MISSES.
The plain for-loop twin blocks coded. Filed 2026-10-10 11:35 UTC
wave-399 (coverage analysis round 67, local node validation, $0.00
model spend (0 paid calls)). Prints BREAK on the open tree.
"""
import os, sys

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
            "f1084-%s-comma-for-update" % tag,
            ("var C=%s;var S='';var I=0;"
             "for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I++);"
             "var RESULT=S;") % c))
        out.append((
            "f1084-%s-while-comma-body" % tag,
            ("var C=%s;var S='';var I=0;"
             "while(I<C.length){I++,S+=String.fromCharCode(C[I-1]);}"
             "var RESULT=S;") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the plain for-loop twin is modeled -- blocks coded.
    ("aa-for-loop-blocks",
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
