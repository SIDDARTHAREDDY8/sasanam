#!/usr/bin/env python3
"""Red-first for F1086: while-loop accumulation reads (pre-test and post-test).

Pre-test `while` and post-test `do...while` accumulation loops break the
decoder's statement-anchored hook grammars: `var C=[...];var S='';var i=0;
while(i<C.length){S+=String.fromCharCode(C[i]);i++;}var RESULT=S;` and
`var C=[...];var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}
while(I<C.length);var RESULT=S;` assemble node-exactly (v24.20.0) while
find_credential MISSES, in both the braced and braceless forms. The
F1028/F1029 accum-loop parser models only `for` loops, so neither while
form is covered. The pre-test for-loop twin blocks coded. Filed
2026-10-10 11:35 UTC wave-399 (coverage analysis round 67, local node
validation, $0.00 model spend (0 paid calls)). Prints BREAK on the open
tree.
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
            "f1080-%s-dowhile-braced" % tag,
            ("var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}"
             "while(I<C.length);var RESULT=S;") % c))
        out.append((
            "f1080-%s-dowhile-braceless" % tag,
            ("var C=%s;var S='';var I=0;do S+=String.fromCharCode(C[I++]);"
             "while(I<C.length);var RESULT=S;") % c))
        out.append((
            "f1080-%s-while-braced" % tag,
            ("var C=%s;var S='';var I=0;while(I<C.length)"
             "{S+=String.fromCharCode(C[I]);I++;}var RESULT=S;") % c))
        out.append((
            "f1080-%s-while-braceless" % tag,
            ("var C=%s;var S='';var I=0;while(I<C.length)"
             "S+=String.fromCharCode(C[I++]);var RESULT=S;") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the pre-test for-loop twin is modeled -- blocks coded.
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
