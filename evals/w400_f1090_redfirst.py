#!/usr/bin/env python3
"""Red-first for F1090: labeled while-loop accumulation (wave-400 lane 2).

A statement-position label prefix on the F1086 while-loop productions
(`lbl:do{...}while(...);`, `lbl:while(...)...;`) breaks the decoder's
statement-anchored hook grammars: F1074's label handling covers only its
own for/braced-while productions, and the F1086 hook parses no labels.
The label is inert (no break/continue in the text), so ignoring it would
be node-exact -- but no hook does. Filed 2026-10-10 13:38 UTC (wave-400
lane 2 self-file; local node validation, $0.00 model spend (0 paid
calls)). Prints BREAK on the open tree.
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
            "f1090-%s-labeled-dowhile" % tag,
            ("var C=%s;var S='';var I=0;lbl:do{S+=String.fromCharCode(C[I]);"
             "I++;}while(I<C.length);var RESULT=S;") % c))
        out.append((
            "f1090-%s-labeled-while-braceless" % tag,
            ("var C=%s;var S='';var I=0;lbl:while(I<C.length)"
             "S+=String.fromCharCode(C[I++]);var RESULT=S;") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the unlabeled twins block coded (F1086).
    ("aa-unlabeled-dowhile-blocks",
     ("var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}"
      "while(I<C.length);var RESULT=S;") % _codes(SECRET_S), True),
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
    print("%d shapes, %d controls, %d FAIL"
          % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
