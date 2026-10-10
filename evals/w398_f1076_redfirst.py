#!/usr/bin/env python3
"""Red-first for F1076: Function-constructor body staging (F964 residual).

F964 (CLOSED) models `new Function('p1',...,'pn','return p1+...+pn;')` --
the param-passing form. Staging the accumulation loop INSIDE the Function
body string (`new Function("C","var S='';for(var
i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}return S;")` then calling
it with the int array) assembles node-exactly (v24.20.0) while
find_credential MISSES. The direct-codes body twin blocks coded. No eval is
performed by the scanner; the model is pure static text. Filed 2026-10-10
10:43 UTC wave-398 (attack round 66, local node validation, $0.00 model
spend (0 paid calls)). Prints BREAK on the open tree.
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
            "f1076-%s-fn-body-loop" % tag,
            ("var F=new Function(\"C\",\"var S='';for(var i=0;i<C.length;i++)"
             "{S+=String.fromCharCode(C[i]);}return S;\");"
             "var RESULT=F(%s);") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the direct-codes Function body twin is modeled -- blocks coded.
    ("aa-fn-body-codes-blocks",
     ("var F=new Function(\"return String.fromCharCode(%s);\");"
      "var RESULT=F();") % ",".join(str(ord(x)) for x in SECRET_S), True),
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
