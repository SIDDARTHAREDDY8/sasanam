#!/usr/bin/env python3
"""Red-first for F1077: import()-staged int-array fragment reads (F959d residuals).

F959d (CLOSED wave-391) models `var m=await
import('data:text/javascript,export default "L";')` with `m.default`
substitution for STRING-literal defaults and additive tails. Two residuals
assemble node-exactly (v24.20.0) while find_credential MISSES:
  (a) `.then()`-chain consumption instead of top-level await
      (`import('data:...').then(m=>{...accumulate...})`);
  (b) an INT-ARRAY default export (`export default [c0,c1,...]`) read back
      via `String.fromCharCode(...M.default)` or an accumulation loop --
      the hook's substitution covers only string-literal defaults.
The F959d string-default twin blocks coded. Filed 2026-10-10 10:43 UTC
wave-398 (attack round 66, local node validation, $0.00 model spend
(0 paid calls)). Prints BREAK on the open tree.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"
_A = "xoxb-0123456789abcdef"
_B = "0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        out.append((
            "f1077-%s-import-then-loop" % tag,
            ("import('data:text/javascript,export default %s').then(m=>{var S='';"
             "for(var i=0;i<m.default.length;i++){S+=String.fromCharCode(m.default[i]);}"
             "var RESULT=S;});") % c))
        out.append((
            "f1077-%s-await-import-intspread" % tag,
            ("var M=await import('data:text/javascript,export default %s');"
             "var RESULT=String.fromCharCode(...M.default);") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: F959d's string-default await form is modeled -- blocks coded.
    ("aa-f959d-string-default-blocks",
     "var m=await import('data:text/javascript,export default \"%s\";');"
     "var RESULT=m.default+'%s';" % (_A, _B), True),
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
