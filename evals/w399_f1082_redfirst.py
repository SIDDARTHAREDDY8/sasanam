#!/usr/bin/env python3
"""Red-first for F1082: object-spread rest staging reads.

Staging the int array through an object-spread rest object breaks the
decoder's int-array productions: `var P={...{0:c0,1:c1,...}};var
S=String.fromCharCode(...Object.values(P));var RESULT=S;` assembles
node-exactly (v24.20.0, integer-index keys read back in ascending order)
while find_credential MISSES, for both inline-literal and
variable-source spreads. The plain int-array spread twin blocks coded.
Filed 2026-10-10 11:35 UTC wave-399 (coverage analysis round 67, local
node validation, $0.00 model spend (0 paid calls)). Prints BREAK on the
open tree.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _litobj(s):
    return "{" + ",".join("%d:%d" % (i, ord(ch))
                           for i, ch in enumerate(s)) + "}"


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        out.append((
            "f1082-%s-spread-inline-lit" % tag,
            "var P={...%s};var S=String.fromCharCode(...Object.values(P));"
            "var RESULT=S;" % _litobj(secret)))
        out.append((
            "f1082-%s-spread-var-source" % tag,
            "var Q=%s;var P={...Q};"
            "var S=String.fromCharCode(...Object.values(P));"
            "var RESULT=S;" % _litobj(secret)))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the plain int-array spread twin is modeled -- blocks coded.
    ("aa-plain-spread-blocks",
     ("var C=%s;var S=String.fromCharCode(...C);"
      "var RESULT=S;") % _codes(SECRET_S), True),
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
