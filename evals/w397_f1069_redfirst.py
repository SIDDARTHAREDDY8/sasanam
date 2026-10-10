#!/usr/bin/env python3
"""Red-first for F1069: non-identifier fromCharCode spread receivers.

The decoder's int-array spread production requires the spread argument to be
a plain identifier bound to an int-array literal. Spreading a member
expression (`...r.deref().c` via WeakRef, `...globalThis.K`) or a rest
parameter (`(...a)=>String.fromCharCode(...a)`) assembles node-exactly
(v24.20.0) but misses the hook grammar.
Filed 2026-10-10 09:55 UTC wave-397 (attack round 65, local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
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
            "f1069-%s-weakref-deref" % tag,
            "var r=new WeakRef({c:%s});var RESULT=String.fromCharCode(...r.deref().c);" % c))
        out.append((
            "f1069-%s-globalthis-member" % tag,
            "globalThis.K=%s;var RESULT=String.fromCharCode(...globalThis.K);" % c))
        out.append((
            "f1069-%s-rest-param" % tag,
            "var f=(...a)=>String.fromCharCode(...a);var RESULT=f(...%s);" % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the plain-identifier spread twin is modeled -- blocks coded.
    ("aa-plain-spread-blocks",
     "var C=%s;var RESULT=String.fromCharCode(...C);" % _codes(SECRET_S), True),
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
