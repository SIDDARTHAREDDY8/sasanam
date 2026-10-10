#!/usr/bin/env python3
"""Red-first for F1083: Object.create prototype-staged reads.

Staging the int array on the PROTOTYPE via `Object.create` breaks the
decoder's int-array productions, which require a plain-identifier array
binding: `var P={k:[...]};var O=Object.create(P);var S='';for(var
I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;`
assembles node-exactly (v24.20.0, member reads delegate to the
prototype) while find_credential MISSES. The own-property twin blocks
coded. Disjoint from F1045 (Object.setPrototypeOf, CLOSED wave-396).
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


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        out.append((
            "f1083-%s-create-proto-read" % tag,
            ("var P={k:%s};var O=Object.create(P);var S='';"
             "for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}"
             "var RESULT=S;") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the own-property twin is modeled -- blocks coded.
    ("aa-plain-ident-loop-blocks",
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
