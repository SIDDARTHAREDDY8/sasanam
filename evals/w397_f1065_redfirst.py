#!/usr/bin/env python3
"""Red-first for F1065: generator function-declaration accumulation reads.

`function* g(){for(var i=0;i<C.length;i++)yield C[i];}` (named declaration
yielding from an external int array) consumed by for-of / for-await-of with
fromCharCode accumulation assembles node-exactly (v24.20.0). The decoder's
generator productions model only inline-int-literal generators:
F1026 (CLOSED) requires `var|let G=function*(){yield <ints>;}` and F1031
(CLOSED) requires `async function*GEN(){(yield INT;)+}` -- a declaration
iterating an array misses both grammars.
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
            "f1065-%s-sync-decl" % tag,
            ("var C=%s;function* g(){for(var i=0;i<C.length;i++)yield C[i];}"
             "var S='';for(var x of g())S+=String.fromCharCode(x);var RESULT=S;") % c))
        out.append((
            "f1065-%s-async-decl" % tag,
            ("var C=%s;(async function(){async function* g(){for(var i=0;i<C.length;i++)yield C[i];}"
             "var S='';for await(var x of g())S+=String.fromCharCode(x);return S;})()"
             ".then(v=>{globalThis.RESULT=v;});") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: F1026's inline-int-literal generator form is modeled -- blocks coded.
    ("aa-f1026-inline-blocks",
     "var G=function*(){%s;};var S='';for(var x of G()){S+=String.fromCharCode(x);}"
     "var RESULT=S;" % ";".join("yield %d" % ord(c) for c in SECRET_S), True),
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
