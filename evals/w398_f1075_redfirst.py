#!/usr/bin/env python3
"""Red-first for F1075: member-expression / with-scope int-array accumulation reads.

The decoder's int-array loop productions require a plain identifier bound to
an int-array literal. Reading through a member expression
(`O.v[i]` / `O['v'][i]`), through an alias of a member expression, or inside
a `with(O)` scope (where `v` resolves to `O.v`) assembles node-exactly
(v24.20.0) while find_credential MISSES. Plain-identifier spread receivers
are F1069's (OPEN) lane scope -- not filed here; only loop/indexed reads.
Filed 2026-10-10 10:43 UTC wave-398 (attack round 66, local node validation,
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
            "f1075-%s-with-loop" % tag,
            ("var O={v:%s};var S='';with(O){for(var i=0;i<v.length;i++)"
             "{S+=String.fromCharCode(v[i]);}}var RESULT=S;") % c))
        out.append((
            "f1075-%s-member-loop" % tag,
            ("var O={v:%s};var S='';for(var i=0;i<O.v.length;i++)"
             "{S+=String.fromCharCode(O.v[i]);}var RESULT=S;") % c))
    c = _codes(SECRET_S)
    out.append((
        "f1075-s-member-bracket",
        ("var O={v:%s};var S='';for(var i=0;i<O['v'].length;i++)"
         "{S+=String.fromCharCode(O['v'][i]);}var RESULT=S;") % c))
    out.append((
        "f1075-s-member-alias",
        ("var O={v:%s};var V=O.v;var S='';for(var i=0;i<V.length;i++)"
         "{S+=String.fromCharCode(V[i]);}var RESULT=S;") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: plain-identifier loop accumulation is modeled -- blocks coded.
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
