#!/usr/bin/env python3
"""Red-first for F1067: structuredClone non-flat argument forms.

F1036 (CLOSED) models only `String.fromCharCode(...structuredClone([codes]))`
(the flat int-array form). Cloning a nested object
(`structuredClone({a:[ints],b:[ints]})` read back via `...O.a,...O.b`) or a
fragment string (`structuredClone("f1|f2").split("|").join("")`) assembles
node-exactly (v24.20.0) but misses the hook grammar.
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


def _halves(s):
    h = len(s) // 2
    return "[" + ",".join(str(ord(c)) for c in s[:h]) + "]", \
           "[" + ",".join(str(ord(c)) for c in s[h:]) + "]"


def _frags(s):
    return '"%s"' % s[:3], '"%s"' % s[3:]


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        a, b = _halves(secret)
        out.append((
            "f1067-%s-nested-obj" % tag,
            "var O=structuredClone({a:%s,b:%s});"
            "var RESULT=String.fromCharCode(...O.a,...O.b);" % (a, b)))
        f1, f2 = _frags(secret)
        out.append((
            "f1067-%s-string-split" % tag,
            "var S=structuredClone(%s+\"|\"+%s);var RESULT=S.split(\"|\").join(\"\");" % (f1, f2)))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: F1036's flat int-array form is modeled -- blocks coded.
    ("aa-f1036-flat-blocks",
     "var RESULT=String.fromCharCode(...structuredClone(%s));" % _codes(SECRET_S), True),
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
