#!/usr/bin/env python3
"""Red-first for F1092: array-spread object rest source (wave-400 lane 2).

Spreading an ARRAY (not an object literal or object-typed variable) into
the rest object (`var P={...[65,66,...]};`) breaks the F1088 hook's
source grammar: integer-indexed array elements spread to integer keys,
so `Object.values` reads them back in order. Filed 2026-10-10 13:38 UTC
(wave-400 lane 2 self-file; local node validation, $0.00 model spend
(0 paid calls)). Prints BREAK on the open tree.
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
            "f1092-%s-spread-array-lit" % tag,
            "var P={...%s};var S=String.fromCharCode(...Object.values(P));"
            "var RESULT=S;" % c))
        out.append((
            "f1092-%s-spread-array-var" % tag,
            "var A=%s;var P={...A};"
            "var S=String.fromCharCode(...Object.values(P));"
            "var RESULT=S;" % c))
    return out


SHAPES = _shapes()

def _litobj(s):
    return "{" + ",".join("%d:%d" % (i, ord(ch))
                          for i, ch in enumerate(s)) + "}"


CONTROLS = [
    # AA: the object-literal spread twin blocks coded (F1088).
    ("aa-objlit-spread-blocks",
     ("var P={...%s};"
      "var S=String.fromCharCode(...Object.values(P));"
      "var RESULT=S;") % _litobj(SECRET_S), True),
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
