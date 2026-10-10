#!/usr/bin/env python3
"""Red-first for F1086: while-loop accumulation reads (wave-400 lane 2).

Post-test `do...while` (braced/braceless) and braceless pre-test `while`
accumulation loops break the decoder's statement-anchored hook grammars
(the F1028/F1029 accum-loop parser models only `for` loops, and F1074's
while parser requires a braced body). The 2 braced pre-test while twins
are already blocked node-exactly by F1074's hook (partial incidental
closure, documented in the F1086 entry) -- they are controls here, and
the lane hook is verified disjoint from them at the hook level.

Filed 2026-10-10 (wave-399 attack round 67, renumbered at wave-399 merge;
local node validation, $0.00 model spend (0 paid calls)). Prints BREAK on
the open tree for the 6 still-open shapes.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

try:
    from gov.dlp import _js_f1086_stmt_decode  # noqa: E402
except ImportError:
    _js_f1086_stmt_decode = None

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        out.append((
            "f1086-%s-dowhile-braced" % tag,
            ("var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}"
             "while(I<C.length);var RESULT=S;") % c))
        out.append((
            "f1086-%s-dowhile-braceless" % tag,
            ("var C=%s;var S='';var I=0;do S+=String.fromCharCode(C[I++]);"
             "while(I<C.length);var RESULT=S;") % c))
        out.append((
            "f1086-%s-while-braceless" % tag,
            ("var C=%s;var S='';var I=0;while(I<C.length)"
             "S+=String.fromCharCode(C[I++]);var RESULT=S;") % c))
    return out


SHAPES = _shapes()

# The 2 braced pre-test while twins are F1074's (blocked on the open
# tree); the lane hook must MISS them at the hook level (disjointness).
BRACED_TWINS = []
for _tag, _secret in (("s", SECRET_S), ("l", SECRET_L)):
    _c = _codes(_secret)
    BRACED_TWINS.append(
        ("var C=%s;var S='';var I=0;while(I<C.length)"
         "{S+=String.fromCharCode(C[I]);I++;}var RESULT=S;") % _c)

CONTROLS = [
    ("aa-for-loop-blocks",
     ("var C=%s;var S='';for(var i=0;i<C.length;i++)"
      "{S+=String.fromCharCode(C[i]);}var RESULT=S;") % _codes(SECRET_S),
     True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("FAIL " if hit else "BREAK ") + name)
        if hit:
            fails.append(name)
    for i, payload in enumerate(BRACED_TWINS):
        hit = find_credential(payload) is not None
        if _js_f1086_stmt_decode is None:
            # Open tree: the lane hook does not exist yet; the twins are
            # blocked by F1074's hook (partial incidental closure).
            ok = hit
        else:
            hook_miss = _js_f1086_stmt_decode(payload) is None
            ok = hit and hook_miss
        print(("ctrl-ok " if ok else "CTRL-FAIL ") +
              "braced-while-twin-f1074-%d" % i)
        if not ok:
            fails.append("braced-while-twin-%d" % i)
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL"
          % (len(SHAPES), len(BRACED_TWINS) + len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
