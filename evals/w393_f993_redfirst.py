#!/usr/bin/env python3
"""Red-first for F993: RegExp.source reads.

new RegExp(frag).source concatenations assemble node-exactly (v24.20.0);
V8 escapes "/", LF, CR, U+2028/U+2029 in .source and maps "" to "(?:)",
so those fail closed. Prints BREAK when a payload MISSES (open tree),
HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f993-s0",
     'var r=new RegExp("xoxb-0123");var RESULT=r.source+"456789abcdef";'),
    ("f993-s1",
     'var r=new RegExp("xox");var RESULT=r.source+"b-0123456789abcdef0123456789abcdef012";'),
    # generalizations (all node-verified v24.20.0; all credential-shaped)
    ("f993-g-flags", 'var r=new RegExp("xoxb-0123","gi");var RESULT=r.source+"456789abcdef";'),
    ("f993-g-dot", 'var r=new RegExp("xoxb-0123456789");var RESULT=r.source+".abcdef";'),
    ("f993-g-bracket", 'let r=RegExp("xoxb-0123456789");var RESULT=r["source"]+" abcdef";'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("twin-plain-fcc-blocks", 'var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);', True),
    ("slash-fails-closed", 'var r=new RegExp("a/b");var RESULT=r.source;', False),
    ("empty-fails-closed", 'var r=new RegExp("");var RESULT=r.source;', False),
    ("newline-fails-closed", 'var r=new RegExp("a\\nb");var RESULT=r.source;', False),
    ("unbalanced-fails-closed", 'var r=new RegExp("(ab");var RESULT=r.source;', False),
    ("quantifier-fails-closed", 'var r=new RegExp("a*b");var RESULT=r.source;', False),
]


def _check(payload, expect_block):
    hit = find_credential(payload) is not None
    return hit == expect_block, hit


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        ok = not hit
        print(("BREAK " if ok else "FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    for name, payload, expect_block in CONTROLS:
        ok, hit = _check(payload, expect_block)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
