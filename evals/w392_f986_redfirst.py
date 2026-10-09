#!/usr/bin/env python3
"""Red-first for F986: guarded conditional assembly (if/else, ternary, void-||, typeof, instanceof).

Fragment assembly guarded by if/else branches, ternary branches, void 0||fallback, typeof-guards, and instanceof-guards evaluates node-exactly; the decoder has no guard-expression production.
Filed 2026-10-09 16:02 UTC wave-391 (attack round 59); lane battery for wave-392 closure.
Prints BREAK when a payload MISSES, HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_CRED40 = _F1 + _F2
_CODES = ",".join(str(ord(c)) for c in _CRED)

SHAPES = [
    ("f986-if",
     "var s='';if(1){s+='xoxb-0123';}else{s+='x';}s+='456789abcdef';var RESULT=s;"),
    ("f986-if-40",
     "var s='';if(1){s+='xox';}else{s+='x';}s+='b-0123456789abcdef0123456789abcdef012';var RESULT=s;"),
    ("f986-tern",
     "var RESULT=(1?'xoxb-0123':'x')+(0?'y':'456789abcdef');"),
    ("f986-void",
     "var s=void 0||'xoxb-0123';s+='456789abcdef';var RESULT=s;"),
    ("f986-typeof",
     'var RESULT=(typeof qq_zz==="undefined"?\'xoxb-0123\':\'x\')+\'456789abcdef\';'),
    # Generalization: instanceof-guard ternary (node-exact: [] instanceof Array).
    ("f986-instanceof",
     "var RESULT=([] instanceof Array?'xoxb-0123':'x')+'456789abcdef';"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-plain-concat-blocks",
     "'%s'+'%s'" % (_A, _B),
     True),
]

def _check(payload, expect_block):
    hit = find_credential(payload) is not None
    return hit == expect_block, hit

def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("HELD " if hit else "BREAK ") + name)
        if not hit:
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
