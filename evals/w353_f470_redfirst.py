#!/usr/bin/env python3
"""Red-first for F470: method-call-result .filter predicates bypass the
bounded static JS-expression decoder's truthiness-preserving predicate
model.

F447 (closed, wave-350 lane 2) models truthiness-preserving predicates as
syntactic falsiness tests over parsed strings: x=>x!=='' , x=>!!x,
x=>x.length>0, x=>x. A predicate whose truthiness comes from a METHOD CALL
result is unmodeled and not in F447's documented residuals:

- ['frag1','frag2',''].filter(x=>x.match(/[a-z]/)).join('') -- match()
  returns a truthy array for strings containing [a-z], null for '';
- ['frag1','frag2'].filter(x=>x.charCodeAt(0)>47).join('') -- a
  method-call-result comparison, constant-true over the fragment domain.

Both node-evaluate to the credential (node v24.20.0 verified) while the
scanner misses; the plain credential blocks coded. Distinct from F447's
modeled direct-truthiness forms, from F459 (positional predicates, open),
and from F467 (null-comparison predicates, open).

Prints BREAK when a payload MISSES (open tree), HELD when blocked.
Controls: plain credential blocks coded; junk variant quiet; the
neighboring closed F447 shape (x=>x!=='') blocks.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "4567" + "89abcdef"

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("match-truthiness",
     "['%s','%s',''].filter(x=>x.match(/[a-z]/)).join('')" % (A1, A2),
     True),
    ("charcode-comparison",
     "['%s','%s'].filter(x=>x.charCodeAt(0)>47).join('')" % (A1, A2),
     True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet",
     "['ab','cd',''].filter(x=>x.match(/[a-z]/)).join('')", False),
    ("neighbor-f447-blocks",
     "['%s','%s',''].filter(x=>x!=='').join('')" % (A1, A2), True),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
