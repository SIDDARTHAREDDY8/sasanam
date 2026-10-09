#!/usr/bin/env python3
"""Red-first for F945: eval with computed per-iteration args.

eval() called in a loop with per-iteration computed (concatenated) program strings resolves
node-exactly while the decoder produces zero variants. The F893 closure models only eval with a single
string-literal program (documented narrow grammar).
Filed 2026-10-09 12:32 UTC wave-389 (attack round 57).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
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
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"
_CRED = _A + _B
_CRED40 = _L1 + _L2
_CODES = ",".join(str(ord(c)) for c in _CRED)
_CODES40 = ",".join(str(ord(c)) for c in _CRED40)
_ADD = "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1) for c in _CRED)
_ADD40 = "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1) for c in _CRED40)
_ARRLIKE = ",".join("%d:%d" % (i, ord(c)) for i, c in enumerate(_CRED))
_PROPS = ",".join("p%d:%s" % (i, repr(c)) for i, c in enumerate(_CRED))
_PREAD = "+".join("o.p%d" % i for i in range(len(_CRED)))
_PROPS40 = ",".join("q%d:%s" % (i, repr(c)) for i, c in enumerate(_CRED40))
_PREAD40 = "+".join("o.q%d" % i for i in range(len(_CRED40)))

SHAPES = [
    ("s1-eval-loop",
     "(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=eval('String.fromCharCode('+c[i]+')');}return s;})()" % _CODES),
    ("s2-40char",
     "(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=eval('String.fromCharCode('+c[i]+')');}return s;})()" % _CODES40),]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-literal-eval-blocks",
     "(function(){return eval('\'"+_A+_B+"\'');})()",
     True),]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        is_break = not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("shapes %d BREAK / %d HELD; controls tallied above" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
