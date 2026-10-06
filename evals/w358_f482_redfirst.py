#!/usr/bin/env python3
"""Red-first for F482: bracket-string member access on prototype methods
under .call/.apply dispatch. F478 models dot-form dispatch
(Array.prototype.concat.call); F480-B models bracket access on STATIC
methods (String['fromCharCode'], Object['assign']). The composition --
the dispatch TARGET reached as X['method'] instead of X.method --
bypasses both anchors. All shapes node-evaluate (v24.20.0) to the exact
credential while the decoder produces zero variants. Distinct from F478
(dot-form dispatch) and F480 (static-method bracket access).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"
FCC = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]

SHAPES = [
    ("bracket-concat-call",
     "Array.prototype['concat'].call([], '%s','%s').join('')" % (A1, A2), True),
    ("bracket-join-call",
     "Array.prototype['join'].call(['%s','%s'], '')" % (A1, A2), True),
    ("bracket-slice-call",
     "Array.prototype['slice'].call(['%s','%s'], 0, 2).join('')" % (A1, A2), True),
    ("bracket-concat-apply",
     "Array.prototype['concat'].apply([], ['%s','%s']).join('')" % (A1, A2), True),
    ("bracket-strconcat-call",
     "String.prototype['concat'].call('%s','%s')" % (A1, A2), True),
    ("bracket-filter-call",
     "Array.prototype['filter'].call(['%s','%s',''], x=>x!=='').join('')" % (A1, A2), True),
    ("bracket-slice-call-1arg",
     "Array.prototype['slice'].call(['%s','%s'], 0).join('')" % (A1, A2), True),
    ("concat-bracketcall",
     "[].concat['call']([], '%s','%s').join('')" % (A1, A2), True),
    ("proto-concat-bracketapply",
     "Array.prototype.concat['apply']([], ['%s','%s']).join('')" % (A1, A2), True),
    ("bracket-join-call-null",
     "Array.prototype['join'].call(['%s',null,'%s'], '')" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "Array.prototype['concat'].call([], 'ab','cd').join('')", False),
    ("neighbor-f478-dot-held",
     "[].concat.call([], '%s','%s').join('')" % (A1, A2), True),
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
