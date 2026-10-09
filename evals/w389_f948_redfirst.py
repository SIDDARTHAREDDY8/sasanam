#!/usr/bin/env python3
"""Red-first for F948: F924 braced/ASI guard-consequent residual.

Renumbered at wave-389 merge: filed as F937 2026-10-09 12:45 UTC wave-389 lane 1;
attack round 57 filed F937 first 12:34 UTC (wave-272 rule).

F924 (CLOSED wave-389 lane 1) models `if(C===K)continue LBL;` /
`if(C!==K)continue LBL;` in the nested-for inner body, but the
braced twin `if(C===K){continue LBL;}` and the ASI twin (no `;`
after `continue LBL`, newline-terminated) resolve node-exactly
(v24.20.0) while the decoder produces zero variants.
Filed 2026-10-09 12:45 UTC wave-389 lane 1 (F924 closure residual probe).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("s1-braced",
     ("(function(){var s='';outer:for(var i=0;i<1;i++){"
      "for(var j=0;j<3;j++){if(j===1){continue outer;}s+='%s';}}"
      "return s+'%s';})()") % (_A, _B),
     True),
    ("s2-asi",
     ("(function(){var s='';outer:for(var i=0;i<1;i++){"
      "for(var j=0;j<3;j++){if(j===1)continue outer\ns+='%s';}}"
      "return s+'%s';})()") % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
    ("twin-unbraced",
     ("(function(){var s='';outer:for(var i=0;i<1;i++){"
      "for(var j=0;j<3;j++){if(j===1)continue outer;s+='%s';}}"
      "return s+'%s';})()") % (_A, _B), True),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
