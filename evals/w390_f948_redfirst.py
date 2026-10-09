#!/usr/bin/env python3
"""Red-first for F948: F924 residual -- braced/ASI guard consequents.

F924 (CLOSED wave-389 lane 1) models `if(C===K)continue LBL;` but the
braced twin `if(C===K){continue LBL;}` and the ASI twin (newline after
`continue LBL`, no semicolon) resolve node-exactly while the decoder
produces zero variants.
Filed 2026-10-09 12:45 UTC wave-389 lane 1 (renumbered F948 at merge).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("s1-braced",
     ("(function(){var s='';outer:for(var i=0;i<1;i++){"
      "for(var j=0;j<3;j++){if(j===1){continue outer;}s+='%s';}}"
      "return s+'%s';})()") % (_A, _B)),
    ("s2-asi",
     ("(function(){var s='';outer:for(var i=0;i<1;i++){"
      "for(var j=0;j<3;j++){if(j===1)continue outer\ns+='%s';}}"
      "return s+'%s';})()") % (_A, _B)),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-unbraced",
     ("(function(){var s='';outer:for(var i=0;i<1;i++){"
      "for(var j=0;j<3;j++){if(j===1)continue outer;s+='%s';}}"
      "return s+'%s';})()") % (_A, _B),
     True),
]


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
