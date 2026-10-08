#!/usr/bin/env python3
"""Red-first for F679: statement-body accumulation beyond F655.

Statement-body accumulation beyond F655 (two-decl, decl+accum, switch-fallthrough, do-while(false), with-wrapper, labeled-block, try-finally): C-style for, while, for-in guards, try-catch value assembly, if-else chains, for(;;)+break, and do-while+break are distinct statement productions.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
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
    ("cfor",
     "(function(){var s='';for(var i=0;i<2;i++){s+=i===0?'xoxb-0123':'456789abcdef';}return s;})()", True),
    ("while",
     "(function(){var s='';var i=0;while(i<2){s+=i===0?'xoxb-0123':'456789abcdef';i++;}return s;})()", True),
    ("forin-guard",
     "(function(){var o={x:'xoxb-0123'};var s='';for(var k in o){if(k==='x'){s+=o[k];}}return s+'456789abcdef';})()", True),
    ("trycatch",
     "(function(){var s='';try{throw 'xoxb-0123';}catch(e){s+=e;}s+='456789abcdef';return s;})()", True),
    ("ifelse-chain",
     "(function(){var s='';if(false){s+='junk';}else if(true){s+='xoxb-0123';}s+='456789abcdef';return s;})()", True),
    ("forbreak",
     "(function(){var s='';for(;;){s+='xoxb-0123';break;}s+='456789abcdef';return s;})()", True),
    ("dowhile-break",
     "(function(){var s='';var i=0;do{s+=i===0?'xoxb-0123':'456789abcdef';i++;if(i>=2){break;}}while(true);return s;})()", True),
]

CONTROLS = [
    ("array-join-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
