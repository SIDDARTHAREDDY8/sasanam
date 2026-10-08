#!/usr/bin/env python3
"""Red-first for F675: Proxy traps beyond F642/F666/F670.

Proxy traps beyond F642 (get), F666 (apply/has), and F670 (non-concise get forms): set, construct, deleteProperty, getPrototypeOf, and Proxy.revocable are distinct trap productions with no modeled path.
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
    ("set-trap",
     "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v){tr[k]=v;return true;}});p.x='xoxb-0123';return p.x+'456789abcdef';})()", True),
    ("construct",
     "(function(){var P=new Proxy(function(){},{construct:function(){return {x:'xoxb-0123'};}});return new P().x+'456789abcdef';})()", True),
    ("delete",
     "(function(){var o={x:'xoxb-0123'};var p=new Proxy(o,{deleteProperty:function(t,k){return true;}});delete p.x;return o.x+'456789abcdef';})()", True),
    ("getproto",
     "(function(){var p=new Proxy({},{getPrototypeOf:function(){return {x:'xoxb-0123'};}});return Object.getPrototypeOf(p).x+'456789abcdef';})()", True),
    ("revocable",
     "(function(){var r=Proxy.revocable({},{get:function(){return 'xoxb-0123';}});return r.proxy.x+'456789abcdef';})()", True),
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
