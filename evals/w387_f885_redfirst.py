#!/usr/bin/env python3
"""Red-first for F885: arrow-function CustomEvent listeners.

(e)=>{r=e.detail;} listeners resolve node-exactly (v24.20.0
verified); the F808 hook models only `function` listeners, so the
shape resolves node-exactly while the decoder produces zero
variants.
Filed 2026-10-09 05:33 UTC wave-386 lane 7 (review residual of F808).
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
    ("s1",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('x',(e)=>{r=e.detail;});t.dispatchEvent(new CustomEvent('x',{detail:'%s'}));return r+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('y',(e)=>{r=e.detail.k;});t.dispatchEvent(new CustomEvent('y',{detail:{k:'%s'}}));return r+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    # function-listener twin blocks coded (F808 CLOSED) -- the arrow
    # route must not disturb it.
    ("function-twin-blocks",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('x',function(e){r=e.detail;});t.dispatchEvent(new CustomEvent('x',{detail:'%s'}));return r+'%s';})()" % (_A, _B),
     True),
    # param-shadowing arrow listener fails closed (engine assigns the
    # param, not the outer binding).
    ("param-shadow-fails-closed",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('x',(r)=>{r=r.detail;});t.dispatchEvent(new CustomEvent('x',{detail:'%s'}));return r+'%s';})()" % (_A, _B),
     False),
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
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
