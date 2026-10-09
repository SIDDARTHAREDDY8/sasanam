#!/usr/bin/env python3
"""Red-first for F808: CustomEvent detail reads.

The decoder has no event-target production: an EventTarget dispatch
carrying a detail payload resolves node-exactly (v24.20.0) inside
the registered listener while the decoder produces zero variants on
the open tree.
Filed 2026-10-09 03:25 UTC wave-385 attack round 53; closed
2026-10-09 wave-386 lane 7.
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
     "(function(){var t=new EventTarget();var r='';t.addEventListener('x',function(e){r=e.detail;});t.dispatchEvent(new CustomEvent('x',{detail:'%s'}));return r+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('y',function(e){r=e.detail.k;});t.dispatchEvent(new CustomEvent('y',{detail:{k:'%s'}}));return r+'%s';})()" % (_A, _B),
     True),
    ("s3-deep",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('x',function(e){r=e.detail.a.b;});t.dispatchEvent(new CustomEvent('x',{detail:{a:{b:'%s'}}}));return r+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
    ("type-mismatch-closed",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('x',function(e){r=e.detail;});t.dispatchEvent(new CustomEvent('z',{detail:'%s'}));return r+'%s';})()" % (_A, _B),
     False),
    ("two-listeners-closed",
     "(function(){var t=new EventTarget();var r='';t.addEventListener('x',function(e){r=e.detail;});t.addEventListener('x',function(e){r='s';});t.dispatchEvent(new CustomEvent('x',{detail:'%s'}));return r+'%s';})()" % (_A, _B),
     False),
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
