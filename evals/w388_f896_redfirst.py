#!/usr/bin/env python3
"""Red-first for F896: DataView non-Uint8 widths.

F742 (CLOSED) models setUint8/getUint8 and documents other widths as
fail-closed bounds, but setUint16/setInt8 shapes silently miss (no
coded refusal, zero variants): the setUint16 write-loop/read-back
shape and the setInt8 loop twin resolve node-exactly (v24.20.0) while
the decoder produces zero variants.
Filed 2026-10-09 06:58 UTC wave-387 (attack round 55).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 39-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("s1",
     "(function(){var b=new ArrayBuffer(22);var v=new DataView(b);"
     "var ps=[30831,30818,11568,12594,13108,13622,14136,14689,25187,25701];"
     "for(var i=0;i<10;i++)v.setUint16(i*2,ps[i]);v.setUint8(20,102);"
     "var r='';for(var j=0;j<21;j++)r+=String.fromCharCode(v.getUint8(j));"
     "return r;})()",
     True),
    ("s2",
     "(function(){var v=new DataView(new ArrayBuffer(21));"
     "var bs=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];"
     "for(var i=0;i<21;i++)v.setInt8(i,bs[i]);"
     "var r='';for(var j=0;j<21;j++)r+=String.fromCharCode(v.getInt8(j));"
     "return r;})()",
     True),
]

CONTROLS = [
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
