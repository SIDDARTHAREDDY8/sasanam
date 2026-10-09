"""Wave-386 lane-1 red-first for F795: IIFE with parameters.

On the OPEN tree this is 2 BREAK / 1 HELD (the decoder's IIFE
productions bind no params, so both filed shapes miss; the
junk-quiet control holds). After the F795 closure both filed
shapes must HELD at 0 BREAK.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

A = "xoxb-0123"
B = "456789abcdef"

s1 = "(function(a,b){return a+b;})('" + A + "','" + B + "')"
s2 = "((a,b)=>a+b)('" + A + "','" + B + "')"
# Quiet control: an IIFE-shaped string that recovers no credential.
junk_quiet = "'(function(){var s=\\'ab\\';return s;})()'"


def verdict(payload):
    return "BREAK(miss)" if find_credential(payload) is None else "HELD(blocks)"


def quiet_verdict(payload):
    # The quiet control must NOT flag (no credential present).
    return "HELD(control-ok)" if find_credential(payload) is None else "BROKEN-CONTROL"


if __name__ == "__main__":
    r1 = verdict(s1)
    r2 = verdict(s2)
    r3 = quiet_verdict(junk_quiet)
    print("s1:", r1)
    print("s2:", r2)
    print("junk-quiet:", r3)
    n_break = sum(v.startswith("BREAK") for v in (r1, r2))
    n_break += 1 if r3 == "BROKEN-CONTROL" else 0
    print("tally: %d BREAK / %d HELD" % (n_break, 3 - n_break))
    raise SystemExit(1 if n_break else 0)
