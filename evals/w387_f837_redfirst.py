"""Wave-387 lane-3 red-first for F837: IIFE returning object/array literal.

On the OPEN tree this is 2 BREAK / 1 HELD (the decoder's IIFE
productions bind only string literals / atob fragments / paren
expressions -- an inner `(function(){return {k:'...'};})()` or
`(function(){return ['...'];})()` misses everywhere, and no
var-binding production accepts an IIFE initializer; the junk-quiet
control holds). After the F837 closure both filed shapes must HELD
at 0 BREAK.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

A = "xoxb-0123456789abcdef"
B = "xoxb-9876543210fedcba"

# Filed s1: IIFE returning an object literal, member-read in primary
# position.
s1 = "(function(){return {k:'" + A + "'};})().k"
# Filed s2: var-bound inner IIFE returning an array literal.
s2 = ("(function(){var r=(function(){return ['" + A + "','" + B
      + "'];})();return r[0]+r[1];})()")
# Quiet control: an IIFE-shaped string that recovers no credential.
junk_quiet = "\"(function(){return {k:'ab'};})().k\""


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
