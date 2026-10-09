"""Wave-387 lane-3 red-first for F838: nested function declarations.

On the OPEN tree this is 2 BREAK / 1 HELD (the decoder's nested-
function production only accepts bodies that are exactly `return
EXPR;` -- a body containing a further `function` declaration misses;
the junk-quiet control holds). After the F838 closure both filed
shapes must HELD at 0 BREAK.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

A = "xoxb-0123456789abcdef"
B = "xoxb-9876543210fedcba"

# Filed s1: nested function declaration inside a nested function body.
s1 = ("(function(){function outer(){function inner(){return '" + A
      + "';}return inner();}return outer()+'" + B + "';})()")
# Filed s2: triple nesting.
s2 = ("(function(){function a(){function b(){function c(){return '" + A
      + "';}return c();}return b();}return a()+'" + B + "';})()")
# Quiet control: nested-function IIFE shape recovering no credential.
junk_quiet = ("\"(function(){function outer(){function inner(){return 'ab';}"
              "return inner();}return outer();})()\"")


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
