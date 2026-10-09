"""Wave-387 lane-3 red-first for F839: block-scoped let/const accumulation.

On the OPEN tree this is 2 BREAK / 1 HELD (the decoder's IIFE
productions accept only immediate-`return` / assignment-statement
bodies -- a bare block `{let k='...';r=k;}` or an `if(true){...}`
guard between the declaration and the return misses; the junk-quiet
control holds). After the F839 closure both filed shapes must HELD
at 0 BREAK.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

A = "xoxb-0123456789abcdef"
B = "xoxb-9876543210fedcba"

# Filed s1: block-scoped let accumulation.
s1 = ("(function(){var r='';{let k='" + A + "';r=k;}return r+'" + B
      + "';})()")
# Filed s2: if(true)-guarded const accumulation.
s2 = ("(function(){var r='';if(true){const k='" + A + "';r=k;}return r+'"
      + B + "';})()")
# Quiet control: block-accumulation shape recovering no credential.
junk_quiet = "\"(function(){var r='';{let k='ab';r=k;}return r;})()\""


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
