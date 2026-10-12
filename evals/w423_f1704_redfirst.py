"""Red-first battery for F1704: F1689 S2-fresh variant gap.

Filed 2026-10-12 01:30 UTC by wave-423 merge red-first audit.
Lane D's _js_f1689_stmt_decode handles the S-redeclare form but MISSES
the S2-fresh variant. This battery verifies the gap BREAKs (MISS) on
the merged tree.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


SECRET = "xoxb-0123456789abcdef"
# F1704: S2-fresh variant (MISSES on merged tree -- the gap)
PAYLOAD = ("var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');"
           "var D=[...S].map(function(ch){return ch.charCodeAt(0);});"
           "var S2=String.fromCharCode.apply(null,D);var RESULT=S2;").replace("{I}", _codes(SECRET))


def main():
    from gov.dlp import find_credential
    hit = find_credential(PAYLOAD) is not None
    # F1704 is OPEN: expect MISS (BREAK)
    if not hit:
        print("RESULT: BREAK (F1704 OPEN -- S2-fresh variant still misses)")
        return 0
    else:
        print("RESULT: NO-BREAK (F1704 unexpectedly HIT)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
