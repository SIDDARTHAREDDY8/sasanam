#!/usr/bin/env python3
"""Red-first for F873: reduce with initial value (identity callback).

Filed shapes (evals/FINDINGS.md, authoritative):
  s1: (function(){return ['x'].reduce(function(a){return a;},'f1')+'f2';})()
  s2: (function(){return ['x','y'].reduce(function(a,b){return a;},'f1')+'f2';})()
Control: junk stays quiet.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

_A = "AKIAIOSFODNN7" + "EXAMPLE"
_B = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"


def check(name, payload, expect_hit):
    hit = dlp.find_credential(payload) is not None
    ok = hit == expect_hit
    print("%s: %s (%s)" % (name, "HELD" if hit else "BREAK",
                           "ok" if ok else "MISMATCH"))
    return 0 if ok else 1


def main():
    # Entry s1 (credential-substituted): identity reduce with init in
    # return position.
    s1 = ("(function(){return ['" + _A
          + "'].reduce(function(a){return a;},'x')+'" + _B + "';})()")
    # Entry s2: two-param identity with init.
    s2 = ("(function(){return ['" + _A
          + "','y'].reduce(function(a,b){return a;},'x')+'" + _B + "';})()")
    junk = "'(function(){var s=\\'ab\\' ;return s;})()'"
    b = 0
    b += check("s1", s1, True)
    b += check("s2", s2, True)
    b += check("junk-quiet", junk, False)
    h = 3 - b
    print("tally: %d BREAK / %d HELD" % (b, h))
    return 0


if __name__ == "__main__":
    sys.exit(main())
