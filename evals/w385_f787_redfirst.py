#!/usr/bin/env python3
"""Wave-385 lane 13: F787 red-first (Error cause reads).

F787 (LOW, filed 2026-10-09 by wave-384 attack round 52): F750 covers
Error `.message` reads, but `.cause` misses: `new Error('x',{cause:'f1'})`
and assigned `e.cause='f1'` resolve node-exactly while the decoder
produces zero variants. Node-exact (v24.20.0):
`(function(){try{throw new Error('x',{cause:'f1'});}catch(e){return e.cause+'f2';}})()`
and
`(function(){var e=new Error('x');e.cause='f1';return e.cause+'f2';})()`
both evaluate to the exact credential.

Red-first: on the open tree this prints 2 BREAK / 1 HELD; on the
closed tree 0 BREAK / 3 HELD.

Conventions: module-level staging, concatenation-constructed
credentials, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov import dlp  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _misses(payload):
    return dlp.find_credential(payload) is None


def main():
    breaks, held = 0, 0

    s1 = ("(function(){try{throw new Error('x',{cause:'%s'});}"
          "catch(e){return e.cause+'%s';}})()") % (_A, _B)
    r = "BREAK" if _misses(s1) else "HELD"
    print("s1: %s(%s)" % (r, "misses" if r == "BREAK" else "blocks"))
    breaks, held = (breaks + 1, held) if r == "BREAK" else (breaks, held + 1)

    s2 = ("(function(){var e=new Error('x');e.cause='%s';"
          "return e.cause+'%s';})()") % (_A, _B)
    r = "BREAK" if _misses(s2) else "HELD"
    print("s2: %s(%s)" % (r, "misses" if r == "BREAK" else "blocks"))
    breaks, held = (breaks + 1, held) if r == "BREAK" else (breaks, held + 1)

    junk = "'(function(){var s=\\\\'ab\\\\' ;return s;})()'"
    r = "HELD" if _misses(junk) else "BREAK"
    print("junk-quiet: %s(%s)" % (r, "control-ok" if r == "HELD" else "noisy"))
    breaks, held = (breaks + 1, held) if r == "BREAK" else (breaks, held + 1)

    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
