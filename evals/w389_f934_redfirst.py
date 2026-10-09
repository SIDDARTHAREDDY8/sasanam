#!/usr/bin/env python3
"""Red-first for F934: async function promise laundering.

The decoder had no async production: an async function whose promise
resolves to the credential half, chained with .then, resolved
node-exactly (awaited) while the decoder produced zero variants.
Filed 2026-10-09 11:21 UTC wave-388 (attack round 56).
Closed wave-389: _js_parse_f934_async_then_iife models the
deterministic resolution statically (F618/F631 precedent).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("s1",
     "(function(){async function f(){return '%s';}return f().then(function(v){return v+'%s';});})()" % (_A, _B),
     True),
    ("s2-long",
     "(function(){async function f(){return '%s';}return f().then(function(v){return v+'%s';});})()" % (_L1, _L2),
     True),
    # Lane generalizations (node-exact, v24.20.0):
    ("g-arrow",
     "(function(){async function f(){return '%s';}return f().then((v)=>v+'%s');})()" % (_A, _B),
     True),
    ("g-block-arrow",
     "(function(){async function f(){return '%s';}return f().then((v)=>{return v+'%s';});})()" % (_A, _B),
     True),
    ("g-additive-resolve",
     "(function(){async function f(){return 'xox'+'b-0123';}return f().then(function(v){return v+'%s';});})()" % _B,
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
    ("twin-sync",
     "(function(){function f(){return '%s';}return f()+'%s';})()" % (_A, _B), True),
]

# Fail-closed bounds: these must NOT decode (safe misses).
BOUNDS = [
    # non-string async resolution
    "(function(){async function f(){return 1;}return f().then(function(v){return v+'x';});})()",
    # multi-param callback
    "(function(){async function f(){return 'a';}return f().then(function(v,w){return v+'x';});})()",
    # .then on another ident
    "(function(){async function f(){return 'a';}return g().then(function(v){return v+'x';});})()",
    # async function with params
    "(function(){async function f(x){return x;}return f('a').then(function(v){return v+'x';});})()",
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
    for i, payload in enumerate(BOUNDS):
        hit = find_credential(payload) is not None
        ok = not hit
        print("bound-%d: %s" % (i, "HELD(bound-ok)" if ok else "BREAK(bound-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
