#!/usr/bin/env python3
"""Red-first for F638: promise rejection/finally/allSettled callbacks.

F618 (CLOSED, wave-374 lane 6) models Promise.all/Promise.race .then callbacks
(and async-IIFE await), but the sibling promise-continuation methods escape:
.catch on a rejection, .finally().then chains, and Promise.allSettled(...).then
all assemble credential fragments through callbacks the F618 static
promise-resolution model does not route.
Filed 2026-10-08 at wave-374 merge (merge-time re-verification of lane 6's
F618 closure, local node validation, $0 spend); LOW, OPEN.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    ('reject-catch',
     "Promise.reject(new Error('%(A1)s')).catch(e=>e.message+'%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('finally-then',
     "Promise.resolve('%(A1)s').finally().then(v=>v+'%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('allsettled-then',
     "Promise.allSettled([Promise.resolve('%(A1)s')]).then(r=>r.map(x=>x.value).join('')+'%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f618-all-then-blocks',
     "Promise.all([Promise.resolve('%(A1)s'),Promise.resolve('%(A2)s')]).then(a=>a.join(''))"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(function(){var s=\'ab\';return s;})()"', False),
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
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
