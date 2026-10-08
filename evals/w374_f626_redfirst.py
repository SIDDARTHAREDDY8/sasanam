#!/usr/bin/env python3
"""Red-first for F626: URLSearchParams iteration protocols.

F599 (CLOSED) models append/set statement-form mutations with getAll/get terminal reads on the constructor receiver, but the ITERATION read path -- for-of, forEach, keys()+get -- has no modeled path on the same receiver.
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
    ('params-forof',
     "(function(){var p=new URLSearchParams('a=%(A1)s&b=%(A2)s');var s='';for(var kv of p){s+=kv[1];}return s;})()"
     % {"A1": A1, "A2": A2}, True),
    ('params-foreach',
     "(function(){var p=new URLSearchParams('a=%(A1)s&b=%(A2)s');var s='';p.forEach(function(v){s+=v;});return s;})()"
     % {"A1": A1, "A2": A2}, True),
    ('params-keys-get',
     "(function(){var p=new URLSearchParams('a=%(A1)s&b=%(A2)s');var s='';for(var k of p.keys()){s+=p.get(k);}return s;})()"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f599-blocks',
     "(function(){var p=new URLSearchParams('');p.append('q','%(A1)s');p.append('q','%(A2)s');return p.getAll('q').join('');})()"
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
