#!/usr/bin/env python3
"""Red-first for F529: arguments-alias enumerated via Object.keys/for-in.

F516 models `arguments` laundered through an alias (const a = arguments)
used as a dispatch receiver or through Array.from/Object.values; F517
models Object.keys/entries/for-in enumeration on literal objects. The
COMPOSITION escapes both: aliasing arguments and then enumerating the
alias with Object.keys (indexed back into the alias) or for-in recovers
the credential, and neither closure's source grammar accepts the
other's model as input. Both shapes node-evaluate (v24.20.0) to the
exact credential while the decoder produces zero variants. Distinct
from F516 (alias without enumeration) and F517 (enumeration without
aliasing). Prints BREAK when a payload MISSES (open tree), HELD when
blocked.
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
    ("alias-keys-indexed",
     "(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ("alias-forin-accum",
     "(function(){const a=arguments;var s='';for(var i in a){s+=a[i];}return s;})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("f516-alias-held",  # F516 CLOSED wave-364 lane 3
     "(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (A1, A2), True),
    ("f517-keys-held",  # F517 CLOSED wave-364 lane 3
     "Object.keys({'%s':'x','%s':'y'}).join('')" % (A1, A2), True),
    ("junk-quiet",
     "(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('ab','cd')", False),
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
