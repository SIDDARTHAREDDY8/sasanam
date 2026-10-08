#!/usr/bin/env python3
"""Red-first for 606: URLSearchParams unmodeled mutation statements.

F599 (CLOSED, wave-372 lane 3) models `.append`/`.set` statement-form
mutations, but any OTHER mutation statement -- `.sort()`, `.delete()`,
`.has()`-guarded control flow -- fails the whole F599 shape closed, so
a one-token mutation bypasses: the engine still evaluates to the exact
credential (node v24.20.0) while the decoder produces zero variants.
Filed honestly per the standing red-first rule (the spec-axis review
of the F599 closure caught the untracked residual).
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
    ('usp-sort-mutation',
     '"(function(){var p=new URLSearchParams(\'q=%(A1)s\');'
     'p.append(\'q\',\'%(A2)s\');p.sort();'
     'return p.getAll(\'q\').join(\'\');})()"'
     % {"A1": A1, "A2": A2}, True),
    ('usp-delete-mutation',
     '"(function(){var p=new URLSearchParams(\'a=1&q=%(A1)s\');'
     'p.append(\'q\',\'%(A2)s\');p.delete(\'a\');'
     'return p.getAll(\'q\').join(\'\');})()"'
     % {"A1": A1, "A2": A2}, True),
    ('usp-has-guard',
     '"(function(){var p=new URLSearchParams(\'q=%(A1)s\');'
     'p.append(\'q\',\'%(A2)s\');if(p.has(\'q\')){'
     'return p.getAll(\'q\').join(\'\');}return \'\';})()"'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('usp-append-blocked',
     '""(function(){var p=new URLSearchParams(\'q=%(A1)s\');'
     'p.append(\'q\',\'%(A2)s\');return p.getAll(\'q\').join(\'\');})()""'
     % {"A1": A1, "A2": A2}, True),
    ('usp-set-blocked',
     '""(function(){var p=new URLSearchParams(\'q=zz\');'
     'p.set(\'q\',\'%(A1)s%(A2)s\');return p.getAll(\'q\').join(\'\');})()""'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '""(function(){var s=\'ab\';return s;})()""'
     % {"A1": A1, "A2": A2}, False),
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
