#!/usr/bin/env python3
"""Red-first for F567: anchor left-boundary false positives.

`_JS_EXPR_START` has no left ident-boundary, so identifier-suffixed
anchors decode while node throws ReferenceError: `xJSON.parse(...)`
and `xstructuredClone(...)` flag HIT on the decoder while node
throws (v24.20.0 verified). Decoder-wide and pre-existing (the
`Reflect` branch is the exception -- it carries an explicit
left-boundary guard). Distinct from the findings it rides on
(F541/F536 -- this is the anchor class, not the desugar).
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
    # Each shape: (name, payload). The decoder FALSE-POSITIVES on
    # these (flags HIT) while node v24.20.0 throws ReferenceError --
    # a HIT here is the break. When F567 is closed (left-boundary
    # guards), these go quiet.
    ('xjson-prefix',
     'xJSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
     % {"A1": A1, "A2": A2}),
    ('xstructuredclone-prefix',
     'xstructuredClone({c:\'%(A1)s\'}).c+\'%(A2)s\''
     % {"A1": A1, "A2": A2}),

]

CONTROLS = [
    # Unprefixed forms still block (F541/F536 CLOSED -- unaffected).
    ('json-unprefixed-closed',
     'JSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     'xJSON.parse(\'{"x":["ab"]}\').x.join(\'\')'
    , False),

]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        # Inverted semantics: the decoder flagging is the bug.
        print("%s: %s" % (name, "BREAK(false-positive)" if hit else "HELD(quiet)"))
        if hit:
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
