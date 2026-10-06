#!/usr/bin/env python3
"""Red-first for F472: calling repeat as a tagged template bypasses the bounded static JS-expression decoder.

(Renumbered F469->F472 at the wave-353 lane-2 commit: the wave-353 attack
lane committed F469-F471 first, commit e79af076.)

'xoxb-0123'.repeat`2` (repeat invoked as a tag with a literal-only template) node-evaluates to 'xoxb-0123xoxb-0123', which trips the dlp-slack-token rule -- while the raw fragment does not. The tag receives the TemplateStringsArray ['2'] as the repeat count (ToNumber(String(['2'])) == 2). The F463 closure models the tagged-template call site for .join/.concat/.fill only; repeat's ToNumber count conversion is a distinct shape the decoder never models, so it fails closed with zero decode variants.

NOTE: 'C'.repeat`1` with the FULL credential as receiver is NOT a miss -- the raw-text rule blocks it. The minimized shapes below use a fragment receiver so the bypass is decoder-genuine.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: plain credential blocks coded; junk variant quiet; the
neighboring paren form blocks.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
FRAG = "xoxb-" + "0123"          # 'xoxb-0123'.repeat`2` -> 'xoxb-0123xoxb-0123'
CRED = "xoxb-" + "012345678" + "89abcdef"
BT = chr(96)

SHAPES = [
    # (name, payload, node-evaluates-to-rule-tripping-text [node-verified])
    ("tagged-template-repeat", "'%s'.repeat%s2%s" % (FRAG, BT, BT), True),
    ("tagged-template-repeat-ws", "'%s'.repeat %s2%s" % (FRAG, BT, BT), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("plain-blocks", CRED, True),
    ("junk-quiet", "'ab'.repeat%s2%s" % (BT, BT), False),
    ("neighbor-paren-blocks", "'%s'.repeat(2)" % FRAG, True),
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
