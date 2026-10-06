#!/usr/bin/env python3
"""w346 red-first: F440 double-HTML-entity encoding evades the entity sub-layer.

Wave-346 lane 6 (DLP layer-composition audit) filed F440 (LOW, OPEN),
renumbered F437->F440 at the wave-346 merge (attack lane filed first):
wrapping every credential char's numeric entity in a SECOND entity --
``&amp;#xHH;`` (named), ``&#38;#xHH;`` (numeric), ``&amp#xHH;``
(no-semicolon named) -- evades find_credential. The _ENTITY_RUN regex
never matches named entities, and numeric-wrapped runs fragment so the
inner ``&#xHH;`` never materializes within the 2-layer decode budget,
while html.unescape applied twice (a real parser stack) recovers the
credential. 3/3 shapes + a base64-stacked generalization verified MISS
on the merged tree; controls hold; no plaintext in any payload.

Expected on the OPEN tree: prints BREAK (F440 is OPEN).

Wave-346 merge composition note: the F436 closure (wave-346 lane 1,
whole-text entity pass) absorbed the amp-numeric shape (&#38;#xHH;)
-- it now decodes and blocks. 3 residuals remain OPEN and verified:
amp-named, amp-no-semicolon, b64-stacked. The script asserts the
absorbed shape blocks (control) and BREAKs on the 3 open shapes.
After a closure (the decode layer reconstitutes entity-encoded
entities, or refuses obfuscation-shaped runs coded): prints HELD.

$0 SPEND BY CONSTRUCTION: canned transforms of a test credential;
no model calls here. Do NOT add ModelDriver/SpendLedger usage here.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO = os.getcwd()
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import base64  # noqa: E402
import html  # noqa: E402

from gov import dlp  # noqa: E402

# Long test credential (base64 = 52 chars, well over the 24-char
# precision guard). Constructed via concatenation -- never a literal.
_LONG = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"


def _rt_double_unescape(payload):
    """A real parser stack (html.unescape x2) recovers the credential."""
    return html.unescape(html.unescape(payload)) == _LONG


def _rt_b64_double_unescape(payload):
    inner = base64.b64decode(payload).decode()
    return html.unescape(html.unescape(inner)) == _LONG


def _shapes():
    return {
        "amp-named": (
            "".join("&amp;#x%x;" % ord(c) for c in _LONG),
            _rt_double_unescape),
        # absorbed by the F436 closure (wave-346 lane 1 whole-text entity
        # pass) -- kept as a control asserting it now blocks.
        "amp-no-semicolon": (
            "".join("&amp#x%x;" % ord(c) for c in _LONG),
            _rt_double_unescape),
        "b64-stacked": (
            base64.b64encode(
                "".join("&amp;#x%x;" % ord(c)
                        for c in _LONG).encode()).decode(),
            _rt_b64_double_unescape),
    }


def main():
    assert len(base64.b64encode(_LONG.encode()).decode()) >= 24
    control = dlp.find_credential(_LONG) == "dlp-slack-token"
    print("control (plain credential blocks) -> %s"
          % ("HELD" if control else "BROKEN-CONTROL"))
    # absorbed-shape control: amp-numeric must now BLOCK via the F436 closure
    absorbed_payload = "".join("&#38;#x%x;" % ord(c) for c in _LONG)
    assert _LONG not in absorbed_payload
    assert _rt_double_unescape(absorbed_payload), "absorbed-shape roundtrip broken"
    absorbed_blocks = dlp.find_credential(absorbed_payload) == "dlp-slack-token"
    print("amp-numeric (absorbed by F436 closure) -> %s"
          % ("HIT" if absorbed_blocks else "STILL-MISS"))
    misses = {}
    for name, (payload, rt_fn) in _shapes().items():
        assert _LONG not in payload, "payload %s smuggles plaintext" % name
        rt = rt_fn(payload)
        miss = dlp.find_credential(payload) is None
        misses[name] = miss
        print("%-24s -> %s (roundtrip=%s)"
              % (name, "MISS" if miss else "HIT", rt))
        if not rt:
            print("ROUNDTRIP BROKEN for %s -- not a real attack" % name)
            return 2
    if control and absorbed_blocks and all(misses.values()):
        print("BREAK")
        return 1
    print("HELD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
