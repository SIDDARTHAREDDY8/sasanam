#!/usr/bin/env python3
"""w345 red-first: F436 sub-threshold fragment inside a base64 run.

Wave-345 lane 5 filed F436 (LOW, OPEN): a single HTML numeric entity
(decimal &#NN;, hex &#xHH;, or the no-semicolon legacy form) anywhere
inside a base64 run -- or a single text-escape fragment (\\xHH,
\\uXXXX, octal) inside it -- evades find_credential. The {2,}-run
entity/escape sub-layers leave the lone fragment in place, and the
base64 run then fails to match the fragmented remainder, while
html.unescape + base64-decode in any real parser recovers the
credential. A run of 2+ consecutive entities still blocks coded
dlp-slack-token, so the miss is specifically the sub-threshold
fragment. Model-proposed (gpt-4o-mini, round 13, target B2 stacked
encodings); every shape validated locally against the real gov/dlp.py.

WAVE-345 MERGE COMPOSITION NOTE (2026-10-05): the F432 closure
(wave-345 lane 1, text-escape gate {2,} -> 1+) absorbed 6 of the 8
filed shapes -- single decimal/hex entities and single
\\xHH/\\uXXXX/octal fragments inside base64 runs now decode and
block. The 2 residuals below remain OPEN and verified (roundtrip=True
through a real parser). This script now pins the RESIDUAL scope:
prints BREAK while the 2 residuals miss, HELD when they block.

WAVE-346 LANE 1 EXTENSION (2026-10-05): the lane's two-axis review
verified two further shapes of the same close-when ("sub-threshold
entity/escape fragments inside base64 runs"): (c) 12 single entities
spaced inside the run (the whole-text pass was bound at 8 items);
(d) two/three single escape fragments spaced inside the run (the
escape analogue of residual b -- per-run decoding needed one layer
per fragment). Both round-trip through a real parser. They are pinned
as residuals here and closed by the same lane.

Expected on the OPEN tree: prints BREAK (F436 is OPEN).
After a closure (the decode layer recognizes the residual shapes):
prints HELD.

$0 SPEND BY CONSTRUCTION: canned transforms of a test credential;
no model calls here.
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


def _ent(c):
    return "&#%d;" % ord(c)


def _shapes(b64):
    # each shape: (payload, real-parser round-trip check)
    shapes = {
        "single-decimal-entity-at-start": (
            _ent(b64[0]) + b64[1:], _rt_html),
        "single-decimal-entity-in-middle": (
            b64[:20] + _ent(b64[20]) + b64[21:], _rt_html),
        "single-hex-entity-at-start": (
            "&#x%x;" % ord(b64[0]) + b64[1:], _rt_html),
        "single-entity-no-semicolon": (
            "&#%d" % ord(b64[0]) + b64[1:], _rt_html),
        "two-entities-25-apart": (
            _ent(b64[0]) + b64[1:25] + _ent(b64[25]) + b64[26:], _rt_html),
        "single-xHH-fragment": (
            b64[:10] + "\\x%02x" % ord(b64[10]) + b64[11:], _rt_js),
        "single-uXXXX-fragment": (
            b64[:10] + "\\u%04x" % ord(b64[10]) + b64[11:], _rt_js),
        "single-octal-fragment": (
            b64[:10] + "\\%03o" % ord(b64[10]) + b64[11:], _rt_js),
    }
    # Wave-346 lane 1 extension: stacked sub-threshold fragments.
    parts, idx = [], 0
    for _ in range(12):
        parts.append(b64[idx:idx + 3])
        parts.append("&#%d;" % ord(b64[idx + 3]))
        idx += 4
    parts.append(b64[idx:])
    shapes["twelve-spaced-entities"] = ("".join(parts), _rt_html)
    shapes["two-spaced-escape-fragments"] = (
        b64[:10] + "\\x%02x" % ord(b64[10]) + b64[11:30]
        + "\\x%02x" % ord(b64[30]) + b64[31:], _rt_js)
    shapes["three-spaced-escape-fragments"] = (
        b64[:8] + "\\x%02x" % ord(b64[8]) + b64[9:20]
        + "\\u%04x" % ord(b64[20]) + b64[21:32]
        + "\\%03o" % ord(b64[32]) + b64[33:], _rt_js)
    return shapes


def _rt_html(payload):
    """A real HTML parser (html.unescape) recovers the credential."""
    return base64.b64decode(html.unescape(payload)).decode() == _LONG


def _rt_js(payload):
    """A real JS parser (unicode-escape decode) recovers the credential."""
    return base64.b64decode(
        payload.encode("ascii").decode("unicode_escape")).decode() == _LONG


def main():
    b64 = base64.b64encode(_LONG.encode()).decode()
    assert len(b64) >= 24, "precision-guard precondition"
    control = dlp.find_credential(_LONG) == "dlp-slack-token"
    raw_hit = dlp.find_credential(b64) == "dlp-slack-token"
    print("control (plain credential blocks) -> %s" % ("HELD" if control else "BROKEN-CONTROL"))
    print("control (raw base64 of long cred blocks) -> %s" % ("HELD" if raw_hit else "BROKEN-CONTROL"))
    # Residual scope (wave-345 merge + wave-346 lane 1 extension): the
    # 6 shapes absorbed by the F432 closure are documented as
    # HELD-absorbed; BREAK requires the residuals to miss.
    RESIDUALS = {"single-entity-no-semicolon", "two-entities-25-apart",
                 "twelve-spaced-entities", "two-spaced-escape-fragments",
                 "three-spaced-escape-fragments"}
    misses = {}
    for name, (payload, rt_fn) in _shapes(b64).items():
        assert _LONG not in payload, "payload %s smuggles plaintext" % name
        # real-parser sanity: a real parser recovers the credential
        rt = rt_fn(payload)
        miss = dlp.find_credential(payload) is None
        misses[name] = miss
        tag = "RESIDUAL" if name in RESIDUALS else "absorbed-by-F432"
        print("%-32s -> %s (roundtrip=%s) [%s]" % (name, "MISS" if miss else "HIT", rt, tag))
    residual_miss = all(misses[n] for n in RESIDUALS)
    if control and raw_hit and residual_miss:
        print("BREAK")
        return 1
    print("HELD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
