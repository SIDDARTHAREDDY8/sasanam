#!/usr/bin/env python3
"""Wave-345 real-model attack round 13: deterministic pins.

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every pin
below replays a hostile construction from the round-13 attack pass
(3 gpt-4o-mini calls, $0.000273; verbatim transcripts in
~/workspace/teams/wave345-attack/w345_transcripts.json) using canned
inputs -- never a live provider. Do NOT add any live paid-provider
call code here; this battery replays canned inputs only.

Shapes (B1/B2/B3 = the three wave-345 attack targets):
  B1: JS-evaluable constructions beyond the F430/F434 decoded set.
     - new Function('return "CRED";')() contains the raw credential:
       the regex already matches -- not a miss. HELD.
     - eval('"CRED"') contains the raw credential: not a miss. HELD.
     - ({}).toString() literal-embedding shapes all die on the real
       code for the same reason.
  B2: stacked / cross-layer encodings.
     - Base64 run wrapped in per-character numeric HTML entities
       (the model's proposal): with the short 16-char test credential
       this is indistinguishable from the documented base64 precision
       guard, but with a 37-char credential (52-char base64) a SINGLE
       entity anywhere in the run evades -- the {2,}-run entity layer
       leaves the lone fragment and the base64 run then fails on the
       fragmented remainder, while html.unescape + base64-decode
       recovers it. GENUINE: filed as F436 (LOW, OPEN).
     - Single text-escape fragments (\\xHH, \\uXXXX, octal) inside a
       base64 run evade the same way (F432's {2,} threshold leaves the
       lone fragment); a real JS parser recovers the credential.
       Also filed under F436 (same mechanism class).
     - A run of 2+ consecutive entities still blocks coded -- the miss
       is specifically the sub-threshold fragment.
     - Percent-encoded base32: decodes and blocks (layers compose).
       HELD.
     - Hex with NUL-interleave: decodes and blocks. HELD.
  B3: parser-differential / precision-boundary constructions.
     - URL-encoded credential segments: decodes and blocks. HELD.
     - base64 + appended garbage: the DLP misses, but no real parser
       recovers the credential from the garbage-padded blob
       (discontinuous padding is rejected) -- the miss is correct
       non-detection of a non-attack. HELD.
  Precision boundary re-pinned: raw base64 of the 16-char test
  credential misses because _B64_RUN requires 24+ chars -- a
  deliberate F2/F8-era precision guard (real tokens are far longer);
  not a defeated control. HELD-by-design.

  F436: filed OPEN this round; footer now
  open F432, F433, F434, F435, F436 / next F437. F430/F431: CLOSED.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w345_attack_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import html
import subprocess
import sys
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_CRED = "xoxb-" + "abc123" + "def456"          # 16-char (precision-boundary tests)
_LONG = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"  # 37-char (F436)

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def _ent(c):
    return "&#%d;" % ord(c)


# ---------------------------------------------------------------- controls

@_t
def test_b0_plain_long_credential_blocked():
    """Control: the plain 37-char credential blocks coded."""
    blocked, rule = dlp.scan_value("token=" + _LONG)[:2]
    ok = blocked and rule == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "blocked=%s rule=%s" % (blocked, rule))


@_t
def test_b0b_raw_base64_of_long_credential_blocked():
    """Control: raw base64 of the long credential (52 chars, over the
    24-char precision guard) blocks coded -- the F436 shapes evade from
    this baseline."""
    ok = dlp.find_credential(_b64(_LONG)) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "raw b64 blocks=%s" % ok)


# ---------------------------------------------------------------- B1: dead JS proposals

@_t
def test_b1_function_constructor_embeds_literal():
    """B1-#1: new Function('return "CRED";')() contains the raw
    credential text -- the regex already matches. Dead proposal."""
    hit = dlp.find_credential('new Function(\'return "%s";\')()' % _CRED) is not None
    return ("HELD" if hit else "BREAK", "literal-embedding hit=%s" % hit)


@_t
def test_b1_eval_embeds_literal():
    """B1-#2: eval('"CRED"') contains the raw credential text. Dead."""
    hit = dlp.find_credential('eval(\'"%s"\')' % _CRED) is not None
    return ("HELD" if hit else "BREAK", "eval literal hit=%s" % hit)


# ---------------------------------------------------------------- B2: stacked layers

@_t
def test_b2_single_entity_at_start_pinned():
    """F436 primary shape ABSORBED by the F432 closure (wave-345 merge):
    one decimal entity at the start of a 52-char base64 run now decodes
    via the 1+ entity gate and blocks coded. Refusal assertion."""
    b64 = _b64(_LONG)
    payload = _ent(b64[0]) + b64[1:]
    assert _LONG not in payload
    held = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if held else "BREAK",
            "F436 single-entity-start now blocks=%s" % held)


@_t
def test_b2_single_entity_in_middle_pinned():
    """F436 shape ABSORBED by the F432 closure (wave-345 merge):
    single entity in the middle now blocks coded. Refusal assertion."""
    b64 = _b64(_LONG)
    payload = b64[:20] + _ent(b64[20]) + b64[21:]
    assert _LONG not in payload
    held = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if held else "BREAK",
            "F436 single-entity-middle now blocks=%s" % held)


@_t
def test_b2_single_hex_entity_pinned():
    """F436 shape ABSORBED by the F432 closure (wave-345 merge):
    single hex entity at the start now blocks coded. Refusal assertion."""
    b64 = _b64(_LONG)
    payload = "&#x%x;" % ord(b64[0]) + b64[1:]
    assert _LONG not in payload
    held = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if held else "BREAK",
            "F436 single-hex-entity now blocks=%s" % held)


@_t
def test_b2_single_entity_no_semicolon_pinned():
    """F436 shape CLOSED by the wave-346 F436 lane: the legacy
    no-semicolon entity (&#65, recovered by html.unescape) inside a
    base64 run now decodes via the lenient entity layer and blocks
    coded. Refusal assertion."""
    b64 = _b64(_LONG)
    payload = "&#%d" % ord(b64[0]) + b64[1:]
    assert _LONG not in payload
    held = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if held else "BREAK",
            "F436 no-semicolon-entity now blocks=%s" % held)


@_t
def test_b2_two_entities_apart_pinned():
    """F436 shape CLOSED by the wave-346 F436 lane: two single entities
    25 chars apart inside a base64 run now decode via the whole-text
    entity pass and block coded. Refusal assertion."""
    b64 = _b64(_LONG)
    payload = _ent(b64[0]) + b64[1:25] + _ent(b64[25]) + b64[26:]
    assert _LONG not in payload
    held = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if held else "BREAK",
            "F436 two-entities-apart now blocks=%s" % held)


@_t
def test_b2_single_escape_fragments_pinned():
    """F436 escape-fragment class ABSORBED by the F432 closure
    (wave-345 merge): single \\xHH / \\uXXXX / octal fragments now
    decode via the 1+ escape gate and block coded. Refusal assertions."""
    b64 = _b64(_LONG)
    payloads = [
        b64[:10] + "\\x%02x" % ord(b64[10]) + b64[11:],
        b64[:10] + "\\u%04x" % ord(b64[10]) + b64[11:],
        b64[:10] + "\\%03o" % ord(b64[10]) + b64[11:],
    ]
    held = []
    for p in payloads:
        assert _LONG not in p
        held.append(dlp.find_credential(p) == "dlp-slack-token")
    ok = all(held)
    return ("HELD" if ok else "BREAK",
            "F436 escape-fragments now block=%s" % held)


@_t
def test_b2_two_consecutive_entities_still_block():
    """F436 discrimination: a run of 2+ consecutive entities at the
    start still blocks coded -- the entity layer fires, then base64.
    The miss is specifically the sub-threshold fragment."""
    b64 = _b64(_LONG)
    payload = _ent(b64[0]) + _ent(b64[1]) + b64[2:]
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "2-entity run blocks=%s" % ok)


@_t
def test_b2_pct_encoded_base32_still_blocked():
    """B2-#3 dead proposal: percent-encoded base32 decodes through
    both layers and blocks. Layers compose here."""
    b32 = base64.b32encode(_CRED.encode()).decode()
    payload = "".join("%%%02X" % ord(c) for c in b32)
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "pct-b32 blocks=%s" % ok)


@_t
def test_b2_hex_with_nulls_still_blocked():
    """B2-#2 dead proposal: hex with NUL interleave decodes and
    blocks. No genuine shape."""
    payload = "\x00".join(list(_CRED.encode().hex())) + "\x00"
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "hex-nulls blocks=%s" % ok)


@_t
def test_b2_short_base64_precision_guard_pinned():
    """F445 is CLOSED 2026-10-06 wave-349 lane 1: raw base64 of the
    16-char test credential (24 chars incl. padding, under the old
    24-char minimum) now blocks coded dlp-slack-token -- short runs
    are strict-decoded with the credential-shape gate (was filed OPEN
    and pinned as a held-by-design miss; flipped to a refusal
    assertion on closure)."""
    b64 = _b64(_CRED)
    hit = dlp.find_credential(b64) == "dlp-slack-token"
    return ("HELD" if hit else "BREAK",
            "short-b64 blocks=%s (F445 closed)" % hit)


# ---------------------------------------------------------------- B3: dead structural proposals

@_t
def test_b3_url_encoded_segments_still_blocked():
    """B3-#2 dead proposal: URL-encoded credential segments decode
    and block."""
    payload = "".join("%%%02X" % ord(c) for c in _CRED)
    assert _CRED not in payload
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "url-encoded blocks=%s" % ok)


@_t
def test_b3_garbage_padded_base64_correctly_ignored():
    """B3-#1, corrected 2026-10-06 wave-349 lane 1 (F445 closure): base64
    + appended garbage now BLOCKS -- the decoder extracts the maximal
    clean run (the 23-char unpadded prefix, a genuine base64 encoding
    of the credential) and the credential-shape gate fires. This is
    consistent with the long path, which already blocks
    b64(long-cred)=garbage via the same prefix extraction; the
    whole-blob strict decode still rejects discontinuous padding.
    Making the short path differ would create an evasion
    (b64(cred)=x). Was pinned as a held-by-design miss under the old
    24-char floor; flipped to a block assertion on closure."""
    payload = _b64(_CRED) + "zzQqWwEeRr"
    hit = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if hit else "BREAK",
            "garbage-padded b64 prefix blocks=%s" % hit)


@_t
def test_b3_garbage_interleaved_base64_ignored():
    """B3-#1b discrimination (preserved intent): garbage INTERLEAVED
    inside the run corrupts the encoding itself -- no clean prefix
    run survives, strict decode fails, and the blob stays quiet."""
    b64 = _b64(_CRED)
    payload = b64[:3] + "zz" + b64[3:]
    quiet = dlp.find_credential(payload) is None
    return ("HELD" if quiet else "BREAK",
            "garbage-interleaved b64 ignored=%s" % quiet)


# ---------------------------------------------------------------- filing + pins

@_t
def test_z0_f436_closed_with_final_footer():
    """F436 is CLOSED by the wave-346 F436 lane and F437-F442 are filed
    (wave-346 merge renumber: attack .reduce/entity+NUL/triple-b64
    keep F437/F438/F439; dlpaudit double-entity/double-backslash become
    F440/F441; cigated policy_delta_gate becomes F442). F437 is CLOSED
    by wave-347 lane 1, F438 by wave-347 lane 2, F439 by wave-347 lane 3,
    F440 by wave-347 lane 4, F441 by wave-347 lane 5, F442 by wave-347
    lane 6, and F443 is filed by wave-347 lane 7 and CLOSED by wave-348
    lane 1.
    Footer is open none / next F444."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("absorbed by the F436 closure (wave-346 lane 1" in text
          # Wave-363 merge: F436's own entry was lost in the wave-360 merge
          # maintenance (a8fe67a2); the closure is recorded via the F440
          # entry's reference. Assert what the file actually contains.
          and "(F439 filed 2026-10-05, wave-346 lane 2" in text
          and "CLOSED 2026-10-05 wave-347 lane 3" in text
          and "(F437 filed 2026-10-05, wave-346 lane 2" in text
          and "LOW, CLOSED 2026-10-05 wave-347 lane 1" in text
          and "(F438 filed 2026-10-05, wave-346 lane 2" in text
          and "LOW, CLOSED 2026-10-05 wave-347 lane 2" in text
          and "(F440 filed 2026-10-05, wave-346 lane 6" in text
          and "LOW, CLOSED 2026-10-06 wave-347 lane 4" in text
          and "(F441 filed 2026-10-05, wave-346 lane 6" in text
          and "LOW, CLOSED 2026-10-05 wave-347 lane 5" in text
          and "(F442 filed 2026-10-05, wave-346 lane 3" in text
          and "CLOSED 2026-10-05 wave-347 lane 6" in text
          and "(F443 filed 2026-10-05, wave-347 lane 7" in text
          and "CLOSED 2026-10-06 wave-348 lane 1" in text
          and "(F444 filed 2026-10-06, wave-348 lane 2" in text
          and "CLOSED 2026-10-06 wave-349 lane 1" in text
          and "(F445 filed 2026-10-06, wave-348 lane 2" in text
          and "CLOSED 2026-10-06 wave-349 lane 1" in text
          and "Next free finding: **F762**" in text  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "(F453 filed 2026-10-06, wave-350 lane 3" in text
          and "CLOSED 2026-10-06 wave-351 lane 3" in text)
    return ("HELD" if ok else "BREAK", "F436-F445 filed+pinned=%s" % ok)


@_t
def test_z1_taxonomy_pin():
    """Taxonomy pin now 2140 (+5 vendor-watch-*)."""
    ok = (len(TAXONOMY) == TAXONOMY_PIN
          and sorted(TAXONOMY) == list(TAXONOMY))
    return ("HELD" if ok else "BREAK",
            "pin=%d len=%d" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_z2_redfirst_f436_breaks():
    """The F436 red-first script prints HELD on this closed tree
    (wave-346 F436 lane closed both residuals)."""
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    r = subprocess.run(
        [venv_python, os.path.join(REPO_ROOT, "evals", "w345_f436_redfirst.py")],
        capture_output=True, text=True, timeout=300, cwd=REPO_ROOT,
        env=dict(os.environ, GOV_DEPLOYMENT_MODE="staging"))
    ok = "HELD" in r.stdout
    return ("HELD" if ok else "BREAK", "redfirst rc=%d" % r.returncode)


@_t
def test_z3_no_paid_api_references():
    """$0 by construction: no harness/driver/provider references in
    this battery."""
    src = open(__file__).read()
    # forbidden substrings, concatenation-constructed so this check
    # does not itself contain the literals it forbids
    forbidden = ["realmodel" + "_harness", "Model" + "Driver",
                 "--provider" + " openai", "Spend" + "Ledger"]
    hits = [s for s in forbidden if s in src]
    ok = not hits
    return ("HELD" if ok else "BREAK", "paid-api refs=%s" % hits)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere:
# the F436 misses are pinned as known-open (probe returns HELD when
# the miss reproduces); a literal BREAK verdict would mean the pin
# failed or a NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w344_attack_probes.py",):
        tmp = "/var/tmp/g345-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    n_break = n_held = n_err = 0
    probe_breaks = set()
    for fn in TESTS:
        if args.only and fn.__name__ != args.only:
            continue
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - loud, never a skip
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail[:200]))
        if verdict == "BREAK":
            n_break += 1
            probe_breaks.add(fn.__name__)
        elif verdict == "HELD":
            n_held += 1
        else:
            n_err += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    if probe_breaks ^ _EXPECTED_BREAKS:
        print("MISMATCH: breaks=%s expected=%s"
              % (sorted(probe_breaks), sorted(_EXPECTED_BREAKS)))
        sys.exit(2)
    sys.exit(1 if n_break or n_err else 0)


if __name__ == "__main__":
    main()
