#!/usr/bin/env python3
"""Wave-352 F456 closure battery (lane 2).

F456 (LOW, filed 2026-10-06 wave-351 lane 4 (continuous real-model
attack, round 19); CLOSED 2026-10-06 wave-352 lane 2): base64
fragmented with non-whitespace junk evaded every base64 scan path --
base64.b64decode(validate=False) discards EVERY ASCII character
outside the base64 alphabet before decoding (verified: '\\x00' / '!'
/ '.' inserted at every one of 28 positions decode identically),
not just whitespace, so the base64 of a credential with junk
inserted decodes exactly in a real parser while _B64_RUN (24
contiguous alphabet chars) matches nothing and _iter_b64_ws_spans
(F449) requires whitespace-only gaps. Distinct from F449
(whitespace-only spans): different character class, different gap
predicate -- same filing precedent as F451-vs-F449.

Closure design (gov/dlp.py, no new regexes -- linear manual scans,
compose don't fork):
- _is_b64_junk_gap: exactly the chars stdlib discards on str input
  (ASCII whitespace + every other ASCII non-alphabet char except
  '='; '-'/'_' included -- verified discarded at every position).
  '=' is a span BREAKER (verified: truncates at pos%4==3, '=='
  mid-string truncates, 'SGVsbG8=!V29ybGQ=' decodes to b'Hello'
  only -- stripping it would emit variants a real parser does not
  produce). Non-ASCII breaks (b64decode(str) raises -- fail closed).
  No parity sensitivity (verified; unlike F451 hex byte-boundary
  parity).
- _B64_STRICT_ALPHABET (no '-'/'_'): the junk walker fragments at
  '-'/'_' so inserted dash/underscore junk is stripped; genuine
  base64url stays owned by the unchanged contiguous _B64_RUN path
  (normalizes '-'/'_' to '+/'). Both interpretations are attempted;
  the credential-shape gate keeps the duality from
  false-positiving (verified A/B identical on base64url payloads).
- _iter_b64_junk_spans: maximal strict-alphabet spans with >= 1
  non-whitespace junk gap and >= _B64_SHORT_FLOOR alphabet chars;
  pure-whitespace spans SKIPPED (F449 owns them -- no fixpoint seed
  duplication, no _MAX_CANDIDATES budget perturbation).
- _b64_junk_variants: sub-word-runs longest-first through the
  shared _gated_encoded_variants (strict decode + credential-shape
  gate; per-call _MAX_CANDIDATES attempt budget).
- Fixpoint seeds (F453 composition): junk spans seed
  _b64_fixpoint_variants as junk-stripped whole-span candidates --
  a junk-fragmented (or mixed ws+junk) outer over an inner stack
  composes like the F453 ws-outer case.
- Pipeline: _b64_junk_variants wired after _b64_ws_variants
  (additive; F449 path byte-identical).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed shapes block; fixed-seed randomized
      junk-insertion differential (block iff b64decode accepts);
      every ASCII junk class blocks incl. '-'/'_'; dense
      fragmentation blocks; mixed ws+junk outer over inner stack
      blocks (F453 composition); pure-junk outer over inner stack
      blocks.
  P2  controls: plain credential blocks; contiguous b64 blocks;
      junk-of-junk quiet (round-trip); '='-interior spans emit no
      junk variant with the credential (fail closed); non-ASCII
      junk emits no junk variant (fail closed); pure-ws spans not
      yielded by the junk walker (F449 owns them).
  P3  decoder pins: strict alphabet ('-'/'_' are gaps); '='
      breaker; non-ASCII breaker; gap charset exact (ASCII-only);
      no parity sensitivity; alpha floor 8; span cap
      _B64_WS_MAX_SPAN; maximal spans; sub-run longest-first +
      single-word skip; per-call _MAX_CANDIDATES attempt budget;
      credential-shape gate decides variants; stdlib fidelity
      spot-checks.
  P4  discrimination: innocent hyphenated/underscored words quiet;
      FP corpus (repo docs) hit-set identical to base (pinned).
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F449 ws-b64,
      F450 short hex, F451 ws-hex, F452, F453 stacks, F444, F445
      short-b64, F446, F447/F448); F454/F455/F457-F460 pinned open.
  P7  pin + footer: taxonomy pin 2140 (no new decision codes),
      footer open F454, F455, F457, F458, F459, F460 / next F461,
      F456 CLOSED entry present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w352_f456close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import random
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-352: F456 closed, no new decision codes; pin unchanged; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F672, F673, F674, F675, F676, F677, F678, F679, F680, F681, F682, F683, F684, F685"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352: F456 CLOSED (merge finalizes tree-wide)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 lane 1: F461+F462 CLOSED (merge finalizes tree-wide)  # Wave-353 lane 4: F467+F468 CLOSED locally (merge finalizes tree-wide)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 lane 5: F603 CLOSED  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)
FOOTER_NEXT = "F686"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials -- constructed via concatenation, never literals.
_CRED = "xox" + "b-0123456789abcdef"  # 21 chars -> 28 b64 chars
_LONG = "xox" + "b-" + "z" * 40  # 45 chars
_JUNK_CLASSES = ["\x00", "!", ".", "#", "\x7f", "~", "-", "_",
                 "\x01", "\x02"]


def _b64(b):
    return base64.b64encode(b).decode()


def _frag(s, junk, every=12):
    parts, i = [], 0
    while i < len(s):
        parts.append(s[i:i + every])
        i += every
        if i < len(s):
            parts.append(junk)
    return "".join(parts)


def _blocked(payload):
    return dlp.find_credential(payload) == "dlp-slack-token"


# ---------------------------------------------------------------- P1: closure

def p1_closure_f456_filed_shapes():
    b64 = _b64(_CRED.encode())
    for junk in ("\x00", "!", "."):
        p = _frag(b64, junk)
        assert base64.b64decode(p, validate=False) == _CRED.encode()
        if not _blocked("k=" + p + ";"):
            return False
    return True


def p1_closure_f456_junk_classes():
    # Every ASCII junk class (incl. '-'/'_') is bridged.
    b64 = _b64(_LONG.encode())
    for junk in _JUNK_CLASSES:
        p = "id=" + b64[:12] + junk + b64[12:24] + junk + b64[24:] + ";"
        assert base64.b64decode(
            b64[:12] + junk + b64[12:24] + junk + b64[24:],
            validate=False) == _LONG.encode()
        if not _blocked(p):
            return False
    return True


def p1_closure_f456_randomized_differential():
    # Fixed seed. Fidelity is bidirectional: block iff stdlib
    # b64decode recovers the credential from the junked run.
    rnd = random.Random(20261006)
    alphabet = [chr(c) for c in range(128)
                if chr(c) not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                and chr(c) != "="]
    b64 = _b64(_CRED.encode())
    for _ in range(120):
        junk = rnd.choice(alphabet)
        p = b64
        for _ in range(rnd.randint(1, 3)):
            pos = rnd.randint(0, len(p))
            p = p[:pos] + junk * rnd.randint(1, 2) + p[pos:]
        payload = "id=" + p + ";"
        try:
            real_ok = base64.b64decode(p, validate=False) == _CRED.encode()
        except Exception:
            real_ok = False
        scan_hit = _blocked(payload)
        if real_ok != scan_hit:
            return False
    return True


def p1_closure_f456_dense_fragmentation():
    b64 = _b64(_CRED.encode())
    for junk in ("\x00", "!", ".", "-", "_"):
        p = junk.join(b64[i:i + 4] for i in range(0, len(b64), 4))
        assert base64.b64decode(p, validate=False) == _CRED.encode()
        if not _blocked("k=" + p):
            return False
    return True


def p1_closure_f456_mixed_outer_stack():
    # F453 composition: mixed ws+junk fragmented outer over a
    # contiguous inner stack.
    inner = _b64(_CRED.encode())
    outer_b64 = _b64(inner.encode())
    mixed = []
    for i, ch in enumerate(outer_b64):
        mixed.append(ch)
        if i % 5 == 4:
            mixed.append(" ")
        if i % 7 == 6:
            mixed.append("!")
    outer = "".join(mixed)
    assert base64.b64decode(
        base64.b64decode(outer, validate=False).decode(),
        validate=False) == _CRED.encode()
    return _blocked("z=" + outer + ";")


def p1_closure_f456_junk_outer_stack():
    # Pure-junk fragmented outer over a contiguous inner stack.
    inner = _b64(_CRED.encode())
    outer_b64 = _b64(inner.encode())
    outer = "!".join(outer_b64[i:i + 6]
                     for i in range(0, len(outer_b64), 6))
    assert base64.b64decode(
        base64.b64decode(outer, validate=False).decode(),
        validate=False) == _CRED.encode()
    return _blocked("z=" + outer + ";")


# ---------------------------------------------------------------- P2: controls

def p2_control_plain_credential():
    return _blocked(_CRED)


def p2_control_contiguous_b64():
    return _blocked("k=" + _b64(_CRED.encode()) + ";")


def p2_control_junk_of_junk_quiet():
    # Junk-fragmented base64 of non-credential text stays quiet
    # (round-trip validation).
    jb = _b64(b"deadbeef")
    p = "!".join(jb[i:i + 4] for i in range(0, len(jb), 4))
    assert base64.b64decode(p, validate=False) == b"deadbeef"
    return not _blocked("id=" + p + ";")


def p2_control_eq_interior_fail_closed():
    # '=' breaks junk spans: no junk variant may carry the
    # credential when the real parser truncates (fail closed).
    b64 = _b64(_CRED.encode())
    for p in (b64[:14] + "==" + b64[14:],       # truncates
              b64[:12] + "=" + b64[12:]):        # discarded at boundary
        variants = list(dlp._b64_junk_variants("id=" + p + ";"))
        if any(_CRED in v for v in variants):
            try:
                real = base64.b64decode(p, validate=False)
            except Exception:
                real = None
            if real != _CRED.encode():
                return False
    return True


def p2_control_non_ascii_junk_fail_closed():
    # Non-ASCII junk breaks spans (b64decode(str) raises).
    b64 = _b64(_CRED.encode())
    for junk in ("\u00a0", "\u200b", "\u00e9"):
        p = b64[:12] + junk + b64[12:]
        try:
            base64.b64decode(p, validate=False)
            real_ok = True
        except Exception:
            real_ok = False
        variants = list(dlp._b64_junk_variants("id=" + p + ";"))
        if not real_ok and any(_CRED in v for v in variants):
            return False
    return True


def p2_control_ws_span_not_duplicated():
    # Pure-whitespace spans are F449-owned: the junk walker must not
    # yield them (no seed duplication).
    b64 = _b64(_CRED.encode())
    p = "id=" + b64[:12] + " " + b64[12:24] + "\t" + b64[24:] + ";"
    spans = list(dlp._iter_b64_junk_spans(p))
    return spans == []


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_strict_alphabet_dash_underscore_gaps():
    # '-'/'_' are gaps in the junk walker (strict alphabet).
    assert "-" not in dlp._B64_STRICT_ALPHABET
    assert "_" not in dlp._B64_STRICT_ALPHABET
    assert dlp._is_b64_junk_gap("-") and dlp._is_b64_junk_gap("_")
    # ...but still word chars for the contiguous path (base64url).
    assert "-" in dlp._B64_ALPHABET and "_" in dlp._B64_ALPHABET
    return True


def p3_pin_eq_breaker():
    assert not dlp._is_b64_junk_gap("=")
    b64 = _b64(_CRED.encode())
    p = "id=" + b64[:12] + "=" + b64[12:] + ";"
    spans = list(dlp._iter_b64_junk_spans(p))
    # '=' splits; neither side alone is a junk span here (single words)
    return all("=" not in "".join(p[s:e] for s, e in w)
               for _, _, w in spans)


def p3_pin_non_ascii_breaker():
    for ch in ("\u00a0", "\u200b", "\u00e9", "\U0001f600"):
        if dlp._is_b64_junk_gap(ch):
            return False
    return True


def p3_pin_gap_charset_exact():
    # ASCII-only: every ASCII non-alphabet char except '=' is a gap;
    # nothing else is.
    for c in range(128):
        ch = chr(c)
        want = (ch in " \t\n\r\x0b\x0c"
                or (ch not in dlp._B64_STRICT_ALPHABET and ch != "="))
        if dlp._is_b64_junk_gap(ch) != want:
            return False
    return True


def p3_pin_no_parity_sensitivity():
    # Junk at any position bridges identically (unlike F451 hex).
    b64 = _b64(_CRED.encode())
    for pos in range(len(b64)):
        p = "id=" + b64[:pos] + "!" + b64[pos:] + ";"
        if not _blocked(p):
            return False
    return True


def p3_pin_alpha_floor():
    # < 8 alphabet chars -> no span, even with junk gaps.
    spans = list(dlp._iter_b64_junk_spans("id=ab!cd;"))
    return spans == []


def p3_pin_span_cap():
    assert dlp._B64_WS_MAX_SPAN == 4 * dlp._MAX_DECODE_BYTES
    big = "!" .join(["abcd" * 8] * 600)  # span >> cap
    spans = list(dlp._iter_b64_junk_spans("id=" + big + ";"))
    return spans == []


def p3_pin_maximal_spans():
    b64 = _b64(_CRED.encode())
    p = "id=" + b64[:12] + "!" + b64[12:] + ";"
    spans = list(dlp._iter_b64_junk_spans(p))
    if len(spans) != 1:
        return False
    s, e, words = spans[0]
    return p[s:e] == b64[:12] + "!" + b64[12:] and len(words) == 2


def p3_pin_subrun_longest_first_single_skip():
    # Longest-first: the whole-span blob is attempted first; single
    # words are never blobs.
    seen = []
    orig = dlp._gated_encoded_variants

    def spy(text, matches, decode):
        for s, e, blob in matches:
            seen.append(blob)
        return iter(())
    dlp._gated_encoded_variants = spy
    try:
        list(dlp._b64_junk_variants(
            "id=" + "aabb!" + "ccdd!" + "eeff" + ";"))
    finally:
        dlp._gated_encoded_variants = orig
    return (seen and seen[0] == "aabbccddeeff"
            and all(len(b) > 4 for b in seen))


def p3_pin_attempt_budget():
    # Per-call _MAX_CANDIDATES decode attempts, not per-span.
    attempts = [0]
    orig = dlp._try_b64_decode

    def counting(blob, min_payload=24):
        attempts[0] += 1
        return orig(blob, min_payload=min_payload)
    dlp._try_b64_decode = counting
    try:
        words = "!".join(["abcd" * 6] * 12)
        list(dlp._b64_junk_variants("id=" + words + ";"))
    finally:
        dlp._try_b64_decode = orig
    return attempts[0] <= dlp._MAX_CANDIDATES


def p3_pin_shape_gate_not_just_decode():
    # A junk span that strict-decodes to non-credential text emits
    # no variant.
    jb = _b64(b"deadbeef")
    p = "!".join(jb[i:i + 4] for i in range(0, len(jb), 4))
    variants = list(dlp._b64_junk_variants("id=" + p + ";"))
    return variants == []


def p3_pin_shape_gate_emits_for_credential():
    b64 = _b64(_CRED.encode())
    p = _frag(b64, "!")
    variants = list(dlp._b64_junk_variants("id=" + p + ";"))
    return any(_CRED in v for v in variants)


def p3_pin_fidelity_spot():
    # Spot-checks: scanner variant decode == stdlib decode.
    b64 = _b64(_CRED.encode())
    for junk in ("\x00", "!", ".", "-", "_"):
        p = _frag(b64, junk, every=7)
        std = base64.b64decode(p, validate=False).decode()
        variants = list(dlp._b64_junk_variants("k=" + p + ";"))
        if not any(std in v for v in variants):
            return False
    return True


# ---------------------------------------------------------------- P4: discrimination

def p4_discr_innocent_words_quiet():
    return (not _blocked("well-known")
            and not _blocked("user_name-test")
            and not _blocked("e-mail_address")
            and not _blocked("the quick-brown_fox"))


_FP_BASELINE = {
    "README.md": "dlp-github-token",
    "SITUATION_MATRIX.md": "dlp-aws-access-key",
    "docs/decision-code-coverage.md": "dlp-entropy-tripwire",
    "evals/FINDINGS.md": "dlp-aws-access-key",
    "evals/SITUATION_MATRIX.md": "dlp-aws-access-key",
}


def p4_discr_fp_corpus_identical():
    import glob
    corpus = sorted(glob.glob("README.md") + glob.glob("docs/*.md")
                    + glob.glob("evals/*.md")
                    + ["BUILD_LOG.md", "THREAT_MODEL.md",
                       "SITUATION_MATRIX.md"])
    hits = {}
    for p in corpus:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                t = f.read()
        except OSError:
            continue
        r = dlp.find_credential(t[:200000])
        if r:
            hits[p] = r
    return hits == _FP_BASELINE


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    hostile = [
        "!" * 5000,
        ("ab!" * 2000),
        ("a" * 100 + "!" + "b" * 100) * 20,
        "\x00" * 3000 + "abcd" * 100,
        ("-" * 50 + "_") * 100,
    ]
    t0 = time.time()
    for h in hostile:
        dlp.find_credential("id=" + h + ";")
        list(dlp._b64_junk_variants(h))
        list(dlp._iter_b64_junk_spans(h))
    return time.time() - t0 < 10


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f449_ws_b64():
    b64 = _b64(_CRED.encode())
    ws = b64[:12] + " " + b64[12:24] + "\n" + b64[24:]
    assert base64.b64decode(ws, validate=False) == _CRED.encode()
    return _blocked("k=" + ws)


def p6_noreg_f450_short_hex():
    hx = b"xoxb-1234567890".hex()
    return _blocked("h=" + hx[:20] + " " + hx[20:])


def p6_noreg_f451_ws_hex():
    hx = _CRED.encode().hex()
    p = hx[:20] + " " + hx[20:]
    assert bytes.fromhex(p) == _CRED.encode()
    return _blocked("h=" + p)


def p6_noreg_f452_closed():
    # F452 (CLOSED wave-351 lane 2): 32 bare string-literal
    # statements + a real reduce assembly now blocks (the attempt
    # budget no longer burns on undecodable matches).
    junk = "".join("'%s';" % ("j%d" % i) for i in range(32))
    real = "['xoxb-','0123456789abcdef'].reduce((a,b)=>a+b)"
    return _blocked(junk + real)


def p6_noreg_f453_ws_outer_stack():
    inner = _b64(_CRED.encode())
    outer = _b64(inner.encode())
    ws_outer = " ".join(outer[i:i + 8] for i in range(0, len(outer), 8))
    assert base64.b64decode(
        base64.b64decode(ws_outer, validate=False).decode(),
        validate=False) == _CRED.encode()
    return _blocked("z=" + ws_outer + ";")


def p6_noreg_f444_junk_prefix():
    return _blocked("'jk1'+'jk2';" + "['xoxb-','0123456789abcdef'].join('')")


def p6_noreg_f445_short_b64():
    cred = "xox" + "b-abc123" + "def" + "456"  # 16 chars
    short = _b64(cred.encode())  # 23 payload chars < 24
    assert _blocked(cred)
    return _blocked("k=" + short)


def p6_noreg_f446_array_of():
    return _blocked("Array.of('xoxb-','0123456789abcdef').join('')")


def p6_noreg_f447f448_closed():
    # F447/F448 (CLOSED wave-350): pin representative shapes.
    return _blocked("['xoxb-','0123456789abcdef'].reduce((a,b)=>a+b)")


def p6_pin_f454_open():
    # F454 CLOSED (wave-352 merge): multi-arg Array constructor blocks.
    return _blocked("Array('xoxb-','0123456789abcdef').join('')")


def p6_pin_f455_open():
    # F455 CLOSED (wave-352 merge): ws before dot blocks.
    return _blocked("Array .of('xoxb-','0123456789abcdef').join('')")


def p6_pin_f457_open():
    # F457 CLOSED (wave-352 merge): template `${}` interpolation blocks.
    return _blocked("`xoxb-${'0123456789abcdef'}`")


def p6_pin_f458_open():
    # F458 CLOSED (wave-352 merge): String.fromCharCode with octal
    # spellings blocks.
    codes = ",".join("0o%o" % ord(ch) for ch in "xoxb-0123456789abcdef")
    return _blocked("String.fromCharCode(%s)" % codes)


def p6_pin_f459_open():
    # F459 CLOSED (wave-352 merge): positional/index .filter predicates
    # block.
    return _blocked(
        "['xoxb-','0123456789abcdef','zz'].filter((x,i)=>i<2).join('')")


def p6_pin_f460_open():
    # F460 CLOSED (wave-352 merge): .map(String) blocks.
    return _blocked("['xoxb-','0123456789abcdef'].map(String).join('')")


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    # This lane closes F456 locally; the merge finalizes tree-wide.
    # Accept the lane footer (F456 closed) -- the base footer still
    # lists F456 open until the merge sweep. Wave-353 lane 1: the
    # merge-finalized footer now lists F461+F462 closed too.
    ok = ok and (("Open findings: %s." % FOOTER_OPEN) in footer
                 or "Open findings: F672, F673, F674, F675, F676, F677, F678, F679, F680, F681, F682, F683, F684, F685."  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 lane 5: F603 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
                 in footer)
    ok = ok and "(F456 " in footer
    return ok


_PROBES = [
    ("p1-closure-f456-filed-shapes", p1_closure_f456_filed_shapes),
    ("p1-closure-f456-junk-classes", p1_closure_f456_junk_classes),
    ("p1-closure-f456-randomized-differential",
     p1_closure_f456_randomized_differential),
    ("p1-closure-f456-dense-fragmentation",
     p1_closure_f456_dense_fragmentation),
    ("p1-closure-f456-mixed-outer-stack", p1_closure_f456_mixed_outer_stack),
    ("p1-closure-f456-junk-outer-stack", p1_closure_f456_junk_outer_stack),
    ("p2-control-plain-credential", p2_control_plain_credential),
    ("p2-control-contiguous-b64", p2_control_contiguous_b64),
    ("p2-control-junk-of-junk-quiet", p2_control_junk_of_junk_quiet),
    ("p2-control-eq-interior-fail-closed", p2_control_eq_interior_fail_closed),
    ("p2-control-non-ascii-junk-fail-closed",
     p2_control_non_ascii_junk_fail_closed),
    ("p2-control-ws-span-not-duplicated", p2_control_ws_span_not_duplicated),
    ("p3-pin-strict-alphabet-dash-underscore-gaps",
     p3_pin_strict_alphabet_dash_underscore_gaps),
    ("p3-pin-eq-breaker", p3_pin_eq_breaker),
    ("p3-pin-non-ascii-breaker", p3_pin_non_ascii_breaker),
    ("p3-pin-gap-charset-exact", p3_pin_gap_charset_exact),
    ("p3-pin-no-parity-sensitivity", p3_pin_no_parity_sensitivity),
    ("p3-pin-alpha-floor", p3_pin_alpha_floor),
    ("p3-pin-span-cap", p3_pin_span_cap),
    ("p3-pin-maximal-spans", p3_pin_maximal_spans),
    ("p3-pin-subrun-longest-first-single-skip",
     p3_pin_subrun_longest_first_single_skip),
    ("p3-pin-attempt-budget", p3_pin_attempt_budget),
    ("p3-pin-shape-gate-not-just-decode",
     p3_pin_shape_gate_not_just_decode),
    ("p3-pin-shape-gate-emits-for-credential",
     p3_pin_shape_gate_emits_for_credential),
    ("p3-pin-fidelity-spot", p3_pin_fidelity_spot),
    ("p4-discr-innocent-words-quiet", p4_discr_innocent_words_quiet),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f449-ws-b64", p6_noreg_f449_ws_b64),
    ("p6-noreg-f450-short-hex", p6_noreg_f450_short_hex),
    ("p6-noreg-f451-ws-hex", p6_noreg_f451_ws_hex),
    ("p6-noreg-f452-closed", p6_noreg_f452_closed),
    ("p6-noreg-f453-ws-outer-stack", p6_noreg_f453_ws_outer_stack),
    ("p6-noreg-f444-junk-prefix", p6_noreg_f444_junk_prefix),
    ("p6-noreg-f445-short-b64", p6_noreg_f445_short_b64),
    ("p6-noreg-f446-array-of", p6_noreg_f446_array_of),
    ("p6-noreg-f447f448-closed", p6_noreg_f447f448_closed),
    ("p6-pin-f454-open", p6_pin_f454_open),
    ("p6-pin-f455-open", p6_pin_f455_open),
    ("p6-pin-f457-open", p6_pin_f457_open),
    ("p6-pin-f458-open", p6_pin_f458_open),
    ("p6-pin-f459-open", p6_pin_f459_open),
    ("p6-pin-f460-open", p6_pin_f460_open),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:
        print("%-42s ERROR %s: %s" % (pid, type(e).__name__, e))
        return (pid, "ERROR")
    print("%-42s %s" % (pid, "HELD" if ok else "BREAK"))
    return (pid, "HELD" if ok else "BREAK")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w351_attack_probes.py",
               "w350_attack_probes.py",
               "w351_f453close_probes.py",
               "w351_f452close_probes.py",
               "w351_f451close_probes.py",
               "w350_f449f450close_probes.py",
               "w346_dlp_composition_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g352-green-%s-%d" % (script.replace(".py", ""),
                                            os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if "unexpected BREAKs" in out or "expected BREAKs missing" in out:
            raise AssertionError("green check failed: %s" % notes[-1])
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                return 0 if verdict == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v == "BREAK")
    held = sum(1 for _, v in results if v == "HELD")
    err = sum(1 for _, v in results if v == "ERROR")
    print("w352_f456close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
