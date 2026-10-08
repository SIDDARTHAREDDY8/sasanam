#!/usr/bin/env python3
"""Wave-351 F451 closure battery (lane 1).

F451 (LOW, filed 2026-10-06 wave-350 lane 4 (continuous real-model
attack, round 18); CLOSED 2026-10-06 wave-351 lane 1): hex with
embedded whitespace evaded the contiguous-run gate -- gov/dlp.py
`_HEX_RUN` needs 16 contiguous byte-pairs (32 hex chars), but
`bytes.fromhex` ignores whitespace, so the hex of a (long,
over-the-F450-length-gate) credential with spaces/newlines inserted
decoded exactly in a real parser (verified: fromhex(spaced)==credential)
while the static scanner matched no run. Distinct from F450 (the
minimum-length gate): this payload is over the length gate and still
misses, on contiguity alone. Distinct from F449 (base64 whitespace): a
different code path (`_HEX_RUN` + `_try_hex_decode` vs `_B64_RUN` +
`_try_b64_decode`) -- a base64-only F449 fix would not cover it.

Closure design (gov/dlp.py, no new regexes -- linear manual scans,
compose don't fork):
- `_iter_hex_ws_spans`: maximal spans of hex-alphabet words joined by
  gaps of exactly the 6 ASCII whitespace chars `bytes.fromhex`
  ignores (space, \\t, \\n, \\r, \\x0b, \\x0c). `str.isspace()` is
  broader (\\x1c-\\x1f, \\x85, \\xa0, \\u2003, \\u2028, \\u2029 are
  REJECTED by fromhex -- verified empirically), so using it would be a
  fidelity false positive.
- Byte-boundary parity, ground-truth exact: `bytes.fromhex` skips
  whitespace only at even hex-digit positions (verified:
  fromhex('a bcd') raises, fromhex('ab cd') decodes). A gap at odd
  digit parity breaks the span (fail closed) -- the scanner never
  emits a variant a real parser would reject.
- `_hex_ws_variants`: sub-word-runs enumerated longest-first through
  the shared `_gated_encoded_variants` helper (strict decode +
  credential-shape gate; per-call `_MAX_CANDIDATES` attempt budget).
  Single-word sub-runs are skipped (the contiguous `_HEX_RUN` /
  `_iter_hex_short_runs` paths own every single word that could pass
  the shape gate).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed shapes block; fixed-seed randomized
      whitespace-insertion differential (block iff fromhex accepts);
      all 6 gap classes block; fragmented multi-gap payloads block.
  P2  controls: plain credential blocks; contiguous hex blocks;
      whitespace-bearing hex junk stays quiet (round-trip);
      0x-prefixed hex quiet (fromhex rejects 'x'); odd-parity gap
      quiet (fail closed); non-ws interior junk quiet (fail closed);
      \\x1c-gap junk quiet (not a fromhex gap char).
  P3  decoder pins: span semantics (maximal, 6-char gap set, alpha
      floor 20, span cap); byte-boundary parity gate (odd gap breaks
      span; even gap continues); sub-run longest-first + single-word
      skip; per-call _MAX_CANDIDATES attempt budget (no per-span
      reset); credential-shape gate (not just decode) decides
      variants; stdlib fidelity spot-checks.
  P4  discrimination: innocent spaced words quiet; FP corpus (repo
      docs) hit-set identical to base (pinned).
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F449 ws-b64, F450
      short hex, F437 reduce, F439 triple-b64, F440 double-entity,
      F441 bslash, F443 fill/filter, F444 junk-prefix, F445
      short-b64); F452/F453 pinned open; ws-hex outer-layer stacks
      documented (F453 mechanism class, not filed).
  P7  pin + footer: taxonomy pin 2143 (no new decision codes),  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
      footer open F452, F453 / next F454, F451 CLOSED entry present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w351_f451close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import random
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2143  # Wave-351: F451 closed, no new decision codes; pin unchanged; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
FOOTER_OPEN = "F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (4/5): F454-F460 CLOSED; open none (next F461)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # Wave-352 merge (2/5): F456+F457 CLOSED; F458-F460 still OPEN (next F461)  # Wave-351: F451 CLOSED; F452/F453 still OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 lane 4: F458-F460 CLOSED (merge finalizes tree-wide); Wave-351: F451 CLOSED; F452/F453 still OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 lane 2: F463 CLOSED, F469 filed OPEN (next F470)  # Wave-353 lane 2 renumber: F469->F472 (attack lane committed F469-F471 first, e79af076); footer next F473  # Wave-353 lane 4: F467+F468 CLOSED locally (merge finalizes tree-wide)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)
FOOTER_NEXT = "F713"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials -- constructed via concatenation, never literals.
_CRED = "xox" + "b-0123456789abcdef"  # 21 chars -> 42 hex chars
_LONG = "xox" + "b-" + "z" * 40  # 45 chars -> 90 hex chars
_WS6 = [" ", "\t", "\n", "\r", "\x0b", "\x0c"]
assert sorted(map(ord, _WS6)) == [9, 10, 11, 12, 13, 32]


def _hex(b):
    return b.hex()


def _blocked(payload):
    return dlp.find_credential(payload) == "dlp-slack-token"


# ---------------------------------------------------------------- P1: closure

def p1_closure_f451_filed_spaced():
    hx = _hex(_CRED.encode())
    spaced = hx[:20] + " " + hx[20:]
    assert bytes.fromhex(spaced) == _CRED.encode()
    return _blocked(spaced)


def p1_closure_f451_filed_newlined():
    hx = _hex(_CRED.encode())
    newlined = hx[:20] + "\n" + hx[20:]
    assert bytes.fromhex(newlined) == _CRED.encode()
    return _blocked(newlined)


def p1_closure_f451_gap_classes():
    # Every whitespace char bytes.fromhex ignores must be bridged.
    hx = _hex(_LONG.encode())
    for gap in _WS6:
        p = "id=" + hx[:20] + gap + hx[20:40] + gap + hx[40:] + ";"
        try:
            assert bytes.fromhex(hx[:20] + gap + hx[20:40] + gap + hx[40:]) == _LONG.encode()
        except ValueError:
            return False  # gap char must be fromhex-ignored by construction
        if not _blocked(p):
            return False
    return True


def p1_closure_f451_fragmented_fuzz():
    # Arbitrary whitespace insertion points (fixed seed). Fidelity is
    # one-directional here: whenever bytes.fromhex accepts the spaced
    # payload, the scanner MUST block (no true misses). When fromhex
    # rejects (odd-parity gap), no assertion -- documented conservative
    # over-approximation on adversarial inputs (see p1 note below).
    rng = random.Random(3511)
    for _ in range(80):
        c = rng.choice((_CRED.encode(), _LONG.encode()))
        hx = c.hex()
        cuts = sorted(rng.sample(range(1, len(hx) - 1), rng.randint(1, 6)))
        parts, prev = [], 0
        for cut in cuts:
            parts.append(hx[prev:cut])
            parts.append(rng.choice(_WS6))
            prev = cut
        parts.append(hx[prev:])
        spaced = "".join(parts)
        try:
            ground = bytes.fromhex(spaced) == c
        except ValueError:
            continue
        if ground and not _blocked("k " + spaced + " k"):
            return False
    return True


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_hex_contiguous():
    return _blocked(_hex(_LONG.encode()))


def p2_control_hex_junk_spaced_quiet():
    # Whitespace-bearing hex junk stays quiet (round-trip validation +
    # the credential-shape gate, not just the decode).
    return not _blocked("deadbeef cafef00d")


def p2_control_hex_0x_prefixed_quiet():
    # bytes.fromhex rejects 'x' -- the scanner must agree (fail closed).
    try:
        bytes.fromhex("0xab 0xcd")
        return False  # ground truth changed; probe needs rework
    except ValueError:
        pass
    return not _blocked("k=0xab 0xcd 0xef")


def p2_control_hex_odd_parity_gap_quiet():
    # Whitespace between nibbles is rejected by fromhex -- the span
    # must break (fail closed), not strip-and-decode.
    try:
        bytes.fromhex("abc def")
        return False  # ground truth changed; probe needs rework
    except ValueError:
        pass
    return not _blocked("k=abc def")


def p2_control_hex_nonws_junk_quiet():
    # Non-whitespace interior junk breaks the span (fail closed).
    hx = _hex(_CRED.encode())
    p = hx[:20] + "!!" + hx[20:]
    try:
        bytes.fromhex(p)
        return False  # ground truth changed; probe needs rework
    except ValueError:
        pass
    return not _blocked(p)


def p2_control_hex_x1c_gap_quiet():
    # \x1c is str.isspace() but NOT fromhex-ignored -- treating it as
    # a gap would be a fidelity false positive.
    try:
        bytes.fromhex("ab\x1ccd")
        return False  # ground truth changed; probe needs rework
    except ValueError:
        pass
    return not _blocked("k=dead\x1cbeef")


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_ws_span_maximal():
    w1, w2 = "ab" * 10, "cd" * 10
    spans = list(dlp._iter_hex_ws_spans("zz " + w1 + " " + w2 + " zz"))
    if len(spans) != 1:
        return False
    s, e, words = spans[0]
    return (s, e) == (3, 44) and words == [(3, 23), (24, 44)]


def p3_pin_ws_span_alpha_floor():
    # Under 20 alphabet chars total: no span (stray spaced words stay
    # out of the scan).
    return list(dlp._iter_hex_ws_spans("ab cd ef")) == []


def p3_pin_ws_span_cap():
    return list(dlp._iter_hex_ws_spans("ab " * 9000)) == []


def p3_pin_ws_gap_charset():
    # Only the 6 fromhex-ignored chars join words; \x1c and \xa0
    # break the span. (Words sized over the alpha floor.)
    w1, w2 = "ab" * 10, "cd" * 10
    yes = list(dlp._iter_hex_ws_spans(w1 + "\x0b" + w2))
    no1 = list(dlp._iter_hex_ws_spans(w1 + "\x1c" + w2))
    no2 = list(dlp._iter_hex_ws_spans(w1 + " " + w2))
    return len(yes) == 1 and no1 == [] and no2 == []


def p3_pin_ws_parity_gate():
    # Odd-parity gap breaks the span (fromhex('a bcd') raises);
    # even-parity gap continues it (fromhex('ab cd') decodes).
    # "ab"*10 + " " + ("cde" + "ab"*8): gap at parity 20 continues,
    # but the stripped blob is odd-length -> strict decode fails ->
    # no variant (fail closed).
    w_odd = "a" * 21
    w_even = "b" * 20
    brk = list(dlp._iter_hex_ws_spans("zz " + w_odd + " " + w_even + " zz"))
    w1, w2 = "ab" * 10, "cde" + "ab" * 8
    text = "zz " + w1 + " " + w2 + " zz"
    cont = list(dlp._iter_hex_ws_spans(text))
    novar = list(dlp._hex_ws_variants(text))
    return brk == [] and len(cont) == 1 and novar == []


def p3_pin_ws_subrun_longest_first_single_skip():
    # Sub-runs enumerated longest-first; single-word sub-runs skipped
    # (contiguous paths own them).
    hx = _hex(_LONG.encode())
    w1, w2 = hx[:30], hx[30:60]
    text = "k " + w1 + " " + w2 + " k"
    seen = []

    real = dlp._try_hex_decode

    def counting(blob):
        seen.append(blob)
        return real(blob)

    dlp._try_hex_decode = counting
    try:
        variants = list(dlp._hex_ws_variants(text))
    finally:
        dlp._try_hex_decode = real
    # First attempt is the full 2-word blob; single words never attempted.
    ok_order = seen and seen[0] == w1 + w2
    ok_skip = all(len(b) > len(w1) and len(b) > len(w2) for b in seen)
    # The 60-char blob decodes to the 30-char credential prefix, which
    # is credential-shaped -> variant emitted.
    ok_variant = any(_LONG[:30] in v for v in variants)
    return ok_order and ok_skip and ok_variant


def p3_pin_ws_attempt_budget():
    # Routed through _gated_encoded_variants: at most _MAX_CANDIDATES
    # decode attempts per call (no per-span reset).
    calls = []
    real_decode = dlp._try_hex_decode

    def counting(blob):
        calls.append(blob)
        return real_decode(blob)

    text = "k " + " ".join(["abcdef"] * 40) + " k"
    dlp._try_hex_decode = counting
    try:
        list(dlp._hex_ws_variants(text))
    finally:
        dlp._try_hex_decode = real_decode
    return len(calls) <= dlp._MAX_CANDIDATES


def p3_pin_shape_gate_not_just_decode():
    # A whitespace-tolerant run that strict-decodes but is NOT
    # credential-shaped yields no variant -- the gate decides.
    hx_junk = _hex(b"junkjunk12")
    assert dlp._try_hex_decode(hx_junk) == "junkjunk12"
    spaced = hx_junk[:8] + " " + hx_junk[8:]
    assert bytes.fromhex(spaced) == b"junkjunk12"
    return list(dlp._hex_ws_variants("k=" + spaced)) == []


def p3_pin_shape_gate_emits_for_credential():
    hx = _hex(_CRED.encode())
    spaced = hx[:20] + " " + hx[20:]
    variants = list(dlp._hex_ws_variants("k=" + spaced))
    return any(_CRED in v for v in variants)


def p3_pin_fidelity_spot():
    # Ground-truth spot checks for the parity rule.
    try:
        bytes.fromhex("a bcd")
        return False
    except ValueError:
        pass
    try:
        bytes.fromhex("ab\x1ccd")
        return False
    except ValueError:
        pass
    if bytes.fromhex("ab\x0bcd") != b"\xab\xcd":
        return False
    if bytes.fromhex("ab cd") != b"\xab\xcd":
        return False
    return True


# ---------------------------------------------------------------- P4: discrimination

# Pinned FP-corpus hit-set from the base tree (2026-10-06, wave-350
# lane 3): find_credential over README.md, docs/*.md, evals/*.md,
# BUILD_LOG.md, THREAT_MODEL.md, SITUATION_MATRIX.md. The closure must
# not change which repo docs hit.
_FP_BASELINE = {
    "README.md": "dlp-github-token",
    "SITUATION_MATRIX.md": "dlp-aws-access-key",
    "docs/decision-code-coverage.md": "dlp-entropy-tripwire",
    "evals/FINDINGS.md": "dlp-aws-access-key",
    "evals/SITUATION_MATRIX.md": "dlp-aws-access-key",
}


def p4_discr_spaced_words_quiet():
    return (not _blocked("password password")
            and not _blocked("the quick brown fox jumps")
            and not _blocked("ab cd ef gh"))


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
        "a" * 5000,
        ("a " * 5000),
        ("ab " * 5000),
        ("a\x0b" * 4000),
        ("ab" * 14 + " ") * 300,  # many 28-char hex spans
        ("ab" * 14 + "\n") * 300,
        ("abc" + " ") * 2000,  # odd words -> parity breaks
        ("0x" * 3000),
        ("\x1c " * 3000),
        ("ab" * 2500),  # long even hex run (long path owns it)
        ("ab" * 2500 + "c"),  # long odd hex run
        "\t \n" * 2000,
    ]
    t0 = time.time()
    for h in hostile:
        dlp.find_credential(h)
        list(dlp._hex_ws_variants(h))
        list(dlp._iter_hex_ws_spans(h))
    return (time.time() - t0) < 30.0


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f449_ws_b64():
    import base64
    b64 = base64.b64encode(_LONG.encode()).decode()
    spaced = b64[:16] + " " + b64[16:32] + "\n" + b64[32:]
    assert base64.b64decode(spaced) == _LONG.encode()
    return _blocked(spaced)


def p6_noreg_f450_short_hex():
    s15 = "xox" + "b-" + "z" * 10
    assert len(s15) == 15
    return _blocked("k=" + _hex(s15.encode()))


def p6_noreg_f444_junk_prefix():
    junk = "'j0'+'k0';'j1'+'k1';'j2'+'k2';"
    real = "['" + _CRED[:10] + "','" + _CRED[10:] + "'].reduce((a,b)=>a+b)"
    return _blocked(junk + real)


def p6_noreg_f445_short_b64():
    import base64
    return _blocked(base64.b64encode(_CRED.encode()).decode())


def p6_noreg_f437_reduce():
    return _blocked("['" + _CRED[:10] + "','" + _CRED[10:]
                    + "'].reduce((a,b)=>a+b)")


def p6_noreg_f439_triple_b64():
    import base64
    b = _CRED.encode()
    return _blocked(base64.b64encode(
        base64.b64encode(base64.b64encode(b)).decode().encode()).decode())


def p6_noreg_f440_double_entity():
    payload = "".join("&amp;#x%x;" % c for c in _CRED.encode())
    assert _CRED not in payload
    return _blocked(payload)


def p6_noreg_f441_bslash():
    payload = "".join("\\\\u%04x" % c for c in _CRED.encode())
    assert _CRED not in payload
    return _blocked(payload)


def p6_noreg_f443_fill_filter():
    fill = ('Array(2).fill("' + _CRED[:10]
            + 'a1b2").join("c3").concat("' + _CRED[10:] + '")')
    filt = ("['" + _CRED[:10] + "','','" + _CRED[10:]
            + "'].filter(Boolean).join('')")
    return _blocked(fill) and _blocked(filt)


def p6_noreg_hex_stacks_compose():
    # hex_long(ws-b64) and hex_long(ws-hex) compose via the 2-layer
    # pipeline (the long hex path is ungated); b64(ws-hex) composes
    # via the long b64 path.
    import base64
    b64 = base64.b64encode(_LONG.encode()).decode()
    inner_ws_b64 = b64[:16] + " " + b64[16:]
    if not _blocked("k=" + inner_ws_b64.encode().hex()):
        return False
    inner_ws_hex = _hex(_LONG.encode())
    inner_ws_hex = inner_ws_hex[:20] + " " + inner_ws_hex[20:]
    if not _blocked("k=" + inner_ws_hex.encode().hex()):
        return False
    outer_b64 = base64.b64encode(inner_ws_hex.encode()).decode()
    return _blocked("k=" + outer_b64)


def p6_pin_f452_attempt_budget_closed():
    # F452 pinned CLOSED (wave-351 merge): fail-closed JS matches no
    # longer consume the whole-text scan's attempt budget.
    junk = "".join("'%s';" % ("j%d" % i) for i in range(32))
    real = "['" + _CRED[:10] + "','" + _CRED[10:] + "'].reduce((a,b)=>a+b)"
    return _blocked(junk + real)


def p6_pin_f453_ws_outer_stack_closed():
    # F453 pinned CLOSED (wave-351 merge): ws-b64 as the OUTER layer of
    # a stack now composes via the base64 fixpoint seed.
    import base64
    inner = base64.b64encode(_LONG.encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    outer_ws = outer[:20] + " " + outer[20:32] + "\n" + outer[32:]
    assert base64.b64decode(outer_ws) == inner.encode()
    assert base64.b64decode(inner) == _LONG.encode()
    return _blocked(outer_ws)


def p6_note_ws_hex_outer_stack_f453_class():
    # Documented, not filed: ws-hex as the OUTER layer of a stack
    # misses too -- the inner non-credential text never reaches layer
    # 2 through the ws path's credential-shape gate. Same mechanism
    # class as F453 (ws outer layer + shape gate) on the hex alphabet;
    # documented here, not a new finding number.
    import base64
    inner_b64 = base64.b64encode(_LONG.encode()).decode()
    hx = _hex(inner_b64.encode())
    outer_ws_hex = hx[:20] + " " + hx[20:40] + "\n" + hx[40:]
    assert bytes.fromhex(outer_ws_hex) == inner_b64.encode()
    return not _blocked("k=" + outer_ws_hex)


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2143  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-351 lane 1" in footer
    return ok


_PROBES = [
    ("p1-closure-f451-filed-spaced", p1_closure_f451_filed_spaced),
    ("p1-closure-f451-filed-newlined", p1_closure_f451_filed_newlined),
    ("p1-closure-f451-gap-classes", p1_closure_f451_gap_classes),
    ("p1-closure-f451-fragmented-fuzz", p1_closure_f451_fragmented_fuzz),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-hex-contiguous", p2_control_hex_contiguous),
    ("p2-control-hex-junk-spaced-quiet", p2_control_hex_junk_spaced_quiet),
    ("p2-control-hex-0x-prefixed-quiet", p2_control_hex_0x_prefixed_quiet),
    ("p2-control-hex-odd-parity-gap-quiet",
     p2_control_hex_odd_parity_gap_quiet),
    ("p2-control-hex-nonws-junk-quiet", p2_control_hex_nonws_junk_quiet),
    ("p2-control-hex-x1c-gap-quiet", p2_control_hex_x1c_gap_quiet),
    ("p3-pin-ws-span-maximal", p3_pin_ws_span_maximal),
    ("p3-pin-ws-span-alpha-floor", p3_pin_ws_span_alpha_floor),
    ("p3-pin-ws-span-cap", p3_pin_ws_span_cap),
    ("p3-pin-ws-gap-charset", p3_pin_ws_gap_charset),
    ("p3-pin-ws-parity-gate", p3_pin_ws_parity_gate),
    ("p3-pin-ws-subrun-longest-first-single-skip",
     p3_pin_ws_subrun_longest_first_single_skip),
    ("p3-pin-ws-attempt-budget", p3_pin_ws_attempt_budget),
    ("p3-pin-shape-gate-not-just-decode",
     p3_pin_shape_gate_not_just_decode),
    ("p3-pin-shape-gate-emits-for-credential",
     p3_pin_shape_gate_emits_for_credential),
    ("p3-pin-fidelity-spot", p3_pin_fidelity_spot),
    ("p4-discr-spaced-words-quiet", p4_discr_spaced_words_quiet),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f449-ws-b64", p6_noreg_f449_ws_b64),
    ("p6-noreg-f450-short-hex", p6_noreg_f450_short_hex),
    ("p6-noreg-f444-junk-prefix", p6_noreg_f444_junk_prefix),
    ("p6-noreg-f445-short-b64", p6_noreg_f445_short_b64),
    ("p6-noreg-f437-reduce", p6_noreg_f437_reduce),
    ("p6-noreg-f439-triple-b64", p6_noreg_f439_triple_b64),
    ("p6-noreg-f440-double-entity", p6_noreg_f440_double_entity),
    ("p6-noreg-f441-bslash", p6_noreg_f441_bslash),
    ("p6-noreg-f443-fill-filter", p6_noreg_f443_fill_filter),
    ("p6-noreg-hex-stacks-compose", p6_noreg_hex_stacks_compose),
    ("p6-pin-f452-attempt-budget-closed", p6_pin_f452_attempt_budget_closed),
    ("p6-pin-f453-ws-outer-stack-closed", p6_pin_f453_ws_outer_stack_closed),
    ("p6-note-ws-hex-outer-stack-f453-class",
     p6_note_ws_hex_outer_stack_f453_class),
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
    scripts = ("w350_attack_probes.py",
               "w350_f449f450close_probes.py",
               "w349_attack_probes.py",
               "w346_dlp_composition_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g351-green-%s-%d" % (script.replace(".py", ""),
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
    print("w351_f451close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
