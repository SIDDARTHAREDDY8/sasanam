#!/usr/bin/env python3
"""Wave-351 F453 closure battery (lane 3).

F453 (LOW, filed 2026-10-06 wave-350 lane 3 during spec review,
renumbered F451->F453 at the wave-350 merge): whitespace-tolerant
base64 as the OUTER layer of a stack did not compose -- gov/dlp.py
_b64_ws_variants (F449) only emits variants for credential-shaped
decodes (the FP guard), so a ws-b64 outer layer decoding to
non-credential-shaped inner text (e.g. an inner contiguous base64
run) never fed layer 2, while base64.b64decode recovers the
credential exactly through both layers.

Closure design (gov/dlp.py _b64_fixpoint_variants, F439 path):
whitespace-tolerant spans (_iter_b64_ws_spans) now seed the bounded
base64 decode-until-fixpoint as their whitespace-stripped whole-span
candidate. Round 1 decodes the ws outer layer; round 2+ decodes the
inner stack. Each round strips whitespace from its input first
(base64.b64decode ignores whitespace -- ground truth; a no-op for
contiguous runs, so F439 semantics are unchanged), which also
composes ws-b64(ws-b64) two-whitespace-layer stacks. Short seeds
keep the F445 credential-shape-gated short retry; contiguous runs
seed first so base budget behavior is identical; _MAX_B64_ROUNDS=3
and the depth-4+ documented non-goal are unchanged. No new regexes;
bounded; static; never executes.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed F453 shape blocks (ws-b64(b64)); ws-b64(ws-b64)
      two-whitespace-layer stack blocks; ws-b64(b64(b64)) depth-3
      blocks; fixed-seed fuzz over whitespace insertion positions
      blocks; ws-b64url outer stack blocks.
  P2  controls: plain credential blocks; b64(ws-b64) reverse stack
      still blocks; contiguous double/triple b64 still blocks (F439
      unchanged); innocent whitespace-separated words quiet;
      ws-b64 decoding to innocent text quiet; ws-b64(hex(cred))
      documented residual quiet (cross-encoding: the fixpoint is
      base64-only; F451 hex-whitespace still OPEN -- pinned, not a
      finding); fragmented stacked outer (adjacent junk words) quiet
      (fail closed on the whole-span strict round-trip; the F449
      single-layer sub-run path is unchanged).
  P3  decoder pins: ws spans seed the fixpoint (whole-span stripped
      candidate); contiguous runs seed first (base budget behavior
      identical); rounds strip whitespace (ground truth); max 3
      rounds (_MAX_B64_ROUNDS unchanged); depth-4+ ws stack still
      misses (documented non-goal); short ws seeds keep the
      credential-shape gate; byte-fidelity vs stdlib layering on
      every stack shape.
  P4  discrimination: FP corpus (repo docs) hit-set identical to base
      (pinned).
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F439 triple-b64,
      F444 junk-prefix, F445 short-b64, F449 single-layer ws-b64,
      F450 short hex, b64(ws-b64) via 2-layer pipeline).
  P7  pin + footer: taxonomy pin 2140 (no new decision codes),
      footer open F451, F452 / next F454, F453 CLOSED entry present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w351_f453close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import glob
import random
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-351: F453 closed, no new decision codes; pin unchanged; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F595, F606, F608, F609, F610, F611"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (4/5): F454-F460 CLOSED; open none (next F461)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # Wave-352 merge (2/5): F456+F457 CLOSED; F458-F460 still OPEN (next F461)  # Wave-351 lane 3: F453 CLOSED (merge finalizes tree-wide); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 lane 4: F458-F460 CLOSED (merge finalizes tree-wide); Wave-351 lane 3: F453 CLOSED (merge finalizes tree-wide); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 lane 2: F463 CLOSED, F469 filed OPEN (next F470)  # Wave-353 lane 2 renumber: F469->F472 (attack lane committed F469-F471 first, e79af076); footer next F473  # Wave-353 lane 4: F467+F468 CLOSED locally (merge finalizes tree-wide)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint
FOOTER_NEXT = "F612"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)

# Constructed via concatenation: the write path redacts credential literals.
_CRED = "xox" + "b-abc123" + "def" + "456"


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _wsify(s, seed=0):
    """Deterministic whitespace insertion (spaces, newlines, tabs)."""
    out = []
    for i, ch in enumerate(s):
        out.append(ch)
        if (i + seed) % 7 == 3:
            out.append(" ")
        if (i + seed) % 11 == 5:
            out.append("\n")
        if (i + seed) % 13 == 7:
            out.append("\t")
    return "".join(out)


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001
        print("%-45s ERROR %s" % (pid, e))
        return pid, "ERROR"
    print("%-45s %s" % (pid, "HELD" if ok else "BREAK"))
    return pid, ("HELD" if ok else "BREAK")


# ---------------------------------------------------------------- P1: closure

def p1_closure_f453_filed_shape():
    # The exact filed shape: ws-b64 outer over contiguous inner b64.
    inner = _b64(_CRED.encode())
    outer = _b64(inner.encode())
    outer_ws = outer[:20] + " " + outer[20:32] + "\n" + outer[32:]
    assert base64.b64decode(outer_ws) == inner.encode()
    assert base64.b64decode(inner) == _CRED.encode()
    return _blocked("tok=" + outer_ws)


def p1_closure_ws_b64_ws_b64():
    # Two-whitespace-layer stack composes via ws-tolerant rounds.
    inner = _b64(_CRED.encode())
    inner_ws = _wsify(inner, seed=1)
    outer = _b64(inner_ws.encode())
    outer_ws = _wsify(outer, seed=2)
    assert base64.b64decode(outer_ws) == inner_ws.encode()
    assert base64.b64decode(inner_ws) == _CRED.encode()
    return _blocked("tok=" + outer_ws)


def p1_closure_ws_b64_depth3():
    # ws-b64(b64(b64)): 3 rounds, within _MAX_B64_ROUNDS.
    l1 = _b64(_CRED.encode())
    l2 = _b64(l1.encode())
    l3 = _b64(l2.encode())
    outer_ws = _wsify(l3, seed=3)
    assert base64.b64decode(base64.b64decode(
        base64.b64decode(outer_ws))) == _CRED.encode()
    return _blocked("tok=" + outer_ws)


def p1_closure_ws_fuzz_positions():
    # Fixed-seed fuzz: whitespace at many insertion patterns still blocks.
    rng = random.Random(351453)
    inner = _b64(_CRED.encode())
    outer = _b64(inner.encode())
    gaps = [" ", "\n", "\t", "\r\n", "  ", " \n "]
    for trial in range(12):
        chars = []
        for ch in outer:
            chars.append(ch)
            if rng.random() < 0.3:
                chars.append(rng.choice(gaps))
        payload = "".join(chars)
        # Ground truth must recover for the assertion to be meaningful.
        try:
            assert base64.b64decode(payload) == inner.encode()
        except Exception:
            continue  # not a valid ws-b64 shape; skip
        if not _blocked("k=" + payload):
            return False
    return True


def p1_closure_ws_b64url_outer():
    # base64url alphabet outer layer composes too.
    inner = _b64(_CRED.encode())
    outer = base64.urlsafe_b64encode(inner.encode()).decode("ascii")
    outer_ws = outer[:20] + " " + outer[20:32] + "\n" + outer[32:]
    assert base64.b64decode(outer_ws) == inner.encode()
    return _blocked("tok=" + outer_ws)


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_b64_ws_b64_reverse():
    # Reverse direction still composes (2-layer pipeline, unchanged).
    inner = _b64(_CRED.encode())
    inner_ws = inner[:16] + " " + inner[16:]
    outer = _b64(inner_ws.encode())
    return _blocked("tok=" + outer)


def p2_control_contiguous_stacks():
    l1 = _b64(_CRED.encode())
    l2 = _b64(l1.encode())
    l3 = _b64(l2.encode())
    return _blocked("a=" + l2) and _blocked("b=" + l3)


def p2_control_innocent_ws_quiet():
    return not _blocked("hello world foo bar baz qux quux corge")


def p2_control_ws_b64_innocent_quiet():
    innocent = _b64(b"just some harmless words here")
    return not _blocked("note: " + _wsify(innocent))


def p2_control_ws_b64_hex_residual_quiet():
    # DOCUMENTED RESIDUAL (not a finding): ws-b64 over a hex payload
    # does not compose -- the fixpoint is base64-only (cross-encoding
    # stacks need the layer pipeline, which the F449 credential-shape
    # gate does not feed). F451 (hex whitespace) is still OPEN.
    # Pinned quiet so the residual is explicit.
    hexed = _CRED.encode().hex()
    outer = _b64(hexed.encode())
    outer_ws = _wsify(outer)
    assert base64.b64decode(outer_ws) == hexed.encode()
    assert bytes.fromhex(hexed) == _CRED.encode()
    return not _blocked("k=" + outer_ws)


def p2_control_fragmented_stacked_outer_quiet():
    # Fragmented stacked outer: adjacent junk words make the whole-span
    # strict round-trip fail (fail closed). The F449 single-layer
    # sub-run path is unchanged (it never handled stacks).
    inner = _b64(_CRED.encode())
    outer = _b64(inner.encode())
    outer_ws = _wsify(outer)
    payload = "zzTopjunk " + outer_ws + " tailjunk"
    assert base64.b64decode(outer_ws) == inner.encode()
    return not _blocked("k=" + payload)


def p2_control_ws_padding_positions():
    # Whitespace in padding positions: all block (no regression).
    b64c = _b64(_CRED.encode())
    cases = [
        b64c[:-1] + " " + b64c[-1:],
        b64c + " ",
        b64c[:-1] + "\t" + b64c[-1:],
        b64c[:-1] + "\n" + b64c[-1:],
    ]
    for p in cases:
        assert "".join(p.split()) == b64c  # ground truth recovers
        if not _blocked("k=" + p):
            return False
    return True


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_ws_seeds_fixpoint():
    # A ws span seeds the fixpoint as its stripped whole-span candidate.
    inner = _b64(_CRED.encode())
    outer = _b64(inner.encode())
    outer_ws = outer[:20] + " " + outer[20:32] + "\n" + outer[32:]
    text = "k=" + outer_ws
    spans = list(dlp._iter_b64_ws_spans(text))
    assert len(spans) == 1
    s, e, _ = spans[0]
    variants = list(dlp._b64_fixpoint_variants(text))
    cores = []
    for v in variants:
        assert v.startswith(text[:s])
        core = v[len(text[:s]):len(v) - len(text[e:]) if text[e:] else None]
        cores.append(core)
    # Round 1 decodes the ws outer exactly (byte-fidelity vs stdlib).
    assert inner in cores, "ws outer decode not byte-identical"
    # Round 2 decodes the inner stack exactly.
    assert _CRED in cores, "inner stack decode not byte-identical"
    return True


def p3_pin_contiguous_seeds_first():
    # Contiguous runs seed before ws spans: base budget behavior for
    # the long path is identical (ws seeds only fill leftover budget).
    l1 = _b64(_CRED.encode())
    text = "a=" + l1 + " b=" + _wsify(l1, seed=5)
    variants = list(dlp._b64_fixpoint_variants(text))
    # The contiguous run's decode must appear (not starved by ws seeds).
    assert any(_CRED in v for v in variants)
    return True


def p3_pin_max_rounds_unchanged():
    return dlp._MAX_B64_ROUNDS == 3


def p3_pin_depth4_still_misses():
    # Documented non-goal preserved: depth-4+ stacks stay out of budget.
    l1 = _b64(_CRED.encode())
    l2 = _b64(l1.encode())
    l3 = _b64(l2.encode())
    l4 = _b64(l3.encode())
    return not _blocked("k=" + _wsify(l4))


def p3_pin_short_ws_seed_gated():
    # Short ws seeds keep the F445 credential-shape gate: a short
    # ws-b64 decoding to innocent text stays quiet.
    short = _b64(b"hi")  # 4 chars -> "aGk=" (under the 24 floor)
    ws = short[:2] + " " + short[2:]
    return not _blocked("k=" + ws)


def p3_pin_short_ws_seed_credential_blocks():
    # Short ws-b64 decoding to credential-shaped text DOES block
    # (the gated short retry fires for ws seeds too).
    cred = "xoxb-abc123def45"  # 15 chars: shortest credential-shaped
    assert dlp._match_credential_forms(cred) is not None
    short = _b64(cred.encode())  # 20 chars b64: under the 24 floor
    assert len(short.replace("=", "")) < 24
    ws = short[:8] + " " + short[8:12] + "\n" + short[12:]
    return _blocked("k=" + ws)


# ---------------------------------------------------------------- P4: discrimination

_FP_BASELINE = {
    "README.md": "dlp-github-token",
    "SITUATION_MATRIX.md": "dlp-aws-access-key",
    "docs/decision-code-coverage.md": "dlp-entropy-tripwire",
    "evals/FINDINGS.md": "dlp-aws-access-key",
    "evals/SITUATION_MATRIX.md": "dlp-aws-access-key",
}


def p4_discr_fp_corpus_identical():
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


def p4_discr_spaced_uuid_quiet():
    return dlp.find_credential("550e 8400 e29b 41d4 a716 446655440000") is None


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    b64 = _b64(_CRED.encode())
    hostile = [
        "A" * 5000,
        ("A " * 5000),
        ("ab " * 5000),
        ("a " * 8000),
        (b64[:8] + " ") * 400,
        ("ab " * 2500),
        ("A" * 23 + " ") * 300,  # near-miss ws spans
        (_b64(b"x")[:4] + " ") * 500,
    ]
    for h in hostile:
        t0 = time.time()
        try:
            dlp.find_credential(h)
        except Exception:
            return False
        if time.time() - t0 > 5:
            return False
    return True


def p5_redos_fixpoint_bounded():
    # The ws seed path attempts at most _MAX_CANDIDATES seeds.
    real_iter = dlp._iter_b64_ws_spans
    calls = []

    def counting(text):
        for item in real_iter(text):
            calls.append(item)
            yield item

    dlp._iter_b64_ws_spans = counting
    try:
        list(dlp._b64_fixpoint_variants(("ab " * 2000)))
    finally:
        dlp._iter_b64_ws_spans = real_iter
    return len(calls) <= dlp._MAX_CANDIDATES + 1


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f439_triple_b64():
    l1 = _b64(_CRED.encode())
    l2 = _b64(l1.encode())
    l3 = _b64(l2.encode())
    return _blocked("x=" + l3)


def p6_noreg_f444_junk_prefix():
    payload = "'j0'+'j1';'j2'+'j3';" + "['" + "','".join(
        [_CRED[i:i + 4] for i in range(0, len(_CRED), 4)]) + "'].reduce((a,b)=>a+b)"
    return _blocked(payload)


def p6_noreg_f445_short_b64():
    short = _b64(_CRED.encode())
    return _blocked("k=" + short)


def p6_noreg_f449_single_layer_ws():
    b64 = _b64(_CRED.encode())
    ws = b64[:20] + " " + b64[20:32] + "\n" + b64[32:]
    return _blocked("k=" + ws)


def p6_noreg_f450_short_hex():
    hexed = _CRED.encode().hex()
    return _blocked("v=" + hexed[:20] + hexed[20:])


def p6_noreg_b64_ws_b64_pipeline():
    inner = _b64(_CRED.encode())
    inner_ws = inner[:16] + " " + inner[16:]
    outer = _b64(inner_ws.encode())
    return _blocked("tok=" + outer)


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
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-351 lane 3" in footer
    return ok


_PROBES = [
    ("p1-closure-f453-filed-shape", p1_closure_f453_filed_shape),
    ("p1-closure-ws-b64-ws-b64", p1_closure_ws_b64_ws_b64),
    ("p1-closure-ws-b64-depth3", p1_closure_ws_b64_depth3),
    ("p1-closure-ws-fuzz-positions", p1_closure_ws_fuzz_positions),
    ("p1-closure-ws-b64url-outer", p1_closure_ws_b64url_outer),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-b64-ws-b64-reverse", p2_control_b64_ws_b64_reverse),
    ("p2-control-contiguous-stacks", p2_control_contiguous_stacks),
    ("p2-control-innocent-ws-quiet", p2_control_innocent_ws_quiet),
    ("p2-control-ws-b64-innocent-quiet", p2_control_ws_b64_innocent_quiet),
    ("p2-control-ws-b64-hex-residual-quiet",
     p2_control_ws_b64_hex_residual_quiet),
    ("p2-control-fragmented-stacked-outer-quiet",
     p2_control_fragmented_stacked_outer_quiet),
    ("p2-control-ws-padding-positions", p2_control_ws_padding_positions),
    ("p3-pin-ws-seeds-fixpoint", p3_pin_ws_seeds_fixpoint),
    ("p3-pin-contiguous-seeds-first", p3_pin_contiguous_seeds_first),
    ("p3-pin-max-rounds-unchanged", p3_pin_max_rounds_unchanged),
    ("p3-pin-depth4-still-misses", p3_pin_depth4_still_misses),
    ("p3-pin-short-ws-seed-gated", p3_pin_short_ws_seed_gated),
    ("p3-pin-short-ws-seed-credential-blocks",
     p3_pin_short_ws_seed_credential_blocks),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p4-discr-spaced-uuid-quiet", p4_discr_spaced_uuid_quiet),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p5-redos-fixpoint-bounded", p5_redos_fixpoint_bounded),
    ("p6-noreg-f439-triple-b64", p6_noreg_f439_triple_b64),
    ("p6-noreg-f444-junk-prefix", p6_noreg_f444_junk_prefix),
    ("p6-noreg-f445-short-b64", p6_noreg_f445_short_b64),
    ("p6-noreg-f449-single-layer-ws", p6_noreg_f449_single_layer_ws),
    ("p6-noreg-f450-short-hex", p6_noreg_f450_short_hex),
    ("p6-noreg-b64-ws-b64-pipeline", p6_noreg_b64_ws_b64_pipeline),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w350_f449f450close_probes.py",
               "w349_attack_probes.py",
               "w349_f445close_probes.py",
               "w349_f444close_probes.py",
               "w348_attack_probes.py",
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
    print("w351_f453close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
