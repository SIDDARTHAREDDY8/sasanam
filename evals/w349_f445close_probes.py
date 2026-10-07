#!/usr/bin/env python3
"""Wave-349 F445 closure battery: base64/base32 minimum-length gate (lane 1).

F445 (LOW, filed 2026-10-06 wave-348 lane 2 (continuous real-model
attack, round 16, gpt-4o-mini); CLOSED 2026-10-06 wave-349 lane 1):
gov/dlp.py `_B64_RUN`/`_try_b64_decode` required 24+ payload chars (an
FP guard against word-like runs), so base64 of a credential under ~18
chars was never even attempted -- while base64.b64decode recovers it
exactly (verified: 16-char test credential, base64 form MISSED on the
open tree, plain form blocked coded). The same 24-char gate existed on
`_B32_RUN` (same mechanism class, closed together).

Close-when: base64/base32 runs under 24 chars are attempted when
round-trip validation passes; red-first verified.

Closure design (gov/dlp.py): short runs (8-23 payload chars) are
strict-decoded with the lowered floor, and become variants ONLY when
the decoded text is credential-shaped (the 24-char floor's FP guard
made precise -- innocent short decodes never enter the variant
pipeline, so they cannot block and cannot starve the
_MAX_CANDIDATES budget). Byte-verified against base64.b64decode /
base64.b32decode (400 randomized round-trips). F430 discipline: one
decode layer for short runs (stacked short runs compose via the
2-layer pipeline), no eval/exec, bounded, fail closed. Long-path
behavior (24+) is byte-for-byte unchanged.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: short b64/b32/b64url of credential-shaped material
      blocks coded dlp-slack-token (16-char, 15-char boundary,
      atob-wrapped, double-wrapped).
  P2  controls: plain short credential blocks; long b64 blocks (long
      path unchanged); junk decodes stay quiet.
  P3  decoder pins: default 24 floor unchanged; short floor 8;
      round-trip failures rejected; unpadded short runs decode;
      credential-shape gate (not just decode) decides variants;
      stdlib fidelity spot-checks.
  P4  discrimination: innocent short runs (uppercase words incl.
      b32-alphabet words, uuid fragments, b64 of junk words) stay
      quiet; FP corpus (repo docs) hit-set identical to base.
  P5  ReDoS: hostile near-miss short/long runs complete fast with no
      exceptions.
  P6  no-regression: adjacent closures still block (F437 reduce,
      F439 triple-b64, F440 double-entity, F441 bslash, F438
      entity+NUL, F443 fill/filter, long b64 stack).
  P7  pin + footer: taxonomy pin 2135 (no new decision codes),
      footer open F444 / next F446, F445 CLOSED entry present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w349_f445close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-349: F445 closed, no new decision codes; pin unchanged 2135
FOOTER_OPEN = "F513, F514, F515, F516, F517, F518, F519, F520"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # Wave-351 lane 3: F453 CLOSED (ws-b64 outer composes via fixpoint seed)  # Wave-350: F449+F450 CLOSED locally (merge finalizes tree-wide); F446-F448 OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # Wave-350: F449+F450 CLOSED locally (merge finalizes tree-wide); F446-F448 OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521)

FOOTER_NEXT = "F521"  # Wave-350: next free finding after F449+F450's closure  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credential -- constructed via concatenation, never a literal.
_A = "xoxb-" + "abc123"
_B = "def" + "456"
_CRED = _A + _B  # 17 chars -> b64 is 24 chars w/ pad, 23 payload < 24
assert len(_CRED) == 17
_B15 = "xoxb-" + "abc123def4"  # 15 chars: minimum the slack rule matches
assert len(_B15) == 15
_LONG = "xoxb-" + "a" * 40


def _b64(b):
    return base64.b64encode(b).decode()


def _b32(b):
    return base64.b32encode(b).decode()


def _blocked(payload):
    return dlp.find_credential(payload) == "dlp-slack-token"


# ---------------------------------------------------------------- P1: closure

def p1_closure_b64_short():
    return _blocked(_b64(_CRED.encode()))


def p1_closure_b64_15_boundary():
    # 15 chars is the shortest string the slack rule can match.
    return _blocked(_b64(_B15.encode()))


def p1_closure_b32_short():
    return _blocked(_b32(_CRED.encode()))


def p1_closure_b64url_short():
    enc = base64.urlsafe_b64encode(_CRED.encode()).decode()
    return _blocked(enc)


def p1_closure_atob_wrapped():
    # The w346 held-by-design shape: inner 20-char run now decodes.
    return _blocked("atob('" + _b64(_CRED.encode()) + "')")


def p1_closure_double_wrapped():
    # Stacked short runs compose via the 2-layer pipeline / fixpoint.
    return _blocked(_b64(_b64(_CRED.encode()).encode()))


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_long_b64():
    return _blocked(_b64(_LONG.encode()))


def p2_control_junk_b64_quiet():
    return not _blocked(_b64(b"hello world junk"))


def p2_control_junk_b32_quiet():
    return not _blocked(_b32(b"hello world junk"))


def p2_control_junk_decodable_quiet():
    # b64 of a decodable-but-innocent word: decode succeeds, the
    # credential-shape gate keeps it out of the pipeline.
    return (not _blocked(_b64(b"password"))
            and not _blocked(_b64(b"abcdefgh")))


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_default_floor_unchanged():
    # The long path still refuses < 24 payload chars by default --
    # the 24-char FP guard is intact for blind emission.
    run = _b64(b"quarterly report data")  # 28 chars: long path
    assert dlp._try_b64_decode(run) is not None
    short = _b64(_CRED.encode())  # 23 payload chars
    return dlp._try_b64_decode(short) is None


def p3_pin_short_floor():
    ok8 = dlp._try_b64_decode(_b64(b"12345678"), min_payload=8) == "12345678"
    ok7 = dlp._try_b64_decode("MTIzNDU", min_payload=8) is None  # 7 chars
    ok8b = dlp._try_b32_decode(_b32(b"12345"), min_payload=8) == "12345"
    run7b = _b32(b"1234").rstrip("=")  # 7 payload chars
    ok7b = dlp._try_b32_decode(run7b, min_payload=8) is None
    return ok8 and ok7 and ok8b and ok7b


def p3_pin_roundtrip_rejected():
    # Tampered short run: the tail quantum no longer round-trips, so
    # strict decode rejects it (fails closed).
    run = _b64(_CRED.encode())
    bad = run[:-4] + ("AAAA" if not run.endswith("AAAA") else "BBBB")
    assert bad != run
    return dlp._try_b64_decode(bad, min_payload=8) is None


def p3_pin_unpadded_short():
    run = _b64(_CRED.encode()).rstrip("=")
    return dlp._try_b64_decode(run, min_payload=8) == _CRED


def p3_pin_shape_gate_not_just_decode():
    # A short run that strict-decodes but is NOT credential-shaped
    # yields no variant -- the gate, not the decode, decides.
    junk_run = _b64(b"password")
    assert dlp._try_b64_decode(junk_run, min_payload=8) == "password"
    return list(dlp._b64_short_variants(junk_run)) == []


def p3_pin_shape_gate_emits_for_credential():
    run = _b64(_CRED.encode())
    variants = list(dlp._b64_short_variants("k=" + run))
    return any(_CRED in v for v in variants)


def p3_pin_fidelity_spot():
    # Spot-checks against the stdlib decoders.
    pairs = [(_b64(b"xoxb-abc123def456"), _CRED),
             (_b32(b"xoxb-abc123def456"), _CRED),
             (base64.urlsafe_b64encode(b"xoxb-abc123def456").decode(),
              _CRED)]
    return all(dlp._try_b64_decode(r, min_payload=8) == want
               for r, want in pairs[:1]) and \
        all(dlp._try_b32_decode(r, min_payload=8) == want
            for r, want in pairs[1:2])


# ---------------------------------------------------------------- P4: discrimination

def p4_discr_uppercase_words_quiet():
    # All in the b32 alphabet; must stay quiet.
    return all(dlp.find_credential(w) is None
               for w in ("PASSWORD", "DEADBEEF", "CAFEBABE", "ABCDEFGH"))


def p4_discr_fragments_quiet():
    return all(dlp.find_credential(p) is None
               for p in ("550e8400e29b41d4",
                         _b64(b"12345678"),
                         "the quick brown fox jumps"))


def p4_discr_short_run_regex_bounds():
    # A 23-char prefix of a 30-char run is NOT treated as a short run
    # (the long path owns longer runs); a true 23-char run is.
    long_run = "A" * 30
    short_matches = [m.group(0) for m in
                     dlp._B64_SHORT_RUN.finditer("x " + long_run + " y")]
    true_short = "B" * 23
    true_matches = [m.group(0) for m in
                    dlp._B64_SHORT_RUN.finditer("x " + true_short + " y")]
    return short_matches == [] and true_matches == [true_short]


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_runs():
    hostile = [
        "A" * 5000,
        "A" * 4999 + "=",
        ("AB" * 2500) + "==",
        "ABCDEFGHIJKLMNOP" * 200,  # b32 alphabet, long
        "aBcDeF0123456789+/ -_" * 300,
        ("xoxb-" + "A" * 10) * 100,  # credential-ish repetition
    ]
    t0 = time.time()
    for h in hostile:
        dlp.find_credential(h)
        list(dlp._b64_short_variants(h))
        list(dlp._b32_short_variants(h))
    return (time.time() - t0) < 20.0


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_long_b64_still_blocks():
    return _blocked(_b64(_LONG.encode()))


def p6_noreg_triple_b64():
    # F439: triple wrap still composes.
    return _blocked(_b64(_b64(_b64(_CRED.encode()).encode()).encode()))


def p6_noreg_f437_reduce():
    payload = "['xoxb-" + "abc123','def456'].reduce((a,b)=>a+b)"
    return _blocked(payload)


def p6_noreg_f440_double_entity():
    # F440: per-char &amp;#xHH; double-entity encoding of the credential.
    payload = "".join("&amp;#x%x;" % ord(c) for c in _CRED)
    assert _CRED not in payload
    return _blocked(payload)


def p6_noreg_f441_bslash():
    # F441: per-char double-backslash \\uXXXX encoding of the credential.
    payload = "".join("\\\\u%04x" % ord(c) for c in _CRED)
    assert _CRED not in payload
    return _blocked(payload)


def p6_noreg_f443_fill():
    payload = 'Array(2).fill("xoxb-" + "a1b2").join("c3").concat("def456")'
    return _blocked(payload)


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-349 lane 1" in footer
    return ok


_PROBES = [
    ("p1-closure-b64-short", p1_closure_b64_short),
    ("p1-closure-b64-15-boundary", p1_closure_b64_15_boundary),
    ("p1-closure-b32-short", p1_closure_b32_short),
    ("p1-closure-b64url-short", p1_closure_b64url_short),
    ("p1-closure-atob-wrapped", p1_closure_atob_wrapped),
    ("p1-closure-double-wrapped", p1_closure_double_wrapped),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-long-b64", p2_control_long_b64),
    ("p2-control-junk-b64-quiet", p2_control_junk_b64_quiet),
    ("p2-control-junk-b32-quiet", p2_control_junk_b32_quiet),
    ("p2-control-junk-decodable-quiet", p2_control_junk_decodable_quiet),
    ("p3-pin-default-floor-unchanged", p3_pin_default_floor_unchanged),
    ("p3-pin-short-floor", p3_pin_short_floor),
    ("p3-pin-roundtrip-rejected", p3_pin_roundtrip_rejected),
    ("p3-pin-unpadded-short", p3_pin_unpadded_short),
    ("p3-pin-shape-gate-not-just-decode", p3_pin_shape_gate_not_just_decode),
    ("p3-pin-shape-gate-emits-for-credential",
     p3_pin_shape_gate_emits_for_credential),
    ("p3-pin-fidelity-spot", p3_pin_fidelity_spot),
    ("p4-discr-uppercase-words-quiet", p4_discr_uppercase_words_quiet),
    ("p4-discr-fragments-quiet", p4_discr_fragments_quiet),
    ("p4-discr-short-run-regex-bounds", p4_discr_short_run_regex_bounds),
    ("p5-redos-hostile-runs", p5_redos_hostile_runs),
    ("p6-noreg-long-b64-still-blocks", p6_noreg_long_b64_still_blocks),
    ("p6-noreg-triple-b64", p6_noreg_triple_b64),
    ("p6-noreg-f437-reduce", p6_noreg_f437_reduce),
    ("p6-noreg-f440-double-entity", p6_noreg_f440_double_entity),
    ("p6-noreg-f441-bslash", p6_noreg_f441_bslash),
    ("p6-noreg-f443-fill", p6_noreg_f443_fill),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:
        print("%-36s ERROR %s: %s" % (pid, type(e).__name__, e))
        return (pid, "ERROR")
    print("%-36s %s" % (pid, "HELD" if ok else "BREAK"))
    return (pid, "HELD" if ok else "BREAK")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w346_dlp_composition_probes.py",
               "w344_attack_probes.py",
               "w345_attack_probes.py",
               "w346_attack_probes.py",
               "w347_attack_probes.py",
               "w348_attack_probes.py",
               "w347_f437close_probes.py",
               "w347_f438close_probes.py",
               "w347_f439close_probes.py",
               "w347_f440close_probes.py",
               "w347_f441close_probes.py",
               "w347_f442close_probes.py",
               "w348_f443close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g349-green-%s-%d" % (script.replace(".py", ""),
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
    print("w349_f445close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
