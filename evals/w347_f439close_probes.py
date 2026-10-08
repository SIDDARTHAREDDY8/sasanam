#!/usr/bin/env python3
"""Wave-347 F439 closure battery: triple-base64 wrap (lane 3).

F439 (LOW, filed 2026-10-05 wave-346 lane 2 (continuous real-model
attack); CLOSED 2026-10-05 wave-347 lane 3): _decoded_variants composes
decode layers at most 2 deep, so a credential wrapped in three base64
layers decoded only twice, leaving a 52-char base64 run that no rule
matched -- while a real 3x-decode chain recovers the credential
(roundtrip-verified); double-wrapped still blocked (control).

Close-when: the decode layer recognizes N-deep base64 stacks via a
bounded decode-until-fixpoint (max 3 rounds) or refuses
obfuscation-shaped runs coded, such that find_credential flags them,
red-first verified, honest text unaffected.

Fix (gov/dlp.py): _b64_fixpoint_variants decodes each base64/base64url
run repeatedly (at most _MAX_B64_ROUNDS = 3 rounds, strict round-trip +
padding validation, invalid rounds stop fail-closed, output bounded by
_MAX_DECODE_BYTES) and every intermediate variant is rule-checked
directly in _find_credential_strict. The variants are NOT fed back
into the layer pipeline, so the total base64 decode depth across the
scan stays <= 3: depth-4+ stacks are a documented non-goal (bounded
decode budget), pinned in P4, not a finding.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: triple-base64 blocks coded dlp-slack-token (real-parser
      roundtrip verified: base64-decode x3 recovers the credential).
  P2  controls: plain, single-wrap, double-wrap still block coded.
  P3  fixpoint unit pins: _MAX_B64_ROUNDS == 3; b3 yields exactly 3
      variants; b2 -> 2; b64-of-non-b64 -> 1; invalid round stops the
      chain fail-closed; no-run text yields nothing.
  P4  depth bound: depth-4 and depth-5 stacks MISS -- documented
      non-goal, pinned (not a finding).
  P5  discrimination: honest base64 blobs (single/double/triple
      wrapped non-credential text), triple-wrapped short tokens, and
      embedded honest runs do NOT block; the 24-char precision guard
      still applies (short-credential triple wrap is inert).
  P6  embedding: triple-wrap embedded in longer text blocks coded.
  P7  ReDoS/timing: hostile near-miss inputs (long alphabet runs,
      bad padding, non-round-tripping runs) complete fast with no
      exceptions. No new regexes were added for this closure.
  P8  no-absorption: all sibling findings are CLOSED by their own
      lanes (F437/F438/F439/F440/F441/F442 red-firsts print HELD) and
      F436 stays HELD -- the fixpoint widened nothing outside base64
      stacks (absorption pinned by the composition battery + F443
      scope note).
  P9  pin + footer: taxonomy pin 2140, footer open
      F437, F438, F440, F441, F442 / next F443.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w347_f439close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-347: pin 2135 (no new codes in wave-347 lane 3); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F662, F663, F664, F665, F666, F667, F669, F670, F671"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # wave-350 lane 3: F449+F450 CLOSED;  F439 closed this lane; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # wave-350 lane 3: F449+F450 CLOSED;  F439 closed this lane; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)


FOOTER_NEXT = "F672"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Long test credential: base64 is 52 chars, well over the 24-char
# precision guard. Concatenated -- the write/edit tool redacts
# credential-shaped literals in inputs.
_LONG = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _blocks(text):
    return dlp.find_credential(text) == "dlp-slack-token"


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def _wrap(s, n):
    for _ in range(n):
        s = _b64(s)
    return s


# --------------------------------------------------------------- P1: closure
def p1_triple_base64_blocks():
    b3 = _wrap(_LONG, 3)
    assert _LONG not in b3
    # real-parser ground truth: three base64 decodes recover the
    # credential -- this is an attack, not a false positive.
    recovered = base64.b64decode(base64.b64decode(
        base64.b64decode(b3))).decode()
    rt = (recovered == _LONG)
    hit = _blocks(b3)
    print("    triple-b64 -> %s (roundtrip=%s)" % (
        "BLOCK" if hit else "MISS!", rt))
    return _check("p1: triple-base64 blocks coded", rt and hit)


# --------------------------------------------------------------- P2: controls
def p2_controls():
    b1, b2 = _wrap(_LONG, 1), _wrap(_LONG, 2)
    ok = _blocks(_LONG) and _blocks(b1) and _blocks(b2)
    print("    plain=%s single=%s double=%s"
          % (_blocks(_LONG), _blocks(b1), _blocks(b2)))
    return _check("p2: plain/single/double-wrap controls block", ok)


# ---------------------------------------------------------- P3: fixpoint pins
def p3_fixpoint_unit_pins():
    ok = True
    # design bound pinned on the constant itself
    good = dlp._MAX_B64_ROUNDS == 3
    ok = ok and good
    print("    _MAX_B64_ROUNDS == 3 -> %s" % ("ok" if good else "BAD"))
    # b3 yields exactly 3 variants (one per decode round)
    b1, b2, b3 = _wrap(_LONG, 1), _wrap(_LONG, 2), _wrap(_LONG, 3)
    for label, payload, want in (("b1", b1, 1), ("b2", b2, 2),
                                 ("b3", b3, 3)):
        got = len(list(dlp._b64_fixpoint_variants(payload)))
        good = got == want
        ok = ok and good
        print("    variants(%s) = %d (want %d) -> %s"
              % (label, got, want, "ok" if good else "BAD"))
    # invalid round stops the chain fail-closed: b64 of non-b64 text
    # yields exactly 1 variant (the single decode), then stops.
    notb64 = "definitely not base64 !!!"
    one = _b64(notb64)
    got = list(dlp._b64_fixpoint_variants(one))
    good = len(got) == 1 and got[0] == notb64
    ok = ok and good
    print("    invalid-round stops chain -> %s" % ("ok" if good else "BAD"))
    # no base64 run -> no variants
    good = list(dlp._b64_fixpoint_variants("nothing to decode")) == []
    ok = ok and good
    print("    no-run text -> %s" % ("ok" if good else "BAD"))
    # decoded blobs stay within the byte bound
    good = all(len(v.encode()) <= 8 * dlp._MAX_DECODE_BYTES
               for v in dlp._b64_fixpoint_variants(b3))
    ok = ok and good
    print("    variant sizes bounded -> %s" % ("ok" if good else "BAD"))
    return _check("p3: fixpoint unit pins hold", ok)


# ------------------------------------------------------------ P4: depth bound
def p4_depth4_plus_is_nongoal():
    # Depth-4+ base64 stacks are a DOCUMENTED NON-GOAL (bounded decode
    # budget), pinned here so the bound is explicit -- not a finding.
    b4, b5 = _wrap(_LONG, 4), _wrap(_LONG, 5)
    miss4 = dlp.find_credential(b4) is None
    miss5 = dlp.find_credential(b5) is None
    print("    depth-4 -> %s, depth-5 -> %s (both expected MISS)"
          % ("MISS" if miss4 else "BLOCK!", "MISS" if miss5 else "BLOCK!"))
    ok = miss4 and miss5
    # the bound is not a loophole for the closed depth: the pipeline
    # never decodes more than 3 base64 rounds on any single path
    return _check("p4: depth-4+ misses (documented non-goal)", ok)


# ------------------------------------------------------- P5: discrimination
def p5_honest_base64_unaffected():
    honest_blob = base64.b64encode(
        b"The quick brown fox jumps over the lazy dog. " * 6).decode()
    cases = {
        "honest-single": honest_blob,
        "honest-double": _b64(honest_blob),
        "honest-triple": _wrap(honest_blob, 3),
        "short-token-triple": _wrap("tok_abc123", 3),
        "docs-b64": "see aGVsbG8gd29ybGQ= for the hello-world example",
        "embedded-honest": "prefix " + honest_blob + " suffix",
        "prose-triple": _wrap("quarterly report draft v3 - not final", 3),
    }
    ok = True
    for label, text in cases.items():
        quiet = dlp.find_credential(text) is None
        ok = ok and quiet
        print("    %-20s -> %s" % (label, "quiet" if quiet else "BLOCKED!"))
    # the 24-char precision guard still applies: a short credential's
    # triple wrap is inert (its base64 never reaches the run minimum)
    short_cred = "xoxb-" + "short1"
    quiet = dlp.find_credential(_wrap(short_cred, 3)) is None
    ok = ok and quiet
    print("    %-20s -> %s" % ("short-cred-triple",
                               "quiet" if quiet else "BLOCKED!"))
    return _check("p5: honest base64 text unaffected", ok)


# ------------------------------------------------------------- P6: embedding
def p6_embedded_triple_blocks():
    b3 = _wrap(_LONG, 3)
    payload = "some prefix text " + b3 + " some suffix text"
    hit = _blocks(payload)
    print("    embedded triple-b64 -> %s" % ("BLOCK" if hit else "MISS!"))
    return _check("p6: embedded triple-wrap blocks coded", hit)


# ----------------------------------------------------------------- P7: ReDoS
def p7_redos_bounds():
    # No new regexes were added for this closure (the fixpoint reuses
    # _B64_RUN); pin that hostile near-miss inputs complete fast.
    hostile = [
        "A" * 10000,                       # long alphabet run, no round-trip
        "ABCD" * 2500,                     # valid alphabet, binary garbage
        "A" * 96 + "!",                    # bad padding terminator
        _b64("A" * 3000),                  # decodes to non-text
        _wrap("A" * 96, 3),                # triple-wrapped non-credential
        ("ABCD" * 24 + " ") * 200,         # many near-miss runs
        "aGVsbG8" * 1500,                  # repeated partial runs
        "=" * 5000,                        # padding-only noise
    ]
    worst = 0.0
    for h in hostile:
        t0 = time.perf_counter()
        try:
            dlp.find_credential(h)
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            print("    EXCEPTION len=%d: %r" % (len(h), e))
            return _check("p7: hostile inputs raise no exceptions", False)
        worst = max(worst, time.perf_counter() - t0)
    print("    worst hostile input: %.3fs" % worst)
    return _check("p7: hostile near-miss inputs fast (< 1s)", worst < 1.0)


# ------------------------------------------------------- P8: no absorption
def p8_no_sibling_absorption():
    # The fixpoint widens ONLY base64 stacks. At the wave-347 merge every
    # sibling is CLOSED by its own lane (entity/escape/policy-delta
    # classes) -- all red-firsts print HELD; the closed F436 stays HELD.
    # Absorption is pinned by the composition battery (0/45/0) and the
    # F443 scope note (map-join absorbed by F437, documented in FINDINGS).
    # Statuses pinned via their red-first scripts.
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    pairs = [
        ("w346_f437_redfirst.py", "HELD"),  # closed wave-347 lane 1
        ("w346_f438_redfirst.py", "HELD"),  # closed wave-347 lane 2
        ("w346_f440_redfirst.py", "HELD"),  # closed wave-347 lane 4
        ("w346_f441_redfirst.py", "HELD"),  # closed wave-347 lane 5
        ("w346_f442_redfirst.py", "HELD"),  # closed wave-347 lane 6
        ("w345_f436_redfirst.py", "HELD"),  # closed wave-346
        ("w346_f439_redfirst.py", "HELD"),   # closed this lane
    ]
    ok = True
    for script, want in pairs:
        tmp = "/var/tmp/g347-noabs-%s-%d" % (script.replace(".py", ""), os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, timeout=300, cwd=REPO_ROOT,
            env=env)
        tail = (r.stdout.strip().splitlines() or [""])[-1].strip()
        # Red-first scripts print BREAK and exit 1 on the open tree
        # (w311 convention); HELD with rc=0 on the closed tree. The
        # F442 script's verdict line is a full sentence, so match the
        # verdict word rather than the whole line.
        if want == "BREAK":
            good = ("BREAK" in tail and "HELD" not in tail)
        else:
            good = (r.returncode == 0 and "HELD" in tail
                    and "BREAK" not in tail)
        ok = ok and good
        print("    %-24s -> %s (want %s) %s"
              % (script, tail, want, "ok" if good else "BAD"))
    return _check("p8: no sibling-finding absorption", ok)


# -------------------------------------------------------------- P9: pin/footer
def p9_pin_and_footer():
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p9: pin 2140, footer open F437,F438,F440-F442/next F443",
                  ok)


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: F439 red-first (now HELD) + adjacent DLP
    batteries. Green checks run with GOV_SKIP_GREEN=1 in the child env.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w346_f439_redfirst.py", "w346_f436close_probes.py",
                   "w346_dlp_composition_probes.py", "w346_attack_probes.py",
                   "w345_attack_probes.py"):
        tmp = "/var/tmp/g347-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["TMPDIR"] = tmp
        env["GOV_SKIP_GREEN"] = "1"
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, timeout=900, cwd=REPO_ROOT,
            env=env)
        tail = (r.stdout.strip().splitlines() or [""])[-1]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        # A red-first script is green when its verdict line is exactly
        # HELD; a battery is green when it exits 0 AND its tally line
        # shows zero BREAKs (tally lines legitimately contain the word
        # "BREAK", so match the count, not the word).
        if script.endswith("redfirst.py"):
            green = (r.returncode == 0 and tail.strip() == "HELD")
        elif script == "w346_dlp_composition_probes.py":
            # w311 convention: expected BREAKs are listed in the
            # battery's own _EXPECTED_BREAKS; the battery fails loudly
            # on any unexpected BREAK or missing expected BREAK. At the
            # wave-347 merge F440's residuals and F441's shapes are all
            # CLOSED (coded refusals), so _EXPECTED_BREAKS is empty and
            # the battery is green at rc=0 with zero BREAKs.
            green = (r.returncode == 0
                     and "0 BREAK / 45 HELD / 0 ERROR" in tail)
        else:
            m = re.search(r"(\d+)\s+BREAK", tail)
            nbreak = int(m.group(1)) if m else None
            green = (r.returncode == 0 and nbreak == 0)
        if not green:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    results = [
        p1_triple_base64_blocks(),
        p2_controls(),
        p3_fixpoint_unit_pins(),
        p4_depth4_plus_is_nongoal(),
        p5_honest_base64_unaffected(),
        p6_embedded_triple_blocks(),
        p7_redos_bounds(),
        p8_no_sibling_absorption(),
        p9_pin_and_footer(),
    ]
    if not args.skip_green:
        print("green check: %s" % _green_check())
    held = sum(results)
    print("w347_f439close: %d HELD / %d BREAK / 0 ERROR"
          % (held, len(results) - held))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
