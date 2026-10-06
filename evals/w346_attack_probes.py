#!/usr/bin/env python3
"""Wave-346 real-model attack round 14: deterministic pins.

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every pin
below replays a hostile construction from the round-14 attack pass
(3 gpt-4o-mini calls, $0.000306; verbatim transcripts in
~/workspace/teams/wave346-attack/w346_transcripts.json) using canned
inputs -- never a live provider. Do NOT add any live paid-provider
call code here; this battery replays canned inputs only.

Shapes (B1/B2/B3 = the three wave-346 attack targets):
  B1: JS-evaluable constructions beyond the F430/F434 decoded set.
     - atob('b64-of-short-cred'): the inner base64 run is 20 chars,
       under the deliberate 24-char precision guard (F2/F8-era) -- the
       miss is held-by-design, not a defeat; a 52-char inner run
       blocks via the base64 layer. HELD.
     - ['frag1','frag2'].reduce((a,b)=>a+b): evaluates to the
       credential in any real JS engine (node-verified) while the
       bounded static JS decoder handles only join/repeat/concat --
       .reduce is outside F430's and F434's verified shapes. GENUINE:
       filed as F437 (LOW, OPEN). Miss pinned as known-open.
     - ('CRED'.split('').reverse().join('')) embeds the raw
       credential literal: the regex already matches. Dead. HELD.
  B2: multi-layer stacks (decode composes at most 2 layers deep).
     - Triple base64 wrap: two decodes leave a 52-char base64 run no
       rule matches; a real 3x-decode chain recovers the credential.
       GENUINE: filed as F439 (LOW, OPEN). Miss pinned as known-open.
       Double wrap still blocks (control).
     - Bidi-override + hex run: layers compose, blocks. HELD.
     - HTML entities interleaved with NUL bytes: each entity decodes
       in its own single-entity variant (per-run decode spreads the
       8-candidate budget), so the fully-decoded + NUL-stripped form
       is unreachable within depth-2; html.unescape + NUL-strip
       recovers the credential. GENUINE: filed as F438 (LOW, OPEN).
       Miss pinned as known-open.
  B3: precision/normalization boundaries.
     - XOXB- uppercase prefix: misses, but an uppercase slack token
       is not a valid credential at any real endpoint -- correct
       non-detection of a non-attack. HELD-by-design.
     - bidi override inside the credential: the bidi layer strips
       the override and the credential blocks. HELD.

  F437/F438/F439: filed OPEN this round; footer now
  open F436, F437, F438, F439 / next F440. F432-F435: CLOSED.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w346_attack_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import html
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2135  # Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_CRED = "xoxb-" + "abc123" + "def456"          # 16-char (JS/precision tests)
_LONG = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"  # 37-char (F438/F439)

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _b64(s):
    return base64.b64encode(s.encode()).decode()


# ---------------------------------------------------------------- controls

@_t
def test_b0_plain_credential_blocked():
    """Control: the plain credential blocks coded."""
    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    ok = blocked and rule == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "blocked=%s rule=%s" % (blocked, rule))


@_t
def test_b0b_raw_base64_of_long_credential_blocked():
    """Control: raw base64 of the long credential (52 chars, over the
    24-char precision guard) blocks coded."""
    ok = dlp.find_credential(_b64(_LONG)) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "raw b64 blocks=%s" % ok)


# ---------------------------------------------------------------- B1: JS proposals

@_t
def test_b1_atob_short_inner_run_held_by_design():
    """B1-#1: atob('b64-of-16-char-cred') misses only because the inner
    base64 run is 20 chars -- under the deliberate F2/F8-era 24-char
    precision guard (real tokens are far longer). A 52-char inner run
    blocks via the base64 layer. Held-by-design, not a defeat."""
    inner_short = _b64(_CRED)          # 20 chars
    inner_long = _b64(_LONG)           # 52 chars
    miss_short = dlp.find_credential("atob('" + inner_short + "')") is None
    block_long = dlp.find_credential("atob('" + inner_long + "')") == "dlp-slack-token"
    ok = miss_short and block_long
    return ("HELD" if ok else "BREAK",
            "short-miss=%s long-block=%s" % (miss_short, block_long))


@_t
def test_b1_reduce_shape_pinned_open():
    """F437: ['frag1','frag2'].reduce((a,b)=>a+b) evaluates to the
    credential in a real JS engine but misses find_credential -- the
    JS decoder handles only join/repeat/concat. Known-open miss."""
    payload = "['xoxb-" + "abc123','def456'].reduce((a,b)=>a+b)"
    assert _CRED not in payload
    miss = dlp.find_credential(payload) is None
    return ("HELD" if miss else "BREAK",
            "F437 reduce miss reproduced=%s" % miss)


@_t
def test_b1_join_control_still_blocks():
    """Control: the F434 .join('') shape still blocks coded."""
    payload = "['xoxb-" + "abc123','def456'].join('')"
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "join blocks=%s" % ok)


@_t
def test_b1_split_reverse_join_embeds_literal():
    """B1-#3: ('CRED'.split('').reverse().join('')) contains the raw
    credential text -- the regex already matches. Dead proposal."""
    hit = dlp.find_credential("('" + _CRED + "'.split('').reverse().join(''))") is not None
    return ("HELD" if hit else "BREAK", "literal-embedding hit=%s" % hit)


# ---------------------------------------------------------------- B2: stacked layers

@_t
def test_b2_triple_base64_pinned_open():
    """F439: triple base64 wrap exceeds the depth-2 composition budget --
    two decodes leave a 52-char base64 run no rule matches, while a
    real 3x-decode chain recovers the credential. Known-open miss."""
    b3 = _b64(_b64(_b64(_LONG)))
    assert _LONG not in b3
    miss = dlp.find_credential(b3) is None
    return ("HELD" if miss else "BREAK",
            "F439 triple-b64 miss reproduced=%s" % miss)


@_t
def test_b2_double_base64_control_blocks():
    """Control: double base64 wrap still blocks (depth-2 covers it)."""
    ok = dlp.find_credential(_b64(_b64(_LONG))) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "double-b64 blocks=%s" % ok)


@_t
def test_b2_bidi_plus_hex_composes():
    """B2-#2: bidi-override wrapped hex run -- the bidi and hex layers
    compose and the credential blocks. Dead proposal."""
    hexc = _CRED.encode().hex()
    payload = "\u202e" + hexc + "\u202c"  # RLO ... PDF
    hit = dlp.find_credential(payload) is not None
    return ("HELD" if hit else "BREAK", "bidi+hex hit=%s" % hit)


@_t
def test_b2_entity_null_interleave_pinned_open():
    """F438: entities interleaved with NUL bytes -- each decodes in its
    own single-entity variant (budget spread), so the fully-decoded +
    NUL-stripped form is unreachable within depth-2; html.unescape +
    NUL-strip recovers the credential. Known-open miss."""
    payload = "".join("&#x%02x;\x00" % b for b in _LONG.encode())
    assert _LONG not in payload
    recovered = html.unescape(payload).replace("\x00", "")
    assert recovered == _LONG  # real-parser roundtrip holds
    miss = dlp.find_credential(payload) is None
    return ("HELD" if miss else "BREAK",
            "F438 entity+NUL miss reproduced=%s" % miss)


# ---------------------------------------------------------------- B3: precision boundaries

@_t
def test_b3_uppercase_prefix_held_by_design():
    """B3-#1: XOXB-... misses, but an uppercase slack token is not a
    valid credential at any real endpoint -- correct non-detection
    of a non-attack. Held-by-design."""
    miss = dlp.find_credential("XOXB-" + "ABC123DEF456") is None
    return ("HELD" if miss else "BREAK", "uppercase miss=%s" % miss)


@_t
def test_b3_bidi_inside_credential_blocks():
    """B3-#2: bidi override inside the credential -- the bidi layer
    strips the override and the credential blocks. Dead proposal."""
    hit = dlp.find_credential("xoxb-" + "\u202eabc123" + "def456") is not None
    return ("HELD" if hit else "BREAK", "bidi-mid hit=%s" % hit)


# ---------------------------------------------------------------- red-first scripts + filing + pins

@_t
def test_z0_redfirst_scripts_print_break():
    """The three F437/F438/F439 red-first scripts print BREAK on this
    open tree."""
    import io
    from contextlib import redirect_stdout
    ok = True
    for mod in ("w346_f437_redfirst", "w346_f438_redfirst", "w346_f439_redfirst"):
        path = os.path.join(REPO_ROOT, "evals", mod + ".py")
        buf = io.StringIO()
        g = {"__name__": "__main__", "__file__": path}
        with redirect_stdout(buf):
            exec(compile(open(path).read(), path, "exec"), g)
        tail = buf.getvalue().strip().splitlines()[-1]
        ok = ok and (tail == "BREAK")
    return ("HELD" if ok else "BREAK", "red-first BREAKs=%s" % ok)


@_t
def test_z1_findings_filed_open_with_final_footer():
    """F437-F442 are filed OPEN with the wave-346 merge final footer
    (renumber: attack keeps F437/F438/F439; dlpaudit F440/F441; cigated
    F442): pins the filings so the misses cannot go undocumented."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = (all("(F43%d filed 2026-10-05, wave-346 lane 2" % i in text
              for i in (7, 8, 9))
          and "(F440 filed 2026-10-05, wave-346 lane 6" in text
          and "(F441 filed 2026-10-05, wave-346 lane 6" in text
          and "(F442 filed 2026-10-05, wave-346 lane 3" in text
          and text.count("LOW, OPEN:") >= 6
          and "Next free finding: **F442**" in text
          and "Open findings: F437, F438, F439, F440, F441." in text)
    return ("HELD" if ok else "BREAK", "F437-F441 filed open=%s" % ok)


@_t
def test_z2_taxonomy_pin():
    """Taxonomy pin unchanged at 2135 (no new decision codes)."""
    ok = (len(TAXONOMY) == TAXONOMY_PIN
          and sorted(TAXONOMY) == list(TAXONOMY))
    return ("HELD" if ok else "BREAK",
            "pin=%d len=%d" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_z3_no_paid_api_refs():
    """This battery is $0 by construction: it must not itself contain
    the literals it forbids."""
    src = open(__file__).read()
    forbidden = ["realmodel" + "_harness", "Model" + "Driver",
                 "--provider" + " openai", "Spend" + "Ledger"]
    hits = [s for s in forbidden if s in src]
    ok = not hits
    return ("HELD" if ok else "BREAK", "paid-api refs=%s" % hits)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere:
# the F437/F438/F439 misses are pinned as known-open (probe returns HELD
# when the miss reproduces); a literal BREAK verdict would mean the pin
# failed or a NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w345_attack_probes.py",):
        tmp = "/var/tmp/g346-green-%s" % script.replace(".py", "")
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
