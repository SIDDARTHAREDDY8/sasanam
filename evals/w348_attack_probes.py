#!/usr/bin/env python3
"""Wave-348 real-model attack round 16: deterministic pins.

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every pin
below replays a hostile construction from the round-16 attack pass
(5 gpt-4o-mini calls, $0.000634; verbatim transcripts in
~/workspace/teams/wave348-attack/w348_transcripts.json) using canned
inputs -- never a live provider. Do NOT add any live paid-provider
call code here; this battery replays canned inputs only.

Shapes (B1..B5 = the five wave-348 attack targets, probing the
newly-merged wave-347 closure surface: F437 reduce/reduceRight static
decoding, F438 entity+NUL whole-text variant, F439 triple-base64
fixpoint, F440 double-entity double-decode, F441 double-backslash
production, F442 policy-delta mode gate):
  B1: layer-stack compositions across the six new layers.
     - double-HTML-entity + double-backslash: the stack as proposed
       does NOT recover the credential in a real parser (stray
       backslash remains after entity x2 + collapse). Dead proposal.
     - base64 wrapped in double-HTML-entity: recovers via
       html.unescape x2 + base64 -- but the miss is entirely the
       base64 24-char minimum-length gate (long-credential stack
       HELD: the layers DO compose). Folded into F445, not a
       separate finding.
  B2: F437 boundary shapes (nested reduce, filter-then-reduce,
     3-param reduce callback): ALL blocked -- the F437 closure is
     wider than the filed shapes. Pinned as held.
  B3: entity-encoding tricks vs the F440 layer.
     - mixed-case &aMp;/&Lt;: not decoded by any real parser
       (named refs are case-sensitive) -- correct non-detection.
       Dead proposal.
     - no-semicolon numeric &#38: already handled (F436). Dead.
     - double-encoded DECIMAL numeric: blocked -- the F440 layer's
       numeric double-decode covers it. Pinned as held.
  B4: more JS-evaluable constructions.
     - `${[...CRED]}`: evaluates to comma-joined chars, NOT the
       credential. Dead proposal (not an attack).
     - String([CRED]), [].concat(CRED).flat(Infinity).join(''):
       blocked. Pinned as held.
  B5: decode-budget exploitation.
     - junk JS-expression prefix starves the real expression:
       3 junk quoted-concats + real .reduce -> MISS (verified:
       real alone HELD; real-first HELD; node: eval recovers CRED).
       GENUINE: filed as F444 (LOW, OPEN).
     - base64 of a short (<18-char) credential: the 24-char
       minimum-length gate means the run is never attempted.
       GENUINE: filed as F445 (LOW, OPEN). CLOSED 2026-10-06 wave-349
       lane 1 (credential-shape-gated short-run decode).

  F444, F445: filed OPEN this round; footer now
  open F443, F444, F445 / next F446. [F444+F445 CLOSED 2026-10-06
  wave-349; footer now open none / next F446.] [F446-F450 filed
  2026-10-06 wave-349 lane 3; footer now open F446, F447, F448, F449,
  F450 / next F451.]
  F437-F442: CLOSED (wave-347 merge).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w348_attack_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2140  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_CRED = "xoxb-" + "abc123" + "def456"
_A = "xoxb-" + "abc123"
_B = "def" + "456"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


# ---------------------------------------------------------------- controls

@_t
def test_b0_plain_credential_blocked():
    """Control: the plain credential blocks coded."""
    hit = _blocked("token=" + _CRED)
    return ("HELD" if hit else "BREAK", "find_credential=%s" % hit)


@_t
def test_b0_pin_taxonomy():
    """Control: taxonomy pin holds (no new decision codes)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return ("HELD" if ok else "BREAK", "len(TAXONOMY)=%d want %d"
            % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_b0_footer_state():
    """Control: footer shows F451, F452 open, next F454 (F453 CLOSED
    wave-351 lane 3 -- ws-b64 outer layer composes via fixpoint)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F655**" in text  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
and "Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654." in text)  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# ------------------------------------------------- F444: budget starvation

@_t
def test_f444_junk3_then_reduce_blocked():
    """F444 (CLOSED 2026-10-06 wave-349 lane 1): junk-prefixed reduce now
    blocks -- the whole-text JS-expression scan decodes junk and real
    expression in one variant."""
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    payload = "'j0'+'k0';'j1'+'k1';'j2'+'k2';" + real
    hit = _blocked(payload)
    # pinned as closed: HELD when the payload blocks coded dlp-slack-token
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f444_real_reduce_alone_blocks():
    """F444 scope: the real reduce alone blocks (F437 shape)."""
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(real)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f444_real_first_blocks():
    """F444 scope: order matters -- real-first blocks."""
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    hit = _blocked(real + ";'j0'+'k0';'j1'+'k1';'j2'+'k2';")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F445: b64 length gate

@_t
def test_f445_b64_short_credential_miss():
    """F445 is CLOSED 2026-10-06 wave-349 lane 1: base64 of a 16-char
    credential is now attempted (credential-shape-gated short decode)
    and blocks coded dlp-slack-token (was filed OPEN and pinned as a
    miss; flipped to a refusal assertion on closure)."""
    b64 = base64.b64encode(_CRED.encode()).decode()
    hit = _blocked(b64)
    return ("HELD" if hit else "BREAK", "hit=%s b64len=%d" % (hit, len(b64)))


@_t
def test_f445_b64_long_credential_blocks():
    """F445 scope: base64 of a long credential blocks (gate passes)."""
    long_cred = "xoxb-" + "a" * 40
    b64 = base64.b64encode(long_cred.encode()).decode()
    hit = _blocked(b64)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_f445_b64_junk_quiet():
    """F445 discrimination: base64 of junk text stays quiet."""
    b64 = base64.b64encode(b"hello world junk").decode()
    quiet = not _blocked(b64)
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# --------------------------------------- dead proposals (pinned behavior)

@_t
def test_b2_nested_reduce_blocks():
    """B2 dead-end: Array.from reduce is handled by the F437 closure."""
    hit = _blocked("Array.from({length: 3}).reduce((a, b) => a + \"" + _CRED + "\", '')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_filter_reduce_blocks():
    """B2 dead-end: filter-then-reduce is handled."""
    hit = _blocked("[1, 2, 3].filter(x => x > 0).reduce((a, b) => a + \"" + _CRED + "\", '')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_double_decimal_numeric_blocks():
    """B3 dead-end: double-encoded decimal numerics are handled (F440)."""
    dbl = "".join("&#38;#" + str(ord(c)) + ";" for c in _CRED)
    hit = _blocked(dbl)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_string_array_blocks():
    """B4 dead-end: String([cred]) is handled."""
    hit = _blocked("String([\"" + _CRED + "\"])")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_concat_flat_join_blocks():
    """B4 dead-end: concat().flat().join('') is handled."""
    hit = _blocked("[].concat(\"" + _CRED + "\").flat(Infinity).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_url_double_entity_blocks():
    """B1 composition: URL-encoded double-entity stack composes (HELD)."""
    from urllib.parse import quote
    dblent = "".join("&amp;#" + str(ord(c)) + ";" for c in _CRED)
    hit = _blocked(quote(dblent, safe=""))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_nul_double_backslash_blocks():
    """B1 composition: NUL-interleaved double-backslash composes (HELD)."""
    esc = "".join("\\u%04x" % ord(c) for c in _CRED)
    hit = _blocked("\x00".join(list(esc)))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_triple_entity_blocks():
    """B1 composition: triple-entity is handled."""
    ent = "".join("&amp;amp;#" + str(ord(c)) + ";" for c in _CRED)
    hit = _blocked(ent)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_depth4_b64_nongoal_pinned():
    """Depth-4 base64 stays a documented non-goal: pinned miss, not filed."""
    d4 = _CRED
    for _ in range(4):
        d4 = base64.b64encode(d4.encode()).decode()
    miss = not _blocked(d4)
    return ("HELD" if miss else "BREAK", "miss=%s (documented non-goal)" % miss)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F444/F445 misses are pinned as known-open (each probe returns HELD when
# the miss reproduces); a literal BREAK verdict means the pin failed or a
# NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w347_attack_probes.py",):
        tmp = "/var/tmp/g348-green-%s" % script.replace(".py", "")
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
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    held, probe_breaks, errors = 0, set(), 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 - probe must never abort
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
        print("%s %s: %s" % (verdict, fn.__name__, note))
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    if mismatch:
        print("MISMATCH vs expected breaks: got %s want %s"
              % (sorted(probe_breaks), sorted(_EXPECTED_BREAKS)))
        return 1
    print("tally: %d HELD / %d BREAK / %d ERROR" % (held, len(probe_breaks), errors))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
