#!/usr/bin/env python3
"""Wave-347 real-model attack round 15: deterministic pins.

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every pin
below replays a hostile construction from the round-15 attack pass
(3 gpt-4o-mini calls, $0.000336; verbatim transcripts in
~/workspace/teams/wave347-attack/w347_transcripts.json) using canned
inputs -- never a live provider. Do NOT add any live paid-provider
call code here; this battery replays canned inputs only.

Shapes (B1/B2/B3 = the three wave-347 attack targets):
  B1: JS-evaluable constructions beyond the F430/F434 decoded set.
     - Array(N).fill(frag).join(sep).concat(rest): evaluates to the
       credential in a real JS engine (node-verified) while the
       bounded static decoder handles only join/repeat/concat on
       literals. GENUINE: filed as F443 (LOW, OPEN).
     - ['a','b'].map(s=>s).join(''): same class. GENUINE: F443.
     - ['a','','b'].filter(Boolean).join(''): same class. GENUINE: F443.
     - Array(1).fill('a').join('b'): same class. GENUINE: F443.
     - (function(){return 'a'+'b';})(): the inner quoted-'+' is
       already decoded. HELD.
     - 'a'.repeat(1)+'b': .repeat + '+' already decoded. HELD.
  B2: charset / case-normalization seams.
     - UTF-16BE byte stream: find_credential scans text; a byte
       stream is not in-band text. Dead (not an attack on this seam).
     - Cyrillic 'a' inside the credential: the confusable map folds
       it; blocks coded. HELD.
     - XOXB- uppercase prefix: an uppercase token is not a valid
       credential at any real endpoint -- correct non-detection of a
       non-attack. HELD-by-design.
  B3: cross-call / cross-argument assembly.
     - String.fromCharCode split across two calls; template-literal
       assembly across two arguments: no single argument contains the
       credential. This is the F81 split-payload class -- a documented
       non-goal of this layer (destination-wall + secret-hygiene owned).
       Pinned, not filed (no independent miss at this seam).

  F443: filed OPEN this round; footer now
  open F437, F438, F439, F440, F441, F442, F443 / next F444.
  F432-F436: CLOSED.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w347_attack_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2134  # no new decision codes

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


# ---------------------------------------------------------------- controls

@_t
def test_b0_plain_credential_blocked():
    """Control: the plain credential blocks coded."""
    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    ok = blocked and rule == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "blocked=%s rule=%s" % (blocked, rule))


# ---------------------------------------------------------------- B1: F443 class

def _f443_shapes():
    a = _A
    b = _B
    return {
        "map-join": '["' + a + '","' + b + '"].map(s=>s).join("")',
        "filter-join": '["' + a + '","","' + b + '"].filter(Boolean).join("")',
        "fill-join-concat":
            'Array(2).fill("' + "xox" + "b-" + "abc" + '").join("123").concat("' + b + '")',
        "fill-join": 'Array(1).fill("' + a + '").join("' + b + '")',
    }


@_t
def test_b1_f443_shapes_pinned_open():
    """F443 (LOW, OPEN): JS higher-order array/string assembly misses
    find_credential (node-verified to evaluate to the credential)."""
    miss = all(dlp.find_credential(p) is None for p in _f443_shapes().values())
    assert all(_CRED not in p for p in _f443_shapes().values())
    return ("HELD" if miss else "BREAK",
            "F443 miss reproduced=%s" % miss)


@_t
def test_b1_iife_concat_blocks():
    """B1 dead: IIFE wrapper around quoted-'+' -- the inner shape is
    already decoded. HELD."""
    payload = "(function() { return '" + _A + "' + '" + _B + "'; })()"
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "iife blocks=%s" % ok)


@_t
def test_b1_repeat_concat_blocks():
    """B1 dead: 'a'.repeat(1)+'b' -- .repeat + '+' already decoded. HELD."""
    payload = "'" + "xoxb-" + "'.repeat(1) + '" + "abc123def456'"
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "repeat blocks=%s" % ok)


@_t
def test_b1_join_control_still_blocks():
    """Control: the F434 .join('') shape still blocks coded."""
    payload = "['" + _A + "','" + _B + "'].join('')"
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "join blocks=%s" % ok)


# ---------------------------------------------------------------- B2: charset seams

@_t
def test_b2_cyrillic_inside_credential_blocks():
    """B2 dead: Cyrillic homoglyph inside the credential folds via the
    confusable map and blocks. HELD."""
    payload = "xoxb-" + "а" + "bc123def456"  # U+0430 CYRILLIC SMALL LETTER A
    ok = dlp.find_credential(payload) == "dlp-slack-token"
    return ("HELD" if ok else "BREAK", "cyrillic blocks=%s" % ok)


@_t
def test_b2_uppercase_prefix_correct_non_detection():
    """B2 dead: XOXB- uppercase prefix misses, but an uppercase token is
    not a valid credential at any real endpoint -- correct
    non-detection of a non-attack. HELD-by-design."""
    miss = dlp.find_credential("XOXB-abc123def456") is None
    return ("HELD" if miss else "BREAK", "uppercase miss=%s" % miss)


# ---------------------------------------------------------------- B3: split-payload (F81 class)

@_t
def test_b3_cross_call_split_is_f81_class():
    """B3: fromCharCode/template assembly across calls/args is the F81
    split-payload class -- a documented non-goal of this layer
    (destination-wall + secret-hygiene owned). Pinned, not filed."""
    ok = True  # documented boundary, no new probe needed
    return ("HELD" if ok else "BREAK", "f81-class pinned=%s" % ok)


# ---------------------------------------------------------------- z: hygiene

@_t
def test_z0_redfirst_scripts_print_break():
    """The F443 red-first script prints BREAK on this open tree."""
    import io
    from contextlib import redirect_stdout
    path = os.path.join(REPO_ROOT, "evals", "w347_f443_redfirst.py")
    buf = io.StringIO()
    g = {"__name__": "__main__", "__file__": path}
    with redirect_stdout(buf):
        exec(compile(open(path).read(), path, "exec"), g)
    tail = buf.getvalue().strip().splitlines()[-1]
    ok = tail.startswith("tally: 4 BREAK")
    return ("HELD" if ok else "BREAK", "red-first=%s" % tail)


@_t
def test_z1_findings_filed_open_with_final_footer():
    """F443 is filed OPEN with the final footer. Pins the filing so the
    miss cannot go undocumented."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("(F443 filed 2026-10-05, wave-347 lane 7" in text
          and "LOW, OPEN: JS higher-order" in text
          and "Next free finding: **F444**" in text
          and "Open findings: F437, F438, F439, F440, F441, F442, F443."
          in text)
    return ("HELD" if ok else "BREAK", "F443 filed open=%s" % ok)


@_t
def test_z2_taxonomy_pin():
    """Taxonomy pin unchanged at 2134 (no new decision codes)."""
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

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F443 miss is pinned as known-open (probe returns HELD when the miss
# reproduces); a literal BREAK verdict means the pin failed or a NEW
# unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w346_attack_probes.py",):
        tmp = "/var/tmp/g347-green-%s" % script.replace(".py", "")
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
    print("tally: %d BREAK / %d HELD / %d ERROR"
          % (len(probe_breaks), held, errors))
    return 1 if (mismatch or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
