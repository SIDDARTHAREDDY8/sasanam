#!/usr/bin/env python3
"""Wave-345 F435 closure battery: Greek/Cherokee homoglyph DLP (lane 4).

F435 (LOW, filed 2026-10-05 wave-344 merge as an F431-closure
residual, disclosed out-of-scope in wave-344 lane 2; CLOSED
2026-10-05 wave-345 lane 4): Greek homoglyphs (U+03BF omicron,
U+03B1 alpha, U+03C1 rho) and Cherokee O (U+13A3) do not NFKC-fold
and sat outside F431's Cyrillic-only confusable map -- 4/4 verified
MISS on the F431-closed tree. Close-when: the confusable
normalization covers the verified Greek/Cherokee homoglyph
classes (or refuses obfuscation-shaped runs coded), red-first
verified, honest Greek/Cherokee prose unaffected.

gov/dlp.py gains _GREEK_CHEROKEE_HOMOGLYPHS (8 entries, bounded
static, applied after NFKC alongside the Cyrillic map): the four
verified misses anchor the class; the Greek capital siblings and
the Cherokee small letter are the same visual-homoglyph class
(Unicode confusables). No new decision codes; pin unchanged 2135.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: all four verified F435 shapes now block coded
      dlp-slack-token (same rule as the plain control).
  P2  control: the plain credential still blocks coded dlp-slack-token.
  P3  map pinning: every _GREEK_CHEROKEE_HOMOGLYPHS entry folds at
      the normalizer level; the four verified entries also block
      end-to-end via find_credential. (Greek capitals fold to
      uppercase ASCII; the scanner's slack-token pattern is
      lowercase-only, so capitals pin at the normalizer level.)
  P4  NFKC interaction: none of the 8 entries NFKC-folds (the
      static map is the only fold path); plain ASCII text yields no
      variant (normalizer returns None).
  P5  discrimination: honest Greek prose and honest Cherokee prose
      (containing omicron/alpha/rho and Cherokee O) do NOT block;
      a partial homoglyph (no full credential) does NOT block;
      the unicode-escaped Greek run is inert (F429's
      ASCII-printable gate rejects escape decodes to non-ASCII --
      documented strictness, not relaxed).
  P6  bounds: a long homoglyph run normalizes in linear time (no
      new regexes, str.translate only); no hang, no exception.
  P7  layering: bidi-wrapped homoglyph credential blocks (bidi
      strips, then the map folds); the unicode-escaped homoglyph
      run is ignored without crashing.
  P8  pin + footer: taxonomy pin 2135, footer open F432, F433, F434
      / next F436.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w345_f435close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-345: pin 2135 (no new codes in wave-345 lane 4); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F437, F438, F439, F440, F441"
FOOTER_NEXT = "F442"

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_CRED = "xoxb-" + "abc123def456"


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _blocks(text):
    return dlp.find_credential(text) == "dlp-slack-token"


# ------------------------------------------------------------------ P1: closure
def p1_all_four_verified_shapes_block():
    shapes = {
        # Exact shapes from evals/w344_f435_redfirst.py (verified 4/4
        # MISS on the F431-closed tree).
        "greek-omicron": _CRED.replace("o", "\u03bf"),
        "greek-alpha": _CRED.replace("a", "\u03b1"),
        "greek-rho": _CRED.replace("def456", "def\u03c1456"),
        "cherokee-O": _CRED.replace("o", "\u13a3"),
    }
    ok = True
    for name, t in shapes.items():
        assert _CRED not in t, "transform %s smuggles plaintext" % name
        hit = _blocks(t)
        ok = ok and hit
        print("    %-14s -> %s" % (name, "BLOCKED" if hit else "MISS"))
    return _check("p1: all four F435 shapes block coded", ok)


# ------------------------------------------------------------------ P2: control
def p2_plain_control():
    ok = _blocks(_CRED)
    return _check("p2: plain credential blocks coded", ok)


# ------------------------------------------------------------- P3: map pinning
def p3_every_entry_pinned():
    table = dlp._GREEK_CHEROKEE_HOMOGLYPHS
    expect = {
        "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u13a3": "o",
        "\u0391": "A", "\u039f": "O", "\u03a1": "P", "\uab73": "o",
    }
    ok = set(table) == set(expect) and all(
        table[k] == v for k, v in expect.items())
    if not ok:
        return _check("p3: table == pinned 8 entries", False,
                      "table=%r" % sorted(table.items()))
    # Normalizer-level pin for every entry (no raw folded string is
    # printed: a folded credential is credential-shaped).
    all_fold = True
    for ch, tgt in expect.items():
        folded = dlp._normalize_confusables(ch)
        hit = folded == tgt
        all_fold = all_fold and hit
        print("    U+%04X -> %r %s" % (ord(ch), tgt,
                                      "FOLDS" if hit else "NO-FOLD"))
    ok = ok and all_fold
    # End-to-end pin for the four verified misses: the exact
    # shapes from evals/w344_f435_redfirst.py.
    verified = {
        "\u03bf": _CRED.replace("o", "\u03bf"),
        "\u03b1": _CRED.replace("a", "\u03b1"),
        "\u03c1": _CRED.replace("def456", "def\u03c1456"),
        "\u13a3": _CRED.replace("o", "\u13a3"),
    }
    for ch, probe in verified.items():
        assert _CRED not in probe, "probe smuggles plaintext"
        hit = _blocks(probe)
        ok = ok and hit
        print("    end-to-end U+%04X -> %s" % (ord(ch),
                                              "BLOCKED" if hit else "MISS"))
    return _check("p3: every entry pinned, verified block e2e", ok)


# -------------------------------------------------------- P4: NFKC interaction
def p4_nfkc_nonfolding_and_no_variant():
    import unicodedata
    ok = True
    for ch, tgt in dlp._GREEK_CHEROKEE_HOMOGLYPHS.items():
        folded = unicodedata.normalize("NFKC", ch)
        ok = ok and folded != tgt
    # The static map is the only fold path: a pure-ASCII text yields
    # no variant at all.
    ok = ok and dlp._normalize_confusables("plain ascii text") is None
    ok = ok and dlp._normalize_confusables(_CRED) is None
    return _check("p4: none NFKC-fold, ascii has no variant", ok)


# ------------------------------------------------------- P5: discrimination
def p5_honest_prose_unaffected():
    # Honest Greek prose containing omicron/alpha/rho.
    greek = "\u0397 \u03bf\u03b9\u03ba\u03bf\u03bd\u03bf\u03bc\u03af\u03b1 " \
            "\u03b1\u03bd\u03b1\u03c0\u03c4\u03cd\u03c3\u03c3\u03b5\u03c4" \
            "\u03b1\u03b9 \u03c3\u03c4\u03b1\u03b8\u03b5\u03c1\u03ac"
    # Honest Cherokee prose containing U+13A3 (osiyo = hello).
    cherokee = "\u13a3\u13cf\u13f2 \u13a2\u13c8\u13a2"
    ok = dlp.find_credential(greek) is None
    print("    greek prose -> %s" % dlp.find_credential(greek))
    ok = ok and dlp.find_credential(cherokee) is None
    print("    cherokee prose -> %s" % dlp.find_credential(cherokee))
    # Partial homoglyph (no full credential): no block.
    ok = ok and dlp.find_credential("token=x\u03bf") is None
    # Unicode-escaped Greek run: inert per F429's ASCII-printable
    # gate (escape decodes to non-ASCII are rejected -- documented
    # strictness, not relaxed here).
    escaped = "token=" + "".join("\\u%04x" % ord(c)
                                 for c in "x\u03bfxb-abc123def456")
    ok = ok and dlp.find_credential(escaped) is None
    return _check("p5: honest prose/partial/escaped unaffected", ok)


# ----------------------------------------------------------------- P6: bounds
def p6_long_run_linear_no_hang():
    long_run = "v=" + "\u03bf\u03b1\u03c1" * 20000  # 60k homoglyph chars
    t0 = time.time()
    try:
        dlp.find_credential(long_run)
        ok = True
    except Exception:  # noqa: BLE001
        ok = False
    dt = time.time() - t0
    ok = ok and dt < 10
    # No new regexes introduced: the fold is str.translate only.
    return _check("p6: 60k homoglyph run linear, no hang", ok,
                  "dt=%.2fs" % dt)


# -------------------------------------------------------------- P7: layering
def p7_bidi_plus_homoglyph_composition():
    # Bidi wrap outside, homoglyph credential inside: bidi strips
    # (layer 1), the map folds (layer 2) -- same 2-layer budget as
    # F431's P7.
    layered = "token=\u202e" + "x\u03bfxb-abc123def456" + "\u202c"
    assert _CRED not in layered
    ok = _blocks(layered)
    print("    bidi(homoglyph(cred)) -> %s" % dlp.find_credential(layered))
    # Cherokee small letter O (U+AB73, same letter as U+13A3) also
    # blocks end-to-end -- the class extension holds.
    small = "token=" + "x\uab73xb-abc123def456"
    assert _CRED not in small
    ok = ok and _blocks(small)
    print("    cherokee-small(cred) -> %s" % dlp.find_credential(small))
    return _check("p7: bidi+homoglyph layers block", ok)


# ------------------------------------------------------------ P8: pin + footer
def p8_pin_and_footer():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    # The live footer is the LAST footer line (history lines above it
    # carry stale footers -- the wave-269/319 lesson).
    footer = ""
    for ln in reversed(lines):
        if "Next free finding:" in ln:
            footer = ln
            break
    ok = ok and ("Next free finding: **%s**." % FOOTER_NEXT) in footer
    if FOOTER_OPEN == "none":
        ok = ok and "Open findings: none." in footer
    else:
        ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p8: pin 2135, footer open F437-F441 / next F442", ok,
                  footer[-60:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: F435 red-first + F431 closure + F429 closure."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w344_f435_redfirst.py", "w344_f431close_probes.py",
                   "w343_f429close_probes.py"):
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
        tail = (r.stdout + r.stderr)[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = []
    for fn in (p1_all_four_verified_shapes_block, p2_plain_control,
               p3_every_entry_pinned, p4_nfkc_nonfolding_and_no_variant,
               p5_honest_prose_unaffected, p6_long_run_linear_no_hang,
               p7_bidi_plus_homoglyph_composition, p8_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("w345_f435close: %d HELD / %d BREAK / %d ERROR"
          % (n_held, n_break, n_err))
    sys.exit(0 if (n_break == 0 and n_err == 0) else 1)


if __name__ == "__main__":
    main()
