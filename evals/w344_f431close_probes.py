#!/usr/bin/env python3
"""Wave-344 F431 closure battery: bidi-override + Cyrillic-homoglyph DLP (lane 2).

F431 (LOW, filed 2026-10-05 wave-343 merge; CLOSED 2026-10-05 wave-344
lane 2): two F429-closure residuals still missed gov/dlp.py's
find_credential on the F429-closed tree, 2/2 verified -- U+202E
right-to-left override interleaved in the credential (no bidi-control
normalization existed) and Cyrillic homoglyphs (U+043E does NOT
NFKC-fold to ASCII). Close-when: the decode layer strips bidi
controls / reverses RLO-governed runs to visual order and applies a
bounded static Cyrillic-homoglyph map, red-first verified, honest
text unaffected.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: both verified F431 shapes now block coded dlp-slack-token
      (same rule as the plain control).
  P2  control: the plain credential still blocks coded dlp-slack-token.
  P3  homoglyph map: every _CYRILLIC_HOMOGLYPHS entry folds correctly,
      and each entry whose ASCII target occurs in the test credential
      blocks end-to-end via find_credential.
  P4  bidi family: RLO with PDF terminator, LRO/embed/isolate wraps,
      unmatched pops, and nested frames all block or normalize
      without crashing.
  P5  discrimination: honest bidi-bearing text and honest Cyrillic
      prose do NOT block.
  P6  strictness/bounds: >128 bidi controls degrade to strip-only
      without hanging; empty bidi runs are inert; no new regexes
      (linear scan, no ReDoS surface).
  P7  layering: bidi-wrapped unicode-escaped and homoglyph-bearing
      escaped credentials block via the 2-layer decode budget.
  P8  pin + footer: taxonomy pin 2134, footer open F436 / next F437 (wave-345 lane 4: F435 closed).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w344_f431close_probes.py
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

TAXONOMY_PIN = 2134  # Wave-344: pin 2134 (no new codes in wave-344 lane 2)
FOOTER_OPEN = "F437, F439, F440, F441, F442"  # F436 CLOSED 2026-10-05 wave-346 lane 1

FOOTER_NEXT = "F443"

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_CRED = "xoxb-abc123def456"


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _blocks(text):
    return dlp.find_credential(text) == "dlp-slack-token"


# ------------------------------------------------------------------ P1: closure
def p1_both_f431_shapes_block():
    shapes = {
        # A6 exact shape from w343_attack_probes (RLO + reversed tail,
        # no PDF terminator).
        "bidi-rlo-reversed": "token=xoxb-\u202e654fed321cba",
        # A7 exact shape (Cyrillic small letter O for 'o').
        "cyrillic-homoglyph-o": "token=x\u043exb-abc123def456",
    }
    ok = True
    for name, t in shapes.items():
        assert _CRED not in t, "shape %s smuggles plaintext" % name
        rule = dlp.find_credential(t)
        print("    %-24s -> %s" % (name, rule))
        ok = ok and rule == "dlp-slack-token"
    return _check("p1: both verified F431 shapes block coded", ok)


# ------------------------------------------------------------------ P2: control
def p2_plain_control():
    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    return _check("p2: plain credential blocks coded dlp-slack-token",
                  blocked and rule == "dlp-slack-token")


# ------------------------------------------- P3: homoglyph map pinning
def p3_every_homoglyph_entry_pinned():
    table = dlp._CYRILLIC_HOMOGLYPHS
    ok = True
    e2e = 0
    for cyr, asc in sorted(table.items()):
        # The fold contract: the normalizer maps this exact char.
        folded = dlp._normalize_confusables("z" + cyr + "z")
        entry_ok = folded == "z" + asc + "z"
        # End-to-end at the public seam wherever the ASCII target
        # occurs in the test credential.
        if asc in _CRED:
            hostile = "token=" + _CRED.replace(asc, cyr)
            assert _CRED not in hostile
            entry_ok = entry_ok and _blocks(hostile)
            e2e += 1
        if not entry_ok:
            print("    U+%04X -> %r FAILED" % (ord(cyr), asc))
        ok = ok and entry_ok
    return _check("p3: all %d homoglyph entries fold (+%d e2e)"
                  % (len(table), e2e), ok)


# ------------------------------------------------------- P4: bidi family
def p4_bidi_family_blocks():
    shapes = {
        # RLO with an explicit PDF terminator.
        "rlo-pdf-terminated":
            "token=xoxb-\u202e654fed321cba\u202c tail",
        # RLE (RTL embedding) also reverses display order.
        "rle-reversed":
            "token=xoxb-\u202b654fed321cba\u202c tail",
        # LRO wrap: logical order already matches after stripping.
        "lro-wrapped": "token=\u202dxoxb-abc123def456\u202c",
        # RLE embed wrap.
        "rle-wrapped": "token=\u202bxoxb-abc123def456\u202c",
        # Isolate wrap (FSI + PDI).
        "isolate-wrapped": "token=\u2066xoxb-abc123def456\u2069",
        # Unmatched PDF: dropped, credential still matches.
        "unmatched-pdf": "token=xoxb-abc123def456\u202c",
        # Bidi controls around innocent text, credential elsewhere.
        "controls-then-plain": "\u202e\u202c token=xoxb-abc123def456",
    }
    ok = True
    for name, t in shapes.items():
        try:
            hit = _blocks(t)
        except Exception as e:  # noqa: BLE001 - must never crash
            print("    %-20s CRASH %s: %s" % (name, type(e).__name__, e))
            ok = False
            continue
        print("    %-20s -> %s" % (name, hit))
        ok = ok and hit
    # Nested-frame worked example through the normalizer: inner RLO
    # reverses first, then the outer RLO reverses the whole run.
    nested = dlp._normalize_bidi("a\u202eb\u202ecd\u202c")
    ok = ok and nested == "acdb"
    return _check("p4: bidi family blocks / normalizes", ok,
                  "nested=%r" % nested)


# ---------------------------------------------------------- P5: discrimination
def p5_honest_text_unaffected():
    honest = [
        # Bidi controls in honest prose.
        "note: \u202ehello\u202c world",
        "report \u202asummary\u202c done",
        # Honest Cyrillic prose (folds in the variant, no credential).
        "\u043f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440, \u044d\u0442\u043e \u0442\u0435\u0441\u0442",
        # Mixed-script honest text.
        "user \u043e\u043b\u0435\u0433 filed ticket 4821",
        # Lone bidi controls, no credential anywhere.
        "\u202e\u202c\u2066\u2069",
        # Cyrillic homoglyphs spelling innocent words.
        "token=\u043e\u043a",  # 'ok' in Cyrillic: not a credential
    ]
    ok = True
    for h in honest:
        rule = dlp.find_credential(h)
        held = rule is None
        print("    %-40r -> %s" % (h[:40], rule))
        ok = ok and held
    return _check("p5: honest bidi/Cyrillic text not blocked", ok)


# --------------------------------------------------------------- P6: bounds
def p6_bidi_bounds_no_hang():
    # >128 bidi controls: strip-only degradation, linear, no crash.
    many = "\u202e" * 200 + "v=abc"
    t0 = time.time()
    try:
        rule = dlp.find_credential(many)
        dt = time.time() - t0
        ok = rule is None and dt < 10
    except Exception as e:  # noqa: BLE001
        print("    many-controls CRASH %s: %s" % (type(e).__name__, e))
        ok = False
        dt = -1
    # No bidi chars: no variant, no cost beyond the scan.
    ok = ok and dlp._normalize_bidi("plain text") is None
    # Lone RLO at end of string: closes deterministically.
    ok = ok and dlp._normalize_bidi("ab\u202e") == "ab"
    # Long RLO run: linear-time reversal.
    long_run = "v=\u202e" + "ab" * 5000
    t0 = time.time()
    dlp.find_credential(long_run)
    dt2 = time.time() - t0
    ok = ok and dt2 < 10
    return _check("p6: bidi bounds hold, no hang", ok,
                  "dt=%.2fs/%.2fs" % (dt, dt2))


# ---------------------------------------------------------------- P7: layering
def p7_two_layer_compositions():
    """Compositions of the two F431 mechanisms across the 2-layer
    decode budget. NOTE: escape-decode runs that decode to non-ASCII
    are deliberately rejected by F429's ASCII-printable gate
    (undecodable runs ignored) -- that documented strictness is not
    relaxed here; composition with the escape runs goes through the
    bidi mechanism instead."""
    def _uni(s):
        return "".join("\\u%04x" % ord(c) for c in s)

    ok = True
    # RLO wrap outside, unicode escapes inside: bidi strips (layer 1),
    # escape run decodes (layer 2).
    layered1 = "token=\u202e" + _uni(_CRED) + "\u202c"
    ok = ok and _blocks(layered1)
    print("    bidi(unicode-escape(cred)) -> %s"
          % dlp.find_credential(layered1))
    # RLO wrap outside, Cyrillic homoglyph inside: bidi strips
    # (layer 1), homoglyph map folds (layer 2).
    cyr_cred = _CRED.replace("o", "\u043e")
    layered2 = "token=\u202e" + cyr_cred + "\u202c"
    assert _CRED not in layered2
    ok = ok and _blocks(layered2)
    print("    bidi(cyrillic(cred)) -> %s"
          % dlp.find_credential(layered2))
    return _check("p7: bidi/homoglyph compositions block (2 layers)", ok)


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
    return _check("p8: pin 2134, footer open F437-F442 / next F443", ok,

                  footer[-60:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: F431 red-first + F429 closure + attack battery."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w344_f431_redfirst.py", "w343_f429close_probes.py",
                   "w343_attack_probes.py"):
        tmp = "/var/tmp/g344-green-%s" % script.replace(".py", "")
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
    for fn in (p1_both_f431_shapes_block, p2_plain_control,
               p3_every_homoglyph_entry_pinned, p4_bidi_family_blocks,
               p5_honest_text_unaffected, p6_bidi_bounds_no_hang,
               p7_two_layer_compositions, p8_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("w344_f431close: %d HELD / %d BREAK / %d ERROR"
          % (n_held, n_break, n_err))
    sys.exit(0 if (n_break == 0 and n_err == 0) else 1)


if __name__ == "__main__":
    main()
