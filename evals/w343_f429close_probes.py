#!/usr/bin/env python3
"""Wave-343 F429 closure battery: text-escape/normalization-aware DLP (lane 1).

F429 (LOW, filed 2026-10-05 wave-342 lane 5 (continuous real-model
attack), CLOSED 2026-10-05 wave-343 lane 1): nine text-escape /
normalization forms missed gov/dlp.py's find_credential /
scan_value while the plain credential blocked coded dlp-slack-token:
\\uXXXX, \\xXX, octal, and CSS escapes, HTML entities (hex and
decimal), UTF-16 null-interleave, fullwidth confusables, and
zero-width joiners. Close-when: the decode/normalize layer
recognizes these text-escape transforms such that find_credential
flags them, red-first verified, honest text unaffected.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: all nine F429 transforms now block coded dlp-slack-token
      (same rule as the plain control).
  P2  control: the plain credential still blocks coded dlp-slack-token.
  P3  discrimination: honest backslash text, innocent decodes, innocent
      entities, innocent unicode, and zero-width-bearing honest text do
      NOT block -- refusal fires on decoded credential content, never
      on the escape shape alone.
  P4  layering: a unicode-escaped hex-encoded credential blocks via the
      2-layer decode budget.
  P5  decoder strictness: malformed / surrogate / out-of-range runs are
      ignored (no variant, no crash, no block).
  P6  bounds: oversized escape runs are ignored without hanging.
  P7  end-to-end: scan_value and scan_tool_args block the escaped form.
  P8  pin + footer: taxonomy pin 2143, footer open F431 / next F432.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

Usage:
  ~/workspace/.gov-venv/bin/python evals/w343_f429close_probes.py
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

TAXONOMY_PIN = 2143  # Wave-343: pin 2131 (no new codes in wave-343 lane 1); Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
FOOTER_OPEN = "F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F432, F433, F434, F435 CLOSED 2026-10-05 wave-345 lanes 1-4; F436 CLOSED 2026-10-05 wave-346 lane 1; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)



FOOTER_NEXT = "F700"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_CRED = "xoxb-abc123def456"


def _uni(s):
    return "".join("\\u%04x" % ord(c) for c in s)


def _x(s):
    return "".join("\\x%02x" % ord(c) for c in s)


def _oct(s):
    return "".join("\\%03o" % ord(c) for c in s)


def _css(s):
    return "".join("\\%x " % ord(c) for c in s)


def _html_hex(s):
    return "".join("&#x%x;" % ord(c) for c in s)


def _html_dec(s):
    return "".join("&#%d;" % ord(c) for c in s)


def _utf16_null(s):
    return s.encode("utf-16-le").decode("latin-1")


def _fullwidth(s):
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c
                   for c in s)


def _zero_width(s):
    return "\u200b".join(list(s))


_TRANSFORMS = {
    "unicode-escape": _uni(_CRED),
    "py-hex-escape": _x(_CRED),
    "octal-escape": _oct(_CRED),
    "css-escape": _css(_CRED),
    "html-entity-hex": _html_hex(_CRED),
    "html-entity-dec": _html_dec(_CRED),
    "utf16-null-interleave": _utf16_null(_CRED),
    "fullwidth-confusable": _fullwidth(_CRED),
    "zero-width-join": _zero_width(_CRED),
}


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


# ------------------------------------------------------------------ P1: closure
def p1_all_nine_transforms_block():
    ok = True
    for name, t in _TRANSFORMS.items():
        assert _CRED not in t, "transform %s smuggles plaintext" % name
        rule = dlp.find_credential("token=" + t)
        held = rule == "dlp-slack-token"
        print("    %-24s -> %s" % (name, rule))
        ok = ok and held
    return _check("p1: all nine F429 transforms block coded", ok)


# ------------------------------------------------------------------ P2: control
def p2_plain_control():
    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    return _check("p2: plain credential blocks coded dlp-slack-token",
                  blocked and rule == "dlp-slack-token")


# ---------------------------------------------------------- P3: discrimination
def p3_honest_text_unaffected():
    honest = [
        # Windows path: backslashes but no valid escape runs.
        "C:\\Users\\ops\\notes.txt",
        # Prose with a lone backslash-n (not an escape run).
        "first line\\nsecond line of notes",
        # Valid escapes decoding to innocent text: \\x41\\x41 -> "AA".
        "label=\\x41\\x41 end",
        # Innocent numeric entities decoding to "aABc".
        "a&#65;&#66;c",
        # Innocent unicode: NFKC folds the ligature, still no credential.
        "caf\u00e9 \ufb01le report",
        # Zero-width chars in honest text strip to "ab".
        "a\u200bb\u200cc",
        # CSS-ish text without valid escapes.
        "margin: \\q10px solid",
    ]
    ok = True
    for h in honest:
        rule = dlp.find_credential(h)
        held = rule is None
        print("    %-40r -> %s" % (h[:40], rule))
        ok = ok and held
    return _check("p3: honest backslash/unicode/entity text not blocked", ok)


# ---------------------------------------------------------------- P4: layering
def p4_two_layer_escape_of_hex():
    import binascii
    hexed = binascii.hexlify(_CRED.encode()).decode()
    layered = _uni(hexed)
    rule = dlp.find_credential("token=" + layered)
    return _check("p4: unicode-escaped hex credential blocks (2 layers)",
                  rule == "dlp-slack-token", "rule=%s" % rule)


# --------------------------------------------------------------- P5: strictness
def p5_malformed_runs_ignored():
    bad = [
        "\\ud800\\ud800",      # lone surrogates: rejected code points
        "\\U0041\\U0041",      # uppercase U: not a recognized escape
        "\\x4\\x4",            # short hex: not a valid \\xXX run
        "\\q10\\q10",          # unknown escape letter
        "&#x110000;&#x110000;",  # out-of-range code point
        "&#xD800;&#xD800;",    # surrogate entity
    ]
    ok = True
    for b in bad:
        try:
            rule = dlp.find_credential("v=" + b)
        except Exception as e:  # noqa: BLE001 - strictness means no crash
            print("    %-28r CRASH %s" % (b, e))
            ok = False
            continue
        held = rule is None
        print("    %-28r -> %s" % (b, rule))
        ok = ok and held
    return _check("p5: malformed/surrogate runs ignored, no crash", ok)


# ------------------------------------------------------------------- P6: bounds
def p6_oversized_run_bounded():
    big = "\\u0041" * 20000  # decodes to 20000 chars > _MAX_DECODE_BYTES
    t0 = time.time()
    rule = dlp.find_credential("v=" + big)
    dt = time.time() - t0
    ok = rule is None and dt < 10
    medium = "\\u0041" * 500  # decodes to 500 chars: within budget
    rule2 = dlp.find_credential("v=" + medium)
    ok = ok and rule2 is None
    return _check("p6: oversized escape run ignored without hang",
                  ok, "dt=%.2fs" % dt)


# -------------------------------------------------------------- P7: end to end
def p7_scan_value_and_tool_args():
    blocked, rule = dlp.scan_value("token=" + _uni(_CRED))[:2]
    ok = blocked and rule == "dlp-slack-token"
    blocked2, rule2, _, _ = dlp.scan_tool_args(
        "run_shell", {"command": "echo " + _html_dec(_CRED)})
    ok = ok and blocked2 and rule2 == "dlp-slack-token"
    return _check("p7: scan_value/scan_tool_args block escaped forms", ok,
                  "rule=%s/%s" % (rule, rule2))


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
    if FOOTER_OPEN == "none":  # wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454)
        ok = ok and "Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in footer  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
    else:
        ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p8: pin 2143, footer open F437-F441 / next F442", ok,  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

                  footer[-70:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: F429 red-first + F428 closure battery."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w342_textescape_redfirst.py", "w342_unicode_escape_redfirst.py",
                   "w342_f428close_probes.py"):
        tmp = "/var/tmp/g343-green-%s" % script.replace(".py", "")
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
    for fn in (p1_all_nine_transforms_block, p2_plain_control,
               p3_honest_text_unaffected, p4_two_layer_escape_of_hex,
               p5_malformed_runs_ignored, p6_oversized_run_bounded,
               p7_scan_value_and_tool_args, p8_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("w343_f429close: %d HELD / %d BREAK / %d ERROR"
          % (n_held, n_break, n_err))
    sys.exit(0 if (n_break == 0 and n_err == 0) else 1)


if __name__ == "__main__":
    main()
