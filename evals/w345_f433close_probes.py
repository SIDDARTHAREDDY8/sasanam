#!/usr/bin/env python3
"""Wave-345 F433 closure battery: space-free CSS-escape DLP (lane 2).

F433 (LOW, filed 2026-10-05 wave-344 lane 4; CLOSED 2026-10-05 wave-345
lane 2): F429-closure residual -- CSS escapes terminated by a non-hex
character instead of the mandatory space. Per CSS Syntax Level 3 4.3.7
the escape ends at the first non-hex code point, which is NOT consumed,
but the F429 run regex and _decode_one_escape both demanded the
mandatory space. Close-when: the decode layer recognizes space-free
CSS escape termination such that find_credential flags them,
red-first verified, honest text unaffected.

What changed in gov/dlp.py:
  * _ESC_RUN gains a bare [0-9a-fA-F]{1,6} alternative (after the
    with-space form, so "\\78 " still matches with its space) so
    space-free runs are found. The {2,} threshold is UNCHANGED --
    sub-threshold single escapes are F432's scope.
  * New _decode_one_escape_css_free / _try_escape_decode_css_free: a
    second interpretation of each escape run -- \\uXXXX / \\xXX as
    before, CSS 1-6 hex terminated by end-of-run, one whitespace
    (consumed; CRLF counts as one), or any non-hex char (not
    consumed); NO octal fallback. The F429 octal interpretation is
    tried separately, so a run decodes under whichever genuine
    encoding the attacker used.
  * _decode_layer tries both interpretations per run.
  * _decode_one_escape itself is UNTOUCHED (the F430 JS-expression
    decoder shares it).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the verified F433 4-consecutive space-free shape blocks
      coded dlp-slack-token, plus terminator variants (tab/LF/CRLF
      whitespace, 6-digit, uppercase hex, mixed space/space-free).
  P2  control: the plain credential still blocks coded dlp-slack-token.
  P3  decoder unit: _try_escape_decode_css_free decodes single escapes
      (proves the decoder half of the F433 "CSS single" shape -- the
      {2,} run threshold that still gates it is F432's scope;
      composition with the F432 closure flags it).
  P4  discrimination: honest CSS-ish/backslash text does NOT block.
  P5  no-regression: the F429 escape transforms (octal, CSS-with-space,
      unicode, hex) and the F430 concat shape still block.
  P6  ReDoS: hostile near-miss inputs complete in bounded time.
  P7  pin + footer: taxonomy pin 2135; footer open F432, F434, F435 /
      next F436; F433 entry marked CLOSED.
  PZ  green check: adjacent batteries + red-first, depth-1,
      GOV_SKIP_GREEN=1 honored.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w345_f433close_probes.py
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

TAXONOMY_PIN = 2135  # Wave-345: pin 2135 (no new codes in wave-345 lane 2); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F444, F445"  # F436 CLOSED 2026-10-05 wave-346 lane 1; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446)

FOOTER_NEXT = "F446"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446)


from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credential, built by concatenation (never a single literal, per
# the write-tool redaction rule).
_CRED = "xoxb-" + "abc123def456"


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _blocks(text):
    return dlp.find_credential(text) == "dlp-slack-token"


def _quiet(text):
    return dlp.find_credential(text) is None


# ------------------------------------------------------------------ P1
def p1_spacefree_css_blocks():
    """F433 closure: space-free CSS escapes block coded dlp-slack-token."""
    tail = "-abc123def456"
    shapes = {
        # The verified F433 shape: 4 consecutive space-free escapes,
        # each terminated by a backslash (non-hex, not consumed).
        "run/backslash-term": "\\78\\6f\\78\\62" + tail,
        # Punctuation terminators survive decoding (they are not
        # consumed), so they belong in discrimination, not closure.
        # CSS-whitespace terminators: one consumed per escape
        # (CRLF counts as one); the escapes stay consecutive.
        "ws-term": "\\78\t\\6f\n\\78\r\n\\62" + tail,
        # 6-digit and uppercase-hex forms.
        "6digit": "\\000078\\00006f\\000078\\000062" + tail,
        "upper-hex": "\\78\\6F\\78\\62" + tail,
        # Mixed: first escape space-terminated, rest space-free.
        "mixed": "\\78 \\6f\\78\\62" + tail,
        # Longer run: the whole credential CSS-encoded, space-free.
        "full-run": ("\\78\\6f\\78\\62\\2d\\61\\62\\63\\31\\32\\33"
                     + "\\64\\65\\66\\34\\35\\36"),
    }
    ok = True
    for name, shape in shapes.items():
        hit = _blocks("k=" + shape)
        print("    %-18s -> %s" % (name, "BLOCK" if hit else "MISS"))
        ok = ok and hit
    return _check("p1: space-free CSS escapes block coded", ok)


# ------------------------------------------------------------------ P2
def p2_plain_control():
    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    return _check("p2: plain credential blocks coded dlp-slack-token",
                  blocked and rule == "dlp-slack-token")


# ------------------------------------------------------------------ P3
def p3_decoder_unit():
    """The space-free decoder handles single escapes directly.

    find_credential still gates on the {2,} run threshold (F432's
    scope), but the decoder half of the F433 "CSS single" shape is
    proven here -- composition with the F432 closure flags it.
    """
    d = dlp._try_escape_decode_css_free
    da = dlp._try_escape_decode
    cases = [
        # (decoder, input, expected, note)
        (d, "\\78", "x", "single space-free escape decodes"),
        (d, "\\78\\6f\\78\\62", "xoxb", "run decodes"),
        (d, "\\78 ", "x", "space terminator consumed"),
        (d, "\\78\t", "x", "tab terminator consumed"),
        (d, "\\78\r\n", "x", "CRLF terminator consumed as one"),
        (d, "\\000078", "x", "6-digit form"),
        (d, "\\6F", "o", "uppercase hex"),
        (d, "\\u0078", "x", "unicode escape unchanged"),
        (d, "\\x78", "x", "hex escape unchanged"),
        (d, "\\170", None, "0x170 non-ASCII: no octal fallback here"),
        (d, "\\1234567", None, "7 hex digits rejected"),
        (d, "\\q", None, "invalid escape rejected"),
        (d, "\\0", None, "NUL rejected by printable gate"),
        (d, "\\78\\q", None, "partially-valid run rejected whole"),
        (da, "\\78\\6f", None, "interpretation A unchanged (no space)"),
        (da, "\\170\\157", "xo", "interpretation A octal intact"),
        (da, "\\78 \\6f ", "xo", "interpretation A CSS-with-space intact"),
    ]
    ok = True
    for dec, inp, want, note in cases:
        got = dec(inp)
        good = got == want
        print("    %-28r -> %-8r %s (%s)"
              % (inp, got, "ok" if good else "MISMATCH want %r" % (want,),
                 note))
        ok = ok and good
    return _check("p3: space-free decoder unit-pinned", ok)


# ------------------------------------------------------------------ P4
def p4_honest_text_unaffected():
    """Discrimination: honest CSS-ish/backslash text does NOT block."""
    honest = [
        # Single space-free CSS escape: no run forms (F432's threshold).
        "margin: \\78px solid",
        # Double escape decoding to innocent text.
        "a\\78\\64b",
        # Invalid escape: no valid run.
        "a\\q10px solid",
        # Windows path: backslashes but no valid escape runs.
        "C:\\Users\\ops\\notes.txt",
        # 6 hex digits + hex letter: 7th hex char -> strict reject.
        "\\000026B",
        # Classic CSS size shape: single escape, no run.
        "width: \\32px",
        # Spaced escapes never consecutive: no run.
        "a\\78 b\\64 c",
        # Punctuation terminators are NOT consumed per CSS Syntax L3,
        # so they survive decoding: no credential emerges.
        "k=\\78!\\6f?\\78.\\62-abc123def456",
        # Lone backslash-n in prose.
        "first line\\nsecond line of notes",
    ]
    ok = True
    for h in honest:
        rule = dlp.find_credential(h)
        good = rule is None
        print("    %-40r -> %s" % (h[:40], rule))
        ok = ok and good
    return _check("p4: honest CSS-ish text not blocked", ok)


# ------------------------------------------------------------------ P5
def p5_no_regression():
    """F429 transforms + F430 concat still block after the change."""
    octal = "".join("\\%03o" % ord(c) for c in _CRED)
    css_sp = "".join("\\%x " % ord(c) for c in _CRED)
    uni = "".join("\\u%04x" % ord(c) for c in _CRED)
    hexesc = "".join("\\x%02x" % ord(c) for c in _CRED)
    concat = ("token=" + '"' + "xoxb-" + "abc123" + '" + "' + "def456" + '"')
    cases = [
        ("f429-octal", "token=" + octal),
        ("f429-css-space", "token=" + css_sp),
        ("f429-unicode", "token=" + uni),
        ("f429-hex", "token=" + hexesc),
        ("f430-concat", concat),
    ]
    ok = True
    for name, text in cases:
        hit = _blocks(text)
        print("    %-16s -> %s" % (name, "BLOCK" if hit else "MISS"))
        ok = ok and hit
    return _check("p5: F429/F430 closures unregressed", ok)


# ------------------------------------------------------------------ P6
def p6_redos_bounded():
    """Hostile near-miss inputs complete in bounded time."""
    hostile = [
        "\\" + "7" * 20000,
        "\\" + "78" * 10000,
        ("\\78\\" * 3000) + "!",
        "\\1" * 3000,
        "\\" + "f " * 5000,
        "\\78 " * 2000,
        "\\u" + "0" * 50000,
        ("\\78\\6f" * 1500) + "\\7",
    ]
    ok = True
    for h in hostile:
        t0 = time.monotonic()
        dlp.find_credential("k=" + h)
        dt = time.monotonic() - t0
        print("    len=%-7d -> %.2fs" % (len(h), dt))
        ok = ok and dt < 5.0
    return _check("p6: hostile near-miss inputs bounded", ok)


# ------------------------------------------------------------------ P7
def p7_pin_and_footer():
    codes = sorted(TAXONOMY)
    ok_pin = len(codes) == TAXONOMY_PIN == 2135
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok_footer = ("Next free finding: **F446**" in text
                 and "Open findings: F444, F445." in text
                 and "(F433 filed 2026-10-05, wave-344 lane 4" in text
                 and "LOW, CLOSED 2026-10-05 wave-345 lane 2" in text)
    print("    pin=%d footer-open=%s footer-next=%s"
          % (len(codes), FOOTER_OPEN, FOOTER_NEXT))
    return _check("p7: pin 2135 + closed footer", ok_pin and ok_footer)


# ------------------------------------------------------------------ PZ
def _green_check():
    """Depth-1 green check: adjacent batteries + red-first, standalone.

    Honors GOV_SKIP_GREEN=1 (a skipped green check is not an audit --
    the standalone run below always executes it).
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w344_escresid_redfirst.py", "w343_f429close_probes.py",
               "w344_f430close_probes.py", "w344_f431close_probes.py",
               "w344_attack_probes.py")
    for script in scripts:
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
        if script == "w344_escresid_redfirst.py" and "HELD" not in r.stdout:
            raise AssertionError(
                "red-first not HELD on closed tree: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = []
    for fn in (p1_spacefree_css_blocks, p2_plain_control, p3_decoder_unit,
               p4_honest_text_unaffected, p5_no_regression, p6_redos_bounded,
               p7_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("w345_f433close: %d HELD / %d BREAK / %d ERROR"
          % (n_held, n_break, n_err))
    sys.exit(0 if (n_break == 0 and n_err == 0) else 1)


if __name__ == "__main__":
    main()
