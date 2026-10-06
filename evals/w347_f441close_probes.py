#!/usr/bin/env python3
"""Wave-347 F441 closure battery: double-backslash escapes (lane 5).

F441 (LOW, filed 2026-10-05 wave-346 lane 6 (DLP layer-composition
audit), renumbered F438->F441 at the wave-346 merge (attack lane filed
first); CLOSED 2026-10-05 wave-347 lane 5): encoding every credential
char as a double-backslash escape (``\\\\uXXXX`` / ``\\\\xXX``) evaded
find_credential. The escape decoder had no ``\\\\`` -> ``\\``
production: _ESC_RUN matched the inner escape starting at the second
backslash and decoded inside-out, leaving stray backslashes, so the
decode never converged to the credential -- while unicode_escape
applied twice (a real parser stack) recovered it. 3/3 shapes + a
URL-stacked generalization verified MISS on the merged tree.

Close-when: the escape layer handles the escaped-backslash production
-- a bounded whole-text production that collapses doubled backslashes
and decodes the exposed escapes (models the first pass of a real
double-unicode_escape stack) -- such that find_credential flags the
4 shapes coded, red-first verified, honest double-backslash text
unaffected.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: all 4 verified F441 shapes block coded dlp-slack-token
      (bslash-u, bslash-x, bslash-mixed, url-stacked).
  P2  control: plain credential blocks coded; single-backslash
      escapes still block (no regression of F429/F432/F433).
  P3  decoder pins: _try_bslash_unescape_all -- no doubled backslash
      -> []; over-bound pair count -> []; pure collapse variant is
      exposed escapes decoded per interpretation; non-ASCII collapse
      is rejected (fail closed).
  P4  non-looping: repeated application reaches a fixpoint with no
      doubled backslash left (strictly decreasing backslash count).
  P5  discrimination: honest double-backslash content (Windows
      paths, JSON-escaped docs, LaTeX-ish text) does NOT block.
  P6  ReDoS: hostile near-miss backslash inputs complete fast with
      no exceptions (no new regexes -- str.replace/count only).
  P7  no-regression: adjacent closures still block (F429 unicode/
      hex/octal, F432 single-escape, F433 CSS non-hex terminator,
      F434 Array.join, F436 no-semicolon entity).
  P8  pin + footer: taxonomy pin 2135, footer open
      F437, F438, F439, F440, F442 / next F443.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w347_f441close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import codecs
import subprocess
import sys
import time
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-347: pin 2135 (no new codes in wave-347 lane 5); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F496, F497, F498, F499, F500, F501, F502"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # wave-350 lane 3: F449+F450 CLOSED; wave-347 lane 5 (F441 closed); wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # wave-350 lane 3: F449+F450 CLOSED; wave-347 lane 5 (F441 closed); wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN


FOOTER_NEXT = "F503"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credential -- constructed via concatenation, never a literal.
_CRED = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"
assert len(_CRED) == 37


def _blocked(payload):
    return dlp.find_credential(payload) == "dlp-slack-token"


def _rt_double_unescape(payload):
    return (codecs.decode(codecs.decode(payload.encode("ascii"),
                                          "unicode_escape").encode("ascii"),
                          "unicode_escape") == _CRED)


def _rt_url_double_unescape(payload):
    return (codecs.decode(codecs.decode(
        urllib.parse.unquote(payload).encode("ascii"),
        "unicode_escape").encode("ascii"), "unicode_escape") == _CRED)


def p1_closure_bslash_u():
    payload = "".join("\\\\u%04x" % ord(c) for c in _CRED)
    assert _CRED not in payload
    assert _rt_double_unescape(payload), "roundtrip broken (test bug)"
    return _blocked(payload)


def p1_closure_bslash_x():
    payload = "".join("\\\\x%02x" % ord(c) for c in _CRED)
    assert _CRED not in payload
    assert _rt_double_unescape(payload), "roundtrip broken (test bug)"
    return _blocked(payload)


def p1_closure_bslash_mixed():
    payload = ("".join("\\\\u%04x" % ord(c) for c in _CRED[:19])
               + "".join("\\\\x%02x" % ord(c) for c in _CRED[19:]))
    assert _CRED not in payload
    assert _rt_double_unescape(payload), "roundtrip broken (test bug)"
    return _blocked(payload)


def p1_closure_url_stacked():
    payload = ("".join("%%%02X" % ord(c)
                       for c in "".join("\\\\u%04x" % ord(x)
                                        for x in _CRED[:12]))
               + "".join("\\\\u%04x" % ord(c) for c in _CRED[12:]))
    assert _CRED not in payload
    assert _rt_url_double_unescape(payload), "roundtrip broken (test bug)"
    return _blocked(payload)


def p2_control_plain():
    return _blocked(_CRED)


def p2_control_single_escape():
    # F429/F432/F433: single-backslash escapes still block (no regression).
    payload = "".join("\\u%04x" % ord(c) for c in _CRED)
    assert _CRED not in payload
    assert codecs.decode(payload.encode("ascii"),
                         "unicode_escape") == _CRED
    return _blocked(payload)


def p3_decoder_no_pairs():
    return dlp._try_bslash_unescape_all("no backslashes here") == []


def p3_decoder_bound():
    # over-bound doubled pairs fail closed (no variant).
    payload = "\\\\" * (dlp._MAX_WHOLETEXT_ITEMS + 1)
    return dlp._try_bslash_unescape_all(payload) == []


def p3_decoder_collapse_exposes():
    # pure collapse variant + decoded variants, all ASCII-gated.
    payload = "\\\\u0041\\\\u0042"
    vs = dlp._try_bslash_unescape_all(payload)
    assert len(vs) >= 2, "need collapse + decode variants, got %d" % len(vs)
    assert "\\u0041\\u0042" in vs, "pure collapse variant missing"
    assert "AB" in vs, "decoded variant missing"
    return True


def p3_decoder_non_ascii_rejected():
    # collapse decoding to non-ASCII is rejected (fail closed).
    payload = "\\\\u00e9"  # -> \u00e9 -> non-ASCII
    vs = dlp._try_bslash_unescape_all(payload)
    # pure collapse survives (ASCII), decoded form must not appear
    assert "\\u00e9" in vs
    return all(v.encode("ascii", "ignore").decode() == v for v in vs)


def p4_non_looping_fixpoint():
    # repeated application strictly decreases backslashes to a fixpoint.
    payload = "".join("\\\\u%04x" % ord(c) for c in _CRED)
    seen = payload
    for _ in range(10):
        vs = dlp._try_bslash_unescape_all(seen)
        nxt = vs[0] if vs else seen
        assert nxt.count("\\\\") <= seen.count("\\\\"), \
            "backslash count grew -- decode loop"
        if nxt == seen:
            break
        seen = nxt
    else:
        return False
    return "\\\\" not in seen


def p5_discrimination_winpath():
    return dlp.find_credential("C:\\\\Users\\\\admin\\\\docs") is None


def p5_discrimination_json_doc():
    doc = ('{"install_path": "C:\\\\Program Files\\\\app", '
           '"note": "escape \\\\n for newline"}')
    return dlp.find_credential(doc) is None


def p5_discrimination_latex():
    doc = ("\\section{Intro} see \\\\cite{key} and \\\\ref{fig} "
           "in the docs")
    return dlp.find_credential(doc) is None


def p6_redos_hostile():
    hostile = [
        "\\" * 500,
        "\\\\" * 500,
        ("\\\\u" + "0" * 3) * 200,
        "\\\\x" * 500,
        ("a\\\\u0041" * 200),
        "\\\\" * 100 + "\\u00",
        "%5C" * 400,
        "C:" + "\\\\.." * 300,
        "\\\\u0041" * 500 + "!",
    ]
    t0 = time.time()
    for h in hostile:
        dlp.find_credential(h)
    dt = time.time() - t0
    print("    [redos %d hostile inputs in %.2fs]" % (len(hostile), dt))
    return dt < 10.0


def p7_noreg_f429_unicode():
    payload = "".join("\\u%04x" % ord(c) for c in _CRED[:10]) + _CRED[10:]
    assert _CRED not in payload
    return _blocked(payload)


def p7_noreg_f432_single():
    payload = "\\u0078" + "oxb-" + _CRED[4:]
    assert _CRED not in payload
    return _blocked(payload)


def p7_noreg_f433_css_nospace():
    payload = "".join("\\%x" % ord(c) for c in _CRED)
    assert _CRED not in payload
    return _blocked(payload)


def p7_noreg_f434_array_join():
    payload = ("['" + "','".join(_CRED[i:i + 4]
                                for i in range(0, len(_CRED), 4))
               + "'].join('')")
    assert _CRED not in payload
    return _blocked(payload)


def p7_noreg_f436_nosemi_entity():
    payload = "".join("&#%d" % ord(c) for c in _CRED)
    assert _CRED not in payload
    return _blocked(payload)


def p8_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "F441" not in FOOTER_OPEN
    return ok


_PROBES = [
    ("p1-closure-bslash-u", p1_closure_bslash_u),
    ("p1-closure-bslash-x", p1_closure_bslash_x),
    ("p1-closure-bslash-mixed", p1_closure_bslash_mixed),
    ("p1-closure-url-stacked", p1_closure_url_stacked),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-single-escape", p2_control_single_escape),
    ("p3-decoder-no-pairs", p3_decoder_no_pairs),
    ("p3-decoder-bound", p3_decoder_bound),
    ("p3-decoder-collapse-exposes", p3_decoder_collapse_exposes),
    ("p3-decoder-non-ascii-rejected", p3_decoder_non_ascii_rejected),
    ("p4-non-looping-fixpoint", p4_non_looping_fixpoint),
    ("p5-discrimination-winpath", p5_discrimination_winpath),
    ("p5-discrimination-json-doc", p5_discrimination_json_doc),
    ("p5-discrimination-latex", p5_discrimination_latex),
    ("p6-redos-hostile", p6_redos_hostile),
    ("p7-noreg-f429-unicode", p7_noreg_f429_unicode),
    ("p7-noreg-f432-single", p7_noreg_f432_single),
    ("p7-noreg-f433-css-nospace", p7_noreg_f433_css_nospace),
    ("p7-noreg-f434-array-join", p7_noreg_f434_array_join),
    ("p7-noreg-f436-nosemi-entity", p7_noreg_f436_nosemi_entity),
    ("p8-pin-and-footer", p8_pin_and_footer),
]

_EXPECTED_BREAKS = set()  # F441 closed: no expected BREAKs


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001 - battery harness reports
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
    for script in ("w346_dlp_composition_probes.py",
                   "w346_f436close_probes.py",
                   "w345_attack_probes.py"):
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
        out = r.stdout + r.stderr
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if script == "w346_dlp_composition_probes.py":
            # w311_redteam convention: exit 1 with ONLY expected BREAKs
            # (open findings). Pass iff no unexpected/missing BREAKs.
            if "unexpected BREAKs" in out or "expected BREAKs missing" in out:
                raise AssertionError("green check failed: %s" % notes[-1])
            continue
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
    print("w347_f441close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
