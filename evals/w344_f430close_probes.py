#!/usr/bin/env python3
"""Wave-344 F430 closure battery: JS-expression-aware DLP decode layer (lane 1).

F430 (LOW, filed 2026-10-05 wave-343 lane 3, CLOSED 2026-10-05 wave-344
lane 1): a JS string-concatenation expression ('"xoxb-abc123" + "def456"')
evaluates to a credential in any JS engine but missed gov/dlp.py's
find_credential -- the F428 JSFuck parser is alphabet-specific and the
F429 normalization pass decodes no JS expressions. Close-when: the
decode layer statically decodes bounded JS string expressions (no eval)
so the decoded content passes the credential rules.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  red-first closure: the four w343 concat shapes now block coded
      dlp-slack-token (same rule as the plain control).
  P2  extended decode forms: template literals, .concat(), .repeat(),
      String.fromCharCode (decimal and 0x), parenthesized expressions,
      JS number coercion, escapes inside literals.
  P3  discrimination: honest quoted/paren text, bare literals,
      unterminated/interpolated/over-budget/undecodable runs do NOT
      block and never raise.
  P4  end-to-end: scan_value and scan_tool_args block the concat form.
  P5  ReDoS pins: hostile near-miss inputs are fast and exception-free.
  P6  pin + footer: taxonomy pin 2135, footer open F431 / next F432.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w344_f430close_probes.py
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

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2135  # Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); no new codes in wave-344 lane 1; Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F506, F507, F508, F509, F510, F511"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F436 CLOSED 2026-10-05 wave-346 lane 1; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)




FOOTER_NEXT = "F513"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

PLAIN = "xoxb-abc123def456"

_SHAPES = [
    '"xoxb-abc123" + "def456"',
    "'xoxb-abc123' + 'def456'",
    '"xoxb-" + "abc123" + "def456"',
    '"xoxb-abc123"+"def456"',
]


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


# ---------------------------------------------------------------- P1: closure
def p1_concat_shapes_block():
    ok = True
    plain_rule = dlp.find_credential("token=" + PLAIN)
    ok = _check("P1a plain control blocks coded",
                plain_rule == "dlp-slack-token",
                "rule=%s" % plain_rule) and ok
    for i, shape in enumerate(_SHAPES):
        rule = dlp.find_credential("token=" + shape)
        ok = _check("P1%s concat shape blocks coded" % chr(ord("b") + i),
                    rule == "dlp-slack-token",
                    "rule=%s" % rule) and ok
    return ok


# ------------------------------------------------------- P2: extended forms
def p2_extended_decode_forms():
    ok = True
    forms = [
        ("template literals", "`xoxb-abc123` + `def456`"),
        ("concat method", '"xoxb-abc123".concat("def456")'),
        ("repeat method", '"xoxb-".repeat(1) + "abc123def456"'),
        ("fromCharCode decimal",
         "String.fromCharCode(120,111,120,98,45,97,98,99,49,50,51,100,101,102,52,53,54)"),
        ("fromCharCode hex",
         "String.fromCharCode(0x78,0x6f,0x78,0x62,0x2d,0x61,0x62,0x63,0x31,0x32,0x33,0x64,0x65,0x66,0x34,0x35,0x36)"),
        ("parenthesized", '("xoxb-abc123") + ("def456")'),
        ("number coercion", '"xoxb-abc123def" + 456'),
        ("escapes in literal", '"\\x78\\x6f\\x78\\x62-" + "abc123def456"'),
        ("mixed quotes", "'xoxb-abc123' + \"def456\""),
        ("concat chain", '"xoxb-".concat("abc123").concat("def456")'),
    ]
    for name, payload in forms:
        rule = dlp.find_credential("token=" + payload)
        ok = _check("P2 %-28s blocks coded" % name,
                    rule == "dlp-slack-token", "rule=%s" % rule) and ok
    return ok


# ------------------------------------------------------- P3: discrimination
def p3_honest_text_unaffected():
    ok = True
    honest = [
        'He said "hi" + "there" and left',
        "(see the notes)",
        'token="abc"',
        '"unterminated + "def456"',
        '`a${b}c` + "def456"',
        "String.fromCharCode(65)",
        '"a".repeat(999999)',
        '"a" + "b" + "c" + "d"',
        '"xoxb-abc123" + unknownVar',
        "3 + 4",
        "price = (5 + 3) * 2",
    ]
    for payload in honest:
        try:
            rule = dlp.find_credential("token=" + payload)
        except Exception as e:  # noqa: BLE001 - must never raise
            ok = _check("P3 no-raise %r" % payload[:32], False,
                        "%s: %s" % (type(e).__name__, e)) and ok
            continue
        ok = _check("P3 honest not blocked %r" % payload[:32],
                    rule != "dlp-slack-token", "rule=%s" % rule) and ok
    # A fromCharCode decode to innocent text must not block either.
    rule = dlp.find_credential("token=String.fromCharCode(104,105)")
    ok = _check("P3 innocent fromCharCode not blocked",
                rule != "dlp-slack-token", "rule=%s" % rule) and ok
    return ok


# ------------------------------------------------------------ P4: end-to-end
def p4_end_to_end():
    ok = True
    blocked, rule = dlp.scan_value('token="xoxb-abc123" + "def456"')[:2]
    ok = _check("P4a scan_value blocks concat coded",
                blocked and rule == "dlp-slack-token",
                "blocked=%s rule=%s" % (blocked, rule)) and ok
    blocked, rule, _red, _marks = dlp.scan_tool_args(
        "shell_exec", {"command": 'echo "xoxb-abc123" + "def456"'})
    ok = _check("P4b scan_tool_args blocks concat coded",
                blocked and rule == "dlp-slack-token",
                "blocked=%s rule=%s" % (blocked, rule)) and ok
    return ok


# ---------------------------------------------------------------- P5: ReDoS
def p5_redos_pins():
    ok = True
    hostile = [
        '"' * 5000,
        '("a" + ' * 2000,
        '"a"' + ' + "a"' * 5000,
        "String.fromCharCode(" + "65," * 5000 + "65)",
        '"a".repeat(' + "9" * 5000 + ")",
        "(" * 5000,
        '"\\' * 5000,
        "`" + "${" * 2000,
        '"a".concat(' * 2000,
        "String.fromCharCode(0x" + "f" * 5000,
        '"a".repeat(' + "9" * 10000 + ")",
    ]
    t0 = time.time()
    for h in hostile:
        try:
            dlp.find_credential("token=" + h)
        except Exception as e:  # noqa: BLE001 - must fail closed, never loud
            ok = _check("P5 no-raise len=%d" % len(h), False,
                        "%s" % type(e).__name__) and ok
    dt = time.time() - t0
    ok = _check("P5 hostile inputs fast", dt < 5.0, "%.2fs" % dt) and ok
    return ok


# ---------------------------------------------------------- P6: pin + footer
def p6_pin_and_footer():
    ok = True
    ok = _check("P6a pin-taxonomy-2135",
                len(TAXONOMY) == TAXONOMY_PIN
                and len(set(TAXONOMY)) == TAXONOMY_PIN,
                "%d/%d" % (len(TAXONOMY), len(set(TAXONOMY)))) and ok
    last = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
                ).read().splitlines()
    last = [l for l in last if 'Next free finding:' in l][-1]  # Wave-356 merge: footer not last line  # Wave-357 merge: re-indent fix (pre-existing wave-356 rot)
    ok = _check("P6b footer open none / next F437",

                ("Next free finding: **%s**." % FOOTER_NEXT) in last
                and ("Open findings: %s." % FOOTER_OPEN) in last,
                last[:60]) and ok
    full = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _check("P6c F430 closed entry",
                "(F430 filed 2026-10-05, wave-343 lane 3" in full
                and "LOW, CLOSED 2026-10-05 wave-344 lane 1" in full,
                "") and ok  # Wave-361 merge: entries moved off the footer line to standalone lines (format migration); check the file, not just the last line
    return ok


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w343_concat_redfirst.py", "w342_f428close_probes.py",
                   "w343_f429close_probes.py", "w343_attack_probes.py"):
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
        tail = (r.stdout + r.stderr)[-200:]
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
    results = []
    for fn in (p1_concat_shapes_block, p2_extended_decode_forms,
               p3_honest_text_unaffected, p4_end_to_end, p5_redos_pins,
               p6_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
