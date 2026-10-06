#!/usr/bin/env python3
"""Wave-342 F428 closure battery: JSFuck-aware DLP decode layer (lane 1).

F428 (LOW, filed 2026-10-05 wave-341 lane C, CLOSED 2026-10-05 wave-342
lane 1): a JSFuck-obfuscated credential missed gov/dlp.py's
find_credential/entropy/scan_value while plain/base64/hex/base32 forms
blocked. Close-when: the decode layer statically decodes JSFuck runs
(no eval) so the decoded content passes the credential rules.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  red-first closure: the w341 artifact JSFuck payload now blocks
      coded dlp-slack-token (same rule as the plain control).
  P2  discrimination: benign JSFuck-alphabet noise and valid JSFuck
      decoding to innocent text do NOT block -- refusal fires on decoded
      credential content, never on the alphabet shape alone.
  P3  decoder strictness unit pins: the construction set decodes;
      Function() / unknown constructs / malformed runs fail closed
      (no variant, no crash, no hang).
  P4  end-to-end: scan_value and scan_tool_args block the JSFuck form.
  P5  F429 closure pin: backslash-escape forms now block coded
      (F429 CLOSED 2026-10-05 wave-343 lane 1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w342_f428close_probes.py
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

TAXONOMY_PIN = 2135  # Wave-341 merge: pin 2131 (no new codes in wave-342 lane 1); Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F480, F481"  # F436 CLOSED 2026-10-05 wave-346 lane 1; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)



FOOTER_NEXT = "F482"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

PLAIN = "xoxb-abc123def456"
ARTIFACT = os.path.join(REPO_ROOT, "evals", "artifacts",
                        "w341_jsfuck_slack_token.txt")


def _check(name, cond, detail=""):
    print("%-42s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


# ------------------------------------------------------------------ P1: closure
def p1_jsfuck_credential_blocks():
    payload = open(ARTIFACT).read().strip()
    bad = sorted(set(payload) - set("[]()!+-"))
    assert not bad, "payload charset drift: %r" % bad
    rule = dlp.find_credential("token=" + payload)
    ok = _check("P1a jsfuck-artifact blocks coded", rule == "dlp-slack-token",
                "rule=%s" % rule)
    plain_rule = dlp.find_credential("token=" + PLAIN)
    ok = _check("P1b same rule as plain control",
                rule == plain_rule == "dlp-slack-token",
                "plain=%s" % plain_rule) and ok
    return ok


# ---------------------------------------------------------- P2: discrimination
def p2_benign_does_not_block():
    ok = True
    # Benign alphabet noise: not valid JSFuck -> no variant -> no block.
    noise = "[()!]" * 40
    ok = _check("P2a alphabet noise ignored",
                dlp.find_credential("note " + noise) is None) and ok
    # Valid JSFuck decoding to innocent text: variant produced, no
    # credential regex matches -> no block.
    ok = _check("P2b innocent decode (->'false') ignored",
                dlp.find_credential("x=" + "(![]+[])") is None) and ok
    ok = _check("P2c innocent decode (->'undefined') ignored",
                dlp.find_credential("y=" + "([][[]]+[])") is None) and ok
    # Short valid JSFuck (below the run threshold): ignored, no crash.
    ok = _check("P2d short jsfuck ignored",
                dlp.find_credential("z=" + "(![]+[])[+[]]") is None) and ok
    # Honest text mentioning brackets: untouched.
    ok = _check("P2e honest bracket text untouched",
                dlp.find_credential("array: [1, 2] and (a+b)!") is None) and ok
    return ok


# ------------------------------------------------------- P3: decoder strictness
def p3_decoder_strictness():
    ok = True
    # Construction set decodes.
    cases = [
        ("![]", "false"),
        ("!![]", "true"),
        ("+[]", "0"),
        ("+!+[]", "1"),
        ("(![]+[])", "false"),
        ("(![]+[])[+[]]", "f"),
        ("([][[]]+[])", "undefined"),
        ("((+!![]+!+[]+!+[]))", "3"),
        # JS semantics check: +!![]+!+[] is 1+true=2 (not 1+1), and
        # 3+[0] string-concatenates via Array join -> "30".
        ("((+!![]+!+[]+!+[]+[+[]]))", "30"),
        ("([+[]]+[])", "0"),
        ("(+[![]]+[])", "NaN"),
    ]
    for src, want in cases:
        got = dlp._try_jsfuck_decode("(" + src + ")")
        ok = _check("P3a construct %r" % src[:12], got == want,
                    "got=%r" % got) and ok
    # Function() (arbitrary code) fails closed.
    evil = ("([][(![]+[])[+[]]+([][[]]+[])[+!![]+!+[]+!+[]+!+[]+!+[]]"
            "+(![]+[])[+!![]+!+[]]+(![]+[])[+!![]+!+[]]])"
            "[(![]+[])[+[]]+([][[]]+[])[+!![]+!+[]+!+[]+!+[]+!+[]]"
            "+(![]+[])[+!![]+!+[]]+(![]+[])[+!![]+!+[]]+"
            "([][[]]+[])[+[]]+([][[]]+[])[+!![]+!+[]+!+[]+!+[]+!+[]]"
            "+(![]+[])[+!![]+!+[]]+(![]+[])[+!![]+!+[]]]"
            "((![]+[])[+[]]+([][[]]+[])[+!![]+!+[]+!+[]+!+[]+!+[]])+")
    ok = _check("P3b Function() constructor call refused",
                dlp._try_jsfuck_decode("(" + evil + ")") is None) and ok
    # Malformed runs: fail closed, fast.
    t0 = time.time()
    bad_runs = [
        "(" * 500 + "[]" + ")" * 500,   # depth blowout
        "[()!]" * 40,                    # invalid grammar
        "[]()!+-" * 20000,               # oversize run -> skipped
    ]
    for i, run in enumerate(bad_runs):
        r = dlp._try_jsfuck_decode(run)
        ok = _check("P3c malformed run %d ignored" % i, r is None) and ok
    dt = time.time() - t0
    ok = _check("P3d malformed runs fast (no hang)", dt < 5.0,
                "%.2fs" % dt) and ok
    return ok


# -------------------------------------------------------------- P4: end-to-end
def p4_end_to_end():
    payload = open(ARTIFACT).read().strip()
    ok = True
    blocked, rule, _red, _hits = dlp.scan_value("token=" + payload)
    ok = _check("P4a scan_value blocks jsfuck",
                blocked and rule == "dlp-slack-token") and ok
    b2, r2, _ra, _rh = dlp.scan_tool_args(
        "send_email", {"body": "leak: " + payload})
    ok = _check("P4b scan_tool_args blocks jsfuck",
                b2 and r2 == "dlp-slack-token") and ok
    # Cross-field: jsfuck split across two params still decodes per-part.
    half = len(payload) // 2
    r3 = dlp.find_credential_cross_field(
        {"a": payload[:half], "b": payload[half:]})
    ok = _check("P4c cross-field jsfuck halves block",
                r3 == "dlp-slack-token", "rule=%s" % r3) and ok
    return ok


# ------------------------------------------------------- P5: F429 closure pin
def p5_f429_still_open():
    """F429 CLOSED 2026-10-05 wave-343 lane 1: the backslash-escape
    forms the F428 lane filed as F429 now block coded dlp-slack-token.
    Name kept for merge-sweep stability."""
    ok = True
    forms = {
        "unicode \\uXXXX": "".join("\\u%04x" % ord(c) for c in PLAIN),
        "hex \\xXX": "".join("\\x%02x" % ord(c) for c in PLAIN),
    }
    for name, form in forms.items():
        r = dlp.find_credential("token=" + form)
        ok = _check("P5 %s now blocks coded (F429 CLOSED)" % name,
                    r == "dlp-slack-token", "rule=%s" % r) and ok
    return ok


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
    return ok


def _green_check():
    """Depth-1 green check: sibling w341 batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w341_jsfuck_probes.py", "w341_tmpl_escape_probes.py",
                   "w341_attack_probes.py"):
        tmp = "/var/tmp/g342-green-%s" % script.replace(".py", "")
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
    for fn in (p1_jsfuck_credential_blocks, p2_benign_does_not_block,
               p3_decoder_strictness, p4_end_to_end, p5_f429_still_open,
               p6_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-42s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
