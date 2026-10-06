#!/usr/bin/env python3
"""Wave-345 F434 closure battery: Array.join JS-expression decode (lane 3).

F434 (LOW, filed 2026-10-05 wave-344 merge as an F430-closure overstatement,
CLOSED 2026-10-05 wave-345 lane 3): the Array.join construction
['x','o','x','b','-','a','b','c','1','2','3','d','e','f','4','5','6'].join('')
evaluates to a credential in any JS engine but missed gov/dlp.py's
find_credential -- the F430 bounded static JS-expression decoder covered
quoted '+' concatenation, template literals, String.fromCharCode,
.concat/.repeat, but not array-literal + .join. Close-when: the decode
layer statically decodes bounded array-literal .join(sep) expressions
(no eval) so the decoded content passes the credential rules.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

NOTE: this file constructs the test credential from fragments at import
time -- never write the full credential-shaped literal into source text
(the edit/write path redacts credential-shaped literals).

Probes:
  P1  red-first closure: F434 join shapes (char-by-char, multi-part,
      double-quote, separator variants, number coercion, fromCharCode
      elements, post-join .concat) now block coded dlp-slack-token.
  P2  discrimination: honest bracket/array text, bare unjoined arrays,
      join on non-arrays, nested arrays, interpolation, unterminated
      runs do NOT block and never raise.
  P3  bounds: over-part-budget and over-output-budget joins decode to
      nothing (never raise); the 64-part boundary decodes.
  P4  end-to-end: scan_value and scan_tool_args block the join form.
  P5  ReDoS pins: hostile near-miss inputs are fast and exception-free.
  P6  pin + footer: taxonomy pin 2135, footer open F432, F433, F435 /
      next F436, F434 closed entry present.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w345_f434close_probes.py
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

TAXONOMY_PIN = 2135  # Wave-343 merge pin; no new codes in wave-345 lane 3; Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F473, F474"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)



FOOTER_NEXT = "F475"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Credential fragments -- the full literal is never written out.
_A = "xoxb"
_D = "-"
_B = "abc123"
_C = "def456"
CRED = _A + _D + _B + _C


def _check(name, cond, detail=""):
    print("%-52s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _char_join(s):
    """The exact F434 red-first shape: char-by-char .join('')."""
    return "[" + ", ".join("'%s'" % ch for ch in s) + "].join('')"


# ---------------------------------------------------------------- P1: closure
def p1_join_shapes_block():
    ok = True
    plain_rule = dlp.find_credential(CRED)
    ok = _check("P1a plain control blocks coded",
                plain_rule == "dlp-slack-token",
                "rule=%s" % plain_rule) and ok
    shapes = [
        ("char-by-char (red-first shape)", _char_join(CRED)),
        ("three-part join",
         "['" + _A + _D + "','" + _B + "','" + _C + "'].join('')"),
        ("double-quote arrays",
         '["' + _A + _D + '", "' + _B + _C + '"].join("")'),
        ("separator '-'", "['" + _A + "','" + _B + _C + "'].join('-')"),
        ("number coercion",
         "['" + _A + _D + _B + _C[:3] + "', " + _C[3:] + "].join('')"),
        ("fromCharCode elements",
         "[String.fromCharCode(120,111,120,98),'" + _D + _B + _C
         + "'].join('')"),
        ("join then .concat",
         "['" + _A + _D + "','" + _B + "'].join('').concat('" + _C + "')"),
        ("whitespace-tolerant",
         "[ '" + _A + _D + "' , '" + _B + _C + "' ].join( '' )"),
        ("template-literal elements",
         "[`" + _A + _D + "`, `" + _B + _C + "`].join('')"),
    ]
    for name, payload in shapes:
        assert CRED not in payload, "payload smuggles plaintext: %s" % name
        rule = dlp.find_credential(payload)
        ok = _check("P1 %s blocks coded" % name,
                    rule == "dlp-slack-token", "rule=%s" % rule) and ok
    return ok


# ------------------------------------------------------- P2: discrimination
def p2_honest_text_unaffected():
    ok = True
    honest = [
        'config = {"ports": [80, 443], "hosts": ["a", "b"]}',
        "[see docs] for details",
        "['a', 'b']",
        "[1, 2, 3].join()",
        "use ['a','b'].join('') to concatenate",
        "'x'.join('')",
        "[['" + _A + "'],'" + _B + "'].join('')",
        "[`" + _A + "${x}`,'" + _B + "'].join('')",
        "['" + _A + "','" + _B + "'.join('')",
        '"token=abc"',
        "[1,2,3].concat([4])",
        "matrix[[0, 1], [2, 3]]",
    ]
    for payload in honest:
        try:
            rule = dlp.find_credential("token=" + payload)
        except Exception as e:  # noqa: BLE001 - must never raise
            ok = _check("P2 no-raise %r" % payload[:36], False,
                        "%s: %s" % (type(e).__name__, e)) and ok
            continue
        ok = _check("P2 honest not blocked %r" % payload[:36],
                    rule != "dlp-slack-token", "rule=%s" % rule) and ok
    # A bare unjoined array is not obfuscation-shaped: no rewrite at all.
    r = dlp._try_js_expr_decode("['a','b']", 0)
    ok = _check("P2 bare array not rewritten", r is None, "r=%r" % (r,)) and ok
    # join on a non-array fails closed (JS would throw): no decode.
    r = dlp._try_js_expr_decode("'abc'.join('')", 0)
    ok = _check("P2 join-on-string fails closed", r is None,
                "r=%r" % (r,)) and ok
    return ok


# ---------------------------------------------------------------- P3: bounds
def p3_budgets_hold():
    ok = True
    # 64 elements is within the part budget: decodes.
    within = "[" + ",".join("'a'" for _ in range(64)) + "].join('')"
    r = dlp._try_js_expr_decode(within, 0)
    ok = _check("P3 64-element join decodes",
                r is not None and r[0] == "a" * 64,
                "r=%r" % (r[0][:12] + "..." if r else None,)) and ok
    # 65+ elements exceeds the budget: no decode, never raise.
    over = "[" + ",".join("'a'" for _ in range(70)) + "].join('')"
    try:
        r = dlp._try_js_expr_decode(over, 0)
    except Exception as e:  # noqa: BLE001
        r = "RAISED:%s" % type(e).__name__
    ok = _check("P3 70-element join fails closed", r is None,
                "r=%r" % (r,)) and ok
    # Output over _MAX_DECODE_BYTES fails closed.
    big = "['" + "a" * 3000 + "','" + "a" * 2000 + "'].join('')"
    try:
        r = dlp._try_js_expr_decode(big, 0)
    except Exception as e:  # noqa: BLE001
        r = "RAISED:%s" % type(e).__name__
    ok = _check("P3 over-output join fails closed", r is None,
                "r=%r" % (r,)) and ok
    # A single over-long literal element fails closed.
    long_elem = "['" + "a" * 5000 + "'].join('')"
    try:
        r = dlp._try_js_expr_decode(long_elem, 0)
    except Exception as e:  # noqa: BLE001
        r = "RAISED:%s" % type(e).__name__
    ok = _check("P3 over-long element fails closed", r is None,
                "r=%r" % (r,)) and ok
    return ok


# ------------------------------------------------------------ P4: end-to-end
def p4_end_to_end():
    ok = True
    payload = _char_join(CRED)
    blocked, rule = dlp.scan_value(payload)[:2]
    ok = _check("P4a scan_value blocks join coded",
                blocked and rule == "dlp-slack-token",
                "blocked=%s rule=%s" % (blocked, rule)) and ok
    blocked, rule, _red, _marks = dlp.scan_tool_args(
        "shell_exec", {"command": "echo " + payload})
    ok = _check("P4b scan_tool_args blocks join coded",
                blocked and rule == "dlp-slack-token",
                "blocked=%s rule=%s" % (blocked, rule)) and ok
    return ok


# ---------------------------------------------------------------- P5: ReDoS
def p5_redos_pins():
    ok = True
    hostile = [
        "[" * 5000,
        "['a'," * 2000,
        "[" + "['a']," * 2000,
        "['a'].join(" * 1000,
        "['" + "a" * 5000 + "'].join(",
        "[" + "'a'," * 5000 + "]",
        "['a'].join('" + "x" * 5000 + "')",
        "[String.fromCharCode(" + "65," * 5000 + "65)].join('')",
        "[" * 200 + "]" * 200,
        "['a'" + " + 'b'" * 2000 + "].join('')",
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
                ).read().splitlines()[-1]
    ok = _check("P6b footer open F436 / next F437",
                ("Next free finding: **%s**." % FOOTER_NEXT) in last
                and ("Open findings: %s." % FOOTER_OPEN) in last,
                last[:60]) and ok
    ok = _check("P6c F434 closed entry",
                "(F434 filed 2026-10-05, wave-344 merge" in last
                and "LOW, CLOSED 2026-10-05 wave-345 lane 3" in last,
                "") and ok
    return ok


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w344_f430close_probes.py", "w343_concat_redfirst.py",
                   "w344_f434_redfirst.py", "w343_attack_probes.py"):
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
    for fn in (p1_join_shapes_block, p2_honest_text_unaffected,
               p3_budgets_hold, p4_end_to_end, p5_redos_pins,
               p6_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-52s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
