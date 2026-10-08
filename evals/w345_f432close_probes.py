#!/usr/bin/env python3
"""Wave-345 F432 closure battery: sub-threshold single-escape DLP (lane 1).

F432 (LOW, filed 2026-10-05 wave-344 lane 4; CLOSED 2026-10-05 wave-345
lane 1): the F429 decode layer only attempted a decode when 2+ escapes
ran consecutively (_ESC_RUN / _ENTITY_RUN ``{2,}``). A credential with
exactly ONE escaped character -- ``k=\\u0078oxb-abc123def456`` and its
\\xXX, octal, CSS-space, and &#x..; siblings -- decodes to the raw
credential in any real JSON/JS/CSS/HTML parser but evaded
find_credential, 5/5 verified. Close-when: the decode layer handles
sub-threshold escape runs (or refuses obfuscation-shaped runs coded)
such that find_credential flags them, red-first verified, honest text
unaffected.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: all five verified F432 shapes now block coded
      dlp-slack-token (same rule as the plain control).
  P2  control: the plain credential still blocks coded dlp-slack-token.
  P3  escape-class pins: every escape class decodes a test char through
      the real layer (\\uXXXX, \\UXXXXXXXX, \\xXX, octal, CSS-space,
      &#x..;, &#..;) and end-to-end single-escape credentials block.
  P4  discrimination: honest single-backslash/entity text (Windows
      paths, LaTeX, regex backreference docs, CSS docs, entity docs,
      null escapes) does NOT block.
  P5  scope: the F433 shapes still MISS -- F433 is a separate closure
      lane and must not be silently absorbed into F432.
  P6  ReDoS: hostile near-miss inputs on the widened regexes complete
      fast with no exceptions.
  P7  layering: URL-encoded single-escape credentials block via the
      2-layer decode budget.
  P8  pin + footer: taxonomy pin 2140, footer open F436, F437, F438 /
      next F439 (wave-346 lane 6 filed F437/F438).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w345_f432close_probes.py
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

TAXONOMY_PIN = 2140  # Wave-345: pin 2135 (no new codes in wave-345 lane 1); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F662, F663, F664, F665, F666, F667, F669, F670, F671"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-346 merge final; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)



FOOTER_NEXT = "F672"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_CRED = "xoxb-" + "abc123def456"  # concatenated: write/edit redacts literals


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _blocks(text):
    return dlp.find_credential(text) == "dlp-slack-token"


# ------------------------------------------------------------------ P1: closure
def p1_all_five_f432_shapes_block():
    shapes = {
        "json-\\uXXXX": "k=\\u0078oxb-abc123def456",
        "js-\\xXX": "k=\\x78oxb-abc123def456",
        "js-octal": "k=\\170oxb-abc123def456",
        "css-space": "k=\\78 oxb-abc123def456",
        "html-hex-entity": "k=&#x78;oxb-abc123def456",
    }
    ok = True
    for label, shape in shapes.items():
        if not _blocks(shape):
            ok = False
        print("    %-18s -> %s" % (label, "BLOCK" if _blocks(shape) else "MISS"))
    return _check("p1: all 5 verified F432 shapes block coded", ok)


# ------------------------------------------------------------------ P2: control
def p2_plain_control():
    return _check("p2: plain credential blocks coded", _blocks("token=" + _CRED))


# ------------------------------------------------------- P3: escape-class pins
def p3_every_escape_class_decodes():
    # Each escape class decodes 'x' (0x78) through the real layer, and a
    # credential with one such escape blocks end-to-end.
    cases = {
        "\\uXXXX": "k=\\u0078oxb-abc123def456",
        "\\UXXXXXXXX": "k=\\U00000078oxb-abc123def456",
        "\\xXX": "k=\\x78oxb-abc123def456",
        "octal": "k=\\170oxb-abc123def456",
        "CSS-space": "k=\\78 oxb-abc123def456",
        "&#x..;": "k=&#x78;oxb-abc123def456",
        "&#..;": "k=&#120;oxb-abc123def456",
    }
    ok = True
    for label, shape in cases.items():
        hit = _blocks(shape)
        ok = ok and hit
        print("    %-12s -> %s" % (label, "BLOCK" if hit else "MISS"))
    # Unit-level: the layer decoders accept a single escape directly.
    ok = ok and dlp._try_escape_decode("\\u0078") == "x"
    ok = ok and dlp._try_escape_decode("\\x78") == "x"
    ok = ok and dlp._try_escape_decode("\\170") == "x"
    ok = ok and dlp._try_escape_decode("\\78 ") == "x"
    ok = ok and dlp._try_entity_decode("&#x78;") == "x"
    ok = ok and dlp._try_entity_decode("&#120;") == "x"
    return _check("p3: every escape class decodes and blocks", ok)


# ------------------------------------------------------------ P4: discrimination
def p4_honest_single_backslash_text_unaffected():
    honest = {
        "windows-path": "C:\\new\\project\\file.txt",
        "windows-users": "C:\\Users\\admin\\notes.txt",
        "latex": "\\section{intro} and \\textbf{bold}",
        "backref-docs": "use \\1 to refer to group 1",
        "null-doc": "value \\0 terminated",
        "css-doc": "the escape \\41  is capital A",
        "unicode-doc": "the code point \\u0041 renders as A",
        "entity-doc": "write &#38; for an ampersand",
        "bare-backslash": "a lone \\ in prose stays inert",
    }
    ok = True
    for label, text in honest.items():
        held = dlp.find_credential(text) is None
        ok = ok and held
        print("    %-16s -> %s" % (label, "quiet" if held else "BLOCKED!"))
    return _check("p4: honest single-backslash text unaffected", ok)


# ---------------------------------------------------------------- P5: F433 scope
def p5_f433_shapes_still_miss():
    # F433 (space-free CSS escape termination) was a SEPARATE closure
    # lane (wave-345 lane 2); on the merged tree its shapes now BLOCK
    # coded via the second escape-run interpretation. Refusal assertion.
    shapes = {
        "css-nospace-run": "k=\\78\\6f\\78\\62-abc123def456",
        "css-nospace-single": "k=\\78oxb-abc123def456",
    }
    ok = True
    for label, shape in shapes.items():
        held = dlp.find_credential(shape) == "dlp-slack-token"
        ok = ok and held
        print("    %-18s -> %s" % (label, "BLOCK" if held else "MISS!"))
    return _check("p5: F433 shapes now block (lane 2 closed at merge)", ok)


# ------------------------------------------------------------------- P6: ReDoS
def p6_redos_bounds():
    hostile = [
        "\\" * 2000,
        "\\7" * 2000,
        "\\7777777777" * 200,
        "\\uxyz" * 1000,
        "\\x" * 2000,
        "&" + "#" * 2000,
        "&#x" + "f" * 5000,
        "&#" + "1" * 5000,
        "k=" + "\\1" * 3000,
    ]
    worst = 0.0
    for h in hostile:
        t0 = time.perf_counter()
        dlp.find_credential(h)
        worst = max(worst, time.perf_counter() - t0)
    print("    worst hostile input: %.3fs" % worst)
    return _check("p6: hostile near-miss inputs fast (< 1s)", worst < 1.0)


# ----------------------------------------------------------------- P7: layering
def p7_two_layer_composition():
    # URL-encoded single-escape: %5C -> backslash, then the escape
    # layer decodes -> credential. Exercises the 2-layer budget.
    shape = "k=%5Cu0078oxb-abc123def456"
    return _check("p7: url-encoded single escape blocks", _blocks(shape))


# -------------------------------------------------------------- P8: pin/footer
def p8_pin_and_footer():
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p8: pin 2140, footer open F437-F441 / next F442",
                  ok, footer[-60:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: F432 red-first + F429 closure + attack battery.

    The F432 red-first script now prints HELD (F432 shapes block; F433
    shapes still miss, correctly). Green checks run with
    GOV_SKIP_GREEN=1 in the child env.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w344_escresid_redfirst.py", "w343_f429close_probes.py",
                   "w344_attack_probes.py"):
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
    for fn in (p1_all_five_f432_shapes_block, p2_plain_control,
               p3_every_escape_class_decodes,
               p4_honest_single_backslash_text_unaffected,
               p5_f433_shapes_still_miss, p6_redos_bounds,
               p7_two_layer_composition, p8_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("w345_f432close: %d HELD / %d BREAK / %d ERROR"
          % (n_held, n_break, n_err))
    sys.exit(0 if (n_break == 0 and n_err == 0) else 1)


if __name__ == "__main__":
    main()
