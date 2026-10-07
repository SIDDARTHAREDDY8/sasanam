#!/usr/bin/env python3
"""Wave-346 F436 closure battery: base64-run poisoning residuals (lane 1).

F436 (LOW, filed 2026-10-05 wave-345 lane 5; scope-narrowed at the
wave-345 merge; CLOSED 2026-10-05 wave-346 lane 1): two genuine
residuals where a sub-threshold HTML-entity fragment inside a base64
run poisoned the run match while a real parser (html.unescape +
base64-decode) recovered the credential --
  (a) a single entity WITHOUT the trailing semicolon (&#65 form)
      inside the run -- the entity regex required ';' while
      html.unescape recovers the legacy form;
  (b) two single entities 25 chars apart inside the run -- per-run
      decoding needed one layer per entity, so entity+base64 could
      not compose inside the 2-layer budget;
  (c) N single entities spaced inside the run (verified at 12) --
      the whole-text pass item bound must cover realistic stacks;
  (d) two/three single escape fragments spaced inside the run --
      the escape analogue of (b): per-run escape decoding needed
      one layer per fragment.
The other 6 filed shapes were absorbed by the F432 closure.

Close-when: the entity layer recognizes the legacy no-semicolon form
mirroring html.unescape (greedy 6-hex/7-decimal digit consumption;
7+ hex / 8+ decimal digits are always out of range so the cap is
semantically identical), a whole-text single-variant entity pass
decodes every entity at once (bounded at 64 items), and a whole-text
escape pass decodes every escape run under both run interpretations
at once -- so entity+base64 and escape+base64 stacks compose in 2
layers -- bounded, static, never executes. All residuals now block
coded dlp-slack-token; honest entity/base64 text unaffected.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: all verified F436 residuals block coded dlp-slack-token
      (no-semicolon entity; two entities 25 apart; 12 spaced
      entities; two/three spaced escape fragments).
  P2  control: plain credential and raw base64 block coded.
  P3  decoder pins: lenient no-semicolon entities decode ('&#65' ->
      'A', '&#x41' -> 'A', '&#X41;' -> 'A'); whole-text pass decodes
      spaced entities in one variant; out-of-range / surrogate /
      non-ASCII decodes are rejected (fail closed).
  P4  discrimination: honest entity/base64 text (docs, email
      obfuscation, prose, honest base64 blobs) does NOT block.
  P5  scope: the 6 F432-absorbed F436 shapes still block (no
      regression of the absorbed class).
  P6  ReDoS: hostile near-miss inputs on the widened entity regexes
      complete fast with no exceptions.
  P7  layering: no-semicolon hex entity + base64 composes; entity
      decode feeds the JS-expression layer within the 2-layer budget.
  P8  pin + footer: taxonomy pin 2135, footer open F437-F441 / next F442.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w346_f436close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import html
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-346: pin 2134 (no new codes in wave-346 merge); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F506, F507, F508, F509, F510, F511"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-347 merge final: F437-F442 CLOSED, F443 OPEN; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)



FOOTER_NEXT = "F513"  #wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)



from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Long test credential: base64 is 52 chars, well over the 24-char
# precision guard. Concatenated -- the write/edit tool redacts
# credential-shaped literals in inputs.
_LONG = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


def _blocks(text):
    return dlp.find_credential(text) == "dlp-slack-token"


def _b64():
    return base64.b64encode(_LONG.encode()).decode()


def _ent(c):
    return "&#%d;" % ord(c)


# --------------------------------------------------------------- P1: closure
def p1_all_f436_residuals_block():
    b64 = _b64()
    # (a) no-semicolon entity inside the base64 run
    a = "&#%d" % ord(b64[0]) + b64[1:]
    # (b) two single entities 25 chars apart inside the run
    b = _ent(b64[0]) + b64[1:25] + _ent(b64[25]) + b64[26:]
    # (c) 12 single entities spaced inside the run (item-bound stress)
    parts, idx = [], 0
    for _ in range(12):
        parts.append(b64[idx:idx + 3])
        parts.append("&#%d;" % ord(b64[idx + 3]))
        idx += 4
    parts.append(b64[idx:])
    c = "".join(parts)
    # (d) two / three single escape fragments spaced inside the run
    d = (b64[:10] + "\\x%02x" % ord(b64[10]) + b64[11:30]
         + "\\x%02x" % ord(b64[30]) + b64[31:])
    e = (b64[:8] + "\\x%02x" % ord(b64[8]) + b64[9:20]
         + "\\u%04x" % ord(b64[20]) + b64[21:32]
         + "\\%03o" % ord(b64[32]) + b64[33:])
    ok = True
    for label, payload, rtfn in (
            ("no-semicolon-entity", a, _rt_html),
            ("two-entities-25-apart", b, _rt_html),
            ("twelve-spaced-entities", c, _rt_html),
            ("two-spaced-escape-fragments", d, _rt_js),
            ("three-spaced-escape-fragments", e, _rt_js)):
        assert _LONG not in payload, "payload smuggles plaintext"
        # real-parser sanity: a real parser recovers the credential
        rt = rtfn(payload)
        hit = _blocks(payload)
        ok = ok and rt and hit
        print("    %-30s -> %s (roundtrip=%s)"
              % (label, "BLOCK" if hit else "MISS!", rt))
    return _check("p1: all verified F436 residuals block coded", ok)


def _rt_html(payload):
    """A real HTML parser (html.unescape) recovers the credential."""
    return base64.b64decode(html.unescape(payload)).decode() == _LONG


def _rt_js(payload):
    """A real JS parser (unicode-escape decode) recovers the credential."""
    return base64.b64decode(
        payload.encode("ascii").decode("unicode_escape")).decode() == _LONG


# --------------------------------------------------------------- P2: control
def p2_plain_and_raw_base64_controls():
    b64 = _b64()
    ok = _blocks(_LONG) and _blocks(b64)
    print("    plain=%s raw-b64=%s"
          % (_blocks(_LONG), _blocks(b64)))
    return _check("p2: plain credential and raw base64 block coded", ok)


# -------------------------------------------------------- P3: decoder pins
def p3_lenient_entity_decoder_pins():
    ok = True
    cases = {
        "&#65": "A",        # legacy no-semicolon decimal
        "&#65;": "A",       # strict decimal unchanged
        "&#x41": "A",       # legacy no-semicolon hex
        "&#X41;": "A",      # strict uppercase-X hex unchanged
        "&#065;": "A",      # leading zeros
    }
    for shape, want in cases.items():
        got = dlp._try_entity_decode(shape)
        good = got == want
        ok = ok and good
        print("    %-10s -> %r %s" % (shape, got, "ok" if good else "BAD"))
    # whole-text pass: two spaced entities decode in one variant
    b64 = _b64()
    payload = _ent(b64[0]) + b64[1:25] + _ent(b64[25]) + b64[26:]
    whole = dlp._try_entity_decode_all(payload)
    good = whole == b64[0] + b64[1:25] + b64[25] + b64[26:]
    ok = ok and good
    print("    decode-all spaced entities -> %s" % ("ok" if good else "BAD"))
    # fail-closed rejections (mirror: real parser cannot recover a
    # credential through these either)
    rejects = [
        "&#0;",        # NUL -> replacement char in html.unescape
        "&#xD800;",    # surrogate
        "&#99999999;",  # out of range
        "&#x110000;",  # out of range
        "&#233;",      # non-ASCII printable gate
    ]
    for shape in rejects:
        good = dlp._try_entity_decode(shape) is None
        ok = ok and good
        print("    %-12s rejected -> %s" % (shape, "ok" if good else "BAD"))
    # no entities at all -> no variant
    good = dlp._try_entity_decode_all("nothing to decode here") is None
    ok = ok and good
    print("    decode-all no-entity text -> %s" % ("ok" if good else "BAD"))
    return _check("p3: lenient entity decoder pins hold", ok)


# ------------------------------------------------------- P4: discrimination
def p4_honest_entity_text_unaffected():
    honest = {
        "entity-docs": "use &#38; for ampersand and &#60;tag&#62; for tags",
        "nosemi-prose": "see &#64 for the at-sign docs",
        "nosemi-price": "price: 5&#46;00 after discount",
        "long-digits": "order &#12345678 shipped yesterday",
        "windows-path": "C:\\new\\project\\file.txt",
        "latex": "\\section{intro} and \\textbf{bold}",
        "honest-b64": "aGVsbG8gd29ybGQ= is just hello world",
        "bad-hex": "token &#xZZ; is not valid hex",
        "percent-doc": "100&#37; genuine leather",
        "email-obfs": "contact bob&#64;example&#46;com",
        "bare-opener": "fish &# chips and more &# stuff",
    }
    ok = True
    for label, text in honest.items():
        quiet = dlp.find_credential(text) is None
        ok = ok and quiet
        print("    %-14s -> %s" % (label, "quiet" if quiet else "BLOCKED!"))
    return _check("p4: honest entity/base64 text unaffected", ok)


# ---------------------------------------------------------------- P5: scope
def p5_absorbed_shapes_still_block():
    # The 6 F436 shapes absorbed by the F432 closure must keep
    # blocking -- the F436 lane must not regress them.
    b64 = _b64()
    shapes = {
        "single-decimal-start": _ent(b64[0]) + b64[1:],
        "single-decimal-middle": b64[:20] + _ent(b64[20]) + b64[21:],
        "single-hex-start": "&#x%x;" % ord(b64[0]) + b64[1:],
        "single-xHH": b64[:10] + "\\x%02x" % ord(b64[10]) + b64[11:],
        "single-uXXXX": b64[:10] + "\\u%04x" % ord(b64[10]) + b64[11:],
        "single-octal": b64[:10] + "\\%03o" % ord(b64[10]) + b64[11:],
    }
    ok = True
    for label, payload in shapes.items():
        hit = _blocks(payload)
        ok = ok and hit
        print("    %-22s -> %s" % (label, "BLOCK" if hit else "MISS!"))
    return _check("p5: F432-absorbed F436 shapes still block", ok)


# ------------------------------------------------------------------- P6: ReDoS
def p6_redos_bounds():
    hostile = [
        "&#" + "6" * 5000,
        "&#" + "6" * 5000 + ";",
        "&#65" * 2000,
        "&#65;" * 2000,
        "&#x" + "a" * 5000,
        "&" + "#6" * 3000 + ";",
        "&#" + "1;" * 3000,
        "x" * 2000 + "&#65" + "y" * 2000,
        "&#" * 2000,
        "&#65 " * 1500,
        "&#x41abc" * 1000,  # greedy-hex boundary churn
    ]
    worst = 0.0
    for h in hostile:
        t0 = time.perf_counter()
        try:
            dlp.find_credential(h)
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            print("    EXCEPTION len=%d: %r" % (len(h), e))
            return _check("p6: hostile inputs raise no exceptions", False)
        worst = max(worst, time.perf_counter() - t0)
    print("    worst hostile input: %.3fs" % worst)
    return _check("p6: hostile near-miss inputs fast (< 1s)", worst < 1.0)


# ----------------------------------------------------------------- P7: layering
def p7_decode_layer_composition():
    ok = True
    # no-semicolon HEX entity inside a base64 run: greedy hex
    # consumption mirrors html.unescape; use a position whose
    # successor is not a hex digit so the REAL parser recovers the
    # credential (otherwise the shape is not an attack at all).
    b64 = _b64()
    hexshape = None
    for i, c in enumerate(b64[:-1]):
        if b64[i + 1] in "0123456789abcdefABCDEF":
            continue
        cand = b64[:i] + "&#x%x" % ord(c) + b64[i + 1:]
        try:
            if base64.b64decode(html.unescape(cand)).decode() == _LONG:
                hexshape = cand
                break
        except Exception:  # noqa: BLE001 -- not a round-tripping shape
            continue
    assert hexshape is not None, "no round-tripping nosemi-hex position"
    hit = _blocks(hexshape)
    ok = ok and hit
    print("    nosemi-hex-in-b64 -> %s (roundtrip=True)"
          % ("BLOCK" if hit else "MISS!"))
    # entity decode feeds the JS-expression layer within budget:
    # '&#34;' -> '"' is strict; use the lenient form inside concat
    js = '"&#x78;oxb-" + "abc123def456"'
    hit = _blocks(js)
    ok = ok and hit
    print("    entity-inside-js-concat -> %s" % ("BLOCK" if hit else "MISS!"))
    return _check("p7: entity layer composes with b64/js layers", ok)


# -------------------------------------------------------------- P8: pin/footer
def p8_pin_and_footer():
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p8: pin 2135, footer open F437-F441 / next F442",
                  ok, footer[-60:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: F436 red-first + F429 closure + attack battery.

    The F436 red-first script now prints HELD (both residuals block).
    Green checks run with GOV_SKIP_GREEN=1 in the child env.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w345_f436_redfirst.py", "w343_f429close_probes.py",
                   "w345_attack_probes.py"):
        tmp = "/var/tmp/g346-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["TMPDIR"] = tmp
        env["GOV_SKIP_GREEN"] = "1"
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, timeout=900, cwd=REPO_ROOT,
            env=env)
        tail = (r.stdout.strip().splitlines() or [""])[-1]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        # A red-first script is green when its verdict line is exactly
        # HELD; a battery is green when it exits 0 AND its tally line
        # shows zero BREAKs (tally lines legitimately contain the word
        # "BREAK", so match the count, not the word).
        if script.endswith("redfirst.py"):
            green = (r.returncode == 0 and tail.strip() == "HELD")
        else:
            m = re.search(r"(\d+)\s+BREAK", tail)
            nbreak = int(m.group(1)) if m else None
            green = (r.returncode == 0 and nbreak == 0)
        if not green:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    results = [
        p1_all_f436_residuals_block(),
        p2_plain_and_raw_base64_controls(),
        p3_lenient_entity_decoder_pins(),
        p4_honest_entity_text_unaffected(),
        p5_absorbed_shapes_still_block(),
        p6_redos_bounds(),
        p7_decode_layer_composition(),
        p8_pin_and_footer(),
    ]
    if not args.skip_green:
        print("green check: %s" % _green_check())
    held = sum(results)
    print("w346_f436close: %d HELD / %d BREAK / 0 ERROR"
          % (held, len(results) - held))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
