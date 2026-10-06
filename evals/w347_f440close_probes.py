#!/usr/bin/env python3
"""Wave-347 F440 closure battery: double-HTML-entity encoding (lane 4).

F440 (LOW, filed 2026-10-05 wave-346 lane 6, renumbered F437->F440 at the
wave-346 merge; CLOSED 2026-10-06 wave-347 lane 4): wrapping every
credential char's numeric entity in a SECOND entity -- ``&amp;#xHH;``
(named), ``&amp#xHH;`` (no-semicolon named) -- evaded the entity
sub-layer: _ENTITY_RUN never matched named entities and the inner
``&#xHH;`` never materialized within the 2-layer decode budget, while
html.unescape applied twice (a real parser stack) recovered the
credential. The amp-numeric shape (``&#38;#xHH;``) had already been
absorbed by the F436 closure (wave-346 merge scope note).

Close-when: the decode layer reconstitutes entity-encoded entities --
a whole-text bounded named+numeric double-decode
(_try_double_entity_decode mirrors html.unescape x2 over the bounded
named table amp/AMP, lt/LT, gt/GT, quot/QUOT, apos plus numeric
entities per _ENTITY_ONE) -- so the 3 residuals block coded
dlp-slack-token inside the 2-layer budget (entity+base64 stacks
included), honest named-entity text unaffected, bounded, static,
never executes.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 3 verified F440 residuals block coded
      dlp-slack-token (amp-named, amp-no-semicolon, b64-stacked);
      the absorbed amp-numeric shape still blocks (control).
  P2  control: plain credential and raw base64 block coded.
  P3  decoder pins: bounded named table (exact html.unescape case
      variants: amp/AMP, lt/LT, gt/GT, quot/QUOT, apos (semicolon-only,
      not a legacy no-semicolon name);
      longest-prefix legacy rule); double-decode semantics;
      out-of-table names (``&Lt;``, ``&nbsp;``, ``&APOS;``) stay
      literal; undecodable code points fail closed; no-``&`` text
      yields no variant.
  P4  discrimination: honest named-entity prose (docs, prose,
      ``&amp;``/``&lt;`` mentions, legacy ``&amp`` without semicolon,
      case variants) does NOT block.
  P5  scope: the absorbed amp-numeric shape keeps blocking (no
      regression of the wave-346 merge scope note); the full HTML
      named table is NOT swallowed (``&nbsp;``/``&copy;`` literal).
  P6  ReDoS: hostile named/numeric-entity near-miss inputs complete
      fast with no exceptions.
  P7  layering: double-entity decode composes with the base64 layer
      (b64-stacked) and the JS-expression layer (entity inside
      JS string concatenation) within the 2-layer budget.
  P8  pin + footer: taxonomy pin 2135, footer open
      F437, F438, F439, F441, F442 / next F443.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w347_f440close_probes.py
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

TAXONOMY_PIN = 2135  # Wave-347: pin 2135 (no new codes in wave-347 lane 4); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F447, F448, F449, F450"  # wave-347 lane 4: F440 closed; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 lane 1: F446 CLOSED (open F447-F450)

FOOTER_NEXT = "F451"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)


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


def _dbl(c):
    return "&amp;#x%x;" % ord(c)


def _dbl_nosemi(c):
    return "&amp#x%x;" % ord(c)


def _rt_double_unescape(payload):
    """A real parser stack (html.unescape x2) recovers the credential."""
    return html.unescape(html.unescape(payload)) == _LONG


def _rt_b64_double_unescape(payload):
    inner = base64.b64decode(payload).decode()
    return html.unescape(html.unescape(inner)) == _LONG


# --------------------------------------------------------------- P1: closure
def p1_all_f440_residuals_block():
    shapes = {
        # verified MISS on the open tree (3/3 + b64-stacked)
        "amp-named": ("".join(_dbl(c) for c in _LONG),
                      _rt_double_unescape),
        "amp-no-semicolon": ("".join(_dbl_nosemi(c) for c in _LONG),
                             _rt_double_unescape),
        "b64-stacked": (base64.b64encode(
            "".join(_dbl(c) for c in _LONG).encode()).decode(),
            _rt_b64_double_unescape),
        # absorbed by the F436 closure (wave-346 merge scope note):
        # must keep blocking
        "amp-numeric-absorbed": ("".join("&#38;#x%x;" % ord(c)
                                        for c in _LONG),
                                _rt_double_unescape),
    }
    ok = True
    for label, (payload, rtfn) in shapes.items():
        assert _LONG not in payload, "payload smuggles plaintext"
        rt = rtfn(payload)
        hit = _blocks(payload)
        ok = ok and rt and hit
        print("    %-22s -> %s (roundtrip=%s)"
              % (label, "BLOCK" if hit else "MISS!", rt))
    return _check("p1: all F440 residuals block coded", ok)


# --------------------------------------------------------------- P2: control
def p2_plain_and_raw_base64_controls():
    b64 = base64.b64encode(_LONG.encode()).decode()
    ok = _blocks(_LONG) and _blocks(b64)
    print("    plain=%s raw-b64=%s" % (_blocks(_LONG), _blocks(b64)))
    return _check("p2: plain credential and raw base64 block coded", ok)


# -------------------------------------------------------- P3: decoder pins
def p3_named_entity_decoder_pins():
    ok = True
    # one-pass pins: exact html.unescape case variants of the bounded table
    once = {
        "&amp;": "&", "&amp": "&", "&AMP;": "&", "&AMP": "&",
        "&lt;": "<", "&lt": "<", "&LT;": "<", "&LT": "<",
        "&gt;": ">", "&gt": ">", "&GT;": ">", "&GT": ">",
        "&quot;": '"', "&quot": '"', "&QUOT;": '"', "&QUOT": '"',
        "&apos;": "'",
        "&amplify": "&lify",   # longest-prefix legacy rule
        "&amp=x": "&=x",       # legacy before '='
        "&#65": "A", "&#65;": "A", "&#x41": "A", "&#X41;": "A",
    }
    for shape, want in once.items():
        r = dlp._decode_entity_refs_once(shape)
        got = r[0] if r is not None else None
        good = got == want
        ok = ok and good
        print("    %-12r -> %r %s" % (shape, got, "ok" if good else "BAD"))
    # out-of-table names stay literal (the full HTML table is NOT
    # swallowed): single pass returns the text unchanged
    literal = ["&Lt;", "&Lt", "&nbsp;", "&copy;", "&APOS;", "&Apos;",
               "&apos", "&apostrophe", "&;", "&unknown;", "&123;"]
    for shape in literal:
        r = dlp._decode_entity_refs_once(shape)
        good = r is not None and r[0] == shape
        ok = ok and good
        print("    %-12r stays literal -> %s" % (shape, "ok" if good else "BAD"))
    # double-decode pins
    dbl = {
        "&amp;#x78;": "x",
        "&amp#x78;": "x",
        "&#38;#x78;": "x",
        "&AMP;#x41;": "A",
    }
    for shape, want in dbl.items():
        got = dlp._try_double_entity_decode(shape)
        good = got == want
        ok = ok and good
        print("    double %-14r -> %r %s" % (shape, got, "ok" if good else "BAD"))
    # fail-closed rejections
    rejects = [
        "&#xD800;",     # surrogate
        "&#x110000;",   # out of range
        "&#233;",       # non-ASCII printable gate (single pass decodes,
                        # double-decode variant gated by ASCII)
    ]
    for shape in rejects:
        good = dlp._try_double_entity_decode(shape) is None
        ok = ok and good
        print("    %-12r rejected -> %s" % (shape, "ok" if good else "BAD"))
    # no '&' at all -> no variant
    good = dlp._try_double_entity_decode("nothing to decode here") is None
    ok = ok and good
    print("    no-ampersand text -> %s" % ("ok" if good else "BAD"))
    return _check("p3: bounded named-entity decoder pins hold", ok)


# ------------------------------------------------------- P4: discrimination
def p4_honest_named_entity_text_unaffected():
    honest = {
        "amp-prose": "Tom &amp; Jerry went up the hill",
        "lt-prose": "a &lt; b and c &gt; d in the docs",
        "quot-prose": "use &quot;quotes&quot; for emphasis",
        "apos-prose": "it&apos;s a lovely day",
        "entity-docs": "write &amp;amp; to show an ampersand",
        "legacy-nosemi": "old docs say &amplt works too",
        "upper-prose": "the &AMP; entity means ampersand",
        "mixed-prose": "5 &lt; 10 &amp;&amp; 10 &gt; 5",
        "bare-amp": "fish & chips and R&D",
        "html-sample": "<p>Tom &amp; Jerry</p>",
    }
    ok = True
    for label, text in honest.items():
        quiet = dlp.find_credential(text) is None
        ok = ok and quiet
        print("    %-14s -> %s" % (label, "quiet" if quiet else "BLOCKED!"))
    return _check("p4: honest named-entity text unaffected", ok)


# ---------------------------------------------------------------- P5: scope
def p5_absorbed_and_bounded_scope():
    ok = True
    # absorbed amp-numeric shape keeps blocking (wave-346 merge scope note)
    absorbed = "".join("&#38;#x%x;" % ord(c) for c in _LONG)
    hit = _blocks(absorbed)
    ok = ok and hit
    print("    amp-numeric-absorbed -> %s" % ("BLOCK" if hit else "MISS!"))
    # the bounded table does not swallow the full HTML entity set:
    # &nbsp;/&copy; decode to non-ASCII, gated by the ASCII variant gate
    for shape in ("A&nbsp;B", "X&copy;Y"):
        r = dlp._decode_entity_refs_once(shape)
        good = r is not None and r[0] == shape
        ok = ok and good
        print("    %-10r stays literal -> %s" % (shape, "ok" if good else "BAD"))
    return _check("p5: absorbed shape holds, table stays bounded", ok)


# ------------------------------------------------------------------- P6: ReDoS
def p6_redos_bounds():
    hostile = [
        "&" * 5000,
        "&amp" * 2000,
        "&amp;" * 2000,
        "&#" * 3000,
        "&a" * 4000,
        "&#x" * 2500,
        "&#38;" * 1500,
        "&" + "a" * 10000,
        "&#9999999" * 1000,
        "&AMP;" * 2000,
        "&amp#x" * 1500,
        "&#xD800;" * 1000,
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
    # b64-stacked composes: base64 layer then double-entity layer
    stacked = base64.b64encode(
        "".join(_dbl(c) for c in _LONG).encode()).decode()
    hit = _blocks(stacked)
    ok = ok and hit
    print("    b64-stacked -> %s" % ("BLOCK" if hit else "MISS!"))
    # double-entity inside JS string concatenation: JS layer then
    # double-entity layer, inside the 2-layer budget
    js = ('"' + _dbl("x") + "oxb-" + '" + '
          + '"' + _LONG[len("xoxb-"):] + '"')
    assert _LONG not in js, "js payload smuggles plaintext"
    hit = _blocks(js)
    ok = ok and hit
    print("    entity-inside-js-concat -> %s" % ("BLOCK" if hit else "MISS!"))
    # URL-encoded double-entity: URL layer then double-entity layer
    import urllib.parse  # noqa: E402
    url = urllib.parse.quote("".join(_dbl(c) for c in _LONG), safe="")
    hit = _blocks(url)
    ok = ok and hit
    print("    url-encoded-double-entity -> %s" % ("BLOCK" if hit else "MISS!"))
    return _check("p7: double-entity composes with b64/js/url layers", ok)


# -------------------------------------------------------------- P8: pin/footer
def p8_pin_and_footer():
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p8: pin 2135, footer open F437, F438, F439, F441, F442 / next F443",
                  ok, footer[-60:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: F440 red-first + composition + F436 closure.

    The F440 red-first script now prints HELD (3 residuals block); the
    composition battery keeps its 4 expected F441 BREAKs; the F436
    closure battery stays 8/8. Green checks run with GOV_SKIP_GREEN=1
    in the child env.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w346_f440_redfirst.py", "w346_dlp_composition_probes.py",
               "w346_f436close_probes.py")
    for script in scripts:
        # One TMPDIR per suite run (wave-173 lesson): pid suffix so
        # re-runs never share a dir (stale egress_ledger key risk).
        tmp = "/var/tmp/g347-green-%s-%d" % (script.replace(".py", ""),
                                            os.getpid())
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
        # HELD; the composition battery is green when it exits 1 with
        # exactly its 4 expected F441 BREAKs; other batteries are green
        # when they exit 0 with zero BREAKs (tally lines legitimately
        # contain the word "BREAK", so match the count, not the word).
        if script.endswith("redfirst.py"):
            green = (r.returncode == 0 and tail.strip() == "HELD")
        elif script == "w346_dlp_composition_probes.py":
            m = re.search(r"(\d+)\s+BREAK", tail)
            nbreak = int(m.group(1)) if m else None
            # wave-347 merge: F440's residuals and F441's shapes are all
            # CLOSED (coded refusals); _EXPECTED_BREAKS is empty, so the
            # battery is green at rc=0 with zero BREAKs.
            green = (r.returncode == 0 and nbreak == 0
                     and "unexpected" not in r.stdout)
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
        p1_all_f440_residuals_block(),
        p2_plain_and_raw_base64_controls(),
        p3_named_entity_decoder_pins(),
        p4_honest_named_entity_text_unaffected(),
        p5_absorbed_and_bounded_scope(),
        p6_redos_bounds(),
        p7_decode_layer_composition(),
        p8_pin_and_footer(),
    ]
    if not args.skip_green:
        print("green check: %s" % _green_check())
    held = sum(results)
    print("w347_f440close: %d HELD / %d BREAK / 0 ERROR"
          % (held, len(results) - held))
    return 0 if held == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
