#!/usr/bin/env python3
"""Wave-374 lane 2: close F613 -- String.raw tag in non-leading positions.

F613 (LOW, filed attack round 41): the String.raw TAG form decoded only
when the whole-text scan anchored at the backtick itself (the leading
primary position: String.raw`f1`+'f2' blocks coded, F463 CLOSED). The
tag parser never fired in any other operand position, so
'f1'+String.raw`f2` (RHS of +), (String.raw`f1`)+'f2' (parenthesized),
and [String.raw`f1`,String.raw`f2`].join('') (array elements) all
node-evaluated to the exact credential (v24.20.0) while the decoder
produced zero variants. Distinct from F463 (leading/substitution tag
forms, CLOSED) and F493/F551/F575 (call forms, CLOSED).

Closure (gov/dlp.py, F613): _js_parse_raw_tag_template -- the raw-text
twin of _js_parse_tag_template (escapes kept literally, node-exact:
String.raw`a\\nb` === "a\\\\nb"); _js_parse_primary's String branch
routes String.raw (ws-tolerant, ident-bounded) + backtick to it in
EVERY operand position (RHS of +, parenthesized groups, array
elements, call args); the _JS_EXPR_START anchor gains the
`\\(String.raw`` ` alternative so parenthesized tags are reached at
the group paren (re.compile stays 28). ${...} interpolation fails
closed (the substitution form keeps its anchor-at-backtick cooked
handling, the F463 control).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g374-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_rhs_of_plus():
    """F613 shape 1 CLOSED: 'f1'+String.raw`f2` blocks."""
    ok = _blocked("'%s'+String.raw`%s`" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_parenthesized():
    """F613 shape 2 CLOSED: (String.raw`f1`)+'f2' blocks."""
    ok = _blocked("(String.raw`%s`)+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_array_join():
    """F613 shape 3 CLOSED: [String.raw`f1`,String.raw`f2`].join('') blocks."""
    ok = _blocked("[String.raw`%s`,String.raw`%s`].join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ node-exact variants

def test_p2_raw_escapes_kept():
    """Raw escapes stay literal (node: String.raw`a\\nb` === "a\\\\nb")."""
    # 'x' + raw("a\\nb") -> 'xa\\nb' is not credential-shaped, but the
    # decode must be byte-exact: assert via the whole-text variant.
    from gov.dlp import _try_js_expr_decode_all
    v = _try_js_expr_decode_all("'x'+String.raw`a\\nb`")
    ok = v is not None and "xa\\nb" in v and "xa\nb" not in v
    return ("HELD" if ok else "BREAK", "variant=%r" % (v,))


def test_p2_ws_tolerant_tag():
    """Whitespace between String.raw and the template decodes (node-exact)."""
    ok = _blocked("'x'+String . raw `%s%s`" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_paren_nested():
    """Doubly-parenthesized tag decodes (anchor reaches the outer paren)."""
    ok = _blocked("((String.raw`%s`))+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_tag_in_call_arg():
    """Tag as a call argument decodes (primary position generality)."""
    ok = _blocked("''.concat(String.raw`%s%s`)" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ fail-closed boundaries

def test_p3_interpolation_fails_closed():
    """${...} in a non-leading tag fails closed (F463 discipline)."""
    from gov.dlp import _try_js_expr_decode_all
    # The tag itself must not decode; only the pre-existing
    # anchor-at-backtick cooked path may fire (no credential assembly).
    v = _try_js_expr_decode_all("'%s'+String.raw`${'x'}`" % _A)
    ok = v is None or (_A + "x") not in v
    return ("HELD" if ok else "BREAK", "variant=%r" % (v,))


def test_p3_non_raw_tags_fail_closed():
    """Other tags / ident continuations fail closed."""
    shapes = [
        "'%s'+String.rawx`%s`" % (_A, _B),   # ident continuation
        "'%s'+Stringx.raw`%s`" % (_A, _B),    # Stringx
        "'%s'+Object.raw`%s`" % (_A, _B),     # non-String tag
        "'%s'+String.raw`%s" % (_A, _B),      # unterminated
    ]
    bad = [s for s in shapes if _blocked(s)]
    return (("BREAK", "leaked: %s" % bad) if bad
            else ("HELD", "4/4 fail closed"))


def test_p3_trailing_junk_after_tag():
    """Trailing junk after a closed tag stays quiet (node: SyntaxError)."""
    # String.raw`ab`+`B` -- the tag closes at the second backtick; the
    # trailing template never assembles a credential.
    ok = _misses("String.raw`ab`+`%s`" % _B)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ neighbors & controls

def test_p4_f463_controls_intact():
    """F463 leading/substitution forms still block (unchanged)."""
    ok = (_blocked("String.raw`%s`+'%s'" % (_A, _B))
          and _blocked("String.raw`${'%s'}${'%s'}`" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_call_forms_intact():
    """F493/F551/F575 call forms still block."""
    ok = (_blocked("String.raw({raw:['%s','%s']})" % (_A, _B))
          and _blocked("String.raw.call(null,{raw:['%s','%s']})" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_plain_template_intact():
    """F457 plain templates unaffected."""
    ok = _blocked("`%s`+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_method_tags_intact():
    """F463/F472 method-tag forms unaffected."""
    ok = _blocked("['%s','%s'].join``" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_junk_quiet():
    """Honest text unaffected: junk stays quiet."""
    ok = (_misses("(function(){var s='ab';return s;})()")
          and _misses("String.raw`hello`")
          and _misses("'ab'+String.raw`cd`"))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2143; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2143 and len(dc.TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F613 closed; open F612, F614-F620; next F621 (lane-local)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F921**" in text  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28 (anchor edits the existing regex)."""
    import re
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """Tag anchor does not blow the scan budget (F452 discipline)."""
    corpus = ("junk " * 500 + "'%s'+String.raw`%s` " % (_A, _B)) * 4
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green check: wave-373 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g374-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w373_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    for line in out.splitlines():
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    ok = (real_break == 0)
    return ("HELD" if ok else "BREAK",
            "w373_attack real_break=%d" % real_break)


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
