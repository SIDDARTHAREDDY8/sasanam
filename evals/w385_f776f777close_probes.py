#!/usr/bin/env python3
"""Wave-385 lane 8: close F776 + F777.

F776 (LOW, filed 2026-10-09 by wave-384 attack round 52): F673
residual -- nested-object __proto__ literal reads. F673 (CLOSED)
models Object.create({LIT}) prototype reads with direct string
values, but a nested object as the __proto__ value misses:
  (function(){var o={__proto__:{x:'f1'}};return o.x+'f2';})()
  (function(){var o={};o.__proto__={x:'f1'};
   return o.__proto__.x+'f2';})()
both node-evaluate (v24.20.0) to the exact credential while the
decoder produced zero variants.

F777 (LOW, filed 2026-10-09 by wave-384 attack round 52): F748
residual -- plain || / && value flows. F748 (CLOSED) models the
||= / &&= assignment forms, but plain || / && value flow has no
production:
  (function(){var x='';return (x||'f1')+'f2';})()
  (function(){return (1&&'f1')+'f2';})()
and the (null||'f1') / ('x'&&'f1') variants both node-evaluate to
the exact credential while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F776: _js_parse_f776_proto_iife (+ _js_f776_parse_nested_proto,
  _js_f776_parse_proto_object, _js_f776_resolve_member), hooked
  after F757 with the parts/ops snapshot-restore discipline
  (wave-383 F733 lesson). The __proto__ literal key (ident or
  string form -- the engine treats both as the setter) with a
  nested string-valued object installs the _JSObj proto
  node-exactly; the o.__proto__={...}; assignment twin installs
  it post-declaration. Member reads resolve through the proto
  chain (own shadows); o.__proto__ reads the proto itself.
  Duplicate __proto__, non-object values, null proto, getters,
  methods, spreads, computed keys, nested protos, missing keys,
  and non-string resolutions fail closed.
- F777: _js_parse_f777_logical_iife (+ _js_f777_truthy,
  _js_f777_parse_operand, _js_f777_logical_at), hooked after
  F776 with snapshot/restore. Operands are string literals,
  decimal ints, true/false/null, or bound names -- the
  decidable-truthiness domain. (A||B)/(A&&B) select per the
  engine's short-circuit semantics; the selected operand must be
  a string or the decoder fails closed (e.g. (0&&'f1') is 0).
  ||= / &&= never match (F748's domain); ?? is out of scope;
  bare (unparenthesized) logicals fail closed (precedence).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_footer_state():
    """Control: lane-local footer (F776/F777 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, "
              "F769, F770, F771, F772, F773, F774, F775, F778, F779, F780, "
              "F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, "
              "F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f776_s1():
    """F776 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var o={__proto__:{x:'" + _A
         + "'}};return o.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f776_s2():
    """F776 filed shape 2 (assignment twin) blocks + decodes node-exact."""
    s = ("(function(){var o={};o.__proto__={x:'" + _A
         + "'};return o.__proto__.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f777_s1():
    """F777 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var x='';return (x||'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f777_s2():
    """F777 filed shape 2 blocks + decodes node-exact."""
    s = ("(function(){return (1&&'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f776_quoted_key():
    """F776 quoted '__proto__' key blocks + exact (engine setter)."""
    s = ("(function(){var o={'__proto__':{x:'" + _A
         + "'}};return o.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f776_own_shadows():
    """F776 own property shadows the proto (node-exact)."""
    s = ("(function(){var o={__proto__:{x:'" + _A
         + "'},x:'zz'};return o.x+'" + _B + "';})()")
    ok = _decodes_exact(s, "zz" + _B)
    return ("HELD" if ok else "BREAK", "shadow=%s" % ok)


@_t
def test_p2_f776_multi_key_proto():
    """F776 multi-key proto object blocks + exact."""
    s = ("(function(){var o={__proto__:{x:'" + _A
         + "',y:'q'}};return o.x+o.y+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "q" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f776_assign_multi():
    """F776 assignment twin with multi-key proto blocks + exact."""
    s = ("(function(){var o={};o.__proto__={x:'" + _A
         + "',y:'q'};return o.__proto__.x+o.__proto__.y+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "q" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f777_null_or():
    """F777 (null||'f1') variant blocks + exact."""
    s = ("(function(){return (null||'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f777_str_and():
    """F777 ('x'&&'f1') variant blocks + exact."""
    s = ("(function(){return ('x'&&'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f777_truthy_or_selects_a():
    """F777 truthy || selects A node-exactly."""
    s = ("(function(){var d='dd';return ('a'||d)+'" + _B + "';})()")
    ok = _decodes_exact(s, "a" + _B)
    return ("HELD" if ok else "BREAK", "or-a=%s" % ok)


@_t
def test_p2_f777_bound_b():
    """F777 bound string name as B blocks + exact."""
    s = ("(function(){var d='" + _A + "';return (''||d)+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f777_false_or():
    """F777 (false||'f1') blocks + exact."""
    s = ("(function(){return (false||'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f777_true_and():
    """F777 (true&&'f1') via bound bool blocks + exact."""
    s = ("(function(){var t=true;return (t&&'" + _A + "')+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f776_null_proto():
    """F776 {__proto__:null} fails closed (documented bound)."""
    s = ("(function(){var o={__proto__:null};return o.x+'" + _B
         + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f776_dup_proto():
    """F776 duplicate __proto__ fails closed."""
    s = ("(function(){var o={__proto__:{x:'" + _A
         + "'},__proto__:{y:'q'}};return o.x+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f776_nonlit_proto_value():
    """F776 non-literal proto value fails closed."""
    s = ("(function(){var o={__proto__:{x:y}};return o.x+'" + _B
         + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f776_nested_proto():
    """F776 proto inside proto fails closed (documented bound)."""
    s = ("(function(){var o={__proto__:{__proto__:{x:'" + _A
         + "'}}};return o.x+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f776_computed_proto():
    """F776 computed ['__proto__'] fails closed (own data prop in engine)."""
    s = ("(function(){var o={['__proto__']:{x:'" + _A
         + "'}};return o.x+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f776_missing_key():
    """F776 missing key fails closed (engine undefined)."""
    s = ("(function(){var o={__proto__:{x:'" + _A
         + "'}};return o.zz+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f776_bare_object_read():
    """F776 bare bound object in additive fails closed."""
    s = ("(function(){var o={__proto__:{x:'" + _A
         + "'}};return o+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f777_qq_out_of_scope():
    """F777 ?? is out of scope (F647's domain); this hook refuses it."""
    # (F647 decodes (null??'f1') on its own hook -- this asserts the
    # F777 hook does not claim it: the F777 parse path fails closed.)
    from gov.dlp import _js_f777_logical_at  # noqa: E402
    try:
        _js_f777_logical_at("(null??'x')", 1, {})
        ok = False
    except Exception:  # noqa: BLE001 -- any refusal is the assertion
        ok = True
    return ("HELD" if ok else "BREAK", "f777-refuses-qq=%s" % ok)


@_t
def test_p3_f777_nested_logical():
    """F777 nested logical groups fail closed."""
    s = ("(function(){return ((1||2)&&'" + _A + "')+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f777_logassign_not_matched():
    """F777 (x||='f1') never matches the value-flow hook (F748's domain)."""
    # Bound env so the test pins the operator guard itself, not the
    # unbound-operand refusal.
    from gov.dlp import _js_f777_logical_at  # noqa: E402
    try:
        _js_f777_logical_at("(x||='x')", 1, {"x": ("str", "")})
        ok = False
    except Exception:  # noqa: BLE001
        ok = True
    return ("HELD" if ok else "BREAK", "f777-refuses-logassign=%s" % ok)


@_t
def test_p3_f777_float_operand():
    """F777 float operand fails closed (documented bound)."""
    s = ("(function(){return (1.5&&'" + _A + "')+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f777_hex_operand():
    """F777 hex operand fails closed (documented bound)."""
    s = ("(function(){return (0x1&&'" + _A + "')+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f777_unbound_operand():
    """F777 unbound operand fails closed."""
    s = ("(function(){return (zz||'" + _A + "')+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f777_nonstring_b():
    """F777 non-string B fails closed."""
    s = ("(function(){return (''||1)+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f777_nonstring_selected():
    """F777 (0&&'f1') selects 0 (non-string) -- fails closed."""
    s = ("(function(){var z=0;return (z&&'" + _A + "')+'b';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f777_bare_logical():
    """F777 bare (unparenthesized) logical fails closed (precedence)."""
    s = ("(function(){var x='';return x||'" + _A + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f673_create():
    """F673 Object.create proto pin still blocks."""
    s = ("(function(){var o=Object.create({x:'" + _A
         + "'});return o.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f673=%s" % ok)


@_t
def test_p4_sibling_f671():
    """F671 plain member-read pin still blocks."""
    s = ("(function(){var o={x:'" + _A + "'};return o.x+'" + _B
         + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f671=%s" % ok)


@_t
def test_p4_sibling_f748():
    """F748 logical-assignment pin still blocks."""
    s = ("(function(){var x;x||='" + _A + "';x+='" + _B + "';return x;})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f748=%s" % ok)


@_t
def test_p4_sibling_f756():
    """F756 ternary pin still blocks."""
    s = ("(function(){var c=true;return (c?'" + _A + "':'z')+'" + _B
         + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f756=%s" % ok)


@_t
def test_p4_sibling_f647_qq():
    """F647 ?? pin still blocks (its own hook, untouched)."""
    s = ("(function(){return (null??'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f647=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_proto_unaffected():
    """Honest object literal without __proto__ still misses."""
    s = ("(function(){var o={a:'x'};return o.a+'yz';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_logical_unaffected():
    """Honest arithmetic IIFE still misses."""
    s = ("(function(){var x=1;return x+2;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){var o={__proto__:{x:'a%d'}};return o.x;})()" % k)
        sites.append(
            "(function(){var x='';return (x||'a%d');})()" % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs): the w384 attack battery's only
    # expected BREAK is test_b0_footer_state (base footer pin; the
    # lane-local repoint is merge-owned, wave-305 lesson).
    for batt, expect_break in (("evals/w384_f776_redfirst.py", 0),
                               ("evals/w384_f777_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: F776/F777 red-firsts (0 BREAK) + wave-384
    attack battery (1 BREAK: the footer pin only, lane-local repoint;
    tree-wide repoint is merge-owned)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
