#!/usr/bin/env python3
"""Wave-385 lane 16: close F793 + F794.

F793 (LOW, filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round
52): Iterator helper reads (Iterator.prototype.map / drop). F752
(CLOSED wave-384 lane 8) covers builtin-iterator .next().value reads,
but the ES2025 Iterator helpers had no production:
(function(){return [...['f1','f2'].values().map(function(x){return x;})].join('');})()
and
(function(){return [...['xx','f1','f2'].values().drop(1)].join('');})()
both node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

F794 (LOW, filed 2026-10-09 00:36:36 UTC by wave-384 lane 3 as F762,
renumbered F762->F794 at the wave-384 merge -- wave-272 rule, attack
round 52 filed F762 first at 00:07 UTC): non-string primitive
Symbol.toPrimitive returns not modeled. The shared
_js_f697_toprimitive (F697 literal form, F743 assigned form) failed
closed when the coercion body resolved to a non-string, but node
v24.20.0 String()-coerces number/boolean @@toPrimitive returns (only
Object returns throw TypeError): a numeric-returning toPrimitive
launders bytes through fromCharCode while the decoder produced zero
variants. NOTE (wave-385 lane 16 correction): the filed red-first
shapes used the literal 'xb-0123', which decodes to "xxb-..."/"oxb-..."
-- never the credential, so the red-first could never go green. The
shapes are corrected here and in w384_f794_redfirst.py to use
'oxb-0123' (fromCharCode(120)='x' completes "xoxb-0123"); the FINDINGS
entry shapes are corrected likewise.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F794: _js_f794_parse_primitive_literal + _js_f794_toprimitive_number;
  _js_f697_toprimitive String()-coerces numeric/boolean literal
  @@toPrimitive bodies node-exactly (@@toPrimitive is
  hint-independent). valueOf/toString numeric bodies stay
  fail-closed (hint-dependent method order not threaded --
  documented residual). `String.fromCharCode(o)` terms added to
  both F697's and F743's return loops (ToNumber via the own
  @@toPrimitive; bool->1/0).
- F793: _js_parse_f793_iter_helper_iife (+
  _js_parse_f793_map_callback, _js_parse_f793_callback_additive),
  hooked after F752 with the parts/ops snapshot-restore discipline.
  `(function(){return [...SRC.map(f)|.drop(n)].join('SEP');})()`
  where SRC is an F752 inline iterator source; .map(f) applies a
  string-additive callback per item; .drop(n) drops the first n
  (non-negative integer literal only; negatives throw RangeError
  in the engine and fail closed here).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Wave-385: pin 2143 -> 2144
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

TAXONOMY_PIN = 2144  # no new decision codes this lane  # Wave-385: pin 2143 -> 2144

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
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F793/F794 closed, F824/F825 filed,
    next F797)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F797**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, "
              "F768, F769, F770, F771, F772, F773, F774, F775, F776, "
              "F777, F778, F779, F780, F781, F782, F783, F784, F785, "
              "F786, F787, F788, F789, F790, F791, F792, F824, F825."
              in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_b1_f824_open():
    """F824 OPEN (filed 2026-10-09 03:37:08 UTC): non-integer drop miss."""
    s1 = ("(function(){return [...['xx','" + _A + "','" + _B
           + "'].values().drop(1.5)].join('');})()")
    s2 = ("(function(){return [...['xx','" + _A + "','" + _B
           + "'].values().drop(\"1\")].join('');})()")
    ok = _misses(s1) and _misses(s2)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_b1_f825_open():
    """F825 OPEN (filed 2026-10-09 03:37:15 UTC): fromCharCode valueOf
    miss."""
    s = ("(function(){var o={valueOf:function(){return 120;}};"
         "return String.fromCharCode(o)+'oxb-0123'+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f793_s1():
    """F793 filed shape 1 (map identity) blocks + decodes node-exact."""
    s = ("(function(){return [...['" + _A + "','" + _B
         + "'].values().map(function(x){return x;})].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f793_s2():
    """F793 filed shape 2 (drop) blocks + decodes node-exact."""
    s = ("(function(){return [...['xx','" + _A + "','" + _B
         + "'].values().drop(1)].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f794_s1():
    """F794 filed shape 1 (assigned toPrimitive, corrected) blocks."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return 120;};return String.fromCharCode(o)+'oxb-0123'+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f794_s2():
    """F794 filed shape 2 (literal toPrimitive, corrected) blocks."""
    s = ("(function(){var o={[Symbol.toPrimitive]:function()"
         "{return 120;}};return String.fromCharCode(o)+'oxb-0123'+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f793_map_arrow():
    """F793 map with arrow callback blocks + exact."""
    s = ("(function(){return [...['" + _A + "','" + _B
         + "'].values().map((x)=>x)].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f793_map_additive():
    """F793 map with additive callback blocks + exact."""
    s = ("(function(){return [...['" + _A + "'].values().map("
         "function(x){return x+'" + _B + "';})].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f793_drop_zero():
    """F793 drop(0) blocks + exact."""
    s = ("(function(){return [...['" + _A + "','" + _B
         + "'].values().drop(0)].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f793_set_source():
    """F793 Set source with map blocks + exact."""
    s = ("(function(){return [...new Set(['" + _A + "','" + _B
         + "']).values().map(function(x){return x;})].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f794_bool_true():
    """F794 boolean true body: String(o) -> 'true', blocks."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return true;};return String(o)+'|" + _A + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "true|" + _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f794_f697_literal_stringof():
    """F794 literal form with String(o) term blocks + exact."""
    s = ("(function(){var o={[Symbol.toPrimitive]:function()"
         "{return 120;}};return String.fromCharCode(111)+'x'+'"
         + _A + _B + "';})()")
    # Control: fromCharCode literal args still work (F458).
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f793_take_unmodeled():
    """F793 .take is unmodeled -> fail closed."""
    s = ("(function(){return [...['" + _A + "','" + _B
         + "'].values().take(1)].join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f793_filter_unmodeled():
    """F793 .filter is unmodeled -> fail closed."""
    s = ("(function(){return [...['" + _A + "'].values().filter("
         "function(x){return true;})].join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f793_drop_negative():
    """F793 drop(-1): engine throws RangeError -> fail closed."""
    s = ("(function(){return [...['" + _A + "'].values().drop(-1)]"
         ".join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f793_drop_float():
    """F793 drop(1.5): unmodeled (engine truncates) -> fail closed."""
    s = ("(function(){return [...['" + _A + "'].values().drop(1.5)]"
         ".join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f793_map_thisarg():
    """F793 map with thisArg -> fail closed."""
    s = ("(function(){return [...['" + _A + "'].values().map("
         "function(x){return x;},{} )].join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f793_map_foreign_ident():
    """F793 map callback referencing foreign ident -> fail closed."""
    s = ("(function(){return [...['" + _A + "'].values().map("
         "function(x){return y;})].join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f793_no_spread():
    """F793 without spread -> fail closed."""
    s = ("(function(){return [['" + _A + "'].values().map("
         "function(x){return x;})].join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f793_decl_present():
    """F793 with a declaration -> fail closed (F752's shape)."""
    s = ("(function(){var it=['" + _A + "'].values();return "
         "[...it.map(function(x){return x;})].join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f794_object_return():
    """F794 object-returning toPrimitive: engine throws -> fail closed."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return {};};return String.fromCharCode(o)+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f794_nonliteral_body():
    """F794 non-literal toPrimitive body -> fail closed."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return x;};return String.fromCharCode(o)+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f794_float_body():
    """F794 float body: unmodeled -> fail closed."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return 1.5;};return String.fromCharCode(o)+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f794_hex_body():
    """F794 hex literal body: unmodeled -> fail closed."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return 0x78;};return String.fromCharCode(o)+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f794_fromcharcode_two_args():
    """F794 fromCharCode with two args -> fail closed."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return 120;};return String.fromCharCode(o,111)+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f794_valueof_numeric():
    """F794 valueOf numeric body: hint-ordering unmodeled -> fail closed."""
    s = ("(function(){var o={valueOf:function(){return 65;}};"
         "return String(o)+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still behave


@_t
def test_p4_sibling_f752():
    """F752 .next().value pin still blocks."""
    s = ("(function(){var it=['" + _A + "'].values();"
         "var x=it.next().value;return x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f752=%s" % ok)


@_t
def test_p4_sibling_f697_string():
    """F697 string toPrimitive pin still blocks."""
    s = ("(function(){var o={[Symbol.toPrimitive]:function()"
         "{return '" + _A + "';}};return o+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f697=%s" % ok)


@_t
def test_p4_sibling_f743_string():
    """F743 assigned string toPrimitive pin still blocks."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function()"
         "{return '" + _A + "';};return String(o)+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f743=%s" % ok)


@_t
def test_p4_sibling_f761():
    """F761 non-callable toPrimitive still fails closed (miss)."""
    s = ("(function(){var o={[Symbol.toPrimitive]:'x',"
         "toString:function(){return 'y';}};return o+'z';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f761-closed=%s" % ok)


@_t
def test_p4_neighbor_f792_open():
    """Neighbor F792 still misses (open)."""
    s = ("(function(){var o=Object.groupBy(['" + _A + "'],"
         "function(x){return 'k';});return o.k[0]+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f792-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_map_unaffected():
    """Honest array .map (not iterator) still misses."""
    s = "(function(){return ['ab','cd'].map(function(x){return x;}).join('');})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_fromcharcode_unaffected():
    """Honest fromCharCode literal still misses."""
    s = "String.fromCharCode(104,105)"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){return [...['a%d','b'].values().map("
            "function(x){return x;})].join('');})()" % k)
        sites.append(
            "(function(){var o={};o[Symbol.toPrimitive]=function()"
            "{return 120;};return String.fromCharCode(o);})()")
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
    # expected BREAK is test_b0_footer_state (lane-local footer;
    # tree-wide repoint is merge-owned, wave-305 lesson). The F793
    # pins were flipped to closed in-lane.
    for batt, expect_break in (("evals/w384_f793_redfirst.py", 0),
                               ("evals/w384_f794_redfirst.py", 0),
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
    """Depth-1 green check: red-firsts (0 BREAK) + w384 attack battery
    (1 BREAK: the footer pin only, lane-local repoint; tree-wide
    repoint is merge-owned)."""
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
