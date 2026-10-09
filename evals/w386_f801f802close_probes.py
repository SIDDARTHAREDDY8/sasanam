#!/usr/bin/env python3
"""Wave-386 lane 4: close F801 + F802 (Reflect.apply on named function
declarations; flat/flatMap on var-bound arrays).

F801 (LOW; filed 2026-10-09 by wave-385 lane 13, attack round 53):
Reflect.apply reads -- F614 (CLOSED, wave-373) covers .call/.apply/.bind
on function-expression receivers and _js_parse_reflect_apply_concat
(F469) covers Reflect.apply only for the Array.prototype.concat
target, but Reflect.apply on a named function declaration has no
production: Reflect.apply(f,null,[]) and Reflect.apply(f,null,['f1','f2'])
resolve node-exactly while the decoder produces zero variants.

F802 (LOW; filed 2026-10-09 by wave-385 lane 13, attack round 53):
array flat/flatMap reads -- the F574 flat/flatMap productions fire for
inline array literals, but on a var-bound array they miss: nested-array
flat() and flatMap(identity) resolve node-exactly while the decoder
produces zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F801: _js_parse_f801_reflect_apply_iife (hooked after F792) parses
  (function(){function NAME(params){return BODY;}return ADD;})()
  where ADD carries >=1 Reflect.apply(NAME,thisArg,[args]) term.
  Node-exact desugar (v24.20.0): Reflect.apply(f,t,args) is
  f.apply(t,args); the thisArg is parsed and discarded (modeled
  bodies never reference `this`, the F614 precedent); the argsArray
  is the F556 string-literal-only list; arity follows the F614
  precedent (shortfall fails closed, extras dropped). Dot, ?.
  (Reflect never nullish), and F504 bracket-string member twins.
- F802: _js_parse_f802_flat_varbound_iife (hooked after F801) parses
  (function(){DECL a=ARRLIT;return ADD;})() where each non-literal
  return term is a.<flat|flatMap>(...)[...] chain. The binding is
  resolved to its _JSArr and the native postfix chain
  (_js_parse_postfix) runs it -- flat/flatMap/join branches are
  already node-exact with documented fail-closed bounds (F466/F574).
  Disjoint: the first chain step must be flat/flatMap (F769 owns
  .at()); accepted chains never mutate the binding in the engine,
  so per-term resolution is engine-identical.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
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
def test_b0_footer_state():
    """Control: lane-local footer (F801/F802 closed; F829/F830/F831
    filed; next F832)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F832**" in text
          and "F795, F796, F797, F798, F799, F800, F803, F804, F805, "
              "F806, F807, F808, F809, F810, F811, F812, F813, F814, "
              "F815, F816, F817, F819, F820, F821, F822, F823, F824, "
              "F825, F826, F827, F828, F829, F830, F831." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f801_s1():
    """F801 filed shape 1 (Reflect.apply no-arg) blocks + exact."""
    s = ("(function(){function f(){return '" + _A + "';}"
         "return Reflect.apply(f,null,[])+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f801_s2():
    """F801 filed shape 2 (Reflect.apply with args) blocks + exact."""
    s = ("(function(){function f(a,b){return a+b;}"
         "return Reflect.apply(f,null,['" + _A + "','" + _B + "']);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f802_s1():
    """F802 filed shape 1 (var-bound flat) blocks + exact."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B + "']];"
         "return a.flat().join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f802_s2():
    """F802 filed shape 2 (var-bound flatMap) blocks + exact."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return a.flatMap(function(x){return [x];}).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f801_bracket():
    """Reflect['apply'] bracket twin blocks + exact."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect['apply'](f,null,['" + _A + "'])+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f801_optchain():
    """Reflect?.apply twin blocks + exact (Reflect never nullish)."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect?.apply(f,null,['" + _A + "'])+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f801_ws():
    """Whitespace-tolerant Reflect . apply blocks + exact."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect . apply ( f , null , ['" + _A + "'] )+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f801_extra_args():
    """Extra args beyond params are dropped engine-exactly."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect.apply(f,null,['" + _A + "','" + _B + "'])+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f801_semi():
    """Optional ; after the declaration blocks + exact."""
    s = ("(function(){function f(a){return a;};"
         "return Reflect.apply(f,null,['" + _A + "'])+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f801_obj_thisarg():
    """Object-literal thisArg fails closed (safe; the F614 precedent --
    _js_parse_ignored_value has no object-literal branch)."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect.apply(f,{x:1},['" + _A + "'])+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p2_f802_depth():
    """flat(2) on deeper nesting blocks + exact."""
    s = ("(function(){var a=[[['" + _A + "']],['" + _B + "']];"
         "return a.flat(2).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f802_infinity():
    """flat(Infinity) blocks + exact."""
    s = ("(function(){var a=[[['" + _A + "']],['" + _B + "']];"
         "return a.flat(Infinity).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f802_arrow_cb():
    """flatMap arrow twin x=>[x] blocks + exact."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return a.flatMap(x=>[x]).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f802_bracket():
    """a['flat']() bracket twin blocks + exact."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B + "']];"
         "return a['flat']().join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f802_let():
    """let-bound twin blocks + exact."""
    s = ("(function(){let a=[['" + _A + "'],['" + _B + "']];"
         "return a.flat().join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f802_multi_term():
    """Two flat terms in one additive both resolve."""
    s = ("(function(){var a=[['" + _A + "']];"
         "return a.flat().join('')+a.flatMap(x=>[x]).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f801_missing_args():
    """Reflect.apply(f,null) throws in the engine -> fail closed."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect.apply(f,null);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f801_nonarray_args():
    """Non-array argsArray throws in the engine -> fail closed."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect.apply(f,null,'" + _A + "');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f801_wrong_target():
    """Target ident != declared name -> fail closed."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect.apply(g,null,['" + _A + "']);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f801_arity():
    """Fewer args than params (F519 precedent) -> fail closed."""
    s = ("(function(){function f(a,b){return a+b;}"
         "return Reflect.apply(f,null,['" + _A + "']);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f801_this_body():
    """this-reading body is F782's domain -> fail closed here."""
    s = ("(function(){function f(){return this.x;}"
         "return Reflect.apply(f,{x:'" + _A + "'},[]);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f801_generator():
    """Generator declaration -> fail closed."""
    s = ("(function(){function* f(){yield '" + _A + "';}"
         "return Reflect.apply(f,null,[]);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f801_non_return_use():
    """Dispatch bound to a var, not in return -> fail closed."""
    s = ("(function(){function f(a){return a;}"
         "var x=Reflect.apply(f,null,['" + _A + "']);return x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f801_construct():
    """Reflect.construct is a different builtin -> fail closed."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect.construct(f,['" + _A + "']);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f802_neg_depth():
    """flat(-1): native F574 boundary -> fail closed."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B + "']];"
         "return a.flat(-1).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f802_hole():
    """Holes fail closed (F574 boundary)."""
    s = ("(function(){var a=[['" + _A + "'],,['" + _B + "']];"
         "return a.flat().join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f802_nonstr():
    """Numeric elements fail closed (strict validator)."""
    s = ("(function(){var a=[['" + _A + "'],[42]];"
         "return a.flat().join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f802_no_join():
    """Bare a.flat() yields an array, not a string variant."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B + "']];"
         "return a.flat();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f802_unbound():
    """Read of an unbound ident -> fail closed."""
    s = ("(function(){var a=[['" + _A + "']];"
         "return b.flat().join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f802_nonflat_first():
    """Non-flat first method stays with earlier routes (disjoint)."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return a.reverse().join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings (must stay HELD)


@_t
def test_p4_sibling_f782():
    """F782 filed shape (thisArg call on declaration) still blocks."""
    s = ("(function(){function f(){return this.x;}"
         "return f.call({x:'" + _A + "'})+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f769():
    """F769 var-bound .at() still blocks (disjoint)."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return a.at(0)+a.at(1);})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_inline_flat():
    """F574 inline flat still blocks."""
    s = "[['" + _A + "'],['" + _B + "']].flat().join('')"
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_concat_reflect():
    """F469 Reflect.apply(Array.prototype.concat,...) still blocks."""
    s = ("Reflect.apply(Array.prototype.concat,['" + _A + "'],"
         "[['" + _B + "']]).join('')")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_neighbor_f800_open():
    """F800 (Proxy get-trap residuals) still misses -- not absorbed."""
    s = ("(function(){var p=new Proxy({},{get:function(t,k)"
         "{return '" + _A + "';}});return p.anything+'" + _B + "';})()")
    ok = not _blocked(s)
    return ("HELD" if ok else "BREAK", "still-open=%s" % ok)


@_t
def test_p4_neighbor_f803_open():
    """F803 (var-bound method-call results) still misses -- not absorbed."""
    s = ("(function(){var s='" + _A + "'.repeat(1);"
         "return s+'" + _B + "';})()")
    ok = not _blocked(s)
    return ("HELD" if ok else "BREAK", "still-open=%s" % ok)


# ------------------------------------------------ p5: honest text quiet


@_t
def test_p5_junk_quiet():
    """Junk control stays quiet."""
    ok = not _blocked("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_reflect():
    """Honest Reflect.apply on a non-credential stays quiet."""
    s = ("(function(){function f(a){return a;}"
         "return Reflect.apply(f,null,['ok']);})()")
    ok = not _blocked(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_flat():
    """Honest flat().join('') on non-credentials stays quiet."""
    s = ("(function(){var a=[['x'],['y']];return a.flat().join('');})()")
    ok = not _blocked(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){function f(a){return a;}"
            "return Reflect.apply(f,null,['a%d']);})()" % k)
        sites.append(
            "(function(){var a=[['b%d'],['c%d']];"
            "return a.flat().join('');})()" % (k, k))
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
    # The two red-firsts must be 0 BREAK (F801/F802 closed); the
    # wave-385 attack battery is expected to report exactly 5 BREAK:
    # its test_b0_footer_state asserts the base footer (lane-local
    # footer differs -- merge-owned, wave-305 lesson) and its four
    # test_r53_f801/f802_*_open tests assert F801/F802 are OPEN --
    # this lane closed them, so those four now (correctly) report
    # miss=False. All functional probes must HELD.
    for batt, expect_break in (("evals/w386_f801_redfirst.py", 0),
                               ("evals/w386_f802_redfirst.py", 0),
                               ("evals/w385_attack_probes.py", 5)):
        tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
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
    """Depth-1 green check: both red-firsts 0 BREAK + wave-385 attack
    battery 5 BREAK (1 footer pin, lane-local/merge-owned, + 4
    F801/F802 shapes this lane closed)."""
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
