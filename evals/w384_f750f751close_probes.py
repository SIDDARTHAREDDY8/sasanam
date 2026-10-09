#!/usr/bin/env python3
"""Wave-384 lane 7: close F750 + F751 (Error .message reads; ownKeys/keys map-reads).

F750 (LOW, filed 2026-10-08 21:09 UTC by wave-383 lane 14 as F748,
renumbered at the wave-383 merge -- lane 6 filed F738/F739 first
~17:30/~17:45 UTC): the decoder had no Error-object production, so a
thrown/caught Error's .message (including subclasses) carried the
fragment node-exactly while the decoder produced zero variants:
(function(){try{throw new Error('f1');}catch(e){return e.message+'f2';}})()
and (function(){function f(){throw new RangeError('f1');}try{f();}
catch(e){return e.message+'f2';}})() both node-evaluate to the exact
credential (node v24.20.0). Controls: junk-quiet control passes.

F751 (LOW, filed 2026-10-08 21:09 UTC by wave-383 lane 14 as F749,
renumbered at the wave-383 merge): F579 (CLOSED) models
Reflect.ownKeys ORDER but not key-iteration reads:
(function(){var o={x:'f1',y:'f2'};return Reflect.ownKeys(o)
.map(function(k){return o[k];}).join('');})() and
(function(){var o={};o.x='f1';o.y='f2';var s='';
Reflect.ownKeys(o).forEach(function(k){s+=o[k];});return s;})()
both node-evaluate to the exact credential (node v24.20.0).
Controls: junk-quiet control passes.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f750_error_message_iife (+ _js_f750_parse_error_new,
  _js_f750_parse_predecl, _js_f750_parse_throw_stmt,
  _js_f750_parse_msg_additive): `PRE* try{THROW}catch(C){return
  RET;}` where PRE declares error-valued bindings or thrower
  functions, THROW is `throw [new] CTOR('LIT'|);` / `throw X;` /
  `F();`, and RET is a `C.message` / `C['message']` additive.
  Hooked after F679; disjoint (F679 has no Error production;
  red-first verified: 2 BREAK on the open tree).
- _js_parse_f751_ownkeys_map_iife (+ _js_f751_parse_obj_binding,
  _js_f751_parse_key_head, _js_f751_parse_map_cb,
  _js_f751_parse_foreach_cb, _js_f751_parse_accum,
  _js_f751_parse_oread, _js_f751_is_intkey): the object binding
  (literal + literal-valued mutations, engine-exact key order)
  then the `.map(...).join(SEP)` return or the forEach
  accumulation twin. Hooked after F750; disjoint from F579 (which
  resolves only the bracket-index key form; red-first verified:
  2 BREAK on the open tree).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Wave-385: pin 2143 -> 2144
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile

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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "junk=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f750_s1():
    """F750 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){try{throw new Error('%s');}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f750-s1=%s" % ok)


@_t
def test_p1_f750_s2():
    """F750 filed shape 2 (thrower function) blocks."""
    ok = _blocked(
        "(function(){function f(){throw new RangeError('%s');}"
        "try{f();}catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f750-s2=%s" % ok)


@_t
def test_p1_f751_s1():
    """F751 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s',y:'%s'};"
        "return Reflect.ownKeys(o).map(function(k){return o[k];})"
        ".join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f751-s1=%s" % ok)


@_t
def test_p1_f751_s2():
    """F751 filed shape 2 (forEach accumulation) blocks."""
    ok = _blocked(
        "(function(){var o={};o.x='%s';o.y='%s';var s='';"
        "Reflect.ownKeys(o).forEach(function(k){s+=o[k];});"
        "return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f751-s2=%s" % ok)


# ------------------------------------------------------------- variants p2

@_t
def test_p2_f750_nonew():
    """Error() without new decodes node-exactly."""
    ok = _blocked(
        "(function(){try{throw Error('%s');}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonew=%s" % ok)


@_t
def test_p2_f750_subclass():
    """TypeError subclass decodes node-exactly."""
    ok = _blocked(
        "(function(){try{throw new TypeError('%s');}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "subclass=%s" % ok)


@_t
def test_p2_f750_bracket():
    """e['message'] bracket read decodes node-exactly."""
    ok = _blocked(
        "(function(){try{throw new Error('%s');}"
        "catch(e){return e['message']+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p2_f750_varbound():
    """Var-bound error throw decodes node-exactly."""
    ok = _blocked(
        "(function(){var x=new Error('%s');try{throw x;}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "varbound=%s" % ok)


@_t
def test_p2_f750_multimsg():
    """Two .message reads decode node-exactly (value-level)."""
    r = dlp._js_parse_f750_error_message_iife(
        "(function(){try{throw new EvalError('%s');}"
        "catch(e){return e.message+'-'+e.message;}})()" % (_A,),
        0, 0, {"parts": 0, "ops": 0})
    ok = r is not None and r[0] == _A + "-" + _A
    return ("HELD" if ok else "BREAK", "multimsg=%s" % ok)


@_t
def test_p2_f751_objkeys():
    """Object.keys head decodes node-exactly."""
    ok = _blocked(
        "(function(){var o={x:'%s',y:'%s'};"
        "return Object.keys(o).map(function(k){return o[k];})"
        ".join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "objkeys=%s" % ok)


@_t
def test_p2_f751_arrow():
    """Arrow map callback decodes node-exactly."""
    ok = _blocked(
        "(function(){var o={x:'%s',y:'%s'};"
        "return Reflect.ownKeys(o).map(k=>o[k]).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "arrow=%s" % ok)


@_t
def test_p2_f751_mutation():
    """Literal + mutation object decodes node-exactly."""
    ok = _blocked(
        "(function(){var o={x:'%s'};o.y='%s';"
        "return Object.keys(o).map(k=>o[k]).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "mutation=%s" % ok)


@_t
def test_p2_f751_foreach_arrow():
    """Arrow forEach callback decodes node-exactly."""
    ok = _blocked(
        "(function(){var o={x:'%s',y:'%s'};var s='';"
        "Reflect.ownKeys(o).forEach(k=>{s+=o[k];});"
        "return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "foreach-arrow=%s" % ok)


@_t
def test_p2_f751_intkeys():
    """Integer keys enumerate numerically first (node-exact)."""
    ok = _blocked(
        "(function(){var o={1:'%s',0:'%s'};"
        "return Reflect.ownKeys(o).map(k=>o[k]).join('');})()" % (_B, _A))
    return ("HELD" if ok else "BREAK", "intkeys=%s" % ok)


# ---------------------------------------------------------------- bounds p3

@_t
def test_p3_f750_numeric_msg():
    """new Error(123) fails closed (engine coerces to '123')."""
    ok = _misses(
        "(function(){try{throw new Error(123);}"
        "catch(e){return e.message+'%s';}})()" % (_B,))
    return ("HELD" if ok else "BREAK", "numeric=%s" % ok)


@_t
def test_p3_f750_aggregate():
    """AggregateError (message is 2nd arg) fails closed."""
    ok = _misses(
        "(function(){try{throw new AggregateError(['x'],'%s');}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "aggregate=%s" % ok)


@_t
def test_p3_f750_custom_ctor():
    """Non-Error constructor fails closed."""
    ok = _misses(
        "(function(){try{throw new CustomError('%s');}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "custom=%s" % ok)


@_t
def test_p3_f750_stmt_before_throw():
    """Statements before the throw fail closed."""
    ok = _misses(
        "(function(){var q='zz';try{q='yy';throw new Error('%s');}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "stmt-before=%s" % ok)


@_t
def test_p3_f750_bare_e():
    """Bare `return e` (error object, not a string) fails closed."""
    ok = _misses(
        "(function(){try{throw new Error('xx');}catch(e){return e;}})()")
    return ("HELD" if ok else "BREAK", "bare-e=%s" % ok)


@_t
def test_p3_f750_estack():
    """Non-message member read fails closed."""
    ok = _misses(
        "(function(){try{throw new Error('xx');}"
        "catch(e){return e.stack;}})()")
    return ("HELD" if ok else "BREAK", "estack=%s" % ok)


@_t
def test_p3_f751_nonlit_val():
    """Non-literal object values fail closed."""
    ok = _misses(
        "(function(){var o={x:123};"
        "return Reflect.ownKeys(o).map(k=>o[k]).join('');})()")
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_f751_dot_read():
    """o.k literal read in the callback fails closed."""
    ok = _misses(
        "(function(){var o={x:'%s',y:'%s'};"
        "return Reflect.ownKeys(o).map(k=>o.x).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "dot-read=%s" % ok)


@_t
def test_p3_f751_bracketlit_read():
    """o['x'] literal read in the callback fails closed."""
    ok = _misses(
        "(function(){var o={x:'%s',y:'%s'};"
        "return Reflect.ownKeys(o).map(k=>o['x']).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracketlit=%s" % ok)


@_t
def test_p3_f751_accum_nonempty():
    """Non-empty accumulator initializer fails closed."""
    ok = _misses(
        "(function(){var o={x:'%s',y:'%s'};var s='q';"
        "Reflect.ownKeys(o).forEach(k=>{s+=o[k];});"
        "return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "accum-nonempty=%s" % ok)


@_t
def test_p3_f751_map_string():
    """Non-callback map argument fails closed."""
    ok = _misses(
        "(function(){var o={x:'%s',y:'%s'};"
        "return Reflect.ownKeys(o).map(String).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "map-string=%s" % ok)


@_t
def test_p3_f751_getter():
    """Getter-valued literal fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "return Reflect.ownKeys(o).map(k=>o[k]).join('');})()" % (_A,))
    return ("HELD" if ok else "BREAK", "getter=%s" % ok)


# --------------------------------------------------------------- neighbors p4

@_t
def test_p4_f679_intact():
    """F679 for-loop statement accumulation still blocks."""
    ok = _blocked(
        "(function(){var r='';for(var i=0;i<1;i++){r+='%s';r+='%s';}"
        "return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f679=%s" % ok)


@_t
def test_p4_f740_now_closed():
    """F740 (try/catch value flows) now blocks (closed wave-384 lane 2)."""
    ok = _blocked(
        "(function(){var r;try{throw '%s';}catch(e){r=e;}"
        "return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f740-closed=%s" % ok)


@_t
def test_p4_honest_text():
    """Honest text stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p5: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w383_f750_redfirst.py", 0),
                               ("evals/w383_f751_redfirst.py", 0),
                               ("evals/w383_attack_probes.py", 0)):
        # w383_attack: pins flipped + footer repointed lane-locally,
        # so 0 BREAK is expected here; the tree-wide repoint is
        # merge-owned (wave-305 lesson).
        tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
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
def test_p5_green_check():
    """Depth-1 green check: F750/F751 red-firsts + attack battery green."""
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