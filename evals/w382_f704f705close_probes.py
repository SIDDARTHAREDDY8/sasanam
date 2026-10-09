#!/usr/bin/env python3
"""Wave-382 lane 3: close F704 + F705 (object-creation and Reflect residuals).

F704 (LOW; filed 2026-10-08 by wave-381 lane 8, attack round 49):
Object.create with property-descriptor map accessors bypasses the
bounded static JS-expression decoder -- the decoder models
Object.create prototype reads via the F548 chain (F673) but not
descriptor-map accessors:
  (function(){var o=Object.create(null,{x:{get:function(){return 'f1';}}});
  return o.x+'f2';})()
and the Object.prototype twin both node-evaluate to the exact
credential (node v24.20.0) while the decoder produces zero variants.
Distinct from F673 (prototype reads).

F705 (LOW; filed 2026-10-08 by wave-381 lane 8, attack round 49):
Reflect.get with receiver bypasses the decoder -- no Reflect.get
production for var-bound targets:
  (function(){var o={get x(){return 'f1';}};
  return Reflect.get(o,'x',{})+'f2';})()
and the two-arg twin both node-evaluate to the exact credential
while the decoder produces zero variants. Distinct from F674
(explicit this-bound reads, which blocks) and F698 (descriptor .get()).

Fix (gov/dlp.py, zero new re.compile):
- _js_parse_f548_props_object: `get` descriptors now install a
  _JSAccessor (the getter's return was already evaluated at parse
  time; this-dependent bodies fail closed there, so read-time
  invocation is argument-independent, node-exact). The F699
  _js_str_is_unsafe_int guard applies (F664/F691 parity);
  set-only descriptors still fail closed (F550 parity).
- _js_parse_f548_object_create: `Object.prototype` accepted as
  PROTO (modeled as an empty proto -- its members are functions,
  never string-decodable, so reads fail closed, node-exact).
- _js_parse_f704_create_accessor_iife (hooked after F673):
  `(function(){DECL o=Object.create(PROTO,PROPS);return ADD;})()`
  -- the var binds the F548 create result; the return is a
  +-joined additive of literals and member reads on the bound
  ident (F671 member-term discipline); unsafe-int member values
  fail closed at read time (F711 parity).
- _js_parse_f705_reflect_get_iife (hooked after F674):
  `(function(){DECL o=OBJLIT;return ADD;})()` where the additive
  carries `Reflect.get(o,'KEY')` / `Reflect.get(o,'KEY',{})`
  terms -- the object is parsed accessor-aware (this-dependent
  getters fail closed at parse, so every _JSAccessor is provably
  receiver-independent); data values decode, missing keys /
  non-literal keys / non-`{}` receivers fail closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
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


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f704_filed_null():
    """F704 filed shape 1 blocks."""
    p = ("(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});"
         "return o.x+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "filed-null")


@_t
def test_p1_f704_filed_proto():
    """F704 filed shape 2 blocks."""
    p = ("(function(){var o=Object.create(Object.prototype,{x:{enumerable:true,"
         "get:function(){return '%s';}}});return o.x+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "filed-proto")


@_t
def test_p1_f705_filed_receiver():
    """F705 filed shape 1 blocks."""
    p = ("(function(){var o={get x(){return '%s';}};"
         "return Reflect.get(o,'x',{})+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "filed-receiver")


@_t
def test_p1_f705_filed_plain():
    """F705 filed shape 2 blocks."""
    p = ("(function(){var o={get x(){return '%s';}};"
         "return Reflect.get(o,'x')+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "filed-plain")


# ------------------------------------------------ p2: variants (must block, node-exact)


@_t
def test_p2_f704_inline():
    """F704 inline (non-var-bound) twin blocks."""
    p = ("Object.create(null,{x:{get:function(){return '%s';}}}).x+'%s'") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "inline")


@_t
def test_p2_f704_arrow():
    """F704 arrow getter twins block."""
    ps = [("Object.create(null,{x:{get:()=>'%s'}}).x+'%s'") % (_A, _B),
          ("Object.create(null,{x:{get:()=>{return '%s';}}}).x+'%s'") % (_A, _B)]
    bad = [p for p in ps if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


@_t
def test_p2_f704_multi_descriptor():
    """F704 multi-descriptor (get + value) blocks."""
    p = ("(function(){var o=Object.create(null,{x:{get:function(){return '%s';}},"
         "y:{value:'%s'}});return o.x+o.y;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "multi")


@_t
def test_p2_f704_proto_chain():
    """F704 create over a literal proto blocks."""
    p = ("Object.create({p:'zz'},{x:{get:function(){return '%s';}}}).x+'%s'") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "proto-chain")


@_t
def test_p2_f704_bracket_optchain():
    """F704 bracket and ?. reads block."""
    ps = [("(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});"
           "return o['x']+'%s';})()") % (_A, _B),
          ("(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});"
           "return o?.x+'%s';})()") % (_A, _B)]
    bad = [p for p in ps if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


@_t
def test_p2_f704_ws_let():
    """F704 ws/let twins block."""
    ps = [("Object . create ( null , { x : { get : function ( ) { return '%s' ; } } } ) . x + '%s'") % (_A, _B),
          ("(function(){let o=Object.create(null,{x:{get:function(){return '%s';}}});return o.x+'%s';})()") % (_A, _B)]
    bad = [p for p in ps if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


@_t
def test_p2_f705_data_property():
    """F705 data-property target blocks."""
    p = ("(function(){var o={x:'%s'};return Reflect.get(o,'x')+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "data")


@_t
def test_p2_f705_bracket_key():
    """F705 bracket-string key blocks."""
    p = ("(function(){var o={get x(){return '%s';}};return Reflect.get(o,['x'])+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "bracket-key")


@_t
def test_p2_f705_multi_term():
    """F705 multi-term additive blocks."""
    p = ("(function(){var o={get x(){return '%s';},get y(){return '%s';}};"
         "return Reflect.get(o,'x')+Reflect.get(o,'y');})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "multi-term")


@_t
def test_p2_f705_named_getter():
    """F705 named getter blocks."""
    p = ("(function(){var o={get x(){return '%s';}};return Reflect.get(o,'x')+'%s';})()") % (_A, _B)
    # named function-expression getter in descriptor position
    p2 = ("(function(){var o=Object.create(null,{x:{get:function g(){return '%s';}}});"
          "return o.x+'%s';})()") % (_A, _B)
    bad = [q for q in (p, p2) if not _blocked(q)]
    return ("HELD" if not bad else "BREAK", "n=2")


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f704_set_only():
    """F704 set-only descriptor stays fail-closed."""
    p = "Object.create({},{c:{set:function(v){}}}).c+'%s'" % _B
    return ("HELD" if _misses(p) else "BREAK", "set-only")


@_t
def test_p3_f704_get_writable():
    """F704 get+writable (engine throws) stays fail-closed."""
    p = ("Object.create({},{c:{get:function(){return '%s';},writable:true}}).c+'%s'") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "get-writable")


@_t
def test_p3_f704_get_set_both():
    """F704 get+set together stays fail-closed (documented)."""
    p = ("Object.create(null,{x:{get:function(){return '%s';},set:function(v){}}}).x+'%s'") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "get-set")


@_t
def test_p3_f704_proto_key():
    """F704 __proto__ descriptor key stays fail-closed."""
    p = ("Object.create(null,{__proto__:{get:function(){return '%s';}}}).x+'%s'") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "proto-key")


@_t
def test_p3_f704_bracket_head():
    """F704 Object['create'] stays fail-closed (documented)."""
    p = ("Object['create'](null,{x:{get:function(){return '%s';}}}).x+'%s'") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "bracket-head")


@_t
def test_p3_f704_this_getter():
    """F704 this-dependent getter stays fail-closed."""
    p = "Object.create(null,{x:{get:function(){return this.y;}}}).x+'%s'" % _B
    return ("HELD" if _misses(p) else "BREAK", "this-getter")


@_t
def test_p3_f704_unsafe_int():
    """F704 unsafe-int member values stay fail-closed (F711 parity)."""
    ps = [("Object.create(null,{x:{get:function(){return 9007199254740993;}}}).x+'%s'") % _B,
          ("(function(){var o=Object.create(null,{x:{value:9007199254740993}});"
           "return o.x+'%s';})()") % _B]
    bad = [p for p in ps if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


@_t
def test_p3_f704_missing_key():
    """F704 missing key stays fail-closed."""
    p = ("(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});"
         "return o.z+'%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "missing-key")


@_t
def test_p3_f705_missing_key():
    """F705 missing key stays fail-closed."""
    p = ("(function(){var o={get x(){return '%s';}};return Reflect.get(o,'z')+'%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "missing-key")


@_t
def test_p3_f705_wrong_target():
    """F705 unbound target stays fail-closed."""
    p = ("(function(){var o={get x(){return '%s';}};return Reflect.get(p,'x')+'%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "wrong-target")


@_t
def test_p3_f705_this_getter():
    """F705 this-dependent getter stays fail-closed."""
    p = ("(function(){var o={get x(){return this.y;},y:'%s'};"
         "return Reflect.get(o,'x',{})+'%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "this-getter")


@_t
def test_p3_f705_nonempty_receiver():
    """F705 non-{} receiver stays fail-closed (documented)."""
    p = ("(function(){var o={get x(){return '%s';}};"
         "return Reflect.get(o,'x',{a:1})+'%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "nonempty-recv")


@_t
def test_p3_f705_bracket_head():
    """F705 Reflect['get'] stays fail-closed (documented)."""
    p = ("(function(){var o={get x(){return '%s';}};"
         "return Reflect['get'](o,'x')+'%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "bracket-head")


@_t
def test_p3_f705_unsafe_int():
    """F705 unsafe-int values stay fail-closed (F699 parity)."""
    p = ("(function(){var o={x:9007199254740993};"
         "return Reflect.get(o,'x')+'%s';})()") % _B
    return ("HELD" if _misses(p) else "BREAK", "unsafe-int")


@_t
def test_p3_f705_nonstring_value():
    """F705 non-string values stay fail-closed."""
    p = ("(function(){var o={x:{y:'%s'}};return Reflect.get(o,'x')+'%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "nonstring")


@_t
def test_p3_f705_shape_bounds():
    """F705 shape bounds (named fn, extra stmt, call args) stay fail-closed."""
    ps = [("(function f(){var o={get x(){return '%s';}};"
           "return Reflect.get(o,'x')+'%s';})()") % (_A, _B),
          ("(function(){var o={get x(){return '%s';}};var z=1;"
           "return Reflect.get(o,'x')+'%s';})()") % (_A, _B),
          ("(function(){var o={get x(){return '%s';}};"
           "return Reflect.get(o,'x')+'%s';})(1)") % (_A, _B)]
    bad = [p for p in ps if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


# ------------------------------------------------ p4: siblings still hold


@_t
def test_p4_siblings_hold():
    """F548/F549/F550/F664/F691/F698/F673/F674/F671 spot checks still block."""
    ps = ["Object.create({c:'%s'}).c+'%s'" % (_A, _B),
          "Object.getOwnPropertyDescriptor({c:'%s'},'c').value+'%s'" % (_A, _B),
          "Object.defineProperty({},'c',{get:function(){return '%s';}}).c+'%s'" % (_A, _B),
          ("(function(){var o={get x(){return '%s';}};"
           "return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()") % (_A, _B),
          ("(function(){var o={};Object.defineProperty(o,'x',{value:'%s'});"
           "return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()") % (_A, _B),
          ("(function(){var o={x:'%s'};return o.x+'%s';})()") % (_A, _B)]
    bad = [p for p in ps if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


# ------------------------------------------------ p5: open neighbors still miss


@_t
def test_p5_open_neighbors_miss():
    """F706/F708/F710 now CLOSED by sibling lanes (merge): their shapes block coded."""
    ps = ["(function(){var s=new Set(['k']);var f=s.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B),
          "(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de){tr[pr]='%s';return true;}});Object.defineProperty(p,'x',{value:1});return t.x+'%s';})()" % (_A, _B),
          "(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B)]
    bad = [p for p in ps if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


# ------------------------------------------------ p6: junk quiet / composition


@_t
def test_p6_junk_quiet():
    """Junk stays quiet; honest composition unaffected."""
    ps = ["'(function(){var s=\\'ab\\' ;return s;})()'",
          "Object.create({c:'zz'}).c+'yy'"]
    bad = [p for p in ps if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "n=%d" % len(ps))


# ------------------------------------------------ p7: pin, footer, no new regexes


@_t
def test_p7_pin_footer():
    """Pin 2143; lane-local footer (open F700-F703, F706-F712 / next F713)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F921**" in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p7_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p8: perf


@_t
def test_p8_perf():
    """200 mixed F704/F705 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var o=Object.create(null,{x:{get:function(){return 'x%d';}}});"
                      "return o.x;})()" % k)
        corpus.append("(function(){var o={get x(){return 'x%d';}};"
                      "return Reflect.get(o,'x');})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p9: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w381_f704_redfirst.py", 0),
                               ("evals/w381_f705_redfirst.py", 0),
                               ("evals/w381_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
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
def test_p9_green_check():
    """Depth-1 green check: F704/F705 red-firsts + wave-381 attack battery."""
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
