#!/usr/bin/env python3
"""Wave-383 lane 6: close F723 + F724 (prototype-chain getter reads).

F723 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
Object.create prototype-chain getter reads -- the decoder models
Object.create prototype reads via the F548 chain (F673, CLOSED)
and literal-getter sources (F664, CLOSED) but not getter invocation
through a VAR-BOUND prototype chain: `(function(){var o={get
x(){return 'f1';}};var c=Object.create(o);return c.x+'f2';})()`
and the nested twin `(function(){var p={get y(){return
'f1';}};var c=Object.create(p);var d=Object.create(c);return
d.y+'f2';})()` both node-evaluate (v24.20.0) to the exact
credential while the decoder produced zero variants. Distinct
from F704 (descriptor-map accessors, filed round 49).

F724 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
Object.setPrototypeOf installed getter reads -- the decoder has no
Object.setPrototypeOf production: `(function(){var
c={};Object.setPrototypeOf(c,{get x(){return 'f1';}});return
c.x+'f2';})()` and the bound-proto twin `(function(){var c={};var
p={get y(){return 'f1';}};Object.setPrototypeOf(c,p);return
c.y+'f2';})()` both node-evaluate to the exact credential while
the decoder produced zero variants. Distinct from F723
(Object.create).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_f723f724_match_object_head: shared `Object.<member>(` head
  matcher (i-1 ident guard, dot-form only, member commits).
- _js_f723f724_parse_proto_value: proto values -- bound _JSObj
  ident, null (-> None), Object.prototype (empty _JSObj, F704),
  nested one-arg Object.create (recursed); literal `{...}` only
  when allow_literal (F724 statements); F673's literal-proto
  create raises (disjoint).
- _js_f723f724_parse_create_arg: one-arg create arg; `{` or `,`
  after arg -> (None, None) (F673's / F704's heads, disjoint).
- _js_f723f724_parse_decl_init: `{LIT}` (accessor-aware) or
  one-arg create -> _JSObj.
- _js_f723f724_parse_setproto_stmt: `Object.setPrototypeOf(T,P);`
  mutates env[T].proto (last wins; cyclic protos fail closed --
  the engine throws TypeError).
- _js_parse_f723_proto_chain_iife: `(function(){DECL;+ return
  ADD;})()` with one-arg create decls; hooked after F702/F703.
- _js_parse_f724_setproto_iife: decls + setproto statements;
  hooked after F723.
Return additive via _js_parse_f671_member_term (F548 chain via
_jsobj_lookup, _JSAccessor unwrap); F711 unsafe-int guard;
F452 parts/ops charging.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g383-*
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


# ------------------------------------------------ p0: pin/taxonomy


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s len=%d" % (TAXONOMY_PIN,
                                                          len(TAXONOMY)))


# ------------------------------------------------ p1: filed shapes


@_t
def test_p1_f723_s1():
    """F723 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f723-s1=%s" % ok)


@_t
def test_p1_f723_s2():
    """F723 filed shape 2 (nested chain) blocks."""
    ok = _blocked(
        "(function(){var p={get y(){return '%s';}};"
        "var c=Object.create(p);var d=Object.create(c);"
        "return d.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f723-s2=%s" % ok)


@_t
def test_p1_f724_s1():
    """F724 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var c={};"
        "Object.setPrototypeOf(c,{get x(){return '%s';}});"
        "return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f724-s1=%s" % ok)


@_t
def test_p1_f724_s2():
    """F724 filed shape 2 (bound proto) blocks."""
    ok = _blocked(
        "(function(){var c={};var p={get y(){return '%s';}};"
        "Object.setPrototypeOf(c,p);return c.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f724-s2=%s" % ok)


# ------------------------------------------------ p2: generalizations


@_t
def test_p2_deep_chain():
    """Three-deep create chain decodes."""
    ok = _blocked(
        "(function(){var a={get x(){return '%s';}};"
        "var b=Object.create(a);var c=Object.create(b);"
        "var d=Object.create(c);return d.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "deep3=%s" % ok)


@_t
def test_p2_shadow():
    """Own data prop shadows proto getter (node-exact)."""
    ok = _blocked(
        "(function(){var c={x:'%s'};var p={get x(){return 'no';}};"
        "Object.setPrototypeOf(c,p);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "shadow=%s" % ok)


@_t
def test_p2_last_wins():
    """Last setPrototypeOf wins."""
    ok = _blocked(
        "(function(){var c={};var p={get x(){return 'no';}};"
        "var q={get x(){return '%s';}};"
        "Object.setPrototypeOf(c,p);Object.setPrototypeOf(c,q);"
        "return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "lastwins=%s" % ok)


@_t
def test_p2_null_proto():
    """setPrototypeOf(c, null): own props still read."""
    ok = _blocked(
        "(function(){var c={x:'%s'};Object.setPrototypeOf(c,null);"
        "return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nullproto=%s" % ok)


@_t
def test_p2_bracket_and_opt():
    """Bracket and ?. reads through the chain."""
    ok = (_blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.create(o);return c['x']+'%s';})()" % (_A, _B))
        and _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.create(o);return c?.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "bracket-opt=%s" % ok)


@_t
def test_p2_data_proto():
    """Data (non-getter) proto prop reads."""
    ok = _blocked(
        "(function(){var o={x:'%s'};var c=Object.create(o);"
        "return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "data-proto=%s" % ok)


@_t
def test_p2_nested_create_arg():
    """Nested one-arg create in the proto position."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.create(Object.create(o));"
        "return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nested-arg=%s" % ok)


@_t
def test_p2_create_then_setproto():
    """Create decl followed by setPrototypeOf statement."""
    ok = _blocked(
        "(function(){var o={get x(){return 'no';}};"
        "var c=Object.create(o);var p={get x(){return '%s';}};"
        "Object.setPrototypeOf(c,p);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "create-setproto=%s" % ok)


@_t
def test_p2_multi_term():
    """Multiple additive terms through the chain."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.create(o);"
        "return c.x+c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "multi-term=%s" % ok)


# ------------------------------------------------ p3: bounds (fail closed)


@_t
def test_p3_unbound_proto():
    """Unbound proto ident fails closed."""
    ok = _misses(
        "(function(){var c=Object.create(q);return c.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_nonobject_proto():
    """Non-object proto (engine throws) fails closed."""
    ok = _misses(
        "(function(){var c=Object.create(1);return c.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "nonobj=%s" % ok)


@_t
def test_p3_cyclic():
    """Cyclic setPrototypeOf (engine throws) fails closed."""
    ok = _misses(
        "(function(){var c={};Object.setPrototypeOf(c,c);"
        "return c.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "cyclic=%s" % ok)


@_t
def test_p3_setproto_unbound_target():
    """setPrototypeOf on unbound target fails closed."""
    ok = _misses(
        "(function(){var c={};"
        "Object.setPrototypeOf(q,{get x(){return 'a';}});"
        "return c.x;})()")
    return ("HELD" if ok else "BREAK", "unbound-tgt=%s" % ok)


@_t
def test_p3_bracket_create():
    """Object['create'] (documented residual) fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return 'a';}};"
        "var c=Object['create'](o);return c.x;})()")
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p3_reassign():
    """Reassignment of a bound ident fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return 'a';}};"
        "var c=Object.create(o);c=1;return c.x;})()")
    return ("HELD" if ok else "BREAK", "reassign=%s" % ok)


@_t
def test_p3_extra_stmt():
    """Extra non-decl statement fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return 'a';}};"
        "var c=Object.create(o);var z=1;return c.x;})()")
    return ("HELD" if ok else "BREAK", "extra=%s" % ok)


@_t
def test_p3_named_fn():
    """Named function fails closed."""
    ok = _misses(
        "(function foo(){var o={get x(){return 'a';}};"
        "var c=Object.create(o);return c.x;})()")
    return ("HELD" if ok else "BREAK", "named=%s" % ok)


@_t
def test_p3_missing_key():
    """Missing key fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return 'a';}};"
        "var c=Object.create(o);return c.zzz;})()")
    return ("HELD" if ok else "BREAK", "missing=%s" % ok)


@_t
def test_p3_unsafe_int():
    """Unsafe-int member fails closed (F711 parity)."""
    ok = _misses(
        "(function(){var o={get x(){return 'a';}};"
        "var c=Object.create(o);return c[9007199254740993];})()")
    return ("HELD" if ok else "BREAK", "unsafeint=%s" % ok)


@_t
def test_p3_twoarg_bound():
    """Two-arg create with bound proto (residual) fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return 'a';}};"
        "var c=Object.create(o,{y:{value:'b'}});return c.x;})()")
    return ("HELD" if ok else "BREAK", "twoarg=%s" % ok)


@_t
def test_p3_reflect_setproto():
    """Reflect.setPrototypeOf (residual) fails closed."""
    ok = _misses(
        "(function(){var c={};"
        "Reflect.setPrototypeOf(c,{get x(){return 'a';}});"
        "return c.x;})()")
    return ("HELD" if ok else "BREAK", "reflect=%s" % ok)


@_t
def test_p3_dunder_proto():
    """__proto__ assignment (residual) fails closed."""
    ok = _misses(
        "(function(){var c={};var p={get x(){return 'a';}};"
        "c.__proto__=p;return c.x;})()")
    return ("HELD" if ok else "BREAK", "dunder=%s" % ok)


# ------------------------------------------------ p4: siblings + open neighbors


@_t
def test_p4_sibling_f704():
    """F704 descriptor-map create still blocks."""
    ok = _blocked(
        "(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});"
        "return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f704=%s" % ok)


@_t
def test_p4_sibling_f673():
    """F673 one-arg literal-proto create still blocks."""
    ok = _blocked(
        "(function(){var o=Object.create({get x(){return '%s';}});"
        "return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f673=%s" % ok)


@_t
def test_p4_sibling_f664():
    """F664 literal-getter source still blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f664=%s" % ok)


@_t
def test_p4_neighbor_f725_open():
    """F725 (__lookupGetter__) now BLOCKS (closed wave-383 merge)."""
    ok = not _misses(
        "(function(){var o={};o.__defineGetter__('x',function(){return '%s';});"
        "var g=o.__lookupGetter__('x');return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f725-closed=%s" % ok)


@_t
def test_p4_neighbor_f726_open():
    """F726 valueOf-only: correctly yields "[object Object]" (spec: inherited
    toString tried before valueOf; F726 entry documents this node-exact).
    Not a bypass -- honest non-credential."""
    ok = _misses(
        "(function(){var o={valueOf:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f726-valueof-honest=%s" % ok)


# ------------------------------------------------ p5: honest text quiet


@_t
def test_p5_junk_quiet():
    """Honest text stays quiet."""
    ok = (_misses("just a regular sentence about getting things done")
          and _misses("(function(){var o={x:1};var c=Object.create(o);return c.x;})()")
          and _misses("(function(){var c={};Object.setPrototypeOf(c,{});return 1;})()"))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: pin + footer


@_t
def test_p6_pin_footer():
    """Pin 2143; lane-local footer (F723/F724 CLOSED, F738/F739 filed; next F740)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p7: perf


@_t
def test_p7_perf():
    """200 mixed sites decode quickly."""
    t0 = time.time()
    for _ in range(100):
        _blocked(
            "(function(){var o={get x(){return '%s';}};"
            "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
        _blocked(
            "(function(){var c={};"
            "Object.setPrototypeOf(c,{get x(){return '%s';}});"
            "return c.x+'%s';})()" % (_A, _B))
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p8: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts expect 0 BREAK post-closure; the attack battery
    # expects 0 BREAK (its footer pin was repointed lane-locally,
    # merge owns the tree-wide repoint).
    for batt, expect_break in (("evals/w382_f723_redfirst.py", 0),
                               ("evals/w382_f724_redfirst.py", 0),
                               ("evals/w382_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
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
def test_p8_green_check():
    """Depth-1 green check: F723/F724 red-firsts + attack battery green."""
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
            verdict, note = "ERROR", "%s: %r" % (fn.__name__, e)
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
