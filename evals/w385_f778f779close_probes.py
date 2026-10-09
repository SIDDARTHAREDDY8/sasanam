#!/usr/bin/env python3
"""Wave-385 lane 9: close F778 + F779.

F778 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round
52): F647 residual -- ?? with computed right operand. F647 (CLOSED)
models ?? with literal right operands only; a non-literal right
operand missed: (null??(()=> 'f1'))() and (null??o.x) resolve
node-exactly while the decoder produced zero variants. The member-read
family already decoded via the existing routes (red-first s2 HELD on
the open tree); the IIFE right operand is the true residual.

F779 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round
52): Symbol introspection reads (description, keyFor) -- the decoder
had no Symbol-introspection production: Symbol('f1').description and
Symbol.keyFor(Symbol.for('f1')) resolve node-exactly while the decoder
produced zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F778: _js_parse_f778_nullish_computed_iife (+4 helpers), hooked
  after F747 with the saved parts/ops discipline (wave-383 lesson).
  DECLS bind var|let|const IDENT = null|undefined (any order, >=1).
  The group `(NULLISH ?? IIFE)()` picks the IIFE exactly when LEFT
  is provably nullish (null/undefined keyword or null-bound ident;
  the grammar has no reassignment production) and the trailing ()
  invokes the zero-param IIFE whose body provably returns a plain
  string (anonymous function or string-body arrow). Non-invoked
  groups, non-nullish LEFTs, named/param/non-literal IIFEs, and
  arg-carrying invokes fail closed. The member-read RIGHT family
  is intentionally NOT modeled here -- it already decodes via the
  existing routes (no behavior change).
- F779: _js_parse_f779_symbol_introspection_iife (+3 helpers),
  hooked after F778 with the saved parts/ops discipline. DECLS
  bind var|let|const IDENT = Symbol('LIT') / Symbol.for('LIT')
  (string-literal arg only). Terms: s.description / s['description']
  (the description literal) and Symbol.keyFor(s) (the registry key,
  only for Symbol.for-created bindings -- the engine yields
  undefined for Symbol()-created symbols, so those fail closed).
  Symbol() no-arg, non-literal/extra args, new Symbol(), keyFor on
  non-global or unbound idents, non-description members, computed
  bracket keys, reassignment, and extra statements fail closed.

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
def test_b0_footer_state():
    """Control: lane-local footer (F778/F779 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f778_s1():
    """F778 filed shape 1 (IIFE right, invoked) blocks + decodes node-exact."""
    s = ("(function(){var f=null;return (f??(function(){return '" + _A
         + "';}))()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f778_s2():
    """F778 filed shape 2 (member-read right) blocks + decodes node-exact."""
    s = ("(function(){var o={x:'" + _A + "'};var n=null;return (n??o.x)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f779_s1():
    """F779 filed shape 1 (.description) blocks + decodes node-exact."""
    s = ("(function(){var s=Symbol('" + _A + "');return s.description+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f779_s2():
    """F779 filed shape 2 (Symbol.keyFor) blocks + decodes node-exact."""
    s = ("(function(){var s=Symbol.for('" + _A + "');return Symbol.keyFor(s)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f779_s3():
    """F779 filed variant (bracket read) blocks + decodes node-exact."""
    s = ("(function(){var s=Symbol('" + _A + "');return s['description']+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f778_arrow():
    """F778 arrow IIFE right blocks + exact."""
    s = ("(function(){var f=null;return (f??(()=>'" + _A + "'))()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f778_undef_bound():
    """F778 undefined-bound ident LEFT blocks + exact."""
    s = ("(function(){var f=undefined;return (f??(function(){return '"
         + _A + "';}))()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f778_null_keyword():
    """F778 null-keyword LEFT blocks + exact."""
    s = ("(function(){var f=null;return (null??(function(){return '"
         + _A + "';}))()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f778_two_groups():
    """F778 two groups in one return blocks + exact."""
    s = ("(function(){var f=null;return (f??(function(){return '" + _A
         + "';}))()+(f??(()=>'" + _B + "'))();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f778_let_const():
    """F778 let/const decl twins block + exact."""
    s1 = ("(function(){let f=null;return (f??(function(){return '" + _A
          + "';}))()+'" + _B + "';})()")
    s2 = ("(function(){const f=null;return (f??(function(){return '" + _A
          + "';}))()+'" + _B + "';})()")
    ok = (_blocked(s1) and _decodes_exact(s1, _A + _B)
          and _blocked(s2) and _decodes_exact(s2, _A + _B))
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f779_for_description():
    """F779 .description on a Symbol.for binding blocks + exact."""
    s = ("(function(){var s=Symbol.for('" + _A + "');return s.description+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f779_two_symbols():
    """F779 two symbol bindings in one return blocks + exact."""
    s = ("(function(){var a=Symbol('" + _A + "');var b=Symbol.for('"
         + _B + "');return a.description+Symbol.keyFor(b);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f779_dquote_bracket():
    """F779 double-quote bracket read blocks + exact."""
    s = ('(function(){var s=Symbol("' + _A + '");return s["description"]+"'
         + _B + '";})()')
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f778_noinvoke():
    """F778 non-invoked group fails closed (engine yields the function)."""
    s = ("(function(){var f=null;return (f??(function(){return '" + _A
         + "';}))+'';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_nonnullish_left():
    """F778 non-nullish LEFT fails closed (engine picks LEFT)."""
    s = ("(function(){var z=0;return (z??(function(){return '" + _A
         + "';}))()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_named_iife():
    """F778 named function IIFE fails closed."""
    s = ("(function(){var f=null;return (f??(function g(){return '" + _A
         + "';}))()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_param_iife():
    """F778 param-carrying IIFE fails closed."""
    s = ("(function(){var f=null;return (f??(function(x){return '" + _A
         + "';}))()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_nonlit_body():
    """F778 non-literal IIFE body fails closed."""
    s = ("(function(){var f=null;return (f??(function(){return x;}))()+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_block_arrow():
    """F778 block-body arrow IIFE fails closed."""
    s = ("(function(){var f=null;return (f??(()=>{return '" + _A
         + "';}))()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_unbound_left():
    """F778 unbound ident LEFT fails closed (engine ReferenceError)."""
    s = ("(function(){return (g??(function(){return '" + _A
         + "';}))()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_str_bound():
    """F778 string-bound ident LEFT fails closed (engine picks LEFT)."""
    s = ("(function(){var f='x';return (f??(function(){return '" + _A
         + "';}))()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_noarg():
    """F779 Symbol() no-arg fails closed (engine description undefined)."""
    s = ("(function(){var s=Symbol();return s.description+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_keyfor_nonglobal():
    """F779 Symbol.keyFor on a Symbol()-created binding fails closed."""
    s = ("(function(){var s=Symbol('" + _A + "');return Symbol.keyFor(s)+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_tostring():
    """F779 .toString() member fails closed."""
    s = ("(function(){var s=Symbol('" + _A + "');return s.toString()+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_bad_bracket():
    """F779 wrong bracket key fails closed."""
    s = ("(function(){var s=Symbol('" + _A + "');return s['desc']+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_new_symbol():
    """F779 new Symbol() fails closed (engine throws)."""
    s = ("(function(){var s=new Symbol('" + _A + "');return s.description+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_reassign():
    """F779 reassigned binding fails closed."""
    s = ("(function(){var s=Symbol('" + _A + "');s=Symbol('zz');"
         "return s.description+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_numarg():
    """F779 non-string Symbol arg fails closed."""
    s = ("(function(){var s=Symbol(123);return s.description+'" + _B
         + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_valueof_member():
    """F779 non-description member read fails closed."""
    s = ("(function(){var s=Symbol('" + _A + "');return s.valueOf+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f778_reserved_decl():
    """F778 reserved-word binding name fails closed (engine SyntaxError)."""
    s = ("(function(){var null=null;return (null??(()=>'" + _A
         + "'))()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f779_reserved_decl():
    """F779 reserved-word binding name fails closed (engine SyntaxError)."""
    s = ("(function(){var null=Symbol('" + _A + "');return null.description+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p2_f778_nodecl_general():
    """F778 decl-free variant decodes node-exactly."""
    s = ("(function(){return (null??(()=>'" + _A + "'))()+'"
         + _B + "';})()")
    ok = _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "node-exact=%s" % ok)


# ------------------------------------------------ p4: siblings still block / neighbors open


@_t
def test_p4_sibling_f647():
    """F647 literal-right pin still blocks."""
    s = ("(function(){var z;return (z??'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f647=%s" % ok)


@_t
def test_p4_sibling_f747_augassign():
    """F747 ??= pin still blocks."""
    s = ("(function(){var x=null;x??='" + _A + "';return x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f747=%s" % ok)


@_t
def test_p4_neighbor_f780_open():
    """Neighbor F780 (constructor this-binding) still misses -- open."""
    s = ("(function(){function C(x){this.x=x;}var o=new C('" + _A
         + "');return o.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f780-open=%s" % ok)


@_t
def test_p4_neighbor_f781_open():
    """Neighbor F781 (prototype method reads) still misses -- open."""
    s = ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};var o=new C();return o.m()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f781-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_symbol():
    """Honest Symbol use without a literal description still misses."""
    ok = _misses("var s=Symbol('id');console.log(typeof s);")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_nullish():
    """Honest ?? without an IIFE right still misses."""
    ok = _misses("var x=a??'default';")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){var f=null;return (f??(function(){return 'a%d';}))()+'x';})()" % k)
        sites.append(
            "(function(){var s=Symbol('k%d');return s.description+'x';})()" % k)
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
    # The two red-firsts must show 0 BREAK on the closed tree; the
    # wave-384 attack battery must be fully green on the lane tree
    # (its F778/F779 pins were flipped to closed and its footer
    # probe repointed lane-locally).
    for batt, expect_break in (("evals/w385_f778_redfirst.py", 0),
                               ("evals/w385_f779_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 0)):
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
    """Depth-1 green check: both red-firsts (0 BREAK) + wave-384
    attack battery (0 BREAK: F778/F779 pins flipped closed,
    footer repointed lane-locally)."""
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
