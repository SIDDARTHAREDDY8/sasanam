#!/usr/bin/env python3
"""Wave-387 lane 7: close F853 + F854 + F855 + F856 (generator params /
generator return values / Iterator.take / TextEncoder-TextDecoder).

F853 (LOW; filed 2026-10-09 05:30 UTC, wave-386 attack round 54, local
node validation, $0 model spend): generator parameters -- the decoder
models parameterless generators (F728) but not parameterized ones:
(function(){function* g(a){yield a;}var it=g('f1');
return it.next().value+'f2';})() and the two-param twin
(function(){function* g(a,b){yield a;yield b;}var it=g('f1','f2');
return it.next().value+it.next().value;})() resolve node-exactly while
the decoder produced zero variants. Controls: the parameterless twin
blocks coded; junk-quiet control passes.

F854 (LOW; filed 2026-10-09 05:30 UTC, wave-386 attack round 54, local
node validation, $0 model spend): generator return values -- the
decoder models `yield` values (F728) but not generator `return`
values: (function(){function* g(){yield 'x';return 'f1';}var it=g();
it.next();return it.next().value+'f2';})() and the no-yield twin
(function(){function* g(){return 'f1';}var it=g();
return it.next().value+'f2';})() resolve node-exactly while the
decoder produced zero variants. Controls: the yield twin blocks
coded; junk-quiet control passes.

F855 (LOW; filed 2026-10-09 05:30 UTC, wave-386 attack round 54, local
node validation, $0 model spend): Iterator.take -- the decoder models
Iterator.map/drop (F793) but not `take`:
(function(){var it=['f1','f2'].values().take(2).toArray();
return it[0]+it[1];})() and
(function(){return [...['f1','f2','x'].values().take(2)].join('');})()
resolve node-exactly while the decoder produced zero variants.
Controls: the .drop twin blocks coded; junk-quiet control passes.

F856 (LOW; filed 2026-10-09 05:30 UTC, wave-386 attack round 54, local
node validation, $0 model spend): TextEncoder/TextDecoder round-trip --
the decoder has no TextEncoder/TextDecoder production:
(function(){var b=new TextEncoder().encode('f1');
return new TextDecoder().decode(b)+'f2';})() and
(function(){var e=new TextEncoder();var d=new TextDecoder();
return d.decode(e.encode('f1'))+'f2';})() resolve node-exactly while
the decoder produced zero variants. Controls: no twin (novel builtin
class); junk-quiet control passes.

Fix (gov/dlp.py, zero new re.compile -- count stays 28):
- F853: _js_parse_f853_paramgen_iife, hooked after F728. Node-exact
  (v24.20.0): >=1 param (disjoint from F728's empty-()); positional
  binding; missing arg fails closed (engine undefined); extra literal
  args ignored; yield operand literal-or-bound-param (paren twin
  yield('LIT') admitted; yield* refused); trailing return
  literal-or-bound-param, must be last; (IT.next();)* bare statements
  consume delivery slots (shared helper _js_parse_gen_bare_nexts);
  .next().value additive; <=16 calls.
- F854: _js_parse_f854_genreturn_iife, hooked after F853. Node-exact:
  bare IT.next(); statements consume delivery slots via the shared
  helper (stops before .value); zero-yield body allowed only with a
  trailing return; empty body fails closed; past-exhaustion .value is
  engine-undefined and fails closed. Disjoint from F728 by the
  bare-statement/no-yield requirements.
- F855: F793's spread branch gains a .take arm sharing the new
  ToIntegerOrInfinity count-arg parser _js_parse_f793f855_count_arg
  (F793's .drop refactored onto it, behavior-preserving), plus new
  var-bound _js_parse_f855_take_varbound_iife
  (var|let|const IT=SRC.values().take(n).toArray(); return ADD with
  IT[k] bracket-index reads; out-of-range/negative/non-integer
  indices fail closed). take(2)/take(0)/take(9)/take(1.5->1) keep the
  first n; take(-1)/NaN throw RangeError -> fail closed.
- F856: _js_parse_f856_textcodec_iife (+ _js_f856_sanitize,
  _js_parse_f856_new_codec, _js_parse_f856_encode_expr,
  _js_parse_f856_decode_term), hooked after F855's var-bound block.
  Node-exact (v24.20.0): UTF-8 round-trip identity; lone surrogates
  sanitize to U+FFFD (no regex); ctor args fail closed (a non-UTF-8
  decoder would break the identity); decode options fail closed;
  non-literal encode fails closed; unknown bindings and shadowing
  fail closed; decl-less inline form admitted when >=1 decode term
  is present.
All four: F452 per-attempt budget charging with snapshot/restore on
every miss (wave-383); results bounded by _MAX_DECODE_BYTES.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
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
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33 (evidence-schema domain)."""
    VERIFIER_TAXONOMY_PIN = 33
    ok = VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "vpin=%s" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recount():
    """Zero new re.compile (28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: wave-387 merge footer (F829-F892 closed; open F893-F920; next F921)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = (bool(foot)
          and "**F921**" in foot[-1]
          and "F893, F894" in foot[-1]
          and "F919, F920." in foot[-1]
          and "# Wave-387 merge: F829-F892 CLOSED (64)" in foot[-1])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f853_s1():
    """F853 filed shape 1 (one param) blocks + decodes node-exact."""
    s = ("(function(){function* g(a){yield a;}var it=g('" + _A
         + "');return it.next().value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f853_s2():
    """F853 filed shape 2 (two params) blocks + decodes node-exact."""
    s = ("(function(){function* g(a,b){yield a;yield b;}var it=g('"
         + _A + "','" + _B + "');"
         "return it.next().value+it.next().value;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f854_s1():
    """F854 filed shape 1 (yield + return, bare next) blocks + exact."""
    s = ("(function(){function* g(){yield 'x';return '" + _A + "';}"
         "var it=g();it.next();return it.next().value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f854_s2():
    """F854 filed shape 2 (no-yield return) blocks + decodes exact."""
    s = ("(function(){function* g(){return '" + _A + "';}var it=g();"
         "return it.next().value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f855_s1():
    """F855 filed shape 1 (var-bound take/toArray) blocks + exact."""
    s = ("(function(){var it=['" + _A + "','" + _B + "'].values()"
         ".take(2).toArray();return it[0]+it[1];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f855_s2():
    """F855 filed shape 2 (spread take/join) blocks + decodes exact."""
    s = ("(function(){return [...['" + _A + "','" + _B
         + "','x'].values().take(2)].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f856_s1():
    """F856 filed shape 1 (bytes binding) blocks + decodes exact."""
    s = ("(function(){var b=new TextEncoder().encode('" + _A + "');"
         "return new TextDecoder().decode(b)+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f856_s2():
    """F856 filed shape 2 (bound codecs) blocks + decodes exact."""
    s = ("(function(){var e=new TextEncoder();var d=new TextDecoder();"
         "return d.decode(e.encode('" + _A + "'))+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f853_gen():
    """F853 generalizations: extra arg, paren yield, two params, bare
    nexts with params, return-param."""
    s1 = ("(function(){function* g(a){yield a;}var it=g('" + _A
          + "','x');return it.next().value+'" + _B + "';})()")
    s2 = ("(function(){function* g(a){yield(a);}var it=g('" + _A
          + "');return it.next().value+'" + _B + "';})()")
    s3 = ("(function(){function* g(a,b){yield b;yield a;}"
          "var it=g('x','" + _A + "');return it.next().value+'"
          + _B + "';})()")
    s4 = ("(function(){function* g(a){yield 'x';return a;}"
          "var it=g('" + _A + "');it.next();"
          "return it.next().value+'" + _B + "';})()")
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    ok = ok and _blocked(s3) and _decodes_exact(s3, _A + _B)
    ok = ok and _blocked(s4) and _decodes_exact(s4, _A + _B)
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f854_gen():
    """F854 generalizations: two bare nexts, bare+additive mix."""
    s1 = ("(function(){function* g(){yield 'a';yield 'b';return '"
          + _A + "';}var it=g();it.next();it.next();"
          "return it.next().value+'" + _B + "';})()")
    s2 = ("(function(){function* g(){yield 'x';return '" + _A + "';}"
          "var it=g();it.next();"
          "return it.next().value+'" + _B + "';})()")
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f855_gen():
    """F855 generalizations: take(9), take(2.9)->2, take('2'), Set
    source, take(1) spread."""
    s1 = ("(function(){var it=['" + _A + "','" + _B + "'].values()"
          ".take(9).toArray();return it[0]+it[1];})()")
    s2 = ("(function(){var it=['a','" + _A + _B + "','c'].values()"
          ".take(2.9).toArray();return it[0]+it[1];})()")
    s3 = ("(function(){return [...['xx','" + _A + _B
          + "'].values().take('2')].join('');})()")
    s4 = ("(function(){var it=new Set(['" + _A + _B
          + "','f2']).values().take(1).toArray();return it[0];})()")
    s5 = ("(function(){return [...['" + _A + _B
          + "','x'].values().take(1)].join('');})()")
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, "a" + _A + _B)
    ok = ok and _blocked(s3) and _decodes_exact(s3, "xx" + _A + _B)
    ok = ok and _blocked(s4) and _decodes_exact(s4, _A + _B)
    ok = ok and _blocked(s5) and _decodes_exact(s5, _A + _B)
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f856_gen():
    """F856 generalizations: decl-less inline, bound-bytes decode,
    let/const decls."""
    s1 = ("(function(){return new TextDecoder().decode("
          "new TextEncoder().encode('" + _A + "'))+'" + _B + "';})()")
    s2 = ("(function(){var b=new TextEncoder().encode('" + _A + "');"
          "var d=new TextDecoder();return d.decode(b)+'" + _B + "';})()")
    s3 = ("(function(){let e=new TextEncoder();const d=new TextDecoder();"
          "return d.decode(e.encode('" + _A + "'))+'" + _B + "';})()")
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    ok = ok and _blocked(s3) and _decodes_exact(s3, _A + _B)
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f853_bounds():
    """F853 fail-closed: missing arg, non-literal arg, unbound yield,
    past exhaustion, .next(args), yield*."""
    s1 = ("(function(){function* g(a,b){yield b;}var it=g('x');"
          "return it.next().value;})()")
    s2 = ("(function(){function* g(a){yield a;}var x='" + _A + "';"
          "var it=g(x);return it.next().value;})()")
    s3 = ("(function(){function* g(a){yield b;}var it=g('" + _A + "');"
          "return it.next().value;})()")
    s4 = ("(function(){function* g(a){yield a;}var it=g('" + _A + "');"
          "it.next();return it.next().value;})()")
    s5 = ("(function(){function* g(a){yield a;}var it=g('" + _A + "');"
          "return it.next(1).value;})()")
    s6 = ("(function(){function* g(a){yield* a;}var it=g(['" + _A
          + "']);return it.next().value;})()")
    ok = (_fails_closed(s1) and _fails_closed(s2) and _fails_closed(s3)
          and _fails_closed(s4) and _fails_closed(s5)
          and _fails_closed(s6))
    return ("HELD" if ok else "BREAK", "fc=%s" % ok)


@_t
def test_p3_f854_bounds():
    """F854 fail-closed: return-then-undefined, no-yield-no-return,
    wrong iterator name, empty body."""
    s1 = ("(function(){function* g(){return '" + _A + "';}var it=g();"
          "it.next();return String(it.next().value);})()")
    s2 = ("(function(){function* g(){}var it=g();"
          "return String(it.next().value);})()")
    s3 = ("(function(){function* g(){yield 'x';return '" + _A + "';}"
          "var it=g();xx.next();return it.next().value;})()")
    s4 = ("(function(){function* g(){}var it=g();"
          "return it.next().value;})()")
    ok = (_fails_closed(s1) and _fails_closed(s2)
          and _fails_closed(s3) and _fails_closed(s4))
    return ("HELD" if ok else "BREAK", "fc=%s" % ok)


@_t
def test_p3_f855_bounds():
    """F855 fail-closed: take(-1), take(NaN), index out of range,
    negative index, take(0) empty read."""
    s1 = ("(function(){var it=['" + _A + "','f2'].values()"
          ".take(-1).toArray();return it[0];})()")
    s2 = ("(function(){var it=['" + _A + "','f2'].values()"
          ".take(NaN).toArray();return it[0];})()")
    s3 = ("(function(){var it=['" + _A + "'].values()"
          ".take(1).toArray();return it[5];})()")
    s4 = ("(function(){var it=['" + _A + "','f2'].values()"
          ".take(2).toArray();return it[-1];})()")
    s5 = ("(function(){var it=['" + _A + "','f2'].values()"
          ".take(0).toArray();return it[0];})()")
    s6 = ("(function(){var it=['" + _A + "','f2'].values()"
          ".take(1).toArray();return it[" + "9" * 5000 + "];})()")
    ok = (_fails_closed(s1) and _fails_closed(s2) and _fails_closed(s3)
          and _fails_closed(s4) and _fails_closed(s5)
          and _fails_closed(s6))
    return ("HELD" if ok else "BREAK", "fc=%s" % ok)


@_t
def test_p3_f856_bounds():
    """F856 fail-closed: utf-16le ctor arg, decode options, non-literal
    encode, unknown decode arg, encoder ctor arg."""
    s1 = ("(function(){var e=new TextEncoder();"
          "return new TextDecoder('utf-16le').decode(e.encode('"
          + _A + "'));})()")
    s2 = ("(function(){var e=new TextEncoder();var d=new TextDecoder();"
          "return d.decode(e.encode('" + _A + "'),{stream:true});})()")
    s3 = ("(function(){var e=new TextEncoder();var x='" + _A + "';"
          "return new TextDecoder().decode(e.encode(x));})()")
    s4 = ("(function(){var d=new TextDecoder();"
          "return d.decode(zzz);})()")
    s5 = ("(function(){return new TextDecoder().decode("
          "new TextEncoder('x').encode('" + _A + "'));})()")
    ok = (_fails_closed(s1) and _fails_closed(s2) and _fails_closed(s3)
          and _fails_closed(s4) and _fails_closed(s5))
    return ("HELD" if ok else "BREAK", "fc=%s" % ok)


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_sibling_f728():
    """F728 (parameterless generator, return right after decl) still
    decodes."""
    s = ("(function(){function* g(){yield '" + _A + "';}var it=g();"
         "return it.next().value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f728=%s" % ok)


@_t
def test_p4_sibling_f793_drop():
    """F793 (.drop twin) still decodes after the count-arg refactor."""
    s = ("(function(){return [...['x','" + _A + _B
         + "'].values().drop(1)].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f793drop=%s" % ok)


@_t
def test_p4_sibling_f793_map():
    """F793 (.map twin) still decodes."""
    s = ("(function(){return [...['" + _A + _B + "'].values()"
         ".map(function(p){return p;})].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f793map=%s" % ok)


@_t
def test_p4_sibling_f752():
    """F752 (iterator source decl) still decodes."""
    s = ("(function(){var it=['" + _A + _B + "'].values();"
         "return it.next().value;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f752=%s" % ok)


@_t
def test_p4_sibling_f824():
    """F824 (drop count discipline sibling) still decodes."""
    s = ("(function(){return [...['x','" + _A + _B
         + "'].values().drop(1)].join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f824=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_honest_quiet():
    """Honest text in the four shapes but no credential stays quiet."""
    s1 = ("(function(){function* g(a){yield a;}var it=g('x');"
          "return it.next().value+'y';})()")
    s2 = ("(function(){function* g(){yield 'x';return 'y';}var it=g();"
          "it.next();return it.next().value;})()")
    s3 = ("(function(){var it=['a','b'].values().take(2).toArray();"
          "return it[0]+it[1];})()")
    s4 = ("(function(){var b=new TextEncoder().encode('hi');"
          "return new TextDecoder().decode(b);})()")
    s5 = "var hello = 'world';"
    ok = (_misses(s1) and _misses(s2) and _misses(s3)
          and _misses(s4) and _misses(s5))
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(50):
        sites.append(
            "(function(){function* g(a){yield a;}var it=g('p%d');"
            "return it.next().value;})()" % k)
        sites.append(
            "(function(){function* g(){return 'q%d';}var it=g();"
            "return it.next().value;})()" % k)
        sites.append(
            "(function(){var it=['r%d'].values().take(1).toArray();"
            "return it[0];})()" % k)
        sites.append(
            "(function(){return new TextDecoder().decode("
            "new TextEncoder().encode('s%d'));})()" % k)
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
    # All four lane red-firsts must be 0 BREAK on the closed tree.
    for batt in ("evals/w387_f853_redfirst.py",
                 "evals/w387_f854_redfirst.py",
                 "evals/w387_f855_redfirst.py",
                 "evals/w387_f856_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
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
        elif nbreak != 0:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: all four lane red-firsts 0 BREAK."""
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
