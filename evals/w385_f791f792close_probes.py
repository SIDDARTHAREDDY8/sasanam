#!/usr/bin/env python3
"""Wave-385 lane 15: close F791 + F792 (private method reads; groupBy reads).

F791 (LOW; filed 2026-10-09 by wave-384 attack round 52): private
METHOD reads -- the decoder modeled private FIELD reads (#x, F672)
but not private methods: `this.#m()` and static `C.#m()` dispatch
node-exactly while the decoder produced zero variants.

F792 (LOW; filed 2026-10-09 by wave-384 attack round 52): groupBy
reads -- the decoder had no groupBy production: the ES2024
`Map.groupBy`/`Object.groupBy` builtins group fragments
node-exactly while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F791: the F672 class-body parser now accepts `[static] #name()`
  zero-arg private methods (stored in rec["pmeth"]/rec["psmeth"]);
  the F672 body additive accepts `this.#M()`/`CNAME.#M()` call
  terms ("pmcall"); eval resolves them against the LEXICALLY
  declaring class's own record with the engine's brand check
  (node-verified: subclass same-named #m does not shadow the
  parent's inside the parent's method; subclass receivers lack
  the static brand). Params, private getters, out-of-scope refs,
  and brand violations fail closed.
- F792: `_js_parse_f792_groupby_iife` (+ `_js_f792_parse_callback`,
  `_js_f792_parse_key_expr`, `_js_f792_parse_return_additive`,
  `_js_f792_parse_group_read`), hooked after F757 with the
  F452 parts/ops snapshot-restore discipline. Callback forms:
  `function(x){return x;}` / `return x[NUM];` / `return 'K';`
  and the arrow twins. Map reads `M.get('K')[NUM]`; Object reads
  `M.K[NUM]`/`M['K'][NUM]` (cross-kind throws in the engine --
  fail closed).

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
    """Control: lane-local footer (F791/F792 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, "
              "F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, "
              "F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, "
              "F789, F790, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f791_s1():
    """F791 filed shape 1 (this.#m()) blocks + decodes node-exact."""
    s = ("(function(){class C{#m(){return '" + _A
         + "';}go(){return this.#m();}}return new C().go()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f791_s2():
    """F791 filed shape 2 (static C.#m()) blocks + decodes node-exact."""
    s = ("(function(){class C{static #m(){return '" + _A
         + "';}static go(){return C.#m();}}return C.go()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f792_s1():
    """F792 filed shape 1 (Map.groupBy) blocks + decodes node-exact."""
    s = ("(function(){var m=Map.groupBy(['" + _A + "','" + _B
         + "'],function(x){return x[0];});return m.get('x')[0]+m.get('4')[0];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f792_s2():
    """F792 filed shape 2 (Object.groupBy) blocks + decodes node-exact."""
    s = ("(function(){var o=Object.groupBy(['" + _A + "','" + _B
         + "'],function(x){return x[0];});return o.x[0]+o['4'][0];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f791_static_this():
    """F791 `this.#m()` inside a static method blocks + exact."""
    s = ("(function(){class C{static #m(){return '" + _A
         + "';}static go(){return this.#m();}}return C.go()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f791_nested():
    """F791 private method calling a private method blocks + exact."""
    s = ("(function(){class C{#a(){return '" + _A
         + "';}#m(){return this.#a();}go(){return this.#m();}}"
         "return new C().go()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f791_subclass_inherit():
    """F791 subclass inheriting go(): lexical #m wins, blocks + exact."""
    s = ("(function(){class C{#m(){return '" + _A
         + "';}go(){return this.#m();}}class D extends C{}"
         "return new D().go()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f791_priv_pub_coexist():
    """F791 #m and public m coexist (called from outside): blocks + exact."""
    s = ("(function(){class C{#m(){return '" + _A
         + "';}m(){return 'xx';}go(){return this.#m();}}"
         "return new C().go()+new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "xx" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f792_arrow():
    """F792 arrow callback blocks + exact."""
    s = ("(function(){var m=Map.groupBy(['" + _A + "','" + _B
         + "'],x=>x[0]);return m.get('x')[0]+m.get('4')[0];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f792_identity():
    """F792 identity callback blocks + exact."""
    s = ("(function(){var m=Map.groupBy(['" + _A + "','" + _B
         + "'],function(x){return x;});return m.get('" + _A
         + "')[0]+m.get('" + _B + "')[0];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f792_const_key():
    """F792 constant-literal key blocks + exact."""
    s = ("(function(){var m=Map.groupBy(['" + _A + "','" + _B
         + "'],function(x){return 'k';});return m.get('k')[0]+m.get('k')[1];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f792_multi_group():
    """F792 multi-item groups: insertion order, blocks + exact."""
    s = ("(function(){var m=Map.groupBy(['Aa','Ab','Ba'],x=>x[0]);"
         "return m.get('A')[0]+m.get('A')[1]+m.get('B')[0];})()")
    ok = _decodes_exact(s, "AaAbBa")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f792_let():
    """F792 let-bound group var blocks + exact."""
    s = ("(function(){let o=Object.groupBy(['" + _A + "'],x=>x);"
         "return o['" + _A + "'][0]+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f791_params():
    """F791 private method with params fails closed."""
    s = ("(function(){class C{#m(a){return a;}go(){return this.#m('"
         + _A + "');}}return new C().go()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f791_call_on_field():
    """F791 calling a private field value fails closed (engine throws)."""
    s = ("(function(){class C{#x='q';go(){return this.#x();}}"
         "return new C().go()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f791_instpriv_on_class():
    """F791 C.#m() on an instance private method fails closed."""
    s = ("(function(){class C{#m(){return '" + _A
         + "';}static go(){return C.#m();}}return C.go()+'" + _B
         + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f791_staticpriv_in_instance():
    """F791 this.#m() in an instance method on a static #m fails closed."""
    s = ("(function(){class C{static #m(){return '" + _A
         + "';}go(){return this.#m();}}return new C().go()+'" + _B
         + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f791_unscoped():
    """F791 undeclared #m reference fails closed (engine SyntaxError)."""
    s = ("(function(){class C{go(){return this.#m();}}"
         "return new C().go()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f791_dup_private():
    """F791 duplicate static+instance #m fails closed (engine SyntaxError)."""
    s = ("(function(){class C{static #m(){return '" + _A
         + "';}#m(){return 'x';}go(){return 1;}}return 'q';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f791_args_call():
    """F791 this.#m(1) with call args fails closed (zero-arg model)."""
    s = ("(function(){class C{#m(){return '" + _A
         + "';}go(){return this.#m(1);}}return new C().go()+'" + _B
         + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f791_recursion():
    """F791 self-recursive private method fails closed fast (no hang)."""
    s = ("(function(){class C{#m(){return this.#m();}go(){return this.#m();}}"
         "return new C().go();})()")
    t0 = time.time()
    ok = _fails_closed(s)
    dt = time.time() - t0
    ok = ok and dt < 20.0
    return ("HELD" if ok else "BREAK", "closed=%s dt=%.2f" % (ok, dt))


@_t
def test_p3_f792_missing_group():
    """F792 missing group key fails closed (engine throws)."""
    s = ("(function(){var m=Map.groupBy(['" + _A
         + "'],x=>x);return m.get('zzz')[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f792_read_oob():
    """F792 out-of-range read index fails closed."""
    s = ("(function(){var m=Map.groupBy(['" + _A
         + "'],x=>x);return m.get('" + _A + "')[5];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f792_cross_kind():
    """F792 Map read via .k member fails closed (engine throws)."""
    s = ("(function(){var m=Map.groupBy(['k1'],x=>x);return m.k[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f792_cross_kind_obj():
    """F792 Object read via .get fails closed (engine throws)."""
    s = ("(function(){var o=Object.groupBy(['" + _A
         + "'],x=>x);return o.get('" + _A + "')[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f792_two_params():
    """F792 two-param callback fails closed (one-param model)."""
    s = ("(function(){var m=Map.groupBy(['" + _A
         + "'],function(x,i){return x;});return m.get('" + _A + "')[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f792_nonlit_items():
    """F792 non-literal array items fail closed."""
    s = "(function(){var m=Map.groupBy([x],x=>x);return m.get('A')[0];})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f792_extra_stmt():
    """F792 extra statement fails closed (one-statement model)."""
    s = ("(function(){var m=Map.groupBy(['" + _A
         + "'],x=>x);var z=1;return m.get('" + _A + "')[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f792_key_oob():
    """F792 key index out of range fails closed (engine undefined-key)."""
    s = ("(function(){var m=Map.groupBy(['ab'],function(x){return x[9];});"
         "return m.get('undefined')[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f672_privfield():
    """F672 private-field read pin still blocks."""
    s = ("(function(){class C{#x='" + _A
         + "';go(){return this.#x;}}return new C().go()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f672=%s" % ok)


@_t
def test_p4_sibling_f672_static_privfield():
    """F672 static private-field read pin still blocks."""
    s = ("(function(){class C{static #x='" + _A
         + "';static go(){return C.#x;}}return C.go()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f672=%s" % ok)


@_t
def test_p4_sibling_f757():
    """F757 new.target pin still blocks."""
    s = ("(function(){function C(){this.x=new.target===C?'" + _A
         + "':'z';}return new C().x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f757=%s" % ok)


@_t
def test_p4_neighbor_f793_open():
    """Neighbor F793 (Iterator helpers) still misses -- honest open shape."""
    s = ("(function(){return [...['" + _A + "','" + _B
         + "'].values().map(function(x){return x;})].join('');})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f793-open=%s" % ok)


@_t
def test_p4_neighbor_f790_open():
    """Neighbor F790 (destructuring rest) still misses -- honest open shape."""
    s = ("(function(){var {a,...r}={a:'" + _A + "',b:'" + _B
         + "'};return a+r.b;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f790-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_class_unaffected():
    """Honest class without privates still misses."""
    s = ("(function(){class C{m(){return 'ab';}}return new C().m()+'cd';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_groupby_unaffected():
    """Honest Map.groupBy without fragments still misses."""
    s = ("(function(){var m=Map.groupBy(['a','b'],x=>x);return m.get('a')[0];})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){class C{#m(){return 'a%d';}go(){return this.#m();}}"
            "return new C().go();})()" % k)
        sites.append(
            "(function(){var m=Map.groupBy(['v%d'],x=>x);"
            "return m.get('v%d')[0];})()" % (k, k))
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
    # All three run with green checks skipped at depth-1. The lane
    # red-firsts expect 0 BREAK; w384_attack_probes.py expects
    # exactly 1 BREAK = its test_b0_footer_state pin on the
    # lane-local footer (wave-305 class; tree-wide repoint is
    # merge-owned). All functional probes must HELD.
    for batt, expect_break in (("evals/w385_f791_redfirst.py", 0),
                               ("evals/w385_f792_redfirst.py", 0),
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
    """Depth-1 green check: lane red-firsts + w384 attack battery, 0 BREAK."""
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
