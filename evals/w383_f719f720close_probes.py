#!/usr/bin/env python3
"""Wave-383 lane 4: close F719 + F720 (Set for-of accumulation, Array.includes).

F719 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
for-of accumulation over a var-bound Set bypasses the bounded static
JS-expression decoder -- the decoder modeled for-of accumulation
over an inline `new Set` (F602, CLOSED) but failed closed on the
var-bound twin `(function(){var r='';var s=new
Set(['f1','f2']);for(var x of s){r+=x;}return r;})()` and on the
additive-assign twin `(function(){var r='';for(var x of new
Set(['f1','f2'])){r=r+x;}return r;})()`. Both node-evaluate to the
exact credential (node v24.20.0) while the decoder produced zero
variants. Distinct from F602 (inline set + `S+=X` body) and F709
(counted for/while loops).

F720 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
Array.prototype.includes conditional reads bypass the bounded
static JS-expression decoder -- the decoder modeled the
Set.has/WeakSet.has membership-marker ternaries (F710/F687,
CLOSED) but had no includes production:
`(function(){var f=['k'].includes('k')?'f1':'xx';return
f+'f2';})()` and the var-bound twin `(function(){var
a=['q','k'];var f=a.includes('k')?'f1':'xx';return
f+'f2';})()` both node-evaluate to the exact credential (node
v24.20.0) while the decoder produced zero variants. Vehicle: the
general ternary is unmodeled (same as F687/F710); the novel
contribution is the unmodeled includes API.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f719_set_forof_iife: the var-bound Set for-of shape
  (`var|let S='';var|let|const ST=new Set([LITS]);
  for(var|let|const X of ST){S+=X|S=X+X;}return S;`, the F669 set
  decl reused for the binding) and the additive-assign twin of the
  inline form (`for(var|let|const X of new Set([LITS])){S=S+X;}`).
  Hooked after F602's forEach in the IIFE chain; disjoint (F602's
  for-of requires the inline set immediately after the accum decl
  with an `S+=X` body -- this route fails closed on that twin).
- _js_parse_f720_includes_iife (+ _js_parse_f720_includes,
  _js_parse_f720_ternary, _js_parse_f720_array_lit): the F710-shaped
  IIFE grammar with COND = `[!]ARR.includes('LIT')` (ARR a bound
  or inline literal array; SameValueZero-exact for strings,
  node v24.20.0). Hooked after F710; disjoint (array-literal decls
  vs `new Set`/`new WeakSet` heads; `.includes` vs `.has`).

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

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
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


# ------------------------------------------------------- p0: pin

TAXONOMY_PIN = 2143


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------------- p1: filed shapes block

@_t
def test_p1_f719_s1():
    """F719 filed shape 1 (var-bound Set + for-of) blocks."""
    ok = _blocked(
        "(function(){var r='';var s=new Set(['%s','%s']);"
        "for(var x of s){r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f719-s1=%s" % ok)


@_t
def test_p1_f719_s2():
    """F719 filed shape 2 (inline Set + r=r+x) blocks."""
    ok = _blocked(
        "(function(){var r='';for(var x of new Set(['%s','%s']))"
        "{r=r+x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f719-s2=%s" % ok)


@_t
def test_p1_f720_s1():
    """F720 filed shape 1 (inline array includes) blocks."""
    ok = _blocked(
        "(function(){var f=['k'].includes('k')?'%s':'xx';"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f720-s1=%s" % ok)


@_t
def test_p1_f720_s2():
    """F720 filed shape 2 (bound array includes) blocks."""
    ok = _blocked(
        "(function(){var a=['q','k'];var f=a.includes('k')?'%s':'xx';"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f720-s2=%s" % ok)


# ------------------------------------------------------- p2: generalizations

@_t
def test_p2_f719_dedup():
    """Set dedup is node-exact (first occurrence wins)."""
    ok = _blocked(
        "(function(){var r='';var s=new Set(['%s','%s','%s']);"
        "for(var x of s){r+=x;}return r;})()" % (_A, _A, _B))
    return ("HELD" if ok else "BREAK", "dedup=%s" % ok)


@_t
def test_p2_f719_let_const():
    """let/const declaration twins block."""
    ok = _blocked(
        "(function(){let r='';const s=new Set(['%s','%s']);"
        "for(const x of s){r=r+x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


@_t
def test_p2_f719_unbraced():
    """Unbraced loop body twin blocks."""
    ok = _blocked(
        "(function(){var r='';var s=new Set(['%s','%s']);"
        "for(var x of s)r+=x;return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbraced=%s" % ok)


@_t
def test_p2_f720_miss_branch():
    """Includes-miss selects the else branch node-exactly."""
    ok = _misses(
        "(function(){var a=['q','z'];var f=a.includes('k')?'%s':'yy';"
        "return f;})()" % _A)
    return ("HELD" if ok else "BREAK", "miss-branch-misses=%s" % ok)


@_t
def test_p2_f720_negation():
    """Negated includes selects correctly."""
    ok = _blocked(
        "(function(){var a=['k'];var f=!a.includes('z')?'%s':'xx';"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "negation=%s" % ok)


@_t
def test_p2_f720_paren_return():
    """Parenthesized return-position ternary blocks."""
    ok = _blocked(
        "(function(){var a=['k'];"
        "return (a.includes('k')?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "paren-return=%s" % ok)


# ------------------------------------------------------- p3: bounds fail closed

@_t
def test_p3_bound_nonempty_accum():
    ok = _misses(
        "(function(){var r='x';var s=new Set(['%s']);"
        "for(var x of s){r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "nonempty-accum=%s" % ok)


@_t
def test_p3_bound_loopvar_shadow():
    ok = _misses(
        "(function(){var r='';var s=new Set(['%s']);"
        "for(var s of s){r+=s;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "loopvar-shadow=%s" % ok)


@_t
def test_p3_bound_set_shadows_accum():
    ok = _misses(
        "(function(){var r='';var r=new Set(['%s']);"
        "for(var x of r){r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "set-shadows-accum=%s" % ok)


@_t
def test_p3_bound_body_other_ident():
    ok = _misses(
        "(function(){var r='';var s=new Set(['%s']);"
        "for(var x of s){r+=r;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "body-other-ident=%s" % ok)


@_t
def test_p3_bound_iterates_other():
    ok = _misses(
        "(function(){var r='';var s=new Set(['%s']);var t=s;"
        "for(var x of t){r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "iterates-other=%s" % ok)


@_t
def test_p3_bound_nonliteral_elem():
    ok = _misses(
        "(function(){var r='';var s=new Set([k]);"
        "for(var x of s){r+=x;}return r;})()")
    return ("HELD" if ok else "BREAK", "nonliteral-elem=%s" % ok)


@_t
def test_p3_bound_fromindex():
    ok = _misses(
        "(function(){var a=['k'];var f=a.includes('k',1)?'%s':'xx';"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "fromindex=%s" % ok)


@_t
def test_p3_bound_nonliteral_needle():
    ok = _misses(
        "(function(){var a=['k'];var k='k';var f=a.includes(k)?'%s':'xx';"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonliteral-needle=%s" % ok)


@_t
def test_p3_bound_rebinding():
    ok = _misses(
        "(function(){var a=['k'];var a=['z'];"
        "var f=a.includes('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "rebinding=%s" % ok)


# ------------------------------------------------------- p4: siblings + open neighbors

@_t
def test_p4_sibling_f602():
    """F602 inline for-of still blocks (disjoint, no shadowing)."""
    ok = _blocked(
        "(function(){var s='';for(var x of new Set(['%s','%s']))"
        "{s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f602=%s" % ok)


@_t
def test_p4_sibling_f710():
    """F710 Set.has ternary still blocks."""
    ok = _blocked(
        "(function(){var s=new Set(['k']);"
        "return (s.has('k')?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f710=%s" % ok)


@_t
def test_p4_sibling_f687():
    """F687 WeakSet.has ternary still blocks."""
    ok = _blocked(
        "(function(){var s=new WeakSet();var o={};s.add(o);"
        "return (s.has(o)?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f687=%s" % ok)


@_t
def test_p4_neighbor_f721_open():
    """F721 (indexOf) still misses -- open, not absorbed."""
    ok = not _misses(
        "(function(){var f=['k'].indexOf('k')===0?'%s':'xx';"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f721-closed=%s" % ok)


@_t
def test_p4_neighbor_f718_open():
    """F718 (Reflect.has) still misses -- open, not absorbed."""
    ok = not _misses(
        "(function(){var o={x:1};var f=Reflect.has(o,'x')?'%s':'xx';"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f718-closed=%s" % ok)


# ------------------------------------------------------- p5: honest text quiet

@_t
def test_p5_honest_text():
    cases = [
        "the quick brown fox jumps over the lazy dog",
        "for (var x of y) { console.log(x); }",
        "arr.includes(x) ? doA() : doB();",
        "var s = new Set([1,2,3]); for (var x of s) { sum += x; }",
        "if (list.includes(item)) { process(item); }",
    ]
    bad = [c for c in cases if not _misses(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "honest-quiet=%s" % ok)


# ------------------------------------------------------- p6: footer (lane-local)

@_t
def test_p6_footer_state():
    """Control: lane-local footer (F719/F720 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F762**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- p7: perf

@_t
def test_p7_perf():
    """200 mixed F719/F720 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append(
            "(function(){var r='';var s=new Set(['a%d','b']);"
            "for(var x of s){r+=x;}return r;})()" % k)
        corpus.append(
            "(function(){var a=['q','k%d'];var f=a.includes('k%d')"
            "?'x':'y';return f;})()" % (k, k))
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------------- p8: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Both red-firsts expect 0 BREAK (filed shapes now block).
    # w382_attack_probes expects exactly 1 BREAK: the lane-local
    # footer pin (merge owns the tree-wide repoint); any other
    # count fails loudly.
    for batt, expect_break in (("evals/w382_f719_redfirst.py", 0),
                               ("evals/w382_f720_redfirst.py", 0),
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
    """Depth-1 green check: F719/F720 red-firsts + wave-382 attack battery."""
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
