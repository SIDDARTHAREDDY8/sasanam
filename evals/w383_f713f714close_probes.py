#!/usr/bin/env python3
"""Wave-383 lane 1: close F713 + F714.

F713 (LOW, filed 2026-10-08 by wave-382 lane 7 as F713, kept at the
wave-382 merge by first-filing): F669 residual -- a
LITERAL-constructed Map's spread-join with an additive tail, and the
bare-spread twin, bypass the bounded static JS-expression decoder.
F669 (CLOSED) requires the join to be the return terminal and fails
closed on bare Map spreads: `(function(){var m=new
Map([['k','f1']]);return [...m.values()].join('')+'f2';})()` and
`(function(){var m=new Map([['k','f1']]);return
[...m].join('')+'f2';})()` both node-evaluate to the exact
credential (node v24.20.0) while the decoder produced zero variants.

F714 (LOW, filed 2026-10-08 by attack round 50): Proxy has-trap +
`in` operator conditional reads with the ternary bound to a variable
first. F666 (CLOSED) requires the in-ternary as the DIRECT return
terminal and only models `return IDENT==='LIT';` trap bodies:
`(function(){var p=new Proxy({},{has:function(t,k){return
true;}});var f=('x' in p)?'f1':'xx';return f+'f2';})()` and the
`k==='y'` twin both node-evaluate to the exact credential while the
decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f713_map_spread_join_tail_iife (+
  _js_parse_f713_join_tail): reuses the F669 decl/set/spread-head
  helpers; the join may carry an additive `+'LIT'` tail; a bare
  `[...m]` spread stringifies each [k,v] pair node-exactly as
  k+','+v. Hooked right after F669's map parser (disjoint:
  F669 wins its exact terminal first).
- _js_parse_f714_has_trap_iife (+ _js_parse_f714_has_trap,
  _js_parse_f714_trap_body, _js_parse_f714_block_body): `new
  Proxy({}, {has:TRAP})` with constant-true/false or key-param
  `==='LIT'` trap bodies; `var f=('KEY' in p)?'A':'B';return
  f(+'LIT')*;`. Hooked right after F666's has-trap (disjoint:
  F666 requires the direct-return terminal).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g383-*
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


def _decodes_exact(payload, expected):
    """The decoder's value for payload is node-exact."""
    return dlp._try_js_expr_decode_all(payload) == expected


# ------------------------------------------------ p0: pin sanity

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------ p1: filed shapes block

@_t
def test_p1_f713_s1():
    """F713 filed shape 1 (values-join + tail) blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f713-s1=%s" % ok)


@_t
def test_p1_f713_s2():
    """F713 filed shape 2 (bare-spread join + tail) blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f713-s2=%s" % ok)


@_t
def test_p1_f714_s1():
    """F714 filed shape 1 (constant-true has trap) blocks."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f714-s1=%s" % ok)


@_t
def test_p1_f714_s2():
    """F714 filed shape 2 (k==='y' has trap) blocks."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{has:function(t,k){return k==='y';}});"
        "var f=('y' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f714-s2=%s" % ok)


# ------------------------------------------------ p2: F713 generalizations

@_t
def test_p2_f713_keys_tail():
    """F713 keys-spread twin with tail blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['%s','v']]);"
        "return [...m.keys()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "keys-tail=%s" % ok)


@_t
def test_p2_f713_bare_multi():
    """F713 bare spread over multi-pair map decodes node-exactly."""
    ok = _decodes_exact(
        "(function(){var m=new Map([['k','%s'],['j','x']]);"
        "return [...m].join('-')+'%s';})()" % (_A, _B),
        "k," + _A + "-j,x" + _B)
    return ("HELD" if ok else "BREAK", "bare-multi=%s" % ok)


@_t
def test_p2_f713_set_tail():
    """F713 set-tail Map with additive tail blocks."""
    ok = _blocked(
        "(function(){var m=new Map();m.set('k','%s');"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "set-tail=%s" % ok)


@_t
def test_p2_f713_no_tail_bare():
    """F713 bare spread without tail decodes node-exactly."""
    ok = _decodes_exact(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m].join('');})()" % _A,
        "k," + _A)
    return ("HELD" if ok else "BREAK", "bare-no-tail=%s" % ok)


@_t
def test_p2_f713_numeric_key():
    """F713 numeric key stringifies canonically."""
    ok = _blocked(
        "(function(){var m=new Map([[1,'%s']]);"
        "return [...m].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "numkey=%s" % ok)


# ------------------------------------------------ p3: F713 bounds (fail closed)

@_t
def test_p3_f713_nonliteral_value():
    """F713 non-literal Map value fails closed."""
    ok = _misses(
        "(function(){var m=new Map([['k',x]]);"
        "return [...m.values()].join('')+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_f713_nonjoin_terminal():
    """F713 non-join terminal fails closed."""
    ok = _misses(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m.values()].length+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonjoin=%s" % ok)


@_t
def test_p3_f713_nonliteral_tail():
    """F713 non-literal additive tail fails closed."""
    ok = _misses(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m.values()].join('')+x;})()" % _A)
    return ("HELD" if ok else "BREAK", "nontail=%s" % ok)


@_t
def test_p3_f713_spread_other_ident():
    """F713 spread of another ident fails closed."""
    ok = _misses(
        "(function(){var m=new Map([['k','%s']]);var n=m;"
        "return [...n.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "other-ident=%s" % ok)


@_t
def test_p3_f713_extra_stmt():
    """F713 extra statement fails closed."""
    ok = _misses(
        "(function(){var m=new Map([['k','%s']]);var z=1;"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "extra-stmt=%s" % ok)


# ------------------------------------------------ p4: F714 generalizations

@_t
def test_p4_f714_method_shorthand():
    """F714 method-shorthand trap blocks."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{has(t,k){return true;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "method=%s" % ok)


@_t
def test_p4_f714_arrow_trap():
    """F714 concise-arrow trap blocks."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{has:(t,k)=>true});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "arrow=%s" % ok)


@_t
def test_p4_f714_false_trap_else():
    """F714 constant-false trap selects the else branch (no cred)."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return false;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "false-else=%s" % ok)


@_t
def test_p4_f714_eq_mismatch_else():
    """F714 k==='y' trap with 'z' key selects else (no cred)."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return k==='y';}});"
        "var f=('z' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "eq-mismatch=%s" % ok)


@_t
def test_p4_f714_multi_tail():
    """F714 multiple additive tail elements block."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s'+'!';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "multi-tail=%s" % ok)


@_t
def test_p4_f714_let_const():
    """F714 let/const decl forms block."""
    ok = _blocked(
        "(function(){let p=new Proxy({},{has:function(t,k){return true;}});"
        "const f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


# ------------------------------------------------ p5: F714 bounds (fail closed)

@_t
def test_p5_f714_nonempty_target():
    """F714 non-empty target fails closed."""
    ok = _misses(
        "(function(){var p=new Proxy({a:1},{has:function(t,k){return true;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nontarget=%s" % ok)


@_t
def test_p5_f714_extra_trap():
    """F714 extra handler key fails closed."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return true;},get:function(t,k){return 1;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "extra-trap=%s" % ok)


@_t
def test_p5_f714_truthy_not_true():
    """F714 `return 1;` (ToBoolean-unclear) fails closed."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return 1;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "truthy=%s" % ok)


@_t
def test_p5_f714_compare_first_param():
    """F714 comparison on the target param fails closed."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return t==='y';}});"
        "var f=('y' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "first-param=%s" % ok)


@_t
def test_p5_f714_nonliteral_key():
    """F714 non-literal in-key fails closed."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});"
        "var f=(x in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonlit-key=%s" % ok)


@_t
def test_p5_f714_in_other_ident():
    """F714 in-test on another ident fails closed."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});var q=p;"
        "var f=('x' in q)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "other-ident=%s" % ok)


@_t
def test_p5_f714_negated():
    """F714 negated in-test fails closed (unmodeled)."""
    ok = _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});"
        "var f=!('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "negated=%s" % ok)


@_t
def test_p5_f714_truncated_input():
    """F714 truncated bodies fail closed (no IndexError; standards-review catch)."""
    truncs = [
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});"
        "var f=('x' in p)?'a':'xx';return f+",
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});"
        "var f=('x' in p)?'a':'xx';return",
        "(function(){var p=new Proxy({},{has:function(t,k){return true;",
    ]
    ok = True
    for t in truncs:
        try:
            if not _misses(t):
                ok = False
        except Exception:  # noqa: BLE001 -- any raise is a bug
            ok = False
    return ("HELD" if ok else "BREAK", "truncated-closed=%s" % ok)


# ------------------------------------------------ p6: siblings, neighbors, honest

@_t
def test_p6_sibling_f669():
    """Sibling F669 shapes still block."""
    ok = _blocked(
        "(function(){var m=new Map();m.set('a','%s');m.set('b','%s');"
        "return [...m.values()].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f669=%s" % ok)


@_t
def test_p6_sibling_f666():
    """Sibling F666 direct-return has-trap still blocks."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
        "return ('x' in p?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f666=%s" % ok)


@_t
def test_p6_sibling_f686():
    """Sibling F686 ownKeys trap still blocks (filed shape)."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "return Object.keys(p).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)


@_t
def test_p6_neighbor_f715_open():
    """Neighbor F715 now BLOCKS (closed wave-383 lane 2; merge update)."""
    ok = not _misses(
        "(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});"
        "delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f715-closed=%s" % ok)


@_t
def test_p6_neighbor_f716_open():
    """Neighbor F716 now BLOCKS (closed wave-383 lane 2; merge update)."""
    ok = not _misses(
        "(function(){var o={};Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f716-closed=%s" % ok)


@_t
def test_p6_honest_quiet():
    """Honest text stays quiet."""
    ok = _misses("the map of the united states shows state boundaries")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p7: pin, footer, no new regexes

@_t
def test_p7_pin_footer():
    """Pin 2143; lane-local footer (F713/F714 CLOSED; open F715-F737 / next F738)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F762**" in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    ok = ok and ("Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
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
    """200 mixed F713/F714 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var m=new Map([['k','a%d']]);return [...m.values()].join('')+'b';})()" % k)
        corpus.append("(function(){var p=new Proxy({},{has:function(t,k){return true;}});var f=('x' in p)?'a%d':'xx';return f+'b';})()" % k)
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
    for batt, expect_break in (("evals/w382_f713_redfirst.py", 0),
                               ("evals/w382_f714_redfirst.py", 0)):
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
    # w382_attack_probes: the lane-local footer repoint breaks its
    # footer pin by design (merge-owned tree-wide repoint); tolerate
    # exactly that 1 BREAK.
    tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w382_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break, footer_break = 0, 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    real_break -= footer_break
    if real_break != 0:
        bad.append(("evals/w382_attack_probes.py", real_break))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green: %s" % ("ok" if ok else bad))


@_t
def test_p9_green_check():
    """Green check: red-firsts + attack battery stay green (depth-1)."""
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
