#!/usr/bin/env python3
"""Wave-384 lane 8: close F752 + F753.

F752 (LOW, filed 2026-10-08 by wave-383 lane 14 as F750, renumbered at
the wave-383 merge -- lane 6 filed F738/F739 first ~17:30/~17:45 UTC):
F728 residual -- builtin-iterator .next().value. F728 (wave-383)
models direct .next().value reads on DECLARED GENERATOR iterators
only; builtin iterators (array/string [Symbol.iterator](),
Set.values()/.keys(), Map.values()/.keys()) have no modeled path:
(function(){var it=['f1','f2'][Symbol.iterator]();var s='';
s+=it.next().value;s+=it.next().value;return s;})() and
(function(){var s=new Set(['f1','f2']);var it=s.values();var r='';
r+=it.next().value;r+=it.next().value;return r;})() both
node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

F753 (LOW, filed 2026-10-08 by wave-383 lane 14 as F751, renumbered
at the wave-383 merge): spread argument lists (call). The decoder
models spread in array/object literals but not in argument lists:
(function(){function h(){var s='';for(var i=0;
i<arguments.length;i++)s+=arguments[i];return s;}
return h(...['f1','f2']);})() and
(function(){function h(a,b){return a+b;}
return h(...['f1','f2']);})() both node-evaluate to the exact
credential (node v24.20.0) while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f752_builtin_iter_iife (+ _js_parse_f752_iter_source,
  _js_parse_f752_iter_member, _js_parse_f752_bindable,
  _js_parse_f752_next_value): statement-IIFE grammar with an
  optional var-bound Set/Map/array origin, an iterator-source
  declaration, an optional literal accumulator, accumulation
  statements (ACC+=/=/var-bound IT.next().value reads), and a
  string-only return additive. Node-exact (v24.20.0): the n-th
  .next() delivers items[n-1]; Set/Map insertion order (F494/F602
  disciplines); string iteration by code point. Post-exhaustion
  reads, non-empty .next() args, .entries(), Map numeric keys,
  array .keys(), and non-.value members all fail closed. At most
  16 .next() calls; F452 parts charged per call. Hooked after
  F728 (disjoint: F728 requires the function* head).
- _js_parse_f753_spread_call_iife (+ _js_parse_f753_spread_source,
  _js_parse_f753_call_args, _js_parse_f753_args_join_body): the
  named function declaration / arguments-join / var-bound
  function-expression twins; spreads expand in place (array
  literal, new Set dedupe, new Map().values()); the F614 additive
  body is applied via _js_f556_apply. F556/F614 arity precedent:
  extras dropped, fewer args than params fail closed.
- _js_parse_f753_arrow_spread_iife: the ((P)=>ADD)(...[LITS])
  twin (array-literal spreads only -- disjoint from F608/F615).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F752/F753 closed, next F762)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F762**" in text
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F754, F755, F756, F757, F758, F759, F760, F761." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f752_s1():
    """F752 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var it=['%s','%s'][Symbol.iterator]();"
        "var s='';s+=it.next().value;s+=it.next().value;"
        "return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-s1=%s" % ok)


@_t
def test_p1_f752_s2():
    """F752 filed shape 2 blocks."""
    ok = _blocked(
        "(function(){var s=new Set(['%s','%s']);var it=s.values();"
        "var r='';r+=it.next().value;r+=it.next().value;"
        "return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-s2=%s" % ok)


@_t
def test_p1_f753_s1():
    """F753 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){function h(){var s='';"
        "for(var i=0;i<arguments.length;i++)s+=arguments[i];"
        "return s;}return h(...['%s','%s']);})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-s1=%s" % ok)


@_t
def test_p1_f753_s2():
    """F753 filed shape 2 blocks."""
    ok = _blocked(
        "(function(){function h(a,b){return a+b;}"
        "return h(...['%s','%s']);})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-s2=%s" % ok)


# --------------------------------------------- node-exact variants (p2)

@_t
def test_p2_f752_string_iter():
    """F752: string code-point iteration (node-exact)."""
    ok = _blocked(
        "(function(){var it='%s'[Symbol.iterator]();var s='';"
        "s+=it.next().value;s+=it.next().value;s+=it.next().value;"
        "s+=it.next().value;s+=it.next().value;s+=it.next().value;"
        "s+=it.next().value;s+=it.next().value;s+=it.next().value;"
        "return s+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-str=%s" % ok)


@_t
def test_p2_f752_set_keys():
    """F752: Set.keys() alias of values (node-exact)."""
    ok = _blocked(
        "(function(){var it=new Set(['%s','%s']).keys();"
        "return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-keys=%s" % ok)


@_t
def test_p2_f752_map_values():
    """F752: Map.values() insertion order (node-exact)."""
    ok = _blocked(
        "(function(){var it=new Map([['k1','%s'],['k2','%s']]).values();"
        "var s='';s+=it.next().value;s+=it.next().value;"
        "return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-mapvals=%s" % ok)


@_t
def test_p2_f752_map_keys():
    """F752: Map.keys() string keys (node-exact)."""
    ok = _blocked(
        "(function(){var it=new Map([['%s','x'],['%s','y']]).keys();"
        "return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-mapkeys=%s" % ok)


@_t
def test_p2_f752_bound_array():
    """F752: var-bound array source (node-exact)."""
    ok = _blocked(
        "(function(){var a=['%s','%s'];var it=a[Symbol.iterator]();"
        "return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-boundarr=%s" % ok)


@_t
def test_p2_f752_bound_read():
    """F752: var-bound single read + additive (node-exact)."""
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);var it=m.values();"
        "var x=it.next().value;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f752-boundread=%s" % ok)


@_t
def test_p2_f752_set_dedupe():
    """F752: Set dedupe before iteration (node-exact)."""
    ok = _blocked(
        "(function(){var it=new Set(['%s','%s','%s']).values();"
        "return it.next().value+it.next().value;})()" % (_A, _A, _B))
    return ("HELD" if ok else "BREAK", "f752-dedupe=%s" % ok)


@_t
def test_p2_f753_set_spread():
    """F753: new Set spread args (node-exact dedupe)."""
    ok = _blocked(
        "(function(){function h(a,b){return a+b;}"
        "return h(...new Set(['%s','%s']));})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-set=%s" % ok)


@_t
def test_p2_f753_map_spread():
    """F753: new Map().values() spread args (node-exact)."""
    ok = _blocked(
        "(function(){function h(a,b){return a+b;}"
        "return h(...new Map([['k1','%s'],['k2','%s']]).values());})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-map=%s" % ok)


@_t
def test_p2_f753_mixed_args():
    """F753: literal + multiple spreads expand in place (node-exact)."""
    ok = _blocked(
        "(function(){function h(a,b,c){return a+b+c;}"
        "return h('xoxb-',...['%s'],...['%s']);})()"
        % (_A[5:], _B))
    return ("HELD" if ok else "BREAK", "f753-mixed=%s" % ok)


@_t
def test_p2_f753_tail():
    """F753: additive literal tail after spread call (node-exact)."""
    ok = _blocked(
        "(function(){function h(a){return a;}"
        "return h(...['%s'])+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-tail=%s" % ok)


@_t
def test_p2_f753_varbound_fn():
    """F753: var-bound function expression twin (node-exact)."""
    ok = _blocked(
        "(function(){var h=function(a,b){return a+b;};"
        "return h(...['%s','%s']);})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-varexpr=%s" % ok)


@_t
def test_p2_f753_arrow():
    """F753: arrow-IIFE array-spread twin (node-exact)."""
    ok = _blocked("((a,b)=>a+b)(...['%s','%s'])" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-arrow=%s" % ok)


@_t
def test_p2_f753_join_twins():
    """F753: arguments-join update/body twins (node-exact)."""
    twins = [
        "(function(){function h(){var s='';for(var i=0;i<arguments.length;i++)s=s+arguments[i];return s;}return h(...['%s','%s']);})()",
        "(function(){function h(){var s='';for(var i=0;i<arguments.length;++i)s+=arguments[i];return s;}return h(...['%s','%s']);})()",
        "(function(){function h(){var s='';for(var i=0;i<arguments.length;i+=1)s+=arguments[i];return s;}return h(...['%s','%s']);})()",
        "(function(){function h(){var s='';for(var i=0;i<arguments.length;i++){s+=arguments[i];}return s;}return h(...['%s','%s']);})()",
    ]
    bad = [t for t in twins if not _blocked(t % (_A, _B))]
    ok = not bad
    return ("HELD" if ok else "BREAK", "f753-jointwins=%s" % (bad if bad else "ok"))


# ------------------------------------------------- fail-closed bounds (p3)

@_t
def test_p3_f752_exhaustion():
    """F752: .next() past exhaustion fails closed (engine undefined)."""
    ok = _misses(
        "(function(){var it=['a'][Symbol.iterator]();it.next();"
        "it.next();return it.next().value;})()")
    return ("HELD" if ok else "BREAK", "f752-exhaust=%s" % ok)


@_t
def test_p3_f752_next_args():
    """F752: non-empty .next() args fail closed (F728 precedent)."""
    ok = _misses(
        "(function(){var it=['a'][Symbol.iterator]();"
        "return it.next(0).value;})()")
    return ("HELD" if ok else "BREAK", "f752-nextargs=%s" % ok)


@_t
def test_p3_f752_entries():
    """F752: .entries() fails closed (yields pairs)."""
    ok = _misses(
        "(function(){var it=new Map([['k','v']]).entries();"
        "return it.next().value;})()")
    return ("HELD" if ok else "BREAK", "f752-entries=%s" % ok)


@_t
def test_p3_f752_map_numkey():
    """F752: Map numeric keys fail closed (engine yields numbers)."""
    ok = _misses(
        "(function(){var it=new Map([[1,'a']]).keys();"
        "return it.next().value;})()")
    return ("HELD" if ok else "BREAK", "f752-mapnumkey=%s" % ok)


@_t
def test_p3_f752_array_keys():
    """F752: array .keys() fails closed (index keys are numbers)."""
    ok = _misses(
        "(function(){var it=['a','b'].keys();"
        "return it.next().value;})()")
    return ("HELD" if ok else "BREAK", "f752-arrkeys=%s" % ok)


@_t
def test_p3_f752_done_member():
    """F752: non-.value members fail closed."""
    ok = _misses(
        "(function(){var it=['a'][Symbol.iterator]();"
        "return it.next().done;})()")
    return ("HELD" if ok else "BREAK", "f752-done=%s" % ok)


@_t
def test_p3_f752_two_iterators():
    """F752: a second iterator binding fails closed."""
    ok = _misses(
        "(function(){var a=['x'][Symbol.iterator]();"
        "var b=['y'][Symbol.iterator]();"
        "return a.next().value;})()")
    return ("HELD" if ok else "BREAK", "f752-twoiter=%s" % ok)


@_t
def test_p3_f752_unbound_source():
    """F752: unbound iterator source fails closed."""
    ok = _misses(
        "(function(){var it=q.values();"
        "return it.next().value;})()")
    return ("HELD" if ok else "BREAK", "f752-unbound=%s" % ok)


@_t
def test_p3_f752_wrong_accum_target():
    """F752: accumulation into a non-accumulator ident fails closed
    (standards-review catch: aname was unchecked)."""
    ok = _misses(
        "(function(){var it=['f1','f2'][Symbol.iterator]();var s='';"
        "x+=it.next().value;return s;})()")
    ok2 = _misses(
        "(function(){var it=['f1','f2'][Symbol.iterator]();"
        "s+=it.next().value;return s;})()")
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "f752-wrongacc=%s" % ok)


@_t
def test_p3_f752_map_iterator():
    """F752: Map [Symbol.iterator]() fails closed -- the engine yields
    entry pairs, not keys (spec-review catch)."""
    ok = _misses(
        "(function(){var it=new Map([['k','v']])[Symbol.iterator]();"
        "return it.next().value;})()")
    ok2 = _misses(
        "(function(){var m=new Map([['k','v']]);"
        "var it=m[Symbol.iterator]();return it.next().value;})()")
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "f752-mapiter=%s" % ok)


@_t
def test_p3_f753_fewer_args():
    """F753: fewer args than params fails closed (engine undefined)."""
    ok = _misses(
        "(function(){function h(a,b){return a+b;}"
        "return h(...['x']);})()")
    return ("HELD" if ok else "BREAK", "f753-fewer=%s" % ok)


@_t
def test_p3_f753_nonliteral_spread():
    """F753: spread of a non-literal source fails closed."""
    ok = _misses(
        "(function(){function h(a){return a;}var x=['f1'];"
        "return h(...x);})()")
    return ("HELD" if ok else "BREAK", "f753-nonlitspread=%s" % ok)


@_t
def test_p3_f753_nonliteral_arg():
    """F753: non-literal call args fail closed."""
    ok = _misses(
        "(function(){function h(a,b){return a+b;}"
        "return h(...['x'],y);})()")
    return ("HELD" if ok else "BREAK", "f753-nonlitarg=%s" % ok)


@_t
def test_p3_f753_callee_mismatch():
    """F753: callee name mismatch fails closed."""
    ok = _misses(
        "(function(){function h(a){return a;}"
        "return g(...['x']);})()")
    return ("HELD" if ok else "BREAK", "f753-calleemis=%s" % ok)


@_t
def test_p3_f753_construct():
    """F753: new C(...xs) fails closed (documented residual)."""
    ok = _misses(
        "(function(){function C(a){this.v=a;}"
        "var c=new C(...['x']);return c.v;})()")
    return ("HELD" if ok else "BREAK", "f753-construct=%s" % ok)


@_t
def test_p3_f753_generator():
    """F753: generator functions fail closed."""
    ok = _misses(
        "(function(){function* h(a){yield a;}"
        "return h(...['x']);})()")
    return ("HELD" if ok else "BREAK", "f753-gen=%s" % ok)


@_t
def test_p3_f753_join_with_params():
    """F753: arguments-join twin with params fails closed."""
    ok = _misses(
        "(function(){function h(a){var s='';"
        "for(var i=0;i<arguments.length;i++)s+=arguments[i];"
        "return s;}return h(...['x']);})()")
    return ("HELD" if ok else "BREAK", "f753-joinparams=%s" % ok)


# ------------------------------------------------------ siblings intact (p4)

@_t
def test_p4_sibling_f728():
    """F728 declared-generator .next().value still decodes."""
    ok = _blocked(
        "(function(){function* G(){yield '%s';}var it=G();"
        "return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "sib-f728=%s" % ok)


@_t
def test_p4_sibling_f608():
    """F608 Set-spread arrow IIFE still decodes."""
    ok = _blocked("((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B))
    return ("HELD" if ok else "BREAK", "sib-f608=%s" % ok)


@_t
def test_p4_sibling_f614():
    """F614 .call dispatch still decodes."""
    ok = _blocked("((a,b)=>a+b).call(null,'%s','%s')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f614=%s" % ok)


@_t
def test_p4_sibling_f735():
    """F735 literal-arg nested call still decodes."""
    ok = _blocked(
        "(function(){function h(a,b){return a+b;}"
        "return h('%s','%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "sib-f735=%s" % ok)


@_t
def test_p4_sibling_f556():
    """F556 .bind dispatch still decodes."""
    ok = _blocked("((a)=>(a+'%s')).bind(null,'%s')()" % (_B, _A))
    return ("HELD" if ok else "BREAK", "sib-f556=%s" % ok)


# ------------------------------------------------- junk quiet + perf (p5)

@_t
def test_p5_junk_quiet():
    """Honest text stays quiet."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


@_t
def test_p5_honest_iterators():
    """Honest iterator reads stay quiet."""
    quiet = _misses(
        "(function(){var it=['a','b'][Symbol.iterator]();"
        "return it.next().value;})()")
    return ("HELD" if quiet else "BREAK", "honest-iter=%s" % quiet)


@_t
def test_p5_perf():
    """200 mixed sites decode in reasonable time."""
    site = ("(function(){var it=['%s','%s'][Symbol.iterator]();"
            "return it.next().value+it.next().value;})()" % ("ab", "cd"))
    blob = ("junk " + site + " ") * 200
    t0 = time.time()
    dlp.find_credential(blob)
    dt = time.time() - t0
    ok = dt < 30
    return ("HELD" if ok else "BREAK", "perf=%.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, tolerated_breaks): the attack battery's footer pin is
    # stale by design -- the lane-local footer repoint is merge-owned
    # (wave-305/306 class).
    for batt, tolerated in (("evals/w383_f752_redfirst.py", 0),
                            ("evals/w383_f753_redfirst.py", 0),
                            ("evals/w383_attack_probes.py", 1)):
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
        elif nbreak != tolerated:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: red-firsts + attack battery green."""
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
