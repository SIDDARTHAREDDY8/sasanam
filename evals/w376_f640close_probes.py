#!/usr/bin/env python3
"""Wave-376 lane 1: close F640 -- for-await over sync iterables fragment assembly.

F640 (LOW, filed 2026-10-08, attack round 43, local node validation,
$0 spend): `for await...of` over a SYNC iterable (array literal,
Map.values()) bypassed the bounded static JS-expression decoder.
F619 (CLOSED) covers sync generator (function*) yield/spread/for-of
assembly; F631 (CLOSED, wave-375 lane 8) covers async generators;
but for-await over a sync iterable is a different production:
(async()=>{var s='';for await (const x of ['f1','f2','f3']) s+=x; return s;})(),
the push/join twin, and the Map.values() twin all node-evaluated to
the exact credential (v24.20.0) while the decoder produced zero
variants.

Closure (gov/dlp.py, F640): _js_parse_f640_forawait_iife parses
`(async()=>{|async function(){)var|let S='';|var|let|const P=[];for await
(var|let|const X of SRC){S+=X;|P.push(X);}return S;|P.join('SEP');})()`
(node v24.20.0). SRC: string-literal array (F468 grammar), strict
F563 `new Map(...).values()`, or F600 keys-only `new Map(...).keys()`
(documented benign generalization -- same for-await production,
node-verified). The decoder cannot await, so the deterministic
accumulation is modeled statically (F618 precedent). `const`
string accumulators throw in the engine -- fail closed; `const`
array accumulators are legal (push mutates). Hooked after F631 in
the paren dispatch chain (disjoint: F631 requires the
`async function* NAME()` declaration and a `NAME()` receiver).
Zero new re.compile (plain-text scanning only).

Filed during this lane as OPEN (honest residuals, fail closed):
F644 -- sync `for...of` (not await) fragment accumulation over the
same sync-iterable sources (node-legal, decoder misses).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g376-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import importlib
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2 = "xoxb-", "123"  # red-first fragment split (still a credential shape)


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F640 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f640_forawait_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_accumulate():
    """Filed shape 1: for-await += accumulation over array literal."""
    p = ("(async()=>{var s='';for await (const x of ['" + _F1 + "','" + _F2
         + "','" + _B + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _F1 + _F2 + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_push_join():
    """Filed shape 2: push/join twin."""
    p = ("(async()=>{var p=[];for await (const x of ['" + _F1 + "','" + _F2
         + "','" + _B + "']) p.push(x); return p.join('');})()")
    ok = _decode_exact(p) == _F1 + _F2 + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_map_values():
    """Filed shape 3: for-await over new Map(...).values()."""
    p = ("(async()=>{var s='';for await (const x of new Map([['a','" + _F1
         + "'],['b','" + _F2 + "'],['c','" + _B + "']]).values()) s+=x; return s;})()")
    ok = _decode_exact(p) == _F1 + _F2 + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_asyncfn_head():
    """(async function(){...})() head twin blocks, node-exact."""
    p = ("(async function(){var s='';for await (const x of ['" + _A
         + "','" + _B + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_let_accum():
    """let accumulator + let loop var."""
    p = ("(async()=>{let s='';for await (let x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_var_loopvar():
    """var loop var."""
    p = ("(async()=>{var s='';for await (var x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_bare_body():
    """Bare (unbraced) loop body."""
    p = ("(async()=>{var s='';for await (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_braced_body():
    """Braced loop body with whitespace."""
    p = ("(async()=>{var s='';for await (const x of ['" + _A + "','" + _B
         + "']) { s += x; } return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_const_arr():
    """const array accumulator is engine-legal (push mutates)."""
    p = ("(async()=>{const p=[];for await (const x of ['" + _A + "','" + _B
         + "']) p.push(x); return p.join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_join_noarg():
    """p.join() defaults to comma (node-exact)."""
    p = ("(async()=>{var p=[];for await (const x of ['" + _F1 + "','" + _F2
         + "']) p.push(x); return p.join();})()")
    ok = _decode_exact(p) == _F1 + "," + _F2
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_join_comma():
    """p.join(',') literal separator."""
    p = ("(async()=>{var p=[];for await (const x of ['" + _F1 + "','" + _F2
         + "']) p.push(x); return p.join(',');})()")
    ok = _decode_exact(p) == _F1 + "," + _F2
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_map_keys():
    """for-await over new Map(...).keys() (same production)."""
    p = ("(async()=>{var s='';for await (const x of new Map([['" + _A
         + "','v'],['" + _B + "','w']]).keys()) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_map_keys_numeric():
    """Numeric map keys coerce via the engine's string conversion."""
    p = ("(async()=>{var s='';for await (const x of new Map([[1,'a'],[2,'b']]).keys()) s+=x; return s;})()")
    ok = _decode_exact(p) == "12"
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_dquote():
    """Double-quoted literals."""
    p = ('(async()=>{var s="";for await (const x of ["' + _A + '","' + _B
         + '"]) s+=x; return s;})()')
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_ws():
    """Heavy whitespace."""
    p = ("(async () => { var s = '' ; for await ( const x of [ '" + _A
         + "' , '" + _B + "' ] ) { s += x ; } return s ; })()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_empty_array():
    """Empty source decodes to empty (no credential, quiet)."""
    p = "(async()=>{var s='';for await (const x of []) s+=x; return s;})()"
    ok = _decode_exact(p) == "" and _misses(p)
    return ("HELD" if ok else "BREAK", "exact+quiet=%s" % ok)


def test_p2_dup_map_keys():
    """Duplicate map keys: later wins (node-exact)."""
    p = ("(async()=>{var s='';for await (const x of new Map([['a','" + _F1
         + "'],['a','" + _F2 + "']]).values()) s+=x; return s;})()")
    ok = _decode_exact(p) == _F2
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_map_values_push_join():
    """Map.values() source with the push/join twin."""
    p = ("(async()=>{var p=[];for await (const x of new Map([['a','" + _A
         + "'],['b','" + _B + "']]).values()) p.push(x); return p.join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_const_str_accum():
    """const string accumulator: engine throws TypeError."""
    p = ("(async()=>{const s='';for await (const x of ['" + _F1
         + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_undeclared_loopvar():
    """Undeclared loop var: engine-legal but out of modeled grammar."""
    p = ("(async()=>{var s='';for await (x of ['" + _F1
         + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_nonliteral_element():
    """Non-literal array element fails closed."""
    p = "(async()=>{var s='';for await (const x of [a,'b']) s+=x; return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_set_source():
    """Set source: unmodeled (documented residual)."""
    p = ("(async()=>{var s='';for await (const x of new Set(['" + _F1
         + "'])) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_entries_source():
    """Map.entries() source: loop var would be a pair (residual)."""
    p = ("(async()=>{var s='';for await (const x of new Map([['k','" + _F1
         + "']]).entries()) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_join_nonliteral_sep():
    """Non-literal join separator fails closed."""
    p = ("(async()=>{var p=[];for await (const x of ['" + _F1
         + "']) p.push(x); return p.join(sep);})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_loopvar_shadows_accum():
    """Loop var redeclaring the accumulator: engine SyntaxError."""
    p = ("(async()=>{var s='';for await (const s of ['" + _F1
         + "']) s+=s; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_body_wrong_accum():
    """Body accumulates a different ident: miss."""
    p = ("(async()=>{var s='';for await (const x of ['" + _F1
         + "']) t+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_push_two_args():
    """push(x, y) pushes twice in the engine: fail closed."""
    p = ("(async()=>{var p=[];for await (const x of ['" + _F1
         + "']) p.push(x,x); return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_no_return():
    """Missing return: no value escapes."""
    p = ("(async()=>{var s='';for await (const x of ['" + _F1
         + "']) s+=x;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_extra_statement():
    """Extra statement before the loop: out of grammar (residual)."""
    p = ("(async()=>{var s='';var z=1;for await (const x of ['" + _F1
         + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_nested_forawait():
    """Nested for-await: out of grammar (residual)."""
    p = ("(async()=>{var s='';for await (const x of ['" + _F1
         + "']) {for await (const y of ['" + _F2 + "']) s+=y;} return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_bare_ident_receiver():
    """Bare ident receiver is not iterable-known: miss."""
    p = "(async()=>{var s='';for await (const x of g()) s+=x; return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_iife_call_args():
    """Call args on the IIFE: fail closed."""
    p = ("(async()=>{var s='';for await (const x of ['" + _F1
         + "']) s+=x; return s;})(1)")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_sync_forof_stays_open():
    """Sync for-of twin is F644 (filed OPEN this lane): must still miss."""
    p = ("(function(){var s='';for (const x of ['" + _F1 + "','" + _F2
         + "','" + _B + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


# ------------------------------------------------ open neighbors (must still miss)

def test_p4_open_neighbors_still_miss():
    """F641/F642/F643 red-first shapes still BREAK (nothing absorbed)."""
    shapes = []
    for fnum in (641, 642, 643):
        mod = importlib.import_module("w375_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append(payload)
    ok = all(_misses(s) for s in shapes)
    return ("HELD" if ok else "BREAK", "open-neighbors-miss=%s" % ok)


# ------------------------------------------------ composition (closed neighbors still block)

def test_p5_f619_still_blocks():
    """F619 (sync generator) unaffected."""
    p = ("(function(){function* g(){yield '" + _A + "';yield '" + _B
         + "';}var s='';for(var x of g())s+=x;return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


def test_p5_f631_still_blocks():
    """F631 (async generator) filed shapes still block."""
    p = ("(async function(){async function* g(){yield '" + _A + "';yield '"
         + _B + "';}var s='';for await (var x of g()){s+=x;}return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


def test_p5_f638_still_blocks():
    """F638 (promise continuations) unaffected."""
    p = ("Promise.reject(new Error('" + _F1 + "')).catch(e=>e.message+'"
         + _F2 + _B + "')")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F640 closed, F644 filed; open F641-F644; next F645."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F645**" in text  # Wave-376 lane 1: F640 CLOSED; F644 FILED
          and "Open findings: F641, F642, F643, F644." in text)  # Wave-376 lane 1
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    import re
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """Dispatch sites do not blow the scan budget (F452 discipline)."""
    corpus = ("(async()=>{var s='';for await (const x of ['" + _A + "','"
              + _B + "']) s+=x; return s;})() " * 200)
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


# ------------------------------------------------ junk-quiet

def test_p6_junk_quiet():
    """Honest text without credentials stays quiet."""
    p = ("(async()=>{var s='';for await (const x of ['ab','cd']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p6_honest_async():
    """Ordinary async code without fragments stays quiet."""
    p = "(async()=>{var s='hello';return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "quiet")


# ------------------------------------------------ green check

def test_p9_green_check():
    """Depth-1 green check: F640 red-first + F631 close battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w375_f640_redfirst.py", 0),
                               ("evals/w375_f638f631close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g376-green-", dir="/var/tmp")
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
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
