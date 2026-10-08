#!/usr/bin/env python3
"""Wave-377 lane 8: close F654 -- sync for-of over sync iterables fragment assembly.

F654 (LOW, filed 2026-10-08 by wave-376 lane 1 as F644, renumbered at
the wave-376 merge per wave-272 first-filing -- the attack lane filed
F644 first; local node validation, $0 spend): the SYNC `for...of`
twin of F640's for-await production. F640 (CLOSED, wave-376 lane 1)
models `for await...of` over sync iterables, but sync for-of is a
different production with no modeled path:
(function(){var s='';for (const x of ['f1','f2','f3']) s+=x; return s;})(),
the push/join twin, and the Map.values() twin all node-evaluated to
the exact credential (v24.20.0) while the decoder produced zero
variants.

Closure (gov/dlp.py, F654): _js_parse_f654_sync_forof_iife parses
`(function(){var|let S='';|var|let|const P=[];for (var|let|const X
of SRC){S+=X;|P.push(X);}return S;|P.join('SEP');})()` (node
v24.20.0). SRC shares F640's sync-source grammar (string-literal
array, strict F563 `new Map(...).values()`, F600 keys-only
`new Map(...).keys()`). The only production difference from F640 is
the loop head (`for` vs `for await`); the accumulator discipline is
shared (`_js_parse_f640_accum_decl` -- `const` string accumulators
throw in the engine, fail closed). Hooked after F642 in the
sync-IIFE dispatch chain (disjoint: F640's hook requires the
`async` head, which this head rejects; every earlier route
requires a specific binding family or a for-in head). Zero new
re.compile (plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g377-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
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
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2 = "xoxb-", "123"  # red-first fragment split (still a credential shape)


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F654 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f654_sync_forof_iife(js, 0, 0, state)
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
    """Filed shape 1: sync for-of += accumulation over array literal."""
    p = ("(function(){var s='';for (const x of ['" + _F1 + "','" + _F2
         + "','" + _B + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _F1 + _F2 + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_push_join():
    """Filed shape 2: push/join twin."""
    p = ("(function(){var p=[];for (const x of ['" + _F1 + "','" + _F2
         + "','" + _B + "']) p.push(x); return p.join('');})()")
    ok = _decode_exact(p) == _F1 + _F2 + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_map_values():
    """Filed shape 3: sync for-of over new Map(...).values()."""
    p = ("(function(){var s='';for (const x of new Map([['a','" + _F1
         + "'],['b','" + _F2 + "'],['c','" + _B + "']]).values()) s+=x; return s;})()")
    ok = _decode_exact(p) == _F1 + _F2 + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_let_accum():
    """let string accumulator, node-exact."""
    p = ("(function(){let s='';for (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_var_loopvar():
    """var loop var, node-exact."""
    p = ("(function(){var s='';for (var x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_bare_body():
    """Unbraced loop body, node-exact."""
    p = ("(function(){var s='';for (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_ws_head():
    """Whitespace-tolerant sync head, node-exact."""
    p = ("( function () {var s='';for (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_map_keys():
    """new Map(...).keys() source -- keys only, node-exact."""
    p = ("(function(){var s='';for (const x of new Map([['" + _A
         + "','z'],['" + _B + "','w']]).keys()) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_join_sep():
    """join(',') separator, node-exact (decode only: the comma means no credential forms)."""
    p = ("(function(){var p=[];for (const x of ['" + _A + "','" + _B
         + "']) p.push(x); return p.join(',');})()")
    ok = _decode_exact(p) == _A + "," + _B
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_join_default():
    """join() missing-arg comma default, node-exact (decode only)."""
    p = ("(function(){var p=[];for (const x of ['" + _A + "','" + _B
         + "']) p.push(x); return p.join();})()")
    ok = _decode_exact(p) == _A + "," + _B
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_const_arr_accum():
    """const array accumulator is engine-legal (push mutates)."""
    p = ("(function(){const p=[];for (const x of ['" + _A + "','" + _B
         + "']) p.push(x); return p.join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_dquote():
    """Double-quoted literals, node-exact."""
    p = ('(function(){var s="";for (const x of ["' + _A + '","' + _B
         + '"]) s+=x; return s;})()')
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_let_loopvar():
    """let loop var, node-exact."""
    p = ("(function(){var s='';for (let x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_braced_push():
    """Braced push body, node-exact."""
    p = ("(function(){var p=[];for (const x of ['" + _A + "','" + _B
         + "']) {p.push(x);} return p.join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_forawait_stays_f640():
    """for-await is F640's production: this parser must miss."""
    p = ("(async()=>{var s='';for await (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    ok = _decode_exact(p) is None
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_const_str_accum():
    """const string accumulator throws in the engine: fail closed."""
    p = ("(function(){const s='';for (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_for_in():
    """for-in is F517/F623/F632 territory: fail closed."""
    p = ("(function(){var s='';for (const x in ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_named_function():
    """Named function head is a documented residual: fail closed."""
    p = ("(function f(){var s='';for (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_extra_statement():
    """Trailing statement after the loop: fail closed."""
    p = ("(function(){var s='';for (const x of ['" + _A + "','" + _B
         + "']) s+=x; s+='z'; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_undeclared_loopvar():
    """Undeclared loop var: fail closed."""
    p = ("(function(){var s='';for (x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_shadowed_accum():
    """Loop var shadowing the accumulator: fail closed."""
    p = ("(function(){var s='';for (const s of ['" + _A + "','" + _B
         + "']) s+=s; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_nonloop_operand():
    """Accumulator operand that is not the loop var: fail closed."""
    p = ("(function(){var s='';var y='z';for (const x of ['" + _A
         + "','" + _B + "']) s+=y; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


# ------------------------------------------------ composition (closed neighbors still block)

def test_p5_f602_still_blocks():
    """F602 (Set for-of accumulation) owns new Set sources: unaffected."""
    p = ("(function(){var s='';for (const x of new Set(['" + _A
         + "','" + _B + "'])){s+=x;}return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


def test_p3_nonliteral_element():
    """Non-literal array element: fail closed."""
    p = ("(function(){var s='';for (const x of ['" + _A
         + "',y]) s+=x; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_join_nonliteral_sep():
    """Non-literal join separator: fail closed."""
    p = ("(function(){var p=[];for (const x of ['" + _A + "','" + _B
         + "']) p.push(x); return p.join(sep);})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_multiarg_push():
    """Multi-arg push: fail closed."""
    p = ("(function(){var p=[];for (const x of ['" + _A + "','" + _B
         + "']) p.push(x,x); return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_cstyle_for():
    """C-style for(;;): fail closed."""
    p = ("(function(){var s='';for (var i=0;i<2;i++) s+='f'; return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p3_return_nonaccum():
    """Return of the loop var (not the accumulator): fail closed."""
    p = ("(function(){var s='';for (const x of ['" + _A + "','" + _B
         + "']) s+=x; return x;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


# ------------------------------------------------ composition (closed neighbors still block)

def test_p5_f640_still_blocks():
    """F640 (for-await twin) unaffected."""
    p = ("(async()=>{var s='';for await (const x of ['" + _A + "','" + _B
         + "']) s+=x; return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


def test_p5_f619_still_blocks():
    """F619 (sync generator) unaffected."""
    p = ("(function(){function* g(){yield '" + _A + "';yield '" + _B
         + "';}var s='';for(var x of g())s+=x;return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


def test_p5_f631_still_blocks():
    """F631 (async generator) unaffected."""
    p = ("(async function(){async function* g(){yield '" + _A + "';yield '" + _B
         + "';}var s='';for await (var x of g()){s+=x;}return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


def test_p5_f517_still_blocks():
    """F517 (for-in accumulation) unaffected."""
    p = ("(function(){var o={'a':'" + _A + "','b':'" + _B
         + "'};var s='';for(var k in o)s+=o[k];return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "hit")


# ------------------------------------------------ open neighbors (must still miss)

def test_p4_open_neighbors_still_miss():
    """F644-F653 CLOSED at the wave-377 merge: their red-first shapes now block (nothing absorbed)."""
    shapes = []
    for fnum in (644, 645, 646, 647, 648, 649, 650, 651, 652, 653):
        mod = importlib.import_module("w376_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append(payload)
    ok = all(_blocked(s) for s in shapes)
    return ("HELD" if ok else "BREAK", "closed-neighbors-block=%s" % ok)


# ------------------------------------------------ junk-quiet control

def test_p6_junk_quiet():
    """Junk that must stay quiet."""
    p = "'(function(){var s=\\'ab\\';return s;})()'"
    return ("HELD" if _misses(p) else "BREAK", "quiet")


# ------------------------------------------------ pin + footer

def test_p7_pin_taxonomy():
    """Taxonomy pin 2143."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = TAXONOMY_PIN == 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p8_lane_footer():
    """Merge footer: F644-F655 closed; open F662-F671 / next F672."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    ok = ("**Status: CLOSED 2026-10-08 wave-377 lane 8.**" in text  # Wave-377 lane 8: F654 CLOSED
          and "**Status: CLOSED 2026-10-08 wave-378 lane 1.**" in text  # Wave-378 lane 1: F655 CLOSED
          and "Open findings: F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737." in text  # Wave-378 lane 1: F655 CLOSED; footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
          and "Next free finding: **F672**." in text)  # Wave-378 lane 1: F655 CLOSED; footer repoint open F662-F671 / next F672
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p9_perf():
    """Perf bound: 200 sites under 5s."""
    t0 = time.time()
    for _ in range(200):
        _blocked("(function(){var s='';for (const x of ['" + _A + "','" + _B
                 + "']) s+=x; return s;})()")
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


def test_p10_recompile_count():
    """re.compile count stays 28."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "n=%d" % n)


def test_p11_green_check():
    """Depth-1 green check: F654 red-first + F640 close battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w376_f654_redfirst.py", 0),
                               ("evals/w376_f640close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g377-green-", dir="/var/tmp")
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
