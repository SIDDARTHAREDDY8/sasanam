#!/usr/bin/env python3
"""Wave-375 lane 9: close F639 -- nested var-bound Object.values/entries paths.

F639 (LOW, filed 2026-10-08 at the wave-374 merge -- merge-time
re-verification of lane 1's F612 closure, local node validation,
$0 spend): nested var-bound Object.values/entries paths bypassed the
bounded static JS-expression decoder. F612 (CLOSED, wave-374 lane 1)
resolves Object.values/Object.entries through a var-bound
intermediate, but only when the call argument is the BARE bound
ident; member-access paths on the intermediate
(`Object.values(o.x)`) escaped:
(function(){var o={x:{p:'f1'},y:{q:'f2'}};
return Object.values(o.x).concat(Object.values(o.y)).join('');})()
and the entries twin
(function(){var o={x:{p:'f1'},y:{q:'f2'}};
return Object.entries(o.x).map(e=>e[1]).join('')
+Object.entries(o.y).map(e=>e[1]).join('');})()
both node-evaluated to the exact credential (v24.20.0) while the
decoder produced zero variants.

Closure (gov/dlp.py, F639):
_js_parse_f639_nested_values_varbound_iife parses
`(function(){DECL o=NESTED;return TERM;})()`: the var binds an
object literal (F535 grammar) whose values are ALL nested object
literals, each enumerated with the F510 string-only discipline
(_js_f639_enumerate_obj -- integer-index keys ascending first,
then string keys in insertion order; symbol keys skipped
engine-exactly). The return is an additive of nested terms:
`Object.values(o.M)` / `Object.entries(o.M).map(P=>P[0|1])`
terms composed by `.concat(...)` before a single postfix tail, or
`+`-joined string summands (each side `.join('')`d first --
node-exact; `+` on non-strings fails closed). Hooked after F617 in
the statement-IIFE chain (disjoint: F612 requires the bare bound
ident; F599/F606/F610/F616/F617 require URLSearchParams/URL
bindings). Zero new re.compile (plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g375-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
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


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F639 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f639_nested_values_varbound_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001
        verdict, note = "BREAK", "ERROR %r" % e
    results.append((name, verdict, note))
    print("%-42s %s (%s)" % (name, verdict, note))


def test_p1_filed_values():
    """Filed shape 1: nested values + concat + join."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
         "return Object.values(o.x).concat(Object.values(o.y)).join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "filed-values")


def test_p1_filed_entries():
    """Filed shape 2: nested entries + map + join, +-joined."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
         "return Object.entries(o.x).map(e=>e[1]).join('')"
         "+Object.entries(o.y).map(e=>e[1]).join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "filed-entries")


def test_p2_bracket_member():
    """o['x'] bracket-string member path (full credential: exact + hit)."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
         "return Object.values(o['x']).concat(Object.values(o['y'])).join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "bracket-member")


def test_p2_dquote_member():
    """o["x"] double-quoted member path."""
    p = ('(function(){var o={x:{p:\'' + _A + '\'},y:{q:\'' + _B + '\'}};'
         'return Object.values(o["x"]).concat(Object.values(o["y"])).join("");})()')
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "dquote-member")


def test_p2_bracket_call_member():
    """Object['values'](o.x) bracket-string call member."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
         "return Object['values'](o.x).concat(Object['values'](o.y)).join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "bracket-call")


def test_p2_bracket_entries():
    """Object['entries'](o['x']).map(e=>e[1]) twin."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
         "return Object['entries'](o['x']).map(e=>e[1]).join('')"
         "+Object['entries'](o['y']).map(e=>e[1]).join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "bracket-entries")


def test_p2_entries_keys():
    """Entries keys projection: .map(e=>e[0]) decodes exactly."""
    p = ("(function(){var o={x:{p:'" + _A + "',q:'" + _B + "'}};"
         "return Object.entries(o.x).map(e=>e[0]).join('');})()")
    ok = _decode_exact(p) == "pq"
    return ("HELD" if ok else "BREAK", "entries-keys")


def test_p2_entries_block_projection():
    """Entries projection with block body {return e[0];}."""
    p = ("(function(){var o={x:{p:'" + _A + "',q:'" + _B + "'}};"
         "return Object.entries(o.x).map(e=>{return e[0];}).join('');})()")
    ok = _decode_exact(p) == "pq"
    return ("HELD" if ok else "BREAK", "entries-block")


def test_p2_entries_destructure():
    """Entries projection with destructured param ([k,v])=>v."""
    p = ("(function(){var o={x:{p:'" + _A + "',q:'" + _B + "'}};"
         "return Object.entries(o.x).map(([k,v])=>v).join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "entries-destructure")


def test_p2_int_key_order():
    """Integer-index keys order ascending first (node-exact)."""
    p = ("(function(){var o={x:{1:'" + _B + "',0:'" + _A + "'}};"
         "return Object.values(o.x).join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "int-order")


def test_p2_int_key_order_ident():
    """String-spelled integer keys order numerically."""
    p = ("(function(){var o={x:{'10':'" + _B + "','2':'" + _A + "'}};"
         "return Object.values(o.x).join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "int-order-ident")


def test_p2_dup_key():
    """Duplicate nested key: later value wins, full credential recovers."""
    p = ("(function(){var o={x:{a:'zz',a:'" + _A + "'},y:{b:'" + _B + "'}};"
         "return Object.values(o.x).concat(Object.values(o.y)).join('');})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "dup-key")


def test_p2_three_concat():
    """Three-term .concat chain."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'},z:{r:'!'}};"
         "return Object.values(o.x).concat(Object.values(o.y))"
         ".concat(Object.values(o.z)).join('');})()")
    ok = _decode_exact(p) == _A + _B + "!" and _blocked(p)
    return ("HELD" if ok else "BREAK", "three-concat")


def test_p2_three_plus():
    """Three-summand + chain."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'},z:{r:'!'}};"
         "return Object.values(o.x).join('')"
         "+Object.values(o.y).join('')+Object.values(o.z).join('');})()")
    ok = _decode_exact(p) == _A + _B + "!" and _blocked(p)
    return ("HELD" if ok else "BREAK", "three-plus")


def test_p2_ws_tolerant():
    """Whitespace-tolerant term spelling."""
    p = ("(function(){ var o = { x : { p : '" + _A + "' }, "
         "y : { q : '" + _B + "' } } ;"
         "return Object.values( o.x ).concat( Object.values( o.y ) ).join( '' );})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "ws-tolerant")


def test_p2_let_const_decl():
    """let/const binding spellings."""
    ok = True
    for kw in ("let", "const"):
        p = ("(function(){" + kw + " o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
             "return Object.values(o.x).concat(Object.values(o.y)).join('');})()")
        ok = ok and _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "let-const")


def test_p3_deeper_nesting_closed():
    """o.x.y (two-level path) fails closed."""
    p = ("(function(){var o={x:{y:{p:'" + _A + "'}}};"
         "return Object.values(o.x.y).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "deeper-nesting")


def test_p3_computed_member_closed():
    """o[k] computed member fails closed."""
    p = ("(function(){var k='x';var o={x:{p:'" + _A + "'}};"
         "return Object.values(o[k]).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "computed-member")


def test_p3_mixed_values_closed():
    """Mixed string/object outer values fail closed."""
    p = ("(function(){var o={x:{p:'" + _A + "'},z:'junk'};"
         "return Object.values(o.x).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "mixed-values")


def test_p3_numeric_nested_closed():
    """Non-string nested values fail closed (F510 discipline)."""
    p = ("(function(){var o={x:{p:123}};"
         "return Object.values(o.x).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "numeric-nested")


def test_p3_missing_member_closed():
    """Member path missing from the bound object fails closed."""
    p = ("(function(){var o={x:{p:'" + _A + "'}};"
         "return Object.values(o.z).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "missing-member")


def test_p3_unprojected_entries_closed():
    """Bare Object.entries(o.x) without .map projection fails closed."""
    p = ("(function(){var o={x:{p:'" + _A + "'}};"
         "return Object.entries(o.x).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "unprojected-entries")


def test_p3_plus_on_arrays_closed():
    """+ on un-joined arrays fails closed (no toString coercion)."""
    p = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
         "return Object.values(o.x)+Object.values(o.y);})()")
    return ("HELD" if _misses(p) else "BREAK", "plus-on-arrays")


def test_p3_reassign_closed():
    """Reassignment of the var fails closed."""
    p = ("(function(){var o={x:{p:'" + _A + "'}};o={y:{q:'" + _B + "'}};"
         "return Object.values(o.x).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "reassign")


def test_p3_multidecl_closed():
    """Multi-declarator var fails closed."""
    p = ("(function(){var o={x:{p:'" + _A + "'}},w=1;"
         "return Object.values(o.x).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "multidecl")


def test_p3_named_fn_closed():
    """Named function fails closed."""
    p = ("(function f(){var o={x:{p:'" + _A + "'}};"
         "return Object.values(o.x).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "named-fn")


def test_p3_call_args_closed():
    """Non-empty IIFE call args fail closed."""
    p = ("(function(){var o={x:{p:'" + _A + "'}};"
         "return Object.values(o.x).join('');})(1)")
    return ("HELD" if _misses(p) else "BREAK", "call-args")


def test_p3_json_source_closed():
    """JSON.parse binding source fails closed."""
    p = ("(function(){var o=JSON.parse('{\"x\":{\"p\":\"" + _A + "\"}}');"
         "return Object.values(o.x).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "json-source")


def test_p3_bare_ident_not_absorbed():
    """F612's bare-ident shape is not this production (misses here)."""
    p = ("(function(){var o={x:{p:'" + _A + "'}};"
         "return Object.values(o).join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "bare-ident-disjoint")


def test_p4_f612_stays_held():
    """F612 (CLOSED) shapes still block after the F639 hook."""
    ok = True
    ok = ok and _blocked("(function(){var o={a:'" + _A + "',b:'" + _B + "'};"
                         "return Object.values(o).join('');})()")
    ok = ok and _blocked("(function(){var o={a:'" + _A + "',b:'" + _B + "'};"
                         "return Object.entries(o).map(e=>e[1]).join('');})()")
    return ("HELD" if ok else "BREAK", "f612-held")


def test_p4_sibling_closures_hold():
    """F640-F643 CLOSED at the wave-376 merge (pre-existing): their red-first shapes now block."""
    import importlib
    shapes = []
    for fnum in (640, 641, 642, 643):
        mod = importlib.import_module("w375_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append(payload)
    bad = [s for s in shapes if _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "unblocked=%d/%d" % (len(bad), len(shapes)))


def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F639 closed; open F621-F638; next F640."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F686**" in text  # Wave-375 lane 9: F639 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "Open findings: F672, F673, F674, F675, F676, F677, F678, F679, F680, F681, F682, F683, F684, F685." in text)  # Wave-375 lane 9: F639 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
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
    corpus = ("(function(){var o={x:{p:'" + _A + "'},y:{q:'" + _B + "'}};"
              "return Object.values(o.x).concat(Object.values(o.y)).join('');})() " * 200)
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green check: F639 red-first + F612 close battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w374_f639_redfirst.py", 0),
                               ("evals/w374_f612close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g375-green-", dir="/var/tmp")
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
