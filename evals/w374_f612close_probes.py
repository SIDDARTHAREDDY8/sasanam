#!/usr/bin/env python3
"""Wave-374 lane 1: F612 CLOSED -- var-bound Object.values/Object.entries
indirection.

F510 (wave-363 lane 4, CLOSED) models Object.values/Object.entries on
INLINE enumeration sources (plain literals, integrity wrappers, the
entries-reduce rebuild idiom), but a var-bound intermediate --
`var o = <source>; Object.values(o)` -- escaped the source model.
Node-exact desugar (v24.20.0): the var binds a parsed F510
enumeration source; Object.values(o) is the ordered value list and
Object.entries(o).map(P=>P[1|0]) the ordered values/keys (F517's
mandatory-projection grammar). Distinct from F510 (inline sources,
still HELD).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (fresh /var/tmp/g374-* TMPDIRs), hard pin 2143,  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
concatenation-constructed credentials, $0-spend-by-construction
(evals-only: no realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402
from gov import dlp as _dlp  # noqa: E402 -- internal seam for exact values

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F612 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f612_values_varbound_iife(js, 0, 0, state)
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

def test_p1_filed_values_plain():
    """F612 shape 1 CLOSED: var-bound plain literal values block."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};"
                  "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_values_freeze():
    """F612 shape 2 CLOSED: var-bound frozen literal values block."""
    ok = _blocked("(function(){var o=Object.freeze({a:'%s',b:'%s'});"
                  "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_entries():
    """F612 shape 3 CLOSED: var-bound entries+map projection blocks."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};"
                  "return Object.entries(o).map(e=>e[1]).join('');})()"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ node-exact twins (must block)

def test_p2_const_let_twins():
    """const/let binding twins block (node-identical bindings)."""
    h1 = _blocked("(function(){const o={a:'%s',b:'%s'};"
                  "return Object.values(o).join('');})()" % (_A, _B))
    h2 = _blocked("(function(){let o={a:'%s',b:'%s'};"
                  "return Object.entries(o).map(e=>e[1]).join('');})()"
                  % (_A, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_bracket_members():
    """Object['values']/Object['entries'] twins block (F510 discipline)."""
    h1 = _blocked("(function(){var o={a:'%s',b:'%s'};"
                  "return Object['values'](o).join('');})()" % (_A, _B))
    h2 = _blocked("(function(){var o={a:'%s',b:'%s'};"
                  "return Object['entries'](o).map(e=>e[1]).join('');})()"
                  % (_A, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_int_key_order():
    """Integer-index keys order ascending first (F510 discipline)."""
    js = ("(function(){var o={1:'%s',0:'%s'};"
          "return Object.values(o).join('');})()" % (_B, _A))
    ok = _decode_exact(js) == _A + _B and _blocked(js)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_seal_wrapper():
    """Object.seal wrapper source blocks (F510 wrapper grammar)."""
    ok = _blocked("(function(){var o=Object.seal({a:'%s',b:'%s'});"
                  "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_entries_reduce_source():
    """entries-reduce rebuild idiom as var source blocks (F510 grammar)."""
    ok = _blocked("(function(){var o=Object.entries({a:'%s',b:'%s'})"
                  ".reduce((A,[B,C])=>(A[B]=C,A),{});"
                  "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_ws_tolerant():
    """Whitespace inside the IIFE body decodes (established scope)."""
    ok = _blocked("(function( ){ var  o = { a : '%s' , b : '%s' } ;"
                  "return Object . values ( o ).join('') ; })()"
                  % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_entries_fn_projection():
    """function-expression projection twin blocks (F517 grammar)."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};"
                  "return Object.entries(o).map(function(e){return e[1];})"
                  ".join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_entries_keys_projection_exact():
    """Keys projection decodes exactly to 'ab' (internal seam)."""
    js = ("(function(){var o={a:'%s',b:'%s'};"
          "return Object.entries(o).map(e=>e[0]).join('');})()" % (_A, _B))
    ok = _decode_exact(js) == "ab"
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_rebind_misses():
    """Rebinding the var after the binding fails closed (no room)."""
    ok = _misses("(function(){var o={a:'x'};o={a:'%s',b:'%s'};"
                 "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nonliteral_source_misses():
    """Non-literal sources fail closed (JSON.parse now modeled -- F630).

    Wave-375 lane 3 closed F630: JSON.parse('LITERAL') is now a
    modeled enumeration source, so the JSON.parse shape blocks
    (previously a documented fail-closed residual of F612). A
    genuinely non-literal source (identifier-bound) still misses.
    """
    ok = _blocked("(function(){var o=JSON.parse('{\"a\":\"%s\",\"b\":\"%s\"}');"
                  "return Object.values(o).join('');})()" % (_A, _B))
    ok = ok and _misses("(function(){var o=someCall();"
                        "return Object.values(o).join('');})()")
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


def test_p3_multidecl_misses():
    """Multi-declarator bindings fail closed."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'},p=1;"
                 "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_named_params_misses():
    """Named functions and parameters fail closed."""
    m1 = _misses("(function f(){var o={a:'%s',b:'%s'};"
                 "return Object.values(o).join('');})()" % (_A, _B))
    m2 = _misses("(function(x){var o={a:'%s',b:'%s'};"
                 "return Object.values(o).join('');})()" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_invoke_args_misses():
    """Non-empty call args fail closed (exact () only)."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'};"
                 "return Object.values(o).join('');})(1)" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_extra_stmt_misses():
    """Extra statements between binding and return fail closed."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'};var q=1;"
                 "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_wrong_ident_misses():
    """Call arg must be the bare bound ident (alias indirection fails)."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'};var p=o;"
                 "return Object.values(p).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_bare_entries_misses():
    """Bare Object.entries(o) without the map projection fails closed."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'};"
                 "return Object.entries(o);})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nop_projection_misses():
    """Non-projecting .map callbacks fail closed (F517 discipline)."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'};"
                 "return Object.entries(o).map(e=>e).join('');})()"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nonstring_values_misses():
    """Non-string values fail closed (F583 fallback is inline-only)."""
    ok = _misses("(function(){var o={a:1,b:'%s'};"
                 "return Object.values(o).join('');})()" % _B)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_prologue_misses():
    """Directive prologues fail closed (conservative)."""
    ok = _misses("(function(){'use strict';var o={a:'%s',b:'%s'};"
                 "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_keys_not_modeled():
    """Object.keys on the var-bound form is out of scope (fails closed)."""
    ok = _misses("(function(){var o={a:'%s',b:'%s'};"
                 "return Object.keys(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_mixed_int_str_keys_misses():
    """Mixed integer+string keys fail closed (pre-existing F510 scope)."""
    ok = _misses("(function(){var o={1:'%s',0:'%s',a:'zz'};"
                 "return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ compositions (must hold)

def test_p4_f510_inline_still_blocked():
    """F510 inline values/entries stay blocked (no regression)."""
    h1 = _blocked("Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B))
    h2 = _blocked("Object.values(Object.freeze({a:'%s',b:'%s'}))"
                  ".join('')" % (_A, _B))
    h3 = _blocked("Object.entries({a:'%s',b:'%s'})"
                  ".map(e=>e[1]).join('')" % (_A, _B))
    ok = h1 and h2 and h3
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def _round42_shapes():
    """Filed shapes of the currently-OPEN findings (must still miss).

    F621-F639 all CLOSED on the merged tree (wave-375 merge, lanes 1-9);
    their shapes now block. Only F640-F643 (attack round 43) remain open.
    """
    import importlib
    shapes = []
    # Wave-375 merge: F621-F639 CLOSED -- dropped from the still-open set.
    for fnum in (640, 641, 642, 643):
        mod = importlib.import_module("w375_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append((fnum, name, payload))
    return shapes


def test_p4_open_neighbors_still_miss():
    """Still-open round-42 findings still miss (nothing absorbed)."""
    bad = [(fnum, name) for fnum, name, payload in _round42_shapes()
           if not _misses(payload)]  # Wave-375 lane 2: latent NameError fixed (`f` -> fnum/name)
    ok = not bad
    return ("HELD" if ok else "BREAK", "miss=%s bad=%s" % (ok, bad[:3]))


def test_p4_sibling_iife_unchanged():
    """Sibling closure IIFEs still decode (F599/F606/F610/F611)."""
    h1 = _blocked("(function(){var p=new URLSearchParams('q=%s');"
                  "p.append('q','%s');"
                  "return p.getAll('q').join('');})()" % (_A, _B))  # F599
    h2 = _blocked("(function(){var p=new URLSearchParams('q=%s');"
                  "p.set('q','%s');"
                  "return p.get('q')+'%s';})()" % (_A, _A, _B))  # F610
    h3 = _blocked("atob('eG94Yi0wMTIz')+'%s'" % _B)  # F611 fragment
    ok = h1 and h2 and h3
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_junk_quiet():
    """Honest text unaffected: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    ok = ok and _misses("(function(){var o={a:'x',b:'y'};"
                        "return Object.values(o).join('');})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2143; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2143 and len(dc.TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F612 closed; open F613-F620; next F621 (lane-local)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F738**" in text  # Wave-375 merge lanes 1-9/10: F621-F639 CLOSED  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "Open findings: F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737." in text)  # Wave-375 merge lanes 1-9/10: F621-F639 CLOSED  # Wave-374 merge: footer repoint open F621-F639 / next F640  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28 (no new regexes this lane)."""
    import re
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """F612 IIFE anchor does not blow the scan budget (F452 discipline)."""
    one = ("(function(){var o={a:'x',b:'y'};"
           "return Object.values(o).join('');})() ")
    corpus = ("junk " * 500 + one) * 4
    t0 = time.time()
    hit = _blocked(corpus + "(function(){var o={a:'%s',b:'%s'};"
                    "return Object.values(o).join('');})()" % (_A, _B))
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green checks: attack + sibling closure batteries."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    ok_all = True
    notes = []
    for bat, expect_break in (("w373_attack_probes.py", 0),
                              ("w373_f611close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g374-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", bat)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        real_break = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                try:
                    real_break = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        good = (real_break == expect_break)
        ok_all = ok_all and good
        notes.append("%s=%s" % (bat, real_break))
    return ("HELD" if ok_all else "BREAK", ",".join(notes))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
