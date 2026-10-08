#!/usr/bin/env python3
"""Wave-375 lane 2: F622 + F632 CLOSED -- enumeration read family.

F622 (LOW): Object.keys enumeration with computed bracket reads on
var-bound objects -- `var o=<src>;var k=Object.keys(o);return
o[k[0]]+o[k[1]];` and the `Object.keys(o).map(k=>o[k]).join('')`
twin. F612 (CLOSED) covers Object.values/Object.entries through
var-bound intermediates and F535 (CLOSED) covers literal-key member
reads, but the enumerated-key computed-bracket read path escaped
both. Node-exact desugar (v24.20.0): the var binds an F510
enumeration source; Object.keys(o) is the ordered key list, so
`o[k[<int>]]` resolves positionally to the aligned ordered value;
the map twin reads each enumerated key back through the bound
object (empty separator required).

F632 (LOW): for-in with compound member expressions --
`s+=o[k].p||o[k].q` / `s+=o[k]['p']||o[k]['q']`. F592 (CLOSED)
models for-in accumulation over object literals with an optional
single .MEM member read, but compound member expressions exceed
the modeled grammar. Node-exact desugar (v24.20.0): each
enumerated value's member chain is evaluated with the engine's
short-circuit `||` semantics (first truthy operand wins; all-falsy
yields the last operand, missing reads as "undefined" exactly as
F592's single-member convention); a numeric `0` property value
under a chain-member name fails the chain closed (the F535 value
grammar coerces numbers to strings, losing the engine's falsy-0 --
documented boundary); Object.prototype member names fail closed
(documented); the two independent declarations may appear in either
order (engine-identical).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (fresh /var/tmp/g375-* TMPDIRs), hard pin 2140,
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
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _dec_f622(js):
    """Exact decoded value via the F622 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0}
    r = _dlp._js_parse_f622_keys_bracket_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


def _dec_f632(js):
    """Exact decoded value via the for-in IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0}
    r = _dlp._js_parse_forin_accum_iife(js, 0, 0, state)
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

def test_p1_f622_keys_bracket():
    """F622 filed shape 1: var-bound keys + computed bracket reads."""
    hit = _blocked("(function(){var o={a:'%s',b:'%s'};var k=Object.keys(o);"
                   "return o[k[0]]+o[k[1]];})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


def test_p1_f622_keys_map():
    """F622 filed shape 2: Object.keys(o).map(k=>o[k]).join('')."""
    hit = _blocked("(function(){var o={a:'%s',b:'%s'};"
                   "return Object.keys(o).map(k=>o[k]).join('');})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


def test_p1_f632_or_member():
    """F632 filed shape 1: for-in with o[k].p||o[k].q."""
    hit = _blocked("(function(){var o={x:{p:'%s'},y:{q:'%s'}};var s='';"
                   "for(var k in o){s+=o[k].p||o[k].q;}return s;})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


def test_p1_f632_or_bracket():
    """F632 filed shape 2: for-in with o[k]['p']||o[k]['q']."""
    hit = _blocked("(function(){var o={x:{p:'%s'},y:{q:'%s'}};var s='';"
                   "for(var k in o){s+=o[k]['p']||o[k]['q'];}return s;})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------ F622 variants (node-exact)

def test_p2_f622_bracket_keys_call():
    """Object['keys'](o) -- bracket-string member, engine-identical."""
    got = _dec_f622("(function(){var o={a:'%s',b:'%s'};var k=Object['keys'](o);"
                    "return o[k[0]]+o[k[1]];})()" % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_const_let_twins():
    """const/let declarations -- engine-identical binding."""
    got = _dec_f622("(function(){const o={a:'%s',b:'%s'};let k=Object.keys(o);"
                    "return o[k[0]]+o[k[1]];})()" % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_int_key_order():
    """Integer keys order ascending first (node-exact)."""
    got = _dec_f622("(function(){var o={1:'one',0:'zero'};var k=Object.keys(o);"
                    "return o[k[0]]+o[k[1]];})()")
    ok = got == "zeroone"
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_three_terms():
    """Three-term additive chain."""
    got = _dec_f622("(function(){var o={a:'%s',b:'%s',c:'!'};var k=Object.keys(o);"
                    "return o[k[0]]+o[k[1]]+o[k[2]];})()" % (_A, _B))
    ok = got == _A + _B + "!"
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_single_term():
    """Single bracket read term."""
    got = _dec_f622("(function(){var o={a:'%s'};var k=Object.keys(o);"
                    "return o[k[0]];})()" % (_A,))
    ok = got == _A
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_ws_tolerant():
    """Whitespace inside brackets -- engine-insensitive."""
    got = _dec_f622("(function(){var o={a:'%s',b:'%s'};var k=Object.keys(o);"
                    "return o[ k[ 0 ] ]+o[k[1]];})()" % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_freeze_source():
    """Integrity-wrapper source (F510 grammar) -- engine-identical."""
    got = _dec_f622("(function(){var o=Object.freeze({a:'%s',b:'%s'});"
                    "var k=Object.keys(o);return o[k[0]]+o[k[1]];})()"
                    % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_map_paren_param():
    """Parenthesized map param (k)=>o[k] -- engine-identical."""
    got = _dec_f622("(function(){var o={a:'%s',b:'%s'};"
                    "return Object.keys(o).map((k)=>o[k]).join('');})()"
                    % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p2_f622_map_ws_tolerant():
    """Whitespace around the keys-map chain -- engine-insensitive."""
    got = _dec_f622("(function(){var o={a:'%s',b:'%s'};"
                    "return Object.keys( o ).map( k=>o[k] ).join( '' );})()"
                    % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


# ------------------------------------------------ F632 variants (node-exact)

def test_p3_f632_braced_body():
    """Braced loop body -- engine-identical."""
    got = _dec_f632("(function(){var o={x:{p:'%s'},y:{q:'%s'}};var s='';"
                    "for(var k in o){s+=o[k].p||o[k].q;}return s;})()"
                    % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_accum_first_order():
    """Accumulator-first declaration order -- engine-identical."""
    got = _dec_f632("(function(){var s='';var o={x:{p:'%s'},y:{q:'%s'}};"
                    "for(var k in o)s+=o[k].p||o[k].q;return s;})()"
                    % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_three_operands():
    """Three-operand || chain -- same operator, engine-exact."""
    got = _dec_f632("(function(){var o={x:{p:'%s'},y:{r:'%s'}};var s='';"
                    "for(var k in o){s+=o[k].p||o[k].q||o[k].r;}return s;})()"
                    % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_mixed_dot_bracket():
    """Mixed dot and bracket members in one chain."""
    got = _dec_f632("(function(){var o={x:{p:'%s'},y:{q:'%s'}};var s='';"
                    "for(var k in o){s+=o[k].p||o[k]['q'];}return s;})()"
                    % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_empty_string_fallthrough():
    """Empty-string operand is falsy: falls through (node-exact)."""
    got = _dec_f632("(function(){var o={x:{p:'',q:'%s'}};var s='';"
                    "for(var k in o){s+=o[k].p||o[k].q;}return s;})()" % (_A,))
    ok = got == _A
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_both_missing_undefined():
    """All operands missing: engine appends undefined (node-exact)."""
    got = _dec_f632("(function(){var o={x:{z:1}};var s='';"
                    "for(var k in o){s+=o[k].p||o[k].q;}return s;})()")
    ok = got == "undefined"
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_primitive_value_undefined():
    """Member read on a primitive boxes to undefined (node-exact)."""
    got = _dec_f632("(function(){var o={x:'str'};var s='';"
                    "for(var k in o){s+=o[k].p||o[k].q;}return s;})()")
    ok = got == "undefined"
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_bracket_single_member():
    """Lone bracket member o[k]['p'] -- F592 path, engine-identical."""
    got = _dec_f632("(function(){var s='';var o={x:{p:'%s'}};"
                    "for(var k in o){s+=o[k]['p'];}return s;})()" % (_A,))
    ok = got == _A
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


def test_p3_f632_objfirst_plain_forin():
    """Object-first order with the plain F517 body -- unchanged."""
    got = _dec_f632("(function(){var o={a:'%s',b:'%s'};var s='';"
                    "for(var k in o){s+=o[k];}return s;})()" % (_A, _B))
    ok = got == _A + _B
    return ("HELD" if ok else "BREAK", "got=%r" % (got,))


# ------------------------------------------------ F622 fail-closed boundaries

def test_p4_f622_index_out_of_range():
    """Bracket index past the key list -- fail closed."""
    bad = _misses("(function(){var o={a:'%s'};var k=Object.keys(o);"
                  "return o[k[5]];})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_wrong_idents():
    """Reads through a different object/keys ident -- fail closed."""
    bad = _misses("(function(){var o={a:'%s'};var k=Object.keys(o);"
                  "return p[k[0]];})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_multidecl():
    """Multi-declarator statement -- fail closed."""
    bad = _misses("(function(){var o={a:'%s'},p=1;var k=Object.keys(o);"
                  "return o[k[0]];})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_extra_statement():
    """Extra statement between decls -- fail closed."""
    bad = _misses("(function(){var o={a:'%s'};var z=1;var k=Object.keys(o);"
                  "return o[k[0]];})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_named_function():
    """Named function IIFE -- fail closed."""
    bad = _misses("(function f(){var o={a:'%s'};var k=Object.keys(o);"
                  "return o[k[0]];})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_call_args():
    """Non-empty invocation args -- fail closed."""
    bad = _misses("(function(){var o={a:'%s'};var k=Object.keys(o);"
                  "return o[k[0]];})(1)" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_join_separator():
    """Non-empty join separator -- fail closed."""
    bad = _misses("(function(){var o={a:'%s',b:'%s'};"
                  "return Object.keys(o).map(k=>o[k]).join(',');})()"
                  % (_A, _B))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_map_body_not_read():
    """Map callback body not o[param] -- fail closed."""
    bad = _misses("(function(){var o={a:'%s',b:'%s'};"
                  "return Object.keys(o).map(k=>k).join('');})()"
                  % (_A, _B))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_keys_wrong_arg():
    """Object.keys on a different ident -- fail closed."""
    bad = _misses("(function(){var o={a:'%s'};var k=Object.keys(p);"
                  "return o[k[0]];})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p4_f622_hex_index():
    """Non-decimal bracket index -- fail closed."""
    bad = _misses("(function(){var o={a:'%s'};var k=Object.keys(o);"
                  "return o[k[0x0]];})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


# ------------------------------------------------ F632 fail-closed boundaries

def test_p5_f632_logical_assign():
    """||= is logical assignment, engine-different -- fail closed."""
    bad = _misses("(function(){var o={x:{p:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].p||=o[k].q;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_and_chain():
    """&& chain is engine-different -- fail closed."""
    bad = _misses("(function(){var o={x:{p:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].p&&o[k].q;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_prototype_member():
    """Object.prototype member in the chain -- fail closed."""
    bad = _misses("(function(){var o={x:{p:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].toString||o[k].p;}return s;})()"
                  % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_numeric_zero_member():
    """Numeric 0 under a chain member -- fail closed (documented)."""
    bad = _misses("(function(){var o={x:{p:0,q:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].p||o[k].q;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_nonstring_member():
    """Non-string present member value -- fail closed (F592 discipline)."""
    bad = _misses("(function(){var o={x:{p:{},q:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].p||o[k].q;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_deeper_chain():
    """Deeper member chain o[k].p.q -- fail closed."""
    bad = _misses("(function(){var o={x:{p:{q:'%s'}}};var s='';"
                  "for(var k in o){s+=o[k].p.q||o[k].r;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_operand_other_object():
    """OR operand reading a different object -- fail closed."""
    bad = _misses("(function(){var o={x:{p:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].p||p[k].q;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_operand_other_key():
    """OR operand indexing a different key var -- fail closed."""
    bad = _misses("(function(){var o={x:{p:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].p||o[j].q;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


def test_p5_f632_call_operand():
    """Call in an OR operand -- fail closed."""
    bad = _misses("(function(){var o={x:{p:'%s'}};var s='';"
                  "for(var k in o){s+=o[k].p()||o[k].q;}return s;})()" % (_A,))
    return ("HELD" if bad else "BREAK", "miss=%s" % bad)


# ------------------------------------------------ composition

def test_p6_closed_neighbors_still_block():
    """F592/F612/F583/F535 closures unaffected by this lane."""
    shapes = [
        "(function(){var s='';var o={a:'%s',b:'%s'};for(var k in o){s+=o[k];}return s;})()",
        "(function(){var s='';var o={a:{v:'%s'},b:{v:'%s'}};for(var k in o){s+=o[k].v;}return s;})()",
        "(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()",
        "Object.keys({'%s':1,'%s':1}).join('')",
        "({a:'%s',b:'%s'}).a+'%s'",
    ]
    args = [(_A, _B), (_A, _B), (_A, _B), (_A, _B), (_A, _B, _B)]
    ok = all(_blocked(s % a) for s, a in zip(shapes, args))
    return ("HELD" if ok else "BREAK", "all=%s" % ok)


def test_p6_open_neighbors_still_miss():
    """Open findings (F640-F643) not absorbed by these closures."""
    import importlib
    shapes = []
    for fnum in (640, 641, 642, 643):
        mod = importlib.import_module("w375_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append(payload)
    ok = all(_misses(s) for s in shapes)
    return ("HELD" if ok else "BREAK", "all=%s n=%d" % (ok, len(shapes)))


def test_p6_junk_quiet():
    """Honest text stays quiet."""
    quiet = _misses('"(function(){var s=\'ab\';return s;})()"')
    quiet2 = _misses("the quick brown fox jumps over the lazy dog")
    ok = quiet and quiet2
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p8_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p8_footer_state():
    """Footer: F622/F632 closed; open F621,F623-F631,F633-F639; next F640 (lane-local)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F686**" in text  # Wave-375 lane 2: F622, F632 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "Open findings: F672, F673, F674, F675, F676, F677, F678, F679, F680, F681, F682, F683, F684, F685." in text)  # Wave-375 lane 2: F622, F632 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p8_no_new_regexes():
    """re.compile count stays 28 (no new regexes this lane)."""
    import re
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p8_perf_corpus():
    """New productions do not blow the scan budget (F452 discipline)."""
    one = ("(function(){var o={a:'x',b:'y'};var k=Object.keys(o);"
           "return o[k[0]]+o[k[1]];})() ")
    two = ("(function(){var o={x:{p:'x'}};var s='';"
           "for(var k in o){s+=o[k].p||o[k].q;}return s;})() ")
    corpus = ("junk " * 500 + one + two) * 4
    t0 = time.time()
    hit = _blocked(corpus + "(function(){var o={a:'%s',b:'%s'};"
                            "var k=Object.keys(o);return o[k[0]]+o[k[1]];})()"
                    % (_A, _B))
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green checks: red-firsts, attack, sibling closure batteries."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    ok_all = True
    notes = []
    for bat, expect_break in (("w374_f622_redfirst.py", 0),
                              ("w374_f632_redfirst.py", 0),
                              ("w374_attack_probes.py", 0),
                              ("w371_f592f594close_probes.py", 0),
                              ("w374_f612close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g375-green-", dir="/var/tmp")
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
