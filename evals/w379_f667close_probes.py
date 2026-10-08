#!/usr/bin/env python3
"""Wave-379 lane 5: close F667 (with-statement scope resolution).

F667 (LOW, filed 2026-10-08 by wave-378 lane 7, attack round 46): bare
identifier reads resolved through a with-statement scope object bypass
the bounded static JS-expression decoder:
  (function(){var o={x:'f1',y:'f2'};with(o){return x+y;}})()
  (function(){var o={x:'f1'};with(o){return x+'f2';}})()
both node-evaluate (v24.20.0) to the exact credential while the decoder
produced zero variants. Distinct from F655 (CLOSED): F655 models `with`
only as a decl+accum wrapper over an EMPTY scope object; F667 is the
scope-RESOLUTION production over a non-empty scope object (disjoint by
construction). Distinct from F561 (Array.prototype.with, not the
statement).

Fix (gov/dlp.py, zero new re.compile): _js_parse_f667_with_iife parses
(function(){[DECL S='LIT';]*[DECL S={LIT};]with(S|{LIT}){return ADD;}})()
-- the scope object via the F535/F510 literal-object grammar, the with
body via the F645 string-only additive grammar, with node-exact
resolution order (scope-object members shadow the IIFE's string
bindings; unbound identifiers fail closed because the engine throws
ReferenceError; non-string member values are excluded because their
engine read is not a plain string). Hooked after F655.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g379-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
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

TAXONOMY_PIN = 2143  # no new decision codes this lane; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

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
    return got is not None and got == want


# ------------------------------------------------ p1: filed shapes (must block, exact)

@_t
def test_p1_f667_filed_two_idents():
    """F667 filed shape 1: with(o){return x+y;} blocks, exact 'f1f2'."""
    s = ("(function(){var o={x:'" + _A + "',y:'" + _B
         + "'};with(o){return x+y;}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f667_filed_one_ident():
    """F667 filed shape 2: with(o){return x+'f2';} blocks, exact."""
    s = ("(function(){var o={x:'" + _A + "'};with(o){return x+'" + _B
         + "';}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block, exact)

@_t
def test_p2_shadow_member_wins():
    """Scope-object member shadows an outer binding (node-exact)."""
    s = ("(function(){var x='xx';var o={x:'" + _A + "'};with(o){return x+'"
         + _B + "';}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_outer_binding_read():
    """Non-member bare read resolves through the IIFE's bindings."""
    s = ("(function(){var a='" + _A + "';var o={b:'" + _B
         + "'};with(o){return a+b;}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_direct_literal_scope():
    """with({LIT}) direct-literal scope object blocks."""
    s = ("(function(){with({x:'" + _A + "'}){return x+'" + _B + "';}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_const_let_decl():
    """const/let scope-object declarations block."""
    got = []
    for kw in ("const", "let"):
        s = ("(function(){" + kw + " o={x:'" + _A + "'};with(o){return x+'"
             + _B + "';}})()")
        got.append(_blocked(s) and _decodes_exact(s, _A + _B))
    ok = all(got)
    return ("HELD" if ok else "BREAK", "block=%s" % got)


@_t
def test_p2_ws_dquote():
    """Whitespace and double-quote twins block."""
    s1 = ("(function(){var o={x:'" + _A + "'};with ( o ) { return x + '"
          + _B + "' ; } })()")
    s2 = ("(function(){var o={x:\"" + _A + "\"};with(o){return x+\""
          + _B + "\";}})()")
    ok = (_blocked(s1) and _decodes_exact(s1, _A + _B)
          and _blocked(s2) and _decodes_exact(s2, _A + _B))
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_multi_member():
    """Three members, two read: x+y blocks exact."""
    s = ("(function(){var o={x:'" + _A + "',y:'" + _B
         + "',z:'zz'};with(o){return x+y;}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_quoted_key_dup_key():
    """Quoted keys and later-wins duplicate keys (node-exact)."""
    s1 = ("(function(){var o={'x':'" + _A + "'};with(o){return x+'" + _B
          + "';}})()")
    s2 = ("(function(){var o={x:'zz',x:'" + _A + "'};with(o){return x+'"
          + _B + "';}})()")
    ok = (_blocked(s1) and _decodes_exact(s1, _A + _B)
          and _blocked(s2) and _decodes_exact(s2, _A + _B))
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_getter_member():
    """Getter member resolves to its return (node-exact: invoked on read)."""
    s = ("(function(){var o={get x(){return '" + _A
         + "';}};with(o){return x+'" + _B + "';}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_spread_member():
    """Spread-assembled scope object (F557, node-exact later-wins)."""
    s = ("(function(){var o={...{x:'" + _A + "'}};with(o){return x+'" + _B
         + "';}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_lone_member_read():
    """Lone member read: with(o){return x;} blocks exact."""
    s = ("(function(){var o={x:'" + _A + _B + "'};with(o){return x;}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)

@_t
def test_p3_unbound_ident():
    """Bare read of a non-member/non-binding: engine ReferenceError."""
    s = ("(function(){with({x:'" + _A + "'}){return y+'" + _B + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_proto_member():
    """Prototype-chain member (toString): engine read is not a string."""
    s = "(function(){with({x:'" + _A + "'}){return toString;}})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_empty_scope():
    """with({}) empty scope: no bindings; bare reads fail closed."""
    s = ("(function(){var o={};with(o){return x+'" + _B + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_unbound_scope():
    """with(q) where q is unbound: fail closed."""
    s = ("(function(){with(q){return x+'" + _B + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_wrong_scope_name():
    """with(p) naming a different object than the bound scope."""
    s = ("(function(){var o={x:'" + _A + "'};with(p){return x+'" + _B
         + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_write_in_body():
    """Assignment inside the with body: not the modeled shape."""
    s = ("(function(){var o={x:'" + _A + "'};with(o){x='" + _B
         + "';return x;}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_decl_in_body():
    """Declaration inside the with body: not the modeled shape."""
    s = ("(function(){var o={x:'" + _A + "'};with(o){var s=x;return s+'"
         + _B + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_call_args():
    """Invocation with arguments: fail closed."""
    s = ("(function(){var o={x:'" + _A + "'};with(o){return x+'" + _B
         + "';}})(1)")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_method_terminal():
    """Non-additive terminal (x.concat): outside the modeled grammar."""
    s = ("(function(){var o={x:'" + _A + "'};with(o){return x.concat('"
         + _B + "');}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_two_scope_objects():
    """Two object declarations: ambiguous scope; fail closed."""
    s = ("(function(){var o={x:'" + _A + "'};var p={y:'" + _B
         + "'};with(o){return x+y;}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_proto_key():
    """__proto__ key in the scope object: fail closed."""
    s = ("(function(){var o={__proto__:{x:'" + _A
         + "'}};with(o){return x+'" + _B + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_additive_member_value():
    """Additive member value {x:'A'+'zz'}: value grammar is literal-only.

    (The adjacent-halves twin {x:'A'+'B'} is flagged by the strict
    text rules on the base tree -- pre-existing, not the decoder.)
    """
    s = ("(function(){var o={x:'" + _A + "'+'zz'};with(o){return x;}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_bigint_precision_member():
    """Integer member above 2^53: engine loses precision; fail closed."""
    s = ("(function(){var o={x:9007199254740993};with(o){return x+'"
         + _B + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_reserved_name():
    """Reserved word as the scope-object name: engine SyntaxError."""
    s = ("(function(){var with={x:'" + _A + "'};with(with){return x+'"
         + _B + "';}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p4: open neighbors still miss

@_t
def test_p4_open_neighbors_still_miss():
    """F662-F666, F668-F671 now CLOSED (wave-379 merge): they block."""
    shapes = [
        # F662: class-declaration fragment sources
        "(function(){class C{static x='" + _A + "';}return C.x+'" + _B + "';})()",
        # F663: Object.fromEntries-sourced member reads
        ("(function(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})()"),
        # F664: getOwnPropertyDescriptor getter invocation in additive position
        ("(function(){var o={get x(){return '" + _A
         + "';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'"
         + _B + "';})()"),
        # F665: optional-chaining member reads
        "({x:'" + _A + "'})?.x+'" + _B + "'",
        # F666: Proxy apply/has traps
        ("(function(){var p=new Proxy(function(){},{apply:function(){return '"
         + _A + "';}});return p()+'" + _B + "';})()"),
        # F668: custom tag-function templates
        ("(function(){function tag(s){return s[0]+'" + _B
         + "';}return tag`" + _A + "`;})()"),
        # F669: builtin-iterable spread consumption
        ("(function(){var st=new Set(['" + _A + "','" + _B
         + "']);return [...st].join('');})()"),
        # F670: Proxy get-trap non-concise forms
        ("(function(){var a='" + _A + "',b='" + _B
         + "';var p=new Proxy({},{get:(t,k)=>{return a+b;}});return p.anything;})()"),
        # F671: member reads in IIFE-return additive position
        ("(function(){var o={x:'" + _A + "'};return o.x+'" + _B + "';})()"),
    ]
    got = [dlp.find_credential(s) is not None for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p5: closed neighbors still held

@_t
def test_p5_closed_neighbors_held():
    """F655 (with-wrapper), F611, F612, F645, F510 still block."""
    shapes = [
        # F655: with({}) decl+accum wrapper
        ("(function(){var a='" + _A + "';var b='" + _B
         + "';with({}){return a+b;}})()"),
        # F611: single-decl IIFE
        "(function(){var s='" + _A + _B + "';return s;})()",
        # F612: enumeration-source IIFE (filed shape)
        ("(function(){var o={a:'" + _A + "',b:'" + _B
         + "'};return Object.values(o).join('');})()"),
        # F645: default-param IIFE
        "(function(x='" + _A + "'){return x+'" + _B + "';})()",
        # F510: enumeration source
        ("(function(){var o={a:'" + _A + "',b:'" + _B
         + "'};return Object.values(o).join('');})()"),
    ]
    got = [dlp.find_credential(s) is not None for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "held=%s" % got)


# ------------------------------------------------ p6: junk quiet

@_t
def test_p6_junk_quiet():
    """No-credential with-shapes stay quiet."""
    shapes = [
        "(function(){var o={x:'ab'};with(o){return x+'cd';}})()",
        "(function(){var o={x:'jx'};with(o){return x;}})()",
        "(function(){with({a:'1'}){return a;}})()",
    ]
    got = [dlp.find_credential(s) is None for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p7: pin, footer, no new regexes

@_t
def test_p7_pin_footer():
    """Pin 2143; lane-local footer (F667 closed; open F662-F666, F668-F671 / next F672)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F713**" in text)  # Wave-379 lane 5: F667 CLOSED; open F662-F666, F668-F671 / next F672
    ok = ok and ("Open findings: F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712." in text)  # Wave-379 lane 5: F667 CLOSED; open F662-F666, F668-F671 / next F672
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
    """200 mixed with-scope sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var o={x:'a%d'};with(o){return x+'b';}})()" % k)
        corpus.append("(function(){with({y:'a%d'}){return y+'b';}})()" % k)
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
    for batt, expect_break in (("evals/w378_f667_redfirst.py", 0),
                               ("evals/w378_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g379-green-", dir="/var/tmp")
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
def test_p9_green_check():
    """Depth-1 green check: F667 red-first + wave-378 attack battery green."""
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
