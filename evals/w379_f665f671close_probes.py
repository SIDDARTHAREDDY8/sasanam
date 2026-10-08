#!/usr/bin/env python3
"""Wave-379 lane 3: close F665 (optional-chaining member reads) + F671
(IIFE-return additive member reads).

F665 (LOW; filed attack round 46, 2026-10-08): the bounded static
JS-expression decoder failed closed on every `?.` member read at
bare-expression level:
  ({x:'f1'})?.x+'f2'                 -> node "f1f2"
  (({x:'f1'})?.x)+(({x:'f2'})?.x)    -> node "f1f2"
while the plain-dot statement-level twin `({x:'f1'}).x+'f2'` blocks
(boundary -- the gap is ?.-specific). The F535 _JSObj postfix chain
only consumed `.` and `[` heads.

Fix (gov/dlp.py, zero new re.compile): the `_JSObj` branch of
_js_parse_postfix consumes a `?.` head before the member -- the
receiver is statically resolved and provably non-null, so the
short-circuit can never trigger and `?.` === `.` (node-exact; the
same normalization F490 applies to `?.` members). `?.` + ident and
`?.` + string-literal bracket resolve; chained `?.?.` falls out
naturally. A bare `?`, `??`, `?.(`, or a missing key fails closed as
before.

F671 (LOW; split out of F665 at the round-46 spec review): member
reads in IIFE-return additive position miss regardless of `?.` vs `.`:
  (function(){var o={x:'f1'};return o.x+'f2';})()          -> node "f1f2"
  (function(){return {x:'f1'}.x+'f2';})()                  -> node "f1f2"
  (function(){var o={x:'f1',y:'f2'};return o.x+o.y;})()    -> node "f1f2"
F535 routes object-literal member reads at statement level, but the
IIFE-body return additive grammar had no member-read term.

Fix (gov/dlp.py, zero new re.compile): new route
_js_parse_f671_member_reads_iife, modeled on
_js_parse_f649_varbound_members_iife: `(function(){[DECL
NAME={LIT};]return ADD;})()` with a custom return-additive loop.
Terms: string literals | member reads `NAME(.M|?.M|['M]|?.['M'])+`
against the bound props via _jsobj_lookup (F548 chain) | inline
`{LIT}`/`({LIT})` member chains. Named fn, params, prologue, extra
statements, multi-decl, non-empty call args, non-string values,
computed members, missing keys, unbound names all fail closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g379-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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

TAXONOMY_PIN = 2140  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_BT = chr(96)

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


# ------------------------------------------------ p1: F665 filed shapes (must block)

@_t
def test_p1_f665_filed_optchain():
    """F665 filed shape 1: ({x:'f1'})?.x+'f2' blocks, decodes exact."""
    s = "({x:'%s'})?.x+'%s'" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f665_filed_optchain_double():
    """F665 filed shape 2: (({x:'f1'})?.x)+(({x:'f2'})?.x) blocks."""
    s = "(({x:'%s'})?.x)+(({x:'%s'})?.x)" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: F665 variants

@_t
def test_p2_f665_variants():
    """F665 variants: ?.[, chained ?.?., ws, all decode exact."""
    shapes = [
        ("({x:'%s'})?.['x']+'%s'" % (_A, _B), _A + _B),
        ("({x:{c:'%s'}})?.x?.c+'%s'" % (_A, _B), _A + _B),
        ("({x:'%s'}) ?. x + '%s'" % (_A, _B), _A + _B),
        ("({x:{c:'%s'}})?.['x']?.c+'%s'" % (_A, _B), _A + _B),
    ]
    got = [_blocked(s) and _decodes_exact(s, want) for s, want in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "variants=%s" % got)


# ------------------------------------------------ p3: F671 filed shapes (must block)

@_t
def test_p3_f671_filed_varbound_dot():
    """F671 filed shape 1: var-bound o.x+'f2' blocks, decodes exact."""
    s = "(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p3_f671_filed_inline_dot():
    """F671 filed shape 2: inline {x}.x+'f2' blocks, decodes exact."""
    s = "(function(){return {x:'%s'}.x+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p3_f671_filed_varbound_double():
    """F671 filed shape 3: var-bound o.x+o.y blocks, decodes exact."""
    s = "(function(){var o={x:'%s',y:'%s'};return o.x+o.y;})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p4: F671 variants

@_t
def test_p4_f671_variants():
    """F671 variants: ?. , ?.[, nested, let/const, paren-inline."""
    shapes = [
        ("(function(){var o={x:'%s'};return o?.x+'%s';})()" % (_A, _B),
         _A + _B),
        ("(function(){var o={x:'%s'};return o?.['x']+'%s';})()" % (_A, _B),
         _A + _B),
        ("(function(){var o={x:{c:'%s'}};return o.x.c+'%s';})()" % (_A, _B),
         _A + _B),
        ("(function(){let o={x:'%s'};return o['x']+'%s';})()" % (_A, _B),
         _A + _B),
        ("(function(){const o={x:'%s'};return o.x+'%s';})()" % (_A, _B),
         _A + _B),
        ("(function(){return ({x:'%s'}).x+'%s';})()" % (_A, _B), _A + _B),
    ]
    got = [_blocked(s) and _decodes_exact(s, want) for s, want in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "variants=%s" % got)


@_t
def test_p4_f671_single_term_decode():
    """F671 single member term decodes exact (partial credential stays quiet at find_credential)."""
    s = "(function(){const o={x:'%s'};return o.x;})()" % _A
    ok = _decodes_exact(s, _A) and _misses(s)
    return ("HELD" if ok else "BREAK", "exact+quiet=%s" % ok)


# ------------------------------------------------ p5: fail-closed bounds

@_t
def test_p5_f665_bounds():
    """F665 boundaries: bare ?/??/?.(, missing key, null receiver, ws ? . stay quiet."""
    shapes = [
        "({x:'%s'})?.y+'%s'" % (_A, _B),       # node: undefinedf2
        "(null)?.x",                             # node: undefined
        "({x:'%s'})?.('x')" % _A,                # ?.(
        "({x:'%s'}) ? 'a' : 'b'" % _A,           # ternary
        "({x:'%s'}) ?? 'd'" % _A,                # nullish
        "({x:'%s'})? .x+'%s'" % (_A, _B),        # ws between ? and . : SyntaxError in node
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


@_t
def test_p5_f671_bounds():
    """F671 boundaries: bare ident, missing key, computed member, multi-decl, named fn, args stay quiet."""
    shapes = [
        "(function(){var o={x:'%s'};return o;})()" % _A,          # [object Object] in node
        "(function(){var o={x:'%s'};return o.y+'%s';})()" % (_A, _B),  # undefinedf2 in node
        "(function(){var o={x:'%s'};return o[0]+'%s';})()" % (_A, _B),
        "(function(){var o='%s';return o.x+'%s';})()" % (_A, _B),
        "(function(){var o={x:'%s'};return o.x=o.y;})()" % _A,
        "(function(){var o={x:'%s'};var p='q';return o.x+p;})()" % _A,
        "(function(){var arguments={x:'%s'};return arguments.x;})()" % _A,
        "(function f(){var o={x:'%s'};return o.x;})()" % _A,
        "(function(){var o={x:'%s'};return o.x;}) (1)" % _A,
        "(function(){var o={x:'%s'};var k='x';return o[k];})()" % _A,
        "(function(){var o={x:'%s'};return o.x;var q=1;})()" % _A,
        "(function(){var o={__proto__:{x:'%s'}};return o.x;})()" % _A,
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p6: twin boundaries still HELD

@_t
def test_p6_twin_boundaries():
    """Plain-dot twin (F665 boundary) and F535 statement-level twin (F671 boundary) still block."""
    shapes = [
        "({x:'%s'}).x+'%s'" % (_A, _B),      # F665 boundary: plain-dot bare-expression
        "({x:'%s'}).x+'%s'" % (_A, _B),      # F671 boundary: F535 statement-level twin
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "held=%s" % got)


# ------------------------------------------------ p7: open findings still BREAK (nothing absorbed)

@_t
def test_p7_open_findings_still_break():
    """F662-F664 / F666-F670 open pins still miss -- F665/F671 closures absorbed nothing."""
    shapes = [
        ("F662", "(function(){class C{static x='%s';}return C.x+'%s';})()" % (_A, _B)),
        ("F662", "(function(){class C{x='%s';}return new C().x+'%s';})()" % (_A, _B)),
        ("F663", "(function(){var o=Object.fromEntries([['a','%s'],['b','%s']]);return o.a+o.b;})()" % (_A, _B)),
        ("F664", "(function(){var o={get x(){return '%s';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B)),
        ("F666", "(function(){var p=new Proxy(function(){},{apply:function(){return '%s';}});return p()+'%s';})()" % (_A, _B)),
        ("F667", "(function(){var o={x:'%s',y:'%s'};with(o){return x+y;}})()" % (_A, _B)),
        ("F668", "(function(){function tag(s){return s[0]+'%s';}return tag%s%s%s;})()" % (_B, _BT, _A, _BT)),
        ("F669", "(function(){var st=new Set(['%s','%s']);return [...st].join('');})()" % (_A, _B)),
        ("F670", "(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>{return a+b;}});return p.anything;})()" % (_A, _B)),
    ]
    got = [_misses(s) for _, s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "still-miss=%s" % got)


# ------------------------------------------------ p8: junk quiet

@_t
def test_p8_junk_quiet():
    """No-credential shapes stay quiet."""
    shapes = [
        "({x:'jx'})?.x+'jy'",
        "(function(){var o={x:'jx'};return o.x+'jy';})()",
        "(function(){return {x:'jx'}.x+'jy';})()",
        "({x:'jx'})?.['x']+'jy'",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p9: composition

@_t
def test_p9_composition():
    """Filed shapes embedded in junk / larger contexts still block."""
    shapes = [
        ("junk " + "({x:'%s'})?.x+'%s'" + " junk") % (_A, _B),
        ("var t=(" + "(function(){var o={x:'%s'};return o.x+'%s';})()" + ");t") % (_A, _B),
        ("(" + "({x:'%s'})?.x+'%s'" + ")+(" + "(function(){return {x:'%s'}.x+'%s';})()" + ")") % (_A, _B, _A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "held=%s" % got)


# ------------------------------------------------ p10: pin, footer, no new regexes

@_t
def test_p10_pin_footer():
    """Pin 2140; lane-local footer (F665/F671 CLOSED; open F662-F664, F666-F670 / next F672)."""
    ok = (TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F672**" in text)  # Wave-379 lane 3: F665/F671 CLOSED; open F662-F664, F666-F670 / next F672
    ok = ok and ("Open findings: F662, F663, F664, F666, F667, F668, F669, F670." in text)  # Wave-379 lane 3: F665/F671 CLOSED; open F662-F664, F666-F670 / next F672
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p10_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p11: perf

@_t
def test_p11_perf():
    """200 mixed F665/F671 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("({x:'a%d'})?.x+'b'" % k)
        corpus.append("(function(){var o={x:'a%d'};return o.x+'b';})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p12: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w378_f665_redfirst.py", 0),
                               ("evals/w378_f671_redfirst.py", 0),
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
def test_p12_green_check():
    """Depth-1 green check: F665/F671 red-firsts + wave-378 attack battery green."""
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
