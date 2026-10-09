#!/usr/bin/env python3
"""Wave-380 lane 4: close F676 + F678 (optional-chaining + with-statement family).

F676 (LOW, filed 2026-10-08 by wave-379 lane 8, attack round 47): optional-
chaining shapes beyond F665 bypass the bounded static JS-expression
decoder. Filed shapes: ?.() method calls
  (function(){var o={f:function(){return 'f1';}};return o?.f()+'f2';})(),
?.[] bracket reads, nullish combos
  (function(){var o=null;return (o?.x ?? 'f1')+'f2';})(),
and chained ?. reads. The wave-379 merge documented that F665's closure
absorbed the ?.['x'] bracket and o?.x?.y chained shapes; F676 stayed OPEN
for the ?.() call and (o?.x ?? 'f1') nullish-combo shapes.

F678 (LOW, filed 2026-10-08 by wave-379 lane 8, attack round 47): with-
statement shapes beyond F667 bypass the decoder. Filed shapes: nested
with scopes
  (function(){var o={x:'f1'};var p={y:'f2'};with(o){with(p){return x+y;}}})()
and with-then-tail reads
  (function(){var o={x:'f1'};var s;with(o){s=x;}return s+'f2';})().

Fix (gov/dlp.py, zero new re.compile): _js_parse_f676_optchain_iife
parses the opt-call and nullish productions node-exactly (v24.20.0);
_js_parse_f678_with_iife parses nested with scopes (2-3 levels,
innermost-shadows-outer) and with-tail assignments (writes through to
IIFE bindings; a target naming a scope member fails closed because the
engine writes the scope object). Both hooked after F667.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g380-*
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
def test_p1_f676_optcall():
    """F676 filed: o?.f() method call blocks, exact 'f1f2'."""
    s = ("(function(){var o={f:function(){return '" + _A
         + "';}};return o?.f()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f676_nullish():
    """F676 filed: (o?.x ?? 'f1') nullish combo blocks, exact 'f1f2'."""
    s = ("(function(){var o=null;return (o?.x ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f678_nested():
    """F678 filed: nested with scopes block, exact 'f1f2'."""
    s = ("(function(){var o={x:'" + _A + "'};var p={y:'" + _B
         + "'};with(o){with(p){return x+y;}}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f678_tail():
    """F678 filed: with-then-tail read blocks, exact 'f1f2'."""
    s = ("(function(){var o={x:'" + _A + "'};var s;with(o){s=x;}return s+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block, exact)

@_t
def test_p2_optcall_named_fn():
    """Named function value: {f:function g(){return 'f1';}} blocks."""
    s = ("(function(){var o={f:function g(){return '" + _A
         + "';}};return o?.f()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_optcall_ws():
    """Whitespace around ?. and the call: o ?. f ( ) blocks."""
    s = ("(function(){var o={f:function(){return '" + _A
         + "';}};return o ?. f () +'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_nullish_undefined():
    """var o=undefined receiver: (o?.x ?? 'f1') blocks."""
    s = ("(function(){var o=undefined;return (o?.x ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_nullish_bracket():
    """Bracket member in the nullish LHS: (o?.['x'] ?? 'f1') blocks."""
    s = ("(function(){var o=null;return (o?.['x'] ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_nullish_lhs_wins():
    """Non-nullish LHS wins node-exactly: (o?.x ?? 'f1') with o={x:'q'}.

    Decodes to 'q'+'f2' (not the full credential, so find_credential
    need not hit -- exact-decode only)."""
    s = ("(function(){var o={x:'q'};return (o?.x ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _decodes_exact(s, "q" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_nullish_missing_key():
    """Missing key on an object receiver is nullish: RHS wins."""
    s = ("(function(){var o={a:'q'};return (o?.zzz ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_nested_shadow():
    """Inner scope shadows outer scope (node-exact).

    Decodes to 'f1' alone (not the full credential -- exact-decode
    only)."""
    s = ("(function(){var o={x:'ZZ'};var p={x:'" + _A
         + "'};with(o){with(p){return x;}}})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_nested_inline():
    """Inline literal scopes at both levels block."""
    s = ("(function(){with({x:'" + _A + "'}){with({y:'" + _B
         + "'}){return x+y;}}})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_tail_two_assigns():
    """Two assignments inside the with body block."""
    s = ("(function(){var o={x:'" + _A + "',y:'" + _B
         + "'};var s;var t;with(o){s=x;t=y;}return s+t;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_tail_inline_scope():
    """Inline literal scope with a tail read blocks."""
    s = ("(function(){var s;with({x:'" + _A + "'}){s=x;}return s+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_small_int_member():
    """Small integer members (<= 2^53) still decode exactly."""
    s = ("(function(){var o={x:42};return (o?.x ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _decodes_exact(s, "42" + _B)
    s2 = ("(function(){var o={x:42};var p={y:'" + _B
          + "'};with(o){with(p){return x+y;}}})()")
    ok = ok and _decodes_exact(s2, "42" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)

@_t
def test_p3_bigint_member_misses():
    """Integer member above 2^53: engine loses precision; fail closed."""
    s1 = ("(function(){var o={x:9007199254740993};return (o?.x ?? '" + _A
          + "')+'" + _B + "';})()")
    s2 = ("(function(){var o={x:9007199254740993};var p={y:'" + _B
          + "'};with(o){with(p){return x+y;}}})()")
    s3 = ("(function(){var o={x:9007199254740993};var s;with(o){s=x;}"
          "return s;})()")
    ok = _misses(s1) and _misses(s2) and _misses(s3)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_optcall_dot_twin_absorbed():
    """Plain-dot o.f() twin absorbed by F674 (honest, documented).

    Wave-380 merge: F674 (lane 2, this-bound method reads) decodes the
    plain-dot o.f() call twin node-exactly (verified: lane-2 tree HITs,
    node evaluates to the exact credential). F676's closure is unchanged;
    its documented bound is absorbed by the sibling F674 closure.
    Recorded in F676's FINDINGS.md entry.
    """
    s = ("(function(){var o={f:function(){return '" + _A
         + "';}};return o.f()+'" + _B + "';})()")
    ok = not _misses(s)
    return ("HELD" if ok else "BREAK", "absorbed-by-f674=%s" % ok)


@_t
def test_p3_optcall_args_miss():
    """Call arguments fail closed: o?.f('x') misses."""
    s = ("(function(){var o={f:function(){return '" + _A
         + "';}};return o?.f('x')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_optcall_wrong_member_misses():
    """Member name must equal the function key: o?.g() misses."""
    s = ("(function(){var o={f:function(){return '" + _A
         + "';}};return o?.g()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_nullish_str_receiver_misses():
    """String receiver fails closed (engine .length would mis-decode)."""
    s = ("(function(){var o='ab';return (o?.x ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_nullish_chained_misses():
    """Chained ?. in the nullish LHS fails closed (tight scope)."""
    s = ("(function(){var o=null;return (o?.x?.y ?? '" + _A + "')+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_tail_shadow_write_misses():
    """Target naming a scope member: engine writes the scope object."""
    s = ("(function(){var o={x:'" + _A + "',s:'ZZ'};var s;with(o){s=x;}"
         "return s+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_tail_undeclared_target_misses():
    """Assignment to an undeclared name fails closed (sloppy global)."""
    s = ("(function(){var o={x:'" + _A + "'};with(o){zzz=x;}return zzz;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_tail_unbound_read_misses():
    """Assignment RHS reading an unbound name fails closed."""
    s = ("(function(){var o={x:'" + _A
         + "'};var s;with(o){s=zzz;}return s;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_nested_return_inside_with_misses():
    """with(o){s=x;return s;} (return inside) is neither C nor D."""
    s = ("(function(){var o={x:'" + _A
         + "'};var s;with(o){s=x;return s;}})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: open neighbors still miss (nothing absorbed)

_OPEN_SHAPES = [
    # Wave-380 merge: f672-f675 removed (CLOSED by lanes 1-3).
    ("f677", "(function(){var o={i:0,next:function(){this.i++;return this.i<=2?{value:this.i===1?'%s':'%s',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()"),
    ("f679", "(function(){var s='';for(var i=0;i<2;i++){s+=i===0?'%s':'%s';}return s;})()"),
    ("f680", "(function(){return Symbol.keyFor(Symbol.for('%s'))+'%s';})()"),
    ("f681", "(function(){var a=['junk','%s','%s'];a.splice(0,1);return a.join('');})()"),
    ("f682", "(function(){return ' %s '.trim()+'%s';})()"),
    ("f683", "(function(){return JSON.parse('{\"x\":\"%s\"}',function(k,v){return typeof v==='string'?v+'%s':v;}).x;})()"),
    ("f684", "(function({a='%s',b=a+'%s'}={}){return b;})()"),
    ("f685", "(function(){var f=()=>arguments[0];return f()+'%s';})('%s')"),
]


@_t
def test_p4_open_neighbors_still_miss():
    """F677, F679-F685 filed shapes still miss (nothing absorbed; F672-F675 CLOSED by lanes 1-3)."""
    bad = []
    for name, tmpl in _OPEN_SHAPES:
        s = tmpl % (_A, _B)
        if not _misses(s):
            bad.append(name)
    ok = not bad
    return ("HELD" if ok else "BREAK", "absorbed=%s" % (bad if bad else "none"))


@_t
def test_p4_f676_absorbed_shapes_still_block():
    """F665-absorbed F676 shapes (bracket, chained) still block."""
    s1 = ("(function(){var o={x:'" + _A + "'};return o?.['x']+'" + _B
          + "';})()")
    s2 = ("(function(){var o={x:{y:'" + _A + "'}};return o?.x?.y+'" + _B
          + "';})()")
    ok = (_blocked(s1) and _decodes_exact(s1, _A + _B)
          and _blocked(s2) and _decodes_exact(s2, _A + _B))
    return ("HELD" if ok else "BREAK", "absorbed-still-block=%s" % ok)


# ------------------------------------------------ p5: closed neighbors still held

@_t
def test_p5_closed_neighbors_still_held():
    """F665 (?.) and F667 (with) still block their shapes."""
    s665 = ("(function(){var o={x:'" + _A + "'};return o?.x+'" + _B
            + "';})()")
    s667 = ("(function(){var o={x:'" + _A + "',y:'" + _B
            + "'};with(o){return x+y;}})()")
    ok = (_blocked(s665) and _decodes_exact(s665, _A + _B)
          and _blocked(s667) and _decodes_exact(s667, _A + _B))
    return ("HELD" if ok else "BREAK", "neighbors-held=%s" % ok)


# ------------------------------------------------ p6: junk quiet

@_t
def test_p6_junk_quiet():
    """Junk shapes never decode to the credential."""
    shapes = [
        "'(function(){var s=\\'ab\\';return s;})()'",
        "(function(){var o=null;return (o?.x ?? 'ab')+'cd';})()",
        "(function(){var o={x:'ab'};var s;with(o){s=x;}return s+'cd';})()",
        "(function(){var o={f:function(){return 'ab';}};return o?.f()+'cd';})()",
    ]
    got = [dlp.find_credential(s) is None for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p7: pin, footer, no new regexes

@_t
def test_p7_pin_footer():
    """Pin 2143; merge footer (F672-F676, F678 closed; lane-4 F686->F699; open F677, F679-F685, F699 / next F700)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F795**" in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
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
    """200 mixed optchain/with junk sites stay quiet quickly (bounded miss time)."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var o={f:function(){return 'a%d';}};return o?.f()+'b';})()" % k)
        corpus.append("(function(){var o={x:'a%d'};var s;with(o){s=x;}return s+'b';})()" % k)
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
    for batt, expect_break in (("evals/w379_f676_redfirst.py", 0),
                               ("evals/w379_f678_redfirst.py", 0),
                               ("evals/w379_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g380-green-", dir="/var/tmp")
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
    """Depth-1 green check: F676/F678 red-firsts + wave-379 attack battery green."""
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
