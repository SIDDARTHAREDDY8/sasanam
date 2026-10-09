#!/usr/bin/env python3
"""Wave-380 lane 3: close F675 (Proxy-trap residuals).

F675 (LOW, filed 2026-10-08 by wave-379 lane 8, attack round 47): Proxy
traps beyond F642 (get), F666 (apply/has), and F670 (non-concise get
forms) bypass the bounded static JS-expression decoder -- set traps
(`p.x='LIT'` writes through the trap into the bound target),
construct traps (`new P()` invokes the trap, whose literal-object
return is member-read), deleteProperty traps (the filed no-op body
`{return true;}` claims the delete without touching the target),
getPrototypeOf traps (`Object.getPrototypeOf(p)` invokes the trap),
and `Proxy.revocable` (whose `.proxy` member fires the get trap).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f675_set_trap_iife: the set-trap body must be exactly
  the target-write `TR[K]=V` (TR/K/V the trap params; block
  `{TR[K]=V;return true;}`/`{TR[K]=V;}` or concise `(TR,K,V)=>TR[K]=V`,
  plus method shorthand); each `p.X='LIT'`/`t.X='LIT'` statement
  stores into the tracked target; `(p|t).MEM` reads fall through
  to the target (no get trap).
- _js_parse_f675_construct_trap_iife: `new P()` invokes the
  construct trap; the modeled body returns the literal object
  (block `return {PROPS};` or concise `()=>({PROPS})`); `.MEM`
  reads it. The engine's construct invariant (object result)
  means primitive returns throw -- they fail closed.
- _js_parse_f675_delete_trap_iife: the no-op `{return true;}` /
  `()=>true` body leaves the target intact; the deleting
  `{delete T0[T1];return true;}` body removes the named member
  from the tracked target. Reads of deleted/missing members fail
  closed (the engine yields undefined).
- _js_parse_f675_getproto_trap_iife: `Object.getPrototypeOf(p)`
  invokes the trap; the literal-object return is member-read.
  The proxy target is provably irrelevant and ignored.
- _js_parse_f675_revocable_iife: `Proxy.revocable` head (not
  `new Proxy`); `r.proxy.MEM` fires the get trap parsed by
  `_js_parse_f642_proxy_trap` (all four function forms). Any
  `revoke()` call fails closed (the engine throws TypeError).
Shared: _js_parse_f675_fn_head (four function forms),
_js_parse_f675_keyed_trap (`{KEY:FN}`/`{KEY(P){...}}`),
_js_parse_f675_iife_head/_js_parse_f675_iife_tail,
_js_parse_f675_decl_ident, _js_parse_f675_new_proxy_head,
_js_parse_f675_add_tail (literal and member summands).
Hooked after F666 in _js_parse_primary; disjoint by trap key /
head grammar (F642 requires `get`+`new Proxy`; F666 requires
`apply`/`has`).

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
    return got is not None and want in got


# ------------------------------------------------ p1: filed shapes (must block)

@_t
def test_p1_set_filed():
    """F675 filed shape 1: set trap write-through blocks."""
    s = ("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
         "{tr[k]=v;return true;}});p.x='" + _A + "';return p.x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_construct_filed():
    """F675 filed shape 2: construct trap blocks."""
    s = ("(function(){var P=new Proxy(function(){},{construct:function()"
         "{return {x:'" + _A + "'};}});return new P().x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_delete_filed():
    """F675 filed shape 3: deleteProperty no-op trap blocks."""
    s = ("(function(){var o={x:'" + _A + "'};var p=new Proxy(o,"
         "{deleteProperty:function(t,k){return true;}});delete p.x;"
         "return o.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_getproto_filed():
    """F675 filed shape 4: getPrototypeOf trap blocks."""
    s = ("(function(){var p=new Proxy({},{getPrototypeOf:function()"
         "{return {x:'" + _A + "'};}});return Object.getPrototypeOf(p).x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_revocable_filed():
    """F675 filed shape 5: Proxy.revocable get trap blocks."""
    s = ("(function(){var r=Proxy.revocable({},{get:function()"
         "{return '" + _A + "';}});return r.proxy.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block)

@_t
def test_p2_set_arrow():
    """Set trap concise-arrow twin blocks."""
    s = ("(function(){var t={};var p=new Proxy(t,{set:(tr,k,v)=>tr[k]=v});"
         "p.x='" + _A + "';return p.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_set_method_shorthand():
    """Set trap method-shorthand twin blocks."""
    s = ("(function(){var t={};var p=new Proxy(t,{set(tr,k,v)"
         "{tr[k]=v;return true;}});p.x='" + _A + "';return p.x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_set_two_writes_member_tail():
    """Two trap writes with a member-read tail block."""
    s = ("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
         "{tr[k]=v;return true;}});p.x='" + _A + "';p.y='" + _B
         + "';return p.x+p.y;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_set_bracket_members():
    """Bracket-string members on the trap write/read block."""
    s = ("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
         "{tr[k]=v;return true;}});p['y']='" + _A + "';return p['y']+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_set_target_direct():
    """Direct target read/write twins block."""
    s = ("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
         "{tr[k]=v;return true;}});t.x='" + _A + "';return p.x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_construct_arrow_paren():
    """Construct trap concise parenthesized-object twin blocks."""
    s = ("(function(){var P=new Proxy(function(){},{construct:()=>({x:'"
         + _A + "'})});return new P().x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_construct_method_shorthand():
    """Construct trap method-shorthand twin blocks."""
    s = ("(function(){var P=new Proxy(function(){},{construct()"
         "{return {x:'" + _A + "'};}});return new P().x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_delete_deleting_body():
    """deleteProperty deleting-body twin blocks (other member read)."""
    s = ("(function(){var o={x:'" + _A + "',y:'junk'};var p=new Proxy(o,"
         "{deleteProperty:function(t,k){delete t[k];return true;}});"
         "delete p.y;return o.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_delete_concise_noop():
    """deleteProperty concise no-op twin blocks."""
    s = ("(function(){var o={x:'" + _A + "'};var p=new Proxy(o,"
         "{deleteProperty:()=>true});delete p.x;return o.x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_getproto_arrow_paren():
    """getPrototypeOf concise parenthesized-object twin blocks."""
    s = ("(function(){var p=new Proxy({z:'q'},{getPrototypeOf:()=>({x:'"
         + _A + "'})});return Object.getPrototypeOf(p).x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_revocable_block_arrow():
    """Revocable block-body arrow twin blocks."""
    s = ("(function(){var r=Proxy.revocable({},{get:(t,k)=>{return '"
         + _A + "';}});return r.proxy.anything+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_revocable_method_shorthand():
    """Revocable method-shorthand twin blocks."""
    s = ("(function(){var r=Proxy.revocable({},{get(t,k){return '"
         + _A + "';}});return r.proxy.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)

@_t
def test_p3_bounds():
    """Non-modeled trap bodies/members fail closed."""
    shapes = [
        # set trap that never writes: the read is undefined in node
        "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
        "{return true;}});p.x='" + _A + "';return p.x+'" + _B + "';})()",
        # __proto__ write is silently ignored by the engine
        "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
        "{tr[k]=v;return true;}});p['__proto__']='" + _A
        + "';return p.x+'" + _B + "';})()",
        # non-string write
        "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
        "{tr[k]=v;return true;}});p.x=123;return p.x+'" + _B + "';})()",
        # construct trap returning a primitive throws TypeError
        "(function(){var P=new Proxy(function(){},{construct:function()"
        "{return 's';}});return new P().x+'" + _B + "';})()",
        # construct trap with args: outside the filed grammar
        "(function(){var P=new Proxy(function(){},{construct:function(t,a)"
        "{return {x:'" + _A + "'};}});return new P('z').x+'" + _B
        + "';})()",
        # missing member on the constructed object: undefined
        "(function(){var P=new Proxy(function(){},{construct:function()"
        "{return {x:'" + _A + "'};}});return new P().y+'" + _B + "';})()",
        # deleting body + read of the deleted member: undefined
        "(function(){var o={x:'" + _A + "'};var p=new Proxy(o,"
        "{deleteProperty:function(t,k){delete t[k];return true;}});"
        "delete p.x;return o.x+'" + _B + "';})()",
        # getPrototypeOf trap returning a primitive throws TypeError
        "(function(){var p=new Proxy({},{getPrototypeOf:function()"
        "{return 's';}});return Object.getPrototypeOf(p).x+'" + _B
        + "';})()",
        # revoke() then read throws TypeError
        "(function(){var r=Proxy.revocable({},{get:function()"
        "{return '" + _A + "';}});r.revoke();return r.proxy.x+'"
        + _B + "';})()",
        # revocable without a get trap: falls through to the target
        # (a distinct residual, not the F675 filed shape)
        "(function(){var r=Proxy.revocable({x:'" + _A
        + "'},{set:function(){return true;}});return r.proxy.x+'"
        + _B + "';})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "miss=%s" % got)


@_t
def test_p3_delete_direct_target():
    """Direct-target delete bypasses the trap: member gone even with a
    no-op body (node-exact; spec-review regression)."""
    # delete o.x removes x despite the no-op trap -> read is undefined
    # in node -> must miss (fail closed)
    s1 = ("(function(){var o={x:'" + _A + "'};var p=new Proxy(o,"
          "{deleteProperty:function(t,k){return true;}});delete o.x;"
          "return o.x+'" + _B + "';})()")
    # delete o.y (other member) leaves x intact -> still blocks
    s2 = ("(function(){var o={x:'" + _A + "',y:'junk'};var p=new Proxy(o,"
          "{deleteProperty:function(t,k){return true;}});delete o.y;"
          "return o.x+'" + _B + "';})()")
    ok = _misses(s1) and _blocked(s2) and _decodes_exact(s2, _A + _B)
    return ("HELD" if ok else "BREAK",
            "direct-miss=%s other-block=%s" % (_misses(s1), _blocked(s2)))


# ------------------------------------------------ p4: neighbors (open still miss, closed still block)

@_t
def test_p4_open_neighbors_still_miss():
    """Wave-380 merge: F672-F674/F676-F685 CLOSED -- former neighbors now block (not absorbed, closed)."""
    shapes = [
        # F672: class private statics (exact red-first shape)
        "(function(){class C{static #x='xoxb-0123';static y(){return C.#x;}}"
        "return C.y()+'456789abcdef';})()",
        # F673: defineProperties getter (exact red-first shape)
        "(function(){var o={};Object.defineProperties(o,{x:{get:function()"
        "{return 'xoxb-0123';}}});return o.x+'456789abcdef';})()",
        # F674: this-bound method (exact red-first shape)
        "(function(){var o={x:'xoxb-0123',get:function(){return this.x;}};"
        "return o.get()+'456789abcdef';})()",
        # F676: optional-call shape (exact red-first shape; the
        # ?.() call form was NOT absorbed by F665)
        "(function(){var o={f:function(){return 'xoxb-0123';}};"
        "return o?.f()+'456789abcdef';})()",
        # F677: manual iterator protocol (exact red-first shape)
        "(function(){var o={i:0,next:function(){this.i++;return this.i<=2?"
        "{value:this.i===1?'xoxb-0123':'456789abcdef',done:false}:"
        "{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();"
        "s+=r.value;return s;})()",
        # F685: arrow arguments (exact red-first shape)
        "(function(){var f=()=>arguments[0];return f()+'456789abcdef';})"
        "('xoxb-0123')",
    ]
    got = [_misses(s) for s in shapes]
    ok = not any(got)
    return ("HELD" if ok else "BREAK", "still-missing=%s" % [s for s, m in zip(shapes, got) if m])


@_t
def test_p4_closed_neighbors_still_block():
    """F642/F666/F670 closures still block on their shapes."""
    shapes = [
        ("(function(){var a='xoxb-0123',b='456789abcdef',c='zz';var p=new "
         "Proxy({},{get:(t,k)=>a+b+c});return p.anything;})()"),
        ("(function(){var p=new Proxy(function(){},{apply:function()"
         "{return 'xoxb-0123';}});return p()+'456789abcdef';})()"),
        ("(function(){var a='xoxb-0123',b='456789abcdef';var p=new Proxy({},"
         "{get:(t,k)=>{return a+b;}});return p.anything;})()"),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "held=%s" % got)


# ------------------------------------------------ p5: junk quiet

@_t
def test_p5_junk_quiet():
    """No-credential trap shapes stay quiet."""
    shapes = [
        "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
        "{tr[k]=v;return true;}});p.x='jx';return p.x+'jy';})()",
        "(function(){var P=new Proxy(function(){},{construct:function()"
        "{return {x:'jx'};}});return new P().x+'jy';})()",
        "(function(){var o={x:'jx'};var p=new Proxy(o,{deleteProperty:"
        "function(t,k){return true;}});delete p.x;return o.x+'jy';})()",
        "(function(){var p=new Proxy({},{getPrototypeOf:function()"
        "{return {x:'jx'};}});return Object.getPrototypeOf(p).x+'jy';})()",
        "(function(){var r=Proxy.revocable({},{get:function(){return 'jx';}});"
        "return r.proxy.x+'jy';})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p6: pin, footer, no new regexes

@_t
def test_p6_pin_footer():
    """Pin 2143; lane-local footer (open F672-F674, F676-F685 / next F686)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F921**" in text)  # Wave-380 lane 3: F675 CLOSED; open F672-F674, F676-F685 / next F686  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-380 lane 3: F675 CLOSED; open F672-F674, F676-F685 / next F686  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p6_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p7: perf

@_t
def test_p7_perf():
    """200 mixed trap sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v)"
                      "{tr[k]=v;return true;}});p.x='a%d';return p.x+'b';})()" % k)
        corpus.append("(function(){var r=Proxy.revocable({},{get:function()"
                      "{return 'a%d';}});return r.proxy.x+'b';})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p8: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w379_f675_redfirst.py", 0),
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
def test_p8_green_check():
    """Depth-1 green check: F675 red-first + wave-379 attack battery green."""
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
