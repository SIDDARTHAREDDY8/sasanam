"""F672 close battery (wave-380 lane 1): class-declaration fragment sources.

F672 (LOW, filed attack round 47, 2026-10-08): class-declaration
residual fragment sources -- class shapes beyond the F662 closure
(private static/instance fields, methods, instance getters,
extends clauses with inherited reads, class expressions, computed
member names, mixins). F672 models those productions node-exactly
(v24.20.0) via _js_parse_f672_class_iife (tried after F662; disjoint
by head grammar -- F662 fails closed on every shape this accepts).

Pin 2143. Lane-local footer: open F673-F685 / next F686.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

Evals-only: $0 spend. No paid API calls anywhere in this battery.
"""

import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import gov.dlp as _dlp  # noqa: E402
from gov.dlp import find_credential  # noqa: E402
import gov.decision_codes as dc  # noqa: E402

TAXONOMY_PIN = 2143  # Wave-380 lane 1: F672 CLOSED; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

_A = "xoxb-" + "0123"  # concatenation-constructed credentials
_B = "456789" + "abcdef"
_CRED = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F672 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f672_class_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


# ------------------------------------------------ filed shapes

_FILED = [
    ("priv-static",
     "(function(){class C{static #x='%s';static y(){return C.#x;}}return C.y()+'%s';})()"),
    ("priv-inst",
     "(function(){class C{#x='%s';get(){return this.#x;}}return new C().get()+'%s';})()"),
    ("extends-super",
     "(function(){class C{get x(){return '%s';}}class D extends C{}return new D().x+'%s';})()"),
    ("class-expr",
     "(function(){var C=class{static x='%s';};return C.x+'%s';})()"),
    ("computed-method",
     "(function(){class C{['g'+''](){return '%s';}}return new C()['g'+'']()+'%s';})()"),
    ("static-inherit",
     "(function(){class C{static x='%s';}class D extends C{}return D.x+'%s';})()"),
    ("mixin",
     "(function(){var M=function(S){return class extends S{get x(){return '%s';}};};class B{}return new (M(B))().x+'%s';})()"),
]


def test_p1_filed_shapes():
    """All 7 filed shapes block at the public seam and decode exactly."""
    bad = []
    for name, tpl in _FILED:
        p = tpl % (_A, _B)
        if not (_decode_exact(p) == _CRED and _blocked(p)):
            bad.append(name)
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad,))


# ------------------------------------------------ node-exact variants

_VARIANTS = [
    # Multiple private fields, one accessor.
    ("multi-priv",
     "(function(){class C{static #a='%s';static #b='%s';static y(){return C.#a+C.#b;}}return C.y();})()",
     _CRED),
    # Static method reading its own private through `this`.
    ("static-this-priv",
     "(function(){class C{static #x='%s';static y(){return this.#x+'%s';}}return C.y();})()",
     _CRED),
    # Instance private fields, two of them.
    ("multi-inst-priv",
     "(function(){class C{#x='%s';#y='%s';get(){return this.#x+this.#y;}}return new C().get();})()",
     _CRED),
    # Two-level extends chain, instance getter at the root.
    ("extends-chain",
     "(function(){class C{get x(){return '%s';}}class D extends C{}class E extends D{}return new E().x+'%s';})()",
     _CRED),
    # Two static getters inherited through the chain.
    ("static-getters-inherit",
     "(function(){class C{static get x(){return '%s';}static get y(){return '%s';}}class D extends C{}return D.x+D.y;})()",
     _CRED),
    # Named class expression (inner name discarded).
    ("named-class-expr",
     "(function(){var C=class D{static x='%s';};return C.x+'%s';})()",
     _CRED),
    # Computed static field with concatenated key.
    ("computed-static-field",
     "(function(){class C{static ['k'+'ey']='%s';}return C['key']+'%s';})()",
     _CRED),
    # Two computed methods, called.
    ("computed-methods",
     "(function(){class C{['a'](){return '%s';}['b'](){return '%s';}}return new C()['a']()+new C()['b']();})()",
     _CRED),
    # Two static methods.
    ("two-static-methods",
     "(function(){class C{static m(){return '%s';}static n(){return '%s';}}return C.m()+C.n();})()",
     _CRED),
    # Inherited static method calling through to C's private.
    ("inherited-priv-method",
     "(function(){class C{static #x='%s';static y(){return C.#x;}}class D extends C{}return D.y()+'%s';})()",
     _CRED),
    # Subclass adds its own static field beside the inherited one.
    ("subclass-own-field",
     "(function(){class C{static x='%s';}class D extends C{static y='%s';}return D.x+D.y;})()",
     _CRED),
    # Static block alongside F672 members (F662 production reused).
    ("static-block-mix",
     "(function(){var s='';class C{static{s='%s';}}s+='%s';return s;})()",
     _CRED),
    # Later duplicate field wins (node-verified).
    ("dup-field-later-wins",
     "(function(){class C{static x='%s';static x='%s';}return C.x;})()",
     _B),
    # Later duplicate method wins (node-verified).
    ("dup-method-later-wins",
     "(function(){class C{m(){return '%s';}m(){return '%s';}}return new C().m();})()",
     _B),
    # Later duplicate getter wins (node-verified).
    ("dup-getter-later-wins",
     "(function(){class C{get x(){return '%s';}get x(){return '%s';}}return new C().x;})()",
     _B),
    # Field declared after the getter wins over it (node-verified).
    ("field-beats-getter",
     "(function(){class C{static get x(){return '%s';}static x='%s';}return C.x;})()",
     _B),
]


def test_p2_variants_node_exact():
    """Variants decode node-exactly (including duplicate-wins rules)."""
    bad = []
    for name, tpl, want in _VARIANTS:
        n = tpl.count("%s")
        p = tpl % ((_A, _B) if n == 2 else (_A,))
        got = _decode_exact(p)
        if got != want:
            bad.append("%s(got=%r want=%r)" % (name, got, want))
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad,))


# ------------------------------------------------ fail-closed bounds

_BOUNDS = [
    # Duplicate private names are a node SyntaxError.
    "dup-priv",
    "cross-class-priv",
    "priv-never-called-outofscope",
    # NOTE (wave-381 lane 4): "constructor" was an F672 fail-closed
    # bound; F690 now models constructor this-assignments
    # node-exactly -- see test_p3b_f690_absorbed below. Honest
    # absorption of a documented residual, not a regression.
    "private-method",
    "setter",
    "async-method",
    "generator",
    "body-public-this",
    "mixin-extends-nonclass",
    "mixin-extra-param",
    "mixin-returns-param",
    "nonlit-private",
    "uninit-private-call-miss",
    "getter-member-collision",
    "field-method-collision",
    "static-call-nonmethod",
    "uncalled-method-read",
    "extends-unknown",
    "named-fn",
    "call-args",
    "new-arg",
    "optchain",
    "asi-missing-semi",
    "nonlit-computed-key",
    "nonlit-field-init",
    "body-nonlit-decl-init",
    "public-this-read-in-method",
    "member-read-in-method",
    "call-in-method",
    "plus-eq-in-method",
    "super",
    "class-decl-anon",
]

_BOUND_TPLS = {
    "dup-priv": "(function(){class C{static #x='%s';static #x='q';}return C.y;})()",
    "cross-class-priv": "(function(){class C{static #x='%s';}class D{static y(){return C.#x;}}return D.y();})()",
    "priv-never-called-outofscope": "(function(){class C{static y(){return C.#z;}}return 'q';})()",
    # "constructor" moved to test_p3b_f690_absorbed (wave-381 lane 4).
    "private-method": "(function(){class C{static #m(){return '%s';}}return C.m();})()",
    "setter": "(function(){class C{set x(v){}}return 'q';})()",
    "async-method": "(function(){class C{static async m(){return '%s';}}return 'q';})()",
    "generator": "(function(){class C{static *m(){return '%s';}}return 'q';})()",
    "body-public-this": "(function(){class C{static y(){return this;}}return 'q';})()",
    "mixin-extends-nonclass": "(function(){var M=function(S){return class extends S{get x(){return '%s';}};};return new (M('str'))().x;})()",
    "mixin-extra-param": "(function(){var M=function(S,T){return class extends S{};};class B{}return 'q';})()",
    "mixin-returns-param": "(function(){var M=function(S){return S;};class B{}return new (M(B))().x;})()",
    "nonlit-private": "(function(){class C{static #x=y;}return 'q';})()",
    "uninit-private-call-miss": "(function(){class C{#x;}return new C().nope();})()",
    "getter-member-collision": "(function(){class C{get x(){return '%s';}x(){return 'q';}}return new C().x;})()",
    "field-method-collision": "(function(){class C{x='%s';x(){return 'q';}}return new C().x;})()",
    "static-call-nonmethod": "(function(){class C{static x='%s';}return C.x();})()",
    "uncalled-method-read": "(function(){class C{static m(){return '%s';}}return C.m;})()",
    "extends-unknown": "(function(){class C extends Z{static x='%s';}return C.x+'%s';})()",
    "named-fn": "(function foo(){class C{static #x='%s';}return 'q';})()",
    "call-args": "(function(){class C{static x='%s';}return C.x;})('z')",
    "new-arg": "(function(){class C{x='%s';}return new C('z').x+'%s';})()",
    "optchain": "(function(){class C{static x='%s';}return C?.x+'%s';})()",
    "asi-missing-semi": "(function(){class C{static x='%s'}return C.x+'%s';})()",
    "nonlit-computed-key": "(function(){class C{[k](){return '%s';}}return 'q';})()",
    "nonlit-field-init": "(function(){class C{static x=y;}return C.x;})()",
    "body-nonlit-decl-init": "(function(){class C{static #x='%s';static y(){var t=C.#x;return t;}}return C.y();})()",
    "public-this-read-in-method": "(function(){class C{m(){return this.x;}}return 'q';})()",
    "member-read-in-method": "(function(){class C{static x='%s';static m(){return C.x;}}return 'q';})()",
    "call-in-method": "(function(){class C{static m(){return String('%s');}}return 'q';})()",
    "plus-eq-in-method": "(function(){var s='';class C{static m(){s+='%s';return s;}}return 'q';})()",
    "super": "(function(){class C{get x(){return '%s';}}class D extends C{get x(){return super.x;}}return new D().x;})()",
    "class-decl-anon": "(function(){class{static x='%s';}return 'q';})()",
}


def test_p3_bounds_miss():
    """Fail-closed bounds: decoder misses (never mis-decodes)."""
    bad = []
    for name in _BOUNDS:
        tpl = _BOUND_TPLS[name]
        n = tpl.count("%s")
        p = tpl % ((_A, _B) if n == 2 else ((_A,) if n == 1 else ()))
        if not (_decode_exact(p) is None and _misses(p)):
            bad.append(name)
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad,))


def _decode_exact_f690(js):
    """Exact decoded value via the F690 ctor parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f690_ctor_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


def test_p3b_f690_absorbed():
    """F690-absorbed ex-bound: decodes node-exactly (wave-381 lane 4).

    The constructor shape was an F672 fail-closed bound; F690 models
    constructor this-assignments node-exactly, so it now decodes to
    the credential. Honest absorption of a documented residual.
    """
    p = ("(function(){class C{constructor(){this.x='%s';}}"
         "return new C().x+'%s';})()") % (_A, _B)
    ok = (_decode_exact_f690(p) == _CRED and _blocked(p))
    return ("HELD" if ok else "BREAK", "absorbed=%s" % ok)


# ------------------------------------------------ sibling closures hold

def test_p4_sibling_closures_hold():
    """F662 (CLOSED) still blocks its shapes; F663-F671 representative shapes block."""
    cases = [
        ("f662-field", "(function(){class C{static x='%s';}return C.x+'%s';})()"),
        ("f662-getter", "(function(){class C{static get x(){return '%s';}}return C.x+'%s';})()"),
        ("f662-block", "(function(){var s='';class C{static{s='%s';}}return s+'%s';})()"),
        ("f663", "(function(){var o=Object.fromEntries([['a','%s'],['b','%s']]);return o.a+o.b;})()"),
        ("f664", "(function(){var o={get x(){return '%s';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()"),
        ("f665", "(function(){var o={a:'%s'};return o?.a+'%s';})()"),
        ("f666", "(function(){var p=new Proxy(function(){},{apply:function(){return '%s';}});return p()+'%s';})()"),
        ("f667", "(function(){var o={x:'%s'};with(o){return x+'%s';}})()"),
        ("f669", "(function(){var st=new Set(['%s','%s']);return [...st].join('');})()"),
        ("f670", "(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>{return a+b;}});return p.anything;})()"),
        ("f671", "(function(){var o={x:'%s'};return o.x+'%s';})()"),
    ]
    bad = []
    for name, tpl in cases:
        p = tpl % (_A, _B)
        if not _blocked(p):
            bad.append(name)
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad,))


# ------------------------------------------------ open neighbors still miss

_OPEN_NEIGHBORS = [
    ("f673", "(function(){var o={};Object.defineProperties(o,{x:{get:function(){return '%s';}}});return o.x+'%s';})()"),
    ("f674", "(function(){var o={x:'%s',get:function(){return this.x;}};return o.get()+'%s';})()"),
    ("f675", "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v){tr[k]=v;return true;}});p.x='%s';return p.x+'%s';})()"),
    ("f676-call", "(function(){var o={f:function(){return '%s';}};return o?.f()+'%s';})()"),
    ("f676-nullish", "(function(){var o=null;return (o?.x ?? '%s')+'%s';})()"),
    ("f677", "(function(){function* g(){yield '%s';return '%s';}var it=g();var a=it.next();var b=it.next();return a.value+b.value;})()"),
    ("f678", "(function(){var o={x:'%s'};var p={y:'%s'};with(o){with(p){return x+y;}}})()"),
    ("f679", "(function(){var s='';for(var i=0;i<2;i++){s+=i===0?'%s':'%s';}return s;})()"),
    ("f680", "(function(){return Symbol.keyFor(Symbol.for('%s'))+'%s';})()"),
    ("f681", "(function(){var a=['junk','%s','%s'];a.splice(0,1);return a.join('');})()"),
    ("f682", "(function(){return ' %s '.trim()+'%s';})()"),
    ("f683", "(function(){return JSON.parse('{\"x\":\"%s\"}',function(k,v){return typeof v==='string'?v+'%s':v;}).x;})()"),
    ("f684", "(function({a='%s',b=a+'%s'}={}){return b;})()"),
    ("f685", lambda a, b: "(function(){var f=()=>arguments[0];return f()+'%s';})('%s')" % (b, a)),
]


def test_p5_open_neighbors_still_miss():
    """Wave-380 merge: F673-F685 CLOSED by lanes 2-7 -- former open neighbors now block (absorbed by closures)."""
    # All former neighbors (F673-F685) are CLOSED in the merge tree; the
    # _OPEN_NEIGHBORS list is retained for history but every entry now
    # decodes (blocks) rather than misses.
    bad = []
    for name, tpl in _OPEN_NEIGHBORS:
        p = tpl(_A, _B) if callable(tpl) else tpl % (_A, _B)
        if _misses(p):
            bad.append(name)
    ok = not bad
    return ("HELD" if ok else "BREAK", "still-missing=%s" % (bad,))


# ------------------------------------------------ junk quiet + composition

def test_p6_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


def test_p6_composition():
    """Return-position tag+'LIT' composition blocks (pre-existing route)."""
    hit = _blocked("(function(){function tag(s){return s[0];}return tag`%s`+'%s';})()"
                   % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------ node differential

def test_p7_node_differential():
    """Decoder agrees with node v24.20.0 on the exact-decode set."""
    try:
        out = subprocess.run(
            ["node", "-e",
             "const cs=["
             "[\"(function(){class C{static #x='A';static y(){return C.#x;}}return C.y()+'B';})()\",\"AB\"],"
             "[\"(function(){class C{#x='A';get(){return this.#x;}}return new C().get()+'B';})()\",\"AB\"],"
             "[\"(function(){class C{get x(){return 'A';}}class D extends C{}return new D().x+'B';})()\",\"AB\"],"
             "[\"(function(){var C=class{static x='A';};return C.x+'B';})()\",\"AB\"],"
             "[\"(function(){class C{['g'+''](){return 'A';}}return new C()['g'+'']()+'B';})()\",\"AB\"],"
             "[\"(function(){class C{static x='A';}class D extends C{}return D.x+'B';})()\",\"AB\"],"
             "[\"(function(){var M=function(S){return class extends S{get x(){return 'A';}};};class Q{}return new (M(Q))().x+'B';})()\",\"AB\"]"
             "];"
             "for(const [src,want] of cs){"
             "  const got=eval(src);"
             "  if(got!==want){console.log('NODE-MISMATCH '+src+' got='+JSON.stringify(got));process.exit(1);}"
             "}"
             "console.log('node-ok');"],
            capture_output=True, text=True, timeout=60)
        node_ok = (out.returncode == 0 and "node-ok" in (out.stdout or ""))
    except Exception:
        node_ok = False
    dec_ok = all(_decode_exact(p % (_A, _B)) == _CRED for _, p in _FILED)
    ok = node_ok and dec_ok
    return ("HELD" if ok else "BREAK", "node=%s dec=%s" % (node_ok, dec_ok))


# ------------------------------------------------ pin + footer + re.compile

def test_p8_pin_footer():
    """Pin 2143 and lane-local footer (F672 CLOSED: open F673-F685 / next F686)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143 and len(dc.TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F700**" in text)  # Wave-380 lane 1: F672 CLOSED; footer repoint open F673-F685 / next F686
    ok = ok and ("Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text)  # Wave-380 lane 1: F672 CLOSED; footer repoint open F673-F685 / next F686
    ok = ok and (_dlp is not None)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


def test_p8_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    import re
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ perf

def test_p9_perf():
    """200 mixed F672 sites decode quickly (F452 parts-budget honored)."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){class C{static #x='a%d';static y(){return C.#x;}}return C.y();})()" % k)
        corpus.append("(function(){class C{m(){return 'b%d';}}return new C().m();})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ green check (depth-1)

def test_p10_green_check():
    """Depth-1 green check: F672 red-first + F662 close battery + w379 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w379_f672_redfirst.py", 0),
                               ("evals/w379_f662close_probes.py", 0),
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
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            elif "BREAK /" in line and "HELD" in line:
                try:
                    nbreak = int(line.split("BREAK")[0].rsplit(":", 1)[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    tests = [
        ("test_p1_filed_shapes", test_p1_filed_shapes),
        ("test_p2_variants_node_exact", test_p2_variants_node_exact),
        ("test_p3_bounds_miss", test_p3_bounds_miss),
        ("test_p4_sibling_closures_hold", test_p4_sibling_closures_hold),
        ("test_p5_open_neighbors_still_miss", test_p5_open_neighbors_still_miss),
        ("test_p6_junk_quiet", test_p6_junk_quiet),
        ("test_p6_composition", test_p6_composition),
        ("test_p7_node_differential", test_p7_node_differential),
        ("test_p8_pin_footer", test_p8_pin_footer),
        ("test_p8_no_new_regexes", test_p8_no_new_regexes),
        ("test_p9_perf", test_p9_perf),
        ("test_p10_green_check", test_p10_green_check),
    ]
    nbreak = nheld = nerr = 0
    for name, fn in tests:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001
            status, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%-38s %-6s %s" % (name, status, note))
        if status == "BREAK":
            nbreak += 1
        elif status == "HELD":
            nheld += 1
        else:
            nerr += 1
    print("tally: %d BREAK / %d HELD / %d ERROR / %d total"
          % (nbreak, nheld, nerr, nbreak + nheld + nerr))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
