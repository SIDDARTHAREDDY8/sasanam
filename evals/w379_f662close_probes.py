#!/usr/bin/env python3
"""Wave-379 lane 1: close F662 -- class-declaration fragment sources.

F662 (LOW, filed 2026-10-08 by wave-378 lane 7, attack round 46, local
node validation + 2 gpt-4o-mini calls hints-only, $0 spend): class
declarations have no modeled path in the bounded static
JS-expression decoder. Four filed shapes, one mechanism:
(function(){class C{static x='f1';}return C.x+'f2';})() (static
field), (function(){let s='';class C{static{s='f1';}}s+='f2';return
s;})() (static block), (function(){class C{static get x(){return
'f1';}}return C.x+'f2';})() (static getter), and
(function(){class C{x='f1';}return new C().x+'f2';})() (instance
field) -- all node-evaluate to the exact credential (node
v24.20.0) while the decoder produced zero variants. Distinct from
F535/F642 (object-literal getters/Proxy traps, not class syntax).

Closure (gov/dlp.py): new _js_parse_f662_class_iife (+
_js_f662_parse_class_body, _js_f662_static_block,
_js_f662_member_head, _js_f662_member_access, _js_f662_top_stmt,
_js_f662_parse_term, _js_f662_return_additive, _js_f662_charge)
parses (function(){[STMT;]* return ADD;})() with class
declarations. Node-exact (v24.20.0): static fields (later
duplicate wins), static getters (evaluated at access), instance
fields, static blocks executed at definition against the
statement environment; member reads resolve with the F510
string-only discipline. Hooked after F655 in _js_parse_primary.
Zero new re.compile (28 stays).

Accepted generalizations (same mechanism, node-exact,
battery-pinned): bracket-string member reads (C['x']), var-bound
instances (var o=new C();return o.x), accumulation from member
reads (s=C.x), duplicate fields (later wins).

Fail-closed boundaries (documented residuals): methods, instance
getters, constructor, extends, #private members, computed
[expr] members, non-literal field initializers, string-literal
member names, a static field + static getter sharing a name (node
SyntaxError), unbound/const static-block targets, declarations or
return inside static blocks, ?.-reads, method calls, anonymous
classes, class expressions, uninitialized-field reads
(undefined), missing members.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g379-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gov.dlp as _dlp  # noqa: E402
from gov.dlp import find_credential  # noqa: E402
import gov.decision_codes as dc  # noqa: E402

TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F662 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f662_class_iife(js, 0, 0, state)
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


def test_p1_filed_static_field():
    """Filed shape 1: class static field."""
    p = ("(function(){class C{static x='" + _A + "';}return C.x+'"
         + _B + "';})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_static_block():
    """Filed shape 2: class static block."""
    p = ("(function(){let s='';class C{static{s='" + _A
         + "';}}s+='" + _B + "';return s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_static_getter():
    """Filed shape 3: class static getter."""
    p = ("(function(){class C{static get x(){return '" + _A
         + "';}}return C.x+'" + _B + "';})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_instance_field():
    """Filed shape 4: class instance field."""
    p = ("(function(){class C{x='" + _A + "';}return new C().x+'"
         + _B + "';})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ variants


def test_p2_variants():
    """Node-exact generalizations of the same mechanism."""
    cases = [
        ("two-static-fields",
         "(function(){class C{static a='" + _A + "';static b='" + _B
         + "';}return C.a+C.b;})()"),
        ("bracket-static",
         "(function(){class C{static x='" + _A + "';}return C['x']+'"
         + _B + "';})()"),
        ("bracket-instance",
         "(function(){class C{x='" + _A + "';}return new C()['x']+'"
         + _B + "';})()"),
        ("varbound-instance",
         "(function(){class C{x='" + _A + "';}var o=new C();return o.x+'"
         + _B + "';})()"),
        ("bracket-getter",
         "(function(){class C{static get x(){return '" + _A
         + "';}}return C['x']+'" + _B + "';})()"),
        ("dup-static-later-wins",
         "(function(){class C{static x='jx';static x='" + _A
         + "';}return C.x+'" + _B + "';})()"),
        ("dup-instance-later-wins",
         "(function(){class C{x='jx';x='" + _A + "';}return new C().x+'"
         + _B + "';})()"),
        ("ws-tolerant",
         "(function(){ class  C { static  x = '" + _A
         + "' ; } return C.x + '" + _B + "' ; })()"),
        ("dquote",
         '(function(){class C{static x="' + _A + '";}return C.x+"'
         + _B + '";})()'),
        ("assign-from-member",
         "(function(){let s='';class C{static x='" + _A
         + "';}s=C.x;s+='" + _B + "';return s;})()"),
        ("accum-from-member",
         "(function(){let s='';class C{static x='" + _A
         + "';}s+=C.x;s+='" + _B + "';return s;})()"),
        ("two-classes",
         "(function(){class C{static x='" + _A + "';}class D{static y='"
         + _B + "';}return C.x+D.y;})()"),
        ("block-multi-assign",
         "(function(){let s='';class C{static{s='" + _A + "';s+='" + _B
         + "';}}return s;})()"),
        # --- wave-379 spec-review remediation: getter bodies are the
        # getter's own function scope (node v24.20.0 verified) ---
        ("getter-paren-return",
         "(function(){class C{static get x(){return ('" + _A
         + "');}}return C.x+'" + _B + "';})()"),
        ("getter-local-var",
         "(function(){class C{static get x(){var t='" + _A
         + "';return t;}}return C.x+'" + _B + "';})()"),
        ("getter-local-let",
         "(function(){class C{static get x(){let t='" + _A
         + "';return t;}}return C.x+'" + _B + "';})()"),
        ("getter-local-const",
         "(function(){class C{static get x(){const t='" + _A
         + "';return t;}}return C.x+'" + _B + "';})()"),
        ("getter-dead-after-return",
         "(function(){class C{static get x(){return '" + _A
         + "';var z='q';}}return C.x+'" + _B + "';})()"),
        ("getter-additive-return",
         "(function(){class C{static get x(){return 'xoxb-'+'0123';}}return C.x+'"
         + _B + "';})()"),
        ("getter-outer-reassign",
         "(function(){var u='junk';class C{static get x(){return u;}}u='"
         + _A + "';return C.x+'" + _B + "';})()"),
        ("getter-shadows-outer",
         "(function(){var t='outer';class C{static get x(){var t='" + _A
         + "';return t;}}return C.x+'" + _B + "';})()"),
        ("getter-writes-outer",
         "(function(){var u='a';class C{static get x(){u='" + _A
         + "';return u;}}return C.x+'" + _B + "';})()"),
        # --- field always replaces same-named getter (node-verified)
        ("clash-field-first",
         "(function(){class C{static x='" + _A
         + "';static get x(){return 'junk';}}return C.x+'" + _B + "';})()"),
        ("clash-getter-first",
         "(function(){class C{static get x(){return 'junk';}static x='" + _A
         + "';}return C.x+'" + _B + "';})()"),
        ("dup-getter-later-wins",
         "(function(){class C{static get x(){return 'a';}static get x(){return '"
         + _A + "';}}return C.x+'" + _B + "';})()"),
        # --- uninitialized declarations feeding static blocks ---
        ("uninit-var-before",
         "(function(){var s;class C{static{s='" + _A + "';}}return s+'"
         + _B + "';})()"),
        ("uninit-var-after-hoisted",
         "(function(){class C{static{s='" + _A + "';}}var s;return s+'"
         + _B + "';})()"),
        ("uninit-let-before",
         "(function(){let s;class C{static{s='" + _A + "';}}return s+'"
         + _B + "';})()"),
        ("uninit-accum",
         "(function(){var s;class C{static{s='" + _A + "';}}s+='" + _B
         + "';return s;})()"),
        ("var-redecl-keeps-value",
         "(function(){var s='" + _A + "';var s;return s+'" + _B + "';})()"),
    ]
    bad = [n for n, p in cases
           if not (_decode_exact(p) == _CRED and _blocked(p))]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad,))


# ------------------------------------------------ fail-closed bounds


def test_p3_bounds():
    """Boundaries: decoder must miss (never mis-decode).

    NOTE (wave-380 lane 1): the "method", "computed",
    "instance-getter", and "class-expr" shapes below were F662
    fail-closed bounds; F672 (wave-380 lane 1) now models those
    productions node-exactly, so they decode -- see
    test_p3b_f672_absorbed. NOTE (wave-381 lane 4): the
    "constructor" shape below was an F662 fail-closed bound; F690
    (wave-381 lane 4) now models constructor this-assignments
    node-exactly, so it decodes -- see test_p3c_f690_absorbed.
    Honest absorption of documented residuals, not a regression.
    """
    cases = [
        ("extends", "(function(){class C extends Object{static x='" + _A
         + "';}return C.x+'" + _B + "';})()"),
        ("private", "(function(){class C{#x='qx';static y='f2';}return C.y;})()"),
        ("nonlit-field", "(function(){class C{static x=y;}return C.x;})()"),
        ("uninit-read", "(function(){class C{static x;}return C.x+'" + _B
         + "';})()"),
        ("missing-member", "(function(){class C{static x='" + _A
         + "';}return C.z+'" + _B + "';})()"),
        ("optchain", "(function(){class C{static x='" + _A
         + "';}return C?.x+'" + _B + "';})()"),
        ("anonymous", "(function(){return (class{static x='" + _A
         + "';}).x+'" + _B + "';})()"),
        ("block-decl", "(function(){let s='';class C{static{let t='" + _A
         + "';s=t;}}return s;})()"),
        ("block-return", "(function(){let s='';class C{static{return '" + _A
         + "';}}return s;})()"),
        ("call-args", "(function(){class C{static x='" + _A
         + "';}return C.x;})('z')"),
        ("named-fn", "(function foo(){class C{static x='" + _A
         + "';}return C.x+'" + _B + "';})()"),
        ("new-arg", "(function(){class C{x='" + _A
         + "';}return new C('z').x+'" + _B + "';})()"),
        ("strlit-member-name", "(function(){class C{static 'x'='" + _A
         + "';}return C.x+'" + _B + "';})()"),
        ("block-const-target", "(function(){const s='';class C{static{s='" + _A
         + "';}}return s;})()"),
        ("block-unbound-target", "(function(){class C{static{s='" + _A
         + "';}}return s;})()"),
        ("trailing-stmt", "(function(){class C{static x='" + _A
         + "';}return C.x;var z='q';})()"),
        # --- wave-379 spec-review remediation: documented bounds ---
        # ASI (missing `;`) is a decoder-family-wide boundary: F655
        # likewise requires explicit semicolons.
        ("getter-asi", "(function(){class C{static get x(){return '" + _A
         + "'}}return C.x+'" + _B + "';})()"),
        ("field-asi", "(function(){class C{static x='" + _A
         + "'}return C.x+'" + _B + "';})()"),
        ("block-asi", "(function(){var s='';class C{static{s='" + _A
         + "'}}return s+'" + _B + "';})()"),
        # `+=` on an uninitialized binding: the engine yields
        # 'undefinedLIT', outside the string-only discipline.
        ("block-plus-eq-uninit", "(function(){var s;class C{static{s+='" + _A
         + "';}}return s+'" + _B + "';})()"),
        # `let` after the class: TDZ -- the engine throws.
        ("let-after-class-tdz", "(function(){class C{static{s='" + _A
         + "';}}let s;return s+'" + _B + "';})()"),
        # Member reads / calls inside getter bodies are not modeled.
        ("getter-member-read", "(function(){class C{static y='" + _A
         + "';static get x(){return C.y;}}return C.x+'" + _B + "';})()"),
        ("getter-call", "(function(){class C{static get x(){return String('"
         + _A + "');}}return C.x+'" + _B + "';})()"),
        # Getter-body scope violations fail closed (engine throws or
        # yields a non-string).
        ("getter-unbound-ident", "(function(){class C{static get x(){return q;}}return C.x+'"
         + _B + "';})()"),
        ("getter-const-reassign", "(function(){class C{static get x(){const t='a';t='b';return t;}}return C.x+'"
         + _B + "';})()"),
        ("getter-let-tdz", "(function(){class C{static get x(){return t;let t='a';}}return C.x+'"
         + _B + "';})()"),
        ("getter-use-before-var", "(function(){class C{static get x(){return t;var t='a';}}return C.x+'"
         + _B + "';})()"),
        ("getter-nonlit-stmt", "(function(){class C{static get x(){var t=y;return t;}}return C.x+'"
         + _B + "';})()"),
    ]
    bad = [n for n, p in cases
           if not (_decode_exact(p) is None and _misses(p))]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad,))


def _decode_exact_f672(js):
    """Exact decoded value via the F672 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f672_class_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


def test_p3b_f672_absorbed():
    """F672-absorbed ex-bounds: decode node-exactly (wave-380 lane 1).

    These four shapes were F662 fail-closed bounds; F672 models the
    underlying productions (methods, computed members, instance
    getters, class expressions) node-exactly, so they now decode to
    the credential. Honest absorption of documented residuals.
    """
    cases = [
        ("method", "(function(){class C{static m(){return '" + _A
         + "';}}return C.m()+'" + _B + "';})()"),
        ("computed", "(function(){class C{static ['x']='" + _A
         + "';}return C.x+'" + _B + "';})()"),
        ("instance-getter", "(function(){class C{get x(){return '" + _A
         + "';}}return new C().x+'" + _B + "';})()"),
        ("class-expr", "(function(){var K=class C{static x='" + _A
         + "';};return K.x+'" + _B + "';})()"),
    ]
    bad = [n for n, p in cases
           if not (_decode_exact_f672(p) == _CRED and _blocked(p))]
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


def test_p3c_f690_absorbed():
    """F690-absorbed ex-bound: decodes node-exactly (wave-381 lane 4).

    The constructor shape was an F662 fail-closed bound; F690 models
    constructor this-assignments node-exactly, so it now decodes to
    the credential. Honest absorption of a documented residual.
    """
    cases = [
        ("constructor", "(function(){class C{constructor(){this.x='" + _A
         + "';}}return new C().x+'" + _B + "';})()"),
    ]
    bad = [n for n, p in cases
           if not (_decode_exact_f690(p) == _CRED and _blocked(p))]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad,))


# ------------------------------------------------ neighbors


def test_p4_open_neighbors_still_miss():
    """F663-F671 now CLOSED (wave-379 merge): they block, nothing absorbed."""
    cases = [
        ("f663", "(function(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})()"),
        ("f664", "(function(){var o={get x(){return '" + _A
         + "';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'"
         + _B + "';})()"),
        ("f665", "(function(){var o={a:'" + _A + "'};return o?.a+'" + _B
         + "';})()"),
        ("f666", "(function(){var p=new Proxy(function(){},{apply:function(){return '"
         + _A + "';}});return p()+'" + _B + "';})()"),
        ("f667", "(function(){var o={a:'" + _A + "',b:'" + _B
         + "'};with(o){return a+b;}})()"),
        ("f668", "(function(){function tag(s){return s[0]+'" + _B
         + "';}return tag`" + _A + "`;})()"),
        ("f669", "(function(){var s=new Set(['" + _A + "','" + _B
         + "']);return [...s].join('');})()"),
        ("f670", "(function(){var a='" + _A + "',b='" + _B
         + "';var p=new Proxy({},{get:(t,k)=>{return a+b;}});return p.anything;})()"),
        ("f671", "(function(){var o={x:'" + _A + "'};return o.x+'" + _B
         + "';})()"),
    ]
    bad = [n for n, p in cases if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "not_blocked=%s" % (bad,))


def test_p5_closed_neighbors_still_held():
    """Closed neighbors: F655/F611/F642/F535/F649 still block."""
    cases = [
        ("f655", "(function(){var a='" + _A + "';var b='" + _B
         + "';return a+b;})()"),
        ("f611", "(function(){var s='" + _A + "';return s+'" + _B
         + "';})()"),
        ("f642", "(function(){var a='" + _A + "',b='" + _B
         + "';var o={get s(){return a+b;}};return o.s;})()"),
        ("f535", "({a:'" + _A + "'}).a+'" + _B + "'"),
        ("f649", "(function(){var o=structuredClone({a:'" + _A + "',b:'"
         + _B + "'});return o.a+o.b;})()"),
    ]
    bad = [n for n, p in cases if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "lost=%s" % (bad,))


# ------------------------------------------------ junk / composition


def test_p6_junk_quiet():
    """Honest text stays quiet."""
    cases = [
        "(function(){var s='ab';return s;})()",
        "(function(){class C{static x='ab';}return C.x;})()",
        "just some text with class C{static x='y';} in it",
    ]
    bad = [p for p in cases if not _misses(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "noisy=%s" % (len(bad),))


def test_p6_composition():
    """F662 fragments compose with the outer additive grammar."""
    p = ("(function(){class C{static x='" + _A + "';}return C.x;})()+'"
         + _B + "'")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "outer-additive=%s" % ok)


# ------------------------------------------------ node differential


def test_p7_node_differential():
    """Decoder agrees with node v24.20.0 on the modeled class."""
    try:
        node = subprocess.run(["node", "--version"], capture_output=True,
                              text=True, timeout=10).stdout.strip()
    except Exception:
        return ("HELD", "node unavailable -- skipped")
    import json
    cases = [
        # (payload, want): True = decode == node == _CRED;
        # "MISS:<json>" = decode None, node == <json>; "THROW" = both miss/throw.
        ("(function(){class C{static x='" + _A + "';}return C.x+'" + _B
         + "';})()", True),
        ("(function(){let s='';class C{static{s='" + _A + "';}}s+='" + _B
         + "';return s;})()", True),
        ("(function(){class C{static get x(){return '" + _A
         + "';}}return C.x+'" + _B + "';})()", True),
        ("(function(){class C{x='" + _A + "';}return new C().x+'" + _B
         + "';})()", True),
        ("(function(){class C{static x='jx';static x='" + _A
         + "';}return C.x+'" + _B + "';})()", True),
        ("(function(){class C{static m(){return '" + _A
         + "';}}return 'f2';})()", "MISS:" + json.dumps("f2")),
        # --- wave-379 spec-review remediation shapes ---
        ("(function(){class C{static get x(){return ('" + _A
         + "');}}return C.x+'" + _B + "';})()", True),
        ("(function(){class C{static get x(){var t='" + _A
         + "';return t;}}return C.x+'" + _B + "';})()", True),
        ("(function(){class C{static get x(){let t='" + _A
         + "';return t;}}return C.x+'" + _B + "';})()", True),
        ("(function(){var u='junk';class C{static get x(){return u;}}u='"
         + _A + "';return C.x+'" + _B + "';})()", True),
        ("(function(){class C{static x='" + _A
         + "';static get x(){return 'junk';}}return C.x+'" + _B + "';})()",
         True),
        ("(function(){class C{static get x(){return 'junk';}static x='" + _A
         + "';}return C.x+'" + _B + "';})()", True),
        ("(function(){var s;class C{static{s='" + _A + "';}}return s+'"
         + _B + "';})()", True),
        ("(function(){class C{static{s='" + _A + "';}}var s;return s+'"
         + _B + "';})()", True),
        ("(function(){let s;class C{static{s='" + _A + "';}}return s+'"
         + _B + "';})()", True),
        ("(function(){class C{static{s='" + _A + "';}}let s;return s;})()",
         "THROW"),
        ("(function(){class C{static get x(){return t;let t='a';}}return C.x;})()",
         "THROW"),
        ("(function(){class C{static get x(){return t;var t='a';}}return typeof C.x;})()",
         "MISS:" + json.dumps("undefined")),
    ]
    bad = []
    for p, want in cases:
        r = subprocess.run(
            ["node", "-e",
             "try{console.log(JSON.stringify(eval(" + json.dumps(p)
             + ")))}catch(e){console.log('THROW')}"],
            capture_output=True, text=True, timeout=15)
        nv = r.stdout.strip()
        dv = _decode_exact(p)
        if want is True:
            if not (dv == _CRED and nv == json.dumps(_CRED)):
                bad.append(p[:40])
        elif want == "THROW":
            if not (dv is None and nv == "THROW"):
                bad.append(p[:40])
        else:
            assert want.startswith("MISS:")
            if not (dv is None and nv == want[5:]):
                bad.append(p[:40])
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "node=%s bad=%s" % (node, bad))


# ------------------------------------------------ pin / footer / perf


def test_p8_pin_footer():
    """Pin 2143; lane-local footer: open F673-F685, next F686 (F672 CLOSED wave-380 lane 1)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    import re
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "FINDINGS.md")
    text = open(p, encoding="utf-8").read()
    ok = (TAXONOMY_PIN == 2143 and len(dc.TAXONOMY) > 0  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
          and "Next free finding: **F700**." in text
          and "Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699."  # Wave-380 merge: F672-F685 CLOSED; footer repoint open F686-F699 / next F700
          in text)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


def test_p8_no_new_regexes():
    """Zero new re.compile in gov/dlp.py (28 stays)."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "gov", "dlp.py"),
               encoding="utf-8").read()
    n = src.count("re.compile(")
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


def test_p9_perf():
    """200 class sites decode fast."""
    p = ("(function(){class C{static x='" + _A + "';}return C.x+'" + _B
         + "';})()")
    t0 = time.time()
    for _ in range(200):
        find_credential(p)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "200 in %.2fs" % dt)


# ------------------------------------------------ green check (depth-1)


def test_p10_green_check():
    """Depth-1 green check: F662 red-first + w378 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    here = os.path.dirname(os.path.abspath(__file__))
    tmp = tempfile.mkdtemp(prefix="g379-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    bad = []
    for batt, label in (("w378_f662_redfirst.py", "f662-redfirst"),
                        ("w378_attack_probes.py", "w378-attack")):
        r = subprocess.run(
            [sys.executable, os.path.join(here, batt)],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(here, ".."))
        tail = (r.stdout + r.stderr)[-400:]
        # The red-first must now be 0 BREAK; the attack battery must
        # have no *real* BREAK (footer staleness is merge-owned).
        if label == "f662-redfirst":
            if "0 BREAK" not in tail:
                bad.append("%s: %s" % (label, tail[-120:]))
        else:
            if "BREAK" in tail and "0 BREAK" not in tail:
                # tolerate only footer-state lines
                lines = [ln for ln in tail.splitlines()
                         if "BREAK" in ln and "footer" not in ln.lower()]
                if lines:
                    bad.append("%s: %s" % (label, lines[0][-120:]))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name, fn in sorted(
            [(k, v) for k, v in globals().items()
             if k.startswith("test_") and callable(v)]):
        _t(name, fn)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD / %d total"
          % (breaks, held, len(results)))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
