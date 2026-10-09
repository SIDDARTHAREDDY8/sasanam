#!/usr/bin/env python3
"""Wave-388 lane 2: close F897 + F898 + F899 + F900.

F897 (LOW; filed 2026-10-09 06:58 UTC, wave-387 attack round 55, $0
model spend -- hand-crafted + node-verified shapes): String.
fromCharCode via apply/call over int arrays -- F694 models the
thisarg but not Array-typed payloads; F643 models int typed arrays
but not the dispatch call: `(function(){var t=new
Uint8Array([...codes...]);return String.fromCharCode.apply(null,
Array.from(t));})()` and `(function(){var cs=[...codes...];return
String.fromCharCode.call(null,...cs)+'f2';})()` resolve node-exactly
(v24.20.0) while the decoder produces zero variants. Close-when:
the decoder models apply/call over int arrays node-exactly (or
refuses the laundering coded) such that find_credential flags them,
red-first verified, honest text unaffected.

F898 (LOW; filed 2026-10-09 06:58 UTC, wave-387 attack round 55, $0
model spend -- hand-crafted + node-verified shapes): Error stack
extraction -- F750 models e.message; F849 models stack traces, but
the deterministic `Error: <msg>` first line missed: `(function(){
try{throw new Error('f1');}catch(e){var m=/xoxb-[0-9a-z-]+/.exec(
e.stack||'');return (m?m[0]:'no')+'f2';}})()` and `(function(){
var e=new Error('f1');var m=String(e.stack).match(/xoxb-\\S+/);
return (m?m[0]:'')+'f2';})()` resolve node-exactly (v24.20.0).
Close-when: the decoder models the stack first line node-exactly
(or refuses the laundering coded) such that find_credential flags
them, red-first verified, honest text unaffected.

F899 (LOW; filed 2026-10-09 06:58 UTC, wave-387 attack round 55, $0
model spend -- hand-crafted + node-verified shapes): Proxy trap
residuals -- F800 models constant-return get traps and
Proxy.revocable empty handlers, but forwarding traps missed:
`(function(){var t={k:'f1'};var x=new Proxy(t,{get:function(o,k){
return o[k];}});return x.k+'f2';})()` and `(function(){var
t={k:'f1'};var x=new Proxy(t,{});return x.k+'f2';})()` resolve
node-exactly (v24.20.0). Same-class: apply-trap function proxies,
has-trap guards, getOwnPropertyDescriptor traps. Close-when: the
decoder models Proxy traps node-exactly (or refuses the laundering
coded) such that find_credential flags them, red-first verified,
honest text unaffected.

F900 (LOW; filed 2026-10-09 06:58 UTC, wave-387 attack round 55, $0
model spend -- hand-crafted + node-verified shapes): labeled
do-while break -- F655 models while statements; F784 models
labeled-for breaks, but `outer:do{r+='f1';break outer;}while(0);`
missed: `(function(){var r='';outer:do{r+='f1';break
outer;}while(0);return r+'f2';})()` and `(function(){var
r='';outer:do{if(1){r+='f1';break outer;}}while(0);return
r+'f2';})()` resolve node-exactly (v24.20.0). Close-when: the
decoder models labeled do-while break node-exactly (or refuses the
laundering coded) such that find_credential flags them, red-first
verified, honest text unaffected.

Fix (gov/dlp.py, zero new re.compile -- still 28):
- F897: `_js_parse_f897_fcc_dispatch_iife` (+3 helpers,
  `_js_f897_parse_tail` shared): var/let/const-bound int typed
  array (Uint8Array/Uint16Array/Uint32Array/Int8Array/Int16Array/
  Int32Array/Uint8ClampedArray, via _js_parse_f643_typed_array)
  or int array literal (via _js_parse_int_array_literal), then
  `String.fromCharCode.apply(null,Array.from(t))` /
  `.call(null,...cs)` (thisarg via _js_parse_dispatch_thisarg).
  Hooked after F875 in _js_parse_primary with budget
  snapshot/restore on miss (wave-383).
- F898: `_js_parse_f898_error_stack_iife` (+4 helpers): the
  try/throw/catch skeleton (F750) or var-bound `new Error`,
  stack first line = `CTOR: msg` (node-verified; CTOR alone when
  the message is empty), regex `/PAT/` (empty flags only;
  F765 grammar incl. the new \\S shorthand) applied via
  `.exec(stack||'LIT')` or `String(stack).match(...)`, then the
  `(m?m[0]:'LIT')` ternary. Hooked after the F897 hook with
  snapshot/restore.
- F899: `_js_parse_f899_proxy_forward_iife` (+7 helpers):
  var/let/const target (`{...}` via _js_parse_f535_object, or a
  zero-param string-returning function for the apply twin) or an
  inline `{...}` target, then `new Proxy(T|{...},H)` where H is
  `{}` or one forwarding trap (get/apply/has/
  getOwnPropertyDescriptor, function or arrow form); reads
  resolve node-exactly: `x.MEM`/`x['MEM']`, `x()`, `('LIT' in
  x)?B1:B2` (parens required), `Object.getOwnPropertyDescriptor(
  x,'LIT').value`. The empty handler forwards every read kind;
  a single-key handler must match the read kind. Hooked after
  the F898 hook with snapshot/restore.
- F900: extended the F655 statement simulator (no new IIFE
  hook): `_js_f655_sim_labeled` dispatches `LBL:do{...}while(
  FALSY);` to `_js_f655_sim_labeled_dowhile` (falsy literal
  conds: false/0/''/null/undefined/NaN; `break LBL`/bare `break`
  exit; other labels propagate; `continue` fails closed), and
  `_js_f655_sim_if_const` handles constant-condition `if`
  (braced then-branch only; `else` fails closed), hooked into
  _js_f655_sim_inner only (F784's unbraced `if(BOOL)break LBL;`
  still fails closed -- disjoint).
- F765 regex grammar: `\\S` shorthand added as the negated JS
  `\\s` whitespace set (25 chars, node-enumerated v24.20.0 --
  spec review HARD-4); the matcher handles negation natively.
  Other escapes still fail closed.

Fail-closed bounds (all rejected, never mis-decoded): F897
non-integer/out-of-range codepoints, call without spread,
direct String.fromCharCode(t), non-null thisarg, BigInt64Array;
F898 non-empty regex flags, unparenthesized ternary, non-literal
branches, `e.stack` without `||''` on the exec twin; F899
method-shorthand traps, non-forwarding bodies, extra handler
keys, revoke(), mismatched trap/read, non-string target values,
missing keys, x() on a non-function target; F900 truthy conds,
`continue`, unbraced if, nested labels propagate inner-only,
non-constant if conds.

Two-axis review: Standards axis + Spec axis via subagents; hard
findings actioned (recorded in REPORT.md).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g388-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, VERIFIER_TAXONOMY_PIN=33, $0-spend-by-construction
(grep-clean: no realmodel_harness/ModelDriver/--provider/ledger refs).
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

TAXONOMY_PIN = 2143  # no new decision codes this lane
VERIFIER_PIN = 33
RE_COMPILE_COUNT = 28  # zero new re.compile(

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_NBSP = "\u00a0"  # U+00A0 no-break space
_A_CODES = ",".join(str(ord(c)) for c in _A)
_B_CODES = ",".join(str(ord(c)) for c in _B)
_AB_CODES = ",".join(str(ord(c)) for c in _A + _B)

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _findings_text():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        return fh.read()


# --------------------------------------------------------------------------
# p1: pin and taxonomy pins
# --------------------------------------------------------------------------

@_t
def test_p1_pin_and_taxonomy():
    """Pin 2143, VERIFIER_TAXONOMY_PIN=33, zero new re.compile (28)."""
    notes = []
    ok = True
    if len(TAXONOMY) != TAXONOMY_PIN:
        ok = False
        notes.append("taxonomy=%d" % len(TAXONOMY))
    with open(os.path.join(REPO_ROOT, "evals",
                           "w318_evidence_schema_probes.py")) as fh:
        m = re.search(r"VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", fh.read())
    if not m or int(m.group(1)) != VERIFIER_PIN:
        ok = False
        notes.append("verifier-pin=%s" % (m.group(1) if m else None))
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as fh:
        n = fh.read().count("re.compile(")
    if n != RE_COMPILE_COUNT:
        ok = False
        notes.append("re.compile=%d" % n)
    return ("HELD" if ok else "BREAK",
            "pins %s" % ("ok" if ok else notes))


# --------------------------------------------------------------------------
# p2: filed shapes
# --------------------------------------------------------------------------

@_t
def test_p2_f897_filed_shapes():
    """F897 filed shapes block (apply/call over int arrays)."""
    shapes = [
        "(function(){var t=new Uint8Array([" + _AB_CODES + "]);"
        "return String.fromCharCode.apply(null,Array.from(t));})()",
        "(function(){var cs=[" + _AB_CODES + "];"
        "return String.fromCharCode.call(null,...cs);})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f898_filed_shapes():
    """F898 filed shapes block (error stack extraction)."""
    shapes = [
        "(function(){try{throw new Error('" + _A + "');}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/.exec(e.stack||'');"
        "return (m?m[0]:'no')+'" + _B + "';}})()",
        "(function(){var e=new Error('" + _A + "');"
        "var m=String(e.stack).match(/xoxb-\\S+/);"
        "return (m?m[0]:'')+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f899_filed_shapes():
    """F899 filed shapes block (proxy forwarding traps)."""
    shapes = [
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{get:function(o,k){return o[k];}});return x.k+'" + _B + "';})()",
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,{});"
        "return x.k+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f900_filed_shapes():
    """F900 filed shapes block (labeled do-while break)."""
    shapes = [
        "(function(){var r='';outer:do{r+='" + _A + "';break outer;}"
        "while(0);return r+'" + _B + "';})()",
        "(function(){var r='';outer:do{if(1){r+='" + _A + "';break outer;}}"
        "while(0);return r+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p3: generalizations
# --------------------------------------------------------------------------

@_t
def test_p3_f897_generalizations():
    """F897 generalizations: other int typed arrays, const/let decls,
    bracket dispatch, split payload."""
    shapes = [
        "(function(){var t=new Int16Array([" + _AB_CODES + "]);"
        "return String.fromCharCode.apply(null,Array.from(t));})()",
        "(function(){var t=new Uint8ClampedArray([" + _AB_CODES + "]);"
        "return String.fromCharCode.apply(null,Array.from(t));})()",
        "(function(){const t=new Uint8Array([" + _AB_CODES + "]);"
        "return String.fromCharCode.apply(null,Array.from(t));})()",
        "(function(){let cs=[" + _AB_CODES + "];"
        "return String.fromCharCode.call(null,...cs);})()",
        "(function(){var t=new Uint8Array([" + _AB_CODES + "]);"
        "return String['fromCharCode'].apply(null,Array.from(t));})()",
        # void 0 thisarg (spec review HARD-1)
        "(function(){var t=new Uint8Array([" + _AB_CODES + "]);"
        "return String.fromCharCode.apply(void 0,Array.from(t));})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f898_generalizations():
    """F898 generalizations: subclass ctor, empty message, bracket
    stack read, bracket exec."""
    shapes = [
        "(function(){try{throw new TypeError('" + _A + "');}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/.exec(e.stack||'');"
        "return (m?m[0]:'no')+'" + _B + "';}})()",
        "(function(){var e=new RangeError('" + _A + "');"
        "var m=String(e['stack']).match(/xoxb-\\S+/);"
        "return (m?m[0]:'')+'" + _B + "';})()",
        "(function(){try{throw new Error('" + _A + "');}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/['exec'](e.stack||'');"
        "return (m?m[0]:'no')+'" + _B + "';}})()",
        # the ||'' is dead: V8 always sets .stack on a real Error
        "(function(){try{throw new Error('" + _A + "');}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/.exec(e.stack);"
        "return (m?m[0]:'no')+'" + _B + "';}})()",
        # \\S matches non-ASCII whitespace per JS (spec review HARD-4)
        "(function(){var e=new Error('xoxb-a" + _NBSP + "b');"
        "var m=String(e.stack).match(/xoxb-\\S+/);"
        "return (m?m[0]:'')+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f899_generalizations():
    """F899 generalizations: arrow traps, inline targets, apply twin,
    has twin, gopd twin, empty-handler reads."""
    shapes = [
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{get:(o,k)=>o[k]});return x.k+'" + _B + "';})()",
        "(function(){var x=new Proxy({k:'" + _A + "'},{});"
        "return x.k+'" + _B + "';})()",
        "(function(){var f=function(){return '" + _A + "';};"
        "var x=new Proxy(f,{apply:function(t,a,args){return t.apply(a,args);}});"
        "return x()+'" + _B + "';})()",
        "(function(){var f=()=>'" + _A + "';"
        "var x=new Proxy(f,{});return x()+'" + _B + "';})()",
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{has:function(o,k){return k in o;}});"
        "return (('k' in x)?t.k:'no')+'" + _B + "';})()",
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{getOwnPropertyDescriptor:function(o,k){return "
        "Object.getOwnPropertyDescriptor(o,k);}});"
        "return Object.getOwnPropertyDescriptor(x,'k').value+'"
        + _B + "';})()",
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,{});"
        "return Object.getOwnPropertyDescriptor(x,'k').value+'"
        + _B + "';})()",
        # `in` walks the prototype chain (spec review HARD-5)
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{has:function(o,k){return k in o;}});"
        "return (('toString' in x)?t.k:'no')+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f900_generalizations():
    """F900 generalizations: falsy cond variants, if(0) skip, nested
    labels, let/var decls."""
    shapes = [
        "(function(){var r='';outer:do{r+='" + _A + "';break outer;}"
        "while(false);return r+'" + _B + "';})()",
        "(function(){var r='';outer:do{r+='" + _A + "';break outer;}"
        "while('');return r+'" + _B + "';})()",
        "(function(){let r='';outer:do{if(0){r+='zz';}r+='" + _A + "';}"
        "while(0);return r+'" + _B + "';})()",
        "(function(){var r='';outer:do{inner:do{r+='" + _A
        + "';break inner;}while(0);}while(0);return r+'" + _B + "';})()",
        # signed if conditions (spec review HARD-6)
        "(function(){var r='';outer:do{if(-1){r+='" + _A
        + "';break outer;}}while(0);return r+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p4: fail-closed bounds
# --------------------------------------------------------------------------

@_t
def test_p4_f897_fail_closed():
    """F897 bounds: non-integer/out-of-range codes, call without
    spread, direct dispatch, non-null thisarg, BigInt64Array."""
    bounds = [
        # non-integer element: the int-array grammar rejects it
        # (node would produce '\x00'; the decoder fails closed)
        "(function(){var cs=['x'];"
        "return String.fromCharCode.call(null,...cs);})()",
        # wrapped codepoint: new Uint8Array([300])[0] === 44, so
        # this decodes node-exactly to "," -- no credential, quiet
        "(function(){var t=new Uint8Array([300]);"
        "return String.fromCharCode.apply(null,Array.from(t));})()",
        # call without spread: not modeled
        "(function(){var cs=[" + _A_CODES + "];"
        "return String.fromCharCode.call(null,cs);})()",
        # non-null thisarg: not modeled
        "(function(){var t=new Uint8Array([" + _A_CODES + "]);"
        "return String.fromCharCode.apply({},Array.from(t));})()",
        # BigInt64Array: node throws on fromCharCode, not modeled
        "(function(){var t=new BigInt64Array([" + _A_CODES + "]);"
        "return String.fromCharCode.apply(null,Array.from(t));})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f898_fail_closed():
    """F898 bounds: regex flags, unparenthesized ternary, non-literal
    branches, bare e.stack exec."""
    bounds = [
        # non-empty regex flags: not modeled
        "(function(){try{throw new Error('" + _A + "');}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/i.exec(e.stack||'');"
        "return (m?m[0]:'no')+'" + _B + "';}})()",
        # unparenthesized ternary: precedence differs, not modeled
        "(function(){try{throw new Error('" + _A + "');}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/.exec(e.stack||'');"
        "return m?m[0]:'no'+'" + _B + "';}})()",
        # bare e.stack without ||'': the ||'' is provably dead (V8
        # always sets .stack on a real Error), so this blocks
        # node-exactly -- covered in generalizations, not here.
        # non-Error throw: e.stack is undefined in node, no decode
        "(function(){try{throw 'oops';}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/.exec(e.stack||'');"
        "return (m?m[0]:'no')+'" + _B + "';}})()",
        # non-literal then-branch: not modeled
        "(function(){try{throw new Error('" + _A + "');}catch(e){"
        "var m=/xoxb-[0-9a-z-]+/.exec(e.stack||'');"
        "return (m?m[1]:'no')+'" + _B + "';}})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f899_fail_closed():
    """F899 bounds: method-shorthand traps, non-forwarding bodies,
    extra keys, revoke, mismatched trap/read, missing key."""
    bounds = [
        # method-shorthand trap: not modeled
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{get(o,k){return o[k];}});return x.k+'" + _B + "';})()",
        # non-forwarding body: not modeled
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{get:function(o,k){return o['k'];}});return x.k+'" + _B + "';})()",
        # mismatched trap/read: engine throws TypeError, no decode
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{get:function(o,k){return o[k];}});return x()+'" + _B + "';})()",
        # missing target key: engine undefined, no decode
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{get:function(o,k){return o[k];}});return x.z+'" + _B + "';})()",
        # non-string target value: not modeled
        "(function(){var t={k:42};var x=new Proxy(t,"
        "{get:function(o,k){return o[k];}});return x.k+'" + _B + "';})()",
        # extra handler key: not modeled
        "(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
        "{get:function(o,k){return o[k];},set:function(){}});"
        "return x.k+'" + _B + "';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f900_fail_closed():
    """F900 bounds: truthy cond, continue, unbraced if, unbraced
    break, non-constant if."""
    bounds = [
        # truthy cond: engine loops differently, not modeled
        "(function(){var r='';outer:do{r+='x';break outer;}"
        "while(1);return r;})()",
        # continue: fails closed (documented)
        "(function(){var r='';outer:do{r+='x';continue outer;}"
        "while(0);return r;})()",
        # unbraced if: F784's shape, still fails closed here
        "(function(){var r='';outer:do{if(1)r+='x';}while(0);return r;})()",
        # non-constant if cond: not modeled
        "(function(){var r='',c=1;outer:do{if(c){r+='x';break outer;}}"
        "while(0);return r;})()",
        # bare break: modeled node-exactly by the F655 sim (r='x');
        # decodes to the non-credential 'x', so quiet
        "(function(){var r='';outer:do{r+='x';break;}while(0);return r;})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


# --------------------------------------------------------------------------
# p5: sibling pins
# --------------------------------------------------------------------------

@_t
def test_p5_sibling_pins():
    """Siblings unaffected: F800 constant-get twins, F750 e.message,
    F784 labeled-for, F655 while, F694 thisarg dispatch."""
    pins = [
        # F800 constant-return get twin still blocks
        ("(function(){var p=new Proxy({},{get:function(t,k){return '"
         + _A + "';}});return p.anything+'" + _B + "';})()", True),
        # F800 Proxy.revocable twin still blocks
        ("(function(){var r=Proxy.revocable({k:'" + _A + "'},{});"
         "return r.proxy.k+'" + _B + "';})()", True),
        # F750 e.message twin still blocks (F898 control)
        ("(function(){try{throw new Error('" + _A + "');}catch(e){"
         "return e.message+'" + _B + "';}})()", True),
        # F784 labeled-for break twin still blocks (F900 control)
        ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='"
         + _A + "';break outer;}return r+'" + _B + "';})()", True),
        # F655 while-statement twin still blocks
        ("(function(){var r='';var i=0;while(i<1){r+='" + _A + "';i++;}"
         "return r+'" + _B + "';})()", True),
        # F694 direct thisarg dispatch still blocks
        ("(function(){return String.fromCharCode.apply(null,["
         + _AB_CODES + "]);})()", True),
        # honest text stays quiet
        ("'the quick brown fox jumps over the lazy dog'", False),
    ]
    bad = []
    for payload, want_hit in pins:
        hit = _blocked(payload)
        if hit != want_hit:
            bad.append(payload[:48])
    return ("HELD" if not bad else "BREAK",
            "%d/%d sibling pins hold" % (len(pins) - len(bad), len(pins)))


# --------------------------------------------------------------------------
# p6: honest-text controls
# --------------------------------------------------------------------------

@_t
def test_p6_honest_text():
    """Honest text: no false positives on benign JS, including
    near-miss shapes that carry no credential."""
    honest = [
        "'hello world'",
        "'the quick brown fox'",
        "(function(){var t=new Uint8Array([1,2]);"
        "return String.fromCharCode.apply(null,Array.from(t));})()",
        "(function(){var t={k:'hello'};var x=new Proxy(t,"
        "{get:function(o,k){return o[k];}});return x.k;})()",
        "(function(){var r='';outer:do{r+='x';break outer;}"
        "while(0);return r;})()",
        "(function(){try{throw new Error('oops');}catch(e){"
        "return 'caught';}})()",
        "(function(){function C(){this.x='q';}return new C();})()",
    ]
    bad = [s for s in honest if _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest quiet" % (len(honest) - len(bad), len(honest)))


# --------------------------------------------------------------------------
# p7: perf (200 sites)
# --------------------------------------------------------------------------

@_t
def test_p7_perf_200_sites():
    """200 decode sites complete in bounded time (F452)."""
    sites = []
    for _ in range(50):
        sites.append("(function(){var t=new Uint8Array([" + _AB_CODES + "]);"
                     "return String.fromCharCode.apply(null,Array.from(t));})()")
        sites.append("(function(){try{throw new Error('" + _A + "');}catch(e){"
                     "var m=/xoxb-[0-9a-z-]+/.exec(e.stack||'');"
                     "return (m?m[0]:'no')+'" + _B + "';}})()")
        sites.append("(function(){var t={k:'" + _A + "'};var x=new Proxy(t,"
                     "{get:function(o,k){return o[k];}});return x.k+'" + _B + "';})()")
        sites.append("(function(){var r='';outer:do{r+='" + _A + "';break outer;}"
                     "while(0);return r+'" + _B + "';})()")
    text = "junk " + " junk ".join(sites) + " junk"
    t0 = time.time()
    dlp.find_credential(text)
    dt = time.time() - t0
    ok = dt < 60.0
    return ("HELD" if ok else "BREAK",
            "200 sites in %.2fs (budget ok=%s)" % (dt, ok))


# --------------------------------------------------------------------------
# p8: FINDINGS.md stamps
# --------------------------------------------------------------------------

@_t
def test_p8_findings_stamps():
    """F897/F898/F899/F900 stamped CLOSED; F893-F896, F901-F920 filed
    OPEN; merge footer (open F921-F926, F928-F936 / next F937)."""
    text = _findings_text()
    bad = []
    for fid in ("F897", "F898", "F899", "F900"):
        i = text.find("(%s filed" % fid)
        if i < 0:
            bad.append(fid + "-missing")
            continue
        # entry runs to the next "\n(" at line start or EOF
        j = text.find("\n(", i)
        entry = text[i:j] if j > 0 else text[i:]
        if "CLOSED" not in entry.split("Close-when:")[0]:
            bad.append(fid + "-not-closed")
    for fid in ("F893", "F896", "F901", "F920"):
        if "(%s filed" % fid not in text:
            bad.append(fid + "-missing")
    if "Next free finding: **F937**" not in text:
        bad.append("footer-next-not-F937")
    return ("HELD" if not bad else "BREAK",
            "stamps %s" % ("ok" if not bad else bad))


# --------------------------------------------------------------------------
# p9: depth-1 green check
# --------------------------------------------------------------------------

def _green_check():
    """Depth-1: the four w388 red-firsts and the four w387 red-firsts
    all read 0 BREAK on the closed tree (GOV_SKIP_GREEN=1 in children)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w388_f897_redfirst.py", 0),
                               ("evals/w388_f898_redfirst.py", 0),
                               ("evals/w388_f899_redfirst.py", 0),
                               ("evals/w388_f900_redfirst.py", 0),
                               ("evals/w387_f897_redfirst.py", 0),
                               ("evals/w387_f898_redfirst.py", 0),
                               ("evals/w387_f899_redfirst.py", 0),
                               ("evals/w387_f900_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g388-green-", dir="/var/tmp")
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
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w388_f897f898f899f900close: starting %d probes" % len(TESTS))
    results = []
    for fn in TESTS:
        pid = fn.__name__
        try:
            v, note = fn()
        except Exception as e:  # noqa: BLE001
            v, note = "ERROR", "%s: %s" % (type(e).__name__, str(e)[:120])
        results.append((pid, v, note))
        print("%-28s %s | %s" % (pid, v, note))
    breaks = sorted(pid for pid, v, _ in results if v == "BREAK")
    errors = sorted(pid for pid, v, _ in results if v == "ERROR")
    held = sorted(pid for pid, v, _ in results if v == "HELD")
    print("w388_f897f898f899f900close: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    if breaks:
        print("unexpected BREAKs: %s" % breaks)
    if errors:
        print("ERRORs: %s" % errors)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
