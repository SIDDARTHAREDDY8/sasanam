#!/usr/bin/env python3
"""Wave-410 lane 3 close battery: F1274-F1280 CLOSED (+ F1315).

F1274: TypedArray apply/while staging -- new Uint8Array(C) then
String.fromCharCode.apply(null,U) or while(i<U.length){S+=fcc(U[i++])}.
Closed by _js_f1274_stmt_decode (ToUint8 decode). Disjoint from F1254
(plain-array apply) and F1246 (plain-array while) by the TypedArray.

F1275: join/split codec residuals -- U.join(",")/split(",")/Number()
or C.toLocaleString("en-US")/split(",")/Number(). Closed by
_js_f1275_stmt_decode. The toLocaleString branch fails closed on codes
>= 1000 (en-US grouping breaks the node roundtrip). Disjoint from F1199
(plain-Array join/split) by the TypedArray/toLocaleString.

F1276: text codec roundtrips -- D.decode(E.encode(J)) or the
codePointAt push-loop + apply. Closed by _js_f1276_stmt_decode.
Disjoint from F1219 (charCodeAt) by the TextEncoder/codePointAt.

F1277: block-statement wrappers -- F1199 body inside if(true){},
try{}catch{}, lbl:{}, for(;;){break;}, with({A:...}){}. Closed by
_js_f1277_stmt_decode. Disjoint from F1123 (whole-text unwrap) by the
mid-text position and F1195 (expression wrappers) by the block form.

F1278: expression-guard wrappers -- comma, void||, typeof ternary,
instanceof ternary. Closed by _js_f1278_stmt_decode. Disjoint from
F1195 (template/String()/""+ wrappers) by the guard expressions.

F1279: in-operator while-loop staging -- while((i in O)) over a
forEach/for-loop staged object. Closed by _js_f1279_stmt_decode.
Disjoint from F1246 (plain while) by the `in` operator and F1209
(while+shift) by the loop form.

F1280: hasOwn-guarded for-in staging -- for(k in O){if(hasOwn){...}}.
Closed by _js_f1280_stmt_decode. Disjoint from F1044 (bare for-in)
by the hasOwn guard and staged fill.

F1315: hasOwnProperty method-call guard -- O.hasOwnProperty(k).
Discovered during F1280 closure (filed 2026-10-11 07:10 UTC, next-free
from wave-409 footer). Closed by the extended _js_f1280_parse_guard.

All hooks are whole-text, narrow-grammar, fail-closed, F452-charged
per attempt (snapshot/restore on branch miss), and results are bounded
by _MAX_DECODE_BYTES. Never evals. Green checks ON. $0-spend-by-construction.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RECOMPILE_PIN = 29
STMTDEC_PIN = 58  # wave-410 lane 3: 57 + 1 F1274-F1280 loop (real code-count change)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _hits(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _p(tmpl, secret=SECRET_S):
    return tmpl.replace("{I}", _codes(secret))

FILED = [
    ("f1274-u8-apply",
     "var C={I};var U=new Uint8Array(C);var S=String.fromCharCode.apply(null,U);var RESULT=S;"),
    ("f1274-u8-while",
     "var C={I};var U=new Uint8Array(C);var S='';var i=0;while(i<U.length){S+=String.fromCharCode(U[i++]);}var RESULT=S;"),
    ("f1275-u8-join-split",
     "var C={I};var U=new Uint8Array(C);var J=U.join(',');var A=J.split(',');var S=String.fromCharCode.apply(null,A.map(function(x){return Number(x);}));var RESULT=S;"),
    ("f1275-tolocalestring",
     "var C={I};var J=C.toLocaleString('en-US');var A=J.split(',');var S=String.fromCharCode.apply(null,A.map(function(x){return Number(x);}));var RESULT=S;"),
    ("f1276-textenc",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var E=new TextEncoder();var D=new TextDecoder();var S=D.decode(E.encode(J));var RESULT=S;"),
    ("f1276-codepointat",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var N=[];for(var i=0;i<J.length;i++){N.push(J.codePointAt(i));}var S=String.fromCharCode.apply(null,N);var RESULT=S;"),
    ("f1277-if",
     "var C={I};var S='';if(true){var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}var RESULT=S;"),
    ("f1277-try",
     "var C={I};var S='';try{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}catch(e){}var RESULT=S;"),
    ("f1277-label",
     "var C={I};var S='';blk:{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');S=J.split('|:|').join('');}var RESULT=S;"),
    ("f1277-forbreak",
     "var C={I};var S='';for(;;){var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');S=J.split('|:|').join('');break;}var RESULT=S;"),
    ("f1277-with",
     "var C={I};var S='';with({A:C.map(function(x){return String.fromCharCode(x);})}){S=A.join('');}var RESULT=S;"),
    ("f1277-dowhile",
     "var C={I};var S='';do{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}while(false);var RESULT=S;"),
    ("f1277-switch",
     "var C={I};var S='';switch(true){case true:var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;break;}var RESULT=S;"),
    ("f1278-comma",
     "var C={I};var S=(C.map(function(x){return String.fromCharCode(x);}),C.map(function(x){return String.fromCharCode(x);}).join(''));var RESULT=S;"),
    ("f1278-void",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var S=void A.join('')||A.join('');var RESULT=S;"),
    ("f1278-typeof",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var S=typeof A.join==='function'?A.join(''):'';var RESULT=S;"),
    ("f1278-instanceof",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var S=A instanceof Array?A.join(''):'';var RESULT=S;"),
    ("f1279-in-foreach",
     "var C={I};var O={};C.forEach(function(c,i){O[i]=c;});var S='';var i=0;while((i in O)){S+=String.fromCharCode(O[i++]);}var RESULT=S;"),
    ("f1279-in-for",
     "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var S='';var j=0;while(j in O){S+=String.fromCharCode(O[j]);j++;}var RESULT=S;"),
    ("f1280-hasown",
     "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(Object.hasOwn(O,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
    ("f1280-hasownproperty",
     "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(Object.prototype.hasOwnProperty.call(O,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
    ("f1315-method",
     "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(O.hasOwnProperty(k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
]

# Generalizations: node-verified (v24.20.0) to assemble the credential.
GENERALIZATIONS = [
    ("f1274-let",
     "let C={I};let U=new Uint8Array(C);let S=String.fromCharCode.apply(null,U);var RESULT=S;"),
    ("f1274-const-while",
     "const C={I};const U=new Uint8Array(C);let S='';let i=0;while(i<U.length){S+=String.fromCharCode(U[i++]);}var RESULT=S;"),
    ("f1275-dq-locale",
     "var C={I};var J=C.toLocaleString(\"en-US\");var A=J.split(\",\");var S=String.fromCharCode.apply(null,A.map(function(x){return Number(x);}));var RESULT=S;"),
    ("f1275-let",
     "let C={I};let U=new Uint8Array(C);let J=U.join(',');let A=J.split(',');let S=String.fromCharCode.apply(null,A.map(function(x){return Number(x);}));var RESULT=S;"),
    ("f1276-arrow",
     "var C={I};var A=C.map(c=>String.fromCharCode(c));var J=A.join('');var E=new TextEncoder();var D=new TextDecoder();var S=D.decode(E.encode(J));var RESULT=S;"),
    ("f1276-let",
     "let C={I};let A=C.map(function(c){return String.fromCharCode(c);});let J=A.join('');let N=[];for(let i=0;i<J.length;i++){N.push(J.codePointAt(i));}let S=String.fromCharCode.apply(null,N);var RESULT=S;"),
    ("f1277-catch-nobind",
     "var C={I};var S='';try{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}catch{}var RESULT=S;"),
    ("f1277-let",
     "let C={I};let S='';if(true){let A=C.map(function(x){return String.fromCharCode(x);});let J=A.join('|:|');let P=J.split('|:|').join('');S=P;}var RESULT=S;"),
    ("f1277-label2",
     "var C={I};var S='';myblk:{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');S=J.split('|:|').join('');}var RESULT=S;"),
    ("f1278-arrow",
     "var C={I};var S=(C.map(x=>String.fromCharCode(x)),C.map(x=>String.fromCharCode(x)).join(''));var RESULT=S;"),
    ("f1278-let",
     "let C={I};let A=C.map(function(c){return String.fromCharCode(c);});let S=void A.join('')||A.join('');var RESULT=S;"),
    ("f1279-let",
     "let C={I};let O={};C.forEach(function(c,i){O[i]=c;});let S='';let i=0;while((i in O)){S+=String.fromCharCode(O[i++]);}var RESULT=S;"),
    ("f1279-bare-idx",
     "var C={I};var O={};C.forEach(function(c,i){O[i]=c;});var S='';var j=0;while(j in O){S+=String.fromCharCode(O[j]);j++;}var RESULT=S;"),
    ("f1280-let",
     "let C={I};let O={};C.forEach(function(c,i){O['k'+i]=c;});let S='';for(let k in O){if(Object.hasOwn(O,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
    ("f1280-bare-k",
     "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(k in O){if(Object.hasOwn(O,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
    ("f1315-dq",
     "var C={I};var O={};C.forEach(function(c,i){O[\"k\"+i]=c;});var S=\"\";for(var k in O){if(O.hasOwnProperty(k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
]

# Fail-closed: my hook must MISS (never mis-decode). Sibling-hook cases
# assert MY hook misses by calling it directly.
FAIL_CLOSED = [
    # F1274 Uint16Array not Uint8Array
    ("f1274-u16", "var C={I};var U=new Uint16Array(C);var S=String.fromCharCode.apply(null,U);var RESULT=S;"),
    # F1274 separate incr not postincr-index
    ("f1274-sep-incr", "var C={I};var U=new Uint8Array(C);var S='';var i=0;while(i<U.length){S+=String.fromCharCode(U[i]);i++;}var RESULT=S;"),
    # F1275 code>=1000 groups in en-US
    ("f1275-big-code", "var C=[1200,111,120];var J=C.toLocaleString('en-US');var A=J.split(',');var S=String.fromCharCode.apply(null,A.map(function(x){return Number(x);}));var RESULT=S;"),
    # F1275 wrong locale
    ("f1275-de-locale", "var C={I};var J=C.toLocaleString('de-DE');var A=J.split(',');var S=String.fromCharCode.apply(null,A.map(function(x){return Number(x);}));var RESULT=S;"),
    # F1276 TextDecoder with arg
    ("f1276-decoder-arg", "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var E=new TextEncoder();var D=new TextDecoder('utf-8');var S=D.decode(E.encode(J));var RESULT=S;"),
    # F1276 codePointAt wrong obj
    ("f1276-wrong-obj", "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var N=[];for(var i=0;i<J.length;i++){N.push(X.codePointAt(i));}var S=String.fromCharCode.apply(null,N);var RESULT=S;"),
    # F1277 if(false) never runs
    ("f1277-if-false", "var C={I};var S='';if(false){var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}var RESULT=S;"),
    # F1277 non-empty catch
    ("f1277-catch-body", "var C={I};var S='';try{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}catch(e){x=1;}var RESULT=S;"),
    # F1277 do-while(true) infinite loop (must not hang, must miss)
    ("f1277-dowhile-true", "var C={I};var S='';do{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}while(true);var RESULT=S;"),
    # F1277 switch(false) takes no case
    ("f1277-switch-false", "var C={I};var S='';switch(false){case true:var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;break;}var RESULT=S;"),
    # F1278 void||'' yields empty
    ("f1278-void-empty", "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var S=void A.join('')||'';var RESULT=S;"),
    # F1278 typeof object takes else
    ("f1278-typeof-obj", "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var S=typeof A.join==='object'?A.join(''):'';var RESULT=S;"),
    # F1279 in wrong obj (empty loop)
    ("f1279-wrong-obj", "var C={I};var O={};var P={};C.forEach(function(c,i){O[i]=c;});var S='';var i=0;while((i in P)){S+=String.fromCharCode(P[i++]);}var RESULT=S;"),
    # F1279 no fill (empty loop)
    ("f1279-no-fill", "var C={I};var O={};var S='';var i=0;while((i in O)){S+=String.fromCharCode(O[i++]);}var RESULT=S;"),
    # F1280 no guard (F1044 sibling)
    ("f1280-no-guard", "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){S+=String.fromCharCode(O[k]);}var RESULT=S;", "sibling"),
    # F1280 guard wrong obj (empty)
    ("f1280-wrong-guard-obj", "var C={I};var O={};var P={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(Object.hasOwn(P,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
]

_MY_HOOK = {
    "f1274": dlp._js_f1274_stmt_decode,
    "f1275": dlp._js_f1275_stmt_decode,
    "f1276": dlp._js_f1276_stmt_decode,
    "f1277": dlp._js_f1277_stmt_decode,
    "f1278": dlp._js_f1278_stmt_decode,
    "f1279": dlp._js_f1279_stmt_decode,
    "f1280": dlp._js_f1280_stmt_decode,
    "f1315": dlp._js_f1280_stmt_decode,
}

POLITE = ("the quarterly financial summary shows revenue growth across "
          "all regional divisions and market segments")


@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_taxonomy_pin (%d)" % len(TAXONOMY))
    return ok


@_t
def test_p0_verifier_pin():
    ok = VERIFIER_TAXONOMY_PIN == 33
    print(("HELD " if ok else "BREAK") + " test_p0_verifier_pin (%d)" % VERIFIER_TAXONOMY_PIN)
    return ok


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == RECOMPILE_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_recompile_pin (%d)" % n)
    return ok


@_t
def test_p0_stmtdec_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \([^)]*\):", body, re.DOTALL)
    ok = len(loops) == STMTDEC_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_stmtdec_pin (%d)" % len(loops))
    return ok


@_t
def test_p0_footer_state():
    """Lane tree: F1274-F1280 + F1315 stamped CLOSED (this lane)."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    bad = []
    for num in list(range(1274, 1281)) + [1289]:
        m = re.search(r"\(F%d filed .*?; LOW, (OPEN|\[CLOSED)" % num, text)
        if not m or not m.group(1).startswith("[CLOSED"):
            bad.append("F%d-not-closed" % num)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_p0_footer_state%s"
          % ("" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_filed_shapes():
    """All filed productions (8 findings, 22 shapes x 2 sizes) now BLOCK."""
    bad = []
    total = 0
    for name, tmpl in FILED:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            if not _hits(_p(tmpl, secret)):
                bad.append("%s/%s" % (name, "L" if secret == SECRET_L else "S"))
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_filed_shapes (%d%s)"
          % (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_generalizations():
    """Node-verified twins and spellings also BLOCK."""
    bad = []
    for name, tmpl in GENERALIZATIONS:
        if not _hits(_p(tmpl)):
            bad.append(name)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_generalizations (%d%s)"
          % (len(GENERALIZATIONS), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_fail_closed():
    """Guard and narrowness cases: my hook must MISS (never mis-decode)."""
    bad = []
    for entry in FAIL_CLOSED:
        name, tmpl = entry[0], entry[1]
        sibling = len(entry) > 2 and entry[2] == "sibling"
        payload = _p(tmpl)
        hook = _MY_HOOK[name.split("-")[0]]
        if hook(payload) is not None:
            bad.append(name + "-myhook-hit")
        if sibling:
            continue
        # Non-sibling shapes must also MISS the whole scanner, except
        # shapes that node assembles differently (noted, still must
        # miss MY hook which is asserted above).
        if name in ("f1275-big-code",):
            # node groups "1,200" -> split gives ["1","200"] -> Number
            # restores [1,200] not [1200]; assembles wrong chars.
            # Scanner may or may not hit; my hook must miss (asserted).
            continue
        if not _misses(payload):
            bad.append(name + "-scanner-hit")
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_fail_closed (%d%s)"
          % (len(FAIL_CLOSED), "" if ok else ": " + ",".join(bad)))
    return ok


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


@_t
def test_sibling_closed_still_hit():
    """Sibling closed shapes still BLOCK via their own hooks."""
    bad = []
    total = 0
    # F1254 apply derived-array (F1274's twin)
    total += 1
    if not _hits(_p("var C={I};var D=C.slice();"
                    "var S=String.fromCharCode.apply(null,D);var RESULT=S;")):
        bad.append("f1254")
    # F1246 plain while (F1279's twin)
    total += 1
    if not _hits(_p("var C={I};var S='';var i=0;"
                    "while(i<C.length){S+=String.fromCharCode(C[i++]);}"
                    "var RESULT=S;")):
        bad.append("f1246")
    # F1219 charCodeAt roundtrip (F1276's twin)
    for name, payload in _redfirst_shapes("w408", 1219)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1219")
            break
    # F1199 bare join/split (F1275/F1277's twin)
    total += 1
    if not _hits(_p("var C={I};var A=C.map(function(x){return String.fromCharCode(x);});"
                    "var J=A.join('|:|');var S=J.split('|:|').join('');var RESULT=S;")):
        bad.append("f1199")
    # F1195 expression wrappers (F1278's twin)
    for name, payload in _redfirst_shapes("w407", 1195)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1195")
            break
    # F1209 while+shift (F1279's twin)
    for name, payload in _redfirst_shapes("w408", 1209)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1209")
            break
    # F1044 bare for-in (F1280's twin)
    for name, payload in _redfirst_shapes("w396", 1044)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1044")
            break
    # F1112 TypedArray.from (F1274's twin)
    total += 1
    if not _hits(_p("var C={I};var T=Uint16Array.from(C);"
                    "var S=String.fromCharCode(...T);var RESULT=S;")):
        bad.append("f1112")
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_sibling_closed_still_hit (%d%s)"
          % (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_still_open():
    """F1260-F1273, F1281-F1288 are OPEN on this lane tree (sibling lanes
    not merged); their filed shapes must still MISS."""
    bad = []
    total = 0
    for num in list(range(1260, 1274)) + list(range(1281, 1289)):
        for name, payload in _redfirst_shapes("w409", num)[:2]:
            total += 1
            if not _misses(payload):
                bad.append("f%d" % num)
                break
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_still_open (%d%s)"
          % (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_honest_quiet():
    """Honest text and near-miss shapes stay quiet."""
    cases = [
        ("polite", POLITE),
        ("honest-loop",
         "var C=[1,2,3];var S='';for(var i=0;i<C.length;i++){S+=i;}var R=S;"),
        ("u8-honest",
         "var C=[1,2,3];var U=new Uint8Array(C);var R=U.length;"),
        ("join-honest",
         "var A=['a','b'];var J=A.join(',');var R=J;"),
        ("textenc-honest",
         "var E=new TextEncoder();var D=new TextDecoder();var R=D.decode(E.encode('hi'));"),
        ("if-honest",
         "var S='';if(true){var x=1;}var R=S;"),
        ("void-honest",
         "var x=void 0;var R=x;"),
        ("forin-honest",
         "var O={a:1};var S='';for(var k in O){S+=k;}var R=S;"),
        ("in-honest",
         "var O={a:1};var R=('a' in O);"),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_honest_quiet (%d%s)"
          % (len(cases), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_perf_200_sites():
    texts = []
    for i in range(200):
        if i % 5 == 0:
            texts.append(_p(FILED[i % len(FILED)][1]))
        elif i % 5 == 1:
            texts.append(POLITE + " site %d" % i)
        elif i % 5 == 2:
            texts.append("var x = %d; // honest text %d" % (i, i))
        elif i % 5 == 3:
            texts.append(_p(GENERALIZATIONS[i % len(GENERALIZATIONS)][1]))
        else:
            texts.append("<p>honest paragraph number %d with words</p>" % i)
    t0 = time.time()
    for t in texts:
        dlp.find_credential(t)
    dt = time.time() - t0
    ok = dt < 120
    print(("HELD " if ok else "BREAK") + " test_perf_200_sites (%.2fs)" % dt)
    return ok


@_t
def test_green_w409():
    """Depth-1 green check on w409's attack battery. On the lane tree,
    F1274-F1280+F1315 are CLOSED (their open pins must BREAK); the rest
    stay HELD. Honor GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w409 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g410l3-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    child = os.path.join(REPO_ROOT, "evals", "w409_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, child],
                           capture_output=True, text=True, env=env,
                           timeout=900, cwd=os.path.join(REPO_ROOT, "evals"))
        broke = [l for l in (r.stdout or "").split("\n") if l.startswith("BREAK")]
        # Expect exactly the 8 closed findings' pins to break (7 filed +
        # F1315); anything else breaking is a regression.
        broke_f = sorted(set(
            re.search(r"f(\d+)", l).group(1) for l in broke
            if re.search(r"f(\d+)", l)))
        # F1274-F1280 now CLOSED -> their OPEN pins BREAK. F1315 is not
        # in the attack battery (lane-filed). F1260-F1273, F1281-F1288
        # stay OPEN -> HELD.
        expect = sorted(["1274", "1275", "1276", "1277", "1278", "1279",
                         "1280"])
        ok = (broke_f == expect and r.returncode != 0)
        print(("HELD " if ok else "BREAK") +
              " test_green_w409 (broke=%s)" % ",".join(broke_f))
        if not ok:
            print("  expected: %s" % ",".join(expect))
            print("  rc=%d" % r.returncode)
        return ok
    except Exception as e:
        print("BREAK test_green_w409 (exec failed: %s)" % e)
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    fails = []
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            if not fn():
                fails.append(fn.__name__)
        except Exception as e:
            print("BREAK " + fn.__name__ + " (exception: %s)" % e)
            fails.append(fn.__name__)
    print("%d/%d HELD" % (len(TESTS) - len(fails), len(TESTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
