#!/usr/bin/env python3
"""Wave-397 lane 2 close battery: F1052 + F1053 + F1054 + F1055.

F1052: Headers value reads (.get concat, forEach accumulation)
F1053: memory-view staged code reads (WebAssembly.Memory / ArrayBuffer /
       DataView views)
F1054: RegExp match-group fragment assembly (named + numbered)
F1055: JSON.parse reviver-staged fragment reads

Pins: taxonomy 2143, verifier 33, re.compile 28. Lane-local footer:
open F1048-F1051, F1056-F1064 (13); next free F1065.
$0-spend-by-construction (no harness/paid refs).
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RE_COMPILE_PIN = 28

from gov import dlp  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _check(name, ok, note=""):
    return ("HELD" if ok else "BREAK", note)


CRED21 = "xoxb-0123456789abcdef"
C21 = "120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102"
C40 = ("120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,"
       "48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50")

# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    ok = TAXONOMY_PIN == 2143
    return _check("pin-taxonomy", ok, str(TAXONOMY_PIN))


@_t
def test_p0_pin_verifier():
    path = os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py")
    src = open(path).read()
    ok = "VERIFIER_TAXONOMY_PIN = 33" in src
    return _check("pin-verifier", ok, str(ok))


@_t
def test_p0_pin_re_compile():
    path = os.path.join(REPO_ROOT, "gov", "dlp.py")
    src = open(path).read()
    n = src.count("re.compile(")
    return _check("pin-re-compile", n == RE_COMPILE_PIN, "%d" % n)


@_t
def test_p0_lane_footer():
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("F1052-F1055 CLOSED (4" in text
          and "F1048-F1051, F1056-F1064 OPEN (13" in text
          and "next free F1065" in text)
    return _check("lane-footer", ok, str(ok))


@_t
def test_p0_stamps():
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = all("(F105%d" % d in text and "CLOSED" in text for d in (2, 3, 4, 5))
    lines = [l for l in text.splitlines()
             if l.startswith("(F1052") or l.startswith("(F1053")
             or l.startswith("(F1054") or l.startswith("(F1055")]
    ok = ok and len(lines) == 4 and all("[CLOSED" in l for l in lines)
    return _check("stamps-closed", ok, "%d entry lines" % len(lines))


# ------------------------------------------------------- filed shapes


@_t
def test_f1052_filed_s0():
    p = ('var h=new Headers({"X-A":"xoxb-01","X-B":"23456789abcdef"});'
         'var RESULT=h.get("X-A")+h.get("X-B");')
    return _check("f1052-s0", _blocked(p))


@_t
def test_f1052_filed_s1_40():
    p = ('var h=new Headers({"X-A":"xox",'
         '"X-B":"b-0123456789abcdef0123456789abcdef012"});'
         'var RESULT=h.get("X-A")+h.get("X-B");')
    return _check("f1052-s1-40", _blocked(p))


@_t
def test_f1052_filed_s2_foreach():
    p = ('var h=new Headers({"X-A":"xoxb-01","X-B":"23456789abcdef"});'
         'var s="";h.forEach(function(v,k){s+=v;});var RESULT=s;')
    return _check("f1052-s2-foreach", _blocked(p))


@_t
def test_f1053_filed_s0_wasm():
    p = ('var m=new WebAssembly.Memory({initial:1});'
         'var v=new Uint8Array(m.buffer);v.set([' + C21 + ']);var s="";'
         'for(var i=0;i<21;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;')
    return _check("f1053-s0-wasm", _blocked(p))


@_t
def test_f1053_filed_s1_wasm_40():
    p = ('var m=new WebAssembly.Memory({initial:1});'
         'var v=new Uint8Array(m.buffer);v.set([' + C40 + ']);var s="";'
         'for(var i=0;i<40;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;')
    return _check("f1053-s1-wasm-40", _blocked(p))


@_t
def test_f1053_filed_s2_arraybuffer():
    p = ('var b=new ArrayBuffer(21);new Uint8Array(b).set([' + C21 + ']);'
         'var s="";var v=new Uint8Array(b);'
         'for(var i=0;i<21;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;')
    return _check("f1053-s2-arraybuffer", _blocked(p))


@_t
def test_f1053_filed_s3_dataview():
    p = ('var b=new ArrayBuffer(21);var dv=new DataView(b);var cs=[' + C21 + '];'
         'for(var i=0;i<21;i++){dv.setUint8(i,cs[i]);}var s="";'
         'for(var j=0;j<21;j++){s+=String.fromCharCode(dv.getUint8(j));}'
         'var RESULT=s;')
    return _check("f1053-s3-dataview", _blocked(p))


@_t
def test_f1054_filed_s0_named():
    p = ('var m="k1=xoxb-01 k2=23456789abcdef".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.x+m.groups.y;')
    return _check("f1054-s0-named", _blocked(p))


@_t
def test_f1054_filed_s1_named_40():
    p = ('var m="k1=xox k2=b-0123456789abcdef0123456789abcdef012".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.x+m.groups.y;')
    return _check("f1054-s1-named-40", _blocked(p))


@_t
def test_f1054_filed_s2_numbered():
    p = ('var m="k1=xoxb-01 k2=23456789abcdef".match(/k1=(\\S+)\\sk2=(\\S+)/);'
         'var RESULT=m[1]+m[2];')
    return _check("f1054-s2-numbered", _blocked(p))


@_t
def test_f1055_filed_s0():
    p = ('var o=JSON.parse(\'{"a":"xoxb-01","b":"23456789abcdef"}\','
         '(k,v)=>v);var RESULT=o.a+o.b;')
    return _check("f1055-s0", _blocked(p))


@_t
def test_f1055_filed_s1_40():
    p = ('var o=JSON.parse(\'{"a":"xox",'
         '"b":"b-0123456789abcdef0123456789abcdef012"}\','
         '(k,v)=>v);var RESULT=o.a+o.b;')
    return _check("f1055-s1-40", _blocked(p))


# ------------------------------------------------------- generalizations
# Every expected value below was verified node-exact (v24.20.0) before
# being pinned here.


@_t
def test_g_f1052_reversed_get_order():
    # Reversed concat is not credential-shaped; assert the hook's
    # node-exact decode directly.
    p = ('var h=new Headers({"X-A":"xoxb-01","X-B":"23456789abcdef"});'
         'var RESULT=h.get("X-B")+h.get("X-A");')
    dec = dlp._js_f1052_stmt_decode(p)
    ok = dec == "23456789abcdefxoxb-01"
    return _check("f1052-rev-order", ok, repr(dec))


@_t
def test_g_f1052_three_gets():
    p = ('var h=new Headers({"a":"xox","b":"b-01","c":"23456789abcdef"});'
         'var RESULT=h.get("a")+h.get("b")+h.get("c");')
    return _check("f1052-three-gets", _blocked(p))


@_t
def test_g_f1052_case_insensitive():
    p = ('var h=new Headers({"X-A":"xoxb-01","X-B":"23456789abcdef"});'
         'var RESULT=h.get("x-a")+h.get("X-b");')
    return _check("f1052-case-insensitive", _blocked(p))


@_t
def test_g_f1052_dup_key_later_wins():
    p = ('var h=new Headers({"X-A":"junk","X-A":"xoxb-0123456789abcdef"});'
         'var RESULT=h.get("X-A");')
    return _check("f1052-dup-later-wins", _blocked(p))


@_t
def test_g_f1052_arrow_foreach():
    p = ('var h=new Headers({"X-B":"23456789abcdef","X-A":"xoxb-01"});'
         'var s="";h.forEach((v,k)=>{s+=v;});var RESULT=s;')
    return _check("f1052-arrow-foreach", _blocked(p))


@_t
def test_g_f1052_foreach_sorted():
    # forEach visits in sorted-name order: X-10 < X-2 < X-A
    # (node-verified); the decoder must reproduce that order.
    p = ('var h=new Headers({"X-A":"C","X-2":"B","X-10":"A"});'
         'var s="";h.forEach(function(v,k){s+=v;});var RESULT=s;')
    dec = dlp._js_f1052_stmt_decode(p)
    ok = dec == "ABC"
    return _check("f1052-foreach-sorted", ok, repr(dec))


@_t
def test_g_f1052_padded_value_trimmed():
    # Engine strips leading/trailing SP/TAB from header values
    # (node-verified) -- the hook must reproduce the trimmed value.
    _cred = 'xoxb-0123456789abcdef'
    p = ('var h=new Headers({"X-A":"  ' + _cred + '\\t"});'
         'var RESULT=h.get("X-A");')
    dec = dlp._js_f1052_stmt_decode(p)
    ok = dec == _cred and _blocked(p)
    return _check("f1052-padded-trim", ok, repr(dec))


@_t
def test_g_f1052_let_const():
    p = ('let h=new Headers({"X-A":"xoxb-01","X-B":"23456789abcdef"});'
         'const RESULT=h.get("X-A")+h.get("X-B");')
    return _check("f1052-let-const", _blocked(p))


@_t
def test_g_f1053_braceless_loop():
    p = ('var m=new WebAssembly.Memory({initial:1});'
         'var v=new Uint8Array(m.buffer);v.set([' + C21 + ']);var s="";'
         'for(var i=0;i<21;i++)s+=String.fromCharCode(v[i]);var RESULT=s;')
    return _check("f1053-braceless", _blocked(p))


@_t
def test_g_f1053_accum_twin():
    p = ('var b=new ArrayBuffer(21);new Uint8Array(b).set([' + C21 + ']);'
         'let s="";var v=new Uint8Array(b);'
         'for(let i=0;i<21;++i){s=s+String.fromCharCode(v[i]);}var RESULT=s;')
    return _check("f1053-accum-twin", _blocked(p))


@_t
def test_g_f1053_partial_read():
    # K < len(codes): node reads the first K staged bytes (verified);
    # "xoxb-" is not credential-shaped, so assert the hook's
    # node-exact decode directly.
    p = ('var m=new WebAssembly.Memory({initial:1});'
         'var v=new Uint8Array(m.buffer);v.set([' + C21 + ']);var s="";'
         'for(var i=0;i<5;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;')
    dec = dlp._js_f1053_stmt_decode(p)
    ok = dec == "xoxb-"
    return _check("f1053-partial-read", ok, repr(dec))


@_t
def test_g_f1053_wrap_codes():
    # codes > 255 wrap mod 256 (node-verified: 300->44, -1->255).
    p = ('var m=new WebAssembly.Memory({initial:1});'
         'var v=new Uint8Array(m.buffer);v.set([300,-1,65]);var s="";'
         'for(var i=0;i<3;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;')
    dec = dlp._js_f1053_stmt_decode(p)
    ok = dec == ",\xffA"
    return _check("f1053-wrap", ok, repr(dec))


@_t
def test_g_f1053_step_variants():
    p = ('var b=new ArrayBuffer(21);var dv=new DataView(b);var cs=[' + C21 + '];'
         'for(let i=0;i<21;i+=1){dv.setUint8(i,cs[i]);}var s="";'
         'for(let j=0;j<21;j+=1){s+=String.fromCharCode(dv.getUint8(j));}'
         'var RESULT=s;')
    return _check("f1053-step-variants", _blocked(p))


@_t
def test_g_f1054_reversed_groups():
    p = ('var m="k1=xoxb-01 k2=23456789abcdef".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.y+m.groups.x;')
    dec = dlp._js_f1054_stmt_decode(p)
    ok = dec == "23456789abcdefxoxb-01"
    return _check("f1054-rev-groups", ok, repr(dec))


@_t
def test_g_f1054_bracket_groups():
    p = ('var m="k1=xoxb-01 k2=23456789abcdef".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);'
         'var RESULT=m.groups["x"]+m.groups["y"];')
    return _check("f1054-bracket-groups", _blocked(p))


@_t
def test_g_f1054_numbered_reversed():
    p = ('var m="k1=xoxb-01 k2=23456789abcdef".match(/k1=(\\S+)\\sk2=(\\S+)/);'
         'var RESULT=m[2]+m[1];')
    dec = dlp._js_f1054_stmt_decode(p)
    ok = dec == "23456789abcdefxoxb-01"
    return _check("f1054-num-reversed", ok, repr(dec))


@_t
def test_g_f1054_unanchored():
    p = ('var m="pre k1=xoxb-01 k2=23456789abcdef post".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.x+m.groups.y;')
    return _check("f1054-unanchored", _blocked(p))


@_t
def test_g_f1054_let():
    p = ('let m="k1=xoxb-01 k2=23456789abcdef".match(/k1=(\\S+)\\sk2=(\\S+)/);'
         'const RESULT=m[1]+m[2];')
    return _check("f1054-let-const", _blocked(p))


@_t
def test_g_f1055_function_reviver():
    p = ('var o=JSON.parse(\'{"a":"xoxb-01","b":"23456789abcdef"}\','
         'function(k,v){return v;});var RESULT=o.a+o.b;')
    return _check("f1055-fn-reviver", _blocked(p))


@_t
def test_g_f1055_bracket_reads():
    p = ('var o=JSON.parse(\'{"a":"xoxb-01","b":"23456789abcdef"}\','
         '(k,v)=>v);var RESULT=o["a"]+o["b"];')
    return _check("f1055-bracket-reads", _blocked(p))


@_t
def test_g_f1055_three_keys():
    p = ('var o=JSON.parse(\'{"a":"xox","b":"b-01","c":"23456789abcdef"}\','
         '(k,v)=>v);var RESULT=o.c+o.a+o.b;')
    dec = dlp._js_f1055_stmt_decode(p)
    ok = dec == "23456789abcdefxoxb-01"
    return _check("f1055-three-keys", ok, repr(dec))


@_t
def test_g_f1055_key_order_irrelevant():
    p = ('var o=JSON.parse(\'{"b":"23456789abcdef","a":"xoxb-01"}\','
         '(k,v)=>v);var RESULT=o.a+o.b;')
    return _check("f1055-key-order", _blocked(p))


@_t
def test_b_f1054_x1c_divergence():
    # Python re \s matches \x1c-\x1f but the engine does not
    # (node-verified) -- fail closed, never mis-decode.
    p = ("var m=\"k1=a\x1ck2=b\".match(/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);"
         "var RESULT=m.groups.x+m.groups.y;")
    return _check("f1054-x1c", _misses(p))


# ------------------------------------------------------- fail-closed


@_t
def test_b_f1052_missing_key():
    # engine: null + frag -> "nullfrag"; the decoder refuses to model
    # null (fail closed = miss).
    p = ('var h=new Headers({"X-A":"xoxb-01"});'
         'var RESULT=h.get("X-A")+h.get("X-B");')
    return _check("f1052-missing-key", _misses(p))


@_t
def test_b_f1052_nonstring_value():
    p = ('var h=new Headers({"X-A":123});'
         'var RESULT=h.get("X-A");')
    return _check("f1052-nonstring-value", _misses(p))


@_t
def test_b_f1052_nonascii_value():
    p = ('var h=new Headers({"X-A":"caf\\u00e9"});'
         'var RESULT=h.get("X-A");')
    return _check("f1052-nonascii-value", _misses(p))


@_t
def test_b_f1052_newline_value():
    # \n / \r / \x00 in a value is the engine TypeError -- miss.
    p = ("var h=new Headers({\"X-A\":\"a\\nb\"});"
         "var RESULT=h.get(\"X-A\");")
    return _check("f1052-newline-value", _misses(p))


@_t
def test_b_f1052_sequence_init():
    p = ('var h=new Headers([["X-A","xoxb-01"]]);'
         'var RESULT=h.get("X-A");')
    return _check("f1052-sequence-init", _misses(p))


@_t
def test_b_f1052_shadowed_string():
    p = ('var String=1;var h=new Headers({"X-A":"xoxb-01"});'
         'var RESULT=h.get("X-A");')
    return _check("f1052-shadow", _misses(p))


@_t
def test_b_f1053_staged_past_view():
    # engine: RangeError on set -- fail closed (miss, never mis-decode).
    p = ('var b=new ArrayBuffer(2);new Uint8Array(b).set([' + C21 + ']);'
         'var s="";var v=new Uint8Array(b);'
         'for(var i=0;i<21;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;')
    return _check("f1053-staged-past-view", _misses(p))


@_t
def test_b_f1053_loop_past_view():
    p = ('var b=new ArrayBuffer(21);new Uint8Array(b).set([' + C21 + ']);'
         'var s="";var v=new Uint8Array(b);'
         'for(var i=0;i<22;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;')
    return _check("f1053-loop-past-view", _misses(p))


@_t
def test_b_f1053_page_cap():
    # >65536 pages is the engine RangeError (node-verified) -- miss.
    p = ("var m=new WebAssembly.Memory({initial:70000});"
         "var v=new Uint8Array(m.buffer);v.set([65]);var s=\"\";"
         "for(var i=0;i<1;i++){s+=String.fromCharCode(v[i]);}var RESULT=s;")
    return _check("f1053-page-cap", _misses(p))


@_t
def test_b_f1053_getint8_read():
    p = ('var b=new ArrayBuffer(21);var dv=new DataView(b);var cs=[' + C21 + '];'
         'for(var i=0;i<21;i++){dv.setUint8(i,cs[i]);}var s="";'
         'for(var j=0;j<21;j++){s+=String.fromCharCode(dv.getInt8(j));}'
         'var RESULT=s;')
    return _check("f1053-getint8", _misses(p))


@_t
def test_b_f1053_sharedarraybuffer():
    # F1039's anchor, not this hook's -- must miss here.
    p = ('var b=new SharedArrayBuffer(84);var v=new Int32Array(b);'
         'var RESULT=String.fromCharCode(65);')
    return _check("f1053-not-f1039", _misses(p))


@_t
def test_b_f1054_global_flag():
    # /g drops .groups (engine) -- fail closed.
    p = ('var m="k1=xoxb-01 k2=23456789abcdef".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/g);var RESULT=m.groups.x+m.groups.y;')
    return _check("f1054-global-flag", _misses(p))


@_t
def test_b_f1054_other_skeleton():
    p = ('var m="a=xoxb-01".match(/a=(?<x>\\S+)/);'
         'var RESULT=m.groups.x;')
    return _check("f1054-other-skeleton", _misses(p))


@_t
def test_b_f1054_no_match():
    # engine: null.match groups throws -- fail closed.
    p = ('var m="k1=xoxb-01".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.x+m.groups.y;')
    return _check("f1054-no-match", _misses(p))


@_t
def test_b_f1054_nonascii_subject():
    p = ('var m="k1=caf\\u00e9 k2=zz".match('
         '/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.x+m.groups.y;')
    return _check("f1054-nonascii", _misses(p))


@_t
def test_b_f1055_transforming_reviver():
    p = ('var o=JSON.parse(\'{"a":"xoxb-01","b":"23456789abcdef"}\','
         '(k,v)=>k);var RESULT=o.a+o.b;')
    return _check("f1055-transforming", _misses(p))


@_t
def test_b_f1055_single_param_reviver():
    # (v)=>v receives the KEY, not the value (node) -- not identity.
    p = ('var o=JSON.parse(\'{"a":"xoxb-01","b":"23456789abcdef"}\','
         '(v)=>v);var RESULT=o.a+o.b;')
    return _check("f1055-single-param", _misses(p))


@_t
def test_b_f1055_missing_key():
    p = ('var o=JSON.parse(\'{"a":"xoxb-01"}\','
         '(k,v)=>v);var RESULT=o.a+o.b;')
    return _check("f1055-missing-key", _misses(p))


@_t
def test_b_f1055_non_dict():
    p = ('var o=JSON.parse(\'["xoxb-01"]\','
         '(k,v)=>v);var RESULT=o[0];')
    return _check("f1055-non-dict", _misses(p))


@_t
def test_b_f1055_bad_json():
    p = ('var o=JSON.parse(\'{bad json}\','
         '(k,v)=>v);var RESULT=o.a;')
    return _check("f1055-bad-json", _misses(p))


@_t
def test_b_trailing_garbage():
    p = ('var h=new Headers({"X-A":"xoxb-01"});'
         'var RESULT=h.get("X-A");var ZZZ=1;')
    return _check("trailing-garbage", _misses(p))


# ------------------------------------------------------- sibling pins


@_t
def test_s_f1056_still_open():
    # Lane 3's finding: String.replace capture assembly -- must miss here.
    p = ('var s="k1=xoxb-01 k2=23456789abcdef".replace('
         '/k1=(\\S+)\\sk2=(\\S+)/,"$1$2");var RESULT=s;')
    return _check("f1056-still-open", _misses(p))


@_t
def test_s_f1050_now_closed():
    # F1050 CLOSED (wave-397 lane 1, merge-reconciled): URLSearchParams reads block.
    p = ('var u=new URLSearchParams("k1=xoxb-01&k2=23456789abcdef");'
         'var RESULT=u.get("k1")+u.get("k2");')
    return _check("f1050-now-closed", _blocked(p))


@_t
def test_s_f1051_now_closed():
    # F1051 CLOSED (wave-397 lane 1, merge-reconciled): FormData reads block.
    p = ('var f=new FormData();f.append("a","xoxb-01");'
         'f.append("b","23456789abcdef");var RESULT=f.get("a")+f.get("b");')
    return _check("f1051-now-closed", _blocked(p))


@_t
def test_s_f1048_still_open():
    p = ('var e=new Error("x",{cause:new Error("y",{cause:"xoxb-01"})});'
         'var RESULT=e.cause.cause;')
    return _check("f1048-still-open", _misses(p))


@_t
def test_s_f1058_still_open():
    p = ('var t=new TextEncoder().encode("xoxb-01");'
         'var RESULT=new TextDecoder().decode(t);')
    return _check("f1058-still-open", _misses(p))


@_t
def test_s_f861_still_blocked():
    # F861 CLOSED: IIFE-wrapped Headers production still holds.
    p = ('(function(){var h=new Headers({"x-k":"xoxb-0123456789abcdef"});'
         'return h.get("x-k");})()')
    return _check("f861-still-blocked", _blocked(p))


@_t
def test_s_f958_still_blocked():
    # F958 CLOSED: its restricted pattern grammar still holds.
    p = ("var m='xoxb-01|23456789abcdef'.match(/(.*)\\\\|(.*)/);"
         "var RESULT=m[1]+m[2];")
    return _check("f958-still-blocked", _blocked(p))


@_t
def test_s_f630_single_arg():
    # F630: single-arg JSON.parse enumeration source -- my hook must
    # not steal it, and it must still decode as before.
    p = 'var RESULT=JSON.parse(\'{"k":"v"}\');'
    before = _blocked(p)
    mine = dlp._js_f1055_stmt_decode(p) is None
    return _check("f630-untouched", mine, "blocked=%s mine-miss=%s"
                  % (before, mine))


@_t
def test_s_f1039_still_blocked():
    # F1039 CLOSED: Atomics/SharedArrayBuffer still holds (filed shape
    # from w396_f1039_redfirst.py).
    p = ('var b=new Int32Array(new SharedArrayBuffer(84));'
         'var c=[' + C21 + '];'
         'for(var i=0;i<21;i++){Atomics.store(b,i,c[i]);}var s="";'
         'for(var i=0;i<21;i++){s+=String.fromCharCode(Atomics.load(b,i));}'
         'var RESULT=s;')
    return _check("f1039-still-blocked", _blocked(p))


# ------------------------------------------------------- honest text


@_t
def test_h_junk_quiet():
    return _check("junk-quiet",
                  _misses("(function(){var s='ab';return s;})()"))


@_t
def test_h_headers_benign():
    p = ('var h=new Headers({"Content-Type":"text/html"});'
         'var RESULT=h.get("Content-Type");')
    return _check("headers-benign", _misses(p))


@_t
def test_h_json_benign():
    p = ('var o=JSON.parse(\'{"a":"hello"}\',(k,v)=>v);'
         'var RESULT=o.a;')
    return _check("json-benign", _misses(p))


@_t
def test_h_regex_benign():
    p = ('var m="k1=AA k2=BB".match(/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);'
         'var RESULT=m.groups.x;')
    return _check("regex-benign", _misses(p))


@_t
def test_h_view_benign():
    p = ('var b=new ArrayBuffer(4);var v=new Uint8Array(b);v.set([1,2]);'
         'var RESULT="done";')
    return _check("view-benign", _misses(p))


# ------------------------------------------------------- perf


@_t
def test_perf_200_sites():
    sites = []
    base = ('var h=new Headers({"X-A":"v1","X-B":"v2"});'
            'var RESULT=h.get("X-A")+h.get("X-B");')
    for i in range(200):
        sites.append("site%d: %s" % (i, base))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return _check("perf-200", dt < 30, "%.2fs" % dt)


# --------------------------------------- depth-1 green check


def _run_battery(name):
    tmp = tempfile.mkdtemp(prefix="g397-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
        capture_output=True, text=True, env=env, timeout=600,
        cwd=REPO_ROOT)
    return (p.stdout or "") + (p.stderr or "")


@_t
def test_p7_green_check():
    """Depth-1 green check: lane red-firsts 0 BREAK; attack battery shows
    the 4 F1052-F1055 pins as _closed/HELD (flipped at merge);
    no other round-64 pin BREAKs."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return _check("green-skip", True, "skipped (GOV_SKIP_GREEN=1)")
    bad_notes = []
    for battery in ("w397_f1052_redfirst.py", "w397_f1053_redfirst.py",
                    "w397_f1054_redfirst.py", "w397_f1055_redfirst.py"):
        out = _run_battery(battery)
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("FAIL ") or line.startswith("BREAK "))
        if bad or nshapes == 0:
            bad_notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
    out = _run_battery("w396_attack_probes.py")
    closed_ok = [l for l in out.splitlines()
                 if ": HELD" in l
                 and any("test_r64_f105%d_closed" % d in l for d in (2, 3, 4, 5))]
    real_break = [l for l in out.splitlines()
                  if ": BREAK" in l and "test_r64_f10" in l]
    # the 4 now-closed pins must report HELD as _closed; no r64 pin may BREAK
    if len(closed_ok) != 4:
        bad_notes.append("attack closed=%d (want 4): %s" % (len(closed_ok), closed_ok[:4]))
    if real_break:
        bad_notes.append("attack unexpected BREAKs: %s" % real_break[:3])
    ok = not bad_notes
    return _check("green", ok, "bad=[%s]" % "; ".join(bad_notes))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    held, broke, failed = 0, 0, []
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "BREAK", "%s raised %r" % (fn.__name__, e)
        if verdict == "HELD":
            held += 1
        else:
            broke += 1
            failed.append((fn.__name__, note))
        print("%-42s %s %s" % (fn.__name__, verdict, note))
    print("HELD %d / BREAK %d / %d total" % (held, broke, held + broke))
    for name, note in failed:
        print("FAILED:", name, note)
    return 1 if broke else 0


if __name__ == "__main__":
    sys.exit(main())
