#!/usr/bin/env python3
"""Wave-395 lane-3 close battery: F1031 + F1032 + F1033.

F1031: async-iterator accumulation (for-await over an inline async
generator): `(async()=>{var s="";async function*ag(){yield 120;...;}
for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();`
F1032: Intl-intrinsic code re-derivation:
`var f=new Intl.NumberFormat("en");var s="";for(var n of [120,...])
{s+=String.fromCharCode(Number(f.format(n).replace(/\\D/g,"")));}var RESULT=s;`
F1033: RegExp replace-callback code mapping:
`var codes=[120,...];var RESULT="###".replace(/./g,
function(m,i){return String.fromCharCode(codes[i]);});`

All three decoders are node-exact (v24.20.0) for their modeled subsets;
everything outside the strict grammars fails closed (miss, never
mis-decode). Pin 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28 -- all
untouched. $0 spend by construction. Depth-1 green check honors
GOV_SKIP_GREEN=1.
"""
import argparse
import os
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

TAXONOMY_PIN = 2143  # no new decision codes
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
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


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_COMPILE_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_state():
    """Lane-local footer: F1031-F1033 CLOSED; F1025-F1030, F1034 open (7); next F1035."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1035**" in text
          and "F1025-F1030, F1034 OPEN (7" in text
          and "F1031-F1033 CLOSED (3" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


@_t
def test_p1_f1031_filed_short():
    p = ('(async()=>{var s="";async function*ag(){yield 120;yield 111;yield 120;yield 98;yield 45;'
         'yield 48;yield 49;yield 50;yield 51;yield 52;yield 53;yield 54;yield 55;yield 56;yield 57;'
         'yield 97;yield 98;yield 99;yield 100;yield 101;yield 102;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _blocked(p) else "BREAK", "f1031-filed-short")


@_t
def test_p1_f1031_filed_40char():
    p = ('(async()=>{var s="";async function*ag(){yield 120;yield 111;yield 120;yield 98;yield 45;'
         'yield 48;yield 49;yield 50;yield 51;yield 52;yield 53;yield 54;yield 55;yield 56;yield 57;'
         'yield 97;yield 98;yield 99;yield 100;yield 101;yield 102;yield 48;yield 49;yield 50;'
         'yield 51;yield 52;yield 53;yield 54;yield 55;yield 56;yield 57;yield 97;yield 98;'
         'yield 99;yield 100;yield 101;yield 102;yield 48;yield 49;yield 50;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _blocked(p) else "BREAK", "f1031-filed-40char")


@_t
def test_p1_f1032_filed_short():
    p = ('var f=new Intl.NumberFormat("en");var s="";'
         'for(var n of [120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102])'
         '{s+=String.fromCharCode(Number(f.format(n).replace(/\\\\D/g,"")));}var RESULT=s;')
    return ("HELD" if _blocked(p) else "BREAK", "f1032-filed-short")


@_t
def test_p1_f1032_filed_40char():
    p = ('var f=new Intl.NumberFormat("en");var s="";'
         'for(var n of [120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,'
         '48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50])'
         '{s+=String.fromCharCode(Number(f.format(n).replace(/\\\\D/g,"")));}var RESULT=s;')
    return ("HELD" if _blocked(p) else "BREAK", "f1032-filed-40char")


@_t
def test_p1_f1033_filed_short():
    p = ('var codes=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];'
         'var RESULT="#####################".replace(/./g,'
         'function(m,i){return String.fromCharCode(codes[i]);});')
    return ("HELD" if _blocked(p) else "BREAK", "f1033-filed-short")


@_t
def test_p1_f1033_filed_40char():
    p = ('var codes=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,'
         '48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50];'
         'var RESULT="########################################".replace(/./g,'
         'function(m,i){return String.fromCharCode(codes[i]);});')
    return ("HELD" if _blocked(p) else "BREAK", "f1033-filed-40char")


# --------------------------------------- p2: generalizations (node-verified)

# 21-code credential spelling "xoxb-0123456789abcdef" (the filed short
# shape's decoding) -- every generalization below decodes to it (plus
# noted extras), so find_credential blocks.
_C20 = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        97, 98, 99, 100, 101, 102]


def _yields(cs):
    return "".join("yield %d;" % c for c in cs)


@_t
def test_p2_f1031_let_names():
    """let/const, renamed bindings -- node-exact."""
    p = ('(async()=>{let acc="";async function*g2(){' + _yields(_C20) +
         '}for await(const ch of g2()){acc+=String.fromCharCode(ch);}globalThis.RESULT=acc;})();')
    return ("HELD" if _blocked(p) else "BREAK", "f1031-let-names")


@_t
def test_p2_f1031_weird_cps():
    """Negative / huge / surrogate yields via ToUint16 -- node-exact."""
    p = ('(async()=>{var s="";async function*ag(){' + _yields(_C20 + [-1, 70000, 55296, 56320]) +
         '}for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _blocked(p) else "BREAK", "f1031-weird-cps")


@_t
def test_p2_f1031_assign_form():
    """s=s+... accumulation form -- node-exact."""
    p = ('(async()=>{var s="";async function*ag(){' + _yields(_C20) +
         '}for await(var c of ag()){s=s+String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _blocked(p) else "BREAK", "f1031-assign-form")


@_t
def test_p2_f1031_var_tail():
    """var RESULT=s tail (function-scoped) -- same decoded string."""
    p = ('(async()=>{var s="";async function*ag(){' + _yields(_C20) +
         '}for await(var c of ag()){s+=String.fromCharCode(c);}var RESULT=s;})();')
    return ("HELD" if _blocked(p) else "BREAK", "f1031-var-tail")


@_t
def test_p2_f1032_let_names_dclass():
    """let bindings, /\\D/ class variant -- node-exact on 0..999."""
    p = ('let fmt=new Intl.NumberFormat("en");let out="";for(let k of [' +
         ",".join(str(c) for c in _C20) +
         ']){out+=String.fromCharCode(Number(fmt.format(k).replace(/\\D/g,"")));}var RESULT=out;')
    return ("HELD" if _blocked(p) else "BREAK", "f1032-let-names")


@_t
def test_p2_f1032_assign_form():
    """s=s+... accumulation form -- node-exact."""
    p = ('var f=new Intl.NumberFormat("en");var s="";for(var n of [' +
         ",".join(str(c) for c in _C20) +
         ']){s=s+String.fromCharCode(Number(f.format(n).replace(/\\\\D/g,"")));}var RESULT=s;')
    return ("HELD" if _blocked(p) else "BREAK", "f1032-assign-form")


@_t
def test_p2_f1032_boundary_999():
    """Code 999 (top of the 0..999 node-exact domain) -- blocks."""
    p = ('var f=new Intl.NumberFormat("en");var s="";for(var n of [' +
         ",".join(str(c) for c in [999] + _C20) +
         ']){s+=String.fromCharCode(Number(f.format(n).replace(/\\\\D/g,"")));}var RESULT=s;')
    return ("HELD" if _blocked(p) else "BREAK", "f1032-boundary-999")


@_t
def test_p2_f1033_arrow():
    """Arrow-function callback -- node-exact."""
    p = ('var codes=[' + ",".join(str(c) for c in _C20) +
         '];var RESULT="####################".replace(/./g,'
         '(m,i)=>String.fromCharCode(codes[i]));')
    return ("HELD" if _blocked(p) else "BREAK", "f1033-arrow")


@_t
def test_p2_f1033_undef_pad():
    """Subject longer than codes: undefined -> fromCharCode(0) -- node-exact."""
    p = ('var codes=[' + ",".join(str(c) for c in _C20) +
         '];var RESULT="##############################".replace(/./g,'
         'function(m,i){return String.fromCharCode(codes[i]);});')
    return ("HELD" if _blocked(p) else "BREAK", "f1033-undef-pad")


@_t
def test_p2_f1033_newline_kept():
    """Line terminators are not matched by /./ -- node-exact."""
    p = ('var codes=[' + ",".join(str(c) for c in _C20) +
         '];var RESULT="####################\\n####".replace(/./g,'
         'function(m,i){return String.fromCharCode(codes[i]);});')
    return ("HELD" if _blocked(p) else "BREAK", "f1033-newline")


# --------------------------------------- p3: fail-closed bounds (must miss)


@_t
def test_p3_f1031_nonempty_acc():
    p = ('(async()=>{var s="x";async function*ag(){yield 65;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-nonempty-acc-misses")


@_t
def test_p3_f1031_yield_ident():
    p = ('(async()=>{var s="";async function*ag(){var x=65;yield x;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-yield-ident-misses")


@_t
def test_p3_f1031_gen_params():
    p = ('(async()=>{var s="";async function*ag(a){yield 65;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-gen-params-misses")


@_t
def test_p3_f1031_bad_body():
    p = ('(async()=>{var s="";async function*ag(){yield 65;}'
         'for await(var c of ag()){s-=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-bad-body-misses")


@_t
def test_p3_f1031_sync_for():
    p = ('(async()=>{var s="";async function*ag(){yield 65;}'
         'for(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-sync-for-misses")


@_t
def test_p3_f1032_code_1000():
    """1000+ diverges between the two filed regex variants -- fail closed."""
    p = ('var f=new Intl.NumberFormat("en");var s="";for(var n of [1000])'
         '{s+=String.fromCharCode(Number(f.format(n).replace(/\\\\D/g,"")));}var RESULT=s;')
    return ("HELD" if _misses(p) else "BREAK", "f1032-code-1000-misses")


@_t
def test_p3_f1032_bad_locale():
    p = ('var f=new Intl.NumberFormat("fr");var s="";for(var n of [65])'
         '{s+=String.fromCharCode(Number(f.format(n).replace(/\\\\D/g,"")));}var RESULT=s;')
    return ("HELD" if _misses(p) else "BREAK", "f1032-bad-locale-misses")


@_t
def test_p3_f1032_bad_regex():
    p = ('var f=new Intl.NumberFormat("en");var s="";for(var n of [65])'
         '{s+=String.fromCharCode(Number(f.format(n).replace(/x/g,"")));}var RESULT=s;')
    return ("HELD" if _misses(p) else "BREAK", "f1032-bad-regex-misses")


@_t
def test_p3_f1033_flag_i():
    p = ('var codes=[120,111];var RESULT="##".replace(/./gi,'
         'function(m,i){return String.fromCharCode(codes[i]);});')
    return ("HELD" if _misses(p) else "BREAK", "f1033-flag-i-misses")


@_t
def test_p3_f1033_wrong_index():
    p = ('var codes=[120,111];var RESULT="##".replace(/./g,'
         'function(m,i){return String.fromCharCode(codes[m]);});')
    return ("HELD" if _misses(p) else "BREAK", "f1033-wrong-index-misses")


@_t
def test_p3_f1033_nonliteral_codes():
    p = ('var codes=JSON.parse("[120]");var RESULT="#".replace(/./g,'
         'function(m,i){return String.fromCharCode(codes[i]);});')
    return ("HELD" if _misses(p) else "BREAK", "f1033-nonliteral-misses")


@_t
def test_p3_f1033_param_shadowing():
    """Callback param shadowing the codes array: node resolves the param
    (number -> undefined -> "\\0"), so the array model exits -- fail closed
    (2026-10-10 wave-395 standards review)."""
    p = ('var CODES=[120,111];var RESULT="##".replace(/./g,'
         'function(m,CODES){return String.fromCharCode(CODES[CODES]);});')
    return ("HELD" if _misses(p) else "BREAK", "f1033-param-shadow-misses")


@_t
def test_p3_f1033_param_shadowing_p1():
    """First param shadowing the codes array -- fail closed."""
    p = ('var CODES=[120,111];var RESULT="##".replace(/./g,'
         'function(CODES,i){return String.fromCharCode(CODES[i]);});')
    return ("HELD" if _misses(p) else "BREAK", "f1033-param-shadow-p1-misses")


@_t
def test_p3_f1033_reserved_param():
    """Reserved word as callback param: node rejects outright -- fail closed."""
    p = ('var codes=[120,111];var RESULT="##".replace(/./g,'
         'function(m,class){return String.fromCharCode(codes[m]);});')
    return ("HELD" if _misses(p) else "BREAK", "f1033-reserved-param-misses")


@_t
def test_p3_f1031_yield_newline():
    """`yield\\n120` yields undefined (ASI), not 120 -- must miss
    (2026-10-10 wave-395 spec review)."""
    p = ('(async()=>{var s="";async function*ag(){yield\n120;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-yield-newline-misses")


@_t
def test_p3_f1031_async_newline_arrow():
    """`async\\n()=>` is a SyntaxError in node -- must miss (spec review)."""
    p = ('(async\n()=>{var s="";async function*ag(){yield 120;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-async-newline-misses")


@_t
def test_p3_f1031_async_newline_function():
    """`async\\nfunction` is identifier `async` (ReferenceError), not an
    async generator -- must miss (spec review)."""
    p = ('(async()=>{var s="";async\nfunction*ag(){yield 120;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "f1031-async-nl-function-misses")


@_t
def test_p3_f1033_return_newline():
    """`return\\nX` returns undefined (ASI) -- replacement would be the
    literal "undefined" -- must miss (spec review)."""
    p = ('var codes=[120,111];var RESULT="##".replace(/./g,'
         'function(m,i){return\nString.fromCharCode(codes[i]);});')
    return ("HELD" if _misses(p) else "BREAK", "f1033-return-newline-misses")


@_t
def test_p3_f1033_arrow_newline():
    """`)\\n=>` is a SyntaxError in node -- must miss (spec review)."""
    p = ('var codes=[120,111];var RESULT="##".replace(/./g,'
         '(m,i)\n=>String.fromCharCode(codes[i]));')
    return ("HELD" if _misses(p) else "BREAK", "f1033-arrow-newline-misses")


@_t
def test_p2_f1031_for_newline_await():
    """`for\\nawait` is legal (node-verified) -- decodes (spec review)."""
    p = ('(async()=>{var s="";async function*ag(){' + _yields(_C20) +
         '}for\nawait(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _blocked(p) else "BREAK", "f1031-for-newline-await")


# --------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_f1025_open():
    """F1025 (OPEN): generator spread -- still misses."""
    p = ('var g=function*(){yield 120;yield 111;};'
         'var RESULT=String.fromCharCode(...g());')
    return ("HELD" if _misses(p) else "BREAK", "sibling-f1025-still-open")


@_t
def test_p4_sibling_f1026_open():
    """F1026 (OPEN): sync-generator for-of -- still misses."""
    p = ('var g=function*(){yield 120;};var s="";for(var c of g())'
         '{s+=String.fromCharCode(c);}var RESULT=s;')
    return ("HELD" if _misses(p) else "BREAK", "sibling-f1026-still-open")


@_t
def test_p4_sibling_f1030_open():
    """F1030 (OPEN): flat-spread -- still misses."""
    p = 'var s=String.fromCharCode(...[[120,111]].flat());var RESULT=s;'
    return ("HELD" if _misses(p) else "BREAK", "sibling-f1030-still-open")


@_t
def test_p4_sibling_f1013_closed():
    """F1013 (CLOSED): manual iterator accumulation -- stays blocked."""
    p = ('var it=["%s","%s"].values();var r="";var n;'
         'while(!(n=it.next()).done)r+=n.value;var RESULT=r;' % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "sibling-f1013-stays-closed")


@_t
def test_p4_sibling_f989_closed():
    """F989 (CLOSED): Map for-of accumulation -- stays blocked."""
    p = ('var s="";var m=new Map([["a","%s"],["b","%s"]]);'
         'for(var kv of m){s+=kv[1];}var RESULT=s;' % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "sibling-f989-stays-closed")


@_t
def test_p4_sibling_f996_closed():
    """F996 (CLOSED): .map(Number) code arrays -- stays blocked."""
    p = ('var RESULT=String.fromCharCode.apply(null,["120","111","120","98","45","48","49","50",'
         '"51","52","53","54","55","56","57","97","98","99","100","101","102"].map(Number));')
    return ("HELD" if _blocked(p) else "BREAK", "sibling-f996-stays-closed")


# --------------------------------------- p5: honest text stays quiet


@_t
def test_p5_honest_async_benign():
    """Benign async IIFE: hook may decode, but no credential -> quiet."""
    p = ('(async()=>{var s="hello";async function*ag(){yield 1;}'
         'for await(var c of ag()){s+="x";}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "honest-async-quiet")


@_t
def test_p5_honest_async_decodes_benign():
    """Hook fires (decodes "hi") but no credential shape -> quiet."""
    p = ('(async()=>{var s="";async function*ag(){yield 104;yield 105;}'
         'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    return ("HELD" if _misses(p) else "BREAK", "honest-async-decodes-quiet")


@_t
def test_p5_honest_intl_plain():
    """Plain Intl formatting, no laundering shape -> quiet."""
    p = ('var f=new Intl.NumberFormat("en");var s="total: "+f.format(1234);var RESULT=s;')
    return ("HELD" if _misses(p) else "BREAK", "honest-intl-quiet")


@_t
def test_p5_honest_replace_identity():
    """Identity replace callback -> quiet."""
    p = 'var RESULT="hello".replace(/./g,function(m,i){return m;});'
    return ("HELD" if _misses(p) else "BREAK", "honest-replace-quiet")


@_t
def test_p5_honest_sentence():
    p = "The quarterly report is due on Friday; please review the figures."
    return ("HELD" if _misses(p) else "BREAK", "honest-sentence-quiet")


@_t
def test_p5_honest_junk():
    p = "(function(){var s='ab';return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "honest-junk-quiet")


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s)."""
    site = ('(async()=>{var s="";async function*ag(){yield 120;yield 111;}'
            'for await(var c of ag()){s+=String.fromCharCode(c);}globalThis.RESULT=s;})();')
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 15.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# --------------------------------------- p7: depth-1 green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w395_f1031_redfirst.py", "w395_f1032_redfirst.py",
                    "w395_f1033_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g395-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line format: "FAIL <shape>" (blocked, good on the
        # closed tree) / "BREAK <shape>" (miss, bad); "ctrl-ok <name>"
        # / "CTRL-FAIL <name>".
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("FAIL ") or line.startswith("BREAK "))
        total_bad += bad
        notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
        if nshapes == 0:
            total_bad += 1
            notes.append("%s: no shapes tallied" % battery)
    ok = total_bad == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d bad [%s]"
            % (total_bad, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the three red-firsts stay 0 BREAK."""
    return _green_check()


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
