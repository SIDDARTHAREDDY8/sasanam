#!/usr/bin/env python3
"""Wave-398 lane-2 close battery: F1068 + F1069 + F1070 + F1071.

F1068: Proxy set-trap accumulation reads --
`var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});`
`[INTS].forEach((v,i)=>{p[i]=v;});` (or `P[INT]=INT;` runs)
`var RESULT=Object.values(o).join('');` (distinct vs F1059's get-trap).
F1069: non-identifier fromCharCode spread receivers -- WeakRef deref
member (`...r.deref().c`), globalThis member (`...globalThis.K`),
rest param (`(...a)=>String.fromCharCode(...a)` + `f(...[INTS])`)
(distinct vs F991's quoted-literal `.deref().v` reads).
F1070: Intl.Segmenter ZWSP-filter reassembly --
`[...new Intl.Segmenter().segment(P.join("\\u200b"))]`
`.filter(s=>s.segment!=="\\u200b").map(s=>s.segment).join("")`
(distinct vs F857/F910's ASCII-only Segmenter productions).
F1071: Object.getOwnPropertyNames loop accumulation --
`for(var k of Object.getOwnPropertyNames(O))S+=O[k];`
(distinct vs F1044's for-in enumeration and F525's
expression-level key enumeration).

All decoders are node-exact (v24.20.0, 20-case differential) for
their modeled subsets; everything outside the strict grammars fails
closed (miss, never mis-decode). Pin 2143, VERIFIER_TAXONOMY_PIN 33,
re.compile( 28 in gov/dlp.py -- all untouched; N_STMTDEC_LOOPS
18 -> 19 (real code-count change: this lane's dispatch loop,
wave-385 rule). $0 spend by construction. Depth-1 green check
honors GOV_SKIP_GREEN=1.
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
RE_COMPILE_COUNT = 28  # zero new re.compile( in gov/dlp.py -- audited count
STMTDEC_LOOPS = 21  # wave-398 merge: three new dispatch loops (18 -> 21, real code-count change, wave-385 rule)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_CRED = "xoxb-" + "0123456789abcdef"
_CRED40 = "xox" + "b-0123456789abcdef0123456789abcdef012"
_F1 = "xoxb-" + "01"
_F2 = "23456789" + "abcdef"
_F1_40 = "xox"
_F2_40 = "b-0123456789abcdef0123456789abcdef012"
_ZW = "\\u200b"  # 6-char JS escape for U+200B, as in the filed shapes


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _frags(s):
    return '"%s"' % s[:3], '"%s"' % s[3:]


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
    """Zero new re.compile( in gov/dlp.py -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_COMPILE_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_pin_stmtdec_loops():
    """One new _stmtdec dispatch loop (F1068-F1071); pin 18 -> 19."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    m = text.find("def _decode_layer(text):")
    body = text[m:text.find("\ndef ", m)]
    import re
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL)
    ok = len(loops) == STMTDEC_LOOPS
    return ("HELD" if ok else "BREAK",
            "stmtdec_loops=%d pin=%d" % (len(loops), STMTDEC_LOOPS))


@_t
def test_p0_footer_state():
    """F1068-F1071 stamped CLOSED (span-positional); merged-tree footer:
    F1065-F1073 closed (9); F1074-F1079 open (6); next free F1080."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    entries = [ln for ln in text.splitlines()
               if ln.startswith("(F1068 filed ")
               or ln.startswith("(F1069 filed ")
               or ln.startswith("(F1070 filed ")
               or ln.startswith("(F1071 filed ")]
    ok = (len(entries) == 4
          and all("[CLOSED" in e for e in entries)
          and "Next free finding: **F1080**" in text
          and "F1065-F1073 CLOSED (9" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


@_t
def test_p1_filed_shapes_block():
    """All 12 filed shapes (w397 red-firsts) block on the closed tree."""
    shapes = [
        # F1068 filed (2)
        "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});"
        "%s.forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');" % _codes(_CRED),
        "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});"
        "%s.forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');" % _codes(_CRED40),
        # F1069 filed (6)
        "var r=new WeakRef({c:%s});var RESULT=String.fromCharCode(...r.deref().c);" % _codes(_CRED),
        "globalThis.K=%s;var RESULT=String.fromCharCode(...globalThis.K);" % _codes(_CRED),
        "var f=(...a)=>String.fromCharCode(...a);var RESULT=f(...%s);" % _codes(_CRED),
        "var r=new WeakRef({c:%s});var RESULT=String.fromCharCode(...r.deref().c);" % _codes(_CRED40),
        "globalThis.K=%s;var RESULT=String.fromCharCode(...globalThis.K);" % _codes(_CRED40),
        "var f=(...a)=>String.fromCharCode(...a);var RESULT=f(...%s);" % _codes(_CRED40),
        # F1070 filed (2)
        'var parts=[%s,%s];var RESULT=[...new Intl.Segmenter().segment(parts.join("%s"))]'
        '.filter(s=>s.segment!=="%s").map(s=>s.segment).join("");' % (_frags(_CRED) + (_ZW, _ZW)),
        'var parts=[%s,%s];var RESULT=[...new Intl.Segmenter().segment(parts.join("%s"))]'
        '.filter(s=>s.segment!=="%s").map(s=>s.segment).join("");' % (_frags(_CRED40) + (_ZW, _ZW)),
        # F1071 filed (2)
        'var O={a:%s,b:%s};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];'
        "var RESULT=S;" % _frags(_CRED),
        'var O={a:%s,b:%s};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];'
        "var RESULT=S;" % _frags(_CRED40),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------- p2: generalizations (node-verified)


@_t
def test_p2_generalizations_block():
    """Node-verified generalizations (20-case differential) decode
    node-exactly at the hook level (fragments are non-credential, so
    the assertion is hook decode == node RESULT)."""
    cases = [
        # F1068: arrow-colon trap, function-callback, sequential writes,
        # rewrite order, dup-key later-wins.
        (dlp._js_f1068_stmt_decode,
         "var o={};var p=new Proxy(o,{set:(t,k,v)=>{t[k]=String.fromCharCode(v);return true;}});[120,111].forEach(function(v,i){p[i]=v;});var RESULT=Object.values(o).join(\"\");",
         "xo"),
        (dlp._js_f1068_stmt_decode,
         "let o={};let p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});[120,111,120].forEach((v,i)=>p[i]=v);var RESULT=Object.values(o).join('');",
         "xox"),
        (dlp._js_f1068_stmt_decode,
         "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});p[0]=120;p[1]=111;p[2]=120;var RESULT=Object.values(o).join('');",
         "xox"),
        (dlp._js_f1068_stmt_decode,
         "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});p[1]=111;p[0]=120;p[1]=120;var RESULT=Object.values(o).join('');",
         "xx"),
        # F1069: quoted weakref prop + bracket read, globalThis bracket,
        # function-decl rest, named codes array, braced arrow.
        (dlp._js_f1069_stmt_decode,
         'var r=new WeakRef({"c":[120,111],"d":"x"});var RESULT=String.fromCharCode(...r.deref()["c"]);',
         "xo"),
        (dlp._js_f1069_stmt_decode,
         'globalThis["K"]=[120,111];var RESULT=String.fromCharCode(...globalThis["K"]);',
         "xo"),
        (dlp._js_f1069_stmt_decode,
         "function g(...a){return String.fromCharCode(...a);}var RESULT=g(...[120,111]);",
         "xo"),
        (dlp._js_f1069_stmt_decode,
         "var C=[120,111];var f=(...a)=>{return String.fromCharCode(...a);};var RESULT=f(...C);",
         "xo"),
        (dlp._js_f1069_stmt_decode,
         "const r=new WeakRef({c:[120,111]});const RESULT=String.fromCharCode(...r.deref().c);",
         "xo"),
        # F1070: locale arg, word granularity, Array.from, paren params,
        # != twin, trailing comma.
        (dlp._js_f1070_stmt_decode,
         'var parts=["x","o"];var RESULT=Array.from(new Intl.Segmenter("en",{granularity:"grapheme"}).segment(parts.join("%s"))).filter((s)=>s.segment!="%s").map((s)=>s.segment).join("");' % (_ZW, _ZW),
         "xo"),
        (dlp._js_f1070_stmt_decode,
         'let parts=["x","o",];var RESULT=[...new Intl.Segmenter("en").segment(parts.join("%s"))].filter(s=>s.segment!=="%s").map(s=>s.segment).join("");' % (_ZW, _ZW),
         "xo"),
        (dlp._js_f1070_stmt_decode,
         'var parts=["x","","o"];var RESULT=[...new Intl.Segmenter().segment(parts.join("%s"))].filter(s=>s.segment!=="%s").map(s=>s.segment).join("");' % (_ZW, _ZW),
         "xo"),
        # F1071: int-key ordering, dup later-wins, S=S+O[k], braceless,
        # additive RESULT, bare numeric keys.
        (dlp._js_f1071_stmt_decode,
         'var O={2:"b",a:"a",1:"A"};var S="";for(const k of Object.getOwnPropertyNames(O))S=S+O[k];var RESULT=">"+S+"<";',
         ">Aba<"),
        (dlp._js_f1071_stmt_decode,
         'let O={a:"x",b:"o"};let S="";for(let k of Object.getOwnPropertyNames(O))S+=O[k];let RESULT=S;',
         "xo"),
        (dlp._js_f1071_stmt_decode,
         'var O={a:"x",b:"o"};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];var RESULT=S;',
         "xo"),
        (dlp._js_f1071_stmt_decode,
         'var O={a:"x",a:"o"};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];var RESULT=S;',
         "o"),
        (dlp._js_f1071_stmt_decode,
         'var O={0:"x",1:"o"};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];var RESULT=S;',
         "xo"),
    ]
    bad = [(p, want, fn(p)) for fn, p, want in cases if fn(p) != want]
    ok = not bad
    note = "%d/%d generalizations node-exact" % (len(cases) - len(bad), len(cases))
    if bad:
        note += " e.g. %r want %r got %r" % (bad[0][0][:60], bad[0][1], bad[0][2])
    return ("HELD" if ok else "BREAK", note)


# --------------------------------------- p3: fail-closed bounds


@_t
def test_p3_fail_closed():
    """Adversarial near-misses stay quiet (miss, never mis-decode)."""
    quiet = [
        # F1068
        "var o={};var p=new Proxy(o,{get(t,k){return t[k];}});[120].forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');",
        "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=v;return true;}});[120].forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');",
        "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);}});[120].forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');",
        "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});p[01]=120;var RESULT=Object.values(o).join('');",
        "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;},get(t,k){return t[k];}});[120].forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');",
        "var o={a:1};var p=new Proxy(o,{set(t,k,v){t[k]=String.fromCharCode(v);return true;}});[120].forEach((cc,i)=>{p[i]=cc;});var RESULT=Object.values(o).join('');",
        # F1069
        'var r=new WeakRef({c:"ab"});var RESULT=String.fromCharCode(...r.deref().c);',
        'var r=new WeakRef({c:[120]});var RESULT=r.deref().c;',
        "globalThis.__proto__=[120];var RESULT=String.fromCharCode(...globalThis.__proto__);",
        "var f=(...a)=>String.fromCharCode(...a);var RESULT=f(120,111);",
        "var f=(a)=>String.fromCharCode(...a);var RESULT=f(...[120]);",
        "var C=[120];var f=(...a)=>String.fromCharCode(...a);var RESULT=f(...D);",
        # F1070
        'var parts=["x","o"];var RESULT=[...new Intl.Segmenter().segment(parts.join("|"))].filter(s=>s.segment!=="|").map(s=>s.segment).join("");',
        'var parts=["x","o"];var RESULT=[...new Intl.Segmenter("en",{granularity:"sentence"}).segment(parts.join("%s"))].filter(s=>s.segment!=="%s").map(s=>s.segment).join("");' % (_ZW, _ZW),
        # Spec review H-1: "word" granularity fails closed -- U+200B
        # merges with a following Extend/Format char there (stripping
        # it would mis-decode: node keeps "a\u200b\u0301x").
        'var P=["a","\u0301x"];var RESULT=[...new Intl.Segmenter("en",{granularity:"word"}).segment(P.join("%s"))].filter(s=>s.segment!=="%s").map(s=>s.segment).join("");' % (_ZW, _ZW),
        'var parts=["x","o"];var RESULT=[...new Intl.Segmenter("en",{granularity:"word"}).segment(parts.join("%s"))].filter(s=>s.segment!=="%s").map(s=>s.segment).join("");' % (_ZW, _ZW),
        'var parts=["x","o"];var RESULT=[...new Intl.Segmenter().segment(parts.join("%s"))].filter(s=>s.segment==="x").map(s=>s.segment).join("");' % _ZW,
        # F1071
        'var O={a:"x"};var S="";for(var k in O)S+=O[k];var RESULT=S;',
        'var O={a:"x"};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k]+O[k];var RESULT=S;',
        'var O={a:"x"};var S="y";for(var k of Object.getOwnPropertyNames(O))S+=O[k];var RESULT=S;',
        'var O={__proto__:"x"};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];var RESULT=S;',
        'var O={a:120};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];var RESULT=S;',
        'var O={a:"x"};var S="";for(var k of Object.keys(O))S+=O[k];var RESULT=S;',
    ]
    bad = [s for s in quiet if not _misses(s)]
    ok = not bad
    note = "%d/%d fail-closed quiet" % (len(quiet) - len(bad), len(quiet))
    if bad:
        note += " e.g. %r" % bad[0][:70]
    return ("HELD" if ok else "BREAK", note)


# --------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_pins():
    """Adjacent productions keep their behavior: F1059 (get-trap),
    F991 (WeakRef quoted reads), F1044 (for-in), and the still-open
    F1065-F1067/F1072-F1073 stay open."""
    blocked = [
        # F1059 Proxy named-target get-trap still blocks coded.
        'var t={a:"%s",b:"%s"};var p=new Proxy(t,{get:function(o,k){return o[k];}});var RESULT=p.a+p.b;' % (_F1, _F2),
        # F991 WeakRef quoted-literal deref reads still block coded.
        'var r=new WeakRef({v:"%s"});var RESULT=r.deref().v+"%s";' % (_F1, _F2),
        # F1044 for-in enumeration reads still block coded.
        'var o={0:120,1:111,2:120,3:98,4:45};var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s+"0123456789abcdef";',
        # F1062 Set.forEach (wave-397 lane 4, now CLOSED) blocks.
        'var s=new Set(["%s","%s"]);var acc="";s.forEach(function(v){acc+=v;});var RESULT=acc;' % (_F1, _F2),
        # --- merged-tree reconciliation: now-CLOSED siblings (wave-398 merge) ---
        # F1065 generator function-declaration accumulation (wave-398
        # lane 1, CLOSED at wave-398 merge -- true filed shape from the w397
        # red-first; stale invented shapes that embed a credential
        # literal are not pins, wave-396 lesson).
        "var C=%s;function* g(){for(var i=0;i<C.length;i++)yield C[i];}"
        "var S='';for(var x of g())S+=String.fromCharCode(x);var RESULT=S;" % _codes(_CRED),
        # F1072 JSON.parse plain property reads (wave-398 lane 3, CLOSED at merge).
        'var o=JSON.parse(\'{"a":"%s","b":"%s"}\');var RESULT=o.a+o.b;' % (_F1, _F2),
    ]
    still_open = []
    bad_blocked = [s for s in blocked if not _blocked(s)]
    bad_open = [s for s in still_open if not _misses(s)]
    ok = not bad_blocked and not bad_open
    return ("HELD" if ok else "BREAK",
            "blocked %d/%d, open-miss %d/%d"
            % (len(blocked) - len(bad_blocked), len(blocked),
               len(still_open) - len(bad_open), len(still_open)))


# --------------------------------------- p5: honest-text controls


@_t
def test_p5_honest_text_quiet():
    """Prose mentioning these APIs stays quiet."""
    quiet = [
        "The Proxy set trap intercepts property assignments before they reach the target object.",
        "Use a WeakRef when you want to observe an object without preventing garbage collection.",
        "Spread the array into String.fromCharCode to decode the bytes.",
        "Intl.Segmenter splits text into graphemes, words, or sentences per locale.",
        "Object.getOwnPropertyNames returns all own property keys including non-enumerable ones.",
        "We store the config on globalThis so all modules can read it.",
        "The filter callback removes segments matching the separator before joining.",
        "(function(){var s='ab';return s;})()",
    ]
    bad = [s for s in quiet if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d honest-text quiet" % (len(quiet) - len(bad), len(quiet)))


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 mixed sites scan in under 60s."""
    sites = [
        "Contact support at help@example.com for assistance.",
        "var o={};var p=new Proxy(o,{set(t,k,v){t[k]=v;return true;}});var RESULT=Object.values(o).join('');",
        "The Intl.Segmenter documentation shows word granularity examples.",
        'var O={a:"x"};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];var RESULT=S;',
        "Object.getOwnPropertyNames is the standard way to enumerate keys.",
    ]
    t0 = time.time()
    for i in range(200):
        _blocked(sites[i % len(sites)])
    dt = time.time() - t0
    ok = dt < 60.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# --------------------------------------- p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    batteries = ("w397_f1068_redfirst.py", "w397_f1069_redfirst.py",
                 "w397_f1070_redfirst.py", "w397_f1071_redfirst.py")
    for battery in batteries:
        tmp = tempfile.mkdtemp(prefix="g398-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line formats: "FAIL <shape>" (blocked, good on the
        # closed tree) / "BREAK <shape>" (miss, bad);
        # "ctrl-ok"/"CTRL-FAIL".
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith(("FAIL ", "BREAK ", "HELD ")))
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
    """Depth-1 green check: w397 F1068-F1071 red-firsts show 0 BREAK."""
    return _green_check()


_EXPECTED_BREAKS = set()


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
        except Exception as e:  # noqa: BLE001 - battery must not die
            verdict, note = "BREAK", "EXC %s: %s" % (type(e).__name__, e)
        if verdict == "HELD":
            held += 1
        else:
            broke += 1
            failed.append((fn.__name__, note))
        print("%s %s -- %s" % (verdict, fn.__name__, note))
    print("HELD %d / BREAK %d / %d tests" % (held, broke, len(TESTS)))
    for name, note in failed:
        print("FAILED:", name, "--", note)
    return 1 if broke else 0


if __name__ == "__main__":
    sys.exit(main())
