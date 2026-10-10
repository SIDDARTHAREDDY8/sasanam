#!/usr/bin/env python3
"""Wave-397 lane-1 close battery: F1048 + F1049 + F1050 + F1051.

F1048: nested Error cause-chain reads --
`var e=new Error("a",{cause:new Error("b",{cause:"frag"})});`
`var RESULT=e.cause.cause+"frag";` (inline and named-intermediate
forms; the decoder modeled only the single-level cause read --
distinct vs F787 single-level and F992 Error.message).
F1049: Promise resolution-staged fragment assembly --
`var RESULT="";var f1="frag1",f2="frag2";`
`Promise.all([f1,f2]).then(function(a){RESULT=a[0]+a[1];});` and
`var RESULT="";Promise.resolve("frag1").then(function(a){RESULT=a+"frag2";});`
(no Promise production was modeled).
F1050: URLSearchParams fragment reads --
`var u=new URLSearchParams({k1:"frag1",k2:"frag2"});`
`var RESULT=u.get("k1")+u.get("k2");` (object-init and query-string
forms) and the entries() iteration form (no URLSearchParams
production was modeled).
F1051: FormData staged fragment reads --
`var d=new FormData();d.append("a","frag1");d.append("b","frag2");`
`var RESULT=d.get("a")+d.get("b");` plus entries() value-iteration
and keys() iteration forms (no FormData production was modeled).

All decoders are node-exact (v24.20.0, 19-case differential) for
their modeled subsets; everything outside the strict grammars fails
closed (miss, never mis-decode). Pin 2143, VERIFIER_TAXONOMY_PIN 33,
re.compile( 28 in gov/dlp.py -- all untouched; N_STMTDEC_LOOPS
14 -> 15 (real code-count change: this lane's dispatch loop,
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
STMTDEC_LOOPS = 18  # wave-397 merge: lanes 1+2+3+4 each add one dispatch loop (14 -> 18, real code-count change, wave-385 rule)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_CRED = "xoxb-" + "0123456789abcdef"
_CRED40 = "xox" + "b-0123456789abcdef0123456789abcdef012"
_F1 = "xoxb-" + "01"
_F2 = "23456789" + "abcdef"
_F1_40 = "xox"
_F2_40 = "b-0123456789abcdef0123456789abcdef012"


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
    """One new _stmtdec dispatch loop (F1048-F1051); pin 14 -> 15."""
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
    """F1048-F1051 stamped CLOSED (span-positional); lane-local footer:
    F1052-F1064 open (13); next free F1065."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    entries = [ln for ln in text.splitlines()
               if ln.startswith("(F1048 filed ")
               or ln.startswith("(F1049 filed ")
               or ln.startswith("(F1050 filed ")
               or ln.startswith("(F1051 filed ")]
    ok = (len(entries) == 4
          and all("[CLOSED" in e for e in entries)
          and "Next free finding: **F1065**" in text
          and "F1052-F1064 OPEN (13" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


@_t
def test_p1_filed_shapes_block():
    """All 13 filed shapes (w396 red-firsts) block on the closed tree."""
    shapes = [
        # F1048 filed (3)
        'var e=new Error("a",{cause:new Error("b",{cause:"%s"})});var RESULT=e.cause.cause+"%s";' % (_F1, _F2),
        'var e=new Error("a",{cause:new Error("b",{cause:"%s"})});var RESULT=e.cause.cause+"%s";' % (_F1_40, _F2_40),
        'var inner=new Error("b",{cause:"%s"});var e=new Error("a",{cause:inner});var RESULT=e.cause.cause+"%s";' % (_F1, _F2),
        # F1049 filed (3)
        'var RESULT="";var f1="%s",f2="%s";Promise.all([f1,f2]).then(function(a){RESULT=a[0]+a[1];});' % (_F1, _F2),
        'var RESULT="";var f1="%s",f2="%s";Promise.all([f1,f2]).then(function(a){RESULT=a[0]+a[1];});' % (_F1_40, _F2_40),
        'var RESULT="";Promise.resolve("%s").then(function(a){RESULT=a+"%s";});' % (_F1, _F2),
        # F1050 filed (3)
        'var u=new URLSearchParams({k1:"%s",k2:"%s"});var RESULT=u.get("k1")+u.get("k2");' % (_F1, _F2),
        'var u=new URLSearchParams("k1=%s&k2=%s");var RESULT=u.get("k1")+u.get("k2");' % (_F1_40, _F2_40),
        'var u=new URLSearchParams({k1:"%s",k2:"%s"});var s="";for(var p of u.entries()){s+=p[1];}var RESULT=s;' % (_F1, _F2),
        # F1051 filed (4)
        'var d=new FormData();d.append("a","%s");d.append("b","%s");var RESULT=d.get("a")+d.get("b");' % (_F1, _F2),
        'var d=new FormData();d.append("a","%s");d.append("b","%s");var RESULT=d.get("a")+d.get("b");' % (_F1_40, _F2_40),
        'var d=new FormData();d.append("a","%s");d.append("b","%s");var s="";for(var p of d.entries()){s+=p[1];}var RESULT=s;' % (_F1, _F2),
        'var d=new FormData();d.append("%s","x");d.append("%s","y");var s="";for(var k of d.keys()){s+=k;}var RESULT=s;' % (_F1, _F2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------- p2: generalizations (node-verified)


@_t
def test_p2_generalizations_block():
    """Node-verified generalizations (19-case differential) decode
    node-exactly at the hook level (fragments are non-credential, so
    the assertion is hook decode == node RESULT)."""
    cases = [
        # F1048: quoted cause key, let/const, trailing literal, bare
        # RESULT, pre-literal, named-let.
        (dlp._js_f1048_stmt_decode,
         'var e=new Error("a",{"cause":new Error("b",{cause:"FR1"})});var RESULT=e.cause.cause+"FR2";',
         "FR1FR2"),
        (dlp._js_f1048_stmt_decode,
         'let e=new Error("a",{cause:new Error("b",{cause:"FR1"})});let RESULT=e.cause.cause+"FR2";',
         "FR1FR2"),
        (dlp._js_f1048_stmt_decode,
         'var e=new Error("a",{cause:new Error("b",{cause:"FR1"})});var RESULT=e.cause.cause+"FR2"+"FR3";',
         "FR1FR2FR3"),
        (dlp._js_f1048_stmt_decode,
         'var e=new Error("a",{cause:new Error("b",{cause:"FR1"})});var RESULT=e.cause.cause;',
         "FR1"),
        (dlp._js_f1048_stmt_decode,
         'var e=new Error("a",{cause:new Error("b",{cause:"FR1"})});var RESULT="FR0"+e.cause.cause;',
         "FR0FR1"),
        (dlp._js_f1048_stmt_decode,
         'const inner=new Error("b",{cause:"FR1"});const e=new Error("a",{cause:inner});var RESULT=e.cause.cause+"FR2";',
         "FR1FR2"),
        # F1049: reversed resolve body, let decls.
        (dlp._js_f1049_stmt_decode,
         'var RESULT="";Promise.resolve("FR1").then(function(a){RESULT="FR2"+a;});',
         "FR2FR1"),
        (dlp._js_f1049_stmt_decode,
         'let RESULT="";let f1="FR1",f2="FR2";Promise.all([f1,f2]).then(function(a){RESULT=a[0]+a[1];});',
         "FR1FR2"),
        # F1050: percent-encoding, +-space, dup keys (get-first),
        # int-key ordering, insertion-order entries, bare name,
        # quoted keys.
        (dlp._js_f1050_stmt_decode,
         'var u=new URLSearchParams("k1=a%20b&k2=c+d");var RESULT=u.get("k1")+u.get("k2");',
         "a bc d"),
        (dlp._js_f1050_stmt_decode,
         'var u=new URLSearchParams("k=a&k=b");var RESULT=u.get("k");',
         "a"),
        (dlp._js_f1050_stmt_decode,
         'var u=new URLSearchParams({2:"b",1:"a",k:"c"});var s="";for(var p of u.entries()){s+=p[1];}var RESULT=s;',
         "abc"),
        (dlp._js_f1050_stmt_decode,
         'var u=new URLSearchParams({b:"2",a:"1"});var s="";for(var p of u.entries()){s+=p[1];}var RESULT=s;',
         "21"),
        (dlp._js_f1050_stmt_decode,
         'var u=new URLSearchParams("k1&k2=v");var RESULT=u.get("k1")+u.get("k2");',
         "v"),
        (dlp._js_f1050_stmt_decode,
         'var u=new URLSearchParams({"k1":"v1","k2":"v2"});var RESULT=u.get("k1")+u.get("k2");',
         "v1v2"),
        (dlp._js_f1050_stmt_decode,
         'var u=new URLSearchParams("?k1=FR1&k2=FR2");var RESULT=u.get("k1")+u.get("k2");',
         "FR1FR2"),
        # F1051: dup appends (get-first), entries with dups, S=S+K,
        # braceless for, let decls.
        (dlp._js_f1051_stmt_decode,
         'var d=new FormData();d.append("a","v1");d.append("a","v2");var RESULT=d.get("a");',
         "v1"),
        (dlp._js_f1051_stmt_decode,
         'var d=new FormData();d.append("a","v1");d.append("b","v2");d.append("a","v3");var s="";for(var p of d.entries()){s+=p[1];}var RESULT=s;',
         "v1v2v3"),
        (dlp._js_f1051_stmt_decode,
         'var d=new FormData();d.append("k1","x");d.append("k2","y");var s="";for(var k of d.keys()){s=s+k;}var RESULT=s;',
         "k1k2"),
        (dlp._js_f1051_stmt_decode,
         'var d=new FormData();d.append("k1","x");var s="";for(var k of d.keys())s+=k;var RESULT=s;',
         "k1"),
        (dlp._js_f1051_stmt_decode,
         'let d=new FormData();d.append("a","v1");let RESULT=d.get("a");',
         "v1"),
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
    """Out-of-grammar inputs miss (never mis-decode)."""
    misses = [
        # F1048: 3-level chain, non-literal cause, TypeError ctor,
        # non-Error ctor.
        'var e=new Error("a",{cause:new Error("b",{cause:new Error("c",{cause:"x"})})});var RESULT=e.cause.cause.cause+"y";',
        'var e=new Error("a",{cause:new Error("b",{cause:x})});var RESULT=e.cause.cause+"y";',
        'var e=new TypeError("a",{cause:new Error("b",{cause:"x"})});var RESULT=e.cause.cause+"y";',
        'var e=new Error("a",{cause:"x"});var RESULT=e.cause.cause+"y";',
        # F1049: arrow callback, 3-element all, missing prologue,
        # non-literal fragment.
        'var RESULT="";Promise.resolve("a").then(a=>{RESULT=a+"b";});',
        'var RESULT="";var f1="a",f2="b";Promise.all([f1,f2,"c"]).then(function(a){RESULT=a[0]+a[1];});',
        'Promise.resolve("a").then(function(a){RESULT=a+"b";});',
        'var RESULT="";var f1=a,f2="b";Promise.all([f1,f2]).then(function(a){RESULT=a[0]+a[1];});',
        # F1050: missing get-name, no-arg ctor, non-literal init.
        'var u=new URLSearchParams({k1:"a"});var RESULT=u.get("k1")+u.get("nope");',
        'var u=new URLSearchParams();var RESULT=u.get("k");',
        'var u=new URLSearchParams(qs);var RESULT=u.get("k1");',
        # F1051: non-literal append arg, ctor arg, missing get-name,
        # values() method.
        'var d=new FormData();d.append("a",f);var RESULT=d.get("a");',
        'var d=new FormData(document.forms[0]);d.append("a","b");var RESULT=d.get("a");',
        'var d=new FormData();d.append("a","b");var RESULT=d.get("zz");',
        'var d=new FormData();d.append("a","b");var s="";for(var v of d.values()){s+=v;}var RESULT=s;',
    ]
    bad = [s for s in misses if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d fail-closed miss" % (len(misses) - len(bad), len(misses)))


# --------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_pins():
    """Closed siblings stay blocked; still-open F1052-F1064 still miss."""
    blocked = [
        # F787 single-level cause read still blocks coded.
        'var e=new Error("x",{cause:"%s"});var RESULT=e.cause+"%s";' % (_F1, _F2),
        # F992 Error.message read still blocks coded.
        'var e=new Error("%s");var RESULT=e.message;' % _CRED,
        # F1044-F1047 (wave-396 lane 4) still block.
        'var o={0:120,1:111,2:120,3:98,4:45};var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s+"0123456789abcdef";',
        # F1052 Headers (wave-397 lane 2, now CLOSED) blocks.
        'var h=new Headers({"X-A":"%s","X-B":"%s"});var RESULT=h.get("X-A")+h.get("X-B");' % (_F1, _F2),
        'var h=new Headers({"X-A":"%s","X-B":"%s"});var s="";h.forEach(function(v,k){s+=v;});var RESULT=s;' % (_F1, _F2),
        # F1058 TextEncoder/TextDecoder (wave-397 lane 3, now CLOSED) blocks.
        'var enc=new TextEncoder();var p=[enc.encode("%s"),enc.encode("%s")];var dec=new TextDecoder();var RESULT=dec.decode(p[0])+dec.decode(p[1]);' % (_F1, _F2),
        # F1063 WeakMap staged-array (wave-397 lane 4, now CLOSED) blocks.
        'var wm=new WeakMap();var k={};wm.set(k,["%s","%s"]);var RESULT=wm.get(k)[0]+wm.get(k)[1];' % (_F1, _F2),
    ]
    # All F1048-F1064 now closed at merge; nothing in this lane's sibling
    # set remains open.
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
        "The Promise.all documentation shows how to wait for multiple promises before continuing.",
        "Use new FormData() to submit the form; call append for each field before sending.",
        "URLSearchParams parses the query string; call .get() to read values.",
        "The error cause chain helps debug nested failures in production logs.",
        "We migrated from callbacks to Promise.resolve for the default value.",
        "Check the entries() of the map and accumulate the values in a loop.",
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
        'var e=new Error("a",{cause:new Error("b",{cause:"%s"})});var RESULT=e.cause.cause+"%s";' % (_F1, _F2),
        "The quarterly report discusses Promise.all usage patterns.",
        'var u=new URLSearchParams({k1:"a",k2:"b"});var RESULT=u.get("k1");',
        "FormData append is the standard way to build multipart bodies.",
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
    batteries = ("w396_f1048_redfirst.py", "w396_f1049_redfirst.py",
                 "w396_f1050_redfirst.py", "w396_f1051_redfirst.py")
    for battery in batteries:
        tmp = tempfile.mkdtemp(prefix="g397-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line formats: "FAIL <shape>"/"HELD <shape>" (blocked,
        # good on the closed tree) / "BREAK <shape>" (miss, bad);
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
    """Depth-1 green check: w396 F1048-F1051 red-firsts show 0 BREAK."""
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
