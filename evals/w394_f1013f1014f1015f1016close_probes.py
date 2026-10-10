#!/usr/bin/env python3
"""Wave-394 lane 3 close battery: F1013/F1014/F1015/F1016 CLOSED.

F1013 = manual iterator accumulation (attack round 61).
F1014 = new Function fragment body (attack round 61).
F1015 = Object.keys().map().join() reassembly (attack round 61).
F1016 = push assembly (attack round 61).

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0); fail-closed bounds stay quiet (miss, never
mis-decode); sibling pins unaffected; honest text quiet; 200-site perf;
F1015/F751 consistency on the shared subset; depth-1 green check on
w393_attack_probes.py (only the 4 now-closed pins may BREAK there --
the merge flips them, wave-391 precedent).

F1015 coverage note: F751 (via the F949 top-level rewrite) already
blocks `function(K){return O[K];}` (with semicolon) and `K=>O[K]`;
this lane covers the filed no-semicolon form plus named-function and
block-body-arrow generalizations. Shared shapes decode identically.

Pins: TAXONOMY_PIN 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28.
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

TAXONOMY_PIN = 2143  # wave-393 merge (no code-count change)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "012"
_B = "3456789" + "abcdef"
_A40 = "xox"
_B40 = "b-0123456789abcdef0123456789abcdef012"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls


@_t
def test_b0_pin_taxonomy():
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s codes=%d" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_b0_pin_verifier():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "w318", os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ok = mod.VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % mod.VERIFIER_TAXONOMY_PIN)


@_t
def test_b0_recompile_count():
    n = len(re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Lane-local footer (wave-394 lane 3): F1013-F1016 CLOSED; open F1005-F1012, F1017-F1024 (16); next free F1025."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F1013-F1016 CLOSED (4" in text
          and "open F1005-F1012, F1017-F1024 (16)" in text
          and "next free F1025" in text)
    return ("HELD" if ok else "BREAK", "lane_footer=%s" % ok)


@_t
def test_b0_junk_quiet():
    quiet = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


# ------------------------------------------------------- P1 filed shapes


@_t
def test_p1_filed_shapes():
    shapes = [
        # F1013
        'var it=["%s","%s"].values();var r="";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;' % (_A, _B),
        'var it=["%s","%s"].values();var r="";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;' % (_A40, _B40),
        # F1014
        'var RESULT=new Function("return \\"%s\\"+\\"%s\\"")();' % (_A, _B),
        'var RESULT=new Function("return \\"%s\\"+\\"%s\\"")();' % (_A40, _B40),
        # F1015
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");' % (_A, _B),
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");' % (_A40, _B40),
        # F1016
        'var a=["%s"];a.push("%s");var RESULT=a.join("");' % (_A, _B),
        'var a=["%s"];a.push("%s");var RESULT=a.join("");' % (_A40, _B40),
    ]
    bad = [i for i, p in enumerate(shapes) if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "filed: %d/%d blocked; misses=%s" % (len(shapes) - len(bad), len(shapes), bad))


# ---------------------------------------------------- P2 generalizations


@_t
def test_p2_generalizations():
    shapes = [
        # F1013: bare loop var, =-form body, let/const
        'var it=["%s","%s"].values();var r="";while(!(n=it.next()).done)r+=n.value;var RESULT=r;' % (_A, _B),
        'var it=["%s","%s"].values();var r="";var n;while(!(n=it.next()).done)r=r+n.value;var RESULT=r;' % (_A, _B),
        'let it=["%s","%s"].values();let r="";let n;while(!(n=it.next()).done)r+=n.value;const RESULT=r;' % (_A, _B),
        # F1014: no-new, single-quote body with trailing semi
        'var RESULT=Function("return \\"%s\\"+\\"%s\\"")();' % (_A, _B),
        "var RESULT=new Function('return \\'%s\\'+\\'%s\\';')();" % (_A, _B),
        # F1015: arrow, paren-arrow, block-body arrow, named function, int keys
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(k=>o[k]).join("");' % (_A, _B),
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map((k)=>o[k]).join("");' % (_A, _B),
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(k=>{return o[k];}).join("");' % (_A, _B),
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(function f(k){return o[k];}).join("");' % (_A, _B),
        'var o={a:"%s",a:"%s",b:"%s",};var RESULT=Object.keys(o).map(function(k){return o[k];}).join("");' % (_A, _A, _B),
        'var o={2:"%s",0:"%s"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");' % (_B, _A),
        # F1016: multi-arg push, multiple pushes, non-empty sep, zero-arg push
        'var a=["%s"];a.push("3456","%s");var RESULT=a.join("");' % (_A, _B[4:]),
        'var a=["xoxb-"];a.push("012");a.push("%s");var RESULT=a.join("");' % _B,
        'var a=["xoxb","0123456789abcdef"];a.push();var RESULT=a.join("-");',
    ]
    bad = [i for i, p in enumerate(shapes) if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "generalizations: %d/%d blocked; misses=%s" % (len(shapes) - len(bad), len(shapes), bad))


# ---------------------------------------------------- P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    misses = [
        # F1013
        'var it=["a","b"].values();var r="x";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;',
        'var it=x.values();var r="";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;',
        'var it=["a","b"].values();var r="";var n;while(!(n=it.next()).done)r=n.value;var RESULT=r;',
        'var it=["a","b"].values();var r="";var n;while(n=it.next())r+=n.value;var RESULT=r;',
        'var it=["a","b"].keys();var r="";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;',
        'var it=["a","b"].values();var r="";var m;while(!(n=it.next()).done)r+=n.value;var RESULT=r;',
        'var it=["a","b"].values();var it="";var n;while(!(n=it.next()).done)it+=n.value;var RESULT=it;',
        'var it=["a","b"].values();var r="";var n;while(!(n=it.next()).done)r+=n.value;var q=1;var RESULT=r;',
        # F1014
        'var RESULT=new Function("a","return a")();',
        'var RESULT=new Function("var x=1")();',
        'var RESULT=new Function("return a+b")();',
        'var RESULT=new Function("return \'a\'","return \'b\'")();',
        'var RESULT=new Function("return \'a\'");',
        'var RESULT=new Function("return \'a\';var x=1")();',
        'var RESULT=new Function("return \'\\141\'")();',
        # F1015
        'var o={a:x};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");',
        'var o={__proto__:"x",a:"y"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");',
        'var o={a:"x"};var RESULT=Object.keys(o).map(function(k){return p[k]}).join("");',
        'var o={a:"x"};var RESULT=Object.keys(o).map(function(k){return o[j]}).join("");',
        'var o={a:"x"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join(x);',
        'var o={a:"x"};var q=1;var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");',
        'var o={"a":"x"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");',
        'var o={01:"x"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");',
        'var o={a:"x"};var RESULT=Object.keys(p).map(function(k){return o[k]}).join("");',
        # F1016
        'var a=["x"];var RESULT=a.join("");',
        'var a=["x"];a.push(y);var RESULT=a.join("");',
        'var a=["x"];b.push("y");var RESULT=a.join("");',
        'var a=["x"];a.push("y");var RESULT=a.join(x);',
        'var a=["x"];a.push("y");var RESULT=b.join("");',
        'var a=["x"];a.push("y");var q=1;var RESULT=a.join("");',
        'var a=["x"];a.splice(0,1);var RESULT=a.join("");',
    ]
    bad = [i for i, p in enumerate(misses) if not _misses(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "fail-closed: %d/%d quiet; blocked=%s" % (len(misses) - len(bad), len(misses), bad))


# ------------------------------------------------------- P4 sibling pins


@_t
def test_p4_sibling_open_still_break():
    """Open findings F1005-F1012, F1017-F1023 must still MISS."""
    payloads = [
        'var p={v:"%s"};var o=Object.create(p);o.x="%s";var RESULT=o.v+o.x;' % (_A, _B),  # F1005
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}});var RESULT=f(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);',  # F1006
        'var RESULT=String.fromCharCode(parseInt(\'78\',16),parseInt(\'6f\',16));',  # F1007 (shape head)
        'class A{p="%s"};var RESULT=new A().p+"%s";' % (_A, _B),  # F1008
        'class A{static p="%s"};var RESULT=A.p+"%s";' % (_A, _B),  # F1009
        'var o={};o.__defineGetter__("p",function(){return "%s"});var RESULT=o.p+"%s";' % (_A, _B),  # F1010
        'var r="";["%s","%s"].forEach(function(x){r+=x});var RESULT=r;' % (_A, _B),  # F1011
        'var r="";for(var kv of [["a","%s"],["b","%s"]])r+=kv[1];var RESULT=r;' % (_A, _B),  # F1012
        'var s=Reflect.construct(String,["%s"]);var RESULT=s+"%s";' % (_A, _B),  # F1017
        'var o={};Object.setPrototypeOf(o,{p:"%s"});var RESULT=o.p+"%s";' % (_A, _B),  # F1018
        'var a=["Q","%s","%s"];a.shift();var RESULT=a.join("");' % (_A, _B),  # F1019
        'function t(s,v){return s[0]+v+s[1]}var f="%s";var RESULT=t`%s${f}`;' % (_B, _A),  # F1020
        'with({a:"%s"}){var RESULT=a+"%s"};' % (_A, _B),  # F1021
        'var RESULT=Object.fromEntries(Object.entries({a:"%s",b:"%s"}))["a"]+Object.fromEntries(Object.entries({a:"%s",b:"%s"}))["b"];' % (_A, _B, _A, _B),  # F1022
        'var q=1;\nvar o={get p(){return "%s"}};var RESULT=o.p+"%s";' % (_A, _B),  # F1023
    ]
    bad = [i for i, p in enumerate(payloads) if not _misses(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "sibling-open: %d/%d still miss; blocked=%s" % (len(payloads) - len(bad), len(payloads), bad))


@_t
def test_p4_sibling_closed_still_block():
    """Closed findings F988-F1004 must still BLOCK (no regression)."""
    payloads = [
        'var s=new String("%s");var RESULT=s+"%s";' % (_A, _B),  # F988
        'var s="";var m=new Map([["a","%s"],["b","%s"]]);for(var kv of m){s+=kv[1];}var RESULT=s;' % (_A, _B),  # F989
        'var p=new Proxy({a:"%s",b:"%s"},{get:function(t,k){return t[k];}});var RESULT=p.a+p.b;' % (_A, _B),  # F990
        'var e=new Error("%s");var RESULT=e.message+"%s";' % (_A, _B),  # F992
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(function(k){return o[k];}).join("");' % (_A, _B),  # F751-covered F1015 twin
        'var q=["%s","%s"];var s="";while(q.length){s=s+q.pop();}var RESULT=s;' % (_B, _A),  # F981 filed shape
    ]
    bad = [i for i, p in enumerate(payloads) if not _blocked(p)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "sibling-closed: %d/%d blocked; misses=%s" % (len(payloads) - len(bad), len(payloads), bad))


# ------------------------------------------------------- P5 honest text


@_t
def test_p5_honest_text():
    texts = [
        "The invoice iterator values were reviewed in the meeting notes.",
        "new Function is disabled by CSP in this deployment.",
        "Object.keys(o).map(k => k.toUpperCase()) is a common pattern.",
        "Please push the release notes and join the call at noon.",
        "while(!(n=it.next()).done) is how the docs describe iteration.",
        "var RESULT = compute(); // honest code mentioning RESULT",
    ]
    bad = [i for i, t in enumerate(texts) if not _misses(t)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "honest: %d/%d quiet; blocked=%s" % (len(texts) - len(bad), len(texts), bad))


# ------------------------------------------------------- P6 perf


@_t
def test_p6_perf():
    """200 hostile sites decode in well under the lane budget (timing only)."""
    sites = []
    base = 'var it=["%s","%s"].values();var r="";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;'
    for i in range(200):
        sites.append(base % (_A, _B))
    t0 = time.time()
    hits = 0
    for s in sites:
        if dlp.find_credential(s) is not None:
            hits += 1
    dt = time.time() - t0
    ok = hits == 200 and dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites: %.2fs hits=%d/200" % (dt, hits))


# --------------------------------- P7 F1015/F751 consistency (shared subset)


@_t
def test_p7_f751_consistency():
    """On shapes F751 already covers, my hook must decode identically."""
    shapes = [
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(function(k){return o[k];}).join("");' % (_A, _B),
        'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(k=>o[k]).join("");' % (_A, _B),
        'var o={a:"%s",b:"%s",};var RESULT=Object.keys(o).map(function(k){return o[k];}).join("");' % (_A, _B),
    ]
    bad = []
    for i, p in enumerate(shapes):
        mine = dlp._js_f1015_stmt_decode(p)
        variants = dlp._decoded_variants(p)
        # my hook must produce the same decoded value some variant carries
        if mine is None or not any(mine in v for v in variants):
            bad.append(i)
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "f751-consistency: %d/%d identical; bad=%s" % (len(shapes) - len(bad), len(shapes), bad))


# ------------------------------------------------------ P8 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g394l3-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w393_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, target],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        lines = (r.stdout or "").strip().split("\n")
        broken = []
        for ln in lines[:-1]:
            if ": BREAK" in ln:
                broken.append(ln.split(":")[0])
        # Wave-394 merge: my 4 closures flip to _closed pins there; only
        # these 4 open pins may BREAK here.
        expected = {"test_r61_f1013_open", "test_r61_f1014_open",
                    "test_r61_f1015_open", "test_r61_f1016_open"}
        ok = set(broken) == expected
        return (("HELD" if ok else "BREAK"),
                "green(w393_attack): broken=%s" % sorted(broken))
    finally:
        pass


@_t
def test_p8_green_check():
    """Depth-1 green check on the round-61 attack battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            verdict, note = "BREAK", "probe raised %r" % (e,)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
