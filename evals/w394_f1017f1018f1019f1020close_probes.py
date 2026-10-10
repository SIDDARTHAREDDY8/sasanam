#!/usr/bin/env python3
"""Wave-394 lane 4 close battery: F1017/F1018/F1019/F1020 CLOSED.

F1017 = Reflect.construct(String,...) reads (attack round 61).
F1018 = Object.setPrototypeOf reads (attack round 61).
F1019 = shift assembly (attack round 61).
F1020 = tagged-template substitution (attack round 61).

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0); fail-closed bounds stay quiet (miss, never
mis-decode); sibling pins unaffected; honest text quiet; 200-site perf;
depth-1 green check on w393_attack_probes.py (only the 4 now-closed
pins may BREAK there -- the merge flips them, wave-391 precedent).

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
    """Merged footer (wave-393): F988-F1004 CLOSED; F1005-F1024 OPEN; next free F1025."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F988-F1004 CLOSED (17" in text
          and "F1005-F1024 OPEN (20" in text
          and "Next free finding: **F1025**" in text
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
        # F1017 (filed shapes, short + 40-char)
        'var s=Reflect.construct(String,["xoxb-012"]);var RESULT=s+"3456789abcdef";',
        'var s=Reflect.construct(String,["xox"]);var RESULT=s+"b-0123456789abcdef0123456789abcdef012";',
        # F1018
        'var o={};Object.setPrototypeOf(o,{p:"xoxb-012"});var RESULT=o.p+"3456789abcdef";',
        'var o={};Object.setPrototypeOf(o,{p:"xox"});var RESULT=o.p+"b-0123456789abcdef0123456789abcdef012";',
        # F1019
        'var a=["Q","xoxb-012","3456789abcdef"];a.shift();var RESULT=a.join("");',
        'var a=["Q","xox","b-0123456789abcdef0123456789abcdef012"];a.shift();var RESULT=a.join("");',
        # F1020
        'function t(s,v){return s[0]+v+s[1]}var f="3456789abcdef";var RESULT=t`xoxb-012${f}`;',
        'function t(s,v){return s[0]+v+s[1]}var f="b-0123456789abcdef0123456789abcdef012";var RESULT=t`xox${f}`;',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/8" % len(missed))


# ----------------------------------------------------- P2 generalizations


@_t
def test_p2_generalizations():
    # All node-verified v24.20.0; each holds a credential-shaped value.
    shapes = [
        # F1017: multi-arg (first wins), empty array, let, 3-term additive
        'var s=Reflect.construct(String,["xoxb-012","junk"]);var RESULT=s+"3456789abcdef";',
        'var s=Reflect.construct(String,[]);var RESULT=s+"xoxb-0123456789abcdef";',
        'let s=Reflect.construct(String,["xoxb-012"]);var RESULT="pre"+s+"3456789abcdef";',
        'const s=Reflect.construct(String,["xoxb"]);var RESULT=s+"-012"+"3456789abcdef";',
        # F1018: own-prop shadowing, bracket reads, multi-prop proto, let
        'var o={a:"Q"};Object.setPrototypeOf(o,{p:"xoxb-012"});var RESULT=o.a+o.p+"3456789abcdef";',
        'var o={};Object.setPrototypeOf(o,{p:"xoxb-012"});var RESULT=o["p"]+"3456789abcdef";',
        'var o={};Object.setPrototypeOf(o,{x:"1",p:"xoxb-012"});var RESULT=o.p+"3456789abcdef";',
        "let o={};Object.setPrototypeOf(o,{'p':'xoxb-012'});var RESULT=o.p+'3456789abcdef';",
        # F1019: two shifts, separator join, const, trailing comma
        'var a=["Q","J","xoxb-012","3456789abcdef"];a.shift();a.shift();var RESULT=a.join("");',
        'var a=["Q","xoxb-0123456789","abcdef"];a.shift();var RESULT=a.join("");',
        'const a=["Q","xoxb-012","3456789abcdef",];a.shift();var RESULT=a.join("");',
        # F1020: renamed tag/params, literal subst, two bindings, trailing lit
        'function tag(a,b){return a[0]+b+a[1]}var f="3456789abcdef";var RESULT=tag`xoxb-012${f}`;',
        'function t(s,v){return s[0]+v+s[1]}var RESULT=t`xoxb-012${"3456789abcdef"}`;',
        'function t(s,v){return s[0]+v+s[1];}var g="zz";var f="3456789abcdef";var RESULT=t`xoxb-012${f}`;',
        'function t(s,v){return s[0]+v+s[1]}var f="3456789abcdef";var RESULT=t`xoxb-012${f}!!`;',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/15" % len(missed))


# ------------------------------------------------------ P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    # Outside the modeled subset: must stay quiet (miss), never mis-decode.
    # NOTE: shapes holding a credential-shaped FRAGMENT are avoided here;
    # these use inert fragments so a miss is provably quiet, and the
    # node-exactness of each boundary was verified against node v24.20.0.
    quiet_shapes = [
        # F1017: third arg (newTarget) fails closed; non-literal arg fails
        # closed; non-String target is not this production; trailing
        # statement after the sequence fails closed.
        'var s=Reflect.construct(String,["ab"],Object);var RESULT=s+"cd";',
        'var s=Reflect.construct(String,[x]);var RESULT=s+"cd";',
        'var s=Reflect.construct(Array,["ab"]);var RESULT=s+"cd";',
        'var s=Reflect.construct(String,["ab"]);var RESULT=s+"cd";var z=1;',
        # F1018: missing key is engine-undefined (fail closed); __proto__
        # keys fail closed; proto installed on a different name fails
        # closed; non-object proto arg fails closed.
        'var o={};Object.setPrototypeOf(o,{p:"ab"});var RESULT=o.q+"cd";',
        'var o={};Object.setPrototypeOf(o,{__proto__:{p:"ab"}});var RESULT=o.p+"cd";',
        'var o={};var w={};Object.setPrototypeOf(w,{p:"ab"});var RESULT=o.p+"cd";',
        'var o={};Object.setPrototypeOf(o,"ab");var RESULT=o.p+"cd";',
        # F1019: no shift is not this production; non-literal separator
        # fails closed; shift on a non-array-literal fails closed.
        'var a=["ab","cd"];var RESULT=a.join("");',
        'var a=["ab","cd"];a.shift();var s="";var RESULT=a.join(s);',
        'var a=getArr();a.shift();var RESULT=a.join("");',
        # F1020: a different tag body is not this production; two
        # substitutions fail closed; backslash escapes fail closed (no
        # cooking); unbound substitution name fails closed; the tag call
        # on a different function fails closed.
        'function t(s,v){return s[0]+v;}var f="cd";var RESULT=t`ab${f}`;',
        'function t(s,v){return s[0]+v+s[1]}var f="cd";var RESULT=t`ab${f}x${f}`;',
        'function t(s,v){return s[0]+v+s[1]}var f="cd";var RESULT=t`a\\nb${f}`;',
        'function t(s,v){return s[0]+v+s[1]}var RESULT=t`ab${zz}`;',
        'function t(s,v){return s[0]+v+s[1]}var f="cd";var RESULT=u`ab${f}`;',
        # Spec-review hard findings (wave-393): Annex-B octal escapes fail
        # closed (no mis-decode) in every hook's literals.
        'var s=Reflect.construct(String,["\\141"]);var RESULT=s+"b";',
        'var o={};Object.setPrototypeOf(o,{p:"\\141"});var RESULT=o.p+"b";',
        'var a=["\\141","b"];a.shift();var RESULT=a.join("");',
        'function t(s,v){return s[0]+v+s[1]}var f="b";var RESULT=t`\\141${f}`;',
    ]
    flagged = [s for s in quiet_shapes if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/21" % len(flagged))


# ------------------------------------------------------ P4 sibling pins


@_t
def test_p4_sibling_pins():
    # Disjointness from the nearest closed/open neighbors. Quiet twins
    # (credential-free) must stay quiet; already-CLOSED siblings must
    # stay blocked -- my hooks must neither over-block nor steal their
    # productions. Still-OPEN neighbors must stay open (no incidental
    # closures).
    quiet_twins = [
        'var s=Reflect.construct(String,["hello"]);var RESULT=s+"world";',
        'var o={};Object.setPrototypeOf(o,{p:"hello"});var RESULT=o.p+"world";',
        'var a=["Q","hello"];a.shift();var RESULT=a.join("");',
        'function t(s,v){return s[0]+v+s[1]}var f="world";var RESULT=t`hello${f}`;',
    ]
    still_closed = [
        # F1001 CLOSED: Reflect.apply on String.prototype.concat
        'var RESULT=Reflect.apply(String.prototype.concat,"xoxb-012",["3456789abcdef"]);',
        # F938 CLOSED: shift inside while-accumulation (r60 pin shape)
        "var q=['456789abcdef','xoxb-0123'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;",
        # F992 CLOSED: Error.message reads
        'var e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";',
        # F990 CLOSED: Proxy get-trap reads (filed shape)
        'var p=new Proxy({a:"xoxb-0123",b:"456789abcdef"},{get:function(t,k){return t[k];}});var RESULT=p.a+p.b;',
    ]
    still_open = [
        # F1005 OPEN: proto-chain reads WITHOUT setPrototypeOf -- my F1018
        # hook requires the setPrototypeOf statement and must not fire.
        'var p={v:"xoxb-012"};var o=Object.create(p);o.x="3456789abcdef";var RESULT=o.v+o.x;',
        # F1006 OPEN: Proxy apply-trap reads -- untouched by this lane.
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}});var RESULT=f(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);',
    ]
    bad_open = [s for s in quiet_twins if _blocked(s)]
    bad_closed = [s for s in still_closed if not _blocked(s)]
    bad_incidental = [s for s in still_open if _blocked(s)]
    ok = not bad_open and not bad_closed and not bad_incidental
    return ("HELD" if ok else "BREAK",
            "overblocked=%d lost_closed=%d incidental=%d"
            % (len(bad_open), len(bad_closed), len(bad_incidental)))


# ------------------------------------------------------ P5 honest text


@_t
def test_p5_honest_text():
    honest = [
        'var s=Reflect.construct(String,["hello"]);var RESULT=s+" world";',
        'var o={};Object.setPrototypeOf(o,{role:"admin"});var RESULT=o.role;',
        'var tasks=["done","todo"];tasks.shift();var RESULT=tasks.join(", ");',
        'function t(s,v){return s[0]+v+s[1]}var name="world";var RESULT=t`hello ${name}!`;',
        "var msg='error: something failed';var r=msg;",
    ]
    flagged = [s for s in honest if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/5" % len(flagged))


# ------------------------------------------------------ P6 perf


@_t
def test_p6_perf():
    # Bounded-work smoke check, not a latency SLA: per-call cost is
    # ~23ms in isolation; wall-clock here is contention-sensitive
    # (sibling lanes share the box -- F186 lesson), so the bar is
    # generous. Structural boundedness comes from _js_f96x_charge +
    # _MAX_DECODE_BYTES, not this timer.
    sites = []
    base = 'var s=Reflect.construct(String,["%s"]);var RESULT=s+"tail";'
    for i in range(200):
        sites.append(base % ("ab" * (i % 7 + 1),))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 30 else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------ P7 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g394l4-green-", dir="/var/tmp")
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
        # Wave-394 merge: my closures are flipped to _closed pins -- only
        # the 4 now-closed pins may BREAK there; the merge flips them.
        expected = {"test_r61_f1017_open", "test_r61_f1018_open",
                    "test_r61_f1019_open", "test_r61_f1020_open"}
        ok = set(broken) == expected
        return (("HELD" if ok else "BREAK"),
                "green(w393_attack): broken=%s" % sorted(broken))
    finally:
        pass


@_t
def test_p7_green_check():
    """Depth-1 green check on the round-61 attack battery."""
    return _green_check()


def main():
    fails = []
    held = 0
    for fn in TESTS:
        try:
            verdict, detail = fn()
        except Exception as ex:  # noqa: BLE001
            verdict, detail = "BREAK", "exception: %r" % ex
        print("%s: %s (%s)" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            fails.append(fn.__name__)
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (len(fails), held))
    return 1 if fails else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    sys.exit(main())
