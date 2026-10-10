#!/usr/bin/env python3
"""Wave-393 lane 2 close battery: F992/F993/F994/F995 CLOSED.

F992 = Error.message reads (attack round 60).
F993 = RegExp.source reads (attack round 60).
F994 = arguments indexed reads (F980 residual).
F995 = rest-parameter indexed reads (attack round 60).

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0); fail-closed bounds stay quiet (miss, never
mis-decode); sibling pins unaffected; honest text quiet; 200-site perf;
depth-1 green check on w392_attack_probes.py (only the 4 now-closed
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

TAXONOMY_PIN = 2143  # wave-392 merge (no code-count change)

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
        # F992
        'var e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";',
        'var e=new Error("xox");var RESULT=e.message+"b-0123456789abcdef0123456789abcdef012";',
        # F993
        'var r=new RegExp("xoxb-0123");var RESULT=r.source+"456789abcdef";',
        'var r=new RegExp("xox");var RESULT=r.source+"b-0123456789abcdef0123456789abcdef012";',
        # F994
        '(function(){var RESULT=arguments[0]+arguments[1];return RESULT;})("xoxb-0123","456789abcdef");',
        '(function(){var RESULT=arguments[0]+arguments[1];return RESULT;})("xox","b-0123456789abcdef0123456789abcdef012");',
        # F995
        '(function(...a){var RESULT=a[0]+a[1];return RESULT;})("xoxb-0123","456789abcdef");',
        '(function(...a){var RESULT=a[0]+a[1];return RESULT;})("xox","b-0123456789abcdef0123456789abcdef012");',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/8" % len(missed))


# ----------------------------------------------------- P2 generalizations


@_t
def test_p2_generalizations():
    # All node-verified v24.20.0; each holds a credential-shaped value.
    shapes = [
        # F992: let, bracket read, no-new, mixed additive
        'let e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";',
        'var e=new Error("xoxb-0123");var RESULT=e["message"]+"456789abcdef";',
        'var e=Error("xoxb-0123");var RESULT=e.message+"456789abcdef";',
        'var e=new Error("xox");var RESULT="xoxb-0123"+e.message+"456789abcdef";',
        # F993: flags ignored by .source, . in charset, bracket read
        'var r=new RegExp("xoxb-0123","gi");var RESULT=r.source+"456789abcdef";',
        'var r=new RegExp("xoxb-0123456789");var RESULT=r.source+".abcdef";',
        'let r=RegExp("xoxb-0123456789");var RESULT=r["source"]+" abcdef";',
        # F994: arg[2] skip, single arg, whitespace in index
        '(function(){var RESULT=arguments[0]+arguments[2];return RESULT;})("xoxb-0123456789","junk","abcdef");',
        '(function(){var RESULT=arguments[0];return RESULT;})("xoxb-0123456789abcdef");',
        '(function(){var RESULT=arguments[ 0 ]+arguments[ 1 ];return RESULT;})("xox","b-0123456789abcdef0123456789abcdef012");',
        # F995: renamed rest, three reads
        '(function(...zz){var RESULT=zz[1]+zz[0];return RESULT;})("abcdef","xoxb-0123456789");',
        '(function(...a){var RESULT=a[0]+a[1]+a[2];return RESULT;})("xoxb-0123","456789","abcdef");',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/12" % len(missed))


# ------------------------------------------------------ P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    # Outside the modeled subset: must stay quiet (miss), never mis-decode.
    quiet_shapes = [
        # F992
        'var e=new Error("ab");var RESULT=e.msg+"cd";',
        'var e=new Error("ab");var RESULT=e.message+"cd";var x=1;',
        'var e=new Error();var RESULT=e.message;',
        # F993
        'var r=new RegExp("a/b");var RESULT=r.source;',
        'var r=new RegExp("");var RESULT=r.source;',
        'var r=new RegExp("a\\nb");var RESULT=r.source;',
        'var r=new RegExp("(ab");var RESULT=r.source;',
        'var r=new RegExp("a*b");var RESULT=r.source;',
        # F994
        '(function(x){var RESULT=arguments[0];return RESULT;})("ab");',
        '(function(){var RESULT=arguments[5];return RESULT;})("ab");',
        '(function(){var RESULT=arguments.length;return RESULT;})("ab");',
        '(function(...a){var RESULT=a[0];return RESULT;})("ab");',
        # F995
        '(function(...a){var RESULT=a[9];return RESULT;})("a");',
        '(function(...arguments){var RESULT=arguments[0];return RESULT;})("a");',
        '(function(){var RESULT=arguments[0];return RESULT;})("ab");',
        # Spec-review hard findings (wave-393): Annex-B octal escapes fail
        # closed (no mis-decode); unicode-digit indices fail closed (no crash).
        'var e=new Error("\\101");var RESULT=e.message;',
        '(function(){var RESULT=arguments[0];return RESULT;})("\\101");',
        '(function(){var RESULT=arguments[\u00b2];return RESULT;})("ab");',
    ]
    flagged = [s for s in quiet_shapes if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/18" % len(flagged))


# ------------------------------------------------------ P4 sibling pins


@_t
def test_p4_sibling_pins():
    # Disjointness from the nearest closed/open neighbors. Quiet twins
    # (credential-free) must stay quiet; already-CLOSED siblings (wave-392)
    # must stay blocked -- my hooks must neither over-block nor steal
    # their productions.
    quiet_twins = [
        'var e=new Error("hello");var RESULT=e.message;',
        '(function(){var RESULT=arguments[0];return RESULT;})("hello");',
    ]
    still_closed = [
        # F980 CLOSED: arguments spread into fromCharCode (r60 pin shape)
        "var RESULT=(function(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51)+'456789abcdef';",
        # F981 CLOSED: pop accumulation (F938 residual)
        "var q=['456789abcdef','xoxb-0123'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;",
    ]
    bad_open = [s for s in quiet_twins if _blocked(s)]
    bad_closed = [s for s in still_closed if not _blocked(s)]
    ok = not bad_open and not bad_closed
    return ("HELD" if ok else "BREAK",
            "overblocked=%d lost_closed=%d" % (len(bad_open), len(bad_closed)))


# ------------------------------------------------------ P5 honest text


@_t
def test_p5_honest_text():
    honest = [
        'var e=new Error("hello world");var RESULT=e.message;',
        'var r=new RegExp("abc");var RESULT=r.source;',
        '(function(){var RESULT=arguments[0];return RESULT;})("hello");',
        '(function(...a){var RESULT=a[0];return RESULT;})("hi");',
        "var msg='error: something failed';var r=msg;",
    ]
    flagged = [s for s in honest if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/5" % len(flagged))


# ------------------------------------------------------ P6 perf


@_t
def test_p6_perf():
    sites = []
    base = 'var e=new Error("%s");var RESULT=e.message+"tail";'
    for i in range(200):
        sites.append(base % ("ab" * (i % 7 + 1),))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 10 else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------ P7 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g393l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w392_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, target],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        lines = (r.stdout or "").strip().split("\n")
        broken = []
        for ln in lines[:-1]:
            if ": BREAK" in ln:
                broken.append(ln.split(":")[0])
        # Wave-393 merge: my closures are flipped to _closed pins -- none may
        # BREAK there; the flipped pins must be present.
        names = set(ln.split(":")[0] for ln in lines[:-1])
        expected_closed = {"test_r60_f992_closed", "test_r60_f993_closed",
                    "test_r60_f994_closed", "test_r60_f995_closed"}
        ok = set(broken) == set() and expected_closed <= names
        return (("HELD" if ok else "BREAK"),
                "green(w392_attack): broken=%s" % sorted(broken))
    finally:
        pass


@_t
def test_p7_green_check():
    """Depth-1 green check on the round-60 attack battery."""
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
