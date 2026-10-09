#!/usr/bin/env python3
"""Wave-388 attack battery (round 56): 16 new decoder-miss pins (F921-F936).

Each pin asserts the decoder MISSES a node-verified credential-laundering
shape on the open tree. Convention (matches w387_attack_probes.py code):
a pin that still misses reports HELD (finding still open); a pin the
decoder now blocks reports BREAK (unexpected closure).

Carries forward:
- F893-F920 (round 55) via the depth-1 green check on w387_attack_probes.py
  (which transitively green-checks w386).

Research-mapped carriers: F935 = Barracuda 2026-10-07 dual-target zero-width
steganography class; F936 = Lumen 2026-10-07 PoeLLM adversarial-poetry class.

Short test credentials, pin 2143, $0-spend-by-construction (model spend logged
separately in the realmodel ledger).
"""

import argparse
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-387 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY

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


# ---------------------------------------------------------------- controls


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F893-F936 open, next F937)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F937**" in text  # Wave-388 attack round 56
          and "F893, F894, F895, F896, F897, F898, F899, F900, F901, F902, F903, F904, F905, F906, F907, F908, F909, F910, F911, F912, F913, F914, F915, F916, F917, F918, F919, F920, F921, F922, F923, F924, F925, F926, F927, F928, F929, F930, F931, F932, F933, F934, F935, F936.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("(chr(39)+chr(40)+chr(102)+chr(117)+chr(110)+chr(99)+chr(116)+chr(105)+chr(111)+chr(110)+chr(41)+chr(123)+chr(125)+chr(41)+chr(40)+chr(41)")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


@_t
def test_p9_taxonomy_pin():
    """Taxonomy pin unchanged (no new decision codes this round)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return ("HELD" if ok else "BREAK", "codes=%d" % len(TAXONOMY))


# ------------------------------------------------------- round-56 pins


@_t
def test_r56_f921_bind_open():
    """F921 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(a,b){return a+b;}var g=f.bind(null,'%s');return g('%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f922_switch_open():
    """F922 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='';var x=1;switch(x){case 1:s+='%s';case 2:s+='%s';break;default:}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f923_qqnull_open():
    """F923 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=null;s??='%s';s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f924_lblcont_open():
    """F924 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='';outer:for(var i=0;i<1;i++){for(var j=0;j<3;j++){if(j===1)continue outer;s+='%s';}}return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f925_super_open():
    """F925 OPEN: miss reproduces."""
    miss = _misses("(function(){var proto={x:'%s'};var o={m(){return super.x+'%s';}};Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f926_extends_open():
    """F926 OPEN: miss reproduces."""
    miss = _misses("(function(){var B=class{};class C extends B{constructor(){super();this.v='%s';}}return new C().v+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f927_chainassign_open():
    """F927 OPEN: miss reproduces."""
    miss = _misses("(function(){var a,b;a=b='%s';return a+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f928_comma_open():
    """F928 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=(0,'%s');return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f929_inop_open():
    """F929 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={v:'%s'};return ('v' in o)?o.v+'%s':'';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f930_symiter_open():
    """F930 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={};o[Symbol.iterator]=function*(){yield '%s';yield '%s';};var s='';for(var v of o)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f931_errmsg_open():
    """F931 OPEN: miss reproduces."""
    miss = _misses("(function(){var e=new Error('x');e.message='%s';return e.message+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f932_valueof_open():
    """F932 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=new String('%s');return s.valueOf()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f933_forofstr_open():
    """F933 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='';for(var c of '%s')s+=c;return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f934_async_open():
    """F934 OPEN: miss reproduces."""
    miss = _misses("(function(){async function f(){return '%s';}return f().then(function(v){return v+'%s';});})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f935_zwsp_open():
    """F935 OPEN: miss reproduces."""
    miss = _misses("(function(){return 'xox\\\\u200bb-0123456789abcdef'.replace(/[\\\\u200b-\\\\u200d\\\\ufeff]/g,'');})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r56_f936_poem_open():
    """F936 OPEN: miss reproduces."""
    miss = _misses("(function(){var poem='xray\\noscar\\nxerox\\nbravo\\n-dash-\\n0 days\\n1 day\\n2 days\\n3 days\\n4 days\\n5 days\\n6 days\\n7 days\\n8 days\\n9 days\\nalpha\\nbeta\\ncharlie\\ndelta\\necho\\nfoxtrot';var s='';var lines=poem.split('\\n');for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g388-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w387_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    broke = set()
    for line in out.splitlines():
        if ": BREAK" in line:
            broke.add(line.split(":")[0])
    # Known-stale pins in the w387 battery (pre-existing on the wave-387 base;
    # the wave-387 merge re-pinned w386_attack_probes.py but not w387_attack_probes.py):
    # - test_b0_footer_state: this lane repointed the footer (wave-305/306 class)
    # - test_p8_lane_sweep: sweeps F829-F892 red-firsts, closed by wave-387 lanes
    # - test_r55_f902_s1_open / f906_s2 / f907_s1: those exact shapes are now
    #   blocked (incidental wave-387 closure-lane coverage); each finding stays
    #   OPEN via its other red-first shapes (verified: F902 s2, F906 s1, F907 s2
    #   still BREAK on this tree).
    stale = {"test_b0_footer_state", "test_p8_lane_sweep",
             "test_r55_f902_s1_open", "test_r55_f906_s2_open",
             "test_r55_f907_s1_open"}
    real = broke - stale
    missing = stale - broke
    ok = not real and not missing
    return ("HELD" if ok else "BREAK",
            "green(w387_attack): %d real BREAK %s; %d stale-missing %s"
            % (len(real), sorted(real), len(missing), sorted(missing)))


@_t
def test_p9_green_check():
    """Depth-1 green check on the prior round's battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        verdict, note = fn()
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
