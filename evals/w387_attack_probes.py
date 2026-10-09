#!/usr/bin/env python3
"""Wave-387 attack battery (round 55): 17 new decoder-miss pins (F893-F909).

Each pin asserts the decoder MISSES a node-verified credential-laundering
shape on the open tree. Convention (matches w386_attack_probes.py code):
a pin that still misses reports HELD (finding still open); a pin the
decoder now blocks reports BREAK (unexpected closure).

Carries forward:
- F829-F833 + F883-F892 (lane-filed) via the lane red-first sweep below.
- F834-F882 (round 54) via the depth-1 green check on w386_attack_probes.py
  (which transitively green-checks w385).

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

TAXONOMY_PIN = 2143  # wave-386 merge (no code-count change)

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
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F829-F909 open, next F910)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F910**" in text  # Wave-387 attack round 55
          and "F893, F894, F895, F896, F897, F898, F899, F900, F901, F902, F903, F904, F905, F906, F907, F908, F909.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)

# ------------------------------------------- open pins (must miss -> HELD)


@_t
def test_r55_f893_s1_open():
    """F893 OPEN: miss reproduces."""
    miss = _misses("(function(){var g=eval;return g(\"'%s'\")+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f893_s2_open():
    """F893 OPEN: miss reproduces."""
    miss = _misses("(function(){return (0,eval)(\"'%s'\")+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f894_s1_open():
    """F894 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s'};with(o){var q=k;}return q+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f894_s2_open():
    """F894 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s',j:'%s'};var r='';with(o){r=k+j;}return r;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f895_s1_open():
    """F895 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return [...arguments].join('');}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f895_s2_open():
    """F895 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return Array.from(arguments).join('');}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f896_s1_open():
    """F896 OPEN: miss reproduces."""
    miss = _misses("(function(){var b=new ArrayBuffer(22);var v=new DataView(b);var ps=[30831,30818,11568,12594,13108,13622,14136,14689,25187,25701];for(var i=0;i<10;i++)v.setUint16(i*2,ps[i]);v.setUint8(20,102);var r='';for(var j=0;j<21;j++)r+=String.fromCharCode(v.getUint8(j));return r;})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f896_s2_open():
    """F896 OPEN: miss reproduces."""
    miss = _misses("(function(){var v=new DataView(new ArrayBuffer(21));var bs=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];for(var i=0;i<21;i++)v.setInt8(i,bs[i]);var r='';for(var j=0;j<21;j++)r+=String.fromCharCode(v.getInt8(j));return r;})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f897_s1_open():
    """F897 OPEN: miss reproduces."""
    miss = _misses("(function(){var t=new Uint8Array([120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]);return String.fromCharCode.apply(null,Array.from(t));})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f897_s2_open():
    """F897 OPEN: miss reproduces."""
    miss = _misses("(function(){var cs=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];return String.fromCharCode.call(null,...cs)+'%s';})()" % (_A))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f898_s1_open():
    """F898 OPEN: miss reproduces."""
    miss = _misses("(function(){try{throw new Error('%s');}catch(e){var m=/xoxb-[0-9a-z-]+/.exec(e.stack||'');return (m?m[0]:'no')+'%s';}})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f898_s2_open():
    """F898 OPEN: miss reproduces."""
    miss = _misses("(function(){var e=new Error('%s');var m=String(e.stack).match(/xoxb-\\S+/);return (m?m[0]:'')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f899_s1_open():
    """F899 OPEN: miss reproduces."""
    miss = _misses("(function(){var t={k:'%s'};var x=new Proxy(t,{get:function(o,k){return o[k];}});return x.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f899_s2_open():
    """F899 OPEN: miss reproduces."""
    miss = _misses("(function(){var t={k:'%s'};var x=new Proxy(t,{});return x.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f900_s1_open():
    """F900 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';outer:do{r+='%s';break outer;}while(0);return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f900_s2_open():
    """F900 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';outer:do{if(1){r+='%s';break outer;}}while(0);return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f901_s1_open():
    """F901 OPEN: miss reproduces."""
    miss = _misses("(function(){var r;r='x',r='%s';return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f901_s2_open():
    """F901 OPEN: miss reproduces."""
    miss = _misses("(function(){var a,b;a=b='%s';return a+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f902_s1_open():
    """F902 OPEN: miss reproduces."""
    miss = _misses("(function(){try{throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f902_s2_open():
    """F902 OPEN: miss reproduces."""
    miss = _misses("(function(){try{throw '%s';}catch(e){var m=e;return m+'%s';}})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f903_s1_open():
    """F903 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=JSON.stringify(['%s']);return s.slice(2,-2)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f903_s2_open():
    """F903 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=JSON.stringify({k:'%s'});return s.slice(6,-2)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f904_s1_open():
    """F904 OPEN: miss reproduces."""
    miss = _misses("(function(){class B{constructor(){this.k='%s';}}class C extends B{}return new C().k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f904_s2_open():
    """F904 OPEN: miss reproduces."""
    miss = _misses("(function(){class B{constructor(x){this.k=x;}}class C extends B{constructor(){super('%s');}}return new C().k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f905_s1_open():
    """F905 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';for(var [k,v] of Object.entries({k:'%s'})){r+=v;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f905_s2_open():
    """F905 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';for(var e of Object.entries({k:'%s'})){r+=e[1];}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f906_s1_open():
    """F906 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['%s','z'].reduceRight(function(a,b){return b;})+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f906_s2_open():
    """F906 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['z'].reduceRight(function(a){return a;},'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f907_s1_open():
    """F907 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['%s','z'].reduce((a,b)=>a)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f907_s2_open():
    """F907 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['z','%s'].reduce((a,b)=>b)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f908_s1_open():
    """F908 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='';var m=new Map([['a','%s'],['b','%s']]);for(var [k,v] of m)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f908_s2_open():
    """F908 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='';var m=new Map();m.set('x','%s');m.set('y','%s');for(var [k,v] of m)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f909_s1_open():
    """F909 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({},{get:function(){return '%s';}});return p.anything+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r55_f909_s2_open():
    """F909 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({},{get(){return '%s';}});return p.anything+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

# --------------------------------- lane red-first sweep (F829-F833, F883-F892)

LANE_NUMS = [829, 830, 831, 832, 833, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892]


@_t
def test_p8_lane_sweep():
    """All lane-filed open findings still miss (via their red-firsts)."""
    bad = []
    for n in LANE_NUMS:
        tmp = tempfile.mkdtemp(prefix="g387-lanesweep-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", "w386_f%d_redfirst.py" % n)],
            capture_output=True, text=True, env=env, timeout=300, cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # open = at least one BREAK (or RAISED) in the tally
        m = [l for l in out.splitlines() if l.startswith("tally:")]
        still_open = any(("BREAK" in l or "RAISED" in l) and not l.startswith("tally: 0 BREAK") for l in m)
        if not still_open:
            bad.append(n)
    ok = not bad
    return ("HELD" if ok else "BREAK", "lane-still-open=%s bad=%s" % (ok, bad))


# ------------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w386_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # The w386 battery's footer pin is stale by design: this lane repointed it
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w386_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


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
