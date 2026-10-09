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
    """Control: merged footer (F949-F987 closed; open F988-F1003, F1004; next F1005)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F1005**" in text  # Wave-392 merge
          and "F967-F974 CLOSED (8" in text
          and "F988-F1003 OPEN (16" in text
          and "F937-F948 CLOSED (12)" in text)
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
def test_r56_f921_bind_closed():
    """F921 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){function f(a,b){return a+b;}var g=f.bind(null,'%s');return g('%s');})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f922_switch_closed():
    """F922 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s='';var x=1;switch(x){case 1:s+='%s';case 2:s+='%s';break;default:}return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f923_qqnull_closed():
    """F923 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s=null;s??='%s';s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f924_lblcont_closed():
    """F924 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s='';outer:for(var i=0;i<1;i++){for(var j=0;j<3;j++){if(j===1)continue outer;s+='%s';}}return s+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f925_super_closed():
    """F925 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var proto={x:'%s'};var o={m(){return super.x+'%s';}};Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f926_extends_closed():
    """F926 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var B=class{};class C extends B{constructor(){super();this.v='%s';}}return new C().v+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f927_chainassign_closed():
    """F927 CLOSED (wave-388 merge, incidental: F901's chained-assignment closure covers it)."""
    miss = _misses("(function(){var a,b;a=b='%s';return a+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f928_comma_closed():
    """F928 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s=(0,'%s');return s+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f929_inop_closed():
    """F929 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var o={v:'%s'};return ('v' in o)?o.v+'%s':'';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f930_symiter_closed():
    """F930 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var o={};o[Symbol.iterator]=function*(){yield '%s';yield '%s';};var s='';for(var v of o)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f931_errmsg_closed():
    """F931 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var e=new Error('x');e.message='%s';return e.message+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f932_valueof_closed():
    """F932 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s=new String('%s');return s.valueOf()+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f933_forofstr_closed():
    """F933 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var s='';for(var c of '%s')s+=c;return s+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f934_async_closed():
    """F934 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){async function f(){return '%s';}return f().then(function(v){return v+'%s';});})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f935_zwsp_closed():
    """F935 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){return 'xox\\\\u200bb-0123456789abcdef'.replace(/[\\\\u200b-\\\\u200d\\\\ufeff]/g,'');})()")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

@_t
def test_r56_f936_poem_closed():
    """F936 CLOSED (wave-389 merge): now blocked."""
    miss = _misses("(function(){var poem='xray\\noscar\\nxerox\\nbravo\\n-dash-\\n0 days\\n1 day\\n2 days\\n3 days\\n4 days\\n5 days\\n6 days\\n7 days\\n8 days\\n9 days\\nalpha\\nbeta\\ncharlie\\ndelta\\necho\\nfoxtrot';var s='';var lines=poem.split('\\n');for(var i=0;i<lines.length;i++){s+=lines[i][0];}return s;})()")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


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
    # The w387 battery was fully re-pinned at the wave-388 merge
    # (F893-F909 closed-hit pins, footer + lane-sweep updated) --
    # it must now report 0 BREAKs; no stale set remains.
    stale = set()
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
