#!/usr/bin/env python3
"""Wave-390 attack battery (round 58): 18 new decoder-miss pins (F949-F966).

Each pin asserts the decoder MISSES a node-verified credential-laundering
shape on the open tree. Convention (matches w389_attack_probes.py code):
a pin that still misses reports HELD (finding still open); a pin the
decoder now blocks reports BREAK (unexpected closure).

Carries forward:
- F937-F948 (rounds 57 + lane-1 residual) as expected-open pins.
- Earlier rounds via the depth-1 green check on w389_attack_probes.py.

Short test credentials, pin 2143, $0-spend-by-construction (model spend logged
separately in the realmodel ledger: 1 gpt-4o-mini brainstorm call ~$0.000311
+ 1 cost-probe call $0.000003).
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

TAXONOMY_PIN = 2143  # wave-389 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_CODES = ",".join(str(ord(c)) for c in _CRED)
_RCODES = ",".join(str(ord(c)) for c in _CRED[::-1])
_C1 = ",".join(str(ord(c)) for c in _CRED[1:])

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
    ok = ("Next free finding: **F1005**" in text
          and "F967-F974 CLOSED (8" in text
          and "F988-F1003 OPEN (16" in text)
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


# ------------------------------------------------------- round-58 pins


@_t
def test_r58_f949_closed():
    """F949 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f950_closed():
    """F950 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var s='';try{throw '%s';}catch(e){s=e;}finally{s+='%s';}var RESULT=s;" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f951_closed():
    """F951 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var RESULT=Reflect.construct(String,['%s'])+'%s';" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f952_closed():
    """F952 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (_RCODES,))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f953_closed():
    """F953 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var s='',i=0;switch(i){case 0:s+='%s';case 1:s+='%s';}var RESULT=s;" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f954_closed():
    """F954 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var RESULT=new TextDecoder().decode(new Uint8Array([0,%s,0]).subarray(1,22));" % (_CODES,))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f955_closed():
    """F955 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var s='';outer:for(var i=0;i<1;i++){s+='%s';for(var j=0;j<1;j++){s+='%s';break outer;}}var RESULT=s;" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f956_closed():
    """F956 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o[k];}var RESULT=s;" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f957_closed():
    """F957 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var u=new URL('https://h/?k=%s');var RESULT=u.searchParams.get('k')+'%s';" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f958_closed():
    """F958 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var m='%s|%s'.match(/(.*)\\|(.*)/);var RESULT=m[1]+m[2];" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f959_closed():
    """F959 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var RESULT=await Promise.resolve('%s').then(a=>a+'%s');" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f960_closed():
    """F960 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var wm=new WeakMap();var k={};wm.set(k,'%s');var RESULT=wm.get(k)+'%s';" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f961_closed():
    """F961 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var e=['%s','%s'].entries();var RESULT=e.next().value[1]+e.next().value[1];" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f962_closed():
    """F962 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var a=['p','%s','%s'];a.copyWithin(0,1);var RESULT=a[0]+a[1];" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f963_closed():
    """F963 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var RESULT=new Array(2).fill('%s').map((x,i)=>i===0?'%s':x).join('');" % (_B, _A))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f964_closed():
    """F964 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var f=new Function('p1','p2','return p1+p2;');var RESULT=f('%s','%s');" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f965_closed():
    """F965 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("var RESULT=(function(){var parts=['%s','%s'];return eval('`${parts[0]}${parts[1]}`');})();" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r58_f966_closed():
    """F966 CLOSED (wave-391 merge): now blocked."""
    miss = _misses("function*gen(){yield '%s';yield '%s';}var RESULT=[...gen()].reduce((a,b)=>a+b);" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))

# --------------------------------------------- rounds 57 + residual carried forward


@_t
def test_r57_f937_charloop_closed():
    """F937 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=String.fromCharCode(c[i]);}return s;})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f938_fragloop_closed():
    """F938 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var a=['%s','%s'],s='';for(var i=0;i<a.length;i++){s+=a[i];}return s;})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f939_perelmap_closed():
    """F939 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return [%s].map(function(c){return String.fromCharCode(c);}).join('');})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f940_reducefcc_closed():
    """F940 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return [%s].reduce(function(s,c){return s+String.fromCharCode(c);},'');})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f941_recursion_closed():
    """F941 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var c=[%s];function f(i){return i>=c.length?'':String.fromCharCode(c[i])+f(i+1);}return f(0);})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f942_spreadgen_closed():
    """F942 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){function* g(){var c=[%s];for(var x of c)yield x;}return String.fromCharCode(...g());})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f943_anchors_closed():
    """F943 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return Reflect.apply(String.fromCharCode,null,[%s]);})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f944_uescape_closed():
    """F944 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){return '\\u{78}\\u{6f}\\u{78}\\u{62}-0123456789abcdef';})()")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f945_evalloop_closed():
    """F945 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=eval('String.fromCharCode('+c[i]+')');}return s;})()" % _CODES)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f946_addcodes_closed():
    """F946 CLOSED (wave-390 merge): now blocked."""
    add = "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1) for c in _CRED)
    miss = _misses("(function(){return %s;})()" % add)
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f947_propasm_closed():
    """F947 CLOSED (wave-390 merge): now blocked."""
    props = ",".join("p%d:%s" % (i, repr(c)) for i, c in enumerate(_CRED))
    pread = "+".join("o.p%d" % i for i in range(len(_CRED)))
    miss = _misses("(function(){var o={%s};return %s;})()" % (props, pread))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r57_f948_bracedasi_closed():
    """F948 CLOSED (wave-390 merge): now blocked."""
    miss = _misses("(function(){var s='';outer:for(var i=0;i<1;i++){for(var j=0;j<3;j++){if(j===1){continue outer;}s+='%s';}}return s+'%s';})()" % (_A, _B))
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


# ------------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g390-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w389_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, target, "--tally-only"],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        lines = (r.stdout or "").strip().split("\n")
        tally = lines[-1] if lines else ""
        real, missing = [], []
        for ln in lines[:-1]:
            if ": BREAK" in ln:
                real.append(ln.split(":")[0])
            elif "stale" in ln.lower():
                missing.append(ln.split(":")[0])
        ok = (r.returncode == 0)
        return (("HELD" if ok else "BREAK"),
                "green(w389_attack): %d real BREAK %s; %d stale-missing %s; tally=%s"
                % (len(real), sorted(real), len(missing), sorted(missing), tally))
    finally:
        pass


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
