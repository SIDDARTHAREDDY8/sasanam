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
    """Control: lane-local footer (F937-F948 carried open; new open F949-F966; next F967)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F967**" in text
          and "F949, F950, F951, F952, F953, F954, F955, F956, F957, F958, F959, F960, F961, F962, F963, F964, F965, F966.**" in text)
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
def test_r58_f949_open():
    """F949 OPEN: top-level packaging misses."""
    miss = _misses("var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f950_open():
    """F950 OPEN: throw/catch misses."""
    miss = _misses("var s='';try{throw '%s';}catch(e){s=e;}finally{s+='%s';}var RESULT=s;" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f951_open():
    """F951 OPEN: Reflect String misses."""
    miss = _misses("var RESULT=Reflect.construct(String,['%s'])+'%s';" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f952_open():
    """F952 OPEN: toReversed apply misses."""
    miss = _misses("var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (_RCODES,))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f953_open():
    """F953 OPEN: switch fallthrough misses."""
    miss = _misses("var s='',i=0;switch(i){case 0:s+='%s';case 1:s+='%s';}var RESULT=s;" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f954_open():
    """F954 OPEN: TextDecoder subarray misses."""
    miss = _misses("var RESULT=new TextDecoder().decode(new Uint8Array([0,%s,0]).subarray(1,22));" % (_CODES,))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f955_open():
    """F955 OPEN: labeled for misses."""
    miss = _misses("var s='';outer:for(var i=0;i<1;i++){s+='%s';for(var j=0;j<1;j++){s+='%s';break outer;}}var RESULT=s;" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f956_open():
    """F956 OPEN: for-in misses."""
    miss = _misses("var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o[k];}var RESULT=s;" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f957_open():
    """F957 OPEN: searchParams misses."""
    miss = _misses("var u=new URL('https://h/?k=%s');var RESULT=u.searchParams.get('k')+'%s';" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f958_open():
    """F958 OPEN: regexp groups misses."""
    miss = _misses("var m='%s|%s'.match(/(.*)\\|(.*)/);var RESULT=m[1]+m[2];" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f959_open():
    """F959 OPEN: promise then misses."""
    miss = _misses("var RESULT=await Promise.resolve('%s').then(a=>a+'%s');" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f960_open():
    """F960 OPEN: WeakMap misses."""
    miss = _misses("var wm=new WeakMap();var k={};wm.set(k,'%s');var RESULT=wm.get(k)+'%s';" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f961_open():
    """F961 OPEN: iterator next misses."""
    miss = _misses("var e=['%s','%s'].entries();var RESULT=e.next().value[1]+e.next().value[1];" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f962_open():
    """F962 OPEN: copyWithin misses."""
    miss = _misses("var a=['p','%s','%s'];a.copyWithin(0,1);var RESULT=a[0]+a[1];" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f963_open():
    """F963 OPEN: fill+map misses."""
    miss = _misses("var RESULT=new Array(2).fill('%s').map((x,i)=>i===0?'%s':x).join('');" % (_B, _A))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f964_open():
    """F964 OPEN: Function params misses."""
    miss = _misses("var f=new Function('p1','p2','return p1+p2;');var RESULT=f('%s','%s');" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f965_open():
    """F965 OPEN: eval template misses."""
    miss = _misses("var RESULT=(function(){var parts=['%s','%s'];return eval('`${parts[0]}${parts[1]}`');})();" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f966_open():
    """F966 OPEN: gen reduce misses."""
    miss = _misses("function*gen(){yield '%s';yield '%s';}var RESULT=[...gen()].reduce((a,b)=>a+b);" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

# --------------------------------------------- rounds 57 + residual carried forward


@_t
def test_r57_f937_charloop_open():
    """F937 OPEN: char-code accumulation loop misses."""
    miss = _misses("(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=String.fromCharCode(c[i]);}return s;})()" % _CODES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f938_fragloop_open():
    """F938 OPEN: string-fragment accumulation loop misses."""
    miss = _misses("(function(){var a=['%s','%s'],s='';for(var i=0;i<a.length;i++){s+=a[i];}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f939_perelmap_open():
    """F939 OPEN: per-element fromCharCode map misses."""
    miss = _misses("(function(){return [%s].map(function(c){return String.fromCharCode(c);}).join('');})()" % _CODES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f940_reducefcc_open():
    """F940 OPEN: reduce with fromCharCode-concat misses."""
    miss = _misses("(function(){return [%s].reduce(function(s,c){return s+String.fromCharCode(c);},'');})()" % _CODES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f941_recursion_open():
    """F941 OPEN: recursion-based assembly misses."""
    miss = _misses("(function(){var c=[%s];function f(i){return i>=c.length?'':String.fromCharCode(c[i])+f(i+1);}return f(0);})()" % _CODES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f942_spreadgen_open():
    """F942 OPEN: spread-iterable fromCharCode misses."""
    miss = _misses("(function(){function* g(){var c=[%s];for(var x of c)yield x;}return String.fromCharCode(...g());})()" % _CODES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f943_anchors_open():
    """F943 OPEN: non-canonical fromCharCode anchor misses."""
    miss = _misses("(function(){return Reflect.apply(String.fromCharCode,null,[%s]);})()" % _CODES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f944_uescape_open():
    """F944 OPEN: code-point escape literal misses."""
    miss = _misses("(function(){return '\\u{78}\\u{6f}\\u{78}\\u{62}-0123456789abcdef';})()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f945_evalloop_open():
    """F945 OPEN: computed-arg eval loop misses."""
    miss = _misses("(function(){var c=[%s],s='';for(var i=0;i<c.length;i++){s+=eval('String.fromCharCode('+c[i]+')');}return s;})()" % _CODES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f946_addcodes_open():
    """F946 OPEN: additive code arguments miss."""
    add = "+".join("String.fromCharCode(%d+%d)" % (ord(c) - 1, 1) for c in _CRED)
    miss = _misses("(function(){return %s;})()" % add)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f947_propasm_open():
    """F947 OPEN: property char assembly misses."""
    props = ",".join("p%d:%s" % (i, repr(c)) for i, c in enumerate(_CRED))
    pread = "+".join("o.p%d" % i for i in range(len(_CRED)))
    miss = _misses("(function(){var o={%s};return %s;})()" % (props, pread))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r57_f948_bracedasi_open():
    """F948 OPEN: F924 braced/ASI residual misses."""
    miss = _misses("(function(){var s='';outer:for(var i=0;i<1;i++){for(var j=0;j<3;j++){if(j===1){continue outer;}s+='%s';}}return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


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
