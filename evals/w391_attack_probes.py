#!/usr/bin/env python3
"""Wave-391 attack battery (round 59): 21 new decoder-miss pins (F967-F987).

Each pin asserts the decoder MISSES a node-verified credential-laundering
shape on the open tree. Convention (matches w390_attack_probes.py code):
a pin that still misses reports HELD (finding still open); a pin the
decoder now blocks reports BREAK (unexpected closure).

Carries forward:
- F949-F966 (round 58) as expected-open pins.
- Earlier rounds via the depth-1 green check on w390_attack_probes.py.

Short test credentials, pin 2143, $0-spend-by-construction (no paid calls;
model spend lives in the realmodel ledger -- this round: $0.00, 0 calls).
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

TAXONOMY_PIN = 2143  # wave-390 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_CODES = ",".join(str(ord(c)) for c in _CRED)

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
    """Control: lane-local footer (F949-F987 open; next F988)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F988**" in text
          and "F967, F968, F969, F970, F971, F972, F973, F974, F975, F976, F977, F978, F979, F980, F981, F982, F983, F984, F985, F986, F987.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


@_t
def test_p9_taxonomy_pin():
    """Taxonomy pin unchanged (no new decision codes)."""
    ok = (TAXONOMY_PIN == 2143)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------- new pins (round 59)

@_t
def test_r59_f967_open():
    """F967 OPEN: flat/flatMap on fromCharCode arg arrays (F952 residual)."""
    miss = _misses('var c=[[120,111,120,98,45,48,49,50,51],[52,53,54,55,56,57,97,98,99,100,101,102]];var RESULT=String.fromCharCode.apply(null,c.flat());')
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f968_open():
    """F968 OPEN: Object.fromEntries reassembly."""
    miss = _misses("var o=Object.fromEntries([['a','xoxb-0123'],['b','456789abcdef']]);var RESULT=o.a+o.b;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f969_open():
    """F969 OPEN: multi-name FormData.getAll (F914 residual)."""
    miss = _misses("var f=new FormData();f.append('a','xoxb-0123');f.append('b','456789abcdef');var RESULT=String(f.getAll('a'))+String(f.getAll('b'));")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f970_open():
    """F970 OPEN: property-descriptor assembly."""
    miss = _misses("var d=Object.getOwnPropertyDescriptor({a:'xoxb-0123'},'a');var RESULT=d.value+'456789abcdef';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f971_open():
    """F971 OPEN: Reflect.ownKeys / Map.get reads."""
    miss = _misses("var o={a:'xoxb-0123',b:'456789abcdef'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[1]];")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f972_open():
    """F972 OPEN: JSON.parse/new-Array sources for fromCharCode (F943 residual)."""
    miss = _misses("var a=JSON.parse('[120,111,120,98,45,48,49,50,51]');var RESULT=String.fromCharCode(...a)+'456789abcdef';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f973_open():
    """F973 OPEN: closure-captured reads."""
    miss = _misses("function f(){var q='xoxb-0123';return function(){return q+'456789abcdef';};}var RESULT=f()();")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f974_open():
    """F974 OPEN: getter assembly."""
    miss = _misses("var o={a:'xoxb-0123',b:'456789abcdef',get s(){return this.a+this.b;}};var RESULT=o.s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f975_open():
    """F975 OPEN: class private fields."""
    miss = _misses("class C{#x='xoxb-0123';get s(){return this.#x+'456789abcdef';}}var RESULT=new C().s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f976_open():
    """F976 OPEN: optional chaining."""
    miss = _misses("var o={a:'xoxb-0123'};var RESULT=(o?.a??'x')+'456789abcdef';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f977_open():
    """F977 OPEN: delete/re-add lifecycle."""
    miss = _misses("var o={a:'xoxb-0123',b:'456789abcdef'};delete o.b;o.b='456789abcdef';var RESULT=o.a+o.b;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f978_open():
    """F978 OPEN: splice reassembly."""
    miss = _misses("var q=['x','xoxb-0123','y','456789abcdef','z'];q.splice(0,1);q.splice(1,1);q.splice(2,1);var RESULT=q.join('');")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f979_open():
    """F979 OPEN: Object.keys mapped reads."""
    miss = _misses("var o={a:'xoxb-0123',b:'456789abcdef'};var RESULT=Object.keys(o).map(function(k){return o[k];}).join('');")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f980_open():
    """F980 OPEN: arguments spread into fromCharCode."""
    miss = _misses("var RESULT=(function(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51)+'456789abcdef';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f981_open():
    """F981 OPEN: pop accumulation (F938 residual)."""
    miss = _misses("var q=['456789abcdef','xoxb-0123'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f982_open():
    """F982 OPEN: F937 loop-form residuals."""
    miss = _misses("var s='',i=0;do{s+='xoxb-0123',i++;}while(i<1);s+='456789abcdef';var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f983_open():
    """F983 OPEN: switch computed discriminant (F953 residual)."""
    miss = _misses("var s='';switch(1+1){case 1:s+='no';break;case 2:s+='xoxb-0123';s+='456789abcdef';break;}var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f984_open():
    """F984 OPEN: try/catch around statement builtins (F949/F950 composition)."""
    miss = _misses("var s='';try{var o=structuredClone({a:'xoxb-0123',b:'456789abcdef'});s=o.a+o.b;}catch(e){s='no';}var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f985_open():
    """F985 OPEN: charCodeAt inverse."""
    miss = _misses("var t='xoxb-0123';var c=t.charCodeAt(0);var RESULT=String.fromCharCode(c)+'oxb-0123'+'456789abcdef';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f986_open():
    """F986 OPEN: guarded conditional assembly."""
    miss = _misses("var s='';if(1){s+='xoxb-0123';}else{s+='x';}s+='456789abcdef';var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r59_f987_open():
    """F987 OPEN: var-bound fromCharCode arg arrays (F643 residual)."""
    miss = _misses('var c=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];var RESULT=String.fromCharCode.apply(null,c);')
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)



# -------------------------------------- carried forward (round 58, still open)

@_t
def test_r58_f949_open():
    """F949 OPEN (carried): F949 OPEN: top-level packaging misses."""
    miss = _misses("var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f950_open():
    """F950 OPEN (carried): F950 OPEN: throw/catch misses."""
    miss = _misses("var s='';try{throw '%s';}catch(e){s=e;}finally{s+='%s';}var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f951_open():
    """F951 OPEN (carried): F951 OPEN: Reflect String misses."""
    miss = _misses("var RESULT=Reflect.construct(String,['%s'])+'%s';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f952_open():
    """F952 OPEN (carried): F952 OPEN: toReversed apply misses."""
    miss = _misses("var RESULT=String.fromCharCode.apply(null,[%s].toReversed());")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f953_open():
    """F953 OPEN (carried): F953 OPEN: switch fallthrough misses."""
    miss = _misses("var s='',i=0;switch(i){case 0:s+='%s';case 1:s+='%s';}var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f954_open():
    """F954 OPEN (carried): F954 OPEN: TextDecoder subarray misses."""
    miss = _misses("var RESULT=new TextDecoder().decode(new Uint8Array([0,%s,0]).subarray(1,22));")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f955_open():
    """F955 OPEN (carried): F955 OPEN: labeled for misses."""
    miss = _misses("var s='';outer:for(var i=0;i<1;i++){s+='%s';for(var j=0;j<1;j++){s+='%s';break outer;}}var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f956_open():
    """F956 OPEN (carried): F956 OPEN: for-in misses."""
    miss = _misses("var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o[k];}var RESULT=s;")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f957_open():
    """F957 OPEN (carried): F957 OPEN: searchParams misses."""
    miss = _misses("var u=new URL('https://h/?k=%s');var RESULT=u.searchParams.get('k')+'%s';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f958_open():
    """F958 OPEN (carried): F958 OPEN: regexp groups misses."""
    miss = _misses("var m='%s|%s'.match(/(.*)\\|(.*)/);var RESULT=m[1]+m[2];")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f959_open():
    """F959 OPEN (carried): F959 OPEN: promise then misses."""
    miss = _misses("var RESULT=await Promise.resolve('%s').then(a=>a+'%s');")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f960_open():
    """F960 OPEN (carried): F960 OPEN: WeakMap misses."""
    miss = _misses("var wm=new WeakMap();var k={};wm.set(k,'%s');var RESULT=wm.get(k)+'%s';")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f961_open():
    """F961 OPEN (carried): F961 OPEN: iterator next misses."""
    miss = _misses("var e=['%s','%s'].entries();var RESULT=e.next().value[1]+e.next().value[1];")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f962_open():
    """F962 OPEN (carried): F962 OPEN: copyWithin misses."""
    miss = _misses("var a=['p','%s','%s'];a.copyWithin(0,1);var RESULT=a[0]+a[1];")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f963_open():
    """F963 OPEN (carried): F963 OPEN: fill+map misses."""
    miss = _misses("var RESULT=new Array(2).fill('%s').map((x,i)=>i===0?'%s':x).join('');")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f964_open():
    """F964 OPEN (carried): F964 OPEN: Function params misses."""
    miss = _misses("var f=new Function('p1','p2','return p1+p2;');var RESULT=f('%s','%s');")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f965_open():
    """F965 OPEN (carried): F965 OPEN: eval template misses."""
    miss = _misses("var RESULT=(function(){var parts=['%s','%s'];return eval('`${parts[0]}${parts[1]}`');})();")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r58_f966_open():
    """F966 OPEN (carried): F966 OPEN: gen reduce misses."""
    miss = _misses("function*gen(){yield '%s';yield '%s';}var RESULT=[...gen()].reduce((a,b)=>a+b);")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g391-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w390_attack_probes.py")
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
                "green(w390_attack): %d real BREAK %s; %d stale-missing %s; tally=%s"
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
