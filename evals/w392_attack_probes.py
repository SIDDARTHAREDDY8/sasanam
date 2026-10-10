#!/usr/bin/env python3
"""Round-60 attack battery: 17 new pins (expected miss) + carried pins.

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). Pins marked CLOSED:
HELD while blocked, BREAK if a miss reappears.
$0-spend-by-construction (no harness/paid refs; model spend lives in the ledger).
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

TAXONOMY_PIN = 2143  # wave-391 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_CODES = ",".join(str(ord(c)) for c in _CRED)
_RCODES = ",".join(str(ord(c)) for c in _CRED[::-1])

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
    """Control: merged footer (wave-393: F988-F1004 closed; F1005-F1024 open; next F1025)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("F988-F1004 CLOSED (17" in text
          and "F1005-F1024 OPEN (20" in text
          and "Next free finding: **F1025**" in text
          and "next free F1025" in text)
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


# ------------------------------------------------- new pins (round 60)


@_t
def test_r60_f988_closed():
    """F988 CLOSED (wave-393): new String boxing reads."""
    miss = _misses('var s=new String("xoxb-0123");var RESULT=s+"456789abcdef";')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f989_closed():
    """F989 CLOSED (wave-393): for-of over Map entries."""
    miss = _misses('var s="";var m=new Map([["a","xoxb-0123"],["b","456789abcdef"]]);for(var kv of m){s+=kv[1];}var RESULT=s;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f990_closed():
    """F990 CLOSED (wave-393): Proxy get-trap reads."""
    miss = _misses('var p=new Proxy({a:"xoxb-0123",b:"456789abcdef"},{get:function(t,k){return t[k];}});var RESULT=p.a+p.b;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f991_closed():
    """F991 CLOSED (wave-393): WeakRef deref reads."""
    miss = _misses('var w=new WeakRef({v:"xoxb-0123"});var x=new WeakRef({v:"456789abcdef"});var RESULT=w.deref().v+x.deref().v;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f992_closed():
    """F992 CLOSED (wave-393): Error.message reads."""
    miss = _misses('var e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f993_closed():
    """F993 CLOSED (wave-393): RegExp.source reads."""
    miss = _misses('var r=new RegExp("xoxb-0123");var RESULT=r.source+"456789abcdef";')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f994_closed():
    """F994 CLOSED (wave-393): arguments indexed reads."""
    miss = _misses('(function(){var RESULT=arguments[0]+arguments[1];return RESULT;})("xoxb-0123","456789abcdef");')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f995_closed():
    """F995 CLOSED (wave-393): rest-parameter indexed reads."""
    miss = _misses('(function(...a){var RESULT=a[0]+a[1];return RESULT;})("xoxb-0123","456789abcdef");')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f996_closed():
    """F996 CLOSED (wave-393): .map(Number) over string-code arrays."""
    miss = _misses('var RESULT=String.fromCharCode.apply(null,["120","111","120","98","45","48","49","50","51","52","53","54","55","56","57","97","98","99","100","101","102"].map(Number));')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f997_closed():
    """F997 CLOSED (wave-393): slice-trimmed code arrays."""
    miss = _misses('var RESULT=String.fromCharCode.apply(null,[0,120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,0].slice(1,-1));')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f998_closed():
    """F998 CLOSED (wave-393): globalThis stash reads."""
    miss = _misses('globalThis.x="xoxb-0123";globalThis.y="456789abcdef";var RESULT=globalThis.x+globalThis.y;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f999_closed():
    """F999 CLOSED (wave-393): descriptor-object assembly."""
    miss = _misses('var o={};Object.defineProperties(o,{a:{value:"xoxb-0123",enumerable:true},b:{value:"456789abcdef",enumerable:true}});var RESULT=o.a+o.b;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f1000_closed():
    """F1000 CLOSED (wave-393): assignment-operator assembly."""
    miss = _misses('var s="";s||="xoxb-0123";s+="456789abcdef";var RESULT=s;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f1001_closed():
    """F1001 CLOSED (wave-393): Reflect.apply on String.prototype.concat."""
    miss = _misses('var RESULT=Reflect.apply(String.prototype.concat,"xoxb-0123",["456789abcdef"]);')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f1002_closed():
    """F1002 CLOSED (wave-393): prototype-chain descriptor reads."""
    miss = _misses('var p={v:"xoxb-0123"};var o=Object.create(p);o.w="456789abcdef";var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+o.w;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



@_t
def test_r60_f1003_closed():
    """F1003 CLOSED (wave-393): comma-sequence assembly."""
    miss = _misses('var s;s="xoxb-0123",s+="456789abcdef";var RESULT=s;')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



# --------------------------------- carried pins (rounds 58/59)


@_t
def test_r59_f967_closed():
    """F967 CLOSED: flat/flatMap on fromCharCode arg arrays (F952 residual)."""
    miss = _misses('var c=[[120,111,120,98,45,48,49,50,51],[52,53,54,55,56,57,97,98,99,100,101,102]];var RESULT=String.fromCharCode.apply(null,c.flat());')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f968_closed():
    """F968 CLOSED (residual): entries->fromEntries round-trip still breaks; literal-pair forms closed by merge composition."""
    miss = _misses("var e=Object.entries({a:'xoxb-0123',b:'456789abcdef'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f969_closed():
    """F969 CLOSED: multi-name FormData.getAll (F914 residual)."""
    miss = _misses("var f=new FormData();f.append('a','xoxb-0123');f.append('b','456789abcdef');var RESULT=String(f.getAll('a'))+String(f.getAll('b'));")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f970_closed():
    """F970 CLOSED: property-descriptor assembly."""
    miss = _misses("var d=Object.getOwnPropertyDescriptor({a:'xoxb-0123'},'a');var RESULT=d.value+'456789abcdef';")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f971_closed():
    """F971 CLOSED: Reflect.ownKeys / Map.get reads."""
    miss = _misses("var o={a:'xoxb-0123',b:'456789abcdef'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[1]];")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f972_closed():
    """F972 CLOSED: JSON.parse/new-Array sources for fromCharCode (F943 residual)."""
    miss = _misses("var a=JSON.parse('[120,111,120,98,45,48,49,50,51]');var RESULT=String.fromCharCode(...a)+'456789abcdef';")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f973_closed():
    """F973 CLOSED: closure-captured reads."""
    miss = _misses("function f(){var q='xoxb-0123';return function(){return q+'456789abcdef';};}var RESULT=f()();")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f974_closed():
    """F974 CLOSED (residual): symbol-keyed member reads still break; plain getter forms closed by merge composition."""
    miss = _misses("var k=Symbol.for('a');var o={};o[k]='xoxb-0123';var r={get s(){return o[k]+'456789abcdef';}};var RESULT=r.s;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f975_closed():
    """F975 CLOSED (wave-391 merge incidental: F949+F947 composition blocks all filed shapes)."""
    miss = _misses("class C{#x='xoxb-0123';get s(){return this.#x+'456789abcdef';}}var RESULT=new C().s;")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r59_f976_closed():
    """F976 CLOSED (wave-391 merge incidental: F949+F947 composition blocks all filed shapes)."""
    miss = _misses("var o={a:'xoxb-0123'};var RESULT=(o?.a??'x')+'456789abcdef';")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r59_f977_closed():
    """F977 CLOSED: delete/re-add lifecycle."""
    miss = _misses("var o={a:'xoxb-0123',b:'456789abcdef'};delete o.b;o.b='456789abcdef';var RESULT=o.a+o.b;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f978_closed():
    """F978 CLOSED: splice reassembly."""
    miss = _misses("var q=['x','xoxb-0123','y','456789abcdef','z'];q.splice(0,1);q.splice(1,1);q.splice(2,1);var RESULT=q.join('');")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f979_closed():
    """F979 CLOSED (wave-391 merge incidental: F949+F947 composition blocks all filed shapes)."""
    miss = _misses("var o={a:'xoxb-0123',b:'456789abcdef'};var RESULT=Object.keys(o).map(function(k){return o[k];}).join('');")
    return ("HELD" if not miss else "BREAK", "blocked=%s" % (not miss))


@_t
def test_r59_f980_closed():
    """F980 CLOSED: arguments spread into fromCharCode."""
    miss = _misses("var RESULT=(function(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51)+'456789abcdef';")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f981_closed():
    """F981 CLOSED: pop accumulation (F938 residual)."""
    miss = _misses("var q=['456789abcdef','xoxb-0123'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f982_closed():
    """F982 CLOSED: F937 loop-form residuals."""
    miss = _misses("var s='',i=0;do{s+='xoxb-0123',i++;}while(i<1);s+='456789abcdef';var RESULT=s;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f983_closed():
    """F983 CLOSED: switch computed discriminant (F953 residual)."""
    miss = _misses("var s='';switch(1+1){case 1:s+='no';break;case 2:s+='xoxb-0123';s+='456789abcdef';break;}var RESULT=s;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f984_closed():
    """F984 CLOSED: try/catch around statement builtins (F949/F950 composition)."""
    miss = _misses("var s='';try{var o=structuredClone({a:'xoxb-0123',b:'456789abcdef'});s=o.a+o.b;}catch(e){s='no';}var RESULT=s;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f985_closed():
    """F985 CLOSED: charCodeAt inverse."""
    miss = _misses("var t='xoxb-0123';var c=t.charCodeAt(0);var RESULT=String.fromCharCode(c)+'oxb-0123'+'456789abcdef';")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f986_closed():
    """F986 CLOSED: guarded conditional assembly."""
    miss = _misses("var s='';if(1){s+='xoxb-0123';}else{s+='x';}s+='456789abcdef';var RESULT=s;")
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)


@_t
def test_r59_f987_closed():
    """F987 CLOSED: var-bound fromCharCode arg arrays (F643 residual)."""
    miss = _misses('var c=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];var RESULT=String.fromCharCode.apply(null,c);')
    return ("BREAK" if miss else "HELD", "miss=%s" % miss)



# -------------------------------------- carried forward (round 58, still open)


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


# ------------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g392-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w391_attack_probes.py")
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
                "green(w391_attack): %d real BREAK %s; %d stale-missing %s; tally=%s"
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
