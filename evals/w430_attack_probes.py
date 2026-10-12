#!/usr/bin/env python3
"""Wave-430 attack round 98 coverage battery (UPDATED wave-431 merge): F1782-F1801 pins now HIT (CLOSED wave-431) +
F1768-F1781 carry-forward pins now HIT (CLOSED wave-431) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: p1/p2 scanner pins were verified empirically by the 20 red-first
batteries (evals/w430_f1782_redfirst.py .. f1801: 20/20 HELD per
~/workspace/teams/wave430-attack/run_batteries98.log) during the round;
this battery pins the templates for merge-gate coverage.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-" + "0123456789abcde"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


# New round-98 pins: (name, template) — MISS on open tree
_NEW = [
    ("f1782", "var C={I};var D=[C.slice(0,10),C.slice(10)].flat();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1783", "var C={I};var D=C.slice(undefined,undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1784", "var C={I};var D=C.concat(C).slice(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1785", "var C={I};var D=[];C.forEach(function(c){D.push(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1786", "var C={I};var D=[];for(var c of C){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1787", "var C={I};var D=Array.from(C.keys()).map(function(i){return C[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1788", "var C={I};var D=Array.from(C.entries()).map(function(e){return e[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1789", "var C={I};var it=C[Symbol.iterator]();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1790", "var C={I};function*g(){yield*C;}var D=Array.from(g());var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1791", "var C={I};var D=Array.from(C.values().map(function(c){return c;}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1792", "var C={I};var D=Array.from(C.values().filter(function(){return true;}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1793", "var C={I};var D=new Array(C.length);for(var i=0;i<C.length;i++){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1794", "var C={I};var D=[];for(var i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1795", "var C={I};var D=Array.from(Object.create(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1796", "var C={I};var W=new WeakMap();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1797", "var C={I};var R=new WeakRef(C);var D=R.deref();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1798", "var C={I};var D=Array.from(new Uint16Array(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1799", "var C={I};var D=Array.from(new Float64Array(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1800", "var C={I};var R=function(){var r={};for(var i=0;i<C.length;i++){r[i]=C[i];}r.length=C.length;return r;}();var S=String.fromCharCode.apply(null,R);var RESULT=S;"),
    ("f1801", "var C={I};var D=C.slice();var t=D[0];D[0]=D[D.length-1];D[D.length-1]=t;var u=D[0];D[0]=D[D.length-1];D[D.length-1]=u;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Carry-forward OPEN pins (F1768-F1781 attack 97) — must still MISS
_CARRY = [
    ("F1768", "var C={I};var D=new Array(...C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1769", "var C={I};var [...D]=C;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1770", "var C={I};var D=C.slice(0).reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1771", "var C={I};var D=C.toSorted(function(){return 0;}).toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1772", "var C={I};var D=C.with(C.length-C.length,C[C.length-C.length]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1773", "var C={I};var D=C.slice();D.splice(D.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1774", "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('');"),
    ("F1775", "var C={I};var it=C.values();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1776", "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1777", "var C={I};Promise.resolve(C).then(function(c){var S=String.fromCharCode.apply(null,c);var RESULT=S;});"),
    ("F1778", "var C={I};var D;var S=(D=C,String.fromCharCode.apply(null,D));var RESULT=S;"),
    ("F1779", "var C={I};var D;D??=C;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1780", "var C={I};var D=C||[];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1781", "var C={I};var D=[];while(C.length){D.push(C.shift());}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


def main():
    held = 0
    total = 0
    # p1: new pins must HIT (CLOSED wave-431) (both sizes)
    h1 = t1 = 0
    for name, tmpl in _NEW:
        for secret in (SECRET_S, SECRET_L):
            t1 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "HIT":
                h1 += 1
            else:
                print("FAIL new %s: got %s" % (name, v))
    print("p1 new pins: %d/%d HELD" % (h1, t1))
    held += h1
    total += t1
    # p2: carry-forward pins must HIT (CLOSED wave-431) (both sizes)
    h2 = t2 = 0
    for name, tmpl in _CARRY:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "HIT":
                h2 += 1
            else:
                print("FAIL carry %s: got %s" % (name, v))
    print("p2 carry pins: %d/%d HELD" % (h2, t2))
    held += h2
    total += t2
    # p3: taxonomy pin 2143 in gov/guac_graph.py
    t3 = 1
    h3 = 0
    gtxt = open(os.path.join(REPO_ROOT, "gov", "guac_graph.py")).read()
    m = re.search(r"TAXONOMY_PIN\s*=\s*(\d+)", gtxt)
    if m and m.group(1) == "2143":
        h3 = 1
    else:
        print("FAIL taxonomy pin")
    print("p3 taxonomy: %d/%d HELD" % (h3, t3))
    held += h3
    total += t3
    # p4: footer
    t4 = 1
    h4 = 0
    ftxt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "# Wave-430 attack round 98:" in ftxt and "next free F1802" in ftxt:
        h4 = 1
    else:
        print("FAIL footer")
    print("p4 footer: %d/%d HELD" % (h4, t4))
    held += h4
    total += t4
    # p5: no paid machinery in new batteries
    bad = ["realmodel_harness", "ModelDriver", "openai"]
    t5 = 0
    h5 = 0
    for num in range(1782, 1802):
        t5 += 1
        btxt = open(os.path.join(REPO_ROOT, "evals", "w430_f%d_redfirst.py" % num)).read()
        if not any(b in btxt for b in bad):
            h5 += 1
        else:
            print("FAIL paid-machinery f%d" % num)
    print("p5 no-paid: %d/%d HELD" % (h5, t5))
    held += h5
    total += t5
    # p6: footer-vs-stamp — F1782-F1801 all OPEN
    t6 = 0
    h6 = 0
    for num in range(1782, 1802):
        t6 += 1
        idx = ftxt.find("(F%d filed" % num)
        if idx >= 0 and "LOW, OPEN" in ftxt[idx:idx+4000]:
            h6 += 1
        else:
            print("FAIL stamp f%d" % num)
    print("p6 stamps: %d/%d HELD" % (h6, t6))
    held += h6
    total += t6
    print("TOTAL: %d/%d HELD" % (held, total))
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
