#!/usr/bin/env python3
"""Wave-425 attack round 93 coverage battery: new F1715-F1724 pins (MISS) +
carry-forward F1703, F1705-F1714 pins (MISS) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
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

SECRET_S = "xoxb-01" + "23456789abcdef"
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


def _codes_bare(s):
    return ",".join(str(ord(c)) for c in s)


# New round-93 pins: (name, template) — must MISS on open tree
_NEW = [
    ("f1715", "var C={I};var D=C.reduceRight(function(a,c){return [c].concat(a);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1716", "var C={I};var E=C.entries();var D=[];for(var [i,c] of E){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1717", "var C={I};var O=Object.assign({},C);var D=[];for(var [k,v] of Object.entries(O)){D.push(Number(v));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1718", "var C={I};var D=[];D.push.apply(D,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1719", "var C={I};var D=Array.from(C,function(c){return c;},undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1720", "var C={I};var T=C.join(undefined);var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1721", "var C={I};var D=[C];var E=D.flat(Infinity);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1722", "var C={I};var D=structuredClone(C,{transfer:[]});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1723", "var C={I};var T=[];C.findLast(function(c){T.unshift(c);return false;});var S=String.fromCharCode.apply(null,T);var RESULT=S;"),
    ("f1724", "var C={I};var D=C.filter(function(c,i,a){return a[i]===c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Carry-forward pins (must still MISS except F1703-partial): F1705-F1714
# F1703 is OPEN (partial): wave-424 lane D fixed the statement-decoder paths,
# so the statement shape now HITs (asserted as HIT-OK in _CARRY_HIT below);
# the remaining expression-route gap is covered by the F1714 pin.
_CARRY_MISS = [
    # F1705-F1713: round-92 shapes
    ("F1705", "var C={I};var D=Object.assign([],C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1706", "var C={I};var S=String.fromCharCode.apply(null,C);var T=`${S}`;var RESULT=T;"),
    ("F1707", "var C={I};var D=[C];var E=D.flat(C.length-C.length+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1708", "var C={I};var D=C.flatMap(function(c){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1709", "var C={I};var D=C.map(function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1710", "var C={I};var D=Array.from(C,function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1711", "var C={I};var D=[...C,];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1712", "var C={I};var D=C.slice();D.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1713", "var C={I};var D=C.reduce(function(a,c){return a.concat([c]);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1714: renumbered lane-D residual — direct apply with surrogate prefix
    ("F1714", "var C=[55296,{CODES}];var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
]

# F1703-partial: statement-decoder shape must now HIT (partial fix verified)
_CARRY_HIT = [
    ("F1703-partial", "var C=[55296,{CODES}];var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


def main():
    held = 0
    total = 0
    # p1: new pins must MISS (both sizes)
    h1 = t1 = 0
    for name, tmpl in _NEW:
        for secret in (SECRET_S, SECRET_L):
            t1 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "MISS":
                h1 += 1
            else:
                print("FAIL new %s: got %s" % (name, v))
    print("p1 new pins: %d/%d HELD" % (h1, t1))
    held += h1
    total += t1
    # p2: carry-forward MISS pins (both sizes)
    h2 = t2 = 0
    for name, tmpl in _CARRY_MISS:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            if "{CODES}" in tmpl:
                payload = tmpl.replace("{CODES}", _codes_bare(secret))
            else:
                payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            if v == "MISS":
                h2 += 1
            else:
                print("FAIL carry %s: got %s" % (name, v))
    print("p2 carry pins: %d/%d HELD" % (h2, t2))
    held += h2
    total += t2
    # p2b: F1703-partial HIT pins (both sizes) — statement path fixed
    h2b = t2b = 0
    for name, tmpl in _CARRY_HIT:
        for secret in (SECRET_S, SECRET_L):
            t2b += 1
            payload = tmpl.replace("{CODES}", _codes_bare(secret))
            v = _scan(payload)
            if v == "HIT":
                h2b += 1
            else:
                print("FAIL partial %s: got %s" % (name, v))
    print("p2b partial-hit pins: %d/%d HELD" % (h2b, t2b))
    held += h2b
    total += t2b
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
    if "# Wave-425 attack round 93:" in ftxt and "next free F1725" in ftxt:
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
    for num in range(1715, 1725):
        t5 += 1
        btxt = open(os.path.join(REPO_ROOT, "evals", "w425_f%d_redfirst.py" % num)).read()
        if not any(b in btxt for b in bad):
            h5 += 1
        else:
            print("FAIL paid-machinery f%d" % num)
    print("p5 no-paid: %d/%d HELD" % (h5, t5))
    held += h5
    total += t5
    print("TOTAL: %d/%d HELD" % (held, total))
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
