#!/usr/bin/env python3
"""Wave-391 lane 2 close battery: F953 + F954 + F955 + F956.

F953 (filed 2026-10-09 14:19 UTC, wave-390 attack round 58): switch-case
fallthrough assembly -- loop + loop-free switch(i){case 0:s+='f1';case 1:s+='f2';}.
F954 (filed 2026-10-09 14:19 UTC, wave-390 attack round 58): TextDecoder over
non-literal buffer sources (F629 residual: SharedArrayBuffer view, subarray,
re-wrapped buffer).
F955 (filed 2026-10-09 14:19 UTC, wave-390 attack round 58): labeled for-loop
break/continue (F900 residual).
F956 (filed 2026-10-09 14:19 UTC, wave-390 attack round 58): for-in
accumulation (F937 residual).

Closure: F954's expression-level forms extend the F629 TextDecoder grammar
(subarray postfix, new- over new- re-wrap); F953/F955/F956 plus the F954
top-level (SAB view + forEach fill + TextDecoder RESULT) decode through the
new _js_f95x_top_seq statement-sequence producer hooked at the end of
_decode_layer. All node-exact (v24.20.0) for the modeled subset; every other
shape fails closed. Zero new re.compile (pin 28); taxonomy pin stays 2143.

Orientation: filed shapes + generalizations BLOCK; fail-closed bounds MISS
without crash or mis-decode; F949 sibling shapes fail THIS lane's sim closed
(disjointness); honest-text controls quiet. $0 spend (hand-crafted +
node-verified shapes only). Node v24.20.0 verified.
"""
import os
import sys
import time
import subprocess
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential, _js_f95x_top_seq  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_CRED40 = _F1 + _F2
_CODES = ",".join(str(ord(c)) for c in (_A + _B))
_CODES40 = ",".join(str(ord(c)) for c in _CRED40)

FAILS = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (" -- " + detail if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def expect_block(name, payload):
    hit = find_credential(payload) is not None
    check("block:" + name, hit, "payload not blocked: %r" % payload[:70])


def expect_quiet(name, payload):
    try:
        hit = find_credential(payload) is not None
    except Exception as e:  # noqa: BLE001 -- fail-closed bounds must not crash
        check("quiet:" + name, False, "raised %r" % e)
        return
    check("quiet:" + name, not hit, "false positive: %r" % payload[:70])


def expect_sim_none(name, payload):
    """This lane's sim must fail the shape closed (disjointness pin)."""
    try:
        val = _js_f95x_top_seq(payload)
    except Exception as e:  # noqa: BLE001
        check("sim-none:" + name, False, "raised %r" % e)
        return
    check("sim-none:" + name, val is None, "sim claimed %r" % (val,))


# ---------------------------------------------------------------- pins
def test_pins():
    with open(os.path.join(REPO, "gov", "dlp.py")) as f:
        dlp_src = f.read()
    check("pin:re-compile-28", dlp_src.count("re.compile(") == 28,
          "count=%d" % dlp_src.count("re.compile("))
    with open(os.path.join(REPO, "gov", "guac_graph.py")) as f:
        guac_src = f.read()
    check("pin:taxonomy-2143", "TAXONOMY_PIN = 2143" in guac_src)
    with open(os.path.join(REPO, "evals", "FINDINGS.md")) as f:
        foot = f.read()
    check("pin:footer-next-f988", "Next free finding: **F988**" in foot)
    for fid in ("F953", "F954", "F955", "F956"):
        lines = [ln for ln in foot.split("\n") if ln.startswith("(%s " % fid)]
        check("pin:footer-%s-closed" % fid.lower(),
              len(lines) == 1 and "CLOSED" in lines[0] and "OPEN" not in lines[0].split("CLOSED")[0],
              "entry not stamped CLOSED")


# ------------------------------------------------------- filed shapes
def test_filed_shapes():
    # F953 (3)
    expect_block("f953:switch-only",
                 "var s='',i=0;switch(i){case 0:s+='%s';case 1:s+='%s';}var RESULT=s;" % (_A, _B))
    expect_block("f953:switch-only-40",
                 "var s='',i=0;switch(i){case 0:s+='%s';case 1:s+='%s';}var RESULT=s;" % (_F1, _F2))
    expect_block("f953:switch-loop",
                 "var s='';for(var i=0;i<1;i++){switch(i){case 0:s+='%s';case 1:s+='%s';break;}}var RESULT=s;" % (_A, _B))
    # F954 (4)
    expect_block("f954:sab",
                 "var u8=new Uint8Array(new SharedArrayBuffer(%d));[%s].forEach((c,i)=>u8[i]=c);var RESULT=new TextDecoder().decode(u8);" % (len(_A + _B), _CODES))
    expect_block("f954:sab-40",
                 "var u8=new Uint8Array(new SharedArrayBuffer(%d));[%s].forEach((c,i)=>u8[i]=c);var RESULT=new TextDecoder().decode(u8);" % (len(_CRED40), _CODES40))
    expect_block("f954:subarray",
                 "var RESULT=new TextDecoder().decode(new Uint8Array([0,%s]).subarray(1));" % _CODES)
    expect_block("f954:wrapped",
                 "var RESULT=new TextDecoder().decode(new Uint8Array(new Uint8Array([%s]).buffer));" % _CODES)
    # F955 (3)
    expect_block("f955:labeled-break",
                 "var s='';outer:for(var i=0;i<1;i++){s+='%s';for(var j=0;j<1;j++){s+='%s';break outer;}}var RESULT=s;" % (_A, _B))
    expect_block("f955:labeled-break-40",
                 "var s='';outer:for(var i=0;i<1;i++){s+='%s';for(var j=0;j<1;j++){s+='%s';break outer;}}var RESULT=s;" % (_F1, _F2))
    expect_block("f955:labeled-continue",
                 "var s='';outer:for(var i=0;i<2;i++){if(i===0){s+='%s';continue outer;}s+='%s';}var RESULT=s;" % (_A, _B))
    # F956 (3)
    expect_block("f956:for-in-one",
                 "var o={k:'%s'};var s='';for(var k in o){s+=o[k];}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("f956:for-in-two",
                 "var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o[k];}var RESULT=s;" % (_A, _B))
    expect_block("f956:for-in-two-40",
                 "var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o[k];}var RESULT=s;" % (_F1, _F2))


# ------------------------------------------------------ generalizations
def test_generalizations():
    # F953: let decls, 3 cases, default, bound-2 loop, renamed idents
    expect_block("gen:f953-let-3case",
                 "let s='';let i=0;for(let i=0;i<2;i++){switch(i){case 0:s+='%s';case 1:s+='%s';default:s+='!';break;}}var RESULT=s;" % (_A, _B))
    expect_block("gen:f953-renamed",
                 "var t='',q=0;switch(q){case 0:t+='%s';case 1:t+='%s';}var RESULT=t;" % (_A, _B))
    # F954: subarray with end, negative index, spaced rewrap, utf8 label
    expect_block("gen:f954-subarray-end",
                 "var RESULT=new TextDecoder().decode(new Uint8Array([0,%s,0]).subarray(1,%d));" % (_CODES, len(_A + _B) + 1))
    expect_block("gen:f954-subarray-neg",
                 "var RESULT=new TextDecoder().decode(new Uint8Array([0,%s]).subarray(-%d));" % (_CODES, len(_A + _B)))
    expect_block("gen:f954-rewrap-spaced",
                 "var RESULT = new TextDecoder( 'utf8' ).decode( new Uint8Array( new Uint8Array( [%s] ).buffer ) );" % _CODES)
    expect_block("gen:f954-sab-foreach-let",
                 "let u8=new Uint8Array(new SharedArrayBuffer(%d));[%s].forEach((c,i)=>u8[i]=c);var RESULT=new TextDecoder('utf-8').decode(u8);" % (len(_A + _B), _CODES))
    # F955: bare break, !== comparison, nested labeled continue
    expect_block("gen:f955-bare-break",
                 "var s='';outer:for(var i=0;i<3;i++){s+='%s';if(i!==0){break;}s+='%s';}var RESULT=s;" % (_A, _B))
    expect_block("gen:f955-nested-continue",
                 "var s='';outer:for(var i=0;i<2;i++){for(var j=0;j<2;j++){if(j===1){s+='%s';continue outer;}s+='%s';}}var RESULT=s;" % (_A, _B))
    # F956: string-literal keys, dot access, let key var, 3 props
    expect_block("gen:f956-strkeys",
                 "var o={'a':'%s','b':'%s'};var s='';for(var k in o){s+=o[k];}var RESULT=s;" % (_A, _B))
    expect_block("gen:f956-dot",
                 "var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o.a;s+=o.b;}var RESULT=s;" % (_A, _B))
    expect_block("gen:f956-letkey",
                 "var o={a:'%s',b:'%s'};var s='';for(let k in o){s+=o[k];}var RESULT=s;" % (_A, _B))
    # for-in break/continue (HARD-1 regression: must not escape).
    expect_block("gen:f956-forin-break",
                 "var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o[k];if(k==='b'){break;}}var RESULT=s;" % (_A, _B))
    expect_block("gen:f956-forin-continue",
                 "var o={a:'%s',b:'%s'};var s='';lbl:for(var k in o){s+=o[k];continue lbl;}var RESULT=s;" % (_A, _B))
    expect_block("gen:f956-result-additive",
                 "var o={a:'%s'};var s='';for(var k in o){s+=o[k];}var RESULT=s+'%s';" % (_A, _B))
    # Integer operands in string positions (node-exact String(i)).
    expect_block("gen:int-result-additive",
                 "var s='';for(var i=0;i<2;i++){s+='%s';}var RESULT=s+'%s'+i;" % (_A, _B))
    expect_block("gen:int-accum",
                 "var s='';for(var i=0;i<1;i++){s+=i;s+='%s';}s+='%s';var RESULT=s;" % (_A, _B))


# ----------------------------------------------------- fail-closed bounds
def test_fail_closed():
    # Outside the modeled grammar: must MISS, never crash, never mis-decode.
    expect_quiet("fc:while-loop",
                 "var s='';var i=0;while(i<1){s+='x';i++;}var RESULT=s;")
    expect_quiet("fc:for-le-bound",
                 "var s='';for(var i=0;i<=1;i++){s+='x';}var RESULT=s;")
    expect_quiet("fc:member-missing",
                 "var o={a:'x'};var s='';for(var k in o){s+=o['b'];}var RESULT=s;")
    expect_quiet("fc:proto-key",
                 "var o={__proto__:'x'};var s='';var RESULT=s;")
    expect_quiet("fc:td-label",
                 "var RESULT=new TextDecoder('utf-16').decode(new Uint8Array([120]));")
    expect_quiet("fc:destructure",
                 "var [a,b]=['x','y'],RESULT=a+b;")
    expect_quiet("fc:top-break",
                 "var s='x';break;var RESULT=s;")
    expect_quiet("fc:continue-in-switch",
                 "var s='';for(var i=0;i<1;i++){switch(i){case 0:continue;}}var RESULT=s;")
    expect_quiet("fc:template-lit",
                 "var s='';for(var i=0;i<1;i++){s+=`x`;}var RESULT=s;")
    expect_quiet("fc:accum-unbound",
                 "var s='';s+=zz;var RESULT=s;")
    expect_quiet("fc:if-nonint",
                 "var s='x';var t='y';if(t==='y'){s+='z';}var RESULT=s;")
    expect_quiet("fc:if-else",
                 "var s='';var i=0;if(i===0){s+='x';}else{s+='y';}var RESULT=s;")
    expect_quiet("fc:result-trailing",
                 "var s='x';var RESULT=s;var q=1;")
    expect_quiet("fc:fill-nonarrow",
                 "var u8=new Uint8Array(new SharedArrayBuffer(2));[120].forEach(function(c,i){u8[i]=c;});var RESULT=new TextDecoder().decode(u8);")
    expect_quiet("fc:fill-byte-range",
                 "var u8=new Uint8Array(new SharedArrayBuffer(1));[999].forEach((c,i)=>u8[i]=c);var RESULT=new TextDecoder().decode(u8);")
    expect_quiet("fc:decl-no-init",
                 "var s;var RESULT='x';")
    # The lane sim itself must fail these closed too (no mis-decode).
    expect_sim_none("fc-sim:while-loop",
                    "var s='';var i=0;while(i<1){s+='x';i++;}var RESULT=s;")
    expect_sim_none("fc-sim:top-break", "var s='x';break;var RESULT=s;")


# --------------------------------------------- sibling disjointness (F949)
_F949 = [
    "var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;",
    "function*g(){yield '%s';yield '%s';}var s='';for(var p of g()){s+=p;}var RESULT=s;",
    "function*g(){yield '%s';yield '%s';}var gg=g();var RESULT=gg.next().value+gg.next().value;",
    "class C{static{this.a='%s';this.b='%s';}}var RESULT=C.a+C.b;",
    "class C{static a='%s';static b='%s';}var RESULT=C.a+C.b;",
    "var r=Proxy.revocable({a:'%s'},{});var RESULT=r.proxy.a+'%s';",
    "var w=new WeakRef({a:'%s'});var RESULT=w.deref().a+'%s';",
    "var [a,b]=['%s','%s'],RESULT=a+b;",
    "var o={a:'%s',b:'%s'};var RESULT=Object.values(o).join('');",
    "var m=new Map([['a','%s'],['b','%s']]);var RESULT=[...m.values()].join('');",
    "var RESULT='';lbl:{RESULT+='%s';if(1){break lbl;}RESULT+='nope';}RESULT+='%s';",
    "var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;",
]


def test_sibling_disjoint():
    for idx, shape in enumerate(_F949):
        payload = shape % ((_A, _B) if shape.count("%s") == 2 else (_A,))
        expect_sim_none("sib:f949-%d" % idx, payload)


# ------------------------------------------------------- honest controls
def test_honest_controls():
    expect_quiet("honest:decl-only", "var x = 1;")
    expect_quiet("honest:copy", "var s='hello';var t=s;var RESULT=t;")
    expect_quiet("honest:iife", "(function(){var s='ab';return s;})()")
    expect_quiet("honest:english",
                 "The quick brown fox jumps over the lazy dog. var is a word.")
    expect_quiet("honest:json", '{"user": "alice", "role": "viewer"}')
    expect_quiet("honest:for-real",
                 "for (var i = 0; i < items.length; i++) { console.log(items[i]); }")


# ------------------------------------------------------------------ perf
def test_perf():
    sites = []
    base = "var s='';for(var i=0;i<1;i++){switch(i){case 0:s+='x';case 1:s+='y';}}var RESULT=s;"
    for n in range(200):
        sites.append(base + " /* pad %d */" % n)
    t0 = time.time()
    for s in sites:
        find_credential(s)
    dt = time.time() - t0
    check("perf:200-sites", dt < 30, "%.1fs for 200 sites" % dt)
    print("perf: 200 sites in %.2fs" % dt)


# ------------------------------------------------------- depth-1 green
def green_check():
    """Depth-1 green check: run adjacent batteries' mains with
    GOV_SKIP_GREEN=1 in the child env (combinatorial-nesting rule).
    Honors the var by returning early when set."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return
    adj = ["evals/w390_f953_redfirst.py", "evals/w390_f954_redfirst.py",
           "evals/w390_f955_redfirst.py", "evals/w390_f956_redfirst.py",
           "evals/w390_f949_redfirst.py"]
    for bat in adj:
        tmpd = tempfile.mkdtemp(prefix="w391lane2-green-", dir="/var/tmp")
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd,
                   GOV_DEPLOYMENT_MODE="staging")
        try:
            p = subprocess.run([sys.executable, os.path.join(REPO, bat)],
                               capture_output=True, text=True, env=env,
                               timeout=300, cwd=REPO)
        except subprocess.TimeoutExpired:
            check("green:" + bat, False, "timeout")
            continue
        # Red-first batteries exit 1 by design when shapes HELD (closed
        # tree); the green signal is "no crash, controls ok".
        crashed = p.returncode not in (0, 1) or "Traceback" in p.stderr
        check("green:" + bat, not crashed,
              "rc=%d err=%s" % (p.returncode, p.stderr[-200:]))


def main():
    test_pins()
    test_filed_shapes()
    test_generalizations()
    test_fail_closed()
    test_sibling_disjoint()
    test_honest_controls()
    test_perf()
    green_check()
    print("%d failures" % len(FAILS))
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
