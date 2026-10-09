#!/usr/bin/env python3
"""Wave-392 lane 4 close battery: F982 + F983 + F984 + F985.

F982 (filed 2026-10-09 16:02 UTC, wave-391 attack round 59): F937
loop-form residuals -- a do-while with comma-sequence body
(`do{s+='f1',i++;}while(i<1)`) and the `for(;;){...;break;}`
infinite-loop form miss node-exactly.
F983 (filed 2026-10-09 16:02 UTC, wave-391 attack round 59): switch
with computed discriminant (F953 residual) -- `switch(1+1)` with
break-terminated computed cases misses node-exactly.
F984 (filed 2026-10-09 16:02 UTC, wave-391 attack round 59):
try/catch around statement-scope builtins (F949/F950 composition)
-- wrapping structuredClone / generator drains in try/catch misses.
F985 (filed 2026-10-09 16:02 UTC, wave-391 attack round 59):
charCodeAt inverse reassembly -- reading char codes back out of
fragment literals via charCodeAt and rebuilding with fromCharCode.

Closure: F982 adds do-while (`do{}while(IDX</<=LIT)`, bounded) and
`for(;;)` (break-terminated, capped) sims plus comma-sequence
expression statements to the F95x top-level grammar; F983 extends
the switch discriminant to integer arithmetic (IEEE-754 exact,
safe-integer gated); F984 adds `try{}catch(){}` (never-throws
guarded) with `var` decls, structuredClone inits, generator decls
and for-of drains; F985 adds charCodeAt int inits/operands,
String.fromCharCode operands, `STR.length` loop bounds and the
charCodeAt-identity drain fast path. All node-exact (v24.20.0) for
the modeled subset; every other shape fails closed. Zero new
re.compile (pin 28); taxonomy pin stays 2143.

Orientation: filed shapes + generalizations BLOCK; fail-closed
bounds stay QUIET without crash or mis-decode; sibling
productions (F953 literal switch, F937 loops, F679 try/catch)
unaffected. $0 spend (hand-crafted + node-verified shapes only).
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
    for fid in ("F982", "F983", "F984", "F985"):
        lines = [ln for ln in foot.split("\n") if ln.startswith("(%s " % fid)]
        check("pin:footer-%s-closed" % fid.lower(),
              len(lines) == 1 and "[CLOSED" in lines[0],
              "entry not stamped CLOSED")


# ------------------------------------------------------- filed shapes
def test_filed_shapes():
    # F982 (3)
    expect_block("f982:comma",
                 "var s='',i=0;do{s+='%s',i++;}while(i<1);s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("f982:comma-40",
                 "var s='',i=0;do{s+='%s',i++;}while(i<1);s+='%s';var RESULT=s;" % (_F1, _F2))
    expect_block("f982:forever",
                 "var s='';for(;;){s+='%s';break;}s+='%s';var RESULT=s;" % (_A, _B))
    # F983 (2)
    expect_block("f983:sw",
                 "var s='';switch(1+1){case 1:s+='no';break;case 2:s+='%s';s+='%s';break;}var RESULT=s;" % (_A, _B))
    expect_block("f983:sw-40",
                 "var s='';switch(1+1){case 1:s+='no';break;case 2:s+='%s';s+='%s';break;}var RESULT=s;" % (_F1, _F2))
    # F984 (3)
    expect_block("f984:try",
                 "var s='';try{var o=structuredClone({a:'%s',b:'%s'});s=o.a+o.b;}catch(e){s='no';}var RESULT=s;" % (_A, _B))
    expect_block("f984:try-40",
                 "var s='';try{var o=structuredClone({a:'%s',b:'%s'});s=o.a+o.b;}catch(e){s='no';}var RESULT=s;" % (_F1, _F2))
    expect_block("f984:trygen",
                 "var s='';try{function*g(){yield '%s';yield '%s';}for(var p of g()){s+=p;}}catch(e){s='no';}var RESULT=s;" % (_A, _B))
    # F985 (2)
    expect_block("f985:cca",
                 "var t='%s';var c=t.charCodeAt(0);var RESULT=String.fromCharCode(c)+'oxb-0123'+'%s';" % (_A, _B))
    expect_block("f985:cca-40",
                 "var t1='%s',t2='%s';var s='';for(var i=0;i<t1.length;i++){s+=String.fromCharCode(t1.charCodeAt(i));}"
                 "for(var j=0;j<t2.length;j++){s+=String.fromCharCode(t2.charCodeAt(j));}var RESULT=s;" % (_F1, _F2))


# ------------------------------------------------------- generalizations
def test_generalizations():
    # F982: <= cond, prefix ++, labeled do-while, nested loop, labeled for(;;)
    expect_block("gen:f982-le",
                 "var s='',i=0;do{s+='%s',i++;}while(i<=1);s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f982-prefix",
                 "var s='',i=0;do{s+='%s',++i;}while(i<1);s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f982-labeled",
                 "var s='',i=0;L:do{s+='%s';i++;if(i>5){break L;}}while(i<1);s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f982-nested",
                 "var s='',i=0;do{for(var k=0;k<1;k++){s+='%s';}i++;}while(i<1);s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f982-forever-labeled",
                 "var s='';L:for(;;){s+='%s';break L;}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f982-forever-cont",
                 "var s='',i=0;for(;;){i++;if(i<2){continue;}s+='%s';break;}s+='%s';var RESULT=s;" % (_A, _B))
    # F983: precedence, hex, parens, negative, pow, mod, default-fallthrough
    expect_block("gen:f983-prec",
                 "var s='';switch(1+2*3){case 7:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-hex",
                 "var s='';switch(0x1+0x1){case 2:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-paren",
                 "var s='';switch((1+1)*2){case 4:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-neg",
                 "var s='';switch(0-5){case -5:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-pow",
                 "var s='';switch(2**3){case 8:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-mod",
                 "var s='';switch(7%%3){case 1:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-default",
                 "var s='';switch(1+1){case 3:s+='no';break;default:s+='%s';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-modneg",
                 "var s='';switch(-7%%3){case -1:s+='%s';break;case 2:s+='no';break;}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-modneg2",
                 "var s='';switch(7%%-3){case 1:s+='%s';break;case -1:s+='no';break;}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-casearith",
                 "var s='';switch(2){case 1+1:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f983-spaced-unary",
                 "var s='';switch(1- -1){case 2:s+='%s';break;default:s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f982-ws-update",
                 "var s='',i=0;do{s+='%s',i++ ;}while(i<1);s+='%s';var RESULT=s;" % (_A, _B))
    # F984: nested try, for inside try, 3-yield drain, additive accum in try
    expect_block("gen:f984-nested",
                 "var s='';try{try{var o=structuredClone({a:'%s'});s+=o.a;}catch(x){s+='no';}}catch(e){s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f984-for",
                 "var s='';try{for(var i=0;i<1;i++){s+='%s';}}catch(e){s+='no';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("gen:f984-3yield",
                 "var s='';try{function*g(){yield '%s';yield '%s';yield '!';}for(var p of g()){s+=p;}}catch(e){s='no';}var RESULT=s;" % (_A, _B))
    expect_block("gen:f984-additive",
                 "var s='';try{var o=structuredClone({a:'%s',b:'%s'});s=o.a+o.b+'!';}catch(e){s='no';}var RESULT=s;" % (_A, _B))
    # F985: small-bound generic path, s=s+ twin drain, literal args, bound-index charCodeAt
    expect_block("gen:f985-small",
                 "var t2='abcdef';var s='';for(var i=0;i<2;i++){s+=String.fromCharCode(t2.charCodeAt(i));}var RESULT=s+'%s'+'%s';" % (_A, _B))
    expect_block("gen:f985-twin",
                 "var t2='%s%s';var s='';for(var i=0;i<t2.length;i++){s=s+String.fromCharCode(t2.charCodeAt(i));}var RESULT=s;" % (_A, _B))
    expect_block("gen:f985-litarg",
                 "var RESULT=String.fromCharCode(%s);" % _CODES)
    expect_block("gen:f985-ccaexpr",
                 "var t='%s';var i=0;var c=t.charCodeAt(i);var RESULT=String.fromCharCode(c)+'oxb-0123'+'%s';" % (_A, _B))


# ------------------------------------------------------- fail-closed
def test_fail_closed():
    # F982: unmodeled conds, break-less for(;;) (must terminate fast), unbound index
    expect_quiet("fc:f982-gt-cond",
                 "var s='',i=2;do{s+='aa',i--;}while(i>0);s+='bb';var RESULT=s;")
    expect_quiet("fc:f982-true-cond",
                 "var s='',i=0;do{s+='aa';i++;}while(true);var RESULT=s;")
    t0 = time.time()
    expect_quiet("fc:f982-nobreak",
                 "var s='';for(;;){s+='aa';}var RESULT=s;")
    check("fc:f982-nobreak-fast", time.time() - t0 < 10,
          "for(;;) without break took too long")
    expect_quiet("fc:f982-unbound",
                 "var s='';do{s+='aa',k++;}while(k<1);var RESULT=s;")
    # F983: NaN / Infinity / fractional / unsafe-integer / unbound discriminants
    expect_quiet("fc:f983-nan",
                 "var s='';switch(0/0){case 0:s+='no';break;default:s+='aa';}var RESULT=s;")
    expect_quiet("fc:f983-inf",
                 "var s='';switch(1/0){case 0:s+='no';break;default:s+='aa';}var RESULT=s;")
    expect_quiet("fc:f983-frac",
                 "var s='';switch(7/2){case 3:s+='no';break;default:s+='aa';}var RESULT=s;")
    expect_quiet("fc:f983-unsafe",
                 "var s='';switch(2**53){case 9007199254740992:s+='no';break;default:s+='aa';}var RESULT=s;")
    expect_quiet("fc:f983-unbound",
                 "var s='';switch(x+1){case 2:s+='aa';break;default:s+='bb';}var RESULT=s;")
    expect_quiet("fc:f983-signed-pow",
                 "var s='';switch(-2**2){case 4:s+='aa';break;default:s+='bb';}var RESULT=s;")
    expect_quiet("fc:f983-complex",
                 "var s='';switch(((-2)**(1/2))%3){case 0:s+='aa';break;default:s+='bb';}var RESULT=s;")
    expect_quiet("fc:f983-dd-adjacent",
                 "var s='';switch(1--2){case 3:s+='aa';break;default:s+='bb';}var RESULT=s;")
    # F984: throw in body, finally, referenced catch param, let in try body
    expect_quiet("fc:f984-throw",
                 "var s='';try{throw 'x';s+='aa';}catch(e){s+='bb';}var RESULT=s;")
    expect_quiet("fc:f984-finally",
                 "var s='';try{s+='aa';}catch(e){s+='bb';}finally{s+='cc';}var RESULT=s;")
    expect_quiet("fc:f984-param-ref",
                 "var s='';try{var o=structuredClone({a:'aa'});s+=o.a;}catch(e){s+=e;}var RESULT=s;")
    expect_quiet("fc:f984-let",
                 "var s='';try{let o='aa';s+=o;}catch(e){s+='bb';}var RESULT=s;")
    # F985: out-of-range / negative charCodeAt, non-BMP, unbound ident arg
    expect_quiet("fc:f985-oob",
                 "var t='ab';var c=t.charCodeAt(5);var RESULT=String.fromCharCode(c)+'!';")
    expect_quiet("fc:f985-neg",
                 "var t='ab';var c=t.charCodeAt(-1);var RESULT=String.fromCharCode(c)+'!';")
    expect_quiet("fc:f985-unbound",
                 "var RESULT=String.fromCharCode(q)+'!';")
    # HARD-4: accumulator == length string (node loops forever as
    # the string grows) and body mutating the length string --
    # both must fail closed, never fabricate, never hang.
    t0 = time.time()
    expect_quiet("fc:f985-drain-alias",
                 "var t='ab';var s='';for(var i=0;i<t.length;i++){t+=String.fromCharCode(t.charCodeAt(i));}var RESULT=s;")
    check("fc:f985-drain-alias-fast", time.time() - t0 < 10,
          "aliasing drain took too long")
    expect_quiet("fc:f985-len-mutated",
                 "var t='ab';var s='';for(var i=0;i<t.length;i++){t+='x';s+='y';}var RESULT=s;")


# ------------------------------------------------------- sibling pins
def test_sibling_pins():
    # Pre-existing productions keep working; this lane's sims stay disjoint.
    expect_block("sib:f953-literal",
                 "var s='';switch(2){case 1:s+='no';break;case 2:s+='%s';s+='%s';break;}var RESULT=s;" % (_A, _B))
    expect_block("sib:f937-loop",
                 "var s='';for(var i=0;i<2;i++){s+='%s';}s+='%s';var RESULT=s;" % (_A, _B))
    expect_block("sib:f679-iife",
                 "(function(){var s='';try{s+='%s';s+='%s';}catch(e){s='no';}return s;})()" % (_A, _B))
    # Disjointness: this lane's sims fail these closed (other productions own them).
    expect_sim_none("disjoint:f655-dowhile-false",
                    "var s='',i=0;do{s+='aa';i++;}while(false);s+='bb';var RESULT=s;")
    expect_sim_none("disjoint:plain-function",
                    "var s='';function f(){return 'aa';}s+=f();var RESULT=s;")


# ------------------------------------------------------- honest controls
def test_honest_controls():
    expect_quiet("honest:decl-only", "var x = 1;")
    expect_quiet("honest:copy", "var s='hello';var t=s;var RESULT=t;")
    expect_quiet("honest:iife", "(function(){var s='ab';return s;})()")
    expect_quiet("honest:english",
                 "The quick brown fox jumps over the lazy dog. var is a word.")
    expect_quiet("honest:json", '{"user": "alice", "role": "viewer"}')
    expect_quiet("honest:switch-real",
                 "switch (x) { case 1: console.log('one'); break; default: console.log('other'); }")
    expect_quiet("honest:try-real",
                 "try { JSON.parse(input); } catch (e) { console.error(e); }")


# ------------------------------------------------------------------ perf
def test_perf():
    sites = []
    base = ("var s='',i=0;do{s+='x',i++;}while(i<1);"
            "for(;;){s+='y';break;}try{s+='z';}catch(e){}var RESULT=s;")
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
    adj = ["evals/w391_f982_redfirst.py", "evals/w391_f983_redfirst.py",
           "evals/w391_f984_redfirst.py", "evals/w391_f985_redfirst.py"]
    for bat in adj:
        tmpd = tempfile.mkdtemp(prefix="w392lane4-green-", dir="/var/tmp")
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
    test_sibling_pins()
    test_honest_controls()
    test_perf()
    green_check()
    print("tally: %d FAIL / %d PASS" % (len(FAILS), _total[0] - len(FAILS)))


_total = [0]
_orig_check = check


def check(name, cond, detail=""):  # noqa: F811 -- tally wrapper
    _total[0] += 1
    _orig_check(name, cond, detail)


if __name__ == "__main__":
    main()
    sys.exit(1 if FAILS else 0)
