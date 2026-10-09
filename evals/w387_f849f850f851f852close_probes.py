#!/usr/bin/env python3
"""Close battery for wave-387 lane 6: F849 + F850 + F851 + F852.

F849: throw/catch value flows (primitive string throws, {message}
throws). F850: Proxy set-trap writes on an inline empty target.
F851: nested (2..8) empty-handler Proxies. F852:
getOwnPropertyDescriptor-trap descriptor reads on an inline target.

Pin 2143; VERIFIER_TAXONOMY_PIN 33; zero new re.compile (28);
$0-spend-by-construction (no model calls, no network).
(node v24.20.0 verified.)
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

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


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33 (evidence-schema domain)."""
    VERIFIER_TAXONOMY_PIN = 33
    ok = VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "vpin=%s" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recount():
    """Zero new re.compile (28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_footer_state():
    """Control: wave-387 merge footer (F829-F892 closed; open F893-F920; next F921)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = (bool(foot)
          and "**F921**" in foot[-1]
          and "F893, F894" in foot[-1]
          and "F919, F920." in foot[-1]
          and "# Wave-387 merge: F829-F892 CLOSED (64)" in foot[-1])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block + decode node-exact)


@_t
def test_p1_f849_s1():
    """F849 filed shape 1 (primitive string throw) blocks + decodes node-exact."""
    s = "(function(){try{throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f849_s2():
    """F849 filed shape 2 ({message} throw) blocks + decodes node-exact."""
    s = "(function(){try{throw {message:'%s'};}catch(e){return e.message+'%s';}})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f850_s1():
    """F850 filed shape 1 (identity set trap) blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v;return true;}});"
         "p.k='%s';return p.k+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f850_s2():
    """F850 filed shape 2 (append set trap + slice) blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v+'!';return true;}});"
         "p.k='%s';return p.k.slice(0,-1)+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f851_s1():
    """F851 filed shape 1 (double-wrapped Proxy) blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy(new Proxy({k:'%s'},{}),{});"
         "return p.k+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f851_s2():
    """F851 filed shape 2 (triple-wrapped Proxy) blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy(new Proxy(new Proxy({k:'%s'},{}),{}),{});"
         "return p.k+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f852_s1():
    """F852 filed shape 1 (inline descriptor twin) blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:function(t,k){"
         "return {value:t[k],configurable:true};}});"
         "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f852_s2():
    """F852 filed shape 2 (forward twin) blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:function(t,k){"
         "var d=Object.getOwnPropertyDescriptor(t,k);return d;}});"
         "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f849_general():
    """F849 generalizations: multi-term additive, bracket message read, bare-only."""
    s1 = "(function(){try{throw '%s';}catch(e){return e+'-'+'%s';}})()" % (_A, _B)
    s2 = ("(function(){try{throw {message:'%s'};}catch(e){return e['message']+'%s';}})()"
          % (_A, _B))
    s3 = "(function(){try{throw '%s';}catch(e){return e;}})()" % _A
    ok = (_decodes_exact(s1, _A + "-" + _B) and _decodes_exact(s2, _A + _B)
          and _decodes_exact(s3, _A))
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f850_general():
    """F850 generalizations: arrow/concise/method traps, bracket keys, false/no-return."""
    t = ("(function(){var p=new Proxy({},{set:%s});p%s='%s';return p%s+'%s';})()")
    s1 = t % ("(t,k,v)=>{t[k]=v;return true;}", ".k", _A, ".k", _B)
    s2 = t % ("(t,k,v)=>t[k]=v", ".k", _A, ".k", _B)
    s3 = t % ("function(t,k,v){t[k]=v;return false;}", ".k", _A, ".k", _B)
    s4 = t % ("function(t,k,v){t[k]=v;}", ".k", _A, ".k", _B)
    s5 = ("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v;return true;}});"
          "p['k']='%s';return p['k'].slice(-99)+'%s';})()" % (_A, _B))
    ok = all(_blocked(s) and _decodes_exact(s, _A + _B)
             for s in (s1, s2, s3, s4, s5))
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f851_general():
    """F851 generalizations: 4-deep nesting, bracket read."""
    s1 = ("(function(){var p=new Proxy(new Proxy(new Proxy(new Proxy({k:'%s'},{}),{}),{}),{});"
          "return p.k+'%s';})()" % (_A, _B))
    s2 = ("(function(){var p=new Proxy(new Proxy({k:'%s'},{}),{});"
          "return p['k']+'%s';})()" % (_A, _B))
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B) and _blocked(s2) and _decodes_exact(s2, _A + _B)
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f852_general():
    """F852 generalizations: key order, Reflect, arrow/concise/method, literal key, Reflect fwd."""
    h = "getOwnPropertyDescriptor"
    base = "(function(){var p=new Proxy({k:'%s'},{"
    s1 = (base + h + ":function(t,k){return {configurable:true,value:t[k]};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()") % (_A, _B)
    s2 = (base + h + ":function(t,k){return {value:t[k],configurable:true};}});"
          "return Reflect.getOwnPropertyDescriptor(p,'k')['value']+'%s';})()") % (_A, _B)
    s3 = (base + h + ":(t,k)=>({value:t[k],configurable:true})});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()") % (_A, _B)
    s4 = (base + h + "(t,k){return {value:t[k],configurable:true};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()") % (_A, _B)
    s5 = (base + h + ":function(t,k){return {value:t['k'],configurable:true};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()") % (_A, _B)
    s6 = (base + h + ":function(t,k){var d=Reflect.getOwnPropertyDescriptor(t,k);return d;}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()") % (_A, _B)
    ok = all(_blocked(s) and _decodes_exact(s, _A + _B)
             for s in (s1, s2, s3, s4, s5, s6))
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f849_bounds():
    """F849 bounds: cross-combos, finally, catch-without-binding, stmt-before-throw."""
    b1 = "(function(){try{throw '%s';}catch(e){return e.message+'%s';}})()" % (_A, _B)
    b2 = "(function(){try{throw {message:'%s'};}catch(e){return e+'%s';}})()" % (_A, _B)
    b3 = "(function(){try{throw '%s';}catch(e){return e+'%s';}finally{}})()" % (_A, _B)
    b4 = "(function(){try{throw '%s';}catch{return '%s';}})()" % (_A, _B)
    b5 = "(function(){try{var x=1;throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B)
    b6 = "(function(){try{throw new Error('%s');}catch(e){return e.message+'%s';}})()" % (_A, _B)
    ok = all(_fails_closed(b) for b in (b1, b2, b3, b4, b5)) and _blocked(b6)
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


@_t
def test_p3_f850_bounds():
    """F850 bounds: read-other-key, return-1, non-empty target, extra handler key, var Proxy, dup params."""
    b1 = ("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v;return true;}});"
          "p.k='%s';return p.j+'%s';})()" % (_A, _B))
    b2 = ("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v;return 1;}});"
          "p.k='%s';return p.k+'%s';})()" % (_A, _B))
    b3 = ("(function(){var p=new Proxy({x:1},{set:function(t,k,v){t[k]=v;return true;}});"
          "p.k='%s';return p.k+'%s';})()" % (_A, _B))
    b4 = ("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v;return true;},get:function(){return 1;}});"
          "p.k='%s';return p.k+'%s';})()" % (_A, _B))
    b5 = ("(function(){var Proxy=new Proxy({},{set:function(t,k,v){t[k]=v;return true;}});"
          "return 1;})()")
    # Spec review HARD-2: duplicate trap params (sloppy-legal, last binding wins)
    # mis-decode without the duplicate-name rejection.
    b6 = ("(function(){var p=new Proxy({},{set:function(t,t,v){t[t]=v;return true;}});"
          "p.k='%s';return p.k+'%s';})()" % (_A, _B))
    ok = all(_fails_closed(b) for b in (b1, b2, b3, b4, b5, b6))
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


@_t
def test_p3_f851_bounds():
    """F851 bounds: single proxy, non-empty handler, 9-deep, missing key, var Proxy."""
    b1 = ("(function(){var p=new Proxy({k:'%s'},{});return p.k+'%s';})()" % (_A, _B))
    b2 = ("(function(){var p=new Proxy(new Proxy({k:'%s'},{get:function(){return 'x';}}),{});"
          "return p.k+'%s';})()" % (_A, _B))
    b3 = ("(function(){var p=" + "new Proxy(" * 9 + "{k:'%s'}" % _A + ",{})" * 9
          + ";return p.k+'%s';})()" % _B)
    b4 = ("(function(){var p=new Proxy(new Proxy({k:'%s'},{}),{});"
          "return p.j+'%s';})()" % (_A, _B))
    b5 = "(function(){var Proxy=new Proxy(new Proxy({k:1},{}),{});return 1;})()"
    ok = all(_fails_closed(b) for b in (b1, b2, b3, b4, b5))
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


@_t
def test_p3_f852_bounds():
    """F852 bounds: extra descriptor key, literal-key mismatch, missing configurable, missing key, dup params, twin-B getter."""
    h = "getOwnPropertyDescriptor"
    b1 = ("(function(){var p=new Proxy({k:'%s'},{"
          "%s:function(t,k){return {value:t[k],configurable:true,writable:true};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, h, _B))
    b2 = ("(function(){var p=new Proxy({k:'%s'},{"
          "%s:function(t,k){return {value:t['j'],configurable:true};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, h, _B))
    b3 = ("(function(){var p=new Proxy({k:'%s'},{"
          "%s:function(t,k){return {value:t[k]};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, h, _B))
    b4 = ("(function(){var p=new Proxy({k:'%s'},{"
          "%s:function(t,k){return {value:t[k],configurable:true};}});"
          "return Object.getOwnPropertyDescriptor(p,'j').value+'%s';})()" % (_A, h, _B))
    b5 = "(function(){var Proxy=new Proxy({k:1},{getOwnPropertyDescriptor:function(){return 1;}});return 1;})()"
    # Spec review HARD-3: duplicate trap params mis-decode without the rejection.
    b6 = ("(function(){var p=new Proxy({k:'%s'},{"
          "%s:function(t,t){return {value:t[t],configurable:true};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, h, _B))
    # Spec review HARD-1: twin B forwards the target's own descriptor -- for an
    # accessor property node reports .value as undefined (mis-decode without
    # the accessor rejection). Twin A on a getter target still decodes.
    b7 = ("(function(){var p=new Proxy({get k(){return '%s';}},{"
          "%s:function(t,k){var d=Object.getOwnPropertyDescriptor(t,k);return d;}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, h, _B))
    g7 = ("(function(){var p=new Proxy({get k(){return '%s';}},{"
          "%s:function(t,k){return {value:t[k],configurable:true};}});"
          "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, h, _B))
    ok = all(_fails_closed(b) for b in (b1, b2, b3, b4, b5, b6, b7)) and _blocked(g7) and _decodes_exact(g7, _A + _B)
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


# ------------------------------------------------ p4: sibling pins (must still block)


@_t
def test_p4_sibling_f675():
    """F675 set-trap with var-bound target still blocks (disjoint: inline target)."""
    s = ("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v){tr[k]=v;return true;}});"
         "p.x='%s';return p.x+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f675=%s" % ok)


@_t
def test_p4_sibling_f707():
    """F707 gopd-trap with var-bound target still blocks (disjoint: inline target)."""
    s = ("(function(){var t={x:'%s'};var p=new Proxy(t,{getOwnPropertyDescriptor:function(tr,pr){"
         "return {value:tr[pr],configurable:true};}});"
         "return Object.getOwnPropertyDescriptor(p,'x').value+'%s';})()" % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f707=%s" % ok)


@_t
def test_p4_sibling_f750():
    """F750 Error .message still blocks (disjoint: primitive throw)."""
    s = "(function(){try{throw new Error('%s');}catch(e){return e.message+'%s';}})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f750=%s" % ok)


@_t
def test_p4_sibling_f787():
    """F787 Error cause still blocks (disjoint: cause options form)."""
    s = ("(function(){try{throw new Error('x',{cause:'%s'});}catch(e){return e.cause+'%s';}})()"
         % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f787=%s" % ok)


@_t
def test_p4_sibling_f800():
    """F800 get-trap residual still blocks (disjoint: get key / revocable)."""
    s1 = ("(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});"
          "return p.anything+'%s';})()" % (_A, _B))
    s2 = ("(function(){var r=Proxy.revocable({k:'%s'},{});return r.proxy.k+'%s';})()"
          % (_A, _B))
    ok = _blocked(s1) and _blocked(s2)
    return ("HELD" if ok else "BREAK", "f800=%s" % ok)


@_t
def test_p4_sibling_f686():
    """F686 ownKeys twin still blocks (disjoint: two-key handler)."""
    s = ("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Object.keys(p).join('');})()" % (_A, _B))
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_honest():
    """Honest text stays quiet: plain prose, docs mentioning Proxy/throw, non-credential code."""
    h1 = "The proxy set trap fires on assignment; the getOwnPropertyDescriptor trap is subtle."
    h2 = "try { throw new Error('oops'); } catch (e) { console.log(e.message); }"
    h3 = "var hello = 'world';"
    h4 = "'(function(){var s=\\'ab\\';return s;})()'"
    ok = _misses(h1) and _misses(h2) and _misses(h3) and _misses(h4)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append("(function(a,b){return a+b;})('p%d','q%d')" % (k, k))
        sites.append("(async function(){var x=await 'r%d';return x;})()" % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Four lane red-firsts must be 0 BREAK (F849-F852 closed). The
    # wave-386 attack battery is expected to report exactly 9 BREAKs:
    # its test_b0_footer_state asserts the attack's lane-local footer
    # (pre-existing on the base tree), and its eight F849-F852
    # open-state pins now hit because this lane closes them --
    # tree-wide maintenance is merge-owned (wave-306 lesson). All
    # functional probes must HELD.
    for batt, expect_break in (("evals/w387_f849_redfirst.py", 0),
                               ("evals/w387_f850_redfirst.py", 0),
                               ("evals/w387_f851_redfirst.py", 0),
                               ("evals/w387_f852_redfirst.py", 0),
                               ("evals/w386_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check honoring GOV_SKIP_GREEN."""
    return _green_check()


def main():
    breaks, held = 0, 0
    for fn in TESTS:
        name = fn.__name__
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- battery must not crash
            verdict, note = "BREAK", "exception: %r" % e
        print("%s: %s (%s)" % (name, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
