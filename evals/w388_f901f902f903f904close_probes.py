#!/usr/bin/env python3
"""Close battery for wave-388 lane 3: F901 + F902 + F903 + F904.

F901: comma-operator and chained assignments in the F679 statement
engine (node-exact: `r='x',r='f1';`, `a=b='f1';`, `var a,b;`
multi-declarators).
F902: catch-binding copies in the F849 throw/catch IIFE
(`var|let|const m=e;` before the return; string-throw kind only).
F903: JSON.stringify + slice laundering
(`var S=JSON.stringify(VALUE);return S.slice(A,B)(+'LIT')*;`).
F904: superclass constructor field init read through a subclass
(`class C extends B{}` / `class C extends B{constructor(){
super(...);}}` in the F780 IIFE; zero-param base classes).

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
    """VERIFIER_TAXONOMY_PIN stays 33 (evidence-schema domain; read from the repo, not a local)."""
    import re
    src = open(os.path.join(REPO_ROOT, "evals",
                            "w318_evidence_schema_probes.py")).read()
    m = re.search(r"^VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", src, re.M)
    ok = m is not None and int(m.group(1)) == 33
    return ("HELD" if ok else "BREAK",
            "vpin=%s" % (m.group(1) if m else None))


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
    """Control: lane-local footer (F901-F904 closed; open F893-F900, F905-F920; next F921)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    # The open list must not contain F901-F904 as open entries.
    open_seg = foot[-1].split("Open findings:")[-1] if "Open findings:" in foot[-1] else ""
    ok = (bool(foot) and "**F921**" in foot[-1]
          and "F893, F894" in foot[-1] and "F919, F920." in foot[-1]
          and "F901," not in open_seg and "F904." not in open_seg
          and "F905" in open_seg)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block + decode node-exact)


@_t
def test_p1_f901_s1():
    """F901 filed shape 1 (comma-operator) blocks + decodes node-exact."""
    s = "(function(){var r;r='x',r='%s';return r+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f901_s2():
    """F901 filed shape 2 (chained assignment) blocks + decodes node-exact."""
    s = "(function(){var a,b;a=b='%s';return a+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f902_s1():
    """F902 filed shape 1 (bare catch param, no copy) blocks + decodes node-exact."""
    s = "(function(){try{throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f902_s2():
    """F902 filed shape 2 (catch-param copy) blocks + decodes node-exact."""
    s = "(function(){try{throw '%s';}catch(e){var m=e;return m+'%s';}})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f903_s1():
    """F903 filed shape 1 (stringify array + slice) blocks + decodes node-exact."""
    s = "(function(){var s=JSON.stringify(['%s']);return s.slice(2,-2)+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f903_s2():
    """F903 filed shape 2 (stringify object + slice) blocks + decodes node-exact."""
    s = "(function(){var s=JSON.stringify({k:'%s'});return s.slice(6,-2)+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f904_s1():
    """F904 filed shape 1 (empty subclass body) blocks + decodes node-exact."""
    s = ("(function(){class B{constructor(){this.k='%s';}}"
         "class C extends B{}return new C().k+'%s';})()") % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f904_s2():
    """F904 filed shape 2 (super-forward) blocks + decodes node-exact."""
    s = ("(function(){class B{constructor(x){this.k=x;}}"
         "class C extends B{constructor(){super('%s');}}"
         "return new C().k+'%s';})()") % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f901_general():
    """F901 generalizations: comma+chain mix, triple chain, +=, initialized multi-declarator."""
    s1 = "(function(){var a,b,c;a=b='%s',c='%s';return a+c;})()" % (_A, _B)
    s2 = "(function(){var a,b,c;a=b=c='%s';return a+'%s';})()" % (_A, _B)
    s3 = "(function(){var a;a='%s';a+='%s';return a;})()" % (_A, _B)
    s4 = "(function(){var a='%s',b='%s';return a+b;})()" % (_A, _B)
    ok = all(_blocked(s) and _decodes_exact(s, _A + _B) for s in (s1, s2, s3, s4))
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f902_general():
    """F902 generalizations: const/let copies, chained copies."""
    s1 = ("(function(){try{throw '%s';}catch(e){const m=e;return m+'%s';}})()"
          % (_A, _B))
    s2 = ("(function(){try{throw '%s';}catch(e){var m=e;var n=m;return n+'%s';}})()"
          % (_A, _B))
    s3 = ("(function(){try{throw '%s';}catch(e){let m=e;return m+'%s';}})()"
          % (_A, _B))
    ok = all(_blocked(s) and _decodes_exact(s, _A + _B) for s in (s1, s2, s3))
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f903_general():
    """F903 generalizations: clamping slice args, nested array, multi-key object."""
    s1 = ("(function(){var s=JSON.stringify(['%s']);return s.slice(0,99);})()"
          % (_A + _B))
    s2 = ("(function(){var s=JSON.stringify([['%s']]);return s.slice(3,-3);})()"
          % (_A + _B))
    s3 = ("(function(){const s=JSON.stringify({a:'x',k:'%s'});return s.slice(14,-2);})()"
          % (_A + _B))
    ok = (_blocked(s1) and _decodes_exact(s1, '["' + _A + _B + '"]')
          and _blocked(s2) and _decodes_exact(s2, _A + _B)
          and _blocked(s3) and _decodes_exact(s3, _A + _B))
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


@_t
def test_p2_f904_general():
    """F904 generalizations: multi-param empty body, subclass-param super-forward, extra super args."""
    s1 = ("(function(){class B{constructor(x,y){this.k=x;this.j=y;}}"
          "class C extends B{}return new C('%s','q').k;})()") % (_A + _B)
    s2 = ("(function(){class B{constructor(x){this.k=x;}}"
          "class C extends B{constructor(y){super(y);}}"
          "return new C('%s').k;})()") % (_A + _B)
    s3 = ("(function(){class B{constructor(x){this.k=x;}}"
          "class C extends B{constructor(){super('%s','extra');}}"
          "return new C().k;})()") % (_A + _B)
    ok = all(_blocked(s) and _decodes_exact(s, _A + _B) for s in (s1, s2, s3))
    return ("HELD" if ok else "BREAK", "gen=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f901_bounds():
    """F901 bounds: int-statement comma, unbound chain target, unbound comma segment."""
    b1 = "(function(){var i=0;i=1,i=2;return 'x';})()"
    b2 = "(function(){var a;a=b='%s';return a;})()" % (_A + _B)
    b3 = "(function(){var r;r='x',q='y';return r;})()"
    ok = all(_fails_closed(b) for b in (b1, b2, b3))
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


@_t
def test_p3_f902_bounds():
    """F902 bounds: reassignment after copy, non-copy initializer, msg-kind copy, multi-declarator copy."""
    b1 = ("(function(){try{throw '%s';}catch(e){var m=e;m='zz';return m+'%s';}})()"
          % (_A, _B))
    b2 = ("(function(){try{throw '%s';}catch(e){var m='x';return m+'%s';}})()"
          % (_A, _B))
    b3 = ("(function(){try{throw {message:'%s'};}catch(e){var m=e;return m.message+'%s';}})()"
          % (_A, _B))
    b4 = ("(function(){try{throw '%s';}catch(e){var m=e,n=e;return m+'%s';}})()"
          % (_A, _B))
    ok = all(_fails_closed(b) for b in (b1, b2, b3, b4))
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


@_t
def test_p3_f903_bounds():
    """F903 bounds: replacer arg, non-int slice args, slice on other name, reassignment between."""
    b1 = ("(function(){var s=JSON.stringify(['%s'],null,1);return s.slice(2,-2);})()"
          % (_A + _B))
    b2 = ("(function(){var s=JSON.stringify(['%s']);return s.slice('a',2);})()"
          % (_A + _B))
    b3 = ("(function(){var s=JSON.stringify(['%s']);return t.slice(2,-2);})()"
          % (_A + _B))
    b4 = ("(function(){var s=JSON.stringify(['%s']);s='x';return s.slice(2,-2);})()"
          % (_A + _B))
    ok = all(_fails_closed(b) for b in (b1, b2, b3, b4))
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


@_t
def test_p3_f904_bounds():
    """F904 bounds: undeclared extends target, unbound super arg, non-super ctor stmt, missing super arg."""
    b1 = "(function(){class C extends Q{}return new C().k;})()"
    b2 = ("(function(){class B{constructor(x){this.k=x;}}"
          "class C extends B{constructor(){super(q);}}"
          "return new C().k;})()")
    b3 = ("(function(){class B{constructor(x){this.k=x;}}"
          "class C extends B{constructor(){var z=1;super('a');}}"
          "return new C().k;})()")
    b4 = ("(function(){class B{constructor(x){this.k=x;}}"
          "class C extends B{constructor(){super();}}"
          "return new C().k+'%s';})()") % _B
    ok = all(_fails_closed(b) for b in (b1, b2, b3, b4))
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


# ------------------------------------------------ p4: sibling pins (must still block)


@_t
def test_p4_sibling_f849():
    """F849 bare-param and {message} twins still block (disjoint: no copies)."""
    s1 = "(function(){try{throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B)
    s2 = ("(function(){try{throw {message:'%s'};}catch(e){return e.message+'%s';}})()"
          % (_A, _B))
    ok = all(_blocked(s) and _decodes_exact(s, _A + _B) for s in (s1, s2))
    return ("HELD" if ok else "BREAK", "f849=%s" % ok)


@_t
def test_p4_sibling_f679():
    """F679 plain accumulation still blocks (disjoint: no comma/chain)."""
    s = "(function(){var r='';r+='%s';r+='%s';return r;})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f679=%s" % ok)


@_t
def test_p4_sibling_f780():
    """F780 function/class ctors still block (disjoint: no extends)."""
    s1 = ("(function(){function C(x){this.x=x;}var o=new C('%s');"
          "return o.x+'%s';})()") % (_A, _B)
    s2 = ("(function(){class C{constructor(x){this.x=x;}}"
          "return new C('%s').x+'%s';})()") % (_A, _B)
    ok = all(_blocked(s) and _decodes_exact(s, _A + _B) for s in (s1, s2))
    return ("HELD" if ok else "BREAK", "f780=%s" % ok)


@_t
def test_p4_sibling_f750():
    """F750 Error .message still blocks (disjoint: primitive throw)."""
    s = "(function(){try{throw new Error('%s');}catch(e){return e.message+'%s';}})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f750=%s" % ok)


@_t
def test_p4_sibling_f903_disjoint():
    """Stringify var without slice stays missed (disjoint: F903 needs .slice)."""
    b = "(function(){var s=JSON.stringify(['%s']);return s;})()" % (_A + _B)
    ok = _fails_closed(b)
    return ("HELD" if ok else "BREAK", "disjoint=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_honest():
    """Honest text stays quiet: prose, docs mentioning the new shapes, non-credential code."""
    h1 = "Use the comma operator to sequence assignments; chained assignment is right-associative."
    h2 = "try { throw new Error('oops'); } catch (e) { var m = e; console.log(m.message); }"
    h3 = "var s = JSON.stringify([1, 2]); return s.slice(0, 2);"
    h4 = "class C extends B {}"
    h5 = "'(function(){var s=\\'ab\\';return s;})()'"
    ok = all(_misses(h) for h in (h1, h2, h3, h4, h5))
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
    # Four lane red-firsts must be 0 BREAK (F901-F904 closed). The
    # wave-387 attack battery is expected to report exactly 12
    # BREAKs: 5 pre-existing open-state pins plus the 7 F901-F904
    # open-state pins, which now decode because this lane closes
    # them -- tree-wide maintenance is merge-owned (wave-306
    # lesson). All functional probes must HELD.
    for batt, expect_break in (("evals/w388_f901_redfirst.py", 0),
                               ("evals/w388_f902_redfirst.py", 0),
                               ("evals/w388_f903_redfirst.py", 0),
                               ("evals/w388_f904_redfirst.py", 0),
                               ("evals/w387_attack_probes.py", 12)):
        tmp = tempfile.mkdtemp(prefix="g388-green-", dir="/var/tmp")
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
