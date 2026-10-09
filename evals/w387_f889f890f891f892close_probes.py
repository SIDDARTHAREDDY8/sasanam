#!/usr/bin/env python3
"""Wave-387 lane 16: close F889 + F890 + F891 + F892.

F889 (filed 2026-10-09 05:41 UTC by wave-386 lane 2, spec-axis
review catch; renumbered from F829 at the wave-386 merge):
_js_parse_f659_yield_star_array was CALLED inside
_js_parse_f6xx_fixed_yield_body but never DEFINED -- every
`yield* ['LIT',...];` shape reaching it escaped find_credential
as a NameError (DoS vector). Pre-existing on the wave-385 base.
Fix: define the helper (F659 array delegation; node-exact
v24.20.0: `yield* ARR` yields each element in order). The filed
shape fails closed (the outer `.next().value` chain is unmodeled);
the spread-copy route now decodes node-exactly.

F890 (filed 2026-10-09 05:43:21 UTC by wave-386 lane 1,
spec-axis review residual of the F795 closure; renumbered from
F829 at the wave-386 merge): the F795 arrow twin requires the
parenthesized param list ((PARAMS)=>...), so the unparenthesized
single-param arrow IIFE `(a=>a)('f1')` -- node-evaluated to 'f1'
(v24.20.0) -- missed. Fix: extend _js_parse_f795_param_arrow_iife
with the F890 bare-param branch (single IDENT param, `arguments`
rejected, no `=>` fails closed). Node-exact.

F891 (filed 2026-10-09 05:50:07 UTC by wave-386 lane 9,
spec-review residual of the F812 closure; renumbered from F830
at the wave-386 merge): Object.seal literals CONTAINING shorthand
methods had no production -- the F539 literal parse fails closed
on methods (so even a pure data read on the sealed object
missed), and the F812 sealed IIFE models only member reads (so a
method CALL missed). Fix: the F891 method-literal grammar (data
props + zero-param shorthand methods with pure-literal bodies,
node-exact v24.20.0) and the sealed-method IIFE for
seal/freeze/preventExtensions heads. Reading a method (not
calling) fails closed -- the engine yields the function object;
calling a data prop throws in the engine -- fail closed.

F892 (filed 2026-10-09 05:55:00 UTC by wave-386 lane 14,
spec-axis review HARD-3 on the F822 closure; renumbered from
F832 at the wave-386 merge): F822 dispatches `?.method(args)`
through the F478 table (14 methods), but the dot form's method
grammar (_JS_POSTFIX_METHOD_NAMES, 40 methods) is wider -- the 26
non-table methods stayed bypassable via `?.`. Fix: the
full-table `?.` direct-call lookahead -- on a provably-non-null
receiver `?.` is engine-identical to `.` (node v24.20.0), so the
26 non-table methods dispatch through _js_apply_method exactly
like the dot form. The 14 F478-table methods keep the F822 path
byte-identical.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

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
    path = os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py")
    ok = "VERIFIER_TAXONOMY_PIN = 33" in open(path).read()
    return ("HELD" if ok else "BREAK", "vpin=%s" % ok)


@_t
def test_p0_recount():
    """Zero new re.compile (28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
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


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f889_filed():
    """F889 filed shape: never raises (fails closed returning None)."""
    s = ("(function(){function* b(){yield* ['f1','f2'];}var it=b();"
         "return it.next().value+it.next().value;})()")
    try:
        r = dlp.find_credential(s)
    except Exception:  # noqa: BLE001 -- the bug WAS the raise
        return ("BREAK", "raised")
    ok = r is None  # the outer .next().value chain is unmodeled
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p1_f889_spread():
    """F889: the defined helper decodes yield* delegation node-exactly."""
    s = "[...(function*(){yield* ['f1','f2'];})()].join('')"
    ok = _decodes_exact(s, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p1_f890_s1():
    """F890 filed shape 1 (bare arrow add) blocks + decodes node-exact."""
    s = "(a=>a+'" + _B + "')('" + _A + "')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f890_s2():
    """F890 filed shape 2 (bare arrow ident) decodes the binding."""
    s = "(a=>a)('" + _A + "')"
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p1_f891_s1():
    """F891 filed shape 1 (data read on method-literal) blocks + exact."""
    s = ("(function(){var o=Object.seal({k:'" + _A
         + "',m(){return 'z';}});return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f891_s2():
    """F891 filed shape 2 (zero-arg method call) blocks + exact."""
    s = ("(function(){var o=Object.seal({m(){return '" + _A
         + "';}});return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f892_s1():
    """F892 filed shape 1 (?.flat) blocks + decodes node-exact."""
    s = "[['" + _A + "'],['" + _B + "']]?.flat().join('')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f892_s2():
    """F892 filed shape 2 (?.split) blocks + decodes node-exact."""
    s = "'" + _A + "," + _B + "'?.split(',').join('')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f889_paren():
    """F889: paren-wrapped delegation decodes; empty delegation fails
    closed (consistent with the pre-existing 'generator yields
    nothing' discipline)."""
    s1 = "[...(function*(){yield* (['f1','f2']);})()].join('')"
    s2 = "[...(function*(){yield* [];})()].join('')"
    ok = _decodes_exact(s1, "f1f2") and _fails_closed(s2)
    return ("HELD" if ok else "BREAK", "paren+empty=%s" % ok)


@_t
def test_p2_f890_ws_extra_longparam():
    """F890: ws-tolerant, extra args ignored, long param names."""
    s1 = "( a => a+'" + _B + "')('" + _A + "')"
    s2 = "(a=>a+'" + _B + "')('" + _A + "','zz')"
    s3 = "(abc=>abc+'" + _B + "')('" + _A + "')"
    ok = _decodes_exact(s1, _A + _B)
    ok = ok and _decodes_exact(s2, _A + _B)
    ok = ok and _decodes_exact(s3, _A + _B)
    return ("HELD" if ok else "BREAK", "variants=%s" % ok)


@_t
def test_p2_f891_twins():
    """F891: freeze/preventExtensions heads decode like seal."""
    s1 = ("(function(){var o=Object.freeze({m(){return '" + _A
          + "';}});return o.m()+'" + _B + "';})()")
    s2 = ("(function(){var o=Object.preventExtensions({k:'" + _A
          + "',m(){return 'z';}});return o.k+'" + _B + "';})()")
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    return ("HELD" if ok else "BREAK", "twins=%s" % ok)


@_t
def test_p2_f891_read_forms():
    """F891: ?. and ['k'] read forms decode; dup keys later-wins."""
    s1 = ("(function(){var o=Object.seal({k:'" + _A
          + "',m(){return 'z';}});return o?.k+'" + _B + "';})()")
    s2 = ("(function(){var o=Object.seal({k:'" + _A
          + "',m(){return 'z';}});return o['k']+'" + _B + "';})()")
    s3 = ("(function(){var o=Object.seal({k:'zz',k:'" + _A
          + "',m(){return 'z';}});return o.k+'" + _B + "';})()")
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    ok = ok and _blocked(s3) and _decodes_exact(s3, _A + _B)
    return ("HELD" if ok else "BREAK", "reads=%s" % ok)


@_t
def test_p2_f891_multilit_body():
    """F891: multi-literal method bodies concatenate."""
    s = ("(function(){var o=Object.seal({m(){return '" + _A + "'+'"
         + _B + "';}});return o.m();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "multilit=%s" % ok)


@_t
def test_p2_f892_method_sweep():
    """F892: representative non-F478 methods block node-exactly."""
    shapes = [
        ("'" + _A + "'?.repeat(1)+'" + _B + "'", _A + _B),
        ("('  " + _A + _B + "  ')?.trim()", _A + _B),
        ("('XOXB-0123'+'456789ABCDEF')?.toLowerCase()", _A + _B),
        ("('" + _A + _B + "zz')?.substring(0,21)", _A + _B),
        ("['z','Q']?.with(0,'" + _A + _B + "').join('')", _A + _B + "Q"),
        ("['" + _B + "','" + _A + "']?.toReversed().join('')", _A + _B),
        ("('" + _A + _B + "')?.normalize()", _A + _B),
        ("('" + _A + "Z" + _B + "')?.replaceAll('Z','')", _A + _B),
    ]
    bad = []
    for s, want in shapes:
        if not (_blocked(s) and _decodes_exact(s, want)):
            bad.append(s[:40])
    ok = not bad
    return ("HELD" if ok else "BREAK", "sweep=%s" % (bad if bad else "8/8"))


@_t
def test_p2_f892_charat_tosorted_exact():
    """F892: charAt/toSorted decode exactly (non-credential outputs)."""
    ok = _decodes_exact("('ab')?.charAt(0)+'c'", "ac")
    ok = ok and _decodes_exact("['b','a']?.toSorted().join(',')", "a,b")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f889_nonliteral():
    """F889: non-literal delegation fails closed (no guessing)."""
    s1 = "[...(function*(){yield* [x];})()].join('')"
    s2 = "[...(function*(){yield* foo();})()].join('')"
    ok = _fails_closed(s1) and _fails_closed(s2)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f890_bounds():
    """F890: no-arg, default, async, block-body, two-param fail closed."""
    shapes = [
        "(a=>a)()",
        "(a='x'=>a)('" + _A + "')",
        "(async a=>a)('" + _A + "')",
        "(a=>{return a;})('" + _A + "')",
        "(a,b=>a)('" + _A + "')",
        "(arguments=>arguments)('" + _A + "')",
    ]
    bad = [s for s in shapes if not _fails_closed(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "failclosed=%s" % (bad if bad else "6/6"))


@_t
def test_p3_f891_bounds():
    """F891: params/getters/this/computed/spread/proto fail closed;
    method-read and data-call fail closed."""
    shapes = [
        # method with a param
        ("(function(){var o=Object.seal({m(x){return '" + _A
          + "';}});return o.m()+'" + _B + "';})()"),
        # getter
        ("(function(){var o=Object.seal({get k(){return '" + _A
          + "';},m(){return 'z';}});return o.k+'" + _B + "';})()"),
        # this in the body
        ("(function(){var o=Object.seal({k:'" + _A
          + "',m(){return this.k;}});return o.m()+'" + _B + "';})()"),
        # computed key
        ("(function(){var o=Object.seal({['k']:'" + _A
          + "',m(){return 'z';}});return o.k+'" + _B + "';})()"),
        # spread
        ("(function(){var o=Object.seal({...q,k:'" + _A
          + "',m(){return 'z';}});return o.k+'" + _B + "';})()"),
        # __proto__
        ("(function(){var o=Object.seal({__proto__:null,k:'" + _A
          + "',m(){return 'z';}});return o.k+'" + _B + "';})()"),
        # read of a method (engine: the function object)
        ("(function(){var o=Object.seal({m(){return '" + _A
          + "';}});return typeof o.m;})()"),
        # call of a data prop (engine: TypeError)
        ("(function(){var o=Object.seal({k:'" + _A
          + "',m(){return 'z';}});return o.k();})()"),
    ]
    bad = [s[:50] for s in shapes if not _fails_closed(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "failclosed=%s" % (bad if bad else "8/8"))


@_t
def test_p3_f892_bounds():
    """F892: kind-mismatched and unknown ?. methods fail closed."""
    shapes = [
        "'ab'?.join(',')",          # join on str: engine TypeError
        "['a']?.replace('a','b')",  # replace on array: engine TypeError
        "'a'?.frobnicate('b')",     # unknown method
        "['a']?.['frobnicate']('b')",
        # HARD-1 (spec review): F478-table methods on non-(array|str)
        # receivers keep the F822 silent chain-end -- node throws
        # TypeError, and _js_apply_method's concat fall-through would
        # over-decode here.
        "(1)?.concat('a','b')",
        "(1n)?.concat('a','b')",
    ]
    bad = [s for s in shapes if not _fails_closed(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "failclosed=%s" % (bad if bad else "6/6"))


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_sibling_f822():
    """F822: F478-table ?. methods still dispatch."""
    s1 = "['" + _A + "','" + _B + "']?.join('')"
    s2 = "'" + _A + "'?.concat('" + _B + "')"
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    return ("HELD" if ok else "BREAK", "f822=%s" % ok)


@_t
def test_p4_sibling_f478():
    """F478: .call/apply/bind dispatch still decodes."""
    s = "Array.prototype.join.call(['" + _A + "','" + _B + "'],'')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f478=%s" % ok)


@_t
def test_p4_sibling_f795():
    """F795: parenthesized arrow twin still decodes."""
    s = "((a)=>a+'" + _B + "')('" + _A + "')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f795=%s" % ok)


@_t
def test_p4_sibling_f812a():
    """F812a: method-free sealed literal still decodes."""
    s = ("(function(){var o=Object.seal({k:'" + _A + "'});"
         "return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f812a=%s" % ok)


@_t
def test_p4_sibling_f659():
    """F659: plain yield delegation still decodes."""
    s = "[...(function*(){yield 'f1';yield 'f2';})()].join('')"
    ok = _decodes_exact(s, "f1f2")
    return ("HELD" if ok else "BREAK", "f659=%s" % ok)


@_t
def test_p4_sibling_f677():
    """F677: plain spread-copy still decodes."""
    s = "[...['f1','f2']].join('')"
    ok = _decodes_exact(s, "f1f2")
    return ("HELD" if ok else "BREAK", "f677=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_honest_quiet():
    """Honest text across the new shapes stays quiet."""
    shapes = [
        "(a=>a)('x')",
        "(function(){var o=Object.seal({m(){return 'x';}});return o.m();})()",
        "['a']?.flat().join('')",
        "[...(function*(){yield* ['x'];})()].join('')",
        "var hello = 'world';",
    ]
    bad = [s for s in shapes if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "honest=%s" % (bad if bad else "5/5"))


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(50):
        sites.append("(a=>a+'q%d')('p%d')" % (k, k))
        sites.append("['p%d']?.repeat(1)+'q%d'" % (k, k))
        sites.append(
            "(function(){var o=Object.seal({m(){return 'p%d';}});"
            "return o.m();})()" % k)
        sites.append(
            "[...(function*(){yield* ['p%d'];})()].join('')" % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Lane red-firsts must be 0 BREAK. The wave-386 attack battery is
    # expected to report exactly 1 BREAK: its test_b0_footer_state
    # asserts the base footer (this lane's footer is lane-local with
    # F889-F892 closed) -- tree-wide maintenance is merge-owned
    # (wave-306 lesson). The attack battery has no F889-F892 pins
    # (they were filed after the attack round).
    for batt, expect_break in (
            ("evals/w387_f889_redfirst.py", 0),
            ("evals/w387_f890_redfirst.py", 0),
            ("evals/w387_f891_redfirst.py", 0),
            ("evals/w387_f892_redfirst.py", 0),
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
    """Depth-1 green check: lane red-firsts 0 BREAK + wave-386 attack
    battery 1 BREAK (footer pin, lane-local; merge-owned)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
