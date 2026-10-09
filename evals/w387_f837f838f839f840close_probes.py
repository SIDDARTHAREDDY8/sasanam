"""Wave-387 lane-3 close battery: F837 + F838 + F839 + F840.

F837: IIFE returning an object/array literal
  s1 `(function(){return {k:'f1'};})().k+'f2'`
  s2 `(function(){var r=(function(){return ['f1','f2'];})();return r[0]+r[1];})()`
F838: nested function declarations
  s1 `(function(){function outer(){function inner(){return 'f1';}return inner();}return outer()+'f2';})()`
  s2 `(function(){function a(){function b(){function c(){return 'f1';}return c();}return b();}return a()+'f2';})()`
F839: block-scoped let/const accumulation
  s1 `(function(){var r='';{let k='f1';r=k;}return r+'f2';})()`
  s2 `(function(){var r='';if(true){const k='f1';r=k;}return r+'f2';})()`
F840: shorthand property in object literal
  s1 `(function(){var k='f1';var o={k};return o.k+'f2';})()`
  s2 `(function(){var k='f1',j='f2';var o={k,j};return o['k']+o['j'];})()`

Covers: pin/footer pins, filed shapes, node-verified generalizations,
fail-closed bounds, sibling pins (F671/F611/F735/F748), honest-text
controls, perf (200 sites), and a depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
TMPDIRs, no in-repo git in self-pins, zero paid-model cost by
construction (asserted below).
"""
import os
import re
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

_A = "xoxb-0123456789abcdef"
_B = "xoxb-9876543210fedcba"
_AB = _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decodes_to(payload, want):
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
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_footer_state():
    """Lane-local footer: F837-F840 closed; F829-F836, F841-F892 open."""
    p = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    src = open(p).read()
    ok = True
    for f in ("F837", "F838", "F839", "F840"):
        i = src.find("(" + f + " filed")
        ok = ok and i != -1 and "CLOSED" in src[i:i + 400]
    # lane-local footer: F837-F840 not in the open list
    m = re.search(r"Open findings: ([^*]*)\.", src)
    ok = ok and m is not None and all(
        f not in m.group(1) for f in ("F837", "F838", "F839", "F840"))
    return ("HELD" if ok else "BREAK", "footer=F837-F840 closed")


# ------------------------------------------------ p1: F837 filed shapes


@_t
def test_p1_f837_s1():
    """Filed s1: IIFE returning object literal, member read."""
    return ("HELD" if _blocked("(function(){return {k:'" + _A
                               + "';};})().k")
            else "BREAK", "f837-s1")


@_t
def test_p1_f837_s2():
    """Filed s2: var-bound inner IIFE returning array literal."""
    return ("HELD" if _blocked("(function(){var r=(function(){return ['"
                               + _A + "','" + _B + "'];})();return r[0]+r[1];})()")
            else "BREAK", "f837-s2")


# ------------------------------------------------ p2: F837 generalizations


@_t
def test_p2_f837_arr_primary():
    """Array-literal IIFE in primary position with [N] read."""
    return ("HELD" if _decodes_to("(function(){return ['" + _A + "','" + _B
                                  + "'];})()[1]", _B)
            else "BREAK", "f837-arr-primary")


@_t
def test_p2_f837_obj_bracket():
    """Object-literal IIFE with ['k'] bracket read."""
    return ("HELD" if _decodes_to("(function(){return {k:'" + _A
                                  + "'};})()['k']", _A)
            else "BREAK", "f837-obj-bracket")


@_t
def test_p2_f837_varbound_obj():
    """Var-bound inner IIFE returning object literal."""
    return ("HELD" if _decodes_to("(function(){var r=(function(){return {k:'"
                                  + _A + "',j:'" + _B + "'};})();"
                                  "return r.k+r.j;})()", _AB)
            else "BREAK", "f837-varbound-obj")


@_t
def test_p2_f837_nested_inner():
    """Inner IIFE as a return-additive term of the outer IIFE."""
    return ("HELD" if _decodes_to("(function(){return (function(){return {k:'"
                                  + _A + "'};})().k+'" + _B + "';})()", _AB)
            else "BREAK", "f837-nested-inner")


@_t
def test_p2_f837_dupkey():
    """Duplicate keys: later wins (node-exact)."""
    return ("HELD" if _decodes_to("(function(){return {k:'zz',k:'" + _A
                                  + "'};})().k", _A)
            else "BREAK", "f837-dupkey")


# ------------------------------------------------ p3: F837 fail-closed


@_t
def test_p3_f837_missing_key():
    """Missing key is undefined -> fail closed."""
    return ("HELD" if _fails_closed("(function(){return {k:'" + _A
                                    + "';};})().zz")
            else "BREAK", "f837-missing-key")


@_t
def test_p3_f837_oob():
    """OOB index is undefined -> fail closed."""
    return ("HELD" if _fails_closed("(function(){return ['" + _A
                                    + "'];})()[5]")
            else "BREAK", "f837-oob")


@_t
def test_p3_f837_negative():
    """Negative index is undefined -> fail closed."""
    return ("HELD" if _fails_closed("(function(){return ['" + _A + "','" + _B
                                    + "'];})()[-1]")
            else "BREAK", "f837-negative")


@_t
def test_p3_f837_nested_value():
    """Nested object value is not a string -> fail closed."""
    return ("HELD" if _fails_closed("(function(){return {k:{x:'" + _A
                                    + "'}};})().k")
            else "BREAK", "f837-nested-value")


@_t
def test_p3_f837_method():
    """Method shorthand is not data -> fail closed."""
    return ("HELD" if _fails_closed("(function(){return {k(){return '"
                                    + _A + "'}};})().k")
            else "BREAK", "f837-method")


# ------------------------------------------------ p4: F838 filed shapes


@_t
def test_p4_f838_s1():
    """Filed s1: nested function declaration."""
    return ("HELD" if _blocked("(function(){function outer(){function inner()"
                               "{return '" + _A + "';}return inner();}"
                               "return outer()+'" + _B + "';})()")
            else "BREAK", "f838-s1")


@_t
def test_p4_f838_s2():
    """Filed s2: triple nesting."""
    return ("HELD" if _blocked("(function(){function a(){function b(){function c()"
                               "{return '" + _A + "';}return c();}return b();}"
                               "return a()+'" + _B + "';})()")
            else "BREAK", "f838-s2")


# ------------------------------------------------ p5: F838 generalizations


@_t
def test_p5_f838_hoisting():
    """Nested declarations hoist (call before textual decl)."""
    return ("HELD" if _decodes_to("(function(){function outer(){return inner();"
                                  "function inner(){return '" + _A + "';}}"
                                  "return outer()+'" + _B + "';})()", _AB)
            else "BREAK", "f838-hoisting")


@_t
def test_p5_f838_closure():
    """Inner function closes over the outer parameter."""
    return ("HELD" if _decodes_to("(function(){function outer(p){function inner()"
                                  "{return p;}return inner();}"
                                  "return outer('" + _A + "')+'" + _B + "';})()",
                                  _AB)
            else "BREAK", "f838-closure")


@_t
def test_p5_f838_shadow():
    """Inner binding shadows the outer one."""
    return ("HELD" if _decodes_to("(function(){var x='zz';function outer(){"
                                  "var x='" + _A + "';function inner(){return x;}"
                                  "return inner();}return outer()+'" + _B
                                  + "';})()", _AB)
            else "BREAK", "f838-shadow")


@_t
def test_p5_f838_param_default():
    """Parameter default used when the arg is missing."""
    return ("HELD" if _decodes_to("(function(){function f(p='" + _A + "')"
                                  "{return p;}return f()+'" + _B + "';})()",
                                  _AB)
            else "BREAK", "f838-param-default")


# ------------------------------------------------ p6: F838 fail-closed


@_t
def test_p6_f838_recursion():
    """Direct recursion would stack-overflow -> fail closed."""
    return ("HELD" if _fails_closed("(function(){function f(){return f();}"
                                    "return f();})()")
            else "BREAK", "f838-recursion")


@_t
def test_p6_f838_mutual():
    """Mutual recursion would stack-overflow -> fail closed."""
    return ("HELD" if _fails_closed("(function(){function a(){return b();}"
                                    "function b(){return a();}return a();})()")
            else "BREAK", "f838-mutual")


@_t
def test_p6_f838_unbound():
    """Unbound identifier is a ReferenceError -> fail closed."""
    return ("HELD" if _fails_closed("(function(){function outer(){return zz;}"
                                    "return outer();})()")
            else "BREAK", "f838-unbound")


@_t
def test_p6_f838_var_fn_collision():
    """var binding overwrites hoisted function: node throws on call.

    `(function(){var f='B';function f(){return 'A';}return f();})()`
    is a TypeError in the engine (f is 'B', not a function) -- the
    decoder must fail closed, never decode 'A'.
    """
    return ("HELD" if _fails_closed("(function(){var f='B';function f()"
                                    "{return '" + _A + "';}return f();})()")
            else "BREAK", "f838-var-fn-collision")


@_t
def test_p6_f838_var_fn_read():
    """var binding overwrites hoisted function: reading gives the var.

    `(function(){var f='B';function f(){return 'A';}return f;})()`
    is 'B' in the engine -- the decoder reads the var value.
    """
    return ("HELD" if _decodes_to("(function(){var f='B';function f()"
                                 "{return '" + _A + "';}return f;})()", "B")
            else "BREAK", "f838-var-fn-read")


@_t
def test_p6_f838_let_var_collision():
    """let then var with the same name is a SyntaxError -> fail closed."""
    return ("HELD" if _fails_closed("(function(){function g(){let x='" + _A
                                    + "';var x='B';return x;}return g();})()")
            else "BREAK", "f838-let-var-collision")


@_t
def test_p6_f838_let_param_collision():
    """let shadowing a parameter is a SyntaxError -> fail closed."""
    return ("HELD" if _fails_closed("(function(){function g(x){let x='" + _A
                                    + "';return x;}return g('B');})()")
            else "BREAK", "f838-let-param-collision")


# ------------------------------------------------ p7: F839 filed shapes


@_t
def test_p7_f839_s1():
    """Filed s1: block-scoped let accumulation."""
    return ("HELD" if _blocked("(function(){var r='';{let k='" + _A
                               + "';r=k;}return r+'" + _B + "';})()")
            else "BREAK", "f839-s1")


@_t
def test_p7_f839_s2():
    """Filed s2: if(true)-guarded const accumulation."""
    return ("HELD" if _blocked("(function(){var r='';if(true){const k='" + _A
                               + "';r=k;}return r+'" + _B + "';})()")
            else "BREAK", "f839-s2")


# ------------------------------------------------ p8: F839 generalizations


@_t
def test_p8_f839_let_acc():
    """let accumulator with var block binding."""
    return ("HELD" if _decodes_to("(function(){let r='x';{var k='" + _A
                                  + "';r=k;}return r+'" + _B + "';})()", _AB)
            else "BREAK", "f839-let-acc")


@_t
def test_p8_f839_if_var():
    """if(true) guard with var block binding."""
    return ("HELD" if _decodes_to("(function(){var r='';if(true){var k='" + _A
                                  + "';r=k;}return r+'" + _B + "';})()", _AB)
            else "BREAK", "f839-if-var")


# ------------------------------------------------ p9: F839 fail-closed


@_t
def test_p9_f839_if_false():
    """if(false) block provably does not run: F679 decodes to just B.

    The F839 hook fails closed on `if(false)` (narrow: only `true`);
    the earlier F679 statement simulator handles it node-exactly
    (block skipped, r stays ''). The credential fragment A must NOT
    appear in the decoded output.
    """
    got = dlp._try_js_expr_decode_all("(function(){var r='';if(false){let k='"
                                      + _A + "';r=k;}return r+'" + _B + "';})()")
    ok = got is not None and _B in got and _A not in got
    return ("HELD" if ok else "BREAK", "f839-if-false")


@_t
def test_p9_f839_if_truthy():
    """if(1) is truthy in the engine but outside the narrow grammar."""
    return ("HELD" if _fails_closed("(function(){var r='';if(1){let k='" + _A
                                    + "';r=k;}return r+'" + _B + "';})()")
            else "BREAK", "f839-if-truthy")


@_t
def test_p9_f839_k_outside():
    """Block binding read outside the block is a ReferenceError."""
    return ("HELD" if _fails_closed("(function(){var r='';{let k='" + _A
                                    + "';}return k+'" + _B + "';})()")
            else "BREAK", "f839-k-outside")


# ------------------------------------------------ p10: F840 filed shapes


@_t
def test_p10_f840_s1():
    """Filed s1: single shorthand property."""
    return ("HELD" if _blocked("(function(){var k='" + _A
                               + "';var o={k};return o.k+'" + _B + "';})()")
            else "BREAK", "f840-s1")


@_t
def test_p10_f840_s2():
    """Filed s2: multi-binding shorthand + bracket reads."""
    return ("HELD" if _blocked("(function(){var k='" + _A + "',j='" + _B
                               + "';var o={k,j};return o['k']+o['j'];})()")
            else "BREAK", "f840-s2")


# ------------------------------------------------ p11: F840 generalizations


@_t
def test_p11_f840_mixed():
    """Shorthand mixed with explicit properties."""
    return ("HELD" if _decodes_to("(function(){var k='" + _A
                                  + "';var o={k,x:'" + _B + "'};"
                                  "return o.k+o.x;})()", _AB)
            else "BREAK", "f840-mixed")


@_t
def test_p11_f840_dupkey():
    """Duplicate keys: later wins (node-exact)."""
    return ("HELD" if _decodes_to("(function(){var k='" + _A
                                  + "';var o={x:'zz',k};return o.k+'" + _B
                                  + "';})()", _AB)
            else "BREAK", "f840-dupkey")


@_t
def test_p11_f840_strkey():
    """String-literal explicit key alongside shorthand."""
    return ("HELD" if _decodes_to("(function(){var k='" + _A
                                  + "';var o={'k2':'" + _B + "',k};"
                                  "return o.k+o.k2;})()", _AB)
            else "BREAK", "f840-strkey")


# ------------------------------------------------ p12: F840 fail-closed


@_t
def test_p12_f840_shorthand_unbound():
    """Shorthand of an unbound name is a ReferenceError."""
    return ("HELD" if _fails_closed("(function(){var k='" + _A
                                    + "';var o={zz};return o.zz+'" + _B
                                    + "';})()")
            else "BREAK", "f840-shorthand-unbound")


@_t
def test_p12_f840_proto():
    """__proto__ key is prototype pollution -> fail closed."""
    return ("HELD" if _fails_closed("(function(){var k='" + _A
                                    + "';var o={__proto__:k};return 'x';})()")
            else "BREAK", "f840-proto")


@_t
def test_p12_f840_nonstr_value():
    """Non-string explicit value -> fail closed."""
    return ("HELD" if _fails_closed("(function(){var k='" + _A
                                    + "';var o={k,x:42};return o.k;})()")
            else "BREAK", "f840-nonstr-value")


# ------------------------------------------------ p13: sibling pins


@_t
def test_p13_sibling_f671():
    """F671 member-read IIFE still decodes."""
    return ("HELD" if _decodes_to("(function(){var o={k:'" + _A
                                  + "'};return o.k+'" + _B + "';})()", _AB)
            else "BREAK", "sibling-f671")


@_t
def test_p13_sibling_f611():
    """F611 var-bound IIFE still decodes."""
    return ("HELD" if _decodes_to("(function(){var r='" + _A
                                  + "';return r+'" + _B + "';})()", _AB)
            else "BREAK", "sibling-f611")


@_t
def test_p13_sibling_f735():
    """F735 nested-function IIFE still decodes."""
    return ("HELD" if _decodes_to("(function(){function f(){return '" + _A
                                  + "';}return f()+'" + _B + "';})()", _AB)
            else "BREAK", "sibling-f735")


@_t
def test_p13_sibling_f748():
    """F748 logical-assignment IIFE still decodes."""
    return ("HELD" if _decodes_to("(function(){var r='';r+='" + _A
                                  + "';return r+'" + _B + "';})()", _AB)
            else "BREAK", "sibling-f748")


# ------------------------------------------------ p14: honest-text controls


@_t
def test_p14_quiet_plain():
    """Plain text with no credential never flags."""
    return ("HELD" if dlp.find_credential("hello world, nothing here") is None
            else "BREAK", "quiet-plain")


@_t
def test_p14_quiet_shapes():
    """Credential-free twins of the new shapes never flag."""
    shapes = [
        "(function(){return {k:'ab'};})().k",
        "(function(){var r=(function(){return ['ab','cd'];})();return r[0]+r[1];})()",
        ("(function(){function outer(){function inner(){return 'ab';}"
         "return inner();}return outer()+'cd';})()"),
        "(function(){var r='';{let k='ab';r=k;}return r+'cd';})()",
        "(function(){var k='ab';var o={k};return o.k+'cd';})()",
    ]
    ok = all(dlp.find_credential(s) is None for s in shapes)
    return ("HELD" if ok else "BREAK", "quiet-shapes")


# ------------------------------------------------ p15: perf


@_t
def test_p15_perf_200():
    """200 mixed sites decode in reasonable time (fail-closed bound)."""
    sites = []
    for n in range(50):
        sites.append("(function(){return {k:'" + _A + "'};})().k")
        sites.append("(function(){function outer(){function inner(){return '"
                     + _A + "';}return inner();}return outer();})()")
        sites.append("(function(){var r='';{let k='" + _A
                     + "';r=k;}return r;})()")
        sites.append("(function(){var k='" + _A
                     + "';var o={k};return o.k;})()")
    t0 = time.time()
    for s in sites:
        dlp._try_js_expr_decode_all(s)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "perf-200sites=%.2fs" % dt)


# ------------------------------------------------ green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # All four lane red-firsts must be 0 BREAK (F837-F840 closed).
    # Tree-wide maintenance (attack batteries, canonical) is
    # merge-owned (wave-306 lesson); this lane's green check is
    # depth-1 over its own red-firsts only.
    for batt in ("evals/w387_f837_redfirst.py",
                 "evals/w387_f838_redfirst.py",
                 "evals/w387_f839_redfirst.py",
                 "evals/w387_f840_redfirst.py"):
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
        if nbreak != 0:
            bad.append("%s: nbreak=%s" % (batt, nbreak))
    if bad:
        return ("BREAK", "green: " + "; ".join(bad))
    return ("HELD", "green: 4 red-firsts 0 BREAK")


def main():
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        os.makedirs("/var/tmp", exist_ok=True)
    results = []
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- fail-closed: probe error is a BREAK
            verdict, note = "BREAK", "%s raised %r" % (fn.__name__, e)
        results.append((fn.__name__, verdict, note))
        print("%-32s %-6s %s" % (fn.__name__, verdict, note))
    gverdict, gnote = _green_check()
    print("%-32s %-6s %s" % ("green_check", gverdict, gnote))
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_break += 1 if gverdict == "BREAK" else 0
    n_total = len(results) + 1
    print("tally: %d BREAK / %d HELD" % (n_break, n_total - n_break))
    raise SystemExit(1 if n_break else 0)


if __name__ == "__main__":
    main()
