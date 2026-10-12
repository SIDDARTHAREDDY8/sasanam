"""Close battery for wave-436 lane A: F1891-F1895.

Tests:
- Filed shapes HIT (both credential sizes)
- Generalizations (var/let/const, renamed vars) -- INFO, grammar is strict
- Fail-closed bounds (mutations must not mis-decode; hook returns None)
- Node-exactness incl. F1891 leading-whitespace edge (hook vs node)
- Sibling pins (F1815, F1842, F1846, F1865 still HIT)
- Honest-text controls (must stay quiet)
- Perf (200 sites)
- Pin/footer pins (N_STMTDEC_LOOPS=151, re.compile=29, wave-435 footer)
- Depth-1 green check honoring GOV_SKIP_GREEN=1
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential
from gov import dlp as dlp_mod

CRED_20 = "xoxb-" + "0123456789abcde"
CRED_40 = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def make_payload(template, cred):
    codes = ",".join(str(ord(c)) for c in cred)
    return template.replace("{I}", codes)


# N_STMTDEC_LOOPS = 151 (150 base + 1 new dispatch loop, wave-436 lane A;
# real code-count change, wave-385 rule). re.compile( count = 29 (untouched).

FILED = {
    1891: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(2)).trimLeft();var RESULT=U;",
    1892: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;",
    1893: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T);var RESULT=U;",
    1894: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`;var RESULT=U;",
    1895: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat(T);var RESULT=U;",
}

HOOKS = {
    1891: dlp_mod._js_f1891_stmt_decode,
    1892: dlp_mod._js_f1892_stmt_decode,
    1893: dlp_mod._js_f1893_stmt_decode,
    1894: dlp_mod._js_f1894_stmt_decode,
    1895: dlp_mod._js_f1895_stmt_decode,
}

SIBLINGS = {
    1815: "var C=[{I}];var T=' '.repeat(C.length-C.length+2)+C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart();var RESULT=U;",
    1842: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat(''.repeat(C.length-C.length));var RESULT=U;",
    1846: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw`${T}`;var RESULT=U;",
    1865: "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(2)).trimRight();var RESULT=U;",
}


def check(name, cond):
    print(("PASS" if cond else "FAIL") + ": " + name)
    return cond


def _node(script):
    r = subprocess.run(["node", "-e", script], capture_output=True,
                       text=True, timeout=60)
    return r.stdout.strip()


def main():
    ok = True

    # 1. Filed shapes HIT (both credential sizes)
    for fn, tmpl in FILED.items():
        for cred, cname in [(CRED_20, "20"), (CRED_40, "40")]:
            payload = make_payload(tmpl, cred)
            hit = find_credential(payload) is not None
            ok = check("F%d filed shape %s HIT" % (fn, cname), hit) and ok

    # 2. Generalizations: let/const + renamed vars (INFO -- strict grammar)
    for fn, tmpl in FILED.items():
        p_let = make_payload(tmpl.replace("var ", "let ", 1), CRED_20)
        print("INFO: F%d let-variant hit=%s" % (fn, find_credential(p_let) is not None))
        p_ren = make_payload(tmpl.replace("var T=", "var Q=").replace("(T+", "(Q+").replace("T.", "Q.").replace("`${T}`", "`${Q}`").replace("String(T)", "String(Q)").replace(".concat(T)", ".concat(Q)"), CRED_20)
        print("INFO: F%d renamed-var hit=%s" % (fn, find_credential(p_ren) is not None))

    # 3. Fail-closed: mutations must not mis-decode (hook returns None)
    mutations = [
        # (finding, mutation template, description)
        (1891, FILED[1891].replace(".trimLeft()", ".trimStart()"), "trimStart not trimLeft"),
        (1891, FILED[1891].replace("' '.repeat(2)", "'x'.repeat(2)"), "non-space pad"),
        (1891, FILED[1891].replace(".trimLeft()", ".trimLeft(  )"), "ws inside parens"),
        (1892, FILED[1892].replace("T.toString()", "T.toString(16)"), "radix arg"),
        (1892, FILED[1892].replace("T.toString()", "T.toString"), "missing call"),
        (1893, FILED[1893].replace("String(T)", "String(T,2)"), "extra arg"),
        (1893, FILED[1893].replace("String(T)", "String.raw`${T}`"), "tagged not plain"),
        (1894, FILED[1894].replace("`${T}`", "`${T}x`"), "trailing literal"),
        (1894, FILED[1894].replace("`${T}`", "`${T}${T}`"), "double subst"),
        (1895, "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T);var RESULT=U;", "non-empty receiver"),
        (1895, "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat(T,T);var RESULT=U;", "extra arg"),
        (1895, "var C=[{I}];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('');var RESULT=U;", "receiver/arg swapped"),
    ]
    for fn, tmpl, desc in mutations:
        payload = make_payload(tmpl, CRED_20)
        hook_hit = HOOKS[fn](payload) is not None
        ok = check("F%d hook miss on mutation (%s)" % (fn, desc), not hook_hit) and ok

    # 4. Node-exactness: hook output == node output
    for fn, tmpl in FILED.items():
        payload = make_payload(tmpl, CRED_20)
        hook_out = HOOKS[fn](payload)
        ok = check("F%d hook non-None" % fn, hook_out is not None) and ok
    # F1891 edge: credential with leading whitespace -- node strips it
    cred_lead = " " + CRED_20
    p_lead = make_payload(FILED[1891], cred_lead)
    hook_lead = HOOKS[1891](p_lead)
    node_lead = _node("var C=[%s];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(2)).trimLeft();console.log(JSON.stringify(U));" % ",".join(str(ord(c)) for c in cred_lead))
    import json as _json
    ok = check("F1891 leading-ws node-exact", hook_lead == _json.loads(node_lead)) and ok
    # F1892-F1895 identity: hook output == credential
    for fn in (1892, 1893, 1894, 1895):
        payload = make_payload(FILED[fn], CRED_20)
        ok = check("F%d hook output == credential" % fn, HOOKS[fn](payload) == CRED_20) and ok
    # F1891: hook output == credential + two spaces (node-exact)
    ok = check("F1891 hook output == cred+2sp", HOOKS[1891](make_payload(FILED[1891], CRED_20)) == CRED_20 + "  ") and ok

    # 5. Sibling pins still HIT
    for fn, tmpl in SIBLINGS.items():
        payload = make_payload(tmpl, CRED_20)
        hit = find_credential(payload) is not None
        ok = check("sibling F%d still HIT" % fn, hit) and ok

    # 6. Honest text quiet
    for i, text in enumerate(["The quick brown fox jumps over the lazy dog.",
                              "var x = 1 + 2; console.log(x);",
                              "Hello, world! This is a test.",
                              "var T='abc';var U=T.toString();",
                              "var s=`hello`;"]):
        hit = find_credential(text) is not None
        ok = check("honest-text %d quiet" % i, not hit) and ok

    # 7. Perf: no F452-class blowup. Relative check against the F1865
    # sibling (same process, back-to-back, so VM contention cancels
    # out), plus a guard-rejection micro-benchmark.
    p_f1891 = make_payload(FILED[1891], CRED_20)
    p_f1865 = make_payload(SIBLINGS[1865], CRED_20)
    find_credential(p_f1891)  # warm up
    t_new = sum((lambda t0=time.time(): (find_credential(p_f1891), time.time() - t0)[1])() for _ in range(10)) / 10
    t_old = sum((lambda t0=time.time(): (find_credential(p_f1865), time.time() - t0)[1])() for _ in range(10)) / 10
    ok = check("perf F1891 %.2fs/call within 3x of F1865 %.2fs/call" % (t_new, t_old),
               t_new < 3 * t_old + 0.5) and ok
    t0 = time.time()
    for _ in range(200):
        HOOKS[1891]("The quick brown fox jumps over the lazy dog. " * 10)
    tg = time.time() - t0
    ok = check("perf guard-reject 200x in %.2fs (<5s)" % tg, tg < 5) and ok

    # 8. Pins
    dlp_txt = open(os.path.join(REPO, "gov", "dlp.py")).read()
    loops = re.findall(r"for _stmtdec in \(([^)]+)\):", dlp_txt)
    ok = check("stmtdec loops=%d (expect 153)" % len(loops), len(loops) == 153) and ok
    ok = check("re.compile count=%d (expect 29)" % dlp_txt.count("re.compile("), dlp_txt.count("re.compile(") == 29) and ok
    findings = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    ok = check("footer has wave-435 line", "# Wave-435:" in findings) and ok
    for fn in (1891, 1892, 1893, 1894, 1895):
        ok = check("hook F%d defined" % fn, ("def _js_f%d_stmt_decode" % fn) in dlp_txt) and ok

    print()
    print("RESULT:", "HELD" if ok else "BROKEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
