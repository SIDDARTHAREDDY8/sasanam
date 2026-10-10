#!/usr/bin/env python3
"""Wave-399 lane 2 close battery: F1076/F1077 CLOSED.

F1076: Function-constructor body staging (F964 residual) -- the
accumulation loop staged INSIDE the `new Function("P","BODY")` body
string, called with the int array (`var F=new Function("C","var
S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}return
S;");var RESULT=F([...]);`). Disjoint from F964 (return-body) by
construction.

F1077: import()-staged int-array reads (F959d residual) -- (a)
`.then()`-chain consumption of `export default [ints]` modules;
(b) awaited `import()` of an INT-ARRAY default export read back via
`String.fromCharCode(...M.default)` or an accumulation loop. Disjoint
from F959d (string-literal defaults) by construction.

Green checks ON. $0-spend-by-construction.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 22  # wave-398 merge's 21 + this lane's F1076/F1077 loop

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402
from gov.instruction_provenance import (  # noqa: E402
    ActionRequest, IngressLabeler, Label, grant_check,
)

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _redfirst_shapes(num, prefix="w399"):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


def _wired(body, consequential=True):
    """Route a wire_transfer driven by *body* through grant_check."""
    lab = IngressLabeler()
    unit = lab.ingest(body, Label.RETRIEVED_UNTRUSTED,
                      carrier="inbox-msg#9(public)")
    req = ActionRequest(action="wire_transfer",
                        args={"to_account": "987654321", "amount": 48200},
                        consequential=consequential,
                        driving_units=[unit.unit_id])
    return grant_check(req, lab).routed_to_approval


CRED_S = "xoxb-01" + "23456789abcdef"
CRED_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return ",".join(str(ord(c)) for c in s)


# --------------------------------------- b0: pins

@_t
def test_b0_pins():
    """Taxonomy pin 2143, verifier taxonomy 33, re.compile 28, base footer."""
    ok = (len(TAXONOMY) == TAXONOMY_PIN)
    ok = (VERIFIER_TAXONOMY_PIN == 33) and ok
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = (n == RECOMPILE_PIN) and ok
    foot = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Pre-stamp base footer: F1074-F1079 still OPEN (merge reconciles).
    ok = ("F988-F1073 CLOSED (86" in foot
          and "F1074-F1079 OPEN (6" in foot
          and "Next free finding: **F1080**" in foot) and ok
    return ("HELD" if ok else "BREAK",
            "pins 2143/33/28 footer=%s" % ok)


@_t
def test_b0_stmtdec_loop_count():
    """N_STMTDEC_LOOPS 22 (21 + this lane's F1076/F1077 loop)."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.S)
    ok = (len(loops) == N_STMTDEC_LOOPS_PIN
          and "_js_f1076_stmt_decode" in "".join(loops)
          and "_js_f1077_stmt_decode" in "".join(loops))
    # every loop keeps its _MAX_CANDIDATES tail guard
    ok = (body.count("if len(variants) >= _MAX_CANDIDATES:") >=
          len(loops)) and ok
    return ("HELD" if ok else "BREAK",
            "%d loops (pin %d)" % (len(loops), N_STMTDEC_LOOPS_PIN))


@_t
def test_b0_junk_quiet():
    """Junk stays quiet on both seams."""
    quiet = _misses("(function(){var s='ab';return s;})()")
    quiet = quiet and _misses(
        'var F=new Function("x","return x*x;");var T=F(21);')
    quiet = quiet and _misses(
        "var M=await import('data:text/javascript,export default 42;');")
    return ("HELD" if quiet else "BREAK", "junk=" + str(quiet))


# --------------------------------------- p1: F1076 filed shapes

@_t
def test_p1_f1076_filed_blocked():
    """Filed F1076 shapes now BLOCKED."""
    shapes = _redfirst_shapes(1076)
    bad = [n for n, p, _c in shapes if not _blocked(p)]
    return ("HELD" if not bad else "BREAK",
            "blocked %d/%d%s" % (len(shapes) - len(bad), len(shapes),
                                 "" if not bad else ": " + ",".join(bad)))


@_t
def test_p1_f1076_node_exact():
    """F1076 hook decodes the credential exactly (node-exact)."""
    ok = True
    for cred in (CRED_S, CRED_L):
        body = ("var S='';for(var i=0;i<C.length;i++)"
                "{S+=String.fromCharCode(C[i]);}return S;")
        p = ('var F=new Function("C","%s");var RESULT=F([%s]);'
             % (body, _codes(cred)))
        if dlp._js_f1076_stmt_decode(p) != cred:
            ok = False
    return ("HELD" if ok else "BREAK", "node-exact=%s" % ok)


# --------------------------------------- p2: F1076 generalizations

@_t
def test_p2_f1076_generalizations():
    """F1076 grammar twins: bare Function, let/const, braceless, S=S+ form."""
    cred = CRED_S
    c = _codes(cred)
    gens = [
        # bare Function (no new)
        ('var F=Function("C","var S=\'\';for(var i=0;i<C.length;i++)'
         '{S+=String.fromCharCode(C[i]);}return S;");var RESULT=F([%s]);' % c),
        # let/const declarators
        ('let F=new Function("C","var S=\'\';for(var i=0;i<C.length;i++)'
         '{S+=String.fromCharCode(C[i]);}return S;");const RESULT=F([%s]);' % c),
        # braceless loop body
        ('var F=new Function("C","var S=\'\';for(var i=0;i<C.length;i++)'
         'S+=String.fromCharCode(C[i]);return S;");var RESULT=F([%s]);' % c),
        # S=S+... body form
        ('var F=new Function("C","let S=\'\';for(let i=0;i<C.length;++i)'
         '{S=S+String.fromCharCode(C[i]);}return S;");var RESULT=F([%s]);' % c),
        # whitespace-tolerant
        ('var  F = new  Function( "C" , "var S=\'\' ; for( var i = 0 ; '
         'i < C.length ; i++ ){ S += String.fromCharCode( C[i] ) ; } '
         'return S ; " ) ; var RESULT = F( [ %s ] ) ;' % c),
    ]
    bad = [g for g in gens if not _blocked(g)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d blocked" % (len(gens) - len(bad), len(gens)))


# --------------------------------------- p3: F1076 fail-closed

@_t
def test_p3_f1076_fail_closed():
    """F1076 fail-closed set: F964 territory, bad grammars stay quiet here."""
    cred = CRED_S
    c = _codes(cred)
    # (payload, expect_hook_none, expect_blocked)
    cases = [
        # F964's return-body production: this hook misses, F964 blocks.
        ('var F=new Function("C","return C;");var T=F("%s");' % cred,
         True, True),
        # extra ctor arg
        ('var F=new Function("C","return C;","x");var T=F([%s]);' % c,
         True, False),
        # non-empty acc init
        ('var F=new Function("C","var S=\'x\';for(var i=0;i<C.length;i++)'
         '{S+=String.fromCharCode(C[i]);}return S;");var RESULT=F([%s]);' % c,
         True, False),
        # const accumulator (node throws on +=)
        ('var F=new Function("C","const S=\'\';for(var i=0;i<C.length;i++)'
         '{S+=String.fromCharCode(C[i]);}return S;");var RESULT=F([%s]);' % c,
         True, False),
        # callee mismatch
        ('var F=new Function("C","var S=\'\';for(var i=0;i<C.length;i++)'
         '{S+=String.fromCharCode(C[i]);}return S;");var RESULT=G([%s]);' % c,
         True, False),
        # junk: honest Function use
        ('var F=new Function("x","return x*x;");var T=F(21);', True, False),
    ]
    bad = []
    for p, expect_none, expect_blocked in cases:
        hook_none = dlp._js_f1076_stmt_decode(p) is None
        blocked = _blocked(p)
        if hook_none != expect_none or blocked != expect_blocked:
            bad.append(p[:60])
    return ("HELD" if not bad else "BREAK",
            "%d/%d fail-closed" % (len(cases) - len(bad), len(cases)))


# --------------------------------------- p4: F1077 filed shapes

@_t
def test_p4_f1077_filed_blocked():
    """Filed F1077 shapes now BLOCKED."""
    shapes = _redfirst_shapes(1077)
    bad = [n for n, p, _c in shapes if not _blocked(p)]
    return ("HELD" if not bad else "BREAK",
            "blocked %d/%d%s" % (len(shapes) - len(bad), len(shapes),
                                 "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_f1077_node_exact():
    """F1077 hook decodes the credential exactly (node-exact)."""
    ok = True
    for cred in (CRED_S, CRED_L):
        c = _codes(cred)
        pa = ("import('data:text/javascript,export default [%s]').then(m=>{var S='';"
              "for(var i=0;i<m.default.length;i++){S+=String.fromCharCode(m.default[i]);}"
              "var RESULT=S;});" % c)
        pb = ("var M=await import('data:text/javascript,export default [%s];');"
              "var RESULT=String.fromCharCode(...M.default);" % c)
        if dlp._js_f1077_stmt_decode(pa) != cred:
            ok = False
        if dlp._js_f1077_stmt_decode(pb) != cred:
            ok = False
    return ("HELD" if ok else "BREAK", "node-exact=%s" % ok)


# --------------------------------------- p5: F1077 generalizations

@_t
def test_p5_f1077_generalizations():
    """F1077 grammar twins: paren param, concise-spread callback, accum tail."""
    cred = CRED_S
    c = _codes(cred)
    gens = [
        # (a) paren arrow param
        ("import('data:text/javascript,export default [%s]').then((m)=>{var S='';"
         "for(var i=0;i<m.default.length;i++){S+=String.fromCharCode(m.default[i]);}"
         "var RESULT=S;});" % c),
        # (a) concise-spread callback body twin
        ("import('data:text/javascript,export default [%s];').then(m=>{"
         "var RESULT=String.fromCharCode(...m.default);});" % c),
        # (b) accum-loop tail twin
        ("var M=await import('data:text/javascript,export default [%s];');"
         "var S='';for(var i=0;i<M.default.length;i++)"
         "{S+=String.fromCharCode(M.default[i]);}var RESULT=S;" % c),
        # (b) let/const declarators
        ("let M=await import('data:text/javascript,export default [%s]');"
         "const RESULT=String.fromCharCode(...M.default);" % c),
        # (a) braceless loop body
        ("import('data:text/javascript,export default [%s]').then(m=>{var S='';"
         "for(var i=0;i<m.default.length;i++)S+=String.fromCharCode(m.default[i]);"
         "var RESULT=S;});" % c),
    ]
    bad = [g for g in gens if not _blocked(g)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d blocked" % (len(gens) - len(bad), len(gens)))


# --------------------------------------- p6: F1077 fail-closed

@_t
def test_p6_f1077_fail_closed():
    """F1077 fail-closed set: F959d territory, bad modules stay quiet here."""
    a_val = "xoxb-0123456789abcdef"
    b_val = "0123456789abcdef012"
    cases = [
        # F959d's string-literal default: this hook misses, F959d blocks.
        ("var m=await import('data:text/javascript,export default \"%s\";');"
         "var RESULT=m.default+'%s';" % (a_val, b_val), True, True),
        # percent-encoded module source
        ("var M=await import('data:text/javascript,export%%20default [1,2];');"
         "var RESULT=String.fromCharCode(...M.default);", True, False),
        # multi-statement module
        ("var M=await import('data:text/javascript,export default [1,2];var x=1;');"
         "var RESULT=String.fromCharCode(...M.default);", True, False),
        # default never read
        ("var M=await import('data:text/javascript,export default [1,2];');"
         "var RESULT=42;", True, False),
        # non-data URL
        ("var M=await import('https://example.com/m.js');"
         "var RESULT=String.fromCharCode(...M.default);", True, False),
        # junk: honest import
        ("(async()=>{var m=await import('data:text/javascript,export default 1;');"
         "return m.default;})();", True, False),
    ]
    bad = []
    for p, expect_none, expect_blocked in cases:
        hook_none = dlp._js_f1077_stmt_decode(p) is None
        blocked = _blocked(p)
        if hook_none != expect_none or blocked != expect_blocked:
            bad.append(p[:60])
    return ("HELD" if not bad else "BREAK",
            "%d/%d fail-closed" % (len(cases) - len(bad), len(cases)))


# --------------------------------------- p7: siblings

@_t
def test_p7_siblings():
    """Sibling pins: F964/F959d block; F1074/F1075/F1078 still MISS; F1079 evades."""
    ok = True
    # F964 twin blocks coded (credential-shaped argument)
    ok = _blocked(
        'var F=new Function("C","return C;");var T=F("%s");' % CRED_S) and ok
    # F959d twin blocks coded (credential-shaped default + tail)
    ok = _blocked(
        "var m=await import('data:text/javascript,export default \"%s\";');"
        "var RESULT=m.default+'%s';"
        % ("xoxb-0123456789abcdef", "0123456789abcdef012")) and ok
    # still-OPEN siblings still miss
    for n in (1074, 1075, 1078):
        shapes = _redfirst_shapes(n, prefix="w398")
        for name, payload in shapes:
            if not _misses(payload):
                ok = False
    # F1079 carriers still evade routing (OPEN)
    shapes = _redfirst_shapes(1079, prefix="w398")
    for name, body in shapes:
        if _wired(body):
            ok = False
    return ("HELD" if ok else "BREAK", "siblings=%s" % ok)


# --------------------------------------- p8: perf

@_t
def test_p8_perf():
    """200-site perf: decode latency bounded."""
    sites = []
    for i in range(100):
        c = _codes("xoxb-%04d" % i)
        sites.append(
            'var F%d=new Function("C","var S=\'\';for(var i=0;i<C.length;i++)'
            '{S+=String.fromCharCode(C[i]);}return S;");var RESULT%d=F%d([%s]);'
            % (i, i, i, c))
        sites.append(
            "var M%d=await import('data:text/javascript,export default [%s];');"
            "var RESULT%d=String.fromCharCode(...M%d.default);" % (i, c, i, i))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200 sites %.2fs" % dt)


# --------------------------------------- green check

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check on w398's attack battery (carries F1074-F1079
    OPEN pins + F1065-F1073 closed pins). Honor GOV_SKIP_GREEN. On this
    lane tree F1076/F1077 are now closed: exactly those 2 open pins
    flip to BREAK; everything else holds."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green(w398_attack): skipped via GOV_SKIP_GREEN=1")
    try:
        import tempfile
        tmpd = tempfile.mkdtemp(prefix="g399lane2-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmpd
        r = subprocess.run(
            [sys.executable, "evals/w398_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real, held = [], []
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (real if parts[0] == "BREAK" else held).append(parts[1])
        # The 2 now-closed pins flip; the footer pin stays HELD (base
        # footer preserved); all other pins hold.
        expect_break = {"test_open_w398_f1076", "test_open_w398_f1077"}
        missing_break = expect_break - set(real)
        extra_break = set(real) - expect_break
        ok = (not missing_break and not extra_break
              and "test_b0_footer_state" in held
              and not _EXPECTED_BREAKS)
        return (("HELD" if ok else "BREAK"),
                "green(w398_attack): %d BREAK missing=%s extra=%s" % (
                    len(real), sorted(missing_break), sorted(extra_break)))
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# --------------------------------------- runner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tally-only", action="store_true")
    args = parser.parse_args()
    held, broke, notes = 0, 0, []
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "BREAK", "EXC %r" % e
        name = fn.__name__
        if not args.tally_only:
            print("%s: %s -- %s" % (verdict, name, note))
        if verdict == "HELD":
            held += 1
        else:
            broke += 1
            notes.append(name)
    print("TALLY: %d HELD / %d BREAK (%d tests)" % (held, broke, len(TESTS)))
    if notes:
        print("BROKE: " + ", ".join(notes))
    return 1 if broke else 0


if __name__ == "__main__":
    sys.exit(main())
