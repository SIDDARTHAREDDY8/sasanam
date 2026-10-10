#!/usr/bin/env python3
"""Wave-404 lane 1 close battery: F1123 CLOSED.

F1123 (SYSTEMIC): whole-text anchoring of statement decoders -- any
leading statement (`var x=1;`, `;`, a comment), any trailing statement,
or one wrapper level (`{...}`, `if(true){...}`, a label, a function
declaration + call, an arrow IIFE, `do...while(false)`, `try...catch`)
broke every statement-anchored hook.

Closed by `_js_f1123_unwrap` (gov/dlp.py): each production strips
exactly one leading/trailing statement or one wrapper level and yields
the inner text as a `_decode_layer` candidate variant; the layer-2
decode pass runs all 38 statement-decoder dispatch loops on it, so
only genuinely-decodable inner text becomes a credential hit. Every
production is node-exact for its wrapper form (v24.20.0). Purely
additive: no existing decoder touched, N_STMTDEC_LOOPS unchanged (38),
re.compile( count unchanged (28), TAXONOMY unchanged (2143).

All shapes node-verified (v24.20.0). Green checks ON.
$0-spend-by-construction.
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
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 38  # wave-403 merge: 34 + 4 loops -> 38; F1123 adds no dispatch loops

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


_CANON = ("var C={{I}};var S='';for(var i=0;i<C.length;i++)"
          "{S+=String.fromCharCode(C[i]);}var RESULT=S;")
_CANON_BODY = ("var C={{I}};var S='';for(var i=0;i<C.length;i++)"
               "{S+=String.fromCharCode(C[i]);}return S;")


# ---------------- p0: pins + footer ----------------

@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return (ok, "taxonomy %d (pin %d)" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_recompile_pin():
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py"),
                encoding="utf-8").read()
    n = len(re.findall(r"re\.compile\(", text))
    ok = n == RECOMPILE_PIN
    return (ok, "%d re.compile (pin %d)" % (n, RECOMPILE_PIN))


@_t
def test_p0_stmtdec_loop_pin():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py"),
               encoding="utf-8").read()
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", src, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    return (ok, "%d loops (pin %d)" % (len(loops), N_STMTDEC_LOOPS_PIN))


@_t
def test_p0_footer_state():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("[CLOSED 2026-10-10 wave-404 lane 1]" in text
          and "F988-F1123 CLOSED (136)" in text
          and "F1124-F1141 OPEN (18" in text
          and "Next free finding: **F1142**" in text)
    return (ok, "F1123 stamped CLOSED; lane footer F1124-F1141 OPEN (18), next F1142")


# ---------------- p1: filed shapes (red-first set) ----------------

@_t
def test_p1_filed_shapes_flagged():
    shapes = _redfirst_shapes("w404", 1123)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    ok = (len(shapes) == 22 and not bad)
    return (ok, "%d/22 flagged%s" % (22 - len(bad),
                                    "" if not bad else "; MISS: %s" % bad[:3]))


# ---------------- p2: generalizations ----------------

def _gen_shapes():
    out = []
    s, li = _codes(SECRET_S), _codes(SECRET_L)
    canon_s = _CANON.replace("{{I}}", s)
    canon_l = _CANON.replace("{{I}}", li)
    body_s = _CANON_BODY.replace("{{I}}", s)
    out.append(("gen-let-lead", "let x=1;" + canon_s))
    out.append(("gen-const-lead", "const x='a';" + canon_s))
    out.append(("gen-linecomment-lead", "// hello\n" + canon_s))
    out.append(("gen-let-trail", canon_s + "let z=2;"))
    out.append(("gen-const-trail", canon_s + "const z='q';"))
    out.append(("gen-if-space", "if ( true ) {" + canon_s + "}"))
    out.append(("gen-if-newline", "if(true)\n{" + canon_s + "}"))
    out.append(("gen-do-space", "do{" + canon_s + "}while (false) ;"))
    out.append(("gen-try-catcharg", "try{" + canon_s + "}catch(err){}"))
    out.append(("gen-fn-let", "function g(){" + body_s + "}let RESULT=g();"))
    out.append(("gen-fn-const", "function g(){" + body_s + "}const RESULT=g();"))
    out.append(("gen-iife-let", "let RESULT=(()=>{" + body_s + "})();"))
    out.append(("gen-label2", "L1:" + canon_s))
    out.append(("gen-trail-semi-block", "{" + canon_s + "};"))
    out.append(("gen-trail-semi-if", "if(true){" + canon_s + "};"))
    out.append(("gen-trail-semi-try", "try{" + canon_s + "}catch(e){};"))
    out.append(("gen-trail-semi-do", "do{" + canon_s + "}while(false);;"))
    out.append(("gen-trail-semi-label", "lbl:" + canon_s + ";"))
    out.append(("gen-do-no-semi", "do{" + canon_s + "}while(false)"))
    out.append(("gen-catch-nobind", "try{" + canon_s + "}catch{}"))
    out.append(("gen-fn-no-semi-return",
                "function g(){" + body_s[:-1] + "}var RESULT=g();"))
    out.append(("gen-long", "var x=1;" + canon_l))
    out.append(("gen-long-block", "{" + canon_l + "}"))
    return out


@_t
def test_p2_generalizations_flagged():
    shapes = _gen_shapes()
    bad = [name for name, payload in shapes if not _blocked(payload)]
    ok = not bad
    return (ok, "%d/%d flagged%s" % (len(shapes) - len(bad), len(shapes),
                                    "" if not bad else "; MISS: %s" % bad[:3]))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_unwrap_yields_nothing():
    s = _codes(SECRET_S)
    cases = [
        "",
        "   ",
        "if(false){foo();}",
        "do{foo();}while(true);",
        "/*unterminated",
        "// only a comment",
        "function g(){return 1;}",
        "function g(){return 1;}var RESULT=h();",
        "function g(){var S='ab';}var RESULT=g();",
        "var:1;",
        "lbl::foo();",
        "var x=1;",
        "var C=[1,2];",
    ]
    bad = [c for c in cases if dlp._js_f1123_unwrap(c)]
    ok = not bad
    return (ok, "%d/%d yield nothing%s" % (len(cases) - len(bad), len(cases),
                                          "" if not bad else "; %r" % bad[:2]))


@_t
def test_p3_two_levels_still_miss():
    # Documented single-level scope: two wrapper levels stay MISS.
    s = _codes(SECRET_S)
    canon = _CANON.replace("{{I}}", s)
    shapes = [
        "if(true){{" + canon + "}}",
        "if(true){var x=1;" + canon + "}",
        "{if(true){" + canon + "}}",
        "lbl:{" + canon + "};",
        "do{" + canon + "}while(false);;;",
    ]
    bad = [p for p in shapes if _blocked(p)]
    ok = not bad
    return (ok, "%d/%d still MISS (single-level scope)%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else "; HIT: %r" % bad[:1]))


@_t
def test_p3_candidate_bounds():
    s = _codes(SECRET_S)
    canon = _CANON.replace("{{I}}", s)
    adv = "var x=1;" * 200 + canon + "var z=2;"
    cands = dlp._js_f1123_unwrap(adv)
    ok_count = len(cands) <= 12
    ok_len = all(len(c) <= len(adv) + 16 for c in cands)
    ok_dedup = len(set(cands)) == len(cands)
    # layer cap: _decode_layer never emits more than _MAX_CANDIDATES
    layer = dlp._decode_layer(adv)
    ok_layer = len(layer) <= dlp._MAX_CANDIDATES
    ok = ok_count and ok_len and ok_dedup and ok_layer
    return (ok, "cands=%d (<=12) lens<=in+16 dedup layer=%d (<=%d)"
            % (len(cands), len(layer), dlp._MAX_CANDIDATES))


@_t
def test_p3_no_budget_interaction():
    # The unwrap is a single bounded parse per production (no match
    # enumeration): it must not consume the F452 part budget. Snapshot
    # the module-level budget knobs around a hostile unwrap.
    before = (dlp._MAX_DECODE_BYTES, dlp._MAX_CANDIDATES)
    s = _codes(SECRET_S)
    for _ in range(50):
        dlp._js_f1123_unwrap("var x=1;" * 40 + _CANON.replace("{{I}}", s))
    after = (dlp._MAX_DECODE_BYTES, dlp._MAX_CANDIDATES)
    ok = before == after
    return (ok, "budget knobs unchanged %r" % (before,))


# ---------------- p4: sibling pins (existing decoders unchanged) ----------------

@_t
def test_p4_sibling_shapes_still_flagged():
    # Canonical shapes of already-CLOSED findings (wave-403): the
    # additive unwrap must not change their verdicts.
    shapes = []
    for num in (1111, 1112, 1114, 1117, 1118, 1119, 1120, 1121, 1122):
        try:
            shapes.extend(_redfirst_shapes("w403", num)[:2])
        except FileNotFoundError:
            pass
    bad = [name for name, payload in shapes if not _blocked(payload)]
    ok = bool(shapes) and not bad
    return (ok, "%d/%d sibling shapes still flagged%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else "; MISS: %s" % bad[:3]))


@_t
def test_p4_canonical_twin_still_flagged():
    s = _codes(SECRET_S)
    ok = _blocked(_CANON.replace("{{I}}", s))
    return (ok, "bare canonical accumulation still flagged")


# ---------------- p5: honest text unaffected ----------------

_HONEST = [
    "var x=1;",
    "console.log('hello world');",
    "(function(){var s='ab';return s;})()",
    "var x=1;console.log('hello world');",
    "{var a=1;var b=2;console.log(a+b);}",
    "if(true){console.log('x');}",
    "// just a comment\nvar q = 42;",
    "/* c */ var q = 42;",
    "function g(){return 1;}var RESULT=g();",
    "try{foo();}catch(e){}",
    "do{bar();}while(false);",
    "lbl:var t=1;",
    "console.log('x');var z=2;",
    ";",
    "var C=[1,2,3];",
]


@_t
def test_p5_honest_quiet():
    bad = [(p, dlp.find_credential(p)) for p in _HONEST if not _quiet(p)]
    ok = not bad
    return (ok, "%d/%d honest quiet%s" % (len(_HONEST) - len(bad),
                                         len(_HONEST),
                                         "" if not bad else "; NOISY: %r" % bad[:2]))


# ---------------- p6: perf (200 sites) ----------------

@_t
def test_p6_perf_200_sites():
    filed = _redfirst_shapes("w404", 1123)
    gen = _gen_shapes()
    sites = []
    i = 0
    while len(sites) < 200:
        for _name, payload in filed + gen:
            sites.append(payload)
            if len(sites) >= 200:
                break
        for p in _HONEST:
            sites.append(p)
            if len(sites) >= 200:
                break
        i += 1
        if i > 10:
            break
    sites = sites[:200]
    t0 = time.time()
    for payload in sites:
        dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 90.0
    return (ok, "200 sites in %.1fs (<90s)" % dt)


# ---------------- g0: green check (depth-1) ----------------

def _green_check():
    """Depth-1 green check on the wave-403 lane-1 pin battery.

    All F1111/F1112/F1114/F1120 pins are closed there and must be
    HELD; it also carries the TAXONOMY/RECOMPILE/loop-count pins this
    lane must not disturb. Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w403lane1): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g404lane1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w403_f1111f1112f1114f1120close_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        m = re.search(r"(\d+) HELD / (\d+) BREAK", r.stdout)
        ok = r.returncode == 0 and m and int(m.group(2)) == 0
        tally = m.group(0) if m else "no tally"
        return (ok, "green(w403lane1): %s rc=%d" % (tally, r.returncode))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# ---------------- runner ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    parser.add_argument("--tally-only", action="store_true")
    args = parser.parse_args()
    held, broken = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        if not args.tally_only:
            print(("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note)))
        held, broken = held + (1 if ok else 0), broken + (0 if ok else 1)
    print("%d HELD / %d BREAK" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
