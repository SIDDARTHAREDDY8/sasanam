#!/usr/bin/env python3
"""Wave-400 lane 1 close battery: F1083/F1084 CLOSED.

F1083: Object.create prototype-staged accumulation reads -- staging the
int array on the PROTOTYPE via `Object.create` broke the decoder's
int-array productions, which require a plain-identifier array binding.
Closed by _js_f1083_stmt_decode (whole-text _stmtdec hook): optional
named proto decl `{key:[INTS]}` (exactly one property, __proto__ fails
closed) or inline literal, `O=Object.create(P|{lit})`, then a C-style
indexed accumulation for-loop over `O.k`/`O["k"]` (reusing
_js_f1074f1075_parse_for/_js_f1074f1075_sim), simulated node-exactly
(v24.20.0). Disjoint from F1005 (RESULT concatenation, no loop),
F1045 (requires Object.setPrototypeOf), F1074 (requires plain-ident
array -- `{` fails its parse).

F1084: comma-operator chain staging reads -- the accumulation riding
the for-update clause (`for(I=0;I<C.length;S+=f(C[I]),I++);`) or a
single comma-expression while body (`while(I<C.length){I++,S+=f(C[I-1]);}`)
broke the statement-anchored hook grammars. Closed by
_js_f1084_stmt_decode: a 2-operand comma chain of exactly one increment
and one accumulation, with node-exact index sequencing (bare `I` when
the accumulation precedes the increment, `I-1` when it follows),
simulated via _js_f1074f1075_sim. Disjoint from F1074 (its for-update
is a bare increment; its loop bodies are ;-separated statements).

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
N_STMTDEC_LOOPS_PIN = 25  # wave-399 merge: 24 + this lane's loop (real code-count change)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _redfirst_shapes(num, prefix="w400"):
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


# ---------------- p0: pins ----------------

@_t
def test_p0_taxonomy_pin():
    return (len(TAXONOMY) == TAXONOMY_PIN,
            "taxonomy=%d pin=%d" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_verifier_pin():
    # evidence-schema domain pin (self-referential by convention)
    return (VERIFIER_TAXONOMY_PIN == 33,
            "verifier_pin=%d" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    return (n == RECOMPILE_PIN, "re.compile=%d pin=%d" % (n, RECOMPILE_PIN))


@_t
def test_p0_stmtdec_loops():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    mine = [lp for lp in loops if "_js_f1083_stmt_decode" in lp]
    ok = ok and len(mine) == 1 and "_js_f1084_stmt_decode" in mine[0]
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-400 lane 1" in src
          and "F1083-F1084 CLOSED (2" in src
          and "F1085-F1089 OPEN (5" in src
          and "Next free finding: **F1090**" in src
          and "F988-F1084 CLOSED (97" in src)
    # entry-count check: F1083/F1084 stamped CLOSED exactly once each.
    ok = ok and src.count("(F1083 filed") == 1 and src.count("(F1084 filed") == 1
    ok = ok and "[CLOSED 2026-10-10 wave-400 lane 1" in src
    return (ok, "lane-local footer present")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1083_filed_block():
    shapes = _redfirst_shapes(1083)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1084_filed_block():
    shapes = _redfirst_shapes(1084)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


# (name, template, hook): hook is the hook-level decoder for variants
# whose decoded value is not credential-shaped (start=1, <=).
_GEN_1083 = [
    ("g-inline-lit", "var O=Object.create({k:%s});var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;", False),
    ("g-bracket", "var P={k:%s};var O=Object.create(P);var S='';for(var I=0;I<O[\"k\"].length;I++){S+=String.fromCharCode(O[\"k\"][I]);}var RESULT=S;", False),
    ("g-lte", "var P={k:%s};var O=Object.create(P);var S='';for(var I=0;I<=O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;", True),
    ("g-start1", "var P={k:%s};var O=Object.create(P);var S='';for(var I=1;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;", True),
    ("g-self-plus", "var P={k:%s};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S=S+String.fromCharCode(O.k[I]);}var RESULT=S;", False),
    ("g-unbraced", "var P={k:%s};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++)S+=String.fromCharCode(O.k[I]);var RESULT=S;", False),
    ("g-let-const", "let P={k:%s};const O=Object.create(P);let S='';for(let I=0;I<O.k.length;I+=1){S+=String.fromCharCode(O.k[I]);}const RESULT=S;", False),
    ("g-key-abc", "var P={abc:%s};var O=Object.create(P);var S='';for(var I=0;I<O.abc.length;I++){S+=String.fromCharCode(O.abc[I]);}var RESULT=S;", False),
    ("g-quoted-key", "var P={'k':%s};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;", False),
    ("g-pp-incr", "var P={k:%s};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;++I){S+=String.fromCharCode(O.k[I]);}var RESULT=S;", False),
    ("g-result-add", "var P={k:%s};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT='pre:'+S;", False),
]

_GEN_1084 = [
    ("g-for-incr-first", "var C=%s;var S='';var I=0;for(I=0;I<C.length;I++,S+=String.fromCharCode(C[I-1]));var RESULT=S;", False),
    ("g-while-accum-first", "var C=%s;var S='';var I=0;while(I<C.length){S+=String.fromCharCode(C[I]),I++;}var RESULT=S;", False),
    ("g-for-lte", "var C=%s;var S='';var I=0;for(I=0;I<=C.length;S+=String.fromCharCode(C[I]),I++);var RESULT=S;", True),
    ("g-while-lte", "var C=%s;var S='';var I=0;while(I<=C.length){I++,S+=String.fromCharCode(C[I-1]);}var RESULT=S;", True),
    ("g-for-no-predecl", "var C=%s;var S='';for(var I=0;I<C.length;S+=String.fromCharCode(C[I]),I++);var RESULT=S;", False),
    ("g-for-start1", "var C=%s;var S='';var I=1;for(I=1;I<C.length;S+=String.fromCharCode(C[I]),I++);var RESULT=S;", True),
    ("g-for-predecl1-header0", "var C=%s;var S='';var I=1;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I++);var RESULT=S;", False),
    ("g-while-start1", "var C=%s;var S='';var I=1;while(I<C.length){I++,S+=String.fromCharCode(C[I-1]);}var RESULT=S;", True),
    ("g-self-plus", "var C=%s;var S='';var I=0;for(I=0;I<C.length;S=S+String.fromCharCode(C[I]),I++);var RESULT=S;", False),
    ("g-pp-incr", "var C=%s;var S='';var I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),++I);var RESULT=S;", False),
    ("g-pluseq1-incr", "var C=%s;var S='';var I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I+=1);var RESULT=S;", False),
    ("g-let-const", "const C=%s;let S='';let I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I++);const RESULT=S+'!';", False),
]


@_t
def test_p2_generalizations():
    bad = []
    for name, tmpl, hook_level in _GEN_1083:
        p = tmpl % _codes(SECRET_S)
        hit = (dlp._js_f1083_stmt_decode(p) is not None) if hook_level else _blocked(p)
        if not hit:
            bad.append(name)
    for name, tmpl, hook_level in _GEN_1084:
        p = tmpl % _codes(SECRET_S)
        hit = (dlp._js_f1084_stmt_decode(p) is not None) if hook_level else _blocked(p)
        if not hit:
            bad.append(name)
    total = len(_GEN_1083) + len(_GEN_1084)
    return (not bad, "%d/%d generalizations blocked" % (total - len(bad), total))


# ---------------- p3: fail-closed bounds ----------------
# Each must MISS at the hook level (a miss, never a mis-decode).

_FC_1083 = [
    ("fc-create-null",
     "var O=Object.create(null);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;"),
    ("fc-create-2args",
     "var P={k:%s};var O=Object.create(P,{});var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;"),
    ("fc-proto-key",
     "var P={__proto__:%s};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;"),
    ("fc-two-props",
     "var P={k:%s,j:%s};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;"),
    ("fc-wrong-key",
     "var P={k:%s};var O=Object.create(P);var S='';for(var I=0;I<O.j.length;I++){S+=String.fromCharCode(O.j[I]);}var RESULT=S;"),
    ("fc-undeclared-proto",
     "var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;"),
    ("fc-empty-arr",
     "var P={k:[]};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;"),
    ("fc-str-value",
     "var P={k:'abc'};var O=Object.create(P);var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;"),
    ("fc-f1005-shape",
     "var P={k0:'ab',k1:'cd'};var O=Object.create(P);var RESULT=O.k0+O.k1;"),
    ("fc-setproto-shape",
     "var P={k:%s};var O=Object.setPrototypeOf({},P);var RESULT=String.fromCharCode(...O.k);"),
]

_FC_1084 = [
    ("fc-wrong-order-for",
     "var C=%s;var S='';var I=0;for(I=0;I<C.length;I++,S+=String.fromCharCode(C[I]));var RESULT=S;"),
    ("fc-wrong-order-accum-first",
     "var C=%s;var S='';var I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I-1]),I++);var RESULT=S;"),
    ("fc-three-operands",
     "var C=%s;var S='';var I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I++,S+='x');var RESULT=S;"),
    ("fc-plain-for",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("fc-f1074-while",
     "var C=%s;var S='';var I=0;while(I<C.length){S+=String.fromCharCode(C[I]);I++;}var RESULT=S;"),
    ("fc-while-no-predecl",
     "var C=%s;var S='';while(I<C.length){I++,S+=String.fromCharCode(C[I-1]);}var RESULT=S;"),
    ("fc-for-nonempty-body",
     "var C=%s;var S='';var I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I++){S+='x';}var RESULT=S;"),
    ("fc-for-no-comma",
     "var C=%s;var S='';var I=0;for(I=0;I<C.length;I++);var RESULT=S;"),
    ("fc-while-two-stmts",
     "var C=%s;var S='';var I=0;while(I<C.length){I++;S+=String.fromCharCode(C[I]);}var RESULT=S;"),
    ("fc-spread-accum",
     "var C=%s;var S='';var I=0;for(I=0;I<C.length;S+=String.fromCharCode(...C),I++);var RESULT=S;"),
    ("fc-wrong-arr",
     "var C=%s;var S='';var I=0;for(I=0;I<D.length;S+=String.fromCharCode(C[I]),I++);var RESULT=S;"),
    ("fc-empty-arr",
     "var C=[];var S='';var I=0;for(I=0;I<C.length;S+=String.fromCharCode(C[I]),I++);var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    bad = []
    for name, tmpl in _FC_1083:
        n = tmpl.count("%s")
        p = tmpl if n == 0 else tmpl % tuple([_codes(SECRET_S)] * n)
        if dlp._js_f1083_stmt_decode(p) is not None:
            bad.append(name)
    for name, tmpl in _FC_1084:
        n = tmpl.count("%s")
        p = tmpl if n == 0 else tmpl % tuple([_codes(SECRET_S)] * n)
        if dlp._js_f1084_stmt_decode(p) is not None:
            bad.append(name)
    total = len(_FC_1083) + len(_FC_1084)
    return (not bad, "%d/%d fail-closed bounds miss" % (total - len(bad), total))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_f1005():
    # F1005 member-read concatenation still decodes via F1005, never via
    # the new F1083 hook.
    shapes = _redfirst_shapes(1005, prefix="w394")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if dlp._js_f1083_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1005 blocked=%d/%d, f1083-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1045():
    # F1045 setPrototypeOf still decodes via F1045, never via F1083.
    shapes = _redfirst_shapes(1045, prefix="w396")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if dlp._js_f1083_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1045 blocked=%d/%d, f1083-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1074():
    # F1074 loops still decode via F1074; the new hooks never hit them.
    shapes = _redfirst_shapes(1074, prefix="w399")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1083_stmt_decode(p) is not None
                or dlp._js_f1084_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1074 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_still_open():
    # F1085-F1089 must still MISS -- no incidental closure. F1086's 2
    # braced pre-test while twins are already blocked by F1074's hook
    # (documented partial incidental closure in w399_attack_probes.py),
    # so pin only its 6 still-open shapes like the attack battery does.
    bad = []
    for num in (1085, 1087, 1088, 1089):
        for sname, shape in _redfirst_shapes(num, prefix="w399"):
            if _blocked(shape):
                bad.append("f%d/%s" % (num, sname))
    for sname, shape in _redfirst_shapes(1086, prefix="w399"):
        if "dowhile" not in sname and "braceless" not in sname:
            continue
        if _blocked(shape):
            bad.append("f1086/%s" % sname)
    return (not bad, "still-open miss, incidental=%d" % len(bad))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-create",
     "var proto={greet:function(){return 'hi';}};var o=Object.create(proto);o.greet();"),
    ("honest-comma",
     "for(var i=0,j=10;i<j;i++,j--){console.log(i);}"),
    ("honest-while",
     "var i=0;while(i<10){i++;}"),
    ("honest-prose",
     "the comma operator, while useful, is rarely needed"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var P={k:%s};var O=Object.create(P);var S='';"
            "for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w399's attack battery (carries F1083-F1089
    open pins). Honor GOV_SKIP_GREEN. On this tree F1083/F1084 are now
    CLOSED, so exactly their two open-pin tests flip to BREAK; every
    other pin must stay HELD."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w399_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g400lane1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w399_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real, held = [], []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (real if parts[0] == "BREAK" else held).append(parts[1])
        # On this tree F1083/F1084 are closed: exactly their open pins
        # flip; everything else must hold.
        expect_break = {"test_open_w399_f1083", "test_open_w399_f1084"}
        missing_break = expect_break - set(real)
        extra_break = set(real) - expect_break
        ok = not missing_break and not extra_break
        return (ok,
                "green(w399_attack): %d BREAK, missing=%s extra=%s"
                % (len(real), sorted(missing_break), sorted(extra_break)))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# ---------------- runner ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    held, broken = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        print(("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note)))
        held, broken = held + (1 if ok else 0), broken + (0 if ok else 1)
    print("%d HELD / %d BREAK" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
