#!/usr/bin/env python3
"""Wave-407 lane 2 close battery: F1187-F1192 CLOSED.

F1187: Array.prototype.flat(2) staged reads -- `C.map(p=>[[p]])` then
`.flat(2)` spread into fromCharCode. Closed by _js_f1187_stmt_decode,
node-exact. Residual of F1142 (flatMap).

F1188: base64 roundtrip laundering -- `atob(btoa(T))` transparent
wrapper around the map+join char string. Closed by
_js_f1188_stmt_decode, node-exact (Latin-1 only).

F1189: async generator staged reads -- `async function*g()` yielding
chars, consumed by for-await. Closed by _js_f1189_stmt_decode,
node-exact.

F1190: Intl.Segmenter grapheme reads -- segment into graphemes and
rejoin (identity on ASCII). Closed by _js_f1190_stmt_decode,
node-exact (ASCII only).

F1191: TypedArray.prototype.set staged reads -- `new Uint8Array(n)`,
`.set(C)`, spread. Closed by _js_f1191_stmt_decode, node-exact
(ToUint8). Residual of F1112 (.from).

F1192: Buffer.from staged reads -- `Buffer.from(C).toString('latin1'/
'binary')`. Closed by _js_f1192_stmt_decode, node-exact (ToUint8).

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
RECOMPILE_PIN = 29  # wave-407 merged
N_STMTDEC_LOOPS_PIN = 53  # wave-408 merge: 49 base + 4 (lanes 1-4, +1 dispatch loop each)

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


def _fill(tmpl, secret=SECRET_S):
    return tmpl.replace("{I}", _codes(secret))


# ---------------- p0: taxonomy + loop-count pins ----------------

@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return (ok, "taxonomy %d (pin %d)" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_stmtdec_loop_pin():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py"), encoding="utf-8").read()
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", src, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    return (ok, "%d loops (pin %d)" % (len(loops), N_STMTDEC_LOOPS_PIN))


@_t
def test_p0_recompile_pin():
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py"), encoding="utf-8").read()
    n = len(re.findall(r"re\.compile\(", text))
    ok = n == RECOMPILE_PIN
    return (ok, "%d re.compile (pin %d)" % (n, RECOMPILE_PIN))


# ---------------- p1: footer pins ----------------

@_t
def test_p1_footer_base():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1159-F1181 CLOSED (23" in text
          and "F1182-F1198 OPEN (17" in text
          and "Next free finding: **F1199**" in text)
    return (ok, "base footer: F1159-F1181 CLOSED (23), F1182-F1198 OPEN (17)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-407 lane 2 (2026-10-11): F1187-F1192 CLOSED (6)" in text
          and "F1182-F1186, F1193-F1198 OPEN (11)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1187_filed_block():
    shapes = _redfirst_shapes("w406", 1187)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1188_filed_block():
    shapes = _redfirst_shapes("w406", 1188)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1189_filed_block():
    shapes = _redfirst_shapes("w406", 1189)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1190_filed_block():
    shapes = _redfirst_shapes("w406", 1190)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1191_filed_block():
    shapes = _redfirst_shapes("w406", 1191)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1192_filed_block():
    shapes = _redfirst_shapes("w406", 1192)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p3: generalizations (node-exact) ----------------

_GENERALIZATIONS = [
    # F1187: let/const, renamed idents, additive RESULT
    ("f1187-let",
     "let C={I};let N=C.map((c)=>[[c]]);let S=String.fromCharCode(...N.flat(2));let RESULT=S;"),
    ("f1187-renamed",
     "var D={I};var M=D.map(function(x){return [[x]];});var T=String.fromCharCode(...M.flat(2));var RESULT='x:'+T;"),
    # F1188: const, renamed
    ("f1188-const",
     "const C={I};const T=C.map((c)=>String.fromCharCode(c)).join('');const S=atob(btoa(T));const RESULT=S;"),
    ("f1188-renamed",
     "var D={I};var U=D.map(function(x){return String.fromCharCode(x);}).join('');var V=atob(btoa(U));var RESULT=V;"),
    # F1190: double-quoted locale, renamed
    ("f1190-dq",
     'var C={I};var T=C.map((c)=>String.fromCharCode(c)).join("");var G=new Intl.Segmenter("en",{granularity:"grapheme"});var S=[...G.segment(T)].map((s)=>s.segment).join("");var RESULT=S;'),
    ("f1190-renamed",
     "var D={I};var U=D.map(function(x){return String.fromCharCode(x);}).join('');var H=new Intl.Segmenter('en',{granularity:'grapheme'});var V=Array.from(H.segment(U),function(t){return t.segment;}).join('');var RESULT=V;"),
    # F1191: const, renamed
    ("f1191-const",
     "const C={I};const U=new Uint8Array(C.length);U.set(C);const S=String.fromCharCode(...U);const RESULT=S;"),
    ("f1191-renamed",
     "var D={I};var V=new Uint8Array(D.length);V.set(D);var T=String.fromCharCode(...V);var RESULT=T;"),
    # F1192: double-quoted encoding, renamed
    ("f1192-dq",
     'var C={I};var S=Buffer.from(C).toString("latin1");var RESULT=S;'),
    ("f1192-renamed",
     "var D={I};var T=Buffer.from(D).toString('binary');var RESULT=T;"),
]


@_t
def test_p3_generalizations_block():
    bad = []
    for name, tmpl in _GENERALIZATIONS:
        for sname, sec in (("S", SECRET_S), ("L", SECRET_L)):
            p = _fill(tmpl, sec)
            if not _blocked(p):
                bad.append("%s-%s" % (name, sname))
    return (not bad, "%d/%d generalizations blocked%s"
            % (len(_GENERALIZATIONS) * 2 - len(bad),
               len(_GENERALIZATIONS) * 2,
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p4: fail-closed bounds ----------------

_FAIL_CLOSED = [
    # F1187: flatMap must not be decoded by the flat(2) hook (F1142's)
    ("f1187-flatmap-reject",
     "var C={I};var N=C.flatMap(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(2));var RESULT=S;",
     "f1187"),
    # F1222/F1228 (wave-408 lane 4): flat(1) and other depths are now
    # CLOSED via the widened F1187 hook -- the old "flat(1) must fail
    # closed" pin is removed (it now HITs, as verified by
    # w408_f1222_redfirst.py / w408_f1228_redfirst.py).
    # F1188: non-empty join separator must fail closed
    ("f1188-join-sep",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=atob(btoa(T));var RESULT=S;",
     None),
    # F1188: btoa only (no atob) must fail closed
    ("f1188-btoa-only",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S=btoa(T);var RESULT=S;",
     None),
    # F1190: non-ASCII codes must fail closed (grapheme safety)
    ("f1190-nonascii",
     "var C=[233,234];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var G=new Intl.Segmenter('en',{granularity:'grapheme'});var S=Array.from(G.segment(T),function(s){return s.segment;}).join('');var RESULT=S;",
     None),
    # F1191: .from() must not be decoded by the .set() hook (F1112's)
    ("f1191-from-reject",
     "var C={I};var U=Uint8Array.from(C);var S=String.fromCharCode(...U);var RESULT=S;",
     "f1191"),
    # F1192: utf8 encoding must fail closed
    ("f1192-utf8",
     "var C={I};var S=Buffer.from(C).toString('utf8');var RESULT=S;",
     None),
    # F1192: Buffer.from with string arg must fail closed
    ("f1192-string-arg",
     "var C={I};var S=Buffer.from('aGVsbG8=').toString('latin1');var RESULT=S;",
     None),
]


@_t
def test_p4_fail_closed():
    bad = []
    for name, tmpl, hook in _FAIL_CLOSED:
        p = _fill(tmpl)
        if hook == "f1187":
            # must not hit the F1187 hook specifically (F1142 may still block)
            r = dlp._js_f1187_stmt_decode(p)
            if r is not None:
                bad.append(name + ":f1187-hook-hit")
        elif hook == "f1191":
            r = dlp._js_f1191_stmt_decode(p)
            if r is not None:
                bad.append(name + ":f1191-hook-hit")
        else:
            # must MISS entirely (no hook should decode it)
            if not _misses(p):
                bad.append(name + ":unexpected-hit")
    return (not bad, "%d/%d fail-closed%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p4_cross_disjoint():
    """New hooks must not fire on each other's filed shapes."""
    hooks = {
        1187: dlp._js_f1187_stmt_decode,
        1188: dlp._js_f1188_stmt_decode,
        1189: dlp._js_f1189_stmt_decode,
        1190: dlp._js_f1190_stmt_decode,
        1191: dlp._js_f1191_stmt_decode,
        1192: dlp._js_f1192_stmt_decode,
    }
    bad = []
    for fn, hook in hooks.items():
        for other in range(1187, 1193):
            if other == fn:
                continue
            for name, payload in _redfirst_shapes("w406", other):
                try:
                    if hook(payload) is not None:
                        bad.append("f%d-hook-on-f%d:%s" % (fn, other, name))
                except Exception:  # noqa: BLE001
                    pass
    return (not bad, "cross-disjoint%s"
            % ((" BAD=" + ",".join(bad[:5])) if bad else " (all clear)"))


# ---------------- p5: siblings + still-open ----------------

@_t
def test_p5_siblings_hold():
    """Sibling hooks (F1142, F1090, F1091, F1112) still block their shapes."""
    sib = []
    for fn, prefix in ((1142, "w404"), (1090, "w400"), (1091, "w400"),
                       (1112, "w402")):
        try:
            sib.extend(_redfirst_shapes(prefix, fn))
        except Exception:  # noqa: BLE001
            pass
    bad = [name for name, p in sib if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(sib) - len(bad), len(sib),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_now_closed_block():
    """F1182-F1186, F1193-F1198 now BLOCK/FLAG on the merged tree."""
    bad = []
    for fn in list(range(1182, 1187)) + list(range(1193, 1196)):
        shapes = _redfirst_shapes("w406", fn)
        miss = [name for name, p in shapes if _misses(p)]
        if miss:
            bad.append("f%d:%s" % (fn, ",".join(miss)))
    from gov.instruction_provenance import instruction_shaped
    for fn in range(1196, 1199):
        shapes = _redfirst_shapes("w406", fn)
        quiet = [name for name, p in shapes if not instruction_shaped(p)]
        if quiet:
            bad.append("f%d:%s" % (fn, ",".join(quiet)))
    return (not bad, "now-closed%s"
            % ((" BAD=" + ",".join(bad)) if bad else " (all BLOCK/flag)"))


@_t
def test_p6_honest_quiet():
    honest = [
        "function greet(name) { return 'Hello, ' + name; }",
        "var flat = arr.flat(2);",
        "var encoded = btoa(text); var decoded = atob(encoded);",
        "async function*gen() { yield 1; }",
        "var seg = new Intl.Segmenter('en', {granularity: 'grapheme'});",
        "var u8 = new Uint8Array(8); u8.set([1,2,3]);",
        "var buf = Buffer.from('hello');",
        "var mapped = items.map(function(x) { return [x]; });",
    ]
    bad = [h[:48] for h in honest if not _misses(h)]
    return (not bad, "%d/%d honest-text quiet%s"
            % (len(honest) - len(bad), len(honest),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    I = _codes(SECRET_S)
    sites = []
    for i in range(200):
        sites.append(
            "var C%d=%s;var N%d=C%d.map(function(c){return [[c]];});"
            "var S%d=String.fromCharCode(...N%d.flat(2));"
            "var RESULT%d=S%d;" % (i, I, i, i, i, i, i, i))
    t0 = time.time()
    for site in sites:
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w406's round-74 attack battery.

    On the lane tree, w406_attack_probes.py pins F1182-F1198 as OPEN.
    The 6 now-closed findings (F1187-F1192) must BREAK (shapes now HIT);
    the remaining 11 pins (F1182-F1186, F1193-F1195, F1196-F1198 prov)
    must stay HELD. Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w406_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g407l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w406_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and (parts[1].startswith("test_closed_w406_f")
                                    or parts[1].startswith("test_closed_prov_w406_f")):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_held = ({"test_closed_w406_f%d" % n for n in range(1182, 1196)}
                       | {"test_closed_prov_w406_f%d" % n for n in range(1196, 1199)})
        ok = (expect_held <= held and not (expect_held & broke))
        return (ok, "green(w406_attack): held=%d/17 CLOSED"
                % (len(expect_held & held),))
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
