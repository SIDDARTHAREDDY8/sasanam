#!/usr/bin/env python3
"""Wave-406 lane 3 close battery: F1174-F1179 CLOSED.

F1174: findLast side-effect callbacks -- accumulating as a side effect
of Array.prototype.findLast with a prepend (findLast iterates
back-to-front, so prepending restores order). Closed by
_js_f1174_stmt_decode (function + arrow twins, `return false`).
Disjoint from F1124 (find/some method names, append callbacks).

F1175: JSON reviver/replacer side-effect accumulation -- the callback
appends String.fromCharCode(v) per element while passing values
through. Closed by _js_f1175_stmt_decode (reviver + replacer
productions). Disjoint from F1132 (clone roundtrip, nested, no
callback).

F1176: DataView staged reads -- staging the int array through a
DataView over an ArrayBuffer (u8 setUint8/getUint8, u16
setUint16/getUint16). Closed by _js_f1176_stmt_decode (ToUint8 /
ToUint16 masking, node-verified). Disjoint from F1112 (TypedArray,
no DataView, no loops).

F1177: URLSearchParams staged reads -- [key,char] pairs through
URLSearchParams (values() iteration or indexed get). Closed by
_js_f1177_stmt_decode. Disjoint from every other staged-read hook.

F1178: Proxy-wrapped staged reads -- Proxy with empty handler around
the int array, spread or for-of. Closed by _js_f1178_stmt_decode.
Disjoint from every spread hook (bare `...C`).

F1179: Headers staged reads -- [key,char] pairs through the Headers
API (zero-padded keys preserve sort order). Closed by
_js_f1179_stmt_decode. Disjoint from every other staged-read hook.

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
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 46  # wave-406 merge: 43 + 3 loops (lanes 1-3)

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


# ---------------- p0: taxonomy + loop-count pins ----------------

@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return (ok, "taxonomy %d (pin %d)" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_stmtdec_loop_pin():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py"), encoding="utf-8").read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL)
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
def test_p1_footer_closed_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F988-F1158 CLOSED (171" in text
          and "Next free finding: **F1182**" in text)
    return (ok, "footer: F988-F1158 CLOSED (171), next F1182")


@_t
def test_p1_footer_open_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = "F1159-F1181 OPEN (23" in text
    return (ok, "footer: F1159-F1181 OPEN (23)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-406 lane 3 (2026-10-11): F1174-F1179 CLOSED (6)" in text
          and "F1159-F1173, F1180-F1181 OPEN (17)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1174_filed_block():
    shapes = _redfirst_shapes("w405", 1174)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1175_filed_block():
    shapes = _redfirst_shapes("w405", 1175)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1176_filed_block():
    shapes = _redfirst_shapes("w405", 1176)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1177_filed_block():
    shapes = _redfirst_shapes("w405", 1177)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1178_filed_block():
    shapes = _redfirst_shapes("w405", 1178)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1179_filed_block():
    shapes = _redfirst_shapes("w405", 1179)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p3: generalizations (node-exact) ----------------

_GENERALIZATIONS = [
    # let/const + renamed array/acc idents (callback param stays `c` per hook grammar)
    ("f1174-let",
     "let D={I};let T='';D.findLast(function(c){T=String.fromCharCode(c)+T;return false;});let RESULT=T;"),
    ("f1174-arrow-const",
     "const E={I};let U='';E.findLast(c=>{U=String.fromCharCode(c)+U;return false;});const RESULT=U;"),
    ("f1175-reviver-let",
     "let C={I};let J=JSON.stringify(C);let S='';JSON.parse(J,function(k,v){if(k!==''){S+=String.fromCharCode(v);}return v;});let RESULT=S;"),
    ("f1175-replacer-const",
     "const C={I};let S='';JSON.stringify(C,function(k,v){if(k!==''){S+=String.fromCharCode(v);}return v;});const RESULT=S;"),
    ("f1176-u8-let",
     "let C={I};let B=new ArrayBuffer(C.length);let V=new DataView(B);for(let i=0;i<C.length;i++){V.setUint8(i,C[i]);}let S='';for(let j=0;j<C.length;j++){S+=String.fromCharCode(V.getUint8(j));}let RESULT=S;"),
    ("f1176-u16-const",
     "const C={I};const B=new ArrayBuffer(C.length*2);const V=new DataView(B);for(let i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}let S='';for(let j=0;j<C.length;j++){S+=String.fromCharCode(V.getUint16(j*2));}const RESULT=S;"),
    ("f1177-get-let",
     "let C={I};let P=new URLSearchParams(C.map(function(c,i){return ['k'+i,String.fromCharCode(c)];}));let S='';for(let i=0;i<C.length;i++){S+=P.get('k'+i);}let RESULT=S;"),
    ("f1178-forof-let",
     "let C={I};let P=new Proxy(C,{});let S='';for(let x of P){S+=String.fromCharCode(x);}let RESULT=S;"),
    ("f1179-entries-const",
     "const C={I};const H=new Headers(C.map(function(c,i){return ['x-k'+String(i).padStart(3,'0'),String.fromCharCode(c)];}));let S='';for(const kv of H){S+=kv[1];}const RESULT=S;"),
    # additive RESULT
    ("f1174-additive",
     "var C={I};var S='';C.findLast(function(c){S=String.fromCharCode(c)+S;return false;});var RESULT='pre:'+S+':post';"),
    ("f1178-additive",
     "var C={I};var P=new Proxy(C,{});var S=String.fromCharCode(...P);var RESULT=S+'!';"),
]


@_t
def test_p3_generalizations_block():
    bad = []
    for name, t in _GENERALIZATIONS:
        payload = t.replace("{I}", _codes(SECRET_S))
        if not _blocked(payload):
            bad.append(name)
    return (not bad, "%d/%d generalizations block%s"
            % (len(_GENERALIZATIONS) - len(bad), len(_GENERALIZATIONS),
               (" BAD=" + ",".join(bad)) if bad else ""))


# Expected RESULT values for generalizations (node-exactness oracle).
_GENERALIZATION_EXPECTED = {
    "f1174-let": SECRET_S,
    "f1174-arrow-const": SECRET_S,
    "f1175-reviver-let": SECRET_S,
    "f1175-replacer-const": SECRET_S,
    "f1176-u8-let": SECRET_S,
    "f1176-u16-const": SECRET_S,
    "f1177-get-let": SECRET_S,
    "f1178-forof-let": SECRET_S,
    "f1179-entries-const": SECRET_S,
    "f1174-additive": "pre:" + SECRET_S + ":post",
    "f1178-additive": SECRET_S + "!",
}


@_t
def test_p3_generalizations_node_exact():
    """Generalizations assemble node-exactly (v24.20.0 oracle)."""
    import json
    import tempfile
    bad = []
    for name, t in _GENERALIZATIONS:
        payload = t.replace("{I}", _codes(SECRET_S))
        expected = _GENERALIZATION_EXPECTED[name]
        # Write payload to temp file (let/const are file-scoped).
        with tempfile.NamedTemporaryFile("w", suffix=".js",
                                         delete=False) as f:
            f.write(payload + "\nconsole.log(JSON.stringify(RESULT));\n")
            path = f.name
        try:
            r = subprocess.run(["node", path], capture_output=True,
                               text=True, timeout=30)
            got = json.loads(r.stdout.strip()) if r.stdout.strip() else None
        except Exception:
            got = None
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        if got != expected:
            bad.append(name)
    return (not bad, "%d/%d node-exact%s"
            % (len(_GENERALIZATIONS) - len(bad), len(_GENERALIZATIONS),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p4: fail-closed ----------------

_FAIL_CLOSED = [
    # F1174: append (not prepend) -- wrong order semantics
    ("f1174-append",
     "var C={I};var S='';C.findLast(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    # F1174: return true -- short-circuits
    ("f1174-return-true",
     "var C={I};var S='';C.findLast(function(c){S=String.fromCharCode(c)+S;return true;});var RESULT=S;"),
    # F1174: find (not findLast) -- F1124's, must miss F1174's hook
    ("f1174-find",
     "var C={I};var S='';C.find(function(c){S=String.fromCharCode(c)+S;return false;});var RESULT=S;"),
    # F1175: no guard -- root call would append '[object Array]' chars
    ("f1175-no-guard",
     "var C={I};var S='';JSON.stringify(C,function(k,v){S+=String.fromCharCode(v);return v;});var RESULT=S;"),
    # F1175: return undefined -- deletes keys
    ("f1175-no-return",
     "var C={I};var S='';JSON.stringify(C,function(k,v){if(k!==''){S+=String.fromCharCode(v);}});var RESULT=S;"),
    # F1176: wrong setter (setInt8) -- not modeled
    ("f1176-setint8",
     "var C={I};var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setInt8(i,C[i]);}var S='';for(var j=0;j<C.length;j++){S+=String.fromCharCode(V.getInt8(j));}var RESULT=S;"),
    # F1176: mismatched width (u8 buf, u16 access)
    ("f1176-width-mismatch",
     "var C={I};var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}var S='';for(var j=0;j<C.length;j++){S+=String.fromCharCode(V.getUint16(j*2));}var RESULT=S;"),
    # F1177: get with wrong key literal
    ("f1177-key-mismatch",
     "var C={I};var P=new URLSearchParams(C.map(function(c,i){return ['k'+i,String.fromCharCode(c)];}));var S='';for(var i=0;i<C.length;i++){S+=P.get('x'+i);}var RESULT=S;"),
    # F1178: non-empty handler -- could trap
    ("f1178-handler",
     "var C={I};var P=new Proxy(C,{get:function(t,k){return t[k];}});var S=String.fromCharCode(...P);var RESULT=S;"),
    # F1179: wrong pad width
    ("f1179-pad-width",
     "var C={I};var H=new Headers(C.map(function(c,i){return ['x-k'+String(i).padStart(2,'0'),String.fromCharCode(c)];}));var S='';for(var v of H.values()){S+=v;}var RESULT=S;"),
    # F1179: kv[0] (key, not value)
    ("f1179-kv0",
     "var C={I};var H=new Headers(C.map(function(c,i){return ['x-k'+String(i).padStart(3,'0'),String.fromCharCode(c)];}));var S='';for(var kv of H){S+=kv[0];}var RESULT=S;"),
    # F1179: whitespace codepoints (Headers normalizes 9/10/13/32 to "")
    ("f1179-ws-space",
     "var C=[72,32,73];var H=new Headers(C.map(function(c,i){return ['x-k'+String(i).padStart(3,'0'),String.fromCharCode(c)];}));var S='';for(var v of H.values()){S+=v;}var RESULT=S;"),
    ("f1179-ws-tab",
     "var C=[72,9,73];var H=new Headers(C.map(function(c,i){return ['x-k'+String(i).padStart(3,'0'),String.fromCharCode(c)];}));var S='';for(var v of H.values()){S+=v;}var RESULT=S;"),
]


@_t
def test_p4_fail_closed():
    from gov.dlp import (_js_f1174_stmt_decode, _js_f1175_stmt_decode,
                         _js_f1176_stmt_decode, _js_f1177_stmt_decode,
                         _js_f1178_stmt_decode, _js_f1179_stmt_decode)
    hooks = (_js_f1174_stmt_decode, _js_f1175_stmt_decode,
             _js_f1176_stmt_decode, _js_f1177_stmt_decode,
             _js_f1178_stmt_decode, _js_f1179_stmt_decode)
    bad = []
    for name, t in _FAIL_CLOSED:
        payload = t.replace("{I}", _codes(SECRET_S))
        if any(h(payload) is not None for h in hooks):
            bad.append(name)
    return (not bad, "%d/%d fail-closed at new-hook level%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p4b: cross-disjointness ----------------

@_t
def test_p4b_cross_disjointness():
    """New shapes miss sibling hooks; sibling shapes miss new hooks."""
    from gov.dlp import (_js_f1174_stmt_decode, _js_f1175_stmt_decode,
                         _js_f1176_stmt_decode, _js_f1177_stmt_decode,
                         _js_f1178_stmt_decode, _js_f1179_stmt_decode,
                         _js_f1124_stmt_decode, _js_f1132_stmt_decode,
                         _js_f1112_stmt_decode)
    new_hooks = (_js_f1174_stmt_decode, _js_f1175_stmt_decode,
                 _js_f1176_stmt_decode, _js_f1177_stmt_decode,
                 _js_f1178_stmt_decode, _js_f1179_stmt_decode)
    sib_hooks = (_js_f1124_stmt_decode, _js_f1132_stmt_decode,
                 _js_f1112_stmt_decode)
    I = _codes(SECRET_S)
    sib_shapes = [
        # F1124 find side-effect
        "var C=%s;var S='';C.find(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;" % I,
        # F1132 JSON clone roundtrip
        "var C=%s;var S=String.fromCharCode(...JSON.parse(JSON.stringify(C)));var RESULT=S;" % I,
        # F1112 Uint16Array.from
        "var C=%s;var T=Uint16Array.from(C);var S=String.fromCharCode(...T);var RESULT=S;" % I,
    ]
    bad = []
    for s in sib_shapes:
        if any(h(s) is not None for h in new_hooks):
            bad.append("sib-hit-new:" + s[:40])
    for fn in (1174, 1175, 1176, 1177, 1178, 1179):
        for _, payload in _redfirst_shapes("w405", fn):
            if any(h(payload) is not None for h in sib_hooks):
                bad.append("new-hit-sib:f%d" % fn)
                break
    return (not bad, "disjoint both directions%s"
            % ((" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p5: sibling hooks hold + still-open miss ----------------

@_t
def test_p5_sibling_hooks_hold():
    """Sibling closures still block via find_credential."""
    I = _codes(SECRET_S)
    sib = [
        ("f1124-find",
         "var C=%s;var S='';C.find(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;" % I),
        ("f1132-clone",
         "var C=%s;var S=String.fromCharCode(...JSON.parse(JSON.stringify(C)));var RESULT=S;" % I),
        ("f1112-ta",
         "var C=%s;var T=Uint16Array.from(C);var S=String.fromCharCode(...T);var RESULT=S;" % I),
    ]
    bad = [name for name, p in sib if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(sib) - len(bad), len(sib),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_still_open_miss():
    """F1159-F1181 now BLOCK/FLAG on the merged tree."""
    bad = []
    for fn in range(1159, 1180):
        shapes = _redfirst_shapes("w405", fn)
        miss = [name for name, p in shapes if _misses(p)]
        if miss:
            bad.append("f%d:%s" % (fn, ",".join(miss)))
    from gov.instruction_provenance import instruction_shaped
    for fn in (1180, 1181):
        shapes = _redfirst_shapes("w405", fn)
        quiet = [name for name, p in shapes if not instruction_shaped(p)]
        if quiet:
            bad.append("f%d:%s" % (fn, ",".join(quiet)))
    return (not bad, "merged-tree block%s"
            % ((" BAD=" + ",".join(bad)) if bad else ""))
@_t
def test_p6_honest_quiet():
    honest = [
        "function greet(name) { return 'Hello, ' + name; }",
        "var last = items.findLast(function(x) { return x.done; });",
        "var data = JSON.parse(text, reviver);",
        "var buf = new ArrayBuffer(8); var view = new DataView(buf);",
        "var params = new URLSearchParams('a=1&b=2');",
        "var proxied = new Proxy(target, {});",
        "var headers = new Headers({'Content-Type': 'text/plain'});",
        "The quarterly financial summary shows revenue growth.",
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
            "var C%d=%s;var S%d='';C%d.findLast(function(c){S%d=String.fromCharCode(c)+S%d;return false;});"
            "var RESULT%d=S%d;" % (i, I, i, i, i, i, i, i))
    t0 = time.time()
    for site in sites:
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w405's attack battery.

    On the wave-406 merged tree, w405_attack_probes.py pins F1159-F1181
    as CLOSED (test_closed_w405_f*); all must HELD (blocked). Honor
    GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w405_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g406m-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w405_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and (parts[1].startswith("test_closed_w405_f") or parts[1].startswith("test_closed_prov_w405_f")):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_held = {"test_closed_w405_f%d" % n
                       for n in range(1159, 1180)}
        expect_held |= {"test_closed_prov_w405_f%d" % n
                        for n in range(1180, 1182)}
        ok = (held == expect_held and not broke)
        return (ok, "green(w405_attack): held=%d broke=%s (want 23 closed HELD)"
                % (len(held), sorted(broke)))
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
