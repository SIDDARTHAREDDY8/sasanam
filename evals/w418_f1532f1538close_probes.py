#!/usr/bin/env python3
"""Wave-418 lane 3 close battery: F1532-F1538 CLOSED.

F1532: Codec roundtrips (4 shapes) --
  (a) `var C=[codes];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var B=new TextEncoder().encode(S);var T=new TextDecoder().decode(B);var RESULT=T;`
  (b) `var C=[codes];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=atob(btoa(S));`
  (c) `var C=[codes];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=decodeURIComponent(encodeURIComponent(S));`
  (d) `var C=[codes];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=unescape(escape(S));`.
  Closed by `_js_f1532_stmt_decode`.
F1533: BigInt.asUintN wrapper --
  `var C=[codes];var E=C.map(function(c){return Number(BigInt.asUintN(16,BigInt(c)));});var S=String.fromCharCode.apply(null,E);var RESULT=S;`.
  Closed by `_js_f1533_stmt_decode`.
F1534: flat computed depth --
  `var C=[codes];var N=C.map(function(c){return [c];});var E=N.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;`.
  Closed by `_js_f1534_stmt_decode`.
F1535: Array.of spread --
  `var C=[codes];var E=Array.of(...C);var S=String.fromCharCode.apply(null,E);var RESULT=S;`.
  Closed by `_js_f1535_stmt_decode`.
F1536: Map entries+values() readout --
  `var C=[codes];var M=new Map(C.map(function(c,i){return [i,c];}));var E=[...M.values()];var S=String.fromCharCode.apply(null,E);var RESULT=S;`.
  Closed by `_js_f1536_stmt_decode`.
F1537: Reflect.ownKeys readout --
  `var C=[codes];var K=Reflect.ownKeys(C);var E=[];for(var k=0;k<K.length;k++){if(K[k]!=='length'){E.push(C[K[k]]);}}var S=String.fromCharCode.apply(null,E);var RESULT=S;`.
  Closed by `_js_f1537_stmt_decode`.
F1538: concat spread singleton --
  `var C=[codes];var E=[].concat(...[C]);var S=String.fromCharCode.apply(null,E);var RESULT=S;`.
  Closed by `_js_f1538_stmt_decode`.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 84->85.
Node-exact on all filed shapes (short + 40-char, v24.20.0); fail-closed
hook-level bounds; sibling pins hold; F1518-F1531, F1539-F1545 (other
wave-418 lanes / attack 86) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
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

from gov import dlp as _dlp

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _hits(payload):
    """True if find_credential flags the payload (in-process)."""
    try:
        return bool(_dlp.find_credential(payload))
    except Exception:
        return False


def _misses(payload):
    return not _hits(payload)


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; N_STMTDEC_LOOPS=85; re.compile=29."""
    ok = True
    notes = []
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    actual = dsrc.count("for _stmtdec in (")
    if pin != 85 or actual != 85:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 85)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=85")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1532 shape (a): TextEncoder/TextDecoder
    ("f1532-a",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var B=new TextEncoder().encode(S);var T=new TextDecoder().decode(B);var RESULT=T;"),
    # F1532 shape (b): btoa/atob
    ("f1532-b",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=atob(btoa(S));"),
    # F1532 shape (c): encodeURIComponent/decodeURIComponent
    ("f1532-c",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=decodeURIComponent(encodeURIComponent(S));"),
    # F1532 shape (d): escape/unescape
    ("f1532-d",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=unescape(escape(S));"),
    # F1533: BigInt.asUintN
    ("f1533",
     "var C={I};var E=C.map(function(c){return Number(BigInt.asUintN(16,BigInt(c)));});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1534: flat(1+1)
    ("f1534",
     "var C={I};var N=C.map(function(c){return [c];});var E=N.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1535: Array.of spread
    ("f1535",
     "var C={I};var E=Array.of(...C);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1536: Map values() spread
    ("f1536",
     "var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var E=[...M.values()];var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1537: Reflect.ownKeys
    ("f1537",
     "var C={I};var K=Reflect.ownKeys(C);var E=[];for(var k=0;k<K.length;k++){if(K[k]!=='length'){E.push(C[K[k]]);}}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1538: concat spread singleton
    ("f1538",
     "var C={I};var E=[].concat(...[C]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


@_t
def test_p1_filed_shapes():
    """All 10 filed shapes BLOCK."""
    bad = []
    for name, tmpl in _FILED:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(name)
    total = len(_FILED) * 2
    return (not bad), "filed=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad))


# ---------------- p2: generalizations ----------------

_GEN = [
    # F1532-a: let, renamed idents
    "let C={I};let S=C.map(function(x){return String.fromCharCode(x);}).join('');let B=new TextEncoder().encode(S);let T=new TextDecoder().decode(B);let RESULT=T;",
    # F1532-b: const
    "const C={I};const S=C.map(function(c){return String.fromCharCode(c);}).join('');const RESULT=atob(btoa(S));",
    # F1533: let, renamed
    "let C={I};let E=C.map(function(x){return Number(BigInt.asUintN(16,BigInt(x)));});let S=String.fromCharCode.apply(null,E);let RESULT=S;",
    # F1534: let, renamed
    "let C={I};let N=C.map(function(x){return [x];});let E=N.flat(1+1);let S=String.fromCharCode.apply(null,E);let RESULT=S;",
    # F1535: let
    "let C={I};let E=Array.of(...C);let S=String.fromCharCode.apply(null,E);let RESULT=S;",
    # F1536: let, renamed
    "let C={I};let M=new Map(C.map(function(a,b){return [b,a];}));let E=[...M.values()];let S=String.fromCharCode.apply(null,E);let RESULT=S;",
    # F1537: let, renamed loop var
    "let C={I};let K=Reflect.ownKeys(C);let E=[];for(var j=0;j<K.length;j++){if(K[j]!=='length'){E.push(C[K[j]]);}}let S=String.fromCharCode.apply(null,E);let RESULT=S;",
    # F1538: const
    "const C={I};const E=[].concat(...[C]);const S=String.fromCharCode.apply(null,E);const RESULT=S;",
    # F1532-c: double-quote join sep variant (still '')
    'var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join("");var RESULT=decodeURIComponent(encodeURIComponent(S));',
]


@_t
def test_p2_generalizations():
    """Generalization twins BLOCK."""
    bad = []
    for tmpl in _GEN:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:40])
    total = len(_GEN) * 2
    return (not bad), "gen=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad[:3]))


# ---------------- p3: fail-closed bounds ----------------

_FAILCLOSED = [
    # F1532: join(',') not '' -> fail closed
    ("f1532-join-sep",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join(',');var RESULT=atob(btoa(S));"),
    # F1532: btoa with non-latin1 code -> fail closed (node throws)
    ("f1532-btoa-nonlatin1",
     "var C=[300,120];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=atob(btoa(S));"),
    # F1532: wrong codec nesting -> fail closed
    ("f1532-wrong-nest",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=btoa(atob(S));"),
    # F1533: asUintN width 8 -> fail closed
    ("f1533-width-8",
     "var C={I};var E=C.map(function(c){return Number(BigInt.asUintN(8,BigInt(c)));});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1533: no asUintN (F1440 shape) -> this hook misses (F1440 handles it)
    ("f1533-no-asuintn",
     "var C={I};var E=C.map(function(c){return Number(BigInt.asUintN(BigInt(c)));});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1534: flat(2) literal (F1432 shape) -> this hook misses
    ("f1534-literal-2",
     "var C={I};var N=C.map(function(c){return [c];});var E=N.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1534: flat(1+2) -> fail closed
    ("f1534-depth-3",
     "var C={I};var N=C.map(function(c){return [c];});var E=N.flat(1+2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1535: Array.of.apply (F1447 shape) -> this hook misses
    ("f1535-of-apply",
     "var C={I};var E=Array.of.apply(null,C);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1536: for-of drain (F1446 shape) -> this hook misses
    ("f1536-forof-drain",
     "var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var D=[];for(var v of M.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1537: no length filter -> fail closed (would mis-decode: E gets 'length'->undefined)
    ("f1537-no-filter",
     "var C={I};var K=Reflect.ownKeys(C);var E=[];for(var k=0;k<K.length;k++){E.push(C[K[k]]);}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1537: wrong filter literal -> fail closed
    ("f1537-wrong-filter",
     "var C={I};var K=Reflect.ownKeys(C);var E=[];for(var k=0;k<K.length;k++){if(K[k]!=='len'){E.push(C[K[k]]);}}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1538: concat without spread (F1387 shape) -> this hook misses
    ("f1538-no-spread",
     "var C={I};var E=[].concat(C);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    """Fail-closed bounds: this hook MISSES non-filed shapes (no mis-decode).

    Note: sibling shapes (F1440/F1432/F1447/F1446/F1387) are handled by
    their own hooks and still BLOCK via those -- here we assert only
    that THIS lane's hooks do not mis-decode them.
    """
    bad = []
    for name, tmpl in _FAILCLOSED:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        # call the specific hook directly, not find_credential
        hook_map = {
            "f1532": _dlp._js_f1532_stmt_decode,
            "f1533": _dlp._js_f1533_stmt_decode,
            "f1534": _dlp._js_f1534_stmt_decode,
            "f1535": _dlp._js_f1535_stmt_decode,
            "f1536": _dlp._js_f1536_stmt_decode,
            "f1537": _dlp._js_f1537_stmt_decode,
            "f1538": _dlp._js_f1538_stmt_decode,
        }
        key = name.split("-")[0]
        try:
            r = hook_map[key](payload)
        except Exception:
            r = "EXC"
        if r is not None:
            bad.append(name)
    total = len(_FAILCLOSED)
    return (not bad), "failclosed=%d/%d hook-MISS%s" % (
        total - len(bad), total, "" if not bad else " DECODED:" + ",".join(bad))


# ---------------- p4: sibling pins ----------------

_SIBLINGS = [
    # F1440 (BigInt(c), no asUintN) still BLOCKs
    "var C={I};var E=C.map(function(c){return Number(BigInt(c));});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1432 (flat(2) double-nested) still BLOCKs
    "var C={I};var D=C.map(function(c){return [[c]];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1447 (Array.of.apply) still BLOCKs
    "var C={I};var E=Array.of.apply(null,C);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1446 (Map for-of drain) still BLOCKs
    "var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var D=[];for(var v of M.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1387 (concat without spread) still BLOCKs
    "var C={I};var E=[].concat(C);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
]


@_t
def test_p4_sibling_pins():
    """Sibling hooks still BLOCK."""
    bad = []
    for tmpl in _SIBLINGS:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:40])
    total = len(_SIBLINGS) * 2
    return (not bad), "siblings=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad[:3]))


# ---------------- p5: honest-text quiet ----------------

_HONEST = [
    "The quarterly report shows revenue growth of 15 percent year over year.",
    "Please review the attached document and provide feedback by Friday.",
    "var x = 1; var y = 2; var z = x + y; console.log(z);",
    "const encoder = new TextEncoder(); const data = encoder.encode('hello');",
    "The map shows the route from downtown to the airport terminal.",
]


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    bad = [t[:40] for t in _HONEST if _hits(t)]
    return (not bad), "honest=%d/%d quiet%s" % (
        len(_HONEST) - len(bad), len(_HONEST),
        "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 sites scan in reasonable time."""
    payload = ("var C=%s;var E=Array.of(...C);var S=String.fromCharCode.apply(null,E);var RESULT=S; " % _codes(SECRET_S)) * 200
    t0 = time.time()
    _hits(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return ok, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

_OTHER_OPENS = [
    # F1518 (wave-418 lane 1 scope): splice(-1) one-arg
    "var C={I};var D=C.splice(-1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1539 (wave-418 lane 4 scope): charAt arithmetic (representative)
    "var C={I};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]).charAt(0);}var RESULT=S;",
    # F1545 (merge-audit residual): chained map.flat(2) -- F1432's hook
    # models only the two-statement form
    "var C={I};var E=C.map(function(c){return [[c]];}).flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """Other wave-418 findings still MISS."""
    bad = []
    for tmpl in _OTHER_OPENS:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if _hits(payload):
            bad.append(tmpl[:40])
    total = len(_OTHER_OPENS)
    return (not bad), "other-opens=%d/%d MISS%s" % (
        total - len(bad), total, "" if not bad else " HIT:" + ",".join(bad))


# ---------------- g0: green check (depth-1) ----------------

def _green():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "green skipped (GOV_SKIP_GREEN=1)"
    # Depth-1: run the seven w418 red-first batteries with
    # GOV_SKIP_GREEN=1 in the child env. They print RESULT: FAIL on
    # the fixed tree (shapes now HIT); what matters is that every
    # shape still verifies node=True (node-exactness preserved) and
    # the harness completes.
    ok = True
    notes = []
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for n in range(1532, 1539):
        bat = "w418_f%d_redfirst.py" % n
        p = os.path.join(REPO_ROOT, "evals", bat)
        r = subprocess.run([sys.executable, p], capture_output=True,
                           text=True, timeout=300, env=env)
        out = (r.stdout or "") + (r.stderr or "")
        # every shape line must show node=True
        shape_lines = [l for l in out.split("\n")
                       if l.startswith(("BREAK ", "FAIL "))]
        bad_node = [l for l in shape_lines if "node=True" not in l]
        if not shape_lines or bad_node or r.returncode not in (0, 1):
            ok = False
            notes.append("%s bad (lines=%d badnode=%d rc=%d)"
                         % (bat, len(shape_lines), len(bad_node),
                            r.returncode))
        else:
            notes.append("%s node-ok(%d)" % (bat, len(shape_lines)))
    return ok, "; ".join(notes)


@_t
def test_g0_green():
    """Depth-1 green check."""
    return _green()


# ---------------- main ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    held = 0
    broken = 0
    for fn in TESTS:
        try:
            ok, note = fn()
        except Exception as e:
            ok, note = False, "EXC %s" % e
        if ok:
            held += 1
            print("HELD %s: %s" % (fn.__name__, note))
        else:
            broken += 1
            print("BREAK %s: %s" % (fn.__name__, note))
    print("HELD:%d BREAK:%d" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
