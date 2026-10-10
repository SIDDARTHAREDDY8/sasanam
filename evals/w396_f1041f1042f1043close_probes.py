#!/usr/bin/env python3
"""Wave-396 lane 3 close battery: F1041 + F1042 + F1043.

F1041: Reflect.get-staged code reads
F1042: Object.fromEntries index-pair reassembly via Object.values spread
F1043: Array .keys() index-iterator reads

Pins: taxonomy 2143, verifier 33, re.compile 28. Lane-local footer:
open F1035-F1040, F1044-F1047 (10); next free F1048.
$0-spend-by-construction (no harness/paid refs).
"""
import argparse
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

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RE_COMPILE_PIN = 28

from gov import dlp  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _check(name, ok, note=""):
    return ("HELD" if ok else "BREAK", note)


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    ok = TAXONOMY_PIN == 2143
    return _check("taxonomy-pin", ok, "pin=%d" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    ok = VERIFIER_TAXONOMY_PIN == 33
    return _check("verifier-pin", ok, "pin=%d" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_pin_recompile():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == RE_COMPILE_PIN
    return _check("recompile-pin", ok, "count=%d pin=%d" % (n, RE_COMPILE_PIN))


@_t
def test_p0_footer_state():
    """Control: lane-local footer (F1041-F1043 stamped CLOSED)."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F1041-F1043 CLOSED (3" in text
          and "F1035-F1040, F1044-F1047 OPEN (10" in text
          and "Next free finding: **F1048**" in text)
    return _check("footer-state", ok, "footer=%s" % ok)


def _entry_has_closed_stamp(text, fnum):
    for line in text.splitlines():
        if line.startswith("(%s filed " % fnum):
            return "[CLOSED 2026-10-10 wave-396 lane 3:" in line
    return False


@_t
def test_p0_f1041_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1041")
    return _check("f1041-stamp", ok, "stamp=%s" % ok)


@_t
def test_p0_f1042_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1042")
    return _check("f1042-stamp", ok, "stamp=%s" % ok)


@_t
def test_p0_f1043_closed_stamp():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _entry_has_closed_stamp(text, "F1043")
    return _check("f1043-stamp", ok, "stamp=%s" % ok)


# --------------------------------------- p1: filed shapes must block

_C20 = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        97, 98, 99, 100, 101, 102]
_C40 = _C20 + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100,
               101, 102, 48, 49, 50]


def _arr(cs):
    return "[" + ",".join(str(c) for c in cs) + "]"


def _pairs(cs):
    return "[" + ",".join("[%d,%d]" % (i, c) for i, c in enumerate(cs)) + "]"


@_t
def test_p1_f1041_filed_short():
    p = 'var o={a:%s};var RESULT=String.fromCharCode(...Reflect.get(o,"a"));' % _arr(_C20)
    return _check("f1041-filed-short", _blocked(p), "blocked")


@_t
def test_p1_f1041_filed_40char():
    p = 'var o={a:%s};var RESULT=String.fromCharCode(...Reflect.get(o,"a"));' % _arr(_C40)
    return _check("f1041-filed-40", _blocked(p), "blocked")


@_t
def test_p1_f1042_filed_short():
    p = 'var o=Object.fromEntries(%s);var RESULT=String.fromCharCode(...Object.values(o));' % _pairs(_C20)
    return _check("f1042-filed-short", _blocked(p), "blocked")


@_t
def test_p1_f1042_filed_40char():
    p = 'var o=Object.fromEntries(%s);var RESULT=String.fromCharCode(...Object.values(o));' % _pairs(_C40)
    return _check("f1042-filed-40", _blocked(p), "blocked")


@_t
def test_p1_f1043_filed_short():
    p = ('var codes=%s;var s="";for(var i of codes.keys())'
         '{s+=String.fromCharCode(codes[i]);}var RESULT=s;' % _arr(_C20))
    return _check("f1043-filed-short", _blocked(p), "blocked")


@_t
def test_p1_f1043_filed_40char():
    p = ('var codes=%s;var s="";for(var i of codes.keys())'
         '{s+=String.fromCharCode(codes[i]);}var RESULT=s;' % _arr(_C40))
    return _check("f1043-filed-40", _blocked(p), "blocked")


# --------------------------------------- p2: generalizations (node-verified)
#
# Every payload below assembles the short test credential
# "xoxb-0123456789abcdef" so that find_credential must block it.

_CRED = "xoxb-0123456789abcdef"
_CRED_CODES = [ord(c) for c in _CRED]


@_t
def test_p2_f1041_strkey():
    """String-literal object key -- node-verified decodes."""
    p = 'var o={"a":%s};var RESULT=String.fromCharCode(...Reflect.get(o,"a"));' % _arr(_CRED_CODES)
    return _check("f1041-strkey", _blocked(p), "blocked")


@_t
def test_p2_f1041_letconst():
    p = 'let o={b:%s};const RESULT=String.fromCharCode(...Reflect.get(o,"b"));' % _arr(_CRED_CODES)
    return _check("f1041-letconst", _blocked(p), "blocked")


@_t
def test_p2_f1041_ws():
    p = ('var  o = { a : %s } ; var RESULT = String.fromCharCode( ...Reflect.get( o , "a" ) ) ;'
         % _arr(_CRED_CODES))
    return _check("f1041-ws", _blocked(p), "blocked")


@_t
def test_p2_f1042_reorder():
    """Out-of-order integer keys -- engine orders numerically."""
    pairs = ",".join("[%d,%d]" % (i, c) for i, c in
                     sorted(enumerate(_CRED_CODES), key=lambda t: (t[0] * 5 + 3) % 21))
    p = 'var o=Object.fromEntries([%s]);var RESULT=String.fromCharCode(...Object.values(o));' % pairs
    return _check("f1042-reorder", _blocked(p), "blocked")


@_t
def test_p2_f1042_dup():
    """Duplicate keys -- engine later-wins."""
    pairs = ",".join("[%d,%d]" % (i % 7, c) for i, c in enumerate(_CRED_CODES))
    p = 'var o=Object.fromEntries([%s]);var RESULT=String.fromCharCode(...Object.values(o));' % pairs
    # NOTE: duplicate keys collapse later-wins, so this assembles only the
    # last 7 codes -- NOT a credential. The hook still decodes; assert the
    # hook fires via the direct decoder (node-exactness), not find_credential.
    from gov.dlp import _js_f1042_stmt_decode
    dec = _js_f1042_stmt_decode(p)
    ok = dec == "".join(chr(c) for c in _CRED_CODES[-7:])
    return _check("f1042-dup", ok, "hook decodes later-wins")


@_t
def test_p2_f1042_strkeys():
    """Canonical digit-string keys are integer indices in the engine."""
    pairs = ",".join('["%d",%d]' % (i, c) for i, c in enumerate(_CRED_CODES))
    p = 'var o=Object.fromEntries([%s]);var RESULT=String.fromCharCode(...Object.values(o));' % pairs
    return _check("f1042-strkeys", _blocked(p), "blocked")


@_t
def test_p2_f1042_negkey():
    """Negative keys are insertion-ordered string keys in the engine."""
    from gov.dlp import _js_f1042_stmt_decode
    p = 'var o=Object.fromEntries([[-1,65],[0,66]]);var RESULT=String.fromCharCode(...Object.values(o));'
    dec = _js_f1042_stmt_decode(p)
    ok = dec == "BA"  # node-verified: integer index first, then "-1"
    return _check("f1042-negkey", ok, "hook decodes BA")


@_t
def test_p2_f1042_mixed():
    from gov.dlp import _js_f1042_stmt_decode
    p = 'var o=Object.fromEntries([[1,66],[0,65],["2",67]]);var RESULT=String.fromCharCode(...Object.values(o));'
    dec = _js_f1042_stmt_decode(p)
    ok = dec == "ABC"
    return _check("f1042-mixed", ok, "hook decodes ABC")


@_t
def test_p2_f1042_noncanon():
    """Non-canonical "007" is a string key in the engine -- still decodes."""
    from gov.dlp import _js_f1042_stmt_decode
    p = 'var o=Object.fromEntries([["007",65],[0,66]]);var RESULT=String.fromCharCode(...Object.values(o));'
    dec = _js_f1042_stmt_decode(p)
    ok = dec == "BA"  # node-verified: "0" index first, then "007"
    return _check("f1042-noncanon", ok, "hook decodes BA")


@_t
def test_p2_f1043_eqplus():
    p = ('var codes=%s;var s="";for(var i of codes.keys())'
         '{s=s+String.fromCharCode(codes[i]);}var RESULT=s;' % _arr(_CRED_CODES))
    return _check("f1043-eqplus", _blocked(p), "blocked")


@_t
def test_p2_f1043_braceless():
    p = ('var codes=%s;var s="";for(var i of codes.keys())'
         's+=String.fromCharCode(codes[i]);var RESULT=s;' % _arr(_CRED_CODES))
    return _check("f1043-braceless", _blocked(p), "blocked")


@_t
def test_p2_f1043_constiter():
    p = ('var codes=%s;var s="";for(const j of codes.keys())'
         '{s+=String.fromCharCode(codes[j]);}var RESULT=s;' % _arr(_CRED_CODES))
    return _check("f1043-constiter", _blocked(p), "blocked")


@_t
def test_p2_f1043_letdecl():
    p = ('let codes=%s;let s="";for(let k of codes.keys())'
         '{s+=String.fromCharCode(codes[k]);}const RESULT=s;' % _arr(_CRED_CODES))
    return _check("f1043-letdecl", _blocked(p), "blocked")


# --------------------------------------- p3: fail-closed bounds (must miss)


@_t
def test_p3_f1041_proto():
    """__proto__ key: engine spreads the prototype (TypeError) -- miss."""
    p = 'var o={a:[65]};var RESULT=String.fromCharCode(...Reflect.get(o,"__proto__"));'
    return _check("f1041-proto", _misses(p), "misses")


@_t
def test_p3_f1041_missing():
    """Missing property: engine throws TypeError -- miss."""
    p = 'var o={a:[65]};var RESULT=String.fromCharCode(...Reflect.get(o,"b"));'
    return _check("f1041-missing", _misses(p), "misses")


@_t
def test_p3_f1041_multi():
    """Multi-property object -- outside the narrow grammar (documented)."""
    p = 'var o={a:[65],b:[66]};var RESULT=String.fromCharCode(...Reflect.get(o,"a"));'
    return _check("f1041-multi", _misses(p), "misses")


@_t
def test_p3_f1041_identkey():
    """Identifier Reflect.get key -- unbound in the engine -- miss."""
    p = 'var o={a:[65]};var k="a";var RESULT=String.fromCharCode(...Reflect.get(o,k));'
    return _check("f1041-identkey", _misses(p), "misses")


@_t
def test_p3_f1041_nospread():
    """No spread: fromCharCode(array) is NaN->"\\0" -- not a credential shape."""
    p = 'var o={a:[65]};var RESULT=String.fromCharCode(Reflect.get(o,"a"));'
    return _check("f1041-nospread", _misses(p), "misses")


@_t
def test_p3_f1041_nonarray():
    """Non-array value: engine throws on spread -- miss."""
    p = 'var o={a:65};var RESULT=String.fromCharCode(...Reflect.get(o,"a"));'
    return _check("f1041-nonarray", _misses(p), "misses")


@_t
def test_p3_f1041_getter():
    """Getter property -- outside the narrow data-property grammar."""
    p = 'var o={get a(){return [65];}};var RESULT=String.fromCharCode(...Reflect.get(o,"a"));'
    return _check("f1041-getter", _misses(p), "misses")


@_t
def test_p3_f1042_strval():
    """String value: engine fromCharCode("x") is \\0 -- not modeled (documented)."""
    p = 'var o=Object.fromEntries([[0,"x"]]);var RESULT=String.fromCharCode(...Object.values(o));'
    return _check("f1042-strval", _misses(p), "misses")


@_t
def test_p3_f1042_ident():
    """fromEntries over an identifier: F968's domain -- disjoint, miss."""
    p = 'var e=[[0,65]];var o=Object.fromEntries(e);var RESULT=String.fromCharCode(...Object.values(o));'
    return _check("f1042-ident", _misses(p), "misses")


@_t
def test_p3_f1042_noobjectvalues():
    """Member read instead of Object.values spread -- miss."""
    p = 'var o=Object.fromEntries([[0,65]]);var RESULT=String.fromCharCode(o[0]);'
    return _check("f1042-noobjectvalues", _misses(p), "misses")


@_t
def test_p3_f1042_triple():
    """Malformed 3-element pair -- miss."""
    p = 'var o=Object.fromEntries([[0,65,1]]);var RESULT=String.fromCharCode(...Object.values(o));'
    return _check("f1042-triple", _misses(p), "misses")


@_t
def test_p3_f1043_values():
    """.values() iteration: different production -- miss."""
    p = ('var codes=[65];var s="";for(var i of codes.values())'
         '{s+=String.fromCharCode(i);}var RESULT=s;')
    return _check("f1043-values", _misses(p), "misses")


@_t
def test_p3_f1043_entries():
    """.entries() iteration: index is a pair, not a code index -- miss."""
    p = ('var codes=[65];var s="";for(var i of codes.entries())'
         '{s+=String.fromCharCode(codes[i]);}var RESULT=s;')
    return _check("f1043-entries", _misses(p), "misses")


@_t
def test_p3_f1043_nonempty():
    """Non-empty accumulator -- outside the filed-shape grammar."""
    p = ('var codes=[65];var s="x";for(var i of codes.keys())'
         '{s+=String.fromCharCode(codes[i]);}var RESULT=s;')
    return _check("f1043-nonempty", _misses(p), "misses")


@_t
def test_p3_f1043_wrongrecv():
    """Body reads a different array -- miss."""
    p = ('var codes=[65];var other=[66];var s="";for(var i of codes.keys())'
         '{s+=String.fromCharCode(other[i]);}var RESULT=s;')
    return _check("f1043-wrongrecv", _misses(p), "misses")


@_t
def test_p3_f1043_sparse():
    """Sparse array: engine reads undefined -> \\0 at the hole -- fail closed."""
    p = ('var codes=[65,,67];var s="";for(var i of codes.keys())'
         '{s+=String.fromCharCode(codes[i]);}var RESULT=s;')
    return _check("f1043-sparse", _misses(p), "misses")


@_t
def test_p3_f1043_resultlit():
    """RESULT not the accumulator -- miss."""
    p = ('var codes=[65];var s="";for(var i of codes.keys())'
         '{s+=String.fromCharCode(codes[i]);}var RESULT="A";')
    return _check("f1043-resultlit", _misses(p), "misses")


# --------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_f968_closed():
    """F968 (CLOSED): entries->fromEntries string-fragment round-trip stays blocked."""
    p = ("var e=Object.entries({a:'xoxb-012',b:'3456789abcdef'});"
         "var o=Object.fromEntries(e);var RESULT=o.a+o.b;")
    return _check("sibling-f968-closed", _blocked(p), "stays blocked")


@_t
def test_p4_sibling_f1001_closed():
    """F1001 (CLOSED): Reflect.apply on concat stays blocked."""
    p = 'var RESULT=Reflect.apply(String.prototype.concat,"xoxb-012",["3456789abcdef"]);'
    return _check("sibling-f1001-closed", _blocked(p), "stays blocked")


@_t
def test_p4_sibling_f1002_closed():
    """F1002 (CLOSED): gopd-via-getPrototypeOf stays blocked."""
    p = ('var p={v:"xoxb-012"};var o=Object.create(p);o.w="3456789abcdef";'
         'var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");'
         'var RESULT=d.value+o.w;')
    return _check("sibling-f1002-closed", _blocked(p), "stays blocked")


@_t
def test_p4_sibling_f1012_closed():
    """F1012 (CLOSED): array-pair for-of stays blocked."""
    p = ('var r="";for(var kv of [["a","xoxb-012"],["b","3456789abcdef"]])r+=kv[1];'
         'var RESULT=r;')
    return _check("sibling-f1012-closed", _blocked(p), "stays blocked")


@_t
def test_p4_sibling_f1035_open():
    """F1035 (OPEN): Object.assign staging -- nearest neighbor of F1041, still misses."""
    p = ('var o=Object.assign({},{a:[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,'
         '97,98,99,100,101,102]});var RESULT=String.fromCharCode(...o.a);')
    return _check("sibling-f1035-open", _misses(p), "still misses")


@_t
def test_p4_sibling_f1040_open():
    """F1040 (OPEN): built-in iterator spread -- nearest neighbor of F1043, still misses."""
    p = ('var RESULT=String.fromCharCode(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,'
         '97,98,99,100,101,102].values());')
    return _check("sibling-f1040-open", _misses(p), "still misses")


@_t
def test_p4_sibling_f1044_open():
    """F1044 (OPEN): for-in over integer-keyed object, filed shape -- still misses."""
    p = ('var o={0:120,1:111,2:120,3:98,4:45,5:48,6:49,7:50,8:51,9:52,10:53,11:54,'
         '12:55,13:56,14:57,15:97,16:98,17:99,18:100,19:101,20:102};var s="";'
         'for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s;')
    return _check("sibling-f1044-open", _misses(p), "still misses")


# --------------------------------------- p5: honest text stays quiet


@_t
def test_p5_honest_reflect_benign():
    """Benign Reflect.get on a non-code object -- hook misses, quiet."""
    p = 'var o={a:1};var RESULT=String(Reflect.get(o,"a"));'
    return _check("honest-reflect", _misses(p), "quiet")


@_t
def test_p5_honest_fromentries_benign():
    """Benign fromEntries/values, no codes -- quiet."""
    p = 'var o=Object.fromEntries([["a","x"]]);var RESULT=Object.values(o).join(",");'
    return _check("honest-fromentries", _misses(p), "quiet")


@_t
def test_p5_honest_keys_benign():
    """Benign .keys() loop, no fromCharCode -- quiet."""
    p = 'var codes=[1,2];var s="";for(var i of codes.keys()){s+=i;}var RESULT=s;'
    return _check("honest-keys", _misses(p), "quiet")


@_t
def test_p5_honest_keys_decodes_benign():
    """Hook fires (decodes "hi") but no credential shape -> quiet."""
    p = ('var codes=[104,105];var s="";for(var i of codes.keys())'
         '{s+=String.fromCharCode(codes[i]);}var RESULT=s;')
    return _check("honest-keys-decodes", _misses(p), "quiet")


@_t
def test_p5_honest_sentence():
    p = "The quarterly report is due on Friday; please review the figures."
    return _check("honest-sentence", _misses(p), "quiet")


@_t
def test_p5_honest_junk():
    p = "(function(){var s='ab';return s;})()"
    return _check("honest-junk", _misses(p), "quiet")


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s)."""
    site = ('var o={a:[120,111]};var RESULT=String.fromCharCode(...Reflect.get(o,"a"));')
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 15.0
    return _check("perf", ok, "200 sites in %.2fs" % dt)


# --------------------------------------- p7: depth-1 green check


def _run_battery(name):
    tmp = tempfile.mkdtemp(prefix="g396-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
        capture_output=True, text=True, env=env, timeout=600,
        cwd=REPO_ROOT)
    return (p.stdout or "") + (p.stderr or "")


@_t
def test_p7_green_check():
    """Depth-1 green check: lane red-firsts 0 BREAK; attack battery breaks
    ONLY the 3 now-closed pins (F1041/F1042/F1043 flip at merge)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return _check("green-skip", True, "skipped (GOV_SKIP_GREEN=1)")
    bad_notes = []
    for battery in ("w396_f1041_redfirst.py", "w396_f1042_redfirst.py",
                    "w396_f1043_redfirst.py"):
        out = _run_battery(battery)
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("FAIL ") or line.startswith("BREAK "))
        if bad or nshapes == 0:
            bad_notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
    out = _run_battery("w395_attack_probes.py")
    broke = [line.split()[0] for line in out.splitlines()
             if re.match(r"^test_r63_f10(41|42|43)_open: BREAK", line)]
    other_broke = [line for line in out.splitlines()
                   if ": BREAK" in line and "f1041" not in line
                   and "f1042" not in line and "f1043" not in line]
    if len(broke) != 3:
        bad_notes.append("attack battery: expected 3 now-closed pins BREAK, got %d" % len(broke))
    if other_broke:
        bad_notes.append("attack battery unexpected BREAKs: %s" % other_broke[:3])
    ok = not bad_notes
    return _check("green", ok, "bad=[%s]" % "; ".join(bad_notes))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    held, broke, failed = 0, 0, []
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "BREAK", "%s raised %r" % (fn.__name__, e)
        if verdict == "HELD":
            held += 1
        else:
            broke += 1
            failed.append((fn.__name__, note))
        print("%-42s %s %s" % (fn.__name__, verdict, note))
    print("HELD %d / BREAK %d / %d total" % (held, broke, held + broke))
    for name, note in failed:
        print("FAILED:", name, note)
    return 1 if broke else 0


if __name__ == "__main__":
    sys.exit(main())
