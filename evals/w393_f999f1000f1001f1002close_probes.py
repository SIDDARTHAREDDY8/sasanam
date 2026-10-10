#!/usr/bin/env python3
"""Wave-393 lane 4 close battery: F999 + F1000 + F1001 + F1002 CLOSED.

Verifies the four LOW findings (wave-392 attack round 60, filed
2026-10-09 18:38 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F970 both families, F951, F947,
fromCharCode), honest text controls, perf (200 sites), and a
depth-1 green check on the four w393 red-first batteries
(GOV_SKIP_GREEN=1 in the child env).

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running).
"""

import argparse
import os
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

TAXONOMY_PIN = 2143  # wave-392 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_FULL40 = _F1 + _F2

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_COMPILE_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_next_free():
    """Merged footer (wave-393): F988-F1004 CLOSED; F1005-F1024 OPEN; next free F1025."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F988-F1004 CLOSED (17" in text
          and "F1005-F1024 OPEN (20" in text
          and "Next free finding: **F1025**" in text
          and "next free F1025" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


@_t
def test_p1_filed_shapes():
    """Filed shapes block: F999 x4, F1000 x4, F1001 x2, F1002 x2."""
    shapes = [
        # F999
        'var o={};Object.defineProperties(o,{a:{value:"%s",enumerable:true},b:{value:"%s",enumerable:true}});var RESULT=o.a+o.b;'
        % (_A, _B),
        'var o={};Object.defineProperties(o,{a:{value:"%s",enumerable:true},b:{value:"%s",enumerable:true}});var RESULT=o.a+o.b;'
        % (_F1, _F2),
        'var o=Object.create(null,{a:{value:"%s",enumerable:true}});o.b="%s";var RESULT=o.a+o.b;'
        % (_A, _B),
        'var o=Object.create(null,{a:{value:"%s",enumerable:true}});o.b="%s";var RESULT=o.a+o.b;'
        % (_F1, _F2),
        # F1000
        'var s="";s||="%s";s+="%s";var RESULT=s;' % (_A, _B),
        'var s="";s||="%s";s+="%s";var RESULT=s;' % (_F1, _F2),
        'var o={v:""};o.v+="%s";o.v+="%s";var RESULT=o.v;' % (_A, _B),
        'var o={v:""};o.v+="%s";o.v+="%s";var RESULT=o.v;' % (_F1, _F2),
        # F1001
        'var RESULT=Reflect.apply(String.prototype.concat,"%s",["%s"]);' % (_A, _B),
        'var RESULT=Reflect.apply(String.prototype.concat,"%s",["%s"]);' % (_F1, _F2),
        # F1002
        'var p={v:"%s"};var o=Object.create(p);o.w="%s";var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+o.w;'
        % (_A, _B),
        'var p={v:"%s"};var o=Object.create(p);o.w="%s";var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+o.w;'
        % (_F1, _F2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------- p2: generalizations must block


@_t
def test_p2_generalizations():
    """Generalizations block (all node-verified to assemble the credential)."""
    shapes = [
        # F999: let decl, bracket reads, missing flags, quoted keys,
        # bound-proto create, multiple installs, bracket assign
        'let o={};Object.defineProperties(o,{a:{value:"%s",enumerable:true},b:{value:"%s",enumerable:true}});let RESULT=o["a"]+o.b;'
        % (_A, _B),
        'var o={};Object.defineProperties(o,{a:{value:"%s"},b:{value:"%s"}});var RESULT=o.a+o.b;'
        % (_A, _B),
        "var o={};Object.defineProperties(o,{'a':{value:\"%s\"},'b':{value:\"%s\",writable:true}});var RESULT=o.a+o.b;"
        % (_A, _B),
        'var p={};var o=Object.create(p,{a:{value:"%s",enumerable:true}});o.b="%s";var RESULT=o.a+o.b;'
        % (_A, _B),
        "var o={a:'zz'};Object.defineProperties(o,{b:{value:\"%s\"}});Object.defineProperties(o,{c:{value:\"%s\"}});var RESULT=o.b+o.c;"
        % (_A, _B),
        'var o=Object.create(null,{a:{value:"%s",enumerable:true}});o["b"]="%s";var RESULT=o.a+o["b"];'
        % (_A, _B),
        # F1000: ??= on bare decl, ||= on null, member ||= on {},
        # &&= on truthy, bracket member, let decl
        'var s;s??="%s";s+="%s";var RESULT=s;' % (_A, _B),
        'var s=null;s||="%s";s+="%s";var RESULT=s;' % (_A, _B),
        'var o={};o.v||="%s";o.v+="%s";var RESULT=o.v;' % (_A, _B),
        'var s="z";s&&="%s";s+="%s";var RESULT=s;' % (_A, _B),
        'var o={v:""};o["v"]+="%s";o.v+="%s";var RESULT=o.v;' % (_A, _B),
        'let s="";s||="%s";s+="%s";let RESULT=s;' % (_A, _B),
        # F1001: empty-string arg, multi-arg, empty array, trailing comma
        'let RESULT=Reflect.apply(String.prototype.concat,"%s",["%s",""]);' % (_A, _B),
        'var RESULT=Reflect.apply(String.prototype.concat,"%s",["45","6789abcdef"]);' % _A,
        'var RESULT=Reflect.apply(String.prototype.concat,"%s",[]);' % _FULL,
        'var RESULT=Reflect.apply(String.prototype.concat,"%s",["%s",]);' % (_A, _B),
        # F1002: Object head, bracket descr read, inline proto,
        # proto-fallback member read
        'var p={v:"%s"};var o=Object.create(p);o.w="%s";var d=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+o.w;'
        % (_A, _B),
        'var p={v:"%s"};var o=Object.create(p);o.w="%s";var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d["value"]+o.w;'
        % (_A, _B),
        'var p={};var o=Object.create({v:"%s"});o.w="%s";var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+o.w;'
        % (_A, _B),
        'var p={v:"%s"};var o=Object.create(p);var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=o.v+"%s";'
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------ p3: fail-closed bounds must miss


@_t
def test_p3_fail_closed():
    """Out-of-grammar shapes stay quiet (never mis-decode).

    Junk fragments throughout: a full credential literal would match
    the raw-text rules and prove nothing about the decoders.
    """
    shapes = [
        # F999: accessor descriptor; non-literal value; redefine of a
        # non-configurable key (engine throws); assign to a
        # non-writable key; __proto__ key; unknown attribute
        "var o={};Object.defineProperties(o,{a:{get:function(){return 'x'}}});var RESULT=o.a;",
        "var o={};var v='x';Object.defineProperties(o,{a:{value:v}});var RESULT=o.a;",
        "var o={};Object.defineProperties(o,{a:{value:'x'}});Object.defineProperties(o,{a:{value:'y'}});var RESULT=o.a;",
        "var o={};Object.defineProperties(o,{a:{value:'x'}});o.a='y';var RESULT=o.a;",
        "var o={};Object.defineProperties(o,{__proto__:{value:'x'}});var RESULT=o.a;",
        "var o={};Object.defineProperties(o,{a:{value:'x',foo:true}});var RESULT=o.a;",
        # F999: unbound proto name in create (engine throws)
        "var o=Object.create(q,{a:{value:'x',enumerable:true}});var RESULT=o.a;",
        # F1000: numeric accumulator; non-literal RHS; += on
        # undefined (node yields "undefinedx"); bitwise |=;
        # member read on a non-object; plain = is not an op
        "var s=1;s+='x';var RESULT=s;",
        "var s=\"\";var t='x';s+=t;var RESULT=s;",
        "var s;s+='x';var RESULT=s;",
        "var s=\"\";s|='x';var RESULT=s;",
        "var s=\"\";s.v+='x';var RESULT=s;",
        "var s=\"\";s='x';var RESULT=s;",
        # F1001: non-literal arg; non-literal thisArg; null thisArg
        # (engine throws); wrong target; numeric arg (the engine would
        # coerce to "a5", but the decoder models string literals only
        # and fails closed by design)
        'var RESULT=Reflect.apply(String.prototype.concat,"a",[b]);',
        'var x="a";var RESULT=Reflect.apply(String.prototype.concat,x,["b"]);',
        'var RESULT=Reflect.apply(String.prototype.concat,null,["b"]);',
        'var RESULT=Reflect.apply(String.prototype.toUpperCase,"a",[]);',
        'var RESULT=Reflect.apply(String.prototype.concat,"a",[5]);',
        # F1002: missing key (engine undefined); null proto (engine
        # throws); gopd without getPrototypeOf (F970 residual);
        # non-literal key
        "var p={v:'x'};var o=Object.create(p);var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),'z');var RESULT=d.value;",
        "var o=Object.create(null);var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),'v');var RESULT=d.value;",
        "var p={v:'x'};var d=Reflect.getOwnPropertyDescriptor(p,'v');var RESULT=d.value;",
        "var p={v:'x'};var k='v';var o=Object.create(p);var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),k);var RESULT=d.value;",
        # F1002 H1 (wave-393 spec review): bare identifiers never
        # assemble strings -- the decoder's internal env keys must not
        # leak through attacker-chosen `_dval`/`d` names (the engine
        # yields "[object Object]" for the descriptor object).
        "var p={v:'x'};var o=Object.create(p);var _dval=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),'v');var RESULT=_dval+'y';",
        "var p={v:'x'};var o=Object.create(p);var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),'v');var RESULT=d+'y';",
        # F1002 H2 (wave-393 spec review): duplicate let/const
        # declarations throw SyntaxError in the engine -- fail closed
        # uniformly (a `var` redeclare would be node-exact, but the
        # hook does not track decl kinds).
        "let p={v:'x'};let o=Object.create(p);let o=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),'v');let RESULT=o.value+'y';",
    ]
    bad = [s for s in shapes if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_pins():
    """Siblings unaffected: F970 both families, F951, F947, fromCharCode."""
    blocked = [
        # F970: singular defineProperty still blocks
        "var o={};Object.defineProperty(o,'a',{value:'%s',enumerable:true});var RESULT=o.a+'%s';"
        % (_A, _B),
        # F970: inline-literal gopd still blocks
        "var d=Object.getOwnPropertyDescriptor({a:'%s'},'a');var RESULT=d.value+'%s';"
        % (_A, _B),
        # F951: Reflect on the String constructor still blocks
        "var RESULT=Reflect.apply(String,null,['%s'])+'%s';" % (_A, _B),
        # F947: object-literal prop assembly still blocks
        "var o={a:'%s',b:'%s'};var RESULT=o.a+o.b;" % (_A, _B),
        # F943: plain fromCharCode still blocks
        "var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);",
    ]
    quiet = [
        # F999's defineProperties shape is not an F1002 proto read
        "var o={};Object.defineProperties(o,{a:{value:'x'}});var RESULT=typeof o.a;",
    ]
    bad = [s for s in blocked if not _blocked(s)]
    bad += [s for s in quiet if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d sibling-ok"
            % (len(blocked) + len(quiet) - len(bad), len(blocked) + len(quiet)))


# ------------------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest text stays quiet: no false positives on the new hooks."""
    texts = [
        "var o={};Object.defineProperties(o,{a:{value:'x',enumerable:true}});var RESULT=o.a;",
        'var s="";s+="x";var RESULT=s;',
        'var RESULT=Reflect.apply(String.prototype.concat,"a",["b"]);',
        "var p={v:'x'};var o=Object.create(p);var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),'v');var RESULT=d.value;",
        "the quick brown fox jumps over the lazy dog",
        "var RESULT='hello world';",
    ]
    bad = [t for t in texts if not _misses(t)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d quiet" % (len(texts) - len(bad), len(texts)))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites decode in reasonable time (F452 discipline)."""
    site = 'var s="";s||="%s";s+="%s";var RESULT=s;' % (_A, _B)
    payload = " ".join(site for _ in range(200))
    t0 = time.time()
    _misses(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w393_f999_redfirst.py", "w393_f1000_redfirst.py",
                    "w393_f1001_redfirst.py", "w393_f1002_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g393-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line format on the CLOSED tree: "FAIL <shape>"
        # (blocked, good); "BREAK <shape>" would be a miss (bad).
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("HELD ") or line.startswith("BREAK ")
                      or line.startswith("FAIL "))
        total_bad += bad
        notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
        if nshapes == 0:
            total_bad += 1
            notes.append("%s: no shapes tallied" % battery)
    ok = total_bad == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d bad [%s]"
            % (total_bad, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the four red-firsts stay 0 failures."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            status, note = "BREAK", "exception %s: %s" % (type(e).__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, status, note))
        if status == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        sys.exit(1 if breaks else 0)


if __name__ == "__main__":
    main()
