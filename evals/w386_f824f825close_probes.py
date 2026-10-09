#!/usr/bin/env python3
"""Wave-386 lane 15: close F824 + F825.

F824 (LOW, filed 2026-10-09 03:37:08 UTC by wave-385 lane 16 as F795,
renumbered F795->F824 at the wave-385 merge -- wave-272 rule, attack
round 53 filed F795 first at 03:25 UTC; spec-review residual of the
F793 closure): non-integer Iterator.prototype.drop arguments
unmodeled. F793 models .drop(n) for non-negative integer literals
only; node (v24.20.0) applies ToNumber then ToIntegerOrInfinity, so
drop(1.5) truncates to 1 and drop("1") coerces to 1.

F825 (LOW, filed 2026-10-09 03:37:15 UTC by wave-385 lane 16 as F796,
renumbered F796->F825 at the wave-385 merge -- wave-272 rule, attack
round 53 filed F796 first; spec-review residual of the F794
closure): String.fromCharCode with numeric valueOf/toString body
unmodeled. F794 models fromCharCode(o) only via an own
[Symbol.toPrimitive]; node resolves the argument with ToNumber whose
ToPrimitive uses hint "number" -- OrdinaryToPrimitive tries valueOf
first, then toString (deterministic order).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_tonumber_str: shared ToNumber for JS strings (F824/F825).
  Node-exact StringNumericLiteral subset: whitespace strip, sign,
  decimal (fraction/exponent), 0x/0b/0o radix, Infinity. Anything
  else is NaN (the engine's ToNumber); callers apply their own
  conversion.
- F824: the F793 .drop branch now accepts a non-negative decimal
  literal (int or float, truncated toward zero) or a string
  literal. The engine throws RangeError when !(n >= 0) --
  negatives AND NaN (node-verified; the filed close-when's "NaN->0"
  was wrong, corrected here) -- so those fail closed.
- F825: _js_f825_coerce_number + _js_touint16. The F697
  fromCharCode term now falls back from F794's @@toPrimitive path
  to OrdinaryToPrimitive (valueOf, then toString). Bodies must be
  bare `return <prim>;`: numeric/boolean literal (direct),
  string literal (ToNumber via the F824 grammar), or
  object/array literal (non-primitive -> engine tries next
  method). An own @@toPrimitive keeps F794 semantics (no
  fall-through). F743's site is untouched (it always has an
  assigned @@toPrimitive, so the fallback cannot apply there).
- Documented residuals (all fail closed, never mis-decoded):
  drop(0x2)/drop(0b10) numeric-literal radix forms; drop(1,2)
  extra args; drop(Number('1')) call args; F697 objects with
  non-literal data values (pre-existing F697 bound);
  valueOf bodies that are expressions (60+60), this-reads, or
  unbound idents; @@toPrimitive with a string body (F794's
  documented residual).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_TAIL = "oxb-" + "0123456789abcdef"  # 'x' + _TAIL == _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _drop(arg):
    return ("(function(){return [...['xx','%s','%s'].values()"
            ".drop(%s)].join('');})()" % (_A, _B, arg))


def _fcc(obj):
    return ("(function(){var o=%s;"
            "return String.fromCharCode(o)+'%%s';})()" % obj) % (_TAIL,)


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    path = os.path.join(REPO_ROOT, "evals",
                        "w318_evidence_schema_probes.py")
    text = open(path).read()
    ok = "VERIFIER_TAXONOMY_PIN = 33" in text
    return ("HELD" if ok else "BREAK", "verifier-pin")


@_t
def test_p0_no_new_recompile():
    """Zero new re.compile: count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", text))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F824/F825 closed; open
    F795-F817, F819-F823, F826-F828; next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ms = list(re.finditer(r"Open findings: (F\d+.*?)\.", text))
    m = ms[-1] if ms else None
    ok = (m and "F824" not in m.group(1) and "F825" not in m.group(1)
          and "F823" in m.group(1) and "F826" in m.group(1)
          and "Next free finding: **F829**" in text)
    return ("HELD" if ok else "BREAK", "footer")


# ------------------------------------------------ p1: F824 filed shapes


@_t
def test_p1_f824_float():
    """Filed s1: drop(1.5) truncates to 1 -- blocks."""
    return ("HELD" if _blocked(_drop("1.5")) else "BREAK", "drop(1.5)")


@_t
def test_p1_f824_string():
    """Filed s2: drop("1") coerces to 1 -- blocks."""
    return ("HELD" if _blocked(_drop('"1"')) else "BREAK", 'drop("1")')


# ------------------------------------------------ p2: F824 generalizations


@_t
def test_p2_f824_ints():
    """Integer args still decode node-exactly: 0/1 keep the
    credential (blocked); 2/99 drop past it (correctly quiet)."""
    ok = (_blocked(_drop("0")) and _blocked(_drop("1"))
          and _misses(_drop("2")) and _misses(_drop("99")))
    return ("HELD" if ok else "BREAK", "ints")


@_t
def test_p2_f824_floats():
    """Float twins truncate toward zero: 1.5/1./.5/0.5 keep the
    credential (blocked); 2.9 drops past it (correctly quiet)."""
    ok = all(_blocked(_drop(a)) for a in ("1.5", "1.", ".5", "0.5"))
    ok = ok and _misses(_drop("2.9"))
    return ("HELD" if ok else "BREAK", "floats")


@_t
def test_p2_f824_strings():
    """String ToNumber node-exact: "1"/""/"1.9"/".5"/"00"/"0"
    keep the credential (blocked); " 2 "/"0x2"/"2e1"/"0b10"/"+3"
    drop past it or empty it (correctly quiet)."""
    keep = ['"1"', '""', '"1.9"', '".5"', '"00"', '"0"']
    quiet = ['" 2 "', '"0x2"', '"2e1"', '"0b10"', '"+3"']
    ok = all(_blocked(_drop(a)) for a in keep)
    ok = ok and all(_misses(_drop(a)) for a in quiet)
    return ("HELD" if ok else "BREAK", "strings")


@_t
def test_p2_f824_inf():
    """drop("Infinity") drops everything: node yields '', the
    decoder stays quiet (no crash, no mis-decode)."""
    return ("HELD" if _misses(_drop('"Infinity"')) else "BREAK", "inf")


# ------------------------------------------------ p3: F824 fail-closed bounds


@_t
def test_p3_f824_throws():
    """Engine-throws args fail closed: -1, "-1", "abc", "1_0",
    "NaN" (RangeError -- !(n >= 0), node-verified)."""
    args = ["-1", '"-1"', '"abc"', '"1_0"', '"NaN"']
    ok = all(_misses(_drop(a)) for a in args)
    return ("HELD" if ok else "BREAK", "throws")


@_t
def test_p3_f824_malformed():
    """Malformed/unmodeled args fail closed: no arg, two args,
    hex literal, call expr, string concat."""
    args = ["", "1,2", "0x2", "Number('1')", '"a"+\'b\'']
    ok = all(_misses(_drop(a)) for a in args)
    return ("HELD" if ok else "BREAK", "malformed")


# ------------------------------------------------ p4: F825 filed shapes


@_t
def test_p4_f825_valueof():
    """Filed shape: valueOf returning 120 -- blocks."""
    return ("HELD" if _blocked(_fcc("{valueOf:function(){return 120;}}"))
            else "BREAK", "valueOf")


@_t
def test_p4_f825_tostring():
    """toString twin: toString returning 120 -- blocks."""
    return ("HELD" if _blocked(_fcc("{toString:function(){return 120;}}"))
            else "BREAK", "toString")


# ------------------------------------------------ p5: F825 generalizations


@_t
def test_p5_f825_both():
    """valueOf wins over toString (hint-number order) -- blocks."""
    p = _fcc("{valueOf:function(){return 120;},"
             "toString:function(){return 121;}}")
    return ("HELD" if _blocked(p) else "BREAK", "both")


@_t
def test_p5_f825_string_bodies():
    """String-literal bodies via ToNumber: '120', '0x78',
    ' 120 ' -- blocks."""
    objs = ["{valueOf:function(){return '120';}}",
            "{valueOf:function(){return '0x78';}}",
            "{valueOf:function(){return ' 120 ';}}",
            "{toString:function(){return '120';}}"]
    ok = all(_blocked(_fcc(o)) for o in objs)
    return ("HELD" if ok else "BREAK", "string-bodies")


@_t
def test_p5_f825_fallthrough():
    """Non-primitive valueOf return falls through to toString:
    {} and [120] bodies -- blocks."""
    objs = ["{valueOf:function(){return {};},"
            "toString:function(){return 120;}}",
            "{valueOf:function(){return [120];},"
            "toString:function(){return 120;}}"]
    ok = all(_blocked(_fcc(o)) for o in objs)
    return ("HELD" if ok else "BREAK", "fallthrough")


@_t
def test_p5_f825_unicode_ws():
    """H1 (wave-386 lane 15 standards review): the full
    ECMAScript whitespace set ToNumbers node-exactly --
    '\\u2000120'/'\\u2028120'/'\\u3000120' -> 120 (blocked),
    '\\x85120' stays NaN (quiet)."""
    ok = all(_blocked(_fcc("{valueOf:function(){return '%s120';}}" % w))
             for w in ("\u2000", "\u2028", "\u3000"))
    ok = ok and _misses(_fcc("{valueOf:function(){return '120';}}"))
    return ("HELD" if ok else "BREAK", "unicode-ws")


@_t
def test_p5_f825_no_false_positive():
    """Bodies that cannot yield the credential stay quiet:
    valueOf true (->\\x01), '' (->\\x00), 'abc' (->\\x00)."""
    objs = ["{valueOf:function(){return true;}}",
            "{valueOf:function(){return '';}}",
            "{valueOf:function(){return 'abc';}}"]
    ok = all(_misses(_fcc(o)) for o in objs)
    return ("HELD" if ok else "BREAK", "no-fp")


# ------------------------------------------------ p6: F825 fail-closed bounds


@_t
def test_p6_f825_bad_bodies():
    """Unevaluable bodies fail closed: unbound ident (engine
    ReferenceError), this-read, expression body."""
    objs = ["{valueOf:function(){return qqq;}}",
            "{valueOf:function(){return this.v;},v:'x'}",
            "{valueOf:function(){return 60+60;}}"]
    ok = all(_misses(_fcc(o)) for o in objs)
    return ("HELD" if ok else "BREAK", "bad-bodies")


@_t
def test_p6_f825_toprimitive_kept():
    """Own @@toPrimitive keeps F794 semantics (no fall-through to
    valueOf): string body, and valueOf+toPrimitive -- miss."""
    objs = ["{[Symbol.toPrimitive]:function(){return '120';}}",
            "{[Symbol.toPrimitive]:function(){return '120';},"
            "valueOf:function(){return 121;}}",
            "{a:1}"]
    ok = all(_misses(_fcc(o)) for o in objs)
    return ("HELD" if ok else "BREAK", "toprimitive-kept")


@_t
def test_p6_f825_data_valueof():
    """Non-callable own valueOf is skipped by the F697 object
    grammar (pre-existing bound) -- miss, never mis-decoded."""
    return ("HELD" if _misses(_fcc("{valueOf:42,"
                                   "toString:function(){return 120;}}"))
            else "BREAK", "data-valueof")


# ------------------------------------------------ p7: sibling pins


@_t
def test_p7_sib_f793_map():
    """F793 .map production still decodes."""
    p = ("(function(){return [...['%s','%s'].values()"
         ".map(function(x){return x;})].join('');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f793-map")


@_t
def test_p7_sib_f794_toprimitive():
    """F794 @@toPrimitive fromCharCode still decodes."""
    p = ("(function(){var o={[Symbol.toPrimitive]:function()"
         "{return 120;}};return String.fromCharCode(o)+'%s';})()"
         % (_TAIL,))
    return ("HELD" if _blocked(p) else "BREAK", "f794-toprimitive")


@_t
def test_p7_sib_f793_int_drop():
    """F793 integer drop(1) still decodes (regression pin)."""
    return ("HELD" if _blocked(_drop("1")) else "BREAK", "f793-drop1")


# ------------------------------------------------ p8: honest text


@_t
def test_p8_honest():
    """Honest text stays quiet."""
    texts = ["hello world",
             "(function(){return 'just a string';})()",
             "var x = 1; // nothing here",
             "(function(){return [...['a','b'].values()].join(',');})()"]
    ok = all(_misses(t) for t in texts)
    return ("HELD" if ok else "BREAK", "honest")


# ------------------------------------------------ p9: perf


@_t
def test_p9_perf():
    """200 mixed sites decode in reasonable time."""
    sites = ([_drop("1.5")] * 50 + [_drop('"2"')] * 50
             + [_fcc("{valueOf:function(){return 120;}}")] * 50
             + ["(function(){return 'plain';})()"] * 50)
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 30
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


# ------------------------------------------------ p10: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs): red-firsts must be 0 BREAK;
    # w385_attack's only expected BREAK is test_b0_footer_state
    # (lane-local footer; tree-wide repoint is merge-owned,
    # wave-305 lesson).
    for batt, expect_break in (("evals/w386_f824_redfirst.py", 0),
                               ("evals/w386_f825_redfirst.py", 0),
                               ("evals/w385_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
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
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p10_green_check():
    """Depth-1 green check: red-firsts (0 BREAK) + w385 attack
    battery (1 BREAK: the footer pin only, lane-local repoint;
    tree-wide repoint is merge-owned)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
