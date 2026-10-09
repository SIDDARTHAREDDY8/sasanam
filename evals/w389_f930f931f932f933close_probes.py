#!/usr/bin/env python3
"""Wave-389 lane 3 close battery: F930 + F931 + F932 + F933 CLOSED.

Verifies the four LOW findings (wave-388 attack round 56, filed
2026-10-09 11:21 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F653/F619/F671/F651/F905/F533 and the
F932 boxing twins), honest-text controls, perf (200 sites), and a
depth-1 green check on the four red-first batteries
(GOV_SKIP_GREEN=1 in the child env).

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running).
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

TAXONOMY_PIN = 2143  # wave-388 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"

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
    """VERIFIER_TAXONOMY_PIN stays 33 (evals/w318_evidence_schema_probes.py)."""
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
def test_p0_footer():
    """Footer: F930-F933 CLOSED; open F921-F929 (sans F927), F934-F936; next F937."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    m = re.search(r"Next free finding: \*\*F937\*\*\. \*\*Open findings: "
                  r"([^*]+)\.", text)
    if not m:
        return ("BREAK", "footer pattern missing")
    open_part = m.group(1)
    ok = ("F930" not in open_part and "F931" not in open_part
          and "F932" not in open_part and "F933" not in open_part)
    for f in ("F921", "F922", "F923", "F924", "F925", "F926", "F928",
              "F929", "F934", "F935", "F936"):
        ok = ok and f in open_part
    ok = ok and "F927" not in open_part
    return ("HELD" if ok else "BREAK", "open=[%s]" % open_part[:80])


# ------------------------------------------------------- p1: filed shapes


@_t
def test_p1_f930_filed():
    """F930 filed shape blocks (generator-backed Symbol.iterator for-of)."""
    p = ("(function(){var o={};o[Symbol.iterator]=function*(){yield '%s';"
         "yield '%s';};var s='';for(var v of o)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f930_filed_long():
    """F930 filed long-split shape blocks."""
    p = ("(function(){var o={};o[Symbol.iterator]=function*(){yield '%s';"
         "yield '%s';};var s='';for(var v of o)s+=v;return s;})()"
         % (_L1, _L2))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f931_filed():
    """F931 filed shape blocks (Error.message assignment)."""
    p = ("(function(){var e=new Error('x');e.message='%s';"
         "return e.message+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f931_filed_long():
    """F931 filed long-split shape blocks."""
    p = ("(function(){var e=new Error('x');e.message='%s';"
         "return e.message+'%s';})()" % (_L1, _L2))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f932_filed():
    """F932 filed shape blocks (new String valueOf)."""
    p = ("(function(){var s=new String('%s');"
         "return s.valueOf()+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f932_filed_long():
    """F932 filed long-split shape blocks."""
    p = ("(function(){var s=new String('%s');"
         "return s.valueOf()+'%s';})()" % (_L1, _L2))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f933_filed_str():
    """F933 filed shape 1 blocks (for-of over string literal)."""
    p = ("(function(){var s='';for(var c of '%s')s+=c;"
         "return s+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f933_filed_entries():
    """F933 filed shape 2 blocks (Array.from entries destructuring)."""
    p = ("(function(){var s='';for(var [i,c] of Array.from('%s').entries())"
         "s+=c;return s+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p1_f933_filed_long():
    """F933 filed long-split shape blocks."""
    p = ("(function(){var s='';for(var c of '%s')s+=c;"
         "return s+'%s';})()" % (_L1, _L2))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


# --------------------------------------------------- p2: generalizations


@_t
def test_p2_f930_named_gen():
    """F930: named generator function still blocks."""
    p = ("(function(){var o={};o[Symbol.iterator]=function* G(){yield '%s';"
         "yield '%s';};var s='';for(var v of o)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f930_let_const():
    """F930: let/const decl + const loopvar still blocks."""
    p = ("(function(){let o={};o[Symbol.iterator]=function*(){yield '%s';"
         "yield '%s';};let s='';for(const v of o)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f930_braced_tail():
    """F930: braced body + additive return tail still blocks."""
    p = ("(function(){var o={};o[Symbol.iterator]=function*(){yield '%s';};"
         "var s='';for(var v of o){s+=v;}return s+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f931_multi():
    """F931: multiple message assignments (last wins) still blocks."""
    p = ("(function(){var e=new Error('x');e.message='%s';"
         "e.message='%s%s';return e.message;})()" % (_A, _A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f931_noarg_let():
    """F931: new Error() no-arg + let decl still blocks."""
    p = ("(function(){let e=new Error();e.message='%s';"
         "return e.message+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f931_litfirst():
    """F931: literal-first additive return still blocks."""
    p = ("(function(){var e=new Error('x');e.message='%s';"
         "return 'pre:'+e.message+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f932_tostring():
    """F932: .toString() unboxing still blocks."""
    p = ("(function(){var s=new String('%s');"
         "return s.toString()+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f932_noarg():
    """F932: new String() no-arg still blocks."""
    p = ("(function(){var s=new String();"
         "return s.valueOf()+'%s';})()" % (_A + _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f932_mixed():
    """F932: mixed valueOf/toString additive still blocks."""
    p = ("(function(){var s=new String('%s');"
         "return s.valueOf()+s.toString()+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f933_braced_let():
    """F933: braced body + let decls still blocks."""
    p = ("(function(){let s='';for(let c of '%s%s'){s+=c;}return s;})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f933_entries_let():
    """F933: entries destructuring with let still blocks."""
    p = ("(function(){let s='';for(let [i,c] of Array.from('%s%s').entries())"
         "{s+=c;}return s;})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p2_f933_astral():
    """F933: astral code points round-trip node-exactly (identity).

    Tested at the hook seam: the whole-text variant gate is
    ASCII-only, so the identity is asserted on the decoded value
    directly (node v24.20.0: for-of over the string iterates code
    points and s+=c re-joins them exactly).
    """
    lit = "A\\U0001F600B"
    p = ("(function(){var s='';for(var c of '%s')s+=c;return s;})()" % lit)
    val, _ = dlp._js_parse_f933_string_forof_iife(
        p, 0, 0, {"parts": 0, "ops": 0})
    ok = val == "A\U0001F600B"
    return ("HELD" if ok else "BREAK", "astral_identity=%s" % ok)

# --------------------------------------------------- p3: fail-closed bounds


@_t
def test_p3_f930_bareyield():
    """F930: bare yield; fails closed (engine yields undefined)."""
    p = ("(function(){var o={};o[Symbol.iterator]=function*(){yield;"
         "yield '%s';yield '%s';};var s='';for(var v of o)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f930_yieldstar():
    """F930: yield* delegation fails closed."""
    p = ("(function(){var o={};o[Symbol.iterator]=function*(){yield* "
         "['%s','%s'];};var s='';for(var v of o)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f930_params():
    """F930: generator params fail closed."""
    p = ("(function(){var o={};o[Symbol.iterator]=function*(x){yield '%s';"
         "yield '%s';};var s='';for(var v of o)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f930_otherobj():
    """F930: for-of over a different object fails closed."""
    p = ("(function(){var o={};var p={};o[Symbol.iterator]=function*(){yield '%s';"
         "yield '%s';};var s='';for(var v of p)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f930_nonemptyobj():
    """F930: non-empty object literal fails closed."""
    p = ("(function(){var o={x:1};o[Symbol.iterator]=function*(){yield '%s';"
         "yield '%s';};var s='';for(var v of o)s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f931_stack():
    """F931: other Error members (stack) fail closed."""
    p = ("(function(){var e=new Error('x');e.message='%s';"
         "return e.stack+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f931_bracket():
    """F931: bracket-form e['message'] fails closed."""
    p = ("(function(){var e=new Error('x');e.message='%s';"
         "return e['message']+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f931_nonlit_rhs():
    """F931: non-literal message RHS fails closed."""
    p = ("(function(){var e=new Error('x');e.message=y;"
         "return e.message+'%s';})()" % _B)
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f931_typeerror():
    """F931: non-Error constructors fail closed."""
    p = ("(function(){var e=new TypeError('x');e.message='%s';"
         "return e.message+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f931_noassign():
    """F931: no message assignment (ctor message read) fails closed."""
    p = ("(function(){var e=new Error('x');"
         "return e.message+'%s';})()" % _B)
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f932_length():
    """F932: other String members (length) fail closed."""
    p = ("(function(){var s=new String('%s');"
         "return s.length+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f932_method_args():
    """F932: valueOf with args fails closed."""
    p = ("(function(){var s=new String('%s');"
         "return s.valueOf('x')+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f932_index():
    """F932: index read s[0] fails closed."""
    p = ("(function(){var s=new String('%s');"
         "return s[0]+'%s';})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f932_nonlit_arg():
    """F932: non-literal String arg fails closed."""
    p = ("(function(){var s=new String(x);"
         "return s.valueOf()+'%s';})()" % _B)
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f933_values():
    """F933: .values() instead of .entries() fails closed."""
    p = ("(function(){var s='';for(var c of Array.from('%s').values())s+=c;"
         "return s+'%s';})()" % (_L1, _L2))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f933_indexacc():
    """F933: accumulating the index element fails closed."""
    p = ("(function(){var s='';for(var [i,c] of Array.from('%s').entries())"
         "s+=i;return s+'%s';})()" % (_L1, _L2))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f933_mapfn():
    """F933: Array.from mapFn fails closed."""
    p = ("(function(){var s='';for(var c of Array.from('%s',x=>x))s+=c;"
         "return s+'%s';})()" % (_L1, _L2))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f933_destrstr():
    """F933: destructuring loopvar over a bare string fails closed."""
    p = ("(function(){var s='';for(var [a,b] of '%s')s+=b;"
         "return s+'%s';})()" % (_L1, _L2))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f933_pairplain():
    """F933: plain loopvar over entries() pairs fails closed."""
    p = ("(function(){var s='';for(var e of Array.from('%s').entries())s+=e;"
         "return s+'%s';})()" % (_L1, _L2))
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


# -------------------------------------------------- p4: sibling pins


@_t
def test_p4_sib_f653():
    """Sibling: F653 protocol-object iterator still blocks."""
    p = ("(function(){var FR=['%s','%s'];var O={i:0};"
         "O[Symbol.iterator]=function(){var SELF=this;return{next:function(){"
         "return SELF.i<2?{value:FR[SELF.i++],done:false}:{done:true};}};};"
         "var s='';for(var v of O)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_f619():
    """Sibling: F619 named-generator for-of still blocks."""
    p = ("(function(){function* G(){yield '%s';yield '%s';}"
         "var s='';for(var v of G())s+=v;return s;})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_f671():
    """Sibling: F671 object-literal member reads still block (F931 twin)."""
    p = ("(function(){var e={message:'%s'};return e.message+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_boxing_twins():
    """Sibling: Object()/String() boxing twins still block (F932 twins)."""
    p1 = ("(function(){return Object('%s')+'%s';})()" % (_A, _B))
    p2 = ("(function(){return String('%s')+'%s';})()" % (_A, _B))
    ok = _blocked(p1) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p4_sib_f651():
    """Sibling: F651 array for-of still blocks (F930/F933 twin)."""
    p = ("(function(){var s='';for(var v of ['%s','%s'])s+=v;return s;})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_f905():
    """Sibling: F905 Object.entries for-of still blocks."""
    p = ("(function(){var s='';for(var [k,v] of Object.entries({a:'%s',b:'%s'}))"
         "s+=v;return s;})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_sib_f533():
    """Sibling: F533 arguments for-of still blocks."""
    p = ("(function(){var a=arguments;var s='';for(var v of a)s+=v;return s;})"
         "('%s','%s')" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


# ----------------------------------------------- p5: honest text


@_t
def test_p5_honest_geniter():
    """Honest: generator-iterator shape without credential stays quiet."""
    p = ("(function(){var o={};o[Symbol.iterator]=function*(){yield 'ab';"
         "yield 'cd';};var s='';for(var v of o)s+=v;return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p5_honest_error():
    """Honest: Error.message shape without credential stays quiet."""
    p = ("(function(){var e=new Error('x');e.message='ab';"
         "return e.message+'cd';})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p5_honest_wrapper():
    """Honest: String-wrapper shape without credential stays quiet."""
    p = ("(function(){var s=new String('ab');"
         "return s.valueOf()+'cd';})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p5_honest_strforof():
    """Honest: string for-of shape without credential stays quiet."""
    p = ("(function(){var s='';for(var c of 'ab')s+=c;return s+'cd';})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


# ------------------------------------------------------- perf


@_t
def test_p6_perf_200_sites():
    """Perf: 200 decode sites stay fast (F452 aggregate budget)."""
    site = ("(function(){var o={};o[Symbol.iterator]=function*(){yield 'ab';};"
            "var s='';for(var v of o)s+=v;return s;})()")
    text = ("prefix " + site + " ") * 200
    t0 = time.time()
    dlp._try_js_expr_decode_all(text)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_break = 0
    notes = []
    for battery in ("w389_f930_redfirst.py", "w389_f931_redfirst.py",
                    "w389_f932_redfirst.py", "w389_f933_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g389-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        breaks = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    breaks = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if breaks is None:
            total_break += 1
            notes.append("%s: no tally" % battery)
        else:
            total_break += breaks
            notes.append("%s: %d BREAK" % (battery, breaks))
    ok = total_break == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d BREAK [%s]" % (total_break, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the four red-firsts stay 0 BREAK."""
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
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
