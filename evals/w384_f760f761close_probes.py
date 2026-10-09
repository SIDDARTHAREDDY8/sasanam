#!/usr/bin/env python3
"""Wave-384 lane 12: close F760 + F761.

F760 (LOW, filed 2026-10-08 by wave-383 lane 14 as F758, renumbered at
the wave-383 merge -- lane 6 filed F738/F739 first ~17:30/~17:45 UTC):
template-nested member reads. F726 covers template-literal
toPrimitive COERCION (`${o}`); nested member reads `${o.x}` had no
modeled path: (function(){var o={x:'f1'};return `${o.x}f2`;})() and
(function(){var o={x:'f1',y:'f2'};return `${o.x}${o.y}`;})() both
node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

F761 (LOW, filed 2026-10-08 by wave-383 lane 7 as F738, renumbered at
the wave-383 merge -- lane 6 filed F738 first ~17:30 UTC): F697 twin
-- own non-callable [Symbol.toPrimitive] over-decode.
_js_f697_toprimitive skipped an own non-callable
[Symbol.toPrimitive] as if absent, but the engine's GetMethod throws
TypeError on it (no fall-through to toString/valueOf, node v24.20.0):
(function(){var o={[Symbol.toPrimitive]:'x',
toString:function(){return 'f1';}};return o+'f2';})() and the valueOf
twin both throw in the engine while the decoder produced the exact
credential decode (over-decode: fail-closed in direction, an
over-block, but a node-exactness violation of the F697 contract).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F761: _js_f697_toprimitive raises _JSExprFail when the own
  [Symbol.toPrimitive] key is present but not a _JSF67xBody
  (mirrors the F726 template-position guard).
- F760: _js_parse_f760_template_member_iife (+
  _js_parse_f760_template_member), hooked after F726 with the
  parts/ops snapshot-restore discipline (wave-383 F733 lesson).
  The var binds a plain object literal (F697 object grammar;
  getters fail closed there); the return is a +-joined additive of
  string literals and template literals whose `${...}`
  interpolations are member reads `${o.MEM}` / `${o['MEM']}`
  resolving to string-literal data properties. At least one
  member-read interpolation is required (disjoint from F726's
  bare-ident interpolations and from plain templates).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
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

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f760_s1():
    """F760 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s'};return `${o.x}%s`;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f760-s1=%s" % ok)


@_t
def test_p1_f760_s2():
    """F760 filed shape 2 (two member reads) blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s',y:'%s'};return `${o.x}${o.y}`;})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f760-s2=%s" % ok)


@_t
def test_p1_f761_s1():
    """F761 filed shape 1 (throwing) fails closed -- no over-decode."""
    ok = _misses(
        "(function(){var o={[Symbol.toPrimitive]:'x',"
        "toString:function(){return '%s';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f761-s1-miss=%s" % ok)


@_t
def test_p1_f761_s2():
    """F761 filed shape 2 (valueOf twin, throwing) fails closed."""
    ok = _misses(
        "(function(){var o={[Symbol.toPrimitive]:'x',"
        "valueOf:function(){return '%s';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f761-s2-miss=%s" % ok)


# ------------------------------------------------------------- variants p2

@_t
def test_p2_bracket():
    """${o['x']} bracket-string member read blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s'};return `${o['x']}%s`;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p2_bracket_dq():
    """${o["x"]} double-quote bracket member read blocks."""
    ok = _blocked(
        '(function(){var o={x:\'%s\'};return `${o["x"]}%s`;})()' % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket-dq=%s" % ok)


@_t
def test_p2_ws():
    """Whitespace-tolerant decl/member/template blocks."""
    ok = _blocked(
        "(function(){ var o = { x : '%s' } ; return `a${ o . x }b%s` ; })()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "ws=%s" % ok)


@_t
def test_p2_additive():
    """Template term in a +-joined additive blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s'};return `${o.x}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "additive=%s" % ok)


@_t
def test_p2_multi():
    """Three member reads assemble the credential."""
    ok = _blocked(
        "(function(){var o={a:'xoxb-',b:'0123',c:'456789abcdef'};"
        "return `${o.a}${o.b}${o.c}`;})()")
    return ("HELD" if ok else "BREAK", "multi=%s" % ok)


@_t
def test_p2_escape():
    """Escape in a literal chunk decodes node-exactly (newline)."""
    ok = _blocked(
        "(function(){var o={x:'%s'};return `\\n${o.x}%s`;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "escape=%s" % ok)


@_t
def test_p2_method_obj():
    """Method-valued sibling props do not disturb data reads."""
    ok = _blocked(
        "(function(){var o={x:'%s',m:function(){return 'zz';}};"
        "return `${o.x}%s`;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "method-obj=%s" % ok)


@_t
def test_p2_let_const():
    """let/const bindings work like var."""
    ok = (_blocked(
        "(function(){let o={x:'%s'};return `${o.x}%s`;})()" % (_A, _B))
        and _blocked(
        "(function(){const o={x:'%s'};return `${o.x}%s`;})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


@_t
def test_p2_f761_numeric():
    """Numeric non-callable @@toPrimitive also throws -- fail closed."""
    ok = _misses(
        "(function(){var o={[Symbol.toPrimitive]:7,"
        "toString:function(){return '%s';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f761-num-miss=%s" % ok)


# --------------------------------------------------------------- bounds p3

@_t
def test_p3_missing_key():
    """Missing key (engine: undefined) fails closed."""
    ok = _misses(
        "(function(){var o={x:'f1'};return `${o.zz}f2`;})()")
    return ("HELD" if ok else "BREAK", "missing=%s" % ok)


@_t
def test_p3_method_valued():
    """Method-valued member (engine: the function) fails closed."""
    ok = _misses(
        "(function(){var o={m:function(){return 'f1';}};return `${o.m}f2`;})()")
    return ("HELD" if ok else "BREAK", "methodval=%s" % ok)


@_t
def test_p3_numeric_member():
    """Numeric member ${o[0]} fails closed."""
    ok = _misses(
        "(function(){var o={x:'f1'};return `${o[0]}f2`;})()")
    return ("HELD" if ok else "BREAK", "numidx=%s" % ok)


@_t
def test_p3_bare_ident():
    """Bare-ident interpolation is F726's domain -- fails closed here."""
    ok = _misses(
        "(function(){var o={x:'f1'};return `${o}f2`;})()")
    return ("HELD" if ok else "BREAK", "bare=%s" % ok)


@_t
def test_p3_call_interp():
    """Call interpolation (engine throws) fails closed."""
    ok = _misses(
        "(function(){var o={x:'f1'};return `${o.x()}f2`;})()")
    return ("HELD" if ok else "BREAK", "call=%s" % ok)


@_t
def test_p3_getter():
    """Getter prop fails closed (F697 grammar; documented residual)."""
    ok = _misses(
        "(function(){var o={get x(){return 'f1';}};return `${o.x}f2`;})()")
    return ("HELD" if ok else "BREAK", "getter=%s" % ok)


@_t
def test_p3_reassign():
    """Reassigned binding fails closed."""
    ok = _misses(
        "(function(){var o={x:'f1'};o={x:'f2'};return `${o.x}xx`;})()")
    return ("HELD" if ok else "BREAK", "reassign=%s" % ok)


@_t
def test_p3_trailing_stmt():
    """Trailing statement after return fails closed."""
    ok = _misses(
        "(function(){var o={x:'f1'};return `${o.x}f2`;var z=1;})()")
    return ("HELD" if ok else "BREAK", "trailing=%s" % ok)


@_t
def test_p3_unbound_ident():
    """Interpolation of an unbound ident fails closed."""
    ok = _misses(
        "(function(){var o={x:'f1'};return `${q.x}f2`;})()")
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_plain_template():
    """Member-free template is not claimed (F457's domain)."""
    ok = _misses(
        "(function(){var o={x:'f1'};return `plain`;})()")
    return ("HELD" if ok else "BREAK", "plain=%s" % ok)


# ---------------------------------------------------------- sibling pins p4

@_t
def test_p4_f697_toprimitive():
    """F697 pin: callable @@toPrimitive still decodes."""
    ok = _blocked(
        "(function(){var o={[Symbol.toPrimitive]:function(){return '%s';}};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697-toprim=%s" % ok)


@_t
def test_p4_f697_valueof():
    """F697 pin: valueOf coercion still decodes."""
    ok = _blocked(
        "(function(){var o={v:'%s',valueOf:function(){return this.v;}};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697-valueof=%s" % ok)


@_t
def test_p4_f697_tostring():
    """F697 pin: toString coercion still decodes."""
    ok = _blocked(
        "(function(){var o={toString:function(){return '%s';}};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697-tostring=%s" % ok)


@_t
def test_p4_f726_coerce():
    """F726 pin: template coercion still decodes."""
    ok = _blocked(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f726-coerce=%s" % ok)


@_t
def test_p4_f726_noncallable():
    """F726 pin: non-callable @@toPrimitive in template still fails closed."""
    ok = _misses(
        "(function(){var o={[Symbol.toPrimitive]:'x',"
        "toString:function(){return '%s';}};return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f726-noncall=%s" % ok)


# ---------------------------------------------------- open neighbors p5

@_t
def test_p5_neighbors_now_closed():
    """Neighbors F738/F739/F759 now block (closed wave-384 lanes 1, 11)."""
    ok = (_blocked(
        "(function(){var o={y:'%s',get x(){return this.y;}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
        and _blocked(
        "(function(){var o={get x(){return {y:'%s'};}};"
        "return o.x.y+'%s';})()" % (_A, _B))
        and _blocked(
        "(function(){var o={set x(v){this.w=v;},get w(){return this._w;},"
        "set w(v){this._w=v;}};o.x='%s';return o._w+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "neighbors=%s" % ok)


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    ok = (_misses("the quick brown fox jumps over the lazy dog")
          and _misses("(function(){var s='ab';return s;})()")
          and _misses("'(function(){var s=\\'ab\\' ;return s;})()'"))
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ----------------------------------------------------------------- perf p6

@_t
def test_p6_perf():
    """200 F760 sites decode in under 20s."""
    t0 = time.time()
    for k in range(200):
        dlp.find_credential(
            "junk junk (function(){var o%d={x:'%s'};return `${o%d.x}%s`;})() tail"
            % (k, _A, k, _B))
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs): the w383 attack battery's only
    # expected BREAK is test_b0_footer_state (base footer pin; the
    # lane-local repoint is merge-owned, wave-382 lane-5 precedent).
    for batt, expect_break in (("evals/w383_f760_redfirst.py", 0),
                               ("evals/w383_f761_redfirst.py", 0),
                               ("evals/w383_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
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
def test_p7_green_check():
    """Depth-1 green check: red-firsts + wave-383 attack battery green."""
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
