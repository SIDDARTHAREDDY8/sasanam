#!/usr/bin/env python3
"""Wave-384 lane 1: close F738 (`this`-dependent getter bodies through
prototype chains) + F739 (object-returning getters fail closed tree-wide).

F738 (LOW, filed 2026-10-08 ~17:30 UTC by wave-383 lane 6): F723/F724
(CLOSED) model prototype-chain getter reads, but the static model
evaluates getter bodies at literal-parse time when `this` is unbound,
so a `this`-dependent body fails closed while the engine invokes the
getter at read time with `this` bound to the receiver:
(function(){var o={y:'f1',get x(){return this.y;}};var
c=Object.create(o);return c.x+'f2';})() and the setPrototypeOf twin
(function(){var c={};var p={y:'f1',get x(){return this.y;}};
Object.setPrototypeOf(c,p);return c.x+'f2';})() both node-evaluate
(v24.20.0) to the exact credential while the decoder produced zero
variants. Distinct from F723/F724 (argument-independent getter bodies).

F739 (LOW, filed 2026-10-08 ~17:45 UTC by wave-383 lane 6): every
getter route parses getter bodies with the F535 getter-value grammar
(additive -> primary), which cannot parse an object literal, so a
getter returning an object fails closed while the engine evaluates
member reads on the returned object node-exactly:
(function(){var o={get x(){return {y:'f1'};}};return o.x.y+'f2';})()
(direct) and the prototype-chain twin
(function(){var o={get x(){return {y:'f1'};}};var
c=Object.create(o);return c.x.y+'f2';})() both node-evaluate
(v24.20.0) to the exact credential while the decoder produced zero
variants. Distinct from F738 (`this`-dependent bodies).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F738: _js_parse_f535_getter_value gains a narrow `return
  this.IDENT;` production returning a _JSThisMember marker;
  _jsobj_lookup resolves the marker against the read's receiver via
  _js_resolve_this_member (bounded recursion; missing key -> None so
  the caller fails closed, matching the engine's undefined). The
  engine binds `this` to the receiver (node v24.20.0, shadow case
  verified), so this is node-exact on every _jsobj_lookup read path.
  `.get()` descriptor paths (F691/F698, gopd) fail closed on the
  marker -- the engine returns the getter function there, for which
  no single evaluated value exists.
- F739: _js_parse_f535_getter_value gains a `return {...};`
  production parsed with the literal-object grammar (nested getters
  evaluate plain; depth-bounded). The returned _JSObj flows through
  the existing member-read loop node-exactly. The F673
  defineProperty route (raw _JSF67xBody text + deliberate
  single-step term) remains a documented residual.

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
def test_p0_no_new_regex():
    """re.compile count stays 28."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F738/F739 closed, next F762)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F762**" in text
          and "Open findings: F740, F741, F742, F743, F744, F745, F746, "
              "F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, "
              "F757, F758, F759, F760, F761." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f738_s1():
    """F738 filed shape 1 (Object.create chain) blocks."""
    ok = _blocked(
        "(function(){var o={y:'%s',get x(){return this.y;}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f738-s1=%s" % ok)


@_t
def test_p1_f738_s2():
    """F738 filed shape 2 (setPrototypeOf) blocks."""
    ok = _blocked(
        "(function(){var c={};var p={y:'%s',get x(){return this.y;}};"
        "Object.setPrototypeOf(c,p);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f738-s2=%s" % ok)


@_t
def test_p1_f739_s1():
    """F739 filed shape 1 (direct) blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return {y:'%s'};}};"
        "return o.x.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f739-s1=%s" % ok)


@_t
def test_p1_f739_s2():
    """F739 filed shape 2 (prototype chain) blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return {y:'%s'};}};"
        "var c=Object.create(o);return c.x.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f739-s2=%s" % ok)


# ------------------------------------------------------------- variants p2

@_t
def test_p2_f738_direct():
    """F738 direct read (no chain) decodes node-exactly."""
    ok = _blocked(
        "(function(){var o={y:'%s',get x(){return this.y;}};"
        "return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "direct=%s" % ok)


@_t
def test_p2_f738_nested_chain():
    """F738 two-level prototype chain decodes."""
    ok = _blocked(
        "(function(){var o={y:'%s',get x(){return this.y;}};"
        "var c=Object.create(o);var d=Object.create(c);"
        "return d.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nested=%s" % ok)


@_t
def test_p2_f738_receiver_shadow():
    """F738 shadowing: receiver's own prop wins (node-exact)."""
    # Engine: this=c, c.y='SH' shadows o.y. The decoder must track
    # the receiver, not the holder. Discriminating: a holder-bound
    # model would emit the xoxb credential here (false positive);
    # the receiver-bound model emits 'SH...' (quiet).
    ok = _misses(
        "(function(){var o={y:'%s',get x(){return this.y;}};"
        "var c=Object.create(o);c.y='SH';"
        "return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "shadow=%s" % ok)


@_t
def test_p2_f738_ws_dot():
    """F738 `this. y` (ws after dot) decodes."""
    ok = _blocked(
        "(function(){var o={y:'%s',get x(){return this. y;}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "wsdot=%s" % ok)


@_t
def test_p2_f739_setproto():
    """F739 setPrototypeOf route decodes."""
    ok = _blocked(
        "(function(){var c={};var p={get x(){return {y:'%s'};}};"
        "Object.setPrototypeOf(c,p);return c.x.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "setproto=%s" % ok)


@_t
def test_p2_f739_nested_getter():
    """F739 object with a nested getter decodes node-exactly."""
    ok = _blocked(
        "(function(){var o={get x(){return {y:'%s',"
        "get z(){return 'Z';}};}};"
        "return o.x.y+o.x.z+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nested-getter=%s" % ok)


@_t
def test_p2_f739_multi_key():
    """F739 multi-key returned object: second key read decodes."""
    ok = _blocked(
        "(function(){var o={get x(){return {a:'q',y:'%s'};}};"
        "return o.x.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "multikey=%s" % ok)


@_t
def test_p2_f739_deep_member():
    """F739 two-level member chain on the returned object."""
    ok = _blocked(
        "(function(){var o={get x(){return {y:{z:'%s'}};}};"
        "return o.x.y.z+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "deep=%s" % ok)


# --------------------------------------------------------------- bounds p3

@_t
def test_p3_bound_this_cycle():
    """Self-referential `this.x` fails closed (no hang)."""
    ok = _misses(
        "(function(){var o={get x(){return this.x;}};"
        "var c=Object.create(o);return c.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "cycle=%s" % ok)


@_t
def test_p3_bound_this_missing():
    """`this` member missing on the receiver fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return this.y;}};"
        "var c=Object.create(o);return c.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "missing=%s" % ok)


@_t
def test_p3_bound_this_nonbare():
    """`this.y` inside a larger expression fails closed (narrow)."""
    ok = _misses(
        "(function(){var o={y:'%s',get x(){return this.y+'!';}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonbare=%s" % ok)


@_t
def test_p3_bound_this_bracket():
    """`this['y']` bracket form fails closed (narrow)."""
    ok = _misses(
        "(function(){var o={y:'%s',get x(){return this['y'];}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p3_bound_this_call():
    """`this.y()` call form fails closed."""
    ok = _misses(
        "(function(){var o={y:'%s',get x(){return this.y();}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "call=%s" % ok)


@_t
def test_p3_bound_obj_getter_array():
    """Getter returning an array still fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return ['%s'];}};"
        "return o.x[0]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "array=%s" % ok)


@_t
def test_p3_bound_obj_getter_deep6():
    """Deeply nested object getters fail closed past depth."""
    deep = "{a:" * 40 + "'%s'" % _A + "}" * 40
    ok = _misses(
        "(function(){var o={get x(){return %s;}};"
        "return o.x;})()" % deep)
    return ("HELD" if ok else "BREAK", "deep=%s" % ok)


@_t
def test_p3_bound_f673_obj_getter():
    """F673 defineProperty object-getter: documented residual."""
    ok = _misses(
        "(function(){var o={};Object.defineProperty(o,'x',"
        "{get:function(){return {y:'%s'};}});"
        "return o.x.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f673-residual=%s" % ok)


# ------------------------------------------- siblings and open neighbors p4

@_t
def test_p4_sibling_f723():
    """F723 argument-independent proto-chain getter still blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f723=%s" % ok)


@_t
def test_p4_sibling_f724():
    """F724 setPrototypeOf getter still blocks."""
    ok = _blocked(
        "(function(){var c={};var p={get x(){return '%s';}};"
        "Object.setPrototypeOf(c,p);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f724=%s" % ok)


@_t
def test_p4_sibling_f664():
    """F664 direct getter still blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f664=%s" % ok)


@_t
def test_p4_sibling_f535_nested():
    """F535 nested literal member reads still block."""
    ok = _blocked(
        "(function(){var o={a:{b:'%s'}};"
        "return o.a.b+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f535=%s" % ok)


@_t
def test_p4_sibling_f671():
    """F671 plain member reads still block."""
    ok = _blocked(
        "(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f671=%s" % ok)


@_t
def test_p4_neighbor_f740_open():
    """F740 (open) still misses."""
    ok = _misses(
        "(function(){var r;try{throw '%s';}catch(e){r=e;}"
        "return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f740-open=%s" % ok)


@_t
def test_p4_neighbor_f761_open():
    """F761 (open) keeps its filed over-decode behavior.

    F761's filed shapes throw in the engine (own non-callable
    [Symbol.toPrimitive]) while the decoder over-decodes -- that
    over-decode is F761's open state, owned by another lane. This
    probe pins the verbatim filed shapes so this lane cannot
    silently alter F761.
    """
    ok = _blocked(
        "(function(){var o={[Symbol.toPrimitive]:'x',"
        "toString:function(){return '%s';}};"
        "return o+'%s';})()" % (_A, _B)) and _blocked(
        "(function(){var o={[Symbol.toPrimitive]:'x',"
        "valueOf:function(){return '%s';}};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f761-open=%s" % ok)


# ------------------------------------------------------- honest text p5

@_t
def test_p5_junk_quiet():
    """Honest text stays quiet."""
    ok = _misses("just a regular sentence about getters and prototypes")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_getter():
    """Honest getter without credential fragments is not flagged."""
    ok = _misses(
        "(function(){var o={get x(){return 'plain';}};"
        "return o.x;})()")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_fragment_quiet():
    """A lone fragment never reaches credential shape."""
    ok = _misses("xoxb-0123")
    return ("HELD" if ok else "BREAK", "fragment=%s" % ok)


# ----------------------------------------------------------------- perf p6

@_t
def test_p6_perf():
    """200 mixed getter sites decode in reasonable time."""
    t0 = time.time()
    for k in range(100):
        _blocked(
            "(function(){var o%d={y:'x',get x(){return this.y;}};"
            "var c%d=Object.create(o%d);return c%d.x;})()" % (k, k, k, k))
        _blocked(
            "(function(){var o%d={get x(){return {y:'x'};}};"
            "return o%d.x.y;})()" % (k, k))
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, tolerated footer BREAKs)
    for batt, tol_footer in (("evals/w383_f738_redfirst.py", 0),
                             ("evals/w383_f739_redfirst.py", 0),
                             ("evals/w383_attack_probes.py", 1)):
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
        footer_break = 0
        for line in out.splitlines():
            if line.startswith("test_b0_footer_state: BREAK"):
                footer_break = 1
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        else:
            real = nbreak - (footer_break if tol_footer else 0)
            if real != 0:
                bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: F738/F739 red-firsts + attack battery green."""
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
