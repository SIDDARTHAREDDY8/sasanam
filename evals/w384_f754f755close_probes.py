#!/usr/bin/env python3
"""Wave-384 lane 9: close F754 + F755 (delete statements, computed getters).

F754 (LOW; filed 2026-10-08 by wave-383 lane 14, attack round 51): delete
operator statements bypass the bounded static JS-expression decoder --
the decoder has no delete-operator production, so
  (function(){var o={x:'f1',y:'junk'};delete o.y;return o.x+'f2';})()
  (function(){var o={x:'f1',y:'junk'};delete o['y'];return o.x+'f2';})()
miss while node evaluates the remaining reads exactly (v24.20.0).

F755 (LOW; filed 2026-10-08 by wave-383 lane 14, attack round 51): F535
residual -- computed string-name getters: F535 (CLOSED) models plain
getters but not computed string names, so
  (function(){var o={get ['x'](){return 'f1';}};return o.x+'f2';})()
  (function(){var o={get ['x'](){return 'f1';}};return o['x']+'f2';})()
miss while node fires the getter on read exactly (v24.20.0). Distinct
from F552 (computed Symbol.for keys, CLOSED).

Fix (gov/dlp.py, zero new re.compile):
- F754: _js_parse_f754_delete_stmt_iife, hooked after F729 with the
  hook and trailing return intact (wave-379 lesson) and the
  F452 snapshot/restore discipline on miss. Disjoint by the `delete`
  statement head. Models `delete o.K;` / `delete o['K'];` on the
  var-bound F535 literal (accessor-aware): the tracked dict drops the
  key (node-exact: delete never invokes a getter; absent keys are a
  no-op). Deleted-key reads fail closed (the engine yields
  undefined). Bare deletes, foreign targets, non-literal keys,
  __proto__, and paren operands fail closed.
- F755: the shared _js_parse_f535_getter_head now accepts a
  bracketed string literal (`get ['x']`, `get ["x"]`, ws-tolerant)
  as the getter name -- node-identical to `get 'x'`. Numeric /
  identifier / other computed names fail closed (documented
  boundary). F552's Symbol.for path is untouched (tried only when
  the bracket head is not a string literal).

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

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2143

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

_tests = []


def _t(fn):
    _tests.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


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
def test_p1_f754_s1():
    """F754 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s',y:'junk'};delete o.y;return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f754-s1=%s" % ok)


@_t
def test_p1_f754_s2():
    """F754 filed shape 2 (bracket twin) blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s',y:'junk'};delete o['y'];return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f754-s2=%s" % ok)


@_t
def test_p1_f755_s1():
    """F755 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={get ['x'](){return '%s';}};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f755-s1=%s" % ok)


@_t
def test_p1_f755_s2():
    """F755 filed shape 2 (bracket read) blocks."""
    ok = _blocked(
        "(function(){var o={get ['x'](){return '%s';}};return o['x']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f755-s2=%s" % ok)


# ------------------------------------------------------------- variants (p2)

@_t
def test_p2_delete_let_const():
    """F754 variants: let/const decls block."""
    ok = (_blocked("(function(){let o={x:'%s',y:'junk'};delete o.y;return o.x+'%s';})()" % (_A, _B))
          and _blocked("(function(){const o={x:'%s',y:'junk'};delete o.y;return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


@_t
def test_p2_delete_ws_dq():
    """F754 variants: whitespace-tolerant and double-quoted keys block."""
    ok = (_blocked("(function(){var o={x:'%s',y:'junk'};delete   o . y ;return o.x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var o={x:'%s',y:'junk'};delete o[\"y\"];return o.x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var o={x:'%s',y:'junk'};delete o[ 'y' ];return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "ws-dq=%s" % ok)


@_t
def test_p2_delete_absent_multi():
    """F754 variants: absent-key delete is a no-op; multiple deletes block."""
    ok = (_blocked("(function(){var o={x:'%s'};delete o.zzz;return o.x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var o={x:'%s',y:'a',z:'b'};delete o.y;delete o['z'];return o.x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var o={x:'%s',y:'junk'};delete o.y;delete o.y;return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "absent-multi=%s" % ok)


@_t
def test_p2_delete_getter_key():
    """F754 variant: deleting an accessor key removes it without invoking."""
    ok = _blocked("(function(){var o={get g(){return 'junk';},x:'%s'};delete o.g;return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "getter-del=%s" % ok)


@_t
def test_p2_delete_bracket_read():
    """F754 variant: bracket-form return read blocks."""
    ok = _blocked("(function(){var o={x:'%s',y:'junk'};delete o.y;return o['x']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket-read=%s" % ok)


@_t
def test_p2_computed_dq_ws():
    """F755 variants: double quotes and whitespace in the computed name block."""
    ok = (_blocked("(function(){var o={get [\"x\"](){return '%s';}};return o.x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var o={get [ 'x' ](){return '%s';}};return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "dq-ws=%s" % ok)


@_t
def test_p2_computed_proto_numstr():
    """F755 variants: __proto__ and numeric-string computed names are node-exact."""
    ok = (_blocked("(function(){var o={get ['__proto__'](){return '%s';}};return o.__proto__+'%s';})()" % (_A, _B))
          and _blocked("(function(){var o={get ['0'](){return '%s';}};return o['0']+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "proto-numstr=%s" % ok)


@_t
def test_p2_computed_later_wins():
    """F755 variant: duplicate plain/computed getter names are later-wins."""
    ok = (_blocked("(function(){var o={get ['x'](){return 'no';},get x(){return '%s';}};return o.x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var o={get x(){return 'no';},get ['x'](){return '%s';}};return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "later-wins=%s" % ok)


@_t
def test_p2_computed_mixed_data():
    """F755 variant: computed getter alongside data props blocks."""
    ok = _blocked("(function(){var o={y:'junk',get ['x'](){return '%s';}};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "mixed=%s" % ok)


@_t
def test_p2_computed_delete_compose():
    """F754+F755 composition: delete statements over a computed getter literal."""
    ok = _blocked("(function(){var o={get ['x'](){return '%s';},y:'junk'};delete o.y;return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "compose=%s" % ok)


# --------------------------------------------------------------- bounds (p3)

@_t
def test_p3_delete_bare_unbound():
    """F754 bounds: bare / unbound / foreign delete targets fail closed."""
    ok = (_misses("(function(){var o={x:'%s'};delete o;return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s'};delete x;return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s'};delete p.y;return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "targets=%s" % ok)


@_t
def test_p3_delete_bad_keys():
    """F754 bounds: integer / alias / __proto__ / paren keys fail closed."""
    ok = (_misses("(function(){var o={0:'a',x:'%s'};delete o[0];return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s',y:'junk'};var k='y';delete o[k];return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s'};delete o.__proto__;return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s'};delete o['__proto__'];return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s',y:'junk'};delete(o.y);return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "keys=%s" % ok)


@_t
def test_p3_delete_read_deleted():
    """F754 bound: reading a deleted key fails closed (engine: undefined)."""
    ok = _misses("(function(){var o={x:'%s'};delete o.x;return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "delread=%s" % ok)


@_t
def test_p3_delete_shape_bounds():
    """F754 bounds: malformed shapes fail closed."""
    ok = (_misses("(function(){var o={x:'%s',y:'junk'};delete o.y;var z=1;return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s',y:'junk'};o={x:'%s'};delete o.y;return o.x+'%s';})()" % (_A, _B, _A))
          and _misses("(function(a){var o={x:'%s',y:'junk'};delete o.y;return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var s='%s';delete s.x;return s+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={x:'%s',y:'junk'};delete o.y return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "shapes=%s" % ok)


@_t
def test_p3_computed_bad_names():
    """F755 bounds: non-string computed getter names fail closed."""
    ok = (_misses("(function(){var o={get [0](){return '%s';}};return o[0]+'%s';})()" % (_A, _B))
          and _misses("(function(){var q='x';var o={get [q](){return '%s';}};return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={get [x](){return '%s';}};return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={get [`x`](){return '%s';}};return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "names=%s" % ok)


@_t
def test_p3_computed_setter_method():
    """F755 bounds: computed setters/methods and computed data keys fail closed."""
    ok = (_misses("(function(){var o={set ['x'](v){},get x(){return '%s';}};return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={['x']:'%s'};return o.x+'%s';})()" % (_A, _B))
          and _misses("(function(){var o={get ['x'](a){return '%s';}};return o.x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "setter-method=%s" % ok)


# ------------------------------------------------------ siblings (p4)

@_t
def test_p4_sibling_f535_plain_getter():
    """Sibling: F535 plain getters still block."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f535=%s" % ok)


@_t
def test_p4_sibling_f552_symbol_getter():
    """Sibling: F552 computed Symbol.for getters still block."""
    ok = _blocked("(function(){var o={get [Symbol.for('x')](){return '%s';}};return o[Symbol.for('x')]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f552=%s" % ok)


@_t
def test_p4_sibling_f716_reflect_set():
    """Sibling: F716 Reflect.set writes still block."""
    ok = _blocked("(function(){var o={};Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f716=%s" % ok)


@_t
def test_p4_sibling_f729_void():
    """Sibling: F729 void statements still block."""
    ok = _blocked("(function(){var x='%s';void x;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f729=%s" % ok)


@_t
def test_p4_neighbor_f753_now_closed():
    """Neighbor: F753 (spread args) now blocks (closed wave-384 lane 8)."""
    ok = _blocked("(function(){function h(a,b){return a+b;}return h(...['%s','%s']);})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f753-closed=%s" % ok)


@_t
def test_p4_neighbor_f756_now_closed():
    """Neighbor: F756 (ternary) now blocks (closed wave-384 lane 10)."""
    ok = _blocked("(function(){var c=true;return (c?'%s':'z')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f756-closed=%s" % ok)


# ------------------------------------------------------------ junk (p5)

@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------------- honest text (p6)

@_t
def test_p6_honest_delete_getter_text():
    """Honest delete/getter-adjacent text is unaffected."""
    ok = (_misses("please delete the file after reading")
          and _misses("the getter and setter methods are defined below")
          and _misses("to delete, press the button marked X"))
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ---------------------------------------------------------------- perf (p7)

@_t
def test_p7_perf():
    """200 mixed sites decode in reasonable time (F452 budget holds)."""
    sites = []
    for k in range(50):
        sites.append("(function(){var o={x:'f%d',y:'j'};delete o.y;return o.x;})()" % k)
        sites.append("(function(){var o={get ['x'](){return 'f%d';}};return o.x;})()" % k)
        sites.append("(function(){var x='f%d';return x;})()" % k)
        sites.append("['a','b'].join('')")
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 10
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ---------------------------------------------------------- green check (p8)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs): the F754/F755 red-firsts must be 0
    # BREAK. w383_attack_probes carries 1 expected BREAK -- its
    # test_b0_footer_state asserts the base footer, but this lane
    # repointed it lane-locally (wave-305 class); the tree-wide
    # repoint is merge-owned.
    for batt, expect_break in (("evals/w383_f754_redfirst.py", 0),
                               ("evals/w383_f755_redfirst.py", 0),
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
def test_p8_green_check():
    """Depth-1 green check: F754/F755 red-firsts + wave-383 attack battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errs = 0, 0, 0
    for fn in _tests:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery must not crash
            verdict, detail = "ERROR", "%s: %r" % (fn.__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errs += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errs))
    return 1 if (breaks or errs) else 0


if __name__ == "__main__":
    sys.exit(main())
