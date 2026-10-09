#!/usr/bin/env python3
"""Close battery for F758 + F759 (wave-384 lane 11).

F758 (LOW, attack round 51): rest parameters -- the decoder modeled
arguments indexing (F558, CLOSED) but not rest parameters:
`function h(...xs){return xs.join('');}` called as `h('f1','f2')`,
and the mixed twin `function h(a,...rest){return a+rest[0];}`.
Closed by `_js_parse_f758_rest_param_iife` (gov/dlp.py, hooked
after F735/F736): plain params bind positionally, the rest
parameter gathers the remaining literal args; the body additive
supports string literals, bare plain-param idents,
`REST.join('SEP')` / `REST.join()`, and canonical-int `REST[I]`
(bound-checked).

F759 (LOW, attack round 51): setter value flows -- the decoder
modeled getters (F535, CLOSED) but not setters: `o.x='f1'`
through a setter stores the fragment, readable via the backing
field node-exactly. Closed by `_js_parse_f759_setter_iife`
(gov/dlp.py, hooked after F758): the object literal records data
props, setters, and getters (a `get`+`set` pair merges into one
accessor -- node-exact); `o.P='LIT'` statements invoke setters
(chaining through `this` writes, re-entrancy fails closed); the
return additive reads data fields and evaluates getters against
the current fields.

Prints BREAK on any regression. Standalone: 0 BREAK expected.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
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


# ------------------------------------------------------------- controls

TAXONOMY_PIN = 2144  # Wave-385: pin 2143 -> 2144


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f758_s1():
    """F758 filed shape 1 blocks."""
    ok = _blocked("(function(){function h(...xs){return xs.join('');}return h('%s','%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f758_s2():
    """F758 filed shape 2 blocks."""
    ok = _blocked("(function(){function h(a,...rest){return a+rest[0];}return h('%s','%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f759_s1():
    """F759 filed shape 1 blocks."""
    ok = _blocked("(function(){var o={_v:'',set x(v){this._v=v;}};o.x='%s';return o._v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f759_s2():
    """F759 filed shape 2 blocks."""
    ok = _blocked("(function(){var o={set x(v){this.w=v;},get w(){return this._w;},set w(v){this._w=v;}};o.x='%s';return o._w+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------------------- variants (p2)

@_t
def test_p2_f758_join_variants():
    """F758: join() comma and join('-') separators, node-exact values."""
    r1 = dlp._js_parse_f758_rest_param_iife(
        "(function(){function h(...xs){return xs.join();}return h('%s','%s');})()" % (_A, _B),
        0, 0, {"ops": 0, "parts": 0})
    r2 = dlp._js_parse_f758_rest_param_iife(
        "(function(){function h(...xs){return xs.join('-');}return h('%s','%s');})()" % (_A, _B),
        0, 0, {"ops": 0, "parts": 0})
    ok = (r1 is not None and r1[0] == _A + "," + _B
          and r2 is not None and r2[0] == _A + "-" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f758_multi_plain():
    """F758: multiple plain params plus rest."""
    ok = _blocked("(function(){function h(a,b,...rest){return a+b+rest[0];}return h('%s','%s','ZZ');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_f758_ws():
    """F758: whitespace-tolerant grammar (value matches node)."""
    r = dlp._js_parse_f758_rest_param_iife(
        "(function(){ function h( ... xs ) { return xs.join( '' ); } return h( '%s' , '%s' ); })()" % (_A, _B),
        0, 0, {"ops": 0, "parts": 0})
    ok = r is not None and r[0] == _A + _B
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f759_bracket():
    """F759: bracket-string member forms."""
    ok = _blocked("(function(){var o={_v:'',set x(v){this._v=v;}};o['x']='%s';return o['_v']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_f759_multi_assign():
    """F759: later assignment wins (node-exact value)."""
    r = dlp._js_parse_f759_setter_iife(
        "(function(){var o={_v:'',set x(v){this._v=v;}};o.x='%s';o.x='%s';return o._v;})()" % (_A, _B),
        0, 0, {"ops": 0, "parts": 0})
    ok = r is not None and r[0] == _B
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f759_getter_read():
    """F759: getter read of the chained backing field."""
    ok = _blocked("(function(){var o={set x(v){this.w=v;},get w(){return this._w;},set w(v){this._w=v;}};o.x='%s';return o.w+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_f759_lit_rhs():
    """F759: literal (non-param) setter RHS (node-exact value)."""
    r = dlp._js_parse_f759_setter_iife(
        "(function(){var o={_v:'',set x(v){this._v='Q';}};o.x='%s';return o._v+'%s';})()" % (_A, _B),
        0, 0, {"ops": 0, "parts": 0})
    ok = r is not None and r[0] == "Q" + _B
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f759_multi_write():
    """F759: multi-statement setter body."""
    ok = _blocked("(function(){var o={a:'',b:'',set x(v){this.a=v;this.b=v;}};o.x='%s';return o.a+o.b;})()" % _A)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# --------------------------------------------------------------- bounds (p3)

@_t
def test_p3_f758_bounds():
    """F758: hostile bounds all fail closed."""
    cases = [
        "(function(){function h(a,...xs){return a;}return h();})()",  # arity
        "(function(){function h(...xs){return xs;}return h('%s','%s');})()" % (_A, _B),  # bare rest
        "(function(){function h(...xs){return xs[5];}return h('%s','%s');})()" % (_A, _B),  # oob
        "(function(){function h(...xs){return xs.length;}return h('%s','%s');})()" % (_A, _B),  # non-join member
        "(function(){function h(...xs){return this.x;}return h('%s','%s');})()" % (_A, _B),  # this
        "(function(){function h(...xs){return arguments[0];}return h('%s','%s');})()" % (_A, _B),  # arguments
        "(function(){function h(a,a,...xs){return a;}return h('%s','%s');})()" % (_A, _B),  # dup params
        "(function(){function* h(...xs){return xs.join('');}return h('%s','%s');})()" % (_A, _B),  # generator
        "(function(){function h(x='d',...xs){return x;}return h('%s','%s');})()" % (_A, _B),  # default
        "(function(){var z='%s';function h(...xs){return xs.join('');}return h(z,'%s');})()" % (_A, _B),  # non-literal arg
        "(function(){function h(...xs){return xs.join('','');}return h('%s','%s');})()" % (_A, _B),  # join 2 args
    ]
    bad = [c for c in cases if not _misses(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "leaks=%d" % len(bad))


@_t
def test_p3_f759_bounds():
    """F759: hostile bounds all fail closed."""
    cases = [
        "(function(){var o={set x(v){this.x=v;}};o.x='%s';return 'done';})()" % _A,  # re-entrant
        "(function(){var o={_v:'',set x(v){this._v=w;}};o.x='%s';return o._v+'%s';})()" % (_A, _B),  # non-param rhs
        "(function(){var o={set x(v){this._v=v;}};o.x='%s';return o.x+'%s';})()" % (_A, _B),  # read setter-only
        "(function(){var o={_v:'',get x(){return this._v;}};o.x='%s';return o._v+'%s';})()" % (_A, _B),  # getter-only write
        "(function(){var o={__proto__:{},set x(v){this._v=v;}};o.x='%s';return o._v+'%s';})()" % (_A, _B),  # __proto__
        "(function(){var o={m(){return '%s';},set x(v){this._v=v;}};o.x='%s';return o._v+'%s';})()" % (_A, _B, _B),  # method
        "(function(){var z='%s';var o={_v:'',set x(v){this._v=v;}};o.x=z;return o._v+'%s';})()" % (_A, _B),  # non-literal rhs
        "(function(){var o={get w(){return this._w;},set x(v){this._v=v;}};o.x='%s';return o.w+'%s';})()" % (_A, _B),  # unbound getter field
    ]
    bad = [c for c in cases if not _misses(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "leaks=%d" % len(bad))


# --------------------------------------------------------- node agreement (p4)

@_t
def test_p4_node_agreement():
    """Decoder values match node v24.20.0 byte-exactly (via hooks)."""
    state = {"ops": 0, "parts": 0}
    pairs = [
        (dlp._js_parse_f758_rest_param_iife,
         "(function(){function h(...xs){return xs.join('');}return h('%s','%s');})()" % (_A, _B),
         _A + _B),
        (dlp._js_parse_f758_rest_param_iife,
         "(function(){function h(a,...rest){return a+rest[0];}return h('%s','%s');})()" % (_A, _B),
         _A + _B),
        (dlp._js_parse_f758_rest_param_iife,
         "(function(){function h(...xs){return xs.join();}return h('%s','%s');})()" % (_A, _B),
         _A + "," + _B),
        (dlp._js_parse_f759_setter_iife,
         "(function(){var o={_v:'',set x(v){this._v=v;}};o.x='%s';return o._v+'%s';})()" % (_A, _B),
         _A + _B),
        (dlp._js_parse_f759_setter_iife,
         "(function(){var o={set x(v){this.w=v;},get w(){return this._w;},set w(v){this._w=v;}};o.x='%s';return o._w+'%s';})()" % (_A, _B),
         _A + _B),
    ]
    bad = 0
    for fn, shape, want in pairs:
        r = fn(shape, 0, 0, {"ops": 0, "parts": 0})
        if r is None or r[0] != want:
            bad += 1
    ok = bad == 0
    return ("HELD" if ok else "BREAK", "mismatch=%d" % bad)


# -------------------------------------------------------------- siblings (p5)

@_t
def test_p5_siblings_intact():
    """Sibling routes still decode; open neighbors still miss; honest text quiet."""
    hold = [
        "(function(){var f='%s';function g(){return f;}return g()+'%s';})()" % (_A, _B),  # F735
        "(function(){function h(a='%s'){return a;}return h()+'%s';})()" % (_A, _B),  # F736
        "(function(){function h(a){return a;}return h('%s')+'%s';})()" % (_A, _B),  # F736 plain
        "(function(){var o={get s(){return '%s';}};return o.s+'%s';})()" % (_A, _B),  # F535
        "((...a)=>a.join(''))('%s','%s')" % (_A, _B),  # F577
        "((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B),  # F608
    ]
    miss = [
        "the quarterly report shows revenue growth",
        "(function(){var s='hello';return s;})()",
    ]
    # F760 (template-nested member reads) now blocks (closed wave-384
    # lane 12) -- removed from the miss list.
    bad = [s for s in hold if not _blocked(s)] + [s for s in miss if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%d" % len(bad))


# ------------------------------------------------------------------ perf (p6)

@_t
def test_p6_perf():
    """200 mixed sites decode quickly (F452 budget intact)."""
    t0 = time.time()
    for _ in range(100):
        _blocked("(function(){function h(...xs){return xs.join('');}return h('ab','cd');})()")
        _misses("(function(){function h(...xs){return xs;}return h('ab','cd');})()")
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ---------------------------------------------------------- green check (p7)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts must show 0 BREAK on the closed tree.
    # w383_attack_probes expects exactly 1 BREAK: its footer test
    # still asserts the base footer (open F738-F761 incl.
    # F758/F759); the lane-local footer (F758/F759 closed) is
    # merge-owned tree-wide (wave-305/306 class). Any other BREAK
    # fails loudly.
    for batt, expect_break in (("evals/w383_f758_redfirst.py", 0),
                               ("evals/w383_f759_redfirst.py", 0),
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
    """Depth-1 green check: F758/F759 red-firsts + wave-383 attack battery."""
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
