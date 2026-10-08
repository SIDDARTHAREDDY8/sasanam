#!/usr/bin/env python3
"""Wave-383 lane 2: close F715 + F716 (deleteProperty `{return false;}` residual; Reflect.set).

F715 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
F675 (CLOSED wave-380 lane 3) modeled the deleteProperty trap for the
no-op `{return true;}` body and the deleting body, but not a
`{return false;}` body: the delete fails, the fragment stays in the
target, and the decoder produced zero variants. Filed shapes:
`(function(){var t={x:'f1'};var p=new
Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete
p.x;return t.x+'f2';})()` and the twin with `(a,b)` params and
`delete p['y']`.

F716 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
the decoder had no Reflect.set production -- Reflect.set installs
the fragment on the object and a later member read recovers it
while the decoder produced zero variants. Filed shapes:
`(function(){var o={};Reflect.set(o,'x','f1');return
o.x+'f2';})()` and the var-bound-key twin
`(function(){var o={};var k='x';Reflect.set(o,k,'f1');return
o[k]+'f2';})()`.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F715: `_js_parse_f675_delete_body_after_head` now accepts
  `false` as the trap-body return in both block
  (`{return false;}`) and concise (`=>false`) forms, returning
  deletes=False unless the body itself deleted (saw_delete).
  Node-exact (v24.20.0): in sloppy mode the trap's false return
  makes the delete expression evaluate to false while the member
  survives; the strict-mode directive prologue fails closed
  earlier at the F675 decl parse. F675's pins are unaffected
  (`{return true;}` / deleting bodies decode identically).
- F716: new `_js_parse_f716_reflect_set_iife` -- the var-bound
  Reflect.set IIFE grammar (`DECL o=OBJLIT;` + optional
  `DECL k='LIT';` key aliases + one-or-more
  `Reflect.set(o,KEY,'LIT');` + `return ADD;`), hooked after
  F702/F703 (disjoint: no earlier route accepts a `Reflect.set(`
  statement head; the F702/F703 hook and trailing `return` are
  untouched, wave-379 lesson). Node-exact (v24.20.0): data-prop
  install with later-wins; set on a getter-only accessor fails
  closed (the engine's [[Set]] returns false and installs
  nothing); `__proto__` keys, non-string values (F699
  unsafe-int guard), receiver args, `Reflect['set']`, and
  unbound targets all fail closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g383-*
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


# ------------------------------------------------------- p0: pin control


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------- b0: footer control


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F715/F716 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F738**" in text
          and "Open findings: F713, F714, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- p1: filed shapes


@_t
def test_p1_f715_s1():
    """F715 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f715-s1=%s" % ok)


@_t
def test_p1_f715_s2():
    """F715 filed shape 2 (param twins, bracket delete) blocks."""
    ok = _blocked(
        "(function(){var t={y:'%s'};var p=new Proxy(t,{deleteProperty:function(a,b){return false;}});delete p['y'];return t.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f715-s2=%s" % ok)


@_t
def test_p1_f716_s1():
    """F716 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={};Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f716-s1=%s" % ok)


@_t
def test_p1_f716_s2():
    """F716 filed shape 2 (var-bound key) blocks."""
    ok = _blocked(
        "(function(){var o={};var k='x';Reflect.set(o,k,'%s');return o[k]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f716-s2=%s" % ok)


# ------------------------------------------------------- p2: variants


@_t
def test_p2_f715_concise_false():
    """F715 variant: concise `=>false` trap body blocks."""
    ok = _blocked(
        "(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:(a,b)=>false});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "concise-false=%s" % ok)


@_t
def test_p2_f715_body_delete_then_false():
    """F715 variant: body-delete + `return false` stays fail-closed (member gone)."""
    ok = _misses(
        "(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){delete tr[pr];return false;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "body-delete-closed=%s" % ok)


@_t
def test_p2_f716_later_wins():
    """F716 variant: two sets on one key -- later wins, node-exact."""
    ok = _blocked(
        "(function(){var o={};Reflect.set(o,'x','nope');Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "later-wins=%s" % ok)


@_t
def test_p2_f716_overwrite_literal():
    """F716 variant: set over an initial literal prop decodes node-exactly."""
    ok = _blocked(
        "(function(){var o={z:'nope'};Reflect.set(o,'z','%s');return o.z+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "overwrite=%s" % ok)


@_t
def test_p2_f716_bracket_read():
    """F716 variant: bracket-literal read of a set key blocks."""
    ok = _blocked(
        "(function(){var o={};Reflect.set(o,'x','%s');return o['x']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket-read=%s" % ok)


# ------------------------------------------------------- p3: bounds


@_t
def test_p3_f715_return_zero_closed():
    """Bound: `{return 0;}` trap body fails closed."""
    ok = _misses(
        "(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return 0;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "return-0-closed=%s" % ok)


@_t
def test_p3_f715_strict_closed():
    """Bound: strict-mode directive prologue fails closed."""
    ok = _misses(
        "(function(){'use strict';var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "strict-closed=%s" % ok)


@_t
def test_p3_f716_bracket_set_closed():
    """Bound: `Reflect['set']` fails closed (dot form only)."""
    ok = _misses(
        "(function(){var o={};Reflect['set'](o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket-set-closed=%s" % ok)


@_t
def test_p3_f716_receiver_closed():
    """Bound: 4th receiver argument fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.set(o,'x','%s',{});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "receiver-closed=%s" % ok)


@_t
def test_p3_f716_proto_closed():
    """Bound: `__proto__` set key fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.set(o,'__proto__','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "proto-closed=%s" % ok)


@_t
def test_p3_f716_nonstring_value_closed():
    """Bound: non-string set value fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.set(o,'x',123);return o.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "nonstring-closed=%s" % ok)


@_t
def test_p3_f716_unbound_key_closed():
    """Bound: unbound key ident fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.set(o,q,'%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbound-key-closed=%s" % ok)


@_t
def test_p3_f716_missing_read_closed():
    """Bound: read of a never-set key fails closed (engine undefined)."""
    ok = _misses(
        "(function(){var o={};Reflect.set(o,'x','%s');return o.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "missing-read-closed=%s" % ok)


@_t
def test_p3_f716_accessor_set_closed():
    """Bound: set on a getter-only accessor key fails closed."""
    ok = _misses(
        "(function(){var o={get x(){return 'a';}};Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "accessor-set-closed=%s" % ok)


# ------------------------------------------------------- p4: siblings


@_t
def test_p4_sibling_f675_true_noop():
    """Sibling: F675 `{return true;}` no-op pin still blocks."""
    ok = _blocked(
        "(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return true;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f675-true=%s" % ok)


@_t
def test_p4_sibling_f675_delete_body():
    """Sibling: F675 deleting-body pin still blocks (other member read)."""
    ok = _blocked(
        "(function(){var t={x:'junk',y:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){delete tr[pr];return true;}});delete p.x;return t.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f675-delete=%s" % ok)


@_t
def test_p4_sibling_f705():
    """Sibling: F705 Reflect.get pin still blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};return Reflect.get(o,'x')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f705=%s" % ok)


@_t
def test_p4_neighbor_f717_open():
    """Neighbor: F717 (Reflect.defineProperty) still misses (open)."""
    ok = _misses(
        "(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f717-open=%s" % ok)


@_t
def test_p4_neighbor_f713_open():
    """Neighbor: F713 (lane-7 Map spread-join) still misses (open)."""
    ok = _misses(
        "(function(){var m=new Map([['k','%s']]);return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f713-open=%s" % ok)


# ------------------------------------------------------- p5: honest + perf


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_junk_quiet():
    """Junk control stays quiet."""
    ok = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if ok else "BREAK", "junk=%s" % ok)


@_t
def test_p6_perf():
    """200 mixed F715/F716 sites decode in bounded time (non-credential literals)."""
    corpus = []
    for k in range(100):
        corpus.append(
            "(function(){var o={};Reflect.set(o,'x','a%d');return o.x+'b';})()" % k)
        corpus.append(
            "(function(){var t={x:'a%d'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete p.x;return t.x+'b';})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p9: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # The F715/F716 red-firsts expect 0 BREAK now (closed); the attack
    # battery expects 0 BREAK after the lane's pin flips.
    for batt, expect_break in (("evals/w382_f715_redfirst.py", 0),
                               ("evals/w382_f716_redfirst.py", 0),
                               ("evals/w382_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
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
def test_p9_green_check():
    """Depth-1 green check: F715/F716 red-firsts + attack battery green."""
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
