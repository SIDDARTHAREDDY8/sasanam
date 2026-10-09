#!/usr/bin/env python3
"""Wave-383 lane 13: close F737 (Proxy setPrototypeOf-trap fragment writes).

F737 (LOW, filed 2026-10-08 by wave-382 lane 8 as F713, renumbered at
the wave-382 merge -- lane 7 filed F713 first at 17:58:21 UTC):
Object.setPrototypeOf(p,PROTO) fires a setPrototypeOf trap whose body
writes the fragment to the bound target, leaving it readable via the
target while the decoder produced zero variants:
(function(){var t={};var p=new Proxy(t,{setPrototypeOf:
function(tr,pr){tr.__p='f1';return true;}});Object.setPrototypeOf(p,{});
return t.__p+'f2';})() and the bracket-key twin
(function(){var t={};var p=new Proxy(t,{setPrototypeOf:
function(tg,pt){tg['k']='f1';return true;}});Object.setPrototypeOf(p,[]);
return t.k+'f2';})() both node-evaluate to the exact credential (node
v24.20.0). Distinct from F675 (set/construct/deleteProperty/
getPrototypeOf traps -- no setPrototypeOf production) and F686
(ownKeys). Controls: F675 getPrototypeOf pin blocks coded;
junk-quiet control passes.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f737_setproto_trap_iife (+ _js_parse_f737_setproto_fn,
  _js_parse_f737_setproto_method_body,
  _js_parse_f737_setproto_body_after_head, _js_parse_f737_proto_arg):
  the statement-IIFE body grammar is `var|let|const t={PROPS};
  var|let|const p=new Proxy(t,{setPrototypeOf:SPFN});
  Object.setPrototypeOf(p,PROTO);return (t|p).MEM(+'LIT')*;`.
  The trap body is (TRIDENT.MEM='LIT';|TRIDENT['LIT']='LIT';)+
  `return true;` (function and method-shorthand forms; arrow-block
  also works via the shared F675 fn head). Writes apply to the
  tracked target with later-wins; PROTO is spanned and ignored
  (any {}/[]/null literal -- the engine fires the trap regardless
  and the value never feeds the read). `return true` is required
  (falsy trap return throws TypeError in the engine, node
  v24.20.0). `__proto__` fails closed on write and read (the engine
  changes the prototype, not an own data prop). Accessor-valued
  target props fail closed on overwrite (engine throws --
  wave-382 lane-2 lesson). F452 parts charged per write.
  Hooked after the F675 revocable parser; disjoint by the
  `setPrototypeOf` handler key plus the Object.setPrototypeOf
  fire statement (red-first verified: 2 BREAK on the open tree).

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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F737 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f737_s1():
    """F737 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.__p='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.__p+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f737-s1=%s" % ok)


@_t
def test_p1_f737_s2():
    """F737 filed shape 2 (bracket-key write) blocks."""
    ok = _blocked(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tg,pt){tg['k']='%s';return true;}});"
        "Object.setPrototypeOf(p,[]);return t.k+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f737-s2=%s" % ok)


# ------------------------------------------------------------- variants p2

@_t
def test_p2_two_writes():
    """Two trap writes + null proto decode node-exactly."""
    ok = _blocked(
        "(function(){var t={x:'z'};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.a='%s';tr.b='%s';return true;}});"
        "Object.setPrototypeOf(p,null);return t.a+t.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "two-writes=%s" % ok)


@_t
def test_p2_method_shorthand():
    """setPrototypeOf(tr,pr){...} method shorthand blocks."""
    ok = _blocked(
        "(function(){const t={};let p=new Proxy(t,{setPrototypeOf(tr,pr)"
        "{tr.m='%s';return true;}});Object.setPrototypeOf(p,{});"
        "return t.m+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "shorthand=%s" % ok)


@_t
def test_p2_arrow_block():
    """(tr,pr)=>{...} arrow-block trap blocks."""
    ok = _blocked(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "(tr,pr)=>{tr.m='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.m+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "arrow=%s" % ok)


@_t
def test_p2_initial_props():
    """Initial target props survive alongside trap writes."""
    ok = _blocked(
        "(function(){var t={z:'q'};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.z+t.m+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "initial=%s" % ok)


@_t
def test_p2_proxy_receiver_read():
    """Terminal read via the proxy falls through to the target."""
    ok = _blocked(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return p.m+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "proxy-read=%s" % ok)


@_t
def test_p2_member_summand_tail():
    """Additive tail with a second tracked-member summand blocks."""
    ok = _blocked(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.a='%s';tr.b='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.a+t.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "summand=%s" % ok)


# --------------------------------------------------------------- bounds p3

@_t
def test_p3_bound_return_false():
    """Trap returning false throws in the engine -- fail closed."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m='%s';return false;}});"
        "Object.setPrototypeOf(p,{});return t.m;})()" % _A)
    return ("HELD" if ok else "BREAK", "retfalse=%s" % ok)


@_t
def test_p3_bound_proto_write():
    """__proto__ write changes the prototype -- fail closed."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.__proto__='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.__proto__;})()" % _A)
    return ("HELD" if ok else "BREAK", "protow=%s" % ok)


@_t
def test_p3_bound_direct_target():
    """Object.setPrototypeOf on the raw target fires no trap."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m='%s';return true;}});"
        "Object.setPrototypeOf(t,{});return t.m;})()" % _A)
    return ("HELD" if ok else "BREAK", "direct=%s" % ok)


@_t
def test_p3_bound_wrong_param():
    """Write to the proto param never reaches the target."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){pr.m='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.m;})()" % _A)
    return ("HELD" if ok else "BREAK", "protoparam=%s" % ok)


@_t
def test_p3_bound_no_fire():
    """No Object.setPrototypeOf call -- trap never fires."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m='%s';return true;}});"
        "return t.m;})()" % _A)
    return ("HELD" if ok else "BREAK", "nofire=%s" % ok)


@_t
def test_p3_bound_no_return_true():
    """Trap without `return true` -- fail closed."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m='%s';}});"
        "Object.setPrototypeOf(p,{});return t.m;})()" % _A)
    return ("HELD" if ok else "BREAK", "noret=%s" % ok)


@_t
def test_p3_bound_nonliteral_write():
    """Non-literal write value -- fail closed."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m=other;return true;}});"
        "Object.setPrototypeOf(p,{});return t.m;})()")
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_bound_unwritten_read():
    """Read of a never-written member is undefined -- fail closed."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.m='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.nope;})()" % _A)
    return ("HELD" if ok else "BREAK", "unwritten=%s" % ok)


@_t
def test_p3_bound_accessor_overwrite():
    """Trap write over a getter is silently ignored (sloppy mode).

    The engine drops the [[Set]] on the getter-only accessor, so
    the read returns the getter's value -- node-exact, v24.20.0.
    Discriminating: if the decoder wrongly applied the trap write,
    the getter's credential would vanish (MISS); the correct
    silent-ignore keeps it (BLOCK).
    """
    ok = _blocked(
        "(function(){var t={get m(){return '%s';}};var p=new Proxy(t,"
        "{setPrototypeOf:function(tr,pr){tr.m='zz';return true;}});"
        "Object.setPrototypeOf(p,{});return t.m+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "accessor=%s" % ok)


@_t
def test_p3_bound_accessor_no_false_positive():
    """No false positive: a credential-shaped trap literal over a
    getter must NOT block (node never produces it)."""
    ok = _misses(
        "(function(){var t={get m(){return 'gx';}};var p=new Proxy(t,"
        "{setPrototypeOf:function(tr,pr){tr.m='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.m+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "accessor-fp=%s" % ok)


@_t
def test_p3_bound_getter_read_no_overwrite():
    """Getter read without any trap overwrite decodes node-exactly."""
    ok = _blocked(
        "(function(){var t={get m(){return '%s';}};var p=new Proxy(t,"
        "{setPrototypeOf:function(tr,pr){tr.other='zz';return true;}});"
        "Object.setPrototypeOf(p,{});return t.m+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "getter-read=%s" % ok)


@_t
def test_p3_bound_computed_key():
    """Computed (non-literal) write key -- fail closed."""
    ok = _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr['k'+'e'+'y']='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.key;})()" % _A)
    return ("HELD" if ok else "BREAK", "computed=%s" % ok)


# ------------------------------------------- siblings and open neighbors p4

@_t
def test_p4_sibling_f675_getproto():
    """F675 getPrototypeOf trap still blocks."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{getPrototypeOf:"
        "function(){return {x:'%s'};}});"
        "return Object.getPrototypeOf(p).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f675=%s" % ok)


@_t
def test_p4_sibling_f686_ownkeys():
    """F686 ownKeys trap still blocks."""
    ok = _blocked(
        "(function(){var p=new Proxy({},{ownKeys:function(){return "
        "['%s','%s'];},getOwnPropertyDescriptor:function(){return "
        "{enumerable:true,configurable:true};}});"
        "return Object.keys(p).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)


@_t
def test_p4_neighbor_f713_open():
    """F713 (open) still misses."""
    ok = not _misses(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f713-closed=%s" % ok)


@_t
def test_p4_neighbor_f714_open():
    """F714 (open) still misses."""
    ok = not _misses(
        "(function(){var p=new Proxy({},{has:function(t,k){return true;}});"
        "var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f714-closed=%s" % ok)


@_t
def test_p4_neighbor_f716_open():
    """F716 (open) still misses."""
    ok = not _misses(
        "(function(){var o={};Reflect.set(o,'x','%s');"
        "return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f716-closed=%s" % ok)


# ------------------------------------------------------- honest text p5

@_t
def test_p5_junk_quiet():
    """Honest text stays quiet."""
    ok = _misses("just a regular sentence about setting prototypes")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_setprototypeof():
    """Honest Object.setPrototypeOf without a trap is not flagged."""
    ok = _misses(
        "(function(){var t={};Object.setPrototypeOf(t,{});"
        "return 'done';})()")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ----------------------------------------------------------------- perf p6

@_t
def test_p6_perf():
    """200 mixed sites decode in reasonable time."""
    t0 = time.time()
    for k in range(200):
        _blocked(
            "(function(){var t%d={};var p%d=new Proxy(t%d,"
            "{setPrototypeOf:function(tr,pr){tr.m%d='x';return true;}});"
            "Object.setPrototypeOf(p%d,{});return t%d.m%d;})()"
            % (k, k, k, k, k, k, k))
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w382_f737_redfirst.py", 0),
                               ("evals/w382_attack_probes.py", 0)):
        # w382_attack: 1 tolerated BREAK is test_b0_footer_state, which
        # asserts the base footer; the lane-local footer repoint is
        # merge-owned (wave-382 lane-5 precedent).
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
def test_p7_green_check():
    """Depth-1 green check: F737 red-first + wave-382 attack battery green."""
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
