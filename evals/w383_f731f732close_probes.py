#!/usr/bin/env python3
"""Wave-383 lane 10: close F731 + F732 (Proxy isExtensible-trap and
getPrototypeOf-trap write-body residuals).

F731 (LOW; filed 2026-10-08 by wave-382 lane 8, attack round 50): Proxy
isExtensible-trap -- the decoder modeled Proxy set/construct/
deleteProperty/getPrototypeOf traps (F675) and ownKeys (F686) but not
the isExtensible trap: the trap result selects the fragment branch of
a ternary while the decoder produced zero variants:
  (function(){var p=new Proxy({},{isExtensible:function(t){return true;}});
   var f=Object.isExtensible(p)?'f1':'xx';return f+'f2';})()
and the negation twin. Distinct from F687/F710 (their ternary
vehicles); the novel contribution is the unmodeled isExtensible trap.

F732 (LOW; filed 2026-10-08 by wave-382 lane 8, attack round 50): F675
residual -- Proxy getPrototypeOf-trap write body: F675 (CLOSED)
models the getPrototypeOf trap for literal-object returns but not a
target-write body:
  (function(){var t={};var p=new Proxy(t,{getPrototypeOf:
   function(tr){tr.__g='f1';return Object.getPrototypeOf(tr);}});
   Object.getPrototypeOf(p);return t.__g+'f2';})()
and the bracket-key twin. F675 stays CLOSED on its pins; only the
write-body shape is closed here.

Fix (gov/dlp.py, zero new re.compile):
- F731: _js_parse_f731_isext_iife (+6 helpers), hooked after F707
  with its hook and trailing return intact (wave-379 lesson);
  disjoint by the `isExtensible` handler key. The modeled trap
  returns a literal whose ToBoolean is `true` (true/1/'x' -- the
  engine applies ToBoolean before the invariant check; a falsy
  literal throws TypeError in the engine on a literal-object
  target, node v24.20.0, so it fails closed -- the decoder never
  decodes a throw). The ternary selects its branch node-exactly
  (the F710 ternary idiom).
- F732: _js_parse_f732_gopwrite_iife (+5 helpers), hooked after
  F731; disjoint from F675's getPrototypeOf route (which requires
  a literal-object-return trap body -- this write body fails that
  parse). The firing statement `Object.getPrototypeOf(p)` applies
  each modeled write to the tracked target node-exactly; trap
  writes must target keys absent from the original literal (a
  write to a pre-existing key fails closed: a getter-origin key,
  value-resolved by the F535 parse, would silently ignore the
  assignment in the engine -- mis-decode if recorded).
  Writes to keys added by earlier trap writes in the same body
  are later-wins (node-exact).

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


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F731/F732 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f731_s1():
    """F731 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return true;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f731_s2():
    """F731 filed shape 2 (negation twin) blocks + decodes node-exact."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return true;}});var f=!Object.isExtensible(p)?'xx':'"
         + _A + "';return f+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f732_s1():
    """F732 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){tr.__g='" + _A + "';return "
         "Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);"
         "return t.__g+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f732_s2():
    """F732 filed shape 2 (bracket-key twin) blocks + decodes node-exact."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(x){x['h']='" + _A + "';return "
         "Object.getPrototypeOf(x);}});Object.getPrototypeOf(p);"
         "return t.h+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f731_arrow():
    """F731 concise-arrow trap body blocks + exact."""
    s = ("(function(){var p=new Proxy({},{isExtensible:(t)=>true});"
         "var f=Object.isExtensible(p)?'" + _A + "':'xx';return f+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f731_method():
    """F731 method-shorthand trap body blocks + exact."""
    s = ("(function(){var p=new Proxy({},{isExtensible(t)"
         "{return true;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f732_method():
    """F732 method-shorthand trap body blocks + exact."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf(tr)"
         "{tr.__g='" + _A + "';return Object.getPrototypeOf(tr);}});"
         "Object.getPrototypeOf(p);return t.__g+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f732_multiwrite():
    """F732 multi-write body: later-wins, node-exact."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){tr.a='xx';tr.a='" + _A + "';return "
         "Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);"
         "return t.a+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f732_freshkey_getter_target():
    """F732 write to a fresh key on a getter-bearing target: exact."""
    s = ("(function(){var t={get g(){return 'z';}};var p=new Proxy(t,"
         "{getPrototypeOf:function(tr){tr.__g='" + _A + "';return "
         "Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);"
         "return t.__g+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f731_truthy_one():
    """F731 `return 1` trap: ToBoolean true, blocks + exact."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return 1;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f731_truthy_string():
    """F731 `return 'x'` trap: ToBoolean true, blocks + exact."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return 'x';}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p3_f731_falsy_zero():
    """F731 `return 0` trap: engine throws -> fail closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return 0;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_falsy_empty_string():
    """F731 `return ''` trap: engine throws -> fail closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return '';}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_unmodeled_hex():
    """F731 `return 0x1` trap: unmodeled literal form -> fail closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return 0x1;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_unmodeled_float():
    """F731 `return 1.5` trap: unmodeled literal form -> fail closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return 1.5;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f731_false_throws():
    """F731 `return false` trap: engine throws -> fail closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return false;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_nonlit_body():
    """F731 non-literal trap body fails closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return t;}});var f=Object.isExtensible(p)?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_write_body():
    """F731 trap body with a write fails closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{t.x=1;return true;}});var f=Object.isExtensible(p)?'"
         + _A + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_nonproxy():
    """F731 Object.isExtensible on a non-proxy fails closed."""
    s = ("(function(){var f=Object.isExtensible({})?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_nonlit_branch():
    """F731 non-literal ternary branch fails closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return true;}});var f=Object.isExtensible(p)?x:'xx';"
         "return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f731_extra_stmt():
    """F731 extra statement fails closed."""
    s = ("(function(){var p=new Proxy({},{isExtensible:function(t)"
         "{return true;}});var z=1;var f=Object.isExtensible(p)?'"
         + _A + "':'xx';return f+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f732_nowrite():
    """F732 trap that never writes fails closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){return Object.getPrototypeOf(tr);}});"
         "Object.getPrototypeOf(p);return t.__g+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f732_proto_write():
    """F732 __proto__ write fails closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){tr.__proto__='" + _A + "';return "
         "Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);"
         "return t.x+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f732_nonlit_write():
    """F732 non-literal write value fails closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){tr.__g=x;return Object.getPrototypeOf(tr);}});"
         "Object.getPrototypeOf(p);return t.__g+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f732_nofire():
    """F732 without the firing statement fails closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){tr.__g='" + _A + "';return "
         "Object.getPrototypeOf(tr);}});return t.__g+'" + _B
         + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f732_getterkey_overwrite():
    """F732 write to a getter-origin key fails closed (would mis-decode)."""
    s = ("(function(){var t={get g(){return 'z';}};var p=new Proxy(t,"
         "{getPrototypeOf:function(tr){tr.g='" + _A + "';return "
         "Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);"
         "return t.g+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f732_wrong_receiver():
    """F732 terminal on the wrong receiver fails closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){tr.__g='" + _A + "';return "
         "Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);"
         "return q.__g+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f675_getproto():
    """F675 getPrototypeOf literal-object-return pin still blocks."""
    s = ("(function(){var p=new Proxy({},{getPrototypeOf:function(){"
         "return {m:'" + _A + "'};}});return Object.getPrototypeOf(p).m+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f675=%s" % ok)


@_t
def test_p4_sibling_f706():
    """F706 defineProperty-trap pin still blocks."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:"
         "function(tr,pr,de){tr[pr]=de.value||'xx';return true;}});"
         "Object.defineProperty(p,'k',{value:'" + _A + "'});"
         "return t.k+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f706=%s" % ok)


@_t
def test_p4_sibling_f707():
    """F707 gOPD-trap pin still blocks."""
    s = ("(function(){var t={k:'" + _A + "'};var p=new Proxy(t,"
         "{getOwnPropertyDescriptor:function(tr,pr){return {value:tr[pr],"
         "configurable:true};}});return Object."
         "getOwnPropertyDescriptor(p,'k').value+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f707=%s" % ok)


@_t
def test_p4_neighbor_f730_open():
    """Neighbor: Object.entries indexed access (non-destructuring) still
    misses -- out of F730's destructuring scope; honest open shape."""
    s = ("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
         "function(tr){return Object.getPrototypeOf(tr);}});"
         "var e=Object.entries({a:'" + _A + "'});return e[0][1]+'"
         + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f730-indexed-open=%s" % ok)


@_t
def test_p4_neighbor_f733_open():
    """Neighbor F733 now BLOCKS (closed wave-383 merge)."""
    s = ("(function(){var w=new WeakRef({v:'" + _A + "'});"
         "return w.deref().v+'" + _B + "';})()")
    ok = not _misses(s)
    return ("HELD" if ok else "BREAK", "f733-closed=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_ternary_unaffected():
    """Honest ternary without a proxy still misses."""
    s = ("(function(){var f=(1===1)?'ab':'xx';return f+'cd';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_getproto_unaffected():
    """Honest Object.getPrototypeOf without a proxy still misses."""
    s = "Object.getPrototypeOf([]).constructor.name"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){var p=new Proxy({},{isExtensible:function(t)"
            "{return true;}});var f=Object.isExtensible(p)?'a%d':'xx';"
            "return f;})()" % k)
        sites.append(
            "(function(){var t={};var p=new Proxy(t,{getPrototypeOf:"
            "function(tr){tr.k%d='v';return Object.getPrototypeOf(tr);}});"
            "Object.getPrototypeOf(p);return t.k%d;})()" % (k, k))
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # w382_attack_probes.py expects 1 BREAK: its test_b0_footer_state
    # asserts the base footer (open F713-F737); the lane-local repoint
    # (F731/F732 closed) moves it. The tree-wide footer repoint is
    # merge-owned (wave-305 lesson); all functional probes must HELD.
    for batt, expect_break in (("evals/w382_f731_redfirst.py", 0),
                               ("evals/w382_f732_redfirst.py", 0),
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
def test_p7_green_check():
    """Depth-1 green check: F731/F732 red-firsts (0 BREAK) + wave-382
    attack battery (1 BREAK: the footer pin only, lane-local repoint;
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
