#!/usr/bin/env python3
"""Wave-386 lane 7: close F807 + F808 (structuredClone reads; CustomEvent detail reads).

F807 (LOW; filed 2026-10-09 by wave-385 attack round 53): the decoder
has no structuredClone production -- structuredClone(o).k resolves
node-exactly (v24.20.0) while the decoder produces zero variants.

F808 (LOW; filed 2026-10-09 by wave-385 attack round 53): the decoder
has no event-target production -- an EventTarget dispatch carrying a
detail payload resolves node-exactly (v24.20.0) inside the registered
listener while the decoder produces zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F807: _js_parse_f807_structuredclone_iife, hooked after F792 with
  parts/ops snapshot-restore on miss. (function(){DECL O={...};
  DECL C=structuredClone(O);return ADD;})(). The object literal is
  parsed by _js_f807_parse_nested_obj (plain string values, nesting;
  __proto__/getters/methods/spreads/computed keys fail closed); the
  clone is a prototype-dropping deep copy (node-verified).
- F808: _js_parse_f808_customevent_iife, hooked after F807 with
  snapshot-restore. (function(){var t=new EventTarget();var r='LIT';
  t.addEventListener('TYPE',function(e){r=e.detail(.MEM)*;});
  t.dispatchEvent(new CustomEvent('TYPE',{detail:VAL}));
  return ADD;})(). The dispatch is modeled synchronously: the single
  registered listener runs with the event, executing the single
  r=e.detail(.MEM)* assignment. Type mismatches, missing detail,
  second listeners, member-on-string-detail, and param shadowing
  all fail closed (node-verified).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
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
def test_p0_no_new_re():
    """Zero new re.compile (28 stays)."""
    import re as _re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(_re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F807/F808 closed, F829-F831 filed, next F832)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F832**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, "
              "F801, F802, F803, F804, F805, F806, F809, F810, F811, "
              "F812, F813, F814, F815, F816, F817, F819, F820, F821, "
              "F822, F823, F824, F825, F826, F827, F828, F829, F830, "
              "F831." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block, node-exact)


@_t
def test_p1_f807_s1():
    """F807 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var o={k:'" + _A + "'};var c=structuredClone(o);"
         "return c.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f807_s2():
    """F807 filed shape 2 (nested) blocks + decodes node-exact."""
    s = ("(function(){var o={a:{b:'" + _A + "'}};var c=structuredClone(o);"
         "return c.a.b+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f808_s1():
    """F808 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var t=new EventTarget();var r='';"
         "t.addEventListener('x',function(e){r=e.detail;});"
         "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
         "return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f808_s2():
    """F808 filed shape 2 (nested detail) blocks + decodes node-exact."""
    s = ("(function(){var t=new EventTarget();var r='';"
         "t.addEventListener('y',function(e){r=e.detail.k;});"
         "t.dispatchEvent(new CustomEvent('y',{detail:{k:'" + _A + "'}}));"
         "return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-exact)


@_t
def test_p2_f807_variants():
    """F807 generalizations: let/const, ws, double quotes, orig read, deep."""
    cases = [
        ("(function(){let o={k:'" + _A + "'};const c=structuredClone(o);"
          "return c.k+'" + _B + "';})()"),
        ("(function(){ var o = { k : '" + _A + "' } ; var c = structuredClone( o ) ;"
          " return c.k + '" + _B + "' ; })()"),
        ('(function(){var o={"k":"' + _A + '"};var c=structuredClone(o);'
          'return c.k+"' + _B + '";})()'),
        ("(function(){var o={k:'" + _A + "'};var c=structuredClone(o);"
          "return o.k+'" + _B + "';})()"),
        ("(function(){var o={a:{b:{c:'" + _A + "'}}};var c=structuredClone(o);"
          "return c.a.b.c+'" + _B + "';})()"),
        ("(function(){var o={k:'" + _A + "',j:'zz'};var c=structuredClone(o);"
          "return c.j+c.k+'" + _B + "';})()"),
    ]
    bad = [c for c in cases
           if not (_blocked(c) and _decodes_exact(c, _A + _B))]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d bad=%d" % (len(cases), len(bad)))


@_t
def test_p2_f808_variants():
    """F808 generalizations: ws, non-empty init, deep detail, dq."""
    cases = [
        ("(function(){ var t = new EventTarget() ; var r = '' ;"
          " t.addEventListener( 'x' , function( e ) { r = e.detail ; } ) ;"
          " t.dispatchEvent( new CustomEvent( 'x' , { detail : '" + _A + "' } ) ) ;"
          " return r + '" + _B + "' ; })()"),
        ("(function(){var t=new EventTarget();var r='zz';"
          "t.addEventListener('x',function(e){r=e.detail;});"
          "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
          "return r+'" + _B + "';})()"),
        ("(function(){var t=new EventTarget();var r='';"
          "t.addEventListener('x',function(e){r=e.detail.a.b;});"
          "t.dispatchEvent(new CustomEvent('x',{detail:{a:{b:'" + _A + "'}}}));"
          "return r+'" + _B + "';})()"),
        ('(function(){var t=new EventTarget();var r="";'
          't.addEventListener("x",function(e){r=e.detail;});'
          't.dispatchEvent(new CustomEvent("x",{detail:"' + _A + '"}));'
          'return r+"' + _B + '";})()'),
    ]
    bad = [c for c in cases
           if not (_blocked(c) and _decodes_exact(c, _A + _B))]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d bad=%d" % (len(cases), len(bad)))


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f807_bounds():
    """F807 bounds all fail closed."""
    cases = [
        # extra structuredClone arg
        "(function(){var o={k:'" + _A + "'};var c=structuredClone(o,{});"
        "return c.k+'" + _B + "';})()",
        # unbound clone arg
        "(function(){var o={k:'" + _A + "'};var c=structuredClone(x);"
        "return c.k+'" + _B + "';})()",
        # shadowed structuredClone name
        "(function(){var structuredClone={k:'" + _A + "'};var c=structuredClone;"
        "return c.k+'" + _B + "';})()",
        # __proto__ key (F776 owns it)
        "(function(){var o={__proto__:{x:'" + _A + "'}};var c=structuredClone(o);"
        "return c.x+'" + _B + "';})()",
        # function value (engine throws on clone)
        "(function(){var o={k:function(){return '" + _A + "';}};var c=structuredClone(o);"
        "return c.k+'" + _B + "';})()",
        # non-literal value
        "(function(){var o={k:x};var c=structuredClone(o);"
        "return c.k+'" + _B + "';})()",
        # duplicate key
        "(function(){var o={k:'" + _A + "',k:'zz'};var c=structuredClone(o);"
        "return c.k+'" + _B + "';})()",
        # missing member
        "(function(){var o={k:'" + _A + "'};var c=structuredClone(o);"
        "return c.z+'" + _B + "';})()",
        # bare object read
        "(function(){var o={k:'" + _A + "'};var c=structuredClone(o);"
        "return c+'" + _B + "';})()",
        # getter value
        "(function(){var o={get k(){return '" + _A + "';}};var c=structuredClone(o);"
        "return c.k+'" + _B + "';})()",
        # spread
        "(function(){var o={...x};var c=structuredClone(o);"
        "return c.k+'" + _B + "';})()",
        # computed key
        "(function(){var o={['k']:'" + _A + "'};var c=structuredClone(o);"
        "return c.k+'" + _B + "';})()",
        # numeric key
        "(function(){var o={0:'" + _A + "'};var c=structuredClone(o);"
        "return c.k+'" + _B + "';})()",
        # bracket read (only dot chains modeled)
        "(function(){var o={k:'" + _A + "'};var c=structuredClone(o);"
        "return c['k']+'" + _B + "';})()",
        # trailing statement
        "(function(){var o={k:'" + _A + "'};var c=structuredClone(o);var q=1;"
        "return c.k+'" + _B + "';})()",
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d leaks=%d" % (len(cases), len(bad)))


@_t
def test_p3_f808_bounds():
    """F808 bounds all fail closed."""
    cases = [
        # type mismatch: listener never runs
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('z',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # missing detail option
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x'));"
        "return r+'" + _B + "';})()",
        # second listener (both run in the engine)
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.addEventListener('x',function(e){r='s';});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # member on string detail (engine: undefined)
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail.k;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # bare object detail read (engine: [object Object])
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:{k:'" + _A + "'}}));"
        "return r+'" + _B + "';})()",
        # param shadows the accumulator
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(r){r=r.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # arrow listener
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',(e)=>{r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # multi-statement listener body
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){var q=1;r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # extra option key
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "',bubbles:true}));"
        "return r+'" + _B + "';})()",
        # dispatch on a different target
        "(function(){var t=new EventTarget();var u=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "u.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # listener reads a non-detail member
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.type;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # trailing statement
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "var q=1;return r+'" + _B + "';})()",
        # non-string accumulator init
        "(function(){var t=new EventTarget();var r=5;"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
        # listener assigns a different name
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){q=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d leaks=%d" % (len(cases), len(bad)))


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_siblings():
    """Sibling productions still hold: F776 proto, F792 groupBy, F747 nullish, F769 .at."""
    cases = [
        ("(function(){var o={__proto__:{x:'" + _A + "'}};return o.x+'" + _B + "';})()"),
        ("(function(){var M=Map.groupBy(['" + _A + "'],function(x){return 'k';});"
          "return M.get('k')[0]+'" + _B + "';})()"),
        ("(function(){var o=null;return (o ?? '" + _A + "')+'" + _B + "';})()"),
        ("(function(){var a=['" + _A + "','xx'];return a.at(0)+'" + _B + "';})()"),
    ]
    bad = [c for c in cases if not _blocked(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d bad=%d" % (len(cases), len(bad)))


# ------------------------------------------------ p5: honest text


@_t
def test_p5_honest_text():
    """Honest text stays quiet."""
    cases = [
        "(function(){var s='hello';return s+' world';})()",
        "'just a string with no code'",
        "(function(){var t=new EventTarget();return 'ok';})()",
        "(function(){var o={k:'v'};return 'k='+o.k;})()",
    ]
    bad = [c for c in cases if _blocked(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d noisy=%d" % (len(cases), len(bad)))


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites scan in under 20s; misses stay misses."""
    sites = []
    for k in range(100):
        sites.append("(function(){var o={k:'a%d'};var c=structuredClone(o);"
                     "return c.k+'b';})()" % k)
        sites.append("(function(){var t=new EventTarget();var r='';"
                     "t.addEventListener('x',function(e){r=e.detail;});"
                     "t.dispatchEvent(new CustomEvent('x',{detail:'c%d'}));"
                     "return r+'d';})()" % k)
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
    # Both lane red-firsts must be 0 BREAK (F807/F808 closed); the
    # wave-385 attack battery is expected to report exactly 1 BREAK:
    # its test_b0_footer_state asserts the merged footer, while this
    # lane's footer is lane-local (F807/F808 closed) -- tree-wide
    # repoint is merge-owned (wave-305 lesson). All functional
    # probes must HELD. (The 4 F807/F808 open pins were flipped to
    # closed in-lane, wave-305 class.)
    for batt, expect_break in (("evals/w386_f807_redfirst.py", 0),
                               ("evals/w386_f808_redfirst.py", 0),
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
def test_p7_green_check():
    """Depth-1 green check: both red-firsts 0 BREAK + wave-385 attack
    battery 1 BREAK (footer pin only, lane-local; merge-owned)."""
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
