#!/usr/bin/env python3
"""Wave-385 lane 7: close F774 + F775.

F774 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round
52): property descriptor value reads on var-bound objects --
F549 (CLOSED) covers inline-literal targets and F491 (CLOSED) the
Array/String-prototype targets, but a var-bound target had no
production:
  (function(){var o={x:'f1'};return Object.getOwnPropertyDescriptor(o,'x').value+'f2';})()
  (function(){var o={x:'f1'};return Object.getOwnPropertyDescriptors(o).x.value+'f2';})()

F775 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round
52): F723 residual -- explicit Object.getPrototypeOf(o).x member
reads; F723 (CLOSED) models the proto chain but not the explicit
production:
  (function(){var p={x:'f1'};var o=Object.create(p);return Object.getPrototypeOf(o).x+'f2';})()
  (function(){var p={x:'f1'};var o={};Object.setPrototypeOf(o,p);return Object.getPrototypeOf(o).x+'f2';})()

Fix (gov/dlp.py, zero new re.compile):
- F774: _js_parse_f774_gopd_term + _js_parse_f774_gopd_read_iife,
  hooked after F724 (hook + trailing return intact, wave-379;
  F452 parts/ops snapshot/restore on miss, wave-383 lesson).
  Own-property only, data properties only (.value is undefined
  for accessors in the engine -- fail closed); dot and
  bracket-string `.value`; string values only.
- F775: _js_parse_f775_getproto_term +
  _js_parse_f775_getproto_member_iife, hooked after F774;
  decls via _js_f723f724_parse_decl_init (literal or one-arg
  create), optional setPrototypeOf statements via
  _js_f723f724_parse_setproto_stmt; member reads resolved
  through the proto chain via _jsobj_lookup (getters unwrap
  with the proto as receiver, F738 parity).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Wave-385: pin 2143 -> 2144
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

TAXONOMY_PIN = 2144  # no new decision codes this lane  # Wave-385: pin 2143 -> 2144

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
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_footer_state():
    """Control: lane-local footer (F774/F775 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, "
              "F769, F770, F771, F772, F773, F776, F777, F778, F779, "
              "F780, F781, F782, F783, F784, F785, F786, F787, F788, "
              "F789, F790, F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f774_s1():
    """F774 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptor(o,'x').value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f774_s2():
    """F774 filed shape 2 (plural) blocks + decodes node-exact."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptors(o).x.value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f775_s1():
    """F775 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var p={x:'" + _A + "'};var o=Object.create(p);"
         "return Object.getPrototypeOf(o).x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f775_s2():
    """F775 filed shape 2 (setPrototypeOf) blocks + decodes node-exact."""
    s = ("(function(){var p={x:'" + _A + "'};var o={};"
         "Object.setPrototypeOf(o,p);return Object.getPrototypeOf(o).x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f774_bracket_value():
    """F774 bracket ['value'] read blocks + exact."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptor(o,'x')['value']+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f774_bracket_key():
    """F774 plural bracket ['x']['value'] blocks + exact."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptors(o)['x']['value']+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f774_dquote():
    """F774 double-quoted key/value blocks + exact."""
    s = ('(function(){var o={x:"' + _A + '"};return '
         'Object.getOwnPropertyDescriptor(o,"x").value+"' + _B + '";})()')
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f774_multi_term():
    """F774 two descriptor terms in one additive: exact."""
    s = ("(function(){var o={x:'" + _A + "',y:'" + _B + "'};return "
         "Object.getOwnPropertyDescriptor(o,'x').value+"
         "Object.getOwnPropertyDescriptors(o).y.value;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f774_let():
    """F774 let-bound object blocks + exact."""
    s = ("(function(){let o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptor(o,'x').value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f775_bracket():
    """F775 bracket member read blocks + exact."""
    s = ("(function(){var p={x:'" + _A + "'};var o=Object.create(p);"
         "return Object.getPrototypeOf(o)['x']+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f775_getter():
    """F775 proto getter unwraps (receiver = proto): exact."""
    s = ("(function(){var p={get x(){return '" + _A + "'}};"
         "var o=Object.create(p);return Object.getPrototypeOf(o).x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f775_chain():
    """F775 two-level proto chain: exact."""
    s = ("(function(){var a={x:'" + _A + "'};var p=Object.create(a);"
         "var o=Object.create(p);return Object.getPrototypeOf(o).x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f774_smallint_value():
    """F774 small-int descriptor value decodes node-exact (F549 parity:
    the engine stringifies 5 to '5' in the additive)."""
    s = ("(function(){var o={x:5};return "
         "Object.getOwnPropertyDescriptor(o,'x').value+'" + _B + "';})()")
    ok = _decodes_exact(s, "5" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f774_accessor_value():
    """F774 .value on an accessor is undefined in the engine: closed."""
    s = ("(function(){var o={get x(){return '" + _A + "'}};"
         "return typeof Object.getOwnPropertyDescriptor(o,'x').value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f774_missing_key():
    """F774 missing key throws in the engine: closed."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptor(o,'y').value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f774_plural_missing():
    """F774 plural missing key throws: closed."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptors(o).y.value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f774_unsafe_int():
    """F774 unsafe-int descriptor value: F711 fail-closed."""
    s = ("(function(){var o={x:99999999999999999999};return "
         "Object.getOwnPropertyDescriptor(o,'x').value+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f774_extra_arg():
    """F774 extra call arg: narrow grammar refuses, closed."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "Object.getOwnPropertyDescriptor(o,'x','z').value+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f774_other_field():
    """F774 non-value descriptor field: closed."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         "typeof Object.getOwnPropertyDescriptor(o,'x').writable;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f774_unbound():
    """F774 unbound target: closed."""
    s = ("(function(){return Object.getOwnPropertyDescriptor(q,'x').value+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f775_no_arg():
    """F775 getPrototypeOf() with no args throws: closed."""
    s = "(function(){return typeof Object.getPrototypeOf();})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f775_missing_key():
    """F775 missing key yields undefined: closed."""
    s = ("(function(){var p={};var o=Object.create(p);"
         "return typeof Object.getPrototypeOf(o).x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f775_null_proto():
    """F775 null-prototype member read throws: closed."""
    s = ("(function(){var o=Object.create(null);"
         "return typeof Object.getPrototypeOf(o);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f775_unbound():
    """F775 unbound target: closed."""
    s = "(function(){return Object.getPrototypeOf(q).x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f775_no_member():
    """F775 bare getPrototypeOf with no member step: closed."""
    s = ("(function(){var p={x:'" + _A + "'};var o=Object.create(p);"
         "return typeof Object.getPrototypeOf(o);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f549_inline():
    """F549 inline-literal descriptor read pin still blocks."""
    s = ("(function(){return Object.getOwnPropertyDescriptor({x:'" + _A
         + "'},'x').value+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f549=%s" % ok)


@_t
def test_p4_sibling_f723():
    """F723 proto-chain getter pin still blocks."""
    s = ("(function(){var o={get x(){return '" + _A + "'}};"
         "var c=Object.create(o);return c.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f723=%s" % ok)


@_t
def test_p4_sibling_f724():
    """F724 setPrototypeOf pin still blocks."""
    s = ("(function(){var c={};Object.setPrototypeOf(c,{get x(){return '"
         + _A + "'}});return c.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f724=%s" % ok)


@_t
def test_p4_sibling_f671():
    """F671 member-read pin still blocks."""
    s = ("(function(){var o={x:'" + _A + "'};return o.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f671=%s" % ok)


@_t
def test_p4_neighbor_f776_open():
    """Neighbor F776 still misses -- out of scope; honest open shape."""
    s = ("(function(){var o={__proto__:{x:'" + _A + "'}};"
         "return o.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f776-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_gopd_unaffected():
    """Honest getOwnPropertyDescriptor on an array still misses."""
    s = "Object.getOwnPropertyDescriptor([], 'length').value"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_getproto_unaffected():
    """Honest Object.getPrototypeOf without a member read still misses."""
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
            "(function(){var o={x:'a%d'};return "
            "Object.getOwnPropertyDescriptor(o,'x').value;})()" % k)
        sites.append(
            "(function(){var p={x:'v'};var o=Object.create(p);"
            "return Object.getPrototypeOf(o).x;})()")
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
    # The w384 attack battery's footer pin is stale by design: this
    # lane repointed the footer lane-locally (wave-305/306 class,
    # merge-owned). Its 4 F774/F775 pins were flipped to closed by
    # this lane. All other probes must HELD.
    for batt, expect_break in (("evals/w384_f774_redfirst.py", 0),
                               ("evals/w384_f775_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
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
    """Depth-1 green check: F774/F775 red-firsts (0 BREAK) + wave-384
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
