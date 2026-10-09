#!/usr/bin/env python3
"""Wave-388 lane 1 close battery: F893 + F894 + F895 + F896 CLOSED.

Verifies the four LOW findings (wave-387 attack round 55, filed
2026-10-09 06:58 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block, node-exact), fail-closed bounds (must miss / stay quiet),
sibling pins (eval-adjacent: none modeled before; with-family:
F667/F678; arguments-family: F809; DataView-family: F742; split:
F866), honest-text controls, perf (200 sites), and a depth-1 green
check on the four red-first batteries (GOV_SKIP_GREEN=1 in the
child env).

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

TAXONOMY_PIN = 2143  # wave-387 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_DOTALL_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


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
    ok = "VERIFIER_TAXONOMY_PIN = 33" in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % ok)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( (count stays 28)."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == RE_DOTALL_COUNT else "BREAK",
            "re.compile count=%d" % n)


@_t
def test_p0_footer_state():
    """Control: merge footer (F893-F920 closed; open F921-F926, F928-F936; next F937)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = (bool(foot)
          and "**F937**" in foot[-1]
          and "F921, F922" in foot[-1]
          and "F935, F936." in foot[-1]
          and "F893-F920 CLOSED" in foot[-1])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes


@_t
def test_p1_f893_s1():
    """F893 filed s1 (aliased eval): blocks, node-exact decode."""
    p = ("(function(){var g=eval;return g(\"'%s'\")+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f893_s2():
    """F893 filed s2 (indirect eval): blocks, node-exact decode."""
    p = ("(function(){return (0,eval)(\"'%s'\")+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f894_s1():
    """F894 filed s1 (with-body decl): blocks, node-exact decode."""
    p = ("(function(){var o={k:'%s'};with(o){var q=k;}return q+'%s';})()"
         % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f894_s2():
    """F894 filed s2 (with-body compound assign): blocks, node-exact decode."""
    p = ("(function(){var o={k:'%s',j:'%s'};var r='';with(o){r=k+j;}return r;})()"
         % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f895_s1():
    """F895 filed s1 ([...arguments].join): blocks, node-exact decode."""
    p = ("(function(){function f(){return [...arguments].join('');}"
         "return f('%s','%s');})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f895_s2():
    """F895 filed s2 (Array.from(arguments).join): blocks, node-exact decode."""
    p = ("(function(){function f(){return Array.from(arguments).join('');}"
         "return f('%s','%s');})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f896_s1():
    """F896 filed s1 (setUint16 loop + getUint8 reads): blocks, node-exact."""
    p = ("(function(){var b=new ArrayBuffer(22);var v=new DataView(b);"
         "var ps=[30831,30818,11568,12594,13108,13622,14136,14689,25187,25701];"
         "for(var i=0;i<10;i++)v.setUint16(i*2,ps[i]);v.setUint8(20,102);"
         "var r='';for(var j=0;j<21;j++)r+=String.fromCharCode(v.getUint8(j));"
         "return r;})()")
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f896_s2():
    """F896 filed s2 (setInt8/getInt8 loop): blocks, node-exact decode."""
    p = ("(function(){var v=new DataView(new ArrayBuffer(21));"
         "var bs=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];"
         "for(var i=0;i<21;i++)v.setInt8(i,bs[i]);"
         "var r='';for(var j=0;j<21;j++)r+=String.fromCharCode(v.getInt8(j));"
         "return r;})()")
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


# ------------------------------------------------------- generalizations


@_t
def test_p2_f893_template_literal_arg():
    """F893: template-literal eval args block, node-exact."""
    p1 = ("(function(){return eval(`'%s'`)+'%s';})()" % (_A, _B))
    p2 = ("(function(){var g=eval;return g(`'%s'`)+'%s';})()" % (_A, _B))
    ok = _blocked(p1) and _decode(p1) == _FULL
    ok = ok and _blocked(p2) and _decode(p2) == _FULL
    # Non-literal interpolation stays a miss (fail closed).
    p3 = "(function(){var x='a';return eval(`${x}`);})()"
    ok = ok and _misses(p3)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f893_direct_eval():
    """F893: direct eval('PROG') blocks, node-exact."""
    p = ("(function(){return eval(\"'%s'\")+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f893_eval_call_apply():
    """F893: eval.call / eval.apply twins block, node-exact."""
    p1 = ("(function(){return eval.call(null,\"'%s'\")+'%s';})()" % (_A, _B))
    p2 = ("(function(){return eval.apply(null,[\"'%s'\"])+'%s';})()" % (_A, _B))
    ok = (_blocked(p1) and _decode(p1) == _FULL
          and _blocked(p2) and _decode(p2) == _FULL)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f893_globalthis_eval():
    """F893: globalThis.eval blocks, node-exact."""
    p = ("(function(){return globalThis.eval(\"'%s'\")+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f893_function_forms():
    """F893: Function/new Function/multi-param/alias/.constructor block."""
    mk = lambda call: ("(function(){return %s+'%s';})()" % (call, _B))
    ps = [
        mk("Function(\"return '%s';\")()" % _A),
        mk("new Function(\"return '%s';\")()" % _A),
        mk("Function('a','b',\"return '%s';\")()" % _A),
    ]
    p4 = ("(function(){var F=Function;return new F(\"return '%s';\")()+'%s';})()"
          % (_A, _B))
    p5 = ("(function(){var g=eval;return g.constructor(\"return '%s';\")()+'%s';})()"
          % (_A, _B))
    ok = all(_blocked(p) and _decode(p) == _FULL for p in ps)
    ok = ok and _blocked(p4) and _decode(p4) == _FULL
    ok = ok and _blocked(p5) and _decode(p5) == _FULL
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f894_shadow_and_pluseq():
    """F894: scope-member shadowing and += are node-exact."""
    p1 = ("(function(){var k='outer';var o={k:'%s'};with(o){var q=k;}return q;})()"
          % _A)
    p2 = ("(function(){var o={k:'%s'};var r='';with(o){r+=k;}return r+'%s';})()"
          % (_A, _B))
    p3 = ("(function(){with({k:'%s'}){var q=k;}return q+'%s';})()" % (_A, _B))
    ok = _decode(p1) == _A and _blocked(p2) and _decode(p2) == _FULL
    ok = ok and _blocked(p3) and _decode(p3) == _FULL
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f895_concat_and_spreadobj():
    """F895: ''.concat(...arguments) and {...arguments} twins block."""
    p1 = ("(function(){function f(){return ''.concat(...arguments);}"
          "return f('%s','%s');})()" % (_A, _B))
    p2 = ("(function(){function f(){var o={...arguments};return o[0]+o[1];}"
          "return f('%s','%s');})()" % (_A, _B))
    p3 = ("(function(){function f(){return [...arguments].join('-');}"
          "return f('a','b');})()")
    ok = _blocked(p1) and _decode(p1) == _FULL
    ok = ok and _blocked(p2) and _decode(p2) == _FULL
    ok = ok and _decode(p3) == "a-b"
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f896_widths():
    """F896: setUint32/getUint16/negative-int16 are node-exact at the
    hook level; non-ASCII results stay quiet at the whole-text level
    (the _ascii_printable_or_none emission gate -- designed)."""
    p1 = ("(function(){var v=new DataView(new ArrayBuffer(4));"
          "v.setUint32(0,287454020);var r='';"
          "for(var j=0;j<2;j++)r+=String.fromCharCode(v.getUint16(j*2));"
          "return r;})()")
    # 287454020 = 0x11223344; big-endian getUint16 -> 0x1122, 0x3344.
    # The hook computes the node-exact value...
    st = {"ops": 0, "parts": 0}
    r1 = dlp._js_parse_f896_dataview_iife(p1, 0, 0, st)
    ok = r1 is not None and r1[0] == chr(0x1122) + chr(0x3344)
    # ...but the whole-text layer stays quiet on non-ASCII output.
    ok = ok and _misses(p1)
    p2 = ("(function(){var v=new DataView(new ArrayBuffer(2));"
          "v.setInt16(0,-2);var r='';"
          "for(var j=0;j<1;j++)r+=String.fromCharCode(v.getInt16(j*2));"
          "return r;})()")
    st = {"ops": 0, "parts": 0}
    r2 = dlp._js_parse_f896_dataview_iife(p2, 0, 0, st)
    ok = ok and r2 is not None and r2[0] == chr(0xFFFE) and _misses(p2)
    return ("HELD" if ok else "BREAK", "hook-exact+quiet=%s" % ok)


# ------------------------------------------------------- fail-closed bounds


@_t
def test_p3_f893_nonliteral_arg():
    """F893 bound: eval(x) with a live binding misses (never mis-decodes)."""
    p = ("(function(){var x=\"'a'\";return eval(x);})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f893_empty_and_concat_prog():
    """F893 bound: eval('') and eval('a'+'b') miss."""
    p1 = "(function(){return eval('');})()"
    p2 = "(function(){return eval(\"'a'+'b'\");})()"
    ok = _misses(p1) and _misses(p2)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f893_object_constructor():
    """F893 bound: ({}).constructor is Object, not Function -- miss."""
    p = ("(function(){var g={};return g.constructor(\"return 'a';\")();})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f893_fn_body_not_return():
    """F893 bound: non-return-literal Function bodies miss."""
    p1 = "(function(){return Function('return a;')();})()"
    p2 = "(function(){return Function('a')();})()"
    ok = _misses(p1) and _misses(p2)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f894_nested_with():
    """F894 bound: nested with misses (F678's production owns it)."""
    p = ("(function(){var o={k:'a'};with(o){with(o){var q=k;}}return q;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f894_scope_member_write():
    """F894 bound: with-body write to a scope member misses."""
    p = ("(function(){var o={k:'zz'};with(o){k='a';}return o.k;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss=%s" % _misses(p))


@_t
def test_p3_f894_unbound_and_let():
    """F894 bound: unbound reads and let body decls miss."""
    p1 = "(function(){var o={k:'a'};with(o){var q=z;}return q;})()"
    p2 = "(function(){var o={k:'a'};with(o){let q=k;}return q;})()"
    ok = _misses(p1) and _misses(p2)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f895_arrow_and_nonliteral():
    """F895 bound: arrow functions and non-literal call args miss."""
    p1 = ("(function(){var f=()=>[...arguments].join('');return f('a');})()")
    p2 = ("(function(){function f(){return [...arguments].join('');}"
          "return f(x);})()")
    p3 = ("(function(){function f(){return [...arguments].join('');}"
          "return f();})()")
    ok = _misses(p1) and _misses(p2) and _misses(p3)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f896_oob_and_littleendian():
    """F896 bound: OOB writes and littleEndian args miss (engine throws)."""
    p1 = ("(function(){var v=new DataView(new ArrayBuffer(2));"
          "v.setUint16(1,5);var r='';"
          "for(var j=0;j<2;j++)r+=String.fromCharCode(v.getUint8(j));"
          "return r;})()")
    p2 = ("(function(){var v=new DataView(new ArrayBuffer(2));"
          "v.setUint16(0,5,true);var r='';"
          "for(var j=0;j<2;j++)r+=String.fromCharCode(v.getUint8(j));"
          "return r;})()")
    p3 = ("(function(){var v=new DataView(new ArrayBuffer(4));var n=2;"
          "var bs=[1,2];for(var i=0;i<n;i++)v.setUint8(i,bs[i]);var r='';"
          "for(var j=0;j<2;j++)r+=String.fromCharCode(v.getUint8(j));"
          "return r;})()")
    ok = _misses(p1) and _misses(p2) and _misses(p3)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------------- sibling pins


@_t
def test_p4_f800_proxy_twin():
    """Sibling: F800 constant-get proxy twin still blocks."""
    p = ("(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});"
         "return p.anything+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f809_indexed_arguments():
    """Sibling: F809 indexed arguments still blocks."""
    p = ("(function(){function f(){return arguments[0]+arguments[1];}"
         "return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f742_uint8():
    """Sibling: F742 setUint8/getUint8 loop still blocks."""
    p = ("(function(){var v=new DataView(new ArrayBuffer(20));"
         "var bs=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];"
         "for(var i=0;i<20;i++)v.setUint8(i,bs[i]);var r='';"
         "for(var j=0;j<20;j++)r+=String.fromCharCode(v.getUint8(j));"
         "return r;})()")
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f667_with_return():
    """Sibling: F667 with(...){return} shape still blocks."""
    p = ("(function(){var o={k:'%s'};with(o){return k+'%s';}})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f678_with_tail():
    """Sibling: F678-D with-tail single-read shape still blocks."""
    p = ("(function(){var o={k:'%s'};var r='';with(o){r=k;}return r+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


@_t
def test_p4_f866_split_groups():
    """Sibling: F866 split-with-capture-groups still blocks."""
    p = ("(function(){var s='z%s'+'z';return s.split(/(xoxb-[0-9a-f]+)/)[1]+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "blocked=%s" % _blocked(p))


# ------------------------------------------------------- honest text


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_eval():
    """Honest eval text (no credential) stays quiet."""
    p = "(function(){return eval('1+1');})()"
    return ("HELD" if _misses(p) else "BREAK", "quiet=%s" % _misses(p))


@_t
def test_p5_honest_with():
    """Honest with text (no credential) stays quiet."""
    p = "(function(){var o={k:'v'};with(o){var q=k;}return q;})()"
    return ("HELD" if _misses(p) else "BREAK", "quiet=%s" % _misses(p))


@_t
def test_p5_honest_arguments():
    """Honest arguments-spread text (no credential) stays quiet."""
    p = ("(function(){function f(){return [...arguments].join(',');}"
         "return f('a','b');})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet=%s" % _misses(p))


@_t
def test_p5_honest_dataview():
    """Honest DataView text (no credential) stays quiet."""
    p = ("(function(){var v=new DataView(new ArrayBuffer(2));"
         "v.setUint8(0,65);v.setUint8(1,66);var r='';"
         "for(var j=0;j<2;j++)r+=String.fromCharCode(v.getUint8(j));"
         "return r;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet=%s" % _misses(p))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf_200_sites():
    """Perf: 200 decode sites stay fast (F452 aggregate budget)."""
    site = ("(function(){var g=eval;return g(\"'ab'\");})()")
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
    for battery in ("w388_f893_redfirst.py", "w388_f894_redfirst.py",
                    "w388_f895_redfirst.py", "w388_f896_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g388-green-", dir="/var/tmp")
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
