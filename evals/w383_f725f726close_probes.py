#!/usr/bin/env python3
"""Wave-383 lane 7: close F725 (__lookupGetter__) + F726 (template-literal
toPrimitive coercion).

F725 (LOW, attack round 50): the decoder had no __lookupGetter__
production -- retrieving the getter function and invoking it recovered
the fragment while the decoder produced zero variants. Closed by
_js_parse_f725_lookup_getter_iife (gov/dlp.py, hooked after F702/F703):
var-bound objects with literal getters plus __defineGetter__ installs
are tracked; `var g=o.__lookupGetter__('K')` binds the getter's
evaluated value; `g()` / `g.call()` / `g.call(RECV)` / inline
`o.__lookupGetter__('K').call(...)` resolve it node-exactly
(v24.20.0). Missing keys, data props, __proto__, re-installs, extra
.call args, unbound receivers fail closed (the engine throws there).

F726 (LOW, attack round 50): F697 models implicit ToPrimitive
coercion in valueOf/toString positions but not the template-literal
interpolation position. Closed by
_js_parse_f726_template_coerce_iife (hooked after F725):
`(function(){var o={...};return ADD;})()` where the return carries a
template literal whose ${IDENT} interpolations bind the coercion
object; each coerces via ToPrimitive with the STRING hint
([Symbol.toPrimitive] > toString > valueOf; no own toString ->
inherited Object.prototype.toString -> "[object Object]",
node-exact). Non-ident interpolations, non-string bodies, and
throwing shapes fail closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g383-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

_TESTS = []


def _t(fn):
    _TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s len=%d" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F725/F726 closed, F738 filed, next F739)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f725_s1():
    """F725 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f725-s1=%s" % ok)


@_t
def test_p1_f725_s2():
    """F725 filed shape 2 (defineGetter + inline lookup) blocks."""
    ok = _blocked(
        "(function(){var o={};o.__defineGetter__('y',"
        "function(){return '%s';});"
        "return o.__lookupGetter__('y').call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f725-s2=%s" % ok)


@_t
def test_p1_f726_s1():
    """F726 filed shape 1 (toString in template) blocks."""
    ok = _blocked(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f726-s1=%s" % ok)


@_t
def test_p1_f726_s2():
    """F726 filed shape 2 ([Symbol.toPrimitive] in template) blocks."""
    ok = _blocked(
        "(function(){var o={[Symbol.toPrimitive]:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f726-s2=%s" % ok)


# ------------------------------------------------- F725 generalizations (p2)

@_t
def test_p2_f725_call_norecv():
    """g.call() with no receiver blocks (getter is receiver-independent)."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var g=o.__lookupGetter__('x');return g.call()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "call-norecv=%s" % ok)


@_t
def test_p2_f725_bare_call():
    """Bare g() blocks (the getter ignores `this`)."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var g=o.__lookupGetter__('x');return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bare-g=%s" % ok)


@_t
def test_p2_f725_let_const():
    """let/const bindings work."""
    ok = _blocked(
        "(function(){const o={get x(){return '%s';}};"
        "let g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


# ------------------------------------------------------ F725 bounds (p3)

@_t
def test_p3_f725_missing_key():
    """Missing key misses (engine: undefined.call throws)."""
    miss = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "var g=o.__lookupGetter__('z');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "missing=%s" % miss)


@_t
def test_p3_f725_data_prop():
    """Data prop misses (engine: lookupGetter returns undefined)."""
    miss = _misses(
        "(function(){var o={x:'%s'};"
        "var g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "dataprop=%s" % miss)


@_t
def test_p3_f725_proto():
    """__proto__ key misses (would walk the prototype chain)."""
    miss = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "var g=o.__lookupGetter__('__proto__');return 'q'+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "proto=%s" % miss)


@_t
def test_p3_f725_extra_call_arg():
    """Extra .call args miss (conservative; engine ignores them)."""
    miss = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "var g=o.__lookupGetter__('x');return g.call(o,1)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "extra-arg=%s" % miss)


@_t
def test_p3_f725_reinstall():
    """Re-install misses (F703 parity: redefinition is a residual)."""
    miss = _misses(
        "(function(){var o={};o.__defineGetter__('y',function(){return 'q';});"
        "o.__defineGetter__('y',function(){return '%s';});"
        "var g=o.__lookupGetter__('y');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "reinstall=%s" % miss)


@_t
def test_p3_f725_unbound_recv():
    """Unbound .call receiver misses (engine: ReferenceError)."""
    miss = _misses(
        "(function(){var o={get x(){return '%s';}};"
        "var g=o.__lookupGetter__('x');return g.call(zz)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "unbound-recv=%s" % miss)


@_t
def test_p3_f725_this_getter():
    """this-using getter misses (F535 grammar has no `this`)."""
    miss = _misses(
        "(function(){var o={get x(){return this.y;},y:'%s'};"
        "var g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "this-getter=%s" % miss)


# ------------------------------------------------- F726 generalizations (p4)

@_t
def test_p4_f726_valueof_only():
    """valueOf-only object: inherited toString wins -> '[object Object]' (node-exact)."""
    ok = _blocked(
        "(function(){var o={valueOf:function(){return 'q';}};"
        "return 'pre'+`${o}`;})()") is False  # no credential: must MISS
    # node-exactness of the [object Object] decode is pinned by the
    # decoder differential (see REPORT.md); find_credential stays quiet.
    return ("HELD" if ok else "BREAK", "valueof-only-quiet=%s" % ok)


@_t
def test_p4_f726_both_methods():
    """toString beats valueOf under the string hint."""
    ok = _blocked(
        "(function(){var o={valueOf:function(){return 'V';},"
        "toString:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "both=%s" % ok)


@_t
def test_p4_f726_tp_wins():
    """[Symbol.toPrimitive] beats toString."""
    ok = _blocked(
        "(function(){var o={toString:function(){return 'T';},"
        "[Symbol.toPrimitive]:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "tp-wins=%s" % ok)


@_t
def test_p4_f726_chunks():
    """Literal chunks around the interpolation decode."""
    ok = _blocked(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `x${o}y`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "chunks=%s" % ok)


@_t
def test_p4_f726_escaped():
    """Escaped \\${ stays literal (no coercion)."""
    ok = _misses(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `\\${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "escaped=%s" % ok)


# ------------------------------------------------------ F726 bounds (p5)

@_t
def test_p5_f726_nonident_interp():
    """Non-ident interpolation misses."""
    miss = _misses(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `${'q'}`+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "nonident=%s" % miss)


@_t
def test_p5_f726_unbound_interp():
    """Unbound ident interpolation misses."""
    miss = _misses(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `${zz}`+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "unbound=%s" % miss)


@_t
def test_p5_f726_throwing_shape():
    """Own non-callable toString with no valueOf misses (engine throws)."""
    miss = _misses(
        "(function(){var o={toString:'X'};"
        "return `${o}`+'%s';})()" % _B)
    return ("HELD" if miss else "BREAK", "throwing=%s" % miss)


@_t
def test_p5_f726_noncallable_toprimitive():
    """Own non-callable @@toPrimitive misses (engine: GetMethod throws)."""
    miss = _misses(
        "(function(){var o={[Symbol.toPrimitive]:'x',"
        "toString:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "noncallable-tp=%s" % miss)


@_t
def test_p5_f726_nonstring_body():
    """Non-string coercion body misses (engine: ToString(42))."""
    miss = _misses(
        "(function(){var o={toString:function(){return 42;}};"
        "return `${o}`+'%s';})()" % _B)
    return ("HELD" if miss else "BREAK", "nonstring=%s" % miss)


@_t
def test_p5_f726_member_term():
    """Member/call terms on the bound object miss (F674's shapes)."""
    miss = _misses(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `${o.x}`+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "member-term=%s" % miss)


# --------------------------------------- siblings / neighbors / honesty (p6)

@_t
def test_p6_sibling_f703():
    """F703 (__defineGetter__ member reads) still blocks."""
    ok = _blocked(
        "(function(){var o={};o.__defineGetter__('x',"
        "function(){return '%s';});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f703=%s" % ok)


@_t
def test_p6_sibling_f697():
    """F697 (valueOf/toString additive coercion) still blocks."""
    ok = _blocked(
        "(function(){var o={v:'%s',valueOf:function(){return this.v;}};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697=%s" % ok)


@_t
def test_p6_neighbor_f724_open():
    """F724 now BLOCKS (closed wave-383 merge)."""
    blocked = not _misses(
        "(function(){var c={};var p={get y(){return '%s';}};"
        "Object.setPrototypeOf(c,p);return c.y+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "f724-closed=%s" % blocked)


@_t
def test_p6_neighbor_f727_open():
    """F727 now BLOCKS (closed wave-383 merge)."""
    blocked = not _misses(
        "(function(){var r='';var i=0;do{r+=['%s','%s'][i];i++;}while(i<2);"
        "return r;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "f727-closed=%s" % blocked)


@_t
def test_p6_honest_template():
    """Honest literal-only templates still decode (F457 intact)."""
    ok = _blocked("`%s${'x'}%s`" % (_A, _B))
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p6_junk_quiet():
    """Junk stays quiet."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------------------------ perf

@_t
def test_p7_perf():
    """200 mixed sites stay fast."""
    t0 = time.time()
    for k in range(100):
        _misses("(function(){var o={get x(){return 'q';}};"
                "var g=o.__lookupGetter__('x');return g.call(o)+'%d';})()" % k)
        _misses("(function(){var o={toString:function(){return 'q';}};"
                "return `${o}`+'%d';})()" % k)
    dt = time.time() - t0
    ok = dt < 20
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w382_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # This lane repoints the footer lane-locally (F725/F726 closed);
    # the w382 battery's footer pin is stale by design until the
    # wave-383 merge repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w382_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p8_green_check():
    """Green check: wave-382 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    breaks, held = 0, 0
    for fn in _TESTS:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "BREAK", "EXC %s: %s" % (type(e).__name__, str(e)[:80])
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
        print("%s: %s (%s)" % (fn.__name__, verdict, detail))
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
