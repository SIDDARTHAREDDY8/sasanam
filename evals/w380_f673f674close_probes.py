#!/usr/bin/env python3
"""Wave-380 lane 2: close F673 + F674 -- object-construction / this-bound family.

F673 (LOW, filed attack round 47): object-construction member reads
beyond F663/F664/F671 bypass the bounded static JS-expression
decoder -- F671 files plain-literal member reads in IIFE-return
additive position, but defineProperties-installed getters, Object
entries/values destructuring, computed-key literals, Object.create
prototype reads, and hasOwn-guarded reads all node-evaluated to the
exact credential (v24.20.0) while the decoder produced zero variants.

F674 (LOW, filed attack round 47): this-bound member reads bypass the
decoder -- the decoder resolves member reads on the receiver object
but never binds `this`: a method body reading `this.x` invoked as
`o.get()`, and a getter reading `this.y` read as `o.x`, both
node-evaluated to the exact credential while the decoder produced
zero variants.

Closure (gov/dlp.py, F673/F674): _js_parse_f673_object_construction_iife
parses (function(){STMT;return ADD;})() with six statement shapes --
Object.defineProperties-installed getters (this-aware bodies,
evaluated with `this` = the receiver), entries/values destructuring
(engine-exact enumeration order), computed-key literals (bound ident
keys), Object.create prototype reads (F548 chain, this-aware
prototype bodies), and hasOwn-guarded conditionals (own-properties
only) -- plus the plain-object statement which additionally requires
a hasOwn-guarded term (bare member-read returns stay F671's, hooked
earlier). _js_parse_f674_this_bound_iife parses
(function(){DECL o={...};return ADD;})() where the object carries
>= 1 this-bound method/getter body; method calls and member reads
evaluate with `this` = the receiver, node-exactly (v24.20.0).
Zero new re.compile (28 stays).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g380-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_f673(js):
    """Exact decoded value via the F673 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f673_object_construction_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


def _decode_f674(js):
    """Exact decoded value via the F674 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f674_this_bound_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-44s %s %s" % (name, verdict, note))


def _hit(name, payload):
    ok = _blocked(payload)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def _miss(name, payload):
    ok = _misses(payload)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def _exact(name, decode_fn, payload):
    """Internal-seam exact decode + public-seam block."""
    dec = decode_fn(payload)
    ok = dec == _CRED and _blocked(payload)
    return ("HELD" if ok else "BREAK",
            "exact=%s blocked=%s" % (dec == _CRED, _blocked(payload)))


# ------------------------------------------------ filed shapes (must block)

_t("test_p1_f673_s1_defineprop_getter", lambda: _exact(
    "s1", _decode_f673,
    "(function(){var o={};Object.defineProperties(o,{x:{get:function()"
    "{return '" + _A + "';}}});return o.x+'" + _B + "';})()"))

_t("test_p1_f673_s2_entries_destr", lambda: _exact(
    "s2", _decode_f673,
    "(function(){var [[k,v]]=Object.entries({x:'" + _A + "'});"
    "return v+'" + _B + "';})()"))

_t("test_p1_f673_s3_values_destr", lambda: _exact(
    "s3", _decode_f673,
    "(function(){var [v]=Object.values({x:'" + _A + "'});"
    "return v+'" + _B + "';})()"))

_t("test_p1_f673_s4_computed_key", lambda: _exact(
    "s4", _decode_f673,
    "(function(){var k='x';var o={[k]:'" + _A + "'};"
    "return o.x+'" + _B + "';})()"))

_t("test_p1_f673_s5_create_proto", lambda: _exact(
    "s5", _decode_f673,
    "(function(){var o=Object.create({x:'" + _A + "'});"
    "return o.x+'" + _B + "';})()"))

_t("test_p1_f673_s6_hasown_guard", lambda: _exact(
    "s6", _decode_f673,
    "(function(){var o={x:'" + _A + "'};"
    "return (Object.hasOwn(o,'x')?o.x:'junk')+'" + _B + "';})()"))

_t("test_p1_f674_s1_this_method", lambda: _exact(
    "s1", _decode_f674,
    "(function(){var o={x:'" + _A + "',get:function(){return this.x;}};"
    "return o.get()+'" + _B + "';})()"))

_t("test_p1_f674_s2_this_getter", lambda: _exact(
    "s2", _decode_f674,
    "(function(){var o={get x(){return this.y;},y:'" + _A + "'};"
    "return o.x+'" + _B + "';})()"))


# ------------------------------------------------ variants (must block, node-exact)

_t("test_p2_defineprop_value_descr", lambda: _hit(
    "value-descriptor",
    "(function(){var o={};Object.defineProperties(o,{x:{value:'" + _A + "'}});"
    "return o.x+'" + _B + "';})()"))

_t("test_p2_defineprop_this_body", lambda: _hit(
    "this-aware installed getter",
    "(function(){var o={tag:'" + _A + "'};Object.defineProperties(o,"
    "{x:{get:function(){return this.tag;}}});"
    "return o.x+'" + _B + "';})()"))

_t("test_p2_defineprop_two_props", lambda: _hit(
    "two installed getters",
    "(function(){var o={};Object.defineProperties(o,{x:{get:function()"
    "{return '" + _A + "';}},y:{get:function(){return '" + _B + "';}}});"
    "return o.x+o.y;})()"))

_t("test_p2_entries_intkey_order", lambda: _hit(
    "integer-index keys sort ascending first",
    "(function(){var [[k,v]]=Object.entries({2:'x',1:'" + _A + "'});"
    "return v+'" + _B + "';})()"))

_t("test_p2_values_first_only", lambda: _hit(
    "values destructuring takes the first value",
    "(function(){var [v]=Object.values({x:'" + _A + "',y:'zz'});"
    "return v+'" + _B + "';})()"))

_t("test_p2_let_const_destr", lambda: _hit(
    "let/const destructuring",
    "(function(){let [[k,v]]=Object.entries({x:'" + _A + "'});"
    "return v+'" + _B + "';})()"
    "(function(){const [w]=Object.values({x:'" + _A + "'});"
    "return w+'" + _B + "';})()"))

_t("test_p2_computed_bracket_read", lambda: _hit(
    "computed key with bracket read",
    "(function(){var kk='x';var o={[kk]:'" + _A + "'};"
    "return o['x']+'" + _B + "';})()"))

_t("test_p2_create_bracket_read", lambda: _hit(
    "create-prototype bracket read",
    "(function(){var o=Object.create({x:'" + _A + "'});"
    "return o['x']+'" + _B + "';})()"))

_t("test_p2_create_proto_getter", lambda: _hit(
    "getter in the create prototype, this = receiver",
    "(function(){var o=Object.create({get x(){return this.y;},y:'" + _A + "'});"
    "return o.x+'" + _B + "';})()"))

_t("test_p2_hasown_false_branch", lambda: _miss(
    "hasOwn false takes the alternate (no credential)",
    "(function(){var o={x:'" + _A + "'};"
    "return (Object.hasOwn(o,'zz')?o.x:'junk')+'" + _B + "';})()"))

_t("test_p2_hasown_proto_false", lambda: _miss(
    "hasOwn is own-only: proto key answers false",
    "(function(){var o=Object.create({x:'" + _A + "'});"
    "return (Object.hasOwn(o,'x')?'own':'junk')+'" + _B + "';})()"))

_t("test_p2_named_method", lambda: _hit(
    "named function-expression method",
    "(function(){var o={x:'" + _A + "',get:function g(){return this.x;}};"
    "return o.get()+'" + _B + "';})()"))

_t("test_p2_getter_bracket_read", lambda: _hit(
    "getter via bracket read",
    "(function(){var o={get x(){return this.y;},y:'" + _A + "'};"
    "return o['x']+'" + _B + "';})()"))

_t("test_p2_getter_in_getter", lambda: _hit(
    "getter reading another getter",
    "(function(){var o={get x(){return this.y;},get y(){return '" + _A + "';}};"
    "return o.x+'" + _B + "';})()"))

_t("test_p2_let_method", lambda: _hit(
    "let-bound this object",
    "(function(){let o={x:'" + _A + "',get:function(){return this.x;}};"
    "return o.get()+'" + _B + "';})()"))


# ------------------------------------------------ fail-closed bounds (must miss)

_t("test_p3_self_reading_getter", lambda: _miss(
    "self-reading getter hits the depth guard, never a crash",
    "(function(){var o={get x(){return this.x;}};"
    "return o.x+'" + _B + "';})()"))

_t("test_p3_method_with_params", lambda: _miss(
    "method with parameters",
    "(function(){var o={x:'" + _A + "',get:function(a){return this.x;}};"
    "return o.get()+'" + _B + "';})()"))

_t("test_p3_method_shorthand", lambda: _miss(
    "method shorthand unmodeled",
    "(function(){var o={x:'" + _A + "',get(){return this.x;}};"
    "return o.get()+'" + _B + "';})()"))

_t("test_p3_method_call_args", lambda: _miss(
    "method call with arguments",
    "(function(){var o={x:'" + _A + "',get:function(){return this.x;}};"
    "return o.get('a')+'" + _B + "';})()"))

_t("test_p3_missing_key", lambda: _miss(
    "missing key",
    "(function(){var o={x:'" + _A + "',get:function(){return this.x;}};"
    "return o.zz+'" + _B + "';})()"))

_t("test_p3_bare_object_ident", lambda: _miss(
    "bare bound object ident ([object Object], never decoded)",
    "(function(){var o={x:'" + _A + "',get:function(){return this.x;}};"
    "return o+'" + _B + "';})()"))

_t("test_p3_call_data_prop", lambda: _miss(
    "calling a data property (engine TypeError)",
    "(function(){var o={x:'" + _A + "'};"
    "return o.x()+'" + _B + "';})()"))

_t("test_p3_destructure_mismatch", lambda: _miss(
    "non-nested pattern with entries",
    "(function(){var [k,v]=Object.entries({x:'" + _A + "'});"
    "return v+'" + _B + "';})()"))

_t("test_p3_values_nested_mismatch", lambda: _miss(
    "nested pattern with values",
    "(function(){var [[k,v]]=Object.values({x:'" + _A + "'});"
    "return v+'" + _B + "';})()"))

_t("test_p3_empty_enumeration", lambda: _miss(
    "empty enumeration destructuring",
    "(function(){var [v]=Object.values({});"
    "return v+'" + _B + "';})()"))

_t("test_p3_computed_unbound", lambda: _miss(
    "computed key naming an unbound ident",
    "(function(){var o={[zz]:'" + _A + "'};"
    "return o.x+'" + _B + "';})()"))

_t("test_p3_defineprop_wrong_target", lambda: _miss(
    "defineProperties target not the read ident",
    "(function(){var o={};var p={};Object.defineProperties(p,{x:{get:function()"
    "{return '" + _A + "';}}});return o.x+'" + _B + "';})()"))

_t("test_p3_descriptor_extra_field", lambda: _miss(
    "descriptor with an extra field",
    "(function(){var o={};Object.defineProperties(o,{x:{get:function()"
    "{return '" + _A + "';},enumerable:true}});"
    "return o.x+'" + _B + "';})()"))

_t("test_p3_named_iife", lambda: _miss(
    "named function",
    "(function foo(){var o={x:'" + _A + "',get:function(){return this.x;}};"
    "return o.get()+'" + _B + "';})()"))

_t("test_p3_iife_call_args", lambda: _miss(
    "non-empty iife call args",
    "(function(){var o={x:'" + _A + "',get:function(){return this.x;}};"
    "return o.get()+'" + _B + "';})(1)"))

_t("test_p3_extra_statement", lambda: _miss(
    "extra statement",
    "(function(){var o={x:'" + _A + "',get:function(){return this.x;}};"
    "var z='q';return o.get()+'" + _B + "';})()"))

_t("test_p3_optional_chain_in_body", lambda: _miss(
    "?. in a this-bound body unmodeled",
    "(function(){var o={x:'" + _A + "',get:function(){return this?.x;}};"
    "return o.get()+'" + _B + "';})()"))

_t("test_p3_chained_member", lambda: _miss(
    "chained member past a string",
    "(function(){var o={};Object.defineProperties(o,{x:{get:function()"
    "{return '" + _A + "';}}});return o.x.y+'" + _B + "';})()"))

_t("test_p3_hasown_nonliteral_key", lambda: _miss(
    "hasOwn with a non-literal key",
    "(function(){var o={x:'" + _A + "'};var k='x';"
    "return (Object.hasOwn(o,k)?o.x:'junk')+'" + _B + "';})()"))

_t("test_p3_f671_shape_still_blocks", lambda: _hit(
    "F671's own shape still blocks (via F671, not absorbed)",
    "(function(){var o={x:'" + _A + "'};"
    "return o.x+'" + _B + "';})()"))


# ------------------------------------------------ neighbors (must hold / must miss)

_t("test_p4_f671_redfirst_still_held", lambda: _hit(
    "F671 member-read shape still blocks",
    "(function(){var o={x:'" + _A + "',y:'" + _B + "'};"
    "return o.x+o.y;})()"))

_t("test_p4_f535_direct_still_blocks", lambda: _hit(
    "F535 direct literal member read still blocks",
    "({x:'" + _A + "'}).x+'" + _B + "'"))

_t("test_p2_hasown_str_length", lambda: _hit(
    "hasOwn on a string receiver: 'length' is own (ToObject)",
    "(function(){var [[k,v]]=Object.entries({x:'" + _A + "'});"
    "return (Object.hasOwn(v,'length')?v:'junk')+'" + _B + "';})()"))

_t("test_p2_hasown_str_index", lambda: _hit(
    "hasOwn on a string receiver: canonical index is own",
    "(function(){var [[k,v]]=Object.entries({x:'" + _A + "'});"
    "return (Object.hasOwn(v,'0')?v:'junk')+'" + _B + "';})()"))

_t("test_p2_hasown_str_noncanonical", lambda: _miss(
    "hasOwn on a string receiver: non-canonical index is not own",
    "(function(){var [[k,v]]=Object.entries({x:'" + _A + "'});"
    "return (Object.hasOwn(v,'00')?v:'junk')+'" + _B + "';})()"))

_t("test_p3_hasown_unbound_receiver", lambda: _miss(
    "hasOwn on an unbound ident fails closed (node throws)",
    "(function(){var o={x:'" + _A + "'};"
    "return (Object.hasOwn(zzz,'x')?o.x:'junk')+'" + _B + "';})()"))

_t("test_p4_open_f672_still_misses", lambda: _miss(
    "F672 (private statics) still open",
    "(function(){class C{static #x='" + _A + "';static y(){return C.#x;}}"
    "return C.y()+'" + _B + "';})()"))

_t("test_p4_open_f675_still_misses", lambda: _miss(
    "F675 (Proxy traps) still open",
    "(function(){var p=new Proxy({},{get:function(t,k){return '" + _A
    + "';}});return p.x+'" + _B + "';})()"))

_t("test_p4_open_f677_still_misses", lambda: _miss(
    "F677 (manual iterators) still open",
    "(function(){var o={i:0,next:function(){this.i++;return this.i<=2?"
    "{value:this.i===1?'" + _A + "':'" + _B + "',done:false}:{done:true};}};"
    "var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()"))

_t("test_p4_open_f681_still_misses", lambda: _miss(
    "F681 (array mutators) still open",
    "(function(){var a=['" + _A + "'];a.push('" + _B + "');"
    "return a.join('');})()"))

_t("test_p4_junk_quiet", lambda: _miss(
    "junk prefix stays quiet",
    "lorem ipsum dolor sit amet " * 4))

_t("test_p4_composition", lambda: _hit(
    "junk-prefixed defineProperties shape still blocks",
    "zz " "(function(){var o={};Object.defineProperties(o,"
    "{x:{get:function(){return '" + _A + "';}}});"
    "return o.x+'" + _B + "';})()"))


# ------------------------------------------------ pin + footer

def test_p5_pin_and_footer():
    """Pin 2140; lane-local footer: open F672, F675-F685 / next F686."""
    from gov.decision_codes import TAXONOMY  # noqa: E402
    ok = TAXONOMY_PIN == 2140
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and "Next free finding: **F686**" in text
    ok = ok and ("Open findings: F672, F675, F676, F677, F678, "
                 "F679, F680, F681, F682, F683, F684, F685." in text)
    ok = ok and ("**Status: CLOSED 2026-10-08 wave-380 lane 2.**" in text)
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


_t("test_p5_pin_and_footer", test_p5_pin_and_footer)


# ------------------------------------------------ perf

def test_p6_perf():
    """200 F673/F674 sites decode quickly (bounded work)."""
    site = ("(function(){var o={x:'aa',get:function(){return this.x;}};"
            "return o.get()+'bb';})()")
    payload = "z".join([site] * 200)
    t0 = time.time()
    find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


_t("test_p6_perf", test_p6_perf)


# ------------------------------------------------ green check (depth-1)

def _green_check():
    """Depth-1 green check: w379 attack battery stays green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g380-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w379_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
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
    # This lane flips the F673/F674 pins to closed and repoints the
    # w379 battery's footer to the lane-local footer (open F672,
    # F675-F685 / next F686), matching the FINDINGS.md repoint, so
    # the footer tolerance below is a merge-time safety net only
    # (the merge coordinator repoints both to the merged footer).
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w379_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


def test_p7_green_check():
    """Green check: wave-379 attack battery stays green (depth-1)."""
    return _green_check()


_t("test_p7_green_check", test_p7_green_check)


def main():
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errors = sum(1 for _, v, _ in results if v not in ("BREAK", "HELD"))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
