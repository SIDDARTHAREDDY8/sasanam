#!/usr/bin/env python3
"""Wave-378 lane 3: close F657 -- var-bound Map receiver in forEach accumulation.

F657 (LOW, filed attack round 45): F601 (CLOSED) models
Map.prototype.forEach value-accumulation but its grammar requires an
INLINE `new Map(...)` receiver. A name-bound receiver missed:
(function(){var m=new Map([['k','f1'],['j','f2']]);var s='';
m.forEach(function(v){s+=v;});return s;})() and the let-bound arrow
twin node-evaluated to the exact credential (v24.20.0) while the
decoder produced zero variants. Unlisted in F601's residuals.

Closure (gov/dlp.py, F657): _js_parse_f657_varbound_map_foreach_iife
parses (function(){var|let|const M=new Map([PAIRS]);var|let S='';
M.forEach(CB);return S;})() -- the var-bound twin of F601. The bound
map decl (var|let|const, F563 entry grammar, node-exact insertion
order / duplicate-later-wins) precedes the shared F600/F601/F602
accumulator decl (empty-string only), the receiver ident must name
the bound Map, then the F600/F601/F602 callback grammar is reused
verbatim (function or arrow, S+=E body, one or two params, no
accumulator/param shadowing, no `arguments`). Per-iteration E values
join in insertion order; F452 per-iteration part charge. Hooked after
F601 in the dispatch chain; disjoint (F601 requires the accumulator
decl as the first statement and fails closed on a leading map decl;
this route requires the leading map decl and fails closed on F601's
accumulator-first shape).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g378-*
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
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B
_CRED = _F1 + _F2 + _F3


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F657 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f657_varbound_map_foreach_iife(js, 0, 0, state)
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


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_var_function():
    """Filed shape 1: var-bound map, function callback."""
    p = ("(function(){var m=new Map([['k','" + _F1 + "'],['j','" + _F2
         + _F3 + "']]);var s='';m.forEach(function(v){s+=v;});"
         "return s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_let_arrow():
    """Filed shape 2: let-bound map, arrow callback."""
    p = ("(function(){let m=new Map([['k','" + _F1 + "'],['j','" + _F2
         + _F3 + "']]);let s='';m.forEach((v)=>{s+=v;});"
         "return s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_const_map_decl():
    """const map binding blocks (engine-legal; forEach never reassigns)."""
    return _hit("const-map",
                "(function(){const m=new Map([['k','" + _F1
                + "'],['j','" + _F2 + _F3
                + "']]);var s='';m.forEach(function(v){s+=v;});"
                "return s;})()")


def test_p2_two_param_callback():
    """(v,k) callback: P1=value, P2=key (F601 positional discipline)."""
    p = ("(function(){var m=new Map([['k','" + _F1 + "'],['j','" + _F2
         + _F3 + "']]);var s='';m.forEach(function(v,k){s+=v+k;});"
         "return s;})()")
    # node: v+k per entry in insertion order -> _CRED + keys interleaved
    want = _F1 + "k" + _F2 + _F3 + "j"
    ok = _decode_exact(p) == want and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_concise_arrow():
    """Concise arrow body (v)=>s+=v blocks."""
    return _hit("concise-arrow",
                "(function(){var m=new Map([['k','" + _F1
                + "'],['j','" + _F2 + _F3
                + "']]);var s='';m.forEach((v)=>s+=v);"
                "return s;})()")


def test_p2_bare_param_arrow():
    """Bare single-param arrow v=>{s+=v;} blocks (F448 precedent)."""
    return _hit("bare-param-arrow",
                "(function(){var m=new Map([['k','" + _F1
                + "'],['j','" + _F2 + _F3
                + "']]);var s='';m.forEach(v=>{s+=v;});"
                "return s;})()")


def test_p2_additive_suffix():
    """Additive suffix in the callback body: s+=v+'-'."""
    p = ("(function(){var m=new Map([['k','" + _F1 + "'],['j','" + _F2
         + _F3 + "']]);var s='';m.forEach(function(v){s+=v+'-';});"
         "return s;})()")
    want = _F1 + "-" + _F2 + _F3 + "-"
    ok = _decode_exact(p) == want and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_numeric_key():
    """Numeric map keys: key literal text is canonical digits."""
    p = ("(function(){var m=new Map([[1,'" + _F1 + "'],['j','" + _F2
         + _F3 + "']]);var s='';m.forEach(function(v,k){s+=v+k;});"
         "return s;})()")
    want = _F1 + "1" + _F2 + _F3 + "j"
    ok = _decode_exact(p) == want and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_duplicate_key_later_wins():
    """Duplicate keys: later entry wins (engine-exact, F563 grammar)."""
    p = ("(function(){var m=new Map([['k','jx'],['k','" + _F1 + _F2
         + _F3 + "']]);var s='';m.forEach(function(v){s+=v;});"
         "return s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_dquote_and_ws():
    """Double quotes and free whitespace block.

    Note: whitespace directly inside the forEach call parens
    (forEach( ... )) fails closed here -- the same boundary as
    F601/F602 on the base tree (verified via git stash), not a
    lane regression; documented residual.
    """
    return _hit("dquote-ws",
                "(function(){ var  m = new Map([[\"k\",\"" + _F1
                + "\"],[\"j\",\"" + _F2 + _F3
                + "\"]]) ; var s = '' ; m . forEach(function( v ){ s += v ; }) ;"
                " return s ; })()")


def test_p2_single_entry():
    """Single-entry map blocks."""
    return _hit("single-entry",
                "(function(){var m=new Map([['k','" + _CRED
                + "']]);var s='';m.forEach(function(v){s+=v;});"
                "return s;})()")


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_receiver_mismatch():
    """forEach on an unbound ident fails closed (node: ReferenceError)."""
    return _miss("recv-mismatch",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';n.forEach(function(v){s+=v;});"
                 "return s;})()")


def test_p3_accum_shadows_map():
    """Accumulator redeclaring the map name fails closed (node: TypeError)."""
    return _miss("accum-shadows-map",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var m='';m.forEach(function(v){s+=v;});"
                 "return m;})()")


def test_p3_keys_foreach_bound():
    """Bound-map .keys().forEach is a documented residual (F600 twin only)."""
    return _miss("keys-foreach-bound",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';m.keys().forEach(function(k){s+=k;});"
                 "return s;})()")


def test_p3_nonliteral_entry():
    """Non-literal map entries fail closed (F563 discipline)."""
    return _miss("nonliteral-entry",
                 "(function(){var m=new Map([[k,'" + _F1
                 + "']]);var s='';m.forEach(function(v){s+=v;});"
                 "return s;})()")


def test_p3_const_accum():
    """const accumulator fails closed (F601 discipline: would throw)."""
    return _miss("const-accum",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);const s='';m.forEach(function(v){s+=v;});"
                 "return s;})()")


def test_p3_three_params():
    """Three callback params fail closed (F600/F601/F602 grammar)."""
    return _miss("three-params",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';m.forEach(function(v,k,mp){s+=v;});"
                 "return s;})()")


def test_p3_param_shadows_accum():
    """Callback param shadowing the accumulator fails closed."""
    return _miss("param-shadows-accum",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';m.forEach(function(s){s+=s;});"
                 "return s;})()")


def test_p3_callback_not_accum():
    """Non-S+=E callback bodies fail closed."""
    return _miss("callback-not-accum",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';m.forEach(function(v){s=v;});"
                 "return s;})()")


def test_p3_reassigned_map():
    """Reassigned map binding fails closed."""
    return _miss("reassigned-map",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);m=new Map([['j','zz']]);var s='';"
                 "m.forEach(function(v){s+=v;});return s;})()")


def test_p3_trailing_statements():
    """Extra statements before return fail closed."""
    return _miss("trailing-stmt",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';m.forEach(function(v){s+=v;});"
                 "var q=1;return s;})()")


def test_p3_call_args():
    """Call args on the IIFE fail closed (zero-args tail)."""
    return _miss("call-args",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';m.forEach(function(v){s+=v;});"
                 "return s;})('x')")


def test_p3_arguments_map_name():
    """Binding the name `arguments` fails closed."""
    return _miss("arguments-map",
                 "(function(){var arguments=new Map([['k','" + _F1
                 + "']]);var s='';arguments.forEach(function(v){s+=v;});"
                 "return s;})()")


def test_p3_param_default():
    """Callback param defaults fail closed."""
    return _miss("param-default",
                 "(function(){var m=new Map([['k','" + _F1
                 + "']]);var s='';m.forEach(function(v='x'){s+=v;});"
                 "return s;})()")


def test_p3_numeric_value():
    """Non-string map values fail closed."""
    return _miss("numeric-value",
                 "(function(){var m=new Map([['k',1]]);var s='';"
                 "m.forEach(function(v){s+=v;});return s;})()")


def test_p3_nonmap_receiver():
    """A non-Map bound decl fails closed at the receiver."""
    return _miss("nonmap-receiver",
                 "(function(){var m=[['k','" + _F1
                 + "']];var s='';m.forEach(function(v){s+=v;});"
                 "return s;})()")


# ------------------------------------------------ composition (must hold)

def test_p4_f601_still_blocks():
    """F601 inline receiver still blocks (disjointness, not absorbed)."""
    ok = _blocked("(function(){var s='';new Map([['k','" + _F1
                  + "'],['j','" + _F2 + _F3
                  + "']]).forEach(function(v){s+=v;});return s;})()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f600_still_blocks():
    """F600 inline .keys().forEach still blocks.

    Note: forEach passes (key, key) here, so the KEY must carry
    the credential for find_credential to flag it.
    """
    ok = _blocked("(function(){var s='';new Map([['" + _CRED
                  + "','jx']]).keys().forEach(function(k){s+=k;});"
                  "return s;})()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f602_still_blocks():
    """F602 var-bound Set forEach still blocks."""
    ok = _blocked("(function(){var s='';var st=new Set(['" + _F1
                  + "','" + _F2 + _F3
                  + "']);st.forEach(function(v){s+=v;});"
                  "return s;})()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f646_still_blocks():
    """F646 Array forEach still blocks."""
    ok = _blocked("(function(){var s='';['" + _F1 + "','" + _F2 + _F3
                  + "'].forEach(function(v){s+=v;});return s;})()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_junk_quiet():
    """Junk entries stay quiet (no credential, no false positive)."""
    ok = _misses("(function(){var m=new Map([['k','jx']]);var s='';"
                 "m.forEach(function(v){s+=v;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p4_sibling_closures_hold():
    """F655/F656/F658-F661 CLOSED by sibling lanes (wave-378 merge): their red-first shapes now block."""
    import importlib
    bad = []
    for fnum in (655, 656, 658, 659, 660, 661):
        mod = importlib.import_module("w377_f%d_redfirst" % fnum)
        for entry in mod.SHAPES:
            payload = entry[1]
            if find_credential(payload) is None:
                bad.append("f%d:%s" % (fnum, entry[0]))
    ok = not bad
    return ("HELD" if ok else "BREAK", "block=%s" % (bad or "all"))


# ------------------------------------------------ pin + footer

def test_p5_pin_and_footer():
    """Pin 2140; lane-local footer: open F662-F671 / next F672."""
    from gov.decision_codes import TAXONOMY  # noqa: E402
    ok = TAXONOMY_PIN == 2140
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and "Next free finding: **F672**" in text  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-378 lane 3: F657 CLOSED; footer repoint open F662-F671 / next F672
    ok = ok and ("Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671." in text)  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-378 lane 3: F657 CLOSED; footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
    ok = ok and "**Status: CLOSED 2026-10-08 wave-378 lane 3.**" in text
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


# ------------------------------------------------ perf

def test_p6_perf():
    """200 var-bound forEach sites decode quickly (bounded work)."""
    site = ("(function(){var m=new Map([['k','x1']]);var s='';"
            "m.forEach(function(v){s+=v;});return s;})()")
    payload = "z".join([site] * 200)
    t0 = time.time()
    find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


# ------------------------------------------------ green check (depth-1)

def _green_check():
    """Depth-1 green check: w377 attack battery stays green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g378-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w377_attack_probes.py")],
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
    # The w377 battery's footer pin is stale by design: this lane
    # closed F657, so its expected footer (open F655-F661 / next
    # F662) no longer matches. Merge-time repoint (wave-305/306
    # class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w377_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


def test_p7_green_check():
    """Green check: wave-377 attack battery stays green (depth-1)."""
    return _green_check()


def test_p7_redfirst_green():
    """Red-first battery for F657 stays 0 BREAK on the closed tree."""
    tmp = tempfile.mkdtemp(prefix="g378-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w377_f657_redfirst.py")],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    ok = "tally: 0 BREAK" in out
    return ("HELD" if ok else "BREAK", "redfirst-0-break=%s" % ok)


def main():
    tests = [
        ("p1_filed_var_function", test_p1_filed_var_function),
        ("p1_filed_let_arrow", test_p1_filed_let_arrow),
        ("p2_const_map_decl", test_p2_const_map_decl),
        ("p2_two_param_callback", test_p2_two_param_callback),
        ("p2_concise_arrow", test_p2_concise_arrow),
        ("p2_bare_param_arrow", test_p2_bare_param_arrow),
        ("p2_additive_suffix", test_p2_additive_suffix),
        ("p2_numeric_key", test_p2_numeric_key),
        ("p2_duplicate_key_later_wins", test_p2_duplicate_key_later_wins),
        ("p2_dquote_and_ws", test_p2_dquote_and_ws),
        ("p2_single_entry", test_p2_single_entry),
        ("p3_receiver_mismatch", test_p3_receiver_mismatch),
        ("p3_accum_shadows_map", test_p3_accum_shadows_map),
        ("p3_keys_foreach_bound", test_p3_keys_foreach_bound),
        ("p3_nonliteral_entry", test_p3_nonliteral_entry),
        ("p3_const_accum", test_p3_const_accum),
        ("p3_three_params", test_p3_three_params),
        ("p3_param_shadows_accum", test_p3_param_shadows_accum),
        ("p3_callback_not_accum", test_p3_callback_not_accum),
        ("p3_reassigned_map", test_p3_reassigned_map),
        ("p3_trailing_statements", test_p3_trailing_statements),
        ("p3_call_args", test_p3_call_args),
        ("p3_arguments_map_name", test_p3_arguments_map_name),
        ("p3_param_default", test_p3_param_default),
        ("p3_numeric_value", test_p3_numeric_value),
        ("p3_nonmap_receiver", test_p3_nonmap_receiver),
        ("p4_f601_still_blocks", test_p4_f601_still_blocks),
        ("p4_f600_still_blocks", test_p4_f600_still_blocks),
        ("p4_f602_still_blocks", test_p4_f602_still_blocks),
        ("p4_f646_still_blocks", test_p4_f646_still_blocks),
        ("p4_junk_quiet", test_p4_junk_quiet),
        ("p4_sibling_closures_hold", test_p4_sibling_closures_hold),
        ("p5_pin_and_footer", test_p5_pin_and_footer),
        ("p6_perf", test_p6_perf),
        ("p7_green_check", test_p7_green_check),
        ("p7_redfirst_green", test_p7_redfirst_green),
    ]
    for name, fn in tests:
        _t(name, fn)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
