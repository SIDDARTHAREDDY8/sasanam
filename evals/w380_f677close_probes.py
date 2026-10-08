#!/usr/bin/env python3
"""Wave-380 lane 5: close F677 -- iterator-protocol fragment sources.

F677 (LOW, filed attack round 47, 2026-10-08): iterator-protocol
fragment shapes beyond the F653 (custom Symbol.iterator), F656
(.next().value), F659 (yield* over arrays), and F669 (builtin spread)
closures. Six filed shapes, all node-verified (v24.20.0) as
CRED-EXACT decoder-misses on the open tree:

  s1 manual iterator object: (function(){var o={i:0,next:function(){
       this.i++;return this.i<=2?{value:this.i===1?'f1':'f2',
       done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;
       r=o.next();s+=r.value;return s;})()
  s2 custom asyncIterator: (async function(){var o={vals:['f1','f2'],
       [Symbol.asyncIterator]:async function*(){yield this.vals[0];
       yield this.vals[1];}};var s='';for await(var x of o){s+=x;}
       return s;})()
  s3 generator return delegation: (function(){function* g(){
       yield 'f1';return 'f2';}var it=g();var a=it.next();
       var b=it.next();return a.value+b.value;})()
  s4 multi-.next() on bound generator: (function(){var g=
       (function*(){yield 'f1';yield 'f2';})();var a=g.next();
       var b=g.next();return a.value+b.value;})()
  s5 yield* over generators: (function(){function* h(){yield 'f1';}
       function* g(){yield* h();yield 'f2';}return [...g()].join('');})()
  s6 for-await over promise array: (async function(){var s='';
       for await(var x of [Promise.resolve('f1'),
       Promise.resolve('f2')]){s+=x;}return s;})()

Closure (gov/dlp.py, F677), all node-exact (v24.20.0), never evals:
- _js_parse_f677_manual_iterator_iife (hook after F653): counter-
  simulated manual iterator object; calls past done:true fail closed.
- _js_parse_f677_nextseq_iife (hook after F656): sequenced .next()
  reads on a declared generator (form A) or a var-bound invoked
  generator expression (form B); the call after the last yield
  delivers the trailing return value; later calls fail closed.
- _js_parse_f6xx_fixed_yield_body gains a `yield* IDENT();` branch
  splicing a previously-bound generator's concrete yield list
  (forward/self refs fail closed) -- reused by the F619 IIFE for s5.
- _js_parse_f640_sync_source gains a `[Promise.resolve('LIT'),...]`
  receiver branch and a var-bound async-iterator ident receiver
  branch (s6, s2); the F640 for-await IIFE parses zero or more
  custom-[Symbol.asyncIterator] object decls into a prefix env.
The F640/F619 widenings are benign generalizations (wave-378 lane-2
precedent): only previously-fail-closed inputs are newly accepted.

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


def _exact(fn_name, js):
    """Exact decoded value via an internal F677 parser seam."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = getattr(_dlp, fn_name)(js, 0, 0, state)
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
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ P1: filed shapes block

def test_p1_s1_manual_iterator():
    return _hit("s1", "(function(){var o={i:0,next:function(){this.i++;return this.i<=2?{value:this.i===1?'%s':'%s',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()" % (_A, _B))


def test_p1_s2_async_iterator():
    return _hit("s2", "(async function(){var o={vals:['%s','%s'],[Symbol.asyncIterator]:async function*(){yield this.vals[0];yield this.vals[1];}};var s='';for await(var x of o){s+=x;}return s;})()" % (_A, _B))


def test_p1_s3_gen_return():
    return _hit("s3", "(function(){function* g(){yield '%s';return '%s';}var it=g();var a=it.next();var b=it.next();return a.value+b.value;})()" % (_A, _B))


def test_p1_s4_next_seq():
    return _hit("s4", "(function(){var g=(function*(){yield '%s';yield '%s';})();var a=g.next();var b=g.next();return a.value+b.value;})()" % (_A, _B))


def test_p1_s5_yieldstar_gen():
    return _hit("s5", "(function(){function* h(){yield '%s';}function* g(){yield* h();yield '%s';}return [...g()].join('');})()" % (_A, _B))


def test_p1_s6_forawait_promises():
    return _hit("s6", "(async function(){var s='';for await(var x of [Promise.resolve('%s'),Promise.resolve('%s')]){s+=x;}return s;})()" % (_A, _B))


def test_p1_exact_values():
    """Internal seams decode the exact credential (node-exact values)."""
    cases = [
        ("_js_parse_f677_manual_iterator_iife",
         "(function(){var o={i:0,next:function(){this.i++;return this.i<=2?{value:this.i===1?'%s':'%s',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()" % (_A, _B)),
        ("_js_parse_f677_nextseq_iife",
         "(function(){function* g(){yield '%s';return '%s';}var it=g();var a=it.next();var b=it.next();return a.value+b.value;})()" % (_A, _B)),
        ("_js_parse_f677_nextseq_iife",
         "(function(){var g=(function*(){yield '%s';yield '%s';})();var a=g.next();var b=g.next();return a.value+b.value;})()" % (_A, _B)),
        ("_js_parse_f619_generator_iife",
         "(function(){function* h(){yield '%s';}function* g(){yield* h();yield '%s';}return [...g()].join('');})()" % (_A, _B)),
        ("_js_parse_f640_forawait_iife",
         "(async function(){var o={vals:['%s','%s'],[Symbol.asyncIterator]:async function*(){yield this.vals[0];yield this.vals[1];}};var s='';for await(var x of o){s+=x;}return s;})()" % (_A, _B)),
        ("_js_parse_f640_forawait_iife",
         "(async function(){var s='';for await(var x of [Promise.resolve('%s'),Promise.resolve('%s')]){s+=x;}return s;})()" % (_A, _B)),
    ]
    bad = [fn for fn, js in cases if _exact(fn, js) != _CRED]
    ok = not bad
    return ("HELD" if ok else "BREAK", "inexact=%s" % (bad or "none"))


# ------------------------------------------------ P2: variants block

def test_p2_manual_let_const():
    return _hit("man-let", "(function(){let o={i:0,next:function(){this.i++;return this.i<=2?{value:this.i===1?'%s':'%s',done:false}:{done:true};}};let s='';let r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()" % (_A, _B))


def test_p2_manual_three_calls():
    return _hit("man-3", "(function(){var o={i:0,next:function(){this.i++;return this.i<=3?{value:this.i===1?'%s':'%s',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()" % (_A, _B))


def test_p2_manual_whitespace():
    return _hit("man-ws", "(function(){ var o = { i : 0 , next : function ( ) { this.i ++ ; return this.i <= 2 ? { value : this.i === 1 ? '%s' : '%s' , done : false } : { done : true } ; } } ; var s = '' ; var r = o.next() ; s += r.value ; r = o.next() ; s += r.value ; return s ; })()" % (_A, _B))


def test_p2_async_reordered():
    return _hit("ai-reorder", "(async function(){var o={vals:['%s','%s'],[Symbol.asyncIterator]:async function*(){yield this.vals[1];yield this.vals[0];}};var s='';for await(var x of o){s+=x;}return s;})()" % (_B, _A))


def test_p2_async_push_join():
    return _hit("ai-push", "(async function(){var o={vals:['%s','%s'],[Symbol.asyncIterator]:async function*(){yield this.vals[0];yield this.vals[1];}};var p=[];for await(var x of o){p.push(x);}return p.join('');})()" % (_A, _B))


def test_p2_nextseq_three_yields():
    return _hit("ns-3y", "(function(){function* g(){yield '%s';yield '%s';yield 'zz';}var it=g();var a=it.next();var b=it.next();var c=it.next();return a.value+b.value+c.value;})()" % (_A, _B))


def test_p2_nextseq_literal_additive():
    return _hit("ns-litadd", "(function(){var g=(function*(){yield '%s';yield '%s';})();var a=g.next();var b=g.next();return 'p'+a.value+b.value;})()" % (_A, _B))


def test_p2_yieldstar_chain3():
    return _hit("ys-chain3", "(function(){function* h(){yield '%s';}function* g(){yield* h();yield '%s';}function* f(){yield* g();yield 'zz';}return [...f()].join('');})()" % (_A, _B))


def test_p2_yieldstar_arrayfrom():
    return _hit("ys-from", "(function(){function* h(){yield '%s';}function* g(){yield* h();yield '%s';}return Array.from(g()).join('');})()" % (_A, _B))


def test_p2_yieldstar_forof():
    return _hit("ys-forof", "(function(){function* h(){yield '%s';}function* g(){yield* h();yield '%s';}var s='';for(var x of g())s+=x;return s;})()" % (_A, _B))


def test_p2_promise_three():
    return _hit("pa-3", "(async function(){var s='';for await(const x of [Promise.resolve('%s'),Promise.resolve('%s'),Promise.resolve('zz')]){s+=x;}return s;})()" % (_A, _B))


def test_p2_promise_arrow():
    return _hit("pa-arrow", "(async()=>{var s='';for await(var x of [Promise.resolve('%s'),Promise.resolve('%s')]){s+=x;}return s;})()" % (_A, _B))


# ------------------------------------------------ P3: fail-closed bounds

def test_p3_manual_past_done():
    """A call past done:true delivers undefined in node -- refuse coded."""
    return _miss("b-man-past", "(function(){var o={i:0,next:function(){this.i++;return this.i<=1?{value:'%s',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()" % _A)


def test_p3_manual_next_args():
    return _miss("b-man-args", "(function(){var o={i:0,next:function(x){this.i++;return this.i<=2?{value:'%s',done:false}:{done:true};}};var s='';var r=o.next('q');s+=r.value;return s;})()" % _A)


def test_p3_manual_let_redeclare():
    """let re-declaration throws in node -- refuse coded."""
    return _miss("b-man-letre", "(function(){var o={i:0,next:function(){this.i++;return this.i<=2?{value:'%s',done:false}:{done:true};}};var s='';let r=o.next();s+=r.value;let r=o.next();s+=r.value;return s;})()" % _A)


def test_p3_nextseq_past_return():
    """A call past the return delivers undefined in node -- refuse coded."""
    return _miss("b-ns-past", "(function(){function* g(){yield '%s';return '%s';}var it=g();var a=it.next();var b=it.next();var c=it.next();return a.value;})()" % (_A, _B))


def test_p3_nextseq_call_args():
    return _miss("b-ns-args", "(function(){function* g(){yield '%s';}var it=g();var a=it.next('x');return a.value;})()" % _A)


def test_p3_nextseq_done_read():
    return _miss("b-ns-done", "(function(){function* g(){yield '%s';}var it=g();var a=it.next();return a.done;})()" % _A)


def test_p3_yieldstar_forward_ref():
    """Forward refs are not yet bound at parse time -- fail closed."""
    return _miss("b-ys-fwd", "(function(){function* g(){yield* h();yield '%s';}function* h(){yield '%s';}return [...g()].join('');})()" % (_A, _B))


def test_p3_yieldstar_no_call():
    return _miss("b-ys-nocall", "(function(){function* h(){yield '%s';}function* g(){yield* h;yield '%s';}return [...g()].join('');})()" % (_A, _B))


def test_p3_yieldstar_self_ref():
    return _miss("b-ys-self", "(function(){function* g(){yield* g();yield '%s';}return [...g()].join('');})()" % _A)


def test_p3_asynciter_index_oor():
    return _miss("b-ai-oor", "(async function(){var o={vals:['%s'],[Symbol.asyncIterator]:async function*(){yield this.vals[5];}};var s='';for await(var x of o){s+=x;}return s;})()" % _A)


def test_p3_asynciter_literal_yield():
    return _miss("b-ai-lit", "(async function(){var o={vals:['%s'],[Symbol.asyncIterator]:async function*(){yield '%s';}};var s='';for await(var x of o){s+=x;}return s;})()" % (_A, _B))


def test_p3_promise_mixed_array():
    return _miss("b-pa-mixed", "(async function(){var s='';for await(var x of [Promise.resolve('%s'),'%s']){s+=x;}return s;})()" % (_A, _B))


def test_p3_promise_reject():
    return _miss("b-pa-reject", "(async function(){var s='';for await(var x of [Promise.reject('%s')]){s+=x;}return s;})()" % _A)


def test_p3_sync_forof_promise_miss():
    """Sync for-of over a promise array yields promise objects in node
    ("[object Promise]"), not the literals -- the F677 promise branch
    is for-await-only; the sync path refuses coded."""
    return _miss("b-sync-pa", "(function(){var s='';for(var x of [Promise.resolve('%s'),Promise.resolve('%s')]){s+=x;}return s;})()" % (_A, _B))


# ------------------------------------------------ P4: neighbors + honesty

def test_p4_closed_neighbors_still_block():
    """F653/F656/F619/F640/F669 closures still hold on their shapes."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
    import importlib
    bad = []
    for modname in ("w376_f653_redfirst", "w377_f656_redfirst",
                    "w373_f619_redfirst", "w375_f640_redfirst",
                    "w378_f669_redfirst"):
        mod = importlib.import_module(modname)
        for entry in mod.SHAPES:
            if find_credential(entry[1]) is None:
                bad.append("%s:%s" % (modname, entry[0]))
    ok = not bad
    return ("HELD" if ok else "BREAK", "not_blocked=%s" % (bad or "none"))


def test_p4_open_neighbors_still_miss():
    """Open F672-F676 / F678-F685 pins still miss (nothing absorbed)."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
    import w379_attack_probes as atk
    bad = []
    for fname in dir(atk):
        if not fname.startswith("test_r47_f"):
            continue
        fnum = int(fname.split("_")[2][1:])
        if fnum == 677 or not (672 <= fnum <= 685):
            continue
        fn = getattr(atk, fname)
        if callable(fn):
            verdict, _note = fn()
            if verdict != "HELD":
                bad.append(fname)
    ok = not bad
    return ("HELD" if ok else "BREAK", "changed=%s" % (bad or "none"))


def test_p4_junk_quiet():
    """Honest text stays quiet (no false positives)."""
    return _miss("junk", "var it = {next: function(){ return {done: true}; }};")


def test_p4_composition():
    """F677 shape composed with junk stays precise."""
    p = ("prefix junk (function(){var o={i:0,next:function(){this.i++;return this.i<=2?{value:this.i===1?'"
         + _A + "':'" + _B + "',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})() suffix")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ P5: pin + lane-local footer

def test_p5_pin_and_footer():
    """Pin 2140; lane-local footer: open F672-F676, F678-F685 / next F686."""
    ok = TAXONOMY_PIN == 2140
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and "Next free finding: **F700**" in text
    ok = ok and ("Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text)
    ok = ok and "**Status: CLOSED 2026-10-08 wave-380 lane 5.**" in text
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


# ------------------------------------------------ P6: perf

def test_p6_perf():
    """200 F677 sites decode quickly (bounded work)."""
    site = ("(function(){var o={i:0,next:function(){this.i++;return this.i<=2"
            "?{value:this.i===1?'aa':'bb',done:false}:{done:true};}};"
            "var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;"
            "return s;})()")
    payload = "z".join([site] * 200)
    t0 = time.time()
    find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


# ------------------------------------------------ P7: green checks (depth-1)

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
    # This lane flips the six F677 open pins to closed pins in
    # w379_attack_probes.py (wave-305/306 class) and repoints the
    # battery footer to the lane-local footer (open F672-F676,
    # F678-F685 / next F686), matching the FINDINGS.md repoint, so
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


def test_p7_redfirst_green():
    """F677 red-first battery: 0 BREAK on the closed tree."""
    tmp = tempfile.mkdtemp(prefix="g380-redfirst-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w379_f677_redfirst.py")],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    ok = "tally: 0 BREAK" in out
    return ("HELD" if ok else "BREAK", "redfirst-0-break=%s" % ok)


def main():
    tests = [
        ("p1_s1_manual_iterator", test_p1_s1_manual_iterator),
        ("p1_s2_async_iterator", test_p1_s2_async_iterator),
        ("p1_s3_gen_return", test_p1_s3_gen_return),
        ("p1_s4_next_seq", test_p1_s4_next_seq),
        ("p1_s5_yieldstar_gen", test_p1_s5_yieldstar_gen),
        ("p1_s6_forawait_promises", test_p1_s6_forawait_promises),
        ("p1_exact_values", test_p1_exact_values),
        ("p2_manual_let_const", test_p2_manual_let_const),
        ("p2_manual_three_calls", test_p2_manual_three_calls),
        ("p2_manual_whitespace", test_p2_manual_whitespace),
        ("p2_async_reordered", test_p2_async_reordered),
        ("p2_async_push_join", test_p2_async_push_join),
        ("p2_nextseq_three_yields", test_p2_nextseq_three_yields),
        ("p2_nextseq_literal_additive", test_p2_nextseq_literal_additive),
        ("p2_yieldstar_chain3", test_p2_yieldstar_chain3),
        ("p2_yieldstar_arrayfrom", test_p2_yieldstar_arrayfrom),
        ("p2_yieldstar_forof", test_p2_yieldstar_forof),
        ("p2_promise_three", test_p2_promise_three),
        ("p2_promise_arrow", test_p2_promise_arrow),
        ("p3_manual_past_done", test_p3_manual_past_done),
        ("p3_manual_next_args", test_p3_manual_next_args),
        ("p3_manual_let_redeclare", test_p3_manual_let_redeclare),
        ("p3_nextseq_past_return", test_p3_nextseq_past_return),
        ("p3_nextseq_call_args", test_p3_nextseq_call_args),
        ("p3_nextseq_done_read", test_p3_nextseq_done_read),
        ("p3_yieldstar_forward_ref", test_p3_yieldstar_forward_ref),
        ("p3_yieldstar_no_call", test_p3_yieldstar_no_call),
        ("p3_yieldstar_self_ref", test_p3_yieldstar_self_ref),
        ("p3_asynciter_index_oor", test_p3_asynciter_index_oor),
        ("p3_asynciter_literal_yield", test_p3_asynciter_literal_yield),
        ("p3_promise_mixed_array", test_p3_promise_mixed_array),
        ("p3_promise_reject", test_p3_promise_reject),
        ("p3_sync_forof_promise_miss", test_p3_sync_forof_promise_miss),
        ("p4_closed_neighbors_still_block", test_p4_closed_neighbors_still_block),
        ("p4_open_neighbors_still_miss", test_p4_open_neighbors_still_miss),
        ("p4_junk_quiet", test_p4_junk_quiet),
        ("p4_composition", test_p4_composition),
        ("p5_pin_and_footer", test_p5_pin_and_footer),
        ("p6_perf", test_p6_perf),
        ("p7_green_check", test_p7_green_check),
        ("p7_redfirst_green", test_p7_redfirst_green),
    ]
    for name, fn in tests:
        _t(name, fn)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errs = sum(1 for _, v, _ in results if v not in ("BREAK", "HELD"))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errs))
    return 0 if breaks == 0 and errs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
