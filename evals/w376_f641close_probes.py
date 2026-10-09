#!/usr/bin/env python3
"""Wave-376 lane 2: close F641 -- deferred-callback fragment assembly.

F641 (LOW, filed 2026-10-08, attack round 43, local node validation +
2 gpt-4o-mini hint calls, $0 spend): deferred-callback fragment
assembly bypassed the bounded static JS-expression decoder. F618
(CLOSED) models Promise.all/Promise.race .then callbacks and F638
(CLOSED) the catch/finally/allSettled continuations, but the
scheduling primitives queueMicrotask() and setTimeout() had no
modeled path:
(async()=>{var p=[];queueMicrotask(()=>p.push('f1'));queueMicrotask(()=>p.push('f2'));
queueMicrotask(()=>p.push('f3'));await null;return p.join('');})(),
the nested-microtask twin
(async()=>{var p=[];queueMicrotask(()=>{p.push('f1');
queueMicrotask(()=>p.push('f2'+'f3'));});await null;await null;return p.join('');})(),
the promise-flush twin
(async()=>{var s='';queueMicrotask(()=>{s+='f1';});queueMicrotask(()=>{s+='f2'+'f3';});
await Promise.resolve();return s;})(),
and the setTimeout twin
(async()=>{var p=[];setTimeout(()=>p.push('f1'),0);...;
await new Promise(r=>setTimeout(r,20));return p.join('');})()
all node-evaluate to the exact credential (v24.20.0, async drivers)
while the decoder produced zero variants.

Closure (gov/dlp.py, F641): _js_parse_f641_deferred_iife parses
`(async()=>{var|let ACC=[]|'';(SCHED|MUT)*;AWAIT+;return TAIL;})()`
and runs a node-exact static event-loop simulation: microtasks
queue FIFO; each `await`-literal / `await Promise.resolve()`
flush drains only up to the awaiting function's own resumption
(the continuation is a microtask queued behind the pending
callbacks -- triple-nested microtasks with a single await leave
the inner fragments out, v17-verified); `await new
Promise(P=>setTimeout(P,DELAY))` drains microtasks completely
(the continuation waits on a macrotask) then fires pending
timers with delay <= DELAY in scheduling order (microtasks
always precede timers, b7/b8-verified). Timers never fire under
a microtask-only flush (b2-verified); a timer delayed past the
flush, a timer rescheduled during a flush, scheduling after the
final flush, and every non-literal operand fail closed.
Hooked after F631 in the paren dispatch (disjoint: F631 needs
`async function`, F641 needs `async()=>`). Zero new re.compile
(plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g376-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F641 deferred-IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f641_deferred_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001
        verdict, note = "BREAK", "ERROR %r" % e
    results.append((name, verdict, note))
    print("%-44s %s (%s)" % (name, verdict, note))


# --------------------------------------------- p1: filed shapes (must block)

def test_p1_filed_microtask_assembly():
    """Filed shape 1: three queueMicrotask pushes, await null, join."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'));"
         "queueMicrotask(()=>p.push('" + _F2 + "'));"
         "queueMicrotask(()=>p.push('" + _F3 + "'));"
         "await null;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "filed-s1")


def test_p1_filed_microtask_nested():
    """Filed shape 2: nested microtask, two awaits, join."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>{p.push('" + _F1 + "');"
         "queueMicrotask(()=>p.push('" + _F2 + "'+'" + _F3 + "'));});"
         "await null;await null;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "filed-s2")


def test_p1_filed_promise_flush():
    """Filed shape 3: string accum, await Promise.resolve()."""
    p = ("(async()=>{var s='';queueMicrotask(()=>{s+='" + _F1 + "';});"
         "queueMicrotask(()=>{s+='" + _F2 + "'+'" + _F3 + "';});"
         "await Promise.resolve();return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "filed-s3")


def test_p1_filed_timeout_assembly():
    """Filed shape 4: setTimeout pushes, setTimeout-flush, join."""
    p = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + "'),0);"
         "setTimeout(()=>p.push('" + _F2 + "'),0);"
         "setTimeout(()=>p.push('" + _F3 + "'),0);"
         "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "filed-s4")


# ------------------------------------------------- p2: variants (must block)

def test_p2_fn_callback():
    """function(){} callback twin blocks."""
    p = ("(async()=>{var p=[];queueMicrotask(function(){p.push('" + _F1
         + "');p.push('" + _F2 + _F3 + "');});await null;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "fn-callback")


def test_p2_multiarg_push():
    """p.push(a,b) multi-arg with '-' separator blocks."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "','"
         + _F2 + _F3 + "'));await null;return p.join('-');})()")
    return ("HELD" if _blocked(p) else "BREAK", "multiarg")


def test_p2_additive_arg():
    """p.push('f1'+'f2') additive argument blocks."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'+'"
         + _F2 + _F3 + "'));await null;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "additive-arg")


def test_p2_join_comma_default():
    """p.join() comma-default separator blocks."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + _F2
         + _F3 + "'));await null;return p.join();})()")
    return ("HELD" if _blocked(p) else "BREAK", "join-comma")


def test_p2_mixed_microtask_first():
    """Timer scheduled before microtask: microtask still first, blocks."""
    p = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F2 + _F3 + "'),0);"
         "queueMicrotask(()=>p.push('" + _F1 + "'));"
         "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "mixed-order")


def test_p2_schedule_between_awaits():
    """Scheduling between two awaits flushes on the second, blocks."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'));"
         "await null;queueMicrotask(()=>p.push('" + _F2 + _F3 + "'));"
         "await null;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "interleave")


def test_p2_sync_mutation_top():
    """Synchronous top-level push alongside deferred pushes blocks."""
    p = ("(async()=>{var p=[];p.push('" + _F1 + "');"
         "queueMicrotask(()=>p.push('" + _F2 + _F3 + "'));"
         "await null;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "sync-mut")


def test_p2_paren_flush_param():
    """await new Promise((r)=>setTimeout(r,10)) paren-param twin blocks."""
    p = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + _F2 + _F3
         + "'),0);await new Promise((r)=>setTimeout(r,10));"
         "return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "paren-param")


def test_p2_await_numeric():
    """await 0 flushes microtasks like await null, blocks."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + _F2
         + _F3 + "'));await 0;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "await-num")


def test_p2_whitespace():
    """Whitespace-tolerant spacing twin blocks."""
    p = ("(async () => { var p = [] ; queueMicrotask( () => p.push( '"
         + _F1 + _F2 + _F3 + "' ) ) ; await null ; return p.join( '' ) ; } ) ( )")
    return ("HELD" if _blocked(p) else "BREAK", "ws")


def test_p2_let_accum():
    """let string accumulator twin blocks."""
    p = ("(async()=>{let s='';queueMicrotask(()=>{s+='" + _F1 + _F2 + _F3
         + "';});await Promise.resolve();return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "let")


def test_p2_double_quotes():
    """Double-quoted literal twin blocks."""
    p = ('(async()=>{var p=[];queueMicrotask(()=>p.push("' + _F1 + _F2
         + _F3 + '"));await null;return p.join("");})()')
    return ("HELD" if _blocked(p) else "BREAK", "dquotes")


def test_p2_timer_nested_microtask():
    """Microtask queued by a timer callback drains after it, blocks."""
    p = ("(async()=>{var p=[];setTimeout(()=>{p.push('" + _F1 + "');"
         "queueMicrotask(()=>p.push('" + _F2 + _F3 + "'));},0);"
         "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "timer-nested-micro")


def test_p2_block_bodied_timeout():
    """Block-bodied setTimeout callback twin blocks."""
    p = ("(async()=>{var p=[];setTimeout(()=>{p.push('" + _F1 + _F2 + _F3
         + "');},0);await new Promise(r=>setTimeout(r,20));"
         "return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "block-timeout")


def test_p2_expr_nested_schedule():
    """Expression-bodied arrow with nested scheduling blocks."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>queueMicrotask(()=>p.push('"
         + _F1 + _F2 + _F3 + "')));"
         "await null;await null;return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "expr-nested")


# ------------------------------------------- p3: fail-closed bounds (must miss)

def test_p3_sync_timeout_no_await():
    """Sync IIFE: the timer never fires before return -- miss, never mis-decode."""
    p = ("(function(){var s='" + _F1 + "';setTimeout(function(){s+='"
         + _F2 + _F3 + "';},0);return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "sync-no-await")


def test_p3_timer_await_null_noflush():
    """await null never fires timers -- miss."""
    p = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + "'),0);"
         "await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "timer-await-null")


def test_p3_sched_after_flush():
    """Callback scheduled after the flush never runs before return -- miss."""
    p = ("(async()=>{var p=[];await null;queueMicrotask(()=>p.push('"
         + _F1 + "'));return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "sched-after-flush")


def test_p3_delay_exceeds_flush():
    """Timer delayed past the flush never fires -- miss, never mis-decode."""
    p = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + "'),50);"
         "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "delay-gt-flush")


def test_p3_nonliteral_push():
    """p.push(ident) non-literal operand fails closed."""
    p = ("(async()=>{var p=[];var x='" + _F1 + "';"
         "queueMicrotask(()=>p.push(x));await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "nonliteral-push")


def test_p3_nonliteral_add():
    """s+=ident non-literal operand fails closed."""
    p = ("(async()=>{var s='';var x='" + _F1 + "';"
         "queueMicrotask(()=>{s+=x;});await Promise.resolve();return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "nonliteral-add")


def test_p3_crosskind_push_on_str():
    """push on a string accumulator fails closed."""
    p = ("(async()=>{var s='';queueMicrotask(()=>s.push('" + _F1
         + "'));await null;return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "crosskind-push")


def test_p3_crosskind_add_on_arr():
    """+= on an array accumulator fails closed."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>{p+='" + _F1 + "';});"
         "await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "crosskind-add")


def test_p3_async_callback():
    """async ()=> callbacks are unmodeled -- fail closed."""
    p = ("(async()=>{var p=[];queueMicrotask(async()=>p.push('" + _F1
         + "'));await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "async-callback")


def test_p3_stringcode_callback():
    """setTimeout('code',0) string-code callbacks are unmodeled -- fail closed."""
    p = ("(async()=>{var p=[];setTimeout(\"p.push('" + _F1 + "')\",0);"
         "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "stringcode")


def test_p3_callback_with_param():
    """Non-empty callback params are unmodeled -- fail closed."""
    p = ("(async()=>{var p=[];queueMicrotask((x)=>p.push('" + _F1
         + "'));await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "callback-param")


def test_p3_return_in_callback():
    """return inside a callback body fails closed."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>{p.push('" + _F1
         + "');return;});await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "return-in-callback")


def test_p3_extra_sched_arg():
    """Extra scheduling arguments fail closed."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'),1);"
         "await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "extra-sched-arg")


def test_p3_const_accum():
    """const accumulator would throw on mutation -- fail closed."""
    p = ("(async()=>{const p=[];queueMicrotask(()=>p.push('" + _F1
         + "'));await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "const-accum")


def test_p3_nonempty_accum():
    """Non-empty accumulator initializer fails closed."""
    p = ("(async()=>{var p=['z'];queueMicrotask(()=>p.push('" + _F1
         + "'));await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "nonempty-accum")


def test_p3_no_await():
    """No flush at all: microtasks never run before return -- miss."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1
         + "'));return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "no-await")


def test_p3_call_args_on_iife():
    """Call args on the IIFE fail closed."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1
         + "'));await null;return p.join('');})(1)")
    return ("HELD" if _misses(p) else "BREAK", "iife-args")


def test_p3_ident_boundary():
    """queueMicrotaskx is not queueMicrotask -- fail closed."""
    p = ("(async()=>{var p=[];queueMicrotaskx(()=>p.push('" + _F1
         + "'));await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "ident-boundary")


def test_p3_timer_rescheduled_during_flush():
    """Timer scheduled by a timer callback during a flush fails closed."""
    p = ("(async()=>{var p=[];setTimeout(()=>{setTimeout(()=>p.push('"
         + _F1 + "'),0);},0);"
         "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "timer-resched")


def test_p3_await_unmodeled_operand():
    """await of a call expression is unmodeled -- fail closed."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1
         + "'));await foo();return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "await-operand")


def test_p3_nonliteral_delay():
    """Non-literal setTimeout delay fails closed."""
    p = ("(async()=>{var p=[];var d=0;setTimeout(()=>p.push('" + _F1
         + "'),d);await new Promise(r=>setTimeout(r,20));"
         "return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "nonliteral-delay")


def test_p3_reordered_assembly_quiet():
    """Expiry-ordered timers assemble a non-credential: stays quiet (node-exact)."""
    p = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + "'),10);"
         "setTimeout(()=>p.push('" + _F2 + _F3 + "'),5);"
         "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "reordered-quiet")


def test_p3_resolve_thenable_closed():
    """await Promise.resolve(thenable) fails closed (side-effecting await)."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'));"
         "queueMicrotask(()=>p.push('" + _F2 + "'));"
         "queueMicrotask(()=>p.push('" + _F3 + "'));"
         "await Promise.resolve({then:function(r){r();}});"
         "return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "thenable-closed")


# ------------------------------------------------- p4: composition (neighbors)

def test_p4_f618_still_blocks():
    """F618 (CLOSED) Promise.all/.then still blocks -- nothing absorbed."""
    p = ("Promise.all([Promise.resolve('" + _F1 + "'),Promise.resolve('"
         + _F2 + "'),Promise.resolve('" + _F3 + "')]).then(a=>a.join(''))")
    return ("HELD" if _blocked(p) else "BREAK", "f618")


def test_p4_f631_still_blocks():
    """F631 (CLOSED) async-generator for-await still blocks."""
    p = ("(async function(){async function* g(){yield '" + _F1 + "';yield '"
         + _F2 + _F3 + "';}var s='';for await (const x of g()){s+=x;}"
         "return s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "f631")


def test_p4_f638_still_blocks():
    """F638 (CLOSED) promise catch continuation still blocks."""
    p = ("Promise.reject(new Error('" + _F1 + "')).catch(e=>e.message+'"
         + _F2 + _F3 + "')")
    return ("HELD" if _blocked(p) else "BREAK", "f638")


def test_p4_f640_now_closed():
    """F640 (CLOSED wave-376 lane 1) for-await over sync iterables now blocks."""
    p = ("(async()=>{var p=[];for await (const x of ['" + _F1 + "','"
         + _F2 + "','" + _F3 + "']) p.push(x); return p.join('');})()")
    return ("HELD" if _blocked(p) else "BREAK", "f640-closed")


def test_p4_f642_now_closed():
    """F642 (CLOSED wave-376 lane 3) getter var-fragments now block."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3
         + "';var o={get s(){return a+b+c;}};return o.s;})()")
    return ("HELD" if _blocked(p) else "BREAK", "f642-closed")


def test_p4_f643_now_closed():
    """F643 (CLOSED wave-376 lane 4) fromCharCode-u8-spread now blocks."""
    p = ("String.fromCharCode(...new Uint8Array(["
         + ",".join(str(b) for b in (_F1 + _F2).encode()) + "]))+'"
         + _F3 + "'")
    return ("HELD" if _blocked(p) else "BREAK", "f643-closed")


# ------------------------------------------------- p5: junk quiet

def test_p5_junk_quiet():
    """Honest text stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "junk-quiet")


def test_p5_benign_deferred():
    """Benign deferred shapes (no credential) stay quiet."""
    p = ("(async()=>{var p=[];queueMicrotask(()=>p.push('ab'));"
         "await null;return p.join('');})()")
    return ("HELD" if _misses(p) else "BREAK", "benign-deferred")


# ------------------------------------------- p6: node differential (value-exact)

def _check_exact(name, js, want):
    got = _decode_exact(js)
    ok = (got == want)
    return ("HELD" if ok else "BREAK",
            "%s match=%s" % (name, ok))


def test_p6_exact_filed_s1():
    """Filed s1 decodes node-exactly."""
    js = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'));"
          "queueMicrotask(()=>p.push('" + _F2 + "'));"
          "queueMicrotask(()=>p.push('" + _F3 + "'));"
          "await null;return p.join('');})()")
    return _check_exact("s1", js, _F1 + _F2 + _F3)


def test_p6_exact_filed_s2():
    """Filed s2 (nested, two awaits) decodes node-exactly."""
    js = ("(async()=>{var p=[];queueMicrotask(()=>{p.push('" + _F1 + "');"
          "queueMicrotask(()=>p.push('" + _F2 + "'+'" + _F3 + "'));});"
          "await null;await null;return p.join('');})()")
    return _check_exact("s2", js, _F1 + _F2 + _F3)


def test_p6_exact_filed_s3():
    """Filed s3 (string accum, promise flush) decodes node-exactly."""
    js = ("(async()=>{var s='';queueMicrotask(()=>{s+='" + _F1 + "';});"
          "queueMicrotask(()=>{s+='" + _F2 + "'+'" + _F3 + "';});"
          "await Promise.resolve();return s;})()")
    return _check_exact("s3", js, _F1 + _F2 + _F3)


def test_p6_exact_filed_s4():
    """Filed s4 (timeout twin) decodes node-exactly."""
    js = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + "'),0);"
          "setTimeout(()=>p.push('" + _F2 + "'),0);"
          "setTimeout(()=>p.push('" + _F3 + "'),0);"
          "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return _check_exact("s4", js, _F1 + _F2 + _F3)


def test_p6_exact_resume_marker():
    """Triple-nested microtask, one await: inner fragments excluded (node-exact)."""
    js = ("(async()=>{var p=[];queueMicrotask(()=>{queueMicrotask(()=>{"
          "queueMicrotask(()=>p.push('" + _F1 + "'));});});"
          "await null;return p.join('');})()")
    return _check_exact("resume", js, "")


def test_p6_exact_timer_no_flush():
    """Timer under await-null flush: nothing fires (node-exact '')."""
    js = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + "'),0);"
          "await null;return p.join('');})()")
    return _check_exact("timer-noflush", js, "")


def test_p6_exact_mixed_order():
    """Mixed scheduling: microtasks precede timers (node-exact)."""
    js = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F2 + _F3 + "'),0);"
          "queueMicrotask(()=>p.push('" + _F1 + "'));"
          "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return _check_exact("mixed", js, _F1 + _F2 + _F3)


def test_p6_exact_interleave():
    """Schedule-between-awaits decodes node-exactly."""
    js = ("(async()=>{var p=[];await null;"
          "queueMicrotask(()=>p.push('" + _F1 + "'));"
          "await null;return p.join('');})()")
    return _check_exact("interleave", js, _F1)


def test_p6_exact_sync_mut():
    """Top-level synchronous push composes node-exactly."""
    js = ("(async()=>{var p=[];p.push('" + _F1 + "');"
          "queueMicrotask(()=>p.push('" + _F2 + _F3 + "'));"
          "await null;return p.join('');})()")
    return _check_exact("sync-mut", js, _F1 + _F2 + _F3)


def test_p6_exact_join_comma():
    """join() comma default decodes node-exactly."""
    js = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'));"
          "await null;return p.join();})()")
    return _check_exact("comma", js, _F1)


def test_p6_exact_timer_expiry_order():
    """Differing timer delays decode in expiry order (node-exact)."""
    js = ("(async()=>{var p=[];setTimeout(()=>p.push('" + _F1 + "'),10);"
          "setTimeout(()=>p.push('" + _F2 + _F3 + "'),5);"
          "await new Promise(r=>setTimeout(r,20));return p.join('');})()")
    return _check_exact("expiry", js, _F2 + _F3 + _F1)


def test_p6_exact_resolve_thenable_closed():
    """Promise.resolve(thenable) fails closed (no decode)."""
    js = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1 + "'));"
          "await Promise.resolve({then:function(r){r();}});"
          "return p.join('');})()")
    got = _decode_exact(js)
    ok = (got is None)
    return ("HELD" if ok else "BREAK", "thenable-closed=%s" % ok)


# ------------------------------------------------- p7: pin, footer, hygiene

def test_p7_pin_taxonomy():
    """Pin 2143."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p7_footer_state():
    """Footer: F641 closed; open F640, F642, F643; next F644."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F921**" in text  # Wave-376 lane 2: F641 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-376 lane 2: F641 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p7_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    import re
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov",
                                         "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------- p8: perf

def test_p8_perf_corpus():
    """Dispatch sites do not blow the scan budget (F452 discipline)."""
    corpus = ("(async()=>{var p=[];queueMicrotask(()=>p.push('" + _F1
              + "'));queueMicrotask(()=>p.push('" + _F2
              + "'));queueMicrotask(()=>p.push('" + _F3
              + "'));await null;return p.join('');})() " * 200)
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


# ------------------------------------------------- p9: green check

def test_p9_green_check():
    """Depth-1 green check: F641 red-first + F631/F638 close battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w375_f641_redfirst.py", 0),
                               ("evals/w375_f638f631close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g376-green-", dir="/var/tmp")
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
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
