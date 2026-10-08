"""Wave-304 lane E battery: independent red team vs the wave-303 tree.

Base: wave-303 merge c9138cc53888 (F380-F384 closed; authority-lifecycle
leases landed; pin 1827; footer open F385,F386 / next F387).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. The F380-F384 closures at their close-when boundaries (regression
    probes: ledger-required replay, caller-bound complete, journal
    fixed-point).
 2. gov/authority_lifecycle.py heartbeat edges (counter replay,
    cross-lease proofs, suspend-parks-ttl, forged operator authz).
 3. F385 / F386 as CLOSED regression controls (wave-304 lanes A/B;
    HELD on the merged tree).
 4. F381 amplification (composed _resolve_replay trusts a poisoned
    (digest, ref) pair) as a CLOSED regression control -- filed as F388
    and closed by wave-304 lane C (HELD on the merged tree).
 5. F383 amplification (approval-gated steps sharing one idempotency
    key) -- verified HELD (lane 3's closure holds).

New finding filed from F387:
  F387 (LOW, OPEN) -- gov/workflow.py recv_step/sleep_step completed
    paths skip the inputs-drift refusal that run_step enforces on both
    its replay paths (and that the module docstring promises "for an
    already-completed step slot"). A slot completed for event
    "settled" replays its payload for a "refunded" subscription
    (recv); a slot completed with wake_at=T1 returns awake for
    wake_at=T2 (sleep). Same defect class as F383 (filed LOW).

Falsified (HELD regression probes):
  - F380 ledger-required replay still refuses workflow-authority-revoked.
  - F381 caller binding still refuses workflow-idempotency-caller-mismatch.
  - F382 journal reload is still a fixed point.
  - F379 per-delegator anti-substitution still holds.
  - authority_lifecycle heartbeat edges hold (counter replay, cross-lease
    proof, suspend parks ttl, forged operator authorization).

Run:
  mkdir -p /var/tmp/g304-rt && TMPDIR=/var/tmp/g304-rt \
    ~/workspace/.gov-venv/bin/python evals/w304_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g304-rt2 \
    ~/workspace/.gov-venv/bin/python evals/w304_redteam_probes.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line form)

# Wave-303 merge pin 1827; this lane mints no codes (red team only), so
# the pin stays 1827. The merge-time sweep repoints to the wave-304 pin.
TAXONOMY_PIN = 2143  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "2143/2143/0 sorted")  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)




def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    matches = re.findall(
        r"Next free finding: \*\*F(\d+)\*\*\.\s*\*\*Open findings: ([^*]*)\.\*\*",
        text)
    if not matches:
        return _record("footer-state", "BREAK", "footer not parseable")
    nxt, open_s = int(matches[-1][0]), matches[-1][1].strip()
    want_open = "F597, F598, F599, F600, F601, F602, F603, F604, F605"  # this lane: F387 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)
    # Wave-342 lane 6: repointed to open F429 / next F430 (footer-state probe audit).
    if nxt != 531 or open_s != want_open:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F506 open 'F503, F504, F505')"
                       % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer pins open F521, F522, F523, F524, F525 / next F526")  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w304rt-" + tag).encode()).digest()


def _chain_fx():
    from gov import delegation as dg
    from gov import ed25519
    sa, sb = _seed("a"), _seed("b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    return sa, sb, pa, pb, [root], [pa]


def _authority(chain, trust_roots, ledger=None):
    # F380 closure: the workflow store requires a revocation ledger on
    # every authority verification (fail closed when absent). Mint a
    # fresh (empty) revoker when none is passed.
    if ledger is None:
        from gov import delegation_revocation as rv
        ledger = rv.DelegationRevoker(_seed("a"), "agent-a")
    return {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": chain, "trust_roots": trust_roots,
            "revocation_ledger": ledger}


# ---------------------------------------------------------------------------
# Regression pins (CLOSED on the merged tree; F387 still BREAKs)
# ---------------------------------------------------------------------------

def p_f385_resume_xid_unenforced():
    # F385 (LOW, OPEN): resume_lease never resolves the suspension's XID
    # against live transactions -- the documented XID binding is
    # decorative. A suspension record resumes under another live
    # transaction's XID, or a never-begun well-formed XID.
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    tok = lease["fencing_token"]
    c = wb.BranchCoordinator()
    xid_a = c.begin(ed25519.generate_seed(), lease_manager=lm)
    xid_b = c.begin(ed25519.generate_seed())
    susp = c.suspend_lease(xid_a, lm, "scope-x", tok, "holder-1",
                          suspended_at=1050)
    breaks = []
    tampered = dict(susp)
    tampered["xid"] = xid_b
    try:
        if c.resume_lease(tampered, lm, checked_at=1090) is True:
            breaks.append("another-live-txn-xid")
    except Exception:
        pass
    tampered2 = dict(susp)
    tampered2["xid"] = "ab" * 32  # never begun
    try:
        if c.resume_lease(tampered2, lm, checked_at=1090) is True:
            breaks.append("never-begun-xid")
    except Exception:
        pass
    if breaks:
        return _record("F385-resume-xid-unenforced", "BREAK",
                       "resume_lease accepted suspension under %s "
                       "(XID binding unenforced; F385 still open)"
                       % ("/".join(breaks),))
    _record("F385-resume-xid-unenforced", "HELD",
            "resume_lease binds the suspension XID to a live transaction "
            "(F385 closed)")


def p_f386_verifier_collision():
    # F386 (LOW, CLOSED by wave-304 lane B): regression pin. Two
    # WorkflowComposers share one SagaManager; the second reentrantly
    # executes the SAME plan from inside the first's compensation.
    # Pre-fix: the second composer's verifier install overwrote the
    # first's plan-scoped ref, and c1 escalated coded
    # workflow-saga-compensation-unauthorized. Post-fix (per-composer
    # nonce-scoped refs + deterministic removal): compensates cleanly.
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    import gov.workflow_composed as wc
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()  # shared by both composers
    c1 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    c2 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    ws.start_run("probe", run_id="col-r1", authority=auth, at=AT)
    ws.start_run("probe", run_id="col-r2", authority=auth, at=AT)
    entered = {"n": 0}

    def ok(i):
        return ({"r": 1}, [])

    def boom(i):
        raise RuntimeError("kaboom")

    def comp_s1(i):
        return {"u": 1}

    def comp_s2(i):
        if entered["n"] == 0:
            entered["n"] += 1
            c2.execute(plan, run_id="col-r2", authority=auth, at=AT)
        return {"u": 2}

    sd = sm.define([
        saga.SagaStepDef("s1", "a1", {}, "c1"),
        saga.SagaStepDef("s2", "a2", {}, "c2"),
        saga.SagaStepDef("s3", "a3", {}, "c3")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": ok, "s3": boom},
         "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
         "idem_key": "ck"}])
    try:
        res = c1.execute(plan, run_id="col-r1", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        return _record(
            "F386-verifier-collision", "BREAK",
            "reentrant same-plan execution escalated: coded %r (%r)"
            % (code, e))
    if res["units"]["sg"]["status"] != "compensated":
        return _record("F386-verifier-collision", "BREAK",
                       "unexpected status %r"
                       % (res["units"]["sg"]["status"],))
    _record("F386-verifier-collision", "HELD",
            "reentrant same-plan execution compensates cleanly (F386 closed)")


def p_f381amp_composed_foreign_replay():
    # F388 (MEDIUM, CLOSED by wave-304 lane C): regression pin. A
    # poisoned idempotency record's (digest, ref) pair was trusted by
    # WorkflowComposer._resolve_replay -- the composed unit returned a
    # FOREIGN run's checkpoint outputs without executing. The poisoner
    # is the record's own beginning caller, so the F381 caller-binding
    # fix did not cover it. Post-fix: _resolve_replay refuses coded
    # workflow-composed-replay-foreign (detached, foreign run, or
    # foreign caller).
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    import gov.workflow_composed as wc
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, saga.SagaManager(), im)
    ws.start_run("probe", run_id="victim", authority=auth, at=AT)
    ws.run_step("victim", 1, "vstep", lambda i: {"stolen": 1}, {},
                authority=auth, at=AT)
    victim_outputs = ws.get_step("victim", 1)["outputs"]
    victim_digest = hashlib.sha256(
        json.dumps(victim_outputs, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    op_digest = "f" * 64
    im.begin("composed", "composed-unit", "ak", op_digest,
             caller="agent-b", authority_verifier=lambda **k: True, at=AT)
    mallory = im.begin("composed", "composed-unit", "ak", op_digest,
                       caller="agent-b", authority_verifier=lambda **k: True,
                       at=AT)
    if mallory.status != "retry":
        return _record("F381amp-composed-foreign-replay", "ERROR",
                       "no in-flight record to poison: %s" % (mallory.status,))
    # Mallory is the record's own beginning caller: the F381
    # caller-binding check passes for the poisoner.
    mallory.complete(victim_digest, "wfstep:victim:1", at=AT)
    replay = im.begin("composed", "composed-unit", "ak", op_digest,
                      caller="agent-b", authority_verifier=lambda **k: True,
                      at=AT)
    if replay.status != "replay":
        return _record("F381amp-composed-foreign-replay", "ERROR",
                       "poison did not stick: %s" % (replay.status,))
    try:
        resolved = comp._resolve_replay(replay, "composed-unit",
                                     "unreachable-key",
                                     "fn:redteam-probe")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-composed-replay-foreign":
            return _record(
                "F381amp-composed-foreign-replay", "HELD",
                "foreign pair refused coded (F388 closed)")
        return _record("F381amp-composed-foreign-replay", "ERROR",
                       "unexpected refusal code %r (%r)" % (code, e))
    if resolved == victim_outputs:
        return _record(
            "F381amp-composed-foreign-replay", "BREAK",
            "F381 root cause (composer layer): poisoned record made the "
            "composer return a foreign run's outputs without executing")
    _record("F381amp-composed-foreign-replay", "HELD",
            "foreign ref refused (F388 closed)")


def p_f383amp_gated_key_reuse():
    # F383 amplification: two approval-gated steps sharing one
    # idempotency key, each with a fully valid per-step approval.
    # Lane 3's closure (name + inputs-digest drift checks on the key
    # path) should refuse coded workflow-step-unauthorized. Verified
    # HELD on this tree.
    from gov import workflow_approval as wa
    from gov import workflow as wf
    from gov import ed25519
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)

    def pkg(run_id, seq, name, inputs):
        return wa.request_approval(
            chain=chain, delegation_right="tool.invoke",
            run_id=run_id, seq=seq, name=name, inputs=inputs,
            requester_agent_id="agent-b",
            requester_principal="principal-agent-b",
            requester_pubkey_hex=ed25519.publickey(sb).hex(),
            requester_seed=sb, approver_schema=[], ttl_seconds=3600,
            issued_at=AT)

    store = wf.WorkflowStore()
    store.start_run("wf", run_id="run1", authority=auth, at=AT)
    r = wa.ApprovalGatedWorkflow(store, trust_roots=trust_roots)
    p1 = pkg("run1", 0, "step0", {"x": 1})
    r.run_gated_step("run1", 0, "step0", lambda i: {"y": i["x"] + 1},
                     {"x": 1}, approval_package=p1, authority=auth, at=AT,
                     idempotency_key="K")
    p2 = pkg("run1", 1, "step1", {"x": 100})  # valid approval for step1
    calls = []
    try:
        o2 = r.run_gated_step("run1", 1, "step1",
                              lambda i: calls.append(1) or {"y": i["x"] * 2},
                              {"x": 100}, approval_package=p2, authority=auth,
                              at=AT + 5, idempotency_key="K")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "workflow-step-unauthorized":
            return _record("F383amp-gated-key-reuse", "HELD",
                           "key path refused drift coded "
                           "workflow-step-unauthorized (F383 closure holds)")
        raise
    if o2["outputs"] == {"y": 2} and not calls:
        return _record(
            "F383amp-gated-key-reuse", "BREAK",
            "F383 root cause: valid approval for step1, yet step0's "
            "outputs replayed without executing step1")
    _record("F383amp-gated-key-reuse", "HELD",
            "key path applied drift checks")


# ---------------------------------------------------------------------------
# New finding: F387 (LOW, OPEN)
# ---------------------------------------------------------------------------

def p_f387_recv_event_drift():
    # F387: recv_step's completed path checks the step NAME but not the
    # event subscription. A slot completed for event "settled" replays
    # its payload for a "refunded" subscription -- replayed=True, no
    # refusal. The run_step replay paths (seq slot AND idempotency key)
    # refuse workflow-step-unauthorized on inputs drift, and the module
    # docstring promises drift refusal "for an already-completed step
    # slot". The sleep/recv completed paths don't.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.notify("r1", "settled", {"amount": 100}, authority=auth, at=AT)
    p1, rep1 = ws.recv_step("r1", 1, "wait", "settled",
                            authority=auth, at=AT)
    if p1 != {"amount": 100} or rep1:
        return _record("F387-recv-event-drift", "ERROR",
                       "setup failed: %r %r" % (p1, rep1))
    try:
        p2, rep2 = ws.recv_step("r1", 1, "wait", "refunded",
                                authority=auth, at=AT + 5)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387-recv-event-drift", "HELD",
                           "completed path refused event drift coded "
                           "workflow-step-unauthorized (F387 closed)")
        return _record("F387-recv-event-drift", "ERROR",
                       "wrong refusal: %r" % (e,))
    if rep2 and p2 == {"amount": 100}:
        return _record(
            "F387-recv-event-drift", "BREAK",
            "completed slot replayed the 'settled' payload for a "
            "'refunded' subscription (no inputs-drift refusal; F387)")
    _record("F387-recv-event-drift", "HELD", "no event confusion")


def p_f387_sleep_wakeat_drift():
    # F387, second instance: sleep_step's completed path checks the
    # step NAME but not wake_at. A slot completed with wake_at=T1
    # returns (True, True) for wake_at=T2 -- the inputs-drift refusal
    # is missing. Timing-semantics only (outputs are constant
    # {"awake": True}); the recv instance above carries the severity.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r2", authority=auth, at=AT)
    a1, x1 = ws.sleep_step("r2", 1, "nap", AT + 100,
                           authority=auth, at=AT, now=AT + 200)
    if not (a1 and not x1):
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "setup failed: %r %r" % (a1, x1))
    try:
        a2, x2 = ws.sleep_step("r2", 1, "nap", AT + 999999,
                               authority=auth, at=AT + 5, now=AT + 200)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387-sleep-wakeat-drift", "HELD",
                           "completed path refused wake_at drift coded "
                           "workflow-step-unauthorized (F387 closed)")
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "wrong refusal: %r" % (e,))
    if a2 and x2:
        return _record(
            "F387-sleep-wakeat-drift", "BREAK",
            "completed slot accepted wake_at drift (T1 -> T2) without "
            "refusal (F387)")
    _record("F387-sleep-wakeat-drift", "HELD", "no wake_at confusion")


# ---------------------------------------------------------------------------
# Regression probes: the F380-F384 closures + F379 still hold
# ---------------------------------------------------------------------------

def p_f380_ledger_required_replay():
    # F380 regression: a completed-step replay without a revocation
    # ledger must fail closed coded workflow-authority-revoked.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.run_step("r1", 1, "s1", lambda i: {"v": 1}, {}, authority=auth, at=AT)
    no_ledger = {"actor_id": "agent-b", "action": "tool.invoke",
                 "chain": chain, "trust_roots": trust_roots}
    try:
        ws.run_step("r1", 1, "s1", lambda i: {"v": 2}, {},
                    authority=no_ledger, at=AT + 5)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-authority-revoked":
            return _record("F380-ledger-required-replay", "HELD",
                           "replay without ledger refused coded "
                           "workflow-authority-revoked")
        return _record("F380-ledger-required-replay", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F380-ledger-required-replay", "BREAK",
                   "F380 regressed: replay executed without a ledger")


def p_f381_caller_binding_complete():
    # F381 regression: a different authorized caller cannot complete
    # another actor's in-flight record.
    from gov import workflow_idempotency as idem
    im = idem.IdempotencyStore()
    v = lambda **k: True  # noqa: E731
    o1 = im.begin("ns", "op", "k1", "a" * 64, caller="agent-b",
                  authority_verifier=v, at=AT)
    o2 = im.begin("ns", "op", "k1", "a" * 64, caller="agent-c",
                  authority_verifier=v, at=AT)
    if o2.status != "retry":
        return _record("F381-caller-binding-complete", "ERROR",
                       "setup: %s" % (o2.status,))
    try:
        o2.complete("b" * 64, "ref-1", at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == \
                "workflow-idempotency-caller-mismatch":
            return _record("F381-caller-binding-complete", "HELD",
                           "cross-caller complete refused coded "
                           "workflow-idempotency-caller-mismatch")
        return _record("F381-caller-binding-complete", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F381-caller-binding-complete", "BREAK",
                   "F381 regressed: cross-caller complete succeeded")


def p_f382_journal_fixed_point():
    # F382 regression: reloading a journaled store is a fixed point --
    # the file must not grow on reload.
    from gov import workflow as wf
    import tempfile
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    tmpd = tempfile.mkdtemp(prefix="w304-f382-")
    path = os.path.join(tmpd, "journal.jsonl")
    ws = wf.WorkflowStore(path=path)
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.run_step("r1", 1, "s1", lambda i: {"v": 1}, {}, authority=auth, at=AT)
    n1 = os.path.getsize(path)
    ws2 = wf.WorkflowStore(path=path)  # reload
    n2 = os.path.getsize(path)
    if n1 != n2:
        return _record("F382-journal-fixed-point", "BREAK",
                       "F382 regressed: journal grew %d -> %d on reload"
                       % (n1, n2))
    # And the reloaded state is usable.
    out, rep = ws2.run_step("r1", 1, "s1", lambda i: {"v": 9}, {},
                            authority=auth, at=AT + 5)
    if rep and out == {"v": 1}:
        return _record("F382-journal-fixed-point", "HELD",
                       "reload is a fixed point; state intact")
    return _record("F382-journal-fixed-point", "ERROR",
                   "reloaded state wrong: %r %r" % (out, rep))


def p_f379_antisubstitution_holds():
    # F379 regression: a revoker whose delegator_id does not match its
    # mapping key is ignored (anti-substitution) -- the mapping wins.
    from gov import delegation as dg
    from gov import delegation_revocation as rev
    from gov import ed25519
    sea, seb = bytes([0x0A]) * 32, bytes([0x0B]) * 32
    pea = ed25519.publickey(sea).hex()
    peb = ed25519.publickey(seb).hex()
    root = dg.issue(sea, "authority", "holder", peb, ["lease.acquire"],
                    issued_at=AT)
    child = dg.issue(seb, "holder", "sub",
                     ed25519.publickey(bytes([0x0C]) * 32).hex(),
                     ["lease.acquire"], parent=root, issued_at=AT)
    ra = rev.DelegationRevoker(sea, "authority")
    rb = rev.DelegationRevoker(seb, "holder")
    rb.revoke(child["receipt_id"], AT + 5)
    # Attacker shape: register rb under the WRONG key.
    mapping = {"authority": ra, "WRONG": rb}
    found = []
    for delegator_id in ("authority", "holder"):
        revoker = mapping.get(delegator_id)
        if revoker is None or revoker.delegator_id != delegator_id:
            continue
        found.append(delegator_id)
    if found == ["authority"]:
        return _record("f379-antisubstitution-holds", "HELD",
                       "mismatched revoker ignored; mapping wins")
    return _record("f379-antisubstitution-holds", "BREAK",
                   "anti-substitution failed: %r" % (found,))


# ---------------------------------------------------------------------------
# Regression probes: authority_lifecycle heartbeat edges hold
# ---------------------------------------------------------------------------

def _lc_fx():
    """Build a lease manager with one live lease; return
    (mgr, lease_id, seeds, ids)."""
    from gov import authority_lifecycle as al
    from gov import ed25519
    g_seed, s_seed, m_seed = _seed("g"), _seed("s"), _seed("m")
    g_id, s_id, m_id = "granter", "subject", "monitor"
    mgr = al.AuthorityLeaseManager()
    scope = "ab" * 32
    lease = mgr.issue_lease(
        granter_id=g_id, granter_seed=g_seed, subject_id=s_id,
        subject_pubkey_hex=ed25519.publickey(s_seed).hex(),
        scope_digest=scope, issued_at=AT, ttl_seconds=1000,
        heartbeat_interval_seconds=100,
        monitor_id=m_id,
        monitor_pubkey_hex=ed25519.publickey(m_seed).hex())
    return (mgr, lease["lease_id"], scope,
            {"g": (g_id, g_seed), "s": (s_id, s_seed), "m": (m_id, m_seed)})


def p_lc_counter_replay_refuses():
    # Heartbeat counter replay: a proof with a non-advancing counter
    # must refuse coded authority-lifecycle-heartbeat-lapsed.
    from gov import authority_lifecycle as al
    mgr, lid, scope, ids = _lc_fx()
    s_id, s_seed = ids["s"]
    p1 = al.make_proof(lease_id=lid, subject_id=s_id, scope_digest=scope,
                       counter=1, proof_issued_at=AT + 10, signer_id=s_id,
                       signer_seed=s_seed)
    mgr.heartbeat(lid, p1, at=AT + 10)
    p2 = al.make_proof(lease_id=lid, subject_id=s_id, scope_digest=scope,
                       counter=1, proof_issued_at=AT + 20, signer_id=s_id,
                       signer_seed=s_seed)
    try:
        mgr.heartbeat(lid, p2, at=AT + 20)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "authority-lifecycle-heartbeat-lapsed":
            return _record("lc-counter-replay-refuses", "HELD",
                           "replayed counter refused coded")
        return _record("lc-counter-replay-refuses", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("lc-counter-replay-refuses", "BREAK",
                   "heartbeat counter replay accepted")


def p_lc_cross_lease_proof_refuses():
    # A proof bound to a different lease must refuse.
    from gov import authority_lifecycle as al
    from gov import ed25519
    mgr, lid, scope, ids = _lc_fx()
    s_id, s_seed = ids["s"]
    g_id, g_seed = ids["g"]
    other = mgr.issue_lease(
        granter_id=g_id, granter_seed=g_seed, subject_id="subject2",
        subject_pubkey_hex=ed25519.publickey(_seed("s2")).hex(),
        scope_digest=scope, issued_at=AT, ttl_seconds=1000,
        heartbeat_interval_seconds=100)
    foreign = al.make_proof(lease_id=other["lease_id"], subject_id=s_id,
                            scope_digest=scope, counter=1,
                            proof_issued_at=AT + 10, signer_id=s_id,
                            signer_seed=s_seed)
    try:
        mgr.heartbeat(lid, foreign, at=AT + 10)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "authority-lifecycle-heartbeat-lapsed":
            return _record("lc-cross-lease-proof-refuses", "HELD",
                           "cross-lease proof refused coded")
        return _record("lc-cross-lease-proof-refuses", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("lc-cross-lease-proof-refuses", "BREAK",
                   "cross-lease proof accepted")


def p_lc_suspend_parks_ttl():
    # Suspension parks, never extends: resume after ttl must refuse
    # coded authority-lifecycle-expired.
    from gov import authority_lifecycle as al
    mgr, lid, scope, ids = _lc_fx()
    g_id, g_seed = ids["g"]
    sa = al.make_authorization(action=al.ACT_SUSPEND, lease_id=lid,
                               actor_id=g_id, actor_seed=g_seed, at=AT + 50)
    mgr.suspend(lid, authorization=sa, at=AT + 50)
    ra = al.make_authorization(action=al.ACT_RESUME, lease_id=lid,
                               actor_id=g_id, actor_seed=g_seed,
                               at=AT + 1200)
    s_id, s_seed = ids["s"]
    proof = al.make_proof(lease_id=lid, subject_id=s_id, scope_digest=scope,
                          counter=1, proof_issued_at=AT + 1190,
                          signer_id=s_id, signer_seed=s_seed)
    try:
        mgr.resume(lid, authorization=ra, proof=proof, at=AT + 1200)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "authority-lifecycle-expired":
            return _record("lc-suspend-parks-ttl", "HELD",
                           "post-ttl resume refused coded expired")
        return _record("lc-suspend-parks-ttl", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("lc-suspend-parks-ttl", "BREAK",
                   "suspension extended ttl")


def p_lc_forged_operator_authz_refuses():
    # A suspend authorization signed by a non-owner must refuse coded.
    from gov import authority_lifecycle as al
    mgr, lid, scope, ids = _lc_fx()
    evil_seed = _seed("evil")
    forged = al.make_authorization(action=al.ACT_SUSPEND, lease_id=lid,
                                   actor_id="mallory", actor_seed=evil_seed,
                                   at=AT + 50)
    try:
        mgr.suspend(lid, authorization=forged, at=AT + 50)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "authority-lifecycle-heartbeat-lapsed":
            # Lease must still be usable afterwards.
            if mgr.state_of(lid, at=AT + 50) == "ACTIVE":
                return _record("lc-forged-operator-authz-refuses", "HELD",
                               "forged operator authz refused coded; lease "
                               "untouched")
            return _record("lc-forged-operator-authz-refuses", "ERROR",
                           "lease state corrupted by refused suspend")
        return _record("lc-forged-operator-authz-refuses", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("lc-forged-operator-authz-refuses", "BREAK",
                   "forged operator authorization accepted")


# ---------------------------------------------------------------------------
# Depth-1 green check (wave-173 lesson): adjacent batteries' mains run with
# GOV_SKIP_GREEN=1; this battery's own green check honors the var.
# ---------------------------------------------------------------------------

def _green(pid, battery, expect_break_ids=()):
    """Depth-1 green check honoring GOV_SKIP_GREEN=1; this battery's own
    green check honors the var. Wave-305: delegates to
    evals/green_check.py -- a broken dependency battery fails the check
    loudly (ERROR), never "0 BREAKs"."""
    green_check.check_battery(_record, pid, os.path.join("evals", battery),
                              repo=REPO, expect_break_ids=expect_break_ids)


# The w303 closure batteries' footer-state probes are re-pinned to this
# lane's footer (open F385,F386,F387 / next F388; standard footer
# cascade) -- they should be HELD.
W303_FOOTER_BREAK = ()

# On the wave-303 tree, the w303 red-team battery's expected-open
# BREAKs are F385, F386, and the F381 amplification (its footer-state
# is re-pinned to this lane's footer).
# Wave-304 merge: F385, F386 closed (lanes A/B); F381amp closed as F388
# (lane C). The w303 red-team battery has 0 BREAKs on the merged tree.
W303_REDTEAM_BREAKS = ()


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F385-resume-xid-unenforced", p_f385_resume_xid_unenforced)
    _safe("F386-verifier-collision", p_f386_verifier_collision)
    _safe("F381amp-composed-foreign-replay", p_f381amp_composed_foreign_replay)
    _safe("F383amp-gated-key-reuse", p_f383amp_gated_key_reuse)
    _safe("F387-recv-event-drift", p_f387_recv_event_drift)
    _safe("F387-sleep-wakeat-drift", p_f387_sleep_wakeat_drift)
    _safe("F380-ledger-required-replay", p_f380_ledger_required_replay)
    _safe("F381-caller-binding-complete", p_f381_caller_binding_complete)
    _safe("F382-journal-fixed-point", p_f382_journal_fixed_point)
    _safe("f379-antisubstitution-holds", p_f379_antisubstitution_holds)
    _safe("lc-counter-replay-refuses", p_lc_counter_replay_refuses)
    _safe("lc-cross-lease-proof-refuses", p_lc_cross_lease_proof_refuses)
    _safe("lc-suspend-parks-ttl", p_lc_suspend_parks_ttl)
    _safe("lc-forged-operator-authz-refuses", p_lc_forged_operator_authz_refuses)
    _safe("green-w303-f380",
           lambda: _green("green-w303-f380", "w303_f380_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-f381",
           lambda: _green("green-w303-f381", "w303_f381_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-f382f383",
           lambda: _green("green-w303-f382f383", "w303_f382f383_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-f384",
           lambda: _green("green-w303-f384", "w303_f384_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-lifecycle",
           lambda: _green("green-w303-lifecycle",
                          "w303_authority_lifecycle_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-redteam",
           lambda: _green("green-w303-redteam", "w303_redteam_probes.py",
                          W303_REDTEAM_BREAKS))

    nb = sum(1 for _, v, _ in _results if v == "BREAK")
    nh = sum(1 for _, v, _ in _results if v == "HELD")
    ne = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w304_redteam: %d BREAK / %d HELD / %d ERROR" % (nb, nh, ne))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nb, nh, ne)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    return 1 if (nb or ne) else 0


if __name__ == "__main__":
    sys.exit(main())
