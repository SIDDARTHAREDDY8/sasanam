"""Wave-305 lane E battery: independent red team vs the wave-304 tree.

Base: wave-304 merge 26844345 (F385/F386/F388 closed; heartbeat
scheduling refinement landed; F387 filed OPEN; pin 1827; footer open
F387 / next F389).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. The F385/F386/F388 closures at their close-when boundaries
    (regression probes: XID resolution variants incl. commit/rollback/
    re-park/fabricated; verifier nonce scoping incl. post-unit removal;
    _resolve_replay foreign-pair refusal incl. record_caller binding,
    detached context, and the outbox path).
 2. gov/workflow_branch.py suspend_lease authority gap (NEW finding).
 3. gov/authority_lifecycle.py with the derived schedule (fraction/floor
    arithmetic edges: ttl near floor, fraction extremes, explicit
    override, exact-due heartbeat boundary, schedule journaling).
 4. gov/workflow.py recv_step/sleep_step completed paths (F387, still
    OPEN on base -- expected-open controls).
 5. F380-F384 closure regressions under the new composed/branch changes.
 6. Approval-gated idempotency keys (F383 amplification control).
 7. F379 per-delegator revoker anti-substitution (control).

New finding filed from F389:
  F389 (LOW, OPEN) -- gov/workflow_branch.py::suspend_lease performs no
    authority check: anyone who knows the xid can re-park a different
    suspension record, overwriting the legitimate one. The legitimate
    holder's subsequent resume_lease then refuses
    workflow-branch-xid-mismatch (the F385 exact-parked-record match
    makes the clobbering stick). The attacker cannot complete the
    resume themselves (lease_manager.check_write still gates on the
    fencing token), so this is availability-only and recoverable by
    re-suspending -- but a mutating operation on another party's
    transaction with zero authorization is a genuine API-shape miss.
    XIDs are documented as random ids for uniqueness, not as secret
    bearer capabilities.

Falsified (HELD -- not findings):
  - Lane C's residual: _drain_outbox_composed returns the idem
    result_ref raw on replay without _resolve_replay. The saga's
    drain_outbox discards the dispatcher's return value (counts only),
    and the outbox op class never passes through _resolve_replay, so a
    poisoned outbox record is inert at the public API.
  - Expiry-boundary observation: check() honors a lease at exactly
    at == issued_at + ttl_seconds (strict >). One-instant inclusive
    boundary; a definitional choice, not filed.
  - Same-run-different-step _resolve_replay variant: a poisoned pair
    naming a different completed step of the SAME run (same caller)
    passes the F388 checks. Reaching it through the public execute()
    API requires a concurrent plant race inside a single synchronous
    execute() call (run_ids are fresh per execute); documented as a
    residual, not filed.

Run:
  mkdir -p /var/tmp/g305-rt && TMPDIR=/var/tmp/g305-rt \
    ~/workspace/.gov-venv/bin/python evals/w305_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g305-rt2 \
    ~/workspace/.gov-venv/bin/python evals/w305_redteam_probes.py
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

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-304 merge pin 1827; this lane mints no codes (red team only), so
# the pin stays 1827. The merge-time sweep repoints to the wave-305 pin.
TAXONOMY_PIN = 1827

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
    _record("pin-taxonomy", "HELD", "1827/1827/0 sorted")


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
    # wave-306 merge: F389/F390 CLOSED; footer open none / next F391
    if nxt != 391 or open_s != "none":
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F391 open "
                       "'none')" % (nxt, open_s))
    _record("footer-state", "HELD",
            "footer open none / next F391")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w305rt-" + tag).encode()).digest()


def _chain_fx():
    from gov import delegation as dg
    from gov import ed25519
    sa, sb = _seed("a"), _seed("b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-b", "agent-b", pb, ("tool.invoke",),
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


def _lc_fx(ttl=1000, heartbeat_interval_seconds=100, **kw):
    """Build a lease manager with one live lease; return
    (mgr, lease_id, scope, ids). Pass heartbeat_interval_seconds=None
    for the derived schedule; extra kwargs pass through to issue_lease
    (e.g. heartbeat_fraction, remediation_floor_seconds)."""
    from gov import authority_lifecycle as al
    from gov import ed25519
    g_seed, s_seed, m_seed = _seed("g"), _seed("s"), _seed("m")
    g_id, s_id, m_id = "granter", "subject", "monitor"
    mgr = al.AuthorityLeaseManager()
    scope = "ab" * 32
    lease = mgr.issue_lease(
        granter_id=g_id, granter_seed=g_seed, subject_id=s_id,
        subject_pubkey_hex=ed25519.publickey(s_seed).hex(),
        scope_digest=scope, issued_at=AT, ttl_seconds=ttl,
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        monitor_id=m_id,
        monitor_pubkey_hex=ed25519.publickey(m_seed).hex(),
        **kw)
    return (mgr, lease["lease_id"], scope,
            {"g": (g_id, g_seed), "s": (s_id, s_seed), "m": (m_id, m_seed)})


def _lc_proof(al, lid, scope, s_id, s_seed, counter, at):
    return al.make_proof(lease_id=lid, subject_id=s_id, scope_digest=scope,
                         counter=counter, proof_issued_at=at,
                         signer_id=s_id, signer_seed=s_seed)


# ---------------------------------------------------------------------------
# F385 regression pins (CLOSED by wave-304 lane A) + the new F389 finding
# ---------------------------------------------------------------------------

def _branch_fx():
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import ed25519
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=ed25519.generate_seed(),
                       issued_at=1000)
    c = wb.BranchCoordinator()
    xid_a = c.begin(ed25519.generate_seed())
    return lm, lease["fencing_token"], c, xid_a, ed25519


def _decide(c, xid_a, seed, decision):
    # Drive a transaction to committed/rolled-back via the public
    # decision flow (register -> vote -> decide -> apply).
    c.register_branch(xid_a, "b1", "p1")
    c.vote(xid_a, "b1", decision)
    pkg = c.decide(xid_a, decision, seed)
    c.apply_decision(xid_a, "b1", pkg)


def p_f385_resume_after_commit_refuses():
    # F385 regression: a suspension parked under a transaction that is
    # later committed must refuse resume (transaction no longer open).
    from gov import ed25519
    lm, tok, c, xid_a, _e = _branch_fx()
    # _branch_fx used a throwaway seed; re-begin with a known seed so we
    # can sign the decision.
    seed = ed25519.generate_seed()
    xid = c.begin(seed)
    susp = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                           suspended_at=1050)
    _decide(c, xid, seed, "commit")
    try:
        c.resume_lease(susp, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F385-resume-after-commit-refuses", "HELD",
                       "resume after commit refused: %r"
                       % (getattr(e, "code", None),))
    return _record("F385-resume-after-commit-refuses", "BREAK",
                   "resume succeeded on a committed transaction")


def p_f385_resume_after_rollback_refuses():
    # F385 regression: same for a rolled-back transaction.
    from gov import ed25519
    lm, tok, c, xid_a, _e = _branch_fx()
    seed = ed25519.generate_seed()
    xid = c.begin(seed)
    susp = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                           suspended_at=1050)
    _decide(c, xid, seed, "rollback")
    try:
        c.resume_lease(susp, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F385-resume-after-rollback-refuses", "HELD",
                       "resume after rollback refused: %r"
                       % (getattr(e, "code", None),))
    return _record("F385-resume-after-rollback-refuses", "BREAK",
                   "resume succeeded on a rolled-back transaction")


def p_f385_repark_old_record_refuses():
    # F385 regression: re-parking overwrites the parked record; the old
    # record must then refuse (exact parked-record match).
    lm, tok, c, xid_a, ed25519 = _branch_fx()
    susp_old = c.suspend_lease(xid_a, lm, "scope-x", tok, "holder-1",
                               suspended_at=1050)
    c.suspend_lease(xid_a, lm, "scope-x", tok, "holder-1",
                    suspended_at=1060)
    try:
        c.resume_lease(susp_old, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-branch-xid-mismatch":
            return _record("F385-repark-old-record-refuses", "HELD",
                           "stale parked record refused coded")
        return _record("F385-repark-old-record-refuses", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F385-repark-old-record-refuses", "BREAK",
                   "superseded parked record resumed")


def p_f385_never_parked_fabricated_refuses():
    # F385 regression: a fabricated record for a live transaction with
    # no parked suspension must refuse.
    lm, tok, c, xid_a, ed25519 = _branch_fx()
    fabricated = {"xid": xid_a, "scope": "scope-x",
                  "fencing_token": tok, "holder_id": "holder-1",
                  "suspended_at": 1050,
                  "coordinator_pubkey": "00" * 32}
    try:
        c.resume_lease(fabricated, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        return _record("F385-never-parked-fabricated-refuses", "HELD",
                       "fabricated record refused: %r"
                       % (getattr(e, "code", None),))
    return _record("F385-never-parked-fabricated-refuses", "BREAK",
                   "fabricated suspension record resumed")


def p_f389_suspend_lease_clobber():
    # F389 (LOW, OPEN): suspend_lease performs no authority check. Anyone
    # who knows the xid can re-park a different suspension record,
    # overwriting the legitimate one. The legitimate holder's subsequent
    # resume then refuses workflow-branch-xid-mismatch (the F385 exact
    # parked-record match makes the clobbering stick). The attacker
    # cannot complete the resume themselves (check_write still gates on
    # the fencing token), so this is availability-only, recoverable by
    # re-suspending -- but a mutating operation on another party's
    # transaction with zero authorization is a genuine API-shape miss.
    # XIDs are documented as random ids for uniqueness, not as secret
    # bearer capabilities.
    lm, tok, c, xid_a, ed25519 = _branch_fx()
    susp = c.suspend_lease(xid_a, lm, "scope-x", tok, "holder-1",
                           suspended_at=1050)
    # Attacker: knows xid_a, holds no lease, presents a bogus token.
    # No authority parameter exists on suspend_lease at all.
    try:
        c.suspend_lease(xid_a, lm, "scope-x", 999999, "mallory",
                        suspended_at=1060)
    except Exception:
        return _record("F389-suspend-lease-clobber", "HELD",
                       "unauthenticated re-park refused (F389 closed)")
    # The re-park was accepted: the legitimate holder's resume is now
    # broken.
    try:
        c.resume_lease(susp, lm, checked_at=1090)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-branch-xid-mismatch":
            return _record(
                "F389-suspend-lease-clobber", "BREAK",
                "unauthenticated re-park clobbered the parked suspension; "
                "legitimate resume now refuses "
                "workflow-branch-xid-mismatch (F389)")
        return _record("F389-suspend-lease-clobber", "ERROR",
                       "unexpected refusal after clobber: %r" % (e,))
    return _record("F389-suspend-lease-clobber", "HELD",
                   "legitimate resume unaffected by re-park")


# ---------------------------------------------------------------------------
# F386 regression pins (CLOSED by wave-304 lane B)
# ---------------------------------------------------------------------------

def _composer_fx():
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
    return ws, sm, c1, c2, auth, wc, saga


def p_f386_nonce_scoped_refs():
    # F386 regression: two composers sharing one SagaManager install
    # verifier refs that must differ (per-composer-instance nonce).
    # Both composers execute the same plan cleanly.
    ws, sm, c1, c2, auth, wc, saga = _composer_fx()

    def ok(i):
        return ({"ok": True}, [])

    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok}, "comp_fns": {"s1": ok},
         "idem_key": "ck1"}])
    ws.start_run("probe", run_id="r1", authority=auth, at=AT)
    ws.start_run("probe", run_id="r2", authority=auth, at=AT)
    try:
        r1 = c1.execute(plan, run_id="r1", authority=auth, at=AT)
        r2 = c2.execute(plan, run_id="r2", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F386-nonce-scoped-refs", "ERROR",
                       "execution failed: %r" % (e,))
    if c1._verifier_nonce == c2._verifier_nonce:
        return _record("F386-nonce-scoped-refs", "BREAK",
                       "composer nonces collide")
    st1 = r1["units"]["sg"]["status"]
    st2 = r2["units"]["sg"]["status"]
    if st1 == "succeeded" and st2 == "succeeded":
        return _record("F386-nonce-scoped-refs", "HELD",
                       "nonce-scoped refs; both composers succeed (F386 "
                       "closed)")
    return _record("F386-nonce-scoped-refs", "BREAK",
                   "unexpected statuses %r %r" % (st1, st2))


def p_f386_verifier_removed_after_unit():
    # F386 regression: verifier entries must not outlive the unit.
    # After execute() completes, the shared manager holds no verifier
    # entries for the finished unit (deterministic removal).
    ws, sm, c1, c2, auth, wc, saga = _composer_fx()

    def ok(i):
        return ({"ok": True}, [])

    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok}, "comp_fns": {"s1": ok},
         "idem_key": "ck2"}])
    ws.start_run("probe", run_id="r3", authority=auth, at=AT)
    ws.start_run("probe", run_id="r4", authority=auth, at=AT)
    try:
        c1.execute(plan, run_id="r3", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F386-verifier-removed-after-unit", "ERROR",
                       "execution failed: %r" % (e,))
    leftovers = [r for r in sm._verifiers if c1._verifier_nonce in r]
    if leftovers:
        return _record("F386-verifier-removed-after-unit", "BREAK",
                       "stale verifier entries survive the unit: %r"
                       % (leftovers,))
    # A second composer reusing the same plan must not inherit or
    # collide with the first's (removed) entries.
    try:
        r2 = c2.execute(plan, run_id="r4", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F386-verifier-removed-after-unit", "ERROR",
                       "second execution failed: %r" % (e,))
    if r2["units"]["sg"]["status"] == "succeeded":
        return _record("F386-verifier-removed-after-unit", "HELD",
                       "verifier entries removed deterministically (F386 "
                       "closed)")
    return _record("F386-verifier-removed-after-unit", "BREAK",
                   "second execution status %r"
                   % (r2["units"]["sg"]["status"],))


# ---------------------------------------------------------------------------
# F388 regression pins (CLOSED by wave-304 lane C)
# ---------------------------------------------------------------------------

def _poison_fx():
    """Shared fixture: workflow store with a victim run, idem store,
    composer. Returns (ws, im, comp, auth, victim_digest)."""
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
    return ws, im, comp, auth, victim_digest


def _plant(im, key, digest, ref, caller="agent-b"):
    op_digest = "f" * 64
    im.begin("composed", "composed-unit", key, op_digest, caller=caller,
             authority_verifier=lambda **k: True, at=AT)
    mal = im.begin("composed", "composed-unit", key, op_digest,
                   caller=caller, authority_verifier=lambda **k: True,
                   at=AT)
    if mal.status != "retry":
        return None
    mal.complete(digest, ref, at=AT)
    return im.begin("composed", "composed-unit", key, op_digest,
                    caller=caller, authority_verifier=lambda **k: True,
                    at=AT)


def p_f388_foreign_run_refused():
    # F388 regression: a poisoned (digest, ref) pair naming a foreign
    # run must refuse coded workflow-composed-replay-foreign.
    ws, im, comp, auth, victim_digest = _poison_fx()
    replay = _plant(im, "ak", victim_digest, "wfstep:victim:1")
    if replay is None or replay.status != "replay":
        return _record("F388-foreign-run-refused", "ERROR",
                       "poison did not stick")
    comp._exec_ctx = {"run_id": "other-run", "actor": "agent-b",
                      "plan_digest": "x", "authority": auth,
                      "run": "other-run", "at": AT}
    try:
        comp._resolve_replay(replay, "composed-unit",
                                     "fn:redteam-probe")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-replay-foreign":
            return _record("F388-foreign-run-refused", "HELD",
                           "foreign run refused coded (F388 closed)")
        return _record("F388-foreign-run-refused", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F388-foreign-run-refused", "BREAK",
                   "foreign pair trusted")


def p_f388_record_caller_foreign_refused():
    # F388 regression: a record begun by a different caller than the
    # plan actor must refuse, even when the run matches.
    ws, im, comp, auth, victim_digest = _poison_fx()
    replay = _plant(im, "ak2", victim_digest, "wfstep:victim:1",
                    caller="mallory")
    if replay is None or replay.status != "replay":
        return _record("F388-record-caller-foreign-refused", "ERROR",
                       "poison did not stick")
    if replay.record_caller != "mallory":
        return _record("F388-record-caller-foreign-refused", "ERROR",
                       "record_caller not exposed: %r"
                       % (replay.record_caller,))
    comp._exec_ctx = {"run_id": "victim", "actor": "agent-b",
                      "plan_digest": "x", "authority": auth,
                      "run": "victim", "at": AT}
    try:
        comp._resolve_replay(replay, "composed-unit",
                                     "fn:redteam-probe")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-replay-foreign":
            return _record("F388-record-caller-foreign-refused", "HELD",
                           "foreign caller refused coded (F388 closed)")
        return _record("F388-record-caller-foreign-refused", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F388-record-caller-foreign-refused", "BREAK",
                   "foreign-caller pair trusted")


def p_f388_detached_context_refuses():
    # F388 regression: resolution with no composed execution in progress
    # refuses coded (no run to bind to).
    ws, im, comp, auth, victim_digest = _poison_fx()
    replay = _plant(im, "ak3", victim_digest, "wfstep:victim:1")
    if replay is None or replay.status != "replay":
        return _record("F388-detached-context-refuses", "ERROR",
                       "poison did not stick")
    comp._exec_ctx = None
    try:
        comp._resolve_replay(replay, "composed-unit",
                                     "fn:redteam-probe")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-composed-replay-foreign":
            return _record("F388-detached-context-refuses", "HELD",
                           "detached resolution refused coded (F388 "
                           "closed)")
        return _record("F388-detached-context-refuses", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F388-detached-context-refuses", "BREAK",
                   "detached resolution trusted the pair")


def p_f388_outbox_poison_inert():
    # Lane C's residual, falsified: _drain_outbox_composed returns the
    # idem result_ref raw on replay without _resolve_replay. The saga's
    # drain_outbox discards the dispatcher's return value (counts
    # only), and the outbox op class never passes through
    # _resolve_replay, so a poisoned outbox record is inert at the
    # public API: the composed unit still completes with a dispatch
    # count, and the poisoned ref is trusted nowhere.
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    import gov.workflow_composed as wc
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    im = idem.IdempotencyStore()
    sm = saga.SagaManager()
    comp = wc.WorkflowComposer(ws, sm, im)
    unit_key = "outbox-unit"
    # Plant a poisoned outbox record for the intent the unit will emit.
    # The dispatcher begins (namespace, "composed-outbox",
    # "<unit_key>:<intent_id>") with op_digest = _digest(intent payload).
    # The payload is deterministic: {"intent_id", "payload",
    # "_composed_evidence": {"run_id", "unit", "step_id"}}.
    from gov.workflow_composed import _digest as _cdigest
    payload = {"intent_id": "i1", "payload": {"m": 1},
               "_composed_evidence": {"run_id": "ob-r1", "unit": "sg",
                                      "step_id": "s1"}}
    op_digest = _cdigest(payload)
    okey = "%s:i1" % unit_key
    im.begin("composed", "composed-outbox", okey, op_digest,
             caller="agent-b", authority_verifier=lambda **k: True, at=AT)
    mal = im.begin("composed", "composed-outbox", okey, op_digest,
                   caller="agent-b", authority_verifier=lambda **k: True,
                   at=AT)
    if mal.status != "retry":
        return _record("F388-outbox-poison-inert", "ERROR",
                       "could not plant outbox poison: %s" % (mal.status,))
    mal.complete("0" * 64, "wfstep:evil:9", at=AT)

    def act(i):
        return ({"done": True}, [{"intent_id": "i1", "payload": {"m": 1}}])

    def compf(i):
        return {"undone": True}

    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": act}, "comp_fns": {"s1": compf},
         "idem_key": unit_key}])
    ws.start_run("probe", run_id="ob-r1", authority=auth, at=AT)
    try:
        res = comp.execute(plan, run_id="ob-r1", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F388-outbox-poison-inert", "ERROR",
                       "execution failed: %r" % (e,))
    unit = res["units"]["sg"]
    if unit["status"] == "succeeded" and unit["outbox_dispatched"] == 1:
        return _record("F388-outbox-poison-inert", "HELD",
                       "poisoned outbox record inert: unit succeeded, "
                       "dispatch counted once, ref trusted nowhere")
    return _record("F388-outbox-poison-inert", "BREAK",
                   "outbox poison affected the unit: %r" % (unit,))


# ---------------------------------------------------------------------------
# Lifecycle derived-schedule probes (wave-304 lane D refinement)
# ---------------------------------------------------------------------------

def p_lc_derived_schedule_clamp():
    # ttl below the remediation floor: the derived interval clamps to
    # ttl (the floor must not swallow the ttl; interval <= ttl always).
    from gov import authority_lifecycle as al
    mgr, lid, scope, ids = _lc_fx(ttl=30, heartbeat_interval_seconds=None)
    try:
        v = mgr.check(lid, at=AT + 10)
    except Exception as e:  # noqa: BLE001
        return _record("lc-derived-schedule-clamp", "ERROR",
                       "check failed: %r" % (e,))
    if v["next_heartbeat_due"] == AT + 30:
        return _record("lc-derived-schedule-clamp", "HELD",
                       "derived interval clamped to ttl (30)")
    return _record("lc-derived-schedule-clamp", "BREAK",
                   "derived interval not clamped: next due %r"
                   % (v["next_heartbeat_due"],))


def p_lc_fraction_one():
    # heartbeat_fraction=1.0: derived interval == ttl (re-proof due at
    # expiry; a missed proof can never extend the lease).
    mgr, lid, scope, ids = _lc_fx(ttl=1000, heartbeat_interval_seconds=None,
                                  heartbeat_fraction=1.0,
                                  remediation_floor_seconds=60)
    try:
        v = mgr.check(lid, at=AT + 10)
    except Exception as e:  # noqa: BLE001
        return _record("lc-fraction-one", "ERROR", "check failed: %r" % (e,))
    if v["next_heartbeat_due"] == AT + 1000:
        return _record("lc-fraction-one", "HELD",
                       "fraction=1.0 derives interval == ttl")
    return _record("lc-fraction-one", "BREAK",
                   "fraction=1.0 gave next due %r"
                   % (v["next_heartbeat_due"],))


def p_lc_explicit_override_gt_ttl():
    # Explicit interval above ttl must fail fast (caller bug).
    from gov import authority_lifecycle as al
    from gov import ed25519
    g_seed, s_seed = _seed("g"), _seed("s")
    mgr = al.AuthorityLeaseManager()
    try:
        mgr.issue_lease(
            granter_id="g", granter_seed=g_seed, subject_id="s",
            subject_pubkey_hex=ed25519.publickey(s_seed).hex(),
            scope_digest="ab" * 32, issued_at=AT, ttl_seconds=100,
            heartbeat_interval_seconds=101)
    except ValueError:
        return _record("lc-explicit-override-gt-ttl", "HELD",
                       "explicit interval > ttl fails fast")
    except Exception as e:  # noqa: BLE001
        return _record("lc-explicit-override-gt-ttl", "ERROR",
                       "wrong exception: %r" % (e,))
    return _record("lc-explicit-override-gt-ttl", "BREAK",
                   "explicit interval > ttl accepted")


def p_lc_heartbeat_exact_due():
    # Boundary: a heartbeat at exactly last_heartbeat_at + interval is
    # accepted (lapse is strict >); one instant later suspends.
    from gov import authority_lifecycle as al
    mgr, lid, scope, ids = _lc_fx(ttl=1000, heartbeat_interval_seconds=100)
    s_id, s_seed = ids["s"]
    p1 = _lc_proof(al, lid, scope, s_id, s_seed, 1, AT + 100)
    try:
        mgr.heartbeat(lid, p1, at=AT + 100)
    except Exception as e:  # noqa: BLE001
        return _record("lc-heartbeat-exact-due", "ERROR",
                       "heartbeat at exact due refused: %r" % (e,))
    p2 = _lc_proof(al, lid, scope, s_id, s_seed, 2, AT + 201)
    try:
        mgr.heartbeat(lid, p2, at=AT + 201)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "authority-lifecycle-heartbeat-lapsed":
            return _record("lc-heartbeat-exact-due", "HELD",
                           "exact-due accepted; due+1 lapses coded")
        return _record("lc-heartbeat-exact-due", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("lc-heartbeat-exact-due", "BREAK",
                   "heartbeat past the due instant accepted")


def p_lc_schedule_journaled():
    # The lease-issued journal entry records the schedule parameters
    # (fraction, floor, schedule kind, effective interval) -- the
    # auditor evidence event.
    from gov import authority_lifecycle as al
    mgr, lid, scope, ids = _lc_fx(ttl=1000, heartbeat_interval_seconds=None,
                                  heartbeat_fraction=0.5,
                                  remediation_floor_seconds=60)
    try:
        result = mgr.verify_evidence()
    except Exception as e:  # noqa: BLE001
        return _record("lc-schedule-journaled", "ERROR",
                       "verify_evidence failed: %r" % (e,))
    if not isinstance(result, dict) or result.get("ok") is not True:
        return _record("lc-schedule-journaled", "BREAK",
                       "evidence journal does not verify: %r" % (result,))
    # The issued entry must carry the schedule parameters.
    found = False
    for entry in mgr.journal:
        if entry.get("kind") == "lease-issued" and \
                entry.get("lease_id") == lid:
            f = entry.get("fields", {})
            if f.get("schedule") == "derived" and \
                    f.get("heartbeat_fraction") == 0.5 and \
                    f.get("remediation_floor_seconds") == 60 and \
                    f.get("heartbeat_interval_seconds") == 500:
                found = True
    if found:
        return _record("lc-schedule-journaled", "HELD",
                       "issued entry journals schedule evidence")
    return _record("lc-schedule-journaled", "BREAK",
                   "issued entry missing schedule evidence")


# ---------------------------------------------------------------------------
# F387 expected-open controls (still OPEN on the wave-304 base)
# ---------------------------------------------------------------------------

def p_f387_recv_event_drift():
    # F387 (LOW, OPEN): recv_step's completed path checks the step NAME
    # but not the event subscription. A slot completed for event
    # "settled" replays its payload for a "refunded" subscription.
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
                           "(F387 closed)")
        return _record("F387-recv-event-drift", "ERROR",
                       "wrong refusal: %r" % (e,))
    if rep2 and p2 == {"amount": 100}:
        return _record(
            "F387-recv-event-drift", "BREAK",
            "completed slot replayed the 'settled' payload for a "
            "'refunded' subscription (no inputs-drift refusal; F387)")
    _record("F387-recv-event-drift", "HELD", "no event confusion")


def p_f387_sleep_wakeat_drift():
    # F387, second instance: sleep_step's completed path checks the step
    # NAME but not wake_at. A slot completed with wake_at=T1 returns
    # awake for wake_at=T2.
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r2", authority=auth, at=AT)
    a1, rep1 = ws.sleep_step("r2", 1, "nap", AT + 100,
                             authority=auth, at=AT + 100)
    if not a1 or rep1:
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "setup failed: %r %r" % (a1, rep1))
    try:
        a2, rep2 = ws.sleep_step("r2", 1, "nap", AT + 9999,
                                 authority=auth, at=AT + 100)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F387-sleep-wakeat-drift", "HELD",
                           "completed path refused wake_at drift coded "
                           "(F387 closed)")
        return _record("F387-sleep-wakeat-drift", "ERROR",
                       "wrong refusal: %r" % (e,))
    if rep2 and a2:
        return _record(
            "F387-sleep-wakeat-drift", "BREAK",
            "completed slot accepted wake_at drift (T1 -> T2) without "
            "refusal (F387)")
    _record("F387-sleep-wakeat-drift", "HELD", "no wake_at confusion")


# ---------------------------------------------------------------------------
# Closure regression controls (F380-F384, F379)
# ---------------------------------------------------------------------------

def p_f380_ledger_required_replay():
    # F380 regression: replay without a revocation ledger refuses coded
    # workflow-authority-revoked (the ledger is required on every
    # verification).
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    auth_noledeger = {k: v for k, v in auth.items()
                      if k != "revocation_ledger"}
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.run_step("r1", 1, "s", lambda i: {"ok": 1}, {}, authority=auth,
                at=AT)
    try:
        ws.run_step("r1", 1, "s", lambda i: {"ok": 1}, {},
                    authority=auth_noledeger, at=AT + 1)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-authority-revoked":
            return _record("F380-ledger-required-replay", "HELD",
                           "ledger-less replay refused coded (F380 holds)")
        return _record("F380-ledger-required-replay", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F380-ledger-required-replay", "BREAK",
                   "replay without ledger authorized")


def p_f381_caller_binding():
    # F381 regression: cross-caller complete() refuses coded
    # workflow-idempotency-caller-mismatch.
    from gov import workflow_idempotency as idem
    im = idem.IdempotencyStore()
    op_digest = "f" * 64
    im.begin("ns", "oc", "k1", op_digest, caller="alice",
             authority_verifier=lambda **k: True, at=AT)
    bob = im.begin("ns", "oc", "k1", op_digest, caller="bob",
                   authority_verifier=lambda **k: True, at=AT)
    if bob.status != "retry":
        return _record("F381-caller-binding", "ERROR",
                       "no in-flight record: %s" % (bob.status,))
    try:
        bob.complete("0" * 64, "ref", at=AT)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-idempotency-caller-mismatch":
            return _record("F381-caller-binding", "HELD",
                           "cross-caller complete refused coded (F381 "
                           "holds)")
        return _record("F381-caller-binding", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F381-caller-binding", "BREAK",
                   "cross-caller complete authorized")


def p_f383_gated_key_reuse():
    # F383 amplification regression: two approval-gated steps sharing
    # one idempotency key, each with a valid per-step approval -- the
    # key path must refuse the second step's replay coded
    # workflow-step-unauthorized (lane 3's closure holds).
    from gov import workflow as wf
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    ws.start_run("wf", run_id="r1", authority=auth, at=AT)
    ws.run_step("r1", 1, "step-a", lambda i: {"a": 1}, {"x": 1},
                authority=auth, at=AT, idempotency_key="shared")
    try:
        ws.run_step("r1", 2, "step-b", lambda i: {"b": 2}, {"x": 2},
                    authority=auth, at=AT + 1, idempotency_key="shared")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "workflow-step-unauthorized":
            return _record("F383-gated-key-reuse", "HELD",
                           "shared-key second step refused coded (F383 "
                           "holds)")
        return _record("F383-gated-key-reuse", "ERROR",
                       "wrong refusal: %r" % (e,))
    return _record("F383-gated-key-reuse", "BREAK",
                   "shared idempotency key replayed across steps")


def p_f379_antisubstitution():
    # F379 regression: a revoker for a different delegator is ignored;
    # the per-delegator mapping wins.
    from gov import delegation_revocation as rv
    from gov import ed25519
    revoker = rv.DelegationRevoker(_seed("a"), "agent-a")
    try:
        revoker.revoke("agent-b", _seed("other"), at=AT)
        return _record("F379-antisubstitution", "BREAK",
                       "foreign-delegator revoker accepted")
    except Exception as e:  # noqa: BLE001
        return _record("F379-antisubstitution", "HELD",
                       "mismatched delegator revoker refused: %r"
                       % (getattr(e, "code", None),))


def p_f384_retry_fresh_window():
    # F384 regression: operator recovery on an escalated saga works,
    # is journaled, and double recovery refuses coded. A forged
    # operator verifier refuses coded workflow-saga-operator-
    # unauthorized.
    from gov import workflow_saga as saga
    saga.clear_ops()
    saga.register_op("w305-a", lambda p: ({"ok": 1}, []))

    def bad(p):
        raise RuntimeError("downstream still down")

    saga.register_op("w305-c", bad)
    saga.register_op("w305-f", lambda p: 1 / 0)
    mgr = saga.SagaManager(
        authority_verifiers={"op": lambda: True},
        max_compensation_attempts=1, operator_authority_ref="op")
    d = mgr.define([
        saga.SagaStepDef("s1", "w305-a", {}, "w305-c", {}),
        saga.SagaStepDef("s2", "w305-f", {}, "w305-c", {}),
    ])
    inst = mgr.start(d, saga_id="w305-f384")
    try:
        mgr.run(inst)
    except saga.SagaError:
        pass
    if inst.status != "escalated":
        return _record("F384-retry-fresh-window", "ERROR",
                       "saga did not escalate: %r" % (inst.status,))
    # Forged operator: verifier refuses.
    mgr_bad = saga.SagaManager(
        authority_verifiers={"op": lambda: False},
        max_compensation_attempts=1, operator_authority_ref="op")
    try:
        mgr_bad.retry_compensation(inst)
        return _record("F384-retry-fresh-window", "BREAK",
                       "forged operator recovery authorized")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != \
                "workflow-saga-operator-unauthorized":
            return _record("F384-retry-fresh-window", "ERROR",
                           "wrong refusal: %r" % (e,))
    # Valid operator, downstream fixed: recovery works.
    saga.register_op("w305-c", lambda p: {"fixed": True})
    try:
        mgr.retry_compensation(inst)
    except Exception as e:  # noqa: BLE001
        return _record("F384-retry-fresh-window", "ERROR",
                       "valid recovery failed: %r" % (e,))
    # Double recovery on a non-escalated saga refuses coded.
    try:
        mgr.retry_compensation(inst)
    except Exception as e:  # noqa: BLE001
        return _record("F384-retry-fresh-window", "HELD",
                       "operator recovery works; forged refused; double "
                       "recovery refused coded %r"
                       % (getattr(e, "code", None),))
    return _record("F384-retry-fresh-window", "BREAK",
                   "double recovery authorized")


# ---------------------------------------------------------------------------
# Depth-1 green check, fail-closed form (wave-304 observation): the child
# battery must produce a parseable "N BREAK / M HELD / K ERROR" summary.
# A missing summary or an import-time traceback means the battery never
# ran -- that is a CHECK FAILURE, not 0 BREAKs. Expected BREAKs are
# compared by probe id; unexpected or missing BREAKs fail the check.
# ---------------------------------------------------------------------------

def _green(pid, battery, expect_break_ids=()):
    if SKIP_GREEN:
        _record(pid, "HELD", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmpd = tempfile.mkdtemp(prefix="g305-green-")
    env["TMPDIR"] = tmpd
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "evals", battery)],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=REPO)
        out = proc.stdout + proc.stderr
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "green check crashed: %r" % (e,))
        return
    # Fail-closed: the child must produce a recognizable summary. A
    # missing summary or an import-time traceback means the battery
    # never ran -- that is a CHECK FAILURE, not 0 BREAKs (wave-304
    # w302 header lesson). Two formats are recognized: the probe
    # "N BREAK / M HELD / K ERROR" summary, and unittest "Ran N tests"
    # output.
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", out)
    if m:
        breaks = re.findall(r"\[BREAK\] ([A-Za-z0-9_.\-]+)", out)
        unexpected = [b for b in breaks if b not in expect_break_ids]
        missing = [b for b in expect_break_ids if b not in breaks]
        if unexpected or missing:
            _record(pid, "BREAK",
                    "%s: break mismatch: unexpected %r, missing expected %r"
                    % (battery, unexpected, missing))
        else:
            _record(pid, "HELD",
                    "%s: %d BREAK (all expected) / rest held"
                    % (battery, len(breaks)))
        return
    if re.search(r"Ran \d+ tests?", out):
        # unittest format: fail closed on any failure/error.
        if re.search(r"\nOK(\s|$)", out):
            if expect_break_ids:
                _record(pid, "BREAK",
                        "%s: expected BREAKs %r but unittest battery passed"
                        % (battery, expect_break_ids))
            else:
                _record(pid, "HELD", "%s: unittest OK" % (battery,))
        else:
            _record(pid, "BREAK",
                    "%s: unittest failures/errors" % (battery,))
        return
    _record(pid, "ERROR",
            "%s: no parseable summary -- battery did not run "
            "(import traceback?); stderr tail: %s"
            % (battery, out[-400:]))


# On the wave-304 tree, the w304 red-team battery's expected-open BREAKs
# are the two F387 probes (its footer-state is re-pinned to this lane's
# footer by the standard cascade).
# Wave-305 merge: F387 closed by lane A (recv/sleep completed-path drift
# refusal) — w304_redteam now reports 0 BREAKs on the merged tree.
W304_REDTEAM_BREAKS = ()

# The w303 closure batteries should be fully green on the wave-304 tree.
W303_FOOTER_BREAK = ()


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F387-recv-event-drift", p_f387_recv_event_drift)
    _safe("F387-sleep-wakeat-drift", p_f387_sleep_wakeat_drift)
    _safe("F389-suspend-lease-clobber", p_f389_suspend_lease_clobber)
    _safe("F385-resume-after-commit-refuses",
           p_f385_resume_after_commit_refuses)
    _safe("F385-resume-after-rollback-refuses",
           p_f385_resume_after_rollback_refuses)
    _safe("F385-repark-old-record-refuses", p_f385_repark_old_record_refuses)
    _safe("F385-never-parked-fabricated-refuses",
           p_f385_never_parked_fabricated_refuses)
    _safe("F386-nonce-scoped-refs", p_f386_nonce_scoped_refs)
    _safe("F386-verifier-removed-after-unit",
           p_f386_verifier_removed_after_unit)
    _safe("F388-foreign-run-refused", p_f388_foreign_run_refused)
    _safe("F388-record-caller-foreign-refused",
           p_f388_record_caller_foreign_refused)
    _safe("F388-detached-context-refuses", p_f388_detached_context_refuses)
    _safe("F388-outbox-poison-inert", p_f388_outbox_poison_inert)
    _safe("lc-derived-schedule-clamp", p_lc_derived_schedule_clamp)
    _safe("lc-fraction-one", p_lc_fraction_one)
    _safe("lc-explicit-override-gt-ttl", p_lc_explicit_override_gt_ttl)
    _safe("lc-heartbeat-exact-due", p_lc_heartbeat_exact_due)
    _safe("lc-schedule-journaled", p_lc_schedule_journaled)
    _safe("F380-ledger-required-replay", p_f380_ledger_required_replay)
    _safe("F381-caller-binding", p_f381_caller_binding)
    _safe("F383-gated-key-reuse", p_f383_gated_key_reuse)
    _safe("F379-antisubstitution", p_f379_antisubstitution)
    _safe("F384-retry-fresh-window", p_f384_retry_fresh_window)
    _safe("green-w304-redteam",
           lambda: _green("green-w304-redteam", "w304_redteam_probes.py",
                          W304_REDTEAM_BREAKS))
    _safe("green-w303-f385",
           lambda: _green("green-w303-f385", "w303_f385_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-f386",
           lambda: _green("green-w303-f386", "w303_f386_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-f388",
           lambda: _green("green-w303-f388", "w303_f388_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-heartbeat-schedule",
           lambda: _green("green-w303-heartbeat-schedule",
                          "w303_heartbeat_schedule_probes.py",
                          W303_FOOTER_BREAK))
    _safe("green-w303-authority-lifecycle",
           lambda: _green("green-w303-authority-lifecycle",
                          "w303_authority_lifecycle_probes.py",
                          W303_FOOTER_BREAK))

    nb = sum(1 for _, v, _ in _results if v == "BREAK")
    nh = sum(1 for _, v, _ in _results if v == "HELD")
    ne = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w305_redteam: %d BREAK / %d HELD / %d ERROR" % (nb, nh, ne))
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note.split("\n")[0]))
    return 1 if (nb or ne) else 0


if __name__ == "__main__":
    sys.exit(main())
