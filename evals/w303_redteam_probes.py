"""Wave-303 lane 7 battery: independent red team vs the wave-302 output.

Base: wave-302 merge c18ed4c7b4025d1949b2042aa1ff202e856d6b6f
(F379 closed via per-delegator revokers; pin 1820; footer open
F380-F384 / next free F385).

Targets (all verified empirically with throwaway scripts BEFORE this
battery was written -- diagnosing-bugs loop):
 1. Cross-module confusion between gov/workflow_composed.py,
    gov/workflow_branch.py, gov/workflow_approval.py, gov/workflow.py.
 2. Authority re-verification bypass (gated _gated_step key, composer
    compensation re-proof, branch suspend/resume).
 3. F379's per-delegator revoker model (legacy-shape downgrade?).
 4. F380-F384 as expected-open controls (covered by
    evals/w302_redteam_probes.py -- referenced, not duplicated).

New findings filed from F385:
  F385 (LOW, OPEN) -- gov/workflow_branch.py resume_lease never
    verifies the suspension's XID against the coordinator's live
    transactions: the documented XID binding is decorative. A
    suspension record resumes under another transaction's XID, or a
    never-begun well-formed XID.
  F386 (LOW, OPEN) -- gov/workflow_composed.py installs saga authority
    verifiers into the shared process-global SagaManager under
    plan-scoped refs bound to per-composer-instance mutable context,
    and never removes them. A second composer sharing the manager
    overwrites the first's verifier: the first composer's in-flight
    saga then re-proves the SECOND composer's authority (verified:
    a revoked authority becomes invisible) or, deterministically via
    public API, fails closed into escalation
    (workflow-saga-compensation-unauthorized).

Falsified (HELD regression probes):
  - legacy {"revoker"} + {"revokers"} both present: the mapping wins,
    no downgrade to root-only checking.
  - F379 closure holds on this tree (intermediate revocation fences).

Same-root-cause amplifications (BREAK, annotated to their findings --
NOT new findings):
  - F381 -> composed _resolve_replay trusts a poisoned (digest, ref)
    pair: a fabricated record makes a composed unit return a foreign
    run's checkpoint outputs without executing.
  - F383 -> approval-gated steps sharing one idempotency key: the
    second step's fully valid approval does not stop the key path
    from replaying the first step's outputs.

Run:
  mkdir -p /var/tmp/g303-rt2 && TMPDIR=/var/tmp/g303-rt2 \
    ~/workspace/.gov-venv/bin/python evals/w303_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g303-rt3 \
    ~/workspace/.gov-venv/bin/python evals/w303_redteam_probes.py
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

TAXONOMY_PIN = 1857  # Wave-302 merge pin (1812 + 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

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
    _record("pin-taxonomy", "HELD", "1857/1857/0 sorted")


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
    want_open = "F397"  # wave-304 lane A: F385 CLOSED
    if nxt != 398 or open_s != want_open:
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d open %r (want next F398 open %r)"
                       % (nxt, open_s, want_open))
    _record("footer-state", "HELD",
            "footer pins open F397 / next F398")


AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w303rt-" + tag).encode()).digest()


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
    # Wave-303 merge re-pin (F380 closure): the workflow store requires
    # a revocation ledger on every authority verification (fail closed
    # when absent). Mint a fresh (empty) revoker when none is passed.
    if ledger is None:
        from gov import delegation_revocation as rv
        ledger = rv.DelegationRevoker(_seed("a"), "agent-a")
    return {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": chain, "trust_roots": trust_roots,
            "revocation_ledger": ledger}


def p_f385_resume_xid_unenforced():
    # F385: resume_lease never resolves the suspension's XID against
    # live transactions -- the documented XID binding is decorative.
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
    tampered = dict(susp); tampered["xid"] = xid_b
    try:
        if c.resume_lease(tampered, lm, checked_at=1090) is True:
            breaks.append("another-live-txn-xid")
    except Exception:
        pass
    tampered2 = dict(susp); tampered2["xid"] = "ab" * 32  # never begun
    try:
        if c.resume_lease(tampered2, lm, checked_at=1090) is True:
            breaks.append("never-begun-xid")
    except Exception:
        pass
    if breaks:
        return _record("F385-resume-xid-unenforced", "BREAK",
                       "resume_lease accepted suspension under %s "
                       "(XID binding unenforced)" % ("/".join(breaks),))
    _record("F385-resume-xid-unenforced", "HELD",
            "resume_lease binds the suspension XID to a live transaction")


def p_f386_verifier_collision():
    # F386: two composers sharing one SagaManager, same plan ->
    # plan-scoped verifier ref collides; the second install overwrites
    # the first's, and the first composer's in-flight saga fails its
    # compensation authority check -> escalation. Deterministic via
    # public API only (reentrant execute from inside a compensation).
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    import gov.workflow_composed as wc
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()  # shared
    c1 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    c2 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    run1 = ws.start_run("probe", run_id="col-r1", authority=auth, at=AT)
    run2 = ws.start_run("probe", run_id="col-r2", authority=auth, at=AT)

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

    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1"),
                    saga.SagaStepDef("s2", "a2", {}, "c2"),
                    saga.SagaStepDef("s3", "a3", {}, "c3")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": ok, "s3": boom},
         "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
         "idem_key": "ck"}])
    try:
        res = c1.execute(plan, run_id="col-r1", authority=auth, at=AT)
        return _record("F386-verifier-collision", "HELD",
                       "no collision effect: status %r"
                       % (res["units"]["sg"]["status"],))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "workflow-saga-compensation-unauthorized":
            return _record(
                "F386-verifier-collision", "BREAK",
                "shared-manager verifier overwrite: c1's in-flight saga "
                "escalated coded %r after c2's same-plan install" % (code,))
        return _record("F386-verifier-collision", "ERROR",
                       "unexpected code %r (%r)" % (code, e))


def p_f386_control_no_collision():
    # Control: the same reentrant shape with a DIFFERENT plan on the
    # second composer (different digest -> different ref) compensates
    # normally -- the collision is specifically the shared ref.
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    import gov.workflow_composed as wc
    sa, sb, pa, pb, chain, trust_roots = _chain_fx()
    auth = _authority(chain, trust_roots)
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    c1 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    c2 = wc.WorkflowComposer(ws, sm, idem.IdempotencyStore())
    ws.start_run("probe", run_id="ctl-r1", authority=auth, at=AT)
    ws.start_run("probe", run_id="ctl-r2", authority=auth, at=AT)

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
            plan_other = wc.ComposedPlan([
                {"kind": "saga", "name": "other", "definition": sd,
                 "action_fns": {"s1": ok, "s2": ok, "s3": boom},
                 "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
                 "idem_key": "ck2"}])
            c2.execute(plan_other, run_id="ctl-r2", authority=auth, at=AT)
        return {"u": 2}

    sd = sm.define([saga.SagaStepDef("s1", "a1", {}, "c1"),
                    saga.SagaStepDef("s2", "a2", {}, "c2"),
                    saga.SagaStepDef("s3", "a3", {}, "c3")])
    plan = wc.ComposedPlan([
        {"kind": "saga", "name": "sg", "definition": sd,
         "action_fns": {"s1": ok, "s2": ok, "s3": boom},
         "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
         "idem_key": "ck"}])
    try:
        res = c1.execute(plan, run_id="ctl-r1", authority=auth, at=AT)
    except Exception as e:  # noqa: BLE001
        return _record("F386-control-no-collision", "BREAK",
                       "control escalated unexpectedly: %r"
                       % (getattr(e, "code", None),))
    if res["units"]["sg"]["status"] == "compensated":
        return _record("F386-control-no-collision", "HELD",
                       "different plan -> different ref -> compensated")
    return _record("F386-control-no-collision", "BREAK",
                   "unexpected status %r" % (res["units"]["sg"]["status"],))


def p_f381amp_composed_foreign_replay():
    # F388 (MEDIUM, CLOSED by wave-304 lane C): regression pin. A
    # poisoned idempotency record's (digest, ref) pair was trusted by
    # WorkflowComposer._resolve_replay -- the composed unit returned a
    # FOREIGN run's checkpoint outputs without executing. Post-fix:
    # refuses coded workflow-composed-replay-foreign.
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
            "F381 root cause: poisoned record made the composer return "
            "a foreign run's outputs without executing")
    _record("F381amp-composed-foreign-replay", "HELD",
            "foreign ref refused (F388 closed)")


def p_f383amp_gated_key_reuse():
    # Same root cause as F383 (OPEN): the step-level idempotency-key
    # path replays recorded outputs for different name/inputs without
    # drift checks. Two gated steps with fully valid per-step approvals
    # sharing one idempotency key: the second returns the first's
    # outputs without executing. Annotated to F383, not a new finding.
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
    # Wave-303 merge: F383's closure (lane 3) makes the key path refuse
    # coded workflow-step-unauthorized on name/inputs drift instead of
    # replaying step0's outputs -- the amplification is closed.
    try:
        o2 = r.run_gated_step("run1", 1, "step1",
                              lambda i: calls.append(1) or {"y": i["x"] * 2},
                              {"x": 100}, approval_package=p2, authority=auth,
                              at=AT + 5, idempotency_key="K")
    except Exception as e:
        if getattr(e, "code", "") == "workflow-step-unauthorized":
            return _record("F383amp-gated-key-reuse", "HELD",
                           "key path refused drift coded "
                           "workflow-step-unauthorized (F383 closed)")
        raise
    if o2["outputs"] == {"y": 2} and not calls:
        return _record(
            "F383amp-gated-key-reuse", "BREAK",
            "F383 root cause: valid approval for step1, yet step0's "
            "outputs replayed without executing step1")
    _record("F383amp-gated-key-reuse", "HELD",
            "key path applied drift checks")


def p_f379_both_shapes_mapping_wins():
    # Falsified: a delegation_context carrying BOTH the legacy
    # {"revoker"} and the new {"revokers"} mapping on a multi-hop
    # chain where the intermediate revoked the bound leaf -- the
    # mapping wins (fences); no downgrade to root-only checking.
    from gov import coordination_lease as cl
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
    mgr = cl.LeaseManager()
    binding = {"receipt_id": child["receipt_id"],
               "revocation_list_digest": ra.list_digest()}
    lease = mgr.acquire("u-multi", 3600, "sub", authority_seed=sea,
                        issued_at=AT, delegation_binding=binding)
    both = {"revoker": ra,
            "revokers": {"authority": ra, "holder": rb},
            "chain": [root, child], "trust_roots": [pea]}
    try:
        mgr.check_write("u-multi", lease["fencing_token"], "sub",
                        checked_at=AT + 10, delegation_context=both)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "coord-lease-fencing":
            return _record("f379-both-shapes-mapping-wins", "HELD",
                           "mapping wins over legacy: intermediate "
                           "revocation fences")
        return _record("f379-both-shapes-mapping-wins", "BREAK",
                       "wrong code %r" % (getattr(e, "code", None),))
    return _record("f379-both-shapes-mapping-wins", "BREAK",
                   "legacy shape downgraded the check: write passed")


def p_f379_closure_holds():
    # Control: F379 stays closed on this tree -- intermediate
    # revocation of the bound leaf fences under the mapping shape.
    from gov import coordination_lease as cl
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
    mgr = cl.LeaseManager()
    binding = {"receipt_id": child["receipt_id"],
               "revocation_list_digest": ra.list_digest()}
    lease = mgr.acquire("u-multi2", 3600, "sub", authority_seed=sea,
                        issued_at=AT, delegation_binding=binding)
    ctx = {"revokers": {"authority": ra, "holder": rb},
           "chain": [root, child], "trust_roots": [pea]}
    try:
        mgr.check_write("u-multi2", lease["fencing_token"], "sub",
                        checked_at=AT + 10, delegation_context=ctx)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "coord-lease-fencing":
            return _record("f379-closure-holds", "HELD",
                           "intermediate revocation still fences")
        return _record("f379-closure-holds", "BREAK",
                       "wrong code %r" % (getattr(e, "code", None),))
    return _record("f379-closure-holds", "BREAK",
                   "F379 regressed: revoked write passed")


def _green(pid, battery, expect_break_ids=()):
    """Depth-1 green check: run an adjacent battery's main with
    GOV_SKIP_GREEN=1 and record its verdict line. expect_break_ids is
    the set of probe ids allowed to BREAK (expected-open findings).
    Wave-305: delegates to evals/green_check.py -- a broken dependency
    battery fails the check loudly (ERROR), never "0 BREAKs"."""
    green_check.check_battery(_record, pid, os.path.join("evals", battery),
                              repo=REPO, expect_break_ids=expect_break_ids)


W302_F38X_BREAKS = (
    "F380-revoked-no-ledger-executes",
    "F380-replay-no-authority-check",
    "F380-replay-cross-actor",
    "F381-cross-caller-checkpoint",
    "F381-cross-caller-complete-poisons",
    "F381-evict-unauthenticated",
    "F382-reload-doubles-journal",
    "F383-key-path-skips-drift",
    "F384-escalation-terminal",
    # Test maintenance (not a product break): the w302 battery's own
    # depth-1 green check hardcodes w301_redteam's old
    # "3 BREAK / 35 HELD" line; F379's closure moved it to
    # "0 BREAK / 38 HELD". Merge coordinator to re-pin.
    "green-w301-redteam",
    # Standard footer-cascade signature: this lane's F385/F386 filing
    # moved the footer the w302 battery pins. Merge coordinator
    # re-pins to the merged footer as usual.
    "footer-state",
)


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("footer-state", p_footer_state)
    _safe("F385-resume-xid-unenforced", p_f385_resume_xid_unenforced)
    _safe("F386-verifier-collision", p_f386_verifier_collision)
    _safe("F386-control-no-collision", p_f386_control_no_collision)
    _safe("F381amp-composed-foreign-replay", p_f381amp_composed_foreign_replay)
    _safe("F383amp-gated-key-reuse", p_f383amp_gated_key_reuse)
    _safe("f379-both-shapes-mapping-wins", p_f379_both_shapes_mapping_wins)
    _safe("f379-closure-holds", p_f379_closure_holds)
    _safe("green-w302-redteam",
           lambda: _green("green-w302-redteam", "w302_redteam_probes.py",
                          W302_F38X_BREAKS))
    _safe("green-w302-branch",
           lambda: _green("green-w302-branch", "w302_branch_probes.py"))
    _safe("green-w302-composed",
           lambda: _green("green-w302-composed",
                          "w302_workflow_composed_probes.py"))
    _safe("green-w302-approval",
           lambda: _green("green-w302-approval",
                          "w302_workflow_approval_probes.py"))

    nb = sum(1 for _, v, _ in _results if v == "BREAK")
    nh = sum(1 for _, v, _ in _results if v == "HELD")
    ne = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w303_redteam: %d BREAK / %d HELD / %d ERROR" % (nb, nh, ne))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nb, nh, ne)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    return 1 if (nb or ne) else 0


if __name__ == "__main__":
    sys.exit(main())
