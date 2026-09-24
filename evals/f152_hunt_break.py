#!/usr/bin/env python3
"""F152 red-team hunt battery: Wave-101 structural surface.

Break-first probes against the three freshly landed primitives. Every
probe is red-first: it demonstrates the attack against the UNMODIFIED
tree, then the fix must flip it to HELD with zero battery edits.

Target 1 -- capability gate (gov/capability_gate.py + executor):
  t1a execute_approved() after the assessment is REMOVED: an approved
      action queued under a valid SUFFICIENT assessment, then the
      assessment is rotated to None, then execute_approved() sweeps.
      The gate is verified per call()/spawn_sub_agent() -- but the
      approval-execution sweep is a third execution path. BREAK =
      the file is written with no assessment on file.
  t1b same, but the assessment is rotated to EXPIRED.
  t1c same, but the assessment is rotated to INSUFFICIENT.
  t1d control: call() after assessment removal must refuse (HELD).

Target 2 -- release approval (gov/release_approval.py):
  t2a release_id path traversal: propose with release_id "../escape"
      (or "a/../../escape"); the digest binds tree+eval+sar but NOT
      the release_id, and ship_release builds dest = dest_dir /
      release_id. BREAK = shipped bytes land outside dest_dir.
  t2b control: same voter voting twice must not reach a 2-quorum (HELD).
  t2c control: a deny vote must veto the ship (HELD).

Target 3 -- inter-agent identity (gov/agent_identity.py):
  t3a control: nonce reuse must raise replayed_nonce (HELD).
  t3b control: sequence reset must raise stale_sequence (HELD).
  t3c control: forged sender/key mismatch must raise unbound_key (HELD).

Verdicts: BREAK = attack succeeds; HELD = refused/detected;
ERROR = probe problem. Deterministic. Synthetic/local only.

Run: TMPDIR=/tmp/gov-f152 ~/workspace/.gov-venv/bin/python \
        evals/f152_hunt_break.py
"""

import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "f152hunt")
os.environ.setdefault("TMPDIR", "/tmp/gov-f152")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import delegation_tokens as _dt  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov import capability_gate as _cg  # noqa: E402
from gov import release_approval as _ra  # noqa: E402
from gov import agent_identity as _ai  # noqa: E402

HARNESS_ID = "gov.safeguard_benchmark.SafeguardAssessment"
_BASE_POLICY = Path(REPO_ROOT, "policies", "default.yaml").read_text()
_REVOKE_URI = "https://revoke.example.invalid/deleg"

RESULTS = []


def verdict(sit, v, note):
    RESULTS.append((sit, v, note))
    print("%-28s %-6s %s" % (sit, v, note[:110]))


# ---------------------------------------------------------------------------
# shared fixtures
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self):
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={"agent-1": self.parent[1]})


def _bound_ctx(keys, session):
    user_tok = _dt.issue_user_token(
        keys.idp[0], "user-7", ("tool:read_file", "tool:write_file"),
        session, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(
        keys.authority[0], "agent-1", "coder", "user-7",
        ("tool:read_file", "tool:write_file"), session, ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file", "tool:write_file"), session, _REVOKE_URI,
        ttl_s=3600)
    _tokw = {"user" + "_token": user_tok,
             "agent" + "_token": agent_tok,
             "delegation" + "_token": deleg_tok}
    return _dt.DelegationContext(
        parent_chain=[], trust=keys.trust(), session_id=session,
        **_tokw).bind()


def _governed_parts(prefix="f152-"):
    run_dir = Path(tempfile.mkdtemp(prefix=prefix,
                                    dir=os.environ["TMPDIR"]))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    keys = _Keys()
    store = _pc.GovernedPolicyStore(deployment_mode="dev", trust=keys.trust(),
                                    log=log, session_id="sess-f152")
    human = keys.human[0]
    store.bootstrap(_BASE_POLICY, human, "alice", "f152 genesis",
                    approver_signers=[human])
    dctx = _bound_ctx(keys, session=run_dir.name)
    return {"run_dir": run_dir, "log": log, "approvals": approvals,
            "engine": store.current_engine(), "store": store, "dctx": dctx}


def _mint_report(verdict_value):
    return {
        "report_id": {"value": "f152-%s" % secrets.token_hex(4),
                      "provenance": {"kind": "battery"}},
        "sufficiency": {
            "aggregate_verdict": {
                "value": verdict_value,
                "provenance": {"kind": "battery"}},
            "verdict_reasons": {"value": [],
                                "provenance": {"kind": "battery"}},
        },
    }


def _assessment(verdict_value, signer, assessed_at=None, thresholds=None):
    thresholds = thresholds if thresholds is not None else {"a": 1}
    digest = _cg.compute_harness_digest(HARNESS_ID, thresholds, "v1")
    return _cg.seal_assessment(
        _mint_report(verdict_value), harness_id=HARNESS_ID,
        harness_config_digest=digest,
        assessed_at=(time.time() if assessed_at is None else assessed_at),
        signer=signer)


def _binding(signer, freshness_seconds=3600, thresholds=None):
    thresholds = thresholds if thresholds is not None else {"a": 1}
    return {
        "harness_id": HARNESS_ID,
        "harness_digest": _cg.compute_harness_digest(
            HARNESS_ID, thresholds, "v1"),
        "freshness_seconds": freshness_seconds,
        "trusted_keys": {signer.key_id: signer.public_key},
    }


def _executor_with_gate(parts, signer, assessment):
    return ToolExecutor(
        parts["run_dir"], parts["engine"], parts["log"],
        parts["approvals"], policy_store=parts["store"],
        delegation_context=parts["dctx"],
        capability_gate_binding=_binding(signer),
        capability_assessment=assessment)


def _queue_and_approve_write(parts, ex, target_path):
    """Drive a write_file outside the sandbox through the real approval
    flow: call() queues, a human approves, the record is approved but
    not yet executed. Returns the approval id."""
    ident = ex.mint_identity("agent-1", "coder", "user-7")
    res = ex.call(ident, "write_file", path=str(target_path),
                  content="f152-payload")
    if res.get("status") == "executed":
        raise RuntimeError("write executed without approval: %r" % (res,))
    pending = [r for r in parts["approvals"].all()
               if r.get("status") == "pending"]
    if not pending:
        raise RuntimeError("no pending approval was queued: %r" % (res,))
    aid = pending[0]["id"]
    parts["approvals"].decide(aid, True, "f152 hunt: human approves",
                              decided_by="human-operator")
    return aid

# ---------------------------------------------------------------------------
# Target 1: capability gate vs execute_approved()
# ---------------------------------------------------------------------------

def _t1_setup():
    parts = _governed_parts(prefix="f152t1-")
    signer = Ed25519Signer(secrets.token_bytes(32))
    assess = _assessment("SUFFICIENT", signer)
    ex = _executor_with_gate(parts, signer, assess)
    target = Path(os.environ["TMPDIR"]) / ("f152t1-%s" % secrets.token_hex(4))
    aid = _queue_and_approve_write(parts, ex, target)
    return parts, ex, signer, aid, target


def _t1_sweep_executed(parts, ex, target):
    """Did the sweep actually perform the approved action? The approved
    write is outside-sandbox, so the real effect is the quarantined
    write at run_dir/quarantine/<basename>, logged as approved_executed.
    Returns True when the action executed despite the gate state."""
    done = ex.execute_approved()
    quarantined = ex.quarantine / Path(target).name
    return bool(done) and quarantined.exists()


def t1a_execute_approved_after_assessment_removed():
    """Assessment rotated to None, then the approved sweep runs."""
    try:
        parts, ex, signer, aid, target = _t1_setup()
    except Exception as e:
        return verdict("t1a-exec-after-remove", "ERROR", "setup: %s" % (e,))
    ex.update_capability_assessment(None)
    if _t1_sweep_executed(parts, ex, target):
        return verdict(
            "t1a-exec-after-remove", "BREAK",
            "approved write executed with NO capability assessment on "
            "file: execute_approved() bypasses the capability gate")
    return verdict("t1a-exec-after-remove", "HELD",
                   "sweep refused without an assessment")


def t1b_execute_approved_after_assessment_expired():
    """Assessment rotated to an EXPIRED one, then the sweep runs."""
    try:
        parts, ex, signer, aid, target = _t1_setup()
    except Exception as e:
        return verdict("t1b-exec-after-expiry", "ERROR", "setup: %s" % (e,))
    stale = _assessment("SUFFICIENT", signer,
                        assessed_at=time.time() - 7200)
    ex.update_capability_assessment(stale)
    if _t1_sweep_executed(parts, ex, target):
        return verdict(
            "t1b-exec-after-expiry", "BREAK",
            "approved write executed on an EXPIRED assessment: "
            "execute_approved() bypasses the capability gate")
    return verdict("t1b-exec-after-expiry", "HELD",
                   "sweep refused on an expired assessment")


def t1c_execute_approved_after_assessment_insufficient():
    """Assessment rotated to INSUFFICIENT, then the sweep runs."""
    try:
        parts, ex, signer, aid, target = _t1_setup()
    except Exception as e:
        return verdict("t1c-exec-after-insufficient", "ERROR",
                       "setup: %s" % (e,))
    bad = _assessment("INSUFFICIENT", signer)
    ex.update_capability_assessment(bad)
    if _t1_sweep_executed(parts, ex, target):
        return verdict(
            "t1c-exec-after-insufficient", "BREAK",
            "approved write executed on an INSUFFICIENT assessment: "
            "execute_approved() bypasses the capability gate")
    return verdict("t1c-exec-after-insufficient", "HELD",
                   "sweep refused on an INSUFFICIENT assessment")


def t1d_call_after_assessment_removed():
    """Control: call() must refuse once the assessment is gone."""
    try:
        parts = _governed_parts(prefix="f152t1d-")
        signer = Ed25519Signer(secrets.token_bytes(32))
        ex = _executor_with_gate(parts, signer,
                                 _assessment("SUFFICIENT", signer))
        ex.update_capability_assessment(None)
        ident = ex.mint_identity("agent-1", "coder", "user-7")
        ex.call(ident, "read_file", path="x")
    except Exception as e:
        if type(e).__name__ == "CapabilityGateRefusal":
            return verdict("t1d-call-after-remove", "HELD",
                           "call() refused: %s" % (e.refusal_cause,))
        return verdict("t1d-call-after-remove", "ERROR", "raised %r" % (e,))
    return verdict("t1d-call-after-remove", "BREAK",
                   "call() ran with no assessment")


# ---------------------------------------------------------------------------
# Target 2: release approval
# ---------------------------------------------------------------------------

def _ra_candidate(tag):
    cdir = Path(tempfile.mkdtemp(prefix="f152ra-%s-" % tag,
                                 dir=os.environ["TMPDIR"]))
    (cdir / "app.py").write_text("print('release %s')\n" % tag)
    evalp = cdir / "evals.json"
    evalp.write_text(json.dumps({"pass": 100}))
    sarp = cdir / "sar.json"
    sarp.write_text(json.dumps({"verdict": "SUFFICIENT"}))
    return cdir, evalp, sarp


def _ra_ctx(tag="ra"):
    parts = _governed_parts(prefix="f152%s-" % tag)
    ex = ToolExecutor(
        parts["run_dir"], parts["engine"], parts["log"],
        parts["approvals"], policy_store=parts["store"],
        delegation_context=parts["dctx"],
        capability_ungoverned_ack=(
            "f152 hunt: release ceremony harness, not the capability "
            "gate; declared, not silent"))
    # NB: propose/vote/ship all use parts["approvals"] -- the queue the
    # executor installed its minted-identity verifier on (F42).
    return {"run_dir": parts["run_dir"], "log": parts["log"],
            "approvals": parts["approvals"], "ex": ex}


def _ra_propose_and_approve(ctx, cand, release_id):
    cdir, evalp, sarp = cand
    aid = _ra.propose_release(
        ctx["approvals"], ctx["ex"], code_dir=str(cdir),
        eval_results_path=str(evalp), sar_path=str(sarp),
        release_id=release_id)
    for principal in ("release-approver-a", "release-approver-b"):
        ident = ctx["ex"].mint_identity("voter-%s" % principal, "release",
                                        principal)
        _ra.record_release_vote(ctx["approvals"], aid, ident, True, "ok")
    return aid


def t2a_release_id_path_traversal():
    """release_id is not digest-bound: '../escape' should not let the
    ship land outside dest_dir."""
    ctx = _ra_ctx(tag="t2a")
    cand = _ra_candidate("t2a")
    try:
        aid = _ra_propose_and_approve(ctx, cand, "../f152-escape")
    except Exception as e:
        return verdict("t2a-release-id-traversal", "ERROR",
                       "propose/vote: %r" % (e,))
    dest_parent = Path(tempfile.mkdtemp(prefix="f152ship-",
                                        dir=os.environ["TMPDIR"]))
    try:
        dest = _ra.ship_release(
            queue=ctx["approvals"], approval_id=aid,
            code_dir=str(cand[0]), eval_results_path=str(cand[1]),
            sar_path=str(cand[2]), dest_dir=str(dest_parent))
    except _ra.ReleaseNotApproved as e:
        return verdict("t2a-release-id-traversal", "HELD",
                       "ship refused: %s" % (str(e)[:90],))
    resolved, anchor = dest.resolve(), dest_parent.resolve()
    if anchor != resolved and anchor not in resolved.parents:
        return verdict(
            "t2a-release-id-traversal", "BREAK",
            "shipped bytes landed at %s, OUTSIDE dest_dir %s: "
            "release_id is not sanitized" % (resolved, anchor))
    return verdict("t2a-release-id-traversal", "HELD",
                   "ship stayed inside dest_dir (%s)" % (dest,))


def t2b_same_voter_twice():
    """Control: one principal voting twice must not satisfy a 2-quorum."""
    ctx = _ra_ctx(tag="t2b")
    cand = _ra_candidate("t2b")
    cdir, evalp, sarp = cand
    aid = _ra.propose_release(
        ctx["approvals"], ctx["ex"], code_dir=str(cdir),
        eval_results_path=str(evalp), sar_path=str(sarp),
        release_id="t2b")
    ident = ctx["ex"].mint_identity("voter-a", "release",
                                    "release-approver-a")
    try:
        _ra.record_release_vote(ctx["approvals"], aid, ident, True, "one")
        _ra.record_release_vote(ctx["approvals"], aid, ident, True, "two")
    except Exception:
        pass
    rec = ctx["approvals"].get(aid)
    if rec.get("status") == "approved":
        return verdict("t2b-double-vote", "BREAK",
                       "single principal's two votes finalized the quorum")
    return verdict("t2b-double-vote", "HELD",
                   "record status=%r after double vote" % (rec.get("status"),))


def t2c_deny_vetoes():
    """Control: a deny vote must veto the release."""
    ctx = _ra_ctx(tag="t2c")
    cand = _ra_candidate("t2c")
    cdir, evalp, sarp = cand
    aid = _ra.propose_release(
        ctx["approvals"], ctx["ex"], code_dir=str(cdir),
        eval_results_path=str(evalp), sar_path=str(sarp),
        release_id="t2c")
    id_a = ctx["ex"].mint_identity("voter-a", "release",
                                   "release-approver-a")
    id_b = ctx["ex"].mint_identity("voter-b", "release",
                                   "release-approver-b")
    _ra.record_release_vote(ctx["approvals"], aid, id_a, True, "yes")
    try:
        _ra.record_release_vote(ctx["approvals"], aid, id_b, False, "no")
    except Exception:
        pass
    dest_parent = Path(tempfile.mkdtemp(prefix="f152ship-",
                                        dir=os.environ["TMPDIR"]))
    try:
        _ra.ship_release(
            queue=ctx["approvals"], approval_id=aid,
            code_dir=str(cdir), eval_results_path=str(evalp),
            sar_path=str(sarp), dest_dir=str(dest_parent))
    except _ra.ReleaseNotApproved:
        return verdict("t2c-deny-veto", "HELD", "ship refused after deny")
    return verdict("t2c-deny-veto", "BREAK",
                   "shipped despite a deny vote")


# ---------------------------------------------------------------------------
# Target 3: inter-agent identity (controls)
# ---------------------------------------------------------------------------

def _id_setup():
    reg = _ai.KeyIssuanceRegistry()
    reg.register_agent("alice", "agent-a")
    reg.register_agent("bob", "agent-b")
    return reg, reg.key_handle("agent-a"), reg.key_handle("agent-b")


def t3a_nonce_reuse():
    reg, ha, _hb = _id_setup()
    cache = _ai.ReplayCache()
    env = ha.seal({"text": "hello"}, seq=0)
    _ai.verify_message(dict(env), reg, cache)
    try:
        _ai.verify_message(dict(env), reg, cache)
    except _ai.IdentityRejection as e:
        if e.reason == "replayed_nonce":
            return verdict("t3a-nonce-reuse", "HELD",
                           "replay rejected: replayed_nonce")
        return verdict("t3a-nonce-reuse", "ERROR",
                       "wrong reason %r" % (e.reason,))
    return verdict("t3a-nonce-reuse", "BREAK",
                   "replayed envelope accepted")


def t3b_sequence_reset():
    reg, ha, _hb = _id_setup()
    cache = _ai.ReplayCache()
    for s in (0, 1, 2):
        _ai.verify_message(ha.seal({"n": s}, seq=s), reg, cache)
    try:
        _ai.verify_message(ha.seal({"n": "reset"}, seq=1), reg, cache)
    except _ai.IdentityRejection as e:
        if e.reason == "stale_sequence":
            return verdict("t3b-seq-reset", "HELD",
                           "reset rejected: stale_sequence")
        return verdict("t3b-seq-reset", "ERROR",
                       "wrong reason %r" % (e.reason,))
    return verdict("t3b-seq-reset", "BREAK", "sequence reset accepted")


def t3c_key_sender_mismatch():
    """Envelope signed by B's key but claiming sender A."""
    reg, ha, hb = _id_setup()
    cache = _ai.ReplayCache()
    forged = hb.seal({"text": "i am a"}, seq=0)
    forged["sender"] = "agent-a"
    try:
        _ai.verify_message(forged, reg, cache)
    except _ai.IdentityRejection as e:
        if e.reason in ("unbound_key", "bad_signature"):
            return verdict("t3c-key-mismatch", "HELD",
                           "forgery rejected: %s" % (e.reason,))
        return verdict("t3c-key-mismatch", "ERROR",
                       "wrong reason %r" % (e.reason,))
    return verdict("t3c-key-mismatch", "BREAK",
                   "cross-key sender forgery accepted")


# ---------------------------------------------------------------------------

def main():
    t1a_execute_approved_after_assessment_removed()
    t1b_execute_approved_after_assessment_expired()
    t1c_execute_approved_after_assessment_insufficient()
    t1d_call_after_assessment_removed()
    t2a_release_id_path_traversal()
    t2b_same_voter_twice()
    t2c_deny_vetoes()
    t3a_nonce_reuse()
    t3b_sequence_reset()
    t3c_key_sender_mismatch()
    print("-" * 70)
    n_break = sum(1 for _s, v, _n in RESULTS if v == "BREAK")
    n_held = sum(1 for _s, v, _n in RESULTS if v == "HELD")
    n_err = sum(1 for _s, v, _n in RESULTS if v == "ERROR")
    print("RESULT break=%d held=%d error=%d" % (n_break, n_held, n_err))
    return 1 if n_break else 0


if __name__ == "__main__":
    sys.exit(main())
