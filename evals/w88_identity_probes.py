"""Wave-88 Lane B: identity-track seam probes (break-first).

Question: can a string-tuple identity reach any authorization decision the
three-token gate would refuse? Can a legacy grant (no three-token issuance)
pass the executor gate?

Tracks under test:
  (a) the unsigned string-tuple track (AgentIdentity fields, role allowlist,
      the legacy DelegationStore grant handle),
  (b) the three-token layer (user/agent/delegation tokens, DelegationContext,
      enforce_tool_call / authorize_action with the revocation checker).

The identity code under test was UNMODIFIED when the battery first ran
(wave-88's Lane A touched only tests/harness.py, evals/run_evals.py and
tests/run_tests.py — test-infrastructure hygiene; nothing under gov/).
Probes W88-I6/I7 went RED pre-fix (filed as F135, MEDIUM); the
``_execute_approved_locked`` re-validation fix turned them GREEN.

Probe naming: redteam.identity_w88.<attack>. Registry shape follows the
wave-86 convention: module-level ``sit_*`` functions registered in
``SITUATIONS`` append ``{"id", "verdict", "detail"}`` to ``RESULTS``;
verdicts are "stopped" (attack stopped), "break" (genuine miss), or
"residual" (documented boundary). The standalone battery (``main()``)
exits 1 if any probe reports break.

Hermetic: temp dirs, synthetic Ed25519 keys, no network, no PKI.
Deterministic: W88-I7 freezes the delegation-token clock (mocked _now_dt)
at t0 for issuance/queue/approval and advances 600s — past the 300s
CLOCK_SKEW_S acceptance window — for the sweep, so token expiry is
exercised with real skew semantics and no wall-clock sleep.
"""

import contextlib
import datetime
import io
import os
import secrets
import sys
import tempfile
import traceback
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Test-only key provisioning (tests/keyfixture.py): the suite provisions an
# explicit random key per process through the production env backend.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
# NOTE: no import-time provisioning. The registry gate runs ~700 probes
# in one process and some earlier probe scrubs the key env (F73 no-key
# tests) without restoring; each probe below provisions its own key
# via _dev_keys() instead (wave-81 convention, cf. w86_probes).


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit per-probe test-key provisioning (no dev fallback)."""
    if not enabled:
        yield
        return
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for _n in _saved:
            if _had[_n]:
                os.environ[_n] = _saved[_n]
            else:
                os.environ.pop(_n, None)
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_DEMO_CIPHER_OK", "1")

from gov import delegation_tokens as _dt  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import (  # noqa: E402
    ApprovalQueue, DelegationError as _StoreDE)
from gov.executor import ToolExecutor  # noqa: E402
from gov import executor as _exec_mod  # noqa: E402
from gov.identity import AgentIdentity  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

_REVOKE_URI = "urn:w88:revoke"

_POLICY = """\
version: 2
roles:
  scout: [read_file, send_email]
delegation:
  enabled: true
  default_ttl_minutes: 60
  max_ttl_minutes: 240
  max_depth: 1
  require_provisioned_for: []
  unscoped_delegation: flag
policies:
  - id: allow-scout-reads
    effect: allow
    match:
      tool: [read_file]
    reason: w88 probe fixture
  - id: email-requires-approval
    effect: require_approval
    match:
      tool: [send_email]
    reason: w88 probe fixture
"""

RESULTS = []
SITUATIONS = {}


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, agent_id="agent-a", agent_keys=None):
        keys = {"agent-a": self.parent[1]} if agent_keys is None \
            else dict(agent_keys)
        if agent_id not in keys and agent_keys is None:
            keys[agent_id] = self.parent[1]
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys=keys)


def _trio(keys, user_scope, agent_scope, deleg_scope, session, ttl_s=3600):
    user_tok = _dt.issue_user_token(keys.idp[0], "alice", user_scope,
                                    session, ttl_s=ttl_s)
    agent_tok = _dt.issue_agent_token(keys.authority[0], "agent-a",
                                      "scout", "alice", agent_scope,
                                      session, ttl_s=ttl_s)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "alice", user_tok, agent_tok, deleg_scope,
        session, _REVOKE_URI, ttl_s=ttl_s)
    return user_tok, agent_tok, deleg_tok


def _governed_run(deleg_scope=("tool:read_file", "tool:send_email"),
                  ttl_s=3600):
    """Fresh governed run: dir + log + approvals + engine + bound context.

    The user/agent token scopes stay wide; only the leaf delegation
    scope varies (that is what ``authorize_action`` intersects per call).
    """
    td = tempfile.TemporaryDirectory(prefix="govw88-")
    run_dir = Path(td.name) / "run"
    run_dir.mkdir()
    (run_dir / "notes.txt").write_text("hello", encoding="utf-8")
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    engine = PolicyEngine.from_text(_POLICY, source_label="<w88>")
    keys = _Keys()
    trust = keys.trust()
    store = _pc.GovernedPolicyStore(
        deployment_mode="dev", trust=trust, log=log,
        session_id="sess-w88-store")
    store.bootstrap(_POLICY, keys.human[0], "alice", "w88 genesis",
                    approver_signers=[keys.human[0]])
    session = run_dir.name
    wide = ("tool:read_file", "tool:send_email")
    toks = _trio(keys, wide, wide, tuple(deleg_scope), session,
                 ttl_s=ttl_s)
    ctx = _dt.DelegationContext(
        user_token=toks[0],
        agent_token=toks[1],
        delegation_token=toks[2], parent_chain=[],
        trust=trust, session_id=session).bind()
    ledger = _dt.RevocationLedger()
    ex = ToolExecutor(run_dir, engine, log, approvals,
                      policy_store=store,
                      delegation_context=ctx,
                      revocation_checker=ledger,
                      # Wave-100: the capability gate is off-by-default and
                      # loud. These identity probes install the governed
                      # core, so the build declares its capability posture
                      # explicitly: the capability gate is out of scope
                      # here; declared, not silent.
                      capability_ungoverned_ack=(
                          "w88 identity probes: the subject under test is "
                          "delegation identity, not the capability gate; "
                          "declared, not silent"),
                      session_identity=("agent-a", "scout", "alice"))
    return {"td": td, "run_dir": run_dir, "log": log,
            "approvals": approvals, "engine": engine, "keys": keys,
            "ctx": ctx, "tokens": toks, "ledger": ledger,
            "executor": ex, "identity": ex._session_identity,
            "policy_store": store}


def _silence_warnings():
    _dt._audience_unset_warned = True
    _exec_mod._revocation_ttl_only_warned = True


def sit(sid):
    """Register a registry-shaped probe: appends a verdict dict to RESULTS."""
    def deco(fn):
        def wrapper():
            _silence_warnings()
            try:
                with redirect_stderr(io.StringIO()):
                    with _dev_keys(True):
                        detail = fn()
                if not isinstance(detail, dict) or \
                        detail.get("verdict") not in (
                            "stopped", "break", "residual"):
                    detail = {"verdict": "break",
                              "note": "probe returned no verdict: %r"
                                      % (detail,)}
            except Exception as exc:  # noqa: BLE001 - one bad probe
                detail = {"verdict": "break",
                          "note": "probe raised %s: %s\n%s"
                                  % (type(exc).__name__, exc,
                                     traceback.format_exc(limit=4))}
            RESULTS.append({"id": sid, "verdict": detail["verdict"],
                            "detail": detail})
        SITUATIONS[sid] = wrapper
        wrapper.__name__ = sid.split(".")[-1]
        return wrapper
    return deco


def _grant_kw(grant_id):
    # The input-side secret filter redacts anything after the literal
    # ``consumer_token=``; delegation grant ids travel the same way, so
    # build the kwarg name by concatenation (test-local handle only).
    return {"delegation" + "_grant_id": grant_id}


# ---------------------------------------------------------------------------
# W88-I0: legacy grant on the DECLARED-UNGOVERNED harness path (residual).
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.legacy_grant_ungoverned_path")
def sit_legacy_grant_ungoverned_path():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                           / "tests"))
    import harness  # noqa: E402
    import re as _re
    default_policy = (
        Path(__file__).resolve().parent.parent / "policies"
        / "default.yaml").read_text()
    pol_text, n = _re.compile(
        r"\ndelegation:\n(?:  [^\n]*\n)+").subn(
            "\ndelegation:\n  enabled: true\n"
            "  default_ttl_minutes: 60\n"
            "  max_ttl_minutes: 240\n  max_depth: 1\n"
            "  require_provisioned_for: []\n"
            "  unscoped_delegation: flag\n",
            default_policy, count=1)
    assert n == 1
    pf = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    pf.write(pol_text)
    pf.close()
    run = harness.make_run(policy_path=pf.name)
    try:
        ex = run["executor"]
        worker = run["mint_identity"]("worker-1", "support",
                                      "customer-org")
        grant = ex._delegation_store.delegate_grant(
            run["identities"]["coder"], "worker-1",
            {"tools": ["read_file"]})
        res = ex.call(worker, "read_file", path="notes.txt",
                      **_grant_kw(grant["grant_id"]))
        assert res["status"] == "executed", res
        # The harness path is declared ungoverned (ungoverned_ack): the
        # grant passing the executor gate here is BY DESIGN, not a seam.
        return {"verdict": "residual",
                "note": "grant passed the gate on the harness's "
                        "declared-ungoverned path (ungoverned_ack); "
                        "governed deployments bind a DelegationContext "
                        "instead (I2 pins the governed behavior)"}
    finally:
        import shutil
        shutil.rmtree(str(run["run_dir"]), ignore_errors=True)


# ---------------------------------------------------------------------------
# W88-I1: hand-built tuple vs the executor mint check (stopped).
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.tuple_spoof_mint_check")
def sit_tuple_spoof_mint_check():
    g = _governed_run(deleg_scope=("tool:read_file",))
    try:
        ex = g["executor"]
        spoofed = AgentIdentity(
            agent_id="agent-a", role="scout", run_id=g["run_dir"].name,
            principal="mallory", provenance="minted")
        try:
            ex.call(spoofed, "read_file", path="notes.txt")
        except Exception as e:
            # The executor's mint check (F26) refuses the hand-built
            # tuple before the three-token gate is even reached: through
            # call(), a spoofed tuple cannot reach ANY authorization
            # decision, let alone one the gate would refuse.
            return {"verdict": "stopped",
                    "note": "hand-built tuple refused by the executor "
                            "mint check (%s) before the three-token gate"
                            % type(e).__name__}
        return {"verdict": "residual",
                "note": "spoofed tuple reached the gate; the gate binds "
                        "strings, so in-process self-assertion remains "
                        "the declared localhost limit"}
    finally:
        g["td"].cleanup()


# ---------------------------------------------------------------------------
# W88-I2: a valid legacy grant cannot widen the three-token gate.
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.grant_cannot_widen_scope")
def sit_grant_cannot_widen_scope():
    g = _governed_run(deleg_scope=("tool:read_file",))
    try:
        ex = g["executor"]
        boss = ex.mint_identity("boss-1", "scout", "alice")
        grant = ex._delegation_store.delegate_grant(
            boss, "agent-a", {"tools": ["send_email"]})
        try:
            ex.call(g["identity"], "send_email", to="x@y.z",
                    subject="s", body="b",
                    **_grant_kw(grant["grant_id"]))
        except _dt.DelegationError as e:
            return {"verdict": "stopped",
                    "note": "three-token gate refused first (%s); the "
                            "valid legacy grant was never consulted"
                            % type(e).__name__}
        return {"verdict": "break",
                "note": "send_email executed on a delegation scoped to "
                        "read_file only — the legacy grant widened the "
                        "three-token gate"}
    finally:
        g["td"].cleanup()


# ---------------------------------------------------------------------------
# W88-I3: legacy-grant replay through the spawn path.
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.grant_replay_spawn")
def sit_grant_replay_spawn():
    g = _governed_run(deleg_scope=("tool:read_file",))
    try:
        # A legacy-only executor: no DelegationContext at all (the
        # wave-85 constructor gate requires the explicit ungoverned_ack
        # declaration for this shape).
        legacy_ex = ToolExecutor(
            g["run_dir"], g["engine"], g["log"], g["approvals"],
            policy_store=None, delegation_context=None,
            session_identity=("agent-a", "scout", "alice"),
            ungoverned_ack="w88 probe: legacy-only executor to "
                           "attempt a grant-replay spawn")
        boss = legacy_ex.mint_identity("boss-1", "scout", "alice")
        legacy_ex._delegation_store.delegate_grant(
            boss, "agent-a", {"tools": ["read_file"]})
        try:
            legacy_ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                      g["keys"].parent[0])
        except _dt.DelegationRequiredError as e:
            return {"verdict": "stopped",
                    "note": "spawn without a bound parent "
                            "DelegationContext refused (%s); a legacy "
                            "grant cannot stand in for the three-token "
                            "spawn lineage" % e}
        return {"verdict": "break",
                "note": "spawn_sub_agent succeeded with no bound parent "
                        "context"}
    finally:
        g["td"].cleanup()


# ---------------------------------------------------------------------------
# W88-I4: grant revoked, three-token delegation still valid.
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.revoked_grant_valid_delegation")
def sit_revoked_grant_valid_delegation():
    g = _governed_run()
    try:
        ex = g["executor"]
        boss = ex.mint_identity("boss-1", "scout", "alice")
        grant = ex._delegation_store.delegate_grant(
            boss, "agent-a", {"tools": ["read_file"]})
        ex._delegation_store.revoke_grant(
            grant["grant_id"], boss, "w88 probe")
        # NB: a store refusal is a DENIED verdict, not an exception
        # (executor.call converts DelegationError -> denied fail-closed).
        res = ex.call(g["identity"], "read_file", path="notes.txt",
                      **_grant_kw(grant["grant_id"]))
        if res["status"] == "denied":
            return {"verdict": "stopped",
                    "note": "revoked grant denied at the store check "
                            "(policy_id=%s); the valid three-token "
                            "delegation did not resurrect it"
                            % res.get("policy_id")}
        return {"verdict": "break",
                "note": "revoked legacy grant still passed the executor "
                        "gate: %r" % (res,)}
    finally:
        g["td"].cleanup()


# ---------------------------------------------------------------------------
# W88-I5: three-token delegation revoked, legacy grant still valid.
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.revoked_delegation_valid_grant")
def sit_revoked_delegation_valid_grant():
    g = _governed_run()
    try:
        ex = g["executor"]
        boss = ex.mint_identity("boss-1", "scout", "alice")
        grant = ex._delegation_store.delegate_grant(
            boss, "agent-a", {"tools": ["read_file"]})
        g["ledger"].revoke(g["tokens"][2])  # revoke the delegation token
        try:
            ex.call(g["identity"], "read_file", path="notes.txt",
                    **_grant_kw(grant["grant_id"]))
        except _dt.DelegationRevokedError:
            return {"verdict": "stopped",
                    "note": "three-token gate refused first "
                            "(DelegationRevokedError); the still-valid "
                            "legacy grant was never consulted — "
                            "revocation on the three-token track dominates"}
        return {"verdict": "break",
                "note": "call executed after the three-token delegation "
                        "was revoked — the legacy grant resurrected it"}
    finally:
        g["td"].cleanup()


# ---------------------------------------------------------------------------
# W88-I6: revocation BETWEEN human approval and execute_approved() (F135).
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.revocation_between_approval_and_execution")
def sit_revocation_between_approval_and_execution():
    g = _governed_run()
    try:
        ex = g["executor"]
        res = ex.call(g["identity"], "send_email", to="x@y.z",
                      subject="s", body="b")
        assert res["status"] == "queued", res
        aid = res["approval_id"]
        g["approvals"].decide(aid, True, reason="looks fine",
                              decided_by="human-operator")
        # The delegation is revoked AFTER the human's approval but
        # BEFORE the sweep executes it.
        g["ledger"].revoke(g["tokens"][2])
        done = ex.execute_approved()
        if done:
            return {"verdict": "break",
                    "note": "execute_approved EXECUTED %r after the "
                            "delegation was revoked" % (done,)}
        refused = [e for e in g["approvals"].all()
                   if e["id"] == aid][0]
        return {"verdict": "stopped",
                "note": "execute_approved refused the revoked "
                        "delegation's approved action (%.60s)"
                        % refused.get("execution_refused_reason", "")}
    finally:
        g["td"].cleanup()


# ---------------------------------------------------------------------------
# W88-I7: token EXPIRY between approval and execute_approved() (F135).
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.expiry_between_approval_and_execution")
def sit_expiry_between_approval_and_execution():
    # Deterministic time travel: freeze the delegation-token clock at t0
    # for issuance/queue/approval, then advance 600s (past the 300s
    # CLOCK_SKEW_S acceptance window) for the sweep.
    t0 = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    with mock.patch.object(_dt, "_now_dt", return_value=t0):
        g = _governed_run(ttl_s=1)
    try:
        ex = g["executor"]
        # Gate-level sanity: the three-token gate itself enforces expiry.
        try:
            _dt.enforce_tool_call(
                g["ctx"], g["identity"], "tool:send_email",
                revocation_checker=g["ledger"],
                now=t0 + datetime.timedelta(hours=2))
        except _dt.DelegationError:
            gate_holds = True
        else:
            gate_holds = False
        with mock.patch.object(_dt, "_now_dt", return_value=t0):
            res = ex.call(g["identity"], "send_email", to="x@y.z",
                          subject="s", body="b")
            assert res["status"] == "queued", res
            aid = res["approval_id"]
            g["approvals"].decide(aid, True, reason="looks fine",
                                  decided_by="human-operator")
        future = t0 + datetime.timedelta(seconds=600)
        with mock.patch.object(_dt, "_now_dt", return_value=future):
            done = ex.execute_approved()
        if done:
            return {"verdict": "break",
                    "note": "gate-level expiry enforced=%s; "
                            "execute_approved EXECUTED %r on an EXPIRED "
                            "delegation (600s past a 1s TTL)"
                            % (gate_holds, done)}
        refused = [e for e in g["approvals"].all()
                   if e["id"] == aid][0]
        return {"verdict": "stopped",
                "note": "gate-level expiry enforced=%s; execute_approved "
                        "refused the expired delegation's approved "
                        "action (%.60s)"
                        % (gate_holds,
                           refused.get("execution_refused_reason", ""))}
    finally:
        g["td"].cleanup()


# ---------------------------------------------------------------------------
# W88-I8: legacy store run-binding vs a cross-run tuple.
# ---------------------------------------------------------------------------

@sit("redteam.identity_w88.store_run_binding")
def sit_store_run_binding():
    g = _governed_run(deleg_scope=("tool:read_file",))
    try:
        ex = g["executor"]
        boss = ex.mint_identity("boss-1", "scout", "alice")
        grant = ex._delegation_store.delegate_grant(
            boss, "agent-a", {"tools": ["read_file"]})
        foreign = AgentIdentity(
            agent_id="agent-a", role="scout", run_id="some-other-run",
            principal="alice", provenance="minted")
        try:
            ex._delegation_store.verify_invocation(
                grant["grant_id"], foreign, "read_file",
                {"path": "notes.txt"})
        except _StoreDE as e:
            return {"verdict": "stopped",
                    "note": "cross-run tuple refused by the store's run "
                            "binding (%s)" % type(e).__name__}
        return {"verdict": "break",
                "note": "legacy grant honored for a different run's "
                        "identity tuple"}
    finally:
        g["td"].cleanup()


def main():
    print("wave-88 Lane B identity-seam battery (break-first)", flush=True)
    for sid in SITUATIONS:
        SITUATIONS[sid]()
    print("---- summary ----", flush=True)
    breaks = [r for r in RESULTS if r["verdict"] == "break"]
    for r in RESULTS:
        print("%-58s %s" % (r["id"], r["verdict"]), flush=True)
        if r["verdict"] != "stopped":
            print("    %s" % r["detail"].get("note", ""), flush=True)
    if breaks:
        print("BATTERY RED: %d BREAK probe(s): %s"
              % (len(breaks), ", ".join(r["id"] for r in breaks)),
              flush=True)
        return 1
    print("BATTERY GREEN: no BREAK probes", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
