"""Wave-86 identity: audience binding (F132), revocation wiring (GAP 2),
governed spawn (F133), and the verification-side depth-cap re-check.

Load-bearing claims under test:
- tokens MAY carry a signed ``aud`` claim (the deployment id); when the
  verifier's DelegationTrust sets ``audience``, a missing or mismatched
  aud is refused (DelegationBindingError) — the cross-deployment
  confused-deputy replay dies at verification (F132)
- spawn INHERITS aud from the parent token — never a parameter — so a
  spawn cannot re-target a delegation at another deployment
- the executor's real tool-call path consults the revocation checker
  (leaf AND ancestors, per call); a raising checker fails closed as
  DelegationRevokedError, never a crash (GAP 2)
- ToolExecutor.spawn_sub_agent is the governed spawn path: bound
  parent context required, parent workload key registered in the
  session roster (fail-closed on key swap), an agent_spawn event with
  parent/child token refs chained BEFORE return, spawn budget
  enforced (shared across the lineage), and the child executor is
  itself governed (F55 provisioned identity + wave-85 constructor gate)
  with run_id == session run_id (F133)
- verify_delegation_chain re-checks MAX_DELEGATION_DEPTH: a smuggled
  deep token fails at verification, not just at issuance

Hermetic: temp dirs, synthetic keys via generate_test_keypair, no
network, no PKI. Deterministic except wall-clock iat/exp (never
asserted on).
"""

import inspect
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import delegation_tokens as _dt  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import (  # noqa: E402
    SpawnBudgetExhaustedError, ToolExecutor)
from gov import executor as _exec_mod  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

_SID = "sess-w86"
_REVOKE_URI = "urn:w86:revoke"
_AUD = "deployment-a"

_BASE_POLICY = """\
version: 2
roles:
  scout: [read_file]
policies:
  - id: allow-scout-reads
    effect: allow
    match:
      tool: [read_file]
    reason: w86 fixture
"""


class _Keys(object):
    """One synthetic Ed25519 key per trust layer."""

    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, agent_id="agent-a", audience=None, agent_keys=None):
        keys = {"agent-a": self.parent[1]} if agent_keys is None \
            else dict(agent_keys)
        if agent_id not in keys and agent_keys is None:
            keys[agent_id] = self.parent[1]
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys=keys, audience=audience)


def _trio(keys, user_scope=("tool:read_file",),
          agent_scope=("tool:read_file",),
          deleg_scope=("tool:read_file",), session=_SID,
          audience=None, agent_id="agent-a"):
    user_tok = _dt.issue_user_token(keys.idp[0], "alice", user_scope,
                                    session, ttl_s=3600,
                                    audience=audience)
    agent_tok = _dt.issue_agent_token(keys.authority[0], agent_id,
                                      "scout", "alice", agent_scope,
                                      session, ttl_s=3600,
                                      audience=audience)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "alice", user_tok, agent_tok, deleg_scope,
        session, _REVOKE_URI, ttl_s=3600, audience=audience)
    return user_tok, agent_tok, deleg_tok


def _bound_ctx(keys, trust=None, audience=None, session=_SID, **trio_kw):
    user_tok, agent_tok, deleg_tok = _trio(keys, session=session,
                                          audience=audience, **trio_kw)
    ctx = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=trust or keys.trust(audience=audience),
        session_id=session).bind()
    return ctx, (user_tok, agent_tok, deleg_tok)


class _Quiet(object):
    """Reset the wave-86 one-time warning flags and swallow stderr."""

    def __init__(self, test):
        self._test = test

    def __enter__(self):
        self._old_aud = _dt._audience_unset_warned
        self._old_rev = _exec_mod._revocation_ttl_only_warned
        _dt._audience_unset_warned = True  # already warned: stay silent
        _exec_mod._revocation_ttl_only_warned = True
        self._redir = redirect_stderr(io.StringIO())
        self._redir.__enter__()
        return self

    def __exit__(self, *exc):
        self._redir.__exit__(*exc)
        _dt._audience_unset_warned = self._old_aud
        _exec_mod._revocation_ttl_only_warned = self._old_rev
        return False


class _Run(object):
    """Fresh governed run: dir + log + approvals + engine + store."""

    def __init__(self, test, keys, audience=None, agent_keys=None,
                 mode="staging"):
        self._td = tempfile.TemporaryDirectory(prefix="govw86-")
        test.addCleanup(self._td.cleanup)
        self.run_dir = Path(self._td.name) / "run"
        self.run_dir.mkdir()
        (self.run_dir / "notes.txt").write_text("hello", encoding="utf-8")
        self.log = ActionLog(self.run_dir / "actions.jsonl")
        self.approvals = ApprovalQueue(self.run_dir, self.log)
        self.engine = PolicyEngine.from_text(_BASE_POLICY,
                                             source_label="<w86>")
        self.trust = keys.trust(audience=audience,
                                agent_keys=agent_keys)
        self.store = _pc.GovernedPolicyStore(
            deployment_mode="dev", trust=self.trust, log=self.log,
            session_id="sess-w86-store")
        human = keys.human[0]
        self.store.bootstrap(_BASE_POLICY, human, "alice", "w86 genesis",
                             approver_signers=[human])
        self._patcher = mock.patch.dict(
            os.environ, {"GOV_DEPLOYMENT_MODE": mode})
        self._patcher.start()
        test.addCleanup(self._patcher.stop)

    def build(self, ctx, **kw):
        kw.setdefault("policy_store", self.store)
        kw.setdefault("delegation_context", ctx)
        # Wave-100: the capability gate is off-by-default and loud. These
        # identity tests install the governed core, so each build declares
        # its capability posture explicitly rather than silently looking
        # governed: the capability gate is out of scope for this suite.
        kw.setdefault(
            "capability_ungoverned_ack",
            "w86 identity tests: the subject under test is spawn identity, "
            "not the capability gate; declared, not silent")
        return ToolExecutor(self.run_dir, self.engine, self.log,
                            self.approvals, **kw)

    def entries(self):
        return read_entries(self.run_dir / "actions.jsonl")


# ---------------------------------------------------------------------------
# Audience binding (F132)
# ---------------------------------------------------------------------------

class TestAudienceBinding(unittest.TestCase):
    def test_audience_carried_in_signed_body(self):
        keys = _Keys()
        _, _, deleg_tok = _trio(keys, audience=_AUD)
        self.assertEqual(deleg_tok["aud"], _AUD)
        # The signature covers the body including aud: tampering with
        # aud without re-signing breaks verification.
        tampered = dict(deleg_tok)
        tampered["aud"] = "deployment-evil"
        trust = keys.trust(audience=_AUD)
        with _Quiet(self):
            with self.assertRaises(_dt.DelegationSignatureError):
                _dt.verify_token(tampered, trust.human_keys,
                                 expected_kind="delegation",
                                 expected_session=_SID,
                                 expected_audience=_AUD)

    def test_audience_match_binds(self):
        keys = _Keys()
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, audience=_AUD)
        self.assertTrue(ctx.bound)
        self.assertEqual(ctx.delegation_token["aud"], _AUD)

    def test_audience_mismatch_refused(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys, audience=_AUD)
        # Deployment B: same operator keys, different deployment id.
        trust_b = keys.trust(audience="deployment-b")
        ctx = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=deleg_tok, parent_chain=[],
            trust=trust_b, session_id=_SID)
        with _Quiet(self):
            with self.assertRaises(_dt.DelegationBindingError):
                ctx.bind()

    def test_audience_missing_refused_when_set(self):
        keys = _Keys()
        # Tokens WITHOUT aud, verifier WITH audience: refused.
        ctx, _ = _bound_ctx(keys)  # no audience anywhere: binds
        self.assertTrue(ctx.bound)
        user_tok, agent_tok, deleg_tok = _trio(keys)
        trust_a = keys.trust(audience=_AUD)
        ctx2 = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=deleg_tok, parent_chain=[],
            trust=trust_a, session_id=_SID)
        with _Quiet(self):
            with self.assertRaises(_dt.DelegationBindingError):
                ctx2.bind()

    def test_audience_unset_no_check(self):
        keys = _Keys()
        # Legacy shape (no aud anywhere, no audience configured) still
        # verifies — the gap is disclosed, not silently broken.
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys)
        self.assertTrue(ctx.bound)

    def test_spawn_inherits_aud_not_a_parameter(self):
        keys = _Keys()
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, audience=_AUD)
            child = ctx.spawn("agent-b", ["tool:read_file"],
                              keys.parent[0])
        self.assertEqual(child.delegation_token["aud"], _AUD)
        self.assertTrue(child.bound)
        # aud-swapping at spawn is impossible BY CONSTRUCTION: neither
        # spawn mouth takes an audience parameter.
        self.assertNotIn("audience",
                         inspect.signature(_dt.spawn_sub_agent).parameters)
        self.assertNotIn("audience",
                         inspect.signature(
                             _dt.DelegationContext.spawn).parameters)
        self.assertNotIn("audience",
                         inspect.signature(
                             ToolExecutor.spawn_sub_agent).parameters)

    def test_spawn_without_aud_inherits_absent(self):
        keys = _Keys()
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys)
            child = ctx.spawn("agent-b", ["tool:read_file"],
                              keys.parent[0])
        self.assertNotIn("aud", child.delegation_token)

    def test_audience_unset_warns_once(self):
        keys = _Keys()
        _dt._audience_unset_warned = False
        self.addCleanup(setattr, _dt, "_audience_unset_warned", False)
        buf = io.StringIO()
        with redirect_stderr(buf):
            _bound_ctx(keys)
            _bound_ctx(keys)
        out = buf.getvalue()
        self.assertEqual(out.count("GOVERNANCE WARNING"), 1)
        self.assertIn("confused", out)

    def test_audience_set_no_warning(self):
        keys = _Keys()
        _dt._audience_unset_warned = False
        self.addCleanup(setattr, _dt, "_audience_unset_warned", False)
        buf = io.StringIO()
        with redirect_stderr(buf):
            _bound_ctx(keys, audience=_AUD)
        self.assertNotIn("GOVERNANCE WARNING", buf.getvalue())


# ---------------------------------------------------------------------------
# Revocation wiring (GAP 2)
# ---------------------------------------------------------------------------

class TestRevocationWiring(unittest.TestCase):
    def _executor(self, r, ctx, ledger, **kw):
        with _Quiet(self):
            return r.build(ctx, revocation_checker=ledger,
                           session_identity=("agent-a", "scout", "alice"),
                           **kw)

    def test_revoked_leaf_refused_on_executor_path(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, (_, _, deleg_tok) = _bound_ctx(keys, session=r.run_dir.name)
        ledger = _dt.RevocationLedger()
        ex = self._executor(r, ctx, ledger)
        ident = ex._session_identity
        res = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(res["status"], "executed")
        ledger.revoke(deleg_tok)
        with self.assertRaises(_dt.DelegationRevokedError):
            ex.call(ident, "read_file", path="notes.txt")

    def test_revoked_ancestor_refused_on_executor_path(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, (_, _, deleg_tok) = _bound_ctx(keys, session=r.run_dir.name)
            child_ctx = ctx.spawn("agent-b", ["tool:read_file"],
                                  keys.parent[0])
        ledger = _dt.RevocationLedger()
        ledger.revoke(deleg_tok)  # revoke the PARENT only
        with _Quiet(self):
            child_ex = r.build(
                child_ctx, revocation_checker=ledger,
                session_identity=("agent-b", "scout", "alice"))
        with self.assertRaises(_dt.DelegationRevokedError):
            child_ex.call(child_ex._session_identity, "read_file",
                          path="notes.txt")

    def test_checker_error_fails_closed_not_a_crash(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)

        def _boom(ref):
            raise IOError("revocation source unreachable")

        ex = self._executor(r, ctx, _boom)
        with self.assertRaises(_dt.DelegationRevokedError):
            ex.call(ex._session_identity, "read_file", path="notes.txt")

    def test_ttl_only_warning_once(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        _exec_mod._revocation_ttl_only_warned = False
        self.addCleanup(setattr, _exec_mod,
                        "_revocation_ttl_only_warned", False)
        buf = io.StringIO()
        with redirect_stderr(buf):
            r.build(ctx, session_identity=("agent-a", "scout", "alice"))
            r.build(ctx, session_identity=("agent-a", "scout", "alice"))
        out = buf.getvalue()
        self.assertEqual(out.count("GOVERNANCE WARNING"), 1)
        self.assertIn("TTL-ONLY", out)

    def test_no_warning_when_checker_provided(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        _exec_mod._revocation_ttl_only_warned = False
        self.addCleanup(setattr, _exec_mod,
                        "_revocation_ttl_only_warned", False)
        buf = io.StringIO()
        with redirect_stderr(buf):
            self._executor(r, ctx, _dt.RevocationLedger())
        self.assertNotIn("GOVERNANCE WARNING", buf.getvalue())

    def test_no_warning_without_delegation(self):
        keys = _Keys()
        r = _Run(self, keys)
        _exec_mod._revocation_ttl_only_warned = False
        self.addCleanup(setattr, _exec_mod,
                        "_revocation_ttl_only_warned", False)
        buf = io.StringIO()
        with redirect_stderr(buf):
            ToolExecutor(r.run_dir, r.engine, r.log, r.approvals,
                         ungoverned_ack="w86 test: no delegation")
        self.assertNotIn("TTL-ONLY", buf.getvalue())


# ---------------------------------------------------------------------------
# Governed spawn (F133)
# ---------------------------------------------------------------------------

class TestGovernedSpawn(unittest.TestCase):
    def _executor(self, r, ctx, **kw):
        with _Quiet(self):
            return r.build(ctx,
                           session_identity=("agent-a", "scout", "alice"),
                           **kw)

    def test_spawn_chains_agent_spawn_event(self):
        keys = _Keys()
        r = _Run(self, keys, audience=_AUD)
        with _Quiet(self):
            ctx, (_, _, deleg_tok) = _bound_ctx(
                keys, audience=_AUD, session=r.run_dir.name)
        ex = self._executor(r, ctx)
        with _Quiet(self):
            child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                          keys.parent[0])
        events = [e for e in r.entries()
                  if e.get("event") == "agent_spawn"]
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["parent_token_ref"], _dt.token_ref(deleg_tok))
        self.assertEqual(
            e["child_token_ref"],
            _dt.token_ref(child_ex._delegation_context.delegation_token))
        self.assertEqual(e["sub_agent_id"], "agent-b")
        self.assertEqual(e["sub_scope"], ["tool:read_file"])
        self.assertEqual(e["delegation_depth"], 1)
        self.assertEqual(e["delegator"], "agent-a")
        self.assertEqual(e["session_id"], r.run_dir.name)
        self.assertEqual(e["aud"], _AUD)
        self.assertEqual(e["agent_id"], "agent-a")  # the spawner

    def test_spawn_registers_parent_key(self):
        keys = _Keys()
        # Session-open roster WITHOUT the parent's key: the governed
        # spawn registers it (the F133 registration gap).
        r = _Run(self, keys, agent_keys={})
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, trust=r.trust,
                                session=r.run_dir.name)
        self.assertNotIn("agent-a", r.trust.agent_keys)
        ex = self._executor(r, ctx)
        with _Quiet(self):
            ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                               keys.parent[0])
        self.assertEqual(r.trust.agent_keys["agent-a"], keys.parent[1])
        events = [e for e in r.entries()
                  if e.get("event") == "agent_spawn"]
        self.assertTrue(events[0]["parent_key_registered"])

    def test_spawn_key_swap_refused(self):
        keys = _Keys()
        other = _dt.generate_test_keypair()
        r = _Run(self, keys, agent_keys={"agent-a": other[1]})
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, trust=r.trust,
                                session=r.run_dir.name)
        ex = self._executor(r, ctx)
        with _Quiet(self):
            with self.assertRaises(_dt.DelegationSignatureError):
                ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                   keys.parent[0])

    def test_spawn_budget_exhaustion(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        ex = self._executor(r, ctx, spawn_budget=1)
        with _Quiet(self):
            ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                               keys.parent[0])
            with self.assertRaises(SpawnBudgetExhaustedError):
                ex.spawn_sub_agent("agent-c", ["tool:read_file"],
                                   keys.parent[0])

    def test_spawn_budget_shared_with_lineage(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        ex = self._executor(r, ctx, spawn_budget=2)
        with _Quiet(self):
            child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                          keys.parent[0])
            # The child shares the lineage budget box: one left, so one
            # more spawn succeeds anywhere in the lineage...
            grandchild_ex = child_ex.spawn_sub_agent(
                "agent-c", ["tool:read_file"], keys.parent[0])
            # ...and the third spawn — from parent, child, or
            # grandchild — is refused: the budget bounds the whole
            # tree, not each executor.
            for spawner in (ex, child_ex, grandchild_ex):
                with self.assertRaises(SpawnBudgetExhaustedError):
                    spawner.spawn_sub_agent("agent-x", ["tool:read_file"],
                                            keys.parent[0])

    def test_spawn_budget_validation(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        for bad in (-1, True, "3", 1.5):
            with self.assertRaises(ValueError, msg="budget=%r" % (bad,)):
                with _Quiet(self):
                    r.build(ctx,
                            session_identity=("agent-a", "scout", "alice"),
                            spawn_budget=bad)

    def test_child_executor_passes_gate(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        ex = self._executor(r, ctx)
        with _Quiet(self):
            child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                          keys.parent[0])
        # run_id == session run_id, so the gate's session binding holds.
        self.assertEqual(child_ex.run_id, ex.run_id)
        self.assertEqual(child_ex.run_id, r.run_dir.name)
        ident = child_ex._session_identity
        self.assertEqual(
            (ident.agent_id, ident.role, ident.principal),
            ("agent-b", "scout", "alice"))
        # The leaf delegation names the child: the gate's
        # subject check passes for the provisioned identity.
        res = child_ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(res["status"], "executed")

    def test_child_inherits_revocation_checker(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        ledger = _dt.RevocationLedger()
        ex = self._executor(r, ctx, revocation_checker=ledger)
        with _Quiet(self):
            child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                          keys.parent[0])
        ledger.revoke(child_ex._delegation_context.delegation_token)
        with self.assertRaises(_dt.DelegationRevokedError):
            child_ex.call(child_ex._session_identity, "read_file",
                          path="notes.txt")

    def test_spawn_no_context_refused(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ex = ToolExecutor(
                r.run_dir, r.engine, r.log, r.approvals,
                ungoverned_ack="w86 test: spawn needs delegation")
            with self.assertRaises(_dt.DelegationRequiredError):
                ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                   keys.parent[0])

    def test_spawn_unbound_context_refused(self):
        keys = _Keys()
        r = _Run(self, keys)
        user_tok, agent_tok, deleg_tok = _trio(keys,
                                              session=r.run_dir.name)
        unbound = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=deleg_tok, parent_chain=[],
            trust=r.trust, session_id=r.run_dir.name)
        with _Quiet(self):
            ex = r.build(unbound,
                         session_identity=("agent-a", "scout", "alice"))
            with self.assertRaises(_dt.DelegationRequiredError):
                ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                   keys.parent[0])

    def test_spawn_widens_scope_still_refused(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        ex = self._executor(r, ctx)
        with _Quiet(self):
            with self.assertRaises(_dt.DelegationAttenuationError):
                ex.spawn_sub_agent("agent-b", ["tool:send_email"],
                                   keys.parent[0])

    def test_spawn_executor_never_persists_signer(self):
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, session=r.run_dir.name)
        ex = self._executor(r, ctx)
        with _Quiet(self):
            ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                               keys.parent[0])
        # The caller-provided private signer must not be persisted on
        # the executor: no attribute holds it, under any name.
        self.assertNotIn("parent_signer", vars(ex))
        for name, value in vars(ex).items():
            self.assertIsNot(value, keys.parent[0],
                             msg="executor.%s is the parent signer" % name)


# ---------------------------------------------------------------------------
# Verification-side depth-cap re-check (defense in depth)
# ---------------------------------------------------------------------------

class TestDepthCapVerifySide(unittest.TestCase):
    def _deep_chain(self, keys, session, depth):
        """Hand-forged chain of `depth` hops (depths 0..depth), all
        parent-signed with valid signatures — bypasses issuance, so
        only a verification-side cap can stop it."""
        ut, at, d0 = _trio(keys, session=session,
                            deleg_scope=("tool:read_file",))
        chain = [d0]
        parent_tok = d0
        for i in range(1, depth + 1):
            claims = {
                "delegator": "agent-a",
                "user_token_hash": _dt.token_ref(ut),
                "agent_token_hash": _dt.token_ref(at),
                "scope": ["tool:read_file"],
                "revocation_endpoint": _REVOKE_URI,
                "audit_urls": [],
                "delegation_depth": i,
                "parent_token_hash": _dt.token_ref(parent_tok),
            }
            tok = _dt._base_token("delegation", keys.parent[0],
                                   "agent-deep", session, claims,
                                   None, None)
            chain.append(tok)
            parent_tok = tok
        return ut, at, chain

    def test_depth_8_chain_verifies(self):
        keys = _Keys()
        ut, at, chain = self._deep_chain(keys, _SID, 8)
        trust = keys.trust()
        with _Quiet(self):
            leaf = _dt.DelegationContext(
                user_token=ut, agent_token=at,
                delegation_token=chain[-1], parent_chain=chain[:-1],
                trust=trust, session_id=_SID).bind()
        self.assertTrue(leaf.bound)

    def test_depth_9_chain_refused_at_verify(self):
        keys = _Keys()
        ut, at, chain = self._deep_chain(keys, _SID, 9)
        trust = keys.trust()
        with _Quiet(self):
            with self.assertRaises(_dt.DelegationAttenuationError):
                _dt.DelegationContext(
                    user_token=ut, agent_token=at,
                    delegation_token=chain[-1],
                    parent_chain=chain[:-1],
                    trust=trust, session_id=_SID).bind()


if __name__ == "__main__":
    unittest.main()
