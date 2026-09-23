"""Wave-74 identity: three-token delegation (South et al.), SPIFFE
transport/app split, permission intersection, parent-signed spawn
lineage, provenance v2 token slots, executor delegation gate.

Load-bearing claims under test:
- delegation is Ed25519-signed by a human-side key the agent never
  holds; forgeries with any other key are refused
- effective permission = user permissions ∩ agent capabilities ∩
  delegation scope; the narrowest layer names itself in the refusal
- a sub-agent's scope can only attenuate its parent's (monotonic)
- every spawn is bound to its actual parent's delegation token hash;
  parent-signature swaps and middle-hop tampering break the chain
- the executor's delegation gate runs BEFORE policy evaluation, in
  code: an allow-all policy YAML cannot re-enable a missing-delegation
  call (construction proof)
- the gate binds the acting identity: a sibling cannot borrow another
  agent's delegation, and cross-run token use is replay
- provenance v2 fills the three-token ref slots; v1 records (tokens
  null) still verify; the binds chain commits to the filled tokens so
  truncation/reorder detection works unchanged
- token slots carry refs only (SHA-256), never secrets

Hermetic: temp dirs, synthetic keys via generate_test_keypair, no
network, no PKI. Deterministic except wall-clock iat/exp (never
asserted on).
"""

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import delegation_tokens as _dt  # noqa: E402
from gov import provenance as _prov  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402

_SID = "sess-w74"
_REVOKE_URI = "https://revoke.example.invalid/deleg"


class _Keys(object):
    """One synthetic Ed25519 key per trust layer."""

    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, extra_agent_keys=None):
        agent_keys = {"agent-1": self.parent[1]}
        if extra_agent_keys:
            agent_keys.update(extra_agent_keys)
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys=agent_keys)


def _trio(keys, user_scope=("tool:read_file", "tool:send_email"),
          agent_scope=("tool:read_file", "tool:send_email"),
          deleg_scope=("tool:read_file",), session=_SID, ttl_s=3600,
          now=None):
    """The standard user/agent/delegation token trio, ready to bind."""
    user_tok = _dt.issue_user_token(keys.idp[0], "user-7", user_scope,
                                    session, ttl_s=ttl_s, now=now)
    agent_tok = _dt.issue_agent_token(keys.authority[0], "agent-1",
                                      "scout", "user-7", agent_scope,
                                      session, ttl_s=ttl_s, now=now)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok, deleg_scope,
        session, _REVOKE_URI, ttl_s=ttl_s, now=now)
    return user_tok, agent_tok, deleg_tok


def _bound_ctx(keys, trust=None, **trio_kw):
    user_tok, agent_tok, deleg_tok = _trio(keys, **trio_kw)
    ctx = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=trust or keys.trust(),
        session_id=trio_kw.get("session", _SID)).bind()
    return ctx, (user_tok, agent_tok, deleg_tok)


def _verify(tok, roster, kind, session=_SID, **kw):
    return _dt.verify_token(tok, roster, expected_kind=kind,
                            expected_session=session, **kw)


class IssuanceAndVerificationTest(unittest.TestCase):
    def test_trio_verifies_against_its_own_rosters(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys)
        trust = keys.trust()
        self.assertEqual(
            _verify(user_tok, trust.user_issuer_keys, "user")["user_id"],
            "user-7")
        self.assertEqual(
            _verify(agent_tok, trust.authority_keys,
                    "agent")["agent_id"], "agent-1")
        self.assertEqual(
            _verify(deleg_tok, trust.human_keys,
                    "delegation")["delegator"], "user-7")

    def test_wrong_roster_refuses(self):
        keys = _Keys()
        user_tok, _, deleg_tok = _trio(keys)
        trust = keys.trust()
        # The delegation token is human-signed; verifying it against the
        # IdP roster (which has no human key id) fails closed.
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(deleg_tok, trust.user_issuer_keys, "delegation")
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(user_tok, trust.human_keys, "user")

    def test_forgery_resigned_with_attacker_key_refused(self):
        keys = _Keys()
        trust = keys.trust()
        _, _, deleg_tok = _trio(keys)
        attacker = _dt.generate_test_keypair()
        forged = copy.deepcopy(deleg_tok)
        body = {k: v for k, v in forged.items() if k != "sig"}
        forged["sig"] = attacker[0].sign(
            _dt._TOKEN_DOMAIN + _dt._canonical(body)).hex()
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(forged, trust.human_keys, "delegation")

    def test_tampered_claim_refused(self):
        keys = _Keys()
        trust = keys.trust()
        _, _, deleg_tok = _trio(keys)
        tampered = copy.deepcopy(deleg_tok)
        tampered["claims"] = dict(tampered["claims"])
        tampered["claims"]["scope"] = ["tool:*"]
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(tampered, trust.human_keys, "delegation")

    def test_unknown_key_id_refused(self):
        keys = _Keys()
        _, _, deleg_tok = _trio(keys)
        stranger = _dt.DelegationTrust(
            human_keys={"kid:unknown": keys.human[1]},
            authority_keys={keys.authority[0].key_id: keys.authority[1]},
            user_issuer_keys={keys.idp[0].key_id: keys.idp[1]})
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(deleg_tok, stranger.human_keys, "delegation")

    def test_missing_sig_refused(self):
        keys = _Keys()
        trust = keys.trust()
        _, _, deleg_tok = _trio(keys)
        unsigned = copy.deepcopy(deleg_tok)
        del unsigned["sig"]
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(unsigned, trust.human_keys, "delegation")

    def test_unsupported_token_version_refused(self):
        keys = _Keys()
        trust = keys.trust()
        _, _, deleg_tok = _trio(keys)
        futuristic = copy.deepcopy(deleg_tok)
        futuristic["token_version"] = 99
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(futuristic, trust.human_keys, "delegation")

    def test_malformed_scope_rejected_at_issuance(self):
        keys = _Keys()
        with self.assertRaises(ValueError):
            _dt.issue_user_token(keys.idp[0], "user-7", ["read_file"],
                                 _SID)
        with self.assertRaises(ValueError):
            _dt.issue_agent_token(keys.authority[0], "agent-1", "scout",
                                  "user-7", ["admin"], _SID)
        with self.assertRaises(ValueError):
            _dt.issue_user_token(keys.idp[0], "user-7", ["tool:"], _SID)

    def test_empty_scope_rejected_at_issuance(self):
        keys = _Keys()
        user_tok, agent_tok, _ = _trio(keys)
        with self.assertRaises(ValueError):
            _dt.issue_delegation(keys.human[0], "user-7", user_tok,
                                 agent_tok, [], _SID, _REVOKE_URI)

    def test_ttl_cap_enforced_at_issuance(self):
        keys = _Keys()
        with self.assertRaises(ValueError):
            _dt.issue_user_token(keys.idp[0], "user-7",
                                 ["tool:read_file"], _SID,
                                 ttl_s=_dt.MAX_TTL_S + 1)
        with self.assertRaises(ValueError):
            _dt.issue_user_token(keys.idp[0], "user-7",
                                 ["tool:read_file"], _SID, ttl_s=0)

    def test_token_ref_is_stable_sha256(self):
        keys = _Keys()
        user_tok, _, _ = _trio(keys)
        self.assertEqual(_dt.token_ref(user_tok), _dt.token_ref(user_tok))
        self.assertEqual(len(_dt.token_ref(user_tok)), 64)
        other_tok, _, _ = _trio(keys)
        self.assertNotEqual(_dt.token_ref(user_tok),
                            _dt.token_ref(other_tok))

class ExpiryAndSkewTest(unittest.TestCase):
    def _past(self, **kw):
        return datetime.now(timezone.utc) - timedelta(**kw)

    def test_expired_token_refused(self):
        keys = _Keys()
        trust = keys.trust()
        # Issued ~115 days ago with a 1h TTL: long dead even with skew.
        user_tok, _, _ = _trio(keys, now=self._past(days=115))
        with self.assertRaises(_dt.DelegationExpiredError):
            _verify(user_tok, trust.user_issuer_keys, "user")

    def test_expiry_within_skew_is_tolerated(self):
        keys = _Keys()
        trust = keys.trust()
        # Issued 3700s ago with a 3600s TTL: 100s past nominal expiry,
        # inside the ±300s skew window -> still verifies.
        user_tok, _, _ = _trio(keys, ttl_s=3600,
                               now=self._past(seconds=3700))
        _verify(user_tok, trust.user_issuer_keys, "user")

    def test_expiry_beyond_skew_refused(self):
        keys = _Keys()
        trust = keys.trust()
        # Issued 4000s ago with a 3600s TTL: past nominal expiry + the
        # whole skew window -> refused.
        user_tok, _, _ = _trio(keys, ttl_s=3600,
                               now=self._past(seconds=4000))
        with self.assertRaises(_dt.DelegationExpiredError):
            _verify(user_tok, trust.user_issuer_keys, "user")

    def test_fresh_token_verifies(self):
        keys = _Keys()
        trust = keys.trust()
        user_tok, _, _ = _trio(keys, ttl_s=3600)
        _verify(user_tok, trust.user_issuer_keys, "user")

    def test_authorize_rechecks_expiry_at_use_time(self):
        keys = _Keys()
        # A context bound when the token was fresh refuses at authorize
        # time once the token is past its window (bind() verified
        # signatures; time passes — expiry is checked per action).
        # Issued T-3800, TTL 3600 -> expires T-200.
        issued_ago = self._past(seconds=3800)
        user_tok, agent_tok, deleg_tok = _trio(
            keys, ttl_s=3600, now=issued_ago)
        ctx = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=deleg_tok, parent_chain=[],
            trust=keys.trust(), session_id=_SID).bind(
                # T-100: 100s past expiry, inside the skew window.
                now=self._past(seconds=100))
        with self.assertRaises(_dt.DelegationExpiredError):
            # T+120: 320s past expiry, outside the skew window.
            ctx.authorize(
                "tool:read_file",
                now=datetime.now(timezone.utc) + timedelta(seconds=120))


class BindingTest(unittest.TestCase):
    def test_cross_session_replay_refused(self):
        keys = _Keys()
        trust = keys.trust()
        _, _, deleg_tok = _trio(keys)
        with self.assertRaises(_dt.DelegationBindingError):
            _verify(deleg_tok, trust.human_keys, "delegation",
                    session="sess-other")

    def test_delegation_bound_to_wrong_user_hash_refused(self):
        keys = _Keys()
        ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(keys)
        user_tok2 = _dt.issue_user_token(
            keys.idp[0], "user-7", ["tool:send_email"], _SID)
        tampered = copy.deepcopy(deleg_tok)
        tampered["claims"] = dict(tampered["claims"])
        tampered["claims"]["user_token_hash"] = _dt.token_ref(user_tok2)
        # Re-sign with the human key so the failure is the BINDING, not
        # the signature: a delegation citing a different user token.
        body = {k: v for k, v in tampered.items() if k != "sig"}
        tampered["sig"] = keys.human[0].sign(
            _dt._TOKEN_DOMAIN + _dt._canonical(body)).hex()
        bad_ctx = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=tampered, parent_chain=[],
            trust=keys.trust(), session_id=_SID)
        with self.assertRaises(_dt.DelegationSignatureError) as cm:
            bad_ctx.bind()
        self.assertIn("user_token_hash", str(cm.exception))

    def test_kind_confusion_refused(self):
        keys = _Keys()
        trust = keys.trust()
        _, agent_tok, _ = _trio(keys)
        with self.assertRaises(_dt.DelegationSignatureError):
            _verify(agent_tok, trust.authority_keys, "delegation")


class IntersectionTest(unittest.TestCase):
    def _verdict_allows(self, verdict):
        self.assertTrue(all(verdict["allowed_by"].values()))

    def test_allowed_by_all_three_authorizes(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)
        verdict = ctx.authorize("tool:read_file")
        self._verdict_allows(verdict)
        self.assertEqual(verdict["allowed_by"],
                         {"user": True, "agent": True, "delegation": True})

    def test_delegation_denies_when_user_and_agent_allow(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(
            keys,
            user_scope=("tool:read_file", "tool:send_email"),
            agent_scope=("tool:read_file", "tool:send_email"),
            deleg_scope=("tool:read_file",))
        with self.assertRaises(_dt.DelegationScopeError) as cm:
            ctx.authorize("tool:send_email")
        self.assertIn("delegation", str(cm.exception))

    def test_agent_capability_denies_when_others_allow(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(
            keys,
            user_scope=("tool:read_file", "tool:send_email"),
            agent_scope=("tool:read_file",),
            deleg_scope=("tool:read_file", "tool:send_email"))
        with self.assertRaises(_dt.DelegationScopeError) as cm:
            ctx.authorize("tool:send_email")
        self.assertIn("agent", str(cm.exception))

    def test_user_permission_denies_when_others_allow(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(
            keys,
            user_scope=("tool:read_file",),
            agent_scope=("tool:read_file", "tool:send_email"),
            deleg_scope=("tool:read_file", "tool:send_email"))
        with self.assertRaises(_dt.DelegationScopeError) as cm:
            ctx.authorize("tool:send_email")
        self.assertIn("user", str(cm.exception))

    def test_wildcard_scope_covers_concrete_tool(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(
            keys, user_scope=("tool:*",),
            agent_scope=("tool:read_file",),
            deleg_scope=("tool:read_file",))
        self._verdict_allows(ctx.authorize("tool:read_file"))

    def test_malformed_action_refused(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)
        with self.assertRaises(_dt.DelegationScopeError):
            ctx.authorize("read_file")


class MissingDelegationTest(unittest.TestCase):
    def test_missing_delegation_token_refused_at_bind(self):
        keys = _Keys()
        user_tok, agent_tok, _ = _trio(keys)
        ctx = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=None, parent_chain=[],
            trust=keys.trust(), session_id=_SID)
        with self.assertRaises(_dt.DelegationRequiredError):
            ctx.bind()

    def test_unbound_context_cannot_authorize(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys)
        ctx = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=deleg_tok, parent_chain=[],
            trust=keys.trust(), session_id=_SID)
        with self.assertRaises(_dt.DelegationRequiredError):
            ctx.authorize("tool:read_file")

    def test_none_token_in_chain_verify_refused(self):
        keys = _Keys()
        user_tok, agent_tok, _ = _trio(keys)
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_chain(
                None, [], keys.trust(), user_tok, agent_tok,
                expected_session=_SID)

class SpawnTest(unittest.TestCase):
    def _chain(self, child_ctx, user_tok, agent_tok, deleg_tok):
        return _dt.verify_delegation_chain(
            child_ctx.delegation_token, child_ctx.parent_chain,
            child_ctx.trust, user_tok, agent_tok,
            expected_session=child_ctx.session_id)

    def test_valid_spawn_verifies(self):
        keys = _Keys()
        ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(keys)
        child = ctx.spawn("sub-1", ["tool:read_file"], keys.parent[0])
        self._chain(child, user_tok, agent_tok, deleg_tok)
        verdict = child.authorize("tool:read_file")
        self.assertTrue(all(verdict["allowed_by"].values()))
        self.assertEqual(child._leaf_claims["delegation_depth"], 1)
        self.assertEqual(child._leaf_claims["parent_token_hash"],
                         _dt.token_ref(deleg_tok))
        # The user/agent token hashes are inherited: the chain records
        # the full path back to the originating user.
        self.assertEqual(child._leaf_claims["user_token_hash"],
                         _dt.token_ref(user_tok))
        self.assertEqual(child._leaf_claims["agent_token_hash"],
                         _dt.token_ref(agent_tok))

    def test_spawn_scope_escalation_refused_at_issuance(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)
        with self.assertRaises(_dt.DelegationAttenuationError):
            ctx.spawn("sub-1", ["tool:send_email"], keys.parent[0])

    def test_spawn_with_unregistered_parent_key_refused(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)
        attacker = _dt.generate_test_keypair()
        # spawn() binds the child immediately, so the forgery dies at
        # spawn time: the attacker's key id is not the
        # session-registered parent key. Issuance never consults the
        # roster (it can't); verification always does.
        with self.assertRaises(_dt.DelegationSignatureError) as cm:
            ctx.spawn("sub-1", ["tool:read_file"], attacker[0])
        self.assertIn("parent-signature swap", str(cm.exception))

    def test_parent_signature_swap_fails_chain_verify(self):
        keys = _Keys()
        ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(keys)
        # A sibling session's delegation token: a valid token from a
        # different chain.
        _, (_, _, deleg_tok_b) = _bound_ctx(keys)
        # Forge a child that is correctly parent-SIGNED but cites the
        # SIBLING as its parent: the parent-hash pointer must match the
        # ACTUAL presented parent, so splicing chains is refused.
        now = datetime.now(timezone.utc)
        body = {
            "token_version": _dt.TOKEN_VERSION,
            "token_kind": "delegation",
            "issuer": keys.parent[0].key_id,
            "subject": "sub-1",
            "issued_at": now.isoformat(),
            "not_before": now.isoformat(),
            "expires_at": (now + timedelta(seconds=3600)).isoformat(),
            "session_id": _SID,
            "claims": {
                "delegator": "agent-1",
                "user_token_hash": _dt.token_ref(user_tok),
                "agent_token_hash": _dt.token_ref(agent_tok),
                "scope": ["tool:read_file"],
                "revocation_endpoint": _REVOKE_URI,
                "audit_urls": [],
                "delegation_depth": 1,
                "parent_token_hash": _dt.token_ref(deleg_tok_b),
            },
        }
        body["sig"] = keys.parent[0].sign(
            _dt._TOKEN_DOMAIN + _dt._canonical(body)).hex()
        with self.assertRaises(_dt.DelegationSignatureError) as cm:
            _dt.verify_delegation_chain(
                body, [deleg_tok], keys.trust(), user_tok, agent_tok,
                expected_session=_SID)
        self.assertIn("parent_token_hash", str(cm.exception))

    def test_tampered_child_depth_fails_chain_verify(self):
        keys = _Keys()
        ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(keys)
        child = ctx.spawn("sub-1", ["tool:read_file"], keys.parent[0])
        tampered = copy.deepcopy(child.delegation_token)
        tampered["claims"] = dict(tampered["claims"])
        tampered["claims"]["delegation_depth"] = 5
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_chain(
                tampered, child.parent_chain, keys.trust(), user_tok,
                agent_tok, expected_session=_SID)

    def test_child_scope_wider_than_parent_fails_chain_verify(self):
        keys = _Keys()
        ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(
            keys, deleg_scope=("tool:read_file",))
        # Even a correctly parent-SIGNED child with a wider scope than
        # its parent is refused at chain verification: monotonicity is
        # re-checked by the verifier, not trusted from the issuer.
        now = datetime.now(timezone.utc)
        body = {
            "token_version": _dt.TOKEN_VERSION,
            "token_kind": "delegation",
            "issuer": keys.parent[0].key_id,
            "subject": "sub-1",
            "issued_at": now.isoformat(),
            "not_before": now.isoformat(),
            "expires_at": (now + timedelta(seconds=3600)).isoformat(),
            "session_id": _SID,
            "claims": {
                "delegator": "agent-1",
                "user_token_hash": _dt.token_ref(user_tok),
                "agent_token_hash": _dt.token_ref(agent_tok),
                "scope": ["tool:read_file", "tool:send_email"],
                "revocation_endpoint": _REVOKE_URI,
                "audit_urls": [],
                "delegation_depth": 1,
                "parent_token_hash": _dt.token_ref(deleg_tok),
            },
        }
        body["sig"] = keys.parent[0].sign(
            _dt._TOKEN_DOMAIN + _dt._canonical(body)).hex()
        with self.assertRaises(_dt.DelegationAttenuationError):
            _dt.verify_delegation_chain(
                body, [deleg_tok], keys.trust(), user_tok, agent_tok,
                expected_session=_SID)

    def test_depth_cap_enforced(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)
        cur = ctx
        for i in range(_dt.MAX_DELEGATION_DEPTH):
            cur = cur.spawn("sub-%d" % i, ["tool:read_file"],
                            keys.parent[0])
        self.assertEqual(cur._leaf_claims["delegation_depth"],
                         _dt.MAX_DELEGATION_DEPTH)
        with self.assertRaises(_dt.DelegationAttenuationError):
            cur.spawn("sub-too-deep", ["tool:read_file"],
                      keys.parent[0])

    def test_spawn_requires_bound_parent(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys)
        unbound = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=deleg_tok, parent_chain=[],
            trust=keys.trust(), session_id=_SID)
        with self.assertRaises(_dt.DelegationRequiredError):
            unbound.spawn("sub-1", ["tool:read_file"], keys.parent[0])


class RevocationTest(unittest.TestCase):
    def test_revoked_leaf_refused_at_authorize(self):
        keys = _Keys()
        ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(keys)
        ledger = _dt.RevocationLedger()
        ledger.revoke(deleg_tok)
        with self.assertRaises(_dt.DelegationRevokedError):
            ctx.authorize("tool:read_file", revocation_checker=ledger)

    def test_revoked_parent_invalidates_child(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)
        child = ctx.spawn("sub-1", ["tool:read_file"], keys.parent[0])
        ledger = _dt.RevocationLedger()
        ledger.revoke(ctx.delegation_token)
        with self.assertRaises(_dt.DelegationRevokedError):
            child.authorize("tool:read_file",
                            revocation_checker=ledger)

    def test_checker_error_fails_closed(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)

        def broken(ref):
            raise IOError("revocation service down")

        with self.assertRaises(_dt.DelegationRevokedError):
            ctx.authorize("tool:read_file", revocation_checker=broken)

    def test_no_checker_defaults_to_ttl_only(self):
        keys = _Keys()
        ctx, _ = _bound_ctx(keys)
        verdict = ctx.authorize("tool:read_file")
        self.assertTrue(all(verdict["allowed_by"].values()))

class ProvenanceV2Test(unittest.TestCase):
    def _refs(self, keys):
        user_tok, agent_tok, deleg_tok = _trio(keys)
        return _dt.hop_token_refs(user_tok, agent_tok, deleg_tok)

    def _v2_delegation(self, keys):
        refs = self._refs(keys)
        return _prov.build_delegation([
            {"kind": "principal", "ref": "user-7", "tokens": dict(refs)},
            {"kind": "agent", "ref": "agent-1", "tokens": dict(refs)},
        ])

    def test_v2_filled_tokens_validate(self):
        keys = _Keys()
        d = self._v2_delegation(keys)
        self.assertEqual(d["delegation_schema_version"], 2)
        self.assertEqual(_prov.validate_delegation(d), [])

    def test_v1_null_tokens_still_verify(self):
        d = _prov.build_delegation([
            {"kind": "principal", "ref": "user-7"},
            {"kind": "agent", "ref": "agent-1"},
        ])
        self.assertEqual(d["delegation_schema_version"], 1)
        self.assertEqual(_prov.validate_delegation(d), [])

    def test_v1_with_filled_tokens_rejected(self):
        keys = _Keys()
        refs = self._refs(keys)
        d = _prov.build_delegation([
            {"kind": "principal", "ref": "user-7"},
            {"kind": "agent", "ref": "agent-1"},
        ])
        d["hops"][1]["tokens"] = dict(refs)  # 4th-shape smuggling on v1
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("must be null on v1" in e for e in errors))

    def test_v2_with_null_tokens_rejected(self):
        keys = _Keys()
        d = self._v2_delegation(keys)
        d["hops"][0]["tokens"] = None
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("hops[0]" in e for e in errors))

    def test_v2_unknown_version_fails_closed(self):
        keys = _Keys()
        d = self._v2_delegation(keys)
        d["delegation_schema_version"] = 3
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("unknown" in e for e in errors))

    def test_v2_extra_field_rejected_as_fourth_shape(self):
        keys = _Keys()
        d = self._v2_delegation(keys)
        d["hops"][1]["tokens"]["session_token_ref"] = "00" * 32
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("unknown fields" in e for e in errors))

    def test_v2_wrong_schema_marker_rejected(self):
        keys = _Keys()
        d = self._v2_delegation(keys)
        d["hops"][0]["tokens"]["tokens_schema"] = "custom-shape/v9"
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("tokens_schema" in e for e in errors))

    def test_v2_malformed_ref_rejected(self):
        keys = _Keys()
        d = self._v2_delegation(keys)
        d["hops"][1]["tokens"]["user_token_ref"] = "not-a-hash"
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("user_token_ref" in e for e in errors))

    def test_v2_truncation_still_breaks_binds(self):
        keys = _Keys()
        d = self._v2_delegation(keys)
        d["hops"][1]["binds"] = "00" * 32
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("binds mismatch" in e for e in errors))

    def test_v2_middle_hop_drop_breaks_binds(self):
        keys = _Keys()
        refs = self._refs(keys)
        d = _prov.build_delegation([
            {"kind": "principal", "ref": "user-7", "tokens": dict(refs)},
            {"kind": "agent", "ref": "agent-1", "tokens": dict(refs)},
            {"kind": "sub-agent", "ref": "sub-1", "tokens": dict(refs)},
        ])
        d["hops"] = [d["hops"][0], d["hops"][2]]  # drop the middle hop
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("binds mismatch" in e for e in errors))

    def test_v2_token_ref_tamper_breaks_binds(self):
        keys = _Keys()
        refs = self._refs(keys)
        d = _prov.build_delegation([
            {"kind": "principal", "ref": "user-7", "tokens": dict(refs)},
            {"kind": "agent", "ref": "agent-1", "tokens": dict(refs)},
            {"kind": "sub-agent", "ref": "sub-1", "tokens": dict(refs)},
        ])
        # Tamper a NON-terminal hop's tokens: its successor's binds
        # pointer commits to this hop's content, so the edit is
        # detected. (binds points backward — the terminal hop's own
        # content is anchored by the outer record/log hash chain, not
        # by a successor's binds pointer; that is the documented
        # wave-73 binds property, preserved unchanged.)
        d["hops"][1]["tokens"]["delegation_token_ref"] = "ff" * 32
        errors = _prov.validate_delegation(d)
        self.assertTrue(any("binds mismatch" in e for e in errors))

    def test_slot_carries_refs_never_secrets(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys)
        refs = _dt.hop_token_refs(user_tok, agent_tok, deleg_tok)
        blob = str(refs)
        for tok in (user_tok, agent_tok, deleg_tok):
            self.assertNotIn(tok["sig"], blob)
        self.assertEqual(refs["user_token_ref"],
                         _dt.token_ref(user_tok))
        self.assertEqual(refs["agent_token_ref"],
                         _dt.token_ref(agent_tok))
        self.assertEqual(refs["delegation_token_ref"],
                         _dt.token_ref(deleg_tok))
        self.assertEqual(refs["tokens_schema"], _dt.TOKENS_SCHEMA)


class ExecutorGateTest(unittest.TestCase):
    _ALLOW_ALL = """\
version: 2
roles:
  scout: [read_file, api_call, send_email]
policies:
  - id: allow-all
    effect: allow
    match:
      tool: [read_file, api_call, send_email]
    reason: allow-all fixture
"""

    def _executor(self, keys, agent_id="agent-1", install_gate=True,
                  **trio_kw):
        """Build an executor whose run id IS the delegation session.

        The gate binds the delegation context to the run: cross-run
        token use is replay, so the honest fixture mints the identity
        first and issues the tokens for that run's session.
        """
        run_dir = Path(tempfile.mkdtemp(prefix="govw74-"))
        policy_path = run_dir / "policy.yaml"
        policy_path.write_text(self._ALLOW_ALL)
        policy = PolicyEngine(str(policy_path))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, approvals,
                          ledger_path=run_dir / "egress_ledger.jsonl")
        identity = ex.mint_identity(agent_id, "scout", "user-7")
        ctx = None
        if install_gate:
            trio_kw.setdefault("session", identity.run_id)
            user_tok, agent_tok, deleg_tok = _trio(keys, **trio_kw)
            ctx = _dt.DelegationContext(
                user_token=user_tok, agent_token=agent_tok,
                delegation_token=deleg_tok, parent_chain=[],
                trust=keys.trust(),
                session_id=trio_kw["session"]).bind()
            ex._delegation_context = ctx
        return ex, identity, run_dir, ctx

    def _denied_tool_calls(self, run_dir):
        return [e for e in read_entries(run_dir / "actions.jsonl")
                if e.get("event") == "tool_call"
                and e.get("decision") == "denied"]

    def test_valid_context_executes_under_allow_all(self):
        keys = _Keys()
        ex, identity, _, _ = self._executor(
            keys, deleg_scope=("tool:read_file",))
        r = ex.call(identity, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "executed")

    def test_missing_delegation_fails_closed_despite_allow_all(self):
        # THE construction proof: policy says allow-all, but the
        # delegation gate runs in CODE before policy evaluation — no
        # policy YAML edit can disable it.
        keys = _Keys()
        run_dir = Path(tempfile.mkdtemp(prefix="govw74-"))
        policy_path = run_dir / "policy.yaml"
        policy_path.write_text(self._ALLOW_ALL)
        log = ActionLog(run_dir / "actions.jsonl")
        ex = ToolExecutor(
            run_dir, PolicyEngine(str(policy_path)), log,
            ApprovalQueue(run_dir, log),
            ledger_path=run_dir / "egress_ledger.jsonl")
        identity = ex.mint_identity("agent-1", "scout", "user-7")
        user_tok, agent_tok, _ = _trio(keys, session=identity.run_id)
        ctx = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=None, parent_chain=[],
            trust=keys.trust(), session_id=identity.run_id)
        ex._delegation_context = ctx  # installed but unbound: no token
        with self.assertRaises(_dt.DelegationRequiredError):
            ex.call(identity, "read_file", path="notes.txt")
        denied = self._denied_tool_calls(run_dir)
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["policy_id"], "delegation-required")
        self.assertEqual(denied[0]["flag"], "delegation_gate_refused")
        # The tool never executed.
        self.assertEqual(ex._executed.get("read_file", 0), 0)

    def test_scope_denied_despite_allow_all(self):
        keys = _Keys()
        ex, identity, run_dir, _ = self._executor(
            keys, deleg_scope=("tool:read_file",))
        with self.assertRaises(_dt.DelegationScopeError):
            ex.call(identity, "send_email", to="x@y.z",
                    subject="hi", body="hi")
        denied = self._denied_tool_calls(run_dir)
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["policy_id"], "delegation-required")
        self.assertEqual(ex._executed.get("send_email", 0), 0)

    def test_policy_role_still_narrows_a_valid_context(self):
        # The gate filters; policy narrows further. write_file is in
        # every token's scope but NOT in role scout's allowlist: the
        # gate authorizes, the role check denies.
        keys = _Keys()
        wide = ("tool:read_file", "tool:write_file")
        ex, identity, run_dir, _ = self._executor(
            keys, user_scope=wide, agent_scope=wide,
            deleg_scope=wide)
        r = ex.call(identity, "write_file", path="notes.txt",
                    content="hello")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "role-allowlist")
        denied = self._denied_tool_calls(run_dir)
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["policy_id"], "role-allowlist")

    def test_gate_absent_keeps_pre_wave74_behavior(self):
        # Opt-in: no installed context = zero behavior change for
        # existing callers.
        keys = _Keys()
        ex, identity, _, _ = self._executor(keys, install_gate=False)
        r = ex.call(identity, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "executed")

    def test_sibling_cannot_borrow_delegation(self):
        # The gate binds the acting identity to the leaf delegation's
        # subject: agent-2 cannot ride agent-1's context in the same run.
        keys = _Keys()
        ex, identity, run_dir, _ = self._executor(
            keys, deleg_scope=("tool:read_file",))
        sibling = ex.mint_identity("agent-2", "scout", "user-7")
        with self.assertRaises(_dt.DelegationBindingError):
            ex.call(sibling, "read_file", path="notes.txt")
        denied = self._denied_tool_calls(run_dir)
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["flag"], "delegation_gate_refused")
        self.assertEqual(ex._executed.get("read_file", 0), 0)

    def test_cross_run_token_use_refused(self):
        # A context bound to another session is replay at the gate,
        # even when the acting identity is properly minted here.
        keys = _Keys()
        ex, identity, run_dir, _ = self._executor(
            keys, deleg_scope=("tool:read_file",),
            session="sess-someone-elses-run")
        with self.assertRaises(_dt.DelegationBindingError):
            ex.call(identity, "read_file", path="notes.txt")
        denied = self._denied_tool_calls(run_dir)
        self.assertEqual(len(denied), 1)
        self.assertEqual(ex._executed.get("read_file", 0), 0)


if __name__ == "__main__":
    unittest.main()

class OpenDelegatedSessionTest(unittest.TestCase):
    def test_root_session_chains_refs(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys)
        ctx, delegation = _prov.open_delegated_session(
            user_tok, agent_tok, deleg_tok, keys.trust(), _SID)
        self.assertTrue(ctx.bound)
        self.assertEqual(delegation["delegation_schema_version"], 2)
        self.assertEqual(_prov.validate_delegation(delegation), [])
        hops = delegation["hops"]
        self.assertEqual([h["kind"] for h in hops],
                         ["principal", "agent"])
        self.assertEqual(hops[0]["ref"], "user:user-7")
        self.assertEqual(hops[1]["ref"], "agent:agent-1")
        for hop in hops:
            self.assertEqual(
                hop["tokens"]["user_token_ref"],
                _dt.token_ref(user_tok))
            self.assertEqual(
                hop["tokens"]["agent_token_ref"],
                _dt.token_ref(agent_tok))
            self.assertEqual(
                hop["tokens"]["delegation_token_ref"],
                _dt.token_ref(deleg_tok))

    def test_spawned_session_chains_sub_agent_hop(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys)
        root_ctx = _dt.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=deleg_tok, parent_chain=[],
            trust=keys.trust(), session_id=_SID).bind()
        child = root_ctx.spawn("sub-1", ["tool:read_file"],
                               keys.parent[0])
        ctx, delegation = _prov.open_delegated_session(
            user_tok, agent_tok, child.delegation_token, keys.trust(),
            _SID, parent_chain=[deleg_tok])
        self.assertTrue(ctx.bound)
        self.assertEqual(_prov.validate_delegation(delegation), [])
        hops = delegation["hops"]
        self.assertEqual([h["kind"] for h in hops],
                         ["principal", "agent", "sub-agent"])
        self.assertEqual(hops[2]["ref"], "agent:sub-1")
        # The sub-agent hop carries its OWN delegation token's ref;
        # user/agent refs are inherited from the session root.
        self.assertEqual(
            hops[2]["tokens"]["delegation_token_ref"],
            _dt.token_ref(child.delegation_token))
        self.assertEqual(
            hops[2]["tokens"]["user_token_ref"],
            _dt.token_ref(user_tok))

    def test_open_refuses_unverifiable_chain(self):
        keys = _Keys()
        user_tok, agent_tok, deleg_tok = _trio(keys)
        tampered = copy.deepcopy(deleg_tok)
        tampered["claims"] = dict(tampered["claims"])
        tampered["claims"]["scope"] = ["tool:*"]
        with self.assertRaises(_dt.DelegationError):
            _prov.open_delegated_session(
                user_tok, agent_tok, tampered, keys.trust(), _SID)


if __name__ == "__main__":
    unittest.main()
