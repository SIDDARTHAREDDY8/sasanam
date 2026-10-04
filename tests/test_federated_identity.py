"""Unit tests for gov/federated_identity (wave-325 lane 2).

Federated agent identity via the dex pattern, without the dex server:
short-lived Ed25519-signed identity tokens, a rotation-aware verifier
with pinned issuer keys, a token-backed PrincipalRegistry, and the
ToolExecutor federated-mode integration. Deterministic: fixed seeds
and injected clocks throughout.

The wave-243 lesson is pinned here: gov.ed25519.verify returns
True/False and never raises -- the wrapper must CHECK the return,
never assume it raises.
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from gov import ed25519 as _ed
from gov import federated_identity as fi
from gov.federated_identity import (FederatedIdentityError, TokenIssuer,
                                    TokenVerifier,
                                    TokenBackedPrincipalRegistry,
                                    VerifiedTokenClaims)
from gov.identity import (IdentityTokenError, UnregisteredPrincipalError,
                          UnregisteredRoleError)

ISSUER_SEED = bytes(range(32))
ISSUER_SEED2 = bytes([255 - i for i in range(32)])
AGENT_SEED = bytes([(i * 7) % 256 for i in range(32)])
EVIL_SEED = bytes([(i * 29 + 5) % 256 for i in range(32)])
NOW = 1800000000.0
AUD = "sasanam-policy-engine"


def _agent_pub():
    return _ed.publickey(AGENT_SEED).hex()


def _issuer(seed=ISSUER_SEED, issuer_id="test-issuer", **kw):
    return TokenIssuer(seed, issuer_id, **kw)


def _verifier(**kw):
    v = TokenVerifier(AUD, **kw)
    v.add_issuer("test-issuer", _ed.publickey(ISSUER_SEED).hex())
    return v


def _issue(issuer=None, now=NOW, **kw):
    args = dict(agent_id="agent-7", principal="ops", role="reader",
                agent_pubkey_hex=_agent_pub(), scopes=("read", "write"),
                now=now)
    args.update(kw)
    return (issuer or _issuer()).issue_token(**args)


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Ed25519ContractTest(unittest.TestCase):
    """Wave-243 lesson: pin the bool-returning verify() contract."""

    def test_verify_returns_true_for_good_signature(self):
        sig = _ed.sign(AGENT_SEED, b"contract")
        self.assertIs(_ed.verify(_ed.publickey(AGENT_SEED), b"contract",
                                 sig), True)

    def test_verify_returns_false_for_forged_signature(self):
        sig = _ed.sign(AGENT_SEED, b"contract")
        self.assertIs(_ed.verify(_ed.publickey(EVIL_SEED), b"contract",
                                 sig), False)


class IssueTest(unittest.TestCase):
    def test_round_trip_claims(self):
        token = _issue()
        claims = _verifier().verify_token(token, now=NOW)
        self.assertEqual(claims["iss"], "test-issuer")
        self.assertEqual(claims["sub"], "agent-7")
        self.assertEqual(claims["aud"], AUD)
        self.assertEqual(claims["principal"], "ops")
        self.assertEqual(claims["role"], "reader")
        self.assertEqual(claims["agent_scope"], "read write")
        self.assertEqual(claims["exp"] - claims["iat"], 300)
        self.assertEqual(len(claims["jti"]), 32)

    def test_scopes_required_nonempty(self):
        for bad in ([], ["", " "], "", None):
            with self.assertRaises(ValueError):
                _issue(scopes=bad)

    def test_ttl_capped_at_issuer_max(self):
        with self.assertRaises(ValueError):
            _issue(ttl_seconds=10 ** 9)
        with self.assertRaises(ValueError):
            _issue(ttl_seconds=0)

    def test_bad_agent_pubkey_refused_at_issue(self):
        for bad in ("", "zz" * 32, "ab" * 31, None):
            with self.assertRaises(ValueError):
                _issue(agent_pubkey_hex=bad)

    def test_bad_seed_refused(self):
        with self.assertRaises(ValueError):
            TokenIssuer(b"short", "x")

    def test_nonce_unique_per_issue(self):
        claims = [_verifier().verify_token(_issue(), now=NOW)
                  for _ in range(2)]
        # fresh verifiers per issue (replay cache is per-instance)
        self.assertNotEqual(claims[0]["jti"], claims[1]["jti"])


class VerifyFailureTest(unittest.TestCase):
    def _code(self, token, **kw):
        try:
            _verifier(**kw.pop("vkw", {})).verify_token(token, now=NOW,
                                                        **kw)
        except FederatedIdentityError as exc:
            return exc.code
        self.fail("expected FederatedIdentityError, token verified")

    def test_forged_signature(self):
        p1, p2, p3 = _issue().split(".")
        body = json.loads(base64.urlsafe_b64decode(p2 + "=="))
        body["role"] = "admin"
        p2f = _b64u(json.dumps(body, sort_keys=True,
                               separators=(",", ":")).encode())
        self.assertEqual(self._code(p1 + "." + p2f + "." + p3),
                         "identity-token-tampered")

    def test_unknown_issuer(self):
        token = _issue(issuer=_issuer(EVIL_SEED, issuer_id="evil"))
        self.assertEqual(self._code(token), "identity-token-issuer-unknown")

    def test_unknown_issuer_key_for_known_issuer(self):
        # Issuer pinned, but token carries an unknown kid: refused,
        # never silently accepted.
        evil = _issuer(EVIL_SEED)  # same iss id, different key
        token = _issue(issuer=evil)
        self.assertEqual(self._code(token), "identity-token-issuer-unknown")

    def test_expired(self):
        self.assertEqual(self._code(_issue(now=NOW - 600)),
                         "identity-token-expired")

    def test_future_issued(self):
        self.assertEqual(self._code(_issue(now=NOW + 3600)),
                         "identity-token-not-yet-valid")

    def test_audience_mismatch(self):
        self.assertEqual(self._code(_issue(audience="elsewhere")),
                         "identity-token-audience-mismatch")

    def test_ttl_exceeded(self):
        token = _issue(ttl_seconds=300)
        self.assertEqual(
            self._code(token, vkw={"max_ttl_seconds": 60}),
            "identity-token-ttl-exceeded")

    def test_key_binding_mismatch(self):
        evil_pub = _ed.publickey(EVIL_SEED).hex()
        self.assertEqual(
            self._code(_issue(), expected_key_binding=evil_pub),
            "identity-token-key-binding-mismatch")

    def test_key_binding_match_ok(self):
        claims = _verifier().verify_token(
            _issue(), now=NOW, expected_key_binding=_agent_pub())
        self.assertEqual(claims["sub"], "agent-7")

    def test_malformed_shapes(self):
        bad_json = (_b64u(b'{"alg":"EdDSA"}') + "." + _b64u(b"nope")
                    + "." + _b64u(b"\x00" * 64))
        wrong_alg = (_b64u(json.dumps(
            {"alg": "none", "typ": "sasanam-id-token", "v": 1}).encode())
            + "." + _b64u(b"{}") + "." + _b64u(b"\x00" * 64))
        for bad in ("", "abc", "a.b", "a.b.c.d", "!!!.!!!.!!!",
                    bad_json, wrong_alg):
            self.assertEqual(self._code(bad), "identity-token-malformed",
                             "shape %r" % (bad[:20],))

    def test_within_skew_ok(self):
        # iat/exp within the 60s skew still verify at the boundary.
        token = _issue(now=NOW - 30)
        claims = _verifier().verify_token(token, now=NOW)
        self.assertEqual(claims["sub"], "agent-7")

    def test_expired_beyond_skew_refused(self):
        token = _issue(now=NOW - 361)  # exp = NOW-61, skew 60
        self.assertEqual(self._code(token), "identity-token-expired")


class ReplayTest(unittest.TestCase):
    def test_second_present_replays(self):
        v = _verifier()
        token = _issue()
        v.verify_token(token, now=NOW)
        try:
            v.verify_token(token, now=NOW)
        except FederatedIdentityError as exc:
            self.assertEqual(exc.code, "identity-token-replayed")
            return
        self.fail("replay verified")

    def test_replay_cache_evicts_expired(self):
        v = _verifier()
        t1 = _issue(ttl_seconds=60)
        t2 = _issue(ttl_seconds=60)
        v.verify_token(t1, now=NOW)
        # After t1's expiry + skew, the entry is evicted -- but the
        # token is expired too, so it refuses as expired, not replayed.
        try:
            v.verify_token(t1, now=NOW + 300)
        except FederatedIdentityError as exc:
            self.assertEqual(exc.code, "identity-token-expired")
        # A fresh token still verifies (cache healthy).
        claims = v.verify_token(t2, now=NOW + 10)
        self.assertEqual(claims["sub"], "agent-7")

    def test_distinct_jtis_independent(self):
        v = _verifier()
        for _ in range(3):
            claims = v.verify_token(_issue(), now=NOW)
            self.assertEqual(claims["sub"], "agent-7")


class RotationTest(unittest.TestCase):
    def _rotated(self, retired_at):
        v = _verifier(rotation_grace_seconds=3600)
        old_token = _issue(now=NOW - 100)
        v.rotate_issuer("test-issuer", _ed.publickey(ISSUER_SEED2).hex(),
                        now=retired_at)
        return v, old_token

    def test_old_key_verifies_during_grace(self):
        v, old_token = self._rotated(NOW)  # retired just now
        claims = v.verify_token(old_token, now=NOW)
        self.assertEqual(claims["sub"], "agent-7")

    def test_old_key_refused_after_grace(self):
        v, old_token = self._rotated(NOW - 7200)  # retired 2h ago
        try:
            v.verify_token(old_token, now=NOW)
        except FederatedIdentityError as exc:
            self.assertEqual(exc.code, "identity-issuer-key-retired")
            return
        self.fail("retired key verified after grace")

    def test_new_key_issues_and_verifies(self):
        v, _ = self._rotated(NOW)
        issuer2 = TokenIssuer(ISSUER_SEED2, "test-issuer")
        token = _issue(issuer=issuer2)
        claims = v.verify_token(token, now=NOW)
        self.assertEqual(claims["sub"], "agent-7")

    def test_rotate_unknown_issuer_is_deployment_error(self):
        with self.assertRaises(ValueError):
            _verifier().rotate_issuer("nope", _ed.publickey(
                ISSUER_SEED2).hex())

    def test_rotate_now_validated(self):
        # A non-numeric now is a deployment error at rotation time,
        # not a TypeError at token-verify time.
        v = _verifier()
        for bad in ("now", object(), True):
            with self.assertRaises(ValueError):
                v.rotate_issuer("test-issuer", _ed.publickey(
                    ISSUER_SEED2).hex(), now=bad)

    def test_add_issuer_twice_is_deployment_error(self):
        with self.assertRaises(ValueError):
            _verifier().add_issuer("test-issuer", _agent_pub())

    def test_unknown_kid_never_silently_accepted(self):
        # A token whose kid matches neither current nor previous key
        # refuses as unknown-issuer even during a rotation overlap.
        v, _ = self._rotated(NOW)
        third = TokenIssuer(bytes([9] * 32), "test-issuer")
        token = _issue(issuer=third)
        try:
            v.verify_token(token, now=NOW)
        except FederatedIdentityError as exc:
            self.assertEqual(exc.code, "identity-token-issuer-unknown")
            return
        self.fail("unknown kid silently accepted")


class DomainSeparationTest(unittest.TestCase):
    def test_decision_packet_signature_does_not_verify_as_token(self):
        # The _SIGN_DOMAIN prefix means a signature minted for another
        # envelope (e.g. decision packets) cannot be replayed as an
        # identity token, and vice versa.
        p1, p2, _ = _issue().split(".")
        forged = p1 + "." + p2 + "." + _b64u(
            _ed.sign(ISSUER_SEED, (p1 + "." + p2).encode()))
        try:
            _verifier().verify_token(forged, now=NOW)
        except FederatedIdentityError as exc:
            self.assertEqual(exc.code, "identity-token-tampered")
            return
        self.fail("cross-domain signature verified")

    def test_kid_matches_issuer_key_id(self):
        p1, p2, _ = _issue().split(".")
        payload = json.loads(base64.urlsafe_b64decode(p2 + "=="))
        from gov.signing import ed25519_key_id
        self.assertEqual(payload["kid"],
                         ed25519_key_id(_ed.publickey(ISSUER_SEED)))


class TokenBackedRegistryTest(unittest.TestCase):
    def _registry(self):
        reg = TokenBackedPrincipalRegistry(_verifier())
        reg.present_token(_issue(), now=NOW)
        return reg

    def test_check_identity_bound_tuple(self):
        reg = self._registry()
        self.assertTrue(reg.check_identity("ops", "reader", "agent-7"))
        self.assertTrue(reg.check("ops"))
        self.assertEqual(reg.registered(), {"ops"})
        self.assertEqual(reg.allowed_roles("ops"), {"reader"})

    def test_wrong_role(self):
        reg = self._registry()
        with self.assertRaises(UnregisteredRoleError):
            reg.check_identity("ops", "admin", "agent-7")

    def test_wrong_principal(self):
        reg = self._registry()
        with self.assertRaises(UnregisteredPrincipalError):
            reg.check_identity("evilcorp", "reader", "agent-7")
        with self.assertRaises(UnregisteredPrincipalError):
            reg.check("evilcorp")

    def test_wrong_agent_id(self):
        reg = self._registry()
        with self.assertRaises(UnregisteredPrincipalError):
            reg.check_identity("ops", "reader", "agent-8")

    def test_no_token_refuses(self):
        reg = TokenBackedPrincipalRegistry(_verifier())
        with self.assertRaises(UnregisteredPrincipalError):
            reg.check_identity("ops", "reader", "agent-7")
        self.assertEqual(reg.registered(), set())

    def test_cleared_token_refuses(self):
        reg = self._registry()
        reg.clear_token()
        with self.assertRaises(UnregisteredPrincipalError):
            reg.check_identity("ops", "reader", "agent-7")

    def test_present_forged_token_refuses_nothing_cached(self):
        reg = TokenBackedPrincipalRegistry(_verifier())
        p1, p2, p3 = _issue().split(".")
        body = json.loads(base64.urlsafe_b64decode(p2 + "=="))
        body["role"] = "admin"
        p2f = _b64u(json.dumps(body, sort_keys=True,
                               separators=(",", ":")).encode())
        with self.assertRaises(FederatedIdentityError):
            reg.present_token(p1 + "." + p2f + "." + p3, now=NOW)
        with self.assertRaises(UnregisteredPrincipalError):
            reg.check_identity("ops", "reader", "agent-7")

    def test_interface_parity_with_principal_registry(self):
        from gov.identity import PrincipalRegistry
        for name in ("check", "check_identity", "allowed_roles",
                     "registered"):
            self.assertTrue(callable(getattr(PrincipalRegistry, name)),
                            name)
            self.assertTrue(callable(getattr(TokenBackedPrincipalRegistry,
                                             name)), name)

    def test_rejects_non_verifier(self):
        with self.assertRaises(ValueError):
            TokenBackedPrincipalRegistry(object())


class ExecutorFederatedModeTest(unittest.TestCase):
    _ALLOW_ALL = ("version: 2\nroles:\n  operator: [read_file]\n"
                  "policies:\n  - id: allow-all\n    effect: allow\n"
                  "    match:\n      tool: [read_file]\n"
                  "    reason: dexid fixture\n")

    def _live_issue(self, **kw):
        # The executor verifies with wall-clock time, so tokens for
        # executor probes are issued at wall-clock time, not the fixed
        # NOW used by the pure unit tests.
        import time as _time
        return _issue(now=_time.time(), **kw)

    def _executor(self, token_verifier=None):
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        run_dir = Path(tempfile.mkdtemp(prefix="govdexid-"))
        (run_dir / "policy.yaml").write_text(self._ALLOW_ALL)
        policy = PolicyEngine(str(run_dir / "policy.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        kw = dict(ledger_path=run_dir / "egress_ledger.jsonl",
                  ungoverned_ack="dexid test: synthetic executor")
        if token_verifier is not None:
            kw["token_verifier"] = token_verifier
        return ToolExecutor(run_dir, policy, log, approvals, **kw)

    def test_federated_mode_tokenless_refused(self):
        ex = self._executor(token_verifier=_verifier())
        with self.assertRaises(IdentityTokenError) as ctx:
            ex.mint_identity("agent-7", "reader", "ops")
        self.assertEqual(ctx.exception.code, "identity-token-required")

    def test_federated_mode_string_token_mints(self):
        ex = self._executor(token_verifier=_verifier())
        ident = ex.mint_identity("agent-7", "reader", "ops",
                                 token_claims=self._live_issue())
        self.assertEqual(ident.agent_id, "agent-7")
        self.assertEqual(ident.role, "reader")
        self.assertEqual(ident.principal, "ops")
        self.assertEqual(ident.provenance, "minted")

    def test_federated_mode_forged_token_refused(self):
        ex = self._executor(token_verifier=_verifier())
        p1, p2, p3 = self._live_issue().split(".")
        body = json.loads(base64.urlsafe_b64decode(p2 + "=="))
        body["role"] = "admin"
        p2f = _b64u(json.dumps(body, sort_keys=True,
                               separators=(",", ":")).encode())
        with self.assertRaises(IdentityTokenError):
            ex.mint_identity("agent-7", "admin", "ops",
                             token_claims=p1 + "." + p2f + "." + p3)

    def test_federated_mode_role_escalation_refused(self):
        # A valid reader token cannot mint an admin identity: the
        # pre-existing token-agreement check binds the verified claims.
        ex = self._executor(token_verifier=_verifier())
        with self.assertRaises(IdentityTokenError):
            ex.mint_identity("agent-7", "admin", "ops",
                             token_claims=self._live_issue())

    def test_legacy_mode_unchanged(self):
        # No verifier configured: pre-wave-325 behavior byte-identical.
        ex = self._executor()
        ident = ex.mint_identity("agent-7", "reader", "ops")
        self.assertEqual(ident.agent_id, "agent-7")
        self.assertEqual(ident.role, "reader")
        self.assertEqual(ident.principal, "ops")
        self.assertEqual(ident.provenance, "minted")

    def test_token_verifier_type_checked_at_construction(self):
        with self.assertRaises(ValueError):
            self._executor(token_verifier=object())


class F411ClosureTest(ExecutorFederatedModeTest):
    """F411: a plain-dict token_claims is unverified by construction and
    must never mint in federated mode. Only VerifiedTokenClaims from
    the deployment's own verifier (or the raw token string) is honored.
    """

    def test_forged_dict_refused_coded(self):
        # F411's exact reproduction: a forged dict with no signature
        # anywhere minted attacker-agent/admin/victim-principal.
        import time as _time
        ex = self._executor(token_verifier=_verifier())
        now = _time.time()
        forged = {"iss": "test-issuer", "sub": "attacker-agent",
                  "aud": AUD, "iat": int(now), "exp": int(now) + 300,
                  "jti": "f411-forged", "principal": "victim-principal",
                  "role": "admin", "agent_scope": "all"}
        with self.assertRaises(IdentityTokenError) as ctx:
            ex.mint_identity("attacker-agent", "admin",
                             "victim-principal", token_claims=forged)
        self.assertEqual(ctx.exception.code, "identity-token-tampered")

    def test_verifier_produced_claims_still_mint(self):
        # The documented composition survives: verify_token's output
        # feeds mint_identity unchanged.
        v = _verifier()
        ex = self._executor(token_verifier=v)
        claims = v.verify_token(self._live_issue())
        self.assertIsInstance(claims, VerifiedTokenClaims)
        ident = ex.mint_identity("agent-7", "reader", "ops",
                                 token_claims=claims)
        self.assertEqual(ident.agent_id, "agent-7")
        self.assertEqual(ident.role, "reader")
        self.assertEqual(ident.principal, "ops")

    def test_sealed_claims_from_other_verifier_refused(self):
        # A sealed set proves nothing about THIS deployment's pinned
        # issuers: verified_by is bound by identity, not by shape.
        v1, v2 = _verifier(), _verifier()
        ex = self._executor(token_verifier=v1)
        foreign = v2.verify_token(self._live_issue())
        self.assertIsNot(foreign.verified_by, v1)
        with self.assertRaises(IdentityTokenError) as ctx:
            ex.mint_identity("agent-7", "reader", "ops",
                             token_claims=foreign)
        self.assertEqual(ctx.exception.code, "identity-token-tampered")

    def test_verify_token_marks_provenance(self):
        v = _verifier()
        claims = v.verify_token(self._live_issue())
        self.assertIs(claims.verified_by, v)
        # Still a dict for every existing consumer (registry, packet
        # seam, _mcp_token_claims defensive copy).
        self.assertIsInstance(claims, dict)
        self.assertEqual(claims["sub"], "agent-7")
        self.assertEqual(dict(claims)["role"], "reader")

    def test_registry_present_token_returns_sealed(self):
        v = _verifier()
        reg = TokenBackedPrincipalRegistry(v)
        claims = reg.present_token(self._live_issue())
        self.assertIsInstance(claims, VerifiedTokenClaims)
        self.assertTrue(reg.check_identity("ops", "reader", "agent-7"))

    def test_non_federated_dict_path_unchanged(self):
        # No verifier configured: the legacy dict path is byte-identical
        # (the F411 gate only exists in federated mode).
        import time as _time
        ex = self._executor()
        now = _time.time()
        legacy = {"iss": "whatever", "sub": "agent-7", "aud": AUD,
                  "iat": int(now), "exp": int(now) + 300,
                  "jti": "legacy", "principal": "ops", "role": "reader",
                  "agent_scope": "read"}
        ident = ex.mint_identity("agent-7", "reader", "ops",
                                 token_claims=legacy)
        self.assertEqual(ident.agent_id, "agent-7")


if __name__ == "__main__":
    unittest.main()
