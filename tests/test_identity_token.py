#!/usr/bin/env python3
"""Unit tests for wave-191: agent-identity token claim-set integration.

Covers the public seams only (never internal helper names):
  - gov/decision_packet.check_token_claims (claim-set validation)
  - gov/decision_packet.build_decision_packet(identity_token=...)
  - gov/decision_packet.verify_decision_packet(..., token_claims=...)
  - gov/decision_bom.build_bom principal token_digest + check_bom_shape
  - ToolExecutor.mint_identity(..., token_claims=...)

Stdlib + gov modules only for the packet/BOM classes; the executor
class uses the same synthetic fixtures as tests/test_w74_identity.py.
"""

import copy
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_packet as dp  # noqa: E402
from gov import decision_bom as bom_mod  # noqa: E402
from gov.identity import IdentityTokenError  # noqa: E402

SEED = bytes.fromhex("11" * 32)
ISSUER = "https://dex.sasanam.internal"
DAY = 86400

IDENTITY = {"agent_id": "agent:org1:run-7", "role": "operator",
            "principal": "org1", "run_id": "run-7"}


def _claims(exp_offset, **over):
    now = int(time.time())
    c = {"iss": ISSUER, "sub": IDENTITY["agent_id"],
         "aud": "sasanam-policy-engine", "iat": now - 3600,
         "exp": now + exp_offset, "jti": "token-jti-001",
         "principal": IDENTITY["principal"], "role": IDENTITY["role"],
         "agent_scope": "tools:read"}
    c.update(over)
    return c


def _section(exp_offset, **over):
    s = {"token_digest": "ab" * 32, "iss": ISSUER,
         "aud": "sasanam-policy-engine",
         "exp": int(time.time()) + exp_offset, "jti": "token-jti-001"}
    s.update(over)
    return s


def _bom(**over):
    kw = dict(policy_id="default", policy_version="unversioned",
              policy_digest="ab" * 32, evidence_head_digest="GENESIS",
              principal=dict(IDENTITY))
    kw.update(over)
    return bom_mod.build_bom(**kw)


def _kwargs(**over):
    kw = dict(decision="allow", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              policy_id="default", policy_version="unversioned",
              identity=dict(IDENTITY),
              issued_at="2026-09-28T00:00:00+00:00",
              bill_of_materials=_bom())
    kw.update(over)
    return kw


def _signed(**over):
    return dp.sign_packet(dp.build_decision_packet(**_kwargs(**over)),
                         SEED)


class CheckTokenClaims(unittest.TestCase):
    """Public claim-set validation rules."""

    def test_valid_claims_accepted(self):
        ok, _ = dp.check_token_claims(_claims(900))
        self.assertTrue(ok)

    def test_missing_claims_refused(self):
        for missing in ("iss", "sub", "aud", "iat", "exp", "jti",
                        "principal", "role", "agent_scope"):
            c = _claims(900)
            del c[missing]
            ok, reason = dp.check_token_claims(c)
            self.assertFalse(ok, "claim %r should be required" % missing)
            self.assertIn(missing, reason)

    def test_non_dict_refused(self):
        for bad in (None, [], "claims", 42):
            ok, _ = dp.check_token_claims(bad)
            self.assertFalse(ok, repr(bad))

    def test_wrong_audience_refused(self):
        ok, reason = dp.check_token_claims(
            _claims(900, aud="some-other-service"))
        self.assertFalse(ok)
        self.assertIn("audience", reason)

    def test_audience_list_accepted(self):
        ok, _ = dp.check_token_claims(
            _claims(900, aud=["some-other-service",
                             "sasanam-policy-engine"]))
        self.assertTrue(ok)

    def test_expired_refused(self):
        ok, reason = dp.check_token_claims(_claims(-3650 * DAY))
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_future_iat_refused(self):
        c = _claims(900)
        c["iat"] = c["exp"] + 3600  # issued an hour after expiry: nonsense
        ok, reason = dp.check_token_claims(c)
        self.assertFalse(ok)
        self.assertIn("iat", reason)

    def test_unknown_claims_are_ignored(self):
        ok, _ = dp.check_token_claims(
            _claims(900, email="op@example.com"))
        self.assertTrue(ok)

    def test_numeric_date_type_enforced(self):
        c = _claims(900)
        c["exp"] = "tomorrow"
        ok, reason = dp.check_token_claims(c)
        self.assertFalse(ok)
        self.assertIn("exp", reason)


class BuildIdentityTokenSection(unittest.TestCase):
    """The optional signature-covered packet section."""

    def test_section_records_exactly_five_fields(self):
        packet = _signed(identity_token=_section(900))
        section = packet["identity_token"]
        self.assertEqual(section["producer"], "gov/identity.py")
        self.assertEqual(section["producer_version"], "2")
        self.assertEqual(set(section["value"].keys()),
                         {"token_digest", "iss", "aud", "exp", "jti"})
        self.assertEqual(section["value"]["token_digest"], "ab" * 32)
        self.assertEqual(section["value"]["iss"], ISSUER)
        self.assertEqual(section["value"]["jti"], "token-jti-001")

    def test_raw_token_never_recorded(self):
        section = _signed(identity_token=_section(900))["identity_token"]
        raw = str(section["value"])
        self.assertNotIn("eyJ", raw)  # no JWT blob anywhere in the section
        self.assertEqual(section["value"]["token_digest"], "ab" * 32)

    def test_omitted_means_legacy(self):
        with_section = _signed()
        self.assertNotIn("identity_token", with_section)
        explicit_none = _signed(identity_token=None)
        self.assertNotIn("identity_token", explicit_none)
        # Byte-identical: omitting the kwarg and passing None produce
        # the same digest as the pre-wave-191 path.
        self.assertEqual(dp.packet_digest(with_section),
                         dp.packet_digest(explicit_none))

    def test_malformed_section_raises_packet_error(self):
        bad_sections = [
            dict(_section(900), extra="nope"),
            {k: v for k, v in _section(900).items() if k != "jti"},
            dict(_section(900), token_digest="zz"),
            dict(_section(900), exp="soon"),
            "not-a-dict",
        ]
        for bad in bad_sections:
            with self.assertRaises(dp.PacketError, msg=repr(bad)):
                dp.build_decision_packet(**_kwargs(identity_token=bad))

    def test_section_is_signature_covered(self):
        packet = _signed(identity_token=_section(900))
        tampered = copy.deepcopy(packet)
        tampered["identity_token"]["value"]["jti"] = "swapped-jti"
        ok, reason = dp.verify_decision_packet(tampered)
        self.assertFalse(ok, reason)

    def test_section_participates_in_digest(self):
        legacy = _signed()
        with_section = _signed(identity_token=_section(900))
        self.assertNotEqual(dp.packet_digest(legacy),
                            dp.packet_digest(with_section))


class VerifyTokenPresentation(unittest.TestCase):
    """verify_decision_packet(..., token_claims=...) at the public seam."""

    def test_expired_token_refused(self):
        packet = _signed(identity_token=_section(-3650 * DAY))
        ok, reason = dp.verify_decision_packet(
            copy.deepcopy(packet),
            token_claims=_claims(-3650 * DAY))
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_valid_token_accepted(self):
        packet = _signed(identity_token=_section(900))
        ok, reason = dp.verify_decision_packet(
            copy.deepcopy(packet), token_claims=_claims(900))
        self.assertTrue(ok, reason)

    def test_legacy_path_untouched(self):
        packet = _signed()
        ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
        self.assertTrue(ok, reason)

    def test_section_without_claims_accepted(self):
        packet = _signed(identity_token=_section(900))
        ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
        self.assertTrue(ok, reason)

    def test_claims_without_section_refused(self):
        packet = _signed()
        ok, reason = dp.verify_decision_packet(
            copy.deepcopy(packet), token_claims=_claims(900))
        self.assertFalse(ok)
        self.assertIn("no identity_token", reason)

    def test_wrong_iss_refused(self):
        packet = _signed(identity_token=_section(900))
        ok, _ = dp.verify_decision_packet(
            copy.deepcopy(packet),
            token_claims=_claims(900, iss="https://evil.example"))
        self.assertFalse(ok)

    def test_wrong_aud_refused(self):
        packet = _signed(identity_token=_section(900))
        ok, _ = dp.verify_decision_packet(
            copy.deepcopy(packet),
            token_claims=_claims(900, aud="some-other-service"))
        self.assertFalse(ok)

    def test_exp_missing_refused(self):
        packet = _signed(identity_token=_section(900))
        c = _claims(900)
        del c["exp"]
        ok, _ = dp.verify_decision_packet(copy.deepcopy(packet),
                                           token_claims=c)
        self.assertFalse(ok)

    def test_jti_mismatch_refused(self):
        packet = _signed(identity_token=_section(900))
        ok, _ = dp.verify_decision_packet(
            copy.deepcopy(packet),
            token_claims=_claims(900, jti="other-jti"))
        self.assertFalse(ok)

    def test_sub_mismatch_refused(self):
        packet = _signed(identity_token=_section(900))
        ok, _ = dp.verify_decision_packet(
            copy.deepcopy(packet),
            token_claims=_claims(900, sub="agent:org1:run-9"))
        self.assertFalse(ok)

    def test_role_mismatch_refused(self):
        packet = _signed(identity_token=_section(900))
        ok, _ = dp.verify_decision_packet(
            copy.deepcopy(packet),
            token_claims=_claims(900, role="admin"))
        self.assertFalse(ok)

    def test_forged_claims_refused(self):
        packet = _signed(identity_token=_section(900))
        forged = _claims(900, iss="https://dex.other.example",
                         jti="token-jti-999", sub="agent:orgX:run-1",
                         principal="orgX")
        ok, _ = dp.verify_decision_packet(copy.deepcopy(packet),
                                           token_claims=forged)
        self.assertFalse(ok)

    def test_verifier_never_raises_on_token_inputs(self):
        packet = _signed(identity_token=_section(900))
        for bad in ({"iss": 1}, "claims", [1, 2], None):
            if bad is None:
                continue
            try:
                dp.verify_decision_packet(copy.deepcopy(packet),
                                          token_claims=bad)
            except Exception as e:  # noqa: BLE001
                self.fail("verifier raised %r on %r" % (e, bad))

    def test_bom_digest_mismatch_fails_closed(self):
        principal = dict(IDENTITY)
        principal["token_digest"] = "cd" * 32
        packet = dp.sign_packet(
            dp.build_decision_packet(
                **_kwargs(identity_token=_section(900),
                         bill_of_materials=_bom(principal=principal))),
            SEED)
        ok, reason = dp.verify_decision_packet(copy.deepcopy(packet))
        self.assertFalse(ok)
        self.assertIn("token_digest", reason)

    def test_bom_digest_agreement_accepted(self):
        principal = dict(IDENTITY)
        principal["token_digest"] = "ab" * 32
        packet = dp.sign_packet(
            dp.build_decision_packet(
                **_kwargs(identity_token=_section(900),
                         bill_of_materials=_bom(principal=principal))),
            SEED)
        ok, reason = dp.verify_decision_packet(
            copy.deepcopy(packet), token_claims=_claims(900))
        self.assertTrue(ok, reason)


class BomTokenDigest(unittest.TestCase):
    """The optional principal.token_digest in gov/decision_bom."""

    def test_legacy_bom_has_no_token_digest(self):
        bom = _bom()
        self.assertNotIn("token_digest", bom["inputs"]["principal"])

    def test_token_digest_recorded_when_supplied(self):
        principal = dict(IDENTITY)
        principal["token_digest"] = "ab" * 32
        bom = _bom(principal=principal)
        self.assertEqual(bom["inputs"]["principal"]["token_digest"],
                         "ab" * 32)
        ok, reason = bom_mod.check_bom_shape(bom)
        self.assertTrue(ok, reason)

    def test_malformed_digest_rejected_at_build(self):
        principal = dict(IDENTITY)
        principal["token_digest"] = "not-hex"
        with self.assertRaises(bom_mod.BomError):
            _bom(principal=principal)

    def test_malformed_digest_rejected_at_shape_check(self):
        bom = _bom()
        bom["inputs"]["principal"]["token_digest"] = "ZZ" * 32
        ok, reason = bom_mod.check_bom_shape(bom)
        self.assertFalse(ok)
        self.assertIn("token_digest", reason)


class MintIdentityToken(unittest.TestCase):
    """ToolExecutor.mint_identity(..., token_claims=...)."""

    _ALLOW_ALL = """\
version: 2
roles:
  operator: [read_file]
policies:
  - id: allow-all
    effect: allow
    match:
      tool: [read_file]
    reason: identity-token fixture
"""

    def _executor(self):
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        run_dir = Path(tempfile.mkdtemp(prefix="govtok-"))
        (run_dir / "policy.yaml").write_text(self._ALLOW_ALL)
        policy = PolicyEngine(str(run_dir / "policy.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        return ToolExecutor(
            run_dir, policy, log, approvals,
            ledger_path=run_dir / "egress_ledger.jsonl",
            ungoverned_ack="identity-token test: synthetic executor")

    def test_valid_token_mints(self):
        ex = self._executor()
        ident = ex.mint_identity(
            IDENTITY["agent_id"], IDENTITY["role"],
            IDENTITY["principal"], token_claims=_claims(900))
        self.assertEqual(ident.agent_id, IDENTITY["agent_id"])

    def test_expired_token_refused(self):
        ex = self._executor()
        with self.assertRaises(IdentityTokenError):
            ex.mint_identity(
                IDENTITY["agent_id"], IDENTITY["role"],
                IDENTITY["principal"], token_claims=_claims(-900))

    def test_token_identity_mismatch_refused(self):
        ex = self._executor()
        with self.assertRaises(IdentityTokenError):
            ex.mint_identity(
                "agent:org1:run-9", IDENTITY["role"],
                IDENTITY["principal"], token_claims=_claims(900))

    def test_refused_mint_consumes_no_budget(self):
        ex = self._executor()
        with self.assertRaises(IdentityTokenError):
            ex.mint_identity(
                IDENTITY["agent_id"], IDENTITY["role"],
                IDENTITY["principal"], token_claims=_claims(-900))
        # Budget untouched: a legit mint still lands within budget.
        ex.mint_identity(IDENTITY["agent_id"], IDENTITY["role"],
                         IDENTITY["principal"],
                         token_claims=_claims(900))
        self.assertEqual(ex._mint_count, 1)

    def test_legacy_mint_unaffected(self):
        ex = self._executor()
        ident = ex.mint_identity(IDENTITY["agent_id"], IDENTITY["role"],
                                 IDENTITY["principal"])
        self.assertEqual(ident.agent_id, IDENTITY["agent_id"])
        self.assertEqual(ex._mint_count, 1)


if __name__ == "__main__":
    unittest.main()
