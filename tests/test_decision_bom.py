"""Decision Bill-of-Materials (wave-180 lane A).

Microsoft agent-governance-toolkit steal verdict (STEAL, pattern only --
no vendored code): a Decision BOM -- a reconstructible view of every
factor behind a governance decision, assembled on demand from existing
signals instead of storing pre-built explanations. Cheaper to build,
harder to tamper with.

The BOM rides the signed decision packet as a producer-attributed
section. It binds, by digest, every input artifact that informed the
decision: the policy bundle (id + version + sha256 of the exact bytes
the engine parsed), the evidence-chain head, the principal identity,
the skill/MCP pin digests, and the approval record. An auditor
re-derives the digests on demand (verify_bom) instead of trusting the
packet's pointers -- the same "references, not re-bindings" philosophy
as the packet itself, with teeth: a swapped or missing input digest
fails closed.

Seams under test:
  gov/decision_bom.build_bom / bom_digest / check_bom_shape / verify_bom
  gov/decision_packet.build_decision_packet(bill_of_materials=...)
  gov/decision_packet.verify_decision_packet (BOM presence/shape/
    consistency fail-closed)

Stdlib only. Deterministic: no clock, no randomness, no I/O in the
build/verify path.
"""

import copy
import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_bom
from gov import decision_packet as dp


def _policy_bytes(version="7"):
    return ("version: %s\nroles:\n  ops: [allow]\n" % version).encode()


def _bom(**over):
    kw = dict(
        policy_id="default",
        policy_version="7",
        policy_digest=hashlib.sha256(_policy_bytes("7")).hexdigest(),
        evidence_head_digest="cd" * 32,
        principal={"agent_id": "a1", "role": "ops",
                   "principal": "p", "run_id": "r1"},
        pin_digests={"skill:x": "ef" * 32},
        approval_id="appr-1",
        approval_record_digest="12" * 32,
    )
    kw.update(over)
    return decision_bom.build_bom(**kw)


def _packet_kwargs(**over):
    kw = dict(
        decision="allow",
        boundary_declared=False,
        authority_proof=None,
        policy_id="default",
        policy_version="7",
        evidence_head_digest="cd" * 32,
        identity={"agent_id": "a1", "role": "ops",
                  "principal": "p", "run_id": "r1"},
        approval_id="appr-1",
        issued_at="2026-09-28T00:00:00+00:00",
        # The packet's capability_manifest must agree with the BOM's
        # pins: skill:x is attested with digest ef*32 on both sides.
        # The packet's policy_bundle_digest must agree with the BOM's
        # policy digest (the packet-level swap binding).
        skill_id="skill:x",
        capability_manifest_digest="ef" * 32,
        policy_bundle_digest=hashlib.sha256(_policy_bytes("7")).hexdigest(),
        bill_of_materials=_bom(),
    )
    kw.update(over)
    return kw


def _signed_packet(**over):
    seed = bytes.fromhex("22" * 32)
    return dp.sign_packet(dp.build_decision_packet(**_packet_kwargs(**over)),
                         seed)


class BuildBomTest(unittest.TestCase):
    def test_build_bom_well_formed(self):
        bom = _bom()
        ok, reason = decision_bom.check_bom_shape(bom)
        self.assertTrue(ok, reason)
        self.assertEqual(bom["bom_version"], 1)
        self.assertEqual(bom["inputs"]["policy"]["policy_version"], "7")

    def test_bom_digest_deterministic(self):
        self.assertEqual(decision_bom.bom_digest(_bom()),
                         decision_bom.bom_digest(_bom()))

    def test_build_bom_rejects_missing_policy_digest(self):
        with self.assertRaises(decision_bom.BomError):
            _bom(policy_digest=None)

    def test_build_bom_rejects_malformed_pin_digest(self):
        with self.assertRaises(decision_bom.BomError):
            _bom(pin_digests={"skill:x": "not-hex"})

    def test_build_bom_rejects_empty_policy_version(self):
        with self.assertRaises(decision_bom.BomError):
            _bom(policy_version="")

    def test_build_bom_allows_no_pins_and_no_approval(self):
        # A decision that used no skills and needed no approval still
        # gets a BOM: empty pins and null approval are honest, not gaps.
        bom = _bom(pin_digests={}, approval_id=None,
                   approval_record_digest=None)
        ok, reason = decision_bom.check_bom_shape(bom)
        self.assertTrue(ok, reason)
        self.assertEqual(bom["inputs"]["pins"], {})
        self.assertIsNone(bom["inputs"]["approval"]["approval_id"])

    def test_check_bom_shape_rejects_stripped_section(self):
        bom = _bom()
        del bom["inputs"]["policy"]
        ok, reason = decision_bom.check_bom_shape(bom)
        self.assertFalse(ok)
        self.assertIn("policy", reason)


class VerifyBomTest(unittest.TestCase):
    def test_verify_bom_rederives_policy_digest(self):
        # On-demand reconstruction: the auditor re-hashes the policy
        # bundle bytes instead of trusting the BOM's pointer.
        ok, reason = decision_bom.verify_bom(
            _bom(), policy_bundle_bytes=_policy_bytes("7"))
        self.assertTrue(ok, reason)

    def test_verify_bom_catches_tampered_policy_bytes(self):
        ok, reason = decision_bom.verify_bom(
            _bom(), policy_bundle_bytes=_policy_bytes("8"))
        self.assertFalse(ok)
        self.assertIn("policy", reason.lower())

    def test_verify_bom_version_label_is_a_lookup_key(self):
        # The BOM labels the policy "8" but digests the v7 bytes. An
        # auditor resolving the label to the v8 bundle bytes gets a
        # digest mismatch: the version string is a lookup key, the
        # digest is the ground truth. (The label-vs-packet consistency
        # is checked by verify_decision_packet.)
        bom = _bom(policy_version="8")
        ok, reason = decision_bom.verify_bom(
            bom, policy_bundle_bytes=_policy_bytes("8"))
        self.assertFalse(ok)
        self.assertIn("policy", reason.lower())

    def test_verify_bom_checks_pin_digests_against_registry(self):
        ok, reason = decision_bom.verify_bom(
            _bom(), pin_digests={"skill:x": "ef" * 32})
        self.assertTrue(ok, reason)
        ok, reason = decision_bom.verify_bom(
            _bom(), pin_digests={"skill:x": "00" * 32})
        self.assertFalse(ok)
        self.assertIn("pin", reason.lower())

    def test_verify_bom_never_raises(self):
        ok, reason = decision_bom.verify_bom("not-a-bom")
        self.assertFalse(ok)
        self.assertTrue(reason)


class VerifyBomApprovalLegTest(unittest.TestCase):
    # F200: the approval leg of verify_bom. The record digest is
    # HMAC-keyed (gov/approvals.approval_record_digest), so the
    # auditor supplies their own resolution {approval_id:
    # record_digest}; the BOM's digest must MATCH it.

    def test_tampered_record_digest_fails_closed_with_records(self):
        bom = _bom(approval_record_digest="00" * 32)
        ok, reason = decision_bom.verify_bom(
            bom, policy_bundle_bytes=_policy_bytes("7"),
            approval_records={"appr-1": "12" * 32})
        self.assertFalse(ok)
        self.assertIn("approval", reason.lower())

    def test_honest_record_digest_verifies_with_records(self):
        ok, reason = decision_bom.verify_bom(
            _bom(), policy_bundle_bytes=_policy_bytes("7"),
            approval_records={"appr-1": "12" * 32})
        self.assertTrue(ok, reason)
        self.assertIn("approval", reason)

    def test_approval_leg_unverified_without_records(self):
        # Without the auditor's records the approval leg must be
        # REPORTED unverified -- never silently passed.
        ok, reason = decision_bom.verify_bom(
            _bom(), policy_bundle_bytes=_policy_bytes("7"))
        self.assertTrue(ok, reason)
        self.assertIn("unverified", reason.lower())
        self.assertIn("approval", reason.lower())

    def test_unknown_approval_id_in_records_fails_closed(self):
        ok, reason = decision_bom.verify_bom(
            _bom(), policy_bundle_bytes=_policy_bytes("7"),
            approval_records={"other-id": "12" * 32})
        self.assertFalse(ok)
        self.assertIn("appr-1", reason)

    def test_malformed_approval_records_fail_closed_never_raise(self):
        for bad in ("not-a-dict", {"appr-1": "zz"},
                    {"appr-1": None}, ["appr-1"]):
            ok, reason = decision_bom.verify_bom(
                _bom(), policy_bundle_bytes=_policy_bytes("7"),
                approval_records=bad)
            self.assertFalse(ok, bad)
            self.assertTrue(reason, bad)

    def test_no_approval_bom_ignores_supplied_records(self):
        # A BOM that honestly attests no approval has no approval leg
        # to check; supplied records are vacuous, not an error.
        bom = _bom(approval_id=None, approval_record_digest=None)
        ok, reason = decision_bom.verify_bom(
            bom, policy_bundle_bytes=_policy_bytes("7"),
            approval_records={"appr-1": "12" * 32})
        self.assertTrue(ok, reason)
        self.assertNotIn("unverified", reason.lower())


class PacketBomSectionTest(unittest.TestCase):
    def test_packet_with_complete_bom_verifies(self):
        packet = _signed_packet()
        ok, reason = dp.verify_decision_packet(packet)
        self.assertTrue(ok, reason)

    def test_packet_builder_requires_bom(self):
        kw = _packet_kwargs()
        del kw["bill_of_materials"]
        with self.assertRaises(dp.PacketError):
            dp.build_decision_packet(**kw)

    def test_packet_builder_rejects_malformed_bom(self):
        bom = _bom()
        bom["inputs"]["policy"]["digest"] = "zz"  # not hex
        with self.assertRaises(dp.PacketError):
            dp.build_decision_packet(**_packet_kwargs(bill_of_materials=bom))

    def test_verify_rejects_swapped_policy_digest_in_bom(self):
        # Attacker swaps the BOM's policy digest to a different valid
        # hex value and re-signs. The packet's own policy section still
        # names the true bundle digest, so the verifier fails closed at
        # the PACKET level -- no on-demand audit needed.
        bom = _bom(policy_digest="ab" * 32)
        packet = _signed_packet(bill_of_materials=bom)
        ok, reason = dp.verify_decision_packet(packet)
        self.assertFalse(ok)
        self.assertIn("policy_bundle_digest", reason)
        # ...and the on-demand audit path agrees:
        ok2, _ = decision_bom.verify_bom(
            packet["bill_of_materials"]["value"],
            policy_bundle_bytes=_policy_bytes("7"))
        self.assertFalse(ok2)

    def test_verify_bom_without_artifacts_is_not_a_pass(self):
        # A BOM checked with no artifacts supplied must NOT verify:
        # its shape is valid but its provenance is unverified, and no
        # caller may mistake that for a verified BOM.
        ok, reason = decision_bom.verify_bom(_bom())
        self.assertFalse(ok)
        self.assertIn("UNVERIFIED", reason)

    def test_build_bom_rejects_approval_id_without_record_digest(self):
        # An approval id whose record digest cannot be resolved fails
        # closed: the BOM must never silently drop approval provenance.
        with self.assertRaises(decision_bom.BomError):
            _bom(approval_record_digest=None)

    def test_verify_rejects_bom_that_omits_consumed_pin(self):
        # SLSA-steal falsifiable probe (wave-180 prospectus): the BOM
        # omits the skill the packet's capability_manifest says was
        # consumed. The verifier fails closed on the omission -- a BOM
        # that drops a consumed input is decorative, not evidence.
        bom = _bom(pin_digests={})
        packet = _signed_packet(bill_of_materials=bom)
        ok, reason = dp.verify_decision_packet(packet)
        self.assertFalse(ok)
        self.assertIn("pin", reason.lower())

    def test_verify_rejects_bom_policy_version_mismatch(self):
        # The BOM claims policy version 8 while the packet's own policy
        # section says 7: the consistency check fails closed.
        bom = _bom(policy_version="8")
        packet = _signed_packet(bill_of_materials=bom)
        ok, reason = dp.verify_decision_packet(packet)
        self.assertFalse(ok)
        self.assertIn("policy_version", reason)

    def test_verify_rejects_bom_head_mismatch(self):
        bom = _bom(evidence_head_digest="ff" * 32)
        packet = _signed_packet(bill_of_materials=bom)
        ok, reason = dp.verify_decision_packet(packet)
        self.assertFalse(ok)
        self.assertIn("head_digest", reason)

    def test_verify_rejects_bom_approval_mismatch(self):
        bom = _bom(approval_id="appr-2")
        packet = _signed_packet(bill_of_materials=bom)
        ok, reason = dp.verify_decision_packet(packet)
        self.assertFalse(ok)
        self.assertIn("approval_id", reason)

    def test_verify_rejects_bom_pin_mismatch(self):
        bom = _bom(pin_digests={"skill:x": "00" * 32})
        kw = _packet_kwargs(bill_of_materials=bom)
        # The packet's capability_manifest names the attested skill
        # digest; the BOM must agree with it.
        kw["capability_manifest_digest"] = "ef" * 32
        kw["skill_id"] = "skill:x"
        packet = _signed_packet(**kw)
        ok, reason = dp.verify_decision_packet(packet)
        self.assertFalse(ok)
        self.assertIn("pin", reason.lower())

    def test_verify_rejects_tampered_bom_section(self):
        packet = _signed_packet()
        packet["bill_of_materials"]["value"]["inputs"]["policy"][
            "policy_version"] = "999"
        ok, reason = dp.verify_decision_packet(packet)
        self.assertFalse(ok)  # signature covers the BOM section

    def test_old_packet_without_bom_section_fails_closed(self):
        # Pre-BOM packets do not meet the evidence bar: the verifier
        # says so loudly instead of silently passing.
        packet = _signed_packet()
        body = {k: v for k, v in packet.items() if k != "signature"}
        body.pop("authority", None)
        del body["bill_of_materials"]
        seed = bytes.fromhex("22" * 32)
        resealed = dp.sign_packet(body, seed)
        ok, reason = dp.verify_decision_packet(resealed)
        self.assertFalse(ok)
        self.assertIn("bill_of_materials", reason)


if __name__ == "__main__":
    unittest.main()
