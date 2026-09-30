#!/usr/bin/env python3
"""Unit tests for gov/decision_packet.py (wave-176, OpenShell steal #2).

Adjacent unit suite for the decision-packet battery
(evals/decision_packet_probes.py green check is depth-1: this module
only). Stdlib + gov.decision_packet only; no executor, no harness.
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_packet as dp  # noqa: E402
from gov import authority_proof as ap  # noqa: E402
from gov import decision_bom as bom_mod  # noqa: E402

SEED = bytes.fromhex("11" * 32)


def _minimal_bom(**over):
    kw = dict(policy_id="default", policy_version="unversioned",
              policy_digest="ab" * 32,
              evidence_head_digest="GENESIS",
              principal={"agent_id": None, "role": None,
                         "principal": None, "run_id": None})
    kw.update(over)
    return bom_mod.build_bom(**kw)


def _minimal_kwargs(**over):
    # Wave-180: the BOM is mandatory and the verifier cross-checks it
    # against the packet's own sections, so the fixture BOM is derived
    # from the same kwargs (overrides to evidence_head_digest /
    # policy_id / policy_version flow into both).
    kw = dict(decision="allow", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              policy_id="default", policy_version="unversioned",
              issued_at="2026-09-28T00:00:00+00:00")
    kw.update(over)
    if "bill_of_materials" not in over:
        kw["bill_of_materials"] = _minimal_bom(
            policy_id=kw["policy_id"],
            policy_version=kw["policy_version"],
            evidence_head_digest=kw["evidence_head_digest"])
    return kw


def _proof(**over):
    p = {"verdict": "within_boundary",
         "covered_domains": ["filesystem"],
         "uncovered_domains": ["process_identity"],
         "counterexample": None,
         "boundary_id": "op-boundary-1"}
    p.update(over)
    return p


def _signed(**over):
    body = dp.build_decision_packet(**_minimal_kwargs(**over))
    return dp.sign_packet(body, SEED)


def _chain_for(packet, head="GENESIS"):
    return [{"event": "decision_packet",
             "packet_digest": dp.packet_digest(packet),
             "prev_hash": head, "hash": "entryhash1", "seq": 1}]


class VersionContract(unittest.TestCase):
    def test_packet_version_is_one(self):
        self.assertEqual(dp.DECISION_PACKET_VERSION, 1)

    def test_decisions_closed_set(self):
        self.assertEqual(set(dp.DECISIONS), {"allow", "deny", "queue"})

    def test_proof_verdicts_mirror_authority_proof(self):
        # The standalone module hardcodes the verdict set so it stays
        # verifiable without gov; this pins parity with the real
        # AuthorityProof contract (OpenShell steal #1).
        self.assertEqual(set(dp.PROOF_VERDICTS),
                         {ap.WITHIN, ap.EXCEEDS, ap.UNSUPPORTED,
                          ap.INCONCLUSIVE})


class BuildContract(unittest.TestCase):
    def test_minimal_no_boundary(self):
        body = dp.build_decision_packet(**_minimal_kwargs())
        self.assertNotIn("signature", body)
        self.assertEqual(body["decision"]["value"], "allow")
        self.assertFalse(body["boundary_declared"]["value"])
        self.assertEqual(body["authority_proof"]["value"],
                         dp.NO_BOUNDARY)
        self.assertEqual(body["decision_packet_version"], 1)

    def test_bad_decision_rejected(self):
        with self.assertRaises(dp.PacketError):
            dp.build_decision_packet(**_minimal_kwargs(decision="maybe"))

    def test_declared_boundary_requires_proof(self):
        with self.assertRaises(dp.PacketError):
            dp.build_decision_packet(**_minimal_kwargs(
                boundary_declared=True, authority_proof=None))

    def test_undeclared_boundary_rejects_proof(self):
        with self.assertRaises(dp.PacketError):
            dp.build_decision_packet(**_minimal_kwargs(
                boundary_declared=False, authority_proof=_proof()))

    def test_proof_verdict_must_be_known(self):
        with self.assertRaises(dp.PacketError):
            dp.build_decision_packet(**_minimal_kwargs(
                boundary_declared=True,
                authority_proof=_proof(verdict="probably_fine")))

    def test_proof_counterexample_shape_checked(self):
        bad = _proof(verdict="exceeds_boundary",
                     counterexample={"domain": "fs"})  # missing keys
        with self.assertRaises(dp.PacketError):
            dp.build_decision_packet(**_minimal_kwargs(
                boundary_declared=True, authority_proof=bad))

    def test_exceeds_proof_carries_repair_hint(self):
        ce = {"domain": "filesystem", "access": "write",
              "nearest_rule": "allow-read-only",
              "reason": "no write rule matched"}
        body = dp.build_decision_packet(**_minimal_kwargs(
            decision="deny", boundary_declared=True,
            authority_proof=_proof(verdict="exceeds_boundary",
                                   counterexample=ce)))
        just = body["justification"]["value"]
        self.assertEqual(just["counterexample"], ce)
        self.assertIn("narrow", just["repair_hint"])

    def test_within_proof_no_repair_hint(self):
        body = dp.build_decision_packet(**_minimal_kwargs(
            boundary_declared=True, authority_proof=_proof()))
        self.assertIsNone(
            body["justification"]["value"]["repair_hint"])

    def test_every_section_names_producer(self):
        body = dp.build_decision_packet(**_minimal_kwargs(
            boundary_declared=True, authority_proof=_proof()))
        for name, section in body.items():
            if name == "decision_packet_version":
                continue
            self.assertIsInstance(section, dict, name)
            self.assertIn("value", section, name)
            self.assertTrue(section.get("producer"), name)
            self.assertTrue(section.get("producer_version"), name)


class SignVerify(unittest.TestCase):
    def test_round_trip_with_linkage(self):
        packet = _signed()
        self.assertIn("signature", packet)
        self.assertIn("authority", packet)
        ok, reason = dp.verify_decision_packet(
            packet, _chain_for(packet))
        self.assertTrue(ok, reason)

    def test_round_trip_without_chain(self):
        packet = _signed()
        ok, reason = dp.verify_decision_packet(packet)
        self.assertTrue(ok, reason)
        self.assertIn("not checked", reason)

    def test_deterministic(self):
        a = _signed()
        b = _signed()
        self.assertEqual(dp.canonical_bytes(a), dp.canonical_bytes(b))

    def test_tamper_decision_refused(self):
        packet = _signed()
        p = copy.deepcopy(packet)
        p["decision"]["value"] = "deny"
        ok, _ = dp.verify_decision_packet(p)
        self.assertFalse(ok)

    def test_tamper_authority_pubkey_refused(self):
        packet = _signed()
        p = copy.deepcopy(packet)
        other = dp.sign_packet(
            dp.build_decision_packet(**_minimal_kwargs(
                issued_at="2026-09-28T00:00:01+00:00")),
            bytes.fromhex("22" * 32))
        p["authority"] = other["authority"]
        ok, reason = dp.verify_decision_packet(p)
        self.assertFalse(ok, reason)

    def test_stale_head_refused(self):
        packet = _signed()
        entries = _chain_for(packet)
        stale = copy.deepcopy(packet)
        stale["evidence"]["value"]["head_digest"] = "f" * 64
        body = {k: v for k, v in stale.items() if k != "signature"}
        body.pop("authority", None)
        resealed = dp.sign_packet(body, SEED)
        ok, reason = dp.verify_decision_packet(resealed, entries)
        self.assertFalse(ok)
        self.assertTrue("head" in reason.lower()
                        or "link" in reason.lower(), reason)

    def test_missing_chain_entry_refused(self):
        packet = _signed()
        ok, reason = dp.verify_decision_packet(packet, [])
        self.assertFalse(ok)
        self.assertIn("linkage", reason)

    def test_verifier_never_raises(self):
        for hostile in (None, "nope", 42, [], {},
                        {"decision_packet_version": 1},
                        {"decision_packet_version": 999},
                        {"decision_packet_version": 1,
                         "signature": "!!!not-base64!!!"}):
            ok, reason = dp.verify_decision_packet(hostile)
            self.assertFalse(ok, "verifier raised/accepted %r" % (hostile,))
            self.assertIsInstance(reason, str)

    def test_packet_digest_excludes_signature(self):
        packet = _signed()
        d1 = dp.packet_digest(packet)
        p = copy.deepcopy(packet)
        p["signature"] = "AAAA"
        self.assertEqual(d1, dp.packet_digest(p))

    def test_double_sign_refused(self):
        packet = _signed()
        with self.assertRaises(dp.PacketError):
            dp.sign_packet(packet, SEED)


class KeyResolution(unittest.TestCase):
    def _clean_env(self):
        old = {k: os.environ.pop(k, None)
               for k in ("GOV_DECISION_PACKET_KEY",
                         "GOV_DECISION_PACKET_KEY_FILE")}
        return old

    def _restore_env(self, old):
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_env_key(self):
        old = self._clean_env()
        try:
            os.environ["GOV_DECISION_PACKET_KEY"] = "ab" * 32
            key = dp.resolve_packet_key()
            self.assertEqual(key["seed"], bytes.fromhex("ab" * 32))
            self.assertEqual(len(key["key_id"]), 32)
            self.assertEqual(len(key["pubkey_hex"]), 64)
        finally:
            self._restore_env(old)

    def test_explicit_seed_wins(self):
        old = self._clean_env()
        try:
            os.environ["GOV_DECISION_PACKET_KEY"] = "ab" * 32
            key = dp.resolve_packet_key(explicit="cd" * 32)
            self.assertEqual(key["seed"], bytes.fromhex("cd" * 32))
        finally:
            self._restore_env(old)

    def test_unconfigured_raises(self):
        old = self._clean_env()
        try:
            with self.assertRaises(dp.NoPacketKeyError):
                dp.resolve_packet_key()
        finally:
            self._restore_env(old)

    def test_key_file_0600(self):
        old = self._clean_env()
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "dp-key-test")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("ef" * 32 + "\n")
            os.chmod(path, 0o600)
            os.environ["GOV_DECISION_PACKET_KEY_FILE"] = path
            key = dp.resolve_packet_key()
            self.assertEqual(key["seed"], bytes.fromhex("ef" * 32))
        finally:
            self._restore_env(old)
            if os.path.exists(path):
                os.unlink(path)

    def test_key_file_bad_perms_refused(self):
        old = self._clean_env()
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "dp-key-badperms")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("ef" * 32 + "\n")
            os.chmod(path, 0o644)
            os.environ["GOV_DECISION_PACKET_KEY_FILE"] = path
            with self.assertRaises(dp.NoPacketKeyError):
                dp.resolve_packet_key()
        finally:
            self._restore_env(old)
            if os.path.exists(path):
                os.unlink(path)

    def test_malformed_env_key_refused(self):
        old = self._clean_env()
        try:
            os.environ["GOV_DECISION_PACKET_KEY"] = "not-hex"
            with self.assertRaises(dp.NoPacketKeyError):
                dp.resolve_packet_key()
        finally:
            self._restore_env(old)


class EvidenceHead(unittest.TestCase):
    def test_missing_log_is_genesis(self):
        self.assertEqual(
            dp.evidence_head_digest("/tmp/definitely-no-such-dp-log.jsonl"),
            "GENESIS")

    def test_head_is_last_well_formed_hash(self):
        path = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                            "dp-head-test.jsonl")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"seq": 1, "hash": "aaa"}\n')
                f.write('this line is corrupt\n')
                f.write('{"seq": 2, "hash": "bbb"}\n')
            self.assertEqual(dp.evidence_head_digest(path), "bbb")
        finally:
            if os.path.exists(path):
                os.unlink(path)


class F199Regression(unittest.TestCase):
    """F199: GENESIS-head packet must not dodge F196 re-derivation.

    Red-first: ``test_genesis_head_with_decision_entries_refused``
    verified (True, "ok") pre-fix with an arbitrary decision_digest
    (probe D5 shape); it must fail closed post-fix. A GENESIS-head
    packet verifies only when the chain carries no decision entries
    (the honest first-decision case).
    """

    def _genesis_packet(self, decision_digest=None):
        pkt = _signed()
        if decision_digest is not None:
            p = copy.deepcopy(pkt)
            p["policy"]["value"]["decision_digest"] = decision_digest
            # Re-seal so the signature seam is intact; the BOM does not
            # bind decision_digest, so the refusal must come from the
            # F199 check, not from a signature/BOM seam.
            body = {k: v for k, v in p.items() if k != "signature"}
            body.pop("authority", None)
            pkt = dp.sign_packet(body, SEED)
        return pkt

    def _chain_with_decision(self, packet):
        return [
            {"event": "decision", "hash": "dech0",
             "prev_hash": "GENESIS", "approval_id": "A1",
             "decision_seq": 1,
             "policy_decision": {"policy_id": "default",
                                 "decision": "allow"}},
            {"event": "decision_packet",
             "packet_digest": dp.packet_digest(packet),
             "prev_hash": "GENESIS", "hash": "entryhash1", "seq": 1},
        ]

    def test_genesis_head_with_decision_entries_refused(self):
        pkt = self._genesis_packet(decision_digest="ff" * 32)
        ok, reason = dp.verify_decision_packet(
            pkt, self._chain_with_decision(pkt))
        self.assertFalse(ok, reason)
        self.assertIn("F199", reason)

    def test_genesis_head_without_decision_entries_still_verifies(self):
        pkt = self._genesis_packet()
        ok, reason = dp.verify_decision_packet(pkt, _chain_for(pkt))
        self.assertTrue(ok, reason)


class EnvelopeOptIn(unittest.TestCase):
    # Wave-232 lane C: opt-in DSSE envelope on decision packets.
    def test_envelope_round_trip(self):
        body = dp.build_decision_packet(**_minimal_kwargs())
        p = dp.sign_packet(body, SEED, envelope=True)
        self.assertEqual(p["envelope"]["payloadType"],
                         dp.DECISION_PACKET_ENVELOPE_TYPE)
        ok, why = dp.verify_decision_packet(p)
        self.assertTrue(ok, why)

    def test_legacy_byte_identity(self):
        body = dp.build_decision_packet(**_minimal_kwargs())
        p = dp.sign_packet(body, SEED)
        self.assertNotIn("envelope", p)
        ok, why = dp.verify_decision_packet(p)
        self.assertTrue(ok, why)

    def test_envelope_transplant_refused(self):
        body1 = dp.build_decision_packet(**_minimal_kwargs())
        p1 = dp.sign_packet(body1, SEED, envelope=True)
        body2 = dp.build_decision_packet(
            **_minimal_kwargs(decision="deny"))
        p2 = dp.sign_packet(body2, SEED, envelope=True)
        p2x = dict(p2)
        p2x["envelope"] = p1["envelope"]
        ok, why = dp.verify_decision_packet(p2x)
        self.assertFalse(ok)
        self.assertIn("dsse-signature-invalid", why)

    def test_envelope_forgery_refused(self):
        body = dp.build_decision_packet(**_minimal_kwargs())
        p = dp.sign_packet(body, SEED, envelope=True)
        bad = copy.deepcopy(p)
        bad["envelope"]["signatures"][0]["sig"] = "00" * 64
        ok, why = dp.verify_decision_packet(bad)
        self.assertFalse(ok)
        self.assertIn("dsse-signature-invalid", why)

    def test_envelope_wrong_type_refused(self):
        # Wave-233: a packet envelope re-typed under the denial-receipt
        # payloadType is a cross-module transplant, so the verifier now
        # names it dsse-envelope-transplant (the wave-232 pin
        # dsse-payload-type-refused is obsolete for this path: the
        # packet verifier binds the expected module domain).
        body = dp.build_decision_packet(**_minimal_kwargs())
        p = dp.sign_packet(body, SEED, envelope=True)
        bad = copy.deepcopy(p)
        bad["envelope"]["payloadType"] = \
            "application/vnd.sasanam.denial-receipt+json"
        ok, why = dp.verify_decision_packet(bad)
        self.assertFalse(ok)
        self.assertIn("dsse-envelope-transplant", why)


    def test_envelope_unknown_field_refused(self):
        import copy
        body = dp.build_decision_packet(**_minimal_kwargs())
        p = dp.sign_packet(body, SEED, envelope=True)
        bad = copy.deepcopy(p)
        bad["envelope"]["extra_field"] = "smuggled"
        ok, why = dp.verify_decision_packet(bad)
        self.assertFalse(ok)
        self.assertIn("dsse-envelope-malformed", why)
        bad2 = copy.deepcopy(p)
        bad2["envelope"]["signatures"][0]["extra_sig_field"] = "smuggled"
        ok, why = dp.verify_decision_packet(bad2)
        self.assertFalse(ok)
        self.assertIn("dsse-envelope-malformed", why)


if __name__ == "__main__":
    unittest.main()
