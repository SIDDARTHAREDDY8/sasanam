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

SEED = bytes.fromhex("11" * 32)


def _minimal_kwargs(**over):
    kw = dict(decision="allow", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              issued_at="2026-09-28T00:00:00+00:00")
    kw.update(over)
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


if __name__ == "__main__":
    unittest.main()
