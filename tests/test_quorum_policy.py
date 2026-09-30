#!/usr/bin/env python3
"""Unit tests for gov.quorum_policy (wave-217 lane A).

Pin the step-scoped quorum contract: per-step policy validation,
independently-signed agreeing link records, fail-closed refusals
(disagreement, shortfall, unauthorized/unpinned signers, bad
signatures, equivocation, ambiguity, cross-step replay), the
diagnostic-only expected_command, and the tighten-only promote()
wiring.
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import quorum_policy as qp  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_SEEDA = bytes.fromhex("a1" * 32)
_SEEDB = bytes.fromhex("b2" * 32)
_SEEDC = bytes.fromhex("c3" * 32)
_SEEDD = bytes.fromhex("d4" * 32)

_DIGEST_X = hashlib.sha256(b"fact-X").hexdigest()
_DIGEST_Y = hashlib.sha256(b"fact-Y").hexdigest()


def _signers():
    return {"A": Ed25519Signer(_SEEDA), "B": Ed25519Signer(_SEEDB),
            "C": Ed25519Signer(_SEEDC), "D": Ed25519Signer(_SEEDD)}


def _keyset(signers, *names):
    return {signers[n].key_id: Ed25519Verifier(signers[n].public_key)
            for n in names}


class TestLoadQuorumStep(unittest.TestCase):
    def test_happy_path(self):
        step = qp.load_quorum_step({
            "step_name": "build",
            "authorized_keyids": ["k1", "k2"],
            "threshold": 2,
        })
        self.assertIsInstance(step, qp.QuorumStep)
        self.assertEqual(step.step_name, "build")
        self.assertEqual(step.authorized_keyids, ("k1", "k2"))
        self.assertEqual(step.threshold, 2)

    def test_refusals(self):
        bads = [
            "not-a-dict",
            {"step_name": "s", "authorized_keyids": ["k"], "threshold": 0},
            {"step_name": "s", "authorized_keyids": ["k"], "threshold": 2},
            {"step_name": "s", "authorized_keyids": [], "threshold": 1},
            {"step_name": "", "authorized_keyids": ["k"], "threshold": 1},
            {"step_name": "s", "authorized_keyids": ["k", "k"],
             "threshold": 1},
            {"step_name": "s", "authorized_keyids": ["k"], "threshold": 1,
             "extra": True},
            {"step_name": "s", "authorized_keyids": ["k"],
             "threshold": True},
        ]
        for spec in bads:
            with self.assertRaises(qp.QuorumPolicyError,
                                   msg="spec=%r" % (spec,)):
                qp.load_quorum_step(spec)


class TestMakeLinkRecord(unittest.TestCase):
    def test_shape(self):
        s = _signers()["A"]
        rec = qp.make_link_record("build", _DIGEST_X, s,
                                  expected_command="make all")
        self.assertEqual(set(rec), {
            "step_name", "statement_digest", "expected_command",
            "signer_keyid", "signature"})
        self.assertEqual(rec["signer_keyid"], s.key_id)
        self.assertEqual(len(bytes.fromhex(rec["signature"])), 64)

    def test_bad_signer_refused(self):
        with self.assertRaises(qp.QuorumPolicyError):
            qp.make_link_record("build", _DIGEST_X, object())

    def test_canonical_body_binds_keyid(self):
        # The same (step, digest, command) under different keyids
        # signs different bodies: a keyid label lie cannot survive.
        b1 = qp.canonical_link_body("build", _DIGEST_X, "make", "kidA")
        b2 = qp.canonical_link_body("build", _DIGEST_X, "make", "kidB")
        self.assertNotEqual(b1, b2)


class TestVerifyQuorum(unittest.TestCase):
    def setUp(self):
        self.signers = _signers()
        kids = [self.signers[n].key_id for n in ("A", "B", "C")]
        self.step = qp.load_quorum_step({
            "step_name": "build",
            "authorized_keyids": kids,
            "threshold": 2,
        })
        self.keyset = _keyset(self.signers, "A", "B", "C")

    def _link(self, digest, name, command="make all", step="build"):
        return qp.make_link_record(step, digest, self.signers[name],
                                   expected_command=command)

    def test_honest_quorum(self):
        links = [self._link(_DIGEST_X, "A"), self._link(_DIGEST_X, "B")]
        report = qp.verify_quorum(self.step, links, self.keyset)
        self.assertEqual(report["statement_digest"], _DIGEST_X)
        self.assertEqual(report["distinct_signers"], 2)
        self.assertTrue(report["command_agreement"])

    def test_quorum_met_but_disagree_refused(self):
        step = qp.load_quorum_step({
            "step_name": "build",
            "authorized_keyids": self.step.authorized_keyids,
            "threshold": 3,
        })
        links = [self._link(_DIGEST_X, "A"), self._link(_DIGEST_Y, "B"),
                 self._link(_DIGEST_X, "C")]
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(step, links, self.keyset)

    def test_threshold_short_refused(self):
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(self.step, [self._link(_DIGEST_X, "A")],
                             self.keyset)

    def test_unauthorized_functionary_refused(self):
        links = [self._link(_DIGEST_X, "A"),
                 qp.make_link_record("build", _DIGEST_X,
                                     self.signers["D"])]
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(self.step, links,
                             _keyset(self.signers, "A", "B", "C", "D"))

    def test_unpinned_keyid_refused(self):
        kids = [self.signers["A"].key_id, self.signers["D"].key_id]
        step = qp.load_quorum_step({
            "step_name": "build", "authorized_keyids": kids,
            "threshold": 1,
        })
        links = [qp.make_link_record("build", _DIGEST_X,
                                     self.signers["D"])]
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(step, links,
                             _keyset(self.signers, "A"))

    def test_bad_signature_refused(self):
        body = qp.canonical_link_body(
            "build", _DIGEST_X, "make all",
            self.signers["A"].key_id)
        bad = {
            "step_name": "build",
            "statement_digest": _DIGEST_X,
            "expected_command": "make all",
            "signer_keyid": self.signers["A"].key_id,
            "signature": self.signers["B"].sign(body).hex(),
        }
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(self.step, [bad], self.keyset)

    def test_equivocation_refused(self):
        links = [self._link(_DIGEST_X, "A"), self._link(_DIGEST_Y, "A")]
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(self.step, links, self.keyset)

    def test_ambiguity_refused(self):
        step = qp.load_quorum_step({
            "step_name": "build",
            "authorized_keyids": [self.signers["A"].key_id,
                                  self.signers["B"].key_id],
            "threshold": 1,
        })
        links = [self._link(_DIGEST_X, "A"), self._link(_DIGEST_Y, "B")]
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(step, links,
                             _keyset(self.signers, "A", "B"))

    def test_cross_step_replay_refused(self):
        links = [self._link(_DIGEST_X, "A", step="deploy")]
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(self.step, links, self.keyset)

    def test_duplicate_counts_once(self):
        step = qp.load_quorum_step({
            "step_name": "build",
            "authorized_keyids": [self.signers["A"].key_id],
            "threshold": 1,
        })
        links = [self._link(_DIGEST_X, "A"), self._link(_DIGEST_X, "A")]
        report = qp.verify_quorum(step, links,
                                  _keyset(self.signers, "A"))
        self.assertEqual(report["distinct_signers"], 1)

    def test_command_mismatch_is_diagnostic(self):
        links = [self._link(_DIGEST_X, "A", command="make all"),
                 self._link(_DIGEST_X, "B", command="make install")]
        report = qp.verify_quorum(self.step, links, self.keyset)
        self.assertEqual(report["statement_digest"], _DIGEST_X)
        self.assertFalse(report["command_agreement"])
        self.assertEqual(report["expected_commands"],
                         ["make all", "make install"])

    def test_command_match_does_not_admit(self):
        links = [self._link(_DIGEST_X, "A", command="make all"),
                 self._link(_DIGEST_Y, "B", command="make all")]
        with self.assertRaises(qp.QuorumPolicyError):
            qp.verify_quorum(self.step, links, self.keyset)

    def test_malformed_records_refused(self):
        for bad in ({"step_name": "build"}, "not-a-dict",
                    dict(self._link(_DIGEST_X, "A"),
                         statement_digest="not-hex")):
            with self.assertRaises((qp.QuorumPolicyError, ValueError),
                                   msg="record=%r" % (bad,)):
                qp.verify_quorum(self.step, [bad], self.keyset)

    def test_deterministic_report(self):
        links = [self._link(_DIGEST_X, "B"), self._link(_DIGEST_X, "A")]
        r1 = qp.verify_quorum(self.step, links, self.keyset)
        r2 = qp.verify_quorum(self.step, links, self.keyset)
        self.assertEqual(r1, r2)


class TestPromoteWiring(unittest.TestCase):
    def setUp(self):
        self.signers = _signers()
        self.verifiers = [Ed25519Verifier(s.public_key)
                          for s in (self.signers["A"], self.signers["B"])]
        from gov import sign_deploy_namespaces as sdn  # noqa: E402
        self.sdn = sdn
        self.step = qp.load_quorum_step({
            "step_name": "promote",
            "authorized_keyids": [s.key_id for s in
                                  (self.signers["A"], self.signers["B"])],
            "threshold": 2,
        })

    def _reg(self):
        reg = self.sdn.NamespaceRegistry(verifiers=self.verifiers,
                                         threshold=1)
        reg.stage("skill/q", b"bytes")
        reg.sign("skill/q", [self.signers["A"]])
        return reg

    def _honest(self):
        return [qp.make_link_record("promote", _DIGEST_X,
                                    self.signers[n])
                for n in ("A", "B")]

    def test_absent_policy_legacy_byte_identical(self):
        reg = self._reg()
        promoted = reg.promote("skill/q", operator_ids=["op1", "op2"])
        self.assertEqual(promoted["status"], "promoted")
        audit_detail = reg.audit[-1]["detail"]
        self.assertNotIn("quorum", audit_detail)

    def test_policy_without_links_fails_closed(self):
        reg = self._reg()
        with self.assertRaises(self.sdn.NamespaceError) as ctx:
            reg.promote("skill/q", operator_ids=["op1", "op2"],
                        quorum_policy=self.step)
        self.assertEqual(ctx.exception.code, "quorum-gate-refused")

    def test_honest_quorum_admits(self):
        reg = self._reg()
        promoted = reg.promote("skill/q", operator_ids=["op1", "op2"],
                               quorum_policy=self.step,
                               quorum_links=self._honest())
        self.assertEqual(promoted["status"], "promoted")
        self.assertIn("quorum=", reg.audit[-1]["detail"])

    def test_disagreeing_quorum_denies(self):
        reg = self._reg()
        bad = [qp.make_link_record("promote", _DIGEST_X,
                                   self.signers["A"]),
               qp.make_link_record("promote", _DIGEST_Y,
                                   self.signers["B"])]
        with self.assertRaises(self.sdn.NamespaceError) as ctx:
            reg.promote("skill/q", operator_ids=["op1", "op2"],
                        quorum_policy=self.step, quorum_links=bad)
        self.assertEqual(ctx.exception.code, "quorum-gate-refused")
        self.assertEqual(reg.audit[-1]["op"], "promotion-denied")

    def test_bad_policy_type_refused(self):
        reg = self._reg()
        with self.assertRaises(self.sdn.NamespaceError) as ctx:
            reg.promote("skill/q", operator_ids=["op1", "op2"],
                        quorum_policy={"step_name": "promote"})
        self.assertEqual(ctx.exception.code, "bad-quorum-policy")


if __name__ == "__main__":
    unittest.main()
