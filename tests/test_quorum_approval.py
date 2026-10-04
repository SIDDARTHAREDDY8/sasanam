"""Unit tests for gov/quorum_approval.py (m-of-n operation approval).

Tests the public seams only: register_policy / attest / deny /
operation_digest / QuorumCollector / QuorumGate. The red-first battery
(evals/w320_quorum_probes.py) covers the adversarial paths; these tests
pin the contract edges.
"""

import unittest

import time as _time

from gov import ed25519 as _ed
from gov import quorum_approval as qa


def _approvers(names=("alice", "bob", "carol")):
    out, seeds = [], {}
    for name in names:
        seed = _ed.generate_seed()
        out.append({"name": name,
                    "spiffe_id": "spiffe://prod/%s" % name,
                    "public_key": _ed.publickey(seed)})
        seeds[name] = seed
    return out, seeds


def _policy_cfg(approvers, m=2, policy_id="op:test", version=1):
    return {"policy_id": policy_id, "version": version, "m": m,
            "approvers": approvers,
            "change_log": [{"version": version, "changed_at": 1700000000,
                            "change": "genesis", "author": "test"}]}


class PolicyRegistrationTests(unittest.TestCase):
    def setUp(self):
        qa.reset_registry()

    def test_registers_valid_policy(self):
        approvers, _ = _approvers()
        p = qa.register_policy(_policy_cfg(approvers, m=2))
        self.assertEqual(p.m, 2)
        self.assertEqual(p.version, 1)
        self.assertEqual(p.approver_names(), ("alice", "bob", "carol"))

    def test_m_must_be_positive_int(self):
        approvers, _ = _approvers()
        for bad in (0, -1, "2", 1.5, True):
            with self.assertRaises(qa.PolicyRefusal):
                qa.register_policy(_policy_cfg(approvers, m=bad))

    def test_unreachable_quorum_refused(self):
        approvers, _ = _approvers()
        with self.assertRaises(qa.PolicyRefusal) as ctx:
            qa.register_policy(_policy_cfg(approvers, m=4))
        self.assertEqual(ctx.exception.code, "quorum-unreachable")

    def test_duplicate_names_refused(self):
        approvers, seeds = _approvers()
        approvers = [dict(a) for a in approvers]
        approvers[1] = dict(approvers[1], name="alice",
                            public_key=_ed.publickey(_ed.generate_seed()))
        with self.assertRaises(qa.PolicyRefusal) as ctx:
            qa.register_policy(_policy_cfg(approvers))
        self.assertEqual(ctx.exception.code, "quorum-malformed")

    def test_key_reuse_across_names_refused(self):
        approvers, _ = _approvers()
        approvers = [dict(a) for a in approvers]
        approvers[1] = dict(approvers[1],
                            public_key=approvers[0]["public_key"])
        with self.assertRaises(qa.PolicyRefusal) as ctx:
            qa.register_policy(_policy_cfg(approvers))
        self.assertEqual(ctx.exception.code, "quorum-key-reuse")

    def test_version_monotonic(self):
        approvers, _ = _approvers()
        qa.register_policy(_policy_cfg(approvers, version=1))
        with self.assertRaises(qa.PolicyRefusal) as ctx:
            qa.register_policy(_policy_cfg(approvers, version=1))
        self.assertEqual(ctx.exception.code, "quorum-policy-version-invalid")
        # A bump registers fine.
        p2 = qa.register_policy(_policy_cfg(approvers, version=2))
        self.assertEqual(p2.version, 2)

    def test_change_log_required(self):
        approvers, _ = _approvers()
        cfg = _policy_cfg(approvers)
        cfg["change_log"] = []
        with self.assertRaises(qa.PolicyRefusal):
            qa.register_policy(cfg)


class AttestationTests(unittest.TestCase):
    def setUp(self):
        qa.reset_registry()
        self.approvers, self.seeds = _approvers()
        self.policy = qa.register_policy(_policy_cfg(self.approvers))
        self.digest = qa.operation_digest({"op": "test"})

    def test_attest_signs_verifiably(self):
        att = qa.attest(self.seeds["alice"], "alice", self.digest,
                        self.policy, nonce="n1", issued_at=1700000000)
        self.assertEqual(att["kind"], "approve")
        self.assertEqual(att["policy_version"], 1)
        # The signature verifies against the pinned key (contract pin).
        body = {k: v for k, v in att.items() if k != "signature"}
        self.assertIs(
            _ed.verify(self.approvers[0]["public_key"],
                       qa._canonical_bytes(body),
                       bytes.fromhex(att["signature"])), True)

    def test_deny_has_reason_and_kind(self):
        att = qa.deny(self.seeds["alice"], "alice", self.digest,
                      self.policy, nonce="n1", reason="looks wrong",
                      issued_at=1700000000)
        self.assertEqual(att["kind"], "deny")
        self.assertEqual(att["reason"], "looks wrong")

    def test_deny_requires_reason(self):
        with self.assertRaises(qa.AttestationRefusal):
            qa.deny(self.seeds["alice"], "alice", self.digest,
                    self.policy, nonce="n1", reason="  ")

    def test_operation_digest_deterministic(self):
        d1 = qa.operation_digest({"op": "x", "n": 1})
        d2 = qa.operation_digest({"n": 1, "op": "x"})
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)

    def test_ttl_bounded(self):
        with self.assertRaises(qa.AttestationRefusal):
            qa.attest(self.seeds["alice"], "alice", self.digest,
                      self.policy, nonce="n1", ttl_seconds=7200)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        qa.reset_registry()
        self.approvers, self.seeds = _approvers()
        self.policy = qa.register_policy(_policy_cfg(self.approvers))
        self.digest = qa.operation_digest({"op": "test"})
        self.col = qa.QuorumCollector(self.policy, self.digest,
                                      now=1700000000)

    def _att(self, name, nonce, digest=None):
        return qa.attest(self.seeds[name], name, digest or self.digest,
                         self.policy, nonce=nonce, issued_at=1700000000)

    def test_empty_evaluate_insufficient(self):
        v = self.col.evaluate()
        self.assertFalse(v["executable"])
        self.assertEqual(v["code"], "quorum-insufficient")
        self.assertEqual(v["counted"], 0)

    def test_second_attestation_same_name_recorded_not_counted(self):
        self.col.collect(self._att("alice", "n1"))
        rec = self.col.collect(self._att("alice", "n2"))
        self.assertTrue(rec["accepted"])
        self.assertFalse(rec["counted"])
        # The spec assigns quorum-duplicate-approver to this event
        # (informational); the refusal code for execution attempts is
        # quorum-insufficient.
        self.assertEqual(rec["code"], "quorum-duplicate-approver")
        self.assertEqual(self.col.evaluate()["counted"], 1)

    def test_deny_veto_with_full_quorum(self):
        self.col.collect(self._att("alice", "n1"))
        self.col.collect(self._att("bob", "n2"))
        d = qa.deny(self.seeds["carol"], "carol", self.digest,
                    self.policy, nonce="n3", reason="no",
                    issued_at=1700000000)
        self.col.collect(d)
        v = self.col.evaluate()
        self.assertFalse(v["executable"])
        self.assertEqual(v["code"], "quorum-deny-veto")
        self.assertEqual(v["denied_by"], ["carol"])

    def test_policy_id_binding(self):
        other_policy = qa.register_policy(
            _policy_cfg(self.approvers, policy_id="op:other"))
        att = qa.attest(self.seeds["alice"], "alice", self.digest,
                        other_policy, nonce="n1", issued_at=1700000000)
        with self.assertRaises(qa.AttestationRefusal) as ctx:
            self.col.collect(att)
        self.assertEqual(ctx.exception.code, "quorum-operation-mismatch")

    def test_malformed_attestation_refuses_coded(self):
        # Wrong types fail closed with a coded refusal, never a bare
        # TypeError (e.g. an unhashable approver name in dict.get()).
        att = self._att("alice", "n1")
        for bad in ({"approver": {"x": 1}}, {"approver": ["a"]},
                    {"nonce": 123}, {"issued_at": "now"},
                    {"ttl_seconds": True}, {"signature": "zz"}):
            bad_att = dict(att, **bad)
            with self.assertRaises(qa.AttestationRefusal) as ctx:
                self.col.collect(bad_att)
            self.assertEqual(ctx.exception.code, "quorum-malformed")

    def test_records_audit_trail(self):
        self.col.collect(self._att("alice", "n1"))
        recs = self.col.records()
        self.assertEqual(len(recs), 1)
        self.assertTrue(recs[0]["accepted"])


class GateTests(unittest.TestCase):
    def setUp(self):
        qa.reset_registry()
        self.approvers, self.seeds = _approvers()
        self.policy = qa.register_policy(_policy_cfg(self.approvers))
        self.gate = qa.QuorumGate()

    def test_unregistered_allows_advisory(self):
        v = self.gate.check("op:anything", {"digest": "x"})
        self.assertTrue(v["allowed"])
        self.assertEqual(v["mode"], "absent")

    def test_check_without_digest_refuses(self):
        self.gate.register_sensitive("op:s", self.policy)
        v = self.gate.check("op:s", {})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["code"], "quorum-malformed")

    def test_re_registration_resets_collection(self):
        now = int(_time.time())
        digest = qa.operation_digest({"op": "s"})
        self.gate.register_sensitive("op:s", self.policy)
        self.gate.check("op:s", {"digest": digest})
        col = self.gate.collector_for("op:s")
        col.collect(qa.attest(self.seeds["alice"], "alice", digest,
                              self.policy, nonce="n1", issued_at=now))
        # Re-registering the same policy resets the collector.
        self.gate.register_sensitive("op:s", self.policy)
        with self.assertRaises(KeyError):
            # Old collector is gone; check() creates a fresh one.
            self.gate.collector_for("op:s")
        v = self.gate.check("op:s", {"digest": digest})
        self.assertEqual(v["counted"], 0)


if __name__ == "__main__":
    unittest.main()
