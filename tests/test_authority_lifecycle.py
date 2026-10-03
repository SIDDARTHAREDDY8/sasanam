"""Unit tests for gov/authority_lifecycle.py: authority leases with heartbeats.

Every coded refusal is asserted by code (F351 contract); the ed25519
True/False contract is pinned on the paths this module touches; the
three new decision codes are pinned as raw source literals.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import authority_lifecycle as al
from gov import delegation_revocation as rv
from gov import ed25519


def _seed(tag):
    return hashlib.sha256(("w303alu-" + tag).encode()).digest()


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


AT = 1_700_000_000


class LifecycleFixture(unittest.TestCase):
    def setUp(self):
        self.sg = _seed("granter")
        self.sx = _seed("subject")
        self.px = ed25519.publickey(self.sx).hex()
        self.mgr = al.AuthorityLeaseManager()

    def _lease(self, **kw):
        args = dict(granter_id="granter-a", granter_seed=self.sg,
                    subject_id="agent-x", subject_pubkey_hex=self.px,
                    scope_digest=_hex64("scope:tool.invoke"),
                    issued_at=AT, ttl_seconds=3600,
                    heartbeat_interval_seconds=60)
        args.update(kw)
        return self.mgr.issue_lease(**args)

    def _proof(self, lease, counter, at, seed=None, signer_id="agent-x"):
        return al.make_proof(
            lease_id=lease["lease_id"], subject_id=lease["subject_id"],
            scope_digest=lease["scope_digest"], counter=counter,
            proof_issued_at=at, signer_id=signer_id,
            signer_seed=seed or self.sx)

    def _authz(self, action, lease, actor_id, seed, at):
        return al.make_authorization(action=action,
                                     lease_id=lease["lease_id"],
                                     actor_id=actor_id, actor_seed=seed,
                                     at=at)

    def test_issue_records_granter_signature(self):
        import json
        lease = self._lease()
        self.assertTrue(lease["granter_signature"])
        body = {k: lease[k] for k in (
            "lease_id", "granter_id", "subject_id", "subject_pubkey_hex",
            "monitor_id", "monitor_pubkey_hex", "scope_digest", "issued_at",
            "ttl_seconds", "heartbeat_interval_seconds")}
        # Independent recomputation of the signed message (not the
        # module's own _canonical): the granter's signature must bind
        # exactly this body.
        msg = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
        gp = ed25519.publickey(self.sg)
        self.assertIs(
            ed25519.verify(gp, msg,
                          bytes.fromhex(lease["granter_signature"])),
            True)
        kinds = [e["kind"] for e in self.mgr.journal]
        self.assertIn("lease-issued", kinds)

    def test_lease_id_deterministic(self):
        a = self._lease()
        # Deterministic across manager instances (same issuance identity).
        other_mgr = al.AuthorityLeaseManager()
        self.mgr, prev = other_mgr, self.mgr
        try:
            b = self._lease()
        finally:
            self.mgr = prev
        self.assertEqual(a["lease_id"], b["lease_id"])
        self.assertEqual(a["lease_id"],
                         al.lease_id_for("granter-a", "agent-x",
                                         _hex64("scope:tool.invoke"), AT))
        self.assertRegex(a["lease_id"], r"^[0-9a-f]{64}$")

    def test_check_active(self):
        lease = self._lease()
        v = self.mgr.check(lease["lease_id"], at=AT + 10)
        self.assertEqual(v["state"], "ACTIVE")
        self.assertEqual(v["next_heartbeat_due"], AT + 60)
        self.assertEqual(v["expires_at"], AT + 3600)

    def test_heartbeat_advances_stream(self):
        lease = self._lease()
        acc = self.mgr.heartbeat(lease["lease_id"],
                                 self._proof(lease, 1, AT + 20), at=AT + 20)
        self.assertEqual(acc["counter"], 1)
        self.assertEqual(acc["state"], "ACTIVE")

    def test_missed_heartbeat_suspends_coded(self):
        lease = self._lease()
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.check(lease["lease_id"], at=AT + 61)
        self.assertEqual(cm.exception.code,
                         "authority-lifecycle-heartbeat-lapsed")
        self.assertEqual(self.mgr.state_of(lease["lease_id"], at=AT + 61),
                         "SUSPENDED")

    def test_suspended_check_refuses(self):
        lease = self._lease()
        try:
            self.mgr.check(lease["lease_id"], at=AT + 61)
        except al.AuthorityLifecycleError:
            pass
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.check(lease["lease_id"], at=AT + 62)
        self.assertEqual(cm.exception.code,
                         "authority-lifecycle-heartbeat-lapsed")

    def test_replayed_counter_refused(self):
        lease = self._lease()
        self.mgr.heartbeat(lease["lease_id"], self._proof(lease, 1, AT + 20),
                           at=AT + 20)
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.heartbeat(lease["lease_id"],
                               self._proof(lease, 1, AT + 30), at=AT + 30)
        self.assertEqual(cm.exception.code,
                         "authority-lifecycle-heartbeat-lapsed")

    def test_forged_proof_signature_refused(self):
        lease = self._lease()
        evil = _seed("evil")
        bad = self._proof(lease, 1, AT + 20, seed=evil, signer_id="agent-x")
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.heartbeat(lease["lease_id"], bad, at=AT + 20)
        self.assertEqual(cm.exception.code,
                         "authority-lifecycle-heartbeat-lapsed")

    def test_proof_for_wrong_lease_refused(self):
        a = self._lease()
        b = self._lease(issued_at=AT + 1)
        cross = self._proof(b, 1, AT + 20)
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.heartbeat(a["lease_id"], cross, at=AT + 20)
        self.assertEqual(cm.exception.code,
                         "authority-lifecycle-heartbeat-lapsed")

    def test_expired_terminal_coded(self):
        lease = self._lease(ttl_seconds=100)
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.check(lease["lease_id"], at=AT + 101)
        self.assertEqual(cm.exception.code, "authority-lifecycle-expired")
        self.assertEqual(self.mgr.state_of(lease["lease_id"], at=AT + 101),
                         "EXPIRED")

    def test_revocation_kills_lease_coded(self):
        revoker = rv.DelegationRevoker(self.sg, "granter-a")
        mgr = al.AuthorityLeaseManager(revokers={"granter-a": revoker})
        lease = mgr.issue_lease(
            granter_id="granter-a", granter_seed=self.sg,
            subject_id="agent-x", subject_pubkey_hex=self.px,
            scope_digest=_hex64("scope:tool.invoke"), issued_at=AT,
            ttl_seconds=3600, heartbeat_interval_seconds=60)
        revoker.revoke(lease["lease_id"], AT + 20)
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            mgr.check(lease["lease_id"], at=AT + 30)
        self.assertEqual(cm.exception.code, "authority-lifecycle-revoked")

    def test_revoked_never_revives(self):
        revoker = rv.DelegationRevoker(self.sg, "granter-a")
        mgr = al.AuthorityLeaseManager(revokers={"granter-a": revoker})
        lease = mgr.issue_lease(
            granter_id="granter-a", granter_seed=self.sg,
            subject_id="agent-x", subject_pubkey_hex=self.px,
            scope_digest=_hex64("scope:tool.invoke"), issued_at=AT,
            ttl_seconds=3600, heartbeat_interval_seconds=60)
        revoker.revoke(lease["lease_id"], AT + 20)
        p = al.make_proof(lease_id=lease["lease_id"],
                          subject_id=lease["subject_id"],
                          scope_digest=lease["scope_digest"], counter=1,
                          proof_issued_at=AT + 30, signer_id="agent-x",
                          signer_seed=self.sx)
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            mgr.heartbeat(lease["lease_id"], p, at=AT + 30)
        self.assertEqual(cm.exception.code, "authority-lifecycle-revoked")

    def test_suspend_parks_ttl(self):
        lease = self._lease(ttl_seconds=100, heartbeat_interval_seconds=60)
        self.mgr.suspend(lease["lease_id"],
                         authorization=self._authz(
                             "authority-lifecycle-suspend", lease,
                             "agent-x", self.sx, AT + 10),
                         at=AT + 10)
        self.assertEqual(self.mgr.state_of(lease["lease_id"], at=AT + 11),
                         "SUSPENDED")
        # Resume after ttl refuses expired: the park never extended it.
        p = self._proof(lease, 1, AT + 101)
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.resume(
                lease["lease_id"],
                authorization=self._authz("authority-lifecycle-resume",
                                          lease, "agent-x", self.sx,
                                          AT + 101),
                proof=p, at=AT + 101)
        self.assertEqual(cm.exception.code, "authority-lifecycle-expired")

    def test_resume_restarts_stream(self):
        lease = self._lease()
        self.mgr.suspend(lease["lease_id"],
                         authorization=self._authz(
                             "authority-lifecycle-suspend", lease,
                             "granter-a", self.sg, AT + 10),
                         at=AT + 10)
        acc = self.mgr.resume(
            lease["lease_id"],
            authorization=self._authz("authority-lifecycle-resume", lease,
                                      "granter-a", self.sg, AT + 70),
            proof=self._proof(lease, 1, AT + 70), at=AT + 70)
        self.assertEqual(acc["state"], "ACTIVE")
        v = self.mgr.check(lease["lease_id"], at=AT + 80)
        self.assertEqual(v["state"], "ACTIVE")

    def test_unauthorized_suspend_refused(self):
        lease = self._lease()
        bad = self._authz("authority-lifecycle-suspend", lease, "mallory",
                          _seed("mallory"), AT + 10)
        with self.assertRaises(al.AuthorityLifecycleError) as cm:
            self.mgr.suspend(lease["lease_id"], authorization=bad,
                             at=AT + 10)
        self.assertEqual(cm.exception.code,
                         "authority-lifecycle-heartbeat-lapsed")
        self.assertEqual(self.mgr.state_of(lease["lease_id"], at=AT + 11),
                         "ACTIVE")

    def test_unknown_lease_is_key_error(self):
        with self.assertRaises(KeyError):
            self.mgr.check("0" * 64, at=AT)

    def test_evidence_chain(self):
        lease = self._lease()
        self.mgr.heartbeat(lease["lease_id"], self._proof(lease, 1, AT + 20),
                           at=AT + 20)
        ev = self.mgr.verify_evidence()
        self.assertIs(ev["ok"], True)
        self.assertGreaterEqual(ev["events"], 2)
        # Journal digests chain.
        prev = "0" * 64
        for e in self.mgr.journal:
            self.assertEqual(e["prev"], prev)
            prev = e["digest"]

    def test_new_codes_pinned_as_literals(self):
        import re
        with open("gov/decision_codes.py", encoding="utf-8") as fh:
            src = fh.read()
        for code in ("authority-lifecycle-expired",
                     "authority-lifecycle-heartbeat-lapsed",
                     "authority-lifecycle-revoked"):
            self.assertEqual(len(re.findall(
                r'"code":\s*\'%s\'' % re.escape(code), src)), 1, code)

    def test_ed25519_verify_contract(self):
        pub = ed25519.publickey(self.sx)
        sig = ed25519.sign(self.sx, b"pin")
        self.assertIs(ed25519.verify(pub, b"pin", sig), True)
        self.assertIs(ed25519.verify(pub, b"other", sig), False)


class HeartbeatScheduleTest(unittest.TestCase):
    """Wave-304 lane D: the default heartbeat schedule is
    fraction-of-lifetime with a remediation floor
    (max(ceil(fraction * ttl), floor), clamped to ttl); an explicit
    interval remains a hard override. Scheduling arithmetic only --
    no change to proof verification, suspension, revocation, or the
    coded-refusal contract."""

    def setUp(self):
        self.sg = _seed("granter")
        self.sx = _seed("subject")
        self.px = ed25519.publickey(self.sx).hex()
        self.mgr = al.AuthorityLeaseManager()

    def _issue_default(self, **kw):
        args = dict(granter_id="granter-a", granter_seed=self.sg,
                    subject_id="agent-x", subject_pubkey_hex=self.px,
                    scope_digest=_hex64("scope:tool.invoke"),
                    issued_at=AT, ttl_seconds=3600)
        args.update(kw)
        return self.mgr.issue_lease(**args)

    def test_default_interval_is_fraction_of_ttl(self):
        # max(ceil(0.5 * 3600), 60) = 1800.
        lease = self._issue_default()
        self.assertEqual(lease["heartbeat_interval_seconds"], 1800)

    def test_floor_wins_for_short_ttl(self):
        # max(ceil(0.5 * 100) = 50, 60) = 60.
        lease = self._issue_default(ttl_seconds=100)
        self.assertEqual(lease["heartbeat_interval_seconds"], 60)

    def test_floor_clamped_to_ttl(self):
        # max(ceil(0.5 * 30) = 15, 60) = 60, but the floor must not
        # swallow the ttl -> clamped to 30.
        lease = self._issue_default(ttl_seconds=30)
        self.assertEqual(lease["heartbeat_interval_seconds"], 30)

    def test_explicit_interval_is_hard_override(self):
        lease = self._issue_default(heartbeat_interval_seconds=600)
        self.assertEqual(lease["heartbeat_interval_seconds"], 600)
        v = self.mgr.check(lease["lease_id"], at=AT + 599)
        self.assertEqual(v["next_heartbeat_due"], AT + 600)

    def test_invalid_fraction_refuses(self):
        for frac in (0, 1.5, -0.25, True):
            with self.assertRaises(ValueError, msg="fraction=%r" % (frac,)):
                self._issue_default(heartbeat_fraction=frac)

    def test_invalid_floor_refuses(self):
        for floor in (0, -5, "60"):
            with self.assertRaises(ValueError, msg="floor=%r" % (floor,)):
                self._issue_default(remediation_floor_seconds=floor)

    def test_schedule_parameters_journaled(self):
        lease = self._issue_default()
        issued = [e for e in self.mgr.journal
                  if e["kind"] == "lease-issued"
                  and e["lease_id"] == lease["lease_id"]]
        self.assertEqual(len(issued), 1)
        fields = issued[0]["fields"]
        self.assertEqual(fields["heartbeat_fraction"], 0.5)
        self.assertEqual(fields["remediation_floor_seconds"], 60)
        self.assertEqual(fields["schedule"], "derived")
        self.assertEqual(fields["heartbeat_interval_seconds"], 1800)


if __name__ == "__main__":
    unittest.main()
