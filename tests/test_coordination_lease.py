"""Unit tests for gov/coordination_lease.py (wave-294 lane 2).

Lease-bound authority (etcd pattern): every grant carries a
mandatory expiry and a fencing token; zombie writes die.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import coordination_lease as cl
from gov import decision_codes
from gov import ed25519

_SEED_AUTH = bytes(range(1, 33))
_SEED_OTHER = bytes(range(33, 65))


def _pub(seed):
    return ed25519.publickey(seed).hex()


class CoordinationLeaseTest(unittest.TestCase):
    def setUp(self):
        self.m = cl.LeaseManager()
        self.pub = _pub(_SEED_AUTH)

    def acquire(self, scope="anchor-sequencer", ttl=3600, holder="agent-a",
                issued_at=1000, seed=_SEED_AUTH):
        return self.m.acquire(scope, ttl, holder, authority_seed=seed,
                              issued_at=issued_at)

    # -- acquisition ---------------------------------------------------

    def test_acquire_shape(self):
        lease = self.acquire()
        self.assertEqual(lease["scope"], "anchor-sequencer")
        self.assertEqual(lease["holder_id"], "agent-a")
        self.assertEqual(lease["issued_at"], 1000)
        self.assertEqual(lease["not_after"], 4600)
        self.assertEqual(lease["fencing_token"], 1)
        self.assertEqual(lease["authority_pubkey"], self.pub)
        ok, detail = cl.verify_lease(lease, self.pub, checked_at=1000)
        self.assertIs(ok, True)
        self.assertEqual(detail["fencing_token"], 1)
        self.assertEqual(detail["remaining_seconds"], 3600)

    def test_acquire_denied_while_live(self):
        self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.acquire(holder="agent-b", issued_at=1001)
        self.assertEqual(cm.exception.code, "coord-lease-denied")

    def test_reacquire_after_expiry_higher_token(self):
        old = self.acquire(ttl=100)
        new = self.acquire(ttl=100, holder="agent-b", issued_at=1101)
        self.assertGreater(new["fencing_token"], old["fencing_token"])

    def test_acquire_requires_authority_seed(self):
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.acquire("s", 100, "agent-a", issued_at=1000)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_bad_ttls(self):
        for bad in (0, -5, 10 ** 12, "3600", True, None):
            with self.assertRaises(cl.CoordinationLeaseError,
                                   msg="ttl %r" % (bad,)) as cm:
                self.m.acquire("s", bad, "agent-a",
                               authority_seed=_SEED_AUTH, issued_at=1000)
            self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_bad_scope_holder(self):
        for bad_scope in ("", "UPPER", "x" * 65, 12, None):
            with self.assertRaises(cl.CoordinationLeaseError,
                                   msg="scope %r" % (bad_scope,)) as cm:
                self.m.acquire(bad_scope, 100, "agent-a",
                               authority_seed=_SEED_AUTH, issued_at=1000)
            self.assertEqual(cm.exception.code, "coord-lease-invalid")
        for bad_holder in ("", "Agent-A", 12, None):
            with self.assertRaises(cl.CoordinationLeaseError,
                                   msg="holder %r" % (bad_holder,)) as cm:
                self.m.acquire("s", 100, bad_holder,
                               authority_seed=_SEED_AUTH, issued_at=1000)
            self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_bad_seed(self):
        for bad in (b"short", "not-bytes", None):
            with self.assertRaises(cl.CoordinationLeaseError) as cm:
                self.m.acquire("s", 100, "agent-a",
                               authority_seed=bad, issued_at=1000)
            self.assertEqual(cm.exception.code, "coord-lease-invalid")

    # -- renewal ---------------------------------------------------------

    def test_renew_extends_same_generation(self):
        lease = self.acquire(ttl=100)
        renewed = self.m.renew("anchor-sequencer", lease["fencing_token"],
                               "agent-a", 500, authority_seed=_SEED_AUTH,
                               checked_at=1050)
        self.assertEqual(renewed["not_after"], lease["not_after"] + 500)
        self.assertEqual(renewed["fencing_token"], lease["fencing_token"])
        ok, _ = cl.verify_lease(renewed, self.pub, checked_at=1050)
        self.assertIs(ok, True)

    def test_renew_stale_token_fencing(self):
        lease = self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.renew("anchor-sequencer", lease["fencing_token"] + 99,
                         "agent-a", 500, authority_seed=_SEED_AUTH,
                         checked_at=1050)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_renew_wrong_holder_invalid(self):
        lease = self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.renew("anchor-sequencer", lease["fencing_token"],
                         "agent-b", 500, authority_seed=_SEED_AUTH,
                         checked_at=1050)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_renew_expired(self):
        lease = self.acquire(ttl=100)
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.renew("anchor-sequencer", lease["fencing_token"],
                         "agent-a", 500, authority_seed=_SEED_AUTH,
                         checked_at=1101)
        self.assertEqual(cm.exception.code, "coord-lease-expired")

    def test_renew_authority_mismatch(self):
        lease = self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.renew("anchor-sequencer", lease["fencing_token"],
                         "agent-a", 500, authority_seed=_SEED_OTHER,
                         checked_at=1050)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    # -- write authorization ---------------------------------------------

    def test_check_write_current_token(self):
        lease = self.acquire()
        self.assertTrue(self.m.check_write("anchor-sequencer",
                                           lease["fencing_token"],
                                           "agent-a", checked_at=2000))

    def test_zombie_write_dies(self):
        old = self.acquire(ttl=100)
        self.acquire(ttl=100, holder="agent-b", issued_at=1101)
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.check_write("anchor-sequencer", old["fencing_token"],
                               "agent-a", checked_at=1102)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_old_generation_token_replay_dies(self):
        gen1 = self.acquire(ttl=100)
        self.acquire(ttl=100, holder="agent-a", issued_at=1101)
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.check_write("anchor-sequencer", gen1["fencing_token"],
                               "agent-a", checked_at=1102)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_write_on_expired_lease_predecay(self):
        lease = self.acquire(ttl=100)
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.check_write("anchor-sequencer", lease["fencing_token"],
                               "agent-a", checked_at=1101)
        self.assertEqual(cm.exception.code, "coord-lease-expired")

    def test_write_wrong_holder_current_token(self):
        lease = self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.check_write("anchor-sequencer", lease["fencing_token"],
                               "agent-b", checked_at=2000)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_write_no_lease(self):
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.check_write("anchor-sequencer", 1, "agent-a",
                               checked_at=2000)
        self.assertEqual(cm.exception.code, "coord-lease-expired")

    # -- release ----------------------------------------------------------

    def test_release_frees_scope(self):
        lease = self.acquire()
        self.assertTrue(self.m.release("anchor-sequencer",
                                       lease["fencing_token"], "agent-a"))
        lease2 = self.acquire(holder="agent-b", issued_at=1001)
        self.assertEqual(lease2["holder_id"], "agent-b")
        # The epoch never resets: the next generation's token is higher.
        self.assertGreater(lease2["fencing_token"], lease["fencing_token"])

    def test_release_wrong_holder(self):
        lease = self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.release("anchor-sequencer", lease["fencing_token"],
                           "agent-b")
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_release_stale_token(self):
        lease = self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.release("anchor-sequencer",
                           lease["fencing_token"] + 5, "agent-a")
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_release_no_lease(self):
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            self.m.release("anchor-sequencer", 1, "agent-a")
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    # -- stateless verification -------------------------------------------

    def test_verify_unsigned(self):
        fake = {"scope": "anchor-sequencer", "holder_id": "agent-a",
                "issued_at": 1000, "not_after": 4600, "fencing_token": 1,
                "authority_pubkey": self.pub, "signature": "00" * 64}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            cl.verify_lease(fake, self.pub, checked_at=2000)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_verify_tampered(self):
        lease = self.acquire()
        tampered = dict(lease)
        tampered["not_after"] = 10 ** 12
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            cl.verify_lease(tampered, self.pub, checked_at=2000)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_verify_expired(self):
        lease = self.acquire(ttl=100)
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            cl.verify_lease(lease, self.pub, checked_at=1101)
        self.assertEqual(cm.exception.code, "coord-lease-expired")

    def test_verify_wrong_authority(self):
        lease = self.acquire()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            cl.verify_lease(lease, _pub(_SEED_OTHER), checked_at=2000)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_verify_circular(self):
        evil = {}
        evil["self"] = evil
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            cl.verify_lease(evil, self.pub, checked_at=2000)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_verify_non_dict(self):
        for bad in (None, "lease", [1, 2]):
            with self.assertRaises(cl.CoordinationLeaseError,
                                   msg="%r" % (bad,)) as cm:
                cl.verify_lease(bad, self.pub, checked_at=2000)
            self.assertEqual(cm.exception.code, "coord-lease-invalid")

    # -- seams and contracts -----------------------------------------------

    def test_ed25519_contract(self):
        # Wave-243 lesson: ed25519.verify is bool-returning; assert
        # exact True/False, never truthiness.
        msg = b"contract pin"
        sig = ed25519.sign(_SEED_AUTH, msg)
        self.assertIs(ed25519.verify(self.pub_bytes(), msg, sig), True)
        self.assertIs(ed25519.verify(self.pub_bytes(), msg,
                                     ed25519.sign(_SEED_OTHER, msg)), False)

    def pub_bytes(self):
        return bytes.fromhex(self.pub)

    def test_sink_isolation(self):
        # F345-class: a broken audit sink can never break the lease.
        cl._EMIT = lambda event, fields: 1 / 0
        try:
            lease = self.acquire(scope="sink-test")
            self.assertEqual(lease["scope"], "sink-test")
        finally:
            cl._EMIT = None

    def test_codes_registered(self):
        for code in ("coord-lease-denied", "coord-lease-expired",
                     "coord-lease-fencing", "coord-lease-invalid"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(decision_codes.TAXONOMY[code]["domain"],
                             "coord-lease")

    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), 2131) # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)


if __name__ == "__main__":
    unittest.main()
