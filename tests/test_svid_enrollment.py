"""Unit tests for gov.svid_enrollment (wave-260 lane 3, identity-mesh).

Pre-auth-key enrollment ceremony in front of the TEST issuer: random,
single-use, expiring keys; burn-before-issue ordering; used/expired/
unknown keys refuse with machine codes. Only key digests are stored.
"""

import hashlib
import os
import sys
import threading
import time
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import ed25519 as ed
from gov import svid_enrollment as se
from gov import svid_issuer as sv

_SEED = bytes(range(32))
_PUBKEY = "ab" * 32
_TD = "example.org"
NOW = 1700000000.0
SPIFFE_A = "spiffe://example.org/agent/a"
SPIFFE_B = "spiffe://example.org/agent/b"


def _issuer(**kw):
    kw.setdefault("issuer_seed", _SEED)
    return sv.TestSvidIssuer(**kw)


def _authority(**kw):
    kw.setdefault("issuer", _issuer())
    return se.EnrollmentAuthority(**kw)


def _verifier():
    return sv.SvidVerifier({"test-issuer-1": ed.publickey(_SEED)},
                           trust_domain=_TD)


class IssueKeyTest(unittest.TestCase):
    def test_key_is_random_urlsafe_string(self):
        auth = _authority()
        k1 = auth.issue_key(now=NOW)
        k2 = auth.issue_key(now=NOW)
        self.assertIsInstance(k1, str)
        self.assertTrue(k1)
        self.assertNotEqual(k1, k2)

    def test_default_ttl_recorded(self):
        auth = _authority()
        key = auth.issue_key(now=NOW)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        rec = auth._records[digest]
        self.assertEqual(rec["expires_at"],
                         int(NOW) + se.DEFAULT_KEY_TTL_SECONDS)

    def test_bad_spiffe_id_refused_at_issue(self):
        auth = _authority()
        with self.assertRaises(sv.SvidError) as ctx:
            auth.issue_key(spiffe_id="not-a-spiffe-id", now=NOW)
        self.assertEqual(ctx.exception.code, "svid-identity-malformed")

    def test_bad_ttl_refused_at_issue(self):
        auth = _authority()
        for bad in (0, -5, True, "60"):
            with self.assertRaises(sv.SvidError) as ctx:
                auth.issue_key(ttl_seconds=bad, now=NOW)
            self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_bad_issuer_refused(self):
        with self.assertRaises(sv.SvidError) as ctx:
            se.EnrollmentAuthority(issuer=object())
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_bad_default_ttl_refused(self):
        with self.assertRaises(sv.SvidError) as ctx:
            se.EnrollmentAuthority(issuer=_issuer(),
                                   default_key_ttl_seconds=0)
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_live_keys_counts(self):
        auth = _authority()
        self.assertEqual(auth.live_keys(), 0)
        auth.issue_key(now=NOW)
        auth.issue_key(now=NOW)
        self.assertEqual(auth.live_keys(), 2)


class RedeemHappyTest(unittest.TestCase):
    def test_redeem_mints_first_svid(self):
        auth = _authority()
        key = auth.issue_key(now=NOW)
        doc = auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                          now=NOW)
        claims = _verifier().verify(doc, now=NOW)
        self.assertEqual(claims["spiffe_id"], SPIFFE_A)

    def test_redeem_burns_key(self):
        auth = _authority()
        key = auth.issue_key(now=NOW)
        self.assertEqual(auth.live_keys(), 1)
        auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5, now=NOW)
        self.assertEqual(auth.live_keys(), 0)

    def test_raw_key_never_stored(self):
        auth = _authority()
        key = auth.issue_key(now=NOW)
        stored = list(auth._records.keys())
        self.assertNotIn(key, stored)
        self.assertTrue(all(len(d) == 64 for d in stored))
        self.assertIn(hashlib.sha256(key.encode("utf-8")).hexdigest(),
                      stored)

    def test_bound_key_enrolls_bound_workload(self):
        auth = _authority()
        key = auth.issue_key(spiffe_id=SPIFFE_A, now=NOW)
        doc = auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                          now=NOW)
        self.assertEqual(_verifier().verify(doc, now=NOW)["spiffe_id"],
                         SPIFFE_A)

    def test_binding_case_insensitive(self):
        auth = _authority()
        key = auth.issue_key(spiffe_id="spiffe://example.org/Agent/A",
                             now=NOW)
        doc = auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                          now=NOW)
        self.assertEqual(_verifier().verify(doc, now=NOW)["spiffe_id"],
                         SPIFFE_A)

    def test_unbound_key_enrolls_any_workload(self):
        auth = _authority()
        key = auth.issue_key(now=NOW)
        doc = auth.redeem(key, SPIFFE_B, _PUBKEY, ttl_minutes=5,
                          now=NOW)
        self.assertEqual(_verifier().verify(doc, now=NOW)["spiffe_id"],
                         SPIFFE_B)


class RedeemRefusalTest(unittest.TestCase):
    def test_replay_refused(self):
        auth = _authority()
        key = auth.issue_key(now=NOW)
        auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5, now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                        now=NOW + 1)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-replayed")

    def test_unknown_key_refused(self):
        auth = _authority()
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem("never-issued", SPIFFE_A, _PUBKEY,
                        ttl_minutes=5, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-unknown")

    def test_non_string_key_malformed(self):
        auth = _authority()
        for bad in (None, 123, b"bytes", ""):
            with self.assertRaises(sv.SvidError) as ctx:
                auth.redeem(bad, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                            now=NOW)
            self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_expired_key_refused_and_burned(self):
        auth = _authority(default_key_ttl_seconds=60)
        key = auth.issue_key(now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                        now=NOW + 61)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-expired")
        # Burned: a second redemption is a replay, not another expiry.
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                        now=NOW + 62)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-replayed")

    def test_expiry_boundary(self):
        auth = _authority(default_key_ttl_seconds=60)
        key = auth.issue_key(now=NOW)
        # now == expires_at is expired (>=), one second before is live.
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                        now=NOW + 60)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-expired")

    def test_binding_mismatch_refused_and_burned(self):
        auth = _authority()
        key = auth.issue_key(spiffe_id=SPIFFE_A, now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_B, _PUBKEY, ttl_minutes=5,
                        now=NOW)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-spiffe-mismatch")
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                        now=NOW + 1)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-replayed")

    def test_burn_before_issue(self):
        # Issuance failure (bad workload key) still retires the key.
        auth = _authority()
        key = auth.issue_key(now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, "not-a-key", ttl_minutes=5,
                        now=NOW)
        self.assertEqual(ctx.exception.code, "svid-identity-malformed")
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, _PUBKEY, ttl_minutes=5,
                        now=NOW + 1)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-replayed")

    def test_key_absent_from_error_detail(self):
        auth = _authority()
        try:
            auth.redeem("super-secret-unknown-key", SPIFFE_A, _PUBKEY,
                        ttl_minutes=5, now=NOW)
        except sv.SvidError as e:
            self.assertNotIn("super-secret-unknown-key", str(e))
            self.assertNotIn("super-secret-unknown-key", e.detail)
        else:
            self.fail("unknown key was not refused")


class ConcurrencyTest(unittest.TestCase):
    """F236: the key table is safe under threads.

    The single-key storm went red pre-fix (3-4 double-issuing trials
    per 150 in-lane); the lock makes the double-issue interleaving
    impossible, so these are deterministic green post-fix.
    """

    def test_concurrent_redeem_single_key_issues_exactly_one_svid(self):
        auth = _authority()
        old_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-7)  # scheduling pressure only
        try:
            for _ in range(150):
                key = auth.issue_key(spiffe_id=SPIFFE_A, now=NOW)
                barrier = threading.Barrier(64)
                results = []
                rlock = threading.Lock()

                def worker():
                    barrier.wait()
                    try:
                        auth.redeem(key, SPIFFE_A, _PUBKEY, 5, now=NOW)
                        r = "svid"
                    except sv.SvidError as e:
                        r = e.code
                    with rlock:
                        results.append(r)

                ths = [threading.Thread(target=worker)
                       for _ in range(64)]
                for th in ths:
                    th.start()
                for th in ths:
                    th.join()
                self.assertEqual(results.count("svid"), 1,
                                 "double-issue under concurrent redeem")
        finally:
            sys.setswitchinterval(old_interval)

    def test_concurrent_redeem_distinct_keys_all_succeed(self):
        # No false serialization: distinct keys must not trip each
        # other's burn.
        auth = _authority()
        n = 32
        keys = [auth.issue_key(spiffe_id=SPIFFE_A, now=NOW)
                for _ in range(n)]
        barrier = threading.Barrier(n)
        results = []
        rlock = threading.Lock()

        def worker(i):
            barrier.wait()
            try:
                auth.redeem(keys[i], SPIFFE_A, _PUBKEY, 5, now=NOW)
                r = "svid"
            except sv.SvidError as e:
                r = e.code
            with rlock:
                results.append(r)

        ths = [threading.Thread(target=worker, args=(i,))
               for i in range(n)]
        for th in ths:
            th.start()
        for th in ths:
            th.join(30)
        self.assertFalse(any(th.is_alive() for th in ths),
                         "a distinct-key redeem hung")
        self.assertEqual(results.count("svid"), n)
        self.assertEqual(auth.live_keys(), 0)

    def test_live_keys_survives_concurrent_issue(self):
        # Pre-fix, 2/2 readers crashed with RuntimeError in-lane.
        auth = _authority()
        for _ in range(20):
            auth.issue_key(now=NOW)
        stop = threading.Event()
        errors = []

        def reader():
            while not stop.is_set():
                try:
                    auth.live_keys()
                except Exception as e:  # noqa: BLE001 -- defect shape
                    errors.append(e)
                    return

        def writer():
            while not stop.is_set():
                auth.issue_key(now=NOW)

        ths = ([threading.Thread(target=reader) for _ in range(2)]
               + [threading.Thread(target=writer) for _ in range(2)])
        for th in ths:
            th.start()
        time.sleep(1)
        stop.set()
        for th in ths:
            th.join()
        self.assertEqual(errors, [])

    def test_lock_released_when_issuance_raises(self):
        # Issuer raises post-burn (unknown profile): the key stays
        # burned, the lock is released, later operations proceed.
        auth = _authority()
        key = auth.issue_key(spiffe_id=SPIFFE_A, now=NOW)
        with self.assertRaises(sv.SvidError):
            auth.redeem(key, SPIFFE_A, _PUBKEY, 5,
                        profile="no-such-profile", now=NOW)
        with self.assertRaises(sv.SvidError) as ctx:
            auth.redeem(key, SPIFFE_A, _PUBKEY, 5, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "svid-enrollment-key-replayed")
        key2 = auth.issue_key(spiffe_id=SPIFFE_A, now=NOW)
        auth.redeem(key2, SPIFFE_A, _PUBKEY, 5, now=NOW)  # must not hang


class CodeRegistrationTest(unittest.TestCase):
    def test_enrollment_codes_in_taxonomy(self):
        for code in (se.ENROLLMENT_KEY_UNKNOWN_CODE,
                     se.ENROLLMENT_KEY_REPLAYED_CODE,
                     se.ENROLLMENT_KEY_EXPIRED_CODE,
                     se.ENROLLMENT_SPIFFE_MISMATCH_CODE):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "svid")


if __name__ == "__main__":
    unittest.main()
