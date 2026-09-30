"""Unit tests for gov/absence.py and gov/revocation.py.

Signed absence-attribution (SEP-0000 ADAPT) + exact-target signed
revocation (EMILIA PIP-011 EP-REVOCATION-v1 ADAPT), re-derived prose,
no upstream text copied.

Tests live at the public seams: AbsenceIssuer.attest_absence,
verify_negative, evaluate_negative, RevocationList.revoke/check/
verify/export/import_entries, is_exact_digest, and the
PermitRegistry/PermitLease revocation wiring. Expected values are
independent literals, not recomputed by the modules under test.

$0 spend. stdlib only. No network.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import absence as ab  # noqa: E402
from gov import ed25519 as ed  # noqa: E402
from gov import permit_leases as pl  # noqa: E402
from gov import revocation as rv  # noqa: E402

_DIGEST_A = "aa" * 32
_DIGEST_B = "bb" * 32
_DIGEST_C = "cc" * 32


def _issuer(issuer_id="issuer-1"):
    seed = ed.generate_seed()
    return ab.AbsenceIssuer(issuer_id, seed)


class ExactDigestTests(unittest.TestCase):
    def test_full_lowercase_hex_is_exact(self):
        self.assertTrue(rv.is_exact_digest(_DIGEST_A))

    def test_sha256_scheme_is_exact(self):
        self.assertTrue(rv.is_exact_digest("sha256:" + _DIGEST_A))

    def test_hmac_scheme_is_exact(self):
        self.assertTrue(
            rv.is_exact_digest("hmac-sha256-v1:" + _DIGEST_A))

    def test_prefix_is_not_exact(self):
        self.assertFalse(rv.is_exact_digest(_DIGEST_A[:32]))

    def test_wildcard_is_not_exact(self):
        self.assertFalse(rv.is_exact_digest("*"))
        self.assertFalse(rv.is_exact_digest("tool:*"))

    def test_uppercase_is_not_exact(self):
        self.assertFalse(rv.is_exact_digest(_DIGEST_A.upper()))

    def test_empty_and_non_string_are_not_exact(self):
        self.assertFalse(rv.is_exact_digest(""))
        self.assertFalse(rv.is_exact_digest(None))
        self.assertFalse(rv.is_exact_digest(b"aa" * 32))


class RevocationListTests(unittest.TestCase):
    def test_revoke_and_check(self):
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        entry = rl.revoke(_DIGEST_A, issuer_id="r1", seed=seed)
        self.assertEqual(entry["target_digest"], _DIGEST_A)
        self.assertEqual(entry["issuer_id"], "r1")
        self.assertEqual(len(bytes.fromhex(entry["signature"])), 64)
        self.assertEqual(rl.check(_DIGEST_A), "revoked")
        self.assertEqual(rl.check(_DIGEST_B), "active")

    def test_inexact_targets_refused(self):
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        for target in ("ab12", _DIGEST_A[:32], "*", "tool:*",
                       "sha256:", _DIGEST_A.upper(), ""):
            with self.assertRaises(rv.RevocationInexactTargetError) as cm:
                rl.revoke(target, issuer_id="r1", seed=seed)
            self.assertEqual(cm.exception.code,
                             "revocation-inexact-target-refused")

    def test_idempotent_no_rewrite(self):
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        first = rl.revoke(_DIGEST_A, issuer_id="r1", seed=seed, now=1000.0)
        second = rl.revoke(_DIGEST_A, issuer_id="r1", seed=seed, now=2000.0)
        self.assertEqual(first["revoked_at"], second["revoked_at"])
        self.assertEqual(len(rl.export()), 1)

    def test_verify_against_pinned_keyset(self):
        seed = ed.generate_seed()
        pub = ed.publickey(seed)
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_A, issuer_id="r1", seed=seed)
        self.assertTrue(rl.verify({"r1": pub}))

    def test_export_import_round_trip(self):
        seed = ed.generate_seed()
        pub = ed.publickey(seed)
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_A, issuer_id="r1", seed=seed)
        rl2 = rv.RevocationList()
        rl2.import_entries(rl.export(), {"r1": pub})
        self.assertEqual(rl2.check(_DIGEST_A), "revoked")

    def test_import_with_wrong_keyset_refused(self):
        seed = ed.generate_seed()
        wrong_pub = ed.publickey(ed.generate_seed())
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_A, issuer_id="r1", seed=seed)
        rl2 = rv.RevocationList()
        with self.assertRaises(rv.RevocationEntryUnverifiableError) as cm:
            rl2.import_entries(rl.export(), {"r1": wrong_pub})
        self.assertEqual(cm.exception.code,
                         "revocation-entry-unverifiable")
        self.assertEqual(rl2.check(_DIGEST_A), "active")

    def test_import_tampered_entry_refused(self):
        seed = ed.generate_seed()
        pub = ed.publickey(seed)
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_A, issuer_id="r1", seed=seed)
        exported = rl.export()
        exported[0]["target_digest"] = _DIGEST_B  # tamper after signing
        rl2 = rv.RevocationList()
        with self.assertRaises(rv.RevocationEntryUnverifiableError):
            rl2.import_entries(exported, {"r1": pub})
        self.assertEqual(rl2.check(_DIGEST_B), "active")


class AbsenceTests(unittest.TestCase):
    def test_never_advertised_claim(self):
        issuer = _issuer()
        neg = issuer.attest_absence(_DIGEST_A)
        self.assertEqual(neg["claim"], "never-advertised")
        self.assertIsNone(neg["revocation_target"])
        self.assertEqual(neg["issuer_id"], "issuer-1")

    def test_advertised_but_missing_claim(self):
        issuer = _issuer()
        issuer.advertise(_DIGEST_B)
        neg = issuer.attest_absence(_DIGEST_B)
        self.assertEqual(neg["claim"], "advertised-but-missing")

    def test_revoked_claim_pins_exact_target(self):
        issuer = _issuer()
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_C, issuer_id="r1", seed=seed)
        neg = issuer.attest_absence(_DIGEST_C, revocation=rl)
        self.assertEqual(neg["claim"], "revoked")
        self.assertEqual(neg["revocation_target"], _DIGEST_C)

    def test_revoked_beats_advertised(self):
        # A revoked subject is claimed revoked even if advertised.
        issuer = _issuer()
        issuer.advertise(_DIGEST_C)
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_C, issuer_id="r1", seed=seed)
        neg = issuer.attest_absence(_DIGEST_C, revocation=rl)
        self.assertEqual(neg["claim"], "revoked")

    def test_evaluate_distinguishes_codes(self):
        issuer = _issuer()
        pub = ed.publickey(issuer.seed)
        neg = issuer.attest_absence(_DIGEST_A)
        issuer.advertise(_DIGEST_B)
        missing = issuer.attest_absence(_DIGEST_B)
        with self.assertRaises(ab.AbsenceNeverAdvertisedError) as cm:
            ab.evaluate_negative(neg, pub)
        self.assertEqual(cm.exception.code, "absence-never-advertised")
        with self.assertRaises(ab.AbsenceAdvertisedButMissingError) as cm:
            ab.evaluate_negative(missing, pub)
        self.assertEqual(cm.exception.code,
                         "absence-advertised-but-missing")

    def test_unsigned_negative_refused(self):
        issuer = _issuer()
        pub = ed.publickey(issuer.seed)
        neg = issuer.attest_absence(_DIGEST_A)
        bad = dict(neg)
        bad["signature"] = "00" * 64
        with self.assertRaises(ab.AbsenceUnverifiableError) as cm:
            ab.evaluate_negative(bad, pub)
        self.assertEqual(cm.exception.code, "absence-unverifiable")

    def test_forged_issuer_refused(self):
        issuer = _issuer()
        forged = _issuer("issuer-1").attest_absence(_DIGEST_A)
        pub = ed.publickey(issuer.seed)
        with self.assertRaises(ab.AbsenceUnverifiableError):
            ab.evaluate_negative(forged, pub)

    def test_tampered_claim_refused(self):
        issuer = _issuer()
        pub = ed.publickey(issuer.seed)
        neg = issuer.attest_absence(_DIGEST_A)
        tampered = dict(neg)
        tampered["claim"] = "advertised-but-missing"
        with self.assertRaises(ab.AbsenceUnverifiableError):
            ab.evaluate_negative(tampered, pub)

    def test_negative_is_never_permission(self):
        # Every evaluate_negative path raises — the record authorizes
        # nothing, it only classifies the absence.
        issuer = _issuer()
        pub = ed.publickey(issuer.seed)
        neg = issuer.attest_absence(_DIGEST_A)
        with self.assertRaises(ab.AbsenceError):
            ab.evaluate_negative(neg, pub)


class PermitRevocationWiringTests(unittest.TestCase):
    def test_revoked_lease_refuses_permit_revoked(self):
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        registry = pl.PermitRegistry(revocation_registry=rl)
        digest = "sha256:" + _DIGEST_A
        lease = registry.issue("p1", params_digest=digest,
                               grant_scope={"action": {"read"}})
        rl.revoke(digest, issuer_id="r1", seed=seed)
        with self.assertRaises(pl.PermitRevokedError) as cm:
            registry.redeem("p1", digest)
        self.assertEqual(cm.exception.code, "permit-revoked")
        self.assertFalse(lease.used)

    def test_non_revoked_lease_redeems(self):
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        rl.revoke("sha256:" + _DIGEST_C, issuer_id="r1", seed=seed)
        registry = pl.PermitRegistry(revocation_registry=rl)
        digest = "sha256:" + _DIGEST_A
        registry.issue("p2", params_digest=digest,
                       grant_scope={"action": {"read"}})
        grant = registry.redeem("p2", digest)
        self.assertEqual(grant["permit_id"], "p2")

    def test_no_registry_legacy_identical(self):
        registry = pl.PermitRegistry()
        digest = "sha256:" + _DIGEST_A
        registry.issue("p3", params_digest=digest,
                       grant_scope={"action": {"read"}})
        grant = registry.redeem("p3", digest)
        self.assertEqual(set(grant),
                         {"permit_id", "parameter_digest", "granted_at"})

    def test_revoked_but_used_reports_reused_first(self):
        # Check order: used precedes revocation — a consumed permit
        # never confirms or denies anything else.
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        registry = pl.PermitRegistry(revocation_registry=rl)
        digest = "sha256:" + _DIGEST_A
        registry.issue("p4", params_digest=digest,
                       grant_scope={"action": {"read"}})
        registry.redeem("p4", digest)
        rl.revoke(digest, issuer_id="r1", seed=seed)
        with self.assertRaises(pl.PermitReusedError) as cm:
            registry.redeem("p4", digest)
        self.assertEqual(cm.exception.code, "permit-reused")

    def test_revoked_but_wrong_digest_reports_mismatch(self):
        # Check order: digest precedes revocation — no revocation
        # oracle for a wrong digest.
        seed = ed.generate_seed()
        rl = rv.RevocationList()
        registry = pl.PermitRegistry(revocation_registry=rl)
        digest = "sha256:" + _DIGEST_A
        registry.issue("p5", params_digest=digest,
                       grant_scope={"action": {"read"}})
        rl.revoke(digest, issuer_id="r1", seed=seed)
        with self.assertRaises(pl.PermitDigestMismatchError) as cm:
            registry.redeem("p5", "sha256:" + _DIGEST_B)
        self.assertEqual(cm.exception.code, "permit-digest-mismatch")


if __name__ == "__main__":
    unittest.main()
