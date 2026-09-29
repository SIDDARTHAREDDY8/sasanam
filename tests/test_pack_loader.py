"""Unit tests for the OPA-style pack activation layer (wave-200).

Covers: activation of a well-formed pack, exact member enumeration
(extra member refused, omitted member refused, digest mismatch
refused), signature failures (unsigned, wrong keyset purpose,
threshold unmet), expiry, monotonic rollback floor, failure
telemetry (prior pack preserved), the activation guard
(allow/require_approval/deny), and the PERM trust-domain
parametrization (a rule pack never verifies as a PERM pack and vice
versa).

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import pack_loader as pl  # noqa: E402
from gov import rule_pack as rp  # noqa: E402
from gov.keyset import (  # noqa: E402
    new_keyset,
    keyset_signer_for_version,
)

_SEED1 = bytes.fromhex("41" * 32)
_SEED2 = bytes.fromhex("42" * 32)
_SEED3 = bytes.fromhex("43" * 32)

ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"

MEMBERS = {
    "rules/a.yml": b"rules:\n  - {name: a}\n",
    "rules/b.yml": b"rules:\n  - {name: b}\n",
}


def _digests(members):
    return {mid: "sha256:" + hashlib.sha256(data).hexdigest()
            for mid, data in members.items()}


class PackLoaderTest(unittest.TestCase):
    def setUp(self):
        self.keyset, _ = new_keyset(
            _SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        self.signers = [keyset_signer_for_version(self.keyset, 1,
                                                  _SEED1)]
        self.loader = pl.PackLoader(self.keyset, "test-pack")

    def _mint(self, members=MEMBERS, version=1, threshold=1,
              signers=None, **kw):
        kw.setdefault("issued_at", ISSUED)
        kw.setdefault("expires_at", EXPIRES)
        kw.setdefault("threshold", threshold)
        return rp.mint_rule_pack(
            self.keyset, signers or self.signers,
            rules=_digests(members), pack_version=version, **kw)

    def test_activate_ok(self):
        active = self.loader.present(
            self._mint(), dict(MEMBERS), now=NOW)
        self.assertEqual(active.pack_id, "test-pack")
        self.assertEqual(active.version, 1)
        self.assertEqual(active.member("rules/a.yml"),
                         MEMBERS["rules/a.yml"])
        self.assertIs(self.loader.current, active)

    def test_extra_member_refused(self):
        files = dict(MEMBERS)
        files["rules/evil.yml"] = b"evil: true\n"
        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(self._mint(), files, now=NOW)
        self.assertEqual(ctx.exception.code, "pack-member-extra")
        self.assertIsNone(self.loader.current)

    def test_omitted_member_refused(self):
        files = {"rules/a.yml": MEMBERS["rules/a.yml"]}
        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(self._mint(), files, now=NOW)
        self.assertEqual(ctx.exception.code, "pack-member-omitted")

    def test_digest_mismatch_refused(self):
        files = dict(MEMBERS)
        files["rules/a.yml"] = b"tampered: true\n"
        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(self._mint(), files, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "pack-member-digest-mismatch")

    def test_unsigned_pack_refused(self):
        doc = self._mint()
        doc["signatures"] = []
        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(doc, dict(MEMBERS), now=NOW)
        self.assertTrue(ctx.exception.code.startswith("pack-"))

    def test_threshold_unmet_refused(self):
        # 2-of-2 ceremony (same pattern as the corpus manifest
        # tests): rotate two keys in, mint threshold=2, then break
        # one member signature -> 1 valid < 2 required.
        from gov.keyset import rotate_keyset  # noqa: E402
        from gov.signing import Ed25519Signer  # noqa: E402
        ks, _ = new_keyset(_SEED1,
                           purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        ks, _ = rotate_keyset(ks, _SEED2, _SEED1)
        signers = [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]
        doc = rp.mint_rule_pack(
            ks, signers, rules=_digests(MEMBERS), pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
        doc["signatures"][1]["sig"] = "00" * 64
        with self.assertRaises(pl.PackActivationError) as ctx:
            pl.PackLoader(ks, "t").present(
                doc, dict(MEMBERS), now=NOW)
        self.assertEqual(ctx.exception.code, "pack-threshold-unmet")

    def test_expired_pack_refused(self):
        doc = self._mint(expires_at="2026-09-15T00:00:00+00:00")
        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(doc, dict(MEMBERS), now=NOW)
        self.assertEqual(ctx.exception.code, "pack-pack-expired")

    def test_rollback_refused(self):
        self.loader.present(self._mint(version=3), dict(MEMBERS),
                            now=NOW)
        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(self._mint(version=2),
                                dict(MEMBERS), now=NOW)
        self.assertEqual(ctx.exception.code, "pack-stale")
        # The previously activated pack stays active.
        self.assertEqual(self.loader.current.version, 3)

    def test_failed_candidate_preserves_prior(self):
        good = self.loader.present(self._mint(version=1),
                                   dict(MEMBERS), now=NOW)
        files = dict(MEMBERS)
        files["rules/a.yml"] = b"tampered\n"
        with self.assertRaises(pl.PackActivationError):
            self.loader.present(self._mint(version=2), files,
                                now=NOW)
        self.assertIs(self.loader.current, good)
        failures = self.loader.activation_failures
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["code"],
                         "pack-member-digest-mismatch")

    def test_guard_allow(self):
        seen = {}

        def guard(snapshot):
            seen.update(snapshot)
            return "allow", "ok"

        active = self.loader.present(self._mint(), dict(MEMBERS),
                                     guard=guard, now=NOW)
        self.assertEqual(active.version, 1)
        self.assertEqual(seen["pack_id"], "test-pack")
        self.assertEqual(seen["pack_version"], 1)
        self.assertEqual(seen["threshold"], 1)

    def test_guard_require_approval_refused(self):
        def guard(snapshot):
            return "require_approval", "needs human"

        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(self._mint(), dict(MEMBERS),
                                guard=guard, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "pack-activation-approval-required")
        self.assertIsNone(self.loader.current)

    def test_guard_deny_refused(self):
        def guard(snapshot):
            return "deny", "nope"

        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(self._mint(), dict(MEMBERS),
                                guard=guard, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "pack-activation-denied")

    def test_guard_exception_fails_closed(self):
        def guard(snapshot):
            raise RuntimeError("boom")

        with self.assertRaises(pl.PackActivationError) as ctx:
            self.loader.present(self._mint(), dict(MEMBERS),
                                guard=guard, now=NOW)
        self.assertEqual(ctx.exception.code, "pack-guard-error")

    def test_wrong_keyset_purpose_refused(self):
        other, _ = new_keyset(_SEED2,
                              purpose="sasanam-test-other/v1")
        with self.assertRaises(pl.PackActivationError) as ctx:
            pl.PackLoader(other, "x")
        self.assertEqual(ctx.exception.code, "wrong-keyset-purpose")

    def test_reboot_loses_version_floor(self):
        # Honest residual: a fresh loader has no version memory.
        # Documented as bounded by pack expiry, not hidden.
        self.loader.present(self._mint(version=5), dict(MEMBERS),
                            now=NOW)
        fresh = pl.PackLoader(self.keyset, "test-pack")
        active = fresh.present(self._mint(version=1),
                               dict(MEMBERS), now=NOW)
        self.assertEqual(active.version, 1)


class PermTrustDomainTest(unittest.TestCase):
    """The PERM trust domain never cross-verifies with rule packs."""

    def setUp(self):
        self.rule_ks, _ = new_keyset(
            _SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        self.perm_ks, _ = new_keyset(
            _SEED2, purpose=rp.KEYSET_PURPOSE_PERM_PACK)

    def _mint_perm(self, keyset, signers, version=1):
        members = {"perm-model.yml": b"model: 1\n",
                   "perm-policy.yml": b"policy: 1\n"}
        return rp.mint_rule_pack(
            keyset, signers,
            rules=_digests(members), pack_version=version,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1,
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT), members

    def test_perm_pack_round_trip(self):
        signers = [keyset_signer_for_version(self.perm_ks, 1,
                                             _SEED2)]
        doc, _members = self._mint_perm(self.perm_ks, signers)
        pack = rp.verify_rule_pack(
            doc, self.perm_ks, now=NOW,
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        self.assertEqual(pack.version, 1)

    def test_perm_pack_rejected_as_rule_pack(self):
        signers = [keyset_signer_for_version(self.perm_ks, 1,
                                             _SEED2)]
        doc, _members = self._mint_perm(self.perm_ks, signers)
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack(doc, self.perm_ks, now=NOW)
        self.assertEqual(ctx.exception.code, "bad-format")

    def test_rule_pack_rejected_as_perm_pack(self):
        signers = [keyset_signer_for_version(self.rule_ks, 1,
                                             _SEED1)]
        doc = rp.mint_rule_pack(
            self.rule_ks, signers, rules=_digests(MEMBERS),
            pack_version=1, issued_at=ISSUED, expires_at=EXPIRES,
            threshold=1)
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack(
                doc, self.rule_ks, now=NOW,
                purpose=rp.KEYSET_PURPOSE_PERM_PACK,
                format_tag=rp.PERM_PACK_FORMAT)
        self.assertEqual(ctx.exception.code, "bad-format")

    def test_rule_keyset_cannot_mint_perm_pack(self):
        signers = [keyset_signer_for_version(self.rule_ks, 1,
                                             _SEED1)]
        with self.assertRaises(rp.RulePackError) as ctx:
            self._mint_perm(self.rule_ks, signers)
        self.assertEqual(ctx.exception.code, "wrong-purpose")

    def test_perm_loader_activation(self):
        signers = [keyset_signer_for_version(self.perm_ks, 1,
                                             _SEED2)]
        doc, members = self._mint_perm(self.perm_ks, signers)
        loader = pl.PackLoader(
            self.perm_ks, "perm", purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        active = loader.present(doc, dict(members), now=NOW)
        self.assertEqual(active.version, 1)
        self.assertEqual(sorted(active.member_ids()),
                         ["perm-model.yml", "perm-policy.yml"])

    def test_perm_loader_rejects_rule_keyset(self):
        with self.assertRaises(pl.PackActivationError):
            pl.PackLoader(self.rule_ks, "perm",
                          purpose=rp.KEYSET_PURPOSE_PERM_PACK,
                          format_tag=rp.PERM_PACK_FORMAT)


if __name__ == "__main__":
    unittest.main()
