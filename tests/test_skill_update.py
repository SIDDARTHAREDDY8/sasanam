"""Unit tests for gov/skill_update.py (W248-4).

Install-time admission gate for skill bundles: digest match, chain-pin
match, record expiry, version monotonicity vs installed state, and
fail-closed refusal when the metadata chain cannot vouch.

Pin: taxonomy 944 (938 + 6 skill-update codes), additive only; the
merge coordinator recomposes.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import skill_update as su


NOW = 1780000000
FUTURE = NOW + 86400
PAST = NOW - 86400


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _record(name="demo-skill", version=1, digest=None,
            expires=FUTURE):
    return {"name": name, "version": version,
            "digest": digest or _digest(b"x"),
            "expires": expires}


def _pin(digest, chain_state="trusted"):
    return {"digest": digest, "chain_state": chain_state}


class TaxonomyPinTests(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Wave-248 lane 4: re-pointed to 944 (938 + 6 skill-update
        # codes: digest-mismatch, index-untrusted, malformed,
        # metadata-expired, record-unpinned, version-rollback),
        # additive only; merge coordinator recomposes.
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes), additive only.
        # Wave-250 lane 1 (F211 closure): re-pointed to 980 (979 +
        # 1 skill-update code: digest-changed), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2058)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.

    def test_expected_codes_pinned(self):
        self.assertEqual(
            set(su.EXPECTED_CODES),
            {"skill-update-index-untrusted",
             "skill-update-metadata-expired",
             "skill-update-record-unpinned",
             "skill-update-digest-mismatch",
             "skill-update-version-rollback",
             "skill-update-digest-changed",
             "skill-update-malformed"})


class InstallGateTests(unittest.TestCase):
    def test_happy_path_installs(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        receipt = client.install(bundle, _record(digest=digest),
                                 _pin(digest), NOW)
        self.assertEqual(receipt,
                         {"name": "demo-skill", "version": 1,
                          "digest": digest})
        self.assertEqual(client.installed_version("demo-skill"), 1)

    def test_upgrade_advances_installed(self):
        # Wave-250 lane 1 (F211 closure): the installed map is now
        # {name: (version, digest)}; the digest is tracked so a
        # same-version reinstall must be identical bytes.
        client = su.SkillUpdateClient(
            installed={"demo-skill": (2, _digest(b"skill-bytes-v2"))})
        bundle = b"skill-bytes-v3"
        digest = _digest(bundle)
        receipt = client.install(
            bundle, _record(version=3, digest=digest),
            _pin(digest), NOW)
        self.assertEqual(receipt["version"], 3)
        self.assertEqual(client.installed_version("demo-skill"), 3)

    def test_reinstall_same_version_idempotent(self):
        bundle = b"skill-bytes-v2"
        digest = _digest(bundle)
        client = su.SkillUpdateClient(
            installed={"demo-skill": (2, digest)})
        receipt = client.install(
            bundle, _record(version=2, digest=digest),
            _pin(digest), NOW)
        self.assertEqual(receipt["version"], 2)
        self.assertEqual(client.installed_digest("demo-skill"),
                         digest)

    def test_same_version_digest_change_refused(self):
        # F211 break shape (wave-250 lane 1): same version, different
        # digest -- bytes swapped under a pinned version -- must be
        # refused, not silently installed.
        digest_a = _digest(b"legitimate skill v1")
        bundle_b = b"malicious skill v1 - different bytes"
        digest_b = _digest(bundle_b)
        client = su.SkillUpdateClient(
            installed={"demo-skill": (1, digest_a)})
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle_b,
                           _record(version=1, digest=digest_b),
                           _pin(digest_b), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-digest-changed")
        # Installed state untouched by the refusal.
        self.assertEqual(client.installed_version("demo-skill"), 1)
        self.assertEqual(client.installed_digest("demo-skill"),
                         digest_a)

    def test_version_rollback_refused(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient(
            installed={"demo-skill": (2, _digest(b"skill-bytes-v2"))})
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle, _record(version=1, digest=digest),
                           _pin(digest), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-version-rollback")
        # Installed state untouched by the refusal.
        self.assertEqual(client.installed_version("demo-skill"), 2)

    def test_digest_mismatch_refused(self):
        digest = _digest(b"good-bytes")
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(b"tampered-bytes",
                           _record(digest=digest),
                           _pin(digest), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-digest-mismatch")

    def test_record_unpinned_refused(self):
        # Bundle matches its record, but the record is not what the
        # chain pinned: mix-and-match across versions.
        bundle = b"bytes-v2"
        record_digest = _digest(bundle)
        pinned = _digest(b"pinned-bytes-v2")
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle,
                           _record(version=2, digest=record_digest),
                           _pin(pinned), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-record-unpinned")

    def test_metadata_expired_refused(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle,
                           _record(digest=digest, expires=PAST),
                           _pin(digest), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-metadata-expired")

    def test_expiry_boundary_exclusive(self):
        # now == expires is expired (expiry is exclusive).
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle,
                           _record(digest=digest, expires=NOW),
                           _pin(digest), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-metadata-expired")
        # One second before expiry installs fine.
        client2 = su.SkillUpdateClient()
        receipt = client2.install(
            bundle, _record(digest=digest, expires=NOW),
            _pin(digest), NOW - 1)
        self.assertEqual(receipt["version"], 1)

    def test_stale_chain_refused(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle, _record(digest=digest),
                           _pin(digest, "stale"), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-index-untrusted")

    def test_suspended_chain_refused(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle, _record(digest=digest),
                           _pin(digest, "suspended"), NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-index-untrusted")

    def test_unbound_skill_refused_as_plant(self):
        # No pin from the verified chain: the skill arrived outside
        # the metadata chain and is refused at install.
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle, _record(digest=digest), None,
                           NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-index-untrusted")

    def test_malformed_pin_refused(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            client.install(bundle, _record(digest=digest),
                           {"digest": digest}, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-index-untrusted")


class MalformedInputTests(unittest.TestCase):
    def _client(self):
        return su.SkillUpdateClient()

    def _good(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        return bundle, _record(digest=digest), _pin(digest)

    def test_record_not_dict(self):
        bundle, _, pin = self._good()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, "not-a-dict", pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_record_missing_key(self):
        bundle, record, pin = self._good()
        del record["digest"]
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_record_unknown_key(self):
        bundle, record, pin = self._good()
        record["extra"] = "nope"
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_record_bad_digest_format(self):
        bundle, record, pin = self._good()
        record["digest"] = "ZZZ"
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_record_negative_version(self):
        bundle, record, pin = self._good()
        record["version"] = -1
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_record_bool_version(self):
        bundle, record, pin = self._good()
        record["version"] = True
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_record_empty_name(self):
        bundle, record, pin = self._good()
        record["name"] = ""
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_bundle_not_bytes(self):
        _, record, pin = self._good()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install("not-bytes", record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_bundle_empty(self):
        _, record, pin = self._good()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(b"", record, pin, NOW)
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_now_not_int(self):
        bundle, record, pin = self._good()
        with self.assertRaises(su.SkillUpdateError) as ctx:
            self._client().install(bundle, record, pin, "now")
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_installed_map_validated(self):
        # Wave-250 lane 1 (F211 closure): the installed map is
        # {name: (version, digest)}; the legacy bare-int form is
        # refused as malformed.
        with self.assertRaises(su.SkillUpdateError) as ctx:
            su.SkillUpdateClient(
                installed={"demo-skill": (-1, _digest(b"x"))})
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")
        with self.assertRaises(su.SkillUpdateError) as ctx:
            su.SkillUpdateClient(installed={"demo-skill": 1})
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")
        with self.assertRaises(su.SkillUpdateError) as ctx:
            su.SkillUpdateClient(
                installed={"demo-skill": (1, "not-a-digest")})
        self.assertEqual(ctx.exception.code,
                         "skill-update-malformed")

    def test_error_carries_code_and_detail(self):
        bundle = b"x"
        client = su.SkillUpdateClient()
        try:
            client.install(bundle, {}, None, NOW)
        except su.SkillUpdateError as exc:
            self.assertIn(exc.code, su.EXPECTED_CODES)
            self.assertTrue(exc.detail)
            self.assertIn(exc.code, str(exc))
        else:
            self.fail("expected SkillUpdateError")


class InstalledStateTests(unittest.TestCase):
    def test_unknown_skill_has_no_version(self):
        self.assertIsNone(
            su.SkillUpdateClient().installed_version("nope"))
        self.assertIsNone(
            su.SkillUpdateClient().installed_digest("nope"))

    def test_failed_install_does_not_advance(self):
        bundle = b"skill-bytes-v1"
        digest = _digest(bundle)
        client = su.SkillUpdateClient()
        try:
            client.install(b"wrong", _record(digest=digest),
                           _pin(digest), NOW)
        except su.SkillUpdateError:
            pass
        self.assertIsNone(client.installed_version("demo-skill"))

    def test_multiple_skills_independent(self):
        b1, b2 = b"skill-one", b"skill-two"
        d1, d2 = _digest(b1), _digest(b2)
        # Wave-250 lane 1 (F211 closure): installed map entries are
        # (version, digest) pairs.
        client = su.SkillUpdateClient(installed={"one": (5, d1)})
        client.install(b1, _record(name="one", version=6,
                                   digest=d1), _pin(d1), NOW)
        client.install(b2, _record(name="two", version=1,
                                   digest=d2), _pin(d2), NOW)
        self.assertEqual(client.installed_version("one"), 6)
        self.assertEqual(client.installed_version("two"), 1)


if __name__ == "__main__":
    unittest.main()
