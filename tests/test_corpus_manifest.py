"""Unit tests for the wave-194 TUF follow-on #2 steal: signed corpus
manifest (gov/corpus_manifest.py), the load-gate corpus wiring
(gov/load_gate.CorpusManifestTracker + SkillLoader corpus check), and
the per-skill capability-manifest threshold
(gov/capability_manifests.verify_manifest threshold=).

Hermetic: synthetic deterministic fixtures, no network. Expiries are
anchored far from now (2030 / 2020) except where the test is about
expiry itself.
"""

import copy
import hashlib
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import corpus_manifest as cm  # noqa: E402
from gov import load_gate as lg  # noqa: E402
from gov import capability_manifests as capm  # noqa: E402
from gov import ed25519 as ed  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.keyset import (  # noqa: E402
    new_keyset,
    rotate_keyset,
    revoke_version,
    keyset_signer_for_version,
    KeysetError,
)
from gov.signing import Ed25519Signer  # noqa: E402

_SEED1 = bytes.fromhex("11" * 32)
_SEED2 = bytes.fromhex("22" * 32)
_SEED3 = bytes.fromhex("33" * 32)
_TS = "2026-09-29T00:00:00+00:00"
_ISSUED = "2026-09-01T00:00:00+00:00"
_FUTURE = "2030-01-01T00:00:00+00:00"
_PAST = "2020-01-01T00:00:00+00:00"
_OLD_ISSUED = "2019-01-01T00:00:00+00:00"


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _keyset_world(nsigners=1):
    seeds = [_SEED1, _SEED2, _SEED3][:nsigners]
    keyset, _ = new_keyset(seeds[0],
                           purpose=cm.KEYSET_PURPOSE_CORPUS_MANIFEST)
    signers = [keyset_signer_for_version(keyset, 1, s) for s in seeds]
    return keyset, signers


def _mint(keyset, signers, artifacts, version=1, threshold=1,
          expires_at=_FUTURE):
    return cm.mint_corpus_manifest(
        keyset, signers, artifacts=artifacts, corpus_version=version,
        issued_at=_ISSUED, expires_at=expires_at, threshold=threshold)


def _pin_world():
    h1, h2 = Ed25519Signer(_SEED1), Ed25519Signer(_SEED2)
    ax = Ed25519Signer(_SEED3)
    trust = DelegationTrust(
        human_keys={h1.key_id: h1.public_key, h2.key_id: h2.public_key},
        authority_keys={ax.key_id: ax.public_key},
        user_issuer_keys={ax.key_id: ax.public_key})
    pinset = lg.ArtifactPinset(trust)
    return pinset, h1


def _pin(pinset, h1, artifact_id, digest, tier="dev"):
    body = lg._canonical_pin_body(tier, artifact_id, digest, _TS)
    return pinset.pin(artifact_id, digest, h1.key_id,
                      h1.sign(body).hex(), ts=_TS, tier=tier)


class TestCorpusManifestMintVerify(unittest.TestCase):
    def test_round_trip(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {"skill:a": _digest(b"a")})
        m = cm.verify_corpus_manifest(doc, keyset)
        self.assertEqual(m.version, 1)
        self.assertEqual(m.threshold, 1)
        self.assertEqual(m.digest_for("skill:a"), _digest(b"a"))
        self.assertIsNone(m.digest_for("skill:nope"))
        self.assertEqual(len(m.signing_kids), 1)

    def test_canonical_is_deterministic(self):
        keyset, signers = _keyset_world()
        a1 = {"skill:a": _digest(b"a"), "skill:b": _digest(b"b")}
        a2 = {"skill:b": _digest(b"b"), "skill:a": _digest(b"a")}
        d1 = _mint(keyset, signers, a1)
        d2 = _mint(keyset, signers, a2)
        # Same corpus content -> same canonical bytes -> same signature.
        self.assertEqual(cm.canonical_corpus_json(d1),
                         cm.canonical_corpus_json(d2))
        self.assertEqual(d1["signatures"], d2["signatures"])

    def test_rejects_non_digest_artifact_value(self):
        keyset, signers = _keyset_world()
        with self.assertRaises(cm.CorpusManifestError) as c:
            _mint(keyset, signers, {"skill:a": "latest"})
        self.assertEqual(c.exception.code, "bad-artifacts")

    def test_rejects_threshold_above_signers(self):
        keyset, signers = _keyset_world()
        with self.assertRaises(cm.CorpusManifestError) as c:
            _mint(keyset, signers, {}, threshold=2)
        self.assertEqual(c.exception.code, "bad-threshold")

    def test_rejects_expiry_before_issue(self):
        keyset, signers = _keyset_world()
        with self.assertRaises(cm.CorpusManifestError) as c:
            _mint(keyset, signers, {}, expires_at="2020-01-01T00:00:00+00:00")
        self.assertEqual(c.exception.code, "bad-expiry")

    def test_tampered_doc_fails_signature(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {"skill:a": _digest(b"a")})
        forged = copy.deepcopy(doc)
        forged["artifacts"]["skill:a"] = _digest(b"evil")
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(forged, keyset)
        self.assertEqual(c.exception.code, "bad-signature")

    def test_tampered_version_fails_signature(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {"skill:a": _digest(b"a")}, version=2)
        forged = copy.deepcopy(doc)
        forged["corpus_version"] = 1  # downgrade attack on the doc
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(forged, keyset)
        self.assertEqual(c.exception.code, "bad-signature")

    def test_unknown_fields_refused(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {})
        doc["sneaky"] = 1
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(doc, keyset)
        self.assertEqual(c.exception.code, "bad-format")

    def test_wrong_format_refused(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {})
        doc["format"] = "something-else/v9"
        with self.assertRaises(cm.CorpusManifestError):
            cm.verify_corpus_manifest(doc, keyset)

    def test_expired_refused(self):
        keyset, signers = _keyset_world()
        doc = cm.mint_corpus_manifest(
            keyset, signers, artifacts={}, corpus_version=1,
            issued_at=_OLD_ISSUED, expires_at=_PAST, threshold=1)
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(doc, keyset)
        self.assertEqual(c.exception.code, "corpus-expired")

    def test_rotation_keeps_old_manifest_verifying(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {"skill:a": _digest(b"a")})
        ks2, _ = rotate_keyset(keyset, _SEED2, _SEED1)
        m = cm.verify_corpus_manifest(doc, ks2)
        self.assertEqual(m.version, 1)

    def test_verify_only_version_cannot_mint(self):
        keyset, _ = _keyset_world()
        ks2, _ = rotate_keyset(keyset, _SEED2, _SEED1)
        with self.assertRaises(KeysetError):
            keyset_signer_for_version(ks2, 1, _SEED1)

    def test_revoked_member_stops_counting(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {"skill:a": _digest(b"a")})
        ks2, _ = rotate_keyset(keyset, _SEED2, _SEED1)
        ks_rev = revoke_version(ks2, 1, "compromised", _SEED2)
        # The revoked member's signature stops counting: zero valid
        # members -> bad-signature (nothing verifies), not merely
        # unmet threshold.
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(doc, ks_rev)
        self.assertEqual(c.exception.code, "bad-signature")

    def test_duplicate_kid_counts_once(self):
        keyset, signers = _keyset_world()
        doc = _mint(keyset, signers, {"skill:a": _digest(b"a")})
        dup = copy.deepcopy(doc)
        dup["signatures"] = doc["signatures"] + doc["signatures"]
        dup["threshold"] = 2
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(dup, keyset)
        self.assertEqual(c.exception.code, "threshold-unmet")

    def _two_of_two_keyset(self):
        # Deployment ceremony for 2-of-2: rotate two human keys in as
        # keyset versions, then mint with their plain signers (the
        # keyset model has exactly one active primary, so human
        # attestations ride plain Signers verified via the legacy
        # key-id lookup against their pinned versions).
        keyset, _ = new_keyset(_SEED1,
                               purpose=cm.KEYSET_PURPOSE_CORPUS_MANIFEST)
        ks2, _ = rotate_keyset(keyset, _SEED2, _SEED1)
        ks3, _ = rotate_keyset(ks2, _SEED3, _SEED2)
        return ks3, [Ed25519Signer(_SEED2), Ed25519Signer(_SEED3)]

    def test_two_signer_threshold_two(self):
        ks3, signers = self._two_of_two_keyset()
        doc = _mint(ks3, signers, {"skill:a": _digest(b"a")},
                    threshold=2)
        m = cm.verify_corpus_manifest(doc, ks3)
        self.assertEqual(len(m.signing_kids), 2)
        # One member's signature corrupted -> threshold unmet (the
        # envelope still carries 2 entries, so this is unmet, not
        # malformed).
        short = copy.deepcopy(doc)
        short["signatures"][1]["sig"] = "00" * 64
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(short, ks3)
        self.assertEqual(c.exception.code, "threshold-unmet")

    def test_duplicate_kid_counts_once(self):
        ks3, signers = self._two_of_two_keyset()
        doc = _mint(ks3, signers, {"skill:a": _digest(b"a")},
                    threshold=2)
        dup = copy.deepcopy(doc)
        # Same kid twice: both entries verify (signatures cover the
        # common body, not the envelope) but count as ONE attestation.
        dup["signatures"][1] = copy.deepcopy(doc["signatures"][0])
        with self.assertRaises(cm.CorpusManifestError) as c:
            cm.verify_corpus_manifest(dup, ks3)
        self.assertEqual(c.exception.code, "threshold-unmet")


class TestCorpusTracker(unittest.TestCase):
    def setUp(self):
        self.keyset, self.signers = _keyset_world()

    def _tracker(self):
        return lg.CorpusManifestTracker(self.keyset)

    def test_present_adopts_and_remembers_version(self):
        t = self._tracker()
        doc = _mint(self.keyset, self.signers, {"skill:a": _digest(b"a")},
                    version=3)
        m = t.present(doc)
        self.assertEqual(m.version, 3)
        self.assertEqual(t.highest_version, 3)
        self.assertIs(t.manifest, m)

    def test_older_version_refused(self):
        t = self._tracker()
        t.present(_mint(self.keyset, self.signers, {}, version=2))
        with self.assertRaises(lg.ArtifactRefused) as c:
            t.present(_mint(self.keyset, self.signers, {}, version=1))
        self.assertIn("corpus_manifest_stale", str(c.exception))

    def test_same_version_represent_ok(self):
        t = self._tracker()
        d1 = _mint(self.keyset, self.signers, {"skill:a": _digest(b"a")},
                   version=1)
        t.present(d1)
        # Re-presenting the same version is fine (idempotent boot).
        t.present(d1)
        self.assertEqual(t.highest_version, 1)

    def test_forged_doc_maps_to_artifact_refused(self):
        t = self._tracker()
        doc = _mint(self.keyset, self.signers, {"skill:a": _digest(b"a")})
        forged = copy.deepcopy(doc)
        forged["artifacts"]["skill:a"] = _digest(b"evil")
        with self.assertRaises(lg.ArtifactRefused) as c:
            t.present(forged)
        self.assertIn("corpus_manifest_bad_signature", str(c.exception))

    def test_expired_doc_maps_to_artifact_refused(self):
        t = self._tracker()
        doc = cm.mint_corpus_manifest(
            self.keyset, self.signers, artifacts={}, corpus_version=1,
            issued_at=_OLD_ISSUED, expires_at=_PAST, threshold=1)
        with self.assertRaises(lg.ArtifactRefused) as c:
            t.present(doc)
        self.assertIn("corpus_manifest_corpus_expired", str(c.exception))

    def test_digest_for_unpresented(self):
        t = self._tracker()
        with self.assertRaises(lg.ArtifactRefused) as c:
            t.digest_for("skill:a")
        self.assertIn("corpus_manifest_unpresented", str(c.exception))

    def test_digest_for_unbound(self):
        t = self._tracker()
        t.present(_mint(self.keyset, self.signers, {}))
        with self.assertRaises(lg.ArtifactRefused) as c:
            t.digest_for("skill:ghost")
        self.assertIn("corpus_manifest_unbound", str(c.exception))

    def test_tracker_type_checked(self):
        with self.assertRaises(TypeError):
            lg.CorpusManifestTracker("not-a-keyset")


class TestSkillLoaderCorpusWiring(unittest.TestCase):
    def setUp(self):
        self.keyset, self.signers = _keyset_world()
        self.pinset, self.h1 = _pin_world()
        self.content = b"skill alpha content"
        self.digest = _digest(self.content)
        _pin(self.pinset, self.h1, "skill:alpha", self.digest)

    def _tracker(self):
        return lg.CorpusManifestTracker(self.keyset)

    def test_honest_load_with_corpus(self):
        doc = _mint(self.keyset, self.signers, {"skill:alpha": self.digest})
        marked = lg.load_skill_content(
            self.pinset, {"alpha": self.content}, "alpha",
            corpus=self._tracker(), corpus_doc=doc)
        self.assertEqual(marked._ack_context["digest"], self.digest)

    def test_mix_and_match_refused(self):
        doc = _mint(self.keyset, self.signers,
                    {"skill:alpha": _digest(b"older bytes")})
        with self.assertRaises(lg.ArtifactRefused) as c:
            lg.load_skill_content(
                self.pinset, {"alpha": self.content}, "alpha",
                corpus=self._tracker(), corpus_doc=doc)
        self.assertIn("corpus_manifest_mismatch", str(c.exception))

    def test_unbound_refused(self):
        doc = _mint(self.keyset, self.signers, {})
        with self.assertRaises(lg.ArtifactRefused) as c:
            lg.load_skill_content(
                self.pinset, {"alpha": self.content}, "alpha",
                corpus=self._tracker(), corpus_doc=doc)
        self.assertIn("corpus_manifest_unbound", str(c.exception))

    def test_present_once_enforces_later_loads(self):
        tracker = self._tracker()
        doc = _mint(self.keyset, self.signers, {"skill:alpha": self.digest})
        tracker.present(doc)
        # Later loads without a doc still enforce the adopted manifest.
        marked = lg.load_skill_content(
            self.pinset, {"alpha": self.content}, "alpha", corpus=tracker)
        self.assertEqual(marked._ack_context["digest"], self.digest)

    def test_tracker_without_manifest_refuses(self):
        with self.assertRaises(lg.ArtifactRefused) as c:
            lg.load_skill_content(
                self.pinset, {"alpha": self.content}, "alpha",
                corpus=self._tracker())
        self.assertIn("corpus_manifest_unpresented", str(c.exception))

    def test_doc_without_tracker_refused(self):
        doc = _mint(self.keyset, self.signers, {"skill:alpha": self.digest})
        with self.assertRaises(lg.ArtifactRefused) as c:
            lg.load_skill_content(
                self.pinset, {"alpha": self.content}, "alpha",
                corpus_doc=doc)
        self.assertIn("corpus_manifest_unpresented", str(c.exception))

    def test_no_corpus_keeps_pinset_only_behavior(self):
        marked = lg.load_skill_content(
            self.pinset, {"alpha": self.content}, "alpha")
        self.assertEqual(marked._ack_context["digest"], self.digest)

    def test_loader_type_checks_corpus(self):
        with self.assertRaises(TypeError):
            lg.SkillLoader(self.pinset, {}, corpus="nope")


class TestCapabilityManifestThreshold(unittest.TestCase):
    def setUp(self):
        self.k1, self.k2 = "t-kid-1", "t-kid-2"
        self.store = capm.ManifestStore(
            keys={self.k1: ed.publickey(_SEED1),
                  self.k2: ed.publickey(_SEED2)},
            manifests={})
        self.content = b"threshold skill bytes"

    def _one(self):
        return capm.make_manifest("skill:t", self.content,
                                  capabilities={}, kid=self.k1,
                                  seed=_SEED1)

    def _two(self):
        m = self._one()
        m["signatures"].append(capm.sign_manifest(m, self.k2, _SEED2))
        return m

    def test_default_threshold_one_preserved(self):
        info = capm.verify_manifest(self._one(), self.store)
        self.assertEqual(info["kids"], [self.k1])

    def test_threshold_two_single_sig_refused(self):
        with self.assertRaises(capm.ManifestVerificationError) as c:
            capm.verify_manifest(self._one(), self.store, threshold=2)
        self.assertEqual(c.exception.code, "threshold-unmet")

    def test_threshold_two_two_kids_ok(self):
        info = capm.verify_manifest(self._two(), self.store, threshold=2)
        self.assertEqual(sorted(info["kids"]), [self.k1, self.k2])

    def test_same_kid_twice_counts_once(self):
        m = self._one()
        m["signatures"].append(capm.sign_manifest(m, self.k1, _SEED1))
        info = capm.verify_manifest(m, self.store)
        self.assertEqual(info["kids"], [self.k1])  # deduped
        with self.assertRaises(capm.ManifestVerificationError) as c:
            capm.verify_manifest(m, self.store, threshold=2)
        self.assertEqual(c.exception.code, "threshold-unmet")

    def test_bad_threshold_rejected(self):
        for bad in (0, -1, True, "2", None):
            with self.assertRaises(capm.ManifestVerificationError) as c:
                capm.verify_manifest(self._one(), self.store,
                                     threshold=bad)
            self.assertEqual(c.exception.code, "bad-threshold")

    def test_verify_skill_manifest_carries_threshold(self):
        store = capm.ManifestStore(
            keys={self.k1: ed.publickey(_SEED1),
                  self.k2: ed.publickey(_SEED2)},
            manifests={"skill:t": self._one()})
        ok, detail = capm.verify_skill_manifest("skill:t", self.content,
                                                store)
        self.assertEqual((ok, detail), (True, "clean"))
        ok, detail = capm.verify_skill_manifest("skill:t", self.content,
                                                store, threshold=2)
        self.assertEqual((ok, detail),
                         (False, "manifest-threshold-unmet"))

    def test_verify_skill_manifest_two_sigs_clean(self):
        store = capm.ManifestStore(
            keys={self.k1: ed.publickey(_SEED1),
                  self.k2: ed.publickey(_SEED2)},
            manifests={"skill:t": self._two()})
        ok, detail = capm.verify_skill_manifest("skill:t", self.content,
                                                store, threshold=2)
        self.assertEqual((ok, detail), (True, "clean"))


if __name__ == "__main__":
    unittest.main()
