"""Wave-194 lane A: TUF freshness steal for the load seam — unit tests.

``ArtifactPinset`` pins now carry a monotonic ``version`` (>= 1) and a
``not_after`` expiry bound, both covered by the pin authorship
signature (protocol ``gov-artifact-pin/v2``). ``verify_and_load``
(and therefore the forced entry point ``load_skill_content``) refuses
expired pins before checking the digest; re-pinning at a
non-increasing version is refused (the TUF rollback floor).

Hermetic: synthetic keys/content, no network. Deterministic except
wall-clock "now" (used only for expiry comparison, never asserted on).
"""
import hashlib
import os
import secrets
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import load_gate as _lg  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.ed25519 import publickey as _pubkey  # noqa: E402
from gov.ed25519 import sign as _edsign  # noqa: E402
from gov.sterile import Unvetted  # noqa: E402

_TS = "2026-09-23T00:00:00+00:00"
_PAST = "2020-01-01T00:00:00+00:00"
_FUTURE = "2030-01-01T00:00:00+00:00"


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class LoadSeamFreshnessTest(unittest.TestCase):
    def setUp(self):
        self.s1 = secrets.token_bytes(32)
        self.s2 = secrets.token_bytes(32)
        ax = secrets.token_bytes(32)
        self.trust = DelegationTrust(
            human_keys={"op:alice": _pubkey(self.s1),
                        "op:bob": _pubkey(self.s2)},
            authority_keys={"ax": _pubkey(ax)},
            user_issuer_keys={"idp": _pubkey(secrets.token_bytes(32))},
        )
        self.pinset = _lg.ArtifactPinset(self.trust)

    # -- helpers ------------------------------------------------------

    def _pin(self, artifact_id, digest, seed=None, key_id="op:alice",
             ts=_TS, tier="dev", version=1, not_after=None):
        na = _lg._resolve_pin_not_after(ts, not_after)
        body = _lg._canonical_pin_body(tier, artifact_id, digest, ts,
                                       version=version, not_after=na)
        return self.pinset.pin(
            artifact_id, digest, key_id, _edsign(seed or self.s1, body).hex(),
            ts=ts, tier=tier, version=version, not_after=na)

    def _unpin(self, artifact_id, seed=None, key_id="op:alice", ts=_TS,
               tier="dev", version=2):
        body = _lg._canonical_unpin_body(tier, artifact_id, ts,
                                         version=version)
        return self.pinset.unpin(
            artifact_id, key_id, _edsign(seed or self.s1, body).hex(),
            ts=ts, tier=tier, version=version)

    # -- the pin record ------------------------------------------------

    def test_pin_record_carries_version_and_not_after(self):
        rec = self._pin("skill:x", _digest(b"d"))
        self.assertEqual(rec["version"], 1)
        # Default TTL: pinned_at + 90 days (mirrors the watch layer).
        self.assertEqual(rec["not_after"], "2026-12-22T00:00:00+00:00")

    def test_explicit_not_after_recorded_verbatim(self):
        rec = self._pin("skill:x", _digest(b"d"), not_after=_FUTURE)
        self.assertEqual(rec["not_after"], _FUTURE)

    # -- expiry at the load seam ----------------------------------------

    def test_expired_pin_refused_at_forced_entry(self):
        data = b"skill-bytes"
        self._pin("skill:e", _digest(data), not_after=_PAST)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            _lg.load_skill_content(self.pinset, {"e": data}, "e")
        self.assertIn("pin_expired", str(c.exception))

    def test_expired_pin_refused_at_verify_and_load(self):
        data = b"skill-bytes"
        self._pin("skill:e", _digest(data), not_after=_PAST)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            _lg.verify_and_load(self.pinset, "skill:e", data)
        self.assertIn("pin_expired", str(c.exception))

    def test_expiry_checked_before_digest(self):
        # Stale pins are refused before any content is attested
        # (watch-layer parity) — even wrong bytes report pin_expired.
        self._pin("skill:e", _digest(b"right"), not_after=_PAST)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            _lg.verify_and_load(self.pinset, "skill:e", b"wrong")
        self.assertIn("pin_expired", str(c.exception))

    def test_fresh_pin_still_loads(self):
        data = b"skill-bytes"
        self._pin("skill:f", _digest(data), not_after=_FUTURE)
        marker = _lg.load_skill_content(self.pinset, {"f": data}, "f")
        self.assertIsInstance(marker, Unvetted)

    # -- rollback floor --------------------------------------------------

    def test_rollback_repin_refused_and_newer_pin_survives(self):
        new_data, old_data = b"v2-fixed", b"v1-vuln"
        self._pin("skill:x", _digest(new_data), version=2)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self._pin("skill:x", _digest(old_data), version=1)
        self.assertIn("pin_version_not_monotonic", str(c.exception))
        self.assertEqual(self.pinset.pin_for("skill:x")["digest"],
                         _digest(new_data))

    def test_same_version_repin_refused(self):
        self._pin("skill:x", _digest(b"a"), version=3)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self._pin("skill:x", _digest(b"b"), version=3)
        self.assertIn("pin_version_not_monotonic", str(c.exception))

    def test_higher_version_renewal_accepted(self):
        self._pin("skill:x", _digest(b"v1"), version=1)
        self._pin("skill:x", _digest(b"v2"), version=2)
        got = _lg.verify_and_load(self.pinset, "skill:x", b"v2")
        self.assertEqual(got.digest, _digest(b"v2"))

    # -- unpin versioning -------------------------------------------------

    def test_unpin_replay_refused_and_pin_survives(self):
        self._pin("skill:x", _digest(b"d"), version=2)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self._unpin("skill:x", version=1)
        self.assertIn("unpin_version_not_monotonic", str(c.exception))
        self.assertIsNotNone(self.pinset.pin_for("skill:x"))

    def test_unpin_at_higher_version_works(self):
        self._pin("skill:x", _digest(b"d"), version=1)
        self.assertTrue(self._unpin("skill:x", version=2))
        self.assertIsNone(self.pinset.pin_for("skill:x"))

    # -- fail-closed parsing ----------------------------------------------

    def test_naive_not_after_refused(self):
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self._pin("skill:x", _digest(b"d"),
                      not_after="2026-09-29 00:00:00")
        self.assertIn("no timezone", str(c.exception))

    def test_malformed_not_after_refused(self):
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self._pin("skill:x", _digest(b"d"), not_after="tomorrow-ish")
        self.assertIn("not valid ISO-8601", str(c.exception))

    def test_bad_versions_refused(self):
        for bad in (0, -1, True, "2", 1.5):
            with self.assertRaises(_lg.ArtifactRefused, msg=repr(bad)):
                self._pin("skill:x", _digest(b"d"), version=bad)

    def test_expiry_tamper_breaks_authorship(self):
        # Rewriting not_after while replaying the old signature dies at
        # authorship: the bound is inside the signed body.
        digest = _digest(b"d")
        na = _lg._resolve_pin_not_after(_TS, _FUTURE)
        body = _lg._canonical_pin_body("dev", "skill:x", digest, _TS,
                                       version=1, not_after=na)
        sig = _edsign(self.s1, body).hex()
        with self.assertRaises(_lg.ArtifactRefused) as c:
            self.pinset.pin("skill:x", digest, "op:alice", sig,
                            ts=_TS, tier="dev", version=1,
                            not_after="2031-01-01T00:00:00+00:00")
        self.assertIn("pin_authorship_invalid", str(c.exception))

    # -- no regression on the pre-existing refusals -------------------------

    def test_digest_mismatch_still_refused(self):
        self._pin("skill:x", _digest(b"right"), not_after=_FUTURE)
        with self.assertRaises(_lg.ArtifactRefused) as c:
            _lg.verify_and_load(self.pinset, "skill:x", b"wrong")
        self.assertIn("digest_mismatch", str(c.exception))

    def test_unpinned_still_refused(self):
        with self.assertRaises(_lg.ArtifactRefused) as c:
            _lg.verify_and_load(self.pinset, "skill:nope", b"bytes")
        self.assertIn("artifact_unpinned", str(c.exception))


if __name__ == "__main__":
    unittest.main()
