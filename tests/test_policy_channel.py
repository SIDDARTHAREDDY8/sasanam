"""Unit tests for gov/policy_channel.py (wave-327 lane 3).

Pins the contracts: exact-True signature verification, the rollback
floor, the bounded skip window, revocation persistence, atomic
activation, provenance traceability, the feed trust boundary, and
the loud stale verdict.
"""

import base64
import json
import os
import shutil
import tempfile
import unittest

from gov import ed25519, policy_channel as pc
from gov.bundle_refresh import tuf_canonical_json


def _keys():
    seed = ed25519.generate_seed()
    return seed, ed25519.publickey(seed)


def _mot():
    return [{"origin": "test", "collector": "test",
             "known_since": 1700000000}]


def _doc(version, seed, policy_name="agent-policy", body=None, revokes=None,
         motivated_by="default", issued_at=1700000000):
    if motivated_by == "default":
        motivated_by = _mot()
    payload = {
        "schema": "sasanam-policy-document/v1",
        "policy_name": policy_name,
        "version": version,
        "body": {"rules": ["r%d" % version]} if body is None else body,
        "revokes": [] if revokes is None else list(revokes),
        "motivated_by": list(motivated_by),
        "issued_at": issued_at,
    }
    raw = tuf_canonical_json(payload)
    sig = ed25519.sign(seed, raw)
    return {"payload": base64.b64encode(raw).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii")}


def _raw(envelope):
    return json.dumps(envelope).encode("utf-8")


class ChannelTest(unittest.TestCase):
    def setUp(self):
        self.feed = tempfile.mkdtemp(prefix="pct-feed-")
        self.state = tempfile.mkdtemp(prefix="pct-state-")
        self.seed, self.pub = _keys()
        self.cfg = pc.ChannelConfig(
            feed_dir=self.feed, feed_public_key=self.pub,
            policy_name="agent-policy", max_skip=4,
            max_staleness_seconds=86400)

    def tearDown(self):
        shutil.rmtree(self.feed, ignore_errors=True)
        shutil.rmtree(self.state, ignore_errors=True)

    def _write(self, envelope, version, name=None):
        path = os.path.join(
            self.feed, name or ("agent-policy.v%d.json" % version))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)
        return path

    # -- contract: signature verification is exact True/False -------------

    def test_verify_contract_exact_true(self):
        raw = _raw(_doc(1, self.seed))
        doc = pc.verify_document(self.cfg, raw)
        self.assertEqual(doc["version"], 1)

    def test_verify_forged_signature_refused(self):
        env = _doc(1, self.seed)
        bad = bytearray(base64.b64decode(env["signature"]))
        bad[0] ^= 1
        env["signature"] = base64.b64encode(bytes(bad)).decode("ascii")
        with self.assertRaises(pc.PolicyChannelError) as ctx:
            pc.verify_document(self.cfg, _raw(env))
        self.assertEqual(ctx.exception.code, "policy-channel-unsigned")

    def test_verify_wrong_key_refused(self):
        _seed2, pub2 = _keys()
        cfg2 = pc.ChannelConfig(
            feed_dir=self.feed, feed_public_key=pub2,
            policy_name="agent-policy")
        with self.assertRaises(pc.PolicyChannelError) as ctx:
            pc.verify_document(cfg2, _raw(_doc(1, self.seed)))
        self.assertEqual(ctx.exception.code, "policy-channel-unsigned")

    # -- contract: rollback floor ------------------------------------------

    def test_rollback_floor(self):
        self._write(_doc(1, self.seed), 1)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertTrue(rep["applied"])
        with self.assertRaises(pc.PolicyChannelError) as ctx:
            pc.apply_document(self.cfg, self.state, _raw(_doc(1, self.seed)))
        self.assertEqual(ctx.exception.code, "policy-channel-rollback")
        self.assertEqual(pc.current_version(self.cfg, self.state), 1)

    # -- contract: bounded skip --------------------------------------------

    def test_skip_within_window_applies(self):
        self._write(_doc(1, self.seed), 1)
        pc.poll(self.cfg, self.state, now=1700000001)
        self._write(_doc(5, self.seed), 5)  # 1 + max_skip(4)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertTrue(rep["applied"])
        self.assertEqual(rep["version"], 5)

    def test_skip_beyond_window_refused(self):
        self._write(_doc(1, self.seed), 1)
        pc.poll(self.cfg, self.state, now=1700000001)
        self._write(_doc(6, self.seed), 6)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertFalse(rep["applied"])
        self.assertEqual(rep["code"], "policy-channel-version-skip")
        self.assertEqual(pc.current_version(self.cfg, self.state), 1)

    # -- contract: revocation ----------------------------------------------

    def test_revoked_version_never_reapplied(self):
        self._write(_doc(1, self.seed), 1)
        self._write(_doc(2, self.seed, revokes=[3]), 2)
        pc.poll(self.cfg, self.state, now=1700000001)
        self._write(_doc(3, self.seed), 3)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertFalse(rep["applied"])
        self.assertEqual(rep["code"], "policy-channel-superseded")

    # -- contract: atomic activation ---------------------------------------

    def test_orphaned_tmp_is_loud_and_keeps_old_policy(self):
        self._write(_doc(1, self.seed), 1)
        pc.poll(self.cfg, self.state, now=1700000001)
        body = pc.current_body(self.cfg, self.state)
        orphan = os.path.join(self.state, ".policy-activate-x.tmp")
        with open(orphan, "w") as fh:
            fh.write("partial")
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(rep["code"], "policy-channel-activation-failed")
        self.assertEqual(pc.current_version(self.cfg, self.state), 1)
        self.assertEqual(pc.current_body(self.cfg, self.state), body)
        self.assertFalse(os.path.exists(orphan))

    # -- contract: provenance ----------------------------------------------

    def test_provenance_traced(self):
        mot = [{"origin": "osv.dev", "collector": "c",
                "known_since": 1700000100}]
        self._write(_doc(1, self.seed, motivated_by=mot), 1)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(rep["provenance"], mot)
        self.assertEqual(
            pc.policy_provenance(self.cfg, self.state, 1), mot)

    # -- contract: feed boundary -------------------------------------------

    def test_symlink_escape_refused(self):
        outside = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False)
        outside.write(_raw(_doc(1, self.seed)))
        outside.close()
        self.addCleanup(os.unlink, outside.name)
        os.symlink(outside.name,
                   os.path.join(self.feed, "agent-policy.v1.json"))
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertFalse(rep["applied"])
        self.assertEqual(rep["code"], "policy-channel-feed-escape")

    # -- contract: unknown policy ------------------------------------------

    def test_unknown_policy_name_refused(self):
        with self.assertRaises(pc.PolicyChannelError) as ctx:
            pc.apply_document(self.cfg, self.state,
                              _raw(_doc(1, self.seed, policy_name="nope")))
        self.assertEqual(ctx.exception.code, "policy-channel-unknown-policy")

    # -- contract: stale is loud -------------------------------------------

    def test_stale_loud(self):
        cfg = pc.ChannelConfig(
            feed_dir=self.feed, feed_public_key=self.pub,
            policy_name="agent-policy", max_staleness_seconds=100)
        self._write(_doc(1, self.seed, issued_at=1700000000), 1)
        rep = pc.poll(cfg, self.state, now=1700000000 + 50)
        self.assertFalse(rep["stale"])
        rep = pc.poll(cfg, self.state, now=1700000000 + 101)
        self.assertTrue(rep["stale"])
        self.assertEqual(rep["code"], "policy-channel-stale")
        self.assertEqual(pc.current_version(cfg, self.state), 1)

    # -- contract: tampered file stops the poll ----------------------------

    def test_tampered_file_stops_poll_loud(self):
        self._write(_doc(1, self.seed), 1)
        env = _doc(2, self.seed)
        bad = bytearray(base64.b64decode(env["signature"]))
        bad[0] ^= 1
        env["signature"] = base64.b64encode(bytes(bad)).decode("ascii")
        self._write(env, 2)
        self._write(_doc(3, self.seed), 3)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertTrue(rep["applied"])  # v1 applied on the first poll
        self.assertEqual(rep["version"], 1)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertFalse(rep["applied"])
        self.assertEqual(rep["code"], "policy-channel-unsigned")
        # v3 was NOT processed past the tampered v2.
        self.assertEqual(pc.current_version(self.cfg, self.state), 1)

    # -- contract: bad config fails closed ---------------------------------

    def test_bad_config_fails_closed(self):
        with self.assertRaises(pc.PolicyChannelError):
            pc.ChannelConfig(feed_dir=self.feed, feed_public_key=b"short",
                             policy_name="agent-policy")
        with self.assertRaises(pc.PolicyChannelError):
            pc.ChannelConfig(feed_dir=self.feed,
                             feed_public_key=self.pub,
                             policy_name="agent-policy", max_skip=0)


    def test_empty_motivated_by_refused(self):
        with self.assertRaises(pc.PolicyChannelError) as ctx:
            pc.apply_document(self.cfg, self.state,
                              _raw(_doc(1, self.seed, motivated_by=[])))
        self.assertEqual(ctx.exception.code, "policy-channel-malformed")

    def test_future_issued_at_refused(self):
        with self.assertRaises(pc.PolicyChannelError) as ctx:
            pc.apply_document(
                self.cfg, self.state,
                _raw(_doc(1, self.seed, issued_at=1700000000)),
                now=1700000000 - 1000)
        self.assertEqual(ctx.exception.code, "policy-channel-malformed")

    def test_noncanonical_payload_refused(self):
        payload = {
            "schema": "sasanam-policy-document/v1",
            "policy_name": "agent-policy",
            "version": 1,
            "body": {"rules": ["r1"]},
            "revokes": [],
            "motivated_by": _mot(),
            "issued_at": 1700000000,
        }
        raw = json.dumps(payload, separators=(", ", ": ")).encode("utf-8")
        sig = ed25519.sign(self.seed, raw)
        env = {"payload": base64.b64encode(raw).decode("ascii"),
               "signature": base64.b64encode(sig).decode("ascii")}
        with self.assertRaises(pc.PolicyChannelError) as ctx:
            pc.verify_document(self.cfg, json.dumps(env).encode("utf-8"))
        self.assertEqual(ctx.exception.code, "policy-channel-malformed")

    def test_reconcile_heals_crash_between_writes(self):
        self._write(_doc(1, self.seed), 1)
        pc.poll(self.cfg, self.state, now=1700000001)
        raw_v2 = json.dumps(_doc(2, self.seed)).encode("utf-8")
        with open(os.path.join(self.state, "active_policy.json"),
                  "wb") as fh:
            fh.write(raw_v2)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(rep["code"], "policy-channel-activation-failed")
        self.assertEqual(pc.current_version(self.cfg, self.state), 2)

    def test_stale_fires_even_when_applied(self):
        # A newly applied policy with an ancient issued_at still trips
        # the staleness bound.
        self._write(_doc(1, self.seed, issued_at=1700000000), 1)
        rep = pc.poll(self.cfg, self.state, now=1700000000 + 90000)
        self.assertTrue(rep["applied"])
        self.assertTrue(rep["stale"])
        self.assertEqual(rep["code"], "policy-channel-stale")

    # -- F413: feed iteration is numeric on version, not filename --------

    def test_feed_files_sorted_numerically_by_version(self):
        # The docstring promises "(version, name) pairs ... sorted by
        # version"; filename order would put v10 before v2.
        for v in (1, 2, 10):
            self._write(_doc(v, self.seed), v)
        self.assertEqual(
            pc._feed_files(self.cfg),
            [(1, "agent-policy.v1.json"),
             (2, "agent-policy.v2.json"),
             (10, "agent-policy.v10.json")])

    def test_multi_digit_feed_applies_in_window_before_skip_refusal(self):
        # F413a: feed {v1, v2, v10}, floor v1 -- v2 applies first, then
        # v10 refuses coded policy-channel-version-skip (no stuck floor).
        for v in (1, 2, 10):
            self._write(_doc(v, self.seed), v)
        pc.poll(self.cfg, self.state, now=1700000001)
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(pc.current_version(self.cfg, self.state), 2)
        self.assertEqual(rep["code"], "policy-channel-version-skip")

    def test_intermediate_revocation_not_silently_dropped(self):
        # F413b: feed {v9 (revokes=[12]), v10}, floor v8 -- v9's
        # revocation of v12 is recorded; a later v12 refuses coded
        # policy-channel-superseded (the established revocation code;
        # close-when allows no new codes).
        for v in (4, 8):
            self._write(_doc(v, self.seed), v)
        self._write(_doc(9, self.seed, revokes=[12]), 9)
        self._write(_doc(10, self.seed), 10)
        pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(pc.current_version(self.cfg, self.state), 10)
        revoked = pc._load_state(self.state)["revoked_versions"]
        self.assertIn(12, revoked)
        self._write(_doc(12, self.seed), 12)
        rep2 = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(rep2["code"], "policy-channel-superseded")
        self.assertEqual(pc.current_version(self.cfg, self.state), 10)

    def test_duplicate_version_filenames_resolve_deterministically(self):
        # "pol.v02.json" and "pol.v2.json" both parse to version 2: the
        # stable sort keeps filename order, the first applies, the rest
        # skip as already-held history -- no guess, no crash.
        self._write(_doc(2, self.seed), 2)
        shutil.copy(
            os.path.join(self.feed, "agent-policy.v2.json"),
            os.path.join(self.feed, "agent-policy.v02.json"))
        self.assertEqual(
            pc._feed_files(self.cfg),
            [(2, "agent-policy.v02.json"),
             (2, "agent-policy.v2.json")])
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(pc.current_version(self.cfg, self.state), 2)
        self.assertTrue(rep["applied"])
        self.assertIsNone(rep["code"])


    def test_unicode_digit_version_fragment_refused_coded(self):
        # F415: U+00B2 passes str.isdigit() but int() rejects it. The
        # fragment must refuse coded policy-channel-malformed -- a bare
        # ValueError must never escape poll().
        self._write(_doc(1, self.seed), 1)
        self._write(_doc(2, self.seed), 2, name="agent-policy.v².json")
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(rep["code"], "policy-channel-malformed")
        self.assertFalse(rep["applied"])
        self.assertEqual(pc.current_version(self.cfg, self.state), 0)

    def test_arabic_indic_digit_fragment_refused_coded(self):
        # F415 companion: Arabic-Indic digits (U+0661/U+0662) are also
        # isdigit()-True/int()-rejecting; same coded refusal.
        self._write(_doc(1, self.seed), 1)
        self._write(_doc(2, self.seed), 2, name="agent-policy.v١٢.json")
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertEqual(rep["code"], "policy-channel-malformed")
        self.assertFalse(rep["applied"])

    def test_non_digit_fragment_still_skipped(self):
        # Boundary: fragments that fail isdigit() keep the documented
        # skip behavior -- only isdigit()-passing non-ASCII fragments
        # refuse coded.
        self._write(_doc(1, self.seed), 1)
        self._write(_doc(2, self.seed), 2, name="agent-policy.vX.json")
        rep = pc.poll(self.cfg, self.state, now=1700000001)
        self.assertTrue(rep["applied"])
        self.assertIsNone(rep["code"])
        self.assertEqual(pc.current_version(self.cfg, self.state), 1)


if __name__ == "__main__":
    unittest.main()
