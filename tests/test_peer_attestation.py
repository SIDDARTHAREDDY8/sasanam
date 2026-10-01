"""Unit tests for gov/peer_attestation.py (wave-267).

Pin: 1222 (wave-266 merge) + 7 federation peer-attestation codes =
1229. This file is the lane's own pin holder; the global
test_decision_codes.py pin is left for the merge coordinator's
repoint pass (standard lane convention).
"""

import os
import shutil
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import ed25519
from gov import peer_attestation as pa
from gov import trust_federation as tf

TAXONOMY_PIN = 1299  # Wave-268 merge: pin -> 1299.


def _keys():
    seed = ed25519.generate_seed()
    return seed, ed25519.publickey(seed).hex()


def _scratch(testcase, name):
    td = tempfile.mkdtemp(prefix="g267-pa-ut-%s-" % name,
                          dir="/var/tmp")
    testcase.addCleanup(shutil.rmtree, td, ignore_errors=True)
    return td


def _table(testcase, allowlisted=("team",),
           local_domain="mesh.example"):
    td = _scratch(testcase, "t")
    return pa.PeerAttestationTable(os.path.join(td, "j.db"),
                                   local_domain,
                                   allowlisted_claim_keys=allowlisted), td


def _possession_sig(seed, nonce_hex, peer_id):
    msg = (b"sasanam-peer-possession/v1:" + bytes.fromhex(nonce_hex)
           + b":" + peer_id.encode("utf-8"))
    return ed25519.sign(seed, msg)


def _claim_sig(seed, peer_id, key, value):
    msg = (b"sasanam-peer-claim/v1:" + peer_id.encode("utf-8") + b":"
           + key.encode("utf-8") + b":" + value.encode("utf-8"))
    return ed25519.sign(seed, msg)


class TestCodes(unittest.TestCase):
    def test_codes_tuple(self):
        self.assertEqual(list(pa.CODES), sorted(pa.CODES))
        self.assertEqual(len(pa.CODES), 7)

    def test_taxonomy_pin(self):
        self.assertEqual(len(dc.TAXONOMY), TAXONOMY_PIN)

    def test_entries_present(self):
        for code in pa.CODES:
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "federation")
            self.assertEqual(dc.TAXONOMY[code]["code"], code)

    def test_claim_classes(self):
        self.assertEqual(pa.CLAIM_ANCHOR_SIGNED, "anchor_signed")
        self.assertEqual(pa.CLAIM_SELF_ASSERTABLE, "self_assertable")


class TestTofu(unittest.TestCase):
    def test_double_join_peer_id_rebind(self):
        t, _td = _table(self)
        _, pub1 = _keys()
        _, pub2 = _keys()
        t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
        t.register_peer("peer-a", pub1, now=1000)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.register_peer("peer-a", pub2, now=2000)
        self.assertEqual(cm.exception.code, "federation-double-join")
        # The anchor is still the FIRST key (no silent rebind).
        self.assertEqual(t.peer_record("peer-a")["anchor_public_key"],
                         pub1)

    def test_double_join_anchor_reuse(self):
        t, _td = _table(self)
        _, pub1 = _keys()
        t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
        t.author_identity("peer-b", ["spiffe://mesh.example/peer/b"])
        t.register_peer("peer-a", pub1, now=1000)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.register_peer("peer-b", pub1, now=2000)
        self.assertEqual(cm.exception.code, "federation-double-join")

    def test_double_join_journals_incident(self):
        t, td = _table(self)
        _, pub1 = _keys()
        _, pub2 = _keys()
        t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
        t.register_peer("peer-a", pub1, now=1000)
        try:
            t.register_peer("peer-a", pub2, now=2000)
        except pa.PeerAttestationError:
            pass
        with open(os.path.join(td, "j.db"), "r",
                  encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("peer-double-join-incident", body)
        self.assertIn("security_incident", body)

    def test_remove_then_reregister(self):
        t, _td = _table(self)
        _, pub1 = _keys()
        _, pub2 = _keys()
        t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
        t.register_peer("peer-a", pub1, now=1000)
        t.remove_peer("peer-a", now=2000)
        reg = t.register_peer("peer-a", pub2, now=3000)
        self.assertTrue(reg["registered"])


class TestClaimClasses(unittest.TestCase):
    def _registered(self, t, peer="peer-a", allowlisted=("team",)):
        seed, pub = _keys()
        t.author_identity(peer,
                          ["spiffe://mesh.example/%s" % peer])
        t.register_peer(peer, pub, now=1000)
        return seed

    def test_self_assertable_spoof_denied(self):
        t, _td = _table(self)
        seed = self._registered(t)
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-a")
        claims = {"aws_iid:tag:role": ("prod",
                                       pa.CLAIM_SELF_ASSERTABLE)}
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-a", "spiffe://mesh.example/peer-a",
                     ch["nonce"], sig, claims=claims, now=1200)
        self.assertEqual(cm.exception.code,
                         "federation-claim-class-denied")

    def test_self_assertable_allowlisted_honored(self):
        t, _td = _table(self)
        seed = self._registered(t)
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-a")
        claims = {"team": ("eng", pa.CLAIM_SELF_ASSERTABLE)}
        rec = t.attest("peer-a", "spiffe://mesh.example/peer-a",
                       ch["nonce"], sig, claims=claims, now=1200)
        self.assertTrue(rec["attested"])
        self.assertEqual(rec["claims"]["team"]["class"],
                         "self_assertable")

    def test_anchor_signed_claim_verified(self):
        t, _td = _table(self)
        seed = self._registered(t)
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-a")
        csig = _claim_sig(seed, "peer-a", "hw_model", "x9")
        claims = {"hw_model": ("x9", pa.CLAIM_ANCHOR_SIGNED, csig)}
        rec = t.attest("peer-a", "spiffe://mesh.example/peer-a",
                       ch["nonce"], sig, claims=claims, now=1200)
        self.assertTrue(rec["attested"])
        self.assertEqual(rec["claims"]["hw_model"]["class"],
                         "anchor_signed")

    def test_anchor_signed_claim_forged(self):
        t, _td = _table(self)
        seed = self._registered(t)
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-a")
        csig = _claim_sig(ed25519.generate_seed(), "peer-a",
                          "hw_model", "x9")
        claims = {"hw_model": ("x9", pa.CLAIM_ANCHOR_SIGNED, csig)}
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-a", "spiffe://mesh.example/peer-a",
                     ch["nonce"], sig, claims=claims, now=1200)
        self.assertEqual(cm.exception.code,
                         "federation-claim-class-denied")

    def test_unknown_claim_class_malformed(self):
        t, _td = _table(self)
        self._registered(t)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.register_peer("peer-b", _keys()[1],
                            claims={"k": ("v", "mystery")}, now=2000)
        self.assertEqual(cm.exception.code,
                         "federation-attestation-malformed")


class TestAttestation(unittest.TestCase):
    def _flow(self, peer="peer-a", identities=None):
        t, td = _table(self)
        seed, pub = _keys()
        identities = identities or ["spiffe://mesh.example/" + peer]
        t.author_identity(peer, identities)
        t.register_peer(peer, pub, now=1000)
        return t, td, seed, pub

    def test_happy_path(self):
        t, _td, seed, _pub = self._flow()
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-a")
        rec = t.attest("peer-a", "spiffe://mesh.example/peer-a",
                       ch["nonce"], sig, now=1200)
        self.assertTrue(rec["attested"])
        self.assertEqual(rec["trust_domain"], "mesh.example")

    def test_unmapped_identity(self):
        t, _td, seed, _pub = self._flow()
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-a")
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-a", "spiffe://mesh.example/peer-z",
                     ch["nonce"], sig, now=1200)
        self.assertEqual(cm.exception.code,
                         "federation-identity-unmapped")

    def test_wrong_key_possession(self):
        t, _td, _seed, _pub = self._flow()
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(ed25519.generate_seed(), ch["nonce"],
                              "peer-a")
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-a", "spiffe://mesh.example/peer-a",
                     ch["nonce"], sig, now=1200)
        self.assertEqual(cm.exception.code,
                         "federation-possession-failed")

    def test_challenge_replay(self):
        t, _td, seed, _pub = self._flow()
        ch1 = t.issue_challenge("peer-a", now=1100)
        sig1 = _possession_sig(seed, ch1["nonce"], "peer-a")
        first = t.attest("peer-a", "spiffe://mesh.example/peer-a",
                         ch1["nonce"], sig1, now=1200)
        self.assertTrue(first["attested"])
        ch2 = t.issue_challenge("peer-a", now=1300)
        self.assertNotEqual(ch2["nonce"], ch1["nonce"])
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-a", "spiffe://mesh.example/peer-a",
                     ch2["nonce"], sig1, now=1400)
        self.assertEqual(cm.exception.code,
                         "federation-possession-failed")

    def test_challenge_single_use(self):
        t, _td, seed, _pub = self._flow()
        ch = t.issue_challenge("peer-a", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-a")
        self.assertTrue(t.attest("peer-a",
                                "spiffe://mesh.example/peer-a",
                                ch["nonce"], sig,
                                now=1200)["attested"])
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-a", "spiffe://mesh.example/peer-a",
                     ch["nonce"], sig, now=1300)
        self.assertEqual(cm.exception.code,
                         "federation-possession-failed")

    def test_verify_return_checked_with_is_true(self):
        # The wave-243 lesson: verify() returns True/False and never
        # raises; the module must check the return with `is True`.
        t, _td, _seed, _pub = self._flow()
        ch = t.issue_challenge("peer-a", now=1100)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-a", "spiffe://mesh.example/peer-a",
                     ch["nonce"], b"\x00" * 64, now=1200)
        self.assertEqual(cm.exception.code,
                         "federation-possession-failed")


class TestCrossDomain(unittest.TestCase):
    def _fed(self):
        td = _scratch(self, "fed")
        ftable = tf.FederationTable(os.path.join(td, "fed.db"))
        ftable.add_relationship(
            "foreign.example",
            "https://bundles.foreign.example/bundle",
            tf.ENDPOINT_PROFILE_HTTPS_SPIFFE, "aa" * 32)
        return ftable

    def _peer(self, t, peer="peer-x"):
        seed, pub = _keys()
        t.author_identity(peer,
                          ["spiffe://foreign.example/%s" % peer])
        t.register_peer(peer, pub, now=1000)
        return seed

    def test_unpinned_endpoint_auto_discovery_refused(self):
        t, _td = _table(self)
        seed = self._peer(t)
        ftd = _scratch(self, "fed2")
        ftable = tf.FederationTable(os.path.join(ftd, "fed.db"))
        ch = t.issue_challenge("peer-x", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-x")
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-x", "spiffe://foreign.example/peer-x",
                     ch["nonce"], sig, federation_table=ftable,
                     endpoint_url="https://bundles.foreign.example/"
                     "bundle", now=1200)
        self.assertEqual(cm.exception.code,
                         "federation-untrusted-domain")

    def test_endpoint_substitution_refused(self):
        t, _td = _table(self)
        seed = self._peer(t)
        ftable = self._fed()
        ch = t.issue_challenge("peer-x", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-x")
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("peer-x", "spiffe://foreign.example/peer-x",
                     ch["nonce"], sig, federation_table=ftable,
                     endpoint_url="https://evil.example/bundle",
                     now=1200)
        self.assertEqual(cm.exception.code,
                         "federation-endpoint-unpinned")

    def test_pinned_endpoint_verifies(self):
        t, _td = _table(self)
        seed = self._peer(t)
        ftable = self._fed()
        ch = t.issue_challenge("peer-x", now=1100)
        sig = _possession_sig(seed, ch["nonce"], "peer-x")
        rec = t.attest("peer-x", "spiffe://foreign.example/peer-x",
                       ch["nonce"], sig, federation_table=ftable,
                       endpoint_url="https://bundles.foreign.example/"
                       "bundle", now=1200)
        self.assertTrue(rec["attested"])
        self.assertEqual(rec["trust_domain"], "foreign.example")


class TestBanPrune(unittest.TestCase):
    def test_ban_refuses_challenge_and_attest(self):
        t, _td = _table(self)
        seed, pub = _keys()
        t.author_identity("peer-a", ["spiffe://mesh.example/peer-a"])
        t.register_peer("peer-a", pub, now=1000)
        t.ban_peer("peer-a", "selector spoof observed", now=1500)
        self.assertTrue(t.is_banned("peer-a"))
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.issue_challenge("peer-a", now=1600)
        self.assertEqual(cm.exception.code, "federation-peer-banned")
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.register_peer("peer-a", _keys()[1], now=1700)
        self.assertEqual(cm.exception.code, "federation-peer-banned")

    def test_ban_survives_prune(self):
        t, _td = _table(self)
        _, pub_a = _keys()
        _, pub_b = _keys()
        t.author_identity("peer-a", ["spiffe://mesh.example/peer-a"])
        t.author_identity("peer-b", ["spiffe://mesh.example/peer-b"])
        t.register_peer("peer-a", pub_a, now=1000)
        t.register_peer("peer-b", pub_b, now=1000)
        t.ban_peer("peer-a", "test", now=1500)
        out = t.prune(now=10_000, ttl_seconds=100)
        self.assertEqual(out["pruned"], 1)
        self.assertTrue(t.is_banned("peer-a"))
        self.assertIsNone(t.peer_record("peer-b"))

    def test_prune_bad_ttl_malformed(self):
        t, _td = _table(self)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.prune(now=1000, ttl_seconds=-1)
        self.assertEqual(cm.exception.code,
                         "federation-attestation-malformed")


class TestMalformed(unittest.TestCase):
    def test_bad_peer_id(self):
        t, _td = _table(self)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.register_peer("", "aa" * 32, now=1)
        self.assertEqual(cm.exception.code,
                         "federation-attestation-malformed")

    def test_bad_anchor(self):
        t, _td = _table(self)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.register_peer("peer-a", "not-hex", now=1)
        self.assertEqual(cm.exception.code,
                         "federation-attestation-malformed")

    def test_bad_identity_syntax(self):
        t, _td = _table(self)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.author_identity("peer-a", ["not-a-spiffe-id"])
        self.assertEqual(cm.exception.code,
                         "federation-attestation-malformed")

    def test_unknown_peer_attest(self):
        t, _td = _table(self)
        with self.assertRaises(pa.PeerAttestationError) as cm:
            t.attest("ghost", "spiffe://mesh.example/ghost",
                     "ab" * 32, b"\x00" * 64, now=1)
        self.assertEqual(cm.exception.code,
                         "federation-attestation-malformed")


if __name__ == "__main__":
    unittest.main()
