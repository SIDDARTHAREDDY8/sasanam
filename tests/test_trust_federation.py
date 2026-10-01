"""Unit tests for gov/trust_federation.py (wave-264 lane 3).

Tests sit at the public seams: relationship declaration, bundle
refresh, foreign verification, de-federation, and the
FederatedMeshControl shape. No internals.
"""

import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import svid_issuer as sv
from gov import trust_federation as tf

NOW = 1790000000
PARTNER = "partner.example"
OTHER = "other.example"

_ISSUER_SEED = bytes.fromhex("aa" * 32)
_NEXT_SEED = bytes.fromhex("bb" * 32)
_ENDPOINT_SEED = bytes.fromhex("cc" * 32)
_WORKLOAD_SEED = bytes.fromhex("dd" * 32)

_BUNDLE_DOMAIN = b"sasanam-federation-bundle/v1:"


def _canonical(obj):
    import hashlib
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")
    return body


def _seal(body, seed):
    import hashlib
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    msg = _BUNDLE_DOMAIN + digest.encode("ascii")
    bundle = dict(body)
    bundle["endpoint_signature"] = ed25519.sign(seed, msg).hex()
    return bundle


def _issuer(seed, key_id):
    return sv.TestSvidIssuer(issuer_seed=seed, key_id=key_id)


def _bundle(issuer, nxt, **kw):
    body = {
        "trust_domain": kw.get("domain", PARTNER),
        "bundle_id": kw.get("bundle_id", "u-001"),
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
        "roots": {issuer.key_id: issuer.issuer_public_key.hex()},
        "next_roots": {nxt.key_id: nxt.issuer_public_key.hex()},
    }
    body.update({k: v for k, v in kw.items()
                 if k in ("issued_at", "expires_at", "trust_domain",
                          "bundle_id")})
    seed = kw.get("seal_seed", _ENDPOINT_SEED)
    return _canonical(_seal(body, seed))


def _svid(issuer, domain=PARTNER):
    return issuer.issue("spiffe://%s/agent/u-1" % domain,
                        ed25519.publickey(_WORKLOAD_SEED).hex(),
                        ttl_minutes=30, now=NOW)


def _table():
    # The journal is mandatory (spec: the trust-revocation event is
    # journaled); every table in the tests gets a scratch journal.
    tmp = tempfile.mkdtemp(prefix="w264-tf-unit-")
    path = os.path.join(tmp, "j.jsonl")
    table = tf.FederationTable(path)
    table.add_relationship(
        PARTNER, "https://partner.example/bundle",
        tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
        ed25519.publickey(_ENDPOINT_SEED).hex())
    return table


class RelationshipTests(unittest.TestCase):
    def test_sanctioned_profiles_declare(self):
        for profile in (tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                        tf.ENDPOINT_PROFILE_HTTPS_WEB):
            rel = tf.FederationRelationship(
                "x.example", "https://x.example/b",
                profile, ed25519.publickey(_ENDPOINT_SEED).hex())
            self.assertEqual(rel.endpoint_profile, profile)

    def test_malformed_declarations_refuse(self):
        good_key = ed25519.publickey(_ENDPOINT_SEED).hex()
        cases = [
            ("not a domain", "https://x.example/b",
             tf.ENDPOINT_PROFILE_HTTPS_SPIFFE, good_key),
            (PARTNER, "http://x.example/b",
             tf.ENDPOINT_PROFILE_HTTPS_SPIFFE, good_key),
            (PARTNER, "https://x.example/b", "bogus", good_key),
            (PARTNER, "https://x.example/b",
             tf.ENDPOINT_PROFILE_HTTPS_SPIFFE, "zz"),
        ]
        for domain, endpoint, profile, key in cases:
            with self.assertRaises(tf.FederationError) as ctx:
                tf.FederationRelationship(domain, endpoint, profile,
                                          key)
            self.assertEqual(ctx.exception.code,
                             "federation-relationship-malformed")

    def test_termination_is_deletion(self):
        # Spec: termination is deletion of the domain's bundle from
        # the local table. Afterwards the domain is
        # as-if-never-granted, and a later add_relationship
        # re-federates fresh.
        issuer = _issuer(_ISSUER_SEED, "t-issuer-1")
        nxt = _issuer(_NEXT_SEED, "t-issuer-2")
        table = _table()
        table.refresh_bundle(PARTNER, _bundle(issuer, nxt), now=NOW)
        table.remove(PARTNER)
        with self.assertRaises(tf.FederationError) as ctx:
            table.verify_foreign(_svid(issuer), now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")
        # Re-federation on the same table works.
        table.add_relationship(
            PARTNER, "https://partner.example/bundle",
            tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
            ed25519.publickey(_ENDPOINT_SEED).hex())
        table.refresh_bundle(PARTNER, _bundle(issuer, nxt), now=NOW)
        claims = table.verify_foreign(_svid(issuer), now=NOW)
        self.assertEqual(claims["trust_domain"], PARTNER)

    def test_table_requires_journal(self):
        # The audit trail is not optional: a table without a
        # journal cannot exist.
        with self.assertRaises(TypeError):
            tf.FederationTable()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.issuer = _issuer(_ISSUER_SEED, "u-issuer-1")
        self.nxt = _issuer(_NEXT_SEED, "u-issuer-2")

    def test_refresh_installs_valid_bundle(self):
        table = _table()
        rec = table.refresh_bundle(
            PARTNER, _bundle(self.issuer, self.nxt), now=NOW)
        self.assertEqual(rec["trust_domain"], PARTNER)
        self.assertEqual(rec["bundle_id"], "u-001")

    def test_non_string_trust_domain_is_malformed(self):
        # Structure is validated before domain binding: a
        # non-string trust_domain is federation-bundle-malformed,
        # not federation-bundle-confusion.
        table = _table()
        with self.assertRaises(tf.FederationError) as ctx:
            table.refresh_bundle(
                PARTNER,
                _bundle(self.issuer, self.nxt, trust_domain=12345),
                now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-bundle-malformed")

    def test_next_roots_win_on_key_id_collision(self):
        # A next_root reusing a roots key_id with different key
        # material takes effect: the bundle's author attested to the
        # new key under the pinned endpoint key, so the rotation is
        # not silently dropped.
        issuer = _issuer(_ISSUER_SEED, "c-issuer-1")
        nxt = _issuer(_NEXT_SEED, "c-issuer-1")  # same key_id
        body = {
            "trust_domain": PARTNER,
            "bundle_id": "c-001",
            "issued_at": NOW - 60,
            "expires_at": NOW + 3600,
            "roots": {"c-issuer-1":
                      issuer.issuer_public_key.hex()},
            "next_roots": {"c-issuer-1":
                           nxt.issuer_public_key.hex()},
        }
        raw = _canonical(_seal(body, _ENDPOINT_SEED))
        rel = tf.FederationRelationship(
            PARTNER, "https://partner.example/bundle",
            tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
            ed25519.publickey(_ENDPOINT_SEED).hex())
        bundle = tf.TrustBundle.from_bytes(raw, rel, now=NOW)
        self.assertEqual(bundle.federated_roots()["c-issuer-1"],
                         nxt.issuer_public_key)

    def test_forged_bundle_refuses(self):
        table = _table()
        with self.assertRaises(tf.FederationError) as ctx:
            table.refresh_bundle(
                PARTNER,
                _bundle(self.issuer, self.nxt,
                        seal_seed=bytes.fromhex("ee" * 32)),
                now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-bundle-signature-invalid")

    def test_expired_bundle_refuses(self):
        table = _table()
        with self.assertRaises(tf.FederationError) as ctx:
            table.refresh_bundle(
                PARTNER,
                _bundle(self.issuer, self.nxt, expires_at=NOW - 1),
                now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-bundle-expired")

    def test_cross_domain_bundle_refuses(self):
        table = _table()
        tmp = tempfile.mkdtemp(prefix="w264-tf-unit-")
        other = tf.FederationTable(os.path.join(tmp, "j.jsonl"))
        other.add_relationship(
            OTHER, "https://other.example/b",
            tf.ENDPOINT_PROFILE_HTTPS_WEB,
            ed25519.publickey(_ENDPOINT_SEED).hex())
        with self.assertRaises(tf.FederationError) as ctx:
            other.refresh_bundle(
                OTHER, _bundle(self.issuer, self.nxt,
                               domain=PARTNER), now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-bundle-confusion")

    def test_refresh_unknown_domain_refuses(self):
        table = _table()
        with self.assertRaises(tf.FederationError) as ctx:
            table.refresh_bundle(
                OTHER, _bundle(self.issuer, self.nxt), now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.issuer = _issuer(_ISSUER_SEED, "v-issuer-1")
        self.nxt = _issuer(_NEXT_SEED, "v-issuer-2")
        self.table = _table()
        self.table.refresh_bundle(
            PARTNER, _bundle(self.issuer, self.nxt), now=NOW)

    def test_valid_foreign_svid_verifies(self):
        claims = self.table.verify_foreign(_svid(self.issuer),
                                           now=NOW)
        self.assertEqual(claims["trust_domain"], PARTNER)
        self.assertEqual(claims["spiffe_id"],
                         "spiffe://%s/agent/u-1" % PARTNER)

    def test_next_root_svid_verifies(self):
        claims = self.table.verify_foreign(_svid(self.nxt), now=NOW)
        self.assertEqual(claims["issuer_key_id"], "v-issuer-2")

    def test_unknown_key_refuses_composed_code(self):
        rogue = _issuer(bytes.fromhex("ff" * 32), "rogue-1")
        with self.assertRaises(Exception) as ctx:
            self.table.verify_foreign(_svid(rogue), now=NOW)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         "svid-issuer-unknown")

    def test_unfederated_domain_refuses(self):
        with self.assertRaises(tf.FederationError) as ctx:
            self.table.verify_foreign(_svid(self.issuer,
                                            domain=OTHER), now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")

    def test_missing_svid_refuses(self):
        with self.assertRaises(tf.FederationError) as ctx:
            self.table.verify_foreign(None, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")

    def test_expected_usage_propagates(self):
        with self.assertRaises(Exception) as ctx:
            self.table.verify_foreign(_svid(self.issuer), now=NOW,
                                      expected_usage="nope-usage")
        self.assertEqual(getattr(ctx.exception, "code", None),
                         "svid-usage-mismatch")

    def test_missing_bundle_has_own_code(self):
        # Declared relationship, no bundle ever polled:
        # federation-bundle-missing -- distinct from
        # federation-untrusted-domain (no relationship at all).
        table = _table()
        with self.assertRaises(tf.FederationError) as ctx:
            table.verify_foreign(_svid(self.issuer), now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-bundle-missing")


class TerminationTests(unittest.TestCase):
    def test_remove_ends_trust_and_journals(self):
        table = _table()
        issuer = _issuer(_ISSUER_SEED, "t-issuer-1")
        nxt = _issuer(_NEXT_SEED, "t-issuer-2")
        table.refresh_bundle(PARTNER, _bundle(issuer, nxt), now=NOW)
        rec = table.remove(PARTNER)
        self.assertTrue(rec["revoked"])
        # Termination is deletion: the domain is as-if-never-granted.
        with self.assertRaises(tf.FederationError) as ctx:
            table.verify_foreign(_svid(issuer), now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")
        kinds = [r["type"] for r in table.journal_records()]
        self.assertIn("federation-trust-revoked", kinds)
        self.assertIn("federation-relationship-added", kinds)

    def test_one_way_default(self):
        # Our table trusts PARTNER; a second table (partner's view)
        # with no reverse edge cannot verify our SVIDs.
        home_issuer = _issuer(bytes.fromhex("11" * 32), "home-1")
        tmp = tempfile.mkdtemp(prefix="w264-tf-unit-")
        partner_view = tf.FederationTable(
            os.path.join(tmp, "j.jsonl"))
        home_svid = home_issuer.issue(
            "spiffe://home.example/agent/a",
            ed25519.publickey(_WORKLOAD_SEED).hex(),
            ttl_minutes=30, now=NOW)
        with self.assertRaises(tf.FederationError) as ctx:
            partner_view.verify_foreign(home_svid, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")


class MeshControlTests(unittest.TestCase):
    def test_admit_shape(self):
        issuer = _issuer(_ISSUER_SEED, "m-issuer-1")
        nxt = _issuer(_NEXT_SEED, "m-issuer-2")
        table = _table()
        table.refresh_bundle(PARTNER, _bundle(issuer, nxt), now=NOW)
        control = tf.FederatedMeshControl(table)
        claims = control.admit(_svid(issuer), now=NOW)
        self.assertEqual(claims["trust_domain"], PARTNER)
        with self.assertRaises(tf.FederationError) as ctx:
            control.admit(None, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")

    def test_wrong_table_type_refuses(self):
        # A wiring-time type error, not a trust refusal: TypeError,
        # not a federation-* code.
        with self.assertRaises(TypeError):
            tf.FederatedMeshControl(object())


class AdmissionRouteTests(unittest.TestCase):
    """The federated route mode on gov.mesh_admission.MeshAdmission
    (wave-264 integration): each route evaluates exactly one seam."""

    def setUp(self):
        from gov import mesh_admission as ma
        self.ma = ma
        self.issuer = _issuer(_ISSUER_SEED, "a-issuer-1")
        self.nxt = _issuer(_NEXT_SEED, "a-issuer-2")
        self.table = _table()
        self.table.refresh_bundle(
            PARTNER, _bundle(self.issuer, self.nxt), now=NOW)
        self.federated = tf.FederatedMeshControl(self.table)
        # Local SVID control for the non-federated routes: a
        # separate trust domain the federation table never sees.
        self.local_issuer = _issuer(bytes.fromhex("12" * 32),
                                   "local-issuer-1")
        verifier = sv.SvidVerifier(
            {"local-issuer-1": self.local_issuer.issuer_public_key},
            "home.example")
        self.mesh_control = sv.MeshControl(
            verifier, {"allow": ["spiffe://home.example/agent"]})

    def _admission(self, routes):
        return self.ma.MeshAdmission(
            routes, self.mesh_control,
            federated_control=self.federated)

    def test_federated_route_admits_foreign_svid(self):
        adm = self._admission({"x": {"require": "federated"}})
        rec = adm.admit("x", svid=_svid(self.issuer), now=NOW)
        self.assertEqual(rec["mode"], "federated")
        self.assertEqual(rec["trust_domain"], PARTNER)
        self.assertEqual(rec["spiffe_id"],
                         "spiffe://%s/agent/u-1" % PARTNER)

    def test_federated_route_refuses_unfederated(self):
        adm = self._admission({"x": {"require": "federated"}})
        with self.assertRaises(tf.FederationError) as ctx:
            adm.admit("x", svid=_svid(self.issuer, domain=OTHER),
                      now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")

    def test_federated_route_no_downgrade_to_local(self):
        # A *locally verifiable* SVID (would admit on a "svid"
        # route) presented on a "federated" route must still
        # refuse: the federated path is the only one evaluated,
        # never the local SVID seam.
        adm = self._admission({"x": {"require": "federated"},
                               "s": {"require": "svid"}})
        local_svid = _svid(self.local_issuer, domain="home.example")
        # Sanity: the same SVID admits on the local route.
        rec = adm.admit("s", svid=local_svid, now=NOW)
        self.assertEqual(rec["mode"], "svid")
        # On the federated route it refuses with federation
        # vocabulary -- the local verifier is never consulted.
        with self.assertRaises(tf.FederationError) as ctx:
            adm.admit("x", svid=local_svid, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "federation-untrusted-domain")

    def test_federated_route_missing_control_refuses_at_declare(self):
        with self.assertRaises(sv.SvidError) as ctx:
            self.ma.MeshAdmission({"x": {"require": "federated"}},
                                  self.mesh_control)
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_wrong_control_type_refuses(self):
        with self.assertRaises(sv.SvidError):
            self.ma.MeshAdmission({"x": {"require": "federated"}},
                                  self.mesh_control,
                                  federated_control=object())

    def test_existing_modes_unaffected(self):
        adm = self.ma.MeshAdmission({"s": {"require": "svid"}},
                                    self.mesh_control)
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("s", svid=None, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-missing")


if __name__ == "__main__":
    unittest.main()
