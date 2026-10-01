"""Unit tests for gov.mesh_admission (wave-260 lane 3, identity-mesh).

Dual-seam mesh admission: kernel-attested OR SVID-verified peer
identity over a deployment-owned route table, with NO downgrade
between the seams. Composition is pinned: the kernel seam defers to
gov/attested_channel.ChannelAdmission, the SVID seam to
gov/svid_issuer.MeshControl.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import attested_channel as ac
from gov import decision_codes as dc
from gov import ed25519 as ed
from gov import mesh_admission as ma
from gov import svid_issuer as sv

_SEED = bytes(range(32))
_OTHER_SEED = bytes([255 - b for b in range(32)])
_PUBKEY = "ab" * 32
_TD = "example.org"
NOW = 1700000000.0


def _issuer(seed=_SEED, key_id="test-issuer-1"):
    return sv.TestSvidIssuer(issuer_seed=seed, key_id=key_id)


def _control(key_id="test-issuer-1",
             allow=("spiffe://example.org/agent",)):
    verifier = sv.SvidVerifier({key_id: ed.publickey(_SEED)},
                               trust_domain=_TD)
    return sv.MeshControl(verifier, {"allow": list(allow)})


def _routes(**kw):
    return kw


def _admission(routes, control=None, channel=None):
    kw = {}
    if channel is not None:
        kw["channel"] = channel
    return ma.MeshAdmission(routes, control or _control(), **kw)


def _svid(issuer=None, spiffe_id="spiffe://example.org/agent/a"):
    iss = issuer or _issuer()
    return iss.issue(spiffe_id, _PUBKEY, ttl_minutes=5, now=NOW)


def _bad_svid():
    rogue = _issuer(seed=_OTHER_SEED)
    return _svid(issuer=rogue)


def _kernel(**over):
    base = {
        "peer_identity": {"uid": 1000, "gid": 1000, "pid": 4242,
                          "exe": "/usr/bin/agent"},
        "emitter_claim": {"principal": "agent-1", "ts_emit": NOW,
                          "seq": 0, "payload": {"op": "ping"}},
        "key_location": "daemon",
    }
    base.update(over)
    return base


class RouteTableTest(unittest.TestCase):
    def test_empty_routes_refused(self):
        with self.assertRaises(sv.SvidError) as ctx:
            ma.MeshAdmission({}, _control())
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_bad_require_value_refused(self):
        with self.assertRaises(sv.SvidError) as ctx:
            ma.MeshAdmission({"r": {"require": "password"}}, _control())
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_non_dict_rule_refused(self):
        with self.assertRaises(sv.SvidError) as ctx:
            ma.MeshAdmission({"r": "svid"}, _control())
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_bad_mesh_control_refused(self):
        with self.assertRaises(sv.SvidError) as ctx:
            ma.MeshAdmission({"r": {"require": "svid"}}, object())
        self.assertEqual(ctx.exception.code, "svid-malformed")

    def test_routes_property_is_copy(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        routes = adm.routes
        routes["evil"] = {"require": "kernel"}
        self.assertNotIn("evil", adm.routes)


class SvidSeamTest(unittest.TestCase):
    def test_missing_svid_refused_not_rerouted(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("ctl", svid=None, kernel=_kernel(), now=NOW)
        self.assertEqual(ctx.exception.code, "svid-missing")

    def test_bad_svid_never_falls_through_to_kernel(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("ctl", svid=_bad_svid(), kernel=_kernel(), now=NOW)
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")

    def test_valid_svid_admits_on_svid_seam(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        rec = adm.admit("ctl", svid=_svid(), kernel=_kernel(), now=NOW)
        self.assertEqual(rec["mode"], "svid")
        self.assertEqual(rec["spiffe_id"],
                         "spiffe://example.org/agent/a")
        self.assertEqual(rec["route"], "ctl")

    def test_valid_svid_outside_acl_denied(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        other = _svid(spiffe_id="spiffe://example.org/other/x")
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("ctl", svid=other, kernel=None, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")

    def test_expired_svid_refused(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("ctl", svid=_svid(), kernel=None, now=NOW + 400)
        self.assertEqual(ctx.exception.code, "svid-expired")


class KernelSeamTest(unittest.TestCase):
    def test_no_kernel_identity_refused(self):
        adm = _admission(_routes(data={"require": "kernel"}))
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit("data", svid=_svid(), kernel=None, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "channel-identity-unattested")

    def test_valid_kernel_admits_on_kernel_seam(self):
        adm = _admission(_routes(data={"require": "kernel"}))
        rec = adm.admit("data", svid=None, kernel=_kernel(), now=NOW)
        self.assertEqual(rec["mode"], "kernel")
        self.assertEqual(rec["principal"], "agent-1")
        self.assertEqual(rec["peer_identity"]["uid"], 1000)

    def test_svid_ignored_on_kernel_route(self):
        # A forged SVID riding along cannot influence the kernel seam:
        # it is never evaluated, and a valid kernel peer still admits.
        adm = _admission(_routes(data={"require": "kernel"}))
        rec = adm.admit("data", svid=_bad_svid(), kernel=_kernel(),
                        now=NOW)
        self.assertEqual(rec["mode"], "kernel")

    def test_malformed_kernel_defers_to_channel_vocabulary(self):
        adm = _admission(_routes(data={"require": "kernel"}))
        bad = _kernel(peer_identity={"uid": 1})  # missing fields
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit("data", svid=None, kernel=bad, now=NOW)
        self.assertEqual(ctx.exception.code, "channel-record-malformed")


class EitherSeamTest(unittest.TestCase):
    def test_bad_svid_plus_kernel_refuses_svid_code(self):
        adm = _admission(_routes(mgmt={"require": "either"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("mgmt", svid=_bad_svid(), kernel=_kernel(),
                      now=NOW)
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")

    def test_kernel_only_admits_kernel(self):
        adm = _admission(_routes(mgmt={"require": "either"}))
        rec = adm.admit("mgmt", svid=None, kernel=_kernel(), now=NOW)
        self.assertEqual(rec["mode"], "kernel")

    def test_svid_only_admits_svid(self):
        adm = _admission(_routes(mgmt={"require": "either"}))
        rec = adm.admit("mgmt", svid=_svid(), kernel=None, now=NOW)
        self.assertEqual(rec["mode"], "svid")

    def test_neither_present_refused_outright(self):
        adm = _admission(_routes(mgmt={"require": "either"}))
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit("mgmt", svid=None, kernel=None, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "channel-identity-unattested")

    def test_bad_svid_alone_refuses(self):
        adm = _admission(_routes(mgmt={"require": "either"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("mgmt", svid=_bad_svid(), kernel=None, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-signature-invalid")


class PolicyRefusalTest(unittest.TestCase):
    def test_unknown_route_default_deny(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("nope", svid=_svid(), kernel=None, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")

    def test_non_string_route_default_deny(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit(None, svid=_svid(), kernel=None, now=NOW)
        self.assertEqual(ctx.exception.code, "svid-acl-denied")

    def test_bool_now_refused_f224(self):
        adm = _admission(_routes(ctl={"require": "svid"}))
        with self.assertRaises(sv.SvidError) as ctx:
            adm.admit("ctl", svid=_svid(), kernel=None, now=True)
        self.assertEqual(ctx.exception.code, "svid-malformed")


class CodeRegistrationTest(unittest.TestCase):
    def test_mesh_admission_codes_in_taxonomy(self):
        for code in ("svid-missing", "svid-acl-denied", "svid-malformed"):
            self.assertIn(code, dc.TAXONOMY)

    def test_require_constants(self):
        self.assertEqual(
            {ma.REQUIRE_SVID, ma.REQUIRE_KERNEL, ma.REQUIRE_EITHER},
            {"svid", "kernel", "either"})


if __name__ == "__main__":
    unittest.main()
