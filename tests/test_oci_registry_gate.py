#!/usr/bin/env python3
"""Unit tests for gov/oci_registry_gate.py (wave-339 lane 3, R25).

All transports are in-memory mocks -- this module certifies distribution
paths; no test here touches the network. See evals/w339_oci_gate_probes.py
for the break-battery counterpart.
"""

import json
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2131  # Wave-339 lane 3: pin 2126 -> 2127 (+1 oci-registry-onboarding-refused); Wave-339 merge: pin 2128 -> 2130 (+4 codes: oci-bundle-not-verifiable, witness-policy-dual-threshold-unmet, witness-daemon-state-failed, oci-registry-onboarding-refused); Wave-340 lane 3: pin 2130 -> 2131 (+1 deadctrl-subject-mutated).

from gov import decision_codes as DC
from gov import oci_registry_gate as G


def _mock_transport(status, body=b"{}", record=None):
    def send(request):
        if record is not None:
            record.append(request)
        return (status, {"content-type": "application/json"},
                body if isinstance(body, bytes) else body.encode())
    return send


def _index_doc(n=0):
    return json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "referrers": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "digest": "sha256:%064x" % i, "size": 1}
                      for i in range(n)],
    }).encode()


class TestProbe(unittest.TestCase):
    def test_200_empty_index_supported(self):
        reqs = []
        r, detail = G.probe_referrers_api(
            _mock_transport(200, _index_doc(0), reqs),
            "https://zot.example", "evidence")
        self.assertEqual(r, "supported")
        self.assertIn("referrers", reqs[0]["url"])

    def test_404_unsupported(self):
        r, _ = G.probe_referrers_api(_mock_transport(404),
                                     "https://ghcr.io", "evidence")
        self.assertEqual(r, "unsupported")

    def test_400_unsupported(self):
        r, _ = G.probe_referrers_api(_mock_transport(400),
                                     "https://x.example", "evidence")
        self.assertEqual(r, "unsupported")

    def test_401_inconclusive_not_unsupported(self):
        # Auth-required is never misread as "no Referrers API".
        r, detail = G.probe_referrers_api(_mock_transport(401),
                                          "https://x.example", "evidence")
        self.assertEqual(r, "inconclusive")
        self.assertIn("401", detail)

    def test_500_inconclusive(self):
        r, _ = G.probe_referrers_api(_mock_transport(500),
                                     "https://x.example", "evidence")
        self.assertEqual(r, "inconclusive")

    def test_200_non_json_inconclusive(self):
        r, _ = G.probe_referrers_api(_mock_transport(200, b"not-json"),
                                     "https://x.example", "evidence")
        self.assertEqual(r, "inconclusive")

    def test_200_missing_referrers_list_inconclusive(self):
        r, _ = G.probe_referrers_api(_mock_transport(200, b'{"a":1}'),
                                     "https://x.example", "evidence")
        self.assertEqual(r, "inconclusive")

    def test_transport_failure_inconclusive(self):
        def boom(request):
            raise ConnectionError("down")
        r, _ = G.probe_referrers_api(boom, "https://x.example", "evidence")
        self.assertEqual(r, "inconclusive")

    def test_no_implicit_io(self):
        # The gate must never dial on its own: a transport that records
        # and a transport of None both behave -- None is a TypeError,
        # never a socket.
        with self.assertRaises(TypeError):
            G.probe_referrers_api(None, "https://x.example", "evidence")


class TestOnboard(unittest.TestCase):
    def _onboard(self, kind, status, body=None, path="push", **kw):
        body = _index_doc(0) if body is None else body
        return G.onboard_registry(_mock_transport(status, body),
                                  "https://reg.example", "evidence",
                                  registry_kind=kind,
                                  distribution_path=path, **kw)

    def test_zot_200_certified_in(self):
        v = self._onboard("zot", 200)
        self.assertEqual(v["verdict"], "certified-in")
        self.assertIsNone(v["code"])

    def test_harbor_push_certified_in(self):
        v = self._onboard("harbor", 200, path="push")
        self.assertEqual(v["verdict"], "certified-in")

    def test_harbor_replication_refused(self):
        # The whole point of the Harbor special rule: the Replication
        # Service silently drops referrer manifests (#23210).
        v = self._onboard("harbor", 200, path="replication")
        self.assertEqual(v["verdict"], "refused")
        self.assertEqual(v["code"], G.ONBOARDING_REFUSED_CODE)

    def test_harbor_replication_refused_even_when_probe_fails(self):
        # The path rule applies regardless of the live probe: a Harbor
        # replica read is OUT even if the endpoint answers.
        v = self._onboard("harbor", 404, path="replication")
        self.assertEqual(v["verdict"], "refused")
        self.assertEqual(v["code"], G.ONBOARDING_REFUSED_CODE)

    def test_ghcr_404_refused_expected_out(self):
        v = self._onboard("ghcr", 404)
        self.assertEqual(v["verdict"], "refused")
        self.assertEqual(v["code"], G.ONBOARDING_REFUSED_CODE)
        self.assertIn("no Referrers API", v["detail"])

    def test_zot_404_refused_regression(self):
        # Matrix says IN but the probe found no API: regressed or moved.
        v = self._onboard("zot", 404)
        self.assertEqual(v["verdict"], "refused")
        self.assertIn("re-probe", v["detail"])

    def test_ghcr_200_refused_matrix_disagrees(self):
        # A live 200 from a matrix-OUT host is refused: spoofed probe or
        # unrecorded upgrade -- fail closed, do not certify.
        v = self._onboard("ghcr", 200)
        self.assertEqual(v["verdict"], "refused")
        self.assertEqual(v["code"], G.ONBOARDING_REFUSED_CODE)

    def test_500_refused_inconclusive(self):
        v = self._onboard("zot", 500)
        self.assertEqual(v["verdict"], "refused")
        self.assertIn("OUT until verified", v["detail"])

    def test_unknown_kind_refused(self):
        v = self._onboard("mystery-registry", 200)
        self.assertEqual(v["verdict"], "refused")
        self.assertIn("not in the trust matrix", v["detail"])

    def test_matrix_override_records_private_registry(self):
        v = self._onboard(
            "private-zot", 200,
            matrix_override={"private-zot": {
                "status": "in",
                "notes": "deployment's own Zot, probed 2026-10-05",
                "probed": "2026-10-05"}})
        self.assertEqual(v["verdict"], "certified-in")

    def test_matrix_override_cannot_flip_out_to_in(self):
        # A deployment annotation cannot overrule the research matrix for
        # known-hostile paths.
        v = self._onboard(
            "ghcr", 200,
            matrix_override={"ghcr": {"status": "in", "notes": "no"}})
        self.assertEqual(v["verdict"], "refused")
        self.assertIn("matrix marks", v["detail"])

    def test_docker_hub_certified_in(self):
        v = self._onboard("docker-hub", 200)
        self.assertEqual(v["verdict"], "certified-in")

    def test_acr_cmk_refused(self):
        v = self._onboard("acr-cmk", 200)
        self.assertEqual(v["verdict"], "refused")

    def test_cncf_distribution_refused(self):
        v = self._onboard("cncf-distribution", 404)
        self.assertEqual(v["verdict"], "refused")


class TestSameRepository(unittest.TestCase):
    def test_same_pair_ok(self):
        self.assertTrue(G.check_same_repository(
            "https://zot.example/", "evidence",
            "https://zot.example", "evidence"))

    def test_different_repository_refuses(self):
        with self.assertRaises(G.OCIRegistryGateRefusal) as ctx:
            G.check_same_repository("https://zot.example", "evidence-a",
                                    "https://zot.example", "evidence-b")
        self.assertEqual(ctx.exception.code, G.ONBOARDING_REFUSED_CODE)

    def test_replica_host_refuses(self):
        # Reading from a Harbor replica is exactly the #23210 shape.
        with self.assertRaises(G.OCIRegistryGateRefusal) as ctx:
            G.check_same_repository("https://harbor.example", "evidence",
                                    "https://harbor-replica.example",
                                    "evidence")
        self.assertEqual(ctx.exception.code, G.ONBOARDING_REFUSED_CODE)


class TestRegistration(unittest.TestCase):
    def test_onboarding_code_registered(self):
        self.assertIn(G.ONBOARDING_REFUSED_CODE, DC.TAXONOMY)
        entry = DC.TAXONOMY[G.ONBOARDING_REFUSED_CODE]
        self.assertEqual(entry["domain"], "oci")
        self.assertEqual(len(DC.TAXONOMY), TAXONOMY_PIN)


if __name__ == "__main__":
    unittest.main()
