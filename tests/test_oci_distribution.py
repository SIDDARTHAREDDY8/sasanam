#!/usr/bin/env python3
"""Unit tests for gov/oci_distribution (wave-321 lane 2).

Pure-function and contract tests. The HTTP-surface behavior (fake
registry, tamper, fallback) is covered by evals/w321_oci_probes.py.
"""

import hashlib
import json
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import oci_distribution as oci  # noqa: E402
from gov import decision_codes as dc  # noqa: E402


class TestDigestAndCanonical(unittest.TestCase):
    def test_digest_of_format(self):
        d = oci.digest_of(b"abc")
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(d, "sha256:" + hashlib.sha256(b"abc").hexdigest())

    def test_digest_of_rejects_non_bytes(self):
        with self.assertRaises(TypeError):
            oci.digest_of("abc")

    def test_canonical_json_sorted_and_compact(self):
        b = oci.canonical_json({"z": 1, "a": [3, 2]})
        self.assertEqual(b, b'{"a":[3,2],"z":1}')
        self.assertEqual(oci.canonical_json({"b": 1, "a": 2}),
                         oci.canonical_json({"a": 2, "b": 1}))


class TestManifestBuilder(unittest.TestCase):
    def test_subject_is_evidence_digest(self):
        ev = b'{"evidence": 1}'
        mbytes, mdgst = oci.build_evidence_manifest(ev)
        doc = json.loads(mbytes.decode("utf-8"))
        self.assertEqual(doc["subject"]["digest"], oci.digest_of(ev))
        self.assertEqual(doc["schemaVersion"], 2)
        self.assertEqual(doc["artifactType"], oci.EVIDENCE_ARTIFACT_TYPE)
        self.assertEqual(mdgst, oci.digest_of(mbytes))

    def test_deterministic_twice(self):
        ev = b"same-evidence"
        m1, d1 = oci.build_evidence_manifest(ev, annotations={"k": "v"})
        m2, d2 = oci.build_evidence_manifest(ev, annotations={"k": "v"})
        self.assertEqual(m1, m2)
        self.assertEqual(d1, d2)

    def test_annotation_order_irrelevant(self):
        ev = b"same-evidence"
        _, d1 = oci.build_evidence_manifest(ev,
                                            annotations={"z": "1", "a": "2"})
        _, d2 = oci.build_evidence_manifest(ev,
                                            annotations={"a": "2", "z": "1"})
        self.assertEqual(d1, d2)

    def test_no_nondeterministic_fields(self):
        mbytes, _ = oci.build_evidence_manifest(b"x")
        low = mbytes.decode("utf-8").lower()
        for needle in ("created", "timestamp"):
            self.assertNotIn(needle, low)

    def test_annotations_must_be_str_dict(self):
        with self.assertRaises(TypeError):
            oci.build_evidence_manifest(b"x", annotations={"k": 1})

    def test_evidence_must_be_bytes(self):
        with self.assertRaises(TypeError):
            oci.build_evidence_manifest("not-bytes")


class TestParseManifest(unittest.TestCase):
    def _good(self):
        mbytes, _ = oci.build_evidence_manifest(b"ev")
        return mbytes

    def test_roundtrip(self):
        doc = oci.parse_manifest(self._good())
        self.assertEqual(doc["schemaVersion"], 2)

    def test_not_json(self):
        with self.assertRaises(oci.OCIRefusal) as c:
            oci.parse_manifest(b"not json{")
        self.assertEqual(c.exception.code, "oci-manifest-malformed")

    def test_missing_subject(self):
        doc = json.loads(self._good().decode("utf-8"))
        del doc["subject"]
        with self.assertRaises(oci.OCIRefusal) as c:
            oci.parse_manifest(json.dumps(doc).encode())
        self.assertEqual(c.exception.code, "oci-manifest-malformed")

    def test_bad_subject_digest(self):
        doc = json.loads(self._good().decode("utf-8"))
        doc["subject"]["digest"] = "nope"
        with self.assertRaises(oci.OCIRefusal) as c:
            oci.parse_manifest(json.dumps(doc).encode())
        self.assertEqual(c.exception.code, "oci-manifest-malformed")


class TestFallbackTag(unittest.TestCase):
    def test_shape(self):
        dgst = oci.digest_of(b"x")
        tag = oci.fallback_tag_for(dgst)
        self.assertEqual(tag, "sha256-" + dgst.split(":")[1] + ".sig")

    def test_malformed_digest(self):
        with self.assertRaises(ValueError):
            oci.fallback_tag_for("bogus")


class TestClientConstruction(unittest.TestCase):
    def test_malformed_repository(self):
        with self.assertRaises(ValueError):
            oci.OCIRegistryClient("http://x", "/leading-slash")
        with self.assertRaises(ValueError):
            oci.OCIRegistryClient("http://x", "a/../b")

    def test_malformed_subject_digest(self):
        c = oci.OCIRegistryClient("http://127.0.0.1:9", "r")
        with self.assertRaises(ValueError):
            c.discover_referrers("bogus")

    def test_refusal_carries_code(self):
        r = oci.OCIRefusal("oci-blob-digest-mismatch", "detail")
        self.assertEqual(r.code, "oci-blob-digest-mismatch")
        self.assertIn("oci-blob-digest-mismatch", str(r))


class TestDecisionCodes(unittest.TestCase):
    def test_oci_codes_registered(self):
        for code in ("oci-artifact-type-mismatch",
                     "oci-blob-digest-mismatch",
                     "oci-manifest-malformed",
                     "oci-referrers-unavailable",
                     "oci-subject-mismatch"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["code"], code)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "oci")


class TestPayloadVerifierHook(unittest.TestCase):
    """The optional payload_verifier hook chains payload-authenticity
    checks (e.g. DSSE/Sigstore) without this module inventing key
    authority. Transport-integrity refusals fire regardless."""

    def _stubbed_client(self, ev):
        mbytes, _ = oci.build_evidence_manifest(ev)
        c = oci.OCIRegistryClient("http://127.0.0.1:9", "repo")
        c.discover_referrers = (
            lambda dgst: ([{"digest": oci.digest_of(mbytes)}],
                          "referrers-api"))
        c.get_manifest = lambda ref: mbytes
        c.get_blob = lambda dgst: ev
        return c

    def test_verifier_called_with_evidence_bytes(self):
        ev = b'{"evidence":"hook"}'
        c = self._stubbed_client(ev)
        seen = []
        out = c.pull_and_verify(oci.digest_of(ev),
                                payload_verifier=seen.append)
        self.assertEqual(out, ev)
        self.assertEqual(seen, [ev])

    def test_verifier_refusal_propagates(self):
        def refusing(payload):
            raise oci.OCIRefusal("sigstore-bundle-invalid",
                                 "hook refusal")

        ev = b'{"evidence":"hook"}'
        c = self._stubbed_client(ev)
        with self.assertRaises(oci.OCIRefusal) as ctx:
            c.pull_and_verify(oci.digest_of(ev),
                              payload_verifier=refusing)
        self.assertEqual(ctx.exception.code, "sigstore-bundle-invalid")

    def test_hook_defaults_to_none(self):
        import inspect
        sig = inspect.signature(oci.OCIRegistryClient.pull_and_verify)
        self.assertIsNone(
            sig.parameters["payload_verifier"].default)


if __name__ == "__main__":
    unittest.main()
