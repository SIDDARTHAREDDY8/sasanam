#!/usr/bin/env python3
"""Unit tests for gov/oci_referrer.py (wave-338 lane 4, R17).

Offline: all registry interaction goes through an in-memory
MockRegistryTransport implementing the caller-supplied transport
protocol. Covers: attach/discover/pull round-trip (byte-identical),
digest-only refusals, subject-binding refusals, missing-Referrers-API
fail-closed (no tag fallback), tampered-layer refusals, predicate-type
annotation extraction, the Harbor direct-push-only caveat (replica gap +
registry badge never trusted), and no-implicit-I/O.
"""

import base64
import hashlib
import inspect
import json
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import oci_referrer as OR
from gov import sigstore_bundle as SB
from gov import evidence_intoto as _intoto
from gov import decision_codes as DC
from gov.signing import Ed25519Signer

TAXONOMY_PIN = 2127  # Wave-339 lane 3: pin 2126 -> 2127 (+1 oci-registry-onboarding-refused)

_SEED = bytes(range(32))
_SIGNER = Ed25519Signer(_SEED)
_PUB = _SIGNER.public_key

BASE = "https://registry.example"
REPO = "sasanam/evidence"


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class MockRegistryTransport(object):
    """In-memory OCI registry speaking the transport protocol.

    ``referrers_api=False`` simulates a registry (or Harbor replica)
    without the Referrers API: the endpoint 404s. Every request is
    logged in ``self.requests``.
    """

    def __init__(self, *, referrers_api=True, badge=None):
        self.blobs = {}
        self.manifests = {}
        self.referrers_api = referrers_api
        self.badge = badge  # extra annotations stamped on index entries
        self.requests = []

    def __call__(self, request):
        method = request["method"]
        url = request["url"]
        body = request.get("body") or b""
        self.requests.append((method, url))
        parts = urllib.parse.urlparse(url)
        path = parts.path
        query = urllib.parse.parse_qs(parts.query)
        prefix = "/v2/" + REPO + "/"
        assert path.startswith(prefix), path
        rest = path[len(prefix):]

        if method == "POST" and rest == "blobs/uploads/":
            loc = prefix + "blobs/uploads/session-1"
            return (202, {"location": loc}, b"")
        if method == "PUT" and rest.startswith("blobs/uploads/"):
            dgst = query.get("digest", [None])[0]
            assert dgst and dgst.startswith("sha256:"), query
            self.blobs[dgst] = bytes(body)
            return (201, {"docker-content-digest": dgst}, b"")
        if method == "PUT" and rest.startswith("manifests/"):
            dgst = rest[len("manifests/"):]
            self.manifests[dgst] = bytes(body)
            return (201, {"docker-content-digest": dgst}, b"")
        if method == "GET" and rest.startswith("referrers/"):
            if not self.referrers_api:
                return (404, {}, b'{"errors":[{"code":"NOT_FOUND"}]}')
            subject = rest[len("referrers/"):]
            entries = []
            for dgst, mbytes in self.manifests.items():
                try:
                    man = json.loads(mbytes.decode("utf-8"))
                except ValueError:
                    continue
                subj = man.get("subject") or {}
                if subj.get("digest") != subject:
                    continue
                entry = {"mediaType": man.get("mediaType"),
                         "digest": dgst,
                         "size": len(mbytes),
                         "artifactType": man.get("artifactType"),
                         "subject": subj,
                         "annotations": dict(man.get("annotations") or {})}
                if self.badge:
                    entry["annotations"].update(self.badge)
                entries.append(entry)
            index = {"schemaVersion": 2,
                     "mediaType": OR.OCI_INDEX_MEDIA_TYPE,
                     "referrers": entries}
            return (200, {"content-type": OR.OCI_INDEX_MEDIA_TYPE},
                    json.dumps(index).encode("utf-8"))
        if method == "GET" and rest.startswith("manifests/"):
            dgst = rest[len("manifests/"):]
            if dgst in self.manifests:
                return (200, {"content-type": OR.OCI_MANIFEST_MEDIA_TYPE},
                        self.manifests[dgst])
            return (404, {}, b"")
        if method == "GET" and rest.startswith("blobs/"):
            dgst = rest[len("blobs/"):]
            if dgst in self.blobs:
                return (200, {"content-type": "application/octet-stream"},
                        self.blobs[dgst])
            return (404, {}, b"")
        raise AssertionError("unexpected request: %s %s" % (method, url))

    def urls(self):
        return [u for _, u in self.requests]


def _sealed_bundle(predicate_claims=None):
    stmt = _intoto.build_statement(b'{"decision": "deny", "seq": 1}',
                                   predicate_claims or {"lane": "w338"})
    payload = _intoto.statement_bytes(stmt)
    bundle = SB.seal_keyed_bundle(payload, _SIGNER)
    return OR.canonical_json(bundle)


class OciReferrerTests(unittest.TestCase):
    def test_media_type_pinned_to_sigstore_bundle(self):
        self.assertEqual(OR.BUNDLE_LAYER_MEDIA_TYPE,
                         SB.SIGSTORE_BUNDLE_MEDIA_TYPE)
        self.assertEqual(OR.BUNDLE_ARTIFACT_TYPE,
                         SB.SIGSTORE_BUNDLE_MEDIA_TYPE)

    def test_taxonomy_pin_and_codes_registered(self):
        self.assertEqual(len(DC.TAXONOMY), TAXONOMY_PIN)
        for code in ("oci-tag-refused", "oci-layer-media-type-mismatch"):
            self.assertIn(code, DC.TAXONOMY)
            self.assertEqual(DC.TAXONOMY[code]["domain"], "oci")

    def test_no_implicit_io(self):
        # Source-level: the module must never import urllib.request at
        # module scope (no implicit network capability). The reference
        # transport imports it lazily, inside the function body.
        import ast
        tree = ast.parse(inspect.getsource(OR))
        # Module level only: the lazy import inside urllib_transport's
        # closure is the one permitted exception.
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(alias.name, "urllib.request")
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual(node.module, "urllib.request")

    def test_transport_none_is_type_error_not_network(self):
        bundle = _sealed_bundle()
        subject = _digest(b"subject")
        with self.assertRaises(TypeError):
            OR.attach_keyed_bundle(None, BASE, REPO, subject, bundle)

    def test_attach_discover_pull_roundtrip_byte_identical(self):
        t = MockRegistryTransport()
        bundle = _sealed_bundle()
        subject = _digest(b"the-evidence-subject")
        res = OR.attach_keyed_bundle(t, BASE, REPO, subject, bundle)
        self.assertEqual(res["subject_digest"], subject)
        self.assertEqual(res["bundle_digest"], _digest(bundle))
        self.assertEqual(res["predicate_type"],
                         _intoto.SASANAM_EVIDENCE_PREDICATE_TYPE)
        found = OR.discover_keyed_bundles(t, BASE, REPO, subject)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["digest"], res["manifest_digest"])
        pulled = OR.pull_keyed_bundle(t, BASE, REPO, found[0], subject)
        self.assertEqual(pulled, bundle)
        self.assertTrue(SB.verify_keyed_bundle(json.loads(pulled.decode("utf-8")), _PUB))

    def test_explicit_predicate_type_overrides_extraction(self):
        t = MockRegistryTransport()
        bundle = _sealed_bundle()
        subject = _digest(b"s2")
        res = OR.attach_keyed_bundle(t, BASE, REPO, subject, bundle,
                                     predicate_type="custom.example/v1")
        self.assertEqual(res["predicate_type"], "custom.example/v1")
        man = json.loads(t.manifests[res["manifest_digest"]].decode())
        self.assertEqual(
            man["annotations"][OR.PREDICATE_TYPE_ANNOTATION],
            "custom.example/v1")

    def test_tag_refused_everywhere(self):
        t = MockRegistryTransport()
        bundle = _sealed_bundle()
        for fn in (lambda: OR.attach_keyed_bundle(t, BASE, REPO, "latest",
                                                  bundle),
                   lambda: OR.discover_keyed_bundles(t, BASE, REPO,
                                                     "v1.0"),
                   lambda: OR.pull_keyed_bundle(t, BASE, REPO,
                                                {"digest": "latest"},
                                                _digest(b"x"))):
            with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
                fn()
            self.assertEqual(ctx.exception.code, "oci-tag-refused")

    def test_subject_mismatch_refuses_on_discovery(self):
        doc = {"schemaVersion": 2, "mediaType": OR.OCI_INDEX_MEDIA_TYPE,
               "referrers": [
                   {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                    "digest": _digest(b"m"),
                    "size": 3,
                    "artifactType": OR.BUNDLE_ARTIFACT_TYPE,
                    "subject": {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                                "digest": _digest(b"OTHER-SUBJECT")}}]}
        with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
            OR.verify_referrer_binding(doc, _digest(b"queried"))
        self.assertEqual(ctx.exception.code, "oci-subject-mismatch")

    def test_subject_mismatch_refuses_on_pull(self):
        t = MockRegistryTransport()
        bundle = _sealed_bundle()
        subject = _digest(b"real-subject")
        res = OR.attach_keyed_bundle(t, BASE, REPO, subject, bundle)
        found = OR.discover_keyed_bundles(t, BASE, REPO, subject)
        with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
            OR.pull_keyed_bundle(t, BASE, REPO, found[0],
                                 _digest(b"wrong-subject"))
        self.assertEqual(ctx.exception.code, "oci-subject-mismatch")

    def test_missing_referrers_api_fails_closed_no_tag_fallback(self):
        t = MockRegistryTransport(referrers_api=False)
        subject = _digest(b"s3")
        with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
            OR.discover_keyed_bundles(t, BASE, REPO, subject)
        self.assertEqual(ctx.exception.code, "oci-referrers-unavailable")
        for url in t.urls():
            self.assertNotIn("/tags/", url,
                             "tag-scheme fallback attempted: %s" % url)

    def test_tampered_blob_refuses(self):
        t = MockRegistryTransport()
        bundle = _sealed_bundle()
        subject = _digest(b"s4")
        res = OR.attach_keyed_bundle(t, BASE, REPO, subject, bundle)
        found = OR.discover_keyed_bundles(t, BASE, REPO, subject)
        t.blobs[res["bundle_digest"]] = b'{"tampered": true}'
        with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
            OR.pull_keyed_bundle(t, BASE, REPO, found[0], subject)
        self.assertEqual(ctx.exception.code, "oci-blob-digest-mismatch")

    def test_tampered_manifest_refuses(self):
        t = MockRegistryTransport()
        bundle = _sealed_bundle()
        subject = _digest(b"s5")
        res = OR.attach_keyed_bundle(t, BASE, REPO, subject, bundle)
        found = OR.discover_keyed_bundles(t, BASE, REPO, subject)
        t.manifests[res["manifest_digest"]] = b'{"schemaVersion": 2}'
        with self.assertRaises(OR.OCIReferrerRefusal):
            OR.pull_keyed_bundle(t, BASE, REPO, found[0], subject)

    def test_non_bundle_content_refused_at_attach(self):
        t = MockRegistryTransport()
        subject = _digest(b"s6")
        for bad in (b"not-json",
                    OR.canonical_json({"mediaType": "application/json"}),
                    OR.canonical_json({"mediaType":
                                       OR.BUNDLE_LAYER_MEDIA_TYPE[:-1]})):
            with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
                OR.attach_keyed_bundle(t, BASE, REPO, subject, bad)
            self.assertEqual(ctx.exception.code,
                             "oci-layer-media-type-mismatch")

    def test_wrong_layer_media_type_refuses_on_pull(self):
        t = MockRegistryTransport()
        bundle = _sealed_bundle()
        subject = _digest(b"s7")
        res = OR.attach_keyed_bundle(t, BASE, REPO, subject, bundle)
        man = json.loads(t.manifests[res["manifest_digest"]].decode())
        man["layers"][0]["mediaType"] = "application/octet-stream"
        mbytes = OR.canonical_json(man)
        # Re-store under a fresh digest so the manifest fetch itself
        # verifies; only the layer media type is wrong.
        new_digest = _digest(mbytes)
        t.manifests[new_digest] = mbytes
        desc = {"digest": new_digest, "mediaType":
                OR.OCI_MANIFEST_MEDIA_TYPE, "size": len(mbytes)}
        with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
            OR.pull_keyed_bundle(t, BASE, REPO, desc, subject)
        self.assertEqual(ctx.exception.code,
                         "oci-layer-media-type-mismatch")

    def test_harbor_replica_gap_fails_closed(self):
        # Harbor Replication Service ignores referrer manifests: a replica
        # has the blobs but no referrers index. Direct-push only.
        origin = MockRegistryTransport()
        bundle = _sealed_bundle()
        subject = _digest(b"s8")
        OR.attach_keyed_bundle(origin, BASE, REPO, subject, bundle)
        replica = MockRegistryTransport(referrers_api=False)
        replica.blobs = dict(origin.blobs)  # blobs replicate; referrers don't
        with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
            OR.discover_keyed_bundles(replica, BASE, REPO, subject)
        self.assertEqual(ctx.exception.code, "oci-referrers-unavailable")

    def test_registry_badge_never_trusted(self):
        # A "verified: true" badge on a tampered bundle still refuses...
        t = MockRegistryTransport(badge={"verified": "true"})
        bundle = _sealed_bundle()
        subject = _digest(b"s9")
        res = OR.attach_keyed_bundle(t, BASE, REPO, subject, bundle)
        found = OR.discover_keyed_bundles(t, BASE, REPO, subject)
        t.blobs[res["bundle_digest"]] = b"tampered"
        with self.assertRaises(OR.OCIReferrerRefusal):
            OR.pull_keyed_bundle(t, BASE, REPO, found[0], subject)
        # ...and a "verified: false" badge on a good bundle still passes
        # transport checks (verdicts come from digests, not badges).
        t2 = MockRegistryTransport(badge={"verified": "false"})
        res2 = OR.attach_keyed_bundle(t2, BASE, REPO, subject, bundle)
        found2 = OR.discover_keyed_bundles(t2, BASE, REPO, subject)
        pulled = OR.pull_keyed_bundle(t2, BASE, REPO, found2[0], subject)
        self.assertEqual(pulled, bundle)
        self.assertTrue(SB.verify_keyed_bundle(json.loads(pulled.decode("utf-8")), _PUB))

    def test_malformed_referrers_index_refuses(self):
        for bad in (b"not-json", b"[]",
                    OR.canonical_json({"referrers": {}})):
            with self.assertRaises(OR.OCIReferrerRefusal) as ctx:
                OR.verify_referrer_binding(bad, _digest(b"s"))
            self.assertEqual(ctx.exception.code, "oci-referrers-malformed")

    def test_missing_artifacttype_is_nonmatch_not_error(self):
        # Wave-339 (R25) pin: cosign v3.1.2 fixed missing `artifactType`
        # in referrer manifests; older artifacts may lack it. Discovery
        # treats a referrer entry with a missing (or wrong) artifactType
        # as a NON-MATCH -- silently skipped -- never as a match and
        # never as an error. Pinning this so a future "improvement" that
        # matches typeless entries cannot silently adopt foreign
        # artifacts as evidence bundles.
        subject = _digest(b"s5")
        doc = {"schemaVersion": 2, "mediaType": OR.OCI_INDEX_MEDIA_TYPE,
               "referrers": [
                   {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                    "digest": _digest(b"no-artifact-type"),
                    "size": 5,
                    "subject": {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                                "digest": subject}},
                   {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                    "digest": _digest(b"wrong-artifact-type"),
                    "size": 5,
                    "artifactType": "application/vnd.example.other+json",
                    "subject": {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                                "digest": subject}},
                   {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                    "digest": _digest(b"right-artifact-type"),
                    "size": 5,
                    "artifactType": OR.BUNDLE_ARTIFACT_TYPE,
                    "subject": {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                                "digest": subject}}]}
        selected = OR.verify_referrer_binding(doc, subject)
        self.assertEqual([e["digest"] for e in selected],
                         [_digest(b"right-artifact-type")])
        # All-typeless index: no match, no error, no refusal -- "no
        # bundles attached" is a legitimate answer.
        doc2 = {"schemaVersion": 2, "mediaType": OR.OCI_INDEX_MEDIA_TYPE,
                "referrers": [
                    {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                     "digest": _digest(b"typeless"),
                     "size": 5,
                     "subject": {"mediaType": OR.OCI_MANIFEST_MEDIA_TYPE,
                                 "digest": subject}}]}
        self.assertEqual(OR.verify_referrer_binding(doc2, subject), [])


if __name__ == "__main__":
    unittest.main()
