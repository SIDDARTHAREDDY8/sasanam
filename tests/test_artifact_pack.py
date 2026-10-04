"""Unit tests for gov/artifact_pack.py (W248-7 ORAS artifacts lane).

Lane-local taxonomy pin: 945 (938 + 7 artifact-pack codes), additive
only; merge coordinator recomposes.
"""

import copy
import json
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import artifact_pack as ap
from gov import decision_codes


def _blobs():
    return {
        "record-0000.json": b'{"seq": 0}',
        "policy.txt": b"deny\n",
    }


class PackBasicsTest(unittest.TestCase):
    def test_taxonomy_pin_945(self):
        # Wave-248 lane 7: re-pointed to 945 (938 + 7 artifact-pack codes), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 1946)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.

    def test_new_codes_registered(self):
        for code in ("artifact-blob-extra", "artifact-blob-missing",
                     "artifact-blob-tampered",
                     "artifact-manifest-malformed",
                     "artifact-manifest-tampered",
                     "artifact-size-mismatch", "artifact-type-unknown"):
            self.assertIn(code, decision_codes.TAXONOMY)

    def test_pack_returns_manifest_and_digest(self):
        manifest, digest = ap.pack(
            _blobs(), ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertEqual(
            manifest["artifactType"],
            ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        self.assertEqual(len(manifest["blobs"]), 2)
        self.assertTrue(digest.startswith("sha256:"))
        # entries sorted by name -> order-independent
        names = [e["name"] for e in manifest["blobs"]]
        self.assertEqual(names, sorted(names))

    def test_pack_unknown_type_refused(self):
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.pack(_blobs(), "application/vnd.evil.v9")
        self.assertEqual(ctx.exception.code, "artifact-type-unknown")

    def test_pack_rejects_non_bytes(self):
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.pack({"a.txt": "not-bytes"},
                    ap.ARTIFACT_TYPE_SKILL_BUNDLE)
        self.assertEqual(ctx.exception.code,
                         "artifact-manifest-malformed")

    def test_pack_rejects_bad_names(self):
        for bad in ("", "a\x00b", " not-clean ", "a/../b"):
            with self.assertRaises(ap.ArtifactPackError) as ctx:
                ap.pack({bad: b"x"},
                        ap.ARTIFACT_TYPE_SKILL_BUNDLE)
            self.assertEqual(ctx.exception.code,
                             "artifact-manifest-malformed")

    def test_pack_rejects_bad_annotations(self):
        with self.assertRaises(ap.ArtifactPackError):
            ap.pack(_blobs(), ap.ARTIFACT_TYPE_SKILL_BUNDLE,
                    annotations={"k": 123})

    def test_pack_rejects_media_type_for_unknown_blob(self):
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.pack(_blobs(), ap.ARTIFACT_TYPE_SKILL_BUNDLE,
                    media_types={"ghost.bin": "application/octet-stream"})
        self.assertEqual(ctx.exception.code,
                         "artifact-manifest-malformed")

    def test_error_carries_code_and_detail(self):
        try:
            ap.pack(_blobs(), "nope")
        except ap.ArtifactPackError as exc:
            self.assertEqual(exc.code, "artifact-type-unknown")
            self.assertIn("artifact-type-unknown", str(exc))
        else:
            self.fail("no error raised")


class VerifyTest(unittest.TestCase):
    def test_verify_ok_returns_true(self):
        blobs = _blobs()
        manifest, digest = ap.pack(
            blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        self.assertTrue(ap.verify(manifest, dict(blobs), digest))

    def test_unpack_returns_copy(self):
        blobs = _blobs()
        manifest, digest = ap.pack(
            blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        out = ap.unpack(manifest, dict(blobs), digest)
        self.assertEqual(out, blobs)
        self.assertIsNot(out, blobs)

    def test_tampered_blob(self):
        blobs = _blobs()
        manifest, digest = ap.pack(
            blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        evil = dict(blobs)
        evil["policy.txt"] = b"deny\r"  # same length, flipped byte
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(manifest, evil, digest)
        self.assertEqual(ctx.exception.code, "artifact-blob-tampered")

    def test_missing_blob(self):
        blobs = _blobs()
        manifest, digest = ap.pack(
            blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        fewer = dict(blobs)
        del fewer["policy.txt"]
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(manifest, fewer, digest)
        self.assertEqual(ctx.exception.code, "artifact-blob-missing")

    def test_extra_blob(self):
        blobs = _blobs()
        manifest, digest = ap.pack(
            blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        more = dict(blobs)
        more["extra.bin"] = b"x"
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(manifest, more, digest)
        self.assertEqual(ctx.exception.code, "artifact-blob-extra")

    def test_size_mismatch(self):
        blobs = _blobs()
        manifest, _ = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        lied = copy.deepcopy(manifest)
        lied["blobs"][0]["size"] += 10
        lied_digest = ap.manifest_digest(lied)
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(lied, dict(blobs), lied_digest)
        self.assertEqual(ctx.exception.code, "artifact-size-mismatch")

    def test_manifest_tampered(self):
        blobs = _blobs()
        manifest, digest = ap.pack(
            blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        tampered = copy.deepcopy(manifest)
        tampered["blobs"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(tampered, dict(blobs), digest)
        self.assertEqual(ctx.exception.code,
                         "artifact-manifest-tampered")

    def test_wrong_expected_digest(self):
        blobs = _blobs()
        manifest, _ = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(manifest, dict(blobs), "sha256:" + "0" * 64)
        self.assertEqual(ctx.exception.code,
                         "artifact-manifest-tampered")

    def test_unknown_artifact_type(self):
        blobs = _blobs()
        manifest, _ = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        evil = copy.deepcopy(manifest)
        evil["artifactType"] = "application/vnd.evil.v9"
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(evil, dict(blobs), ap.manifest_digest(evil))
        self.assertEqual(ctx.exception.code, "artifact-type-unknown")

    def test_malformed_manifest(self):
        blobs = _blobs()
        _, digest = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        for broken in ({"artifactType": "x"}, {"blobs": {}},
                       {"schemaVersion": 99, "mediaType": "m",
                        "artifactType":
                        ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE,
                        "blobs": [], "annotations": {}}):
            with self.assertRaises(ap.ArtifactPackError) as ctx:
                ap.verify(broken, dict(blobs), digest)
            self.assertEqual(ctx.exception.code,
                             "artifact-manifest-malformed")

    def test_duplicate_blob_entry(self):
        blobs = _blobs()
        manifest, _ = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        dup = copy.deepcopy(manifest)
        dup["blobs"].append(copy.deepcopy(dup["blobs"][0]))
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(dup, dict(blobs), ap.manifest_digest(dup))
        self.assertEqual(ctx.exception.code,
                         "artifact-manifest-malformed")

    def test_malformed_blob_entry_digest(self):
        blobs = _blobs()
        manifest, _ = ap.pack(blobs, ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        bad = copy.deepcopy(manifest)
        bad["blobs"][0]["digest"] = "not-a-digest"
        with self.assertRaises(ap.ArtifactPackError) as ctx:
            ap.verify(bad, dict(blobs), ap.manifest_digest(bad))
        self.assertEqual(ctx.exception.code,
                         "artifact-manifest-malformed")


class WireFnsTest(unittest.TestCase):
    def test_evidence_records_roundtrip(self):
        records = [{"seq": 0, "decision": "deny"},
                   {"seq": 1, "decision": "allow"}]
        manifest, digest = ap.pack_evidence_records(records)
        self.assertEqual(
            manifest["artifactType"],
            ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        blobs = {}
        for i, rec in enumerate(records):
            blobs["record-%04d.json" % i] = json.dumps(
                rec, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode("utf-8")
        back = ap.unpack_evidence_records(manifest, blobs, digest)
        self.assertEqual(back, records)

    def test_evidence_records_reject_non_dict(self):
        with self.assertRaises(ap.ArtifactPackError):
            ap.pack_evidence_records([{"ok": 1}, "nope"])

    def test_skill_files_roundtrip(self):
        files = {"SKILL.md": b"# s\n"}
        manifest, digest = ap.pack_skill_files(files)
        self.assertEqual(manifest["artifactType"],
                         ap.ARTIFACT_TYPE_SKILL_BUNDLE)
        self.assertEqual(ap.unpack(manifest, dict(files), digest),
                         files)

    def test_skill_files_media_types(self):
        files = {"SKILL.md": b"# s\n"}
        manifest, _ = ap.pack_skill_files(
            files, media_types={"SKILL.md": "text/markdown"})
        self.assertEqual(manifest["blobs"][0]["mediaType"],
                         "text/markdown")


class DigestIdentityTest(unittest.TestCase):
    def test_manifest_digest_shape(self):
        manifest, digest = ap.pack(
            _blobs(), ap.ARTIFACT_TYPE_EVIDENCE_BUNDLE)
        self.assertEqual(digest, ap.manifest_digest(manifest))
        hexpart = digest[len("sha256:"):]
        self.assertEqual(len(hexpart), 64)
        self.assertEqual(hexpart, hexpart.lower())
        int(hexpart, 16)

    def test_determinism(self):
        _, d1 = ap.pack(_blobs(), ap.ARTIFACT_TYPE_SKILL_BUNDLE)
        _, d2 = ap.pack(_blobs(), ap.ARTIFACT_TYPE_SKILL_BUNDLE)
        self.assertEqual(d1, d2)

    def test_byte_flip_changes_digest(self):
        _, d1 = ap.pack(_blobs(), ap.ARTIFACT_TYPE_SKILL_BUNDLE)
        evil = _blobs()
        evil["policy.txt"] = b"deny\r\n"
        _, d2 = ap.pack(evil, ap.ARTIFACT_TYPE_SKILL_BUNDLE)
        self.assertNotEqual(d1, d2)

    def test_annotations_change_digest(self):
        _, d1 = ap.pack(_blobs(), ap.ARTIFACT_TYPE_SKILL_BUNDLE)
        _, d2 = ap.pack(_blobs(), ap.ARTIFACT_TYPE_SKILL_BUNDLE,
                        annotations={"k": "v"})
        self.assertNotEqual(d1, d2)


if __name__ == "__main__":
    unittest.main()
