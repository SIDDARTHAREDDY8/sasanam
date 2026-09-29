"""Tests for gov/evidence_distribute.py (Wave-191 Lane B).

Public seams only: pack_bundle determinism, push_bundle tag discipline,
attach_bom/attach_signature referrer graph, pull_bundle byte-compare,
resolve_and_pin, and the audit_bundle auditor workflow. The OCI client is
a hermetic in-test fake implementing the injected-client protocol --
zero network. Deterministic, synthetic, $0.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.keyfixture import provision_test_key

from gov import evidence_distribute as ed
from gov.digest_ref import DigestRef
from gov.evidence_bundle import EvidenceBundle, log_evidence_bundle_receipt
from gov.log import ActionLog
from gov.signing import Ed25519Signer


def _seed(tag):
    return hashlib.sha256(
        ("test-evidence-distribute:" + tag).encode()).digest()


OPERATOR = Ed25519Signer(_seed("operator"))
OPERATOR_PUB_HEX = OPERATOR.public_key.hex()


class FakeRegistry(object):
    """Hermetic OCI fake implementing the injected-client protocol."""

    def __init__(self):
        self.blobs = {}
        self.manifests = {}
        self.registered = set()
        self.tags = {}
        self.referrers = {}

    @staticmethod
    def _ref_to_key(ref):
        # The client protocol is string-keyed (the registry wire speaks
        # strings); the product seams pass DigestRef. The fake -- like a
        # real adapter -- converts explicitly at its boundary.
        if isinstance(ref, DigestRef):
            return ref.digest
        return ref

    def push_blob(self, repo, data, media_type):
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self.blobs[(repo, digest)] = data
        return digest

    def put_manifest(self, repo, manifest_bytes, tag=None):
        if isinstance(manifest_bytes, dict):
            manifest_bytes = json.dumps(
                manifest_bytes, sort_keys=True).encode()
        digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        self.manifests[(repo, digest)] = manifest_bytes
        self.registered.add((repo, digest))
        try:
            m = json.loads(manifest_bytes.decode("utf-8"))
        except Exception:
            m = {}
        subj = m.get("subject") or {}
        if isinstance(subj, dict) and subj.get("digest"):
            self.referrers.setdefault(
                (repo, subj["digest"]), []).append(digest)
        if tag is not None:
            self.tags[(repo, tag)] = digest
        return digest

    def get_manifest(self, repo, reference):
        reference = self._ref_to_key(reference)
        if (repo, reference) not in self.registered:
            raise KeyError("manifest unknown: %s" % reference)
        raw = self.manifests[(repo, reference)]
        return json.loads(raw.decode("utf-8")), reference

    def pull_blob(self, repo, digest):
        digest = self._ref_to_key(digest)
        try:
            return self.blobs[(repo, digest)]
        except KeyError:
            raise KeyError("blob unknown: %s" % digest)

    def list_referrers(self, repo, digest):
        digest = self._ref_to_key(digest)
        out = []
        for md in self.referrers.get((repo, digest), []):
            m, _ = self.get_manifest(repo, md)
            out.append({"mediaType": m.get("mediaType"),
                        "artifactType": m.get("artifactType"),
                        "digest": md})
        return out

    def resolve_tag(self, repo, tag):
        try:
            return self.tags[(repo, tag)]
        except KeyError:
            raise KeyError("tag unknown: %s" % tag)

    def strip_referrers(self, repo, digest):
        digest = self._ref_to_key(digest)
        for md in self.referrers.pop((repo, digest), []):
            self.manifests.pop((repo, md), None)
            self.registered.discard((repo, md))

    def tamper_blob(self, repo, digest, data):
        self.blobs[(repo, self._ref_to_key(digest))] = data


def _build_bundle(tmp, name):
    """Genuine bundle via the repo's own builder; hermetic per name."""
    provision_test_key(epoch="test-distribute")
    rundir = os.path.join(tmp, "bb-" + name)
    os.makedirs(rundir, exist_ok=True)
    log_path = os.path.join(rundir, "audit.log")
    log = ActionLog(log_path, signer=OPERATOR, deployment_mode="staging")
    log.append({"event": "policy_loaded", "policy_hash": "h" * 16,
                "policy_path": "policies/p1.yaml", "pinned": True,
                "policy_version": "1.0", "run": name})
    log.append({"event": "approval_decision", "decision": "approve",
                "ticket": "T-1", "run": name})
    eb = EvidenceBundle(log_path, exported_at="2026-09-26T00:00:00+00:00",
                        operator_id="test-distribute")
    payload = eb.build()
    manifest = eb.seal(payload, signer=OPERATOR)
    log_evidence_bundle_receipt(
        manifest,
        ActionLog(log_path, signer=OPERATOR, deployment_mode="staging"),
        signer=OPERATOR)
    op = {"key_id": OPERATOR.key_id, "public_key_hex": OPERATOR_PUB_HEX}
    out = os.path.join(rundir, "bundle")
    eb.assemble(payload, manifest, operator_key=op,
                checkpoint_keys=[dict(op)], out_dir=out)
    return out


class DistributeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="test-distribute-")
        self.fake = FakeRegistry()
        self.repo = "sasanam/evidence"

    def _push_sig(self, subject, sig_bytes=b'{"sig": "test"}'):
        return ed.attach_signature(self.fake, self.repo, subject, sig_bytes)

    # -- packing ------------------------------------------------------
    def test_pack_bundle_deterministic(self):
        d = _build_bundle(self.tmp, "pack")
        a = ed.pack_bundle(d)
        b = ed.pack_bundle(d)
        self.assertEqual(a, b)
        # mtime changes must not move the bytes.
        p = os.path.join(d, "manifest.json")
        os.utime(p, (1234567890, 1234567890))
        self.assertEqual(ed.pack_bundle(d), a)

    def test_pack_bundle_content_sensitive(self):
        d = _build_bundle(self.tmp, "pack2")
        a = ed.pack_bundle(d)
        with open(os.path.join(d, "extra.txt"), "w") as fh:
            fh.write("x")
        self.assertNotEqual(ed.pack_bundle(d), a)

    # -- push ---------------------------------------------------------
    def test_push_and_resolve(self):
        d = _build_bundle(self.tmp, "push")
        digest = ed.push_bundle(d, self.fake, self.repo, tag="evidence:v1")
        self.assertIsInstance(digest, DigestRef)
        self.assertTrue(digest.digest.startswith("sha256:"))
        self.assertEqual(digest.reference,
                         self.repo + "@" + digest.digest)
        self.assertEqual(self.fake.resolve_tag(self.repo, "evidence:v1"),
                         digest.digest)

    def test_push_tag_clobber_refused(self):
        a = _build_bundle(self.tmp, "clobber-a")
        b = _build_bundle(self.tmp, "clobber-b")
        da = ed.push_bundle(a, self.fake, self.repo, tag="evidence:shared")
        with self.assertRaises(ed.DistributionError):
            ed.push_bundle(b, self.fake, self.repo, tag="evidence:shared")
        self.assertEqual(
            self.fake.resolve_tag(self.repo, "evidence:shared"), da.digest)

    def test_push_idempotent_same_bytes(self):
        d = _build_bundle(self.tmp, "idem")
        da = ed.push_bundle(d, self.fake, self.repo, tag="evidence:idem")
        db = ed.push_bundle(d, self.fake, self.repo, tag="evidence:idem")
        self.assertEqual(da, db)

    def test_push_without_tag(self):
        d = _build_bundle(self.tmp, "notag")
        digest = ed.push_bundle(d, self.fake, self.repo)
        manifest, resolved = self.fake.get_manifest(self.repo, digest)
        self.assertEqual(resolved, digest.digest)
        self.assertEqual(manifest["layers"][0]["mediaType"],
                         ed.MT_BUNDLE_TAR)

    # -- referrers ----------------------------------------------------
    def test_attach_bom_and_signature(self):
        d = _build_bundle(self.tmp, "refs")
        subject = ed.push_bundle(d, self.fake, self.repo)
        bom = b'{"bom": "decision-bom/1"}'
        sig = b'{"sig": "envelope"}'
        ed.attach_bom(self.fake, self.repo, subject, bom)
        ed.attach_signature(self.fake, self.repo, subject, sig)
        refs = self.fake.list_referrers(self.repo, subject)
        kinds = sorted(r["artifactType"] for r in refs)
        self.assertEqual(kinds, [ed.AT_BOM, ed.AT_SIG])

    def test_attach_requires_digest_pin(self):
        d = _build_bundle(self.tmp, "pin")
        subject = ed.push_bundle(d, self.fake, self.repo, tag="evidence:pin")
        with self.assertRaises(TypeError):
            ed.attach_signature(self.fake, self.repo, "evidence:pin",
                                b'{"sig": 1}')

    # -- pull ---------------------------------------------------------
    def test_pull_bundle_roundtrip(self):
        d = _build_bundle(self.tmp, "pull")
        subject = ed.push_bundle(d, self.fake, self.repo, tag="evidence:p")
        outdir = os.path.join(self.tmp, "pulled")
        self.assertEqual(ed.pull_bundle(self.fake, self.repo, subject,
                                        outdir), outdir)
        manifest, _ = self.fake.get_manifest(self.repo, subject)
        want = self.fake.pull_blob(
            self.repo, manifest["layers"][0]["digest"])
        # Re-pack the pulled dir: byte-identical to the pushed tar.
        self.assertEqual(ed.pack_bundle(outdir), want)

    def test_pull_bundle_rejects_tag(self):
        d = _build_bundle(self.tmp, "pulltag")
        ed.push_bundle(d, self.fake, self.repo, tag="evidence:t")
        with self.assertRaises(TypeError):
            ed.pull_bundle(self.fake, self.repo, "evidence:t",
                           os.path.join(self.tmp, "o"))

    def test_pull_bundle_lying_registry(self):
        d = _build_bundle(self.tmp, "lie")
        subject = ed.push_bundle(d, self.fake, self.repo)
        manifest, _ = self.fake.get_manifest(self.repo, subject)
        tar_digest = manifest["layers"][0]["digest"]
        other = _build_bundle(self.tmp, "lie-other")
        self.fake.tamper_blob(self.repo, tar_digest,
                              ed.pack_bundle(other))
        with self.assertRaises(ed.DistributionError):
            ed.pull_bundle(self.fake, self.repo, subject,
                           os.path.join(self.tmp, "o"))

    def test_pull_bundle_unknown_digest(self):
        with self.assertRaises(ed.DistributionError):
            ed.pull_bundle(self.fake, self.repo,
                           DigestRef.from_hex("0" * 64),
                           os.path.join(self.tmp, "o"))

    def test_pull_bundle_hostile_tar_member(self):
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            ti = tarfile.TarInfo(name="../../evil")
            data = b"evil"
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        with self.assertRaises(ed.DistributionError):
            ed._safe_untar(buf.getvalue(),
                           os.path.join(self.tmp, "evil-out"))

    # -- resolve_and_pin ----------------------------------------------
    def test_resolve_and_pin(self):
        d = _build_bundle(self.tmp, "pin2")
        digest = ed.push_bundle(d, self.fake, self.repo, tag="evidence:rp")
        self.assertEqual(
            ed.resolve_and_pin(self.fake, self.repo, "evidence:rp"), digest)

    def test_resolve_and_pin_unknown_tag(self):
        with self.assertRaises(ed.DistributionError):
            ed.resolve_and_pin(self.fake, self.repo, "evidence:nope")

    # -- audit --------------------------------------------------------
    def _audited(self, name):
        d = _build_bundle(self.tmp, name)
        subject = ed.push_bundle(d, self.fake, self.repo)
        ed.attach_bom(self.fake, self.repo, subject, b'{"bom": 1}')
        self._push_sig(subject)
        return subject

    def test_audit_bundle_happy_path(self):
        subject = self._audited("audit-ok")
        outdir = os.path.join(self.tmp, "audit-out")
        verdict = ed.audit_bundle(
            self.fake, self.repo, ref=subject, outdir=outdir,
            operator_pins=(OPERATOR_PUB_HEX,))
        self.assertEqual(verdict["digest"], subject.digest)
        self.assertEqual(verdict["verify_code"], 0)
        self.assertTrue(verdict["signature"].startswith("sha256:"))
        self.assertTrue(verdict["bom"].startswith("sha256:"))

    def test_audit_bundle_stripped_signature(self):
        subject = self._audited("audit-strip")
        self.fake.strip_referrers(self.repo, subject)
        with self.assertRaises(ed.DistributionError):
            ed.audit_bundle(self.fake, self.repo, ref=subject,
                            outdir=os.path.join(self.tmp, "o"),
                            operator_pins=(OPERATOR_PUB_HEX,))

    def test_audit_bundle_requires_pins(self):
        subject = self._audited("audit-nopins")
        with self.assertRaises(ed.DistributionError):
            ed.audit_bundle(self.fake, self.repo, ref=subject,
                            outdir=os.path.join(self.tmp, "o"),
                            operator_pins=())

    def test_audit_bundle_referrer_digest_mismatch(self):
        subject = self._audited("audit-mismatch")
        real_refs = self.fake.list_referrers(self.repo, subject)
        lying = [dict(r, digest="sha256:" + "f" * 64) for r in real_refs]
        self.fake.list_referrers = lambda repo, digest: lying
        with self.assertRaises(ed.DistributionError):
            ed.audit_bundle(self.fake, self.repo, ref=subject,
                            outdir=os.path.join(self.tmp, "o"),
                            operator_pins=(OPERATOR_PUB_HEX,))

    def test_audit_bundle_bad_bundle_fails_verifier(self):
        junk = os.path.join(self.tmp, "junk")
        os.makedirs(junk)
        with open(os.path.join(junk, "x.txt"), "w") as fh:
            fh.write("not a bundle")
        subject = ed.push_bundle(junk, self.fake, self.repo)
        self._push_sig(subject)
        with self.assertRaises(ed.DistributionError):
            ed.audit_bundle(self.fake, self.repo, ref=subject,
                            outdir=os.path.join(self.tmp, "o"),
                            operator_pins=(OPERATOR_PUB_HEX,))

    def test_client_errors_become_distribution_error(self):
        class Broken(object):
            def __getattr__(self, name):
                def boom(*a, **k):
                    raise RuntimeError("wire down")
                return boom
        d = _build_bundle(self.tmp, "broken")
        with self.assertRaises(ed.DistributionError):
            ed.push_bundle(d, Broken(), self.repo, tag="x")
        with self.assertRaises(ed.DistributionError):
            ed.resolve_and_pin(Broken(), self.repo, "x")
        with self.assertRaises(ed.DistributionError):
            ed.pull_bundle(Broken(), self.repo,
                           DigestRef.from_hex("0" * 64),
                           os.path.join(self.tmp, "o"))


if __name__ == "__main__":
    unittest.main()
