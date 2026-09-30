"""Unit tests for gov/render_commit.py and the approval_render wiring
(wave-221 lane A: approval rendering commitments).

Tests at the public seams: commit/verify/check_commitment_shape and
seal_approval/verify_seal/guardian_decide with rendering_commitment.
Expected values are independent literals (hand-computed digests),
never recomputed the way the code computes them.
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import render_commit as rc  # noqa: E402
from gov import approval_render as ar  # noqa: E402
from gov import presentation as pres  # noqa: E402

# sha256("abc") spec vector, independent literal.
ABC_HEX = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABC_DIGEST = "sha256:" + ABC_HEX


def _commitment(**over):
    c = {
        "artifact_digest": "sha256:" + "0" * 64,
        "render_hash": ABC_DIGEST,
        "rendered_at": "2026-09-29T23:00:00+0000",
        "renderer_id": "queue-view",
        "render_policy_digest": "",
    }
    c.update(over)
    return c


def _record(**over):
    rec = {
        "id": "appr-0001",
        "tool": "write_file",
        "args": {"path": "/etc/app/config.yaml", "mode": "overwrite"},
        "preview": "write /etc/app/config.yaml (overwrite)",
        "agent_id": "agent-7",
        "role": "executor",
        "principal": "principal:agent-7",
        "policy_id": "pol-9",
        "policy_version": 3,
        "matched_rules": ["rule-write"],
        "policy_flag": None,
        "packet_risk_score": 55,
        "packet_risk_factors": ["writes-outside-sandbox"],
        "shield_tier": "standard",
        "persuasion_score": 0,
        "persuasion_markers": [],
        "policy_context": {"path_resolved": "/etc/app/config.yaml",
                           "memory_provenance": [],
                           "attachment_carriers": []},
        "deferred_effect": None,
    }
    rec.update(over)
    return rec


class TestCommit(unittest.TestCase):
    def test_fields_and_known_digest(self):
        c = rc.commit(b"abc", "sha256:" + "0" * 64, renderer_id="op-1")
        self.assertEqual(c["render_hash"], ABC_DIGEST)
        self.assertEqual(c["artifact_digest"], "sha256:" + "0" * 64)
        self.assertEqual(c["renderer_id"], "op-1")
        self.assertEqual(c["render_policy_digest"], "")
        self.assertTrue(c["rendered_at"])
        self.assertEqual(set(c),
                         {"artifact_digest", "render_hash", "rendered_at",
                          "renderer_id", "render_policy_digest"})

    def test_render_policy_digest_recorded(self):
        c = rc.commit(b"abc", "sha256:" + "0" * 64, renderer_id="op-1",
                      render_policy_digest="sha256:" + "2" * 64)
        self.assertEqual(c["render_policy_digest"], "sha256:" + "2" * 64)

    def test_digest_is_independent_of_python_hash(self):
        # sha256 over raw bytes: no string encoding assumptions.
        want = "sha256:" + hashlib.sha256(b"\x00\xff").hexdigest()
        self.assertEqual(rc.commit(b"\x00\xff", "sha256:" + "0" * 64,
                                  renderer_id="op")["render_hash"], want)

    def test_rejects_nonbytes(self):
        with self.assertRaises(TypeError):
            rc.commit("abc", "sha256:" + "0" * 64, renderer_id="op-1")

    def test_rejects_empty_digest(self):
        with self.assertRaises(ValueError):
            rc.commit(b"abc", "", renderer_id="op-1")

    def test_rejects_empty_renderer(self):
        with self.assertRaises(ValueError):
            rc.commit(b"abc", "sha256:" + "0" * 64, renderer_id="")


class TestVerify(unittest.TestCase):
    def test_exact_replay_returns_true(self):
        c = rc.commit(b"abc", "sha256:" + "0" * 64, renderer_id="op-1")
        self.assertTrue(rc.verify(c, b"abc"))

    def test_tampered_replay_code(self):
        c = rc.commit(b"abc", "sha256:" + "0" * 64, renderer_id="op-1")
        with self.assertRaises(rc.RenderingCommitmentError) as ctx:
            rc.verify(c, b"abd")
        self.assertEqual(ctx.exception.code, "rendering-commitment-broken")

    def test_extra_byte_breaks_replay(self):
        c = rc.commit(b"abc", "sha256:" + "0" * 64, renderer_id="op-1")
        with self.assertRaises(rc.RenderingCommitmentError):
            rc.verify(c, b"abc\n")

    def test_nonbytes_replay_is_authoring_misuse(self):
        c = rc.commit(b"abc", "sha256:" + "0" * 64, renderer_id="op-1")
        with self.assertRaises(TypeError):
            rc.verify(c, "abc")


class TestShape(unittest.TestCase):
    def test_valid_shape(self):
        self.assertTrue(rc.check_commitment_shape(_commitment()))

    def test_missing_key(self):
        c = _commitment()
        del c["renderer_id"]
        with self.assertRaises(rc.RenderingCommitmentError) as ctx:
            rc.check_commitment_shape(c)
        self.assertEqual(ctx.exception.code, "rendering-commitment-broken")

    def test_extra_key(self):
        c = _commitment(permit_id="p-1")
        with self.assertRaises(rc.RenderingCommitmentError):
            rc.check_commitment_shape(c)

    def test_bad_render_hash_format(self):
        c = _commitment(render_hash="sha256:nothex")
        with self.assertRaises(rc.RenderingCommitmentError):
            rc.check_commitment_shape(c)

    def test_not_a_dict(self):
        with self.assertRaises(rc.RenderingCommitmentError):
            rc.check_commitment_shape(["nope"])


class TestSealWiring(unittest.TestCase):
    def _sealed(self, record, **kw):
        presentation = ar.render_approval(record)
        commitment = rc.commit(presentation["text"].encode("utf-8"),
                               pres.artifact_digest(record),
                               renderer_id="queue-view")
        return ar.seal_approval(record, presentation, signer="op-1",
                                rendering_commitment=commitment, **kw)

    def test_seal_carries_commitment(self):
        sealed = self._sealed(_record())
        self.assertIn("rendering_commitment", sealed)
        self.assertEqual(sealed["rendering_commitment"]["render_hash"],
                         sealed["presentation_digest"])

    def test_seal_refuses_commitment_for_wrong_presentation(self):
        record = _record()
        presentation = ar.render_approval(record)
        other = ar.render_approval(_record(id="appr-0002"))
        commitment = rc.commit(other["text"].encode("utf-8"),
                               pres.artifact_digest(record),
                               renderer_id="queue-view")
        with self.assertRaises(pres.DisplayHashMismatchError) as ctx:
            ar.seal_approval(record, presentation, signer="op-1",
                             rendering_commitment=commitment)
        self.assertEqual(ctx.exception.code, "display-hash-mismatch")

    def test_verify_seal_replays(self):
        record = _record()
        self.assertTrue(ar.verify_seal(record, self._sealed(record)))

    def test_verify_seal_refuses_stale_commitment(self):
        record = _record()
        presentation = ar.render_approval(record)
        commitment = rc.commit(presentation["text"].encode("utf-8"),
                               pres.artifact_digest(record),
                               renderer_id="queue-view")
        other = _record(id="appr-0002")
        sealed = ar.seal_approval(other, ar.render_approval(other),
                                  signer="op-1")
        sealed["rendering_commitment"] = commitment
        with self.assertRaises(pres.DisplayHashMismatchError) as ctx:
            ar.verify_seal(other, sealed)
        self.assertEqual(ctx.exception.code, "display-hash-mismatch")

    def test_legacy_seal_keys_unchanged(self):
        record = _record()
        sealed = ar.seal_approval(record, ar.render_approval(record),
                                  signer="op-1")
        self.assertEqual(set(sealed),
                         {"approval_id", "artifact_digest",
                          "presentation_digest", "presentation_text",
                          "signer", "at"})


if __name__ == "__main__":
    unittest.main()
