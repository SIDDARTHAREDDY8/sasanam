#!/usr/bin/env python3
"""Unit tests for gov/artifacts.py and the Row-12 executor wiring.

Covers: inventory registration/lookup, hash-chain integrity and
tamper detection, exact-byte hashing, the four egress verdicts,
label precedence, multi-ref dominance, path normalization, the
approved-sweep re-registration, and child inventory sharing.
"""

import hashlib
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import artifacts as _artifacts  # noqa: E402
from gov.artifacts import ArtifactInventory, normalize_path  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class TestNormalizePath(unittest.TestCase):
    def test_backslash_and_leading_slash(self):
        self.assertEqual(normalize_path("\\a\\b.txt"), "a/b.txt")
        self.assertEqual(normalize_path("/a/b.txt"), "a/b.txt")
        self.assertEqual(normalize_path("./a/b.txt"), "a/b.txt")

    def test_none_and_empty(self):
        self.assertEqual(normalize_path(None), "")
        self.assertEqual(normalize_path(""), "")


class TestInventory(unittest.TestCase):
    def setUp(self):
        self.inv = ArtifactInventory()

    def _reg(self, path="a.txt", content=b"hello", **kw):
        params = dict(sha256=_sha(content), size=len(content),
                      agent_id="agent-1", run_id="run-1")
        params.update(kw)
        return self.inv.register(path, **params)

    def test_register_and_lookup(self):
        rec = self._reg("docs/a.txt", b"hello")
        self.assertEqual(self.inv.lookup("docs/a.txt"), rec)
        self.assertEqual(rec.sha256, _sha(b"hello"))
        self.assertEqual(rec.size, 5)
        self.assertIsNone(self.inv.lookup("docs/missing.txt"))

    def test_lookup_normalizes(self):
        self._reg("docs/a.txt", b"hello")
        self.assertIsNotNone(self.inv.lookup("/docs/a.txt"))
        self.assertIsNotNone(self.inv.lookup("docs\\a.txt"))

    def test_reregister_overwrites_with_new_bytes(self):
        self._reg("a.txt", b"v1")
        rec2 = self._reg("a.txt", b"v2-longer")
        self.assertEqual(rec2.sha256, _sha(b"v2-longer"))
        self.assertEqual(len(self.inv), 1)
        ok, _ = self.inv.verify_chain()
        self.assertTrue(ok)

    def test_rejects_empty_path_and_bad_digest(self):
        with self.assertRaises(ValueError):
            self.inv.register("", sha256=_sha(b"x"), size=1,
                              agent_id="a", run_id="r")
        with self.assertRaises(ValueError):
            self.inv.register("a.txt", sha256="not-a-digest", size=1,
                              agent_id="a", run_id="r")

    def test_chain_intact(self):
        self._reg("a.txt", b"1")
        self._reg("b.txt", b"2")
        self._reg("c.txt", b"3")
        ok, reason = self.inv.verify_chain()
        self.assertTrue(ok, reason)

    def test_chain_detects_payload_tamper(self):
        rec = self._reg("a.txt", b"1")
        self._reg("b.txt", b"2")
        # Adversary edits a registered payload in place.
        rec.size = 999
        ok, reason = self.inv.verify_chain()
        self.assertFalse(ok)
        self.assertIn("tampered", reason)

    def test_chain_detects_dropped_event(self):
        self._reg("a.txt", b"1")
        self._reg("b.txt", b"2")
        # Adversary drops a registration event from the trail.
        del self.inv._chain[0]
        ok, reason = self.inv.verify_chain()
        self.assertFalse(ok)
        self.assertIn("linkage", reason)

    def test_empty_chain_verifies(self):
        ok, _ = ArtifactInventory().verify_chain()
        self.assertTrue(ok)


class TestCheckEgress(unittest.TestCase):
    def setUp(self):
        self.inv = ArtifactInventory()
        self.content = b"artifact bytes"
        self.digest = _sha(self.content)
        self.inv.register("pub.txt", sha256=self.digest,
                          size=len(self.content), agent_id="a",
                          run_id="r", classification="public")
        self.inv.register("sec.txt", sha256=self.digest,
                          size=len(self.content), agent_id="a",
                          run_id="r", classification="restricted")

    def test_unknown(self):
        v = self.inv.check_egress("never-written.bin",
                                  sha256_now=_sha(b"x"))
        self.assertEqual(v["status"], "unknown")
        self.assertEqual(v["flag"], _artifacts.UNKNOWN_FLAG)

    def test_tampered(self):
        v = self.inv.check_egress("pub.txt", sha256_now=_sha(b"changed"))
        self.assertEqual(v["status"], "tampered")
        self.assertEqual(v["flag"], _artifacts.TAMPERED_FLAG)

    def test_restricted(self):
        v = self.inv.check_egress("sec.txt", sha256_now=self.digest)
        self.assertEqual(v["status"], "restricted")
        self.assertEqual(v["flag"], _artifacts.RESTRICTED_FLAG)

    def test_clean_public(self):
        v = self.inv.check_egress("pub.txt", sha256_now=self.digest)
        self.assertEqual(v["status"], "clean")
        self.assertIsNone(v["flag"])

    def test_unreadable_skips_tamper_check(self):
        # sha256_now=None (file could not be hashed): no tamper
        # verdict, falls through to the label verdict.
        v = self.inv.check_egress("sec.txt", sha256_now=None)
        self.assertEqual(v["status"], "restricted")

    def test_current_label_more_restrictive_wins(self):
        # Registered public, but the deployment labeled it restricted
        # afterwards -> still gates.
        v = self.inv.check_egress("pub.txt", sha256_now=self.digest,
                                  current_label="restricted")
        self.assertEqual(v["status"], "restricted")

    def test_stored_label_survives_unlabel(self):
        # Deployment removed the label; the registration-time label
        # still gates (conservative).
        v = self.inv.check_egress("sec.txt", sha256_now=self.digest,
                                  current_label=None)
        self.assertEqual(v["status"], "restricted")

    def test_unknown_label_string_is_not_a_restriction(self):
        self.inv.register("weird.txt", sha256=self.digest, size=1,
                          agent_id="a", run_id="r",
                          classification="topsecret!!")
        v = self.inv.check_egress("weird.txt", sha256_now=self.digest)
        self.assertEqual(v["status"], "clean")


def _session():
    run_dir = Path(tempfile.mkdtemp(prefix="govartifact-ut-",
                                    dir=os.environ.get("TMPDIR", "/tmp")))
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack="artifact unit test harness")
    ident = ex.mint_identity("coder-1", "coder", "user-1")
    return run_dir, ex, ident, approvals


class TestExecutorWiring(unittest.TestCase):
    def setUp(self):
        self.run_dir, self.ex, self.ident, self.approvals = _session()

    def _write(self, rel, content):
        r = self.ex.call(self.ident, "write_file", path=rel,
                         content=content)
        self.assertEqual(r.get("status"), "executed")
        return r

    def _api_upload(self, params):
        return self.ex.call(
            self.ident, "api_call",
            endpoint="https://vendor.synthetic.local/crm", params=params)

    def test_write_registers_exact_disk_bytes(self):
        self._write("a.txt", "hello")
        rec = self.ex.artifacts.lookup("a.txt")
        self.assertIsNotNone(rec)
        on_disk = (self.run_dir / "sandbox" / "a.txt").read_bytes()
        self.assertEqual(rec.sha256, _sha(on_disk))
        self.assertEqual(rec.agent_id, "coder-1")

    def test_write_registers_label(self):
        self.ex.classification.label("sec.txt", "restricted")
        self._write("sec.txt", "sensitive draft")
        rec = self.ex.artifacts.lookup("sec.txt")
        self.assertEqual(rec.classification, "restricted")

    def test_restricted_artifact_egress_queued(self):
        self.ex.classification.label("sec.txt", "restricted")
        self._write("sec.txt", "sensitive draft")
        r = self._api_upload({"action": "upload", "file": "sec.txt"})
        self.assertEqual(r.get("status"), "queued")
        flag = (self.approvals.get(r["approval_id"]) or {}).get(
            "policy_flag")
        self.assertEqual(flag, "artifact_restricted_egress")

    def test_unknown_artifact_egress_queued_loud(self):
        (self.run_dir / "sandbox" / "planted.bin").write_bytes(b"xx")
        r = self._api_upload({"action": "upload", "file": "planted.bin"})
        self.assertEqual(r.get("status"), "queued")
        flag = (self.approvals.get(r["approval_id"]) or {}).get(
            "policy_flag")
        self.assertEqual(flag, "unknown_artifact_egress")

    def test_public_artifact_egress_clean(self):
        self._write("pub.txt", "changelog")
        r = self._api_upload({"action": "upload", "file": "pub.txt"})
        self.assertEqual(r.get("status"), "executed")

    def test_tampered_artifact_egress_queued(self):
        self._write("card.txt", "v1")
        (self.run_dir / "sandbox" / "card.txt").write_bytes(b"v1+evil")
        r = self._api_upload({"action": "upload", "file": "card.txt"})
        self.assertEqual(r.get("status"), "queued")
        flag = (self.approvals.get(r["approval_id"]) or {}).get(
            "policy_flag")
        self.assertEqual(flag, "artifact_tampered")

    def test_one_bad_ref_dominates(self):
        self._write("good.txt", "fine")
        (self.run_dir / "sandbox" / "bad.bin").write_bytes(b"xx")
        r = self._api_upload({"action": "upload",
                              "files": ["good.txt", "bad.bin"]})
        self.assertEqual(r.get("status"), "queued")
        flag = (self.approvals.get(r["approval_id"]) or {}).get(
            "policy_flag")
        self.assertEqual(flag, "unknown_artifact_egress")

    def test_tampered_dominates_restricted(self):
        self.ex.classification.label("sec.txt", "restricted")
        self._write("sec.txt", "v1")
        (self.run_dir / "sandbox" / "sec.txt").write_bytes(b"v1+evil")
        r = self._api_upload({"action": "upload", "file": "sec.txt"})
        self.assertEqual(r.get("status"), "queued")
        flag = (self.approvals.get(r["approval_id"]) or {}).get(
            "policy_flag")
        # Policy rule order is loudest-first: tampered before restricted.
        self.assertEqual(flag, "artifact_tampered")

    def test_phantom_ref_no_signal(self):
        r = self._api_upload({"action": "note",
                              "text": "see drafts/ghost.pdf"})
        self.assertEqual(r.get("status"), "executed")

    def test_sweep_refuses_tampered_after_approval(self):
        # TOCTOU: queue a restricted-artifact egress, approve it, tamper
        # the bytes before the sweep, verify the sweep REFUSES (does not
        # execute the tampered bytes the human never approved).
        self.ex.classification.label("sec.txt", "restricted")
        self._write("sec.txt", "v1")
        r = self._api_upload({"action": "upload", "file": "sec.txt"})
        self.assertEqual(r.get("status"), "queued")
        aid = r["approval_id"]
        self.approvals.decide(aid, True, "human approved v1 bytes")
        # Attacker swaps the bytes after approval.
        (self.run_dir / "sandbox" / "sec.txt").write_bytes(b"v1+evil")
        self.ex.execute_approved()
        # The sweep refused; the tampered bytes never left.
        rec = self.approvals.get(aid)
        self.assertIsNotNone(rec.get("execution_refused_reason"))
        self.assertIn("changed since approval",
                      rec["execution_refused_reason"])

    def test_approved_sweep_registers_write(self):
        # An outside-sandbox write_file is queued (quarantine rule);
        # after human approval the sweep executes it, and the
        # mirrored hook registers it in the inventory exactly like a
        # direct write.
        outside = os.path.join(
            tempfile.gettempdir(),
            "govartifact-sweep-%s.txt" % secrets.token_hex(4))
        r = self.ex.call(self.ident, "write_file", path=outside,
                         content="sweep bytes")
        self.assertEqual(r.get("status"), "queued",
                         "outside-sandbox write should queue, got %r" % (r,))
        aid = r["approval_id"]
        self.assertEqual(len(self.ex.artifacts), 0)
        self.approvals.decide(aid, True, "test approval")
        swept = self.ex.execute_approved()
        self.assertTrue(swept)
        self.assertEqual(len(self.ex.artifacts), 1)

    def test_send_email_attachment_surface(self):
        # publisher role: send_email + read_file. Use a fresh session
        # with the publisher identity for the email surface.
        run_dir, ex, _, approvals = _session()
        ident = ex.mint_identity("pub-1", "publisher", "user-1")
        # publisher cannot write_file; plant via the inventory's own
        # registration path is not available — so register through a
        # coder write in the same run dir is out of scope here.
        # Instead: unknown attachment on send_email must still gate.
        (run_dir / "sandbox" / "drop.bin").write_bytes(b"xx")
        r = ex.call(ident, "send_email", to="x@synthetic.local",
                    subject="s", body="b", attachments=["drop.bin"])
        self.assertEqual(r.get("status"), "queued")
        flag = (approvals.get(r["approval_id"]) or {}).get("policy_flag")
        self.assertEqual(flag, "unknown_artifact_egress")

    def test_http_post_files_surface(self):
        # publisher role has http_post. Unknown file in the files
        # field must gate; a registered public file must not.
        run_dir, ex, _, approvals = _session()
        ident = ex.mint_identity("pub-1", "publisher", "user-1")
        (run_dir / "sandbox" / "up.bin").write_bytes(b"xx")
        r = ex.call(ident, "http_post",
                    url="https://vendor.synthetic.local/upload",
                    payload={"note": "x"}, files={"data": "up.bin"})
        self.assertEqual(r.get("status"), "queued")
        flag = (approvals.get(r["approval_id"]) or {}).get("policy_flag")
        self.assertEqual(flag, "unknown_artifact_egress")


class TestSpawnSharing(unittest.TestCase):
    def test_child_shares_inventory(self):
        run_dir, ex, ident, _ = _session()
        r = ex.call(ident, "write_file", path="shared.txt",
                    content="parent bytes")
        self.assertEqual(r.get("status"), "executed")
        # Simulate the spawn inheritance line (spawn_sub_agent needs
        # delegation plumbing; the unit pins the contract directly).
        child = ToolExecutor(run_dir, ex.policy, ex.log, ex.approvals,
                             ledger_path=run_dir / "egress2.jsonl",
                             ungoverned_ack="artifact unit test harness")
        child.artifacts = ex.artifacts  # the spawn contract
        self.assertIsNotNone(child.artifacts.lookup("shared.txt"))
        v = child.artifacts.check_egress(
            "shared.txt",
            sha256_now=_sha((run_dir / "sandbox" / "shared.txt")
                            .read_bytes()))
        self.assertEqual(v["status"], "clean")


if __name__ == "__main__":
    unittest.main(verbosity=2)
