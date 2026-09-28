"""Wave-179 lane A: production wiring for audit-log Ed25519 entry signatures.

Red-first: the signing mechanics (ed_sig, format-2 signed checkpoints,
third-party checkpoint verification) already exist in gov/log.py (see
tests/test_crypto_gov.py), but no production ActionLog is ever
constructed with signer= -- every real log is HMAC-only, so the
"verifies with just a public key" story does not hold for the audit log
itself. This lane adds:

* gov.log.resolve_audit_signer(): dedicated GOV_AUDIT_SIGNING_KEY /
  GOV_AUDIT_SIGNING_KEY_FILE seam (resolve_anchor_key idiom:
  explicit > env hex > 0600 file; fail-closed on malformed config,
  None when absent).
* gov.log.open_audit_log(): factory wiring the resolved signer into
  production ActionLog constructions.
* Evidence-bundle manifest "audit_entry_signing" block bound into the
  signed claim, plus standalone-verifier per-entry ed_sig checks.

These tests are written red-first: they fail on the pristine tree
(no resolve_audit_signer / open_audit_log / audit_entry_signing).
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               ".."))

from tests.keyfixture import provision_test_key, scrub_key_env

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
VERIFY_SCRIPT = os.path.join(REPO, "tools", "evidence-verify")
PYTHON3 = shutil.which("python3") or sys.executable

_AUDIT_VARS = ("GOV_AUDIT_SIGNING_KEY", "GOV_AUDIT_SIGNING_KEY_FILE")


def _scrub_audit_env():
    saved = {n: os.environ.get(n) for n in _AUDIT_VARS}
    for n in _AUDIT_VARS:
        os.environ.pop(n, None)

    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    return restore


class TestResolveAuditSigner(unittest.TestCase):
    def setUp(self):
        self._restore_keys = scrub_key_env()
        provision_test_key()
        self._restore_audit = _scrub_audit_env()

    def tearDown(self):
        self._restore_audit()
        self._restore_keys()

    def test_configured_env_key_resolves(self):
        from gov import log as _log
        from gov import ed25519 as _ed
        from gov.signing import ed25519_key_id
        seed = secrets.token_bytes(32)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = seed.hex()
        signer = _log.resolve_audit_signer()
        self.assertIsNotNone(signer)
        self.assertEqual(signer.public_key, _ed.publickey(seed))
        self.assertEqual(signer.key_id,
                         ed25519_key_id(_ed.publickey(seed)))

    def test_explicit_seed_wins_over_env(self):
        from gov import log as _log
        from gov import ed25519 as _ed
        seed_env = secrets.token_bytes(32)
        seed_arg = secrets.token_bytes(32)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = seed_env.hex()
        signer = _log.resolve_audit_signer(explicit=seed_arg.hex())
        self.assertEqual(signer.public_key, _ed.publickey(seed_arg))

    def test_absent_returns_none(self):
        from gov import log as _log
        self.assertIsNone(_log.resolve_audit_signer())

    def test_bad_hex_raises(self):
        from gov import log as _log
        os.environ["GOV_AUDIT_SIGNING_KEY"] = "not-hex!!"
        with self.assertRaises(_log.NoAuditSigningKeyError):
            _log.resolve_audit_signer()

    def test_wrong_length_raises(self):
        from gov import log as _log
        os.environ["GOV_AUDIT_SIGNING_KEY"] = secrets.token_bytes(31).hex()
        with self.assertRaises(_log.NoAuditSigningKeyError):
            _log.resolve_audit_signer()

    def test_file_backend_0600(self):
        from gov import log as _log
        from gov import ed25519 as _ed
        seed = secrets.token_bytes(32)
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "audit.key")
            with open(p, "w") as f:
                f.write(seed.hex() + "\n")
            os.chmod(p, 0o600)
            os.environ["GOV_AUDIT_SIGNING_KEY_FILE"] = p
            signer = _log.resolve_audit_signer()
            self.assertEqual(signer.public_key, _ed.publickey(seed))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_file_backend_world_readable_refused(self):
        # Wave-91 posture: the permission gate runs BEFORE any key bytes
        # are read; a group/world-accessible file is refused, not warned.
        from gov import log as _log
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "audit.key")
            with open(p, "w") as f:
                f.write(secrets.token_bytes(32).hex())
            os.chmod(p, 0o644)
            os.environ["GOV_AUDIT_SIGNING_KEY_FILE"] = p
            with self.assertRaises(_log.NoAuditSigningKeyError):
                _log.resolve_audit_signer()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_missing_file_raises(self):
        from gov import log as _log
        os.environ["GOV_AUDIT_SIGNING_KEY_FILE"] = "/nonexistent/audit.key"
        with self.assertRaises(_log.NoAuditSigningKeyError):
            _log.resolve_audit_signer()


class TestOpenAuditLog(unittest.TestCase):
    def setUp(self):
        self._restore_keys = scrub_key_env()
        provision_test_key()
        self._restore_audit = _scrub_audit_env()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "actions.jsonl")

    def tearDown(self):
        self.tmp.cleanup()
        self._restore_audit()
        self._restore_keys()

    def _seed_env(self):
        seed = secrets.token_bytes(32)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = seed.hex()
        return seed

    def test_signs_entries_when_configured(self):
        from gov import log as _log
        from gov import ed25519 as _ed
        seed = self._seed_env()
        lg = _log.open_audit_log(self.log_path, deployment_mode="staging")
        e = lg.append({"event": "tool_call", "decision": "allow"})
        self.assertIn("ed_sig", e)
        self.assertIn("sig_key_id", e)
        pub = _ed.publickey(seed)
        self.assertTrue(_ed.verify(pub, _log._entry_sig_body(e),
                                  bytes.fromhex(e["ed_sig"])))
        # Format-2 signed checkpoint (the STH) exists.
        cps = _log.signed_checkpoints(self.log_path)
        self.assertTrue(cps)
        self.assertEqual(cps[-1]["format_version"], 2)

    def test_hmac_only_when_absent(self):
        from gov import log as _log
        lg = _log.open_audit_log(self.log_path, deployment_mode="staging")
        e = lg.append({"event": "tool_call", "decision": "allow"})
        self.assertNotIn("ed_sig", e)
        self.assertNotIn("sig_key_id", e)
        # Chain still verifies: HMAC behavior byte-identical.
        ok, _, _ = _log.verify_chain(self.log_path)
        self.assertTrue(ok)

    def test_malformed_key_loud_at_open(self):
        # Misconfiguration must fail at log open, not silently degrade
        # to HMAC-only at first append.
        from gov import log as _log
        os.environ["GOV_AUDIT_SIGNING_KEY"] = "bogus"
        with self.assertRaises(_log.NoAuditSigningKeyError):
            _log.open_audit_log(self.log_path, deployment_mode="staging")

    def test_explicit_signer_passthrough(self):
        from gov import log as _log
        from gov.signing import Ed25519Signer
        signer = Ed25519Signer(secrets.token_bytes(32))
        lg = _log.open_audit_log(self.log_path, signer=signer,
                                 deployment_mode="staging")
        e = lg.append({"event": "x"})
        self.assertEqual(e["sig_key_id"], signer.key_id)


class TestBundleBindsEntrySigningKey(unittest.TestCase):
    """The sealed manifest binds the window's entry-signing key set into
    the operator-signed claim; the standalone verifier checks per-entry
    ed_sig against the shipped checkpoint_keys envelope."""

    def setUp(self):
        self._restore_keys = scrub_key_env()
        provision_test_key()
        self._restore_audit = _scrub_audit_env()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "actions.jsonl")

    def tearDown(self):
        self.tmp.cleanup()
        self._restore_audit()
        self._restore_keys()

    def _signed_log(self, n=4):
        from gov import log as _log
        from gov.signing import Ed25519Signer
        seed = secrets.token_bytes(32)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = seed.hex()
        lg = _log.open_audit_log(self.log_path, deployment_mode="staging")
        for i in range(n):
            lg.append({"event": "tool_call", "decision": "allow",
                       "tool": "tool-%d" % i})
        signer = Ed25519Signer(seed)
        return lg, signer

    def _assemble(self, log_path, signer, name="bundle"):
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        eb = EvidenceBundle(log_path,
                            exported_at="2026-09-28T00:00:00+00:00",
                            operator_id="lane-a-test")
        payload = eb.build()
        manifest = eb.seal(payload, signer=signer)
        log_evidence_bundle_receipt(
            manifest, ActionLog(log_path, signer=signer,
                                deployment_mode="staging"),
            signer=signer)
        op = {"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}
        out = os.path.join(self.tmp.name, name)
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        return out, payload, manifest

    def test_manifest_binds_entry_signing_block(self):
        _lg, signer = self._signed_log(n=4)
        _out, _payload, manifest = self._assemble(self.log_path, signer)
        block = manifest.get("audit_entry_signing")
        self.assertIsInstance(block, dict)
        self.assertEqual(block["key_ids"], [signer.key_id])
        self.assertEqual(block["signed_entries"], 4)
        self.assertEqual(block["total_entries"], 4)
        # The public key itself ships in keys/checkpoint_keys.json
        # (envelope coverage is enforced by assemble()); the manifest
        # binds key_ids + counts into the signed claim.

    def test_unsigned_log_binds_empty_block(self):
        # HMAC-only windows stay honest: the block says zero signed.
        from gov.log import ActionLog
        from gov.signing import Ed25519Signer
        lg = ActionLog(self.log_path, deployment_mode="staging")
        for i in range(2):
            lg.append({"event": "x", "i": i})
        op_signer = Ed25519Signer(secrets.token_bytes(32))
        _out, _payload, manifest = self._assemble(self.log_path, op_signer,
                                                  name="bundle-unsigned")
        block = manifest.get("audit_entry_signing")
        self.assertEqual(block["signed_entries"], 0)
        self.assertEqual(block["total_entries"], 2)
        self.assertEqual(block["key_ids"], [])

    def test_tampered_block_breaks_operator_signature(self):
        # The block is inside the signed claim: any unsigned alteration
        # fails the manifest signature (F173 pattern).
        from gov import ed25519 as _ed
        from gov.evidence_bundle import EvidenceBundle
        _lg, signer = self._signed_log(n=3)
        _out, _payload, manifest = self._assemble(self.log_path, signer,
                                                  name="bundle-tamper")
        tampered = json.loads(json.dumps(manifest))
        tampered["audit_entry_signing"]["signed_entries"] = 999
        body = EvidenceBundle.signed_body(tampered)
        sig = bytes.fromhex(manifest["signing"]["signature_hex"])
        self.assertFalse(_ed.verify(signer.public_key, body, sig))

    def _run_verifier(self, bundle_dir, *args):
        cmd = [PYTHON3, VERIFY_SCRIPT, bundle_dir] + list(args)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env.pop("PYTHONPATH", None)
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              env=env, cwd="/tmp")
        return proc.returncode, proc.stdout, proc.stderr

    def _rewrite(self, bundle_dir, rel, obj):
        from gov.evidence_bundle import canonical
        with open(os.path.join(bundle_dir, rel), "wb") as f:
            f.write(canonical(obj) + b"\n")

    def _redigest(self, bundle_dir):
        from gov.safeguard_bundle import compute_bundle_digest
        digest = compute_bundle_digest(bundle_dir)
        with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"),
                  "w") as f:
            f.write(digest + "\n")

    def test_verifier_accepts_signed_bundle(self):
        _lg, signer = self._signed_log(n=4)
        out, _payload, _manifest = self._assemble(self.log_path, signer)
        rc, stdout, stderr = self._run_verifier(out)
        self.assertIn(rc, (0, 2), stdout + stderr)
        # Fully pinned (operator pubkey + checkpoint key id): the auditor
        # verifies with public-key material alone -- no shared secret,
        # no engine -- and gets VERIFIED (exit 0).
        rc, stdout, stderr = self._run_verifier(
            out,
            "--pin-operator-pubkey", signer.public_key.hex(),
            "--pin-checkpoint-key-ids", signer.key_id)
        self.assertEqual(rc, 0, stdout + stderr)
        self.assertIn("VERIFIED", stdout + stderr)

    def test_verifier_rejects_forged_entry_sig(self):
        # Wrong-key forgery (adversarial, not garbage): the entry's
        # ed_sig is a *valid* Ed25519 signature from a different key,
        # while sig_key_id still names the real key. V9d must fail.
        from gov.log import _entry_sig_body
        from gov.signing import Ed25519Signer as _Evil
        _lg, signer = self._signed_log(n=4)
        out, _payload, _manifest = self._assemble(self.log_path, signer)
        evil = _Evil(secrets.token_bytes(32))
        with open(os.path.join(out, "log_slice.jsonl")) as f:
            entries = [json.loads(line) for line in f if line.strip()]
        entries[1]["ed_sig"] = evil.sign(
            _entry_sig_body(entries[1])).hex()
        with open(os.path.join(out, "log_slice.jsonl"), "w") as f:
            for e in entries:
                f.write(json.dumps(e, sort_keys=True) + "\n")
        self._redigest(out)
        rc, stdout, stderr = self._run_verifier(out)
        self.assertEqual(rc, 1, stdout + stderr)
        self.assertIn("V9d", stdout + stderr)

    def test_verifier_rejects_stripped_entry_sigs(self):
        # Stripping ed_sig does not break inclusion proofs (the leaf
        # deliberately excludes the sig envelope so re-signing never
        # changes tree roots) -- the manifest-bound signed_entries
        # count is what catches the strip.
        _lg, signer = self._signed_log(n=4)
        out, _payload, _manifest = self._assemble(self.log_path, signer)
        with open(os.path.join(out, "log_slice.jsonl")) as f:
            entries = [json.loads(line) for line in f if line.strip()]
        for e in entries:
            e.pop("ed_sig", None)
            e.pop("sig_key_id", None)
        with open(os.path.join(out, "log_slice.jsonl"), "w") as f:
            for e in entries:
                f.write(json.dumps(e, sort_keys=True) + "\n")
        self._redigest(out)
        rc, stdout, stderr = self._run_verifier(out)
        self.assertEqual(rc, 1, stdout + stderr)

    def _v9d_check(self, entry, key_ids, envelope):
        # Direct unit pin for V9d branches that the full bundle
        # pipeline cannot reach end-to-end (assemble() already refuses
        # unshippable envelopes; V8 fails before V9d on bad
        # checkpoints) -- defense-in-depth for hand-rolled bundles.
        from types import SimpleNamespace
        import gov.evidence_verify as ev
        ctx = SimpleNamespace(
            manifest={"audit_entry_signing": {
                "key_ids": key_ids,
                "signed_entries": 1, "total_entries": 1}},
            slice_entries=[entry],
            cp_envelope=envelope)
        return ev.v9d_entry_signatures(ctx)

    def _first_signed_entry(self):
        from gov.log import read_entries
        _lg, signer = self._signed_log(n=1)
        entry = read_entries(self.log_path)[0]
        self.assertIn("ed_sig", entry)
        return entry, signer

    def test_v9d_rejects_unbound_key_id(self):
        # The entry carries a VALID signature, but sig_key_id names a
        # key the manifest block does not bind: fail closed before any
        # crypto runs.
        from gov.signing import Ed25519Signer
        entry, signer = self._first_signed_entry()
        stranger = Ed25519Signer(secrets.token_bytes(32))
        entry["sig_key_id"] = stranger.key_id
        check = self._v9d_check(
            entry, [signer.key_id],
            [{"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}])
        self.assertEqual(check.id, "V9d")
        self.assertEqual(check.status, "fail")
        self.assertIn("not bound", check.detail)

    def test_v9d_rejects_missing_envelope_key(self):
        # The manifest binds the entry's key, but the shipped
        # checkpoint_keys envelope does not carry it: offline
        # verification is impossible, so fail closed.
        from gov.signing import Ed25519Signer
        entry, signer = self._first_signed_entry()
        stranger = Ed25519Signer(secrets.token_bytes(32))
        check = self._v9d_check(
            entry, [signer.key_id],
            [{"key_id": stranger.key_id,
              "public_key_hex": stranger.public_key.hex()}])
        self.assertEqual(check.id, "V9d")
        self.assertEqual(check.status, "fail")
        self.assertIn("not in the", check.detail)

    def test_assemble_refuses_unshipped_entry_key(self):
        # The envelope must cover every entry sig_key_id in the
        # window: a bundle whose entries name an unshipped key could
        # never pass V9d, so assemble() refuses it at build time.
        # Checkpoint sigs are stripped to isolate the entry branch
        # (the harness uses one key for both; the checkpoint branch is
        # pinned by the pre-existing coverage test).
        from gov.evidence_bundle import (
            EvidenceBundle, EvidenceBundleError,
            log_evidence_bundle_receipt)
        from gov.log import ActionLog
        from gov.signing import Ed25519Signer
        _lg, signer = self._signed_log(n=4)
        eb = EvidenceBundle(self.log_path,
                            exported_at="2026-09-28T00:00:00+00:00",
                            operator_id="lane-a-test")
        payload = eb.build()
        manifest = eb.seal(payload, signer=signer)
        for cp in manifest.get("checkpoints", []):
            cp["sigs"] = []
        log_evidence_bundle_receipt(
            manifest, ActionLog(self.log_path, signer=signer,
                                deployment_mode="staging"),
            signer=signer)
        stranger = Ed25519Signer(secrets.token_bytes(32))
        op = {"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}
        out = os.path.join(self.tmp.name, "bundle-unshipped-key")
        with self.assertRaises(EvidenceBundleError) as cm:
            eb.assemble(payload, manifest, operator_key=op,
                        checkpoint_keys=[{
                            "key_id": stranger.key_id,
                            "public_key_hex": stranger.public_key.hex()}],
                        out_dir=out)
        self.assertIn("entry signers", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
