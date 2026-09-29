"""Verifier + tamper battery for evidence bundle v1 (spec §6: T1–T10).

Runs the REAL standalone verifier (tools/evidence-verify) as a
subprocess under the system python3 — no venv, no repo on sys.path —
proving the stdlib-only claim. Each tamper targets exactly one check;
the battery asserts the verifier fails LOUDLY (exit 1) with the right
check named, and that untampered bundles verify (exit 0 pinned,
exit 2 unpinned).

Red-first: these tests were written before gov/evidence_verify.py
existed and failed on FileNotFoundError.
"""

import hashlib
import json
import os
import re
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


def _signer(seed_byte="11"):
    from gov.signing import Ed25519Signer
    return Ed25519Signer(bytes.fromhex(seed_byte * 32))


def _build_log(path, signer):
    from gov.log import ActionLog
    log = ActionLog(path, signer=signer, deployment_mode="staging")
    log.append({"event": "policy_loaded", "policy_version": "p1",
                "policy_hash": "h" * 16, "policy_path": "policies/p1.yaml",
                "pinned": True})
    for i in range(3):
        log.append({"event": "tool_call", "decision": "allow",
                    "tool": "tool-%d" % i})
    return log


def _redigest(bundle_dir):
    from gov.safeguard_bundle import compute_bundle_digest
    digest = compute_bundle_digest(bundle_dir)
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w") as f:
        f.write(digest + "\n")
    return digest


class _VerifyBase(unittest.TestCase):
    def setUp(self):
        # Hermetic key provisioning via the shared tests/keyfixture.py
        # (explicit production env-backend path, fresh random key).
        self._restore = scrub_key_env()
        provision_test_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        self.signer = _signer()
        _build_log(self.log_path, self.signer)
        self.bundle_dir, self.payload, self.manifest = self._assemble()

    def tearDown(self):
        self.tmp.cleanup()
        self._restore()

    def _assemble(self, name="bundle"):
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        eb = EvidenceBundle(self.log_path,
                            exported_at="2026-09-26T00:00:00+00:00",
                            operator_id="tamper-battery")
        payload = eb.build()
        manifest = eb.seal(payload, signer=self.signer)
        log_evidence_bundle_receipt(
            manifest, ActionLog(self.log_path, signer=self.signer,
                                deployment_mode="staging"),
            signer=self.signer)
        op = {"key_id": self.signer.key_id,
              "public_key_hex": self.signer.public_key.hex()}
        out = os.path.join(self.tmp.name, name)
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        return out, payload, manifest

    def _run(self, bundle_dir, *args):
        cmd = [PYTHON3, VERIFY_SCRIPT, bundle_dir] + list(args)
        env = {k: v for k, v in os.environ.items()
               if k != "PYTHONPATH"}
        # Prove stdlib-only: the verifier must not see the repo.
        env.pop("PYTHONPATH", None)
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              env=env, cwd="/tmp")
        return proc.returncode, proc.stdout, proc.stderr

    def _rewrite(self, rel, obj):
        """Rewrite a JSON bundle file (canonical + newline)."""
        from gov.evidence_bundle import canonical
        with open(os.path.join(self.bundle_dir, rel), "wb") as f:
            f.write(canonical(obj) + b"\n")


class TestEvidenceVerifyTamper(_VerifyBase):
    """T1–T10: each tamper must fail loudly with the right check."""

    def test_t1_bitflip_evidence_json(self):
        p = os.path.join(self.bundle_dir, "evidence.json")
        data = bytearray(open(p, "rb").read())
        data[100] ^= 0x01
        open(p, "wb").write(bytes(data))
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V3 V3 transport digest")

    def test_t2_signature_tampered(self):
        man = dict(self.manifest)
        man["signing"] = dict(man["signing"])
        sig = man["signing"]["signature_hex"]
        man["signing"]["signature_hex"] = (
            ("0" if sig[0] != "0" else "1") + sig[1:])
        self._rewrite("manifest.json", man)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(
            self.bundle_dir, "--pin-operator-pubkey",
            self.signer.public_key.hex())
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V7 V7 operator signature")

    def test_t3_checkpoint_sig_removed(self):
        p = os.path.join(self.bundle_dir, "checkpoints.jsonl")
        heads = [json.loads(l) for l in open(p) if l.strip()]
        heads[0]["sigs"] = []
        with open(p, "w") as f:
            for h in heads:
                f.write(json.dumps(h, sort_keys=True) + "\n")
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V8 V8 checkpoint signatures")

    def test_t4_slice_entry_altered(self):
        p = os.path.join(self.bundle_dir, "log_slice.jsonl")
        lines = open(p).read().splitlines()
        e = json.loads(lines[1])
        e["decision"] = "deny"  # was "allow"
        lines[1] = json.dumps(e, sort_keys=True)
        open(p, "w").write("\n".join(lines) + "\n")
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 1)
        # Digest recomputed, so V1 passes; the bundle-vs-slice
        # cross-check in V8 catches the alteration.
        self.assertRegex(out, r"\[PASS\] V3 V3 transport digest")
        self.assertRegex(out, r"\[FAIL\] V8 V8 checkpoint signatures")

    def test_t5_receipt_prev_hash_dropped(self):
        p = os.path.join(self.bundle_dir, "receipt.json")
        r = json.load(open(p))
        r["entry"]["prev_hash"] = "0" * 64
        self._rewrite("receipt.json", r)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V12 V12 export receipt")

    def test_t6_operator_envelope_key_swapped(self):
        other = _signer("22")
        env = {"key_id": other.key_id,
               "public_key_hex": other.public_key.hex()}
        self._rewrite("keys/operator_ed25519.json", env)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(
            self.bundle_dir, "--pin-operator-pubkey",
            other.public_key.hex())
        self.assertEqual(code, 1)
        # The pin matches the envelope, but the envelope key did not
        # sign the manifest.
        self.assertRegex(out, r"\[FAIL\] V7 V7 operator signature")

    def test_t7_provenance_dropped_resigned(self):
        """A builder that drops provenance must not slip past V10.

        The tamperer re-signs (has the key) so V4/V5/V7 all pass and
        the failure lands exactly on V10.
        """
        from gov.evidence_bundle import EvidenceBundle, canonical
        payload = json.loads(json.dumps(self.payload))
        del payload["policy"]["policy_version"]["provenance"]
        # Recompute identity + seal with the same operator key.
        probe = json.loads(json.dumps(payload))
        probe["bundle_meta"]["bundle_id"] = None
        payload["bundle_meta"]["bundle_id"] = (
            "EVB-" + hashlib.sha256(canonical(probe)).hexdigest()[:16])
        man = json.loads(json.dumps(self.manifest))
        man["bundle_id"] = payload["bundle_meta"]["bundle_id"]
        man["export_sha256"] = hashlib.sha256(
            canonical(payload)).hexdigest()
        eb = EvidenceBundle(self.log_path)
        sig = self.signer.sign(eb.signed_body(man))
        man["signing"]["signature_hex"] = sig.hex()
        self._rewrite("evidence.json", payload)
        self._rewrite("manifest.json", man)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[PASS\] V7 V7 operator signature")
        self.assertRegex(out, r"\[FAIL\] V15 V15 provenance")

    def test_t8_inclusion_proof_corrupted(self):
        man = json.loads(json.dumps(self.manifest))
        b = man["inclusion_bundles"][0]["bundle"]
        p0 = b["proof"][0]
        b["proof"][0] = ("0" if p0[0] != "0" else "1") + p0[1:]
        self._rewrite("manifest.json", man)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V9 V9 log-slice integrity")

    def test_t9_digest_truncated(self):
        p = os.path.join(self.bundle_dir, "BUNDLE_DIGEST.sha256")
        open(p, "w").write("abc123\n")
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V3 V3 transport digest")

    def test_t10_unpinned_exit_2_and_pinned_exit_0(self):
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 2)
        self.assertIn("SELF_CONSISTENT", out)
        code, out, _ = self._run(
            self.bundle_dir, "--pin-operator-pubkey",
            self.signer.public_key.hex())
        self.assertEqual(code, 0)
        self.assertIn("VERIFIED", out)
        # Wrong pin: authorship fails loudly, never silently.
        code, out, _ = self._run(
            self.bundle_dir, "--pin-operator-pubkey", "00" * 32)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V6 V6 authorship pin")

    def test_t11_manifest_checkpoints_must_match_signed_digest(self):
        # The manifest's embedded checkpoints are bound to the signed
        # checkpoints_digest; swapping the embedded copy (without
        # touching the digest or the signature) must fail V8 loudly.
        man = dict(self.manifest)
        man["checkpoints"] = [{}]
        self._rewrite("manifest.json", man)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(
            self.bundle_dir, "--pin-operator-pubkey",
            self.signer.public_key.hex())
        self.assertEqual(code, 1)
        self.assertRegex(
            out, r"\[FAIL\] V8 V8 checkpoint signatures.*"
                 r"do not hash to the signed checkpoints_digest")

    def test_t12_hostile_inclusion_bundle_crashes_clean(self):
        # inclusion_bundles is not covered by the operator signature; a
        # non-object entry would crash V8 with a bare AttributeError.
        # The outer guard must turn it into a named FAIL (exit 1, no
        # traceback on stderr).
        man = dict(self.manifest)
        man["inclusion_bundles"] = [5]
        self._rewrite("manifest.json", man)
        _redigest(self.bundle_dir)
        code, out, err = self._run(
            self.bundle_dir, "--pin-operator-pubkey",
            self.signer.public_key.hex())
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] V0 bundle fatal", out)
        self.assertNotIn("Traceback", err)


class TestEvidenceVerifyFormat(unittest.TestCase):
    def test_json_format_carries_honesty_footer(self):
        base = _VerifyBase()
        base.setUp()
        try:
            code, out, _ = base._run(base.bundle_dir, "--format", "json")
            self.assertEqual(code, 2)  # unpinned
            doc = json.loads(out)
            self.assertEqual(doc["verdict"], "SELF_CONSISTENT")
            self.assertIn("what_this_does_not_prove", doc)
            # Spec §4.3: the honesty footer is a list in JSON output.
            self.assertIsInstance(doc["what_this_does_not_prove"], list)
            self.assertTrue(any("unpinned" in s.lower()
                                for s in doc["what_this_does_not_prove"]))
            # Spec §4.3: authorship is {"pinned": bool, "key_id": str|null}.
            self.assertIsInstance(doc["authorship"], dict)
            self.assertFalse(doc["authorship"]["pinned"])
            self.assertIsNone(doc["authorship"]["key_id"])
            # 19 checks since wave-209 lane A: V18 "claim bounds" added
            # the claim-bounds check to the standalone verifier (was 18
            # since wave-179's V9d; wave-175's V17 before that).
            self.assertEqual(len(doc["checks"]), 19)
        finally:
            base.tearDown()

    def test_usage_error_exit_3(self):
        proc = subprocess.run(
            [PYTHON3, VERIFY_SCRIPT, "/nonexistent-dir-xyz"],
            capture_output=True, text=True, cwd="/tmp")
        self.assertEqual(proc.returncode, 3)  # config error, not a bundle
        proc = subprocess.run(
            [PYTHON3, VERIFY_SCRIPT], capture_output=True, text=True,
            cwd="/tmp")
        self.assertEqual(proc.returncode, 3)  # argparse usage error


class TestEvidenceVerifyUnversionedPolicy(_VerifyBase):
    """Spec §4.1.1 item 3: a policy_loaded event with no policy_version
    field renders the payload policy_version as "unversioned"; V11 must
    apply the same rendering rule and pass — a genuine bundle must
    verify."""

    def _build_unversioned_log(self, path, signer):
        from gov.log import ActionLog
        log = ActionLog(path, signer=signer, deployment_mode="staging")
        log.append({"event": "policy_loaded",
                    "policy_hash": "h" * 16,
                    "policy_path": "policies/p1.yaml", "pinned": True})
        log.append({"event": "tool_call", "decision": "allow",
                    "tool": "tool-x"})
        return log

    def test_unversioned_policy_genuine_bundle_verifies(self):
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        # One log per directory: gov/log.py keeps the checkpoint sidecar
        # (checkpoints.jsonl) per parent directory, so a second log needs
        # its own subdirectory (same convention as every other test).
        uv_dir = os.path.join(self.tmp.name, "uv")
        os.mkdir(uv_dir)
        uv_path = os.path.join(uv_dir, "audit-uv.log")
        self._build_unversioned_log(uv_path, self.signer)
        eb = EvidenceBundle(uv_path,
                            exported_at="2026-09-26T00:00:00+00:00",
                            operator_id="unversioned-test")
        payload = eb.build()
        self.assertEqual(
            payload["policy"]["policy_version"]["value"], "unversioned",
            "builder must render missing policy_version as 'unversioned'")
        manifest = eb.seal(payload, signer=self.signer)
        log_evidence_bundle_receipt(
            manifest, ActionLog(uv_path, signer=self.signer,
                                deployment_mode="staging"),
            signer=self.signer)
        op = {"key_id": self.signer.key_id,
              "public_key_hex": self.signer.public_key.hex()}
        out = os.path.join(self.tmp.name, "bundle-uv")
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        code, stdout, _stderr = self._run(
            out, "--pin-operator-pubkey", self.signer.public_key.hex())
        self.assertEqual(code, 0,
                         "genuine bundle with unversioned policy must "
                         "verify; got:\n%s" % stdout)


class TestEvidenceVerifyF173F174(_VerifyBase):
    """F173 (coverage/receipt binding) + F174 (operator_id disclosure).

    Red-first: each test crafts the exact attacker/misleading shape
    from the finding and asserts the verifier's verdict at the public
    seam (real tools/evidence-verify subprocess, exit codes + check
    lines). Nothing here weakens an existing assertion.
    """

    def _pin(self):
        return ["--pin-operator-pubkey", self.signer.public_key.hex()]

    # -- F173 ------------------------------------------------------

    def test_f173_inclusion_strip_fails_v7(self):
        # F1a shape: no-key attacker strips 2 inclusion bundles and
        # adjusts the unsigned counts (no re-sign). The operator-signed
        # claim now binds presence+counts, so V7 must fail — the strip
        # can no longer sail through to VERIFIED.
        man = json.loads(json.dumps(self.manifest))
        n = 0
        for ib in man["inclusion_bundles"]:
            if ib["seq"] in (2, 4):
                ib["bundle"] = None
                ib["unavailable_reason"] = "stripped (simulated)"
                n += 1
        self.assertEqual(n, 2, "fixture must have bundles at seq 2 and 4")
        man["inclusion_coverage"]["with_bundle"] -= n
        self._rewrite("manifest.json", man)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir, *self._pin())
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V7 V7 operator signature")
        self.assertNotIn("verdict: VERIFIED", out)

    def test_f173_receipt_bundle_strip_fails_v12(self):
        # F1b shape: strip receipt.json's own inclusion bundle with a
        # fabricated reason. The transported receipt no longer matches
        # the operator-signed manifest receipt binding -> V12 fails.
        rpath = os.path.join(self.bundle_dir, "receipt.json")
        receipt = json.loads(open(rpath, encoding="utf-8").read())
        self.assertIsNotNone(receipt["bundle"],
                             "fixture receipt must have a bundle")
        receipt["bundle"] = None
        receipt["unavailable_reason"] = "withheld (simulated strip)"
        self._rewrite("receipt.json", receipt)
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir, *self._pin())
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V12 V12 export receipt")
        self.assertNotIn("verdict: VERIFIED", out)

    def test_f173_honest_degraded_bundle_verifies_labeled(self):
        # Honestly-degraded seal: an HMAC-only log has no signed
        # checkpoints, so the operator seals with bundle_present=False
        # + explicit reasons. The signature BINDS that degraded state,
        # so the bundle still verifies — with explicitly labeled reduced
        # coverage (attacker-stripped vs operator-declared-degraded are
        # distinguished by the signature, not by the reason text).
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        d = os.path.join(self.tmp.name, "deg")
        os.mkdir(d)
        lp = os.path.join(d, "audit.log")
        log = ActionLog(lp, signer=None, deployment_mode="staging")
        log.append({"event": "policy_loaded", "policy_version": "p1",
                    "policy_hash": "h" * 16,
                    "policy_path": "policies/p1.yaml", "pinned": True})
        for i in range(3):
            log.append({"event": "tool_call", "decision": "allow",
                        "tool": "tool-%d" % i})
        eb = EvidenceBundle(lp, exported_at="2026-09-26T00:00:00+00:00",
                            operator_id="degraded-test")
        payload = eb.build()
        manifest = eb.seal(payload, signer=self.signer)
        self.assertEqual(manifest["inclusion_coverage"]["with_bundle"], 0)
        self.assertEqual(manifest["inclusion_coverage"]["entries"], 4)
        log_evidence_bundle_receipt(
            manifest, ActionLog(lp, signer=None,
                                deployment_mode="staging"),
            signer=self.signer)
        op = {"key_id": self.signer.key_id,
              "public_key_hex": self.signer.public_key.hex()}
        out = os.path.join(self.tmp.name, "bundle-deg")
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        code, stdout, _ = self._run(out, *self._pin())
        self.assertEqual(code, 0, "honestly-degraded bundle must verify;"
                         " got:\n%s" % stdout)
        self.assertRegex(stdout, r"\[PASS\] V7 V7 operator signature")
        self.assertRegex(stdout, r"\[PASS\] V9 V9 log-slice integrity")
        self.assertIn("0 inclusion bundles verified", stdout)
        self.assertIn("4 reduced-coverage entries", stdout)

    def test_f173_legacy_bundle_refused(self):
        # 1.0 bundles have no coverage/receipt binding: the V1 gate
        # fails them closed with the explicit F173 message (never a
        # silent accept, never a VERIFIED-with-label).
        vpath = os.path.join(self.bundle_dir, "VERSION")
        lines = open(vpath, encoding="utf-8").read().splitlines()
        lines[0] = "evidence-bundle/1.0"
        with open(vpath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        _redigest(self.bundle_dir)
        code, out, _ = self._run(self.bundle_dir, *self._pin())
        self.assertEqual(code, 1)
        self.assertRegex(out, r"\[FAIL\] V1 V1 version gate")
        self.assertIn("legacy bundle", out)
        self.assertIn("F173", out)
        self.assertNotIn("verdict: VERIFIED", out)

    # -- F174 ------------------------------------------------------

    def test_signed_body_builder_verifier_equivalence(self):
        # The builder's EvidenceBundle.signed_body and the standalone
        # verifier's _signed_claim must construct byte-identical signed
        # bodies — otherwise V7 would reject genuine bundles (or, worse,
        # the two sides would disagree on what the signature binds).
        sys.path.insert(0, os.path.join(REPO, "gov"))
        try:
            import evidence_bundle as eb_mod
            import evidence_verify as ev_mod
        finally:
            sys.path.pop(0)
        manifest = json.loads(open(
            os.path.join(self.bundle_dir, "manifest.json"),
            encoding="utf-8").read())
        builder_bytes = eb_mod.EvidenceBundle.signed_body(manifest)
        verifier_bytes = (ev_mod.SIGN_DOMAIN
                          + bytes.fromhex(manifest["export_sha256"])
                          + ev_mod.canonical(
                              ev_mod._signed_claim(manifest)))
        self.assertEqual(builder_bytes, verifier_bytes,
                         "builder and verifier disagree on the signed body")
        # And the receipt-minted manifest (post-receipt re-sign) agrees
        # too: strip the receipt and the bodies must differ (the claim
        # binds the receipt), restore and they agree again.
        no_receipt = json.loads(json.dumps(manifest))
        del no_receipt["receipt"]
        self.assertNotEqual(
            eb_mod.EvidenceBundle.signed_body(no_receipt), builder_bytes)

    def test_f174_claimed_operator_rendered_with_disclaimer(self):
        # Disclosure, not rejection: the operator-supplied operator_id
        # is visible in BOTH text and JSON summaries, always labeled as
        # unverified — while the bundle still verifies exit 0.
        code, out, _ = self._run(self.bundle_dir, *self._pin())
        self.assertEqual(code, 0)
        self.assertIn(
            "claimed operator: tamper-battery "
            "(operator-supplied, not independently verified)", out)
        code, jout, _ = self._run(self.bundle_dir, *self._pin(),
                                  "--format", "json")
        self.assertEqual(code, 0)
        doc = json.loads(jout)
        cop = doc["claimed_operator"]
        self.assertEqual(cop["value"], "tamper-battery")
        self.assertEqual(cop["disclaimer"],
                         "operator-supplied, not independently verified")

    def test_f174_claimed_operator_shown_when_unpinned(self):
        # The disclosure rides the summary on every verdict path, not
        # just the pinned one.
        code, out, _ = self._run(self.bundle_dir)
        self.assertEqual(code, 2)  # unpinned: SELF_CONSISTENT
        self.assertIn("claimed operator: tamper-battery", out)


class TestEvidenceVerifyCrypto(unittest.TestCase):
    def test_rfc8032_vectors(self):
        """Vendored Ed25519 verifies the RFC 8032 §7.1 vectors."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "evidence_verify_mod",
            os.path.join(REPO, "gov", "evidence_verify.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        spec2 = importlib.util.spec_from_file_location(
            "ed25519_mod", os.path.join(REPO, "gov", "ed25519.py"))
        ed = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(ed)
        for i, v in enumerate(ed.RFC8032_VECTORS, 1):
            pk = bytes.fromhex(v["pk"])
            msg = bytes.fromhex(v["msg"])
            sig = bytes.fromhex(v["sig"])
            self.assertTrue(mod.verify(pk, msg, sig),
                            "RFC 8032 TEST %d failed to verify" % i)
            self.assertFalse(mod.verify(pk, msg + b"\x00", sig),
                             "tampered message verified (TEST %d)" % i)

    def test_ed25519_vendoring_drift_guard(self):
        """The vendored section must stay byte-identical to
        gov/ed25519.py (minus its __main__ self-test block)."""
        src = open(os.path.join(REPO, "gov", "ed25519.py")).read()
        src = re.sub(r'\n\nif __name__ == "__main__":\n(?:    .*\n?)+$',
                     "\n", src)
        ver = open(os.path.join(REPO, "gov", "evidence_verify.py")).read()
        begin = "# --- begin vendored gov/ed25519.py (verbatim) ---\n"
        end = "# --- end vendored gov/ed25519.py ---"
        vendored = ver[ver.index(begin) + len(begin):ver.index(end)]
        self.assertEqual(vendored.strip("\n"), src.strip("\n"),
                         "vendored ed25519 drifted from gov/ed25519.py")


if __name__ == "__main__":
    unittest.main()
