"""Tests for the §5 deterministic assessment bundle.

gov/safeguard_bundle.py — bundle_assemble()/bundle_verify(): the
self-contained, deterministic transport bundle that closes the spec
§5 gap (KNOWN DEBT in log_benchmark_receipt): trusted checkpoint
heads and the operator's public key travel WITH the bundle, so a
third party verifies with zero out-of-band inputs.

$0 spend, synthetic/local only. Keys are fresh random per test via the
explicit GOV_LOG_KEY env backend (same production path tests use).

Seams under test (pre-agreed): bundle_assemble(), bundle_verify().
Red-first: these tests were written before the module existed.
"""

import copy
import hashlib
import json
import os
import secrets
import tempfile
import unittest

_KEY_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _provision_key():
    saved = {k: os.environ.get(k) for k in _KEY_VARS}
    os.environ["GOV_LOG_KEY"] = secrets.token_bytes(32).hex()
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)

    def restore():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return restore


def _write_battery(records):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(records, f)
    return path


def _append(log, event, **kw):
    rec = {"event": event}
    rec.update(kw)
    return log.append(rec)


def _build_sar_log(path, signer=None):
    """Synthetic governed-deployment log for SAR bundle tests."""
    from gov.log import ActionLog
    log = ActionLog(path, signer=signer)
    _append(log, "tool_call", tool="read_file", agent_id="a1", run_id="r1",
            decision="allow", policy_id="p-default")
    _append(log, "tool_call", tool="send_email", agent_id="a1",
            run_id="r1", decision="queued_pending",
            policy_id="p-critical", approval_id="A-1")
    _append(log, "approval_decision", agent_id="human",
            run_id="r1", decision="approved", approval_id="A-1",
            policy_id="p-critical")
    _append(log, "detector_trip", agent_id="monitor", run_id="r1",
            decision="escalated", policy_id="detection-breaker",
            reason="velocity breaker tripped")
    return log


def _redigest(bundle_dir):
    """Test-side adversarial helper: recompute and rewrite the bundle
    digest after a post-assembly file swap, simulating an attacker who
    re-digests their tampering. Uses the library's pure digest
    function so the test asserts against the library's own rule."""
    from gov.safeguard_bundle import compute_bundle_digest, DIGEST_FILE
    digest = compute_bundle_digest(bundle_dir)
    with open(os.path.join(bundle_dir, DIGEST_FILE), "w",
              encoding="utf-8") as f:
        f.write(digest + "\n")
    return digest


class TestSafeguardBundle(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        self.battery_path = _write_battery([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "stopped"},
            {"id": "p2", "category": "sandbox_escape",
             "verdict": "stopped"},
        ])

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()
        os.unlink(self.battery_path)

    # -- fixtures ----------------------------------------------------

    def _signer(self):
        from gov.signing import Ed25519Signer
        return Ed25519Signer(secrets.token_bytes(32))

    def _sealed_pair(self, signer):
        """Build + seal a SAR and append its chained receipt.

        Returns (report, manifest). Mirrors the production order:
        build -> seal(signer) -> log_benchmark_receipt.
        """
        from gov.log import ActionLog
        from gov.safeguard_benchmark import (
            SafeguardAssessment, log_benchmark_receipt)
        _build_sar_log(self.log_path, signer=signer)
        sa = SafeguardAssessment(self.log_path, self.battery_path)
        rep = sa.build()
        manifest = sa.seal(rep, signer=signer)
        log_benchmark_receipt(
            manifest, ActionLog(self.log_path, signer=signer))
        return rep, manifest

    def _keys(self, signer):
        op = {"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}
        return op, [dict(op)]

    def _assemble(self, rep, manifest, signer, name="bundle"):
        from gov.safeguard_bundle import bundle_assemble
        op, cp_keys = self._keys(signer)
        out_dir = os.path.join(self.tmp.name, name)
        return bundle_assemble(rep, manifest, operator_key=op,
                               checkpoint_keys=cp_keys, out_dir=out_dir)

    # -- slice 1: round trip ------------------------------------------

    def test_assemble_then_verify_passes_with_zero_out_of_band_inputs(self):
        # The evaluator's ONLY input is the bundle directory: no log
        # access, no env, no config, no network.
        from gov.safeguard_bundle import bundle_verify
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        info = self._assemble(rep, manifest, signer)
        out = bundle_verify(info["bundle_dir"])
        self.assertTrue(out["passed"], out["failures"])
        self.assertTrue(out["bundle_digest_ok"])
        self.assertEqual(out["report_id"],
                         rep["report_id"]["value"])
        # The bundle carries every file the procedure needs.
        for rel in ("report.json", "manifest.json",
                    "checkpoints.jsonl",
                    "keys/operator_ed25519.json",
                    "keys/checkpoint_keys.json",
                    "VERSION", "VERIFY.txt"):
            self.assertTrue(os.path.isfile(
                os.path.join(info["bundle_dir"], rel)), rel)
        # The seven §4 checks ran inside the bundle verification.
        steps = [c["step"] for c in out["checks"]
                 if c.get("layer") == "section4"]
        self.assertEqual(sorted(steps), [1, 2, 3, 4, 5, 6, 7])

    def test_assemble_does_not_mutate_its_inputs(self):
        from gov.safeguard_benchmark import SafeguardAssessment
        from gov.safeguard_bundle import bundle_assemble
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        before = (SafeguardAssessment.canonical(rep),
                  SafeguardAssessment.canonical(manifest))
        op, cp_keys = self._keys(signer)
        bundle_assemble(rep, manifest, operator_key=op,
                        checkpoint_keys=cp_keys,
                        out_dir=os.path.join(self.tmp.name, "b"))
        after = (SafeguardAssessment.canonical(rep),
                 SafeguardAssessment.canonical(manifest))
        self.assertEqual(before, after)

    # -- slice 2: tampered SAR ----------------------------------------

    def test_tampered_sar_inside_bundle_fails(self):
        from gov.safeguard_bundle import bundle_verify
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        info = self._assemble(rep, manifest, signer)
        # Attacker flips the verdict byte inside the shipped report.
        rp = os.path.join(info["bundle_dir"], "report.json")
        with open(rp, "rb") as f:
            raw = f.read()
        self.assertIn(b"INSUFFICIENT", raw)
        with open(rp, "wb") as f:
            f.write(raw.replace(b"INSUFFICIENT", b"SUFFICIENT", 1))
        out = bundle_verify(info["bundle_dir"])
        self.assertFalse(out["passed"])
        self.assertFalse(out["bundle_digest_ok"])
        self.assertTrue(any("digest" in f for f in out["failures"]),
                        out["failures"])

    # -- slice 3: swapped checkpoint head -------------------------------

    def test_swapped_checkpoint_head_fails(self):
        # Adversarial: the shipped checkpoints.jsonl is replaced with
        # heads from a DIFFERENT log (different checkpoint key) and the
        # bundle digest is re-computed, so the swap must still die on
        # the checkpoint-signature / head-binding layer — not on the
        # digest, which any attacker can re-compute.
        from gov.log import ActionLog
        from gov.safeguard_bundle import bundle_verify
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        info = self._assemble(rep, manifest, signer)
        foreign_signer = self._signer()
        foreign_log = os.path.join(self.tmp.name, "foreign.log")
        foreign = ActionLog(foreign_log, signer=foreign_signer)
        _append(foreign, "tool_call", tool="read_file")
        foreign_heads = os.path.join(self.tmp.name, "checkpoints.jsonl")
        with open(foreign_heads, "r", encoding="utf-8") as f:
            heads = f.read()
        self.assertTrue(heads.strip())
        with open(os.path.join(info["bundle_dir"],
                               "checkpoints.jsonl"),
                  "w", encoding="utf-8") as f:
            f.write(heads)
        _redigest(info["bundle_dir"])
        out = bundle_verify(info["bundle_dir"])
        self.assertFalse(out["passed"])
        self.assertTrue(out["bundle_digest_ok"])  # digest re-done
        self.assertTrue(any("checkpoint" in f for f in out["failures"]),
                        out["failures"])

    # -- slice 4: unsigned bundle fails closed --------------------------

    def test_missing_operator_key_fails_closed(self):
        # The key envelope loses the operator key: no authorship, no
        # verification. Fail closed by name, not by implication.
        from gov.safeguard_bundle import bundle_verify
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        info = self._assemble(rep, manifest, signer)
        os.unlink(os.path.join(info["bundle_dir"], "keys",
                               "operator_ed25519.json"))
        _redigest(info["bundle_dir"])
        out = bundle_verify(info["bundle_dir"])
        self.assertFalse(out["passed"])
        self.assertTrue(any("operator" in f and "key" in f
                            for f in out["failures"]),
                        out["failures"])

    def test_unsealed_manifest_fails_closed_in_bundle(self):
        # scheme="none" manifest inside a bundle: the bundle is a
        # third-party transport, so an unsealed manifest fails closed
        # (verify_report's expect_sealed=True path).
        from gov.safeguard_bundle import bundle_verify
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        manifest = copy.deepcopy(manifest)
        manifest["signing"] = {"scheme": "none",
                               "note": "test downgrade"}
        # Re-seal would be needed for a real seal; here the point is
        # the bundle carries an unsealed manifest: assemble must still
        # write it (faithful transport), verify must fail closed.
        info = self._assemble(rep, manifest, signer)
        out = bundle_verify(info["bundle_dir"])
        self.assertFalse(out["passed"])
        self.assertTrue(any("step 5" in f for f in out["failures"]),
                        out["failures"])

    # -- slice 5: determinism -------------------------------------------

    def test_two_assemblies_of_identical_inputs_are_byte_identical(self):
        from gov.safeguard_bundle import bundle_assemble
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        op, cp_keys = self._keys(signer)
        a = bundle_assemble(rep, manifest, operator_key=op,
                            checkpoint_keys=cp_keys,
                            out_dir=os.path.join(self.tmp.name, "a"))
        # Independent second assembly of the identical inputs.
        b = bundle_assemble(copy.deepcopy(rep),
                            copy.deepcopy(manifest),
                            operator_key=dict(op),
                            checkpoint_keys=[dict(k)
                                             for k in cp_keys],
                            out_dir=os.path.join(self.tmp.name, "b"))
        self.assertEqual(a["bundle_digest"], b["bundle_digest"])
        self.assertEqual(set(a["files"]), set(b["files"]))
        for rel in a["files"]:
            with open(os.path.join(a["bundle_dir"], rel), "rb") as f:
                ba = f.read()
            with open(os.path.join(b["bundle_dir"], rel), "rb") as f:
                bb = f.read()
            self.assertEqual(ba, bb, rel)

    # -- slice 6: assemble fail-closed inputs -----------------------------

    def test_assemble_refuses_foreign_schema_version(self):
        from gov.safeguard_bundle import (
            bundle_assemble, SafeguardBundleError)
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        manifest = copy.deepcopy(manifest)
        manifest["schema_version"] = "safeguard-assessment/9.9"
        op, cp_keys = self._keys(signer)
        with self.assertRaises(SafeguardBundleError):
            bundle_assemble(rep, manifest, operator_key=op,
                            checkpoint_keys=cp_keys,
                            out_dir=os.path.join(self.tmp.name, "x"))

    def test_assemble_refuses_manifest_without_receipt(self):
        # A bundle that can never pass verify_report step 6 is a lie:
        # refuse to assemble it.
        from gov.safeguard_bundle import (
            bundle_assemble, SafeguardBundleError)
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        manifest = copy.deepcopy(manifest)
        del manifest["receipt"]
        op, cp_keys = self._keys(signer)
        with self.assertRaises(SafeguardBundleError):
            bundle_assemble(rep, manifest, operator_key=op,
                            checkpoint_keys=cp_keys,
                            out_dir=os.path.join(self.tmp.name, "y"))

    def test_assemble_refuses_malformed_operator_key(self):
        from gov.safeguard_bundle import (
            bundle_assemble, SafeguardBundleError)
        signer = self._signer()
        rep, manifest = self._sealed_pair(signer)
        _op, cp_keys = self._keys(signer)
        with self.assertRaises(SafeguardBundleError):
            bundle_assemble(rep, manifest,
                            operator_key={"key_id": "x"},
                            checkpoint_keys=cp_keys,
                            out_dir=os.path.join(self.tmp.name, "z"))

    def test_verify_nonexistent_dir_fails_closed(self):
        from gov.safeguard_bundle import bundle_verify
        out = bundle_verify(os.path.join(self.tmp.name, "nope"))
        self.assertFalse(out["passed"])
        self.assertTrue(out["failures"])


class TestF151BundlePinning(unittest.TestCase):
    """F151 red-first: authorship pinning for bundle_verify.

    The bundle's key envelope is self-asserted by whoever assembled
    the bundle; bundle_verify(bundle_dir) alone proves
    self-consistency, not authorship. Optional expected-key pinning
    lets Victor bind the bundle to the operator's out-of-band key.
    """

    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        self.battery_path = _write_battery([
            {"id": "p1", "category": "prompt_injection",
             "verdict": "stopped"},
        ])
        self.signer = self._signer()
        self.rep, self.manifest = self._sealed_pair(self.signer)
        op, cp_keys = self._keys(self.signer)
        from gov.safeguard_bundle import bundle_assemble
        self.info = bundle_assemble(
            self.rep, self.manifest, operator_key=op,
            checkpoint_keys=cp_keys,
            out_dir=os.path.join(self.tmp.name, "bundle"))
        self.op_key_id = self.signer.key_id
        self.op_key_hex = self.signer.public_key.hex()
        self.cp_key_ids = [self.op_key_id]

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()
        os.unlink(self.battery_path)

    # -- fixtures (same as TestSafeguardBundle) -----------------------

    def _signer(self):
        from gov.signing import Ed25519Signer
        return Ed25519Signer(secrets.token_bytes(32))

    def _sealed_pair(self, signer):
        from gov.log import ActionLog
        from gov.safeguard_benchmark import (
            SafeguardAssessment, log_benchmark_receipt)
        _build_sar_log(self.log_path, signer=signer)
        sa = SafeguardAssessment(self.log_path, self.battery_path)
        rep = sa.build()
        manifest = sa.seal(rep, signer=signer)
        log_benchmark_receipt(
            manifest, ActionLog(self.log_path, signer=signer))
        return rep, manifest

    def _keys(self, signer):
        op = {"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}
        return op, [dict(op)]

    def _pin_check(self, out):
        for c in out["checks"]:
            if c.get("step") == "B6":
                return c
        return None

    # -- pinning behavior ------------------------------------------------

    def test_pinned_operator_key_correct_verifies(self):
        from gov.safeguard_bundle import bundle_verify
        out = bundle_verify(
            self.info["bundle_dir"],
            expected_operator_key_id=self.op_key_id)
        self.assertTrue(out["passed"], out["failures"])
        b6 = self._pin_check(out)
        self.assertIsNotNone(b6)
        self.assertEqual(b6["status"], "pass")

    def test_pinned_operator_key_wrong_key_id_fails_closed(self):
        from gov.safeguard_bundle import bundle_verify
        out = bundle_verify(
            self.info["bundle_dir"],
            expected_operator_key_id="mallory-key-id")
        self.assertFalse(out["passed"])
        self.assertTrue(any("B6" in f or "pin" in f.lower()
                            for f in out["failures"]),
                        out["failures"])
        # Fatal: §4 is not run against the wrong operator's keys.
        self.assertFalse(any(c.get("layer") == "section4"
                             for c in out["checks"]))

    def test_pinned_operator_public_key_wrong_hex_fails_closed(self):
        from gov.safeguard_bundle import bundle_verify
        other = self._signer()
        out = bundle_verify(
            self.info["bundle_dir"],
            expected_operator_public_key_hex=other.public_key.hex())
        self.assertFalse(out["passed"], out["checks"])

    def test_checkpoint_pinning_mismatch_fails_closed(self):
        from gov.safeguard_bundle import bundle_verify
        out = bundle_verify(
            self.info["bundle_dir"],
            expected_checkpoint_key_ids=["some-other-key"])
        self.assertFalse(out["passed"])
        self.assertTrue(any("B6" in f or "pin" in f.lower()
                            for f in out["failures"]),
                        out["failures"])

    def test_unpinned_verifies_but_flags_self_consistency_only(self):
        # Pinning-off is NOT silent: the bundle verifies, but the B6
        # check is explicitly not_applicable and names the residual.
        from gov.safeguard_bundle import bundle_verify
        out = bundle_verify(self.info["bundle_dir"])
        self.assertTrue(out["passed"], out["failures"])
        b6 = self._pin_check(out)
        self.assertIsNotNone(b6)
        self.assertEqual(b6["status"], "not_applicable")
        self.assertIn("out-of-band", b6["detail"])

    def test_malformed_pin_fails_loud(self):
        # A typo'd pin must never silently pass.
        from gov.safeguard_bundle import (
            bundle_verify, SafeguardBundleError)
        with self.assertRaises(SafeguardBundleError):
            bundle_verify(
                self.info["bundle_dir"],
                expected_operator_public_key_hex="zzzz")

    def test_assemble_refuses_mismatched_operator_key(self):
        # p4 INFO footgun: the assembler will not silently ship a
        # bundle whose operator key differs from the manifest seal's.
        from gov.safeguard_bundle import (
            bundle_assemble, SafeguardBundleError)
        wrong = self._signer()
        op = {"key_id": wrong.key_id,
              "public_key_hex": wrong.public_key.hex()}
        _good, cp_keys = self._keys(self.signer)
        with self.assertRaises(SafeguardBundleError):
            bundle_assemble(self.rep, self.manifest, operator_key=op,
                            checkpoint_keys=cp_keys,
                            out_dir=os.path.join(self.tmp.name,
                                                 "mismatch"))


if __name__ == "__main__":
    unittest.main()
