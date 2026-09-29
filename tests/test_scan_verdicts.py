#!/usr/bin/env python3
"""Unit tests for gov.scan_verdicts (wave-213 lane A).

Public-seam tests: emission wire rules, verification refusal codes,
policy parsing, gate admission/refusal, and the load_gate wiring.
Deterministic (fixed seeds, fixed clock except where the loader's
verifier clock is intentionally the wall clock); stdlib-only plus gov
modules.
"""

import hashlib
import os
import sys
import time
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import scan_verdicts as sv  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_NOW = 1700000000
_SEED_A = bytes.fromhex("a1" * 32)
_SEED_B = bytes.fromhex("b2" * 32)
_DIGEST = "sha256:" + "aa" * 32
_DIGEST2 = "sha256:" + "bb" * 32
_RULESET = "sha256:" + "cc" * 32


def _keys(seed):
    s = Ed25519Signer(seed)
    return s, [Ed25519Verifier(s.public_key)]


class Emission(unittest.TestCase):
    def test_happy_path_wire_shape(self):
        signer, _ = _keys(_SEED_A)
        env = sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1.4.2",
            scan_target_digest=_DIGEST, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=_NOW - 3600,
            expires_at=_NOW + 86400, signer=signer, now=_NOW)
        self.assertEqual(env["payloadType"],
                         sv.SCAN_VERDICT_PAYLOAD_TYPE)
        self.assertIn("signatures", env)
        self.assertEqual(len(env["signatures"]), 1)

    def test_default_bounds_pinned(self):
        bounds = sv.default_scan_bounds()
        self.assertEqual(set(bounds),
                         {"proves", "does_not_prove",
                          "verifier_assumptions", "scope_limits"})
        self.assertIn("target-is-vulnerability-free",
                      bounds["does_not_prove"])

    def test_eternal_window_refused(self):
        signer, _ = _keys(_SEED_A)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.emit_scan_verdict(
                scanner_name="a", scanner_version="1",
                scan_target_digest=_DIGEST, verdict="pass",
                ruleset_digest=_RULESET, scanned_at=_NOW,
                expires_at=_NOW + sv.MAX_VERDICT_TTL_SECONDS + 1,
                signer=signer, now=_NOW)
        self.assertIn("window_too_long", str(cm.exception))

    def test_missing_expires_at_refused(self):
        signer, _ = _keys(_SEED_A)
        with self.assertRaises(sv.ScanVerdictError):
            sv.emit_scan_verdict(
                scanner_name="a", scanner_version="1",
                scan_target_digest=_DIGEST, verdict="pass",
                ruleset_digest=_RULESET, scanned_at=_NOW,
                expires_at=None, signer=signer, now=_NOW)

    def test_born_stale_refused(self):
        signer, _ = _keys(_SEED_A)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.emit_scan_verdict(
                scanner_name="a", scanner_version="1",
                scan_target_digest=_DIGEST, verdict="pass",
                ruleset_digest=_RULESET, scanned_at=_NOW - 7200,
                expires_at=_NOW - 60, signer=signer, now=_NOW)
        self.assertIn("born_stale", str(cm.exception))

    def test_future_scan_refused(self):
        signer, _ = _keys(_SEED_A)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.emit_scan_verdict(
                scanner_name="a", scanner_version="1",
                scan_target_digest=_DIGEST, verdict="pass",
                ruleset_digest=_RULESET, scanned_at=_NOW + 60,
                expires_at=_NOW + 86400, signer=signer, now=_NOW)
        self.assertIn("future_scan", str(cm.exception))

    def test_bad_verdict_refused(self):
        signer, _ = _keys(_SEED_A)
        with self.assertRaises(sv.ScanVerdictError):
            sv.emit_scan_verdict(
                scanner_name="a", scanner_version="1",
                scan_target_digest=_DIGEST, verdict="maybe",
                ruleset_digest=_RULESET, scanned_at=_NOW - 60,
                expires_at=_NOW + 3600, signer=signer, now=_NOW)

    def test_malformed_digest_pin_refused_not_coerced(self):
        signer, _ = _keys(_SEED_A)
        with self.assertRaises(sv.ScanVerdictError):
            sv.emit_scan_verdict(
                scanner_name="a", scanner_version="1",
                scan_target_digest="aa" * 32, verdict="pass",
                ruleset_digest=_RULESET, scanned_at=_NOW - 60,
                expires_at=_NOW + 3600, signer=signer, now=_NOW)


class Verification(unittest.TestCase):
    def _emit(self, signer, **kw):
        base = dict(scanner_name="scanner-a", scanner_version="1.4.2",
                    scan_target_digest=_DIGEST, verdict="pass",
                    ruleset_digest=_RULESET, scanned_at=_NOW - 3600,
                    expires_at=_NOW + 86400, signer=signer, now=_NOW)
        base.update(kw)
        return sv.emit_scan_verdict(**base)

    def test_verify_roundtrip(self):
        signer, verifiers = _keys(_SEED_A)
        env = self._emit(signer)
        got = sv.verify_scan_verdict(
            env, verifiers=verifiers, scanner_name="scanner-a",
            scan_target_digest=_DIGEST, now=_NOW)
        stmt = got["statement"]
        self.assertEqual(stmt["verdict"], "pass")
        self.assertEqual(got["verified_key_ids"],
                         [verifiers[0].key_id])

    def test_stale_refused(self):
        signer, verifiers = _keys(_SEED_A)
        env = self._emit(signer)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.verify_scan_verdict(
                env, verifiers=verifiers, scanner_name="scanner-a",
                scan_target_digest=_DIGEST, now=_NOW + 90000)
        self.assertIn("stale", str(cm.exception))

    def test_future_scan_refused(self):
        signer, verifiers = _keys(_SEED_A)
        env = self._emit(signer)
        with self.assertRaises(sv.ScanVerdictError):
            sv.verify_scan_verdict(
                env, verifiers=verifiers, scanner_name="scanner-a",
                scan_target_digest=_DIGEST, now=_NOW - 7200)

    def test_wrong_target_refused(self):
        signer, verifiers = _keys(_SEED_A)
        env = self._emit(signer)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.verify_scan_verdict(
                env, verifiers=verifiers, scanner_name="scanner-a",
                scan_target_digest=_DIGEST2, now=_NOW)
        self.assertIn("target_mismatch", str(cm.exception))

    def test_scanner_name_mismatch_refused(self):
        signer, verifiers = _keys(_SEED_A)
        env = self._emit(signer)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.verify_scan_verdict(
                env, verifiers=verifiers, scanner_name="scanner-b",
                scan_target_digest=_DIGEST, now=_NOW)
        self.assertIn("scanner_mismatch", str(cm.exception))

    def test_signature_swap_refused(self):
        signer_b, _ = _keys(_SEED_B)
        _, verifiers_a = _keys(_SEED_A)
        env = self._emit(signer_b)  # B signs, claims A
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.verify_scan_verdict(
                env, verifiers=verifiers_a, scanner_name="scanner-a",
                scan_target_digest=_DIGEST, now=_NOW)
        self.assertIn("signature_invalid", str(cm.exception))

    def test_tampered_payload_refused(self):
        import base64
        import copy
        import json
        signer, verifiers = _keys(_SEED_A)
        env = self._emit(signer)
        tampered = copy.deepcopy(env)
        payload = json.loads(base64.b64decode(tampered["payload"]))
        payload["verdict"] = "fail"
        tampered["payload"] = base64.b64encode(
            json.dumps(payload, sort_keys=True,
                       separators=(",", ":")).encode()).decode()
        with self.assertRaises(sv.ScanVerdictError):
            sv.verify_scan_verdict(
                tampered, verifiers=verifiers, scanner_name="scanner-a",
                scan_target_digest=_DIGEST, now=_NOW)

    def test_error_verdict_verifies(self):
        signer, verifiers = _keys(_SEED_A)
        env = self._emit(signer, verdict="error")
        got = sv.verify_scan_verdict(
            env, verifiers=verifiers, scanner_name="scanner-a",
            scan_target_digest=_DIGEST, now=_NOW)
        self.assertEqual(got["statement"]["verdict"], "error")
        self.assertEqual(got["verified_key_ids"],
                         [verifiers[0].key_id])

    def test_field_refusals_carry_codes(self):
        signer, _ = _keys(_SEED_A)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            sv.emit_scan_verdict(
                scanner_name="", scanner_version="1",
                scan_target_digest=_DIGEST, verdict="pass",
                ruleset_digest=_RULESET, scanned_at=_NOW - 60,
                expires_at=_NOW + 3600, signer=signer, now=_NOW)
        self.assertIn("scan_verdict_bad_scanner_name", str(cm.exception))


class PolicyAndGate(unittest.TestCase):
    def _gate(self, required):
        signer, verifiers = _keys(_SEED_A)
        gate = sv.ScanGate(sv.ScanPolicy(required_scans=required),
                           {"scanner-a": verifiers})
        return signer, verifiers, gate

    def test_default_policy_empty(self):
        p = sv.ScanPolicy()
        self.assertEqual(p.required_scans, ())
        gate = sv.ScanGate(p, {})
        res = gate.check(_DIGEST, [], now=_NOW)
        self.assertTrue(res["ok"])

    def test_policy_roundtrip(self):
        p = sv.ScanPolicy.from_dict({"required_scans": ["a", "b"]})
        self.assertEqual(p.to_dict(), {"required_scans": ["a", "b"]})

    def test_policy_rejects_duplicates(self):
        with self.assertRaises(sv.ScanVerdictError):
            sv.ScanPolicy(required_scans=["a", "a"])

    def test_policy_rejects_unknown_fields(self):
        with self.assertRaises(sv.ScanVerdictError):
            sv.ScanPolicy.from_dict({"required_scans": [],
                                     "threshold": 3})

    def test_missing_required_refused(self):
        _, _, gate = self._gate(["scanner-a"])
        with self.assertRaises(sv.ScanVerdictError) as cm:
            gate.check(_DIGEST, [], now=_NOW)
        self.assertIn("missing", str(cm.exception))

    def test_unknown_scanner_loud(self):
        signer_b, _ = _keys(_SEED_B)
        _, _, gate = self._gate(["scanner-a"])
        env = sv.emit_scan_verdict(
            scanner_name="scanner-rogue", scanner_version="9",
            scan_target_digest=_DIGEST, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=_NOW - 60,
            expires_at=_NOW + 3600, signer=signer_b, now=_NOW)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            gate.check(_DIGEST, [env], now=_NOW)
        self.assertIn("unknown_scanner", str(cm.exception))

    def test_fail_blocks_even_with_pass(self):
        signer, _, gate = self._gate(["scanner-a"])
        good = sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1.4.2",
            scan_target_digest=_DIGEST, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=_NOW - 3600,
            expires_at=_NOW + 86400, signer=signer, now=_NOW)
        bad = sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1.4.2",
            scan_target_digest=_DIGEST, verdict="fail",
            ruleset_digest=_RULESET, scanned_at=_NOW - 1800,
            expires_at=_NOW + 86400, signer=signer, now=_NOW)
        with self.assertRaises(sv.ScanVerdictError) as cm:
            gate.check(_DIGEST, [good, bad], now=_NOW)
        self.assertIn("negative", str(cm.exception))

    def test_two_required_scanners(self):
        signer_a, ver_a = _keys(_SEED_A)
        signer_b, ver_b = _keys(_SEED_B)
        gate = sv.ScanGate(
            sv.ScanPolicy(required_scans=["scanner-a", "scanner-b"]),
            {"scanner-a": ver_a, "scanner-b": ver_b})
        env_a = sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1",
            scan_target_digest=_DIGEST, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=_NOW - 60,
            expires_at=_NOW + 3600, signer=signer_a, now=_NOW)
        # Only scanner-a present: scanner-b missing -> refused.
        with self.assertRaises(sv.ScanVerdictError):
            gate.check(_DIGEST, [env_a], now=_NOW)
        env_b = sv.emit_scan_verdict(
            scanner_name="scanner-b", scanner_version="2",
            scan_target_digest=_DIGEST, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=_NOW - 60,
            expires_at=_NOW + 3600, signer=signer_b, now=_NOW)
        res = gate.check(_DIGEST, [env_a, env_b], now=_NOW)
        self.assertTrue(res["ok"])
        self.assertEqual(res["checked"], ["scanner-a", "scanner-b"])


class LoadGateWiring(unittest.TestCase):
    _SEED_PIN = bytes.fromhex("d4" * 32)
    _SEED_AUTH = bytes.fromhex("e5" * 32)
    _TS = "2026-09-23T00:00:00+00:00"

    def _loader(self, gate):
        from gov import load_gate as lg
        from gov.delegation_tokens import DelegationTrust
        pin_signer = Ed25519Signer(self._SEED_PIN)
        auth = Ed25519Signer(self._SEED_AUTH)
        trust = DelegationTrust(
            human_keys={pin_signer.key_id: pin_signer.public_key},
            authority_keys={auth.key_id: auth.public_key},
            user_issuer_keys={pin_signer.key_id: pin_signer.public_key})
        pinset = lg.ArtifactPinset(trust)
        store, log = {}, []

        def pin(name, content):
            digest = "sha256:" + hashlib.sha256(content).hexdigest()
            na = lg._resolve_pin_not_after(self._TS, None)
            body = lg._canonical_pin_body("dev", "skill:" + name,
                                          digest, self._TS, version=1,
                                          not_after=na)
            pinset.pin("skill:" + name, digest, pin_signer.key_id,
                       pin_signer.sign(body).hex(), ts=self._TS,
                       tier="dev", version=1, not_after=na)
            store[name] = content
            return digest
        return lg, lg.SkillLoader(pinset, store, log=log,
                                 scan_gate=gate), pin, log

    def test_wired_unpresented_refused(self):
        from gov import load_gate as lg
        signer, verifiers = _keys(_SEED_A)
        gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                           {"scanner-a": verifiers})
        lg_mod, loader, pin, log = self._loader(gate)
        pin("w", b"w")
        with self.assertRaises(lg_mod.ArtifactRefused) as cm:
            loader.load_skill("w")
        self.assertIn("scan_verdicts_unpresented", str(cm.exception))
        reasons = [e.get("reason") for e in log
                   if e.get("event") == "artifact_load_refused"]
        self.assertIn("scan_verdicts_unpresented", reasons)

    def test_wired_empty_policy_admits_without_verdicts(self):
        # Spec-axis regression: a wired gate whose policy requires
        # NOTHING must not demand verdicts (opt-in, never silently
        # mandatory).
        _, verifiers = _keys(_SEED_A)
        gate = sv.ScanGate(sv.ScanPolicy(), {"scanner-a": verifiers})
        _, loader, pin, _ = self._loader(gate)
        pin("e", b"e")
        verified = loader.load_skill("e")
        self.assertEqual(verified.data, b"e")

    def test_wired_valid_verdict_loads_and_logs(self):
        signer, verifiers = _keys(_SEED_A)
        gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                           {"scanner-a": verifiers})
        lg_mod, loader, pin, log = self._loader(gate)
        digest = pin("v", b"v")
        wall = int(time.time())
        env = sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1.4.2",
            scan_target_digest=digest, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=wall - 60,
            expires_at=wall + 3600, signer=signer, now=wall)
        verified = loader.load_skill("v", scan_verdicts=[env])
        self.assertEqual(verified.data, b"v")
        checked = [e for e in log if e.get("event") == "scan_gate_checked"]
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0]["required"], ["scanner-a"])

    def test_wired_stale_verdict_refused(self):
        from gov import load_gate as lg
        signer, verifiers = _keys(_SEED_A)
        gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                           {"scanner-a": verifiers})
        lg_mod, loader, pin, log = self._loader(gate)
        digest = pin("s", b"s")
        env = sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1.4.2",
            scan_target_digest=digest, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=_NOW - 7200,
            expires_at=_NOW - 3600, signer=signer, now=_NOW - 7200)
        # Valid at emission (expires_at > emission now), stale at the
        # loader's verifier (wall) clock.
        with self.assertRaises(lg_mod.ArtifactRefused) as cm:
            loader.load_skill("s", scan_verdicts=[env])
        self.assertIn("scan_gate_refused", str(cm.exception))

    def test_unwired_loader_unchanged(self):
        lg_mod, loader, pin, log = self._loader(None)
        pin("u", b"u")
        verified = loader.load_skill("u")
        self.assertEqual(verified.data, b"u")

    def test_verdicts_without_gate_refused(self):
        from gov import load_gate as lg
        signer, _ = _keys(_SEED_A)
        lg_mod, loader, pin, log = self._loader(None)
        digest = pin("x", b"x")
        wall = int(time.time())
        env = sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1.4.2",
            scan_target_digest=digest, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=wall - 60,
            expires_at=wall + 3600, signer=signer, now=wall)
        with self.assertRaises(lg_mod.ArtifactRefused) as cm:
            loader.load_skill("x", scan_verdicts=[env])
        self.assertIn("scan_gate_unwired", str(cm.exception))

    def test_constructor_rejects_bad_gate(self):
        from gov import load_gate as lg
        from gov.delegation_tokens import DelegationTrust
        pin_signer = Ed25519Signer(self._SEED_PIN)
        auth = Ed25519Signer(self._SEED_AUTH)
        trust = DelegationTrust(
            human_keys={pin_signer.key_id: pin_signer.public_key},
            authority_keys={auth.key_id: auth.public_key},
            user_issuer_keys={pin_signer.key_id: pin_signer.public_key})
        pinset = lg.ArtifactPinset(trust)
        with self.assertRaises(TypeError):
            lg.SkillLoader(pinset, {}, scan_gate=object())


if __name__ == "__main__":
    unittest.main()
