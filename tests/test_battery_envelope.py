"""Unit tests for gov/battery_envelope.py (wave-278 evidence-envelope lane)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import battery_envelope as be  # noqa: E402


def _honest(n_violating=1, n_clean=1):
    b = be.RunBuilder("unit", "0.0")
    for i in range(n_violating):
        b.record("v%d" % i, oracle="violating", expected="BREAK",
                 verdict="BREAK", note="golden attack")
    for i in range(n_clean):
        b.record("c%d" % i, oracle="clean", expected="HELD",
                 verdict="HELD", note="golden benign")
    return b.seal()


class EmitVerifyTest(unittest.TestCase):
    def test_round_trip(self):
        env = _honest()
        hdr = be.verify_envelope(env)
        self.assertEqual(hdr["sample_count"], 2)
        self.assertEqual(hdr["battery"], "unit")

    def test_sample_chain_order_matters(self):
        env = _honest()
        env["samples"][0], env["samples"][1] = (
            env["samples"][1], env["samples"][0])
        with self.assertRaises(be.BatteryEnvelopeError):
            be.verify_envelope(env)

    def test_note_tamper_refuses(self):
        env = _honest()
        env["samples"][1]["note"] = "edited"
        with self.assertRaises(be.BatteryEnvelopeError) as ctx:
            be.verify_envelope(env)
        self.assertEqual(ctx.exception.reason, "envelope-sample-tampered")

    def test_oracle_joint_forgery_refuses(self):
        env = _honest()
        s = env["samples"][0]
        s["verdict"] = "HELD"
        s["expected"] = "HELD"
        with self.assertRaises(be.BatteryEnvelopeError) as ctx:
            be.verify_envelope(env)
        self.assertEqual(ctx.exception.reason,
                         "envelope-oracle-mismatch")

    def test_verdict_mismatch_refuses(self):
        env = _honest()
        env["samples"][1]["verdict"] = "BREAK"
        with self.assertRaises(be.BatteryEnvelopeError) as ctx:
            be.verify_envelope(env)
        self.assertEqual(ctx.exception.reason,
                         "envelope-verdict-mismatch")

    def test_unknown_schema_refuses(self):
        env = _honest()
        env["schema_version"] = "2.0"
        with self.assertRaises(be.BatteryEnvelopeError) as ctx:
            be.verify_envelope(env)
        self.assertEqual(ctx.exception.reason,
                         "envelope-unknown-schema")

    def test_count_mismatch_refuses(self):
        env = _honest()
        env["header"]["sample_count"] = 99
        with self.assertRaises(be.BatteryEnvelopeError) as ctx:
            be.verify_envelope(env)
        self.assertEqual(ctx.exception.reason,
                         "envelope-count-mismatch")

    def test_emitter_enforces_oracle_contract(self):
        b = be.RunBuilder("unit", "0.0")
        with self.assertRaises(be.BatteryEnvelopeError):
            b.record("x", oracle="clean", expected="BREAK",
                     verdict="BREAK", note="contradiction")

    def test_emitter_rejects_bad_vocab(self):
        b = be.RunBuilder("unit", "0.0")
        with self.assertRaises(be.BatteryEnvelopeError):
            b.record("x", oracle="maybe", expected="HELD",
                     verdict="HELD", note="bad oracle")

    def test_error_verdict_allowed_with_clean_oracle(self):
        b = be.RunBuilder("unit", "0.0")
        b.record("x", oracle="clean", expected="ERROR",
                 verdict="ERROR", note="probe errored")
        be.verify_envelope(b.seal())  # must not raise

    def test_standalone_verifier_agrees(self):
        env = _honest()
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False,
                dir="/var/tmp") as f:
            json.dump(env, f)
            path = f.name
        try:
            p = subprocess.run(
                [sys.executable,
                 os.path.join(REPO, "tools", "envelope-verify"), path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=120)
            self.assertEqual(p.returncode, 0, p.stdout)
            env["samples"][0]["verdict"] = "HELD"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(env, f)
            p = subprocess.run(
                [sys.executable,
                 os.path.join(REPO, "tools", "envelope-verify"), path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=120)
            self.assertEqual(p.returncode, 1)
        finally:
            os.unlink(path)

    def test_no_taxonomy_codes_added(self):
        # The envelope layer must not touch the decision-code pin.
        import re
        with open(os.path.join(REPO, "gov", "decision_codes.py"),
                  encoding="utf-8") as f:
            src = f.read()
        literals = re.findall(
            r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        self.assertEqual(len(literals), 2014)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        self.assertEqual(len(set(literals)), 2014)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1857 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1857 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)

    def test_schema_shape(self):
        schema = be.envelope_schema()
        self.assertEqual(schema["format"], be.FORMAT)
        self.assertEqual(schema["schema_version"], be.SCHEMA_VERSION)
        self.assertIn("sample_digest", schema["sample"])


if __name__ == "__main__":
    unittest.main()
