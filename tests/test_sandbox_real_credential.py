"""Wave-273 lane H unit tests: sandbox fail-closed on real credentials.

Tests the public seams only: Sandbox(..., sentinel_vault=...),
Sandbox.run refusal behavior, and SentinelVault.is_registered_real.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes as dc  # noqa: E402
from gov import sandbox as sb  # noqa: E402
from gov import sentinel_substitution as sent  # noqa: E402

REAL = "synthetic-api-token-wave273-0042"
BENIGN = "a3f9c2e1b4d60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5"
PLACEHOLDER = "fake_value_12345678-1234-1234-1234-1234567890ab"


def _vault():
    v = sent.SentinelVault()
    v.register("cred-1", REAL, ["api.example.com"],
               credential_class="api-key", release_policy="legacy-host-only")
    return v


class TestVaultOracle(unittest.TestCase):
    def test_registered_real_matches(self):
        self.assertIs(_vault().is_registered_real(REAL), True)

    def test_unknown_value_no_match(self):
        self.assertIs(_vault().is_registered_real(BENIGN), False)

    def test_sentinel_placeholder_no_match(self):
        v = _vault()
        sentinel = v.sentinel_for("cred-1")
        self.assertIs(v.is_registered_real(sentinel), False)

    def test_decoy_never_matches(self):
        v = _vault()
        decoy = v.register_decoy("trip-test")
        self.assertIs(v.is_registered_real(decoy), False)

    def test_non_string_no_match(self):
        v = _vault()
        self.assertIs(v.is_registered_real(None), False)
        self.assertIs(v.is_registered_real(12345), False)
        self.assertIs(v.is_registered_real(b"bytes"), False)

    def test_empty_string_no_match(self):
        self.assertIs(_vault().is_registered_real(""), False)

    def test_bytes_match_examined(self):
        self.assertIs(_vault().is_registered_real(REAL.encode("utf-8")),
                      True)

    def test_non_utf8_bytes_no_match(self):
        # Cannot be byte-equal to any UTF-8-encoded registered real;
        # examined and rejected, never silently skipped.
        self.assertIs(_vault().is_registered_real(b"\xff\xfe\x00"), False)


class TestSandboxVaultWiring(unittest.TestCase):
    def test_vault_kwarg_accepted(self):
        box = sb.Sandbox(sentinel_vault=_vault())
        self.assertIsNotNone(box.sentinel_vault)

    def test_vault_kwarg_defaults_none(self):
        self.assertIsNone(sb.Sandbox().sentinel_vault)

    def test_vault_kwarg_wrong_type_fails_closed(self):
        with self.assertRaises(ValueError):
            sb.Sandbox(sentinel_vault=object())

    def test_vault_missing_oracle_fails_closed(self):
        class FakeVault(object):
            pass
        with self.assertRaises(ValueError):
            sb.Sandbox(sentinel_vault=FakeVault())


class TestBoundaryRefusal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w273-ut-")
        self.old_tmpdir = os.environ.get("TMPDIR")
        os.environ["TMPDIR"] = self.tmp

    def tearDown(self):
        if self.old_tmpdir is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = self.old_tmpdir
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _box(self, **kw):
        kw.setdefault("sentinel_vault", _vault())
        kw.setdefault("refusal_receipt_dir", self.tmp)
        return sb.Sandbox(**kw)

    def test_env_crossing_refused(self):
        box = self._box()
        with self.assertRaises(sb.SandboxError) as cm:
            box.run([sys.executable, "-I", "-c", "print('x')"],
                    extra_env={"W273_CRED": REAL})
        self.assertIn("sandbox-real-credential-blocked", str(cm.exception))
        self.assertNotIn(REAL, str(cm.exception))

    def test_argv_crossing_refused(self):
        box = self._box()
        with self.assertRaises(sb.SandboxError) as cm:
            box.run([sys.executable, "-I", "-c", "import sys",
                     REAL])
        self.assertIn("sandbox-real-credential-blocked", str(cm.exception))

    def test_stdin_crossing_refused(self):
        box = self._box()
        with self.assertRaises(sb.SandboxError) as cm:
            box.run([sys.executable, "-I", "-c", "print('x')"],
                    stdin_data=REAL.encode("utf-8"))
        self.assertIn("sandbox-real-credential-blocked", str(cm.exception))

    def test_bytes_env_crossing_refused(self):
        # The byte path is examined (as bytes), not skipped: a real
        # credential arriving as a bytes env value refuses too.
        box = self._box()
        with self.assertRaises(sb.SandboxError) as cm:
            box.run([sys.executable, "-I", "-c", "print('x')"],
                    extra_env={"W273_CRED": REAL.encode("utf-8")})
        self.assertIn("sandbox-real-credential-blocked", str(cm.exception))
        self.assertNotIn(REAL, str(cm.exception))

    def test_non_utf8_bytes_stdin_passes(self):
        # Non-decodable bytes cannot be byte-equal to a registered str
        # real; they pass (examined, not skipped) without refusal.
        box = self._box()
        r = box.run([sys.executable, "-I", "-c", "print('ok')"],
                    stdin_data=b"\xff\xfe\x00")
        self.assertTrue(r.ok)

    def test_refusal_names_carrier_and_key(self):
        box = self._box()
        try:
            box.run([sys.executable, "-I", "-c", "print('x')"],
                    extra_env={"W273_CRED": REAL})
        except sb.SandboxError as e:
            self.assertIn("env", str(e))
            self.assertIn("W273_CRED", str(e))
        else:
            self.fail("expected SandboxError")

    def test_receipt_redacts_value(self):
        box = self._box()
        try:
            box.run([sys.executable, "-I", "-c", "print('x')"],
                    extra_env={"W273_CRED": REAL})
        except sb.SandboxError:
            pass
        else:
            self.fail("expected SandboxError")
        with open(os.path.join(self.tmp, "refusals.jsonl"),
                  encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("sandbox-real-credential-blocked", body)
        self.assertNotIn(REAL, body)

    def test_placeholder_passes(self):
        box = self._box()
        r = box.run(
            [sys.executable, "-I", "-c",
             "import os,sys;sys.stdout.write(os.environ.get('W','ABSENT'))"],
            extra_env={"W": PLACEHOLDER})
        self.assertTrue(r.ok)
        self.assertIn(PLACEHOLDER, r.stdout)

    def test_benign_value_passes(self):
        box = self._box()
        r = box.run(
            [sys.executable, "-I", "-c",
             "import os,sys;sys.stdout.write(os.environ.get('W','ABSENT'))"],
            extra_env={"W": BENIGN})
        self.assertTrue(r.ok)
        self.assertIn(BENIGN, r.stdout)

    def test_no_vault_no_screen(self):
        box = sb.Sandbox()
        r = box.run(
            [sys.executable, "-I", "-c",
             "import os,sys;sys.stdout.write(os.environ.get('W','ABSENT'))"],
            extra_env={"W": REAL})
        self.assertTrue(r.ok)
        self.assertIn(REAL, r.stdout)


class TestDecisionCode(unittest.TestCase):
    def test_code_present(self):
        entry = dc.TAXONOMY.get("sandbox-real-credential-blocked")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["domain"], "sandbox")
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(len(dc.TAXONOMY), 1486)  # Wave-273 lane H: +1 sandbox-*


if __name__ == "__main__":
    unittest.main()
