"""Wave-81 break-first: the dev-key fallback is deleted from ``gov/``.

Two halves:

1. STATIC: no ``gov/**/*.py`` module defines, imports, calls, or
   references any dev-key machinery — not by name, attribute, call,
   or string constant. (Comments/docstrings may narrate the removal;
   the AST walk checks code, and the string-constant walk skips
   comment lines.)

2. BEHAVIORAL: every key entry point fails closed without an
   explicitly provisioned key, in every deployment mode, with no
   provisioning as a side effect.

Static analysis cannot prove runtime behavior under arbitrary dynamic
imports; the subprocess refusal tests are the behavioral complement.
"""

import ast
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOV_DIR = REPO_ROOT / "gov"

_KEY_ENV = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
            "GOV_KEYRING_FILE", "GOV_ANCHOR_KEY", "GOV_ANCHOR_KEY_FILE")


@contextlib.contextmanager
def _no_key_env():
    """Scrub every key env var; restore afterwards."""
    saved = {k: os.environ.get(k) for k in _KEY_ENV}
    for k in _KEY_ENV:
        os.environ.pop(k, None)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _scrubbed_env():
    env = dict(os.environ)
    for k in _KEY_ENV:
        env.pop(k, None)
    return env


# ---------------------------------------------------------------- static


class TestNoDevKeyReferencesInGov(unittest.TestCase):
    """AST + string-constant audit: zero dev-key machinery under gov/."""

    FORBIDDEN_NAMES = {
        "_DEV_KEY_CANONICAL", "enable_dev_keys", "dev_keys_enabled",
        "DevKeyProvider", "production_contradiction",
        "_dev_material_rejected", "enable_dev_anchor_keys",
    }
    FORBIDDEN_ATTR_ON_KEYRING = "dev"  # KeyRing.dev / KeyRing.dev(...)
    FORBIDDEN_STRINGS = {
        "GOV_DEV_KEYS", "NOT-FOR-PRODUCTION",
        "agent-governance-dev-key-v1",
    }

    def _gov_py_files(self):
        return sorted(p for p in GOV_DIR.rglob("*.py")
                      if "__pycache__" not in p.parts)

    def test_forbidden_names_attributes_calls(self):
        violations = []
        for path in self._gov_py_files():
            tree = ast.parse(path.read_text(encoding="utf-8"),
                             filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id in self.FORBIDDEN_NAMES:
                    violations.append("%s: Name %s" % (path.name, node.id))
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                       ast.ClassDef)) and \
                        node.name in self.FORBIDDEN_NAMES:
                    violations.append("%s: def %s" % (path.name, node.name))
                elif isinstance(node, ast.Attribute):
                    if node.attr in self.FORBIDDEN_NAMES:
                        violations.append("%s: attr .%s" % (path.name, node.attr))
                    if (node.attr == self.FORBIDDEN_ATTR_ON_KEYRING
                            and isinstance(node.value, ast.Name)
                            and node.value.id == "KeyRing"):
                        violations.append("%s: KeyRing.dev access" % path.name)
                elif isinstance(node, ast.arg) and \
                        node.arg in self.FORBIDDEN_NAMES:
                    violations.append("%s: arg %s" % (path.name, node.arg))
        self.assertEqual([], violations,
                         "dev-key machinery referenced in gov/: %r" % violations)

    def test_forbidden_string_constants(self):
        violations = []
        for path in self._gov_py_files():
            for i, line in enumerate(path.read_text(encoding="utf-8")
                                     .splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue  # comments narrate the removal; code is checked
                for s in self.FORBIDDEN_STRINGS:
                    if s in line:
                        violations.append("%s:%d: %r" % (path.name, i, s))
        self.assertEqual([], violations,
                         "dev-key string constants in gov/: %r" % violations)


# ---------------------------------------------------------------- behavioral


class TestRequireKeyRefusesEveryMode(unittest.TestCase):
    """require_key() / require_production_key(): no provisioning, ever."""

    def test_require_key_no_key_every_mode(self):
        from gov.keys import NoKeyConfiguredError, require_key
        with _no_key_env():
            for mode in ("production", "staging", "dev", "test", None):
                with self.assertRaises(NoKeyConfiguredError,
                                       msg="mode=%r" % (mode,)):
                    require_key(deployment_mode=mode)

    def test_require_production_key_no_key(self):
        from gov.keys import NoKeyConfiguredError, require_production_key
        with _no_key_env():
            with self.assertRaises(NoKeyConfiguredError):
                require_production_key()

    def test_require_key_refusal_is_not_provisioning(self):
        # After refusal, the env must be untouched: no key material may
        # have been minted or persisted as a side effect.
        from gov.keys import NoKeyConfiguredError, require_key
        with _no_key_env():
            with self.assertRaises(NoKeyConfiguredError):
                require_key()
            for k in _KEY_ENV:
                self.assertNotIn(k, os.environ)

    def test_unknown_mode_fails_fast(self):
        from gov.keys import require_key
        with _no_key_env():
            with self.assertRaises(Exception):
                require_key(deployment_mode="bogus-mode")


class TestKeyProviderRefusesEveryMode(unittest.TestCase):
    """KeyProvider / resolve_active_key(): explicit provisioning only."""

    def test_resolve_active_key_no_key_every_mode(self):
        from gov.keys import NoKeyConfiguredError
        from gov.keyprovider import resolve_active_key
        with _no_key_env():
            for mode in ("production", "staging", "dev", "test", None):
                with self.assertRaises(NoKeyConfiguredError,
                                       msg="mode=%r" % (mode,)):
                    resolve_active_key(mode)

    def test_abstract_provider_cannot_be_instantiated(self):
        from gov.keyprovider import KeyProvider
        with self.assertRaises(TypeError):
            KeyProvider()  # abstract: resolve() is unimplemented

    def test_deleted_provider_names(self):
        import gov.keyprovider as kp
        self.assertFalse(hasattr(kp, "DevKeyProvider"))
        self.assertFalse(hasattr(kp, "production_contradiction"))
        self.assertFalse(hasattr(kp, "_dev_material_rejected"))

    def test_deleted_keyring_api(self):
        from gov.keys import KeyRing
        self.assertFalse(hasattr(KeyRing, "dev"))

    def test_deleted_log_api(self):
        import gov.log as gl
        for name in ("enable_dev_keys", "dev_keys_enabled",
                     "_dev_enabled", "_dev_warned", "_DEV_KEY"):
            self.assertFalse(hasattr(gl, name), name)
        with self.assertRaises(ImportError):
            from gov.log import enable_dev_keys  # noqa: F401


class TestLogChainRefusesWithoutKey(unittest.TestCase):
    """The live log path: no key -> NoKeyConfiguredError on append."""

    def test_action_log_append_no_key(self):
        from gov.keys import NoKeyConfiguredError
        from gov.log import ActionLog
        with _no_key_env():
            d = Path(tempfile.mkdtemp(
                prefix="w81-", dir=os.environ.get("TMPDIR", "/tmp/gov-run")))
            with self.assertRaises(NoKeyConfiguredError):
                ActionLog(str(d / "a.jsonl")).append({"event": "x"})

    def test_explicit_key_still_works(self):
        import secrets
        from gov.log import ActionLog
        with _no_key_env():
            os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
            os.environ["GOV_LOG_KEY_EPOCH"] = "test"
            d = Path(tempfile.mkdtemp(
                prefix="w81-", dir=os.environ.get("TMPDIR", "/tmp/gov-run")))
            ActionLog(str(d / "a.jsonl")).append({"event": "x"})


class TestAnchorRefusesWithoutKey(unittest.TestCase):
    """Anchor resolution: explicit seed or file, else NoAnchorKeyError."""

    def test_resolve_anchor_key_no_key(self):
        from gov.anchorer import NoAnchorKeyError, resolve_anchor_key
        with _no_key_env():
            with self.assertRaises(NoAnchorKeyError):
                resolve_anchor_key()

    def test_anchor_explicit_seed_still_works(self):
        import secrets
        from gov.anchorer import resolve_anchor_key
        with _no_key_env():
            got = resolve_anchor_key(explicit=secrets.token_hex(32))
            self.assertFalse(got["dev"])
            self.assertEqual(len(got["seed"]), 32)


class TestVerifyCli(unittest.TestCase):
    """gov.verify: fails closed without a key; --dev is gone."""

    def _make_log(self):
        import secrets
        from gov.log import ActionLog
        d = Path(tempfile.mkdtemp(
            prefix="w81-", dir=os.environ.get("TMPDIR", "/tmp/gov-run")))
        with _no_key_env():
            os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
            os.environ["GOV_LOG_KEY_EPOCH"] = "test"
            ap = str(d / "a.jsonl")
            ActionLog(ap).append({"event": "w81"})
        return ap

    def test_verify_fails_closed_without_key(self):
        ap = self._make_log()
        proc = subprocess.run(
            [sys.executable, "-m", "gov.verify", ap],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
            timeout=60, env=_scrubbed_env())
        try:
            verdict = json.loads(proc.stdout)
        except ValueError:
            verdict = {}
        self.assertFalse(verdict.get("ok", True))
        self.assertNotEqual(0, proc.returncode)

    def test_verify_dev_flag_rejected(self):
        # Wave-81: the --dev flag is deleted; verify.py's manual argv
        # parser treats it as a positional path and fails closed —
        # it must never verify anything under it.
        ap = self._make_log()
        proc = subprocess.run(
            [sys.executable, "-m", "gov.verify", "--dev", ap],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
            timeout=60, env=_scrubbed_env())
        self.assertNotEqual(0, proc.returncode,
                            "--dev must not be accepted by gov.verify")
        try:
            verdict = json.loads(proc.stdout)
        except ValueError:
            verdict = {}
        self.assertFalse(verdict.get("ok", False),
                         "--dev must never yield a successful verification")


if __name__ == "__main__":
    unittest.main()
