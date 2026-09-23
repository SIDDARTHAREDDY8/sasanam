"""Wave-70 Lane 1 tests: ``deployment_mode=`` kwarg wiring end-to-end.

Wave-69's design doc says "explicit ``deployment_mode=`` kwarg wins"
but only ``resolve_active_key()`` had the kwarg — ``ActionLog`` (the
primary chain-creating entry point) and ``keys.require_key()`` did not,
so the documented precedence was not fully wired. Direction (a):
keyword-only ``deployment_mode=None`` on ``ActionLog.__init__`` and
``keys.require_key()``, flowing through ``_active_key()`` into
``resolve_active_key`` (explicit kwarg > ``GOV_DEPLOYMENT_MODE`` >
default ``"production"``, unknown fails fast).

Break-first properties covered here:
- kwarg-vs-env conflict: explicit kwarg is authoritative (both
  directions: staging-kwarg beats production-env, production-kwarg
  beats staging-env via the loud contradiction).
- Unknown mode string via kwarg: ValueError at construction (fail fast,
  not at first append).
- ``ActionLog`` in a production deployment with no key configured:
  refuses loud (NoKeyConfiguredError), never dev-fallback.
- The kwarg is keyword-only with default None: existing positional
  callers are untouched, and None preserves byte-identical behavior.

Deterministic, $0, synthetic/local only. Env hygiene: every test saves
and restores all touched env vars plus the ``gov.log`` dev flags.
"""

import inspect
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import keyprovider as kp
from gov import keys
from gov import log as log_mod
from gov.keys import KeyRing, NoKeyConfiguredError
from gov.log import ActionLog, _DEV_KEY

_ENV_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
              "GOV_DEV_KEYS", "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


def _clean_env():
    saved = {n: os.environ.get(n) for n in _ENV_NAMES}
    had = {n: n in os.environ for n in _ENV_NAMES}
    prev_enabled = log_mod._dev_enabled
    prev_warned = log_mod._dev_warned
    for n in _ENV_NAMES:
        os.environ.pop(n, None)

    def restore():
        for n in _ENV_NAMES:
            if had[n]:
                os.environ[n] = saved[n]
            else:
                os.environ.pop(n, None)
        log_mod._dev_enabled = prev_enabled
        log_mod._dev_warned = prev_warned

    return restore


def _dev_opt_in(on=True):
    """Explicit in-code dev-key factor for this test."""
    log_mod._dev_enabled = on


def _quiet():
    """Swallow the loud dev-key stderr warnings (asserted elsewhere)."""
    return redirect_stderr(StringIO())


class ActionLogDeploymentModeKwargTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        self._tmp = tempfile.mkdtemp(prefix="w70-")
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmp, ignore_errors=True))

    def _path(self, name="actions.jsonl"):
        return os.path.join(self._tmp, name)

    def test_kwarg_is_keyword_only_with_none_default(self):
        param = inspect.signature(ActionLog.__init__).parameters[
            "deployment_mode"]
        self.assertEqual(param.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(param.default)

    def test_unknown_mode_fails_fast_at_construction(self):
        # Fail fast: the ValueError surfaces at construction, before any
        # log operation could run under an unknown (unguarded) mode.
        with self.assertRaises(ValueError):
            ActionLog(self._path(), deployment_mode="bogus")
        with self.assertRaises(ValueError):
            ActionLog(self._path(), deployment_mode="prod")

    def test_kwarg_wins_over_env_staging_beats_production(self):
        # The documented precedence, both factors of the dev opt-in
        # present, env declaring production: the explicit kwarg is
        # authoritative, so the staging dev key resolves (loudly).
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        os.environ["GOV_DEV_KEYS"] = "1"
        _dev_opt_in(True)
        with _quiet():
            log = ActionLog(self._path(), deployment_mode="staging")
            log.append({"ev": "kwarg-wins"})
        with open(self._path(), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["ev"], "kwarg-wins")
        self.assertEqual(entry["key_epoch"], "dev")

    def test_kwarg_production_over_staging_env_contradiction(self):
        # Reverse conflict: env says staging (dev opt-in active) but the
        # explicit kwarg declares production -> the wave-69 contradiction
        # refuses LOUD at append time.
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        os.environ["GOV_DEV_KEYS"] = "1"
        _dev_opt_in(True)
        with _quiet():
            log = ActionLog(self._path(), deployment_mode="production")
            with self.assertRaises(NoKeyConfiguredError):
                log.append({"ev": "must-not-write"})

    def test_production_no_key_refuses_never_dev_fallback(self):
        # No kwarg, production env, nothing configured, no opt-in: loud
        # refusal, never a silent dev fallback.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        _dev_opt_in(False)
        log = ActionLog(self._path())
        with self.assertRaises(NoKeyConfiguredError):
            log.append({"ev": "must-not-write"})

    def test_production_no_key_refuses_with_explicit_none_kwarg(self):
        # deployment_mode=None is exactly the default: falls through to
        # env -> production -> refuse.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        _dev_opt_in(False)
        log = ActionLog(self._path(), deployment_mode=None)
        with self.assertRaises(NoKeyConfiguredError):
            log.append({"ev": "must-not-write"})

    def test_env_key_unaffected_by_mode_kwarg(self):
        # Provider order is orthogonal to the mode declaration: a
        # configured env key still wins, whatever the kwarg says.
        os.environ["GOV_LOG_KEY"] = "wave70-env-key-bytes-32-or-more!!"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        _dev_opt_in(False)
        log = ActionLog(self._path(), deployment_mode="staging")
        log.append({"ev": "env-key"})
        with open(self._path(), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["ev"], "env-key")

    def test_write_checkpoint_honors_kwarg(self):
        # write_checkpoint is the other key-resolving mutation path on
        # the instance; it must honor the same declaration.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        os.environ["GOV_DEV_KEYS"] = "1"
        _dev_opt_in(True)
        with _quiet():
            log = ActionLog(self._path(), deployment_mode="staging")
            log.append({"ev": 1})
            log.write_checkpoint()

    def test_none_kwarg_byte_identical_resolution(self):
        # No kwarg: resolution is byte-identical to pre-wave-70 (env key
        # bytes flow through unchanged).
        os.environ["GOV_LOG_KEY"] = "wave70-env-key-bytes-32-or-more!!"
        _dev_opt_in(False)
        key, epoch = log_mod._active_key()
        self.assertEqual(key, b"wave70-env-key-bytes-32-or-more!!")
        key2, epoch2 = log_mod._active_key(None)
        self.assertEqual((key2, epoch2), (key, epoch))


class RequireKeyDeploymentModeKwargTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())

    def test_kwarg_is_keyword_only_with_none_default(self):
        param = inspect.signature(keys.require_key).parameters[
            "deployment_mode"]
        self.assertEqual(param.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(param.default)

    def test_kwarg_production_triggers_contradiction(self):
        # Env says staging with the dev opt-in fully active, but the
        # explicit kwarg declares production -> loud contradiction.
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        os.environ["GOV_DEV_KEYS"] = "1"
        _dev_opt_in(True)
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key(deployment_mode="production")

    def test_kwarg_staging_allows_dev_with_opt_in(self):
        # Explicit staging kwarg over a production env: the kwarg wins,
        # dev key resolves under the double opt-in.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        os.environ["GOV_DEV_KEYS"] = "1"
        _dev_opt_in(True)
        with _quiet():
            ring = keys.require_key(deployment_mode="staging")
        self.assertIsInstance(ring, KeyRing)
        self.assertEqual(ring.active().key, _DEV_KEY)

    def test_unknown_mode_fails_fast(self):
        # Unknown mode fails fast — but only once the dev-opt-in path
        # reaches mode resolution (without the in-code opt-in the
        # earlier refusal is the correct, louder gate).
        os.environ["GOV_DEV_KEYS"] = "1"
        _dev_opt_in(True)
        with self.assertRaises(ValueError):
            keys.require_key(deployment_mode="bogus")

    def test_none_kwarg_preserves_old_behavior(self):
        # No kwarg, no key, no opt-in: the pre-wave-70 refusal, unchanged.
        _dev_opt_in(False)
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key()
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key(deployment_mode=None)


if __name__ == "__main__":
    unittest.main()
