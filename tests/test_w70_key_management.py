"""Wave-70 Lane 1 tests: ``deployment_mode=`` kwarg wiring end-to-end.

Wave-69's design doc says "explicit ``deployment_mode=`` kwarg wins"
but only ``resolve_active_key()`` had the kwarg — ``ActionLog`` (the
primary chain-creating entry point) and ``keys.require_key()`` did not,
so the documented precedence was not fully wired. Direction (a):
keyword-only ``deployment_mode=None`` on ``ActionLog.__init__`` and
``keys.require_key()``, flowing through ``_active_key()`` into
``resolve_active_key`` (explicit kwarg > ``GOV_DEPLOYMENT_MODE`` >
default ``"production"``, unknown fails fast).

Wave-81: the dev key is deleted from gov/, so the kwarg no longer
selects a key story -- it only VALIDATES the mode declaration.
Provisioning is explicit in every mode: a configured key works under
any kwarg, and no key refuses under any kwarg.

Break-first properties covered here:
- kwarg-vs-env conflict: explicit kwarg is authoritative for the mode
  declaration, but key selection is unchanged (configured key wins in
  every mode; no key refuses in every mode).
- Unknown mode string via kwarg: ValueError at construction (fail fast,
  not at first append).
- ``ActionLog`` in a deployment with no key configured: refuses loud
  (NoKeyConfiguredError), never a fallback.
- The kwarg is keyword-only with default None: existing positional
  callers are untouched, and None preserves byte-identical behavior.

Deterministic, $0, synthetic/local only. Env hygiene: every test saves
and restores all touched env vars.
"""

import inspect
import json
import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import keys
from gov import log as log_mod
from gov.keys import NoKeyConfiguredError
from gov.log import ActionLog

_ENV_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
              "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


def _clean_env():
    saved = {n: os.environ.get(n) for n in _ENV_NAMES}
    had = {n: n in os.environ for n in _ENV_NAMES}
    for n in _ENV_NAMES:
        os.environ.pop(n, None)

    def restore():
        for n in _ENV_NAMES:
            if had[n]:
                os.environ[n] = saved[n]
            else:
                os.environ.pop(n, None)

    return restore


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

    def test_kwarg_does_not_change_key_selection(self):
        # Wave-81: the kwarg declares/validates the mode but no longer
        # selects a key story. Explicit staging kwarg over a production
        # env, with a configured key: the key resolves (loudly refused
        # only when no key is provisioned, in every mode).
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        os.environ["GOV_LOG_KEY"] = "wave70-explicit-key"
        log = ActionLog(self._path(), deployment_mode="staging")
        log.append({"ev": "kwarg-no-story"})
        with open(self._path(), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["ev"], "kwarg-no-story")
        self.assertEqual(entry["key_epoch"], "env")

    def test_kwarg_production_with_key_appends(self):
        # The old wave-69 "contradiction" is unstatable now: production
        # kwarg + configured key is simply a working production chain.
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        os.environ["GOV_LOG_KEY"] = "wave70-explicit-key"
        log = ActionLog(self._path(), deployment_mode="production")
        log.append({"ev": "production-chain"})
        with open(self._path(), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["key_epoch"], "env")

    def test_production_no_key_refuses_never_fallback(self):
        # No kwarg, production env, nothing configured: loud refusal,
        # never a silent fallback (there is no fallback left).
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log = ActionLog(self._path())
        with self.assertRaises(NoKeyConfiguredError):
            log.append({"ev": "must-not-write"})

    def test_production_no_key_refuses_with_explicit_none_kwarg(self):
        # deployment_mode=None is exactly the default: falls through to
        # env -> production -> refuse.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log = ActionLog(self._path(), deployment_mode=None)
        with self.assertRaises(NoKeyConfiguredError):
            log.append({"ev": "must-not-write"})

    def test_no_key_refuses_in_every_mode(self):
        # Wave-81: the kwarg cannot conjure a key in any mode.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        for mode in ("production", "staging", "dev", "test"):
            log = ActionLog(self._path("a-%s.jsonl" % mode),
                            deployment_mode=mode)
            with self.assertRaises(NoKeyConfiguredError, msg=mode):
                log.append({"ev": "must-not-write"})

    def test_env_key_unaffected_by_mode_kwarg(self):
        # Provider order is orthogonal to the mode declaration: a
        # configured env key still wins, whatever the kwarg says.
        os.environ["GOV_LOG_KEY"] = "wave70-env-key-bytes-32-or-more!!"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log = ActionLog(self._path(), deployment_mode="staging")
        log.append({"ev": "env-key"})
        with open(self._path(), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["ev"], "env-key")

    def test_write_checkpoint_honors_kwarg(self):
        # write_checkpoint is the other key-resolving mutation path on
        # the instance; it must honor the same declaration.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        os.environ["GOV_LOG_KEY"] = "wave70-explicit-key"
        log = ActionLog(self._path(), deployment_mode="staging")
        log.append({"ev": 1})
        log.write_checkpoint()

    def test_none_kwarg_byte_identical_resolution(self):
        # No kwarg: resolution is byte-identical to pre-wave-70 (env key
        # bytes flow through unchanged).
        os.environ["GOV_LOG_KEY"] = "wave70-env-key-bytes-32-or-more!!"
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

    def test_kwarg_validated_not_key_selecting(self):
        # Wave-81: the kwarg validates the mode declaration but selects
        # no key story. A configured key works under every kwarg...
        os.environ["GOV_LOG_KEY"] = "wave70-explicit-key"
        for mode in ("production", "staging", "dev", "test"):
            ring = keys.require_key(deployment_mode=mode)
            self.assertEqual(ring.active().key, b"wave70-explicit-key")
        # ...and no key refuses under every kwarg.
        del os.environ["GOV_LOG_KEY"]
        for mode in ("production", "staging", "dev", "test"):
            with self.assertRaises(NoKeyConfiguredError, msg=mode):
                keys.require_key(deployment_mode=mode)

    def test_unknown_mode_fails_fast(self):
        with self.assertRaises(ValueError):
            keys.require_key(deployment_mode="bogus")

    def test_none_kwarg_preserves_old_behavior(self):
        # No kwarg, no key: the pre-wave-70 refusal, unchanged.
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key()
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key(deployment_mode=None)


if __name__ == "__main__":
    unittest.main()
