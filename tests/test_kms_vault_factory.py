"""Red-first battery for F160: ``kms_provider_from_config`` ``provider:
vault`` transport knobs + error-type contract.

Covers the factory seam (``gov.kms.kms_provider_from_config``,
``provider: vault`` branch) for the three transport knobs the factory
previously hard-coded — ``allow_http``, ``ca_bundle``, ``timeout_s`` —
and the error-type contract: operator-caused failures at the factory
boundary raise the module's typed :class:`KmsError`, never a bare
``ValueError``. Direct construction of ``UrllibVaultTransport`` keeps
its ``ValueError`` convention (programmer error) — see the live
battery's ``TransportDisciplineTests``.

Knob plumbing is observed at stdlib seams (``ssl.create_default_context``
for ``ca_bundle``; ``urllib.request.urlopen`` for ``timeout_s``), never
via transport internals.

Deterministic: stdlib unittest only, zero network.

Per repo convention this module sets the deployment-mode gate at
module level and must be verified under a clean environment:
``env -u GOV_DEPLOYMENT_MODE <venv-python> -m unittest
tests.test_kms_vault_factory -v``.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import ssl
import tempfile
import unittest
import urllib.request
from unittest import mock

from gov.kms import KmsError, kms_provider_from_config
from gov.kms_vault import UrllibVaultTransport, VaultKmsProvider


class _FakeResp:
    """Minimal urlopen stand-in: records kwargs, returns canned 200."""

    def __init__(self, calls, status=200, body=b"{}"):
        self._calls = calls
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen_factory(calls):
    def _fake_urlopen(req, timeout=None, context=None):
        calls["timeout"] = timeout
        calls["context"] = context
        return _FakeResp(calls)
    return _fake_urlopen


class FactoryTransportKnobsTest(unittest.TestCase):
    """F160: transport knobs on the ``provider: vault`` factory."""

    def _env(self, addr, token="tok-f160"):
        return mock.patch.dict(os.environ,
                               {"VAULT_ADDR": addr, "VAULT_TOKEN": token})

    def test_allow_http_honored(self):
        # Dev/test loopback: http VAULT_ADDR + explicit allow_http must
        # build a working provider.
        with self._env("http://127.0.0.1:18200"):
            p = kms_provider_from_config({"provider": "vault",
                                          "allow_http": True})
        self.assertIsInstance(p, VaultKmsProvider)
        self.assertIsInstance(p._transport, UrllibVaultTransport)

    def test_allow_http_refused_by_default(self):
        # Fail-closed default: plaintext addr without the explicit knob
        # is refused at config time — as KmsError, not bare ValueError.
        with self._env("http://127.0.0.1:18200"):
            with self.assertRaises(KmsError):
                kms_provider_from_config({"provider": "vault"})

    def test_ca_bundle_plumbed(self):
        # The ca_bundle path must reach ssl.create_default_context as
        # cafile= (observed at the stdlib seam).
        with tempfile.NamedTemporaryFile(suffix=".pem") as tf:
            tf.write(b"not-a-real-bundle")
            tf.flush()
            seen = {}
            real = ssl.create_default_context

            def spy(cafile=None, *a, **k):
                seen["cafile"] = cafile
                return real()

            with self._env("https://vault.internal:8200"):
                with mock.patch.object(ssl, "create_default_context",
                                       side_effect=spy):
                    kms_provider_from_config({"provider": "vault",
                                              "ca_bundle": tf.name})
        self.assertEqual(seen.get("cafile"), tf.name)

    def test_timeout_s_plumbed(self):
        # The timeout_s knob must reach urlopen(timeout=...) on the
        # transport the factory builds (observed at the stdlib seam).
        with self._env("https://vault.internal:8200"):
            p = kms_provider_from_config({"provider": "vault",
                                          "timeout_s": 3})
        calls = {}
        with mock.patch.object(urllib.request, "urlopen",
                               side_effect=_fake_urlopen_factory(calls)):
            status, body = p._transport.request("GET", "/v1/sys/health",
                                                {}, b"")
        self.assertEqual(status, 200)
        self.assertEqual(calls.get("timeout"), 3)

    def test_factory_error_type_contract(self):
        # The filed bug: http VAULT_ADDR through the factory died with
        # bare ValueError. The factory boundary must raise KmsError
        # (the typed fail-closed error), with the refusal reason
        # preserved — and KmsError must not BE a ValueError.
        self.assertFalse(issubclass(KmsError, ValueError))
        with self._env("http://127.0.0.1:18200"):
            try:
                kms_provider_from_config({"provider": "vault"})
            except KmsError as e:
                self.assertNotIsInstance(e, ValueError)
                self.assertIn("http", str(e).lower())
            else:
                self.fail("expected KmsError for plaintext VAULT_ADDR")

    def test_invalid_knob_values_fail_closed(self):
        # Ambiguous or nonsensical knob values are config errors, not
        # silent defaults: strict-bool allow_http, positive timeout_s,
        # existing-file ca_bundle.
        with self._env("https://vault.internal:8200"):
            with self.assertRaises(KmsError):
                kms_provider_from_config({"provider": "vault",
                                          "allow_http": "yes"})
            with self.assertRaises(KmsError):
                kms_provider_from_config({"provider": "vault",
                                          "timeout_s": 0})
            with self.assertRaises(KmsError):
                kms_provider_from_config({"provider": "vault",
                                          "timeout_s": "fast"})
            with self.assertRaises(KmsError):
                kms_provider_from_config(
                    {"provider": "vault",
                     "ca_bundle": "/nonexistent/f160-ca-bundle.pem"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
