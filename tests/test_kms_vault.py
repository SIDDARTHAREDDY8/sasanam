"""In-memory fake of Vault's transit-engine HTTP API. TEST-ONLY.

STREAM-1 test support — emulates the *server-side* semantics of a KMS
(opaque ciphertext handles held by the server, like real Vault transit),
not real cryptography: ``encrypt`` mints a random ``vault:v1:<...>``
handle and stores the plaintext mapping server-side; ``decrypt`` looks
the handle up. This fake provides ZERO production security and must
never stand in for a real Vault server outside tests.

Behavioral fidelity (approximate, documented):
  * Unknown key on encrypt/decrypt -> 400; unknown key on keys-read -> 404.
  * Wrong ``X-Vault-Token`` -> 403 (auth-failure path).
  * Decrypting a handle under a different key name than the one that
    encrypted it -> 400 (mirrors AES-GCM tag failure under the wrong
    key — defense in depth behind the adapter's own key-id binding).
  * Unknown/mangled ciphertext handle -> 400.
  * ``outage = True`` -> every call raises ``VaultTransportError``
    (fail-closed path).
  * ``calls`` records an audit trail of ``(method, path)``.

The adapter under test must treat every non-200 as ``KmsError``; the
exact status codes above only need to be *non-200* for the contract.
"""

import base64
import json
import re
import secrets
import threading
import urllib.parse

from gov.kms_vault import VaultTransport, VaultTransportError

_PATH_RE = re.compile(r"^/v1/([^/]+)/(encrypt|decrypt|keys)/(.+)$")


class FakeVaultTransport(VaultTransport):
    """In-memory transit engine. Create keys with :meth:`create_key`."""

    def __init__(self, token="test-vault-token"):
        self._token = token
        self._keys = {}    # name -> {"version": int}
        self._vault = {}   # ciphertext handle -> (key_name, plaintext_b64)
        self._lock = threading.Lock()
        self.outage = False
        self.calls = []

    # -- test controls ------------------------------------------------

    def create_key(self, name, version=1):
        with self._lock:
            if name in self._keys:
                raise ValueError("key %r already exists" % (name,))
            self._keys[name] = {"version": version}

    def delete_key(self, name):
        with self._lock:
            self._keys.pop(name, None)

    # -- transport -----------------------------------------------------

    def _header(self, headers, name):
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def _err(self, status, *errors):
        return status, json.dumps({"errors": list(errors)}).encode("utf-8")

    def _ok(self, data):
        return 200, json.dumps({"data": data}).encode("utf-8")

    def request(self, method, path, headers, body):
        if self.outage:
            raise VaultTransportError("simulated outage")
        with self._lock:
            self.calls.append((method, path))
            if self._header(headers, "X-Vault-Token") != self._token:
                return self._err(403, "permission denied")
            m = _PATH_RE.match(path)
            if not m:
                return self._err(404, "no handler for path %r" % path)
            _, op, raw_name = m.groups()
            name = urllib.parse.unquote(raw_name)
            if op == "keys":
                return self._read_key(name)
            try:
                payload = json.loads((body or b"").decode("utf-8"))
            except Exception:
                return self._err(400, "malformed request body")
            if not isinstance(payload, dict):
                return self._err(400, "malformed request body")
            if op == "encrypt":
                return self._encrypt(name, payload)
            return self._decrypt(name, payload)

    # -- transit emulation ----------------------------------------------

    def _read_key(self, name):
        info = self._keys.get(name)
        if info is None:
            return self._err(404, "no handler for path")
        return self._ok({"name": name,
                         "type": "aes256-gcm96",
                         "latest_version": info["version"],
                         "min_decryption_version": 1,
                         "deletion_allowed": False,
                         "export_private_key": False,
                         "keys": {str(info["version"]): {}}})

    def _encrypt(self, name, payload):
        if name not in self._keys:
            return self._err(400, "no handler for path")
        pt_b64 = payload.get("plaintext")
        if not isinstance(pt_b64, str) or not pt_b64:
            return self._err(400, "missing plaintext")
        try:
            base64.b64decode(pt_b64, validate=True)
        except Exception:
            return self._err(400, "invalid base64 plaintext")
        handle = ("vault:v%d:" % self._keys[name]["version"]
                  + base64.urlsafe_b64encode(secrets.token_bytes(18))
                  .decode("ascii").rstrip("="))
        self._vault[handle] = (name, pt_b64)
        return self._ok({"ciphertext": handle,
                         "key_version": self._keys[name]["version"]})

    def _decrypt(self, name, payload):
        if name not in self._keys:
            return self._err(400, "no handler for path")
        ct = payload.get("ciphertext")
        if not isinstance(ct, str) or not ct:
            return self._err(400, "missing ciphertext")
        entry = self._vault.get(ct)
        if entry is None:
            return self._err(400, "invalid ciphertext: handle unknown")
        enc_name, pt_b64 = entry
        if enc_name != name:
            # Mirrors real transit: the ciphertext does not authenticate
            # under a different key name (GCM tag failure).
            return self._err(400,
                              "ciphertext was not encrypted with key %r"
                              % (name,))
        return self._ok({"plaintext": pt_b64})


"""Tests for gov/kms_vault.py: HashiCorp Vault transit-engine KMS backend.

Promoted from workstreams/kms/vault-adapter/ (24 tests, green) after
central integration review.

Zero network: every test runs against the in-file ``FakeVaultTransport``,
except two localhost-only ``UrllibVaultTransport`` checks (connection
refused on a closed loopback port; a loopback HTTP server for error
mapping) — no external traffic, ever.

Covers: KmsProvider contract, wrap/unwrap roundtrip, key-id binding
(Attack-2 regression: blob wrapped under one key id never unwraps under
another), tamper/malformed blob rejection, unknown/deleted keys,
fail-closed on outage/auth-failure/broken transport, describe metadata,
secrecy (no key material, ciphertext handles, or tokens in logs or
exceptions), the stdlib urllib transport, and the
``kms_provider_from_config`` ``provider: vault`` branch (env-sourced
credentials only — the operator config surface never carries the token).

Deterministic: stdlib unittest only.
"""

import base64
import http.server
import logging
import secrets
import socketserver
import threading
import os
import unittest
from unittest import mock

from gov.kms import KmsError, KmsProvider, kms_provider_from_config
from gov.kms_vault import (
    UrllibVaultTransport,
    VaultKmsProvider,
    VaultTransport,
    VaultTransportError,
)


def _provider(token="tok-test-1", **kw):
    t = FakeVaultTransport(token=token)
    t.create_key("prod-key-1")
    t.create_key("prod-key-2")
    return VaultKmsProvider(t, token=token, **kw), t


class ContractTest(unittest.TestCase):
    def test_implements_kms_provider(self):
        p, _ = _provider()
        self.assertIsInstance(p, KmsProvider)
        self.assertTrue(issubclass(VaultKmsProvider, KmsProvider))
        self.assertEqual(p.provider_name, "vault")

    def test_constructor_validation(self):
        t = FakeVaultTransport()
        with self.assertRaises(TypeError):
            VaultKmsProvider("not-a-transport", token="x")
        with self.assertRaises(ValueError):
            VaultKmsProvider(t, token="")
        with self.assertRaises(ValueError):
            VaultKmsProvider(t, token=None)
        with self.assertRaises(ValueError):
            VaultKmsProvider(t, token="x", mount="../evil")
        # Happy path with a non-default mount.
        p = VaultKmsProvider(t, token="x", mount="transit-prod")
        self.assertEqual(p._mount, "transit-prod")

    def test_bad_key_ids_rejected_before_network(self):
        p, t = _provider()
        for bad in ("../evil", "", "has space", "x" * 300):
            with self.assertRaises(KmsError, msg=bad):
                p.wrap_data_key(bad, b"\x00" * 32)
            with self.assertRaises(KmsError, msg=bad):
                p.describe_key(bad)
        self.assertEqual(t.calls, [])  # rejected locally, no HTTP call

    def test_empty_plaintext_rejected(self):
        p, _ = _provider()
        with self.assertRaises(KmsError):
            p.wrap_data_key("prod-key-1", b"")


class RoundtripTest(unittest.TestCase):
    def test_wrap_unwrap_roundtrip(self):
        p, _ = _provider()
        pt = secrets.token_bytes(32)
        blob = p.wrap_data_key("prod-key-1", pt)
        self.assertEqual(p.unwrap_data_key("prod-key-1", blob), pt)

    def test_wrap_produces_opaque_bound_blob(self):
        p, _ = _provider()
        pt = b"P" * 32
        blob = p.wrap_data_key("prod-key-1", pt)
        self.assertIsInstance(blob, bytes)
        self.assertTrue(blob.startswith(b"VAULTKMS1"))
        self.assertNotIn(pt, blob)  # envelope binds kid + transit handle
        self.assertIn(b"prod-key-1", blob)  # kid binding is inspectable
        # Two wraps of the same plaintext differ (fresh transit handle).
        self.assertNotEqual(p.wrap_data_key("prod-key-1", pt),
                            p.wrap_data_key("prod-key-1", pt))

    def test_key_id_with_special_chars_is_url_quoted(self):
        t = FakeVaultTransport()
        t.create_key("team:sub/key")
        p = VaultKmsProvider(t, token="test-vault-token")
        pt = secrets.token_bytes(32)
        blob = p.wrap_data_key("team:sub/key", pt)
        self.assertEqual(p.unwrap_data_key("team:sub/key", blob), pt)
        paths = [c[1] for c in t.calls]
        self.assertTrue(any("team%3Asub%2Fkey" in q for q in paths),
                        paths)

    def test_custom_mount_used_in_paths(self):
        t = FakeVaultTransport()
        t.create_key("k1")
        p = VaultKmsProvider(t, token="test-vault-token",
                             mount="transit-prod")
        p.describe_key("k1")
        self.assertTrue(any("/v1/transit-prod/keys/" in c[1]
                            for c in t.calls), t.calls)


class KeyIdBindingTest(unittest.TestCase):
    """Attack-2 (kms impersonator) regression for the Vault backend: a
    blob wrapped under one key id must never unwrap under another."""

    def test_unwrap_key_id_mismatch_raises(self):
        p, _ = _provider()
        evil_blob = p.wrap_data_key("prod-key-2", b"E" * 32)
        with self.assertRaises(KmsError):
            p.unwrap_data_key("prod-key-1", evil_blob)

    def test_cross_key_ciphertext_swap_raises(self):
        """Surgical attack: envelope says prod-key-1 but the transit
        handle was minted under prod-key-2. The adapter's binding check
        passes (kid matches); the transit decrypt must still fail."""
        p, _ = _provider()
        blob2 = p.wrap_data_key("prod-key-2", b"S" * 32)
        _, ct2 = VaultKmsProvider._parse_envelope(blob2, "prod-key-2")
        evil = VaultKmsProvider._envelope("prod-key-1", ct2)
        with self.assertRaises(KmsError):
            p.unwrap_data_key("prod-key-1", evil)


class TamperTest(unittest.TestCase):
    def test_tampered_and_malformed_blobs_rejected(self):
        p, _ = _provider()
        blob = bytearray(p.wrap_data_key("prod-key-1", b"\x01" * 32))
        blob[14] ^= 0xFF  # flip a byte inside the envelope
        bad_blobs = [
            bytes(blob),
            bytes(blob)[:-6],          # truncated
            b"",                       # empty
            b"short",                  # too short for magic
            b"NOPEMAGIC" + b"\x00" * 20,  # bad magic
            p.wrap_data_key("prod-key-1", b"\x02" * 32)[:-1],  # clipped
        ]
        for bad in bad_blobs:
            with self.assertRaises(KmsError):
                p.unwrap_data_key("prod-key-1", bad)

    def test_unknown_ciphertext_handle_rejected(self):
        p, t = _provider()
        blob = p.wrap_data_key("prod-key-1", b"U" * 32)
        kid, _ = VaultKmsProvider._parse_envelope(blob, "prod-key-1")
        forged_ct = ("vault:v1:" + base64.urlsafe_b64encode(
            secrets.token_bytes(18)).decode("ascii")).encode("utf-8")
        evil = VaultKmsProvider._envelope(kid, forged_ct)
        with self.assertRaises(KmsError):
            p.unwrap_data_key("prod-key-1", evil)


class UnknownKeyTest(unittest.TestCase):
    def test_unknown_key_raises(self):
        p, _ = _provider()
        with self.assertRaises(KmsError):
            p.wrap_data_key("no-such-key", b"x" * 32)
        with self.assertRaises(KmsError):
            p.describe_key("no-such-key")
        with self.assertRaises(KmsError):
            p.unwrap_data_key("no-such-key", b"junk-blob")

    def test_deleted_key_raises(self):
        p, t = _provider()
        t.delete_key("prod-key-1")
        with self.assertRaises(KmsError):
            p.wrap_data_key("prod-key-1", b"x" * 32)


class FailClosedTest(unittest.TestCase):
    def test_transport_outage_raises_on_all_ops(self):
        p, t = _provider()
        blob = p.wrap_data_key("prod-key-1", b"x" * 32)
        t.outage = True
        try:
            for op in (lambda: p.wrap_data_key("prod-key-1", b"x" * 32),
                       lambda: p.unwrap_data_key("prod-key-1", blob),
                       lambda: p.describe_key("prod-key-1")):
                with self.assertRaises(KmsError):
                    op()
        finally:
            t.outage = False

    def test_auth_failure_raises(self):
        t = FakeVaultTransport(token="correct-token")
        t.create_key("prod-key-1")
        p = VaultKmsProvider(t, token="wrong-token")
        with self.assertRaises(KmsError) as cm:
            p.wrap_data_key("prod-key-1", b"x" * 32)
        self.assertIn("403", str(cm.exception))
        with self.assertRaises(KmsError):
            p.describe_key("prod-key-1")

    def test_broken_transport_raises_kms_error_not_raw(self):
        class Broken(VaultTransport):
            def request(self, method, path, headers, body):
                raise RuntimeError("boom")

        p = VaultKmsProvider(Broken(), token="x")
        with self.assertRaises(KmsError):
            p.describe_key("prod-key-1")


class DescribeTest(unittest.TestCase):
    def test_describe_key_metadata_only(self):
        p, _ = _provider()
        desc = p.describe_key("prod-key-1")
        self.assertEqual(desc.key_id, "prod-key-1")
        self.assertEqual(desc.provider_name, "vault")
        self.assertTrue(desc.enabled)
        self.assertEqual(desc.arn_or_name, "vault:transit:prod-key-1")
        d = desc.describe()
        self.assertEqual(d["key_id"], "prod-key-1")


class SecrecyTest(unittest.TestCase):
    """Key material, ciphertext handles, and the Vault token must never
    appear in logs or exception messages."""

    def test_no_key_material_in_logs_or_exceptions(self):
        sentinel_pt = b"S3NT1N3L-PT-" + secrets.token_bytes(8)
        sentinel_tok = "tok-S3NT1N3L-" + secrets.token_hex(4)
        t = FakeVaultTransport(token=sentinel_tok)
        t.create_key("k1")
        t.create_key("k2")
        p = VaultKmsProvider(t, token=sentinel_tok)
        blob = p.wrap_data_key("k1", sentinel_pt)

        with self.assertLogs("gov.kms.vault", level="DEBUG") as cm:
            p.wrap_data_key("k1", sentinel_pt)
            p.unwrap_data_key("k1", blob)
            with self.assertRaises(KmsError):
                p.unwrap_data_key("k2", blob)      # kid mismatch
            with self.assertRaises(KmsError):
                p.unwrap_data_key("k1", b"GARBAGE")
        self.assertTrue(cm.records, "expected log records")
        for rec in cm.records:
            msg = rec.getMessage()
            self.assertNotIn(sentinel_pt.decode("latin1"), msg)
            self.assertNotIn(sentinel_tok, msg)
            self.assertNotIn("vault:v1:", msg)  # no ciphertext handles

        t.outage = True
        try:
            with self.assertRaises(KmsError) as e1:
                p.wrap_data_key("k1", sentinel_pt)
            with self.assertRaises(KmsError) as e2:
                p.unwrap_data_key("k2", blob)
        finally:
            t.outage = False
        for exc in (e1.exception, e2.exception):
            text = str(exc)
            self.assertNotIn(sentinel_pt.decode("latin1"), text)
            self.assertNotIn(sentinel_tok, text)
            self.assertNotIn("vault:v1:", text)

    def test_token_never_in_transport_error_text(self):
        # The urllib transport's I/O error text must not echo the token.
        tr = UrllibVaultTransport("http://127.0.0.1:1",
                                  allow_http=True, timeout_s=2)
        with self.assertRaises(VaultTransportError) as cm:
            tr.request("GET", "/v1/transit/keys/k",
                       {"X-Vault-Token": "tok-S3CR3T"}, b"")
        self.assertNotIn("tok-S3CR3T", str(cm.exception))


class UrllibTransportTest(unittest.TestCase):
    """Localhost-only checks of the real (stdlib) transport: no
    external network, ever."""

    def test_refuses_plaintext_http_by_default(self):
        with self.assertRaises(ValueError):
            UrllibVaultTransport("http://127.0.0.1:8200")
        tr = UrllibVaultTransport("http://127.0.0.1:8200",
                                  allow_http=True)
        self.assertTrue(tr._base_url.startswith("http://"))
        with self.assertRaises(ValueError):
            UrllibVaultTransport("ftp://x")

    def test_connection_refused_maps_to_transport_error(self):
        tr = UrllibVaultTransport("http://127.0.0.1:1", allow_http=True,
                                  timeout_s=2)
        with self.assertRaises(VaultTransportError):
            tr.request("GET", "/v1/sys/health", {}, b"")

    def test_http_error_status_returned_not_raised(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"errors":["permission denied"]}'
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            tr = UrllibVaultTransport("http://127.0.0.1:%d" % port,
                                      allow_http=True, timeout_s=5)
            status, body = tr.request("GET", "/v1/transit/keys/k", {}, b"")
            self.assertEqual(status, 403)
            self.assertIn(b"permission denied", body)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_adapter_maps_http_error_to_kms_error(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = b'{"errors":["permission denied"]}'
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            tr = UrllibVaultTransport("http://127.0.0.1:%d" % port,
                                      allow_http=True, timeout_s=5)
            p = VaultKmsProvider(tr, token="t")
            with self.assertRaises(KmsError) as cm:
                p.wrap_data_key("any-key", b"x" * 32)
            self.assertIn("403", str(cm.exception))
            self.assertIn("permission denied", str(cm.exception))
        finally:
            srv.shutdown()
            srv.server_close()


class FactoryTest(unittest.TestCase):
    """``kms_provider_from_config`` ``provider: vault`` branch.

    Credentials come from the environment (VAULT_ADDR / VAULT_TOKEN)
    only — never from the operator config mapping. Missing credentials
    fail closed.
    """

    def _env_without(self, *names):
        env = {k: v for k, v in os.environ.items()
               if k not in names}
        return mock.patch.dict(os.environ, env, clear=True)

    def _env_with(self, **kw):
        return mock.patch.dict(os.environ, kw)

    def test_vault_branch_builds_provider_from_env(self):
        with self._env_with(VAULT_ADDR="https://vault.internal:8200",
                            VAULT_TOKEN="tok-env-1"):
            p = kms_provider_from_config({"provider": "vault"})
        self.assertIsInstance(p, VaultKmsProvider)
        self.assertIsInstance(p._transport, UrllibVaultTransport)
        self.assertEqual(p._mount, "transit")
        self.assertEqual(p._token, "tok-env-1")

    def test_vault_branch_mount_override(self):
        with self._env_with(VAULT_ADDR="https://vault.internal:8200",
                            VAULT_TOKEN="t"):
            p = kms_provider_from_config({"provider": "vault",
                                          "mount": "transit-prod"})
        self.assertEqual(p._mount, "transit-prod")

    def test_vault_branch_missing_addr_fails_closed(self):
        with self._env_without("VAULT_ADDR", "VAULT_TOKEN"):
            with self.assertRaises(KmsError):
                kms_provider_from_config({"provider": "vault"})

    def test_vault_branch_missing_token_fails_closed(self):
        with self._env_with(VAULT_ADDR="https://vault.internal:8200"):
            with self._env_without("VAULT_TOKEN"):
                with self.assertRaises(KmsError):
                    kms_provider_from_config({"provider": "vault"})

    def test_vault_branch_token_never_from_config_file(self):
        # A 'token' key smuggled into the operator mapping must NOT be
        # honored — the token comes from the environment only.
        with self._env_with(VAULT_ADDR="https://vault.internal:8200",
                            VAULT_TOKEN="tok-env-real"):
            p = kms_provider_from_config({"provider": "vault",
                                          "token": "tok-config-evil"})
        self.assertEqual(p._token, "tok-env-real")

    def test_vault_branch_rejects_bad_mount(self):
        with self._env_with(VAULT_ADDR="https://vault.internal:8200",
                            VAULT_TOKEN="t"):
            with self.assertRaises((KmsError, ValueError)):
                kms_provider_from_config({"provider": "vault",
                                          "mount": "../evil"})


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main(verbosity=2)
