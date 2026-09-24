"""Live-server tests for gov/kms_vault.py against a REAL HashiCorp Vault.

Spike-A (real KMS validation). These tests spin up an actual
``vault server -dev`` (loopback only, ephemeral, no TLS) and run the
``VaultKmsProvider`` adapter against the real transit engine —
round-trip, key-id binding, key rotation, fail-closed outage/auth
paths, and the config factory.

SKIP-CLEAN: every test that needs the server skips via
``self.skipTest`` when no ``vault`` binary is found on PATH or the dev
server cannot be started. They are never run by default CI and do not
touch any production or shared Vault.

Bring-up: ``vault`` on PATH (https://releases.hashicorp.com/vault —
the spike used v1.20.0). Optional env overrides:
  VAULT_TEST_BINARY  path to the vault binary
  VAULT_TEST_ADDR    use an ALREADY-RUNNING dev server instead of
                     spawning one (token via VAULT_TEST_TOKEN)

Per repo convention this module sets the deployment-mode gate at
module level and must be verified under a clean environment:
``env -u GOV_DEPLOYMENT_MODE <venv-python> -m unittest tests.test_kms_vault_live -v``.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import base64
import json
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from gov.kms import KmsError, EnvelopeKeyRing, kms_provider_from_config
from gov.kms_vault import VaultKmsProvider, UrllibVaultTransport

_LIVE_PORT = 18200
_LIVE_ADDR = "http://127.0.0.1:%d" % _LIVE_PORT
_KEY_A = "gov-spike-a"
_KEY_B = "gov-spike-a-other"
_TIMEOUT = 10


def _vault_binary():
    return (os.environ.get("VAULT_TEST_BINARY")
            or shutil.which("vault"))


def _ct_version(blob):
    """Transit key version embedded in the wrapped blob's ciphertext."""
    off = len(b"VAULTKMS1") + 2 + len(_KEY_A) + 4
    head = bytes(blob)[off:off + 16].decode("utf-8")  # "vault:vN:..."
    return int(head.split(":")[1][1:])


class _DevServer:
    """Owns one loopback `vault server -dev` subprocess."""

    def __init__(self, binary):
        self.log_path = tempfile.mktemp(prefix="vault-dev-", suffix=".log")
        self._log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [binary, "server", "-dev",
             "-dev-listen-address=127.0.0.1:%d" % _LIVE_PORT],
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env={**os.environ, "VAULT_DEV_LISTEN_ADDRESS":
                 "127.0.0.1:%d" % _LIVE_PORT})
        self.token = self._await_token()
        env = {**os.environ, "VAULT_ADDR": _LIVE_ADDR,
               "VAULT_TOKEN": self.token}
        subprocess.run([binary, "secrets", "enable", "-path=transit",
                        "transit"], env=env, check=True,
                       capture_output=True)
        for k in (_KEY_A, _KEY_B):
            subprocess.run([binary, "write", "-f",
                            "transit/keys/%s" % k], env=env, check=True,
                           capture_output=True)

    def _await_token(self):
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with open(self.log_path) as f:
                    for line in f:
                        m = re.search(r"Root Token:\s*(\S+)", line)
                        if m:
                            return m.group(1)
            except FileNotFoundError:
                pass
            # also wait for the health endpoint so the listener is up
            try:
                urllib.request.urlopen(_LIVE_ADDR + "/v1/sys/health",
                                       timeout=1).read()
            except Exception:
                pass
            time.sleep(0.2)
        raise RuntimeError("dev server did not print a root token in 30s")

    def rotate(self, key):
        env = {**os.environ, "VAULT_ADDR": _LIVE_ADDR,
               "VAULT_TOKEN": self.token}
        subprocess.run([_vault_binary(), "write", "-f",
                        "transit/keys/%s/rotate" % key],
                       env=env, check=True, capture_output=True)

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._log.close()


def _provider(token, addr=_LIVE_ADDR, timeout_s=5):
    return VaultKmsProvider(
        UrllibVaultTransport(addr, allow_http=True, timeout_s=timeout_s),
        token=token)


class LiveVaultAdapterTests(unittest.TestCase):
    """Against a real dev server. Skips clean without a vault binary."""

    server = None

    @classmethod
    def setUpClass(cls):
        binary = _vault_binary()
        if not binary:
            raise unittest.SkipTest("no `vault` binary on PATH "
                                    "(spike install: releases.hashicorp.com/vault)")
        ext = os.environ.get("VAULT_TEST_ADDR")
        if ext:
            tok = os.environ.get("VAULT_TEST_TOKEN")
            if not tok:
                raise unittest.SkipTest(
                    "VAULT_TEST_ADDR set but VAULT_TEST_TOKEN missing")
            cls.server = None
            cls.addr, cls.token = ext, tok
            return
        try:
            cls.server = _DevServer(binary)
        except Exception as e:
            raise unittest.SkipTest("could not start dev server: %s" % e)
        cls.addr, cls.token = _LIVE_ADDR, cls.server.token

    @classmethod
    def tearDownClass(cls):
        if cls.server is not None:
            cls.server.close()
            cls.server = None

    def setUp(self):
        self.prov = _provider(self.token, self.addr)

    # -- contract: round-trip -----------------------------------------

    def test_live_round_trip(self):
        pt = secrets.token_bytes(32)
        blob = self.prov.wrap_data_key(_KEY_A, pt)
        self.assertIsInstance(blob, bytes)
        self.assertTrue(blob.startswith(b"VAULTKMS1"))
        self.assertEqual(self.prov.unwrap_data_key(_KEY_A, blob), pt)

    def test_live_round_trip_empty_plaintext_rejected(self):
        with self.assertRaises(KmsError):
            self.prov.wrap_data_key(_KEY_A, b"")

    def test_live_round_trip_invalid_key_id_rejected(self):
        with self.assertRaises(KmsError):
            self.prov.wrap_data_key("not a valid id!!", b"x" * 32)

    # -- contract: key-id binding --------------------------------------

    def test_live_key_id_binding_wrong_key(self):
        blob = self.prov.wrap_data_key(_KEY_A, secrets.token_bytes(32))
        with self.assertRaises(KmsError):
            self.prov.unwrap_data_key(_KEY_B, blob)

    def test_live_key_id_binding_tampered_envelope(self):
        blob = bytearray(self.prov.wrap_data_key(
            _KEY_A, secrets.token_bytes(32)))
        # kid starts at offset 9, length _KEY_A; corrupt one byte
        blob[9 + 3] ^= 0x01
        with self.assertRaises(KmsError):
            self.prov.unwrap_data_key(_KEY_A, bytes(blob))

    def test_live_server_cross_key_decrypt_refused(self):
        # Defense in depth behind the adapter's own binding: the real
        # server also refuses decrypting A's ciphertext under B.
        blob = self.prov.wrap_data_key(_KEY_A, secrets.token_bytes(32))
        off = len(b"VAULTKMS1") + 2 + len(_KEY_A) + 4
        ct = blob[off:].decode("utf-8")
        self.assertTrue(ct.startswith("vault:v"))
        with self.assertRaises(KmsError):
            self.prov._api("test", "POST",
                           self.prov._path("decrypt", _KEY_B),
                           {"ciphertext": ct})

    def test_live_tampered_transit_ciphertext(self):
        blob = bytearray(self.prov.wrap_data_key(
            _KEY_A, secrets.token_bytes(32)))
        off = len(b"VAULTKMS1") + 2 + len(_KEY_A) + 4 + 12
        blob[off] ^= 0x01
        with self.assertRaises(KmsError):
            self.prov.unwrap_data_key(_KEY_A, bytes(blob))

    def test_live_garbage_blob(self):
        with self.assertRaises(KmsError):
            self.prov.unwrap_data_key(_KEY_A, b"not-a-vault-blob")

    # -- contract: rotation --------------------------------------------

    def test_live_rotation_old_ciphertext_still_decrypts(self):
        if self.server is None:  # external server: don't mutate it
            self.skipTest("rotation test needs the owned dev server")
        pt = secrets.token_bytes(32)
        old_blob = self.prov.wrap_data_key(_KEY_A, pt)
        old_ver = _ct_version(old_blob)
        self.server.rotate(_KEY_A)
        self.assertEqual(self.prov.unwrap_data_key(_KEY_A, old_blob), pt)
        new_blob = self.prov.wrap_data_key(_KEY_A, pt)
        new_ver = _ct_version(new_blob)
        self.assertEqual(new_ver, old_ver + 1)

    # -- contract: describe ---------------------------------------------

    def test_live_describe_key(self):
        d = self.prov.describe_key(_KEY_A).describe()
        self.assertEqual(d["provider"], "vault")
        self.assertEqual(d["key_id"], _KEY_A)
        self.assertTrue(d["enabled"])
        self.assertNotIn("material", str(d).lower())

    def test_live_describe_unknown_key(self):
        with self.assertRaises(KmsError):
            self.prov.describe_key("gov-no-such-key-ever")

    # -- contract: fail-closed ------------------------------------------

    def test_live_wrong_token_is_kms_error(self):
        bad = _provider("bogus-token")
        with self.assertRaises(KmsError):
            bad.wrap_data_key(_KEY_A, secrets.token_bytes(32))

    def test_live_unreachable_is_kms_error(self):
        dead = _provider(self.token, "http://127.0.0.1:1", timeout_s=2)
        with self.assertRaises(KmsError):
            dead.wrap_data_key(_KEY_A, secrets.token_bytes(32))
        with self.assertRaises(KmsError):
            dead.describe_key(_KEY_A)

    def test_live_unknown_mount_is_kms_error(self):
        bad = VaultKmsProvider(
            UrllibVaultTransport(self.addr, allow_http=True),
            token=self.token, mount="no-such-mount")
        with self.assertRaises(KmsError):
            bad.wrap_data_key(_KEY_A, secrets.token_bytes(32))

    # -- end-to-end through the envelope protocol -----------------------

    def test_live_envelope_keyring_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            ring_path = os.path.join(td, "ring.json")
            ring = EnvelopeKeyRing.generate(self.prov, _KEY_A)
            ring.save(ring_path)
            loaded = EnvelopeKeyRing.load(ring_path)
            mat = loaded.materialize(self.prov)
            self.assertEqual(len(mat.get("epoch-1").key), 64)  # 32 bytes hex
            # retired epochs unwrap lazily through the real server too
            loaded.rotate(self.prov)
            mat2 = loaded.materialize(self.prov)
            self.assertEqual(mat2.get("epoch-1").key,
                             mat.get("epoch-1").key)


# ---------------------------------------------------------------------------
# Adapter-level (no server needed) — kept here so the live file documents
# the whole boundary. These run everywhere.
# ---------------------------------------------------------------------------

class TransportDisciplineTests(unittest.TestCase):
    def test_plaintext_http_refused_without_allow_http(self):
        with self.assertRaises(ValueError):
            UrllibVaultTransport("http://127.0.0.1:8200")

    def test_https_constructs(self):
        t = UrllibVaultTransport("https://127.0.0.1:8200")
        self.assertIsNotNone(t)

    def test_bad_scheme_rejected(self):
        with self.assertRaises(ValueError):
            UrllibVaultTransport("ftp://example.com")

    def test_factory_vault_http_addr_refused(self):
        # F160: the factory must refuse a plaintext VAULT_ADDR
        # fail-closed (token must not cross cleartext) with the typed
        # KmsError — the old bare ValueError was the filed bug.
        os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
        os.environ["VAULT_TOKEN"] = "x"
        try:
            with self.assertRaises(KmsError):
                kms_provider_from_config({"provider": "vault"})
        finally:
            del os.environ["VAULT_ADDR"]
            del os.environ["VAULT_TOKEN"]

    def test_factory_vault_needs_env(self):
        for var in ("VAULT_ADDR", "VAULT_TOKEN"):
            os.environ.pop(var, None)
        with self.assertRaises(KmsError):
            kms_provider_from_config({"provider": "vault"})
        os.environ["VAULT_ADDR"] = "https://127.0.0.1:8200"
        with self.assertRaises(KmsError):
            kms_provider_from_config({"provider": "vault"})
        del os.environ["VAULT_ADDR"]


if __name__ == "__main__":
    unittest.main()
