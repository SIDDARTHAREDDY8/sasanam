#!/usr/bin/env python3
"""Unit tests for gov/spiffe_credential_provider.py (wave-232 lane A).

Independent expected values (literals, not recomputed from the module).
The 8 attack-shape probes live in evals/w232_spiffe_probes.py; these
tests pin constructor edges, the login error taxonomy, caching, and the
factory wiring.
"""

import base64
import json
import os
import tempfile
import threading
import unittest

from gov.kms import KmsError, kms_provider_from_config
from gov.kms_vault import VaultKmsProvider, VaultTransport
from gov.spiffe_credential_provider import (
    AudienceMismatchError,
    AuthRefusedError,
    CredentialProvider,
    FileJwtSvidCredentialProvider,
    PermissionInvalidError,
    SpiffeError,
    SvidExpiredError,
    SvidMalformedError,
    SvidUnavailableError,
    vault_provider_from_spiffe_config,
)

_AUD = "vault://unit-cluster"
_ROLE = "unit-role"
_NOW = 1700000000


def _jwt(payload):
    def b64(o):
        return base64.urlsafe_b64encode(
            json.dumps(o, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
    return "%s.%s.%s" % (b64({"alg": "none"}), b64(payload), "sig")


class _FakeTransport(VaultTransport):
    """Scriptable fake: login_script = [(status, auth_dict|None), ...]."""

    def __init__(self, login_script=None):
        self.calls = []
        self.login_script = list(login_script or [])
        self._lock = threading.Lock()

    def request(self, method, path, headers, body):
        with self._lock:
            self.calls.append((method, path, dict(headers), body))
            if path == "/v1/auth/jwt/login":
                if self.login_script:
                    status, auth = self.login_script.pop(0)
                    if status == 200:
                        return 200, json.dumps(
                            {"auth": auth}).encode("utf-8")
                    return status, b'{"errors":["denied"]}'
                return 200, json.dumps(
                    {"auth": {"client_token": "tok-default",
                             "lease_duration": 300}}).encode("utf-8")
            if path.endswith("/encrypt/k1"):
                return 200, json.dumps(
                    {"data": {"ciphertext": "vault:v1:AAA",
                             "key_version": 1}}).encode("utf-8")
            return 404, b'{"errors":["no handler"]}'


def _write(path, text, mode=0o600):
    with open(path, "w") as fh:
        fh.write(text)
    os.chmod(path, mode)


def _svid_file(tmpdir, payload, mode=0o600):
    path = os.path.join(tmpdir, "svid.jwt")
    _write(path, _jwt(payload), mode)
    return path


def _provider(path, transport, **kw):
    kw.setdefault("now", lambda: _NOW)
    return FileJwtSvidCredentialProvider(
        path, audience=_AUD, role=_ROLE, transport=transport, **kw)


def _good_payload(**over):
    p = {"sub": "spiffe://sasanam/ns/u/sa/x", "aud": _AUD,
         "exp": _NOW + 3600}
    p.update(over)
    return p


class ConstructorTest(unittest.TestCase):
    def test_abc_not_instantiable(self):
        with self.assertRaises(TypeError):
            CredentialProvider()  # abstract

    def test_bad_args_refused(self):
        t = _FakeTransport()
        with self.assertRaises(ValueError):
            FileJwtSvidCredentialProvider(
                "", audience=_AUD, role=_ROLE, transport=t)
        with self.assertRaises(ValueError):
            FileJwtSvidCredentialProvider(
                "/x", audience="", role=_ROLE, transport=t)
        with self.assertRaises(ValueError):
            FileJwtSvidCredentialProvider(
                "/x", audience=_AUD, role="", transport=t)
        with self.assertRaises(TypeError):
            FileJwtSvidCredentialProvider(
                "/x", audience=_AUD, role=_ROLE, transport=None)
        with self.assertRaises(ValueError):
            FileJwtSvidCredentialProvider(
                "/x", audience=_AUD, role=_ROLE, transport=t,
                clock_skew_s=-1)

    def test_errors_are_kms_errors_with_codes(self):
        for cls, code in (
                (SvidUnavailableError, "spiffe-svid-unavailable"),
                (SvidExpiredError, "spiffe-svid-expired"),
                (SvidMalformedError, "spiffe-svid-malformed"),
                (AudienceMismatchError, "spiffe-audience-mismatch"),
                (AuthRefusedError, "spiffe-auth-refused"),
                (PermissionInvalidError, "spiffe-permission-invalid")):
            exc = cls("msg")
            self.assertIsInstance(exc, KmsError)
            self.assertIsInstance(exc, SpiffeError)
            self.assertEqual(exc.code, code)


class SvidCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w232u")
        self.t = _FakeTransport()

    def test_happy_path_caches_token(self):
        path = _svid_file(self.tmp, _good_payload())
        p = _provider(path, self.t)
        self.assertEqual(p.current_token(), "tok-default")
        self.assertEqual(p.current_token(), "tok-default")
        logins = [c for c in self.t.calls if c[1] == "/v1/auth/jwt/login"]
        self.assertEqual(len(logins), 1)
        # The login carries no X-Vault-Token header.
        self.assertNotIn("X-Vault-Token", logins[0][2])

    def test_invalidate_reauthenticates(self):
        path = _svid_file(self.tmp, _good_payload())
        t = _FakeTransport(login_script=[
            (200, {"client_token": "tok-1", "lease_duration": 300}),
            (200, {"client_token": "tok-2", "lease_duration": 300})])
        p = _provider(path, t)
        self.assertEqual(p.current_token(), "tok-1")
        p.invalidate()
        self.assertEqual(p.current_token(), "tok-2")

    def test_directory_refused_malformed(self):
        # A directory at the SVID path is a wrong file shape
        # (malformed), not agent-down (unavailable).
        p = _provider(self.tmp, self.t)
        with self.assertRaises(SvidMalformedError) as cm:
            p.current_token()
        self.assertEqual(cm.exception.code, "spiffe-svid-malformed")

    def test_oversize_refused(self):
        path = os.path.join(self.tmp, "big.jwt")
        _write(path, "a" * 9000)
        p = _provider(path, self.t)
        with self.assertRaises(SvidMalformedError):
            p.current_token()

    def test_non_ascii_refused(self):
        path = os.path.join(self.tmp, "bin.jwt")
        with open(path, "wb") as fh:
            fh.write(b"\xff\xfe" + b"a" * 10)
        os.chmod(path, 0o600)
        p = _provider(path, self.t)
        with self.assertRaises(SvidMalformedError):
            p.current_token()

    def test_bad_json_refused(self):
        path = os.path.join(self.tmp, "j.jwt")
        # Payload segment decodes to b"0": valid base64, invalid JSON
        # object -- and even if parsed, not a dict.
        _write(path, "eyJhbGciOiJub25lIn0.e30.sig")
        p = _provider(path, self.t)
        with self.assertRaises(SvidMalformedError):
            p.current_token()

    def test_non_dict_payload_refused(self):
        def b64(o):
            return base64.urlsafe_b64encode(
                json.dumps(o).encode()).rstrip(b"=").decode()
        path = os.path.join(self.tmp, "l.jwt")
        _write(path, "%s.%s.%s" % (b64({"alg": "none"}), b64([1, 2]),
                                   "sig"))
        p = _provider(path, self.t)
        with self.assertRaises(SvidMalformedError):
            p.current_token()

    def test_bool_exp_refused(self):
        path = _svid_file(self.tmp, _good_payload(exp=True))
        p = _provider(path, self.t)
        with self.assertRaises(SvidMalformedError):
            p.current_token()

    def test_bad_aud_type_refused(self):
        path = _svid_file(self.tmp, _good_payload(aud={"x": 1}))
        p = _provider(path, self.t)
        with self.assertRaises(SvidMalformedError):
            p.current_token()

    def test_future_nbf_refused(self):
        path = _svid_file(self.tmp,
                          _good_payload(nbf=_NOW + 3600))
        p = _provider(path, self.t)
        with self.assertRaises(SvidMalformedError):
            p.current_token()

    def test_exp_within_skew_accepted(self):
        # exp 30s in the past is within the 60s skew allowance.
        path = _svid_file(self.tmp, _good_payload(exp=_NOW - 30))
        p = _provider(path, self.t)
        self.assertEqual(p.current_token(), "tok-default")


class LoginTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w232ul")
        self.path = _svid_file(self.tmp, _good_payload())

    def test_http_500_refused(self):
        t = _FakeTransport(login_script=[(500, None)])
        p = _provider(self.path, t)
        with self.assertRaises(AuthRefusedError) as cm:
            p.current_token()
        self.assertEqual(cm.exception.code, "spiffe-auth-refused")

    def test_malformed_response_refused(self):
        t = _FakeTransport()

        def bad_login(method, path, headers, body):
            return 200, b"not-json"

        t.request = bad_login
        p = _provider(self.path, t)
        with self.assertRaises(AuthRefusedError):
            p.current_token()

    def test_empty_token_refused(self):
        t = _FakeTransport(login_script=[
            (200, {"client_token": "", "lease_duration": 60})])
        p = _provider(self.path, t)
        with self.assertRaises(AuthRefusedError):
            p.current_token()

    def test_negative_lease_refused(self):
        t = _FakeTransport(login_script=[
            (200, {"client_token": "tok", "lease_duration": -5})])
        p = _provider(self.path, t)
        with self.assertRaises(AuthRefusedError):
            p.current_token()

    def test_transport_failure_refused(self):
        t = _FakeTransport()

        def down(method, path, headers, body):
            raise IOError("simulated outage")

        t.request = down
        p = _provider(self.path, t)
        with self.assertRaises(AuthRefusedError):
            p.current_token()

    def test_login_body_shape(self):
        t = _FakeTransport()
        p = _provider(self.path, t)
        p.current_token()
        _m, path, _h, body = t.calls[0]
        self.assertEqual(path, "/v1/auth/jwt/login")
        doc = json.loads(body.decode("utf-8"))
        self.assertEqual(doc["role"], _ROLE)
        self.assertEqual(doc["jwt"].count("."), 2)


class ApiRetryTest(unittest.TestCase):
    def test_data_403_retries_once_then_succeeds(self):
        t = _FakeTransport()
        calls = {"n": 0}
        orig = t.request

        def scripted(method, path, headers, body):
            if path.endswith("/encrypt/k1"):
                calls["n"] += 1
                if calls["n"] == 1:
                    return 403, b'{"errors":["bad token"]}'
            return orig(method, path, headers, body)

        t.request = scripted
        path = _svid_file(tempfile.mkdtemp(prefix="w232ur"),
                          _good_payload())
        prov = _provider(path, t)
        kms = VaultKmsProvider(t, credential_provider=prov)
        blob = kms.wrap_data_key("k1", b"data")
        self.assertTrue(blob.startswith(b"VAULTKMS1"))
        self.assertEqual(calls["n"], 2)

    def test_data_403_twice_fails_closed(self):
        t = _FakeTransport()

        def always403(method, path, headers, body):
            if path == "/v1/auth/jwt/login":
                return 200, json.dumps(
                    {"auth": {"client_token": "tok",
                             "lease_duration": 300}}).encode("utf-8")
            return 403, b'{"errors":["bad token"]}'

        t.request = always403
        path = _svid_file(tempfile.mkdtemp(prefix="w232ur2"),
                          _good_payload())
        prov = _provider(path, t)
        kms = VaultKmsProvider(t, credential_provider=prov)
        with self.assertRaises(KmsError):
            kms.wrap_data_key("k1", b"data")


class FactoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w232uf")
        self.path = _svid_file(self.tmp, _good_payload())
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def _mapping(self, **over):
        m = {"provider": "vault-spiffe", "svid_path": self.path,
             "audience": _AUD, "role": _ROLE, "allow_http": True}
        m.update(over)
        return m

    def test_bad_mapping_refused(self):
        with self.assertRaises(KmsError):
            vault_provider_from_spiffe_config("nope")
        with self.assertRaises(KmsError):
            vault_provider_from_spiffe_config(
                self._mapping(svid_path=""))
        with self.assertRaises(KmsError):
            vault_provider_from_spiffe_config(
                self._mapping(audience=""))
        with self.assertRaises(KmsError):
            vault_provider_from_spiffe_config(
                self._mapping(role=""))
        with self.assertRaises(KmsError):
            vault_provider_from_spiffe_config(
                self._mapping(timeout_s=-1))
        with self.assertRaises(KmsError):
            vault_provider_from_spiffe_config(
                self._mapping(allow_http="yes"))

    def test_missing_addr_refused(self):
        os.environ.pop("VAULT_ADDR", None)
        with self.assertRaises(KmsError):
            vault_provider_from_spiffe_config(self._mapping())

    def test_builds_provider(self):
        os.environ["VAULT_ADDR"] = "http://127.0.0.1:1"
        kms = vault_provider_from_spiffe_config(self._mapping())
        self.assertIsInstance(kms, VaultKmsProvider)
        self.assertIsNotNone(kms._credential_provider)
        self.assertIsNone(kms._token)

    def test_kms_config_wiring(self):
        os.environ["VAULT_ADDR"] = "http://127.0.0.1:1"
        kms = kms_provider_from_config(self._mapping())
        self.assertIsInstance(kms, VaultKmsProvider)
        with self.assertRaises(KmsError):
            kms_provider_from_config({"provider": "vault-spiffe-nope"})


if __name__ == "__main__":
    unittest.main()
