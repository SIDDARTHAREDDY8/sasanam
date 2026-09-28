"""Tests for gov/transit_signer.py: transit-managed Ed25519 audit signing.

Zero network: every test runs against the in-file ``FakeTransitTransport``
(an in-memory transit engine with REAL Ed25519 keys per version and a
deliberately lying /verify endpoint). Mirrors the S1-S9 red-team probes
in evals/transit_signer_probes.py at the unit level, plus constructor,
PEM-parsing, and config-factory seams.
"""

import base64
import hashlib
import json
import os
import threading
import unittest
import urllib.parse

from gov import ed25519
from gov import transit_signer as ts
from gov.kms import KmsError
from gov.kms_vault import VaultTransport, VaultTransportError
from gov.signing import Signer, Verifier


def _seed(tag):
    return hashlib.sha256(b"test-transit-signer:" + tag.encode()).digest()


def _spki_pem(pub):
    der = bytes.fromhex("302a300506032b6570032100") + bytes(pub)
    b64 = base64.encodebytes(der).decode("ascii")
    return ("-----BEGIN PUBLIC KEY-----\n" + b64 +
            "-----END PUBLIC KEY-----\n")


class FakeTransitTransport(VaultTransport):
    """In-memory transit engine: real Ed25519 keys per version, real
    local signing, versioned ``vault:vN:`` envelopes, and a /verify
    endpoint that ALWAYS claims valid (the compromised-server model)."""

    def __init__(self, token="test-token", mount="transit"):
        self._token = token
        self._mount = mount
        self._keys = {}
        self._lock = threading.Lock()
        self.outage = False
        self.lie_about_version = False
        self.bad_export = False
        self.calls = []

    def create_signing_key(self, name):
        with self._lock:
            seed = _seed("key:" + name + ":v1")
            self._keys[name] = {1: (seed, ed25519.publickey(seed))}

    def rotate(self, name):
        with self._lock:
            vs = self._keys[name]
            v = max(vs) + 1
            seed = _seed("key:" + name + ":v%d" % v)
            vs[v] = (seed, ed25519.publickey(seed))
            return v

    def _err(self, status, *errors):
        return status, json.dumps({"errors": list(errors)}).encode()

    def _ok(self, data):
        return 200, json.dumps({"data": data}).encode()

    def request(self, method, path, headers, body):
        if self.outage:
            raise VaultTransportError("simulated outage")
        with self._lock:
            self.calls.append((method, path))
            if headers.get("X-Vault-Token") != self._token:
                return self._err(403, "permission denied")
            prefix = "/v1/%s/" % self._mount
            if not path.startswith(prefix):
                return self._err(404, "no handler")
            rest = path[len(prefix):]
            if method == "GET" and rest.startswith("export/public-key/"):
                return self._export(rest[len("export/public-key/"):])
            if method == "GET" and rest.startswith("keys/"):
                return self._read_key(rest[len("keys/"):])
            try:
                payload = json.loads((body or b"").decode("utf-8"))
            except Exception:
                return self._err(400, "malformed body")
            if method == "POST" and rest.startswith("sign/"):
                return self._sign(rest[len("sign/"):], payload)
            if method == "POST" and rest.startswith("verify/"):
                return self._ok({"valid": True})  # THE LIE
            return self._err(404, "no handler")

    def _read_key(self, raw):
        name = urllib.parse.unquote(raw)
        vs = self._keys.get(name)
        if vs is None:
            return self._err(404, "no such key")
        return self._ok({"name": name, "type": "ed25519",
                         "latest_version": max(vs),
                         "min_decryption_version": 1,
                         "export_private_key": False})

    def _sign(self, raw, payload):
        name = urllib.parse.unquote(raw)
        vs = self._keys.get(name)
        if vs is None:
            return self._err(404, "no such key")
        raw_input = payload.get("input")
        if not isinstance(raw_input, str) or not raw_input:
            return self._err(400, "missing input")
        try:
            data = base64.b64decode(raw_input, validate=True)
        except Exception:
            return self._err(400, "bad input")
        if not data:
            return self._err(400, "missing input")
        want = payload.get("key_version", 0)
        v = max(vs) if want in (None, 0) else want
        if not isinstance(v, int) or v not in vs:
            return self._err(400, "invalid key_version")
        seed, _pub = vs[v]
        sig = base64.b64encode(ed25519.sign(seed, data)).decode("ascii")
        reported = 999 if self.lie_about_version else v
        return self._ok({"signature": "vault:v%d:%s" % (v, sig),
                         "key_version": reported})

    def _export(self, raw):
        parts = urllib.parse.unquote(raw).split("/")
        name = parts[0]
        if self.bad_export:
            return self._ok({"public_key": "NOT-A-PEM", "name": name})
        vs = self._keys.get(name)
        if vs is None:
            return self._err(404, "no such key")
        v = max(vs) if len(parts) == 1 else int(parts[1])
        if v not in vs:
            return self._err(404, "no such version")
        _seed_v, pub = vs[v]
        return self._ok({"name": name, "public_key": _spki_pem(pub)})


def _pair(name="audit-sign", **kw):
    fake = FakeTransitTransport()
    fake.create_signing_key(name)
    return ts.TransitSigner(fake, token="test-token", key_name=name,
                            **kw), fake


class ConstructorTest(unittest.TestCase):
    def test_rejects_bad_transport(self):
        with self.assertRaises(TypeError):
            ts.TransitSigner(object(), token="t", key_name="k")

    def test_rejects_empty_token(self):
        with self.assertRaises(ValueError):
            ts.TransitSigner(FakeTransitTransport(), token="",
                             key_name="k")

    def test_rejects_bad_key_name(self):
        fake = FakeTransitTransport()
        for bad in ("", "has space", "../escape", "a" * 300):
            with self.assertRaises(ValueError, msg=bad):
                ts.TransitSigner(fake, token="t", key_name=bad)

    def test_rejects_bad_mount(self):
        with self.assertRaises(ValueError):
            ts.TransitSigner(FakeTransitTransport(), token="t",
                             key_name="k", mount="../x")

    def test_rejects_bad_key_version(self):
        fake = FakeTransitTransport()
        for bad in (0, -1, True, "1", 1.5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ts.TransitSigner(fake, token="t", key_name="k",
                                 key_version=bad)

    def test_no_network_at_construction(self):
        fake = FakeTransitTransport()  # no keys created
        s = ts.TransitSigner(fake, token="test-token", key_name="k")
        self.assertEqual(fake.calls, [])
        self.assertEqual(s.key_name, "k")
        self.assertIsNone(s.pinned_version)
        self.assertIsNone(s.last_signed_version)


class AbcConformanceTest(unittest.TestCase):
    def test_is_signer(self):
        s, _fake = _pair()
        self.assertIsInstance(s, Signer)

    def test_identity_resolves(self):
        s, _fake = _pair()
        self.assertEqual(len(s.public_key), 32)
        self.assertTrue(s.key_id)
        # key_id is the ed25519_key_id of the exported public key.
        from gov.signing import ed25519_key_id
        self.assertEqual(s.key_id, ed25519_key_id(s.public_key))

    def test_verifier_is_verifier(self):
        s, _fake = _pair()
        v = s.verifier_for(1)
        self.assertIsInstance(v, Verifier)
        self.assertEqual(v.version, 1)
        self.assertEqual(v.key_id, s.key_id)


class SignRoundTripTest(unittest.TestCase):
    def test_sign_returns_64_bytes(self):
        s, _fake = _pair()
        sig = s.sign(b"hello")
        self.assertEqual(len(sig), 64)
        self.assertEqual(s.last_signed_version, 1)

    def test_sign_versioned_reports_version(self):
        s, _fake = _pair()
        sig, ver = s.sign_versioned(b"hello")
        self.assertEqual((len(sig), ver), (64, 1))

    def test_local_verify_roundtrip(self):
        s, fake = _pair()
        sig, ver = s.sign_versioned(b"audit entry")
        self.assertTrue(s.verifier_for(ver).verify(b"audit entry", sig))
        # The server /verify endpoint was never consulted.
        self.assertFalse(any(p.startswith("/v1/transit/verify/")
                             for _m, p in fake.calls))

    def test_pinned_version(self):
        s, fake = _pair()
        fake.rotate("audit-sign")
        pinned = ts.TransitSigner(fake, token="test-token",
                                  key_name="audit-sign", key_version=1)
        sig, ver = pinned.sign_versioned(b"data")
        self.assertEqual(ver, 1)
        self.assertTrue(pinned.verifier_for(1).verify(b"data", sig))

    def test_refresh_after_rotation(self):
        s, fake = _pair()
        self.assertEqual(s.sign_versioned(b"x")[1], 1)
        fake.rotate("audit-sign")
        s.refresh()
        self.assertEqual(s.sign_versioned(b"x")[1], 2)
        # Identity follows the version.
        self.assertNotEqual(
            ts.TransitSigner(fake, token="test-token",
                             key_name="audit-sign",
                             key_version=1).key_id, s.key_id)

    def test_sign_rejects_non_bytes(self):
        s, _fake = _pair()
        with self.assertRaises(TypeError):
            s.sign("not bytes")

    def test_sign_rejects_empty(self):
        s, _fake = _pair()
        with self.assertRaises(KmsError):
            s.sign(b"")


class ForgeryTest(unittest.TestCase):
    def test_forged_signature_rejected(self):
        s, fake = _pair()
        forged = ed25519.sign(_seed("attacker"), b"audit entry")
        self.assertFalse(s.verifier_for(1).verify(b"audit entry", forged))
        self.assertFalse(any(p.startswith("/v1/transit/verify/")
                             for _m, p in fake.calls))

    def test_tampered_message_rejected(self):
        s, _fake = _pair()
        sig, ver = s.sign_versioned(b"audit entry")
        self.assertFalse(
            s.verifier_for(ver).verify(b"audit entry!", sig))

    def test_truncated_signature_rejected(self):
        s, _fake = _pair()
        sig, ver = s.sign_versioned(b"audit entry")
        self.assertFalse(s.verifier_for(ver).verify(b"audit entry",
                                                    sig[:32]))

    def test_verifier_never_raises(self):
        s, _fake = _pair()
        v = s.verifier_for(1)
        for data, sig in ((None, b"x" * 64), (b"d", None),
                          (b"d", "not bytes"), (b"d", b"short")):
            self.assertFalse(v.verify(data, sig))


class VersionConfusionTest(unittest.TestCase):
    def _rotated(self):
        s, fake = _pair()
        sig1, _v1 = s.sign_versioned(b"entry")
        fake.rotate("audit-sign")
        s.refresh()
        sig2, _v2 = s.sign_versioned(b"entry")
        return s, sig1, sig2

    def test_cross_version_verify_fails(self):
        s, sig1, sig2 = self._rotated()
        self.assertFalse(s.verifier_for(2).verify(b"entry", sig1))
        self.assertFalse(s.verifier_for(1).verify(b"entry", sig2))

    def test_verify_versioned_honest(self):
        s, _sig1, sig2 = self._rotated()
        self.assertTrue(
            ts.verify_versioned(b"entry", sig2, 2, s.verifier_for))

    def test_verify_versioned_confused(self):
        s, sig1, _sig2 = self._rotated()
        self.assertFalse(
            ts.verify_versioned(b"entry", sig1, 2, s.verifier_for))

    def test_verify_versioned_stripped_refused(self):
        s, _sig1, sig2 = self._rotated()
        with self.assertRaises(KmsError):
            ts.verify_versioned(b"entry", sig2, None, s.verifier_for)

    def test_verify_versioned_bad_version_refused(self):
        s, _sig1, sig2 = self._rotated()
        for bad in (0, -1, True, "2"):
            with self.assertRaises(KmsError, msg=repr(bad)):
                ts.verify_versioned(b"entry", sig2, bad, s.verifier_for)


class FailClosedTest(unittest.TestCase):
    def test_outage_on_every_seam(self):
        s, fake = _pair()
        fake.outage = True
        for fn in (lambda: s.sign(b"x"), lambda: s.sign_versioned(b"x"),
                   lambda: s.verifier_for(1), lambda: s.key_id,
                   lambda: s.public_key):
            with self.assertRaises(KmsError):
                fn()

    def test_outage_raises_kmserror_not_transport_error(self):
        s, fake = _pair()
        fake.outage = True
        with self.assertRaises(KmsError) as cm:
            s.sign(b"x")
        self.assertNotIsInstance(cm.exception, VaultTransportError)

    def test_bad_token(self):
        fake = FakeTransitTransport()
        fake.create_signing_key("k")
        bad = ts.TransitSigner(fake, token="wrong", key_name="k")
        with self.assertRaises(KmsError):
            bad.sign(b"x")

    def test_unknown_key(self):
        fake = FakeTransitTransport()
        s = ts.TransitSigner(fake, token="test-token", key_name="nope")
        with self.assertRaises(KmsError):
            s.sign(b"x")

    def test_lying_server_version_rejected(self):
        s, fake = _pair()
        fake.lie_about_version = True
        with self.assertRaises(KmsError):
            s.sign_versioned(b"x")

    def test_bad_export_rejected(self):
        s, fake = _pair()
        fake.bad_export = True
        with self.assertRaises(KmsError):
            s.verifier_for(1)

    def test_malformed_sign_response(self):
        class BadFake(FakeTransitTransport):
            def _sign(self, raw, payload):
                return self._ok({"bogus": 1})

        fake = BadFake()
        fake.create_signing_key("k")
        s = ts.TransitSigner(fake, token="test-token", key_name="k")
        with self.assertRaises(KmsError):
            s.sign(b"x")


class PemParsingTest(unittest.TestCase):
    def test_roundtrip(self):
        pub = ed25519.publickey(_seed("pem"))
        self.assertEqual(ts._parse_ed25519_spki_pem(_spki_pem(pub)), pub)

    def test_rejects_garbage(self):
        for bad in ("", "NOT-A-PEM", _spki_pem(b"y" * 32)[:-5],
                    "-----BEGIN PUBLIC KEY-----\n!!!!\n"
                    "-----END PUBLIC KEY-----\n"):
            with self.assertRaises(KmsError, msg=repr(bad)[:40]):
                ts._parse_ed25519_spki_pem(bad)

    def test_rejects_wrong_key_type(self):
        # A 33-byte "key" under the Ed25519 prefix is not Ed25519.
        der = bytes.fromhex("302a300506032b6570032100") + b"z" * 33
        pem = ("-----BEGIN PUBLIC KEY-----\n"
               + base64.encodebytes(der).decode("ascii")
               + "-----END PUBLIC KEY-----\n")
        with self.assertRaises(KmsError):
            ts._parse_ed25519_spki_pem(pem)

    def test_rejects_non_string(self):
        with self.assertRaises(KmsError):
            ts._parse_ed25519_spki_pem(b"bytes not str")


class ExportHelperTest(unittest.TestCase):
    def test_export_latest(self):
        fake = FakeTransitTransport()
        fake.create_signing_key("k")
        pub, ver = ts.export_transit_public_key(
            fake, "test-token", "transit", "k")
        self.assertEqual(len(pub), 32)
        self.assertEqual(ver, 1)

    def test_export_pinned(self):
        fake = FakeTransitTransport()
        fake.create_signing_key("k")
        fake.rotate("k")
        pub, ver = ts.export_transit_public_key(
            fake, "test-token", "transit", "k", version=1)
        self.assertEqual(ver, 1)
        s = ts.TransitSigner(fake, token="test-token", key_name="k",
                             key_version=1)
        self.assertEqual(pub, s.public_key)


class ConfigFactoryTest(unittest.TestCase):
    def _env(self, addr="http://127.0.0.1:8200", token="tok"):
        old = dict(os.environ)
        os.environ["VAULT_ADDR"] = addr
        os.environ["VAULT_TOKEN"] = token
        return old

    def test_missing_env_fails_closed(self):
        old = dict(os.environ)
        os.environ.pop("VAULT_ADDR", None)
        os.environ.pop("VAULT_TOKEN", None)
        try:
            with self.assertRaises(KmsError):
                ts.transit_signer_from_config({"key_name": "k"})
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_missing_key_name_fails_closed(self):
        old = self._env()
        try:
            with self.assertRaises(KmsError):
                ts.transit_signer_from_config({})
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_bad_key_version_fails_closed(self):
        old = self._env()
        try:
            with self.assertRaises(KmsError):
                ts.transit_signer_from_config({"key_name": "k",
                                               "key_version": 0})
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_bad_knob_fails_closed(self):
        old = self._env()
        try:
            with self.assertRaises(KmsError):
                ts.transit_signer_from_config({"key_name": "k",
                                               "allow_http": "yes"})
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_plaintext_refused_without_allow_http(self):
        old = self._env(addr="http://127.0.0.1:8200")
        try:
            with self.assertRaises(KmsError):
                ts.transit_signer_from_config({"key_name": "k"})
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_non_mapping_fails_closed(self):
        old = self._env()
        try:
            with self.assertRaises(KmsError):
                ts.transit_signer_from_config("key_name=k")
        finally:
            os.environ.clear()
            os.environ.update(old)


class SecrecyTest(unittest.TestCase):
    def test_no_key_material_in_errors(self):
        s, fake = _pair()
        fake.outage = True
        try:
            s.sign(b"super secret input")
        except KmsError as e:
            msg = str(e)
            self.assertNotIn("super secret input", msg)
            self.assertNotIn("test-token", msg)
        else:
            self.fail("expected KmsError")


class LogIntegrationTest(unittest.TestCase):
    """TransitSigner composes with gov.log's ``sig_key_version`` seam.

    ``ActionLog.append`` reads ``getattr(signer, "key_version", None)``,
    writes it into the envelope BEFORE computing the v2 signature
    body, then calls ``signer.sign(body)``. These tests pin the whole
    round trip: envelope version, locally-verified signature, and
    rotation across appends.
    """

    def _read_entries(self, path):
        entries = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def test_append_writes_versioned_envelope(self):
        from gov import log as _log
        import tempfile
        s, _fake = _pair()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.log")
            lg = _log.ActionLog(path, signer=s,
                                deployment_mode="staging")
            lg.append({"event": "test"})
            (entry,) = self._read_entries(path)
        ver = entry.get("sig_key_version")
        self.assertIsInstance(ver, int)
        self.assertGreaterEqual(ver, 1)
        self.assertEqual(ver, s.last_signed_version)
        self.assertEqual(entry["sig_key_id"], s.key_id)
        # The version is bound into the v2 body: verify locally.
        body = _log._entry_sig_body(entry)
        self.assertTrue(s.verifier_for(ver).verify(
            body, bytes.fromhex(entry["ed_sig"])))

    def test_rotation_across_appends(self):
        from gov import log as _log
        import tempfile
        s, fake = _pair()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.log")
            lg = _log.ActionLog(path, signer=s,
                                deployment_mode="staging")
            lg.append({"event": "one"})
            fake.rotate("audit-sign")
            s.refresh()
            lg.append({"event": "two"})
            e1, e2 = self._read_entries(path)
        self.assertEqual(e1["sig_key_version"], 1)
        self.assertEqual(e2["sig_key_version"], 2)
        # Each entry verifies under its own version's key.
        for e in (e1, e2):
            v = e["sig_key_version"]
            body = _log._entry_sig_body(e)
            self.assertTrue(s.verifier_for(v).verify(
                body, bytes.fromhex(e["ed_sig"])),
                "entry failed local verify at v%d" % v)
        # Cross-version does not verify (no silent aliasing).
        self.assertFalse(s.verifier_for(2).verify(
            _log._entry_sig_body(e1), bytes.fromhex(e1["ed_sig"])))

    def test_tampered_version_breaks_verify(self):
        from gov import log as _log
        import tempfile
        s, fake = _pair()
        fake.rotate("audit-sign")  # v2 exists so v2 is a "valid" version
        s.refresh()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.log")
            lg = _log.ActionLog(path, signer=s,
                                deployment_mode="staging")
            lg.append({"event": "one"})
            (entry,) = self._read_entries(path)
        # Flip the envelope version to the other valid version: the
        # v2 body binds the version, so the signature no longer
        # verifies under the tampered envelope.
        entry["sig_key_version"] = 1
        body = _log._entry_sig_body(entry)
        self.assertFalse(s.verifier_for(2).verify(
            body, bytes.fromhex(entry["ed_sig"])))


if __name__ == "__main__":
    unittest.main()
