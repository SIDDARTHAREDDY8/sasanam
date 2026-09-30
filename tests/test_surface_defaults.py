"""Unit tests for gov.surface_defaults (W244-7)."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import surface_defaults as sd  # noqa: E402

_KEY = b"\x0b" * 32


def _cfg(**over):
    cfg = {
        "surface": "gw",
        "gateway": {"credentials": {"username": "ops",
                                   "password": "s3cure!-v4lue"}},
        "endpoints": [
            {"name": "admin", "admin": True, "auth": "token",
             "transport": "https"},
            {"name": "pub", "public": True, "execution_guard": True,
             "auth": "token", "transport": "https"},
        ],
    }
    cfg.update(over)
    return cfg


class RefusalVocabularyTest(unittest.TestCase):
    def _code(self, cfg, **kw):
        try:
            sd.audit_surface(cfg, issuer_key=kw.get("issuer_key", _KEY))
        except sd.SurfaceDefaultsError as exc:
            return exc
        self.fail("expected refusal")

    def test_default_password_refused(self):
        cfg = _cfg()
        cfg["gateway"]["credentials"]["password"] = "changeme"
        exc = self._code(cfg)
        self.assertEqual(exc.code, "surface-default-credentials")
        self.assertIn("changeme", exc.detail)

    def test_case_insensitive_default(self):
        cfg = _cfg()
        cfg["gateway"]["credentials"]["password"] = "ADMIN"
        exc = self._code(cfg)
        self.assertEqual(exc.code, "surface-default-credentials")

    def test_missing_credentials_refused(self):
        cfg = _cfg()
        del cfg["gateway"]["credentials"]
        exc = self._code(cfg)
        self.assertEqual(exc.code, "surface-default-credentials")

    def test_empty_password_refused(self):
        cfg = _cfg()
        cfg["gateway"]["credentials"]["password"] = "   "
        exc = self._code(cfg)
        self.assertEqual(exc.code, "surface-default-credentials")

    def test_admin_without_auth_refused(self):
        cfg = _cfg()
        cfg["endpoints"][0]["auth"] = "none"
        exc = self._code(cfg)
        self.assertEqual(exc.code, "surface-admin-unauthenticated")

    def test_public_without_guard_refused(self):
        cfg = _cfg()
        cfg["endpoints"][1]["execution_guard"] = "yes"
        exc = self._code(cfg)
        # "yes" is truthy but not explicit True -> refused fail-closed.
        self.assertEqual(exc.code, "surface-public-unguarded")

    def test_stdio_without_mediation_refused(self):
        cfg = _cfg()
        cfg["endpoints"].append({"name": "s", "transport": "stdio",
                                "auth": "token"})
        exc = self._code(cfg)
        self.assertEqual(exc.code, "surface-transport-bypass")

    def test_malformed_config_refused(self):
        exc = self._code({"surface": "gw"})
        self.assertEqual(exc.code, "surface-config-malformed")

    def test_missing_issuer_key_refused(self):
        exc = self._code(_cfg(), issuer_key=None)
        self.assertEqual(exc.code, "surface-attestation-key-missing")

    def test_bool_is_not_valid_name(self):
        cfg = _cfg(surface=True)
        exc = self._code(cfg)
        self.assertEqual(exc.code, "surface-config-malformed")


class AttestationTest(unittest.TestCase):
    def test_happy_path_attested(self):
        cfg = _cfg()
        att = sd.audit_surface(cfg, issuer_key=_KEY)
        self.assertEqual(att["verdict"], "attested")
        self.assertEqual(att["surface"], "gw")
        self.assertEqual(att["config_digest"], sd.config_digest(cfg))
        self.assertTrue(sd.verify_attestation(att, cfg, issuer_key=_KEY))

    def test_drift_detected(self):
        cfg = _cfg()
        att = sd.audit_surface(cfg, issuer_key=_KEY)
        cfg["endpoints"][0]["auth"] = "mtls"
        self.assertFalse(sd.verify_attestation(att, cfg, issuer_key=_KEY))

    def test_wrong_key_rejected(self):
        cfg = _cfg()
        att = sd.audit_surface(cfg, issuer_key=_KEY)
        self.assertFalse(sd.verify_attestation(att, cfg,
                                              issuer_key=b"\x01" * 32))

    def test_tampered_mac_rejected(self):
        cfg = _cfg()
        att = sd.audit_surface(cfg, issuer_key=_KEY)
        att["mac"] = "0" * 64
        self.assertFalse(sd.verify_attestation(att, cfg, issuer_key=_KEY))

    def test_malformed_attestation_never_raises(self):
        self.assertFalse(sd.verify_attestation(None, _cfg(),
                                              issuer_key=_KEY))
        self.assertFalse(sd.verify_attestation({"verdict": "attested"},
                                              _cfg(), issuer_key=_KEY))

    def test_no_mutation(self):
        cfg = _cfg()
        before = copy.deepcopy(cfg)
        sd.audit_surface(cfg, issuer_key=_KEY)
        self.assertEqual(cfg, before)

    def test_weak_but_unlisted_password_is_not_this_module(self):
        # The default list is a known-placeholder list, not a strength
        # meter: "hunter2" is not a refusal here (credential policy is
        # deployment-owned).
        cfg = _cfg()
        cfg["gateway"]["credentials"]["password"] = "hunter2"
        att = sd.audit_surface(cfg, issuer_key=_KEY)
        self.assertEqual(att["verdict"], "attested")


if __name__ == "__main__":
    unittest.main()
