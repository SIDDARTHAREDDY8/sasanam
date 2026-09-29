"""Unit pins for the wave-211 trust-config wiring into
``verify_skill_manifest`` (``gov/capability_manifests.py``).

Pins: (a) refusal verdict names when the trust registry is wired;
(b) the legacy byte-identical contract when it is not (trust_registry
is None -> today's results exactly); (c) the fail-closed shape of the
wiring (no class, no config, revoked root, unknown class).
"""

import hashlib
import unittest

from gov import capability_manifests as cm
from gov import deploy_trust_config as dtc
from gov import ed25519 as _ed
from gov.keyset import new_keyset, keyset_signer_for_version

_SEED = hashlib.sha256(b"trust-wiring-unit-test-key").digest()
_SEED_EVIL = hashlib.sha256(b"trust-wiring-unit-attacker-key").digest()
_SEED_ROOT = hashlib.sha256(b"trust-wiring-unit-deploy-root").digest()
_KID = "trust-wiring-unit-key-1"
_KID_EVIL = "trust-wiring-unit-evil-1"
_PUB = _ed.publickey(_SEED)
_PUB_EVIL = _ed.publickey(_SEED_EVIL)

CLASS = "capability_skills"

ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"

BENIGN_FS = (b"def tool_read(path):\n"
             b"    with open(path) as f:\n"
             b"        return f.read()\n")
CAPS_FS_ONLY = {"tools": ["tool_read"], "egress": [],
                "filesystem": ["/data"], "exec": [],
                "env": [], "secrets": []}


def _trust_env():
    root_keyset, _ = new_keyset(_SEED_ROOT,
                                purpose=dtc.KEYSET_PURPOSE_DEPLOY_TRUST)
    root_signer = keyset_signer_for_version(root_keyset, 1, _SEED_ROOT)
    return root_keyset, root_signer


def _config_body(trusted_kids, revoked_kids=()):
    classes = {
        CLASS: dtc.make_class_config(
            policy="signed-only",
            trust_roots=[dtc.make_trust_root(
                kid, 1, (_ed.publickey(
                    _SEED if kid == _KID else _SEED_EVIL)).hex())
                for kid in trusted_kids],
            threshold=1),
    }
    return dtc.make_config_body(
        config_version=1, issued_at=ISSUED, expires_at=EXPIRES,
        classes=classes,
        revoked_kids=[{"kid": k, "reason": "unit-revoked"}
                      for k in revoked_kids])


def _activate(body):
    root_keyset, root_signer = _trust_env()
    doc = dtc.mint_trust_config(
        root_keyset, [root_signer], body=body, pack_version=1,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
    body_bytes = dtc.canonical_trust_config_json(body).encode("utf-8")
    registry = dtc.TrustConfigRegistry(root_keyset)
    registry.activate(doc, body_bytes, now=NOW)
    return registry


def _store(manifests):
    return cm.ManifestStore(
        keys={_KID: _PUB, _KID_EVIL: _PUB_EVIL}, manifests=manifests)


def _manifest(kid, seed):
    return cm.make_manifest("fs1", BENIGN_FS,
                            capabilities=CAPS_FS_ONLY,
                            kid=kid, seed=seed)


class TestTrustWiring(unittest.TestCase):
    def test_unwired_is_byte_identical_legacy(self):
        # No registry: the exact pre-wave-211 contract.
        store = _store({"fs1": _manifest(_KID, _SEED)})
        self.assertEqual(cm.verify_skill_manifest("fs1", BENIGN_FS,
                                                  store),
                         (True, "clean"))
        store = _store({"fs1": _manifest(_KID_EVIL, _SEED_EVIL)})
        self.assertEqual(cm.verify_skill_manifest("fs1", BENIGN_FS,
                                                  store),
                         (True, "clean"))

    def test_trusted_signer_admits_with_suffix(self):
        registry = _activate(_config_body([_KID]))
        store = _store({"fs1": _manifest(_KID, _SEED)})
        self.assertEqual(cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW),
            (True, "clean|trust-checked"))

    def test_untrusted_signer_refused_named(self):
        registry = _activate(_config_body([_KID]))
        store = _store({"fs1": _manifest(_KID_EVIL, _SEED_EVIL)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        self.assertFalse(ok)
        self.assertEqual(detail, "manifest-trust-trust-root-unknown")

    def test_missing_class_fails_closed(self):
        registry = _activate(_config_body([_KID]))
        store = _store({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            trust_now=NOW)
        self.assertFalse(ok)
        self.assertEqual(detail, "manifest-trust-class-missing")

    def test_no_active_config_fails_closed(self):
        root_keyset, _ = _trust_env()
        registry = dtc.TrustConfigRegistry(root_keyset)
        store = _store({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        self.assertFalse(ok)
        self.assertEqual(detail, "manifest-trust-no-trust-config")

    def test_revoked_root_refused_loudly(self):
        registry = _activate(_config_body([_KID], [_KID_EVIL]))
        store = _store({"fs1": _manifest(_KID_EVIL, _SEED_EVIL)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        self.assertFalse(ok)
        self.assertEqual(detail, "manifest-trust-trust-root-revoked")

    def test_unknown_class_default_deny(self):
        registry = _activate(_config_body([_KID]))
        store = _store({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class="no-such-class", trust_now=NOW)
        self.assertFalse(ok)
        self.assertEqual(detail, "manifest-trust-trust-class-unknown")

    def test_wrong_registry_type_fails_loud(self):
        store = _store({"fs1": _manifest(_KID, _SEED)})
        with self.assertRaises(TypeError):
            cm.verify_skill_manifest(
                "fs1", BENIGN_FS, store,
                trust_registry=object(), pack_class=CLASS)

    def test_trust_check_precedes_content_checks(self):
        # A manifest that ALSO has digest drift refuses on trust
        # first: trust verdict names the signer problem, proving the
        # trust check runs immediately after signature verification.
        registry = _activate(_config_body([_KID]))
        store = _store({"fs1": _manifest(_KID_EVIL, _SEED_EVIL)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS + b"drift", store,
            trust_registry=registry, pack_class=CLASS, trust_now=NOW)
        self.assertFalse(ok)
        self.assertEqual(detail, "manifest-trust-trust-root-unknown")


if __name__ == "__main__":
    unittest.main()
