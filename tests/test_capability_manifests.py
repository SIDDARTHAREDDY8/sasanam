"""Unit tests for gov/capability_manifests.py and its SkillWatch wiring.

Red-before-green: these tests were written against the module's
specified contract (see gov/capability_manifests.py docstring) and
fail on the unmodified tree (no such module).
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import capability_manifests as cm
from gov import ed25519 as _ed
from gov import skill_watch

_SEED = hashlib.sha256(b"capability-manifests-unit-test-key").digest()
_KID = "unit-key-1"
_PUB = _ed.publickey(_SEED)

ORIGIN = {"registry_url": "https://registry.synthetic.local/s/u",
          "installer_identity": "unit",
          "installed_at": "2026-09-28T00:00:00Z"}

CONTENT = b"def tool_read(p):\n    return open(p).read()\n"
CAPS = {"tools": ["tool_read"], "egress": [], "filesystem": ["/d"],
        "exec": [], "env": [], "secrets": []}


class _Src(skill_watch.ContentSource):
    def __init__(self, data):
        self._data = data

    def read_bytes(self):
        return self._data

    def stat_hint(self):
        return None


def _store(manifests):
    return cm.ManifestStore(keys={_KID: _PUB}, manifests=manifests)


class CanonicalizationTest(unittest.TestCase):
    def test_excludes_signatures_and_is_deterministic(self):
        m = {"b": 1, "a": [1.0, 2.5],
             "signatures": [{"protected": "x", "signature": "y"}]}
        c1 = cm.canonical_manifest_json(m)
        c2 = cm.canonical_manifest_json(dict(m))
        self.assertEqual(c1, c2)
        self.assertNotIn(b"signatures", c1)
        self.assertEqual(c1, b'{"a":[1,2.5],"b":1}')

    def test_non_object_fails_closed(self):
        with self.assertRaises(cm.ManifestVerificationError) as ctx:
            cm.canonical_manifest_json(["not", "a", "dict"])
        self.assertEqual(ctx.exception.code, "canonicalization-failure")


class SignVerifyTest(unittest.TestCase):
    def test_round_trip(self):
        man = cm.make_manifest("s", CONTENT, capabilities=CAPS,
                               kid=_KID, seed=_SEED)
        info = cm.verify_manifest(man, _store({"s": man}),
                                  expected_skill_id="s")
        self.assertEqual(info["skill_id"], "s")
        self.assertEqual(info["kids"], [_KID])
        self.assertTrue(info["artifact_digest"].startswith("sha256:"))

    def test_missing_signatures(self):
        man = cm.make_manifest("s", CONTENT, capabilities=CAPS,
                               kid=_KID, seed=_SEED)
        del man["signatures"]
        with self.assertRaises(cm.ManifestVerificationError) as ctx:
            cm.verify_manifest(man, _store({}))
        self.assertEqual(ctx.exception.code, "missing-signatures")

    def test_unknown_kid(self):
        man = cm.make_manifest("s", CONTENT, capabilities=CAPS,
                               kid="nope", seed=_SEED)
        with self.assertRaises(cm.ManifestVerificationError) as ctx:
            cm.verify_manifest(man, _store({}))
        self.assertEqual(ctx.exception.code, "unknown-kid")

    def test_skill_id_mismatch(self):
        man = cm.make_manifest("s", CONTENT, capabilities=CAPS,
                               kid=_KID, seed=_SEED)
        with self.assertRaises(cm.ManifestVerificationError) as ctx:
            cm.verify_manifest(man, _store({}), expected_skill_id="other")
        self.assertEqual(ctx.exception.code, "skill-id-mismatch")

    def test_unsupported_alg(self):
        man = cm.make_manifest("s", CONTENT, capabilities=CAPS,
                               kid=_KID, seed=_SEED)
        import base64
        import json
        entry = man["signatures"][0]
        prot = json.loads(base64.urlsafe_b64decode(
            entry["protected"] + "==").decode("utf-8"))
        prot["alg"] = "ES256"
        entry["protected"] = base64.urlsafe_b64encode(
            json.dumps(prot).encode("utf-8")).rstrip(b"=").decode("ascii")
        with self.assertRaises(cm.ManifestVerificationError) as ctx:
            cm.verify_manifest(man, _store({}))
        self.assertEqual(ctx.exception.code, "unsupported-alg")

    def test_store_rejects_short_key(self):
        with self.assertRaises(ValueError):
            cm.ManifestStore(keys={_KID: b"short"})


class LintTest(unittest.TestCase):
    def test_each_category_detected(self):
        cases = {
            "egress": b"import socket\n",
            "filesystem": b"x = open('f').read()\n",
            "exec": b"import subprocess\n",
            "env": b"v = os.environ['HOME']\n",
            "secrets": b"import getpass\n",
            "tools": b"@tool\ndef my_tool():\n    pass\n",
        }
        for cat, blob in cases.items():
            det = cm.detect_capabilities(blob)
            self.assertTrue(det[cat]["signals"],
                            "no signal detected for %s" % cat)

    def test_env_names_extracted(self):
        det = cm.detect_capabilities(b"x = os.environ[\"AWS_KEY\"]\n")
        self.assertIn("AWS_KEY", det["env"]["names"])

    def test_tool_names_extracted(self):
        det = cm.detect_capabilities(b"def tool_hidden():\n    pass\n")
        self.assertIn("tool_hidden", det["tools"]["names"])

    def test_opaque_bytes_vacuous(self):
        det = cm.detect_capabilities(b"\x00\x01\x02binary blob\xff")
        for cat in cm.CATEGORIES:
            self.assertEqual(det[cat]["signals"], [])
            self.assertEqual(det[cat]["names"], [])

    def test_check_clean(self):
        ok, detail = cm.check_capabilities(
            CAPS, cm.detect_capabilities(CONTENT))
        self.assertTrue(ok, detail)

    def test_check_undeclared_category(self):
        ok, detail = cm.check_capabilities(
            CAPS, cm.detect_capabilities(b"import socket\n"))
        self.assertFalse(ok)
        self.assertTrue(detail.startswith("capability-drift:egress"))

    def test_check_undeclared_env_name(self):
        caps = dict(CAPS)
        caps["env"] = ["HOME"]
        ok, detail = cm.check_capabilities(
            caps, cm.detect_capabilities(b"x=os.environ['AWS_KEY']\n"))
        self.assertFalse(ok)
        self.assertIn("AWS_KEY", detail)

    def test_check_malformed_declaration_fails_closed(self):
        ok, detail = cm.check_capabilities(
            {"egress": "yes-please"}, cm.detect_capabilities(b""))
        self.assertFalse(ok)
        self.assertIn("malformed-declaration", detail)


class VerifySkillManifestTest(unittest.TestCase):
    def test_no_store_keeps_behavior(self):
        ok, detail = cm.verify_skill_manifest("s", CONTENT, None)
        self.assertEqual((ok, detail), (True, "no-store"))

    def test_absent_manifest(self):
        ok, detail = cm.verify_skill_manifest("s", CONTENT, _store({}))
        self.assertEqual((ok, detail), (True, "manifest-absent"))

    def test_clean(self):
        man = cm.make_manifest("s", CONTENT, capabilities=CAPS,
                               kid=_KID, seed=_SEED)
        ok, detail = cm.verify_skill_manifest("s", CONTENT,
                                              _store({"s": man}))
        self.assertEqual((ok, detail), (True, "clean"))

    def test_digest_mismatch(self):
        man = cm.make_manifest("s", CONTENT, capabilities=CAPS,
                               kid=_KID, seed=_SEED)
        ok, detail = cm.verify_skill_manifest(
            "s", CONTENT + b"tampered", _store({"s": man}))
        self.assertEqual((ok, detail), (False, "manifest-digest-mismatch"))


class WatchWiringTest(unittest.TestCase):
    def test_drift_refused_at_use_time(self):
        drift = CONTENT + b"import socket\n"
        man = cm.make_manifest("d", drift, capabilities=CAPS,
                               kid=_KID, seed=_SEED)
        w = skill_watch.SkillWatch(manifest_store=_store({"d": man}))
        w.register_skill("d", _Src(drift), origin=ORIGIN)
        ok, verified, detail = w.fetch_verified_at_use("d")
        self.assertFalse(ok)
        self.assertIsNone(verified)
        self.assertTrue(detail.startswith("capability-drift:egress"))

    def test_absent_manifest_advisory(self):
        w = skill_watch.SkillWatch(manifest_store=_store({}))
        w.register_skill("a", _Src(CONTENT), origin=ORIGIN)
        ok, verified, detail = w.fetch_verified_at_use("a")
        self.assertTrue(ok)
        self.assertEqual(detail, "clean")
        advisories = [e for e in w.events
                      if e["event_type"] == "capability_manifest_absent"]
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["skill_id"], "a")

    def test_set_manifest_store_validates(self):
        w = skill_watch.SkillWatch()
        with self.assertRaises(skill_watch.SkillWatchError):
            w.set_manifest_store(object())
        w.set_manifest_store(_store({}))
        self.assertIsNotNone(w._manifest_store)
        w.set_manifest_store(None)
        self.assertIsNone(w._manifest_store)


if __name__ == "__main__":
    unittest.main()
