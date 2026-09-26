"""H22: authenticate the skill pin file (row 6 residual).

RED (before): a run-dir writer who rewrites a pinned digest in the pin
file re-anchors trust silently — PinStore.load() accepts the tampered
manifest and check_at_use() enforces the attacker's pin.

GREEN (after): the pin manifest is MAC'd with the operator key at save;
PinStore.peek()/load() fail closed and LOUD on tamper
(skill_pin_tamper). Legitimate re-pins via request_repin/approve_repin
still work (control).

Deterministic in both normal and clean (env -u GOV_DEPLOYMENT_MODE)
environments. $0, synthetic/local only.
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import os as _os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

# The pin-file MAC uses the operator key (same custody as the audit
# log); provision an explicit test key like production does.
_os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
_os.environ.setdefault("GOV_LOG_KEY_EPOCH", "h22-probe")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import skill_watch
from gov.skill_watch import (
    SkillWatch, PinStore, PinStoreError, CallableContentSource,
)
from gov import keyprovider as _kp

V1 = b"skill v1 benign content"
V2 = b"skill v2 attacker content"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def _watch_with_skill(content=V1):
    w = SkillWatch()
    w.register_skill(
        "weather",
        CallableContentSource(lambda: content),
        origin={"registry_url": "https://registry.synthetic.local/s/weather",
                "installer_identity": "operator:alice",
                "installed_at": "2026-09-26T00:00:00+00:00"})
    return w


class H22Probe(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="h22-")
        self.pin_path = os.path.join(self.tmpdir, "pins.json")
        self.key, _ = _kp.resolve_active_key()

    def _tamper_digest(self, new_digest):
        with open(self.pin_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["pins"]["weather"]["pinned_digest"] = new_digest
        with open(self.pin_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")

    def test_tampered_pin_file_refused_loud(self):
        """Rewriting a pinned digest is refused LOUD, not used silently."""
        w = _watch_with_skill()
        PinStore.save(w, self.pin_path, mac_key=self.key)
        # Attacker rewrites the pin to match their content.
        self._tamper_digest(sha(V2))
        with self.assertRaises(PinStoreError) as cm:
            PinStore.peek(self.pin_path, mac_key=self.key)
        self.assertIn("tamper", str(cm.exception).lower(),
                      "refusal does not name tampering: %s" % cm.exception)
        # The deployment path (load) refuses too.
        with self.assertRaises(PinStoreError):
            PinStore.load(self.pin_path, mac_key=self.key)

    def test_tampered_mac_field_itself_refused(self):
        """Rewriting the MAC field (or stripping it) is also refused."""
        w = _watch_with_skill()
        PinStore.save(w, self.pin_path, mac_key=self.key)
        with open(self.pin_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Attacker forges a MAC (doesn't have the key).
        data["manifest_mac"] = "00" * 32
        with open(self.pin_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        with self.assertRaises(PinStoreError):
            PinStore.peek(self.pin_path, mac_key=self.key)

    def test_legitimate_repin_still_works(self):
        """request_repin/approve_repin + save + load is unaffected."""
        w = _watch_with_skill()
        PinStore.save(w, self.pin_path, mac_key=self.key)
        # Legitimate operator-driven re-pin to V2.
        w2 = PinStore.load(
            self.pin_path, mac_key=self.key,
            source_factory=lambda sid, origin: CallableContentSource(
                lambda: V2))
        # Trigger a mutation so request_repin has something to approve.
        ok, detail = w2.check_at_use("weather")
        self.assertFalse(ok)
        req_id = w2.request_repin("weather", operator="operator:alice")
        w2.approve_repin("weather", approval={
            "operator": "operator:alice",
            "new_digest": sha(V2),
            "reason": "h22 probe: legitimate content update",
        })
        PinStore.save(w2, self.pin_path, mac_key=self.key)
        w3 = PinStore.load(
            self.pin_path, mac_key=self.key,
            source_factory=lambda sid, origin: CallableContentSource(
                lambda: V2))
        ok, detail = w3.check_at_use("weather")
        self.assertTrue(ok, "legitimate re-pin denied: %s" % detail)

    def test_post_load_tamper_caught_at_use_time(self):
        """A pin file rewritten AFTER load is caught at check_at_use."""
        w = _watch_with_skill()
        PinStore.save(w, self.pin_path, mac_key=self.key)
        w2 = PinStore.load(
            self.pin_path, mac_key=self.key,
            source_factory=lambda sid, origin: CallableContentSource(
                lambda: V1))
        # Baseline: clean.
        ok, _ = w2.check_at_use("weather")
        self.assertTrue(ok)
        # Attacker rewrites the pin file on disk (post-load).
        self._tamper_digest(sha(V2))
        # The next check_at_use revalidates (mtime changed) and fails
        # closed LOUD.
        ok, detail = w2.check_at_use("weather")
        self.assertFalse(ok)
        self.assertIn("tamper", detail)
        self.assertTrue(w2.is_quarantined("weather"))

    def test_unsigned_legacy_file_loads_without_key(self):
        """Pre-H22 pin files (no MAC) still load when no key is given."""
        w = _watch_with_skill()
        PinStore.save(w, self.pin_path)  # no mac_key -> unsigned
        data = PinStore.peek(self.pin_path)
        self.assertNotIn("manifest_mac", data)
        self.assertEqual(data["pins"]["weather"]["pinned_digest"], sha(V1))


def main():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(H22Probe)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("RESULT: GREEN — pin-file tamper refused loud; "
              "legitimate re-pins unaffected.")
    else:
        print("RESULT: RED — pin-file tamper used silently "
              "(failures=%d, errors=%d)."
              % (len(result.failures), len(result.errors)))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
