"""TUF-steal: expiry + rollback/freeze protection on pin metadata (wave-179 lane D).

Pattern stolen from theupdateframework/python-tuf (MIT license; pattern only,
no vendored code — see gov/skill_watch.py for the attribution comment):
  1. every metadata carries ``expires``; the client refuses stale metadata;
  2. metadata versions are monotonic; the client refuses metadata older than
     what it has already seen (rollback/freeze protection).

Public seams under test: SkillWatch.check_at_use, PinStore.save/load/peek.

RED-FIRST: every test in TestPinExpiry and TestPinRollback FAILS on the
pre-fix tree (the capability does not exist there). Tests in
TestTufNoWeakening PASS on both trees — they guard against regressions.
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import skill_watch  # noqa: F401  (module-attr assertions below)
from gov.skill_watch import (
    SkillWatch, SkillWatchError, PinStore, PinStoreError,
    CallableContentSource,
)
from gov import keyprovider as _keyprovider

ORIGIN = {"registry_url": "https://registry.synthetic.local/s/weather",
          "installer_identity": "operator:alice",
          "installed_at": "2026-09-23T15:00:00+00:00"}

V1 = b"skill v1 benign content"
V2 = b"skill v2 MUTATED content"
V3 = b"skill v3 re-pinned content"

# Far-past / far-future bounds: deterministic without clock injection.
FAR_PAST = "2000-01-01T00:00:00+00:00"
FAR_FUTURE = "2100-01-01T00:00:00+00:00"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def _origin(**kw):
    o = dict(ORIGIN)
    o.update(kw)
    return o


class CountingSource(CallableContentSource):
    def __init__(self, content):
        self.content = content
        super().__init__(self._read)

    def _read(self):
        return self.content


def _pin_key():
    key, _ = _keyprovider.resolve_active_key()
    return key


def _test_factory(content):
    """source_factory for PinStore.load in tests (origin has no path)."""
    def factory(skill_id, origin):
        return CountingSource(content)
    return factory


class TestPinExpiry(unittest.TestCase):
    """not_after on pin metadata; check_at_use refuses stale pins."""

    def test_expired_pin_refused_at_use(self):
        w = SkillWatch()
        w.register_skill("s", CountingSource(V1),
                         origin=_origin(not_after=FAR_PAST))
        ok, detail = w.check_at_use("s")
        self.assertFalse(ok)
        self.assertEqual(detail, "pin-expired")

    def test_malformed_not_after_rejected_at_registration(self):
        w = SkillWatch()
        with self.assertRaises(SkillWatchError):
            w.register_skill("s", CountingSource(V1),
                             origin=_origin(not_after="someday"))

    def test_naive_not_after_rejected_at_registration(self):
        # Naive datetimes are ambiguous: fail closed, never assumed UTC.
        w = SkillWatch()
        with self.assertRaises(SkillWatchError):
            w.register_skill("s", CountingSource(V1),
                             origin=_origin(not_after="2000-01-01T00:00:00"))

    def test_repin_can_set_explicit_not_after(self):
        src = CountingSource(V1)
        w = SkillWatch()
        w.register_skill("s", src, origin=_origin(not_after=FAR_FUTURE))
        src.content = V2
        w.verify_all()
        w.request_repin("s", operator="operator:alice")
        w.approve_repin("s", {"operator": "operator:alice",
                              "new_digest": sha(V2),
                              "reason": "reviewed",
                              "new_not_after": "2001-02-03T04:05:06+00:00"})
        rec = w._skills["s"]
        self.assertEqual(rec["not_after"], "2001-02-03T04:05:06+00:00")

    def test_repin_rejects_malformed_new_not_after(self):
        src = CountingSource(V1)
        w = SkillWatch()
        w.register_skill("s", src, origin=_origin(not_after=FAR_FUTURE))
        src.content = V2
        w.verify_all()
        w.request_repin("s", operator="operator:alice")
        with self.assertRaises(SkillWatchError):
            w.approve_repin("s", {"operator": "operator:alice",
                                  "new_digest": sha(V2),
                                  "reason": "reviewed",
                                  "new_not_after": "never"})


class TestPinRollback(unittest.TestCase):
    """Monotonic manifest_version; older pin metadata is refused."""

    def test_old_signed_pin_file_rejected_in_process(self):
        # THE rollback break: an attacker with pin-file write access (but
        # not the MAC key) restores an older, validly-signed pin file.
        # The MAC still verifies — only a version check catches it.
        key = _pin_key()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pins.json")
            src = CountingSource(V1)
            w = SkillWatch()
            w.register_skill("s", src,
                             origin=_origin(not_after=FAR_FUTURE))
            PinStore.save(w, path, mac_key=key)
            with open(path, "rb") as f:
                v1_bytes = f.read()
            # Two governed repins -> the watcher has seen version 3.
            for content in (V2, V3):
                src.content = content
                w.verify_all()
                w.request_repin("s", operator="operator:alice")
                w.approve_repin("s", {"operator": "operator:alice",
                                      "new_digest": sha(content),
                                      "reason": "reviewed"})
                PinStore.save(w, path, mac_key=key)
            # Attacker swaps in the older, validly-signed file.
            with open(path, "wb") as f:
                f.write(v1_bytes)
            ok, detail = w.check_at_use("s")
            self.assertFalse(ok)
            self.assertIn("rollback", detail)
            self.assertTrue(w.is_quarantined("s"))

    def test_load_rejects_older_manifest_with_floor(self):
        # Cross-restart: the deployment passes the last-seen version it
        # holds in trusted local state; an older file is refused LOUD.
        key = _pin_key()
        with tempfile.TemporaryDirectory() as d:
            p1 = os.path.join(d, "p1.json")
            p3 = os.path.join(d, "p3.json")
            src = CountingSource(V1)
            w = SkillWatch()
            w.register_skill("s", src,
                             origin=_origin(not_after=FAR_FUTURE))
            PinStore.save(w, p1, mac_key=key)
            for content in (V2, V3):
                src.content = content
                w.verify_all()
                w.request_repin("s", operator="operator:alice")
                w.approve_repin("s", {"operator": "operator:alice",
                                      "new_digest": sha(content),
                                      "reason": "reviewed"})
            PinStore.save(w, p3, mac_key=key)
            with self.assertRaises(PinStoreError):
                PinStore.load(p1, mac_key=key, min_manifest_version=3,
                              source_factory=_test_factory(V3))

    def test_load_accepts_current_manifest_with_floor(self):
        key = _pin_key()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pins.json")
            w = SkillWatch()
            w.register_skill("s", CountingSource(V1),
                             origin=_origin(not_after=FAR_FUTURE))
            PinStore.save(w, path, mac_key=key)
            data = PinStore.peek(path, mac_key=key)
            w2 = PinStore.load(path, mac_key=key,
                               min_manifest_version=data["manifest_version"],
                               source_factory=_test_factory(V1))
            self.assertIn("s", w2.registered_skills())

    def test_manifest_version_increments_on_save(self):
        key = _pin_key()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pins.json")
            w = SkillWatch()
            w.register_skill("s", CountingSource(V1),
                             origin=_origin(not_after=FAR_FUTURE))
            PinStore.save(w, path, mac_key=key)
            v1 = PinStore.peek(path, mac_key=key)["manifest_version"]
            PinStore.save(w, path, mac_key=key)
            v2 = PinStore.peek(path, mac_key=key)["manifest_version"]
            self.assertGreater(v2, v1)

    def test_pin_version_bumps_on_repin(self):
        src = CountingSource(V1)
        w = SkillWatch()
        w.register_skill("s", src, origin=_origin(not_after=FAR_FUTURE))
        self.assertEqual(w._skills["s"]["pin_version"], 1)
        src.content = V2
        w.verify_all()
        w.request_repin("s", operator="operator:alice")
        w.approve_repin("s", {"operator": "operator:alice",
                              "new_digest": sha(V2),
                              "reason": "reviewed"})
        self.assertEqual(w._skills["s"]["pin_version"], 2)


class TestTufNoWeakening(unittest.TestCase):
    """Guards: the new checks must not change behavior for fresh pins."""

    def test_fresh_pin_usable(self):
        w = SkillWatch()
        w.register_skill("s", CountingSource(V1),
                         origin=_origin(not_after=FAR_FUTURE))
        self.assertEqual(w.check_at_use("s"), (True, "clean"))

    def test_default_ttl_applied_when_not_after_absent(self):
        w = SkillWatch()
        w.register_skill("s", CountingSource(V1), origin=dict(ORIGIN))
        rec = w._skills["s"]
        # Default: registered_at + 90 days, still in the future.
        self.assertIn("not_after", rec)
        ok, _ = w.check_at_use("s")
        self.assertTrue(ok)

    def test_repin_without_new_not_after_refreshes_default(self):
        src = CountingSource(V1)
        w = SkillWatch()
        w.register_skill("s", src, origin=_origin(not_after=FAR_FUTURE))
        src.content = V2
        w.verify_all()
        w.request_repin("s", operator="operator:alice")
        w.approve_repin("s", {"operator": "operator:alice",
                              "new_digest": sha(V2),
                              "reason": "reviewed"})
        rec = w._skills["s"]
        self.assertIn("not_after", rec)
        self.assertNotEqual(rec["not_after"], FAR_FUTURE)

    def test_expiry_does_not_quarantine(self):
        # Expiry is staleness, not compromise: refuse the use, keep the
        # pin renewable via the governed re-pin flow.
        w = SkillWatch()
        w.register_skill("s", CountingSource(V1),
                         origin=_origin(not_after=FAR_PAST))
        w.check_at_use("s")
        self.assertFalse(w.is_quarantined("s"))
        evs = [e for e in w.events
               if e["event_type"] == "skill_pin_expired"]
        self.assertEqual(len(evs), 1)


if __name__ == "__main__":
    unittest.main()
