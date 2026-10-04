#!/usr/bin/env python3
"""Wave-328 lane 2 (residual hardening): unit tests for the seven hardened
gaps from the wave-326 / wave-327 red-team "Hardening observations".

Each test pins the hardened behavior at the module seam:
  W327-1  register_skill re-registration refused LOUD
          (supplychain-scan-already-registered) + the
          update_skill_registration config path.
  W327-2  missed_intervals bounded at MAX_MISSED_INTERVALS_REPORTED;
          the true total travels LOUD in the report.
  W327-3  every report carries clock_trust="caller-supplied".
  W327-4  standing_of's chain includes the agreeing tip voice.
  W327-5  OSV envelope with asserted_standing "revoked" applies when the
          feed key signed it (doc now matches code; fail-closed preserved).
  W326-1  supersede() refuses exact version ties LOUD
          (advisory-version-tie); identical-object dedup still fine.
  W326-3  check_package() refuses non-sealed dicts LOUD
          (advisory-input-unpinned); the sealed path still verifies.
"""
import base64
import hashlib
import json
import os
import tempfile
import unittest

from gov import advisory_binding as AB
from gov import background_scan as BS
from gov import decision_codes as DC
from gov import ed25519 as ED
from gov import knowledge_ingest as KI
from gov import standing_verdicts as SV


def _b64(b):
    return base64.b64encode(b).decode("ascii")


# ---------------------------------------------------------------------------
# W327-1 / W327-2 / W327-3: background_scan
# ---------------------------------------------------------------------------

_T0 = 1_700_000_000
_SKILL = "skills/demo"


def _deleg_wire(version):
    # Envelope form that _delegation_version parses (best-effort hint).
    payload = base64.b64encode(
        json.dumps({"version": version}).encode("utf-8")).decode("ascii")
    return json.dumps({"payload": payload}).encode("utf-8")


def _authz_wire(payload):
    return b"AUTHZ:" + payload


def _register(sp, **kw):
    args = dict(skill_path=_SKILL, delegation_wire=_deleg_wire(1),
                authz_wire=_authz_wire(b"v1"), skill_bytes=b"v1",
                ttl_seconds=3600, scan_interval_seconds=900, now=_T0)
    args.update(kw)
    return BS.register_skill(sp, **args)


class TestReregisterGuard(unittest.TestCase):
    def test_second_registration_refused_loud(self):
        sp = tempfile.mkdtemp(prefix="w328-r1-")
        sp = os.path.join(sp, "state.json")
        _register(sp)
        with self.assertRaises(BS.BackgroundScanError) as ctx:
            _register(sp, now=_T0 + 5, delegation_wire=_deleg_wire(2))
        self.assertEqual(ctx.exception.code,
                         "supplychain-scan-already-registered")
        with open(sp, encoding="utf-8") as fh:
            state = json.load(fh)
        # The refused call did not re-baseline anything.
        self.assertEqual(state["skills"][_SKILL]["delegations_version"], 1)
        self.assertEqual(state["skills"][_SKILL]["digest"],
                         hashlib.sha256(b"v1").hexdigest())

    def test_update_registration_config_path(self):
        sp = tempfile.mkdtemp(prefix="w328-r1b-")
        sp = os.path.join(sp, "state.json")
        _register(sp)
        rec = BS.update_skill_registration(
            sp, skill_path=_SKILL, ttl_seconds=999,
            scan_interval_seconds=60)
        self.assertEqual(rec["ttl_seconds"], 999)
        self.assertEqual(rec["scan_interval_seconds"], 60)
        # Scan-owned baselines untouched.
        self.assertEqual(rec["delegations_version"], 1)
        self.assertEqual(rec["digest"], hashlib.sha256(b"v1").hexdigest())
        # No args: no-op that still validates the skill exists.
        rec2 = BS.update_skill_registration(sp, skill_path=_SKILL)
        self.assertEqual(rec2["ttl_seconds"], 999)
        # Unknown skill refused.
        with self.assertRaises(BS.BackgroundScanError) as ctx:
            BS.update_skill_registration(sp, skill_path="skills/nope",
                                         ttl_seconds=1)
        self.assertEqual(ctx.exception.code, "supplychain-scan-malformed")

    def test_code_registered_in_taxonomy(self):
        entry = DC.TAXONOMY["supplychain-scan-already-registered"]
        self.assertEqual(entry["domain"], "supplychain")


class TestMissedIntervalsBound(unittest.TestCase):
    def test_report_list_capped_but_total_loud(self):
        rec = {"digest": "d", "delegations_version": 1,
               "next_scan_at": _T0, "scan_interval_seconds": 10}
        trig, missed, total = BS._evaluate_triggers(
            rec, digest_now="d", deleg_version_now=1,
            now=_T0 + 10 * 10000)
        self.assertEqual(trig, "interval")
        self.assertEqual(total, 9999)
        self.assertEqual(len(missed), BS.MAX_MISSED_INTERVALS_REPORTED)
        # Small gaps are untouched: no truncation, no flag.
        trig2, missed2, total2 = BS._evaluate_triggers(
            rec, digest_now="d", deleg_version_now=1, now=_T0 + 35)
        self.assertEqual(total2, 3)
        self.assertEqual(missed2, [_T0, _T0 + 10, _T0 + 20])

    def test_report_carries_truncation_fields(self):
        sp = tempfile.mkdtemp(prefix="w328-r2-")
        sp = os.path.join(sp, "state.json")
        _register(sp, scan_interval_seconds=10, now=_T0)
        entry = {"skill_path": _SKILL, "skill_bytes": b"v1",
                 "delegation_wire": _deleg_wire(1),
                 "authz_wire": _authz_wire(b"v1")}
        reports = BS.run_scan(
            sp, [entry], {"keys": []}, now=_T0 + 10 * 10000)
        rep = reports[0]
        self.assertEqual(rep["missed_intervals_total"], 9999)
        self.assertTrue(rep["missed_intervals_truncated"])
        self.assertEqual(len(rep["missed_intervals"]),
                         BS.MAX_MISSED_INTERVALS_REPORTED)
        self.assertIn("9999", " ".join(rep["notes"]))
        self.assertIn("supplychain-scan-missed-interval",
                      " ".join(rep["notes"]))
        # The scan itself fails on the empty root trust (carried in the
        # report); the catch-up accounting above is what this pins.


class TestClockTrust(unittest.TestCase):
    def test_report_carries_clock_trust(self):
        sp = tempfile.mkdtemp(prefix="w328-r3-")
        sp = os.path.join(sp, "state.json")
        _register(sp, now=_T0)
        entry = {"skill_path": _SKILL, "skill_bytes": b"v1",
                 "delegation_wire": _deleg_wire(1),
                 "authz_wire": _authz_wire(b"v1")}
        reports = BS.run_scan(sp, [entry], {"keys": []}, now=_T0)
        self.assertEqual(reports[0]["clock_trust"], "caller-supplied")
        self.assertEqual(BS.CLOCK_TRUST, "caller-supplied")


# ---------------------------------------------------------------------------
# W327-4: standing_of chain completeness
# ---------------------------------------------------------------------------

_D1 = "sha256:" + "aa" * 32


def _new_store():
    d = tempfile.mkdtemp(prefix="w328-sv-")
    store = SV.StandingStore(os.path.join(d, "j.jsonl"))
    store.register_artifact(_D1, "inventory")
    return store


def _entry(store, standing, justification, supersedes=None):
    e = {"artifact_digest": _D1, "asserted_standing": standing,
         "justification": justification, "origin": "osv.dev",
         "collector": "c", "known_since": 1000,
         "supersedes": supersedes}
    return store.attach_knowledge(e)["seq"]


class TestChainCompleteness(unittest.TestCase):
    def test_agreeing_tip_voice_in_chain(self):
        store = _new_store()
        s1 = _entry(store, "quarantined", "j1")
        # Concurrent agreeing voice: supersedes the tip's PARENT (none).
        s2 = _entry(store, "quarantined", "j2", supersedes=None)
        s3 = _entry(store, "trusted", "j3", supersedes=s2)
        got = store.standing_of(_D1)
        seqs = [c["seq"] for c in got["chain"]]
        self.assertEqual(seqs, [s1, s2, s3])
        self.assertIn(s2, seqs)  # the agreeing voice is not skipped
        self.assertEqual(got["tip_seq"], s3)

    def test_linear_chain_unchanged(self):
        store = _new_store()
        s1 = _entry(store, "quarantined", "j1")
        s2 = _entry(store, "trusted", "j2", supersedes=s1)
        got = store.standing_of(_D1)
        self.assertEqual([c["seq"] for c in got["chain"]], [s1, s2])
        self.assertEqual(got["chain"][1]["justification"], "j2")


# ---------------------------------------------------------------------------
# W327-5: OSV revoked envelope (doc now matches code)
# ---------------------------------------------------------------------------

class TestOsvRevoked(unittest.TestCase):
    def test_feed_signed_revoked_applies(self):
        feed_sk = bytes([77]) * 32
        feed_pub = ED.publickey(feed_sk)
        feed_dir = tempfile.mkdtemp(prefix="w328-r5-")
        cfg = KI.FeedConfig(feed_dir, feed_pub, "c")
        osv = {"id": "GHSA-1", "summary": "s", "details": "d",
               "published": "2026-01-01T00:00:00Z",
               "affected": [{"package": {"ecosystem": "npm",
                                         "name": "leftpad"}}]}
        doc = {"schema": "osv/v1", "osv": osv, "artifact_digest": _D1,
               "asserted_standing": "revoked", "supersedes": None}
        canon = json.dumps(doc, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
        doc["signature"] = _b64(ED.sign(feed_sk, canon))
        path = os.path.join(feed_dir, "a.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        got = KI.ingest_file(path, cfg)
        self.assertEqual(got["asserted_standing"], "revoked")

    def test_forged_revoked_still_refused(self):
        feed_sk = bytes([77]) * 32
        feed_pub = ED.publickey(feed_sk)
        rogue = bytes([78]) * 32
        feed_dir = tempfile.mkdtemp(prefix="w328-r5b-")
        cfg = KI.FeedConfig(feed_dir, feed_pub, "c")
        osv = {"id": "GHSA-1", "summary": "s", "details": "d",
               "published": "2026-01-01T00:00:00Z",
               "affected": [{"package": {"ecosystem": "npm",
                                         "name": "leftpad"}}]}
        doc = {"schema": "osv/v1", "osv": osv, "artifact_digest": _D1,
               "asserted_standing": "revoked", "supersedes": None}
        canon = json.dumps(doc, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
        doc["signature"] = _b64(ED.sign(rogue, canon))  # wrong key
        path = os.path.join(feed_dir, "a.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        with self.assertRaises(KI.IngestError):
            KI.ingest_file(path, cfg)


# ---------------------------------------------------------------------------
# W326-1 / W326-3: advisory_binding
# ---------------------------------------------------------------------------

def _adv_policy(pub_b64):
    return {"advisory_policy_input": "adv-pol",
            "signature_threshold": 1,
            "freshness_seconds": 3600,
            "trusted_keys": [pub_b64]}


def _sealed(flags, version, seed_byte=11, fetched_at=1_700_000_000):
    sk = bytes([seed_byte]) * 32
    pub_b64 = _b64(ED.publickey(sk))
    snap = {"advisory_id": "ADV-1", "version": version, "issuer": "feed",
            "fetched_at": fetched_at, "flags": dict(flags)}
    canon = json.dumps(snap, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")
    snap["canonical_bytes"] = canon
    snap["digest"] = hashlib.sha256(canon).hexdigest()
    snap["signatures"] = [{"key": pub_b64,
                           "sig": _b64(ED.sign(sk, canon))}]
    return AB.bind_advisory_input(_adv_policy(pub_b64), snap,
                                  1_700_000_000)


class TestSupersedeTie(unittest.TestCase):
    def test_exact_tie_refused_loud(self):
        a = _sealed({"pkg": "allow"}, 3, seed_byte=11)
        b = _sealed({"pkg": "flagged"}, 3, seed_byte=12)
        with self.assertRaises(AB.AdvisoryBindingError) as ctx:
            AB.supersede([a, b])
        self.assertEqual(ctx.exception.code, "advisory-version-tie")

    def test_identical_object_not_a_tie(self):
        a = _sealed({"pkg": "allow"}, 3)
        self.assertIs(AB.supersede([a, a]), a)

    def test_newest_wins_still_works(self):
        old = _sealed({"pkg": "allow"}, 3)
        new = _sealed({"pkg": "flagged"}, 4)
        self.assertIs(AB.supersede([old, new]), new)
        self.assertIs(AB.supersede([new, old]), new)

    def test_code_registered_in_taxonomy(self):
        self.assertEqual(DC.TAXONOMY["advisory-version-tie"]["domain"],
                         "authority")


class TestSealedInput(unittest.TestCase):
    def test_handbuilt_dict_refused_loud(self):
        pinned = {"advisory_policy_input": "handbuilt",
                  "advisory_id": "handbuilt", "version": 9,
                  "issuer": "handbuilt", "fetched_at": 1_700_000_000,
                  "freshness_seconds": 3600, "signature_threshold": 1,
                  "valid_signatures": 99, "flags": {"pkg": "allow"},
                  "digest": "ab" * 32}
        with self.assertRaises(AB.AdvisoryBindingError) as ctx:
            AB.check_package(pinned, "pkg", 1_700_000_100)
        self.assertEqual(ctx.exception.code, "advisory-input-unpinned")

    def test_sealed_path_still_verifies(self):
        pinned = _sealed({"pkg": "allow"}, 9)
        self.assertIsInstance(pinned, AB.PinnedAdvisory)
        r = AB.check_package(pinned, "pkg", 1_700_000_100)
        self.assertEqual(r["verdict"], "advisory-clear")

    def test_supersede_preserves_seal(self):
        old = _sealed({"pkg": "allow"}, 3)
        new = _sealed({"pkg": "flagged"}, 4)
        winner = AB.supersede([old, new])
        self.assertIsInstance(winner, AB.PinnedAdvisory)
        # The sealed winner flows straight into check_package.
        with self.assertRaises(AB.AdvisoryBindingError) as ctx:
            AB.check_package(winner, "pkg", 1_700_000_100)
        self.assertEqual(ctx.exception.code, "package-advisory-flagged")

    def test_code_registered_in_taxonomy(self):
        self.assertEqual(DC.TAXONOMY["advisory-input-unpinned"]["domain"],
                         "authority")


if __name__ == "__main__":
    unittest.main()
