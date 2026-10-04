"""Unit tests for gov/background_scan.py (wave-326 lane 3).

These cover the seams the break-first battery does not: input
validation, trigger-evaluation edge cases, atomic state writes, the
unparseable-sidecar path, and re-registration. Fixtures mirror
evals/w326_sched_probes.py (fixed seeds, deterministic keys).
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import background_scan as BS  # noqa: E402
from gov import skill_supply_chain as SC  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402


def _seed(tag):
    return (tag + "-seed").ljust(32, "0")[:32].encode("ascii")


_R1 = Ed25519Signer(_seed("sched-r1"))
_P1 = Ed25519Signer(_seed("sched-p1"))

FUTURE = "2030-01-01T00:00:00Z"
T0 = 1800000000
SKILL = "skills/pay/x"
BYTES_V1 = b"skill-content-v1"


def _keyinfo(signer):
    return {"keytype": "ed25519",
            "keyval": {"public": signer.public_key.hex()}}


ROOT_TRUST = {"keys": {"r1": _keyinfo(_R1), "pay-k1": _keyinfo(_P1)},
              "root": {"keyids": ["r1"], "threshold": 1}}


def _seal(kind, doc, pairs):
    return SC.seal_document(kind, doc, pairs)


def _deleg_wire(version):
    doc = {"version": version, "expires": FUTURE,
           "delegations": [{"name": "pay", "keyids": ["pay-k1"],
                             "threshold": 1, "paths": ["skills/pay/*"],
                             "terminating": False}]}
    return _seal("delegations", doc, [("r1", _R1)])


def _authz_wire(skill_bytes):
    doc = {"skill": SKILL, "version": 1,
           "digest": hashlib.sha256(skill_bytes).hexdigest(),
           "expires": FUTURE}
    return _seal("link", doc, [("pay-k1", _P1)])


def _tmp_state():
    return os.path.join(tempfile.mkdtemp(prefix="ut-sched-"), "state.json")


def _register(sp, **kw):
    args = dict(skill_path=SKILL, delegation_wire=_deleg_wire(1),
                authz_wire=_authz_wire(BYTES_V1), skill_bytes=BYTES_V1,
                ttl_seconds=3600, scan_interval_seconds=900, now=T0)
    args.update(kw)
    return BS.register_skill(sp, **args)


def _inv(**kw):
    entry = {"skill_path": SKILL, "skill_bytes": BYTES_V1,
             "delegation_wire": _deleg_wire(1),
             "authz_wire": _authz_wire(BYTES_V1)}
    entry.update(kw)
    return [entry]


class TestRegistrationValidation(unittest.TestCase):
    def test_empty_skill_path_rejected(self):
        with self.assertRaises(BS.BackgroundScanError) as ctx:
            _register(_tmp_state(), skill_path="")
        self.assertEqual(ctx.exception.code, "supplychain-scan-malformed")

    def test_non_bytes_rejected(self):
        with self.assertRaises(BS.BackgroundScanError) as ctx:
            _register(_tmp_state(), skill_bytes="not-bytes")
        self.assertEqual(ctx.exception.code, "supplychain-scan-malformed")

    def test_non_positive_ttl_rejected(self):
        for bad in (0, -5, "3600"):
            with self.assertRaises(BS.BackgroundScanError):
                _register(_tmp_state(), ttl_seconds=bad)

    def test_non_positive_interval_rejected(self):
        for bad in (0, -1):
            with self.assertRaises(BS.BackgroundScanError):
                _register(_tmp_state(), scan_interval_seconds=bad)

    def test_state_file_is_valid_json_after_register(self):
        sp = _tmp_state()
        _register(sp)
        with open(sp, encoding="utf-8") as _fh:
            state = json.load(_fh)
        self.assertEqual(state["schema"], "sasanam-background-scan-state/v1")
        self.assertIn(SKILL, state["skills"])

    def test_re_registration_refused_loud(self):
        # Wave-328 lane 2: re-registration is a caller bug and is refused
        # LOUD; it no longer silently re-baselines.
        sp = _tmp_state()
        _register(sp, now=T0)
        with self.assertRaises(BS.BackgroundScanError) as ctx:
            _register(sp, now=T0 + 5, delegation_wire=_deleg_wire(2))
        self.assertEqual(ctx.exception.code,
                         "supplychain-scan-already-registered")
        with open(sp, encoding="utf-8") as _fh:
            state = json.load(_fh)
        # Baseline untouched by the refused call.
        self.assertEqual(state["skills"][SKILL]["delegations_version"], 1)

    def test_update_skill_registration_config_path(self):
        # Wave-328 lane 2: the legitimate config-change path; scan-owned
        # baselines are never rewritten by it.
        sp = _tmp_state()
        _register(sp, now=T0)
        rec = BS.update_skill_registration(
            sp, skill_path=SKILL, ttl_seconds=999,
            scan_interval_seconds=60)
        self.assertEqual(rec["ttl_seconds"], 999)
        self.assertEqual(rec["scan_interval_seconds"], 60)
        self.assertEqual(rec["delegations_version"], 1)
        with self.assertRaises(BS.BackgroundScanError) as ctx:
            BS.update_skill_registration(
                sp, skill_path="skills/nope", ttl_seconds=1)
        self.assertEqual(ctx.exception.code, "supplychain-scan-malformed")

    def test_register_returns_record(self):
        rec = _register(_tmp_state())
        self.assertEqual(rec["status"], "never-scanned")
        # Registration makes the first scan due immediately.
        self.assertEqual(rec["next_scan_at"], T0)
        self.assertIsNone(rec["expires_at"])


class TestTriggerEvaluation(unittest.TestCase):
    def _rec(self, **kw):
        rec = {"digest": "d", "delegations_version": 1,
               "next_scan_at": T0 + 100, "scan_interval_seconds": 100}
        rec.update(kw)
        return rec

    def test_interval_due(self):
        trig, missed, missed_total = BS._evaluate_triggers(self._rec(), now=T0 + 100,
                                       digest_now="d",
                                       deleg_version_now=1)
        self.assertEqual(trig, "interval")
        self.assertEqual(missed, [])
        self.assertEqual(missed_total, 0)

    def test_interval_not_due(self):
        trig, missed, missed_total = BS._evaluate_triggers(self._rec(), now=T0 + 99,
                                       digest_now="d",
                                       deleg_version_now=1)
        self.assertIsNone(trig)
        self.assertEqual(missed, [])

    def test_missed_intervals_counted(self):
        trig, missed, missed_total = BS._evaluate_triggers(self._rec(), now=T0 + 350,
                                       digest_now="d",
                                       deleg_version_now=1)
        # The currently-due interval (T0+300) is the live trigger,
        # not a missed one.
        self.assertEqual(missed, [T0 + 100, T0 + 200])
        self.assertEqual(trig, "interval")

    def test_policy_change_trigger(self):
        trig, _, _ = BS._evaluate_triggers(self._rec(), now=T0,
                                        digest_now="d", deleg_version_now=2)
        self.assertEqual(trig, "policy-change")

    def test_policy_change_unknown_baseline_no_trigger(self):
        # Baseline version unknown: cannot claim a change.
        rec = self._rec(delegations_version=None)
        trig, _, _ = BS._evaluate_triggers(rec, now=T0, digest_now="d",
                                        deleg_version_now=2)
        self.assertIsNone(trig)

    def test_resource_change_trigger(self):
        trig, _, _ = BS._evaluate_triggers(self._rec(), now=T0, digest_now="other",
                                        deleg_version_now=1)
        self.assertEqual(trig, "resource-change")

    def test_policy_beats_interval_in_precedence(self):
        # When both fire, policy-change is the reported trigger.
        trig, _, _ = BS._evaluate_triggers(self._rec(), now=T0 + 500,
                                        digest_now="d", deleg_version_now=2)
        self.assertEqual(trig, "policy-change")


class TestRunScanEdges(unittest.TestCase):
    def test_empty_inventory_returns_no_reports(self):
        sp = _tmp_state()
        _register(sp)
        self.assertEqual(BS.run_scan(sp, [], ROOT_TRUST, now=T0), [])

    def test_no_trigger_no_scan_but_standing_checked(self):
        sp = _tmp_state()
        _register(sp, now=T0, ttl_seconds=100,
                  scan_interval_seconds=10000)
        BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)
        reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0 + 50)
        self.assertEqual(len(reports), 1)
        r = reports[0]
        self.assertIsNone(r["trigger"])
        self.assertFalse(r["scan_performed"])
        self.assertEqual(r["verdict"], "not-scanned")
        self.assertEqual(r["standing"]["status"], "current")

    def test_unparseable_sidecar_notes_every_report_loud(self):
        sp = _tmp_state()
        _register(sp, now=T0)
        with open(sp + ".inprogress", "w", encoding="utf-8") as fh:
            fh.write("not-json{{{")
        reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0 + 10)
        self.assertTrue(any("unknown skill" in n for n in reports[0]["notes"]))
        self.assertFalse(os.path.exists(sp + ".inprogress"))

    def test_sidecar_for_other_skill_not_attributed(self):
        sp = _tmp_state()
        _register(sp, now=T0)
        with open(sp + ".inprogress", "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"skill": "skills/other/y",
                                 "started_at": T0 + 1}))
        reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0 + 10)
        self.assertFalse(any("crash-recovered" in n
                             for n in reports[0]["notes"]))
        self.assertFalse(os.path.exists(sp + ".inprogress"))

    def test_state_written_atomically(self):
        # No stray temp files beside the state after a scan.
        sp = _tmp_state()
        _register(sp, now=T0)
        BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)
        names = os.listdir(os.path.dirname(sp))
        self.assertEqual(sorted(names), ["state.json"])

    def test_bad_state_version_refused(self):
        sp = _tmp_state()
        with open(sp, "w", encoding="utf-8") as fh:
            json.dump({"version": 99, "skills": {}}, fh)
        with self.assertRaises(BS.BackgroundScanError) as ctx:
            BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)
        self.assertEqual(ctx.exception.code, "supplychain-scan-state-corrupt")

    def test_root_trust_type_checked(self):
        sp = _tmp_state()
        _register(sp, now=T0)
        with self.assertRaises(BS.BackgroundScanError):
            BS.run_scan(sp, _inv(), "not-a-dict", now=T0)

    def test_lapse_boundary_is_inclusive(self):
        # At exactly expires_at the TTL has fully elapsed: the standing
        # lapses (>= boundary, no 1s grace).
        sp = _tmp_state()
        _register(sp, now=T0, ttl_seconds=100, scan_interval_seconds=10000)
        BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)
        reports = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0 + 100)
        r = reports[0]
        self.assertEqual(r["standing"]["status"], "lapsed")
        self.assertEqual(r["code"], "supplychain-standing-lapsed")

    def test_report_schema_keys_stable(self):
        sp = _tmp_state()
        _register(sp, now=T0)
        r = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]
        self.assertEqual(r["schema"], "sasanam-background-scan-report/v1")
        for key in ("skill", "scanned_at", "trigger", "scan_performed",
                    "verdict", "code", "detail", "checked",
                    "missed_intervals", "notes", "standing"):
            self.assertIn(key, r)


if __name__ == "__main__":
    unittest.main()
