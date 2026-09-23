"""Wave-73 provenance records: schema, validation, tiering, delegation
chain, session timing (2026-09-22).

Load-bearing claims under test (PROVENANCE_DESIGN.md):
- provenance forgery without the key breaks chain verification
- record-type confusion is refused by schema validation
- schema version games fail closed (never silently accepted)
- delegation-path truncation breaks the binds chain
- payload-tier smuggling into the default tier is refused
- the key-holder session-backdate residual is stated, not hidden:
  in-chain verification passes, the export-time anchor cross-check flags
  impossible timing and reports the soft window as unverifiable

Hermetic: temp dirs, dev key via tests/__init__ opt-in, no network.
Deterministic except wall-clock ts (never asserted on).
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import log as _log  # noqa: E402
from gov import provenance as _prov  # noqa: E402
from gov.log import ActionLog  # noqa: E402

_T0 = "2026-09-22T15:00:00+00:00"
_T1 = "2026-09-22T15:05:00+00:00"
_UNTIL = "2027-03-22T15:00:00+00:00"  # 6 months after _T0


def _delegation():
    return _prov.build_delegation([
        {"kind": "principal", "ref": "user:u_8f31"},
        {"kind": "agent", "ref": "agent:orchestrator-7"},
        {"kind": "sub-agent", "ref": "agent:researcher-3"},
        {"kind": "tool", "ref": "tool:webfetch"},
    ])


def _decision(overrides=None):
    prov = {
        "schema_version": 1,
        "record_type": "decision",
        "session_id": "sess-0001",
        "session_open": _T0,
        "clock_source": "system-wall:UTC+00:00",
        "principal": {"kind": "user", "ref": "user:u_8f31"},
        "delegation": _delegation(),
        "approvals": [{"approval_id": "ap-1", "decision": "approved",
                       "decided_by": "human:ops", "decided_at": _T0}],
        "action": {"verb": "fetch", "tool": "webfetch",
                   "args_digest": "sha256:abc"},
        "resource": {"kind": "url", "ref": "https://example.com/x",
                     "scope": "read"},
        "policy_version": "demo-policy:2026-09-22",
        "matched_rules": ["R3"],
        "payload_tier": "decision",
        "retention": {"class": "decision", "until": _UNTIL,
                      "policy": "art12-default"},
    }
    if overrides:
        prov.update(overrides)
    return {"event": "prov_decision", "prov": prov}


def _outcome(overrides=None):
    e = _decision()
    e["prov"]["record_type"] = "outcome"
    e["prov"]["outcome"] = {"status": "ok", "detail": "fetched 200"}
    e["event"] = "prov_outcome"
    if overrides:
        e["prov"].update(overrides)
    return e


class ProvenanceSchemaTest(unittest.TestCase):
    def test_valid_decision_verifies(self):
        v = _prov.validate_provenance(_decision())
        self.assertTrue(v["ok"], v["errors"])
        self.assertEqual(v["warnings"], [])

    def test_valid_outcome_session_records_verify(self):
        self.assertTrue(_prov.validate_provenance(_outcome())["ok"])
        so = _decision({"record_type": "session_open"})
        del so["prov"]["action"], so["prov"]["resource"], \
            so["prov"]["approvals"]
        self.assertTrue(_prov.validate_provenance(so)["ok"],
                        _prov.validate_provenance(so)["errors"])
        sc = _decision({"record_type": "session_close",
                        "session_close": _T1})
        del sc["prov"]["action"], sc["prov"]["resource"], \
            sc["prov"]["approvals"]
        self.assertTrue(_prov.validate_provenance(sc)["ok"],
                        _prov.validate_provenance(sc)["errors"])

    def test_missing_prov_refused(self):
        v = _prov.validate_provenance({"event": "x"})
        self.assertFalse(v["ok"])

    def test_schema_version_games_fail_closed(self):
        # v2 fields to a v1 verifier: refused, never silently accepted.
        v = _prov.validate_provenance(_decision({"schema_version": 2}))
        self.assertFalse(v["ok"])
        self.assertTrue(any("schema_version" in e for e in v["errors"]))
        # Non-integer version is not 1 either.
        v = _prov.validate_provenance(_decision({"schema_version": "1"}))
        self.assertFalse(v["ok"])
        # Missing version fails closed too.
        e = _decision()
        del e["prov"]["schema_version"]
        self.assertFalse(_prov.validate_provenance(e)["ok"])

    def test_record_type_confusion_rejected(self):
        # A decision record carrying an outcome: escalation attempt.
        e = _decision()
        e["prov"]["outcome"] = {"status": "ok", "detail": "self-approved"}
        v = _prov.validate_provenance(e)
        self.assertFalse(v["ok"])
        self.assertTrue(any("confusion" in x for x in v["errors"]))
        # session_open carrying a session_close.
        e = _decision({"record_type": "session_open",
                       "session_close": _T1})
        del e["prov"]["action"], e["prov"]["resource"], \
            e["prov"]["approvals"]
        v = _prov.validate_provenance(e)
        self.assertFalse(v["ok"])
        # Unknown record type.
        v = _prov.validate_provenance(_decision({"record_type": "grant"}))
        self.assertFalse(v["ok"])
        # Approval carrying action fields without a linked decision ref:
        # escalation surface — refused (wave-73 break→fix).
        e = _decision({"record_type": "approval"})
        v = _prov.validate_provenance(e)
        self.assertFalse(v["ok"])
        self.assertTrue(any("decision_ref" in x for x in v["errors"]))
        # ...but with a decision_ref naming the approved decision it is
        # a well-formed approval record.
        e["prov"]["decision_ref"] = "seq:12"
        v = _prov.validate_provenance(e)
        self.assertTrue(v["ok"], v["errors"])
        # session_close without session_close timestamp.
        e = _decision({"record_type": "session_close"})
        del e["prov"]["action"], e["prov"]["resource"], \
            e["prov"]["approvals"]
        self.assertFalse(_prov.validate_provenance(e)["ok"])

    def test_empty_approvals_require_stated_basis(self):
        e = _decision({"approvals": []})
        v = _prov.validate_provenance(e)
        self.assertFalse(v["ok"])
        e = _decision({"approvals": [], "approval_basis": "policy-auto"})
        self.assertTrue(_prov.validate_provenance(e)["ok"])

    def test_ambient_authority_ref_warns(self):
        e = _decision()
        e["prov"]["principal"] = {"kind": "user", "ref": "system"}
        v = _prov.validate_provenance(e)
        self.assertTrue(v["ok"])  # warning, not error
        self.assertTrue(any("ambient-authority" in w
                            for w in v["warnings"]))


class DelegationChainTest(unittest.TestCase):
    def test_binds_chain_verifies(self):
        d = _delegation()
        self.assertEqual(_prov.validate_delegation(d), [])

    def test_truncation_of_middle_hop_detected(self):
        d = _delegation()
        # Drop the middle hop (index 2, sub-agent): the tool hop's binds
        # still points at the sub-agent's content -> mismatch.
        d["hops"] = [d["hops"][0], d["hops"][1], d["hops"][3]]
        errs = _prov.validate_delegation(d)
        self.assertTrue(errs, "truncated delegation path must fail")
        self.assertTrue(any("binds" in x for x in errs))
        # And the full record is refused.
        self.assertFalse(
            _prov.validate_provenance(_decision({"delegation": d}))["ok"])

    def test_reordered_hops_detected(self):
        d = _delegation()
        d["hops"] = [d["hops"][0], d["hops"][2], d["hops"][1], d["hops"][3]]
        self.assertTrue(_prov.validate_delegation(d))

    def test_edited_hop_content_detected(self):
        d = _delegation()
        d["hops"][2]["ref"] = "agent:attacker-controlled"
        self.assertTrue(_prov.validate_delegation(d))

    def test_principal_must_be_first(self):
        d = _delegation()
        d["hops"][0]["kind"] = "agent"
        d["hops"][0]["binds"] = "GENESIS"
        errs = _prov.validate_delegation(d)
        self.assertTrue(any("principal" in x for x in errs))

    def test_tokens_slot_reserved_for_wave74(self):
        d = _delegation()
        d["hops"][1]["tokens"] = {"user_token": "invented-shape"}
        errs = _prov.validate_delegation(d)
        self.assertTrue(any("Wave-74" in x for x in errs))

    def test_empty_delegation_needs_reason(self):
        d = _prov.build_delegation([], no_delegation_reason="daemon tick")
        self.assertEqual(_prov.validate_delegation(d), [])
        with self.assertRaises(_prov.ProvenanceError):
            _prov.build_delegation([])

    def test_delegation_version_games_fail_closed(self):
        d = _delegation()
        # Wave-74 revved the delegation sub-schema to v2 (§7 contract),
        # so the version game is now played against v3+: unknown
        # versions still fail closed, never silently accepted.
        d["delegation_schema_version"] = 3
        errs = _prov.validate_delegation(d)
        self.assertTrue(any("delegation_schema_version" in x
                            for x in errs))
        # And v2 with v1-shaped (null-token) hops is refused: v2
        # REQUIRES the filled three-token slots on every hop.
        d2 = _delegation()
        d2["delegation_schema_version"] = 2
        errs2 = _prov.validate_delegation(d2)
        self.assertTrue(errs2)


class PayloadTierTest(unittest.TestCase):
    def test_smuggled_prompt_refused(self):
        e = _decision()
        e["prov"]["action"]["args_digest"] = "prompt_text: see below"
        e["prompt_text"] = "full user prompt with secrets"
        v = _prov.validate_provenance(e)
        self.assertFalse(v["ok"])
        self.assertTrue(any("payload-tier bypass" in x
                            for x in v["errors"]))

    def test_smuggled_prompt_nested_refused(self):
        e = _decision()
        e["prov"]["resource"] = {"kind": "url", "ref": "https://x",
                                "scope": "read",
                                "transcript": ["turn1", "turn2"]}
        self.assertFalse(_prov.validate_provenance(e)["ok"])

    def test_restricted_tier_needs_bound_and_access(self):
        e = _decision({"payload_tier": "restricted"})
        e["prov"]["retention"]["class"] = "restricted"
        e["prompt_text"] = "payload content here"
        # Missing access list -> refused.
        self.assertFalse(_prov.validate_provenance(e)["ok"])
        e["prov"]["access"] = ["auditor"]
        v = _prov.validate_provenance(e)
        self.assertTrue(v["ok"], v["errors"])
        # Unbounded retention (until missing) -> refused.
        del e["prov"]["retention"]["until"]
        self.assertFalse(_prov.validate_provenance(e)["ok"])

    def test_retention_class_must_match_tier(self):
        e = _decision()
        e["prov"]["retention"]["class"] = "restricted"
        self.assertFalse(_prov.validate_provenance(e)["ok"])


class AppendIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w73-prov-")
        self.log = ActionLog(str(Path(self.tmp) / "actions.jsonl"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_append_provenance_roundtrip_verifies(self):
        e = _prov.append_provenance(self.log, _decision())
        self.assertEqual(e["prov"]["record_type"], "decision")
        verdict = _log._verify(str(Path(self.tmp) / "actions.jsonl"))
        self.assertTrue(verdict["ok"], verdict.get("error"))
        # The prov section is inside the MAC'd canonical form: altering
        # identity fields without the key breaks the chain.
        lines = (Path(self.tmp) / "actions.jsonl").read_text(
            encoding="utf-8").splitlines()
        forged = json.loads(lines[0])
        forged["prov"]["principal"]["ref"] = "user:attacker"
        (Path(self.tmp) / "actions.jsonl").write_text(
            json.dumps(forged, ensure_ascii=True) + "\n",
            encoding="utf-8")
        verdict = _log._verify(str(Path(self.tmp) / "actions.jsonl"))
        self.assertFalse(verdict["ok"])

    def test_append_provenance_refuses_before_writing(self):
        bad = _decision()
        bad["prov"]["record_type"] = "grant"  # unknown type
        with self.assertRaises(_prov.ProvenanceError):
            _prov.append_provenance(self.log, bad)
        # Nothing was written: the log is still empty.
        self.assertFalse((Path(self.tmp) / "actions.jsonl").exists())

    def test_epoch_id_stamped_on_provenance_records(self):
        e = _prov.append_provenance(self.log, _decision())
        self.assertTrue(e["epoch_id"].startswith("e"))


class SessionTimingTest(unittest.TestCase):
    def _anchored(self, epoch_id, witness_time, grade="anchored"):
        return {"epochs": [{"epoch_id": epoch_id, "grade": grade,
                             "backend": "fake",
                             "witness_time": witness_time}],
                "open_epoch": {"epoch_id": "e00000099",
                               "unanchored_records": 0}}

    def _entry(self, session_id, sopen, sclose, epoch_id):
        e = _decision({"session_id": session_id, "session_open": sopen})
        if sclose:
            e["prov"]["record_type"] = "session_close"
            e["prov"]["session_close"] = sclose
            del e["prov"]["action"], e["prov"]["resource"], \
                e["prov"]["approvals"]
        e["epoch_id"] = epoch_id
        e["seq"] = 1
        return e

    def test_impossible_timing_flagged(self):
        # Session claims to end AFTER the epoch was witnessed: impossible.
        anchors = self._anchored("e00000001", "2026-09-22T16:00:00+00:00")
        entries = [self._entry("s1", _T0, "2026-09-22T18:00:00+00:00",
                               "e00000001")]
        findings = _prov.check_session_timing(entries, anchors)
        self.assertTrue(any(f["kind"] == "impossible-timing"
                            for f in findings), findings)

    def test_sane_timing_clean(self):
        anchors = self._anchored("e00000001", "2026-09-22T16:00:00+00:00")
        entries = [self._entry("s1", _T0, _T1, "e00000001")]
        findings = _prov.check_session_timing(entries, anchors)
        self.assertEqual([f for f in findings
                          if f["kind"] == "impossible-timing"], [])

    def test_soft_window_reported_not_blessed(self):
        # Session spans only the open epoch: timing is unverifiable, and
        # the export says so instead of blessing it.
        anchors = {"epochs": [], "open_epoch": {"epoch_id": "e00000001",
                                                "unanchored_records": 2}}
        entries = [self._entry("s1", _T0, None, "e00000001")]
        findings = _prov.check_session_timing(entries, anchors)
        self.assertTrue(any(f["kind"] == "timing-unverifiable-soft-window"
                            for f in findings), findings)


class RetentionManifestTest(unittest.TestCase):
    def test_manifest_aggregates_per_tier(self):
        entries = [_decision(), _outcome()]
        m = _prov.build_retention_manifest(entries)
        self.assertEqual(m["tiers"]["decision"]["records"], 2)
        self.assertEqual(m["flags"], [])
        self.assertIn("P6M", m["retention_floor"])

    def test_over_retained_restricted_flagged(self):
        e = _decision({"payload_tier": "restricted",
                       "access": ["auditor"]})
        e["prov"]["retention"]["class"] = "restricted"
        # 12 months retention under the default policy: needs a named
        # legal basis.
        e["prov"]["retention"]["until"] = "2027-09-22T15:00:00+00:00"
        m = _prov.build_retention_manifest([e])
        self.assertTrue(any("past the 6-month floor" in f
                            for f in m["flags"]), m["flags"])


class ProvenanceExportTest(unittest.TestCase):
    def test_export_joins_anchor_grades(self):
        anchors = {"epochs": [{"epoch_id": "e00000001",
                               "grade": "anchored", "backend": "fake",
                               "witness_time": "2026-09-22T16:00:00+00:00"}],
                   "open_epoch": {"epoch_id": "e00000002",
                                  "unanchored_records": 1}}
        e1 = _decision()
        e1["epoch_id"] = "e00000001"
        e1["seq"] = 1
        e2 = _decision({"session_id": "sess-0002"})
        e2["epoch_id"] = "e00000002"
        e2["seq"] = 2
        exp = _prov.provenance_export([e1, e2], anchors)
        self.assertIn("Art 12(1)", exp["automatic_recording"])
        rows = {r["seq"]: r for r in exp["traceability_rows"]}
        self.assertEqual(rows[1]["anchor_grade"], "anchored")
        # Unknown epoch -> operator-attested-only, never silently clean.
        self.assertEqual(rows[2]["anchor_grade"], "operator-attested-only")
        self.assertEqual(exp["delegation_monitoring"]
                         ["records_with_delegation"], 2)
        self.assertEqual(exp["delegation_monitoring"]
                         ["distinct_hop_depths"], [4])


if __name__ == "__main__":
    unittest.main()
