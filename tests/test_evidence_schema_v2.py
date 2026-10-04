"""Unit tests for gov/evidence_schema_v2.py (wave-318 lane 2).

AU-3 record extraction, CC8.1 decision-maker versioning, and the
change-log consistency rule. Hermetic: no keys, no log files.
"""

import unittest

from gov import evidence_schema_v2 as sv2

PROMPT = "ab" * 32
PROMPT2 = "cd" * 32
CFG = "ef" * 32


def _genesis(prompt=PROMPT, cfg=CFG):
    return [
        {"changed_at": "2026-10-01T00:00:00Z", "component": "model",
         "from_version": None, "to_version": "2026.10.1",
         "to_digest": None, "note": "genesis"},
        {"changed_at": "2026-10-01T00:00:00Z", "component": "system_prompt",
         "from_version": None, "to_version": "sp-2026-10-01",
         "to_digest": prompt, "note": "genesis"},
        {"changed_at": "2026-10-01T00:00:00Z", "component": "config",
         "from_version": None, "to_version": "cfg-2026-10-01",
         "to_digest": cfg, "note": "genesis"},
    ]


def _dm(prompt=PROMPT, cfg=CFG, changelog=None):
    return {
        "model": {"name": "m", "version": "2026.10.1"},
        "system_prompt": {"digest_sha256": prompt,
                          "version": "sp-2026-10-01"},
        "config": {"snapshot_digest_sha256": cfg,
                   "version": "cfg-2026-10-01"},
        "change_log": _genesis(prompt, cfg) if changelog is None
        else changelog,
    }


class TestExtractAU3(unittest.TestCase):
    def test_full_entry_is_complete(self):
        rec = sv2.extract_au3({
            "seq": 3, "hash": "00" * 32, "event": "tool_call",
            "principal": "agent:alpha", "ts": "2026-10-04T00:00:00Z",
            "source": "executor:local", "decision": "allow"})
        self.assertEqual(rec["au3"],
                         {"who": "agent:alpha", "what": "tool_call",
                          "when": "2026-10-04T00:00:00Z",
                          "where": "executor:local", "result": "allow"})
        self.assertTrue(rec["complete"])
        self.assertEqual(rec["seq"], 3)

    def test_missing_fields_are_honest_nulls(self):
        rec = sv2.extract_au3({"seq": 1, "hash": "11" * 32,
                               "event": "approval_granted"})
        self.assertIsNone(rec["au3"]["who"])
        self.assertIsNone(rec["au3"]["where"])
        self.assertEqual(rec["au3"]["what"], "approval_granted")
        self.assertFalse(rec["complete"])

    def test_non_dict_refused(self):
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.extract_au3("not-a-record")

    def test_build_records_not_a_list(self):
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.build_au3_records({"seq": 1})


class TestDecisionMaker(unittest.TestCase):
    def test_none_is_honest_absence(self):
        dmv = sv2.build_decision_maker_versions(None, None)
        self.assertIsNone(dmv["model"]["value"])
        self.assertTrue(dmv["model"]["operator_must_supply"])
        self.assertEqual(dmv["change_log"], [])

    def test_genesis_chain_accepted(self):
        dmv = sv2.build_decision_maker_versions(
            {"model": {"name": "m", "version": "2026.10.1"},
             "system_prompt": {"digest_sha256": PROMPT,
                               "version": "sp-1"},
             "config": {"snapshot_digest_sha256": CFG,
                        "version": "cfg-1"}},
            _genesis())
        self.assertEqual(dmv["model"]["version"], "2026.10.1")
        self.assertEqual(len(dmv["change_log"]), 3)

    def test_non_genesis_first_entry_refused(self):
        bad = _genesis()
        bad[0]["from_version"] = "0.0"  # must be null for the first entry
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.build_decision_maker_versions(
                {"model": {"name": "m", "version": "2026.10.1"},
                 "system_prompt": {"digest_sha256": PROMPT,
                                   "version": "sp-1"},
                 "config": {"snapshot_digest_sha256": CFG,
                            "version": "cfg-1"}}, bad)

    def test_broken_chain_refused(self):
        log = _genesis()
        log.append({"changed_at": "2026-10-04T00:00:00Z",
                    "component": "model",
                    "from_version": "WRONG.0",  # does not chain
                    "to_version": "2026.10.2", "to_digest": None,
                    "note": "upgrade"})
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.build_decision_maker_versions(
                {"model": {"name": "m", "version": "2026.10.2"},
                 "system_prompt": {"digest_sha256": PROMPT,
                                   "version": "sp-1"},
                 "config": {"snapshot_digest_sha256": CFG,
                            "version": "cfg-1"}}, log)

    def test_unknown_component_refused(self):
        log = _genesis()
        log.append({"changed_at": "2026-10-04T00:00:00Z",
                    "component": "retrieval_index",
                    "from_version": None, "to_version": "v1",
                    "to_digest": None, "note": "nope"})
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.build_decision_maker_versions(
                {"model": {"name": "m", "version": "2026.10.1"},
                 "system_prompt": {"digest_sha256": PROMPT,
                                   "version": "sp-1"},
                 "config": {"snapshot_digest_sha256": CFG,
                            "version": "cfg-1"}}, log)

    def test_bad_digest_refused(self):
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.build_decision_maker_versions(
                {"model": {"name": "m", "version": "2026.10.1"},
                 "system_prompt": {"digest_sha256": "not-hex",
                                   "version": "sp-1"},
                 "config": {"snapshot_digest_sha256": CFG,
                            "version": "cfg-1"}}, _genesis())


class TestChangeLogConsistency(unittest.TestCase):
    def test_consistent_history_passes(self):
        sv2.check_changelog_consistency(
            sv2.build_decision_maker_versions(
                {"model": {"name": "m", "version": "2026.10.2"},
                 "system_prompt": {"digest_sha256": PROMPT2,
                                   "version": "sp-2"},
                 "config": {"snapshot_digest_sha256": CFG,
                            "version": "cfg-1"}},
                _genesis() + [
                    {"changed_at": "2026-10-04T00:00:00Z",
                     "component": "model", "from_version": "2026.10.1",
                     "to_version": "2026.10.2", "to_digest": None,
                     "note": "upgrade"},
                    {"changed_at": "2026-10-04T00:00:00Z",
                     "component": "system_prompt",
                     "from_version": "sp-2026-10-01", "to_version": "sp-2",
                     "to_digest": PROMPT2, "note": "prompt update"},
                ]))

    def test_prompt_change_without_landing_entry_refused(self):
        dmv = sv2.build_decision_maker_versions(
            {"model": {"name": "m", "version": "2026.10.1"},
             "system_prompt": {"digest_sha256": PROMPT2,  # changed...
                               "version": "sp-2"},
             "config": {"snapshot_digest_sha256": CFG,
                        "version": "cfg-1"}},
            _genesis())  # ...but no entry lands on PROMPT2
        with self.assertRaises(sv2.SchemaV2Error) as ctx:
            sv2.check_changelog_consistency(dmv)
        self.assertEqual(ctx.exception.code, "change-log-gap")

    def test_missing_component_log_refused(self):
        dmv = sv2.build_decision_maker_versions(
            {"model": {"name": "m", "version": "2026.10.1"},
             "system_prompt": {"digest_sha256": PROMPT,
                               "version": "sp-1"},
             "config": {"snapshot_digest_sha256": CFG,
                        "version": "cfg-1"}},
            [e for e in _genesis()
             if e["component"] != "system_prompt"])
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.check_changelog_consistency(dmv)


class TestValidateClaims(unittest.TestCase):
    def test_good_claims_pass(self):
        sv2.validate_v2_claims({
            "au3_records": [
                {"seq": 1, "hash": "00" * 32,
                 "au3": {"who": "a", "what": "e", "when": "t",
                         "where": "l", "result": "r"},
                 "complete": True}],
            "decision_maker_versions": _dm(),
        })

    def test_missing_au3_refused(self):
        with self.assertRaises(sv2.SchemaV2Error) as ctx:
            sv2.validate_v2_claims({"decision_maker_versions": _dm()})
        self.assertEqual(ctx.exception.code, "extension-section-missing")

    def test_missing_decision_maker_versions_refused(self):
        with self.assertRaises(sv2.SchemaV2Error) as ctx:
            sv2.validate_v2_claims({"au3_records": []})
        self.assertEqual(ctx.exception.code, "extension-section-missing")

    def test_old_decision_maker_key_refused(self):
        # The claim key is the builder section name
        # (decision_maker_versions); the old short name is not accepted.
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.validate_v2_claims({"au3_records": [],
                                    "decision_maker": _dm()})

    def test_au3_not_a_list_refused(self):
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.validate_v2_claims({"au3_records": {"x": 1},
                                    "decision_maker": _dm()})

    def test_complete_with_nulls_refused(self):
        with self.assertRaises(sv2.SchemaV2Error):
            sv2.validate_v2_claims({
                "au3_records": [
                    {"seq": 1, "hash": "00" * 32,
                     "au3": {"who": None, "what": "e", "when": "t",
                             "where": "l", "result": "r"},
                     "complete": True}],  # lies: nulls but complete
                "decision_maker": _dm(),
            })

    def test_build_v2_sections_shape(self):
        sections = sv2.build_v2_sections(
            [{"seq": 1, "hash": "00" * 32, "event": "e"}],
            {"model": {"name": "m", "version": "v"},
             "system_prompt": {"digest_sha256": PROMPT, "version": "sp"},
             "config": {"snapshot_digest_sha256": CFG, "version": "cfg"}},
            _genesis())
        self.assertEqual(len(sections["au3_records"]), 1)
        self.assertEqual(sections["decision_maker_versions"]["model"]
                         ["version"], "v")

    def test_build_v2_sections_requires_decision_maker(self):
        # Schema 2.0 without decision-maker context refuses fail-fast
        # (build 1.0 instead); it is never issued unverifiable.
        with self.assertRaises(sv2.SchemaV2Error) as ctx:
            sv2.build_v2_sections(
                [{"seq": 1, "hash": "00" * 32, "event": "e"}],
                None, None)
        self.assertEqual(ctx.exception.code, "decision-maker-required")


if __name__ == "__main__":
    unittest.main()
