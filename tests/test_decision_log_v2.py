"""Unit tests for gov/decision_log_v2.py (wave-202 lane D).

Public seams only: build_event / verify_event / verify_redaction /
verify_replay / append_event / register_replay_fn / is_v2_event /
event_digest + the decision_bom decision_event_v2 wiring.
Deterministic. Stdlib unittest.
"""

import copy
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_log_v2 as dlv  # noqa: E402


def _honest_parts():
    decision = {"kind": "tool_call", "effect": "deny",
                "policy_id": "p1", "reason": "rule r1 matched"}
    raw = {"agent_id": "a1", "ssn": "123-45-6789", "note": "x",
           "nested": {"token": "sekret", "level": 3}}
    inputs = {"rules": [{"id": "r1", "effect": "deny",
                         "match": {"role": "intern"}}],
              "request": {"role": "intern", "tool": "read"}}
    verdict = {"effect": "deny", "matched_rule": "r1",
               "reason": "deny-first: rule r1 matched"}
    return decision, raw, inputs, verdict


def _honest_event():
    decision, raw, inputs, verdict = _honest_parts()
    event = dlv.build_event(
        decision=decision, raw_body=raw,
        erased=["/ssn"], masked=["/nested/token"],
        replay_fn="deny_first_rules",
        replay_inputs=inputs, replay_verdict=verdict)
    return event, raw


def _reid(event):
    """Recompute decision_id after hand-tampering (the forger's move)."""
    event = copy.deepcopy(event)
    event["decision_id"] = dlv._decision_id_for(event)
    return event


class BuildTests(unittest.TestCase):
    def test_round_trip(self):
        event, _ = _honest_event()
        self.assertTrue(dlv.verify_event(event))
        self.assertTrue(dlv.is_v2_event(event))
        self.assertEqual(event["event_version"], 2)

    def test_erased_absent_masked_placeholder(self):
        event, _ = _honest_event()
        self.assertNotIn("ssn", event["body"])
        self.assertEqual(event["body"]["nested"]["token"],
                         {"$masked": True})
        self.assertEqual(event["body"]["nested"]["level"], 3)

    def test_decision_id_stable_and_content_derived(self):
        e1, _ = _honest_event()
        e2, _ = _honest_event()
        self.assertEqual(e1["decision_id"], e2["decision_id"])
        e3 = copy.deepcopy(e1)
        e3["decision"]["reason"] = "changed"
        self.assertNotEqual(e3["decision_id"],
                            dlv._decision_id_for(e3))

    def test_bad_pointer_syntax(self):
        decision, raw, inputs, verdict = _honest_parts()
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw,
                            erased=["no-slash"],
                            replay_fn="deny_first_rules",
                            replay_inputs=inputs, replay_verdict=verdict)

    def test_missing_pointer(self):
        decision, raw, inputs, verdict = _honest_parts()
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw,
                            erased=["/nope"],
                            replay_fn="deny_first_rules",
                            replay_inputs=inputs, replay_verdict=verdict)

    def test_overlapping_pointers_refused(self):
        decision, raw, inputs, verdict = _honest_parts()
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw,
                            erased=["/nested"], masked=["/nested/token"],
                            replay_fn="deny_first_rules",
                            replay_inputs=inputs, replay_verdict=verdict)

    def test_pointer_escaping(self):
        decision = {"kind": "k", "effect": "allow", "policy_id": "p",
                    "reason": "r"}
        raw = {"a/b": {"~key": "secret"}}
        inputs = {"rules": [], "request": {}}
        verdict = {"effect": "deny", "matched_rule": None,
                   "reason": "default-deny: no rule matched"}
        event = dlv.build_event(
            decision=decision, raw_body=raw, erased=["/a~1b/~0key"],
            replay_fn="deny_first_rules",
            replay_inputs=inputs, replay_verdict=verdict)
        self.assertTrue(dlv.verify_event(event))
        self.assertNotIn("~key", event["body"]["a/b"])

    def test_unknown_replay_fn_refused(self):
        decision, raw, inputs, verdict = _honest_parts()
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw,
                            replay_fn="nope",
                            replay_inputs=inputs, replay_verdict=verdict)

    def test_duplicate_replay_fn_refused(self):
        with self.assertRaises(dlv.EventBuildError):
            dlv.register_replay_fn("deny_first_rules", lambda i: {})

    def test_list_index_deletion_order(self):
        # Erasing two list elements must erase the CLAIMED ones, not
        # their shifted neighbors.
        decision = {"kind": "k", "effect": "allow", "policy_id": "p",
                    "reason": "r"}
        raw = {"items": ["a", "b", "c", "d"]}
        inputs = {"rules": [], "request": {}}
        verdict = {"effect": "deny", "matched_rule": None,
                   "reason": "default-deny: no rule matched"}
        event = dlv.build_event(
            decision=decision, raw_body=raw, erased=["/items/0", "/items/2"],
            replay_fn="deny_first_rules",
            replay_inputs=inputs, replay_verdict=verdict)
        self.assertEqual(event["body"]["items"], ["b", "d"])
        self.assertTrue(dlv.verify_event(event))
        self.assertTrue(dlv.verify_redaction(event, raw))

    def test_duplicate_pointers_refused(self):
        decision, raw, inputs, verdict = _honest_parts()
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw,
                            masked=["/nested/token", "/nested/token"],
                            replay_fn="deny_first_rules",
                            replay_inputs=inputs, replay_verdict=verdict)

    def test_non_canonicalizable_build(self):
        decision, raw, inputs, verdict = _honest_parts()
        raw_bad = {"ok": {(1, 2): "tuple-key"}}
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw_bad,
                            replay_fn="deny_first_rules",
                            replay_inputs=inputs, replay_verdict=verdict)

    def test_non_canonicalizable_verify(self):
        event, _ = _honest_event()
        event["body"]["bad"] = {(1, 2): "tuple-key"}
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event(event)

    def test_unknown_decision_keys_refused(self):
        decision, raw, inputs, verdict = _honest_parts()
        decision["surprise"] = 1
        with self.assertRaises(dlv.EventBuildError):
            dlv.build_event(decision=decision, raw_body=raw,
                            replay_fn="deny_first_rules",
                            replay_inputs=inputs, replay_verdict=verdict)

    def test_raw_body_not_mutated(self):
        _, raw = _honest_event()
        self.assertEqual(raw["ssn"], "123-45-6789")
        self.assertEqual(raw["nested"]["token"], "sekret")


class VerifyTests(unittest.TestCase):
    def test_tampered_body_id_mismatch(self):
        event, _ = _honest_event()
        event["body"]["note"] = "tampered"
        with self.assertRaises(dlv.EventVerifyError) as cm:
            dlv.verify_event(event)
        self.assertIn("MISMATCH", str(cm.exception))

    def test_forged_decision_id_refused(self):
        event, _ = _honest_event()
        event["decision_id"] = "0" * 64
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event(event)

    def test_not_v2(self):
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event({"event_version": 1, "decision_trace": {}})
        self.assertFalse(dlv.is_v2_event({"event_version": 1}))

    def test_redaction_lie_dropped_pointer(self):
        # The forger's move: drop /ssn from erased, restore the value,
        # recompute decision_id -- the committed digest betrays them.
        event, _ = _honest_event()
        forged = copy.deepcopy(event)
        forged["erased"] = []
        forged["body"]["ssn"] = "123-45-6789"
        forged = _reid(forged)
        with self.assertRaises(dlv.RedactionLieError) as cm:
            dlv.verify_event(forged)
        self.assertIn("/ssn", str(cm.exception))

    def test_redaction_lie_erased_present(self):
        event, _ = _honest_event()
        forged = copy.deepcopy(event)
        forged["body"]["ssn"] = "123-45-6789"
        forged = _reid(forged)
        with self.assertRaises(dlv.RedactionLieError):
            dlv.verify_event(forged)

    def test_redaction_lie_mask_placeholder_wrong(self):
        event, _ = _honest_event()
        forged = copy.deepcopy(event)
        forged["body"]["nested"]["token"] = "sekret"
        forged = _reid(forged)
        with self.assertRaises(dlv.RedactionLieError):
            dlv.verify_event(forged)

    def test_value_predicate_hook(self):
        event, _ = _honest_event()
        # A predicate flagging anything looking like an ssn in the body;
        # /ssn is erased so no hit. Plant one uncovered.
        forged = copy.deepcopy(event)
        forged["body"]["other"] = "999-99-9999"
        forged = _reid(forged)
        pred = lambda p, v: isinstance(v, str) and v.count("-") == 2  # noqa: E731
        with self.assertRaises(dlv.RedactionLieError):
            dlv.verify_event(forged, value_predicates=[pred])
        # And the honest event passes the same predicate.
        self.assertTrue(dlv.verify_event(event, value_predicates=[pred]))

    def test_verify_redaction_with_raw(self):
        event, raw = _honest_event()
        self.assertTrue(dlv.verify_redaction(event, raw))

    def test_verify_redaction_catches_capture_time_lie(self):
        # Producer built the event from a SANITIZED copy (ssn="123-...")
        # while the true raw had ssn="999-...". The event is internally
        # consistent -- offline verification passes -- but the auditor
        # holding the true raw catches the digest mismatch.
        event, raw = _honest_event()
        true_raw = copy.deepcopy(raw)
        true_raw["ssn"] = "999-99-9999"
        self.assertTrue(dlv.verify_event(event))  # offline: consistent
        with self.assertRaises(dlv.RedactionLieError):
            dlv.verify_redaction(event, true_raw)


class ReplayTests(unittest.TestCase):
    def test_replay_ok(self):
        event, _ = _honest_event()
        self.assertTrue(dlv.verify_replay(event))

    def test_replay_divergence_on_omitted_input(self):
        # Drop the material input request.role; the forger recomputes
        # the id. Replay now default-denies instead of matching r1.
        event, _ = _honest_event()
        forged = copy.deepcopy(event)
        del forged["replay"]["inputs"]["request"]["role"]
        forged = _reid(forged)
        with self.assertRaises(dlv.ReplayDivergenceError) as cm:
            dlv.verify_event(forged)
        self.assertIn("DIVERGED", str(cm.exception))

    def test_replay_missing_inputs_fail_closed(self):
        event, _ = _honest_event()
        forged = copy.deepcopy(event)
        del forged["replay"]["inputs"]["request"]
        forged = _reid(forged)
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event(forged)

    def test_replay_unknown_fn(self):
        event, _ = _honest_event()
        forged = copy.deepcopy(event)
        forged["replay"]["fn"] = "ghost"
        forged = _reid(forged)
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event(forged)

    def test_replay_complete_false_refused(self):
        decision, raw, inputs, verdict = _honest_parts()
        event = dlv.build_event(
            decision=decision, raw_body=raw,
            replay_fn="deny_first_rules",
            replay_inputs=inputs, replay_verdict=verdict,
            replay_complete=False)
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_event(event)

    def test_deny_first_semantics(self):
        fn = dlv._REPLAY_FNS["deny_first_rules"]
        inputs = {"rules": [
            {"id": "a", "effect": "allow", "match": {"x": 1}},
            {"id": "d", "effect": "deny", "match": {"x": 1}}],
            "request": {"x": 1}}
        self.assertEqual(fn(inputs)["effect"], "deny")
        inputs["request"] = {"x": 2}
        self.assertEqual(fn(inputs)["effect"], "deny")
        self.assertIsNone(fn(inputs)["matched_rule"])


class ChainTests(unittest.TestCase):
    def test_append_event_chains(self):
        from gov.log import ActionLog, verify_chain
        tmp = tempfile.mkdtemp(prefix="g202d-test-")
        log = ActionLog(os.path.join(tmp, "audit.jsonl"),
                        deployment_mode="staging")
        event, _ = _honest_event()
        entry = dlv.append_event(log, event)
        self.assertEqual(event["audit"]["seq"], entry["seq"])
        self.assertEqual(event["audit"]["entry_hash"], entry["hash"])
        # decision_id still verifies: audit is chain bookkeeping,
        # excluded from the id preimage.
        self.assertTrue(dlv.verify_event(event))
        ok, _, _ = verify_chain(os.path.join(tmp, "audit.jsonl"))
        self.assertTrue(ok)

    def test_verify_redaction_rejects_forged_id(self):
        event, raw = _honest_event()
        event["decision_id"] = "0" * 64
        with self.assertRaises(dlv.EventVerifyError):
            dlv.verify_redaction(event, raw)

    def test_append_event_rejects_extra_override(self):
        from gov.log import ActionLog
        tmp = tempfile.mkdtemp(prefix="g202d-test-")
        log = ActionLog(os.path.join(tmp, "audit.jsonl"),
                        deployment_mode="staging")
        event, _ = _honest_event()
        with self.assertRaises(dlv.EventBuildError):
            dlv.append_event(log, event,
                             extra={"decision_event_v2": {"evil": True}})

    def test_event_digest_excludes_audit_and_reproduces_from_log(self):
        # The BOM binds event_digest; an auditor holding ONLY the
        # chained log entry must reproduce it. append_event stamps
        # audit in-memory AFTER serialization, so the persisted entry
        # has no audit key -- the digest must exclude it.
        from gov.log import ActionLog, read_entries
        tmp = tempfile.mkdtemp(prefix="g202d-test-")
        path = os.path.join(tmp, "audit.jsonl")
        log = ActionLog(path, deployment_mode="staging")
        event, _ = _honest_event()
        d_pre = dlv.event_digest(event)
        dlv.append_event(log, event)
        self.assertIn("audit", event)  # stamped in-memory only
        persisted = read_entries(path)[0]["decision_event_v2"]
        self.assertNotIn("audit", persisted)
        self.assertEqual(dlv.event_digest(persisted), d_pre)

    def test_v1_entries_untouched(self):
        # A v1-style entry (no v2 envelope) appends and reads back fine.
        from gov.log import ActionLog, read_entries
        tmp = tempfile.mkdtemp(prefix="g202d-test-")
        log = ActionLog(os.path.join(tmp, "audit.jsonl"),
                        deployment_mode="staging")
        log.append({"decision": "execution_authorized",
                    "decision_trace": {"trace_version": 1}})
        entries = read_entries(os.path.join(tmp, "audit.jsonl"))
        self.assertEqual(entries[0]["decision"], "execution_authorized")
        self.assertFalse(dlv.is_v2_event(entries[0]))


class BomWiringTests(unittest.TestCase):
    def _bom_kwargs(self):
        return dict(policy_id="p1", policy_version="v1",
                    policy_digest="a" * 64,
                    evidence_head_digest="b" * 64,
                    principal={"agent_id": "a1"})

    def test_bom_binds_event(self):
        from gov import decision_bom as bom
        event, _ = _honest_event()
        b = bom.build_bom(**self._bom_kwargs(), decision_event_v2=event)
        ok, reason = bom.check_bom_shape(b)
        self.assertTrue(ok, reason)
        section = b["inputs"]["decision_event"]
        self.assertEqual(section["decision_id"], event["decision_id"])
        self.assertEqual(section["event_digest"], dlv.event_digest(event))

    def test_bom_absent_unchanged(self):
        from gov import decision_bom as bom
        b = bom.build_bom(**self._bom_kwargs())
        ok, reason = bom.check_bom_shape(b)
        self.assertTrue(ok, reason)
        self.assertNotIn("decision_event", b["inputs"])

    def test_bom_rejects_bad_event(self):
        from gov import decision_bom as bom
        event, _ = _honest_event()
        event["body"]["note"] = "tampered"
        with self.assertRaises(bom.BomError):
            bom.build_bom(**self._bom_kwargs(), decision_event_v2=event)

    def test_bom_shape_rejects_malformed_section(self):
        from gov import decision_bom as bom
        b = bom.build_bom(**self._bom_kwargs())
        b["inputs"]["decision_event"] = {"decision_id": "zz"}
        ok, _ = bom.check_bom_shape(b)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
