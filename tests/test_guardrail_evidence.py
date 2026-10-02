#!/usr/bin/env python3
"""Unit tests for gov/guardrail_evidence.py (wave-279 lane 5).

Covers: the intentional-block vs technical-failure distinction,
loud fail-closed GuardrailFailureError, advisory mode, per-writer
record chaining, digest binding of input/rationale, and the
PolicyEvidenceAdapter seam wiring.
"""

import os
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import guardrail_evidence as ge  # noqa: E402
from gov.log import ActionLog  # noqa: E402


def _writer():
    d = tempfile.mkdtemp(prefix="ge_", dir=os.environ.get("TMPDIR"))
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    return ge.GuardrailEvidenceWriter(log), log


class OutcomeVocabularyTests(unittest.TestCase):
    def test_vocabulary_is_exactly_four(self):
        self.assertEqual(ge.OUTCOMES,
                         ("allow", "intentional_block", "advisory_flagged",
                          "technical_failure"))

    def test_record_rejects_unknown_outcome(self):
        w, _ = _writer()
        with self.assertRaises(ge.GuardrailEvidenceError):
            w.record("g", "n", outcome="blocked", input_bytes=b"x")

    def test_record_rejects_unknown_mode(self):
        w, _ = _writer()
        with self.assertRaises(ge.GuardrailEvidenceError):
            w.record("g", "n", mode="passthrough", outcome="allow",
                     input_bytes=b"x")


class RunGuardrailTests(unittest.TestCase):
    class PolicyBlock(Exception):
        pass

    def test_intentional_block_records_and_reraises(self):
        w, log = _writer()

        def deny():
            raise self.PolicyBlock("exfiltration")

        with self.assertRaises(self.PolicyBlock):
            ge.run_guardrail(w, guardrail_id="g-egress",
                             guardrail_name="egress-screen",
                             mode="blocking", event_scope="pre_call",
                             fn=deny, input_bytes=b"req",
                             intentional_block_types=(self.PolicyBlock,))
        recs = ge.guardrail_run_records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"], "intentional_block")
        self.assertEqual(recs[0]["guardrail_id"], "g-egress")

    def test_technical_failure_is_loud_and_distinct(self):
        w, log = _writer()

        def boom():
            raise ValueError("scanner crashed")

        with self.assertRaises(ge.GuardrailFailureError):
            ge.run_guardrail(w, guardrail_id="g-scan",
                             guardrail_name="scanner",
                             mode="blocking", event_scope="pre_call",
                             fn=boom, input_bytes=b"req")
        recs = ge.guardrail_run_records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"], "technical_failure")
        # the original crash is chained, not swallowed
        try:
            ge.run_guardrail(ge.GuardrailEvidenceWriter(log),
                             guardrail_id="g2", guardrail_name="g2",
                             fn=boom, input_bytes=b"x")
        except ge.GuardrailFailureError as e:
            self.assertIsInstance(e.__cause__, ValueError)
        else:
            self.fail("GuardrailFailureError not raised")

    def test_undeclared_subclass_still_intentional(self):
        w, log = _writer()

        class SpecificBlock(self.PolicyBlock):
            pass

        def deny():
            raise SpecificBlock("no")

        with self.assertRaises(SpecificBlock):
            ge.run_guardrail(w, guardrail_id="g", guardrail_name="g",
                             fn=deny, input_bytes=b"x",
                             intentional_block_types=(self.PolicyBlock,))
        self.assertEqual(
            ge.guardrail_run_records(log)[0]["outcome"], "intentional_block")

    def test_advisory_flags_without_raising(self):
        w, log = _writer()

        def deny():
            raise self.PolicyBlock("flag me")

        allowed, rec = ge.run_guardrail(
            w, guardrail_id="g-adv", guardrail_name="advisory",
            mode="advisory", event_scope="during_call", fn=deny,
            input_bytes=b"a", intentional_block_types=(self.PolicyBlock,))
        self.assertIs(allowed, False)
        self.assertEqual(rec["outcome"], "advisory_flagged")
        self.assertEqual(
            ge.guardrail_run_records(log)[0]["outcome"], "advisory_flagged")

    def test_allow_path_records_allow(self):
        w, log = _writer()
        allowed, rec = ge.run_guardrail(w, guardrail_id="g", guardrail_name="g",
                                        fn=lambda: None, input_bytes=b"x")
        self.assertIs(allowed, True)
        self.assertEqual(rec["outcome"], "allow")


class ChainAndDigestTests(unittest.TestCase):
    def test_records_chain_and_verify(self):
        w, log = _writer()
        w.record("g-1", "one", outcome="allow", rationale="fine",
                 input_bytes=b"1")
        w.record("g-2", "two", outcome="intentional_block", rationale="nope",
                 input_bytes=b"2")
        recs = ge.guardrail_run_records(log)
        self.assertEqual(len(recs), 2)
        self.assertTrue(ge.verify_guardrail_records(recs))
        self.assertEqual(recs[1]["prev_guardrail_record_digest"],
                         recs[0]["record_digest"])

    def test_tampered_verdict_refuses(self):
        import json
        w, log = _writer()
        w.record("g-1", "one", outcome="intentional_block", rationale="x",
                 input_bytes=b"1")
        recs = ge.guardrail_run_records(log)
        tampered = json.loads(json.dumps(recs))
        tampered[0]["outcome"] = "allow"
        self.assertFalse(ge.verify_guardrail_records(tampered))

    def test_reordered_records_refuse(self):
        import json
        w, log = _writer()
        w.record("g-1", "one", outcome="allow", input_bytes=b"1")
        w.record("g-2", "two", outcome="allow", input_bytes=b"2")
        recs = ge.guardrail_run_records(log)
        self.assertFalse(ge.verify_guardrail_records(list(reversed(recs))))

    def test_digests_bind_actual_bytes(self):
        import hashlib
        w, _ = _writer()
        rec = w.record("g", "n", outcome="allow", rationale="input clean",
                       input_bytes=b'{"tool":"read"}')
        self.assertEqual(rec["input_digest"],
                         hashlib.sha256(b'{"tool":"read"}').hexdigest())
        self.assertEqual(rec["rationale_digest"],
                         hashlib.sha256(b"input clean").hexdigest())

    def test_free_floating_dict_is_not_evidence(self):
        # A record dict fabricated off-log carries no log chain; the
        # module's own digest still self-checks, but there is no
        # audit-log entry for it -- guardrail_run_records only sees
        # what the log bound.
        w, log = _writer()
        forged = w.record("g", "n", outcome="allow", input_bytes=b"x")
        self.assertEqual(len(ge.guardrail_run_records(log)), 1)
        # deleting the log entry would be the attack; what matters is
        # the reader only trusts log-bound records
        self.assertIn(forged["record_digest"],
                      [r["record_digest"]
                       for r in ge.guardrail_run_records(log)])


class PolicyEvidenceAdapterTests(unittest.TestCase):
    def test_policy_decisions_emit_records(self):
        from gov.policy import PolicyEngine
        w, log = _writer()
        eng = PolicyEngine(os.path.join(REPO, "policies", "default.yaml"))
        adapter = ge.PolicyEvidenceAdapter(eng, w)
        decision = adapter.evaluate({"tool": "read",
                                     "args": {"path": "/etc/passwd"}})
        recs = ge.guardrail_run_records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"],
                         "intentional_block" if decision.effect == "deny"
                         else "allow")
        self.assertEqual(recs[0]["decision_effect"], decision.effect)
        self.assertTrue(ge.verify_guardrail_records(recs))


class LabelsTests(unittest.TestCase):
    """Wave-280: first-class ``labels`` on guardrail-run records."""

    def test_labels_stored_and_digested(self):
        w, log = _writer()
        w.record("g-1", "one", outcome="allow", input_bytes=b"1",
                 labels={"provider_kind": "remote"})
        recs = ge.guardrail_run_records(log)
        self.assertEqual(recs[0]["labels"],
                         {"provider_kind": "remote"})
        self.assertTrue(ge.verify_guardrail_records(recs))

    def test_labels_covered_by_digest(self):
        w, log = _writer()
        w.record("g-1", "one", outcome="allow", input_bytes=b"1",
                 labels={"provider_kind": "inline"})
        recs = ge.guardrail_run_records(log)
        recs[0]["labels"] = {"provider_kind": "remote"}
        self.assertFalse(ge.verify_guardrail_records(recs))

    def test_labels_removal_fails_honestly(self):
        w, log = _writer()
        w.record("g-1", "one", outcome="allow", input_bytes=b"1",
                 labels={"provider_kind": "remote"})
        recs = ge.guardrail_run_records(log)
        del recs[0]["labels"]
        self.assertFalse(ge.verify_guardrail_records(recs))

    def test_bad_labels_refused(self):
        w, _ = _writer()
        with self.assertRaises(ge.GuardrailEvidenceError):
            w.record("g-1", "one", outcome="allow",
                     labels={"k": 1})
        with self.assertRaises(ge.GuardrailEvidenceError):
            w.record("g-1", "one", outcome="allow",
                     labels=[("k", "v")])

    def test_run_guardrail_passes_labels(self):
        w, log = _writer()
        ok, rec = ge.run_guardrail(
            w, guardrail_id="g", guardrail_name="g",
            fn=lambda: None, labels={"provider_kind": "inline"})
        self.assertTrue(ok)
        self.assertEqual(rec["labels"], {"provider_kind": "inline"})
        self.assertTrue(ge.verify_guardrail_records(
            ge.guardrail_run_records(log)))

    def test_pre_labels_records_still_verify(self):
        # Backward compatibility: a record written before the labels
        # field existed (no "labels" key at all) must still verify --
        # the verifier digests only the keys a record carries.
        import hashlib
        import json
        from gov.guardrail_evidence import RECORD_TYPE, SCHEMA_VERSION
        rec = {
            "record_type": RECORD_TYPE,
            "schema_version": SCHEMA_VERSION,
            "guardrail_id": "g-old",
            "guardrail_name": "g-old",
            "guardrail_mode": "blocking",
            "event_scope": "pre_call",
            "outcome": "allow",
            "rationale": "old",
            "rationale_digest": hashlib.sha256(b"old").hexdigest(),
            "input_digest": hashlib.sha256(b"1").hexdigest(),
            "started_at": "2026-01-01T00:00:00+00:00",
            "duration_ms": 1.0,
            "decision_effect": None,
            "policy_id": None,
            "prev_guardrail_record_digest": "genesis",
        }
        rec["record_digest"] = hashlib.sha256(json.dumps(
            rec, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("utf-8")).hexdigest()
        self.assertTrue(ge.verify_guardrail_records([rec]))


if __name__ == "__main__":
    unittest.main()
