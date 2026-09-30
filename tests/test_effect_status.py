#!/usr/bin/env python3
"""Unit tests for gov/effect_status.py + decision_packet rule_labels.

Wave-225 lane C: portable effect statuses and rule-labeled decision
evidence. Tests use independent spec-vector literals (not recomputed
from the implementation) so they can disagree with the code.
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import effect_status as es  # noqa: E402
from gov import decision_packet as dp  # noqa: E402
from gov import decision_bom as bom_mod  # noqa: E402
from gov import action_capsule as ac  # noqa: E402

SEED = bytes.fromhex("22" * 32)


def _bom(**over):
    kw = dict(policy_id="default", policy_version="unversioned",
              policy_digest="ab" * 32, evidence_head_digest="GENESIS",
              principal={"agent_id": None, "role": None,
                         "principal": None, "run_id": None})
    kw.update(over)
    return bom_mod.build_bom(**kw)


def _pkt_kwargs(**over):
    kw = dict(decision="allow", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              policy_id="default", policy_version="unversioned",
              issued_at="2026-09-30T00:00:00+00:00",
              bill_of_materials=_bom())
    kw.update(over)
    return kw


class Vocabulary(unittest.TestCase):
    def test_closed_vocabulary(self):
        self.assertEqual(set(es.EFFECT_STATUSES), {
            "completed", "failed", "denied",
            "cancelled-before-execution",
            "cancelled-after-possible-effect",
            "timed-out-before-effect",
            "timed-out-after-possible-effect",
            "unknown"})

    def test_terminals_pass_through(self):
        for outcome in ("completed", "failed", "denied"):
            self.assertEqual(
                es.classify({"outcome": outcome,
                             "executor_may_have_accepted": True}),
                outcome)

    def test_pre_execution_interrupts(self):
        self.assertEqual(
            es.classify({"outcome": "timed-out",
                         "executor_may_have_accepted": False}),
            "timed-out-before-effect")
        self.assertEqual(
            es.classify({"outcome": "cancelled",
                         "executor_may_have_accepted": False}),
            "cancelled-before-execution")

    def test_post_acceptance_interrupts(self):
        self.assertEqual(
            es.classify({"outcome": "timed-out",
                         "executor_may_have_accepted": True}),
            "timed-out-after-possible-effect")
        self.assertEqual(
            es.classify({"outcome": "cancelled",
                         "executor_may_have_accepted": True}),
            "cancelled-after-possible-effect")

    def test_unknown_pre_acceptance(self):
        self.assertEqual(
            es.classify({"outcome": "unknown",
                         "executor_may_have_accepted": False}),
            "unknown")

    def test_unknown_post_acceptance_refuses(self):
        with self.assertRaises(es.EffectStatusError) as ctx:
            es.classify({"outcome": "unknown",
                         "executor_may_have_accepted": True})
        self.assertEqual(ctx.exception.code,
                         "effect-status-ambiguous-refused")

    def test_malformed_refuses(self):
        for obs in ({"outcome": "vaporized",
                     "executor_may_have_accepted": False},
                    {"outcome": "timed-out",
                     "executor_may_have_accepted": "yes"},
                    {"outcome": "timed-out"},
                    "timed-out",
                    None,
                    {"outcome": "timed-out",
                     "executor_may_have_accepted": None}):
            with self.assertRaises(es.EffectStatusError) as ctx:
                es.classify(obs)
            self.assertEqual(ctx.exception.code, "effect-status-invalid",
                             "observation %r" % (obs,))


class EffectCapsules(unittest.TestCase):
    def _attempt(self):
        return {"action": "write_file",
                "params_digest": "sha256:" + "a1" * 32}

    def test_completed_capsule_seals_and_verifies(self):
        cap = es.capsule_from_effect({"attempt": self._attempt()},
                                     "completed")
        body = ac.verify_capsule(cap)
        self.assertEqual(body["effect"]["portable_status"], "completed")
        self.assertEqual(body["effect"]["status"], "admitted")
        self.assertTrue(body["effect"]["evidence"])

    def test_timeout_statuses_seal(self):
        for status in ("timed-out-before-effect",
                       "timed-out-after-possible-effect",
                       "cancelled-before-execution",
                       "cancelled-after-possible-effect",
                       "failed", "unknown"):
            cap = es.capsule_from_effect({"attempt": self._attempt()},
                                         status)
            body = ac.verify_capsule(cap)
            self.assertEqual(body["effect"]["portable_status"], status)

    def test_denied_capsule_is_refusal(self):
        cap = es.capsule_from_effect({"attempt": self._attempt()},
                                     "denied")
        body = ac.verify_capsule(cap)
        self.assertEqual(body["effect"]["status"], "refused")
        self.assertEqual(body["effect"]["portable_status"], "denied")
        self.assertTrue(body["effect"]["code"])

    def test_bad_status_refuses(self):
        with self.assertRaises(es.EffectStatusError) as ctx:
            es.capsule_from_effect({"attempt": self._attempt()},
                                   "vaporized")
        self.assertEqual(ctx.exception.code, "effect-status-invalid")

    def test_bad_verdict_record_refuses(self):
        for rec in ({"attempt": {}}, {}, "attempt", None):
            with self.assertRaises(es.EffectStatusError) as ctx:
                es.capsule_from_effect(rec, "completed")
            self.assertEqual(ctx.exception.code, "effect-status-invalid")


class RuleLabels(unittest.TestCase):
    def test_labels_embedded_and_signed(self):
        body = dp.build_decision_packet(
            **_pkt_kwargs(rule_labels={"allow-read": "p1.rule",
                                       "deny-write": "p2.rule"}))
        self.assertEqual(body["rule_labels"]["value"],
                         {"allow-read": "p1.rule",
                          "deny-write": "p2.rule"})
        self.assertEqual(body["rule_labels"]["producer"],
                         "gov/decision_packet.py")
        signed = dp.sign_packet(body, SEED)
        ok, reason = dp.verify_decision_packet(signed)
        self.assertTrue(ok, reason)

    def test_legacy_byte_identical(self):
        # rule_labels=None (default) adds no section: canonical body
        # bytes identical whether the kwarg is omitted or None.
        a = dp.build_decision_packet(**_pkt_kwargs())
        b = dp.build_decision_packet(**_pkt_kwargs(rule_labels=None))
        self.assertNotIn("rule_labels", a)
        self.assertEqual(dp.canonical_bytes(a), dp.canonical_bytes(b))

    def test_legacy_packet_verifies(self):
        signed = dp.sign_packet(dp.build_decision_packet(**_pkt_kwargs()),
                                SEED)
        ok, reason = dp.verify_decision_packet(signed)
        self.assertTrue(ok, reason)

    def test_invalid_labels_refuse(self):
        for labels in ({"": "p1.rule"},
                       {"k": "p\x01.rule"},
                       {"k\x02": "p1.rule"},
                       {"k": ""},
                       {"k": 7},
                       ["p1.rule"],
                       "p1.rule",
                       {}):
            with self.assertRaises(dp.PacketError) as ctx:
                dp.build_decision_packet(**_pkt_kwargs(rule_labels=labels))
            self.assertEqual(getattr(ctx.exception, "code", None),
                             "decision-labels-invalid",
                             "labels %r" % (labels,))

    def test_caller_dict_not_aliased(self):
        labels = {"allow-read": "p1.rule"}
        body = dp.build_decision_packet(**_pkt_kwargs(rule_labels=labels))
        labels["evil"] = "p9.rule"
        self.assertNotIn("evil", body["rule_labels"]["value"])

    def test_tampered_labels_break_signature(self):
        body = dp.build_decision_packet(
            **_pkt_kwargs(rule_labels={"allow-read": "p1.rule"}))
        signed = dp.sign_packet(body, SEED)
        forged = copy.deepcopy(signed)
        forged["rule_labels"]["value"]["allow-read"] = "p9.evil"
        ok, _reason = dp.verify_decision_packet(forged)
        self.assertFalse(ok)

    def test_malformed_section_fails_closed(self):
        # A packet carrying a malformed rule_labels section fails
        # closed even before signature checking matters: strip the
        # section's attribution from a signed packet.
        body = dp.build_decision_packet(
            **_pkt_kwargs(rule_labels={"allow-read": "p1.rule"}))
        signed = dp.sign_packet(body, SEED)
        forged = copy.deepcopy(signed)
        del forged["rule_labels"]["producer"]
        ok, reason = dp.verify_decision_packet(forged)
        self.assertFalse(ok)
        self.assertIn("producer", reason)


if __name__ == "__main__":
    unittest.main()
