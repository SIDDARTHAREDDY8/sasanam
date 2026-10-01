#!/usr/bin/env python3
"""Unit tests for gov/bundle_rsl.py (wave-271).

Pin the public contract: rule-file creation discipline, transition
authorization, prevent-time refusals, verify-time verdicts, determinism,
and the exact-bool verify contract (wave-243 lesson: never truthiness).
"""

import hashlib
import json
import os
import tempfile
import unittest

from gov import bundle_rsl
from gov import decision_codes as dc
from gov import ed25519 as _ed

TAXONOMY_PIN = 1477  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).

NOW = 1790860000
DAY = 86400


def _seed(byte):
    return bytes([byte & 0xFF]) * 32


def _pub(seed):
    return _ed.publickey(seed).hex()


def _digest(tag):
    return hashlib.sha256(b"unit:" + tag.encode()).hexdigest()


class _Fx(object):
    def __init__(self):
        self.s1, self.s2, self.s3, self.st = (_seed(1), _seed(2),
                                             _seed(3), _seed(9))
        self.principals = {"k1": {"pub": _pub(self.s1)},
                           "k2": {"pub": _pub(self.s2)},
                           "k3": {"pub": _pub(self.s3)},
                           "k-deploy": {"pub": _pub(self.st)}}
        self.delegations = [
            {"name": "releasers", "key_ids": ["k1", "k2"], "threshold": 2},
            {"name": "security", "key_ids": ["k3"], "threshold": 1},
        ]
        self.tmp = tempfile.mkdtemp(prefix="rsl-unit-")
        self.path = os.path.join(self.tmp, "rsl.jsonl")

    def wire(self, **kw):
        args = dict(rule_id="rsl-rules/skill.acme", bundle="skill.acme",
                    principals=self.principals,
                    delegations=self.delegations,
                    terminal_key_id="k-deploy", terminal_seed=self.st,
                    expires=NOW + 30 * DAY, now=NOW)
        args.update(kw)
        return bundle_rsl.make_rule_file(**args)

    def log(self, **kw):
        return bundle_rsl.open_log(self.path, self.wire(**kw), NOW)

    def genesis(self, log, tag="v1"):
        d = _digest(tag)
        log.authorize_transition("skill.acme", None, d, "releasers",
                                 [self.s1, self.s2])
        log.record_state("skill.acme", d)
        return d


class TestRuleCreation(unittest.TestCase):
    def test_threshold_gt_principals_refused_at_creation(self):
        fx = _Fx()
        bad = [{"name": "releasers", "key_ids": ["k1", "k2"],
                "threshold": 3}]
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            fx.wire(delegations=bad)
        self.assertEqual(cm.exception.code, "rsl-threshold-invalid")

    def test_threshold_zero_refused(self):
        fx = _Fx()
        bad = [{"name": "releasers", "key_ids": ["k1", "k2"],
                "threshold": 0}]
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            fx.wire(delegations=bad)
        self.assertEqual(cm.exception.code, "rsl-threshold-invalid")

    def test_unsigned_terminal_refused(self):
        fx = _Fx()
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            fx.wire(terminal_seed=None)
        self.assertEqual(cm.exception.code, "rsl-terminal-rule-unsigned")

    def test_tampered_terminal_signature_refused_at_open(self):
        fx = _Fx()
        wire = json.loads(fx.wire())
        wire["signatures"]["terminal"]["sig"] = "00" * 64
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            bundle_rsl.open_log(fx.path, json.dumps(wire), NOW)
        self.assertEqual(cm.exception.code, "rsl-terminal-rule-unsigned")

    def test_expired_rule_refused(self):
        fx = _Fx()
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            fx.wire(expires=NOW - 1)
        self.assertEqual(cm.exception.code, "rsl-rule-expired")

    def test_rule_wire_is_signed_json(self):
        fx = _Fx()
        wire = json.loads(fx.wire())
        self.assertEqual(wire["schema_version"], 1)
        self.assertIn("terminal", wire["signatures"])


class TestTransitions(unittest.TestCase):
    def test_unknown_signer_refused(self):
        fx = _Fx()
        log = fx.log()
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            log.authorize_transition("skill.acme", None, _digest("x"),
                                     "releasers", [_seed(77)])
        self.assertEqual(cm.exception.code, "rsl-transition-unauthorized")

    def test_below_threshold_refused(self):
        fx = _Fx()
        log = fx.log()
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            log.authorize_transition("skill.acme", None, _digest("x"),
                                     "releasers", [fx.s1])  # need 2
        self.assertEqual(cm.exception.code, "rsl-transition-unauthorized")

    def test_wrong_delegation_key_refused(self):
        fx = _Fx()
        log = fx.log()
        # k3 is not in the releasers delegation
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            log.authorize_transition("skill.acme", None, _digest("x"),
                                     "releasers", [fx.s1, fx.s3])
        self.assertEqual(cm.exception.code, "rsl-transition-unauthorized")

    def test_record_without_authorization_refused(self):
        fx = _Fx()
        log = fx.log()
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            log.record_state("skill.acme", _digest("rogue"))
        self.assertEqual(cm.exception.code, "rsl-transition-unauthorized")

    def test_rollback_rerecord_refused(self):
        fx = _Fx()
        log = fx.log()
        d1 = fx.genesis(log)
        d2 = _digest("v2")
        log.authorize_transition("skill.acme", d1, d2, "releasers",
                                 [fx.s1, fx.s2])
        log.record_state("skill.acme", d2)
        log.authorize_transition("skill.acme", d2, d1, "releasers",
                                 [fx.s1, fx.s2])
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            log.record_state("skill.acme", d1)
        self.assertEqual(cm.exception.code, "rsl-rollback-attempt")

    def test_duplicate_tip_is_client_bug(self):
        fx = _Fx()
        log = fx.log()
        d1 = fx.genesis(log)
        with self.assertRaises(ValueError):
            log.record_state("skill.acme", d1)


class TestVerify(unittest.TestCase):
    def test_verify_never_raises_and_exact_bool(self):
        fx = _Fx()
        log = fx.log()
        v = log.verify("skill.acme")
        self.assertIs(v["ok"], False)
        self.assertIsInstance(v["code"], str)

    def test_valid_chain_verifies(self):
        fx = _Fx()
        log = fx.log()
        d1 = fx.genesis(log)
        d2 = _digest("v2")
        log.authorize_transition("skill.acme", d1, d2, "releasers",
                                 [fx.s1, fx.s2])
        log.record_state("skill.acme", d2)
        v = log.verify("skill.acme")
        self.assertIs(v["ok"], True)
        self.assertIsNone(v["code"])
        v2 = log.verify("skill.acme", at_digest=d2)
        self.assertIs(v2["ok"], True)

    def test_ancestor_pin_is_rollback(self):
        fx = _Fx()
        log = fx.log()
        d1 = fx.genesis(log)
        d2 = _digest("v2")
        log.authorize_transition("skill.acme", d1, d2, "releasers",
                                 [fx.s1, fx.s2])
        log.record_state("skill.acme", d2)
        v = log.verify("skill.acme", at_digest=d1)
        self.assertIs(v["ok"], False)
        self.assertEqual(v["code"], "rsl-rollback-attempt")

    def test_skip_revokes(self):
        fx = _Fx()
        log = fx.log()
        fx.genesis(log)
        log.skip_annotate("skill.acme", 0, "suspect", [fx.s1])
        v = log.verify("skill.acme")
        self.assertIs(v["ok"], False)
        self.assertEqual(v["code"], "rsl-skipped-revoked")

    def test_skip_unknown_signer_refused(self):
        fx = _Fx()
        log = fx.log()
        fx.genesis(log)
        with self.assertRaises(bundle_rsl.RSLError) as cm:
            log.skip_annotate("skill.acme", 0, "x", [_seed(77)])
        self.assertEqual(cm.exception.code, "rsl-transition-unauthorized")

    def test_fork_detected_verify_time(self):
        fx = _Fx()
        log = fx.log()
        d1 = fx.genesis(log)
        from gov.durable_journal import Journal
        j = Journal(fx.path)
        mk = lambda tag: {"bundle": "skill.acme",
                          "state_digest": _digest(tag), "seq": 1,
                          "prev_digest": d1, "transition": "injected",
                          "custom_fields": {}}
        j.append("rsl-state", mk("a"))
        j.append("rsl-state", mk("b"))
        v = log.verify("skill.acme")
        self.assertIs(v["ok"], False)
        self.assertEqual(v["code"], "rsl-fork-detected")

    def test_forged_skip_dishonored(self):
        fx = _Fx()
        log = fx.log()
        fx.genesis(log)
        from gov.durable_journal import Journal
        j = Journal(fx.path)
        j.append("rsl-skip", {"bundle": "skill.acme", "target_seq": 0,
                              "target_digest": "00" * 32,
                              "reason": "forged",
                              "signatures": {"k1": "00" * 64}})
        v = log.verify("skill.acme")
        self.assertIs(v["ok"], True)  # forged skip is powerless

    def test_corrupt_journal_maps_to_code(self):
        fx = _Fx()
        log = fx.log()
        fx.genesis(log)
        with open(fx.path, "ab") as f:
            f.write(b"not-json{{{")
        v = log.verify("skill.acme")
        self.assertIs(v["ok"], False)
        self.assertEqual(v["code"], "rsl-log-corrupt")


class TestDeterminism(unittest.TestCase):
    def test_identical_scenarios_byte_identical(self):
        blobs = []
        for _ in range(2):
            fx = _Fx()
            log = fx.log()
            d1 = fx.genesis(log)
            d2 = _digest("v2")
            log.authorize_transition("skill.acme", d1, d2, "releasers",
                                     [fx.s1, fx.s2])
            log.record_state("skill.acme", d2)
            with open(fx.path, "rb") as f:
                blobs.append(f.read())
        self.assertEqual(blobs[0], blobs[1])


class TestTaxonomyPin(unittest.TestCase):
    def test_eight_codes_registered_and_pin(self):
        import re
        src = open(os.path.join(os.path.dirname(__file__), "..", "gov",
                                "decision_codes.py")).read()
        lits = re.findall(r"\"code\":\s*'([a-z][a-z0-9-_.]*)'", src)
        new = [c for c in lits if c.startswith("rsl-")]
        self.assertEqual(len(lits), len(set(lits)))
        self.assertEqual(len(new), 8)
        for c in new:
            self.assertEqual(lits.count(c), 1)
        self.assertEqual(len(dc.TAXONOMY), TAXONOMY_PIN)
        for c in new:
            self.assertIn(c, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[c]["domain"], "bundle")


if __name__ == "__main__":
    unittest.main()
