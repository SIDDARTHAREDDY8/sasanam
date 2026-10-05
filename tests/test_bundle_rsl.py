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

TAXONOMY_PIN = 2128 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


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
