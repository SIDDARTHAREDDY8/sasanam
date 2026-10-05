"""Unit tests for gov/policy_harness (wave-251 lane 2).

The fixture-driven policy test harness: run_harness() evaluates every
fixture against every policy and combines via policy_combine; the
forbid-overrides guarantee is exercised through the full path.
diff_policies() is the policy-delta primitive.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes
from gov import policy_harness as ph


PERMIT_YAML = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
"""

FORBID_YAML = """\
version: "1"
policies:
  - id: deny-send
    effect: deny
    match:
      tool: send_email
"""

APPROVAL_YAML = """\
version: "1"
policies:
  - id: approval-send
    effect: require_approval
    match:
      tool: send_email
"""


def _write(root, policies, fixtures, expected):
    for name, text in policies.items():
        with open(os.path.join(root, "policies", name), "w",
                  encoding="utf-8") as fh:
            fh.write(text)
    for name, obj in fixtures.items():
        with open(os.path.join(root, "fixtures", name), "w",
                  encoding="utf-8") as fh:
            json.dump(obj, fh, sort_keys=True)
    for name, obj in expected.items():
        with open(os.path.join(root, "expected", name), "w",
                  encoding="utf-8") as fh:
            json.dump(obj, fh, sort_keys=True)


class HarnessTestBase:
    """Plain mixin (not a TestCase) providing a harness scratch dir."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="harness-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for sub in ("policies", "fixtures", "expected"):
            os.makedirs(os.path.join(self.tmp, sub))

    def make(self, policies, fixtures, expected):
        _write(self.tmp, policies, fixtures, expected)
        return self.tmp


SEND = {"action": {"tool": "send_email", "args": {"to": "a@x.com"}}}


class TestRunHarness(HarnessTestBase, unittest.TestCase):
    def setUp(self):
        HarnessTestBase.setUp(self)

    def test_permit_only_passes(self):
        root = self.make({"p.yaml": PERMIT_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "allow"}})
        rep = ph.run_harness(root)
        self.assertEqual((rep.passed, rep.failed, rep.total), (1, 0, 1))
        self.assertEqual(rep.results[0].actual_effect, "allow")

    def test_forbid_overrides_permit_through_harness(self):
        root = self.make({"a.yaml": PERMIT_YAML, "b.yaml": FORBID_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "deny",
                                     "code": "combine-forbid-overrides"}})
        rep = ph.run_harness(root)
        self.assertEqual((rep.passed, rep.failed, rep.total), (1, 0, 1))
        self.assertEqual(rep.results[0].actual_code,
                         "combine-forbid-overrides")

    def test_require_approval_passes(self):
        root = self.make({"a.yaml": APPROVAL_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "require_approval"}})
        rep = ph.run_harness(root)
        self.assertEqual(rep.passed, 1)
        self.assertIsNone(rep.results[0].actual_code)

    def test_mismatch_fails_with_diff(self):
        root = self.make({"p.yaml": FORBID_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "allow"}})
        rep = ph.run_harness(root)
        self.assertEqual((rep.passed, rep.failed), (0, 1))
        fx = rep.results[0]
        self.assertFalse(fx.passed)
        self.assertIn("effect", fx.diff)
        self.assertIn("'deny'", fx.diff)

    def test_code_mismatch_fails(self):
        root = self.make({"p.yaml": PERMIT_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "allow",
                                     "code": "combine-forbid-overrides"}})
        rep = ph.run_harness(root)
        self.assertEqual(rep.failed, 1)
        self.assertIn("code", rep.results[0].diff)

    def test_report_json_is_canonical(self):
        root = self.make({"p.yaml": PERMIT_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "allow"}})
        j1 = ph.run_harness(root).to_json()
        j2 = ph.run_harness(root).to_json()
        self.assertEqual(j1, j2)
        # canonical form: no spaces after separators
        self.assertNotIn('": ', j1)

    def test_context_is_used(self):
        # A fixture with a context dict must reach the engine.
        root = self.make({"p.yaml": PERMIT_YAML},
                         {"f.json": {"action": SEND["action"],
                                     "context": {"env": "test"}}},
                         {"f.json": {"effect": "allow"}})
        rep = ph.run_harness(root)
        self.assertEqual(rep.passed, 1)


class TestFailClosed(HarnessTestBase, unittest.TestCase):
    def setUp(self):
        HarnessTestBase.setUp(self)

    def _expect_code(self, fn, code):
        with self.assertRaises(ph.HarnessError) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)
        self.assertTrue(str(ctx.exception).startswith(code + ":"))
        return ctx.exception

    def test_malformed_fixture_json(self):
        self.make({"p.yaml": PERMIT_YAML}, {}, {})
        with open(os.path.join(self.tmp, "fixtures", "f.json"), "w") as fh:
            fh.write("{bad")
        with open(os.path.join(self.tmp, "expected", "f.json"),
                  "w") as fh:
            json.dump({"effect": "allow"}, fh)
        self._expect_code(lambda: ph.run_harness(self.tmp),
                          "policy-harness-malformed")

    def test_missing_expected(self):
        self.make({"p.yaml": PERMIT_YAML},
                  {"f.json": SEND}, {})
        self._expect_code(lambda: ph.run_harness(self.tmp),
                          "policy-harness-missing-expected")

    def test_no_policies(self):
        self.make({}, {"f.json": SEND},
                  {"f.json": {"effect": "allow"}})
        self._expect_code(lambda: ph.run_harness(self.tmp),
                          "policy-harness-no-policies")

    def test_unknown_policy_format(self):
        self.make({"p.txt": PERMIT_YAML},
                  {"f.json": SEND},
                  {"f.json": {"effect": "allow"}})
        self._expect_code(lambda: ph.run_harness(self.tmp),
                          "policy-harness-unknown-format")

    def test_bad_expected_effect(self):
        self.make({"p.yaml": PERMIT_YAML},
                  {"f.json": SEND},
                  {"f.json": {"effect": "maybe"}})
        self._expect_code(lambda: ph.run_harness(self.tmp),
                          "policy-harness-malformed")

    def test_fixture_without_action(self):
        self.make({"p.yaml": PERMIT_YAML},
                  {"f.json": {"context": {}}},
                  {"f.json": {"effect": "allow"}})
        self._expect_code(lambda: ph.run_harness(self.tmp),
                          "policy-harness-malformed")

    def test_malformed_policy_yaml(self):
        # The engine refuses unknown top-level keys fail-closed
        # (F90); the harness must surface that as malformed, not skip.
        self.make({"p.yaml": "version: \"1\"\nbugets: {}\n"},
                  {"f.json": SEND},
                  {"f.json": {"effect": "allow"}})
        self._expect_code(lambda: ph.run_harness(self.tmp),
                          "policy-harness-malformed")


class TestDiffPolicies(HarnessTestBase, unittest.TestCase):
    def setUp(self):
        HarnessTestBase.setUp(self)

    def _two_dirs(self, old_policies, new_policies):
        old = os.path.join(self.tmp, "old")
        new = os.path.join(self.tmp, "new")
        for d in (old, new):
            for sub in ("policies", "fixtures", "expected"):
                os.makedirs(os.path.join(d, sub))
        _write(old, old_policies, {"f.json": SEND},
               {"f.json": {"effect": "allow"}})
        _write(new, new_policies, {}, {})
        return old, new

    def test_flip_allow_to_deny(self):
        old, new = self._two_dirs({"p.yaml": PERMIT_YAML},
                                  {"p.yaml": PERMIT_YAML,
                                   "q.yaml": FORBID_YAML})
        delta = ph.diff_policies(old, new)
        self.assertEqual(delta.changed, 1)
        self.assertEqual(delta.new_denials, 1)
        self.assertEqual(delta.new_allows, 0)
        flip = delta.flips[0]
        self.assertEqual(flip["fixture"], "f.json")
        self.assertEqual((flip["old"], flip["new"]), ("allow", "deny"))

    def test_no_change(self):
        old, new = self._two_dirs({"p.yaml": PERMIT_YAML},
                                  {"p.yaml": PERMIT_YAML})
        delta = ph.diff_policies(old, new)
        self.assertEqual(delta.changed, 0)
        self.assertEqual(delta.new_denials, 0)

    def test_regression_detected(self):
        # Old set satisfied expected; new set breaks it.
        old, new = self._two_dirs({"p.yaml": PERMIT_YAML},
                                  {"p.yaml": FORBID_YAML})
        delta = ph.diff_policies(old, new)
        self.assertEqual(list(delta.regressions), ["f.json"])

    def test_delta_json_canonical(self):
        old, new = self._two_dirs({"p.yaml": PERMIT_YAML},
                                  {"p.yaml": PERMIT_YAML})
        self.assertEqual(ph.diff_policies(old, new).to_json(),
                         ph.diff_policies(old, new).to_json())


class TestMain(HarnessTestBase, unittest.TestCase):
    def setUp(self):
        HarnessTestBase.setUp(self)

    def test_main_exit_zero_on_pass(self):
        root = self.make({"p.yaml": PERMIT_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "allow"}})
        self.assertEqual(ph.main([root]), 0)

    def test_main_exit_one_on_fail(self):
        root = self.make({"p.yaml": FORBID_YAML},
                         {"f.json": SEND},
                         {"f.json": {"effect": "allow"}})
        self.assertEqual(ph.main([root]), 1)

    def test_main_exit_two_on_harness_error(self):
        root = self.make({}, {"f.json": SEND},
                         {"f.json": {"effect": "allow"}})
        self.assertEqual(ph.main([root]), 2)


class TestTaxonomyPin(unittest.TestCase):
    def test_pin_1001(self):
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 2069)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-251 lane 2: re-pointed to 1001 (997 + 4 policy-harness
        # codes), additive only.
        for code in ("policy-harness-malformed",
                     "policy-harness-missing-expected",
                     "policy-harness-no-policies",
                     "policy-harness-unknown-format"):
            rec = decision_codes.TAXONOMY[code]
            self.assertEqual(rec["domain"], "policy-harness")


if __name__ == "__main__":
    unittest.main()
