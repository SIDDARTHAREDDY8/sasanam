"""Unit tests for gov/policy_combine.py (wave-248 lane 6).

Covers the forbid-overrides-permit combiner: verdict rules, the
structural no-override guarantee, misuse refusals, CombinedDecision
seams, and the taxonomy pin (938 + 3 combine codes = 941; additive
only, merge coordinator recomposes).
"""

import inspect
import unittest

from gov import decision_codes
from gov import policy_combine as pc
from gov.decision_contract import Decision, Diagnostics, Request
from gov.policy import PolicyDecision, PolicyEngine

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

ACTION = {"tool": "send_email", "args": {"to": "a@example.com"}}


def _decide(yaml_text, action=ACTION):
    eng = PolicyEngine.from_text(yaml_text, source_label="<test>")
    return eng.evaluate(action, record_telemetry=False)


class TestCombineVerdicts(unittest.TestCase):
    def test_forbid_plus_permit_denies(self):
        out = pc.combine([_decide(FORBID_YAML), _decide(PERMIT_YAML)])
        self.assertEqual(out.effect, "deny")
        self.assertEqual(out.code, "combine-forbid-overrides")
        self.assertIn("deny-send", out.reason)
        self.assertEqual(out.forbid_policy_ids, ("deny-send",))
        self.assertEqual(out.permit_policy_ids, ("allow-send",))

    def test_permit_only_allows(self):
        out = pc.combine([_decide(PERMIT_YAML)])
        self.assertEqual(out.effect, "allow")
        self.assertIsNone(out.code)
        self.assertIn("allow-send", out.reason)

    def test_empty_set_default_denies(self):
        out = pc.combine([])
        self.assertEqual(out.effect, "deny")
        self.assertEqual(out.code, "combine-default-deny")

    def test_forbid_wins_regardless_of_order(self):
        a = pc.combine([_decide(PERMIT_YAML), _decide(FORBID_YAML)])
        b = pc.combine([_decide(FORBID_YAML), _decide(PERMIT_YAML)])
        self.assertEqual(a.effect, "deny")
        self.assertEqual(b.effect, "deny")
        self.assertEqual(a.reason, b.reason)
        self.assertEqual(a.code, b.code)

    def test_require_approval_without_forbid(self):
        out = pc.combine([_decide(APPROVAL_YAML), _decide(PERMIT_YAML)])
        self.assertEqual(out.effect, "require_approval")
        self.assertIsNone(out.code)

    def test_forbid_beats_require_approval(self):
        out = pc.combine([_decide(FORBID_YAML), _decide(APPROVAL_YAML)])
        self.assertEqual(out.effect, "deny")
        self.assertEqual(out.code, "combine-forbid-overrides")

    def test_multiple_forbids_all_named(self):
        f1 = _decide(FORBID_YAML)
        f2 = PolicyDecision("deny", "second forbid", policy_id="deny-two")
        out = pc.combine([f1, f2])
        self.assertEqual(out.effect, "deny")
        self.assertEqual(out.forbid_policy_ids, ("deny-send", "deny-two"))

    def test_final_effect_used_not_nominal(self):
        # A ladder-demoted verdict is treated as the verdict the
        # engine actually enforced (its final effect).
        demoted = PolicyDecision(
            "allow", "demoted by ladder", policy_id="warn-rule",
            nominal_effect="deny", mode="warn")
        out = pc.combine([demoted])
        self.assertEqual(out.effect, "allow")

    def test_contract_decision_accepted(self):
        req = Request.from_action(ACTION, None)
        contract = Decision(
            effect="deny", allowed=False, reason="contract forbid",
            policy_id="contract-pol", flag=None,
            diagnostics=Diagnostics(deciding_rule=None), request=req)
        out = pc.combine([contract, _decide(PERMIT_YAML)])
        self.assertEqual(out.effect, "deny")
        self.assertIn("contract-pol", out.reason)


class TestNoOverrideExpressible(unittest.TestCase):
    def test_combine_takes_exactly_one_parameter(self):
        sig = inspect.signature(pc.combine)
        params = list(sig.parameters.values())
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].default, inspect.Parameter.empty)

    def test_override_kwargs_refused(self):
        for kwarg in ("prefer_permit", "permit_overrides_forbid",
                      "forbid_priority", "mode", "allow_overrides",
                      "priority"):
            with self.assertRaises(TypeError, msg=kwarg):
                pc.combine([_decide(PERMIT_YAML)], **{kwarg: True})

    def test_no_override_attribute(self):
        # The module exposes no alternate combiner, no policy, no
        # mode that could weaken the rule.
        for name in ("combine_permit_first", "combine_with_priority",
                     "PERMIT_OVERRIDES", "set_forbid_priority"):
            self.assertFalse(hasattr(pc, name), name)


class TestMisuseRefused(unittest.TestCase):
    def test_non_decisions_refused(self):
        for bad in ("allow", 42, None, b"deny", 3.14):
            with self.assertRaises(pc.CombinerMisuseError, msg=repr(bad)):
                pc.combine([bad])

    def test_raw_dict_refused(self):
        with self.assertRaises(pc.CombinerMisuseError) as ctx:
            pc.combine([{"effect": "allow", "reason": "smuggled"}])
        self.assertEqual(ctx.exception.code, "combine-misuse")

    def test_string_sequence_refused(self):
        with self.assertRaises(pc.CombinerMisuseError):
            pc.combine("allow")

    def test_non_iterable_refused(self):
        with self.assertRaises(pc.CombinerMisuseError):
            pc.combine(42)

    def test_unknown_effect_refused(self):
        weird = PolicyDecision.__new__(PolicyDecision)
        weird.effect = "maybe"
        weird.reason = "hand-mutated"
        weird.policy_id = "weird"
        with self.assertRaises(pc.CombinerMisuseError):
            pc.combine([weird])

    def test_empty_reason_refused(self):
        bad = PolicyDecision("allow", "", policy_id="no-reason")
        with self.assertRaises(pc.CombinerMisuseError):
            pc.combine([bad])

    def test_misuse_is_value_error_with_code(self):
        self.assertTrue(issubclass(pc.CombinerMisuseError, ValueError))
        self.assertEqual(pc.CombinerMisuseError.code, "combine-misuse")


class TestCombinedDecision(unittest.TestCase):
    def test_to_dict_shape(self):
        out = pc.combine([_decide(FORBID_YAML), _decide(PERMIT_YAML)])
        d = out.to_dict()
        self.assertEqual(d["effect"], "deny")
        self.assertEqual(d["code"], "combine-forbid-overrides")
        self.assertEqual(d["forbid_policy_ids"], ["deny-send"])
        self.assertEqual(d["permit_policy_ids"], ["allow-send"])
        self.assertEqual(d["n_decisions"], 2)

    def test_to_policy_decision(self):
        out = pc.combine([_decide(PERMIT_YAML)])
        legacy = out.to_policy_decision()
        self.assertIsInstance(legacy, PolicyDecision)
        self.assertEqual(legacy.effect, "allow")
        self.assertEqual(legacy.policy_id, "policy_set")

    def test_deterministic(self):
        first = pc.combine([_decide(PERMIT_YAML), _decide(FORBID_YAML)])
        second = pc.combine([_decide(PERMIT_YAML), _decide(FORBID_YAML)])
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_unlabeled_policy_gets_index_label(self):
        anon = PolicyDecision("deny", "anonymous forbid")
        out = pc.combine([anon])
        self.assertEqual(out.forbid_policy_ids, ("<policy-0>",))


class TestTaxonomyPin(unittest.TestCase):
    def test_pin_941(self):
        # Wave-248 lane 6: re-pointed to 941 (938 + 3 policy-combine
        # codes: combine-default-deny, combine-forbid-overrides,
        # combine-misuse), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 2035)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.

    def test_combine_codes_shape(self):
        for code in ("combine-default-deny", "combine-forbid-overrides",
                     "combine-misuse"):
            rec = decision_codes.TAXONOMY[code]
            self.assertEqual(rec["domain"], "policy-combine")
            self.assertEqual(rec["code"], code)
            self.assertIn(rec["severity"], ("high", "medium"))

    def test_no_duplicate_keys(self):
        # TAXONOMY is a dict; assert the source has no duplicate
        # literals by re-scanning.
        import re
        with open("gov/decision_codes.py") as fh:
            src = fh.read()
        keys = re.findall(r"^    '([a-z0-9][a-z0-9\-_]*)': \{",
                          src, re.M)
        self.assertEqual(len(keys), len(set(keys)),
                         "duplicate code literals in decision_codes.py")


if __name__ == "__main__":
    unittest.main()
