"""Units for gov.policy_delta_gate (W246-1).

Covers: contract pins (constants, function surface, the 11 new
taxonomy codes via code_for), every refusal/flag/pass path at the
analyze_policy_delta seam, determinism (sorted findings, stable
digest), and malformed-input traps.
"""

import unittest

from gov import decision_codes as dc
from gov import policy_delta_gate as pdg

BASE = """\
version: 2
roles:
  support: [read_file, send_email]
  coder: [read_file, write_file]
rate_limit:
  max_sends_per_run: 10
egress:
  domain_allowlist: [synthetic.local]
approvals:
  ttl_hours: 24
  batch_excluded_queue_reasons: [dlp, egress_violation]
  delegation:
    enabled: false
    max_hops: 1
policies:
  - id: deny-secret-reads
    effect: deny
    match:
      tool: [read_file, write_file]
      path_contains_any: [secret, credentials, token]
    reason: test fixture
  - id: deny-egress-unallowlisted
    effect: deny
    match:
      tool: [send_email]
      domain_allowlisted: false
    reason: test fixture
"""


def _swap(old, new):
    assert old in BASE
    return BASE.replace(old, new)


CODES = [
    "policy-delta-widening",
    "policy-delta-forbid-removed",
    "policy-delta-forbid-narrowed",
    "policy-delta-effect-weakened",
    "policy-delta-allow-unforbidden",
    "policy-delta-forbid-modified",
    "policy-delta-allow-modified",
    "policy-delta-check-removed",
    "policy-delta-role-added",
    "policy-delta-section-changed",
    "policy-delta-malformed",
]


class ContractTest(unittest.TestCase):
    def test_code_constants(self):
        self.assertEqual(pdg.MALFORMED, "policy-delta-malformed")
        self.assertEqual(pdg.WIDENING, "policy-delta-widening")
        self.assertEqual(pdg.FORBID_REMOVED, "policy-delta-forbid-removed")
        self.assertEqual(pdg.FORBID_NARROWED, "policy-delta-forbid-narrowed")
        self.assertEqual(pdg.EFFECT_WEAKENED, "policy-delta-effect-weakened")
        self.assertEqual(pdg.ALLOW_UNFORBIDDEN,
                         "policy-delta-allow-unforbidden")

    def test_taxonomy_codes_registered(self):
        for code in CODES:
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "policy-delta")

    def test_taxonomy_pin(self):
        # Wave-246 merge: re-pointed lane-local pin to the composed 936 (was lane-local 906); additive only.
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1706)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.

    def test_exception_carries_code(self):
        exc = pdg.PolicyDeltaError("policy-delta-malformed", "x")
        self.assertEqual(exc.code, "policy-delta-malformed")
        self.assertIn("policy-delta-malformed", str(exc))


class RefusalTest(unittest.TestCase):
    def _refuse(self, old, new):
        with self.assertRaises(pdg.PolicyDeltaError) as cm:
            pdg.check_policy_delta(old, new)
        return cm.exception

    def test_role_gains_tool(self):
        exc = self._refuse(BASE, _swap("support: [read_file, send_email]",
                                       "support: [read_file, send_email, "
                                       "api_call]"))
        self.assertEqual(exc.code, "policy-delta-widening")

    def test_forbid_removed(self):
        out, skip = [], 0
        for ln in BASE.splitlines(keepends=True):
            if skip:
                skip -= 1
                continue
            if "id: deny-secret-reads" in ln:
                skip = 5
                continue
            out.append(ln)
        exc = self._refuse(BASE, "".join(out))
        self.assertEqual(exc.code, "policy-delta-forbid-removed")

    def test_deny_to_allow_flip(self):
        exc = self._refuse(
            BASE, _swap("  - id: deny-secret-reads\n    effect: deny",
                        "  - id: deny-secret-reads\n    effect: allow"))
        self.assertEqual(exc.code, "policy-delta-effect-weakened")

    def test_deny_to_require_approval_flip(self):
        exc = self._refuse(
            BASE, _swap("  - id: deny-secret-reads\n    effect: deny",
                        "  - id: deny-secret-reads\n"
                        "    effect: require_approval"))
        self.assertEqual(exc.code, "policy-delta-effect-weakened")

    def test_forbid_narrowed(self):
        exc = self._refuse(BASE, _swap("tool: [read_file, write_file]",
                                       "tool: [read_file]"))
        self.assertEqual(exc.code, "policy-delta-forbid-narrowed")

    def test_budget_increased(self):
        exc = self._refuse(BASE, _swap("max_sends_per_run: 10",
                                       "max_sends_per_run: 20"))
        self.assertEqual(exc.code, "policy-delta-widening")

    def test_budget_removed(self):
        exc = self._refuse(BASE, _swap("  max_sends_per_run: 10\n", ""))
        self.assertEqual(exc.code, "policy-delta-widening")

    def test_egress_widened(self):
        exc = self._refuse(BASE, _swap(
            "domain_allowlist: [synthetic.local]",
            "domain_allowlist: [synthetic.local, evil.example]"))
        self.assertEqual(exc.code, "policy-delta-widening")

    def test_allow_match_widened(self):
        new = BASE + ("  - id: allow-install-guarded\n"
                      "    effect: allow\n"
                      "    match:\n"
                      "      tool: [send_email]\n"
                      "    reason: test\n")
        # widen the new allow's match: add a tool the deny does not cover
        new2 = new.replace("      tool: [send_email]\n"
                           "    reason: test",
                           "      tool: [send_email, install_package]\n"
                           "    reason: test")
        rep = pdg.analyze_policy_delta(BASE, new)
        self.assertEqual(rep["verdict"], "pass")
        rep2 = pdg.analyze_policy_delta(new, new2)
        self.assertEqual(rep2["verdict"], "refuse")
        self.assertEqual(rep2["risk_findings"][0]["risk_class"],
                         "policy-delta-widening")

    def test_delegation_enabled(self):
        exc = self._refuse(BASE, _swap("    enabled: false",
                                       "    enabled: true"))
        self.assertEqual(exc.code, "policy-delta-widening")

    def test_batch_exclusion_lost(self):
        exc = self._refuse(
            BASE, _swap("batch_excluded_queue_reasons: [dlp, egress_violation]",
                        "batch_excluded_queue_reasons: [dlp]"))
        self.assertEqual(exc.code, "policy-delta-widening")

    def test_check_policy_delta_raises_on_refuse(self):
        with self.assertRaises(pdg.PolicyDeltaError) as cm:
            pdg.check_policy_delta(
                BASE, _swap("support: [read_file, send_email]",
                            "support: [read_file, send_email, api_call]"))
        self.assertEqual(cm.exception.code, "policy-delta-widening")


class FlagTest(unittest.TestCase):
    def _pass(self, old, new):
        rep = pdg.analyze_policy_delta(old, new)
        self.assertEqual(rep["verdict"], "pass", rep)
        return rep

    def _codes(self, rep):
        return [f["risk_class"] for f in rep["risk_findings"]]

    def test_allow_without_forbid_flagged(self):
        new = BASE + ("  - id: allow-install\n"
                      "    effect: allow\n"
                      "    match:\n"
                      "      tool: [install_package]\n"
                      "    reason: test\n")
        rep = self._pass(BASE, new)
        self.assertIn("policy-delta-allow-unforbidden", self._codes(rep))

    def test_new_role_flagged(self):
        new = _swap("  coder: [read_file, write_file]",
                    "  coder: [read_file, write_file]\n"
                    "  auditor: [read_file, api_call]")
        rep = self._pass(BASE, new)
        self.assertIn("policy-delta-role-added", self._codes(rep))

    def test_check_removed_flagged(self):
        base2 = BASE + ("  - id: review-large-writes\n"
                        "    effect: require_approval\n"
                        "    match:\n"
                        "      tool: [write_file]\n"
                        "    reason: test\n")
        out, skip = [], 0
        for ln in base2.splitlines(keepends=True):
            if skip:
                skip -= 1
                continue
            if "id: review-large-writes" in ln:
                skip = 4
                continue
            out.append(ln)
        rep = self._pass(base2, "".join(out))
        self.assertIn("policy-delta-check-removed", self._codes(rep))

    def test_forbid_match_unprovable_change_flagged(self):
        # change a scalar match key on a deny rule: direction unprovable
        new = _swap("      domain_allowlisted: false",
                    "      domain_allowlisted: true")
        rep = self._pass(BASE, new)
        self.assertIn("policy-delta-forbid-modified", self._codes(rep))

    def test_unknown_section_flagged(self):
        new = BASE + "custom_section:\n  key: value\n"
        rep = self._pass(BASE, new)
        self.assertIn("policy-delta-section-changed", self._codes(rep))


class PassTest(unittest.TestCase):
    def _pass_clean(self, old, new):
        rep = pdg.analyze_policy_delta(old, new)
        self.assertEqual(rep["verdict"], "pass", rep)
        self.assertEqual(rep["risk_findings"], [], rep)
        return rep

    def test_noop(self):
        new = "# comment\n" + BASE.replace("version: 2",
                                           "version: 2  # c")
        self._pass_clean(BASE, new)

    def test_tighten_role(self):
        self._pass_clean(BASE, _swap("support: [read_file, send_email]",
                                     "support: [read_file]"))

    def test_new_deny_rule(self):
        new = BASE + ("  - id: deny-new\n"
                      "    effect: deny\n"
                      "    match:\n"
                      "      tool: [http_post]\n"
                      "    reason: test\n")
        self._pass_clean(BASE, new)

    def test_allow_with_forbid(self):
        new = BASE + ("  - id: allow-support-email\n"
                      "    effect: allow\n"
                      "    match:\n"
                      "      tool: [send_email]\n"
                      "      domain_allowlisted: true\n"
                      "    reason: test\n")
        self._pass_clean(BASE, new)

    def test_allow_to_deny_flip(self):
        base2 = BASE + ("  - id: allow-tmp\n"
                        "    effect: allow\n"
                        "    match:\n"
                        "      tool: [api_call]\n"
                        "    reason: test\n")
        new2 = base2.replace("  - id: allow-tmp\n    effect: allow",
                             "  - id: allow-tmp\n    effect: deny")
        self._pass_clean(base2, new2)

    def test_budget_decreased(self):
        self._pass_clean(BASE, _swap("max_sends_per_run: 10",
                                     "max_sends_per_run: 5"))

    def test_egress_shrunk(self):
        base2 = _swap("domain_allowlist: [synthetic.local]",
                      "domain_allowlist: [synthetic.local, old.example]")
        self._pass_clean(base2, BASE)

    def test_forbid_match_widened(self):
        self._pass_clean(BASE, _swap("tool: [read_file, write_file]",
                                     "tool: [read_file, write_file, "
                                     "delete_file]"))

    def test_allow_match_narrowed(self):
        base3 = BASE + ("  - id: allow-wide\n"
                        "    effect: allow\n"
                        "    match:\n"
                        "      tool: [send_email]\n"
                        "      domain_allowlisted: true\n"
                        "    reason: test\n")
        self._pass_clean(base3, base3)

    def test_check_policy_delta_returns_report(self):
        rep = pdg.check_policy_delta(BASE, BASE)
        self.assertEqual(rep["verdict"], "pass")


class DeterminismTest(unittest.TestCase):
    def test_stable_digest_and_order(self):
        new = _swap("support: [read_file, send_email]",
                    "support: [read_file, send_email, api_call]")
        r1 = pdg.analyze_policy_delta(BASE, new)
        r2 = pdg.analyze_policy_delta(BASE, new)
        self.assertEqual(r1["delta_digest"], r2["delta_digest"])
        self.assertEqual(r1["risk_findings"], r2["risk_findings"])
        # findings sorted by (severity, section, rule, class)
        keys = [(f["severity"], f["section"], f["rule_id"] or "",
                 f["risk_class"]) for f in r1["risk_findings"]]
        self.assertEqual(keys, sorted(
            keys, key=lambda k: ({"high": 0, "medium": 1, "low": 2}[k[0]],
                                 k[1], k[2], k[3])))

    def test_old_new_digests(self):
        rep = pdg.analyze_policy_delta(BASE, BASE)
        self.assertEqual(len(rep["old_digest"]), 64)
        self.assertEqual(rep["old_digest"], rep["new_digest"])


class MalformedTest(unittest.TestCase):
    def _malformed(self, old, new):
        with self.assertRaises(pdg.PolicyDeltaError) as cm:
            pdg.analyze_policy_delta(old, new)
        self.assertEqual(cm.exception.code, "policy-delta-malformed")

    def test_unparseable_new(self):
        self._malformed(BASE, ":\n: bad")

    def test_unparseable_old(self):
        self._malformed(":\n: bad", BASE)

    def test_non_mapping_old(self):
        self._malformed(["not", "a", "mapping"], BASE)

    def test_non_string_input(self):
        self._malformed(None, BASE)

    def test_duplicate_rule_ids(self):
        self._malformed(
            BASE, BASE.replace("id: deny-egress-unallowlisted",
                               "id: deny-secret-reads"))

    def test_unknown_effect(self):
        new = _swap("  - id: deny-egress-unallowlisted\n    effect: deny",
                    "  - id: deny-egress-unallowlisted\n"
                    "    effect: quarantine")
        self._malformed(BASE, new)

    def test_rule_not_mapping(self):
        new = BASE.replace("  - id: deny-secret-reads",
                           "  - just-a-string")
        self._malformed(BASE, new)

    def test_match_not_mapping(self):
        new = _swap("    match:\n      tool: [send_email]",
                    "    match: not-a-mapping\n")
        self._malformed(BASE, new)


if __name__ == "__main__":
    unittest.main()
