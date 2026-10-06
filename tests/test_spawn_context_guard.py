"""Units for gov.spawn_context_guard (W245-3).

Covers: contract pins (constants, function surface), the 5 new
taxonomy codes via code_for, and every rule's allow/refuse paths,
including the config_trust reuse contract (provenance refusal
vocabulary is shared, not re-implemented) and malformed-input traps
(bool flags, non-dict records, closed-vocabulary violations).
"""

import unittest

from gov import decision_codes as dc
from gov import spawn_context_guard as sg


BYPASS = ["--dangerously-skip-permissions"]


def _launch(context, source_id, flags):
    return {"context": context,
            "provenance": {"source_id": source_id},
            "flags": flags,
            "argv0": "claude"}


class ContractTest(unittest.TestCase):
    def test_code_constants(self):
        self.assertEqual(sg.SPAWN_CONTEXT_RECORD_MALFORMED,
                         "spawn-context-record-malformed")
        self.assertEqual(sg.TOOL_SPAWN_CONTEXT_UNTRUSTED,
                         "tool-spawn-context-untrusted")
        self.assertEqual(sg.SPAWN_CONTEXT_DECLARED_RISK,
                         "spawn-context-declared-risk")
        self.assertEqual(sg.EGRESS_DESTINATION_EXEMPTION_REFUSED,
                         "egress-destination-exemption-refused")
        self.assertEqual(sg.PERSISTENCE_MODIFICATION_REFUSED,
                         "persistence-modification-refused")

    def test_function_surface(self):
        for name in ("check_tool_launch", "check_egress_destination",
                     "check_rc_modification", "SpawnContextGuardError"):
            self.assertTrue(hasattr(sg, name), name)

    def test_error_carries_code(self):
        try:
            sg.check_tool_launch(
                ["nope"], {"user-terminal": "deployment-pinned"},
                ["user-terminal"])
        except sg.SpawnContextGuardError as exc:
            self.assertEqual(exc.code,
                             "spawn-context-record-malformed")
            self.assertIn("spawn-context-record-malformed",
                          str(exc))
        else:
            self.fail("expected SpawnContextGuardError")

    def test_all_five_codes_mapped(self):
        for code in ("spawn-context-record-malformed",
                     "tool-spawn-context-untrusted",
                     "spawn-context-declared-risk",
                     "egress-destination-exemption-refused",
                     "persistence-modification-refused"):
            self.assertIn(code, dc.TAXONOMY, code)
            self.assertEqual(dc.TAXONOMY[code]["domain"],
                             "spawn-context", code)
            self.assertEqual(dc.TAXONOMY[code]["code"], code, code)
            self.assertIsNotNone(dc.code_for(code), code)


class ToolLaunchTest(unittest.TestCase):
    def _refuse(self, rec, source_map, auth, code):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_tool_launch(rec, source_map, auth)
        self.assertEqual(ctx.exception.code, code)

    def test_postinstall_bypass_refused(self):
        self._refuse(
            _launch("postinstall", "pkg-postinstall", BYPASS),
            {"user-terminal": "deployment-pinned"}, ["user-terminal"],
            "tool-spawn-context-untrusted")

    def test_config_key_spelling_also_counts(self):
        rec = _launch("postinstall", "pkg-postinstall",
                      ["dangerously_skip_permissions"])
        self._refuse(rec, {"user-terminal": "deployment-pinned"},
                     ["user-terminal"], "tool-spawn-context-untrusted")

    def test_substring_does_not_count(self):
        # Closed vocabulary: a flag that merely mentions the bypass is
        # not a bypass flag.
        rec = _launch("postinstall", "pkg-postinstall",
                      ["--not-dangerously-skip-permissions"])
        verdict = sg.check_tool_launch(
            rec, {"user-terminal": "deployment-pinned"},
            ["user-terminal"])
        self.assertEqual(verdict["decision"], "allow")

    def test_authorized_user_invoked_is_declared_risk(self):
        rec = _launch("user-invoked", "user-terminal", BYPASS)
        verdict = sg.check_tool_launch(
            rec, {"user-terminal": "deployment-pinned"},
            ["user-terminal"])
        self.assertEqual(verdict["decision"], "declared-risk")
        self.assertEqual(verdict["code"],
                         "spawn-context-declared-risk")

    def test_vouched_but_not_authorized_refused(self):
        # Deployment-vouched context is not enough: bypass must be
        # explicitly authorized for that context.
        rec = _launch("user-invoked", "user-terminal", BYPASS)
        self._refuse(rec, {"user-terminal": "deployment-pinned"},
                     ["other-terminal"], "tool-spawn-context-untrusted")

    def test_no_bypass_flags_allow(self):
        rec = _launch("postinstall", "pkg-postinstall", ["--print"])
        verdict = sg.check_tool_launch(
            rec, {"user-terminal": "deployment-pinned"},
            ["user-terminal"])
        self.assertEqual(verdict["decision"], "allow")

    def test_unknown_context_malformed(self):
        self._refuse(_launch("systemd-service", "user-terminal", []),
                     {"user-terminal": "deployment-pinned"},
                     ["user-terminal"],
                     "spawn-context-record-malformed")

    def test_self_asserted_provenance_reuses_config_trust(self):
        rec = _launch("user-invoked", "pkg-postinstall", BYPASS)
        rec["provenance"] = {"source_id": "pkg-postinstall",
                             "trusted": True}
        self._refuse(rec, {"user-terminal": "deployment-pinned"},
                     ["user-terminal"],
                     "config-provenance-agent-asserted")

    def test_missing_provenance_reuses_config_trust(self):
        rec = {"context": "postinstall", "flags": BYPASS,
               "argv0": "claude"}
        self._refuse(rec, {"user-terminal": "deployment-pinned"},
                     ["user-terminal"], "config-provenance-untrusted")

    def test_bool_flag_malformed(self):
        rec = _launch("postinstall", "pkg-postinstall",
                      ["--print", True])
        self._refuse(rec, {"user-terminal": "deployment-pinned"},
                     ["user-terminal"],
                     "spawn-context-record-malformed")

    def test_flags_not_list_malformed(self):
        rec = _launch("postinstall", "pkg-postinstall",
                      "--dangerously-skip-permissions")
        self._refuse(rec, {"user-terminal": "deployment-pinned"},
                     ["user-terminal"],
                     "spawn-context-record-malformed")

    def test_authorized_contexts_not_collection_malformed(self):
        rec = _launch("postinstall", "pkg-postinstall", [])
        self._refuse(rec, {"user-terminal": "deployment-pinned"},
                     "user-terminal", "spawn-context-record-malformed")


class EgressDestinationTest(unittest.TestCase):
    def _dest(self, destination, owner, exempt_claim=False):
        return {"destination": destination, "owner": owner,
                "exempt_claim": exempt_claim,
                "provenance": {"source_id": "egress-review"}}

    def test_victim_owned_review_required(self):
        verdict = sg.check_egress_destination(
            self._dest("github.com/victim/private", "victim-owned"),
            ["internal.example.com"])
        self.assertEqual(verdict["decision"], "review-required")
        self.assertEqual(verdict["owner"], "victim-owned")

    def test_foreign_review_required_same_as_victim_owned(self):
        foreign = sg.check_egress_destination(
            self._dest("exfil.example.net", "foreign"),
            ["internal.example.com"])
        victim = sg.check_egress_destination(
            self._dest("github.com/victim/private", "victim-owned"),
            ["internal.example.com"])
        self.assertEqual(foreign["decision"], victim["decision"])
        self.assertEqual(foreign["decision"], "review-required")

    def test_ownership_exemption_refused(self):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_egress_destination(
                self._dest("github.com/victim/private",
                           "victim-owned", exempt_claim=True),
                ["internal.example.com"])
        self.assertEqual(ctx.exception.code,
                         "egress-destination-exemption-refused")

    def test_unvouched_pinned_claim_refused(self):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_egress_destination(
                self._dest("evil.example.com", "deployment-pinned"),
                ["internal.example.com"])
        self.assertEqual(ctx.exception.code,
                         "egress-destination-exemption-refused")

    def test_pinned_destination_exempt(self):
        verdict = sg.check_egress_destination(
            self._dest("internal.example.com/releases",
                       "deployment-pinned"),
            ["internal.example.com/releases"])
        self.assertEqual(verdict["decision"], "exempt")

    def test_non_bool_exempt_claim_malformed(self):
        rec = self._dest("github.com/victim/private", "victim-owned")
        rec["exempt_claim"] = "yes"
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_egress_destination(rec, [])
        self.assertEqual(ctx.exception.code,
                         "spawn-context-record-malformed")

    def test_unknown_owner_class_malformed(self):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_egress_destination(
                self._dest("x", "partner"), ["internal.example.com"])
        self.assertEqual(ctx.exception.code,
                         "spawn-context-record-malformed")


class RcModificationTest(unittest.TestCase):
    def _mod(self, target, writer_source_id):
        return {"target": target, "writer_source_id": writer_source_id,
                "provenance": {"source_id": writer_source_id}}

    def test_postinstall_bashrc_refused(self):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_rc_modification(
                self._mod("/home/victim/.bashrc", "pkg-postinstall"),
                ["deploy-admin"])
        self.assertEqual(ctx.exception.code,
                         "persistence-modification-refused")

    def test_etc_profile_unvouched_refused(self):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_rc_modification(
                self._mod("/etc/profile", "pkg-postinstall"),
                ["deploy-admin"])
        self.assertEqual(ctx.exception.code,
                         "persistence-modification-refused")

    def test_tilde_bashrc_basename_matches(self):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_rc_modification(
                self._mod("~/.zshrc", "pkg-postinstall"),
                ["deploy-admin"])
        self.assertEqual(ctx.exception.code,
                         "persistence-modification-refused")

    def test_admin_rc_write_allowed(self):
        verdict = sg.check_rc_modification(
            self._mod("/etc/profile", "deploy-admin"),
            ["deploy-admin"])
        self.assertEqual(verdict["decision"], "allow")

    def test_mismatched_source_id_refused(self):
        # A vouched source claiming a write for an unvouched writer is
        # still refused.
        rec = self._mod("/home/victim/.bashrc", "pkg-postinstall")
        rec["provenance"] = {"source_id": "deploy-admin"}
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_rc_modification(rec, ["deploy-admin"])
        self.assertEqual(ctx.exception.code,
                         "persistence-modification-refused")

    def test_non_rc_target_allowed(self):
        verdict = sg.check_rc_modification(
            self._mod("/tmp/notes.txt", "pkg-postinstall"),
            ["deploy-admin"])
        self.assertEqual(verdict["decision"], "allow")
        self.assertIn("not a shell-rc target", verdict["note"])

    def test_non_dict_malformed(self):
        with self.assertRaises(sg.SpawnContextGuardError) as ctx:
            sg.check_rc_modification(["nope"], ["deploy-admin"])
        self.assertEqual(ctx.exception.code,
                         "spawn-context-record-malformed")


class TaxonomyPinTest(unittest.TestCase):
    def test_pin_868(self):
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes),
        # additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2135) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*) Wave-342 lane 6: pin 2134 -> 2127.; Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
