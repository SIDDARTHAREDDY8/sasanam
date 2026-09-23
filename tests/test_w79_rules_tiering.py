"""Wave-79: lethal-trifecta tiering as a policy primitive.

Covers gov/rules_tiering.py (classification, tier computation,
composition over effective grants, the approval floor) and the
executor wiring (escalation record, floor override, cross-hop
composition).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gov import rules_tiering as rt
from gov.policy import KNOWN_TOOLS
from harness import make_run, plant_file


class TestClassification(unittest.TestCase):
    def test_closed_universe_every_known_tool_classified(self):
        self.assertEqual(set(rt.TOOL_AXES), set(KNOWN_TOOLS))

    def test_api_call_alone_is_the_trifecta(self):
        # The honest headline: an agent with api_call holds private
        # data + untrusted content + external comm in one tool.
        self.assertEqual(rt.axes_of("api_call"),
                         frozenset(rt.AXES))

    def test_read_file_is_two_axes_not_external(self):
        self.assertEqual(rt.axes_of("read_file"),
                         frozenset({"private_data", "untrusted_content"}))

    def test_local_mutation_tools_hold_no_axis(self):
        self.assertEqual(rt.axes_of("write_file"), frozenset())
        self.assertEqual(rt.axes_of("delete_file"), frozenset())

    def test_sends_are_external_only(self):
        self.assertEqual(rt.axes_of("http_post"),
                         frozenset({"external_comm"}))
        self.assertEqual(rt.axes_of("send_email"),
                         frozenset({"external_comm"}))

    def test_install_is_untrusted_plus_external(self):
        self.assertEqual(rt.axes_of("install_package"),
                         frozenset({"untrusted_content", "external_comm"}))

    def test_unknown_tool_fails_closed(self):
        with self.assertRaises(rt.TieringError):
            rt.axes_of("exfiltrate_everything")

    def test_unknown_axis_fails_closed(self):
        with self.assertRaises(rt.TieringError):
            rt.tool_carries_axis("api_call", "mind_reading")


class TestTierComputation(unittest.TestCase):
    def test_two_axes_is_standard(self):
        tier, axes = rt.session_tier(["read_file", "write_file"])
        self.assertEqual(tier, rt.TIER_STANDARD)
        self.assertEqual(axes, frozenset({"private_data",
                                          "untrusted_content"}))

    def test_three_axes_is_elevated(self):
        tier, axes = rt.session_tier(["read_file", "send_email"])
        self.assertEqual(tier, rt.TIER_ELEVATED)
        self.assertTrue(frozenset(rt.AXES) <= axes)

    def test_single_tool_trifecta_elevates(self):
        self.assertTrue(rt.is_trifecta(["api_call"]))

    def test_empty_grants_standard(self):
        self.assertEqual(rt.session_tier([])[0], rt.TIER_STANDARD)

    def test_role_tiers_fall_out_of_registry(self):
        # coder/researcher/scout/publisher elevate; triage/builder do not.
        self.assertTrue(rt.is_trifecta(
            ["read_file", "write_file", "delete_file", "api_call",
             "install_package"]))
        self.assertTrue(rt.is_trifecta(["read_file", "api_call"]))
        self.assertTrue(rt.is_trifecta(
            ["read_file", "http_post", "send_email"]))
        self.assertFalse(rt.is_trifecta(["read_file", "write_file"]))
        self.assertFalse(rt.is_trifecta(
            ["read_file", "write_file", "delete_file"]))


class TestComposition(unittest.TestCase):
    def test_effective_grants_union(self):
        grants = rt.effective_grants(
            role_tools=["read_file", "write_file"],
            delegation_scope=["send_email"],
            lease_scope=[])
        self.assertEqual(grants,
                         frozenset({"read_file", "write_file",
                                    "send_email"}))

    def test_composition_trips_tier(self):
        # Parent holds two axes; the composed union adds the third.
        # This is the cross-hop shape: attenuation untouched, the tier
        # composes over effective grants.
        parent = rt.effective_grants(role_tools=["read_file",
                                                 "write_file"])
        self.assertEqual(rt.session_tier(parent)[0], rt.TIER_STANDARD)
        composed = rt.effective_grants(
            role_tools=["read_file", "write_file"],
            delegation_scope=["http_post"])
        self.assertEqual(rt.session_tier(composed)[0], rt.TIER_ELEVATED)

    def test_effective_grants_unknown_tool_fails_closed(self):
        # A dropped tool would UNDERSTATE the tier — refuse instead.
        with self.assertRaises(rt.TieringError):
            rt.effective_grants(role_tools=["read_file", "mystery_tool"])


class TestFloor(unittest.TestCase):
    def test_floor_bites_on_allow_elevated_external(self):
        self.assertTrue(rt.floor_applies(["read_file", "api_call"],
                                         "api_call", "allow"))

    def test_floor_does_not_override_deny(self):
        self.assertFalse(rt.floor_applies(["read_file", "api_call"],
                                          "api_call", "deny"))

    def test_floor_does_not_double_queue(self):
        self.assertFalse(rt.floor_applies(["read_file", "api_call"],
                                          "api_call", "require_approval"))

    def test_floor_ignores_non_external_tools(self):
        self.assertFalse(rt.floor_applies(["read_file", "api_call"],
                                          "read_file", "allow"))

    def test_floor_ignores_standard_tier(self):
        self.assertFalse(rt.floor_applies(["read_file", "write_file"],
                                          "send_email", "allow"))


class TestExecutorWiring(unittest.TestCase):
    def test_elevated_session_external_call_queued_by_floor(self):
        ctx = make_run(trifecta_floor=True)
        ident = ctx["mint_identity"]("coder-9", "coder", "dev-org")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/v1/data", params={})
        self.assertEqual(r["status"], "queued")
        entries = ctx["read_log"]()
        queued = [e for e in entries
                  if e.get("decision") == "queued_pending"]
        self.assertTrue(queued)
        q = queued[-1]
        self.assertEqual(q["flag"], "trifecta_floor")
        self.assertIn("allow-api", q["matched_rules"])
        self.assertIn(rt.TRIFECTA_FLOOR_SENTINEL, q["matched_rules"])
        self.assertEqual(q["policy_version"], "2")

    def test_standard_session_allow_executes(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("triage-9", "triage", "ops-org")
        plant_file(ctx, "data/n.txt", "hello")
        r = ctx["executor"].call(ident, "read_file", path="data/n.txt")
        self.assertEqual(r["status"], "executed")

    def test_escalation_record_chained_once(self):
        ctx = make_run(trifecta_floor=True)
        ident = ctx["mint_identity"]("coder-9", "coder", "dev-org")
        ctx["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/v1/a", params={})
        ctx["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/v1/b", params={})
        entries = ctx["read_log"]()
        esc = [e for e in entries
               if e.get("decision") == "tier_escalated"]
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0]["tier"], "elevated")
        self.assertEqual(sorted(esc[0]["tier_axes"]), sorted(rt.AXES))
        # Totality: the escalation record is a decision record.
        self.assertEqual(esc[0]["policy_version"], "2")
        self.assertEqual(esc[0]["matched_rules"], [])

    def test_floor_does_not_override_policy_deny(self):
        ctx = make_run(trifecta_floor=True)
        ident = ctx["mint_identity"]("coder-9", "coder", "dev-org")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://evil.example/v1/data", params={})
        self.assertEqual(r["status"], "denied")
        entries = ctx["read_log"]()
        denied = [e for e in entries if e.get("decision") == "denied"]
        self.assertTrue(denied)
        self.assertEqual(denied[-1]["policy_id"],
                         "deny-egress-unallowlisted")

    def test_cross_hop_composition_trips_floor(self):
        # Parent-shaped session (triage: two axes) never elevates on
        # its own tools; the child-shaped session (researcher role
        # adds the third axis) trips the floor at its first external
        # call. Attenuation is untouched — the tier composes over
        # effective grants, not token scopes.
        ctx = make_run(trifecta_floor=True)
        parent = ctx["mint_identity"]("parent-1", "triage", "ops-org")
        plant_file(ctx, "data/n.txt", "hello")
        r = ctx["executor"].call(parent, "read_file", path="data/n.txt")
        self.assertEqual(r["status"], "executed")
        entries = ctx["read_log"]()
        self.assertFalse([e for e in entries
                          if e.get("decision") == "tier_escalated"])
        child = ctx["mint_identity"]("child-1", "researcher", "ops-org")
        r = ctx["executor"].call(
            child, "api_call",
            endpoint="https://synthetic.local/v1/data", params={})
        self.assertEqual(r["status"], "queued")
        entries = ctx["read_log"]()
        queued = [e for e in entries
                  if e.get("decision") == "queued_pending"]
        self.assertEqual(queued[-1]["flag"], "trifecta_floor")

    def test_floor_off_by_default(self):
        # The trifecta floor is an explicit deployment opt-in: with
        # the default (off), an elevated session's allowlisted
        # api_call executes exactly as the policy allows — zero
        # behavior change, no tier record chained.
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-9", "coder", "dev-org")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/v1/data", params={})
        self.assertEqual(r["status"], "executed")
        entries = ctx["read_log"]()
        self.assertFalse([e for e in entries
                          if e.get("decision") == "tier_escalated"])
        self.assertFalse([e for e in entries
                          if e.get("flag") == "trifecta_floor"])

    def test_non_external_tool_unaffected_in_elevated_session(self):
        ctx = make_run(trifecta_floor=True)
        ident = ctx["mint_identity"]("coder-9", "coder", "dev-org")
        plant_file(ctx, "data/n.txt", "hello")
        r = ctx["executor"].call(ident, "read_file", path="data/n.txt")
        self.assertEqual(r["status"], "executed")


if __name__ == "__main__":
    unittest.main()
