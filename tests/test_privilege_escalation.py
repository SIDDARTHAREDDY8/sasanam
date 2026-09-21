"""T2 (confused deputy / missing per-call authorization), T3 (cross-agent
delegation escalation), and T11 (identity spoofing) scenarios.

CONVENTION: every attack test asserts the control the requirements demand
(R2 least-privilege identities, executor-enforced allowlists, delegation
model). On the current product code these assertions FAIL -- the failure is
the documented weakness (see tests/weaknesses-a.md). Tests must always RUN
(no import/collection errors); only assertion failures are expected.
"""

import unittest

from gov.identity import AgentIdentity
from tests.harness import make_run


class PrivilegeEscalationTests(unittest.TestCase):
    def test_support_delete_file_refused(self):
        """T2: delete_file is NOT in support's allowlist. The executor must
        refuse it before policy evaluation (no ambient authority, R2)."""
        ctx = make_run()
        ex = ctx["executor"]
        support = ctx["identities"]["support"]

        r = ex.call(support, "delete_file", path="notes.txt")
        self.assertEqual(
            r["status"],
            "denied",
            "W-A7: support executed delete_file outside its allowlist "
            "(seq %s -> %s); role allowlists not enforced in executor" % (
                r.get("seq"), r["status"]),
        )

    def test_support_write_file_refused(self):
        """T2: write_file is NOT in support's allowlist; must be refused."""
        ctx = make_run()
        ex = ctx["executor"]
        support = ctx["identities"]["support"]

        r = ex.call(support, "write_file", path="notes.txt", content="hello")
        self.assertEqual(
            r["status"],
            "denied",
            "W-A8: support executed write_file outside its allowlist "
            "(seq %s -> %s)" % (r.get("seq"), r["status"]),
        )

    def test_support_cannot_use_coder_only_api_tool(self):
        """T2 confused deputy: a low-privilege request (support) rides a
        higher-privilege tool (api_call, a coder/researcher tool) with
        crafted args. Must be denied by role-based authorization."""
        ctx = make_run()
        ex = ctx["executor"]
        support = ctx["identities"]["support"]

        r = ex.call(support, "api_call", endpoint="admin/rotate-keys",
                    params={"scope": "all"})
        self.assertEqual(
            r["status"],
            "denied",
            "W-A9: support executed coder-level api_call with crafted args "
            "(seq %s -> %s); no per-call role authorization" % (
                r.get("seq"), r["status"]),
        )

    def test_forged_admin_identity_rejected(self):
        """T11: the executor must reject identities it did not mint. A
        self-claimed role='admin' identity must not be usable."""
        ctx = make_run()
        ex = ctx["executor"]

        forged = AgentIdentity(
            agent_id="support-1",
            role="admin",
            run_id=ctx["run_dir"].name,
            principal="customer-org",
        )
        self.assertFalse(ctx["is_minted"](forged), "precondition: forged identity unminted")

        outcome = None
        try:
            r = ex.call(forged, "read_file", path="notes.txt")
            outcome = "accepted(status=%s, seq=%s)" % (r["status"], r.get("seq"))
        except Exception as e:  # noqa: BLE001 - any rejection counts
            outcome = "rejected(%s)" % type(e).__name__
        self.assertTrue(
            outcome.startswith("rejected"),
            "W-A10: executor trusted a self-claimed admin identity (%s); "
            "no executor-minted identity enforcement" % outcome,
        )

    def test_agent_cannot_impersonate_another_agent(self):
        """T11: support must not be able to act as coder-1 by forging its
        agent_id. The executor must reject unminted identities instead of
        trusting self-declared claims (here: a coder-1 identity minted for
        no run the harness knows)."""
        ctx = make_run()
        ex = ctx["executor"]

        impostor = AgentIdentity(
            agent_id="coder-1",
            role="coder",
            run_id="attacker-run-99",  # never minted by this harness
            principal="dev-org",
        )
        self.assertFalse(ctx["is_minted"](impostor), "precondition: impostor unminted")

        r = ex.call(impostor, "delete_file", path="prod.db")
        entries = ctx["read_log"]()
        attributed_to = entries[-1]["agent_id"] if entries else None
        self.assertEqual(
            r["status"],
            "denied",
            "W-A11: forged coder-1 identity executed delete_file "
            "(seq %s -> %s, log attributes it to agent_id=%r); "
            "executor trusts self-declared identities" % (
                r.get("seq"), r["status"], attributed_to),
        )

    def test_delegation_rights_intersection_enforced(self):
        """T3: no delegation model exists. support invoking 'on behalf of'
        coder-1 must NOT inherit coder's write rights; effective rights are
        the intersection (here: empty for write_file) and must be denied."""
        ctx = make_run()
        ex = ctx["executor"]
        support = ctx["identities"]["support"]

        r = ex.call(
            support,
            "write_file",
            path="deploy.sh",
            content="malicious payload",
            on_behalf_of="coder-1",
            delegated_by="coder-1",
        )
        self.assertEqual(
            r["status"],
            "denied",
            "W-A12: delegated write_file EXECUTED with ambient authority "
            "(seq %s -> %s); no delegation model, no rights intersection" % (
                r.get("seq"), r["status"]),
        )


if __name__ == "__main__":
    unittest.main()
