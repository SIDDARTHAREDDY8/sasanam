"""Unit tests for gov.config_trust (W244-4)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import config_trust as ct


def _pinned(grants=None):
    grants = grants if grants is not None else [{"action": "ci:exec"}]
    return ct.pin_authority_source(
        {"verifier_policy_input": "pin:unit-v1", "grants": grants})


def _map():
    return {"anchor": "deployment-pinned", "upload": "agent-observed"}


class TestPinAuthority(unittest.TestCase):
    def test_pin_digest_deterministic(self):
        src = {"verifier_policy_input": "pin:x",
               "grants": [{"action": "a"}, {"action": "b"}]}
        a = ct.pin_authority_source(dict(src))
        b = ct.pin_authority_source(dict(src))
        self.assertEqual(a["pin_digest"], b["pin_digest"])

    def test_pin_rejects_non_dict(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.pin_authority_source("nope")
        self.assertEqual(cm.exception.code, "config-record-malformed")

    def test_pin_rejects_empty_policy_input(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.pin_authority_source(
                {"verifier_policy_input": "", "grants": []})
        self.assertEqual(cm.exception.code, "config-record-malformed")

    def test_pin_rejects_bool_minted_at(self):
        # The Python True == 1 epoch trap: a bool is not a timestamp.
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.pin_authority_source({
                "verifier_policy_input": "pin:x",
                "grants": [{"action": "a", "authority_id": "a",
                            "authority_minted_at": True}]})
        self.assertEqual(cm.exception.code, "config-record-malformed")

    def test_verify_contract_bool_return(self):
        # ct.check_privilege_claim returns a dict, never raises on allow;
        # refusal is always a ConfigTrustError with a .code.
        ok = ct.check_privilege_claim(
            {"settings": {}, "provenance": {"source_id": "upload"}},
            _pinned(), _map())
        self.assertIsInstance(ok, dict)
        self.assertEqual(ok["decision"], "allow")


class TestProvenance(unittest.TestCase):
    def test_deployment_pinned_source(self):
        cls, missing = ct.classify_provenance(
            {"provenance": {"source_id": "anchor"}}, _map())
        self.assertEqual(cls, "deployment-pinned")
        self.assertFalse(missing)

    def test_unknown_source_is_agent_observed(self):
        cls, missing = ct.classify_provenance(
            {"provenance": {"source_id": "stranger"}}, _map())
        self.assertEqual(cls, "agent-observed")
        self.assertFalse(missing)

    def test_missing_provenance_is_agent_observed(self):
        cls, missing = ct.classify_provenance({}, _map())
        self.assertEqual(cls, "agent-observed")
        self.assertTrue(missing)

    def test_self_asserted_trust_refused(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.classify_provenance(
                {"provenance": {"source_id": "upload",
                                "trusted": True}}, _map())
        self.assertEqual(cm.exception.code,
                         "config-provenance-agent-asserted")

    def test_vouched_trust_not_refused(self):
        # A deployment-vouched pin may carry trusted: true -- the vouch
        # wins, the self-assertion is moot.
        cls, _ = ct.classify_provenance(
            {"provenance": {"source_id": "anchor", "trusted": True}},
            _map())
        self.assertEqual(cls, "deployment-pinned")


class TestPrivilegeClaims(unittest.TestCase):
    def test_ungranted_role_refused(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.check_privilege_claim(
                {"settings": {"role": "admin"},
                 "provenance": {"source_id": "upload"}},
                _pinned(), _map())
        self.assertEqual(cm.exception.code,
                         "config-authority-claim-refused")

    def test_granted_action_allowed(self):
        v = ct.check_privilege_claim(
            {"settings": {"grants": ["ci:exec"]},
             "provenance": {"source_id": "upload"}}, _pinned(), _map())
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["verifier_policy_input"], "pin:unit-v1")

    def test_anchor_allowlisted_ci_path_allowed(self):
        v = ct.check_privilege_claim(
            {"settings": {"allowlisted_commands": ["/usr/bin/ci-run"]},
             "provenance": {"source_id": "anchor"}}, _pinned(), _map())
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["provenance"], "deployment-pinned")

    def test_upload_allowlisted_ci_path_refused(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.check_privilege_claim(
                {"settings": {
                    "allowlisted_commands": ["/usr/bin/ci-run"]},
                 "provenance": {"source_id": "upload"}}, _pinned(), _map())
        self.assertEqual(cm.exception.code,
                         "config-authority-claim-refused")

    def test_no_claims_no_provenance_allowed(self):
        v = ct.check_privilege_claim(
            {"settings": {"color": "blue"},
             "provenance": {"source_id": "upload"}}, _pinned(), _map())
        self.assertEqual(v["decision"], "allow")

    def test_non_privilege_keys_ignored(self):
        v = ct.check_privilege_claim(
            {"settings": {"role_note": "admin notes",
                          "description": "sudo access requested"},
             "provenance": {"source_id": "upload"}}, _pinned(), _map())
        # Closed vocabulary: substrings and near-miss keys are not
        # privilege claims.
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["matched"], [])


class TestAgentBasis(unittest.TestCase):
    def test_config_quote_refused(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.check_agent_basis(
                {"claim": "ci:exec", "basis_source": "config:repo"},
                _pinned())
        self.assertEqual(cm.exception.code,
                         "config-authority-claim-refused")

    def test_pinned_basis_granted(self):
        v = ct.check_agent_basis(
            {"claim": "ci:exec",
             "basis_source": "deployment-pinned-authority"}, _pinned())
        self.assertEqual(v["decision"], "allow")

    def test_pinned_basis_ungranted(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.check_agent_basis(
                {"claim": "root:all",
                 "basis_source": "deployment-pinned-authority"},
                _pinned())
        self.assertEqual(cm.exception.code,
                         "config-authority-claim-refused")

    def test_missing_basis_source_malformed(self):
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.check_agent_basis({"claim": "ci:exec"}, _pinned())
        self.assertEqual(cm.exception.code, "config-record-malformed")


class TestLapseCitation(unittest.TestCase):
    _Lapsed = "draft-emirdag-scitt-ai-agent-execution-00"

    def _lapsed_pinned(self, minted_at):
        return _pinned(grants=[{
            "action": "ci:exec",
            "authority_id": self._Lapsed,
            "authority_minted_at": minted_at}])

    def test_datetime_minted_at_routes_stale_authority(self):
        from datetime import datetime, timezone
        minted = datetime(2027, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.check_privilege_claim(
                {"settings": {"grants": ["ci:exec"]},
                 "provenance": {"source_id": "upload"}},
                self._lapsed_pinned(minted), _map())
        self.assertEqual(cm.exception.code, "stale-authority")

    def test_epoch_minted_at_routes_stale_authority(self):
        # stale_authority.check_authority takes a datetime, not an
        # epoch float: the module coerces numeric epochs first. This
        # pins that contract so a stale_authority signature change is
        # caught here, not silently in production.
        from datetime import datetime, timezone
        minted = datetime(2027, 1, 1, tzinfo=timezone.utc).timestamp()
        with self.assertRaises(ct.ConfigTrustError) as cm:
            ct.check_privilege_claim(
                {"settings": {"grants": ["ci:exec"]},
                 "provenance": {"source_id": "upload"}},
                self._lapsed_pinned(minted), _map())
        self.assertEqual(cm.exception.code, "stale-authority")


class TestConfigMonitor(unittest.TestCase):
    def test_first_observe_and_unchanged(self):
        mon = ct.ConfigMonitor(_map(), _pinned())
        rec = {"settings": {"grants": []},
               "provenance": {"source_id": "upload"}}
        first = mon.observe(rec)
        self.assertEqual(first["event"], "first-observed")
        again = mon.observe(dict(rec))
        self.assertEqual(again["event"], "unchanged")

    def test_rewrite_adding_privilege_refused_and_audited(self):
        mon = ct.ConfigMonitor(_map(), _pinned())
        mon.observe({"settings": {"grants": []},
                     "provenance": {"source_id": "upload"}})
        with self.assertRaises(ct.ConfigTrustError) as cm:
            mon.observe({"settings": {"grants": ["ci:exec"]},
                         "provenance": {"source_id": "upload"}})
        self.assertEqual(cm.exception.code,
                         "config-rewritten-privilege")
        events = [e["event"] for e in mon.audit_log]
        self.assertIn("rewrite-adds-privileges", events)

    def test_rewrite_without_new_privilege_allowed(self):
        mon = ct.ConfigMonitor(_map(), _pinned())
        mon.observe({"settings": {"grants": ["ci:exec"]},
                     "provenance": {"source_id": "upload"}})
        entry = mon.observe({"settings": {"grants": ["ci:exec"],
                                           "theme": "dark"},
                             "provenance": {"source_id": "upload"}})
        self.assertEqual(entry["event"], "rewrite-no-new-privileges")

    def test_audit_chain_links(self):
        mon = ct.ConfigMonitor(_map(), _pinned())
        rec = {"settings": {}, "provenance": {"source_id": "upload"}}
        first = mon.observe(rec)
        second = mon.observe(dict(rec))
        self.assertEqual(first["prev"], "genesis")
        self.assertEqual(second["prev"], first["entry_digest"])


if __name__ == "__main__":
    unittest.main()
