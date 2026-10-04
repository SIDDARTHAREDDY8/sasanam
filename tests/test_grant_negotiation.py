"""Unit tests for gov/grant_negotiation.py (wave-319 lane 1).

Tests the public seams only: validate_request, issue, derive, narrows,
verify, verify_chain, GrantRegistry, advisory_check, call_resource.
Deterministic: fixed `now` injected everywhere; test-local keys only.
"""
import hashlib
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import ed25519
from gov import grant_negotiation as gn

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def _kp(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.publickey(seed)
    return seed, pub, hashlib.sha256(pub).hexdigest()[:16]


OWNER_SEED, OWNER_PUB, OWNER_KID = _kp("51" * 32)
AGENT_SEED, AGENT_PUB, AGENT_KID = _kp("52" * 32)
OTHER_SEED, OTHER_PUB, OTHER_KID = _kp("53" * 32)

PUBKEYS = {OWNER_KID: OWNER_PUB, AGENT_KID: AGENT_PUB, OTHER_KID: OTHER_PUB}


def _grant(**over):
    seed = over.pop("_seed", OWNER_SEED)
    base = {
        "type": "sasanam_tool_grant",
        "tool": "send_email",
        "actions": ["send"],
        "resources": ["a@x.test"],
        "constraints": {"max_bytes": 100},
        "identifier": "u-1",
        "privileges": [],
        "issued_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=30)).isoformat(),
        "issuer": OWNER_KID,
        "audience": "agent-7",
        "parent": None,
    }
    base.update(over)
    body = {k: v for k, v in base.items() if k != "signature"}
    base["signature"] = ed25519.sign(
        seed, gn.canonical_bytes(body)).hex()
    return base


def _registry(*tools):
    reg = gn.GrantRegistry()
    for t in tools or ("send_email",):
        reg.register_tool(t, owner_key_id=OWNER_KID)
    for kid, pub in PUBKEYS.items():
        reg.register_key(kid, pub)
    return reg


class TestRequestGrammar(unittest.TestCase):
    def test_single_pair_request_ok(self):
        req = [{"type": "sasanam_tool_grant", "tool": "send_email",
                "actions": ["send"], "resources": ["a@x.test"]}]
        self.assertEqual(gn.validate_request(req), req)

    def test_length_one_resource_list_ok(self):
        req = [{"type": "sasanam_tool_grant", "tool": "send_email",
                "actions": ["send"], "resources": ["a@x.test"]}]
        self.assertEqual(gn.validate_request(req), req)

    def test_multi_resource_refused(self):
        req = [{"type": "sasanam_tool_grant", "tool": "send_email",
                "actions": ["read", "write"],
                "resources": ["contacts", "photos"]}]
        with self.assertRaises(gn.GrantProductOfFieldsError) as c:
            gn.validate_request(req)
        self.assertEqual(c.exception.code, "grantneg-product-of-fields")

    def test_list_tool_refused(self):
        req = [{"type": "sasanam_tool_grant", "tool": ["a", "b"],
                "actions": ["send"], "resources": ["a@x.test"]}]
        with self.assertRaises(gn.GrantProductOfFieldsError):
            gn.validate_request(req)

    def test_empty_request_refused(self):
        with self.assertRaises(gn.GrantMalformedError):
            gn.validate_request([])

    def test_missing_actions_refused(self):
        req = [{"type": "sasanam_tool_grant", "tool": "send_email",
                "resources": ["a@x.test"]}]
        with self.assertRaises(gn.GrantMalformedError):
            gn.validate_request(req)


class TestIssueVerify(unittest.TestCase):
    def test_validate_grant_shape_only(self):
        g = _grant()
        # Tampered after sealing: shape still valid (signature check
        # is verify()'s job, not validate_grant()'s).
        g["actions"] = ["send", "delete"]
        self.assertEqual(gn.validate_grant(g)["identifier"], "u-1")
        with self.assertRaises(gn.GrantMalformedError):
            gn.validate_grant({"type": "sasanam_tool_grant"})
        multi = _grant()
        multi["resources"] = ["a", "b"]
        with self.assertRaises(gn.GrantProductOfFieldsError):
            gn.validate_grant(multi)

    def test_issue_round_trip(self):
        g = gn.issue("send_email", ["send"], "a@x.test", OWNER_KID,
                     OWNER_SEED, "agent-7", issued_at=NOW)
        out = gn.verify(g, PUBKEYS, now=NOW)
        self.assertEqual(out["identifier"], g["identifier"])

    def test_issue_links_parent_digest(self):
        parent = gn.issue("send_email", ["send"], "a@x.test", OWNER_KID,
                          OWNER_SEED, "agent-7", issued_at=NOW)
        child = gn.issue("send_email", ["send"], "a@x.test", AGENT_KID,
                         AGENT_SEED, "agent-7", parent=parent,
                         issued_at=NOW)
        self.assertEqual(child["parent"], gn.grant_digest(parent))

    def test_issue_ttl_bound(self):
        with self.assertRaises(gn.GrantMalformedError):
            gn.issue("send_email", ["send"], "a@x.test", OWNER_KID,
                     OWNER_SEED, "agent-7", ttl_seconds=7200,
                     issued_at=NOW)

    def test_verify_tampered(self):
        g = _grant()
        g["actions"] = ["send", "delete"]
        with self.assertRaises(gn.GrantChainUnverifiableError) as c:
            gn.verify(g, PUBKEYS, now=NOW)
        self.assertEqual(c.exception.code, "grantneg-chain-unverifiable")

    def test_verify_unknown_issuer(self):
        g = _grant(issuer=OTHER_KID, _seed=OTHER_SEED)
        with self.assertRaises(gn.GrantChainUnverifiableError):
            gn.verify(g, {OWNER_KID: OWNER_PUB}, now=NOW)

    def test_verify_checks_exact_bool(self):
        # ed25519.verify returns exact True/False; a truthy-but-not-True
        # must not pass. (wave-243 lesson.)
        g = _grant()
        bad = dict(g)
        bad["signature"] = "00" * 64
        with self.assertRaises(gn.GrantChainUnverifiableError):
            gn.verify(bad, PUBKEYS, now=NOW)


class TestAttenuation(unittest.TestCase):
    def test_equal_narrows(self):
        p = _grant()
        self.assertTrue(gn.narrows(dict(p), p))

    def test_subset_actions_narrows(self):
        p = _grant(actions=["send", "delete"])
        c = _grant(actions=["send"])
        self.assertTrue(gn.narrows(c, p))
        self.assertFalse(gn.narrows(p, c))

    def test_added_constraint_narrows(self):
        p = _grant(constraints={})
        c = _grant(constraints={"max_bytes": 10})
        self.assertTrue(gn.narrows(c, p))

    def test_loosened_constraint_not_narrows(self):
        p = _grant(constraints={"max_bytes": 100})
        c = _grant(constraints={"max_bytes": 101})
        self.assertFalse(gn.narrows(c, p))

    def test_dropped_constraint_not_narrows(self):
        p = _grant(constraints={"max_bytes": 100})
        c = _grant(constraints={})
        self.assertFalse(gn.narrows(c, p))

    def test_different_resource_not_narrows(self):
        p = _grant(resources=["a@x.test"])
        c = _grant(resources=["b@x.test"])
        self.assertFalse(gn.narrows(c, p))

    def test_later_expiry_not_narrows(self):
        p = _grant()
        c = _grant(expires_at=(NOW + timedelta(minutes=31)).isoformat())
        self.assertFalse(gn.narrows(c, p))

    def test_derive_requires_strict(self):
        p = gn.issue("send_email", ["send"], "a@x.test", OWNER_KID,
                     OWNER_SEED, "agent-7", issued_at=NOW)
        with self.assertRaises(gn.GrantWideningRefusedError) as c:
            gn.derive(p, issuer_key_id=AGENT_KID, issuer_seed=AGENT_SEED)
        self.assertEqual(c.exception.code, "grantneg-widening-refused")

    def test_derive_narrowed_ok(self):
        p = gn.issue("send_email", ["send", "delete"], "a@x.test",
                     OWNER_KID, OWNER_SEED, "agent-7", issued_at=NOW)
        c = gn.derive(p, actions=["send"], issuer_key_id=AGENT_KID,
                      issuer_seed=AGENT_SEED, issued_at=NOW)
        self.assertEqual(c["parent"], gn.grant_digest(p))
        rec = gn.verify_chain([p, c], PUBKEYS, OWNER_KID, "agent-7",
                              now=NOW)
        self.assertEqual(rec["chain_length"], 2)


class TestChain(unittest.TestCase):
    def _chain(self):
        root = _grant()
        mid = _grant(parent=gn.grant_digest(root), issuer=AGENT_KID,
                     _seed=AGENT_SEED)
        return [root, mid]

    def test_good_chain(self):
        rec = gn.verify_chain(self._chain(), PUBKEYS, OWNER_KID,
                              "agent-7", now=NOW)
        self.assertEqual(rec["chain_length"], 2)
        self.assertEqual(rec["root_grant_id"], "u-1")

    def test_broken_linkage(self):
        root, mid = self._chain()
        mid["parent"] = "00" * 32
        # re-seal so the failure is linkage, not signature
        body = {k: v for k, v in mid.items() if k != "signature"}
        mid["signature"] = ed25519.sign(
            AGENT_SEED, gn.canonical_bytes(body)).hex()
        with self.assertRaises(gn.GrantChainUnverifiableError):
            gn.verify_chain([root, mid], PUBKEYS, OWNER_KID, "agent-7",
                            now=NOW)

    def test_mid_chain_start_refused(self):
        root, mid = self._chain()
        with self.assertRaises(gn.GrantMalformedError):
            gn.verify_chain([mid], PUBKEYS, OWNER_KID, "agent-7",
                            now=NOW)

    def test_empty_chain_refused(self):
        with self.assertRaises(gn.GrantMalformedError):
            gn.verify_chain([], PUBKEYS, OWNER_KID, "agent-7", now=NOW)


class TestRegistry(unittest.TestCase):
    def test_register_and_get(self):
        reg = _registry()
        self.assertEqual(reg.get("send_email")["owner_key_id"], OWNER_KID)

    def test_unregistered_none(self):
        self.assertIsNone(_registry().get("nope"))

    def test_conflicting_reregistration_loud(self):
        reg = _registry()
        with self.assertRaises(ValueError):
            reg.register_tool("send_email", owner_key_id=OTHER_KID)

    def test_idempotent_reregistration(self):
        reg = _registry()
        reg.register_tool("send_email", owner_key_id=OWNER_KID,
                          grant_types=("sasanam_tool_grant",))

    def test_advertise(self):
        doc = _registry().advertise()
        self.assertEqual(
            doc["tools"]["send_email"]
            ["authorization_details_types_supported"],
            ["sasanam_tool_grant"])

    def test_register_key_hex_and_bytes(self):
        reg = gn.GrantRegistry()
        reg.register_key("k1", OWNER_PUB)
        reg.register_key("k2", OWNER_PUB.hex())
        self.assertEqual(reg.pubkeys()["k1"], reg.pubkeys()["k2"])


class TestAdvisory(unittest.TestCase):
    def test_no_registry_not_applicable(self):
        s, _ = gn.advisory_check(None, "send_email", _grant(), "agent-7",
                                 now=NOW)
        self.assertEqual(s, "not-applicable")

    def test_unregistered_tool_not_applicable(self):
        s, _ = gn.advisory_check(_registry(), "read_file", _grant(),
                                 "agent-7", now=NOW)
        self.assertEqual(s, "not-applicable")

    def test_absent_grant(self):
        s, _ = gn.advisory_check(_registry(), "send_email", None,
                                 "agent-7", now=NOW)
        self.assertEqual(s, "absent")

    def test_verified_with_scope(self):
        g = _grant()
        s, rec = gn.advisory_check(_registry(), "send_email", g,
                                   "agent-7", args={"to": "a@x.test"},
                                   now=NOW)
        self.assertEqual(s, "verified")
        self.assertEqual(rec["chain_length"], 1)

    def test_verified_without_args_skips_resource_binding(self):
        # Unknown call shape: resource binding skipped, not failed.
        g = _grant()
        s, _ = gn.advisory_check(_registry(), "send_email", g,
                                 "agent-7", now=NOW)
        self.assertEqual(s, "verified")

    def test_scope_mismatch_tool(self):
        reg = _registry("send_email", "write_file")
        g = _grant()  # tool=send_email
        s, d = gn.advisory_check(reg, "write_file", g, "agent-7",
                                 args={"path": "a@x.test"}, now=NOW)
        self.assertEqual(s, "refused")
        self.assertEqual(d["code"], "grantneg-scope-mismatch")

    def test_scope_mismatch_resource(self):
        g = _grant()
        s, d = gn.advisory_check(_registry(), "send_email", g, "agent-7",
                                 args={"to": "b@x.test"}, now=NOW)
        self.assertEqual(s, "refused")
        self.assertEqual(d["code"], "grantneg-scope-mismatch")

    def test_unknown_tool_skips_resource_binding(self):
        # A registered tool with no known locator: binding skipped.
        reg = gn.GrantRegistry()
        reg.register_tool("mystery_tool", owner_key_id=OWNER_KID)
        for kid, pub in PUBKEYS.items():
            reg.register_key(kid, pub)
        g = _grant(tool="mystery_tool")
        s, _ = gn.advisory_check(reg, "mystery_tool", g, "agent-7",
                                 args={"weird": 1}, now=NOW)
        self.assertEqual(s, "verified")

    def test_refused_carries_code(self):
        g = _grant()
        g["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
        body = {k: v for k, v in g.items() if k != "signature"}
        g["signature"] = ed25519.sign(
            OWNER_SEED, gn.canonical_bytes(body)).hex()
        s, d = gn.advisory_check(_registry(), "send_email", g, "agent-7",
                                 args={"to": "a@x.test"}, now=NOW)
        self.assertEqual(s, "refused")
        self.assertEqual(d["code"], "grantneg-expired")

    def test_call_resource(self):
        self.assertEqual(
            gn.call_resource("send_email", {"to": "a@x.test"}), "a@x.test")
        self.assertIsNone(gn.call_resource("mystery", {"to": "x"}))
        self.assertEqual(gn.call_resource("write_file", {}), "")


class TestCodes(unittest.TestCase):
    def test_all_codes_in_taxonomy(self):
        from gov import decision_codes as dc
        for code in ("grantneg-malformed", "grantneg-product-of-fields",
                     "grantneg-widening-refused", "grantneg-expired",
                     "grantneg-chain-unverifiable", "grantneg-chain-widened",
                     "grantneg-anchor-untrusted",
                     "grantneg-audience-mismatch",
                     "grantneg-scope-mismatch"):
            self.assertIn(code, dc.TAXONOMY)

    def test_error_classes_carry_codes(self):
        cases = [
            (gn.GrantMalformedError, "grantneg-malformed"),
            (gn.GrantProductOfFieldsError, "grantneg-product-of-fields"),
            (gn.GrantWideningRefusedError, "grantneg-widening-refused"),
            (gn.GrantExpiredError, "grantneg-expired"),
            (gn.GrantChainUnverifiableError, "grantneg-chain-unverifiable"),
            (gn.GrantChainWidenedError, "grantneg-chain-widened"),
            (gn.GrantAnchorUntrustedError, "grantneg-anchor-untrusted"),
            (gn.GrantAudienceMismatchError, "grantneg-audience-mismatch"),
            (gn.GrantScopeMismatchError, "grantneg-scope-mismatch"),
        ]
        for cls, code in cases:
            self.assertEqual(cls.code, code)
            self.assertEqual(cls("x").code, code)


if __name__ == "__main__":
    unittest.main()
