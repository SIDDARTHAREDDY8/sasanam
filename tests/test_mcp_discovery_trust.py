"""Unit tests for gov/mcp_discovery_trust.py (W246-9).

Pins the discovery-trust contract: the discovery plane is untrusted
input; trust comes only from deployment pins; a claimed pinned
identity that does not match refuses loudly; malformed input fails
closed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import mcp_discovery_trust as mdt

PINS = {"trusted-server": "key-fp-9f2a44c1"}


def _discovery(name="trusted-server",
               endpoint="https://trusted.example/mcp",
               identity="key-fp-9f2a44c1",
               source="dns"):
    return {"name": name, "endpoint": endpoint, "identity": identity,
            "source": source}


class AcceptTest(unittest.TestCase):
    def test_pinned_identity_accepts_with_pin_verified(self):
        record = mdt.check_discovery(_discovery(), PINS)
        self.assertEqual(record["verdict"], "accept")
        self.assertEqual(record["name"], "trusted-server")
        self.assertEqual(record["identity"], "key-fp-9f2a44c1")

    def test_endpoint_change_with_matching_identity_accepts(self):
        # Endpoint is a locator, not identity.
        record = mdt.check_discovery(
            _discovery(endpoint="https://trusted-new.example/mcp"), PINS)
        self.assertEqual(record["verdict"], "accept")

    def test_source_label_recorded_not_trusted(self):
        via_dns = mdt.check_discovery(_discovery(source="dns"), PINS)
        via_manual = mdt.check_discovery(_discovery(source="manual"), PINS)
        self.assertEqual(via_dns["verdict"], via_manual["verdict"])
        self.assertEqual(via_dns["source"], "dns")


class UnpinnedTest(unittest.TestCase):
    def test_unknown_server_refused(self):
        with self.assertRaises(mdt.McpDiscoveryTrustError) as ctx:
            mdt.check_discovery(
                _discovery(name="unknown", identity="key-fp-x"), PINS)
        self.assertEqual(ctx.exception.code, "discovery-unpinned")

    def test_empty_pin_set_refuses_everything(self):
        with self.assertRaises(mdt.McpDiscoveryTrustError) as ctx:
            mdt.check_discovery(_discovery(), {})
        self.assertEqual(ctx.exception.code, "discovery-unpinned")

    def test_unpinned_refused_regardless_of_source(self):
        for source in ("dns", "manual", "operator-ui"):
            with self.assertRaises(mdt.McpDiscoveryTrustError) as ctx:
                mdt.check_discovery(
                    _discovery(name="unknown", identity="x", source=source),
                    PINS)
            self.assertEqual(ctx.exception.code, "discovery-unpinned")


class IdentityMismatchTest(unittest.TestCase):
    def test_wrong_identity_for_pinned_name_refused(self):
        with self.assertRaises(mdt.McpDiscoveryTrustError) as ctx:
            mdt.check_discovery(_discovery(identity="key-fp-ATTACKER"),
                                PINS)
        self.assertEqual(ctx.exception.code, "discovery-identity-mismatch")

    def test_forged_dns_record_never_accepted(self):
        forged = {"name": "trusted-server",
                  "endpoint": "https://attacker.invalid/mcp",
                  "identity": "key-fp-ATTACKER",
                  "source": "dns"}
        with self.assertRaises(mdt.McpDiscoveryTrustError) as ctx:
            mdt.check_discovery(forged, PINS)
        self.assertEqual(ctx.exception.code, "discovery-identity-mismatch")

    def test_error_carries_code_and_detail(self):
        try:
            mdt.check_discovery(_discovery(identity="key-fp-ATTACKER"),
                                PINS)
        except mdt.McpDiscoveryTrustError as exc:
            self.assertEqual(exc.code, "discovery-identity-mismatch")
            self.assertTrue(exc.detail)
        else:
            self.fail("no refusal")


class MalformedTest(unittest.TestCase):
    def test_malformed_shapes_refuse(self):
        cases = [
            (None, PINS),
            ("not-a-mapping", PINS),
            ({}, PINS),
            ({"name": "", "endpoint": "https://x.example",
              "identity": "k", "source": "dns"}, PINS),
            ({"name": "trusted-server", "endpoint": "https://x.example",
              "source": "dns"}, PINS),
            ({"name": "trusted-server", "endpoint": "https://x.example",
              "identity": "k", "source": None}, PINS),
            (_discovery(), None),
            (_discovery(), {"trusted-server": ""}),
            (_discovery(), {"trusted-server": 42}),
            (_discovery(), {"": "key-fp-9f2a44c1"}),
        ]
        for discovery, pins in cases:
            with self.assertRaises(mdt.McpDiscoveryTrustError) as ctx:
                mdt.check_discovery(discovery, pins)
            self.assertEqual(ctx.exception.code,
                             "discovery-result-malformed",
                             "shape %r" % (discovery,))

    def test_refusal_never_returns_verdict(self):
        # check_discovery either returns the accept record or raises;
        # it never returns a refusal-shaped dict.
        with self.assertRaises(mdt.McpDiscoveryTrustError):
            mdt.check_discovery(_discovery(name="nope", identity="x"),
                                PINS)


if __name__ == "__main__":
    unittest.main()
