"""Unit tests for gov.delegation_freshness (W245-5)."""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import delegation_freshness as df  # noqa: E402
from gov import decision_codes  # noqa: E402

# Known-good literals: sha256 of json.dumps(["tool:read"],
# separators=(",", ":"), ensure_ascii=True), computed independently of
# the module and hardcoded so the test pins the canonical form.
_READ_DIGEST = ("2da1a5c80b6968edfe83fd9ea1ee00cd"
                "9abff1c8601b900c9c6a6155fe8eb0ac")
_READ_WRITE_DIGEST = ("06e419ce057d9f2d458cbffa98b974348"
                     "f1dc6ab2f185572bbe78ed72ca2a64c")

NOW = datetime(2026, 9, 30, 16, 0, 0, tzinfo=timezone.utc)


def _att(issuer="agent://planner", subject="agent://worker",
         caps=("tool:read",), issued_at=NOW, ttl=300, state_hash="AUTO"):
    if state_hash == "AUTO":
        state_hash = df.digest_capabilities(caps)
    return df.CapabilityAttestation(
        issuer=issuer, subject=subject, capabilities=caps,
        issued_at=issued_at, ttl_seconds=ttl, state_hash=state_hash)


class DigestTest(unittest.TestCase):
    def test_known_literal(self):
        # The canonical digest form is pinned: a later change to the
        # canonicalization must break this test loudly.
        self.assertEqual(df.digest_capabilities(("tool:read",)),
                         _READ_DIGEST)

    def test_order_and_duplicates_ignored(self):
        self.assertEqual(df.digest_capabilities(("tool:write", "tool:read")),
                         _READ_WRITE_DIGEST)
        self.assertEqual(df.digest_capabilities(
            ("tool:read", "tool:write", "tool:read")),
            _READ_WRITE_DIGEST)

    def test_empty_rejected(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.digest_capabilities(())
        self.assertEqual(ctx.exception.code,
                         "delegation-attestation-malformed")

    def test_non_string_entry_rejected(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.digest_capabilities(("tool:read", 42))
        self.assertEqual(ctx.exception.code,
                         "delegation-attestation-malformed")


class FreshnessTest(unittest.TestCase):
    def test_fresh_passes(self):
        self.assertTrue(df.check_fresh(_att(), NOW))

    def test_missing_ttl_is_expired(self):
        for bad in (None, 0, -5, "60", 60.0):
            with self.subTest(ttl=bad):
                with self.assertRaises(
                        df.DelegationFreshnessError) as ctx:
                    df.check_fresh(_att(ttl=bad), NOW)
                self.assertEqual(ctx.exception.code,
                                 "delegation-ttl-missing")

    def test_bool_ttl_rejected(self):
        # True == 1 in Python: a boolean TTL must not pass as ttl==1.
        for bad in (True, False):
            with self.subTest(ttl=bad):
                with self.assertRaises(
                        df.DelegationFreshnessError) as ctx:
                    df.check_fresh(_att(ttl=bad), NOW)
                self.assertEqual(ctx.exception.code,
                                 "delegation-ttl-missing")

    def test_stale_refused(self):
        a = _att(issued_at=NOW - timedelta(seconds=120), ttl=60)
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.check_fresh(a, NOW)
        self.assertEqual(ctx.exception.code, "delegation-freshness-expired")

    def test_expiry_boundary_is_expired(self):
        # now == issued_at + ttl is expired: fail closed at the boundary.
        a = _att(issued_at=NOW - timedelta(seconds=60), ttl=60)
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.check_fresh(a, NOW)
        self.assertEqual(ctx.exception.code, "delegation-freshness-expired")

    def test_just_before_expiry_passes(self):
        a = _att(issued_at=NOW - timedelta(seconds=59), ttl=60)
        self.assertTrue(df.check_fresh(a, NOW))

    def test_excessive_ttl_refused(self):
        a = _att(ttl=3600)
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.check_fresh(a, NOW, max_ttl=300)
        self.assertEqual(ctx.exception.code, "delegation-ttl-excessive")

    def test_ttl_equal_to_cap_passes(self):
        self.assertTrue(df.check_fresh(_att(ttl=300), NOW, max_ttl=300))

    def test_naive_now_refused(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.check_fresh(_att(), NOW.replace(tzinfo=None))
        self.assertEqual(ctx.exception.code,
                         "delegation-attestation-malformed")


class StateBindingTest(unittest.TestCase):
    def test_matching_binding_returns_digest(self):
        self.assertEqual(df.check_state_binding(_att()), _READ_DIGEST)

    def test_drift_refused(self):
        a = _att(state_hash="0" * 64)
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.check_state_binding(a)
        self.assertEqual(ctx.exception.code, "delegation-state-mismatch")


class HopTest(unittest.TestCase):
    def test_narrowing_hop_passes(self):
        parent = _att(issuer="agent://root", subject="agent://planner",
                      caps=("tool:*",))
        child = _att(issuer="agent://planner", subject="agent://worker",
                     caps=("tool:read", "tool:write"))
        self.assertTrue(df.check_hop(parent, child))

    def test_wildcard_star_covers_all(self):
        parent = _att(issuer="agent://root", subject="agent://planner",
                      caps=("*",))
        child = _att(issuer="agent://planner", subject="agent://worker",
                     caps=("tool:exec", "store:partition_9"))
        self.assertTrue(df.check_hop(parent, child))

    def test_widening_hop_refused(self):
        parent = _att(issuer="agent://root", subject="agent://planner",
                      caps=("tool:read",))
        child = _att(issuer="agent://planner", subject="agent://worker",
                     caps=("tool:read", "tool:exec"))
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.check_hop(parent, child)
        self.assertEqual(ctx.exception.code,
                         "delegation-monotonicity-violated")
        self.assertIn("tool:exec", ctx.exception.detail)

    def test_continuity_broken_refused(self):
        parent = _att(issuer="agent://root", subject="agent://planner",
                      caps=("tool:*",))
        child = _att(issuer="agent://stranger", subject="agent://worker",
                     caps=("tool:read",))
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.check_hop(parent, child)
        self.assertEqual(ctx.exception.code, "delegation-chain-broken")


class ChainTest(unittest.TestCase):
    def _chain(self):
        return [
            _att(issuer="agent://root", subject="agent://planner",
                 caps=("tool:*",), ttl=300),
            _att(issuer="agent://planner", subject="agent://worker",
                 caps=("tool:read", "tool:write"), ttl=200),
            _att(issuer="agent://worker", subject="agent://leaf",
                 caps=("tool:read",), ttl=100),
        ]

    def test_valid_chain_returns_records(self):
        recs = df.validate_chain(self._chain(), NOW)
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0][0], "agent://root")
        self.assertEqual(recs[2][1], "agent://leaf")
        self.assertEqual(recs[2][2], _READ_DIGEST)

    def test_empty_chain_refused(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.validate_chain([], NOW)
        self.assertEqual(ctx.exception.code, "delegation-chain-broken")

    def test_stale_middle_hop_refused(self):
        chain = self._chain()
        stale = _att(issuer="agent://planner", subject="agent://worker",
                     caps=("tool:read", "tool:write"),
                     issued_at=NOW - timedelta(seconds=300), ttl=200)
        chain[1] = stale
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.validate_chain(chain, NOW)
        self.assertEqual(ctx.exception.code, "delegation-freshness-expired")

    def test_non_attestation_refused(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.validate_chain([{"issuer": "x"}], NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-attestation-malformed")


class ShapeTest(unittest.TestCase):
    def test_naive_issued_at_refused(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            _att(issued_at=NOW.replace(tzinfo=None))
        self.assertEqual(ctx.exception.code,
                         "delegation-attestation-malformed")

    def test_iso_string_issued_at_accepted(self):
        a = _att(issued_at="2026-09-30T15:59:00Z")
        self.assertTrue(df.check_fresh(a, NOW))

    def test_string_capabilities_refused(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.CapabilityAttestation(
                issuer="agent://a", subject="agent://b",
                capabilities="tool:read", issued_at=NOW,
                ttl_seconds=60, state_hash="0" * 64)
        self.assertEqual(ctx.exception.code,
                         "delegation-attestation-malformed")

    def test_from_dict_round_trip(self):
        a = _att()
        data = {"issuer": a.issuer, "subject": a.subject,
                "capabilities": list(a.capabilities),
                "issued_at": a.issued_at.isoformat(),
                "ttl_seconds": a.ttl_seconds,
                "state_hash": a.state_hash}
        b = df.CapabilityAttestation.from_dict(data)
        self.assertTrue(df.validate_chain([b], NOW))

    def test_from_dict_missing_field_refused(self):
        with self.assertRaises(df.DelegationFreshnessError) as ctx:
            df.CapabilityAttestation.from_dict({"issuer": "agent://a"})
        self.assertEqual(ctx.exception.code,
                         "delegation-attestation-malformed")


class TaxonomyTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        for code in ("delegation-ttl-missing",
                     "delegation-freshness-expired",
                     "delegation-monotonicity-violated",
                     "delegation-state-mismatch",
                     "delegation-attestation-malformed",
                     "delegation-ttl-excessive",
                     "delegation-chain-broken"):
            with self.subTest(code=code):
                entry = decision_codes.TAXONOMY.get(code)
                self.assertIsNotNone(entry)
                self.assertEqual(entry["domain"], "delegation-freshness")


if __name__ == "__main__":
    unittest.main()
