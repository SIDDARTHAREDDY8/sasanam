#!/usr/bin/env python3
"""Unit tests for gov/permit_leases.py — one-use, mission-bound ARAP
permit leases (wave-220 lane B)."""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import arap  # noqa: E402
from gov import permit_leases as pl  # noqa: E402
from gov import policy_compile as pc  # noqa: E402

NOW = 1785000000
KEY = b"w220-unit-test-key-0123456789abcdef"
CTX = {"amount": 100, "currency": "USD"}


def _req(**kw):
    args = dict(request_id="r1", subject="alice", resource="doc/1",
                action="read", context=dict(CTX), key=KEY)
    args.update(kw)
    return arap.new_request(**args)


def _reg(**kw):
    kw.setdefault("now", lambda: NOW)
    return pl.PermitRegistry(**kw)


class IssueRedeem(unittest.TestCase):
    def test_issue_redeem_exact(self):
        reg = _reg()
        lease = reg.issue_for_arap(_req(), permit_id="u1", ttl_s=60)
        self.assertFalse(lease.used)
        grant = reg.redeem("u1", lease.parameter_digest)
        self.assertEqual(grant["permit_id"], "u1")
        self.assertTrue(lease.used)

    def test_double_redeem_refused(self):
        reg = _reg()
        lease = reg.issue_for_arap(_req(), permit_id="u2", ttl_s=60)
        reg.redeem("u2", lease.parameter_digest)
        with self.assertRaises(pl.PermitReusedError) as ctx:
            reg.redeem("u2", lease.parameter_digest)
        self.assertEqual(ctx.exception.code, "permit-reused")

    def test_digest_mismatch_refused(self):
        reg = _reg()
        reg.issue_for_arap(_req(), permit_id="u3", ttl_s=60)
        other = pc.compile_arap_context({"amount": 1}, key=KEY)
        with self.assertRaises(pl.PermitDigestMismatchError) as ctx:
            reg.redeem("u3", other.binding)
        self.assertEqual(ctx.exception.code, "permit-digest-mismatch")

    def test_expired_refused(self):
        reg = _reg()
        lease = reg.issue_for_arap(_req(), permit_id="u4", ttl_s=60)
        late = pl.PermitRegistry(now=lambda: NOW + 61)
        late._leases["u4"] = lease
        with self.assertRaises(pl.PermitExpiredError) as ctx:
            late.redeem("u4", lease.parameter_digest)
        self.assertEqual(ctx.exception.code, "permit-expired")

    def test_boundary_now_equals_expiry_is_expired(self):
        reg = _reg()
        lease = reg.issue_for_arap(_req(), permit_id="u4b", ttl_s=60)
        edge = pl.PermitRegistry(now=lambda: NOW + 60)
        edge._leases["u4b"] = lease
        with self.assertRaises(pl.PermitExpiredError):
            edge.redeem("u4b", lease.parameter_digest)

    def test_unknown_permit_refused(self):
        reg = _reg()
        with self.assertRaises(pl.PermitUnknownError) as ctx:
            reg.redeem("ghost", "sha256:" + "0" * 64)
        self.assertEqual(ctx.exception.code, "permit-unknown")

    def test_redeem_failure_does_not_consume(self):
        reg = _reg()
        lease = reg.issue_for_arap(_req(), permit_id="u7", ttl_s=60)
        with self.assertRaises(pl.PermitDigestMismatchError):
            reg.redeem("u7", "sha256:" + "0" * 64)
        self.assertFalse(lease.used)
        grant = reg.redeem("u7", lease.parameter_digest)
        self.assertEqual(grant["permit_id"], "u7")

    def test_duplicate_permit_id_is_authoring_bug(self):
        reg = _reg()
        reg.issue_for_arap(_req(), permit_id="dup", ttl_s=60)
        with self.assertRaises(ValueError):
            reg.issue_for_arap(_req(), permit_id="dup", ttl_s=60)

    def test_unbound_request_cannot_receive_permit(self):
        reg = _reg()
        bare = arap.new_request("r0", "alice", "doc/1", "read")
        with self.assertRaises(ValueError):
            reg.issue_for_arap(bare, permit_id="u9", ttl_s=60)

    def test_nonpositive_ttl_is_authoring_bug(self):
        reg = _reg()
        with self.assertRaises(ValueError):
            reg.issue_for_arap(_req(), permit_id="u10", ttl_s=0)

    def test_parameter_digest_reuses_arap_binding(self):
        # The mission-bound property: the permit's digest IS the ARAP
        # context_binding — one digest scheme, not two.
        req = _req()
        lease = _reg().issue_for_arap(req, permit_id="u11", ttl_s=60)
        self.assertEqual(lease.parameter_digest, req["context_binding"])
        self.assertTrue(
            lease.parameter_digest.startswith("hmac-sha256-v1:"))

    def test_grant_scope_defaults_to_triple(self):
        lease = _reg().issue_for_arap(_req(), permit_id="u12", ttl_s=60)
        self.assertEqual(lease.grant_scope,
                         {"subject": frozenset({"alice"}),
                          "resource": frozenset({"doc/1"}),
                          "action": frozenset({"read"})})


class Scope(unittest.TestCase):
    GRANT = {"subject": {"alice"}, "resource": {"doc/1"},
             "action": {"read", "write"}}

    def test_equal_accepted(self):
        self.assertTrue(pl.PermitLease.check_scope(dict(self.GRANT),
                                                  self.GRANT))

    def test_narrow_accepted(self):
        self.assertTrue(pl.PermitLease.check_scope({"action": {"read"}},
                                                  self.GRANT))

    def test_widen_action_refused(self):
        with self.assertRaises(pl.PermitDowngradeRefusedError) as ctx:
            pl.PermitLease.check_scope({"action": {"read", "delete"}},
                                       self.GRANT)
        self.assertEqual(ctx.exception.code, "permit-downgrade-refused")

    def test_subject_swap_refused(self):
        with self.assertRaises(pl.PermitDowngradeRefusedError):
            pl.PermitLease.check_scope({"subject": {"mallory"}}, self.GRANT)

    def test_extra_dimension_refused(self):
        with self.assertRaises(pl.PermitDowngradeRefusedError):
            pl.PermitLease.check_scope(
                {"subject": {"alice"}, "clearance": {"top"}}, self.GRANT)

    def test_malformed_scope_refuses_not_typeerror(self):
        for bad in (["action"], {"action": [{"read"}]},
                    {"action": [None]}, {"action": []}, "action"):
            with self.assertRaises(pl.PermitDowngradeRefusedError,
                                   msg="bad=%r" % (bad,)):
                pl.PermitLease.check_scope(bad, self.GRANT)

    def test_malformed_grant_scope_is_authoring_bug(self):
        reg = _reg()
        with self.assertRaises(ValueError):
            reg.issue_for_arap(_req(), permit_id="g1", ttl_s=60,
                               grant_scope={"action": [{"read"}]})

    def test_redeem_enforces_scope(self):
        reg = _reg()
        lease = reg.issue_for_arap(_req(), permit_id="s1", ttl_s=60)
        with self.assertRaises(pl.PermitDowngradeRefusedError):
            reg.redeem("s1", lease.parameter_digest,
                       request_scope={"subject": {"alice"},
                                      "resource": {"doc/1"},
                                      "action": {"read", "write"}})
        self.assertFalse(lease.used)  # refused redeem does not consume


class TransitionWiring(unittest.TestCase):
    def test_approved_transition_issues_permit(self):
        reg = _reg()
        req = _req()
        arap.transition(req, "approved", by="a1", lease_registry=reg,
                        lease_ttl_s=120)
        pid = req.get("permit_id")
        self.assertTrue(pid)
        self.assertIn(pid, reg._leases)
        self.assertEqual(reg._leases[pid].parameter_digest,
                         req["context_binding"])

    def test_denied_transition_issues_nothing(self):
        reg = _reg()
        req = _req()
        arap.transition(req, "denied", by="a1", lease_registry=reg)
        self.assertNotIn("permit_id", req)
        self.assertEqual(reg._leases, {})

    def test_unbound_approval_skips_loudly(self):
        events = []
        reg = _reg(audit=events.append)
        req = arap.new_request("r2", "alice", "doc/1", "read")
        arap.transition(req, "approved", by="a1", audit=events.append,
                        lease_registry=reg)
        self.assertNotIn("permit_id", req)
        self.assertTrue(any(e.get("event") == "arap_permit_skipped"
                            for e in events))

    def test_legacy_default_unchanged(self):
        req = _req()
        arap.transition(req, "approved", by="a1")
        self.assertNotIn("permit_id", req)
        self.assertEqual(
            set(req.keys()),
            {"request_id", "subject", "resource", "action",
             "declared_context", "context_binding", "idempotency_key",
             "authorized_cancellers", "status", "history"})

    def test_refusals_are_audited(self):
        events = []
        reg = _reg(audit=events.append)
        lease = reg.issue_for_arap(_req(), permit_id="a1", ttl_s=60)
        with self.assertRaises(pl.PermitDigestMismatchError):
            reg.redeem("a1", "sha256:" + "0" * 64)
        codes = [e.get("code") for e in events
                 if e.get("event") == "permit_redeem_refused"]
        self.assertEqual(codes, ["permit-digest-mismatch"])


if __name__ == "__main__":
    unittest.main()
