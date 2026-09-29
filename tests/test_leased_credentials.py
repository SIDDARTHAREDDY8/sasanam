#!/usr/bin/env python3
"""Unit tests for gov/leased_credentials.py (wave-212 lane C).

Hermetic: FakeLeaseTransport only, injectable clock, no network.
"""

import json
import unittest

from gov import leased_credentials as lc


class _Clock(object):
    def __init__(self, t=1000.0):
        self.t = t

    def now(self):
        return self.t


def _make(**kw):
    clock = _Clock(kw.pop("t0", 1000.0))
    transport = kw.pop("transport", None) or lc.FakeLeaseTransport()
    audit = []
    m = lc.LeasedCredentialManager(transport, token="op-token",
                                   audit_log=audit, now=clock.now,
                                   **kw)
    return m, audit, clock


def _issue(m, **kw):
    kw.setdefault("credential_id", "db-password")
    kw.setdefault("agent_id", "agent-1")
    kw.setdefault("run_id", "run-1")
    kw.setdefault("credential_kind", "db-password")
    kw.setdefault("source_path", "database/creds/app")
    kw.setdefault("inject_hosts", ["db.internal.example.com"])
    kw.setdefault("secret", "SYNTHETIC-db-secret-01")
    return m.issue_lease(**kw)


class TestIssue(unittest.TestCase):
    def test_issue_returns_record_and_sentinel(self):
        m, audit, _ = _make()
        rec, sentinel = _issue(m)
        self.assertIsInstance(rec, lc.LeaseRecord)
        self.assertTrue(sentinel.startswith("fake_value_"))
        self.assertTrue(rec.lease_id.startswith("lc_lease_"))
        self.assertEqual(rec.state, "active")
        self.assertEqual(rec.expires_at, 1000.0 + 3600)

    def test_issue_record_fields(self):
        m, audit, _ = _make()
        rec, _ = _issue(m, ttl_s=60, max_ttl_s=120, credential_id="c1")
        self.assertEqual(rec.credential_id, "c1")
        self.assertEqual(rec.expires_at - rec.issued_at, 60)
        self.assertEqual(rec.max_ttl_s, 120)
        self.assertTrue(rec.renewable)

    def test_issue_audited(self):
        m, audit, _ = _make()
        rec, _ = _issue(m)
        self.assertEqual([e["action"] for e in audit], ["issue"])
        ev = audit[0]
        self.assertEqual(ev["event"], "lease_lifecycle")
        self.assertEqual(ev["lease_id"], rec.lease_id)
        self.assertNotIn("SYNTHETIC-db-secret-01", json.dumps(audit))
        self.assertNotIn("op-token", json.dumps(audit))

    def test_issue_requires_nonempty_strings(self):
        m, _, _ = _make()
        for bad in ("", "   ", None):
            with self.assertRaises(lc.LeaseError):
                _issue(m, credential_id=bad)

    def test_issue_requires_hosts(self):
        m, _, _ = _make()
        with self.assertRaises(lc.LeaseError):
            _issue(m, inject_hosts=[])

    def test_issue_rejects_bad_host(self):
        m, _, _ = _make()
        with self.assertRaises(lc.LeaseError):
            _issue(m, inject_hosts=["not a host!!"])

    def test_issue_normalizes_hosts(self):
        m, _, _ = _make()
        rec, _ = _issue(m, inject_hosts=["DB.INTERNAL.EXAMPLE.COM."])
        bind = list(m._sentinels.values())[0]
        self.assertEqual(bind["hosts"], ["db.internal.example.com"])

    def test_issue_down_transport_fails_closed(self):
        m, audit, _ = _make(transport=lc.FakeLeaseTransport(down=True))
        with self.assertRaises(lc.LeaseError):
            _issue(m)
        self.assertEqual(m.issued_lease_ids(), [])

    def test_issue_requires_transport_and_token(self):
        with self.assertRaises(lc.LeaseError):
            lc.LeasedCredentialManager(None, token="x")
        with self.assertRaises(lc.LeaseError):
            lc.LeasedCredentialManager(lc.FakeLeaseTransport(), token="")

    def test_issue_refuses_credential_shaped_secret(self):
        m, _, _ = _make()
        with self.assertRaises(lc.LeaseError):
            _issue(m, secret="ghp_" + "a" * 36)

    def test_repr_redacts(self):
        m, _, _ = _make()
        _issue(m)
        self.assertNotIn("SYNTHETIC-db-secret-01", repr(m))


class TestRenew(unittest.TestCase):
    def test_renew_default(self):
        m, audit, clock = _make()
        rec, _ = _issue(m, ttl_s=100, max_ttl_s=600)
        clock.t = 1050.0
        rec2 = m.renew_lease(rec.lease_id)
        self.assertEqual(rec2.expires_at, 1050.0 + 100)

    def test_renew_explicit_increment(self):
        m, _, clock = _make()
        rec, _ = _issue(m, ttl_s=100, max_ttl_s=1000)
        rec2 = m.renew_lease(rec.lease_id, increment_s=200)
        self.assertEqual(rec2.expires_at, 1000.0 + 200)
        acts = [e["action"] for e in [] if False]
        self.assertNotIn("noop", acts)

    def test_renew_past_max_refused_definite(self):
        m, audit, clock = _make()
        rec, _ = _issue(m, ttl_s=600, max_ttl_s=600)
        with self.assertRaises(lc.LeaseError):
            m.renew_lease(rec.lease_id, increment_s=600)
        # Definite refusal: lease survives until its current expiry.
        self.assertEqual(m.lease_status(rec.lease_id), "active")
        self.assertEqual(m.lease_record(rec.lease_id).expires_at, 1600.0)

    def test_renew_unknown_lease_marks_dead(self):
        m, audit, _ = _make()
        rec, _ = _issue(m)
        m.transport.forget_lease(rec.lease_id)
        with self.assertRaises(lc.LeaseError):
            m.renew_lease(rec.lease_id)
        self.assertEqual(m.lease_status(rec.lease_id), "dead")

    def test_renew_transport_down_marks_dead(self):
        m, audit, _ = _make()
        rec, _ = _issue(m)
        m.transport.down = True
        with self.assertRaises(lc.LeaseError):
            m.renew_lease(rec.lease_id)
        self.assertEqual(m.lease_status(rec.lease_id), "dead")

    def test_renew_after_dead_stays_dead(self):
        m, _, _ = _make()
        rec, _ = _issue(m)
        m.transport.forget_lease(rec.lease_id)
        with self.assertRaises(lc.LeaseError):
            m.renew_lease(rec.lease_id)
        with self.assertRaises(lc.LeaseError):
            m.renew_lease(rec.lease_id)
        self.assertEqual(m.lease_status(rec.lease_id), "dead")

    def test_renew_nonrenewable_refused_definite(self):
        fake = lc.FakeLeaseTransport()
        m, _, _ = _make(transport=fake)
        rec, _ = _issue(m, renewable=False)
        with self.assertRaises(lc.LeaseError):
            m.renew_lease(rec.lease_id)
        self.assertEqual(m.lease_status(rec.lease_id), "active")


class TestRevoke(unittest.TestCase):
    def test_revoke(self):
        m, audit, _ = _make()
        rec, _ = _issue(m)
        m.revoke_lease(rec.lease_id, reason="incident-response")
        self.assertEqual(m.lease_status(rec.lease_id), "revoked")
        self.assertEqual([e["action"] for e in audit], ["issue", "revoke"])

    def test_revoke_requires_reason(self):
        m, _, _ = _make()
        rec, _ = _issue(m)
        with self.assertRaises(lc.LeaseError):
            m.revoke_lease(rec.lease_id, reason="")

    def test_revoke_down_transport_marks_dead_and_raises(self):
        m, audit, _ = _make()
        rec, _ = _issue(m)
        m.transport.down = True
        with self.assertRaises(lc.LeaseError):
            m.revoke_lease(rec.lease_id, reason="incident")
        self.assertEqual(m.lease_status(rec.lease_id), "dead")
        acts = [e["action"] for e in audit]
        self.assertIn("revoke_failed", acts)


class TestStatus(unittest.TestCase):
    def test_active_expired(self):
        m, _, clock = _make()
        rec, _ = _issue(m, ttl_s=10)
        self.assertEqual(m.lease_status(rec.lease_id), "active")
        clock.t = 1011.0
        self.assertEqual(m.lease_status(rec.lease_id), "expired")

    def test_recheck_finds_server_revocation(self):
        m, _, _ = _make()
        rec, _ = _issue(m, ttl_s=600)
        m.transport.request("PUT", "/v1/sys/leases/revoke", {},
                            json.dumps({"lease_id": rec.lease_id}).encode())
        self.assertEqual(m.lease_status(rec.lease_id), "active")
        self.assertEqual(m.lease_status(rec.lease_id, recheck=True),
                         "revoked")
        self.assertEqual(m.lease_status(rec.lease_id), "revoked")

    def test_recheck_unknown_lease_marks_dead(self):
        m, _, _ = _make()
        rec, _ = _issue(m, ttl_s=600)
        m.transport.forget_lease(rec.lease_id)
        self.assertEqual(m.lease_status(rec.lease_id, recheck=True), "dead")

    def test_unknown_lease_raises(self):
        m, _, _ = _make()
        with self.assertRaises(lc.LeaseError):
            m.lease_status("lc_lease_nope")
        with self.assertRaises(lc.LeaseError):
            m.lease_record("lc_lease_nope")


class TestDeliver(unittest.TestCase):
    def test_deliver_authorized(self):
        m, _, _ = _make()
        rec, sentinel = _issue(m)
        out = m.deliver(rec.lease_id, sentinel=sentinel,
                        dest_host="db.internal.example.com")
        self.assertEqual(out, "SYNTHETIC-db-secret-01")

    def test_deliver_expired_refused(self):
        m, audit, clock = _make()
        rec, sentinel = _issue(m, ttl_s=10)
        clock.t = 1011.0
        with self.assertRaises(lc.LeaseError):
            m.deliver(rec.lease_id, sentinel=sentinel,
                      dest_host="db.internal.example.com")
        self.assertIn("use_refused",
                      [e["action"] for e in audit])

    def test_deliver_revoked_refused(self):
        m, _, _ = _make()
        rec, sentinel = _issue(m)
        m.revoke_lease(rec.lease_id, reason="x")
        with self.assertRaises(lc.LeaseError):
            m.deliver(rec.lease_id, sentinel=sentinel,
                      dest_host="db.internal.example.com")

    def test_deliver_dead_refused(self):
        m, _, _ = _make()
        rec, sentinel = _issue(m)
        m.transport.forget_lease(rec.lease_id)
        with self.assertRaises(lc.LeaseError):
            m.renew_lease(rec.lease_id)
        with self.assertRaises(lc.LeaseError):
            m.deliver(rec.lease_id, sentinel=sentinel,
                      dest_host="db.internal.example.com")

    def test_deliver_wrong_sentinel_refused(self):
        m, _, _ = _make()
        rec, _ = _issue(m)
        with self.assertRaises(lc.LeaseError):
            m.deliver(rec.lease_id, sentinel="fake_value_nope",
                      dest_host="db.internal.example.com")

    def test_deliver_unauthorized_host_refused(self):
        m, _, _ = _make()
        rec, sentinel = _issue(m)
        with self.assertRaises(lc.LeaseError):
            m.deliver(rec.lease_id, sentinel=sentinel,
                      dest_host="evil.example.net")

    def test_deliver_case_insensitive_host(self):
        m, _, _ = _make()
        rec, sentinel = _issue(m)
        out = m.deliver(rec.lease_id, sentinel=sentinel,
                        dest_host="DB.Internal.Example.COM.")
        self.assertEqual(out, "SYNTHETIC-db-secret-01")


class TestWrapping(unittest.TestCase):
    def test_wrap_unwrap_once(self):
        m, audit, _ = _make()
        rec, sentinel = _issue(m)
        wrap = m.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                   dest_host="db.internal.example.com")
        self.assertTrue(wrap.startswith("wrap_"))
        out = m.unwrap(wrap, dest_host="db.internal.example.com")
        self.assertEqual(out, "SYNTHETIC-db-secret-01")
        with self.assertRaises(lc.LeaseError):
            m.unwrap(wrap, dest_host="db.internal.example.com")

    def test_unwrap_unknown_token(self):
        m, _, _ = _make()
        _issue(m)
        with self.assertRaises(lc.LeaseError):
            m.unwrap("wrap_nope", dest_host="db.internal.example.com")

    def test_unwrap_wrong_host_burns_and_audits(self):
        m, audit, _ = _make()
        rec, sentinel = _issue(m)
        wrap = m.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                   dest_host="db.internal.example.com")
        with self.assertRaises(lc.LeaseError):
            m.unwrap(wrap, dest_host="evil.example.net")
        # Token is burned: the legitimate recipient sees it as spent.
        with self.assertRaises(lc.LeaseError):
            m.unwrap(wrap, dest_host="db.internal.example.com")
        self.assertIn("unwrap_intercepted",
                      [e["action"] for e in audit])

    def test_unwrap_after_lease_death_refused(self):
        m, _, clock = _make()
        rec, sentinel = _issue(m, ttl_s=600)
        wrap = m.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                   dest_host="db.internal.example.com")
        m.revoke_lease(rec.lease_id, reason="x")
        with self.assertRaises(lc.LeaseError):
            m.unwrap(wrap, dest_host="db.internal.example.com")

    def test_wrap_token_expires(self):
        m, _, clock = _make(wrapping_ttl_s=5)
        rec, sentinel = _issue(m, ttl_s=600)
        wrap = m.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                   dest_host="db.internal.example.com")
        clock.t += 6.0
        with self.assertRaises(lc.LeaseError):
            m.unwrap(wrap, dest_host="db.internal.example.com")

    def test_wrap_unauthorized_host_refused(self):
        m, _, _ = _make()
        rec, sentinel = _issue(m)
        with self.assertRaises(lc.LeaseError):
            m.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                dest_host="evil.example.net")


class TestTransport(unittest.TestCase):
    def test_urllib_rejects_http_without_flag(self):
        with self.assertRaises(lc.LeaseError):
            lc.UrllibLeaseTransport("http://vault:8200")

    def test_urllib_rejects_relative_url(self):
        with self.assertRaises(lc.LeaseError):
            lc.UrllibLeaseTransport("/v1")

    def test_urllib_allows_http_with_flag(self):
        t = lc.UrllibLeaseTransport("http://vault:8200", allow_http=True)
        self.assertIsInstance(t, lc.LeaseTransport)

    def test_lease_event_shape(self):
        ev = lc.lease_event(action="issue", lease_id="l", credential_id="c",
                            agent_id="a", run_id="r", detail="d")
        self.assertEqual(ev["event"], "lease_lifecycle")
        self.assertEqual(ev["action"], "issue")
        self.assertNotIn("secret", json.dumps(ev).lower())


if __name__ == "__main__":
    unittest.main()
