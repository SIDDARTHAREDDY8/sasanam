"""Unit tests for gov/arap.py (wave-218 lane A).

ARAP hardening: authorization-relevant context binding, terminal
lifecycle statuses, Idempotency-Key discipline, and independent
cancellation authorization with handles that carry no authority.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import arap  # noqa: E402

_KEY = b"arap-unit-key-0123456789abcdef"


class TestContextBinding(unittest.TestCase):
    def test_declare_and_verify_roundtrip(self):
        decl = arap.declare_context({"flag": "b", "n": 3}, key=_KEY)
        self.assertEqual(set(decl["declared"]), {"flag", "n"})
        self.assertTrue(decl["declared"]["flag"].startswith("sha256:"))
        self.assertTrue(decl["binding"].startswith("hmac-sha256-v1:"))
        arap.verify_context_binding(decl["declared"], decl["binding"],
                                    key=_KEY)

    def test_field_digests_differ_per_value(self):
        a = arap.declare_context({"f": "x"}, key=_KEY)
        b = arap.declare_context({"f": "y"}, key=_KEY)
        self.assertNotEqual(a["declared"]["f"], b["declared"]["f"])

    def test_binding_scope_strings(self):
        self.assertEqual(arap.binding_scope({}), "subject/resource/action")
        self.assertEqual(
            arap.binding_scope({"a": "d"}),
            "subject/resource/action + 1 declared context fields")

    def test_check_cited_context_happy(self):
        decl = arap.declare_context({"a": 1, "b": 2}, key=_KEY)
        self.assertTrue(arap.check_cited_context(["a"], decl["declared"]))
        self.assertTrue(arap.check_cited_context([], decl["declared"]))
        self.assertTrue(arap.check_cited_context(None, {}))

    def test_check_cited_context_refused(self):
        decl = arap.declare_context({"a": 1}, key=_KEY)
        with self.assertRaises(arap.ContextNotDeclaredError) as ctx:
            arap.check_cited_context(["a", "zzz"], decl["declared"])
        self.assertEqual(ctx.exception.code, "context-not-declared")

    def test_verify_binding_tamper(self):
        decl = arap.declare_context({"a": 1}, key=_KEY)
        bad = dict(decl["declared"])
        bad["evil"] = "sha256:" + "00" * 32
        with self.assertRaises(arap.ContextNotDeclaredError) as ctx:
            arap.verify_context_binding(bad, decl["binding"], key=_KEY)
        self.assertEqual(ctx.exception.code, "context-binding-mismatch")

    def test_verify_binding_wrong_key(self):
        decl = arap.declare_context({"a": 1}, key=_KEY)
        with self.assertRaises(arap.ContextNotDeclaredError) as ctx:
            arap.verify_context_binding(decl["declared"], decl["binding"],
                                        key=b"0" * 32)
        self.assertEqual(ctx.exception.code, "context-binding-mismatch")

    def test_short_key_refused(self):
        with self.assertRaises(ValueError):
            arap.declare_context({"a": 1}, key=b"short")


class TestLifecycle(unittest.TestCase):
    def test_new_request_defaults(self):
        req = arap.new_request("r1", "s", "res", "act")
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["declared_context"], {})
        self.assertIsNone(req["context_binding"])
        self.assertEqual(req["authorized_cancellers"], [])
        self.assertEqual(req["history"][0]["from"], None)
        self.assertEqual(req["history"][0]["to"], "pending")

    def test_new_request_binds_context_with_key(self):
        req = arap.new_request("r1", "s", "res", "act",
                               context={"flag": "b"}, key=_KEY,
                               authorized_cancellers=("op",))
        self.assertNotEqual(req["declared_context"], {})
        self.assertIsNotNone(req["context_binding"])
        self.assertEqual(req["authorized_cancellers"], ["op"])

    def test_new_request_context_without_key_binds_triple_only(self):
        # Context offered but no key: it cannot be integrity-protected,
        # so it is dropped from the binding (loud triple-only), never
        # silently treated as bound.
        req = arap.new_request("r1", "s", "res", "act",
                               context={"flag": "b"})
        self.assertEqual(req["declared_context"], {})
        self.assertIsNone(req["context_binding"])

    def test_new_request_bad_input(self):
        for bad in ("", None, 3):
            with self.assertRaises(ValueError):
                arap.new_request(bad, "s", "res", "act")

    def test_transition_happy_and_audit(self):
        entries = []
        req = arap.new_request("r1", "s", "res", "act")
        arap.transition(req, "approved", by="op", audit=entries.append)
        self.assertEqual(req["status"], "approved")
        self.assertEqual(len(req["history"]), 2)
        self.assertEqual(req["history"][-1]["from"], "pending")
        self.assertEqual(req["history"][-1]["by"], "op")
        self.assertTrue(entries)
        self.assertEqual(entries[0]["event"], "arap_status_transition")
        self.assertEqual(entries[0]["to"], "approved")

    def test_transition_terminal_final(self):
        req = arap.new_request("r1", "s", "res", "act")
        arap.transition(req, "failed", by="sys")
        for target in ("pending", "approved", "cancelled", "failed"):
            with self.assertRaises(arap.TerminalTransitionError) as ctx:
                arap.transition(req, target, by="op")
            self.assertEqual(ctx.exception.code,
                             "terminal-transition-refused")
        self.assertEqual(req["status"], "failed")

    def test_transition_unknown_status(self):
        req = arap.new_request("r1", "s", "res", "act")
        with self.assertRaises(ValueError):
            arap.transition(req, "limbo", by="op")

    def test_transition_noop_refused(self):
        req = arap.new_request("r1", "s", "res", "act")
        with self.assertRaises(arap.TerminalTransitionError):
            arap.transition(req, "pending", by="op")

    def test_all_terminal_statuses_reachable(self):
        for status in sorted(arap.TERMINAL_STATUSES):
            req = arap.new_request("r-" + status, "s", "res", "act")
            arap.transition(req, status, by="op")
            self.assertEqual(req["status"], status)

    def test_aggregate_statuses(self):
        self.assertEqual(arap.aggregate_statuses(["approved"]), "approved")
        self.assertEqual(arap.aggregate_statuses(["denied", "denied"]),
                         "denied")
        self.assertEqual(arap.aggregate_statuses(["approved", "denied"]),
                         "partial")
        self.assertEqual(
            arap.aggregate_statuses(["approved", "cancelled", "expired"]),
            "partial")
        for bad in ([], ["approved", "pending"], ["limbo"]):
            with self.assertRaises(ValueError):
                arap.aggregate_statuses(bad)


class TestIdempotency(unittest.TestCase):
    def test_idempotency_new_replay(self):
        reg = arap.IdempotencyRegistry()
        self.assertEqual(reg.check("k", "sha256:aa"), "new")
        self.assertEqual(reg.record("k", "sha256:aa", "dec-1"), "recorded")
        self.assertEqual(reg.check("k", "sha256:aa"), "replay")
        self.assertEqual(reg.decision("k"), "dec-1")
        # Re-recording the same body + same decision is a benign replay.
        self.assertEqual(reg.record("k", "sha256:aa", "dec-1"), "replay")

    def test_idempotency_mismatch_refused(self):
        reg = arap.IdempotencyRegistry()
        reg.record("k", "sha256:aa", "dec-1")
        with self.assertRaises(arap.DuplicateRequestError) as ctx:
            reg.check("k", "sha256:bb")
        self.assertEqual(ctx.exception.code, "duplicate_request")

    def test_idempotency_redecision_refused(self):
        # Same key + same body + DIFFERENT decision: re-deciding a
        # completed request is refused; the original stands.
        reg = arap.IdempotencyRegistry()
        reg.record("k", "sha256:aa", "dec-1")
        with self.assertRaises(arap.DuplicateRequestError):
            reg.record("k", "sha256:aa", "dec-2")
        self.assertEqual(reg.decision("k"), "dec-1")

    def test_idempotency_bad_input(self):
        reg = arap.IdempotencyRegistry()
        for key in ("", None):
            with self.assertRaises(ValueError):
                reg.check(key, "sha256:aa")


class TestCancellationAndHandles(unittest.TestCase):
    def test_cancellation_authorized(self):
        entries = []
        req = arap.new_request("r1", "s", "res", "act",
                               authorized_cancellers=("op",))
        arap.cancel_request(req, "op", audit=entries.append)
        self.assertEqual(req["status"], "cancelled")
        self.assertEqual(entries[0]["to"], "cancelled")

    def test_cancellation_unauthorized(self):
        req = arap.new_request("r1", "s", "res", "act",
                               authorized_cancellers=("op",))
        with self.assertRaises(arap.CancellationUnauthorizedError) as ctx:
            arap.cancel_request(req, "agent-1")
        self.assertEqual(ctx.exception.code, "cancellation-unauthorized")
        self.assertEqual(req["status"], "pending")

    def test_cancellation_empty_set_means_nobody(self):
        req = arap.new_request("r1", "s", "res", "act")
        with self.assertRaises(arap.CancellationUnauthorizedError):
            arap.cancel_request(req, "op")

    def test_handle_issue_resolve(self):
        reg = arap.HandleRegistry()
        h1 = reg.issue("req-1")
        h2 = reg.issue("req-1")
        self.assertNotEqual(h1, h2)  # opaque and unique per issuance
        self.assertFalse(h1.endswith("req-1"))
        self.assertEqual(reg.resolve(h1, "op", authorized=("op",)),
                         "req-1")

    def test_handle_unauthorized_presenter_refused(self):
        reg = arap.HandleRegistry()
        h = reg.issue("req-1")
        with self.assertRaises(arap.HandleNotAuthorityError) as ctx:
            reg.resolve(h, "agent-1", authorized=("op",))
        self.assertEqual(ctx.exception.code, "handle-not-authority")

    def test_handle_unknown_refused(self):
        reg = arap.HandleRegistry()
        with self.assertRaises(arap.HandleNotAuthorityError) as ctx:
            reg.resolve("bogus", "op", authorized=("op",))
        self.assertEqual(ctx.exception.code, "handle-unknown")

    def test_handle_issue_bad_input(self):
        reg = arap.HandleRegistry()
        for bad in ("", None):
            with self.assertRaises(ValueError):
                reg.issue(bad)


if __name__ == "__main__":
    unittest.main()
