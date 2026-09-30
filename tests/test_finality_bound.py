"""Wave-243 lane B units: finality-bound revocation.

W243-2 — ADAPT of draft-das-finality-bound-revocation -00 (patterns
only; no draft text, no vendored code). The Finality Sink performs an
atomic check-and-commit against the revocation basis bound at issue.
"""

import unittest
from datetime import datetime, timezone

from gov import decision_codes
from gov import finality_bound as fb


def _store(basis="basis-1"):
    store = fb.RevocationStore()
    store.register_basis(basis)
    return store


def _issue(store, basis="basis-1", now=1000):
    return fb.issue_authorization(
        "agent-7", "write-file", basis, "issuer-anchor-9", store, now)


class TestRevocationStore(unittest.TestCase):
    def test_register_and_live_epoch(self):
        store = _store()
        self.assertIsNone(store.revocation_epoch("basis-1"))

    def test_revoke_sets_epoch(self):
        store = _store()
        store.revoke("basis-1", 1500, 1400)
        self.assertEqual(store.revocation_epoch("basis-1"), 1500)

    def test_double_register_refused(self):
        store = _store()
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            store.register_basis("basis-1")
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")

    def test_revoke_unknown_basis_refused(self):
        store = _store()
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            store.revoke("nope", 1500, 1400)
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")

    def test_non_numeric_epoch_refused(self):
        store = _store()
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            store.revoke("basis-1", "soon", 1400)
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")

    def test_bool_epoch_refused(self):
        # bool is not a numeric epoch (the True == 1 trap).
        store = _store()
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            store.revoke("basis-1", True, 1400)
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")


class TestIssueAuthorization(unittest.TestCase):
    def test_binding_digest_stable(self):
        store = _store()
        first = _issue(store, now=1000)
        second = _issue(store, now=1000)
        self.assertEqual(first["binding_digest"], second["binding_digest"])

    def test_binding_records_epoch_at_issue(self):
        store = _store()
        authz = _issue(store, now=1000)
        self.assertIsNone(authz["binding"]["revocation_epoch_at_issue"])

    def test_empty_basis_refused(self):
        store = _store()
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.issue_authorization("s", "a", "", "anchor", store, 1000)
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")

    def test_issue_on_unknown_basis_refused(self):
        store = _store()
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.issue_authorization("s", "a", "nope", "anchor", store, 1000)
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")


class TestFinalitySink(unittest.TestCase):
    def test_live_basis_commits(self):
        store = _store()
        receipt = fb.finality_sink_commit(_issue(store, now=1000), store, 1200)
        self.assertTrue(receipt["committed"])
        self.assertEqual(receipt["basis_id"], "basis-1")

    def test_revoked_basis_refused(self):
        store = _store()
        authz = _issue(store, now=1000)
        store.revoke("basis-1", 1500, 1500)
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit(authz, store, 1600)
        self.assertEqual(ctx.exception.code, "revocation-applicable")

    def test_future_revocation_not_applicable(self):
        # A revocation scheduled after now does not block this commit.
        store = _store()
        authz = _issue(store, now=1000)
        store.revoke("basis-1", 2000, 1500)
        receipt = fb.finality_sink_commit(authz, store, 1600)
        self.assertTrue(receipt["committed"])

    def test_revoked_at_issue_refused(self):
        store = _store()
        store.revoke("basis-1", 900, 900)
        authz = _issue(store, now=1000)
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit(authz, store, 1100)
        self.assertEqual(ctx.exception.code, "revocation-applicable")

    def test_mid_check_mutation_refused(self):
        class RacingStore(fb.RevocationStore):
            def revocation_epoch(self, basis_id):
                self.revoke("basis-1", 1050, 1050)
                return super().revocation_epoch(basis_id)

        store = RacingStore()
        store.register_basis("basis-1")
        authz = _issue(store, now=1000)
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit(authz, store, 1100)
        self.assertEqual(ctx.exception.code, "revocation-check-unsealed")

    def test_non_atomic_store_refused(self):
        class PlainStore(object):
            def revocation_epoch(self, basis_id):
                return None

        store = _store()
        authz = _issue(store, now=1000)
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit(authz, PlainStore(), 1100)
        self.assertEqual(ctx.exception.code, "revocation-sink-nonatomic")

    def test_tampered_binding_refused(self):
        store = _store()
        authz = _issue(store, now=1000)
        authz["binding"]["action"] = "delete-everything"
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit(authz, store, 1100)
        self.assertEqual(ctx.exception.code, "revocation-basis-tampered")

    def test_forged_authorization_refused(self):
        store = _store()
        forged = {
            "type": "finality-bound-authorization",
            "binding": {
                "subject": "agent-7",
                "action": "write-file",
                "basis_id": "basis-1",
                "revocation_epoch_at_issue": None,
                "issued_at": 1000,
            },
            "issuer_trust_anchor": "issuer-anchor-9",
            "binding_digest": "f" * 64,
        }
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit(forged, store, 1100)
        self.assertEqual(ctx.exception.code, "revocation-basis-tampered")

    def test_malformed_authorization_refused(self):
        store = _store()
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit({"nope": True}, store, 1100)
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")

    def test_non_numeric_now_refused(self):
        store = _store()
        authz = _issue(store, now=1000)
        with self.assertRaises(fb.FinalityBoundError) as ctx:
            fb.finality_sink_commit(authz, store, "later")
        self.assertEqual(ctx.exception.code, "revocation-basis-malformed")


class TestIntegrations(unittest.TestCase):
    def test_stale_authority_lapse_propagates(self):
        from gov import stale_authority as sa
        store = _store()
        authz = fb.issue_authorization(
            "agent-7", "write-file", "basis-1", "issuer-anchor-9",
            store, 1000,
            authority_id="draft-emirdag-scitt-ai-agent-execution-00",
            minted_at=datetime(2026, 10, 14, tzinfo=timezone.utc))
        with self.assertRaises(sa.StaleAuthorityError) as ctx:
            fb.finality_sink_commit(authz, store, 1100)
        self.assertEqual(ctx.exception.code, "stale-authority")

    def test_pre_expiry_authority_passes(self):
        store = _store()
        authz = fb.issue_authorization(
            "agent-7", "write-file", "basis-1", "issuer-anchor-9",
            store, 1000,
            authority_id="draft-emirdag-scitt-ai-agent-execution-00",
            minted_at=datetime(2026, 10, 1, tzinfo=timezone.utc))
        receipt = fb.finality_sink_commit(authz, store, 1100)
        self.assertTrue(receipt["committed"])

    def test_expired_exception_no_longer_shields(self):
        from gov import exception_ttl as et
        from gov import gate_outcomes as go
        store = _store()
        decl = et.declare_exception(
            valid_until=1200, reason="maintenance", scope="sink-1",
            issued_at=1000)
        with self.assertRaises(go.GateOutcomeError) as ctx:
            fb.finality_sink_commit(_issue(store, now=1000), store, 1300,
                                    exception=decl, scope="sink-1")
        self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_live_exception_shields(self):
        from gov import exception_ttl as et
        store = _store()
        decl = et.declare_exception(
            valid_until=2000, reason="maintenance", scope="sink-1",
            issued_at=1000)
        receipt = fb.finality_sink_commit(_issue(store, now=1000), store,
                                          1300, exception=decl,
                                          scope="sink-1")
        self.assertTrue(receipt["committed"])


class TestTaxonomyPin(unittest.TestCase):
    def test_pin(self):
        # Wave-243 lane B: re-pointed to pin 793 (5 additive
        # finality-bound revocation codes), additive only.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-246 merge: re-pointed to 936 (41 additive wave-246 codes: 11 policy-delta + 5 schema-ref + 1 advisory-input-malformed + 6 did-key/reputation + 11 breach-boundary + 3 mcp-discovery + 4 attested-identity), additive only, composed from the twelve lane commits by direct byte-verification.
        self.assertEqual(len(decision_codes.TAXONOMY), 936)

    def test_new_codes_mapped(self):
        for code in ("revocation-applicable", "revocation-basis-malformed",
                     "revocation-basis-tampered", "revocation-check-unsealed",
                     "revocation-sink-nonatomic"):
            record = decision_codes.code_for(code)
            self.assertEqual(record["code"], code)
            self.assertEqual(record["domain"], "revocation")


if __name__ == "__main__":
    unittest.main()
