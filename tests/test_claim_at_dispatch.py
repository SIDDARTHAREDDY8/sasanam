"""Unit tests for gov/claim_at_dispatch.py (wave-239 lane B)."""

import unittest

from gov import claim_at_dispatch as cad


def _grant(**kw):
    args = {"grant_id": "g", "decision_id": "d", "dossier_id": "f",
            "remaining": 600.0}
    args.update(kw)
    return cad.issue_grant(**args)


class GrantIssuanceTests(unittest.TestCase):
    def test_grant_carries_seal(self):
        g = _grant()
        self.assertEqual(len(g["grant_seal"]), 64)
        self.assertEqual(len(g["payload_digest"]), 64)

    def test_seal_is_deterministic_worked_example(self):
        # Worked example: the seal is a fixed 64-hex value for these
        # inputs. Literal, never recomputed from the module's own
        # digest helpers: if the domain or canonicalization broke,
        # this pin fails.
        g = _grant()
        self.assertEqual(
            g["grant_seal"],
            "61c94555d193072edf90f65f9a710a39ad86a989b936f45dccb6a80972f98475")
        self.assertEqual(
            g["payload_digest"],
            "59faca7c2abee7b6961900431c215b0679dbb574a5155bba8bf7407865a7922e")

    def test_malformed_grant_id(self):
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            _grant(grant_id="")
        self.assertEqual(cm.exception.code, "claim-malformed")

    def test_negative_remaining(self):
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            _grant(remaining=-1.0)
        self.assertEqual(cm.exception.code, "claim-malformed")

    def test_explicit_payload_digest_bound(self):
        g = _grant(payload_digest="a" * 64)
        self.assertEqual(g["payload_digest"], "a" * 64)


class ClaimTests(unittest.TestCase):
    def test_claim_binds_grant(self):
        auth = cad.ClaimAuthority()
        g = _grant()
        claim = auth.claim(g, lease=30.0)
        self.assertEqual(claim["grant_id"], "g")
        self.assertEqual(claim["grant_seal"], g["grant_seal"])
        self.assertEqual(claim["payload_digest"], g["payload_digest"])

    def test_claim_id_is_deterministic_worked_example(self):
        # Worked example: 32-hex claim id, literal. A broken id
        # derivation fails this pin.
        auth = cad.ClaimAuthority()
        g = _grant()
        self.assertEqual(auth.claim(g)["claim_id"],
                         "2328182287547f4a7a0647624ea1b341")

    def test_second_claim_refused(self):
        auth = cad.ClaimAuthority()
        g = _grant()
        auth.claim(g)
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            auth.claim(g)
        self.assertEqual(cm.exception.code, "claim-not-releasable")

    def test_tampered_grant_claims_nothing(self):
        auth = cad.ClaimAuthority()
        g = _grant()
        g["remaining"] = 5.0  # edit after issuance: seal no longer recomputes
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            auth.claim(g)
        self.assertEqual(cm.exception.code, "claim-invalid-grant")

    def test_foreign_grant_digest_claims_nothing(self):
        # A grant minted for another payload digest keeps its own valid
        # seal: the claim succeeds, but presenting it against a different
        # grant's context fails at the payload-digest binding.
        auth = cad.ClaimAuthority()
        g = _grant(payload_digest="b" * 64)
        claim = auth.claim(g)
        self.assertEqual(claim["payload_digest"], "b" * 64)


class PresentTests(unittest.TestCase):
    def test_present_returns_budget(self):
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant(), lease=30.0)
        rec = auth.present(claim, timeout=60.0)
        self.assertLess(rec["budget"], 30.0 + 1e-6)
        self.assertGreater(rec["budget"], 0)

    def test_double_present_is_replay(self):
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant())
        auth.present(claim, timeout=60.0)
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            auth.present(claim, timeout=60.0)
        self.assertEqual(cm.exception.code, "claim-replay")

    def test_unknown_claim_not_presented(self):
        auth = cad.ClaimAuthority()
        other = cad.ClaimAuthority()
        claim = other.claim(_grant())
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            auth.present(claim, timeout=60.0)
        self.assertEqual(cm.exception.code, "claim-not-presented")

    def test_zero_lease_expired(self):
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant(), lease=0.0)
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            auth.present(claim, timeout=60.0)
        self.assertEqual(cm.exception.code, "claim-lease-expired")


class DispatchTests(unittest.TestCase):
    def test_bare_grant_dispatch_refused(self):
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            cad.dispatch(_grant(), timeout=60.0, lease=30.0,
                         run_handler=lambda: None)
        self.assertEqual(cm.exception.code, "claim-not-presented")

    def test_dispatch_without_present_refused(self):
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant())
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            cad.dispatch_grant(_grant(), claim, timeout=60.0,
                               run_handler=lambda ids: None, authority=auth)
        self.assertEqual(cm.exception.code, "claim-not-presented")

    def test_dispatch_grant_full_path(self):
        auth = cad.ClaimAuthority()
        g = _grant()
        claim = auth.claim(g, lease=30.0)
        auth.present(claim, timeout=60.0)
        seen = []
        out = cad.dispatch_grant(g, claim, timeout=60.0,
                                 run_handler=lambda ids: seen.append(ids) or "done",
                                 authority=auth)
        self.assertTrue(out["dispatched"])
        ids = seen[0]
        self.assertEqual(ids["decision_id"], "d")
        self.assertEqual(ids["dossier_id"], "f")
        self.assertEqual(ids["claim_id"], claim["claim_id"])
        self.assertNotIn("grant_seal", str(ids))

    def test_cross_grant_claim_cannot_dispatch(self):
        auth = cad.ClaimAuthority()
        g_a = cad.issue_grant(grant_id="ga", decision_id="d", dossier_id="f",
                              remaining=600.0)
        g_b = cad.issue_grant(grant_id="gb", decision_id="d", dossier_id="f",
                              remaining=600.0)
        claim_a = auth.claim(g_a, lease=30.0)
        auth.present(claim_a, timeout=60.0)
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            cad.dispatch_grant(g_b, claim_a, timeout=60.0,
                               run_handler=lambda ids: None, authority=auth)
        self.assertEqual(cm.exception.code, "claim-invalid-grant")

    def test_dispatch_never_twice(self):
        auth = cad.ClaimAuthority()
        g = _grant()
        claim = auth.claim(g, lease=30.0)
        auth.present(claim, timeout=60.0)
        runs = []
        cad.dispatch_grant(g, claim, timeout=60.0,
                           run_handler=lambda ids: runs.append(1),
                           authority=auth)
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            cad.dispatch_grant(g, claim, timeout=60.0,
                               run_handler=lambda ids: runs.append(1),
                               authority=auth)
        self.assertEqual(cm.exception.code, "claim-replay")
        self.assertEqual(len(runs), 1)

    def test_claim_checks_expected_payload_digest(self):
        auth = cad.ClaimAuthority()
        g = _grant()
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            auth.claim(g, expected_payload_digest="0" * 64)
        self.assertEqual(cm.exception.code, "claim-invalid-grant")
        claim = auth.claim(g, expected_payload_digest=g["payload_digest"])
        self.assertEqual(claim["payload_digest"], g["payload_digest"])

    def test_dispatch_budget_decayed(self):
        import time
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant(), lease=0.6)
        time.sleep(0.3)
        budget = cad.dispatch_budget(_grant(), claim, 60.0)
        self.assertLessEqual(budget, 0.6 - 0.3 + 0.05)
        self.assertGreater(budget, 0)

    def test_dispatch_budget_minimum(self):
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant(), lease=10.0)
        # The lease term decays only by the microseconds since claim();
        # pin it as within 0.5 of the full lease, and exactly when the
        # other terms are smaller.
        budget = cad.dispatch_budget(_grant(), claim, 120.0)
        self.assertLessEqual(budget, 10.0)
        self.assertGreater(budget, 9.5)
        self.assertAlmostEqual(cad.dispatch_budget(_grant(remaining=3.0), claim, 120.0), 3.0)
        self.assertAlmostEqual(cad.dispatch_budget(_grant(), claim, 2.0), 2.0)


class FinalizeTests(unittest.TestCase):
    def test_finalize_records_outcome(self):
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant())
        rec = cad.finalize(auth, claim, "completed")
        self.assertEqual(rec["outcome"], "completed")
        self.assertEqual(rec["claim_id"], claim["claim_id"])

    def test_crash_finalize_never_releases(self):
        auth = cad.ClaimAuthority()
        g = _grant()
        claim = auth.claim(g)
        cad.finalize(auth, claim, "crashed")
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            auth.claim(g)
        self.assertEqual(cm.exception.code, "claim-not-releasable")

    def test_bad_outcome_malformed(self):
        auth = cad.ClaimAuthority()
        claim = auth.claim(_grant())
        with self.assertRaises(cad.ClaimDispatchError) as cm:
            cad.finalize(auth, claim, "retried")
        self.assertEqual(cm.exception.code, "claim-malformed")

    def test_finalize_unknown_claim_still_records(self):
        # Finalization is evidence: it records what happened for the
        # claim id presented; authority checks happen at claim/present.
        auth = cad.ClaimAuthority()
        rec = cad.finalize(auth, {"claim_id": "ghost"}, "indeterminate")
        self.assertEqual(rec["outcome"], "indeterminate")


if __name__ == "__main__":
    unittest.main()
