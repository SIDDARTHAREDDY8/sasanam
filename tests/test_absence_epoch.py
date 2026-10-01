"""Unit tests for gov/absence_epoch.py (wave-242 lane D, W242-9).

Deterministic: fixed epoch numbers and injected times; fixed seeds.
"""

import json
import unittest

from gov import absence_epoch as ax


EPOCH = 41000
T_OPEN = EPOCH * 3600
T_MID = T_OPEN + 1800
T_CLOSE = T_OPEN + 3600
SCOPE = "egress:corp-net"
BEACON_SEED = bytes(range(32))
OBSERVER_SEED = bytes([200]) * 32


def _beacon():
    return ax.open_epoch(BEACON_SEED, EPOCH, "00" * 32, T_OPEN)


class EpochMathTest(unittest.TestCase):
    def test_epoch_of(self):
        self.assertEqual(ax.epoch_of(T_OPEN), EPOCH)
        self.assertEqual(ax.epoch_of(T_OPEN + 3599), EPOCH)
        self.assertEqual(ax.epoch_of(T_OPEN + 3600), EPOCH + 1)

    def test_epoch_seconds(self):
        self.assertEqual(ax.EPOCH_SECONDS, 3600)


class BeaconTest(unittest.TestCase):
    def test_open_epoch_shape(self):
        beacon = _beacon()
        self.assertEqual(beacon["epoch"], EPOCH)
        self.assertEqual(beacon["beacon_pub"], ax.pub_of(BEACON_SEED))
        self.assertEqual(len(beacon["sig"]), 128)

    def test_pub_of_deterministic(self):
        self.assertEqual(ax.pub_of(BEACON_SEED), ax.pub_of(BEACON_SEED))
        self.assertNotEqual(ax.pub_of(BEACON_SEED),
                            ax.pub_of(OBSERVER_SEED))

    def test_bad_seed_refused(self):
        with self.assertRaises(ax.AbsenceEpochError) as ctx:
            ax.pub_of(b"short")
        self.assertEqual(ctx.exception.code, "absence-epoch-malformed")


class MerkleTest(unittest.TestCase):
    def test_empty_root_stable(self):
        self.assertEqual(ax.smt_root([]), ax.smt_root([]))

    def test_root_changes_with_leaf(self):
        r1 = ax.smt_root([(b"k" * 32, b"v" * 32)])
        r2 = ax.smt_root([(b"k" * 32, b"w" * 32)])
        self.assertNotEqual(r1, r2)

    def test_root_order_independent(self):
        pairs = [(b"a" * 32, b"1" * 32), (b"b" * 32, b"2" * 32)]
        self.assertEqual(ax.smt_root(pairs),
                         ax.smt_root(list(reversed(pairs))))

    def test_two_leaves_share_root_with_ledger(self):
        beacon = _beacon()
        o1 = ax.observe_absence(OBSERVER_SEED, beacon, SCOPE, T_MID)
        o2 = ax.observe_absence(OBSERVER_SEED, beacon, "other", T_MID + 5)
        ledger = {SCOPE: o1, "other": o2}
        close = ax.close_epoch(BEACON_SEED, EPOCH, ledger, "00" * 32,
                               T_CLOSE)
        self.assertEqual(len(close["root"]), 64)


class ObservationTest(unittest.TestCase):
    def test_observe_outside_epoch_refused(self):
        beacon = _beacon()
        with self.assertRaises(ax.AbsenceEpochError) as ctx:
            ax.observe_absence(OBSERVER_SEED, beacon, SCOPE, T_OPEN - 1)
        self.assertEqual(ctx.exception.code, "absence-backdated")

    def test_observe_after_close_refused(self):
        beacon = _beacon()
        close = ax.close_epoch(BEACON_SEED, EPOCH, {}, "00" * 32, T_CLOSE)
        with self.assertRaises(ax.AbsenceEpochError) as ctx:
            ax.observe_absence(OBSERVER_SEED, beacon, SCOPE, T_MID,
                               closed_epochs={str(EPOCH): close})
        self.assertEqual(ctx.exception.code, "absence-epoch-closed")

    def test_resign_amends_honestly(self):
        beacon = _beacon()
        obs = ax.observe_absence(OBSERVER_SEED, beacon, SCOPE, T_MID)
        obs2 = dict(obs)
        obs2["observed_at"] = T_MID + 1
        resigned = ax.resign_observation(OBSERVER_SEED, obs2)
        self.assertNotEqual(resigned["sig"], obs["sig"])
        self.assertEqual(resigned["observed_at"], T_MID + 1)


class VerifyTest(unittest.TestCase):
    def _bundle(self, ledger):
        beacon = _beacon()
        close = ax.close_epoch(BEACON_SEED, EPOCH, ledger, "00" * 32,
                               T_CLOSE)
        return ax.make_bundle(
            [beacon], [close], {str(EPOCH): ledger},
            {"beacon": ax.pub_of(BEACON_SEED),
             "observer": ax.pub_of(OBSERVER_SEED)}), beacon, close

    def test_happy_path(self):
        beacon = _beacon()
        ledger = {SCOPE: ax.observe_absence(OBSERVER_SEED, beacon, SCOPE,
                                           T_MID)}
        bundle, _b, _c = self._bundle(ledger)
        self.assertTrue(ax.verify_absence(bundle, EPOCH, SCOPE,
                                          ax.pub_of(OBSERVER_SEED)))

    def test_no_beacon(self):
        bundle, _b, _c = self._bundle({})
        bundle["beacons"] = []
        with self.assertRaises(ax.AbsenceEpochError) as ctx:
            ax.verify_absence(bundle, EPOCH, SCOPE,
                              ax.pub_of(OBSERVER_SEED))
        self.assertEqual(ctx.exception.code, "absence-epoch-not-open")

    def test_no_close(self):
        beacon = _beacon()
        bundle = ax.make_bundle([beacon], [], {str(EPOCH): {}},
                                {"beacon": ax.pub_of(BEACON_SEED)})
        with self.assertRaises(ax.AbsenceEpochError) as ctx:
            ax.verify_absence(bundle, EPOCH, SCOPE,
                              ax.pub_of(OBSERVER_SEED))
        self.assertEqual(ctx.exception.code, "absence-epoch-not-closed")

    def test_wrong_observer(self):
        beacon = _beacon()
        ledger = {SCOPE: ax.observe_absence(OBSERVER_SEED, beacon, SCOPE,
                                           T_MID)}
        bundle, _b, _c = self._bundle(ledger)
        with self.assertRaises(ax.AbsenceEpochError) as ctx:
            ax.verify_absence(bundle, EPOCH, SCOPE,
                              ax.pub_of(bytes([9]) * 32))
        self.assertEqual(ctx.exception.code,
                         "absence-observation-unsigned")

    def test_bundle_json_round_trip(self):
        beacon = _beacon()
        ledger = {SCOPE: ax.observe_absence(OBSERVER_SEED, beacon, SCOPE,
                                           T_MID)}
        bundle, _b, _c = self._bundle(ledger)
        reloaded = json.loads(json.dumps(bundle))
        self.assertTrue(ax.verify_absence(reloaded, EPOCH, SCOPE,
                                          ax.pub_of(OBSERVER_SEED)))

    def test_error_carries_code(self):
        err = ax.AbsenceEpochError("absence-backdated", "d")
        self.assertEqual(err.code, "absence-backdated")
        self.assertIn("absence-backdated", str(err))


class TaxonomyTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        # Wave-242 merge: re-pointed 776 -> 788 (22 new codes:
        # 5 aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only.
        from gov import decision_codes as dc
        for code in ("absence-epoch-beacon-unsigned",
                     "absence-epoch-not-open",
                     "absence-epoch-not-closed",
                     "absence-epoch-closed",
                     "absence-epoch-malformed",
                     "absence-backdated",
                     "absence-root-mismatch",
                     "absence-disclosure-recorded",
                     "absence-not-observed",
                     "absence-observation-unsigned"):
            dc.code_for(code)
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-254 merge: re-pointed to 1029 (1017 + 5 approval-policy + 7 compliance-emitter), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1029)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
