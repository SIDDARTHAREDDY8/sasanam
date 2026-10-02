"""Unit tests for gov.posture_cards (wave-251 lane 1).

Pin the public contract: card shape, fail-closed state reads, track
levels, VSA-style summary issue/verify, and the taxonomy pin.
"""

import json
import unittest

from gov import decision_codes as dc
from gov import ed25519
from gov import posture_cards as pc


def _full_state():
    return {
        "assessed_at": "2026-09-30T00:00:00Z",
        "skill_admission": {
            "authority_pub": "ab" * 32,
            "admitted_layouts": 3,
        },
        "skill_update": {
            "pin": {"digest": "cd" * 32,
                    "not_after": "2027-01-01T00:00:00Z"},
        },
        "agent_identity": {
            "connector": "oidc",
            "subject_source": "sub",
        },
        "policy": {
            "combiner_active": True,
            "decision_log": {"root": "ef" * 32},
        },
        "evidence": {
            "enveloped_exports": 5,
            "graph": {"nodes": 12},
        },
        "durability": {
            "permit_journal": {"tip": "01" * 32},
        },
    }


class CardShapeTest(unittest.TestCase):
    def test_all_tracks_covered(self):
        cards = pc.assess(_full_state())
        tracks = {c["track"] for c in cards}
        self.assertEqual(tracks, set(pc.TRACKS))

    def test_card_keys_and_sort(self):
        cards = pc.assess(_full_state())
        keys = [(c["track"], c["check"]) for c in cards]
        self.assertEqual(keys, sorted(keys))
        for c in cards:
            self.assertEqual(set(c),
                             {"check", "track", "probe", "score",
                              "reason", "remediation"})
            self.assertIn(c["probe"], ("pass", "fail", "unavailable"))
            self.assertTrue(0 <= c["score"] <= 10)

    def test_full_state_all_pass(self):
        for c in pc.assess(_full_state()):
            self.assertEqual(c["probe"], "pass", c["check"])
            self.assertEqual(c["score"], 10, c["check"])

    def test_assess_non_dict_refuses(self):
        with self.assertRaises(pc.PostureCardError) as ctx:
            pc.assess("nope")
        self.assertEqual(ctx.exception.code, "posture-card-malformed")


class FailClosedTest(unittest.TestCase):
    def test_missing_section_unavailable(self):
        state = _full_state()
        del state["durability"]
        card = {c["check"]: c for c in pc.assess(state)}
        self.assertEqual(card["permit-journal-active"]["probe"],
                         "unavailable")

    def test_bad_authority_key_fails(self):
        state = _full_state()
        state["skill_admission"]["authority_pub"] = "zz"
        card = {c["check"]: c for c in pc.assess(state)}
        self.assertEqual(card["skill-admission-configured"]["probe"],
                         "fail")

    def test_unsupported_connector_fails(self):
        state = _full_state()
        state["agent_identity"]["connector"] = "saml"
        card = {c["check"]: c for c in pc.assess(state)}
        self.assertEqual(
            card["federated-identity-configured"]["probe"], "fail")

    def test_malformed_timestamp_fails(self):
        state = _full_state()
        state["skill_update"]["pin"]["not_after"] = "tomorrow"
        card = {c["check"]: c for c in pc.assess(state)}
        self.assertEqual(card["tuf-pins-fresh"]["probe"], "fail")


class TrackLevelTest(unittest.TestCase):
    def test_full_partial_absent(self):
        full = pc.assess(_full_state())
        self.assertEqual(pc.track_level(full, "evidence"), "full")
        state = _full_state()
        state["evidence"]["enveloped_exports"] = 0
        partial = pc.assess(state)
        self.assertEqual(pc.track_level(partial, "evidence"), "partial")
        self.assertEqual(pc.track_level([], "evidence"), "absent")

    def test_unknown_track_refuses(self):
        with self.assertRaises(pc.PostureCardError) as ctx:
            pc.track_level([], "nope")
        self.assertEqual(ctx.exception.code,
                         "posture-card-unknown-track")


class SummaryTest(unittest.TestCase):
    def _issue(self):
        seed = b"\x77" * 32
        cards = pc.assess(_full_state())
        return pc.issue_summary("deployment:staging-1", cards, seed,
                                issuer="auditor:local",
                                issued_at="2026-09-30T00:00:00Z")

    def test_roundtrip(self):
        record = pc.verify_summary(self._issue())
        self.assertEqual(record["subject"], "deployment:staging-1")
        self.assertEqual(record["issuer"], "auditor:local")
        self.assertEqual(record["v"], 1)
        levels = {t["track"]: t["level"] for t in record["tracks"]}
        self.assertEqual(levels["supply-chain"], "full")

    def test_tampered_level_refused(self):
        summary = self._issue()
        forged = json.loads(json.dumps(summary))
        forged["record"]["tracks"][0]["level"] = "absent"
        with self.assertRaises(pc.PostureCardError) as ctx:
            pc.verify_summary(forged)
        self.assertEqual(ctx.exception.code,
                         "posture-card-unverifiable")

    def test_wrong_key_refused(self):
        summary = self._issue()
        other = ed25519.publickey(b"\x88" * 32).hex()
        summary["pub"] = other
        with self.assertRaises(pc.PostureCardError) as ctx:
            pc.verify_summary(summary)
        self.assertEqual(ctx.exception.code,
                         "posture-card-unverifiable")

    def test_malformed_summary_refused(self):
        with self.assertRaises(pc.PostureCardError) as ctx:
            pc.verify_summary({"record": {}})
        self.assertEqual(ctx.exception.code, "posture-card-malformed")

    def test_bad_seed_refuses(self):
        with self.assertRaises(pc.PostureCardError) as ctx:
            pc.issue_summary("s", [], b"short", issuer="i",
                             issued_at="2026-09-30T00:00:00Z")
        self.assertEqual(ctx.exception.code, "posture-card-malformed")

    def test_deterministic(self):
        self.assertEqual(self._issue(), self._issue())


class TaxonomyPinTest(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Wave-251 lane 1: re-pointed to 1000 (997 + 3 posture-card
        # codes), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1587)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*)
        for code in ("posture-card-malformed",
                     "posture-card-unverifiable",
                     "posture-card-unknown-track"):
            self.assertIn(code, dc.TAXONOMY)


if __name__ == "__main__":
    unittest.main()
