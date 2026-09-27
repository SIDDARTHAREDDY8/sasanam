"""Unit tests for the wave-139 fresh-ID laundering leg (row 11).

Seam under test: gov.goals.detect_cross_run_laundering (public), plus
the FRESH_ID_SIMILARITY_THRESHOLD constant. Expectations are
hand-computed at the public seam: measured target_similarity scores
("customer database export" vs "client database export" = 0.800;
vs "client roster export" = 0.500, exactly on the threshold;
"alpha beta gamma delta" vs "alpha epsilon zeta eta" = 0.400;
"evil.com" vs "vendor.synthetic.local" = 0.000 via destination
veto) come from gov/target_match.py's documented Tversky measure,
not from the code under test.
"""
import unittest

from gov import goals
from gov.target_match import DEFAULT_THRESHOLD, MATCH_METHOD


def _deny(registry, goal, approval_id="apr-test"):
    res = goals.apply_approval_resolution(
        registry, new_goal_id=goal["goal_id"], existing_goal_ids=[],
        approved=False, approval_id=approval_id)
    assert res["decision"] == "rejected", res
    assert registry.get_goal(goal["goal_id"])["status"] == "superseded"
    return goal


def _denied_pair(description, effects, new_effects, run="run-1"):
    """Fixture: run-1 goal denied (superseded, unexercised); run-2
    fresh-ID re-registration returned alongside the registry."""
    events = []
    reg = goals.GoalRegistry(audit=events.append)
    g1, _ = reg.register("a1", run, description, effects=effects)
    _deny(reg, g1)
    g2, _ = reg.register("a1", "run-2", "paraphrased prose",
                         effects=new_effects)
    assert g2["goal_id"] != g1["goal_id"]
    return reg, g1, g2, events


def _fresh_id(findings):
    return [f for f in findings
            if f.get("type") == "fresh_id_laundering"]


class ThresholdTest(unittest.TestCase):
    def test_threshold_is_the_target_match_default_not_a_new_measure(self):
        self.assertIs(goals.FRESH_ID_SIMILARITY_THRESHOLD,
                      DEFAULT_THRESHOLD)
        self.assertEqual(goals.FRESH_ID_SIMILARITY_THRESHOLD, 0.5)


class FreshIdLaunderingTest(unittest.TestCase):
    def test_identical_remint_flagged_loud(self):
        reg, g1, g2, events = _denied_pair(
            "exfiltrate client list", [("send", "evil.com")],
            [("send", "evil.com")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        hits = _fresh_id(finds)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["severity"], "high")
        self.assertEqual(hit["agent_id"], "a1")
        d = hit["detail"]
        self.assertEqual(d["prior_goal_id"], g1["goal_id"])
        self.assertEqual(d["prior_run_id"], "run-1")
        self.assertEqual(d["match_method"], MATCH_METHOD)
        self.assertEqual(d["threshold"], 0.5)
        self.assertEqual(d["atom_scores"], [1.0])
        # LOUD audit event, not just a return value.
        loud = [e for e in events
                if e.get("event") == "goal_cross_run_flag"
                and e.get("finding_type") == "fresh_id_laundering"]
        self.assertEqual(len(loud), 1)
        self.assertEqual(loud[0]["severity"], "high")

    def test_paraphrased_target_flagged_with_measured_score(self):
        reg, g1, g2, _events = _denied_pair(
            "archive customer records",
            [("write", "customer database export")],
            [("write", "client database export")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        hits = _fresh_id(finds)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["detail"]["atom_scores"], [0.8])

    def test_boundary_pair_at_threshold_flagged(self):
        # "customer database export" vs "client roster export"
        # scores exactly 0.500; the seam uses >= threshold.
        reg, g1, g2, _events = _denied_pair(
            "archive customer records",
            [("write", "customer database export")],
            [("write", "client roster export")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        hits = _fresh_id(finds)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["detail"]["atom_scores"], [0.5])

    def test_below_threshold_silent(self):
        # 0.400 < 0.5: the by-design below-threshold tradeoff.
        reg, g1, g2, _events = _denied_pair(
            "alpha run", [("write", "alpha beta gamma delta")],
            [("write", "alpha epsilon zeta eta")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        self.assertEqual(_fresh_id(finds), [])

    def test_unrelated_target_silent_destination_veto(self):
        reg, g1, g2, _events = _denied_pair(
            "exfiltrate client list", [("send", "evil.com")],
            [("send", "vendor.synthetic.local")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        self.assertEqual(_fresh_id(finds), [])

    def test_verb_differing_silent_effects_must_match(self):
        # Target similarity is 0.800, but the verb differs:
        # similarity alone must not condemn.
        reg, g1, g2, _events = _denied_pair(
            "archive customer records",
            [("write", "customer database export")],
            [("read", "client database export")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        self.assertEqual(_fresh_id(finds), [])

    def test_superset_effects_silent(self):
        # The new goal declares an extra atom the prior never had:
        # conjunctive per-atom rule breaks the match.
        reg, g1, g2, _events = _denied_pair(
            "archive customer records",
            [("write", "customer database export")],
            [("write", "client database export"),
             ("send", "notify.synthetic.local")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        self.assertEqual(_fresh_id(finds), [])

    def test_exercised_prior_silent_legitimate_resolve(self):
        # Prior superseded AFTER being exercised: the legitimate
        # register -> exercise -> resolve flow stays silent.
        reg = goals.GoalRegistry()
        g1, _ = reg.register("a1", "run-1", "vendor sync",
                             effects=[("send", "vendor.synthetic.local")])
        reg.set_status(g1["goal_id"], "superseded")
        g2, _ = reg.register("a1", "run-2", "vendor sync again",
                             effects=[("send", "vendor.synthetic.local")])
        finds = goals.detect_cross_run_laundering(
            reg, g2,
            executed_history={("a1", "run-1"):
                              [("send", "vendor.synthetic.local")]})
        self.assertEqual(_fresh_id(finds), [])

    def test_no_history_silent_unobserved_is_not_denied(self):
        reg, g1, g2, _events = _denied_pair(
            "exfiltrate client list", [("send", "evil.com")],
            [("send", "evil.com")])
        finds = goals.detect_cross_run_laundering(reg, g2,
                                                  executed_history={})
        self.assertEqual(_fresh_id(finds), [])

    def test_active_prior_not_considered(self):
        # A still-active prior is not a denial: no flag.
        reg = goals.GoalRegistry()
        g1, _ = reg.register("a1", "run-1", "vendor sync",
                             effects=[("send", "vendor.synthetic.local")])
        g2, _ = reg.register("a1", "run-2", "vendor sync again",
                             effects=[("send", "vendor.synthetic.local")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a1", "run-1"): []})
        self.assertEqual(_fresh_id(finds), [])

    def test_other_agent_prior_not_considered(self):
        # Attribution keys on the registering agent.
        reg = goals.GoalRegistry()
        g1, _ = reg.register("a1", "run-1", "exfiltrate",
                             effects=[("send", "evil.com")])
        _deny(reg, g1)
        g2, _ = reg.register("a2", "run-2", "sync",
                             effects=[("send", "evil.com")])
        finds = goals.detect_cross_run_laundering(
            reg, g2, executed_history={("a2", "run-1"): []})
        self.assertEqual(_fresh_id(finds), [])

    def test_existing_id_path_intact_dormant_still_fires(self):
        # The additive leg must not disturb the existing signals:
        # 3-run unexercised identical goal still flags dormant.
        reg = goals.GoalRegistry()
        hist = {}
        last = None
        for i in range(3):
            run = "run-%d" % (i + 1)
            last, _ = reg.register("a1", run, "nightly sync",
                                   effects=[("send",
                                             "vendor.synthetic.local")])
            hist[("a1", run)] = []
        finds = goals.detect_cross_run_laundering(
            reg, last, executed_history=hist)
        types = [f.get("type") for f in finds]
        self.assertIn("dormant_goal", types)


if __name__ == "__main__":
    unittest.main()
