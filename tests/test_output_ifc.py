"""Unit tests for gov/output_ifc.py (wave-268 IFC labels lane).

Covers the lattice laws (vendored Oak core), label assignment,
sink enforcement, taint combination, and the privilege ceremony at
the public seams. Deterministic; explicit ``now`` timestamps only.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import output_ifc as ifc  # noqa: E402

NOW = "2026-10-01T10:00:00Z"
LATER = "2026-10-01T10:01:00Z"
EXPIRED_NOW = "2026-10-01T12:00:00Z"

PRIV = {"declassification": ["credential"],
        "endorsement": ["user-verified"]}
AUTH = {"kind": "human-approval", "ref": "appr-9"}


def _grant(**kw):
    args = {"privilege": PRIV, "granted_by": "officer",
            "authorization": AUTH, "ttl_seconds": 3600, "now": NOW}
    args.update(kw)
    return ifc.issue_grant(**args)


def _audit():
    records = []

    def hook(record):
        records.append(record)
    return records, hook


class LatticeLawsTest(unittest.TestCase):
    def test_secrecy_join_is_union(self):
        a = ifc.SecrecyLabel(frozenset({"x"}))
        b = ifc.SecrecyLabel(frozenset({"y"}))
        self.assertEqual(a.join(b).tags, frozenset({"x", "y"}))

    def test_secrecy_meet_is_intersection(self):
        a = ifc.SecrecyLabel(frozenset({"x", "y"}))
        b = ifc.SecrecyLabel(frozenset({"y"}))
        self.assertEqual(a.meet(b).tags, frozenset({"y"}))

    def test_secrecy_no_write_down(self):
        high = ifc.SecrecyLabel(frozenset({"credential"}))
        low = ifc.SecrecyLabel(frozenset())
        self.assertTrue(low.can_flow_to(high))
        self.assertFalse(high.can_flow_to(low))

    def test_integrity_no_read_down(self):
        trusted = ifc.IntegrityLabel(frozenset({"user-verified"}))
        plain = ifc.IntegrityLabel(frozenset())
        # Target requiring trust can only be fed by trusted source.
        self.assertTrue(trusted.can_flow_to(
            ifc.IntegrityLabel(frozenset({"user-verified"}))))
        self.assertFalse(plain.can_flow_to(
            ifc.IntegrityLabel(frozenset({"user-verified"}))))

    def test_combined_label_flow_needs_both(self):
        src = ifc.Label(ifc.SecrecyLabel(frozenset({"c"})),
                        ifc.IntegrityLabel(frozenset({"user-verified"})))
        sink_ok = ifc.Label(ifc.SecrecyLabel(frozenset({"c"})),
                            ifc.IntegrityLabel(frozenset()))
        sink_bad = ifc.Label(ifc.SecrecyLabel(frozenset()),
                             ifc.IntegrityLabel(frozenset()))
        self.assertTrue(src.can_flow_to(sink_ok))
        self.assertFalse(src.can_flow_to(sink_bad))

    def test_join_meet_associativity(self):
        a = ifc.SecrecyLabel(frozenset({"a"}))
        b = ifc.SecrecyLabel(frozenset({"b"}))
        c = ifc.SecrecyLabel(frozenset({"c"}))
        self.assertEqual(a.join(b).join(c).tags,
                         a.join(b.join(c)).tags)
        self.assertEqual(a.meet(a.join(b)).tags, a.tags)  # absorption

    def test_reflexivity(self):
        lab = ifc.Label(ifc.SecrecyLabel(frozenset({"c"})),
                        ifc.IntegrityLabel(frozenset({"t"})))
        self.assertTrue(lab.can_flow_to(lab))


class AssignLabelTest(unittest.TestCase):
    def test_default_is_untrusted(self):
        lab = ifc.assign_label("web_fetch")
        self.assertEqual(lab, {"secrecy": [],
                               "integrity": ["tool-external"]})

    def test_registry_tool_tags(self):
        reg = {"tool_integrity": {"agent_draft": ["reviewed"]}}
        lab = ifc.assign_label("agent_draft", None, reg)
        self.assertEqual(lab["integrity"],
                         ["reviewed", "tool-external"])

    def test_assertable_tags_allowed(self):
        reg = {"assertable_tags": ["reviewed"]}
        lab = ifc.assign_label("t", {"integrity": ["reviewed"]}, reg)
        self.assertIn("reviewed", lab["integrity"])

    def test_unendorsed_trust_claim_refused(self):
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.assign_label("t", {"integrity": ["user-verified"]})
        self.assertEqual(ctx.exception.code, "ifc-privilege-denied")

    def test_malformed_inputs(self):
        for bad in (123, "", None.__class__ and b"x"):
            with self.assertRaises(ifc.OutputIFCError) as ctx:
                ifc.assign_label(bad)
            self.assertEqual(ctx.exception.code, "ifc-label-malformed",
                             bad)
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.assign_label("t", {"integrity": "user-verified"})
        self.assertEqual(ctx.exception.code, "ifc-label-malformed")

    def test_canonical_dict_sorted(self):
        lab = ifc.assign_label("t", {"secrecy": ["b", "a"]})
        self.assertEqual(lab["secrecy"], ["a", "b"])


class SinkTest(unittest.TestCase):
    def test_execution_requires_endorsement(self):
        lab = ifc.assign_label("web_fetch")
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.check_sink(lab, "execution")
        self.assertEqual(ctx.exception.code, "ifc-integrity-flow-denied")

    def test_secret_egress_refused(self):
        lab = ifc.assign_label("t", {"secrecy": ["credential"]})
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.check_sink(lab, "egress")
        self.assertEqual(ctx.exception.code, "ifc-secrecy-flow-denied")

    def test_public_egress_allowed(self):
        r = ifc.check_sink(ifc.assign_label("t"), "egress")
        self.assertTrue(r["allowed"])
        self.assertEqual(r["sink"], "egress")

    def test_journal_accepts_untrusted(self):
        r = ifc.check_sink(ifc.assign_label("t"), "journal")
        self.assertTrue(r["allowed"])

    def test_unknown_sink(self):
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.check_sink(ifc.assign_label("t"), "elsewhere")
        self.assertEqual(ctx.exception.code, "ifc-sink-unmapped")

    def test_custom_sink_policy(self):
        lab = ifc.assign_label("t", {"secrecy": ["credential"]})
        pol = {"name": "vault", "secrecy": ["credential"],
               "integrity": []}
        r = ifc.check_sink(lab, pol)
        self.assertTrue(r["allowed"])


class CombineTest(unittest.TestCase):
    def _endorsed(self, lab):
        records, hook = _audit()
        return ifc.exercise_privilege(
            _grant(), lab, "endorse", ["user-verified"], hook,
            LATER)["label"]

    def test_integrity_meet_blocks_tainted(self):
        good = self._endorsed(ifc.assign_label("agent_draft"))
        bad = ifc.assign_label("web_fetch")
        combo = ifc.combine_outputs(good, bad)
        self.assertEqual(combo["integrity"], ["tool-external"])
        self.assertNotIn("user-verified", combo["integrity"])
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.check_sink(combo, "execution")
        self.assertEqual(ctx.exception.code, "ifc-integrity-flow-denied")

    def test_secrecy_join_propagates(self):
        secret = ifc.assign_label("db", {"secrecy": ["credential"]})
        public = ifc.assign_label("web")
        combo = ifc.combine_outputs(secret, public)
        self.assertEqual(combo["secrecy"], ["credential"])

    def test_needs_at_least_one(self):
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.combine_outputs()
        self.assertEqual(ctx.exception.code, "ifc-label-malformed")


class PrivilegeTest(unittest.TestCase):
    def test_issue_grant_deterministic_digest(self):
        self.assertEqual(_grant(), _grant())

    def test_bad_authorization_kinds(self):
        for auth in ({"kind": "self-asserted", "ref": "x"},
                     {"kind": "human-approval", "ref": ""},
                     "nope"):
            with self.assertRaises(ifc.OutputIFCError) as ctx:
                _grant(authorization=auth)
            self.assertEqual(ctx.exception.code,
                             "ifc-privilege-unauthorized", auth)

    def test_declassify_legit(self):
        records, hook = _audit()
        lab = ifc.assign_label("db", {"secrecy": ["credential"]})
        res = ifc.exercise_privilege(_grant(), lab, "declassify",
                                     ["credential"], hook, LATER)
        self.assertEqual(res["label"]["secrecy"], [])
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["operation"], "declassify")
        self.assertEqual(rec["tags"], ["credential"])
        self.assertEqual(rec["label_before"]["secrecy"], ["credential"])
        self.assertEqual(rec["label_after"]["secrecy"], [])

    def test_endorse_legit(self):
        records, hook = _audit()
        lab = ifc.assign_label("draft")
        res = ifc.exercise_privilege(_grant(), lab, "endorse",
                                     ["user-verified"], hook, LATER)
        self.assertEqual(res["label"]["integrity"],
                         ["tool-external", "user-verified"])

    def test_no_privilege(self):
        records, hook = _audit()
        grant = _grant(privilege={"declassification": [],
                                  "endorsement": []})
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, ifc.assign_label("t"),
                                   "declassify", ["credential"], hook,
                                   LATER)
        self.assertEqual(ctx.exception.code, "ifc-privilege-denied")

    def test_scope_exceeded(self):
        records, hook = _audit()
        grant = _grant(privilege={"declassification": ["public"],
                                  "endorsement": []})
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, ifc.assign_label("t"),
                                   "declassify", ["credential"], hook,
                                   LATER)
        self.assertEqual(ctx.exception.code,
                         "ifc-privilege-scope-denied")

    def test_expired(self):
        records, hook = _audit()
        grant = _grant(ttl_seconds=60)
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, ifc.assign_label("t"),
                                   "declassify", ["credential"], hook,
                                   EXPIRED_NOW)
        self.assertEqual(ctx.exception.code, "ifc-privilege-expired")

    def test_no_audit_hook_refused(self):
        grant = _grant()
        lab = ifc.assign_label("db", {"secrecy": ["credential"]})
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, lab, "declassify",
                                   ["credential"], None, LATER)
        self.assertEqual(ctx.exception.code, "ifc-audit-required")

    def test_tampered_grant_detected(self):
        records, hook = _audit()
        grant = dict(_grant())
        grant["privilege"] = {"declassification": ["credential"],
                              "endorsement": ["root"]}
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, ifc.assign_label("t"),
                                   "endorse", ["root"], hook, LATER)
        self.assertEqual(ctx.exception.code,
                         "ifc-privilege-unauthorized")

    def test_codes_tuple_live(self):
        self.assertEqual(tuple(sorted(ifc.CODES)), ifc.CODES)
        for code in ifc.CODES:
            self.assertIn(code, __import__(
                "gov.decision_codes", fromlist=["TAXONOMY"]).TAXONOMY)


if __name__ == "__main__":
    unittest.main()
