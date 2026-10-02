"""Unit tests for gov/trust_vector.py (wave-287 lane 8, veraison STEAL).

Covers: vector grading semantics, the no-endorsement=>insufficient
structural rule, endorsement independence, scheme grammar fail-closed,
policy pinning, the require_affirmed gate (including the exception
routing and the never-upgrade-contraindication invariant), the scheme
plugin registry, and determinism of digests.
"""

import hashlib
import json
import os
import tempfile
import time
import unittest

from gov import trust_vector as tv
from gov import governed_exceptions as ge


def _scheme(scheme_id="ut-firmware/v1"):
    desc = tv.SchemeDescriptor(
        scheme_id=scheme_id,
        claim_grammar={"fw_digest": "digest",
                       "fw_version": "str",
                       "debug_fuse": "bool"},
        dimensions=[
            {"name": "sw_integrity", "rule": "endorsed-match",
             "claims": ["fw_digest"]},
            {"name": "sw_up_to_dateness", "rule": "endorsed-match",
             "claims": ["fw_version"]},
            {"name": "config_integrity", "rule": "operator-trust",
             "claims": ["debug_fuse"]},
        ])
    try:
        tv.register_scheme(desc)
    except tv.TrustVectorError as e:
        if e.code != tv.SCHEME_DUPLICATE:
            raise
    return desc


def _evidence(producer="prod-a", **over):
    claims = {"fw_digest": "ab" * 32,
              "fw_version": "1.2.3",
              "debug_fuse": False}
    claims.update(over)
    return tv.submit_evidence("ut-firmware/v1", claims, producer)


def _policy(policy_id="ut-policy", anchors=None):
    return tv.compile_policy({
        "format": "sasanam-appraisal-policy/v1",
        "policy_id": policy_id,
        "scheme_id": "ut-firmware/v1",
        "trusted_producers": anchors or {},
    })


def _pins(policy, digest=None):
    d = tempfile.mkdtemp(prefix="ut-ear-pin-")
    path = os.path.join(d, "pins.json")
    tv.pin_appraisal_policy(policy.policy_id,
                            digest if digest is not None else policy.digest,
                            path)
    return tv.load_appraisal_pins(path)


def _store(live=True):
    reg = ge.CheckRegistry()
    reg.register("SAS_TRUSTVEC_ACCEPT_RISK", "trust-vector accept risk",
                 "attestation", "medium",
                 "accept an insufficient trust vector at operator risk",
                 ["policy"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["op-1"])
    now = time.time()
    if live:
        store.grant("SAS_TRUSTVEC_ACCEPT_RISK", ("policy", "ut-policy"),
                    "accepting insufficient vector at operator risk",
                    "op-1", now + 3600, now - 5, now=now)
    return store


class TestGrades(unittest.TestCase):
    def test_matching_endorsement_affirms(self):
        _scheme()
        ev = _evidence()
        pol = _policy(anchors={"prod-a": "key-1"})
        ends = [tv.endorse(ev, "fw_digest", "ab" * 32, "end-1"),
                tv.endorse(ev, "fw_version", "1.2.3", "end-1")]
        ear = tv.appraise(ev, ends, pol, _pins(pol))
        self.assertEqual(ear["vector"]["sw_integrity"], "affirmed")
        self.assertEqual(ear["vector"]["sw_up_to_dateness"], "affirmed")
        self.assertEqual(ear["vector"]["config_integrity"], "affirmed")
        self.assertEqual(ear["overall"], "affirmed")

    def test_mismatch_contraindicates_and_surfaces(self):
        _scheme()
        ev = _evidence()
        pol = _policy(anchors={"prod-a": "key-1"})
        end = tv.endorse(ev, "fw_digest", "ff" * 32, "end-1")
        ear = tv.appraise(ev, [end], pol, _pins(pol))
        self.assertEqual(ear["vector"]["sw_integrity"], "contraindicated")
        self.assertNotEqual(ear["overall"], "affirmed")

    def test_no_endorsement_never_affirmed(self):
        _scheme()
        ev = _evidence()
        pol = _policy()
        ear = tv.appraise(ev, [], pol, _pins(pol))
        for dim, grade in ear["vector"].items():
            self.assertNotEqual(grade, "affirmed", dim)
        self.assertNotEqual(ear["overall"], "affirmed")

    def test_operator_trust_needs_anchor(self):
        _scheme()
        ev = _evidence()
        pol = _policy()  # prod-a not anchored
        ear = tv.appraise(ev, [], pol, _pins(pol))
        self.assertEqual(ear["vector"]["config_integrity"], "insufficient")
        pol2 = _policy(policy_id="ut-policy-2", anchors={"prod-a": "k"})
        ear2 = tv.appraise(ev, [], pol2, _pins(pol2))
        self.assertEqual(ear2["vector"]["config_integrity"], "affirmed")

    def test_endorsement_wrong_evidence_refused(self):
        _scheme()
        ev = _evidence()
        ev2 = _evidence(producer="prod-b")
        pol = _policy()
        end = tv.endorse(ev2, "fw_digest", "ab" * 32, "end-1")
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.appraise(ev, [end], pol, _pins(pol))
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)


class TestFailClosed(unittest.TestCase):
    def test_unknown_scheme(self):
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.submit_evidence("nope/v0", {}, "p")
        self.assertEqual(cm.exception.code, tv.SCHEME_UNKNOWN)

    def test_missing_claim(self):
        _scheme()
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.submit_evidence("ut-firmware/v1",
                               {"fw_digest": "ab" * 32}, "p")
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)

    def test_wrong_claim_type(self):
        _scheme()
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.submit_evidence(
                "ut-firmware/v1",
                {"fw_digest": "zz", "fw_version": "1.2.3",
                 "debug_fuse": False}, "p")
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)

    def test_extra_claim(self):
        _scheme()
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.submit_evidence(
                "ut-firmware/v1",
                {"fw_digest": "ab" * 32, "fw_version": "1.2.3",
                 "debug_fuse": False, "nope": 1}, "p")
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)

    def test_nonjson_claim_refused_coded(self):
        # F344: a set nested in a list claim must refuse LOUD with the
        # coded trustvec-evidence-invalid, never an uncoded TypeError.
        desc = tv.SchemeDescriptor(scheme_id="ut-nonjson/v1",
                                   claim_grammar={"items": "list"},
                                   dimensions=[])
        try:
            tv.register_scheme(desc)
        except tv.TrustVectorError as e:
            if e.code != tv.SCHEME_DUPLICATE:
                raise
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.submit_evidence("ut-nonjson/v1",
                               {"items": [{"s": {1, 2}}]}, "p")
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)

    def test_self_endorsement_refused(self):
        _scheme()
        ev = _evidence(producer="prod-a")
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.endorse(ev, "fw_digest", "ab" * 32, "prod-a")
        self.assertEqual(cm.exception.code,
                         tv.ENDORSEMENT_NOT_INDEPENDENT)

    def test_endorse_unknown_claim(self):
        _scheme()
        ev = _evidence()
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.endorse(ev, "nope", "x", "end-1")
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)

    def test_policy_unpinned(self):
        _scheme()
        ev = _evidence()
        pol = _policy()
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.appraise(ev, [], pol, {})
        self.assertEqual(cm.exception.code, tv.POLICY_UNPINNED)

    def test_policy_drift(self):
        _scheme()
        ev = _evidence()
        pol = _policy()
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.appraise(ev, [], pol, _pins(pol, digest="00" * 32))
        self.assertEqual(cm.exception.code, tv.POLICY_DRIFT)

    def test_policy_bad_format(self):
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.compile_policy({"format": "nope"})
        self.assertEqual(cm.exception.code, tv.POLICY_INVALID)

    def test_policy_scheme_mismatch(self):
        _scheme()
        ev = _evidence()
        pol = tv.compile_policy({
            "format": "sasanam-appraisal-policy/v1",
            "policy_id": "ut-policy-x",
            "scheme_id": "ut-firmware/v1",
            "trusted_producers": {}})
        # evidence scheme != policy scheme: build a second scheme
        desc = tv.SchemeDescriptor(
            scheme_id="ut-other/v1",
            claim_grammar={"fw_digest": "digest"},
            dimensions=[{"name": "d", "rule": "advisory",
                         "claims": ["fw_digest"]}])
        try:
            tv.register_scheme(desc)
        except tv.TrustVectorError as e:
            if e.code != tv.SCHEME_DUPLICATE:
                raise
        ev2 = tv.submit_evidence("ut-other/v1",
                                 {"fw_digest": "ab" * 32}, "prod-a")
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.appraise(ev2, [], pol, _pins(pol))
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)


class TestRequireAffirmed(unittest.TestCase):
    def _affirmed_ear(self):
        _scheme()
        ev = _evidence()
        pol = _policy(anchors={"prod-a": "key-1"})
        ends = [tv.endorse(ev, "fw_digest", "ab" * 32, "end-1"),
                tv.endorse(ev, "fw_version", "1.2.3", "end-1")]
        return tv.appraise(ev, ends, pol, _pins(pol))

    def test_affirmed_passes(self):
        ear = self._affirmed_ear()
        res = tv.require_affirmed(ear)
        self.assertEqual(res["status"], "affirmed")

    def test_contraindicated_refuses(self):
        _scheme()
        ev = _evidence()
        pol = _policy(anchors={"prod-a": "key-1"})
        end = tv.endorse(ev, "fw_digest", "ff" * 32, "end-1")
        ear = tv.appraise(ev, [end], pol, _pins(pol))
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.require_affirmed(ear)
        self.assertEqual(cm.exception.code,
                         tv.APPRAISAL_CONTRAINDICATED)

    def test_contraindicated_never_upgraded_by_exception(self):
        _scheme()
        ev = _evidence()
        pol = _policy(policy_id="ut-policy",
                      anchors={"prod-a": "key-1"})
        end = tv.endorse(ev, "fw_digest", "ff" * 32, "end-1")
        ear = tv.appraise(ev, [end], pol, _pins(pol))
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.require_affirmed(ear, exception_store=_store(live=True))
        self.assertEqual(cm.exception.code,
                         tv.APPRAISAL_CONTRAINDICATED)

    def test_insufficient_without_store_refuses(self):
        _scheme()
        ev = _evidence()
        pol = _policy()
        ear = tv.appraise(ev, [], pol, _pins(pol))
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.require_affirmed(ear)
        self.assertEqual(cm.exception.code, tv.APPRAISAL_INSUFFICIENT)

    def test_insufficient_without_covering_exception_refuses(self):
        _scheme()
        ev = _evidence()
        pol = _policy()
        ear = tv.appraise(ev, [], pol, _pins(pol))
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.require_affirmed(ear, exception_store=_store(live=False))
        self.assertEqual(cm.exception.code, tv.NO_COVERING_EXCEPTION)

    def test_insufficient_with_live_exception_accepted_at_risk(self):
        _scheme()
        ev = _evidence()
        pol = _policy()
        ear = tv.appraise(ev, [], pol, _pins(pol))
        res = tv.require_affirmed(ear, exception_store=_store(live=True))
        self.assertEqual(res["status"], "accepted-at-risk")
        self.assertIn("exception_digest", res)
        # The vector is UNCHANGED: the exception never upgrades it.
        self.assertEqual(res["ear"]["vector"], ear["vector"])
        self.assertEqual(res["ear"]["overall"], "insufficient")

    def test_malformed_ear_refused(self):
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.require_affirmed({"overall": "affirmed"})
        self.assertEqual(cm.exception.code, tv.EVIDENCE_INVALID)


class TestRegistry(unittest.TestCase):
    def test_duplicate_scheme_refused(self):
        _scheme()
        dup = tv.SchemeDescriptor(
            scheme_id="ut-firmware/v1",
            claim_grammar={"a": "str"}, dimensions=[])
        with self.assertRaises(tv.TrustVectorError) as cm:
            tv.register_scheme(dup)
        self.assertEqual(cm.exception.code, tv.SCHEME_DUPLICATE)

    def test_registered_schemes_lists(self):
        _scheme()
        self.assertIn("ut-firmware/v1", tv.registered_schemes())

    def test_custom_hook_dispatch(self):
        def _hook(evidence, endorsements, policy, grade):
            vec = grade(evidence, endorsements, policy)
            vec = dict(vec)
            if evidence.claims.get("debug_fuse") is True:
                vec["config_integrity"] = "contraindicated"
            return vec

        desc = tv.SchemeDescriptor(
            scheme_id="ut-hooked/v1",
            claim_grammar={"fw_digest": "digest", "debug_fuse": "bool"},
            dimensions=[
                {"name": "sw_integrity", "rule": "endorsed-match",
                 "claims": ["fw_digest"]},
                {"name": "config_integrity", "rule": "operator-trust",
                 "claims": ["debug_fuse"]},
            ],
            appraise_fn=_hook)
        try:
            tv.register_scheme(desc)
        except tv.TrustVectorError as e:
            if e.code != tv.SCHEME_DUPLICATE:
                raise
        ev = tv.submit_evidence("ut-hooked/v1",
                                {"fw_digest": "ab" * 32,
                                 "debug_fuse": True}, "prod-a")
        pol = tv.compile_policy({
            "format": "sasanam-appraisal-policy/v1",
            "policy_id": "ut-hook-pol", "scheme_id": "ut-hooked/v1",
            "trusted_producers": {"prod-a": "key-1"}})
        ear = tv.appraise(ev, [], pol, _pins(pol))
        self.assertEqual(ear["vector"]["config_integrity"],
                         "contraindicated")


class TestDeterminism(unittest.TestCase):
    def test_digests_deterministic(self):
        _scheme()
        ev1 = _evidence()
        ev2 = _evidence()
        self.assertEqual(ev1.digest, ev2.digest)
        pol1 = _policy()
        pol2 = _policy()
        self.assertEqual(pol1.digest, pol2.digest)
        ear1 = tv.appraise(ev1, [], pol1, _pins(pol1))
        ear2 = tv.appraise(ev2, [], pol2, _pins(pol2))
        self.assertEqual(ear1["vector"], ear2["vector"])
        self.assertEqual(ear1["appraisal_digest"], ear2["appraisal_digest"])


if __name__ == "__main__":
    unittest.main()
