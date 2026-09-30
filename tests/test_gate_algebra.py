"""Unit tests for gov/gate_algebra.py.

Wave-223 lane C: gate algebra (Harbor AND-composable pull-time
policies, re-derived prose) over gov/admission.py by composition.
Tests at the public seams; expected values are independent
literals, never recomputed the way the code does.
"""

import hashlib
import unittest

from gov import admission as adm
from gov import ed25519 as _ed
from gov import gate_algebra as ga


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _keypair(tag):
    seed = hashlib.sha256(b"w223-unit-%s" % tag.encode()).digest()
    return seed, _ed.publickey(seed)


def _sign(seed, digest):
    return _ed.sign(seed, adm.SIGN_DOMAIN + digest.encode("ascii"))


def _artifact(seed, payload, fmt="evidence-bundle/1"):
    digest = _sha(payload)
    return {
        "format": fmt,
        "payload_digest": digest,
        "signature": _sign(seed, digest),
        "payload": payload,
    }


def _policy(issuer_pub, digest_pin, fmt="evidence-bundle/1"):
    return adm.AdmissionPolicy(digest_pin=digest_pin,
                               issuer_pin=issuer_pub,
                               bundle_format=fmt)


class ConjunctionAuthoringTests(unittest.TestCase):
    def test_empty_members(self):
        with self.assertRaises(ValueError):
            ga.PolicyConjunction()

    def test_member_without_admit(self):
        with self.assertRaises(ValueError):
            ga.PolicyConjunction(object())

    def test_admission_error_codes_exported(self):
        self.assertEqual(ga.CODE_CONJUNCTION_REFUSED,
                         "admission-conjunction-refused")
        self.assertEqual(ga.CODE_SEVERITY_EXCEEDED,
                         "admission-severity-exceeded")
        self.assertEqual(ga.CODE_SEVERITY_UNVERIFIABLE,
                         "admission-severity-unverifiable")
        self.assertEqual(ga.CODE_TAG_MUTATED, "admission-tag-mutated")


class ConjunctionTests(unittest.TestCase):
    def test_all_admit(self):
        seed, pub = _keypair("c1")
        payload = b"payload one"
        artifact = _artifact(seed, payload)
        conj = ga.PolicyConjunction(_policy(pub, _sha(payload)),
                                    _policy(pub, _sha(payload)))
        rec = conj.admit(artifact)
        self.assertTrue(rec["admissible"])
        self.assertEqual(rec["members_admitted"], 2)

    def test_single_refusal_attributed_and_counted(self):
        seed, pub = _keypair("c2")
        payload = b"payload two"
        artifact = _artifact(seed, payload)
        conj = ga.PolicyConjunction(_policy(pub, _sha(payload)),
                                    _policy(pub, _sha(b"wrong")))
        with self.assertRaises(adm.AdmissionError) as ctx:
            conj.admit(artifact)
        self.assertEqual(ctx.exception.code, "admission-conjunction-refused")
        self.assertEqual(ctx.exception.refused_count, 1)
        results = ctx.exception.member_results
        self.assertEqual(len(results), 2)
        codes = {r["member"]: r["code"] for r in results}
        self.assertEqual(codes[0], "admitted")
        self.assertEqual(codes[1], "admission-digest-mismatch")

    def test_no_short_circuit(self):
        seed, pub = _keypair("c3")
        payload = b"payload three"
        artifact = _artifact(seed, payload)
        conj = ga.PolicyConjunction(_policy(pub, _sha(b"nope-a")),
                                    _policy(pub, _sha(b"nope-b")),
                                    _policy(pub, _sha(b"nope-c")))
        with self.assertRaises(adm.AdmissionError) as ctx:
            conj.admit(artifact)
        self.assertEqual(ctx.exception.refused_count, 3)

    def test_member_error_fails_closed(self):
        seed, pub = _keypair("c4")
        payload = b"payload four"
        artifact = _artifact(seed, payload)

        class _Boom(object):
            def admit(self, _artifact):
                raise RuntimeError("kaboom")

        conj = ga.PolicyConjunction(_policy(pub, _sha(payload)), _Boom())
        with self.assertRaises(adm.AdmissionError) as ctx:
            conj.admit(artifact)
        self.assertEqual(ctx.exception.code, "admission-conjunction-refused")
        results = ctx.exception.member_results
        self.assertEqual(results[1]["code"],
                         "admission-conjunction-member-error")

    def test_nested_conjunction(self):
        seed, pub = _keypair("c5")
        payload = b"payload five"
        artifact = _artifact(seed, payload)
        inner = ga.PolicyConjunction(_policy(pub, _sha(payload)))
        outer = ga.PolicyConjunction(inner, _policy(pub, _sha(payload)))
        self.assertTrue(outer.admit(artifact)["admissible"])


class SeverityAuthoringTests(unittest.TestCase):
    def test_bad_threshold_string(self):
        _, pub = _keypair("s1")
        with self.assertRaises(ValueError):
            ga.SeverityGate(_policy(pub, _sha(b"x")), "mild")

    def test_bad_threshold_mapping(self):
        _, pub = _keypair("s2")
        with self.assertRaises(ValueError):
            ga.SeverityGate(_policy(pub, _sha(b"x")),
                            {"f": "extreme"})

    def test_empty_mapping(self):
        _, pub = _keypair("s3")
        with self.assertRaises(ValueError):
            ga.SeverityGate(_policy(pub, _sha(b"x")), {})

    def test_bad_policy(self):
        with self.assertRaises(ValueError):
            ga.SeverityGate(object(), "high")


class SeverityTests(unittest.TestCase):
    def test_under_and_at_threshold_admit(self):
        seed, pub = _keypair("s4")
        payload = b"payload six"
        artifact = _artifact(seed, payload)
        gate = ga.SeverityGate(_policy(pub, _sha(payload)),
                               {"evidence-bundle/1": "medium"})
        self.assertTrue(
            gate.admit(artifact,
                       findings=[{"id": "a", "severity": "low"}])
            ["admissible"])
        self.assertTrue(
            gate.admit(artifact,
                       findings=[{"id": "a", "severity": "medium"}])
            ["admissible"])

    def test_above_threshold_refused(self):
        seed, pub = _keypair("s5")
        payload = b"payload seven"
        artifact = _artifact(seed, payload)
        gate = ga.SeverityGate(_policy(pub, _sha(payload)), "medium")
        with self.assertRaises(adm.AdmissionError) as ctx:
            gate.admit(artifact, findings=[{"id": "x", "severity": "high"}])
        self.assertEqual(ctx.exception.code, "admission-severity-exceeded")

    def test_unknown_severity_refused(self):
        seed, pub = _keypair("s6")
        payload = b"payload eight"
        artifact = _artifact(seed, payload)
        gate = ga.SeverityGate(_policy(pub, _sha(payload)), "critical")
        with self.assertRaises(adm.AdmissionError) as ctx:
            gate.admit(artifact,
                       findings=[{"id": "x", "severity": "unknown"}])
        self.assertEqual(ctx.exception.code,
                         "admission-severity-unverifiable")

    def test_absent_findings_refused(self):
        seed, pub = _keypair("s7")
        payload = b"payload nine"
        artifact = _artifact(seed, payload)
        gate = ga.SeverityGate(_policy(pub, _sha(payload)), "critical")
        with self.assertRaises(adm.AdmissionError) as ctx:
            gate.admit(artifact, findings=None)
        self.assertEqual(ctx.exception.code,
                         "admission-severity-unverifiable")

    def test_unconfigured_class_refused(self):
        seed, pub = _keypair("s8")
        payload = b"payload ten"
        artifact = _artifact(seed, payload, fmt="other/9")
        gate = ga.SeverityGate(_policy(pub, _sha(payload), fmt="other/9"),
                               {"evidence-bundle/1": "critical"})
        with self.assertRaises(adm.AdmissionError) as ctx:
            gate.admit(artifact, findings=[])
        self.assertEqual(ctx.exception.code,
                         "admission-severity-unverifiable")

    def test_malformed_artifact_named_refusal(self):
        # Spec-axis review (c1): a non-dict artifact must refuse with
        # a named AdmissionError, never leak AttributeError.
        gate = ga.SeverityGate(
            _policy(_keypair("sm")[1], _sha(b"x")), "critical")
        with self.assertRaises(adm.AdmissionError) as ctx:
            gate.admit("not-a-dict", findings=[])
        self.assertEqual(ctx.exception.code, "admission-malformed")

    def test_inner_policy_refusal_survives(self):
        seed, pub = _keypair("s9")
        payload = b"payload eleven"
        artifact = _artifact(seed, payload)
        gate = ga.SeverityGate(_policy(pub, _sha(b"wrong")), "critical")
        with self.assertRaises(adm.AdmissionError) as ctx:
            gate.admit(artifact, findings=[])
        self.assertEqual(ctx.exception.code, "admission-digest-mismatch")


class ImmutableTagTests(unittest.TestCase):
    def test_mutation_refused(self):
        seed, pub = _keypair("t1")
        gate = ga.ImmutableTag(_policy(pub, _sha(b"v1")),
                               tag_of=lambda a: "f/1:latest")
        self.assertTrue(gate.admit(_artifact(seed, b"v1"))["admissible"])
        with self.assertRaises(adm.AdmissionError) as ctx:
            gate.admit(_artifact(seed, b"v2"))
        self.assertEqual(ctx.exception.code, "admission-tag-mutated")

    def test_same_digest_idempotent(self):
        seed, pub = _keypair("t2")
        gate = ga.ImmutableTag(_policy(pub, _sha(b"v1")),
                               tag_of=lambda a: "f/1:latest")
        rec1 = gate.admit(_artifact(seed, b"v1"))
        rec2 = gate.admit(_artifact(seed, b"v1"))
        self.assertTrue(rec1["admissible"] and rec2["admissible"])
        self.assertEqual(rec2["payload_digest"], _sha(b"v1"))
        self.assertEqual(rec2["tag"], "f/1:latest")

    def test_distinct_tags_independent(self):
        seed, pub = _keypair("t3")
        gate = ga.ImmutableTag(_policy(pub, _sha(b"v1")),
                               tag_of=lambda a: a["payload"].decode())
        self.assertTrue(
            gate.admit(_artifact(seed, b"v1"))["admissible"])

    def test_mutation_does_not_register(self):
        # A refused mutation must not poison the registry: the
        # original digest still re-admits.
        seed, pub = _keypair("t4")
        gate = ga.ImmutableTag(_policy(pub, _sha(b"v1")),
                               tag_of=lambda a: "f/1:latest")
        gate.admit(_artifact(seed, b"v1"))
        with self.assertRaises(adm.AdmissionError):
            gate.admit(_artifact(seed, b"v2"))
        self.assertTrue(gate.admit(_artifact(seed, b"v1"))["admissible"])

    def test_bad_tag_of(self):
        _, pub = _keypair("t5")
        with self.assertRaises(ValueError):
            ga.ImmutableTag(_policy(pub, _sha(b"x")), tag_of="nope")

    def test_composition_with_conjunction(self):
        seed, pub = _keypair("t6")
        conj = ga.PolicyConjunction(_policy(pub, _sha(b"v1")),
                                    _policy(pub, _sha(b"v1")))
        gate = ga.ImmutableTag(conj, tag_of=lambda a: "f/1:latest")
        rec = gate.admit(_artifact(seed, b"v1"))
        self.assertTrue(rec["admissible"])


if __name__ == "__main__":
    unittest.main()
