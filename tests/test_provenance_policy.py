"""Unit tests for gov/provenance_policy.py (wave-263 lane 3).

Red-first: written before the module; admission-time provenance
policy (slsa-verifier D3 ADAPT as pattern only): policy-as-data,
verify_and_emit piping, VSA delegated verification.

Stdlib only. No network. Injectable clock via `now` args.
"""

import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import gov.decision_codes as dc
import gov.provenance_policy as pp

BUILDER_A = ("https://github.com/SIDDARTHAREDDY8/sasanam/"
             ".github/workflows/build.yml@v1")
SOURCE = "git@github.com:SIDDARTHAREDDY8/sasanam"
SOURCE_HEX = "a" * 64
SEED = b"w263-provenance-signer-a-0000000"
OTHER_SEED = b"w263-provenance-signer-b-0000000"
VERIFIER_SEED = b"w263-provenance-verifier-0000000"
VERIFIER_ID = "gate-registry"
SUBJECT = "c" * 64


def _signers(seed=SEED):
    pub = pp.ed25519_publickey(seed)
    return {pp.key_id_hex(pub): pub.hex()}


def _policy_dict(**kw):
    base = {
        "name": "unit-policy",
        "version": 1,
        "sources": {"allowed": [SOURCE, "sha256:" + SOURCE_HEX]},
        "builders": {"allowed": [BUILDER_A]},
        "tags": {"mode": "versioned-tag", "semver": ">=0.9.0,<1.0.0",
                 "required": True},
        "require_signed_statement": True,
        "statement_signers": _signers(),
        "trusted_verifiers": {
            VERIFIER_ID: pp.ed25519_publickey(VERIFIER_SEED).hex()},
        "vsa_max_age_seconds": 86400,
        "vsa_required_level": "SLSA_BUILD_LEVEL_3",
    }
    base.update(kw)
    return base


def _policy(**kw):
    return pp.ProvenancePolicy.from_dict(_policy_dict(**kw))


def _statement(builder=BUILDER_A, tag="v0.9.1", source=SOURCE,
               seed=SEED, subject=SUBJECT, inputs=None,
               drop_source_digest=False):
    st = {
        "format": "sasanam-provenance-statement/1",
        "subject": {"name": "artifact.zip",
                    "digest": {"sha256": subject}},
        "predicate": {
            "source": {"uri": source,
                       "digest": {"sha256": SOURCE_HEX}},
            "builder": {"id": builder},
            "tag": tag,
            "inputs": inputs or {},
        },
    }
    if drop_source_digest:
        del st["predicate"]["source"]["digest"]
    return pp.sign_statement(st, seed)


class PolicyConstructionTests(unittest.TestCase):
    def test_happy_construction(self):
        pol = _policy()
        self.assertEqual(pol.name, "unit-policy")

    def test_empty_sources_vacuous(self):
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            _policy(sources={"allowed": []})
        self.assertEqual(cm.exception.code, "provenance-policy-vacuous")

    def test_missing_sources_vacuous(self):
        d = _policy_dict()
        del d["sources"]
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pp.ProvenancePolicy.from_dict(d)
        self.assertEqual(cm.exception.code, "provenance-policy-vacuous")

    def test_empty_builders_vacuous(self):
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            _policy(builders={"allowed": []})
        self.assertEqual(cm.exception.code, "provenance-policy-vacuous")

    def test_no_signers_vacuous(self):
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            _policy(statement_signers={})
        self.assertEqual(cm.exception.code, "provenance-policy-vacuous")

    def test_bad_semver_clause_vacuous(self):
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            _policy(tags={"mode": "versioned-tag", "semver": ">>=nope"})
        self.assertEqual(cm.exception.code, "provenance-policy-vacuous")

    def test_branch_mode_needs_allowed(self):
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            _policy(tags={"mode": "branch", "allowed": []})
        self.assertEqual(cm.exception.code, "provenance-policy-vacuous")

    def test_semver_outside_versioned_tag_mode_vacuous(self):
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            _policy(tags={"mode": "any", "semver": ">=0.9.0"})
        self.assertEqual(cm.exception.code, "provenance-policy-vacuous")

    def test_adapter_refuses_unreadable_bundle(self):
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pp.statement_from_offline_bundle("/nonexistent/dir-xyz",
                                             SEED)
        self.assertEqual(cm.exception.code,
                         "provenance-statement-unverified")


class AdmissionTests(unittest.TestCase):
    def test_happy_admit(self):
        pol = _policy()
        self.assertTrue(pol.admit(_statement(),
                                  expected_subject_digest=SUBJECT))

    def test_evaluate_twin(self):
        pol = _policy()
        ok, code, _ = pol.evaluate(_statement(),
                                   expected_subject_digest=SUBJECT)
        self.assertTrue(ok)
        self.assertIsNone(code)
        bad = _statement(builder="https://x.example/other")
        ok, code, _ = pol.evaluate(bad)
        self.assertFalse(ok)
        self.assertEqual(code, "provenance-builder-refused")

    def test_swapped_builder_refused(self):
        # The pinned signer asserts a FOREIGN builder id: the signature
        # is genuine but the CLAIM is checked against policy, not made
        # true by the signature.
        pol = _policy()
        st = _statement(builder="https://evil.example/build.yml",
                        seed=SEED)
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit(st, expected_subject_digest=SUBJECT)
        self.assertEqual(cm.exception.code, "provenance-builder-refused")
        # ...and a statement from a wholly unpinned signer never even
        # reaches claim evaluation.
        evil = _statement(builder="https://evil.example/build.yml",
                          seed=OTHER_SEED)
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit(evil, expected_subject_digest=SUBJECT)
        self.assertEqual(cm.exception.code,
                         "provenance-statement-unverified")

    def test_wrong_source_refused(self):
        pol = _policy()
        st = _statement(source="git@evil.example/repo",
                        drop_source_digest=True)  # uri is the only claim
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit(st)
        self.assertEqual(cm.exception.code, "provenance-source-refused")
        # ...but the policy ALSO allows the exact source digest, and a
        # digest match admits even when the uri is foreign (digests are
        # the stronger claim: "this exact commit, from anywhere").
        self.assertTrue(pol.admit(_statement(source="git@evil.example/repo"),
                                  expected_subject_digest=SUBJECT))

    def test_source_digest_match_admits(self):
        pol = _policy()
        st = _statement(source="git@somewhere.else/repo")  # uri not allowed
        self.assertTrue(pol.admit(st, expected_subject_digest=SUBJECT))

    def test_expected_input_mismatch_refused(self):
        pol = _policy(expected_inputs={"policy_digest": "sha256:" + "e" * 64})
        st = _statement(inputs={"policy_digest": "sha256:" + "f" * 64})
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit(st, expected_subject_digest=SUBJECT)
        self.assertEqual(cm.exception.code, "provenance-source-refused")
        good = _statement(inputs={"policy_digest": "sha256:" + "e" * 64})
        self.assertTrue(pol.admit(good, expected_subject_digest=SUBJECT))

    def test_subject_mismatch_refused(self):
        pol = _policy()
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit(_statement(), expected_subject_digest="d" * 64)
        self.assertEqual(cm.exception.code, "provenance-subject-refused")

    def test_missing_subject_refused(self):
        pol = _policy()
        st = _statement()
        del st["subject"]
        pp.sign_statement(st, SEED)  # re-sign the mutilated statement
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit(st)
        self.assertEqual(cm.exception.code, "provenance-subject-refused")


class TagTests(unittest.TestCase):
    def test_range_enforced(self):
        pol = _policy()
        for tag in ("v0.9.0", "v0.9.5", "0.9.9"):
            self.assertTrue(pol.admit(_statement(tag=tag),
                                      expected_subject_digest=SUBJECT),
                            tag)
        for tag in ("v2.0.0", "v0.8.9", "not-a-version", ""):
            with self.assertRaises(pp.ProvenancePolicyError) as cm:
                pol.admit(_statement(tag=tag))
            self.assertEqual(cm.exception.code, "provenance-tag-refused",
                             tag)

    def test_prerelease_strictness(self):
        # Conservative prerelease rule: a prerelease tag only satisfies
        # a range that itself names a prerelease. v0.9.0-alpha sorts
        # below the v0.9.0 floor, and v1.0.0-rc1 must not slip under the
        # <1.0.0 ceiling on tuple ordering alone.
        pol = _policy()
        for tag in ("v0.9.0-alpha", "v0.9.1-beta", "v1.0.0-rc1"):
            with self.assertRaises(pp.ProvenancePolicyError) as cm:
                pol.admit(_statement(tag=tag))
            self.assertEqual(cm.exception.code, "provenance-tag-refused",
                             tag)
        pre_pol = _policy(tags={"mode": "versioned-tag",
                                "semver": ">=0.9.0-beta,<1.0.0",
                                "required": True})
        self.assertTrue(pre_pol.admit(_statement(tag="v0.9.1-beta"),
                                      expected_subject_digest=SUBJECT))

    def test_branch_mode(self):
        pol = _policy(tags={"mode": "branch", "allowed": ["main"],
                            "required": True})
        self.assertTrue(pol.admit(_statement(tag="main"),
                                  expected_subject_digest=SUBJECT))
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit(_statement(tag="feature/x"))
        self.assertEqual(cm.exception.code, "provenance-tag-refused")


class SignatureTests(unittest.TestCase):
    def test_tamper_refuses_and_emits_nothing(self):
        st = _statement()
        st["predicate"]["tag"] = "v9.9.9"
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pp.verify_and_emit(st, _signers())
        self.assertEqual(cm.exception.code,
                         "provenance-statement-unverified")

    def test_emit_stable_canonical(self):
        st = _statement()
        b1 = pp.verify_and_emit(st, _signers())
        b2 = pp.verify_and_emit(st, _signers())
        self.assertEqual(b1, b2)
        self.assertTrue(b1.endswith(b"\n"))
        self.assertEqual(json.loads(b1)["format"],
                         pp.STATEMENT_FORMAT)

    def test_unknown_signer_refuses(self):
        st = _statement(seed=OTHER_SEED)  # valid sig, unpinned key
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pp.verify_and_emit(st, _signers())
        self.assertEqual(cm.exception.code,
                         "provenance-statement-unverified")

    def test_piping_into_policy(self):
        pol = _policy()
        blob = pp.verify_and_emit(_statement(), _signers())
        self.assertTrue(pol.admit(json.loads(blob),
                                  expected_subject_digest=SUBJECT))


class VSATests(unittest.TestCase):
    def _vsa(self, **kw):
        args = dict(subject_digest=SUBJECT,
                    policy_id="unit-policy",
                    verified_level="SLSA_BUILD_LEVEL_3",
                    issued_at=1000.0, ttl_seconds=3600)
        args.update(kw)
        return pp.VSAIssuer(VERIFIER_ID, VERIFIER_SEED).issue(**args)

    def test_happy_vsa(self):
        pol = _policy()
        self.assertTrue(pol.admit_vsa(self._vsa(), "unit-policy",
                                      SUBJECT, now=1100.0))

    def test_scope_mismatch(self):
        pol = _policy()
        other = _policy(name="other-policy")
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            other.admit_vsa(self._vsa(), "other-policy", SUBJECT,
                            now=1100.0)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_expired(self):
        pol = _policy()
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit_vsa(self._vsa(ttl_seconds=100), "unit-policy",
                          SUBJECT, now=2000.0)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_unpinned_verifier(self):
        pol = _policy()
        vsa = pp.VSAIssuer("rogue", OTHER_SEED).issue(
            SUBJECT, "unit-policy", "SLSA_BUILD_LEVEL_3", 1000.0, 3600)
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit_vsa(vsa, "unit-policy", SUBJECT, now=1100.0)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_tampered_vsa_signature(self):
        pol = _policy()
        vsa = self._vsa()
        vsa["verified_level"] = "SLSA_BUILD_LEVEL_3-tampered"
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit_vsa(vsa, "unit-policy", SUBJECT, now=1100.0)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_wrong_subject(self):
        pol = _policy()
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit_vsa(self._vsa(), "unit-policy", "d" * 64,
                          now=1100.0)
        self.assertEqual(cm.exception.code, "provenance-subject-refused")

    def test_level_too_low(self):
        pol = _policy()
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit_vsa(self._vsa(verified_level="SLSA_BUILD_LEVEL_1"),
                          "unit-policy", SUBJECT, now=1100.0)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_max_age_cap(self):
        pol = _policy(vsa_max_age_seconds=60)
        vsa = self._vsa(issued_at=1000.0, ttl_seconds=100000)
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            pol.admit_vsa(vsa, "unit-policy", SUBJECT, now=2000.0)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_issuer_rejects_bad_level(self):
        with self.assertRaises(ValueError):
            pp.VSAIssuer(VERIFIER_ID, VERIFIER_SEED).issue(
                SUBJECT, "unit-policy", "BOGUS", 1000.0, 3600)


class SemverTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(pp._parse_semver("v1.2.3"), ((1, 2, 3), 1, ""))
        self.assertEqual(pp._parse_semver("1.2"), ((1, 2, 0), 1, ""))
        self.assertEqual(pp._parse_semver("v1.0.0-rc1"),
                         ((1, 0, 0), 0, "rc1"))
        self.assertIsNone(pp._parse_semver("not-a-version"))
        self.assertIsNone(pp._parse_semver("v1.2.3.4"))
        self.assertIsNone(pp._parse_semver(""))

    def test_ranges(self):
        self.assertTrue(pp._semver_satisfies("v0.9.5", ">=0.9.0,<1.0.0"))
        self.assertFalse(pp._semver_satisfies("v2.0.0", ">=0.9.0,<1.0.0"))
        self.assertTrue(pp._semver_satisfies("v1.2.3", "==1.2.3"))
        self.assertFalse(pp._semver_satisfies("v1.2.4", "==1.2.3"))
        self.assertFalse(pp._semver_satisfies("nope", ">=0.9.0"))
        # prereleases need a prerelease-naming range
        self.assertFalse(pp._semver_satisfies("v1.0.0-rc1",
                                              ">=0.9.0,<1.0.0"))
        self.assertTrue(pp._semver_satisfies("v1.0.0-rc1",
                                             ">=0.9.0,<1.0.0-rc2"))


class OfflineBundleAdapterTests(unittest.TestCase):
    def test_adapter_builds_signable_statement(self):
        tmp = tempfile.mkdtemp(prefix="w263-adapter-")
        manifest = {
            "bundle_id": "test-bundle",
            "exporter": "gov/offline_bundle.py 1.0.0",
            "ledger_digest": "e" * 64,
            "window": {"from_seq": 1, "to_seq": 3},
        }
        with open(os.path.join(tmp, "manifest.json"), "w") as f:
            json.dump(manifest, f)
        with open(os.path.join(tmp, "BUNDLE_DIGEST.sha256"), "w") as f:
            f.write("f" * 64 + "\n")
        st = pp.statement_from_offline_bundle(tmp, SEED)
        self.assertEqual(st["subject"]["digest"]["sha256"], "f" * 64)
        self.assertEqual(st["predicate"]["source"]["uri"],
                         pp.UNRECORDED_SOURCE)
        self.assertIn("sasanam-offline-exporter/",
                      st["predicate"]["builder"]["id"])
        # a policy that explicitly allows the unrecorded source admits
        pol = _policy(sources={"allowed": [pp.UNRECORDED_SOURCE]},
                      builders={"allowed": [
                          "sasanam-offline-exporter/"
                          "gov/offline_bundle.py 1.0.0"]},
                      tags={"mode": "any", "required": False})
        self.assertTrue(pol.admit(st,
                                  expected_subject_digest="f" * 64))
        # a default policy (source must be the repo) refuses it
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            _policy().admit(st, expected_subject_digest="f" * 64)
        self.assertEqual(cm.exception.code, "provenance-source-refused")


class TaxonomyTests(unittest.TestCase):
    def test_pin_and_codes(self):
        n = len(dc.TAXONOMY)
        self.assertEqual(n, 1869)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 merge: pin 1742 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        for c in pp.CODES:
            self.assertIn(c, dc.TAXONOMY)
        self.assertEqual(len(set(dc.TAXONOMY)), 1869)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)


if __name__ == "__main__":
    unittest.main()
