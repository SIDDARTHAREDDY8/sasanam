"""Unit tests for gov.ratify (wave-282 lane 6).

Mechanism lineage: notaryproject/ratify ADAPT (Apache-2.0) -- per-artifact-type
any/all policy combinators, nested VerifierResult report trees, sealed into
evidence bundles/VSAs, and the admission-before-binding gate at the
grant-graph binding point.
"""

import hashlib
import json
import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import ratify as R


def _hex(data):
    return hashlib.sha256(data).hexdigest()


class ClosedVocabulariesTests(unittest.TestCase):
    def test_subject_kinds(self):
        self.assertEqual(R.SUBJECT_KINDS,
                         ("tool-definition", "skill-bundle",
                          "evidence-manifest"))

    def test_artifact_types(self):
        self.assertEqual(R.ARTIFACT_TYPES,
                         ("signature", "digest", "provenance", "sbom",
                          "license", "vuln-report"))

    def test_combinators(self):
        self.assertEqual(R.COMBINATORS, ("any", "all"))


class VerifierResultTests(unittest.TestCase):
    def test_exact_bool_required(self):
        with self.assertRaises(R.RatifyError):
            R.verifier_result(subject="s", name="n", artifact_type="digest",
                              is_success=1)
        with self.assertRaises(R.RatifyError):
            R.verifier_result(subject="s", name="n", artifact_type="digest",
                              is_success=None)

    def test_unknown_artifact_type_refused(self):
        with self.assertRaises(R.RatifyError):
            R.verifier_result(subject="s", name="n", artifact_type="elf",
                              is_success=True)

    def test_report_digest_stable(self):
        node = R.verifier_result(subject="s", name="n",
                                 artifact_type="digest", is_success=True,
                                 results=["ok"])
        self.assertEqual(R.report_digest(node), R.report_digest(node))
        self.assertTrue(len(R.report_digest(node)) == 64)

    def test_recursion_guard(self):
        # Build the deep tree as raw dicts (the factory itself fails fast
        # on depth at construction); the standalone digest path guards too.
        def raw(depth):
            node = {"subject": "s", "is_success": True, "name": "n",
                    "artifact_type": "policy-combinator", "results": [],
                    "nested_results": []}
            for _ in range(depth):
                node = {"subject": "s", "is_success": True, "name": "n",
                        "artifact_type": "policy-combinator", "results": [],
                        "nested_results": [node]}
            return node
        with self.assertRaises(R.RatifyError):
            R.report_digest(raw(40))


class CombinatorTests(unittest.TestCase):
    def _enforce(self, verifiers, mapping):
        return R.PolicyEnforcer().verify(
            subject="tool:x", subject_kind="tool-definition",
            subject_bytes=b"tool-def-bytes", metadata={},
            verifiers=verifiers,
            policy=R.VerificationPolicy(mapping))

    def test_unknown_combinator_refused_fail_fast(self):
        with self.assertRaises(ValueError):
            R.VerificationPolicy({"digest": "majority"})

    def test_unknown_artifact_type_refused_fail_fast(self):
        with self.assertRaises(R.RatifyError):
            R.VerificationPolicy({"elf": "all"})

    def test_any_one_good_succeeds(self):
        subject = b"tool-def-bytes"
        good = R.DigestVerifier("d-good", expected_hex=_hex(subject))
        bad = R.DigestVerifier("d-bad", expected_hex="00" * 32)
        root = self._enforce([good, bad], {"digest": "any"})
        self.assertIs(root["is_success"], True)

    def test_any_all_bad_fails(self):
        bad1 = R.DigestVerifier("d1", expected_hex="00" * 32)
        bad2 = R.DigestVerifier("d2", expected_hex="11" * 32)
        root = self._enforce([bad1, bad2], {"digest": "any"})
        self.assertIs(root["is_success"], False)

    def test_all_requires_every_verifier(self):
        subject = b"tool-def-bytes"
        good = R.DigestVerifier("d-good", expected_hex=_hex(subject))
        bad = R.DigestVerifier("d-bad", expected_hex="00" * 32)
        root = self._enforce([good, bad], {"digest": "all"})
        self.assertIs(root["is_success"], False)
        root_ok = self._enforce([good], {"digest": "all"})
        self.assertIs(root_ok["is_success"], True)

    def test_missing_verifier_fails_closed(self):
        root = self._enforce([], {"digest": "all"})
        self.assertIs(root["is_success"], False)
        self.assertTrue(any("fail-closed" in r
                            for r in root["nested_results"][0]["results"]))

    def test_verifier_crash_fails_closed_with_machine_code(self):
        class Boom(R.Verifier):
            artifact_type = "digest"

            def __init__(self):
                super(Boom, self).__init__("boom")

            def verify(self, subject_bytes, metadata):
                raise RuntimeError("kaput")

        root = self._enforce([Boom()], {"digest": "any"})
        self.assertIs(root["is_success"], False)
        leaf = root["nested_results"][0]["nested_results"][0]
        self.assertIs(leaf["is_success"], False)
        self.assertTrue(any(R.RatifyVerifierError.code in r
                            for r in leaf["results"]))

    def test_policy_failure_carries_machine_code(self):
        bad = R.DigestVerifier("d", expected_hex="00" * 32)
        root = self._enforce([bad], {"digest": "all"})
        self.assertTrue(any(R.RatifyPolicyError.code in r
                            for r in root["results"]))


class NestedRollupTests(unittest.TestCase):
    def test_per_type_nodes_then_root(self):
        seed = secrets.token_bytes(32)
        subject = b"tool-def-bytes"
        pub = ed25519.publickey(seed).hex()
        sig = ed25519.sign(seed, subject).hex()
        verifiers = [
            R.SignatureVerifier("sig", pubkey_hex=pub, signature_hex=sig),
            R.DigestVerifier("dig", expected_hex=_hex(subject)),
        ]
        root = R.PolicyEnforcer().verify(
            subject="tool:x", subject_kind="tool-definition",
            subject_bytes=subject, metadata={},
            verifiers=verifiers,
            policy=R.VerificationPolicy(
                {"signature": "all", "digest": "all"}))
        self.assertIs(root["is_success"], True)
        self.assertEqual(len(root["nested_results"]), 2)
        by_name = {n["name"]: n for n in root["nested_results"]}
        self.assertEqual(by_name["signature"]["artifact_type"],
                         "policy-combinator")
        self.assertEqual(len(by_name["signature"]["nested_results"]), 1)


class VerifierContractTests(unittest.TestCase):
    def test_signature_honors_exact_bool_contract(self):
        seed = secrets.token_bytes(32)
        subject = b"tool-def-bytes"
        pub = ed25519.publickey(seed).hex()
        good_sig = ed25519.sign(seed, subject).hex()
        good = R.SignatureVerifier(
            "s", pubkey_hex=pub, signature_hex=good_sig)
        bad = R.SignatureVerifier(
            "s", pubkey_hex=pub, signature_hex="00" * 128)
        self.assertIs(good.verify(subject, {})["is_success"], True)
        self.assertIs(bad.verify(subject, {})["is_success"], False)

    def test_signature_malformed_hex_fails_closed(self):
        v = R.SignatureVerifier("s", pubkey_hex="zz", signature_hex="zz")
        self.assertIs(v.verify(b"bytes", {})["is_success"], False)

    def test_provenance_requires_material_digests(self):
        v = R.ProvenanceVerifier("p")
        self.assertIs(v.verify(b"b", {"provenance": None})["is_success"],
                      False)
        good = {"builder_id": "b", "materials": [{"digest": "ab" * 32}]}
        self.assertIs(v.verify(b"b", {"provenance": good})["is_success"],
                      True)
        badmats = {"builder_id": "b", "materials": [{"digest": "nope"}]}
        self.assertIs(v.verify(b"b", {"provenance": badmats})["is_success"],
                      False)

    def test_sbom_shape(self):
        v = R.SbomVerifier("s")
        self.assertIs(v.verify(b"b", {})["is_success"], False)
        good = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                "components": []}
        self.assertIs(v.verify(b"b", {"sbom": good})["is_success"], True)

    def test_license_allowlist_exact(self):
        v = R.LicenseVerifier("l", allowlist=["Apache-2.0", "MIT"])
        self.assertIs(v.verify(b"b", {"license": "MIT"})["is_success"], True)
        self.assertIs(v.verify(b"b", {"license": "GPL-3.0"})["is_success"],
                      False)
        self.assertIs(v.verify(b"b", {})["is_success"], False)


class AdmissionTests(unittest.TestCase):
    def _report(self, subject, ok):
        return R.verifier_result(subject=subject, name="policy-enforcer",
                                 artifact_type="policy", is_success=ok)

    def test_ratified_tool_admitted(self):
        self.assertIs(
            R.check_admission(tool="tool:x",
                              report=self._report("tool:x", True)),
            True)

    def test_unratified_refused_with_code(self):
        with self.assertRaises(R.RatifyRefused) as cm:
            R.check_admission(tool="tool:x",
                              report=self._report("tool:x", False))
        self.assertEqual(cm.exception.code,
                         "ratify-unratified-tool-refused")

    def test_subject_mismatch_refused(self):
        with self.assertRaises(R.RatifyRefused) as cm:
            R.check_admission(tool="tool:y",
                              report=self._report("tool:x", True))
        self.assertEqual(cm.exception.code,
                         "ratify-unratified-tool-refused")

    def test_absent_report_unverifiable(self):
        with self.assertRaises(R.RatifyAdmissionError) as cm:
            R.check_admission(tool="tool:x", report=None)
        self.assertEqual(cm.exception.code,
                         "ratify-admission-unverifiable")

    def test_malformed_report_unverifiable(self):
        with self.assertRaises(R.RatifyAdmissionError) as cm:
            R.check_admission(tool="tool:x", report={"nope": 1})
        self.assertEqual(cm.exception.code,
                         "ratify-admission-unverifiable")


class AuditChainTests(unittest.TestCase):
    def test_writer_chains_records(self):
        from gov.log import ActionLog, read_entries
        from tests.keyfixture import provision_test_key
        provision_test_key()
        d = tempfile.mkdtemp(prefix="ratify-unit-")
        path = os.path.join(d, "audit.jsonl")
        log = ActionLog(path)
        writer = R.RatificationWriter(log)
        rep1 = R.verifier_result(subject="tool:a", name="policy-enforcer",
                                 artifact_type="policy", is_success=True)
        rep2 = R.verifier_result(subject="tool:b", name="policy-enforcer",
                                 artifact_type="policy", is_success=False)
        e1 = writer.record("tool:a", "tool-definition", rep1)
        e2 = writer.record("tool:b", "tool-definition", rep2)
        records = R.ratification_verdict_records(log)
        self.assertEqual(len(records), 2)
        # chain continuity
        self.assertEqual(records[0]["prev_ratification_record_digest"],
                         "0" * 64)
        self.assertEqual(records[1]["prev_ratification_record_digest"],
                         records[0]["ratification_record_digest"])
        # digests recompute over exactly the writer's fields (the log's
        # own chain metadata rides on the stored entry separately)
        _WRITER_KEYS = ("record_type", "tool", "subject_kind", "subject",
                        "report_digest", "is_success",
                        "prev_ratification_record_digest")
        for rec in records:
            body = {k: rec[k] for k in _WRITER_KEYS}
            canon = json.dumps(
                body, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode("utf-8")
            self.assertEqual(rec["ratification_record_digest"],
                             hashlib.sha256(canon).hexdigest())
        # record matches report digest
        self.assertEqual(records[0]["report_digest"],
                         R.report_digest(rep1))
        self.assertIs(e2["is_success"], False)

    def test_chain_tamper_breaks(self):
        from tests.keyfixture import provision_test_key
        provision_test_key()
        d = tempfile.mkdtemp(prefix="ratify-unit-")
        path = os.path.join(d, "audit.jsonl")
        from gov.log import ActionLog, read_entries
        writer = R.RatificationWriter(ActionLog(path))
        rep = R.verifier_result(subject="tool:a", name="policy-enforcer",
                                artifact_type="policy", is_success=True)
        writer.record("tool:a", "tool-definition", rep)
        records = R.ratification_verdict_records(ActionLog(path))
        tampered = dict(records[0])
        tampered["is_success"] = False
        body = {k: v for k, v in tampered.items()
                if k != "ratification_record_digest"}
        canon = json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("utf-8")
        self.assertNotEqual(tampered["ratification_record_digest"],
                            hashlib.sha256(canon).hexdigest())


    def test_vuln_report_fail_closed_on_criticals(self):
        v = R.VulnReportVerifier("v")
        clean = {"scanner": "unit", "findings": [
            {"id": "CVE-1", "severity": "critical", "status": "fixed"},
            {"id": "CVE-2", "severity": "low", "status": "open"}]}
        dirty = {"scanner": "unit", "findings": [
            {"id": "CVE-3", "severity": "critical", "status": "open"}]}
        self.assertIs(v.verify(b"b", {"vuln_report": clean})["is_success"],
                      True)
        self.assertIs(v.verify(b"b", {"vuln_report": dirty})["is_success"],
                      False)
        self.assertIs(v.verify(b"b", {})["is_success"], False)
        self.assertIs(
            v.verify(b"b", {"vuln_report": {"findings": "nope"}})
            ["is_success"], False)

    def test_vuln_report_forbidden_severities_configurable(self):
        v = R.VulnReportVerifier("v",
                                 forbidden_severities=("critical", "high"))
        rep = {"findings": [{"id": "CVE-9", "severity": "high"}]}
        self.assertIs(v.verify(b"b", {"vuln_report": rep})["is_success"],
                      False)
        with self.assertRaises(R.RatifyError):
            R.VulnReportVerifier("v", forbidden_severities=())

    def test_vuln_report_in_policy_rollup(self):
        v = R.VulnReportVerifier("v")
        rep = {"scanner": "unit", "findings": []}
        root = R.PolicyEnforcer().verify(
            subject="tool:x", subject_kind="tool-definition",
            subject_bytes=b"b", metadata={"vuln_report": rep},
            verifiers=[v],
            policy=R.VerificationPolicy({"vuln-report": "all"}))
        self.assertIs(root["is_success"], True)
        self.assertEqual(root["nested_results"][0]["name"], "vuln-report")


class EvidencePackageTests(unittest.TestCase):
    def _report(self):
        return R.verifier_result(subject="tool:x", name="policy-enforcer",
                                 artifact_type="policy", is_success=True,
                                 nested_results=[
                                     R.verifier_result(
                                         subject="tool:x", name="digest",
                                         artifact_type="policy-combinator",
                                         is_success=True)])

    def test_round_trip(self):
        pkg = R.ratification_evidence_package(self._report())
        self.assertEqual(pkg["format"],
                         "sasanam-ratification-package/1")
        self.assertEqual(pkg["package_digest"],
                         R.report_digest(pkg["report"]))
        self.assertTrue(R.verify_ratification_package(pkg))

    def test_tampered_report_fails(self):
        pkg = R.ratification_evidence_package(self._report())
        pkg["report"]["is_success"] = False
        self.assertFalse(R.verify_ratification_package(pkg))

    def test_malformed_never_raises(self):
        self.assertFalse(R.verify_ratification_package(None))
        self.assertFalse(R.verify_ratification_package({}))
        self.assertFalse(R.verify_ratification_package(
            {"format": "nope", "report": {}, "package_digest": "x"}))


class DeriveGrantsHookTests(unittest.TestCase):
    def test_unratified_refused_at_binding(self):
        from gov import capability_grants as cg
        from gov.log import ActionLog
        from tests.keyfixture import provision_test_key
        provision_test_key()
        d = tempfile.mkdtemp(prefix="ratify-hook-")
        log = ActionLog(os.path.join(d, "audit.jsonl"))
        registry = cg.GrantRegistry(audit_log=log)
        manifest = {
            "schema_version": "1",
            "tool_id": "skill.x",
            "skill_id": "skill.x",
            "declared": {"file": [{"label": "f", "path": "a.txt",
                                   "rights": ["read"]}]},
        }
        policy = cg.GrantPolicy(fs_root=d)
        bad_report = R.verifier_result(subject="skill.x",
                                       name="policy-enforcer",
                                       artifact_type="policy",
                                       is_success=False)
        with self.assertRaises(cg.GrantRefused):
            cg.derive_grants(
                verified_manifest=manifest, grant_policy=policy,
                approval={"approval_id": "a1", "record_digest": "ab" * 32},
                decision_id="d1",
                registry=registry, ratify_report=bad_report)
        denied = [r for r in registry.refusals
                  if r.get("reason") == "ratify-unratified-tool-refused"]
        self.assertTrue(denied)

    def test_legacy_path_unchanged_without_report(self):
        from gov import capability_grants as cg
        from gov.log import ActionLog
        from tests.keyfixture import provision_test_key
        provision_test_key()
        d = tempfile.mkdtemp(prefix="ratify-hook-")
        log = ActionLog(os.path.join(d, "audit.jsonl"))
        registry = cg.GrantRegistry(audit_log=log)
        fsroot = os.path.join(d, "fs")
        os.makedirs(fsroot)
        with open(os.path.join(fsroot, "a.txt"), "w") as f:
            f.write("alpha")
        manifest = {
            "schema_version": "1",
            "tool_id": "skill.x",
            "skill_id": "skill.x",
            "declared": {"file": [{"label": "f", "path": "a.txt",
                                   "rights": ["read"]}]},
        }
        policy = cg.GrantPolicy(fs_root=fsroot)
        grants = cg.derive_grants(
            verified_manifest=manifest, grant_policy=policy,
            approval={"approval_id": "a2", "record_digest": "ab" * 32},
                decision_id="d2",
            registry=registry)
        self.assertTrue(len(grants) >= 1)


if __name__ == "__main__":
    unittest.main()
