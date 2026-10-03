"""Unit tests for gov/policy_ci.py (wave-297 lane 3): single-source policy
with derived artifacts, mandatory companions, dryrun-then-enforce rollout.
"""

import unittest
from types import MappingProxyType

from gov import policy_ci as PCI
from gov import policy_authoring as PA
from gov import ed25519 as ED

SOURCE = """version: 1
policies:
  - name: block-secret-reads
    description: Deny reads of secret-like paths.
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
    actions:
      - type: deny
        reason: Secret-like read denied.
        flag: secret_access_attempt
"""

OTHER = SOURCE.replace("block-secret-reads", "block-other-reads")


def good_artifact(**over):
    kw = dict(author="tests", change_note="unit test change",
              probes=["p-source-compiles"])
    kw.update(over)
    return PCI.derive(SOURCE, **kw)


class DeriveTests(unittest.TestCase):
    def test_derive_frozen(self):
        art = good_artifact()
        self.assertIsInstance(art, MappingProxyType)
        with self.assertRaises(TypeError):
            art["author"] = "mallory"

    def test_derive_records_digests(self):
        art = good_artifact()
        for name, text in art["derived"].items():
            import hashlib
            self.assertEqual(art["digests"][name],
                             hashlib.sha256(text.encode("utf-8")).hexdigest())

    def test_derive_malformed_source_invalid(self):
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.derive("not: [valid")
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_derive_empty_source_invalid(self):
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.derive("   \n")
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_derive_non_str_invalid(self):
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.derive({"version": 1})
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_derive_oversize_invalid(self):
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.derive("x" * (PCI.SOURCE_MAX_BYTES + 1))
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")


class LoadTests(unittest.TestCase):
    def test_tampered_derived_refused(self):
        art = good_artifact()
        evil = dict(art)
        evil["derived"] = dict(evil["derived"])
        evil["derived"]["policy.native.yaml"] = (
            evil["derived"]["policy.native.yaml"].replace("deny", "allow"))
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.load_artifact(evil)
        self.assertEqual(ctx.exception.code, "policy-ci-derived-tampered")

    def test_tampered_manifest_refused(self):
        art = good_artifact()
        evil = dict(art)
        evil["derived"] = dict(evil["derived"])
        evil["derived"]["policy.manifest.json"] = '{"forged": true}'
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.load_artifact(evil)
        self.assertEqual(ctx.exception.code, "policy-ci-derived-tampered")

    def test_unknown_format_invalid(self):
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.load_artifact({"format": "nope"})
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_verify_for_source_stale_refused(self):
        art = good_artifact()
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.verify_artifact_for_source(art, OTHER)
        self.assertEqual(ctx.exception.code, "policy-ci-derived-tampered")

    def test_verify_for_source_happy(self):
        art = good_artifact()
        self.assertIsInstance(PCI.verify_artifact_for_source(art, SOURCE),
                              MappingProxyType)


class CheckTests(unittest.TestCase):
    def test_missing_note_refused(self):
        art = good_artifact(change_note="  ")
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.check(SOURCE, art)
        self.assertEqual(ctx.exception.code, "policy-ci-companion-missing")

    def test_missing_probes_refused(self):
        art = good_artifact(probes=[])
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.check(SOURCE, art)
        self.assertEqual(ctx.exception.code, "policy-ci-companion-missing")

    def test_missing_author_refused(self):
        art = good_artifact(author="")
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.check(SOURCE, art)
        self.assertEqual(ctx.exception.code, "policy-ci-companion-missing")

    def test_happy(self):
        art = good_artifact()
        self.assertIsInstance(PCI.check(SOURCE, art), MappingProxyType)

    def test_stale_artifact_refused(self):
        art = good_artifact()
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.check(OTHER, art)
        self.assertEqual(ctx.exception.code, "policy-ci-derived-tampered")


class LoadPathWiringTests(unittest.TestCase):
    def test_wired_artifact_ok(self):
        art = good_artifact()
        compiled = PA.compile_authoring(SOURCE, artifact=art)
        self.assertIn("block-secret-reads", compiled.native_text)

    def test_wired_artifact_tampered(self):
        art = good_artifact()
        evil = dict(art)
        evil["derived"] = dict(evil["derived"])
        evil["derived"]["policy.native.yaml"] = "garbage"
        with self.assertRaises(Exception) as ctx:
            PA.compile_authoring(SOURCE, artifact=evil)
        self.assertEqual(ctx.exception.code, "policy-ci-derived-tampered")

    def test_no_artifact_unchanged(self):
        compiled = PA.compile_authoring(SOURCE)
        self.assertIn("block-secret-reads", compiled.native_text)


class RolloutTests(unittest.TestCase):
    def _rollout(self, obs=60, start=1000.0):
        art = good_artifact()
        return PCI.begin_rollout(art, observation_seconds=obs, now=start)

    def _promoted(self, obs=60):
        rec = self._rollout(obs=obs)
        rec = PCI.observe(rec, [{"decision": "deny", "tool": "read_file"}])
        seed = ED.generate_seed()
        report, sig = PCI.sign_report(seed, rec)
        return PCI.promote(rec, report=report, signature=sig,
                           pubkey=ED.publickey(seed), now=1000.0 + obs + 10)

    def test_begin_state_dryrun(self):
        rec = self._rollout()
        self.assertEqual(PCI.status(rec), "dryrun")
        self.assertIsInstance(rec, MappingProxyType)

    def test_begin_bad_window_invalid(self):
        art = good_artifact()
        for bad in (0, -5, "60", True, 1.5):
            with self.assertRaises(PCI.PolicyCIError) as ctx:
                PCI.begin_rollout(art, observation_seconds=bad, now=1.0)
            self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_promote_happy(self):
        final = self._promoted()
        self.assertEqual(PCI.status(final), "enforcing")

    def test_promote_window_not_elapsed(self):
        rec = self._rollout()
        seed = ED.generate_seed()
        report, sig = PCI.sign_report(seed, rec)
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.promote(rec, report=report, signature=sig,
                        pubkey=ED.publickey(seed), now=1001.0)
        self.assertEqual(ctx.exception.code, "policy-ci-dryrun-skipped")

    def test_promote_no_report(self):
        rec = self._rollout()
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.promote(rec, report=None, signature=b"y" * 64,
                        pubkey=b"z" * 32, now=1100.0)
        self.assertEqual(ctx.exception.code, "policy-ci-dryrun-skipped")

    def test_promote_forged_report(self):
        rec = self._rollout()
        seed = ED.generate_seed()
        report, sig = PCI.sign_report(seed, rec)
        wrong_pub = ED.publickey(ED.generate_seed())
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.promote(rec, report=report, signature=sig,
                        pubkey=wrong_pub, now=1100.0)
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_promote_double(self):
        final = self._promoted()
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.promote(final, report=b"x", signature=b"y" * 64,
                        pubkey=b"z" * 32, now=1200.0)
        self.assertEqual(ctx.exception.code, "policy-ci-dryrun-skipped")

    def test_unknown_state_invalid(self):
        bogus = MappingProxyType({"format": PCI.ROLLOUT_FORMAT, "state": "x"})
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.status(bogus)
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_observe_chains(self):
        rec = self._rollout()
        rec2 = PCI.observe(rec, [{"decision": "deny"}])
        self.assertNotEqual(rec2["decisions_digest"], rec["decisions_digest"])
        self.assertEqual(rec2["decisions_count"], 1)
        # Original record is immutable.
        self.assertEqual(rec["decisions_count"], 0)

    def test_observe_non_mapping_invalid(self):
        rec = self._rollout()
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.observe(rec, ["not-a-mapping"])
        self.assertEqual(ctx.exception.code, "policy-ci-invalid")

    def test_observe_after_enforce_refused(self):
        final = self._promoted()
        with self.assertRaises(PCI.PolicyCIError) as ctx:
            PCI.observe(final, [{"decision": "deny"}])
        self.assertEqual(ctx.exception.code, "policy-ci-dryrun-skipped")


if __name__ == "__main__":
    unittest.main()
