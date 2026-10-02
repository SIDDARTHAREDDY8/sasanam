"""Unit tests for tools/forcing_honesty.py (W240-1, FORCING-HONESTY).

Behavior-level tests at the public seams. The demo fixture (a toy
guard + toy battery) keeps the campaign fast and deterministic.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools import forcing_honesty as fh  # noqa: E402


def _demo():
    tmp = tempfile.mkdtemp(prefix="fh-unit-")
    harness = fh.ForcingHarness(repo_root=tmp, work_root=tmp)
    cond = fh.demo_condition(tmp)
    with open(os.path.join(tmp, cond.target)) as fp:
        src = fp.read()
    muts = fh.enumerate_mutations(src)
    return tmp, harness, cond, muts


def _teardown(tmp):
    shutil.rmtree(tmp, ignore_errors=True)


def _mut_by(muts, operator, hint=None):
    for m in muts:
        if m.operator == operator and (hint is None or hint in m.description):
            return m
    raise AssertionError("no %s mutation%s" % (
        operator, " with %r" % hint if hint else ""))


class MutationOperatorTests(unittest.TestCase):
    def test_enumerate_finds_emission_site(self):
        muts = fh.enumerate_mutations(fh.DEMO_GUARD_SOURCE)
        ops = {m.operator for m in muts}
        self.assertIn("remove_call", ops)
        self.assertIn("remove_raise", ops)

    def test_stable_ids_unique(self):
        muts = fh.enumerate_mutations(fh.DEMO_GUARD_SOURCE)
        ids = [m.stable_id for m in muts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_remove_call_drops_emission(self):
        muts = fh.enumerate_mutations(fh.DEMO_GUARD_SOURCE)
        mut = _mut_by(muts, "remove_call", "EMISSIONS.append")
        out = fh.apply_mutation(fh.DEMO_GUARD_SOURCE, mut)
        self.assertNotIn("EMISSIONS.append", out)
        self.assertIn("raise RefusalError", out)
        compile(out, "<mut>", "exec")  # still valid python

    def test_remove_raise_drops_refusal(self):
        muts = fh.enumerate_mutations(fh.DEMO_GUARD_SOURCE)
        mut = _mut_by(muts, "remove_raise")
        out = fh.apply_mutation(fh.DEMO_GUARD_SOURCE, mut)
        self.assertNotIn("raise RefusalError", out)
        compile(out, "<mut>", "exec")

    def test_flip_bool(self):
        muts = fh.enumerate_mutations("x = True\n")
        mut = _mut_by(muts, "flip_bool")
        out = fh.apply_mutation("x = True\n", mut)
        self.assertIn("x = False", out)

    def test_flip_compare(self):
        muts = fh.enumerate_mutations("if a == b:\n    pass\n")
        mut = _mut_by(muts, "flip_compare")
        out = fh.apply_mutation("if a == b:\n    pass\n", mut)
        self.assertIn("!=", out)

    def test_remove_disjunct_and_conjunct(self):
        src = "if a or b:\n    pass\nif c and d:\n    pass\n"
        muts = fh.enumerate_mutations(src)
        disj = _mut_by(muts, "remove_disjunct")
        conj = _mut_by(muts, "remove_conjunct")
        self.assertIn("if a:", fh.apply_mutation(src, disj))
        self.assertIn("if c:", fh.apply_mutation(src, conj))

    def test_delete_branch_and_truncate_loop(self):
        src = ("if x:\n    y()\nelse:\n    z()\n"
               "for i in items:\n    w(i)\n")
        muts = fh.enumerate_mutations(src)
        branch = _mut_by(muts, "delete_branch")
        loop = _mut_by(muts, "truncate_loop")
        out = fh.apply_mutation(src, branch)
        compile(out, "<mut>", "exec")
        self.assertNotIn("y()", out.split("else:")[0])
        out2 = fh.apply_mutation(src, loop)
        compile(out2, "<mut>", "exec")
        self.assertNotIn("w(i)", out2)

    def test_delete_case_arm(self):
        src = ("match cmd:\n"
               '    case "a":\n'
               "        run_a()\n"
               '    case "b":\n'
               "        run_b()\n")
        muts = fh.enumerate_mutations(src)
        arms = [m for m in muts if m.operator == "delete_case_arm"]
        self.assertEqual(len(arms), 2)
        out = fh.apply_mutation(src, arms[0])
        compile(out, "<mut>", "exec")
        self.assertNotIn("run_a()", out)
        self.assertIn("run_b()", out)

    def test_unknown_site_refuses(self):
        mut = fh.Mutation(operator="remove_raise", lineno=9999, col=0)
        with self.assertRaises(fh.HonestyError) as cm:
            fh.apply_mutation("x = 1\n", mut)
        self.assertEqual(cm.exception.code, "honesty-mutant-invalid")


class ClassificationTests(unittest.TestCase):
    def test_emission_removal_is_silent(self):
        tmp, harness, cond, muts = _demo()
        try:
            mut = _mut_by(muts, "remove_call", "EMISSIONS.append")
            res = harness.run_condition(cond, mut)
            self.assertEqual(res.classification, fh.SILENT)
        finally:
            _teardown(tmp)

    def test_raise_removal_is_killed(self):
        tmp, harness, cond, muts = _demo()
        try:
            mut = _mut_by(muts, "remove_raise")
            res = harness.run_condition(cond, mut)
            self.assertEqual(res.classification, fh.KILLED)
            self.assertIn("toy-refuses", res.killed_probes)
        finally:
            _teardown(tmp)

    def test_identity_mutation_is_dead(self):
        # A mutation that changes nothing observable: flip a bool in a
        # comment-free dead spot is hard on the toy; instead replay the
        # pristine battery twice -- identical observations must be DEAD
        # when compared. Direct classify() check:
        tmp, harness, cond, _ = _demo()
        try:
            pre = harness.run_battery(cond)
            self.assertEqual(fh.classify(pre, pre), fh.DEAD)
        finally:
            _teardown(tmp)

    def test_timing_noise_normalizes_to_dead(self):
        # Battery notes carry "(%.1fms)" timing; it must not flip
        # DEAD/SILENT between identical-behavior runs.
        pre = fh.BatteryRun(
            condition_id="x", probes={"p": "HELD"}, held=1,
            stdout="p HELD ok (0.3ms)\nsummary: 1 HELD / 0 GAP / 0 BREAK / 0 ERROR\n",
            exit_code=0)
        post = fh.BatteryRun(
            condition_id="x", probes={"p": "HELD"}, held=1,
            stdout="p HELD ok (1.7ms)\nsummary: 1 HELD / 0 GAP / 0 BREAK / 0 ERROR\n",
            exit_code=0)
        self.assertEqual(fh.classify(pre, post), fh.DEAD)
        self.assertEqual(fh.classify_independent(pre, post), fh.DEAD)

    def test_syntax_error_is_inconclusive(self):
        tmp, harness, cond, muts = _demo()
        try:
            mut = _mut_by(muts, "remove_call", "EMISSIONS.append")
            bad = fh.Mutation(operator="remove_call",
                              lineno=mut.lineno, col=mut.col,
                              description=mut.description)
            # Corrupt the mutant file after writing: write garbage.
            res_pre = harness.run_battery(cond)
            mut_dir = os.path.join(tmp, "bad-mutant")
            os.makedirs(mut_dir)
            bad_path = os.path.join(mut_dir, "toy_guard.py")
            with open(bad_path, "w") as fp:
                fp.write("def broken(:\n")
            post = harness.run_battery(cond, mutant_path=bad_path)
            self.assertTrue(post.failed_to_build)
            self.assertEqual(fh.classify(res_pre, post), fh.INCONCLUSIVE)
        finally:
            _teardown(tmp)

    def test_import_time_name_error_is_inconclusive_not_killed(self):
        # A mutant that breaks module import with a non-syntax exception
        # never built: INCONCLUSIVE, never credited as KILLED.
        tmp, harness, cond, _ = _demo()
        try:
            pre = harness.run_battery(cond)
            mut_dir = os.path.join(tmp, "nameerror-mutant")
            os.makedirs(mut_dir)
            bad_path = os.path.join(mut_dir, "toy_guard.py")
            with open(bad_path, "w") as fp:
                fp.write("import _undefined_module_xyz\n"
                         + fh.DEMO_GUARD_SOURCE)
            post = harness.run_battery(cond, mutant_path=bad_path)
            self.assertTrue(post.load_failed)
            self.assertEqual(fh.classify(pre, post), fh.INCONCLUSIVE)
            self.assertEqual(fh.classify_independent(pre, post),
                             fh.INCONCLUSIVE)
        finally:
            _teardown(tmp)

    def test_crosscheck_agrees_on_demo_campaign(self):
        tmp, harness, cond, muts = _demo()
        try:
            emit = _mut_by(muts, "remove_call", "EMISSIONS.append")
            kill = _mut_by(muts, "remove_raise")
            results = [harness.run_condition(cond, emit),
                       harness.run_condition(cond, kill)]
            self.assertEqual(fh.crosscheck(results), [])
        finally:
            _teardown(tmp)


class BaselineTests(unittest.TestCase):
    def _results(self, harness, cond, muts, tmp):
        emit = _mut_by(muts, "remove_call", "EMISSIONS.append")
        kill = _mut_by(muts, "remove_raise")
        return [harness.run_condition(cond, emit),
                harness.run_condition(cond, kill)]

    def test_sync_writes_checksummed_baseline(self):
        tmp, harness, cond, muts = _demo()
        try:
            results = self._results(harness, cond, muts, tmp)
            path = os.path.join(tmp, "baseline.json")
            fh.sync_baseline(results, [cond], path)
            loaded = fh.load_baseline(path)
            self.assertIn(cond.id, loaded["conditions"])
            # SILENT present -> not forced.
            self.assertFalse(loaded["conditions"][cond.id]["forced"])
            self.assertEqual(loaded["conditions"][cond.id]["silent"], 1)
            self.assertEqual(loaded["conditions"][cond.id]["killed"], 1)
        finally:
            _teardown(tmp)

    def test_hand_edit_refused(self):
        tmp, harness, cond, muts = _demo()
        try:
            results = self._results(harness, cond, muts, tmp)
            path = os.path.join(tmp, "baseline.json")
            fh.sync_baseline(results, [cond], path)
            with open(path) as fp:
                data = json.load(fp)
            data["conditions"][cond.id]["silent"] = 0
            with open(path, "w") as fp:
                json.dump(data, fp, indent=2, sort_keys=True)
            with self.assertRaises(fh.HonestyError) as cm:
                fh.load_baseline(path)
            self.assertEqual(cm.exception.code, "honesty-baseline-tampered")
        finally:
            _teardown(tmp)

    def test_tighten_only_blocks_unforce(self):
        tmp, harness, cond, muts = _demo()
        try:
            kill = _mut_by(muts, "remove_raise")
            # Baseline where the condition IS forced (only the kill).
            forced_results = [harness.run_condition(cond, kill)]
            path = os.path.join(tmp, "baseline.json")
            fh.sync_baseline(forced_results, [cond], path)
            self.assertTrue(
                fh.load_baseline(path)["conditions"][cond.id]["forced"])
            # New campaign introduces a SILENT mutation: unforced.
            weak_results = self._results(harness, cond, muts, tmp)
            with self.assertRaises(fh.HonestyError) as cm:
                fh.sync_baseline(weak_results, [cond], path)
            self.assertEqual(cm.exception.code, "honesty-baseline-unforced")
            # ... unless named one at a time to --accept-unforced.
            fh.sync_baseline(weak_results, [cond], path,
                             accept_unforced=(cond.id,))
            # Two at a time is refused even if both are real.
            with self.assertRaises(fh.HonestyError) as cm2:
                fh.sync_baseline(weak_results, [cond], path,
                                 accept_unforced=(cond.id, "other"))
            self.assertEqual(cm2.exception.code, "honesty-baseline-unforced")
        finally:
            _teardown(tmp)

    def _synth_result(self, cond, classification):
        mut = fh.Mutation(operator="remove_raise", lineno=1, col=0)
        pre = fh.BatteryRun(condition_id=cond.id)
        post = fh.BatteryRun(condition_id=cond.id)
        return fh.MutationResult(condition=cond, mutation=mut,
                                 classification=classification,
                                 pre=pre, post=post)

    def test_ratchet_hole_two_unforce_one_named(self):
        # Two conditions unforce, only one named: the sync must refuse --
        # the unnamed one may not loosen silently.
        cond_a = fh.Condition(id="fc-a", target="t.py", battery="b.py")
        cond_b = fh.Condition(id="fc-b", target="t.py", battery="b.py")
        tmp = tempfile.mkdtemp(prefix="fh-unit-")
        try:
            path = os.path.join(tmp, "baseline.json")
            forced = [self._synth_result(cond_a, fh.KILLED),
                      self._synth_result(cond_b, fh.KILLED)]
            fh.sync_baseline(forced, [cond_a, cond_b], path)
            weak = [self._synth_result(cond_a, fh.SILENT),
                    self._synth_result(cond_b, fh.SILENT)]
            with self.assertRaises(fh.HonestyError) as cm:
                fh.sync_baseline(weak, [cond_a, cond_b], path,
                                 accept_unforced=("fc-a",))
            self.assertEqual(cm.exception.code, "honesty-baseline-unforced")
            # Naming the single unforced condition works.
            weak_one = [self._synth_result(cond_a, fh.SILENT),
                        self._synth_result(cond_b, fh.KILLED)]
            fh.sync_baseline(weak_one, [cond_a, cond_b], path,
                             accept_unforced=("fc-a",))
        finally:
            _teardown(tmp)


class CoverageTests(unittest.TestCase):
    def test_vacuous_probe_flagged_killing_probe_not(self):
        tmp, harness, cond, muts = _demo()
        try:
            emit = _mut_by(muts, "remove_call", "EMISSIONS.append")
            kill = _mut_by(muts, "remove_raise")
            results = [harness.run_condition(cond, emit),
                       harness.run_condition(cond, kill)]
            suspects = fh.analyze_probe_coverage(results)
            by_probe = {s["probe"]: s for s in suspects}
            self.assertIn("toy-constant", by_probe)
            self.assertEqual(by_probe["toy-constant"]["code"],
                             "honesty-tautology-suspect")
            self.assertNotIn("toy-refuses", by_probe)
        finally:
            _teardown(tmp)

    def test_silent_finding_hook(self):
        tmp, harness, cond, muts = _demo()
        try:
            emit = _mut_by(muts, "remove_call", "EMISSIONS.append")
            kill = _mut_by(muts, "remove_raise")
            results = [harness.run_condition(cond, emit),
                       harness.run_condition(cond, kill)]
            findings = fh.file_silent_findings(results)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["code"], "honesty-condition-silent")
            self.assertEqual(findings[0]["condition"], cond.id)
            # Public-seam evidence: the observation diff is attached.
            self.assertIn("toy-emissions-observed", findings[0]["evidence"])
        finally:
            _teardown(tmp)


class PinTests(unittest.TestCase):
    def test_taxonomy_pin(self):
        from gov import decision_codes as dc
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1715)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        for code in ("honesty-baseline-tampered",
                     "honesty-baseline-unforced",
                     "honesty-condition-silent",
                     "honesty-tautology-suspect",
                     "honesty-mutant-invalid",
                     "honesty-mutant-inconclusive"):
            dc.code_for(code)


if __name__ == "__main__":
    unittest.main()
