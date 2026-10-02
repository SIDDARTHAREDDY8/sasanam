"""Unit tests for gov/eval_tasks.py (wave-280 lane 6)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import eval_tasks as et


def _grader(sample, output):
    return 1.0 if output == sample["want"] else 0.0


def _reg():
    reg = et.EvalTaskRegistry()
    reg.register_dataset("ds", [{"q": "a", "want": "A"},
                                {"q": "b", "want": "B"}])
    reg.register_scoring_function("exact", _grader)
    reg.register_eval_task("t", dataset_id="ds", scoring_ids=["exact"],
                           run_config={"temperature": 0})
    return reg


class RegistryTest(unittest.TestCase):
    def test_dataset_digest_stable(self):
        r1, r2 = _reg(), _reg()
        self.assertEqual(r1.get_dataset("ds")["dataset_digest"],
                         r2.get_dataset("ds")["dataset_digest"])

    def test_duplicate_dataset_refused(self):
        reg = et.EvalTaskRegistry()
        reg.register_dataset("d", [{"a": 1}])
        with self.assertRaises(et.EvalTaskError) as ctx:
            reg.register_dataset("d", [{"a": 1}])
        self.assertEqual(ctx.exception.code, "evaltask-duplicate-dataset")

    def test_codes_are_machine_readable(self):
        reg = et.EvalTaskRegistry()
        with self.assertRaises(et.EvalTaskError) as ctx:
            reg.get_eval_task("ghost")
        self.assertEqual(ctx.exception.code, "evaltask-unknown-task")
        with self.assertRaises(et.EvalTaskError) as ctx:
            reg.get_dataset("ghost")
        self.assertEqual(ctx.exception.code, "evaltask-unknown-dataset")

    def test_duplicate_scoring_refused(self):
        reg = et.EvalTaskRegistry()
        reg.register_scoring_function("s", _grader)
        with self.assertRaises(et.EvalTaskError):
            reg.register_scoring_function("s", _grader)

    def test_task_pins_digests(self):
        reg = _reg()
        task = reg.get_eval_task("t")
        self.assertEqual(task["dataset_digest"],
                         reg.get_dataset("ds")["dataset_digest"])
        self.assertEqual(task["scoring_functions"]["exact"],
                         reg.get_scoring_function("exact")["digest"])

    def test_unknown_references_refused(self):
        reg = et.EvalTaskRegistry()
        with self.assertRaises(et.EvalTaskError):
            reg.register_eval_task("t", dataset_id="ghost",
                                   scoring_ids=["exact"])

    def test_non_json_sample_refused(self):
        reg = et.EvalTaskRegistry()
        with self.assertRaises(et.EvalTaskError):
            reg.register_dataset("d", [{"f": object()}])


class RunTest(unittest.TestCase):
    def test_headless_run_means(self):
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        self.assertEqual(res["sample_count"], 2)
        self.assertEqual(res["means"]["exact"], 1.0)
        self.assertTrue(et.verify_eval_result(res))

    def test_partial_credit_mean(self):
        reg = _reg()
        res = et.run_eval_task(
            reg, "t", target=lambda s: s["want"] if s["q"] == "a" else "zzz")
        self.assertEqual(res["means"]["exact"], 0.5)
        self.assertTrue(et.verify_eval_result(res))

    def test_target_crash_loud(self):
        reg = _reg()

        def _boom(sample):
            raise RuntimeError("x")

        with self.assertRaises(et.EvalTaskError):
            et.run_eval_task(reg, "t", target=_boom)

    def test_grader_crash_loud(self):
        reg = et.EvalTaskRegistry()
        reg.register_dataset("d", [{"a": 1}])

        def _bad(sample, output):
            raise RuntimeError("x")

        reg.register_scoring_function("bad", _bad)
        reg.register_eval_task("t", dataset_id="d", scoring_ids=["bad"])
        with self.assertRaises(et.EvalTaskError) as ctx:
            et.run_eval_task(reg, "t", target=lambda s: 1)
        self.assertEqual(ctx.exception.code, "evaltask-grader-crashed")

    def test_nan_score_refused(self):
        reg = et.EvalTaskRegistry()
        reg.register_dataset("d", [{"a": 1}])
        reg.register_scoring_function(
            "nan", lambda s, o: float("nan"))
        reg.register_eval_task("t", dataset_id="d", scoring_ids=["nan"])
        with self.assertRaises(et.EvalTaskError):
            et.run_eval_task(reg, "t", target=lambda s: 1)

    def test_bool_score_refused(self):
        reg = et.EvalTaskRegistry()
        reg.register_dataset("d", [{"a": 1}])
        reg.register_scoring_function("b", lambda s, o: True)
        reg.register_eval_task("t", dataset_id="d", scoring_ids=["b"])
        with self.assertRaises(et.EvalTaskError):
            et.run_eval_task(reg, "t", target=lambda s: 1)

    def test_tampered_result_fails(self):
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        res["per_sample"][0]["scores"]["exact"] = 0.0
        self.assertFalse(et.verify_eval_result(res))
        res2 = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        res2["means"]["exact"] = 0.0
        self.assertFalse(et.verify_eval_result(res2))

    def test_hostile_shapes_fail_verify(self):
        self.assertFalse(et.verify_eval_result(None))
        self.assertFalse(et.verify_eval_result({}))
        self.assertFalse(et.verify_eval_result({"result_digest": "x"}))


class EvidencePackageTest(unittest.TestCase):
    def test_package_verifies_standalone(self):
        import hashlib
        import json
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        pkg = et.eval_task_evidence_package(res)
        body = {k: pkg[k] for k in pkg if k != "package_digest"}
        expect = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, default=str).encode("utf-8")).hexdigest()
        self.assertEqual(pkg["package_digest"], expect)
        self.assertEqual(pkg["artifact_kind"], "eval-task-result")

    def test_unverifiable_result_not_packaged(self):
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        res["means"]["exact"] = 0.5
        with self.assertRaises(et.EvalTaskError):
            et.eval_task_evidence_package(res)


class VerifyConsistencyTest(unittest.TestCase):
    def test_integer_scores_verify(self):
        # _check_score accepts ints; verify must too (external auditors
        # may hand-build results with integer scores).
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        for row in res["per_sample"]:
            row["scores"] = {k: int(v) for k, v in row["scores"].items()}
        res["means"] = {k: int(v) for k, v in res["means"].items()}
        body = {k: res[k] for k in res if k != "result_digest"}
        import hashlib
        import json
        res["result_digest"] = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, default=str).encode("utf-8")).hexdigest()
        self.assertTrue(et.verify_eval_result(res))

    def test_swapped_grader_refused_at_run(self):
        reg = _reg()
        task = reg.get_eval_task("t")
        task["scoring_functions"]["exact"] = "0" * 64  # corrupt the pin
        with self.assertRaises(et.EvalTaskError):
            et.run_eval_task(reg, "t", target=lambda s: s["want"])

    def test_swapped_dataset_refused_at_run(self):
        reg = _reg()
        task = reg.get_eval_task("t")
        task["dataset_digest"] = "0" * 64
        with self.assertRaises(et.EvalTaskError):
            et.run_eval_task(reg, "t", target=lambda s: s["want"])


class BindFeedTest(unittest.TestCase):
    def test_bind_appends_event_with_package(self):
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        events = []

        class _Log:
            def append(self, rec):
                events.append(rec)

        pkg = et.bind_eval_task_result(
            _Log(), "t", res, run_id="r1", agent_id="eval-harness")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "eval-task-result")
        self.assertEqual(events[0]["package"], pkg)

    def test_bind_refuses_unverifiable(self):
        reg = _reg()
        res = et.run_eval_task(reg, "t", target=lambda s: s["want"])
        res["means"]["exact"] = 0.0

        class _Log:
            def append(self, rec):
                raise AssertionError("must not append")

        with self.assertRaises(et.EvalTaskError):
            et.bind_eval_task_result(
                _Log(), "t", res, run_id="r1", agent_id="eval-harness")

    def test_bundle_feed_end_to_end(self):
        import secrets
        from tests.keyfixture import provision_test_key, scrub_key_env
        from gov.log import ActionLog, read_entries
        from gov.evidence_bundle import EvidenceBundle
        from gov.signing import Ed25519Signer
        restore = scrub_key_env()  # hermetic: never depend on ambient keys
        provision_test_key()
        try:
            reg = _reg()
            res = et.run_eval_task(reg, "t",
                                   target=lambda s: s["want"])
            d = tempfile.mkdtemp(prefix="g280feed_")
            log = ActionLog(os.path.join(d, "audit.jsonl"))
            log.append({"event": "policy_loaded", "run_id": "r1",
                        "agent_id": "system", "decision": "policy_loaded",
                        "policy_id": "policy-pin", "policy_path": "/x",
                        "policy_hash": "ab" * 32, "pinned": True,
                        "reason": "test"})
            pkg = et.bind_eval_task_result(
                log, "t", res, run_id="r1", agent_id="eval-harness")
            eb = EvidenceBundle(log.path)
            manifest = eb.seal(
                eb.build(), signer=Ed25519Signer(
                    secrets.token_bytes(32)))
            self.assertTrue(manifest.get("chain_verified"))
            found = [e for e in read_entries(log.path)
                     if e.get("event") == "eval-task-result"]
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["package"], pkg)
        finally:
            restore()


if __name__ == "__main__":
    unittest.main()
