"""Unit tests for gov.campaign (wave-283, Caldera ADAPT).

Tests at the public seams: FactStore typing, requirement gating,
objective validation, planner selection, campaign run/auto-close,
evidence chaining, deterministic replay.
"""

import json
import os
import tempfile
import unittest

from gov import battery_lang as bl
from gov import campaign as cp


def registry_of(specs):
    registry = {}
    for spec in specs:
        bl.register_atomic(registry, spec)
    return registry


def _ok_executor():
    def run(ctx):
        return "BREAK", "probe broke it"
    return {"run": run, "elevation_required": False}


def _held_executor():
    def run(ctx):
        return "HELD", "probe held it"
    return {"run": run, "elevation_required": False}


def _atomic(name, executor=None, **kw):
    spec = {"name": name,
            "description": "wave-283 campaign test atomic",
            "input_arguments": {},
            "executor": executor or _ok_executor()}
    spec.update(kw)
    return spec


def _tmpdir():
    return tempfile.mkdtemp(prefix="test-campaign-")


class TestFactStore(unittest.TestCase):
    def test_strict_types(self):
        fs = cp.FactStore()
        fs.set_fact("a.b.c", True, "bool", source="seed")
        self.assertIs(fs.get("a.b.c"), True)
        self.assertFalse(fs.has("no.such.fact"))
        self.assertEqual(fs.get("no.such.fact"), None)
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("a.b.c", 1, "int", source="seed")  # re-type
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("a.b.c", "yes", "bool", source="seed")  # mistype
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("bad trait!", True, "bool", source="seed")
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("a.b.c", "x", "nope", source="seed")
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("a.b.c", True, "bool", source="bogus")

    def test_bool_is_not_int(self):
        fs = cp.FactStore()
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("a.b.c", True, "int", source="seed")
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("a.b.c", 1, "bool", source="seed")

    def test_trait_shape(self):
        fs = cp.FactStore()
        for bad in ("single", "UPPER.case", "a..b", ".a.b", "a.b."):
            with self.assertRaises(cp.CampaignError, msg=bad):
                fs.set_fact(bad, 1, "int", source="seed")
        fs.set_fact("a.b2_c.d3", 1, "int", source="seed")
        self.assertEqual(fs.get("a.b2_c.d3"), 1)

    def test_enum_facts(self):
        fs = cp.FactStore()
        fs.set_fact("host.os.family", "linux", "enum",
                    choices=["linux", "macos", "windows"], source="seed")
        self.assertEqual(fs.get("host.os.family"), "linux")
        # Value outside the declared domain refused.
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("host.os.family", "plan9", "enum",
                        choices=["linux", "macos", "windows"], source="seed")
        # Enum needs choices; choices only valid for enum.
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("host.os.family", "linux", "enum", source="seed")
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("a.b.c", "x", "str", source="seed",
                        choices=["x"])
        # Domain is stable like the type: changing it is refused.
        with self.assertRaises(cp.CampaignError):
            fs.set_fact("host.os.family", "macos", "enum",
                        choices=["macos"], source="seed")
        # Same domain, new value: fine.
        fs.set_fact("host.os.family", "macos", "enum",
                    choices=["linux", "macos", "windows"], source="seed")
        self.assertEqual(fs.get("host.os.family"), "macos")

    def test_seed_enum(self):
        fs = cp.FactStore()
        norm = cp.seed_fact_store(fs, {
            "host.os.family": {"value": "linux", "type": "enum",
                               "choices": ["linux", "windows"]},
        })
        self.assertEqual(norm["host.os.family"]["choices"],
                         ["linux", "windows"])
        self.assertEqual(fs.get("host.os.family"), "linux")

    def test_seed_fact_store(self):
        fs = cp.FactStore()
        norm = cp.seed_fact_store(fs, {
            "a.b.c": {"value": 1, "type": "int"},
            "d.e.f": (True, "bool"),
        })
        self.assertEqual(norm["a.b.c"], {"value": 1, "type": "int"})
        self.assertEqual(fs.get("d.e.f"), True)
        with self.assertRaises(cp.CampaignError):
            cp.seed_fact_store(cp.FactStore(), {"a.b.c": "nope"})
        with self.assertRaises(cp.CampaignError):
            cp.seed_fact_store(cp.FactStore(), ["not", "a", "dict"])
        fs = cp.FactStore()
        norm = cp.seed_fact_store(fs, {
            "a.b.c": {"value": 1, "type": "int"},
            "d.e.f": (True, "bool"),
        })
        self.assertEqual(norm["a.b.c"], {"value": 1, "type": "int"})
        self.assertEqual(fs.get("d.e.f"), True)
        with self.assertRaises(cp.CampaignError):
            cp.seed_fact_store(cp.FactStore(), {"a.b.c": "nope"})
        with self.assertRaises(cp.CampaignError):
            cp.seed_fact_store(cp.FactStore(), ["not", "a", "dict"])


class TestRequirements(unittest.TestCase):
    def _store(self):
        fs = cp.FactStore()
        fs.set_fact("host.os.name", "linux", "str", source="seed")
        fs.set_fact("host.port_open", 22, "int", source="seed")
        fs.set_fact("tool.write.available", True, "bool", source="seed")
        return fs

    def test_ops(self):
        fs = self._store()
        cases = [
            ({"fact": "host.os.name", "op": "exists"}, True),
            ({"fact": "nope.nothing.x", "op": "exists"}, False),
            ({"fact": "host.os.name", "op": "eq", "value": "linux"}, True),
            ({"fact": "host.os.name", "op": "ne", "value": "win"}, True),
            ({"fact": "host.port_open", "op": "gt", "value": 20}, True),
            ({"fact": "host.port_open", "op": "lt", "value": 20}, False),
            ({"fact": "host.port_open", "op": "gte", "value": 22}, True),
            ({"fact": "host.port_open", "op": "lte", "value": 22}, True),
            ({"fact": "host.os.name", "op": "in",
               "value": ["linux", "macos"]}, True),
            ({"fact": "host.os.name", "op": "in",
               "value": ["win"]}, False),
            # Strict: int 22 != str "22"; bool is not int.
            ({"fact": "host.port_open", "op": "eq", "value": "22"}, False),
            # Numeric op on non-numeric fact is False, never raises.
            ({"fact": "host.os.name", "op": "gt", "value": 1}, False),
            # Missing fact: every op is False (fail-closed chaining).
            ({"fact": "nope.nothing.x", "op": "eq", "value": 1}, False),
        ]
        for req, want in cases:
            self.assertEqual(cp._requirement_holds(req, fs), want,
                             msg=req)

    def test_eligibility(self):
        runner = cp.CampaignRunner({})
        spec = {"requires": [{"fact": "x.y.z", "op": "exists"}]}
        self.assertFalse(runner._eligible(spec, cp.FactStore()))
        fs = cp.FactStore()
        fs.set_fact("x.y.z", 1, "int", source="seed")
        self.assertTrue(runner._eligible(spec, fs))
        self.assertTrue(runner._eligible({}, cp.FactStore()))


class TestObjectives(unittest.TestCase):
    def test_validate(self):
        g = cp.validate_objective(
            {"count": 2, "operator": "gte",
             "target": "campaign.breaks", "value": 1})
        self.assertEqual(g["count"], 2)
        for bad in (
            {"count": 0, "operator": "gte",
             "target": "campaign.breaks", "value": 1},
            {"count": 1, "operator": "maybe",
             "target": "campaign.breaks", "value": 1},
            {"count": 1, "operator": "gte",
             "target": "bad trait!", "value": 1},
            {"count": 1, "operator": "gte",
             "target": "campaign.breaks", "value": "x"},
            {"count": 1, "operator": "gte",
             "target": "campaign.breaks"},
            "not-a-dict",
        ):
            with self.assertRaises(cp.CampaignError, msg=str(bad)):
                cp.validate_objective(bad)

    def test_unknown_planner(self):
        runner = cp.CampaignRunner({})
        with self.assertRaises(cp.CampaignError):
            runner.run("x", atomics=[], planner_id="nope",
                       objectives=[], seed_facts={}, args_map={},
                       evidence_path=os.path.join(_tmpdir(), "e.jsonl"))


class TestPlanners(unittest.TestCase):
    def test_all_registered(self):
        self.assertEqual(set(cp.PLANNERS),
                         {"minimize-to-first-break", "coverage-maximizer",
                          "greedy-break-chaser"})
        self.assertIsInstance(cp.PLANNERS["minimize-to-first-break"],
                              cp._BasePlanner)


class TestRunner(unittest.TestCase):
    def _evidence(self):
        return os.path.join(_tmpdir(), "campaign.jsonl")

    def test_chain_two_atomcs(self):
        registry = registry_of([
            _atomic("first",
                    produces=[{"fact": "recon.host.reachable",
                               "type": "bool", "value": True}]),
            _atomic("second",
                    requires=[{"fact": "recon.host.reachable",
                               "op": "eq", "value": True}],
                    produces=[{"fact": "exfil.channel.open",
                               "type": "bool", "value": True}]),
        ])
        runner = cp.CampaignRunner(registry)
        path = self._evidence()
        cid = runner.run(
            "chain", atomics=["first", "second"],
            planner_id="coverage-maximizer", objectives=[], seed_facts={},
            args_map={}, evidence_path=path)
        self.assertTrue(runner.facts.get("exfil.channel.open") is True)
        summary = cp.campaign_summary(path)
        self.assertEqual(summary["outcome"], "no-eligible-atomics")
        self.assertEqual([n for _, n, _ in summary["step_verdicts"]],
                         ["first", "second"])
        self.assertTrue(cid)

    def test_produces_held_not_on_break(self):
        registry = registry_of([
            _atomic("writer", executor=_held_executor(),
                    produces=[{"fact": "tool.x.y", "type": "bool",
                               "value": True, "on": "break"}]),
        ])
        runner = cp.CampaignRunner(registry)
        runner.run("p", atomics=["writer"],
                   planner_id="minimize-to-first-break", objectives=[],
                   seed_facts={}, args_map={},
                   evidence_path=self._evidence())
        self.assertIsNone(runner.facts.get("tool.x.y"))

    def test_auto_close_reasons(self):
        # objectives-met
        registry = registry_of([_atomic("a")])
        runner = cp.CampaignRunner(registry)
        path = self._evidence()
        runner.run("o", atomics=["a"],
                   planner_id="minimize-to-first-break",
                   objectives=[{"count": 1, "operator": "gte",
                                "target": "campaign.breaks", "value": 1}],
                   seed_facts={}, args_map={}, evidence_path=path)
        self.assertEqual(cp.campaign_summary(path)["outcome"],
                         "objectives-met")
        # step-budget-exhausted (coverage-maximizer has no intrinsic
        # stop, so the budget is the binding constraint)
        runner2 = cp.CampaignRunner(registry_of([_atomic("a"), _atomic("b")]))
        path2 = self._evidence()
        runner2.run("s", atomics=["a", "b"],
                    planner_id="coverage-maximizer", objectives=[],
                    seed_facts={}, args_map={}, evidence_path=path2,
                    max_steps=1)
        self.assertEqual(cp.campaign_summary(path2)["outcome"],
                         "step-budget-exhausted")

    def test_minimize_stops_at_first_break(self):
        registry = registry_of([_atomic("a1"), _atomic("a2")])
        runner = cp.CampaignRunner(registry)
        path = self._evidence()
        runner.run("p", atomics=["a1", "a2"],
                   planner_id="minimize-to-first-break", objectives=[],
                   seed_facts={}, args_map={}, evidence_path=path)
        summary = cp.campaign_summary(path)
        self.assertEqual(summary["outcome"], "planner-stopped")
        self.assertEqual(summary["steps_run"], 1)
        self.assertEqual(summary["breaks"], 1)

    def test_manual_approve_denial(self):
        registry = registry_of([_atomic("a")])
        runner = cp.CampaignRunner(registry)
        path = self._evidence()
        runner.run("m", atomics=["a"],
                   planner_id="minimize-to-first-break", objectives=[],
                   seed_facts={}, args_map={}, evidence_path=path,
                   manual_approve=True, approve_fn=lambda n: False)
        summary = cp.campaign_summary(path)
        self.assertEqual(summary["outcome"], "approval-denied")
        self.assertEqual(summary["steps_run"], 0)

    def test_elevation_gated(self):
        def run(ctx):
            return "BREAK", "x"
        registry = registry_of([
            _atomic("root", executor={"run": run,
                                      "elevation_required": True}),
        ])
        runner = cp.CampaignRunner(registry)
        path = self._evidence()
        runner.run("e", atomics=["root"],
                   planner_id="minimize-to-first-break", objectives=[],
                   seed_facts={}, args_map={}, evidence_path=path,
                   elevation_granted=False)
        self.assertEqual(cp.campaign_summary(path)["outcome"],
                         "no-eligible-atomics")

    def test_parser_harvest_and_refusals(self):
        def parser(result):
            return [{"fact": "net.port.open", "value": 22},
                    {"fact": "undeclared.x.y", "value": 1}]
        registry = registry_of([
            _atomic("p", executor=_held_executor(),
                    produces=[{"fact": "net.port.open", "type": "int",
                               "value": 0, "on": "always"}],
                    fact_parser=parser),
        ])
        runner = cp.CampaignRunner(registry)
        path = self._evidence()
        runner.run("p", atomics=["p"],
                   planner_id="minimize-to-first-break", objectives=[],
                   seed_facts={}, args_map={}, evidence_path=path)
        # Declared parser fact harvested (overwrote the on=always
        # declaration with same type); undeclared refused.
        self.assertEqual(runner.facts.get("net.port.open"), 22)
        self.assertIsNone(runner.facts.get("undeclared.x.y"))
        steps = [r for r in cp.read_campaign_records(path)
                 if r["record_type"] == "campaign-step"]
        self.assertIn("refused", steps[0]["parser_note"])

    def test_parser_raising_is_recorded_not_fatal(self):
        def parser(result):
            raise RuntimeError("boom")
        registry = registry_of([
            _atomic("p", fact_parser=parser),
        ])
        runner = cp.CampaignRunner(registry)
        path = self._evidence()
        runner.run("p", atomics=["p"],
                   planner_id="minimize-to-first-break", objectives=[],
                   seed_facts={}, args_map={}, evidence_path=path)
        steps = [r for r in cp.read_campaign_records(path)
                 if r["record_type"] == "campaign-step"]
        self.assertEqual(steps[0]["verdict"], "BREAK")
        self.assertIn("raised RuntimeError", steps[0]["parser_note"])


class TestEvidence(unittest.TestCase):
    def _run(self, path):
        registry = registry_of([_atomic("a")])
        runner = cp.CampaignRunner(registry)
        runner.run("ev", atomics=["a"],
                   planner_id="minimize-to-first-break", objectives=[],
                   seed_facts={"seed.k.v": (1, "int")}, args_map={},
                   evidence_path=path)

    def test_chain_and_tamper(self):
        path = os.path.join(_tmpdir(), "e.jsonl")
        self._run(path)
        records = cp.read_campaign_records(path)
        self.assertTrue(cp.verify_campaign_records(records))
        self.assertEqual(records[0]["prev_digest"], cp._GENESIS)
        tampered = json.loads(json.dumps(records))
        tampered[1]["verdict"] = "BREAK" if \
            tampered[1]["verdict"] != "BREAK" else "HELD"
        self.assertFalse(cp.verify_campaign_records(tampered))
        self.assertFalse(cp.verify_campaign_records(
            records + [dict(records[-1])]))  # replayed digest breaks chain

    def test_replay_deterministic(self):
        path = os.path.join(_tmpdir(), "e.jsonl")
        self._run(path)
        registry = registry_of([_atomic("a")])
        diffs = cp.replay_campaign(path, registry)
        self.assertEqual(diffs, [])

    def test_replay_detects_verdict_drift(self):
        calls = {"n": 0}

        def run(ctx):
            calls["n"] += 1
            return ("BREAK" if calls["n"] == 1 else "HELD"), "flip-flop"
        path = os.path.join(_tmpdir(), "e.jsonl")
        registry = {}
        bl.register_atomic(registry, _atomic("flip", executor={"run": run,
            "elevation_required": False}))
        cp.CampaignRunner(registry).run(
            "flip", atomics=["flip"],
            planner_id="minimize-to-first-break", objectives=[],
            seed_facts={}, args_map={}, evidence_path=path)
        diffs = cp.replay_campaign(path, registry)
        self.assertEqual([d["kind"] for d in diffs], ["verdict-drift"])
        self.assertEqual(diffs[0]["before"], "BREAK")
        self.assertEqual(diffs[0]["after"], "HELD")


class TestGuidStability(unittest.TestCase):
    def test_legacy_guid_unaffected(self):
        registry = {}
        g1 = bl.register_atomic(registry, _atomic("legacy"))
        self.assertEqual(bl.atomic_guid({"name": "legacy",
                                         "description": "wave-283 campaign test atomic",
                                         "input_arguments": {},
                                         "dependencies": [],
                                         "executor": {"run": registry[g1]["spec"]["executor"]["run"],
                                                      "elevation_required": False}}),
                         g1)
        with_pre = bl.atomic_guid(_atomic(
            "legacy",
            requires=[{"fact": "a.b.c", "op": "exists"}]))
        self.assertNotEqual(with_pre, g1)


if __name__ == "__main__":
    unittest.main()
