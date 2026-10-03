"""Unit tests for F396: the F393 code binding binds __defaults__/__kwdefaults__.

F396 (MEDIUM, wave-311 independent red-team): `_code_fingerprint` never
read `__defaults__`/`__kwdefaults__` -- two fns with identical bytecode
but different default-argument values yielded identical code_digest and
therefore identical plan digests, defeating the run->plan binding (the
victim's fn never executed; the attacker's outputs returned as native).

The fix (wave-312 lane A) adds `_defaults_fingerprint`: JSON-native
default values bind by value (positional order preserved, keyword-only
sorted by name); non-JSON-native ("exotic") defaults refuse coded
`workflow-composed-definition-invalid` (F395-shaped fail closed). No new
decision codes; pin unchanged 1841.
"""
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import workflow_composed as wc

REFUSAL = "workflow-composed-definition-invalid"


def _code(fn):
    try:
        return wc._code_fingerprint(fn), None
    except Exception as e:  # noqa: BLE001
        return None, getattr(e, "code", None)


class DefaultsFingerprintTest(unittest.TestCase):
    def test_no_defaults_binds_empty_marker(self):
        def fn(i):
            return i

        fp, code = _code(fn)
        self.assertIsNone(code)
        self.assertEqual(fp["defaults"], {"pos": [], "kw": []})

    def test_none_defaults_same_as_empty(self):
        def f_none(i):
            return i

        def f_empty(i, *a):
            return i

        # Both have __defaults__/__kwdefaults__ None; the empty marker
        # binds identically (the calling-convention difference is
        # already covered by _code_fingerprint_inner).
        fp_none, _ = _code(f_none)
        fp_empty, _ = _code(f_empty)
        self.assertEqual(fp_none["defaults"], fp_empty["defaults"])

    def test_positional_defaults_bound_by_value(self):
        def mk(v):
            def fn(i, c=v):
                return i
            return fn

        fa, _ = _code(mk({"e": "evil"}))
        fb, _ = _code(mk({"e": "real"}))
        self.assertNotEqual(fa, fb)
        self.assertEqual(fa["defaults"], {"pos": [{"e": "evil"}], "kw": []})

    def test_kwdefaults_bound_by_value(self):
        def mk(v):
            def fn(i, *, c=v):
                return i
            return fn

        fa, _ = _code(mk(1))
        fb, _ = _code(mk(2))
        self.assertNotEqual(fa, fb)
        self.assertEqual(
            fa["defaults"], {"pos": [], "kw": [["c", 1]]})

    def test_kwdefaults_only(self):
        def mk():
            def fn(i, *, retries=3, endpoint="x"):
                return i
            return fn

        fp, code = _code(mk())
        self.assertIsNone(code)
        # Keyword-only defaults sort by name for determinism.
        self.assertEqual(fp["defaults"],
                         {"pos": [], "kw": [["endpoint", "x"],
                                            ["retries", 3]]})

    def test_nested_defaults_bound_by_value(self):
        def mk(v):
            def fn(i, c=v):
                return i
            return fn

        fa, _ = _code(mk({"e": "x", "r": [1, {"n": 2}]}))
        fb, _ = _code(mk({"e": "x", "r": [1, {"n": 2}]}))
        fc, _ = _code(mk({"e": "x", "r": [1, {"n": 3}]}))
        self.assertEqual(fa, fb)
        self.assertNotEqual(fa, fc)

    def test_same_values_rebuild_same_fingerprint(self):
        # Crash-recovery stability: the same source rebuilt yields the
        # same fingerprint (no memory addresses, no identity hashes).
        def mk(v):
            def fn(i, c=v):
                return i
            return fn

        fa, _ = _code(mk({"e": "x"}))
        fb, _ = _code(mk({"e": "x"}))
        self.assertEqual(fa, fb)

    def test_exotic_positional_default_refuses_coded(self):
        class Exotic:
            pass

        def mk(v):
            def fn(i, c=v):
                return i
            return fn

        _, code = _code(mk(Exotic()))
        self.assertEqual(code, REFUSAL)

    def test_exotic_kwdefault_refuses_coded(self):
        class Exotic:
            pass

        def mk(v):
            def fn(i, *, c=v):
                return i
            return fn

        _, code = _code(mk(Exotic()))
        self.assertEqual(code, REFUSAL)

    def test_exotic_nested_in_container_refuses_coded(self):
        class Exotic:
            pass

        def mk(v):
            def fn(i, c={"wrapped": v}):
                return i
            return fn

        _, code = _code(mk(Exotic()))
        self.assertEqual(code, REFUSAL)

    def test_dict_subclass_default_refuses_coded(self):
        # Exact-builtin rule (F395): a lying container subclass cannot
        # be bound by value, so it refuses.
        class Sneaky(dict):
            pass

        def mk(v):
            def fn(i, c=v):
                return i
            return fn

        _, code = _code(mk(Sneaky({"e": "x"})))
        self.assertEqual(code, REFUSAL)

    def test_mutation_after_construction_binds_construction_time(self):
        # Documented residual (same TOCTOU class as F395 closures): the
        # plan digest binds the defaults as of plan construction.
        def mk(v):
            def fn(i, c=v):
                return i
            return fn

        fn = mk({"e": "real"})
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": fn,
             "inputs": {}, "idem_key": "k"}])
        fn.__defaults__ = ({"e": "evil"},)
        # A fresh fingerprint sees the mutation...
        mutated, _ = _code(fn)
        pristine, _ = _code(mk({"e": "real"}))
        self.assertNotEqual(mutated, pristine)
        # ...but the plan digest still matches the construction-time
        # values.
        fresh = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": mk({"e": "real"}),
             "inputs": {}, "idem_key": "k"}])
        self.assertEqual(plan.digest, fresh.digest)

    def test_bound_method_defaults_do_not_crash(self):
        class Svc:
            def run(self, i, retries=3):
                return i

        fp, code = _code(Svc().run)
        self.assertIsNone(code)
        self.assertEqual(fp["defaults"], {"pos": [3], "kw": []})

    def test_plan_construction_refuses_exotic_default_coded(self):
        class Exotic:
            pass

        def fn(i, c=Exotic()):
            return i

        with self.assertRaises(Exception) as ctx:
            wc.ComposedPlan([
                {"kind": "fn", "name": "u", "fn": fn,
                 "inputs": {}, "idem_key": "k"}])
        self.assertEqual(getattr(ctx.exception, "code", None), REFUSAL)


if __name__ == "__main__":
    unittest.main()
