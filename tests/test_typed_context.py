"""Unit tests for the wave-194 R1 typed context-attribute schema.

The schema (gov/context_schema.py) is the Cedar D1 steal: mistyped
context attributes are refused LOUD at the Request boundary instead of
being silently bool()/int()-coerced at match time.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.context_schema import (
    BOOL_SIGNALS,
    CONTEXT_SCHEMA,
    THRESHOLD_KEYS,
    ContextTypeError,
    checked_bool,
    checked_counter,
    validate_context,
    validate_match_types,
)
from gov.decision_contract import Request
from gov.policy import PolicyEngine, default_policy_path


def _action(tool="http_post", args=None):
    return {"tool": tool, "role": "analyst", "agent_id": "alice",
            "args": args or {"url": "https://evil.example/x"}}


class ValidateContextTests(unittest.TestCase):
    def test_all_bool_signals_accept_bool(self):
        for key in BOOL_SIGNALS:
            validate_context({key: True})
            validate_context({key: False})

    def test_bool_signals_reject_string(self):
        # The D1 red: a truthy string is NOT a bool.
        for key in ("domain_allowlisted", "read_classified"):
            with self.assertRaises(ContextTypeError) as cm:
                validate_context({key: "false"})
            self.assertIn(key, str(cm.exception))

    def test_bool_signals_reject_int(self):
        # Truthy ints are not bools either.
        with self.assertRaises(ContextTypeError):
            validate_context({"domain_allowlisted": 1})
        with self.assertRaises(ContextTypeError):
            validate_context({"domain_allowlisted": 0})

    def test_none_is_absence(self):
        # None is the documented absence sentinel, not a mistype.
        for key in BOOL_SIGNALS:
            validate_context({key: None})

    def test_counters_accept_ints(self):
        validate_context({"counters": {"api_call": 5, "send_email": 0}})

    def test_counters_reject_string(self):
        with self.assertRaises(ContextTypeError) as cm:
            validate_context({"counters": {"api_call": "5"}})
        self.assertIn("api_call", str(cm.exception))

    def test_counters_reject_bool(self):
        # bool is not int: int(True) == 1 would silently coerce.
        with self.assertRaises(ContextTypeError):
            validate_context({"counters": {"api_call": True}})

    def test_counters_reject_non_mapping(self):
        with self.assertRaises(ContextTypeError):
            validate_context({"counters": "nope"})

    def test_scalar_kinds(self):
        validate_context({"api_calls": 3, "path_resolved": "a/b",
                          "sandbox_root": "/s", "artifact_refs": [],
                          "registry_hosts": ["h"], "authority_proof": {}})
        for key, bad in (("api_calls", True), ("api_calls", "3"),
                         ("path_resolved", 5),
                         ("sandbox_root", b"x"),
                         ("artifact_refs", "x"),
                         ("registry_hosts", "x"),
                         ("authority_proof", "x")):
            with self.assertRaises(ContextTypeError, msg=key):
                validate_context({key: bad})

    def test_unknown_keys_pass_through(self):
        # Forward compatibility: undeclared keys are ignored.
        validate_context({"some_future_signal": "x", "role": "analyst"})

    def test_error_names_key_and_types(self):
        try:
            validate_context({"domain_allowlisted": "false"})
        except ContextTypeError as e:
            msg = str(e)
            self.assertIn("domain_allowlisted", msg)
            self.assertIn("bool", msg)
            self.assertIn("str", msg)
        else:
            self.fail("no refusal")
        # Machine-distinguishable: it is a TypeError.
        self.assertTrue(issubclass(ContextTypeError, TypeError))


class CheckedAccessorTests(unittest.TestCase):
    def test_checked_bool_passthrough_and_absence(self):
        self.assertTrue(checked_bool({"k": True}, "k"))
        self.assertFalse(checked_bool({"k": False}, "k"))
        self.assertFalse(checked_bool({"k": None}, "k"))
        self.assertFalse(checked_bool({}, "k"))

    def test_checked_bool_refuses(self):
        for bad in ("false", "true", 1, 0, 1.0, [], {}):
            with self.assertRaises(ContextTypeError, msg=repr(bad)):
                checked_bool({"k": bad}, "k")

    def test_checked_counter_passthrough_and_default(self):
        self.assertEqual(checked_counter({"api_call": 5}, "api_call"), 5)
        self.assertEqual(checked_counter({}, "api_call"), 0)
        self.assertEqual(checked_counter(None, "api_call"), 0)

    def test_checked_counter_refuses(self):
        for bad in ("5", True, 1.0, None):
            with self.assertRaises(ContextTypeError, msg=repr(bad)):
                checked_counter({"api_call": bad}, "api_call")
        with self.assertRaises(ContextTypeError):
            checked_counter("nope", "api_call")


class ValidateMatchTypesTests(unittest.TestCase):
    def test_valid_match_values_accepted(self):
        validate_match_types("r", {"tool": ["http_post"],
                                   "domain_allowlisted": False,
                                   "min_external_calls": 5,
                                   "path_contains_any": ["/etc", "/x"]})

    def test_bool_key_string_refused(self):
        with self.assertRaises(ValueError) as cm:
            validate_match_types("r", {"domain_allowlisted": "false"})
        self.assertIn("domain_allowlisted", str(cm.exception))

    def test_bool_key_int_refused(self):
        with self.assertRaises(ValueError):
            validate_match_types("r", {"read_classified": 1})

    def test_threshold_string_refused(self):
        with self.assertRaises(ValueError) as cm:
            validate_match_types("r", {"min_external_calls": "5"})
        self.assertIn("min_external_calls", str(cm.exception))

    def test_threshold_bool_refused(self):
        with self.assertRaises(ValueError):
            validate_match_types("r", {"min_sends": True})

    def test_path_contains_any_non_string_refused(self):
        with self.assertRaises(ValueError):
            validate_match_types("r", {"path_contains_any": [5]})


class RequestWiringTests(unittest.TestCase):
    def test_request_refuses_mistyped_context(self):
        with self.assertRaises(TypeError):
            Request(principal="a", action="http_post", resource=None,
                    role="r", args={},
                    context={"domain_allowlisted": "false"})

    def test_request_accepts_well_typed_context(self):
        req = Request(principal="a", action="http_post", resource=None,
                      role="r", args={},
                      context={"domain_allowlisted": False,
                               "counters": {"api_call": 2},
                               "path_resolved": None})
        self.assertFalse(req.context["domain_allowlisted"])

    def test_from_action_validates(self):
        with self.assertRaises(TypeError):
            Request.from_action(
                {"tool": "http_post", "role": "r", "agent_id": "a",
                 "args": {}},
                {"domain_allowlisted": "yes"})


class MatchesIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine(default_policy_path())

    def test_all_bool_signals_strict_in_matches(self):
        # Every declared bool signal: bool passes through _matches,
        # a string raises -- the strict accessor is actually wired.
        for key in sorted(BOOL_SIGNALS):
            match = {"tool": ["read_file"], key: True}
            ok = self.eng._matches(match, _action("read_file", {"path": "/s/a"}),
                                   {key: True})
            self.assertTrue(ok, key)
            no = self.eng._matches(match, _action("read_file", {"path": "/s/a"}),
                                   {key: False})
            self.assertFalse(no, key)
            with self.assertRaises(ContextTypeError, msg=key):
                self.eng._matches(match, _action("read_file", {"path": "/s/a"}),
                                  {key: "true"})

    def test_counter_thresholds_strict_in_matches(self):
        match = {"tool": ["api_call"], "min_external_calls": 5}
        action = _action("api_call", {"endpoint": "https://x/"})
        self.assertTrue(self.eng._matches(
            match, action, {"counters": {"api_call": 5}}))
        self.assertFalse(self.eng._matches(
            match, action, {"counters": {"api_call": 3}}))
        with self.assertRaises(ContextTypeError):
            self.eng._matches(match, action, {"counters": {"api_call": "5"}})

    def test_default_policy_loads_with_typed_match_values(self):
        # The shipped policy must satisfy the new load-time checks.
        PolicyEngine(default_policy_path())

    def test_mistyped_policy_refused_at_load(self):
        with self.assertRaises(ValueError):
            PolicyEngine.from_text(
                "version: 2\npolicies:\n"
                "  - id: x\n    effect: deny\n"
                "    match:\n      tool: [http_post]\n"
                "      domain_allowlisted: \"false\"\n"
                "    reason: r\n",
                source_label="<test>")


class SchemaCoverageTests(unittest.TestCase):
    def test_bool_signals_match_known_match_keys(self):
        # The schema declares exactly the bool-typed match keys the
        # engine supports (modulo non-signal keys like tool/role).
        from gov.policy import KNOWN_MATCH_KEYS
        signal_keys = (KNOWN_MATCH_KEYS
                       - {"tool", "role", "agent", "path_contains_any",
                          "when"} - THRESHOLD_KEYS)
        self.assertEqual(set(BOOL_SIGNALS), set(signal_keys))

    def test_context_schema_covers_bool_signals(self):
        for key in BOOL_SIGNALS:
            self.assertEqual(CONTEXT_SCHEMA[key], "bool_or_none")


if __name__ == "__main__":
    unittest.main()
