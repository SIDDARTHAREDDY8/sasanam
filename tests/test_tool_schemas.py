"""Unit tests for gov/tool_schemas.py: declarative typed tool schemas.

Tests live at the public seams: compile_schema_set, validate_args, and
the opt-in composition with gov/tool_call_policy.py's decide. Expected
values come from the spec (hand-written schema docs with known
outcomes), never recomputed from the implementation.
"""

import unittest

from gov import tool_call_policy as tp
from gov import tool_schemas as ts


def _doc(**over):
    doc = {
        "format": "sasanam-tool-schema-set/v1",
        "name": "unit-schemas",
        "tools": {
            "search": {"args": {
                "query": {"type": "string", "max_len": 64},
                "limit": {"type": "integer", "min_value": 1,
                          "max_value": 100, "optional": True,
                          "default": 10},
                "mode": {"type": "enum",
                         "choices": ["fast", "deep"],
                         "optional": True, "default": "fast"},
                "verbose": {"type": "boolean", "optional": True},
                "tags": {"type": "list",
                         "element": {"type": "string", "max_len": 16},
                         "max_items": 8, "optional": True},
                "flags": {"type": "dict",
                          "value": {"type": "boolean"},
                          "max_items": 16, "optional": True},
            }},
            "ping": {"args": {}},
        },
    }
    doc.update(over)
    return doc


def _policy_doc(**over):
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "unit-ts-policy",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [{"action": "ALLOW", "tool": "*", "operation": "run"}],
    }
    doc.update(over)
    return doc


def _caller():
    return {"identity": "agent-1", "authenticated": True}


class CompileTests(unittest.TestCase):
    def test_valid_compiles_with_stable_digest(self):
        a = ts.compile_schema_set(_doc())
        b = ts.compile_schema_set(_doc())
        self.assertEqual(a.digest, b.digest)
        self.assertTrue(a.digest)

    def test_tools_closed_inventory(self):
        ss = ts.compile_schema_set(_doc())
        self.assertEqual(ss.tools, ("ping", "search"))

    def test_bad_format_refused(self):
        doc = _doc()
        doc["format"] = "nope"
        with self.assertRaises(ts.ToolSchemaError) as cm:
            ts.compile_schema_set(doc)
        self.assertEqual(cm.exception.code,
                         "toolcall-schema-compile-invalid")

    def test_unknown_field_type_refused(self):
        doc = _doc()
        doc["tools"]["search"]["args"]["query"]["type"] = "float"
        with self.assertRaises(ts.ToolSchemaError) as cm:
            ts.compile_schema_set(doc)
        self.assertEqual(cm.exception.code,
                         "toolcall-schema-compile-invalid")

    def test_credential_field_names_refused(self):
        for bad in ("api_key", "password", "clientSecret",
                    "ACCESS-TOKEN", "session_token", "pwd_hash"):
            doc = _doc()
            doc["tools"]["search"]["args"][bad] = {"type": "string",
                                                   "max_len": 8}
            with self.assertRaises(ts.ToolSchemaError) as cm:
                ts.compile_schema_set(doc)
            self.assertEqual(cm.exception.code,
                             "toolcall-schema-secret-field",
                             "field name %r" % (bad,))

    def test_credential_like_tool_name_allowed(self):
        # The gate applies to FIELD names only: a tool may be named for
        # a credential domain; a field may not.
        doc = _doc()
        doc["tools"]["secrets-rotate"] = {"args": {}}
        ss = ts.compile_schema_set(doc)
        self.assertIn("secrets-rotate", ss.tools)

    def test_unbounded_string_refused(self):
        doc = _doc()
        del doc["tools"]["search"]["args"]["query"]["max_len"]
        with self.assertRaises(ts.ToolSchemaError) as cm:
            ts.compile_schema_set(doc)
        self.assertEqual(cm.exception.code,
                         "toolcall-schema-compile-invalid")

    def test_unsafe_pattern_refused(self):
        doc = _doc()
        doc["tools"]["search"]["args"]["query"]["pattern"] = r"(a+)+$"
        with self.assertRaises(ts.ToolSchemaError) as cm:
            ts.compile_schema_set(doc)
        self.assertEqual(cm.exception.code,
                         "toolcall-schema-compile-invalid")

    def test_safe_pattern_accepted(self):
        doc = _doc()
        doc["tools"]["search"]["args"]["query"]["pattern"] = r"[a-z0-9 ]+"
        ss = ts.compile_schema_set(doc)
        out = ss.validate_args("search", {"query": "hello world 1"})
        self.assertEqual(out["query"], "hello world 1")
        with self.assertRaises(ts.ToolSchemaError) as cm:
            ss.validate_args("search", {"query": "HELLO!"})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_bad_default_refused_at_compile(self):
        doc = _doc()
        doc["tools"]["search"]["args"]["limit"]["default"] = 500
        with self.assertRaises(ts.ToolSchemaError) as cm:
            ts.compile_schema_set(doc)
        self.assertEqual(cm.exception.code,
                         "toolcall-schema-compile-invalid")

    def test_default_requires_optional(self):
        doc = _doc()
        doc["tools"]["search"]["args"]["query"]["default"] = "x"
        with self.assertRaises(ts.ToolSchemaError):
            ts.compile_schema_set(doc)

    def test_frozen_doc_resists_mutation(self):
        ss = ts.compile_schema_set(_doc())
        with self.assertRaises(TypeError):
            ss._doc["tools"]["search"]["args"]["query"]["max_len"] = 1


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.ss = ts.compile_schema_set(_doc())

    def test_valid_injects_defaults(self):
        out = self.ss.validate_args("search", {"query": "q"})
        self.assertEqual(out,
                         {"query": "q", "limit": 10, "mode": "fast"})

    def test_undeclared_tool_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("nosuch", {})
        self.assertEqual(cm.exception.code,
                         "toolcall-schema-unknown-tool")

    def test_undeclared_arg_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search", {"query": "q", "nope": 1})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_missing_required_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search", {"limit": 5})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_int_as_string_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search", {"query": 42})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_bool_is_not_integer(self):
        # Strict typing: bool is not a valid integer (pydantic-strict
        # semantics).
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search", {"query": "q", "limit": True})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_non_bool_refused_for_boolean(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search",
                                  {"query": "q", "verbose": 1})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_range_escape_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search", {"query": "q", "limit": 0})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_oversized_list_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search",
                                  {"query": "q", "tags": ["t"] * 9})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_bad_list_element_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search",
                                  {"query": "q", "tags": ["ok", 7]})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_bad_dict_value_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search",
                                  {"query": "q",
                                   "flags": {"verbose": "yes"}})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_null_value_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search", {"query": None})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_enum_violation_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search",
                                  {"query": "q", "mode": "warp"})
        self.assertEqual(cm.exception.code, "toolcall-schema-invalid")

    def test_secret_shaped_value_refused(self):
        with self.assertRaises(ts.ToolSchemaError) as cm:
            self.ss.validate_args("search",
                                  {"query": "sk-abcdef1234567890XY"})
        self.assertEqual(cm.exception.code, "toolcall-secret-in-args")

    def test_validated_output_is_alias_free(self):
        args = {"query": "q", "tags": ["a"]}
        out = self.ss.validate_args("search", args)
        args["tags"].append("b")
        self.assertEqual(out["tags"], ["a"])

    def test_empty_args_tool(self):
        out = self.ss.validate_args("ping", {})
        self.assertEqual(out, {})


class ComposeTests(unittest.TestCase):
    def test_bound_registry_prefilters_decide(self):
        ss = ts.compile_schema_set(_doc())
        pol = tp.compile_policy(_policy_doc())
        pol.bind_schema_registry(ss)
        good = pol.decide(_caller(), "search", "run", {"query": "ok"})
        self.assertEqual(good.verdict, "ALLOW")
        bad = pol.decide(_caller(), "search", "run", {"query": 5})
        self.assertEqual(bad.verdict, "DENY")
        self.assertEqual(bad.code, "toolcall-schema-invalid")
        self.assertEqual(bad.rejection_layer, "schema")

    def test_bound_registry_closes_tool_inventory(self):
        ss = ts.compile_schema_set(_doc())
        pol = tp.compile_policy(_policy_doc())
        pol.bind_schema_registry(ss)
        d = pol.decide(_caller(), "nosuch", "run", {})
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.code, "toolcall-schema-unknown-tool")

    def test_unbound_policy_unchanged(self):
        pol = tp.compile_policy(_policy_doc())
        d = pol.decide(_caller(), "search", "run", {"query": 5})
        self.assertEqual(d.verdict, "ALLOW")

    def test_audit_mode_would_deny(self):
        ss = ts.compile_schema_set(_doc())
        pol = tp.compile_policy(_policy_doc(mode="audit"))
        pol.bind_schema_registry(ss)
        d = pol.decide(_caller(), "search", "run", {"query": 5})
        self.assertEqual(d.verdict, "ALLOW")
        self.assertEqual(d.code, "toolcall-audit-would-deny")

    def test_bind_rejects_wrong_type(self):
        pol = tp.compile_policy(_policy_doc())
        with self.assertRaises(tp.ToolCallPolicyError):
            pol.bind_schema_registry({"not": "a schema set"})

    def test_validated_defaults_flow_into_rules(self):
        # A DENY rule on the defaulted value must see the injected
        # default, proving validated args flow into the policy rules.
        ss = ts.compile_schema_set(_doc())
        doc = _policy_doc()
        doc["rules"] = [{"action": "DENY", "tool": "search",
                         "operation": "run",
                         "args": {"mode": {"equals": "fast"}}}]
        pol = tp.compile_policy(doc)
        pol.bind_schema_registry(ss)
        d = pol.decide(_caller(), "search", "run", {"query": "q"})
        self.assertEqual(d.verdict, "DENY")


if __name__ == "__main__":
    unittest.main()
