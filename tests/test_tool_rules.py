"""Unit tests for gov/tool_rules.py: declared tool-call sequence grammar.

Tests live at the public seams: compile_rule_set, check_call, and the
opt-in composition with gov/tool_call_policy.py's decide. Expected values
come from the spec (hand-written rule sets with known outcomes), never
recomputed from the implementation.
"""

import unittest

from gov import tool_call_policy as tp
from gov import tool_rules as tr


def _doc(**over):
    doc = {
        "format": "sasanam-tool-rule-set/v1",
        "name": "unit-rules",
        "tools": ["read_file", "write_file", "shell"],
        "predicates": {
            "approved": {"kind": "flag", "flag": "human_approved"},
        },
        "rules": [
            {"kind": "Init", "tool": "read_file"},
            {"kind": "Child", "tool": "write_file", "parent": "read_file"},
            {"kind": "Terminal", "tool": "shell"},
        ],
    }
    doc.update(over)
    return doc


def _policy_doc():
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "unit-tr-policy",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "*", "operation": "run",
             "severity": 1, "tags": []},
        ],
    }


def _caller():
    return {"authenticated": True, "identity": "agent-1"}


class CompileTest(unittest.TestCase):
    def test_valid_compiles_with_stable_digest(self):
        a = tr.compile_rule_set(_doc())
        b = tr.compile_rule_set(_doc())
        self.assertEqual(a.digest, b.digest)
        self.assertEqual(len(a.digest), 64)
        self.assertEqual(a.name, "unit-rules")

    def test_closed_inventory(self):
        rs = tr.compile_rule_set(_doc())
        self.assertEqual(set(rs.tools), {"read_file", "write_file", "shell"})

    def test_unknown_kind_refused_coded(self):
        doc = _doc(rules=[{"kind": "Nuke", "tool": "shell"}])
        with self.assertRaises(tr.ToolRuleError) as cm:
            tr.compile_rule_set(doc)
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")

    def test_non_dict_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            tr.compile_rule_set(["nope"])
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")

    def test_wrong_format_refused_coded(self):
        doc = _doc()
        doc["format"] = "something-else/v1"
        with self.assertRaises(tr.ToolRuleError) as cm:
            tr.compile_rule_set(doc)
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")

    def test_child_self_parent_refused(self):
        doc = _doc(rules=[{"kind": "Child", "tool": "shell",
                           "parent": "shell"}])
        with self.assertRaises(tr.ToolRuleError) as cm:
            tr.compile_rule_set(doc)
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")

    def test_conditional_undeclared_predicate_refused(self):
        doc = _doc(rules=[{"kind": "Conditional", "tool": "shell",
                           "when": "ghost"}])
        with self.assertRaises(tr.ToolRuleError) as cm:
            tr.compile_rule_set(doc)
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")

    def test_unknown_rule_key_refused(self):
        doc = _doc(rules=[{"kind": "Init", "tool": "read_file",
                           "sneaky": True}])
        with self.assertRaises(tr.ToolRuleError) as cm:
            tr.compile_rule_set(doc)
        self.assertEqual(cm.exception.code, "toolcall-rule-compile-invalid")

    def test_caller_doc_mutation_inert(self):
        doc = _doc()
        rs = tr.compile_rule_set(doc)
        doc["rules"].append({"kind": "Terminal", "tool": "read_file"})
        rec = rs.check_call("read_file", {}, [])
        self.assertTrue(rec["allowed"])

    def test_compiled_doc_frozen(self):
        rs = tr.compile_rule_set(_doc())
        with self.assertRaises(TypeError):
            rs._doc["rules"] = ()


class SequenceTest(unittest.TestCase):
    def setUp(self):
        self.rs = tr.compile_rule_set(_doc())

    def test_init_first_allowed(self):
        rec = self.rs.check_call("read_file", {}, [])
        self.assertTrue(rec["allowed"])
        self.assertEqual(rec["tool"], "read_file")

    def test_init_late_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("read_file", {}, [{"tool": "read_file"}])
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")

    def test_child_after_parent_allowed(self):
        rec = self.rs.check_call("write_file", {},
                                 [{"tool": "read_file"}])
        self.assertTrue(rec["allowed"])

    def test_child_first_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("write_file", {}, [])
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")

    def test_child_after_stranger_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("write_file", {}, [{"tool": "shell"}])
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")

    def test_terminal_call_allowed_then_session_closed(self):
        rec = self.rs.check_call("shell", {}, [{"tool": "read_file"}])
        self.assertTrue(rec["allowed"])
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("read_file", {}, [{"tool": "shell"}])
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")

    def test_undeclared_tool_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("nmap", {}, [])
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")

    def test_ill_typed_tool_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call(None, {}, [])
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")

    def test_unconstrained_declared_tool_allowed(self):
        rs = tr.compile_rule_set(_doc(rules=[]))
        rec = rs.check_call("shell", {}, [{"tool": "read_file"}])
        self.assertTrue(rec["allowed"])


class ConditionalTest(unittest.TestCase):
    def test_flag_predicate(self):
        rs = tr.compile_rule_set(_doc(
            rules=[{"kind": "Conditional", "tool": "shell",
                    "when": "approved"}]))
        with self.assertRaises(tr.ToolRuleError) as cm:
            rs.check_call("shell", {}, [])
        self.assertEqual(cm.exception.code, "toolcall-sequence-violated")
        rec = rs.check_call("shell", {}, [],
                            context_flags={"human_approved": True})
        self.assertTrue(rec["allowed"])

    def test_history_predicate(self):
        doc = _doc(
            predicates={"read_twice": {"kind": "history",
                                       "tool": "read_file",
                                       "min_calls": 2}},
            rules=[{"kind": "Conditional", "tool": "write_file",
                    "when": "read_twice"}])
        rs = tr.compile_rule_set(doc)
        with self.assertRaises(tr.ToolRuleError):
            rs.check_call("write_file", {}, [{"tool": "read_file"}])
        rec = rs.check_call("write_file", {},
                            [{"tool": "read_file"},
                             {"tool": "read_file"}])
        self.assertTrue(rec["allowed"])


class SecretGateTest(unittest.TestCase):
    def setUp(self):
        self.rs = tr.compile_rule_set(_doc())

    def test_sk_value_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("read_file",
                               {"token": "sk-abcdefghijklmnop123456"}, [])
        self.assertEqual(cm.exception.code, "toolcall-secret-in-args")

    def test_nested_secret_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("read_file",
                               {"opts": {"key": "ghp_" + "z" * 24}}, [])
        self.assertEqual(cm.exception.code, "toolcall-secret-in-args")

    def test_secret_named_arg_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call("read_file", {"api_key": "placeholder"}, [])
        self.assertEqual(cm.exception.code, "toolcall-secret-in-args")

    def test_pem_block_refused_coded(self):
        with self.assertRaises(tr.ToolRuleError) as cm:
            self.rs.check_call(
                "read_file",
                {"blob": "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n"}, [])
        self.assertEqual(cm.exception.code, "toolcall-secret-in-args")

    def test_benign_args_allowed(self):
        rec = self.rs.check_call("read_file",
                                 {"path": "/tmp/x", "mode": "text"}, [])
        self.assertTrue(rec["allowed"])


class CompositionTest(unittest.TestCase):
    def _bound(self):
        rs = tr.compile_rule_set(_doc())
        comp = tp.compile_policy(_policy_doc())
        comp.bind_rule_set(rs)
        return comp

    def test_sequence_violation_denies_coded_in_decide(self):
        comp = self._bound()
        d = comp.decide(_caller(), "write_file", "run", args={},
                        history=[])
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.code, "toolcall-sequence-violated")
        self.assertEqual(d.rejection_layer, "sequence")

    def test_legal_sequence_allows_in_decide(self):
        comp = self._bound()
        d = comp.decide(_caller(), "write_file", "run", args={},
                        history=[{"tool": "read_file"}])
        self.assertEqual(d.verdict, "ALLOW")

    def test_secret_args_deny_coded_in_decide(self):
        comp = self._bound()
        d = comp.decide(_caller(), "read_file", "run",
                        args={"token": "sk-abcdefghijklmnop123456"},
                        history=[])
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.code, "toolcall-secret-in-args")

    def test_unbound_policy_ignores_sequence(self):
        comp = tp.compile_policy(_policy_doc())
        d = comp.decide(_caller(), "write_file", "run", args={},
                        history=[])
        self.assertEqual(d.verdict, "ALLOW")

    def test_bind_rejects_wrong_type(self):
        comp = tp.compile_policy(_policy_doc())
        with self.assertRaises(tp.ToolCallPolicyError):
            comp.bind_rule_set({"not": "a rule set"})

    def test_binding_derives_history_from_allow_decisions(self):
        rs = tr.compile_rule_set(_doc())
        comp = tp.compile_policy(_policy_doc())
        comp.bind_rule_set(rs)
        binding = tp.bind(comp, comp.digest)
        caller = _caller()
        self.assertEqual(
            binding.decide(caller, "read_file", "run", args={}).verdict,
            "ALLOW")
        self.assertEqual(
            binding.decide(caller, "write_file", "run", args={}).verdict,
            "ALLOW")
        # Terminal shell closes the session; the next call must DENY.
        self.assertEqual(
            binding.decide(caller, "shell", "run", args={}).verdict,
            "ALLOW")
        d = binding.decide(caller, "read_file", "run", args={})
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.code, "toolcall-sequence-violated")


if __name__ == "__main__":
    unittest.main()
