"""Adapter tests: generic decorator + context-manager registry.

Covers mediation of allowed/denied/queued calls, fail-closed behavior
for unregistered tools and positional args, the run_body execution
model, registry sealing, and bypass attempts (raw function handles,
__wrapped__ stripping, post-seal registration).
"""

import os
import sys
import unittest
from types import MappingProxyType

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.adapters.core import (
    AdapterError,
    ApprovalRequiredError,
    GovernedBinding,
    ToolDeniedError,
    UnregisteredToolError,
)
from gov.adapters.generic import governed, governed_registry


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


class TestGovernedDecorator(unittest.TestCase):
    def test_allowed_call_returns_executor_result(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, tool="write_file")
        def write_notes(path, content):
            """Write notes (body is spec only; never runs by default)."""

        result = write_notes(path="notes.txt", content="hello")
        self.assertEqual(result["status"], "executed")
        self.assertTrue((ctx["run_dir"] / "sandbox" / "notes.txt").is_file())

    def test_tool_name_defaults_to_function_name(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding)
        def read_file(path):
            """Read a file."""

        self.assertEqual(read_file.__governed_tool__, "read_file")
        result = read_file(path="notes.txt")
        self.assertEqual(result["status"], "executed")

    def test_denied_call_raises_by_default(self):
        ctx = make_run()
        binding = _coder_binding(ctx)  # coder may not send_email

        @governed(binding)
        def send_email(to, subject, body):
            """Send an email."""

        with self.assertRaises(ToolDeniedError) as cm:
            send_email(to="x@synthetic.local", subject="s", body="b")
        self.assertEqual(cm.exception.result["status"], "denied")
        self.assertEqual(cm.exception.framework_tool, "send_email")

    def test_denied_call_return_mode(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, on_denied="return")
        def send_email(to, subject, body):
            """Send an email."""

        result = send_email(to="x@synthetic.local", subject="s", body="b")
        self.assertEqual(result["status"], "denied")

    def test_queued_call_raises_approval_required(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, tool="write_file")
        def write_outside(path, content):
            """Write outside the sandbox (needs approval)."""

        with self.assertRaises(ApprovalRequiredError) as cm:
            write_outside(path="/tmp/adapter-should-not-write.txt",
                          content="x")
        self.assertIsNotNone(cm.exception.approval_id)
        self.assertEqual(cm.exception.result["status"], "queued")
        self.assertFalse(
            os.path.exists("/tmp/adapter-should-not-write.txt"),
            "queued call must not execute anywhere")

    def test_unregistered_tool_fails_closed(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, tool="drop_database")
        def drop_database(name):
            """Not a real tool."""

        with self.assertRaises(UnregisteredToolError):
            drop_database(name="prod")
        # The executor never saw it: no counter entry, no log entry.
        self.assertNotIn("drop_database", ctx["executor"].counters)

    def test_positional_args_rejected(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, tool="read_file")
        def read_it(path):
            """Read."""

        with self.assertRaises(AdapterError):
            read_it("notes.txt")

    def test_body_does_not_run_by_default(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        ran = []

        @governed(binding, tool="write_file")
        def write_it(path, content):
            ran.append(True)
            return "body-value"

        result = write_it(path="a.txt", content="x")
        self.assertEqual(result["status"], "executed")
        self.assertEqual(ran, [], "default mode must not run the body")
        self.assertNotIn("body_result", result)

    def test_run_body_mode_runs_after_execute(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, tool="read_file", run_body=True)
        def read_it(path):
            return "body-saw-" + path

        result = read_it(path="notes.txt")
        self.assertEqual(result["status"], "executed")
        self.assertEqual(result["body_result"], "body-saw-notes.txt")
        self.assertIn("split authorization/execution",
                      result["execution_note"])

    def test_run_body_not_run_when_denied(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        ran = []

        @governed(binding, run_body=True)  # name -> send_email: denied
        def send_email(to, subject, body):
            ran.append(True)

        with self.assertRaises(ToolDeniedError):
            send_email(to="x@synthetic.local", subject="s", body="b")
        self.assertEqual(ran, [])

    def test_invalid_on_denied_rejected(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with self.assertRaises(ValueError):
            governed(binding, on_denied="sometimes")

    def test_wrapped_bypass_removed(self):
        """functools.wraps would otherwise publish __wrapped__ as a raw,
        unmediated handle to the original function."""
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, tool="read_file")
        def read_it(path):
            """Read."""

        self.assertFalse(hasattr(read_it, "__wrapped__"),
                         "__wrapped__ must not expose the raw function")
        # Metadata is still preserved for introspection/docs.
        self.assertEqual(read_it.__name__, "read_it")
        self.assertIn("Read.", read_it.__doc__)

    def test_binding_requires_governed_binding(self):
        ctx = make_run()
        with self.assertRaises(TypeError):
            governed(ctx["executor"])


class TestBindingImmutability(unittest.TestCase):
    def test_tool_map_is_immutable(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        self.assertIsInstance(binding.tool_map, MappingProxyType)
        with self.assertRaises(TypeError):
            binding.tool_map["evil"] = "read_file"

    def test_alias_mapping(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        binding = GovernedBinding(ctx["executor"], ident,
                                  tool_map={"read_notes": "read_file"})
        self.assertEqual(binding.resolve("read_notes"), "read_file")
        self.assertEqual(binding.resolve("read_file"), "read_file")

    def test_invalid_native_target_rejected(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        with self.assertRaises(ValueError):
            GovernedBinding(ctx["executor"], ident,
                             tool_map={"x": "not_a_tool"})

    def test_non_string_tool_name_rejected(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        with self.assertRaises((ValueError, TypeError)):
            GovernedBinding(ctx["executor"], ident, tool_map={None: "read_file"})

    def test_executor_and_identity_type_checked(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        with self.assertRaises(TypeError):
            GovernedBinding("not-an-executor", ident)
        with self.assertRaises(TypeError):
            GovernedBinding(ctx["executor"], "not-an-identity")

    def test_control_kwarg_collision_fails_loudly(self):
        # `on_denied`/`on_queued`/`framework_tool` are adapter control
        # parameters. A tool argument with the same name cannot be routed
        # through this API: Python raises TypeError (duplicate keyword)
        # instead of silently misrouting it. None of the six native tools
        # have such argument names.
        ctx = make_run()
        binding = _coder_binding(ctx)

        @governed(binding, tool="read_file")
        def read_it(path, on_denied="nope"):
            """Read."""

        with self.assertRaises(TypeError):
            read_it(path="x.txt", on_denied="raise")


class TestGovernedRegistry(unittest.TestCase):
    def test_register_call_and_seal(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with governed_registry(binding) as reg:
            @reg.tool("write_file")
            def _write(path, content):
                """Write."""

            self.assertEqual(reg.tools(), ["write_file"])
            result = reg.call("write_file", path="r.txt", content="z")
            self.assertEqual(result["status"], "executed")
            self.assertFalse(reg.sealed)
        self.assertTrue(reg.sealed)
        # Dispatch still works after sealing; registration does not.
        result = reg.call("write_file", path="r2.txt", content="z")
        self.assertEqual(result["status"], "executed")
        with self.assertRaises(AdapterError):
            reg.register("read_file", lambda path: None)

    def test_register_positional_form(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with governed_registry(binding) as reg:
            def read_file(path):
                """Read."""
            wrapped = reg.register(read_file)
            self.assertIs(wrapped, reg.resolve("read_file"))
            self.assertEqual(reg.call("read_file", path="x.txt")["status"],
                             "executed")

    def test_register_unknown_name_fails_closed_at_registration(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with governed_registry(binding) as reg:
            with self.assertRaises(UnregisteredToolError):
                reg.register("drop_database", lambda name: None)

    def test_double_registration_rejected(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with governed_registry(binding) as reg:
            reg.register("read_file", lambda path: None)
            with self.assertRaises(AdapterError):
                reg.register("read_file", lambda path: None)

    def test_dispatch_unknown_name_fails_closed(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with governed_registry(binding) as reg:
            with self.assertRaises(UnregisteredToolError):
                reg.call("nope", x=1)

    def test_denied_dispatch_raises(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with governed_registry(binding) as reg:
            reg.register("send_email", lambda to, subject, body: None)
            with self.assertRaises(ToolDeniedError):
                reg.call("send_email", to="x@synthetic.local",
                         subject="s", body="b")

    def test_bypass_raw_function_is_unmediated_by_design(self):
        """Documents the trust boundary: the undecorated raw function is
        just a function. Only governed handles are handed to agents."""
        ctx = make_run()
        binding = _coder_binding(ctx)
        side_effects = []

        def raw_write(path, content):
            side_effects.append((path, content))

        wrapped = governed(binding, tool="write_file")(raw_write)
        # Calling the raw function directly bypasses mediation entirely --
        # this is why agent code must only receive `wrapped`.
        raw_write(path="evil.txt", content="x")
        self.assertEqual(side_effects, [("evil.txt", "x")])
        self.assertNotIn("write_file", ctx["executor"].counters)


if __name__ == "__main__":
    unittest.main()
