"""S1 (K-017): AgentSpec DSL compiler tests (gov/dsl.py).

Verifies the v1 compiler surface:

* ``tool_call`` triggers compile to ordinary policy rules
  (allow/deny/require_approval) that inherit deny-priority evaluation
  and default-deny.
* The compiler has ZERO executor involvement: importing ``gov.dsl``
  must not import ``gov.executor``, and the module contains no
  executor import.
* Deferred v2 surface (``tool_result`` / ``queue_event`` /
  ``session_event`` triggers, ``redact`` enforcement) is REJECTED
  with an explicit "deferred to v2" error — not silently accepted.
* ``GOV_DSL_HASH`` pinning: a tampered DSL source fails closed with
  ``DslPinMismatchError`` before any rule is promoted.
* ``policy.policy_hash`` is untouched by ``apply_dsl`` (the DSL
  digest is recorded separately, per the crypto-lane boundary).

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import ast
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov.dsl import (  # noqa: E402
    DslCompileError,
    DslPinMismatchError,
    apply_dsl,
    compile_dsl,
    dsl_source_hash,
)
from gov.policy import PolicyEngine  # noqa: E402

_PIN_ENV = "GOV_DSL_HASH"

_MIN_POLICY = """\
version: 2
roles:
  tester: [read_file, api_call, http_post, send_email]
policies:
  - id: base-allow-post
    effect: allow
    match:
      tool: [http_post]
    reason: Base policy allows posts; a DSL deny must override it.
"""

_DSL_THREE_RULES = """\
- id: dsl-deny-post
  trigger: {on: tool_call, tool: http_post}
  enforcement: deny
  reason: DSL deny test.
- id: dsl-allow-api
  trigger:
    on: tool_call
    tool: api_call
  enforcement: allow
  reason: DSL allow test.
- id: dsl-queue-send
  trigger: {on: tool_call, tool: send_email}
  enforcement: require_approval
  reason: DSL queue test.
"""


def _tmpdir(prefix):
    """Private scratch dir under /tmp/gov-run (never the bare /tmp)."""
    base = Path("/tmp/gov-run")
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


class TestDslCompile(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir("govs1-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._saved_pin = os.environ.pop(_PIN_ENV, None)
        self.addCleanup(self._restore_pin)

    def _restore_pin(self):
        if self._saved_pin is None:
            os.environ.pop(_PIN_ENV, None)
        else:
            os.environ[_PIN_ENV] = self._saved_pin

    def _policy(self, text=_MIN_POLICY):
        p = self.tmp / "policy.yaml"
        p.write_text(text, encoding="utf-8")
        return PolicyEngine(str(p))

    # -- compilation ----------------------------------------------------

    def test_tool_call_triggers_compile_to_policy_rules(self):
        """allow/deny/require_approval from tool_call triggers become
        ordinary policy rule dicts (id/effect/match/reason)."""
        rules = compile_dsl(_DSL_THREE_RULES)
        self.assertEqual(len(rules), 3)
        by_id = {r["id"]: r for r in rules}
        self.assertEqual(by_id["dsl-deny-post"]["effect"], "deny")
        self.assertEqual(by_id["dsl-deny-post"]["match"],
                         {"tool": "http_post"})
        self.assertEqual(by_id["dsl-allow-api"]["effect"], "allow")
        self.assertEqual(by_id["dsl-allow-api"]["match"],
                         {"tool": "api_call"})
        self.assertEqual(by_id["dsl-queue-send"]["effect"],
                         "require_approval")
        self.assertEqual(by_id["dsl-queue-send"]["match"],
                         {"tool": "send_email"})
        # Provenance marker present on every compiled rule.
        self.assertTrue(all(r.get("dsl_rule") is True for r in rules))

    def test_tool_absent_matches_every_tool(self):
        """A trigger with no ``tool`` compiles to an empty match (the
        rule then applies to every tool)."""
        rules = compile_dsl(
            "- id: dsl-all\n"
            "  trigger: {on: tool_call}\n"
            "  enforcement: require_approval\n")
        self.assertEqual(rules[0]["match"], {})

    def test_predicate_compiles_1to1_into_match(self):
        """Predicate keys land verbatim in the rule match block; the
        trigger's tool stays a match key too."""
        rules = compile_dsl(
            "- id: dsl-pred\n"
            "  trigger: {on: tool_call, tool: http_post}\n"
            "  predicate: {read_sensitive: true}\n"
            "  enforcement: deny\n")
        self.assertEqual(rules[0]["match"],
                         {"tool": "http_post", "read_sensitive": True})

    def test_predicate_must_not_set_tool(self):
        with self.assertRaises(DslCompileError) as cm:
            compile_dsl(
                "- id: dsl-bad\n"
                "  trigger: {on: tool_call}\n"
                "  predicate: {tool: http_post}\n"
                "  enforcement: deny\n")
        self.assertIn("trigger", str(cm.exception))

    def test_unknown_predicate_key_rejected(self):
        with self.assertRaises(DslCompileError) as cm:
            compile_dsl(
                "- id: dsl-bad\n"
                "  trigger: {on: tool_call}\n"
                "  predicate: {no_such_key: true}\n"
                "  enforcement: deny\n")
        self.assertIn("unknown predicate key", str(cm.exception))

    def test_duplicate_rule_id_rejected(self):
        with self.assertRaises(DslCompileError) as cm:
            compile_dsl(
                "- id: dup\n"
                "  trigger: {on: tool_call}\n"
                "  enforcement: allow\n"
                "- id: dup\n"
                "  trigger: {on: tool_call}\n"
                "  enforcement: deny\n")
        self.assertIn("duplicate rule id", str(cm.exception))

    def test_rule_id_collision_with_policy_rejected(self):
        """apply_dsl refuses when a DSL id collides with an existing
        policy rule id (audit traceability)."""
        policy = self._policy()
        with self.assertRaises(DslCompileError) as cm:
            apply_dsl(policy,
                      "- id: base-allow-post\n"
                      "  trigger: {on: tool_call}\n"
                      "  enforcement: deny\n")
        self.assertIn("collides", str(cm.exception))
        self.assertEqual(len(policy.policies), 1)  # nothing promoted

    # -- v2 deferrals ----------------------------------------------------

    def test_deferred_triggers_rejected_with_v2_error(self):
        """tool_result / queue_event / session_event are rejected with
        an explicit 'deferred to v2' error, not a generic unknown."""
        for on in ("tool_result", "queue_event", "session_event"):
            with self.subTest(trigger=on):
                with self.assertRaises(DslCompileError) as cm:
                    compile_dsl(
                        "- id: dsl-deferred\n"
                        "  trigger: {on: %s}\n"
                        "  enforcement: deny\n" % on)
                self.assertIn("DEFERRED to v2", str(cm.exception))

    def test_redact_enforcement_rejected_with_v2_error(self):
        with self.assertRaises(DslCompileError) as cm:
            compile_dsl(
                "- id: dsl-redact\n"
                "  trigger: {on: tool_call}\n"
                "  enforcement: redact\n")
        self.assertIn("DEFERRED to v2", str(cm.exception))

    def test_unknown_trigger_rejected(self):
        with self.assertRaises(DslCompileError) as cm:
            compile_dsl(
                "- id: dsl-bad\n"
                "  trigger: {on: cron_tick}\n"
                "  enforcement: deny\n")
        self.assertIn("unknown trigger", str(cm.exception))

    # -- promotion / pinning ---------------------------------------------

    def test_apply_promotes_rules_and_records_provenance(self):
        policy = self._policy()
        digest = dsl_source_hash(_DSL_THREE_RULES)
        os.environ[_PIN_ENV] = digest  # correct pin
        rules = apply_dsl(policy, _DSL_THREE_RULES)
        self.assertEqual(len(rules), 3)
        self.assertEqual(len(policy.policies), 4)  # 1 base + 3 DSL
        self.assertEqual(policy.dsl_source_hash, digest)
        self.assertTrue(policy.dsl_pinned)
        self.assertEqual(policy.dsl_rule_ids,
                         ("dsl-deny-post", "dsl-allow-api", "dsl-queue-send"))

    def test_pin_mismatch_fails_closed_before_promotion(self):
        """A tampered (or wrongly-pinned) DSL source raises
        DslPinMismatchError and promotes NOTHING."""
        policy = self._policy()
        os.environ[_PIN_ENV] = dsl_source_hash("the-original-source")
        with self.assertRaises(DslPinMismatchError) as cm:
            apply_dsl(policy, _DSL_THREE_RULES)
        self.assertIn("pin mismatch", str(cm.exception).lower())
        self.assertEqual(len(policy.policies), 1)  # base rule only
        self.assertIsNone(policy.dsl_source_hash)
        self.assertFalse(policy.dsl_pinned)
        self.assertEqual(policy.dsl_rule_ids, ())

    def test_tampered_source_breaks_pin(self):
        """Pin computed over the original bytes; a one-byte edit to
        the source must fail the pin (the gap the pin exists for)."""
        os.environ[_PIN_ENV] = dsl_source_hash(_DSL_THREE_RULES)
        policy = self._policy()
        tampered = _DSL_THREE_RULES.replace("deny", "allow", 1)
        with self.assertRaises(DslPinMismatchError):
            apply_dsl(policy, tampered)

    def test_no_pin_applies_unpinned(self):
        """Without GOV_DSL_HASH the DSL still applies (human sign-off
        is the apply_dsl call itself); it is recorded as unpinned."""
        policy = self._policy()
        apply_dsl(policy, _DSL_THREE_RULES)
        self.assertFalse(policy.dsl_pinned)
        self.assertIsNotNone(policy.dsl_source_hash)

    def test_policy_hash_untouched_by_apply(self):
        """The DSL digest is NOT folded into policy_hash (crypto-lane
        boundary); it is recorded on separate attributes."""
        policy = self._policy()
        before = policy.policy_hash
        os.environ[_PIN_ENV] = dsl_source_hash(_DSL_THREE_RULES)
        apply_dsl(policy, _DSL_THREE_RULES)
        self.assertEqual(policy.policy_hash, before)
        self.assertEqual(policy.dsl_source_hash,
                         dsl_source_hash(_DSL_THREE_RULES))

    def test_no_dsl_leaves_provenance_null(self):
        policy = self._policy()
        self.assertIsNone(policy.dsl_source_hash)
        self.assertFalse(policy.dsl_pinned)
        self.assertEqual(policy.dsl_rule_ids, ())

    def test_compile_does_not_auto_promote(self):
        """compile_dsl alone never touches the enforced set: promotion
        happens ONLY through the explicit apply_dsl sign-off."""
        policy = self._policy()
        before = list(policy.policies)
        compile_dsl(_DSL_THREE_RULES)
        self.assertEqual(policy.policies, before)

    # -- compiled rules behave like ordinary policy rules ----------------

    def test_compiled_rules_inherit_deny_priority(self):
        """A DSL deny overrides a base allow for the same tool
        (deny-priority evaluation, forbid-first)."""
        policy = self._policy()
        apply_dsl(policy,
                  "- id: dsl-deny-post\n"
                  "  trigger: {on: tool_call, tool: http_post}\n"
                  "  enforcement: deny\n"
                  "  reason: DSL deny wins.\n")
        decision = policy.evaluate(
            {"tool": "http_post", "args": {}, "role": "tester",
             "agent_id": "a1"}, {})
        self.assertEqual(decision.effect, "deny")
        self.assertEqual(decision.policy_id, "dsl-deny-post")

    def test_compiled_rules_inherit_default_deny(self):
        """A DSL allow only fires where it matches; anything else is
        still default-denied."""
        policy = self._policy()
        apply_dsl(policy,
                  "- id: dsl-allow-api\n"
                  "  trigger: {on: tool_call, tool: api_call}\n"
                  "  enforcement: allow\n")
        action = {"tool": "api_call", "args": {}, "role": "tester",
                  "agent_id": "a1"}
        self.assertEqual(policy.evaluate(action, {}).effect, "allow")
        other = dict(action, tool="send_email")
        self.assertEqual(policy.evaluate(other, {}).effect, "deny")

    # -- zero executor involvement ----------------------------------------

    def test_dsl_import_does_not_pull_in_executor(self):
        """The DSL module's own dependency closure must not include
        gov.executor: the compiler stays usable without the executor.

        (The check bypasses gov/__init__.py, which eagerly imports
        the executor for the whole package — pre-existing design.
        What matters here is that gov/dsl.py itself, plus the modules
        it imports, never touch the executor.)"""
        code = (
            "import importlib.util, sys\n"
            "from pathlib import Path\n"
            "root = Path(%r)\n"
            "pkg = importlib.util.module_from_spec(\n"
            "    importlib.util.spec_from_loader('gov', loader=None))\n"
            "pkg.__path__ = [str(root / 'gov')]\n"
            "sys.modules['gov'] = pkg  # skip the eager package __init__\n"
            "spec = importlib.util.spec_from_file_location(\n"
            "    'gov.dsl', root / 'gov' / 'dsl.py')\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "sys.modules['gov.dsl'] = mod\n"
            "spec.loader.exec_module(mod)\n"
            "sys.exit(0 if 'gov.executor' not in sys.modules else 1)\n"
        ) % str(REPO_ROOT)
        proc = subprocess.run(
            [sys.executable, "-c", code], cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0,
                         "gov.dsl's own import closure pulled in "
                         "gov.executor: " + proc.stderr[-500:])

    def test_dsl_module_has_no_executor_import(self):
        """AST check: gov/dsl.py contains no import of the executor
        (direct or from-import)."""
        tree = ast.parse((REPO_ROOT / "gov" / "dsl.py")
                         .read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn("executor", alias.name,
                                     "gov/dsl.py imports %r" % alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn("executor", node.module or "",
                                 "gov/dsl.py from-imports %r"
                                 % (node.module,))


if __name__ == "__main__":
    unittest.main()
