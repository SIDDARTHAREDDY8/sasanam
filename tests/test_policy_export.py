"""Unit tests for gov/policy_export.py's fail-closed contract (D3, A14).

Covers: hash pinning, determinism, plain-Cedar refusal of stateful keys,
require_approval handling, bridge validation, export limitations +
strict mode, CLI exit codes, and policy_lint --export-check.
"""

import io
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from hashlib import sha256
from pathlib import Path

from gov.policy import PolicyEngine
from gov import policy_export
from gov.policy_export import (
    PolicyExportError,
    TRANSLATOR_VERSION,
    translate,
    translate_for_cedar,
    translate_for_dogwood,
    translate_text,
)


def _write(yaml_text):
    tmpdir = tempfile.mkdtemp(prefix="gov-export-ut-")
    path = Path(tmpdir) / "policy.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return str(path)


def _cleanup(path):
    try:
        Path(path).unlink()
        Path(path).parent.rmdir()
    except OSError:
        pass


STATELESS_POLICY = """\
version: 2
roles:
  coder: [read_file, write_file]
policies:
  - id: deny-secret
    effect: deny
    match:
      tool: [read_file]
      path_contains_any: [secret]
  - id: allow-reads
    effect: allow
    match:
      tool: [read_file]
"""


class HeaderTests(unittest.TestCase):
    def test_header_pins_source_hash(self):
        path = _write(STATELESS_POLICY)
        try:
            text = translate(path)
            expected = sha256(Path(path).read_bytes()).hexdigest()
            self.assertIn("// Source sha256 : %s" % expected, text)
            # ... and it matches the engine's own pin for the same file.
            self.assertEqual(expected, PolicyEngine(path).policy_hash)
        finally:
            _cleanup(path)

    def test_header_carries_translator_version(self):
        path = _write(STATELESS_POLICY)
        try:
            text = translate(path)
            self.assertIn("translator v%s" % TRANSLATOR_VERSION, text)
        finally:
            _cleanup(path)

    def test_deterministic_output(self):
        path = _write(STATELESS_POLICY)
        try:
            self.assertEqual(translate(path), translate(path))
            self.assertEqual(translate_for_dogwood(path),
                             translate_for_dogwood(path))
        finally:
            _cleanup(path)

    def test_auto_selects_cedar_for_stateless(self):
        path = _write(STATELESS_POLICY)
        try:
            text = translate(path, format="auto")
            self.assertIn("// Target format : cedar", text)
            self.assertNotIn("when temporal", text)
        finally:
            _cleanup(path)

    def test_auto_selects_dogwood_for_stateful(self):
        policy = (STATELESS_POLICY +
                  "  - id: deny-bulk\n    effect: deny\n    match:\n"
                  "      tool: [read_file]\n      min_writes: 1\n")
        path = _write(policy)
        try:
            text = translate(path, format="auto")
            self.assertIn("// Target format : dogwood", text)
        finally:
            _cleanup(path)

    def test_empty_policy_translates(self):
        path = _write("version: 2\nroles:\n  coder: [read_file]\npolicies: []\n")
        try:
            text = translate(path)
            self.assertIn("// Rules         : 0", text)
        finally:
            _cleanup(path)


class RefusalTests(unittest.TestCase):
    def test_plain_cedar_refuses_each_stateful_key(self):
        for key in ("min_external_calls", "min_sends", "min_writes",
                    "min_deletes", "cross_run_campaign",
                    "velocity_exceeded"):
            value = "true" if key in ("cross_run_campaign",
                                      "velocity_exceeded") else "1"
            policy = ("version: 2\nroles:\n  coder: [api_call]\npolicies:\n"
                      "  - id: r1\n    effect: deny\n    match:\n"
                      "      tool: [api_call]\n      %s: %s\n" % (key, value))
            path = _write(policy)
            try:
                with self.assertRaises(PolicyExportError, msg=key) as cm:
                    translate_for_cedar(path)
                self.assertIn(key, str(cm.exception))
                # dogwood must accept the same policy
                translate_for_dogwood(path)
            finally:
                _cleanup(path)

    def test_require_approval_without_bridge_refused_everywhere(self):
        policy = ("version: 2\nroles:\n  coder: [write_file]\npolicies:\n"
                  "  - id: r1\n    effect: require_approval\n    match:\n"
                  "      tool: [write_file]\n")
        path = _write(policy)
        try:
            for fmt in ("auto", "cedar", "dogwood"):
                with self.assertRaises(PolicyExportError, msg=fmt):
                    translate(path, format=fmt)
        finally:
            _cleanup(path)

    def test_unknown_tool_fails_at_load(self):
        policy = ("version: 2\nroles:\n  coder: [read_file]\npolicies:\n"
                  "  - id: r1\n    effect: deny\n    match:\n"
                  "      tool: [teleport]\n")
        path = _write(policy)
        try:
            with self.assertRaises(ValueError):
                translate(path)
        finally:
            _cleanup(path)

    def test_unknown_match_key_fails_at_load(self):
        policy = ("version: 2\nroles:\n  coder: [read_file]\npolicies:\n"
                  "  - id: r1\n    effect: deny\n    match:\n"
                  "      tool: [read_file]\n      mind_reading: true\n")
        path = _write(policy)
        try:
            with self.assertRaises(ValueError):
                translate(path)
        finally:
            _cleanup(path)

    def test_non_v2_version_refused(self):
        for version_line in ("version: 1\n", "", "version: \"2\"\n"):
            policy = (version_line + "roles:\n  coder: [read_file]\npolicies:\n"
                      "  - id: r1\n    effect: allow\n    match:\n"
                      "      tool: [read_file]\n")
            path = _write(policy)
            try:
                with self.assertRaises(PolicyExportError,
                                       msg=repr(version_line)):
                    translate(path)
            finally:
                _cleanup(path)

    def test_unknown_top_level_section_refused(self):
        policy = ("version: 2\nroles:\n  coder: [read_file]\npolicies:\n"
                  "  - id: r1\n    effect: allow\n    match:\n"
                  "      tool: [read_file]\n"
                  "mind_control:\n  enabled: true\n")
        path = _write(policy)
        try:
            # F90: the engine now refuses unknown top-level keys at load
            # (ValueError), before the exporter's own check
            # (PolicyExportError) runs. Either refusal satisfies the pin:
            # the section is refused, never silently ignored.
            with self.assertRaises((PolicyExportError, ValueError)) as ctx:
                translate(path)
            self.assertIn("mind_control", str(ctx.exception))
        finally:
            _cleanup(path)

    def test_unknown_rule_field_refused(self):
        policy = ("version: 2\nroles:\n  coder: [read_file]\npolicies:\n"
                  "  - id: r1\n    effect: allow\n    match:\n"
                  "      tool: [read_file]\n"
                  "    reaosn: typo for reason\n")
        path = _write(policy)
        try:
            # F90: the engine now refuses unknown rule fields at load
            # (ValueError), before the exporter's own check
            # (PolicyExportError) runs. Either refusal satisfies the pin.
            with self.assertRaises((PolicyExportError, ValueError)) as ctx:
                translate(path)
            self.assertIn("reaosn", str(ctx.exception))
        finally:
            _cleanup(path)

    def test_bridge_field_allowed_on_rules(self):
        # ``bridge:`` is exporter-only metadata and must not trip the
        # unknown-field check.
        policy = ("version: 2\nroles:\n  coder: [write_file]\npolicies:\n"
                  "  - id: r1\n    effect: require_approval\n    match:\n"
                  "      tool: [write_file]\n"
                  "    bridge:\n"
                  "      approval_action: \"ApproveWrite\"\n"
                  "      ttl_seconds: 600\n")
        path = _write(policy)
        try:
            text = translate(path, format="dogwood")
            self.assertIn("forbid companion", text)
        finally:
            _cleanup(path)

    def test_when_float_refused(self):
        policy = ("version: 2\nroles:\n  coder: [api_call]\npolicies:\n"
                  "  - id: r1\n    effect: deny\n    match:\n"
                  "      tool: [api_call]\n      when:\n"
                  "        - path: counters.api_call\n          gte: 2.5\n")
        path = _write(policy)
        try:
            with self.assertRaises(PolicyExportError):
                translate(path)
        finally:
            _cleanup(path)

    def test_control_characters_refused(self):
        # yamlmini does not process \u escapes, so exercise the emitter
        # directly with a real control character.
        with self.assertRaises(PolicyExportError):
            policy_export._cedar_str("a\x01b")
        with self.assertRaises(PolicyExportError):
            policy_export._cedar_str("a\x7fb")
        # ... while normal strings (incl. backslash-u text) are fine.
        self.assertEqual(policy_export._cedar_str('a"b\\c'), '"a\\"b\\\\c"')

    def test_ttl_not_multiple_of_60_refused(self):
        policy = ("version: 2\nroles:\n  coder: [write_file]\npolicies:\n"
                  "  - id: r1\n    effect: require_approval\n    match:\n"
                  "      tool: [write_file]\n    bridge:\n"
                  "      approval_action: \"ApproveWrite\"\n"
                  "      ttl_seconds: 90\n")
        path = _write(policy)
        try:
            with self.assertRaises(PolicyExportError) as cm:
                translate(path, format="dogwood")
            self.assertIn("multiple of 60", str(cm.exception))
        finally:
            _cleanup(path)

    def test_ttl_hours_rendered(self):
        policy = ("version: 2\nroles:\n  coder: [write_file]\npolicies:\n"
                  "  - id: r1\n    effect: require_approval\n    match:\n"
                  "      tool: [write_file]\n    bridge:\n"
                  "      approval_action: \"ApproveWrite\"\n"
                  "      ttl_seconds: 7200\n")
        path = _write(policy)
        try:
            text = translate(path, format="dogwood")
            self.assertIn("formerly within 2h", text)
        finally:
            _cleanup(path)


class LimitationTests(unittest.TestCase):
    def test_operational_sections_listed_loudly(self):
        policy = (STATELESS_POLICY +
                  "budgets:\n  max_actions_per_run: 100\n"
                  "rate_limit:\n  max_sends_per_run: 10\n")
        path = _write(policy)
        try:
            text = translate(path)
            self.assertIn("// EXPORT LIMITATIONS", text)
            self.assertIn("//   - budgets:", text)
            self.assertIn("//   - rate_limit:", text)
            # ... but translation still succeeds (operational, documented)
            self.assertIn("permit (", text)
        finally:
            _cleanup(path)

    def test_strict_turns_limitations_into_errors(self):
        policy = (STATELESS_POLICY +
                  "budgets:\n  max_actions_per_run: 100\n")
        path = _write(policy)
        try:
            with self.assertRaises(PolicyExportError):
                translate(path, strict=True)
        finally:
            _cleanup(path)

    def test_absent_sections_no_limitations(self):
        path = _write(STATELESS_POLICY)
        try:
            text = translate(path)
            self.assertIn("// EXPORT LIMITATIONS : none", text)
        finally:
            _cleanup(path)

    def test_delegation_section_listed_as_limitation(self):
        # P10 top-level delegation (wave-24) is enforced outside the
        # authorizer: the export must name it loudly, never silently.
        policy = (STATELESS_POLICY +
                  "delegation:\n  enabled: false\n")
        path = _write(policy)
        try:
            text = translate(path)
            self.assertIn("//   - delegation:", text)
        finally:
            _cleanup(path)


class BridgeEmissionTests(unittest.TestCase):
    BRIDGED = """\
version: 2
roles:
  coder: [write_file]
policies:
  - id: approve-write
    effect: require_approval
    match:
      tool: [write_file]
      path_outside_sandbox: true
    bridge:
      approval_action: "ApproveWrite"
      ttl_seconds: 600
      match_fields: [path]
"""

    def test_bridged_emits_temporal_permit(self):
        path = _write(self.BRIDGED)
        try:
            text = translate(path, format="dogwood")
            self.assertIn("permit (", text)
            self.assertIn("when temporal", text)
            self.assertIn("output.approved: true", text)
            self.assertIn("input.path: context.input.path", text)
            self.assertIn("formerly within 10m", text)
        finally:
            _cleanup(path)

    def test_single_translator_entry_point(self):
        # A13 single-translator rule: the D2 Dogwood target consumes
        # translate_for_dogwood(); it must exist and be the documented path.
        self.assertTrue(callable(translate_for_dogwood))
        path = _write(self.BRIDGED)
        try:
            self.assertIn("when temporal",
                          translate_for_dogwood(path))
        finally:
            _cleanup(path)

    def test_translate_text(self):
        text = translate_text(STATELESS_POLICY, format="cedar")
        self.assertIn("// Target format : cedar", text)
        self.assertIn("// Source policy : <inline>", text)
        # Deterministic: identical input yields identical bytes (the
        # header must not leak the random temp path).
        self.assertEqual(text, translate_text(STATELESS_POLICY,
                                              format="cedar"))
        with self.assertRaises(PolicyExportError):
            translate_text(123)


class CLITests(unittest.TestCase):
    def test_cli_cedar_stdout(self):
        path = _write(STATELESS_POLICY)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = policy_export.main(
                    ["--policy", path, "--format", "cedar"])
            self.assertEqual(rc, 0)
            self.assertIn("// Target format : cedar", buf.getvalue())
        finally:
            _cleanup(path)

    def test_cli_out_file(self):
        path = _write(STATELESS_POLICY)
        try:
            tmpdir = tempfile.mkdtemp(prefix="gov-export-cli-")
            out = str(Path(tmpdir) / "out.cedar")
            rc = policy_export.main(
                ["--policy", path, "--format", "cedar", "--out", out])
            self.assertEqual(rc, 0)
            self.assertIn("// Target format : cedar",
                          Path(out).read_text(encoding="utf-8"))
        finally:
            _cleanup(path)

    def test_cli_refusal_exit_1(self):
        policy = ("version: 2\nroles:\n  coder: [api_call]\npolicies:\n"
                  "  - id: r1\n    effect: deny\n    match:\n"
                  "      tool: [api_call]\n      min_sends: 1\n")
        path = _write(policy)
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                rc = policy_export.main(
                    ["--policy", path, "--format", "cedar"])
            self.assertEqual(rc, 1)
            self.assertIn("EXPORT ERROR", err.getvalue())
        finally:
            _cleanup(path)

    def test_cli_missing_policy_exit_2(self):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = policy_export.main(["--format", "cedar"])
        self.assertEqual(rc, 2)

    def test_cli_help_exit_0(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = policy_export.main(["--help"])
        self.assertEqual(rc, 0)


class ExportCheckTests(unittest.TestCase):
    def test_export_check_ok(self):
        from gov import policy_lint
        path = _write(STATELESS_POLICY)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = policy_lint.main(["--export-check", path])
            self.assertEqual(rc, 0)
            self.assertIn("export OK", buf.getvalue())
        finally:
            _cleanup(path)

    def test_export_check_fails_loudly(self):
        from gov import policy_lint
        from gov.policy import default_policy_path
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = policy_lint.main(
                ["--export-check", str(default_policy_path())])
        self.assertEqual(rc, 1)
        self.assertIn("export check FAILED", buf.getvalue())

    def test_export_check_strict(self):
        from gov import policy_lint
        policy = STATELESS_POLICY + "budgets:\n  max_actions_per_run: 5\n"
        path = _write(policy)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = policy_lint.main(["--export-check", path])
            self.assertEqual(rc, 0)  # non-strict: limitations are notes
            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                rc2 = policy_lint.main(
                    ["--export-check", path, "--strict"])
            self.assertEqual(rc2, 1)
        finally:
            _cleanup(path)


if __name__ == "__main__":
    unittest.main()
