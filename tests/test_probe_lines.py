"""Contract tests for evals/probe_lines.py (canonical probe-line form).

Wave-308 lane F: the canonical form is the one shape the green-check
contract already parses, so these tests pin the exact string contract
that makes future coherence enforcement sound.
"""

import io
import os
import sys
import contextlib
import unittest
from contextlib import redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402


class TestCanonicalFormat(unittest.TestCase):
    def test_format_line_exact_shape(self):
        self.assertEqual(
            probe_lines.format_line("f388-x", "HELD", "note here"),
            "[HELD] f388-x: note here")

    def test_format_line_verdicts(self):
        for v in ("BREAK", "HELD", "ERROR", "SKIP"):
            line = probe_lines.format_line("pid1", v, "n")
            self.assertTrue(line.startswith("[%s] pid1: " % v))

    def test_first_line_takes_head(self):
        self.assertEqual(probe_lines.first_line("a\nb\nc"), "a")

    def test_first_line_empty_note(self):
        # Must not raise: an empty note is legal, prints an empty tail.
        self.assertEqual(probe_lines.first_line(""), "")
        self.assertEqual(probe_lines.format_line("p", "HELD", ""),
                         "[HELD] p: ")

    def test_parse_line_roundtrip(self):
        line = probe_lines.format_line("f391-x", "BREAK", "why\nmore")
        self.assertEqual(probe_lines.parse_line(line),
                         ("BREAK", "f391-x", "why"))

    def test_parse_line_rejects_noncanonical(self):
        # Indented, columnar, and summary lines do not parse.
        self.assertIsNone(probe_lines.parse_line("  [HELD] p: n"))
        self.assertIsNone(probe_lines.parse_line("pid1 HELD note"))
        self.assertIsNone(probe_lines.parse_line("0 BREAK / 1 HELD / 0 ERROR"))

    def test_emit_one_line_per_probe_in_order(self):
        results = [("a", "HELD", "x"), ("b", "BREAK", "y\nz"),
                   ("c", "ERROR", "")]
        buf = io.StringIO()
        with redirect_stdout(buf):
            probe_lines.emit(results)
        self.assertEqual(buf.getvalue().splitlines(),
                         ["[HELD] a: x", "[BREAK] b: y", "[ERROR] c: "])

    def test_pid_class_matches_green_check(self):
        # The green-check contract captures \[BREAK\] ([A-Za-z0-9_.\-]+):
        # every pid the emitter accepts must survive that capture.
        import re
        break_re = re.compile(r"\[BREAK\] ([A-Za-z0-9_.\-]+)")
        line = probe_lines.format_line("f388-foreign_run.replay-1",
                                       "BREAK", "n")
        self.assertEqual(break_re.search(line).group(1),
                         "f388-foreign_run.replay-1")


class TestCheckCoherence(unittest.TestCase):
    def test_coherent(self):
        results = [("a", "HELD", "x"), ("b", "BREAK", "y")]
        ok, diags = probe_lines.check_coherence(results, 1, 1, 0)
        self.assertTrue(ok)
        self.assertEqual(diags, [])

    def test_count_mismatch(self):
        results = [("a", "HELD", "x")]
        ok, diags = probe_lines.check_coherence(results, 0, 2, 0)
        self.assertFalse(ok)
        self.assertTrue(any("HELD" in d for d in diags))

    def test_unknown_verdict(self):
        ok, diags = probe_lines.check_coherence([("a", "MAYBE", "x")],
                                                0, 0, 0)
        self.assertFalse(ok)
        self.assertTrue(any("MAYBE" in d for d in diags))

    def test_nonconforming_pid(self):
        ok, diags = probe_lines.check_coherence([("has space", "HELD", "x")],
                                                0, 1, 0)
        self.assertFalse(ok)
        self.assertTrue(any("has space" in d for d in diags))

    def test_never_raises(self):
        # Advisory by design: malformed input yields diagnostics, never
        # an exception.
        ok, diags = probe_lines.check_coherence([("a",)], 0, 0, 0)
        self.assertFalse(ok)
        self.assertTrue(diags)
        ok, diags = probe_lines.check_coherence(None, 0, 0, 0)
        self.assertFalse(ok)

    def test_emit_dicts_basic(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            probe_lines.emit_dicts([
                {"probe_id": "a", "verdict": "BREAK", "note": "x"},
                {"probe_id": "b", "verdict": "HELD", "note": "y\nz"},
            ])
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "[BREAK] a: x")
        self.assertEqual(lines[1], "[HELD] b: y")  # first_line applied

    def test_emit_dicts_strict_verdict(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            probe_lines.emit_dicts(
                [{"probe_id": "a", "verdict": "GAP", "note": "x"}])
        line = out.getvalue().strip()
        self.assertTrue(line.startswith("[ERROR] a:"))
        self.assertIn("GAP", line)

    def test_emit_dicts_missing_key(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            probe_lines.emit_dicts([{"probe_id": "a", "verdict": "HELD"}])
        line = out.getvalue().strip()
        self.assertTrue(line.startswith("[ERROR] a:"))

    def test_emit_dicts_note_getter(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            probe_lines.emit_dicts(
                [{"id": "a", "verdict": "HELD",
                  "detail": {"note": "n1"}}],
                pid_key="id",
                note_getter=lambda r: r["detail"]["note"])
        self.assertEqual(out.getvalue().strip(), "[HELD] a: n1")

    def test_emit_dicts_note_getter_failure(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            probe_lines.emit_dicts(
                [{"id": "a", "verdict": "HELD", "detail": {}}],
                pid_key="id",
                note_getter=lambda r: r["detail"]["note"])
        line = out.getvalue().strip()
        self.assertTrue(line.startswith("[ERROR] a:"))

    def test_emit_dicts_never_raises(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            probe_lines.emit_dicts([None, 42, {}])
        self.assertEqual(len(out.getvalue().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
