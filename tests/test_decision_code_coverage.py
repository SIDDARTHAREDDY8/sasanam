"""Unit tests for scripts/check_decision_code_coverage.py (wave-338 R14).

Hermetic: the matcher is tested on synthetic fixture dirs, never the
real tree (the full-tree scan is exercised by the lane battery P5, not
the canonical suite).
"""

import importlib.util
import os
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_REPO, "scripts", "check_decision_code_coverage.py")


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_decision_code_coverage", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load()


class CollectHitsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cov-unit-")
        self.repo = self.tmp
        self.tests = os.path.join(self.tmp, "tests")
        os.makedirs(self.tests)

    def _write(self, rel, text):
        path = os.path.join(self.tests, rel)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_quoted_code_single_and_double_quotes(self):
        self._write("a.py", 'x = "w338-synthetic-quoted"\ny = \'w338-synthetic-underscore_x\'\n')
        hits = _mod.collect_hits([self.tests], self.repo)
        self.assertIn("w338-synthetic-quoted", hits)
        self.assertIn("w338-synthetic-underscore_x", hits)
        self.assertEqual(hits["w338-synthetic-quoted"], {"tests/a.py"})

    def test_unquoted_identifier_not_counted(self):
        # attest_absence as a METHOD name (issuer.attest_absence(...))
        # is not a quoted code literal and must not count.
        self._write("b.py", "neg = issuer.w338_synthetic_mint(digest)\n")
        hits = _mod.collect_hits([self.tests], self.repo)
        self.assertNotIn("w338-synthetic-methodname", hits)

    def test_substring_codes_do_not_collide(self):
        # 'deny' must not be falsely matched by 'deny-receipt'.
        self._write("c.py", 'x = "w338-synthetic-quoted"\n')
        hits = _mod.collect_hits([self.tests], self.repo)
        self.assertNotIn("deny", hits)
        self.assertIn("w338-synthetic-quoted", hits)

    def test_non_py_files_ignored(self):
        self._write("d.py", "pass\n")
        with open(os.path.join(self.tests, "fixture.json"),
                  "w", encoding="utf-8") as fh:
            fh.write('{"code": "json-only-code"}')
        hits = _mod.collect_hits([self.tests], self.repo)
        self.assertNotIn("json-only-code", hits)

    def test_relative_paths_sorted_by_caller(self):
        self._write("e1.py", 'x = "w338-synthetic-shared"\n')
        self._write("e2.py", 'x = "w338-synthetic-shared"\n')
        hits = _mod.collect_hits([self.tests], self.repo)
        self.assertEqual(sorted(hits["w338-synthetic-shared"]),
                         ["tests/e1.py", "tests/e2.py"])


class PinTest(unittest.TestCase):
    def test_pin_matches_live_registry(self):
        sys.path.insert(0, _REPO)
        try:
            from gov import decision_codes as dc
        finally:
            sys.path.remove(_REPO)
        self.assertEqual(len(dc.TAXONOMY), _mod.COVERAGE_PIN)


if __name__ == "__main__":
    unittest.main()
