"""Units for gov.startup_sinks (W245-9): closed-list sink registry and
pre-trust config stripping. Red-first battery is
evals/w245_gitspawn_open_path_probes.py."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import startup_sinks as ss
from gov import session_trust as st


class SinkRegistryTest(unittest.TestCase):
    def test_unregistered_refuses_pretrust(self):
        reg = ss.StartupSinkRegistry()
        with self.assertRaises(st.SessionTrustError) as ctx:
            reg.resolve("ultrareview")
        self.assertEqual(ctx.exception.code, "repo-hook-pretrust-refused")

    def test_renames_never_evade(self):
        reg = ss.StartupSinkRegistry()
        reg.register_sink("review", declared_by="operator")
        for name in ("ultra-review", "ultrareviews", "u1trarev1ew",
                     "ULTRAREVIEW", "ultrareview "):
            with self.assertRaises(st.SessionTrustError) as ctx:
                reg.resolve(name)
            self.assertEqual(ctx.exception.code,
                             "repo-hook-pretrust-refused")

    def test_registered_resolves(self):
        reg = ss.StartupSinkRegistry()
        reg.register_sink("review", declared_by="operator")
        out = reg.resolve("review")
        self.assertEqual(out["name"], "review")
        self.assertEqual(out["declared_by"], "operator")

    def test_malformed_name_fails_closed(self):
        reg = ss.StartupSinkRegistry()
        for bad in ("Bad Name!", "", "a" * 70, "-lead", None, 123):
            with self.assertRaises(st.SessionTrustError) as ctx:
                reg.register_sink(bad, declared_by="operator")
            self.assertEqual(ctx.exception.code, "session-trust-malformed")
        self.assertEqual(reg.registered_names(), [])

    def test_unnamed_principal_fails_closed(self):
        reg = ss.StartupSinkRegistry()
        with self.assertRaises(st.SessionTrustError) as ctx:
            reg.register_sink("review", declared_by="  ")
        self.assertEqual(ctx.exception.code, "session-trust-malformed")


class StripConfigTest(unittest.TestCase):
    CFG = ("[core]\n"
           "\thooksPath = /tmp/evil-hooks\n"
           "\tbare = false\n"
           "# a comment\n")

    def test_hookspath_stripped_bare_kept(self):
        res = ss.strip_unknown_config_keys(self.CFG, {"core.bare"})
        kept = "\n".join(res["kept"])
        stripped = "\n".join(res["stripped"])
        self.assertNotIn("hooksPath", kept)
        self.assertIn("hooksPath", stripped)
        self.assertIn("bare", kept)

    def test_unknown_section_key_stripped(self):
        cfg = "[core]\n\tfsmonitor = /bin/true\n"
        res = ss.strip_unknown_config_keys(cfg, {"core.bare"})
        self.assertEqual(res["kept"], ["[core]"])
        self.assertEqual(len(res["stripped"]), 1)

    def test_empty_known_strips_all_keyed_lines(self):
        res = ss.strip_unknown_config_keys(self.CFG, set())
        self.assertNotIn("hooksPath", "\n".join(res["kept"]))
        self.assertNotIn("bare", "\n".join(res["kept"]))
        # comments and section headers carry no executable surface
        self.assertIn("# a comment", "\n".join(res["kept"]))

    def test_non_string_config_fails_closed(self):
        with self.assertRaises(st.SessionTrustError) as ctx:
            ss.strip_unknown_config_keys(None, {"core.bare"})
        self.assertEqual(ctx.exception.code, "session-trust-malformed")

    def test_input_never_mutated(self):
        cfg = self.CFG
        ss.strip_unknown_config_keys(cfg, {"core.bare"})
        self.assertEqual(cfg, self.CFG)


if __name__ == "__main__":
    unittest.main()
