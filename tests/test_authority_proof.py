"""Unit tests for gov.authority_proof (wave-176, OpenShell steal #1).

Tests target the public seam -- boundary_from_dict() and check() --
with expectations from the spec, not the implementation.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import authority_proof as ap


def _b(**kw):
    d = {"boundary_id": "u", "version": "1"}
    d.update(kw)
    return ap.boundary_from_dict(d)


def _act(tool, args):
    return {"tool": tool, "args": dict(args)}


class TestBoundaryLoad(unittest.TestCase):
    def test_ok(self):
        b = _b(fs_write_prefixes=["/a"], egress_hosts=["Api.Internal"])
        self.assertEqual(b.fs_write_prefixes, ("/a",))
        self.assertEqual(b.egress_hosts, ("api.internal",))

    def test_relative_prefix_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(fs_write_prefixes=["rel/path"])

    def test_dotdot_prefix_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(fs_read_prefixes=["/a/../b"])

    def test_unnormalized_prefix_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(fs_write_prefixes=["/a//b"])

    def test_wildcard_host_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(egress_hosts=["*.example"])

    def test_host_with_port_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(egress_hosts=["api.example:443"])

    def test_host_with_scheme_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(egress_hosts=["https://api.example"])

    def test_unknown_key_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(filesystem_paths=["/a"])

    def test_empty_id_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            ap.boundary_from_dict({"boundary_id": "", "version": "1"})

    def test_non_mapping_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            ap.boundary_from_dict([("boundary_id", "x")])


class TestCheckVerdicts(unittest.TestCase):
    def test_within_write(self):
        p = ap.check(_act("write_file", {"path": "/a/b/c"}),
                     {"path_resolved": "/a/b/c"},
                     _b(fs_write_prefixes=["/a"]))
        self.assertEqual(p.verdict, ap.WITHIN)
        self.assertIsNone(p.counterexample)
        self.assertIn("filesystem", p.covered_domains)
        self.assertIn("process_identity", p.uncovered_domains)
        self.assertEqual(p.resolution_source, "path_resolved")

    def test_within_read_uses_read_prefixes(self):
        p = ap.check(_act("read_file", {"path": "/r/x"}),
                     {"path_resolved": "/r/x"},
                     _b(fs_read_prefixes=["/r"], fs_write_prefixes=["/w"]))
        self.assertEqual(p.verdict, ap.WITHIN)

    def test_read_not_covered_by_write_prefix(self):
        p = ap.check(_act("read_file", {"path": "/w/x"}),
                     {"path_resolved": "/w/x"},
                     _b(fs_read_prefixes=["/r"], fs_write_prefixes=["/w"]))
        self.assertEqual(p.verdict, ap.EXCEEDS)

    def test_exceeds_counterexample(self):
        p = ap.check(_act("write_file", {"path": "/etc/x"}),
                     {"path_resolved": "/etc/x"},
                     _b(fs_write_prefixes=["/a", "/ab"]))
        self.assertEqual(p.verdict, ap.EXCEEDS)
        ce = p.counterexample
        self.assertIsNotNone(ce)
        self.assertEqual(ce.domain, "filesystem")
        self.assertEqual(ce.access, "/etc/x")
        # nearest rule: "/a" and "/ab" share no prefix with /etc/x;
        # one of them is returned, deterministically the first.
        self.assertIn(ce.nearest_rule, ("/a", "/ab"))
        self.assertTrue(ce.reason)

    def test_prefix_boundary_exact(self):
        # "/ab" must NOT match prefix "/a" (segment boundary).
        p = ap.check(_act("write_file", {"path": "/ab/x"}),
                     {"path_resolved": "/ab/x"},
                     _b(fs_write_prefixes=["/a"]))
        self.assertEqual(p.verdict, ap.EXCEEDS)

    def test_egress_within(self):
        p = ap.check(_act("http_post", {"url": "https://API.internal/v1"}),
                     {}, _b(egress_hosts=["api.internal"]))
        self.assertEqual(p.verdict, ap.WITHIN)

    def test_egress_exceeds(self):
        p = ap.check(_act("api_call", {"endpoint": "https://evil.example/"}),
                     {}, _b(egress_hosts=["api.internal"]))
        self.assertEqual(p.verdict, ap.EXCEEDS)
        self.assertEqual(p.counterexample.domain, "egress")
        self.assertEqual(p.counterexample.access, "evil.example")

    def test_mail_to_domain(self):
        p = ap.check(_act("send_email", {"to": "ops@api.internal"}),
                     {}, _b(egress_hosts=["api.internal"]))
        self.assertEqual(p.verdict, ap.WITHIN)

    def test_dotdot_escape_unsupported(self):
        p = ap.check(_act("write_file", {"path": "/a/../../etc/passwd"}),
                     {}, _b(fs_write_prefixes=["/a"]))
        self.assertEqual(p.verdict, ap.UNSUPPORTED)

    def test_relative_no_root_unsupported(self):
        p = ap.check(_act("write_file", {"path": "rel/x"}),
                     {}, _b(fs_write_prefixes=["/a"]))
        self.assertEqual(p.verdict, ap.UNSUPPORTED)

    def test_relative_with_root_resolves(self):
        p = ap.check(_act("write_file", {"path": "sub/x"}),
                     {"path_resolved": "sub/x",
                      "sandbox_root": "/sandbox"},
                     _b(fs_write_prefixes=["/sandbox"]))
        self.assertEqual(p.verdict, ap.WITHIN)
        self.assertEqual(p.resolution_source, "path_resolved")

    def test_declared_path_fallback(self):
        p = ap.check(_act("write_file", {"path": "/a/x"}), {},
                     _b(fs_write_prefixes=["/a"]))
        self.assertEqual(p.verdict, ap.WITHIN)
        self.assertEqual(p.resolution_source, "declared_path")

    def test_unparseable_url_unsupported(self):
        p = ap.check(_act("http_post", {"url": "::::"}), {},
                     _b(egress_hosts=["a.example"]))
        self.assertEqual(p.verdict, ap.UNSUPPORTED)

    def test_non_http_scheme_unsupported(self):
        p = ap.check(_act("http_post", {"url": "gopher://a.example/x"}),
                     {}, _b(egress_hosts=["a.example"]))
        self.assertEqual(p.verdict, ap.UNSUPPORTED)

    def test_no_boundary_inconclusive(self):
        p = ap.check(_act("write_file", {"path": "/a"}), {}, None)
        self.assertEqual(p.verdict, ap.INCONCLUSIVE)
        self.assertEqual(p.covered_domains, ())
        self.assertEqual(set(p.uncovered_domains),
                         {"filesystem", "egress", "mcp_tools", "graphql",
                          "process_identity"})
        self.assertIsNone(p.counterexample)

    def test_budget_inconclusive(self):
        p = ap.check(_act("write_file", {"path": "/a"}),
                     {"path_resolved": "/a"},
                     _b(fs_write_prefixes=["/a"]), max_accesses=0)
        self.assertEqual(p.verdict, ap.INCONCLUSIVE)

    def test_vacuous_tool_within(self):
        # A tool with no modeled accesses is trivially within; the
        # policy's own unknown-tool handling still governs it.
        p = ap.check(_act("list_tools", {}), {},
                     _b(fs_write_prefixes=["/a"]))
        self.assertEqual(p.verdict, ap.WITHIN)


class TestNeverRaises(unittest.TestCase):
    def test_hostile_inputs(self):
        b = _b(fs_write_prefixes=["/a"])
        hostile = [
            (None, {}), ("x", {}),
            ({"tool": "write_file", "args": None}, {}),
            ({"tool": None, "args": {"path": "/a"}}, {}),
            ({"tool": "write_file",
              "args": {"path": 12345}}, {}),
            ({"tool": "write_file",
              "args": {"path": "/a\x00b"}}, {}),
            ({"tool": "http_post",
              "args": {"url": ["not", "a", "str"]}}, {}),
            ({"tool": "write_file", "args": {"path": "/a"}},
             {"path_resolved": object()}),
        ]
        for action, ctx in hostile:
            p = ap.check(action, ctx, b)
            self.assertIn(p.verdict, ap.VERDICTS)

    def test_wrong_boundary_type_inconclusive(self):
        p = ap.check(_act("write_file", {"path": "/a"}), {},
                     boundary="not-a-boundary")
        self.assertEqual(p.verdict, ap.INCONCLUSIVE)


class TestDeterminism(unittest.TestCase):
    def test_same_inputs_same_proof(self):
        b = _b(fs_write_prefixes=["/a"], egress_hosts=["h.example"])
        a = _act("write_file", {"path": "/elsewhere"})
        c = {"path_resolved": "/elsewhere"}
        p1 = ap.check(a, c, b).to_dict()
        p2 = ap.check(a, c, b).to_dict()
        self.assertEqual(p1, p2)
        self.assertEqual(p1["counterexample"]["access"], "/elsewhere")


if __name__ == "__main__":
    unittest.main()
