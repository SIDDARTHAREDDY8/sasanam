"""Unit tests for the wave-177 AuthorityProof extensions (MCP/GraphQL).

Tests target the public seam -- boundary_from_dict() and check() --
with expectations from the spec, not the implementation. The GraphQL
mini-parser is exercised through _parse_graphql (module-private but
the honest unit for the static analysis).
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import authority_proof as ap


def _b(**kw):
    d = {"boundary_id": "u", "version": "1"}
    d.update(kw)
    return ap.boundary_from_dict(d)


def _mcp_b(**kw):
    d = {"mcp_servers": ["files", "search"],
         "mcp_tools": ["files::read", "search::query"],
         "mcp_max_arg_bytes": 64}
    d.update(kw)
    return _b(**d)


def _gql_b(**kw):
    d = {"graphql_max_depth": 4, "graphql_allow_mutations": True,
         "graphql_mutation_allowlist": ["updateProfile"],
         "graphql_allow_introspection": False,
         "egress_hosts": ["api.internal"]}
    d.update(kw)
    return _b(**d)


def _mcp_action(server="files", name="read", arguments=None):
    args = {"server": server, "name": name}
    if arguments is not None:
        args["arguments"] = arguments
    return {"tool": "mcp_call", "args": args}


def _gql_action(query, endpoint="https://api.internal/graphql"):
    return {"tool": "graphql",
            "args": {"endpoint": endpoint, "query": query}}


class TestMcpBoundaryLoad(unittest.TestCase):
    def test_ok(self):
        b = _mcp_b()
        self.assertEqual(b.mcp_servers, ("files", "search"))
        self.assertEqual(b.mcp_tools, ("files::read", "search::query"))
        self.assertEqual(b.mcp_max_arg_bytes, 64)

    def test_pair_separator_rejected_in_server(self):
        with self.assertRaises(ap.BoundaryError):
            _b(mcp_servers=["a::b"])

    def test_pair_separator_rejected_in_tool(self):
        with self.assertRaises(ap.BoundaryError):
            _b(mcp_servers=["files"],
               mcp_tools=["files::re::ad"])

    def test_pair_must_name_listed_server(self):
        with self.assertRaises(ap.BoundaryError):
            _b(mcp_servers=["files"], mcp_tools=["ghost::read"])

    def test_pair_malformed(self):
        for bad in ("files", "files::", "::read", "a::b::c"):
            with self.assertRaises(ap.BoundaryError, msg=bad):
                _b(mcp_servers=["files", "a"], mcp_tools=[bad])

    def test_wildcard_server_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(mcp_servers=["*"])

    def test_negative_arg_bytes_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(mcp_max_arg_bytes=-1)

    def test_bool_arg_bytes_rejected(self):
        # bool is not an int here: True must not silently mean 1.
        with self.assertRaises(ap.BoundaryError):
            _b(mcp_max_arg_bytes=True)


class TestGraphqlBoundaryLoad(unittest.TestCase):
    def test_ok(self):
        b = _gql_b()
        self.assertEqual(b.graphql_max_depth, 4)
        self.assertTrue(b.graphql_allow_mutations)
        self.assertEqual(b.graphql_mutation_allowlist, ("updateProfile",))
        self.assertFalse(b.graphql_allow_introspection)

    def test_bool_strictness(self):
        with self.assertRaises(ap.BoundaryError):
            _b(graphql_allow_mutations=1)
        with self.assertRaises(ap.BoundaryError):
            _b(graphql_allow_introspection="no")

    def test_bad_mutation_name_rejected(self):
        with self.assertRaises(ap.BoundaryError):
            _b(graphql_mutation_allowlist=["not a name"])


class TestMcpCheck(unittest.TestCase):
    def test_arg_bytes_boundary_exact(self):
        # Exactly at the budget is within; one byte over exceeds.
        b = _mcp_b(mcp_max_arg_bytes=10)
        args = {"k": "v"}  # canonical: {"k":"v"} = 9 bytes
        p = ap.check(_mcp_action(arguments=args), {}, b)
        self.assertEqual(p.verdict, "within_boundary")
        args2 = {"k": "vv"}  # 10 bytes -> within
        p2 = ap.check(_mcp_action(arguments=args2), {}, b)
        self.assertEqual(p2.verdict, "within_boundary")
        args3 = {"k": "vvv"}  # 11 bytes -> exceeds
        p3 = ap.check(_mcp_action(arguments=args3), {}, b)
        self.assertEqual(p3.verdict, "exceeds_boundary")

    def test_deterministic_arg_bytes(self):
        # Key order must not affect the byte count (canonical JSON).
        b = _mcp_b(mcp_max_arg_bytes=1000)
        p1 = ap.check(
            _mcp_action(arguments={"a": 1, "b": 2}), {}, b)
        p2 = ap.check(
            _mcp_action(arguments={"b": 2, "a": 1}), {}, b)
        self.assertEqual(p1.to_dict(), p2.to_dict())

    def test_never_raises_on_hostile(self):
        b = _mcp_b()
        for action in (
            {"tool": "mcp_call", "args": None},
            {"tool": "mcp_call", "args": {"server": ["x"], "name": 1}},
            {"tool": "mcp_call", "args": {"server": "s", "name": "n",
                                          "arguments": {"x": object()}}},
            {"tool": None, "args": {}},
            "not-a-mapping",
        ):
            p = ap.check(action, {}, b)
            self.assertIn(p.verdict, ap.VERDICTS)

    def test_counterexample_names_pair(self):
        b = _mcp_b()
        p = ap.check(_mcp_action(server="search", name="nuke"), {}, b)
        self.assertEqual(p.verdict, "exceeds_boundary")
        self.assertEqual(p.counterexample.domain, "mcp_tools")
        self.assertEqual(p.counterexample.access, "search::nuke")


class TestGraphqlParser(unittest.TestCase):
    def test_depth_counts_braces(self):
        op = ap._parse_graphql("query { a { b { c } } }")
        self.assertEqual(op[0], "query")
        self.assertEqual(op[1], 3)

    def test_anonymous_is_query(self):
        op = ap._parse_graphql("{ x }")
        self.assertEqual(op[0], "query")
        self.assertEqual(op[1], 1)

    def test_alias_uses_real_name(self):
        # alias: real -- the allowlist sees the real field.
        op = ap._parse_graphql(
            "mutation { aliased: deleteUser(id: 1) { id } }")
        self.assertEqual(op[2], ("deleteUser",))

    def test_typename_counts_as_introspection(self):
        op = ap._parse_graphql("query { user { __typename } }")
        self.assertTrue(op[3])

    def test_string_braces_ignored(self):
        op = ap._parse_graphql('query { f(arg: "{ not } a { selection") }')
        self.assertEqual(op[1], 1)

    def test_comments_ignored(self):
        op = ap._parse_graphql("# a comment\nquery { x } # trailing")
        self.assertEqual(op[1], 1)

    def test_directives_not_evaluated(self):
        # @include(if: false) would exclude the branch at runtime;
        # the static checker measures it as written (fail-closed).
        op = ap._parse_graphql(
            "query { a @include(if: false) { b { c } } }")
        self.assertEqual(op[1], 3)


class TestGraphqlCheck(unittest.TestCase):
    def test_endpoint_host_composes_with_egress(self):
        b = _gql_b()
        p = ap.check(
            _gql_action("query { x }",
                        endpoint="https://evil.example/graphql"),
            {}, b)
        self.assertEqual(p.verdict, "exceeds_boundary")
        self.assertEqual(p.counterexample.domain, "egress")

    def test_subscription_exceeds(self):
        b = _gql_b()
        p = ap.check(
            _gql_action("subscription { tick { n } }"), {}, b)
        self.assertEqual(p.verdict, "exceeds_boundary")
        self.assertIn("subscription", p.counterexample.reason)

    def test_proof_never_upgrades_deny(self):
        # The checker is a pure function: it exposes no allow/permit
        # API, and within_boundary carries no authority of its own.
        self.assertFalse(hasattr(ap, "allow"))
        self.assertFalse(hasattr(ap, "permit"))
        b = _gql_b()
        p = ap.check(_gql_action("query { x }"), {}, b)
        self.assertEqual(p.verdict, "within_boundary")
        self.assertNotIn("allow", p.to_dict())

    def test_new_domains_in_covered(self):
        b = _mcp_b()
        p = ap.check(_mcp_action(), {}, b)
        self.assertIn("mcp_tools", p.covered_domains)
        self.assertIn("graphql", p.covered_domains)
        self.assertIn("process_identity", p.uncovered_domains)


if __name__ == "__main__":
    unittest.main()
