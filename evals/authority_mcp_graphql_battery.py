#!/usr/bin/env python3
"""Wave-177 lane B: AuthorityProof coverage for MCP tool calls + GraphQL.

Extends the wave-176 AuthorityProof contract (gov/authority_proof.py)
with two new covered domains -- the exact gap flagged in NVIDIA's
OpenShell prover (their containment proof does NOT cover GraphQL/MCP):

  * ``mcp_tools`` -- MCP server tool calls: server identity, tool name
    (as exact "server::tool" pairs, so cross-server name confusion
    cannot smuggle), and argument-schema bounds (canonical JSON byte
    budget per call).
  * ``graphql``   -- GraphQL operations: operation type, field
    selection depth (fragments inlined, cycles fail closed),
    mutation allowlist, introspection control.

RED-FIRST: run this battery against the PRISTINE tree first. The
new-domain probes FAIL there (unknown tools are vacuously
within_boundary on the unmodified checker -- residual #8 of the
wave-176 lane), and PASS once gov/authority_proof.py models the two
domains. Probes:

  mcp_within                      -- listed server::tool pair, small
                                     args -> within_boundary.
  mcp_exceeds_unlisted_server     -- server outside the allowlist ->
                                     exceeds_boundary + counterexample.
  mcp_exceeds_unlisted_pair       -- listed server, unlisted tool ->
                                     exceeds_boundary (the confusion
                                     case: evil::read != files::read).
  mcp_confusion_prefix_server     -- "files-backup" is NOT "files":
                                     exact match only, no prefixes.
  mcp_exceeds_arg_bytes           -- arguments over the byte budget ->
                                     exceeds_boundary.
  mcp_unsupported_shapes          -- missing/non-string server, tool,
                                     or non-object arguments ->
                                     unsupported (fail-closed, never
                                     silently normalized).
  mcp_boundary_rejects_bad_ids    -- "::" inside a server id or tool
                                     name raises BoundaryError at load
                                     (the pair separator cannot be
                                     smuggled); a pair naming an
                                     unlisted server is rejected too.
  graphql_within_query            -- shallow query -> within_boundary.
  graphql_exceeds_depth           -- selection depth over the max ->
                                     exceeds_boundary.
  graphql_exceeds_introspection   -- __schema with introspection
                                     disallowed -> exceeds_boundary.
  graphql_exceeds_mutation_flag   -- mutation with allow_mutations off
                                     -> exceeds_boundary.
  graphql_mutation_allowlist      -- mutation root outside the allowlist
                                     -> exceeds_boundary; listed root
                                     -> within_boundary.
  graphql_unsupported_multi_op    -- two operations in one document ->
                                     unsupported (cannot attribute).
  graphql_unsupported_frag_cycle  -- cyclic fragment spreads ->
                                     unsupported.
  graphql_fragment_depth_inlined  -- a deep fragment spread into a
                                     shallow query still counts ->
                                     exceeds_boundary when over max.
  graphql_exceeds_subscription    -- subscriptions are outside the
                                     boundary schema -> exceeds.
  inconclusive_no_boundary        -- boundary=None -> inconclusive with
                                     ALL domains uncovered (now incl.
                                     mcp_tools + graphql); advisory.
  executor_refuses_mcp_exceeds    -- end-to-end: declared boundary +
                                     mcp_call to an unlisted server ->
                                     denied with policy_id
                                     authority-boundary (fail-closed,
                                     no side effect).
  executor_advisory_mcp           -- no boundary: the proof rides the
                                     record as inconclusive and the
                                     policy verdict stands (a within
                                     proof never upgrades a deny).
  determinism                     -- the whole battery runs twice
                                     in-process; verdicts must agree.

Deterministic; synthetic/local only; $0.
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "authority-mcp-graphql-battery")

REPO_ROOT = str(Path(__file__).resolve().parents[1])
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from gov import authority_proof  # noqa: E402
    HAVE_MODULE = True
    IMPORT_ERROR = None
except Exception as e:  # noqa: BLE001 -- red phase must be loud
    authority_proof = None
    HAVE_MODULE = False
    IMPORT_ERROR = e

from harness import make_run  # noqa: E402

_records = []


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


def _require_module(name):
    if not HAVE_MODULE:
        return ("FAIL", "gov.authority_proof unavailable: %r" % (IMPORT_ERROR,))
    return None


def _boundary(**kw):
    """Build a boundary with the wave-177 keys; None if unsupported.

    Returns None (instead of raising) when the tree predates the new
    domain keys, so red-phase probes report FAIL, not ERROR.
    """
    d = {"boundary_id": "mcp-gql-boundary", "version": "1"}
    d.update(kw)
    try:
        return authority_proof.boundary_from_dict(d)
    except Exception:
        return None


def _mcp_boundary():
    return _boundary(
        mcp_servers=["files", "search"],
        mcp_tools=["files::read", "files::write", "search::query"],
        mcp_max_arg_bytes=256,
    )


def _gql_boundary(**kw):
    d = {"graphql_max_depth": 5, "graphql_allow_mutations": True,
         "graphql_mutation_allowlist": ["updateProfile"],
         "graphql_allow_introspection": False,
         # The graphql tool's endpoint host is covered by the egress
         # domain (composition): allowlist it here.
         "egress_hosts": ["api.internal"]}
    d.update(kw)
    return _boundary(**d)


def _action(tool, args):
    return {"tool": tool, "args": dict(args),
            "agent_id": "battery-agent", "role": "coder"}


def _mcp(server, tool, arguments=None):
    # Mirrors the MCP tools/call wire shape: params are
    # {"name": ..., "arguments": {...}}; "server" names the MCP server
    # identity. ("tool" cannot be an arg key: ToolExecutor.call()
    # takes tool as a named parameter.)
    args = {"server": server, "name": tool}
    if arguments is not None:
        args["arguments"] = arguments
    return _action("mcp_call", args)


# ---------------------------------------------------------------- MCP


def p_mcp_within():
    """Listed server::tool pair with small args -> within_boundary."""
    name = "mcp_within"
    miss = _require_module(name)
    if miss:
        return miss
    b = _mcp_boundary()
    if b is None:
        return ("FAIL", "mcp boundary keys unsupported by this tree")
    proof = authority_proof.check(
        _mcp("files", "read", {"path": "/a.txt"}), {}, b)
    ok = (proof.verdict == "within_boundary"
          and proof.counterexample is None
          and "mcp_tools" in proof.covered_domains)
    return ("PASS" if ok else "FAIL",
            "verdict=%s covered=%s" % (proof.verdict,
                                       proof.covered_domains))


def p_mcp_exceeds_unlisted_server():
    """Server outside the allowlist -> exceeds + counterexample."""
    name = "mcp_exceeds_unlisted_server"
    miss = _require_module(name)
    if miss:
        return miss
    b = _mcp_boundary()
    if b is None:
        return ("FAIL", "mcp boundary keys unsupported by this tree")
    proof = authority_proof.check(_mcp("evil", "read", {}), {}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None and ce.domain == "mcp_tools"
          and ce.access == "evil::read")
    return ("PASS" if ok else "FAIL",
            "verdict=%s counterexample=%r" % (proof.verdict, ce))


def p_mcp_exceeds_unlisted_pair():
    """Listed server, unlisted tool -> exceeds (name-confusion case)."""
    name = "mcp_exceeds_unlisted_pair"
    miss = _require_module(name)
    if miss:
        return miss
    b = _mcp_boundary()
    if b is None:
        return ("FAIL", "mcp boundary keys unsupported by this tree")
    # "search" is a listed server but "search::delete_index" is not a
    # listed pair: the tool name must match exactly, not the server.
    proof = authority_proof.check(
        _mcp("search", "delete_index", {}), {}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None and ce.domain == "mcp_tools"
          and ce.access == "search::delete_index")
    return ("PASS" if ok else "FAIL",
            "verdict=%s counterexample=%r" % (proof.verdict, ce))


def p_mcp_confusion_prefix_server():
    """'files-backup' is not 'files': exact match, never prefixes."""
    name = "mcp_confusion_prefix_server"
    miss = _require_module(name)
    if miss:
        return miss
    b = _mcp_boundary()
    if b is None:
        return ("FAIL", "mcp boundary keys unsupported by this tree")
    proof = authority_proof.check(
        _mcp("files-backup", "read", {"path": "/a.txt"}), {}, b)
    ok = (proof.verdict == "exceeds_boundary"
          and proof.counterexample is not None
          and proof.counterexample.access == "files-backup::read")
    return ("PASS" if ok else "FAIL",
            "verdict=%s" % proof.verdict)


def p_mcp_exceeds_arg_bytes():
    """Arguments over the byte budget -> exceeds_boundary."""
    name = "mcp_exceeds_arg_bytes"
    miss = _require_module(name)
    if miss:
        return miss
    b = _mcp_boundary()
    if b is None:
        return ("FAIL", "mcp boundary keys unsupported by this tree")
    big = {"blob": "x" * 1000}
    proof = authority_proof.check(_mcp("files", "read", big), {}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None and ce.domain == "mcp_tools"
          and "bytes" in ce.reason)
    return ("PASS" if ok else "FAIL",
            "verdict=%s reason=%r" % (
                proof.verdict, ce.reason if ce else None))


def p_mcp_unsupported_shapes():
    """Malformed mcp_call shapes -> unsupported, never normalized."""
    name = "mcp_unsupported_shapes"
    miss = _require_module(name)
    if miss:
        return miss
    b = _mcp_boundary()
    if b is None:
        return ("FAIL", "mcp boundary keys unsupported by this tree")
    shapes = [
        _mcp(None, "read", {}),            # server not a string
        _action("mcp_call", {"name": "read"}),  # server missing
        _mcp("files", "", {}),             # empty tool name
        _mcp("files", "read", ["not", "a", "dict"]),  # args not an object
        _action("mcp_call", {"server": "a::b", "name": "read"}),
    ]
    verdicts = [authority_proof.check(s, {}, b).verdict for s in shapes]
    ok = all(v == "unsupported" for v in verdicts)
    return ("PASS" if ok else "FAIL", "verdicts=%s" % (verdicts,))


def p_mcp_boundary_rejects_bad_ids():
    """'::' inside ids and pairs naming unlisted servers -> loud load."""
    name = "mcp_boundary_rejects_bad_ids"
    miss = _require_module(name)
    if miss:
        return miss
    cases = []
    for bad in (
        {"mcp_servers": ["a::b"]},
        {"mcp_servers": ["files"], "mcp_tools": ["fi::le::s::read"]},
        {"mcp_servers": ["files"], "mcp_tools": ["ghost::read"]},
        {"mcp_servers": ["has space"]},
        {"mcp_max_arg_bytes": -1},
        {"mcp_max_arg_bytes": True},
    ):
        d = {"boundary_id": "x", "version": "1"}
        d.update(bad)
        try:
            authority_proof.boundary_from_dict(d)
            cases.append("NO-RAISE:%r" % (bad,))
        except authority_proof.BoundaryError as e:
            # Must name the specific cause, not just "unknown keys"
            # (pre-fix trees raise for the unknown key instead).
            msg = str(e)
            specific = ("::" in msg or "pair" in msg or "space" in msg
                        or "whitespace" in msg or "non-negative" in msg
                        or "bool" in msg or "integer" in msg)
            cases.append("RAISE-OK" if specific else "RAISE-VAGUE:%s" % msg)
        except Exception as e:  # noqa: BLE001
            cases.append("WRONG-EXC:%r" % e)
    ok = all(c == "RAISE-OK" for c in cases)
    return ("PASS" if ok else "FAIL", "cases=%s" % (cases,))


# ------------------------------------------------------------- GraphQL


def p_graphql_within_query():
    """Shallow query inside the depth budget -> within_boundary."""
    name = "graphql_within_query"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary()
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    q = "query { user { name friends { name } } }"
    proof = authority_proof.check(
        _action("graphql", {"endpoint": "https://api.internal/graphql",
                            "query": q}), {}, b)
    ok = (proof.verdict == "within_boundary"
          and "graphql" in proof.covered_domains)
    return ("PASS" if ok else "FAIL",
            "verdict=%s detail=%s" % (proof.verdict, proof.detail))


def p_graphql_exceeds_depth():
    """Selection depth over the max -> exceeds_boundary."""
    name = "graphql_exceeds_depth"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary(graphql_max_depth=3)
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    q = "query { a { b { c { d { e } } } } }"  # depth 5
    proof = authority_proof.check(
        _action("graphql", {"query": q}), {}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None and ce.domain == "graphql"
          and "depth" in ce.reason)
    return ("PASS" if ok else "FAIL",
            "verdict=%s reason=%r" % (
                proof.verdict, ce.reason if ce else None))


def p_graphql_exceeds_introspection():
    """__schema with introspection disallowed -> exceeds_boundary."""
    name = "graphql_exceeds_introspection"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary(graphql_allow_introspection=False)
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    q = "query { __schema { types { name } } }"
    proof = authority_proof.check(
        _action("graphql", {"query": q}), {}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None and ce.domain == "graphql"
          and "ntrospection" in ce.reason)
    # ... and the allowed case stays within:
    b2 = _gql_boundary(graphql_allow_introspection=True)
    p2 = authority_proof.check(_action("graphql", {"query": q}), {}, b2)
    ok = ok and p2.verdict == "within_boundary"
    return ("PASS" if ok else "FAIL",
            "verdict=%s allowed-case=%s" % (proof.verdict, p2.verdict))


def p_graphql_exceeds_mutation_flag():
    """Mutation with allow_mutations off -> exceeds_boundary."""
    name = "graphql_exceeds_mutation_flag"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary(graphql_allow_mutations=False)
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    q = "mutation { updateProfile(name: \"x\") { id } }"
    proof = authority_proof.check(
        _action("graphql", {"query": q}), {}, b)
    ok = (proof.verdict == "exceeds_boundary"
          and proof.counterexample is not None
          and proof.counterexample.domain == "graphql")
    return ("PASS" if ok else "FAIL", "verdict=%s" % proof.verdict)


def p_graphql_mutation_allowlist():
    """Mutation root outside the allowlist -> exceeds; listed -> within."""
    name = "graphql_mutation_allowlist"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary()
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    bad = authority_proof.check(
        _action("graphql", {"query": "mutation { deleteUser(id: 1) }"}),
        {}, b)
    good = authority_proof.check(
        _action("graphql",
                {"query": "mutation { updateProfile(name: \"x\") { id } }"}),
        {}, b)
    ce = bad.counterexample
    ok = (bad.verdict == "exceeds_boundary"
          and ce is not None and ce.access == "mutation:deleteUser"
          and good.verdict == "within_boundary")
    return ("PASS" if ok else "FAIL",
            "bad=%s good=%s" % (bad.verdict, good.verdict))


def p_graphql_unsupported_multi_op():
    """Two operations, one document -> unsupported (cannot attribute)."""
    name = "graphql_unsupported_multi_op"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary()
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    # The disguise: a benign query stapled to a mutation. The checker
    # cannot know which operation the caller will run.
    q = ("query GetUser { user { name } } "
         "mutation Sneaky { deleteUser(id: 1) }")
    proof = authority_proof.check(
        _action("graphql", {"query": q}), {}, b)
    ok = (proof.verdict == "unsupported"
          and proof.counterexample is not None
          and proof.counterexample.domain == "graphql")
    return ("PASS" if ok else "FAIL", "verdict=%s" % proof.verdict)


def p_graphql_unsupported_frag_cycle():
    """Cyclic fragment spreads -> unsupported (no hang, no guess)."""
    name = "graphql_unsupported_frag_cycle"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary()
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    q = ("query { ...A } "
         "fragment A on Query { x ...B } "
         "fragment B on Query { y ...A }")
    proof = authority_proof.check(
        _action("graphql", {"query": q}), {}, b)
    ok = (proof.verdict == "unsupported"
          and proof.counterexample is not None)
    return ("PASS" if ok else "FAIL", "verdict=%s" % proof.verdict)


def p_graphql_fragment_depth_inlined():
    """Depth hidden behind a fragment spread still counts."""
    name = "graphql_fragment_depth_inlined"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary(graphql_max_depth=2)
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    # Literal depth is 1; the fragment adds three more levels.
    q = ("query { ...Deep } "
         "fragment Deep on Query { a { b { c { d } } } }")
    proof = authority_proof.check(
        _action("graphql", {"query": q}), {}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None and "depth" in ce.reason)
    return ("PASS" if ok else "FAIL",
            "verdict=%s reason=%r" % (
                proof.verdict, ce.reason if ce else None))


def p_graphql_exceeds_subscription():
    """Subscriptions are outside the boundary schema -> exceeds."""
    name = "graphql_exceeds_subscription"
    miss = _require_module(name)
    if miss:
        return miss
    b = _gql_boundary()
    if b is None:
        return ("FAIL", "graphql boundary keys unsupported by this tree")
    q = "subscription { messageAdded { text } }"
    proof = authority_proof.check(
        _action("graphql", {"query": q}), {}, b)
    ok = (proof.verdict == "exceeds_boundary"
          and proof.counterexample is not None
          and "subscription" in proof.counterexample.reason)
    return ("PASS" if ok else "FAIL", "verdict=%s" % proof.verdict)


# ------------------------------------------------- seam-level probes


def p_inconclusive_no_boundary():
    """No boundary -> inconclusive, ALL domains uncovered, advisory."""
    name = "inconclusive_no_boundary"
    miss = _require_module(name)
    if miss:
        return miss
    for action in (_mcp("files", "read", {}),
                   _action("graphql", {"query": "query { x }"})):
        proof = authority_proof.check(action, {}, None)
        ok = (proof.verdict == "inconclusive"
              and proof.covered_domains == ()
              and "mcp_tools" in proof.uncovered_domains
              and "graphql" in proof.uncovered_domains)
        if not ok:
            return ("FAIL",
                    "verdict=%s uncovered=%s" % (
                        proof.verdict, proof.uncovered_domains))
    return ("PASS", "both new domains uncovered when advisory")


def _setup(tag):
    # Battery-local policy: the coder role may invoke the declared
    # mcp_call/graphql shapes so the executor probes reach the
    # authority-proof seam (the repo's default.yaml is untouched --
    # the engine has no MCP/GraphQL handlers yet; this lane only
    # models the declared shapes in the proof contract).
    src = Path(REPO_ROOT, "policies", "default.yaml").read_text()
    src = src.replace(
        "coder: [read_file, write_file, delete_file, api_call, "
        "install_package]",
        "coder: [read_file, write_file, delete_file, api_call, "
        "install_package, mcp_call, graphql]")
    path = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]),
                "policy-mcp-gql.yaml")
    path.write_text(src)
    ctx = make_run(policy_path=str(path))
    ident = ctx["executor"].mint_identity("mcp-gql-%s" % tag, "coder",
                                         "mcp-gql-p")
    return ctx, ident


def p_executor_refuses_mcp_exceeds():
    """End-to-end: declared boundary + unlisted MCP server -> denied."""
    name = "executor_refuses_mcp_exceeds"
    miss = _require_module(name)
    if miss:
        return miss
    b = _mcp_boundary()
    if b is None:
        return ("FAIL", "mcp boundary keys unsupported by this tree")
    ctx, ident = _setup("refuse")
    ex = ctx["executor"]
    ex.set_authority_boundary(b)
    r = ex.call(ident, "mcp_call", server="evil", name="read",
                arguments={})
    denied = [e for e in ctx["read_log"]()
              if isinstance(e, dict)
              and e.get("decision") == "denied"
              and e.get("flag") == "authority_boundary_refused"]
    ok = (r.get("status") == "denied"
          and r.get("policy_id") == "authority-boundary"
          and len(denied) == 1
          and denied[0].get("authority_proof", {}).get("verdict")
          == "exceeds_boundary"
          and denied[0].get("authority_proof", {})
          .get("counterexample", {}).get("domain") == "mcp_tools")
    return ("PASS" if ok else "FAIL",
            "status=%r policy_id=%r denials=%d" % (
                r.get("status"), r.get("policy_id"), len(denied)))


def p_executor_advisory_mcp():
    """No boundary: proof rides the record; policy verdict stands."""
    name = "executor_advisory_mcp"
    miss = _require_module(name)
    if miss:
        return miss
    ctx, ident = _setup("advisory")
    ex = ctx["executor"]
    # No boundary set -> advisory mode.
    r = ex.call(ident, "mcp_call", server="files", name="read",
                arguments={"path": "/a.txt"})
    # The proof rides policy_ctx_snapshot["authority_proof"], logged
    # under the entry's "policy_context" key (wave-176 seam).
    proofs = [e.get("policy_context", {}).get("authority_proof")
              for e in ctx["read_log"]()
              if isinstance(e, dict)
              and isinstance(e.get("policy_context"), dict)]
    proofs = [p for p in proofs if p]
    ok = (r.get("policy_id") != "authority-boundary"
          and len(proofs) >= 1
          and proofs[0].get("verdict") == "inconclusive"
          and "mcp_tools" in proofs[0].get("uncovered_domains", ()))
    return ("PASS" if ok else "FAIL",
            "status=%r policy_id=%r proofs=%d" % (
                r.get("status"), r.get("policy_id"), len(proofs)))


PROBES = [
    p_mcp_within,
    p_mcp_exceeds_unlisted_server,
    p_mcp_exceeds_unlisted_pair,
    p_mcp_confusion_prefix_server,
    p_mcp_exceeds_arg_bytes,
    p_mcp_unsupported_shapes,
    p_mcp_boundary_rejects_bad_ids,
    p_graphql_within_query,
    p_graphql_exceeds_depth,
    p_graphql_exceeds_introspection,
    p_graphql_exceeds_mutation_flag,
    p_graphql_mutation_allowlist,
    p_graphql_unsupported_multi_op,
    p_graphql_unsupported_frag_cycle,
    p_graphql_fragment_depth_inlined,
    p_graphql_exceeds_subscription,
    p_inconclusive_no_boundary,
    p_executor_refuses_mcp_exceeds,
    p_executor_advisory_mcp,
]


def _run_once():
    _records.clear()
    for probe in PROBES:
        try:
            verdict, detail = probe()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, detail = "ERROR", "%s: %s" % (
                type(e).__name__, e)
        _record(probe.__name__, verdict, detail)
    return list(_records)


def _green_check_adjacent():
    """Depth-1 green check: adjacent unit tests, GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "tests/test_authority_proof_mcp_graphql.py standalone")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="gql-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_authority_proof_mcp_graphql", "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    ok = (r.returncode == 0)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if ok else "FAIL",
            "tests.test_authority_proof_mcp_graphql rc=%d %s"
            % (r.returncode, tail[0]))


def main():
    first = _run_once()
    second = _run_once()  # determinism: identical verdicts twice
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(PROBES)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    npass = sum(1 for _, v, _ in _records if v == "PASS")
    nfail = sum(1 for _, v, _ in _records if v in ("FAIL", "ERROR"))
    skipped = sum(1 for _, v, _ in _records if v == "SKIP")
    print("== authority MCP/GraphQL battery ==")
    for n, v, d in _records:
        print("[%s] %s -- %s" % (v, n, d))
    print("PASS=%d FAIL/ERROR=%d SKIP=%d" % (npass, nfail, skipped))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
