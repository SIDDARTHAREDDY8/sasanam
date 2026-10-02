"""BloodHound-pattern attack-path auditor over the agent grant graph.

Mechanism provenance: SpecterOps/BloodHound Community Edition (Apache-2.0
-- mechanism shapes only, no BloodHound code vendored; do not confuse
with the GPL-3.0 deprecated BloodHound-Legacy). NOT the stack: no Neo4j,
no PostgreSQL -- a stdlib-only in-memory graph.

What this module is: the continuous audit half of grant-graph analysis.
BloodHound turns AD privileges into typed edges and asks "shortest path
to Domain Admins?"; here the privilege graph is the agent->tool grant
graph (agents, sessions, delegation tokens, grants, approval checkpoints,
human principals) and the flagship query is "shortest path to each
high-value capability".

Three pieces, one per the prospectus teardown:

1. Typed edges with exploit semantics + composition: ``granted_to`` and
   ``delegated_by`` compose into the derived ``can_call`` relation
   (nested delegation is nested group membership; an over-broad grant is
   unconstrained delegation).
2. Shortest-path queries to marked high-value targets (exfil-capable or
   credential-bearing tools, the audit log itself) from any principal.
3. Automatic findings enumeration -- dangerous exposures surfaced without
   a human asking: unprovenanced paths to high-value targets, delegation
   cycles, unapproved grants to high-value tools.

The key governance primitive is provenance checkpoints as REQUIRED
WAYPOINT edges: any path that reaches a high-value capability without
traversing a provenance checkpoint is flagged
(``unprovenanced-path-to-high-value``). This puts direct, structural
pressure on the F307 class of defects (plan-trace omission defeating
provenance routing): omission becomes a graph query, not a code review.

Findings are machine-readable dicts with a sha256 ``finding_digest``,
chained into the HMAC audit log at enumeration time via
``AttackPathWriter`` (the wave-280 grant-decision-writer precedent).

Fail-closed: unknown nodes/edge types refuse with coded
``AttackPathError``; malformed finding dicts are refused at write time;
graph queries never raise on absent nodes (``can_call``/``shortest_paths``
return empty/false).
"""

import hashlib
import json

_GENESIS = "GENESIS"
SCHEMA_VERSION = 1
RECORD_TYPE = "attack-path-finding"

# Digest scope for record verification: only this module's fields, never
# the log's chain metadata (the guardrail-evidence precedent).
RECORD_FIELDS = frozenset({
    "record_type", "schema_version", "finding_kind", "source", "target",
    "path", "missing_waypoints", "finding_digest",
    "prev_attack_path_digest", "record_digest",
})

NODE_KINDS = frozenset({
    "agent", "user", "session", "tool", "checkpoint", "approval",
})

# Closed edge vocabulary. Traversal edges (granted_to, delegated_by)
# compose into can_call. Evidence edges (approved, checked) annotate
# grants but are not traversed by the path queries.
EDGE_TYPES = frozenset({
    "granted_to",    # principal -> tool: direct grant
    "delegated_by",  # principal -> principal: sub-delegation
    "approved",      # approval -> tool: approval record exists for grants
    "checked",       # checkpoint -> tool: provenance checkpoint deployed
                     # on this tool; grants to it count as waypoint-clean
})

FINDING_KINDS = frozenset({
    "unprovenanced-path-to-high-value",
    "delegation-cycle",
    "unapproved-high-value-grant",
})

EXPECTED_CODES = frozenset({
    "attackpath-unknown-node",
    "attackpath-unknown-edge-type",
    "attackpath-duplicate-node",
})


class AttackPathError(Exception):
    """Coded refusal. ``code`` is always one of EXPECTED_CODES."""

    def __init__(self, code, detail):
        super(AttackPathError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise AttackPathError(code, detail)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _check_id(value, what):
    if not isinstance(value, str) or not value:
        _refuse("attackpath-unknown-node",
                "%s must be a non-empty str" % what)


class GrantGraph(object):
    """In-memory typed grant graph. Mutation is fail-fast; queries are
    total (never raise on absent nodes)."""

    def __init__(self):
        self._nodes = {}          # node_id -> {"kind": str, "labels": frozenset}
        self._edges = []          # (src, edge_type, dst, attrs)
        self._high_value = set()

    # -- construction -------------------------------------------------
    def add_node(self, node_id, kind, labels=()):
        _check_id(node_id, "node_id")
        if node_id in self._nodes:
            _refuse("attackpath-duplicate-node",
                    "node %r already registered" % node_id)
        if kind not in NODE_KINDS:
            _refuse("attackpath-unknown-node",
                    "unknown node kind %r" % (kind,))
        lab = frozenset(labels)
        for l in lab:
            if not isinstance(l, str) or not l:
                _refuse("attackpath-unknown-node",
                        "label must be a non-empty str")
        self._nodes[node_id] = {"kind": kind, "labels": lab}

    def add_edge(self, src, dst, edge_type, *, provenance_checkpoint=False,
                 approved=False):
        _check_id(src, "edge src")
        _check_id(dst, "edge dst")
        if edge_type not in EDGE_TYPES:
            _refuse("attackpath-unknown-edge-type",
                    "unknown edge type %r" % (edge_type,))
        if src not in self._nodes:
            _refuse("attackpath-unknown-node",
                    "edge src %r not registered" % src)
        if dst not in self._nodes:
            _refuse("attackpath-unknown-node",
                    "edge dst %r not registered" % dst)
        self._edges.append((src, edge_type, dst, {
            "provenance_checkpoint": bool(provenance_checkpoint),
            "approved": bool(approved),
        }))

    def mark_high_value(self, node_id):
        _check_id(node_id, "node_id")
        if node_id not in self._nodes:
            _refuse("attackpath-unknown-node",
                    "cannot mark unregistered node %r high-value" % node_id)
        self._high_value.add(node_id)

    # -- inspection ---------------------------------------------------
    def nodes(self):
        return sorted(self._nodes)

    def edges(self):
        return list(self._edges)

    def node(self, node_id):
        n = self._nodes.get(node_id)
        if n is None:
            return None
        return {"kind": n["kind"], "labels": sorted(n["labels"])}

    def edge(self, src, dst, edge_type):
        for (s, et, d, attrs) in self._edges:
            if s == src and et == edge_type and d == dst:
                return dict(attrs)
        return None

    def high_value_nodes(self):
        return sorted(self._high_value)


def _traversal_edges(graph):
    """Adjacency over the two composition edges, cycle-safe order."""
    adj = {}
    for (s, et, d, attrs) in graph._edges:
        if et in ("granted_to", "delegated_by"):
            adj.setdefault(s, []).append((et, d, attrs))
    return adj


def can_call(graph, principal, tool):
    """Derived reachability: principal can call tool via granted_to +
    delegated_by composition. Total: False on absent nodes."""
    if principal not in graph._nodes or tool not in graph._nodes:
        return False
    seen = {principal}
    stack = [principal]
    adj = _traversal_edges(graph)
    while stack:
        cur = stack.pop()
        if cur == tool:
            return True
        for (et, dst, _attrs) in adj.get(cur, []):
            if dst not in seen:
                seen.add(dst)
                stack.append(dst)
    return False


def shortest_paths(graph, source, target):
    """All minimal-length paths from source to target over the traversal
    edges. Each path is a list of (src, edge_type, dst, attrs) hops.
    Cycle-safe BFS. Total: [] on absent nodes or no path."""
    if source not in graph._nodes or target not in graph._nodes:
        return []
    adj = _traversal_edges(graph)
    # BFS by layers; keep all parents that achieve the minimal distance.
    dist = {source: 0}
    parents = {source: []}
    frontier = [source]
    found = None
    while frontier and found is None:
        nxt = []
        for cur in frontier:
            for (et, dst, attrs) in adj.get(cur, []):
                if dst not in dist:
                    dist[dst] = dist[cur] + 1
                    parents[dst] = [(cur, et, attrs)]
                    nxt.append(dst)
                    if dst == target:
                        found = dist[dst]
                elif dist[dst] == dist[cur] + 1 and (found is None
                                                    or dist[dst] <= found):
                    parents[dst].append((cur, et, attrs))
        frontier = nxt
    if target not in dist:
        return []
    # Reconstruct all minimal paths backwards.
    paths = []

    def _build(node, acc):
        if node == source:
            paths.append(list(reversed(acc)))
            return
        for (par, et, attrs) in parents[node]:
            acc.append((par, et, node, dict(attrs)))
            _build(par, acc)
            acc.pop()

    _build(target, [])
    return paths


def _path_clean(graph, path):
    """A path is waypoint-clean iff every granted_to edge carries a
    provenance checkpoint (edge attribute) or lands on a tool with a
    deployed checkpoint (inbound ``checked`` edge).

    Model residual (documented, not refused): enumeration sources are
    principal kinds (agent/user/session); a granted_to edge whose src is
    not a principal kind is outside the waypoint query's source set."""
    gated = {d for (s, et, d, _a) in graph._edges if et == "checked"}
    for (src, et, dst, attrs) in path:
        if et == "granted_to" and not attrs.get("provenance_checkpoint") \
                and dst not in gated:
            return False
    return True


def _finding(kind, source, target, path):
    hops = [{"src": s, "edge": et, "dst": d,
             "provenance_checkpoint": bool(a.get("provenance_checkpoint"))}
            for (s, et, d, a) in path]
    missing = [h for h in hops
               if h["edge"] == "granted_to"
               and not h["provenance_checkpoint"]]
    body = {
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "finding_kind": kind,
        "source": source,
        "target": target,
        "path": hops,
        "missing_waypoints": missing,
    }
    body["finding_digest"] = _digest(_canonical(body))
    return body


def _delegation_cycles(graph):
    """Cycles in the delegated_by subgraph (nested delegation is nested
    group membership). Deterministic order."""
    adj = {}
    for (s, et, d, _a) in graph._edges:
        if et == "delegated_by":
            adj.setdefault(s, []).append(d)
    cycles = []
    seen_cycles = set()

    def _dfs(node, stack, on_stack):
        stack.append(node)
        on_stack.add(node)
        for nxt in sorted(adj.get(node, [])):
            if nxt in on_stack:
                cyc = stack[stack.index(nxt):] + [nxt]
                key = tuple(sorted(cyc))
                if key not in seen_cycles:
                    seen_cycles.add(key)
                    cycles.append(list(cyc))
            elif nxt not in visited:
                visited.add(nxt)
                _dfs(nxt, stack, on_stack)
        stack.pop()
        on_stack.discard(node)

    visited = set()
    for node in sorted(adj):
        if node not in visited:
            visited.add(node)
            _dfs(node, [], set())
    return cycles


def enumerate_findings(graph):
    """Automatic findings enumeration, deterministic. Three kinds:
    - unprovenanced-path-to-high-value: a shortest path from a principal
      to a high-value node containing a granted_to edge without a
      provenance checkpoint (the F307 pressure point).
    - delegation-cycle: a cycle in delegated_by edges.
    - unapproved-high-value-grant: a granted_to edge to a high-value
      node with no approved edge to that node."""
    findings = []
    principals = sorted(n for n in graph._nodes
                        if graph._nodes[n]["kind"]
                        in ("agent", "user", "session"))
    for target in graph.high_value_nodes():
        for src in principals:
            if src == target:
                continue
            for path in shortest_paths(graph, src, target):
                if not _path_clean(graph, path):
                    findings.append(_finding(
                        "unprovenanced-path-to-high-value", src, target,
                        path))
    for cyc in _delegation_cycles(graph):
        body = {
            "record_type": RECORD_TYPE,
            "schema_version": SCHEMA_VERSION,
            "finding_kind": "delegation-cycle",
            "source": cyc[0],
            "target": cyc[0],
            "path": [{"src": cyc[i], "edge": "delegated_by",
                      "dst": cyc[i + 1],
                      "provenance_checkpoint": False}
                     for i in range(len(cyc) - 1)],
            "missing_waypoints": [],
        }
        body["finding_digest"] = _digest(_canonical(body))
        findings.append(body)
    approved_tools = {d for (s, et, d, _a) in graph._edges
                      if et == "approved"}
    for (s, et, d, _a) in graph._edges:
        if et == "granted_to" and d in graph._high_value \
                and d not in approved_tools:
            findings.append(_finding("unapproved-high-value-grant", s, d,
                                     [(s, et, d, {})]))
    findings.sort(key=lambda f: (f["finding_kind"], f["source"],
                                 f["target"], f["finding_digest"]))
    return findings


class AttackPathWriter(object):
    """Chains machine-readable attack-path findings into the HMAC audit
    log AT ENUMERATION TIME (the grant-decision-writer precedent).
    Fail-closed: if log.append raises, the exception propagates."""

    def __init__(self, log):
        self._log = log
        self._last_digest = _GENESIS

    def write_findings(self, findings):
        entries = []
        for f in findings:
            record = self._checked_record(f)
            record["prev_attack_path_digest"] = self._last_digest
            record["record_digest"] = _digest(_canonical(record))
            entries.append(self._log.append(record))
            self._last_digest = record["record_digest"]
        return entries

    @staticmethod
    def _checked_record(f):
        if not isinstance(f, dict):
            _refuse("attackpath-unknown-node",
                    "finding must be a dict")
        for key in ("finding_kind", "source", "target", "path",
                    "missing_waypoints", "finding_digest"):
            if key not in f:
                _refuse("attackpath-unknown-node",
                        "finding missing key %r" % key)
        if f["finding_kind"] not in FINDING_KINDS:
            _refuse("attackpath-unknown-edge-type",
                    "unknown finding kind %r" % (f["finding_kind"],))
        return {
            "record_type": RECORD_TYPE,
            "schema_version": SCHEMA_VERSION,
            "finding_kind": f["finding_kind"],
            "source": f["source"],
            "target": f["target"],
            "path": f["path"],
            "missing_waypoints": f["missing_waypoints"],
            "finding_digest": f["finding_digest"],
        }


def attack_path_records(log):
    """All attack-path-finding records in ``log``, in stored order
    (the grant-decision-records precedent)."""
    from gov.log import read_entries
    return [e for e in read_entries(log.path)
            if isinstance(e, dict) and e.get("record_type") == RECORD_TYPE]


def verify_attack_path_records(records):
    """Standalone verifier: True iff every record's digest verifies and
    the per-writer chain is continuous. Exact bool, never raises."""
    try:
        last = _GENESIS
        for r in records:
            if not isinstance(r, dict):
                return False
            if r.get("record_type") != RECORD_TYPE:
                return False
            if r.get("prev_attack_path_digest") != last:
                return False
            # Digest only this module's fields (never the log's seq/ts/
            # prev_hash metadata); absent keys are excluded so only
            # actual removal breaks the digest.
            body = {k: r[k] for k in RECORD_FIELDS
                    if k != "record_digest" and k in r}
            if r.get("record_digest") != _digest(_canonical(body)):
                return False
            last = r["record_digest"]
        return True
    except Exception:
        return False
