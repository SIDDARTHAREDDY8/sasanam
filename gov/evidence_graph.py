"""Evidence-graph projection over bundles, skills, and decisions
(wave-250 lane 4).

PATTERN LINEAGE: guacsec/guac (Graph for Understanding Artifact
Composition, Apache-2.0) -- aggregation-and-synthesis evidence graph.
ADAPTED pattern only: this module projects skills, evidence bundles,
bundle records, decisions, identities, and policy revisions from
ALREADY-VERIFIED
artifacts (in-toto layouts, DSSE envelopes, offline bundles, decision
packets) into one traversable auditor view, so "show me everything
about this skill/decision" is a query, not manual assembly. No GUAC
source is vendored; GUAC's package/vulnerability backend is
deliberately dropped (category error for our evidence graph).

Hardening vs GUAC's own admission: GUAC's README admits heuristic
identifier linking. This graph FAILS CLOSED on identifier linking --
``link()`` resolves a selector to exactly one node; zero matches
refuse ``evidence-graph-unlinked`` and two-or-more matches refuse
``evidence-graph-ambiguous-link``. The graph never guesses an
identity, and no query walks a partially-resolved edge set.

Model (edges are src -> dst, "src relates-to dst"):

    admitted_by    skill -> identity        (registry authority
                                            admitted the skill)
    sealed_in      record/decision -> bundle (contained in the bundle)
    decided_by     decision -> identity      (agent identity that
                                            made the decision)
    produced_by    artifact -> skill|identity (what produced it)
    supersedes     policy_revision -> policy_revision (newer -> older)
    revokes        identity -> identity|skill (revoker -> target)

Queries:

    traverse(node_id)        every node reachable over any edges
                             (the full connected evidence set)
    provenance(node_id)      backward chains from the node to its
                             admission roots (paths, sorted)
    blast_radius(node_id)    everything forward-dependent on the
                             node (what a compromise would touch)

Determinism: adjacency is stored sorted; ``serialize()`` emits
canonical JSON (sort_keys, compact separators); ``digest()`` is the
sha256 hex of the canonical bytes -- the graph's identity. Insertion
order never changes the digest.

Bounded: ``max_nodes``/``max_edges`` cap the graph; adds beyond the
cap refuse ``evidence-graph-overflow`` instead of growing silently.

Stdlib only. Deterministic. No env reads, no I/O, no wall clock.
Fail-closed on malformed input.
"""

import hashlib
import json
import re

# Machine codes (all registered in gov/decision_codes.py TAXONOMY).
EVIDENCE_GRAPH_AMBIGUOUS_LINK = "evidence-graph-ambiguous-link"
EVIDENCE_GRAPH_MALFORMED = "evidence-graph-malformed"
EVIDENCE_GRAPH_OVERFLOW = "evidence-graph-overflow"
EVIDENCE_GRAPH_UNLINKED = "evidence-graph-unlinked"

NODE_TYPES = ("skill", "bundle", "decision", "identity",
              "policy_revision", "record")

EDGE_KINDS = ("admitted_by", "sealed_in", "decided_by", "produced_by",
              "supersedes", "revokes")

_NODE_ID_RE = re.compile(r"^([a-z_]+):([A-Za-z0-9][A-Za-z0-9._/-]*)$")

# Default bounds: generous for an auditor view, still finite.
DEFAULT_MAX_NODES = 10000
DEFAULT_MAX_EDGES = 100000


class EvidenceGraphError(Exception):
    """Base class; carries the machine ``code``."""

    code = EVIDENCE_GRAPH_MALFORMED

    def __init__(self, code, detail):
        super(EvidenceGraphError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class AmbiguousLink(EvidenceGraphError):
    """A selector matched more than one node; refused fail-closed."""


class Unlinked(EvidenceGraphError):
    """A selector matched no node; refused fail-closed."""


class GraphOverflow(EvidenceGraphError):
    """A node/edge add would exceed the configured cap."""


class GraphMalformed(EvidenceGraphError):
    """Malformed node/edge/graph input; refused fail-closed."""


def _refuse(exc_class, code, detail):
    raise exc_class(code, detail)


def _check_node_id(node_id):
    if not isinstance(node_id, str):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "node id must be a string")
    match = _NODE_ID_RE.match(node_id)
    if match is None:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "node id must be '<type>:<local>' with a known type")
    node_type = match.group(1)
    if node_type not in NODE_TYPES:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "unknown node type: %r" % (node_type,))
    return node_type


def _check_edge_kind(kind):
    if kind not in EDGE_KINDS:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "unknown edge kind: %r" % (kind,))


def _check_attrs(attrs, where):
    if attrs is None:
        return {}
    if not isinstance(attrs, dict):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "%s attrs must be a dict" % (where,))
    try:
        json.dumps(attrs, sort_keys=True)
    except (TypeError, ValueError):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "%s attrs must be JSON-serializable" % (where,))
    return dict(attrs)


class EvidenceGraph(object):
    """Bounded, deterministic, fail-closed evidence graph."""

    def __init__(self, *, max_nodes=DEFAULT_MAX_NODES,
                 max_edges=DEFAULT_MAX_EDGES):
        if not isinstance(max_nodes, int) or max_nodes <= 0:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "max_nodes must be a positive int")
        if not isinstance(max_edges, int) or max_edges <= 0:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "max_edges must be a positive int")
        self._max_nodes = max_nodes
        self._max_edges = max_edges
        # node_id -> {"type": ..., "attrs": {...}}
        self._nodes = {}
        # (src, dst, kind) tuples; adjacency derived sorted.
        self._edges = set()

    # -- mutation -------------------------------------------------

    def add_node(self, node_id, node_type, attrs=None):
        """Add a node; idempotent for identical re-adds."""
        declared = _check_node_id(node_id)
        if not isinstance(node_type, str) or node_type != declared:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "node type %r does not match node id %r" % (
                        node_type, node_id))
        checked = _check_attrs(attrs, "node")
        existing = self._nodes.get(node_id)
        if existing is not None:
            merged = dict(existing["attrs"])
            merged.update(checked)
            existing["attrs"] = merged
            return node_id
        if len(self._nodes) >= self._max_nodes:
            _refuse(GraphOverflow, EVIDENCE_GRAPH_OVERFLOW,
                    "node cap %d reached" % (self._max_nodes,))
        self._nodes[node_id] = {"type": node_type, "attrs": checked}
        return node_id

    def add_identity(self, identity_id, attrs=None):
        """Convenience: add an identity node."""
        return self.add_node(identity_id, "identity", attrs)

    def add_edge(self, src, dst, kind):
        """Add a directed edge; both endpoints must exist."""
        _check_node_id(src)
        _check_node_id(dst)
        _check_edge_kind(kind)
        if src not in self._nodes:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "edge source missing from graph: %r" % (src,))
        if dst not in self._nodes:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "edge target missing from graph: %r" % (dst,))
        edge = (src, dst, kind)
        if edge in self._edges:
            return edge
        if len(self._edges) >= self._max_edges:
            _refuse(GraphOverflow, EVIDENCE_GRAPH_OVERFLOW,
                    "edge cap %d reached" % (self._max_edges,))
        self._edges.add(edge)
        return edge

    def link(self, src_id, selector, kind):
        """Resolve ``selector`` to exactly one node and edge src->it.

        Fail-closed: zero matches -> ``evidence-graph-unlinked``;
        two-or-more matches -> ``evidence-graph-ambiguous-link``.
        """
        _check_node_id(src_id)
        _check_edge_kind(kind)
        if not isinstance(selector, str) or not selector:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "selector must be a non-empty string")
        matches = sorted(n for n in self._nodes
                         if n == selector or n.startswith(selector))
        if not matches:
            _refuse(Unlinked, EVIDENCE_GRAPH_UNLINKED,
                    "selector %r matched no node" % (selector,))
        if len(matches) > 1:
            _refuse(AmbiguousLink, EVIDENCE_GRAPH_AMBIGUOUS_LINK,
                    "selector %r matched %d nodes; refusing to guess" % (
                        selector, len(matches)))
        return self.add_edge(src_id, matches[0], kind)

    # -- queries ---------------------------------------------------

    def _adjacency(self, kinds, direction):
        """Sorted adjacency: direction 'out' (src->dst) or 'in'."""
        adj = {}
        for (src, dst, kind) in sorted(self._edges):
            if kinds is not None and kind not in kinds:
                continue
            if direction == "out":
                adj.setdefault(src, []).append(dst)
            else:
                adj.setdefault(dst, []).append(src)
        return adj

    def traverse(self, node_id, *, edge_kinds=None):
        """Every node reachable from ``node_id`` over any edge
        direction (the full connected evidence set), sorted."""
        _check_node_id(node_id)
        if node_id not in self._nodes:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "unknown node: %r" % (node_id,))
        kinds = self._kinds_or_all(edge_kinds)
        out_adj = self._adjacency(kinds, "out")
        in_adj = self._adjacency(kinds, "in")
        seen = {node_id}
        stack = [node_id]
        while stack:
            current = stack.pop()
            for nxt in out_adj.get(current, []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
            for nxt in in_adj.get(current, []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return sorted(seen)

    def provenance(self, node_id):
        """Backward chains from ``node_id`` to admission roots.

        Follows src->dst edges from the node (dependent -> authority/
        container/producer) to every root, returning one path per
        root, paths sorted lexicographically. The first element of
        every path is the node itself.
        """
        _check_node_id(node_id)
        if node_id not in self._nodes:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "unknown node: %r" % (node_id,))
        out_adj = self._adjacency(None, "out")

        paths = []

        def walk(current, path, on_path):
            children = out_adj.get(current, [])
            if not children:
                paths.append(list(path))
                return
            for nxt in children:
                if nxt in on_path:
                    continue  # cycle-safe; cycles cannot form via
                    # project_* (see docstring), but never hang
                on_path.add(nxt)
                path.append(nxt)
                walk(nxt, path, on_path)
                path.pop()
                on_path.discard(nxt)

        walk(node_id, [node_id], {node_id})
        return sorted(paths)

    def blast_radius(self, node_id):
        """Everything forward-dependent on ``node_id``.

        Walks reverse edges (dst -> src: who depends on this node)
        plus forward ``sealed_in`` edges (a bundle sealing a tainted
        decision is affected too), returning the sorted set including
        the node itself: the decisions a skill produced, the bundles
        sealing them, the targets of a revocation, and so on.
        Upstream authorities (``admitted_by``, ``decided_by``) are
        never included -- a compromised skill does not compromise its
        admission authority.
        """
        _check_node_id(node_id)
        if node_id not in self._nodes:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "unknown node: %r" % (node_id,))
        # neighbors: everything that points AT a node, plus anything
        # the node seals (forward sealed_in only).
        rev_adj = {}
        seal_adj = {}
        for (src, dst, kind) in sorted(self._edges):
            rev_adj.setdefault(dst, []).append(src)
            if kind == "sealed_in":
                seal_adj.setdefault(src, []).append(dst)
        seen = {node_id}
        stack = [node_id]
        while stack:
            current = stack.pop()
            for nxt in rev_adj.get(current, []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
            for nxt in seal_adj.get(current, []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return sorted(seen)

    # -- identity --------------------------------------------------

    def serialize(self):
        """Canonical JSON bytes of the graph (sorted, compact)."""
        canonical = {
            "nodes": {nid: {"type": info["type"],
                            "attrs": info["attrs"]}
                      for nid, info in sorted(self._nodes.items())},
            "edges": sorted([list(e) for e in self._edges]),
        }
        return json.dumps(canonical, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def digest(self):
        """sha256 hex of the canonical serialization: the graph's
        identity. Insertion order never changes it."""
        return hashlib.sha256(self.serialize()).hexdigest()

    def node_count(self):
        return len(self._nodes)

    def edge_count(self):
        return len(self._edges)

    @staticmethod
    def _kinds_or_all(edge_kinds):
        if edge_kinds is None:
            return None
        kinds = tuple(edge_kinds)
        for kind in kinds:
            _check_edge_kind(kind)
        return frozenset(kinds)


# ------------------------------------------------------------------
# projections: verified artifacts -> graph nodes/edges
# ------------------------------------------------------------------

def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def project_admission(graph, verdict, *, authority_id):
    """Project a skill-admission verdict into the graph.

    ``verdict``: the dict returned by
    ``gov.skill_admission.admit``. Adds ``skill:<layout_id>`` and
    ``identity:<authority_id>`` with an ``admitted_by`` edge.
    Refused verdicts are not projectable (fail-closed).
    """
    if not isinstance(verdict, dict):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "verdict must be a dict")
    if verdict.get("admitted") is not True:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "refused admissions are not projectable")
    evidence = verdict.get("evidence")
    if not isinstance(evidence, dict):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "verdict.evidence must be a dict")
    layout_id = evidence.get("layout_id")
    if not isinstance(layout_id, str) or not layout_id:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "verdict.evidence.layout_id must be a non-empty string")
    if not isinstance(authority_id, str) or not authority_id:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "authority_id must be a non-empty string")
    skill = "skill:" + layout_id
    authority = "identity:" + authority_id
    graph.add_node(skill, "skill",
                   {"layout_id": layout_id})
    graph.add_identity(authority, {"role": "layout-authority"})
    graph.add_edge(skill, authority, "admitted_by")
    return skill


def project_bundle_manifest(graph, manifest, *, record_nodes=()):
    """Project an offline-bundle manifest into the graph.

    Adds ``bundle:<bundle_id>``; every entry in
    ``manifest["entries"]`` becomes ``record:<digest>`` with a
    ``sealed_in`` edge to the bundle, as does every node id in
    ``record_nodes`` (already-projected decisions/records the bundle
    seals).
    """
    if not isinstance(manifest, dict):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "manifest must be a dict")
    bundle_id = manifest.get("bundle_id")
    if not isinstance(bundle_id, str) or not bundle_id:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "manifest.bundle_id must be a non-empty string")
    bundle = "bundle:" + bundle_id
    graph.add_node(bundle, "bundle",
                   {"ledger_digest": manifest.get("ledger_digest")})
    entries = manifest.get("entries", ())
    if not isinstance(entries, (list, tuple)):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "manifest.entries must be a list")
    for entry in entries:
        if not isinstance(entry, dict):
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "manifest entry must be a dict")
        digest = entry.get("digest")
        if not isinstance(digest, str) or not digest:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "manifest entry needs a digest")
        record = "record:" + digest
        _check_node_id(record)
        graph.add_node(record, "record", {"seq": entry.get("seq")})
        graph.add_edge(record, bundle, "sealed_in")
    for record_node in record_nodes:
        _check_node_id(record_node)
        if record_node not in graph._nodes:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "record node not in graph: %r" % (record_node,))
        graph.add_edge(record_node, bundle, "sealed_in")
    return bundle


def project_decision_packet(graph, packet, *, identity_id, skill_id=None):
    """Project a decision packet into the graph.

    Adds ``decision:<digest>`` (sha256 of the canonical packet body,
    signature excluded) with a ``decided_by`` edge to
    ``identity:<identity_id>`` and, when ``skill_id`` is given, a
    ``produced_by`` edge to ``skill:<skill_id>``.
    """
    if not isinstance(packet, dict):
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "packet must be a dict")
    if not isinstance(identity_id, str) or not identity_id:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "identity_id must be a non-empty string")
    body = {k: v for k, v in packet.items() if k != "signature"}
    digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    decision = "decision:" + digest
    identity = "identity:" + identity_id
    graph.add_node(decision, "decision",
                   {"value": packet.get("decision")})
    graph.add_identity(identity)
    graph.add_edge(decision, identity, "decided_by")
    if skill_id is not None:
        if not isinstance(skill_id, str) or not skill_id:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "skill_id must be a non-empty string")
        skill = "skill:" + skill_id
        graph.add_node(skill, "skill")
        graph.add_edge(decision, skill, "produced_by")
    return decision


def project_policy_revision(graph, rev_id, *, supersedes=None):
    """Project a policy revision; ``supersedes`` links the old rev."""
    if not isinstance(rev_id, str) or not rev_id:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "rev_id must be a non-empty string")
    rev = "policy_revision:" + rev_id
    graph.add_node(rev, "policy_revision", {"rev_id": rev_id})
    if supersedes is not None:
        if not isinstance(supersedes, str) or not supersedes:
            _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                    "supersedes must be a non-empty string")
        old = "policy_revision:" + supersedes
        graph.add_node(old, "policy_revision", {"rev_id": supersedes})
        graph.add_edge(rev, old, "supersedes")
    return rev


def project_revocation(graph, revoker_id, target_id):
    """Project a revocation: identity ``revoker_id`` revokes
    ``target_id`` (a full node id, e.g. ``identity:<k>`` or
    ``skill:<layout>``)."""
    if not isinstance(revoker_id, str) or not revoker_id:
        _refuse(GraphMalformed, EVIDENCE_GRAPH_MALFORMED,
                "revoker_id must be a non-empty string")
    _check_node_id(target_id)
    revoker = "identity:" + revoker_id
    graph.add_identity(revoker, {"role": "revoker"})
    node_type = _check_node_id(target_id)
    graph.add_node(target_id, node_type)
    graph.add_edge(revoker, target_id, "revokes")
    return target_id


# module-level re-exports for the battery / convenience API
def traverse(graph, node_id, *, edge_kinds=None):
    return graph.traverse(node_id, edge_kinds=edge_kinds)


def provenance(graph, node_id):
    return graph.provenance(node_id)


def blast_radius(graph, node_id):
    return graph.blast_radius(node_id)
