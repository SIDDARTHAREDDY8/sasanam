"""Blast-radius queries over the Decision BOM decision graph
(wave-214 lane B -- GUAC query-discipline ADAPT).

PATTERN LINEAGE: GUAC (Graph for Understanding Artifact Composition,
https://github.com/guacsec/guac, Apache-2.0). Only the QUERY
DISCIPLINE is adapted: GUAC's GraphQL ``usingOnly`` restricts every
traversal to an explicit caller-declared edge set, so two analysts
running the same query always walk the same edges and the answer is
reproducible and auditable. GUAC's package-graph backend is
deliberately DROPPED -- it models packages and vulnerabilities, a
category error for an evidence graph of decisions, builders, keys,
artifacts, scan verdicts, and promotions. No GUAC source is vendored;
the discipline is re-described in our own words.

What this module is and is not:

* It is a READ-ONLY query layer. It changes no BOM emission
  semantics (``gov.decision_bom`` is untouched) and it never admits
  evidence -- the graph is assembled by the caller from already
  verified artifacts (BOMs, DSSE envelopes, audit entries). A query
  answers only from the edges the caller put in.
* It answers three revocation-blast-radius questions:
    1. which decisions used revoked builder X
    2. which artifacts were emitted under key K
    3. which promotions depend on scan verdict V
  plus a generic ``reachable()`` path/neighbors traversal.
* Every traversal runs under the edge ALLOWLIST (the usingOnly
  discipline): the caller declares the edge kinds the query may use;
  any declared kind outside the pinned allowlist fails CLOSED -- the
  query raises instead of silently walking a smaller edge set and
  returning a partial-looking answer. ``add_edge`` refuses
  non-allowlisted kinds at build time, so no graph can ever carry a
  smuggled edge. The allowlist itself is signed AND pinned:
  ``sign_allowlist`` Ed25519-signs the canonical record and
  ``verify_allowlist_signature`` checks the signature against the
  deployment-pinned key (key-swap and stale/foreign disciplines
  refused); ``allowlist_digest`` / ``pin_allowlist`` provide the
  digest pin for startup checks.

Determinism and pinning: all result lists are sorted, every report
carries the allowlist version and its digest, and ``report_digest``
binds the whole answer -- the same inputs always produce
byte-identical outputs, so a blast-radius answer is evidence that can
be re-derived, not an engine-side opinion.

Honest boundaries (documented, not absorbed):
* Missing-node queries return EMPTY, never errors-as-denials: an
  unknown builder/key/verdict/decision id yields [], so a caller can
  never mistake a lookup failure for an exoneration or an accusation.
* The graph proves what the caller RECORDED, not what happened: a
  decision built without its builder edge is invisible to these
  queries (same caller-owned-reality doctrine as
  ``gov.artifact_rules``). Graph assembly must come from the verified
  evidence (BOM digests, audit log, DSSE envelopes), never from the
  claimant.
* Cycles terminate (visited set); each node is reported exactly once.
* Node ids are caller-owned strings; the module validates shape, not
  truth. Revocation status is a node attribute the caller sets from
  its own revocation source.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads.
"""

import hashlib
import json


class GraphError(ValueError):
    """The decision graph could not be built (loud, fail-closed for
    graph builders)."""


class QueryError(ValueError):
    """A blast-radius query was refused (loud, fail-closed for
    queriers)."""


#: Node kinds this layer knows. Closed vocabulary -- an unknown kind
#: is refused at add_node time.
NODE_KINDS = frozenset({
    "decision",
    "builder",
    "key",
    "artifact",
    "scan_verdict",
    "promotion",
})

#: The edge ALLOWLIST (the usingOnly discipline). Only edges of these
#: kinds exist in a DecisionGraph, and only these kinds may be declared
#: in a traversal. FROZEN: there is no API that mutates it. Changing
#: the set is a new ALLOWLIST_VERSION with a new allowlist_digest --
#: never a silent widening.
ALLOWLIST_VERSION = 1
ALLOWLIST = frozenset({
    "decision/used-builder",        # decision -> builder
    "decision/attested-by",         # decision -> key (signing key)
    "decision/emitted",             # decision -> artifact
    "decision/consumed-verdict",    # decision -> scan_verdict
    "artifact/attested-by",         # artifact -> key (signing key)
    "artifact/derived-from",        # artifact -> decision
    "promotion/promoted-decision",  # promotion -> decision
    "promotion/admitted-verdict",   # promotion -> scan_verdict
})

#: Default using-edges per headline query. Each is a declared subset
#: of ALLOWLIST (pinned by battery and unit tests).
DEFAULT_USING_EDGES = {
    "decisions_using_builder": ("decision/used-builder",),
    "artifacts_emitted_under_key": (
        "decision/attested-by",
        "decision/emitted",
        "artifact/attested-by",
    ),
    "promotions_depending_on_verdict": (
        "promotion/admitted-verdict",
        "promotion/promoted-decision",
        "decision/consumed-verdict",
    ),
}

_QUERY_NAMES = frozenset(DEFAULT_USING_EDGES)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _is_nonempty_str(value):
    return isinstance(value, str) and bool(value)


def allowlist_digest():
    """sha256 over the canonical {version, edges} record -- the pin
    every query report carries."""
    record = {"version": ALLOWLIST_VERSION,
              "edges": sorted(ALLOWLIST)}
    return hashlib.sha256(_canonical(record)).hexdigest()


def pin_allowlist(expected_digest):
    """Fail closed unless the pinned allowlist digest matches.

    Deployments that must guarantee the exact query discipline they
    audited can call this at startup with the digest they pinned; a
    mismatch (i.e. a changed ALLOWLIST_VERSION or edge set) raises
    GraphError instead of running queries under a wider discipline.
    """
    actual = allowlist_digest()
    if not isinstance(expected_digest, str) or expected_digest != actual:
        raise GraphError(
            "allowlist pin mismatch: expected %r, pinned allowlist "
            "digests to %s (ALLOWLIST_VERSION=%d)" % (
                expected_digest, actual, ALLOWLIST_VERSION))
    return True


def allowlist_record():
    """The canonical allowlist record: version + the pinned edge set +
    its digest. This is what gets signed."""
    return {"version": ALLOWLIST_VERSION,
            "edges": sorted(ALLOWLIST),
            "digest": allowlist_digest()}


def sign_allowlist(signer):
    """Ed25519-sign the allowlist record with a ``gov.signing.Signer``.

    The signed record binds the exact edge set a deployment audited;
    verifiers check the signature against the deployment-pinned public
    key with :func:`verify_allowlist_signature`. The key is
    caller-owned (key custody is the deployment's job, per the wave-23
    key-custody posture); the module only binds and verifies.
    """
    record = allowlist_record()
    sig = signer.sign(_canonical(record))
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        raise GraphError("signer returned a malformed signature")
    return {"record": record,
            "key_id": signer.key_id,
            "signature": bytes(sig).hex()}


def verify_allowlist_signature(verifier, signed):
    """Verify a signed allowlist record against a
    ``gov.signing.Verifier``. Returns the verified record dict.

    Fail-closed (GraphError) on: malformed envelope, a ``key_id``
    that does not match the verifier (key-swap refused), a record
    whose version/edges/digest do not describe THIS pinned allowlist
    (stale or foreign discipline refused), or a bad signature. A
    signed record for a different edge set can never pass as this
    deployment's allowlist.
    """
    if not isinstance(signed, dict):
        raise GraphError("signed allowlist is not a dict")
    record = signed.get("record")
    key_id = signed.get("key_id")
    signature = signed.get("signature")
    if key_id != verifier.key_id:
        raise GraphError(
            "signed allowlist key_id %r does not match the verifier's "
            "%r (key-swap refused)" % (key_id, verifier.key_id))
    expected = allowlist_record()
    if not isinstance(record, dict) or record != expected:
        raise GraphError(
            "signed allowlist record does not describe the pinned "
            "allowlist (version %d); stale or foreign discipline "
            "refused" % (ALLOWLIST_VERSION,))
    if not isinstance(signature, str):
        raise GraphError("signed allowlist signature is not a string")
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        raise GraphError("signed allowlist signature is not hex")
    if not verifier.verify(_canonical(record), sig_bytes):
        raise GraphError("allowlist signature invalid")
    return record


def list_edge_kinds():
    """The pinned allowlist as a sorted list (read-only view)."""
    return sorted(ALLOWLIST)


class DecisionGraph:
    """An in-memory evidence graph for blast-radius queries.

    Nodes are (kind, node_id) with caller-owned attribute dicts
    (e.g. ``{"revoked": True}`` on a builder node). Edges are
    directed and each carries a kind from ALLOWLIST -- nothing else
    can be added, so every traversable relationship is one the query
    discipline was pinned against.
    """

    def __init__(self):
        self._nodes = {}   # (kind, node_id) -> attrs dict
        self._by_id = {}   # node_id -> kind (ids must be unique)
        self._out = {}     # node_id -> list of (edge_kind, dst_id)

    # ---------------------------------------------------------- builders

    def add_node(self, kind, node_id, attrs=None):
        """Add a node. Loud GraphError on: unknown kind, malformed
        id, non-dict attrs, or a duplicate id (two attribute sets for
        one id would make queries ambiguous)."""
        if kind not in NODE_KINDS:
            raise GraphError(
                "unknown node kind %r; must be one of %s"
                % (kind, sorted(NODE_KINDS)))
        if not _is_nonempty_str(node_id):
            raise GraphError("node_id must be a non-empty string")
        if attrs is None:
            attrs = {}
        if not isinstance(attrs, dict):
            raise GraphError("attrs must be a dict or None")
        if node_id in self._by_id:
            raise GraphError(
                "duplicate node_id %r (already a %s node)"
                % (node_id, self._by_id[node_id]))
        self._nodes[(kind, node_id)] = dict(attrs)
        self._by_id[node_id] = kind
        self._out[node_id] = []
        return node_id

    def add_edge(self, src_id, dst_id, edge_kind):
        """Add a directed edge. Loud GraphError on: a non-allowlisted
        edge kind (the usingOnly discipline starts at build time),
        unknown endpoints (no dangling edges), or a malformed id."""
        if edge_kind not in ALLOWLIST:
            raise GraphError(
                "edge kind %r is not in the pinned allowlist "
                "(version %d); refusing to build a graph with a "
                "non-traversable edge" % (edge_kind, ALLOWLIST_VERSION))
        for label, node_id in (("src", src_id), ("dst", dst_id)):
            if not _is_nonempty_str(node_id):
                raise GraphError("%s node_id must be a non-empty string"
                                 % (label,))
            if node_id not in self._by_id:
                raise GraphError(
                    "%s node %r not in the graph; edges may not "
                    "dangle" % (label, node_id))
        self._out[src_id].append((edge_kind, dst_id))
        return (src_id, dst_id, edge_kind)

    # ------------------------------------------------------------- views

    def node_kind(self, node_id):
        """The kind of a node id, or None when unknown."""
        return self._by_id.get(node_id)

    def node_attrs(self, node_id):
        """A copy of the node's attrs, or None when unknown."""
        kind = self._by_id.get(node_id)
        if kind is None:
            return None
        return dict(self._nodes[(kind, node_id)])

    def node_ids(self, kind):
        """Sorted node ids of one kind (closed vocabulary enforced)."""
        if kind not in NODE_KINDS:
            raise GraphError("unknown node kind %r" % (kind,))
        return sorted(nid for (k, nid) in self._nodes if k == kind)

    def out_edges(self, node_id, using_edges):
        """Sorted (edge_kind, dst_id) out-edges of a node, restricted
        to the declared edge set. Unknown node -> []. This is the
        public adjacency seam every query walks -- nothing reaches
        into the private adjacency maps."""
        _check_using_edges(using_edges)
        if node_id not in self._by_id:
            return []
        wanted = frozenset(using_edges)
        return sorted((ek, dst) for (ek, dst) in self._out[node_id]
                      if ek in wanted)

    def neighbors(self, node_id, using_edges):
        """Alias for out_edges: the neighbors of a node under the
        declared edge set (sorted (edge_kind, dst_id) pairs)."""
        return self.out_edges(node_id, using_edges)


def _check_using_edges(using_edges):
    """The usingOnly gate: every declared edge kind must be in the
    pinned allowlist, else fail CLOSED. Never silently narrows."""
    if using_edges is None:
        raise QueryError("using_edges must be declared explicitly")
    try:
        declared = tuple(using_edges)
    except TypeError:
        raise QueryError("using_edges must be an iterable of edge kinds")
    for kind in declared:
        if kind not in ALLOWLIST:
            raise QueryError(
                "edge kind %r is not in the pinned allowlist "
                "(version %d); refusing the traversal instead of "
                "silently walking a smaller edge set"
                % (kind, ALLOWLIST_VERSION))
    return declared


def reachable(graph, start_id, *, using_edges):
    """Deterministic breadth-first traversal from start_id over ONLY
    the declared edge kinds (the usingOnly discipline).

    Cycles terminate (visited set); each node is reported exactly
    once; the start node itself is excluded; results are sorted.
    Unknown start_id -> [] (missing-node queries return empty, never
    errors-as-denials). A non-allowlisted declared kind raises
    QueryError fail-closed.
    """
    import collections
    if not isinstance(graph, DecisionGraph):
        raise QueryError("graph must be a DecisionGraph")
    declared = _check_using_edges(using_edges)
    if not _is_nonempty_str(start_id):
        raise QueryError("start_id must be a non-empty string")
    if graph.node_kind(start_id) is None:
        return []
    seen = {start_id}
    queue = collections.deque([start_id])
    while queue:
        node = queue.popleft()
        for edge_kind, dst in graph.out_edges(node, declared):
            if dst not in seen:
                seen.add(dst)
                queue.append(dst)
    seen.discard(start_id)
    return sorted(seen)


def _require_using_edges(query_name, using_edges):
    if using_edges is None:
        return DEFAULT_USING_EDGES[query_name]
    return _check_using_edges(using_edges)


def decisions_using_builder(graph, builder_id, *, require_revoked=True,
                            using_edges=None):
    """Which decisions used builder X (sorted decision ids).

    With ``require_revoked=True`` (the default -- the "revoked
    builder" blast-radius question) the answer is non-empty only when
    the builder node exists AND is marked ``{"revoked": True}``; a
    live or unknown builder yields [] (no false blast radius).
    Pass ``require_revoked=False`` to list a live builder's decisions
    honestly.
    """
    if not isinstance(graph, DecisionGraph):
        raise QueryError("graph must be a DecisionGraph")
    declared = _require_using_edges("decisions_using_builder",
                                    using_edges)
    if graph.node_kind(builder_id) != "builder":
        return []
    if require_revoked:
        attrs = graph.node_attrs(builder_id) or {}
        if attrs.get("revoked") is not True:
            return []
    wanted = frozenset(declared)
    hits = []
    for nid in graph.node_ids("decision"):
        for edge_kind, dst in graph.out_edges(nid, declared):
            if edge_kind in wanted and dst == builder_id:
                hits.append(nid)
                break
    return sorted(hits)


def artifacts_emitted_under_key(graph, key_id, *, using_edges=None):
    """Which artifacts were emitted under key K (sorted artifact ids).

    Two fixed, declared paths: (a) a decision bound to K by a
    ``decision/attested-by`` edge that emitted the artifact; (b) an
    artifact directly attested by K (``artifact/attested-by``). The
    attestation edge KIND is pinned, not just the edge target: a
    narrower declared edge set can never silently promote some other
    edge kind into an attestation. Unknown key -> [].
    """
    if not isinstance(graph, DecisionGraph):
        raise QueryError("graph must be a DecisionGraph")
    declared = _require_using_edges("artifacts_emitted_under_key",
                                    using_edges)
    if graph.node_kind(key_id) != "key":
        return []
    wanted = frozenset(declared)
    hits = set()
    for nid in graph.node_ids("decision"):
        edges = graph.out_edges(nid, declared)
        attested = any(ek == "decision/attested-by" and ek in wanted
                       and dst == key_id for ek, dst in edges)
        if attested:
            for ek, dst in edges:
                if ek == "decision/emitted" and ek in wanted:
                    hits.add(dst)
    for nid in graph.node_ids("artifact"):
        if any(ek == "artifact/attested-by" and ek in wanted
               and dst == key_id
               for ek, dst in graph.out_edges(nid, declared)):
            hits.add(nid)
    # Only artifacts may be reported (a mislabeled edge is a build
    # bug, not a query result).
    return sorted(a for a in hits if graph.node_kind(a) == "artifact")


def promotions_depending_on_verdict(graph, verdict_id, *, using_edges=None):
    """Which promotions depend on scan verdict V (sorted promotion
    ids).

    Two fixed, declared paths: (a) the promotion directly admitted V
    (promotion/admitted-verdict); (b) the promotion promoted a decision
    that consumed V (promotion/promoted-decision then
    decision/consumed-verdict). Unknown verdict -> [].
    """
    if not isinstance(graph, DecisionGraph):
        raise QueryError("graph must be a DecisionGraph")
    declared = _require_using_edges("promotions_depending_on_verdict",
                                    using_edges)
    if graph.node_kind(verdict_id) != "scan_verdict":
        return []
    wanted = frozenset(declared)
    consumed_by = set()
    for nid in graph.node_ids("decision"):
        if any(ek == "decision/consumed-verdict" and ek in wanted
               and dst == verdict_id
               for ek, dst in graph.out_edges(nid, declared)):
            consumed_by.add(nid)
    hits = set()
    for nid in graph.node_ids("promotion"):
        for ek, dst in graph.out_edges(nid, declared):
            if ek not in wanted:
                continue
            if ek == "promotion/admitted-verdict" and dst == verdict_id:
                hits.add(nid)
                break
            if (ek == "promotion/promoted-decision"
                    and dst in consumed_by):
                hits.add(nid)
                break
    return sorted(hits)


def _report_decisions_using_builder(graph, params, using_edges):
    if "builder_id" not in params:
        raise QueryError("params missing required key 'builder_id'")
    return decisions_using_builder(
        graph, params["builder_id"],
        require_revoked=params.get("require_revoked", True),
        using_edges=using_edges)


def _report_artifacts_emitted_under_key(graph, params, using_edges):
    if "key_id" not in params:
        raise QueryError("params missing required key 'key_id'")
    return artifacts_emitted_under_key(
        graph, params["key_id"], using_edges=using_edges)


def _report_promotions_depending_on_verdict(graph, params, using_edges):
    if "verdict_id" not in params:
        raise QueryError("params missing required key 'verdict_id'")
    return promotions_depending_on_verdict(
        graph, params["verdict_id"], using_edges=using_edges)


#: Report dispatch registry -- one branch per query name, so the
#: branch count cannot drift as queries are added.
_REPORT_DISPATCH = {
    "decisions_using_builder": _report_decisions_using_builder,
    "artifacts_emitted_under_key": _report_artifacts_emitted_under_key,
    "promotions_depending_on_verdict":
        _report_promotions_depending_on_verdict,
}


def query_report(graph, query_name, params):
    """Run a headline query and bind the answer as an evidence
    report: query name, params, the declared using-edges, the pinned
    allowlist version+digest, and the sorted results. Deterministic:
    the same inputs always produce the identical report.

    The required param key for the query must be PRESENT (a missing
    key is a caller bug and raises QueryError -- a digest-bound report
    must never silently exonerate on a typo). An unknown node id still
    yields an empty results list, per the missing-node honest
    boundary.
    """
    if query_name not in _QUERY_NAMES:
        raise QueryError("unknown query %r; must be one of %s"
                         % (query_name, sorted(_QUERY_NAMES)))
    if not isinstance(params, dict):
        raise QueryError("params must be a dict")
    using_edges = DEFAULT_USING_EDGES[query_name]
    results = _REPORT_DISPATCH[query_name](graph, params, using_edges)
    return {
        "query": query_name,
        "params": dict(params),
        "using_edges": list(using_edges),
        "allowlist_version": ALLOWLIST_VERSION,
        "allowlist_digest": allowlist_digest(),
        "results": results,
    }


def report_digest(report):
    """sha256 over the canonical report -- the tamper-evident binding
    of one blast-radius answer."""
    if not isinstance(report, dict):
        raise QueryError("report must be a dict")
    return hashlib.sha256(_canonical(report)).hexdigest()


def add_decision_bom(graph, bom, *, builder_id=None, signing_key_ids=(),
                      scan_verdict_ids=(), emitted_artifact_ids=(),
                      node_attrs=None):
    """Bind one Decision BOM into the graph (the honest BOM bridge).

    The decision node id is ``bom_digest(bom)`` -- the BOM's own
    tamper-evident binding -- so the graph references the exact BOM
    bytes, never a caller-supplied label. Optional evidence ids wire
    allowlisted edges: builder_id -> decision/used-builder,
    signing_key_ids -> decision/attested-by, scan_verdict_ids ->
    decision/consumed-verdict, emitted_artifact_ids ->
    decision/emitted. Referenced evidence nodes must already exist in
    the graph (no dangling edges); the caller admits them from
    verified artifacts first -- admission of evidence is
    caller-owned, documented in the module header. (The BOM's C2PA
    ``root_ingredient_digests`` name the artifact's direct parents,
    not the emitted artifact itself, so the caller supplies the
    emitted artifact ids from the promotion/seal record -- the module
    does not invent them.)

    Raises GraphError (fail-closed) on a malformed BOM or a missing
    referenced node. Does NOT change BOM emission semantics: this is
    the read-only query layer's ingestion seam, not a BOM seam.
    """
    from gov import decision_bom as _bom
    if not isinstance(graph, DecisionGraph):
        raise GraphError("graph must be a DecisionGraph")
    ok, reason = _bom.check_bom_shape(bom)
    if not ok:
        raise GraphError("bom failed shape check: %s" % (reason,))
    decision_id = "decision:%s" % _bom.bom_digest(bom)
    graph.add_node("decision", decision_id, node_attrs)
    if builder_id is not None:
        graph.add_edge(decision_id, builder_id, "decision/used-builder")
    for key_id in signing_key_ids:
        graph.add_edge(decision_id, key_id, "decision/attested-by")
    for verdict_id in scan_verdict_ids:
        graph.add_edge(decision_id, verdict_id,
                       "decision/consumed-verdict")
    for artifact_id in emitted_artifact_ids:
        graph.add_edge(decision_id, artifact_id, "decision/emitted")
    return decision_id
