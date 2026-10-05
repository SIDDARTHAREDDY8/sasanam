"""GUAC-pattern evidence graph (wave-284 lane 5).

PATTERN LINEAGE: guacsec/guac (Apache-2.0 -- LICENSE bytes verified by
the wave-283 prospecting lane): the evidence/actor/software triad
ontology, the typed edge vocabulary (``CertifyBad`` blast-radius,
``IsOccurrence`` deployment facts), DSSE-first evidence layering
(ITE-6: signatures->actor, subject->software, predicate->action), and
the ``*Spec`` typed filter inputs. This is a clean-room stdlib
re-implementation of the *mechanisms* only; no GUAC code is vendored
here (its Go/ent stack does not fit this Python tree). GUAC's
package/vulnerability backend is deliberately dropped -- the graph here
is the queryable join for "sell evidence": which bundles about which
skill version were attested by which key.

What this adds over the wave-250 ``gov/evidence_graph.py`` aggregation
graph (which stays, untouched):

* a PINNED, closed triad ontology: node types ``evidence`` / ``actor``
  / ``software`` / ``artifact`` only;
* the GUAC edge vocabulary, shape-checked per edge (src/dst type
  signatures);
* DSSE-first ingestion: a claim enters the graph ONLY through a
  verified DSSE envelope (``gov/dsse_envelope.py``); the envelope is
  the unit of distribution, the graph node is the unit of query. The
  claim's evidence node IS the sha256 of the envelope payload;
  envelope signatures map to ``actor`` nodes (ITE-6 layer 1);
* collector-claim corroboration: ``CertifyBad`` / ``CertifyGood`` /
  ``IsOccurrence`` assertions from collectors are UNTRUSTED until
  >=2 DISTINCT actor principals sign the same claim (edge kind +
  subject; the statement's ``src`` actor must match the envelope
  signer, so no piggybacked attribution) (the act-gate quorum
  precedent). Pending claims are stored but excluded from
  blast-radius propagation. Quorum disagreement (bad vs good) is a
  loud ``guac-graph-claim-conflict`` -- the graph never picks a side;
* ``blast_radius``: the GUAC canonical query -- transitive closure
  over verified ``CertifyBad`` + ``IsDependency`` + ``IsOccurrence``
  + alias edges, deterministic and cycle-safe;
* closed ``*Spec`` filter structs: no raw string query language;
  unknown filter fields refuse ``guac-graph-bad-spec``.

Fail-closed throughout: unknown nodes refuse ``guac-graph-unlinked``,
ambiguous selectors refuse ``guac-graph-ambiguous-link``, malformed
input refuses ``guac-graph-malformed``, caps refuse
``guac-graph-overflow``, envelope parse/verify failures refuse
``guac-graph-envelope-refused``. Serialization seals
``schema_version``; the digest is order-independent.

Stdlib only. Deterministic. No env reads, no I/O, no wall clock.
"""

import hashlib
import json
import re

from gov import dsse_envelope as _dsse

#: Pinned schema version (the wave-283 trap: GUAC's schema churns;
#: ours is pinned and any drift refuses at deserialize time).
SCHEMA_VERSION = 1

#: The closed claim-statement payload type. The payload type is inside
#: the signed PAE bytes, so a claim cannot be transplanted onto a
#: different statement shape.
GUAC_STATEMENT_PAYLOAD_TYPE = "application/vnd.sasanam.guac-statement+json"

#: Corroboration quorum: distinct actor principals that must assert the
#: same collector claim before it counts (the >=2-principal act-gate
#: precedent).
CLAIM_QUORUM = 2

# Machine codes (all registered in gov/decision_codes.py TAXONOMY).
GUAC_GRAPH_AMBIGUOUS_LINK = "guac-graph-ambiguous-link"
GUAC_GRAPH_BAD_SPEC = "guac-graph-bad-spec"
GUAC_GRAPH_CLAIM_CONFLICT = "guac-graph-claim-conflict"
GUAC_GRAPH_ENVELOPE_REFUSED = "guac-graph-envelope-refused"
GUAC_GRAPH_MALFORMED = "guac-graph-malformed"
GUAC_GRAPH_OVERFLOW = "guac-graph-overflow"
GUAC_GRAPH_UNLINKED = "guac-graph-unlinked"

#: The triad ontology: closed node vocabulary.
NODE_TYPES = ("evidence", "actor", "software", "artifact")

# Edge vocabulary: kind -> (allowed src types, allowed dst types).
# ``CertifyBad``/``CertifyGood``/``IsOccurrence`` are collector CLAIM
# edges: untrusted until CLAIM_QUORUM distinct actors corroborate.
EDGE_KINDS = {
    "HasSBOM": (("software",), ("evidence",)),
    "HasSLSA": (("software",), ("evidence",)),
    "CertifyVuln": (("evidence",), ("software",)),
    "CertifyBad": (("actor",), ("software", "artifact")),
    "CertifyGood": (("actor",), ("software", "artifact")),
    "IsDependency": (("software",), ("software",)),
    "IsOccurrence": (("software",), ("artifact",)),
    "HashEqual": (("artifact",), ("artifact",)),
    "PkgEqual": (("software",), ("software",)),
    "HasSourceAt": (("software",), ("evidence",)),
    "HasMetadata": (("software",), ("evidence",)),
}

#: Collector-claim edges: corroboration-gated.
CLAIM_EDGES = frozenset({"CertifyBad", "CertifyGood", "IsOccurrence"})

#: Edges walked forward by blast_radius (blast propagation kinds).
_BLAST_KINDS = frozenset({
    "CertifyBad", "IsDependency", "IsOccurrence", "HashEqual", "PkgEqual",
})

#: Blast radius walks DEPENDENTS backward: "X depends on bad Y" is
#: stored as IsDependency(X, Y), so from Y we walk reverse edges.
#: HashEqual/PkgEqual are aliases and walk both directions.
_BLAST_REVERSE_KINDS = frozenset({"IsDependency", "HashEqual", "PkgEqual"})

# Identifier grammars per node type.
_IDENT_PATTERNS = {
    "evidence": re.compile(r"^[0-9a-f]{64}$"),          # payload digest
    "actor": re.compile(r"^[0-9a-f]{8,64}$"),          # key id
    "software": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*"
                           r"@[A-Za-z0-9][A-Za-z0-9._-]*$"),  # name@version
    "artifact": re.compile(r"^[0-9a-f]{64}$"),         # content digest
}

# Default bounds: generous for an auditor view, still finite.
DEFAULT_MAX_NODES = 10000
DEFAULT_MAX_EDGES = 100000


class GuacGraphError(Exception):
    """Base class; carries the machine ``code``."""

    code = GUAC_GRAPH_MALFORMED

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _node_id(node_type, identifier):
    if node_type not in NODE_TYPES:
        raise GuacGraphError(
            "unknown node type %r (expected one of %s)"
            % (node_type, NODE_TYPES), code=GUAC_GRAPH_MALFORMED)
    pattern = _IDENT_PATTERNS[node_type]
    if not isinstance(identifier, str) or not pattern.match(identifier):
        raise GuacGraphError(
            "%s identifier fails the %s grammar: %r"
            % (node_type, node_type, identifier),
            code=GUAC_GRAPH_MALFORMED)
    return "%s:%s" % (node_type, identifier)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


# Claim statement argument shapes: arg name -> allowed node types.
# The claim's ACTOR (the asserter) is separate from the edge args and
# is bound to the envelope signer -- a collector cannot attribute a
# claim to another actor.
_CLAIM_ARG_SHAPES = {
    "CertifyBad": (("subject", ("software", "artifact")),),
    "CertifyGood": (("subject", ("software", "artifact")),),
    "IsOccurrence": (("software", ("software",)),
                     ("artifact", ("artifact",))),
}


def _check_arg_value(name, value, allowed_types):
    if not isinstance(value, str) or ":" not in value:
        raise GuacGraphError(
            "claim arg %r must be a node id, got %r" % (name, value),
            code=GUAC_GRAPH_MALFORMED)
    vtype, ident = value.split(":", 1)
    if vtype not in allowed_types:
        raise GuacGraphError(
            "claim arg %r cannot be a %s node" % (name, vtype),
            code=GUAC_GRAPH_MALFORMED)
    _node_id(vtype, ident)  # grammar check; raises on mismatch
    return value


def make_claim_statement(actor_keyid, edge, justification="", **args):
    """Build the canonical claim-statement bytes (unsigned).

    ``actor_keyid`` is the asserting actor's key id; ``edge`` is one of
    the claim edges; ``args`` are the edge's subject arguments
    (``subject=`` for CertifyBad/CertifyGood, ``software=`` +
    ``artifact=`` for IsOccurrence). The caller seals these bytes with
    ``dsse_envelope.seal`` (or the ``seal_claim`` helper). The
    statement is a closed schema: unknown fields are refused at
    ingest.
    """
    actor = _node_id("actor", actor_keyid)
    if edge not in CLAIM_EDGES:
        raise GuacGraphError(
            "claim edge must be one of %s, got %r"
            % (sorted(CLAIM_EDGES), edge), code=GUAC_GRAPH_MALFORMED)
    if not isinstance(justification, str) or len(justification) > 2000:
        raise GuacGraphError("justification must be a str of <= 2000 chars",
                             code=GUAC_GRAPH_MALFORMED)
    shape = _CLAIM_ARG_SHAPES[edge]
    expected = {name for name, _ in shape}
    if set(args) != expected:
        raise GuacGraphError(
            "claim edge %s takes args %s, got %s"
            % (edge, sorted(expected), sorted(args)),
            code=GUAC_GRAPH_MALFORMED)
    checked = {}
    for name, allowed in shape:
        checked[name] = _check_arg_value(name, args[name], allowed)
    statement = {
        "schema_version": SCHEMA_VERSION,
        "claim": {
            "actor": actor, "edge": edge, "args": checked,
            "justification": justification,
        },
    }
    return _canonical(statement)


def seal_claim(signer, edge, justification="", **args):
    """Seal a claim statement into a DSSE envelope with ``signer``.

    ``signer`` is a ``gov.signing.Signer``; its key id becomes the
    claim's actor, and the envelope's ``keyid`` binds the assertion to
    the signer. Example::

        seal_claim(signer, "CertifyBad", "pwned", subject="software:x@1.0")
    """
    body = make_claim_statement(signer.key_id, edge, justification,
                                **args)
    return _dsse.seal(body, GUAC_STATEMENT_PAYLOAD_TYPE, [signer])


class _Spec:
    """Base for closed filter structs: unknown kwargs refuse loudly."""

    _FIELDS = frozenset()

    def __init__(self, **kwargs):
        unknown = sorted(set(kwargs) - self._FIELDS)
        if unknown:
            raise GuacGraphError(
                "%s: unknown filter field(s): %s (no raw query language)"
                % (type(self).__name__, unknown),
                code=GUAC_GRAPH_BAD_SPEC)
        for field in self._FIELDS:
            setattr(self, field, kwargs.get(field))

    def matches(self, src, kind, dst):
        raise NotImplementedError  # pragma: no cover - subclass contract


class EdgeSpec(_Spec):
    """Closed filter over edges: kind (required), optional src/dst."""

    _FIELDS = frozenset({"kind", "src", "dst"})

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.kind not in EDGE_KINDS:
            raise GuacGraphError(
                "EdgeSpec: unknown edge kind %r" % (self.kind,),
                code=GUAC_GRAPH_BAD_SPEC)

    def matches(self, src, kind, dst):
        return ((self.kind is None or kind == self.kind)
                and (self.src is None or src == self.src)
                and (self.dst is None or dst == self.dst))


class CertifyBadSpec(_Spec):
    """Closed filter for compromise claims."""

    _FIELDS = frozenset({"actor", "subject"})

    def matches(self, src, kind, dst):
        return (kind == "CertifyBad"
                and (self.actor is None or src == self.actor)
                and (self.subject is None or dst == self.subject))


class IsOccurrenceSpec(_Spec):
    """Closed filter for deployment-fact edges."""

    _FIELDS = frozenset({"software", "artifact"})

    def matches(self, src, kind, dst):
        return (kind == "IsOccurrence"
                and (self.software is None or src == self.software)
                and (self.artifact is None or dst == self.artifact))


class GuacGraph:
    """The GUAC-pattern evidence graph.

    Nodes are identity-only (``type:identifier``); edges are typed
    and shape-checked. Claim edges are corroboration-gated: a claim
    reaches ``verified`` when CLAIM_QUORUM distinct actors assert the
    same (edge, dst) claim; before that it is ``pending`` and invisible
    to ``blast_radius``.
    """

    def __init__(self, max_nodes=DEFAULT_MAX_NODES,
                 max_edges=DEFAULT_MAX_EDGES):
        self._nodes = set()
        # Structural edges: (src, kind, dst) -> record. Claim edges are
        # keyed (edge, dst) in self._claims: the claim identity is the
        # SUBJECT and the claim kind, never the asserting actor -- two
        # actors asserting "the same claim" have different srcs, so
        # keying by src would make quorum unreachable by construction.
        self._edges = {}
        self._claims = {}
        self._max_nodes = max_nodes
        self._max_edges = max_edges

    # -- nodes --------------------------------------------------------

    def add_node(self, node_type, identifier):
        node_id = _node_id(node_type, identifier)
        if node_id not in self._nodes:
            if len(self._nodes) >= self._max_nodes:
                raise GuacGraphError(
                    "node cap %d reached" % self._max_nodes,
                    code=GUAC_GRAPH_OVERFLOW)
            self._nodes.add(node_id)
        return node_id

    def node_ids(self):
        return sorted(self._nodes)

    def has_node(self, node_id):
        return node_id in self._nodes

    # -- edges --------------------------------------------------------

    def _check_edge(self, src, kind, dst):
        if kind not in EDGE_KINDS:
            raise GuacGraphError("unknown edge kind %r" % (kind,),
                                 code=GUAC_GRAPH_MALFORMED)
        for label, node_id in (("src", src), ("dst", dst)):
            if node_id not in self._nodes:
                raise GuacGraphError(
                    "edge %s %s %s: %s node %r is not in the graph"
                    % (src, kind, dst, label, node_id),
                    code=GUAC_GRAPH_UNLINKED)
        src_type = src.split(":", 1)[0]
        dst_type = dst.split(":", 1)[0]
        allowed_src, allowed_dst = EDGE_KINDS[kind]
        if src_type not in allowed_src or dst_type not in allowed_dst:
            raise GuacGraphError(
                "edge %s cannot run %s -> %s" % (kind, src_type, dst_type),
                code=GUAC_GRAPH_MALFORMED)

    def add_edge(self, src, kind, dst):
        """Add a STRUCTURAL (non-claim) edge. Claim edges must arrive
        through ``ingest_envelope`` so their corroboration is counted.
        """
        if kind in CLAIM_EDGES:
            raise GuacGraphError(
                "claim edge %s must arrive via ingest_envelope "
                "(corroboration is counted there)" % kind,
                code=GUAC_GRAPH_MALFORMED)
        self._check_edge(src, kind, dst)
        key = (src, kind, dst)
        if key not in self._edges:
            if len(self._edges) >= self._max_edges:
                raise GuacGraphError(
                    "edge cap %d reached" % self._max_edges,
                    code=GUAC_GRAPH_OVERFLOW)
            self._edges[key] = {"kind": "structural", "actors": (),
                                "status": "verified"}
        return key

    def edges_with(self, spec):
        """Return sorted ``(src, kind, dst, status)`` matching a Spec.

        Claim edges emit one row per asserting actor: ``(actor_id,
        kind, subject, status)``.
        """
        if not isinstance(spec, _Spec):
            raise GuacGraphError(
                "edges_with requires a Spec struct (no raw queries)",
                code=GUAC_GRAPH_BAD_SPEC)
        hits = []
        for (src, kind, dst), record in self._edges.items():
            if spec.matches(src, kind, dst):
                hits.append((src, kind, dst, record["status"]))
        for key, record in self._claims.items():
            kind = key[0]
            args = record["args"]
            if kind in ("CertifyBad", "CertifyGood"):
                # One row per asserting actor: (actor, kind, subject).
                for actor in record["actors"]:
                    if spec.matches(actor, kind, args["subject"]):
                        hits.append((actor, kind, args["subject"],
                                     record["status"]))
            else:  # IsOccurrence: (software, kind, artifact).
                if spec.matches(args["software"], kind, args["artifact"]):
                    hits.append((args["software"], kind, args["artifact"],
                                 record["status"]))
        return sorted(hits)

    # -- DSSE-first claim ingestion ------------------------------------

    def ingest_envelope(self, envelope, verifiers, threshold=1):
        """Ingest a claim through a verified DSSE envelope.

        The envelope is the unit of distribution: strict parse, the
        payload type is bound to the claim-statement type, and the
        envelope's signature must verify under the given verifiers.
        Exactly one actor may assert per envelope (the claim's actor
        must match the signer: no piggybacked attribution); quorum
        corroboration happens by ingesting one envelope per actor, so
        ``threshold`` is pinned at 1 and any other value is refused.
        evidence node IS the sha256 of the envelope payload; each
        verifying key id maps to an ``actor`` node (ITE-6 layering).
        Returns a claim record ``{"src","edge","dst","status",
        "actors","evidence_node"}``.
        """
        if threshold != 1:
            raise GuacGraphError(
                "ingest threshold is pinned at 1: quorum corroboration is "
                "one envelope per actor (got threshold=%r)" % (threshold,),
                code=GUAC_GRAPH_MALFORMED)
        try:
            payload, payload_type, _sigs = _dsse.parse_envelope(envelope)
        except _dsse.EnvelopeError as exc:
            raise GuacGraphError(
                "envelope parse refused: %s" % exc,
                code=GUAC_GRAPH_ENVELOPE_REFUSED) from exc
        if payload_type != GUAC_STATEMENT_PAYLOAD_TYPE:
            raise GuacGraphError(
                "envelope payloadType %r is not a claim statement"
                % (payload_type,), code=GUAC_GRAPH_ENVELOPE_REFUSED)
        try:
            statement = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise GuacGraphError(
                "claim payload is not JSON: %s" % exc,
                code=GUAC_GRAPH_ENVELOPE_REFUSED) from exc
        claim = self._parse_claim(statement)
        pae_bytes = _dsse.pae(payload_type, payload)
        actors = self._verify_claim_actors(envelope, pae_bytes, verifiers,
                                           threshold)
        return self._register_claim(claim, actors, payload)

    def _parse_claim(self, statement):
        if not isinstance(statement, dict):
            raise GuacGraphError("claim statement must be a dict",
                                 code=GUAC_GRAPH_ENVELOPE_REFUSED)
        if statement.get("schema_version") != SCHEMA_VERSION:
            raise GuacGraphError(
                "claim schema_version %r refused (pinned at %d)"
                % (statement.get("schema_version"), SCHEMA_VERSION),
                code=GUAC_GRAPH_ENVELOPE_REFUSED)
        claim = statement.get("claim")
        if not isinstance(claim, dict):
            raise GuacGraphError("claim statement has no claim object",
                                 code=GUAC_GRAPH_ENVELOPE_REFUSED)
        extra = set(statement) - {"schema_version", "claim"}
        if extra:
            raise GuacGraphError(
                "claim statement has unknown field(s): %s" % sorted(extra),
                code=GUAC_GRAPH_ENVELOPE_REFUSED)
        extra_claim = set(claim) - {"actor", "edge", "args", "justification"}
        if extra_claim:
            raise GuacGraphError(
                "claim object has unknown field(s): %s"
                % sorted(extra_claim), code=GUAC_GRAPH_ENVELOPE_REFUSED)
        actor = claim.get("actor")
        edge = claim.get("edge")
        args = claim.get("args")
        justification = claim.get("justification", "")
        if not isinstance(justification, str):
            raise GuacGraphError("claim justification must be a str",
                                 code=GUAC_GRAPH_ENVELOPE_REFUSED)
        if not isinstance(args, dict):
            raise GuacGraphError("claim args must be a dict",
                                 code=GUAC_GRAPH_ENVELOPE_REFUSED)
        # Re-run the closed constructor: it validates the actor, the
        # edge, and every argument, so a hand-crafted envelope cannot
        # smuggle a malformed claim past this point.
        body = make_claim_statement(
            actor.split(":", 1)[1] if isinstance(actor, str)
            and actor.startswith("actor:") else "",
            edge if isinstance(edge, str) else "",
            justification,
            **{k: v for k, v in args.items() if isinstance(k, str)})
        return json.loads(body.decode("utf-8"))["claim"]

    def _claim_key(self, claim):
        edge = claim["edge"]
        arg_names = sorted(claim["args"])
        return (edge,) + tuple((n, claim["args"][n]) for n in arg_names)

    def _verify_claim_actors(self, envelope, pae_bytes, verifiers,
                             threshold):
        verifiers = list(verifiers)
        if not verifiers:
            raise GuacGraphError("ingest requires at least one verifier",
                                 code=GUAC_GRAPH_ENVELOPE_REFUSED)
        _, _, parsed = _dsse.parse_envelope(envelope)
        ok_keyids = set()
        for keyid, sig in parsed:
            for verifier in verifiers:
                if keyid is not None and verifier.key_id != keyid:
                    continue
                if verifier.verify(pae_bytes, sig):
                    ok_keyids.add(verifier.key_id)
                    break
        if len(ok_keyids) < threshold:
            raise GuacGraphError(
                "claim needs %d distinct verifying keys, got %d"
                % (threshold, len(ok_keyids)),
                code=GUAC_GRAPH_ENVELOPE_REFUSED)
        return sorted(ok_keyids)

    def _register_claim(self, claim, actor_keyids, payload):
        actor, edge = claim["actor"], claim["edge"]
        # The claim's actor must BE the envelope signer(s): a collector
        # cannot sign a claim attributing it to another actor (no
        # piggybacking).
        for keyid in actor_keyids:
            if "actor:" + keyid != actor:
                raise GuacGraphError(
                    "claim actor %r does not match the envelope signer "
                    "(%r): refusing piggybacked attribution"
                    % (actor, keyid), code=GUAC_GRAPH_ENVELOPE_REFUSED)
        # Nodes materialize from validated identifiers only.
        self.add_node("actor", actor.split(":", 1)[1])
        for _name, value in claim["args"].items():
            vtype, ident = value.split(":", 1)
            self.add_node(vtype, ident)
        evidence_node = self.add_node(
            "evidence", hashlib.sha256(payload).hexdigest())
        actors = [self.add_node("actor", keyid) for keyid in actor_keyids]
        key = self._claim_key(claim)
        record = self._claims.get(key)
        if record is None:
            if len(self._edges) + len(self._claims) >= self._max_edges:
                raise GuacGraphError(
                    "edge cap %d reached" % self._max_edges,
                    code=GUAC_GRAPH_OVERFLOW)
            record = {"actors": (), "status": "pending",
                      "evidence_nodes": (), "args": dict(claim["args"])}
            self._claims[key] = record
        known = set(record["actors"]) | set(actors)
        record["actors"] = tuple(sorted(known))
        evidenced = set(record["evidence_nodes"]) | {evidence_node}
        record["evidence_nodes"] = tuple(sorted(evidenced))
        if len(known) >= CLAIM_QUORUM:
            record["status"] = "verified"
        else:
            record["status"] = "pending"
        return {"actor": actor, "edge": edge, "args": dict(claim["args"]),
                "status": record["status"], "actors": record["actors"],
                "evidence_node": evidence_node}

    def contested(self):
        """Subjects with quorum on both CertifyBad and CertifyGood."""
        bad, good = set(), set()
        for key, record in self._claims.items():
            if record.get("status") != "verified":
                continue
            if key[0] == "CertifyBad":
                bad.add(record["args"]["subject"])
            elif key[0] == "CertifyGood":
                good.add(record["args"]["subject"])
        return sorted(bad & good)

    def _bad_subjects(self):
        return {record["args"]["subject"]
                for key, record in self._claims.items()
                if key[0] == "CertifyBad"
                and record.get("status") == "verified"}

    # -- blast radius --------------------------------------------------

    def blast_radius(self, node_id):
        """The GUAC canonical query: everything within the blast
        radius of a compromised node.

        The seed must be a VERIFIED-bad subject (or an actor with
        verified CertifyBad claims): a pending claim does not
        propagate. From a bad seed, the closure walks verified edges:
        dependents (reverse IsDependency), occurrences (forward
        IsOccurrence), and alias peers (HashEqual/PkgEqual, both
        directions). Deterministic, sorted, cycle-safe. Refuses
        unlinked nodes and contested subjects. A verified-clean seed
        returns itself: nothing is in the blast radius of an
        uncompromised node except the node.
        """
        if node_id not in self._nodes:
            raise GuacGraphError("unknown node %r" % (node_id,),
                                 code=GUAC_GRAPH_UNLINKED)
        if node_id in self.contested():
            raise GuacGraphError(
                "subject %s is contested (quorum disagreement); "
                "refusing to walk" % (node_id,),
                code=GUAC_GRAPH_CLAIM_CONFLICT)
        bad_subjects = self._bad_subjects()
        seed_is_bad = node_id in bad_subjects
        seed_is_actor = node_id.split(":", 1)[0] == "actor"
        if not seed_is_bad and not seed_is_actor:
            return [node_id]
        forward = {}
        reverse = {}
        for (src, kind, dst), record in self._edges.items():
            if kind in _BLAST_KINDS:
                forward.setdefault(src, []).append((kind, dst))
            if kind in _BLAST_REVERSE_KINDS:
                reverse.setdefault(dst, []).append((kind, src))
        # Claim rows: verified claims contribute their GUAC edges.
        for key, record in self._claims.items():
            if record.get("status") != "verified":
                continue
            kind, args = key[0], record["args"]
            if kind == "CertifyBad":
                for actor in record["actors"]:
                    forward.setdefault(actor, []).append(
                        (kind, args["subject"]))
            elif kind == "IsOccurrence":
                forward.setdefault(args["software"], []).append(
                    (kind, args["artifact"]))
        seen = {node_id}
        frontier = [node_id]
        while frontier:
            current = frontier.pop()
            for _kind, nxt in forward.get(current, []):
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append(nxt)
            for _kind, nxt in reverse.get(current, []):
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append(nxt)
        return sorted(seen)

    # -- identity ------------------------------------------------------

    def serialize(self):
        edges = []
        for (src, kind, dst) in sorted(self._edges):
            record = self._edges[(src, kind, dst)]
            edges.append({
                "src": src, "kind": kind, "dst": dst,
                "status": record["status"],
                "actors": list(record["actors"]),
            })
        claims = []
        for key in sorted(self._claims):
            record = self._claims[key]
            claims.append({
                "edge": key[0],
                "args": {name: value for name, value in key[1:]},
                "status": record["status"],
                "actors": list(record["actors"]),
                "evidence_nodes": list(record["evidence_nodes"]),
            })
        return _canonical({
            "schema_version": SCHEMA_VERSION,
            "nodes": sorted(self._nodes),
            "edges": edges,
            "claims": claims,
        }).decode("utf-8")

    def digest(self):
        return hashlib.sha256(self.serialize().encode("utf-8")).hexdigest()


#: The taxonomy pin this battery asserts (kept on the module so the
#: pin assertion lives next to the code that moves it).
TAXONOMY_PIN = 2083 # Wave-326 lane 3: pin 2020 -> 2027 (+7 supplychain-scan-*/supplychain-standing-lapsed). # Wave-283 merge: pin 1579 -> 1587 (+2 finding-* +6 inventory-*); wave-284 lane 5: 1587 -> 1594 (+7 guac-graph-*).; Wave-284 merge: pin 1594 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-302 merge: pin 1706 -> 1820 (stale since wave-290, repointed at merge); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-313 merge: pin 1857 -> 1863 (+6 approval-token-* +6 plan-policy-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-321 lane 2: pin 1946 -> 1951 (+5 oci-*); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*) # Wave-334 lane 6: pin 2077 -> 2083 (+6 incident-gpai9-*).


