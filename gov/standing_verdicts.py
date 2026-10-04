"""Standing-verdict store for skill/bundle supply-chain trust (GUAC CertifyBad ADAPT).

Wave-325 prospectus verdict #3: GUAC lets new *knowledge* attach to
*existing* artifact nodes -- ``CertifyBad`` ("this package should not be
used", with justification, origin, collector, knownSince). The artifact's
digest never changes; its *standing* flips as knowledge arrives.

This module is the standing layer that ``gov/advisory_binding.py`` (advisory
*input* binding) does not provide:

- per-artifact current verdict: ``trusted`` / ``quarantined`` / ``revoked``,
  keyed by artifact digest (``sha256:<64hex>``);
- an append-only journal: new knowledge ATTACHES, never rewrites history;
- standing flips are journaled with mandatory provenance
  (origin, collector, known_since) and a justification;
- conflicting advisories resolve newest-wins by ``known_since`` with the
  conflict itself journaled -- never silent;
- blast-radius queries: which artifacts share a compromised
  origin/collector.

The store is a *consumer* of ``gov/advisory_binding.py`` in the
architectural sense: advisories arrive already input-bound (see
``gov/knowledge_ingest.py``, which authenticates them against the feed key
using the same JSON canonicalization discipline); this module decides what
they do to standings. Mechanically the store does not import
``advisory_binding`` -- it trusts only its journal file and requires its
callers to authenticate knowledge first (the precondition is stated on
``attach_knowledge``). It never weakens the input-binding layer.

Trust model: the journal file is trusted local state (single writer). The
*contents* are only as trustworthy as the knowledge attached to them -- every
standing change cites its knowledge entry, and ``standing_of`` returns the
full justification chain so an auditor can re-derive every verdict.

Fail-closed rules:
- unknown artifact digest (never registered) -> knowledge is recorded as
  UNATTACHED; it never creates a standing;
- a standing flip without a justification -> refused
  ``supplychain-standing-flip-unjustified``;
- ``supersedes`` pointing anywhere but the current tip (or the tip's
  parent seq, i.e. a concurrent write from the same parent) -> refused
  ``supplychain-standing-history-rewrite``;
- concurrent writes (same parent, different asserted standing) resolve
  newest-wins by ``known_since``; an exact tie is refused loudly
  ``supplychain-standing-conflict`` (genuinely ambiguous -- a human decides).

Stdlib only. No network. Deterministic.
"""

import json
import os
import re

STANDINGS = ("trusted", "quarantined", "revoked")

_UNKNOWN = "unknown"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_KIND_REGISTER = "register"
_KIND_KNOWLEDGE = "knowledge"
_KIND_CONFLICT = "conflict"
_KIND_UNATTACHED = "unattached"


class StandingError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(StandingError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise StandingError(code, detail)


def _check_digest(digest):
    if isinstance(digest, bool) or not isinstance(digest, str) \
            or not _DIGEST_RE.match(digest):
        _refuse("supplychain-malformed",
                "artifact digest must be sha256:<64 hex>, got %r" % (digest,))
    return digest


def _check_standing(standing):
    if standing not in STANDINGS:
        _refuse("supplychain-malformed",
                "standing must be one of %s, got %r"
                % ("/".join(STANDINGS), standing))
    return standing


def _check_str(value, name, allow_empty=False):
    if isinstance(value, bool) or not isinstance(value, str):
        _refuse("supplychain-malformed", "%s must be a str" % name)
    if not allow_empty and not value:
        _refuse("supplychain-malformed",
                "%s must be a non-empty str" % name)
    return value


def _check_known_since(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _refuse("supplychain-malformed",
                "known_since must be a non-negative int")
    return value


def _check_seq(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _refuse("supplychain-malformed",
                "%s must be a non-negative int" % name)
    return value


def _check_knowledge(knowledge):
    """Validate a knowledge record's shape. Returns a normalized dict."""
    if not isinstance(knowledge, dict):
        _refuse("supplychain-malformed", "knowledge must be a dict")
    digest = _check_digest(knowledge.get("artifact_digest"))
    standing = _check_standing(knowledge.get("asserted_standing"))
    justification = _check_str(knowledge.get("justification", ""),
                               "justification", allow_empty=True)
    origin = _check_str(knowledge.get("origin"), "origin")
    collector = _check_str(knowledge.get("collector"), "collector")
    known_since = _check_known_since(knowledge.get("known_since"))
    supersedes = knowledge.get("supersedes")
    if supersedes is not None:
        _check_seq(supersedes, "supersedes")
    # advisory_id is the ingest layer's citation for WHICH advisory
    # produced this knowledge; the store preserves it in the journal so
    # the audit trail can cite the source document. Optional for direct
    # store callers, always present via gov/knowledge_ingest.py.
    advisory_id = knowledge.get("advisory_id")
    if advisory_id is not None:
        _check_str(advisory_id, "advisory_id")
    affected = knowledge.get("affected_packages")
    if affected is not None:
        if (not isinstance(affected, list) or not affected
                or any(isinstance(p, bool) or not isinstance(p, str)
                       or not p for p in affected)):
            _refuse("supplychain-malformed",
                    "affected_packages must be a non-empty list of str")
    return {
        "artifact_digest": digest,
        "asserted_standing": standing,
        "justification": justification,
        "origin": origin,
        "collector": collector,
        "known_since": known_since,
        "supersedes": supersedes,
        "advisory_id": advisory_id,
        "affected_packages": affected,
    }


class StandingStore(object):
    """Append-only standing-verdict store backed by a JSON-lines journal."""

    def __init__(self, path):
        self._path = path
        self._entries = []          # every journal entry, in seq order
        self._inventory = set()     # registered artifact digests
        self._tips = {}             # digest -> seq of current tip knowledge
        self._by_seq = {}           # seq -> entry
        self._next_seq = 0
        self._load()

    # -- journal ------------------------------------------------------

    def _load(self):
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    _refuse("supplychain-malformed",
                            "journal line %d is not JSON" % lineno)
                self._replay(entry)

    def _replay(self, entry):
        if not isinstance(entry, dict):
            _refuse("supplychain-malformed", "journal entry must be a dict")
        seq = entry.get("seq")
        _check_seq(seq, "seq")
        if seq != self._next_seq:
            _refuse("supplychain-malformed",
                    "journal seq gap or reorder: want %d, got %r"
                    % (self._next_seq, seq))
        kind = entry.get("kind")
        if kind == _KIND_REGISTER:
            self._inventory.add(_check_digest(entry.get("artifact_digest")))
        elif kind in (_KIND_KNOWLEDGE, _KIND_CONFLICT):
            if kind == _KIND_KNOWLEDGE:
                # Cheap fail-closed hardening: a tampered journal that
                # smuggles a malformed knowledge payload refuses loudly on
                # load instead of poisoning the index.
                _check_knowledge(entry)
            self._tips[_check_digest(entry.get("artifact_digest"))] = seq
        elif kind == _KIND_UNATTACHED:
            pass  # recorded, never a standing
        else:
            _refuse("supplychain-malformed",
                    "unknown journal kind %r" % (kind,))
        self._entries.append(entry)
        self._by_seq[seq] = entry
        self._next_seq = seq + 1

    def _append(self, entry):
        entry = dict(entry)
        entry["seq"] = self._next_seq
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True) + "\n"
        # Single-writer append, fsync'd for durability.
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        self._replay(entry)
        return dict(entry)

    # -- inventory ----------------------------------------------------

    def register_artifact(self, digest, source):
        """Register an artifact digest in the standing inventory.

        ``source`` names where the artifact came from (e.g. the installed
        skill inventory). Re-registering is idempotent in effect but is
        still journaled, so the audit trail shows every registration.
        """
        _check_digest(digest)
        _check_str(source, "source")
        return self._append({
            "kind": _KIND_REGISTER,
            "artifact_digest": digest,
            "source": source,
        })

    def is_registered(self, digest):
        return digest in self._inventory

    # -- knowledge ----------------------------------------------------

    def attach_knowledge(self, knowledge):
        """Attach a knowledge record; returns the journal entry.

        AUTHENTICATION PRECONDITION: knowledge must be authenticated
        BEFORE it reaches this method. The supported path is
        ``gov/knowledge_ingest.py::ingest_file``, which verifies the
        Ed25519 feed signature over the canonical advisory bytes; this
        method performs NO signature verification itself. Feeding it
        unsigned knowledge is a caller bug, not a supported flow.

        For a registered artifact this may set the initial standing or flip
        it (flip requires a non-blank justification). For an unregistered
        digest the knowledge is recorded as UNATTACHED and never creates a
        standing. Concurrent writes (same parent as the current tip,
        different asserted standing) resolve newest-wins by ``known_since``
        with the conflict journaled; an exact ``known_since`` tie is
        refused loudly.
        """
        k = _check_knowledge(knowledge)
        digest = k["artifact_digest"]

        if digest not in self._inventory:
            return self._append({
                "kind": _KIND_UNATTACHED,
                "code": "supplychain-standing-knowledge-unattached",
                "artifact_digest": digest,
                "asserted_standing": k["asserted_standing"],
                "justification": k["justification"],
                "origin": k["origin"],
                "collector": k["collector"],
                "known_since": k["known_since"],
                "advisory_id": k["advisory_id"],
                "affected_packages": k["affected_packages"],
                "applied": False,
                "detail": "advisory for unknown artifact recorded as "
                          "unattached knowledge; no standing created",
            })

        tip_seq = self._tips.get(digest)
        tip = self._by_seq.get(tip_seq) if tip_seq is not None else None
        current = tip["asserted_standing"] if tip is not None else None

        is_flip = current is not None and \
            k["asserted_standing"] != current
        if is_flip and not k["justification"].strip():
            _refuse("supplychain-standing-flip-unjustified",
                    "standing flip %s -> %s for %s has no justification; "
                    "flips require origin+collector+known_since and a "
                    "non-blank justification" % (current,
                                                 k["asserted_standing"],
                                                 digest))

        supersedes = k["supersedes"]
        if tip is None:
            # First knowledge for this artifact: supersedes must be null.
            if supersedes is not None:
                _refuse("supplychain-standing-history-rewrite",
                        "first knowledge for %s must not supersede "
                        "anything, got %r" % (digest, supersedes))
            return self._append(dict(k, kind=_KIND_KNOWLEDGE))

        parent_seq = tip.get("supersedes")
        if supersedes == tip_seq:
            return self._append(dict(k, kind=_KIND_KNOWLEDGE))

        if supersedes == parent_seq:
            # Concurrent write: same parent as the tip. A different
            # verdict is a conflict (newest-wins, journaled); an
            # agreeing verdict just attaches.
            if k["asserted_standing"] != tip["asserted_standing"]:
                return self._resolve_conflict(k, tip)
            return self._append(dict(k, kind=_KIND_KNOWLEDGE))

        _refuse("supplychain-standing-history-rewrite",
                "knowledge for %s supersedes %r, but the current tip is "
                "seq %d (parent %r); knowledge must attach at the tip, "
                "never rewrite history"
                % (digest, supersedes, tip_seq, parent_seq))

    def _resolve_conflict(self, incoming, tip):
        """Newest-wins by known_since; the conflict is journaled."""
        digest = incoming["artifact_digest"]
        if incoming["known_since"] > tip["known_since"]:
            winner, loser = incoming, tip
        elif incoming["known_since"] < tip["known_since"]:
            winner, loser = tip, incoming
        else:
            _refuse("supplychain-standing-conflict",
                    "conflicting advisories for %s agree on known_since=%d "
                    "but disagree on standing (%s vs %s); unresolvable "
                    "without a human decision"
                    % (digest, incoming["known_since"],
                       tip["asserted_standing"],
                       incoming["asserted_standing"]))
        # The winner attaches at the current tip to keep the chain linear;
        # its original parent is preserved for the audit trail. The
        # conflict entry takes self._next_seq, so the winner's seq is
        # deterministically self._next_seq + 1 (single writer, no other
        # appends in between).
        winner_entry = dict(winner)
        winner_entry["original_supersedes"] = winner_entry["supersedes"]
        winner_entry["supersedes"] = tip["seq"]
        self._append({
            "kind": _KIND_CONFLICT,
            "code": "supplychain-standing-conflict",
            "artifact_digest": digest,
            "winner_seq": self._next_seq + 1,
            "winner_known_since": winner["known_since"],
            "winner_standing": winner["asserted_standing"],
            "winner_justification": winner["justification"],
            "loser_known_since": loser["known_since"],
            "loser_standing": loser["asserted_standing"],
            "loser_justification": loser["justification"],
            "loser_origin": loser["origin"],
            "loser_collector": loser["collector"],
            "detail": "concurrent advisories for %s resolved "
                      "newest-wins by known_since" % digest,
        })
        return self._append(dict(winner_entry, kind=_KIND_KNOWLEDGE))

    # -- queries ------------------------------------------------------

    def standing_of(self, digest):
        """Current standing plus the full justification chain.

        Returns ``{"digest", "standing", "chain", "tip_seq"}``. Unknown or
        unregistered digests report standing ``"unknown"`` with an empty
        chain -- never a refusal, never an invented verdict.
        """
        _check_digest(digest)
        tip_seq = self._tips.get(digest)
        if tip_seq is None:
            return {"digest": digest, "standing": _UNKNOWN,
                    "chain": [], "tip_seq": None}
        tip = self._by_seq[tip_seq]
        chain = []
        seq = tip_seq
        while seq is not None:
            entry = self._by_seq[seq]
            chain.append({
                "seq": entry["seq"],
                "asserted_standing": entry.get("asserted_standing"),
                "justification": entry.get("justification", ""),
                "origin": entry.get("origin"),
                "collector": entry.get("collector"),
                "known_since": entry.get("known_since"),
                "advisory_id": entry.get("advisory_id"),
                "kind": entry.get("kind"),
            })
            seq = entry.get("supersedes")
        chain.reverse()
        return {"digest": digest,
                "standing": tip["asserted_standing"],
                "chain": chain, "tip_seq": tip_seq}

    def blast_radius(self, origin=None, collector=None):
        """Artifact digests with knowledge citing an origin/collector.

        The incident-response primitive: "which installed artifacts does
        this compromised origin/collector touch". At least one of
        ``origin``/``collector`` must be given. Returns a sorted list.
        """
        if origin is None and collector is None:
            _refuse("supplychain-malformed",
                    "blast_radius requires origin and/or collector")
        if origin is not None:
            _check_str(origin, "origin")
        if collector is not None:
            _check_str(collector, "collector")
        hits = set()
        for entry in self._entries:
            if entry.get("kind") == _KIND_KNOWLEDGE:
                if origin is not None and entry.get("origin") != origin:
                    continue
                if collector is not None \
                        and entry.get("collector") != collector:
                    continue
                hits.add(entry["artifact_digest"])
            elif entry.get("kind") == _KIND_CONFLICT:
                # The conflict record cites the loser's provenance; a
                # blast-radius query must see losing knowledge too, with
                # the SAME and-semantics as the knowledge branch above.
                if origin is not None \
                        and entry.get("loser_origin") != origin:
                    continue
                if collector is not None \
                        and entry.get("loser_collector") != collector:
                    continue
                hits.add(entry["artifact_digest"])
        return sorted(hits)

    # -- introspection --------------------------------------------------

    def journal_entries(self):
        """Every journal entry in seq order (audit read path)."""
        return [dict(e) for e in self._entries]
