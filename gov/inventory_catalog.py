"""Declarative agent/tool/skill inventory catalog.

Backstage (Apache-2.0) pattern adaptation -- pattern only, no code reuse:
a software catalog of declared entries (``agent`` / ``tool`` / ``skill``)
with ownership and typed relationships, composed with posture scorecards
(``gov.posture_cards`` public seam) and the deployment's grant graph.

Fail-closed load: unresolvable relationship targets, duplicate names,
malformed shapes, and non-dict scorecards are refused with dedicated
machine codes; nothing is silently accepted. Grant-type relationships
are checked against a deployment-supplied grants provider; the keto
grant graph seam is deployment-owned, so a missing provider refuses
``inventory-catalog-seam-unavailable`` instead of assuming grants.

Stdlib only.
"""

import copy

from gov import posture_cards

KINDS = ("agent", "tool", "skill")
REL_TYPES = ("uses", "owns", "grant")

CARD_MALFORMED = "inventory-catalog-card-malformed"
DANGLING_REFERENCE = "inventory-catalog-dangling-reference"
DUPLICATE_ENTRY = "inventory-catalog-duplicate-entry"
ENTRY_MALFORMED = "inventory-catalog-entry-malformed"
GRANT_UNRESOLVED = "inventory-catalog-grant-unresolved"
SEAM_UNAVAILABLE = "inventory-catalog-seam-unavailable"
UNKNOWN_ENTRY = "inventory-catalog-unknown-entry"


class CatalogError(Exception):
    """Base error for the inventory catalog."""


class CatalogRefused(CatalogError):
    """Fail-closed refusal. ``code`` is a decision-codes machine code."""

    def __init__(self, code, detail):
        super(CatalogRefused, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise CatalogRefused(code, detail)


def _nonempty_str(value, field):
    return isinstance(value, str) and bool(value.strip())


def _check_entry(raw):
    """Validate one declarative entry; return a normalized copy."""
    if not isinstance(raw, dict):
        _refuse(ENTRY_MALFORMED,
                "entry must be a dict, got %s" % type(raw).__name__)
    kind = raw.get("kind")
    name = raw.get("name")
    owner = raw.get("owner")
    if kind not in KINDS:
        _refuse(ENTRY_MALFORMED,
                "entry kind must be one of %s, got %r"
                % (", ".join(KINDS), kind))
    if not _nonempty_str(name, "name"):
        _refuse(ENTRY_MALFORMED, "entry name must be a non-empty string")
    if not _nonempty_str(owner, "owner"):
        _refuse(ENTRY_MALFORMED, "entry owner must be a non-empty string")
    rels = raw.get("relationships", [])
    if not isinstance(rels, list):
        _refuse(ENTRY_MALFORMED,
                "relationships must be a list, got %s"
                % type(rels).__name__)
    checked = []
    for rel in rels:
        if not isinstance(rel, dict):
            _refuse(ENTRY_MALFORMED,
                    "relationship must be a dict, got %s"
                    % type(rel).__name__)
        to = rel.get("to")
        rtype = rel.get("type")
        if not _nonempty_str(to, "to"):
            _refuse(ENTRY_MALFORMED,
                    "relationship 'to' must be a non-empty string")
        if rtype not in REL_TYPES:
            _refuse(ENTRY_MALFORMED,
                    "relationship type must be one of %s, got %r"
                    % (", ".join(REL_TYPES), rtype))
        checked.append({"to": to, "type": rtype})
    return {"kind": kind, "name": name, "owner": owner,
            "relationships": checked}


class Catalog(object):
    """An immutable snapshot of declared catalog entries.

    Built only via ``load_catalog`` (which refuses fail-closed) and
    ``attach_scorecard`` / ``attach_owner_attribution`` (which return
    new Catalogs). All readers return deep copies; caller mutation
    can never corrupt state.
    """

    def __init__(self, entries, scorecards=None, owner_attributions=None):
        self._entries = entries          # name -> normalized entry
        self._scorecards = scorecards or {}  # name -> card list
        # name -> OwnershipAttribution dict (gov/ownership_inference):
        # the EVIDENCE-BACKED inferred owner, distinct from the entry's
        # DECLARED owner field. An auditor compares the two via
        # declared_vs_inferred_owner().
        self._owner_attributions = owner_attributions or {}

    def names(self):
        return sorted(self._entries)


def load_catalog(entries):
    """Load and validate a declarative catalog.

    Every relationship target must resolve to a declared entry name;
    unresolvable references refuse ``inventory-catalog-dangling-
    reference``. Duplicate names and malformed shapes refuse as well.
    """
    if not isinstance(entries, list):
        _refuse(ENTRY_MALFORMED,
                "catalog must be a list of entries, got %s"
                % type(entries).__name__)
    normalized = [_check_entry(e) for e in entries]
    by_name = {}
    for entry in normalized:
        if entry["name"] in by_name:
            _refuse(DUPLICATE_ENTRY,
                    "duplicate catalog entry %r" % (entry["name"],))
        by_name[entry["name"]] = entry
    for entry in normalized:
        for rel in entry["relationships"]:
            if rel["to"] not in by_name:
                _refuse(DANGLING_REFERENCE,
                        "%r references unresolvable entry %r"
                        % (entry["name"], rel["to"]))
    return Catalog(copy.deepcopy(by_name))


def entry_of(catalog, name):
    """Return a copy of the entry named ``name``."""
    _require_catalog(catalog)
    try:
        return copy.deepcopy(catalog._entries[name])
    except KeyError:
        _refuse(UNKNOWN_ENTRY, "no catalog entry named %r" % (name,))


def attach_scorecard(catalog, name, cards):
    """Attach posture cards to an entry; returns a NEW Catalog.

    Cards are validated at the posture_cards public seam: they must be
    a list of dicts (``inventory-catalog-card-malformed`` otherwise),
    the same class the F215 closure guards.
    """
    _require_catalog(catalog)
    if name not in catalog._entries:
        _refuse(UNKNOWN_ENTRY, "no catalog entry named %r" % (name,))
    if not isinstance(cards, list) or not all(
            isinstance(c, dict) for c in cards):
        _refuse(CARD_MALFORMED,
                "scorecard cards must be a list of dicts, got %s"
                % type(cards).__name__)
    new_scorecards = copy.deepcopy(catalog._scorecards)
    new_scorecards[name] = copy.deepcopy(cards)
    return Catalog(copy.deepcopy(catalog._entries), new_scorecards,
                   copy.deepcopy(catalog._owner_attributions))


def attach_owner_attribution(catalog, name, attribution):
    """Attach an evidence-backed owner attribution to an agent entry.

    ``attribution`` is an OwnershipAttribution dict produced by
    ``gov/ownership_inference.infer_owner`` /
    ``attribute_owner``; it is re-validated at the seam here
    (``check_attribution_value`` -- compare-don't-trust, a
    caller-supplied dict is never trusted) and must name an owner
    for an *agent*-kind entry. An attribution for a non-agent entry
    refuses ``inventory-catalog-entry-malformed`` -- ownership
    inference is an agent-identity primitive.

    Returns a NEW Catalog (immutable-snapshot pattern). The entry's
    DECLARED ``owner`` field is untouched: declared and inferred
    owners are compared via ``declared_vs_inferred_owner`` so an
    auditor always sees both.
    """
    from . import ownership_inference as _oi
    _require_catalog(catalog)
    if name not in catalog._entries:
        _refuse(UNKNOWN_ENTRY, "no catalog entry named %r" % (name,))
    if catalog._entries[name]["kind"] != "agent":
        _refuse(ENTRY_MALFORMED,
                "owner attributions attach only to agent entries; "
                "%r is a %s" % (name,
                                catalog._entries[name]["kind"]))
    ok, reason = _oi.check_attribution_value(attribution)
    if not ok:
        _refuse(ENTRY_MALFORMED,
                "owner attribution failed validation: %s" % reason)
    new_attributions = copy.deepcopy(catalog._owner_attributions)
    new_attributions[name] = copy.deepcopy(attribution)
    return Catalog(copy.deepcopy(catalog._entries),
                   copy.deepcopy(catalog._scorecards),
                   new_attributions)


def owner_attribution_of(catalog, name):
    """Return a copy of the attached owner attribution, or None when
    no attribution has been attached to the entry."""
    _require_catalog(catalog)
    if name not in catalog._entries:
        _refuse(UNKNOWN_ENTRY, "no catalog entry named %r" % (name,))
    return copy.deepcopy(catalog._owner_attributions.get(name))


def declared_vs_inferred_owner(catalog, name):
    """Compare the entry's DECLARED owner with its INFERRED owner.

    Returns ``{"declared": ..., "inferred": ..., "attribution": ...,
    "verdict": ...}`` where verdict is one of:

    * ``"no-attribution"`` -- no owner attribution has been attached
      (the comparison cannot be made; explicit, never silent);
    * ``"declared-matches-inferred"``;
    * ``"declared-differs-inferred"`` -- the declared owner disagrees
      with the evidence-backed inference (principal-spoofing signal);
    * ``"owner-unresolved"`` -- the attribution itself is an explicit
      coded unresolved (see the attribution's ``code``).

    The attribution's own ``declared_consistency`` field carries the
    same comparison as computed at inference time; this function
    re-derives it against the CURRENT declared owner so a catalog
    edit after inference is still caught.
    """
    _require_catalog(catalog)
    if name not in catalog._entries:
        _refuse(UNKNOWN_ENTRY, "no catalog entry named %r" % (name,))
    entry = catalog._entries[name]
    attribution = catalog._owner_attributions.get(name)
    if attribution is None:
        return {"declared": entry["owner"], "inferred": None,
                "attribution": None, "verdict": "no-attribution"}
    inferred = attribution.get("owner")
    if inferred is None:
        verdict = "owner-unresolved"
    elif inferred == entry["owner"]:
        verdict = "declared-matches-inferred"
    else:
        verdict = "declared-differs-inferred"
    return {"declared": entry["owner"], "inferred": inferred,
            "attribution": copy.deepcopy(attribution),
            "verdict": verdict}


def report(catalog, name):
    """Entry plus its posture scorecard track levels.

    Track levels are computed through the ``posture_cards.track_level``
    public seam, which re-validates the card shapes. No scorecard
    attached -> ``scorecard`` is None.
    """
    _require_catalog(catalog)
    if name not in catalog._entries:
        _refuse(UNKNOWN_ENTRY, "no catalog entry named %r" % (name,))
    cards = catalog._scorecards.get(name)
    scorecard = None
    if cards is not None:
        scorecard = {track: posture_cards.track_level(cards, track)
                     for track in posture_cards.TRACKS}
    return {"entry": copy.deepcopy(catalog._entries[name]),
            "scorecard": scorecard}


def grant_edges(catalog, grants_provider=None):
    """Resolve ``grant``-type relationships against the grants seam.

    ``grants_provider`` is deployment-supplied: a callable taking
    ``(agent_name, tool_name)`` and returning truthy when the grant is
    confirmed, or a mapping keyed by ``(agent_name, tool_name)`` pairs.
    The keto grant graph seam is deployment-owned; a missing provider
    refuses ``inventory-catalog-seam-unavailable`` fail-closed instead
    of assuming any grant. An unconfirmed grant refuses
    ``inventory-catalog-grant-unresolved``.

    Returns the list of confirmed ``(agent_name, tool_name)`` edges,
    sorted for determinism.
    """
    _require_catalog(catalog)
    if grants_provider is None:
        _refuse(SEAM_UNAVAILABLE,
                "grant relationships require a deployment-supplied "
                "grants provider; the keto grant graph seam is "
                "unavailable")
    if callable(grants_provider):
        confirmed = grants_provider
    else:
        confirmed = lambda a, t: grants_provider.get((a, t), False)
    edges = []
    for name in sorted(catalog._entries):
        entry = catalog._entries[name]
        for rel in entry["relationships"]:
            if rel["type"] != "grant":
                continue
            agent = name if entry["kind"] == "agent" else None
            tool = rel["to"]
            if agent is None:
                _refuse(ENTRY_MALFORMED,
                        "grant relationships must originate from an "
                        "agent entry; %r is a %s"
                        % (name, entry["kind"]))
            try:
                ok = confirmed(agent, tool)
            except Exception as exc:
                _refuse(GRANT_UNRESOLVED,
                        "grants provider failed for (%r, %r): %s"
                        % (agent, tool, exc))
            if not ok:
                _refuse(GRANT_UNRESOLVED,
                        "grant (%r, %r) not confirmed by grants provider"
                        % (agent, tool))
            edges.append((agent, tool))
    return edges


def is_registered_name(catalog, name):
    """Predicate: is ``name`` a declared catalog entry?

    Feeds the 2026-09-23 discovery/inventory stream: the deployment
    wires this (over its own candidate-view -> name mapping) into
    ``gov.discovery.unregistered_candidates``'s ``is_registered`` hook,
    so scan-discovered candidates diff against the declared catalog
    instead of an ad-hoc list.
    """
    _require_catalog(catalog)
    return name in catalog._entries


def _require_catalog(catalog):
    if not isinstance(catalog, Catalog):
        _refuse(ENTRY_MALFORMED,
                "expected a Catalog, got %s" % type(catalog).__name__)
