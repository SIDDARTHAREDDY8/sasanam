"""Posture-assessment cards + signed maturity summary (VSA-style).

ADAPT of the ossf/scorecard shape (check -> probe -> score -> reason
-> remediation cards) and the slsa-framework VSA vocabulary (track +
level summary). Pattern only: no Scorecard code is reused, and no
SLSA spec text is quoted -- the vocabulary (tracks, levels) is our
own.

HONEST LABELING (Scorecard's own non-goals say its checks are
heuristics, not a safety certification; the same applies here): these
cards are posture EVIDENCE, not a certification. A card with score 10
proves the deployment ran the check against live state, not that the
deployment is safe. The VSA-style summary is a SIGNED CLAIM about
posture; a signed claim proves the issuer signed the claim, not that
the claim is true. Treat both as inputs to an auditor's judgment,
never as verdicts.

Every card probe runs against deployment-supplied ``state`` -- a
nested dict the deployment assembles from its live modules -- never
a static claim. Missing or unreadable state fails closed: the card
records ``unavailable``, never ``pass``.

This module is distinct from :mod:`gov.posture` (signed posture
SIGNALS about revocation/denial events). Cards assess posture;
signals report events. Neither carries authority.

Stdlib only.
"""

import json
from datetime import datetime, timezone

from . import ed25519 as _ed

# ---------------------------------------------------------------------------
# Errors.
# ---------------------------------------------------------------------------

MALFORMED = "posture-card-malformed"
UNVERIFIABLE = "posture-card-unverifiable"
UNKNOWN_TRACK = "posture-card-unknown-track"


class PostureCardError(Exception):
    """Fail-closed posture-card refusal carrying a taxonomy ``code``."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _refuse(code, detail):
    raise PostureCardError("%s: %s" % (code, detail), code)


# ---------------------------------------------------------------------------
# Vocabulary.
# ---------------------------------------------------------------------------

TRACKS = ("supply-chain", "identity", "policy", "evidence", "durability")
LEVELS = ("absent", "partial", "full")

_PASS = "pass"
_FAIL = "fail"
_UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# State access helpers (fail-closed reads).
# ---------------------------------------------------------------------------

_MISSING = object()


def _get(state, *path):
    """Nested dict lookup; returns _MISSING on any absent/non-dict hop."""
    node = state
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return _MISSING
        node = node[key]
    return node


def _is_hex64(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return False
    return len(raw) == 32 and value == value.lower()


def _is_hex128(value):
    if not isinstance(value, str) or len(value) != 128:
        return False
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return False
    return len(raw) == 64 and value == value.lower()


def _is_iso_z(value):
    """Fixed-shape UTC timestamp ``YYYY-MM-DDTHH:MM:SSZ``; lexicographic
    comparison is chronological for this shape."""
    if not isinstance(value, str) or len(value) != 20:
        return False
    if value[4] != "-" or value[7] != "-" or value[10] != "T":
        return False
    if value[13] != ":" or value[16] != ":" or value[19] != "Z":
        return False
    return value[:19].replace("-", "").replace(":", "").replace(
        "T", "").isdigit()


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _card(check, track, probe, score, reason, remediation):
    return {
        "check": check,
        "track": track,
        "probe": probe,
        "score": score,
        "reason": reason,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# Card probes. Each takes the deployment state and returns a card.
# ---------------------------------------------------------------------------

def _probe_skill_admission(state):
    section = _get(state, "skill_admission")
    if section is _MISSING:
        return _card("skill-admission-configured", "supply-chain",
                     _UNAVAILABLE, 0,
                     "skill_admission state absent; cannot assess",
                     "provide skill_admission.authority_pub and "
                     "admitted_layouts in the assessment state")
    pub = _get(section, "authority_pub")
    if not _is_hex64(pub):
        return _card("skill-admission-configured", "supply-chain",
                     _FAIL, 0,
                     "no valid skill-admission authority key configured",
                     "configure a 32-byte Ed25519 authority key for "
                     "skill admission (gov.skill_admission)")
    layouts = _get(section, "admitted_layouts")
    if not isinstance(layouts, int) or isinstance(layouts, bool) \
            or layouts < 1:
        return _card("skill-admission-configured", "supply-chain",
                     _FAIL, 0,
                     "authority configured but no layouts admitted",
                     "admit at least one signed skill layout before "
                     "relying on admission")
    return _card("skill-admission-configured", "supply-chain",
                 _PASS, 10,
                 "%d layout(s) admitted under a configured authority" %
                 layouts,
                 "none")


def _probe_tuf_pins(state):
    assessed = _get(state, "assessed_at")
    pin = _get(state, "skill_update", "pin")
    if pin is _MISSING or assessed is _MISSING:
        return _card("tuf-pins-fresh", "supply-chain",
                     _UNAVAILABLE, 0,
                     "skill_update pin or assessed_at absent; cannot "
                     "assess freshness",
                     "provide skill_update.pin.not_after and assessed_at "
                     "in the assessment state")
    expiry = _get(pin, "not_after")
    if not _is_iso_z(expiry) or not _is_iso_z(assessed):
        return _card("tuf-pins-fresh", "supply-chain",
                     _FAIL, 0,
                     "pin expiry or assessment time is not a valid "
                     "UTC timestamp; treated as stale",
                     "record pin not_after as YYYY-MM-DDTHH:MM:SSZ")
    if expiry <= assessed:
        return _card("tuf-pins-fresh", "supply-chain",
                     _FAIL, 0,
                     "skill-update pin expired at %s" % expiry,
                     "refresh the TUF-style pin via "
                     "gov.skill_update.pin_from_refresher")
    return _card("tuf-pins-fresh", "supply-chain",
                 _PASS, 10,
                 "skill-update pin fresh until %s" % expiry,
                 "none")


def _probe_federated_identity(state):
    section = _get(state, "agent_identity")
    if section is _MISSING:
        return _card("federated-identity-configured", "identity",
                     _UNAVAILABLE, 0,
                     "agent_identity state absent; cannot assess",
                     "provide agent_identity.connector and "
                     "subject_source in the assessment state")
    connector = _get(section, "connector")
    source = _get(section, "subject_source")
    if connector not in ("oidc", "static"):
        return _card("federated-identity-configured", "identity",
                     _FAIL, 0,
                     "no supported identity connector configured",
                     "configure an oidc or static connector via "
                     "gov.agent_identity (SAML is unsupported)")
    if not isinstance(source, str) or not source:
        return _card("federated-identity-configured", "identity",
                     _FAIL, 0,
                     "identity subject source not declared",
                     "declare subject_source for claim normalization")
    return _card("federated-identity-configured", "identity",
                 _PASS, 10,
                 "federated identity via %s connector" % connector,
                 "none")


def _probe_combiner(state):
    active = _get(state, "policy", "combiner_active")
    if active is _MISSING:
        return _card("combiner-active", "policy",
                     _UNAVAILABLE, 0,
                     "policy.combiner_active absent; cannot assess",
                     "declare whether gov.policy_combine is in the "
                     "verdict path")
    if active is not True:
        return _card("combiner-active", "policy",
                     _FAIL, 0,
                     "forbid-overrides-permit combiner not active in "
                     "the verdict path",
                     "wire gov.policy_combine into the executor "
                     "policy_set")
    return _card("combiner-active", "policy",
                 _PASS, 10,
                 "cross-policy-set decisions combined with "
                 "forbid-overrides-permit",
                 "none")


def _probe_decision_log(state):
    root = _get(state, "policy", "decision_log", "root")
    if root is _MISSING:
        return _card("decision-log-running", "policy",
                     _UNAVAILABLE, 0,
                     "policy.decision_log.root absent; cannot assess",
                     "report the RFC 6962 decision-log tree root")
    if not _is_hex64(root):
        return _card("decision-log-running", "policy",
                     _FAIL, 0,
                     "decision-log root is not a 32-byte hash",
                     "run gov.decision_log and report its tree root")
    return _card("decision-log-running", "policy",
                 _PASS, 10,
                 "decision log active, root %s..." % root[:16],
                 "none")


def _probe_dsse_envelopes(state):
    count = _get(state, "evidence", "enveloped_exports")
    if count is _MISSING:
        return _card("dsse-envelopes-on-export", "evidence",
                     _UNAVAILABLE, 0,
                     "evidence.enveloped_exports absent; cannot assess",
                     "report the number of DSSE-enveloped exports")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        return _card("dsse-envelopes-on-export", "evidence",
                     _FAIL, 0,
                     "no DSSE-enveloped evidence exports",
                     "seal exports via gov.evidence_envelope")
    return _card("dsse-envelopes-on-export", "evidence",
                 _PASS, 10,
                 "%d DSSE-enveloped export(s)" % count,
                 "none")


def _probe_evidence_graph(state):
    nodes = _get(state, "evidence", "graph", "nodes")
    if nodes is _MISSING:
        return _card("evidence-graph-built", "evidence",
                     _UNAVAILABLE, 0,
                     "evidence.graph.nodes absent; cannot assess",
                     "report the evidence-graph node count")
    if not isinstance(nodes, int) or isinstance(nodes, bool) or nodes < 1:
        return _card("evidence-graph-built", "evidence",
                     _FAIL, 0,
                     "evidence graph has no nodes",
                     "project artifacts via gov.evidence_graph")
    return _card("evidence-graph-built", "evidence",
                 _PASS, 10,
                 "evidence graph built with %d node(s)" % nodes,
                 "none")


def _probe_permit_journal(state):
    tip = _get(state, "durability", "permit_journal", "tip")
    if tip is _MISSING:
        return _card("permit-journal-active", "durability",
                     _UNAVAILABLE, 0,
                     "durability.permit_journal.tip absent; cannot assess",
                     "report the permit-journal chain tip MAC")
    if not _is_hex64(tip):
        return _card("permit-journal-active", "durability",
                     _FAIL, 0,
                     "permit-journal tip is not a 32-byte MAC",
                     "run gov.permit_journal and report its tip")
    return _card("permit-journal-active", "durability",
                 _PASS, 10,
                 "permit journal active, tip %s..." % tip[:16],
                 "none")


_CARD_PROBES = (
    _probe_skill_admission,
    _probe_tuf_pins,
    _probe_federated_identity,
    _probe_combiner,
    _probe_decision_log,
    _probe_dsse_envelopes,
    _probe_evidence_graph,
    _probe_permit_journal,
)


# ---------------------------------------------------------------------------
# Assessment.
# ---------------------------------------------------------------------------

def assess(state):
    """Run every card probe against deployment ``state``.

    Returns the card list sorted by (track, check) -- deterministic for
    machine output. ``state`` must be a dict; anything else refuses
    ``posture-card-malformed``.
    """
    if not isinstance(state, dict):
        _refuse(MALFORMED, "state must be a dict, got %s" %
                type(state).__name__)
    cards = [probe(state) for probe in _CARD_PROBES]
    cards.sort(key=lambda c: (c["track"], c["check"]))
    return cards


def track_level(cards, track):
    """Maturity level for ``track`` over ``cards``.

    full: every card in the track passes. partial: at least one card
    passes. absent: none pass (or no cards). An unknown track refuses
    ``posture-card-unknown-track`` -- the vocabulary is closed.
    """
    if track not in TRACKS:
        _refuse(UNKNOWN_TRACK, "unknown track %r; closed set: %s" %
                (track, ", ".join(TRACKS)))
    scoped = [c for c in cards if c.get("track") == track]
    passed = sum(1 for c in scoped if c.get("probe") == _PASS)
    if scoped and passed == len(scoped):
        return "full"
    if passed >= 1:
        return "partial"
    return "absent"


# ---------------------------------------------------------------------------
# VSA-style signed summary.
# ---------------------------------------------------------------------------

_SUMMARY_VERSION = 1


def _canonical_record(record):
    try:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _refuse(MALFORMED, "summary record not JSON-serializable: %s"
                % (exc,))
    return raw


def issue_summary(subject, cards, seed, *, issuer, issued_at=None):
    """Sign a maturity summary over ``cards``.

    The summary record::

        {v, subject, tracks: [{track, level}...], issued, issuer}

    is signed with the deployment-owned Ed25519 ``seed`` (32 bytes).
    The key is never generated or stored here. Returns
    ``{"record", "pub", "sig"}``. Malformed inputs refuse
    ``posture-card-malformed``.
    """
    if not isinstance(subject, str) or not subject:
        _refuse(MALFORMED, "subject must be a non-empty string")
    if not isinstance(issuer, str) or not issuer:
        _refuse(MALFORMED, "issuer must be a non-empty string")
    if not isinstance(cards, list):
        _refuse(MALFORMED, "cards must be a list")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        _refuse(MALFORMED, "seed must be 32 bytes")
    stamp = issued_at if issued_at is not None else _utcnow()
    if not _is_iso_z(stamp):
        _refuse(MALFORMED, "issued_at must be YYYY-MM-DDTHH:MM:SSZ")
    record = {
        "v": _SUMMARY_VERSION,
        "subject": subject,
        "tracks": [{"track": t, "level": track_level(cards, t)}
                   for t in TRACKS],
        "issued": stamp,
        "issuer": issuer,
    }
    canonical = _canonical_record(record)
    sig = _ed.sign(bytes(seed), canonical)
    pub = _ed.publickey(bytes(seed))
    return {"record": record, "pub": pub.hex(), "sig": sig.hex()}


def verify_summary(summary):
    """Verify a signed summary; return its record on success.

    Shape problems refuse ``posture-card-malformed``; a signature that
    does not verify refuses ``posture-card-unverifiable``. Note:
    ``gov.ed25519.verify`` returns True/False and never raises.
    """
    if not isinstance(summary, dict):
        _refuse(MALFORMED, "summary must be a dict")
    record = summary.get("record")
    pub = summary.get("pub")
    sig = summary.get("sig")
    if not isinstance(record, dict):
        _refuse(MALFORMED, "summary.record must be a dict")
    if not _is_hex64(pub):
        _refuse(MALFORMED, "summary.pub must be a 32-byte hex key")
    if not _is_hex128(sig):
        _refuse(MALFORMED, "summary.sig must be a 64-byte hex signature")
    if not isinstance(record.get("subject"), str) or \
            not record.get("subject"):
        _refuse(MALFORMED, "record.subject must be a non-empty string")
    if not isinstance(record.get("issuer"), str) or \
            not record.get("issuer"):
        _refuse(MALFORMED, "record.issuer must be a non-empty string")
    if not _is_iso_z(record.get("issued")):
        _refuse(MALFORMED, "record.issued must be YYYY-MM-DDTHH:MM:SSZ")
    if record.get("v") != _SUMMARY_VERSION:
        _refuse(MALFORMED, "unsupported summary version %r" %
                (record.get("v"),))
    tracks = record.get("tracks")
    if not isinstance(tracks, list) or \
            [t.get("track") for t in tracks
             if isinstance(t, dict)] != list(TRACKS):
        _refuse(MALFORMED, "record.tracks must cover all closed tracks")
    for entry in tracks:
        if entry.get("level") not in LEVELS:
            _refuse(MALFORMED, "record.tracks has unknown level %r" %
                     (entry.get("level"),))
    canonical = _canonical_record(record)
    ok = _ed.verify(bytes.fromhex(pub), canonical,
                    bytes.fromhex(sig)) is True
    if not ok:
        _refuse(UNVERIFIABLE, "summary signature does not verify")
    return record
