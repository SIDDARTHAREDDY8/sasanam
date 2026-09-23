"""Provenance records — the Art-12-shaped auditor schema (wave-73).

The audit chain (``gov/log.py``: HMAC-chained, checkpointed, wave-72
anchored) is the envelope. This module is the letter inside it: a
first-class, versioned, validator-enforced schema for *provenance*
records — who acted, when, on what resource, with what outcome, under
which delegation, approvals, policy version, and session timing.

Design: ``workstreams/architect/PROVENANCE_DESIGN.md`` (the load-bearing
document). Regulatory vocabulary: EU AI Act Art 12 (automatic recording,
who/when/resource/outcome traceability, 6-month retention floor,
post-market monitoring as a live capability) + CSA agentic NIST profile
MEASURE (delegation-chain monitoring). Art 12(3)'s minimum-content list
is Annex III 1(a)-only and is NOT claimed here; session start/end is
Art 12(2) general traceability.

Every governed record is a log entry carrying a reserved top-level
``prov`` object. Validation is fail-closed and runs BEFORE append
(:func:`append_provenance`): an invalid record is refused and the
refusal is itself logged as a ``decision``/``denied`` record, never
written half-formed.

Security model (honest): the schema layer binds honest writers and
gives auditors per-record verifiable claims. A key-holder who reforges
the whole chain (wave-72's threat model) can reforge ``prov`` content
too — that attacker is answered by the external anchor, not by this
schema. What the schema *does* stop without the key: forgery,
record-type confusion, tier smuggling, delegation truncation, and
version games — all pinned by the wave-73 break-first probes.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone

# Envelope major version. Fail closed on unknown majors (§6 of the
# design doc): a v2 record presented to this verifier is refused, never
# silently accepted. v1 records verify under v1 rules forever.
PROVENANCE_SCHEMA_VERSION = 1
# Delegation sub-schema version, revved independently (design §6/§7).
# Wave-74 fills the three-token identity slots: v2 records carry the
# filled ``tokens`` shape on every hop; v1 records (tokens null) keep
# verifying under v1 rules, unchanged.
DELEGATION_SCHEMA_VERSION = 2

# The three-token slot marker (the adopted South et al. shape). Imported
# from the identity module so the schema and the token implementation
# can never drift apart on the marker string.
from .delegation_tokens import (TOKENS_SCHEMA, DelegationContext,
                                hop_token_refs)  # noqa: E402

RECORD_TYPES = frozenset({
    "decision", "approval", "outcome",
    "session_open", "session_close", "delegation_link",
    # Wave-75 (governing the governors): policy changes and break-glass
    # ceremony transitions are first-class governed events.
    "policy_change", "breakglass",
    # Wave-76 (detection): behavioral-monitor trip records -- the
    # monitor's trip -> enforcement wiring is chained like everything
    # else. Emitted by the operator-side monitor, never by an agent.
    "detector_trip",
})

# Wave-75: allowed statuses for a policy_change record's lifecycle.
POLICY_CHANGE_STATUSES = frozenset({
    "proposed", "approved", "applied", "rejected",
})
# Wave-75: break-glass ceremony phases (the PAL state machine).
BREAKGLASS_PHASES = frozenset({
    "declared", "activated", "used", "expired", "reviewed",
})

PRINCIPAL_KINDS = frozenset({"user", "service", "agent"})
HOP_KINDS = frozenset({"principal", "agent", "sub-agent", "tool"})
OUTCOME_STATUSES = frozenset({"ok", "denied", "error", "flagged"})
PAYLOAD_TIERS = frozenset({"decision", "restricted"})

# §4 tiering: the default "decision" tier carries purpose vocabulary
# only. These keys anywhere in a default-tier record are smuggling and
# the record is refused. (The restricted tier names its payload fields
# explicitly instead.)
_FORBIDDEN_DEFAULT_TIER_KEYS = frozenset({
    "prompt_text", "prompt", "full_output", "output_text", "transcript",
    "messages", "tool_result_body", "pii",
})

# Retention floor: Art 12(4) / Art 26(5) six months. The validator
# rejects *unbounded* restricted records; the export manifest flags
# over-retained ones.
_RETENTION_FLOOR = timedelta(days=183)
# Session-timing skew allowance for the export-time anchor cross-check.
_TIMING_SKEW = timedelta(minutes=5)

_GENESIS_BINDS = "GENESIS"


class ProvenanceError(ValueError):
    """Fail-closed: a provenance record failed schema validation.

    Raised by :func:`append_provenance` BEFORE anything is written; the
    caller logs the refusal as a ``decision``/``denied`` record so
    refusals are auditable, never silent.
    """


def _canonical_hop(hop):
    """Canonical bytes of a delegation hop EXCLUDING its own ``binds``.

    ``binds`` commits to the *content* of the previous hop, not to its
    binds value — otherwise the chain would be self-referential and a
    middle hop could be swapped together with its binds pointer.
    """
    body = {k: v for k, v in hop.items() if k != "binds"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def hop_binds(prev_hop):
    """The binds pointer a hop must carry to follow ``prev_hop``."""
    return hashlib.sha256(_canonical_hop(prev_hop)).hexdigest()


def _check_tokens_shape(tokens, where):
    """Fail-closed shape check for a v2 hop ``tokens`` slot, applied at
    build time. The slot is FIXED by the §7 contract: the three-token
    ref object, nothing else — an extra field is someone inventing a
    fourth token shape and is refused."""
    if not isinstance(tokens, dict):
        raise ProvenanceError(
            "%s.tokens must be the three-token ref object "
            "(tokens_schema %r)" % (where, TOKENS_SCHEMA))
    if tokens.get("tokens_schema") != TOKENS_SCHEMA:
        raise ProvenanceError(
            "%s.tokens.tokens_schema must be %r (got %r): no fourth "
            "token shape" % (where, TOKENS_SCHEMA,
                             tokens.get("tokens_schema")))
    allowed = {"tokens_schema", "user_token_ref", "agent_token_ref",
               "delegation_token_ref"}
    unknown = sorted(set(tokens) - allowed)
    if unknown:
        raise ProvenanceError(
            "%s.tokens carries unknown fields %r: no fourth token shape"
            % (where, unknown))
    for field in ("user_token_ref", "agent_token_ref",
                  "delegation_token_ref"):
        ref = tokens.get(field)
        if not isinstance(ref, str) or len(ref) != 64:
            raise ProvenanceError(
                "%s.tokens.%s must be a SHA-256 hex ref" % (where, field))
        try:
            int(ref, 16)
        except ValueError:
            raise ProvenanceError(
                "%s.tokens.%s must be a SHA-256 hex ref" % (where, field))
    return dict(tokens)


def _validate_tokens_shape(tokens, where):
    """Validator-side v2 tokens shape check. Returns an error list."""
    try:
        _check_tokens_shape(tokens, where)
    except ProvenanceError as e:
        return [str(e)]
    return []


def open_delegated_session(user_token, agent_token, delegation_token,
                            trust, session_id, parent_chain=(), now=None):
    """Open a session under the three-token identity (Wave-74, §7).

    Builds the :class:`DelegationContext`, binds (verifies) it, and
    returns ``(ctx, delegation)`` where ``delegation`` is the v2
    provenance delegation object with the three-token ref slots filled
    on every hop — ready to chain into the session-open provenance
    record. This is where the token refs enter the hash-chained log:
    refs only, never secrets.

    ``parent_chain``: ancestor delegation tokens, root-first (empty for
    the human-delegated root agent). Sub-agent hops carry their OWN
    delegation token's ref; user/agent refs are inherited from the
    session root (the chain records the full path back to the
    originating user).
    """
    ctx = DelegationContext(
        user_token=user_token, agent_token=agent_token,
        delegation_token=delegation_token,
        parent_chain=list(parent_chain), trust=trust,
        session_id=session_id).bind(now=now)
    # bind() verified the tokens, so these claims are trustworthy.
    user_id = user_token["claims"]["user_id"]
    agent_id = agent_token["claims"]["agent_id"]
    chain = list(parent_chain) + [delegation_token]
    hop_specs = [
        {"kind": "principal", "ref": "user:" + str(user_id),
         "tokens": hop_token_refs(user_token, agent_token, chain[0])},
        {"kind": "agent", "ref": "agent:" + str(agent_id),
         "tokens": hop_token_refs(user_token, agent_token, chain[0])},
    ]
    for tok in chain[1:]:
        hop_specs.append({
            "kind": "sub-agent",
            "ref": "agent:" + str(tok.get("subject") or "?"),
            "tokens": hop_token_refs(user_token, agent_token, tok),
        })
    return ctx, build_delegation(hop_specs)


def build_delegation(hop_specs, no_delegation_reason=None):
    """Build a delegation object with chained binds pointers.

    ``hop_specs``: ordered list of ``{"kind", "ref"}`` dicts, index 0
    the principal. Returns the ``prov.delegation`` object with ``binds``
    computed. Empty ``hop_specs`` requires ``no_delegation_reason``.

    Wave-74: a hop spec may carry ``"tokens"`` — the three-token ref
    object from ``gov.delegation_tokens.hop_token_refs`` (refs only,
    never secrets). Filling ANY hop's tokens bumps the record to
    delegation sub-schema v2 (§7 contract: "fill tokens, don't
    reshape"); all-null tokens stay v1 and keep verifying under v1
    rules. The binds chain commits to hop content INCLUDING the filled
    tokens (``_canonical_hop`` excludes only ``binds``), so truncation
    detection works unchanged on v2.
    """
    if not hop_specs:
        if not no_delegation_reason:
            raise ProvenanceError(
                "empty delegation path requires a stated "
                "no_delegation_reason")
        return {
            "delegation_schema_version": 1,
            "hops": [],
            "no_delegation_reason": no_delegation_reason,
        }
    hops = []
    filled = False
    for i, spec in enumerate(hop_specs):
        tokens = spec.get("tokens")
        if tokens is not None:
            filled = True
            tokens = _check_tokens_shape(tokens,
                                         "hop_specs[%d]" % i)
        hop = {"kind": spec["kind"], "ref": spec["ref"], "tokens": tokens}
        hop["binds"] = _GENESIS_BINDS if i == 0 else hop_binds(hops[i - 1])
        hops.append(hop)
    return {
        "delegation_schema_version": 2 if filled else 1,
        "hops": hops,
    }


def _is_iso8601(value):
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def validate_delegation(delegation):
    """Structural verification of a delegation path. Returns error list.

    Checks: sub-schema version (1 or 2 — anything else fails closed),
    hop kinds/order (index 0 is the principal), binds-chain continuity
    (dropping ANY hop — including a middle one — breaks its successor's
    binds pointer), and the ``tokens`` slots:

    * v1: tokens must stay null (a non-null tokens on a v1 record is
      someone inventing a fourth token shape — reject);
    * v2 (Wave-74): every hop's tokens must be the three-token ref
      object (``tokens_schema`` + three SHA-256 hex refs, no extra
      fields). The binds chain commits to the filled tokens, so
      truncation/reorder/edit detection works unchanged.

    Scope is deliberately NOT evaluated here (design §2/§7): the schema
    layer binds structure; signature and scope evaluation belong to
    ``gov/delegation_tokens.py``.
    """
    errors = []
    if not isinstance(delegation, dict):
        return ["delegation must be an object"]
    version = delegation.get("delegation_schema_version")
    if version not in (1, 2):
        errors.append(
            "delegation_schema_version %r unknown (this verifier knows "
            "1 and 2)" % (version,))
        return errors  # fail closed on the sub-schema version
    hops = delegation.get("hops")
    if not isinstance(hops, list):
        return ["delegation.hops must be a list"]
    if not hops:
        if not delegation.get("no_delegation_reason"):
            errors.append("empty delegation.hops requires "
                          "no_delegation_reason")
        return errors
    for i, hop in enumerate(hops):
        where = "delegation.hops[%d]" % i
        if not isinstance(hop, dict):
            errors.append("%s must be an object" % where)
            continue
        if hop.get("kind") not in HOP_KINDS:
            errors.append("%s.kind %r not in %s"
                          % (where, hop.get("kind"), sorted(HOP_KINDS)))
        if not isinstance(hop.get("ref"), str) or not hop.get("ref"):
            errors.append("%s.ref must be a non-empty string" % where)
        if i == 0:
            if hop.get("kind") != "principal":
                errors.append("delegation.hops[0].kind must be "
                              "'principal', got %r" % hop.get("kind"))
            if hop.get("binds") != _GENESIS_BINDS:
                errors.append("delegation.hops[0].binds must be %r"
                              % _GENESIS_BINDS)
        else:
            expect = hop_binds(hops[i - 1])
            if hop.get("binds") != expect:
                errors.append(
                    "%s.binds mismatch: delegation path broken at hop %d "
                    "(hop dropped, reordered, or edited)" % (where, i))
        # Wave-74 contract (§7): v1 records keep the tokens slot null;
        # v2 records carry the filled three-token shape on EVERY hop.
        tokens = hop.get("tokens")
        if version == 1:
            if tokens is not None:
                errors.append(
                    "%s.tokens must be null on v1 records (Wave-74 fills "
                    "the three-token shape as v2; a non-null tokens here "
                    "is a fourth token shape)" % where)
        else:
            errors.extend(_validate_tokens_shape(tokens, where))
    return errors


def _find_forbidden_keys(obj, path="$"):
    """Yield (path, key) for every default-tier-forbidden key anywhere
    in the record. Smuggling is smuggling wherever it hides."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _FORBIDDEN_DEFAULT_TIER_KEYS:
                found.append(("%s.%s" % (path, k), k))
            found.extend(_find_forbidden_keys(v, "%s.%s" % (path, k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(_find_forbidden_keys(v, "%s[%d]" % (path, i)))
    return found


def validate_provenance(entry):
    """Validate a log entry's ``prov`` section. Returns a verdict dict.

    ``{"ok": bool, "errors": [...], "warnings": [...]}``. Fail-closed:
    any error means the record must not be appended. Checks: envelope
    version, record type, the record-type → required-field matrix (§1.2),
    delegation structure, tier enforcement, retention boundedness,
    session-timing well-formedness. Warnings (e.g. ambient-authority
    ref strings) do not fail validation but are export-visible.
    """
    errors, warnings = [], []

    def err(msg):
        errors.append(msg)

    if not isinstance(entry, dict):
        return {"ok": False, "errors": ["entry must be a dict"],
                "warnings": []}
    prov = entry.get("prov")
    if not isinstance(prov, dict):
        return {"ok": False, "errors": ["entry.prov must be an object"],
                "warnings": []}

    # §6: envelope version — unknown majors fail closed, never silently
    # accepted. Non-integer versions fail too (a string "1" is not 1).
    sv = prov.get("schema_version")
    if sv != PROVENANCE_SCHEMA_VERSION or isinstance(sv, bool):
        err("prov.schema_version %r unknown to this verifier (knows %d); "
            "refusing — migrate explicitly, never silently accept"
            % (sv, PROVENANCE_SCHEMA_VERSION))
        return {"ok": False, "errors": errors, "warnings": warnings}

    rtype = prov.get("record_type")
    if rtype not in RECORD_TYPES:
        err("prov.record_type %r not in %s"
            % (rtype, sorted(RECORD_TYPES)))

    # Traceability core: who/when.
    if not isinstance(prov.get("session_id"), str) or \
            not prov.get("session_id"):
        err("prov.session_id must be a non-empty string")
    if not _is_iso8601(prov.get("session_open")):
        err("prov.session_open must be an ISO-8601 timestamp")
    if prov.get("session_close") is not None:
        if not _is_iso8601(prov.get("session_close")):
            err("prov.session_close must be an ISO-8601 timestamp")
        elif _is_iso8601(prov.get("session_open")) and \
                datetime.fromisoformat(prov["session_close"]) < \
                datetime.fromisoformat(prov["session_open"]):
            err("prov.session_close precedes prov.session_open")
    if not isinstance(prov.get("clock_source"), str) or \
            not prov.get("clock_source"):
        err("prov.clock_source must be a stated non-empty string")

    principal = prov.get("principal")
    if not isinstance(principal, dict):
        err("prov.principal must be an object")
    else:
        if principal.get("kind") not in PRINCIPAL_KINDS:
            err("prov.principal.kind %r not in %s"
                % (principal.get("kind"), sorted(PRINCIPAL_KINDS)))
        ref = principal.get("ref")
        if not isinstance(ref, str) or not ref:
            err("prov.principal.ref must be a non-empty string")
        elif ref.strip().lower() == "system":
            # The learnings memo's theater note: agent_id "system"
            # strings. Warning, not error — a deployment may genuinely
            # register that ref; the auditor sees it.
            warnings.append("prov.principal.ref is the ambient-authority "
                            "string 'system'")

    # Delegation path (required on every record; §2).
    errors.extend(validate_delegation(prov.get("delegation")))

    # Record-type → required-field matrix (§1.2): record-type confusion
    # (swapping type to escalate what a record authorizes) fails here.
    approvals = prov.get("approvals")
    if rtype in ("decision", "outcome"):
        if not isinstance(approvals, list):
            err("prov.approvals must be a list on %r records" % rtype)
        elif not approvals and prov.get("approval_basis") not in \
                ("policy-auto", "none-required"):
            err("empty prov.approvals on a %r record requires a stated "
                "prov.approval_basis ('policy-auto' or 'none-required')"
                % rtype)
        for a in approvals or []:
            if not isinstance(a, dict) or not all(
                    isinstance(a.get(k), str) and a.get(k)
                    for k in ("approval_id", "decision", "decided_by",
                              "decided_at")):
                err("prov.approvals[] entries need string approval_id, "
                    "decision, decided_by, decided_at")
                break
        for field in ("action", "resource"):
            fval = prov.get(field)
            if not isinstance(fval, dict):
                err("prov.%s must be an object on %r records"
                    % (field, rtype))
            elif field == "action":
                for k in ("verb", "tool", "args_digest"):
                    if not isinstance(fval.get(k), str) or \
                            not fval.get(k):
                        err("prov.action.%s must be a non-empty string"
                            % k)
            else:
                for k in ("kind", "ref", "scope"):
                    if not isinstance(fval.get(k), str) or \
                            not fval.get(k):
                        err("prov.resource.%s must be a non-empty string"
                            % k)
    if rtype == "outcome":
        oc = prov.get("outcome")
        if not isinstance(oc, dict):
            err("prov.outcome must be an object on 'outcome' records")
        else:
            if oc.get("status") not in OUTCOME_STATUSES:
                err("prov.outcome.status %r not in %s"
                    % (oc.get("status"), sorted(OUTCOME_STATUSES)))
            if not isinstance(oc.get("detail"), str) or \
                    not oc.get("detail"):
                err("prov.outcome.detail must be a non-empty string")
    if rtype == "decision" and "outcome" in prov:
        err("record-type confusion: 'decision' records must not carry "
            "prov.outcome (outcomes are separate records)")
    if rtype == "approval":
        # An approval authorizes a decision; it must name the decision it
        # approves. Carrying action fields without a linked decision ref
        # is record-type confusion (escalation surface): refuse.
        if not isinstance(approvals, list) or not approvals:
            err("'approval' records require a non-empty prov.approvals "
                "list")
        if "action" in prov and not prov.get("decision_ref"):
            err("record-type confusion: 'approval' records must not carry "
                "prov.action without prov.decision_ref naming the approved "
                "decision")
    if rtype == "session_open" and "session_close" in prov:
        err("record-type confusion: 'session_open' must not carry "
            "prov.session_close")
    if rtype == "session_close":
        if not _is_iso8601(prov.get("session_close")):
            err("'session_close' records require prov.session_close")
        for f in ("action", "outcome"):
            if f in prov:
                err("record-type confusion: 'session_close' must not "
                    "carry prov.%s" % f)
    if rtype == "policy_change":
        # Wave-75: a policy mutation is a governed event, not a file
        # edit. The record commits to the author, the diff, the tier's
        # approvals, and the version transition.
        pc = prov.get("policy")
        if not isinstance(pc, dict):
            err("'policy_change' records require prov.policy as an "
                "object")
        else:
            for k in ("change_id", "policy_version", "prior_version",
                      "status", "tier", "author_key_id", "policy_digest",
                      "prior_digest", "diff_digest", "purpose"):
                if not isinstance(pc.get(k), str) or not pc.get(k):
                    err("prov.policy.%s must be a non-empty string" % k)
            if pc.get("status") not in POLICY_CHANGE_STATUSES:
                err("prov.policy.status %r not in %s"
                    % (pc.get("status"), sorted(POLICY_CHANGE_STATUSES)))
            if pc.get("tier") not in ("single-human", "two-person"):
                err("prov.policy.tier %r not in ('single-human', "
                    "'two-person')" % pc.get("tier"))
            if not isinstance(pc.get("approver_key_ids"), list) or \
                    any(not isinstance(a, str) or not a
                        for a in pc["approver_key_ids"]):
                err("prov.policy.approver_key_ids must be a list of "
                    "key-id strings")
            ds = pc.get("diff_summary")
            if not isinstance(ds, dict):
                err("prov.policy.diff_summary must be an object")
            if not isinstance(approvals, list):
                err("prov.approvals must be a list on 'policy_change' "
                    "records")
            elif pc.get("status") in ("approved", "applied") and \
                    not approvals:
                err("'policy_change' records with status %r require a "
                    "non-empty prov.approvals list (the tier's human "
                    "approvals)" % pc.get("status"))
            if "action" in prov or "outcome" in prov:
                err("record-type confusion: 'policy_change' must not "
                    "carry prov.action/prov.outcome")
    if rtype == "detector_trip":
        # Wave-76: the behavioral monitor's trip record. Commits to the
        # tripped identity key, the signal, the trip kind, and the
        # baseline that fired -- the evidence an auditor (or Wave-77
        # response) needs. Must not carry action/outcome (record-type
        # confusion: a trip authorizes nothing and records no outcome).
        dt = prov.get("detector_trip")
        if not isinstance(dt, dict):
            err("'detector_trip' records require prov.detector_trip as "
                "an object")
        else:
            for k in ("identity_key", "signal", "trip_kind", "observed",
                      "threshold", "baseline_mean", "baseline_sigma",
                      "basis"):
                if not isinstance(dt.get(k), str) or not dt.get(k):
                    err("prov.detector_trip.%s must be a non-empty "
                        "string" % k)
            if dt.get("trip_kind") not in ("ewma_spike", "cusum_drift",
                                           "boolean_tripwire"):
                err("prov.detector_trip.trip_kind %r not in "
                    "('ewma_spike', 'cusum_drift', 'boolean_tripwire')"
                    % (dt.get("trip_kind"),))
            for k in ("buckets_seen", "window_buckets"):
                if not isinstance(dt.get(k), int) or dt.get(k) < 0:
                    err("prov.detector_trip.%s must be a non-negative "
                        "int" % k)
            if "action" in prov or "outcome" in prov:
                err("record-type confusion: 'detector_trip' must not "
                    "carry prov.action/prov.outcome")
    if rtype == "breakglass":
        # Wave-75: break-glass ceremony transitions (the PAL model).
        # Each transition is its own chained record; the state machine
        # lives in gov/policy_change.py.
        bg = prov.get("breakglass")
        if not isinstance(bg, dict):
            err("'breakglass' records require prov.breakglass as an "
                "object")
        else:
            for k in ("declaration_id", "phase", "purpose",
                      "requested_by", "review_status"):
                if not isinstance(bg.get(k), str) or not bg.get(k):
                    err("prov.breakglass.%s must be a non-empty string"
                        % k)
            if bg.get("phase") not in BREAKGLASS_PHASES:
                err("prov.breakglass.phase %r not in %s"
                    % (bg.get("phase"), sorted(BREAKGLASS_PHASES)))
            if not isinstance(bg.get("ttl_s"), int) or bg["ttl_s"] <= 0:
                err("prov.breakglass.ttl_s must be a positive int")
            if bg.get("review_status") not in ("pending", "complete",
                                               "n/a"):
                err("prov.breakglass.review_status %r not in "
                    "('pending', 'complete', 'n/a')"
                    % bg.get("review_status"))
            if bg.get("phase") == "reviewed" and \
                    bg.get("review_status") != "complete":
                err("'reviewed' phase requires review_status "
                    "'complete'")
            if "action" in prov or "outcome" in prov:
                err("record-type confusion: 'breakglass' must not "
                    "carry prov.action/prov.outcome")

    # Decision provenance (authensor's matchedRules vocabulary).
    if not isinstance(prov.get("policy_version"), str) or \
            not prov.get("policy_version"):
        err("prov.policy_version must be a non-empty string")
    mr = prov.get("matched_rules")
    if not isinstance(mr, list) or \
            any(not isinstance(r, str) for r in mr):
        err("prov.matched_rules must be a list of rule-id strings")

    # §4 tiering.
    tier = prov.get("payload_tier")
    if tier not in PAYLOAD_TIERS:
        err("prov.payload_tier %r not in %s"
            % (tier, sorted(PAYLOAD_TIERS)))
    elif tier == "decision":
        # Tier enforcement is validator-enforced, not advisory: any
        # forbidden payload key anywhere in a default-tier record is a
        # smuggling attempt → refuse.
        for path, key in _find_forbidden_keys(entry):
            err("payload-tier bypass: forbidden key %r at %s in a "
                "'decision'-tier record — move payload content to the "
                "explicit 'restricted' tier" % (key, path))
    retention = prov.get("retention")
    if not isinstance(retention, dict):
        err("prov.retention must be an object")
    else:
        if retention.get("class") != tier:
            err("prov.retention.class %r must match prov.payload_tier %r"
                % (retention.get("class"), tier))
        if not _is_iso8601(retention.get("until")):
            err("prov.retention.until must be an ISO-8601 timestamp")
        if not isinstance(retention.get("policy"), str) or \
                not retention.get("policy"):
            err("prov.retention.policy must be a non-empty string")
        if tier == "restricted":
            # Unbounded restricted records are refused: the tier is
            # retention-bounded by definition (§4).
            if not _is_iso8601(retention.get("until")):
                err("'restricted'-tier records require a bounded "
                    "prov.retention.until")
            access = prov.get("access")
            if not isinstance(access, list) or not access or \
                    any(not isinstance(a, str) for a in access):
                err("'restricted'-tier records require prov.access as a "
                    "non-empty list of role strings")

    # anchor_ref is export-populated (§3); if present it must be
    # well-formed, never trusted blindly.
    aref = prov.get("anchor_ref")
    if aref is not None:
        if not isinstance(aref, dict) or aref.get("grade") not in \
                ("anchored", "operator-attested-only"):
            err("prov.anchor_ref, when present, needs grade "
                "'anchored' or 'operator-attested-only'")

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def require_valid(entry):
    """Validate or raise :class:`ProvenanceError` (fail-closed)."""
    verdict = validate_provenance(entry)
    if not verdict["ok"]:
        raise ProvenanceError(
            "provenance record refused: %s" % "; ".join(verdict["errors"]))
    return verdict


def append_provenance(log, event):
    """Validate the ``prov`` section, then append via ``ActionLog``.

    Fail-closed: :class:`ProvenanceError` propagates BEFORE anything is
    written — the caller must log the refusal as a ``decision`` record
    with outcome ``denied`` so refusals are auditable, never silent.
    Reserved chain metadata stays the log's (``ActionLog.append``
    clobbers same-named caller keys, as always).
    """
    require_valid(event)
    return log.append(event)


def check_session_timing(entries, anchors):
    """Export-time session-timing cross-check against anchor grades.

    For each session's claimed [session_open, session_close]: a claim
    that ends AFTER its epoch's witness_time (+ skew) is impossible —
    the witness saw the epoch's records before the session supposedly
    ended — and is flagged loud. Claims inside unanchored (open) epochs
    are reported as *unverifiable* (the soft window), never as clean:
    a key-holder can backdate within the open epoch with valid reforged
    MACs (design §5 residual), so the export states the window instead
    of blessing the timing.

    ``anchors`` is the ``gov.anchorer.anchor_summary`` dict (or None).
    Returns a list of finding dicts; empty means nothing to flag.
    """
    findings = []
    sessions = {}
    for e in entries:
        prov = e.get("prov") if isinstance(e, dict) else None
        if not isinstance(prov, dict):
            continue
        sid = prov.get("session_id")
        if not sid:
            continue
        s = sessions.setdefault(sid, {"open": None, "close": None,
                                      "epochs": set()})
        if _is_iso8601(prov.get("session_open")):
            t = datetime.fromisoformat(prov["session_open"])
            if s["open"] is None or t < s["open"]:
                s["open"] = t
        if _is_iso8601(prov.get("session_close")):
            t = datetime.fromisoformat(prov["session_close"])
            if s["close"] is None or t > s["close"]:
                s["close"] = t
        if isinstance(e.get("epoch_id"), str):
            s["epochs"].add(e["epoch_id"])

    by_epoch = {}
    if isinstance(anchors, dict):
        for ep in anchors.get("epochs") or []:
            by_epoch[ep.get("epoch_id")] = ep
    open_epoch = (anchors or {}).get("open_epoch") or {}
    open_id = open_epoch.get("epoch_id")

    for sid, s in sorted(sessions.items()):
        anchored_epochs = [by_epoch[eid] for eid in s["epochs"]
                           if by_epoch.get(eid, {}).get("grade")
                           == "anchored"]
        if s["close"] is not None:
            for ep in anchored_epochs:
                wt = ep.get("witness_time")
                if _is_iso8601(wt) and s["close"] > \
                        datetime.fromisoformat(wt) + _TIMING_SKEW:
                    findings.append({
                        "session_id": sid,
                        "kind": "impossible-timing",
                        "detail": "session claims to end at %s, after epoch "
                                  "%s was witnessed at %s — backdated or "
                                  "mis-bound session timing"
                                  % (s["close"].isoformat(),
                                     ep.get("epoch_id"), wt),
                    })
        unanchored = [eid for eid in s["epochs"]
                      if eid == open_id or by_epoch.get(eid, {}).get(
                          "grade") != "anchored"]
        if unanchored:
            findings.append({
                "session_id": sid,
                "kind": "timing-unverifiable-soft-window",
                "detail": "session spans unanchored epoch(s) %s: session "
                          "timing is operator-attested only until the "
                          "epoch anchors (key-holder backdating within "
                          "the open epoch is undetectable in-chain)"
                          % sorted(unanchored),
            })
    return findings


def build_retention_manifest(entries, policy_ref="art12-default"):
    """Aggregate per-record ``prov.retention`` into a retention manifest.

    The manifest states, per payload tier: record count, earliest and
    latest ``retention.until``, the governing policy ref, and flags —
    records missing retention (schema violation at export time) and
    restricted-tier records retained past the 6-month floor without a
    named legal basis (``retention.policy`` naming anything other than
    the default floor ref). Deterministic given the entries.
    """
    manifest = {"policy_ref": policy_ref,
                "retention_floor": "P6M (Art 12(4)/26(5))",
                "tiers": {}, "flags": []}
    for e in entries:
        prov = e.get("prov") if isinstance(e, dict) else None
        if not isinstance(prov, dict):
            continue
        tier = prov.get("payload_tier")
        if tier not in PAYLOAD_TIERS:
            continue
        t = manifest["tiers"].setdefault(
            tier, {"records": 0, "earliest_until": None,
                   "latest_until": None})
        t["records"] += 1
        ret = prov.get("retention") or {}
        until = ret.get("until")
        if not _is_iso8601(until):
            manifest["flags"].append(
                "seq %s: missing or malformed prov.retention.until" %
                e.get("seq"))
            continue
        if t["earliest_until"] is None or until < t["earliest_until"]:
            t["earliest_until"] = until
        if t["latest_until"] is None or until > t["latest_until"]:
            t["latest_until"] = until
        if tier == "restricted" and _is_iso8601(prov.get("session_open")):
            opened = datetime.fromisoformat(prov["session_open"])
            if datetime.fromisoformat(until) > opened + _RETENTION_FLOOR \
                    and ret.get("policy") == policy_ref:
                manifest["flags"].append(
                    "seq %s: restricted-tier record retained past the "
                    "6-month floor under the default policy — needs a "
                    "named legal basis in prov.retention.policy"
                    % e.get("seq"))
    return manifest


def provenance_export(entries, anchors):
    """Build the auditor-facing provenance export dict.

    Joins per-record ``prov`` sections with chain metadata (``seq``,
    ``ts``, ``epoch_id``), Wave-72 anchor grades per epoch (§3), the
    retention manifest, delegation-chain monitoring (hop counts per
    session), and session-timing findings. This is the live capability
    the Art 12 export vocabulary asks for — computed from the log on
    demand, never a cached claim.
    """
    rows = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        prov = e.get("prov")
        if not isinstance(prov, dict):
            continue
        rows.append({
            "seq": e.get("seq"),
            "ts": e.get("ts"),
            "epoch_id": e.get("epoch_id"),
            "record_type": prov.get("record_type"),
            "session_id": prov.get("session_id"),
            "principal": (prov.get("principal") or {}).get("ref"),
            "action": "%s %s" % (
                (prov.get("action") or {}).get("verb", "?"),
                (prov.get("action") or {}).get("tool", "?")),
            "resource": (prov.get("resource") or {}).get("ref"),
            "outcome": (prov.get("outcome") or {}).get("status"),
            "policy_version": prov.get("policy_version"),
            "matched_rules": prov.get("matched_rules"),
            "payload_tier": prov.get("payload_tier"),
            "delegation_hops": len(
                (prov.get("delegation") or {}).get("hops") or []),
        })
    by_epoch = {}
    if isinstance(anchors, dict):
        for ep in anchors.get("epochs") or []:
            by_epoch[ep.get("epoch_id")] = ep.get("grade")
    for r in rows:
        r["anchor_grade"] = by_epoch.get(r["epoch_id"],
                                        "operator-attested-only")
    hop_counts = sorted({r["delegation_hops"] for r in rows})
    return {
        "automatic_recording": (
            "Provenance records are written by the governance layer at "
            "decision/enforcement time — never at the agent's invocation, "
            "never opt-in (EU AI Act Art 12(1) automatic recording)."),
        "traceability_rows": rows,
        "retention_manifest": build_retention_manifest(entries),
        "delegation_monitoring": {
            "records_with_delegation": len(rows),
            "distinct_hop_depths": hop_counts,
            "note": "CSA agentic NIST profile MEASURE: delegation-chain "
                    "monitoring — every record carries the principal → "
                    "agent → sub-agent → tool path as chained structure.",
        },
        "session_timing_findings": check_session_timing(entries, anchors),
        # Wave-75 (governing the governors): every policy change and
        # break-glass ceremony transition is a chained record in the
        # same log — they anchor like everything else. The export
        # surfaces them as the governor-oversight section: who changed
        # the rules, what the diff was, who approved it, and each
        # record's epoch anchor grade.
        "governor_changes": _governor_changes_section(entries, by_epoch),
    }


def _governor_changes_section(entries, by_epoch):
    rows = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        prov = e.get("prov")
        if not isinstance(prov, dict):
            continue
        rtype = prov.get("record_type")
        if rtype == "policy_change":
            pc = prov.get("policy") or {}
            rows.append({
                "seq": e.get("seq"),
                "ts": e.get("ts"),
                "epoch_id": e.get("epoch_id"),
                "kind": "policy_change",
                "change_id": pc.get("change_id"),
                "status": pc.get("status"),
                "tier": pc.get("tier"),
                "author_key_id": pc.get("author_key_id"),
                "approver_key_ids": pc.get("approver_key_ids"),
                "policy_version": pc.get("policy_version"),
                "prior_version": pc.get("prior_version"),
                "diff_digest": pc.get("diff_digest"),
                "diff_summary": pc.get("diff_summary"),
                "authorship_ref": prov.get("authorship_ref"),
                "anchor_grade": by_epoch.get(e.get("epoch_id"),
                                             "operator-attested-only"),
            })
        elif rtype == "breakglass":
            bg = prov.get("breakglass") or {}
            rows.append({
                "seq": e.get("seq"),
                "ts": e.get("ts"),
                "epoch_id": e.get("epoch_id"),
                "kind": "breakglass",
                "declaration_id": bg.get("declaration_id"),
                "phase": bg.get("phase"),
                "purpose": bg.get("purpose"),
                "requested_by": bg.get("requested_by"),
                "review_status": bg.get("review_status"),
                "anchor_grade": by_epoch.get(e.get("epoch_id"),
                                             "operator-attested-only"),
            })
    return {
        "records": rows,
        "note": "Policy changes and break-glass uses are chained "
                "provenance records in the same HMAC-chained log as "
                "decisions; per-record epoch anchor grades say which "
                "are externally anchored vs operator-attested-only.",
    }
