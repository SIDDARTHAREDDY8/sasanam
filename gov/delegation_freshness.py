"""Delegation freshness gate (W245-5; agent-capability-attestation
ADAPT).

ADAPT of the five validation rules from
yunaremaia/agent-capability-attestation (MIT; patterns only, no code
vendored), re-expressed in this repo's vocabulary:

  1. TTL metadata      -- a CapabilityAttestation carries capabilities,
                         issued_at, ttl_seconds and state_hash; a missing
                         or unusable TTL is expired, never an
                         infinite-life attestation
                         (``delegation-ttl-missing``).
  2. Freshness         -- ttl_seconds must not have elapsed at check
                         time (``delegation-freshness-expired``).
  3. State binding     -- state_hash must equal
                         digest_capabilities(capabilities), so a hop
                         cannot silently swap its capability set
                         (``delegation-state-mismatch``).
  4. Monotonic narrowing -- every child capability entry must be
                         covered by the parent's set (exact entry,
                         ``"*"``, or ``"<prefix>:*"``); widening
                         refuses (``delegation-monotonicity-violated``).
  5. Fail closed       -- malformed records refuse
                         (``delegation-attestation-malformed``); chain
                         continuity is checked per hop
                         (``delegation-chain-broken``); a TTL above the
                         deployment max_ttl refuses
                         (``delegation-ttl-excessive``).

Verification order inside check_fresh: shape -> TTL presence/format ->
TTL cap -> expiry. Inside validate_chain: every hop fresh and
state-bound, then each hop's continuity and coverage against its
parent.

What this module does NOT do (blunt residuals):
  * It cannot prove the issuer actually holds the parent capabilities
    it delegates: the first hop's authority is vouched by whoever wired
    the check (same honest boundary as verifier_failclosed's
    authority-source feed trust).
  * It does not enforce time-window narrowing across hops: each
    attestation is checked against its own TTL. A policy check site
    that needs "child expiry <= parent expiry" must enforce it.
  * state_hash binds the *presented* capability set, not the agent's
    live capabilities; the agent self-declares both.

Stdlib only. Deterministic. Fail-closed on malformed input.
"""

import hashlib
import json
from datetime import datetime, timedelta

TTL_MISSING = "delegation-ttl-missing"
FRESHNESS_EXPIRED = "delegation-freshness-expired"
MONOTONICITY_VIOLATED = "delegation-monotonicity-violated"
STATE_MISMATCH = "delegation-state-mismatch"
ATTESTATION_MALFORMED = "delegation-attestation-malformed"
TTL_EXCESSIVE = "delegation-ttl-excessive"
CHAIN_BROKEN = "delegation-chain-broken"

REFUSALS = {
    TTL_MISSING: "the attestation carries no usable TTL (missing, zero, "
                 "negative, non-integer, or boolean); treated as expired, "
                 "refused fail-closed",
    FRESHNESS_EXPIRED: "the attestation's TTL has elapsed at check time; "
                       "refused fail-closed",
    MONOTONICITY_VIOLATED: "a delegation hop's capability set is not "
                           "covered by its parent's set; refused "
                           "fail-closed",
    STATE_MISMATCH: "the attestation's state_hash does not match the "
                    "digest of its presented capability set; refused "
                    "fail-closed",
    ATTESTATION_MALFORMED: "the attestation record is not the expected "
                           "shape; refused fail-closed",
    TTL_EXCESSIVE: "the attestation's TTL exceeds the deployment max_ttl "
                   "cap; refused fail-closed",
    CHAIN_BROKEN: "the delegation chain is empty, not a sequence, or a "
                  "hop's issuer does not equal its parent's subject; "
                  "refused fail-closed",
}


class DelegationFreshnessError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code, and
    ``step`` names the verification step at which the refusal fired."""

    def __init__(self, code, detail, step=None):
        super(DelegationFreshnessError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail
        self.step = step


def _refuse(code, detail, step):
    raise DelegationFreshnessError(code, detail, step=step)


def digest_capabilities(capabilities):
    """Digest a capability set: sha256 of the canonical (sorted,
    deduplicated) JSON encoding. Binds the presented capability set to
    the attestation's state_hash."""
    try:
        items = list(capabilities)
    except TypeError:
        _refuse(ATTESTATION_MALFORMED,
                "capabilities are not iterable", "digest")
    if isinstance(capabilities, (str, bytes)):
        # A bare string is iterable but is never a capability set;
        # tuple()/list() would silently shred it into characters.
        _refuse(ATTESTATION_MALFORMED,
                "capabilities must be a sequence of strings, not a "
                "single string", "digest")
    if not items:
        _refuse(ATTESTATION_MALFORMED,
                "capabilities are empty", "digest")
    for entry in items:
        if not isinstance(entry, str) or not entry:
            _refuse(ATTESTATION_MALFORMED,
                     "capability entry %r is not a non-empty string"
                     % (entry,), "digest")
    canonical = json.dumps(sorted(set(items)),
                           separators=(",", ":"),
                           ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _coerce_time(value, what):
    """Accept a tz-aware datetime or an ISO-8601 string. Naive times
    refuse: a freshness gate must not guess timezones."""
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(
                value.replace("Z", "+00:00"))
        except ValueError:
            _refuse(ATTESTATION_MALFORMED,
                    "%s %r is not ISO-8601" % (what, value), "shape")
    else:
        _refuse(ATTESTATION_MALFORMED,
                "%s must be a datetime or ISO-8601 string" % what,
                "shape")
    if moment.tzinfo is None or moment.utcoffset() is None:
        _refuse(ATTESTATION_MALFORMED,
                "%s is timezone-naive" % what, "shape")
    return moment


class CapabilityAttestation(object):
    """A claim by ``issuer`` that ``subject`` holds ``capabilities``,
    valid for ``ttl_seconds`` from ``issued_at``, bound to
    ``state_hash``.

    The TTL is stored raw and interpreted at check time: a missing or
    unusable TTL is expired (fail closed), never a constructor error --
    that is what lets check_fresh express "missing TTL = expired".
    """

    def __init__(self, issuer, subject, capabilities, issued_at,
                 ttl_seconds, state_hash):
        if not isinstance(issuer, str) or not issuer:
            _refuse(ATTESTATION_MALFORMED,
                    "issuer must be a non-empty string", "shape")
        if not isinstance(subject, str) or not subject:
            _refuse(ATTESTATION_MALFORMED,
                    "subject must be a non-empty string", "shape")
        try:
            caps = tuple(capabilities)
        except TypeError:
            _refuse(ATTESTATION_MALFORMED,
                    "capabilities are not a sequence", "shape")
        if isinstance(capabilities, (str, bytes)):
            # A bare string is iterable but is never a capability set;
            # tuple() would silently shred it into characters.
            _refuse(ATTESTATION_MALFORMED,
                    "capabilities must be a sequence of strings, not a "
                    "single string", "shape")
        if not caps or any(not isinstance(c, str) or not c
                           for c in caps):
            _refuse(ATTESTATION_MALFORMED,
                    "capabilities must be non-empty strings", "shape")
        if not isinstance(state_hash, str) or not state_hash:
            _refuse(ATTESTATION_MALFORMED,
                    "state_hash must be a non-empty string", "shape")
        self.issuer = issuer
        self.subject = subject
        self.capabilities = caps
        self.issued_at = _coerce_time(issued_at, "issued_at")
        self.ttl_seconds = ttl_seconds
        self.state_hash = state_hash

    @classmethod
    def from_dict(cls, data):
        """Parse a JSON-shaped record. Missing fields refuse malformed;
        a missing TTL becomes None and fails closed at check time."""
        if not isinstance(data, dict):
            _refuse(ATTESTATION_MALFORMED,
                    "attestation record must be a dict", "shape")
        try:
            return cls(issuer=data["issuer"],
                       subject=data["subject"],
                       capabilities=data["capabilities"],
                       issued_at=data["issued_at"],
                       ttl_seconds=data.get("ttl_seconds"),
                       state_hash=data["state_hash"])
        except KeyError as exc:
            _refuse(ATTESTATION_MALFORMED,
                    "missing field %s" % (exc,), "shape")

    def __repr__(self):
        return ("CapabilityAttestation(issuer=%r, subject=%r, "
                "capabilities=%r, issued_at=%r, ttl_seconds=%r)"
                % (self.issuer, self.subject, self.capabilities,
                   self.issued_at.isoformat(), self.ttl_seconds))


def _check_ttl(att, max_ttl):
    """TTL gate: None / bool / non-int / <=0 is *expired* (fail closed).
    A boolean is rejected explicitly because True == 1 in Python."""
    ttl = att.ttl_seconds
    if (ttl is None or isinstance(ttl, bool)
            or not isinstance(ttl, int) or ttl <= 0):
        _refuse(TTL_MISSING,
                "attestation carries no usable TTL (got %r); treated "
                "as expired, refused fail-closed" % (ttl,), "ttl")
    if max_ttl is not None:
        if (isinstance(max_ttl, bool) or not isinstance(max_ttl, int)
                or max_ttl <= 0):
            _refuse(ATTESTATION_MALFORMED,
                    "max_ttl deployment cap %r is malformed" % (max_ttl,),
                    "ttl")
        if ttl > max_ttl:
            _refuse(TTL_EXCESSIVE,
                    "ttl_seconds %d exceeds deployment max_ttl %d"
                    % (ttl, max_ttl), "ttl")
    return ttl


def check_fresh(att, now, max_ttl=None):
    """Freshness gate. Order: shape -> TTL presence/format -> TTL cap ->
    expiry. Returns True on a fresh attestation."""
    if not isinstance(att, CapabilityAttestation):
        _refuse(ATTESTATION_MALFORMED,
                "not a CapabilityAttestation", "shape")
    ttl = _check_ttl(att, max_ttl)
    moment = _coerce_time(now, "now")
    expires_at = att.issued_at + timedelta(seconds=ttl)
    if moment >= expires_at:
        _refuse(FRESHNESS_EXPIRED,
                "attestation expired at %s (checked at %s)"
                % (expires_at.isoformat(), moment.isoformat()),
                "freshness")
    return True


def check_state_binding(att):
    """State-hash binding: state_hash must equal
    digest_capabilities(capabilities). Returns the recomputed digest."""
    if not isinstance(att, CapabilityAttestation):
        _refuse(ATTESTATION_MALFORMED,
                "not a CapabilityAttestation", "shape")
    expected = digest_capabilities(att.capabilities)
    if att.state_hash != expected:
        _refuse(STATE_MISMATCH,
                "state_hash does not match digest(capabilities); the "
                "hop swapped its capability set or never bound it",
                "state")
    return expected


def _entry_covered(parent_caps, child_entry):
    """A child entry is covered when it equals a parent entry, when the
    parent entry is "*", or when the parent entry is "<prefix>:*" and
    the child entry starts with that prefix."""
    if child_entry in parent_caps:
        return True
    for parent_entry in parent_caps:
        if parent_entry == "*":
            return True
        if (parent_entry.endswith(":*")
                and child_entry.startswith(parent_entry[:-1])):
            return True
    return False


def check_hop(parent, child):
    """One delegation hop: continuity (child.issuer == parent.subject)
    then monotonic coverage of every child entry by the parent set."""
    for record, name in ((parent, "parent"), (child, "child")):
        if not isinstance(record, CapabilityAttestation):
            _refuse(ATTESTATION_MALFORMED,
                    "%s is not a CapabilityAttestation" % name, "hop")
    if child.issuer != parent.subject:
        _refuse(CHAIN_BROKEN,
                "child issuer %r does not equal parent subject %r"
                % (child.issuer, parent.subject), "hop")
    parent_set = set(parent.capabilities)
    for entry in child.capabilities:
        if not _entry_covered(parent_set, entry):
            _refuse(MONOTONICITY_VIOLATED,
                    "child capability %r is not covered by the "
                    "parent's capability set" % (entry,), "hop")
    return True


def validate_chain(attestations, now, max_ttl=None):
    """Validate a delegation chain in order: every hop fresh and
    state-bound, then each hop's continuity and monotonic coverage
    against its parent. Returns the verified chain record as
    [(issuer, subject, capability_digest)]."""
    try:
        chain = list(attestations)
    except TypeError:
        _refuse(CHAIN_BROKEN, "delegation chain is not a sequence",
                "chain")
    if not chain:
        _refuse(CHAIN_BROKEN, "delegation chain is empty", "chain")
    for record in chain:
        check_fresh(record, now, max_ttl=max_ttl)
        check_state_binding(record)
    for index in range(1, len(chain)):
        check_hop(chain[index - 1], chain[index])
    return [(record.issuer, record.subject,
             digest_capabilities(record.capabilities))
            for record in chain]
