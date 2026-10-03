"""Approval quorum: votes are signed declarations; one blocking veto is un-outvotable.

PATTERN LINEAGE: gerrit / phorge (Apache-2.0) -- the mechanisms adapted
here, clean-room stdlib-only, no upstream code vendored:

* votes are signed declarations on an approval-request digest;
* named blocking-veto roles: ONE veto = the request cannot pass, full
  stop -- a veto is un-outvotable (phorge's blocking reviewers,
  gerrit's -2);
* gerrit's approval-reset-on-version-change becomes the append-only
  ballot box: a cast vote cannot be withdrawn; retracting refuses
  coded ``approval-quorum-invalid`` and a re-plan requires a new
  request (a new digest, never a mutation of the counted set);
* requester != approver: a requester's own vote on their request
  refuses coded ``approval-quorum-self-vote``.

Domain contract (defined LOCALLY in this module; the wave-297 merge
wired it to ``gov/approval_request.py`` via the seam below -- only a
LAZY import inside ``request_digest_from_request``, so this module
stays importable standalone):

* REQUEST shape (the thing voted on): a mapping with
  ``{"schema": "approval-request/v1", "request_id": <str>,
    "requester_id": <str>, "action_digest": <64 lowercase hex>,
    "expires_at": <int unix epoch>, "version": 1}``.
  ``request_digest(request)`` = sha256 of the canonical JSON of that
  mapping (field ORDER fixed by canonicalization, not by the caller).
  WAVE-297 MERGE RESOLUTION: ``gov.approval_request`` (built in the
  parallel lane) emits richer signed envelopes; the seam is
  ``gov.approval_request.quorum_digest_input`` -> this module's
  ``request_digest_from_request`` (request_id = sha256 of the
  canonical request body, requester_id = requester agent_id,
  expires_at = issued_at + ttl_seconds). That projection -- and only
  it -- is the digest the quorum binds votes to.
* VOTE body (the thing signed): ``{"schema": "approval-vote/v1",
  "request_digest": <64 hex>, "voter_id": <str>,
  "verdict": "approve" | "reject" | "veto",
  "reason_digest": <64 lowercase hex>}``. The voter's ed25519
  signature is over the canonical bytes of the body; the signature
  and body travel together as ``{"body": ..., "signature": <128 hex>}``.
* VOTER REGISTRY: mapping ``voter_id -> pubkey hex`` (32-byte ed25519
  keys). The registry is the trust anchor: unknown voter = the vote is
  not counted, refused coded ``approval-quorum-invalid`` (fail closed,
  never silently dropped from the tally).
* DECISION shape (what :func:`tally` returns on success):
  ``{"schema": "approval-quorum-decision/v1", "request_digest": ...,
    "outcome": "approved", "approve_count": <int>,
    "min_approvals": <int>, "vetoes": <int>, "rejects": <int>,
    "tally_digest": <64 hex>}``. The decision is SIGNED only in the
  compositional sense: every counted vote carries a valid signature
  over the same request digest, and ``tally_digest`` is the sha256 of
  the canonical vote set -- a verifier re-verifies each vote and
  recomputes the tally without the engine (the decision is evidence,
  never authority: presenting it where authority is needed refuses
  ``decision-code-not-authorization`` per the taxonomy's standing rule).

QuorumPredicate (declared, frozen at construction):

* ``min_approvals``: bounded integer, 1..99. Zero or absurd minimums
  are not expressible -- a predicate with no meaning cannot be built.
* ``blocking_veto_roles``: frozenset of voter_ids whose ``veto``
  verdict is blocking. A ``veto`` verdict from a voter NOT in this
  set refuses coded ``approval-quorum-invalid`` (veto is an authority,
  not an opinion).
* ``max_voters``: bounded integer capping the registry size the
  predicate will accept (DoS bound on the tally loop); default 1024.

Tally rules (in this order, first refusal wins):

1. request malformed -> ``approval-quorum-invalid``;
2. ``now >= expires_at`` -> ``approval-request-expired`` (an expired
   request's quorum cannot complete -- fail closed, never "just a bit
   late");
3. any vote malformed / signature invalid / unknown voter /
   vote.request_digest != the request's digest -> 
   ``approval-quorum-invalid`` (a bad ballot poisons the whole tally --
   count nothing, refuse loudly);
4. voter_id == requester_id on ANY vote ->
   ``approval-quorum-self-vote`` (even one self-vote refuses the tally;
   the requester approves by re-proposing, never by voting);
5. duplicate voter_id across votes -> ``approval-quorum-invalid``
   (ballot-box stuffing is a malformed ballot box, not "count the
   first one");
6. any verified ``veto`` from a blocking-veto-role voter ->
   ``approval-quorum-vetoed`` -- UN-OUTVOTABLE: ten approves and one
   veto = vetoed, full stop;
7. distinct approves < min_approvals -> ``approval-quorum-unmet``;
8. otherwise the signed decision is returned.

Withdrawals: :func:`retract_vote` exists only to refuse --
``approval-quorum-invalid``. Re-planning a vetoed or unmet request
means issuing a NEW request (new digest); the old vote set is never
mutated in place.

Honest boundary (documented, not hidden): the quorum binds the
*declared* votes handed to :func:`tally`. It does not observe whether
the approved action is what actually executes -- actual-vs-claimed
enforcement is post-v1. Votes are not confidential. ``expires_at``
is a deployment-claimed clock reading; a lying clock is a
deployment-integrity problem, not a quorum problem.

All refusals are LOUD: coded :class:`ApprovalQuorumError`, never
silent. ``gov.ed25519.verify`` returns exact True/False -- every call
site checks ``is True``, never truthiness (wave-243 lesson).
"""

import hashlib
import json
import time
from collections.abc import Mapping
from types import MappingProxyType

from gov import ed25519 as _ed25519

# ------------------------------------------------------------------
# Errors.
# ------------------------------------------------------------------


class ApprovalQuorumError(Exception):
    """Machine-coded quorum refusal. ``code`` is a decision code."""

    def __init__(self, code, detail):
        super(ApprovalQuorumError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class _SchemaViolation(Exception):
    pass


# ------------------------------------------------------------------
# Constants.
# ------------------------------------------------------------------

_VOTE_SCHEMA = "approval-vote/v1"
_REQUEST_SCHEMA = "approval-request/v1"
_DECISION_SCHEMA = "approval-quorum-decision/v1"

_VERDICTS = ("approve", "reject", "veto")

_MIN_APPROVALS_FLOOR = 1
_MIN_APPROVALS_CEIL = 99
_DEFAULT_MAX_VOTERS = 1024

_HEX64 = frozenset("0123456789abcdef")


# ------------------------------------------------------------------
# Deterministic helpers.
# ------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in _HEX64 for c in value))


def _refuse(code, detail):
    raise ApprovalQuorumError(code, detail)


# ------------------------------------------------------------------
# Request shape (the integration seam; see module docstring).
# ------------------------------------------------------------------

_REQUEST_FIELDS = ("schema", "request_id", "requester_id",
                   "action_digest", "expires_at", "version")


def validate_request(request):
    """Validate the request mapping; return it unchanged on success.

    Refuses coded ``approval-quorum-invalid`` on any malformed field.
    """
    if not isinstance(request, dict):
        _refuse("approval-quorum-invalid",
                "request must be a mapping, got %s" % type(request).__name__)
    try:
        if request.get("schema") != _REQUEST_SCHEMA:
            raise _SchemaViolation("schema must be %r" % _REQUEST_SCHEMA)
        for field in ("request_id", "requester_id"):
            value = request.get(field)
            if not isinstance(value, str) or not value:
                raise _SchemaViolation("%s must be a non-empty string"
                                       % field)
        if not _is_hex64(request.get("action_digest")):
            raise _SchemaViolation("action_digest must be 64 lowercase "
                                   "hex chars")
        expires_at = request.get("expires_at")
        if (not isinstance(expires_at, int)
                or isinstance(expires_at, bool) or expires_at <= 0):
            raise _SchemaViolation("expires_at must be a positive int "
                                   "unix epoch")
        if request.get("version") != 1:
            raise _SchemaViolation("version must be 1")
    except _SchemaViolation as exc:
        _refuse("approval-quorum-invalid", "malformed request: %s" % exc)
    return request


def request_digest(request):
    """The digest votes are bound to (canonical sha256 of the request)."""
    validate_request(request)
    return _sha256_hex(_canonical(
        {k: request[k] for k in _REQUEST_FIELDS}))


def request_digest_from_request(request):
    """Digest a gov.approval_request envelope (or bare body).

    Wave-297 merge seam: Lane 1 (``gov.approval_request``) produces rich
    signed request envelopes; this module's digest shape is the 6-field
    mapping documented above. The projection is computed by
    ``gov.approval_request.quorum_digest_input`` (``request_id`` =
    sha256 of the canonical request body, ``requester_id`` = the
    requester's agent_id, ``expires_at`` = issued_at + ttl_seconds) and
    then digested by :func:`request_digest` exactly as if the caller
    had passed the projected mapping directly. The import is lazy so
    this module stays importable standalone.
    """
    from . import approval_request as _ar
    return request_digest(_ar.quorum_digest_input(request))


# ------------------------------------------------------------------
# Quorum predicate: declared, validated, frozen.
# ------------------------------------------------------------------

class QuorumPredicate(object):
    """The declared quorum rule. Immutable after construction."""

    __slots__ = ("_min_approvals", "_blocking_veto_roles", "_max_voters")

    def __init__(self, min_approvals, blocking_veto_roles=(),
                 max_voters=_DEFAULT_MAX_VOTERS):
        if (not isinstance(min_approvals, int)
                or isinstance(min_approvals, bool)
                or not (_MIN_APPROVALS_FLOOR
                        <= min_approvals <= _MIN_APPROVALS_CEIL)):
            _refuse("approval-quorum-invalid",
                    "min_approvals must be an int in [%d, %d], got %r"
                    % (_MIN_APPROVALS_FLOOR, _MIN_APPROVALS_CEIL,
                       min_approvals))
        try:
            roles = frozenset(blocking_veto_roles)
        except TypeError:
            _refuse("approval-quorum-invalid",
                    "blocking_veto_roles must be an iterable of voter ids")
        for role in roles:
            if not isinstance(role, str) or not role:
                _refuse("approval-quorum-invalid",
                        "blocking veto roles must be non-empty strings")
        if (not isinstance(max_voters, int) or isinstance(max_voters, bool)
                or max_voters <= 0):
            _refuse("approval-quorum-invalid",
                    "max_voters must be a positive int")
        # The F330/F340 pattern: freeze the declaration so a post-build
        # in-process mutation cannot silently change decisions under a
        # still-valid digest. frozenset is already immutable; the object
        # itself is slot-locked (no __dict__).
        self._min_approvals = min_approvals
        self._blocking_veto_roles = roles
        self._max_voters = max_voters

    @property
    def min_approvals(self):
        return self._min_approvals

    @property
    def blocking_veto_roles(self):
        return self._blocking_veto_roles

    @property
    def max_voters(self):
        return self._max_voters

    def digest(self):
        """Stable digest of the declared predicate."""
        return _sha256_hex(_canonical({
            "min_approvals": self._min_approvals,
            "blocking_veto_roles": sorted(self._blocking_veto_roles),
            "max_voters": self._max_voters,
        }))


# ------------------------------------------------------------------
# Votes: signed declarations on the request digest.
# ------------------------------------------------------------------

_VOTE_FIELDS = ("schema", "request_digest", "voter_id",
                "verdict", "reason_digest")


def _check_vote_body(body):
    if not isinstance(body, dict):
        raise _SchemaViolation("vote body must be a mapping")
    if body.get("schema") != _VOTE_SCHEMA:
        raise _SchemaViolation("schema must be %r" % _VOTE_SCHEMA)
    if not _is_hex64(body.get("request_digest")):
        raise _SchemaViolation("request_digest must be 64 lowercase hex")
    voter_id = body.get("voter_id")
    if not isinstance(voter_id, str) or not voter_id:
        raise _SchemaViolation("voter_id must be a non-empty string")
    if body.get("verdict") not in _VERDICTS:
        raise _SchemaViolation("verdict must be one of %r" % (_VERDICTS,))
    if not _is_hex64(body.get("reason_digest")):
        raise _SchemaViolation("reason_digest must be 64 lowercase hex")


def vote_body(request_digest_hex, voter_id, verdict, reason_digest):
    """Build the signable vote body (caller signs canonical bytes)."""
    body = {
        "schema": _VOTE_SCHEMA,
        "request_digest": request_digest_hex,
        "voter_id": voter_id,
        "verdict": verdict,
        "reason_digest": reason_digest,
    }
    _check_vote_body(body)
    return body


def sign_vote(seed, body):
    """Sign a vote body with the voter's seed; return the vote envelope.

    Envelope: ``{"body": body, "signature": <128 hex>}``.
    """
    _check_vote_body(body)
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        _refuse("approval-quorum-invalid",
                "voter seed must be 32 bytes")
    sig = _ed25519.sign(bytes(seed), _canonical(body))
    return {"body": body, "signature": sig.hex()}


def _verify_vote_envelope(vote, voter_registry):
    """Verify one vote envelope; return (voter_id, verdict) on success.

    Refuses coded ``approval-quorum-invalid`` on ANY defect: malformed
    envelope, unknown voter, bad hex, or a signature that does not
    verify. ``gov.ed25519.verify`` returns exact True/False -- checked
    with ``is True``, never truthiness (wave-243 lesson).
    """
    try:
        if not isinstance(vote, dict):
            raise _SchemaViolation("vote must be a mapping")
        body = vote.get("body")
        _check_vote_body(body)
        voter_id = body["voter_id"]
        pubkey_hex = voter_registry.get(voter_id)
        if not isinstance(pubkey_hex, str):
            raise _SchemaViolation("unknown voter %r: not in registry"
                                   % voter_id)
        try:
            pubkey = bytes.fromhex(pubkey_hex)
            sig = bytes.fromhex(vote.get("signature", ""))
        except (TypeError, ValueError):
            raise _SchemaViolation("pubkey/signature must be hex")
        # verify() never raises on malformed inputs (fail-closed False),
        # but the hex decode above already failed closed.
        if _ed25519.verify(pubkey, _canonical(body), sig) is not True:
            raise _SchemaViolation("vote signature does not verify: "
                                   "forged vote or wrong key")
    except _SchemaViolation as exc:
        _refuse("approval-quorum-invalid", "bad ballot: %s" % exc)
    return voter_id, body["verdict"]


def cast_vote(seed, request_digest_hex, voter_id, verdict, reason_digest):
    """Public seam: build + sign one vote. Convenience wrapper."""
    return sign_vote(seed, vote_body(request_digest_hex, voter_id,
                                    verdict, reason_digest))


def retract_vote(vote):
    """Votes are append-only: withdrawing a cast vote always refuses.

    A re-plan requires a NEW request (new digest). The vote set is never
    mutated in place -- gerrit's approval-reset-on-version-change,
    expressed as append-only.
    """
    _refuse("approval-quorum-invalid",
            "votes are append-only: a cast vote cannot be withdrawn; "
            "re-plan as a new request")


# ------------------------------------------------------------------
# Tally.
# ------------------------------------------------------------------

def tally(votes, predicate, request, voter_registry, now=None):
    """Tally signed votes against the predicate and request.

    Returns the decision record on approval. Refuses coded:
    ``approval-quorum-invalid`` (malformed request/bad ballot/unknown
    voter/duplicate voter/non-role veto/withdrawn-vote-shaped input),
    ``approval-request-expired`` (``now >= expires_at`` -- the quorum
    cannot complete after expiry), ``approval-quorum-self-vote`` (any
    vote whose voter_id equals the requester_id),
    ``approval-quorum-vetoed`` (one blocking veto -- un-outvotable),
    ``approval-quorum-unmet`` (too few distinct approves).
    """
    if not isinstance(predicate, QuorumPredicate):
        _refuse("approval-quorum-invalid",
                "predicate must be a QuorumPredicate")
    validate_request(request)
    if not isinstance(voter_registry, Mapping):
        _refuse("approval-quorum-invalid",
                "voter_registry must be a mapping of voter_id -> pubkey hex")
    if len(voter_registry) > predicate.max_voters:
        _refuse("approval-quorum-invalid",
                "voter registry (%d) exceeds predicate max_voters (%d)"
                % (len(voter_registry), predicate.max_voters))
    digest = request_digest(request)

    moment = time.time() if now is None else now
    if not isinstance(moment, (int, float)) or isinstance(moment, bool):
        _refuse("approval-quorum-invalid",
                "now must be a numeric epoch")
    if moment >= request["expires_at"]:
        _refuse("approval-request-expired",
                "request %r expired at %d (now %s): the quorum cannot "
                "complete after expiry"
                % (request["request_id"], request["expires_at"], moment))

    if not isinstance(votes, (list, tuple)):
        _refuse("approval-quorum-invalid",
                "votes must be a list of vote envelopes")

    seen_voters = set()
    approves = 0
    rejects = 0
    vetoes = 0
    counted_bodies = []
    for vote in votes:
        voter_id, verdict = _verify_vote_envelope(vote, voter_registry)
        body = vote["body"]
        if body["request_digest"] != digest:
            _refuse("approval-quorum-invalid",
                    "vote by %r is bound to a different request digest: "
                    "votes are never rebound across requests" % voter_id)
        if voter_id == request["requester_id"]:
            _refuse("approval-quorum-self-vote",
                    "requester %r voted on their own request: the "
                    "requester approves by re-proposing, never by voting"
                    % voter_id)
        if voter_id in seen_voters:
            _refuse("approval-quorum-invalid",
                    "duplicate vote by %r: ballot-box stuffing is a "
                    "malformed ballot box, not 'count the first one'"
                    % voter_id)
        seen_voters.add(voter_id)
        if verdict == "approve":
            approves += 1
        elif verdict == "reject":
            rejects += 1
        else:  # veto
            if voter_id not in predicate.blocking_veto_roles:
                _refuse("approval-quorum-invalid",
                        "veto by %r refused: veto is an authority held "
                        "only by the named blocking veto roles"
                        % voter_id)
            vetoes += 1
        counted_bodies.append(body)

    # The veto is UN-OUTVOTABLE: one blocking veto ends the tally,
    # regardless of how many approves stand beside it.
    if vetoes:
        _refuse("approval-quorum-vetoed",
                "request %r vetoed by a blocking veto role: one veto "
                "cannot be outvoted (%d approves do not override it)"
                % (request["request_id"], approves))

    if approves < predicate.min_approvals:
        _refuse("approval-quorum-unmet",
                "request %r: %d approves below the declared minimum of "
                "%d (rejects=%d)" % (request["request_id"], approves,
                                     predicate.min_approvals, rejects))

    tally_digest = _sha256_hex(_canonical({
        "request_digest": digest,
        "predicate_digest": predicate.digest(),
        "votes": counted_bodies,
    }))
    return {
        "schema": _DECISION_SCHEMA,
        "request_digest": digest,
        "outcome": "approved",
        "approve_count": approves,
        "min_approvals": predicate.min_approvals,
        "vetoes": vetoes,
        "rejects": rejects,
        "tally_digest": tally_digest,
    }


def verify_decision(decision, votes, predicate, request, voter_registry):
    """Re-verify a decision WITHOUT trusting the tally: recompute it.

    Re-runs :func:`tally` and checks the recomputed decision equals the
    presented one. Returns True on exact match; refuses coded
    ``approval-quorum-invalid`` if the presented decision diverges
    (evidence re-execution, the taxonomy's reverify discipline).
    """
    recomputed = tally(votes, predicate, request, voter_registry)
    if not isinstance(decision, dict) or decision != recomputed:
        _refuse("approval-quorum-invalid",
                "presented decision diverges from the recomputed tally: "
                "the decision is evidence, never authority")
    return True


# ------------------------------------------------------------------
# Registry helpers (deployment-owned, kept minimal).
# ------------------------------------------------------------------

def build_registry(voter_seeds):
    """Build a voter registry from {voter_id: 32-byte seed}.

    Test and deployment convenience: the registry is
    {voter_id: pubkey-hex}; seeds never leave the caller.
    """
    if not isinstance(voter_seeds, dict) or not voter_seeds:
        _refuse("approval-quorum-invalid",
                "voter_seeds must be a non-empty mapping")
    registry = {}
    for voter_id, seed in voter_seeds.items():
        if not isinstance(voter_id, str) or not voter_id:
            _refuse("approval-quorum-invalid",
                    "voter ids must be non-empty strings")
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            _refuse("approval-quorum-invalid",
                    "seed for %r must be 32 bytes" % voter_id)
        registry[voter_id] = _ed25519.publickey(bytes(seed)).hex()
    return MappingProxyType(registry)
