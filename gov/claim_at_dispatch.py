"""Claim-at-dispatch (wave-239, W239-3: decionis AgentSafe adaptation).

"An ALLOW is not permission; a claimed grant is." A grant token is a
decision record; it is NOT a dispatch authorization. Dispatch is
authorized only by a **claim** presented immediately before the
handler runs. Offline verification of a grant proves the grant; it
authorizes nothing downstream, because a stateless verifier cannot
know whether the grant was consumed.

Rules (prose re-derive of the decionis AgentSafe authority pattern,
Apache-2.0, no upstream code reused):

* The handler never sees the grant token: it receives only the
  verified authorization's identifiers (``decision_id``,
  ``dossier_id``, ``claim_id``).
* A claim is single-use and atomic at the authority: a second
  presentation of the same grant, a grant for another payload digest,
  or a tampered grant claims nothing.
* Dispatch budget = min(upstream timeout, remaining grant,
  remaining claim lease), measured on a monotonic clock.
* Claim succeeded then crash before the handler ran: the grant is
  NOT released for a second claim (execution was not observed); the
  claim lease and the finalization record say what happened.
* Finalization is evidence, not authority: it records what happened
  (``completed`` / ``failed`` / ``indeterminate`` / ``crashed``) and
  never re-opens a consumed grant.

The six machine refusals:

* ``claim-malformed`` -- the grant, claim, or an argument is the
  wrong shape; refusing instead of guessing.
* ``claim-invalid-grant`` -- the grant's seal does not recompute
  (edited after issuance), or the grant belongs to another payload
  digest. Tampered grants claim nothing.
* ``claim-not-presented`` -- a dispatch attempted without a
  presented claim. A locally-verified-but-never-claimed grant MUST
  NOT dispatch; offline verification alone authorizes nothing.
* ``claim-not-releasable`` -- a second claim attempted against an
  already-consumed grant (including after a crash). The grant is not
  released, not retried.
* ``claim-replay`` -- the same claim presented twice. One claim, one
  presentation, one dispatch attempt.
* ``claim-lease-expired`` -- the claim's lease elapsed (monotonic
  clock) before presentation. A slow upstream cannot outlive the
  permission.

Deterministic apart from the monotonic clock: no randomness, no I/O,
no environment reads. Grant sealing is domain-separated SHA-256
(``gov-claim-at-dispatch/v1``).

Honest boundaries (what this does NOT prove):

* The grant seal detects EDITS, not forgery: anyone who can mint a
  grant can mint a self-consistent one. Authenticated minting is
  deployment-owned.
* Consumption state lives in the ``ClaimAuthority`` instance the
  caller holds: single-use atomicity across processes, hosts, or a
  real crash is deployment-owned (a durable shared consume store is
  the admission gate). This module makes the claim vocabulary and
  the refusal semantics exact, not the storage durable.
* The monotonic clock cannot survive a real process crash: the
  lease is in-memory here. The crash rule (no release, no retry) is
  what the module enforces; durable lease persistence is the
  deployment's job.
* The ``run_handler`` callable is caller-supplied: dispatch runs it
  with identifier-only arguments, but this module cannot prove the
  handler actually executed the granted action; finalization records
  the reported outcome.

Stdlib only.
"""

import hashlib
import json
import time

_DOMAIN = b"gov-claim-at-dispatch/v1"

_GRANT_FIELDS = ("version", "grant_id", "decision_id", "dossier_id",
                 "payload_digest", "remaining")

_CLAIM_FIELDS = ("version", "claim_id", "grant_id", "decision_id",
                 "dossier_id", "payload_digest", "grant_seal", "lease",
                 "issued_at")

_HEX64 = set("0123456789abcdef")


class ClaimDispatchError(Exception):
    """Refusal with a machine code registered in gov/decision_codes.py."""

    code = "claim-malformed"

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _refuse(code, message):
    raise ClaimDispatchError(code, message)


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in _HEX64 for c in value))


def _is_nonempty_str(value):
    return isinstance(value, str) and len(value) > 0


def _is_nonneg_number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and value >= 0)


def _canonical_dumps(obj):
    """JCS-style canonical JSON: sorted keys, compact separators, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _seal(body, fields):
    canonical = _canonical_dumps({k: body[k] for k in fields}).encode("ascii")
    return hashlib.sha256(_DOMAIN + canonical).hexdigest()


def _claim_id_for(grant_id, grant_seal):
    return hashlib.sha256(
        _DOMAIN + b"claim-id/" + grant_id.encode("ascii")
        + b"/" + grant_seal.encode("ascii")).hexdigest()[:32]


def issue_grant(grant_id, decision_id, dossier_id, remaining,
                payload_digest=None):
    """Mint a grant record (the grant token). Never handed to a handler."""
    if not _is_nonempty_str(grant_id):
        _refuse("claim-malformed", "grant_id must be a non-empty string")
    if not _is_nonempty_str(decision_id):
        _refuse("claim-malformed", "decision_id must be a non-empty string")
    if not _is_nonempty_str(dossier_id):
        _refuse("claim-malformed", "dossier_id must be a non-empty string")
    if not _is_nonneg_number(remaining):
        _refuse("claim-malformed", "remaining must be a non-negative number")
    if payload_digest is None:
        payload_digest = _seal({"grant_id": grant_id,
                                "decision_id": decision_id,
                                "dossier_id": dossier_id},
                               ("grant_id", "decision_id", "dossier_id"))
    if not _is_hex64(payload_digest):
        _refuse("claim-malformed", "payload_digest must be a 64-char hex digest")
    body = {"version": 1, "grant_id": grant_id, "decision_id": decision_id,
            "dossier_id": dossier_id, "payload_digest": payload_digest,
            "remaining": float(remaining)}
    body["grant_seal"] = _seal(body, _GRANT_FIELDS)
    return body


def _check_grant(grant):
    if not isinstance(grant, dict):
        _refuse("claim-malformed", "grant must be a dict")
    try:
        expected = _seal(grant, _GRANT_FIELDS)
    except (KeyError, TypeError):
        _refuse("claim-malformed", "grant is missing sealed fields")
    if not _is_hex64(grant.get("grant_seal")) or grant["grant_seal"] != expected:
        _refuse("claim-invalid-grant",
                "grant seal does not recompute; the grant was edited "
                "after issuance and claims nothing")
    return grant


class ClaimAuthority:
    """The single-use atomic claim point. One grant, one claim, one dispatch."""

    _FINAL_OUTCOMES = ("completed", "failed", "indeterminate", "crashed")

    def __init__(self):
        self._claims = {}   # grant_id -> claim record
        self._presented = {}  # claim_id -> presentation record
        self._finalized = {}  # claim_id -> finalization record

    def claim(self, grant, lease=30.0, expected_payload_digest=None):
        """Claim a grant immediately before dispatch. Single-use, atomic.

        ``expected_payload_digest`` is the digest the pipeline itself
        reproduced for the current input: when supplied, a valid-sealed
        grant minted for a different intent hash claims nothing.
        """
        if not _is_nonneg_number(lease):
            _refuse("claim-malformed", "lease must be a non-negative number")
        _check_grant(grant)
        if expected_payload_digest is not None:
            if not _is_hex64(expected_payload_digest):
                _refuse("claim-malformed",
                        "expected_payload_digest must be a 64-char hex digest")
            if grant["payload_digest"] != expected_payload_digest:
                _refuse("claim-invalid-grant",
                        "grant is for another payload digest; the pipeline's "
                        "reproduced digest does not match, so this grant "
                        "claims nothing")
        grant_id = grant["grant_id"]
        if grant_id in self._claims:
            _refuse("claim-not-releasable",
                    "grant %r is already consumed; a grant is never "
                    "released for a second claim" % (grant_id,))
        now = time.monotonic()
        claim = {"version": 1,
                 "claim_id": _claim_id_for(grant_id, grant["grant_seal"]),
                 "grant_id": grant_id,
                 "decision_id": grant["decision_id"],
                 "dossier_id": grant["dossier_id"],
                 "payload_digest": grant["payload_digest"],
                 "grant_seal": grant["grant_seal"],
                 "lease": float(lease),
                 "issued_at": now}
        claim["claim_seal"] = _seal(claim, _CLAIM_FIELDS)
        self._claims[grant_id] = claim
        return dict(claim)

    def present(self, claim, timeout):
        """Present a claim at dispatch time; returns the dispatch budget."""
        if not _is_nonneg_number(timeout):
            _refuse("claim-malformed", "timeout must be a non-negative number")
        if not isinstance(claim, dict):
            _refuse("claim-malformed", "claim must be a dict")
        claim_id = claim.get("claim_id")
        if not _is_nonempty_str(claim_id):
            _refuse("claim-malformed", "claim has no claim_id")
        if claim_id in self._presented:
            _refuse("claim-replay",
                    "claim %r was already presented; one claim, one "
                    "dispatch attempt" % (claim_id,))
        grant_id = claim.get("grant_id")
        recorded = self._claims.get(grant_id)
        if (recorded is None or recorded["claim_id"] != claim_id
                or recorded["claim_seal"] != claim.get("claim_seal")):
            _refuse("claim-not-presented",
                    "no matching live claim for claim_id %r" % (claim_id,))
        if recorded["payload_digest"] != claim.get("payload_digest"):
            _refuse("claim-invalid-grant",
                    "claim's payload digest does not match the recorded "
                    "grant; a grant for another intent claims nothing")
        now = time.monotonic()
        remaining_lease = recorded["lease"] - (now - recorded["issued_at"])
        if remaining_lease <= 0:
            _refuse("claim-lease-expired",
                    "claim %r lease elapsed; a slow upstream cannot "
                    "outlive the permission" % (claim_id,))
        record = {"claim_id": claim_id, "presented_at": now,
                  "budget": remaining_lease}
        self._presented[claim_id] = record
        return dict(record)


def dispatch_budget(grant, claim, timeout):
    """min(upstream timeout, remaining grant, remaining claim lease).

    The lease term is the time left on the claim's monotonic lease at
    the moment of the call; a claim record that carries no ``issued_at``
    falls back to its full lease.
    """
    _check_grant(grant)
    if not _is_nonneg_number(timeout):
        _refuse("claim-malformed", "timeout must be a non-negative number")
    if not isinstance(claim, dict) or not _is_nonneg_number(claim.get("lease")):
        _refuse("claim-malformed", "claim must carry a lease")
    lease = float(claim["lease"])
    issued_at = claim.get("issued_at")
    if _is_nonneg_number(issued_at):
        lease = max(0.0, lease - (time.monotonic() - float(issued_at)))
    return min(float(timeout), float(grant["remaining"]), lease)


def dispatch(grant, timeout, lease, run_handler, authority=None):
    """Refuse: a bare grant presented at dispatch without a claim.

    The parameters mirror the dispatch call shape so a caller that
    forgot the claim step hits this refusal with its own arguments
    visible; all four are intentionally unused -- the refusal is
    unconditional.
    """
    _check_grant(grant)
    _refuse("claim-not-presented",
            "grant %r presented at dispatch with no claim; offline "
            "verification alone authorizes nothing" % (grant["grant_id"],))


def dispatch_grant(grant, claim, timeout, run_handler, authority=None):
    """Dispatch against a presented claim; the handler sees identifiers only.

    The claim binds exactly the grant it was minted for
    (``grant_id`` + ``grant_seal``); a presented claim for another
    grant dispatches nothing. Each presentation dispatches at most
    once: a second call against the same presentation refuses
    ``claim-replay``.
    """
    _check_grant(grant)
    if authority is None:
        _refuse("claim-not-presented",
                "dispatch requires the claim authority's presented "
                "record, not just the claim bytes")
    if not callable(run_handler):
        _refuse("claim-malformed", "run_handler must be callable")
    if not isinstance(claim, dict):
        _refuse("claim-malformed", "claim must be a dict")
    presented = authority._presented.get(claim.get("claim_id"))
    if presented is None:
        _refuse("claim-not-presented",
                "claim %r was never presented at the authority; "
                "dispatch requires presentation, not possession" % (
                    claim.get("claim_id"),))
    if (claim.get("grant_id") != grant["grant_id"]
            or claim.get("grant_seal") != grant["grant_seal"]):
        _refuse("claim-invalid-grant",
                "this claim was minted for another grant; a claim "
                "presented for grant %r cannot dispatch grant %r" % (
                    claim.get("grant_id"), grant["grant_id"]))
    if presented.get("dispatched"):
        _refuse("claim-replay",
                "claim %r already dispatched; one presentation, one "
                "dispatch attempt" % (claim.get("claim_id"),))
    ids = {"decision_id": grant["decision_id"],
           "dossier_id": grant["dossier_id"],
           "claim_id": claim["claim_id"]}
    outcome = run_handler(dict(ids))
    presented["dispatched"] = True
    return {"dispatched": True, "identifiers": ids,
            "budget": presented["budget"], "handler_result": outcome}


def finalize(authority, claim, outcome):
    """Record what happened to a claimed dispatch. Evidence, not authority.

    ``outcome`` is one of completed / failed / indeterminate / crashed.
    A ``crashed`` finalization never releases the grant for a second
    claim; the record says what happened.
    """
    if not isinstance(claim, dict) or not _is_nonempty_str(claim.get("claim_id")):
        _refuse("claim-malformed", "claim must carry a claim_id")
    if outcome not in ClaimAuthority._FINAL_OUTCOMES:
        _refuse("claim-malformed",
                "outcome must be one of %s" % (
                    ", ".join(ClaimAuthority._FINAL_OUTCOMES)))
    record = {"claim_id": claim["claim_id"], "outcome": outcome,
              "finalized_at": time.monotonic()}
    authority._finalized[claim["claim_id"]] = record
    return dict(record)
