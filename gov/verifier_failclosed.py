"""Verifier-side fail-closed delegation-chain evaluation (W243-7 + W243-8).

The verifier's half of delegation-chain evaluation, per the jackson
wimse-evaluation and sankarshan ARPA discipline: proof verification is
not authority, and the verifier's own inputs are part of the verdict.

- A chain whose SOURCE is unavailable refuses ``chain-source-unavailable``
  (fail closed; never allow).
- A chain whose source input is stale yields the explicit verdict
  ``stale`` with code ``chain-source-stale`` (not a silent pass).
- Two verifiers on the same chain with different pinned policy inputs
  each record their verdict under ``verifier_policy_input`` -- verdicts
  are never valid without naming the policy that produced them
  (falsifies verifier-input blindness).
- Proof verifying but authority revoked or expired refuses
  ``authority-stale``: proof verification does not by itself establish
  authority (fail-safe, not proof pass-through).
- Authority source unavailable refuses ``authority-unavailable`` with a
  deterministic fail-safe (not a timeout-retry loop).
- Authority citing a lapse-registered draft is routed to
  ``gov.stale_authority``; its ``stale-authority`` code is re-raised
  here (never passed on legacy text).

Reuses ``gov.stale_authority`` (lapse registry) and
``gov.expected_participants`` (declared-participant audit); neither is
duplicated here.

Honest residuals:
- Authority statuses are caller-supplied ("valid", "revoked",
  "expired", "unavailable"). This module trusts the authority-source
  feed for the *status value*; the fail-closed discipline is about the
  decision the verifier draws from a bad status, not about proving
  the feed honest. A lying authority source is an attestation problem
  upstream.
- Expected-participant audit authenticates nothing: signature genuineness
  remains deployment-owned, as in ``gov.expected_participants``.
- ``now`` is an explicit caller-supplied clock; expiry comparisons are
  deterministic and testable.

Stdlib only. Deterministic. Fail-closed on malformed input.
"""

CHAIN_SOURCE_UNAVAILABLE = "chain-source-unavailable"
CHAIN_SOURCE_STALE = "chain-source-stale"
AUTHORITY_STALE = "authority-stale"
AUTHORITY_UNAVAILABLE = "authority-unavailable"
VERIFIER_INPUT_MALFORMED = "verifier-input-malformed"

# Re-raised (not redefined): lapse-registered authority citations route
# through gov.stale_authority, whose codes are already in the taxonomy.
_STALE_AUTHORITY_CODE = "stale-authority"

_VALID_STATUSES = ("valid", "revoked", "expired", "unavailable")


class VerifierFailclosedError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(VerifierFailclosedError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise VerifierFailclosedError(code, detail)


def _policy(policy):
    if not isinstance(policy, dict):
        _refuse(VERIFIER_INPUT_MALFORMED,
                "verifier_policy must be a dict")
    policy_input = policy.get("verifier_policy_input")
    if not isinstance(policy_input, str) or not policy_input:
        _refuse(VERIFIER_INPUT_MALFORMED,
                "verifier_policy must name a non-empty "
                "verifier_policy_input (the pinned policy producing "
                "this verdict)")
    return policy_input


def _hops(chain):
    """Validate the chain shape; malformed hops fail closed."""
    if isinstance(chain, (str, bytes)) or not hasattr(chain, "__iter__"):
        _refuse(VERIFIER_INPUT_MALFORMED,
                "chain must be an iterable of hop dicts")
    hops = []
    for index, hop in enumerate(chain):
        if not isinstance(hop, dict):
            _refuse(VERIFIER_INPUT_MALFORMED,
                    "hop %d is not a dict" % (index,))
        participant = hop.get("participant_id")
        if not isinstance(participant, str) or not participant:
            _refuse(VERIFIER_INPUT_MALFORMED,
                    "hop %d has no participant_id" % (index,))
        hops.append(hop)
    if not hops:
        _refuse(VERIFIER_INPUT_MALFORMED,
                "chain must contain at least one hop")
    return hops


def _source_status(policy):
    """Resolve the chain-source availability/freshness declaration.

    The declaration is deployment-provided data; a missing declaration
    defaults to available-and-fresh (the honest control).
    """
    source = policy.get("chain_source", {})
    if not isinstance(source, dict):
        _refuse(VERIFIER_INPUT_MALFORMED,
                "chain_source must be a dict")
    return source.get("available", True), source.get("stale", False)


def _check_chain_source(policy, policy_input):
    """Fail closed on an unavailable or stale chain source."""
    available, stale = _source_status(policy)
    if available is not True:
        _refuse(CHAIN_SOURCE_UNAVAILABLE,
                "delegation-chain source unavailable; fail closed, "
                "never allow (verifier_policy_input=%r)" % (policy_input,))
    if stale is True:
        # Explicit stale verdict, not a silent pass and not an allow.
        return {"verdict": "stale",
                "code": CHAIN_SOURCE_STALE,
                "detail": "chain source input is stale; explicit "
                          "stale verdict, not a pass"}
    return None


def _authority_status(hop, policy):
    """Resolve a hop's authority status from the policy's authority
    store. Unknown authority ids are unavailable: the verifier cannot
    assume authority it cannot see."""
    store = policy.get("authority_store", {})
    if not isinstance(store, dict):
        _refuse(VERIFIER_INPUT_MALFORMED,
                "authority_store must be a dict")
    authority_id = hop.get("authority_id")
    if authority_id is None:
        return "valid", None
    if not isinstance(authority_id, str) or not authority_id:
        _refuse(VERIFIER_INPUT_MALFORMED,
                "hop authority_id must be a non-empty string")
    record = store.get(authority_id)
    if record is None:
        return "unavailable", authority_id
    if not isinstance(record, dict):
        _refuse(VERIFIER_INPUT_MALFORMED,
                "authority_store[%r] must be a dict" % (authority_id,))
    status = record.get("status", "valid")
    if status not in _VALID_STATUSES:
        _refuse(VERIFIER_INPUT_MALFORMED,
                "authority_store[%r] status %r not in %s"
                % (authority_id, status, _VALID_STATUSES))
    return status, authority_id


def _check_lapse_citation_first(authority_id, hop):
    """Lapse-registered authority citations route through
    gov.stale_authority BEFORE the authority-store lookup: a lapsed
    draft's citation names the more specific, more dangerous claim, and
    a store calling a lapsed draft "valid" is exactly the
    green-on-lapsed-authority defect."""
    from gov import stale_authority as _sa
    if authority_id not in _sa.LAPSED_AUTHORITIES:
        return
    minted_at = hop.get("authority_minted_at")
    if minted_at is None:
        _refuse(AUTHORITY_STALE,
                "authority %r cites a lapse-registered draft without a "
                "receipt timestamp; citation freshness is "
                "unverifiable" % (authority_id,))
    _check_lapse_citation(authority_id, hop, None)


def _check_lapse_citation(authority_id, hop, policy):
    """Route lapse-registered authority citations through
    gov.stale_authority. A re-raised stale-authority refusal carries the
    original taxonomy code; the refusal is never passed on legacy
    text."""
    minted_at = hop.get("authority_minted_at")
    if minted_at is None:
        return
    from gov import stale_authority as _sa
    try:
        _sa.check_authority(authority_id, minted_at)
    except _sa.StaleAuthorityError as exc:
        if exc.code != _STALE_AUTHORITY_CODE:
            raise
        _refuse(exc.code, "lapse-registered authority citation: %s"
                % (exc.detail,))
    # A downgraded-provenance acceptance is not fresh authority: a
    # pre-lapse receipt re-read as live authority is still stale.
    _refuse(AUTHORITY_STALE,
            "authority %r was accepted only with downgraded provenance "
            "(lapsed draft); a verifier that passes it as live authority "
            "repeats the green-on-lapsed-authority defect" % (authority_id,))


def _check_hop(hop, policy, policy_input):
    """Proof verifies but authority revoked/expired -> refuse. This is
    the proof != authority fail-safe: the signature may verify and the
    hop is still not authorized."""
    authority_id = hop.get("authority_id")
    if authority_id is not None and isinstance(authority_id, str) \
            and authority_id:
        _check_lapse_citation_first(authority_id, hop)
    status, authority_id = _authority_status(hop, policy)
    if status == "unavailable":
        _refuse(AUTHORITY_UNAVAILABLE,
                "authority source unavailable for %r; deterministic "
                "fail-safe, not a timeout-retry loop "
                "(verifier_policy_input=%r)" % (authority_id, policy_input))
    if status in ("revoked", "expired"):
        signed = hop.get("signature_present") is True
        _refuse(AUTHORITY_STALE,
                "proof verification does not establish authority: "
                "authority %r is %s (signature_present=%s); "
                "refused fail-safe (verifier_policy_input=%r)"
                % (authority_id, status, signed, policy_input))
    return {"participant_id": hop["participant_id"],
            "signature_present": hop.get("signature_present") is True,
            "authority_id": authority_id,
            "authority_status": status}


def _audit_expected(chain, policy):
    """Declared expected-participant audit via gov.expected_participants.
    The module's own codes propagate; authentication stays out of
    scope, exactly as documented there."""
    workload = policy.get("expected_workload")
    declarations = policy.get("expected_declarations")
    if workload is None and declarations is None:
        return None
    if not (isinstance(workload, str) and workload) or not isinstance(
            declarations, dict):
        _refuse(VERIFIER_INPUT_MALFORMED,
                "expected_workload and expected_declarations must be a "
                "non-empty string and a dict")
    from gov import expected_participants as _ep
    ep_policy = _ep.ExpectedParticipantsPolicy(declarations)
    expected = ep_policy.expected_for(workload)
    signed = [hop["participant_id"] for hop in chain
              if hop.get("signature_present") is True]
    missing = [p for p in expected if p not in signed]
    if missing:
        _ep._refuse(_ep.EXPECTED_PARTICIPANT_MISSING,
                    "expected participants missing from chain: %s"
                    % (", ".join(missing),))
    unexpected = [p for p in signed if p not in expected]
    if unexpected:
        _ep._refuse(_ep.UNEXPECTED_PARTICIPANT_SIGNED,
                    "signed hops are not declared expected: %s"
                    % (", ".join(unexpected),))
    return list(expected)


def evaluate_delegation_chain(chain, verifier_policy):
    """Evaluate a delegation chain fail-closed from the verifier's side.

    Returns a verdict dict naming the pinned
    ``verifier_policy_input`` that produced it. Raises
    ``VerifierFailclosedError`` with a taxonomy code on every
    fail-closed path.
    """
    policy_input = _policy(verifier_policy)
    hops = _hops(chain)
    source_verdict = _check_chain_source(verifier_policy, policy_input)
    if source_verdict is not None:
        source_verdict["verifier_policy_input"] = policy_input
        return source_verdict
    hop_results = [_check_hop(hop, verifier_policy, policy_input)
                   for hop in hops]
    expected = _audit_expected(hops, verifier_policy)
    return {"verdict": "allow",
            "code": None,
            "verifier_policy_input": policy_input,
            "hops": hop_results,
            "expected_participants": expected}
