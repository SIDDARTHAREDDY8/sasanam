"""Delegated approvals: delegation receipt chains composed with approval requests.

Wave-300 lane 5. Stdlib only. Additive: this module changes no existing
API -- it composes ``gov/delegation.py`` (signed, chained, attenuated
receipts), ``gov/approval_request.py`` (signed, time-boxed approval
requests), and ``gov/delegation_revocation.py`` (revocation liveness).

A DELEGATED approval is an approval request issued by an agent acting
under a delegation receipt chain on the delegator's behalf. The request
carries three delegation bindings in its context digests (digests, never
raw chains):

* ``delegation_chain_digest`` -- sha256 of the canonical receipt-id list
  of the presented chain (the ids commit to the full receipt bodies, so
  the digest commits to the whole chain);
* ``delegator_id_digest`` -- sha256 of the chain root's ``delegator_id``;
* ``delegation_right_digest`` -- sha256 of the closed-vocabulary right
  the delegatee acts under.

``issue_delegated_request`` binds these digests at issue time (signed by
the delegatee, i.e. the chain tip holder). ``verify_delegated_request``
checks, in order: the approval-request envelope (shape, digest-binding,
action binding, expiry, signature -- the existing
``approval-request-*`` codes), the three digest bindings (the two new
``delegation-approval-*`` codes below), optional revocation liveness
(``delegation-revoked`` et al. via
``DelegationRevoker.assert_live_native`` -- revocation beats expiry),
and the delegation chain itself via ``gov/delegation.py::authorize``
(chain validity, holder key continuity, rights-narrowing, leaf rights
covering the presented right, allowed targets -- the existing
``delegation-*`` codes). No new codes are minted for chain failures:
the delegation module already says exactly what broke.

The requester of a delegated request is the DELEGATEE (the chain tip
holder): the human sees WHO is requesting plus the delegation proof.
``issue`` refuses ``delegation-invalid`` unless the requester is the
chain tip's delegatee (fail fast at issue; re-checked at verify via
``authorize``).

Quorum composition (documented, not wired): a delegated request is a
valid approval request, so ``gov/approval_quorum.tally`` counts its
votes unchanged -- the delegation proof is part of the REQUEST, not the
votes. The future "delegated requests need N+1 approvals" hook is in
``gov/approval_quorum.py::tally`` after ``validate_request(request)``:
extend the quorum request shape (or pass the approval-request envelope
alongside) to detect the ``delegation_chain_digest`` binding and count
against a new ``QuorumPredicate.delegated_min_approvals`` field. Not
built here.

Queue composition: ``gov/approvals.ApprovalQueue.queue(...,
approval_request=...)`` verifies any valid request envelope at queue
time and re-verifies at every ``decide()``; a delegated request
envelope is a valid envelope, so delegated requests are accepted
transparently. This module does not change the queue.

Threat model: the delegator root key is the trust anchor
(compromised-host class); expiry uses caller-supplied instants
(deployment-owned clock); the revocation list is per-verifier
(distribution deployment-owned). A verifier that never presents a
revocation list accepts revoked-but-unexpired chains -- pass
``revoker`` when revocation matters.

$0 spend, synthetic/local, deterministic. Stdlib only.
"""

import hashlib
import json
import time
from collections.abc import Mapping

from gov import approval_request as _ar
from gov import delegation as _dg

# ---------------------------------------------------------------------------
# Codes (F351: every refusal carries one). Two are minted by this lane; all
# chain/request failures reuse the existing delegation-* and
# approval-request-* codes.
# ---------------------------------------------------------------------------

DA_CHAIN_MISMATCH = "delegation-approval-chain-mismatch"
DA_RIGHT_MISMATCH = "delegation-approval-right-mismatch"

# Context digest names bound into the approval request at issue time.
CTX_CHAIN_DIGEST = "delegation_chain_digest"
CTX_DELEGATOR_DIGEST = "delegator_id_digest"
CTX_RIGHT_DIGEST = "delegation_right_digest"

# The delegation package shape returned by issue_delegated_request.
PACKAGE_FIELDS = ("envelope", "chain", "delegation_right")


class DelegationApprovalError(Exception):
    """Code-first exception for delegated-approval composition failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise DelegationApprovalError(detail, code=code)


# F345-class audit sink: records digests/ids only; never breaks the module.
_SINK = None


def set_sink(fn):
    """Install an audit sink ``fn(record)``; None clears it."""
    global _SINK
    _SINK = fn


def _emit(event, detail=None):
    if _SINK is None:
        return
    try:
        _SINK({"event": event, "detail": detail or {}})
    except Exception:
        pass


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _shahex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _is_agent_id(value):
    return (isinstance(value, str) and 1 <= len(value) <= 64
            and value[0].isalpha()
            and all(c.isalnum() or c in "-_" for c in value))


def chain_digest(chain):
    """Digest binding for a delegation chain: sha256 of the canonical
    receipt-id list. Each link's ``receipt_id`` commits to its full body
    (``gov/delegation.py`` recomputes it in ``_check_receipt_shape`` and
    refuses ``delegation-chain-broken`` on mismatch), so the digest
    commits to the whole chain. Refuses ``delegation-invalid`` on a
    malformed chain."""
    if not isinstance(chain, (list, tuple)) or not chain:
        _fail(_dg.DELEGATION_INVALID,
              "chain must be a non-empty list of receipts")
    ids = []
    for i, link in enumerate(chain):
        if not isinstance(link, Mapping):
            _fail(_dg.DELEGATION_INVALID,
                  "chain link %d is not a mapping" % i)
        rid = link.get("receipt_id")
        if not _is_hex64(rid):
            _fail(_dg.DELEGATION_INVALID,
                  "chain link %d has no 64-hex receipt_id" % i)
        ids.append(rid)
    return _shahex(_canonical(ids))


def _check_package_shape(package):
    if not isinstance(package, dict):
        _fail(_dg.DELEGATION_INVALID,
              "package must be a dict; got %r" % (type(package),))
    for field in PACKAGE_FIELDS:
        if field not in package:
            _fail(_dg.DELEGATION_INVALID,
                  "package missing field %r" % (field,))
    if set(package.keys()) - set(PACKAGE_FIELDS):
        _fail(_dg.DELEGATION_INVALID,
              "package has unknown fields: %r"
              % sorted(set(package.keys()) - set(PACKAGE_FIELDS)))
    return package


def issue_delegated_request(*, chain, delegation_right, action,
                            requester_agent_id, requester_principal,
                            requester_pubkey_hex, requester_seed,
                            context_digests=None, approver_schema,
                            ttl_seconds, issued_at=None):
    """Issue an approval request for ``action`` made by the delegatee
    acting under ``chain``.

    ``chain`` is root-first [root, ..., leaf] of ``gov/delegation.py``
    receipts (mappings; frozen MappingProxyTypes accepted).
    ``delegation_right`` is the closed-vocabulary right the delegatee
    acts under (e.g. ``"tool.invoke"``); it must be in
    ``gov/delegation.RIGHTS``. ``action`` is the approval action
    ``{tool, args}``; its digest is what the human approves.
    ``requester_*`` identify and sign as the delegatee: the requester
    MUST be the chain tip's delegatee (holder continuity is key
    continuity -- a third party cannot request on a chain it does not
    hold).

    The request binds ``delegation_chain_digest``,
    ``delegator_id_digest``, and ``delegation_right_digest`` into its
    context digests. Returns the delegation package
    ``{"envelope", "chain", "delegation_right"}``. The chain itself is
    NOT verified here (no trust roots at issue time necessarily) --
    the request is a signed declaration; verification is the
    verifier's job (``verify_delegated_request``). All refusals coded.
    """
    chain = list(chain) if isinstance(chain, (list, tuple)) else None
    if chain is None or not chain:
        _fail(_dg.DELEGATION_INVALID,
              "chain must be a non-empty list of receipts")
    for i, link in enumerate(chain):
        if not isinstance(link, Mapping):
            _fail(_dg.DELEGATION_INVALID,
                  "chain link %d is not a mapping" % i)
    leaf = chain[-1]
    if delegation_right not in _dg.RIGHTS:
        _fail(_dg.DELEGATION_INVALID,
              "delegation_right %r outside the closed vocabulary"
              % (delegation_right,))
    leaf_delegatee = leaf.get("delegatee_id")
    if requester_agent_id != leaf_delegatee:
        _fail(_dg.DELEGATION_INVALID,
              "requester %r is not the chain tip's delegatee %r; only "
              "the holder can request on a chain"
              % (requester_agent_id, leaf_delegatee))
    if not _is_agent_id(requester_agent_id):
        _fail(_dg.DELEGATION_INVALID, "bad requester_agent_id")
    root_delegator = chain[0].get("delegator_id")
    if not _is_agent_id(root_delegator):
        _fail(_dg.DELEGATION_INVALID,
              "chain root has no valid delegator_id")

    digests = dict(context_digests) if context_digests else {}
    for name in (CTX_CHAIN_DIGEST, CTX_DELEGATOR_DIGEST, CTX_RIGHT_DIGEST):
        if name in digests:
            _fail(_dg.DELEGATION_INVALID,
                  "context_digests must not predefine reserved binding %r"
                  % (name,))
    digests[CTX_CHAIN_DIGEST] = chain_digest(chain)
    digests[CTX_DELEGATOR_DIGEST] = _shahex(root_delegator.encode("utf-8"))
    digests[CTX_RIGHT_DIGEST] = _shahex(delegation_right.encode("utf-8"))

    action_digest = _ar.action_digest_for(action)
    envelope = _ar.issue(
        action_digest=action_digest,
        requester_agent_id=requester_agent_id,
        requester_principal=requester_principal,
        requester_pubkey_hex=requester_pubkey_hex,
        context_digests=digests,
        approver_schema=approver_schema,
        ttl_seconds=ttl_seconds,
        issued_at=issued_at,
        requester_seed=requester_seed,
    )
    _emit("delegated-request-issued", {
        "chain_digest": digests[CTX_CHAIN_DIGEST][:16],
        "delegator_id": root_delegator,
        "right": delegation_right,
    })
    return {
        "envelope": envelope,
        "chain": [dict(link) for link in chain],
        "delegation_right": delegation_right,
    }


def verify_delegated_request(package, *, at=None, trust_roots, revoker=None):
    """Verify a delegated request package.

    Checks, in order:

    1. the approval-request envelope (shape, digest-binding, action
       binding, expiry, signature) -- ``approval-request-*`` codes;
    2. the digest bindings: the presented chain's digest, the root
       delegator's digest, and the presented right's digest must match
       the request's bound context digests -- ``delegation-approval-
       chain-mismatch`` / ``delegation-approval-right-mismatch``;
    3. revocation liveness, when ``revoker`` (a
       ``gov/delegation_revocation.DelegationRevoker``) is given --
       ``delegation-revoked`` et al. (revocation beats expiry);
    4. the delegation chain via ``gov/delegation.py::authorize`` --
       chain validity, holder key continuity, rights-narrowing, the
       leaf's rights covering ``delegation_right``, allowed targets --
       the existing ``delegation-*`` codes.

    ``at`` is the verification instant (int epoch; defaults to wall
    clock). ``trust_roots`` are the accepted root delegator pubkeys
    (hex), as for ``gov/delegation.verify_chain``. Returns a verdict
    dict on success; refuses coded otherwise.
    """
    package = _check_package_shape(package)
    envelope = package["envelope"]
    chain = package["chain"]
    delegation_right = package["delegation_right"]

    if not isinstance(chain, list) or not chain:
        _fail(_dg.DELEGATION_INVALID, "package chain must be a non-empty list")
    if not isinstance(delegation_right, str) or not delegation_right:
        _fail(_dg.DELEGATION_INVALID,
              "package delegation_right must be a non-empty string")

    moment = int(time.time()) if at is None else at
    if not isinstance(moment, int) or isinstance(moment, bool):
        _fail(_dg.DELEGATION_INVALID, "at must be an int epoch")

    # 1. The approval request itself.
    body = _ar.verify_request(envelope, now=moment)
    ctx = body["context_digests"]
    for name in (CTX_CHAIN_DIGEST, CTX_DELEGATOR_DIGEST, CTX_RIGHT_DIGEST):
        if name not in ctx:
            _fail(DA_CHAIN_MISMATCH,
                  "request carries no delegation binding %r: not a "
                  "delegated request" % (name,))

    # 2. The digest bindings.
    if chain_digest(chain) != ctx[CTX_CHAIN_DIGEST]:
        _fail(DA_CHAIN_MISMATCH,
              "presented chain does not match the request's bound "
              "delegation_chain_digest")
    root_delegator = chain[0].get("delegator_id")
    if not isinstance(root_delegator, str) or \
            _shahex(root_delegator.encode("utf-8")) != ctx[CTX_DELEGATOR_DIGEST]:
        _fail(DA_CHAIN_MISMATCH,
              "presented chain's root delegator does not match the "
              "request's bound delegator_id_digest")
    if _shahex(delegation_right.encode("utf-8")) != ctx[CTX_RIGHT_DIGEST]:
        _fail(DA_RIGHT_MISMATCH,
              "presented delegation_right does not match the request's "
              "bound delegation_right_digest")
    if delegation_right not in _dg.RIGHTS:
        _fail(_dg.DELEGATION_INVALID,
              "delegation_right %r outside the closed vocabulary"
              % (delegation_right,))

    # 3. Revocation liveness (when the verifier cares).
    if revoker is not None:
        revoker.assert_live_native(list(chain), at=moment,
                                   trust_roots=trust_roots)

    # 4. The delegation chain: validity, holder continuity, rights.
    verdict = _dg.authorize(chain, delegation_right,
                            body["requester"]["agent_id"],
                            at=moment, trust_roots=trust_roots)
    _emit("delegated-request-verified", {
        "leaf_receipt_id": verdict["leaf_receipt_id"],
        "delegator_id": root_delegator,
        "right": delegation_right,
    })
    return {
        "request": body,
        "delegation_verdict": verdict,
        "leaf_receipt_id": verdict["leaf_receipt_id"],
        "delegator_id": root_delegator,
        "delegation_right": delegation_right,
    }
