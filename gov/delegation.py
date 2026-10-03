"""Signed, chained, attenuated delegation receipts (capnproto + Agoric OCap).

Pattern lineage: capnproto/capnproto (MIT) -- unforgeable capability
references as the delegation primitive (delegation = passing a
reference; attenuation = interposition, wrapping narrower;
confused-deputy resistance by construction); Agoric/agoric-sdk
(Apache-2.0) -- OCap discipline (no ambient authority; authority
arrives as explicit endowments), ERTP-style attenuated
rights-objects, Zoe escrow/offer-safety for delegated multi-step
work. Mechanisms only; no vendored code; stdlib only.

Standing design rule: "Delegation narrows, never widens -- every
handoff is a signed, attenuated receipt on the chain."

A **delegation receipt** is a signed, chained, attenuated record::

    {receipt_id, schema, parent_receipt_id, delegator_id, delegatee_id,
     delegator_pubkey, rights, constraints, designated_object,
     attenuation_digest, depth, signature}

* root receipts (``parent_receipt_id=None``) are self-signed by the
  delegator's key; every downstream receipt embeds its parent's
  digest and proves rights-narrowing: a receipt claiming rights
  WIDER than its parent refuses coded ``delegation-widened``;
* no ambient authority: every delegated action is presented with its
  receipt chain; the verifier walks the chain to the root, checking
  each link's signature (``ed25519.verify(...) is True``, wave-243),
  rights-narrowing, holder continuity
  (``link[i].delegator == link[i-1].delegatee``), and expiry. A
  broken link refuses coded ``delegation-chain-broken``;
* attenuation by interposition: ``attenuate`` returns a NEW signed
  receipt wrapping the old (never mutates); the old receipt stays
  valid for its own rights -- capnproto's wrapping-narrower;
* Zoe-style escrow: ``escrow_begin`` declares a multi-step task's
  expected effects up front (offer-safety); ``escrow_commit``
  requires every step's receipt chain to verify; ``escrow_abort``
  is always available and refuses nothing;
* depth bound: ``max_depth`` (1..16); delegating at max depth
  refuses coded ``delegation-depth-exceeded``.

This module is a DECISION layer: ``verify_chain`` and ``authorize``
return verdicts; ``issue``/``attenuate`` construct signed records.
Actual effecting of delegated actions is deployment-owned. All
refusals raise ``DelegationError`` carrying the machine code (the
F351 contract). The audit sink is F345-class: it never breaks the
module. Timestamps are caller-supplied freshness markers (wave-292
decay precedent), not a trusted clock.

Composition points (documented here; this lane is self-contained
and changes no existing API):

* ``gov/approval_request.py``: a receipt's ``designated_object`` is
  an action digest -- the same digest shape an approval request
  binds, so a delegation receipt can designate exactly what an
  approval request approved;
* ``gov/coordination_lease.py``: a lease grant can be carried as a
  receipt right (``lease.acquire``); fencing tokens remain the
  lease module's own enforcement;
* wave-293 tool-sequence rules: a tool handed to a sub-agent is a
  capability reference (the receipt), never a resolvable name --
  the sub-agent cannot reach tools it was not handed.

Honest limits: no revocation yet (a follow-on lane); identity
binding is key-based, not hardware-attested (a follow-on lane);
the root key is the trust anchor (compromised-host class).
"""

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType

from gov import ed25519

# ---------------------------------------------------------------------------
# Codes (the F351 contract: every refusal carries a machine code).
# ---------------------------------------------------------------------------

DELEGATION_INVALID = "delegation-invalid"
DELEGATION_WIDENED = "delegation-widened"
DELEGATION_CHAIN_BROKEN = "delegation-chain-broken"  # pre-existing code, reused
DELEGATION_DEPTH_EXCEEDED = "delegation-depth-exceeded"
DELEGATION_ESCROW_VIOLATED = "delegation-escrow-violated"
# Reused pre-existing codes (not minted by this lane):
DELEGATION_EXPIRED = "delegation-expired"
DELEGATION_ROOT_UNTRUSTED = "delegation-root-untrusted"

SCHEMA = "delegation-receipt/v1"
ESCROW_SCHEMA = "delegation-escrow/v1"

# Closed rights vocabulary: subset-only, never widened downstream.
RIGHTS = frozenset({
    "tool.invoke",
    "memory.read",
    "memory.write",
    "approval.request",
    "lease.acquire",
    "subagent.spawn",
    "escrow.commit",
})

_MAX_DEPTH_BOUND = 16
_HEX64 = 64


class DelegationError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = DELEGATION_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise DelegationError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_sink = None


def set_sink(fn):
    """Install the audit sink (or None to clear). F345-class: a
    failing sink never breaks the module."""
    global _sink
    _sink = fn


def _emit(event, receipt_id=None, detail=None):
    if _sink is None:
        return
    try:
        _sink({"event": event, "receipt_id": receipt_id, "detail": detail})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Canonical encoding / digests.
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == _HEX64
            and all(c in "0123456789abcdef" for c in value))


def _is_agent_id(value):
    return (isinstance(value, str) and 1 <= len(value) <= 64
            and all(c.isalnum() or c in "-_." for c in value))


# ---------------------------------------------------------------------------
# Receipt construction.
# ---------------------------------------------------------------------------

_UNSIGNED_FIELDS = (
    "receipt_id", "schema", "parent_receipt_id", "delegator_id",
    "delegatee_id", "delegator_pubkey", "delegatee_pubkey", "rights",
    "constraints", "designated_object", "attenuation_digest", "depth",
)


def _unsigned_body(**fields):
    body = {k: fields[k] for k in _UNSIGNED_FIELDS if k in fields}
    return body


def _check_rights(rights):
    if not isinstance(rights, (list, tuple, set, frozenset)) or not rights:
        _fail(DELEGATION_INVALID, "rights must be a non-empty collection")
    rights = frozenset(rights)
    unknown = rights - RIGHTS
    if unknown:
        _fail(DELEGATION_INVALID,
              "rights outside the closed vocabulary: %s" % sorted(unknown))
    return rights


def _check_constraints(constraints, delegatee_id=None):
    if not isinstance(constraints, dict):
        _fail(DELEGATION_INVALID, "constraints must be a mapping")
    try:
        expires_at = constraints["expires_at"]
        max_depth = constraints["max_depth"]
        allowed_targets = constraints.get("allowed_targets", ())
    except KeyError:
        _fail(DELEGATION_INVALID,
              "constraints must carry expires_at and max_depth")
    if not isinstance(expires_at, int) or expires_at <= 0:
        _fail(DELEGATION_INVALID, "expires_at must be a positive int")
    if not isinstance(max_depth, int) or not 1 <= max_depth <= _MAX_DEPTH_BOUND:
        _fail(DELEGATION_INVALID,
              "max_depth must be an int in [1, %d]" % _MAX_DEPTH_BOUND)
    if not isinstance(allowed_targets, (list, tuple)):
        _fail(DELEGATION_INVALID, "allowed_targets must be a list/tuple")
    for target in allowed_targets:
        if not _is_agent_id(target):
            _fail(DELEGATION_INVALID, "bad allowed_target: %r" % (target,))
    if allowed_targets and delegatee_id not in allowed_targets:
        _fail(DELEGATION_INVALID,
              "allowed_targets must include the delegatee")
    return {
        "expires_at": expires_at,
        "max_depth": max_depth,
        "allowed_targets": tuple(allowed_targets),
    }


def issue(delegator_seed, delegator_id, delegatee_id, delegatee_pubkey,
          rights, *, parent=None, constraints=None,
          designated_object=None, issued_at=None):
    """Issue a signed delegation receipt.

    Root (``parent=None``): self-signed by the delegator's key.
    Downstream: ``rights`` must be a subset of the parent's rights
    (else ``delegation-widened``), the new depth must not exceed the
    parent's ``max_depth`` (else ``delegation-depth-exceeded``), and
    the signing key must be the key the parent designated for its
    delegatee (holder continuity is KEY continuity, not label
    continuity -- a third party cannot re-delegate a capability it
    does not hold; else ``delegation-chain-broken``).
    """
    if not isinstance(delegator_seed, (bytes, bytearray)) \
            or len(delegator_seed) != 32:
        _fail(DELEGATION_INVALID, "delegator_seed must be 32 bytes")
    if not _is_agent_id(delegator_id):
        _fail(DELEGATION_INVALID, "bad delegator_id")
    if not _is_agent_id(delegatee_id):
        _fail(DELEGATION_INVALID, "bad delegatee_id")
    if not isinstance(delegatee_pubkey, str) or len(delegatee_pubkey) != 64:
        _fail(DELEGATION_INVALID, "delegatee_pubkey must be 64 hex")
    try:
        bytes.fromhex(delegatee_pubkey)
    except ValueError:
        _fail(DELEGATION_INVALID, "delegatee_pubkey not hex")
    rights = _check_rights(rights)
    constraints = _check_constraints(
        constraints if constraints is not None
        else {"expires_at": 2 ** 62, "max_depth": _MAX_DEPTH_BOUND},
        delegatee_id)
    if designated_object is not None and not _is_hex64(designated_object):
        _fail(DELEGATION_INVALID, "designated_object must be 64 hex or None")
    if issued_at is not None and not isinstance(issued_at, int):
        _fail(DELEGATION_INVALID, "issued_at must be an int or None")

    delegator_pubkey = ed25519.publickey(bytes(delegator_seed)).hex()

    parent_receipt_id = None
    attenuation_digest = None
    depth = 0
    if parent is not None:
        _check_receipt_shape(parent)
        if issued_at is not None and issued_at >= parent["constraints"]["expires_at"]:
            _fail(DELEGATION_EXPIRED, "parent receipt expired at issue time")
        if delegator_pubkey != parent["delegatee_pubkey"]:
            _fail(DELEGATION_CHAIN_BROKEN,
                  "signing key is not the parent's designated delegatee key")
        if delegator_id != parent["delegatee_id"]:
            _fail(DELEGATION_CHAIN_BROKEN,
                  "delegator label does not match the parent's delegatee")
        if not rights <= frozenset(parent["rights"]):
            _fail(DELEGATION_WIDENED,
                  "rights %s exceed parent rights %s"
                  % (sorted(rights), sorted(parent["rights"])))
        depth = parent["depth"] + 1
        if depth > parent["constraints"]["max_depth"]:
            _fail(DELEGATION_DEPTH_EXCEEDED,
                  "depth %d exceeds max_depth %d"
                  % (depth, parent["constraints"]["max_depth"]))
        parent_receipt_id = parent["receipt_id"]
        attenuation_digest = _digest_hex(
            _canonical(sorted(parent["rights"])))

    body = {
        "receipt_id": None,  # filled below
        "schema": SCHEMA,
        "parent_receipt_id": parent_receipt_id,
        "delegator_id": delegator_id,
        "delegatee_id": delegatee_id,
        "delegator_pubkey": delegator_pubkey,
        "delegatee_pubkey": delegatee_pubkey.lower(),
        "rights": sorted(rights),
        "constraints": {
            "expires_at": constraints["expires_at"],
            "max_depth": constraints["max_depth"],
            "allowed_targets": list(constraints["allowed_targets"]),
        },
        "designated_object": designated_object,
        "attenuation_digest": attenuation_digest,
        "depth": depth,
    }
    body["receipt_id"] = _digest_hex(_canonical(
        {k: body[k] for k in _UNSIGNED_FIELDS if k != "receipt_id"}))
    signature = ed25519.sign(bytes(delegator_seed),
                             _canonical(
                                 {k: body[k] for k in _UNSIGNED_FIELDS}))
    receipt = dict(body)
    receipt["signature"] = signature.hex()
    _emit("delegation-issued", receipt_id=receipt["receipt_id"],
          detail={"depth": depth, "rights": sorted(rights)})
    return MappingProxyType(receipt)


def _check_receipt_shape(receipt):
    if not isinstance(receipt, Mapping):
        _fail(DELEGATION_INVALID, "receipt must be a mapping")
    for field in _UNSIGNED_FIELDS:
        if field not in receipt:
            _fail(DELEGATION_INVALID, "receipt missing field %r" % field)
    if receipt.get("schema") != SCHEMA:
        _fail(DELEGATION_INVALID, "unknown receipt schema")
    if not _is_hex64(receipt["receipt_id"]):
        _fail(DELEGATION_INVALID, "bad receipt_id")
    parent = receipt["parent_receipt_id"]
    if parent is not None and not _is_hex64(parent):
        _fail(DELEGATION_INVALID, "bad parent_receipt_id")
    if not _is_agent_id(receipt["delegator_id"]):
        _fail(DELEGATION_INVALID, "bad delegator_id")
    if not _is_agent_id(receipt["delegatee_id"]):
        _fail(DELEGATION_INVALID, "bad delegatee_id")
    pubkey = receipt["delegator_pubkey"]
    if not isinstance(pubkey, str) or len(pubkey) != 64:
        _fail(DELEGATION_INVALID, "bad delegator_pubkey")
    try:
        bytes.fromhex(pubkey)
    except ValueError:
        _fail(DELEGATION_INVALID, "delegator_pubkey not hex")
    dpubkey = receipt["delegatee_pubkey"]
    if not isinstance(dpubkey, str) or len(dpubkey) != 64:
        _fail(DELEGATION_INVALID, "bad delegatee_pubkey")
    try:
        bytes.fromhex(dpubkey)
    except ValueError:
        _fail(DELEGATION_INVALID, "delegatee_pubkey not hex")
    _check_rights(receipt["rights"])
    _check_constraints(receipt["constraints"], receipt["delegatee_id"])
    desig = receipt["designated_object"]
    if desig is not None and not _is_hex64(desig):
        _fail(DELEGATION_INVALID, "bad designated_object")
    atten = receipt["attenuation_digest"]
    if atten is not None and not _is_hex64(atten):
        _fail(DELEGATION_INVALID, "bad attenuation_digest")
    if not isinstance(receipt["depth"], int) or receipt["depth"] < 0:
        _fail(DELEGATION_INVALID, "bad depth")
    sig = receipt.get("signature")
    if not isinstance(sig, str) or len(sig) != 128:
        _fail(DELEGATION_INVALID, "bad signature")
    try:
        bytes.fromhex(sig)
    except ValueError:
        _fail(DELEGATION_INVALID, "signature not hex")
    # receipt_id must be the digest of the unsigned body (no silent
    # field swaps after signing).
    expected = _digest_hex(_canonical(
        {k: receipt[k] for k in _UNSIGNED_FIELDS if k != "receipt_id"}))
    if receipt["receipt_id"] != expected:
        _fail(DELEGATION_CHAIN_BROKEN, "receipt_id does not match body")
    return receipt


def attenuate(receipt, narrower_rights, holder_seed, *, issued_at=None):
    """Attenuation by interposition (capnproto): return a NEW signed
    receipt wrapping ``receipt`` with ``narrower_rights``. The holder
    (the receipt's delegatee) wraps their own capability; the old
    receipt stays valid for its own rights. Never mutates."""
    _check_receipt_shape(receipt)
    narrower = _check_rights(narrower_rights)
    if not narrower <= frozenset(receipt["rights"]):
        _fail(DELEGATION_WIDENED,
              "attenuated rights exceed the wrapped receipt's rights")
    return issue(
        holder_seed,
        receipt["delegatee_id"],
        receipt["delegatee_id"],
        receipt["delegatee_pubkey"],
        narrower,
        parent=receipt,
        constraints={
            "expires_at": receipt["constraints"]["expires_at"],
            "max_depth": receipt["constraints"]["max_depth"],
            "allowed_targets":
                list(receipt["constraints"]["allowed_targets"]),
        },
        designated_object=receipt["designated_object"],
        issued_at=issued_at,
    )


# ---------------------------------------------------------------------------
# Chain verification: no ambient authority.
# ---------------------------------------------------------------------------

def verify_chain(receipt, chain, *, at, trust_roots):
    """Walk ``chain`` (root first, leaf last) to the root, checking
    each link's signature (``is True``, wave-243), rights-narrowing,
    holder continuity, depth, attenuation digests, and expiry at
    instant ``at``. The root's delegator key must be in
    ``trust_roots`` (else ``delegation-root-untrusted``). Returns a
    verdict dict; refuses coded on the first broken link."""
    if not isinstance(chain, (list, tuple)) or not chain:
        _fail(DELEGATION_INVALID, "chain must be a non-empty sequence")
    if not isinstance(at, int):
        _fail(DELEGATION_INVALID, "at must be an int instant")
    roots = set()
    for root in trust_roots or ():
        if isinstance(root, str):
            roots.add(root.lower())
        elif isinstance(root, (bytes, bytearray)):
            roots.add(bytes(root).hex())

    _check_receipt_shape(receipt)
    if chain[-1]["receipt_id"] != receipt["receipt_id"]:
        _fail(DELEGATION_CHAIN_BROKEN, "leaf does not match the chain tip")

    previous = None
    for index, link in enumerate(chain):
        _check_receipt_shape(link)
        pubkey = bytes.fromhex(link["delegator_pubkey"])
        body = _canonical({k: link[k] for k in _UNSIGNED_FIELDS})
        if ed25519.verify(pubkey, body,
                           bytes.fromhex(link["signature"])) is not True:
            _fail(DELEGATION_CHAIN_BROKEN,
                  "link %d signature does not verify" % index)
        if at >= link["constraints"]["expires_at"]:
            _fail(DELEGATION_EXPIRED,
                  "link %d expired at instant %d" % (index, at))
        if link["depth"] > link["constraints"]["max_depth"]:
            _fail(DELEGATION_DEPTH_EXCEEDED,
                  "link %d depth exceeds max_depth" % index)
        if previous is None:
            if link["parent_receipt_id"] is not None or link["depth"] != 0:
                _fail(DELEGATION_INVALID, "root link malformed")
            if link["attenuation_digest"] is not None:
                _fail(DELEGATION_INVALID,
                      "root link must not carry an attenuation digest")
            if link["delegator_pubkey"].lower() not in roots:
                _fail(DELEGATION_ROOT_UNTRUSTED,
                      "root key not in the trust set")
        else:
            if link["parent_receipt_id"] != previous["receipt_id"]:
                _fail(DELEGATION_CHAIN_BROKEN,
                      "link %d parent linkage broken" % index)
            if link["delegator_pubkey"].lower() != \
                    previous["delegatee_pubkey"].lower():
                _fail(DELEGATION_CHAIN_BROKEN,
                      "link %d holder key continuity broken" % index)
            if link["delegator_id"] != previous["delegatee_id"]:
                _fail(DELEGATION_CHAIN_BROKEN,
                      "link %d holder label continuity broken" % index)
            if link["depth"] != previous["depth"] + 1:
                _fail(DELEGATION_INVALID,
                      "link %d depth inconsistent" % index)
            if not frozenset(link["rights"]) <= frozenset(previous["rights"]):
                _fail(DELEGATION_WIDENED,
                      "link %d rights exceed its parent" % index)
            expected_atten = _digest_hex(
                _canonical(sorted(previous["rights"])))
            if link["attenuation_digest"] != expected_atten:
                _fail(DELEGATION_CHAIN_BROKEN,
                      "link %d attenuation digest mismatch" % index)
        previous = link

    verdict = {
        "verified": True,
        "leaf_receipt_id": receipt["receipt_id"],
        "depth": len(chain) - 1,
        "rights": sorted(chain[-1]["rights"]),
        "delegatee_id": chain[-1]["delegatee_id"],
    }
    _emit("delegation-chain-verified",
          receipt_id=receipt["receipt_id"],
          detail={"depth": verdict["depth"]})
    return verdict


def authorize(chain, action, actor_id, *, at, trust_roots):
    """No ambient authority: verify the chain AND require the leaf
    to carry ``action`` in its rights and ``actor_id`` in its
    allowed targets (empty targets = any holder). Returns the
    chain verdict; refuses coded."""
    if action not in RIGHTS:
        _fail(DELEGATION_INVALID, "action outside the closed vocabulary")
    if not _is_agent_id(actor_id):
        _fail(DELEGATION_INVALID, "bad actor_id")
    if not isinstance(chain, (list, tuple)) or not chain:
        _fail(DELEGATION_INVALID, "chain must be a non-empty sequence")
    verdict = verify_chain(chain[-1], chain, at=at, trust_roots=trust_roots)
    leaf = chain[-1]
    if actor_id != leaf["delegatee_id"]:
        _fail(DELEGATION_CHAIN_BROKEN,
              "actor is not the leaf's delegatee")
    if action not in leaf["rights"]:
        _fail(DELEGATION_INVALID,
              "action %r not in the leaf's rights" % action)
    targets = leaf["constraints"]["allowed_targets"]
    if targets and actor_id not in targets:
        _fail(DELEGATION_INVALID,
              "actor not in the leaf's allowed targets")
    _emit("delegation-authorized", receipt_id=leaf["receipt_id"],
          detail={"action": action, "actor": actor_id})
    return verdict


# ---------------------------------------------------------------------------
# Zoe-style escrow for delegated multi-step work (offer-safety).
# ---------------------------------------------------------------------------

_ESCROW_UNSIGNED = ("escrow_id", "schema", "initiator_id", "initiator_pubkey",
                    "steps", "begun_at")


def escrow_begin(steps, initiator_seed, initiator_id, *, at):
    """Declare a multi-step delegated task up front: each step names
    its ``step_id`` and ``expected_effect_digest`` (64 hex). The
    escrow is open; commit requires every step's receipt chain to
    verify against its declared effect. Abort is always available."""
    if not isinstance(initiator_seed, (bytes, bytearray)) \
            or len(initiator_seed) != 32:
        _fail(DELEGATION_INVALID, "initiator_seed must be 32 bytes")
    if not _is_agent_id(initiator_id):
        _fail(DELEGATION_INVALID, "bad initiator_id")
    if not isinstance(at, int):
        _fail(DELEGATION_INVALID, "at must be an int instant")
    if not isinstance(steps, (list, tuple)) or not steps:
        _fail(DELEGATION_ESCROW_VIOLATED, "steps must be non-empty")
    seen = set()
    norm_steps = []
    for step in steps:
        if not isinstance(step, dict):
            _fail(DELEGATION_ESCROW_VIOLATED, "step must be a mapping")
        step_id = step.get("step_id")
        effect = step.get("expected_effect_digest")
        if not isinstance(step_id, str) or not step_id or step_id in seen:
            _fail(DELEGATION_ESCROW_VIOLATED,
                  "step_ids must be unique non-empty strings")
        if not _is_hex64(effect):
            _fail(DELEGATION_ESCROW_VIOLATED,
                  "expected_effect_digest must be 64 hex")
        seen.add(step_id)
        norm_steps.append({"step_id": step_id,
                           "expected_effect_digest": effect})
    body = {
        "escrow_id": None,
        "schema": ESCROW_SCHEMA,
        "initiator_id": initiator_id,
        "initiator_pubkey": ed25519.publickey(bytes(initiator_seed)).hex(),
        "steps": norm_steps,
        "begun_at": at,
    }
    body["escrow_id"] = _digest_hex(_canonical(
        {k: body[k] for k in _ESCROW_UNSIGNED if k != "escrow_id"}))
    signature = ed25519.sign(bytes(initiator_seed),
                             _canonical(
                                 {k: body[k] for k in _ESCROW_UNSIGNED}))
    record = dict(body)
    record["state"] = "open"
    record["signature"] = signature.hex()
    _emit("delegation-escrow-begun", detail={"steps": len(norm_steps)})
    return MappingProxyType(record)


def _check_escrow_shape(escrow):
    if not isinstance(escrow, Mapping):
        _fail(DELEGATION_ESCROW_VIOLATED, "escrow must be a mapping")
    for field in _ESCROW_UNSIGNED:
        if field not in escrow:
            _fail(DELEGATION_ESCROW_VIOLATED,
                  "escrow missing field %r" % field)
    if escrow.get("schema") != ESCROW_SCHEMA:
        _fail(DELEGATION_ESCROW_VIOLATED, "unknown escrow schema")
    if escrow.get("state") not in ("open", "committed", "aborted"):
        _fail(DELEGATION_ESCROW_VIOLATED, "bad escrow state")
    pubkey = escrow["initiator_pubkey"]
    if not isinstance(pubkey, str) or len(pubkey) != 64:
        _fail(DELEGATION_ESCROW_VIOLATED, "bad initiator_pubkey")
    try:
        bytes.fromhex(pubkey)
    except ValueError:
        _fail(DELEGATION_ESCROW_VIOLATED, "initiator_pubkey not hex")
    sig = escrow.get("signature")
    if not isinstance(sig, str) or len(sig) != 128:
        _fail(DELEGATION_ESCROW_VIOLATED, "bad escrow signature")
    try:
        sig_bytes = bytes.fromhex(sig)
    except ValueError:
        _fail(DELEGATION_ESCROW_VIOLATED, "escrow signature not hex")
    body = _canonical({k: escrow[k] for k in _ESCROW_UNSIGNED})
    if ed25519.verify(bytes.fromhex(pubkey), body, sig_bytes) is not True:
        _fail(DELEGATION_CHAIN_BROKEN, "escrow signature does not verify")
    expected = _digest_hex(_canonical(
        {k: escrow[k] for k in _ESCROW_UNSIGNED if k != "escrow_id"}))
    if escrow["escrow_id"] != expected:
        _fail(DELEGATION_CHAIN_BROKEN, "escrow_id does not match body")
    return escrow


def escrow_commit(escrow, chains, *, at, trust_roots):
    """Commit an open escrow: every declared step must present a
    receipt chain that verifies AND whose leaf designates the step's
    expected effect. Any gap refuses coded
    ``delegation-escrow-violated`` -- offer-safety: the task cannot
    commit effects it did not declare."""
    _check_escrow_shape(escrow)
    if escrow["state"] != "open":
        _fail(DELEGATION_ESCROW_VIOLATED,
              "escrow is not open (state=%s)" % escrow["state"])
    if not isinstance(chains, dict):
        _fail(DELEGATION_ESCROW_VIOLATED, "chains must map step_id -> chain")
    for step in escrow["steps"]:
        step_id = step["step_id"]
        chain = chains.get(step_id)
        if not isinstance(chain, (list, tuple)) or not chain:
            _fail(DELEGATION_ESCROW_VIOLATED,
                  "step %r has no receipt chain" % step_id)
        verdict = verify_chain(chain[-1], chain, at=at,
                               trust_roots=trust_roots)
        leaf = chain[-1]
        if "escrow.commit" not in leaf["rights"]:
            _fail(DELEGATION_ESCROW_VIOLATED,
                  "step %r leaf lacks the escrow.commit right" % step_id)
        if leaf["designated_object"] != step["expected_effect_digest"]:
            _fail(DELEGATION_ESCROW_VIOLATED,
                  "step %r leaf designates a different effect" % step_id)
    record = dict(escrow)
    record["state"] = "committed"
    _emit("delegation-escrow-committed", detail={"steps": len(escrow["steps"])})
    return MappingProxyType(record)


def escrow_abort(escrow):
    """Abort is always available and refuses nothing: an open escrow
    becomes aborted; a terminal escrow is returned unchanged."""
    _check_escrow_shape(escrow)
    if escrow["state"] != "open":
        return escrow
    record = dict(escrow)
    record["state"] = "aborted"
    _emit("delegation-escrow-aborted", detail=None)
    return MappingProxyType(record)
