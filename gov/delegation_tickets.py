"""Kerberos-style delegation tickets for agent authority transfer.

Wave-299 lane 3. Stdlib only.

krb5/krb5 ADAPT (MIT-style permissive license; mechanism only, no
vendored code): delegation as a FIRST-CLASS TICKET TYPE with its own
session key (attributable); ``ok-as-delegate`` recipient opt-in;
constrained delegation naming the downstream set (S4U2Self/S4U2Proxy).

A ticket is a signed, frozen, time-boxed credential that says WHO may
act, on WHAT scope, under WHICH ticket type, chained to a parent
ticket or a root authority.  No ticket is ever "the parent's authority
by reference": every delegation ticket carries its own fresh ticket key
pair (the Kerberos session-key analogue), so actions taken under a
delegation ticket are cryptographically distinguishable from the
parent's actions.  The ticket private seed is returned to the ISSUER at
issue time; delivery to the delegatee is deployment-owned (the module
never transmits key material).  The ticket itself carries only the
ticket public key.

Ticket types (signed into the ticket; enforced at issue AND at
presentation):

- ``FORWARDABLE`` -- may be re-delegated within constraints.
- ``CONSTRAINED`` -- may only be presented to / re-delegated within the
  named ``allowed_downstream`` set (bounded, <= 64 principals).
- ``NON_FORWARDABLE`` -- single hop; re-delegation refuses coded.

``ok-as-delegate`` opt-in (krb5's ``ok-as-delegate`` flag): a
delegatee must hold a live, signed opt-in declaration BEFORE a ticket
can be issued to it.  The opt-in is a standalone signed declaration
(see ``OPT_IN_SCHEMA``); the merge seam to ``gov/supervision.py``
``ChildSpec`` is documented below -- a future ``ChildSpec`` field such
as ``accepts_delegation`` can feed the opt-in registry, but this
module does not import supervision and does not depend on it.

Delegation narrows, never widens (wave-298 prospecting design rule):
scopes are dot-separated capability paths (``"sasanam.tools.read"``);
a child ticket's scope must equal or EXTEND the parent's scope, and a
child ticket's expiry must not exceed the parent's expiry.  A
CONSTRAINED child's ``allowed_downstream`` must be a subset of the
parent's set.

WAVE-299 MERGE COMPOSITION: ``gov/delegation.py`` is the canonical
native receipt issuer; tickets are the PRESENTATION half of delegation,
receipts the RECORD half. The seam is WIRED (below):

* ``issue_ticket_on_receipt`` issues a ticket anchored on a native
  receipt: the receipt chain is verified first, the ticket issuer must
  be the receipt HOLDER (holder key continuity across the seam), the
  ticket scope must sit within the receipt's rights, and the ticket's
  ``parent_ticket_digest`` is the receipt's ``receipt_id``.
* ``present`` accepts an optional ``receipt_chain`` (+ ``trust_roots``);
  when a ticket's parent digest is a receipt id rather than a ticket
  id, the receipt chain is verified with ``gov/delegation.verify_chain``
  (lazy import -- delegation never imports this module) and the ticket
  signature is checked against the receipt's ``delegatee_pubkey``.

WAVE-301 F378 CLOSURE: the revocation story now reaches the ticket
layer. Both ``issue_ticket_on_receipt`` and ``present`` accept an
optional ``revocation`` input::

    {"revoker": <gov.delegation_revocation.DelegationRevoker>}

Whenever a receipt chain is consulted (issuance, or presentation of
a receipt-anchored ticket), revocation liveness is enforced
fail-closed (wave-300 lane-4 ``coordination_lease`` precedent):

* no revocation state presented -> refuse coded
  ``delegation-ticket-invalid`` (fail closed: a receipt-anchored
  ticket never presents on "no revocation info");
* the presented revoker must be the ANCHORING receipt's own
  delegator's revoker (``delegator_id`` match + revoker key equals the
  receipt's ``delegator_pubkey``) -- a substituted list from another
  principal refuses coded, never silently validates (a digest-only or
  id-only check is insufficient: an empty attacker revoker is
  indistinguishable from an empty legitimate one without the key
  binding);
* the anchoring receipt -- or any receipt in the presented chain --
  revoked -> refuse coded ``delegation-revoked`` (revocation beats
  expiry, matching the revocation module's refusal order);
* an expired anchoring receipt -> ``delegation-expired``.

Pure ticket chains (no receipt ancestry) are unaffected: no receipt
chain is consulted, so no revocation input is required. Revocation
freshness (how recent the presented list is) remains
deployment-owned -- the list is presented, not fetched; a deployment
that needs freshness pins it explicitly.

All refusals carry machine codes (F351 contract)::

    delegation-ticket-invalid        -- malformed ticket/opt-in, bad
                                        signature, wrong holder, scope
                                        escape, broken chain, child
                                        expiry exceeds parent
    delegation-ticket-expired        -- ticket (or opt-in) outside its
                                        validity window
    delegation-ticket-not-opted-in   -- issue to a delegatee with no
                                        live ok-as-delegate declaration
    delegation-ticket-type-violated  -- re-delegating NON_FORWARDABLE,
                                        CONSTRAINED presented outside
                                        its downstream set, empty
                                        downstream on CONSTRAINED issue

    (Wave-301 F378: receipt-anchored paths additionally refuse with
    the revocation module's own codes, reused not re-minted:
    ``delegation-revoked`` -- anchoring receipt or ancestor revoked;
    ``delegation-expired`` -- anchoring receipt outside its window.
    No-revocation-state and substituted-revoker refusals are coded
    ``delegation-ticket-invalid``.)

Decision layer: in-memory per verifier (wave-292 decay precedent);
timestamps are caller-supplied freshness markers.  The audit sink is
F345-class (never breaks the module; digests and ids only).
"""

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType

from gov import ed25519

# ---------------------------------------------------------------------------
# Codes (registered in gov/decision_codes.py at true sorted positions).
# ---------------------------------------------------------------------------

TKT_INVALID = "delegation-ticket-invalid"
TKT_EXPIRED = "delegation-ticket-expired"
TKT_NOT_OPTED_IN = "delegation-ticket-not-opted-in"
TKT_TYPE_VIOLATED = "delegation-ticket-type-violated"

# ---------------------------------------------------------------------------
# Shapes.
# ---------------------------------------------------------------------------

TICKET_SCHEMA = "delegation-ticket/v1"
OPT_IN_SCHEMA = "delegation-opt-in/v1"

FORWARDABLE = "forwardable"
CONSTRAINED = "constrained"
NON_FORWARDABLE = "non-forwardable"
_TICKET_TYPES = (FORWARDABLE, CONSTRAINED, NON_FORWARDABLE)

# Parent digest for root tickets: the digest of the literal marker, so a
# root ticket is structurally a ticket whose parent is the trust anchor.
ROOT_PARENT_DIGEST = hashlib.sha256(b"delegation-ticket/root").hexdigest()

_TICKET_FIELDS = ("schema", "ticket_id", "ticket_type", "issuer_id",
                  "issuer_pubkey", "delegatee_id", "scope",
                  "parent_ticket_digest", "ticket_key_pub",
                  "allowed_downstream", "issued_at", "expires_at",
                  "version")
_OPT_IN_FIELDS = ("schema", "principal_id", "pubkey",
                  "accepts_delegation", "issued_at", "expires_at",
                  "version")

_MAX_DOWNSTREAM = 64
_MAX_SCOPE_LEN = 512
_MAX_ID_LEN = 128
_MIN_TTL = 60          # 1 minute; a ticket narrower than a minute is noise
_MAX_TTL = 2592000     # 30 days; no unbounded delegation


class DelegationTicketError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = TKT_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise DelegationTicketError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def _emit_event(event, fields):
    """Returns True if a sink consumed the event, False when no sink
    is wired or the sink raised. Never raises (F345-class)."""
    if _EMIT is None:
        return False
    try:
        _EMIT(event, fields)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Canonical encoding / digests.
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _is_id(value):
    return (isinstance(value, str) and 1 <= len(value) <= _MAX_ID_LEN
            and all(c.isalnum() or c in "-_." for c in value))


def _is_scope(value):
    """Dot-separated capability path; each segment [a-z0-9][a-z0-9_-]*."""
    if not isinstance(value, str) or not (1 <= len(value) <= _MAX_SCOPE_LEN):
        return False
    parts = value.split(".")
    return all(len(p) >= 1 and p[0].isalnum()
               and all(c.isalnum() or c in "-_" for c in p)
               for p in parts)


def _scope_within(child, parent):
    """True when ``child`` narrows (or equals) ``parent``."""
    return child == parent or child.startswith(parent + ".")


# ---------------------------------------------------------------------------
# Signature helpers (wave-243: check ``is True`` / ``is False``).
# ---------------------------------------------------------------------------

def _sign_body(seed, fields, body):
    """Sign the canonical JSON of the field-restricted body."""
    unsigned = {k: body[k] for k in fields if k != "signature"}
    return ed25519.sign(seed, _canonical(unsigned)).hex()


def _verify_body(pubkey_hex, fields, body):
    """True iff the body's signature verifies under the given pubkey."""
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(body.get("signature", ""))
    except (ValueError, TypeError, AttributeError):
        return False
    unsigned = {k: body[k] for k in fields
                if k != "signature" and k in body}
    if set(unsigned) != set(f for f in fields if f != "signature"):
        return False
    return ed25519.verify(pub, _canonical(unsigned), sig) is True


# ---------------------------------------------------------------------------
# ok-as-delegate opt-in declarations.
# ---------------------------------------------------------------------------

def declare_opt_in(principal_seed, principal_id, ttl_seconds, at):
    """A principal's signed ``ok-as-delegate`` declaration.

    Returns ``(opt_in, )`` -- a frozen signed declaration that the
    principal accepts delegation tickets.  ``ttl_seconds`` is bounded;
    ``at`` is the caller-supplied instant.
    """
    if not isinstance(principal_seed, (bytes, bytearray)) \
            or len(principal_seed) != 32:
        _fail(TKT_INVALID, "principal seed must be 32 bytes")
    if not _is_id(principal_id):
        _fail(TKT_INVALID, "malformed principal_id")
    if not isinstance(ttl_seconds, int) \
            or not (_MIN_TTL <= ttl_seconds <= _MAX_TTL):
        _fail(TKT_INVALID, "opt-in ttl out of bounds")
    if not isinstance(at, int) or at < 0:
        _fail(TKT_INVALID, "malformed instant")
    body = {
        "schema": OPT_IN_SCHEMA,
        "principal_id": principal_id,
        "pubkey": ed25519.publickey(bytes(principal_seed)).hex(),
        "accepts_delegation": True,
        "issued_at": at,
        "expires_at": at + ttl_seconds,
        "version": 1,
    }
    body["signature"] = _sign_body(bytes(principal_seed), _OPT_IN_FIELDS,
                                   body)
    return MappingProxyType(body)


def _check_opt_in(opt_in, at):
    """Validate a stored opt-in declaration at instant ``at``."""
    if not isinstance(opt_in, Mapping):
        _fail(TKT_INVALID, "opt-in not a mapping")
    for field in _OPT_IN_FIELDS:
        if field not in opt_in:
            _fail(TKT_INVALID, "opt-in missing field %r" % field)
    if opt_in.get("schema") != OPT_IN_SCHEMA:
        _fail(TKT_INVALID, "opt-in wrong schema")
    if opt_in.get("accepts_delegation") is not True:
        _fail(TKT_INVALID, "opt-in does not accept delegation")
    if not _verify_body(opt_in.get("pubkey", ""), _OPT_IN_FIELDS, opt_in):
        _fail(TKT_INVALID, "opt-in signature invalid")
    if not (opt_in["issued_at"] <= at < opt_in["expires_at"]):
        _fail(TKT_EXPIRED, "opt-in outside validity window")
    return opt_in


class OptInRegistry:
    """In-memory registry of ok-as-delegate declarations (per
    verifier; wave-292 decay precedent)."""

    def __init__(self):
        self._opt_ins = {}

    def register(self, opt_in, at):
        """Store a declaration after verifying it at ``at``."""
        checked = _check_opt_in(opt_in, at)
        self._opt_ins[checked["principal_id"]] = dict(checked)
        _emit_event("opt-in-registered",
                    {"principal_id": checked["principal_id"]})
        return True

    def is_opted_in(self, principal_id, at):
        """True iff a live opt-in exists for the principal at ``at``."""
        rec = self._opt_ins.get(principal_id)
        if rec is None:
            return False
        try:
            _check_opt_in(rec, at)
        except DelegationTicketError:
            return False
        return True


# ---------------------------------------------------------------------------
# Ticket issuance.
# ---------------------------------------------------------------------------

def _check_common(issuer_id, delegatee_id, scope, ttl_seconds, at,
                  ticket_type, allowed_downstream):
    if not _is_id(issuer_id):
        _fail(TKT_INVALID, "malformed issuer_id")
    if not _is_id(delegatee_id):
        _fail(TKT_INVALID, "malformed delegatee_id")
    if issuer_id == delegatee_id:
        _fail(TKT_INVALID, "self-delegation is not delegation")
    if not _is_scope(scope):
        _fail(TKT_INVALID, "malformed scope path")
    if ticket_type not in _TICKET_TYPES:
        _fail(TKT_INVALID, "unknown ticket type")
    if not isinstance(ttl_seconds, int) \
            or not (_MIN_TTL <= ttl_seconds <= _MAX_TTL):
        _fail(TKT_INVALID, "ticket ttl out of bounds")
    if not isinstance(at, int) or at < 0:
        _fail(TKT_INVALID, "malformed instant")
    if allowed_downstream is None:
        allowed_downstream = []
    else:
        allowed_downstream = list(allowed_downstream)
    if len(allowed_downstream) > _MAX_DOWNSTREAM:
        _fail(TKT_INVALID, "downstream set exceeds bound")
    if any(not _is_id(p) for p in allowed_downstream):
        _fail(TKT_INVALID, "malformed downstream principal")
    if len(set(allowed_downstream)) != len(allowed_downstream):
        _fail(TKT_INVALID, "duplicate downstream principal")
    if ticket_type == CONSTRAINED and not allowed_downstream:
        # krb5 constrained delegation names the downstream set; an
        # empty set is fail-closed, never "unconstrained".
        _fail(TKT_TYPE_VIOLATED,
              "constrained ticket with empty downstream set")
    if ticket_type != CONSTRAINED and allowed_downstream:
        _fail(TKT_INVALID,
              "downstream set only meaningful on constrained tickets")
    return sorted(allowed_downstream)


def _build_ticket(issuer_seed, issuer_id, delegatee_id, scope,
                  ticket_type, allowed_downstream, parent_digest,
                  ttl_seconds, at):
    ticket_seed = ed25519.generate_seed()
    body = {
        "schema": TICKET_SCHEMA,
        "ticket_id": _digest({"issuer": issuer_id,
                              "delegatee": delegatee_id,
                              "scope": scope,
                              "at": at,
                              "key": ed25519.publickey(ticket_seed).hex()}),
        "ticket_type": ticket_type,
        "issuer_id": issuer_id,
        "issuer_pubkey": ed25519.publickey(bytes(issuer_seed)).hex(),
        "delegatee_id": delegatee_id,
        "scope": scope,
        "parent_ticket_digest": parent_digest,
        "ticket_key_pub": ed25519.publickey(ticket_seed).hex(),
        "allowed_downstream": allowed_downstream,
        "issued_at": at,
        "expires_at": at + ttl_seconds,
        "version": 1,
    }
    body["signature"] = _sign_body(bytes(issuer_seed), _TICKET_FIELDS, body)
    _emit_event("ticket-issued",
                {"ticket_id": body["ticket_id"],
                 "issuer_id": issuer_id,
                 "delegatee_id": delegatee_id,
                 "ticket_type": ticket_type})
    # The ticket seed is returned to the ISSUER; delivery to the
    # delegatee is deployment-owned.  The ticket carries only the
    # public half.
    return MappingProxyType(body), ticket_seed


# ---------------------------------------------------------------------------
# Revocation liveness for receipt-anchored tickets (wave-301, F378).
# ---------------------------------------------------------------------------

def _enforce_receipt_revocation(receipt_chain, at, trust_roots,
                                revocation):
    """Enforce revocation liveness on a native receipt chain, fail-closed.

    Called whenever a receipt chain is consulted for a ticket --
    issuance (``issue_ticket_on_receipt``) and presentation
    (``_verify_receipt_parent``). ``revocation`` must be a dict of the
    shape ``{"revoker": <gov.delegation_revocation.DelegationRevoker>}``.

    Refusal order: revocation-state presence -> anti-substitution ->
    revocation -> chain verification (revocation beats expiry, matching
    the revocation module). A revoked anchoring receipt -- or any
    revoked receipt in the presented chain -- refuses coded
    ``delegation-revoked``. Chain defects propagate as the
    ``gov/delegation.py`` coded error unchanged (the previous
    behavior); every other revocation defect refuses coded here.
    """
    from gov import delegation_revocation as _rv  # lazy: no cycle
    anchor = receipt_chain[-1]
    if not isinstance(revocation, dict):
        _fail(TKT_INVALID,
              "receipt-anchored ticket without revocation state "
              "(fail closed): pass revocation={'revoker': "
              "DelegationRevoker}")
    revoker = revocation.get("revoker")
    if not isinstance(revoker, _rv.DelegationRevoker):
        _fail(TKT_INVALID,
              "receipt-anchored ticket without the delegator's "
              "revocation list (fail closed)")
    # Anti-substitution: the presented revoker must be the ANCHORING
    # receipt's own delegator's revoker -- delegator_id match AND the
    # revoker's key equals the receipt's delegator_pubkey.  An id-only
    # or digest-only check is insufficient: an empty attacker revoker
    # is indistinguishable from an empty legitimate one without the
    # key binding (wave-300 lane-4 lesson).
    anchor_delegator = anchor.get("delegator_id") \
        if isinstance(anchor, Mapping) else None
    anchor_pubkey = anchor.get("delegator_pubkey") \
        if isinstance(anchor, Mapping) else None
    if revoker.delegator_id != anchor_delegator:
        _fail(TKT_INVALID,
              "presented revocation list is not the anchoring "
              "receipt's delegator's own list")
    if not isinstance(anchor_pubkey, str) or \
            revoker.pubkey_hex.lower() != anchor_pubkey.lower():
        _fail(TKT_INVALID,
              "presented revoker key does not match the anchoring "
              "receipt's delegator key")
    try:
        from gov import delegation as _dg  # lazy: no cycle
        _chain_errors = (_rv.RevocationError, _dg.DelegationError)
    except ImportError:  # pragma: no cover - defensive
        _chain_errors = (_rv.RevocationError,)
    try:
        # Checks every chain member's id against the revoker's list
        # (revocation first), then verifies the native chain.
        revoker.assert_live_native(receipt_chain, at, trust_roots)
    except _chain_errors as exc:
        code = getattr(exc, "code", None)
        if code == _rv.RV_REVOKED:
            _fail(_rv.RV_REVOKED,
                  "anchoring receipt %s revoked; the ticket's "
                  "authority is dead"
                  % (anchor.get("receipt_id", "")[:16]
                     if isinstance(anchor, Mapping) else "?"))
        if code == _rv.EXP:
            _fail(_rv.EXP, "anchoring receipt expired")
        if isinstance(exc, _rv.RevocationError):
            _fail(TKT_INVALID,
                  "receipt revocation liveness check failed (%s)"
                  % (code,))
        # gov/delegation.py chain defects propagate unchanged.
        raise


def issue_root_ticket(authority_seed, authority_id, scope, ttl_seconds,
                      at, ticket_type=FORWARDABLE):
    """Issue a root ticket: the trust anchor's own delegation
    credential.  The parent digest is the ROOT marker."""
    if not isinstance(authority_seed, (bytes, bytearray)) \
            or len(authority_seed) != 32:
        _fail(TKT_INVALID, "authority seed must be 32 bytes")
    if not _is_id(authority_id):
        _fail(TKT_INVALID, "malformed authority_id")
    if not _is_scope(scope):
        _fail(TKT_INVALID, "malformed scope path")
    if ticket_type not in _TICKET_TYPES:
        _fail(TKT_INVALID, "unknown ticket type")
    if ticket_type == CONSTRAINED:
        _fail(TKT_TYPE_VIOLATED,
              "root ticket cannot be constrained (no downstream set)")
    if not isinstance(ttl_seconds, int) \
            or not (_MIN_TTL <= ttl_seconds <= _MAX_TTL):
        _fail(TKT_INVALID, "ticket ttl out of bounds")
    if not isinstance(at, int) or at < 0:
        _fail(TKT_INVALID, "malformed instant")
    # A root ticket's delegatee is the authority itself: the anchor
    # holds its own credential.  (The self-delegation prohibition in
    # _check_common applies to delegation tickets, not to the anchor.)
    ticket_seed = ed25519.generate_seed()
    body = {
        "schema": TICKET_SCHEMA,
        "ticket_id": _digest({"issuer": authority_id,
                              "delegatee": authority_id,
                              "scope": scope,
                              "at": at,
                              "key": ed25519.publickey(ticket_seed).hex()}),
        "ticket_type": ticket_type,
        "issuer_id": authority_id,
        "issuer_pubkey": ed25519.publickey(bytes(authority_seed)).hex(),
        "delegatee_id": authority_id,
        "scope": scope,
        "parent_ticket_digest": ROOT_PARENT_DIGEST,
        "ticket_key_pub": ed25519.publickey(ticket_seed).hex(),
        "allowed_downstream": [],
        "issued_at": at,
        "expires_at": at + ttl_seconds,
        "version": 1,
    }
    body["signature"] = _sign_body(bytes(authority_seed), _TICKET_FIELDS,
                                   body)
    _emit_event("ticket-issued",
                {"ticket_id": body["ticket_id"],
                 "issuer_id": authority_id,
                 "delegatee_id": authority_id,
                 "ticket_type": ticket_type})
    return MappingProxyType(body), ticket_seed


def _check_ticket_shape(ticket):
    if not isinstance(ticket, Mapping):
        _fail(TKT_INVALID, "ticket not a mapping")
    for field in _TICKET_FIELDS:
        if field not in ticket:
            _fail(TKT_INVALID, "ticket missing field %r" % field)
    if ticket.get("schema") != TICKET_SCHEMA:
        _fail(TKT_INVALID, "ticket wrong schema")
    if ticket.get("version") != 1:
        _fail(TKT_INVALID, "ticket wrong version")
    if ticket.get("ticket_type") not in _TICKET_TYPES:
        _fail(TKT_INVALID, "ticket unknown type")
    if not _is_id(ticket.get("issuer_id")):
        _fail(TKT_INVALID, "ticket malformed issuer_id")
    if not _is_id(ticket.get("delegatee_id")):
        _fail(TKT_INVALID, "ticket malformed delegatee_id")
    if not _is_scope(ticket.get("scope")):
        _fail(TKT_INVALID, "ticket malformed scope")
    if not _is_hex64(ticket.get("parent_ticket_digest", "")):
        _fail(TKT_INVALID, "ticket malformed parent digest")
    if not _is_hex64(ticket.get("issuer_pubkey", "")):
        _fail(TKT_INVALID, "ticket malformed issuer pubkey")
    if not _is_hex64(ticket.get("ticket_key_pub", "")):
        _fail(TKT_INVALID, "ticket malformed ticket key")
    if not _is_hex64(ticket.get("ticket_id", "")):
        _fail(TKT_INVALID, "ticket malformed ticket id")
    downstream = ticket.get("allowed_downstream")
    if not isinstance(downstream, list) or \
            any(not _is_id(p) for p in downstream):
        _fail(TKT_INVALID, "ticket malformed downstream set")
    if ticket["ticket_type"] == CONSTRAINED and not downstream:
        _fail(TKT_TYPE_VIOLATED,
              "constrained ticket with empty downstream set")
    for instant_field in ("issued_at", "expires_at"):
        if not isinstance(ticket.get(instant_field), int):
            _fail(TKT_INVALID, "ticket malformed %s" % instant_field)
    if not _verify_body(ticket["issuer_pubkey"], _TICKET_FIELDS, ticket):
        _fail(TKT_INVALID, "ticket signature invalid")
    return ticket


def issue_delegation_ticket(parent_ticket, parent_seed, delegatee_id,
                            scope, ticket_type, allowed_downstream,
                            ttl_seconds, opt_ins, at):
    """Issue a delegation ticket under ``parent_ticket``.

    ``parent_seed`` is the 32-byte seed of the parent ticket's TICKET
    KEY (the fresh per-ticket key the parent issuer generated) -- the
    holder of a ticket delegates with the ticket's own key, never the
    issuer's long-term key.  ``opt_ins`` is an ``OptInRegistry``.
    Returns ``(ticket, ticket_seed)``.
    """
    if not isinstance(parent_seed, (bytes, bytearray)) \
            or len(parent_seed) != 32:
        _fail(TKT_INVALID, "parent ticket seed must be 32 bytes")
    parent = _check_ticket_shape(parent_ticket)
    # The delegating key must be the parent ticket's OWN ticket key:
    # delegating with the issuer's long-term key (or any other key) is
    # the ticket-key confusion this module refuses.
    if ed25519.publickey(bytes(parent_seed)).hex() \
            != parent["ticket_key_pub"]:
        _fail(TKT_INVALID,
              "delegation must use the parent ticket's own ticket key")
    if parent["ticket_type"] == NON_FORWARDABLE:
        _fail(TKT_TYPE_VIOLATED,
              "non-forwardable ticket cannot be re-delegated")
    allowed = _check_common(parent["delegatee_id"], delegatee_id, scope,
                            ttl_seconds, at, ticket_type,
                            allowed_downstream)
    if not _scope_within(scope, parent["scope"]):
        _fail(TKT_TYPE_VIOLATED,
              "delegation widens the parent scope")
    if parent["ticket_type"] == CONSTRAINED \
            and delegatee_id not in parent["allowed_downstream"]:
        _fail(TKT_TYPE_VIOLATED,
              "delegatee outside the constrained downstream set")
    if ticket_type == CONSTRAINED:
        if not set(allowed) <= set(parent["allowed_downstream"]) \
                and parent["ticket_type"] == CONSTRAINED:
            _fail(TKT_TYPE_VIOLATED,
                  "constrained child exceeds parent downstream set")
    if not isinstance(opt_ins, OptInRegistry):
        _fail(TKT_INVALID, "opt-in registry required")
    if not opt_ins.is_opted_in(delegatee_id, at):
        _fail(TKT_NOT_OPTED_IN,
              "delegatee has no live ok-as-delegate declaration")
    child_expires = at + ttl_seconds
    if child_expires > parent["expires_at"]:
        _fail(TKT_INVALID,
              "delegation cannot outlive its parent ticket")
    parent_digest = _digest({k: parent[k] for k in _TICKET_FIELDS
                             if k != "signature"})
    return _build_ticket(parent_seed, parent["delegatee_id"],
                         delegatee_id, scope, ticket_type, allowed,
                         parent_digest, ttl_seconds, at)


def issue_ticket_on_receipt(receipt, receipt_chain, holder_seed,
                            delegatee_id, scope, ticket_type,
                            allowed_downstream, ttl_seconds, opt_ins, at,
                            trust_roots, revocation=None):
    """Issue a delegation ticket anchored on a ``gov/delegation.py`` receipt.

    ``receipt_chain`` is the root-first native receipt chain whose leaf
    is ``receipt``; it is verified with ``gov/delegation.verify_chain``
    (lazy import) before anything is issued. ``holder_seed`` must be
    the 32-byte seed whose pubkey equals the receipt's
    ``delegatee_pubkey`` -- the ticket issuer must HOLD the receipt
    (cross-seam holder continuity); anyone else refuses coded
    ``delegation-ticket-invalid``. The ticket scope must sit within the
    receipt's rights, and the ticket cannot outlive the receipt's
    ``expires_at``. The ticket's ``parent_ticket_digest`` is the
    receipt's ``receipt_id``: the receipt is the authority RECORD, the
    ticket the PRESENTATION token. Returns ``(ticket, ticket_seed)``.

    ``revocation`` (optional, wave-301 F378): ``{"revoker":
    <gov.delegation_revocation.DelegationRevoker>}``. Revocation
    liveness of the anchoring chain is enforced fail-closed: no
    revocation state -> ``delegation-ticket-invalid``; a revoked
    anchoring receipt (or revoked ancestor) -> ``delegation-revoked``.
    """
    if not isinstance(holder_seed, (bytes, bytearray)) \
            or len(holder_seed) != 32:
        _fail(TKT_INVALID, "holder seed must be 32 bytes")
    if not isinstance(receipt_chain, (list, tuple)) or not receipt_chain:
        _fail(TKT_INVALID, "receipt chain must be a non-empty sequence")
    if receipt_chain[-1].get("receipt_id") != receipt.get("receipt_id"):
        _fail(TKT_INVALID, "receipt is not the chain leaf")
    _enforce_receipt_revocation(receipt_chain, at, trust_roots,
                                revocation)
    if ed25519.publickey(bytes(holder_seed)).hex() \
            != receipt["delegatee_pubkey"]:
        _fail(TKT_INVALID,
              "ticket issuer must hold the receipt (holder key mismatch)")
    allowed = _check_common(receipt["delegatee_id"], delegatee_id, scope,
                            ttl_seconds, at, ticket_type,
                            allowed_downstream)
    if not any(_scope_within(scope, right)
               for right in receipt.get("rights", ())):
        _fail(TKT_TYPE_VIOLATED,
              "ticket scope escapes the receipt's rights")
    if not isinstance(opt_ins, OptInRegistry):
        _fail(TKT_INVALID, "opt-in registry required")
    if not opt_ins.is_opted_in(delegatee_id, at):
        _fail(TKT_NOT_OPTED_IN,
              "delegatee has no live ok-as-delegate declaration")
    child_expires = at + ttl_seconds
    if child_expires > receipt["constraints"]["expires_at"]:
        _fail(TKT_INVALID,
              "ticket cannot outlive its anchoring receipt")
    return _build_ticket(holder_seed, receipt["delegatee_id"],
                         delegatee_id, scope, ticket_type, allowed,
                         receipt["receipt_id"], ttl_seconds, at)


# ---------------------------------------------------------------------------
# Presentation (use) of a ticket.
# ---------------------------------------------------------------------------

def attest_action(ticket_seed, ticket, action_digest):
    """Sign an action digest with the ticket's own ticket key.

    Returns the 64-byte-hex signature.  The verifier checks it against
    the ticket's ``ticket_key_pub`` -- actions under a delegation
    ticket are attributable to the ticket, not to the parent.
    """
    ticket = _check_ticket_shape(ticket)
    if not isinstance(ticket_seed, (bytes, bytearray)) \
            or len(ticket_seed) != 32:
        _fail(TKT_INVALID, "ticket seed must be 32 bytes")
    if ed25519.publickey(bytes(ticket_seed)).hex() \
            != ticket["ticket_key_pub"]:
        _fail(TKT_INVALID,
              "attestation must use the ticket's own ticket key")
    if not _is_hex64(action_digest):
        _fail(TKT_INVALID, "malformed action digest")
    return ed25519.sign(bytes(ticket_seed),
                        bytes.fromhex(action_digest)).hex()


def _verify_chain(ticket, at, ticket_store, depth=0, receipt_chain=None,
                trust_roots=None, revocation=None):
    """Recursively verify the parent chain to a root ticket.

    When ``parent_ticket_digest`` names a ``gov/delegation.py`` receipt
    id (see ``issue_ticket_on_receipt``) rather than a ticket id, the
    receipt chain is verified instead: pass the root-first native
    receipt ``receipt_chain`` whose leaf id equals the digest, plus the
    native ``trust_roots``. The ticket issuer must be the receipt's
    delegatee (cross-seam holder continuity) and the ticket signature
    must verify under the receipt's ``delegatee_pubkey``.

    ``revocation`` (wave-301 F378) is threaded to the receipt leg:
    receipt-anchored tickets enforce revocation liveness fail-closed.
    """
    if depth > 32:
        _fail(TKT_INVALID, "delegation chain exceeds depth bound")
    parent_digest = ticket["parent_ticket_digest"]
    if parent_digest == ROOT_PARENT_DIGEST:
        return True
    if not isinstance(ticket_store, dict):
        _fail(TKT_INVALID, "ticket store required for chained ticket")
    parent = ticket_store.get(parent_digest)
    if parent is None:
        return _verify_receipt_parent(ticket, parent_digest, at,
                                      receipt_chain, trust_roots, depth,
                                      revocation)

    parent = _check_ticket_shape(parent)
    if not (parent["issued_at"] <= at < parent["expires_at"]):
        _fail(TKT_EXPIRED, "parent ticket outside validity window")
    if parent["delegatee_id"] != ticket["issuer_id"]:
        _fail(TKT_INVALID, "chain issuer/delegatee mismatch")
    # The child ticket's signature was made by the parent's ticket key
    # (the delegating key), not the parent's issuer key.
    try:
        delegating_pub = bytes.fromhex(parent["ticket_key_pub"])
        sig = bytes.fromhex(ticket.get("signature", ""))
    except (ValueError, TypeError, AttributeError):
        _fail(TKT_INVALID, "ticket signature malformed")
    unsigned = {k: ticket[k] for k in _TICKET_FIELDS
                if k != "signature" and k in ticket}
    if ed25519.verify(delegating_pub, _canonical(unsigned), sig) \
            is not True:
        _fail(TKT_INVALID, "ticket not signed by parent ticket key")
    return _verify_chain(parent, at, ticket_store, depth + 1,
                         receipt_chain, trust_roots, revocation)


def _verify_receipt_parent(ticket, parent_digest, at, receipt_chain,
                           trust_roots, depth, revocation=None):
    """Verify a ticket whose parent is a ``gov/delegation.py`` receipt.

    Wave-301 F378: revocation liveness is enforced fail-closed via
    ``_enforce_receipt_revocation`` before the holder-continuity and
    signature checks.
    """
    if not isinstance(receipt_chain, (list, tuple)) or not receipt_chain:
        _fail(TKT_INVALID, "parent digest not in store and no receipt "
                          "chain supplied")
    receipt = receipt_chain[-1]
    if receipt.get("receipt_id") != parent_digest:
        _fail(TKT_INVALID, "receipt chain leaf does not match parent digest")
    _enforce_receipt_revocation(receipt_chain, at, trust_roots,
                                revocation)
    if ticket["issuer_id"] != receipt["delegatee_id"]:
        _fail(TKT_INVALID,
              "ticket issuer is not the receipt holder "
              "(cross-seam holder continuity broken)")
    try:
        holder_pub = bytes.fromhex(receipt["delegatee_pubkey"])
        sig = bytes.fromhex(ticket.get("signature", ""))
    except (ValueError, TypeError, AttributeError):
        _fail(TKT_INVALID, "ticket signature malformed")
    if ticket.get("issuer_pubkey") != receipt["delegatee_pubkey"]:
        _fail(TKT_INVALID,
              "ticket issuer key is not the receipt holder key")
    unsigned = {k: ticket[k] for k in _TICKET_FIELDS
                if k != "signature" and k in ticket}
    if ed25519.verify(holder_pub, _canonical(unsigned), sig) is not True:
        _fail(TKT_INVALID, "ticket not signed by the receipt holder key")
    return True


def present(ticket, presenter_id, action_scope, action_digest, at,
            ticket_store=None, action_sig=None, receipt_chain=None,
            trust_roots=None, revocation=None):
    """Present a ticket to authorize an action.

    Verifies, in order: shape -> signature -> validity window ->
    holder -> scope containment -> chain to root -> optional
    ticket-key action attestation.  Returns the verified ticket
    (frozen) on success; every failure refuses coded.

    ``revocation`` (optional, wave-301 F378): ``{"revoker":
    <gov.delegation_revocation.DelegationRevoker>}``.  Required
    whenever a receipt chain is consulted (receipt-anchored ticket):
    revocation liveness is enforced fail-closed -- a receipt-anchored
    ticket presented without revocation state refuses coded
    ``delegation-ticket-invalid``, and a revoked anchoring receipt
    refuses coded ``delegation-revoked``.  Pure ticket chains need no
    revocation input.
    """
    ticket = _check_ticket_shape(ticket)
    if not _is_id(presenter_id):
        _fail(TKT_INVALID, "malformed presenter id")
    if not _is_scope(action_scope):
        _fail(TKT_INVALID, "malformed action scope")
    if not _is_hex64(action_digest):
        _fail(TKT_INVALID, "malformed action digest")
    if not isinstance(at, int) or at < 0:
        _fail(TKT_INVALID, "malformed instant")
    if not (ticket["issued_at"] <= at < ticket["expires_at"]):
        _fail(TKT_EXPIRED, "ticket outside validity window")
    if presenter_id != ticket["delegatee_id"]:
        _fail(TKT_INVALID, "presenter is not the ticket delegatee")
    if not _scope_within(action_scope, ticket["scope"]):
        _fail(TKT_INVALID, "action scope escapes the ticket scope")
    _verify_chain(ticket, at, ticket_store or {}, 0, receipt_chain,
                trust_roots, revocation)
    if action_sig is not None:
        try:
            key_pub = bytes.fromhex(ticket["ticket_key_pub"])
            sig = bytes.fromhex(action_sig)
        except (ValueError, TypeError, AttributeError):
            _fail(TKT_INVALID, "action attestation malformed")
        if ed25519.verify(key_pub, bytes.fromhex(action_digest), sig) \
                is not True:
            # Ticket-key confusion (e.g. signed with the parent key)
            # lands here: the attestation must verify under THIS
            # ticket's key, never another's.
            _fail(TKT_INVALID, "action not attributable to this ticket")
    _emit_event("ticket-presented",
                {"ticket_id": ticket["ticket_id"],
                 "presenter_id": presenter_id,
                 "action_digest": action_digest})
    return ticket
