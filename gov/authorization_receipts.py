"""Authorization receipts with the three-digests-three-jobs discipline.

Design input (ADAPT, idea only, no source vendored): EMILIA's
authorization-receipt discipline -- a receipt shaped like a SCITT
Signed Statement where three digests do three jobs and are never
conflated:

* ``subject_digest``        -- WHAT was authorized (the action target).
* ``authorization_payload_digest`` -- WHO authorized and WHY (the
  approval context: decider identity, reason, decision time).
* ``statement_entry_digest`` -- the ENVELOPE LOCATOR (the audit-log
  entry that records the decision; the receipt points at the
  evidence, it is not itself the evidence).

Standing grants are REFERENCED BY ``grant_hash`` -- the receipt never
inlines a grant. A grant hash resolves through a deployment-pinned
:class:`GrantRegistry`; an unknown or revoked grant hash fails closed
at issuance AND at verification. Digest-role confusion (a subject
digest presented where the authorization-payload digest belongs)
fails closed at construction: digests are typed by role.

IETF status: the EMILIA drafts are individual (not adopted); this
module does NOT claim EMILIA or SCITT wire conformance. The
three-digests-three-jobs discipline is re-implemented natively,
stdlib-only.

Wiring: :class:`ReceiptEmittingApprovalQueue` subclasses
``gov.approvals.ApprovalQueue`` and emits a receipt after an
APPROVED ``decide()`` when (and only when) a :class:`ReceiptConfig`
is supplied. With no receipt config the queue is byte-identical
legacy: ``decide()`` returns the same ``(target, entry)`` and the
audit log gains no receipt events. Receipt emission is post-decision
evidence -- it never vetoes a decision -- but an emission failure is
loud: the failure is audit-logged and the exception re-raised, so a
missing receipt can never be silent.

Fail-closed: every refusal raises :class:`AuthorizationReceiptError`
with a machine-readable ``code``.

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import json
import time

from .approvals import ApprovalQueue
from .signing import Signer, Verifier

__all__ = [
    "AUTHORIZATION_RECEIPT_FORMAT",
    "RECEIPT_SIGN_DOMAIN",
    "AuthorizationReceiptError",
    "SubjectDigest",
    "AuthorizationPayloadDigest",
    "StatementEntryDigest",
    "grant_hash",
    "GrantRegistry",
    "ReceiptIssuer",
    "ReceiptConfig",
    "ReceiptEmittingApprovalQueue",
    "verify_receipt",
]

#: Receipt body format tag (exact match at verify).
AUTHORIZATION_RECEIPT_FORMAT = "sasanam-authorization-receipt/v1"

#: Domain separation for receipt signatures.
RECEIPT_SIGN_DOMAIN = b"sasanam-authorization-receipt-sign/v1:"

#: sha256 hex: 64 lowercase hex chars.
_SHA256_HEX_LEN = 64


class AuthorizationReceiptError(Exception):
    """Fail-closed authorization-receipt violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(AuthorizationReceiptError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _check_sha256_hex(value, where):
    if (not isinstance(value, str) or len(value) != _SHA256_HEX_LEN
            or any(c not in "0123456789abcdef" for c in value)):
        raise AuthorizationReceiptError(
            "digest-malformed",
            "%s must be a 64-char lowercase sha256 hex string" % (where,))
    return value


# ----------------------------------------------------------------------
# Typed digests -- the role is part of the type, not a comment.
# ----------------------------------------------------------------------

class _TypedDigest(object):
    """A sha256 digest bound to exactly one of the three jobs. The
    role travels with the value so a subject digest can never be
    silently presented where the authorization-payload digest belongs."""

    role = None  # overridden per subclass

    def __init__(self, hex_value):
        if self.role is None:
            raise AuthorizationReceiptError(
                "digest-role-missing",
                "untyped digest construction is refused")
        self.hex = _check_sha256_hex(hex_value, "digest")

    @classmethod
    def from_bytes(cls, data):
        """Bind the exact bytes to this digest's role. ``data`` must
        be bytes-like; anything else is refused loudly, never coerced."""
        if not isinstance(data, (bytes, bytearray)):
            raise AuthorizationReceiptError(
                "digest-bad-input",
                "digest input must be bytes, not %s" % type(data).__name__)
        return cls(_sha256_hex(bytes(data)))

    def __eq__(self, other):
        return (isinstance(other, _TypedDigest)
                and self.role == other.role and self.hex == other.hex)

    def __repr__(self):
        return "%s(%s...)" % (type(self).__name__, self.hex[:12])


class SubjectDigest(_TypedDigest):
    """WHAT was authorized."""

    role = "subject"


class AuthorizationPayloadDigest(_TypedDigest):
    """WHO authorized and WHY (the approval context)."""

    role = "authorization-payload"


class StatementEntryDigest(_TypedDigest):
    """The envelope locator (the audit-log entry recording the
    decision)."""

    role = "statement-entry"


def _require_role(digest, expected_cls, slot):
    """The conflation gate: the digest in ``slot`` must be an instance
    of ``expected_cls`` (correct role), never None, never a different
    role. Refuses ``digest-role-mismatch`` / ``missing-digest``."""
    if digest is None:
        raise AuthorizationReceiptError(
            "missing-digest", "%s digest is required" % (slot,))
    if not isinstance(digest, expected_cls):
        got = (digest.role if isinstance(digest, _TypedDigest)
               else type(digest).__name__)
        raise AuthorizationReceiptError(
            "digest-role-mismatch",
            "%s digest must have role %r, got %r"
            % (slot, expected_cls.role, got))
    return digest


# ----------------------------------------------------------------------
# Grant registry -- grants referenced by hash, never inlined.
# ----------------------------------------------------------------------

def grant_hash(grant_record):
    """The grant reference: sha256 over the canonical grant record."""
    if not isinstance(grant_record, dict):
        raise AuthorizationReceiptError(
            "grant-malformed", "grant record must be a dict")
    return _sha256_hex(_canonical(grant_record))


class GrantRegistry(object):
    """Deployment-pinned standing-grant registry. Grants live here;
    receipts carry only their hashes. Resolution is explicit:
    unknown hash -> ``unknown-grant``; revoked hash ->
    ``grant-revoked``. Both fail closed."""

    def __init__(self):
        self._grants = {}   # hash -> grant record (copies)
        self._revoked = set()

    def register(self, grant_record):
        """Register a standing grant; returns its grant_hash."""
        h = grant_hash(grant_record)
        self._grants[h] = json.loads(json.dumps(grant_record))
        return h

    def revoke(self, grant_hash_value):
        """Revoke a standing grant. Unknown hash -> refused loudly
        (revoking nothing is a caller bug, not a no-op)."""
        _check_sha256_hex(grant_hash_value, "grant hash")
        if grant_hash_value not in self._grants:
            raise AuthorizationReceiptError(
                "unknown-grant",
                "cannot revoke unknown grant hash")
        self._revoked.add(grant_hash_value)

    def resolve_active(self, grant_hash_value):
        """Return the grant record iff the hash is known AND not
        revoked; fail closed otherwise. This is the only path by
        which a grant hash becomes a grant."""
        _check_sha256_hex(grant_hash_value, "grant hash")
        if grant_hash_value not in self._grants:
            raise AuthorizationReceiptError(
                "unknown-grant",
                "grant hash is not registered")
        if grant_hash_value in self._revoked:
            raise AuthorizationReceiptError(
                "grant-revoked",
                "grant hash was revoked")
        return json.loads(json.dumps(self._grants[grant_hash_value]))

    def known_hashes(self):
        """Sorted list of registered grant hashes (active + revoked)."""
        return sorted(self._grants)


# ----------------------------------------------------------------------
# Issuer / verifier.
# ----------------------------------------------------------------------

def _signing_bytes(body):
    return RECEIPT_SIGN_DOMAIN + _sha256_hex(_canonical(body)).encode(
        "ascii")


def _check_receipt_body(body):
    if not isinstance(body, dict):
        raise AuthorizationReceiptError(
            "receipt-malformed", "receipt body must be a dict")
    if body.get("format") != AUTHORIZATION_RECEIPT_FORMAT:
        raise AuthorizationReceiptError(
            "receipt-format-mismatch",
            "expected format %r" % (AUTHORIZATION_RECEIPT_FORMAT,))
    for slot in ("subject_digest", "authorization_payload_digest",
                 "statement_entry_digest"):
        if slot not in body:
            raise AuthorizationReceiptError(
                "missing-digest", "receipt body missing %r" % (slot,))
        _check_sha256_hex(body[slot], "receipt.%s" % (slot,))
    for slot in ("issuer", "issuer_kid"):
        if (not isinstance(body.get(slot), str)
                or not body.get(slot)):
            raise AuthorizationReceiptError(
                "receipt-malformed",
                "receipt body %r must be a non-empty string" % (slot,))
    for slot in ("issued_at", "expires"):
        if not isinstance(body.get(slot), int) or body[slot] < 0:
            raise AuthorizationReceiptError(
                "receipt-malformed",
                "receipt body %r must be a non-negative int" % (slot,))
    if body["expires"] <= body["issued_at"]:
        raise AuthorizationReceiptError(
            "receipt-malformed",
            "expires must be after issued_at")
    grant_refs = body.get("grant_refs")
    if not isinstance(grant_refs, list):
        raise AuthorizationReceiptError(
            "receipt-malformed", "grant_refs must be a list")
    for g in grant_refs:
        _check_sha256_hex(g, "grant_refs entry")
    if len(set(grant_refs)) != len(grant_refs):
        raise AuthorizationReceiptError(
            "receipt-malformed", "duplicate grant_refs")
    return body


class ReceiptIssuer(object):
    """Issues authorization receipts. The signing key is
    caller-owned (key custody is the deployment's job); the issuer
    binds and signs, nothing else."""

    def __init__(self, signer, issuer_id, grant_registry,
                 default_ttl_seconds=3600):
        if not isinstance(signer, Signer):
            raise AuthorizationReceiptError(
                "issuer-malformed", "signer must be a gov.signing.Signer")
        if not isinstance(issuer_id, str) or not issuer_id:
            raise AuthorizationReceiptError(
                "issuer-malformed", "issuer_id must be a non-empty string")
        if not isinstance(grant_registry, GrantRegistry):
            raise AuthorizationReceiptError(
                "issuer-malformed",
                "grant_registry must be a GrantRegistry")
        if (not isinstance(default_ttl_seconds, int)
                or default_ttl_seconds <= 0):
            raise AuthorizationReceiptError(
                "issuer-malformed",
                "default_ttl_seconds must be a positive int")
        self._signer = signer
        self._issuer_id = issuer_id
        self._grants = grant_registry
        self._default_ttl = default_ttl_seconds

    @property
    def issuer_id(self):
        return self._issuer_id

    @property
    def key_id(self):
        return self._signer.key_id

    def issue(self, subject, auth_payload, statement_entry,
              grant_hashes=(), now=None, ttl_seconds=None):
        """Issue a signed receipt binding all three digests. Every
        grant hash must resolve to an ACTIVE grant at issuance --
        unknown or revoked hashes fail closed here, not at audit
        time. Digest roles are checked by type; a subject digest in
        the payload slot is ``digest-role-mismatch``, never
        re-interpreted."""
        _require_role(subject, SubjectDigest, "subject")
        _require_role(auth_payload, AuthorizationPayloadDigest,
                      "authorization-payload")
        _require_role(statement_entry, StatementEntryDigest,
                      "statement-entry")
        if grant_hashes is None:
            grant_hashes = ()
        try:
            grant_hashes = tuple(grant_hashes)
        except TypeError:
            raise AuthorizationReceiptError(
                "grant-malformed", "grant_hashes must be iterable")
        for g in grant_hashes:
            self._grants.resolve_active(g)
        if now is None:
            now = int(time.time())
        if not isinstance(now, int) or now < 0:
            raise AuthorizationReceiptError(
                "issuer-malformed", "now must be a non-negative int")
        if ttl_seconds is None:
            ttl_seconds = self._default_ttl
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise AuthorizationReceiptError(
                "issuer-malformed", "ttl_seconds must be a positive int")
        body = {
            "format": AUTHORIZATION_RECEIPT_FORMAT,
            "subject_digest": subject.hex,
            "authorization_payload_digest": auth_payload.hex,
            "statement_entry_digest": statement_entry.hex,
            "grant_refs": list(grant_hashes),
            "issuer": self._issuer_id,
            "issuer_kid": self._signer.key_id,
            "issued_at": now,
            "expires": now + ttl_seconds,
        }
        sig = self._signer.sign(_signing_bytes(body))
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            raise AuthorizationReceiptError(
                "issuer-malformed",
                "signer returned a malformed signature")
        return {
            "receipt": body,
            "issuer_kid": self._signer.key_id,
            "signature": bytes(sig).hex(),
        }


def verify_receipt(envelope, verifier, grant_registry, now=None):
    """Verify a receipt envelope against the deployment-pinned
    verifier and grant registry. Returns the verified receipt body.

    Fail-closed: malformed envelope, ``issuer_kid`` not matching the
    verifier (key-swap refused), bad signature, expired receipt
    (``now >= expires``), unknown or revoked grant refs."""
    if not isinstance(envelope, dict):
        raise AuthorizationReceiptError(
            "receipt-malformed", "envelope must be a dict")
    body = envelope.get("receipt")
    kid = envelope.get("issuer_kid")
    signature = envelope.get("signature")
    _check_receipt_body(body)
    if not isinstance(verifier, Verifier):
        raise AuthorizationReceiptError(
            "verifier-malformed", "verifier must be a gov.signing.Verifier")
    if kid != verifier.key_id:
        raise AuthorizationReceiptError(
            "key-swap-refused",
            "envelope issuer_kid %r does not match verifier %r"
            % (kid, verifier.key_id))
    if not isinstance(signature, str):
        raise AuthorizationReceiptError(
            "receipt-malformed", "signature must be a hex string")
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        raise AuthorizationReceiptError(
            "receipt-malformed", "signature is not hex")
    if not verifier.verify(_signing_bytes(body), sig_bytes):
        raise AuthorizationReceiptError(
            "signature-invalid", "receipt signature does not verify")
    if now is None:
        now = int(time.time())
    if not isinstance(now, int) or now < 0:
        raise AuthorizationReceiptError(
            "verifier-malformed", "now must be a non-negative int")
    if now >= body["expires"]:
        raise AuthorizationReceiptError(
            "receipt-expired",
            "receipt expired at %d (now %d)" % (body["expires"], now))
    if not isinstance(grant_registry, GrantRegistry):
        raise AuthorizationReceiptError(
            "verifier-malformed", "grant_registry must be a GrantRegistry")
    for g in body["grant_refs"]:
        grant_registry.resolve_active(g)
    return dict(body)


# ----------------------------------------------------------------------
# Approval-path wiring (opt-in, tighten-only).
# ----------------------------------------------------------------------

def _subject_bytes(target):
    return _canonical({
        "approval_id": target.get("id"),
        "tool": target.get("tool"),
        "args": target.get("args"),
        "policy_id": target.get("policy_id"),
    })


def _auth_payload_bytes(target, decided_by, reason, approved):
    return _canonical({
        "approval_id": target.get("id"),
        "decision": "approved" if approved else "rejected",
        "decided_by": decided_by,
        "reason": reason,
    })


class ReceiptConfig(object):
    """How receipts are emitted for approval decisions. ``issuer``
    does the signing; ``grant_hashes_for`` maps a decided record to
    its standing-grant hashes (default: no grant refs)."""

    def __init__(self, issuer, grant_hashes_for=None):
        if not isinstance(issuer, ReceiptIssuer):
            raise AuthorizationReceiptError(
                "config-malformed", "issuer must be a ReceiptIssuer")
        if grant_hashes_for is not None and not callable(
                grant_hashes_for):
            raise AuthorizationReceiptError(
                "config-malformed", "grant_hashes_for must be callable")
        self.issuer = issuer
        self.grant_hashes_for = (
            grant_hashes_for if grant_hashes_for is not None
            else (lambda target: ()))

    def emit_for_decision(self, target, entry, decided_by, reason,
                          approved=True, now=None):
        """Build and sign a receipt for a recorded decision. The
        subject binds WHAT was approved, the payload binds WHO/WHY,
        and the statement entry binds the audit-log entry itself."""
        if not isinstance(target, dict):
            raise AuthorizationReceiptError(
                "config-malformed", "target must be a dict")
        if not isinstance(entry, dict):
            raise AuthorizationReceiptError(
                "config-malformed", "entry must be a dict")
        grant_hashes = self.grant_hashes_for(target)
        return self.issuer.issue(
            SubjectDigest.from_bytes(_subject_bytes(target)),
            AuthorizationPayloadDigest.from_bytes(
                _auth_payload_bytes(target, decided_by, reason, approved)),
            StatementEntryDigest.from_bytes(_canonical(entry)),
            grant_hashes=grant_hashes,
            now=now,
        )


class ReceiptEmittingApprovalQueue(ApprovalQueue):
    """An :class:`ApprovalQueue` that emits an authorization receipt
    after every APPROVED ``decide()`` when ``receipt_config`` is
    supplied. With ``receipt_config=None`` (the default) the queue is
    byte-identical legacy: ``decide()`` returns the same
    ``(target, entry)`` and emits no receipt events.

    Receipt emission is post-decision evidence -- it never vetoes a
    decision -- but an emission failure is loud: the failure is
    audit-logged and the exception re-raised, so a missing receipt
    can never be silent. Emitted receipts accumulate in
    ``emitted_receipts`` in decide order."""

    def __init__(self, run_dir, log, *args, receipt_config=None,
                 **kwargs):
        if receipt_config is not None and not isinstance(
                receipt_config, ReceiptConfig):
            raise AuthorizationReceiptError(
                "config-malformed",
                "receipt_config must be a ReceiptConfig or None")
        super(ReceiptEmittingApprovalQueue, self).__init__(
            run_dir, log, *args, **kwargs)
        self.receipt_config = receipt_config
        self.emitted_receipts = []

    def decide(self, approval_id, approved, reason,
               decided_by="human-operator", **kwargs):
        target, entry = super(ReceiptEmittingApprovalQueue, self).decide(
            approval_id, approved, reason,
            decided_by=decided_by, **kwargs)
        if approved and self.receipt_config is not None:
            try:
                envelope = self.receipt_config.emit_for_decision(
                    target, entry, decided_by, reason, approved=True)
            except Exception as emit_err:  # noqa: BLE001 - loud, never silent
                try:
                    self._log({
                        "event": "authorization_receipt_failed",
                        "flag": "authorization_receipt_failed",
                        "approval_id": approval_id,
                        "decided_by": decided_by,
                        "error": "%s: %s" % (type(emit_err).__name__,
                                             emit_err),
                    })
                except Exception:
                    pass
                raise
            self.emitted_receipts.append(envelope)
            try:
                body = envelope["receipt"]
                self._log({
                    "event": "authorization_receipt_emitted",
                    "approval_id": approval_id,
                    "decided_by": decided_by,
                    "issuer": body["issuer"],
                    "subject_digest": body["subject_digest"],
                    "authorization_payload_digest":
                        body["authorization_payload_digest"],
                    "statement_entry_digest":
                        body["statement_entry_digest"],
                    "grant_refs": body["grant_refs"],
                })
            except Exception:
                pass
        return target, entry
