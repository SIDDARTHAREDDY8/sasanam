"""Credential revocation lineage: retired-reuse is a revocation event.

Pattern lineage: supertokens/supertokens-core (Apache-2.0) rotating
single-use refresh tokens with server-side theft lineage
(``RECENT_PREV``/``ORPHANED_BRANCH``/``STALE_LINEAGE`` -- a retired
generation's reuse is a revocation EVENT, not a 401), cert-manager
trust-manager (Apache-2.0) versioned trust bundles where rotation
keeps old+new anchors during an overlap window, never an atomic swap,
and gardener/gardener (Apache-2.0) two-phase credential rotation
(Preparing->Prepared->Completing->Completed) holding the union-of-trust
invariant throughout. This module reimplements the *mechanisms* only;
no vendored code; stdlib only.

Two standing rules become code here:

* **Reuse of a retired credential is a revocation event, not an
  authentication failure.** When a rotation retires ``rid-old`` and the
  verifier later sees ``rid-old`` presented again, the verification
  path refuses LOUD with ``revocation-retired-reuse`` -- the retired
  generation is treated exactly like a revoked one, and the event is
  audit-logged as a rotation-anomaly, never downgraded to a soft
  auth failure.
* **Rotation is a declared, phased ceremony; old and new coexist
  during overlap, old retires only after new is proven live.**
  ``rotate()`` issues the successor FIRST and only then marks the
  predecessor retired with the successor named. There is no atomic
  swap moment where neither or both are valid.

Shapes::

    credential (unsigned)::  {"credential_format": "sasanam-revocable-credential/1",
                              "rid": <revocation id>, "holder_pubkey": <64 hex>,
                              "capabilities": [<str>, ...],
                              "issued_at": <int>, "expires_at": <int>}
    credential envelope::     {"credential": <credential>,
                              "signature": <128 hex>, "keyid": "registry"}
    status response (unsigned):: {"response_format": "sasanam-revocation-status/1",
                                  "rid": <rid>, "state": "active"|"retired"|"revoked",
                                  "checked_at": <int>,
                                  "successor": <rid|null>, "revoked_at": <int|null>,
                                  "revoke_reason": <str|null>,
                                  "registry_digest": <64 hex>}
    status envelope::         {"status": <status response>,
                              "signature": <128 hex>, "keyid": "registry"}

The status envelope is countersigned by the REGISTRY key so a verifier
can accept it offline and hand it to an auditor as evidence. The
signature on the credential proves issuance; the signature on the
status proves CURRENT STATE at ``checked_at``. Signature !=
authorization: ``verify_credential`` never consults revocation --
call ``enforce_revocation`` for that. Time-validity (expires_at) is
owned by the credential's own verify path, not by revocation state.

Composition:

* gov/evidence_provenance.py: ``BuilderPolicy`` accepts
  ``revocation_required=()`` (a set of rids); ``verify_provenance``
  accepts ``revocation_gate`` / ``revocation_statuses`` and, when a
  policy demand exists, requires a signed status envelope for every
  demanded rid and enforces it. The demand is OPT-IN: an empty
  ``revocation_required`` changes nothing about the default admission
  posture (honest default -- revocation enforcement stays opt-in
  until the key-succession ceremony exists).

THREAT MODEL (read this before trusting a status response):

* The registry's signing key is the trust anchor. The issuer holds it;
  key distribution to verifiers is out-of-band (same posture as the
  provenance BuilderPolicy). A compromised registry key can mint
  "active" for a revoked rid -- no in-module defense.
* ``checked_at`` is freshness, not a clock: a stale "active" response
  replays indefinitely. Verifiers must bound response age in policy;
  this module records the time, it does not enforce it.
* The registry is in-memory and issuer-side. Persistence, replication,
  and crash recovery are the operator's job; a lost registry forgets
  revocations.
"""

import hashlib
import json
import re
import time

from gov import ed25519 as _ed25519

CREDENTIAL_FORMAT = "sasanam-revocable-credential/1"
STATUS_FORMAT = "sasanam-revocation-status/1"

STATUS_UNVERIFIABLE = "revocation-status-unverifiable"
RETIRED_REUSE = "revocation-retired-reuse"
REVOKED = "revocation-revoked"

ACTIVE = "active"
RETIRED = "retired"
REVOKED_STATE = "revoked"

_RID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
# Public grammar alias for composing modules (e.g. BuilderPolicy).
RID_GRAMMAR = _RID_RE
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")


class RevocationError(Exception):
    """Base class; carries the machine ``code``."""

    code = STATUS_UNVERIFIABLE

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise RevocationError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def _emit_event(event, fields):
    if _EMIT is None:
        return
    try:
        _EMIT(event, fields)
    except Exception:
        # F345-class trade-off: a broken sink can never break
        # revocation issuance or enforcement.
        pass


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _check_rid(value, what="rid"):
    if not isinstance(value, str) or not _RID_RE.match(value):
        _fail(STATUS_UNVERIFIABLE,
              "%s fails revocation-id grammar" % what)


def _check_pubkey_hex(value, what="holder public key"):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        _fail(STATUS_UNVERIFIABLE,
              "%s must be 64 lowercase hex chars" % what)


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(STATUS_UNVERIFIABLE, "%s must be a non-negative int" % what)


class RevocationRegistry:
    """Issuer-side revocation registry. The issuer holds the seed.

    ``issue`` mints a signed credential carrying an rid; ``rotate``
    issues the successor first and only then retires the predecessor
    (the phased-ceremony rule -- old and new coexist during overlap);
    ``revoke`` marks an rid revoked; ``check_status`` returns a signed,
    offline-verifiable status envelope for any known rid.

    An unknown rid at ``check_status`` refuses
    ``revocation-status-unverifiable`` -- unknown is never active
    (fail-closed).
    """

    def __init__(self, registry_id, seed):
        if not isinstance(registry_id, str) or \
                not _RID_RE.match(registry_id):
            _fail(STATUS_UNVERIFIABLE, "registry id fails grammar")
        if not isinstance(seed, bytes) or len(seed) != 32:
            _fail(STATUS_UNVERIFIABLE,
                  "registry seed must be 32 raw bytes")
        self.registry_id = registry_id
        self._seed = bytes(seed)
        self._entries = {}

    def registry_pubkey_hex(self):
        return _ed25519.publickey(self._seed).hex()

    def _registry_digest(self):
        ordered = {rid: self._entries[rid] for rid in sorted(self._entries)}
        return hashlib.sha256(_canonical(ordered)).hexdigest()

    def _sign(self, payload):
        return _ed25519.sign(self._seed, _canonical(payload)).hex()

    def issue(self, rid, holder_pubkey_hex, issued_at, expires_at,
              capabilities=()):
        """Mint a signed revocable credential. Refuses LOUD on a
        duplicate rid (``revocation-entry-unverifiable``) -- the
        registry never issues the same rid twice."""
        _check_rid(rid)
        _check_pubkey_hex(holder_pubkey_hex)
        _check_ts(issued_at, "issued_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= issued_at:
            _fail(STATUS_UNVERIFIABLE,
                  "expires_at must be after issued_at")
        if not isinstance(capabilities, (list, tuple)) or \
                not all(isinstance(c, str) for c in capabilities):
            _fail(STATUS_UNVERIFIABLE,
                  "capabilities must be a list of strings")
        if rid in self._entries:
            _fail("revocation-entry-unverifiable",
                  "rid %r already issued: the registry never re-issues "
                  "an rid; rotate to a fresh rid instead" % (rid,))
        self._entries[rid] = {
            "rid": rid,
            "holder_pubkey": holder_pubkey_hex,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "state": ACTIVE,
            "successor": None,
            "retired_at": None,
            "revoked_at": None,
            "revoke_reason": None,
        }
        credential = {
            "credential_format": CREDENTIAL_FORMAT,
            "rid": rid,
            "holder_pubkey": holder_pubkey_hex,
            "capabilities": list(capabilities),
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        envelope = {"credential": credential,
                    "signature": self._sign(credential),
                    "keyid": "registry"}
        _emit_event("revocation-issued",
                    {"rid": rid, "registry_id": self.registry_id})
        return envelope

    def rotate(self, old_rid, new_rid, holder_pubkey_hex, issued_at,
               expires_at, capabilities=()):
        """Phased rotation: the successor is issued FIRST, then the
        predecessor is marked retired with the successor named. The
        two overlap -- there is no instant where both are invalid.

        Returns ``(new_credential_envelope, retired_status_envelope)``.
        Rotating a non-active rid refuses LOUD (``revocation-refused``
        for retired/revoked predecessors -- a retired generation is
        never re-rotated); an unknown predecessor refuses
        ``revocation-status-unverifiable``.
        """
        _check_rid(old_rid, "old_rid")
        _check_rid(new_rid, "new_rid")
        entry = self._entries.get(old_rid)
        if entry is None:
            _fail(STATUS_UNVERIFIABLE,
                  "cannot rotate unknown rid %r" % (old_rid,))
        if entry["state"] != ACTIVE:
            _fail("revocation-refused",
                  "rid %r is %s: only active credentials rotate"
                  % (old_rid, entry["state"]))
        new_credential = self.issue(new_rid, holder_pubkey_hex, issued_at,
                                    expires_at, capabilities)
        entry["state"] = RETIRED
        entry["successor"] = new_rid
        entry["retired_at"] = issued_at
        _emit_event("revocation-rotated",
                    {"old_rid": old_rid, "new_rid": new_rid,
                     "registry_id": self.registry_id})
        return new_credential, self.check_status(old_rid, issued_at)

    def revoke(self, rid, reason):
        """Mark an rid revoked. Idempotent: revoking an already-revoked
        rid returns True without changing the record. Unknown rids
        refuse ``revocation-status-unverifiable``."""
        _check_rid(rid)
        if not isinstance(reason, str) or not reason:
            _fail(STATUS_UNVERIFIABLE, "revoke reason must be a non-empty "
                                      "string")
        entry = self._entries.get(rid)
        if entry is None:
            _fail(STATUS_UNVERIFIABLE,
                  "cannot revoke unknown rid %r" % (rid,))
        if entry["state"] == REVOKED_STATE:
            return True
        entry["state"] = REVOKED_STATE
        entry["revoked_at"] = int(time.time())
        entry["revoke_reason"] = reason
        _emit_event("revocation-revoked",
                    {"rid": rid, "registry_id": self.registry_id})
        return True

    def check_status(self, rid, checked_at=None):
        """Return a signed, offline-verifiable status envelope for a
        known rid. Unknown rids refuse ``revocation-status-unverifiable``
        -- unknown is never active."""
        _check_rid(rid)
        entry = self._entries.get(rid)
        if entry is None:
            _fail(STATUS_UNVERIFIABLE,
                  "no status for unknown rid %r: unknown is never active"
                  % (rid,))
        if checked_at is None:
            checked_at = int(time.time())
        else:
            _check_ts(checked_at, "checked_at")
        status = {
            "response_format": STATUS_FORMAT,
            "rid": rid,
            "state": entry["state"],
            "checked_at": checked_at,
            "successor": entry["successor"],
            "revoked_at": entry["revoked_at"],
            "revoke_reason": entry["revoke_reason"],
            "registry_digest": self._registry_digest(),
        }
        return {"status": status,
                "signature": self._sign(status),
                "keyid": "registry"}


def verify_credential(envelope, registry_pubkey_hex):
    """Verify a credential envelope's signature. Returns the credential
    dict. This checks ISSUANCE ONLY -- it never consults revocation
    state; call ``enforce_revocation`` for that. Any failure refuses
    coded ``revocation-status-unverifiable``."""
    if not isinstance(envelope, dict):
        _fail(STATUS_UNVERIFIABLE, "credential envelope must be a dict")
    credential = envelope.get("credential")
    sig_hex = envelope.get("signature")
    if not isinstance(credential, dict) or \
            not isinstance(sig_hex, str):
        _fail(STATUS_UNVERIFIABLE,
              "credential envelope must carry credential and signature")
    if credential.get("credential_format") != CREDENTIAL_FORMAT:
        _fail(STATUS_UNVERIFIABLE, "credential format mismatch")
    _check_rid(credential.get("rid"))
    _check_pubkey_hex(credential.get("holder_pubkey"))
    if not isinstance(sig_hex, str) or not _HEX128_RE.match(sig_hex):
        _fail(STATUS_UNVERIFIABLE, "credential signature is not 128 hex")
    try:
        pub = bytes.fromhex(registry_pubkey_hex)
    except (TypeError, ValueError):
        _fail(STATUS_UNVERIFIABLE, "registry public key is not hex")
    if len(pub) != 32:
        _fail(STATUS_UNVERIFIABLE, "registry public key is not 32 bytes")
    ok = _ed25519.verify(pub, _canonical(credential),
                         bytes.fromhex(sig_hex))
    if ok is not True:
        _fail(STATUS_UNVERIFIABLE,
              "credential signature does not verify under the pinned "
              "registry key")
    return credential


def verify_status_response(envelope, registry_pubkey_hex):
    """Verify a signed status envelope. Returns the status dict. Any
    failure refuses coded ``revocation-status-unverifiable``."""
    if not isinstance(envelope, dict):
        _fail(STATUS_UNVERIFIABLE, "status envelope must be a dict")
    status = envelope.get("status")
    sig_hex = envelope.get("signature")
    if not isinstance(status, dict) or not isinstance(sig_hex, str):
        _fail(STATUS_UNVERIFIABLE,
              "status envelope must carry status and signature")
    if status.get("response_format") != STATUS_FORMAT:
        _fail(STATUS_UNVERIFIABLE, "status response format mismatch")
    _check_rid(status.get("rid"))
    if status.get("state") not in (ACTIVE, RETIRED, REVOKED_STATE):
        _fail(STATUS_UNVERIFIABLE, "status state is not a known state")
    _check_ts(status.get("checked_at"), "checked_at")
    if not _HEX128_RE.match(sig_hex):
        _fail(STATUS_UNVERIFIABLE, "status signature is not 128 hex")
    try:
        pub = bytes.fromhex(registry_pubkey_hex)
    except (TypeError, ValueError):
        _fail(STATUS_UNVERIFIABLE, "registry public key is not hex")
    if len(pub) != 32:
        _fail(STATUS_UNVERIFIABLE, "registry public key is not 32 bytes")
    ok = _ed25519.verify(pub, _canonical(status),
                         bytes.fromhex(sig_hex))
    if ok is not True:
        _fail(STATUS_UNVERIFIABLE,
              "status signature does not verify under the pinned "
              "registry key")
    return status


def enforce_revocation(status_envelope, registry_pubkey_hex):
    """The enforcement seam. Verifies the status envelope, then:

    * ``active`` -> returns True;
    * ``retired`` -> refuses LOUD ``revocation-retired-reuse``. Reuse
      of a retired credential is a REVOCATION EVENT, not an
      authentication failure: it is coded, loud, and auditable;
    * ``revoked`` -> refuses LOUD ``revocation-revoked``.

    The status envelope may be presented by the credential holder --
    it is verified, never trusted.
    """
    status = verify_status_response(status_envelope, registry_pubkey_hex)
    state = status["state"]
    rid = status["rid"]
    if state == ACTIVE:
        _emit_event("revocation-enforced-active", {"rid": rid})
        return True
    if state == RETIRED:
        _emit_event("revocation-retired-reuse",
                    {"rid": rid, "successor": status.get("successor")})
        _fail(RETIRED_REUSE,
              "rid %r is retired (rotation successor: %r): reuse of a "
              "retired credential is a revocation event, refused LOUD"
              % (rid, status.get("successor")))
    _emit_event("revocation-enforced-revoked", {"rid": rid})
    _fail(REVOKED, "rid %r is revoked: %s"
          % (rid, status.get("revoke_reason")))


class RevocationGate:
    """Composable opt-in gate for existing verify paths.

    ``registry_pubkey_hex`` is the pinned registry key (out-of-band).
    ``required_rids`` names the rids the gate demands status for.
    ``gate(rid, status_envelope)`` enforces one rid's status;
    ``require_all(status_envelopes)`` demands a covering, verified,
    enforced status envelope for every required rid and returns True.
    Missing coverage refuses ``revocation-status-unverifiable``.
    """

    def __init__(self, registry_pubkey_hex, required_rids=()):
        if not isinstance(registry_pubkey_hex, str) or \
                not _HEX64_RE.match(registry_pubkey_hex):
            _fail(STATUS_UNVERIFIABLE,
                  "registry public key must be 64 lowercase hex chars")
        if not isinstance(required_rids, (list, tuple, set, frozenset)) or \
                not required_rids:
            _fail(STATUS_UNVERIFIABLE,
                  "a revocation gate requires at least one rid: vacuous "
                  "gates are refused at construction")
        self.registry_pubkey_hex = registry_pubkey_hex
        self.required_rids = frozenset()
        for rid in required_rids:
            _check_rid(rid)
            self.required_rids |= {rid}

    def gate(self, rid, status_envelope):
        _check_rid(rid)
        status = verify_status_response(status_envelope,
                                        self.registry_pubkey_hex)
        if status["rid"] != rid:
            _fail(STATUS_UNVERIFIABLE,
                  "status envelope is for rid %r, gate demanded %r"
                  % (status["rid"], rid))
        return enforce_revocation(status_envelope, self.registry_pubkey_hex)

    def require_all(self, status_envelopes):
        if not isinstance(status_envelopes, (list, tuple)):
            _fail(STATUS_UNVERIFIABLE,
                  "status envelopes must be a list or tuple")
        by_rid = {}
        for envelope in status_envelopes:
            status = verify_status_response(envelope,
                                            self.registry_pubkey_hex)
            by_rid[status["rid"]] = envelope
        missing = sorted(self.required_rids - set(by_rid))
        if missing:
            _fail(STATUS_UNVERIFIABLE,
                  "revocation gate demands status for rids %r and none "
                  "was supplied" % (missing,))
        for rid in sorted(self.required_rids):
            self.gate(rid, by_rid[rid])
        return True
