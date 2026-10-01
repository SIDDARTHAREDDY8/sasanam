"""Short-lived credential issuance for agent workloads.

Wave-256 lane 2. Stdlib only.

Lease-shape ADAPT (infisical OSS core, MIT -- a pattern adaptation
only, never infisical's code or server, never the ``ee/`` carve-out):
credentials are dynamic-secret leases -- minted on demand, bound to a
principal and an explicit scope, carrying an explicit bounded TTL,
revocable before expiry, and every issuance/use/revocation is
journaled so a credential's full lifetime is reconstructable.

Two integrity layers, two threat models (same honest split as
gov/permit_journal.py):

1. **Reliability layer** -- ``gov.durable_journal.Journal``: POSIX-fcntl
   single-writer discipline, atomic fsync'd appends, torn-tail
   detection. Crash safety, not adversaries.
2. **Adversarial layer** -- every credential event carries an
   HMAC-SHA256 MAC over its canonical bytes chained to the previous
   event's MAC. Replay integrity rides the HMAC key, verified on every
   load; any mismatch fails closed. The journal file is
   attacker-reachable storage.

Key ownership: the HMAC key is deployment-owned. Constructor
resolution order: explicit ``key`` kwarg > ``GOV_CREDENTIAL_KEY``
(hex) env > a fresh random 32-byte key. Durability ACROSS RESTARTS
requires the deployment to supply a STABLE key; the random-key
fallback is for tests and single-process use only -- reopening with a
different key fails closed (``short-lived-credential-chain-broken``),
which is the integrity property working as designed. HMAC gives
shared-secret authenticity, NOT non-repudiation: anyone holding the
key can forge events, so the key's custody is the trust root.

The credential secret is returned ONCE at issuance and never written
to disk: the journal stores only
``HMAC(key, credential_id + ":" + secret)``. Verification recomputes
the binding. Unknown ids and secret mismatches share one refusal
code (``short-lived-credential-unknown``): id-existence is not
leaked.

Wall-clock expiry uses ``time.time()``; ``now`` is an injectable
parameter on the read paths so tests are deterministic. ``now``
must be a finite number (non-numeric, bool, NaN, and inf are
refused machine-coded); a past numeric ``now`` is honored by
design -- the caller is the trusted deployment. Clock skew
between issuer and verifier is deployment-owned.
"""

import copy
import hashlib
import hmac
import json
import math
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

from . import durable_journal as _dj

__all__ = [
    "CredentialIssuer",
    "CredentialError",
    "CredentialRefusal",
    "CredentialCorrupted",
    "CRED_ISSUED",
    "CRED_USED",
    "CRED_REVOKED",
    "CRED_EXPIRED",
    "CHAIN_BROKEN_CODE",
    "CORRUPTED_CODE",
    "EXPIRED_CODE",
    "KEY_WEAK_CODE",
    "MALFORMED_CODE",
    "REVOKED_CODE",
    "SCOPE_FORBIDDEN_CODE",
    "TTL_UNBOUNDED_CODE",
    "UNKNOWN_CODE",
]

# ---------------------------------------------------------------------------
# Event vocabulary
# ---------------------------------------------------------------------------

CRED_ISSUED = "CRED_ISSUED"
CRED_USED = "CRED_USED"
CRED_REVOKED = "CRED_REVOKED"
CRED_EXPIRED = "CRED_EXPIRED"

_CRED_EVENT_TYPES = (
    CRED_ISSUED, CRED_USED, CRED_REVOKED, CRED_EXPIRED,
)

_TERMINAL_EVENTS = (CRED_REVOKED, CRED_EXPIRED)

# Machine decision codes emitted by this module (also registered in
# gov/decision_codes.py under domain "short-lived-credential").
CHAIN_BROKEN_CODE = "short-lived-credential-chain-broken"
CORRUPTED_CODE = "short-lived-credential-corrupted"
EXPIRED_CODE = "short-lived-credential-expired"
KEY_WEAK_CODE = "short-lived-credential-key-weak"
MALFORMED_CODE = "short-lived-credential-malformed"
REVOKED_CODE = "short-lived-credential-revoked"
SCOPE_FORBIDDEN_CODE = "short-lived-credential-scope-forbidden"
TTL_UNBOUNDED_CODE = "short-lived-credential-ttl-unbounded"
UNKNOWN_CODE = "short-lived-credential-unknown"

_KEY_ENV = "GOV_CREDENTIAL_KEY"
_KEY_MIN_BYTES = 16
_GENESIS_DOMAIN = b"CREDENTIAL_JOURNAL:GENESIS:v1"

_EVENT_FIELDS = ("credential_id", "event_id", "event_type",
                 "issued_at", "mono_ns", "payload", "prev_mac",
                 "mac")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class CredentialError(Exception):
    """Base class for all credential refusals. Carries ``code``."""

    code = MALFORMED_CODE

    def __init__(self, code, detail):
        super(CredentialError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class CredentialCorrupted(CredentialError):
    """The journal failed integrity verification. Fail closed."""


class CredentialRefusal(CredentialError):
    """An issuance or verification was refused (fail-closed)."""


# ---------------------------------------------------------------------------
# Canonical bytes + MACs
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _genesis_mac(key):
    """The MAC that anchors the chain: key-bound, not a constant."""
    return hmac.new(key, _GENESIS_DOMAIN, hashlib.sha256).hexdigest()


def _event_mac(key, credential_id, event_id, event_type, issued_at,
               mono_ns, payload, prev_mac):
    """HMAC-SHA256 over one credential event, chained to prev_mac."""
    return hmac.new(
        key,
        _canonical({"credential_id": credential_id,
                    "event_id": event_id, "event_type": event_type,
                    "issued_at": issued_at, "mono_ns": mono_ns,
                    "payload": payload, "prev_mac": prev_mac}),
        hashlib.sha256).hexdigest()


def _secret_binding(key, credential_id, secret):
    """The stored proof of the secret, without storing the secret."""
    return hmac.new(
        key,
        ("%s:%s" % (credential_id, secret)).encode("utf-8"),
        hashlib.sha256).hexdigest()


# The dummy comparison target for the unknown-id refusal path (F223):
# same length as a hex sha256 digest so compare_digest is
# constant-time against it, and a fixed value the caller cannot
# influence.
_DUMMY_BINDING = "0" * 64


def _dummy_binding_check(key, credential_id, secret):
    """Equivalent dummy HMAC work for the unknown-id refusal path.

    The secret-mismatch path in verify() runs one _secret_binding
    HMAC plus one compare_digest before refusing; this runs the
    same work on the unknown-id path so the two refusal paths are
    timing-indistinguishable within noise. The API-level claim
    (shared refusal code) already held; this closes the timing
    level. Honest residual: dummy work is not a panacea --
    microarchitectural channels are out of scope for this layer.
    """
    expect = _secret_binding(key, credential_id, secret or "")
    hmac.compare_digest(expect, _DUMMY_BINDING)


# ---------------------------------------------------------------------------
# Key resolution + input validation
# ---------------------------------------------------------------------------

def _resolve_key(key):
    if key is None:
        env = os.environ.get(_KEY_ENV)
        if env:
            try:
                key = bytes.fromhex(env.strip())
            except ValueError:
                raise CredentialRefusal(
                    KEY_WEAK_CODE,
                    "%s is not valid hex" % _KEY_ENV)
        else:
            # Single-process/tests fallback. Documented: NOT durable
            # across restarts unless the deployment re-supplies it.
            key = secrets.token_bytes(32)
    if not isinstance(key, (bytes, bytearray)) or len(key) < _KEY_MIN_BYTES:
        raise CredentialRefusal(
            KEY_WEAK_CODE,
            "key must be bytes of at least %d bytes" % _KEY_MIN_BYTES)
    return bytes(key)


def _require_nonempty_str(value, what):
    if not isinstance(value, str) or not value:
        raise CredentialRefusal(
            MALFORMED_CODE,
            "%s must be a non-empty string" % what)
    return value


def _validate_ttl(ttl_seconds, max_ttl_seconds):
    if ttl_seconds is None:
        raise CredentialRefusal(
            TTL_UNBOUNDED_CODE,
            "ttl_seconds is required: unbounded leases are refused")
    if isinstance(ttl_seconds, bool) or \
            not isinstance(ttl_seconds, int):
        raise CredentialRefusal(
            MALFORMED_CODE,
            "ttl_seconds must be an int, got %s"
            % type(ttl_seconds).__name__)
    if ttl_seconds <= 0 or ttl_seconds > max_ttl_seconds:
        raise CredentialRefusal(
            TTL_UNBOUNDED_CODE,
            "ttl_seconds %r is not within (0, %d]"
            % (ttl_seconds, max_ttl_seconds))
    return ttl_seconds


def _validate_scope(scope, allow_wildcard_scope):
    _require_nonempty_str(scope, "scope")
    segments = scope.split(":")
    if not allow_wildcard_scope and any(s == "*" for s in segments):
        raise CredentialRefusal(
            SCOPE_FORBIDDEN_CODE,
            "wildcard scope %r is refused by default" % scope)
    return scope


def _validate_now(now):
    """Validate the injectable wall-clock hook.

    ``None`` means "use time.time()". Otherwise ``now`` must be a
    finite int/float unix-epoch value. A bool is refused even
    though it is an int subclass -- it carries no timestamp
    semantics. Non-finite values are refused: a NaN ``now`` would
    silently never trigger expiry (``nan >= expires_at`` is
    False), and an inf ``now`` would silently force expiry. The
    caller is the trusted deployment, so a PAST numeric ``now``
    is honored by design (documented test hook, pinned by the
    credentials/past-now-is-test-hook probe).
    """
    if now is None:
        return time.time()
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise CredentialRefusal(
            MALFORMED_CODE,
            "now must be a unix-epoch number, got %s"
            % type(now).__name__)
    if math.isnan(now) or math.isinf(now):
        raise CredentialRefusal(
            MALFORMED_CODE,
            "now must be a finite unix-epoch number")
    return now


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# The issuer
# ---------------------------------------------------------------------------

class CredentialIssuer:
    """Mint, verify, and revoke short-lived agent credentials."""

    def __init__(self, path, key=None, max_ttl_seconds=3600,
                 allow_wildcard_scope=False):
        if isinstance(max_ttl_seconds, bool) or \
                not isinstance(max_ttl_seconds, int) or \
                max_ttl_seconds <= 0:
            raise CredentialRefusal(
                MALFORMED_CODE,
                "max_ttl_seconds must be a positive int")
        self._path = os.path.abspath(path)
        self._key = _resolve_key(key)
        self._max_ttl = max_ttl_seconds
        self._allow_wildcard = bool(allow_wildcard_scope)
        try:
            self._journal = _dj.Journal(self._path)
        except _dj.JournalCorrupted as exc:
            raise CredentialCorrupted(
                CORRUPTED_CODE,
                "underlying journal failed verification: %s" % exc)
        self._states = {}
        self._event_ids = set()
        self._running_mac = _genesis_mac(self._key)
        self._rebuild()

    # ------------------------------------------------------------------
    # loading / verification
    # ------------------------------------------------------------------

    def _rebuild(self):
        for rec in self._journal.records:
            if rec.get("type") in _CRED_EVENT_TYPES:
                self._verify_and_fold(rec)
            # System records are sha256-verified by the durable layer;
            # they carry no credential-event MAC and are skipped.

    def _verify_and_fold(self, rec):
        body = rec.get("body")
        if not isinstance(body, dict):
            raise CredentialCorrupted(
                CHAIN_BROKEN_CODE, "credential event body is not a dict")
        for field in _EVENT_FIELDS:
            if field not in body:
                raise CredentialCorrupted(
                    CHAIN_BROKEN_CODE,
                    "credential event missing field %r" % field)
        if body["event_type"] != rec.get("type"):
            raise CredentialCorrupted(
                CHAIN_BROKEN_CODE,
                "event_type %r disagrees with record type %r" % (
                    body["event_type"], rec.get("type")))
        if not isinstance(body["payload"], dict):
            raise CredentialCorrupted(
                CHAIN_BROKEN_CODE, "credential event payload is not a dict")
        if body["event_id"] in self._event_ids:
            raise CredentialCorrupted(
                CHAIN_BROKEN_CODE,
                "duplicate event_id %r in the journal (replay?)"
                % (body["event_id"],))
        expect = _event_mac(
            self._key, body["credential_id"], body["event_id"],
            body["event_type"], body["issued_at"], body["mono_ns"],
            body["payload"], self._running_mac)
        if body["prev_mac"] != self._running_mac or \
                not hmac.compare_digest(str(body["mac"]), expect):
            raise CredentialCorrupted(
                CHAIN_BROKEN_CODE,
                "HMAC chain break at event %r (credential %r): not made "
                "by a key holder or tampered after write" % (
                    body["event_id"], body["credential_id"]))
        self._event_ids.add(body["event_id"])
        self._fold_state(body)
        self._running_mac = str(body["mac"])

    def _fold_state(self, body):
        cid = body["credential_id"]
        etype = body["event_type"]
        payload = body["payload"]
        st = self._states.get(cid)
        if st is None:
            st = {"status": "unknown", "events": []}
            self._states[cid] = st
        st["events"].append(copy.deepcopy(body))
        if etype == CRED_ISSUED:
            st.update({
                "status": "active",
                "principal": payload["principal"],
                "scope": payload["scope"],
                "issued_at": payload["issued_at"],
                "expires_at": payload["expires_at"],
                "secret_binding": payload["secret_binding"],
            })
        elif etype == CRED_USED:
            st["last_used_at"] = payload["used_at"]
        elif etype in _TERMINAL_EVENTS:
            st["status"] = ("revoked" if etype == CRED_REVOKED
                            else "expired")
            st["terminal_at"] = payload.get("revoked_at") or \
                payload.get("expired_at")

    def _append_event(self, credential_id, event_type, payload):
        event_id = uuid.uuid4().hex
        body = {
            "credential_id": credential_id,
            "event_id": event_id,
            "event_type": event_type,
            "issued_at": _utcnow_iso(),
            "mono_ns": time.monotonic_ns(),
            "payload": payload,
            "prev_mac": self._running_mac,
        }
        body["mac"] = _event_mac(
            self._key, credential_id, event_id, event_type,
            body["issued_at"], body["mono_ns"], payload,
            self._running_mac)
        self._journal.append(event_type, body)
        # Fold locally from the body we just wrote (already MAC'd).
        self._event_ids.add(event_id)
        self._fold_state(body)
        self._running_mac = body["mac"]
        return body

    def _state(self, credential_id):
        st = self._states.get(credential_id)
        if st is None or st.get("status") == "unknown":
            raise CredentialRefusal(
                UNKNOWN_CODE,
                "no such credential %r" % (credential_id,))
        return st

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def issue(self, principal, scope, ttl_seconds):
        """Mint a credential. Returns the credential dict (secret once)."""
        _require_nonempty_str(principal, "principal")
        _validate_scope(scope, self._allow_wildcard)
        _validate_ttl(ttl_seconds, self._max_ttl)
        credential_id = uuid.uuid4().hex
        secret = secrets.token_urlsafe(32)
        now = time.time()
        payload = {
            "principal": principal,
            "scope": scope,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "ttl_seconds": ttl_seconds,
            "secret_binding": _secret_binding(
                self._key, credential_id, secret),
        }
        self._append_event(credential_id, CRED_ISSUED, payload)
        return {
            "credential_id": credential_id,
            "secret": secret,
            "principal": principal,
            "scope": scope,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
        }

    def verify(self, credential_id, secret, scope=None, now=None):
        """Verify a presented credential; journals CRED_USED on success.

        Fail-closed: unknown id/secret, revoked, expired, or
        scope-mismatched presentations are refused. An expired
        presentation also journals CRED_EXPIRED (once).
        """
        st = self._states.get(credential_id)
        if st is None or st.get("status") == "unknown":
            # F223: the secret-mismatch path below performs one
            # _secret_binding HMAC plus a compare_digest before
            # refusing; run equivalent dummy work here first so the
            # two refusal paths are timing-indistinguishable
            # within noise.
            _dummy_binding_check(self._key, credential_id, secret)
            raise CredentialRefusal(
                UNKNOWN_CODE,
                "no such credential %r" % (credential_id,))
        expect = _secret_binding(self._key, credential_id, secret or "")
        if not hmac.compare_digest(str(st.get("secret_binding", "")),
                                   expect):
            # Same code as unknown id: id-existence is not leaked.
            raise CredentialRefusal(
                UNKNOWN_CODE,
                "credential %r not recognized" % (credential_id,))
        if st["status"] == "revoked":
            raise CredentialRefusal(
                REVOKED_CODE,
                "credential %r was revoked" % (credential_id,))
        if st["status"] == "expired":
            raise CredentialRefusal(
                EXPIRED_CODE,
                "credential %r expired at %r" % (
                    credential_id, st["expires_at"]))
        if scope is not None and scope != st["scope"]:
            raise CredentialRefusal(
                SCOPE_FORBIDDEN_CODE,
                "credential %r is not bound to scope %r"
                % (credential_id, scope))
        at = _validate_now(now)
        if at >= st["expires_at"]:
            if st["status"] == "active":
                self._append_event(credential_id, CRED_EXPIRED, {
                    "expired_at": at,
                    "expires_at": st["expires_at"],
                })
            raise CredentialRefusal(
                EXPIRED_CODE,
                "credential %r expired at %r" % (
                    credential_id, st["expires_at"]))
        self._append_event(credential_id, CRED_USED, {"used_at": at})
        return {
            "credential_id": credential_id,
            "principal": st["principal"],
            "scope": st["scope"],
            "issued_at": st["issued_at"],
            "expires_at": st["expires_at"],
        }

    def revoke(self, credential_id):
        """Revoke a credential before expiry. Terminal and journaled."""
        st = self._state(credential_id)
        if st["status"] in ("revoked", "expired"):
            raise CredentialRefusal(
                MALFORMED_CODE,
                "credential %r is already %s" % (
                    credential_id, st["status"]))
        self._append_event(credential_id, CRED_REVOKED, {
            "revoked_at": time.time(),
        })

    def expire_due(self, now=None):
        """Journal CRED_EXPIRED for every active credential past TTL."""
        at = _validate_now(now)
        count = 0
        for cid, st in list(self._states.items()):
            if st.get("status") == "active" and at >= st["expires_at"]:
                self._append_event(cid, CRED_EXPIRED, {
                    "expired_at": at,
                    "expires_at": st["expires_at"],
                })
                count += 1
        return count

    def history(self, credential_id):
        """The credential's full event list, oldest first (deep-copied)."""
        st = self._state(credential_id)
        return copy.deepcopy(st["events"])
