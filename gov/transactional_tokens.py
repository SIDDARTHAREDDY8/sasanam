"""Transactional authorization tokens (W243-3 ADAPT, patterns only).

Adapts the mechanism of draft-tulshi-oauth-transactional-access-tokens
-00 as PROSE ONLY: no draft text is read, copied, imported, or vendored
here. The mechanism: per-transaction fresh authorization-server policy
decisions, each authorization scoped by the triple

    (txn-id binding, very-short-lifetime, single-resource-server audience)

which is the OAuth-native answer to stale authority -- an authorization
cannot outlive the transaction it was minted for, cannot be carried to
another transaction, and cannot be presented to another resource server.

Token shape (plain wire dict, no serialization magic)::

    {"v": 1, "txn_id": <str>, "aud": <str>, "iat": <epoch>,
     "exp": <epoch>, "mac": <hex HMAC-SHA256>}

The MAC covers the RFC-8785-shaped canonical JSON (sorted keys,
minimal separators) of every field except ``mac`` itself, prefixed
with a domain separator. Verification order is fixed:

1. shape (fail closed on malformed),
2. MAC (tamper reported as tamper, never as a binding mismatch),
3. expiry (per-token lifetime, injectable clock),
4. resource-server audience (exact-string binding, reusing the
   ``gov.aauth_egress`` binding primitive and translating its refusal),
5. transaction-id binding.

The lifetime is a PER-TOKEN property: ``issue`` requires an explicit
``ttl_seconds`` argument (no default a caller could extend), the ttl
is signed into the token, and ``verify`` reads only the signed value --
there is no duration config to override. A ttl beyond
``TRANSACTION_TTL_MAX_SECONDS`` (300s) is refused at issue: these are
*very-short* tokens by design.

Key material: tokens are HMAC-bound bearer secrets ONLY when the
deployment supplies a key. ``TransactionalTokenIssuer(None)`` (or any
non-bytes/empty key) fails closed with ``transaction-key-missing`` on
every operation -- the dev-key fallback was removed and is honored
here (there is no silent insecure default).

Honest boundaries:
- Same-transaction replay within the lifetime is NOT tracked: there is
  no nonce store here, so a stolen token is usable inside its own
  transaction until ``exp``. The very-short lifetime bounds the blast
  radius; true single-use is deployment-owned.
- The verifier's clock is trusted; clock trust is deployment-owned.
- HMAC proves shared-secret authenticity, not non-repudiation; the
  bearer secret's transport protection is deployment-owned.
- Expiry is ``now >= exp``; a token presented exactly at ``exp`` is
  expired (closed interval on the stale side).
"""

import hashlib
import hmac
import json
import time

from . import aauth_egress as _aauth

TOKEN_VERSION = 1

# Very-short lifetime cap: a transaction authorization lives seconds,
# not minutes. ttl_seconds must be > 0 and <= this cap.
TRANSACTION_TTL_MAX_SECONDS = 300

_TOKEN_DOMAIN = b"gov-txn-token/v1\x00"

CODES = (
    "transaction-id-mismatch",
    "transaction-expired",
    "resource-server-mismatch",
    "transaction-malformed",
    "transaction-signature-invalid",
    "transaction-key-missing",
)


class TransactionalTokenError(Exception):
    """Fail-closed refusal. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        super().__init__("%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise TransactionalTokenError(code, detail)


def _require_epoch(value, name):
    """Numeric (non-bool) epoch; fail closed with transaction-malformed."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _refuse("transaction-malformed",
                "%s %r is not a numeric epoch" % (name, value))
    return value


def _require_nonempty_str(value, name):
    if not isinstance(value, str) or not value:
        _refuse("transaction-malformed",
                "%s must be a non-empty string" % (name,))
    return value


def _canonical_body(body):
    """RFC-8785-shaped canonical bytes of the unsigned token body."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _mac(key, body):
    return hmac.new(key, _TOKEN_DOMAIN + _canonical_body(body),
                    hashlib.sha256).hexdigest()


class TransactionalTokenIssuer(object):
    """Issue and verify per-transaction tokens under a deployment key.

    ``key`` must be non-empty bytes. ``None`` (or anything else) builds
    an issuer whose every operation refuses ``transaction-key-missing``
    -- no silent fallback.
    """

    def __init__(self, key):
        self._key = key if isinstance(key, bytes) and key else None

    def _key_or_refuse(self):
        if self._key is None:
            _refuse("transaction-key-missing",
                    "no deployment key supplied; failing closed "
                    "(no dev-key fallback)")
        return self._key

    def issue(self, txn_id, rs_audience, ttl_seconds, now=None):
        """Mint a token scoped to one transaction.

        ``ttl_seconds`` is a REQUIRED per-token argument (no default);
        values outside (0, TRANSACTION_TTL_MAX_SECONDS] refuse
        ``transaction-malformed`` at issue. ``now`` is an injectable
        epoch for determinism (defaults to the wall clock).
        """
        key = self._key_or_refuse()
        _require_nonempty_str(txn_id, "txn_id")
        _require_nonempty_str(rs_audience, "rs_audience")
        if isinstance(ttl_seconds, bool) or not isinstance(
                ttl_seconds, (int, float)):
            _refuse("transaction-malformed",
                    "ttl_seconds %r is not numeric" % (ttl_seconds,))
        if not 0 < ttl_seconds <= TRANSACTION_TTL_MAX_SECONDS:
            _refuse("transaction-malformed",
                    "ttl_seconds %r outside (0, %ds]"
                    % (ttl_seconds, TRANSACTION_TTL_MAX_SECONDS))
        iat = _require_epoch(time.time() if now is None else now, "now")
        body = {"v": TOKEN_VERSION, "txn_id": txn_id, "aud": rs_audience,
                "iat": iat, "exp": iat + ttl_seconds}
        return dict(body, mac=_mac(key, body))

    def verify(self, token, expected_txn_id, expected_rs_audience, now):
        """Verify a token against its transaction and audience.

        Refusals (in check order): ``transaction-malformed``,
        ``transaction-key-missing``, ``transaction-signature-invalid``,
        ``transaction-expired``, ``resource-server-mismatch``,
        ``transaction-id-mismatch``. Returns the verified token body
        (a copy) on success.
        """
        key = self._key_or_refuse()
        if not isinstance(token, dict):
            _refuse("transaction-malformed", "token must be a dict")
        for field in ("v", "txn_id", "aud", "iat", "exp", "mac"):
            if field not in token:
                _refuse("transaction-malformed",
                        "token missing field %r" % (field,))
        if token["v"] != TOKEN_VERSION:
            _refuse("transaction-malformed",
                    "unsupported token version %r" % (token["v"],))
        _require_nonempty_str(token["txn_id"], "txn_id")
        _require_nonempty_str(token["aud"], "aud")
        iat = _require_epoch(token["iat"], "iat")
        exp = _require_epoch(token["exp"], "exp")
        if not isinstance(token["mac"], str) or not token["mac"]:
            _refuse("transaction-malformed", "mac must be a non-empty string")
        body = {"v": TOKEN_VERSION, "txn_id": token["txn_id"],
                "aud": token["aud"], "iat": iat, "exp": exp}
        if not hmac.compare_digest(_mac(key, body), token["mac"]):
            _refuse("transaction-signature-invalid",
                    "MAC does not cover the presented bytes")
        now = _require_epoch(now, "now")
        if now >= exp:
            _refuse("transaction-expired",
                    "token expired at %r (now %r)" % (exp, now))
        _require_nonempty_str(expected_rs_audience, "expected_rs_audience")
        try:
            _aauth.check_audience(token["aud"], expected_rs_audience)
        except _aauth.AauthEgressError as exc:
            _refuse("resource-server-mismatch", exc.detail)
        _require_nonempty_str(expected_txn_id, "expected_txn_id")
        if token["txn_id"] != expected_txn_id:
            _refuse("transaction-id-mismatch",
                    "token is bound to transaction %r, presented for %r"
                    % (token["txn_id"], expected_txn_id))
        return dict(body)
