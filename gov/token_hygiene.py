"""NIST IR 8587-style token hygiene for agent credentials.

Wave-234 lane B. Stdlib only.

Re-derived from the W234-8 direction (wave-233 prospectus): agent
credential tokens carry bounded lifetimes (TTL <= 1h at ISSUANCE),
explicit audiences, and key-rotation windows; token VALUES are bearer
secrets that must never land in logs -- log lines carry
``{type, issuer, scope, audience}`` metadata only.

Two halves.

1. :class:`TokenHygiene` -- claim-structure validation at ISSUANCE
   time and at PRESENTATION time.

   * ``validate_issuance``: TTL <= :data:`MAX_TTL_SECONDS` (1h) is a
     hard cap enforced AT ISSUANCE (``token-ttl-exceeded``); ``iat`` /
     ``exp`` present and sane (``token-malformed``); an explicit
     ``aud`` is required (``token-audience-missing``); the issuing
     ``key_id`` and ``key_issued_at`` are required, and a high-impact
     key older than
     :data:`HIGH_IMPACT_KEY_ROTATION_WINDOW_SECONDS` (90 days) refuses
     ``token-key-stale``.
   * ``present``: expired tokens refuse ``token-expired`` -- never
     refreshed, never tolerated; presentation outside the declared
     ``aud`` refuses ``token-audience-mismatch``.

   Clocks are injectable (``now=``) for deterministic tests; ``None``
   means wall-clock time.

   This module validates CLAIM STRUCTURE, not signatures: whether a
   token is authentic is the credential provider's job; hygiene is
   about what a validly-issued token is allowed to SAY and WHERE it
   may appear.

2. Log hygiene -- token values must never reach the audit log.

   Precise semantics (the pragmatic compromise the brief mandates):

   * The caller contract is that the audit log is NEVER handed a
     token value in the first place. Events carry ``{type, issuer,
     scope, audience}`` metadata only; a token value is a bearer
     secret, not evidence.
   * :func:`token_scrub` is DEFENSE-IN-DEPTH, not enforcement: the
     audit-log writer calls it on the entry BEFORE chain/MAC
     computation, so an accidental pass-through of a REGISTERED
     value is replaced by ``"<redacted:token>"`` and cannot fork the
     chain or destroy the event. The scrub is visible in the stored
     line -- it is never silent about what it did.
   * Enforcement is the SCAN mode:
     :meth:`TokenRedactor.assert_clean` refuses ``token-in-log``
     (incident material) on any rendered or stored line that still
     carries a registered token value. Batteries and CI run the
     scanner; the writer never silently accepts a leak.

   Issuers call :func:`register_known_token` when minting bearer
   values in this process; only registered values are mechanically
   checkable.

What this does NOT do (honest boundaries):

* It does not detect arbitrary personal data -- only registered
  token values are mechanically checkable. PII handling remains a
  caller-side contract.
* The registry is process-local; a token minted in another process
  is unregistered here. Deployments that need cross-process coverage
  must funnel minting through registration (documented residual).
* Unregistered values pass the scrub vacuously; ``assert_clean`` is
  the backstop for CI scanning of known values, not a guarantee of
  absence.

Deliberate fail-closed extensions of the brief (documented, pinned):

* ``key_id`` / ``key_issued_at`` are required on EVERY token, not only
  high-impact ones: a credential that does not name its issuing key
  is unverifiable inventory, and the rotation policy is only
  enforceable when the key is always named. ``impact`` defaults to
  ``"standard"``; an unknown impact is ``token-malformed``.
* The 1h cap and the 90-day window are constructor invariants: the
  constructor raises ``token-ttl-exceeded`` if asked to widen the
  cap past 3600s; tightening is allowed (a deployment may demand
  less than 1h / 90d).
"""

import threading
import time

# Hard cap on token lifetime at ISSUANCE: one hour (NIST IR 8587
# token-hygiene direction; a token living longer is not a hygiene
# token -- it is a long-lived credential and must not be issued here).
MAX_TTL_SECONDS = 3600

# High-impact signing keys must rotate at least this often. A token
# issued under a high-impact key older than this refuses at issuance.
HIGH_IMPACT_KEY_ROTATION_WINDOW_SECONDS = 90 * 86400

# Marker left in place of a redacted bearer value. Deliberately
# greppable so scans can distinguish "redacted by design" from "leaked".
REDACTED_MARKER = "<redacted:token>"

_HIGH_IMPACT = "high"
_STANDARD_IMPACT = "standard"


# ----------------------------------------------------------------------
# Refusal vocabulary. Base class defines no code (wave-233 lane-A
# lesson: no base-class product vocabulary -- the w228 scanner maps
# class-level ``code`` attributes on concrete exception classes).
# ----------------------------------------------------------------------


class TokenHygieneError(Exception):
    """Base for token-hygiene refusals.

    Each concrete subclass defines ``code``, the single
    machine-readable refusal code (the only vocabulary; detail lives
    in the message). ``reason`` mirrors ``code`` for the lane-battery
    convention. The base class itself is never raised, so it defines
    no code.
    """

    def __init__(self, message):
        super(TokenHygieneError, self).__init__(message)
        self.reason = self.code


class _Malformed(TokenHygieneError):
    code = "token-malformed"


class _TtlExceeded(TokenHygieneError):
    code = "token-ttl-exceeded"


class _Expired(TokenHygieneError):
    code = "token-expired"


class _AudienceMissing(TokenHygieneError):
    code = "token-audience-missing"


class _AudienceMismatch(TokenHygieneError):
    code = "token-audience-mismatch"


class _KeyStale(TokenHygieneError):
    code = "token-key-stale"


class _InLog(TokenHygieneError):
    code = "token-in-log"


# ----------------------------------------------------------------------
# Process-local registry of known bearer VALUES.
# ----------------------------------------------------------------------

_registry_lock = threading.Lock()
_registered_tokens = set()


def register_known_token(token_value):
    """Register a minted bearer value for mechanical leak checking.

    Issuers call this when minting a token value in this process.
    Registration is what makes ``token_scrub`` and
    ``TokenRedactor.assert_clean`` able to find the value later.
    Values are bearer secrets: this registry is process-local and
    never serialized.
    """
    if not isinstance(token_value, str) or not token_value:
        raise _Malformed("token value must be a non-empty string")
    with _registry_lock:
        _registered_tokens.add(token_value)
    return None


def known_token_values():
    """Return a snapshot of the registered bearer values."""
    with _registry_lock:
        return frozenset(_registered_tokens)


def clear_known_tokens():
    """Drop all registered values. Test/deploy utility; never called
    on a production path (forgetting a value weakens the scan)."""
    with _registry_lock:
        _registered_tokens.clear()
    return None


# ----------------------------------------------------------------------
# Claim-structure validation.
# ----------------------------------------------------------------------


def _now_epoch(now):
    return int(time.time()) if now is None else int(now)


def _require_str(claims, field):
    value = claims.get(field)
    if not isinstance(value, str) or not value:
        raise _Malformed("claims.%s must be a non-empty string" % field)
    if len(value) > 1024:
        raise _Malformed("claims.%s is too long" % field)
    return value


def _require_epoch(claims, field):
    value = claims.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Malformed("claims.%s must be an integer epoch, got %r"
                         % (field, value))
    if value < 0:
        raise _Malformed("claims.%s must be non-negative" % field)
    return value


class TokenHygiene:
    """NIST IR 8587-style hygiene validator for agent credential tokens.

    ``max_ttl_seconds`` and ``high_impact_rotation_window_s`` are
    constructor parameters so deployments can tighten them; widening
    the TTL cap beyond 3600 is refused (fail-closed: the 1h cap is the
    hygiene invariant, not a default).
    """

    def __init__(self, max_ttl_seconds=MAX_TTL_SECONDS,
                 high_impact_rotation_window_s=
                 HIGH_IMPACT_KEY_ROTATION_WINDOW_SECONDS):
        if max_ttl_seconds > MAX_TTL_SECONDS:
            raise _TtlExceeded(
                "token hygiene refuses a TTL cap above %d seconds: the 1h "
                "cap is the invariant, not a default" % MAX_TTL_SECONDS)
        if max_ttl_seconds <= 0:
            raise _Malformed("max_ttl_seconds must be positive")
        if high_impact_rotation_window_s <= 0:
            raise _Malformed("high_impact_rotation_window_s must be positive")
        self._max_ttl = int(max_ttl_seconds)
        self._rotation_window = int(high_impact_rotation_window_s)

    def validate_issuance(self, claims, now=None):
        """Validate a token's claims AT ISSUANCE. Returns a normalized copy.

        Refuses ``token-ttl-exceeded`` when ``exp - iat`` is longer
        than the cap (the cap is checked here, not just at expiry --
        a token must never be ISSUED with a longer life);
        ``token-audience-missing`` when no explicit ``aud`` is
        present; ``token-key-stale`` when a high-impact issuing key
        is older than the rotation window; ``token-malformed`` on
        misshapen claims.
        """
        if not isinstance(claims, dict):
            raise _Malformed("claims must be a dict, got %r"
                             % type(claims).__name__)
        iat = _require_epoch(claims, "iat")
        exp = _require_epoch(claims, "exp")
        if exp <= iat:
            raise _Malformed("claims.exp must be after claims.iat")
        ttl = exp - iat
        if ttl > self._max_ttl:
            raise _TtlExceeded(
                "token TTL %d seconds exceeds the %d-second issuance cap; "
                "issue a shorter-lived token" % (ttl, self._max_ttl))
        aud = claims.get("aud")
        if not isinstance(aud, str) or not aud:
            raise _AudienceMissing(
                "every token must declare an explicit audience (aud)")
        _require_str(claims, "key_id")
        key_issued_at = _require_epoch(claims, "key_issued_at")
        impact = claims.get("impact", _STANDARD_IMPACT)
        if impact not in (_STANDARD_IMPACT, _HIGH_IMPACT):
            raise _Malformed("claims.impact must be 'standard' or 'high'")
        if impact == _HIGH_IMPACT:
            age = _now_epoch(now) - key_issued_at
            if age > self._rotation_window:
                raise _KeyStale(
                    "high-impact issuing key %r is %d days old; rotation "
                    "window is %d days -- rotate before issuing"
                    % (claims["key_id"], age // 86400,
                       self._rotation_window // 86400))
        return dict(claims)

    def present(self, claims, audience, now=None):
        """Validate a token at PRESENTATION. Returns the claims.

        Refuses ``token-expired`` -- expired tokens are never
        refreshed and never tolerated; ``token-audience-mismatch``
        when the presentation audience differs from the declared
        ``aud``. The full issuance policy is re-validated at
        presentation (deliberate fail-closed strictness: a token
        issued under a key that has since crossed the rotation
        window refuses ``token-key-stale``; the 1h TTL cap bounds
        how far issuance and presentation can drift).
        """
        checked = self.validate_issuance(claims, now=now)
        at = _now_epoch(now)
        if at >= checked["exp"]:
            raise _Expired(
                "token expired at epoch %d (now %d): expired tokens are "
                "refused outright, never refreshed" % (checked["exp"], at))
        if audience != checked["aud"]:
            raise _AudienceMismatch(
                "token audience %r does not match presentation audience "
                "%r" % (checked["aud"], audience))
        return checked


# ----------------------------------------------------------------------
# Log hygiene: redaction (defense-in-depth) + scan (enforcement).
# ----------------------------------------------------------------------


def _scrub_value(value, values):
    if isinstance(value, str):
        for token_value in values:
            if token_value in value:
                value = value.replace(token_value, REDACTED_MARKER)
        return value
    if isinstance(value, dict):
        # Dict KEYS are never claims or secrets: they are the log's
        # own field names. Only values are scrubbed.
        return {k: _scrub_value(v, values) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_value(v, values) for v in value]
    return value


def token_scrub(artifact):
    """Return a copy of ``artifact`` with registered token values redacted.

    Defense-in-depth, NOT enforcement: the caller contract is to never
    hand the log a token value in the first place. The audit-log
    writer calls this on the entry BEFORE chain/MAC computation, so a
    scrubbed entry is what the chain binds (an accident cannot fork
    the chain). With no registered values this returns ``artifact``
    unchanged.
    """
    values = known_token_values()
    if not values:
        return artifact
    return _scrub_value(artifact, values)


class TokenRedactor:
    """Scan-mode enforcement: token values in rendered lines are incidents.

    This class ONLY scans; it never redacts. ``assert_clean`` refuses
    ``token-in-log`` (incident material) when a rendered or stored
    line still carries a registered token value. Batteries and CI run
    the scanner over rendered lines; a leak is an incident, never a
    quiet redact. (Redaction is the module-level :func:`token_scrub`,
    the defense-in-depth half -- the two halves stay separate by
    design.)
    """

    def __init__(self, values=()):
        self._values = frozenset(values)

    @classmethod
    def from_registry(cls):
        """Build a redactor over the process-local registered values."""
        return cls(known_token_values())

    def assert_clean(self, line):
        """Refuse ``token-in-log`` if ``line`` carries a token value.

        The refusal message names this as incident material: a token
        value in a log line means a bearer secret escaped the hygiene
        boundary and must be investigated (and the token rotated).
        """
        if not isinstance(line, str):
            raise _Malformed("line must be a string")
        for token_value in sorted(self._values):
            if token_value in line:
                raise _InLog(
                    "token-in-log: a bearer token value reached a log "
                    "line -- INCIDENT MATERIAL: rotate the token, audit "
                    "the leak path; lines must carry {type, issuer, "
                    "scope, audience} metadata only")
        return None
