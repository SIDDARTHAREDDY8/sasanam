"""Attestation-conditioned credential release (Trustee KBS mechanism steal).

Wave-198. Upgrades sentinel credential substitution from host-binding-only
release to attestation-conditioned release. The release predicate
(``evaluate_release``) is evaluated per release at the execution boundary
(``gov.sentinel_substitution.substitute_for_execution``), with a fail-closed
pre-check on the attempt path
(``gov.sentinel_substitution.validate_sentinel_binding``). The host check
becomes one conjunct of the predicate -- never a fallback: an
attestation-mandatory credential with a missing, invalid, or expired
attestation, or with no issuer trust anchor configured, is LOUDLY refused.
There is no silent degradation to host-only release (the R6 downgrade
guard).

Mechanism stolen from confidential-containers/trustee (Apache-2.0;
read-only source study in the wave-196 spike -- no Rust/TEE stack, no OPA
dependency, stdlib-only Python):

* the release predicate -- attestation-claim-gated ``allow(...)``,
  default-deny, policy-as-data (``attested`` / ``deny_all`` /
  operator-signed override);
* the claim vocabulary -- EAR ``status`` (affirming/warning/
  contraindicated) mapped onto the wave-191/192 token claim-set
  (iss/sub/aud/iat/exp/jti/agent_scope);
* per-release evaluation at the execution boundary (the TOCTOU guard);
* session binding -- the JWE-to-tee-pubkey replay defense without
  enclaves: the attestation is bound to (agent_id, run_id), so a token
  copied into another session refuses on sub/session mismatch;
* the ``insecure_header_jwk`` lesson -- the signing key is resolved via
  ``kid`` from the trusted issuer keyset, never from material embedded
  in the token.

Deliberate vocabulary mapping (spike section 4.1 / 6): Trustee's EAR
``submods`` map (per-submodule ``ear.status``) is mapped ONTO our flat
claim-set -- the spike says to take the claim vocabulary (EAR ``status``
+ ``iss/sub/aud/iat/exp/jti/agent_scope``) but NOT the TEE-specific
``submods`` hardware shape. So the token carries one top-level
``status`` and a non-empty ``agent_scope`` list (Trustee's
``count(submods) > 0`` anti-vacuous guard becomes "scope must cover at
least one credential class"); any non-``affirming`` status refuses the
whole release (the R4 mixed-attestation shape has no partial path).

Attestation tokens are keyset-attested statements (the wave-193/196
ceremony: canonical JSON, domain-separated Ed25519, exact-field
structures, keyset-hash pinning, rotation-stable lineage), minted with
keyset purpose ``"attestation-release"``.

Migration: ``SentinelVault.register`` takes ``release_policy`` --
``"attested"`` (default for new credentials: attestation-mandatory from
day one), ``"legacy-host-only"`` (the old host-binding path, kept during
migration with a LOUD audit event on every use and a documented sunset),
``"deny_all"`` (credential classes under incident hold).

Honest residual: revocation beyond the short attestation TTL (<= 300s) is
follow-on work -- there is no revocation list yet (matches the wave-191
residual). ``AttestationReleaseConfig.revoke_attestation`` drops the
registry entry so subsequent releases refuse, but already-issued tokens
stay valid until ``exp``.

$0 spend. Stdlib only. No product-code changes outside the sentinel seam.
"""

import json
import time
import uuid

try:
    from . import ed25519 as _ed
except ImportError:  # pragma: no cover - direct module use
    import ed25519 as _ed

try:
    from .keyset import (
        Keyset,
        KeysetError,
        keyset_signer_for_version,
    )
except ImportError:  # pragma: no cover - direct module use
    from keyset import (
        Keyset,
        KeysetError,
        keyset_signer_for_version,
    )

try:
    from .cosign_attest import keyset_hash_at_version
except ImportError:  # pragma: no cover - direct module use
    from cosign_attest import keyset_hash_at_version


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATTESTATION_PURPOSE = "attestation-release"
ATTESTATION_FORMAT = "sasanam-attestation-release/v1"
ATTESTATION_DOMAIN = b"sasanam.attestation-release.v1:"
ATTESTATION_AUDIENCE = "sentinel-release"

OVERRIDE_PURPOSE = "attestation-policy-override"
OVERRIDE_FORMAT = "sasanam-attestation-override/v1"
OVERRIDE_DOMAIN = b"sasanam.attestation-override.v1:"

#: Attestation tokens are short-lived by construction (the Trustee AS
#: issues short-lived tokens; the wave-191 residual records that expiry,
#: not a revocation list, is the primary control).
MAX_ATTESTATION_TTL_SECONDS = 300
CLOCK_SKEW_SECONDS = 60

#: The legacy host-only path is a migration bridge, not a destination.
LEGACY_RELEASE_SUNSET = "2026-12-31"

#: Per-credential release policies (policy-as-data, Trustee's pluggable
#: affirming.rego / deny_all.rego -- re-implemented stdlib-only).
RELEASE_POLICIES = ("attested", "legacy-host-only", "deny_all")

#: EAR attestation status vocabulary (adapted from Trustee's
#: ``ear.status``).
ATTESTATION_STATUSES = ("affirming", "warning", "contraindicated")

#: Machine-readable release reason for the operator-signed override
#: path. Both the producer (``evaluate_release``) and the consumer
#: (``_attested_decision`` in gov/sentinel_substitution.py) reference
#: this constant -- never match the literal string.
REASON_OPERATOR_OVERRIDE = "operator-override"


class AttestationReleaseError(Exception):
    """Fail-closed error for the attestation-release seam."""


# ---------------------------------------------------------------------------
# Canonical JSON + small validators (same recipe as gov/keyset)
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _require_text(value, what):
    if not isinstance(value, str) or not value:
        raise AttestationReleaseError("%s must be a non-empty string"
                                      % (what,))
    return value


def _require_int(value, what):
    if isinstance(value, bool) or not isinstance(value, int):
        raise AttestationReleaseError("%s must be an integer, got %r"
                                      % (what, value))
    return value


def _require_classes(value, what="agent_scope"):
    if not isinstance(value, (list, tuple)) or not value:
        raise AttestationReleaseError(
            "%s must be a non-empty list of non-empty strings" % (what,))
    out = []
    for c in value:
        if not isinstance(c, str) or not c:
            raise AttestationReleaseError(
                "%s entries must be non-empty strings" % (what,))
        out.append(c)
    return tuple(sorted(set(out)))


def _exact_fields(obj, fields, name):
    unknown = set(obj) - fields
    if unknown:
        return "%s carries unknown fields: %s" % (name, sorted(unknown))
    missing = fields - set(obj)
    if missing:
        return "%s missing fields: %s" % (name, sorted(missing))
    return None


_STATEMENT_FIELDS = frozenset({
    "format", "sub", "iss", "aud", "status", "iat", "exp", "jti",
    "agent_scope", "session", "attested_by", "envelope",
})
_ATTESTED_BY_FIELDS = frozenset({
    "purpose", "keyset_key_id", "keyset_version", "keyset_hash",
})
_ENVELOPE_FIELDS = frozenset({"sig_key_id", "sig_key_version", "sig"})
_SESSION_FIELDS = frozenset({"agent_id", "run_id"})

_OVERRIDE_FIELDS = frozenset({
    "format", "agent_scope", "not_before", "not_after", "reason",
    "attested_by", "envelope",
})


# ---------------------------------------------------------------------------
# Minting (attestation-service / operator side)
# ---------------------------------------------------------------------------

def attest_release(keyset, seed, *, sub, iss, agent_scope, session,
                   status="affirming", ttl_seconds=MAX_ATTESTATION_TTL_SECONDS,
                   at=None, version=None, jti=None):
    """Mint an attestation-release token.

    ``keyset`` must carry purpose ``"attestation-release"``; the signing
    handle is minted via ``keyset_signer_for_version`` -- a revoked or
    verify-only version's seed is refused here (retired material cannot
    mint new attestations).

    Returns the token as a dict (public material). Raises
    :class:`AttestationReleaseError` on any bad input.
    """
    if not isinstance(keyset, Keyset):
        raise AttestationReleaseError("keyset must be a gov.keyset.Keyset")
    if keyset.purpose != ATTESTATION_PURPOSE:
        raise AttestationReleaseError(
            "keyset purpose %r cannot mint release attestations (need %r)"
            % (keyset.purpose, ATTESTATION_PURPOSE))
    _require_text(sub, "'sub'")
    _require_text(iss, "'iss'")
    classes = _require_classes(agent_scope)
    if status not in ATTESTATION_STATUSES:
        raise AttestationReleaseError(
            "status %r is not in %s" % (status, ATTESTATION_STATUSES))
    if not isinstance(session, dict):
        raise AttestationReleaseError("session must be a mapping")
    err = _exact_fields(session, _SESSION_FIELDS, "session")
    if err:
        raise AttestationReleaseError(err)
    _require_text(session["agent_id"], "session.agent_id")
    _require_text(session["run_id"], "session.run_id")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise AttestationReleaseError("'ttl_seconds' must be an integer")
    if ttl_seconds < 1 or ttl_seconds > MAX_ATTESTATION_TTL_SECONDS:
        raise AttestationReleaseError(
            "'ttl_seconds' must be within [1, %d]"
            % (MAX_ATTESTATION_TTL_SECONDS,))
    stamp = int(time.time()) if at is None else _require_int(at, "'at'")
    token_jti = jti if jti is not None else uuid.uuid4().hex
    _require_text(token_jti, "'jti'")
    if version is None:
        version = keyset.primary_version
    try:
        signer = keyset_signer_for_version(keyset, version, seed)
    except KeysetError as e:
        raise AttestationReleaseError(
            "cannot mint an attestation signing handle: %s" % e)
    body = {
        "format": ATTESTATION_FORMAT,
        "sub": sub,
        "iss": iss,
        "aud": ATTESTATION_AUDIENCE,
        "status": status,
        "iat": stamp,
        "exp": stamp + ttl_seconds,
        "jti": token_jti,
        "agent_scope": list(classes),
        "session": {"agent_id": session["agent_id"],
                    "run_id": session["run_id"]},
        "attested_by": {
            "purpose": keyset.purpose,
            "keyset_key_id": signer.key_id,
            "keyset_version": signer.key_version,
            "keyset_hash": keyset_hash_at_version(keyset,
                                                 signer.key_version),
        },
    }
    sig = signer.sign(ATTESTATION_DOMAIN + _canonical(body)).hex()
    body["envelope"] = {
        "sig_key_id": signer.key_id,
        "sig_key_version": signer.key_version,
        "sig": sig,
    }
    return body


# ---------------------------------------------------------------------------
# Verification (relying side -- never raises)
# ---------------------------------------------------------------------------

def _statement_error(reason):
    return False, reason


def verify_attestation(token, keyset_doc, *, forensics=False):
    """Verify an attestation-release token against an issuer keyset doc.

    Steps: structure (exact fields, exact format) -> claim shapes ->
    attested_by/envelope consistency -> keyset parse + purpose + lineage ->
    keyset-hash pin (rotation-stable via lineage) -> envelope key
    resolution (``kid`` from the trusted keyset -- embedded keys are never
    accepted; revoked refuses unless ``forensics``) -> Ed25519 signature
    over domain + canonical token.

    Returns ``(True, details)`` or ``(False, reason)``; never raises.
    ``details`` carries the verified claims (sub/iss/status/iat/exp/jti/
    agent_scope/session) plus keyset provenance.
    """
    if not isinstance(token, dict):
        return _statement_error("attestation is not a mapping")
    err = _exact_fields(token, _STATEMENT_FIELDS, "attestation")
    if err:
        return _statement_error(err)
    if token["format"] != ATTESTATION_FORMAT:
        return _statement_error(
            "attestation format %r is not %r (exact match required)"
            % (token.get("format"), ATTESTATION_FORMAT))
    for name in ("sub", "iss", "aud", "status", "jti"):
        val = token.get(name)
        if not isinstance(val, str) or not val:
            return _statement_error(
                "attestation claim %r must be a non-empty string" % (name,))
    if token["status"] not in ATTESTATION_STATUSES:
        return _statement_error(
            "attestation status %r is not a known EAR status"
            % (token["status"],))
    for name in ("iat", "exp"):
        val = token.get(name)
        if isinstance(val, bool) or not isinstance(val, int):
            return _statement_error(
                "attestation claim %r must be an integer" % (name,))
    if token["exp"] <= token["iat"]:
        return _statement_error("attestation 'exp' is not after 'iat'")
    try:
        classes = _require_classes(token["agent_scope"])
    except AttestationReleaseError as e:
        return _statement_error("bad agent_scope: %s" % e)
    session = token["session"]
    if not isinstance(session, dict):
        return _statement_error("attestation session is not a mapping")
    err = _exact_fields(session, _SESSION_FIELDS, "session")
    if err:
        return _statement_error(err)
    for name in ("agent_id", "run_id"):
        if not isinstance(session[name], str) or not session[name]:
            return _statement_error(
                "attestation session.%s must be a non-empty string"
                % (name,))

    att_by = token["attested_by"]
    if not isinstance(att_by, dict):
        return _statement_error("attested_by is not a mapping")
    err = _exact_fields(att_by, _ATTESTED_BY_FIELDS, "attested_by")
    if err:
        return _statement_error(err)
    if att_by["purpose"] != ATTESTATION_PURPOSE:
        return _statement_error(
            "attested_by purpose %r is not %r"
            % (att_by.get("purpose"), ATTESTATION_PURPOSE))
    if not isinstance(att_by["keyset_key_id"], str) \
            or not att_by["keyset_key_id"]:
        return _statement_error("attested_by.keyset_key_id is not text")
    av = att_by["keyset_version"]
    if isinstance(av, bool) or not isinstance(av, int) or av < 1:
        return _statement_error("attested_by.keyset_version is not a "
                                "positive integer")
    kh = att_by["keyset_hash"]
    if not isinstance(kh, str) or len(kh) != 64:
        return _statement_error("attested_by.keyset_hash is malformed")

    env = token["envelope"]
    if not isinstance(env, dict):
        return _statement_error("attestation envelope is not a mapping")
    err = _exact_fields(env, _ENVELOPE_FIELDS, "envelope")
    if err:
        return _statement_error(err)
    if env["sig_key_id"] != att_by["keyset_key_id"] \
            or env["sig_key_version"] != av:
        return _statement_error("envelope does not name the attested_by "
                                "key (key id / version mismatch)")

    try:
        ks = Keyset.from_dict(keyset_doc)
    except KeysetError as e:
        return _statement_error("issuer keyset document invalid: %s" % e)
    if ks.purpose != ATTESTATION_PURPOSE:
        return _statement_error(
            "issuer keyset purpose %r cannot mint release attestations"
            % (ks.purpose,))
    ok, kerr = ks.verify()
    if not ok:
        return _statement_error("issuer keyset lineage invalid: %s" % kerr)
    try:
        pinned = keyset_hash_at_version(ks, av)
    except KeysetError as e:
        return _statement_error("attested keyset version not in keyset: %s"
                                % e)
    if pinned != kh:
        return _statement_error(
            "attested_by.keyset_hash does not match the issuer keyset "
            "document as of version %d (silent keyset substitution)" % av)

    # kid-from-keyset: the envelope names the key, the trusted keyset
    # resolves it. Keys embedded in the token are never accepted (the
    # insecure_header_jwk lesson).
    if forensics:
        kv, lookup = ks.find_verifying_key_for_forensics(env)
    else:
        kv, lookup = ks.find_verifying_key(env)
    if kv is None:
        return _statement_error("envelope key lookup failed: %s" % lookup)
    if kv.version != av or kv.key_id != att_by["keyset_key_id"]:
        return _statement_error("resolved key does not match attested_by")

    stmt = {k: v for k, v in token.items() if k != "envelope"}
    try:
        sig = bytes.fromhex(env["sig"])
    except (ValueError, TypeError):
        return _statement_error("envelope sig is not valid hex")
    if len(sig) != 64:
        return _statement_error("envelope sig is not 64 bytes")
    if not _ed.verify(kv.public_key, ATTESTATION_DOMAIN + _canonical(stmt),
                      sig):
        return _statement_error("attestation signature does not verify")

    return True, {
        "sub": token["sub"],
        "iss": token["iss"],
        "aud": token["aud"],
        "status": token["status"],
        "iat": token["iat"],
        "exp": token["exp"],
        "jti": token["jti"],
        "agent_scope": list(classes),
        "session": {"agent_id": session["agent_id"],
                    "run_id": session["run_id"]},
        "keyset_version": kv.version,
        "keyset_key_id": kv.key_id,
        "lookup": lookup,
    }


# ---------------------------------------------------------------------------
# Trust anchor + live attestation store (one per executor)
# ---------------------------------------------------------------------------

class AttestationReleaseConfig(object):
    """Trust anchor and live attestation store for one executor.

    ``keyset_doc`` is the trusted issuer keyset (parsed fail-fast);
    ``trusted_issuers`` the pinned issuer ids. Attestations are
    registered per agent id by the attestation service / operator and
    looked up FRESH at every release -- never cached from run start
    (per-release evaluation). ``seen_jtis`` is the replay cache.
    """

    def __init__(self, keyset_doc, trusted_issuers):
        try:
            ks = Keyset.from_dict(keyset_doc)
        except KeysetError as e:
            raise AttestationReleaseError(
                "attestation keyset document invalid: %s" % e)
        if ks.purpose != ATTESTATION_PURPOSE:
            raise AttestationReleaseError(
                "keyset purpose %r cannot anchor release attestations"
                % (ks.purpose,))
        ok, err = ks.verify()
        if not ok:
            raise AttestationReleaseError(
                "attestation keyset lineage invalid: %s" % err)
        if not trusted_issuers:
            raise AttestationReleaseError(
                "trusted_issuers must be non-empty")
        issuers = frozenset(trusted_issuers)
        if any(not isinstance(i, str) or not i for i in issuers):
            raise AttestationReleaseError(
                "trusted_issuers must be non-empty strings")
        self.keyset_doc = ks.to_dict()
        self.trusted_issuers = issuers
        self._attestations = {}  # agent_id -> token dict
        self.seen_jtis = set()
        # Trustee-style release counters (spike section 7):
        # evaluations / approvals / violations / errors. Incremented
        # by evaluate_release at the single decision point; surfaced
        # into the audit path via counters_snapshot().
        self.counters = {"evaluations": 0, "approvals": 0,
                         "violations": 0, "errors": 0}
        # Optional operator-signed policy override (the allow_all
        # escape hatch): (override, override_keyset_doc), verified at
        # install time. Consulted by the release predicate only when
        # the caller passes no explicit override. Every use is
        # LOUD-audited by the caller.
        self.policy_override = None

    def counters_snapshot(self):
        """A copy of the release counters for the audit path."""
        return dict(self.counters)

    def set_policy_override(self, override, keyset_doc, *, now=None):
        """Install an operator-signed policy override.

        Verified NOW (fail-fast): a bad override is refused at install,
        never consulted. ``keyset_doc`` is the override keyset
        (purpose ``"attestation-policy-override"``), independent of the
        attestation keyset. ``now`` is the evaluation instant (default:
        real time).
        """
        ok, info = verify_policy_override(override, keyset_doc, now=now)
        if not ok:
            raise AttestationReleaseError(
                "policy override does not verify: %s" % (info,))
        self.policy_override = (override, keyset_doc)

    def clear_policy_override(self):
        """Remove the operator-signed policy override, if any."""
        self.policy_override = None

    def register_attestation(self, agent_id, token):
        """Store the current attestation token for an agent id."""
        _require_text(agent_id, "'agent_id'")
        if not isinstance(token, dict):
            raise AttestationReleaseError("attestation token must be a dict")
        self._attestations[agent_id] = token

    def revoke_attestation(self, agent_id):
        """Drop the registry entry. Subsequent releases refuse; tokens
        already issued stay valid until ``exp`` (documented residual --
        there is no revocation list yet)."""
        return self._attestations.pop(agent_id, None) is not None

    def attestation_for(self, agent_id):
        """The current attestation for an agent id, or None."""
        return self._attestations.get(agent_id)

    def jti_seen(self, jti):
        return jti in self.seen_jtis

    def mark_jti(self, jti):
        self.seen_jtis.add(jti)


# ---------------------------------------------------------------------------
# The release predicate (our data.policy.allow)
# ---------------------------------------------------------------------------

def evaluate_release(credential_id, credential_class, token, *, config,
                     agent_id, run_id, policy="attested", override=None,
                     override_keyset_doc=None, now=None, consume=True):
    """Evaluate the release predicate for one credential.

    ``policy`` is the credential's release policy (``attested`` /
    ``deny_all``; ``legacy-host-only`` never reaches this function).
    ``override`` is an optional operator-signed policy override (the
    ``allow_all`` escape hatch -- verified against
    ``override_keyset_doc``, windowed, LOUD).

    Returns ``(True, "ok"|REASON_OPERATOR_OVERRIDE, jti)`` or
    ``(False, reason, None)``; never raises. With ``consume=True`` a
    successful evaluation marks the token's ``jti`` in the replay cache;
    the attempt-path pre-check passes ``consume=False`` so the
    authoritative execution-boundary evaluation is the single consumer.

    Trustee-style counters (evaluations / approvals / violations /
    errors) are incremented on ``config`` at this single decision
    point: ``approvals`` for allowed releases, ``violations`` for
    refused attestations (the attack shape), ``errors`` for
    operational misconfiguration (no trust anchor, unknown policy).
    """
    result = _evaluate_release(
        credential_id, credential_class, token, config=config,
        agent_id=agent_id, run_id=run_id, policy=policy, override=override,
        override_keyset_doc=override_keyset_doc, now=now, consume=consume)
    if isinstance(config, AttestationReleaseConfig):
        config.counters["evaluations"] += 1
        ok, reason = result[0], result[1]
        if ok:
            config.counters["approvals"] += 1
        elif reason.startswith("no attestation trust anchor configured") \
                or reason.startswith("unknown release policy"):
            config.counters["errors"] += 1
        else:
            config.counters["violations"] += 1
    return result


def _evaluate_release(credential_id, credential_class, token, *, config,
                      agent_id, run_id, policy="attested", override=None,
                      override_keyset_doc=None, now=None, consume=True):
    """The release predicate itself; see :func:`evaluate_release`."""
    if policy == "deny_all":
        return (False,
                "credential %r is under incident hold (deny_all): refused"
                % (credential_id,), None)
    if policy not in ("attested",):
        return (False,
                "unknown release policy %r for credential %r: refused "
                "fail-closed" % (policy, credential_id), None)
    if not isinstance(config, AttestationReleaseConfig):
        return (False,
                "no attestation trust anchor configured: release refused "
                "(no silent fallback to host-only)", None)

    if override is not None:
        ok, info = verify_policy_override(override, override_keyset_doc,
                                          now=now)
        if not ok:
            return (False,
                    "operator override invalid: %s: refused" % (info,), None)
        if credential_class not in info["agent_scope"]:
            return (False,
                    "operator override does not cover credential class %r: "
                    "refused" % (credential_class,), None)
        # The override is verified, live, and covers this class. The
        # host binding is still ANDed by the caller (it is evaluated
        # separately in substitute_for_execution). LOUD audit is the
        # caller's duty.
        return True, REASON_OPERATOR_OVERRIDE, None

    if not isinstance(token, dict):
        return (False,
                "no attestation presented for attestation-mandatory "
                "credential %r: refused (no silent fallback to host-only)"
                % (credential_id,), None)
    ok, details = verify_attestation(token, config.keyset_doc)
    if not ok:
        return False, "attestation does not verify: %s" % (details,), None

    # Trustee's affirming.rego, transposed: every conjunct must hold.
    if details["status"] != "affirming":
        return (False,
                "attestation status %r is not affirming: refused"
                % (details["status"],), None)
    if details["aud"] != ATTESTATION_AUDIENCE:
        return (False,
                "attestation audience %r is not the release domain: refused"
                % (details["aud"],), None)
    stamp = time.time() if now is None else now
    if details["iat"] > stamp + CLOCK_SKEW_SECONDS:
        return (False,
                "attestation issued in the future: refused", None)
    if details["exp"] <= stamp - CLOCK_SKEW_SECONDS:
        return (False,
                "attestation expired: refused at the execution boundary",
                None)
    if details["exp"] - details["iat"] > MAX_ATTESTATION_TTL_SECONDS:
        return (False,
                "attestation TTL exceeds the %ds maximum: refused"
                % (MAX_ATTESTATION_TTL_SECONDS,), None)
    jti = details["jti"]
    if config.jti_seen(jti):
        return (False,
                "attestation already used (jti replay): refused", None)
    if details["sub"] != agent_id:
        return (False,
                "attestation sub %r does not match the requesting agent "
                "%r: refused" % (details["sub"], agent_id), None)
    if details["iss"] not in config.trusted_issuers:
        return (False,
                "attestation issuer %r is not trusted: refused"
                % (details["iss"],), None)
    if credential_class not in details["agent_scope"]:
        return (False,
                "attestation does not cover credential class %r: refused"
                % (credential_class,), None)
    # Trustee's count(submods) > 0: an attestation covering no classes
    # must not vacuous-allow (belt-and-braces; minting already enforces
    # non-empty).
    if not details["agent_scope"]:
        return (False,
                "attestation covers no credential classes: refused", None)
    # Session binding (the JWE-to-tee-pubkey analog): the attestation is
    # bound to the attested session; a token copied into another
    # session refuses here.
    session = details["session"]
    if session["agent_id"] != agent_id or session["run_id"] != run_id:
        return (False,
                "attestation session binding mismatch: refused", None)
    if consume:
        config.mark_jti(jti)
    return True, "ok", jti


# ---------------------------------------------------------------------------
# Operator-signed policy override (the allow_all escape hatch, never silent)
# ---------------------------------------------------------------------------

def mint_policy_override(keyset, seed, *, agent_scope,
                         window_seconds=600, reason="", at=None,
                         version=None):
    """Mint an operator-signed release override for credential classes.

    This is Trustee's ``allow_all.rego`` made explicit: turning the
    engine off for a class requires a fresh operator signature, a tight
    window, and a stated reason -- and every use is LOUD-audited by the
    caller. Raises :class:`AttestationReleaseError` on bad input.
    """
    if not isinstance(keyset, Keyset):
        raise AttestationReleaseError("keyset must be a gov.keyset.Keyset")
    if keyset.purpose != OVERRIDE_PURPOSE:
        raise AttestationReleaseError(
            "keyset purpose %r cannot mint policy overrides (need %r)"
            % (keyset.purpose, OVERRIDE_PURPOSE))
    classes = _require_classes(agent_scope)
    if not isinstance(reason, str):
        raise AttestationReleaseError("'reason' must be a string")
    if isinstance(window_seconds, bool) or not isinstance(window_seconds,
                                                           int):
        raise AttestationReleaseError("'window_seconds' must be an integer")
    if window_seconds < 1 or window_seconds > 3600:
        raise AttestationReleaseError(
            "'window_seconds' must be within [1, 3600]")
    stamp = int(time.time()) if at is None else _require_int(at, "'at'")
    if version is None:
        version = keyset.primary_version
    try:
        signer = keyset_signer_for_version(keyset, version, seed)
    except KeysetError as e:
        raise AttestationReleaseError(
            "cannot mint an override signing handle: %s" % e)
    body = {
        "format": OVERRIDE_FORMAT,
        "agent_scope": list(classes),
        "not_before": stamp,
        "not_after": stamp + window_seconds,
        "reason": reason,
        "attested_by": {
            "purpose": keyset.purpose,
            "keyset_key_id": signer.key_id,
            "keyset_version": signer.key_version,
            "keyset_hash": keyset_hash_at_version(keyset,
                                                 signer.key_version),
        },
    }
    sig = signer.sign(OVERRIDE_DOMAIN + _canonical(body)).hex()
    body["envelope"] = {
        "sig_key_id": signer.key_id,
        "sig_key_version": signer.key_version,
        "sig": sig,
    }
    return body


def verify_policy_override(override, keyset_doc, *, now=None):
    """Verify an operator-signed policy override.

    Returns ``(True, details)`` or ``(False, reason)``; never raises.
    ``details`` carries agent_scope, not_before/not_after, reason.
    """
    if not isinstance(override, dict):
        return False, "override is not a mapping"
    err = _exact_fields(override, _OVERRIDE_FIELDS, "override")
    if err:
        return False, err
    if override["format"] != OVERRIDE_FORMAT:
        return False, "override format %r is not %r (exact match required)" \
            % (override.get("format"), OVERRIDE_FORMAT)
    try:
        classes = _require_classes(override["agent_scope"])
    except AttestationReleaseError as e:
        return False, "bad agent_scope: %s" % e
    for name in ("not_before", "not_after"):
        val = override.get(name)
        if isinstance(val, bool) or not isinstance(val, int):
            return False, "override %r must be an integer" % (name,)
    if override["not_after"] <= override["not_before"]:
        return False, "override window is empty"
    if not isinstance(override.get("reason"), str):
        return False, "override reason must be a string"

    att_by = override["attested_by"]
    if not isinstance(att_by, dict):
        return False, "attested_by is not a mapping"
    err = _exact_fields(att_by, _ATTESTED_BY_FIELDS, "attested_by")
    if err:
        return False, err
    if att_by["purpose"] != OVERRIDE_PURPOSE:
        return False, "attested_by purpose %r is not %r" \
            % (att_by.get("purpose"), OVERRIDE_PURPOSE)
    av = att_by["keyset_version"]
    if isinstance(av, bool) or not isinstance(av, int) or av < 1:
        return False, "attested_by.keyset_version is not a positive integer"
    kh = att_by["keyset_hash"]
    if not isinstance(kh, str) or len(kh) != 64:
        return False, "attested_by.keyset_hash is malformed"
    env = override["envelope"]
    if not isinstance(env, dict):
        return False, "override envelope is not a mapping"
    err = _exact_fields(env, _ENVELOPE_FIELDS, "envelope")
    if err:
        return False, err
    if env["sig_key_id"] != att_by["keyset_key_id"] \
            or env["sig_key_version"] != av:
        return False, "envelope does not name the attested_by key"

    try:
        ks = Keyset.from_dict(keyset_doc)
    except KeysetError as e:
        return False, "override keyset document invalid: %s" % e
    if ks.purpose != OVERRIDE_PURPOSE:
        return False, "keyset purpose %r cannot mint policy overrides" \
            % (ks.purpose,)
    ok, kerr = ks.verify()
    if not ok:
        return False, "override keyset lineage invalid: %s" % kerr
    try:
        pinned = keyset_hash_at_version(ks, av)
    except KeysetError as e:
        return False, "attested keyset version not in keyset: %s" % e
    if pinned != kh:
        return False, "attested_by.keyset_hash does not match the override " \
            "keyset document as of version %d" % av
    kv, lookup = ks.find_verifying_key(env)
    if kv is None:
        return False, "envelope key lookup failed: %s" % lookup
    if kv.version != av or kv.key_id != att_by["keyset_key_id"]:
        return False, "resolved key does not match attested_by"
    stmt = {k: v for k, v in override.items() if k != "envelope"}
    try:
        sig = bytes.fromhex(env["sig"])
    except (ValueError, TypeError):
        return False, "envelope sig is not valid hex"
    if len(sig) != 64:
        return False, "envelope sig is not 64 bytes"
    if not _ed.verify(kv.public_key, OVERRIDE_DOMAIN + _canonical(stmt),
                      sig):
        return False, "override signature does not verify"
    stamp = time.time() if now is None else now
    if not (override["not_before"] - CLOCK_SKEW_SECONDS
            <= stamp
            <= override["not_after"] + CLOCK_SKEW_SECONDS):
        return False, "override is outside its validity window"
    return True, {
        "agent_scope": list(classes),
        "not_before": override["not_before"],
        "not_after": override["not_after"],
        "reason": override["reason"],
        "keyset_version": kv.version,
        "keyset_key_id": kv.key_id,
    }


# ---------------------------------------------------------------------------
# Audit event helper (no secrets, no token material)
# ---------------------------------------------------------------------------

def release_event(*, credential_id, agent_id, run_id, verdict, reason,
                  policy, via_override=False, counters=None):
    """Build the ``attestation_release`` audit event dict.

    ``verdict`` is ``"allowed"`` or ``"denied"``. Carries credential
    id, agent id, verdict, reason, and policy -- never real values,
    never token material. ``counters`` is the Trustee-style release
    counter snapshot (evaluations / approvals / violations / errors)
    from ``AttestationReleaseConfig.counters_snapshot()``.
    """
    return {
        "event": "attestation_release",
        "run_id": run_id,
        "agent_id": agent_id,
        "credential_id": credential_id,
        "verdict": verdict,
        "reason": reason,
        "policy": policy,
        "via_override": bool(via_override),
        "counters": dict(counters) if counters is not None else None,
    }


def legacy_release_event(*, credential_id, agent_id, run_id, dest,
                         counters=None):
    """The LOUD migration-path event: a legacy host-only release.

    Every use of the ``legacy-host-only`` policy is audited loudly with
    the sunset date -- the legacy path is a bridge, not a destination.
    """
    return {
        "event": "attestation_release_legacy",
        "run_id": run_id,
        "agent_id": agent_id,
        "credential_id": credential_id,
        "verdict": "allowed",
        "policy": "legacy-host-only",
        "warning": ("legacy host-only release (no attestation condition); "
                    "migrate this credential to release_policy='attested'; "
                    "legacy path sunsets %s" % (LEGACY_RELEASE_SUNSET,)),
        "destination": dest,
        "counters": dict(counters) if counters is not None else None,
    }
