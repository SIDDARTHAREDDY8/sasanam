"""Constructive decision packets at the policy decision seam (wave-176).

OpenShell prospectus steal #2, adapted not vendored: OpenShell emits a
decision packet per authorization -- machine-checkable, self-describing,
carrying the decision plus its justification (deny + counterexample +
obligations). Ours is a SIGNED, SELF-DESCRIBING record of one policy
decision, emitted by the executor at the final allow/deny/queue routing.

The packet COMPOSES existing bindings instead of duplicating them: it
references digests (policy decision, preview, receipt) rather than
re-binding the underlying values. It EMBEDS the authority-proof outcome
(verdict + coverage domains + counterexample) when a boundary is
configured, and says "no boundary configured" otherwise.

Every field is wrapped as {"value", "producer", "producer_version"} so an
offline auditor can see exactly which component produced each claim --
the packet is verifiable WITHOUT the engine (see verify_decision_packet;
the offline probe copies decision_packet.py + decision_bom.py +
ed25519.py, plus decision_codes.py when verifying packets that carry a
decision_code section -- the taxonomy replay needs the taxonomy).

Stdlib only. Deterministic: no clock (issued_at is injectable), no
randomness (RFC 8032 deterministic nonces), no I/O, no env reads in the
build/verify path. The Ed25519 backend loads dual-mode (gov.ed25519 in
the repo, bare ed25519.py standalone) so verification works with no gov
package on sys.path.

What this does NOT do (honest boundaries):
- It does not grant authority. A within_boundary proof never upgrades a
  policy deny; the packet records the decision, it is not the decision.
- It does not prove the boundary is correct or task-minimal (steal #1's
  residuals apply unchanged).
- It is emitted at the call() decision seam only. Pre-decision
  fail-closed gates (authority-boundary refusal, quarantine, skill-watch
  denial) return before the seam; their audit entries carry the proof
  directly and no packet is emitted for them.
- The packet names the evidence-chain head it was built under; a
  concurrent writer between head-read and append is handled by the
  executor's rebuild-once (see ToolExecutor._emit_decision_packet).
"""

import base64
import hashlib
import json
import os
import stat

try:
    from . import ed25519 as _ed
except ImportError:  # standalone/offline: ed25519.py beside this file
    import ed25519 as _ed

try:
    from . import decision_bom as _bom
except ImportError:  # standalone/offline: decision_bom.py beside this file
    import decision_bom as _bom


def _decision_codes():
    """Lazy handle on gov/decision_codes (wave-228).

    Imported lazily -- and only on the decision_code path -- so the
    legacy standalone story is unchanged: a verifier that never sees a
    decision_code section never needs the taxonomy module. Packets that
    DO carry a decision_code section require decision_codes.py beside
    this file for offline verification (the verifier replays the
    claim against the live taxonomy instead of trusting the section).
    """
    try:
        from . import decision_codes as mod
    except ImportError:  # standalone/offline: decision_codes.py beside
        import decision_codes as mod  # this file
    return mod


def _trust_material():
    """Lazy handle on gov/trust_material (wave-235).

    Imported lazily -- and only on the trust-root / relied-claims
    paths -- so the legacy standalone story is unchanged: a verifier
    that never passes trust_root/relied_claims never needs
    trust_material.py beside this file.
    """
    try:
        from . import trust_material as mod
    except ImportError:  # standalone/offline: trust_material.py beside
        import trust_material as mod  # this file
    return mod


def _dsse_envelope():
    """Lazy handle on gov/dsse_envelope (wave-232).

    Imported lazily -- and only on the envelope path -- so the legacy
    standalone story is unchanged: a packet that never carries an
    envelope never needs dsse_envelope.py.
    """
    try:
        from . import dsse_envelope as mod
    except ImportError:  # standalone/offline: dsse_envelope.py beside
        import dsse_envelope as mod  # this file
    # Wave-233: register the packet domain (and the denial-receipt
    # domain, so a transplanted receipt envelope names its home
    # domain) with the shared envelope-domain registry. Registration
    # is idempotent; a transplant from an unregistered domain degrades
    # to dsse-payloadtype-mismatch -- code degrades, verdict never.
    mod.register_envelope_domain("decision_packet",
                                 DECISION_PACKET_ENVELOPE_TYPE)
    try:
        from . import deny_receipts as _dr
    except ImportError:
        try:
            import deny_receipts as _dr
        except ImportError:
            _dr = None
    if _dr is not None:
        mod.register_envelope_domain("deny_receipts",
                                     _dr.DENY_RECEIPT_ENVELOPE_TYPE)
    return mod


def _deny_receipts():
    """Lazy handle on gov/deny_receipts (wave-230).

    Imported lazily -- and only on the deny_receipt path -- so the
    legacy standalone story is unchanged: a packet builder that never
    attaches a receipt never needs the receipt module.
    """
    try:
        from . import deny_receipts as mod
    except ImportError:  # standalone/offline: deny_receipts.py beside
        import deny_receipts as mod  # this file
    return mod


DECISION_PACKET_VERSION = 1

# Wave-232 lane C: optional DSSE envelope. The payload type is vendored
# so a packet envelope can never be re-presented as another artifact's
# envelope (the payloadType is inside the signed PAE bytes).
DECISION_PACKET_ENVELOPE_TYPE = \
    "application/vnd.sasanam.decision-packet+json"

DECISIONS = ("allow", "deny", "queue")

# The authority-proof verdicts, mirroring gov/authority_proof.py
# (WITHIN/EXCEEDS/UNSUPPORTED/INCONCLUSIVE). Hardcoded (not imported) so
# this module stays standalone-verifiable; tests/test_decision_packet.py
# asserts parity with gov.authority_proof.
PROOF_VERDICTS = ("within_boundary", "exceeds_boundary",
                  "unsupported", "inconclusive")

NO_BOUNDARY = "no boundary configured"

# producer_version names the value-shape version of that producer's
# contribution as defined by decision_packet v1. All "1" today; the
# per-field split exists so a producer can rev its contribution without
# revving the whole packet schema.
PRODUCER_VERSIONS = {
    "gov/executor.py": "1",
    "gov/authority_proof.py": "1",
    "gov/decision_contract.py": "1",
    "gov/skill_watch.py": "1",
    "gov/memory_actgate.py": "1",
    "gov/audio_carrier.py": "1",
    "gov/invocation_receipts.py": "1",
    "gov/log.py": "1",
    "gov/decision_packet.py": "1",
    "gov/decision_bom.py": "1",
    # Wave-228 (decision codes): the decision_code section is produced
    # by gov/decision_codes.py at producer_version "1".
    "gov/decision_codes.py": "1",
    # Wave-230 (signed denial receipts): the deny_receipt_evidence
    # section is produced by gov/deny_receipts.py at producer_version
    # "1".
    "gov/deny_receipts.py": "1",
    # Wave-343 lane 4 (ownership inference): the owner_attribution
    # section is produced by gov/ownership_inference.py at
    # producer_version "1".
    "gov/ownership_inference.py": "1",
    # Wave-229 (policy-revision-pinned replay): the policy_revision
    # section is produced by gov/policy_revisions.py at
    # producer_version "1".
    "gov/policy_revisions.py": "1",
    # Wave-191 (identity token): the identity_token section is produced
    # by gov/identity.py at producer_version "2", leaving room for a
    # sibling identity_cert section without revving the packet.
    "gov/identity.py": "2",
}

_SIGN_DOMAIN = b"decision-packet-v1:"


class PacketError(Exception):
    """The packet could not be built (loud, fail-closed for builders)."""


class InvalidLabels(PacketError):
    """rule_labels failed validation (code ``decision-labels-invalid``).

    Raised by build_decision_packet when the rule-labels evidence map
    is not a dict of non-empty printable string keys to non-empty
    printable string values.
    """

    code = "decision-labels-invalid"


class InvalidDecisionCode(PacketError):
    """decision_code failed taxonomy mapping (wave-228).

    Raised by build_decision_packet when the decision_code refusal
    string cannot be emitted by gov/decision_codes (unmapped or
    malformed). The taxonomy's machine ``code`` (e.g.
    ``decision-code-unmapped``) is set on the instance's ``.code`` so
    callers can match on it.
    """

    def __init__(self, message, taxonomy_code):
        super().__init__(message)
        self.code = taxonomy_code


class NoPacketKeyError(Exception):
    """No packet-signing key configured (loud, no dev-key fallback)."""


# ---------------------------------------------------------------------------
# Agent identity tokens (wave-191, dexidp/dex ADAPT follow-through).
#
# The decision packet can carry an OPTIONAL identity_token section --
# the digest-bound record of the OIDC claim set the identity was
# minted from: {token_digest, iss, aud, exp, jti}, producer
# gov/identity.py, producer_version "2". The raw bearer token NEVER
# lands in the evidence chain; token_digest (sha256 of the raw JWT)
# binds the recorded claims to the presented token, and the packet's
# Ed25519 signature binds the record to the decision.
#
# verify_decision_packet takes an optional token_claims dict: the
# VERIFIED claim set -- the caller checked the JWT signature against
# the deployment's pinned issuer JWKS. The verifier enforces claim
# well-formedness, expiry (60s skew), audience, and consistency with
# the signed section and the packet's identity section. None means "no
# token presented": legacy acceptance, byte-identical to the pre-token
# verifier.
# ---------------------------------------------------------------------------

#: The audience every identity token must name (the governance layer).
TOKEN_AUDIENCE = "sasanam-policy-engine"

#: Clock-skew allowance for the exp check: a token is refused only
#: when exp is more than this many seconds in the past.
TOKEN_SKEW_SECONDS = 60

TOKEN_IDENTITY_PRODUCER = "gov/identity.py"
TOKEN_IDENTITY_PRODUCER_VERSION = "2"

#: Required claims on a presented identity-token claim set.
TOKEN_REQUIRED_CLAIMS = ("iss", "sub", "aud", "iat", "exp", "jti",
                         "principal", "role", "agent_scope")

#: The packet's identity_token section carries exactly these fields.
IDENTITY_TOKEN_FIELDS = ("token_digest", "iss", "aud", "exp", "jti")


def _now_epoch():
    import time
    return time.time()


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _norm_aud(aud):
    """Normalize an aud claim to a set of strings, or None if malformed."""
    if isinstance(aud, str):
        return {aud} if aud else None
    if (isinstance(aud, (list, tuple)) and aud
            and all(isinstance(x, str) and x for x in aud)):
        return set(aud)
    return None


def check_token_claims(claims):
    """Validate a presented identity-token claim set.

    Returns ``(True, "ok")`` or ``(False, reason)``. Never raises.

    This is the shared strict validation used by
    :func:`verify_decision_packet` (``token_claims``) and
    ``ToolExecutor.mint_identity``: every required claim present with
    the right type, a non-empty issuer string, an audience naming this
    governance layer, and an ``exp`` no more than
    :data:`TOKEN_SKEW_SECONDS` in the past. Extra claims are ignored.

    It does NOT check the JWT signature -- the caller presents the
    VERIFIED claim set (signature checked against the deployment's
    pinned issuer JWKS by the dex client). This enforces the claim
    policy on what was presented. Issuer *pinning* (claims.iss ==
    the deployment's issuer) is enforced by the packet verifier's
    consistency check against the signed identity_token section, and
    by the dex client's signature check at issuance.
    """
    if not isinstance(claims, dict):
        return False, "token_claims is not a dict"
    for name in TOKEN_REQUIRED_CLAIMS:
        if claims.get(name) is None:
            return False, "token claim %r missing" % (name,)
    iss = claims.get("iss")
    if not isinstance(iss, str) or not iss:
        return False, "token claim 'iss' must be a non-empty string"
    for name in ("sub", "jti", "principal", "role", "agent_scope"):
        val = claims.get(name)
        if not isinstance(val, str) or not val:
            return False, \
                "token claim %r must be a non-empty string" % (name,)
    aud = _norm_aud(claims.get("aud"))
    if aud is None:
        return False, "token claim 'aud' must be a non-empty string " \
            "or a list of non-empty strings"
    if TOKEN_AUDIENCE not in aud:
        return False, "token audience %r does not include %r" % (
            sorted(aud), TOKEN_AUDIENCE)
    if not _is_number(claims.get("iat")):
        return False, "token claim 'iat' must be a number"
    exp = claims.get("exp")
    if not _is_number(exp):
        return False, "token claim 'exp' must be a number"
    if exp < _now_epoch() - TOKEN_SKEW_SECONDS:
        return False, "token expired (exp %r is more than %ds in the " \
            "past)" % (exp, TOKEN_SKEW_SECONDS)
    iat = claims.get("iat")
    if iat > exp + TOKEN_SKEW_SECONDS:
        return False, "token claim 'iat' is after 'exp' (issued after " \
            "expiry)"
    return True, "ok"


def _check_identity_token_value(value):
    """Validate the 5-field identity_token section value.

    Returns ``(ok, reason)``. Shared by the builder (which raises
    :class:`PacketError` on failure) and the verifier (which fails
    closed) so the two can never disagree on the shape.
    """
    if not isinstance(value, dict):
        return False, "identity_token value is not a dict"
    if set(value.keys()) != set(IDENTITY_TOKEN_FIELDS):
        return False, "identity_token must carry exactly %r" % (
            IDENTITY_TOKEN_FIELDS,)
    if not _is_hex64(value.get("token_digest")):
        return False, "identity_token.token_digest must be 64-char " \
            "lowercase hex"
    if not isinstance(value.get("iss"), str) or not value.get("iss"):
        return False, "identity_token.iss must be a non-empty string"
    if _norm_aud(value.get("aud")) is None:
        return False, "identity_token.aud must be a non-empty string " \
            "or a list of non-empty strings"
    if not _is_number(value.get("exp")):
        return False, "identity_token.exp must be a number"
    if not isinstance(value.get("jti"), str) or not value.get("jti"):
        return False, "identity_token.jti must be a non-empty string"
    return True, "ok"


IDENTITY_CLAIMS_FIELDS = ("verification_status", "subject_digest",
                          "email_digest", "email_verified",
                          "groups_count")


def _check_identity_claims_value(value):
    """Validate the 5-field identity_claims section value.

    Returns ``(ok, reason)``. Shared by the builder (which raises
    :class:`PacketError` on failure) and the verifier (which fails
    closed) so the two can never disagree on the shape.

    The section carries only digests and machine facts -- no raw
    PII. ``email_verified=True`` requires a non-None ``email_digest``
    (verified against WHAT must be answerable from the packet). The
    verification-status vocabulary lives in
    ``gov/ownership_inference.py`` (lazy import: this module is
    import-safe for the standalone verifier).
    """
    if not isinstance(value, dict):
        return False, "identity_claims value is not a dict"
    if set(value.keys()) != set(IDENTITY_CLAIMS_FIELDS):
        return False, "identity_claims must carry exactly %r" % (
            IDENTITY_CLAIMS_FIELDS,)
    try:
        from . import ownership_inference as _oi
    except ImportError:  # standalone/offline: ownership_inference
        import ownership_inference as _oi  # beside this file
    if value.get("verification_status") not in \
            _oi.IDENTITY_VERIFICATION_STATUSES:
        return False, "identity_claims.verification_status must be one " \
            "of %r" % (sorted(_oi.IDENTITY_VERIFICATION_STATUSES),)
    subject_digest = value.get("subject_digest")
    if subject_digest is not None and not _is_hex64(subject_digest):
        return False, "identity_claims.subject_digest must be None or " \
            "64-char lowercase hex"
    email_digest = value.get("email_digest")
    if email_digest is not None and not _is_hex64(email_digest):
        return False, "identity_claims.email_digest must be None or " \
            "64-char lowercase hex"
    if not isinstance(value.get("email_verified"), bool):
        return False, "identity_claims.email_verified must be a bool"
    if value.get("email_verified") and email_digest is None:
        return False, "identity_claims.email_verified=True requires " \
            "email_digest (verified against WHAT must be answerable)"
    if not isinstance(value.get("groups_count"), int) or \
            isinstance(value.get("groups_count"), bool) or \
            value.get("groups_count") < 0:
        return False, "identity_claims.groups_count must be a " \
            "non-negative int"
    return True, "ok"


def _check_rule_labels(rule_labels):
    """Validate the rule_labels evidence map.

    Returns a fresh dict on success. Refuses ``decision-labels-invalid``
    (via :class:`InvalidLabels`) when the map is not a dict of
    non-empty string keys to non-empty printable string values --
    evidence labels must be machine-readable and safe to render, so
    control characters and empty names fail closed at construction.
    ``None`` (absent) returns None: the caller adds no section and the
    packet stays byte-identical to the legacy shape.
    """
    if rule_labels is None:
        return None
    if not isinstance(rule_labels, dict):
        raise InvalidLabels(
            "rule_labels must be a dict, got %s"
            % type(rule_labels).__name__)
    if not rule_labels:
        raise InvalidLabels("rule_labels must not be empty")
    checked = {}
    for key, value in rule_labels.items():
        if not isinstance(key, str) or not key:
            raise InvalidLabels(
                "rule_labels keys must be non-empty strings, got %r" % (key,))
        if not isinstance(value, str) or not value:
            raise InvalidLabels(
                "rule_labels[%r] value must be a non-empty string, got %r"
                % (key, value))
        if not value.isprintable() or not key.isprintable():
            raise InvalidLabels(
                "rule_labels[%r] contains non-printable characters" % (key,))
        checked[key] = value
    return checked


def _get_identity_token_section(packet):
    """Fetch and shape-check the packet's identity_token section.

    Returns ``(ok, value, reason)``. The section is optional: absence
    is reported (not an exception) so the caller can decide -- the
    legacy path skips token checks entirely, while a presented
    token_claims set with no section fails closed.
    """
    section = packet.get("identity_token")
    if section is None:
        return False, None, "packet carries no identity_token section"
    if not isinstance(section, dict):
        return False, None, "identity_token section is not a dict"
    if section.get("producer") != TOKEN_IDENTITY_PRODUCER:
        return False, "identity_token section producer must be %r" % (
            TOKEN_IDENTITY_PRODUCER,)
    if section.get("producer_version") != TOKEN_IDENTITY_PRODUCER_VERSION:
        return False, None, \
            "identity_token section producer_version must be %r" % (
                TOKEN_IDENTITY_PRODUCER_VERSION,)
    value = section.get("value")
    ok, reason = _check_identity_token_value(value)
    if not ok:
        return False, None, reason
    return True, value, "ok"


def _check_token_presentation(packet, claims):
    """Validate presented token_claims against the signed packet.

    Returns ``(ok, reason)``. Enforces: the claim set is well-formed
    and unexpired (:func:`check_token_claims`); the packet carries a
    well-formed identity_token section; the presented claims match the
    signature-bound section (iss/aud/exp/jti); and the claims agree
    with the packet's identity section (sub -> agent_id, role,
    principal). A forged claim set -- one that does not match what the
    packet key signed -- is refused here: the section values are
    covered by the packet's Ed25519 signature, so only the claims the
    packet was built under can pass.
    """
    ok, reason = check_token_claims(claims)
    if not ok:
        return False, "token_claims invalid: %s" % (reason,)
    ok, section, reason = _get_identity_token_section(packet)
    if not ok:
        return False, "token_claims presented but %s" % (reason,)
    if claims["iss"] != section["iss"]:
        return False, "token iss %r does not match the packet's " \
            "identity_token.iss %r (foreign issuer)" % (
                claims["iss"], section["iss"])
    if _norm_aud(claims["aud"]) != _norm_aud(section["aud"]):
        return False, "token aud does not match the packet's " \
            "identity_token.aud"
    if claims["exp"] != section["exp"]:
        return False, "token exp does not match the packet's " \
            "identity_token.exp"
    if claims["jti"] != section["jti"]:
        return False, "token jti does not match the packet's " \
            "identity_token.jti"
    identity = packet["identity"]["value"]
    for claim_name, field in (("sub", "agent_id"), ("role", "role"),
                              ("principal", "principal")):
        if claims[claim_name] != identity.get(field):
            return False, "token claim %r (%r) disagrees with the " \
                "packet's identity.%s (%r)" % (
                    claim_name, claims[claim_name], field,
                    identity.get(field))
    return True, "ok (token claims valid and consistent)"


def _canonical(obj):
    """Deterministic canonical JSON bytes (sort_keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def canonical_bytes(packet):
    """Canonical bytes of a packet (what digests and signatures bind)."""
    return _canonical(packet)


def packet_digest(packet):
    """sha256 over the canonical packet EXCLUDING the signature.

    This is the digest the executor's audit entry references
    (entry["packet_digest"]) and the digest linkage checks recompute.
    """
    body = {k: v for k, v in packet.items() if k != "signature"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def signing_input(body):
    """Domain-separated signing input over the unsigned body (which
    INCLUDES the authority block, mirroring gov/invocation_receipts)."""
    return _SIGN_DOMAIN + _canonical(body)


def _b64u_encode(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text):
    import base64
    if not isinstance(text, str):
        raise ValueError("not a string")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _utcnow_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def resolve_packet_key(explicit=None):
    """Resolve the Ed25519 packet-signing key (keyprovider idiom).

    Precedence: explicit hex seed > ``GOV_DECISION_PACKET_KEY`` (hex) >
    ``GOV_DECISION_PACKET_KEY_FILE`` (0600 file, hex). Nothing configured
    raises :class:`NoPacketKeyError`. No dev-key fallback, ever.

    Returns ``{"seed", "key_id", "pubkey_hex"}`` where ``key_id`` is
    ``sha256(pubkey)[:16]`` hex -- the same key-id convention as the
    invocation receipts.
    """
    seed_hex = (explicit or os.environ.get("GOV_DECISION_PACKET_KEY",
                                           "")).strip()
    if seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise NoPacketKeyError("GOV_DECISION_PACKET_KEY is not hex")
        if len(seed) != 32:
            raise NoPacketKeyError(
                "GOV_DECISION_PACKET_KEY must be 32 bytes")
        pub = _ed.publickey(seed)
        return {"seed": seed,
                "key_id": hashlib.sha256(pub).digest()[:16].hex(),
                "pubkey_hex": pub.hex()}
    key_file = os.environ.get("GOV_DECISION_PACKET_KEY_FILE", "").strip()
    if key_file:
        try:
            st = os.stat(key_file)
        except OSError as e:
            raise NoPacketKeyError(
                "refusing GOV_DECISION_PACKET_KEY_FILE %s: %s"
                % (key_file, e))
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise NoPacketKeyError(
                "refusing GOV_DECISION_PACKET_KEY_FILE %s: not 0600"
                % key_file)
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                seed = bytes.fromhex(f.read().strip())
        except (OSError, ValueError) as e:
            raise NoPacketKeyError(
                "cannot read GOV_DECISION_PACKET_KEY_FILE: %s" % (e,))
        if len(seed) != 32:
            raise NoPacketKeyError(
                "packet key file must hold 32 bytes hex")
        pub = _ed.publickey(seed)
        return {"seed": seed,
                "key_id": hashlib.sha256(pub).digest()[:16].hex(),
                "pubkey_hex": pub.hex()}
    raise NoPacketKeyError(
        # Wave-219 unsafe-path registry: gov.decision_packet.packets_disabled_no_key
        "no packet-signing key configured (GOV_DECISION_PACKET_KEY / "
        "GOV_DECISION_PACKET_KEY_FILE); decision packets are disabled "
        "[gov.decision_packet.packets_disabled_no_key]")


def _wrap(value, producer):
    """Wrap one field value with its producer attribution."""
    return {"value": value,
            "producer": producer,
            "producer_version": PRODUCER_VERSIONS[producer]}


def _check_proof_shape(proof):
    """Validate an embedded authority-proof dict. Returns (ok, reason)."""
    if not isinstance(proof, dict):
        return False, "authority_proof is not a dict"
    verdict = proof.get("verdict")
    if verdict not in PROOF_VERDICTS:
        return False, "authority_proof.verdict %r not a proof verdict" % (
            verdict,)
    for key in ("covered_domains", "uncovered_domains"):
        val = proof.get(key)
        if not isinstance(val, list) or not all(
                isinstance(x, str) for x in val):
            return False, "authority_proof.%s must be a list of str" % key
    ce = proof.get("counterexample")
    if ce is not None:
        if not isinstance(ce, dict):
            return False, "authority_proof.counterexample is not a dict"
        for key in ("domain", "access", "reason"):
            if not isinstance(ce.get(key), str):
                return False, \
                    "authority_proof.counterexample.%s must be str" % key
        # nearest_rule is Optional[str] on the producer side
        # (Counterexample.to_dict emits None when no boundary entry is
        # even close, or when the shape was unmodelable -- e.g. every
        # `unsupported` verdict). Accept str or null; anything else is
        # still malformed. (F195)
        nr = ce.get("nearest_rule")
        if nr is not None and not isinstance(nr, str):
            return False, \
                "authority_proof.counterexample.nearest_rule must be str or null"
    return True, "ok"


def _repair_hint(decision, proof):
    """The constructive element (steal #2): machine-actionable guidance
    for revising the REQUEST. Never revises the policy or the boundary."""
    if not isinstance(proof, dict):
        return None
    verdict = proof.get("verdict")
    ce = proof.get("counterexample") or {}
    if verdict == "exceeds_boundary":
        return ("narrow the request: %s access %r exceeds the boundary; "
                "nearest boundary rule %r (%s)"
                % (ce.get("domain"), ce.get("access"),
                   ce.get("nearest_rule"), ce.get("reason")))
    if verdict in ("unsupported", "inconclusive"):
        return ("the boundary does not cover this action shape (%s); "
                "declare the missing domain or split the action"
                % verdict)
    if decision == "deny":
        return ("the policy denied this action; revise the request, not "
                "the policy")
    return None


def build_decision_packet(*, decision, boundary_declared,
                          authority_proof=None,
                          policy_id=None, policy_version=None,
                          matched_rules=(), policy_flag=None,
                          decision_digest=None,
                          canonical_target=None, preview_digest=None,
                          capability_manifest_digest=None, skill_id=None,
                          actgate_tier="gate_not_attached",
                          actgate_disclosure_digest=None,
                          attachment_carriers=(), memory_carriers=(),
                          evidence_head_digest="GENESIS",
                          identity=None, approval_id=None,
                          decision_seq=None, policy_reason=None,
                          issued_at=None, bill_of_materials=None,
                          policy_bundle_digest=None, identity_token=None,
                          rule_labels=None, decision_code=None,
                          policy_rev_id=None, policy_digest=None,
                          deny_receipt=None, owner_attribution=None,
                          identity_claims=None):
    """Build the UNSIGNED decision-packet body (dict, no ``signature``).

    ``decision`` is "allow" | "deny" | "queue" (the executor maps
    require_approval -> queue). ``authority_proof`` is the
    AuthorityProof.to_dict() when a boundary is declared, else None
    (the packet then records "no boundary configured"). Digests are
    referenced, not re-bound: ``decision_digest`` (sha256 over the
    canonical policy decision), ``preview_digest``, and the receipt
    digest (minted post-execution; the packet carries None and names
    the invocation_receipt entry that chains under it).

    Raises :class:`PacketError` (loud) when a declared boundary has no
    proof, or when a proof rides an undeclared boundary -- a packet
    that misstates the boundary posture is refused at construction,
    not patched at verify time.

    ``identity_token`` is the OPTIONAL digest-bound record of the OIDC
    claim set the identity was minted from: exactly
    ``{token_digest, iss, aud, exp, jti}`` -- the claims, never the raw
    bearer token. ``None`` builds a legacy packet: the 17 existing
    sections are byte-identical to a build without the kwarg.

    ``identity_claims`` (wave-345 lane 6) is the OPTIONAL machine
    record of the verified ``mint_identity`` claims bound to this
    packet's acting identity: exactly
    ``{verification_status, subject_digest, email_digest,
    email_verified, groups_count}`` -- digests and machine facts, no
    raw PII. ``verification_status`` is one of
    ``gov/ownership_inference.IDENTITY_VERIFICATION_STATUSES``;
    ``email_verified=True`` requires a non-None ``email_digest``. The
    executor builds it at packet-emit time from the claim record
    captured at mint (binding-checked against the acting identity);
    malformed values raise :class:`PacketError`. The section is
    signature-covered like every other section, so a swapped digest
    breaks the packet signature, and the verifier re-validates the
    shape after the signature. ``None`` (the default) builds a legacy
    packet: no ``identity_claims`` section is added and the body is
    byte-identical to a build without the kwarg. The section is
    evidence of how the acting identity was verified, never
    authority.

    ``rule_labels`` is the OPTIONAL evidence-enrichment map
    ``{rule_name: rule_identifier}`` naming the policy rules/verdicts
    that produced the decision (OPA 1.21.1 ``rule_labels`` pattern,
    re-derived -- prose and mechanics written fresh). Keys must be
    non-empty strings and values non-empty printable strings;
    violations raise :class:`InvalidLabels`
    (``decision-labels-invalid``). ``None`` builds a legacy packet: no
    ``rule_labels`` section is added and the body is byte-identical to
    a build without the kwarg. When present the section is
    signature-covered like every other section, so a swapped label
    breaks the packet signature.

    ``decision_code`` (wave-228) is the OPTIONAL machine decision-code
    refusal string (see gov/decision_codes.py) naming the refusal the
    packet records, e.g. ``"capsule-count-mismatch"``. Only a mapped
    refusal string is accepted: the builder emits the machine claim
    through the taxonomy itself (``decision_codes.emit``), so a
    caller-supplied claim dict can never be smuggled in; an unmapped
    or malformed string raises :class:`InvalidDecisionCode`
    (carrying the taxonomy's ``decision-code-unmapped`` /
    ``decision-code-malformed`` on ``.code``). ``None`` (the default)
    builds a legacy packet: no ``decision_code`` section is added and
    the body is byte-identical to a build without the kwarg. When
    present the section is signature-covered like every other section,
    so a swapped code breaks the packet signature; the verifier
    additionally replays the claim against the live taxonomy. The
    attached code is EVIDENCE, never authority: it records which
    refusal fired and how to re-verify it, and confers no permission.

    ``policy_rev_id`` / ``policy_digest`` (wave-229) are the OPTIONAL
    pinned policy revision (see gov/policy_revisions.py): ``rev_id``
    like ``"policy:1"`` and the recomputed sha256 digest of the exact
    ruleset bytes. Both must be supplied together (half-pinned
    refuses :class:`PacketError`); the section is digest-bound and
    signature-covered like every other section, so a swapped digest
    breaks the packet signature. ``None`` (the default) builds a
    legacy packet: no ``policy_revision`` section is added and the
    body is byte-identical to a build without the kwargs. The pinned
    revision is evidence for replay, never authority.

    ``deny_receipt`` (wave-230) is the OPTIONAL signed denial (or
    permit) receipt dict produced by gov/deny_receipts.emit. The
    packet stores its digest-linked evidence record (see
    gov/deny_receipts.receipt_evidence), signature-covered like every
    other section (it is part of the body before sign_packet runs),
    so a swapped digest breaks the packet signature. The full signed
    receipt travels out of band; an auditor re-verifies it against
    the digest committed here. ``None`` (the default) builds a legacy
    packet: no ``deny_receipt_evidence`` section is added and the
    body is byte-identical to a build without the kwarg. The receipt
    is evidence of the decision, never authority.

    ``owner_attribution`` (wave-343 lane 4) is the OPTIONAL
    ownership-attribution dict produced by
    ``gov/ownership_inference.infer_owner`` / ``attribute_owner``
    (Rig steal #3: every agent identity auto-traced to its human
    owner -- "block the agent, not the employee"). The value is
    shape-checked AND digest-recomputed at construction
    (``check_attribution_value`` -- compare-don't-trust, a
    caller-supplied dict is never trusted); a malformed or
    digest-mismatched attribution raises :class:`PacketError`. The
    section is signature-covered like every other section, so a
    swapped owner breaks the packet signature, and the verifier
    re-validates shape + digest after the signature. ``None`` (the
    default) builds a legacy packet: no ``owner_attribution`` section
    is added and the body is byte-identical to a build without the
    kwarg. An attribution with ``owner: None`` carries the coded
    unresolved state (``ownership-inference-unresolved`` /
    ``-ambiguous``) -- the undecided state is explicit, never
    omitted.
    """
    if decision not in DECISIONS:
        raise PacketError(
            "decision must be one of %r, got %r" % (DECISIONS, decision))
    if not isinstance(boundary_declared, bool):
        raise PacketError("boundary_declared must be bool")
    if boundary_declared:
        ok, reason = _check_proof_shape(authority_proof)
        if not ok:
            raise PacketError(
                "boundary declared but authority proof invalid: %s"
                % reason)
        proof_value = authority_proof
    else:
        if authority_proof is not None:
            raise PacketError(
                "no boundary declared but an authority proof was supplied "
                "-- refusing to misstate the boundary posture")
        proof_value = NO_BOUNDARY
    if actgate_tier not in ("gate_not_attached", "no_un_elevated_reads",
                            "un_elevated_reads_present"):
        raise PacketError("unknown actgate_tier %r" % (actgate_tier,))
    # Wave-180 (Decision BOM): every packet carries the bill of
    # materials -- the digest-bound list of every input artifact that
    # informed the decision. A packet without one does not meet the
    # evidence bar and is refused at construction, not patched later.
    if bill_of_materials is None:
        raise PacketError(
            "bill_of_materials is required: every decision packet "
            "must carry a Decision BOM (gov/decision_bom.build_bom)")
    bom_ok, bom_reason = _bom.check_bom_shape(bill_of_materials)
    if not bom_ok:
        raise PacketError(
            "bill_of_materials malformed: %s" % bom_reason)
    if identity_token is not None:
        tok_ok, tok_reason = _check_identity_token_value(identity_token)
        if not tok_ok:
            raise PacketError(
                "identity_token invalid: %s" % tok_reason)
    if identity_claims is not None:
        clm_ok, clm_reason = _check_identity_claims_value(identity_claims)
        if not clm_ok:
            raise PacketError(
                "identity_claims invalid: %s" % clm_reason)
    ident = identity if isinstance(identity, dict) else {}
    body = {
        "decision_packet_version": DECISION_PACKET_VERSION,
        "decision": _wrap(decision, "gov/executor.py"),
        "boundary_declared": _wrap(boundary_declared, "gov/executor.py"),
        "authority_proof": _wrap(proof_value, "gov/authority_proof.py"),
        "policy": _wrap({
            "policy_id": policy_id,
            "policy_version": policy_version,
            # The policy bundle itself, by digest: sha256 over the exact
            # bytes the engine parsed (PolicyEngine.policy_hash). The
            # verifier cross-checks the BOM's policy digest against this
            # field, so a swapped BOM digest fails PACKET verification,
            # not just the on-demand audit path. None when the caller
            # has no bundle digest (the cross-check is then skipped).
            "policy_bundle_digest": policy_bundle_digest,
            "matched_rules": list(matched_rules or []),
            "policy_flag": policy_flag,
            # The decision itself, by digest: the packet composes the
            # policy binding rather than re-binding it. An auditor
            # re-hashes the chained decision entry to confirm.
            "decision_digest": decision_digest,
        }, "gov/decision_contract.py"),
        "canonical_target": _wrap(canonical_target, "gov/executor.py"),
        "preview_digest": _wrap(preview_digest, "gov/executor.py"),
        "capability_manifest": _wrap({
            "digest": capability_manifest_digest,
            "skill_id": skill_id,
        }, "gov/skill_watch.py"),
        "memory_actgate": _wrap({
            "tier": actgate_tier,
            "disclosure_digest": actgate_disclosure_digest,
        }, "gov/memory_actgate.py"),
        "carriers": _wrap({
            "attachment_carriers": list(attachment_carriers or []),
            "memory_carriers": list(memory_carriers or []),
        }, "gov/audio_carrier.py"),
        "evidence": _wrap({
            # The chain head this packet was built under. The packet's
            # own audit entry chains onto it; linkage is verified by
            # matching entry prev_hash (see verify_decision_packet).
            "head_digest": evidence_head_digest,
        }, "gov/log.py"),
        "identity": _wrap({
            "agent_id": ident.get("agent_id"),
            "role": ident.get("role"),
            "principal": ident.get("principal"),
            "run_id": ident.get("run_id"),
        }, "gov/executor.py"),
        "approval_id": _wrap(approval_id, "gov/executor.py"),
        "decision_seq": _wrap(decision_seq, "gov/executor.py"),
        # The constructive refusal (steal #2): what the decision was
        # and, on deny/exceeds, machine-readable guidance for revising
        # the REQUEST. Never revises the policy or the boundary.
        "justification": _wrap({
            "policy_reason": policy_reason,
            "matched_rules": list(matched_rules or []),
            "counterexample": ((authority_proof or {}).get("counterexample")
                               if boundary_declared else None),
            "repair_hint": _repair_hint(decision,
                                        authority_proof
                                        if boundary_declared else None),
        }, "gov/decision_packet.py"),
        # Receipts mint post-execution over the executed action; the
        # packet references the receipt by digest when one exists yet
        # (it never does at decision time -- the packet is emitted
        # first and the invocation_receipt entry chains under it).
        # None here is honest ordering, not a gap.
        "receipt_digest": _wrap(None, "gov/invocation_receipts.py"),
        # Wave-180 (Decision BOM): the digest-bound input list. The
        # signature covers this section, so a swapped entry breaks
        # the signature; the verifier additionally cross-checks the
        # BOM against the packet's own sections (fail-closed).
        "bill_of_materials": _wrap(bill_of_materials,
                                   "gov/decision_bom.py"),
        "issued_at": _wrap(issued_at or _utcnow_iso(),
                           "gov/decision_packet.py"),
    }
    if identity_token is not None:
        # Wave-191 (identity token): the optional digest-bound record
        # of the OIDC claim set. Signature-covered like every other
        # section (it is part of the body before sign_packet runs), so
        # a swapped record breaks the packet signature; the verifier
        # additionally cross-checks presented token claims against it.
        # A copy is stored so the caller's dict is never aliased.
        body["identity_token"] = _wrap(dict(identity_token),
                                       TOKEN_IDENTITY_PRODUCER)
    if identity_claims is not None:
        # Wave-345 (ownership threading): the digest-bound record of
        # the verified mint_identity claims bound to this packet's
        # acting identity. Signature-covered like every other section
        # (it is part of the body before sign_packet runs), so a
        # swapped digest breaks the packet signature; the verifier
        # additionally re-validates the shape. A copy is stored so
        # the caller's dict is never aliased.
        body["identity_claims"] = _wrap(dict(identity_claims),
                                        "gov/executor.py")
    labels = _check_rule_labels(rule_labels)
    if labels is not None:
        # Wave-225 (rule labels): the optional evidence-enrichment
        # section naming the rules/verdicts that produced the
        # decision. Signature-covered like every other section (it is
        # part of the body before sign_packet runs), so a swapped
        # label breaks the packet signature. A copy is stored so the
        # caller's dict is never aliased.
        body["rule_labels"] = _wrap(dict(labels), "gov/decision_packet.py")
    if decision_code is not None:
        # Wave-228 (decision codes): the optional machine decision-code
        # section. Only a mapped refusal STRING is accepted -- the
        # builder emits the claim through the taxonomy itself, never
        # trusting a caller-supplied claim dict. Unmapped/malformed
        # strings refuse at construction via InvalidDecisionCode.
        # Signature-covered like every other section (it is part of
        # the body before sign_packet runs), so a swapped code breaks
        # the packet signature; the verifier replays the claim
        # against the live taxonomy. The attached code is evidence,
        # never authority.
        _dc = _decision_codes()
        try:
            machine_claim = _dc.emit(decision_code)
        except _dc.DecisionCodeError as e:
            raise InvalidDecisionCode(
                "decision_code %r refused by the taxonomy: %s"
                % (decision_code, e), e.code)
        body["decision_code"] = _wrap(machine_claim,
                                      "gov/decision_codes.py")
    if (policy_rev_id is None) != (policy_digest is None):
        raise PacketError(
            "policy_rev_id and policy_digest must be supplied "
            "together: a half-pinned revision misstates the replay "
            "posture")
    if policy_rev_id is not None:
        # Wave-229 (policy-revision-pinned replay): the optional
        # digest-bound pinned policy revision. The value is stored
        # verbatim as digest-linked evidence; signature-covered like
        # every other section (it is part of the body before
        # sign_packet runs), so a swapped digest breaks the packet
        # signature. The producer pins the revision via
        # gov/policy_revisions -- the packet never trusts a bare
        # claim without the digest.
        if not isinstance(policy_rev_id, str) or not policy_rev_id:
            raise PacketError("policy_rev_id must be a non-empty string")
        if not isinstance(policy_digest, str) or len(policy_digest) != 64:
            raise PacketError("policy_digest must be a 64-char hex digest")
        body["policy_revision"] = _wrap(
            {"rev_id": policy_rev_id, "digest": policy_digest},
            "gov/policy_revisions.py")
    if deny_receipt is not None:
        # Wave-230 (signed denial receipts): the optional
        # digest-linked receipt evidence. The module validates the
        # receipt shape itself (never a caller-supplied digest), and
        # the evidence record is signature-covered like every other
        # section, so a swapped digest breaks the packet signature.
        _dr = _deny_receipts()
        try:
            ev = _dr.receipt_evidence(deny_receipt)
        except _dr.DenyReceiptError as e:
            raise PacketError(
                "deny_receipt refused by gov/deny_receipts: %s" % e)
        body["deny_receipt_evidence"] = _wrap(
            ev, "gov/deny_receipts.py")
    if owner_attribution is not None:
        # Wave-343 lane 4 (ownership inference): the optional
        # owner-attribution evidence section. Shape-checked AND
        # digest-recomputed via the inference module -- a
        # caller-supplied dict is never trusted, and a digest
        # mismatch refuses at construction (PacketError), not at
        # verify time. Signature-covered like every other section;
        # a swapped owner breaks the packet signature, and the
        # verifier re-validates shape + digest after the signature.
        # A copy is stored so the caller's dict is never aliased.
        try:
            from . import ownership_inference as _oi
        except ImportError:  # standalone/offline: ownership_inference
            import ownership_inference as _oi  # beside this file
        ok, reason = _oi.check_attribution_value(owner_attribution)
        if not ok:
            raise PacketError(
                "owner_attribution invalid: %s" % reason)
        body["owner_attribution"] = _wrap(dict(owner_attribution),
                                         "gov/ownership_inference.py")
    return body


def sign_packet(body, seed, *, envelope=False):
    """Attach the executor's Ed25519 packet signature. Returns a new dict.

    ``seed`` is the 32-byte packet-signing seed (see resolve_packet_key).
    The authority block (kid/pubkey) is part of the signed body, so the
    signature binds the key identity to the packet.

    Wave-232: ``envelope`` (keyword-only, default False) attaches an
    additional DSSE ``"envelope"`` field whose signature covers the PAE
    bytes (vendored payloadType + canonical body). Additive only: the
    legacy ``"signature"`` field is unchanged, so an envelope-bearing
    packet minus its ``"envelope"`` field is byte-identical to the
    legacy packet.
    """
    if not isinstance(body, dict):
        raise PacketError("body must be a dict")
    if "signature" in body:
        raise PacketError("body is already signed")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise PacketError("seed must be 32 bytes")
    pub = _ed.publickey(bytes(seed))
    authority = {"kid": hashlib.sha256(pub).digest()[:16].hex(),
                 "pubkey": pub.hex()}
    body_with_auth = dict(body)
    body_with_auth["authority"] = authority
    sig = _ed.sign(bytes(seed), signing_input(body_with_auth))
    packet = dict(body_with_auth)
    packet["signature"] = _b64u_encode(sig)
    if envelope:
        mod = _dsse_envelope()
        pae_bytes = mod.pae(DECISION_PACKET_ENVELOPE_TYPE,
                            signing_input(body_with_auth))
        try:
            env_sig = _ed.sign(bytes(seed), pae_bytes)
        except Exception as exc:
            raise PacketError("dsse-envelope-malformed: packet envelope "
                              "signing failed: %s" % (exc,))
        packet["envelope"] = {
            "payloadType": DECISION_PACKET_ENVELOPE_TYPE,
            "payload": base64.b64encode(
                signing_input(body_with_auth)).decode("ascii"),
            "signatures": [{
                "keyid": authority["kid"],
                "sig": bytes(env_sig).hex(),
            }],
            "signing_input_digest":
                hashlib.sha256(pae_bytes).hexdigest(),
        }
    return packet


def _find_packet_entries(entries, digest):
    """Decision-packet audit entries whose packet_digest matches."""
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "decision_packet":
            continue
        if e.get("packet_digest") == digest:
            out.append(e)
    return out


def verify_decision_packet(packet, entries=None, token_claims=None,
                           trust_root=None, relied_claims=None):
    """Offline verification of a signed decision packet (stdlib only).

    Returns ``(True, "ok")`` or ``(False, reason)``. Never raises on
    malformed input (fail-closed for verifiers: malformed is False, never
    an exception). Checks, in order: structure (every section present and
    producer-attributed), packet version, decision value, the
    boundary/proof consistency rule (a declared boundary MUST carry a
    proof; an undeclared boundary MUST NOT), authority well-formedness
    (32-byte pubkey, kid == sha256(pub)[:16]), the Ed25519 signature over
    the domain-separated canonical body, the decision_code replay
    against the live taxonomy (when a decision_code section is
    present -- an unmapped or mutated refusal is refused at the
    taxonomy seam, never trusted), the BOM cross-checks (including
    the wave-191 token_digest agreement when both sides record one),
    the optional token-consistency check (see ``token_claims``), and --
    when ``entries`` (audit entries) are supplied -- the digest linkage:
    some decision_packet entry references this packet's digest AND its
    prev_hash equals the packet's stated head digest AND that head
    exists in the chain.

    ``token_claims`` is the OPTIONAL verified OIDC claim set the
    identity was minted from (the caller checked the JWT signature
    against the deployment's pinned issuer JWKS). ``None`` -- the
    default -- is the legacy path: token checks are skipped entirely
    and acceptance is byte-identical to the pre-token verifier. A dict
    is strictly validated (required claims, types, audience, expiry
    with 60s skew) and must be consistent with the packet's signed
    identity_token section (iss/aud/exp/jti) and its identity section
    (sub -> agent_id, role, principal); any failure returns
    ``(False, reason)``.

    ``trust_root`` is the OPTIONAL external trust root
    (``gov.trust_material.TrustRoot``) the deployment pinned the
    packet-signing keys in. ``None`` -- the default -- keeps the
    legacy semantics exactly: the record's self-asserted authority
    block is trusted after the well-formedness checks. When a root is
    supplied, the packet's (kid, pubkey) pair is bound to the root
    after the pubkey shape check and BEFORE the kid/pubkey
    self-consistency check: an unpinned key id refuses
    ``untrusted-key`` (key material carried inside the record is never
    trusted) and a pinned key id with different material refuses
    ``trust-key-repointed``. External-root enforcement is opt-in: the
    deployment owns the root-pinning decision (wave-235 honest
    residual -- without a pinned root there is no external trust).

    ``relied_claims`` is the OPTIONAL ``{field: expected_value}`` set
    of claims the caller wants verification to treat as trusted. Every
    named claim is resolved from the SIGNATURE-COVERED body only: a
    claim with no covered source refuses ``unsigned-field-ignored``
    (fail closed, never silent accept), and a claim whose covered
    value disagrees with the expected value refuses. Unsigned fields
    are never consulted by verification.

    ``entries=None`` skips the linkage check (reported in the reason);
    pass the chain for the full check.
    """
    try:
        return _verify(packet, entries, token_claims, trust_root,
                       relied_claims)
    except Exception as e:  # noqa: BLE001 - verifiers never raise
        return False, "verifier exception (fail-closed): %s: %s" % (
            type(e).__name__, e)


def _verify(packet, entries, token_claims, trust_root, relied_claims):
    if not isinstance(packet, dict):
        return False, "packet is not a dict"
    if packet.get("decision_packet_version") != DECISION_PACKET_VERSION:
        return False, "unsupported decision_packet_version %r" % (
            packet.get("decision_packet_version"),)
    required = ("decision", "boundary_declared", "authority_proof",
                "policy", "canonical_target", "preview_digest",
                "capability_manifest", "memory_actgate", "carriers",
                "evidence", "identity", "approval_id", "decision_seq",
                "justification", "receipt_digest", "bill_of_materials",
                "issued_at")
    for name in required:
        section = packet.get(name)
        if not isinstance(section, dict):
            return False, "missing section %r" % name
        if "value" not in section:
            return False, "section %r has no value" % name
        if not section.get("producer"):
            return False, "section %r names no producer" % name
        if not section.get("producer_version"):
            return False, "section %r names no producer_version" % name
    labels_section = packet.get("rule_labels")
    if labels_section is not None:
        # Wave-225 (rule labels): optional evidence section. When
        # present it must be well-formed and producer-attributed; the
        # label values themselves are signature-covered, so a tampered
        # label fails the signature check below -- this rejects
        # malformed shapes for unsigned consumers (defense in depth).
        if not isinstance(labels_section, dict):
            return False, "rule_labels section is not a dict"
        if "value" not in labels_section:
            return False, "rule_labels section has no value"
        if not labels_section.get("producer"):
            return False, "rule_labels section names no producer"
        if not labels_section.get("producer_version"):
            return False, "rule_labels section names no producer_version"
        labels_value = labels_section.get("value")
        if not isinstance(labels_value, dict) or not labels_value:
            return False, "rule_labels value must be a non-empty dict"
        for lkey, lval in labels_value.items():
            if (not isinstance(lkey, str) or not lkey
                    or not lkey.isprintable()
                    or not isinstance(lval, str) or not lval
                    or not lval.isprintable()):
                return False, \
                    "rule_labels entries must be non-empty printable strings"
    code_section = packet.get("decision_code")
    if code_section is not None:
        # Wave-228 (decision codes): optional evidence section. When
        # present it must be well-formed and producer-attributed; the
        # claim value is signature-covered, so a tampered claim fails
        # the signature check below -- and the verifier replays the
        # claim against the live taxonomy after the signature (a
        # well-signed section naming an unmapped or mutated refusal is
        # refused at the taxonomy seam, never trusted).
        if not isinstance(code_section, dict):
            return False, "decision_code section is not a dict"
        if "value" not in code_section:
            return False, "decision_code section has no value"
        if code_section.get("producer") != "gov/decision_codes.py":
            return False, "decision_code section producer must be " \
                "'gov/decision_codes.py'"
        if code_section.get("producer_version") != \
                PRODUCER_VERSIONS["gov/decision_codes.py"]:
            return False, "decision_code section producer_version " \
                "must be %r" % (PRODUCER_VERSIONS["gov/decision_codes.py"],)
    owner_section = packet.get("owner_attribution")
    if owner_section is not None:
        # Wave-343 lane 4 (ownership inference): optional evidence
        # section. When present it must be well-formed,
        # producer-attributed, and its value must pass the inference
        # module's shape + digest check -- a tampered owner fails the
        # signature check below, and a well-signed section with a
        # recomputed-digest mismatch is refused at this seam (defense
        # in depth for unsigned consumers).
        if not isinstance(owner_section, dict):
            return False, "owner_attribution section is not a dict"
        if "value" not in owner_section:
            return False, "owner_attribution section has no value"
        if owner_section.get("producer") != "gov/ownership_inference.py":
            return False, "owner_attribution section producer must be " \
                "'gov/ownership_inference.py'"
        if owner_section.get("producer_version") != \
                PRODUCER_VERSIONS["gov/ownership_inference.py"]:
            return False, "owner_attribution section producer_version " \
                "must be %r" % (
                    PRODUCER_VERSIONS["gov/ownership_inference.py"],)
        try:
            from . import ownership_inference as _oiv
        except ImportError:  # standalone/offline
            import ownership_inference as _oiv
        ok, reason = _oiv.check_attribution_value(
            owner_section.get("value"))
        if not ok:
            return False, "owner_attribution value invalid: %s" % reason
    ic_section = packet.get("identity_claims")
    if ic_section is not None:
        # Wave-345 (ownership threading): optional evidence section
        # carrying the verified mint_identity claim record bound to
        # this packet's acting identity. When present it must be
        # well-formed and producer-attributed; the digests are
        # signature-covered, so a swapped digest fails the signature
        # check below. The shape is re-validated with the SAME
        # checker the builder used, so builder and verifier can never
        # disagree. The section is evidence of how the acting identity
        # was verified, never authority.
        if not isinstance(ic_section, dict):
            return False, "identity_claims section is not a dict"
        if "value" not in ic_section:
            return False, "identity_claims section has no value"
        if ic_section.get("producer") != "gov/executor.py":
            return False, "identity_claims section producer must be " \
                "'gov/executor.py'"
        if ic_section.get("producer_version") != \
                PRODUCER_VERSIONS["gov/executor.py"]:
            return False, "identity_claims section producer_version " \
                "must be %r" % (PRODUCER_VERSIONS["gov/executor.py"],)
        _ic_ok, _ic_reason = _check_identity_claims_value(
            ic_section.get("value"))
        if not _ic_ok:
            return False, "identity_claims value invalid: %s" % _ic_reason
    rev_section = packet.get("policy_revision")
    if rev_section is not None:
        # Wave-229 (policy-revision-pinned replay): optional
        # evidence section. When present it must be well-formed and
        # producer-attributed; the pinned digest is signature-covered,
        # so a tampered digest fails the signature check below. The
        # digest is evidence for replay, never authority.
        if not isinstance(rev_section, dict):
            return False, "policy_revision section is not a dict"
        if "value" not in rev_section:
            return False, "policy_revision section has no value"
        if rev_section.get("producer") != "gov/policy_revisions.py":
            return False, "policy_revision section producer must be " \
                "'gov/policy_revisions.py'"
        if rev_section.get("producer_version") != \
                PRODUCER_VERSIONS["gov/policy_revisions.py"]:
            return False, "policy_revision section producer_version " \
                "must be %r" % (PRODUCER_VERSIONS["gov/policy_revisions.py"],)
        rev_value = rev_section.get("value")
        if not isinstance(rev_value, dict):
            return False, "policy_revision section value is not a dict"
        if not isinstance(rev_value.get("rev_id"), str) \
                or not rev_value.get("rev_id"):
            return False, "policy_revision rev_id must be a non-empty " \
                "string"
        digest = rev_value.get("digest")
        if not isinstance(digest, str) or len(digest) != 64 \
                or set(digest) - set("0123456789abcdef"):
            return False, "policy_revision digest must be a 64-char " \
                "hex digest"
    dr_section = packet.get("deny_receipt_evidence")
    if dr_section is not None:
        # Wave-230 (signed denial receipts): optional evidence
        # section. When present it must be well-formed and
        # producer-attributed; the receipt digest is
        # signature-covered, so a swapped digest fails the signature
        # check below. The evidence record is checked for shape
        # (digest + verdict + class) -- the full signed receipt is
        # re-verified by the auditor out of band against the committed
        # digest. The receipt is evidence of the decision, never
        # authority.
        if not isinstance(dr_section, dict):
            return False, "deny_receipt_evidence section is not a dict"
        if "value" not in dr_section:
            return False, "deny_receipt_evidence section has no value"
        if dr_section.get("producer") != "gov/deny_receipts.py":
            return False, "deny_receipt_evidence section producer must be " \
                "'gov/deny_receipts.py'"
        if dr_section.get("producer_version") != \
                PRODUCER_VERSIONS["gov/deny_receipts.py"]:
            return False, "deny_receipt_evidence section producer_version " \
                "must be %r" % (PRODUCER_VERSIONS["gov/deny_receipts.py"],)
        dr_value = dr_section.get("value")
        if not isinstance(dr_value, dict):
            return False, "deny_receipt_evidence section value is not a dict"
        if dr_value.get("kind") != "deny-receipt-evidence":
            return False, "deny_receipt_evidence kind mismatch"
        digest = dr_value.get("digest")
        if not isinstance(digest, str) or len(digest) != 64 \
                or set(digest) - set("0123456789abcdef"):
            return False, "deny_receipt_evidence digest must be a 64-char " \
                "hex digest"
        if dr_value.get("verdict") not in ("PERMIT", "DENY"):
            return False, "deny_receipt_evidence verdict must be " \
                "PERMIT or DENY"
        if dr_value.get("class") not in ("ok", "violation", "unavailable"):
            return False, "deny_receipt_evidence class must be ok, " \
                "violation or unavailable"
    if packet["decision"]["value"] not in DECISIONS:
        return False, "decision %r not in %r" % (
            packet["decision"]["value"], DECISIONS)
    declared = packet["boundary_declared"]["value"]
    if not isinstance(declared, bool):
        return False, "boundary_declared is not bool"
    proof_value = packet["authority_proof"]["value"]
    if declared:
        ok, reason = _check_proof_shape(proof_value)
        if not ok:
            return False, \
                "boundary declared but no valid authority proof: %s" % reason
    else:
        if proof_value != NO_BOUNDARY:
            return False, \
                "no boundary declared but packet carries a proof"
    auth = packet.get("authority")
    if not isinstance(auth, dict):
        return False, "missing authority block"
    try:
        pub = bytes.fromhex(auth.get("pubkey") or "")
    except (ValueError, TypeError):
        return False, "authority.pubkey not hex"
    if len(pub) != 32:
        return False, "authority.pubkey not 32 bytes"
    if trust_root is not None:
        # Wave-235 (trust-material externality): bind the record's
        # (kid, pubkey) pair to the EXTERNAL trust root BEFORE any
        # self-consistency check. The root is the deployment's pinned
        # key material; the record's own key material (authority block,
        # any embedded keys bundle) is never consulted. An unpinned key
        # id refuses untrusted-key; a pinned id with different material
        # refuses trust-key-repointed. From here on the verifier uses
        # the PINNED material, never the record's.
        _tm = _trust_material()
        if not isinstance(trust_root, _tm.TrustRoot):
            return False, \
                "trust_root is not a gov.trust_material.TrustRoot"
        try:
            pub = trust_root.bind_authority(auth.get("kid"), pub)
        except _tm.TrustMaterialError as exc:
            return False, "%s: %s" % (exc.code, exc.detail)
    if auth.get("kid") != hashlib.sha256(pub).digest()[:16].hex():
        return False, "authority.kid does not match pubkey"
    sig_b64 = packet.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        return False, "missing signature"
    try:
        sig = _b64u_decode(sig_b64)
    except (ValueError, TypeError):
        return False, "signature not base64url"
    body = {k: v for k, v in packet.items()
            if k not in ("signature", "envelope")}
    if not _ed.verify(pub, signing_input(body), sig):
        return False, "Ed25519 packet signature does not verify"
    # Wave-232: when an envelope rides along, verify it too -- through the
    # shared verify_envelope seam so the strictness matches the receipt
    # path exactly (unknown fields refused, PAE recomputed from the
    # decoded fields and digest-bound, every listed signature verified
    # over the PAE bytes with the authority key). The envelope's payload
    # must additionally be exactly the signed body bytes (payload
    # transplant is refused). The legacy path above is unchanged
    # (narrowing, never widened).
    if "envelope" in packet:
        mod = _dsse_envelope()

        def _verify_envelope(pae_bytes, sig_bytes, _pub=pub):
            return bool(_ed.verify(_pub, pae_bytes, sig_bytes))

        try:
            got = mod.verify_envelope(
                packet["envelope"], verify=_verify_envelope,
                expected_type=DECISION_PACKET_ENVELOPE_TYPE,
                expected_domain="decision_packet")
        except mod.EnvelopeError as exc:
            return False, exc.reason
        if got["payload"] != signing_input(body):
            return False, "dsse-signature-invalid: packet envelope " \
                "payload is not the packet's signed body (payload " \
                "transplant)"
    # Wave-235 (trust-material externality): claims the caller wants
    # verification to rely on are resolved from the SIGNATURE-COVERED
    # body only -- this runs after the signature check, so the body is
    # trustworthy here. A claim with no covered source refuses
    # unsigned-field-ignored (fail closed, never silent accept); a
    # claim whose covered value disagrees refuses as a mismatch.
    # Unsigned fields are never consulted by verification.
    if relied_claims is not None:
        if not isinstance(relied_claims, dict):
            return False, "relied_claims must be a dict"
        for _name, _expected in relied_claims.items():
            if _name not in body:
                return False, \
                    "unsigned-field-ignored: relied claim %r has no " \
                    "signature-covered source; verification refuses to " \
                    "consult unsigned fields" % (_name,)
            _covered = body[_name]
            _value = _covered.get("value") \
                if isinstance(_covered, dict) else _covered
            if _value != _expected:
                return False, \
                    "relied claim %r disagrees with the " \
                    "signature-covered packet value" % (_name,)
    # Wave-228 (decision codes): replay the attached machine claim
    # against the live taxonomy. The claim is signature-covered, so a
    # swapped claim already fails above; this rejects a well-signed
    # packet whose section names an unmapped refusal, carries a
    # mutated claim, or was built under a drifted taxonomy -- the
    # verifier trusts the taxonomy, never the section.
    if packet.get("decision_code") is not None:
        _dc = _decision_codes()
        try:
            _dc.replay(packet["decision_code"]["value"])
        except _dc.DecisionCodeError as e:
            return False, "decision_code replay refused: %s" % (e,)
    # Wave-180 (Decision BOM): the BOM section is signature-covered,
    # so a tampered BOM already fails above; these checks catch a
    # well-signed packet whose BOM disagrees with the packet's own
    # sections (a producer that signed a lie must lie consistently
    # everywhere, and any single disagreement fails closed).
    bom = packet["bill_of_materials"]["value"]
    bom_ok, bom_reason = _bom.check_bom_shape(bom)
    if not bom_ok:
        return False, "bill_of_materials malformed: %s" % bom_reason
    bom_inputs = bom["inputs"]
    bom_policy = bom_inputs["policy"]
    pkt_policy = packet["policy"]["value"]
    if bom_policy["policy_id"] != pkt_policy.get("policy_id"):
        return False, "BOM policy_id disagrees with the packet's policy section"
    if bom_policy["policy_version"] != pkt_policy.get("policy_version"):
        return False, "BOM policy_version disagrees with the packet's " \
            "policy section (tampered version)"
    pkt_bundle_digest = pkt_policy.get("policy_bundle_digest")
    if pkt_bundle_digest is not None and \
            bom_policy["digest"] != pkt_bundle_digest:
        return False, "BOM policy digest disagrees with the packet's " \
            "policy_bundle_digest (swapped or tampered policy bundle)"
    if bom_inputs["evidence"]["head_digest"] != \
            packet["evidence"]["value"].get("head_digest"):
        return False, "BOM head_digest disagrees with the packet's " \
            "evidence section"
    if bom_inputs["approval"]["approval_id"] != \
            packet["approval_id"]["value"]:
        return False, "BOM approval_id disagrees with the packet's approval_id"
    bom_principal = bom_inputs["principal"]
    pkt_identity = packet["identity"]["value"]
    for field in ("agent_id", "role", "principal", "run_id"):
        if bom_principal.get(field) != pkt_identity.get(field):
            return False, "BOM principal.%s disagrees with the packet's " \
                "identity section" % field
    pkt_skill = packet["capability_manifest"]["value"].get("skill_id")
    pkt_skill_digest = packet["capability_manifest"]["value"].get("digest")
    bom_pins = bom_inputs["pins"]
    if pkt_skill is None:
        if bom_pins:
            return False, "BOM names pins but the packet names no skill"
    else:
        if bom_pins.get(pkt_skill) != pkt_skill_digest:
            return False, "BOM pin digest for %r disagrees with the " \
                "packet's capability_manifest" % (pkt_skill,)
    # Wave-191 (identity token): when the BOM records a token_digest
    # AND the packet carries an identity_token section, the two must
    # agree -- a well-signed packet whose token digest disagrees with
    # its BOM fails closed (same pattern as the checks above). Either
    # side absent skips the check (additive: legacy packets predate
    # both, and a token-carrying packet whose BOM predates the binding
    # is not punished for the BOM's age).
    bom_token_digest = bom_inputs["principal"].get("token_digest")
    if bom_token_digest is not None:
        _tok_section = packet.get("identity_token")
        _sec_value = _tok_section.get("value") \
            if isinstance(_tok_section, dict) else None
        _sec_digest = _sec_value.get("token_digest") \
            if isinstance(_sec_value, dict) else None
        if _sec_digest != bom_token_digest:
            return False, "BOM principal.token_digest disagrees with " \
                "the packet's identity_token section (swapped or " \
                "misbound token)"
    # Wave-191: the optional token-consistency check. token_claims=None
    # is the legacy path -- acceptance is byte-identical to the
    # pre-token verifier. A presented claim set must be well-formed,
    # unexpired, and consistent with the signed identity_token section
    # and the packet's identity section, or verification fails closed.
    if token_claims is not None:
        tok_ok, tok_reason = _check_token_presentation(packet,
                                                       token_claims)
        if not tok_ok:
            return False, tok_reason
    head = packet["evidence"]["value"].get("head_digest")
    if not isinstance(head, str) or not head:
        return False, "evidence.head_digest missing"
    digest = packet_digest(packet)
    if entries is None:
        return True, "ok (structure+signature; chain linkage not checked)"
    if not isinstance(entries, (list, tuple)):
        return False, "entries is not a list"
    matches = _find_packet_entries(entries, digest)
    if not matches:
        return False, \
            "digest linkage: no decision_packet entry references this packet"
    for m in matches:
        if m.get("prev_hash") != head:
            return False, \
                "digest linkage: entry prev_hash does not match the " \
                "packet's stated head digest (stale or forked head)"
    hashes = {e.get("hash") for e in entries
              if isinstance(e, dict) and e.get("hash")}
    if head != "GENESIS" and head not in hashes:
        return False, \
            "digest linkage: stated head digest not present in the chain"
    # F196 (MATCH re-binding, close-when #1): re-derive decision_digest
    # from the chained decision entry this packet answers. The decision
    # entry is located by the packet's stated evidence.head_digest (the
    # declared audit parent), never by head position, so the check
    # survives the rebuild-once path.
    if head == "GENESIS":
        # F199: a GENESIS head claims "no audit parent exists". That
        # claim is only honest when the supplied chain carries no
        # decision entries (the first-decision case, e.g. the
        # round-trip pin where the chain holds only the packet's own
        # entry). A key-holding producer can otherwise mint a
        # GENESIS-head packet with an arbitrary decision_digest that
        # dodges re-derivation on a chain that DOES contain the real
        # decision entry (probe D5), so the GENESIS-head case fails
        # closed whenever decision entries are present.
        for e in entries:
            if isinstance(e, dict) and e.get("event") == "decision":
                return False, \
                    "F199: GENESIS-head packet presented on a chain " \
                    "that carries decision entries; decision_digest " \
                    "cannot be re-derived (opaque pointer)"
    else:
        decision_entry = None
        for e in entries:
            if isinstance(e, dict) and e.get("hash") == head:
                decision_entry = e
                break
        if decision_entry is None:
            return False, \
                "F196: no chained entry for evidence.head_digest; " \
                "cannot re-derive decision_digest"
        policy_decision = decision_entry.get("policy_decision")
        if not isinstance(policy_decision, dict):
            return False, \
                "F196: chained decision entry carries no policy_decision; " \
                "cannot re-derive decision_digest"
        rebound = hashlib.sha256(
            _canonical(policy_decision)).hexdigest()
        claimed = packet["policy"]["value"].get("decision_digest")
        if rebound != claimed:
            return False, \
                "F196: decision_digest does not re-derive from the " \
                "chained decision entry (opaque pointer)"
    # F196 (packet<->receipt pairing, close-when #2): an
    # invocation_receipt entry answering this packet must carry the same
    # approval_id/decision_seq, and the countersigned receipt inside must
    # attribute the execution to the same approval_id. Absence of an
    # answering receipt is legitimate (deny path, non-invoked allows)
    # and skips the check; only a present-but-mismatched receipt fails
    # closed.
    packet_aid = packet["approval_id"]["value"]
    packet_seq = packet["decision_seq"]["value"]
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "invocation_receipt":
            continue
        if e.get("approval_id") != packet_aid:
            continue
        if e.get("decision_seq") != packet_seq:
            continue
        receipt = e.get("receipt")
        if not isinstance(receipt, dict):
            return False, \
                "F196: answering invocation_receipt entry carries no receipt"
        rpolicy = receipt.get("policy")
        inner_aid = rpolicy.get("approval_id") \
            if isinstance(rpolicy, dict) else None
        if inner_aid != packet_aid:
            return False, \
                "F196: receipt attributes execution to approval %r, " \
                "packet answers %r (misattribution)" % (inner_aid,
                                                        packet_aid)
    return True, "ok"


def evidence_head_digest(log_path):
    """The current evidence-chain head digest for a JSONL audit log.

    Returns the ``hash`` of the last well-formed entry (mirroring
    ActionLog.refresh's F52 rule: unparseable tail lines are skipped,
    never trusted), or "GENESIS" for a missing/empty log with no
    well-formed entries.
    """
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            window = min(size, 1 << 16)
            f.seek(size - window)
            tail = f.read()
    except FileNotFoundError:
        return "GENESIS"
    except OSError as e:
        raise PacketError("cannot read log %s: %s" % (log_path, e))
    lines = [ln for ln in tail.splitlines() if ln.strip()]
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if (isinstance(entry, dict)
                and isinstance(entry.get("seq"), int)
                and isinstance(entry.get("hash"), str)
                and entry["hash"]):
            return entry["hash"]
    if size > 1 << 16:
        # The tail window held no well-formed entry; fall back to a
        # full scan rather than misreporting the head.
        head = None
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if (isinstance(entry, dict)
                            and isinstance(entry.get("seq"), int)
                            and isinstance(entry.get("hash"), str)
                            and entry["hash"]):
                        head = entry["hash"]
        except OSError as e:
            raise PacketError("cannot read log %s: %s" % (log_path, e))
        return head or "GENESIS"
    return "GENESIS"
