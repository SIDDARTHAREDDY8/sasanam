"""Evidence bundle v2 + Rekor-shaped transparency contract.

Three-artifact split for offline evidence, joined ONLY by
``cert_digest`` (the join key from ``gov.evidence_certs``):

  (a) evidence artifact      -- canonical JSON body + artifact_digest
  (b) signature attestation  -- ``make_signature_attestation``: artifact
      digest, cert digest, signature. Carries NO issuance metadata.
  (c) issuance attestation   -- the ``evidence-cert-issued`` audit-log
      entry minted by ``EvidenceCA.issue``. Carries NO signature
      material. Lives in the hash-chained audit log.

The bundle never mutates the v1 evidence bundle or the corroboration
receipts: composition is by digest, never by mutation.

TransparencyLog provider interface
----------------------------------
``submit(digest) -> {log_id, integrated_time, inclusion_proof}`` plus
``verify_inclusion`` / ``verify_checkpoint`` / ``verify_consistency``.
The default provider, ``InProcessTransparencyLog``, is an in-memory
append-only RFC 6962 Merkle tree (reusing ``gov.rekor_anchor``'s
verified helpers). It has honest, documented limits: no durability
across restarts, no network, no witnesses, no real Rekor.

The key<->producer binding Rekor omits
---------------------------------------
Rekor's honest claim is "this digest exists, signed by K, received at
T" -- it never checks that K was AUTHORIZED to produce the digest.
``submit`` therefore requires a ``producer_auth`` record and the v2
seam verifies it through the evidence-cert ceremony
(chain-then-binding) BEFORE the log accepts the digest: a bare digest,
a forged artifact signature, or an approval mismatch is refused with
``evcert-*``/``evbundle-unauthorized-producer``. The orchestration
(``submit_evidence``) verifies the producer authorization itself, so
even a permissive provider cannot launder an unauthorized producer
through this seam.

Honest claims
-------------
Every verified record carries ``honest_claims``: existence + producer
authorization + receipt time. Never "authorized to act". The in-process
log additionally disclaims durability and witness cosigning.
"""

import base64
import hashlib
import hmac
import json
import re
import time

from .evidence_certs import (
    EvidenceCertError,
    cert_digest,
    make_signature_attestation,
    verify_evidence_signature,
)
from . import log as _audit_log
from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify
from .rekor_anchor import (
    _r6962_inclusion_proof,
    _r6962_leaf,
    _r6962_root,
    _r6962_verify_proof,
)

BUNDLE_FORMAT = "evidence-bundle.v2"
SUBMISSION_FORMAT = "evidence-submission.v2"

_HONEST_CLAIMS = (
    "This record proves: (1) the evidence artifact existed with this "
    "digest; (2) it was signed by a producer whose evidence certificate "
    "chained to a trusted CA and whose approval/intent binding verified; "
    "(3) the digest was received by the transparency log at "
    "integrated_time. It does NOT prove the producer was authorized to "
    "act, the evidence is true, or the log is durable or witnessed."
)
_STUB_HONEST_CLAIMS = _HONEST_CLAIMS + (
    " In-process log: entries live in memory only; restart loses the "
    "log; no witness cosignatures; no network Rekor involved."
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceBundleV2Error(Exception):
    """Coded, fail-closed v2 bundle error. ``code`` is a machine code in
    the ``evbundle`` or ``prodauth`` decision-code domain; ``detail``
    is human text."""

    def __init__(self, code, detail):
        super(EvidenceBundleV2Error, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _hex64(value, where):
    if not isinstance(value, str) or not _HEX64.match(value):
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "%s must be 64 lowercase hex chars" % where)
    return value


# ---------------------------------------------------------------------------
# Three-artifact split
# ---------------------------------------------------------------------------

def build_artifact(body):
    """Build the evidence artifact. Returns (artifact, artifact_digest).

    The artifact is ``{"format", "body", "artifact_digest"}`` where the
    digest is sha256 over the canonical JSON of ``body``. ``body`` must
    be a JSON-serializable dict.
    """
    if not isinstance(body, dict):
        raise EvidenceBundleV2Error(
            "evbundle-malformed", "artifact body must be a dict")
    try:
        raw = _canonical(body)
    except (TypeError, ValueError) as e:
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "artifact body is not JSON-serializable: %s" % (e,))
    digest = hashlib.sha256(raw).hexdigest()
    artifact = {"format": "evidence-artifact.v2",
                "body": body,
                "artifact_digest": digest}
    return artifact, digest


def seal_evidence(*, artifact_body, cert, artifact_signature, approval_id,
                  intent_digest, ca_public_key, verify_time):
    """Seal an evidence artifact: chain-then-bind the producer's
    signature, then build the signature attestation.

    ``artifact_signature`` is the 64-byte Ed25519 signature over the
    canonical artifact-body bytes, made by the certificate's subject
    key. Certificate failures raise the ``evcert-*`` codes from
    ``gov.evidence_certs`` (honest layering: the failure belongs to the
    ceremony, not the bundle). Returns the sealed record: the artifact,
    the signature attestation, the public evidence certificate (needed
    to re-verify the ceremony at verification time), and the
    ``cert_digest`` join key. The issuance attestation itself stays in
    the audit log (see ``find_issuance_attestation``).
    """
    if not isinstance(artifact_signature, (bytes, bytearray)) \
            or len(artifact_signature) != 64:
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "artifact_signature must be 64 bytes")
    artifact, digest = build_artifact(artifact_body)
    # Chain first, then binding -- raises evcert-* on any failure.
    verify_evidence_signature(cert=cert,
                              artifact_bytes=_canonical(artifact_body),
                              artifact_signature=bytes(artifact_signature),
                              approval_id=approval_id,
                              intent_digest=intent_digest,
                              ca_public_key=ca_public_key,
                              verify_time=verify_time)
    attestation = make_signature_attestation(
        cert, digest, base64.b64encode(bytes(artifact_signature))
        .decode("ascii"))
    return {"kind": BUNDLE_FORMAT,
            "artifact": artifact,
            "signature_attestation": attestation,
            "cert": cert,
            "cert_digest": cert_digest(cert)}


def find_issuance_attestation(*, audit_log_path, cert_digest):
    """Locate the issuance attestation in the hash-chained audit log.

    The log chain is verified first: a broken chain is
    ``evbundle-issuance-unverifiable`` (an evidence bundle on top of an
    unauthenticated log is worse than no bundle). Absence of a matching
    ``evidence-cert-issued`` entry is the same refusal: issuance is
    never detached from the log.
    """
    _hex64(cert_digest, "cert_digest")
    try:
        ok, broken_seq, _count = _audit_log.verify_chain(audit_log_path)
    except Exception as e:  # noqa: BLE001 -- fail closed, loudly
        raise EvidenceBundleV2Error(
            "evbundle-issuance-unverifiable",
            "audit-log chain could not be verified: %r" % (e,))
    if not ok:
        raise EvidenceBundleV2Error(
            "evbundle-issuance-unverifiable",
            "audit-log chain does not verify (broken at seq %s)"
            % (broken_seq,))
    try:
        entries = _audit_log.read_entries(audit_log_path)
    except Exception as e:  # noqa: BLE001
        raise EvidenceBundleV2Error(
            "evbundle-issuance-unverifiable",
            "audit log unreadable: %r" % (e,))
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("kind") != "evidence-cert-issued":
            continue
        if entry.get("cert_digest") == cert_digest:
            return entry
    raise EvidenceBundleV2Error(
        "evbundle-issuance-unverifiable",
        "no evidence-cert-issued attestation for cert_digest %s"
        % cert_digest[:16])


def verify_sealed_bundle(*, sealed, audit_log_path, ca_public_key,
                         verify_time, require_producer_claim=False,
                         claim_public_key=None):
    """Verify the three-artifact split. Order: shape, artifact
    self-consistency, attestation joins, cert join + full ceremony
    re-verification (``evcert-*`` failures propagate -- the signature
    is NEVER taken on trust), issuance join against the audit log.

    Any cross-artifact digest disagreement is
    ``evbundle-join-mismatch``; certificate failures surface as
    ``evcert-*``; a missing/broken issuance attestation is
    ``evbundle-issuance-unverifiable``.

    With ``require_producer_claim=True``, the issuance attestation
    must carry a producer-authorization claim (``prodauth-claim-*``
    failures propagate): the claim signature, expiry, and the
    (approval_id, subject_key_id) join are re-verified against the
    attestation. The legacy path (``False``) never requires the
    claim, so existing bundles keep verifying byte-identically.
    """
    if not isinstance(sealed, dict) or sealed.get("kind") != BUNDLE_FORMAT:
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "sealed bundle must be a %s record" % BUNDLE_FORMAT)
    artifact = sealed.get("artifact")
    attestation = sealed.get("signature_attestation")
    cert = sealed.get("cert")
    if not isinstance(artifact, dict) or not isinstance(attestation, dict) \
            or not isinstance(cert, dict):
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "sealed bundle must carry artifact, signature_attestation, "
            "and cert")
    _hex64(sealed.get("cert_digest"), "sealed cert_digest")
    _hex64(attestation.get("cert_digest"), "attestation cert_digest")
    _hex64(attestation.get("artifact_digest"), "attestation artifact_digest")
    recomputed = hashlib.sha256(
        _canonical(artifact.get("body"))).hexdigest()
    if not hmac.compare_digest(recomputed, artifact.get("artifact_digest", "")):
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "artifact body does not hash to its claimed digest")
    if not hmac.compare_digest(artifact["artifact_digest"],
                               attestation["artifact_digest"]):
        raise EvidenceBundleV2Error(
            "evbundle-join-mismatch",
            "artifact digest disagrees with the signature attestation")
    if not hmac.compare_digest(sealed["cert_digest"],
                               attestation["cert_digest"]):
        raise EvidenceBundleV2Error(
            "evbundle-join-mismatch",
            "sealed cert_digest disagrees with the signature attestation")
    if not hmac.compare_digest(cert_digest(cert), sealed["cert_digest"]):
        raise EvidenceBundleV2Error(
            "evbundle-join-mismatch",
            "sealed cert does not hash to the claimed cert_digest")
    # Re-verify the full ceremony from the sealed cert -- evcert-*
    # failures propagate (honest layering).
    try:
        sig_bytes = base64.b64decode(attestation.get("signature", ""),
                                     validate=True)
    except ValueError:
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "signature attestation has undecodable signature")
    extensions = cert.get("extensions") or {}
    verify_evidence_signature(cert=cert,
                              artifact_bytes=_canonical(artifact["body"]),
                              artifact_signature=sig_bytes,
                              approval_id=extensions.get("approval_id"),
                              intent_digest=extensions.get("intent_digest"),
                              ca_public_key=ca_public_key,
                              verify_time=verify_time)
    issuance = find_issuance_attestation(audit_log_path=audit_log_path,
                                         cert_digest=sealed["cert_digest"])
    if not hmac.compare_digest(issuance.get("cert_digest", ""),
                               sealed["cert_digest"]):
        raise EvidenceBundleV2Error(
            "evbundle-join-mismatch",
            "issuance attestation cert_digest disagrees with the seal")
    result = {"verified": True,
              "cert_digest": sealed["cert_digest"],
              "artifact_digest": artifact["artifact_digest"],
              "issuance_seq": issuance.get("seq"),
              "honest_claims": _HONEST_CLAIMS}
    if require_producer_claim:
        result["producer_authz"] = _verify_issuance_claim(
            issuance, claim_public_key=claim_public_key,
            verify_time=verify_time)
    return result


def _verify_issuance_claim(issuance, *, claim_public_key, verify_time):
    """Require and verify the producer-authorization claim embedded
    in an issuance attestation. Missing claim ->
    ``prodauth-claim-invalid`` (the bundle claims the producer path
    but the attestation carries no claim); signature/expiry/join
    failures propagate from ``verify_producer_claim``."""
    claim = issuance.get("producer_authz_claim")
    if claim is None:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "producer-authorization claim required but the issuance "
            "attestation carries none")
    return verify_producer_claim(
        claim, claim_public_key=claim_public_key,
        approval_id=issuance.get("approval_id"),
        subject_key_id=issuance.get("subject_key_id"),
        verify_time=verify_time)


# ---------------------------------------------------------------------------
# Producer authorization: the binding Rekor omits
# ---------------------------------------------------------------------------

def default_producer_auth_verifier(auth, digest):
    """Verify that a producer is authorized to submit ``digest``.

    ``auth`` must be an ``evidence-cert`` record: the certificate, the
    artifact bytes, the artifact signature, and the approval/intent
    binding, verified chain-then-binding against the CA public key.
    Returns the verified producer record. Any failure -- missing auth,
    wrong shape, digest mismatch, ceremony refusal -- is
    ``evbundle-unauthorized-producer``: the digest is NOT authorized.
    """
    if not isinstance(auth, dict) or auth.get("kind") != "evidence-cert":
        raise EvidenceBundleV2Error(
            "evbundle-unauthorized-producer",
            "producer authorization must be an evidence-cert record")
    required = ("cert", "artifact_bytes", "artifact_signature",
                "approval_id", "intent_digest", "ca_public_key",
                "verify_time")
    missing = [k for k in required if k not in auth]
    if missing:
        raise EvidenceBundleV2Error(
            "evbundle-unauthorized-producer",
            "producer authorization missing fields: %s"
            % ",".join(missing))
    if not isinstance(auth["artifact_bytes"], (bytes, bytearray)):
        raise EvidenceBundleV2Error(
            "evbundle-unauthorized-producer",
            "artifact_bytes must be bytes")
    actual = hashlib.sha256(bytes(auth["artifact_bytes"])).hexdigest()
    if not hmac.compare_digest(actual, digest):
        raise EvidenceBundleV2Error(
            "evbundle-unauthorized-producer",
            "producer authorization does not cover this digest")
    try:
        verified = verify_evidence_signature(
            cert=auth["cert"],
            artifact_bytes=bytes(auth["artifact_bytes"]),
            artifact_signature=bytes(auth["artifact_signature"]),
            approval_id=auth["approval_id"],
            intent_digest=auth["intent_digest"],
            ca_public_key=auth["ca_public_key"],
            verify_time=auth["verify_time"])
    except EvidenceCertError as e:
        raise EvidenceBundleV2Error(
            "evbundle-unauthorized-producer",
            "producer certificate rejected (%s): %s" % (e.code, e.detail))
    return {"producer": "evidence-cert",
            "subject_key_id": verified["subject_key_id"],
            "principal": verified["principal"],
            "approval_id": verified["approval_id"]}


# ---------------------------------------------------------------------------
# Producer-authorization claim (SLSA-shaped)
#
# SLSA's provenance and Fulcio's identity machinery both answer "which
# key signed this digest" but omit the application-level question: was
# the producer AUTHORIZED to speak for the claimed application
# identity? This seam closes that negative space: on the claim path
# (``submit_evidence_with_producer_claim``), the evidence-cert
# ceremony MUST establish that the requesting producer is authorized
# for the claimed application scope BEFORE the transparency log sees
# the digest. Pattern-only steal (clean-room; no Fulcio/SLSA code):
# Fulcio's "issue on presentation of a valid identity token" ceremony,
# SLSA's {"_type", "subject", "predicate"} statement shape.
#
# The claim binds (producer identity, authorized scope) to one
# certificate issuance via the (approval_id, subject_key_id) pair --
# both are fixed before the certificate is minted, so the claim can
# be minted before issuance and embedded by the CA into the
# ``evidence-cert-issued`` attestation (see
# ``EvidenceCA.issue(producer_authz_claim=...)``). Verify-time
# re-checks: claim signature (exact ``is True``, wave-243 lesson),
# expiry, and the approval/subject-key join against the attestation.
#
# Honest limit: this proves "the producer was authorized to produce
# for scope S at claim time" -- never "the producer was authorized to
# act", and never the truth of the evidence.
# ---------------------------------------------------------------------------

PRODAUTH_TOKEN_FORMAT = "prodauth-identity-token.v1"
PRODAUTH_TOKEN_AUDIENCE = "sasanam-evcert-ca"
PRODAUTH_CLAIM_FORMAT = "prodauth-claim.v1"
PRODAUTH_STATEMENT_TYPE = \
    "https://sasanam.dev/producer-authorization/v1"
PRODAUTH_PREDICATE_TYPE = \
    "https://sasanam.dev/producer-authorization/predicate/v1"
PRODAUTH_REGISTRY_STATEMENT_FORMAT = "prodauth-registry-statement.v1"

# Identity tokens are single-use-ish and short-lived; the default is
# deliberately small so a captured token is a poor replay asset.
PRODAUTH_DEFAULT_TOKEN_TTL_S = 300
PRODAUTH_DEFAULT_CLAIM_TTL_S = 300
PRODAUTH_MAX_TTL_S = 3600

_HEX16 = re.compile(r"^[0-9a-f]{16}$")

def _now_int(now):
    """Accept ``now`` as None, an int epoch, or a zero-arg callable."""
    if now is None:
        return int(time.time())
    if callable(now):
        return int(now())
    return int(now)


_HEX32 = re.compile(r"^[0-9a-f]{32}$")


class ProducerRegistry(object):
    """producer identity -> authorized scopes, fail-closed on unknowns.

    ``entries`` maps a producer identity (non-empty string, e.g. the
    identity-token ``sub``) to an iterable of authorized scope strings.
    ``admin_public_key`` is the Ed25519 key that signs registration
    statements; ``register()`` verifies the statement signature (exact
    ``is True``), shape, and expiry before mutating the mapping, so a
    registry with an admin key cannot be silently rewritten.
    Scope matching is EXACT (no wildcards, deny-by-default): a producer
    not in the mapping, or a scope not in the producer's set, is
    refused -- never defaulted. Unknown producers fail closed with
    ``prodauth-producer-unknown``; this is the load-bearing check the
    SLSA/Fulcio negative space motivates.
    """

    def __init__(self, *, entries=None, admin_public_key=None, now=None):
        if admin_public_key is not None and (
                not isinstance(admin_public_key, (bytes, bytearray))
                or len(admin_public_key) != 32):
            raise TypeError(
                "admin_public_key must be 32 bytes or None")
        self._admin = None if admin_public_key is None \
            else bytes(admin_public_key)
        if now is None:
            self._now = time.time
        elif callable(now):
            self._now = now
        else:
            # An int epoch: freeze into a thunk so register()'s
            # self._now() call keeps working (convention: None/int/
            # callable all accepted).
            self._now = lambda n=int(now): n
        self._entries = {}
        for producer, scopes in (entries or {}).items():
            self._entries[self._check_producer(producer)] = \
                frozenset(self._check_scopes(scopes))

    @staticmethod
    def _check_producer(producer):
        if not isinstance(producer, str) or not producer:
            raise EvidenceBundleV2Error(
                "prodauth-producer-unknown",
                "producer identity must be a non-empty string")
        return producer

    @staticmethod
    def _check_scopes(scopes):
        if not isinstance(scopes, (list, tuple, set, frozenset)) \
                or not scopes:
            raise EvidenceBundleV2Error(
                "prodauth-scope-not-authorized",
                "scopes must be a non-empty list of scope strings")
        out = []
        for s in scopes:
            if not isinstance(s, str) or not s:
                raise EvidenceBundleV2Error(
                    "prodauth-scope-not-authorized",
                    "each scope must be a non-empty string")
            out.append(s)
        return out

    def register(self, *, statement, now=None):
        """Register (or replace) a producer's scopes on a signed admin
        statement. ``statement`` is
        ``{"statement": body, "signature": b64}`` with
        ``body = {"format": "prodauth-registry-statement.v1",
        "producer": ..., "scopes": [...], "exp": int}``.
        Refusals are ``prodauth-registry-unauthorized`` (no admin key
        configured, malformed statement, expired, or bad signature --
        a forged registration is dishonored, never honored). Returns
        the registered producer identity.
        """
        now = _now_int(now if now is not None else self._now())
        if self._admin is None:
            raise EvidenceBundleV2Error(
                "prodauth-registry-unauthorized",
                "registry has no admin key; refusing registration")
        if not isinstance(statement, dict) \
                or not isinstance(statement.get("statement"), dict) \
                or not isinstance(statement.get("signature"), str):
            raise EvidenceBundleV2Error(
                "prodauth-registry-unauthorized",
                "registration statement must be "
                "{statement: dict, signature: str}")
        body = statement["statement"]
        if body.get("format") != PRODAUTH_REGISTRY_STATEMENT_FORMAT:
            raise EvidenceBundleV2Error(
                "prodauth-registry-unauthorized",
                "unknown registration statement format %r"
                % (body.get("format"),))
        producer = body.get("producer")
        scopes = body.get("scopes")
        exp = body.get("exp")
        if not isinstance(producer, str) or not producer \
                or not isinstance(scopes, list) or not scopes \
                or not all(isinstance(s, str) and s for s in scopes) \
                or not isinstance(exp, int):
            raise EvidenceBundleV2Error(
                "prodauth-registry-unauthorized",
                "registration statement has bad shape")
        if exp <= now:
            raise EvidenceBundleV2Error(
                "prodauth-registry-unauthorized",
                "registration statement expired")
        try:
            sig = base64.b64decode(statement["signature"], validate=True)
        except ValueError:
            raise EvidenceBundleV2Error(
                "prodauth-registry-unauthorized",
                "registration statement signature is not valid base64")
        if _ed_verify(self._admin, _canonical(body), sig) is not True:
            raise EvidenceBundleV2Error(
                "prodauth-registry-unauthorized",
                "registration statement signature does not verify "
                "against the registry admin key")
        self._entries[producer] = frozenset(scopes)
        return producer

    def check(self, producer, scope):
        """Fail-closed authorization check. Returns True; raises
        ``prodauth-producer-unknown`` (producer not registered) or
        ``prodauth-scope-not-authorized`` (scope not in the producer's
        set). Exact scope match only."""
        if not isinstance(producer, str) or not producer:
            raise EvidenceBundleV2Error(
                "prodauth-producer-unknown",
                "producer identity must be a non-empty string")
        if not isinstance(scope, str) or not scope:
            raise EvidenceBundleV2Error(
                "prodauth-scope-not-authorized",
                "scope must be a non-empty string")
        scopes = self._entries.get(producer)
        if scopes is None:
            raise EvidenceBundleV2Error(
                "prodauth-producer-unknown",
                "producer %r is not registered; refusing rather than "
                "defaulting" % (producer,))
        if scope not in scopes:
            raise EvidenceBundleV2Error(
                "prodauth-scope-not-authorized",
                "producer %r is not authorized for scope %r"
                % (producer, scope))
        return True


def mint_identity_token(*, issuer_signing_key, sub, ttl_s=None,
                        now=None, iss="sasanam-identity-issuer"):
    """Mint a Fulcio-shaped identity token: the certificate is issued
    on presentation of a valid token (clean-room pattern, no Fulcio
    code). ``sub`` is the producer identity. The audience is pinned
    to the evidence CA so a token cannot be replayed into another
    system. Returns ``{"token": body, "token_signature": b64}``."""
    now = _now_int(now)
    ttl_s = PRODAUTH_DEFAULT_TOKEN_TTL_S if ttl_s is None else ttl_s
    if not isinstance(issuer_signing_key, (bytes, bytearray)) \
            or len(issuer_signing_key) != 32:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "issuer_signing_key must be 32 bytes")
    if not isinstance(sub, str) or not sub:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "sub must be a non-empty producer identity string")
    if not isinstance(ttl_s, int) or not 1 <= ttl_s <= PRODAUTH_MAX_TTL_S:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "ttl_s must be in [1, %d]" % PRODAUTH_MAX_TTL_S)
    body = {"format": PRODAUTH_TOKEN_FORMAT,
            "iss": iss,
            "sub": sub,
            "aud": PRODAUTH_TOKEN_AUDIENCE,
            "iat": now,
            "exp": now + ttl_s}
    sig = _ed_sign(bytes(issuer_signing_key), _canonical(body))
    return {"token": body,
            "token_signature": base64.b64encode(sig).decode("ascii")}


def verify_identity_token(token, *, issuer_public_key, now=None):
    """Verify a presented identity token: shape, pinned audience,
    expiry, then the issuer signature (exact ``is True``). Refusals:
    ``prodauth-token-invalid`` (shape, audience, or signature) and
    ``prodauth-token-expired``. Returns
    ``{"producer": sub, "iss": iss}``."""
    now = _now_int(now)
    if not isinstance(issuer_public_key, (bytes, bytearray)) \
            or len(issuer_public_key) != 32:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "issuer_public_key must be 32 bytes")
    if not isinstance(token, dict) \
            or not isinstance(token.get("token"), dict) \
            or not isinstance(token.get("token_signature"), str):
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "identity token must be {token: dict, token_signature: str}")
    body = token["token"]
    if body.get("format") != PRODAUTH_TOKEN_FORMAT:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "unknown identity token format %r" % (body.get("format"),))
    if body.get("aud") != PRODAUTH_TOKEN_AUDIENCE:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "token audience %r is not the evidence CA (replay into "
            "another system refused)" % (body.get("aud"),))
    sub = body.get("sub")
    if not isinstance(sub, str) or not sub:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "token sub must be a non-empty producer identity string")
    exp = body.get("exp")
    if not isinstance(exp, int) or exp <= now:
        raise EvidenceBundleV2Error(
            "prodauth-token-expired",
            "identity token expired (exp %r <= now %d)"
            % (exp, now))
    try:
        sig = base64.b64decode(token["token_signature"], validate=True)
    except ValueError:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "token signature is not valid base64")
    if _ed_verify(bytes(issuer_public_key), _canonical(body), sig) \
            is not True:
        raise EvidenceBundleV2Error(
            "prodauth-token-invalid",
            "identity token signature does not verify against the "
            "identity issuer key")
    return {"producer": sub, "iss": body.get("iss")}


def issue_producer_claim(*, registry, identity_token,
                         identity_issuer_public_key, requested_scope,
                         subject_key_id, approval_id, claim_signing_key,
                         ttl_s=None, now=None):
    """Mint the SLSA-shaped producer-authorization claim: verify the
    identity token (Fulcio-shaped ceremony), then the
    producer->scope authorization (fail-closed on unknown producers).
    The claim binds (producer, scope) to the (approval_id,
    subject_key_id) pair of the issuance it was minted for, so the
    claim can be minted before the certificate exists. Signed by the
    claim authority key (deployment-owned). Returns
    ``{"format": "prodauth-claim.v1", "statement": {...},
    "signature": b64}``."""
    now = _now_int(now)
    ttl_s = PRODAUTH_DEFAULT_CLAIM_TTL_S if ttl_s is None else ttl_s
    if not isinstance(registry, ProducerRegistry):
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "registry must be a ProducerRegistry")
    if not isinstance(claim_signing_key, (bytes, bytearray)) \
            or len(claim_signing_key) != 32:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim_signing_key must be 32 bytes")
    if not isinstance(ttl_s, int) or not 1 <= ttl_s <= PRODAUTH_MAX_TTL_S:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "ttl_s must be in [1, %d]" % PRODAUTH_MAX_TTL_S)
    if not isinstance(subject_key_id, str) \
            or not _HEX16.match(subject_key_id):
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "subject_key_id must be 16 lowercase hex chars")
    if not isinstance(approval_id, str) or not _HEX32.match(approval_id):
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "approval_id must be 32 lowercase hex chars")
    verified = verify_identity_token(
        identity_token, issuer_public_key=identity_issuer_public_key,
        now=now)
    producer = verified["producer"]
    # The load-bearing check: unknown producers fail closed here,
    # before any claim (and any digest) exists.
    registry.check(producer, requested_scope)
    body = {
        "_type": PRODAUTH_STATEMENT_TYPE,
        "subject": [{
            "name": "evidence-cert-subject-key:" + subject_key_id,
            "digest": {"sasanam-key-id-v1": subject_key_id},
        }],
        "predicateType": PRODAUTH_PREDICATE_TYPE,
        "predicate": {
            "producer": {"identity": producer,
                         "identityIssuer": verified["iss"]},
            "authorizedScope": requested_scope,
            "approvalId": approval_id,
            "issuedAt": now,
            "expiresAt": now + ttl_s,
        },
    }
    sig = _ed_sign(bytes(claim_signing_key), _canonical(body))
    return {"format": PRODAUTH_CLAIM_FORMAT,
            "statement": body,
            "signature": base64.b64encode(sig).decode("ascii")}


def verify_producer_claim(claim, *, claim_public_key, approval_id,
                          subject_key_id, verify_time):
    """Verify a producer-authorization claim at the use site: shape,
    claim-authority signature (exact ``is True``), expiry, then the
    (approval_id, subject_key_id) join. Refusals:
    ``prodauth-claim-invalid`` (shape/signature),
    ``prodauth-claim-expired``,
    ``prodauth-claim-mismatch`` (the claim was minted for a different
    issuance). Returns ``{"producer": ..., "scope": ...}``."""
    if not isinstance(claim_public_key, (bytes, bytearray)) \
            or len(claim_public_key) != 32:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim_public_key must be 32 bytes")
    if not isinstance(claim, dict) \
            or claim.get("format") != PRODAUTH_CLAIM_FORMAT \
            or not isinstance(claim.get("statement"), dict) \
            or not isinstance(claim.get("signature"), str):
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim must be {format: %r, statement: dict, "
            "signature: str}" % PRODAUTH_CLAIM_FORMAT)
    stmt = claim["statement"]
    if stmt.get("_type") != PRODAUTH_STATEMENT_TYPE \
            or stmt.get("predicateType") != PRODAUTH_PREDICATE_TYPE:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim statement has wrong _type/predicateType")
    try:
        sig = base64.b64decode(claim["signature"], validate=True)
    except ValueError:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim signature is not valid base64")
    if _ed_verify(bytes(claim_public_key), _canonical(stmt), sig) \
            is not True:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim signature does not verify against the claim "
            "authority key")
    pred = stmt.get("predicate")
    if not isinstance(pred, dict):
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim predicate must be a dict")
    exp = pred.get("expiresAt")
    if not isinstance(exp, int) or exp <= verify_time:
        raise EvidenceBundleV2Error(
            "prodauth-claim-expired",
            "producer-authorization claim expired (expiresAt %r <= "
            "verify_time %d)" % (exp, verify_time))
    subjects = stmt.get("subject")
    bound_key = None
    if isinstance(subjects, list):
        for s in subjects:
            if isinstance(s, dict):
                d = s.get("digest")
                if isinstance(d, dict) and "sasanam-key-id-v1" in d:
                    bound_key = d["sasanam-key-id-v1"]
                    break
    if pred.get("approvalId") != approval_id \
            or bound_key != subject_key_id:
        raise EvidenceBundleV2Error(
            "prodauth-claim-mismatch",
            "claim was minted for a different issuance "
            "(approval/subject-key join failed)")
    producer = (pred.get("producer") or {}).get("identity")
    scope = pred.get("authorizedScope")
    if not isinstance(producer, str) or not producer \
            or not isinstance(scope, str) or not scope:
        raise EvidenceBundleV2Error(
            "prodauth-claim-invalid",
            "claim predicate has bad producer/scope")
    return {"producer": producer, "scope": scope}


# ---------------------------------------------------------------------------
# TransparencyLog provider interface
# ---------------------------------------------------------------------------

class TransparencyLogProvider(object):
    """Rekor-shaped transparency-log contract.

    ``submit(digest, producer_auth=...)`` returns
    ``{"log_id", "integrated_time", "inclusion_proof", "tree_size",
    "root", "digest"}``. ``verify_inclusion``,
    ``verify_checkpoint`` and ``verify_consistency`` raise coded
    ``EvidenceBundleV2Error`` on failure and return True on success.
    The interface promises NOTHING about producer authorization --
    that is the v2 seam's job (see ``default_producer_auth_verifier``).
    """

    provider_name = "abstract"

    def submit(self, digest, *, producer_auth=None):
        raise NotImplementedError

    def verify_inclusion(self, digest, inclusion_proof, checkpoint):
        raise NotImplementedError

    def verify_checkpoint(self, checkpoint):
        raise NotImplementedError

    def verify_consistency(self, old_checkpoint, new_checkpoint):
        raise NotImplementedError


class InProcessTransparencyLog(TransparencyLogProvider):
    """Default provider: in-memory append-only RFC 6962 Merkle tree.

    Honest limits (also in every receipt's ``honest_claims``): entries
    live in memory only -- a restart loses the log; no network, no
    real Rekor, no witness cosignatures. ``verify_consistency`` is
    structural (both checkpoints re-derived from the same in-memory
    history); a remote Rekor adapter would use real RFC 6962
    consistency proofs instead.
    """

    provider_name = "inprocess"

    def __init__(self, *, producer_auth_verifier=None, log_id=None,
                 now=None):
        self._verifier = producer_auth_verifier
        self._log_id = log_id or "inprocess"
        self._now = now or time.time
        self._leaves = []  # 32-byte digests, append-only

    # -- internal ------------------------------------------------------

    def _leaf_hashes(self, n=None):
        leaves = self._leaves if n is None else self._leaves[:n]
        return [_r6962_leaf(l) for l in leaves]

    def _root(self, n=None):
        hashes = self._leaf_hashes(n)
        if not hashes:
            raise EvidenceBundleV2Error(
                "evbundle-checkpoint-invalid",
                "cannot checkpoint an empty log")
        return _r6962_root(hashes).hex()

    def _checkpoint(self, tree_size):
        return {"log_id": self._log_id,
                "tree_size": tree_size,
                "root": self._root(tree_size),
                "integrated_time": int(self._now())}

    def _receipt(self, digest, index):
        hashes = self._leaf_hashes()
        proof_hashes = _r6962_inclusion_proof(hashes, index)
        proof = [h.hex() for h in proof_hashes]
        checkpoint = self._checkpoint(len(hashes))
        return {"log_id": checkpoint["log_id"],
                "integrated_time": checkpoint["integrated_time"],
                "inclusion_proof": {"leaf_index": index, "hashes": proof},
                "tree_size": checkpoint["tree_size"],
                "root": checkpoint["root"],
                "digest": digest,
                "honest_claims": _STUB_HONEST_CLAIMS}

    # -- public --------------------------------------------------------

    def submit(self, digest, *, producer_auth=None):
        _hex64(digest, "digest")
        if producer_auth is None:
            raise EvidenceBundleV2Error(
                "evbundle-unauthorized-producer",
                "no producer authorization: bare digests are not logged "
                "(the binding Rekor omits)")
        if self._verifier is None:
            raise EvidenceBundleV2Error(
                "evbundle-unauthorized-producer",
                "this log has no producer-auth verifier configured; "
                "refusing rather than logging unverified")
        try:
            self._verifier(producer_auth, digest)
        except EvidenceBundleV2Error:
            raise
        except Exception as e:  # noqa: BLE001 -- fail closed
            raise EvidenceBundleV2Error(
                "evbundle-unauthorized-producer",
                "producer-auth verifier failed: %r" % (e,))
        raw = bytes.fromhex(digest)
        if raw in self._leaves:
            # Idempotent: the same digest returns its original receipt.
            return self._receipt(digest, self._leaves.index(raw))
        self._leaves.append(raw)
        return self._receipt(digest, len(self._leaves) - 1)

    def verify_inclusion(self, digest, inclusion_proof, checkpoint):
        _hex64(digest, "digest")
        if not isinstance(inclusion_proof, dict) \
                or not isinstance(checkpoint, dict):
            raise EvidenceBundleV2Error(
                "evbundle-malformed",
                "inclusion_proof and checkpoint must be dicts")
        index = inclusion_proof.get("leaf_index")
        hashes = inclusion_proof.get("hashes")
        tree_size = checkpoint.get("tree_size")
        root = checkpoint.get("root")
        if not isinstance(index, int) or not isinstance(hashes, list) \
                or not isinstance(tree_size, int):
            raise EvidenceBundleV2Error(
                "evbundle-malformed",
                "inclusion_proof/checkpoint have bad shapes")
        _hex64(root, "checkpoint root")
        try:
            recomputed = _r6962_verify_proof(
                bytes.fromhex(digest), index, hashes, tree_size).hex()
        except ValueError as e:
            raise EvidenceBundleV2Error(
                "evbundle-inclusion-unverified",
                "inclusion proof malformed: %s" % (e,))
        if not hmac.compare_digest(recomputed, root):
            raise EvidenceBundleV2Error(
                "evbundle-inclusion-unverified",
                "inclusion proof does not recompute the checkpoint root")
        return True

    def verify_checkpoint(self, checkpoint):
        if not isinstance(checkpoint, dict):
            raise EvidenceBundleV2Error(
                "evbundle-checkpoint-invalid",
                "checkpoint must be a dict")
        if checkpoint.get("log_id") != self._log_id:
            raise EvidenceBundleV2Error(
                "evbundle-checkpoint-invalid",
                "checkpoint is for a different log")
        tree_size = checkpoint.get("tree_size")
        root = checkpoint.get("root")
        if not isinstance(tree_size, int) or tree_size < 1 \
                or tree_size > len(self._leaves):
            raise EvidenceBundleV2Error(
                "evbundle-checkpoint-invalid",
                "tree_size %r is outside this log's history"
                % (tree_size,))
        _hex64(root, "checkpoint root")
        if not hmac.compare_digest(self._root(tree_size), root):
            raise EvidenceBundleV2Error(
                "evbundle-checkpoint-invalid",
                "checkpoint root does not match this log's history")
        return True

    def verify_consistency(self, old_checkpoint, new_checkpoint):
        # Both checkpoints re-derive from the same in-memory history,
        # so consistency is structural: same log, both valid, and the
        # old tree is a prefix of the new one. A remote adapter would
        # verify real RFC 6962 consistency proofs instead.
        for cp in (old_checkpoint, new_checkpoint):
            if not isinstance(cp, dict):
                raise EvidenceBundleV2Error(
                    "evbundle-malformed",
                    "checkpoints must be dicts")
        if old_checkpoint.get("log_id") != new_checkpoint.get("log_id"):
            raise EvidenceBundleV2Error(
                "evbundle-consistency-invalid",
                "checkpoints are for different logs")
        self.verify_checkpoint(old_checkpoint)
        self.verify_checkpoint(new_checkpoint)
        if old_checkpoint["tree_size"] > new_checkpoint["tree_size"]:
            raise EvidenceBundleV2Error(
                "evbundle-consistency-invalid",
                "old tree_size exceeds new tree_size")
        return True


def make_log(*, producer_auth_verifier=None, log_id=None, now=None):
    """Construct the default transparency log."""
    return InProcessTransparencyLog(
        producer_auth_verifier=producer_auth_verifier, log_id=log_id,
        now=now)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def submit_evidence(*, artifact_body, cert, artifact_signature,
                    approval_id, intent_digest, audit_log_path,
                    ca_public_key, verify_time, transparency_log=None,
                    now=None):
    """Seal an evidence artifact and submit it to the transparency log.

    Order: seal (chain-then-binding; ``evcert-*`` failures propagate),
    issuance join against the audit log, producer-authorization
    verification (the key<->producer binding, done HERE so even a
    permissive provider cannot launder an unauthorized producer), then
    log submission. Provider failures fail closed as
    ``evbundle-transparency-unavailable`` -- the log is never silently
    skipped.
    """
    sealed = seal_evidence(artifact_body=artifact_body, cert=cert,
                           artifact_signature=artifact_signature,
                           approval_id=approval_id,
                           intent_digest=intent_digest,
                           ca_public_key=ca_public_key,
                           verify_time=verify_time)
    find_issuance_attestation(audit_log_path=audit_log_path,
                             cert_digest=sealed["cert_digest"])
    digest = sealed["artifact"]["artifact_digest"]
    auth = {"kind": "evidence-cert",
            "cert": cert,
            "artifact_bytes": _canonical(artifact_body),
            "artifact_signature": bytes(artifact_signature),
            "approval_id": approval_id,
            "intent_digest": intent_digest,
            "ca_public_key": ca_public_key,
            "verify_time": verify_time}
    # Authorize the producer at the seam, before the provider sees it.
    default_producer_auth_verifier(auth, digest)
    log = transparency_log if transparency_log is not None else make_log(
        producer_auth_verifier=default_producer_auth_verifier, now=now)
    try:
        receipt = log.submit(digest, producer_auth=auth)
    except EvidenceBundleV2Error:
        raise
    except Exception as e:  # noqa: BLE001 -- never silently skip the log
        raise EvidenceBundleV2Error(
            "evbundle-transparency-unavailable",
            "transparency provider %r failed: %r"
            % (getattr(log, "provider_name", "?"), e))
    return {"kind": SUBMISSION_FORMAT,
            "sealed": sealed,
            "issuance_ref": {"cert_digest": sealed["cert_digest"],
                             "audit_log_path": audit_log_path},
            "transparency_receipt": receipt,
            "honest_claims": _HONEST_CLAIMS}


def verify_submission(*, submission, audit_log_path, ca_public_key,
                      verify_time, transparency_log,
                      require_producer_claim=False, claim_public_key=None):
    """Verify a v2 submission end to end: the three-artifact split,
    then the transparency receipt against the log.

    ``require_producer_claim=True`` additionally requires and
    verifies the producer-authorization claim on the issuance
    attestation (see ``verify_sealed_bundle``)."""
    if not isinstance(submission, dict) \
            or submission.get("kind") != SUBMISSION_FORMAT:
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "submission must be a %s record" % SUBMISSION_FORMAT)
    sealed = submission.get("sealed")
    receipt = submission.get("transparency_receipt")
    if not isinstance(receipt, dict):
        raise EvidenceBundleV2Error(
            "evbundle-malformed",
            "submission must carry a transparency_receipt")
    verified = verify_sealed_bundle(
        sealed=sealed, audit_log_path=audit_log_path,
        ca_public_key=ca_public_key, verify_time=verify_time,
        require_producer_claim=require_producer_claim,
        claim_public_key=claim_public_key)
    checkpoint = {"log_id": receipt.get("log_id"),
                  "tree_size": receipt.get("tree_size"),
                  "root": receipt.get("root"),
                  "integrated_time": receipt.get("integrated_time")}
    try:
        transparency_log.verify_checkpoint(checkpoint)
        transparency_log.verify_inclusion(
            verified["artifact_digest"],
            receipt.get("inclusion_proof"), checkpoint)
    except EvidenceBundleV2Error:
        raise
    except Exception as e:  # noqa: BLE001
        raise EvidenceBundleV2Error(
            "evbundle-transparency-unavailable",
            "transparency verification failed: %r" % (e,))
    result = {"verified": True,
              "cert_digest": verified["cert_digest"],
              "artifact_digest": verified["artifact_digest"],
              "tree_size": checkpoint["tree_size"],
              "honest_claims": _HONEST_CLAIMS}
    if verified.get("producer_authz") is not None:
        # Claim path only: the legacy return dict stays
        # byte-identical to before.
        result["producer_authz"] = verified["producer_authz"]
    return result


def submit_evidence_with_producer_claim(
        *, artifact_body, cert, artifact_signature, approval_id,
        intent_digest, audit_log_path, ca_public_key, verify_time,
        identity_token, identity_issuer_public_key, producer_registry,
        requested_scope, claim_public_key,
        transparency_log=None, now=None):
    """Claim-path submission: the evidence-cert ceremony MUST
    establish producer authorization BEFORE the transparency log sees
    the digest.

    Order: (1) verify the presented identity token and the
    producer->scope authorization -- any ``prodauth-*`` refusal
    happens here and the digest is NEVER submitted; (2) seal
    (chain-then-binding; ``evcert-*`` failures propagate) and join
    the issuance attestation; (3) the attestation MUST carry a
    producer-authorization claim that verifies (signature, expiry,
    issuance join) AND names this producer and scope -- a claim for a
    different issuance, an expired claim, or a claim for a different
    scope is refused with ``prodauth-claim-mismatch``; (4) the
    existing producer-auth seam and transparency submission.

    The claim itself is minted by ``issue_producer_claim`` and
    embedded at issuance time by
    ``EvidenceCA.issue(producer_authz_claim=...)``; this function
    never mints -- it verifies what the attestation carries.
    """
    now_s = _now_int(now)
    # (1) The ceremony: token -> producer, registry -> scope.
    # Fail-closed on unknown producers BEFORE any digest exists.
    token_out = verify_identity_token(
        identity_token, issuer_public_key=identity_issuer_public_key,
        now=now_s)
    producer = token_out["producer"]
    if not isinstance(producer_registry, ProducerRegistry):
        raise EvidenceBundleV2Error(
            "prodauth-producer-unknown",
            "producer_registry must be a ProducerRegistry")
    producer_registry.check(producer, requested_scope)
    # (2) Seal + issuance join (honest layering: evcert-* propagate).
    sealed = seal_evidence(artifact_body=artifact_body, cert=cert,
                           artifact_signature=artifact_signature,
                           approval_id=approval_id,
                           intent_digest=intent_digest,
                           ca_public_key=ca_public_key,
                           verify_time=verify_time)
    issuance = find_issuance_attestation(
        audit_log_path=audit_log_path,
        cert_digest=sealed["cert_digest"])
    # (3) The attestation must carry a verifying claim for THIS
    # producer and scope.
    claim_out = _verify_issuance_claim(
        issuance, claim_public_key=claim_public_key,
        verify_time=verify_time)
    if claim_out["producer"] != producer \
            or claim_out["scope"] != requested_scope:
        raise EvidenceBundleV2Error(
            "prodauth-claim-mismatch",
            "issuance claim authorizes producer %r for scope %r, not "
            "the presenting producer %r / requested scope %r"
            % (claim_out["producer"], claim_out["scope"],
               producer, requested_scope))
    # (4) Existing producer-auth seam + transparency submission.
    digest = sealed["artifact"]["artifact_digest"]
    auth = {"kind": "evidence-cert",
            "cert": cert,
            "artifact_bytes": _canonical(artifact_body),
            "artifact_signature": bytes(artifact_signature),
            "approval_id": approval_id,
            "intent_digest": intent_digest,
            "ca_public_key": ca_public_key,
            "verify_time": verify_time}
    default_producer_auth_verifier(auth, digest)
    log = transparency_log if transparency_log is not None else make_log(
        producer_auth_verifier=default_producer_auth_verifier,
        now=lambda: now_s)
    try:
        receipt = log.submit(digest, producer_auth=auth)
    except EvidenceBundleV2Error:
        raise
    except Exception as e:  # noqa: BLE001 -- never silently skip the log
        raise EvidenceBundleV2Error(
            "evbundle-transparency-unavailable",
            "transparency provider %r failed: %r"
            % (getattr(log, "provider_name", "?"), e))
    return {"kind": SUBMISSION_FORMAT,
            "sealed": sealed,
            "issuance_ref": {"cert_digest": sealed["cert_digest"],
                             "audit_log_path": audit_log_path},
            "transparency_receipt": receipt,
            "producer_authz": {"producer": producer,
                               "scope": requested_scope},
            "honest_claims": _HONEST_CLAIMS}
