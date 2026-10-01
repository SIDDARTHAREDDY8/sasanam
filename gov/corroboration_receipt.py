"""Human-corroboration receipts (wave-267).

SB 947 ("No Robo Bosses Act", signed 2026-09-30, operative
2027-07-01) imposes a duty of independent human corroboration of ADS
output for disciplinary decisions -- but mandates no wire format.
This module is the wire format: when a human signs off in the
approval queue, the sign-off emits a dual receipt per corroborated
decision --

  * an in-toto v1 attestation (new ``human-corroboration`` predicate
    type) inside a DSSE-shaped envelope, digest-bound to the decision
    packet + evidence bundle and anchored in the audit log, and
  * a W3C VC Data Model v2.0 rendering (issuer = reviewer via
    did:key, DataIntegrityProof / eddsa-jcs-2022, credentialStatus)
    for regulator consumption.

Design inputs (patterns only, no source vendored; Apache-2.0/MIT
verified upstream): in-toto attestation v1 ``Statement`` /
``ResourceDescriptor`` models; cosign's split of envelope-signature
verification from subject/claim binding as two independently
auditable steps (here ``verify_envelope`` then
``verify_statement_binding``); W3C VC Data Model v2.0 for the
regulator-facing rendering.

Wiring: :class:`CorroboratingApprovalQueue` subclasses
``gov.approvals.ApprovalQueue`` and emits a receipt after an APPROVED
``decide()`` when (and only when) a :class:`CorroborationConfig` is
supplied. With no config the queue is byte-identical legacy.
Emission is post-decision evidence -- it never vetoes a decision --
but an emission failure is loud: the failure is audit-logged and the
exception re-raised, so a missing receipt can never be silent.
Composes with (never replaces) ``gov.authorization_receipts``: a
corroboration receipt corroborates an autonomous *decision*, while an
authorization receipt authorizes an agent *action*.

HONEST LIMITS (stated in every public claim):
  * A corroboration receipt proves a keyholder signed a scope-bound
    statement at a time -- it does NOT prove independent
    investigation. Anti-rubber-stamp properties (evidence actually
    presented, minimum review dwell, reviewer independence) belong in
    the approval *ceremony*, not the receipt. A receipt with zero
    evidence digests verifies honestly: absence is disclosed, never
    hidden.
  * did:key proves key possession, not Sybil resistance: one operator
    can mint arbitrarily many reviewer keys.
  * credentialStatus points at a deployment-operated status list;
    this module does not run the list. It is required on the issuer
    and queue paths: a status-less VC cannot be minted there (the
    low-level ``build_vc`` primitive leaves it to the caller).

Fail-closed: every refusal raises :class:`CorroborationReceiptError`
with a machine-readable ``code`` from the decision taxonomy
(``corrob-*``).

$0 spend, synthetic/local deterministic only. No network.
"""

import base64
import binascii
import hashlib
import json
import math
import time

from .agent_identity import (
    b58decode,
    b58encode,
    did_key_from_pubkey,
    pubkey_from_did_key,
    DidKeyError,
)
from .approvals import ApprovalQueue
from .signing import Signer, Verifier

__all__ = [
    "CORROBORATION_FORMAT",
    "RECEIPT_SIGN_DOMAIN",
    "HUMAN_CORROBORATION_PREDICATE",
    "DSSE_PAYLOAD_TYPE",
    "VC_CONTEXT_V2",
    "VC_CREDENTIAL_TYPE",
    "VC_PROOF_CRYPTOSUITE",
    "HONEST_LIMITS",
    "VERDICTS",
    "CorroborationReceiptError",
    "build_statement",
    "statement_digest",
    "dsse_envelope",
    "sign_envelope",
    "verify_envelope",
    "verify_statement_binding",
    "verify_dual_receipt",
    "build_vc",
    "sign_vc",
    "verify_vc",
    "CorroborationIssuer",
    "CorroborationConfig",
    "CorroboratingApprovalQueue",
]

CORROBORATION_FORMAT = "sasanam/corroboration-receipt/v1"
HUMAN_CORROBORATION_PREDICATE = (
    "https://sasanam.dev/attestation/human-corroboration/v1")
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VC_CREDENTIAL_TYPE = "HumanCorroborationCredential"
VC_PROOF_CRYPTOSUITE = "eddsa-jcs-2022"

# Carried inside both signed artifacts (predicate + credentialSubject)
# so the regulator-facing surfaces state the limit themselves.
HONEST_LIMITS = (
    "This receipt proves a keyholder signed a scope-bound statement "
    "at a time; it does not prove independent investigation.")

# Envelope signature domain separation (repo convention: domain +
# sha256(canonical(body)); cf. gov/authorization_receipts.py).
RECEIPT_SIGN_DOMAIN = b"sasanam-corroboration-receipt-sign/v1:"

VERDICTS = ("corroborated", "corroborated-with-notes")


class CorroborationReceiptError(Exception):
    """Fail-closed receipt error. ``code`` is the taxonomy refusal code."""

    def __init__(self, code, detail=""):
        super(CorroborationReceiptError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------
# Canonical JSON (statement/DSSE layer) and JCS (VC proof layer).
# ------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _check_sha256_hex(value, where):
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "%s must be 64 lowercase hex chars" % (where,))


def _utf16_units(text):
    """UTF-16 code units for JCS key ordering (RFC 8785 3.2.1)."""
    units = []
    for char in text:
        point = ord(char)
        if 0xD800 <= point <= 0xDFFF:
            raise CorroborationReceiptError(
                "corrob-receipt-malformed",
                "JCS forbids lone surrogates in strings")
        if point < 0x10000:
            units.append(point)
        else:
            point -= 0x10000
            units.append(0xD800 + (point >> 10))
            units.append(0xDC00 + (point & 0x3FF))
    return units


def _es_number(value):
    """ECMAScript Number::toString for a finite float (JCS 3.2.2).

    JCS additionally requires integer-valued numbers to serialize as
    integers, which differs from bare ES toString for e.g. 1e21.
    """
    if isinstance(value, bool):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "bool is not a JCS number")
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, float):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "not a JCS number")
    if math.isnan(value) or math.isinf(value):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "JCS forbids NaN/Infinity")
    if value == 0:
        return "0"  # -0 -> "0" per JCS
    if value == int(value):
        return str(int(value))
    rep = repr(value)
    negative = rep.startswith("-")
    if negative:
        rep = rep[1:]
    if "e" in rep:
        mantissa, exponent = rep.split("e")
        exponent = int(exponent)
    else:
        mantissa, exponent = rep, 0
    int_part, _, frac_part = mantissa.partition(".")
    digits = (int_part + frac_part).lstrip("0") or "0"
    # value = digits_as_int * 10**(exponent - len(frac_part));
    # ES: value = s * 10**(n-k), k = len(s).
    k = len(digits)
    n = exponent - len(frac_part) + k
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        out = digits[0]
        if k > 1:
            out += "." + digits[1:]
        out += "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
    return ("-" if negative else "") + out


def _jcs(obj):
    """JSON Canonicalization Scheme (RFC 8785), stdlib-only."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, (int, float)):
        return _es_number(obj)
    if isinstance(obj, str):
        _utf16_units(obj)  # validates: no lone surrogates
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_jcs(item) for item in obj) + "]"
    if isinstance(obj, dict):
        for key in obj:
            if not isinstance(key, str):
                raise CorroborationReceiptError(
                    "corrob-receipt-malformed",
                    "JCS object keys must be strings")
        parts = []
        for key in sorted(obj.keys(), key=_utf16_units):
            parts.append(_jcs(key) + ":" + _jcs(obj[key]))
        return "{" + ",".join(parts) + "}"
    raise CorroborationReceiptError(
        "corrob-receipt-malformed",
        "JCS cannot serialize %s" % type(obj).__name__)


def _jcs_bytes(obj):
    return _jcs(obj).encode("utf-8")


def _rfc3339(ts=None):
    moment = int(ts) if ts is not None else int(time.time())
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment))


def _require_did_key(value, where):
    if not isinstance(value, str) or not value:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "%s must be a did:key string" % where)
    try:
        pubkey = pubkey_from_did_key(value)
    except DidKeyError as exc:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "%s: %s" % (where, exc.code))
    return pubkey


# ------------------------------------------------------------------
# in-toto v1 statement (human-corroboration predicate).
# ------------------------------------------------------------------

def build_statement(reviewer_did, decision_digest, evidence_digests,
                    scope, verdict, issued_at, approval_channel,
                    statement_entry_digest, decision_reason=None):
    """Build the in-toto v1 Statement for a corroborated decision."""
    reviewer_pub = _require_did_key(reviewer_did, "reviewer")
    _check_sha256_hex(decision_digest, "decision_digest")
    if not isinstance(evidence_digests, (list, tuple)):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "evidence_digests must be a list")
    for digest in evidence_digests:
        _check_sha256_hex(digest, "evidence_digests entry")
    if not isinstance(scope, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "scope must be a dict")
    if not isinstance(scope.get("action"), str) or not scope["action"]:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "scope.action must be a non-empty string")
    resource = scope.get("resource")
    if not isinstance(resource, str) or not resource:
        resource = "unspecified"
    if verdict not in VERDICTS:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "verdict must be one of %s" % (list(VERDICTS),))
    if not isinstance(issued_at, str) or not issued_at:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "issued_at must be an RFC3339 string")
    if not isinstance(approval_channel, str) or not approval_channel:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "approval_channel must be a non-empty string")
    _check_sha256_hex(statement_entry_digest, "statement_entry_digest")
    if decision_reason is not None and not isinstance(decision_reason, str):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "decision_reason must be a string when supplied")
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": "decision",
            "digest": {"sha256": decision_digest},
        }],
        "predicateType": HUMAN_CORROBORATION_PREDICATE,
        "predicate": {
            "format": CORROBORATION_FORMAT,
            "reviewer": reviewer_did,
            "reviewerKeyId": _sha256_hex(reviewer_pub)[:16],
            "verdict": verdict,
            "issuedAt": issued_at,
            "evidenceDigests": list(evidence_digests),
            "scope": {"action": scope["action"],
                      "resource": resource},
            "approvalChannel": approval_channel,
            "statementEntryDigest": statement_entry_digest,
            "decisionReason": decision_reason or "",
            "honestLimits": HONEST_LIMITS,
        },
    }


def statement_digest(statement):
    """Digest identity of a statement (binds the VC to the envelope)."""
    if not isinstance(statement, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement must be a dict")
    return _sha256_hex(_canonical(statement))


# ------------------------------------------------------------------
# DSSE-shaped envelope.
# ------------------------------------------------------------------

def _signing_bytes(statement):
    return RECEIPT_SIGN_DOMAIN + _sha256_hex(
        _canonical(statement)).encode("ascii")


def dsse_envelope(statement):
    """Wrap a statement in a DSSE-shaped envelope (unsigned)."""
    if not isinstance(statement, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement must be a dict")
    raw = _canonical(statement)
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(raw).decode("ascii"),
        "signatures": [],
    }


def sign_envelope(envelope, signer, keyid):
    """Attach an Ed25519 signature to a DSSE-shaped envelope.

    Deliberately lenient about statement shape: a malformed payload
    must still be wrappable so that ``verify_envelope`` -- not the
    signer -- is the single choke point that refuses it.
    """
    if not isinstance(signer, Signer):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "signer must be a gov.signing.Signer")
    if not isinstance(envelope, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "envelope must be a dict")
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "envelope payloadType mismatch")
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, KeyError) as exc:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "envelope payload is not decodable JSON: %s" % (exc,))
    if not isinstance(statement, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement must be a dict")
    if not isinstance(keyid, str) or not keyid:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "keyid must be a non-empty string")
    out = json.loads(json.dumps(envelope))  # deep copy, JSON-safe
    signature = signer.sign(_signing_bytes(statement))
    out["signatures"] = [{
        "keyid": keyid,
        "sig": base64.b64encode(bytes(signature)).decode("ascii"),
    }]
    return out


def _issuer_bound(verifier, reviewer_pub):
    """True iff the pinned verifier IS the statement's reviewer key.

    Prefers the verifier's raw public key when exposed; falls back to
    the ``key_id`` interface (``ed25519_key_id`` == sha256(pub)[:16],
    the same convention as the statement's reviewerKeyId).
    """
    try:
        pub = getattr(verifier, "public_key", None)
        if pub is not None:
            return bytes(pub) == bytes(reviewer_pub)
        return verifier.key_id == _sha256_hex(bytes(reviewer_pub))[:16]
    except Exception:
        return False


def _check_statement_shape(statement):
    if not isinstance(statement, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement must be a dict")
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement _type mismatch")
    if "predicateType" not in statement:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement predicateType missing")
    if statement.get("predicateType") != HUMAN_CORROBORATION_PREDICATE:
        raise CorroborationReceiptError(
            "corrob-receipt-predicate-mismatch",
            "predicateType %r is not the human-corroboration predicate"
            % (statement.get("predicateType"),))
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement predicate must be a dict")
    if predicate.get("format") != CORROBORATION_FORMAT:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "predicate format mismatch")
    _require_did_key(predicate.get("reviewer"), "predicate.reviewer")
    if predicate.get("verdict") not in VERDICTS:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "predicate verdict unknown")
    subjects = statement.get("subject")
    if (not isinstance(subjects, list) or not subjects
            or not isinstance(subjects[0], dict)):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "statement subject malformed")
    _check_sha256_hex(subjects[0].get("digest", {}).get("sha256"),
                      "subject digest")
    return statement


def verify_envelope(envelope, verifier):
    """Step 1 (cosign split): verify the envelope signature.

    Also enforces the issuer binding: the envelope must verify under
    the key the statement's predicate names as reviewer. Returns
    ``(True, statement)``; raises on any failure.
    """
    if not isinstance(verifier, Verifier):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "verifier must be a gov.signing.Verifier")
    if not isinstance(envelope, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-malformed", "envelope must be a dict")
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "envelope payloadType %r != %r"
            % (envelope.get("payloadType"), DSSE_PAYLOAD_TYPE))
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise CorroborationReceiptError(
            "corrob-receipt-signature-invalid", "envelope has no signatures")
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, KeyError) as exc:
        raise CorroborationReceiptError(
            "corrob-receipt-malformed",
            "envelope payload is not decodable JSON: %s" % (exc,))
    _check_statement_shape(statement)
    # Issuer binding (before signature math): the pinned verifier must
    # be the key the statement names as reviewer. A valid signature
    # from any other key is corrob-receipt-unbound-issuer, not a pass.
    reviewer_pub = _require_did_key(
        statement["predicate"]["reviewer"], "predicate.reviewer")
    if not _issuer_bound(verifier, reviewer_pub):
        raise CorroborationReceiptError(
            "corrob-receipt-unbound-issuer",
            "verifier key is not the statement's reviewer key")
    entry = signatures[0]
    if not isinstance(entry, dict):
        raise CorroborationReceiptError(
            "corrob-receipt-signature-invalid", "signature entry malformed")
    try:
        signature = base64.b64decode(entry.get("sig", ""), validate=True)
    except (binascii.Error, TypeError):
        raise CorroborationReceiptError(
            "corrob-receipt-signature-invalid",
            "signature is not valid base64")
    if verifier.verify(_signing_bytes(statement), signature) is not True:
        raise CorroborationReceiptError(
            "corrob-receipt-signature-invalid",
            "envelope signature does not verify")
    return True, statement


def verify_statement_binding(statement, decision_digest):
    """Step 2 (cosign split): the statement subject must bind the
    exact decision digest being corroborated. Signature alone is not
    enough."""
    _check_statement_shape(statement)
    _check_sha256_hex(decision_digest, "decision_digest")
    bound = statement["subject"][0]["digest"]["sha256"]
    if bound != decision_digest:
        raise CorroborationReceiptError(
            "corrob-receipt-subject-mismatch",
            "statement binds %s, corroborating %s"
            % (bound[:16], decision_digest[:16]))
    return True


# ------------------------------------------------------------------

# ------------------------------------------------------------------
# W3C VC Data Model v2.0 rendering (regulator-facing).
# ------------------------------------------------------------------

def _vc_fail(detail):
    return CorroborationReceiptError("corrob-vc-proof-invalid", detail)


def _vc_check_sha256_hex(value, where):
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        raise _vc_fail("%s must be 64 lowercase hex chars" % (where,))


def _vc_require_did_key(value, where):
    if not isinstance(value, str) or not value:
        raise _vc_fail("%s must be a did:key string" % where)
    try:
        pubkey = pubkey_from_did_key(value)
    except DidKeyError as exc:
        raise _vc_fail("%s: %s" % (where, exc.code))
    return pubkey


def _check_credential_status(status):
    if not isinstance(status, dict):
        raise _vc_fail("credentialStatus must be a dict")
    for key in ("id", "type", "statusPurpose",
                "statusListIndex", "statusListCredential"):
        if not isinstance(status.get(key), str) or not status[key]:
            raise _vc_fail(
                "credentialStatus.%s must be a non-empty string" % key)
    return dict(status)


def build_vc(issuer_did, statement_digest_value, scope, verdict,
             valid_from, credential_id, credential_status=None):
    """Build the W3C VC 2.0 rendering of a corroboration receipt.

    ``credential_status`` is attached when supplied; production
    deployments MUST supply it (via ``CorroborationConfig``) so the
    regulator-facing credential always carries a status entry. The
    low-level builder leaves it to the caller.
    """
    _vc_require_did_key(issuer_did, "issuer")
    _vc_check_sha256_hex(statement_digest_value, "statementDigest")
    if not isinstance(scope, dict):
        raise _vc_fail("scope must be a dict")
    if not isinstance(scope.get("action"), str) or not scope["action"]:
        raise _vc_fail("scope.action must be a non-empty string")
    if verdict not in VERDICTS:
        raise _vc_fail("verdict unknown")
    if not isinstance(valid_from, str) or not valid_from:
        raise _vc_fail("valid_from must be an RFC3339 string")
    if not isinstance(credential_id, str) or not credential_id:
        raise _vc_fail("credential_id must be a non-empty string")
    credential = {
        "@context": [VC_CONTEXT_V2],
        "id": credential_id,
        "type": ["VerifiableCredential", VC_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": valid_from,
        "credentialSubject": {
            "id": issuer_did,
            "statementDigest": statement_digest_value,
            "scope": dict(scope),
            "verdict": verdict,
            "honestLimits": HONEST_LIMITS,
        },
    }
    if credential_status is not None:
        credential["credentialStatus"] = _check_credential_status(
            credential_status)
    return credential


def _vc_proof_bytes(proof_options, document):
    return (hashlib.sha256(_jcs_bytes(proof_options)).digest()
            + hashlib.sha256(_jcs_bytes(document)).digest())


def sign_vc(credential, signer, created=None):
    """Attach a DataIntegrityProof (eddsa-jcs-2022) to a credential.

    The verificationMethod is derived from the credential's issuer
    did:key and the signing key's id. Deliberately lenient about
    signer/issuer ownership: a mismatched signer still produces a
    credential, and ``verify_vc`` -- not the signer -- is the single
    choke point that refuses it.
    """
    if not isinstance(signer, Signer):
        raise _vc_fail("signer must be a gov.signing.Signer")
    if not isinstance(credential, dict):
        raise _vc_fail("credential must be a dict")
    if "proof" in credential:
        raise _vc_fail("credential already carries a proof")
    issuer_did = credential.get("issuer")
    _vc_require_did_key(issuer_did, "issuer")
    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": VC_PROOF_CRYPTOSUITE,
        "created": created or _rfc3339(),
        "verificationMethod": (issuer_did + "#"
                               + _sha256_hex(bytes(signer.public_key))[:16]),
        "proofPurpose": "assertionMethod",
    }
    signature = signer.sign(_vc_proof_bytes(proof_options, credential))
    out = json.loads(json.dumps(credential))  # deep copy, JSON-safe
    proof_options["proofValue"] = "z" + b58encode(bytes(signature))
    out["proof"] = proof_options
    return out


def verify_vc(credential, verifier):
    """Verify a credential's DataIntegrityProof.

    Enforces the issuer binding (the proof must verify under the key
    the credential's issuer did:key resolves to) and the presence of
    a well-formed statementDigest. Does NOT re-verify the envelope --
    that is the ``verify_envelope`` step; the relying party must
    additionally compare ``credentialSubject.statementDigest`` against
    ``statement_digest`` of the verified envelope statement.
    """
    if not isinstance(verifier, Verifier):
        raise _vc_fail("verifier must be a gov.signing.Verifier")
    if not isinstance(credential, dict):
        raise _vc_fail("credential must be a dict")
    if VC_CONTEXT_V2 not in credential.get("@context", []):
        raise _vc_fail("@context missing v2 context")
    types = credential.get("type", [])
    if "VerifiableCredential" not in types or VC_CREDENTIAL_TYPE not in types:
        raise _vc_fail("credential type mismatch")
    issuer_pub = _vc_require_did_key(credential.get("issuer"), "issuer")
    if not _issuer_bound(verifier, issuer_pub):
        raise _vc_fail("verifier key is not the credential's issuer key")
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict):
        raise _vc_fail("credentialSubject missing")
    _vc_check_sha256_hex(subject.get("statementDigest"), "statementDigest")
    proof = credential.get("proof")
    if not isinstance(proof, dict):
        raise _vc_fail("proof missing")
    if (proof.get("type") != "DataIntegrityProof"
            or proof.get("cryptosuite") != VC_PROOF_CRYPTOSUITE
            or proof.get("proofPurpose") != "assertionMethod"):
        raise _vc_fail("proof type/cryptosuite mismatch")
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise _vc_fail("proofValue malformed")
    try:
        signature = b58decode(proof_value[1:])
    except DidKeyError:
        raise _vc_fail("proofValue is not valid base58btc")
    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    document = {k: v for k, v in credential.items() if k != "proof"}
    if verifier.verify(_vc_proof_bytes(proof_options, document),
                       signature) is not True:
        raise _vc_fail("VC proof does not verify")
    return True


def verify_dual_receipt(envelope, vc, verifier, decision_digest):
    """Verify the dual receipt as one ceremony.

    Runs the cosign-style split -- envelope signature + issuer
    binding (step 1), then statement<->decision binding (step 2) --
    verifies the VC's DataIntegrityProof (+ issuer binding), and
    cross-checks that the VC's ``credentialSubject.statementDigest``
    equals the digest of the verified envelope statement. A VC
    re-pointed at a different statement is refused here even though
    its proof alone verifies. Returns ``(True, statement)``.
    """
    ok, statement = verify_envelope(envelope, verifier)
    verify_statement_binding(statement, decision_digest)
    verify_vc(vc, verifier)
    bound = statement_digest(statement)
    claimed = vc.get("credentialSubject", {}).get("statementDigest")
    if claimed != bound:
        raise CorroborationReceiptError(
            "corrob-vc-proof-invalid",
            "VC statementDigest does not match the envelope statement")
    return True, statement


# ------------------------------------------------------------------
# Issuer.
# ------------------------------------------------------------------

class CorroborationIssuer:
    """Binds a signing key to a reviewer did:key and mints receipts.

    Construction itself enforces the key<->did binding:
    ``did_key_from_pubkey(signer.public_key)`` must equal
    ``reviewer_did``. A signer that does not own the reviewer DID
    cannot become an issuer for it (corrob-receipt-unbound-issuer).
    """

    def __init__(self, signer, reviewer_did):
        if not isinstance(signer, Signer):
            raise CorroborationReceiptError(
                "corrob-receipt-malformed",
                "signer must be a gov.signing.Signer")
        _require_did_key(reviewer_did, "reviewer_did")
        bound = did_key_from_pubkey(bytes(signer.public_key))
        if bound != reviewer_did:
            raise CorroborationReceiptError(
                "corrob-receipt-unbound-issuer",
                "signer key does not own %s" % (reviewer_did[:24],))
        self.signer = signer
        self.reviewer_did = reviewer_did
        self.keyid = _sha256_hex(bytes(signer.public_key))[:16]

    def issue(self, decision_digest, evidence_digests, scope, verdict,
              approval_channel, statement_entry_digest, approved=True,
              now=None, credential_status=None, credential_id=None,
              decision_reason=None):
        """Mint the dual receipt for an approved decision.

        ``credential_status`` is required: the regulator-facing VC
        always carries a status entry. ``decision_reason`` records the
        reviewer's stated justification inside the signed predicate.
        """
        if approved is not True:
            raise CorroborationReceiptError(
                "corrob-receipt-not-approved",
                "refusing to mint a corroboration receipt for a decision "
                "that was not approved")
        if credential_status is None:
            raise CorroborationReceiptError(
                "corrob-vc-proof-invalid",
                "credential_status is required for the VC rendering")
        statement = build_statement(
            self.reviewer_did, decision_digest, evidence_digests, scope,
            verdict, _rfc3339(now), approval_channel,
            statement_entry_digest, decision_reason=decision_reason)
        envelope = sign_envelope(
            dsse_envelope(statement), self.signer, self.keyid)
        digest = statement_digest(statement)
        credential = sign_vc(
            build_vc(self.reviewer_did, digest, scope, verdict,
                     _rfc3339(now),
                     credential_id or ("urn:corroboration:" + digest[:16]),
                     credential_status),
            self.signer, created=_rfc3339(now))
        return {
            "envelope": envelope,
            "vc": credential,
            "statement": statement,
            "receipt_digest": _sha256_hex(_canonical(envelope)),
            "statement_digest": digest,
        }


# ------------------------------------------------------------------
# Approval-queue wiring.
# ------------------------------------------------------------------

class CorroborationConfig:
    """Reviewer-bound emission policy for the corroborating queue.

    ``issuer`` owns the reviewer key; ``reviewer_did`` names the
    reviewer the receipts are issued as (audit-logged per emission).
    A receipt is emitted only for approved decisions whose requester
    is not the decider. ``credential_status`` is required: the
    regulator-facing VC always carries a status entry, so the queue
    path cannot emit a status-less credential.
    """

    def __init__(self, issuer, reviewer_did, *, credential_status,
                 evidence_digests_for=None, scope_for=None):
        if not isinstance(issuer, CorroborationIssuer):
            raise CorroborationReceiptError(
                "corrob-receipt-malformed",
                "issuer must be a CorroborationIssuer")
        _require_did_key(reviewer_did, "reviewer_did")
        self.issuer = issuer
        self.reviewer_did = reviewer_did
        self.evidence_digests_for = evidence_digests_for
        self.scope_for = scope_for
        self.credential_status = _check_credential_status(credential_status)

    def emit_for_decision(self, target, entry, decided_by, reason,
                          approved=True, now=None):
        """Emit the dual receipt for a decided record (post-decision)."""
        if approved is not True:
            raise CorroborationReceiptError(
                "corrob-receipt-not-approved",
                "refusing receipt for an unapproved decision")
        if not isinstance(target, dict) or not isinstance(entry, dict):
            raise CorroborationReceiptError(
                "corrob-receipt-malformed",
                "target/entry must be record dicts")
        requester = target.get("agent_id")
        if decided_by == requester:
            raise CorroborationReceiptError(
                "corrob-receipt-self-corroboration",
                "reviewer %r cannot corroborate their own request"
                % (decided_by,))
        decision_digest = entry.get("packet_digest")
        if decision_digest is None:
            decision_digest = _sha256_hex(_canonical(target))
        _check_sha256_hex(decision_digest, "decision_digest")
        evidence = self.evidence_digests_for
        evidence_digests = list(evidence(target)) if evidence else []
        scope_fn = self.scope_for
        scope = dict(scope_fn(target)) if scope_fn else {
            "action": str(target.get("action", "unknown")),
            "resource": str(target.get("resource", "unknown")),
        }
        return self.issuer.issue(
            decision_digest, evidence_digests, scope, "corroborated",
            "approval-queue", _sha256_hex(_canonical(entry)),
            approved=True, now=now,
            credential_status=self.credential_status,
            decision_reason=reason)


class CorroboratingApprovalQueue(ApprovalQueue):
    """ApprovalQueue that emits a corroboration receipt per approval.

    Mirrors ``gov.authorization_receipts.ReceiptEmittingApprovalQueue``:
    emission happens after ``decide()`` commits, is recorded in the
    audit log, and a failure is loud (logged then re-raised). With no
    ``receipt_config`` the queue is byte-identical legacy.

    A self-approval attempt is refused with
    corrob-receipt-self-corroboration *before* the base queue's
    separation-of-duties check, so the refusal is machine-coded at the
    receipt layer too.

    Timestamps (issuedAt/validFrom/proof created) use wall-clock time
    unless ``now`` (epoch seconds) is passed to ``decide()``; tests
    pin ``now`` for determinism.
    """

    def __init__(self, *args, receipt_config=None, **kwargs):
        super(CorroboratingApprovalQueue, self).__init__(*args, **kwargs)
        self.receipt_config = receipt_config
        self.emitted_receipts = []

    def decide(self, approval_id, approved, reason,
               decided_by="human-operator", now=None, **kwargs):
        if approved and self.receipt_config is not None:
            record = self.get(approval_id)
            if record is not None and decided_by == record.get("agent_id"):
                config = self.receipt_config
                self._log({
                    "event": "corroboration_receipt_failed",
                    "flag": "corroboration_receipt_failed",
                    "approval_id": approval_id,
                    "decision_id": record.get("id"),
                    "reviewer": config.reviewer_did,
                    "code": "corrob-receipt-self-corroboration",
                })
                raise CorroborationReceiptError(
                    "corrob-receipt-self-corroboration",
                    "reviewer %r cannot corroborate their own request"
                    % (decided_by,))
        target, entry = super(CorroboratingApprovalQueue, self).decide(
            approval_id, approved, reason, decided_by=decided_by, **kwargs)
        config = self.receipt_config
        if config is None or not approved:
            return target, entry
        try:
            receipt = config.emit_for_decision(
                target, entry, decided_by, reason, approved=True, now=now)
        except Exception as exc:
            code = getattr(exc, "code", "corrob-receipt-failed")
            self._log({
                "event": "corroboration_receipt_failed",
                "flag": "corroboration_receipt_failed",
                "approval_id": approval_id,
                "decision_id": entry.get("id"),
                "reviewer": config.reviewer_did,
                "code": code,
                "detail": str(exc)[:200],
            })
            raise
        self._log({
            "event": "corroboration_receipt_emitted",
            "approval_id": approval_id,
            "decision_id": entry.get("id"),
            "reviewer": config.reviewer_did,
            "verdict": "corroborated",
            "receipt_digest": receipt["receipt_digest"],
            "statement_digest": receipt["statement_digest"],
            "reason": reason,
        })
        self.emitted_receipts.append({
            "approval_id": approval_id,
            "envelope": receipt["envelope"],
            "vc": receipt["vc"],
            "statement_digest": receipt["statement_digest"],
            "receipt_digest": receipt["receipt_digest"],
            "entry": entry,
        })
        return target, entry
