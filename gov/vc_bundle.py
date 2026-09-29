"""VC-shaped evidence emission.

ADAPT of the W3C Verifiable Credentials Data Model 2.0 *data model*
only (wave-207 prospecting section 1): the issuer -> holder -> verifier
ecosystem maps onto "sell evidence, not the engine" -- the auditor
holds the bundle without the engine and is the verifier; the anchored
digests are the verifiable data registry.

What this module does:

- ``emit_credential()`` renders our offline evidence as a VC-shaped
  document: ``{"@context", "type", "issuer", "validFrom", "validUntil",
  "credentialSubject", "evidence", "claimBounds", "proof"}``.
  ``credentialSubject`` carries digest-identity claims; ``evidence``
  carries attestation reports and break-battery results (verdicts
  only -- never the live engine). ``claimBounds`` carries the
  narrow-claims discipline: "verifiable" does not imply "true".
- The ``proof`` binds our DSSE/PAE signature machinery with our own
  cryptosuite label. It is NOT a W3C-registered cryptosuite, and this
  module refuses to verify any foreign cryptosuite: honest non-claim
  of interop.
- ``verify_credential()`` is a standalone, offline verifier. It fails
  closed on non-conforming documents: unknown top-level fields are
  refused, required fields are validated, time bounds are enforced,
  and proof verification failure is refused. The ``@context`` URL is
  treated as an identifier only -- it is never resolved (offline
  verification must not phone home).
- ``redact_copy()`` is the v1 selective-disclosure answer:
  redaction-by-copy re-issued by the holder with a NEW signature,
  explicitly labeled as NOT ECDSA-SD-2023 (real cryptographic
  selective disclosure needs BBS+/ECDSA-SD, which are not stdlib).

stdlib-only. Fail closed everywhere: no ``None`` defaults that would
turn into a green path, no field ever defaulted silently.
"""

import copy
import hashlib
import json
import os
from datetime import datetime, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import dsse_envelope  # noqa: E402
from gov import claim_bounds as _claim_bounds  # noqa: E402
from gov.signing import Verifier  # noqa: E402

CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"

#: Our credential types. ``VerifiableCredential`` keeps the VC 2.0
#: ecosystem shape; ``SasanamEvidenceCredential`` is our profile.
CREDENTIAL_TYPES = ["VerifiableCredential", "SasanamEvidenceCredential"]

#: Our cryptosuite label. NOT a W3C-registered cryptosuite. This
#: module will only ever verify envelopes bound to this label; any
#: other cryptosuite is refused with an explicit non-interop message.
CRYPTO_SUITE = "sasanam-dsse-pae-ed25519-v1"

#: PAE payload type bound into the DSSE envelope over the credential
#: bytes. Type-swap attacks die on this binding.
PAYLOAD_TYPE = "application/vnd.sasanam.vc-credential+json"

#: Strict top-level schema. Extension fields are refused: a document
#: with fields we do not understand is not a conforming document.
_TOP_LEVEL_FIELDS = frozenset({
    "@context", "type", "issuer", "validFrom", "validUntil",
    "credentialSubject", "evidence", "claimBounds", "proof",
    "redactionNotice",
})

_JSON_SCALARS = (str, int, float, bool, type(None))


def _check_json_native(value, where):
    """Refuse non-JSON-native values at issuance: ``default=str`` in
    the canonicalizer would otherwise let a non-JSON-native value and
    its ``str()`` rendering bind to identical bytes (digest-identity
    ambiguity, plus cross-process verify failures for nondeterministic
    ``str()``)."""
    if isinstance(value, _JSON_SCALARS):
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise VCBundleError("%s: dict keys must be str, got %r"
                                    % (where, k))
            _check_json_native(v, where + "." + k)
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check_json_native(v, "%s[%d]" % (where, i))
        return
    raise VCBundleError("%s: value of type %s is not JSON-native "
                        "(would bind via str(); make it a string "
                        "explicitly)" % (where, type(value).__name__))


#: Strict proof-object schema: unknown proof sub-fields are refused so
#: a downstream consumer cannot be misled by unauthenticated metadata.
_PROOF_FIELDS = frozenset({
    "type", "cryptosuite", "proofPurpose", "verificationMethod",
    "threshold", "envelope",
})
_DEFAULT_PROVES = [
    "integrity of the credential payload as issued",
    "authenticity of the issuer's key over the payload",
    "containment of the digest-identity claims in credentialSubject",
]
_DEFAULT_DOES_NOT_PROVE = [
    "truth or correctness of the claims encoded in the credential",
    "safety or wisdom of any agent action the evidence describes",
    "that any referenced digest resolves to its bytes",
]

_REDACTION_METHOD = "redaction-by-copy"
_REDACTION_NOTE = (
    "This credential was produced by redaction-by-copy, NOT by "
    "ECDSA-SD-2023 selective disclosure: the original signature was "
    "discarded and the holder re-issued this credential with a new "
    "signature. The original issuer's signature does NOT survive "
    "subset selection.")


class VCBundleError(ValueError):
    """Fail-closed refusal on any non-conforming or unverifiable
    credential."""


def _check_nonempty_str(value, where):
    if not isinstance(value, str) or not value:
        raise VCBundleError("%s: must be a non-empty str, got %r"
                            % (where, value))
    return value


def _parse_time(value, where):
    if not isinstance(value, str) or not value:
        raise VCBundleError("%s: must be an ISO-8601 datetime str"
                            % where)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise VCBundleError("%s: not a parseable ISO-8601 datetime: %r"
                            % (where, value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        # The public seam speaks one fail-closed vocabulary: a document
        # that cannot be canonicalized is refused, not leaked as a
        # bare TypeError.
        raise VCBundleError("credential is not canonicalizable: %s"
                            % exc)


def _credential_bytes(doc):
    """Canonical bytes the proof binds: the credential minus ``proof``."""
    body = {k: v for k, v in doc.items() if k != "proof"}
    return _canonical(body)


def _build_claim_bounds(claim_bounds):
    if claim_bounds is None:
        return {"proves": list(_DEFAULT_PROVES),
                "doesNotProve": list(_DEFAULT_DOES_NOT_PROVE)}
    if not isinstance(claim_bounds, dict):
        raise VCBundleError("claimBounds: must be a dict")
    proves = claim_bounds.get("proves")
    does_not = claim_bounds.get("doesNotProve")
    if (not isinstance(proves, list) or not proves
            or not all(isinstance(s, str) and s for s in proves)):
        raise VCBundleError("claimBounds.proves: must be a non-empty "
                            "list of non-empty str")
    if (not isinstance(does_not, list) or not does_not
            or not all(isinstance(s, str) and s for s in does_not)):
        raise VCBundleError("claimBounds.doesNotProve: must be a "
                            "non-empty list of non-empty str")
    built = {"proves": list(proves), "doesNotProve": list(does_not)}
    # Wave-209: the narrow-claims discipline is one primitive across
    # every evidence shape. The VC profile's bounds must also validate
    # under the canonical gov/claim_bounds schema (the bridge inherits
    # the canonical verifier assumptions and scope limits explicitly).
    # ClaimBoundsError is wrapped to keep this seam's single error
    # vocabulary.
    try:
        _claim_bounds.from_vc_bounds(built)
    except _claim_bounds.ClaimBoundsError as e:
        raise VCBundleError("claimBounds: canonical schema refused: %s"
                            % e)
    return built


def _check_evidence(evidence):
    if not isinstance(evidence, list):
        raise VCBundleError("evidence: must be a list")
    for i, entry in enumerate(evidence):
        where = "evidence[%d]" % i
        if not isinstance(entry, dict):
            raise VCBundleError("%s: must be a dict" % where)
        _check_nonempty_str(entry.get("type"), where + ".type")
    return list(evidence)


def emit_credential(*, issuer, subject_id, subject_claims, evidence,
                    valid_from, valid_until, signer, threshold=1,
                    claim_bounds=None):
    """Issue a VC-shaped evidence credential.

    ``issuer`` is a non-empty issuer id string (our identity is the key
    ceremony + pinned keys, not the DID stack -- wave-207 SKIP).
    ``subject_id`` is the digest-identity of the subject.
    ``subject_claims`` is a dict of digest-identity claims.
    ``evidence`` is a list of dicts (attestation reports, break-battery
    results -- verdicts only). ``signer`` signs the DSSE/PAE envelope.
    ``threshold`` is the distinct-key signature threshold.
    """
    _check_nonempty_str(issuer, "issuer")
    _check_nonempty_str(subject_id, "subject_id")
    if not isinstance(subject_claims, dict) or not subject_claims:
        raise VCBundleError("subject_claims: must be a non-empty dict")
    if "id" in subject_claims:
        # "id" is reserved for the digest-identity of the subject; a
        # claim with the same key would silently override subject_id.
        raise VCBundleError("subject_claims: 'id' is reserved (it is "
                            "set from subject_id)")
    for k in subject_claims:
        if not isinstance(k, str) or not k:
            raise VCBundleError("subject_claims: keys must be non-empty "
                                "str, got %r" % (k,))
    _check_json_native(subject_claims, "subject_claims")
    evidence = _check_evidence(evidence)
    for i, entry in enumerate(evidence):
        _check_json_native(entry, "evidence[%d]" % i)
    vf = _parse_time(valid_from, "valid_from")
    vu = _parse_time(valid_until, "valid_until")
    if vf >= vu:
        raise VCBundleError("valid_from must be strictly before "
                            "valid_until")
    if not isinstance(threshold, int) or isinstance(threshold, bool) \
            or threshold < 1:
        raise VCBundleError("threshold: must be a positive int")
    if threshold > 1:
        # emit_credential seals with exactly one signer today: a
        # document claiming a higher quorum could never verify at it,
        # yet would mislead an auditor reading proof["threshold"].
        raise VCBundleError("threshold: emit_credential seals with one "
                            "signer; a threshold above 1 cannot be met "
                            "(the verify-side threshold is the policy)")
    key_id = getattr(signer, "key_id", None)
    if not isinstance(key_id, str) or not key_id:
        raise VCBundleError("signer: must expose a non-empty key_id")
    if not callable(getattr(signer, "sign", None)):
        raise VCBundleError("signer: must expose a callable sign()")

    doc = {
        "@context": [CONTEXT_V2],
        "type": list(CREDENTIAL_TYPES),
        "issuer": issuer,
        "validFrom": valid_from,
        "validUntil": valid_until,
        "credentialSubject": {"id": subject_id,
                              **copy.deepcopy(subject_claims)},
        "evidence": copy.deepcopy(evidence),
        "claimBounds": _build_claim_bounds(claim_bounds),
    }
    envelope = dsse_envelope.seal(_credential_bytes(doc), PAYLOAD_TYPE,
                                  [signer])
    doc["proof"] = {
        "type": "SasanamDSSEProof",
        "cryptosuite": CRYPTO_SUITE,
        "proofPurpose": "assertionMethod",
        "verificationMethod": key_id,
        "threshold": threshold,
        "envelope": envelope,
    }
    return doc


def _parse(doc, where="credential"):
    """Strict schema parse. Refuses unknown fields and malformed
    required fields -- fail closed, never defaulted."""
    if not isinstance(doc, dict):
        raise VCBundleError("%s: must be a dict, got %s"
                            % (where, type(doc).__name__))
    extra = set(doc) - _TOP_LEVEL_FIELDS
    if extra:
        raise VCBundleError("%s: unknown field(s) refused: %s"
                            % (where, sorted(extra)))
    context = doc.get("@context")
    if not isinstance(context, list) or CONTEXT_V2 not in context:
        # The @context URL is an identifier only: we check for its
        # presence as a string and NEVER resolve it (offline rule).
        raise VCBundleError("%s: @context must be a list containing %r "
                            "(checked as a string; never resolved)"
                            % (where, CONTEXT_V2))
    types = doc.get("type")
    if (not isinstance(types, list) or "VerifiableCredential" not in types
            or "SasanamEvidenceCredential" not in types
            or len(types) != 2):
        raise VCBundleError("%s: type must be exactly %r"
                            % (where, CREDENTIAL_TYPES))
    _check_nonempty_str(doc.get("issuer"), where + ".issuer")
    vf = _parse_time(doc.get("validFrom"), where + ".validFrom")
    vu = _parse_time(doc.get("validUntil"), where + ".validUntil")
    if vf >= vu:
        raise VCBundleError("%s: validFrom must be strictly before "
                            "validUntil" % where)
    subject = doc.get("credentialSubject")
    if not isinstance(subject, dict):
        raise VCBundleError("%s.credentialSubject: must be a dict"
                            % where)
    _check_nonempty_str(subject.get("id"),
                        where + ".credentialSubject.id")
    _check_evidence(doc.get("evidence", []))
    bounds = doc.get("claimBounds")
    if not isinstance(bounds, dict):
        raise VCBundleError("%s.claimBounds: required dict "
                            "(narrow-claims honesty rule)" % where)
    _build_claim_bounds(bounds)  # validates shape
    notice = doc.get("redactionNotice")
    if notice is not None:
        if not isinstance(notice, dict):
            raise VCBundleError("%s.redactionNotice: must be a dict"
                                % where)
        method = notice.get("method")
        if method != _REDACTION_METHOD:
            raise VCBundleError(
                "%s.redactionNotice: this module only issues "
                "redaction-by-copy; a credential claiming %r is refused"
                % (where, method))
        derived = notice.get("derivedFrom")
        if not isinstance(derived, str) or not derived:
            raise VCBundleError("%s.redactionNotice.derivedFrom: must "
                                "be a non-empty str" % where)
    return {"valid_from": vf, "valid_until": vu,
            "redacted": notice is not None}


def verify_credential(doc, *, verifiers, threshold=1, now=None):
    """Standalone offline verifier. Returns a detail dict on success;
    raises VCBundleError (fail closed) on any non-conforming document
    or proof verification failure.

    ``verifiers`` is a list of ``gov.signing.Verifier``. No issuer
    interaction happens: the proof is checked against the supplied
    verifiers and the anchored digest identity, nothing else.
    ``now`` is an ISO-8601 datetime for the time-bound check
    (defaults to current UTC).
    """
    parsed = _parse(doc)
    if verifiers is None or not isinstance(verifiers, (list, tuple)):
        raise VCBundleError("verifiers: must be a non-empty list of "
                            "gov.signing.Verifier")
    verifiers = list(verifiers)
    if not verifiers or not all(isinstance(v, Verifier)
                                for v in verifiers):
        raise VCBundleError("verifiers: must be a non-empty list of "
                            "gov.signing.Verifier")
    if not isinstance(threshold, int) or isinstance(threshold, bool) \
            or threshold < 1:
        raise VCBundleError("threshold: must be a positive int")
    now_dt = (_parse_time(now, "now") if now is not None
              else datetime.now(timezone.utc))
    if now_dt < parsed["valid_from"]:
        raise VCBundleError("credential is not yet valid "
                            "(validFrom in the future)")
    if now_dt > parsed["valid_until"]:
        raise VCBundleError("credential is expired (validUntil passed)")

    proof = doc.get("proof")
    if not isinstance(proof, dict):
        raise VCBundleError("proof: must be a dict")
    extra = set(proof) - _PROOF_FIELDS
    if extra:
        raise VCBundleError("proof: unknown field(s) refused: %s"
                            % sorted(extra))
    if proof.get("type") != "SasanamDSSEProof":
        raise VCBundleError("proof.type: %r is not a proof this "
                            "verifier understands" % (proof.get("type"),))
    suite = proof.get("cryptosuite")
    if suite != CRYPTO_SUITE:
        # Honest non-claim of interop: we do not attempt to verify
        # foreign cryptosuites, even W3C-registered ones.
        raise VCBundleError("proof.cryptosuite %r is not verifiable by "
                            "this offline verifier (it only verifies "
                            "%r); refusing, not attempting interop"
                            % (suite, CRYPTO_SUITE))
    envelope = proof.get("envelope")
    if not isinstance(envelope, dict):
        raise VCBundleError("proof.envelope: must be a dict")
    # Authentication precedes binding: a tampered payload is refused on
    # the signature path, not merely on the digest comparison. The
    # envelope seam's own error type is wrapped so the public seam
    # speaks one fail-closed vocabulary (VCBundleError).
    try:
        opened = dsse_envelope.open_envelope(
            envelope, _credential_bytes(doc), PAYLOAD_TYPE, verifiers,
            threshold=threshold)
    except dsse_envelope.EnvelopeError as exc:
        raise VCBundleError("proof verification failed: %s" % exc)
    return {
        "valid": True,
        "issuer": doc["issuer"],
        "subject_id": doc["credentialSubject"]["id"],
        "key_ids": opened["key_ids"],
        "threshold": threshold,
        "redacted": parsed["redacted"],
        "evidence_count": len(doc["evidence"]),
    }


def redact_copy(doc, *, keep_subject_fields, keep_evidence_types,
                holder_issuer, signer, verifiers, valid_from, valid_until,
                now=None):
    """Produce a redacted re-issue of a verified credential.

    Only the credentialSubject fields named in
    ``keep_subject_fields`` and the evidence entries whose ``type`` is
    in ``keep_evidence_types`` survive. The input is verified first
    (with ``verifiers``) -- only a genuinely-issued bundle may be
    redacted. The result is a NEW credential issued by
    ``holder_issuer`` with a NEW signature from ``signer``, carrying a
    ``redactionNotice`` that explicitly disclaims ECDSA-SD-2023
    selective disclosure and binds ``derivedFrom`` (the digest of the
    source credential as issued).
    """
    if (not isinstance(keep_subject_fields, (set, frozenset, list, tuple))
            or not all(isinstance(f, str) and f for f in
                       keep_subject_fields)):
        raise VCBundleError("keep_subject_fields: must be a collection "
                            "of non-empty str")
    if (not isinstance(keep_evidence_types, (set, frozenset, list, tuple))
            or not all(isinstance(t, str) and t for t in
                       keep_evidence_types)):
        raise VCBundleError("keep_evidence_types: must be a collection "
                            "of non-empty str")
    verify_credential(doc, verifiers=verifiers, now=now)
    keep_subject_fields = set(keep_subject_fields)
    keep_evidence_types = set(keep_evidence_types)
    subject = doc["credentialSubject"]
    new_claims = {k: copy.deepcopy(v) for k, v in subject.items()
                  if k in keep_subject_fields}
    new_evidence = [copy.deepcopy(e) for e in doc["evidence"]
                    if e.get("type") in keep_evidence_types]
    redacted = emit_credential(
        issuer=holder_issuer,
        subject_id=subject["id"],
        subject_claims=new_claims or {"redacted": "all-claims-withheld"},
        evidence=new_evidence,
        valid_from=valid_from,
        valid_until=valid_until,
        signer=signer,
        claim_bounds={
            "proves": ["integrity of this redacted credential as "
                       "re-issued", "authenticity of the holder's key "
                       "over the redacted payload"],
            "doesNotProve": list(_DEFAULT_DOES_NOT_PROVE) + [
                "that the redacted fields ever existed or their values",
            ],
        },
    )
    # The notice must ride INSIDE the proof-bound payload: strip the
    # issuer's proof, attach the notice, then re-seal exactly once over
    # the full credential-minus-proof bytes.
    del redacted["proof"]
    redacted["redactionNotice"] = {
        "method": _REDACTION_METHOD,
        "note": _REDACTION_NOTE,
        "derivedFrom": hashlib.sha256(
            _credential_bytes(doc)).hexdigest(),
    }
    envelope = dsse_envelope.seal(_credential_bytes(redacted),
                                  PAYLOAD_TYPE, [signer])
    redacted["proof"] = {
        "type": "SasanamDSSEProof",
        "cryptosuite": CRYPTO_SUITE,
        "proofPurpose": "assertionMethod",
        "verificationMethod": signer.key_id,
        "threshold": 1,
        "envelope": envelope,
    }
    return redacted
