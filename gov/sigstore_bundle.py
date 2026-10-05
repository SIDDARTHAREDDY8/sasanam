"""Spec-strict keyed Sigstore Bundle v0.3 export (wave-321 lane 1).

Complements ``gov/evidence_sigstore.py`` (wave-311 lane D, witness-backed
bundle): this module emits the fully-offline, self-signed, KEYED bundle
form -- ``VerificationMaterial`` form (1), ``PublicKeyIdentifier`` --
proven verifiable by third-party tooling in an independent 2026-08-15
spike (cosign ``verify-blob-attestation --key ... --insecure-ignore-tlog``
-> ``Verified OK``; sigstore-go ``verify.WithKey()``).

Bundle wire shape (Sigstore Bundle v0.3 protobuf JSON)::

    {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "verificationMaterial": {
        "publicKey": {"hint": "<hex sha256(DER(SPKI))>"}
      },
      "dsseEnvelope": {
        "payload": "<base64 statement bytes>",
        "payloadType": "application/vnd.sasanam.evidence+json",
        "signatures": [{"keyid": "", "sig": "<base64>"}]   # exactly one
      }
    }

Differences from ``gov/evidence_sigstore.py``, stated honestly:

- ``verificationMaterial.publicKey`` is the spec form (1)
  ``PublicKeyIdentifier`` -- ``{"hint": ...}`` ONLY. No raw key bytes
  in-band: the key travels out-of-band and is pinned by the auditor
  (the ``verify`` caller's ``public_key`` argument). The wave-311 module
  embeds ``{"rawBytes": ..., "keyDetails": ...}`` where the proto expects
  a ``PublicKeyIdentifier`` (which has only ``hint``).
- ``hint`` is populated at seal (OSSF model-signing convention:
  ``hex(sha256(DER(SPKI)))``); the DSSE ``keyid`` stays empty. Key
  selection comes only from the caller's pinned key, never from
  in-band hints (per DSSE, keyid MUST NOT be used for security
  decisions). The hint lets an auditor confirm out-of-band which key
  the bundle was sealed for; verify accepts an empty hint too -- the
  2026-08-15 spike proved cosign verifies
  ``verificationMaterial == {"publicKey": {}}``.
- Exactly ONE signature per DSSE envelope, enforced at seal AND verify
  (the proto is normative: "a client MUST reject an envelope if the
  number of signatures is not equal to one"). Multiple signers fan out
  at export: one bundle per signer.
- The DSSE signature covers ``PAE(payloadType, payload)`` --
  ``PAE(UTF8(payloadType), payload)`` per secure-systems-lab/dsse --
  computed by ``gov.dsse_envelope.pae``; the signature cannot be
  transplanted onto a differently-typed payload or a raw (non-PAE)
  message.
- Sasanam-namespaced ``payloadType``
  (``application/vnd.sasanam.evidence+json``) that auditors pin.
- NO ``tlogEntries``, NO ``timestampVerificationData``: this is the
  fully-offline self-signed bundle, which the Bundle spec leaves
  conformant (both fields optional). A bundle carrying tlog entries or
  timestamps is REFUSED -- we cannot verify them offline, so we do not
  accept them (fail-closed; the wave-311 witness-backed bundle is the
  place for log-anchored evidence). The audit log is NEVER shoehorned
  into ``TransparencyLogEntry``.

Negative design rules (2026 Sigstore CVEs, wave-310 research):

- No issuing CAs exist in the keyed form, so there is nothing to
  "silently accept expired" -- but the analogue is enforced: the
  signature is checked against the CALLER-PINNED key only; a signature
  that verifies under any other key is a refusal, never a success.
- No false "Verified OK": every refusal raises coded
  :class:`KeyedBundleError`; success returns only after mediaType,
  oneof, hint, keyid, envelope shape, single-signature, PAE signature,
  and (in the evidence variant) subject-digest binding all pass.

Coded refusal reasons (``sigstore-keyed-*`` taxonomy decision codes,
registered in ``gov/decision_codes.py`` like every other evidence
module):

- ``sigstore-keyed-malformed`` -- bundle/envelope shape violations (not
  a dict, bad base64, missing fields, bad key types).
- ``sigstore-keyed-media-type`` -- mediaType is not the pinned v0.3
  value.
- ``sigstore-keyed-verification-material`` -- verificationMaterial is
  not the form-(1) oneof: missing ``publicKey``, presence of
  ``x509CertificateChain``/``certificate``/``publicKeyIdentifier``
  (the sigstore/docs#451 field-name trap), or non-``hint`` keys inside
  ``publicKey``.
- ``sigstore-keyed-hint-mismatch`` -- hint is neither empty nor the
  pinned key's fingerprint.
- ``sigstore-keyed-message-signature-unexpected`` -- the bundle carries
  a ``messageSignature``: the v0.3 content oneof is
  ``message_signature XOR dsse_envelope``, and this module is the
  DSSE-envelope form. A bundle carrying both is refused so a
  downstream tool can never interpret the bundle via a blob our
  verifier did not check.
- ``sigstore-keyed-keyid-mismatch`` -- DSSE keyid is neither empty nor
  absent (hint-consistency MUST).
- ``sigstore-keyed-tlog-unexpected`` -- non-empty ``tlogEntries``.
- ``sigstore-keyed-timestamp-unexpected`` -- non-empty
  ``timestampVerificationData``.
- ``sigstore-keyed-envelope`` -- dsseEnvelope shape violations.
- ``sigstore-keyed-multi-signature`` -- signatures list length != 1.
- ``sigstore-keyed-payload-type`` -- payloadType is not the expected
  (auditor-pinned) value.
- ``sigstore-keyed-signature-invalid`` -- the single Ed25519 signature
  does not verify over ``PAE(payloadType, payload)`` under the pinned
  key (covers forged, wrong-key, tampered-payload, and non-PAE
  signatures).
- ``sigstore-keyed-subject-mismatch`` -- (evidence variant) the
  in-toto statement subject digest does not name the caller's expected
  evidence digest (artifact + signature + key binding, CVE-2026-22703
  lesson).

Reserved post-quantum slot (wave-335 lane 4, format only): the bundle
format reserves the top-level ``pqAlgId`` field naming a PQ signature
algorithm from the closed :mod:`gov.pq_envelope` table. The slot is
DISABLED in this build -- sealing with it refuses
``evidence-pq-not-enabled`` (unknown identifiers refuse
``evidence-pq-unknown-alg``), and a bundle carrying it is refused
before any classical signature work, so a PQ-claimed bundle can never
be verified down the Ed25519 path (algorithm-confusion kill).
Classical bundles (slot absent) seal and verify byte-identically to
the pre-slot format.

Stdlib only. $0 spend. Synthetic/local testing. No network.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json

from gov import dsse_envelope as _dsse
from gov import pq_envelope as _pq
from gov.signing import Ed25519Verifier

__all__ = [
    "SIGSTORE_BUNDLE_MEDIA_TYPE",
    "SASANAM_PAYLOAD_TYPE",
    "KeyedBundleError",
    "spki_der_ed25519",
    "key_hint",
    "seal_keyed_bundle",
    "seal_keyed_bundle_fanout",
    "open_keyed_bundle",
    "verify_keyed_bundle",
    "open_keyed_evidence_bundle",
]

#: Pinned Sigstore Bundle media type (v0.3 protobuf JSON contract).
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"

#: Sasanam-namespaced DSSE payloadType, bound inside the PAE signature.
SASANAM_PAYLOAD_TYPE = "application/vnd.sasanam.evidence+json"

#: DER prefix of an Ed25519 SubjectPublicKeyInfo:
#: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING <32 raw bytes> }.
_ED25519_SPKI_DER_PREFIX = binascii.unhexlify("302a300506032b6570032100")


class KeyedBundleError(Exception):
    """Coded refusal for keyed-bundle seal/verify failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _refuse(code, detail):
    raise KeyedBundleError("%s: %s" % (code, detail), code=code)


def _pq_gate(pq_alg_id, where):
    """Reserved-PQ-slot gate (wave-335 lane 4, format only).

    Parses the ``pqAlgId`` identifier against the closed table, then
    refuses: the slot is reserved/disabled in this build, so any real
    USE (seal or verify) is refused fail-closed. Re-raises as
    :class:`KeyedBundleError` so the bundle seam keeps one exception
    type; the machine ``code`` string is preserved verbatim.
    """
    try:
        _pq.pq_use_refused(pq_alg_id)
    except _pq.PQEnvelopeError as exc:
        _refuse(exc.code, "%s: %s" % (where, exc))
    # pq_use_refused never returns; the line below is unreachable by
    # construction (kept as a backstop, never a silent pass).
    _refuse("evidence-pq-not-enabled",
            "%s: unreachable PQ gate fallthrough" % where)


def _malformed(detail):
    _refuse("sigstore-keyed-malformed", detail)


def _check_raw_pubkey(public_key, where):
    if (not isinstance(public_key, (bytes, bytearray))
            or len(public_key) != 32):
        _malformed("%s: public_key must be 32 raw bytes, got %s"
                   % (where, type(public_key).__name__))
    return bytes(public_key)


def spki_der_ed25519(raw_pubkey):
    """Return the DER-encoded SubjectPublicKeyInfo for a raw Ed25519 key.

    The DER is fixed for Ed25519: ``302a300506032b6570032100`` followed
    by the 32 raw key bytes (the BIT STRING contents).
    """
    raw = _check_raw_pubkey(raw_pubkey, "spki_der_ed25519")
    return _ED25519_SPKI_DER_PREFIX + raw


def key_hint(raw_pubkey):
    """Return the key hint for a raw Ed25519 public key.

    ``hex(sha256(DER(SPKI)))`` -- the OSSF model-signing convention the
    prospectus proposes for the out-of-band ``PublicKeyIdentifier.hint``.
    """
    return hashlib.sha256(spki_der_ed25519(raw_pubkey)).hexdigest()


def _check_statement_bytes(value, where):
    if not isinstance(value, (bytes, bytearray)) or not value:
        _malformed("%s: statement bytes must be non-empty bytes" % where)
    return bytes(value)


def _seal_one(statement_bytes, signer, payload_type):
    statement_bytes = _check_statement_bytes(statement_bytes,
                                             "seal_keyed_bundle")
    if not hasattr(signer, "sign") or not hasattr(signer, "public_key"):
        _malformed("seal_keyed_bundle: signer must expose sign() and "
                   "public_key")
    # The signature covers PAE(payloadType, payload) -- confirmed by
    # construction: gov.dsse_envelope.pae builds the exact signed bytes.
    pae_bytes = _dsse.pae(payload_type, statement_bytes)
    try:
        sig = bytes(signer.sign(pae_bytes))
    except Exception as exc:
        # Keep the traceback chain so seal-path programmer errors stay
        # debuggable (standards review, wave-321 lane 1).
        raise KeyedBundleError(
            "sigstore-keyed-malformed: seal_keyed_bundle: signer.sign "
            "failed: %r" % (exc,), code="sigstore-keyed-malformed") from exc
    if len(sig) != 64:
        _malformed("seal_keyed_bundle: signer produced %d-byte signature, "
                   "need 64" % len(sig))
    hint = key_hint(signer.public_key)
    # NOTE (spec review, wave-321 lane 1): the hint is NON-EMPTY here
    # while the DSSE keyid below is empty. That is the intended
    # invariant -- key selection comes only from the caller's pinned
    # key; the hint names that key's fingerprint for the auditor, and
    # keyid is never used for security decisions (DSSE). Do NOT
    # "fix" this into keyid == hint.
    return {
        "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            # Form (1) PublicKeyIdentifier: hint ONLY. The key itself
            # travels out-of-band, pinned by the auditor.
            "publicKey": {"hint": hint},
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(statement_bytes).decode("ascii"),
            "payloadType": payload_type,
            # Exactly one signature per envelope (proto MUST). keyid
            # stays empty so the hint-consistency MUST is satisfied by
            # emptiness on both sides.
            "signatures": [
                {"keyid": "", "sig": base64.b64encode(sig).decode("ascii")},
            ],
        },
    }


def seal_keyed_bundle(statement_bytes, signer,
                      payload_type=SASANAM_PAYLOAD_TYPE, *, pq_alg_id=None):
    """Seal statement bytes into ONE keyed Sigstore bundle.

    ``signer`` is a ``gov.signing.Signer`` (``sign()`` over bytes,
    ``public_key`` 32 raw bytes). The envelope carries exactly one
    signature; use :func:`seal_keyed_bundle_fanout` for multiple
    signers.

    ``pq_alg_id`` is the RESERVED post-quantum slot (wave-335 lane 4,
    format only): this build never seals a PQ-claimed bundle, so any
    non-None value refuses ``evidence-pq-not-enabled``
    (``evidence-pq-unknown-alg`` for identifiers outside the closed
    table). With ``pq_alg_id=None`` (the default) the sealed bytes are
    byte-identical to the pre-slot format.
    """
    if not isinstance(payload_type, str) or not payload_type:
        _malformed("seal_keyed_bundle: payload_type must be a non-empty str")
    if pq_alg_id is not None:
        _pq_gate(pq_alg_id, "seal_keyed_bundle")
    return _seal_one(statement_bytes, signer, payload_type)


def seal_keyed_bundle_fanout(statement_bytes, signers,
                             payload_type=SASANAM_PAYLOAD_TYPE, *,
                             pq_alg_id=None):
    """Seal statement bytes once per signer: one bundle per signature.

    Returns a list of bundle dicts, each with exactly one DSSE
    signature (the proto's one-signature-per-envelope MUST). Refuses an
    empty signer list. ``pq_alg_id`` is the reserved PQ slot -- see
    :func:`seal_keyed_bundle`; any non-None value refuses.
    """
    signers = list(signers) if signers is not None else []
    if not signers:
        _malformed("seal_keyed_bundle_fanout: need at least one signer")
    if not isinstance(payload_type, str) or not payload_type:
        _malformed("seal_keyed_bundle_fanout: payload_type must be a "
                   "non-empty str")
    if pq_alg_id is not None:
        _pq_gate(pq_alg_id, "seal_keyed_bundle_fanout")
    return [_seal_one(statement_bytes, s, payload_type) for s in signers]


def _b64_decode(value, where):
    if not isinstance(value, str):
        _malformed("%s: must be a base64 str, got %s"
                   % (where, type(value).__name__))
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        _malformed("%s: invalid base64" % where)


def check_keyed_bundle_structure(bundle,
                                 expected_payload_type=SASANAM_PAYLOAD_TYPE):
    """Keyless structural check: is this bundle *verifiable*?

    Runs every :func:`open_keyed_bundle` check that does not need the
    pinned key: the bundle is a JSON object with the Sigstore bundle
    media type, carries no ``messageSignature`` alongside the DSSE
    envelope, passes the reserved PQ-slot gate, carries form-(1)
    verification material (hint present as a string; the hint-to-pinned-
    key binding is the verifier's job, not this check's), carries no
    tlog/timestamp claims (unverifiable offline), and carries a
    well-shaped single-signature DSSE envelope with the expected
    payload type.

    Raises coded :class:`KeyedBundleError` on any structural refusal.
    Returns None on success. This is the builder-side half of the
    wave-339 R22 contract (Bernstein #6371: builders never emit a
    bundle containing a payload the verifier cannot verify) -- e.g.
    ``gov/oci_referrer.py::attach_keyed_bundle`` calls it before
    putting anything on the wire. Signature validity and hint pinning
    stay the consumer's job: this check proves *verifiability*, not
    *validity*.
    """
    if not isinstance(bundle, dict):
        _malformed("bundle must be a JSON object")

    # --- mediaType (protobuf JSON contract) ---
    if bundle.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        _refuse("sigstore-keyed-media-type",
                "mediaType must be %r" % SIGSTORE_BUNDLE_MEDIA_TYPE)

    # --- content oneof: this module is the dsseEnvelope form ---
    # The v0.3 Bundle content is message_signature XOR dsse_envelope.
    # A bundle carrying a messageSignature alongside the envelope is
    # non-conformant, and a downstream tool might interpret the bundle
    # via the blob we did not verify -- so it is refused, not ignored.
    if bundle.get("messageSignature"):
        _refuse("sigstore-keyed-message-signature-unexpected",
                "keyed bundles are DSSE-envelope bundles; "
                "messageSignature refused")

    # --- reserved PQ slot (wave-335 lane 4, format only) ---
    # A bundle carrying ``pqAlgId`` claims post-quantum provenance.
    # This build has no PQ verifier, so the bundle is refused BEFORE
    # any classical signature work: verifying a PQ-claimed bundle down
    # the Ed25519 path would be algorithm confusion. Unknown
    # identifiers refuse ``evidence-pq-unknown-alg``; known ones refuse
    # ``evidence-pq-not-enabled``. Absent (or null) slot: the classical
    # path below, byte-identical to the pre-slot format.
    _pq_slot = bundle.get("pqAlgId")
    if _pq_slot is not None:
        _pq_gate(_pq_slot, "check_keyed_bundle_structure")

    # --- verificationMaterial: form-(1) oneof, strictly ---
    vm = bundle.get("verificationMaterial")
    if not isinstance(vm, dict):
        _refuse("sigstore-keyed-verification-material",
                "verificationMaterial must be an object")
    for forbidden in ("x509CertificateChain", "certificate",
                      "publicKeyIdentifier"):
        if forbidden in vm:
            _refuse("sigstore-keyed-verification-material",
                    "keyed bundles carry no %s (form (1) only; note "
                    "sigstore/docs#451: the JSON key is 'publicKey')"
                    % forbidden)
    pk = vm.get("publicKey")
    if not isinstance(pk, dict):
        _refuse("sigstore-keyed-verification-material",
                "verificationMaterial.publicKey must be an object")
    unknown = set(pk) - {"hint"}
    if unknown:
        _refuse("sigstore-keyed-verification-material",
                "publicKey carries unknown fields %s (PublicKeyIdentifier "
                "has only 'hint')" % sorted(unknown))
    hint = pk.get("hint", "")
    if not isinstance(hint, str):
        _refuse("sigstore-keyed-verification-material",
                "publicKey.hint must be a string")
    # NOTE: hint-to-pinned-key binding is NOT checked here -- it needs
    # the pinned key, which the builder side may not hold. The verifier
    # (open_keyed_bundle) enforces it before any signature work.

    # --- tlog / timestamp: absent or empty, never accepted blind ---
    tlog = bundle.get("tlogEntries", [])
    if tlog:
        _refuse("sigstore-keyed-tlog-unexpected",
                "keyed offline bundles carry no tlogEntries; refusing "
                "unverifiable log claims")
    if not isinstance(tlog, list):
        _malformed("tlogEntries must be a list")
    ts = bundle.get("timestampVerificationData", {})
    if ts:
        _refuse("sigstore-keyed-timestamp-unexpected",
                "keyed offline bundles carry no timestamps; refusing "
                "unverifiable time claims")
    if not isinstance(ts, dict):
        _malformed("timestampVerificationData must be an object")
    # (Also spelled inside verificationMaterial by some producers --
    # same rule.)
    vm_tlog = vm.get("tlogEntries", [])
    if vm_tlog:
        _refuse("sigstore-keyed-tlog-unexpected",
                "verificationMaterial.tlogEntries refused (offline bundle)")
    vm_ts = vm.get("timestampVerificationData", {})
    if vm_ts:
        _refuse("sigstore-keyed-timestamp-unexpected",
                "verificationMaterial.timestampVerificationData refused "
                "(offline bundle)")

    # --- dsseEnvelope: the single parse ---
    env = bundle.get("dsseEnvelope")
    if not isinstance(env, dict):
        _refuse("sigstore-keyed-envelope", "dsseEnvelope must be an object")
    payload = _b64_decode(env.get("payload"), "dsseEnvelope.payload")
    if not payload:
        _refuse("sigstore-keyed-envelope", "empty payload refused")
    payload_type = env.get("payloadType")
    if not isinstance(payload_type, str) or not payload_type:
        _refuse("sigstore-keyed-envelope", "payloadType must be a string")
    if payload_type != expected_payload_type:
        _refuse("sigstore-keyed-payload-type",
                "envelope carries %r, expected %r"
                % (payload_type, expected_payload_type))

    sigs = env.get("signatures")
    if not isinstance(sigs, list):
        _refuse("sigstore-keyed-envelope", "signatures must be a list")
    # The proto MUST: exactly one signature per envelope in a bundle.
    if len(sigs) != 1:
        _refuse("sigstore-keyed-multi-signature",
                "bundle envelopes must carry exactly one signature, got %d"
                % len(sigs))
    entry = sigs[0]
    if not isinstance(entry, dict):
        _refuse("sigstore-keyed-envelope", "signature entry must be an object")
    keyid = entry.get("keyid", "")
    if not isinstance(keyid, str):
        _refuse("sigstore-keyed-envelope", "keyid must be a string")
    if keyid not in ("",):
        _refuse("sigstore-keyed-keyid-mismatch",
                "keyid must be empty (hint-consistency MUST), got %r" % keyid)
    sig = _b64_decode(entry.get("sig"), "dsseEnvelope.signatures[0].sig")
    if len(sig) != 64:
        _refuse("sigstore-keyed-signature-invalid",
                "signature must be 64 bytes, got %d" % len(sig))
    return None


def open_keyed_bundle(bundle, public_key,
                      expected_payload_type=SASANAM_PAYLOAD_TYPE):
    """Verify a keyed bundle and return the verified payload bytes.

    ``public_key`` is the 32-byte raw Ed25519 key the auditor pins --
    the ONLY key a signature may verify under. A malformed ``public_key``
    is a programmer error and raises ``ValueError`` loudly (it is caller
    configuration, never attacker input). Raises coded
    :class:`KeyedBundleError` on any bundle refusal; returns the exact parsed
    payload bytes (the buffer the signature was verified over) on
    success. Never returns unverified bytes.
    """
    # Programmer error: loud, not a bundle refusal. (gov/signing.py
    # raises ValueError for bad key material too.) verify_keyed_bundle
    # deliberately lets this propagate instead of folding it into False.
    if (not isinstance(public_key, (bytes, bytearray))
            or len(public_key) != 32):
        raise ValueError("open_keyed_bundle: public_key must be 32 raw "
                         "bytes, got %s" % type(public_key).__name__)
    pub = bytes(public_key)
    # Verifiability (keyless) first, then pinning, then the signature.
    # check_keyed_bundle_structure performs every structural check below
    # that does not need the pinned key; behavior is identical to the
    # previous inline form (hint pinning moves after the structural
    # checks; both are coded fail-closed refusals).
    check_keyed_bundle_structure(bundle, expected_payload_type)

    # --- hint pinning: the envelope names the pinned key or names none ---
    # The hint is the envelope's only key identifier (keyid MUST be
    # empty), so a hint naming a different key is an envelope for the
    # wrong trust root. Refuse before any signature work -- this is the
    # check the builder side cannot perform without the pinned key.
    hint = bundle["verificationMaterial"]["publicKey"].get("hint", "")
    if hint not in ("", key_hint(pub)):
        _refuse("sigstore-keyed-hint-mismatch",
                "publicKey.hint %r names a different key than the pinned "
                "key (hint %r)" % (hint, key_hint(pub)))

    # --- re-extract the already-validated envelope fields ---
    env = bundle["dsseEnvelope"]
    payload = _b64_decode(env.get("payload"), "dsseEnvelope.payload")
    payload_type = env.get("payloadType")
    sig = _b64_decode(env.get("signatures")[0].get("sig"),
                      "dsseEnvelope.signatures[0].sig")

    # --- the signature check: PAE(payloadType, payload) under the PINNED key ---
    pae_bytes = _dsse.pae(payload_type, payload)
    verifier = Ed25519Verifier(pub)
    # gov.ed25519.verify returns True/False and never raises (wave-243):
    # check the return with `is True`, never truthiness.
    if verifier.verify(pae_bytes, sig) is not True:
        _refuse("sigstore-keyed-signature-invalid",
                "Ed25519 signature does not verify over PAE(payloadType, "
                "payload) under the pinned key")
    return payload


def verify_keyed_bundle(bundle, public_key,
                        expected_payload_type=SASANAM_PAYLOAD_TYPE):
    """Return True iff ``bundle`` verifies under ``public_key``.

    Bool-returning, never raises on bundle problems (only on programmer
    errors such as a malformed ``public_key`` argument): True means every
    check in :func:`open_keyed_bundle` passed; False means any coded
    refusal. Never emits a false success.
    """
    try:
        open_keyed_bundle(bundle, public_key,
                          expected_payload_type=expected_payload_type)
    except KeyedBundleError:
        return False
    return True


def open_keyed_evidence_bundle(bundle, public_key, expected_evidence_digest,
                               expected_payload_type=SASANAM_PAYLOAD_TYPE):
    """Verify a keyed bundle and bind it to the expected evidence digest.

    Runs :func:`open_keyed_bundle`, then parses the verified payload as
    an in-toto statement and requires its subject digest to name
    ``expected_evidence_digest`` (hex sha256 of the evidence bytes the
    caller sealed). This is the artifact + signature + key binding
    (CVE-2026-22703 lesson): a valid signature alone is never enough.

    Returns ``(payload_bytes, statement_dict)``. Raises coded
    :class:`KeyedBundleError` (``sigstore-keyed-subject-mismatch`` for
    the binding) on any refusal.
    """
    if (not isinstance(expected_evidence_digest, str)
            or len(expected_evidence_digest) != 64):
        _malformed("expected_evidence_digest must be a 64-char hex sha256")
    payload = open_keyed_bundle(bundle, public_key,
                                expected_payload_type=expected_payload_type)
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _refuse("sigstore-keyed-subject-mismatch",
                "verified payload is not a JSON statement: %r" % (exc,))
    if not isinstance(statement, dict):
        _refuse("sigstore-keyed-subject-mismatch",
                "verified payload is not a JSON object")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        _refuse("sigstore-keyed-subject-mismatch",
                "statement carries no subjects")
    bound = False
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        digest = subject.get("digest")
        if isinstance(digest, dict) and digest.get("sha256") == \
                expected_evidence_digest:
            bound = True
            break
    if not bound:
        _refuse("sigstore-keyed-subject-mismatch",
                "statement subject digest does not name the expected "
                "evidence digest")
    return payload, statement
