"""Sigstore Bundle v0.3-compatible distribution for evidence bundles (wave-311 lane D).

Additive distribution step implementing build-order step 3 of the
evidence-envelope prospectus
(``research/prospecting/w310_offline_verifier_auditor_ux.md``): take the
sealed in-toto statement envelope (wave-310, ``gov/evidence_intoto.py``)
and wrap it in a Sigstore Bundle v0.3-shaped JSON object so third-party
verifiers (cosign, ``gh attestation verify``) can consume evidence
without the engine.

Bundle wire shape (Sigstore Bundle v0.3 protobuf JSON)::

    {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "verificationMaterial": {
        "publicKey": {"hint": "<hex sha256(DER(SPKI))>"},
        "tlogEntries": [ <witness entry> ],
        "timestampVerificationData": {          # optional, see below
          "rfc3161Timestamps": [{"signedTimestamp": "<base64>"}]
        }
      },
      "dsseEnvelope": {
        "payload": "<base64 statement bytes>",
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [{"keyid": "<hex>", "sig": "<base64>"}]
      }
    }

Differences from a public-Sigstore bundle, stated honestly:

- The DSSE signatures are base64 (the Sigstore protobuf JSON mapping),
  not our native hex -- this is the interop surface cosign parses.
- ``verificationMaterial.publicKey`` is the Bundle v0.3 form (1)
  ``PublicKeyIdentifier``: ``{"hint": ...}`` ONLY, the hex
  ``sha256(DER(SPKI))`` fingerprint (the OSSF model-signing convention,
  shared with ``gov.sigstore_bundle.key_hint``). The raw key travels
  out-of-band, pinned by the auditor; the witness binding resolves the
  primary key from the caller-pinned verifier set
  (``_resolve_primary_key``) -- never from an in-band bundle field.
  (Wave-329: the wave-311 shape embedded
  ``{"rawBytes": ..., "keyDetails": ...}`` where the proto allows only
  ``hint``; strict protobuf-JSON parsers reject unknown fields, so the
  old shape forked the wire format from the interop shape.)
- ``tlogEntries`` carries OUR OWN Rekor-pattern witness entry, issued
  by a local witness key -- NOT the public Rekor service ($0,
  offline-first). With ``witness_log=`` (a ``gov.witness_log.WitnessLog``)
  the entry is log-backed: real ``logIndex`` plus a signed checkpoint +
  Merkle inclusion proof (``gov/witness_log.py``, wave-312). Without it,
  the entry is the offline-fallback shape (SET only).
- The RFC 3161 token field is a CARRIER: an attached token must be
  well-formed, but it is not cryptographically verified in this lane
  (no TSA at $0); the bundle MUST verify without it. Token
  verification is a step-4 (standalone verifier) residual.

Witness entry shape (Rekor-pattern)::

    {
      "logIndex": "0",
      "logId": {"keyId": "<base64 sha256(witness pubkey)>"},
      "kindVersion": {"kind": "sasanam-witness", "version": "0.0.1"},
      "integratedTime": "<unix seconds, int64-as-string>",
      "inclusionPromise": {"signedEntryTimestamp": "<base64 SET>"},
      "canonicalizedBody": "<base64 canonical JSON>",
      "inclusionProof": {                     # log-backed path only
        "checkpoint": {"logId": "<hex>", "treeSize": N,
                       "rootHash": "<hex>", "timestamp": T},
        "checkpointSignature": "<base64>",
        "auditPath": [{"hash": "<hex>", "side": "left|right"}, ...]
      }
    }

``seal_sigstore_bundle(..., witness_log=None)`` selects the path: with
a ``gov.witness_log.WitnessLog``, the canonical body is appended to
the real log, ``logIndex`` is the true tree position, and
``inclusionProof`` carries a signed checkpoint + Merkle audit path
backed by real tree state (wave-312). Without it, the entry keeps the
offline-fallback shape (``logIndex: "0"``, SET only) -- the bundle
verifies either way, and the verifier checks the proof only when
present.

The canonicalized body binds (CVE-2026-22703 lesson -- artifact +
signature + key, never "a valid entry" alone)::

    {"apiVersion": "0.0.1", "kind": "sasanam-witness",
     "spec": {"artifactDigest": "<hex sha256 of the DSSE payload bytes>",
              "signatures": [ <the bundle's exact wire sig entries> ],
              "publicKey": {"rawBytes": "<base64>", "keyDetails": ...}}}

The SET is the witness key's Ed25519 signature over the canonical body
bytes. ``integratedTime`` is the sealer's host clock at seal
(``time.time()``); the verifier checks it against the CALLER-PINNED
``witness_validity`` window (CVE-2026-24122 analogue: issuing-side time
is validated, never trusted blindly). The window is a REQUIRED keyword
-- without it the time check cannot run, and there is no silent
downgrade.

Design rules inherited from prospecting (all enforced below):

- The envelope is the interop; the payload type is bound inside the
  PAE signature (a signature cannot be transplanted onto a
  differently-typed payload).
- Verify the EXACT bytes delivered: the bundle is parsed exactly once;
  the statement is parsed from the verified payload bytes, never
  re-derived; the witness body is recomputed from the verified envelope
  fields and required byte-equal.
- Subjects are digests (statement subject binds the bundle bytes).
- Content checks (payloadType, statement shape, predicateType, subject
  digest) are ALWAYS ON, never opt-in (CVE-2026-39395).
- A crash/malformed input never emits a success signal (CVE-2026-44310):
  every refusal raises coded ``EnvelopeError``; success returns only
  after every stage passes.
- Unknown TOP-LEVEL bundle fields are ignored (protobuf leniency --
  the compatible choice for a v0.3-shaped bundle); every CONSUMED
  field is strictly validated.

Coded refusal reasons (machine ``reason`` on ``EnvelopeError``; these
are bundle-scoped codes, not taxonomy decision codes -- the evidence
modules do not register in ``gov/decision_codes.py``, so the taxonomy
pin is untouched):

- ``evidence-bundle-malformed`` -- bundle/envelope/token shape
  violations (bad mediaType, bad base64, missing fields, bad token
  shape, non-numeric time, missing validity window).
- ``evidence-bundle-verification-material`` -- verificationMaterial is
  not the Bundle v0.3 form-(1) shape: missing ``publicKey``, or unknown
  fields inside ``publicKey`` (``PublicKeyIdentifier`` has only
  ``hint``), or a non-string hint. Unknown fields are refused because
  strict protobuf-JSON parsers reject them.
- ``evidence-bundle-hint-mismatch`` -- the hint is neither empty nor
  the authenticated primary key's fingerprint: it names a key that did
  not authenticate this bundle.
- ``evidence-bundle-signature-invalid`` -- DSSE threshold not met, or
  no pinned verifier authenticates the primary signature (the witness
  binding cannot be checked fail-closed).
- ``evidence-bundle-payload-type-refused`` -- envelope payloadType is
  not ``application/vnd.in-toto+json``.
- ``evidence-bundle-predicate-refused`` -- statement ``_type`` /
  ``predicateType`` / predicate shape rejected (always-on content
  check).
- ``evidence-bundle-subject-mismatch`` -- statement subject digest
  does not match the caller's expected bundle bytes.
- ``evidence-bundle-witness-missing`` -- no witness entry.
- ``evidence-bundle-witness-unsupported`` -- not exactly one entry, or
  an unknown witness kind/version.
- ``evidence-bundle-witness-unbound`` -- the entry's body or logId does
  not bind this bundle's artifact/signature/key.
- ``evidence-bundle-witness-signature-invalid`` -- the SET does not
  verify against the pinned witness verifier.
- ``evidence-bundle-witness-expired`` -- integratedTime outside the
  pinned validity window.
- ``evidence-bundle-witness-key-unavailable`` -- the witness verifier
  does not expose its public key (required for the logId binding;
  key-remote witness verifiers are unsupported in this lane).
- ``evidence-bundle-witness-checkpoint-invalid`` -- the log-backed
  entry's checkpoint does not verify (bad signature, malformed
  checkpoint, or logId not naming the pinned witness key). The
  checkpoint signature is verified FIRST; tree_size/root_hash are
  parsed only from the verified checkpoint.
- ``evidence-bundle-witness-inclusion-invalid`` -- the log-backed
  entry's Merkle inclusion proof does not verify against the
  checkpoint root (or logIndex is outside the checkpoint tree_size).

Residuals (NOT in this lane): RFC 3161 token cryptographic
verification (step 4, standalone verifier); the standalone CLI verifier
itself (step 4 -- do NOT build it here); multi-entry bundles.

Stdlib only. $0 spend. Synthetic/local testing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time

from gov import dsse_envelope as _dsse
from gov import evidence_dsse as _edsse
from gov import evidence_intoto as _intoto
from gov import sigstore_bundle as _sigbundle
from gov import witness_log as _witness_log

__all__ = [
    "SIGSTORE_BUNDLE_MEDIA_TYPE",
    "WITNESS_KIND",
    "WITNESS_KIND_VERSION",
    "WITNESS_API_VERSION",
    "seal_sigstore_bundle",
    "open_sigstore_bundle",
]

#: Pinned Sigstore Bundle media type (v0.3 protobuf JSON contract).
SIGSTORE_BUNDLE_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.bundle.v0.3+json")

#: Our witness entry kind (Rekor-pattern, local witness key).
WITNESS_KIND = "sasanam-witness"
WITNESS_KIND_VERSION = "0.0.1"
WITNESS_API_VERSION = "0.0.1"

_ED25519_KEY_DETAILS = "PKIX_ED25519"


def _refuse(code, detail):
    raise _dsse.EnvelopeError("%s: %s" % (code, detail), code=code)


def _malformed(detail):
    _refuse("evidence-bundle-malformed", detail)


# int64-as-string fields (logIndex, integratedTime) arrive as
# hostile-bundle strings. ``str.isdigit()`` is the wrong gate twice
# over: it admits non-ASCII digits (e.g. "²") that ``int()`` rejects,
# and it admits arbitrarily long runs -- a >4300-digit string passes
# the gate and ``int()`` raises the digit-limit ``ValueError`` bare,
# uncoded, escaping ``open_sigstore_bundle()`` (F416). Parse with an
# ASCII-only, length-bounded check so the conversion is TOTAL: it can
# only return an int or refuse coded ``evidence-bundle-malformed``;
# a bare ``ValueError`` can never escape.
_INT64_AS_STRING_MAX_CHARS = 20  # int64 max is 19 digits; 20 keeps headroom
_INT64_MAX = (1 << 63) - 1


def _parse_int64_as_string(value, field):
    """Total parser for int64-as-string bundle fields (F416).

    Refuses coded ``evidence-bundle-malformed`` on anything that is not
    a short ASCII digit string: non-str, empty, non-ASCII digits, or a
    digit run longer than ``_INT64_AS_STRING_MAX_CHARS`` (the
    digit-limit DoS shape). Never raises bare ``ValueError``.
    """
    if not isinstance(value, str) or not value:
        _malformed("%s must be a non-empty int64-as-string" % field)
    if (len(value) > _INT64_AS_STRING_MAX_CHARS
            or not all("0" <= ch <= "9" for ch in value)):
        _malformed(
            "%s must be a short ASCII int64-as-string (at most %d "
            "digits), got %d chars" % (field, _INT64_AS_STRING_MAX_CHARS,
                                       len(value)))
    n = int(value)  # total here: bounded ASCII digits cannot fail int()
    if n > _INT64_MAX:
        _malformed("%s %d exceeds int64 range" % (field, n))
    return n


def _b64_decode(value, where):
    if not isinstance(value, str):
        _malformed("%s: must be a base64 str, got %s"
                   % (where, type(value).__name__))
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        _malformed("%s: invalid base64: %s" % (where, exc))


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _check_signers(signers, witness_signer):
    signers = list(signers)
    if not signers:
        _malformed("seal_sigstore_bundle requires at least one signer")
    for signer in signers:
        pub = getattr(signer, "public_key", None)
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            _malformed("signer public_key must be 32 bytes")
    pub = getattr(witness_signer, "public_key", None)
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        _malformed("witness_signer public_key must be 32 bytes")
    return signers


def _check_token(rfc3161_token):
    if rfc3161_token is None:
        return []
    tokens = (list(rfc3161_token) if isinstance(rfc3161_token, (list, tuple))
              else [rfc3161_token])
    if not tokens:
        _malformed("rfc3161_token must be non-empty bytes when given")
    for tok in tokens:
        if not isinstance(tok, (bytes, bytearray)) or not tok:
            _malformed("rfc3161_token entries must be non-empty bytes")
    return [bytes(t) for t in tokens]


def _check_integrated_time(integrated_time):
    if integrated_time is None:
        return int(time.time())
    if (isinstance(integrated_time, bool)
            or not isinstance(integrated_time, int)
            or integrated_time < 0):
        _malformed("integrated_time must be a non-negative int unix time")
    return integrated_time


def _witness_body(payload_bytes, wire_signatures, primary_pub):
    """The canonical body the witness SET covers (CVE-2026-22703:
    artifact digest + exact wire signatures + primary key)."""
    return {
        "apiVersion": WITNESS_API_VERSION,
        "kind": WITNESS_KIND,
        "spec": {
            "artifactDigest": hashlib.sha256(payload_bytes).hexdigest(),
            "signatures": wire_signatures,
            "publicKey": {
                "rawBytes": base64.b64encode(
                    bytes(primary_pub)).decode("ascii"),
                "keyDetails": _ED25519_KEY_DETAILS,
            },
        },
    }


def seal_sigstore_bundle(statement_envelope, signers, witness_signer,
                         *, rfc3161_token=None, integrated_time=None,
                         witness_log=None):
    """Wrap a sealed in-toto statement envelope in a Sigstore bundle.

    ``statement_envelope`` is the native DSSE envelope dict from
    :func:`gov.evidence_intoto.seal_statement` (hex sigs); the bundle
    carries it in the Sigstore protobuf JSON shape (base64 sigs).
    ``signers`` are the DSSE signers (``signers[0]`` is the primary
    interop key recorded in ``verificationMaterial``); ``witness_signer``
    issues the witness SET. ``rfc3161_token`` (bytes or list of bytes)
    is carried, not verified. ``integrated_time`` pins the witness
    clock (default: now).

    ``witness_log`` (a ``gov.witness_log.WitnessLog``) selects the
    log-backed witness path (wave-312): the entry's canonical body is
    appended to the real log, ``logIndex`` is the real tree position,
    and the entry carries an ``inclusionProof`` (signed checkpoint +
    Merkle audit path) backed by real tree state. Without it, the
    entry keeps the offline-fallback shape (``logIndex: "0"``, SET
    only) -- the bundle verifies either way.

    The envelope is strict-parsed and its payloadType + statement shape
    are checked BEFORE anything is emitted: a malformed statement is
    never distributed. Returns the bundle dict.
    """
    signers = _check_signers(signers, witness_signer)
    tokens = _check_token(rfc3161_token)
    integrated_time = _check_integrated_time(integrated_time)
    if witness_log is not None and not isinstance(
            witness_log, _witness_log.WitnessLog):
        _malformed("witness_log must be a gov.witness_log.WitnessLog, "
                   "got %s" % type(witness_log).__name__)

    # Strict-parse the envelope: malformed input refuses here, before
    # any bundle bytes are produced.
    payload, payload_type, sig_entries = _dsse.parse_envelope(
        statement_envelope)
    if payload_type != _edsse.EVIDENCE_DSSE_PAYLOAD_TYPE:
        _malformed("statement_envelope payloadType %r is not %r"
                   % (payload_type, _edsse.EVIDENCE_DSSE_PAYLOAD_TYPE))
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _malformed("statement payload is not valid JSON: %s" % exc)
    if not isinstance(statement, dict):
        _malformed("statement payload must be a JSON object")
    if statement.get("_type") != _intoto.INTOTO_STATEMENT_TYPE:
        _malformed("statement _type %r is not the in-toto v1 statement"
                   % (statement.get("_type"),))
    if (statement.get("predicateType")
            != _intoto.SASANAM_EVIDENCE_PREDICATE_TYPE):
        _malformed("statement predicateType %r is not ours"
                   % (statement.get("predicateType"),))

    # Sigstore protobuf JSON wire form: base64 sigs (the interop
    # surface cosign parses), keyid carried as the hint.
    wire_signatures = []
    for keyid, sig in sig_entries:
        entry = {}
        if keyid is not None:
            entry["keyid"] = keyid
        entry["sig"] = base64.b64encode(bytes(sig)).decode("ascii")
        wire_signatures.append(entry)

    primary_pub = bytes(signers[0].public_key)
    body = _witness_body(payload, wire_signatures, primary_pub)
    canonical = _canonical_json(body)
    witness_pub = bytes(witness_signer.public_key)
    try:
        set_sig = witness_signer.sign(canonical)
    except _dsse.EnvelopeError:
        raise
    except Exception as exc:
        _malformed("witness signer failed: %s" % (exc,))
    if not isinstance(set_sig, (bytes, bytearray)) or not set_sig:
        _malformed("witness signer returned empty/non-bytes")

    witness_entry = {
        "logId": {"keyId": base64.b64encode(
            hashlib.sha256(witness_pub).digest()).decode("ascii")},
        "kindVersion": {"kind": WITNESS_KIND,
                        "version": WITNESS_KIND_VERSION},
        "integratedTime": str(integrated_time),
        "inclusionPromise": {"signedEntryTimestamp": base64.b64encode(
            bytes(set_sig)).decode("ascii")},
        "canonicalizedBody": base64.b64encode(canonical).decode("ascii"),
    }
    if witness_log is not None:
        # Log-backed path: the entry is really in the tree. logIndex
        # is the true position; the inclusionProof binds it to a
        # signed checkpoint (checkpoint signature verified FIRST by
        # the verifier, sizes/hashes only from the checkpoint).
        try:
            log_index = witness_log.append(canonical)
            sealed_cp = witness_log.sealed_checkpoint(integrated_time,
                                                      witness_signer)
            proof = witness_log.inclusion_proof(log_index)
        except _witness_log.WitnessError as exc:
            _malformed("witness log failed: [%s] %s"
                       % (exc.code, exc.detail))
        witness_entry["logIndex"] = str(log_index)
        witness_entry["inclusionProof"] = {
            "checkpoint": sealed_cp["checkpoint"],
            "checkpointSignature": sealed_cp["signature"],
            "auditPath": proof["path"],
        }
    else:
        # Offline fallback: entry shape only, no tree behind it.
        witness_entry["logIndex"] = "0"

    verification_material = {
        # Bundle v0.3 form (1): PublicKeyIdentifier carries ONLY hint.
        # The raw key travels out-of-band, pinned by the auditor (the
        # open caller's verifier set); the witness binding resolves the
        # primary key from that set (see _resolve_primary_key), never
        # from an in-band bundle field. A strict protobuf-JSON parser
        # rejects unknown fields inside PublicKeyIdentifier, so embedding
        # rawBytes here would fork our wire shape from the interop shape
        # (wave-329: fixed from the wave-311 {"rawBytes","keyDetails"}
        # deviation documented in gov/sigstore_bundle.py).
        "publicKey": {"hint": _sigbundle.key_hint(primary_pub)},
        "tlogEntries": [witness_entry],
    }
    if tokens:
        verification_material["timestampVerificationData"] = {
            "rfc3161Timestamps": [
                {"signedTimestamp": base64.b64encode(t).decode("ascii")}
                for t in tokens
            ],
        }

    return {
        "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
        "verificationMaterial": verification_material,
        "dsseEnvelope": {
            "payload": base64.b64encode(bytes(payload)).decode("ascii"),
            "payloadType": payload_type,
            "signatures": wire_signatures,
        },
    }


def _coerce_bundle(bundle):
    # The wire journey is bytes; parse exactly once.
    if isinstance(bundle, (bytes, bytearray)):
        try:
            bundle = json.loads(bytes(bundle).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            _malformed("bundle bytes are not valid JSON: %s" % exc)
    if not isinstance(bundle, dict):
        _malformed("bundle must be a JSON object, got %s"
                   % type(bundle).__name__)
    return bundle


def _parse_bundle(bundle):
    """Parse stage: mediaType pin, envelope extraction, witness/token
    staging. Returns (native_envelope, wire_envelope, payload_bytes,
    verification_material, witness_entries, rfc3161_tokens)."""
    bundle = _coerce_bundle(bundle)
    if bundle.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        _malformed("bundle mediaType %r is not %r"
                   % (bundle.get("mediaType"), SIGSTORE_BUNDLE_MEDIA_TYPE))

    wire = bundle.get("dsseEnvelope")
    if not isinstance(wire, dict):
        _malformed("dsseEnvelope must be an object")
    for field in ("payload", "payloadType", "signatures"):
        if field not in wire:
            _malformed("dsseEnvelope missing field %r" % field)
    payload_type = wire["payloadType"]
    if not isinstance(payload_type, str) or not payload_type:
        _malformed("dsseEnvelope.payloadType must be a non-empty str")
    payload_bytes = _b64_decode(wire["payload"], "dsseEnvelope.payload")
    if not isinstance(wire["signatures"], list) or not wire["signatures"]:
        _malformed("dsseEnvelope.signatures must be a non-empty list")
    wire_signatures = []
    for i, entry in enumerate(wire["signatures"]):
        where = "dsseEnvelope.signatures[%d]" % i
        if not isinstance(entry, dict):
            _malformed("%s: must be an object" % where)
        sig = _b64_decode(entry.get("sig"), where + ".sig")
        if len(sig) != 64:
            _malformed("%s.sig: Ed25519 signatures are 64 bytes, got %d"
                       % (where, len(sig)))
        keyid = entry.get("keyid")
        if keyid is not None and (not isinstance(keyid, str) or not keyid):
            _malformed("%s.keyid: must be a non-empty str when present"
                       % where)
        wire_signatures.append({"keyid": keyid, "sig": sig})

    # Rebuild the NATIVE envelope dict (hex sigs) for the DSSE layer.
    # The payload base64 string passes through untouched; the verified
    # payload bytes below come out of the layer's single parse.
    native_signatures = []
    for e in wire_signatures:
        sig_dict = {"sig": bytes(e["sig"]).hex()}
        if e["keyid"] is not None:
            sig_dict["keyid"] = e["keyid"]
        native_signatures.append(sig_dict)
    native = {
        "payload": wire["payload"],
        "payloadType": payload_type,
        "signatures": native_signatures,
    }

    vm = bundle.get("verificationMaterial")
    if not isinstance(vm, dict):
        _malformed("verificationMaterial must be an object")
    entries = vm.get("tlogEntries")
    if not isinstance(entries, list):
        _malformed("verificationMaterial.tlogEntries must be a list")

    tokens = []
    tvd = vm.get("timestampVerificationData")
    if tvd is not None:
        if not isinstance(tvd, dict):
            _malformed("timestampVerificationData must be an object")
        stamps = tvd.get("rfc3161Timestamps", [])
        if not isinstance(stamps, list):
            _malformed("rfc3161Timestamps must be a list")
        for i, stamp in enumerate(stamps):
            where = "rfc3161Timestamps[%d]" % i
            if not isinstance(stamp, dict):
                _refuse("evidence-bundle-timestamp-malformed",
                        "%s: must be an object" % where)
            try:
                raw = _b64_decode(stamp.get("signedTimestamp"),
                                  where + ".signedTimestamp")
            except _dsse.EnvelopeError as exc:
                # The failure is in the timestamp carrier specifically,
                # not the bundle core: name it.
                raise _dsse.EnvelopeError(
                    "evidence-bundle-timestamp-malformed: %s" % exc,
                    code="evidence-bundle-timestamp-malformed")
            if not raw:
                _refuse("evidence-bundle-timestamp-malformed",
                        "%s.signedTimestamp: empty token refused" % where)
            tokens.append(raw)

    return native, wire_signatures, payload_bytes, vm, entries, tokens


def _classify_statement_error(exc):
    """Map the statement layer's refusal onto a bundle-scoped code.

    Deliberate, tested coupling: ``gov.evidence_intoto`` raises plain
    ``EnvelopeError`` messages; the bundle verifier surfaces them under
    its own DepGuard-shaped taxonomy (parse -> crypto -> unsupported ->
    consistency). The mapping is pinned by the break-first probes.
    """
    msg = str(exc)
    if "payloadType mismatch" in msg:
        return "evidence-bundle-payload-type-refused"
    if "signature threshold not met" in msg:
        return "evidence-bundle-signature-invalid"
    if "empty payload refused" in msg:
        return "evidence-bundle-malformed"
    if ("unsupported statement _type" in msg
            or "unsupported predicateType" in msg
            or "statement subject must be" in msg
            or "subject[0].digest.sha256" in msg
            or "statement predicate must be" in msg
            or "statement payload is not valid JSON" in msg):
        return "evidence-bundle-predicate-refused"
    if "subject digest mismatch" in msg:
        return "evidence-bundle-subject-mismatch"
    return "evidence-bundle-malformed"


def _open_statement(native_envelope, expected_bundle_bytes, verifiers,
                    threshold):
    try:
        return _intoto.open_statement(native_envelope,
                                      expected_bundle_bytes,
                                      verifiers, threshold)
    except _dsse.EnvelopeError as exc:
        code = _classify_statement_error(exc)
        raise _dsse.EnvelopeError("%s: %s" % (code, exc),
                                  code=code)


def _verify_witness_checkpoint(entry, witness_pub):
    """Verify the entry's log-backed checkpoint signature (F416).

    Checkpoint-first: the checkpoint signature is verified against the
    pinned witness key BEFORE anything is parsed; tree_size/root_hash
    come ONLY from the verified checkpoint (sigstore-python#248 --
    never from the proof envelope or the entry). Called before
    integratedTime/logIndex are converted, so a hostile bundle's
    garbage index hits the witness refusal first when the checkpoint
    is forged. Refuses coded; returns (tree_size, root_hash_hex).
    """
    ip = entry.get("inclusionProof")
    if not isinstance(ip, dict):
        _malformed("tlogEntries[0].inclusionProof must be an object")
    try:
        cp = _witness_log.verify_checkpoint(
            {"checkpoint": ip.get("checkpoint"),
             "signature": ip.get("checkpointSignature")},
            witness_pub)
    except _witness_log.WitnessError as exc:
        _refuse("evidence-bundle-witness-checkpoint-invalid",
                "log checkpoint rejected: [%s] %s" % (exc.code,
                                                     exc.detail))
    return cp["treeSize"], cp["rootHash"]


def _verify_witness_inclusion(entry, leaf_bytes, log_index, tree_size,
                             root_hash_hex):
    """Range-check log_index against the verified tree_size and verify
    the Merkle audit path (F416). Called only after log_index has been
    converted by the TOTAL bounded parser. Refuses coded; returns
    (tree_size, root_hash_hex).
    """
    root_hash = bytes.fromhex(root_hash_hex)  # hex-validated by verify_checkpoint
    if not 0 <= log_index < tree_size:
        _refuse("evidence-bundle-witness-inclusion-invalid",
                "logIndex %d outside checkpoint tree_size %d"
                % (log_index, tree_size))
    ip = entry.get("inclusionProof")
    try:
        _witness_log.verify_inclusion(leaf_bytes, log_index,
                                     ip.get("auditPath"), tree_size,
                                     root_hash)
    except _witness_log.WitnessError as exc:
        _refuse("evidence-bundle-witness-inclusion-invalid",
                "inclusion proof rejected: [%s] %s" % (exc.code,
                                                      exc.detail))
    return tree_size, root_hash_hex


def _resolve_primary_key(native_envelope, payload_bytes, verifiers):
    """Return the 32-byte key that authenticated the FIRST envelope signature.

    The witness entry binds the primary (signers[0] at seal) key. The
    bundle no longer names that key in-band -- Bundle v0.3 form (1)
    carries only the hint -- so it is resolved from the caller-pinned
    verifier set: the key that actually verified signatures[0]. This is
    strictly stronger than trusting an in-band value: the binding is to
    the authenticated key. Refuses coded
    ``evidence-bundle-signature-invalid`` when no pinned verifier
    authenticates the primary signature (fail-closed: an unresolvable
    primary means the witness binding cannot be checked).
    """
    sigs = native_envelope.get("signatures") or []
    if not sigs:
        _malformed("envelope carries no signatures")
    first = sigs[0]
    try:
        first_sig = bytes.fromhex(first["sig"])
    except (ValueError, TypeError, KeyError, AttributeError):
        _malformed("primary signature is not hex")
    first_kid = first.get("keyid")
    payload_type = native_envelope.get("payloadType")
    if not isinstance(payload_type, str) or not payload_type:
        _malformed("envelope payloadType missing")
    pae_bytes = _dsse.pae(payload_type, payload_bytes)
    cands = list(verifiers)
    # keyid narrows the search (unauthenticated hint); a misconfigured
    # keyid falls back to try-all -- authentication is never weakened.
    narrowed = [v for v in cands
                if first_kid is None
                or getattr(v, "key_id", None) == first_kid]
    ordered = narrowed + [v for v in cands if v not in narrowed]
    for verifier in ordered:
        pub = getattr(verifier, "public_key", None)
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            continue
        try:
            ok = verifier.verify(pae_bytes, first_sig)
        except Exception:  # noqa: BLE001
            continue
        if ok is True:
            return bytes(pub)
    _refuse("evidence-bundle-signature-invalid",
            "no pinned verifier authenticates the primary signature")


def _check_verification_material(vm, primary_pub):
    """Enforce the Bundle v0.3 form-(1) shape on verificationMaterial.

    ``publicKey`` must be a PublicKeyIdentifier: the ``hint`` field
    ONLY. Unknown fields are refused -- strict protobuf-JSON parsers
    (protojson default, as sigstore-go/cosign use) reject them, so
    accepting them would fork our wire shape from the interop shape.
    The hint is informational, never authority: empty (the spike-proven
    cosign ``{"publicKey": {}}`` shape) or the authenticated primary
    key's fingerprint. Anything else names a key that did not
    authenticate this bundle.
    """
    pk = vm.get("publicKey") if isinstance(vm, dict) else None
    if not isinstance(pk, dict):
        _refuse("evidence-bundle-verification-material",
                "verificationMaterial.publicKey must be an object "
                "(Bundle v0.3 form (1): PublicKeyIdentifier)")
    unknown = set(pk) - {"hint"}
    if unknown:
        _refuse("evidence-bundle-verification-material",
                "verificationMaterial.publicKey carries unknown fields %s "
                "(PublicKeyIdentifier has only 'hint')" % sorted(unknown))
    hint = pk.get("hint", "")
    if not isinstance(hint, str):
        _refuse("evidence-bundle-verification-material",
                "verificationMaterial.publicKey.hint must be a string")
    if hint not in ("", _sigbundle.key_hint(primary_pub)):
        _refuse("evidence-bundle-hint-mismatch",
                "hint does not name the authenticated primary key")


def _check_witness(entries, wire_signatures, payload_bytes, primary_pub,
                   witness_verifier, witness_validity):
    """Witness stage: exactly one entry of our kind, body bound to this
    bundle's artifact/signature/key, SET verified, time window honored.

    Order (F416): the witness SET -- logId binding, body binding, SET
    signature -- is verified BEFORE integratedTime/logIndex are
    converted or trusted. A hostile bundle's garbage time/index fields
    hit the witness refusal first; the conversions below are TOTAL
    (bounded ASCII digit parse, coded evidence-bundle-malformed), so a
    bare ValueError can never escape at any point.
    """
    if not entries:
        _refuse("evidence-bundle-witness-missing",
                "bundle carries no witness entry")
    if len(entries) != 1:
        _refuse("evidence-bundle-witness-unsupported",
                "this lane supports exactly one witness entry, got %d"
                % len(entries))
    entry = entries[0]
    if not isinstance(entry, dict):
        _malformed("tlogEntries[0] must be an object")

    kind_version = entry.get("kindVersion")
    if (not isinstance(kind_version, dict)
            or kind_version.get("kind") != WITNESS_KIND
            or kind_version.get("version") != WITNESS_KIND_VERSION):
        _refuse("evidence-bundle-witness-unsupported",
                "witness kind %r is not %s/%s"
                % (kind_version, WITNESS_KIND, WITNESS_KIND_VERSION))

    # The witness verifier must name its key: the logId binding needs
    # the raw public key (key-remote witness verifiers unsupported).
    witness_pub = getattr(witness_verifier, "public_key", None)
    if (not isinstance(witness_pub, (bytes, bytearray))
            or len(witness_pub) != 32):
        _refuse("evidence-bundle-witness-key-unavailable",
                "witness verifier does not expose its 32-byte public key")
    witness_pub = bytes(witness_pub)

    log_id = entry.get("logId")
    if not isinstance(log_id, dict):
        _malformed("tlogEntries[0].logId must be an object")
    got_key_id = _b64_decode(log_id.get("keyId"), "tlogEntries[0].logId.keyId")
    if got_key_id != hashlib.sha256(witness_pub).digest():
        _refuse("evidence-bundle-witness-unbound",
                "logId.keyId does not name the pinned witness key")

    # Binding (CVE-2026-22703): recompute the canonical body from the
    # VERIFIED envelope fields and the AUTHENTICATED primary key, and
    # require byte-equality with the witnessed bytes. The primary key
    # is the key that verified the first envelope signature against the
    # caller-pinned set -- never an in-band bundle field (Bundle v0.3
    # form (1) carries only the hint); the SET below checks who
    # witnessed it.
    recomputed = _canonical_json(_witness_body(
        payload_bytes,
        [{"keyid": e["keyid"], "sig": base64.b64encode(e["sig"]).decode(
            "ascii")} if e["keyid"] is not None else
         {"sig": base64.b64encode(e["sig"]).decode("ascii")}
         for e in wire_signatures],
        primary_pub))
    witnessed = _b64_decode(entry.get("canonicalizedBody"),
                            "tlogEntries[0].canonicalizedBody")
    if witnessed != recomputed:
        _refuse("evidence-bundle-witness-unbound",
                "canonicalizedBody does not bind this bundle's "
                "artifact digest + signatures + key")

    # Crypto: the SET covers the witnessed (now bound) bytes. Verified
    # BEFORE integratedTime/logIndex are touched (F416): a hostile
    # bundle's garbage time/index fields hit this refusal first, never
    # the time/index conversion path.
    promise = entry.get("inclusionPromise")
    if not isinstance(promise, dict):
        _malformed("tlogEntries[0].inclusionPromise must be an object")
    set_sig = _b64_decode(promise.get("signedEntryTimestamp"),
                          "tlogEntries[0].inclusionPromise."
                          "signedEntryTimestamp")
    if witness_verifier.verify(witnessed, set_sig) is not True:
        _refuse("evidence-bundle-witness-signature-invalid",
                "witness SET does not verify against the pinned key")

    # Log-backed path, checkpoint-first (F416(b)): the checkpoint
    # signature is verified BEFORE logIndex/integratedTime are converted
    # -- a hostile bundle's garbage index hits the witness refusal first
    # when the checkpoint is forged. The Merkle range/path checks run
    # after the TOTAL parse below, once log_index is a trusted int.
    checkpoint = None
    if entry.get("inclusionProof") is not None:
        checkpoint = _verify_witness_checkpoint(entry, witness_pub)

    # Only now are the time/index fields converted -- with a TOTAL
    # bounded parser (F416): ASCII digits only, length-bounded before
    # int(), coded evidence-bundle-malformed on anything else. The old
    # isdigit()-then-int() shape admitted >4300-digit strings (bare
    # digit-limit ValueError) and non-ASCII digits (F415 class).
    log_index_raw = entry.get("logIndex")
    log_index = _parse_int64_as_string(
        log_index_raw, "tlogEntries[0].logIndex")
    integrated_time = _parse_int64_as_string(
        entry.get("integratedTime"),
        "tlogEntries[0].integratedTime")

    # The time window is checked against the pinned validity range only
    # after the SET authenticated the entry (F416): the time is not
    # trusted until the witness is. This deliberately moves the old
    # pre-crypto window check (CVE-2026-24122 analogue) -- the SET must
    # verify first so hostile garbage fields hit the witness refusal,
    # not the time path. The bounded parse above still fails fast and
    # coded on garbage, before any Merkle work below.
    not_before, not_after = witness_validity
    if not (not_before <= integrated_time <= not_after):
        _refuse("evidence-bundle-witness-expired",
                "integratedTime %d outside pinned validity window "
                "[%d, %d]" % (integrated_time, not_before, not_after))

    witness_info = {
        "log_index": log_index_raw,
        "integrated_time": integrated_time,
        "time_source": "sealer host clock (time.time) at seal",
        "validity_window": (not_before, not_after),
        "witness_key_id": hashlib.sha256(witness_pub).hexdigest()[:16],
    }

    # Log-backed path: the Merkle range/path checks run on top of the
    # already-verified checkpoint (signature verified above, before the
    # parse) and the now-trusted log_index int. The offline fallback has
    # no proof and verifies exactly as before.
    if checkpoint is not None:
        tree_size, root_hash = _verify_witness_inclusion(
            entry, witnessed, log_index, checkpoint[0], checkpoint[1])
        witness_info["log_backed"] = True
        witness_info["tree_size"] = tree_size
        witness_info["root_hash"] = root_hash
    else:
        witness_info["log_backed"] = False

    return witness_info


def open_sigstore_bundle(bundle, expected_bundle_bytes, verifiers,
                         witness_verifier, *, threshold=1,
                         witness_validity=None):
    """Verify a Sigstore bundle and return the verified statement.

    Stages, in order (DepGuard-shaped: parse -> crypto/content ->
    witness -> token): strict single bundle parse; the sealed statement
    is opened through ``gov.evidence_intoto`` (payloadType binding,
    threshold DSSE signatures over the exact payload bytes, always-on
    statement shape / predicateType / subject-digest checks);
    the witness entry is bound to this bundle's artifact digest +
    signatures + key and its SET verified against ``witness_verifier``
    with ``integratedTime`` inside the REQUIRED ``witness_validity``
    ``(not_before, not_after)`` window; RFC 3161 tokens are
    well-formedness-checked and reported, not cryptographically
    verified.

    Returns ``{"statement", "payload", "payload_sha256", "key_ids",
    "witness", "rfc3161_present"}`` -- the envelope's own verified
    bytes throughout. Raises coded ``EnvelopeError`` loudly on any
    violation; nothing unverified escapes.
    """
    verifiers = list(verifiers)
    if not verifiers:
        _malformed("open_sigstore_bundle requires at least one verifier")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or threshold < 1):
        _malformed("threshold must be a positive int")
    if witness_validity is None:
        _malformed("witness_validity (not_before, not_after) is required: "
                   "without a pinned window the witness time cannot be "
                   "checked")
    try:
        not_before, not_after = witness_validity
    except (TypeError, ValueError):
        _malformed("witness_validity must be a (not_before, not_after) "
                   "pair of unix times")
    for bound in (not_before, not_after):
        if (isinstance(bound, bool) or not isinstance(bound, int)
                or bound < 0):
            _malformed("witness_validity bounds must be non-negative ints")
    if not_before > not_after:
        _malformed("witness_validity: not_before > not_after")

    (native_envelope, wire_signatures, payload_bytes, vm,
     entries, tokens) = _parse_bundle(bundle)

    # Crypto + always-on content checks, delegated to the statement
    # layer (failures re-coded into the bundle taxonomy).
    statement = _open_statement(native_envelope, expected_bundle_bytes,
                                verifiers, threshold)

    # Primary key: the pinned key that authenticated the first envelope
    # signature (signers[0] at seal). Resolved AFTER the threshold
    # passed, so the witness binds the authenticated key, never an
    # in-band claim.
    primary_pub = _resolve_primary_key(native_envelope, payload_bytes,
                                       verifiers)

    # Bundle v0.3 form-(1) verificationMaterial: spec-shape, interop.
    _check_verification_material(vm, primary_pub)

    # Witness stage: binding, time window, SET.
    witness_info = _check_witness(entries, wire_signatures, payload_bytes,
                                  primary_pub, witness_verifier,
                                  (not_before, not_after))

    # key_ids: which verifier keys actually signed (recomputed here so
    # the caller gets them without re-parsing; the threshold already
    # passed above).
    payload_type = native_envelope["payloadType"]
    pae_bytes = _dsse.pae(payload_type, payload_bytes)
    key_ids = set()
    for entry in native_envelope["signatures"]:
        kid = entry.get("keyid")
        sig = bytes.fromhex(entry["sig"])
        for verifier in verifiers:
            if kid is not None and verifier.key_id != kid:
                continue
            if verifier.verify(pae_bytes, sig) is True:
                key_ids.add(verifier.key_id)

    return {
        "statement": statement,
        "payload": payload_bytes,
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "key_ids": sorted(key_ids),
        "witness": witness_info,
        "rfc3161_present": bool(tokens),
    }
