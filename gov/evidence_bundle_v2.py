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
    the ``evbundle`` decision-code domain; ``detail`` is human text."""

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
                         verify_time):
    """Verify the three-artifact split. Order: shape, artifact
    self-consistency, attestation joins, cert join + full ceremony
    re-verification (``evcert-*`` failures propagate -- the signature
    is NEVER taken on trust), issuance join against the audit log.

    Any cross-artifact digest disagreement is
    ``evbundle-join-mismatch``; certificate failures surface as
    ``evcert-*``; a missing/broken issuance attestation is
    ``evbundle-issuance-unverifiable``.
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
    return {"verified": True,
            "cert_digest": sealed["cert_digest"],
            "artifact_digest": artifact["artifact_digest"],
            "issuance_seq": issuance.get("seq"),
            "honest_claims": _HONEST_CLAIMS}


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
                      verify_time, transparency_log):
    """Verify a v2 submission end to end: the three-artifact split,
    then the transparency receipt against the log."""
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
    verified = verify_sealed_bundle(sealed=sealed,
                                    audit_log_path=audit_log_path,
                                    ca_public_key=ca_public_key,
                                    verify_time=verify_time)
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
    return {"verified": True,
            "cert_digest": verified["cert_digest"],
            "artifact_digest": verified["artifact_digest"],
            "tree_size": checkpoint["tree_size"],
            "honest_claims": _HONEST_CLAIMS}
