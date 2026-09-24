"""Capability gate: bind the executor's run path to a sealed capability assessment.

The safeguard benchmark (gov/safeguard_benchmark.py) renders sealed
SUFFICIENT / INSUFFICIENT assessments of a deployment's governance
posture, and the capability harness (gov/capability_measure.py) owns a
human-review gate -- but no production runtime path consults either
before running agents. An unwired gate is a false safety story: the
benchmark grades governance while the runtime never asks.

This module is the wiring contract:

* A deployment declares a **binding**: which harness it was assessed
  against (``harness_id``), the digest of the exact harness/thresholds
  config the assessment was computed against (``harness_digest``), how
  fresh an assessment must be (``freshness_seconds``), and which Ed25519
  keys may seal assessments (``trusted_keys``). A seal is ALWAYS
  required: there is no unsealed mode, because an unsealed mode would
  let a flipped-verdict + recomputed-digest forgery pass.
* The deployment presents an **assessment record**: the rendered report
  plus its sealed manifest (``report`` / ``manifest``). The manifest
  carries ``harness_id``, ``harness_config_digest``, ``assessed_at``,
  ``report_id``, ``export_sha256`` (sha256 of the canonical report
  bytes), and an Ed25519 ``signing`` block over the canonical manifest
  minus the signing block -- the same Ed25519 primitive and
  canonicalization the benchmark's ``SafeguardAssessment`` uses. Note
  the honest boundary: benchmark manifests do not carry ``harness_id``
  / ``harness_config_digest`` / ``assessed_at``, and the benchmark's
  sign bytes additionally exclude a post-seal ``receipt`` -- so a raw
  benchmark-sealed record is REFUSED here (missing harness binding),
  not verified. The supported minting path is :func:`seal_assessment`,
  which produces interoperable records carrying everything the gate
  checks.
* :func:`verify_assessment` enforces the gate fail-closed, in order:
  assessment present -> harness id matches -> config digest matches
  (stale config refused) -> assessed_at within freshness and not in the
  future -> manifest digest recomputed from the report (content forgery
  refused) -> Ed25519 seal verifies against a trusted key -- the seal
  is mandatory, there is no unsealed mode (a flipped verdict with a
  recomputed digest is refused here: the seal cannot be re-minted
  without the key) -> report verdict reads SUFFICIENT (the verdict is
  read only after integrity is established).

Every refusal raises :class:`CapabilityGateRefusal` carrying a
machine-readable ``refusal_cause``; the executor chains it into the
audit log before re-raising. Malformed bindings / assessments are
refused fail-closed -- never treated as "no gate" or "valid".

$0 spend, synthetic/local only. No network.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping

from .signing import Ed25519Verifier


class CapabilityGateError(Exception):
    """Base: any capability-gate failure. Fail-closed."""


class CapabilityGateBindingError(CapabilityGateError):
    """Construction-time: the deployment looks governed but declares no
    usable capability gate (no binding and no valid ungoverned
    acknowledgement), or the binding itself is malformed/contradictory.
    The message always names both remedies."""


class CapabilityGateRefusal(CapabilityGateError):
    """Run-time: a presented assessment failed verification. Carries
    the machine-readable ``refusal_cause`` for the audit event."""

    def __init__(self, refusal_cause, message):
        super().__init__(message)
        self.refusal_cause = refusal_cause


#: Refusal causes emitted by verify_assessment (stable strings; the
#: audit log and the break-first battery key on these).
REFUSAL_MISSING = "capability_assessment_missing"
REFUSAL_HARNESS_ID = "harness_id_mismatch"
REFUSAL_CONFIG_DIGEST = "harness_config_digest_mismatch"
REFUSAL_EXPIRED = "capability_assessment_expired"
REFUSAL_FUTURE = "assessment_from_future"
REFUSAL_REPORT_DIGEST = "assessment_report_digest_mismatch"
REFUSAL_UNSEALED = "assessment_unsealed"
REFUSAL_UNTRUSTED_KEY = "assessment_untrusted_key"
REFUSAL_BAD_SIGNATURE = "assessment_signature_invalid"
REFUSAL_INSUFFICIENT = "capability_assessment_insufficient"
REFUSAL_MALFORMED = "assessment_malformed"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def compute_harness_digest(harness_id, thresholds, schema_version):
    """Digest of the exact harness/thresholds config an assessment was
    computed against. The binding pins this; an assessment minted under
    different thresholds (or a different schema version) carries a
    different digest and is refused as stale. ``thresholds`` must be
    JSON-canonicalizable (plain dicts/lists/str/num/bool)."""
    if not isinstance(harness_id, str) or not harness_id:
        raise CapabilityGateError(
            "harness_id must be a non-empty string")
    try:
        body = _canonical({
            "harness_id": harness_id,
            "schema_version": schema_version,
            "thresholds": thresholds,
        })
    except (TypeError, ValueError) as e:
        raise CapabilityGateError(
            "thresholds are not JSON-canonicalizable: %s" % (e,))
    return hashlib.sha256(body).hexdigest()


def _coerce_pubkey(key_id, value):
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str):
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            raise CapabilityGateError(
                "trusted_keys[%r]: hex string does not decode" % (key_id,))
    else:
        raise CapabilityGateError(
            "trusted_keys[%r]: must be 32-byte Ed25519 public key "
            "(bytes or hex), got %s" % (key_id, type(value).__name__))
    if len(raw) != 32:
        raise CapabilityGateError(
            "trusted_keys[%r]: Ed25519 public key must be 32 bytes, "
            "got %d" % (key_id, len(raw)))
    return raw


def validate_binding(binding):
    """Validate a deployment's capability-gate binding fail-closed.

    Accepts a mapping with ``harness_id`` (non-empty str),
    ``harness_digest`` (64-hex sha256, optional ``sha256:`` prefix),
    ``freshness_seconds`` (positive int), and ``trusted_keys``
    (key_id -> 32-byte Ed25519 public key, bytes or hex; always
    required non-empty -- the seal is mandatory). Returns a normalized
    copy. Raises :class:`CapabilityGateBindingError` on anything
    malformed -- a malformed binding is never treated as "no gate".
    """
    if not isinstance(binding, Mapping):
        raise CapabilityGateBindingError(
            "capability_gate_binding must be a mapping, got %s"
            % type(binding).__name__)
    b = dict(binding)
    harness_id = b.get("harness_id")
    if not isinstance(harness_id, str) or not harness_id.strip():
        raise CapabilityGateBindingError(
            "capability_gate_binding['harness_id'] must be a non-empty "
            "string")
    digest = b.get("harness_digest")
    if isinstance(digest, str) and digest.startswith("sha256:"):
        digest = digest[len("sha256:"):]
    if (not isinstance(digest, str) or len(digest) != 64
            or any(c not in "0123456789abcdefABCDEF" for c in digest)):
        raise CapabilityGateBindingError(
            "capability_gate_binding['harness_digest'] must be a 64-hex "
            "sha256 digest (see compute_harness_digest)")
    freshness = b.get("freshness_seconds")
    if (isinstance(freshness, bool) or not isinstance(freshness, int)
            or freshness <= 0):
        raise CapabilityGateBindingError(
            "capability_gate_binding['freshness_seconds'] must be a "
            "positive int (max assessment age in seconds)")
    trusted = b.get("trusted_keys") or {}
    if not isinstance(trusted, Mapping):
        raise CapabilityGateBindingError(
            "capability_gate_binding['trusted_keys'] must be a mapping "
            "of key_id -> Ed25519 public key")
    trusted = {kid: _coerce_pubkey(kid, v)
               for kid, v in trusted.items()}
    if not trusted:
        raise CapabilityGateBindingError(
            "capability_gate_binding requires non-empty trusted_keys: "
            "the assessment seal is mandatory, so an unsealed-or-"
            "unverifiable assessment can never pass")
    return {
        "harness_id": harness_id,
        "harness_digest": digest.lower(),
        "freshness_seconds": freshness,
        "trusted_keys": trusted,
    }


def seal_assessment(report, *, harness_id, harness_config_digest,
                    assessed_at, signer):
    """Mint an assessment record (deployment/operator side).

    ``report`` is the rendered assessment report (a JSON-able mapping;
    the gate reads the verdict at
    ``report["sufficiency"]["aggregate_verdict"]["value"]``).
    ``signer`` is a ``gov.signing.Signer`` whose public key the
    deployment's binding trusts. Returns
    ``{"report": report, "manifest": manifest}`` with the Ed25519 seal
    over the canonical manifest minus the signing block -- the same
    primitive the benchmark uses. This is the supported minting path:
    a raw benchmark-sealed record lacks the gate's ``harness_id`` /
    ``harness_config_digest`` / ``assessed_at`` fields and is refused,
    so deployments re-seal through here (or through an adapter that
    adds the binding fields and re-seals).
    """
    if not isinstance(report, Mapping):
        raise CapabilityGateError("report must be a mapping")
    try:
        body = _canonical(report)
    except (TypeError, ValueError) as e:
        raise CapabilityGateError(
            "report is not JSON-canonicalizable: %s" % (e,))
    if (isinstance(assessed_at, bool)
            or not isinstance(assessed_at, (int, float))):
        raise CapabilityGateError("assessed_at must be epoch seconds")
    manifest = {
        "kind": "capability_assessment_manifest",
        "generator": "gov/capability_gate.py",
        "harness_id": harness_id,
        "harness_config_digest": harness_config_digest,
        "assessed_at": assessed_at,
        "report_id": (report.get("report_id") or {}).get("value"),
        "export_sha256": hashlib.sha256(body).hexdigest(),
        "signing": None,
    }
    sign_bytes = _canonical({k: v for k, v in manifest.items()
                             if k != "signing"})
    try:
        sig = signer.sign(sign_bytes)
    except Exception as e:
        raise CapabilityGateError("signer failed: %s" % (e,))
    manifest["signing"] = {
        "scheme": "ed25519",
        "key_id": getattr(signer, "key_id", None),
        "signature_hex": bytes(sig).hex(),
    }
    return {"report": dict(report), "manifest": manifest}


def _mapping_get(obj, *path):
    cur = obj
    for key in path:
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(key)
    return cur


def verify_assessment(binding, assessment, *, now=None):
    """Enforce the capability gate against one presented assessment.

    Returns ``{"allowed": True, ...}`` on success. Raises
    :class:`CapabilityGateRefusal` (with ``refusal_cause``) when the
    assessment is missing, stale, failed, forged, or malformed, and
    :class:`CapabilityGateError` when the binding itself is malformed.
    Checks run in integrity order: the verdict is read only after the
    report digest and the seal have verified, so a flipped verdict can
    never pass on a recomputed digest alone.
    """
    if now is None:
        now = time.time()
    b = validate_binding(binding)
    if assessment is None:
        raise CapabilityGateRefusal(
            REFUSAL_MISSING,
            "capability gate: no capability assessment on file -- "
            "refusing to run (bind one via capability_assessment= or "
            "acknowledge ungoverned mode explicitly)")
    if not isinstance(assessment, Mapping):
        raise CapabilityGateRefusal(
            REFUSAL_MALFORMED,
            "capability gate: assessment must be a mapping with "
            "'report' and 'manifest', got %s" % type(assessment).__name__)
    report = assessment.get("report")
    manifest = assessment.get("manifest")
    if not isinstance(report, Mapping) or not isinstance(manifest, Mapping):
        raise CapabilityGateRefusal(
            REFUSAL_MALFORMED,
            "capability gate: assessment must carry a 'report' mapping "
            "and a 'manifest' mapping")
    # 1. Harness identity: the assessment must come from the harness
    #    the deployment bound itself to.
    if manifest.get("harness_id") != b["harness_id"]:
        raise CapabilityGateRefusal(
            REFUSAL_HARNESS_ID,
            "capability gate: assessment harness_id %r does not match "
            "the binding %r" % (manifest.get("harness_id"),
                                b["harness_id"]))
    # 2. Config digest: the assessment must have been computed against
    #    the exact harness/thresholds config the binding pins. A
    #    threshold-weakening after assessment changes the digest and is
    #    refused as stale.
    if manifest.get("harness_config_digest") != b["harness_digest"]:
        raise CapabilityGateRefusal(
            REFUSAL_CONFIG_DIGEST,
            "capability gate: assessment was computed against a "
            "different harness/thresholds config (digest mismatch) -- "
            "re-assess against the bound config")
    # 3. Freshness: assessed_at must be a real timestamp, not in the
    #    future (future-dating would grant indefinite freshness), and
    #    within the binding's freshness window.
    assessed_at = manifest.get("assessed_at")
    if (isinstance(assessed_at, bool)
            or not isinstance(assessed_at, (int, float))):
        raise CapabilityGateRefusal(
            REFUSAL_MALFORMED,
            "capability gate: manifest 'assessed_at' must be epoch "
            "seconds")
    age = now - assessed_at
    if age < 0:
        raise CapabilityGateRefusal(
            REFUSAL_FUTURE,
            "capability gate: assessment is dated in the future "
            "(assessed_at=%r) -- refusing" % (assessed_at,))
    if age > b["freshness_seconds"]:
        raise CapabilityGateRefusal(
            REFUSAL_EXPIRED,
            "capability gate: assessment is %.0f seconds old, older "
            "than the binding's freshness_seconds=%d -- re-assess"
            % (age, b["freshness_seconds"]))
    # 4. Report digest binding: the manifest's export_sha256 must be
    #    recomputed from the presented report. Content tampering that
    #    skips the seal is caught here.
    try:
        recomputed = hashlib.sha256(_canonical(report)).hexdigest()
    except (TypeError, ValueError):
        raise CapabilityGateRefusal(
            REFUSAL_MALFORMED,
            "capability gate: report is not JSON-canonicalizable")
    if manifest.get("export_sha256") != recomputed:
        raise CapabilityGateRefusal(
            REFUSAL_REPORT_DIGEST,
            "capability gate: manifest export_sha256 does not match "
            "the presented report -- the report was altered after "
            "sealing")
    # 5. Seal: the manifest MUST carry an Ed25519 seal from a trusted
    #    key over the canonical manifest minus the signing block. There
    #    is no unsealed mode: a flipped verdict with a recomputed digest
    #    fails HERE -- the seal cannot be re-minted without the key.
    signing = manifest.get("signing")
    if (not isinstance(signing, Mapping)
            or signing.get("scheme") != "ed25519"):
        raise CapabilityGateRefusal(
            REFUSAL_UNSEALED,
            "capability gate: assessment is not Ed25519-sealed; the "
            "seal is mandatory")
    key_id = signing.get("key_id")
    pub = b["trusted_keys"].get(key_id)
    if pub is None:
        raise CapabilityGateRefusal(
            REFUSAL_UNTRUSTED_KEY,
            "capability gate: seal key_id %r is not in the "
            "binding's trusted_keys" % (key_id,))
    sig_hex = signing.get("signature_hex")
    try:
        sig = bytes.fromhex(sig_hex) if isinstance(sig_hex, str) \
            else bytes(sig_hex)
    except (ValueError, TypeError):
        raise CapabilityGateRefusal(
            REFUSAL_MALFORMED,
            "capability gate: signature_hex is not valid hex")
    sign_bytes = _canonical({k: v for k, v in manifest.items()
                             if k != "signing"})
    verifier = Ed25519Verifier(pub, key_id)
    if not verifier.verify(sign_bytes, sig):
        raise CapabilityGateRefusal(
            REFUSAL_BAD_SIGNATURE,
            "capability gate: assessment seal does not verify "
            "against trusted key %r -- the manifest was altered "
            "after sealing (e.g. flipped verdict with recomputed "
            "digest)" % (key_id,))
    # 6. Verdict, read only after integrity is established.
    verdict = _mapping_get(report, "sufficiency", "aggregate_verdict",
                           "value")
    if verdict != "SUFFICIENT":
        raise CapabilityGateRefusal(
            REFUSAL_INSUFFICIENT,
            "capability gate: assessment verdict is %r, not SUFFICIENT "
            "-- refusing to run" % (verdict,))
    return {
        "allowed": True,
        "report_id": manifest.get("report_id"),
        "harness_id": b["harness_id"],
        "assessed_at": assessed_at,
        "age_seconds": age,
    }
