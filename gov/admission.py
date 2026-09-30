"""Artifact-admission gate: Harbor pull-time content-trust, adapted.

Design input (ADAPT, not vendored): Harbor's pull-time content-trust
gate -- an artifact is admitted to a pipeline only when its digest
matches a pinned expectation, its signature verifies against a pinned
issuer keyset, and its format tag is exactly the expected one
(wave-220 prospecting). No Harbor code or configuration is copied;
the pattern is reimplemented here in our own words over the repo's
existing Ed25519 seam (``gov/ed25519.py``).

What this module provides, stdlib-only:

* :class:`AdmissionPolicy`: a pinned expectation triple
  ``{digest_pin, issuer_pin, bundle_format}``. The constructor
  validates the pins (authoring errors refuse at construction, never
  at admission time).
* :meth:`AdmissionPolicy.admit`: gates one artifact BEFORE it enters
  the evidence pipeline. Returns ``admissible`` only when ALL of
  these hold; every failure is a LOUD, machine-readable refusal,
  never a silent admit:

  1. the artifact's ``format`` is EXACTLY the pinned tag
     (``admission-format-unknown``);
  2. the artifact carries a signature -- unsigned-but-claimed
     artifacts refuse as ``admission-unverifiable``;
  3. the payload's sha256 recomputes to the artifact's claimed
     digest AND the digest matches the pin (constant-time compare)
     (``admission-digest-mismatch``);
  4. the Ed25519 signature over the domain-separated signing bytes
     verifies against the pinned issuer key
     (``admission-issuer-untrusted``);
  5. when the policy requires inspection evidence
     (``require_inspection=True``), a verifier-attributed inspection
     link for THIS bundle must be presented and must verify
     (``admission-inspection-missing`` /
     ``admission-inspection-bundle-mismatch`` /
     ``bundle-link-unverifiable``).

  Malformed artifacts refuse with ``admission-malformed`` (an input
  error, distinct from the policy refusals above).

* The gate is **opt-in**: no existing pipeline module imports or
  consults it. The existing evidence pipeline is byte-identical when
  the gate is unused (pinned by
  ``evals/w221_admission_probes.py::adm-07-legacy-pipeline-untouched``).

Honest boundaries (stated, not absorbed):

* The pin ``{digest_pin, issuer_pin, bundle_format}`` is
  out-of-band custody -- the deployment's job, like every other pin
  in this repo. A policy pinned to the wrong digest admits the wrong
  bundle; the gate enforces pins, it does not choose them.
* The signature binds the *digest*, not the payload semantics: it
  proves the issuer authorized this digest, not that the payload is
  benign.
* Admission is not a sandbox: an admitted bundle is trusted to
  ENTER the pipeline, not to execute.

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

import hashlib
import hmac

from . import ed25519 as _ed

__all__ = [
    "SIGN_DOMAIN",
    "CODE_DIGEST_MISMATCH",
    "CODE_ISSUER_UNTRUSTED",
    "CODE_FORMAT_UNKNOWN",
    "CODE_UNVERIFIABLE",
    "CODE_MALFORMED",
    "CODE_INSPECTION_MISSING",
    "CODE_INSPECTION_BUNDLE_MISMATCH",
    "AdmissionError",
    "AdmissionPolicyAuthoringError",
    "signing_bytes",
    "AdmissionPolicy",
]

#: Domain separation for artifact signatures. The signature covers
#: the digest, so a signature can never be replayed as authorizing a
#: different payload.
SIGN_DOMAIN = b"artifact-admission-sign/v1\x00"

CODE_DIGEST_MISMATCH = "admission-digest-mismatch"
CODE_ISSUER_UNTRUSTED = "admission-issuer-untrusted"
CODE_FORMAT_UNKNOWN = "admission-format-unknown"
CODE_UNVERIFIABLE = "admission-unverifiable"
CODE_MALFORMED = "admission-malformed"
CODE_INSPECTION_MISSING = "admission-inspection-missing"
CODE_INSPECTION_BUNDLE_MISMATCH = "admission-inspection-bundle-mismatch"

_HEX = set("0123456789abcdef")

_ARTIFACT_FIELDS = ("format", "payload_digest", "signature", "payload")


class AdmissionError(Exception):
    """Loud admission failure: malformed artifact, pin mismatch,
    untrusted issuer, or missing/bad inspection evidence. ``code``
    is the machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(AdmissionError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


class AdmissionPolicyAuthoringError(Exception):
    """Loud failure at policy construction: the pins are malformed.
    Pin-authoring errors happen at registration/compile time, never
    at admission time."""


def _is_hex64(value):
    return isinstance(value, str) and len(value) == 64 \
        and all(c in _HEX for c in value)


def signing_bytes(payload_digest):
    """Bytes the issuer signs: domain || sha256-canonical digest."""
    return SIGN_DOMAIN + payload_digest.encode("ascii")


class AdmissionPolicy(object):
    """A pinned admission expectation.

    ``digest_pin``: the sha256 hex the artifact's payload must hash
    to. ``issuer_pin``: the 32-byte Ed25519 public key whose
    signature must cover the digest. ``bundle_format``: the exact
    format tag the artifact must declare. ``require_inspection``:
    when True, admission also requires a verifier-attributed
    inspection link (see ``gov/bundle_inspection.py``) bound to the
    admitted bundle's digest.
    """

    def __init__(self, digest_pin, issuer_pin, bundle_format,
                 require_inspection=False):
        if not _is_hex64(digest_pin):
            raise AdmissionPolicyAuthoringError(
                "digest_pin must be a sha256 hex string")
        if not isinstance(issuer_pin, (bytes, bytearray)) \
                or len(issuer_pin) != 32:
            raise AdmissionPolicyAuthoringError(
                "issuer_pin must be a 32-byte Ed25519 public key")
        if not isinstance(bundle_format, str) or not bundle_format:
            raise AdmissionPolicyAuthoringError(
                "bundle_format must be a non-empty string")
        if not isinstance(require_inspection, bool):
            raise AdmissionPolicyAuthoringError(
                "require_inspection must be a bool")
        self._digest_pin = digest_pin
        self._issuer_pin = bytes(issuer_pin)
        self._format = bundle_format
        self._require_inspection = require_inspection

    def _check_shape(self, artifact):
        if not isinstance(artifact, dict):
            raise AdmissionError(CODE_MALFORMED, "artifact is not a dict")
        unknown = sorted(set(artifact) - set(_ARTIFACT_FIELDS))
        if unknown:
            raise AdmissionError(
                CODE_MALFORMED,
                "unknown artifact fields %s (refusing)" % (unknown,))
        missing = [f for f in _ARTIFACT_FIELDS if f not in artifact]
        if missing:
            raise AdmissionError(
                CODE_MALFORMED,
                "missing artifact fields %s" % (missing,))
        if not isinstance(artifact["format"], str):
            raise AdmissionError(CODE_MALFORMED, "format is not a string")
        if not _is_hex64(artifact["payload_digest"]):
            raise AdmissionError(
                CODE_MALFORMED, "payload_digest is not a sha256 hex string")
        if not isinstance(artifact["payload"], (bytes, bytearray)):
            raise AdmissionError(CODE_MALFORMED, "payload is not bytes")
        signature = artifact["signature"]
        if signature is not None and not isinstance(
                signature, (bytes, bytearray)):
            raise AdmissionError(
                CODE_MALFORMED, "signature is neither None nor bytes")

    def admit(self, artifact, inspection=None):
        """Gate one artifact. Returns the audit-visible admission
        record ``{"admissible": True, "payload_digest": ..., "format":
        ..., "issuer_fingerprint": ..., "inspection_verified": ...}``.

        Check order (documented, deterministic):

        1. shape (``admission-malformed``);
        2. format exact match (``admission-format-unknown``);
        3. signature presence (``admission-unverifiable``);
        4. payload recomputation + constant-time pin compare
           (``admission-digest-mismatch``);
        5. issuer signature over the domain-separated digest
           (``admission-issuer-untrusted``);
        6. optional inspection evidence (``admission-inspection-missing``,
           ``admission-inspection-bundle-mismatch``,
           ``bundle-link-unverifiable``).

        ``inspection`` is a ``(log, link)`` pair where ``log`` is a
        ``gov/bundle_inspection.py`` ``BundleInspectionLog`` and
        ``link`` the link to verify. Only consulted when the policy
        requires inspection.
        """
        self._check_shape(artifact)
        if artifact["format"] != self._format:
            raise AdmissionError(
                CODE_FORMAT_UNKNOWN,
                "format %r is not the pinned %r"
                % (artifact["format"], self._format))
        signature = artifact["signature"]
        if signature is None:
            raise AdmissionError(
                CODE_UNVERIFIABLE,
                "artifact carries no issuer signature (unsigned bundle)")
        payload_digest = artifact["payload_digest"]
        if hashlib.sha256(bytes(artifact["payload"])).hexdigest() \
                != payload_digest:
            raise AdmissionError(
                CODE_DIGEST_MISMATCH,
                "payload does not recompute to the claimed digest")
        if not hmac.compare_digest(payload_digest, self._digest_pin):
            raise AdmissionError(
                CODE_DIGEST_MISMATCH,
                "digest does not match the pinned digest")
        if not _ed.verify(self._issuer_pin,
                          signing_bytes(payload_digest),
                          bytes(signature)):
            raise AdmissionError(
                CODE_ISSUER_UNTRUSTED,
                "signature is not by the pinned issuer")
        inspection_verified = False
        if self._require_inspection:
            if inspection is None:
                raise AdmissionError(
                    CODE_INSPECTION_MISSING,
                    "policy requires inspection evidence; none presented")
            if not (isinstance(inspection, tuple) and len(inspection) == 2):
                raise AdmissionError(
                    CODE_MALFORMED,
                    "inspection must be a (log, link) pair")
            log, link = inspection
            if not isinstance(link, dict) \
                    or link.get("bundle_digest") != payload_digest:
                raise AdmissionError(
                    CODE_INSPECTION_BUNDLE_MISMATCH,
                    "inspection link is not bound to this bundle's digest")
            try:
                log.verify_link(link)
            except Exception as exc:  # noqa: BLE001 - named refusals below
                # Named inspection refusals (e.g.
                # bundle-link-unverifiable) surface as admission
                # refusals with their own code. Anything else --
                # a programming error inside the log -- re-raises
                # loudly rather than being masked as a policy refusal.
                if not hasattr(exc, "code"):
                    raise
                raise AdmissionError(
                    exc.code or "bundle-link-unverifiable", str(exc))
            inspection_verified = True
        return {
            "admissible": True,
            "payload_digest": payload_digest,
            "format": self._format,
            "issuer_fingerprint": hashlib.sha256(self._issuer_pin).hexdigest(),
            "inspection_verified": inspection_verified,
        }
