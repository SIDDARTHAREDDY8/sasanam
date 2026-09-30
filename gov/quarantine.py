"""Quarantine-until-decision admission: copy hooks are not the boundary.

Design input (ADAPT, not vendored): the harbor-satellite ADR-0009
rule -- an ORAS copy hook is NOT the admission boundary. An artifact
is copied into QUARANTINE first and enters the trusted store ONLY
after the final admission decision succeeds. Copying != admitting.

No upstream code or text is copied; the pattern is reimplemented here
in our own words over the repo's existing seams
(``gov/admission.py``, ``gov/gate_algebra.py``).

What this module provides, stdlib-only:

* :class:`Quarantine`: an in-memory two-area staging discipline.
  ``stage(artifact_bytes, artifact_digest)`` copies the payload into
  the quarantine area after verifying the claimed digest recomputes
  from the bytes (``quarantine-digest-mismatch``). ``admit(staged,
  admission_policy, ...)`` runs the supplied admission policy (any
  object exposing ``admit(envelope, **kwargs)`` -- e.g.
  ``gov/admission.py``'s ``AdmissionPolicy`` or
  ``gov/gate_algebra.py``'s ``PolicyConjunction`` /
  ``SeverityGate`` / ``ImmutableTag``) at DECISION time and moves
  the staged bytes into the trusted store ONLY on a verified
  success -- every refusal code from the policy propagates by name,
  never laundered, and the staged artifact stays quarantined for
  triage. ``reject(staged, reason)`` removes the artifact with
  ``quarantine-rejected`` carrying the reason.
  ``admit_to_trust(...)`` ALWAYS refuses
  ``quarantine-bypass-refused`` -- the direct-to-trust path exists
  only to refuse loudly; it can never silently admit.

* :class:`StagedArtifact`: the opaque handle binding a staged copy
  to its verified digest. Handles are instance-scoped (a handle from
  another :class:`Quarantine` refuses ``quarantine-unknown-staged``)
  and single-use (admission consumes the handle; a second admit
  refuses ``quarantine-unknown-staged``). The decision-time envelope
  is built from the STAGED bytes and the STAGED digest -- callers may
  not override ``payload`` or ``payload_digest`` at admit time
  (``quarantine-envelope-override-refused``).

The gate is **opt-in**: no existing pipeline module imports or
consults it. ``gov/admission.py`` and ``gov/gate_algebra.py`` are
untouched; their direct use is byte-identical when the quarantine is
unused.

Honest boundaries (stated, not absorbed):

* Both areas are in-memory; persistence of the trusted store is
  deployment-owned, like every other registry in this repo.
* The trusted store holds admitted BYTES; admission is not a sandbox
  and does not prove the payload benign (see ``gov/admission.py``).
* Quarantine proves the artifact was staged before the decision; it
  does not prove the artifact was really searched or scanned.
* Clock, key, and pin custody are deployment-owned (see
  ``gov/admission.py``).

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

import hashlib
import hmac
import secrets
import uuid

__all__ = [
    "CODE_DIGEST_MISMATCH",
    "CODE_MALFORMED",
    "CODE_UNKNOWN_STAGED",
    "CODE_REJECTED",
    "CODE_BYPASS_REFUSED",
    "CODE_OVERRIDE_REFUSED",
    "CODE_NOT_ADMITTED",
    "CODE_CONTRACT_REFUSED",
    "QuarantineError",
    "StagedArtifact",
    "Quarantine",
]

CODE_DIGEST_MISMATCH = "quarantine-digest-mismatch"
CODE_MALFORMED = "quarantine-malformed"
CODE_UNKNOWN_STAGED = "quarantine-unknown-staged"
CODE_REJECTED = "quarantine-rejected"
CODE_BYPASS_REFUSED = "quarantine-bypass-refused"
CODE_OVERRIDE_REFUSED = "quarantine-envelope-override-refused"
CODE_NOT_ADMITTED = "quarantine-not-admitted"
CODE_CONTRACT_REFUSED = "quarantine-policy-contract-refused"

_HEX = set("0123456789abcdef")


class QuarantineError(Exception):
    """Loud quarantine failure: digest mismatch, malformed input,
    unknown/consumed staged handle, rejection, bypass attempt, or an
    envelope-override at decision time. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(QuarantineError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _is_hex64(value):
    return isinstance(value, str) and len(value) == 64 \
        and all(c in _HEX for c in value)


class StagedArtifact(object):
    """Opaque handle binding a staged byte copy to its verified digest.

    Instances are created by :meth:`Quarantine.stage` only; the handle
    is instance-scoped and single-use. ``digest`` is the verified
    sha256 of the staged bytes.
    """

    def __init__(self, quarantine_id, staged_id, digest):
        self._quarantine_id = quarantine_id
        self._staged_id = staged_id
        self._digest = digest

    @property
    def digest(self):
        """The verified sha256 digest of the staged bytes."""
        return self._digest

    def issued_by(self, quarantine_id):
        """True when this handle was issued by the given quarantine
        instance. The comparison lives here (not on the consumer)
        so handle internals stay with the handle."""
        return self._quarantine_id == quarantine_id

    def __repr__(self):
        return "StagedArtifact(digest=%r)" % (self._digest,)


class Quarantine(object):
    """Two-area staging discipline: quarantine first, trust only on
    a successful admission decision."""

    def __init__(self):
        self._id = uuid.uuid4().hex
        self._staged = {}   # staged_id -> {"bytes": b, "digest": hex}
        self._trusted = {}  # digest -> bytes

    # -- staging ----------------------------------------------------

    def stage(self, artifact_bytes, artifact_digest):
        """Copy the artifact into quarantine.

        The claimed digest is verified against the supplied bytes
        (constant-time compare); mismatch refuses
        ``quarantine-digest-mismatch``. Returns an opaque
        :class:`StagedArtifact` handle binding the stored copy to the
        verified digest.
        """
        if not isinstance(artifact_bytes, (bytes, bytearray)):
            raise QuarantineError(CODE_MALFORMED,
                                  "artifact_bytes is not bytes")
        if not _is_hex64(artifact_digest):
            raise QuarantineError(CODE_MALFORMED,
                                  "artifact_digest is not a sha256 hex string")
        payload = bytes(artifact_bytes)
        computed = hashlib.sha256(payload).hexdigest()
        if not hmac.compare_digest(computed, artifact_digest):
            raise QuarantineError(
                CODE_DIGEST_MISMATCH,
                "supplied bytes do not recompute to the claimed digest")
        staged_id = secrets.token_hex(16)
        self._staged[staged_id] = {"bytes": payload,
                                   "digest": artifact_digest}
        return StagedArtifact(self._id, staged_id, artifact_digest)

    # -- decision ---------------------------------------------------

    def _resolve_staged(self, staged):
        if not isinstance(staged, StagedArtifact):
            raise QuarantineError(CODE_UNKNOWN_STAGED,
                                  "not a staged artifact handle")
        if not staged.issued_by(self._id):
            raise QuarantineError(CODE_UNKNOWN_STAGED,
                                  "handle belongs to another quarantine")
        record = self._staged.get(staged._staged_id)
        if record is None:
            raise QuarantineError(CODE_UNKNOWN_STAGED,
                                  "handle is unknown or already consumed")
        return record, staged._staged_id

    def admit(self, staged, admission_policy, bundle_format=None,
              signature=None, **decision_kwargs):
        """Run the admission decision and, ONLY on success, move the
        staged bytes into the trusted store.

        ``admission_policy`` is any object exposing ``admit(envelope,
        **kwargs)`` -- typically ``gov/admission.py``'s
        ``AdmissionPolicy`` or ``gov/gate_algebra.py``'s
        ``PolicyConjunction``/``SeverityGate``/``ImmutableTag``. The
        composition is by interface, verified by the battery; this
        module raises on refusal and never launders codes.

        The decision envelope is built from the STAGED bytes and the
        STAGED digest -- ``payload`` / ``payload_digest`` may not be
        overridden here (``quarantine-envelope-override-refused``).
        ``decision_kwargs`` (e.g. ``inspection=...``,
        ``findings=...``) are forwarded to the policy's ``admit``.

        Success means the policy returned an admissible record
        (``record["admissible"] is True``); a policy that returns
        without an admissible record refuses
        ``quarantine-policy-contract-refused``. Refusals from the
        policy propagate by name (never laundered); the staged
        artifact stays quarantined for triage.
        """
        record, staged_id = self._resolve_staged(staged)
        if "payload_digest" in decision_kwargs \
                or "payload" in decision_kwargs:
            raise QuarantineError(
                CODE_OVERRIDE_REFUSED,
                "payload/payload_digest are bound to the staged copy; "
                "they may not be overridden at decision time")
        if not callable(getattr(admission_policy, "admit", None)):
            raise QuarantineError(CODE_MALFORMED,
                                  "admission_policy has no callable admit()")
        envelope = {"format": bundle_format,
                    "payload_digest": record["digest"],
                    "signature": signature,
                    "payload": record["bytes"]}
        admission_record = admission_policy.admit(envelope,
                                                  **decision_kwargs)
        # Only reached when the policy did not raise. Verify the
        # record actually admits before anything enters trust.
        if not isinstance(admission_record, dict) \
                or admission_record.get("admissible") is not True:
            raise QuarantineError(
                CODE_CONTRACT_REFUSED,
                "policy returned without an admissible record")
        # ONLY on a verified success: move to trust and consume the
        # staged handle.
        self._trusted[record["digest"]] = record["bytes"]
        del self._staged[staged_id]
        return admission_record

    def reject(self, staged, reason):
        """Remove a staged artifact with a named refusal carrying the
        reason. The reason is audit-visible; the artifact leaves
        quarantine and never enters the trusted store."""
        record, staged_id = self._resolve_staged(staged)
        if not isinstance(reason, str) or not reason:
            raise QuarantineError(CODE_MALFORMED,
                                  "reason must be a non-empty string")
        digest = record["digest"]
        del self._staged[staged_id]
        raise QuarantineError(CODE_REJECTED,
                              "staged %s rejected: %s" % (digest, reason))

    def admit_to_trust(self, *args, **kwargs):
        """The bypass path exists only to refuse loudly.

        Admitting an artifact to the trusted store WITHOUT staging it
        first is refused ``quarantine-bypass-refused`` -- the bypass
        can never silently admit.
        """
        raise QuarantineError(
            CODE_BYPASS_REFUSED,
            "direct-to-trust admission is forbidden; stage() first and "
            "let the admission decision succeed")

    # -- observation -------------------------------------------------

    def in_trusted_store(self, digest):
        """True only when this digest was admitted to the trusted
        store. Staged-but-undecided artifacts are NOT in the trusted
        store."""
        return isinstance(digest, str) and digest in self._trusted

    def trusted_payload(self, digest):
        """Return the trusted payload bytes for an admitted digest.
        Refuses ``quarantine-not-admitted`` for anything else."""
        if not isinstance(digest, str) or digest not in self._trusted:
            raise QuarantineError(CODE_NOT_ADMITTED,
                                  "digest %r is not in the trusted store"
                                  % (digest,))
        return self._trusted[digest]

    def quarantined_digests(self):
        """Digests currently staged and awaiting a decision."""
        return sorted(record["digest"] for record in self._staged.values())
