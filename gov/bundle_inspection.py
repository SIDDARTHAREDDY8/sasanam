"""Bundle-inspection discipline: in-toto inspection pattern, re-derived.

Design input (ADAPT, not vendored): in-toto's inspection concept -- a
verifier-side inspection whose results become link metadata. in-toto
runs inspections as bare ``exec.Command`` with verifier privileges
and no sandbox; inspection links are structurally
verifier-attributed (empty signatures). We do NOT copy that trust
model (negative lesson -- wave-219 prospecting); the in-toto
specification text is NOT reused either (Community Specification
License 1.0 -- pattern only, prose re-derived).

What this module steals:

* **Explicit verifier-attribution**: every admitted bundle-inspection
  link structurally carries the verifier's id AND the bundle digest
  it was bound to. A link lacking attribution cannot verify
  (``bundle-link-unverifiable``).
* **Halt-on-nonzero**: inherited from ``gov/inspection.py`` -- a
  nonzero inspection exit halts with a named code; the failed attempt
  is recorded on the evidence log first.
* **Post-evidence ordering**: inherited from ``gov/inspection.py``
  -- evidence is emitted BEFORE the link is admitted; the link's
  ``evidence_seq`` resolves to a log record or the link is
  unverifiable.

This module COMPOSES with ``gov/inspection.py`` (an inner
``InspectionLog`` does the admission/verification work); it adds
only the bundle binding. No duplication of the admission or
ordering logic.

Wiring (opt-in): :class:`AdmissionPolicy` in ``gov/admission.py``
may require inspection evidence (``require_inspection=True``): the
presented ``(log, link)`` pair must verify, and the link's
``bundle_digest`` must equal the admitted bundle's digest. No
existing bundle module imports or consults this one; existing bundle
behavior is byte-identical when the gate is unused (pinned by
``evals/w221_admission_probes.py::bin-04-legacy-bundle-untouched``).

Honest boundaries (stated, not absorbed):

* Like ``gov/inspection.py``, this harness consumes caller-REPORTED
  exit codes and outputs; it cannot observe the inspection's
  execution. A caller that lies ``exit_code=0`` defeats the halt.
* ``bundle_digest`` binding is a claim the caller supplies at log
  construction; the log does not discover the bundle.
* Evidence-log durability across restarts is the deployment's job.

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

from . import inspection as _insp

__all__ = [
    "CODE_LINK_UNVERIFIABLE",
    "CODE_MALFORMED",
    "BundleInspectionError",
    "BundleInspectionLog",
]

CODE_LINK_UNVERIFIABLE = "bundle-link-unverifiable"
CODE_MALFORMED = "bundle-inspection-malformed"

_HEX = set("0123456789abcdef")


class BundleInspectionError(Exception):
    """Fail-closed bundle-inspection violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(BundleInspectionError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _check_digest(value, where):
    if not isinstance(value, str) or len(value) != 64 \
            or any(c not in _HEX for c in value):
        raise BundleInspectionError(
            CODE_MALFORMED, "%s must be a sha256 hex string" % (where,))
    return value


class BundleInspectionLog(object):
    """An inspection log bound to one bundle digest.

    ``verifier_id`` names this verifier; ``bundle_digest`` is the
    sha256 hex of the bundle under inspection. Every admitted link
    carries both, structurally. ``verify_link`` refuses any link
    that is unattributed, bound to a different bundle, or whose
    evidence sequence does not resolve.
    """

    def __init__(self, verifier_id, bundle_digest):
        if not isinstance(verifier_id, str) or not verifier_id:
            raise BundleInspectionError(
                CODE_MALFORMED, "verifier_id must be a non-empty string")
        self._verifier_id = verifier_id
        self._bundle_digest = _check_digest(bundle_digest, "bundle_digest")
        try:
            self._inner = _insp.InspectionLog(verifier_id=verifier_id)
        except _insp.InspectionError as exc:
            raise BundleInspectionError(exc.code, exc.detail)

    @property
    def verifier_id(self):
        return self._verifier_id

    @property
    def bundle_digest(self):
        return self._bundle_digest

    def admit(self, name, script_bytes, pinned_script_digest, exit_code,
              outputs):
        """Admit one inspection result. The inner ``gov/inspection.py``
        log enforces the script-digest pin, the nonzero-exit halt, and
        evidence-before-link ordering; this method adds the bundle
        binding to the admitted link. Inner refusals surface with
        their own named codes (``inspection-script-digest-mismatch``,
        ``inspection-failed``, ``inspection-malformed``)."""
        try:
            link = self._inner.admit(name, script_bytes,
                                     pinned_script_digest, exit_code,
                                     outputs)
        except _insp.InspectionError as exc:
            raise BundleInspectionError(exc.code, exc.detail)
        link = dict(link)
        link["bundle_digest"] = self._bundle_digest
        return link

    def verify(self):
        """The whole log verifies (delegates to the inner log)."""
        try:
            return self._inner.verify()
        except _insp.InspectionError as exc:
            raise BundleInspectionError(exc.code, exc.detail)

    def verify_link(self, link):
        """A link verifies only when it is a dict claiming
        verifier attribution (``verifier_attributed`` True) with the
        verifier id and bundle digest this log was bound to, AND the
        inner log accepts it (evidence sequence resolves, name /
        script digest / outputs digest / verifier id match). Any
        failure is ``bundle-link-unverifiable``."""
        if not isinstance(link, dict) \
                or link.get("verifier_attributed") is not True \
                or link.get("verifier_id") != self._verifier_id \
                or link.get("bundle_digest") != self._bundle_digest:
            raise BundleInspectionError(
                CODE_LINK_UNVERIFIABLE,
                "link is not verifier-attributed to %r for this bundle"
                % (self._verifier_id,))
        try:
            # The inner log re-checks attribution against its own
            # verifier id and evidence ordering; strip the bundle-only
            # key before delegating.
            inner_link = dict(link)
            inner_link.pop("bundle_digest", None)
            return self._inner.verify_link(inner_link)
        except _insp.InspectionError as exc:
            raise BundleInspectionError(
                CODE_LINK_UNVERIFIABLE, exc.detail)

    def records(self):
        """The emitted ordered evidence records (inner log)."""
        return self._inner.records()
