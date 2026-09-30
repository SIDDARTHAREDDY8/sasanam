"""Digest linkage between the credential's scope and the approver's render.

Gap addressed (re-derived idea from draft-ruvalcaba-nhe-authz-00
section 6 digest linkage — the prose and mechanics here are our own,
not the draft's text): the wave-219 ARAP ``context_binding`` is the
digest that scopes a credential (``gov/permit_leases`` binds a permit
to exactly it), and the wave-221 ``RenderingCommitment`` is the digest
of the exact bytes the approver was shown (``gov/render_commit``).
They lived in separate pipes, so an approver could see one digest
while the credential authorizes another — "show A, authorize B" at
the digest level.

This module enforces the invariant at the approval seam: the SAME
canonical digest that scopes the credential MUST be the digest the
approver's render was bound to. It composes the two existing records;
it does not replace them.

Rules (all fail closed, all refusals carry machine-readable codes):

* ``bind_credential_to_render(credential_digest, render_digest)``
  binds the two digests into a ``DigestLinkage`` record —
  ``{credential_digest, render_digest, bound_at}`` — but ONLY when
  they are equal. Unequal digests refuse ``digest-linkage-mismatch``.
  The record carries NO authority: no ``permit_id``, no ``scope``,
  no grant shape, no redeem path. Presenting a linkage record where
  a lease or a commitment is expected fails closed.
* ``check_approval_flow(permit_lease, rendering_commitment)`` verifies
  that the lease's bound ``parameter_digest`` equals the commitment's
  render target ``artifact_digest``; a divergence refuses
  ``approval-digest-diverged``. The approval cannot proceed when what
  the approver saw is not what the credential authorizes.
* Digest fields are runtime data, never trusted: non-string,
  non-hex, or wrong-length inputs refuse ``digest-linkage-malformed``
  (named code, like ``gov/permit_leases``), never a bare
  ``TypeError``/``ValueError`` escape. The two accepted shapes are
  exactly the pipeline's real schemes — ``sha256:<64-hex>`` (the
  presentation / rendering-commitment / non-ARAP-lease scheme) and
  ``hmac-sha256-v1:<64-hex>`` (the ARAP ``context_binding`` scheme).
  A new scheme is a deliberate addition to the allowlist, never an
  accident of lax parsing.
* Absent lease or commitment is LEGACY: ``check_approval_flow`` with
  either (or both) as None passes through unchanged (returns True),
  so deployments that use neither the wave-220 leases nor the
  wave-221 commitments see byte-identical behavior. This gate is
  opt-in; it tightens only where both records are present.
* A wrong-typed ``permit_lease`` (e.g. a raw dict — including a
  ``DigestLinkage`` offered as an authority) is an authoring bug
  (``TypeError``); a malformed commitment fails its own shape check
  (``rendering-commitment-broken``). Neither can slip through as
  authorization.

Stdlib only. No network. $0.
"""

import re
from hmac import compare_digest

from gov.permit_leases import PermitLease
from gov.render_commit import check_commitment_shape, utcnow_iso

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------

DIGEST_LINKAGE_MISMATCH = "digest-linkage-mismatch"
DIGEST_LINKAGE_MALFORMED = "digest-linkage-malformed"
APPROVAL_DIGEST_DIVERGED = "approval-digest-diverged"


class DigestLinkError(Exception):
    """Base class for digest-linkage refusals. ``code`` is
    machine-readable."""

    code = "digest-linkage-refused"

    def __init__(self, message="", code=None):
        super(DigestLinkError, self).__init__(message)
        if code is not None:
            self.code = code


# ----------------------------------------------------------------------
# Digest-field validation (runtime data -> named refusals).
# ----------------------------------------------------------------------

#: The only digest schemes the approval pipeline produces.
_DIGEST_RE = re.compile(r"^(?:sha256|hmac-sha256-v1):([0-9a-f]{64})$")


def check_digest_format(digest, where):
    """Validate a digest field against the pipeline's real schemes.

    Refuses fail-closed with ``digest-linkage-malformed`` when the
    value is not a string, does not carry a known scheme tag, or does
    not carry 64 lowercase hex digits. Digests are runtime data; a
    malformed one is an attack shape, not an authoring bug.
    """
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        raise DigestLinkError(
            "digest-linkage-malformed: %s digest is not a well-formed "
            "sha256:<64-hex> or hmac-sha256-v1:<64-hex> value"
            % (where,), code=DIGEST_LINKAGE_MALFORMED)
    return True


# ----------------------------------------------------------------------
# The linkage.
# ----------------------------------------------------------------------


def bind_credential_to_render(credential_digest, render_digest):
    """Bind the credential's scope digest to the rendered digest.

    Returns a ``DigestLinkage`` record
    ``{credential_digest, render_digest, bound_at}`` — the invariant
    ``credential_digest == render_digest`` is enforced here, at bind
    time, with a constant-time comparison. Unequal digests refuse
    ``digest-linkage-mismatch``: binding "authorize A, show B" is the
    core violation this module exists to prevent.

    THE LINKAGE RECORD CARRIES NO AUTHORITY. It is a verification
    artifact, not a grant: it holds no permit_id, no scope, no
    issuance semantics, and no redeem path. A caller that needs
    authorization must present the lease and the commitment
    separately through :func:`check_approval_flow`.
    """
    check_digest_format(credential_digest, "credential")
    check_digest_format(render_digest, "render")
    if not compare_digest(credential_digest, render_digest):
        raise DigestLinkError(
            "digest-linkage-mismatch: the credential's scope digest is "
            "not the digest the approver's render was bound to — "
            "binding 'authorize A, show B' is refused",
            code=DIGEST_LINKAGE_MISMATCH)
    return {"credential_digest": credential_digest,
            "render_digest": render_digest,
            "bound_at": utcnow_iso()}


def check_approval_flow(permit_lease, rendering_commitment, *, audit=None):
    """Approval-pipeline gate: the lease and the commitment must agree.

    Verifies that the lease's bound ``parameter_digest`` equals the
    commitment's render target ``artifact_digest``. A divergence
    refuses ``approval-digest-diverged``: the approval cannot proceed
    when what the approver saw is not what the credential authorizes.

    When either record is absent (None), this gate passes through
    unchanged (returns True) — the legacy approval path is
    byte-identical without both records present. The gate is opt-in:
    it tightens only where the deployment already uses the wave-220
    permit leases AND the wave-221 rendering commitments.

    Refusals are audit-visible when ``audit`` is supplied
    (``{"event": "digest_link_refused", "code": ...}``).
    """
    if permit_lease is None or rendering_commitment is None:
        # Legacy: nothing to link, nothing to refuse.
        return True
    if not isinstance(permit_lease, PermitLease):
        # A linkage record (or any dict) offered as a lease: fail
        # closed at the type boundary. The record is not authority.
        raise TypeError(
            "permit_lease must be a gov.permit_leases.PermitLease, "
            "got %s" % type(permit_lease).__name__)
    # The commitment must be a real RenderingCommitment: a DigestLinkage
    # dict fails the shape check here (code rendering-commitment-broken).
    check_commitment_shape(rendering_commitment)

    lease_digest = permit_lease.parameter_digest
    render_digest = rendering_commitment["artifact_digest"]
    try:
        check_digest_format(lease_digest, "lease parameter")
        check_digest_format(render_digest, "commitment artifact")
        if not compare_digest(lease_digest, render_digest):
            raise DigestLinkError(
                "approval-digest-diverged: the permit authorizes digest "
                "%r but the approver's render was bound to digest %r — "
                "the approval cannot proceed"
                % (lease_digest, render_digest),
                code=APPROVAL_DIGEST_DIVERGED)
    except DigestLinkError as exc:
        if audit is not None:
            audit({"event": "digest_link_refused", "code": exc.code})
        raise
    return True


__all__ = [
    "DIGEST_LINKAGE_MISMATCH",
    "DIGEST_LINKAGE_MALFORMED",
    "APPROVAL_DIGEST_DIVERGED",
    "DigestLinkError",
    "check_digest_format",
    "bind_credential_to_render",
    "check_approval_flow",
]
