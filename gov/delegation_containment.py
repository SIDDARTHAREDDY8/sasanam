"""Delegation containment + policy-currentness (W242-5, onedoor docs ADAPT).

Two separate honest-gap closures:

1. Parent-permit refusal. A permit that names a ``parent_permit``
   reference is refused outright at the admission step
   (``permit-parent-named``), never forwarded, never admitted. This
   rhymes with wei's delegation-containment ``Contains(parent, child)``:
   a child grant must be containable in its parent, and the only way
   this module admits a child is if the caller supplies the parent's
   bounds and ``verify_containment`` proves the containment. A permit
   that *names* a parent but does not (or cannot) prove containment is
   not a delegation claim to evaluate -- it is a refusal.

2. Policy currentness. Presentation-time policy-currentness is a
   recognized claim (``check_currentness``), but the mechanism that
   could prove "the policy is current" is unavailable in this
   deployment. The claim therefore always reports
   ``permit-currentness-could-not-check`` naming the
   ``policy-currentness-authority`` dependency -- even when an
   authority dict is wired in. It is a could-not-check state, never a
   refusal and never a "verified": the honest residual is that no
   mechanism exists yet, and claiming verified would be
   misattribution.

3. Containment verification. ``verify_containment(parent_bounds,
   child_bounds)`` proves every child bound is within the parent's
   bound. Any child bound exceeding the parent's refuses
   ``delegation-containment-violated`` naming the violated bound keys.
   Bounds are numeric caps (lower numeric value = tighter). Keys
   present in the child but absent in the parent are violations by
   default (no parent cap to contain them); set ``strict=False`` to
   ignore unknown keys instead. Malformed bounds fail closed.

Honest residuals:
- Bounds are numeric caps only; this module does not understand
  non-numeric policy semantics (scopes, principals, temporal windows).
- Containment is a static comparison of two dicts; it cannot prove
  the parent bounds offered are the *actual* parent permit's bounds.
- could-not-check is not evidence: downstream consumers must treat it
  as absence of evidence, not as a green.

Stdlib only. Deterministic. Fail-closed on malformed input.
"""

PERMIT_PARENT_NAMED = "permit-parent-named"
PERMIT_CURRENTNESS_COULD_NOT_CHECK = "permit-currentness-could-not-check"
DELEGATION_CONTAINMENT_VIOLATED = "delegation-containment-violated"
CONTAINMENT_MALFORMED = "permit-containment-malformed"

CURRENTNESS_DEPENDENCY = "policy-currentness-authority"
_ADMISSION_STEP = "admission"


class ContainmentError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code, and
    ``step`` names the verification step at which the refusal fired."""

    def __init__(self, code, detail, step=None):
        super(ContainmentError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail
        self.step = step


def _refuse(code, detail, step=None):
    raise ContainmentError(code, detail, step)


def declare_permit(permit_id, bounds, parent_permit=None):
    """Admit a permit record. A permit that names a parent permit is
    refused outright at the admission step -- it is never forwarded."""
    if not isinstance(permit_id, str) or not permit_id:
        _refuse(CONTAINMENT_MALFORMED,
                "permit_id must be a non-empty string",
                step=_ADMISSION_STEP)
    if parent_permit is not None:
        _refuse(
            PERMIT_PARENT_NAMED,
            "permit %r names parent_permit %r; delegation containment "
            "requires containment to be proved against the parent's "
            "bounds, not merely claimed by reference" % (
                permit_id, parent_permit),
            step=_ADMISSION_STEP)
    _check_bounds(bounds)
    return {"permit_id": permit_id, "bounds": dict(bounds),
            "parent_permit": None, "admitted": True}


def _check_bounds(bounds):
    if not isinstance(bounds, dict) or not bounds:
        _refuse(CONTAINMENT_MALFORMED,
                "bounds must be a non-empty dict of numeric caps",
                step=_ADMISSION_STEP)
    for key, value in bounds.items():
        if not isinstance(key, str) or not key:
            _refuse(CONTAINMENT_MALFORMED,
                    "bounds keys must be non-empty strings",
                    step=_ADMISSION_STEP)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            _refuse(CONTAINMENT_MALFORMED,
                    "bound %r must be numeric" % (key,),
                    step=_ADMISSION_STEP)


def check_currentness(policy_authority=None):
    """Report presentation-time policy currentness. The currentness
    mechanism is unavailable in this deployment, so the claim always
    reports could-not-check -- never a refusal, never "verified"."""
    return {"status": "could-not-check",
            "dependency": CURRENTNESS_DEPENDENCY,
            "wired": policy_authority is not None,
            "code": PERMIT_CURRENTNESS_COULD_NOT_CHECK}


def verify_containment(parent_bounds, child_bounds, strict=True):
    """Prove the child bounds are contained in the parent bounds.

    Numeric caps: a child value greater than the parent's value for
    the same key violates containment. Keys present in the child but
    absent from the parent violate containment under strict=True."""
    _check_bounds(parent_bounds)
    _check_bounds(child_bounds)
    violated = []
    for key, child_value in child_bounds.items():
        if key not in parent_bounds:
            if strict:
                violated.append(key)
            continue
        if child_value > parent_bounds[key]:
            violated.append(key)
    if violated:
        _refuse(
            DELEGATION_CONTAINMENT_VIOLATED,
            "child grant bounds exceed parent bounds on: %s; delegation "
            "containment requires every child bound within its parent "
            "bound (wei §13 Contains)" % (", ".join(sorted(violated)),),
            step="containment")
    return {"ok": True, "violated": []}
