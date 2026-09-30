"""APS -04 axis/result model (wave-240).

Adapted from draft-pidlisnyi-aps -04 (prose re-derived; IETF Trust --
no verbatim copying): the chain-verification AXIS carries four terms --
``valid`` / ``invalid`` / ``indeterminate`` / ``unsupported`` -- each
with a MANDATORY reason code. Per APS section 2.3: "A chain result of
unsupported is carried as unsupported and is neither erased nor folded
into any other value on any axis."

The taxonomy decision (binding, from the wave-239 prospectus): the
per-axis verification result keeps all four terms, but the top-level
gate keeps the wave-237 THREE outcomes (PASS / TAMPER / UNDECIDABLE).
``unsupported`` folds into UNDECIDABLE with the dedicated reason code
``unsupported-profile`` inside the UNDECIDABLE_REASONS vocabulary, and
the ceiling rule maps parser/implementation limits to indeterminate
naming the limit -- never invalid, never TAMPER. The gate is a
*different axis* from verification; APS's hard constraint (never
collapse unsupported into valid; carried, never erased) holds
end-to-end, and the wave-237 "unverifiable is not tampered" semantics
hold at the gate. No fourth gate outcome is invented.

Aggregation order (deterministic, first-hit wins by severity):
invalid > unsupported > indeterminate > valid.

Rules:
- Unestablished axes never contribute to valid: an axis the checker
  cannot establish (missing state store, missing capability) is marked
  ``mark_unestablished`` -> UNSUPPORTED with reason
  ``axis-not-established``. The aggregate is not valid and
  ``require_valid`` refuses ``axis-unestablished``.
- Ceiling rule: verifier ceilings (depth, wire size, chain length) are
  verifier properties -> INDETERMINATE naming the limit, never INVALID.
  ``require_valid`` refuses ``axis-ceiling-hit`` naming the ceiling; the
  gate folds it to UNDECIDABLE with reason ``verifier-limit-reached``.
- A syntax violation observed first stays INVALID (the ceiling rule
  does not soften a real defect).
- Revocation (§8.2.7-8.2.10, prose re-derived): unknown revocation
  state is NOT active (``revocation-state-unknown``); suspension is not
  revocation and expiry is not revocation -- presenting either as
  revocation refuses ``revocation-category-error``.

Refusal codes (all vocabulary-bound to gov/decision_codes.py):
- ``axis-unestablished`` -- require_valid refused a chain that is not
  valid because an axis was unestablished.
- ``axis-ceiling-hit`` -- require_valid refused a chain that is
  indeterminate because a verifier ceiling was hit; the reason names
  the limit.
- ``axis-indeterminate`` -- require_valid refused a chain that is
  indeterminate for a non-ceiling reason; indeterminate never reads
  as valid.
- ``axis-invalid`` -- require_valid refused a chain that aggregates to
  invalid; invalid chains never read as valid.
- ``revocation-state-unknown`` -- the revocation state is unknown, so
  the credential is classified not-active (fail-closed), never active.
- ``revocation-category-error`` -- a non-revocation state (suspension,
  expiry) was presented as revocation.

The module composes with gov/gate_outcomes.py positionally
(``go.Verdict(outcome, reason)``) and does not invent gate outcomes.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads.

What this does NOT do (honest boundaries):
- It does not verify signatures, chains, or revocation itself: it is a
  verdict algebra for verifier results. The axis verdicts are the
  checker's claims; this module only aggregates them faithfully.
- The ceiling verdict trusts the caller's limit name: a verifier that
  lies about its ceiling is outside this module's threat model.
- Revocation evidence is caller-supplied: ``check_revocation`` classifies
  the CLAIMED vs OBSERVED states; it does not prove either one.
- An ``unsupported`` reason code is a free-form mandatory string, not a
  closed vocabulary: the closed vocabularies live at the gate
  (UNDECIDABLE_REASONS) and in the taxonomy (decision codes).
"""

from gov import gate_outcomes as go

VALID = "valid"
INVALID = "invalid"
INDETERMINATE = "indeterminate"
UNSUPPORTED = "unsupported"
TERMS = (VALID, INVALID, INDETERMINATE, UNSUPPORTED)

# Gate-level reasons for the fold. These extend the wave-237
# UNDECIDABLE_REASONS vocabulary (see gov/gate_outcomes.py): both are
# "could not verify", never "tampered".
GATE_REASON_UNSUPPORTED = "unsupported-profile"
GATE_REASON_CEILING = "verifier-limit-reached"

# Axis-level mandatory reason codes minted by this module.
REASON_UNESTABLISHED = "axis-not-established"
CEILING_REASON_PREFIX = "ceiling:"

AXIS_UNESTABLISHED = "axis-unestablished"
AXIS_CEILING_HIT = "axis-ceiling-hit"
AXIS_INDETERMINATE = "axis-indeterminate"
AXIS_INVALID = "axis-invalid"
REVOCATION_STATE_UNKNOWN = "revocation-state-unknown"
REVOCATION_CATEGORY_ERROR = "revocation-category-error"

# Revocation states (APS section 8.2, prose re-derived).
REV_ACTIVE = "active"
REV_REVOKED = "revoked"
REV_SUSPENDED = "suspended"
REV_UNKNOWN = "unknown"
REV_EXPIRED = "expired"
REVOCATION_STATES = (REV_ACTIVE, REV_REVOKED, REV_SUSPENDED,
                     REV_UNKNOWN, REV_EXPIRED)

# The six-member APS artifact verdict set, mapped onto the four axis
# terms. "not established" is unsupported (never valid);
# "not yet effective", "suspended", "restricted" are indeterminate
# (undecided, not invalid).
ARTIFACT_VERDICT_TERMS = {
    "valid": VALID,
    "invalid": INVALID,
    "not established": UNSUPPORTED,
    "not yet effective": INDETERMINATE,
    "suspended": INDETERMINATE,
    "restricted": INDETERMINATE,
}


class AxisModelError(Exception):
    """A model refusal carrying a machine taxonomy code.

    ``code`` is one of the module-level constants; ``detail`` is a
    human sentence. Malformed construction remains a programming error
    (ValueError), not a product refusal.
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s: %s" % (code, detail) if detail else code)


class AxisVerdict:
    """One per-axis verification result.

    ``axis`` names the axis (non-empty string). ``term`` is one of the
    four terms. ``reason`` is a MANDATORY non-empty reason code: for
    ``valid`` a free attestation string; for the other terms the code
    that must be carried, never erased. Malformed construction is a
    programming error (ValueError).
    """

    __slots__ = ("axis", "term", "reason", "detail")

    def __init__(self, axis, term, reason, detail=""):
        if not isinstance(axis, str) or not axis:
            raise ValueError("axis must be a non-empty string")
        if term not in TERMS:
            raise ValueError("term must be one of %r, got %r" % (TERMS, term))
        if not isinstance(reason, str) or not reason:
            raise ValueError(
                "reason is mandatory and must be a non-empty string")
        if not isinstance(detail, str):
            raise ValueError("detail must be a string")
        self.axis = axis
        self.term = term
        self.reason = reason
        self.detail = detail

    def __repr__(self):
        return "AxisVerdict(%r, %r, %r)" % (self.axis, self.term, self.reason)


class ChainResult:
    """The aggregated verification result over one chain of axes."""

    __slots__ = ("term", "verdicts")

    def __init__(self, term, verdicts):
        if term not in TERMS:
            raise ValueError("term must be one of %r, got %r" % (TERMS, term))
        self.term = term
        self.verdicts = tuple(verdicts)


def ceiling(axis, limit_name):
    """Build the INDETERMINATE verdict for a verifier ceiling.

    ``limit_name`` names the limit that was hit (e.g.
    "delegation-depth-64"). Ceilings are verifier properties: hitting
    one is never INVALID, never TAMPER.
    """
    if not isinstance(limit_name, str) or not limit_name:
        raise ValueError("limit_name must be a non-empty string")
    return AxisVerdict(axis, INDETERMINATE, CEILING_REASON_PREFIX + limit_name,
                       detail="verifier ceiling reached: %s" % limit_name)


def mark_unestablished(axis, detail=""):
    """Mark an axis the checker could not establish (missing state
    store, missing capability, missing trust material). The axis is
    UNSUPPORTED -- it never contributes to a valid aggregate.
    """
    return AxisVerdict(axis, UNSUPPORTED, REASON_UNESTABLISHED, detail)


def artifact_verdict_to_term(artifact_verdict):
    """Map the six-member APS artifact verdict onto the four axis
    terms. Unknown verdicts are a programming error (ValueError).
    """
    try:
        return ARTIFACT_VERDICT_TERMS[artifact_verdict]
    except KeyError:
        raise ValueError("unknown artifact verdict %r" % (artifact_verdict,))


def aggregate(verdicts):
    """Aggregate per-axis verdicts into one ChainResult.

    Severity order: invalid > unsupported > indeterminate > valid. An
    unsupported verdict is carried, never erased and never folded into
    valid; a ceiling-induced indeterminate never becomes invalid.
    """
    verdicts = list(verdicts)
    if not verdicts:
        raise ValueError("aggregate requires at least one verdict")
    for v in verdicts:
        if not isinstance(v, AxisVerdict):
            raise ValueError("aggregate takes AxisVerdict entries")
    terms = {v.term for v in verdicts}
    if INVALID in terms:
        term = INVALID
    elif UNSUPPORTED in terms:
        term = UNSUPPORTED
    elif INDETERMINATE in terms:
        term = INDETERMINATE
    else:
        term = VALID
    return ChainResult(term, verdicts)


def _first_reason(chain, term, prefix=None):
    for v in chain.verdicts:
        if v.term == term and (prefix is None or v.reason.startswith(prefix)):
            return v
    return None


def require_valid(chain):
    """Return None iff the chain aggregates to valid, else refuse with
    the named taxonomy code. Unestablished axes refuse
    ``axis-unestablished``; ceiling hits refuse ``axis-ceiling-hit``
    naming the limit. This is the seam where "unestablished never
    contributes to valid" is enforced.
    """
    if not isinstance(chain, ChainResult):
        raise ValueError("require_valid takes a ChainResult")
    if chain.term == VALID:
        return None
    if chain.term == UNSUPPORTED:
        v = _first_reason(chain, UNSUPPORTED)
        raise AxisModelError(
            AXIS_UNESTABLISHED,
            "axis %r is unestablished (%s); unestablished axes never "
            "contribute to valid" % (v.axis, v.reason))
    if chain.term == INDETERMINATE:
        v = _first_reason(chain, INDETERMINATE, CEILING_REASON_PREFIX)
        if v is not None:
            raise AxisModelError(
                AXIS_CEILING_HIT,
                "verifier ceiling reached on axis %r: %s" % (v.axis, v.reason))
        raise AxisModelError(
            AXIS_INDETERMINATE,
            "chain is indeterminate (not valid, not invalid); refusing "
            "rather than treating as valid")
    raise AxisModelError(
        AXIS_INVALID,
        "chain is invalid; refusing")


class RevocationOutcome:
    """The classification of a credential's revocation state.

    ``is_active`` is the only authority bit a consumer may act on:
    True iff the state is positively active. ``code`` carries the
    taxonomy refusal when the state is not positively determined.
    """

    __slots__ = ("claimed", "observed", "is_active", "code", "detail")

    def __init__(self, claimed, observed, is_active, code="", detail=""):
        self.claimed = claimed
        self.observed = observed
        self.is_active = bool(is_active)
        self.code = code
        self.detail = detail


def check_revocation(claimed, observed):
    """Classify CLAIMED vs OBSERVED revocation states (APS 8.2).

    - observed "unknown" -> not active, code revocation-state-unknown
      (fail-closed; unknown is never active).
    - claimed "revoked" while observed "suspended" or "expired" ->
      revocation-category-error (suspension/expiry are not revocation).
    - claimed "revoked" and observed "revoked" -> not active.
    - claimed "active" and observed "active" -> active.
    Any other claimed/observed pair is a programming error (ValueError).
    """
    if claimed not in REVOCATION_STATES or observed not in REVOCATION_STATES:
        raise ValueError(
            "revocation states must be one of %r" % (REVOCATION_STATES,))
    if observed == REV_UNKNOWN:
        return RevocationOutcome(
            claimed, observed, False, REVOCATION_STATE_UNKNOWN,
            "revocation state is unknown; the credential is not active")
    if claimed == REV_REVOKED and observed in (REV_SUSPENDED, REV_EXPIRED):
        raise AxisModelError(
            REVOCATION_CATEGORY_ERROR,
            "observed state %r was presented as revocation; suspension and "
            "expiry are not revocation" % observed)
    if observed == REV_REVOKED:
        return RevocationOutcome(claimed, observed, False, "",
                                 "credential is revoked")
    if claimed == REV_ACTIVE and observed == REV_ACTIVE:
        return RevocationOutcome(claimed, observed, True, "",
                                 "credential is active")
    if claimed == REV_SUSPENDED and observed == REV_SUSPENDED:
        return RevocationOutcome(claimed, observed, False, "",
                                 "credential is suspended")
    if claimed == REV_EXPIRED and observed == REV_EXPIRED:
        return RevocationOutcome(claimed, observed, False, "",
                                 "credential is expired")
    raise ValueError("unsupported claimed/observed pair %r/%r"
                     % (claimed, observed))


def to_gate_verdict(chain):
    """Map a ChainResult onto the wave-237 three-outcome gate.

    valid -> PASS; invalid -> TAMPER; indeterminate -> UNDECIDABLE with
    reason "verifier-limit-reached" for ceiling hits else
    "evidence-incomplete"; unsupported -> UNDECIDABLE with the dedicated
    reason "unsupported-profile". The gate Verdict carries only the
    dedicated fold reason: the per-axis verdicts (with their carried
    reason codes, including the ceiling limit name) stay in the
    caller's ChainResult -- nothing is erased, but the limit name and
    per-axis reasons do not ride into the gate Verdict itself.
    Positional
    construction per the wave-237 vocabulary-coverage convention.
    """
    if not isinstance(chain, ChainResult):
        raise ValueError("to_gate_verdict takes a ChainResult")
    if chain.term == VALID:
        return go.Verdict(go.PASS, "")
    if chain.term == INVALID:
        v = _first_reason(chain, INVALID)
        return go.Verdict(
            go.TAMPER,
            "axis %r invalid: %s" % (v.axis, v.reason),
        )
    if chain.term == UNSUPPORTED:
        # The per-axis unsupported verdict (with its carried reason
        # code) is folded into UNDECIDABLE with the dedicated reason;
        # gate_decide reports "could not verify", never "tampered".
        return go.Verdict(go.UNDECIDABLE, GATE_REASON_UNSUPPORTED)
    # INDETERMINATE
    v = _first_reason(chain, INDETERMINATE, CEILING_REASON_PREFIX)
    if v is not None:
        return go.Verdict(go.UNDECIDABLE, GATE_REASON_CEILING)
    return go.Verdict(go.UNDECIDABLE, "evidence-incomplete")
