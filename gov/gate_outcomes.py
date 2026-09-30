"""Three-outcome gate rule (wave-237).

A verifier may return one of three outcomes: PASS, TAMPER, or UNDECIDABLE.
UNDECIDABLE is *failure to verify* -- the verifier could not verify the
evidence (missing trust root, unknown algorithm, truncated or incomplete
evidence). It is never "it looks fine" and never "it was tampered".

The gate rule is fixed:

* ``pass``        -- allow.
* ``tamper``      -- refuse ``gate-tampered``.
* ``undecidable`` -- refuse ``gate-undecidable``. The undecidable refusal
  code is DISTINCT from the tamper code, and the human detail says
  "could not verify", never "tampered": conflating an unverifiable
  artifact with a tampered one is the exact failure this rule exists to
  stop (it turns a cautious verdict into a false accusation, and it
  turns "we could not check" into "we checked and it passed").

The reason for an undecidable verdict is MANDATORY and comes from the
closed ``UNDECIDABLE_REASONS`` vocabulary. A verifier that returns
UNDECIDABLE without a reason -- or with a reason outside the vocabulary --
is refused by the gate contract itself: ``gate-verdict-unreasoned``.
The vocabulary is mandatory, not advisory.

``gate_selfcheck`` is the compliance check for gates themselves: it runs
a probe UNDECIDABLE verdict through a gate function and refuses
``gate-undecidable-allowed`` when the gate allows it (or when it raises
a non-refusal exception on the probe instead of refusing it). A gate
that passes on undecidable -- allow-when-unverified -- is declared
non-compliant.

The four machine refusals, all vocabulary-bound to
``gov/decision_codes.py``:

- ``gate-tampered`` -- a TAMPER verdict is refused; the evidence is
  declared compromised.
- ``gate-undecidable`` -- an UNDECIDABLE verdict is refused; the gate
  reports "could not verify", never "was tampered".
- ``gate-verdict-unreasoned`` -- the gate contract refuses a verdict
  that is itself unreasoned: UNDECIDABLE without a valid WHY.
- ``gate-undecidable-allowed`` -- the compliance self-check declares
  a gate non-compliant for allowing (or crashing on) an undecidable
  verdict.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads.

What this does NOT do (honest boundaries):
- It does not verify anything itself. It is a gate *contract* for
  verifier outcomes: the actual verification is the verifier's job.
  UNDECIDABLE arriving here means the verifier already declined to
  decide; this module only decides what the gate does with that.
- It does not upgrade a TAMPER into a pass and does not downgrade a
  PASS into a refusal. The mapping is one-way per outcome, by design.
- A malformed Verdict (an outcome outside the three, a non-string
  reason) is a programming error (ValueError), not a product refusal --
  the same convention as the trust-material module. Product refusals
  are the four ``gate-`` codes only.
- The compliance self-check is a liveness probe of the gate's
  behavior, not a certification of its verifier: a gate can be
  compliant here and still wrap a broken verifier.
"""

PASS = "pass"
TAMPER = "tamper"
UNDECIDABLE = "undecidable"
OUTCOMES = (PASS, TAMPER, UNDECIDABLE)

GATE_TAMPERED = "gate-tampered"
GATE_UNDECIDABLE = "gate-undecidable"
GATE_VERDICT_UNREASONED = "gate-verdict-unreasoned"
GATE_UNDECIDABLE_ALLOWED = "gate-undecidable-allowed"

# The mandatory closed vocabulary for WHY a verdict is undecidable.
# "evidence-incomplete" covers declared-missing pieces the verifier
# could name; anything outside this set is a contract failure, not
# a new meaning the gate will invent.
#
# Wave-240 (APS -04 axis/result model): "unsupported-profile" folds the
# per-axis UNSUPPORTED term into UNDECIDABLE -- the verifier does not
# implement the receipt's profile, so it could not verify; this is not
# tamper. "verifier-limit-reached" folds a ceiling-induced
# indeterminate (depth/wire/chain limits are verifier properties) into
# UNDECIDABLE. The limit itself is named in the caller's chain result
# (the axis verdict reason, "ceiling:<limit-name>"): the gate reason
# only identifies the fold family, since the wave-237 gate Verdict
# carries (outcome, reason) and no detail slot. Both additions are
# additive: every previously valid reason stays valid.
UNDECIDABLE_REASONS = frozenset((
    "trust-root-missing",
    "algorithm-unknown",
    "evidence-truncated",
    "evidence-incomplete",
    "unsupported-profile",
    "verifier-limit-reached",
))


class GateOutcomeError(Exception):
    """A gate refusal carrying a machine taxonomy code.

    ``code`` is one of the module-level ``GATE_*`` constants;
    ``detail`` is a human sentence. The base exception carries no
    product vocabulary beyond the named refusal.
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s: %s" % (code, detail) if detail else code)


class Verdict:
    """A verifier's verdict at the gate seam.

    ``outcome`` is one of "pass", "tamper", "undecidable". ``reason``
    is a free string for pass/tamper and a MANDATORY closed-vocabulary
    value for undecidable (checked at the gate, not here). Malformed
    construction is a programming error (ValueError).
    """

    __slots__ = ("outcome", "reason")

    def __init__(self, outcome, reason=""):
        if outcome not in OUTCOMES:
            raise ValueError(
                "verdict outcome must be one of %r, got %r"
                % (OUTCOMES, outcome))
        if not isinstance(reason, str):
            raise ValueError("verdict reason must be a string")
        self.outcome = outcome
        self.reason = reason

    def __repr__(self):
        return "Verdict(outcome=%r, reason=%r)" % (self.outcome,
                                                  self.reason)


def gate_decide(verdict):
    """Decide a verdict at the gate.

    PASS allows (returns True). TAMPER refuses ``gate-tampered``.
    UNDECIDABLE with a reason from ``UNDECIDABLE_REASONS`` refuses
    ``gate-undecidable`` (detail says "could not verify", never
    "tampered"). UNDECIDABLE with no reason, or a reason outside the
    vocabulary, refuses ``gate-verdict-unreasoned`` -- the gate
    contract refuses the verdict itself.
    """
    if not isinstance(verdict, Verdict):
        raise ValueError("gate_decide needs a Verdict, got %r"
                         % (type(verdict).__name__,))
    if verdict.outcome == PASS:
        return True
    if verdict.outcome == TAMPER:
        raise GateOutcomeError(
            GATE_TAMPERED,
            "the verifier reported that the evidence was tampered; "
            "the gate refuses")
    # verdict.outcome == UNDECIDABLE from here.
    if verdict.reason not in UNDECIDABLE_REASONS:
        raise GateOutcomeError(
            GATE_VERDICT_UNREASONED,
            "the verifier returned undecidable without a mandatory "
            "reason from the vocabulary %s; the gate contract refuses "
            "the verdict itself" % (sorted(UNDECIDABLE_REASONS),))
    raise GateOutcomeError(
        GATE_UNDECIDABLE,
        "the verifier could not verify the evidence (reason: %s); "
        "undecidable is a failure to verify and the gate refuses "
        "fail-closed" % verdict.reason)


def gate_selfcheck(gate_fn):
    """Compliance self-check for a gate function.

    Runs a probe UNDECIDABLE verdict through ``gate_fn``. When the
    gate allows it -- or when it raises anything other than a clean
    gate refusal -- the self-check refuses ``gate-undecidable-allowed``
    and the gate is declared non-compliant. A gate that refuses the
    probe passes the check and returns ``{"ok": True, ...}`` declaring
    it compliant. Refusals ARE the return path: a compliant gate never
    returns a bare success string.
    """
    # NOTE (w228 idiom-5 boundary): the reason-vocabulary values are NOT
    # refusal codes -- gate_decide only ever emits the four GATE_* codes.
    # This construction is positional on purpose: the w228 inventory
    # treats `reason="..."` keyword literals in gov/ as refusal
    # vocabulary, and these values must not be inventoried as codes.
    probe = Verdict(UNDECIDABLE, "trust-root-missing")
    try:
        allowed = gate_fn(probe)
    except GateOutcomeError:
        return {"ok": True, "compliance": "compliant",
                "checked": UNDECIDABLE,
                "note": "gate refused an undecidable verdict"}
    except Exception as exc:  # noqa: BLE001 -- a crashing gate is not compliant
        raise GateOutcomeError(
            GATE_UNDECIDABLE_ALLOWED,
            "the gate neither allowed nor cleanly refused an "
            "undecidable verdict (raised %s); the gate is "
            "non-compliant" % type(exc).__name__)
    if allowed:
        raise GateOutcomeError(
            GATE_UNDECIDABLE_ALLOWED,
            "the gate allowed an undecidable verdict; undecidable "
            "must refuse, so the gate is non-compliant")
    return {"ok": True, "compliance": "compliant",
            "checked": UNDECIDABLE,
            "note": "gate did not allow an undecidable verdict"}
