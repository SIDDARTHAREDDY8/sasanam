"""Three-outcome conformance oracle (wave-242, W242-6).

ADAPT of draft-farley-acta-signed-receipts -04, section 5.3
"Verification Outcomes" (staged-only draft, NOT on datatracker --
this is probe-oracle language only; NOTHING here claims ACTA
conformance anywhere external). The staged vocabulary's rule: valid
/ invalid / undecidable must be distinguishable in every
consumer-actionable output including exit status; undecidable is
never reported as invalid (nothing shown false) nor valid
(nothing shown true); causes are named.

This module is the oracle for that rule over a shaped receipt
record. ``classify_receipt`` returns a ``gov/gate_outcomes.Verdict``,
so the oracle composes directly with ``gate_outcomes.gate_decide``
and the existing three-outcome gate contract:

* algorithm not in the supported set -> UNDECIDABLE, cause
  "algorithm-unknown". We could not verify; we did not measure
  tamper. This is the exact "green on unmeasured" failure the
  staged draft diagnoses: reporting an unknown-algorithm receipt
  as invalid claims we showed it false, which we did not.
* key_source "embedded" or anything that is not "trust-anchor" ->
  UNDECIDABLE, cause "trust-root-missing". An embedded-only key
  (the staged draft's section 9.5 forbids its use) carries no
  trust anchor: a failing signature against it is NOT tamper we
  measured, it is verification we could not perform.
* supported algorithm + trust-anchored key + signature measured
  false -> TAMPER (invalid). This is the one measured-false case.
* supported algorithm + trust-anchored key + signature measured
  true -> PASS (valid).
* signature not measured at all (``signature_valid`` is None or
  not a bool) -> UNDECIDABLE, cause "evidence-incomplete". An
  unmeasured signature is never reported valid.
* a missing or malformed receipt shape -> UNDECIDABLE, cause
  "evidence-incomplete" (the oracle is total: malformed input is
  evidence the verifier could not characterize, not tamper).

``render_outcome`` is the consumer-actionable rendering:
``{"outcome": "valid" | "invalid" | "undecidable", "cause": ...,
"exit_status": 0 | 2 | 4}``. The three outcomes are pairwise
distinct as strings and as exit statuses: 0 = valid, 2 = invalid
(measured false), 4 = undecidable (could not check).

What this does NOT do (honest boundaries):
- It does not verify signatures itself. The ``signature_valid``
  flag is the verifier's measurement; the oracle only refuses to
  let that measurement be misreported.
- It does not name the supported set from thin air: the default
  is the in-repo algorithm registry's registered names; callers
  may pass an explicit ``supported_algorithms`` set.
- Cause vocabulary is the closed ``UNDECIDABLE_REASONS`` set from
  ``gov/gate_outcomes.py`` -- a cause outside it would be a
  ``gate-verdict-unreasoned`` at the gate.

Stdlib only.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import gate_outcomes as _go

__all__ = [
    "classify_receipt",
    "render_outcome",
    "OUTCOME_VALID",
    "OUTCOME_INVALID",
    "OUTCOME_UNDECIDABLE",
    "EXIT_VALID",
    "EXIT_INVALID",
    "EXIT_UNDECIDABLE",
    "ThreeOutcomeError",
    "KEY_SOURCE_TRUST_ANCHOR",
    "KEY_SOURCE_EMBEDDED",
]


class ThreeOutcomeError(Exception):
    """A programming-error signal from the oracle (not a product
    refusal). classify_receipt is total over receipt-shaped input;
    this is raised only for non-mapping input."""
    pass


OUTCOME_VALID = "valid"
OUTCOME_INVALID = "invalid"
OUTCOME_UNDECIDABLE = "undecidable"

# Deliberately pairwise distinct: measured-false (2) and could-not-
# check (4) are different operational signals; 4 is not "error",
# it is "no measurement".
EXIT_VALID = 0
EXIT_INVALID = 2
EXIT_UNDECIDABLE = 4

KEY_SOURCE_TRUST_ANCHOR = "trust-anchor"
KEY_SOURCE_EMBEDDED = "embedded"


def _default_supported_algorithms():
    try:
        from gov import alg_registry as _ar
        reg = _ar.default_registry()
        names = reg.names()
        if names:
            return frozenset(names)
    except Exception:  # noqa: BLE001 -- registry detail is not
        # oracle vocabulary
        pass
    return frozenset(("ed25519-rfc8032", "hmac-sha256-mac"))


def classify_receipt(receipt, supported_algorithms=None):
    """Classify a shaped receipt record as PASS / TAMPER / UNDECIDABLE.

    ``receipt`` maps {"algorithm": str, "key_source": str,
    "signature_valid": bool | None}. Returns a
    ``gov.gate_outcomes.Verdict`` whose UNDECIDABLE reasons always
    come from the closed UNDECIDABLE_REASONS vocabulary. The oracle
    is total: malformed input yields UNDECIDABLE
    "evidence-incomplete", never TAMPER and never PASS.
    """
    if not isinstance(receipt, dict):
        raise ThreeOutcomeError(
            "classify_receipt needs a mapping, got %r"
            % (type(receipt).__name__,))
    if supported_algorithms is None:
        supported = _default_supported_algorithms()
    else:
        supported = frozenset(supported_algorithms)
    algorithm = receipt.get("algorithm")
    if not isinstance(algorithm, str) or algorithm not in supported:
        return _go.Verdict(_go.UNDECIDABLE, "algorithm-unknown")
    key_source = receipt.get("key_source")
    if key_source != KEY_SOURCE_TRUST_ANCHOR:
        # Embedded-only keys (staged draft section 9.5 forbids use),
        # unknown key sources, and missing key sources all mean the
        # same thing: there is no trust-anchored key, so a failing
        # signature was never measured as tamper.
        return _go.Verdict(_go.UNDECIDABLE, "trust-root-missing")
    measured = receipt.get("signature_valid")
    if measured is True:
        return _go.Verdict(_go.PASS, "")
    if measured is False:
        # The one measured-false case: supported algorithm,
        # trust-anchored key, check ran and failed.
        return _go.Verdict(_go.TAMPER, "")
    return _go.Verdict(_go.UNDECIDABLE, "evidence-incomplete")


def render_outcome(verdict):
    """Render a Verdict for consumers.

    Returns {"outcome", "cause", "exit_status"} with pairwise
    distinct outcomes and exit statuses. Raises ValueError for
    non-Verdict input (programming error, not a product refusal).
    """
    if not isinstance(verdict, _go.Verdict):
        raise ValueError("render_outcome needs a Verdict, got %r"
                         % (type(verdict).__name__,))
    if verdict.outcome == _go.PASS:
        return {"outcome": OUTCOME_VALID, "cause": None,
                "exit_status": EXIT_VALID}
    if verdict.outcome == _go.TAMPER:
        return {"outcome": OUTCOME_INVALID,
                "cause": verdict.reason or None,
                "exit_status": EXIT_INVALID}
    return {"outcome": OUTCOME_UNDECIDABLE, "cause": verdict.reason,
            "exit_status": EXIT_UNDECIDABLE}
