"""Four-term outcome vocabulary (wave-243, W243-4).

ADAPT of draft-schrock-ae-challenge -08 (prose/pattern only; no draft
text copied; this module makes NO conformance claim anywhere
external). The staged vocabulary's rule: VERIFIED (crypto and
structural checks measured PASS) says NOTHING about trust; ACCEPTED
is VERIFIED plus the relying party's pinned trust inputs; SATISFIED
is evidence requirements met -- evidence SUFFICIENCY only, never
authorization; UNSATISFIED is everything else. The separation is the
exact conflation our refusal layer refuses to make: crypto measured
true presented as authorization.

Terms:

* ``VERIFIED`` -- crypto_ok and structural_ok both measured True.
  This is the strongest claim the crypto layer can make, and it is
  a statement about bytes, not about authority.
* ``ACCEPTED`` -- VERIFIED plus the evidence's trust inputs match
  the relying party's pinned trust inputs (named issuers/keys).
  Trust-input mismatch is never ACCEPTED: it stays VERIFIED with
  reason "trust-inputs-unmet".
* ``SATISFIED`` -- the relying party's evidence REQUIREMENTS are
  met (on top of at least VERIFIED). Sufficiency, never
  authorization.
* ``UNSATISFIED`` -- measured-false, unmeasured, unverifiable, or
  requirements unmet.

The module also carries an evaluation-lineage profile: a lineage
chain binds each link to its predecessor challenge and successor
reference. ``verify_lineage`` refuses ``lineage-gap`` when a link
skips its predecessor -- a lineage that skips its predecessor is
BROKEN, not shortened.

Composition with the three-outcome oracle
(``gov/three_outcome_conformance.py``): the three outcomes answer
"could we verify?" (valid = measured true, invalid = measured
false, undecidable = could not check). The four terms answer "how
far up the trust ladder does the evidence go?". Three-outcome
"valid" composes to at most four-term VERIFIED: a signature
measured true under a trust anchor still says nothing about
authorization. ``classify_receipt_terms`` is the composition
function; it extends the oracle without duplicating it.

What this does NOT do (honest boundaries):
- It does not verify anything itself. ``crypto_ok`` and
  ``structural_ok`` are the verifier's measurements; this module
  only grades them and refuses to let the grade be misreported.
- It does not authorize anything. SATISFIED is the highest grade
  and it still authorizes nothing; the only refusal here is
  against presenting less as more (``satisfied-missing``).
- Trust inputs and requirements are caller-supplied policy; the
  module never invents them. An evidence record that does not
  carry ``trust_inputs_match`` against declared trust inputs is
  VERIFIED, not ACCEPTED.
- The lineage profile binds bytes and links; it does not prove
  the runs actually happened.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no
env reads.
"""

import hashlib

__all__ = [
    "VERIFIED",
    "ACCEPTED",
    "SATISFIED",
    "UNSATISFIED",
    "TERMS",
    "Grade",
    "classify_evidence",
    "accept_report",
    "verify_lineage",
    "classify_receipt_terms",
    "OutcomeVocabularyError",
    "SATISFIED_MISSING",
    "LINEAGE_GAP",
    "OUTCOME_TO_TERM",
]

VERIFIED = "VERIFIED"
ACCEPTED = "ACCEPTED"
SATISFIED = "SATISFIED"
UNSATISFIED = "UNSATISFIED"
TERMS = (VERIFIED, ACCEPTED, SATISFIED, UNSATISFIED)

# The two machine refusals, vocabulary-bound to gov/decision_codes.py.
SATISFIED_MISSING = "satisfied-missing"
LINEAGE_GAP = "lineage-gap"

# Three-outcome "valid" is at most VERIFIED; "invalid" and
# "undecidable" are both UNSATISFIED (measured-false and
# could-not-check are different operationally, which is why the
# cause is preserved in the grade reason, not folded here).
OUTCOME_TO_TERM = {"valid": VERIFIED, "invalid": UNSATISFIED,
                   "undecidable": UNSATISFIED}

# Claims a report may carry. "authorized" and "satisfied" are
# strength claims: the grade must back them. "evidence-grade" only
# asks for the grade.
_CLAIM_AUTHORIZED = "authorized"
_CLAIM_SATISFIED = "satisfied"
_CLAIM_GRADE = "evidence-grade"
_CLAIMS = (_CLAIM_AUTHORIZED, _CLAIM_SATISFIED, _CLAIM_GRADE)


class OutcomeVocabularyError(Exception):
    """A vocabulary refusal carrying a machine taxonomy code.

    ``code`` is one of the module-level constants
    (``satisfied-missing`` / ``lineage-gap``); ``detail`` is a human
    sentence. Raised for product refusals only; programming errors
    (non-mapping input) are ValueError-adjacent -- the same
    convention as the three-outcome oracle's ThreeOutcomeError.
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super(OutcomeVocabularyError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)


class Grade(object):
    """The four-term grade of a piece of evidence.

    ``term`` is one of the four terms; ``reason`` is a closed
    machine string explaining the grade ("trust-inputs-unmet",
    "requirements-unmet", "evidence-incomplete", "evidence-false",
    "tamper-measured", "unverifiable:<cause>", or "" when the term
    itself is the whole story).
    """

    __slots__ = ("term", "reason")

    def __init__(self, term, reason=""):
        if term not in TERMS:
            raise ValueError("Grade term must be one of %r, got %r"
                             % (TERMS, term))
        if not isinstance(reason, str):
            raise ValueError("Grade reason must be a string")
        self.term = term
        self.reason = reason

    def __repr__(self):
        return "Grade(%r, %r)" % (self.term, self.reason)

    def __eq__(self, other):
        return (isinstance(other, Grade)
                and self.term == other.term
                and self.reason == other.reason)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.term, self.reason))


def _is_true(value):
    return value is True


def _measurement_grade(evidence):
    """Grade the raw crypto+structural measurement (no policy)."""
    crypto = evidence.get("crypto_ok")
    structural = evidence.get("structural_ok")
    if crypto is None or structural is None:
        return Grade(UNSATISFIED, "evidence-incomplete")
    if not _is_true(crypto) or not _is_true(structural):
        return Grade(UNSATISFIED, "evidence-false")
    return Grade(VERIFIED, "")


def classify_evidence(evidence, trust_inputs=None, requirements=None):
    """Grade evidence on the four-term ladder.

    ``evidence`` maps {"crypto_ok": bool|None, "structural_ok":
    bool|None} and optionally carries "trust_inputs_match" (bool)
    and "requirements_met" (bool) measured by the caller. When
    ``trust_inputs`` (a pinned-trust-inputs record) is provided, the
    grade only reaches ACCEPTED if the evidence's
    "trust_inputs_match" is True; a mismatch stays VERIFIED with
    reason "trust-inputs-unmet" -- it is never ACCEPTED silently.
    When ``requirements`` (an evidence-requirements record) is
    provided, the grade only reaches SATISFIED if the evidence's
    "requirements_met" is True; unmet requirements keep the grade
    with reason "requirements-unmet".

    Non-mapping input is a programming error (ValueError), the same
    convention as the three-outcome oracle's ThreeOutcomeError.
    """
    if not isinstance(evidence, dict):
        raise ValueError("classify_evidence needs a mapping, got %r"
                         % (type(evidence).__name__,))
    grade = _measurement_grade(evidence)
    if grade.term != VERIFIED:
        return grade
    if trust_inputs is not None:
        if _is_true(evidence.get("trust_inputs_match")):
            grade = Grade(ACCEPTED, "")
        else:
            # Measured bytes, unmeasured trust: the honest grade is
            # VERIFIED -- the ladder stops here until the trust
            # inputs are pinned and matched.
            return Grade(VERIFIED, "trust-inputs-unmet")
    if requirements is not None:
        if _is_true(evidence.get("requirements_met")):
            grade = Grade(SATISFIED, "")
        else:
            return Grade(grade.term, "requirements-unmet")
    return grade


def accept_report(report):
    """Map a gate report into the four-term vocabulary.

    ``report`` maps {"verdict": gate_outcomes.Verdict, "evidence":
    {...}, "trust_inputs": ..., "requirements": ..., "claim":
    "authorized" | "satisfied" | "evidence-grade" | None}. The
    verdict decides the floor:

    * TAMPER -> UNSATISFIED, reason "tamper-measured" (measured
      false, never satisfied).
    * UNDECIDABLE -> UNSATISFIED, reason "unverifiable:<cause>".
      Unverifiable is never SATISFIED and never ACCEPTED.
    * PASS -> ``classify_evidence`` on the rest of the report.

    The claim is then checked against the grade: claim
    "authorized" with anything below SATISFIED refuses
    ``satisfied-missing`` -- VERIFIED (crypto measured true) is
    not authorization, and the module refuses the conflation
    loudly. Claim "satisfied" with anything below SATISFIED
    refuses ``satisfied-missing`` as well: SATISFIED names
    evidence sufficiency, and sufficiency cannot be asserted
    without the requirements met.

    Returns the Grade. Non-Verdict verdicts and non-mapping
    reports are programming errors (ValueError).
    """
    from gov import gate_outcomes as _go

    if not isinstance(report, dict):
        raise ValueError("accept_report needs a mapping, got %r"
                         % (type(report).__name__,))
    verdict = report.get("verdict")
    if not isinstance(verdict, _go.Verdict):
        raise ValueError("accept_report needs a gate_outcomes.Verdict")
    claim = report.get("claim")
    if claim is not None and claim not in _CLAIMS:
        raise ValueError("accept_report claim must be one of %r, got %r"
                         % (_CLAIMS, claim))
    if verdict.outcome == _go.TAMPER:
        grade = Grade(UNSATISFIED, "tamper-measured")
    elif verdict.outcome == _go.UNDECIDABLE:
        grade = Grade(UNSATISFIED,
                      "unverifiable:%s" % (verdict.reason or "unknown"))
    else:
        grade = classify_evidence(
            report.get("evidence") or {},
            trust_inputs=report.get("trust_inputs"),
            requirements=report.get("requirements"))
    if claim in (_CLAIM_AUTHORIZED, _CLAIM_SATISFIED) \
            and grade.term != SATISFIED:
        raise OutcomeVocabularyError(
            SATISFIED_MISSING,
            "claim %r requires grade SATISFIED; evidence grades %s "
            "(%s) -- VERIFIED (crypto measured true) is not "
            "authorization and unverifiable/satisfied-unmet "
            "evidence is not satisfied"
            % (claim, grade.term, grade.reason or "no reason"))
    return grade


def _lineage_digest(chain):
    h = hashlib.sha256()
    for link in chain:
        h.update(repr((link["id"], link["predecessor"],
                       link["challenge"])).encode("utf-8"))
    return h.hexdigest()


def verify_lineage(chain, expected_predecessor=None):
    """Verify an evaluation-lineage chain and bind its terminal.

    ``chain`` is a list of {"id": str, "predecessor": str|None,
    "challenge": str} links in order. Every link after the first
    must name the previous link's id as its predecessor; the
    genesis link's predecessor is the anchor. When
    ``expected_predecessor`` is given, the genesis link must bind
    to it. A link that skips its predecessor -- or a genesis that
    does not bind the expected anchor -- refuses ``lineage-gap``:
    the chain is broken, not shortened. Empty chains are refused
    ``lineage-gap``: a lineage that binds nothing is broken.

    Returns {"terminal": <last id>, "binding": <sha256 of the
    chain>}. Malformed link shapes (non-mapping, missing keys,
    non-string ids) are programming errors (ValueError), not
    product refusals.
    """
    if not isinstance(chain, (list, tuple)) or not chain:
        raise OutcomeVocabularyError(
            LINEAGE_GAP,
            "evaluation lineage is empty: a lineage that binds "
            "nothing is broken, not shortened")
    prev_id = None
    for index, link in enumerate(chain):
        if not isinstance(link, dict):
            raise ValueError("lineage link %d must be a mapping" % index)
        for key in ("id", "predecessor", "challenge"):
            if key not in link:
                raise ValueError("lineage link %d missing key %r"
                                 % (index, key))
        link_id = link["id"]
        if not isinstance(link_id, str) or not link_id:
            raise ValueError("lineage link %d id must be a non-empty "
                             "string" % index)
        want = prev_id if index else expected_predecessor
        if want is not None and link["predecessor"] != want:
            raise OutcomeVocabularyError(
                LINEAGE_GAP,
                "lineage link %r skips its predecessor: expected "
                "predecessor %r, got %r -- the chain is broken, not "
                "shortened" % (link_id, want, link["predecessor"]))
        prev_id = link_id
    return {"terminal": prev_id, "binding": _lineage_digest(chain)}


def classify_receipt_terms(receipt, trust_inputs=None, requirements=None,
                           supported_algorithms=None):
    """Compose the three-outcome oracle with the four-term ladder.

    Runs ``gov/three_outcome_conformance.classify_receipt`` and
    grades the result: "valid" (measured true under a trust
    anchor) is at most VERIFIED -- it climbs the ladder only via
    pinned trust inputs (ACCEPTED) and met requirements
    (SATISFIED). "invalid" and "undecidable" are UNSATISFIED with
    the oracle's cause preserved in the grade reason.

    Returns (verdict, grade, rendered) where verdict is the
    oracle's gate_outcomes.Verdict and rendered is its
    consumer-actionable rendering. This extends the oracle without
    duplicating it: the oracle still owns verifiability; this
    module owns the trust ladder.
    """
    from gov import three_outcome_conformance as _oc
    from gov import gate_outcomes as _go

    verdict = _oc.classify_receipt(
        receipt, supported_algorithms=supported_algorithms)
    rendered = _oc.render_outcome(verdict)
    if verdict.outcome == _go.TAMPER:
        grade = Grade(UNSATISFIED, "tamper-measured")
    elif verdict.outcome == _go.UNDECIDABLE:
        grade = Grade(UNSATISFIED,
                      "unverifiable:%s" % (verdict.reason or "unknown"))
    else:
        evidence = {"crypto_ok": True, "structural_ok": True}
        if trust_inputs is not None:
            evidence["trust_inputs_match"] = \
                receipt.get("trust_inputs_match", False) \
                if isinstance(receipt, dict) else False
        if requirements is not None:
            evidence["requirements_met"] = \
                receipt.get("requirements_met", False) \
                if isinstance(receipt, dict) else False
        grade = classify_evidence(evidence, trust_inputs=trust_inputs,
                                  requirements=requirements)
    return verdict, grade, rendered
