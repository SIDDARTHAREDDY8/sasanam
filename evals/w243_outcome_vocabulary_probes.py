#!/usr/bin/env python3
"""Wave-243 four-term outcome vocabulary probes (W243-4, red-first).

ADAPT of draft-schrock-ae-challenge -08 (prose/pattern only; no draft
text copied; this battery makes NO conformance claim). The staged
vocabulary's rule: VERIFIED (crypto+structural pass) says NOTHING
about trust; ACCEPTED = VERIFIED + the relying party's pinned trust
inputs; SATISFIED = evidence requirements met (sufficiency ONLY, not
authorization); UNSATISFIED = everything else. The exact conflation
our refusal layer refuses to make: crypto measured true presented as
authorization.

This battery probes ``gov/outcome_vocabulary.py``:

  vocabulary-verified-not-authorization -- VERIFIED-grade evidence
      presented with claim "authorized" is refused
      ``satisfied-missing`` (never silently accepted).
  vocabulary-valid-means-verified -- a PASS verdict with only crypto
      measured (no trust inputs, no requirements) grades VERIFIED --
      the renamed "valid" -- never ACCEPTED/SATISFIED/authorized.
  vocabulary-undecidable-never-satisfied -- an UNDECIDABLE verdict
      presented as "satisfied" is refused ``satisfied-missing``:
      unverifiable is never satisfied.
  vocabulary-tamper-unsatisfied -- a TAMPER verdict grades
      UNSATISFIED with cause "tamper-measured".
  vocabulary-accepted-needs-trust -- trust inputs matching the pinned
      set upgrade VERIFIED to ACCEPTED; mismatched trust inputs stay
      VERIFIED with reason "trust-inputs-unmet" (never ACCEPTED).
  vocabulary-satisfied-needs-requirements -- requirements met upgrade
      to SATISFIED; claiming "satisfied" with requirements unmet is
      refused ``satisfied-missing``.
  vocabulary-lineage-gap -- an evaluation lineage that skips its
      predecessor is refused ``lineage-gap`` (broken, not shortened).
  vocabulary-lineage-happy -- a continuous lineage verifies and binds
      its terminal id.
  vocabulary-composition -- three-outcome "valid" composes to at most
      four-term VERIFIED; "undecidable" composes to UNSATISFIED. The
      three outcomes answer "could we verify?"; the four terms answer
      "how far up the trust ladder does the evidence go?".
  vocabulary-claim-satisfied-requires-satisfied -- claim "satisfied"
      on VERIFIED-grade evidence is refused ``satisfied-missing``.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import outcome_vocabulary as _ov
    HAVE_NEW_API = all(hasattr(_ov, n) for n in (
        "classify_evidence", "accept_report", "verify_lineage",
        "classify_receipt_terms", "VERIFIED", "ACCEPTED",
        "SATISFIED", "UNSATISFIED", "OutcomeVocabularyError",
        "SATISFIED_MISSING", "LINEAGE_GAP"))
    from gov import gate_outcomes as _go
    from gov import three_outcome_conformance as _oc
    HAVE_NEW_API = HAVE_NEW_API and hasattr(_go, "GateOutcomeError")
except ImportError:
    _ov = None
    _go = None
    _oc = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _verdict(outcome, reason=""):
    return _go.Verdict(outcome, reason)


def _probe_verified_not_authorization():
    report = {
        "verdict": _verdict(_go.PASS, ""),
        "evidence": {"crypto_ok": True, "structural_ok": True},
        "claim": "authorized",
    }
    try:
        _ov.accept_report(report)
    except _ov.OutcomeVocabularyError as exc:
        assert exc.code == _ov.SATISFIED_MISSING == "satisfied-missing", \
            "must refuse satisfied-missing, got %r" % (exc.code,)
        return "refused satisfied-missing, never silently authorized"
    raise AssertionError("VERIFIED evidence presented as authorized "
                         "was silently accepted")


def _probe_valid_means_verified():
    report = {
        "verdict": _verdict(_go.PASS, ""),
        "evidence": {"crypto_ok": True, "structural_ok": True},
        "claim": "evidence-grade",
    }
    grade = _ov.accept_report(report)
    assert grade.term == _ov.VERIFIED, \
        "crypto-only PASS must grade VERIFIED, got %r" % (grade.term,)
    assert grade.term not in (_ov.ACCEPTED, _ov.SATISFIED), \
        "crypto-only evidence must never grade ACCEPTED/SATISFIED"
    return "crypto-only PASS renamed to VERIFIED, never authorized"


def _probe_undecidable_never_satisfied():
    report = {
        "verdict": _verdict(_go.UNDECIDABLE, "trust-root-missing"),
        "evidence": {"crypto_ok": True, "structural_ok": True},
        "claim": "satisfied",
    }
    try:
        _ov.accept_report(report)
    except _ov.OutcomeVocabularyError as exc:
        assert exc.code == "satisfied-missing", \
            "must refuse satisfied-missing, got %r" % (exc.code,)
        return "undecidable presented as satisfied refused"
    raise AssertionError("undecidable evidence presented as satisfied "
                         "was silently accepted")


def _probe_tamper_unsatisfied():
    report = {
        "verdict": _verdict(_go.TAMPER, ""),
        "evidence": {"crypto_ok": False, "structural_ok": True},
        "claim": "evidence-grade",
    }
    grade = _ov.accept_report(report)
    assert grade.term == _ov.UNSATISFIED, \
        "tamper must grade UNSATISFIED, got %r" % (grade.term,)
    assert grade.reason == "tamper-measured", \
        "cause must be tamper-measured, got %r" % (grade.reason,)
    return "tamper -> UNSATISFIED (tamper-measured)"


def _probe_accepted_needs_trust():
    good = _ov.classify_evidence(
        {"crypto_ok": True, "structural_ok": True,
         "trust_inputs_match": True},
        trust_inputs={"pinned_issuer": "example"})
    assert good.term == _ov.ACCEPTED, \
        "matching trust inputs must grade ACCEPTED, got %r" % (good.term,)
    bad = _ov.classify_evidence(
        {"crypto_ok": True, "structural_ok": True,
         "trust_inputs_match": False},
        trust_inputs={"pinned_issuer": "example"})
    assert bad.term == _ov.VERIFIED, \
        "mismatched trust inputs must stay VERIFIED, got %r" % (bad.term,)
    assert bad.reason == "trust-inputs-unmet", \
        "reason must be trust-inputs-unmet, got %r" % (bad.reason,)
    return "ACCEPTED only with pinned trust inputs; else VERIFIED"


def _probe_satisfied_needs_requirements():
    met = _ov.classify_evidence(
        {"crypto_ok": True, "structural_ok": True,
         "trust_inputs_match": True, "requirements_met": True},
        trust_inputs={"pinned_issuer": "example"},
        requirements={"min_checks": 2})
    assert met.term == _ov.SATISFIED, \
        "requirements met must grade SATISFIED, got %r" % (met.term,)
    report = {
        "verdict": _verdict(_go.PASS, ""),
        "evidence": {"crypto_ok": True, "structural_ok": True,
                     "trust_inputs_match": True,
                     "requirements_met": False},
        "trust_inputs": {"pinned_issuer": "example"},
        "requirements": {"min_checks": 2},
        "claim": "satisfied",
    }
    try:
        _ov.accept_report(report)
    except _ov.OutcomeVocabularyError as exc:
        assert exc.code == "satisfied-missing"
        return "SATISFIED only when requirements met; else refused"
    raise AssertionError("claim 'satisfied' with requirements unmet was "
                         "silently accepted")


def _probe_lineage_gap():
    chain = [
        {"id": "run-1", "predecessor": None, "challenge": "c1"},
        {"id": "run-3", "predecessor": "run-1", "challenge": "c3"},
        # run-3 skips run-2: broken, not shortened.
        {"id": "run-4", "predecessor": "run-3", "challenge": "c4"},
    ]
    chain[1]["predecessor"] = "run-2-missing"
    try:
        _ov.verify_lineage(chain)
    except _ov.OutcomeVocabularyError as exc:
        assert exc.code == _ov.LINEAGE_GAP == "lineage-gap", \
            "must refuse lineage-gap, got %r" % (exc.code,)
        return "skipped predecessor refused lineage-gap"
    raise AssertionError("lineage with a skipped predecessor verified")


def _probe_lineage_happy():
    chain = [
        {"id": "run-1", "predecessor": None, "challenge": "c1"},
        {"id": "run-2", "predecessor": "run-1", "challenge": "c2"},
        {"id": "run-3", "predecessor": "run-2", "challenge": "c3"},
    ]
    binding = _ov.verify_lineage(chain)
    assert binding["terminal"] == "run-3", \
        "terminal must be run-3, got %r" % (binding.get("terminal"),)
    assert isinstance(binding["binding"], str) and binding["binding"], \
        "binding must be a non-empty digest string"
    return "continuous lineage bound to terminal run-3"


def _probe_composition():
    good = {"algorithm": "ed25519-rfc8032", "key_source": "trust-anchor",
            "signature_valid": True}
    verdict, grade, rendered = _ov.classify_receipt_terms(good)
    assert rendered["outcome"] == _oc.OUTCOME_VALID
    assert grade.term == _ov.VERIFIED, \
        "three-outcome 'valid' composes to at most VERIFIED, got %r" \
        % (grade.term,)
    unmeasured = {"algorithm": "ed25519-rfc8032",
                  "key_source": "trust-anchor", "signature_valid": None}
    verdict2, grade2, rendered2 = _ov.classify_receipt_terms(unmeasured)
    assert rendered2["outcome"] == _oc.OUTCOME_UNDECIDABLE
    assert grade2.term == _ov.UNSATISFIED, \
        "three-outcome 'undecidable' composes to UNSATISFIED, got %r" \
        % (grade2.term,)
    return "valid -> VERIFIED (at most); undecidable -> UNSATISFIED"


def _probe_claim_satisfied_requires_satisfied():
    report = {
        "verdict": _verdict(_go.PASS, ""),
        "evidence": {"crypto_ok": True, "structural_ok": True},
        "claim": "satisfied",
    }
    try:
        _ov.accept_report(report)
    except _ov.OutcomeVocabularyError as exc:
        assert exc.code == "satisfied-missing", \
            "must refuse satisfied-missing, got %r" % (exc.code,)
        return "claim 'satisfied' on VERIFIED refused satisfied-missing"
    raise AssertionError("claim 'satisfied' on VERIFIED evidence was "
                         "silently accepted")


_PROBES = {
    "vocabulary-verified-not-authorization": _probe_verified_not_authorization,
    "vocabulary-valid-means-verified": _probe_valid_means_verified,
    "vocabulary-undecidable-never-satisfied":
        _probe_undecidable_never_satisfied,
    "vocabulary-tamper-unsatisfied": _probe_tamper_unsatisfied,
    "vocabulary-accepted-needs-trust": _probe_accepted_needs_trust,
    "vocabulary-satisfied-needs-requirements":
        _probe_satisfied_needs_requirements,
    "vocabulary-lineage-gap": _probe_lineage_gap,
    "vocabulary-lineage-happy": _probe_lineage_happy,
    "vocabulary-composition": _probe_composition,
    "vocabulary-claim-satisfied-requires-satisfied":
        _probe_claim_satisfied_requires_satisfied,
}


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import gate_outcomes as _g
        assert _g.gate_decide(_g.Verdict(_g.PASS, "")) is True
        assert _g.OUTCOMES == (_g.PASS, _g.TAMPER, _g.UNDECIDABLE)
        notes.append("gate_outcomes contract intact")
    except Exception as exc:  # noqa: BLE001
        notes.append("gate contract check FAILED: %r" % (exc,))
    try:
        from gov import three_outcome_conformance as _t
        v = _t.classify_receipt({"algorithm": "ed25519-rfc8032",
                                 "key_source": "trust-anchor",
                                 "signature_valid": True})
        r = _t.render_outcome(v)
        assert r["outcome"] == _t.OUTCOME_VALID and r["exit_status"] == 0
        notes.append("three_outcome_conformance intact")
    except Exception as exc:  # noqa: BLE001
        notes.append("three-outcome check FAILED: %r" % (exc,))
    try:
        from gov import decision_codes as _dc
        for code in ("satisfied-missing", "lineage-gap"):
            rec = _dc.code_for(code)
            assert rec["code"] == code
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-243 outcome-vocabulary probes (new API: %s)" % HAVE_NEW_API)
    results = []
    for name in _PROBES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-46s %s %s" % (name, verdict, note))
    print("HELD %d / GAP %d / BREAK %d / ERROR %d" % (held, gap, brk, err))
    for note in _run_green_checks():
        print("green-check: %s" % note)
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
