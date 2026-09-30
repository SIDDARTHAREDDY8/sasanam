"""Wave-242 no_effect accepted-and-ignored probes (W242-4, red-first).

draft-saha-aadp-03 section 4.1 (adapted): a SIGNED no_effect refusal
on a NON-failure outcome is accepted, ignored, and recorded in the
reconciliation record's ``detail`` as asserted-and-ignored -- it is
NOT a budget release. The current bound-permit state machine
releases on any signed no_effect; this lane adds the outcome branch.

Probes (seam: gov.bound_permit.reconcile_unknown_outcome with the
new refusal_outcome= keyword):
  no-effect-signed-on-failure-releases -- signed no_effect with
      refusal_outcome="failure" -> state not-executed, budget
      released (pre-existing behavior preserved).
  no-effect-signed-on-success-ignored -- signed no_effect with
      refusal_outcome="success" -> accepted, ignored: state unknown,
      record detail == "no-effect-asserted-and-ignored", budget
      stays committed (falsifies over-release).
  no-effect-signed-on-timeout-ignored -- signed no_effect with
      refusal_outcome="timeout" -> same as success.
  no-effect-unsigned-refused -- unsigned no_effect -> still
      permit-no-effect-unattested, budget stays committed
      (pre-existing behavior preserved).
  no-effect-outcome-mismatch-malformed -- the signed refusal names
      outcome "success" but the caller claims "failure" ->
      permit-malformed (contradictory claims fail closed).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import bound_permit as _bp
    from gov import consumption_ledger as _cl
    HAVE_NEW_API = all(hasattr(_bp, n) for n in (
        "reconcile_unknown_outcome", "issue_permit", "consume_permit",
        "PermitRegistry", "BudgetLedger", "BoundPermitError")) and \
        hasattr(_bp.BudgetLedger, "release")
except ImportError:
    _bp = None
    _cl = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "no-effect-signed-on-failure-releases",
    "no-effect-signed-on-success-ignored",
    "no-effect-signed-on-timeout-ignored",
    "no-effect-unsigned-refused",
    "no-effect-outcome-mismatch-malformed",
]

IGNORED_MARKER = "no-effect-asserted-and-ignored"


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


def _accept(record):
    return True


def _issue(reg, jti):
    return _bp.issue_permit(
        {"action": "deploy", "target": "prod", "trust_tier": "high",
         "decision": "permit"},
        {"mandate": "ops-oncall", "scope": "prod-deploy"},
        {"policy_rev": "r42", "rules_digest": "ab" * 32},
        reg, iss="permit-authority", jti=jti,
        verify_decision=_accept, verify_mandate=_accept,
        verify_policy=_accept)


def _store(ledger):
    return _bp.InMemoryConsumeStore(ledger, durable=True)


def _signed_refusal():
    return {"no_effect": True, "sig": "recipient-sig"}


def _verifier(refusal):
    return refusal.get("sig") == "recipient-sig"


def _reconcile(jti, refusal, verifier, refusal_outcome):
    reg = _bp.PermitRegistry()
    ledger = _cl.ConsumptionLedger()
    store = _store(ledger)
    budget = _bp.BudgetLedger()
    permit = _issue(reg, jti=jti)
    _bp.consume_permit(permit, ledger, consume_store=store)
    record = _bp.reconcile_unknown_outcome(
        permit, ledger, reg, budget=budget,
        no_effect_refusal=refusal,
        verify_refusal_signature=verifier,
        refusal_outcome=refusal_outcome)
    return record, budget.state("permit-authority", jti)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_signed_on_failure_releases():
    record, bstate = _reconcile(
        "jti-nf", _signed_refusal(), _verifier, "failure")
    assert record["state"] == "not-executed", record
    assert bstate["released"] is True, bstate
    return "state not-executed, budget released"


def _probe_signed_on_success_ignored():
    record, bstate = _reconcile(
        "jti-ns", _signed_refusal(), _verifier, "success")
    assert record["state"] == "unknown", record
    assert record.get("detail") == IGNORED_MARKER, record
    assert bstate["committed"] is True and bstate["released"] is False, \
        bstate
    return "accepted+ignored, detail=%s, budget stays committed" % \
        IGNORED_MARKER


def _probe_signed_on_timeout_ignored():
    record, bstate = _reconcile(
        "jti-nt", _signed_refusal(), _verifier, "timeout")
    assert record["state"] == "unknown", record
    assert record.get("detail") == IGNORED_MARKER, record
    assert bstate["committed"] is True and bstate["released"] is False, \
        bstate
    return "accepted+ignored, detail=%s, budget stays committed" % \
        IGNORED_MARKER


def _probe_unsigned_refused():
    reg = _bp.PermitRegistry()
    ledger = _cl.ConsumptionLedger()
    store = _store(ledger)
    budget = _bp.BudgetLedger()
    permit = _issue(reg, jti="jti-nu")
    _bp.consume_permit(permit, ledger, consume_store=store)
    try:
        _bp.reconcile_unknown_outcome(
            permit, ledger, reg, budget=budget,
            no_effect_refusal={"no_effect": True},
            verify_refusal_signature=None,
            refusal_outcome="success")
    except _bp.BoundPermitError as exc:
        assert exc.code == "permit-no-effect-unattested", exc.code
    else:
        raise AssertionError("unsigned no_effect passed")
    bstate = budget.state("permit-authority", "jti-nu")
    assert bstate["released"] is False, bstate
    return "refused permit-no-effect-unattested, budget stays committed"


def _probe_outcome_mismatch_malformed():
    refusal = {"no_effect": True, "sig": "recipient-sig",
               "outcome": "success"}
    reg = _bp.PermitRegistry()
    ledger = _cl.ConsumptionLedger()
    store = _store(ledger)
    budget = _bp.BudgetLedger()
    permit = _issue(reg, jti="jti-nm")
    _bp.consume_permit(permit, ledger, consume_store=store)
    try:
        _bp.reconcile_unknown_outcome(
            permit, ledger, reg, budget=budget,
            no_effect_refusal=refusal,
            verify_refusal_signature=_verifier,
            refusal_outcome="failure")
    except _bp.BoundPermitError as exc:
        assert exc.code == "permit-malformed", exc.code
    else:
        raise AssertionError("contradictory outcome claims passed")
    return "contradictory refusal/caller outcome refused malformed"


_PROBES = {
    "no-effect-signed-on-failure-releases": _probe_signed_on_failure_releases,
    "no-effect-signed-on-success-ignored": _probe_signed_on_success_ignored,
    "no-effect-signed-on-timeout-ignored": _probe_signed_on_timeout_ignored,
    "no-effect-unsigned-refused": _probe_unsigned_refused,
    "no-effect-outcome-mismatch-malformed":
        _probe_outcome_mismatch_malformed,
}


def main():
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, s, _ in results if s == "HELD")
    gap = sum(1 for _, s, _ in results if s == "GAP")
    for name, status, note in results:
        print("%s %s: %s" % (status, name, note.splitlines()[0]))
    print("w242-no-effect-branch: %d HELD / %d GAP / %d total"
          % (held, gap, len(results)))
    return 0 if all(s in ("HELD", "GAP") for _, s, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
