#!/usr/bin/env python3
"""Wave-235 lane B: bound-permit conjunction (permit = decision ^ mandate ^ policy).

Attack shapes at the public seams (break-first, red-first on base):
* a permit is issuable only when THREE legs verify independently
  (decision record, mandate record, local policy binding): any leg
  refusing means the permit refuses with the LEG'S EXACT refusal code
  (no leg overrules another);
* a permit issued without a mandate refuses ``permit-mandate-absent``;
  without a policy binding ``permit-policy-absent``; without a decision
  ``permit-decision-absent``;
* consumption is atomic in the wave-234 consumption-ledger semantics:
  double-submit of a consumed permit yields exactly one execution.
  Wave-240 (saha S12) supersedes the old named ``previously-consumed``
  RAISE at this seam: the replay now returns the stored result and is
  recorded as a repeat (probe p2 pins the new semantics);
* unknown outcomes reconcile via jti: ``reconcile_unknown_outcome``
  never re-mints a permit and never retries execution -- it returns a
  reconciliation record naming (iss, jti) and its state
  (completed / unknown / not-executed); a fresh permit for the same
  (iss, jti) after an unknown outcome refuses ``permit-jti-duplicate``
  until a reconciliation record exists;
* two permits differing only in trust tier are not matched as one:
  consumption and reconciliation are keyed to the frozen instance
  digest, never to a bare action id.

Seams under test:
* gov/bound_permit.py -- PermitRegistry, issue_permit, consume_permit,
  execute_permit, reconcile_unknown_outcome, verify_permit.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-234 HEAD 0390dcbd2e65a7d7b15f8c1b0c89efe1807f63d7.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g235b
  TMPDIR=/var/tmp/g235b ~/workspace/.gov-venv/bin/python evals/w235_boundpermit_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import bound_permit as _bp
    from gov import consumption_ledger as _cl
    HAVE_NEW_API = all(hasattr(_bp, n) for n in (
        "BoundPermitError", "PermitRegistry", "issue_permit",
        "consume_permit", "execute_permit", "reconcile_unknown_outcome",
        "verify_permit"))
except ImportError:
    _bp = None
    _cl = None

PROBE_NAMES = [
    "boundpermit-issue-happy-path",
    "boundpermit-double-submit-one-execution",
    "boundpermit-mandate-absent",
    "boundpermit-policy-absent",
    "boundpermit-leg-refusal-propagates-exact-code",
    "boundpermit-unknown-outcome-reconciles",
    "boundpermit-trust-tier-not-matched",
    "boundpermit-tampered-permit-refused",
]


class _LegRefused(Exception):
    """Battery-local leg verifier refusal with a real taxonomy code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _accept(record):
    return True


def _decision():
    return {"action": "deploy", "target": "prod",
            "trust_tier": "high", "decision": "permit"}


def _mandate():
    return {"mandate": "ops-oncall", "scope": "prod-deploy"}


def _policy():
    return {"policy_rev": "r42", "rules_digest": "ab" * 32}


def _issue(reg, iss="permit-authority", jti="jti-001",
           decision=None, mandate="default", policy="default"):
    return _bp.issue_permit(
        _decision() if decision is None else decision,
        _mandate() if mandate == "default" else mandate,
        _policy() if policy == "default" else policy,
        reg, iss=iss, jti=jti,
        verify_decision=_accept, verify_mandate=_accept,
        verify_policy=_accept)


def _expect_code(fn, code):
    """Run fn; return ("HELD", detail) iff an exception with the
    exact machine code is raised, else ("BREAK"/"ERROR", detail)."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - battery records, never masks
        got = getattr(exc, "code", None)
        if got is None:
            got = type(exc).__name__
        if got == code:
            return ("HELD", "raised %r" % (got,))
        return ("BREAK", "wrong code: %r (want %r): %s"
                % (got, code, str(exc)[:160]))
    return ("BREAK", "no refusal raised (want %r)" % (code,))


def _rec(results, name, verdict, detail=""):
    results[name] = verdict if not detail else "%s\n  %s" % (verdict, detail)


def _p1_happy(results):
    try:
        reg = _bp.PermitRegistry()
        permit = _issue(reg)
        assert permit["iss"] == "permit-authority", permit
        assert permit["jti"] == "jti-001", permit
        assert len(permit["instance_digest"]) == 64, permit
        assert len(permit["permit_digest"]) == 64, permit
        assert len(permit["decision_digest"]) == 64, permit
        assert _bp.verify_permit(permit) is True
        # Registry claimed the (iss, jti) slot.
        entry = reg.lookup("permit-authority", "jti-001")
        assert entry is not None and entry["permit"] is not None, entry
        _rec(results, PROBE_NAMES[0], "HELD",
             "permit_digest=%s..." % permit["permit_digest"][:16])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


def _p2_double_submit(results):
    # Wave-240 NOTE (saha S12 supersedes the wave-235 raise): the
    # replay now returns the STORED result and is recorded as a
    # repeat -- the exactly-once invariant is the executor running
    # exactly once, not a raise.
    try:
        reg = _bp.PermitRegistry()
        ledger = _cl.ConsumptionLedger()
        store = _bp.InMemoryConsumeStore(ledger, durable=True)
        permit = _issue(reg, jti="jti-002")
        calls = []

        def _execute(p):
            calls.append(p["jti"])
            return {"executed": True}

        receipt, out = _bp.execute_permit(permit, ledger,
                                          execute=_execute,
                                          consume_store=store)
        assert receipt["outcome"] == "consumed", receipt
        assert out == {"executed": True}, out
        # Second submit: stored result, executor NOT re-run, repeat
        # recorded -- before the executor runs.
        record2, out2 = _bp.execute_permit(permit, ledger,
                                           execute=_execute,
                                           consume_store=store)
        assert record2["outcome"] == "replayed", record2
        assert record2["repeat_recorded"] is True, record2
        assert out2 == {"executed": True}, out2
        assert calls == ["jti-002"], calls  # exactly one execution
        _rec(results, PROBE_NAMES[1], "HELD",
             "executor ran exactly once; replay returns stored result, "
             "recorded as repeat (wave-240 saha S12)")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


def _p3_mandate_absent(results):
    try:
        reg = _bp.PermitRegistry()
        v, detail = _expect_code(
            lambda: _issue(reg, jti="jti-003", mandate=None),
            "permit-mandate-absent")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[2], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


def _p4_policy_absent(results):
    try:
        reg = _bp.PermitRegistry()
        v, detail = _expect_code(
            lambda: _issue(reg, jti="jti-004", policy=None),
            "permit-policy-absent")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[3], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


def _p5_leg_refusal(results):
    try:
        reg = _bp.PermitRegistry()

        def _refuse_decision(record):
            raise _LegRefused("evaluation-incomplete-details",
                             "decision leg: not every detail evaluated")

        v, detail = _expect_code(
            lambda: _bp.issue_permit(
                _decision(), _mandate(), _policy(), reg,
                iss="permit-authority", jti="jti-005",
                verify_decision=_refuse_decision,
                verify_mandate=_accept, verify_policy=_accept),
            "evaluation-incomplete-details")
        assert v == "HELD", detail
        # The refusal names the leg too (no overruling, no masking).
        try:
            _bp.issue_permit(
                _decision(), _mandate(), _policy(), reg,
                iss="permit-authority", jti="jti-005",
                verify_decision=_refuse_decision,
                verify_mandate=_accept, verify_policy=_accept)
            raise AssertionError("no refusal raised")
        except Exception as exc:  # noqa: BLE001 - expected refusal
            assert getattr(exc, "leg", None) == "decision", \
                "refusal must name the refusing leg, got %r" % (
                    getattr(exc, "leg", None),)
        # The (iss, jti) slot is NOT claimed by a refused issue.
        assert reg.lookup("permit-authority", "jti-005") is None
        _rec(results, PROBE_NAMES[4], "HELD",
             "leg refusal propagated with the exact code; slot unclaimed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


def _p6_unknown_outcome(results):
    try:
        reg = _bp.PermitRegistry()
        ledger = _cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-006")
        store = _bp.InMemoryConsumeStore(ledger, durable=True)
        # Consume but never execute: the outcome is unknown.
        receipt = _bp.consume_permit(permit, ledger, consume_store=store)
        assert receipt["outcome"] == "consumed", receipt
        rec = _bp.reconcile_unknown_outcome(permit, ledger, reg)
        assert rec["state"] == "unknown", rec
        assert rec["iss"] == "permit-authority" and rec["jti"] == "jti-006", rec
        # A fresh permit for the same (iss, jti) refuses until reconciled.
        # Reconciliation exists but the outcome is still unknown: still refused.
        v, detail = _expect_code(
            lambda: _issue(reg, jti="jti-006"), "permit-jti-duplicate")
        assert v == "HELD", detail
        # Never-consumed permit reconciles as not-executed.
        permit2 = _issue(reg, jti="jti-007")
        rec2 = _bp.reconcile_unknown_outcome(permit2, ledger, reg)
        assert rec2["state"] == "not-executed", rec2
        # After a not-executed reconciliation, a fresh permit IS issuable
        # and binds the reconciliation: the recovery path stays open.
        permit2b = _bp.issue_permit(
            _decision(), _mandate(), _policy(), reg,
            iss="permit-authority", jti="jti-007",
            verify_decision=_accept, verify_mandate=_accept,
            verify_policy=_accept, reconciliation=rec2)
        assert permit2b["reconciliation_digest"] == rec2["record_digest"], \
            permit2b
        assert permit2b["instance_digest"] != permit2["instance_digest"], \
            "re-issued permit must be a distinct consumable instance"
        receipt2b = _bp.consume_permit(permit2b, ledger,
                                     consume_store=store, registry=reg)
        assert receipt2b["outcome"] == "consumed", receipt2b
        _rec(results, PROBE_NAMES[5], "HELD",
             "unknown -> reconciliation record; duplicate refused; "
             "not-executed -> re-issuable and consumable")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


def _p7_trust_tier(results):
    try:
        reg = _bp.PermitRegistry()
        ledger = _cl.ConsumptionLedger()
        high = _decision()  # trust_tier "high"
        low = dict(_decision(), trust_tier="low")
        pa = _bp.issue_permit(
            high, _mandate(), _policy(), reg,
            iss="permit-authority", jti="jti-008",
            verify_decision=_accept, verify_mandate=_accept,
            verify_policy=_accept)
        pb = _bp.issue_permit(
            low, _mandate(), _policy(), reg,
            iss="permit-authority", jti="jti-009",
            verify_decision=_accept, verify_mandate=_accept,
            verify_policy=_accept)
        assert pa["instance_digest"] != pb["instance_digest"], \
            "trust tier must bind into the frozen instance"
        store = _bp.InMemoryConsumeStore(ledger, durable=True)
        _bp.consume_permit(pa, ledger, consume_store=store)
        # The low-tier permit is a different instance: still consumable.
        receipt_b = _bp.consume_permit(pb, ledger, consume_store=store)
        assert receipt_b["outcome"] == "consumed", receipt_b
        # Reconciliation of one jti never touches the other.
        rec_a = _bp.reconcile_unknown_outcome(pa, ledger, reg)
        assert reg.lookup("permit-authority",
                          "jti-009")["reconciliation"] is None
        assert rec_a["jti"] == "jti-008", rec_a
        _rec(results, PROBE_NAMES[6], "HELD",
             "permits differing only in trust tier are distinct instances")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


def _p8_tampered(results):
    try:
        reg = _bp.PermitRegistry()
        ledger = _cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-010")
        tampered = dict(permit)
        tampered["policy_digest"] = "ff" * 32
        v, detail = _expect_code(
            lambda: _bp.verify_permit(tampered), "permit-tampered")
        assert v == "HELD", detail
        # A tampered permit never reaches the executor.
        calls = []
        store = _bp.InMemoryConsumeStore(ledger, durable=True)
        v, detail = _expect_code(
            lambda: _bp.execute_permit(
                tampered, ledger, execute=lambda p: calls.append(p),
                consume_store=store),
            "permit-tampered")
        assert v == "HELD", detail
        assert calls == [], calls
        _rec(results, PROBE_NAMES[7], "HELD",
             "edited permit refused permit-tampered; executor untouched")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[7], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[7], "ERROR", traceback.format_exc(limit=2))


def _run_all():
    results = {}
    _p1_happy(results)
    _p2_double_submit(results)
    _p3_mandate_absent(results)
    _p4_policy_absent(results)
    _p5_leg_refusal(results)
    _p6_unknown_outcome(results)
    _p7_trust_tier(results)
    _p8_tampered(results)
    return results


def main():
    t0 = time.time()
    if not HAVE_NEW_API:
        for name in PROBE_NAMES:
            print("%-42s GAP (bound-permit module absent)" % name)
        print("summary: 0 HELD / %d GAP / 0 BREAK / 0 ERROR"
              % len(PROBE_NAMES))
        return 2
    results = _run_all()

    def _v(name):
        return results.get(name, "ERROR: missing").split("\n")[0]
    held = sum(1 for name in PROBE_NAMES if _v(name) == "HELD")
    gap = sum(1 for name in PROBE_NAMES if _v(name).startswith("GAP"))
    brk = sum(1 for name in PROBE_NAMES if _v(name).startswith("BREAK"))
    err = sum(1 for name in PROBE_NAMES if _v(name).startswith("ERROR"))
    for name in PROBE_NAMES:
        verdict = results.get(name, "ERROR: missing")
        first = verdict.split("\n")[0]
        print("%-42s %s" % (name, first))
        if "\n" in verdict:
            print(verdict.split("\n", 1)[1])
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)"
          % (held, gap, brk, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
