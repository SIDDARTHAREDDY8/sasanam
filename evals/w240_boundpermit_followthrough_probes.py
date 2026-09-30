#!/usr/bin/env python3
"""Wave-240 lane C: saha bound-permit follow-through probes.

Red-first battery on the PUBLIC seams of gov/bound_permit.py, re-derived
(nothing copied) from draft-saha-aadp-bound-permit-00 (read directly
2026-09-30; IETF Trust prose re-derive): the 13-step verification order
(S8.1 Table 3, state consumed LAST), repeat-vs-idempotency-conflict (S12),
no-new-permit reconciliation (S12), outcome-tied budget accounting (S13),
the no-fallback rule (S8.2), the durable-shared-consume-store admission
gate (S12), and verification-record states (S8.3): verified / refused
(+reason+step) / could-not-check (+dependency) -- never partial.

Seams under test:
* verify_presentation(permit, *, consume_store, ...) -- the 13-step
  order; returns the verification record, never partial.
* consume_permit / execute_permit -- step-13 atomic claim; replay
  returns the STORED result and is recorded as a repeat (S12), never a
  second execution; different content digest under the same (iss, jti)
  refuses permit-idempotency-conflict (409-style).
* InMemoryConsumeStore / BudgetLedger -- admission gate, budget rules.
* reconcile_unknown_outcome -- signed no_effect releases; unsigned
  no_effect is rejected; no new permit is ever minted.

Attack shapes: (a) re-present same (iss, jti) with a different body
digest; (b) consume store unavailable; (c) unknown outcome with a
new-permit attempt; order drift (state before crypto); timeout refund;
unsigned no_effect self-attestation; rate-budget release; permit
absence treated as a fallback trigger.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-239 HEAD
e00d6a69378596c7562dd01f4afc296d66c46318.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (new API absent)
is expected GAP. Determinism is run-twice over the whole battery.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g240c
  TMPDIR=/var/tmp/g240c ~/workspace/.gov-venv/bin/python evals/w240_boundpermit_followthrough_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g240c-u \\
      ~/workspace/.gov-venv/bin/python evals/w240_boundpermit_followthrough_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import sys
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import bound_permit as _bp
    from gov import consumption_ledger as _cl
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

# New follow-through API (absent on the pristine base: red).
HAVE_FOLLOWTHROUGH = (
    HAVE_MODULE
    and hasattr(_bp, "verify_presentation")
    and hasattr(_bp, "InMemoryConsumeStore")
    and hasattr(_bp, "BudgetLedger")
)

PROBE_NAMES = [
    "conflict-different-digest",
    "store-unavailable-could-not-check",
    "reconcile-no-new-permit",
    "replay-stored-result",
    "order-drift-13-steps",
    "crypto-before-state",
    "timeout-commits-budget",
    "unsigned-no-effect-rejected",
    "signed-no-effect-releases",
    "rate-budget-never-released",
    "permit-absence-no-fallback",
    "admission-gate-non-durable",
    "local-policy-denies-no-consume",
    "registry-unavailable-could-not-check",
    "in-progress-retryable",
]


def _rec(results, name, verdict, detail):
    results.append({"probe": name, "verdict": verdict,
                    "detail": detail[:300]})


def _expect_code(fn, code):
    """Run fn; expect a BoundPermitError with machine code `code`."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - probe harness
        got = getattr(exc, "code", None)
        if got == code:
            return "HELD", "refused %r as required" % (code,)
        return "BREAK", "expected code %r, got %r (%s)" % (
            code, got, str(exc)[:120])
    return "BREAK", "expected refusal %r, nothing raised" % (code,)


def _leg_refused(code):
    class _R(Exception):
        pass
    exc = _R("leg says no")
    exc.code = code
    return exc


def _issue(reg, jti="w240-jti-1", iss="w240-iss-1", decision=None,
           mandate=None, policy=None):
    return _bp.issue_permit(
        decision if decision is not None else {"action": "pay", "amount": 10},
        mandate if mandate is not None else {"mandate": "m-1"},
        policy if policy is not None else {"policy": "allow"},
        reg, iss=iss, jti=jti,
        verify_decision=lambda r: None,
        verify_mandate=lambda r: None,
        verify_policy=lambda r: None)


def _ctx(jti):
    """Fresh (registry, ledger, durable store) triple for one jti."""
    reg = _bp.PermitRegistry()
    ledger = _cl.ConsumptionLedger()
    store = _bp.InMemoryConsumeStore(ledger, durable=True)
    permit = _issue(reg, jti=jti)
    return reg, ledger, store, permit


# ---------------------------------------------------------------------------
# (a) Re-present same (iss, jti) with a different body digest -> conflict.
# ---------------------------------------------------------------------------

def _p1_conflict(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[0], "GAP",
             "pre-lane: no verify_presentation/InMemoryConsumeStore")
        return
    try:
        reg, ledger, store, permit = _ctx("p1-jti")
        rec = _bp.consume_permit(permit, ledger, consume_store=store)
        assert rec["outcome"] == "consumed" and rec["step"] == 13, rec
        # Forge: same (iss, jti), different body digests, self-consistent
        # recompute (the honest residual: the module pins digests, it does
        # not sign; the conflict is decided at step 12/13 by (iss, jti)).
        forged = copy.deepcopy(permit)
        forged["decision_digest"] = "ab" * 32
        forged["instance_digest"] = _bp._instance_digest(
            forged["iss"], forged["jti"], forged["decision_digest"],
            forged["mandate_digest"], forged["policy_digest"],
            forged["reconciliation_digest"])
        body = {k: forged[k] for k in _bp._PERMIT_FIELDS}
        forged["permit_digest"] = _bp._body_digest(body)
        v, detail = _expect_code(
            lambda: _bp.consume_permit(forged, ledger, consume_store=store),
            "permit-idempotency-conflict")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[0], "HELD",
             "different digest under same (iss, jti) -> "
             "permit-idempotency-conflict; no second release")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# (b) Consume store unavailable -> could-not-check, not a policy denial.
# ---------------------------------------------------------------------------

def _p2_store_unavailable(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[1], "GAP",
             "pre-lane: no verify_presentation/InMemoryConsumeStore")
        return
    try:
        reg, ledger, _s, permit = _ctx("p2-jti")
        dead = _bp.InMemoryConsumeStore(ledger, durable=True,
                                        available=False)
        rec = _bp.verify_presentation(permit, consume_store=dead)
        assert rec["outcome"] == "could-not-check", rec
        assert rec["reason"] == "permit-consume-store-unavailable", rec
        assert rec["dependency"] == "consume-store", rec
        assert rec["http_status"] == 503, rec  # saha S9 mapping
        # The consume path must raise the same named refusal, and must
        # not have consumed anything.
        v, detail = _expect_code(
            lambda: _bp.consume_permit(permit, ledger, consume_store=dead),
            "permit-consume-store-unavailable")
        assert v == "HELD", detail
        assert dead.lookup("w240-iss-1", "p2-jti") is None
        _rec(results, PROBE_NAMES[1], "HELD",
             "unavailable store -> could-not-check naming consume-store; "
             "nothing consumed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# (c) Unknown outcome -> reconcile by jti; new permit attempt refused.
# ---------------------------------------------------------------------------

def _p3_reconcile(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[2], "GAP",
             "pre-lane: follow-through API absent")
        return
    try:
        reg, ledger, store, permit = _ctx("p3-jti")

        def _execute(p):
            raise RuntimeError("crashed mid-effect: outcome unknown")

        try:
            _bp.execute_permit(permit, ledger, execute=_execute,
                               consume_store=store)
            raise AssertionError("execute should have raised")
        except RuntimeError:
            pass  # outcome unknown: reconcile by jti, never re-mint
        record = _bp.reconcile_unknown_outcome(permit, ledger, reg)
        assert record["state"] == "unknown", record
        assert record["iss"] == "w240-iss-1" and record["jti"] == "p3-jti"
        # A fresh permit under the same (iss, jti) is still refused:
        # reconciliation refuses the new-permit attempt.
        v, detail = _expect_code(
            lambda: _issue(reg, jti="p3-jti"),
            "permit-jti-duplicate")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[2], "HELD",
             "unknown outcome reconciled by jti; fresh permit refused "
             "permit-jti-duplicate -- never re-minted")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Replay: same (iss, jti) + same digest -> stored result, repeat recorded.
# ---------------------------------------------------------------------------

def _p4_replay(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[3], "GAP",
             "pre-lane: follow-through API absent")
        return
    try:
        reg, ledger, store, permit = _ctx("p4-jti")
        calls = []

        def _execute(p):
            calls.append(p["jti"])
            return {"executed": True, "tx": "TX-1"}

        rec1, out1 = _bp.execute_permit(permit, ledger, execute=_execute,
                                       consume_store=store)
        assert rec1["outcome"] == "consumed", rec1
        assert out1 == {"executed": True, "tx": "TX-1"}, out1
        # Same permit presented again: stored result returned, recorded
        # as a repeat -- executor NOT re-invoked (saha S12, vector V07).
        rec2, out2 = _bp.execute_permit(permit, ledger, execute=_execute,
                                       consume_store=store)
        assert rec2["outcome"] == "replayed", rec2
        assert rec2.get("repeat_recorded") is True, rec2
        assert out2 == out1, (out1, out2)
        assert calls == ["p4-jti"], calls  # exactly one execution
        _rec(results, PROBE_NAMES[3], "HELD",
             "replay returned stored result, recorded as repeat, "
             "executor ran exactly once")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Order drift: each of the 13 steps fails in isolation with the right
# step-numbered reason.
# ---------------------------------------------------------------------------

def _p5_order_drift(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[4], "GAP",
             "pre-lane: no verify_presentation")
        return
    try:
        reg, ledger, store, permit = _ctx("p5-jti")

        def _mut(**kw):
            m = copy.deepcopy(permit)
            m.update(kw)
            return m

        def _recompute_digest(m):
            body = {k: m[k] for k in _bp._PERMIT_FIELDS}
            m["permit_digest"] = _bp._body_digest(body)
            return m

        # step 6 fixture: tamper instance_digest, keep permit_digest
        # consistent so the failure lands at step 6.
        m6 = _mut(instance_digest="cd" * 32)
        m6 = _recompute_digest(m6)
        # step 7 fixture: tamper permit_digest only.
        m7 = _mut(permit_digest="ef" * 32)
        # step 8 fixture: reconciliation digest that matches nothing
        # registered. Recompute the digests so steps 1-7 pass and the
        # failure lands in isolation at step 8.
        m8 = _mut(reconciliation_digest="01" * 32)
        m8["instance_digest"] = _bp._instance_digest(
            m8["iss"], m8["jti"], m8["decision_digest"],
            m8["mandate_digest"], m8["policy_digest"],
            m8["reconciliation_digest"])
        m8 = _recompute_digest(m8)
        # step 12 fixture: bind (iss, jti) to another digest first.
        other = _issue(reg, jti="p5-other")
        _bp.consume_permit(other, ledger, consume_store=store)
        forged12 = copy.deepcopy(permit)
        forged12["decision_digest"] = "ab" * 32
        forged12["instance_digest"] = _bp._instance_digest(
            forged12["iss"], forged12["jti"], forged12["decision_digest"],
            forged12["mandate_digest"], forged12["policy_digest"],
            forged12["reconciliation_digest"])
        forged12 = _recompute_digest(forged12)

        dead = _bp.InMemoryConsumeStore(ledger, durable=True,
                                        available=False)
        flimsy = _bp.InMemoryConsumeStore(_cl.ConsumptionLedger(),
                                          durable=False)

        def _lp_no(p):
            raise _leg_refused("local-policy-deny-test")

        cases = [
            # (fixture, expected (step, reason, outcome), kwargs)
            (None, (1, "permit-no-fallback", "refused"), {}),
            ({}, (2, "permit-malformed", "refused"), {}),
            (_mut(version=99), (3, "permit-malformed", "refused"), {}),
            (_mut(jti=""), (4, "permit-malformed", "refused"), {}),
            (_mut(decision_digest="not-hex"), (5, "permit-malformed",
                                               "refused"), {}),
            (m6, (6, "permit-tampered", "refused"), {}),
            (m7, (7, "permit-tampered", "refused"), {}),
            # step 8 needs the issuer registry to check the re-issue
            # binding against: nothing is registered for this (iss,
            # jti), so the binding fails.
            (m8, (8, "permit-malformed", "refused"), {"registry": reg}),
        ]
        for fixture, (step, reason, outcome), kwargs in cases:
            rec = _bp.verify_presentation(fixture, consume_store=store,
                                          **kwargs)
            assert (rec["step"], rec["reason"], rec["outcome"]) == \
                (step, reason, outcome), (fixture, rec)
        # step 9: unavailable store -> could-not-check
        rec = _bp.verify_presentation(permit, consume_store=dead)
        assert (rec["step"], rec["reason"], rec["outcome"],
                rec["dependency"]) == \
            (9, "permit-consume-store-unavailable", "could-not-check",
             "consume-store"), rec
        # step 10: non-durable store, gate on
        rec = _bp.verify_presentation(permit, consume_store=flimsy)
        assert (rec["step"], rec["reason"], rec["outcome"]) == \
            (10, "permit-consume-store-not-durable", "refused"), rec
        # step 11: local policy denies -> refused, nothing consumed
        rec = _bp.verify_presentation(permit, consume_store=store,
                                      local_policy_verifier=_lp_no)
        assert (rec["step"], rec["reason"], rec["outcome"]) == \
            (11, "local-policy-deny-test", "refused"), rec
        assert store.lookup("w240-iss-1", "p5-jti") is None, rec
        # step 12: (iss, jti) bound to a different digest
        _bp.consume_permit(permit, ledger, consume_store=store)
        rec = _bp.verify_presentation(forged12, consume_store=store)
        assert (rec["step"], rec["reason"], rec["outcome"]) == \
            (12, "permit-idempotency-conflict", "refused"), rec
        assert rec["http_status"] == 409, rec  # saha S9 mapping
        # step 13: fresh presentation verifies and consumes
        fresh_reg = _bp.PermitRegistry()
        fresh = _issue(fresh_reg, jti="p5-fresh")
        rec = _bp.verify_presentation(fresh, consume_store=store)
        assert (rec["step"], rec["reason"], rec["outcome"]) == \
            (13, None, "verified"), rec
        assert store.lookup("w240-iss-1", "p5-fresh") is not None
        _rec(results, PROBE_NAMES[4], "HELD",
             "all 13 steps fail in isolation with step-numbered reasons")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Crypto before state: a tampered permit with a conflicting store entry
# must refuse at the crypto step, not the state step.
# ---------------------------------------------------------------------------

def _p6_crypto_before_state(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[5], "GAP",
             "pre-lane: no verify_presentation")
        return
    try:
        reg, ledger, store, permit = _ctx("p6-jti")
        _bp.consume_permit(permit, ledger, consume_store=store)
        # Tampered AND conflicting: order demands the crypto step wins.
        bad = copy.deepcopy(permit)
        bad["instance_digest"] = "99" * 32  # breaks step 6
        body = {k: bad[k] for k in _bp._PERMIT_FIELDS}
        bad["permit_digest"] = _bp._body_digest(body)  # step 7 passes
        rec = _bp.verify_presentation(bad, consume_store=store)
        assert rec["step"] == 6 and rec["reason"] == "permit-tampered", rec
        _rec(results, PROBE_NAMES[5], "HELD",
             "tampered+conflicting refuses at step 6 (crypto), not "
             "step 12/13 (state)")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Timeout: budget committed on timeout, not refunded (saha S13).
# ---------------------------------------------------------------------------

def _p7_timeout_budget(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[6], "GAP",
             "pre-lane: no BudgetLedger")
        return
    try:
        reg, ledger, store, permit = _ctx("p7-jti")
        budget = _bp.BudgetLedger()

        def _execute(p):
            raise TimeoutError("effect timed out: outcome unknown")

        try:
            _bp.execute_permit(permit, ledger, execute=_execute,
                               consume_store=store, budget=budget)
            raise AssertionError("execute should have raised")
        except TimeoutError:
            pass
        st = budget.state("w240-iss-1", "p7-jti")
        assert st["committed"] is True and st["released"] is False, st
        _rec(results, PROBE_NAMES[6], "HELD",
             "timeout committed the budget; no refund on unknown outcome")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Unsigned no_effect self-attestation is rejected; budget stays committed.
# ---------------------------------------------------------------------------

def _p8_unsigned_no_effect(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[7], "GAP",
             "pre-lane: no BudgetLedger")
        return
    try:
        reg, ledger, store, permit = _ctx("p8-jti")
        budget = _bp.BudgetLedger()

        def _execute(p):
            raise TimeoutError("timed out")

        try:
            _bp.execute_permit(permit, ledger, execute=_execute,
                               consume_store=store, budget=budget)
        except TimeoutError:
            pass
        # Presenter self-attests no_effect with NO signature: rejected.
        v, detail = _expect_code(
            lambda: _bp.reconcile_unknown_outcome(
                permit, ledger, reg, budget=budget,
                no_effect_refusal={"no_effect": True, "signed": False},
                verify_refusal_signature=None),
            "permit-no-effect-unattested")
        assert v == "HELD", detail
        st = budget.state("w240-iss-1", "p8-jti")
        assert st["committed"] is True and st["released"] is False, st
        _rec(results, PROBE_NAMES[7], "HELD",
             "unsigned no_effect refused permit-no-effect-unattested; "
             "budget stays committed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[7], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[7], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Signed no_effect failure releases the budget (saha S13).
# ---------------------------------------------------------------------------

def _p9_signed_no_effect(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[8], "GAP",
             "pre-lane: no BudgetLedger")
        return
    try:
        reg, ledger, store, permit = _ctx("p9-jti")
        budget = _bp.BudgetLedger()

        def _execute(p):
            raise TimeoutError("timed out")

        try:
            _bp.execute_permit(permit, ledger, execute=_execute,
                               consume_store=store, budget=budget)
        except TimeoutError:
            pass
        signed = {"no_effect": True, "sig": "recipient-signature-bytes"}
        record = _bp.reconcile_unknown_outcome(
            permit, ledger, reg, budget=budget,
            no_effect_refusal=signed,
            verify_refusal_signature=lambda r: r.get("sig") ==
            "recipient-signature-bytes")
        assert record["state"] == "not-executed", record
        st = budget.state("w240-iss-1", "p9-jti")
        assert st["released"] is True, st
        _rec(results, PROBE_NAMES[8], "HELD",
             "signed no_effect -> budget released, state not-executed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[8], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[8], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Rate budgets are never released (saha S13).
# ---------------------------------------------------------------------------

def _p10_rate_budget(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[9], "GAP",
             "pre-lane: no BudgetLedger")
        return
    try:
        budget = _bp.BudgetLedger()
        budget.commit("w240-iss-1", "p10-jti", kind="rate")
        v, detail = _expect_code(
            lambda: budget.release("w240-iss-1", "p10-jti",
                                   on="not_attempted"),
            "permit-rate-budget-unreleasable")
        assert v == "HELD", detail
        st = budget.state("w240-iss-1", "p10-jti")
        assert st["released"] is False, st
        _rec(results, PROBE_NAMES[9], "HELD",
             "rate-budget release refused "
             "permit-rate-budget-unreleasable; still committed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[9], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[9], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Permit absence is malformed -- never a reason to accept another
# credential (saha S8.2).
# ---------------------------------------------------------------------------

def _p11_no_fallback(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[10], "GAP",
             "pre-lane: no verify_presentation")
        return
    try:
        _reg, ledger, store, _p = _ctx("p11-jti")
        rec = _bp.verify_presentation(None, consume_store=store)
        assert rec["outcome"] == "refused", rec
        assert rec["step"] == 1 and rec["reason"] == "permit-no-fallback", \
            rec
        _rec(results, PROBE_NAMES[10], "HELD",
             "absent permit refuses permit-no-fallback at step 1: "
             "absence is malformed, never a fallback trigger")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[10], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[10], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Admission gate: a non-durable store MUST NOT accept bound permits (S12).
# ---------------------------------------------------------------------------

def _p12_admission_gate(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[11], "GAP",
             "pre-lane: no InMemoryConsumeStore")
        return
    try:
        reg, ledger, _s, permit = _ctx("p12-jti")
        flimsy = _bp.InMemoryConsumeStore(_cl.ConsumptionLedger(),
                                          durable=False)
        v, detail = _expect_code(
            lambda: _bp.consume_permit(permit, ledger,
                                       consume_store=flimsy),
            "permit-consume-store-not-durable")
        assert v == "HELD", detail
        # Explicit single-node opt-out documents the deployment
        # contract and proceeds.
        rec = _bp.consume_permit(permit, ledger, consume_store=flimsy,
                                 require_durable_store=False)
        assert rec["outcome"] == "consumed", rec
        _rec(results, PROBE_NAMES[11], "HELD",
             "non-durable store refused by default; explicit "
             "single-node opt-out documents the contract")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[11], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[11], "ERROR", traceback.format_exc(limit=2))


# ---------------------------------------------------------------------------
# Local policy denies at step 11 -> refused, and the permit is NOT
# consumed (saha S17 vector V24).
# ---------------------------------------------------------------------------

def _p13_local_policy(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[12], "GAP",
             "pre-lane: no verify_presentation")
        return
    try:
        reg, ledger, store, permit = _ctx("p13-jti")

        def _deny(p):
            raise _leg_refused("local-policy")

        rec = _bp.verify_presentation(permit, consume_store=store,
                                      local_policy_verifier=_deny)
        assert rec["outcome"] == "refused", rec
        assert rec["step"] == 11 and rec["reason"] == "local-policy", rec
        assert store.lookup("w240-iss-1", "p13-jti") is None, rec
        _rec(results, PROBE_NAMES[12], "HELD",
             "local-policy denial at step 11 refused; permit not consumed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[12], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[12], "ERROR", traceback.format_exc(limit=2))


def _p14_registry_unavailable(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[13], "GAP",
             "pre-lane: no verify_presentation")
        return
    try:
        reg, ledger, store, permit = _ctx("p14-jti")
        rec = _bp.reconcile_unknown_outcome(permit, ledger, reg)
        fresh = _bp.issue_permit(
            {"action": "pay", "amount": 10}, {"mandate": "m-1"},
            {"policy": "allow"}, reg,
            iss="w240-iss-1", jti="p14-jti",
            verify_decision=lambda r: None,
            verify_mandate=lambda r: None,
            verify_policy=lambda r: None,
            reconciliation=rec)
        assert fresh["reconciliation_digest"] == \
            rec["record_digest"]
        record = _bp.verify_presentation(fresh, consume_store=store)
        assert (record["outcome"], record["step"], record["reason"],
                record["dependency"], record["http_status"]) == (
            "could-not-check", 8, "permit-registry-unavailable",
            "permit-registry", 503), record
        try:
            _bp.consume_permit(
                fresh, ledger,
                consume_store=_bp.InMemoryConsumeStore(ledger,
                                                       durable=True))
        except _bp.BoundPermitError as exc:
            assert exc.code == "permit-registry-unavailable", \
                exc.code
            assert exc.verification_record["outcome"] == \
                "could-not-check"
        else:
            raise AssertionError(
                "expected permit-registry-unavailable")
        # With the registry the same re-issue verifies.
        ok = _bp.verify_presentation(fresh, consume_store=store,
                                     registry=reg)
        assert ok["outcome"] == "verified", ok
        _rec(results, PROBE_NAMES[13], "HELD",
             "re-issue without registry could-not-check at step 8; "
             "with registry verifies")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[13], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[13], "ERROR",
             traceback.format_exc(limit=2))


def _p15_in_progress_retryable(results):
    if not HAVE_FOLLOWTHROUGH:
        _rec(results, PROBE_NAMES[14], "GAP",
             "pre-lane: no verify_presentation")
        return
    try:
        reg, ledger, store, permit = _ctx("p15-jti")
        # Simulate another holder having claimed first: claim
        # directly without recording a result.
        outcome, slot = store.claim(permit)
        assert outcome == "claimed", (outcome, slot)
        # A second presentation is retryable, NOT a replay: no
        # stored result exists yet.
        record = _bp.verify_presentation(permit, consume_store=store)
        assert (record["outcome"], record["step"], record["reason"],
                record["http_status"]) == (
            "retryable", 13, "permit-in-progress", 503), record
        # The consume/execute path raises the typed retryable
        # signal; the executor is never touched and nothing new is
        # reserved.
        calls = []
        try:
            _bp.execute_permit(permit, ledger,
                               execute=lambda p: calls.append(p),
                               consume_store=store)
        except _bp.BoundPermitError as exc:
            assert exc.code == "permit-in-progress", exc.code
            assert exc.verification_record["outcome"] == "retryable"
        else:
            raise AssertionError("expected permit-in-progress")
        assert calls == [], calls
        # Once the first holder records its result, the same
        # presentation replays the stored result exactly once.
        store.record_result("w240-iss-1", "p15-jti", {"done": True})
        record2, out2 = _bp.execute_permit(
            permit, ledger, execute=lambda p: calls.append(p),
            consume_store=store)
        assert record2["outcome"] == "replayed", record2
        assert out2 == {"done": True}, out2
        assert calls == [], calls
        _rec(results, PROBE_NAMES[14], "HELD",
             "in-progress verifies retryable (503); once the result "
             "is recorded the same presentation replays it")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[14], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[14], "ERROR",
             traceback.format_exc(limit=2))


_PROBES = [_p1_conflict, _p2_store_unavailable, _p3_reconcile,
           _p4_replay, _p5_order_drift, _p6_crypto_before_state,
           _p7_timeout_budget, _p8_unsigned_no_effect,
           _p9_signed_no_effect, _p10_rate_budget, _p11_no_fallback,
           _p12_admission_gate, _p13_local_policy,
           _p14_registry_unavailable, _p15_in_progress_retryable]


def _run_once():
    results = []
    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            _rec(results, name, "ERROR", "gov.bound_permit not importable")
        return results
    for probe in _PROBES:
        probe(results)
    return results


def main():
    if not GREEN_SKIP:
        pass  # no nested green checks: depth-1 convention
    first = _run_once()
    second = _run_once()
    det_ok = [a["verdict"] for a in first] == [b["verdict"] for b in second]
    held = sum(1 for r in first if r["verdict"] == "HELD")
    gap = sum(1 for r in first if r["verdict"] == "GAP")
    brk = sum(1 for r in first if r["verdict"] == "BREAK")
    err = sum(1 for r in first if r["verdict"] == "ERROR")
    print("w240_boundpermit_followthrough: %d/%d HELD, %d GAP, %d BREAK, "
          "%d ERROR; determinism %s" % (held, len(first), gap, brk, err,
                                        "OK" if det_ok else "MISMATCH"))
    for r in first:
        if r["verdict"] != "HELD":
            print("  [%s] %s: %s" % (r["verdict"], r["probe"], r["detail"]))
    if not det_ok:
        print("  determinism mismatch between runs")
        return 1
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
