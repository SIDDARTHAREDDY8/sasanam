#!/usr/bin/env python3
"""Wave-229 lane B red-team battery: atomic single-use reserve -> admit ->
reconcile.

Attack shapes at the PUBLIC seams of gov/single_use_lifecycle.py,
deterministic, minimal, against pushed wave-228 HEAD
45fc6cbfa96f82f56e651388513c13af01c3d7b3:

- reserve/admit/reconcile happy path + digest determinism;
- concurrent double-reserve of the same triple: exactly one wins, the
  loser gets the DISTINCT refusal single-use-reserve-conflict (not a
  generic error);
- execution without a live reservation: single-use-not-reserved;
- admit bound to the wrong step_id/input_digest: single-use-reservation-mismatch;
- consumption record digest folded into the execution receipt's
  observation; verify_consumption_binding refuses tampering;
- reserve against an approval digest the registry never saw:
  single-use-reservation-unknown (fail closed);
- forged reservations (tampered reservation_id / foreign triple);
- double-reconcile replays: single-use-reconcile-replayed;
- malformed inputs fail closed as single-use-malformed;
- every new refusal maps in gov/decision_codes.TAXONOMY (the
  wave-228 whole-tree scanner is closed; unmapped codes would red
  the merge battery).

Method (diagnosing-bugs): break-first at the public seams.
Method (tdd): red battery written BEFORE gov/single_use_lifecycle.py;
a pristine run (module absent) is expected GAP, never BREAK.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run (staging):
  mkdir -p /var/tmp/g229b
  TMPDIR=/var/tmp/g229b ~/workspace/.gov-venv/bin/python evals/w229_reconcile_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g229b-u \\
      ~/workspace/.gov-venv/bin/python evals/w229_reconcile_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import threading
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import single_use_lifecycle as _lc
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

try:
    from gov import decision_codes as _dc
    HAVE_CODES = True
except ImportError:
    HAVE_CODES = False

try:
    from gov import receipt_pairs as _rp
    HAVE_RECEIPTS = True
except ImportError:
    HAVE_RECEIPTS = False

try:
    from gov import action_capsule as _ac
    HAVE_CAPSULES = True
except ImportError:
    HAVE_CAPSULES = False

PROBE_NAMES = (
    "lc-01-happy-path-reconciles",
    "lc-02-concurrent-reserve-exactly-one-wins",
    "lc-03-execution-without-reservation-refused",
    "lc-04-wrong-step-admit-refused",
    "lc-05-consumption-digest-bound-into-receipt",
    "lc-06-unknown-approval-fails-closed",
    "lc-07-forged-reservation-refused",
    "lc-08-double-reconcile-replayed",
    "lc-09-malformed-fails-closed",
    "lc-10-admit-idempotent",
    "lc-11-tampered-binding-refused",
    "lc-12-new-codes-in-decision-taxonomy",
    "lc-13-consumption-digest-linked-into-capsule",
    "lc-14-tampered-capsule-link-refused",
)

# 64-hex digests used across probes (fixed, deterministic).
_APPROVAL_A = "a" * 64
_APPROVAL_B = "b" * 64
_INPUT_A = "c" * 64
_INPUT_B = "d" * 64
_RECEIPT_A = "e" * 64
_RECEIPT_B = "f" * 64


def _registry(*approvals):
    reg = _lc.LifecycleRegistry()
    for digest in approvals:
        reg.register_approval(digest)
    return reg


def _verdict_record():
    return {
        "attempt": {"action": "wire", "initiator": "agent-1"},
        "effect": {"status": "admitted", "evidence": "executor-receipt-001"},
    }


def _issue_execution_receipt(consumption_record):
    """Issue a real execution receipt whose observation carries the
    consumption digest -- the digest-fold the lane claims."""
    decision = _rp.issue_decision_receipt(_verdict_record(), 1700000000.0)
    observation = {
        "outcome": "completed",
        "executor_may_have_accepted": True,
        "consumption_digest": consumption_record["consumption_digest"],
    }
    return _rp.issue_execution_receipt(
        _verdict_record(), observation, decision, 1700000060.0)


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.single_use_lifecycle absent on this tree")
        return results

    # lc-01: reserve -> admit -> reconcile happy path; digests deterministic.
    try:
        reg = _registry(_APPROVAL_A)
        r1 = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
        a1 = reg.admit(r1, "step-1", _INPUT_A)
        c1 = reg.reconcile(a1, _RECEIPT_A)
        ok = (c1["reservation_id"] == r1["reservation_id"]
              and c1["execution_receipt_digest"] == _RECEIPT_A
              and len(c1["consumption_digest"]) == 64
              and _lc.LifecycleRegistry.consumption_digest(c1)
              == c1["consumption_digest"]
              and c1["approval_digest"] == _APPROVAL_A
              and c1["step_id"] == "step-1"
              and c1["input_digest"] == _INPUT_A)
        rec("lc-01-happy-path-reconciles", "HELD" if ok else "BREAK",
            "consumption_digest=%s" % c1["consumption_digest"][:16])
    except Exception as exc:  # noqa: BLE001
        rec("lc-01-happy-path-reconciles", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-02: concurrent reserves of the same triple: exactly one wins.
    try:
        reg = _registry(_APPROVAL_A)
        wins = []
        losses = []
        codes = []
        barrier = threading.Barrier(8)

        def racer():
            barrier.wait()
            try:
                wins.append(reg.reserve(_APPROVAL_A, "step-race",
                                        _INPUT_A))
            except Exception as exc:  # noqa: BLE001
                losses.append(exc)
                codes.append(getattr(exc, "code", None))

        threads = [threading.Thread(target=racer) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ok = (len(wins) == 1 and len(losses) == 7
              and all(c == "single-use-reserve-conflict" for c in codes))
        rec("lc-02-concurrent-reserve-exactly-one-wins",
            "HELD" if ok else "BREAK",
            "wins=%d losses=%d codes=%s" % (len(wins), len(losses),
                                            sorted(set(codes))))
    except Exception as exc:  # noqa: BLE001
        rec("lc-02-concurrent-reserve-exactly-one-wins", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-03: execution without a reservation fails closed.
    try:
        reg = _registry(_APPROVAL_A)
        try:
            reg.require_reserved(_APPROVAL_A, "step-1", _INPUT_A)
            ok = False
            detail = "no refusal"
        except Exception as exc:  # noqa: BLE001
            ok = getattr(exc, "code", None) == "single-use-not-reserved"
            detail = "code=%s" % getattr(exc, "code", None)
        # A consumed-then-reconciled triple is also "not reserved".
        r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
        a = reg.admit(r, "step-1", _INPUT_A)
        reg.reconcile(a, _RECEIPT_A)
        try:
            reg.require_reserved(_APPROVAL_A, "step-1", _INPUT_A)
            ok = False
            detail += "; reconciled triple still live"
        except Exception as exc:  # noqa: BLE001
            ok = ok and getattr(exc, "code", None) == \
                "single-use-not-reserved"
        rec("lc-03-execution-without-reservation-refused",
            "HELD" if ok else "BREAK", detail)
    except Exception as exc:  # noqa: BLE001
        rec("lc-03-execution-without-reservation-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-04: admit bound to the wrong step_id / input_digest refuses.
    try:
        reg = _registry(_APPROVAL_A)
        r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
        bad = 0
        for step, digest in (("step-2", _INPUT_A), ("step-1", _INPUT_B)):
            try:
                reg.admit(r, step, digest)
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "code", None) == \
                        "single-use-reservation-mismatch":
                    bad += 1
        ok = bad == 2
        rec("lc-04-wrong-step-admit-refused", "HELD" if ok else "BREAK",
            "mismatches-caught=%d/2" % bad)
    except Exception as exc:  # noqa: BLE001
        rec("lc-04-wrong-step-admit-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-05: consumption digest present in a real execution receipt and
    # binding verifies; the receipt is a recomputable receipt_pairs pair.
    try:
        if not (HAVE_RECEIPTS and HAVE_CAPSULES):
            rec("lc-05-consumption-digest-bound-into-receipt", "ERROR",
                "receipt_pairs/action_capsule unavailable")
        else:
            reg = _registry(_APPROVAL_A)
            r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
            a = reg.admit(r, "step-1", _INPUT_A)
            c = reg.reconcile(a, _RECEIPT_A)
            receipt = _issue_execution_receipt(c)
            ok = (receipt["observation"]["consumption_digest"]
                  == c["consumption_digest"]
                  and reg.verify_consumption_binding(receipt, c)
                  and len(c["consumption_digest"]) == 64)
            rec("lc-05-consumption-digest-bound-into-receipt",
                "HELD" if ok else "BREAK",
                "binding-verified=%s" % ok)
    except Exception as exc:  # noqa: BLE001
        rec("lc-05-consumption-digest-bound-into-receipt", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-06: reserve against an approval digest the registry never saw.
    try:
        reg = _registry(_APPROVAL_A)
        try:
            reg.reserve(_APPROVAL_B, "step-1", _INPUT_A)
            ok = False
            detail = "no refusal"
        except Exception as exc:  # noqa: BLE001
            ok = getattr(exc, "code", None) == "single-use-reservation-unknown"
            detail = "code=%s" % getattr(exc, "code", None)
        rec("lc-06-unknown-approval-fails-closed", "HELD" if ok else "BREAK",
            detail)
    except Exception as exc:  # noqa: BLE001
        rec("lc-06-unknown-approval-fails-closed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-07: forged reservations fail closed.
    try:
        reg = _registry(_APPROVAL_A)
        r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
        forged = dict(r)
        forged["reservation_id"] = "0" * 64
        caught = 0
        for bad_res in (forged, {"reservation_id": "0" * 64},
                        "not-a-record"):
            try:
                reg.admit(bad_res, "step-1", _INPUT_A)
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "code", None) in (
                        "single-use-reservation-unknown",
                        "single-use-malformed"):
                    caught += 1
        ok = caught == 3
        rec("lc-07-forged-reservation-refused", "HELD" if ok else "BREAK",
            "forgeries-caught=%d/3" % caught)
    except Exception as exc:  # noqa: BLE001
        rec("lc-07-forged-reservation-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-08: double reconcile replays fail closed.
    try:
        reg = _registry(_APPROVAL_A)
        r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
        a = reg.admit(r, "step-1", _INPUT_A)
        reg.reconcile(a, _RECEIPT_A)
        try:
            reg.reconcile(a, _RECEIPT_B)
            ok = False
            detail = "no refusal"
        except Exception as exc:  # noqa: BLE001
            ok = getattr(exc, "code", None) == "single-use-reconcile-replayed"
            detail = "code=%s" % getattr(exc, "code", None)
        rec("lc-08-double-reconcile-replayed", "HELD" if ok else "BREAK",
            detail)
    except Exception as exc:  # noqa: BLE001
        rec("lc-08-double-reconcile-replayed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-09: malformed inputs fail closed.
    try:
        reg = _registry(_APPROVAL_A)
        caught = 0
        bad_calls = (
            ("not-a-digest", "step-1", _INPUT_A),
            (_APPROVAL_A, "", _INPUT_A),
            (_APPROVAL_A, "step-1", "ZZZ"),
            (None, "step-1", _INPUT_A),
        )
        for triple in bad_calls:
            try:
                reg.reserve(*triple)
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "code", None) == "single-use-malformed":
                    caught += 1
        ok = caught == len(bad_calls)
        rec("lc-09-malformed-fails-closed", "HELD" if ok else "BREAK",
            "caught=%d/%d" % (caught, len(bad_calls)))
    except Exception as exc:  # noqa: BLE001
        rec("lc-09-malformed-fails-closed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-10: admitting the same triple twice is idempotent.
    try:
        reg = _registry(_APPROVAL_A)
        r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
        a1 = reg.admit(r, "step-1", _INPUT_A)
        a2 = reg.admit(r, "step-1", _INPUT_A)
        ok = (a1["admission_id"] == a2["admission_id"]
              and a1["reservation_id"] == r["reservation_id"])
        rec("lc-10-admit-idempotent", "HELD" if ok else "BREAK",
            "same-admission=%s" % (a1["admission_id"] == a2["admission_id"]))
    except Exception as exc:  # noqa: BLE001
        rec("lc-10-admit-idempotent", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-11: tampered consumption binding refuses at verification.
    try:
        reg = _registry(_APPROVAL_A)
        r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
        a = reg.admit(r, "step-1", _INPUT_A)
        c = reg.reconcile(a, _RECEIPT_A)
        if not (HAVE_RECEIPTS and HAVE_CAPSULES):
            rec("lc-11-tampered-binding-refused", "ERROR",
                "receipt_pairs/action_capsule unavailable")
        else:
            receipt = _issue_execution_receipt(c)
            tampered = dict(c)
            tampered["execution_receipt_digest"] = _RECEIPT_B
            caught = 0
            for bad_consumption, bad_receipt in (
                    (tampered, receipt),
                    (c, None),
            ):
                try:
                    if bad_receipt is None:
                        mutated = dict(receipt)
                        mutated_obs = dict(mutated["observation"])
                        mutated_obs["consumption_digest"] = "0" * 64
                        mutated["observation"] = mutated_obs
                        reg.verify_consumption_binding(mutated, c)
                    else:
                        reg.verify_consumption_binding(bad_receipt,
                                                       bad_consumption)
                except Exception as exc:  # noqa: BLE001
                    if getattr(exc, "code", None) in (
                            "single-use-reservation-mismatch",
                            "single-use-malformed"):
                        caught += 1
            ok = caught == 2
            rec("lc-11-tampered-binding-refused",
                "HELD" if ok else "BREAK", "caught=%d/2" % caught)
    except Exception as exc:  # noqa: BLE001
        rec("lc-11-tampered-binding-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-12: new refusals are mapped in the closed decision taxonomy.
    try:
        if not HAVE_CODES:
            rec("lc-12-new-codes-in-decision-taxonomy", "ERROR",
                "decision_codes unavailable")
        else:
            new_codes = ("single-use-reserve-conflict",
                         "single-use-not-reserved",
                         "single-use-reservation-mismatch",
                         "single-use-reservation-unknown",
                         "single-use-reconcile-replayed",
                         "single-use-lifecycle-refused")
            missing = [c for c in new_codes
                       if c not in _dc.mapped_refusal_codes()]
            emitted = [_dc.emit(c, (_APPROVAL_A,)).get("code")
                       for c in new_codes if c in
                       _dc.mapped_refusal_codes()]
            ok = (not missing
                  and all(code == emitted_code
                          for code, emitted_code in
                          zip(new_codes, emitted)))
            rec("lc-12-new-codes-in-decision-taxonomy",
                "HELD" if ok else "BREAK",
                "missing=%s" % (missing or "none"))
    except Exception as exc:  # noqa: BLE001
        rec("lc-12-new-codes-in-decision-taxonomy", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

        # lc-13: consumption digest enters a capsule digest chain via
    # attach_consumption; the link re-verifies by re-derivation.
    try:
        if not HAVE_CAPSULES:
            rec("lc-13-consumption-digest-linked-into-capsule", "ERROR",
                "action_capsule unavailable")
        else:
            reg = _registry(_APPROVAL_A)
            r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
            a = reg.admit(r, "step-1", _INPUT_A)
            c = reg.reconcile(a, _RECEIPT_A)
            capsule = _ac.seal_capsule(_verdict_record())
            linked = _lc.attach_consumption(capsule, c)
            verified = _lc.verify_capsule_consumption(linked, c)
            linked_effect = _ac.verify_capsule(linked)["effect"]
            ok = (verified == c["consumption_digest"]
                  and linked_effect["consumption_digest"]
                  == c["consumption_digest"]
                  and linked_effect["reservation_id"]
                  == r["reservation_id"])
            rec("lc-13-consumption-digest-linked-into-capsule",
                "HELD" if ok else "BREAK",
                "link-verified=%s" % (verified == c["consumption_digest"]))
    except Exception as exc:  # noqa: BLE001
        rec("lc-13-consumption-digest-linked-into-capsule", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # lc-14: tampering with the linked capsule or the consumption
    # record refuses at verification.
    try:
        if not HAVE_CAPSULES:
            rec("lc-14-tampered-capsule-link-refused", "ERROR",
                "action_capsule unavailable")
        else:
            reg = _registry(_APPROVAL_A)
            r = reg.reserve(_APPROVAL_A, "step-1", _INPUT_A)
            a = reg.admit(r, "step-1", _INPUT_A)
            c = reg.reconcile(a, _RECEIPT_A)
            capsule = _ac.seal_capsule(_verdict_record())
            linked = _lc.attach_consumption(capsule, c)
            caught = 0
            tampered_effect = dict(_ac.verify_capsule(linked)["effect"])
            tampered_effect["consumption_digest"] = "0" * 64
            for bad_capsule, bad_record in (
                    ({"effect": tampered_effect}, c),   # not sealed -> replay refuses
                    (linked, dict(c, step_id="step-2")),  # record tampered
            ):
                try:
                    _lc.verify_capsule_consumption(bad_capsule, bad_record)
                except Exception as exc:  # noqa: BLE001
                    if getattr(exc, "code", None) in (
                            "single-use-reservation-mismatch",
                            "single-use-malformed",
                            "capsule-not-authorization",
                            "capsule-tampered",
                            "capsule-malformed"):
                        caught += 1
            ok = caught == 2
            rec("lc-14-tampered-capsule-link-refused",
                "HELD" if ok else "BREAK", "caught=%d/2" % caught)
    except Exception as exc:  # noqa: BLE001
        rec("lc-14-tampered-capsule-link-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))


    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_single_use.py",
                 "tests/test_receipt_pairs.py",
                 "tests/test_decision_codes.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w229 single-use-lifecycle probes: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
