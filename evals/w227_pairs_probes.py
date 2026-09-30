#!/usr/bin/env python3
"""Wave-227 lane B: recomputable decision<->execution receipt pairs.

RE-DERIVED pattern (the external Vaara receipt -12 draft is not in
this repo; nothing copied): a decision receipt and an execution
receipt are bound by DIGEST, never by claim, and ``recompute_pair``
RE-RUNS every consistency check instead of trusting claimed fields:

* ``bind()`` refuses ``receipt-pair-decision-mismatch`` when the
  execution receipt's backLink != the decision receipt's digest;
* ``recompute_pair()`` re-derives the decision digest from the
  verdict record via gov/action_capsule.py digest rules (drift ->
  ``receipt-pair-decision-drift``), re-runs effect classification via
  gov/effect_status.classify (drift -> ``receipt-pair-effect-drift``),
  and checks executed_at >= issued_at (``receipt-pair-time-inversion``);
* the pair summary is RECOMPUTED and sealed as an action-capsule
  chain commitment; receipts are evidence, never authorization
  (``receipt-pair-not-authorization``).

Seams under test:
* gov/receipt_pairs.py — issue_decision_receipt / issue_execution_receipt
  / bind / recompute_pair / deny_authority_use.

Attack shapes: swap the backLink; tamper the verdict record under a
claimed digest; lie about the effect status; invert the timestamps;
use a receipt as authorization; smuggle unknown receipt fields;
cross-swap the verdict record between the two receipts.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-226 HEAD
e3cc497e9e39004d58baca20abcea5cc2d9b938f.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g227b
  TMPDIR=/var/tmp/g227b ~/workspace/.gov-venv/bin/python evals/w227_pairs_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g227b-u \\
      ~/workspace/.gov-venv/bin/python evals/w227_pairs_probes.py
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
    from gov import receipt_pairs as _rp
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _verdict_record(refused=False):
    if refused:
        return {"attempt": {"action": "install_package",
                            "package": "nginx-1.29"},
                "effect": {"status": "refused",
                           "code": "capgate-refused",
                           "evidence": "gate refused: unlisted package"}}
    return {"attempt": {"action": "install_package",
                        "package": "nginx-1.29"},
            "effect": {"status": "admitted",
                       "evidence": "gate allowed: pinned package"}}


def _valid_pair(obs=None, issued=1700000000.0, executed=1700000060.0,
               refused=False):
    obs = ({"outcome": "timed-out",
            "executor_may_have_accepted": False}
           if obs is None else obs)
    vr = _verdict_record(refused=refused)
    dec = _rp.issue_decision_receipt(vr, issued)
    exe = _rp.issue_execution_receipt(vr, obs, dec, executed)
    return _rp.bind(exe, dec)


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.receipt_pairs absent on this tree")
        return results

    # rp-01: a valid pair binds and recomputes; summary is recomputed.
    try:
        pair = _valid_pair()
        summary = _rp.recompute_pair(pair)
        ok = (summary.get("recomputed") is True
              and summary.get("effect_status") == "timed-out-before-effect"
              and summary.get("verdict") == "admitted"
              and summary.get("decision_digest")
              == pair["decision_receipt"]["decision_digest"]
              and summary.get("chain", {}).get("chain_digest")
              and summary.get("chain", {}).get("close_state")
              == "closed-acknowledged")
        rec("rp-01-valid-pair-recomputes", "HELD" if ok else "BREAK",
            "summary recomputed, chain closed-acknowledged" if ok
            else "recomputed summary wrong: %r" % (summary,))
    except Exception as exc:  # noqa: BLE001
        rec("rp-01-valid-pair-recomputes", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-02: backLink swapped -> bind refuses receipt-pair-decision-mismatch.
    try:
        pair = _valid_pair()
        forged = copy.deepcopy(pair)
        forged["execution_receipt"]["decision_backlink"] = "ff" * 32
        held = _refuses(lambda: _rp.bind(
            forged["execution_receipt"], forged["decision_receipt"]),
            "receipt-pair-decision-mismatch")
        rec("rp-02-backlink-mismatch-refused", "HELD" if held else "BREAK",
            "mismatch refused" if held
            else "backLink swap did not refuse")
    except Exception as exc:  # noqa: BLE001
        rec("rp-02-backlink-mismatch-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-03: verdict record tampered under the claimed decision digest ->
    # recompute refuses receipt-pair-decision-drift.
    try:
        pair = _valid_pair()
        tampered = copy.deepcopy(pair)
        tampered["decision_receipt"]["verdict_record"]["attempt"]["package"] = \
            "evil-9.9"
        held = _refuses(lambda: _rp.recompute_pair(tampered),
                        "receipt-pair-decision-drift")
        rec("rp-03-decision-drift-refused", "HELD" if held else "BREAK",
            "decision drift refused" if held
            else "tampered verdict record survived recompute")
    except Exception as exc:  # noqa: BLE001
        rec("rp-03-decision-drift-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-04: observation tampered (would re-classify differently) ->
    # receipt-pair-effect-drift.
    try:
        pair = _valid_pair()
        tampered = copy.deepcopy(pair)
        tampered["execution_receipt"]["observation"] = {
            "outcome": "completed", "executor_may_have_accepted": False}
        held = _refuses(lambda: _rp.recompute_pair(tampered),
                        "receipt-pair-effect-drift")
        rec("rp-04-observation-tamper-effect-drift", "HELD" if held
            else "BREAK",
            "observation tamper refused as effect drift" if held
            else "re-classified observation was not caught")
    except Exception as exc:  # noqa: BLE001
        rec("rp-04-observation-tamper-effect-drift", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-05: claimed effect_status lies (completed) while the classified
    # observation says timed-out-after-possible-effect ->
    # receipt-pair-effect-drift.
    try:
        pair = _valid_pair(
            obs={"outcome": "timed-out", "executor_may_have_accepted": True})
        lied = copy.deepcopy(pair)
        lied["execution_receipt"]["effect_status"] = "completed"
        held = _refuses(lambda: _rp.recompute_pair(lied),
                        "receipt-pair-effect-drift")
        rec("rp-05-claimed-status-lie-refused", "HELD" if held else "BREAK",
            "claimed-status lie refused" if held
            else "lied effect_status passed recompute")
    except Exception as exc:  # noqa: BLE001
        rec("rp-05-claimed-status-lie-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-06: executed_at before issued_at -> receipt-pair-time-inversion.
    try:
        pair = _valid_pair(issued=1700000060.0, executed=1700000000.0)
        held = _refuses(lambda: _rp.recompute_pair(pair),
                        "receipt-pair-time-inversion")
        rec("rp-06-time-inversion-refused", "HELD" if held else "BREAK",
            "time inversion refused" if held
            else "executed before issued passed recompute")
    except Exception as exc:  # noqa: BLE001
        rec("rp-06-time-inversion-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-07: recomputed summary matches an independent re-derivation.
    try:
        pair = _valid_pair()
        summary = _rp.recompute_pair(pair)
        import hashlib
        expect = hashlib.sha256(
            (pair["decision_receipt"]["decision_digest"]
             + pair["execution_receipt"]["effect_digest"]
             + summary["effect_status"]
             + repr(summary["executed_at"])).encode("utf-8")).hexdigest()
        ok = summary.get("pair_digest") == expect
        rec("rp-07-summary-independently-recomputed",
            "HELD" if ok else "BREAK",
            "pair_digest matches independent derivation" if ok
            else "pair_digest %r != independently derived %r"
            % (summary.get("pair_digest"), expect))
    except Exception as exc:  # noqa: BLE001
        rec("rp-07-summary-independently-recomputed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-08: receipts carry no authority.
    try:
        pair = _valid_pair()
        ok = _refuses(
            lambda: _rp.deny_authority_use(pair["decision_receipt"]),
            "receipt-pair-not-authorization")
        ok = ok and _refuses(
            lambda: _rp.deny_authority_use(pair["execution_receipt"]),
            "receipt-pair-not-authorization")
        # Authority-shaped fields in the verdict record refuse at issuance.
        vr = _verdict_record()
        vr["grant"] = "all"
        ok = ok and _refuses(
            lambda: _rp.issue_decision_receipt(vr, 1700000000.0),
            "capsule-not-authorization")
        rec("rp-08-receipts-carry-no-authority",
            "HELD" if ok else "BREAK",
            "authority-shaped use refused" if ok
            else "receipt could be used as authorization")
    except Exception as exc:  # noqa: BLE001
        rec("rp-08-receipts-carry-no-authority", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-09: unknown top-level receipt fields fail closed.
    try:
        pair = _valid_pair()
        forged = copy.deepcopy(pair)
        forged["execution_receipt"]["authority"] = "admin"
        held = _refuses(lambda: _rp.bind(
            forged["execution_receipt"], forged["decision_receipt"]),
            "receipt-pair-unknown-field")
        rec("rp-09-unknown-field-fails-closed", "HELD" if held else "BREAK",
            "unknown field refused" if held
            else "smuggled receipt field accepted")
    except Exception as exc:  # noqa: BLE001
        rec("rp-09-unknown-field-fails-closed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-10: execution receipt whose verdict record differs from the
    # decision receipt's refuses receipt-pair-decision-drift.
    try:
        pair = _valid_pair()
        vr_other = _verdict_record(refused=True)
        dec = pair["decision_receipt"]
        exe = _rp.issue_execution_receipt(vr_other,
                                          {"outcome": "completed",
                                           "executor_may_have_accepted": False},
                                          dec, 1700000060.0)
        held = _refuses(lambda: _rp.recompute_pair(_rp.bind(exe, dec)),
                        "receipt-pair-decision-drift")
        rec("rp-10-cross-verdict-record-swap-refused",
            "HELD" if held else "BREAK",
            "cross verdict-record swap refused" if held
            else "mismatched verdict records paired silently")
    except Exception as exc:  # noqa: BLE001
        rec("rp-10-cross-verdict-record-swap-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


PROBE_NAMES = [
    "rp-01-valid-pair-recomputes",
    "rp-02-backlink-mismatch-refused",
    "rp-03-decision-drift-refused",
    "rp-04-observation-tamper-effect-drift",
    "rp-05-claimed-status-lie-refused",
    "rp-06-time-inversion-refused",
    "rp-07-summary-independently-recomputed",
    "rp-08-receipts-carry-no-authority",
    "rp-09-unknown-field-fails-closed",
    "rp-10-cross-verdict-record-swap-refused",
]


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_action_capsule.py",
                 "tests/test_effect_status.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        import subprocess
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
    print("w227 receipt-pairs probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  green-check [%s] %s %s" % (status, name, detail))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
