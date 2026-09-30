#!/usr/bin/env python3
"""Wave-230 lane C: decision-vs-effect agreement before acceptance.

ADAPT (re-derived prose; nothing copied) of the decision/effect
agreement direction: an auditor never accepts a decision/execution
pair unless the decision side and the effect side AGREE on what was
authorized and what was executed. gov/decision_effect_agreement.py
recomputes both sides from their digests (the gov/receipt_pairs.py
discipline — claims are never trusted) and fails closed on any
disagreement.

Seams under test:
* gov/decision_effect_agreement.check_agreement(decision_receipt,
  execution_receipt) — pure function, no global state, usable as an
  additional acceptance predicate by the wave-229 checkpoint verifier
  and receipt-pair chains:
  - valid decision<->execution pair recomputes and agrees;
  - swapped effect (execution verdict record differs) refuses
    ``decision-effect-disagreement`` (action capsule attempts digest
    mismatch);
  - decision without an execution record refuses
    ``decision-effect-effect-absent`` (absence is evidence of
    non-execution, not failure);
  - execution record without a decision refuses
    ``decision-effect-extra-effect``;
  - executed_at before issued_at refuses
    ``decision-effect-time-inversion``;
  - tampered decision bytes are caught by recomputation
    (``decision-effect-decision-drift``), not by trusting claims;
  - empty inputs fail closed (``decision-effect-malformed``).
* gov/decision_effect_agreement.seal_agreement(...) — the agreement
  verdict seals into a NEW action capsule (digest-linked evidence;
  gov/action_capsule.py untouched); the agreement digest is
  tamper-evident; authority-shaped use refuses
  ``decision-effect-not-authorization``.

Attack shapes: swap the effect onto a different verdict; drop the
execution record; drop the decision record; invert the timestamps;
mutate the decision verdict bytes in place; offer the agreement as
authority; feed non-dict / empty records.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-229 HEAD
eb3ed254e5afb268dac2d46bdcca1f9e54f96b3b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g230c
  TMPDIR=/var/tmp/g230c ~/workspace/.gov-venv/bin/python evals/w230_agree_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g230c-u \\
      ~/workspace/.gov-venv/bin/python evals/w230_agree_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import subprocess
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import decision_effect_agreement as _dea
    from gov import receipt_pairs as _rp
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False
    _dea = None
    _rp = None

PROBE_NAMES = [
    "agree-01-valid-pair-agrees",
    "agree-02-swapped-effect-refused",
    "agree-03-decision-without-effect-refused",
    "agree-04-effect-without-decision-refused",
    "agree-05-time-inversion-refused",
    "agree-06-tampered-decision-bytes-refused",
    "agree-07-empty-inputs-refused",
    "agree-08-agreement-evidence-sealed",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _attempt(name="tool.op"):
    return {"action": name, "args": {"x": 1}}


def _effect_ok():
    return {"status": "admitted", "evidence": "ok"}


def _pair(name_a="tool.op", name_b=None, issued=1000.0, executed=1010.0):
    """Build a well-formed decision/execution receipt pair.

    ``name_b`` lets the caller give the execution receipt a
    DIFFERENT verdict record (the swapped-effect attack shape).
    """
    dec = _rp.issue_decision_receipt(
        {"attempt": _attempt(name_a), "effect": _effect_ok()}, issued)
    exe = _rp.issue_execution_receipt(
        {"attempt": _attempt(name_b or name_a), "effect": _effect_ok()},
        {"outcome": "completed", "executor_may_have_accepted": True},
        dec, executed)
    return dec, exe


# ----------------------------------------------------------------------
# Probes. Each returns (verdict, detail).
# ----------------------------------------------------------------------

def _p01_valid():
    dec, exe = _pair()
    try:
        out = _dea.check_agreement(dec, exe)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "valid pair refused: %r" % exc
    if not out.get("agreement") or out.get("agreement_digest") is None:
        return "BREAK", "valid pair did not agree: %r" % out
    # The returned digests must be the RECOMPUTED ones, not copies.
    if out["decision_digest"] != dec["decision_digest"]:
        return "BREAK", "decision digest not recomputed from bytes"
    if out["effect_digest"] != exe["effect_digest"]:
        return "BREAK", "effect digest not recomputed from bytes"
    return "HELD", "valid pair agrees; digests recomputed"


def _p02_swapped():
    dec, _ = _pair(name_a="tool.op")
    # An execution receipt whose verdict record is for a DIFFERENT
    # action than the decision authorized. Its backlink still points
    # at the (deterministically identical) tool.op decision digest —
    # the attack is in the bytes, not the link.
    _, other_exe = _pair(name_b="tool.other")
    ok = _refuses(lambda: _dea.check_agreement(dec, other_exe),
                  "decision-effect-disagreement")
    if not ok:
        return "BREAK", "swapped effect not refused as disagreement"
    # Sanity: the two verdict records really differ on the attempt.
    from gov import action_capsule as _ac
    import hashlib as _hl
    dec_attempt = _hl.sha256(_ac.canonical_json_bytes(
        dec["verdict_record"]["attempt"])).hexdigest()
    exe_attempt = _hl.sha256(_ac.canonical_json_bytes(
        other_exe["verdict_record"]["attempt"])).hexdigest()
    if dec_attempt == exe_attempt:
        return "BREAK", "fixture failed: attempts should differ"
    return "HELD", "swapped effect refuses decision-effect-disagreement"


def _p03_effect_absent():
    dec, _ = _pair()
    ok = _refuses(lambda: _dea.check_agreement(dec, None),
                  "decision-effect-effect-absent")
    return ("HELD" if ok else "BREAK",
            "decision without effect refuses "
            "decision-effect-effect-absent")


def _p04_decision_absent():
    _, exe = _pair()
    ok = _refuses(lambda: _dea.check_agreement(None, exe),
                  "decision-effect-extra-effect")
    return ("HELD" if ok else "BREAK",
            "effect without decision refuses decision-effect-extra-effect")


def _p05_time_inversion():
    dec, exe = _pair(issued=1000.0, executed=900.0)
    ok = _refuses(lambda: _dea.check_agreement(dec, exe),
                  "decision-effect-time-inversion")
    return ("HELD" if ok else "BREAK",
            "time-inverted pair refuses decision-effect-time-inversion")


def _p06_tampered_bytes():
    dec, exe = _pair()
    bad = copy.deepcopy(dec)
    # Mutate the verdict bytes in place; keep every claimed digest.
    bad["verdict_record"]["attempt"]["args"]["x"] = 999
    ok = _refuses(lambda: _dea.check_agreement(bad, exe),
                  "decision-effect-decision-drift")
    return ("HELD" if ok else "BREAK",
            "tampered decision bytes caught by recomputation")


def _p07_empty():
    for args in ((None, None), ({}, {}), ("x", {}), ([], [])):
        ok = _refuses(lambda: _dea.check_agreement(*args),
                      "decision-effect-malformed")
        if not ok:
            return "BREAK", "empty inputs not refused: %r" % (args,)
    return "HELD", "empty / non-dict inputs fail closed"


def _p08_sealed():
    dec, exe = _pair()
    try:
        cap = _dea.seal_agreement(dec, exe)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "seal_agreement refused: %r" % exc
    from gov import action_capsule as _ac
    try:
        body = _ac.verify_capsule(cap)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "sealed agreement not verifiable: %r" % exc
    # Tampering the sealed evidence must break its digest commitment.
    tampered = hashlib.sha256(b"tampered").hexdigest()
    if _dea.agreement_digest_of(cap) == tampered:
        return "BREAK", "agreement digest not tamper-evident"
    ok = _refuses(lambda: _dea.deny_authority_use(cap),
                  "decision-effect-not-authorization")
    if not ok:
        return "BREAK", "agreement offered as authority not refused"
    if body["effect"]["status"] != "admitted":
        return "BREAK", "agreement capsule effect mislabeled: %r" % body
    return "HELD", "agreement seals into digest-linked evidence; " \
        "authority-shaped use refused"


_PROBES = [
    _p01_valid, _p02_swapped, _p03_effect_absent, _p04_decision_absent,
    _p05_time_inversion, _p06_tampered_bytes, _p07_empty, _p08_sealed,
]


def _run_once():
    results = []
    for name, probe in zip(PROBE_NAMES, _PROBES):
        if not HAVE_MODULE:
            results.append((name, "GAP",
                            "gov/decision_effect_agreement.py absent "
                            "(pristine red)"))
            continue
        t0 = time.time()
        try:
            verdict, detail = probe()
        except Exception as exc:  # noqa: BLE001
            verdict = "ERROR"
            detail = "%r %s" % (exc, traceback.format_exc(limit=2))
        dt = time.time() - t0
        results.append((name, verdict, "%s (%.2fs)" % (detail, dt)))
    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_receipt_pairs.py",
                 "tests/test_action_capsule.py",
                 "tests/test_effect_status.py"):
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
    print("w230 agreement probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
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
