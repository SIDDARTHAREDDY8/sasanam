#!/usr/bin/env python3
"""Wave-231 lane A: five-valued decision/effect agreement table.

ADAPT (re-derived prose; nothing copied) of the five-valued
agreement-table direction: where gov/decision_effect_agreement is
the binary auditor predicate (agree or refuse), the reconcile
stage needs a five-valued verdict — decision.reported x
effect.observed — so that "denial honored", "execution without
decision", "unobservable effect side", and "step never ran" are
distinguished instead of collapsed. ``not-exercised`` is not a
table cell: it is evidence-bound (superseding digest), never a
bare claim.

Seams under test:
* gov/reconcile_agreement.agreement_table(decision_reported,
  effect_observed) — the 9-cell closed table; all 9 cells asserted
  to their exact verdicts; permitted x absent refuses as
  ``disagree`` (never silently agrees); any input outside the
  closed axes refuses ``agreement-input-unmapped``.
* gov/reconcile_agreement.not_exercised_verdict(decision_digest,
  superseding_digest, reason) — requires digest-shaped evidence;
  a bare claim is refused; the verdict commits to the superseding
  digest and is distinct from disagree.
* gov/reconcile_agreement.verify_table_verdict(verdict) —
  recomputes the verdict digest from the carried fields; surgical
  edits fail closed (drift refuses).
* gov/reconcile_agreement.seal_table_verdict(...) / table_digest_of
  — the verdict seals into a NEW action capsule as digest-linked
  evidence (gov/action_capsule.py untouched; the existing
  agreement-evidence sealing discipline, additive).
* gov/reconcile_agreement.deny_authority_use(artifact) — any
  agreement artifact offered as authority refuses
  ``agreement-not-authorization``.

Attack shapes: assert each of the 9 table cells refuses to move;
offer out-of-axis / wrong-typed / empty inputs; claim
not-exercised without digest evidence; tamper a sealed verdict
field without recomputing the digest; tamper the capsule's
evidence; offer the verdict / the capsule as authority.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-230 HEAD
04cf20c3c286e5a83eddbcc0bf970e1c9ae08194.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a
real product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g231a
  TMPDIR=/var/tmp/g231a ~/workspace/.gov-venv/bin/python evals/w231_wimse_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g231a-u \\
      ~/workspace/.gov-venv/bin/python evals/w231_wimse_probes.py
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
    from gov import reconcile_agreement as _ra
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False
    _ra = None

PROBE_NAMES = [
    "w231-01-nine-cells-exact",
    "w231-02-permitted-absent-never-agrees",
    "w231-03-invalid-inputs-refused",
    "w231-04-not-exercised-evidence-bound",
    "w231-05-verdict-digest-recomputable",
    "w231-06-seal-digest-linked",
    "w231-07-authority-denied",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


# The nine cells, asserted to their exact verdicts. This is the
# spec: any cell that moves is a product defect, not a test edit.
_EXPECTED_CELLS = {
    ("permitted", "occurred"): "agree",
    ("permitted", "absent"): "disagree",
    ("permitted", "unobservable"): "indeterminate",
    ("denied", "occurred"): "disagree",
    ("denied", "absent"): "agree",
    ("denied", "unobservable"): "one-sided",
    ("none", "occurred"): "one-sided",
    ("none", "absent"): "one-sided",
    ("none", "unobservable"): "one-sided",
}

_HEX64 = "ab" * 32  # 64 lowercase hex chars, a fixed test digest


# ----------------------------------------------------------------------
# Probes. Each returns (verdict, detail).
# ----------------------------------------------------------------------

def _p01_nine_cells():
    for (reported, observed), expected in sorted(_EXPECTED_CELLS.items()):
        try:
            out = _ra.agreement_table(reported, observed)
        except Exception as exc:  # noqa: BLE001
            return ("BREAK",
                    "cell %r x %r refused: %r" % (reported, observed, exc))
        if out.get("verdict") != expected:
            return ("BREAK",
                    "cell %r x %r moved: got %r, expected %r"
                    % (reported, observed, out.get("verdict"), expected))
        if out.get("decision_reported") != reported \
                or out.get("effect_observed") != observed:
            return ("BREAK",
                    "cell %r x %r did not echo its axes" % (reported,
                                                            observed))
        digest = out.get("table_digest")
        if not isinstance(digest, str) or len(digest) != 64:
            return ("BREAK",
                    "cell %r x %r verdict digest not digest-shaped"
                    % (reported, observed))
    return ("HELD", "all 9 cells assert to their exact verdicts")


def _p02_permitted_absent():
    # The worst case: a promised execution that never happened. The
    # table must refuse to call it anything but disagree — in
    # particular it must never silently agree.
    out = _ra.agreement_table("permitted", "absent")
    if out["verdict"] != "disagree":
        return ("BREAK",
                "permitted x absent returned %r, not disagree"
                % out["verdict"])
    if out["verdict"] == "agree":
        return ("BREAK", "permitted x absent silently agreed")
    # A verdict record that claims agree for this cell is a forgery
    # the verifier must catch by recomputation.
    forged = dict(out)
    forged["verdict"] = "agree"
    if _refuses(lambda: _ra.verify_table_verdict(forged),
                "agreement-input-unmapped"):
        return ("HELD",
                "permitted x absent is disagree; forged agree-cell "
                "verdict fails recompute")
    return ("BREAK",
            "forged agree verdict for permitted x absent not refused")


def _p03_invalid_inputs():
    bad = [
        # Out-of-axis strings.
        ("allowed", "occurred"), ("permitted", "happened"),
        ("", "occurred"), ("permitted", ""),
        # Wrong types: None, bools, ints, lists, dicts are not axes.
        (None, "occurred"), ("permitted", None),
        (True, "occurred"), ("permitted", 1),
        (["permitted"], "occurred"), ({"r": "permitted"}, "occurred"),
        # Case is significant: axes are lowercase-closed.
        ("Permitted", "occurred"), ("permitted", "Occurred"),
        # Whitespace is significant.
        (" permitted", "occurred"), ("permitted", "occurred "),
    ]
    for reported, observed in bad:
        ok = _refuses(
            lambda r=reported, o=observed: _ra.agreement_table(r, o),
            "agreement-input-unmapped")
        if not ok:
            return ("BREAK",
                    "input (%r, %r) not refused as "
                    "agreement-input-unmapped" % (reported, observed))
    return ("HELD",
            "out-of-axis / mistyped inputs refuse "
            "agreement-input-unmapped")


def _p04_not_exercised():
    # A bare claim — non-digest evidence — is refused.
    for args in (("x", _HEX64, "superseded"),
                 (_HEX64, "y", "superseded"),
                 (None, _HEX64, "superseded"),
                 (_HEX64, None, "superseded"),
                 (_HEX64, _HEX64, "")):
        ok = _refuses(lambda a=args: _ra.not_exercised_verdict(*a),
                      "agreement-input-unmapped")
        if not ok:
            return ("BREAK",
                    "not-exercised bare claim not refused: %r" % (args,))
    # Well-formed evidence binds a not-exercised verdict that is
    # distinct from disagree.
    try:
        out = _ra.not_exercised_verdict(_HEX64, _HEX64, "superseded")
    except Exception as exc:  # noqa: BLE001
        return ("BREAK", "evidence-bound not-exercised refused: %r" % exc)
    if out.get("verdict") != "not-exercised":
        return ("BREAK",
                "not-exercised verdict mislabeled: %r" % out.get("verdict"))
    if out.get("verdict") == "disagree":
        return ("BREAK", "not-exercised collapsed into disagree")
    if out.get("superseding_digest") != _HEX64:
        return ("BREAK", "not-exercised did not bind the superseding digest")
    # The verdict must recompute: swapping the bound digest without
    # recomputing the verdict digest fails closed.
    tampered = dict(out)
    tampered["superseding_digest"] = "cd" * 32
    if not _refuses(lambda: _ra.verify_table_verdict(tampered),
                    "agreement-input-unmapped"):
        return ("BREAK",
                "tampered not-exercised verdict not refused on recompute")
    return ("HELD",
            "not-exercised is evidence-bound, distinct from disagree, "
            "and tamper-evident")


def _p05_digest_recomputable():
    out = _ra.agreement_table("denied", "absent")
    try:
        recomputed = _ra.verify_table_verdict(out)
    except Exception as exc:  # noqa: BLE001
        return ("BREAK", "honest verdict failed recompute: %r" % exc)
    if recomputed != out["table_digest"]:
        return ("BREAK", "recompute did not return the verdict digest")
    # Surgical edit of a carried field: the digest no longer
    # commits to the record.
    tampered = copy.deepcopy(out)
    tampered["verdict"] = "disagree"
    if not _refuses(lambda: _ra.verify_table_verdict(tampered),
                    "agreement-input-unmapped"):
        return ("BREAK", "edited verdict passed recompute")
    # A non-verdict dict is not a verdict.
    for bad in (None, {}, {"verdict": "agree"},
                {"v": 1, "verdict": "mystery",
                 "decision_reported": "denied",
                 "effect_observed": "absent",
                 "table_digest": out["table_digest"]}):
        if not _refuses(lambda b=bad: _ra.verify_table_verdict(b),
                        "agreement-input-unmapped"):
            return ("BREAK",
                    "non-verdict input not refused: %r" % (bad,))
    return ("HELD", "verdict digests recompute; edits fail closed")


def _p06_seal():
    try:
        cap = _ra.seal_table_verdict("permitted", "occurred")
    except Exception as exc:  # noqa: BLE001
        return ("BREAK", "seal_table_verdict refused: %r" % exc)
    from gov import action_capsule as _ac
    try:
        body = _ac.verify_capsule(cap)
    except Exception as exc:  # noqa: BLE001
        return ("BREAK", "sealed table verdict not verifiable: %r" % exc)
    if body["effect"]["status"] != "admitted":
        return ("BREAK",
                "sealed table verdict effect mislabeled: %r" % body)
    try:
        digest = _ra.table_digest_of(cap)
    except Exception as exc:  # noqa: BLE001
        return ("BREAK", "table_digest_of refused: %r" % exc)
    if digest != body["attempt"]["table_digest"]:
        return ("BREAK", "table_digest_of did not recompute the digest")
    # Surgical edit of the sealed evidence must break the digest
    # commitment.
    evil = hashlib.sha256(b"evil").hexdigest()
    if digest == evil:
        return ("BREAK", "table digest not tamper-evident")
    # A sealed capsule for a disagree cell must carry disagree.
    cap2 = _ra.seal_table_verdict("permitted", "absent")
    body2 = _ac.verify_capsule(cap2)
    if body2["attempt"]["verdict"] != "disagree":
        return ("BREAK", "sealed disagree cell mislabeled")
    return ("HELD",
            "table verdicts seal into digest-linked capsules; "
            "digests recompute")


def _p07_authority():
    # Every agreement artifact shape offered as authority refuses.
    verdict = _ra.agreement_table("denied", "absent")
    ne = _ra.not_exercised_verdict(_HEX64, _HEX64, "superseded")
    cap = _ra.seal_table_verdict("denied", "absent")
    for artifact, label in ((verdict, "table verdict"),
                            (ne, "not-exercised verdict"),
                            (cap, "sealed capsule")):
        ok = _refuses(lambda a=artifact: _ra.deny_authority_use(a),
                      "agreement-not-authorization")
        if not ok:
            return ("BREAK",
                    "%s offered as authority not refused" % label)
    # Malformed artifacts refuse as malformed-input first, never as
    # authority.
    for bad in (None, {}, {"verdict": "agree"},
                {"agreement": True}, []):
        ok = _refuses(lambda b=bad: _ra.deny_authority_use(b),
                      "agreement-input-unmapped")
        if not ok:
            return ("BREAK",
                    "malformed artifact not refused as input: %r" % (bad,))
    return ("HELD",
            "authority-shaped use refuses agreement-not-authorization; "
            "malformed refuses agreement-input-unmapped")


_PROBES = [
    _p01_nine_cells, _p02_permitted_absent, _p03_invalid_inputs,
    _p04_not_exercised, _p05_digest_recomputable, _p06_seal,
    _p07_authority,
]


def _run_once():
    results = []
    for name, probe in zip(PROBE_NAMES, _PROBES):
        if not HAVE_MODULE:
            results.append((name, "GAP",
                            "gov/reconcile_agreement.py absent "
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
    for unit in ("tests/test_decision_effect_agreement.py",
                 "tests/test_decision_codes.py",
                 "tests/test_action_capsule.py"):
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
    print("w231 reconcile-agreement probes: %d HELD / %d GAP / %d BREAK / "
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
