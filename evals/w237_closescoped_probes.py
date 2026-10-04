#!/usr/bin/env python3
"""Wave-237 lane D: closure-scoped approvals (OpenClaw bounding).

Attack shapes at the public seams (break-first, red-first on base):
* an approval packet binds run + sandbox + requester + route +
  approval identity + the canonical request digest; presenting the
  packet against a different run_id refuses ``approval-run-mismatch``,
  a different route refuses ``approval-route-mismatch``, a different
  sandbox refuses ``approval-sandbox-mismatch`` -- each binding is
  checked independently and named;
* capabilities die at attempt settlement: ``settle_attempt`` marks the
  packet consumed; ``exercise_capability`` after settlement refuses
  ``approval-capability-dead``; double-settlement is idempotent (the
  same receipt), never a second execution;
* recheck immediately before the effecting write:
  ``recheck_and_write`` re-verifies all bindings AND re-checks the
  request digest against current state at write time (TOCTOU guard);
  state moved since issuance refuses ``approval-state-stale``;
* tampered packets refuse ``scoped-approval-tampered``; malformed
  packets refuse ``scoped-approval-malformed``.

Seams under test:
* gov/closure_scoped_approvals.py -- issue_scoped_approval,
  verify_scoped_approval, settle_attempt, exercise_capability,
  recheck_and_write.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-236 HEAD 9a725ce5fac37b95a2502eaebebfc33e7a8fb0d0.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g237d
  TMPDIR=/var/tmp/g237d ~/workspace/.gov-venv/bin/python \
      evals/w237_closescoped_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_NEW_API = False
try:
    from gov import closure_scoped_approvals as _cs
    HAVE_NEW_API = all(hasattr(_cs, n) for n in (
        "ClosureScopedApprovalError", "issue_scoped_approval",
        "verify_scoped_approval", "settle_attempt", "exercise_capability",
        "recheck_and_write"))
except ImportError:
    _cs = None

PROBE_NAMES = [
    "closescoped-happy-path",
    "closescoped-run-mismatch",
    "closescoped-route-mismatch",
    "closescoped-sandbox-mismatch",
    "closescoped-capability-dead",
    "closescoped-state-stale",
    "closescoped-tampered-refused",
]


def _issue(**kw):
    base = dict(
        run_id="run-001", sandbox_id="sbx-a", requester_id="agent-7",
        route="deploy/prod", approval_identity="approver-3",
        capabilities=["deploy:prod", "logs:read"],
        request_digest="ab" * 32, state_digest="cd" * 32)
    base.update(kw)
    return _cs.issue_scoped_approval(**base)


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
        packet = _issue()
        assert packet["version"] == 1, packet
        assert len(packet["approval_digest"]) == 64, packet
        assert _cs.verify_scoped_approval(packet) is True
        # Independent-context verification holds for the true context.
        assert _cs.verify_scoped_approval(
            packet, run_id="run-001", sandbox_id="sbx-a",
            route="deploy/prod") is True
        # Legitimate capability exercise once, pre-settlement.
        rec = _cs.exercise_capability(packet, "deploy:prod")
        assert isinstance(rec, dict) and rec["capability"] == "deploy:prod"
        # Settlement ends the packet; a second settlement is the same receipt.
        receipt1 = _cs.settle_attempt(packet)
        receipt2 = _cs.settle_attempt(packet)
        assert receipt1 == receipt2, (receipt1, receipt2)
        _rec(results, PROBE_NAMES[0], "HELD",
             "digest=%s..." % packet["approval_digest"][:16])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


def _p2_run_mismatch(results):
    try:
        packet = _issue()
        v, detail = _expect_code(
            lambda: _cs.verify_scoped_approval(packet, run_id="run-999"),
            "approval-run-mismatch")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[1], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


def _p3_route_mismatch(results):
    try:
        # A pre-computed approval re-presented at a different route.
        packet = _issue()
        v, detail = _expect_code(
            lambda: _cs.verify_scoped_approval(packet, route="deploy/stage"),
            "approval-route-mismatch")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[2], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


def _p4_sandbox_mismatch(results):
    try:
        packet = _issue()
        v, detail = _expect_code(
            lambda: _cs.verify_scoped_approval(packet, sandbox_id="sbx-z"),
            "approval-sandbox-mismatch")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[3], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


def _p5_capability_dead(results):
    try:
        packet = _issue()
        receipt = _cs.settle_attempt(packet)
        assert receipt["settled"] is True
        v, detail = _expect_code(
            lambda: _cs.exercise_capability(packet, "deploy:prod"),
            "approval-capability-dead")
        assert v == "HELD", detail
        # The effecting write after settlement is equally dead.
        v2, detail2 = _expect_code(
            lambda: _cs.recheck_and_write(packet, "cd" * 32),
            "approval-capability-dead")
        assert v2 == "HELD", detail2
        _rec(results, PROBE_NAMES[4], "HELD",
             "exercise %s; write %s" % (detail, detail2))
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


def _p6_state_stale(results):
    try:
        packet = _issue()
        # State moved since issuance: the TOCTOU guard fires before any
        # effect, and the packet is NOT settled (refusal is not the write).
        v, detail = _expect_code(
            lambda: _cs.recheck_and_write(packet, "ef" * 32),
            "approval-state-stale")
        assert v == "HELD", detail
        # A matching state rechecks clean and settles the packet.
        receipt = _cs.recheck_and_write(packet, "cd" * 32)
        assert receipt["settled"] is True
        _rec(results, PROBE_NAMES[5], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


def _p7_tampered_refused(results):
    try:
        packet = _issue()
        tampered = dict(packet)
        tampered["route"] = "deploy/prod-evil"
        v, detail = _expect_code(
            lambda: _cs.verify_scoped_approval(tampered),
            "scoped-approval-tampered")
        assert v == "HELD", detail
        # An edited packet never reaches capability exercise or the write.
        v2, detail2 = _expect_code(
            lambda: _cs.exercise_capability(tampered, "deploy:prod"),
            "scoped-approval-tampered")
        assert v2 == "HELD", detail2
        # A malformed packet is refused as malformed, not tampered.
        malformed = {"version": 1, "run_id": "run-001"}
        v3, detail3 = _expect_code(
            lambda: _cs.verify_scoped_approval(malformed),
            "scoped-approval-malformed")
        assert v3 == "HELD", detail3
        _rec(results, PROBE_NAMES[6], "HELD",
             "verify %s; exercise %s; malformed %s"
             % (detail, detail2, detail3))
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


def _run_all():
    results = {}
    _p1_happy(results)
    _p2_run_mismatch(results)
    _p3_route_mismatch(results)
    _p4_sandbox_mismatch(results)
    _p5_capability_dead(results)
    _p6_state_stale(results)
    _p7_tampered_refused(results)
    return results


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# The verdict token is the first word of the recorded verdict string; the
# original first line is kept verbatim as the note (evidence preserved), with
# any multi-line detail collapsed to its first line (" // "-joined).
# Unknown tokens fail closed as ERROR (loud, never silent). Raw results keep
# the battery's own vocabulary (count code and exit contract untouched); the
# mapping happens at emission.
_VERDICT_TOKEN_MAP = {"HELD": "HELD", "GAP": "BREAK", "BREAK": "BREAK",
                      "ERROR": "ERROR"}


def _split_row(name, v):
    first = probe_lines.first_line(v)
    tok = (first.split(":")[0].split() or [""])[0]
    mapped = _VERDICT_TOKEN_MAP.get(tok)
    if mapped is None:
        return {"probe_id": name, "verdict": "ERROR",
                "note": "unparseable verdict string: %r" % (first,)}
    _, _, rest = v.partition("\n")
    rest_first = probe_lines.first_line(rest).strip()
    note = first if not rest_first else first + " // " + rest_first
    return {"probe_id": name, "verdict": mapped, "note": note}

def main():
    t0 = time.time()
    if not HAVE_NEW_API:
        rows = [{"probe_id": name, "verdict": "BREAK",
                 "note": "GAP (closure-scoped-approvals module absent)"} for name in PROBE_NAMES]
        probe_lines.emit_dicts(rows)
        print("%d BREAK / %d HELD / %d ERROR" % (len(PROBE_NAMES), 0, 0))
        return 2
    results = _run_all()

    def _v(name):
        return results.get(name, "ERROR: missing").split("\n")[0]
    held = sum(1 for name in PROBE_NAMES if _v(name) == "HELD")
    gap = sum(1 for name in PROBE_NAMES if _v(name).startswith("GAP"))
    brk = sum(1 for name in PROBE_NAMES if _v(name).startswith("BREAK"))
    err = sum(1 for name in PROBE_NAMES if _v(name).startswith("ERROR"))
    rows = [_split_row(name, results.get(name, "ERROR: missing"))
            for name in PROBE_NAMES]
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["probe_id"], r["verdict"], r["note"]) for r in rows],
        brk + gap, held, err)
    probe_lines.emit_dicts(rows)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR (%.1fs)"
          % (brk + gap, held, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
