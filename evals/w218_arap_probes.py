#!/usr/bin/env python3
"""Wave-218 lane A: ARAP (Access Request and Approval profile) hardening battery.

Seam under test: gov/arap.py — a tighten-only opt-in layer over the
approval queue implementing three ARAP disciplines natively
reimplemented from the AuthZEN ARAP draft (no upstream source vendored,
no spec conformance claimed):

1. Authorization-relevant context: an approval whose context is not
   DECLARED and integrity-protected binds only the
   subject/resource/action triple. Citing uncited context fails closed.
2. Terminal statuses (approved|denied|expired|cancelled|failed|partial)
   with explicit, audited, monotonic transitions and bulk aggregation.
   No terminal -> non-terminal transition is ever allowed.
3. Idempotency-Key discipline: same key + different body -> 409
   duplicate_request; same key + identical body -> the ORIGINAL decision
   is replayed, never re-decided. Cancellation requires its own
   authorization; handles presented to clients carry no authority.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-217 HEAD
aa92522b1a683b9608d50810ca8984dcdebc102b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g218a
  TMPDIR=/var/tmp/g218a ~/workspace/.gov-venv/bin/python evals/w218_arap_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g218a-u \\
      ~/workspace/.gov-venv/bin/python evals/w218_arap_probes.py
"""

import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g218a-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import arap  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    arap = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _break(name, detail=""):
    _record(name, "BREAK", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


# ----------------------------------------------------------------------
# Harness helpers (only meaningful when the module is present).
# ----------------------------------------------------------------------

_KEY = b"arap-test-key-0123456789abcdef"


def _audit_log():
    entries = []

    def _audit(entry):
        entries.append(dict(entry))

    return entries, _audit


def _new_request(**kw):
    kw.setdefault("authorized_cancellers", ("op-canceller",))
    return arap.new_request(
        "req-1", "agent-1", "write_file", "write",
        context={"policy_flag": "b", "risk": "low"},
        **kw)


def _expect_refused(name, fn, exc_types, codes=None):
    """fn must raise one of exc_types (optionally with an expected
    code); anything else is a BREAK."""
    try:
        fn()
    except exc_types as exc:
        if codes is not None and getattr(exc, "code", None) not in codes:
            _break(name, "refused but wrong code %r (want one of %s)"
                   % (getattr(exc, "code", None), codes))
        else:
            _held(name, "refused: %s" % getattr(exc, "code", "?"))
        return
    except Exception as exc:  # noqa: BLE001
        _break(name, "wrong exception type: %s: %s"
               % (type(exc).__name__, exc))
        return
    _break(name, "NOT refused -- attack shape accepted")


# ----------------------------------------------------------------------
# Probes: authorization-relevant context.
# ----------------------------------------------------------------------

@_probe("happy-path-context-declared")
def _p_happy_ctx():
    if not _IMPORT_OK:
        return _gap("happy-path-context-declared")
    decl = arap.declare_context({"policy_flag": "b", "risk": "low"},
                                key=_KEY)
    arap.verify_context_binding(decl["declared"], decl["binding"],
                                key=_KEY)
    arap.check_cited_context(["policy_flag", "risk"], decl["declared"])
    scope = arap.binding_scope(decl["declared"])
    if scope == "subject/resource/action + 2 declared context fields":
        _held("happy-path-context-declared", "declared+cited verified")
    else:
        _break("happy-path-context-declared",
               "unexpected scope string %r" % scope)


@_probe("contextless-approval-binds-triple-only")
def _p_triple_only():
    if not _IMPORT_OK:
        return _gap("contextless-approval-binds-triple-only")
    scope = arap.binding_scope({})
    if scope != "subject/resource/action":
        _break("contextless-approval-binds-triple-only",
               "unexpected scope string %r" % scope)
        return
    _held("contextless-approval-binds-triple-only",
          "no declared context -> triple-only binding")


@_probe("cited-but-undeclared-context-refused")
def _p_undeclared_cited():
    if not _IMPORT_OK:
        return _gap("cited-but-undeclared-context-refused")
    decl = arap.declare_context({"policy_flag": "b"}, key=_KEY)
    _expect_refused(
        "cited-but-undeclared-context-refused",
        lambda: arap.check_cited_context(["policy_flag", "risk_score"],
                                         decl["declared"]),
        (arap.ContextNotDeclaredError,),
        codes=("context-not-declared",))


@_probe("tampered-context-binding-refused")
def _p_tampered_binding():
    if not _IMPORT_OK:
        return _gap("tampered-context-binding-refused")
    decl = arap.declare_context({"policy_flag": "b"}, key=_KEY)
    tampered = dict(decl["declared"])
    tampered["policy_flag"] = "sha256:" + "ff" * 32
    _expect_refused(
        "tampered-context-binding-refused",
        lambda: arap.verify_context_binding(tampered, decl["binding"],
                                            key=_KEY),
        (arap.ContextNotDeclaredError,),
        codes=("context-binding-mismatch",))


@_probe("context-binding-wrong-key-refused")
def _p_wrong_key():
    if not _IMPORT_OK:
        return _gap("context-binding-wrong-key-refused")
    decl = arap.declare_context({"policy_flag": "b"}, key=_KEY)
    _expect_refused(
        "context-binding-wrong-key-refused",
        lambda: arap.verify_context_binding(decl["declared"],
                                            decl["binding"],
                                            key=b"wrong-key-0000000000000000000000"),
        (arap.ContextNotDeclaredError,),
        codes=("context-binding-mismatch",))


# ----------------------------------------------------------------------
# Probes: terminal statuses.
# ----------------------------------------------------------------------

@_probe("terminal-monotonicity-approved-to-pending-refused")
def _p_term_mono():
    if not _IMPORT_OK:
        return _gap("terminal-monotonicity-approved-to-pending-refused")
    entries, audit = _audit_log()
    req = _new_request()
    arap.transition(req, "approved", by="op-1", audit=audit)
    _expect_refused(
        "terminal-monotonicity-approved-to-pending-refused",
        lambda: arap.transition(req, "pending", by="op-1", audit=audit),
        (arap.TerminalTransitionError,),
        codes=("terminal-transition-refused",))
    # The refusal must not have moved the request anywhere.
    if req["status"] != "approved":
        _break("terminal-monotonicity-approved-to-pending-refused",
               "status moved despite refusal: %r" % req["status"])
        return
    if (len(entries) == 1 and entries[0]["event"] == "arap_status_transition"
            and entries[0]["to"] == "approved"):
        _held("terminal-monotonicity-approved-to-pending-refused",
              "audited; refusal held")
    else:
        _break("terminal-monotonicity-approved-to-pending-refused",
               "transition not audited: %r" % entries)


@_probe("terminal-to-terminal-refused")
def _p_term_term():
    if not _IMPORT_OK:
        return _gap("terminal-to-terminal-refused")
    req = _new_request()
    arap.transition(req, "denied", by="op-1")
    _expect_refused(
        "terminal-to-terminal-refused",
        lambda: arap.transition(req, "cancelled", by="op-1"),
        (arap.TerminalTransitionError,),
        codes=("terminal-transition-refused",))


@_probe("expiry-transition-audited")
def _p_expiry():
    if not _IMPORT_OK:
        return _gap("expiry-transition-audited")
    entries, audit = _audit_log()
    req = _new_request()
    arap.transition(req, "expired", by="ttl-sweeper", audit=audit)
    hist = req.get("history", [])
    if (req["status"] == "expired"
            and len(hist) == 2
            and hist[-1]["from"] == "pending"
            and hist[-1]["to"] == "expired"
            and len(entries) == 1
            and entries[0]["event"] == "arap_status_transition"):
        _held("expiry-transition-audited", "explicit + audited")
    else:
        _break("expiry-transition-audited",
               "expiry not explicit/audited: %r %r" % (hist, entries))


@_probe("bulk-aggregation-mixed-is-partial")
def _p_bulk():
    if not _IMPORT_OK:
        return _gap("bulk-aggregation-mixed-is-partial")
    if arap.aggregate_statuses(["approved", "denied"]) != "partial":
        _break("bulk-aggregation-mixed-is-partial",
               "mixed approved/denied did not aggregate to partial")
        return
    if arap.aggregate_statuses(["approved", "approved"]) != "approved":
        _break("bulk-aggregation-mixed-is-partial",
               "uniform approved did not aggregate to approved")
        return
    try:
        arap.aggregate_statuses(["approved", "pending"])
    except ValueError:
        _held("bulk-aggregation-mixed-is-partial",
              "partial on mixed; non-terminal in bulk refused")
        return
    except Exception as exc:  # noqa: BLE001
        _break("bulk-aggregation-mixed-is-partial",
               "wrong exception %s" % type(exc).__name__)
        return
    _break("bulk-aggregation-mixed-is-partial",
           "non-terminal status accepted in bulk aggregation")


# ----------------------------------------------------------------------
# Probes: idempotency.
# ----------------------------------------------------------------------

@_probe("idempotency-replay-returns-original")
def _p_replay():
    if not _IMPORT_OK:
        return _gap("idempotency-replay-returns-original")
    reg = arap.IdempotencyRegistry()
    key, body = "idem-1", "sha256:" + "aa" * 32
    if reg.check(key, body) != "new":
        _break("idempotency-replay-returns-original",
               "first check did not report new")
        return
    reg.record(key, body, "decision:approved#1")
    if reg.check(key, body) != "replay":
        _break("idempotency-replay-returns-original",
               "replay not detected")
        return
    if reg.decision(key) != "decision:approved#1":
        _break("idempotency-replay-returns-original",
               "original decision not returned on replay")
        return
    _held("idempotency-replay-returns-original",
          "original decision replayed, never re-decided")


@_probe("idempotency-body-mismatch-refused")
def _p_mismatch():
    if not _IMPORT_OK:
        return _gap("idempotency-body-mismatch-refused")
    reg = arap.IdempotencyRegistry()
    key = "idem-2"
    reg.record(key, "sha256:" + "aa" * 32, "decision:approved#1")
    _expect_refused(
        "idempotency-body-mismatch-refused",
        lambda: reg.check(key, "sha256:" + "bb" * 32),
        (arap.DuplicateRequestError,),
        codes=("duplicate_request",))


@_probe("idempotency-record-overwrite-refused")
def _p_overwrite():
    if not _IMPORT_OK:
        return _gap("idempotency-record-overwrite-refused")
    reg = arap.IdempotencyRegistry()
    key = "idem-3"
    reg.record(key, "sha256:" + "aa" * 32, "decision:approved#1")
    # A second record() with the same key but a DIFFERENT body is a
    # key-reuse attack: it must be refused, not overwrite.
    _expect_refused(
        "idempotency-record-overwrite-refused",
        lambda: reg.record(key, "sha256:" + "cc" * 32,
                           "decision:approved#2"),
        (arap.DuplicateRequestError,),
        codes=("duplicate_request",))
    if reg.decision(key) != "decision:approved#1":
        _break("idempotency-record-overwrite-refused",
               "original decision was overwritten")


# ----------------------------------------------------------------------
# Probes: cancellation authorization and handles.
# ----------------------------------------------------------------------

@_probe("authorized-cancellation")
def _p_auth_cancel():
    if not _IMPORT_OK:
        return _gap("authorized-cancellation")
    entries, audit = _audit_log()
    req = _new_request()
    arap.cancel_request(req, "op-canceller", audit=audit)
    if (req["status"] == "cancelled"
            and any(e.get("to") == "cancelled" for e in entries)):
        _held("authorized-cancellation", "cancelled + audited")
    else:
        _break("authorized-cancellation",
               "status=%r entries=%r" % (req["status"], entries))


@_probe("unauthorized-cancellation-refused")
def _p_unauth_cancel():
    if not _IMPORT_OK:
        return _gap("unauthorized-cancellation-refused")
    req = _new_request()
    _expect_refused(
        "unauthorized-cancellation-refused",
        lambda: arap.cancel_request(req, "agent-1"),
        (arap.CancellationUnauthorizedError,),
        codes=("cancellation-unauthorized",))
    if req["status"] != "pending":
        _break("unauthorized-cancellation-refused",
               "status moved despite refusal: %r" % req["status"])


@_probe("handle-carries-no-authority")
def _p_handle():
    if not _IMPORT_OK:
        return _gap("handle-carries-no-authority")
    reg = arap.HandleRegistry()
    handle = reg.issue("req-1")
    # A valid handle presented by an UNauthorized principal buys
    # nothing: authority is checked first, handle second.
    _expect_refused(
        "handle-carries-no-authority",
        lambda: reg.resolve(handle, "agent-1",
                            authorized=("op-canceller",)),
        (arap.HandleNotAuthorityError,),
        codes=("handle-not-authority",))
    # The authorized path resolves fine.
    if reg.resolve(handle, "op-canceller",
                   authorized=("op-canceller",)) == "req-1":
        _held("handle-carries-no-authority",
              "handle alone refused; authorized path resolves")
    else:
        _break("handle-carries-no-authority", "authorized resolve failed")


@_probe("unknown-handle-refused")
def _p_unknown_handle():
    if not _IMPORT_OK:
        return _gap("unknown-handle-refused")
    reg = arap.HandleRegistry()
    _expect_refused(
        "unknown-handle-refused",
        lambda: reg.resolve("no-such-handle", "op-canceller",
                            authorized=("op-canceller",)),
        (arap.HandleNotAuthorityError,),
        codes=("handle-unknown",))


# ----------------------------------------------------------------------
# Green check (depth-1) + main.
# ----------------------------------------------------------------------

def _green_check():
    if not _IMPORT_OK:
        _record("green-check", "GAP", "module absent on pristine tree")
        return
    if GREEN_SKIP:
        _record("green-check", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    adj = [
        ["evals/w217_quorum_probes.py"],
        ["evals/w217_receipt_probes.py"],
    ]
    ok = True
    for battery in adj:
        try:
            r = subprocess.run(
                [sys.executable, battery[0]], cwd=REPO, env=env,
                capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                ok = False
                _record("green-check", "ERROR",
                        "%s -> rc %d" % (battery[0], r.returncode))
        except Exception as exc:  # noqa: BLE001
            ok = False
            _record("green-check", "ERROR",
                    "%s -> %s" % (battery[0], exc))
    if ok:
        _record("green-check", "HELD", "2 adjacent batteries green")


def main():
    print("ARAP hardening battery: context binding + terminal lifecycle "
          "+ idempotency + cancellation auth")
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    first = [(n, v) for (n, v, d) in _RESULTS]
    _RESULTS[:] = []
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    if [(n, v) for (n, v, d) in _RESULTS] != first:
        print("DETERMINISM: FAIL")
        return 2
    print("DETERMINISM: PASS (%d/%d probes verdict-identical)"
          % (len(_RESULTS), len(first)))
    _green_check()
    held = sum(1 for _n, v, _d in _RESULTS if v == "HELD")
    gaps = sum(1 for _n, v, _d in _RESULTS if v == "GAP")
    breaks = sum(1 for _n, v, _d in _RESULTS if v == "BREAK")
    errors = sum(1 for _n, v, _d in _RESULTS if v == "ERROR")
    res = sum(1 for _n, v, _d in _RESULTS if v == "RESIDUAL")
    print("SUMMARY: %d HELD / %d GAP / %d BREAK / %d RESIDUAL / %d ERROR"
          % (held, gaps, breaks, res, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
