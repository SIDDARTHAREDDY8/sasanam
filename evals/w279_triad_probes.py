#!/usr/bin/env python3
"""Break-first battery for the wave-279 guardrail triad lane.

Steal of openai/openai-agents-python ``tool_guardrails.py`` (MIT; mechanism
only, no code vendored): per-tool guardrails with a three-outcome triad --
``allow()`` / ``reject_content(message)`` / ``raise_exception()`` -- and a
tripwire record as the canonical guard result, emitted into the audit log.

RED on base: ``gov.tool_guardrails`` does not exist, so triad probes BREAK
(the gap: tool-gate outcomes are binary, there is no deny-but-continue
outcome, and guard runs emit no standard tripwire record). Defense probes
(existing approval behavior unchanged) HELD on base.

Conventions: module-level staging default (harness's declared
ungoverned_ack is refused in production mode); deterministic; depth-1
green checks honoring GOV_SKIP_GREEN; no in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

TAXONOMY_PIN = 2127  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


RESULTS = []
ERRORS = []


def _record(name, verdict, note):
    RESULTS.append((name, verdict, note))


def _import_triad():
    """Return (module, None) or (None, note). Missing module is the red."""
    try:
        import importlib
        mod = importlib.import_module("gov.tool_guardrails")
        return mod, None
    except ImportError as e:
        return None, "no gov.tool_guardrails on this tree (%s)" % e


def _emitter():
    records = []

    def emit(record):
        records.append(record)

    return emit, records


def p_triad_shape_breaks_on_base():
    """The triad outcome vocabulary must exist: allow / reject_content /
    raise_exception plus the tripwire record shape."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-shape", "BREAK", note)
    missing = [n for n in ("allow", "reject_content", "raise_exception",
                           "ToolGuardrailFunctionOutput",
                           "ToolInputGuardrail", "ToolOutputGuardrail",
                           "run_input_guardrails", "run_output_guardrails",
                           "ToolGuardrailTripwireTriggered")
               if not hasattr(mod, n)]
    if missing:
        return _record("tg-shape", "BREAK", "missing: %s" % missing)
    _record("tg-shape", "HELD", "triad vocabulary present")


def p_allow_records_tripwire():
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-allow", "BREAK", note)
    emit, records = _emitter()

    def guard(data):
        return mod.allow()

    g = mod.ToolInputGuardrail(name="tg-allow-guard", run=guard)
    verdict = mod.run_input_guardrails(
        [g], mod.ToolInputGuardrailData(tool_name="read_file",
                                       tool_arguments={"path": "/tmp/x"}),
        emit=emit)
    if verdict.outcome != "allow":
        return _record("tg-allow", "BREAK",
                       "outcome=%r, want 'allow'" % (verdict.outcome,))
    if verdict.tripwire_triggered:
        return _record("tg-allow", "BREAK", "allow tripped the tripwire")
    if len(records) != 1:
        return _record("tg-allow", "BREAK",
                       "expected 1 tripwire record, got %d" % len(records))
    rec = records[0]
    for key in ("guardrail_name", "tool_name", "phase", "outcome",
                "tripwire_triggered", "output_info"):
        if key not in rec:
            return _record("tg-allow", "BREAK",
                           "record missing key %r" % key)
    if rec["tripwire_triggered"] is not False:
        return _record("tg-allow", "BREAK",
                       "allow record must not trip the wire")
    _record("tg-allow", "HELD", "allow recorded, wire quiet")


def p_reject_content_denies_but_continues():
    """reject_content: the call is denied with a model-facing message, but
    the run is not killed (tripwire stays quiet)."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-reject", "BREAK", note)
    emit, records = _emitter()

    def guard(data):
        return mod.reject_content("path is outside the sandbox root")

    g = mod.ToolInputGuardrail(name="tg-reject-guard", run=guard)
    verdict = mod.run_input_guardrails(
        [g], mod.ToolInputGuardrailData(tool_name="read_file",
                                       tool_arguments={"path": "/etc/x"}),
        emit=emit)
    if verdict.outcome != "reject_content":
        return _record("tg-reject", "BREAK",
                       "outcome=%r, want 'reject_content'" % verdict.outcome)
    if verdict.tripwire_triggered:
        return _record("tg-reject", "BREAK",
                       "reject_content must not halt the run")
    if "sandbox" not in (verdict.message or ""):
        return _record("tg-reject", "BREAK",
                       "rejection message lost: %r" % (verdict.message,))
    if not records or "sandbox" not in str(
            records[0].get("output_info", "")):
        return _record("tg-reject", "BREAK",
                       "rejection message not in audit evidence")
    _record("tg-reject", "HELD", "deny-but-continue with evidence")


def p_reject_empty_message_refused_loudly():
    """reject_content with an empty message is a programming error --
    fail loud, not silent."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-reject-empty", "BREAK", note)
    try:
        mod.reject_content("")
    except ValueError:
        return _record("tg-reject-empty", "HELD",
                       "empty rejection refused loudly")
    except Exception as e:
        return _record("tg-reject-empty", "BREAK",
                       "wrong exception: %r" % (e,))
    _record("tg-reject-empty", "BREAK", "empty rejection accepted silently")


def p_raise_exception_halts_loud():
    """raise_exception: loud fail-closed halt with a coded verdict distinct
    from policy refusals."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-raise", "BREAK", note)
    emit, records = _emitter()

    def guard(data):
        return mod.raise_exception("guard saw credential-shaped args")

    g = mod.ToolInputGuardrail(name="tg-raise-guard", run=guard)
    try:
        mod.run_input_guardrails(
            [g], mod.ToolInputGuardrailData(tool_name="send_email",
                                           tool_arguments={"to": "x@y"}),
            emit=emit)
    except mod.ToolGuardrailTripwireTriggered as e:
        code = getattr(e, "code", None)
        if code != "tool-guardrail-tripwire":
            return _record("tg-raise", "BREAK",
                           "coded verdict %r, want "
                           "'tool-guardrail-tripwire'" % (code,))
        if not records or records[0].get("tripwire_triggered") is not True:
            return _record("tg-raise", "BREAK",
                           "halt missing from tripwire record")
        return _record("tg-raise", "HELD",
                       "loud halt, coded verdict, wire tripped")
    except Exception as e:
        return _record("tg-raise", "BREAK", "wrong exception: %r" % (e,))
    _record("tg-raise", "BREAK", "raise_exception did not halt")


def p_guard_crash_fails_closed():
    """A guardrail that crashes is a guard-internal error: fail closed as a
    tripwire halt, never pass-through."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-crash", "BREAK", note)
    emit, records = _emitter()

    def guard(data):
        raise RuntimeError("boom")

    g = mod.ToolInputGuardrail(name="tg-crash-guard", run=guard)
    try:
        mod.run_input_guardrails(
            [g], mod.ToolInputGuardrailData(tool_name="read_file",
                                           tool_arguments={"path": "/tmp/x"}),
            emit=emit)
    except mod.ToolGuardrailTripwireTriggered as e:
        if getattr(e, "code", None) != "tool-guardrail-tripwire":
            return _record("tg-crash", "BREAK", "wrong code %r" % e)
        if not records or "boom" not in str(
                records[0].get("output_info", "")):
            return _record("tg-crash", "BREAK",
                           "guard error not in evidence record")
        return _record("tg-crash", "HELD", "crashed guard fails closed")
    except Exception as e:
        return _record("tg-crash", "BREAK", "wrong exception: %r" % (e,))
    _record("tg-crash", "BREAK", "crashed guard passed through")


def p_guard_order_first_decisive_wins():
    """Guards run in order; the first non-allow outcome wins; all runs are
    recorded."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-order", "BREAK", note)
    emit, records = _emitter()
    seen = []

    def g1(data):
        seen.append("g1")
        return mod.allow()

    def g2(data):
        seen.append("g2")
        return mod.reject_content("second guard says no")

    def g3(data):
        seen.append("g3")
        return mod.allow()

    guards = [mod.ToolInputGuardrail(name=n, run=f)
              for n, f in (("g1", g1), ("g2", g2), ("g3", g3))]
    verdict = mod.run_input_guardrails(
        guards, mod.ToolInputGuardrailData(tool_name="read_file",
                                          tool_arguments={"path": "/tmp/x"}),
        emit=emit)
    if seen != ["g1", "g2"]:
        return _record("tg-order", "BREAK",
                       "evaluation order wrong: %r" % (seen,))
    if verdict.outcome != "reject_content":
        return _record("tg-order", "BREAK", "outcome=%r" % verdict.outcome)
    if len(records) != 2:
        return _record("tg-order", "BREAK",
                       "expected 2 records, got %d" % len(records))
    _record("tg-order", "HELD", "ordered, short-circuit, all recorded")


def p_output_reject_replaces_output():
    """Output guardrails: reject_content replaces the tool output with the
    model-facing message instead of executing-killing."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-output", "BREAK", note)
    emit, records = _emitter()

    def guard(data):
        if "SECRET" in str(data.output):
            return mod.reject_content("output contained sensitive data")
        return mod.allow()

    g = mod.ToolOutputGuardrail(name="tg-output-guard", run=guard)
    verdict = mod.run_output_guardrails(
        [g], mod.ToolOutputGuardrailData(tool_name="read_file",
                                        output="SECRET=hunter2"),
        emit=emit)
    if verdict.outcome != "reject_content":
        return _record("tg-output", "BREAK", "outcome=%r" % verdict.outcome)
    if "SECRET=hunter2" in (verdict.message or ""):
        return _record("tg-output", "BREAK",
                       "sensitive output echoed in rejection")
    if records[0].get("phase") != "output":
        return _record("tg-output", "BREAK", "phase mislabeled")
    _record("tg-output", "HELD", "output replaced, secret not echoed")


def p_bad_outcome_is_programming_error():
    """A guard returning a non-outcome is a programming error (ValueError),
    not a product refusal."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-bad-outcome", "BREAK", note)
    emit, _ = _emitter()

    def guard(data):
        return "sure, fine"

    g = mod.ToolInputGuardrail(name="tg-bad-guard", run=guard)
    try:
        mod.run_input_guardrails(
            [g], mod.ToolInputGuardrailData(tool_name="read_file",
                                           tool_arguments={"path": "/tmp/x"}),
            emit=emit)
    except ValueError:
        return _record("tg-bad-outcome", "HELD", "malformed outcome loud")
    except Exception as e:
        return _record("tg-bad-outcome", "BREAK", "wrong exception: %r" % e)
    _record("tg-bad-outcome", "BREAK", "garbage outcome accepted")


def p_elicitation_composes_with_triad():
    """ApprovalQueue.elicit_decision(guardrails=[...]): reject_content maps
    to a decline carrying the guard message as rationale; a tripwire guard
    refuses loudly with the tripwire code; allow guards proceed."""
    mod, note = _import_triad()
    if mod is None:
        return _record("tg-elicit", "BREAK", note)
    try:
        from harness import make_run
    except Exception as e:
        return _record("tg-elicit", "ERROR", "no harness: %s" % e)

    def _queue_aid(run, agent_id="agent-1"):
        ident = run["executor"].mint_identity(agent_id, "support",
                                              agent_id)
        res = run["executor"].call(
            ident, "send_email", to="victim@synthetic.local",
            subject="hello", body="hello")
        assert res["status"] == "queued", res
        return res["approval_id"]

    # (a) reject_content -> forced decline, guard message as rationale.
    try:
        run = make_run()
        aid = _queue_aid(run, "agent-rej")

        def _reject(data):
            return mod.reject_content(
                "recipient domain outside the allowlist")

        g = mod.ToolInputGuardrail(name="tg-elicit-reject", run=_reject)
        run["approvals"].elicit_decision(aid, "accept", guardrails=[g])
        rec = run["approvals"].get(aid)
        # decide(approved=False) terminal status is "rejected".
        if rec["status"] != "rejected":
            return _record("tg-elicit", "BREAK",
                           "reject guard left status %r" % rec["status"])
        # decide() stores the rationale under "decision_reason".
        if "allowlist" not in str(rec.get("decision_reason", "")):
            return _record("tg-elicit", "BREAK",
                           "guard message not in decline rationale: %r"
                           % (rec.get("decision_reason"),))
        runs = [e for e in run["read_log"]()
                if e.get("event") == "tool_guardrail_run"
                and e.get("guardrail_name") == "tg-elicit-reject"]
        if not runs or runs[0].get("outcome") != "reject_content":
            return _record("tg-elicit", "BREAK",
                           "no tool_guardrail_run audit record")
    except Exception:
        return _record("tg-elicit", "ERROR", traceback.format_exc()[-800:])

    # (b) raise_exception -> loud refusal, tripwire code, record pending.
    try:
        run = make_run()
        aid = _queue_aid(run, "agent-trip")

        def _halt(data):
            return mod.raise_exception("guard veto")

        g = mod.ToolInputGuardrail(name="tg-elicit-halt", run=_halt)
        try:
            run["approvals"].elicit_decision(aid, "accept",
                                             guardrails=[g])
        except Exception as e:
            from gov import elicitation_contract as _ec
            if not isinstance(e, _ec.ElicitationError):
                return _record("tg-elicit", "BREAK",
                               "wrong exception %r" % (e,))
        else:
            return _record("tg-elicit", "BREAK",
                           "tripwire guard did not refuse")
        rec = run["approvals"].get(aid)
        if rec["status"] != "pending":
            return _record("tg-elicit", "BREAK",
                           "halt left status %r" % rec["status"])
        trips = [e for e in run["read_log"]()
                 if e.get("event") == "tool-guardrail-tripwire"]
        if not trips:
            return _record("tg-elicit", "BREAK",
                           "no tool-guardrail-tripwire audit event")
    except Exception:
        return _record("tg-elicit", "ERROR", traceback.format_exc()[-800:])

    # (c) allow guards -> elicitation proceeds normally.
    try:
        run = make_run()
        aid = _queue_aid(run, "agent-ok")

        def _allow(data):
            return mod.allow()

        g = mod.ToolInputGuardrail(name="tg-elicit-allow", run=_allow)
        run["approvals"].elicit_decision(aid, "accept", guardrails=[g])
        rec = run["approvals"].get(aid)
        if rec["status"] != "approved":
            return _record("tg-elicit", "BREAK",
                           "allow guard left status %r" % rec["status"])
    except Exception:
        return _record("tg-elicit", "ERROR", traceback.format_exc()[-800:])
    _record("tg-elicit", "HELD", "reject->decline, halt->loud, allow->ok")


def p_defense_approvals_still_binary_without_guards():
    """Defense: without guardrails attached, approval behavior is
    unchanged (the elicitation seam is additive-only)."""
    try:
        from gov import approvals as _ap
        import inspect
        params = inspect.signature(
            _ap.ApprovalQueue.elicit_decision).parameters
        p = params.get("guardrails")
        if p is not None and p.default is not inspect.Parameter.empty:
            return _record("tg-defense-elicit", "HELD",
                           "guardrails kwarg defaults, additive")
        if p is None:
            return _record("tg-defense-elicit", "HELD",
                           "no guardrails kwarg on base")
        return _record("tg-defense-elicit", "BREAK",
                       "guardrails kwarg is required -- not additive")
    except Exception as e:
        ERRORS.append(("tg-defense-elicit", traceback.format_exc()))
        return _record("tg-defense-elicit", "ERROR", str(e))


def p_taxonomy_pin():
    try:
        from gov import decision_codes as dc
        import re
        src = open(os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))),
            "gov", "decision_codes.py")).read()
        literals = re.findall(r'"code":\s*\'([^\']+)\'', src)
        if len(literals) != TAXONOMY_PIN:
            return _record("tg-pin", "BREAK",
                           "pin %d literal codes, want %d"
                           % (len(literals), TAXONOMY_PIN))
        if len(set(literals)) != len(literals):
            return _record("tg-pin", "BREAK", "duplicate code literals")
        _record("tg-pin", "HELD", "%d/%d unique" % (len(literals),
                                                   TAXONOMY_PIN))
    except Exception as e:
        ERRORS.append(("tg-pin", traceback.format_exc()))
        _record("tg-pin", "ERROR", str(e))


def _green_checks():
    """Depth-1: adjacent suites, honoring GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("[green] skipped (GOV_SKIP_GREEN=1)")
        return
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    venv = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    suites = [
        ("test_elicitation_contract",
         [venv, "-m", "unittest", "tests.test_elicitation_contract"]),
        ("test_approval_ceremony",
         [venv, "-m", "unittest", "tests.test_approval_ceremony"]),
    ]
    for name, cmd in suites:
        try:
            r = subprocess.run(cmd, cwd=repo, capture_output=True,
                               text=True, timeout=300,
                               env={**os.environ, "GOV_SKIP_GREEN": "1",
                                    "TMPDIR": os.environ.get(
                                        "TMPDIR", "/tmp")})
            ok = r.returncode == 0
            print("[green] %s: %s" % (name, "OK" if ok else "FAIL"))
            if not ok:
                print(r.stdout[-2000:])
                print(r.stderr[-2000:])
        except Exception as e:
            print("[green] %s: ERROR %s" % (name, e))


def main():
    for fn in (p_triad_shape_breaks_on_base,
               p_allow_records_tripwire,
               p_reject_content_denies_but_continues,
               p_reject_empty_message_refused_loudly,
               p_raise_exception_halts_loud,
               p_guard_crash_fails_closed,
               p_guard_order_first_decisive_wins,
               p_output_reject_replaces_output,
               p_bad_outcome_is_programming_error,
               p_elicitation_composes_with_triad,
               p_defense_approvals_still_binary_without_guards,
               p_taxonomy_pin):
        try:
            fn()
        except Exception:
            ERRORS.append((fn.__name__, traceback.format_exc()))
            _record(fn.__name__, "ERROR", "unexpected exception")
    _green_checks()
    brk = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    err = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    for name, v, note in RESULTS:
        print("%-22s %-6s %s" % (name, v, note))
    for name, tb in ERRORS:
        print("ERROR-TRACE %s:\n%s" % (name, tb[-1500:]))
    print("== %d BREAK / %d HELD / %d ERROR ==" % (brk, held, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
