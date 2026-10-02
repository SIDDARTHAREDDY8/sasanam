"""Wave-281 F306 closure battery: guard evidence must never echo
credential-shaped material into the audit log.

F306 (LOW): ``tool_guardrail_run`` audit records echo credential-shaped
guard messages *before* the elicitation secret ban runs. In
``ApprovalQueue.elicit_decision(..., guardrails=[...])`` each guard run is
emitted into the HMAC audit log at step 3b (``_run_guards`` ->
``_record_for``, note ``"rejection: %s" % message`` verbatim). The step-5
secret ban refuses the elicitation, but the audit record already carries
the secret -- breaking the elicitation contract's "secret is NEVER echoed
into the log" promise.

Close-when: sanitize guard evidence before emit
(``credential_material_present`` on the message/output_info; on a hit,
record a redacted placeholder); the ``triad-secret-msg`` red-team pin
flips to HELD; adjacent batteries green.

Red-first: on the pristine wave-280 base the leak probes BREAK (the
secret reaches ``read_log()``); after the fix all probes HELD.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g281-f306 && TMPDIR=/var/tmp/g281-f306 \
    ~/workspace/.gov-venv/bin/python evals/w281_f306_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g281-f306b \
    ~/workspace/.gov-venv/bin/python evals/w281_f306_probes.py
"""

import os
import re
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1710  # Wave-280 merge: 1495 + 13 battery-lang + 1 ephemeral + 32 shields; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)

SECRET = "password= hunter2-hunter2-x9"

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    # Wave-260 lesson: assert on raw source literals, not the deduped
    # dict (duplicate "code" literals are invisible to len(TAXONOMY)).
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r"\"code\":\s*'([a-z][a-z0-9-_.]*)'", src)


def p_taxonomy_pin():
    codes = _literals()
    if (len(codes) == TAXONOMY_PIN and len(set(codes)) == TAXONOMY_PIN
            and codes == sorted(codes)):
        _record("taxonomy-pin", "HELD",
                "%d raw / %d unique / 0 duplicates / sorted"
                % (len(codes), len(set(codes))))
    else:
        _record("taxonomy-pin", "BREAK",
                "pin %d: got %d raw / %d unique / sorted=%s"
                % (TAXONOMY_PIN, len(codes), len(set(codes)),
                   codes == sorted(codes)))


def _make_run():
    from harness import make_run
    return make_run()


def _queue_one(run):
    ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
    res = run["executor"].call(ident, "send_email", to="v@synthetic.local",
                              subject="s", body="b")
    return res["approval_id"]


def _leaked(run):
    """Any audit-log entry (any event) whose repr contains the secret."""
    return [e for e in run["read_log"]() if SECRET.split("=")[1].strip() in repr(e)]


def f306_reject_content_secret_not_echoed():
    """The F306 repro: credential-shaped reject_content message must be
    refused AND must never reach the audit log."""
    from gov import tool_guardrails as tg
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(SECRET), "detector must fire"
    run = _make_run()
    aid = _queue_one(run)

    def _reject(data):
        return tg.reject_content("blocking: saw %s in the request" % SECRET)

    g = tg.ToolInputGuardrail(name="tg-secret", run=_reject)
    refused = False
    try:
        run["approvals"].elicit_decision(aid, "accept", guardrails=[g])
    except Exception as e:  # noqa: BLE001 - the refusal is the point
        refused = "secret" in str(e).lower() or "credential" in str(e).lower()
    leaked = _leaked(run)
    if not refused:
        _record("f306-reject-content-secret-not-echoed", "BREAK",
                "credential-shaped guard message was not refused at all")
    elif leaked:
        _record("f306-reject-content-secret-not-echoed", "BREAK",
                "F306: elicitation refused by the secret ban, but the "
                "audit log already echoes the secret in %d record(s)"
                % len(leaked))
    else:
        _record("f306-reject-content-secret-not-echoed", "HELD",
                "refused via the secret ban; secret never reached the log")


def f306_allow_output_info_secret_not_echoed():
    """A guard's allow() output_info is also audit evidence: a
    credential-shaped output_info must be redacted before emit."""
    from gov import tool_guardrails as tg
    run = _make_run()
    emitted = []

    def _ok(data):
        return tg.allow(output_info={"scan": "clean", "note": SECRET})

    g = tg.ToolInputGuardrail(name="tg-leaky-allow", run=_ok)
    data = tg.ToolInputGuardrailData(tool_name="t", tool_arguments={})
    verdict = tg.run_input_guardrails([g], data, emit=emitted.append)
    leaked = [r for r in emitted if SECRET.split("=")[1].strip() in repr(r)]
    if leaked:
        _record("f306-allow-output-info-secret-not-echoed", "BREAK",
                "allow() output_info echoed the secret into the record")
    elif verdict.outcome == "allow":
        _record("f306-allow-output-info-secret-not-echoed", "HELD",
                "allow verdict preserved; secret redacted from evidence")
    else:
        _record("f306-allow-output-info-secret-not-echoed", "BREAK",
                "unexpected verdict %r" % (verdict.outcome,))


def f306_crash_note_secret_not_echoed():
    """A crashing guard's exception text is evidence too: it must be
    redacted before the tripwire record is emitted."""
    from gov import tool_guardrails as tg
    emitted = []

    def _boom(data):
        raise RuntimeError("db blew up on %s" % SECRET)

    g = tg.ToolInputGuardrail(name="tg-leaky-crash", run=_boom)
    data = tg.ToolInputGuardrailData(tool_name="t", tool_arguments={})
    tripped = False
    try:
        tg.run_input_guardrails([g], data, emit=emitted.append)
    except tg.ToolGuardrailTripwireTriggered:
        tripped = True
    leaked = [r for r in emitted if SECRET.split("=")[1].strip() in repr(r)]
    if leaked:
        _record("f306-crash-note-secret-not-echoed", "BREAK",
                "crash note echoed the secret into the tripwire record")
    elif tripped:
        _record("f306-crash-note-secret-not-echoed", "HELD",
                "loud tripwire halt preserved; secret redacted from record")
    else:
        _record("f306-crash-note-secret-not-echoed", "BREAK",
                "crash did not trip the wire")


def f306_rejection_verdict_preserved():
    """Redaction must not drop the verdict: the rejection record stays,
    with a redacted placeholder where the secret was."""
    from gov import tool_guardrails as tg
    emitted = []

    def _reject(data):
        return tg.reject_content("blocking: saw %s in the request" % SECRET)

    g = tg.ToolInputGuardrail(name="tg-secret", run=_reject)
    data = tg.ToolInputGuardrailData(tool_name="t", tool_arguments={})
    verdict = tg.run_input_guardrails([g], data, emit=emitted.append)
    runs = [r for r in emitted if r.get("event") == "tool_guardrail_run"]
    if (verdict.outcome == "reject_content" and runs
            and runs[0].get("outcome") == "reject_content"
            and not runs[0].get("tripwire_triggered")
            and SECRET.split("=")[1].strip() not in repr(runs[0])):
        _record("f306-rejection-verdict-preserved", "HELD",
                "verdict intact (reject_content, no tripwire); evidence "
                "redacted: %r" % (runs[0].get("output_info"),))
    else:
        _record("f306-rejection-verdict-preserved", "BREAK",
                "verdict lost or secret leaked: %r" % (runs,))


def f306_clean_message_verbatim():
    """No over-redaction: an ordinary guard message is recorded verbatim."""
    from gov import tool_guardrails as tg
    emitted = []

    def _reject(data):
        return tg.reject_content("blocking: recipient domain not allowlisted")

    g = tg.ToolInputGuardrail(name="tg-clean", run=_reject)
    data = tg.ToolInputGuardrailData(tool_name="t", tool_arguments={})
    tg.run_input_guardrails([g], data, emit=emitted.append)
    runs = [r for r in emitted if r.get("event") == "tool_guardrail_run"]
    if (runs and runs[0].get("output_info")
            == "rejection: blocking: recipient domain not allowlisted"):
        _record("f306-clean-message-verbatim", "HELD",
                "clean messages pass through untouched")
    else:
        _record("f306-clean-message-verbatim", "BREAK",
                "clean message altered: %r" % (runs,))


def f306_crash_through_elicitation_not_echoed():
    """The spec-review catch: a crashing guard's exception text used to
    ride the step-3b tripwire refusal reason into the audit log. A crash
    through the full elicit_decision path must halt loud AND leak
    nothing."""
    from gov import tool_guardrails as tg
    run = _make_run()
    aid = _queue_one(run)

    def _boom(data):
        raise RuntimeError("db blew up on %s" % SECRET)

    g = tg.ToolInputGuardrail(name="tg-secret-crash", run=_boom)
    tripped = False
    try:
        run["approvals"].elicit_decision(aid, "accept", guardrails=[g])
    except Exception as e:  # noqa: BLE001 - the tripwire halt is the point
        tripped = "tripwire" in str(e).lower() or "halted" in str(e).lower()
    leaked = _leaked(run)
    tripwire_records = [e for e in run["read_log"]()
                        if e.get("event") == "tool-guardrail-tripwire"]
    if leaked:
        _record("f306-crash-through-elicitation-not-echoed", "BREAK",
                "crash-through-elicitation echoed the secret in %d "
                "record(s)" % len(leaked))
    elif tripped and tripwire_records:
        _record("f306-crash-through-elicitation-not-echoed", "HELD",
                "loud tripwire halt; refusal reason sanitized: %r"
                % (tripwire_records[0].get("reason"),))
    else:
        _record("f306-crash-through-elicitation-not-echoed", "BREAK",
                "crash did not halt loud through elicitation")


# ---------------------------------------------------------------------------
# Green checks (depth-1, GOV_SKIP_GREEN honored)
# ---------------------------------------------------------------------------

def _green_checks():
    import subprocess
    if SKIP_GREEN:
        return [("green-skip", "SKIP",
                 "GOV_SKIP_GREEN=1: nested green check skipped")]
    checks = []
    for target in (["evals", "w280_redteam_probes.py"],
                   ["evals", "w279_triad_probes.py"],
                   ["tests", "test_tool_guardrails.py"]):
        tmpd = tempfile.mkdtemp(prefix="g281-green-")
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(REPO, *target)],
                env=env, capture_output=True, text=True, timeout=600,
                cwd=REPO)
            tail = (p.stdout + p.stderr)[-300:]
            name = target[-1]
            if p.returncode == 0:
                checks.append((name, "HELD", "exit 0"))
            else:
                checks.append((name, "BREAK", "exit %d: %s"
                               % (p.returncode, tail)))
        except Exception as e:  # noqa: BLE001
            checks.append((target[-1], "ERROR", "%r" % (e,)))
    return checks


def main():
    probes = [
        p_taxonomy_pin,
        f306_reject_content_secret_not_echoed,
        f306_allow_output_info_secret_not_echoed,
        f306_crash_note_secret_not_echoed,
        f306_crash_through_elicitation_not_echoed,
        f306_rejection_verdict_preserved,
        f306_clean_message_verbatim,
    ]
    for probe in probes:
        try:
            probe()
        except Exception:  # noqa: BLE001 - a probe must never die
            import traceback
            _record(probe.__name__, "ERROR",
                    traceback.format_exc()[-500:])
    for pid, verdict, note in _green_checks():
        _record(pid, verdict, note)

    breaks = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    errors = [r for r in _results if r[1] == "ERROR"]
    print("wave-281 f306: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note[:160]))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
