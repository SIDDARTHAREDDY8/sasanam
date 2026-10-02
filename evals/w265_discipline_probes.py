"""Break-first red-team battery for Alertmanager-style approval
discipline (wave-265 feature lane: approval fatigue).

Target: gov/approval_discipline.py -- an inhibition / silence /
repeat-interval layer that sits IN FRONT of the approval queue. It
answers prompt-spam (approval fatigue): identical pending approvals
are coalesced inside a repeat window, operator-signed time-bounded
silences suppress re-prompting for stated classes, and journaled
refusal facts inhibit redundant prompts. It can never suppress an
enforcement denial -- the module has no deny-suppression API, and
high/critical requests are never silenced.

The battery imports the implementation via GOV_DISCIPLINE_IMPL
(default "gov.approval_discipline"); against the permissive stub
(GOV_DISCIPLINE_IMPL=discipline_stub, PYTHONPATH=/tmp/w265_stub)
every attack probe must BREAK, proving the probes are real. Against
the real module every probe must HELD, in staging and under
`env -u GOV_DEPLOYMENT_MODE`.

Method (tdd + diagnosing-bugs skills): each probe is a falsifiable
break attempt at a PUBLIC seam. A probe returns (ok, detail);
ok=True means HELD (attack refused / gap is a documented residual),
ok=False means BREAK (genuine defect) or harness ERROR.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import importlib
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

TAXONOMY_PIN = 1579  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*)

MOD_NAME = os.environ.get("GOV_DISCIPLINE_IMPL",
                           "gov.approval_discipline")
ad = importlib.import_module(MOD_NAME)

NOW = 4000000000.0
KEY = b"w265-discipline-test-key-32bytes!"
OTHER_KEY = b"w265-discipline-wrong-key-0000000"

CODES = [
    "discipline-inhibitor-malformed",
    "discipline-inhibitor-unverifiable",
    "discipline-prompt-coalesced",
    "discipline-prompt-inhibited",
    "discipline-prompt-silenced",
    "discipline-request-malformed",
    "discipline-silence-forbidden-class",
    "discipline-silence-malformed",
    "discipline-silence-unjournaled",
]


def _req(**over):
    r = {"action": "read_file",
         "scope": "fs:read:/var/log",
         "subject": "agent-subject-digest-001",
         "args_digest": "ab" * 32,
         "context_digest": "cd" * 32,
         "severity": "low"}
    r.update(over)
    return r


def _queue():
    calls = []

    def queue_fn(request):
        calls.append(request)
        return "q-%d" % len(calls)

    return calls, queue_fn


def _disc(journal=None):
    kw = {"repeat_window": 300.0,
          "max_silence_duration": 3600.0,
          "inhibit_window": 600.0,
          "operator_key": KEY}
    if journal is not None:
        kw["journal"] = journal
    return ad.ApprovalDiscipline(**kw)


def _silence(d, matchers, not_after, created_by="op-1", key=KEY,
             now=NOW):
    return d.sign_silence(matchers=matchers, not_after=not_after,
                          created_by=created_by, now=now, key=key)


def _expect_raise(fn, want_code):
    """HELD iff fn raises a DisciplineError with want_code."""
    try:
        fn()
    except ad.DisciplineError as e:
        if e.code == want_code:
            return True, "HELD (%s)" % want_code
        return False, "BREAK: code %s, wanted %s" % (e.code,
                                                    want_code)
    except Exception as e:  # noqa: BLE001 -- harness must not mask
        return False, "ERROR: unexpected %r" % (e,)
    return False, "BREAK: no refusal (wanted %s)" % want_code


def p_fatigue_prompt_spam():
    """50 identical prompts in-window: exactly 1 reaches the queue."""
    d = _disc()
    calls, qf = _queue()
    kinds = [d.prompt(_req(), qf, NOW + i)["kind"]
             for i in range(50)]
    if len(calls) != 1:
        return False, "BREAK: %d queue calls for identical " \
            "requests (wanted 1)" % len(calls)
    if kinds[0] != "prompt":
        return False, "BREAK: first prompt not issued"
    if any(k != "coalesced" for k in kinds[1:]):
        return False, "BREAK: not all repeats coalesced: %r" % (
            kinds,)
    refs = {d.prompt(_req(), qf, NOW)["pending_id"]}
    if len(refs) != 1:
        return False, "BREAK: coalesced prompts disagree on " \
            "pending_ref"
    dec = d.prompt(_req(), qf, NOW)
    if dec["code"] != "discipline-prompt-coalesced":
        return False, "BREAK: coalesce code %r" % (dec["code"],)
    return True, "HELD (1 prompt, 49 coalesced)"


def p_fatigue_different_args_reprompt():
    """Different args digest: never coalesced (control)."""
    d = _disc()
    calls, qf = _queue()
    d.prompt(_req(), qf, NOW)
    dec = d.prompt(_req(args_digest="ff" * 32), qf, NOW + 1)
    if len(calls) != 2 or dec["kind"] != "prompt":
        return False, "BREAK: distinct decision coalesced"
    return True, "HELD (control: distinct decisions re-prompt)"


def p_fatigue_expired_pending_reprompts():
    """Pending older than the repeat window re-prompts (control)."""
    d = _disc()
    calls, qf = _queue()
    d.prompt(_req(), qf, NOW)
    dec = d.prompt(_req(), qf, NOW + 301.0)
    if len(calls) != 2 or dec["kind"] != "prompt":
        return False, "BREAK: expired pending not re-prompted"
    return True, "HELD (control: repeat window re-notifies)"


def p_silence_operator_signed_required():
    """A silence with a forged signature is refused machine-coded."""
    d = _disc(journal=[])
    bad = _silence(d, {"action": "read_file"}, NOW + 100,
                   key=OTHER_KEY)
    return _expect_raise(
        lambda: d.add_silence(bad, journal=[], now=NOW),
        "discipline-silence-malformed")


def p_silence_critical_class_refused():
    """A silence covering severity=high is refused at creation."""
    d = _disc(journal=[])
    s = _silence(d, {"action": "read_file", "severity": "high"},
                 NOW + 100)
    return _expect_raise(
        lambda: d.add_silence(s, journal=[], now=NOW),
        "discipline-silence-forbidden-class")


def p_silence_expiry_mandatory():
    """Silence without expiry / past expiry / over-long window."""
    d = _disc(journal=[])
    noexp = _silence(d, {"action": "read_file"}, NOW + 100)
    del noexp["not_after"]
    # re-sign not possible without not_after; pass raw instead
    raw = {"matchers": {"action": "read_file"},
           "created_by": "op-1", "created_at": NOW, "mac": "00"}
    r1 = _expect_raise(
        lambda: d.add_silence(raw, journal=[], now=NOW),
        "discipline-silence-malformed")
    if not r1[0]:
        return r1
    past = _silence(d, {"action": "read_file"}, NOW - 1)
    r2 = _expect_raise(
        lambda: d.add_silence(past, journal=[], now=NOW),
        "discipline-silence-malformed")
    if not r2[0]:
        return r2
    far = _silence(d, {"action": "read_file"}, NOW + 7200)
    return _expect_raise(
        lambda: d.add_silence(far, journal=[], now=NOW),
        "discipline-silence-malformed")


def p_silence_unjournaled_refused():
    """A silence nobody journals is refused."""
    d = _disc()  # no journal anywhere
    s = _silence(d, {"action": "read_file"}, NOW + 100)
    return _expect_raise(
        lambda: d.add_silence(s, journal=None, now=NOW),
        "discipline-silence-unjournaled")


def p_silence_never_suppresses_denial():
    """silence_covers('enforcement') is always False (structural)."""
    d = _disc(journal=[])
    s = _silence(d, {"action": "read_file"}, NOW + 100)
    sid = d.add_silence(s, journal=[], now=NOW)
    if d.silence_covers(sid, "enforcement"):
        return False, "BREAK: silence claims to suppress an " \
            "enforcement denial"
    if not d.silence_covers(sid, "prompt"):
        return False, "BREAK: silence does not cover prompts"
    return True, "HELD (prompts-only scope is structural)"


def p_silence_high_severity_request_not_silenced():
    """A high-severity request is never silenced, even in-class."""
    journal = []
    d = _disc(journal=journal)
    s = _silence(d, {"action": "read_file"}, NOW + 100)
    d.add_silence(s, journal=journal, now=NOW)
    calls, qf = _queue()
    dec = d.prompt(_req(severity="high"), qf, NOW + 1)
    if dec["kind"] != "prompt" or len(calls) != 1:
        return False, "BREAK: high-severity prompt silenced"
    if len(journal) != 1:
        return False, "BREAK: silence creation not journaled"
    return True, "HELD (high-severity always prompts; " \
        "silence journaled)"


def p_silence_expiry_enforced():
    """A short-lived silence stops suppressing after not_after."""
    journal = []
    d = _disc(journal=journal)
    s = _silence(d, {"action": "read_file"}, NOW + 1)
    d.add_silence(s, journal=journal, now=NOW)
    calls, qf = _queue()
    d1 = d.prompt(_req(), qf, NOW)
    d2 = d.prompt(_req(), qf, NOW + 2)
    if d1["kind"] != "silenced":
        return False, "BREAK: live silence did not suppress"
    if d1["code"] != "discipline-prompt-silenced":
        return False, "BREAK: silence code %r" % (d1["code"],)
    if d2["kind"] != "prompt" or len(calls) != 1:
        return False, "BREAK: expired silence still suppresses"
    return True, "HELD (silence honored, then expired)"


def p_inhibition_journaled_refusal_inhibits():
    """A journaled refusal fact inhibits the redundant prompt."""
    d = _disc()
    fact = {"action": "read_file", "scope": "fs:read:/var/log",
            "subject": "agent-subject-digest-001",
            "args_digest": "ab" * 32, "context_digest": "cd" * 32,
            "kind": "refusal",
            "journal_digest": "de" * 32, "recorded_at": NOW}
    d.note_refusal(fact, NOW)
    calls, qf = _queue()
    dec = d.prompt(_req(), qf, NOW + 1)
    if dec["kind"] != "inhibited" or len(calls) != 0:
        return False, "BREAK: journaled refusal did not inhibit"
    if dec["code"] != "discipline-prompt-inhibited":
        return False, "BREAK: inhibit code %r" % (dec["code"],)
    return True, "HELD (refusal fact inhibits re-prompt)"


def p_inhibition_caller_claim_refused():
    """An inhibitor without a journal binding is refused."""
    d = _disc()
    claim = {"action": "read_file", "scope": "fs:read:/var/log",
             "subject": "agent-subject-digest-001",
             "args_digest": "ab" * 32, "context_digest": "cd" * 32,
             "kind": "refusal", "recorded_at": NOW}
    return _expect_raise(
        lambda: d.note_refusal(claim, NOW),
        "discipline-inhibitor-unverifiable")


def p_inhibition_malformed_refused():
    """A malformed refusal fact is refused machine-coded."""
    d = _disc()
    bad = {"action": "read_file", "kind": "refusal",
           "journal_digest": "de" * 32}
    return _expect_raise(
        lambda: d.note_refusal(bad, NOW),
        "discipline-inhibitor-malformed")


def p_request_malformed_refused():
    """A malformed request is refused loudly, never coalesced."""
    d = _disc()
    calls, qf = _queue()
    ok, detail = _expect_raise(
        lambda: d.prompt({"action": "read_file"}, qf, NOW),
        "discipline-request-malformed")
    if not ok:
        return ok, detail
    if len(calls) != 0:
        return False, "BREAK: malformed request reached queue"
    return True, "HELD (malformed request refused, queue clean)"


def p_silence_journal_failure_not_installed():
    """A journal failure means the silence is never installed."""
    d = _disc()
    s = _silence(d, {"action": "read_file"}, NOW + 100)

    class BadJournal:
        def __call__(self, event):
            raise RuntimeError("journal down")

    try:
        d.add_silence(s, journal=BadJournal(), now=NOW)
    except RuntimeError:
        pass
    else:
        return False, "BREAK: silence accepted despite journal " \
            "failure"
    calls, qf = _queue()
    dec = d.prompt(_req(), qf, NOW + 1)
    if dec["kind"] != "prompt" or len(calls) != 1:
        return False, "BREAK: phantom silence suppresses after " \
            "journal failure"
    return True, "HELD (journal failure -> silence never " \
        "installed)"


def p_control_honest_prompt():
    """A plain request prompts exactly once (control)."""
    d = _disc()
    calls, qf = _queue()
    dec = d.prompt(_req(), qf, NOW)
    if dec["kind"] != "prompt" or len(calls) != 1:
        return False, "BREAK: honest prompt did not flow"
    return True, "HELD (control)"


def p_pin_taxonomy():
    """Pin 1186; all 9 discipline-* codes present; raw literals
    unique (wave-260 lesson)."""
    import gov.decision_codes as dc
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN:
        return False, "BREAK: taxonomy len %d, pin %d" % (
            n, TAXONOMY_PIN)
    missing = [c for c in CODES if c not in dc.TAXONOMY]
    if missing:
        return False, "BREAK: codes missing: %r" % (missing,)
    import pathlib
    src = pathlib.Path("gov/decision_codes.py").read_text()
    dups = [c for c in CODES if src.count('"code": %r' % c) != 1]
    if dups:
        return False, "BREAK: raw literal not unique: %r" % (dups,)
    return True, "HELD (pin %d, 9 codes, literals unique)" % (
        TAXONOMY_PIN,)


PROBES = [
    ("fatigue/prompt-spam-coalesced", p_fatigue_prompt_spam),
    ("fatigue/different-args-reprompt",
     p_fatigue_different_args_reprompt),
    ("fatigue/expired-pending-reprompts",
     p_fatigue_expired_pending_reprompts),
    ("silence/operator-signed-required",
     p_silence_operator_signed_required),
    ("silence/critical-class-refused",
     p_silence_critical_class_refused),
    ("silence/expiry-mandatory", p_silence_expiry_mandatory),
    ("silence/unjournaled-refused", p_silence_unjournaled_refused),
    ("silence/journal-failure-not-installed",
     p_silence_journal_failure_not_installed),
    ("silence/never-suppresses-denial",
     p_silence_never_suppresses_denial),
    ("silence/high-severity-request-not-silenced",
     p_silence_high_severity_request_not_silenced),
    ("silence/expiry-enforced", p_silence_expiry_enforced),
    ("inhibition/journaled-refusal-inhibits",
     p_inhibition_journaled_refusal_inhibits),
    ("inhibition/caller-claim-refused",
     p_inhibition_caller_claim_refused),
    ("inhibition/malformed-refused", p_inhibition_malformed_refused),
    ("request/malformed-refused", p_request_malformed_refused),
    ("control/honest-prompt", p_control_honest_prompt),
    ("pin/taxonomy", p_pin_taxonomy),
]


def run():
    held, broke, errored = 0, 0, 0
    for name, fn in PROBES:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            ok, detail = False, "ERROR: %r" % (e,)
        tag = "HELD" if ok else (
            "BREAK" if detail.startswith("BREAK") else "ERROR")
        if tag == "HELD":
            held += 1
        elif tag == "BREAK":
            broke += 1
        else:
            errored += 1
        print("%-52s %s -- %s" % (name, tag, detail))
    green_rc = green_check()
    print("HELD %d / BREAK %d / ERROR %d" % (held, broke, errored))
    if broke == 0 and errored == 0 and green_rc == 0:
        return 0
    return 1


def green_check():
    """Depth-1 adjacent green check; honors GOV_SKIP_GREEN.

    Notes are informational only (house convention): a sibling's
    lane-local pin drift must not red this battery. Only probe
    BREAK/ERROR drive the exit code.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green-check: skipped (GOV_SKIP_GREEN=1)")
        return 0
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    here = os.path.dirname(os.path.abspath(__file__))
    for battery in ("durable_approval_probes.py",
                    "w264_mandate_probes.py"):
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            print("green-check %s: absent, skipping" % battery)
            continue
        r = subprocess.run(
            [sys.executable, path], env=env,
            capture_output=True, text=True, timeout=600,
            cwd=os.path.dirname(here))
        tail = (r.stdout or "").strip().splitlines()[-1:]
        print("green-check %s: exit=%d %s" % (
            battery, r.returncode,
            tail[0][:100] if tail else ""))
    return 0


if __name__ == "__main__":
    sys.exit(run())
