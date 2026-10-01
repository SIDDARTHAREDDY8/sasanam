"""Wave-253 incident lifecycle probes: break-first.

W253-2: incident lifecycle orchestration (netflix/dispatch ADAPT --
pattern only; dispatch is archived read-only, never a dependency).

Lifecycle: declare -> assign roles -> tasks -> notifications ->
postmortems, with event-sourced state and FAIL-CLOSED resolution
(resolve() refuses ``incident-open-findings`` while linked findings
are open).

Discipline (tdd skill): red before green. Each probe is a falsifiable
break attempt. HELD = attack refused or honest path holds; BREAK =
attack succeeds. On the pristine wave-252 base every probe is GAP
(capability absent); after the build all probes are HELD.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_INC = False
try:
    from gov import incident as _inc
    HAVE_INC = all(hasattr(_inc, n) for n in (
        "IncidentManager", "IncidentError", "declare_incident",
        "STATES", "LEGAL_TRANSITIONS"))
except ImportError:
    _inc = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc,
                                          traceback.format_exc(limit=3))


# ------------------------------------------------- helpers


def _mktmp():
    base = "/var/tmp/w253-incident"
    os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix="probe-", dir=base)


def _mgr(**kw):
    journal = os.path.join(_mktmp(), "incidents.jsonl")
    return _inc.IncidentManager(journal_path=journal, **kw)


def _open_provider(*open_ids):
    def provider(fid):
        return "open" if fid in open_ids else "closed"
    return provider


def _decl(m, iid="INC-001", **kw):
    kw.setdefault("title", "test incident")
    kw.setdefault("severity", "high")
    return m.declare_incident(iid, **kw)


def _drive_to_contained(m, iid="INC-001"):
    m2 = _inc.IncidentManager(journal_path=m.journal_path,
                              finding_status=m._finding_status)
    m2.assign_role(iid, "commander", "alice")
    tid = m2.add_task(iid, "isolate host", owner="alice")
    m2.complete_task(iid, tid)
    m2.notify(iid, "page", "alice", "incident opened")
    m2.transition(iid, "investigating")
    m2.transition(iid, "contained")
    return m2


# ------------------------------------------------- probes


def probe_resolve_open_findings_refused():
    # A1: resolve with an OPEN linked finding must refuse
    # incident-open-findings AND emit an audit trail event.
    m = _mgr(finding_status=_open_provider("F214"))
    _decl(m)
    m.link_finding("INC-001", "F214")
    m.link_finding("INC-001", "F999")
    m2 = _drive_to_contained(m)
    before = m2.event_count("INC-001")
    try:
        m2.resolve("INC-001")
    except _inc.IncidentError as exc:
        assert exc.code == "incident-open-findings", exc.code
        assert m2.event_count("INC-001") == before + 1, \
            "refusal must emit an audit trail event"
        assert m2.state("INC-001") == "contained", \
            "state must not move on refused resolve"
        return "resolve with open finding refused + audited"
    raise AssertionError("resolve() allowed with open finding linked")


def probe_resolve_no_provider_fail_closed():
    # A2: no finding-status provider -> fail closed, never assume.
    m = _mgr()
    _decl(m)
    m.link_finding("INC-001", "F214")
    m2 = _drive_to_contained(m)
    try:
        m2.resolve("INC-001")
    except _inc.IncidentError as exc:
        assert exc.code == "incident-open-findings", exc.code
        return "no provider fails closed on resolve"
    raise AssertionError("resolve() allowed with no status provider")


def probe_resolve_unknown_finding_fail_closed():
    # A3: provider that cannot answer a finding -> fail closed.
    def provider(fid):
        raise KeyError(fid)
    m = _mgr(finding_status=provider)
    _decl(m)
    m.link_finding("INC-001", "F-UNKNOWN")
    m2 = _drive_to_contained(m)
    try:
        m2.resolve("INC-001")
    except _inc.IncidentError as exc:
        assert exc.code == "incident-open-findings", exc.code
        return "unknown finding status fails closed"
    raise AssertionError("resolve() allowed with unknown finding")


def probe_resolve_open_tasks_refused():
    # A4: resolve with incomplete tasks must refuse
    # incident-open-tasks.
    m = _mgr(finding_status=_open_provider())
    _decl(m)
    m.assign_role("INC-001", "commander", "alice")
    m.add_task("INC-001", "unfinished work", owner="alice")
    m.transition("INC-001", "investigating")
    m.transition("INC-001", "contained")
    try:
        m.resolve("INC-001")
    except _inc.IncidentError as exc:
        assert exc.code == "incident-open-tasks", exc.code
        return "resolve with open tasks refused"
    raise AssertionError("resolve() allowed with incomplete tasks")


def probe_illegal_transition_refused():
    # B1: open -> resolved skips the lifecycle; must refuse.
    m = _mgr(finding_status=_open_provider())
    _decl(m)
    for bad in ("resolved", "contained", "closed"):
        try:
            m.transition("INC-001", bad)
        except _inc.IncidentError as exc:
            assert exc.code == "incident-illegal-transition", exc.code
        else:
            raise AssertionError("illegal transition open->%s held" % bad)
    assert m.state("INC-001") == "open", "state moved on refused path"
    return "open->resolved/contained/closed refused"


def probe_transition_after_resolved_refused():
    # B2: resolved is not re-openable through transition(); only
    # close is legal from resolved.
    m = _mgr(finding_status=_open_provider())
    _decl(m)
    m2 = _drive_to_contained(m)
    m2.resolve("INC-001")
    for bad in ("open", "investigating", "contained"):
        try:
            m2.transition("INC-001", bad)
        except _inc.IncidentError as exc:
            assert exc.code == "incident-illegal-transition", exc.code
        else:
            raise AssertionError("resolved->%s held" % bad)
    m2.transition("INC-001", "closed")
    assert m2.state("INC-001") == "closed"
    return "resolved is terminal except ->closed"


def probe_postmortem_unknown_incident():
    # C1: postmortem on a nonexistent incident -> incident-unknown.
    m = _mgr()
    try:
        m.attach_postmortem("INC-NOPE", timeline=[],
                            root_cause="x",
                            action_items=[])
    except _inc.IncidentError as exc:
        assert exc.code == "incident-unknown", exc.code
        return "postmortem on unknown incident refused"
    raise AssertionError("postmortem accepted for unknown incident")


def probe_postmortem_premature():
    # C2: postmortem before containment -> refused; postmortem is
    # structured data, not free text.
    m = _mgr(finding_status=_open_provider())
    _decl(m)
    try:
        m.attach_postmortem("INC-001", timeline=[],
                            root_cause="too early",
                            action_items=[])
    except _inc.IncidentError as exc:
        assert exc.code == "incident-premature-postmortem", exc.code
    else:
        raise AssertionError("premature postmortem accepted")
    m2 = _drive_to_contained(m)
    m2.resolve("INC-001")
    pm = m2.attach_postmortem(
        "INC-001",
        timeline=[{"at": "2026-09-30T00:00:00Z", "event": "detected"}],
        root_cause="misconfigured allowlist",
        action_items=[{"item": "pin allowlist", "owner": "alice",
                       "due": "2026-10-07"}])
    assert pm["root_cause"] == "misconfigured allowlist"
    assert pm["timeline"][0]["event"] == "detected"
    assert pm["action_items"][0]["owner"] == "alice"
    return "postmortem gated on containment; structured"


def probe_forged_resolution_impossible():
    # D1: caller-held objects mutated after the call must not change
    # incident state (the F212 lesson); state must derive from
    # journaled events, never from caller aliases. And no public
    # mutator may move state except transition()/resolve().
    m = _mgr(finding_status=_open_provider())
    _decl(m)
    m2 = _drive_to_contained(m)
    # (a) caller mutates postmortem inputs after attach.
    timeline = [{"at": "t0", "event": "paged"}]
    actions = [{"item": "pin it", "owner": "alice", "due": "tomorrow"}]
    m2.resolve("INC-001")
    m2.attach_postmortem("INC-001", timeline=timeline,
                         root_cause="r", action_items=actions)
    timeline[0]["event"] = "forged"
    timeline.append({"at": "t1", "event": "forged"})
    actions[0]["owner"] = "mallory"
    pm = m2.postmortem("INC-001")
    assert pm["timeline"] == [{"at": "t0", "event": "paged"}], pm
    assert pm["action_items"][0]["owner"] == "alice", pm
    # (b) caller mutates returned views; internal state unaffected.
    evs = m2.events("INC-001")
    evs[0]["body"]["injected"] = True
    roles = m2.roles("INC-001")
    roles["commander"] = "mallory"
    assert m2.roles("INC-001")["commander"] == "alice"
    assert all("injected" not in e["body"]
               for e in m2.events("INC-001"))
    # (c) replay from the journal reconstructs identical state.
    m3 = _inc.IncidentManager(journal_path=m.journal_path,
                              finding_status=_open_provider())
    assert m3.state("INC-001") == "resolved", "replay diverged"
    assert m3.roles("INC-001") == {"commander": "alice"}
    assert m3.tasks("INC-001")[0]["status"] == "done"
    assert m3.postmortem("INC-001")["timeline"][0]["event"] == "paged"
    return "caller mutation cannot forge state; replay is canonical"


def probe_malformed_inputs():
    # E1: malformed declare/role/task/notify inputs refuse
    # incident-malformed.
    m = _mgr()
    bad_calls = [
        lambda: m.declare_incident("", title="t"),
        lambda: m.declare_incident("INC-001", title=""),
        lambda: m.declare_incident("INC-001", title="t",
                                   severity="bogus"),
    ]
    _decl(m)
    bad_calls += [
        lambda: m.assign_role("INC-001", "", "alice"),
        lambda: m.assign_role("INC-001", "commander", ""),
        lambda: m.assign_role("INC-NOPE", "commander", "alice"),
        lambda: m.add_task("INC-001", "", owner="alice"),
        lambda: m.notify("INC-001", "", "alice", "msg"),
        lambda: m.link_finding("INC-001", ""),
        lambda: m.link_evidence("INC-001", ""),
    ]
    for i, call in enumerate(bad_calls):
        try:
            call()
        except _inc.IncidentError as exc:
            assert exc.code in ("incident-malformed",
                                "incident-unknown"), exc.code
        else:
            raise AssertionError("malformed call %d accepted" % i)
    return "malformed inputs refused (%d shapes)" % len(bad_calls)


def probe_duplicate_declare():
    # E2: declaring the same incident id twice refuses.
    m = _mgr()
    _decl(m)
    try:
        _decl(m)
    except _inc.IncidentError as exc:
        assert exc.code == "incident-malformed", exc.code
        assert "duplicate" in str(exc).lower()
        return "duplicate declare refused"
    raise AssertionError("duplicate incident id accepted")


def probe_happy_path_orchestration():
    # F1: full dispatch-shaped orchestration holds end to end.
    m = _mgr(finding_status=_open_provider())
    inc = _decl(m, iid="INC-007", severity="critical")
    assert inc["id"] == "INC-007" and inc["state"] == "open"
    m.assign_role("INC-007", "commander", "alice")
    m.assign_role("INC-007", "comms", "bob")
    assert m.roles("INC-007") == {"commander": "alice",
                                  "comms": "bob"}
    t1 = m.add_task("INC-007", "isolate host", owner="alice")
    t2 = m.add_task("INC-007", "notify customers", owner="bob")
    m.complete_task("INC-007", t1)
    m.complete_task("INC-007", t2)
    m.notify("INC-007", "page", "alice", "sev1 opened")
    m.notify("INC-007", "email", "bob", "comms draft ready")
    assert len(m.notifications("INC-007")) == 2
    m.link_finding("INC-007", "F999")  # closed per provider
    m.link_evidence("INC-007", "decision-log:seq-42")
    m.transition("INC-007", "investigating")
    m.transition("INC-007", "contained")
    m.resolve("INC-007")
    assert m.state("INC-007") == "resolved"
    pm = m.attach_postmortem(
        "INC-007", timeline=[{"at": "t0", "event": "paged"}],
        root_cause="root", action_items=[])
    assert pm["incident_id"] == "INC-007"
    m.transition("INC-007", "closed")
    # Deterministic summary for auditors.
    s1 = m.summary("INC-007")
    s2 = m.summary("INC-007")
    assert s1 == s2, "summary not deterministic"
    return "full orchestration path holds"


def probe_audit_trail_complete():
    # F2: every lifecycle action emits a journaled audit event;
    # the trail survives process restart via replay.
    m = _mgr(finding_status=_open_provider())
    _decl(m)
    m.link_finding("INC-001", "F999")
    m.link_evidence("INC-001", "decision-log:seq-7")
    m2 = _drive_to_contained(m)
    m2.resolve("INC-001")
    kinds = [e["kind"] for e in m2.events("INC-001")]
    for need in ("declared", "role_assigned", "task_added",
                 "task_completed", "notified", "finding_linked",
                 "transitioned", "resolved"):
        assert need in kinds, "missing audit event: %s" % need
    # Refusals are audited too (A1 counted one); journal survives.
    m3 = _inc.IncidentManager(journal_path=m.journal_path,
                              finding_status=_open_provider())
    assert m3.state("INC-001") == "resolved", "restart lost state"
    assert m3.event_count("INC-001") == m2.event_count("INC-001")
    return "audit trail complete + durable (%d events)" % len(kinds)


# ------------------------------------------------- green checks (depth-1)


def _green():
    """Depth-1: run adjacent batteries with GOV_SKIP_GREEN=1 and
    require zero BREAK/ERROR. Honors GOV_SKIP_GREEN itself
    (records skip, never spawns)."""
    import subprocess
    if GREEN_SKIP:
        return ["green checks skipped (GOV_SKIP_GREEN=1)"]
    here = os.path.dirname(os.path.abspath(__file__))
    batteries = [
        "w250_decision_log_probes.py",
        "w250_evidence_graph_probes.py",
        "w251_posture_probes.py",
    ]
    notes = []
    for bat in batteries:
        path = os.path.join(here, bat)
        if not os.path.exists(path):
            notes.append("%s: missing, skipped" % bat)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = _mktmp()
        env["TMPDIR"] = tmpd
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600, cwd=os.path.join(here, ".."))
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("%s green check failed: %r" % (bat, exc))
        out = (proc.stdout or "") + (proc.stderr or "")
        if "BREAK" in out or proc.returncode != 0:
            raise AssertionError(
                "%s green check not green (rc=%d):\n%s"
                % (bat, proc.returncode, out[-2000:]))
        notes.append("%s: green" % bat)
    return notes


# ------------------------------------------------- main


PROBES = [
    ("resolve/open-findings-refused", probe_resolve_open_findings_refused,
     HAVE_INC),
    ("resolve/no-provider-fail-closed", probe_resolve_no_provider_fail_closed,
     HAVE_INC),
    ("resolve/unknown-finding-fail-closed",
     probe_resolve_unknown_finding_fail_closed, HAVE_INC),
    ("resolve/open-tasks-refused", probe_resolve_open_tasks_refused,
     HAVE_INC),
    ("transition/illegal-from-open", probe_illegal_transition_refused,
     HAVE_INC),
    ("transition/resolved-terminal", probe_transition_after_resolved_refused,
     HAVE_INC),
    ("postmortem/unknown-incident", probe_postmortem_unknown_incident,
     HAVE_INC),
    ("postmortem/premature", probe_postmortem_premature, HAVE_INC),
    ("state/no-forged-resolution", probe_forged_resolution_impossible,
     HAVE_INC),
    ("input/malformed", probe_malformed_inputs, HAVE_INC),
    ("input/duplicate-declare", probe_duplicate_declare, HAVE_INC),
    ("orchestration/happy-path", probe_happy_path_orchestration, HAVE_INC),
    ("audit/trail-complete", probe_audit_trail_complete, HAVE_INC),
]


def main():
    results = []
    for name, fn, have in PROBES:
        results.append(_run_probe(name, fn, have))
    held = sum(1 for _n, v, _x in results if v == "HELD")
    brk = sum(1 for _n, v, _x in results if v == "BREAK")
    gap = sum(1 for _n, v, _x in results if v == "GAP")
    err = sum(1 for _n, v, _x in results if v == "ERROR")
    print("w253 incident: %d/%d HELD, %d BREAK, %d GAP, %d ERROR"
          % (held, len(results), brk, gap, err))
    for name, verdict, note in results:
        first = note.splitlines()[0] if note else ""
        print("  [%s] %s: %s" % (verdict, name, first[:160]))
    try:
        for note in _green():
            print("  green: %s" % note)
    except AssertionError as exc:
        print("  GREEN-CHECK FAILED: %s" % (exc,))
        return 2
    if brk or err or gap:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
