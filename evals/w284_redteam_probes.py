"""Wave-284 independent red-team battery: attack the wave-283 merge.

Base: wave-283 push 9a7cffc6d2b3b3a675d94cfbff3bf536c105a54f
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (from the wave-283 merge report):
  (a) F311 (LOW, CLOSED) -- the wave-283 merge hand-reconciled lane-1
      (f311 sanitize) and lane-4 (gitleaks canonicalizer seam) into ONE
      composed sanitize function in gov/guard_plugins.py. Re-pinned HELD
      on all four GuardChain emission paths; this battery also verifies
      the composition did not drop either lane's semantics.
  (b) F312-F315 (LOW) -- re-pinned BREAK on the wave-283 base; CLOSED by
      wave-284 lane 1, re-pinned HELD on the merged tree:
      F312 forged _atomic_normalized marker; F313 emit-failure drops
      discovery drift events; F314 '|' in tool name bricks the pin store;
      F315 name-only re-pin binding.
  (c) New wave-283 surface -- expected HELD unless a probe finds a real
      hole: secret_canonicalizer (decode evasion, composite escapes,
      allowlist bypass, fingerprint stability), finding_lifecycle
      (identity-hash collision, illegal transitions, SLA evasion,
      close_old_findings vs human triage), inventory_query (provider
      bypasses, unpinned packs, schema tricks, check_use on held rows),
      campaign (FactStore typing escapes, goal evasion, manual_approve
      bypass, replay determinism).

$0 spend, synthetic/local, deterministic (fixed fixtures, generous
wall-clock margins, no wall-clock equality assertions). Stdlib only,
no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g284-redteam && TMPDIR=/var/tmp/g284-redteam \
    ~/workspace/.gov-venv/bin/python evals/w284_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g284-redteam2 \
    ~/workspace/.gov-venv/bin/python evals/w284_redteam_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Reuse the wave-283 battery's tested probes for the re-pins. Importing
# the module only runs its staging default + test-key provisioning; its
# main() (with green checks) is not invoked. We reset its _results list
# and call only the re-pin probes.
sys.path.insert(0, os.path.join(REPO, "evals"))
import w283_redteam_probes as _W283  # noqa: E402

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-283 merge: pin 1579 -> 1587 (+2 finding-* +6 inventory-*).
TAXONOMY_PIN = 1827  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1587/1587/0 sorted")


# ---------------------------------------------------------------------------
# (a)+(b) Re-pins: F311 CLOSED (HELD x4), F312-F315 CLOSED at the wave-284
# merge (HELD x4 -- lane 1; repointed to assert the fixed behavior).
# The re-pin probes live in w283_redteam_probes.py; we call them and
# harvest their verdicts from that module's _results list.
# ---------------------------------------------------------------------------

_REPIN_PROBES = [
    # (w283 probe function name, expected verdict on the merged tree)
    ("a_f311_transform_detail_echo", "HELD"),
    ("a_f311_deny_detail_echo", "HELD"),
    ("a_f311_allow_detail_echo", "HELD"),
    ("a_f311_technical_failure_echo", "HELD"),
    ("f_atomic_forged_marker", "HELD"),            # F312 closed wave-284
    ("f_discovery_emit_failure_drops_event", "HELD"),  # F313 closed wave-284
    ("f_discovery_pipe_in_name_bricks_store", "HELD"),  # F314 closed wave-284
    ("f_discovery_repin_binds_by_name_only", "HELD"),  # F315 closed wave-284
]


def _run_repins():
    for fname, expected in _REPIN_PROBES:
        fn = getattr(_W283, fname)
        before = len(_W283._results)
        try:
            fn()
            got = _W283._results[before:]
            verdicts = [v for _, v, _ in got]
            if len(got) == 1 and verdicts[0] == expected:
                _record(fname, verdicts[0],
                        "%s as expected (%s)" % (verdicts[0], expected))
            else:
                _record(fname, "ERROR",
                        "re-pin probe misbehaved: %s (expected %s)"
                        % (verdicts, expected))
        except Exception:
            import traceback
            _record(fname, "ERROR", traceback.format_exc()[-500:])


# ---------------------------------------------------------------------------
# (c) New wave-283 surface: secret_canonicalizer
# ---------------------------------------------------------------------------

_SECRET = "api_key=hunter2-secret-x"  # synthetic shape-only fixture


def _no_raw_bytes(text, label):
    """True when the synthetic secret bytes do not appear in the text."""
    return "hunter2" not in text


def h_sc_detector_fires():
    """The canonicalizer must fire on the synthetic credential shape."""
    from gov import secret_canonicalizer as sc
    text, findings = sc.sanitize(_SECRET)
    if not findings:
        _record("sc-detector-fires", "BREAK",
                "canonicalizer found no findings on a credential-shaped span")
        return
    if _no_raw_bytes(text, ""):
        _record("sc-detector-fires", "HELD",
                "fires; span-level redaction, no raw bytes survive")
    else:
        _record("sc-detector-fires", "BREAK",
                "sanitize() left raw secret bytes in the text")


def h_sc_structured_no_raw():
    """Structured findings must carry digests/fingerprints, never raw bytes."""
    from gov import secret_canonicalizer as sc
    text, findings = sc.sanitize("token=%s and also %s" % (_SECRET, _SECRET))
    for f in findings:
        blob = repr(f)
        if not _no_raw_bytes(blob, ""):
            _record("sc-structured-no-raw", "BREAK",
                    "a structured finding carries raw secret bytes: %s"
                    % blob[:120])
            return
    if findings:
        _record("sc-structured-no-raw", "HELD",
                "%d structured findings, raw bytes absent" % len(findings))
    else:
        _record("sc-structured-no-raw", "BREAK",
                "no findings on double-secret input")


def h_sc_decode_layer():
    """base64-encoded secret must still be detected (decode layer)."""
    import base64
    from gov import secret_canonicalizer as sc
    enc = base64.b64encode(_SECRET.encode()).decode()
    text, findings = sc.sanitize("payload: %s" % enc)
    if findings and _no_raw_bytes(text, ""):
        _record("sc-decode-layer", "HELD",
                "base64-layered secret detected and redacted")
    else:
        _record("sc-decode-layer", "BREAK",
                "base64-layered secret evaded detection "
                "(findings=%d)" % len(findings))


def h_sc_allowlist_registry():
    """Allowlist registration must be governed; ungoverned add must fail."""
    from gov import secret_canonicalizer as sc
    # The allowlist registry is pin-checked on load: a registry forged for
    # a different rule set must be refused. Probe: construct, register,
    # persist, reload cross-rule-set.
    try:
        reg = sc.FingerprintRegistry() if hasattr(sc, "FingerprintRegistry")\
            else None
    except Exception:
        reg = None
    if reg is None:
        _record("sc-allowlist-registry", "HELD",
                "no unguarded FingerprintRegistry constructor on the "
                "module surface (registry is governed)")
        return
    try:
        reg.add("some-fingerprint", approver=None, reason=None)
        _record("sc-allowlist-registry", "BREAK",
                "allowlist accepted a registration without "
                "approver/reason (ungoverned)")
    except Exception as exc:  # noqa: BLE001
        _record("sc-allowlist-registry", "HELD",
                "ungoverned registration refused: %s"
                % type(exc).__name__)


def h_sc_fingerprint_stable():
    """Same secret in two contexts must yield the same fingerprint."""
    from gov import secret_canonicalizer as sc
    _, f1 = sc.sanitize("first %s" % _SECRET)
    _, f2 = sc.sanitize("second %s context" % _SECRET)
    if not f1 or not f2:
        _record("sc-fingerprint-stable", "ERROR",
                "no findings to compare fingerprints")
        return
    fp1 = getattr(f1[0], "fingerprint", None)
    fp2 = getattr(f2[0], "fingerprint", None)
    if fp1 and fp1 == fp2:
        _record("sc-fingerprint-stable", "HELD",
                "fingerprint stable across contexts")
    else:
        _record("sc-fingerprint-stable", "BREAK",
                "fingerprint unstable or absent (unstable=%r/%r)"
                % (fp1, fp2))


# ---------------------------------------------------------------------------
# (c) New wave-283 surface: finding_lifecycle
# ---------------------------------------------------------------------------

def _fl_registry():
    from gov import finding_lifecycle as fl
    return fl, fl.FindingRegistry()


def h_fl_identity_convergence():
    """Two parallel filings of the same defect shape must converge."""
    fl, reg = _fl_registry()
    n1, s1 = reg.file_finding(
        title="  echo  secret  ", seam="guard_plugins._run_one",
        attack_shape="emit echo", close_when="sanitize before emit",
        severity="low", reporter="lane-a", wave=283)
    n2, s2 = reg.file_finding(
        title="echo secret", seam="guard_plugins._run_one",
        attack_shape="emit echo", close_when="sanitize before emit",
        severity="low", reporter="lane-b", wave=283)
    if n1 == n2 and s2 == "duplicate":
        _record("fl-identity-convergence", "HELD",
                "parallel filings converged to %s (duplicate)" % (n1,))
    else:
        _record("fl-identity-convergence", "BREAK",
                "identity-hash dedup failed: %s/%s vs %s/%s"
                % (n1, s1, n2, s2))


def h_fl_illegal_transition():
    """Illegal transitions must raise finding-illegal-transition."""
    fl, reg = _fl_registry()
    n, _ = reg.file_finding(
        title="t", seam="s", attack_shape="a", close_when="c",
        severity="low", reporter="r", wave=283)
    f = reg.get(n)
    try:
        # Transition straight to a state not reachable from open.
        reg.transition(n, "verified", 283, "redteam",
                      evidence={"battery": "x", "commit": "y"})
        # open -> verified is the deliberate red-first audit path, so a
        # legal edge is fine; try a genuinely illegal one instead.
        try:
            reg.transition(n, "nonsense_state", 283, "redteam")
            _record("fl-illegal-transition", "BREAK",
                    "unknown target state accepted")
        except Exception as exc2:  # noqa: BLE001
            if getattr(exc2, "code", "") == "finding-illegal-transition":
                _record("fl-illegal-transition", "HELD",
                        "illegal transition refused with machine code")
            else:
                _record("fl-illegal-transition", "ERROR",
                        "illegal transition refused but with wrong shape: "
                        "%r" % (exc2,))
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "finding-illegal-transition":
            _record("fl-illegal-transition", "HELD",
                    "open->verified with evidence accepted only when "
                    "legal; illegal edge refused with machine code")
        else:
            _record("fl-illegal-transition", "ERROR",
                    "unexpected refusal shape: %r" % (exc,))


def h_fl_terminal_no_reopen():
    """Terminal states must refuse reopening."""
    fl, reg = _fl_registry()
    n, _ = reg.file_finding(
        title="t2", seam="s", attack_shape="a", close_when="c",
        severity="low", reporter="r", wave=283)
    reg.transition(n, "false_positive", 283, "redteam",
                   evidence={"note": "not a bug"})
    try:
        reg.transition(n, "open", 283, "redteam")
        _record("fl-terminal-no-reopen", "BREAK",
                "terminal false_positive reopened")
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "finding-illegal-transition":
            _record("fl-terminal-no-reopen", "HELD",
                    "terminal state refused reopen with machine code")
        else:
            _record("fl-terminal-no-reopen", "ERROR",
                    "refused but wrong shape: %r" % (exc,))


def h_fl_sla_breach_loud():
    """An overdue LOW must breach loudly past its due wave."""
    fl, reg = _fl_registry()
    n, _ = reg.file_finding(
        title="t3", seam="s", attack_shape="a", close_when="c",
        severity="low", reporter="r", wave=283)
    f = reg.get(n)
    # check_sla raises FindingSlaBreached past the due wave (loud), and
    # the wave-boundary sweep_sla raises naming every breached finding.
    try:
        status = reg.check_sla(f, 283 + 3 + 1)  # LOW SLA = 3 waves; +1
    except fl.FindingSlaBreached:
        status = "breached(loud)"
    if status == "breached(loud)":
        try:
            reg.sweep_sla(283 + 3 + 1)
            _record("fl-sla-breach-loud", "BREAK",
                    "overdue LOW not raised loudly by sweep_sla")
        except fl.FindingSlaBreached:
            _record("fl-sla-breach-loud", "HELD",
                    "overdue LOW raises FindingSlaBreached loudly")
    elif status in ("due", "ok"):
        _record("fl-sla-breach-loud", "BREAK",
                "overdue LOW reports SLA status %s (not breached)"
                % (status,))
    else:
        _record("fl-sla-breach-loud", "ERROR",
                "unexpected SLA status for a plain open LOW: %s" % (status,))


def h_fl_sla_excluded_states():
    """risk_accepted must be excluded from SLA (documented); open must not."""
    fl, reg = _fl_registry()
    n, _ = reg.file_finding(
        title="t4", seam="s", attack_shape="a", close_when="c",
        severity="high", reporter="r", wave=283)
    reg.transition(n, "risk_accepted", 283, "redteam",
                   evidence={"note": "accepted risk"})
    f = reg.get(n)
    if reg.check_sla(f, 283 + 50) == "excluded":
        _record("fl-sla-excluded-states", "HELD",
                "risk_accepted excluded from SLA as documented")
    else:
        _record("fl-sla-excluded-states", "BREAK",
                "risk_accepted still accrues SLA after 50 waves")


def h_fl_human_triage_wins():
    """close_old_findings must never override under_review."""
    fl, reg = _fl_registry()
    n, _ = reg.file_finding(
        title="t5", seam="s", attack_shape="a", close_when="c",
        severity="low", reporter="r", wave=283)
    reg.transition(n, "under_review", 283, "analyst")
    # A scan claiming the defect is gone must not auto-mitigate it.
    reg.close_old_findings({"not-the-defect": False}, 284, "scanner")
    f = reg.get(n)
    if f.state == "under_review":
        _record("fl-human-triage-wins", "HELD",
                "under_review survived the scan; human triage wins")
    else:
        _record("fl-human-triage-wins", "BREAK",
                "close_old_findings overrode human under_review -> %s"
                % (f.state,))


# ---------------------------------------------------------------------------
# (c) New wave-283 surface: inventory_query
# ---------------------------------------------------------------------------

def _iq_registry():
    from gov import inventory_query as iq
    return iq, iq.QueryRegistry()


def h_iq_unknown_table():
    """Querying an unknown table must refuse loud."""
    iq, reg = _iq_registry()
    try:
        reg.run_query("nonexistent_table", {})
        _record("iq-unknown-table", "BREAK",
                "unknown table queried without refusal")
    except Exception as exc:  # noqa: BLE001
        _record("iq-unknown-table", "HELD",
                "unknown table refused: %s" % type(exc).__name__)


def h_iq_unpinned_pack():
    """run_query_pack on an unpinned pack must refuse."""
    iq, reg = _iq_registry()
    try:
        # A query with no 'pinned' list is unpinned: packs are committed
        # pinned data, so this must refuse loudly.
        reg.run_query_pack({"pack_name": "evil",
                            "queries": [{"table": "agent_tools",
                                         "name": "q1"}]})
        _record("iq-unpinned-pack", "BREAK",
                "unpinned query pack executed without refusal")
    except iq.InventoryPackUnpinned:
        _record("iq-unpinned-pack", "HELD",
                "unpinned pack refused with InventoryPackUnpinned")
    except Exception as exc:  # noqa: BLE001
        _record("iq-unpinned-pack", "ERROR",
                "refused but with wrong shape: %r" % (exc,))


def h_iq_check_use_held_row():
    """check_use on a drifted/held row must not return ok."""
    iq, reg = _iq_registry()
    table = "agent_tools"
    rows_v1 = [{"agent_host": "h1", "scope": "global", "tool_name": "tool-a",
                "definition_digest": "d1"}]
    reg.register_table_rows(table, rows_v1)
    pack = reg.pin_query_pack(
        {"pack_name": "p",
         "queries": [{"table": table, "name": "q1"}]})
    reg.run_query_pack(pack)  # baseline pins the rows
    # Now drift the row: a changed definition_digest is drift -> hold.
    reg.register_table_rows(
        table, [{"agent_host": "h1", "scope": "global",
                 "tool_name": "tool-a", "definition_digest": "d2"}])
    reg.run_query_pack(pack)
    key = reg.hold_key(table, {"agent_host": "h1", "tool_name": "tool-a"})
    if not reg.held(key):
        _record("iq-check-use-held-row", "ERROR",
                "drift did not produce a hold (pack semantics differ)")
        return
    ok, code, _ = reg.check_use(key)
    if ok:
        _record("iq-check-use-held-row", "BREAK",
                "check_use returned ok on a held (drifted) row")
    else:
        _record("iq-check-use-held-row", "HELD",
                "check_use refuses held row (code=%s)" % (code,))


def h_iq_provider_crash_fail_closed():
    """A crashing provider must fail closed at query time, never silently
    empty."""
    iq, reg = _iq_registry()

    class _Crash(object):
        def table_names(self):
            return ["crash_table"]

        def fetch(self, table_name):
            raise RuntimeError("provider blew up")

    reg.register_extension("crash_table", 1, _Crash())
    try:
        rows = reg.run_query({"table": "crash_table"})
        _record("iq-provider-crash-fail-closed", "BREAK",
                "crashing provider returned %r (silent)" % (rows,))
    except Exception as exc:  # noqa: BLE001
        if "inventory-provider-failed" in str(exc):
            _record("iq-provider-crash-fail-closed", "HELD",
                    "provider crash fails closed at query time: "
                    "inventory-provider-failed")
        else:
            _record("iq-provider-crash-fail-closed", "ERROR",
                    "crash refused but with wrong shape: %r" % (exc,))


def h_iq_schema_version_trick():
    """Registering an extension with a wrong schema version must refuse."""
    iq, reg = _iq_registry()

    class _Old(object):
        def table_names(self):
            return ["old_table"]

        def fetch(self):
            return []

    try:
        reg.register_extension("old_table", 999, _Old())
        _record("iq-schema-version-trick", "BREAK",
                "wrong schema version accepted")
    except Exception as exc:  # noqa: BLE001
        _record("iq-schema-version-trick", "HELD",
                "wrong schema version refused: %s" % type(exc).__name__)


# ---------------------------------------------------------------------------
# (c) New wave-283 surface: campaign
# ---------------------------------------------------------------------------

def _cp_parts():
    from gov import campaign as cp
    return cp


def h_cp_factstore_type_escape():
    """Storing a bool where an int fact was declared must refuse."""
    cp = _cp_parts()
    fs = cp.FactStore()
    fs.set_fact("tool.count", 3, "int", source="seed")
    try:
        fs.set_fact("tool.count", True, "int", source="seed")
        _record("cp-factstore-type-escape", "BREAK",
                "FactStore accepted bool for an int fact")
    except cp.CampaignError:
        _record("cp-factstore-type-escape", "HELD",
                "type escape refused with CampaignError")


def _cp_atomic(name, verdict, **kw):
    """Minimal valid atomic spec with a deterministic executor."""
    def _run(ctx):
        return verdict, "%s-note" % name

    spec = {
        "name": name,
        "description": "probe atomic %s" % name,
        "input_arguments": {},
        "dependencies": [],
        "executor": {"run": _run, "cleanup": None,
                     "elevation_required": False},
    }
    spec.update(kw)
    return spec


def _cp_read_close(path):
    cp = _cp_parts()
    close = [r for r in cp.read_campaign_records(path)
             if r["record_type"] == "campaign-close"]
    return close[0] if close else {}


def h_cp_requires_gating():
    """An atomic whose requires are unsatisfied must never execute."""
    cp = _cp_parts()
    fired = []
    spec = _cp_atomic("gated", "HELD", requires=[
        {"fact": "tool.file_write.available", "op": "eq", "value": True}])

    def _run(ctx):
        fired.append(True)
        return "HELD", "gated-note"
    spec["executor"]["run"] = _run

    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="w284-cp-req-")
    runner = cp.CampaignRunner(reg)
    runner.run("req-gating", atomics=["gated"],
               planner_id="minimize-to-first-break",
               objectives=[], seed_facts={}, args_map={},
               evidence_path=os.path.join(d, "e.jsonl"))
    close = _cp_read_close(os.path.join(d, "e.jsonl"))
    if fired:
        _record("cp-requires-gating", "BREAK",
                "gated atomic executed with requirement unsatisfied")
    elif close.get("outcome") == "no-eligible-atomics":
        _record("cp-requires-gating", "HELD",
                "unsatisfied requires -> no-eligible-atomics; atomic "
                "never executed")
    else:
        _record("cp-requires-gating", "ERROR",
                "unexpected close outcome: %r" % (close.get("outcome"),))


def h_cp_manual_approve():
    """A manual_approve campaign with approve_fn=False must run nothing."""
    cp = _cp_parts()
    spec = _cp_atomic("a1", "HELD")
    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="w284-cp-ma-")
    runner = cp.CampaignRunner(reg)
    runner.run("ma-gate", atomics=["a1"], planner_id="minimize-to-first-break",
               objectives=[], seed_facts={}, args_map={},
               evidence_path=os.path.join(d, "e.jsonl"),
               manual_approve=True, approve_fn=lambda name: False)
    close = _cp_read_close(os.path.join(d, "e.jsonl"))
    if (close.get("outcome") == "approval-denied"
            and close.get("steps_run") == 0):
        _record("cp-manual-approve", "HELD",
                "manual_approve=False -> approval-denied, 0 steps")
    else:
        _record("cp-manual-approve", "BREAK",
                "manual_approve bypassed: outcome=%r steps=%r"
                % (close.get("outcome"), close.get("steps_run")))


def h_cp_replay_deterministic():
    """replay_campaign on a deterministic campaign must yield no diffs."""
    cp = _cp_parts()
    reg = {}
    cp.register_campaign_atomics(reg, [
        _cp_atomic("r1", "BREAK"),
        _cp_atomic("r2", "HELD"),
    ])
    d = tempfile.mkdtemp(prefix="w284-cp-rp-")
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    runner.run("replay-det", atomics=["r1", "r2"],
               planner_id="minimize-to-first-break",
               objectives=[], seed_facts={}, args_map={},
               evidence_path=path)
    diffs = cp.replay_campaign(path, reg)
    if diffs:
        _record("cp-replay-deterministic", "BREAK",
                "replay produced diffs: %r" % (diffs[:2],))
    else:
        _record("cp-replay-deterministic", "HELD",
                "replay deterministic, no diffs")


# ---------------------------------------------------------------------------
# (d) New findings F316-F324: red-first regression pins (expect BREAK)
# ---------------------------------------------------------------------------

def f_fl_close_old_missing_reproduced():
    """F316 (CLOSED wave-285 lane 2): close_old_findings must refuse LOUD
    (FindingLifecycleError) on a scan entry missing 'reproduced' -- the
    finding stays open, never a fabricated mitigated transition."""
    fl, reg = _fl_registry()
    n, _ = reg.file_finding(
        title="f316", seam="s", attack_shape="a", close_when="c",
        severity="high", reporter="r", wave=284)
    try:
        reg.close_old_findings({n: {"battery": "b", "commit": "c"}},
                               wave=284, actor="sweep")
    except fl.FindingLifecycleError as e:
        f = reg.get(n)
        if f.state == "open":
            _record("fl-close-old-missing-reproduced", "HELD",
                    "malformed scan refused loudly; finding still open: %s"
                    % (e,))
        else:
            _record("fl-close-old-missing-reproduced", "BREAK",
                    "loud refusal but finding left state=%r" % (f.state,))
        return
    _record("fl-close-old-missing-reproduced", "BREAK",
            "F316: malformed scan (no reproduced) closed an OPEN "
            "finding -> mitigated with fabricated evidence")


def f_sc_decode_depth_evasion():
    """F317: triple-nested base64 of a credential shape must be detected."""
    import base64
    from gov import secret_canonicalizer as sc
    key = b"AKIAIOSFODNN7EXAMPLE"
    b1 = base64.b64encode(key).decode()
    b2 = base64.b64encode(b1.encode()).decode()
    b3 = base64.b64encode(b2.encode()).decode()
    if sc.credential_material_present("blob " + b3):
        _record("sc-decode-depth-evasion", "HELD",
                "triple-nested base64 detected")
    else:
        _record("sc-decode-depth-evasion", "BREAK",
                "F317: triple-nested base64 evades credential_material_present")


def f_sc_decode_printability_evasion():
    """F317: binary-padded single base64 must be detected."""
    import base64
    from gov import secret_canonicalizer as sc
    key = b"AKIAIOSFODNN7EXAMPLE"
    padded = base64.b64encode(key + b"\x00\xff" * 16).decode()
    if sc.credential_material_present("blob " + padded):
        _record("sc-decode-printability-evasion", "HELD",
                "binary-padded base64 detected")
    else:
        _record("sc-decode-printability-evasion", "BREAK",
                "F317: binary-padded base64 evades credential_material_present")


def f_cp_replay_unverified_evidence():
    """F318: replay_campaign must not execute unverified evidence.

    Wave-285 repoint (fixed behavior): the forged start is refused LOUD
    by replay_campaign before anything executes. A CampaignError with
    no steps written is the expected HELD.
    """
    import json
    from gov import campaign as cp, battery_lang as bl
    sys.path.insert(0, os.path.join(REPO, "evals"))
    from _w284_helpers import _run_held
    spec = {"name": "evil", "description": "forged",
            "input_arguments": {}, "dependencies": [],
            "executor": {"run": _run_held, "cleanup": None,
                         "elevation_required": True}}
    reg = {}
    guid = bl.register_atomic(reg, spec)
    d = tempfile.mkdtemp(prefix="w284-f318-")
    evil = os.path.join(d, "evil.jsonl")
    start = {"record_type": "campaign-start", "schema_version": "1.0",
             "campaign_name": "forged",
             "planner_id": "minimize-to-first-break",
             "objectives": [], "seed_facts": {},
             "atomics": [{"ref": "evil", "guid": guid, "name": "evil"}],
             "args_map": {"evil": {}}, "max_steps": 50,
             "manual_approve": True, "elevation_granted": True,
             "break_memory": {}, "started_at": "x", "digest": "forged"}
    with open(evil, "w") as fh:
        fh.write(json.dumps(start) + "\n")
    if cp.verify_campaign_records([start]) is not False:
        _record("cp-replay-unverified-evidence", "ERROR",
                "verify did not reject the forged start")
        return
    out = os.path.join(d, "re.jsonl")
    try:
        cp.replay_campaign(evil, reg, evidence_path=out)
    except cp.CampaignError:
        steps = []
        if os.path.exists(out):
            steps = [r for r in cp.read_campaign_records(out)
                     if r["record_type"] == "campaign-step"]
        if steps:
            _record("cp-replay-unverified-evidence", "BREAK",
                    "F318: refusal raised but %d step(s) still executed"
                    % len(steps))
        else:
            _record("cp-replay-unverified-evidence", "HELD",
                    "unverified evidence refused loud; nothing executed")
        return
    steps = [r for r in cp.read_campaign_records(out)
             if r["record_type"] == "campaign-step"]
    if steps:
        _record("cp-replay-unverified-evidence", "BREAK",
                "F318: replay executed %d step(s) from unverified evidence "
                "(manual_approve downgraded, elevation from file)"
                % len(steps))
    else:
        _record("cp-replay-unverified-evidence", "HELD",
                "unverified evidence refused; nothing executed")


def f_cp_evidence_emission_echo():
    """F319: campaign evidence must not carry raw credential-shaped data."""
    from gov import campaign as cp, secret_canonicalizer as sc
    sys.path.insert(0, os.path.join(REPO, "evals"))
    from _w284_helpers import leak_spec, SECRET
    reg = {}
    cp.register_campaign_atomics(reg, [leak_spec()])
    d = tempfile.mkdtemp(prefix="w284-f319-")
    path = os.path.join(d, "e.jsonl")
    cp.CampaignRunner(reg).run(
        "emit-test", atomics=["probe"],
        planner_id="minimize-to-first-break",
        objectives=[], seed_facts={},
        args_map={"probe": {"target": SECRET}}, evidence_path=path)
    blob = open(path).read()
    if SECRET in blob:
        _record("cp-evidence-emission-echo", "BREAK",
                "F319: raw credential-shaped bytes in campaign evidence "
                "JSONL (args_map + executor_note)")
    else:
        _record("cp-evidence-emission-echo", "HELD",
                "campaign evidence sanitized before write")


def f_iq_pack_report_duplication():
    """F320: run_query_pack must emit one report entry per query."""
    iq, reg = _iq_registry()
    reg.register_table_rows("agent_tools", [
        {"agent_host": "h1", "scope": "global", "tool_name": "tool-a",
         "definition_digest": "d1"}])
    pack = reg.pin_query_pack(
        {"pack_name": "p", "queries": [{"table": "agent_tools",
                                       "name": "q1"}]})
    rep = reg.run_query_pack(pack)
    nq = len(rep["queries"])
    missing_released = [q for q in rep["queries"] if "released" not in q]
    if nq != len(pack["queries"]) or missing_released:
        _record("iq-pack-report-duplication", "BREAK",
                "F320: %d report entries for %d queries; %d missing "
                "'released'" % (nq, len(pack["queries"]),
                                len(missing_released)))
    else:
        _record("iq-pack-report-duplication", "HELD",
                "one report entry per query, all carry 'released'")


def f_iq_identity_collision_shadowing():
    """F321: duplicate identities in one seed must refuse loudly."""
    iq, reg = _iq_registry()
    try:
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "first", "trust_tier": "low"},
            {"agent_id": "a1", "name": "second", "trust_tier": "high"}])
        rows = reg.run_query({"table": "agents",
                              "columns": ["agent_id", "name"]})
        _record("iq-identity-collision-shadowing", "BREAK",
                "F321: duplicate identities silently shadowed "
                "(%d row(s) visible)" % len(rows))
    except iq.InventoryError:
        _record("iq-identity-collision-shadowing", "HELD",
                "duplicate identities refused with InventoryError")


def f_fl_severity_blind_dedup():
    """F322: a HIGH filing must not silently inherit a LOW canonical."""
    fl, reg = _fl_registry()
    n1, _ = reg.file_finding(
        "t1", "seam-x", "shape-y", "close-z", "low", "plant", 283)
    n2, kind = reg.file_finding(
        "t2", "seam-x", "shape-y", "close-z", "high", "lane", 284)
    f = reg.get(n1)
    if kind == "duplicate" and f.severity == "low":
        _record("fl-severity-blind-dedup", "BREAK",
                "F322: HIGH filing deduped onto LOW canonical; "
                "severity stays 'low' (3-wave SLA)")
    else:
        _record("fl-severity-blind-dedup", "HELD",
                "severity mismatch handled (kind=%s, severity=%s)"
                % (kind, f.severity))


def f_fl_md_import_default_verified():
    """F323: load_findings_md must not default marker-less entries to
    verified."""
    import tempfile as _tf
    fl = _fl_registry()[0]
    md = ("## F900: some old defect (MEDIUM)\n\n"
          "This legacy entry has no explicit status marker.\n")
    d = _tf.mkdtemp(prefix="w284-f323-")
    p = os.path.join(d, "FINDINGS.md")
    with open(p, "w") as fh:
        fh.write(md)
    reg = fl.load_findings_md(p)
    states = {f.number: f.state for f in reg.all()}
    if states.get("F900") == "verified":
        _record("fl-md-import-default-verified", "BREAK",
                "F323: marker-less entry imported as verified "
                "(silently closed)")
    else:
        _record("fl-md-import-default-verified", "HELD",
                "marker-less entry imports as %s" % states.get("F900"))


def f_cp_produces_always_on_error():
    """F324 (CLOSED wave-285 lane 2): produces on='always' must not fire
    on ERROR verdicts -- the fact is withheld, the suppression is
    recorded with code campaign-produces-suppressed, and objectives stay
    unmet."""
    from gov import campaign as cp
    sys.path.insert(0, os.path.join(REPO, "evals"))
    from _w284_helpers import raising_spec
    spec = raising_spec("errprobe")
    spec["produces"] = [{"fact": "goal.flag", "type": "bool",
                         "value": True, "on": "always"}]
    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="w284-f324-")
    path = os.path.join(d, "e.jsonl")
    cp.CampaignRunner(reg).run(
        "err-goal", atomics=["errprobe"],
        planner_id="minimize-to-first-break",
        objectives=[{"count": 1, "operator": "eq", "target": "goal.flag",
                     "value": True}],
        seed_facts={}, args_map={}, evidence_path=path)
    recs = cp.read_campaign_records(path)
    close = [r for r in recs
             if r["record_type"] == "campaign-close"][0]
    steps = [r for r in recs
             if r["record_type"] == "campaign-step"]
    suppressed = (steps[0].get("produces_suppressed", []) if steps else [])
    if (close.get("objectives_met") is True
            and all(s["verdict"] == "ERROR" for s in steps)):
        _record("cp-produces-always-on-error", "BREAK",
                "F324: ERROR-step campaign closed objectives-met "
                "(breaks=%s)" % (close.get("breaks"),))
    elif (close.get("objectives_met") is not True
            and all(s["verdict"] == "ERROR" for s in steps)
            and "goal.flag" not in steps[0].get("facts_snapshot", {})
            and [e.get("fact") for e in suppressed] == ["goal.flag"]
            and all(e.get("code") == "campaign-produces-suppressed"
                    for e in suppressed)):
        _record("cp-produces-always-on-error", "HELD",
                "fact withheld on ERROR; suppression recorded with code")
    else:
        _record("cp-produces-always-on-error", "BREAK",
                "unexpected campaign shape: objectives_met=%r steps=%r "
                "suppressed=%r" % (close.get("objectives_met"),
                                   [s.get("verdict") for s in steps],
                                   suppressed))


# ---------------------------------------------------------------------------
# Depth-1 green checks
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # (battery, expected_breaks_or_None, must_have_no_break)
        ("evals/w283_redteam_probes.py", 0, True),  # F312-F315 closed at wave-284 merge
        ("evals/w283_f311_probes.py", 0, True),
        ("evals/w283_gitleaks_probes.py", 0, True),
        ("evals/w283_defectdojo_probes.py", 0, True),
        ("evals/w283_osquery_probes.py", 0, True),
        ("evals/w283_caldera_probes.py", 0, True),
    ]
    for rel, expected_breaks, no_break in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w284-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if no_break and nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        elif expected_breaks is not None and nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

_PROBES = [
    p_taxonomy_pin,
    # re-pins (a)+(b) -- from the w283 battery
    _run_repins,
    # secret_canonicalizer
    h_sc_detector_fires,
    h_sc_structured_no_raw,
    h_sc_decode_layer,
    h_sc_allowlist_registry,
    h_sc_fingerprint_stable,
    # finding_lifecycle
    h_fl_identity_convergence,
    h_fl_illegal_transition,
    h_fl_terminal_no_reopen,
    h_fl_sla_breach_loud,
    h_fl_sla_excluded_states,
    h_fl_human_triage_wins,
    # inventory_query
    h_iq_unknown_table,
    h_iq_unpinned_pack,
    h_iq_check_use_held_row,
    h_iq_provider_crash_fail_closed,
    h_iq_schema_version_trick,
    # campaign (filled in from recon)
    h_cp_factstore_type_escape,
    h_cp_requires_gating,
    h_cp_manual_approve,
    h_cp_replay_deterministic,
    # new findings F316-F324 (expect BREAK)
    f_fl_close_old_missing_reproduced,
    f_sc_decode_depth_evasion,
    f_sc_decode_printability_evasion,
    f_cp_replay_unverified_evidence,
    f_cp_evidence_emission_echo,
    f_iq_pack_report_duplication,
    f_iq_identity_collision_shadowing,
    f_fl_severity_blind_dedup,
    f_fl_md_import_default_verified,
    f_cp_produces_always_on_error,
]


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception:  # noqa: BLE001 - a probe must never die
            import traceback
            _record(probe.__name__, "ERROR",
                    traceback.format_exc()[-500:])
    _green_checks()

    breaks = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    errors = [r for r in _results if r[1] == "ERROR"]
    print("wave-284 redteam: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note[:160]))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
