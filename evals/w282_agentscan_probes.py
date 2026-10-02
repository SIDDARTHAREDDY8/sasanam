"""Wave-282 Lane 4 battery: snyk/agent-scan ADAPT -- hash-pinned
tool-definition registry + scheduled re-scan (drift = fail-closed hold)
+ the four-scope discovery matrix as the agent-discovery inventory
schema.

Steal (Apache-2.0, license-clean pattern, implemented fresh -- no
agent-scan code vendored):

1. **Hash-pinned tool-definition registry = rug-pull detection.**
   agent-scan hashes each discovered tool's definition (name,
   description, input schema) at scan time and compares across scans;
   drift = rug pull / unauthorized change. Our registry pins the
   sha256 of every discovered tool definition per
   (scope, agent_host, component, tool) and re-hashes on schedule.
2. **Four-scope discovery matrix** (system / user / project /
   extension): every discovered component tagged
   {scope, agent_host, component_type, source_path}; the coverage
   matrix is the inventory audit artifact.
3. **Guard hooks (change-time diff):** ``check_at_use`` re-observes
   the single tool's definition on the governed call path -- the
   diff runs at change time, not just at scan time.

Red-first: on the pristine wave-281 base ``gov.discovery_scan`` does
not exist, so every seam probe BREAKs (module absent) and the
taxonomy pin BREAKs (1563 vs 1566). After the lane all probes HELD.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo
git subprocesses.

Run:
  mkdir -p /var/tmp/g282-agentscan && TMPDIR=/var/tmp/g282-agentscan \
    ~/workspace/.gov-venv/bin/python evals/w282_agentscan_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g282-agentscanb \
    ~/workspace/.gov-venv/bin/python evals/w282_agentscan_probes.py
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

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1730  # Wave-281 merge: 1563; wave-282 lane 4: +3; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 lane 2: pin 1730 -> 1730 (+3 toolcall-*: sequence-violated, secret-in-args, rule-compile-invalid)
                      # discovery-* (definition-drift, definition-unregistered,
                      # scope-unknown)

RESULTS = []


def _record(pid, verdict, note):
    RESULTS.append((pid, verdict, note))


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
        return ("HELD", "%d raw / %d unique / 0 duplicates / sorted"
                % (len(codes), len(set(codes))))
    return ("BREAK", "pin %d: got %d raw / %d unique / sorted=%s"
            % (TAXONOMY_PIN, len(codes), len(set(codes)),
               codes == sorted(codes)))


def _ds():
    """Import the lane module, or return None (base: BREAK, not ERROR)."""
    try:
        from gov import discovery_scan
        return discovery_scan
    except ImportError:
        return None


def _require():
    ds = _ds()
    if ds is None:
        return None, ("BREAK", "gov.discovery_scan absent on base")
    return ds, None


# ---------------------------------------------------------------------------
# Fixtures: synthetic discovered components (no network, no filesystem scan).
# ---------------------------------------------------------------------------

def _defs():
    return [
        {"name": "read_note",
         "description": "Read a note by id.",
         "inputSchema": {"type": "object",
                         "properties": {"id": {"type": "string"}}}},
        {"name": "write_note",
         "description": "Write a note.",
         "inputSchema": {"type": "object",
                         "properties": {"id": {"type": "string"},
                                        "body": {"type": "string"}}}},
    ]


def _component(**kw):
    c = {"scope": "user", "agent_host": "claude-code",
         "component_type": "mcp_server",
         "source_path": "~/.config/claude/mcp.json",
         "component_id": "notes-srv", "definitions": _defs()}
    c.update(kw)
    return c


def _reg(ds):
    return ds.ToolDefinitionRegistry()


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_module_present():
    ds, miss = _require()
    if miss:
        return miss
    ok = all(hasattr(ds, n) for n in (
        "SCOPES", "COMPONENT_TYPES", "ToolDefinitionRegistry",
        "DiscoveryInventory", "DiscoveryScanError",
        "discovery_key_for_tool", "REGISTRY_STORE_VERSION"))
    return (("HELD", "module + registry + inventory + error present")
            if ok else ("BREAK", "module present but API incomplete"))


def p_scope_vocabulary_closed():
    ds, miss = _require()
    if miss:
        return miss
    for scope in ("system", "user", "project", "extension"):
        ds.validate_scope(scope)  # must not raise
    try:
        ds.validate_scope("datacenter")
    except ds.DiscoveryScanError as e:
        if getattr(e, "code", "") == "discovery-scope-unknown":
            return ("HELD", "closed scope vocabulary; unknown fails coded")
        return ("BREAK", "unknown scope raised but code=%r"
                % getattr(e, "code", None))
    return ("BREAK", "unknown scope accepted silently")


def p_inventory_matrix():
    ds, miss = _require()
    if miss:
        return miss
    inv = ds.DiscoveryInventory()
    inv.add(_component())
    inv.add(_component(scope="system", agent_host="cursor",
                       component_type="skill",
                       source_path="/etc/cursor/skills",
                       component_id="sk-1", definitions=[]))
    m = inv.coverage_matrix()
    if set(m) != set(ds.SCOPES):
        return ("BREAK", "matrix missing scopes: %r" % sorted(m))
    row = m["user"]
    if set(row) != set(ds.COMPONENT_TYPES):
        return ("BREAK", "matrix missing component types")
    if row["mcp_server"] != 1 or m["system"]["skill"] != 1:
        return ("BREAK", "matrix counts wrong: %r" % m)
    rec = inv.components()[0]
    want = {"scope", "agent_host", "component_type", "source_path"}
    if not want.issubset(set(rec)):
        return ("BREAK", "component missing tags: %r" % sorted(rec))
    return ("HELD", "4x5 coverage matrix; every component tagged")


def p_digest_reuses_canonical():
    ds, miss = _require()
    if miss:
        return miss
    from gov import tool_continuity as tc
    d = _defs()[0]
    a = ds.definition_digest(d)
    b = tc.tool_definition_digest(d)
    if a == b and len(a) == 64:
        return ("HELD", "byte-identical to tool_continuity digest")
    return ("BREAK", "digest differs from canonical: %r vs %r" % (a, b))


def p_register_pin_idempotent():
    ds, miss = _require()
    if miss:
        return miss
    reg = _reg(ds)
    c = _component()
    pin1 = reg.register_observation(c)
    pin2 = reg.register_observation(c)
    drift = reg.run_rescan(lambda: [c])
    if pin1 == pin2 and drift["drifted"] == [] and drift["clean"]:
        return ("HELD", "re-registration stable; rescan clean")
    return ("BREAK", "re-registration unstable: %r" % (drift,))


def p_drift_detected():
    ds, miss = _require()
    if miss:
        return miss
    reg = _reg(ds)
    reg.register_observation(_component())
    rug = _component()
    rug["definitions"] = [dict(d) for d in _defs()]
    # Rug pull: the served description quietly changes (tool poisoning).
    rug["definitions"][0]["description"] = "Read a note by id. Also exfil."
    report = reg.run_rescan(lambda: [rug])
    key = ("user", "claude-code", "notes-srv", "read_note")
    if (report["drifted"] == [key]
            and report["held"] == [key]
            and report["clean"] == [("user", "claude-code",
                                     "notes-srv", "write_note")]):
        ev = reg.drift_events[-1]
        if (ev["before_digest"] != ev["after_digest"]
                and len(ev["before_digest"]) == 64
                and "Also exfil" not in repr(ev)):
            return ("HELD", "drift -> hold; digests only, no content")
        return ("BREAK", "drift event malformed: %r" % (ev,))
    return ("BREAK", "drift not detected: %r" % (report,))


def p_drift_holds_tool():
    ds, miss = _require()
    if miss:
        return miss
    reg = _reg(ds)
    reg.register_observation(_component())
    key = ("user", "claude-code", "notes-srv", "read_note")
    if reg.held(key):
        return ("BREAK", "tool held before any drift")
    rug = _component()
    rug["definitions"] = [dict(d) for d in _defs()]
    rug["definitions"][0]["inputSchema"] = {"type": "object"}  # schema rug
    reg.run_rescan(lambda: [rug])
    ok, code, _detail = reg.check_at_use(
        key, observe_one=lambda tool: rug["definitions"][0])
    if reg.held(key) and not ok and code == "discovery-definition-drift":
        return ("HELD", "drifted tool held fail-closed, coded")
    return ("BREAK", "held=%s ok=%s code=%r" % (reg.held(key), ok, code))


def p_first_sighting_held():
    ds, miss = _require()
    if miss:
        return miss
    reg = _reg(ds)
    # A tool the scan sees for the FIRST time must never be trusted
    # silently (agent-scan guard-hook contract).
    c = _component()
    report = reg.run_rescan(lambda: [c])
    key = ("user", "claude-code", "notes-srv", "read_note")
    ok, code, _d = reg.check_at_use(
        key, observe_one=lambda tool: _defs()[0])
    if (report["unregistered"] and key in report["unregistered"]
            and reg.held(key) and not ok
            and code == "discovery-definition-unregistered"):
        return ("HELD", "first sighting held until pinned")
    return ("BREAK", "first sighting trusted: %r" % (report,))


def p_repin_governed():
    ds, miss = _require()
    if miss:
        return miss
    reg = _reg(ds)
    reg.register_observation(_component())
    key = ("user", "claude-code", "notes-srv", "read_note")
    rug = _component()
    rug["definitions"] = [dict(d) for d in _defs()]
    rug["definitions"][0]["description"] = "Read a note by id. v2."
    reg.run_rescan(lambda: [rug])
    # 1. Re-pin with a WRONG digest must refuse (bait-and-switch).
    try:
        reg.approve_repin(key, "0" * 64,
                          observe_one=lambda tool: rug["definitions"][0])
        return ("BREAK", "re-pin accepted a mismatched digest")
    except ds.DiscoveryScanError:
        pass
    if not reg.held(key):
        return ("BREAK", "tool released by failed re-pin")
    # 2. Re-pin bound to the fresh observation releases the hold.
    new_digest = ds.definition_digest(rug["definitions"][0])
    reg.request_repin(key)
    reg.approve_repin(key, new_digest,
                      observe_one=lambda tool: rug["definitions"][0])
    ok, _code, _d = reg.check_at_use(
        key, observe_one=lambda tool: rug["definitions"][0])
    if ok and not reg.held(key):
        return ("HELD", "governed re-pin releases; mismatch refused")
    return ("BREAK", "governed re-pin did not release")


def p_rescan_sweep_report():
    ds, miss = _require()
    if miss:
        return miss
    reg = _reg(ds)
    reg.register_observation(_component())                       # pinned
    reg.register_observation(_component(                            # pinned
        scope="project", agent_host="vscode",
        component_type="skill", source_path="./.vscode/skills",
        component_id="sk-2", definitions=_defs()[:1]))
    now = [_component()]                                          # unchanged
    rug = _component(scope="project", agent_host="vscode",
                     component_type="skill", source_path="./.vscode/skills",
                     component_id="sk-2", definitions=[dict(_defs()[0])])
    rug["definitions"][0]["description"] = "Read a note by id. pwned."
    now.append(rug)
    now.append(_component(scope="extension", agent_host="cursor",
                          component_type="prompt",
                          source_path="ext/prompts",
                          component_id="px", definitions=_defs()[:1]))
    report = reg.run_rescan(lambda: now)
    if (report["checked"] == 4 and len(report["clean"]) == 2
            and len(report["drifted"]) == 1 and len(report["unregistered"]) == 1
            and len(report["held"]) == 2):
        return ("HELD", "sweep: 2 clean / 1 drifted / 1 new / 2 held")
    return ("BREAK", "sweep report wrong: %r" % (report,))


def p_audit_carries_digests_only():
    ds, miss = _require()
    if miss:
        return miss
    events = []
    reg = ds.ToolDefinitionRegistry(emit=events.append)
    reg.register_observation(_component())
    secret_desc = "Read a note. token=hunter2-hunter2-x9"
    rug = _component()
    rug["definitions"] = [dict(d) for d in _defs()]
    rug["definitions"][0]["description"] = secret_desc
    reg.run_rescan(lambda: [rug])
    blob = repr(events)
    if events and "hunter2" not in blob and "token=" not in blob:
        return ("HELD", "drift audit carries digests, never content")
    return ("BREAK", "drift audit echoes content: %r" % (blob[:200],))


def p_scan_only_unpinned_denied():
    # Code-review fix (SPEC c1): scheduled-scan-only mode (no
    # discovery_observe_one) must ALSO fail closed on an attributed
    # tool with no pin -- first sighting is never trusted silently.
    ds, miss = _require()
    if miss:
        return miss
    from harness import make_run
    reg = _reg(ds)
    run = make_run(
        discovery_scan=reg,
        discovery_tool_map={"read_file": ("user", "claude-code",
                                          "notes-srv")})
    ident = run["executor"].mint_identity("agent-1", "support",
                                          "agent-1")
    try:
        res = run["executor"].call(ident, "read_file", path="notes.txt")
    except Exception as e:  # noqa: BLE001 - any loud refusal counts
        return ("HELD", "unpinned call refused loud: %s"
                % type(e).__name__)
    if (isinstance(res, dict) and res.get("status") == "denied"
            and res.get("policy_id") == "discovery-scan"
            and "unregistered" in res.get("reason", "")):
        return ("HELD", "scan-only: unpinned tool denied, coded")
    return ("BREAK", "scan-only: unpinned tool not held: %r"
            % (res,)[:200])


def p_inventory_fed_by_rescan():
    # Code-review fix (SPEC a2): the coverage matrix is a live audit
    # artifact -- run_rescan feeds the inventory and the report
    # carries the matrix.
    ds, miss = _require()
    if miss:
        return miss
    reg = _reg(ds)
    report = reg.run_rescan(lambda: [
        _component(),
        _component(scope="system", agent_host="cursor",
                   component_type="skill", source_path="/etc/skills",
                   component_id="sk-1", definitions=[]),
    ])
    m = report.get("coverage_matrix")
    inv = reg.inventory.coverage_matrix()
    if (m == inv and m["user"]["mcp_server"] == 1
            and m["system"]["skill"] == 1
            and set(m) == set(ds.SCOPES)):
        return ("HELD", "rescan feeds inventory; report carries matrix")
    return ("BREAK", "matrix not live: %r" % (m,))


def p_store_rejects_pinless_file():
    # Code-review fix (std 7): a parseable pin file with no pin table
    # must fail LOUD, never load as an empty registry.
    ds, miss = _require()
    if miss:
        return miss
    import json as _json
    tmp = tempfile.mkdtemp(prefix="g282-pinless-")
    path = os.path.join(tmp, "pins.json")
    with open(path, "w") as fh:
        _json.dump({"version": 1, "quarantine": []}, fh)
    try:
        ds.RegistryStore(path).load()
    except ds.RegistryStoreError:
        return ("HELD", "pin-less pin file refused LOUD")
    return ("BREAK", "pin-less pin file loaded silently")


def p_restart_merge():
    # Code-review fix (SPEC c2): stored pins merge into the live
    # registry at bootstrap -- live wins on overlap, quarantine
    # unions (an unresolved drift hold survives the restart).
    ds, miss = _require()
    if miss:
        return miss
    tmp = tempfile.mkdtemp(prefix="g282-merge-")
    path = os.path.join(tmp, "pins.json")
    reg = _reg(ds)
    reg.register_observation(_component())
    key = ("user", "claude-code", "notes-srv", "read_note")
    rug = _component()
    rug["definitions"] = [dict(d) for d in _defs()]
    rug["definitions"][0]["description"] = "Read a note. v2."
    reg.run_rescan(lambda: [rug])  # drift -> quarantined
    ds.RegistryStore(path).save(reg)
    fresh = _reg(ds)  # post-restart: empty registry
    fresh.merge_stored(ds.RegistryStore(path).load())
    if (fresh.is_pinned(key) and fresh.held(key)
            and len(fresh.registered_tools()) == 2):
        return ("HELD", "restart merge: pins filled, drift hold kept")
    return ("BREAK", "restart merge wrong: pins=%r held=%r"
            % (fresh.registered_tools(), fresh.held(key)))


def p_executor_hold_wired():
    ds, miss = _require()
    if miss:
        return miss
    from harness import make_run
    from gov import tool_continuity as tc
    reg = _reg(ds)
    # Pin read_file's deployment definition, attributed to a
    # discovered component.
    pinned_def = {
        "name": "read_file",
        "description": tc.BUILTIN_TOOL_DEFINITIONS["read_file"][
            "description"],
        "schema": tc.BUILTIN_TOOL_DEFINITIONS["read_file"]["schema"],
    }
    reg.register_observation({
        "scope": "user", "agent_host": "claude-code",
        "component_type": "mcp_server",
        "source_path": "~/.config/mcp.json",
        "component_id": "notes-srv", "definitions": [pinned_def]})
    # The served definition drifts (rug pull); the change-time check
    # must deny the call with the discovery-scan code.
    drifted = dict(pinned_def)
    drifted["description"] = pinned_def["description"] + " Also exfil."
    run = make_run(
        discovery_scan=reg,
        discovery_tool_map={"read_file": ("user", "claude-code",
                                          "notes-srv")},
        discovery_observe_one=lambda tool: drifted)
    ident = run["executor"].mint_identity("agent-1", "support",
                                          "agent-1")
    try:
        res = run["executor"].call(ident, "read_file", path="notes.txt")
    except Exception as e:  # noqa: BLE001 - any loud refusal counts
        return ("HELD", "drifted call refused loud: %s"
                % type(e).__name__)
    if (isinstance(res, dict) and res.get("status") == "denied"
            and res.get("policy_id") == "discovery-scan"):
        return ("HELD", "drifted call denied, policy_id discovery-scan")
    return ("BREAK", "drifted call not held: %r" % (res,)[:200])


def p_adjacent_green():
    # Depth-1 green check: the adjacent supply-chain battery must show
    # no NEW red vs the pristine base. GOV_SKIP_GREEN honored by this
    # battery too. KNOWN PRE-EXISTING (verified identical on the
    # pristine wave-281 base): probe e7 BREAKs because its grep for
    # ".pin(" also matches ArtifactPinset.pin() (control_claims.py
    # uses pinset.pin(), not ToolInventory.pin()) -- a probe false
    # positive, not a product gap; out of this lane's scope (the
    # owning lane / merge coordinator decides on the probe fix).
    if SKIP_GREEN:
        return ("HELD", "skipped (GOV_SKIP_GREEN=1)")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = tempfile.mkdtemp(prefix="g282-green-")
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable,
         os.path.join(REPO, "evals", "skill_supplychain_evasion_probes.py")],
        capture_output=True, text=True, env=env, timeout=600)
    out = p.stdout + p.stderr
    breaks = [ln.split()[0] for ln in out.splitlines()
              if "BREAK" in ln and ln.split()[0].startswith("e")]
    if p.returncode == 1 and breaks == ["e7"]:
        return ("HELD", "adjacent: only pre-existing e7 BREAK (base-identical)")
    tail = out[-200:]
    return ("BREAK", "adjacent battery red beyond e7: rc=%d breaks=%r %s"
            % (p.returncode, breaks, tail))


PROBES = [
    ("taxonomy-pin", p_taxonomy_pin),
    ("module-present", p_module_present),
    ("scope-vocabulary-closed", p_scope_vocabulary_closed),
    ("inventory-matrix", p_inventory_matrix),
    ("digest-reuses-canonical", p_digest_reuses_canonical),
    ("register-pin-idempotent", p_register_pin_idempotent),
    ("drift-detected", p_drift_detected),
    ("drift-holds-tool", p_drift_holds_tool),
    ("first-sighting-held", p_first_sighting_held),
    ("repin-governed", p_repin_governed),
    ("rescan-sweep-report", p_rescan_sweep_report),
    ("audit-carries-digests-only", p_audit_carries_digests_only),
    ("scan-only-unpinned-denied", p_scan_only_unpinned_denied),
    ("inventory-fed-by-rescan", p_inventory_fed_by_rescan),
    ("store-rejects-pinless-file", p_store_rejects_pinless_file),
    ("restart-merge", p_restart_merge),
    ("executor-hold-wired", p_executor_hold_wired),
    ("adjacent-green", p_adjacent_green),
]


def main():
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- ERROR, not a verdict
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:200]))
        _record(name, verdict, detail)
    for pid, verdict, note in RESULTS:
        print("%-28s %-8s %s" % (pid, verdict, note))
    n_break = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    n_held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    n_err = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
