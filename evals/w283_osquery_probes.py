"""Wave-283 lane 6 red-first battery: osquery mechanism STEAL (pattern).

Gap (base ad222ce): Sasanam has a hash-pinned discovery registry and a
scheduled re-scan (gov.discovery_scan), but no TABLE-inventory abstraction
over it -- no versioned virtual tables (agents, agent_tools, mcp_servers,
skill_bundles) with digest-bound rows, no provider plug-in contract
(osquery's extension tables), and no committed query packs whose scheduled
deltas hold the registry (the continuous-verification half of the
user-ordered discovery/inventory stream).

Red-first: on base every capability probe BREAKs (gov.inventory_query
absent; the taxonomy pin expects the 6 new inventory-* codes). After the
build: tables are schema-versioned and pinned, row digests bind content,
extension providers register through a closed API (crashes and wrong
schema versions fail closed loud), unpinned query packs refuse loud, and
pack deltas hold fail-closed (drift -> inventory-pack-drift, first
sighting -> inventory-unregistered), with digests-only audit events and
hold persistence mirroring the wave-282 discovery registry.

Pattern lineage: osquery/osquery (canonical repo; moved from
facebook/osquery). Dual license Apache-2.0 OR GPL-2.0-only -- we elect
Apache-2.0. Pattern only, no code taken: virtual tables, the
extension-table API as provider contract, query packs as scheduled
drift=fail-closed audits. $0 spend, stdlib only.
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w283-osquery")
os.environ.setdefault("TMPDIR", "/var/tmp/g283-osquery")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

# Wave-282 merge pin 1579 -> 1585 (+6 inventory-* codes).
TAXONOMY_PIN = 1967 # Wave-283 lane 6: +6 inventory-*; Wave-283 merge: pin 1585 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []

PLUGIN_META = ("guardrail-evidence", "direct", "held-vs-expected")
PROBE_METADATA = {}


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _require_module(probe_id):
    try:
        from gov import inventory_query as Q
        return Q
    except ImportError:
        _record(probe_id, "BREAK", "gov.inventory_query absent on base")
        return None


def _literals():
    import re
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "gov", "decision_codes.py"),
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
    if sorted(lits) != lits:
        return _record("pin-taxonomy", "BREAK", "taxonomy not sorted")
    _record("pin-taxonomy", "HELD", "1588/1588/0 sorted")


def p_module_present():
    Q = _require_module("p-module-present")
    if Q is None:
        return
    if not all(hasattr(Q, n) for n in (
            "QueryRegistry", "row_digest", "InventoryError",
            "InventoryPackUnpinned", "inventory_tables_from_discovery",
            "CORE_TABLES", "table_schema_version")):
        return _record("p-module-present", "BREAK",
                       "public surface incomplete")
    reg = Q.QueryRegistry()
    if not all(hasattr(reg, n) for n in (
            "set_emit", "holds_snapshot", "merge_snapshot",
            "registered_schema_version", "release_hold", "check_use")):
        return _record("p-module-present", "BREAK",
                       "registry audit surface incomplete")
    _record("p-module-present", "HELD", "inventory_query surface present")


def _core_reg(Q):
    reg = Q.QueryRegistry()
    reg.register_table_rows("agents", [{"agent_id": "a1", "name": "red",
                                       "trust_tier": "low"}])
    return reg


def p_table_schema_versions():
    Q = _require_module("p-table-schema-versions")
    if Q is None:
        return
    if Q.CORE_TABLES != ("agents", "agent_tools", "mcp_servers",
                         "skill_bundles"):
        return _record("p-table-schema-versions", "BREAK",
                       "core table set wrong: %r" % (Q.CORE_TABLES,))
    for t in Q.CORE_TABLES:
        if Q.table_schema_version(t) != 1:
            return _record("p-table-schema-versions", "BREAK",
                           "table %s not pinned at v1" % t)
    # Unknown table version lookup refuses loud.
    try:
        Q.table_schema_version("nope")
    except Q.InventoryError:
        pass
    else:
        return _record("p-table-schema-versions", "BREAK",
                       "unknown table version lookup did not refuse")
    # Extension with a wrong schema version refuses fail-closed.
    class P(object):
        def table_names(self):
            return ["ext_t"]

        def fetch(self, table):
            return []
    try:
        Q.QueryRegistry().register_extension("ext_t", 999, P())
    except Q.InventoryError:
        pass
    else:
        return _record("p-table-schema-versions", "BREAK",
                       "wrong schema version accepted")
    _record("p-table-schema-versions", "HELD",
            "4 core tables at pinned v1; unknown/wrong refused")


def p_row_digest_binding():
    Q = _require_module("p-row-digest-binding")
    if Q is None:
        return
    r1 = {"agent_id": "a1", "name": "red"}
    r2 = dict(r1)
    r3 = {"agent_id": "a1", "name": "blue"}
    d1 = Q.row_digest(r1)
    if d1 != Q.row_digest(r2) or d1 == Q.row_digest(r3):
        return _record("p-row-digest-binding", "BREAK",
                       "digest does not bind content")
    # A pre-seeded row_digest key is not trusted: recomputed.
    r4 = {"agent_id": "a1", "name": "red", "row_digest": "forged"}
    if Q.row_digest(r4) != d1:
        return _record("p-row-digest-binding", "BREAK",
                       "row_digest key not recomputed")
    # Malformed rows refuse loud.
    for bad in ("not-a-row", {"agent_id": 1.5, "name": object()}):
        try:
            Q.row_digest(bad)
        except Q.InventoryError:
            pass
        else:
            return _record("p-row-digest-binding", "BREAK",
                           "malformed row accepted: %r" % (bad,))
    _record("p-row-digest-binding", "HELD", "digests bind content; malformed refused")


def p_provider_extension_contract():
    Q = _require_module("p-provider-extension-contract")
    if Q is None:
        return
    class Good(object):
        def table_names(self):
            return ["ext_audit"]

        def fetch(self, table):
            if table != "ext_audit":
                raise AssertionError("closed API routed unknown table")
            return [{"agent_id": "a9", "note": "x"}]
    class Crashy(object):
        def table_names(self):
            return ["ext_crash"]

        def fetch(self, table):
            raise RuntimeError("boom")
    reg = Q.QueryRegistry()
    reg.register_extension("ext_audit", 1, Good())
    rows = reg.run_query({"table": "ext_audit", "where": {},
                          "columns": ["agent_id"]})
    if len(rows) != 1 or rows[0]["agent_id"] != "a9":
        return _record("p-provider-extension-contract", "BREAK",
                       "extension rows not queryable")
    # Unknown table fails closed loud.
    try:
        reg.run_query({"table": "no_such_table", "where": {}, "columns": []})
    except Q.InventoryError:
        pass
    else:
        return _record("p-provider-extension-contract", "BREAK",
                       "unknown table query did not refuse")
    # Provider crash fails closed loud (never silent empty).
    reg.register_extension("ext_crash", 1, Crashy())
    try:
        reg.run_query({"table": "ext_crash", "where": {}, "columns": []})
    except Q.InventoryError:
        pass
    else:
        return _record("p-provider-extension-contract", "BREAK",
                       "provider crash swallowed")
    # Unregistered table query on a fresh registry fails closed.
    try:
        Q.QueryRegistry().run_query(
            {"table": "ext_audit", "where": {}, "columns": []})
    except Q.InventoryError:
        pass
    else:
        return _record("p-provider-extension-contract", "BREAK",
                       "unregistered table query did not refuse")
    _record("p-provider-extension-contract", "HELD",
            "closed provider API; crash/unknown fail closed")


def p_unpinned_pack_refused():
    Q = _require_module("p-unpinned-pack-refused")
    if Q is None:
        return
    reg = _core_reg(Q)
    pack = {"pack_name": "guard", "queries": [
        {"name": "q1", "table": "agents", "where": {}, "columns": []}]}
    try:
        reg.run_query_pack(pack)
    except Q.InventoryPackUnpinned:
        pass
    else:
        return _record("p-unpinned-pack-refused", "BREAK",
                       "unpinned pack ran without refusal")
    # pin_query_pack fills pins from current results, then it runs clean.
    pinned = reg.pin_query_pack(pack)
    rep = reg.run_query_pack(pinned)
    if rep["queries"][0]["drifted"] or rep["queries"][0]["unregistered"]:
        return _record("p-unpinned-pack-refused", "BREAK",
                       "freshly pinned pack not clean")
    _record("p-unpinned-pack-refused", "HELD",
            "unpinned pack refused loud; pin then clean")


def p_pack_drift_hold():
    Q = _require_module("p-pack-drift-hold")
    if Q is None:
        return
    reg = _core_reg(Q)
    pack = reg.pin_query_pack({"pack_name": "guard", "queries": [
        {"name": "q1", "table": "agents", "where": {}, "columns": []}]})
    # Drift: the same identity with changed content (new digest).
    reg.register_table_rows("agents", [{"agent_id": "a1", "name": "red",
                                       "trust_tier": "HIGH"}])
    rep = reg.run_query_pack(pack)
    q = rep["queries"][0]
    if len(q["drifted"]) != 1 or q["unregistered"]:
        return _record("p-pack-drift-hold", "BREAK",
                       "drift not classified: %r" % (q,))
    if not reg.held(("agents", "a1")):
        return _record("p-pack-drift-hold", "BREAK",
                       "drifted row not held")
    ok, code, _ = reg.check_use(("agents", "a1"))
    if ok or code != "inventory-pack-drift":
        return _record("p-pack-drift-hold", "BREAK",
                       "check_use not inventory-pack-drift: %r" % (code,))
    _record("p-pack-drift-hold", "HELD", "drift -> inventory-pack-drift hold")


def p_pack_unregistered_hold():
    Q = _require_module("p-pack-unregistered-hold")
    if Q is None:
        return
    reg = Q.QueryRegistry()
    pack = reg.pin_query_pack({"pack_name": "guard", "queries": [
        {"name": "q1", "table": "agents", "where": {}, "columns": []}]})
    # First sighting: a brand-new identity.
    reg.register_table_rows("agents", [{"agent_id": "a1", "name": "red"},
                                       {"agent_id": "a2", "name": "new"}])
    rep = reg.run_query_pack(pack)
    q = rep["queries"][0]
    if q["drifted"] or len(q["unregistered"]) != 2:
        return _record("p-pack-unregistered-hold", "BREAK",
                       "first sighting not unregistered: %r" % (q,))
    if not reg.held(reg.hold_key("agents", {"agent_id": "a2"})):
        return _record("p-pack-unregistered-hold", "BREAK",
                       "new row not held")
    ok, code, _ = reg.check_use(reg.hold_key("agents", {"agent_id": "a2"}))
    if ok or code != "inventory-unregistered":
        return _record("p-pack-unregistered-hold", "BREAK",
                       "check_use not inventory-unregistered: %r" % (code,))
    # Withdrawn: pinned identity absent from the scan.
    reg2 = Q.QueryRegistry()
    reg2.register_table_rows("agents", [{"agent_id": "a9", "name": "gone"}])
    pack2 = reg2.pin_query_pack({"pack_name": "g2", "queries": [
        {"name": "q1", "table": "agents", "where": {}, "columns": []}]})
    reg2.register_table_rows("agents", [])
    rep2 = reg2.run_query_pack(pack2)
    if len(rep2["queries"][0]["withdrawn"]) != 1:
        return _record("p-pack-unregistered-hold", "BREAK",
                       "withdrawal not reported")
    _record("p-pack-unregistered-hold", "HELD",
            "first sighting held; withdrawal reported")


def p_audit_plumbing():
    Q = _require_module("p-audit-plumbing")
    if Q is None:
        return
    reg = _core_reg(Q)
    events = []
    reg.set_emit(events.append)
    pack = reg.pin_query_pack({"pack_name": "guard", "queries": [
        {"name": "q1", "table": "agents", "where": {}, "columns": []}]})
    reg.register_table_rows("agents", [{"agent_id": "a1", "name": "RED",
                                        "trust_tier": "low"}])
    reg.run_query_pack(pack)
    if len(events) != 1 or events[0]["event"] != "inventory-pack-drift":
        return _record("p-audit-plumbing", "BREAK",
                       "hold event not emitted: %r" % (events,))
    if "RED" in str(events[0]):
        return _record("p-audit-plumbing", "BREAK",
                       "row content leaked into audit event")
    # Persistence: the hold survives a restart via snapshot+merge.
    snap = reg.holds_snapshot()
    reg2 = Q.QueryRegistry()
    reg2.merge_snapshot(json.loads(json.dumps(snap)))
    if not reg2.held(("agents", "a1")):
        return _record("p-audit-plumbing", "BREAK",
                       "hold did not survive snapshot merge")
    # Clean re-scan lifts the hold and reports it.
    reg.register_table_rows("agents", [{"agent_id": "a1", "name": "red",
                                        "trust_tier": "low"}])
    rep = reg.run_query_pack(pack)
    if reg.held(("agents", "a1")):
        return _record("p-audit-plumbing", "BREAK",
                       "clean re-scan did not lift hold")
    if len(rep["queries"][0]["released"]) != 1:
        return _record("p-audit-plumbing", "BREAK",
                       "release not reported")
    _record("p-audit-plumbing", "HELD",
            "emit digests-only; holds persist; clean re-scan lifts")


def p_deterministic():
    Q = _require_module("p-deterministic")
    if Q is None:
        return
    reg = _core_reg(Q)
    pack = reg.pin_query_pack({"pack_name": "guard", "queries": [
        {"name": "q1", "table": "agents", "where": {}, "columns": ["name"]}]})
    r1 = json.dumps(reg.run_query_pack(pack), sort_keys=True, default=str)
    r2 = json.dumps(reg.run_query_pack(pack), sort_keys=True, default=str)
    if r1 != r2:
        return _record("p-deterministic", "BREAK", "pack run not deterministic")
    _record("p-deterministic", "HELD", "pack runs deterministic")


def p_discovery_composition():
    Q = _require_module("p-discovery-composition")
    if Q is None:
        return
    try:
        from gov import discovery_scan as DS
    except ImportError:
        return _record("p-discovery-composition", "BREAK",
                       "gov.discovery_scan absent")
    inv = DS.DiscoveryInventory()
    inv.add({"scope": "system", "agent_host": "h1", "component_id": "c1",
             "component_type": "mcp_server", "source_path": "/srv/mcp",
             "definitions": [{"name": "t1", "description": "d",
                              "input_schema": {}}]})
    inv.add({"scope": "user", "agent_host": "h1", "component_id": "c2",
             "component_type": "skill", "source_path": "/home/s1",
             "definitions": [{"name": "s1", "description": "d",
                              "input_schema": {}}]})
    rows = Q.inventory_tables_from_discovery(inv)
    mcp = [r for r in rows if r[0] == "mcp_servers"]
    skills = [r for r in rows if r[0] == "skill_bundles"]
    agents = [r for r in rows if r[0] == "agents"]
    if len(mcp) != 1 or len(skills) != 1 or len(agents) != 1:
        return _record("p-discovery-composition", "BREAK",
                       "composition row counts wrong: %d/%d/%d"
                       % (len(mcp), len(skills), len(agents)))
    if agents[0][1].get("agent_id") != "h1":
        return _record("p-discovery-composition", "BREAK",
                       "agents projection missing agent_host identity")
    # Digest reuse: tool rows use discovery_scan.definition_digest
    # byte-for-byte (single digest seam, no second implementation).
    d = {"name": "t1", "description": "d", "input_schema": {}}
    if mcp[0][1]["definition_digest"] != DS.definition_digest(d):
        return _record("p-discovery-composition", "BREAK",
                       "digest seam duplicated")
    reg = Q.QueryRegistry()
    reg.register_core_tables_from_discovery(inv)
    q = reg.run_query({"table": "mcp_servers", "where": {"scope": "system"},
                       "columns": ["name"]})
    if len(q) != 1 or q[0]["name"] != "t1":
        return _record("p-discovery-composition", "BREAK",
                       "core tables not populated from inventory")
    _record("p-discovery-composition", "HELD",
            "inventory -> virtual tables; digest seam reused")


def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    checks = (["-m", "unittest", "tests.test_decision_codes"],)
    for argv in checks:
        r = subprocess.run([sys.executable] + argv,
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        tail = (r.stderr or r.stdout)[-200:].replace("\n", " | ")
        _record("green-check_" + os.path.basename(argv[-1]),
                "HELD" if r.returncode == 0 else "ERROR", tail)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_taxonomy_pin, p_module_present, p_table_schema_versions,
                  p_row_digest_binding, p_provider_extension_contract,
                  p_unpinned_pack_refused, p_pack_drift_hold,
                  p_pack_unregistered_hold, p_audit_plumbing,
                  p_deterministic, p_discovery_composition):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w283_osquery: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
