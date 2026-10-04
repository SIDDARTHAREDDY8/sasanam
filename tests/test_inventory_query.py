"""Unit tests for gov/inventory_query.py (wave-283 lane 6, osquery STEAL).

Seams pinned: schema versioning, digest binding, provider plug-in
contract, query packs (drift=fail-closed), discovery composition,
use-time holds.
"""
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from gov import decision_codes  # noqa: E402
from gov import inventory_query as IQ  # noqa: E402


def _reg():
    reg = IQ.QueryRegistry()
    reg.register_table_rows("agents", [
        {"agent_id": "a1", "name": "red", "trust_tier": "low"},
        {"agent_id": "a2", "name": "blue", "trust_tier": "high"},
    ])
    return reg


class SchemaVersionTest(unittest.TestCase):
    def test_core_tables_at_pinned_v1(self):
        for table in IQ.CORE_TABLES:
            self.assertEqual(IQ.table_schema_version(table), 1)
        self.assertEqual(IQ.PINNED_SCHEMA_VERSION, 1)

    def test_unknown_table_refused(self):
        with self.assertRaises(IQ.InventoryError) as ctx:
            IQ.table_schema_version("nope")
        self.assertIn("inventory-schema-mismatch", str(ctx.exception))

    def test_extension_wrong_schema_version_refused(self):
        reg = _reg()
        prov = _DictProvider({"t": [{"k": "v"}]})
        with self.assertRaises(IQ.InventoryError) as ctx:
            reg.register_extension("t", 999, prov)
        self.assertIn("inventory-schema-mismatch", str(ctx.exception))

    def test_core_table_shadow_refused(self):
        reg = _reg()
        with self.assertRaises(IQ.InventoryError) as ctx:
            reg.register_extension("agents", 1, _DictProvider({}))
        self.assertIn("inventory-schema-mismatch", str(ctx.exception))


class RowDigestTest(unittest.TestCase):
    def test_digest_binds_content(self):
        d1 = IQ.row_digest({"a": 1, "b": 2})
        d2 = IQ.row_digest({"b": 2, "a": 1})
        d3 = IQ.row_digest({"a": 1, "b": 3})
        self.assertEqual(d1, d2)  # key order irrelevant
        self.assertNotEqual(d1, d3)
        self.assertEqual(len(d1), 64)

    def test_preseeded_digest_recomputed_not_trusted(self):
        reg = IQ.QueryRegistry()
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "x", "row_digest": "00" * 32}])
        rows = reg.run_query({"table": "agents", "where": {}})
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0]["row_digest"], "00" * 32)
        self.assertEqual(rows[0]["row_digest"],
                         IQ.row_digest({"agent_id": "a1", "name": "x"}))

    def test_non_json_value_refused(self):
        with self.assertRaises(IQ.InventoryError) as ctx:
            IQ.row_digest({"a": object()})
        self.assertIn("inventory-row-malformed", str(ctx.exception))

    def test_undeclared_column_refused(self):
        reg = _reg()
        with self.assertRaises(IQ.InventoryError) as ctx:
            reg.register_table_rows(
                "agents", [{"agent_id": "a9", "name": "x",
                            "nope_col": 1}])
        self.assertIn("inventory-row-malformed", str(ctx.exception))

    def test_missing_identity_column_refused(self):
        reg = _reg()
        with self.assertRaises(IQ.InventoryError) as ctx:
            reg.register_table_rows("agents", [{"name": "x"}])
        self.assertIn("inventory-row-malformed", str(ctx.exception))


class _DictProvider(object):
    def __init__(self, tables):
        self._tables = tables

    def table_names(self):
        return list(self._tables)

    def fetch(self, table_name):
        return self._tables[table_name]


class _CrashProvider(object):
    def table_names(self):
        return ["boom"]

    def fetch(self, table_name):
        raise RuntimeError("boom")


class ProviderContractTest(unittest.TestCase):
    def test_extension_query_works(self):
        reg = _reg()
        reg.register_extension("ext_t", 1, _DictProvider(
            {"ext_t": [{"k": "v1"}, {"k": "v2"}]}))
        rows = reg.run_query({"table": "ext_t", "where": {}})
        self.assertEqual(len(rows), 2)
        self.assertEqual(reg.registered_schema_version("ext_t"), 1)

    def test_provider_crash_fails_closed(self):
        reg = _reg()
        reg.register_extension("boom", 1, _CrashProvider())
        with self.assertRaises(IQ.InventoryError) as ctx:
            reg.run_query({"table": "boom", "where": {}})
        self.assertIn("inventory-provider-failed", str(ctx.exception))

    def test_provider_bad_table_list_refused(self):
        reg = _reg()
        bad = _DictProvider({})
        bad.table_names = lambda: "not-a-list"
        with self.assertRaises(IQ.InventoryError):
            reg.register_extension("t", 1, bad)

    def test_provider_missing_api_refused(self):
        reg = _reg()
        with self.assertRaises(IQ.InventoryError):
            reg.register_extension("t", 1, object())

    def test_provider_non_list_rows_refused(self):
        reg = _reg()
        reg.register_extension("t", 1, _DictProvider({"t": "nope"}))
        with self.assertRaises(IQ.InventoryError) as ctx:
            reg.run_query({"table": "t", "where": {}})
        self.assertIn("inventory-provider-failed", str(ctx.exception))


class QueryPackTest(unittest.TestCase):
    def _pack(self):
        return {"pack_name": "p", "queries": [
            {"name": "q", "table": "agents", "where": {}, "columns": []}]}

    def test_unpinned_pack_refused_loud(self):
        reg = _reg()
        with self.assertRaises(IQ.InventoryPackUnpinned):
            reg.run_query_pack(self._pack())

    def test_pin_then_clean(self):
        reg = _reg()
        pack = reg.pin_query_pack(self._pack())
        rep = reg.run_query_pack(pack)
        self.assertEqual(rep["held"], [])
        self.assertEqual(rep["queries"][0]["clean"], 2)

    def test_drift_held(self):
        reg = _reg()
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red", "trust_tier": "low"},
            {"agent_id": "a2", "name": "BLUE", "trust_tier": "high"},
        ])
        rep = reg.run_query_pack(pack)
        self.assertEqual(len(rep["queries"][0]["drifted"]), 1)
        self.assertTrue(reg.held(reg.hold_key("agents", {"agent_id": "a2"})))
        ok, code, _ = reg.check_use(reg.hold_key("agents", {"agent_id": "a2"}))
        self.assertFalse(ok)
        self.assertEqual(code, "inventory-pack-drift")
        # Non-held row is fine.
        ok2, _, _ = reg.check_use(reg.hold_key("agents", {"agent_id": "a1"}))
        self.assertTrue(ok2)

    def test_unregistered_first_sighting_held(self):
        reg = IQ.QueryRegistry()
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [{"agent_id": "n1", "name": "new"}])
        rep = reg.run_query_pack(pack)
        self.assertEqual(len(rep["queries"][0]["unregistered"]), 1)
        ok, code, _ = reg.check_use(reg.hold_key("agents", {"agent_id": "n1"}))
        self.assertFalse(ok)
        self.assertEqual(code, "inventory-unregistered")

    def test_withdrawn_reported_pin_stands(self):
        reg = _reg()
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [])
        rep = reg.run_query_pack(pack)
        self.assertEqual(len(rep["queries"][0]["withdrawn"]), 2)
        self.assertEqual(rep["held"], [])  # withdrawn is not a hold

    def test_release_hold(self):
        reg = _reg()
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red", "trust_tier": "low"},
            {"agent_id": "a2", "name": "BLUE", "trust_tier": "high"},
        ])
        reg.run_query_pack(pack)
        reg.release_hold(reg.hold_key("agents", {"agent_id": "a2"}))
        self.assertFalse(reg.held(reg.hold_key("agents", {"agent_id": "a2"})))
        ok, _, _ = reg.check_use(reg.hold_key("agents", {"agent_id": "a2"}))
        self.assertTrue(ok)

    def test_pack_run_deterministic(self):
        import json
        reg = _reg()
        pack = reg.pin_query_pack(self._pack())
        r1 = json.dumps(reg.run_query_pack(pack), sort_keys=True,
                        default=str)
        r2 = json.dumps(reg.run_query_pack(pack), sort_keys=True,
                        default=str)
        self.assertEqual(r1, r2)

    def test_snapshot_semantics(self):
        # Re-registering replaces: a second full scan drops old rows.
        reg = _reg()
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red"}])
        rows = reg.run_query({"table": "agents", "where": {}})
        self.assertEqual(len(rows), 1)


class WhereClauseTest(unittest.TestCase):
    def test_equality_in_prefix(self):
        reg = _reg()
        q = {"table": "agents", "where": {"trust_tier": "low"},
             "columns": ["agent_id"]}
        self.assertEqual(len(reg.run_query(q)), 1)
        q2 = {"table": "agents",
              "where": {"agent_id": {"in": ["a1", "a2"]}}, "columns": []}
        self.assertEqual(len(reg.run_query(q2)), 2)
        q3 = {"table": "agents", "where": {"name": {"prefix": "bl"}},
              "columns": []}
        self.assertEqual(len(reg.run_query(q3)), 1)

    def test_bad_where_refused(self):
        reg = _reg()
        with self.assertRaises(IQ.InventoryError):
            reg.run_query({"table": "agents",
                           "where": {"name": {"regex": "x"}},
                           "columns": []})

    def test_unknown_column_in_query_refused(self):
        reg = _reg()
        with self.assertRaises(IQ.InventoryError) as ctx:
            reg.run_query({"table": "agents", "where": {"zzz": 1},
                           "columns": []})
        self.assertIn("inventory-schema-mismatch", str(ctx.exception))


class DiscoveryCompositionTest(unittest.TestCase):
    def test_projection_and_digest_seam(self):
        from gov import discovery_scan as DS
        inv = DS.DiscoveryInventory()
        inv.add({"scope": "system", "agent_host": "h1",
                 "component_id": "c1", "component_type": "mcp_server",
                 "source_path": "/srv/mcp",
                 "definitions": [{"name": "t1", "description": "d",
                                  "input_schema": {}}]})
        inv.add({"scope": "user", "agent_host": "h1",
                 "component_id": "c2", "component_type": "skill",
                 "source_path": "/home/s1",
                 "definitions": [{"name": "s1", "description": "d",
                                  "input_schema": {}}]})
        rows = IQ.inventory_tables_from_discovery(inv)
        tables = {}
        for tname, row in rows:
            tables.setdefault(tname, []).append(row)
        self.assertEqual(len(tables["mcp_servers"]), 1)
        self.assertEqual(len(tables["skill_bundles"]), 1)
        # Single digest seam: byte-for-byte the discovery digest.
        mcp_row = tables["mcp_servers"][0]
        self.assertEqual(mcp_row["definition_digest"],
                         DS.definition_digest(
                             {"name": "t1", "description": "d",
                              "input_schema": {}}))
        # Projected rows register cleanly into the core tables.
        reg = IQ.QueryRegistry()
        reg.register_core_tables_from_discovery(inv)
        self.assertEqual(len(reg.run_query(
            {"table": "mcp_servers", "where": {}})), 1)


class TaxonomyTest(unittest.TestCase):
    def test_inventory_codes_registered(self):
        for code in ("inventory-pack-drift", "inventory-pack-unpinned",
                     "inventory-provider-failed",
                     "inventory-row-malformed", "inventory-schema-mismatch",
                     "inventory-unregistered"):
            self.assertIn(code, decision_codes.TAXONOMY)
        self.assertEqual(len(decision_codes.TAXONOMY), 2027)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)

    def test_no_duplicate_code_literals(self):
        import re
        src = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8").read()
        for code in ("inventory-pack-drift", "inventory-pack-unpinned",
                     "inventory-provider-failed",
                     "inventory-row-malformed", "inventory-schema-mismatch",
                     "inventory-unregistered"):
            self.assertEqual(len(re.findall(
                r'"code":\s*\'%s\'' % re.escape(code), src)), 1,
                "code %r duplicated in source" % code)


class AuditPlumbingTest(unittest.TestCase):
    def _pack(self):
        return {"pack_name": "p", "queries": [
            {"name": "q", "table": "agents", "where": {}, "columns": []}]}

    def test_hold_events_emitted_digests_only(self):
        reg = _reg()
        events = []
        reg.set_emit(events.append)
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red", "trust_tier": "low"},
            {"agent_id": "a2", "name": "BLUE", "trust_tier": "high"},
        ])
        reg.run_query_pack(pack)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "inventory-pack-drift")
        self.assertEqual(ev["table"], "agents")
        self.assertNotIn("BLUE", str(ev))  # content never reaches the log
        self.assertIn("before_digest", ev)
        self.assertIn("after_digest", ev)

    def test_emit_never_breaks_run(self):
        reg = _reg()
        def _boom(event):
            raise RuntimeError("sink down")
        reg.set_emit(_boom)
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red", "trust_tier": "low"},
            {"agent_id": "a2", "name": "BLUE", "trust_tier": "high"},
        ])
        rep = reg.run_query_pack(pack)  # must not raise
        self.assertEqual(len(rep["queries"][0]["drifted"]), 1)

    def test_holds_snapshot_merge_roundtrip(self):
        import json
        reg = _reg()
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red", "trust_tier": "low"},
            {"agent_id": "a2", "name": "BLUE", "trust_tier": "high"},
        ])
        reg.run_query_pack(pack)
        snap = reg.holds_snapshot()
        json.dumps(snap)  # JSON-serializable
        reg2 = IQ.QueryRegistry()
        reg2.merge_snapshot(snap)
        # The hold survives the restart.
        self.assertTrue(reg2.held(reg2.hold_key("agents", {"agent_id": "a2"})))
        ok, code, _ = reg2.check_use(reg2.hold_key("agents", {"agent_id": "a2"}))
        self.assertFalse(ok)
        self.assertEqual(code, "inventory-pack-drift")

    def test_merge_malformed_snapshot_refused(self):
        reg = IQ.QueryRegistry()
        with self.assertRaises(IQ.InventoryError):
            reg.merge_snapshot({"held": "nope"})
        with self.assertRaises(IQ.InventoryError):
            reg.merge_snapshot({"held": [
                {"table": "agents", "identity": {"agent_id": "a1"},
                 "code": "bogus-code"}]})
        with self.assertRaises(IQ.InventoryError):
            reg.merge_snapshot({"held": [
                {"table": "nope", "identity": {"agent_id": "a1"},
                 "code": "inventory-pack-drift"}]})

    def test_clean_rescan_lifts_hold(self):
        reg = _reg()
        pack = reg.pin_query_pack(self._pack())
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red", "trust_tier": "low"},
            {"agent_id": "a2", "name": "BLUE", "trust_tier": "high"},
        ])
        rep1 = reg.run_query_pack(pack)
        self.assertTrue(reg.held(reg.hold_key("agents", {"agent_id": "a2"})))
        # Row returns to pinned content: the next scheduled run lifts
        # the hold and reports it.
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "red", "trust_tier": "low"},
            {"agent_id": "a2", "name": "blue", "trust_tier": "high"},
        ])
        rep2 = reg.run_query_pack(pack)
        self.assertFalse(reg.held(reg.hold_key("agents", {"agent_id": "a2"})))
        self.assertEqual(len(rep2["queries"][0]["released"]), 1)

    def test_unpinned_pack_carries_machine_code(self):
        reg = _reg()
        try:
            reg.run_query_pack(self._pack())
        except IQ.InventoryPackUnpinned as e:
            self.assertIn("inventory-pack-unpinned", str(e))
        else:
            self.fail("InventoryPackUnpinned not raised")


if __name__ == "__main__":
    unittest.main()
