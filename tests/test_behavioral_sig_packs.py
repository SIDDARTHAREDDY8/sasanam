"""Unit tests: behavioral-signature v2 packs + correlator (wave-267).

Covers the module contract pinned by evals/w267_behsig_probes.py at a
finer grain: schema edges, comparator semantics, macro cycles,
enrichment classification, tuning floors, correlator cooldowns, and
determinism. The break-first battery owns the adversarial shapes;
these tests own the contract.
"""

import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import behavioral_sig_packs as bsp
from gov import decision_codes
from gov import ed25519

TAXONOMY_PIN = 1802  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)


def _keys():
    seed = ed25519.generate_seed()
    return seed, ed25519.publickey(seed)


def _sign_blob(pack, seed):
    canon = json.dumps(pack, sort_keys=True,
                       separators=(",", ":")).encode()
    sig = ed25519.sign(seed, canon).hex()
    return json.dumps({"pack": pack,
                       "signatures": [{"keyid": "k", "sig": sig}]}
                      ).encode()


def _rule(**kw):
    base = {"name": "t.r", "desc": "d",
            "condition": {"op": "eq", "field": "tool.action",
                          "value": "db.dump"},
            "output": "fired %tool.action%", "priority": "high",
            "enabled": True, "source": "agent_event", "tags": [],
            "maturity": "stable", "exceptions": [],
            "capture": {"window_events": 1}}
    base.update(kw)
    return base


def _pack(rules):
    return {"pack_format": "sasanam.behavioral-sig-pack/v1",
            "pack_id": "t", "pack_version": "1", "engine_version": "1",
            "macros": [], "lists": [], "rules": rules}


def _load(pack, seed=None, pub=None, **kw):
    seed = seed or _keys()[0]
    pub = pub or ed25519.publickey(seed)
    journal = kw.pop("journal", None)
    recs = []
    j = journal if journal is not None else recs.append
    loaded = bsp.load_pack(_sign_blob(pack, seed),
                           trust_keys={"k": pub}, journal=j, **kw)
    loaded.journal_records = recs
    return loaded


def _ev(**kw):
    base = {"ts": 1.0, "actor_id": "a", "principal": "a",
            "session_id": "s", "tool": "db.dump", "target": "t",
            "args": {}}
    base.update(kw)
    return bsp.enrich_event(base)


class TestSchema(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_duplicate_rule_name_refused(self):
        with self.assertRaises(bsp.PackRefused) as c:
            _load(_pack([_rule(), _rule()]))
        self.assertEqual(c.exception.code, "behsig-pack-malformed")

    def test_bad_priority_refused(self):
        with self.assertRaises(bsp.PackRefused):
            _load(_pack([_rule(priority="urgent")]))

    def test_bad_maturity_refused(self):
        with self.assertRaises(bsp.PackRefused):
            _load(_pack([_rule(maturity="alpha")]))

    def test_macro_cycle_refused(self):
        pack = _pack([_rule(condition={"macro": "m1"})])
        pack["macros"] = [
            {"name": "m1", "def": {"macro": "m2"}},
            {"name": "m2", "def": {"macro": "m1"}},
        ]
        with self.assertRaises(bsp.PackRefused) as c:
            _load(pack)
        self.assertEqual(c.exception.code, "behsig-pack-malformed")

    def test_macro_self_reference_refused(self):
        pack = _pack([_rule(condition={"macro": "m1"})])
        pack["macros"] = [{"name": "m1", "def": {"macro": "m1"}}]
        with self.assertRaises(bsp.PackRefused):
            _load(pack)

    def test_unknown_macro_ref_refused(self):
        with self.assertRaises(bsp.PackRefused):
            _load(_pack([_rule(condition={"macro": "nope"})]))

    def test_not_a_json_object_refused(self):
        seed, pub = _keys()
        with self.assertRaises(bsp.PackRefused) as c:
            bsp.load_pack(b"[1,2]", trust_keys={"k": pub})
        self.assertEqual(c.exception.code, "behsig-pack-malformed")

    def test_wrong_pack_format_refused(self):
        pack = _pack([_rule()])
        pack["pack_format"] = "something-else/v9"
        with self.assertRaises(bsp.PackRefused):
            _load(pack)


class TestTrust(unittest.TestCase):
    def test_wrong_key_refused(self):
        seed1, _ = _keys()
        _, pub2 = _keys()
        with self.assertRaises(bsp.PackRefused) as c:
            bsp.load_pack(_sign_blob(_pack([_rule()]), seed1),
                          trust_keys={"k": pub2})
        self.assertEqual(c.exception.code, "behsig-pack-untrusted")

    def test_unsigned_always_refused_no_hatch(self):
        # There is no unsigned path: an envelope without signatures
        # is refused fail-closed even with trust material configured.
        seed, pub = _keys()
        blob = json.dumps({"pack": _pack([_rule()]),
                           "signatures": []}).encode()
        with self.assertRaises(bsp.PackRefused) as c:
            bsp.load_pack(blob, trust_keys={"k": pub})
        self.assertEqual(c.exception.code, "behsig-pack-untrusted")

    def test_engine_version_gate(self):
        pack = _pack([_rule()])
        pack["engine_version"] = "999"
        with self.assertRaises(bsp.PackRefused) as c:
            _load(pack)
        self.assertEqual(c.exception.code, "behsig-pack-malformed")


class TestMatching(unittest.TestCase):
    def test_comparators(self):
        ev = _ev()
        cases = [
            ({"op": "eq", "field": "tool.action",
              "value": "db.dump"}, True),
            ({"op": "ne", "field": "tool.action",
              "value": "db.dump"}, False),
            ({"op": "in", "field": "tool.action",
              "values": ["db.dump", "x"]}, True),
            ({"op": "nin", "field": "tool.action",
              "values": ["db.dump", "x"]}, False),
            ({"op": "contains", "field": "tool.target",
              "value": "t"}, True),
            ({"op": "startswith", "field": "tool.action",
              "value": "db."}, True),
            ({"op": "gt", "field": "ts", "value": 0.5}, True),
            ({"op": "lt", "field": "ts", "value": 0.5}, False),
            ({"op": "and", "args": [
                {"op": "eq", "field": "tool.action",
                 "value": "db.dump"},
                {"op": "not", "arg": {
                    "op": "eq", "field": "principal",
                    "value": "nobody"}}]}, True),
        ]
        for cond, want in cases:
            rule = _rule(condition=cond)
            loaded = _load(_pack([rule]))
            alerts = bsp.match_pack(loaded, [ev])
            self.assertEqual(bool(alerts), want, cond)

    def test_exception_tuple_and_semantics(self):
        # Author-shaped tuple: BOTH triples must hold to except.
        rule = _rule(exceptions=[
            {"and": [
                {"field": "principal", "comparator": "eq",
                 "value": "svc-a"},
                {"field": "tool.target", "comparator": "eq",
                 "value": "tgt"},
            ]}])
        loaded = _load(_pack([rule]))
        both = _ev(principal="svc-a", target="tgt")
        partial = _ev(principal="svc-a", target="other")
        self.assertEqual(bsp.match_pack(loaded, [both]), [])
        self.assertEqual(len(bsp.match_pack(loaded, [partial])), 1)

    def test_tuning_novel_shape_refused(self):
        loaded = _load(_pack([_rule()]))
        with self.assertRaises(bsp.PackRefused) as c:
            bsp.apply_tuning(
                loaded,
                {"pack_id": "t",
                 "rule_tuning": {
                     "t.r": {"exceptions_add": [
                         {"and": [{"field": "principal",
                                   "comparator": "ne",
                                   "value": "x"}]}]}}})
        self.assertEqual(c.exception.code, "behsig-tuning-rejected")

    def test_tuning_unknown_field_refused(self):
        rule = _rule(exceptions=[
            {"and": [{"field": "principal", "comparator": "eq",
                      "value": "svc-a"}]}])
        loaded = _load(_pack([rule]))
        with self.assertRaises(bsp.PackRefused) as c:
            bsp.apply_tuning(
                loaded,
                {"pack_id": "t",
                 "rule_tuning": {
                     "t.r": {"exceptions_add": [
                         {"and": [{"field": "principal",
                                   "comparator": "eq",
                                   "value": "svc-b"},
                                  {"field": "proc.nope",
                                   "comparator": "ne",
                                   "value": "z"}]}]}}})
        self.assertEqual(c.exception.code, "behsig-tuning-rejected")

    def test_tuning_declared_shape_values_allowed(self):
        rule = _rule(exceptions=[
            {"and": [{"field": "principal", "comparator": "eq",
                      "value": "svc-a"}]}])
        loaded = _load(_pack([rule]))
        tuned = bsp.apply_tuning(
            loaded,
            {"pack_id": "t",
             "rule_tuning": {
                 "t.r": {"exceptions_add": [
                     {"and": [{"field": "principal",
                               "comparator": "eq",
                               "value": "svc-b"}]}]}}})
        self.assertEqual(
            bsp.match_pack(tuned, [_ev(principal="svc-b")]), [])
        self.assertEqual(
            len(bsp.match_pack(tuned, [_ev(principal="svc-c")])), 1)

    def test_raw_event_never_matched(self):
        loaded = _load(_pack([_rule()]))
        with self.assertRaises(ValueError):
            bsp.match_pack(loaded, [{"tool": "db.dump", "ts": 1.0}])

    def test_output_interpolation(self):
        loaded = _load(_pack([_rule()]))
        alerts = bsp.match_pack(loaded, [_ev()])
        self.assertEqual(alerts[0].output, "fired db.dump")

    def test_enrichment_arg_classes(self):
        self.assertEqual(
            _ev(args={"password": "x"})["arg.class"], "credential")
        self.assertEqual(
            _ev(tool="file.export")["arg.class"], "export")
        self.assertEqual(
            _ev(tool="net.egress")["arg.class"], "network")
        self.assertEqual(
            _ev(tool="file.write")["arg.class"], "file_write")
        # Default _ev uses tool="db.dump" (an export action); a plain
        # read with no credential keys classifies benign.
        self.assertEqual(
            _ev(tool="file.read")["arg.class"], "benign")

    def test_malformed_event_raises_loudly(self):
        with self.assertRaises(ValueError):
            bsp.enrich_event({"tool": "db.dump"})  # no ts
        with self.assertRaises(ValueError):
            bsp.enrich_event("not-a-dict")


class TestTuning(unittest.TestCase):
    def test_raising_min_floor_allowed(self):
        loaded = _load(_pack([_rule(params={"min_n": 5})]))
        tuned = bsp.apply_tuning(
            loaded,
            {"pack_id": "t",
             "rule_tuning": {"t.r": {"params": {"min_n": 9}}}})
        self.assertEqual(tuned.rules["t.r"].params["min_n"], 9)
        # Original pack untouched: packs are never edited in place.
        self.assertEqual(loaded.rules["t.r"].params["min_n"], 5)

    def test_unknown_tuning_key_refused(self):
        loaded = _load(_pack([_rule()]))
        with self.assertRaises(bsp.PackRefused) as c:
            bsp.apply_tuning(
                loaded,
                {"pack_id": "t",
                 "rule_tuning": {"t.r": {"nuke": True}}})
        self.assertEqual(c.exception.code, "behsig-tuning-rejected")

    def test_pack_id_mismatch_refused(self):
        loaded = _load(_pack([_rule()]))
        with self.assertRaises(bsp.PackRefused):
            bsp.apply_tuning(loaded, {"pack_id": "other",
                                      "rule_tuning": {}})

    def test_nonsandbox_disable_without_justification_allowed(self):
        loaded = _load(_pack([_rule(maturity="incubating")]))
        recs = []
        tuned = bsp.apply_tuning(
            loaded,
            {"pack_id": "t",
             "rule_tuning": {"t.r": {"disable": True}}},
            journal=recs.append)
        self.assertNotIn("t.r", tuned.rules)
        self.assertTrue(any(r["code"] == "behsig-tuning-applied"
                            for r in recs))


class TestCorrelator(unittest.TestCase):
    def _corr(self, **kw):
        recs = []
        queued = []
        cfg = {"burst": {"window_s": 60, "min_events": 3}}
        cfg.update(kw.pop("config", {}))
        corr = bsp.StatefulCorrelator(cfg, journal=recs.append,
                                      queue=queued.append, **kw)
        return corr, recs, queued

    def test_burst_cooldown(self):
        corr, recs, _ = self._corr()
        out = []
        for i in range(8):
            out.extend(corr.observe(_ev(ts=float(i)), []))
        # First fire at 3 events; cooldown suppresses the rest.
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].kind, "burst")

    def test_fire_storm_counts_alerts_not_events(self):
        corr, _, _ = self._corr(
            config={"fire_storm": {"window_s": 300, "min_fires": 2}})
        loaded = _load(_pack([_rule()]))
        out = []
        for i in range(3):
            ev = _ev(ts=float(i) * 100.0)
            alerts = bsp.match_pack(loaded, [ev])
            out.extend(corr.observe(ev, alerts))
        self.assertTrue(any(a.kind == "fire_storm" for a in out))

    def test_queue_request_is_never_a_deny(self):
        corr, _, queued = self._corr()
        for i in range(4):
            corr.observe(_ev(ts=float(i)), [])
        self.assertTrue(queued)
        for q in queued:
            self.assertEqual(q["decision"], "hold-request")
            self.assertNotEqual(q.get("decision"), "deny")

    def test_bad_config_refused(self):
        with self.assertRaises(bsp.PackRefused):
            bsp.StatefulCorrelator(
                {"burst": {"window_s": -1, "min_events": 3}})

    def test_deterministic(self):
        def run():
            corr, _, _ = self._corr()
            out = []
            for i in range(5):
                out.extend(corr.observe(_ev(ts=float(i)), []))
            return [(a.kind, a.actor_id, a.detail) for a in out]
        self.assertEqual(run(), run())

    def test_journal_carries_digests_not_raw_args(self):
        corr, recs, _ = self._corr()
        for i in range(4):
            corr.observe(_ev(ts=float(i),
                             args={"password": "hunter2"}), [])
        self.assertTrue(recs)
        blob = json.dumps(recs)
        self.assertNotIn("hunter2", blob)


if __name__ == "__main__":
    unittest.main()
