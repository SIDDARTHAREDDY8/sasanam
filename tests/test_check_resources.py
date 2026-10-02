"""Unit tests for gov/check_resources.py (Cerbos ADAPT).

Seams under test: compile_bundle (load-time validation + shadow
analysis), CheckResources.check (per-action decisions with
matched-policy provenance), the decision-record wire (chained at
decision time), and the offline verifiers. No mocks of internals:
every test goes through the public contract.
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w280-cr-units")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import check_resources as cr
from gov.log import ActionLog


def _fresh_log():
    d = tempfile.mkdtemp(prefix="cr_units_", dir=os.environ["TMPDIR"])
    return ActionLog(os.path.join(d, "audit.jsonl"))


def _bundle(**over):
    b = {
        "bundle_version": "1",
        "policy_version": "2026-10-02",
        "derived_roles": [
            {"name": "owner",
             "when": [{"subject": "resource.attr.owner", "op": "eq",
                       "ref": "principal.id"}]},
        ],
        "rules": [
            {"id": "read-own", "resource_kind": "document",
             "actions": ["read"], "roles": ["owner"], "effect": "allow",
             "reason": "owners read", "conditions": []},
            {"id": "write-own", "resource_kind": "document",
             "actions": ["write"], "roles": ["owner"], "effect": "allow",
             "reason": "owners write", "conditions": [
                 {"subject": "context.quota_ok", "op": "eq", "value": True}]},
        ],
    }
    b.update(over)
    return b


def _req(**over):
    r = {
        "request_id": "r1",
        "principal": {"id": "alice", "roles": ["viewer"], "attrs": {}},
        "resource": {"kind": "document", "id": "d1",
                     "attrs": {"owner": "alice"}},
        "actions": ["read"],
        "context": {"quota_ok": True},
    }
    if "actions" in over:
        over = dict(over, actions=list(over["actions"]))
    if "roles" in over:
        over = dict(over, roles=list(over["roles"]))
    r.update(over)
    return r


class CompileTest(unittest.TestCase):
    def test_valid_bundle_compiles(self):
        c = cr.compile_bundle(_bundle())
        self.assertEqual(len(c["rules"]), 2)
        self.assertEqual(c["policy_version"], "2026-10-02")

    def test_non_dict_bundle_refuses(self):
        with self.assertRaises(cr.BundleCompileError):
            cr.compile_bundle(["not", "a", "dict"])

    def test_shadow_by_wildcard_actions(self):
        b = _bundle()
        b["rules"] = [
            {"id": "all-doc", "resource_kind": "document", "actions": ["*"],
             "roles": [], "effect": "allow", "reason": "x", "conditions": []},
            {"id": "read-doc", "resource_kind": "document",
             "actions": ["read"], "roles": [], "effect": "deny",
             "reason": "x", "conditions": []},
        ]
        with self.assertRaises(cr.BundleCompileError) as cm:
            cr.compile_bundle(b)
        self.assertIn("read-doc", str(cm.exception))

    def test_no_shadow_different_kind(self):
        b = _bundle()
        b["rules"] = [
            {"id": "a", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "allow", "reason": "x", "conditions": []},
            {"id": "b", "resource_kind": "photo", "actions": ["read"],
             "roles": [], "effect": "deny", "reason": "x", "conditions": []},
        ]
        cr.compile_bundle(b)  # must not raise

    def test_no_shadow_narrower_earlier_with_condition(self):
        # The EARLIER rule carries the narrower condition, so the
        # later unconditional rule still fires on requests the earlier
        # misses -- no shadow.
        b = _bundle()
        b["rules"] = [
            {"id": "a", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "allow", "reason": "x", "conditions": [
                 {"subject": "context.vip", "op": "eq", "value": True}]},
            {"id": "b", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "deny", "reason": "x", "conditions": []},
        ]
        cr.compile_bundle(b)  # a misses some requests -> b can fire

    def test_condition_implication_triggers_shadow(self):
        b = _bundle()
        b["rules"] = [
            {"id": "a", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "allow", "reason": "x", "conditions": [
                 {"subject": "context.vip", "op": "eq", "value": True}]},
            {"id": "b", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "deny", "reason": "x", "conditions": [
                 {"subject": "context.vip", "op": "eq", "value": True},
                 {"subject": "context.quota_ok", "op": "eq",
                  "value": True}]},
        ]
        with self.assertRaises(cr.BundleCompileError):
            cr.compile_bundle(b)

    def test_error_names_rule_id(self):
        b = _bundle()
        b["rules"] = [
            {"id": "x", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "allow", "reason": "x", "conditions": []},
            {"id": "y", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "allow", "reason": "x", "conditions": []},
        ]
        with self.assertRaises(cr.BundleCompileError) as cm:
            cr.compile_bundle(b)
        self.assertEqual(cm.exception.rule_id, "y")

    def test_duplicate_derived_role_name(self):
        b = _bundle()
        b["derived_roles"] = [dict(b["derived_roles"][0]),
                              dict(b["derived_roles"][0])]
        with self.assertRaises(cr.BundleCompileError):
            cr.compile_bundle(b)


class CheckTest(unittest.TestCase):
    def test_first_match_wins(self):
        # "second" must be fireable (the shadow analysis refuses dead
        # rules): give the EARLIER rule the narrower condition so a
        # request that misses it reaches the later rule.
        b = _bundle()
        b["rules"] = [
            {"id": "first", "resource_kind": "document", "actions": ["read"],
             "roles": [], "effect": "deny", "reason": "first wins",
             "conditions": [
                 {"subject": "context.mode", "op": "eq",
                  "value": "strict"}]},
            {"id": "second", "resource_kind": "document",
             "actions": ["read"], "roles": [], "effect": "allow",
             "reason": "fallback", "conditions": []},
        ]
        pdp = cr.CheckResources(cr.compile_bundle(b), _fresh_log())
        req = _req()
        req["context"] = {"mode": "strict"}
        self.assertEqual(pdp.check(req).results["read"].effect, "deny")
        self.assertEqual(
            pdp.check(req).results["read"].matched_rule_id, "first")
        req["context"] = {"mode": "lax"}
        d = pdp.check(req).results["read"]
        self.assertEqual(d.effect, "allow")
        self.assertEqual(d.matched_rule_id, "second")

    def test_condition_gate(self):
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), _fresh_log())
        req = _req(actions=["write"])
        req["context"] = {"quota_ok": False}
        d = pdp.check(req).results["write"]
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.matched_rule_id, "default_deny")

    def test_missing_condition_attr_fails_closed(self):
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), _fresh_log())
        req = _req(actions=["write"])
        req["context"] = {}
        d = pdp.check(req).results["write"]
        self.assertEqual(d.effect, "deny")

    def test_cross_ref_derived_role_context(self):
        b = _bundle()
        b["derived_roles"] = [
            {"name": "same_team",
             "when": [{"subject": "principal.attr.team", "op": "eq",
                       "ref": "resource.attr.team"}]},
        ]
        b["rules"] = [
            {"id": "team-read", "resource_kind": "document",
             "actions": ["read"], "roles": ["same_team"], "effect": "allow",
             "reason": "team", "conditions": []},
        ]
        pdp = cr.CheckResources(cr.compile_bundle(b), _fresh_log())
        req = _req()
        req["principal"]["attrs"] = {"team": "red"}
        req["resource"]["attrs"] = {"team": "red"}
        self.assertEqual(pdp.check(req).results["read"].effect, "allow")
        req["resource"]["attrs"] = {"team": "blue"}
        self.assertEqual(pdp.check(req).results["read"].effect, "deny")

    def test_in_op(self):
        b = _bundle()
        b["rules"] = [
            {"id": "env-ok", "resource_kind": "document",
             "actions": ["read"], "roles": [], "effect": "allow",
             "reason": "env", "conditions": [
                 {"subject": "context.env", "op": "in",
                  "value": ["prod", "staging"]}]},
        ]
        pdp = cr.CheckResources(cr.compile_bundle(b), _fresh_log())
        req = _req()
        req["context"] = {"env": "prod"}
        self.assertEqual(pdp.check(req).results["read"].effect, "allow")
        req["context"] = {"env": "dev"}
        self.assertEqual(pdp.check(req).results["read"].effect, "deny")

    def test_principal_id_scoped_rule(self):
        b = _bundle()
        b["rules"] = [
            {"id": "alice-only", "resource_kind": "document",
             "actions": ["read"], "roles": [], "principal_id": "alice",
             "effect": "allow", "reason": "alice", "conditions": []},
        ]
        pdp = cr.CheckResources(cr.compile_bundle(b), _fresh_log())
        self.assertEqual(pdp.check(_req()).results["read"].effect, "allow")
        req = _req()
        req["principal"]["id"] = "bob"
        self.assertEqual(pdp.check(req).results["read"].effect, "deny")

    def test_response_carries_request_id(self):
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), _fresh_log())
        resp = pdp.check(_req(request_id="req-42"))
        self.assertEqual(resp.request_id, "req-42")

    def test_log_without_append_refused(self):
        with self.assertRaises(cr.CheckResourcesError):
            cr.CheckResources(cr.compile_bundle(_bundle()),
                              object())  # no .append

    def test_record_failure_propagates(self):
        class BadLog:
            def append(self, event):
                raise IOError("disk full")
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), BadLog())
        with self.assertRaises(IOError):
            pdp.check(_req())


class RecordTest(unittest.TestCase):
    def test_records_verify_and_complete(self):
        log = _fresh_log()
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), log)
        pdp.check(_req(actions=("read", "write"), request_id="r9"))
        recs = cr.decision_records(log)
        self.assertEqual(len(recs), 2)
        self.assertTrue(cr.verify_decision_records(recs))
        self.assertTrue(cr.request_records_complete(recs, request_id="r9"))
        self.assertFalse(cr.request_records_complete(recs,
                                                     request_id="nope"))

    def test_record_fields_owned(self):
        log = _fresh_log()
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), log)
        pdp.check(_req())
        rec = cr.decision_records(log)[0]
        for f in cr.RECORD_FIELDS:
            self.assertIn(f, rec, f)
        self.assertEqual(rec["record_type"], "decision-record")
        self.assertEqual(rec["schema_version"], "1.0")

    def test_interleaved_writers_fail_honestly(self):
        log = _fresh_log()
        a = cr.CheckResources(cr.compile_bundle(_bundle()), log)
        b = cr.CheckResources(cr.compile_bundle(_bundle()), log)
        a.check(_req(request_id="a"))
        b.check(_req(request_id="b"))
        recs = cr.decision_records(log)
        self.assertFalse(cr.verify_decision_records(recs))
        self.assertTrue(cr.verify_decision_records(recs[0:1]))
        self.assertTrue(cr.verify_decision_records(recs[1:2]))

    def test_reordered_refuses(self):
        log = _fresh_log()
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), log)
        pdp.check(_req(actions=("read", "write")))
        recs = cr.decision_records(log)
        self.assertFalse(cr.verify_decision_records(list(reversed(recs))))

    def test_attrs_digest_binds(self):
        log = _fresh_log()
        pdp = cr.CheckResources(cr.compile_bundle(_bundle()), log)
        req = _req()
        req["resource"]["attrs"] = {"owner": "alice", "tag": "x"}
        pdp.check(req)
        rec = cr.decision_records(log)[0]
        want = hashlib.sha256(json.dumps(
            {"owner": "alice", "tag": "x"},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(rec["resource_attrs_digest"], want)

    def test_wrong_record_type_refuses(self):
        self.assertFalse(cr.verify_decision_records(
            [{"record_type": "nope"}]))


class DeterminismTest(unittest.TestCase):
    def test_two_runs_identical(self):
        def run():
            log = _fresh_log()
            pdp = cr.CheckResources(cr.compile_bundle(_bundle()), log)
            resp = pdp.check(_req(actions=("read", "write")))
            recs = cr.decision_records(log)
            return (
                {a: (d.effect, d.matched_rule_id) for a, d in
                 resp.results.items()},
                [{k: r[k] for k in cr.RECORD_FIELDS} for r in recs],
            )
        self.assertEqual(run(), run())


if __name__ == "__main__":
    unittest.main()
