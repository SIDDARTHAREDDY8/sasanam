"""Unit tests for gov/policy_exception.py (wave-268 lane).

Pin 1579 is asserted here; repointed by the wave-275 merge coordinator.
"""

import hashlib
import json
import unittest

import gov.decision_codes as dc
import gov.ed25519 as ed
import gov.policy_exception as pe
from gov.signing import Ed25519Verifier


PIN = 1869  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 7: pin 1541 -> 1545 (+4 casbin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*) ; Wave-295 lane 4: pin 1742 -> 1746 (+4 coord-state-*); Wave-295 merge: pin 1746 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)

EXPECTED_CODES = (
    "exception-compensating-validation-failed",
    "exception-expired",
    "exception-granted-with-attribution",
    "exception-malformed",
    "exception-rule-skipped",
    "exception-unauthorized-authorship",
)

EVAL_START = "2026-10-01T12:00:00Z"


def _keys(keyid="test-key-1"):
    seed = ed.generate_seed()
    return {"seed": seed, "pub": ed.publickey(seed), "keyid": keyid}


def _trusted(*keysets):
    return {k["keyid"]: Ed25519Verifier(k["pub"], k["keyid"])
            for k in keysets}


def _body(**over):
    body = {
        "kind": "sasanam.policy-exception/v1",
        "id": "exc-1",
        "policyName": "test-policy",
        "ruleNames": ["test.rule"],
        "match": {"any": [
            {"path": "principal.id", "op": "eq", "value": "agent-1"}]},
        "conditions": [],
        "expiresAt": "2027-01-01T00:00:00Z",
        "compensatingValidations": [
            {"name": "target-pinned",
             "check": {"path": "resource.target", "op": "startswith",
                       "value": "backup."}},
        ],
    }
    body.update(over)
    return body


def _seal(body, keys):
    sig = ed.sign(keys["seed"], pe.canonical_bytes(body))
    wire = dict(body)
    wire["signature"] = {"keyId": keys["keyid"], "sig": sig.hex()}
    return wire


def _ctx(**over):
    ctx = {"principal": {"id": "agent-1", "roles": ["ops"]},
           "action": "tool.call",
           "resource": {"tool": "db.dump", "target": "backup.east",
                        "class": "data"}}
    ctx.update(over)
    return ctx


class TestPin(unittest.TestCase):
    def test_pin_and_codes(self):
        self.assertEqual(len(dc.TAXONOMY), PIN)
        for code in EXPECTED_CODES:
            self.assertIn(code, dc.TAXONOMY)
        domains = {dc.TAXONOMY[c]["domain"] for c in EXPECTED_CODES}
        self.assertEqual(domains, {"exception"})

    def test_no_duplicate_literals(self):
        src = open("gov/decision_codes.py").read()
        for code in EXPECTED_CODES:
            self.assertEqual(src.count("\"code\": '%s'" % code), 1)


class TestLoading(unittest.TestCase):
    def test_valid_wire_loads(self):
        keys = _keys()
        rep = pe.load_exceptions([_seal(_body(), keys)],
                                 _trusted(keys), EVAL_START)
        self.assertEqual(len(rep.exceptions), 1)
        exc = rep.exceptions[0]
        self.assertEqual(exc.id, "exc-1")
        self.assertEqual(exc.policy_name, "test-policy")
        self.assertEqual(exc.rule_names, ["test.rule"])
        self.assertEqual(exc.author_key_id, "test-key-1")
        self.assertEqual(rep.checked, ["exc-1"])
        self.assertEqual(rep.out_of_scope, [])
        self.assertEqual(rep.refused, [])

    def test_seal_exception_round_trip(self):
        keys = _keys()
        wire = pe.seal_exception(_body(), keys["seed"], keys["keyid"])
        rep = pe.load_exceptions([wire], _trusted(keys), EVAL_START)
        self.assertEqual(rep.exceptions[0].id, "exc-1")

    def test_unknown_author_refused(self):
        keys = _keys()
        rogue = _keys("rogue")
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions([_seal(_body(), rogue)],
                               _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code,
                         "exception-unauthorized-authorship")

    def test_tampered_body_refused(self):
        keys = _keys()
        wire = _seal(_body(), keys)
        wire["ruleNames"] = ["*"]
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions([wire], _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code,
                         "exception-unauthorized-authorship")

    def test_missing_signature_malformed(self):
        keys = _keys()
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions([_body()], _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_duplicate_ids_malformed(self):
        keys = _keys()
        wires = [_seal(_body(), keys), _seal(_body(), keys)]
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions(wires, _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_bad_expires_at_malformed(self):
        keys = _keys()
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions(
                [_seal(_body(expiresAt="soon"), keys)],
                _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_missing_expires_at_malformed(self):
        keys = _keys()
        body = _body()
        del body["expiresAt"]
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions([_seal(body, keys)],
                               _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_unknown_dsl_op_malformed(self):
        keys = _keys()
        body = _body(conditions=[
            {"path": "resource.class", "op": "regex", "value": ".*"}])
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions([_seal(body, keys)],
                               _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_match_shape_closed(self):
        keys = _keys()
        for bad_match in ({"any": [], "all": []},
                          {"either": [{"path": "a", "op": "present"}]},
                          "any"):
            with self.assertRaises(pe.PolicyExceptionError) as cm:
                pe.load_exceptions(
                    [_seal(_body(match=bad_match), keys)],
                    _trusted(keys), EVAL_START)
            self.assertEqual(cm.exception.code, "exception-malformed")

    def test_unknown_wire_key_malformed(self):
        keys = _keys()
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.load_exceptions(
                [_seal(_body(surprise=1), keys)],
                _trusted(keys), EVAL_START)
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_expired_is_out_of_scope_not_refused(self):
        keys = _keys()
        body = _body(expiresAt="2025-01-01T00:00:00Z")
        rep = pe.load_exceptions([_seal(body, keys)],
                                 _trusted(keys), EVAL_START)
        self.assertEqual(rep.out_of_scope, ["exc-1"])
        self.assertEqual(len(rep.exceptions), 1)


class TestEvaluation(unittest.TestCase):
    def _loaded(self, **over):
        keys = _keys()
        rep = pe.load_exceptions([_seal(_body(**over), keys)],
                                 _trusted(keys), EVAL_START)
        return rep.exceptions

    def test_grant_carries_identity(self):
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     self._loaded())
        self.assertEqual(d.kind, "skip")
        self.assertEqual(d.exception_ids, ["exc-1"])

    def test_expired_grants_nothing(self):
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     self._loaded(expiresAt="2025-01-01T00:00:00Z"))
        self.assertEqual(d.kind, "no-skip")
        self.assertEqual(d.detail, [("exception-expired", "exc-1")])

    def test_validation_failure_refuses(self):
        bad = _ctx(resource={"tool": "db.dump", "target": "prod.west",
                             "class": "data"})
        d = pe.apply("test-policy", "test.rule", bad, EVAL_START,
                     self._loaded())
        self.assertEqual(d.kind, "no-skip")
        self.assertEqual(
            d.detail,
            [("exception-compensating-validation-failed", "exc-1")])

    def test_wrong_policy_or_rule(self):
        excs = self._loaded()
        for policy, rule in (("other", "test.rule"),
                             ("test-policy", "other.rule")):
            d = pe.apply(policy, rule, _ctx(), EVAL_START, excs)
            self.assertEqual(d.kind, "no-skip")
            self.assertEqual(d.detail, [])

    def test_match_all(self):
        excs = self._loaded(match={"all": [
            {"path": "principal.id", "op": "eq", "value": "agent-1"},
            {"path": "action", "op": "eq", "value": "tool.call"}]})
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     excs)
        self.assertEqual(d.kind, "skip")
        other = _ctx(action="other.call")
        d2 = pe.apply("test-policy", "test.rule", other, EVAL_START,
                      excs)
        self.assertEqual(d2.kind, "no-skip")

    def test_conditions_must_hold(self):
        excs = self._loaded(conditions=[
            {"path": "resource.class", "op": "eq",
             "value": "credential"}])
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     excs)
        self.assertEqual(d.kind, "no-skip")

    def test_dsl_operators(self):
        cases = [
            ({"path": "principal.id", "op": "in",
              "value": ["agent-1", "agent-2"]}, True),
            ({"path": "principal.id", "op": "nin",
              "value": ["someone-else"]}, True),
            ({"path": "resource.target", "op": "startswith",
              "value": "backup."}, True),
            ({"path": "principal.id", "op": "ne",
              "value": "someone-else"}, True),
            ({"path": "missing.deep.path", "op": "absent"}, True),
            ({"path": "principal.id", "op": "present"}, True),
            ({"path": "missing.deep.path", "op": "eq",
              "value": "x"}, False),   # missing never holds
            ({"path": "principal.id", "op": "gt",
              "value": 3}, False),      # type mismatch is False
            ({"path": "missing.deep.path", "op": "ne",
              "value": "x"}, False),   # missing never holds, even ne
        ]
        for cond, want in cases:
            excs = self._loaded(
                match={"any": [cond]},
                compensatingValidations=[])
            d = pe.apply("test-policy", "test.rule", _ctx(),
                         EVAL_START, excs)
            self.assertEqual(d.kind == "skip", want,
                             "cond %r" % (cond,))

    def test_epoch_eval_start(self):
        excs = self._loaded()
        d = pe.apply("test-policy", "test.rule", _ctx(), 1790904000,
                     excs)
        self.assertEqual(d.kind, "skip")

    def test_multiple_attach_sorted(self):
        keys = _keys()
        wires = [_seal(_body(id="exc-b"), keys),
                 _seal(_body(id="exc-a"), keys)]
        rep = pe.load_exceptions(wires, _trusted(keys), EVAL_START)
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     rep.exceptions)
        self.assertEqual(d.exception_ids, ["exc-a", "exc-b"])

    def test_mixed_expired_and_valid(self):
        keys = _keys()
        wires = [_seal(_body(id="exc-old",
                             expiresAt="2025-01-01T00:00:00Z"), keys),
                 _seal(_body(id="exc-new"), keys)]
        rep = pe.load_exceptions(wires, _trusted(keys), EVAL_START)
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     rep.exceptions)
        self.assertEqual(d.kind, "skip")
        self.assertEqual(d.exception_ids, ["exc-new"])
        self.assertEqual(d.detail, [("exception-expired", "exc-old")])

    def test_match_for_rule(self):
        ids = pe.match_for_rule("test-policy", "test.rule", _ctx(),
                                EVAL_START, self._loaded())
        self.assertEqual(ids, ["exc-1"])


class TestComposition(unittest.TestCase):
    def _loaded(self):
        keys = _keys()
        rep = pe.load_exceptions([_seal(_body(), keys)],
                                 _trusted(keys), EVAL_START)
        return rep.exceptions

    def test_rule_outcome_skip(self):
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     self._loaded())
        out = pe.rule_outcome(True, d)
        self.assertEqual(out["outcome"], "skip")
        self.assertEqual(out["code"],
                         "exception-granted-with-attribution")
        self.assertEqual(out["exception_ids"], ["exc-1"])

    def test_rule_outcome_fail_and_pass(self):
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START, [])
        self.assertEqual(pe.rule_outcome(True, d)["outcome"], "fail")
        self.assertEqual(pe.rule_outcome(False, d)["outcome"], "pass")

    def test_rule_outcome_rejects_foreign_decision(self):
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.rule_outcome(True, "skip")
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_skip_record_digest_linked(self):
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                     self._loaded())
        rec = pe.to_skip_record(d, "test-policy", "test.rule",
                                _ctx(), EVAL_START)
        self.assertEqual(rec["code"],
                         "exception-granted-with-attribution")
        self.assertEqual(rec["exception_ids"], ["exc-1"])
        self.assertEqual(rec["kind"], pe.SKIP_RECORD_KIND)
        check = dict(rec)
        digest = check.pop("digest")
        self.assertEqual(
            digest,
            hashlib.sha256(pe.canonical_bytes(check)).hexdigest())
        self.assertEqual(
            rec["context_digest"],
            hashlib.sha256(pe.canonical_bytes(_ctx())).hexdigest())

    def test_skip_record_refuses_non_skip(self):
        d = pe.apply("test-policy", "test.rule", _ctx(), EVAL_START, [])
        with self.assertRaises(pe.PolicyExceptionError) as cm:
            pe.to_skip_record(d, "test-policy", "test.rule", _ctx(),
                              EVAL_START)
        self.assertEqual(cm.exception.code, "exception-malformed")

    def test_canonical_bytes_deterministic(self):
        obj = {"b": 1, "a": [3, 2, {"z": None}]}
        self.assertEqual(
            pe.canonical_bytes(obj),
            b'{"a":[3,2,{"z":null}],"b":1}')


class TestBehsigHook(unittest.TestCase):
    def test_hook_grants_loud_skip(self):
        import gov.behavioral_sig_packs as bsp
        keys = _keys()
        body = _body(policyName="test-core", ruleNames=["test.cred_rule"],
                     match={"any": [
                         {"path": "principal.id", "op": "eq",
                          "value": "agent-1"}]},
                     compensatingValidations=[])
        rep = pe.load_exceptions([_seal(body, keys)],
                                 _trusted(keys), EVAL_START)
        spec = {
            "pack_format": "sasanam.behavioral-sig-pack/v1",
            "pack_id": "test-core", "pack_version": "1.0.0",
            "engine_version": "1", "macros": [], "lists": [],
            "rules": [{
                "name": "test.cred_rule", "desc": "d",
                "condition": {"op": "eq", "field": "arg.class",
                              "value": "credential"},
                "output": "cred", "priority": "high", "enabled": True,
                "source": "agent_event", "tags": ["maturity_stable"],
                "maturity": "stable", "exceptions": [],
                "capture": {"window_events": 2}, "params": {}}],
        }
        env = {"pack": spec, "signatures": [{
            "keyid": keys["keyid"],
            "sig": ed.sign(keys["seed"],
                           pe.canonical_bytes(spec)).hex()}]}
        records = []

        def _j(rec):
            records.append(rec)
            return rec

        pack = bsp.load_pack(json.dumps(env, sort_keys=True).encode(),
                             trust_keys={keys["keyid"]: keys["pub"]},
                             journal=_j)
        ev = bsp.enrich_event({"ts": 1000.0, "actor_id": "agent-1",
                               "session_id": "s1", "tool": "db.dump",
                               "target": "prod",
                               "args": {"password": "hunter2"}})
        alerts = bsp.match_pack(pack, [ev], journal=_j,
                                policy_exceptions=rep.exceptions,
                                eval_start=EVAL_START)
        self.assertEqual(alerts, [])
        skips = [r for r in records
                 if r.get("code") == "exception-rule-skipped"]
        self.assertEqual(len(skips), 1)
        self.assertEqual(skips[0]["exception_ids"], ["exc-1"])
        self.assertEqual(skips[0]["rule"], "test.cred_rule")

    def test_hook_requires_eval_start(self):
        import gov.behavioral_sig_packs as bsp
        with self.assertRaises(ValueError):
            bsp.match_pack(None, [], policy_exceptions=[],
                           eval_start=None)

    def test_hook_default_unchanged(self):
        import gov.behavioral_sig_packs as bsp
        # Without policy_exceptions the matcher behaves as before:
        # rule-local exception triples still suppress silently.
        spec = {
            "pack_format": "sasanam.behavioral-sig-pack/v1",
            "pack_id": "test-core", "pack_version": "1.0.0",
            "engine_version": "1", "macros": [], "lists": [],
            "rules": [{
                "name": "r1", "desc": "d",
                "condition": {"op": "eq", "field": "arg.class",
                              "value": "credential"},
                "output": "cred", "priority": "high", "enabled": True,
                "source": "agent_event", "tags": ["maturity_stable"],
                "maturity": "stable",
                "exceptions": [{"and": [
                    {"field": "principal", "comparator": "eq",
                     "value": "agent-1"}]}],
                "capture": {"window_events": 2}, "params": {}}],
        }
        keys = _keys()
        env = {"pack": spec, "signatures": [{
            "keyid": keys["keyid"],
            "sig": ed.sign(keys["seed"],
                           pe.canonical_bytes(spec)).hex()}]}
        pack = bsp.load_pack(json.dumps(env, sort_keys=True).encode(),
                             trust_keys={keys["keyid"]: keys["pub"]})
        ev = bsp.enrich_event({"ts": 1000.0, "actor_id": "agent-1",
                               "session_id": "s1", "tool": "db.dump",
                               "target": "prod",
                               "args": {"password": "hunter2"}})
        alerts = bsp.match_pack(pack, [ev])
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
