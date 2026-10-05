"""Unit tests for gov/policy_authoring.py (wave-253 lane 3).

The cloud-custodian ADAPT: filters/actions authoring vocabulary +
harness dry-run + structured match outputs. Pattern only -- no c7n
code, no cloud-resource model.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import policy_authoring as pa
from gov import decision_codes


GOOD = """\
version: 1
policies:
  - name: block-secret-reads
    description: Deny reads of secret-like paths.
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
      - type: value-filter
        key: path
        op: contains-any
        value: [secret, credentials]
    actions:
      - type: deny
        reason: Secret-like read denied.
        flag: secret_access_attempt
"""


class CompileTest(unittest.TestCase):
    def test_compiles_to_engine_valid_native(self):
        compiled = pa.compile_authoring(GOOD)
        self.assertEqual(compiled.rule_ids(), ["block-secret-reads"])
        # The native text is engine-loadable on its own.
        self.assertIn('id: "block-secret-reads"', compiled.native_text)
        self.assertIn('effect: "deny"', compiled.native_text)

    def test_deterministic_bytes(self):
        a = pa.compile_authoring(GOOD).native_text
        b = pa.compile_authoring(GOOD).native_text
        self.assertEqual(a, b)

    def test_enforces(self):
        engine = pa.compile_authoring(GOOD).engine
        deny = engine.evaluate(
            {"tool": "read_file", "args": {"path": "/x/secret"}},
            {}, record_telemetry=False)
        self.assertEqual(deny.effect, "deny")
        # No rule matches: fail-closed default deny (not allow).
        ok = engine.evaluate(
            {"tool": "read_file", "args": {"path": "/x/notes"}},
            {}, record_telemetry=False)
        self.assertEqual(ok.effect, "deny")

    def test_unknown_tool_refused_early(self):
        text = GOOD.replace("value: read_file", "value: rm_rf")
        with self.assertRaises(pa.AuthoringError) as ctx:
            pa.compile_authoring(text)
        self.assertEqual(ctx.exception.code,
                         "policy-authoring-malformed")

    def test_empty_policies_refused(self):
        with self.assertRaises(pa.AuthoringError) as ctx:
            pa.compile_authoring("version: 1\npolicies: []\n")
        self.assertEqual(ctx.exception.code, "policy-authoring-empty")

    def test_non_mapping_filter_refused(self):
        text = GOOD.replace("type: value-filter", "type: value-filter")
        text = text.replace("key: tool", "- just-a-string", 1)
        with self.assertRaises(pa.AuthoringError) as ctx:
            pa.compile_authoring(text)
        self.assertEqual(ctx.exception.code,
                         "policy-authoring-malformed")

    def test_bool_string_not_coerced(self):
        # Wave-194 R1: "false" (string) must not mean False.
        text = GOOD.replace("key: path", "key: domain_allowlisted", 1)
        text = text.replace("op: contains-any", "op: eq", 1)
        text = text.replace("value: [secret, credentials]",
                            'value: "false"', 1)
        with self.assertRaises(pa.AuthoringError) as ctx:
            pa.compile_authoring(text)
        self.assertEqual(ctx.exception.code,
                         "policy-authoring-malformed")

    def test_bool_signal_compiles(self):
        text = """\
version: 1
policies:
  - name: block-unallowlisted
    filters:
      - type: value-filter
        key: domain_allowlisted
        op: eq
        value: false
    actions:
      - type: deny
        reason: x
"""
        engine = pa.compile_authoring(text).engine
        got = engine.evaluate({"tool": "send_email", "args": {}},
                              {"domain_allowlisted": False},
                              record_telemetry=False)
        self.assertEqual(got.effect, "deny")

    def test_counter_gte_compiles(self):
        text = """\
version: 1
policies:
  - name: throttle-sends
    filters:
      - type: value-filter
        key: min_sends
        op: gte
        value: 3
    actions:
      - type: require-approval
        reason: high send volume
"""
        engine = pa.compile_authoring(text).engine
        hot = engine.evaluate(
            {"tool": "send_email", "args": {}},
            {"counters": {"send_email": 5}}, record_telemetry=False)
        self.assertEqual(hot.effect, "require_approval")
        # Below the floor: no rule matches -> default deny.
        cold = engine.evaluate(
            {"tool": "send_email", "args": {}},
            {"counters": {"send_email": 1}}, record_telemetry=False)
        self.assertEqual(cold.effect, "deny")

    def test_nested_and_or(self):
        text = """\
version: 1
policies:
  - name: nested
    filters:
      - type: and
        filters:
          - type: value-filter
            key: tool
            op: eq
            value: send_email
          - type: or
            filters:
              - type: value-filter
                key: domain_allowlisted
                op: eq
                value: false
              - type: value-filter
                key: source_untrusted
                op: eq
                value: true
    actions:
      - type: deny
        reason: x
"""
        compiled = pa.compile_authoring(text)
        # (A) AND (B or C) -> two native rules.
        self.assertEqual(len(compiled.plans), 2)
        engine = compiled.engine
        for ctx in ({"domain_allowlisted": False},
                    {"source_untrusted": True}):
            got = engine.evaluate({"tool": "send_email", "args": {}},
                                  ctx, record_telemetry=False)
            self.assertEqual(got.effect, "deny", ctx)
        got = engine.evaluate(
            {"tool": "send_email", "args": {}},
            {"domain_allowlisted": True, "source_untrusted": False},
            record_telemetry=False)
        self.assertEqual(got.effect, "deny")  # default deny

    def test_multi_action_multi_rule_ids_unique(self):
        compiled = pa.compile_authoring("""\
version: 1
policies:
  - name: two-actions
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
    actions:
      - type: allow
        reason: a
      - type: require-approval
        reason: b
""")
        ids = compiled.rule_ids()
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)


class ExplainTest(unittest.TestCase):
    def test_explanation_matches_engine(self):
        compiled = pa.compile_authoring(GOOD)
        engine = compiled.engine
        from gov.decision_contract import Request
        cases = [
            {"tool": "read_file", "args": {"path": "/x/secret"}},
            {"tool": "read_file", "args": {"path": "/x/notes"}},
            {"tool": "write_file", "args": {"path": "/x/secret"}},
        ]
        for action in cases:
            explained = pa.explain_candidate(compiled, action, {})
            trace = {t.rule_id: bool(t.matched)
                     for t in engine.decide(
                         Request.from_action(action, {}),
                         record_telemetry=False).diagnostics.trace}
            for rec in explained:
                self.assertEqual(rec["matched"],
                                 trace[rec["rule"]], action)

    def test_no_raw_path_in_why(self):
        compiled = pa.compile_authoring(GOOD)
        explained = pa.explain_candidate(
            compiled,
            {"tool": "read_file",
             "args": {"path": "/vault/s3cr3t-stuff"}}, {})
        self.assertNotIn("s3cr3t-stuff", json.dumps(explained))


class DryRunTest(unittest.TestCase):
    def _harness(self):
        tmpd = tempfile.mkdtemp(prefix="pa-test-")
        hdir = os.path.join(tmpd, "h")
        os.makedirs(os.path.join(hdir, "policies"))
        os.makedirs(os.path.join(hdir, "fixtures"))
        os.makedirs(os.path.join(hdir, "expected"))
        with open(os.path.join(hdir, "policies", "p.yaml"), "w",
                  encoding="utf-8") as fh:
            fh.write("version: 2\npolicies:\n"
                     "  - id: allow-all\n"
                     "    effect: allow\n"
                     "    match:\n"
                     "      tool: [read_file, send_email]\n")
        fx = {"action": {"tool": "send_email", "args": {}},
              "context": {}}
        with open(os.path.join(hdir, "fixtures", "f.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(fx, fh)
        with open(os.path.join(hdir, "expected", "f.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"effect": "allow"}, fh)
        return hdir

    def _snap(self, hdir):
        out = {}
        for root, _d, files in os.walk(hdir):
            for f in files:
                p = os.path.join(root, f)
                st = os.stat(p)
                out[os.path.relpath(p, hdir)] = (st.st_size,
                                                 st.st_mtime_ns)
        return out

    def test_dry_run_without_candidate(self):
        hdir = self._harness()
        report = pa.dry_run(hdir)
        d = report.to_dict()
        self.assertTrue(d["dry_run"])
        self.assertIsNone(d["candidate"])
        self.assertEqual(d["summary"]["total"], 1)
        self.assertEqual(d["fixtures"][0]["current"]["effect"],
                         "allow")

    def test_dry_run_read_only(self):
        hdir = self._harness()
        before = self._snap(hdir)
        pa.dry_run(hdir, authoring_text="""\
version: 1
policies:
  - name: c
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: send_email
    actions:
      - type: deny
        reason: x
""")
        self.assertEqual(before, self._snap(hdir))

    def test_dry_run_deterministic(self):
        hdir = self._harness()
        self.assertEqual(pa.dry_run(hdir).to_json(),
                         pa.dry_run(hdir).to_json())


class TaxonomyTest(unittest.TestCase):
    def test_codes_registered(self):
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # additive only.
        self.assertEqual(len(decision_codes.TAXONOMY), 2130) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)
        self.assertEqual(len(set(decision_codes.TAXONOMY)), 2130) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1857 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1857 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)
        for code in (
                "policy-authoring-compile-refused",
                "policy-authoring-conflicting-filters",
                "policy-authoring-empty",
                "policy-authoring-malformed",
                "policy-authoring-unknown-action",
                "policy-authoring-unknown-filter",
                "policy-authoring-unknown-op"):
            self.assertIn(code, decision_codes.TAXONOMY)
            resolved = decision_codes.code_for(code)
            self.assertEqual(resolved["code"], code)


if __name__ == "__main__":
    unittest.main()
