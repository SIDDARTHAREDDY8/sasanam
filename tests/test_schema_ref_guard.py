"""Unit tests for gov.schema_ref_guard (W246-3).

Red-first at the public seam: check_tool_schema raises
SchemaRefGuardError (with .code) on hostile/malformed schemas and
returns an allow verdict with resolution statistics on clean ones.
"""

import copy
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import schema_ref_guard as srg


def _refusal(schema, **kw):
    try:
        srg.check_tool_schema(schema, **kw)
    except srg.SchemaRefGuardError as exc:
        return exc.code
    raise AssertionError("expected refusal, got allow")


class SchemaRefGuardContractTest(unittest.TestCase):
    def test_taxonomy_pin_900(self):
        # Wave-246 lane 3 (W246-3): 5 additive schema-ref codes
        # (external, depth-exceeded, budget-exhausted, malformed,
        # resolved) on the wave-245 pin of 895.
        # Wave-246 merge: re-pointed lane-local pin to the composed 936 (was lane-local 900); additive only.
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2131) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*) Wave-342 lane 6: pin 2131 -> 2127.
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.

    def test_new_codes_mapped(self):
        for code in ("schema-ref-external",
                     "schema-ref-depth-exceeded",
                     "schema-ref-budget-exhausted",
                     "schema-record-malformed",
                     "schema-refs-resolved"):
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "schema-ref")

    def test_error_carries_code(self):
        try:
            srg.check_tool_schema({"$ref": "https://x.example/"})
        except srg.SchemaRefGuardError as exc:
            self.assertEqual(exc.code, "schema-ref-external")
            self.assertTrue(str(exc))
        else:
            self.fail("expected SchemaRefGuardError")

    def test_allow_verdict_shape(self):
        verdict = srg.check_tool_schema({"type": "string"})
        self.assertEqual(verdict["decision"], "allow")
        self.assertEqual(verdict["code"], "schema-refs-resolved")
        self.assertEqual(verdict["refs_resolved"], 0)
        self.assertEqual(verdict["max_depth_seen"], 0)


class SchemaRefGuardRefusalTest(unittest.TestCase):
    def test_external_absolute(self):
        self.assertEqual(
            _refusal({"$ref": "https://attacker.example/schema"}),
            "schema-ref-external")

    def test_external_with_fragment(self):
        self.assertEqual(
            _refusal({"$ref": "bundle.json#/definitions/x"}),
            "schema-ref-external")

    def test_external_bare_path(self):
        self.assertEqual(
            _refusal({"$ref": "other.json"}),
            "schema-ref-external")

    def test_recursive_ref_external(self):
        self.assertEqual(
            _refusal({"$recursiveRef": "https://attacker.example/r"}),
            "schema-ref-external")

    def test_dynamic_ref_external(self):
        self.assertEqual(
            _refusal({"$dynamicRef": "https://attacker.example/d"}),
            "schema-ref-external")

    def test_cycle(self):
        schema = {"definitions": {
            "a": {"$ref": "#/definitions/b"},
            "b": {"$ref": "#/definitions/a"}},
            "$ref": "#/definitions/a"}
        self.assertEqual(_refusal(schema), "schema-ref-depth-exceeded")

    def test_self_root(self):
        self.assertEqual(_refusal({"$ref": "#"}),
                         "schema-ref-depth-exceeded")

    def test_empty_ref_is_external(self):
        # "" does not start with "#": out-of-document by the crisp
        # rule, refused without any base-URI resolution.
        self.assertEqual(_refusal({"$ref": ""}),
                         "schema-ref-external")

    def test_deep_chain_bound(self):
        defs = {"n%d" % i: {"$ref": "#/definitions/n%d" % (i + 1)}
                for i in range(10)}
        schema = {"definitions": defs, "$ref": "#/definitions/n0"}
        self.assertEqual(_refusal(schema, max_ref_depth=4),
                         "schema-ref-depth-exceeded")

    def test_budget_bound(self):
        schema = {"properties":
                  {"p%d" % i: {"$ref": "#/definitions/s"}
                   for i in range(50)},
                  "definitions": {"s": {"type": "string"}}}
        self.assertEqual(_refusal(schema, max_resolution_steps=10),
                         "schema-ref-budget-exhausted")

    def test_dangling_pointer(self):
        self.assertEqual(_refusal({"$ref": "#/definitions/nope"}),
                         "schema-record-malformed")

    def test_non_dict(self):
        for bad in (["$ref"], "x", 42, None, True):
            self.assertEqual(_refusal(bad), "schema-record-malformed")

    def test_non_string_ref(self):
        self.assertEqual(
            _refusal({"properties": {"x": {"$ref": 42}}}),
            "schema-record-malformed")

    def test_bad_bounds_rejected(self):
        for kw in ({"max_ref_depth": 0}, {"max_ref_depth": -1},
                   {"max_resolution_steps": 0},
                   {"max_ref_depth": True}, {"max_ref_depth": "16"}):
            self.assertEqual(_refusal({"type": "string"}, **kw),
                             "schema-record-malformed")

    def test_cyclic_python_container(self):
        d = {}
        d["self"] = d
        self.assertEqual(_refusal(d), "schema-record-malformed")


class SchemaRefGuardAllowTest(unittest.TestCase):
    def test_valid_refs(self):
        schema = {"definitions": {"s": {"type": "string"}},
                  "properties": {"x": {"$ref": "#/definitions/s"}}}
        verdict = srg.check_tool_schema(schema)
        self.assertEqual(verdict["decision"], "allow")
        self.assertEqual(verdict["refs_resolved"], 1)
        self.assertEqual(verdict["max_depth_seen"], 1)

    def test_sibling_keys_scanned(self):
        # $ref siblings (2020-12) are validated too: the nested
        # external ref must still refuse.
        schema = {"$ref": "#/definitions/ok",
                  "definitions": {
                      "ok": {"properties":
                             {"evil": {"$ref": "https://x.example/"}}}}}
        self.assertEqual(_refusal(schema), "schema-ref-external")

    def test_pointer_unescape(self):
        schema = {"definitions": {"a/b": {"type": "string"},
                                  "c~d": {"type": "integer"}},
                  "properties": {
                      "x": {"$ref": "#/definitions/a~1b"},
                      "y": {"$ref": "#/definitions/c~0d"}}}
        verdict = srg.check_tool_schema(schema)
        self.assertEqual(verdict["refs_resolved"], 2)

    def test_list_pointer(self):
        schema = {"allOf": [{"type": "string"}],
                  "$ref": "#/allOf/0"}
        verdict = srg.check_tool_schema(schema)
        self.assertEqual(verdict["decision"], "allow")

    def test_diamond_refs_allowed(self):
        schema = {"definitions": {"s": {"type": "string"}},
                  "properties": {
                      "a": {"$ref": "#/definitions/s"},
                      "b": {"$ref": "#/definitions/s"}}}
        verdict = srg.check_tool_schema(schema)
        self.assertEqual(verdict["refs_resolved"], 2)

    def test_no_mutation(self):
        schema = {"definitions": {"s": {"type": "string"}},
                  "properties": {"x": {"$ref": "#/definitions/s"}}}
        before = copy.deepcopy(schema)
        srg.check_tool_schema(schema)
        self.assertEqual(schema, before)

    def test_no_network_imports(self):
        # Static complement to the battery's runtime no-fetch proof:
        # the module must not import any network client. Check
        # import statements, not prose (the docstring names them).
        import inspect  # noqa: PLC0415
        import re  # noqa: PLC0415
        src = inspect.getsource(srg)
        imports = re.findall(r"^\s*(?:import|from)\s+(\S+)",
                             src, re.M)
        for mod in imports:
            top = mod.split(".")[0]
            self.assertNotIn(top, ("urllib", "socket", "http",
                                   "requests", "httpx", "aiohttp"),
                             "network import: %s" % (mod,))


if __name__ == "__main__":
    unittest.main()
