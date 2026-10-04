"""Unit tests for wave-243 lane H (W243-9 + W243-10).

Covers gov.effect_agreement, gov.registry_acceptance, and
gov.mcp_surface_guard. Red-before-green: these tests were written
against the probe contracts before the modules were complete; the
red-first batteries (evals/w243_*) hold the public-seam evidence.
"""

import base64
import copy
import hashlib
import unittest

from gov import decision_codes as dc
from gov import effect_agreement as ea
from gov import mcp_surface_guard as sg
from gov import registry_acceptance as rg
from gov import ed25519 as _e

T0 = 1727731200
T1 = T0 + 5

_SEEDS = [bytes([i + 1]) * 32 for i in range(3)]
_PUBS = [_e.publickey(s) for s in _SEEDS]
_B64PUBS = [base64.b64encode(p).decode("ascii") for p in _PUBS]

PKG = b"unit-test-package-bytes"
PKG_DIGEST = hashlib.sha256(PKG).hexdigest()


def _payload(**over):
    p = {"name": "skill-pack", "version": "1.0.0", "digest": PKG_DIGEST,
         "issued_at": T0, "valid_until": T0 + 3600}
    p.update(over)
    return p


def _sign(payload, idx):
    body = rg.canonical_manifest_bytes(payload)
    return {"key": _B64PUBS[idx],
            "sig": base64.b64encode(_e.sign(_SEEDS[idx], body)).decode(
                "ascii")}


def _manifest(n=3, **over):
    p = _payload(**over)
    return {"payload": p, "signatures": [_sign(p, i) for i in range(n)]}


def _policy(threshold=3):
    return {"threshold": threshold, "trusted_keys": list(_B64PUBS)}


class EffectAgreementTest(unittest.TestCase):
    def test_aligned(self):
        reg = {}
        rec = ea.record_decision(reg, "a", {"verdict": "allow",
                                            "action": "file:read",
                                            "params": {"p": 1}}, now=T0)
        self.assertEqual(len(rec["decision_digest"]), 64)
        ea.record_observed_effect(reg, "a", {"action": "file:read",
                                             "params": {"p": 1},
                                             "outcome": "success"},
                                  observed_at=T1)
        res = ea.compute_agreement(reg, "a")
        self.assertEqual(res["agreement"], "aligned")
        self.assertIsNone(res["flag"])

    def test_contradicted_action(self):
        reg = {}
        ea.record_decision(reg, "a", {"verdict": "allow",
                                     "action": "file:read",
                                     "params": {}}, now=T0)
        ea.record_observed_effect(reg, "a", {"action": "file:write",
                                             "params": {},
                                             "outcome": "success"},
                                  observed_at=T1)
        with self.assertRaises(ea.EffectAgreementError) as ctx:
            ea.compute_agreement(reg, "a")
        self.assertEqual(ctx.exception.code,
                         "effect-decision-contradicted")

    def test_contradicted_params(self):
        reg = {}
        ea.record_decision(reg, "a", {"verdict": "allow",
                                     "action": "file:read",
                                     "params": {"p": 1}}, now=T0)
        ea.record_observed_effect(reg, "a", {"action": "file:read",
                                             "params": {"p": 2},
                                             "outcome": "success"},
                                  observed_at=T1)
        with self.assertRaises(ea.EffectAgreementError) as ctx:
            ea.compute_agreement(reg, "a")
        self.assertEqual(ctx.exception.code,
                         "effect-decision-contradicted")

    def test_unknown_flagged(self):
        reg = {}
        ea.record_decision(reg, "a", {"verdict": "allow",
                                     "action": "file:read",
                                     "params": {}}, now=T0)
        res = ea.compute_agreement(reg, "a")
        self.assertEqual(res["agreement"], "unknown")
        self.assertEqual(res["flag"], "effect-unobserved")
        self.assertIsNone(res["effect_digest"])

    def test_unbound_effect(self):
        reg = {}
        ea.record_decision(reg, "a", {"verdict": "allow",
                                     "action": "file:read",
                                     "params": {}}, now=T0)
        ea.record_observed_effect(reg, "a", {"action": "file:read",
                                             "params": {},
                                             "outcome": "success"},
                                  observed_at=T1)
        reg["a"]["effect_bytes"] = b'{"action":"file:delete"}'
        with self.assertRaises(ea.EffectAgreementError) as ctx:
            ea.compute_agreement(reg, "a")
        self.assertEqual(ctx.exception.code, "effect-not-bound")

    def test_missing_decision(self):
        with self.assertRaises(ea.EffectAgreementError) as ctx:
            ea.compute_agreement({}, "nope")
        self.assertEqual(ctx.exception.code, "effect-decision-missing")

    def test_malformed_decision(self):
        with self.assertRaises(ea.EffectAgreementError):
            ea.record_decision({}, "a", {"verdict": "allow"}, now=T0)
        with self.assertRaises(ea.EffectAgreementError):
            ea.record_decision({}, "a", "not-a-mapping", now=T0)


class RegistryAcceptanceTest(unittest.TestCase):
    def test_happy(self):
        res = rg.accept_package(_manifest(3), PKG, _policy(3), now=T0 + 10)
        self.assertEqual(res["verdict"], "accept")
        self.assertEqual(res["valid_signatures"], 3)
        self.assertEqual(res["package_digest"], PKG_DIGEST)

    def test_stale(self):
        man = _manifest(3)
        with self.assertRaises(rg.RegistryAcceptanceError) as ctx:
            rg.accept_package(man, PKG, _policy(3), now=T0 + 7200)
        self.assertEqual(ctx.exception.code, "package-stale")

    def test_threshold_unmet(self):
        man = _manifest(1)
        with self.assertRaises(rg.RegistryAcceptanceError) as ctx:
            rg.accept_package(man, PKG, _policy(3), now=T0 + 10)
        self.assertEqual(ctx.exception.code, "registry-threshold-unmet")

    def test_digest_mismatch(self):
        man = _manifest(3)
        with self.assertRaises(rg.RegistryAcceptanceError) as ctx:
            rg.accept_package(man, b"other-bytes", _policy(3), now=T0 + 10)
        self.assertEqual(ctx.exception.code, "package-digest-mismatch")

    def test_bad_signature(self):
        man = _manifest(3)
        bad = copy.deepcopy(man)
        bad["signatures"][2]["sig"] = base64.b64encode(
            b"\xff" * 64).decode("ascii")
        with self.assertRaises(rg.RegistryAcceptanceError) as ctx:
            rg.accept_package(bad, PKG, _policy(2), now=T0 + 10)
        self.assertEqual(ctx.exception.code, "package-signature-invalid")

    def test_untrusted_key(self):
        other = base64.b64encode(
            _e.publickey(bytes([9]) * 32)).decode("ascii")
        man = _manifest(3)
        bad = copy.deepcopy(man)
        bad["signatures"][0]["key"] = other
        with self.assertRaises(rg.RegistryAcceptanceError) as ctx:
            rg.accept_package(bad, PKG, _policy(1), now=T0 + 10)
        self.assertEqual(ctx.exception.code, "package-signature-invalid")

    def test_key_reuse_not_double_counted(self):
        man = _manifest(2)
        dup = copy.deepcopy(man)
        dup["signatures"].append(copy.deepcopy(dup["signatures"][0]))
        with self.assertRaises(rg.RegistryAcceptanceError) as ctx:
            rg.accept_package(dup, PKG, _policy(3), now=T0 + 10)
        self.assertEqual(ctx.exception.code, "package-signature-invalid")

    def test_malformed_manifest(self):
        with self.assertRaises(rg.RegistryAcceptanceError) as ctx:
            rg.accept_package({"payload": {}}, PKG, _policy(1),
                              now=T0 + 10)
        self.assertEqual(ctx.exception.code, "package-manifest-malformed")

    def test_verify_return_checked(self):
        # Pin the wave-243 lesson: ed25519.verify returns False on a
        # forged signature (it does not raise).
        body = b"hello"
        good = _e.sign(_SEEDS[0], body)
        self.assertIs(_e.verify(_PUBS[0], body, good), True)
        forged = b"\x00" * 64
        self.assertIs(_e.verify(_PUBS[0], body, forged), False)


class McpSurfaceGuardTest(unittest.TestCase):
    def test_clean_tool_allows(self):
        res = sg.quarantine_tool_definition({
            "name": "read_file",
            "description": "read a file",
            "inputSchema": {"type": "object",
                            "properties": {
                                "path": {"type": "string"}}}},
            endpoint_public=True)
        self.assertEqual(res["verdict"], "allow")

    def test_executable_param_name(self):
        with self.assertRaises(sg.McpSurfaceGuardError) as ctx:
            sg.quarantine_tool_definition({
                "name": "x",
                "inputSchema": {"properties": {
                    "shell": {"type": "string"}}}},
                endpoint_public=True)
        self.assertEqual(ctx.exception.code, "tool-executable-content")

    def test_executable_default(self):
        with self.assertRaises(sg.McpSurfaceGuardError) as ctx:
            sg.quarantine_tool_definition({
                "name": "x",
                "inputSchema": {"properties": {
                    "post": {"type": "string",
                             "default": "import os; os.system('id')"}}}},
                endpoint_public=True)
        self.assertEqual(ctx.exception.code, "tool-executable-content")

    def test_explicit_marker(self):
        with self.assertRaises(sg.McpSurfaceGuardError) as ctx:
            sg.quarantine_tool_definition(
                {"name": "x", "x-executable": True},
                endpoint_public=True)
        self.assertEqual(ctx.exception.code, "tool-executable-content")

    def test_malformed(self):
        with self.assertRaises(sg.McpSurfaceGuardError) as ctx:
            sg.quarantine_tool_definition({"name": ""},
                                          endpoint_public=True)
        self.assertEqual(ctx.exception.code, "tool-definition-malformed")
        with self.assertRaises(sg.McpSurfaceGuardError) as ctx:
            sg.quarantine_tool_definition("nope", endpoint_public=True)
        self.assertEqual(ctx.exception.code, "tool-definition-malformed")

    def test_nested_property(self):
        with self.assertRaises(sg.McpSurfaceGuardError) as ctx:
            sg.quarantine_tool_definition({
                "name": "x",
                "inputSchema": {"properties": {
                    "opts": {"type": "object", "properties": {
                        "eval": {"type": "string"}}}}}},
                endpoint_public=True)
        self.assertEqual(ctx.exception.code, "tool-executable-content")


class TaxonomyTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        # Wave-243 lane H (W243-9 + W243-10, ADAPT patterns): 10 additive
        # codes. Pin re-pointed 788 -> 798.
        codes = ["effect-decision-contradicted", "effect-decision-missing",
                 "effect-not-bound", "package-stale",
                 "registry-threshold-unmet", "package-digest-mismatch",
                 "package-signature-invalid", "package-manifest-malformed",
                 "tool-executable-content", "tool-definition-malformed"]
        for code in codes:
            self.assertIn(code, dc.TAXONOMY)
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2045)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
