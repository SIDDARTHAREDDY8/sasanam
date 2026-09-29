"""Unit tests for gov.capability_grants (wave-202 lane E).

Value layer, policy binding, derivation, registry semantics, and the
decision-BOM wiring. Nothing here spawns the sandbox; the real-boundary
probes live in evals/capability_grant_probes.py.
"""

import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.capability_grants import (
    Capability, Handle, GrantSet, GrantPolicy, GrantRegistry,
    GrantDispatcher, GrantError, GrantRefused, GrantMintError,
    derive_grants, bom_grants_section, verify_grant_digest,
)
from gov.decision_bom import build_bom, check_bom_shape

_HEX64 = "ab" * 32


def _policy(tmp):
    fsroot = os.path.join(tmp, "fs")
    os.makedirs(fsroot)
    with open(os.path.join(fsroot, "a.txt"), "w") as f:
        f.write("alpha")
    p = GrantPolicy(fs_root=fsroot)
    p.bind_file("read-a", "a.txt", {"read"})
    p.bind_net("api", "API.Example.com", {"connect"}, response=b"canned")
    p.bind_credential("tok", "pay:refund", {"use"},
                      sentinel_id="secret-id:pay:refund")
    return p, fsroot


class CapabilityTests(unittest.TestCase):
    def test_file_kind_requires_rights(self):
        with self.assertRaises(GrantError):
            Capability("file", "/x", {"execute"})
        with self.assertRaises(GrantError):
            Capability("file", "/x", set())

    def test_net_host_is_lowercased(self):
        c = Capability("net", "API.Example.COM", {"connect"})
        self.assertEqual(c.resource, "api.example.com")

    def test_attenuate_never_widens(self):
        c = Capability("file", "/x", {"read", "write"})
        n = c.attenuate({"read"})
        self.assertEqual(n.rights, frozenset({"read"}))
        self.assertTrue(n.is_subset_of(c))
        self.assertFalse(c.is_subset_of(n))
        with self.assertRaises(GrantError):
            c.attenuate(set())
        with self.assertRaises(GrantError):
            c.attenuate({"execute"})

    def test_digest_is_deterministic(self):
        a = GrantSet([Capability("file", "/x", {"read", "write"})])
        b = GrantSet([Capability("file", "/x", {"write", "read"})])
        self.assertEqual(a.digest(), b.digest())


class GrantSetTests(unittest.TestCase):
    def test_hand_built_has_no_id(self):
        gs = GrantSet([Capability("file", "/x", {"read"})])
        self.assertIsNone(gs.grant_id)
        self.assertIsNotNone(gs.digest())

    def test_attenuate_and_subset(self):
        base = GrantSet([Capability("file", "/x", {"read", "write"}),
                         Capability("net", "h", {"connect"})])
        sub = base.attenuate(lambda c: c.kind == "file")
        self.assertEqual(len(sub), 1)
        self.assertTrue(sub.is_subset_of(base))
        self.assertFalse(base.is_subset_of(sub))

    def test_lookup_token(self):
        base = GrantSet([Capability("file", "/x", {"read"})])
        cap = base.lookup_token("h1")
        self.assertEqual(cap.kind, "file")
        with self.assertRaises(GrantRefused):
            base.lookup_token("h9")

    def test_narrowed_subset(self):
        # The attenuation ordering: a read-only narrowing of a
        # read+write grant IS a subset (frozenset inclusion alone
        # would wrongly refuse every narrowed delegation).
        parent = GrantSet([Capability("file", "/x", {"read", "write"})])
        narrow = GrantSet([Capability("file", "/x", {"read"})])
        self.assertTrue(narrow.is_subset_of(parent))
        self.assertFalse(parent.is_subset_of(narrow))
        other = GrantSet([Capability("file", "/y", {"read"})])
        self.assertFalse(other.is_subset_of(parent))

    def test_value_equality(self):
        a = Capability("file", "/x", {"read", "write"})
        b = Capability("file", "/x", {"write", "read"})
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        gs = GrantSet([a, b])
        self.assertEqual(len(gs), 1)  # identical caps dedupe


class GrantPolicyTests(unittest.TestCase):
    def test_unbound_label_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            with self.assertRaises(GrantError):
                p.resolve("filesystem", "no-such-label")
            with self.assertRaises(GrantError):
                p.resolve("egress", "no-such-label")
            with self.assertRaises(GrantError):
                p.resolve("secrets", "no-such-label")

    def test_file_pinned_under_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, fs = _policy(tmp)
            cap = p.resolve("file", "read-a")
            self.assertEqual(cap.resource, os.path.join(fs, "a.txt"))
            self.assertEqual(p.staged_payload(cap), b"alpha")
            # Manifest category names are NOT policy kinds: derivation
            # is the only path from a manifest label to a capability.
            # Passing one to resolve() is a programming error (loud).
            with self.assertRaises(GrantError):
                p.resolve("filesystem", "read-a")
            p2 = GrantPolicy(fs_root=os.path.join(tmp, "fs"))
            with self.assertRaises(GrantError):
                p2.bind_file("evil", "../outside.txt", {"read"})

    def test_credential_is_sentinel_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            cap = p.resolve("credential", "tok")
            # The staged credential payload is the sentinel id as bytes;
            # real secrets never live in the policy.
            self.assertEqual(p.staged_payload(cap),
                             b"secret-id:pay:refund")


class RegistryTests(unittest.TestCase):
    def test_mint_consume_single_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            reg = GrantRegistry()
            caps = [p.resolve("file", "read-a")]
            gs = reg.mint(caps, decision_id="d1")
            self.assertIsNotNone(gs.grant_id)
            back = reg.consume(gs.grant_id, decision_id="d1")
            self.assertEqual(back.digest(), gs.digest())
            with self.assertRaises(GrantRefused):
                reg.consume(gs.grant_id, decision_id="d1")
            kinds = [e["reason"] for e in reg.refusals]
            self.assertIn("grant-already-consumed", kinds)

    def test_consume_unknown_and_wrong_decision(self):
        reg = GrantRegistry()
        with self.assertRaises(GrantRefused):
            reg.consume("grant-nope", decision_id="d1")
        reg2 = GrantRegistry()
        gs = reg2.mint([], decision_id="d1")
        with self.assertRaises(GrantRefused):
            reg2.consume(gs.grant_id, decision_id="d2")

    def test_refuse_appends_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "a.jsonl")
            from gov.log import ActionLog
            old_k, old_e = (os.environ.get("GOV_LOG_KEY"),
                            os.environ.get("GOV_LOG_KEY_EPOCH"))
            os.environ["GOV_LOG_KEY"] = "capgrant-unit-key"
            os.environ["GOV_LOG_KEY_EPOCH"] = "unit"
            try:
                log = ActionLog(log_path)
                reg = GrantRegistry(audit_log=log)
                reg.refuse(decision_id="d1",
                           reason="unit-test-refusal",
                           detail={"grant_id": "g1"})
                self.assertEqual(len(reg.refusals), 1)
                types = set()
                with open(log_path, encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            types.add(json.loads(line)["type"])
                self.assertIn("capability_grant_refusal", types)
            finally:
                for k, v in (("GOV_LOG_KEY", old_k),
                             ("GOV_LOG_KEY_EPOCH", old_e)):
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v


class DeriveTests(unittest.TestCase):
    def test_maps_categories(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            reg = GrantRegistry()
            gs, allow = derive_grants(
                verified_manifest={
                    "skill_id": "s",
                    "capabilities": {
                        "filesystem": ["read-a"],
                        "egress": ["api"],
                        "secrets": ["tok"],
                        "tools": ["tool_reader"],
                    }},
                grant_policy=p,
                approval={"approval_id": "a1",
                          "record_digest": _HEX64},
                decision_id="d1", registry=reg)
            self.assertEqual(len(gs), 3)
            self.assertEqual(allow, frozenset({"tool_reader"}))

    def test_unknown_category_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            reg = GrantRegistry()
            with self.assertRaises(GrantRefused):
                derive_grants(
                    verified_manifest={
                        "skill_id": "s",
                        "capabilities": {"env": ["HOME"]}},
                    grant_policy=p,
                    approval={"approval_id": "a1",
                              "record_digest": _HEX64},
                    decision_id="d1", registry=reg)

    def test_bad_approval_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            reg = GrantRegistry()
            manifest = {"skill_id": "s",
                        "capabilities": {"filesystem": ["read-a"]}}
            with self.assertRaises(GrantMintError):
                derive_grants(verified_manifest=manifest, grant_policy=p,
                              approval={"approval_id": "a1"},
                              decision_id="d1", registry=reg)
            with self.assertRaises(GrantMintError):
                derive_grants(verified_manifest=manifest, grant_policy=p,
                              approval=None, decision_id="d1",
                              registry=reg)

    def test_approval_packet_exact_binding(self):
        # The grant binds to the EXACT approval packet when the caller
        # supplies the records: the packet's own digest must equal the
        # supplied record_digest.
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            old_k, old_e = (os.environ.get("GOV_LOG_KEY"),
                            os.environ.get("GOV_LOG_KEY_EPOCH"))
            os.environ["GOV_LOG_KEY"] = "capgrant-packet-key"
            os.environ["GOV_LOG_KEY_EPOCH"] = "unit"
            try:
                from gov.approvals import approval_record_digest
                rec = {"approval_id": "a1", "tool": "read_file",
                       "args": {"path": "a.txt"}}
                digest = approval_record_digest(rec)
                manifest = {"skill_id": "s",
                            "capabilities": {"filesystem": ["read-a"]}}
                approval = {"approval_id": "a1",
                            "record_digest": digest}
                # 1. exact packet: mints.
                reg = GrantRegistry()
                gs, _a = derive_grants(
                    verified_manifest=manifest, grant_policy=p,
                    approval=approval, decision_id="d1", registry=reg,
                    approval_records={"a1": rec})
                self.assertEqual(len(gs), 1)
                # 2. tampered packet: refused loud + audit-logged.
                reg2 = GrantRegistry()
                with self.assertRaises(GrantRefused):
                    derive_grants(
                        verified_manifest=manifest, grant_policy=p,
                        approval=approval, decision_id="d2",
                        registry=reg2,
                        approval_records={"a1": dict(rec, tool="evil")})
                self.assertIn("approval-record-digest-mismatch",
                              [e["reason"] for e in reg2.refusals])
                # 3. unresolvable id: refused loud.
                reg3 = GrantRegistry()
                with self.assertRaises(GrantRefused):
                    derive_grants(
                        verified_manifest=manifest, grant_policy=p,
                        approval=approval, decision_id="d3",
                        registry=reg3, approval_records={})
                self.assertIn("approval-record-unresolvable",
                              [e["reason"] for e in reg3.refusals])
                # 4. shape-only mode (no records): still mints.
                reg4 = GrantRegistry()
                gs4, _a4 = derive_grants(
                    verified_manifest=manifest, grant_policy=p,
                    approval={"approval_id": "a1",
                              "record_digest": "ab" * 32},
                    decision_id="d4", registry=reg4)
                self.assertEqual(len(gs4), 1)
            finally:
                for k, v in (("GOV_LOG_KEY", old_k),
                             ("GOV_LOG_KEY_EPOCH", old_e)):
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

    def test_verify_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _fs = _policy(tmp)
            reg = GrantRegistry()
            gs, _a = derive_grants(
                verified_manifest={"skill_id": "s",
                                   "capabilities": {
                                       "filesystem": ["read-a"]}},
                grant_policy=p,
                approval={"approval_id": "a1",
                          "record_digest": _HEX64},
                decision_id="d1", registry=reg)
            described = reg.describe_grants(gs.grant_id)
            self.assertTrue(verify_grant_digest(gs.digest(), described))
            self.assertFalse(verify_grant_digest("00" * 32, described))


class BomWiringTests(unittest.TestCase):
    def _bom_kwargs(self, tool_grants=None):
        return dict(policy_id="p", policy_version="1",
                    policy_digest=_HEX64,
                    evidence_head_digest="cd" * 32,
                    principal={"agent_id": "a", "role": "r",
                               "principal": "p", "run_id": "r"},
                    tool_grants=tool_grants)

    def test_absent_grants_byte_identical(self):
        b1 = build_bom(**self._bom_kwargs())
        b2 = build_bom(**self._bom_kwargs())
        self.assertEqual(json.dumps(b1, sort_keys=True),
                         json.dumps(b2, sort_keys=True))
        self.assertNotIn("grants", b1["inputs"])
        self.assertTrue(check_bom_shape(b1)[0])

    def test_grants_section_shape(self):
        section = {"grant_digest": _HEX64, "decision_id": "d1",
                   "capability_count": 2}
        bom = build_bom(**self._bom_kwargs(tool_grants=section))
        ok, reason = check_bom_shape(bom)
        self.assertTrue(ok, reason)
        self.assertEqual(bom["inputs"]["grants"]["capability_count"], 2)

    def test_partial_section_refuses(self):
        with self.assertRaises(Exception):
            build_bom(**self._bom_kwargs(
                tool_grants={"grant_digest": _HEX64}))
        # A tampered section fails the shape check.
        bom = build_bom(**self._bom_kwargs(tool_grants={
            "grant_digest": _HEX64, "decision_id": "d1",
            "capability_count": 1}))
        bom["inputs"]["grants"]["grant_digest"] = "not-hex"
        ok, reason = check_bom_shape(bom)
        self.assertFalse(ok)
        self.assertIn("grant_digest", reason)

    def _grant_bom(self):
        from gov.decision_bom import build_bom
        from gov.capability_grants import bom_grants_section
        gs = GrantSet([Capability("file", "/a", {"read"}),
                       Capability("net", "h", {"connect"})])
        section = bom_grants_section(
            grant_digest=gs.digest(), decision_id="d-grant",
            capability_count=len(gs))
        bom = build_bom(**self._bom_kwargs(tool_grants=section))
        return bom, gs.describe()

    def test_verify_bom_rederives_grant_digest(self):
        from gov.decision_bom import verify_bom
        bom, specs = self._grant_bom()
        ok, reason = verify_bom(bom, grant_capability_specs=specs)
        self.assertTrue(ok, reason)
        self.assertIn("grants", reason)

    def test_verify_bom_tampered_grant_digest_fails(self):
        from gov.decision_bom import verify_bom
        bom, specs = self._grant_bom()
        bom["inputs"]["grants"]["grant_digest"] = _HEX64
        ok, reason = verify_bom(bom, grant_capability_specs=specs)
        self.assertFalse(ok)
        self.assertIn("grant digest", reason)

    def test_verify_bom_wrong_specs_fail(self):
        from gov.decision_bom import verify_bom
        bom, _specs = self._grant_bom()
        wrong = [{"kind": "file", "resource": "/b",
                  "rights": ["read"]}]
        ok, reason = verify_bom(bom, grant_capability_specs=wrong)
        self.assertFalse(ok)

    def test_verify_bom_grants_unverified_without_specs(self):
        from gov.decision_bom import verify_bom
        bom, _specs = self._grant_bom()
        # No artifacts at all: provenance unverified, fail-closed.
        ok, reason = verify_bom(bom)
        self.assertFalse(ok)
        self.assertIn("UNVERIFIED", reason)


if __name__ == "__main__":
    unittest.main()
