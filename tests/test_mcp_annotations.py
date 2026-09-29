#!/usr/bin/env python3
"""Unit tests for wave-196: keyset-attested MCP ToolAnnotations.

Public seams only:
  - gov.mcp_annotations: attest / verify / registry / classification /
    required-scope checks (normalize_* helpers are public too)
  - gov.authority_proof.check(..., mcp_tool_registry=..., token_claims=...)

Stdlib only. $0 spend. Deterministic seeds; no clock dependence.
"""

import copy
import hashlib
import os
import sys
import time
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import authority_proof as ap  # noqa: E402
from gov import mcp_annotations as ma  # noqa: E402
from gov.keyset import (  # noqa: E402
    Keyset,
    new_keyset,
    rotate_keyset,
    revoke_version,
)

READ_ONLY = {"read_only_hint": True, "destructive_hint": False,
             "idempotent_hint": True, "open_world_hint": False}
DESTRUCTIVE = {"read_only_hint": False, "destructive_hint": True,
               "idempotent_hint": False, "open_world_hint": True}

ISSUER = "https://dex.sasanam.internal"


def _seed(tag):
    return hashlib.sha256(b"mcp-annot-tests:" + tag.encode()).digest()


def _keyset(tag):
    ks, _ = new_keyset(_seed(tag), purpose=ma.ATTESTATION_PURPOSE)
    return ks


def _att(ks, seed_tag, pair="files::read", ann=None, scopes=(),
         at=1790000000, version=None):
    return ma.attest_tool_annotations(
        ks, pair, dict(READ_ONLY if ann is None else ann),
        _seed(seed_tag), required_scopes=list(scopes), at=at,
        version=version)


def _claims(exp_offset, **over):
    now = int(time.time())
    c = {"iss": ISSUER, "sub": "agent:org1:run-7",
         "aud": "sasanam-policy-engine", "iat": now - 3600,
         "exp": now + exp_offset, "jti": "token-jti-001",
         "principal": "org1", "role": "operator",
         "agent_scope": "mcp:files:read mcp:files:write"}
    c.update(over)
    return c


def _b(**kw):
    d = {"boundary_id": "u", "version": "1",
         "mcp_servers": ["files"], "mcp_tools": ["files::read"],
         "mcp_max_arg_bytes": 4096}
    d.update(kw)
    return ap.boundary_from_dict(d)


def _mcp_action(server="files", name="read", arguments=None):
    return {"tool": "mcp_call",
            "args": {"server": server, "name": name,
                     "arguments": {} if arguments is None else arguments}}


class TestNormalize(unittest.TestCase):
    def test_pair_ok(self):
        self.assertEqual(ma.normalize_pair("files::read"), "files::read")

    def test_pair_rejects(self):
        for bad in ("", "files", "files::", "::read", "a::b::c", "f*::read",
                    "fi les::read", "files::re ad", "fi\x00les::read",
                    None, 42, ["files::read"]):
            with self.assertRaises(ma.McpAnnotationError, msg=repr(bad)):
                ma.normalize_pair(bad)

    def test_annotations_ok(self):
        self.assertEqual(ma.normalize_annotations(dict(READ_ONLY)),
                         READ_ONLY)

    def test_annotations_strict_bools(self):
        for bad_val in (1, 0, "true", "false", None, [True]):
            ann = dict(READ_ONLY)
            ann["destructive_hint"] = bad_val
            with self.assertRaises(ma.McpAnnotationError,
                                   msg=repr(bad_val)):
                ma.normalize_annotations(ann)

    def test_annotations_exact_fields(self):
        ann = dict(READ_ONLY)
        ann["extra"] = True
        with self.assertRaises(ma.McpAnnotationError):
            ma.normalize_annotations(ann)
        del ann["extra"]
        del ann["open_world_hint"]
        with self.assertRaises(ma.McpAnnotationError):
            ma.normalize_annotations(ann)
        with self.assertRaises(ma.McpAnnotationError):
            ma.normalize_annotations([("read_only_hint", True)])

    def test_scopes_ok_sorted_deduped(self):
        self.assertEqual(ma.normalize_scopes(["b", "a", "a"]), ("a", "b"))
        self.assertEqual(ma.normalize_scopes([]), ())
        self.assertEqual(ma.normalize_scopes(("x",)), ("x",))

    def test_scopes_rejects(self):
        for bad in ([""], ["a b"], ["a\tb"], [None], [42], "abc", None,
                    [["a"]]):
            with self.assertRaises(ma.McpAnnotationError, msg=repr(bad)):
                ma.normalize_scopes(bad)


class TestMint(unittest.TestCase):
    def test_mint_shape(self):
        ks = _keyset("mint-shape")
        att = _att(ks, "mint-shape", scopes=["mcp:files:read"])
        self.assertEqual(att["format"], ma.ANNOTATION_FORMAT)
        self.assertEqual(att["pair"], "files::read")
        self.assertEqual(att["annotations"], READ_ONLY)
        self.assertEqual(att["required_scopes"], ["mcp:files:read"])
        self.assertEqual(att["at"], 1790000000)
        by = att["attested_by"]
        self.assertEqual(by["purpose"], ma.ATTESTATION_PURPOSE)
        self.assertEqual(by["keyset_version"], 1)
        self.assertEqual(len(by["keyset_hash"]), 64)
        env = att["envelope"]
        self.assertEqual(env["sig_key_id"], by["keyset_key_id"])
        self.assertEqual(env["sig_key_version"], 1)
        self.assertEqual(len(bytes.fromhex(env["sig"])), 64)

    def test_mint_rejects_bad_inputs(self):
        ks = _keyset("mint-bad")
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations(ks, "bad pair", READ_ONLY,
                                       _seed("mint-bad"))
        ann = dict(READ_ONLY)
        ann["destructive_hint"] = 1
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations(ks, "files::read", ann,
                                       _seed("mint-bad"))
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations(ks, "files::read", READ_ONLY,
                                       _seed("mint-bad"),
                                       required_scopes=["has space"])
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations("not-a-keyset", "files::read",
                                       READ_ONLY, _seed("mint-bad"))

    def test_mint_rejects_wrong_purpose_keyset(self):
        ks, _ = new_keyset(_seed("mint-purpose"))  # default audit purpose
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations(ks, "files::read", READ_ONLY,
                                       _seed("mint-purpose"))

    def test_mint_rejects_wrong_seed(self):
        ks = _keyset("mint-wrongseed")
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations(ks, "files::read", READ_ONLY,
                                       _seed("someone-elses-seed"))

    def test_mint_rejects_retired_versions(self):
        ks1 = _keyset("mint-ret")
        ks2, _ = rotate_keyset(ks1, _seed("mint-ret2"), _seed("mint-ret"))
        # v1 is verify-only now: its seed cannot mint anymore
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations(ks2, "files::read", READ_ONLY,
                                       _seed("mint-ret"), version=1)
        ks3 = revoke_version(ks2, 1, "test compromise", _seed("mint-ret2"))
        # v2 still active: minting still works under the new primary
        att = _att(ks3, "mint-ret2", version=2)
        ok, _ = ma.verify_tool_attestation(att, ks3.to_dict())
        self.assertTrue(ok)
        # the revoked v1 seed cannot mint
        with self.assertRaises(ma.McpAnnotationError):
            ma.attest_tool_annotations(ks3, "files::read", READ_ONLY,
                                       _seed("mint-ret"), version=1)

    def test_mint_under_new_primary_after_rotation(self):
        ks1 = _keyset("mint-rot")
        ks2, _ = rotate_keyset(ks1, _seed("mint-rot2"), _seed("mint-rot"))
        att = _att(ks2, "mint-rot2")
        self.assertEqual(att["attested_by"]["keyset_version"], 2)
        ok, info = ma.verify_tool_attestation(att, ks2.to_dict())
        self.assertTrue(ok, info)
        self.assertEqual(info["keyset_version"], 2)


class TestVerify(unittest.TestCase):
    def test_verify_ok(self):
        ks = _keyset("verify-ok")
        att = _att(ks, "verify-ok", scopes=["mcp:files:read"])
        ok, info = ma.verify_tool_attestation(att, ks.to_dict())
        self.assertTrue(ok, info)
        self.assertEqual(info["pair"], "files::read")
        self.assertEqual(info["annotations"], READ_ONLY)
        self.assertEqual(info["required_scopes"], ["mcp:files:read"])
        self.assertEqual(info["status"], "active")

    def test_verify_tampered_annotations_refused(self):
        ks = _keyset("verify-tamper")
        att = _att(ks, "verify-tamper")
        evil = copy.deepcopy(att)
        evil["annotations"]["destructive_hint"] = True
        ok, reason = ma.verify_tool_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_verify_tampered_scopes_refused(self):
        ks = _keyset("verify-tscopes")
        att = _att(ks, "verify-tscopes", scopes=["mcp:files:read"])
        evil = copy.deepcopy(att)
        evil["required_scopes"] = ["mcp:admin"]
        ok, reason = ma.verify_tool_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_verify_tampered_pair_refused(self):
        ks = _keyset("verify-tpair")
        att = _att(ks, "verify-tpair")
        evil = copy.deepcopy(att)
        evil["pair"] = "files::delete"
        ok, reason = ma.verify_tool_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_verify_rejects_bad_format(self):
        ks = _keyset("verify-format")
        att = _att(ks, "verify-format")
        evil = copy.deepcopy(att)
        evil["format"] = "sasanam-mcp-tool-annotations/v9"
        ok, reason = ma.verify_tool_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("format", reason)

    def test_verify_rejects_unknown_fields(self):
        ks = _keyset("verify-unknown")
        att = _att(ks, "verify-unknown")
        evil = copy.deepcopy(att)
        evil["server_claim"] = {"read_only_hint": True}
        ok, reason = ma.verify_tool_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("unknown fields", reason)

    def test_verify_rejects_keyset_hash_substitution(self):
        ks = _keyset("verify-sub")
        att = _att(ks, "verify-sub")
        evil = copy.deepcopy(att)
        evil["attested_by"]["keyset_hash"] = "ab" * 32
        ok, reason = ma.verify_tool_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        # the pin mismatch hits before the signature (pin is checked
        # first); either refusal is a refusal, but the pin must name it
        self.assertIn("keyset_hash", reason)

    def test_verify_rejects_broken_lineage(self):
        ks = _keyset("verify-lin")
        att = _att(ks, "verify-lin")
        ks2, _ = rotate_keyset(ks, _seed("verify-lin2"), _seed("verify-lin"))
        doc = ks2.to_dict()
        doc["rotation_lineage"][0]["sig"] = "00" * 64
        ok, reason = ma.verify_tool_attestation(att, doc)
        self.assertFalse(ok)
        self.assertIn("lineage", reason)

    def test_verify_only_still_verifies(self):
        ks1 = _keyset("verify-vo")
        att = _att(ks1, "verify-vo")
        ks2, _ = rotate_keyset(ks1, _seed("verify-vo2"), _seed("verify-vo"))
        ok, info = ma.verify_tool_attestation(att, ks2.to_dict())
        self.assertTrue(ok, info)
        self.assertEqual(info["status"], "verify-only")

    def test_revoked_refuses(self):
        ks1 = _keyset("verify-rev")
        att = _att(ks1, "verify-rev")
        ks2, _ = rotate_keyset(ks1, _seed("verify-rev2"), _seed("verify-rev"))
        ks3 = revoke_version(ks2, 1, "test compromise",
                             _seed("verify-rev2"))
        ok, reason = ma.verify_tool_attestation(att, ks3.to_dict())
        self.assertFalse(ok)
        self.assertIn("revoked", reason)

    def test_revoked_verifies_for_forensics(self):
        ks1 = _keyset("verify-for")
        att = _att(ks1, "verify-for")
        ks2, _ = rotate_keyset(ks1, _seed("verify-for2"), _seed("verify-for"))
        ks3 = revoke_version(ks2, 1, "test compromise",
                             _seed("verify-for2"))
        ok, info = ma.verify_tool_attestation(att, ks3.to_dict(),
                                              forensics=True)
        self.assertTrue(ok, info)
        self.assertEqual(info["status"], "revoked")

    def test_verify_never_raises_on_garbage(self):
        ks = _keyset("verify-garbage")
        doc = ks.to_dict()
        for bad in (None, "x", 42, [], {}, {"format": "x"}):
            ok, reason = ma.verify_tool_attestation(bad, doc)
            self.assertFalse(ok, repr(bad))
            self.assertIsInstance(reason, str)

    def test_verify_wrong_purpose_keyset_refused(self):
        ks = _keyset("verify-purp")
        att = _att(ks, "verify-purp")
        other, _ = new_keyset(_seed("verify-purp"))  # audit purpose
        ok, reason = ma.verify_tool_attestation(att, other.to_dict())
        self.assertFalse(ok)
        self.assertIn("purpose", reason)


class TestRegistry(unittest.TestCase):
    def test_build_ok(self):
        ks = _keyset("reg-ok")
        a1 = _att(ks, "reg-ok", pair="files::read",
                  scopes=["mcp:files:read"])
        a2 = _att(ks, "reg-ok", pair="search::query", ann=DESTRUCTIVE)
        reg, refused = ma.build_tool_registry([a1, a2], ks.to_dict())
        self.assertEqual(refused, [])
        self.assertEqual(set(reg), {"files::read", "search::query"})
        entry = reg["files::read"]
        self.assertEqual(entry["annotations"], READ_ONLY)
        self.assertEqual(entry["required_scopes"], ("mcp:files:read",))
        self.assertEqual(entry["attested_by"]["keyset_version"], 1)
        self.assertEqual(entry["attested_by"]["status"], "active")
        self.assertEqual(entry["at"], 1790000000)

    def test_duplicate_pair_refused_loudly(self):
        ks = _keyset("reg-dup")
        a1 = _att(ks, "reg-dup", pair="files::read", at=1790000000)
        a2 = _att(ks, "reg-dup", pair="files::read", at=1790000001)
        reg, refused = ma.build_tool_registry([a1, a2], ks.to_dict())
        self.assertEqual(set(reg), {"files::read"})
        # the FIRST attestation wins; the duplicate is refused loudly
        self.assertEqual(reg["files::read"]["at"], 1790000000)
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0][0], 1)
        self.assertIn("duplicate", refused[0][1])

    def test_bad_attestation_refused_with_index(self):
        ks = _keyset("reg-bad")
        good = _att(ks, "reg-bad", pair="files::read")
        evil = copy.deepcopy(good)
        evil["annotations"]["read_only_hint"] = False  # breaks signature
        reg, refused = ma.build_tool_registry([good, evil], ks.to_dict())
        self.assertEqual(set(reg), {"files::read"})
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0][0], 1)

    def test_revoked_attestation_refused_from_registry(self):
        ks1 = _keyset("reg-rev")
        att = _att(ks1, "reg-rev", pair="files::read")
        ks2, _ = rotate_keyset(ks1, _seed("reg-rev2"), _seed("reg-rev"))
        ks3 = revoke_version(ks2, 1, "test compromise",
                             _seed("reg-rev2"))
        reg, refused = ma.build_tool_registry([att], ks3.to_dict())
        self.assertEqual(reg, {})
        self.assertEqual(len(refused), 1)
        self.assertIn("revoked", refused[0][1])

    def test_non_list_refused(self):
        ks = _keyset("reg-nonlist")
        reg, refused = ma.build_tool_registry({"pair": "x"}, ks.to_dict())
        self.assertEqual(reg, {})
        self.assertEqual(len(refused), 1)


class TestClassify(unittest.TestCase):
    def _reg(self):
        ks = _keyset("classify")
        att = _att(ks, "classify", pair="files::read")
        reg, refused = ma.build_tool_registry([att], ks.to_dict())
        self.assertEqual(refused, [])
        return reg

    def test_attested_honored_ignores_wire_lies(self):
        reg = self._reg()
        # the server self-declares destructive for an attested
        # read-only tool: the wire lie is accepted for telemetry but
        # never influences the classification
        ann, source = ma.classify_tool(
            "files::read", reg,
            declared={"read_only_hint": False, "destructive_hint": True,
                      "idempotent_hint": False, "open_world_hint": True})
        self.assertEqual(source, "attested")
        self.assertEqual(ann, READ_ONLY)

    def test_unattested_conservative(self):
        reg = self._reg()
        ann, source = ma.classify_tool("files::delete", reg)
        self.assertEqual(source, "conservative")
        self.assertEqual(ann, ma.CONSERVATIVE_ANNOTATIONS)
        self.assertTrue(ann["destructive_hint"])
        self.assertFalse(ann["read_only_hint"])

    def test_unattested_ignores_self_declared_read_only(self):
        # the red-first gap shape: an un-attested destructive tool
        # claims read-only on the wire; the product must not believe it
        reg = self._reg()
        ann, source = ma.classify_tool(
            "files::delete", reg,
            declared={"read_only_hint": True, "destructive_hint": False,
                      "idempotent_hint": True, "open_world_hint": False})
        self.assertEqual(source, "conservative")
        self.assertTrue(ann["destructive_hint"])
        self.assertFalse(ann["read_only_hint"])

    def test_never_raises_on_hostile_input(self):
        reg = self._reg()
        for pair, registry, declared in (
                (None, reg, None), (42, reg, None), ("", reg, None),
                ("files::read", None, None), ("files::read", "x", None),
                ("evil::rm", reg, "not-a-mapping")):
            ann, source = ma.classify_tool(pair, registry, declared)
            self.assertEqual(source, "conservative", repr(pair))
            self.assertEqual(ann, ma.CONSERVATIVE_ANNOTATIONS)
        # a valid attested pair stays attested even when `declared` is
        # hostile -- the wire claim is ignored by design
        ann, source = ma.classify_tool("files::read", reg,
                                       "not-a-mapping")
        self.assertEqual(source, "attested")
        self.assertEqual(ann, READ_ONLY)


class TestRequiredScopes(unittest.TestCase):
    def _reg(self, scopes=("mcp:files:read",)):
        ks = _keyset("scopes")
        att = _att(ks, "scopes", pair="files::read", scopes=scopes)
        reg, refused = ma.build_tool_registry([att], ks.to_dict())
        self.assertEqual(refused, [])
        return reg

    def test_unattested_pair_requires_nothing(self):
        reg = self._reg()
        ok, why = ma.check_required_scopes("files::delete", reg, None)
        self.assertTrue(ok, why)

    def test_no_scopes_required_ok_without_claims(self):
        reg = self._reg(scopes=())
        ok, why = ma.check_required_scopes("files::read", reg, None)
        self.assertTrue(ok, why)

    def test_scopes_required_no_claims_refused(self):
        reg = self._reg()
        ok, why = ma.check_required_scopes("files::read", reg, None)
        self.assertFalse(ok)
        self.assertIn("mcp:files:read", why)

    def test_valid_claims_with_scope_ok(self):
        reg = self._reg()
        ok, why = ma.check_required_scopes("files::read", reg,
                                           _claims(3600))
        self.assertTrue(ok, why)

    def test_missing_scope_refused_and_named(self):
        reg = self._reg()
        claims = _claims(3600, agent_scope="mcp:files:write")
        ok, why = ma.check_required_scopes("files::read", reg, claims)
        self.assertFalse(ok)
        self.assertIn("mcp:files:read", why)

    def test_scope_match_is_exact_not_substring(self):
        reg = self._reg()
        # "mcp:files:readwrite" must NOT satisfy "mcp:files:read"
        claims = _claims(3600, agent_scope="mcp:files:readwrite")
        ok, why = ma.check_required_scopes("files::read", reg, claims)
        self.assertFalse(ok, why)

    def test_expired_claims_refused(self):
        reg = self._reg()
        ok, why = ma.check_required_scopes("files::read", reg,
                                           _claims(-7200))
        self.assertFalse(ok)
        self.assertIn("expired", why)

    def test_wrong_audience_claims_refused(self):
        reg = self._reg()
        ok, why = ma.check_required_scopes(
            "files::read", reg, _claims(3600, aud="someone-else"))
        self.assertFalse(ok)
        self.assertIn("audience", why)

    def test_malformed_claims_refused(self):
        reg = self._reg()
        for bad in (None, "x", 42, {}, {"aud": "x"}):
            ok, why = ma.check_required_scopes("files::read", reg, bad)
            self.assertFalse(ok, repr(bad))

    def test_malformed_registry_refused(self):
        for bad_reg in (None, "x", [], {"files::read": "not-a-dict"},
                        {"files::read": {"required_scopes": "mcp:x"}}):
            ok, why = ma.check_required_scopes("files::read", bad_reg,
                                               _claims(3600))
            self.assertFalse(ok, repr(bad_reg))

    def test_never_raises(self):
        reg = self._reg()
        for pair, registry, claims in (
                (None, reg, None), (42, reg, None), ("x", reg, object()),
                ("files::read", reg, object())):
            ok, why = ma.check_required_scopes(pair, registry, claims)
            self.assertIsInstance(ok, bool)
            self.assertIsInstance(why, str)


class TestCheckIntegration(unittest.TestCase):
    def _reg(self, scopes=("mcp:files:read",)):
        ks = _keyset("check-int")
        att = _att(ks, "check-int", pair="files::read", scopes=scopes)
        reg, refused = ma.build_tool_registry([att], ks.to_dict())
        self.assertEqual(refused, [])
        return reg

    def test_legacy_path_unchanged_without_registry(self):
        p = ap.check(_mcp_action(), {}, _b())
        self.assertEqual(p.verdict, ap.WITHIN)
        # token_claims alone change nothing without a registry
        p = ap.check(_mcp_action(), {}, _b(), token_claims=_claims(3600))
        self.assertEqual(p.verdict, ap.WITHIN)

    def test_in_scope_within(self):
        p = ap.check(_mcp_action(), {}, _b(),
                     mcp_tool_registry=self._reg(),
                     token_claims=_claims(3600))
        self.assertEqual(p.verdict, ap.WITHIN)

    def test_missing_scope_exceeds(self):
        p = ap.check(_mcp_action(), {}, _b(),
                     mcp_tool_registry=self._reg(),
                     token_claims=_claims(3600,
                                         agent_scope="mcp:files:write"))
        self.assertEqual(p.verdict, ap.EXCEEDS)
        self.assertEqual(p.counterexample.domain, "mcp_tools")
        self.assertEqual(p.counterexample.access, "files::read")
        self.assertIn("mcp:files:read", p.counterexample.reason)

    def test_no_claims_exceeds_when_scopes_required(self):
        p = ap.check(_mcp_action(), {}, _b(),
                     mcp_tool_registry=self._reg(), token_claims=None)
        self.assertEqual(p.verdict, ap.EXCEEDS)

    def test_expired_claims_exceeds(self):
        p = ap.check(_mcp_action(), {}, _b(),
                     mcp_tool_registry=self._reg(),
                     token_claims=_claims(-7200))
        self.assertEqual(p.verdict, ap.EXCEEDS)

    def test_unattested_pair_in_boundary_within(self):
        # attestation only tightens: an un-attested pair that IS in the
        # boundary allowlist still passes
        b2 = ap.boundary_from_dict({"boundary_id": "u", "version": "1",
                                    "mcp_servers": ["search"],
                                    "mcp_tools": ["search::query"],
                                    "mcp_max_arg_bytes": 4096})
        p = ap.check(_mcp_action(server="search", name="query"), {}, b2,
                     mcp_tool_registry=self._reg(),
                     token_claims=_claims(3600))
        self.assertEqual(p.verdict, ap.WITHIN)

    def test_malformed_registry_inconclusive(self):
        p = ap.check(_mcp_action(), {}, _b(),
                     mcp_tool_registry=["not", "a", "mapping"])
        self.assertEqual(p.verdict, ap.INCONCLUSIVE)
        self.assertIn("mcp_tool_registry", p.detail)

    def test_scope_check_after_arg_budget(self):
        # an over-budget call still fails on the budget first
        b = _b(mcp_max_arg_bytes=4)
        p = ap.check(_mcp_action(arguments={"k": "v" * 100}), {}, b,
                     mcp_tool_registry=self._reg(),
                     token_claims=_claims(3600))
        self.assertEqual(p.verdict, ap.EXCEEDS)
        self.assertIn("over the declared max", p.counterexample.reason)


if __name__ == "__main__":
    unittest.main()
