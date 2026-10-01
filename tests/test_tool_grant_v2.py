#!/usr/bin/env python3
"""Wave-271 unit tests: per-tool grant v2 enforcement refinement.

Tests the v2 gateway surface (evaluate_request / evaluate_batch /
predicate_registry_hash) at the public seam. Backward compatibility of
v1 enforce() is covered by tests/test_tool_grant.py (all green except the
two lane-local pin assertions, which the merge coordinator repoints).
"""

import unittest

from gov import ed25519
from gov import tool_grant as tg

NOW = 1791000000
SERVER_NAME = "srv"
SERVER_URI = "https://mcp.example/"
TOOL_A, TOOL_B = "tool_a", "tool_b"
MANDATE_ID = "mandate-1"
LINK_A = "sha256:" + "aa" * 32
LINK_B = "sha256:" + "bb" * 32
ISSUER_SEED = b"\x11" * 32
HOLDER_SEED = b"\x22" * 32


def make_fixture():
    mandates = {MANDATE_ID: {"version": 1}}
    issuer = tg.Issuer("sasanam-tool-as", ISSUER_SEED,
                       lambda mid: mandates.get(mid))
    holder_pub = ed25519.publickey(HOLDER_SEED)
    details = [
        {"type": tg.GRANT_TYPE, "identifier": "srv::tool_a",
         "locations": [SERVER_URI], "actions": ["call"],
         "arg_bounds": {"path": {"predicate": "prefix",
                                 "params": {"prefix": "/safe/"}}},
         "supply_chain": {"link_digest": LINK_A}, "max_calls": 5},
        {"type": tg.GRANT_TYPE, "identifier": "srv::tool_b",
         "locations": [SERVER_URI], "actions": ["call"],
         "arg_bounds": {"n": {"predicate": "max_value",
                              "params": {"max_value": 10}}},
         "supply_chain": {"link_digest": LINK_B}, "max_calls": 5},
    ]
    grant = issuer.issue(
        sub="spiffe://example/workload-1", aud=SERVER_URI,
        proof_pub=holder_pub, mandate_id=MANDATE_ID, mandate_version=1,
        details=details, lifetime_s=600, now=NOW)
    links = {"tool_a": LINK_A, "tool_b": LINK_B}
    return {
        "mandates": mandates,
        "issuer": issuer,
        "grant": grant,
        "links": links,
        "cred_dp": {"scopes": ["data-plane"]},
        "cred_admin": {"scopes": ["admin"]},
    }


def proof_for(grant, nonce):
    return tg.make_pop_proof(HOLDER_SEED, grant, method="tools/call",
                             uri=SERVER_URI, now=NOW, nonce=nonce)


def ev_kwargs(f, store, **over):
    kw = dict(issuer_pub=f["issuer"].issuer_pub, server_name=SERVER_NAME,
              server_uri=SERVER_URI, now=NOW, usage_store=store,
              mandate_version_provider=lambda mid: f["mandates"][mid]["version"],
              link_verifier=lambda tool: f["links"][tool])
    kw.update(over)
    return kw


def evaluate(f, store, tool, args, nonce, request_context=None,
             caller_cred=None, cache=None, **over):
    return tg.evaluate_request(
        f["grant"], proof=proof_for(f["grant"], nonce),
        tool=tool, args=args, request_context=request_context,
        caller_cred=caller_cred if caller_cred is not None else f["cred_dp"],
        verdict_cache=cache, **ev_kwargs(f, store, **over))


class TestRegistryHash(unittest.TestCase):
    def test_hash_stable_and_pinned(self):
        self.assertEqual(tg.predicate_registry_hash(),
                         tg.PREDICATE_REGISTRY_HASH)
        self.assertEqual(tg.predicate_registry_hash(),
                         tg.predicate_registry_hash())

    def test_hash_detects_registry_drift(self):
        tg.PREDICATE_REGISTRY["__w271_tmp__"] = lambda a, p: True
        try:
            self.assertNotEqual(tg.predicate_registry_hash(),
                                tg.PREDICATE_REGISTRY_HASH)
        finally:
            del tg.PREDICATE_REGISTRY["__w271_tmp__"]

    def test_issue_pins_hash(self):
        f = make_fixture()
        self.assertEqual(f["grant"]["body"]["predicate_registry_hash"],
                         tg.PREDICATE_REGISTRY_HASH)


class TestEvaluateRequest(unittest.TestCase):
    def test_valid_request_allows(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                     "u1")
        self.assertTrue(v["ok"])
        self.assertEqual(v["code"], "ptgrant-ok")
        self.assertIn("caller:ok", v["checked"])
        self.assertIn("mandate:reachable", v["checked"])

    def test_admin_credential_denied(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                     "u2", caller_cred=f["cred_admin"])
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-caller-unauthorized")

    def test_no_credential_denied(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                     "u3", caller_cred={})
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-caller-unauthorized")

    def test_backend_raise_denied(self):
        f = make_fixture()
        def boom(_mid):
            raise ConnectionError("store down")
        v = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                     "u4", mandate_version_provider=boom)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-mandate-unreachable")

    def test_backend_none_denied(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                     "u5", mandate_version_provider=lambda _mid: None)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-mandate-unreachable")

    def test_stale_mandate_denied(self):
        f = make_fixture()
        f["mandates"][MANDATE_ID]["version"] = 2
        v = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                     "u6")
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-mandate-drift")

    def test_registry_hash_mismatch_denied(self):
        f = make_fixture()
        tg.PREDICATE_REGISTRY["__w271_tmp__"] = lambda a, p: True
        try:
            v = evaluate(f, tg.UsageStore(), "tool_a",
                         {"path": "/safe/x"}, "u7")
        finally:
            del tg.PREDICATE_REGISTRY["__w271_tmp__"]
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-predicate-hash-mismatch")

    def test_missing_attribute_denied_with_fields(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {}, "u8")
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-arg-attribute-missing")
        self.assertIn("path", v["detail"])

    def test_context_provides_attribute(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {}, "u9",
                     request_context={"path": "/safe/x"})
        self.assertTrue(v["ok"])

    def test_context_oversize_denied(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {}, "u10",
                     request_context={"path": "/safe/x", "pad": "y" * 9000})
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-context-oversize")

    def test_context_malformed_denied(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a",
                     {"path": "/safe/x"}, "u11",
                     request_context=["not", "a", "dict"])
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-grant-malformed")

    def test_context_type_confusion_denied(self):
        f = make_fixture()
        v = evaluate(f, tg.UsageStore(), "tool_a", {}, "u12",
                     request_context={"path": 12345})
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-arg-bound-violated")

    def test_context_never_persisted(self):
        f = make_fixture()
        v1 = evaluate(f, tg.UsageStore(), "tool_a", {}, "u13a",
                      request_context={"path": "/safe/x"})
        self.assertTrue(v1["ok"])
        v2 = evaluate(f, tg.UsageStore(), "tool_a", {}, "u13b")
        self.assertFalse(v2["ok"])
        self.assertEqual(v2["code"], "ptgrant-arg-attribute-missing")

    def test_deny_cache_hit(self):
        """F278 close-when (3): legitimate deny caching still works --
        the IDENTICAL proof+context is re-denied from cache."""
        f = make_fixture()
        cache = {}
        v1 = evaluate(f, tg.UsageStore(), "tool_a", {}, "u14", cache=cache)
        self.assertFalse(v1["ok"])
        self.assertEqual(len(cache), 1)
        v2 = evaluate(f, tg.UsageStore(), "tool_a", {}, "u14", cache=cache)
        self.assertFalse(v2["ok"])
        self.assertEqual(v2["code"], "ptgrant-arg-attribute-missing")
        self.assertIn("cache:deny-hit", v2["checked"])

    def test_deny_cache_is_proof_scoped(self):
        """F278: a deny cached for one proof is NOT served to a fresh
        proof -- a fresh proof is evaluated on its own merits."""
        f = make_fixture()
        cache = {}
        v1 = evaluate(f, tg.UsageStore(), "tool_a", {}, "u14a", cache=cache)
        self.assertFalse(v1["ok"])
        v2 = evaluate(f, tg.UsageStore(), "tool_a", {}, "u14b", cache=cache)
        self.assertFalse(v2["ok"])
        self.assertEqual(v2["code"], "ptgrant-arg-attribute-missing")
        self.assertNotIn("cache:deny-hit", v2["checked"])

    def test_no_stale_allow_after_mandate_bump(self):
        f = make_fixture()
        cache = {}
        v1 = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                      "u15a", cache=cache)
        self.assertTrue(v1["ok"])
        self.assertEqual(len(cache), 0)  # allows are never cached
        f["mandates"][MANDATE_ID]["version"] = 2
        v2 = evaluate(f, tg.UsageStore(), "tool_a", {"path": "/safe/x"},
                      "u15b", cache=cache)
        self.assertFalse(v2["ok"])
        self.assertEqual(v2["code"], "ptgrant-mandate-drift")

    def test_new_codes_registered(self):
        for code in ("ptgrant-arg-attribute-missing",
                     "ptgrant-batch-tool-cap-exceeded",
                     "ptgrant-caller-unauthorized",
                     "ptgrant-context-oversize",
                     "ptgrant-mandate-unreachable",
                     "ptgrant-predicate-hash-mismatch"):
            self.assertIn(code, tg.PTGRANT_CODES)


class TestEnforceV1Compatibility(unittest.TestCase):
    """Direct enforce() without the v2 kwargs stays v1-identical."""

    def test_missing_arg_legacy_code(self):
        f = make_fixture()
        v = tg.enforce(f["grant"], proof=proof_for(f["grant"], "u16"),
                       tool="tool_a", args={},
                       **ev_kwargs(f, tg.UsageStore()))
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-arg-bound-violated")

    def test_v1_allow_unchanged(self):
        f = make_fixture()
        v = tg.enforce(f["grant"], proof=proof_for(f["grant"], "u17"),
                       tool="tool_a", args={"path": "/safe/x"},
                       **ev_kwargs(f, tg.UsageStore()))
        self.assertTrue(v["ok"])
        self.assertEqual(v["code"], "ptgrant-ok")


class TestEvaluateBatch(unittest.TestCase):
    def _items(self, f, *tools_args):
        return [{"tool": t, "args": a,
                 "proof": proof_for(f["grant"], "ub%d" % i),
                 "request_context": None}
                for i, (t, a) in enumerate(tools_args)]

    def test_batch_all_covered(self):
        f = make_fixture()
        r = tg.evaluate_batch(
            self._items(f, ("tool_a", {"path": "/safe/x"}),
                        ("tool_b", {"n": 3})),
            grant=f["grant"], caller_cred=f["cred_dp"],
            **ev_kwargs(f, tg.UsageStore()))
        self.assertTrue(all(v["ok"] for v in r["verdicts"]))
        self.assertEqual(r["snapshot"]["mandate_version"], 1)
        self.assertEqual(r["snapshot"]["predicate_registry_hash"],
                         tg.PREDICATE_REGISTRY_HASH)

    def test_batch_partial_coverage(self):
        f = make_fixture()
        r = tg.evaluate_batch(
            self._items(f, ("tool_a", {"path": "/safe/x"}),
                        ("tool_c", {})),
            grant=f["grant"], caller_cred=f["cred_dp"],
            **ev_kwargs(f, tg.UsageStore()))
        self.assertTrue(r["verdicts"][0]["ok"])
        self.assertFalse(r["verdicts"][1]["ok"])
        self.assertEqual(r["verdicts"][1]["code"],
                         "ptgrant-tool-not-covered")

    def test_batch_tool_cap(self):
        f = make_fixture()
        r = tg.evaluate_batch(
            self._items(f, ("tool_a", {"path": "/safe/x"}),
                        ("tool_b", {"n": 3}),
                        ("tool_a", {"path": "/safe/y"})),
            grant=f["grant"], caller_cred=f["cred_dp"],
            max_tools_per_request=2, **ev_kwargs(f, tg.UsageStore()))
        self.assertEqual(len(r["verdicts"]), 3)
        for v in r["verdicts"]:
            self.assertFalse(v["ok"])
            self.assertEqual(v["code"], "ptgrant-batch-tool-cap-exceeded")

    def test_batch_empty(self):
        f = make_fixture()
        r = tg.evaluate_batch([], grant=f["grant"],
                              caller_cred=f["cred_dp"],
                              **ev_kwargs(f, tg.UsageStore()))
        self.assertEqual(r["verdicts"], [])

    def test_batch_unreachable_backend(self):
        f = make_fixture()
        def boom(_mid):
            raise ConnectionError("store down")
        r = tg.evaluate_batch(
            self._items(f, ("tool_a", {"path": "/safe/x"})),
            grant=f["grant"], caller_cred=f["cred_dp"],
            mandate_version_provider=boom,
            **{k: v for k, v in ev_kwargs(f, tg.UsageStore()).items()
               if k != "mandate_version_provider"})
        self.assertFalse(r["verdicts"][0]["ok"])
        self.assertEqual(r["verdicts"][0]["code"],
                         "ptgrant-mandate-unreachable")


if __name__ == "__main__":
    unittest.main()
