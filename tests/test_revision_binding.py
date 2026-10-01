"""Unit tests for gov/revision_binding.py and the wave-272
replay_manifest additions (chain_revision + content_equivalence).

Pin 1443 = 1443 (wave-271 merge) + 7 new codes (4 drift + 3 revbind).
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import replay_manifest as rm  # noqa: E402
from gov import revision_binding as rb  # noqa: E402

_NOW = 1700000000
_V1 = "11" * 32
_V2 = "22" * 32


def _sealed(tool_digest, chain_revision=None, equivalences=()):
    pol = rm.InMemoryPinRegistry()
    pol.register("tool-a", tool_digest)
    b = rm.ReplayManifestBuilder(
        "spiffe://test/workload", now=lambda: _NOW,
        code_pin_policy=pol, chain_revision=chain_revision)
    b.record_tool_call(tool_id="tool-a",
                       input_digest="ab" * 32, output_digest="cd" * 32,
                       tool_digest_pin=tool_digest, seed=1)
    for (tool_id, from_d, to_d, reason) in equivalences:
        b.record_content_equivalence(tool_id=tool_id, from_digest=from_d,
                                     to_digest=to_d, reason=reason)
    return b.seal()


def _resign(manifest, mutate):
    """Return a hash-CONSISTENT copy of a sealed manifest after
    applying ``mutate`` to every tool_call link: recompute link_hash
    per link and the manifest digest, so the result passes the
    cryptographic checks and exercises only the structural
    validation. Uses the module's own hash helpers (test seam)."""
    import copy
    m = copy.deepcopy(manifest)
    for link in m["links"]:
        if link.get("action") != "tool_call":
            continue
        mutate(link)
        body = {k: v for k, v in link.items() if k != "link_hash"}
        link["link_hash"] = rm._link_hash(body)
    m["manifest_digest"] = rm._sha256_hex(rm._canonical(
        {"format": m["format"], "links": m["links"],
         "code_pins": m["code_pins"]}))
    return m


class TestChainRevision(unittest.TestCase):
    def test_binding_block_on_tool_call(self):
        m = _sealed(_V1, chain_revision="rev-7")
        link = m["links"][0]
        self.assertEqual(link["action"], "tool_call")
        self.assertEqual(link["revision_binding"],
                         {"revision": "rev-7", "content_digest": _V1})

    def test_no_block_by_default(self):
        # v1 behavior preserved at default arguments.
        m = _sealed(_V1)
        self.assertNotIn("revision_binding", m["links"][0])

    def test_bad_chain_revision_refused(self):
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            rm.ReplayManifestBuilder("a", chain_revision="")
        self.assertEqual(ctx.exception.code, "replay-malformed")


class TestContentEquivalence(unittest.TestCase):
    def test_record_and_verify(self):
        m = _sealed(_V2, equivalences=[
            ("tool-a", _V1, _V2, "v1->v2 rollout")])
        link = m["links"][-1]
        self.assertEqual(link["action"], "content_equivalence")
        self.assertEqual(link["reason"], "v1->v2 rollout")
        report = rm.verify_manifest(m)
        self.assertTrue(report["verified"])

    def test_empty_reason_refused(self):
        pol = rm.InMemoryPinRegistry()
        pol.register("tool-a", _V1)
        b = rm.ReplayManifestBuilder("a", code_pin_policy=pol)
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            b.record_content_equivalence(tool_id="tool-a",
                                         from_digest=_V1,
                                         to_digest=_V2, reason="")
        self.assertEqual(ctx.exception.code, "replay-malformed")

    def test_malformed_digest_refused(self):
        pol = rm.InMemoryPinRegistry()
        pol.register("tool-a", _V1)
        b = rm.ReplayManifestBuilder("a", code_pin_policy=pol)
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            b.record_content_equivalence(tool_id="tool-a",
                                         from_digest="zzz",
                                         to_digest=_V2, reason="r")
        self.assertEqual(ctx.exception.code, "replay-malformed")


class TestPinRegistry(unittest.TestCase):
    def test_register_and_bound(self):
        reg = rb.PinRegistry()
        out = reg.register_revision("rev-7", _sealed(_V1))
        self.assertEqual(out["revision"], "rev-7")
        self.assertEqual(out["bound"], 1)
        b = reg.bound("rev-7", "tool-a", 0)
        self.assertEqual(b["content_digest"], _V1)
        self.assertIn("rev-7", reg.revisions())

    def test_tampered_manifest_not_bound(self):
        import json
        reg = rb.PinRegistry()
        m = json.loads(json.dumps(_sealed(_V1)))
        m["links"][0]["ts"] += 1
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            reg.register_revision("rev-7", m)
        self.assertEqual(ctx.exception.code, "replay-broken-chain")
        self.assertEqual(reg.revisions(), [])

    def test_bad_revision_refused(self):
        reg = rb.PinRegistry()
        with self.assertRaises(rb.RevisionBindingError) as ctx:
            reg.register_revision("", _sealed(_V1))
        self.assertEqual(ctx.exception.code, "revbind-malformed")

    def test_missing_tool_id_refused_coded(self):
        # B3: a hash-consistent manifest whose tool_call link lacks
        # tool_id must fail with a coded refusal, never an uncoded
        # KeyError at the public seam.
        m = _resign(_sealed(_V1), lambda link: link.pop("tool_id"))
        reg = rb.PinRegistry()
        with self.assertRaises(rb.RevisionBindingError) as ctx:
            reg.register_revision("rev-7", m)
        self.assertEqual(ctx.exception.code, "revbind-malformed")

    def test_malformed_revision_binding_refused(self):
        # B2: a hash-consistent manifest carrying a non-dict
        # revision_binding block is refused at verify time
        # (replay-malformed), before the registry ever sees it.
        m = _resign(_sealed(_V1),
                    lambda link: link.update(
                        {"revision_binding": "not-a-dict"}))
        with self.assertRaises(rm.ReplayManifestError) as ctx:
            rm.verify_manifest(m)
        self.assertEqual(ctx.exception.code, "replay-malformed")


class TestVerifyReplay(unittest.TestCase):
    def test_match_verifies(self):
        reg = rb.PinRegistry()
        reg.register_revision("rev-7", _sealed(_V1))
        report = rb.verify_replay(_sealed(_V1), revision="rev-7",
                                  registry=reg)
        self.assertTrue(report["verified"])
        self.assertEqual(report["held"], 1)

    def test_mismatch_refused(self):
        reg = rb.PinRegistry()
        reg.register_revision("rev-7", _sealed(_V1))
        with self.assertRaises(rb.RevisionBindingError) as ctx:
            rb.verify_replay(_sealed(_V2), revision="rev-7",
                             registry=reg)
        self.assertEqual(ctx.exception.code, "revbind-content-mismatch")

    def test_equivalence_accepted_and_reported(self):
        reg = rb.PinRegistry()
        reg.register_revision("rev-7", _sealed(_V1))
        replay = _sealed(_V2, equivalences=[
            ("tool-a", _V1, _V2, "v1->v2 rollout")])
        report = rb.verify_replay(replay, revision="rev-7",
                                  registry=reg)
        self.assertTrue(report["verified"])
        self.assertEqual(report["equivalence_accepted"], 1)
        self.assertEqual(report["detail"][0]["code"],
                         "revbind-equivalence-accepted")

    def test_wrong_from_digest_refused(self):
        reg = rb.PinRegistry()
        reg.register_revision("rev-7", _sealed(_V1))
        replay = _sealed(_V2, equivalences=[
            ("tool-a", "33" * 32, _V2, "v1->v2 rollout")])
        with self.assertRaises(rb.RevisionBindingError) as ctx:
            rb.verify_replay(replay, revision="rev-7", registry=reg)
        self.assertEqual(ctx.exception.code, "revbind-content-mismatch")

    def test_unbound_reported_not_refused(self):
        reg = rb.PinRegistry()
        report = rb.verify_replay(_sealed(_V1), revision="rev-9",
                                  registry=reg)
        self.assertTrue(report["verified"])
        self.assertEqual(report["unbound"], 1)
        self.assertEqual(report["detail"][0]["status"], "unbound")


if __name__ == "__main__":
    unittest.main()
