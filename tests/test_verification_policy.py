"""Unit tests for gov/verification_policy.py (wave-267 lane).

Pin 1231 is asserted here (lane-local); the global pin repoint is the
merge coordinator's chore per lane convention.
"""

import hashlib
import unittest

import gov.decision_packet as dp
import gov.decision_bom as bom
import gov.decision_codes as dc
import gov.verification_policy as vp


def _seed(byte):
    return bytes([byte]) * 32


def _pubkey(seed):
    import gov.ed25519 as ed
    return ed.publickey(seed).hex()


def _kid(pub):
    return hashlib.sha256(bytes.fromhex(pub)).digest()[:16].hex()


def _ident():
    return {"agent_id": "u", "role": "t", "principal": "u",
            "run_id": "w267"}


def _packet(seed, decision="allow"):
    body = dp.build_decision_packet(
        decision=decision, boundary_declared=False,
        policy_id="p", policy_version="1", policy_digest="ab" * 32,
        policy_rev_id="r1", identity=_ident(),
        bill_of_materials=bom.build_bom(
            policy_id="p", policy_version="1", policy_digest="ab" * 32,
            evidence_head_digest="GENESIS", principal=_ident()))
    return dp.sign_packet(body, seed)


def _authority(seed, **kw):
    pub = _pubkey(seed)
    auth = {"name": "a", "keys": [{"kid": _kid(pub), "pubkey": pub}],
            "threshold": 1, "transparencyLog": {"required": True},
            "attestations": []}
    auth.update(kw)
    return auth


def _doc(seed=_seed(1), **kw):
    doc = {"version": 1, "match": {"decision": "allow"},
           "authorities": [_authority(seed)],
           "policy": {"op": "eq", "path": "packetOk", "value": True},
           "mode": "enforce"}
    doc.update(kw)
    return doc


class LoadPolicyTests(unittest.TestCase):
    def test_valid_loads_with_defaults(self):
        doc = {"version": 1, "authorities": [_authority(_seed(1))]}
        pol = vp.load_policy(doc)
        self.assertEqual(pol["mode"], "enforce")
        self.assertTrue(pol["authorities"][0]["logRequired"])
        self.assertEqual(pol["authorities"][0]["threshold"], 1)

    def test_non_dict_raises_coded(self):
        with self.assertRaises(vp.VerificationPolicyError) as c:
            vp.load_policy([1, 2])
        self.assertEqual(c.exception.code, "verpol-malformed-policy")

    def test_bad_version_raises(self):
        with self.assertRaises(vp.VerificationPolicyError):
            vp.load_policy(_doc() | {"version": 2})

    def test_empty_authorities_raises(self):
        with self.assertRaises(vp.VerificationPolicyError) as c:
            vp.load_policy(_doc() | {"authorities": []})
        self.assertEqual(c.exception.code, "verpol-malformed-policy")

    def test_unknown_match_selector_raises(self):
        with self.assertRaises(vp.VerificationPolicyError):
            vp.load_policy(_doc(match={"bogus": 1}))

    def test_kid_not_hash_of_pubkey_raises(self):
        auth = _authority(_seed(1))
        auth["keys"][0]["kid"] = "ff" * 16
        with self.assertRaises(vp.VerificationPolicyError):
            vp.load_policy(_doc() | {"authorities": [auth]})

    def test_bad_mode_raises(self):
        with self.assertRaises(vp.VerificationPolicyError):
            vp.load_policy(_doc(mode="maybe"))


class PredTests(unittest.TestCase):
    def _ev(self, expr, ctx):
        return vp._eval_pred(expr, ctx)

    def test_ops(self):
        ctx = {"a": 1, "b": "hello", "c": [1, 2]}
        self.assertTrue(self._ev({"op": "eq", "path": "a",
                                  "value": 1}, ctx))
        self.assertTrue(self._ev({"op": "ne", "path": "a",
                                  "value": 2}, ctx))
        self.assertTrue(self._ev({"op": "in", "path": "a",
                                  "value": [1, 3]}, ctx))
        self.assertTrue(self._ev({"op": "gte", "path": "a",
                                  "value": 1}, ctx))
        self.assertTrue(self._ev({"op": "lte", "path": "a",
                                  "value": 1}, ctx))
        self.assertTrue(self._ev({"op": "startswith", "path": "b",
                                  "value": "hell"}, ctx))
        self.assertTrue(self._ev({"op": "present", "path": "c"},
                                 ctx))
        self.assertTrue(self._ev(
            {"op": "all", "exprs": [
                {"op": "eq", "path": "a", "value": 1},
                {"op": "present", "path": "b"}]}, ctx))
        self.assertTrue(self._ev(
            {"op": "any", "exprs": [
                {"op": "eq", "path": "a", "value": 9},
                {"op": "eq", "path": "b", "value": "hello"}]}, ctx))
        self.assertTrue(self._ev(
            {"op": "not", "expr": {"op": "eq", "path": "a",
                                   "value": 9}}, ctx))

    def test_missing_path_is_false_not_error(self):
        self.assertFalse(vp._eval_pred(
            {"op": "eq", "path": "nope.deeper", "value": 1}, {}))
        self.assertFalse(vp._eval_pred({"op": "present",
                                        "path": "nope"}, {}))


class EvaluateTests(unittest.TestCase):
    def _ok(self, **kw):
        kw.setdefault("log_lookup", lambda d: True)
        return vp.evaluate([vp.load_policy(_doc())],
                           _packet(_seed(1)), **kw)

    def test_accept(self):
        pkt = _packet(_seed(1))
        v = vp.evaluate([vp.load_policy(_doc())], pkt,
                        log_lookup=lambda d: True)
        self.assertEqual(v["verdict"], "accept")
        self.assertTrue(v["admitted"])
        self.assertIsNone(v["code"])
        self.assertEqual(v["packet_digest"], dp.packet_digest(pkt))
        self.assertEqual(len(v["evidence_digest"]), 64)
        self.assertIn("packet-verification", v["checked"])
        self.assertIn("freshness", v["out_of_scope"])

    def test_never_raises(self):
        for bad in (None, "x", 42, []):
            v = vp.evaluate([vp.load_policy(_doc())], bad,
                            log_lookup=lambda d: True)
            self.assertEqual(v["verdict"], "refuse")
        v = vp.evaluate("not-a-list", _packet(_seed(1)))
        self.assertEqual(v["verdict"], "refuse")
        self.assertEqual(v["code"], "verpol-malformed-policy")

    def test_no_match(self):
        pol = vp.load_policy(_doc(match={"decision": "deny"}))
        v = vp.evaluate([pol], _packet(_seed(1)),
                        log_lookup=lambda d: True)
        self.assertEqual(v["code"], "verpol-no-match")

    def test_digest_pin(self):
        pkt = _packet(_seed(1))
        digest = dp.packet_digest(pkt)
        pol = vp.load_policy(_doc(match={"digest": digest}))
        v = vp.evaluate([pol], pkt, log_lookup=lambda d: True)
        self.assertEqual(v["verdict"], "accept")
        pol2 = vp.load_policy(_doc(match={"digest": "00" + digest[2:]}))
        v2 = vp.evaluate([pol2], pkt, log_lookup=lambda d: True)
        self.assertEqual(v2["code"], "verpol-no-match")

    def test_warn_never_admits(self):
        pol = vp.load_policy(_doc(mode="warn"))
        v = vp.evaluate([pol], _packet(_seed(1)),
                        log_lookup=lambda d: True)
        self.assertEqual(v["verdict"], "warn")
        self.assertFalse(v["admitted"])

    def test_detail_carries_authority_errors(self):
        pol = vp.load_policy(_doc())
        v = vp.evaluate([pol], _packet(_seed(1)),
                        log_lookup=lambda d: False)
        self.assertEqual(v["code"], "verpol-log-not-anchored")
        self.assertIn("a", v["detail"]["authorityErrors"])

    def test_log_lookup_exception_is_not_anchor(self):
        def boom(d):
            raise RuntimeError("journal down")
        pol = vp.load_policy(_doc())
        v = vp.evaluate([pol], _packet(_seed(1)), log_lookup=boom)
        self.assertEqual(v["code"], "verpol-log-not-anchored")


class PinTests(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Lane-local pin: 1222 + 9 verpol-* codes. The global
        # test_decision_codes.py repoint is the merge coordinator's.
        self.assertEqual(len(dc.TAXONOMY), 1443)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).
        codes = [c for c in dc.TAXONOMY if c.startswith("verpol-")]
        self.assertEqual(len(codes), 9)


if __name__ == "__main__":
    unittest.main()
