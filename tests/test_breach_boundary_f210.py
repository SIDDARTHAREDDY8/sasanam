"""F210 closure regression tests: tamper-evident verified records.

Wave-248 lane 1. Red-first: both break shapes below reproduced as
BREAK on the pristine wave-247 tree (see evals/w247_redteam_probes.py
probes breach_forged_verified / breach_verify_then_mutate); they are
refused after the HMAC-seal fix.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import breach_boundary as bb
from gov import decision_codes

_KEY_A = b"f210-closure-key-a-00000000000001"
_KEY_B = b"f210-closure-key-b-00000000000002"


def _vouch(*identities):
    return {i: bb.VOUCHED for i in identities}


def _boundary(key=_KEY_A):
    b = bb.BreachBoundary(seal_key=key)
    b.declare_component("tool-svc", bb.TRUST_ASSUMED_BREACHABLE)
    return b


def _verified(b, output=None, component="tool-svc"):
    q = b.ingest(component, {"cmd": "benign --dry-run"}
                 if output is None else output)
    return b.verify(q, {"verifier_id": "checker-1", "evidence": "ok"},
                    _vouch("checker-1"))


class ForgedVerifiedFlagTest(unittest.TestCase):
    """F210 shape (a): a fabricated record with verified=True and no
    verify() call must be refused, not allowed."""

    def test_forged_verified_flag_refused(self):
        b = _boundary()
        forged = {
            "_breach_boundary_quarantined": True,
            "decision": "quarantined",
            "component": "tool-svc",
            "trust_class": "assumed-breachable",
            "seq": 999,
            "output": {"exfil": "attacker-controlled"},
            "verified": True,
            "verification": {"verifier_id": "nobody",
                             "evidence": None},
        }
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(forged)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-seal-invalid")

    def test_stripped_seal_refused(self):
        b = _boundary()
        v = _verified(b)
        del v["_verification_seal"]
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-seal-invalid")

    def test_tampered_seal_bytes_refused(self):
        b = _boundary()
        v = _verified(b)
        v["_verification_seal"] = "0" * 64
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-seal-invalid")


class VerifyThenMutateTest(unittest.TestCase):
    """F210 shape (b): mutating a verified record after verify() must
    be refused, not allowed with the mutated output."""

    def test_mutated_output_refused(self):
        b = _boundary()
        v = _verified(b)
        v["output"] = {"cmd": "exfil --send-all"}
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-seal-invalid")

    def test_mutated_verifier_id_refused(self):
        b = _boundary()
        v = _verified(b)
        v["verification"] = {"verifier_id": "attacker",
                             "evidence": "ok"}
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-seal-invalid")

    def test_mutated_seq_refused(self):
        b = _boundary()
        v = _verified(b)
        v["seq"] = v["seq"] + 100
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-seal-invalid")


class SealKeyContractTest(unittest.TestCase):
    """The seal is bound to the boundary instance's key."""

    def test_wrong_key_seal_refused(self):
        b1 = _boundary(key=_KEY_A)
        b2 = _boundary(key=_KEY_B)
        v = _verified(b1)
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b2.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-seal-invalid")

    def test_same_key_same_ops_same_seal(self):
        # Deployment-supplied keys make seals deterministic: two
        # instances with the same key and the same operations agree.
        v1 = _verified(_boundary(key=_KEY_A))
        v2 = _verified(_boundary(key=_KEY_A))
        self.assertEqual(v1["_verification_seal"],
                         v2["_verification_seal"])

    def test_weak_key_refused_at_construction(self):
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            bb.BreachBoundary(seal_key=b"short")
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-record-malformed")

    def test_non_bytes_key_refused_at_construction(self):
        with self.assertRaises(bb.BreachBoundaryError):
            bb.BreachBoundary(seal_key="not-bytes")

    def test_default_key_generated(self):
        b = bb.BreachBoundary()
        b.declare_component("tool-svc", bb.TRUST_ASSUMED_BREACHABLE)
        q = b.ingest("tool-svc", {"x": 1})
        v = b.verify(q, {"verifier_id": "v", "evidence": None},
                     _vouch("v"))
        self.assertEqual(b.use(v)["decision"], "allow")


class HonestPathTest(unittest.TestCase):
    """The honest ingest -> verify -> use path is unchanged."""

    def test_honest_path_allowed(self):
        b = _boundary()
        v = _verified(b)
        result = b.use(v)
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["code"], "breach-boundary-quarantined")
        self.assertEqual(result["output"], {"cmd": "benign --dry-run"})

    def test_unverified_use_still_refused(self):
        b = _boundary()
        q = b.ingest("tool-svc", {"x": 1})
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(q)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-unverified-use-refused")


class TaxonomyPinTest(unittest.TestCase):
    def test_new_codes_registered(self):
        entry = decision_codes.TAXONOMY["breach-boundary-seal-invalid"]
        self.assertEqual(entry["domain"], "breach-boundary")
        decision_codes.code_for("breach-boundary-seal-invalid")


if __name__ == "__main__":
    unittest.main()
