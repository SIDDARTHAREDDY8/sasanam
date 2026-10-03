"""Unit tests for the F371 closure in gov/decision_trace.py (wave-298).

F371: verify_trace dereferenced final_decision/edges POST-signature
without validation, crashing uncoded (bare KeyError/TypeError) on
validly-signed malformed traces. The fix validates every
post-signature dereferenced shape first (reusing _check_edges) and
refuses coded decision-trace-invalid.

Contract pins:
- the four F371 shapes refuse coded decision-trace-invalid;
- well-formed signed traces still verify (regression);
- malformed PRE-signature shapes still refuse invalid (regression);
- forged traces still refuse forgery (no order-of-checks regression);
- ed25519.verify return is checked with is True / is False
  (wave-243 lesson).
"""

import copy
import unittest

from gov import decision_trace as dt
from gov import ed25519 as _ed


SEED = bytes(range(32))


def _tracer():
    return dt.DecisionTracer(SEED, "p1")


def _edges():
    return [
        {"seq": 0, "layer": "l", "rule": "r", "outcome": "pass"},
        {"seq": 1, "layer": "l", "rule": "r2", "outcome": "deny",
         "reason": "x"},
    ]


def _good_envelope(tracer=None, edges=None, verdict="DENY"):
    tracer = tracer or _tracer()
    return tracer.emit("d1", "snap1",
                       edges if edges is not None else _edges(),
                       {"a": 1}, verdict)


def _resign(tracer, body):
    return {"trace": body, "signature": tracer.sign_body(body),
            "keyid": "decision-tracer"}


class F371PostSignatureShapeTests(unittest.TestCase):
    def test_missing_verdict_refuses_invalid(self):
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        del body["final_decision"]["verdict"]
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_final_decision_not_dict_refuses_invalid(self):
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        body["final_decision"] = "DENY"
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_final_decision_none_refuses_invalid(self):
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        body["final_decision"] = None
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_edges_not_list_refuses_invalid(self):
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        body["edges"] = {"0": {}}
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_edge_missing_seq_refuses_invalid(self):
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        body["edges"] = [{"outcome": "deny"}]
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_edge_missing_outcome_refuses_invalid(self):
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        body["edges"] = [{"seq": 0, "layer": "l", "rule": "r"}]
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_edge_duplicate_seq_refuses_invalid(self):
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        body["edges"] = [
            {"seq": 0, "layer": "l", "rule": "r", "outcome": "deny"},
            {"seq": 0, "layer": "l", "rule": "r2", "outcome": "pass"},
        ]
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_nonstandard_verdict_diverges_coded(self):
        # Well-formed shape, non-standard verdict: replay divergence,
        # coded replay-mismatch -- never a crash.
        tracer = _tracer()
        body = copy.deepcopy(_good_envelope(tracer)["trace"])
        body["final_decision"] = {"verdict": "MAYBE", "code": None}
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(_resign(tracer, body), tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code,
                         "decision-trace-replay-mismatch")

    def test_empty_edges_allow_claim_diverges_coded(self):
        tracer = _tracer()
        env = _good_envelope(tracer, edges=[], verdict="ALLOW")
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(env, tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code,
                         "decision-trace-replay-mismatch")

    def test_wellformed_trace_still_verifies(self):
        tracer = _tracer()
        body = dt.verify_trace(_good_envelope(tracer), tracer.pubkey_hex,
                               expected_policy_version="p1",
                               expected_snapshot_token="snap1")
        self.assertIsInstance(body, dict)
        self.assertEqual(body["final_decision"]["verdict"], "DENY")

    def test_presignature_malformed_still_invalid(self):
        tracer = _tracer()
        env = _good_envelope(tracer)
        del env["signature"]
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(env, tracer.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-invalid")

    def test_forged_trace_still_forgery(self):
        tracer = _tracer()
        env = _good_envelope(tracer)
        other = dt.DecisionTracer(bytes([7]) * 32, "p1")
        with self.assertRaises(dt.DecisionTraceError) as ctx:
            dt.verify_trace(env, other.pubkey_hex)
        self.assertEqual(ctx.exception.code, "decision-trace-forgery")

    def test_signature_check_uses_is_true_contract(self):
        # wave-243 lesson: gov.ed25519.verify returns exact True/False.
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = env["trace"]
        sig = bytes.fromhex(env["signature"])
        pubkey = bytes.fromhex(tracer.pubkey_hex)
        from gov.decision_trace import _canonical
        self.assertIs(_ed.verify(pubkey, _canonical(body), sig), True)
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertIs(_ed.verify(pubkey, _canonical(body), bytes(bad)),
                      False)


if __name__ == "__main__":
    unittest.main()
