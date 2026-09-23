"""Wave-67 D5 unit tests: authenticated consumer registry for ack evidence.

Pins workstreams/evals/CONSUMER_REGISTRY.md (design + break-first):
the wave-65/66 self-attested-consumer gap is closed by mechanism —
ConsumerRegistry (deployment-scoped issuance/verification authority),
ConsumerToken (256-bit HMAC-bound bearer, non-serializable/
non-copyable), ConsumerAuthError (fail-closed, LOUD, a VettingError).

What this pins: token forge/flip/foreign refusal; cross-name theft
refusal; same-id registrations distinguished by token_id; expiry and
revocation fail-closed with append-only history; anonymous path
unchanged ("attribution": "unattributed"); invalid token never
degrades silently; token secret never serialized; record ordering
(verify -> record -> unwrap); legitimate flows byte-identical.

Deterministic (injectable clock), hermetic, $0.
"""
import copy
import os
import secrets
import pickle
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
# Wave-81: gov/ has no dev key or dev-key opt-in. Provision an EXPLICIT
# random key via the production env path (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH);
# tests/__init__.py does the same for the canonical suite -- this keeps
# direct `python tests/test_x.py` runs self-sufficient.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.sterile import (  # noqa: E402
    AckAuditSink, ConsumerAuthError, ConsumerRegistry, ConsumerToken,
    Unvetted, VettingError)


class _Clock:
    """Injectable registry clock."""
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def _reg(clock):
    return ConsumerRegistry(name="test-registry", now=clock)


class RegistryConstructionTest(unittest.TestCase):
    def test_bad_consumer_id_refused(self):
        reg = ConsumerRegistry()
        for bad in ("", None, 123, b"x"):
            with self.assertRaises(TypeError):
                reg.register_consumer(bad)

    def test_bad_ttl_refused(self):
        reg = ConsumerRegistry()
        for bad in (0, -5, True, "60"):
            with self.assertRaises(TypeError):
                reg.register_consumer("c", ttl_s=bad)

    def test_bad_registry_name_refused(self):
        with self.assertRaises(TypeError):
            ConsumerRegistry(name="")

    def test_revoke_validates_public_id(self):
        reg = ConsumerRegistry()
        with self.assertRaises(TypeError):
            reg.revoke("")
        reg.revoke("tok-unknown")  # unknown ids are a silent no-op

    def test_token_public_id_shape(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("c")
        self.assertTrue(tok.public_id.startswith("tok-"))
        self.assertEqual(tok.consumer_id, "c")


class TokenVerifyTest(unittest.TestCase):
    def test_roundtrip(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("dashboard")
        att = reg.verify(tok, "dashboard")
        self.assertEqual(att["token_id"], tok.public_id)
        self.assertEqual(att["consumer_id"], "dashboard")

    def test_forged_token_refused(self):
        # Mint "without the registry": a different registry's secret.
        reg = ConsumerRegistry()
        other = ConsumerRegistry()
        tok = other.register_consumer("dashboard")
        with self.assertRaises(ConsumerAuthError):
            reg.verify(tok, "dashboard")

    def test_bit_flip_in_bearer_refused(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("dashboard")
        flipped = bytearray(tok._bearer)
        flipped[0] ^= 0x01
        tok._bearer = bytes(flipped)
        with self.assertRaises(ConsumerAuthError):
            reg.verify(tok, "dashboard")

    def test_bit_flip_in_mac_refused(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("dashboard")
        flipped = bytearray(tok._mac)
        flipped[-1] ^= 0x80
        tok._mac = bytes(flipped)
        with self.assertRaises(ConsumerAuthError):
            reg.verify(tok, "dashboard")

    def test_tampered_consumer_id_on_token_refused(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("dashboard")
        tok._consumer_id = "root"  # MAC binds the original id
        with self.assertRaises(ConsumerAuthError):
            reg.verify(tok, "root")

    def test_cross_name_theft_refused(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("consumer-a")
        with self.assertRaises(ConsumerAuthError):
            reg.verify(tok, "consumer-b")

    def test_non_token_refused(self):
        reg = ConsumerRegistry()
        with self.assertRaises(ConsumerAuthError):
            reg.verify("not-a-token", "c")
        with self.assertRaises(ConsumerAuthError):
            reg.verify(None, "c")

    def test_expiry_enforced(self):
        clock = _Clock()
        reg = _reg(clock)
        tok = reg.register_consumer("c", ttl_s=60)
        reg.verify(tok, "c")  # fresh: fine
        clock.t += 61
        with self.assertRaises(ConsumerAuthError):
            reg.verify(tok, "c")

    def test_no_ttl_never_expires(self):
        clock = _Clock()
        reg = _reg(clock)
        tok = reg.register_consumer("c")
        clock.t += 10 ** 9
        reg.verify(tok, "c")  # no expiry configured: still valid

    def test_revocation_fails_closed(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("c")
        reg.verify(tok, "c")
        self.assertFalse(reg.is_revoked(tok.public_id))
        reg.revoke(tok.public_id)
        self.assertTrue(reg.is_revoked(tok.public_id))
        with self.assertRaises(ConsumerAuthError):
            reg.verify(tok, "c")

    def test_same_id_two_registrations_distinguished(self):
        reg = ConsumerRegistry()
        t1 = reg.register_consumer("dup")
        t2 = reg.register_consumer("dup")
        self.assertNotEqual(t1.public_id, t2.public_id)
        self.assertNotEqual(t1._bearer, t2._bearer)
        reg.verify(t1, "dup")
        reg.verify(t2, "dup")
        reg.revoke(t1.public_id)  # revoking one leaves the other valid
        with self.assertRaises(ConsumerAuthError):
            reg.verify(t1, "dup")
        reg.verify(t2, "dup")

    def test_token_not_serializable_or_copyable(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("c")
        with self.assertRaises(ConsumerAuthError):
            copy.copy(tok)
        with self.assertRaises(ConsumerAuthError):
            copy.deepcopy(tok)
        with self.assertRaises(ConsumerAuthError):
            pickle.dumps(tok)
        with self.assertRaises(ConsumerAuthError):
            tok.__reduce__()
        # The secret bearer never appears in the repr.
        self.assertNotIn(tok._bearer.hex(), repr(tok))

    def test_auth_error_is_vetting_error(self):
        # Same fail-closed family as forged vetted marks.
        self.assertTrue(issubclass(ConsumerAuthError, VettingError))


class AcknowledgeAttributionTest(unittest.TestCase):
    def test_authenticated_record_fields(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("loop-context-merge")
        sink = AckAuditSink()
        payload = {"rows": 3}
        out = Unvetted(payload, ack_context={"window": "w1",
                                             "run_id": "r1"}).acknowledge(
            "loop-context-merge", sink=sink,
            consumer_token=tok, registry=reg)
        self.assertIs(out, payload)
        rec = sink.peek_oldest()
        self.assertEqual(rec["attribution"], "authenticated")
        self.assertEqual(rec["token_id"], tok.public_id)
        self.assertEqual(rec["consumer"], "loop-context-merge")
        self.assertNotIn("bearer", str(rec))

    def test_unattributed_path_unchanged(self):
        sink = AckAuditSink()
        out = Unvetted("x").acknowledge("dash", sink=sink)
        self.assertEqual(out, "x")
        rec = sink.peek_oldest()
        self.assertEqual(rec["attribution"], "unattributed")
        self.assertNotIn("token_id", rec)
        # Legacy wave-66 fields intact.
        for k in ("event", "consumer", "origin", "ack_context",
                  "count", "ts"):
            self.assertIn(k, rec)

    def test_registry_without_token_is_unattributed(self):
        reg = ConsumerRegistry()
        sink = AckAuditSink()
        Unvetted("x").acknowledge("dash", sink=sink, registry=reg)
        self.assertEqual(sink.peek_oldest()["attribution"],
                         "unattributed")

    def test_invalid_token_raises_before_record_or_unwrap(self):
        reg = ConsumerRegistry()
        other = ConsumerRegistry()
        forged = other.register_consumer("dash")
        sink = AckAuditSink()
        marker = Unvetted("secret-payload")
        with self.assertRaises(ConsumerAuthError):
            marker.acknowledge("dash", sink=sink,
                               consumer_token=forged, registry=reg)
        self.assertEqual(sink.pending(), 0)  # no record appended
        # The payload never left the marker: a raising sink still
        # withholds it, and here the failure came even earlier.
        self.assertEqual(marker._payload, "secret-payload")

    def test_token_without_registry_raises_loud(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("dash")
        with self.assertRaises(ConsumerAuthError):
            Unvetted("x").acknowledge("dash", consumer_token=tok)

    def test_non_registry_object_rejected(self):
        with self.assertRaises(TypeError):
            Unvetted("x").acknowledge("dash", registry="not-a-registry")

    def test_sink_none_authenticated_still_marks(self):
        # sink=None is the caller's explicit no-record choice; the
        # unwrap itself still went through verification.
        reg = ConsumerRegistry()
        tok = reg.register_consumer("dash")
        out = Unvetted("x").acknowledge("dash", sink=None,
                                        consumer_token=tok, registry=reg)
        self.assertEqual(out, "x")

    def test_two_registrations_same_id_records_distinguish(self):
        reg = ConsumerRegistry()
        t1 = reg.register_consumer("dup")
        t2 = reg.register_consumer("dup")
        sink = AckAuditSink()
        # Distinct ack_contexts: identical (consumer, origin, context)
        # keys would coalesce under the wave-65 duplicate rule.
        Unvetted("a", ack_context={"seq": 1}).acknowledge(
            "dup", sink=sink, consumer_token=t1, registry=reg)
        Unvetted("b", ack_context={"seq": 2}).acknowledge(
            "dup", sink=sink, consumer_token=t2, registry=reg)
        recs = [sink.pop_oldest(), sink.pop_oldest()]
        self.assertNotEqual(recs[0]["token_id"], recs[1]["token_id"])
        self.assertEqual(recs[0]["token_id"], t1.public_id)
        self.assertEqual(recs[1]["token_id"], t2.public_id)

    def test_revoked_token_ack_refused_record_absent(self):
        reg = ConsumerRegistry()
        tok = reg.register_consumer("dash")
        sink = AckAuditSink()
        reg.revoke(tok.public_id)
        with self.assertRaises(ConsumerAuthError):
            Unvetted("x").acknowledge("dash", sink=sink,
                                      consumer_token=tok, registry=reg)
        self.assertEqual(sink.pending(), 0)

    def test_expired_token_ack_refused(self):
        clock = _Clock()
        reg = _reg(clock)
        tok = reg.register_consumer("dash", ttl_s=10)
        sink = AckAuditSink()
        clock.t += 11
        with self.assertRaises(ConsumerAuthError):
            Unvetted("x").acknowledge("dash", sink=sink,
                                      consumer_token=tok, registry=reg)
        self.assertEqual(sink.pending(), 0)


_DRAIN_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
policies: []
"""


def _drain_run():
    import tempfile
    d = tempfile.mkdtemp(prefix="w67-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_DRAIN_POLICY)
    run = harness.make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _ack_events(run):
    return [e for e in log_mod.read_entries(run["log"].path)
            if e.get("event") == "unvetted_acknowledged"]


class DrainIntegrationTest(unittest.TestCase):
    """Attribution fields survive the executor drain into the chain."""

    def test_authenticated_ack_chains_with_token_id(self):
        run, ident = _drain_run()
        reg = ConsumerRegistry()
        tok = reg.register_consumer("loop-context-merge")
        sink = AckAuditSink()
        Unvetted([1, 2], ack_context={"window": "w1",
                                      "run_id": "r1"}).acknowledge(
            "loop-context-merge", sink=sink,
            consumer_token=tok, registry=reg)
        n = run["executor"].drain_ack_sink(
            sink, agent_id="agent-1", role="researcher")
        self.assertEqual(n, 1)
        evs = _ack_events(run)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["attribution"], "authenticated")
        self.assertEqual(evs[0]["token_id"], tok.public_id)
        # Executor reserved keys still log-wins.
        self.assertEqual(evs[0]["run_id"], run["executor"].run_id)
        self.assertTrue(log_mod.verify_chain(run["log"].path))

    def test_legacy_unattributed_ack_still_chains(self):
        run, ident = _drain_run()
        sink = AckAuditSink()
        Unvetted("x").acknowledge("dash", sink=sink)
        n = run["executor"].drain_ack_sink(sink)
        self.assertEqual(n, 1)
        evs = _ack_events(run)
        self.assertEqual(evs[0]["attribution"], "unattributed")
        self.assertNotIn("token_id", evs[0])
        self.assertTrue(log_mod.verify_chain(run["log"].path))


if __name__ == "__main__":
    unittest.main()
