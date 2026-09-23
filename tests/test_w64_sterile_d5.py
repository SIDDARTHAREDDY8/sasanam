"""Wave-64 D5 unit tests: typed unvetted marker for the reissue pipe.

Pins workstreams/evals/STERILE_D5_REPORT.md (design + break-first):
Unvetted wrapper semantics, the JSON serialization boundary, the
mint-gated Vetted marker, and the executor's producer-boundary wrap
on both reissue paths (close + expiry) with the legitimate flow
unchanged (Wave-49 lesson).

Deterministic, hermetic (make_run temp dirs), $0.
"""
import copy
import json
import os
import pickle
import sys
import tempfile
import time
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
os.environ.setdefault("GOV_DEV_KEYS", "1")

from gov.log import enable_dev_keys  # noqa: E402
enable_dev_keys()

from gov.sterile import (  # noqa: E402
    LoopContract, Unvetted, Vetted, VettingCapability, VettingError,
    VettingStack)


class UnvettedConfusionTest(unittest.TestCase):
    """The wrapper never silently behaves like its payload."""

    def test_confusion_paths_raise(self):
        u = Unvetted([{"result_summary": "s"}], origin="reissue_reads")
        for fn in (lambda: list(u), lambda: iter(u), lambda: u[0],
                   lambda: len(u), lambda: "x" in u, lambda: bool(u)):
            with self.assertRaises(TypeError):
                fn()

    def test_equality_is_fail_closed(self):
        payload = [{"result_summary": "s"}]
        self.assertFalse(Unvetted(payload) == payload)
        self.assertTrue(Unvetted(payload) != payload)

    def test_acknowledge_contract(self):
        u = Unvetted([1, 2], origin="reissue_reads")
        sink = []
        self.assertEqual(u.acknowledge("review-tool", sink), [1, 2])
        # Wave-65 additive evolution: the record gains ack_context
        # (correlation), count (coalescing), and ts (ack time). The
        # wave-64 contract fields are unchanged (pinned below); the
        # new fields are additive-only — no reader of the old shape
        # breaks.
        self.assertEqual(len(sink), 1)
        rec = sink[0]
        for k, v in (("event", "unvetted_acknowledged"),
                     ("consumer", "review-tool"),
                     ("origin", "reissue_reads")):
            self.assertEqual(rec[k], v)
        self.assertEqual(rec["ack_context"], {})
        self.assertEqual(rec["count"], 1)
        self.assertIn("ts", rec)

    def test_acknowledge_requires_consumer_id(self):
        u = Unvetted([1])
        with self.assertRaises(TypeError):
            u.acknowledge("")
        with self.assertRaises(TypeError):
            u.acknowledge(None)

    def test_origin_defaults(self):
        self.assertEqual(Unvetted([1]).origin, "reissue_reads")

    def test_repr_hides_payload(self):
        secret = "AKIA-SECRET-XYZ in a summary"
        r = repr(Unvetted([{"result_summary": secret}]))
        self.assertNotIn(secret, r)
        self.assertIn("Unvetted", r)

    def test_deliberate_bypass_reachable_advisory(self):
        # Pins the honest grading: deliberate attribute access
        # reaches the payload in CPython. The marker is advisory
        # against hostile in-process consumers (F59 family), a real
        # gate against confused ones.
        u = Unvetted([{"result_summary": "s"}])
        self.assertEqual(u._payload, [{"result_summary": "s"}])


class UnvettedSerializationTest(unittest.TestCase):
    """The JSON boundary: marker survives honest round-trips;
    erasure is fail-closed, never fail-open."""

    def test_envelope_roundtrip_remarks(self):
        payload = [{"tool": "api_call", "result_summary": "s"}]
        env = Unvetted(payload, origin="reissue_reads").to_envelope()
        u = Unvetted.from_envelope(json.loads(json.dumps(env)))
        self.assertIsInstance(u, Unvetted)
        self.assertEqual(u.origin, "reissue_reads")
        self.assertEqual(u.acknowledge("t"), payload)

    def test_stripped_key_still_unvetted(self):
        env = Unvetted([1]).to_envelope()
        env.pop("__gov_unvetted__")
        u = Unvetted.from_envelope(env)
        self.assertIsInstance(u, Unvetted)
        self.assertEqual(u.origin, "unmarked-erased")

    def test_pred5_plain_values_decode_unvetted(self):
        for v in ([{"a": 1}], "plain", 42, None):
            u = Unvetted.from_envelope(v)
            self.assertIsInstance(u, Unvetted)
            self.assertEqual(u.acknowledge("t"), v)

    def test_non_json_input_loud(self):
        with self.assertRaises(TypeError):
            Unvetted.from_envelope(object())

    def test_inner_forged_vetted_key_inert(self):
        # A __gov_vetted__-looking key nested in payload is data;
        # Vetted.from_envelope needs the top-level key AND a live
        # capability.
        env = Unvetted([{"__gov_vetted__": True, "payload": "X"}])
        env = env.to_envelope()
        u = Unvetted.from_envelope(json.loads(json.dumps(env)))
        inner = u.acknowledge("t")[0]
        self.assertTrue(inner["__gov_vetted__"])
        with self.assertRaises(VettingError):
            Vetted.from_envelope(inner, VettingStack(), None)

    def test_vetted_claim_without_capability_decodes_unvetted(self):
        st = VettingStack("s")
        venv = st.vet({"d": 1}, st.issue_capability("p")).to_envelope()
        u = Unvetted.from_envelope(json.loads(json.dumps(venv)))
        self.assertIsInstance(u, Unvetted)
        self.assertNotIsInstance(u, Vetted)


class VettedMintTest(unittest.TestCase):
    """The positive mark is mint-gated: untrusted code cannot forge."""

    def test_direct_construction_refused(self):
        with self.assertRaises(TypeError):
            Vetted({"x": 1})

    def test_vet_requires_issued_capability(self):
        st = VettingStack("defense")
        with self.assertRaises(VettingError):
            st.vet({"x": 1}, VettingCapability(b"\x00" * 32))
        with self.assertRaises(VettingError):
            st.vet({"x": 1}, "trust me")
        other = VettingStack("other")
        with self.assertRaises(VettingError):
            other.vet({"x": 1}, st.issue_capability("p"))

    def test_capability_not_duplicable(self):
        cap = VettingStack("s").issue_capability("p")
        with self.assertRaises(VettingError):
            copy.copy(cap)
        with self.assertRaises(VettingError):
            copy.deepcopy(cap)
        with self.assertRaises(VettingError):
            pickle.dumps(cap)

    def test_envelope_decode_checks_mint_id(self):
        st = VettingStack("s")
        cap = st.issue_capability("p")
        venv = st.vet({"d": 1}, cap).to_envelope()
        other_cap = st.issue_capability("q")
        with self.assertRaises(VettingError):
            Vetted.from_envelope(venv, st, other_cap)
        with self.assertRaises(VettingError):
            Vetted.from_envelope(venv, st, None)
        with self.assertRaises(VettingError):
            Vetted.from_envelope(Unvetted([1]).to_envelope(), st, cap)

    def test_legitimate_mint_roundtrip(self):
        st = VettingStack("defense")
        cap = st.issue_capability("human-review")
        v = st.vet({"d": 1}, cap)
        self.assertEqual(v.payload, {"d": 1})
        self.assertEqual(v.stack, "defense")
        self.assertEqual(v.mint_id, cap.public_id)
        v2 = Vetted.from_envelope(json.loads(json.dumps(v.to_envelope())),
                                  st, cap)
        self.assertIsInstance(v2, Vetted)
        self.assertEqual(v2.payload, {"d": 1})

    def test_secret_token_never_serializes(self):
        st = VettingStack("s")
        cap = st.issue_capability("p")
        blob = json.dumps(st.vet({"d": 1}, cap).to_envelope())
        self.assertNotIn(cap._token.hex(), blob)
        self.assertIn(cap.public_id, blob)

    def test_vetted_wrapper_stays_visible(self):
        st = VettingStack("s")
        secret = "vetted-payload-ZZZ9q"
        v = st.vet([secret], st.issue_capability("p"))
        with self.assertRaises(TypeError):
            list(v)
        self.assertEqual(v.payload, [secret])
        self.assertNotIn(secret, repr(v))


class FakeLoop(LoopContract):
    def __init__(self):
        self.reissued = None

    def freeze_context(self, snapshot_ref):
        return None

    def withhold(self, channel):
        return None

    def release(self, channel):
        return None

    def reissue_reads(self, reads):
        self.reissued = list(reads)
        return [{"tool": t, "channel": c, "result_summary": "reissued",
                 "delta_vs_snapshot": False} for t, c in reads]


_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
critical_windows:
  - id: pay
    on_tools: ["http_post"]
    suspend: [web_fetch]
    close_policy: agent_declared
    max_duration_s: 300
    rationale: "test"
policies: []
"""


def _run():
    from harness import make_run  # noqa: E402
    d = tempfile.mkdtemp(prefix="w64d5-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_POLICY)
    run = make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _exit_deltas(run):
    from gov.log import read_entries  # noqa: E402
    exits = [e for e in read_entries(run["log"].path)
             if e.get("event") == "sterile_window_exit"]
    return [e for e in exits if e.get("post_window_delta")]


class ExecutorWrapTest(unittest.TestCase):
    """The executor wraps the reissue return at the producer boundary
    (close + expiry); the legitimate flow is unchanged."""

    def _drive_window(self, run, ident):
        ex = run["executor"]
        ex.attach_loop_contract(FakeLoop())
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "api_call", endpoint="https://synthetic.local/v1",
                params={"q": 1})
        for rec in ex.approvals.pending():
            ex.approvals.decide(rec["id"], True, "test")

    def test_close_path_enveloped(self):
        run, ident = _run()
        self._drive_window(run, ident)
        out = run["executor"].request_window_close(ident)
        self.assertTrue(out["closed"])
        # Wave-49 lesson: the return shape is unchanged.
        self.assertEqual(out["reconcile"], [("api_call", "web_fetch")])
        deltas = _exit_deltas(run)
        self.assertEqual(len(deltas), 1)
        delta = deltas[0]["post_window_delta"]
        self.assertIsInstance(delta, dict)
        self.assertTrue(delta.get("__gov_unvetted__"))
        u = Unvetted.from_envelope(delta)
        self.assertEqual(u.acknowledge("t")[0]["tool"], "api_call")
        # R4 invariant intact.
        self.assertFalse(deltas[0]["reconciled_vetted"])
        # The stored event is JSON-safe with NO default=str fallback:
        # no live Unvetted object leaked into the audit record.
        json.dumps(deltas[0])

    def test_expiry_path_enveloped(self):
        run, ident = _run()
        self._drive_window(run, ident)
        run["executor"]._sterile_expire(t=time.time() + 3600)
        deltas = _exit_deltas(run)
        self.assertEqual(len(deltas), 1)
        self.assertTrue(
            deltas[0]["post_window_delta"].get("__gov_unvetted__"))

    def test_no_loop_path_unchanged(self):
        run, ident = _run()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "api_call", endpoint="https://synthetic.local/v1",
                params={"q": 1})
        for rec in ex.approvals.pending():
            ex.approvals.decide(rec["id"], True, "test")
        ex.request_window_close(ident)
        self.assertEqual(_exit_deltas(run), [])


if __name__ == "__main__":
    unittest.main()
