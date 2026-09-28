"""Hardening round-10 regression tests: wave-11 findings F38-F41.

F38 (HIGH): the approval-queue keyed digest binds run_id and decided_by
(queue() MACs with decided_by=None; decide() verifies the pending digest
first — fail-closed ValueError on tamper — then re-MACs with the decider
bound), and execute_approved() refuses cross-run replay at the execution
boundary (approval_run_mismatch, audited). Pre-R10 digests fail closed.

F39 (HIGH): execute_approved() sweeps run under the approval queue's
exclusive lock (ApprovalQueue._queue_locked) — the read-claim-execute-
mark sequence is atomic across threads and processes, so concurrent
sweeps execute each approval exactly once. A lock timeout refuses the
sweep fail-closed (QueueLockError) and is audited; the sweep never runs
unlocked. Lock order: queue lock (outer) -> action-log lock (inner).

F40 (MEDIUM): the foreign-result normalizer is total and recursive —
nested blocks, arbitrary collections.abc.Sequence instances, and
defensive per-property probing mean one hostile block cannot discard
benign siblings. Opaque/unparseable parts conservatively taint the run
(the taint bit gates; nothing is fabricated). Benign text stays
untainted/ungated; content=None stays clean.

F41 (MEDIUM): the cross-principal campaign quorum requires K distinct
principals AND K-1 established principals (>= 2 observations of the
shape in the window) — two throwaway look-alikes no longer let an
attacker queue a victim's benign call, while a genuine multi-principal
campaign (repeat emitters) still fires.

No network, no clock dependence. Deterministic: key env is pinned in
setUp and restored afterwards.
"""

import collections.abc
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import make_run  # noqa: E402
from gov.approvals import (  # noqa: E402
    APPROVAL_DIGEST_SCHEME,
    QueueLockError,
    approval_digest_ok,
    approval_record_digest,
)

_KEY_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _pin_dev_key_env():
    """Provision an EXPLICIT test key via the production env path
    (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH; wave-81 deleted the dev key from
    gov/). The queue/ledger tests need a working keyed digest; there is
    no fallback to pin anymore — the key here is fresh random material
    per setUp, nothing shared, nothing public.

    (Wave-81 also removed gov.log._LEDGER_KEYRING/_LEDGER_ACTIVE, so the
    old ledger-cache resets are gone — nothing to reset.)"""
    try:
        from tests.keyfixture import provision_test_key
    except ImportError:  # tests/ directly on sys.path
        from keyfixture import provision_test_key
    saved = {n: os.environ.get(n) for n in _KEY_NAMES}
    provision_test_key()
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)

    def _restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v
    return _restore


class _R10Case(unittest.TestCase):
    def setUp(self):
        self._restore_env = _pin_dev_key_env()

    def tearDown(self):
        self._restore_env()


def _queue_send(ctx, q, ex, principal="org"):
    """Queue a send_email (policy-queued) directly through the queue.

    F42 (R11): queue() requires a minted caller identity; the
    action["identity"] dict is ignored by the queue.
    """
    action = {"tool": "send_email",
              "args": {"to": "x@synthetic.local", "subject": "s",
                       "body": "b" * 100},
              "identity": {"agent_id": "a1", "role": "researcher",
                           "run_id": q.run_dir.name, "principal": principal},
              "redactions": [], "agent_justification": None}
    return q.queue(action,
                   _QueueDecision("approval-test", "test queue"),
                   # Wave-174 (display≡execution): renderer-built preview
                   # (the sweep re-derives it from the executor's
                   # renderer).
                   "agent_direct",
                   ex._preview("send_email", action["args"]),
                   policy_hash=ex.policy.policy_hash,
                   egress_bytes=500,
                   caller_identity=ctx["mint_identity"](
                       "a1", "researcher", principal))


class _QueueDecision:
    """Minimal decision-like object for queueing records directly."""

    def __init__(self, policy_id, reason, flag=None):
        self.policy_id = policy_id
        self.reason = reason
        self.flag = flag


def _refusal_entries(ctx):
    from gov.log import read_entries
    return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
            if e.get("event") == "approval_execution_refused"]


# ---------------------------------------------------------------------------
# F38: approval run binding
# ---------------------------------------------------------------------------

class TestF38RunBinding(_R10Case):
    """The keyed digest binds run_id and decided_by; execution refuses
    cross-run replay."""

    def test_cross_run_planted_approval_refused(self):
        # A genuinely-approved record from run A, planted into run B's
        # queue: the digest still verifies (it was properly MACed), but
        # the execution-boundary run_id check refuses it fail-closed.
        ctx_a = make_run()
        qa, exa = ctx_a["approvals"], ctx_a["executor"]
        aid = _queue_send(ctx_a, qa, exa)
        qa.decide(aid, True, "looks fine", decided_by="human-operator")
        rec = qa.get(aid)
        self.assertTrue(approval_digest_ok(rec))

        ctx_b = make_run()
        qb, exb = ctx_b["approvals"], ctx_b["executor"]
        with open(qb.run_dir / "approvals.jsonl", "a",
                   encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=True) + "\n")
        done = exb.execute_approved()
        planted = qb.get(aid)
        self.assertEqual(done, [])
        self.assertFalse(planted.get("executed"))
        self.assertIn("cross-run replay",
                      planted.get("execution_refused_reason") or "")
        refusals = _refusal_entries(ctx_b)
        self.assertTrue(any(e.get("flag") == "approval_run_mismatch"
                            and e.get("approval_id") == aid
                            for e in refusals),
                        "cross-run replay must be audited, not silent")

    def test_relabeled_decider_refused(self):
        # decided_by is MAC-bound: relabeling who approved a decided
        # record invalidates the digest.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queue_send(ctx, q, ex)
        q.decide(aid, True, "looks fine", decided_by="human-operator")
        q._rewrite(lambda rs: [dict(r, decided_by="attacker-agent")
                               if r["id"] == aid else r for r in rs])
        done = ex.execute_approved()
        rec = q.get(aid)
        self.assertEqual(done, [])
        self.assertFalse(rec.get("executed"))
        self.assertIn("integrity digest mismatch",
                      rec.get("execution_refused_reason") or "")

    def test_same_run_approval_still_executes(self):
        # The binding must not break the normal path: queue, decide,
        # and execute in the SAME run works unchanged.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queue_send(ctx, q, ex)
        q.decide(aid, True, "looks fine", decided_by="human-operator")
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(q.get(aid).get("executed"))

    def test_embedded_identity_run_mismatch_refused(self):
        # F43 (R11) changed this: the identity dict IS now a MAC input
        # (the authenticated attribution is bound). Rewriting the
        # embedded identity's run_id breaks the digest — execution
        # refuses fail-closed with approval_integrity_violation.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queue_send(ctx, q, ex)
        q.decide(aid, True, "looks fine", decided_by="human-operator")
        q._rewrite(lambda rs: [
            dict(r, identity=dict(r.get("identity") or {},
                                 run_id="some-other-run"))
            if r["id"] == aid else r for r in rs])
        self.assertFalse(approval_digest_ok(q.get(aid)),
                         "F43: identity is a MAC input — the rewrite "
                         "breaks the digest")
        done = ex.execute_approved()
        rec = q.get(aid)
        self.assertEqual(done, [])
        self.assertFalse(rec.get("executed"))
        refusals = _refusal_entries(ctx)
        self.assertTrue(any(e.get("flag") == "approval_integrity_violation"
                            and e.get("approval_id") == aid
                            for e in refusals),
                        "identity rewrite must be refused as an integrity "
                        "violation")

    def test_rotation_epoch_still_verifies_with_run_binding(self):
        # Key rotation does not invalidate in-flight approvals: a
        # record MACed under an archived epoch verifies via the keyring
        # with run_id/decided_by bound.
        import gov.log as L
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queue_send(ctx, q, ex)
        q.decide(aid, True, "ok", decided_by="human-operator")
        rec = q.get(aid)
        old_key, old_epoch = L._active_key()
        os.environ["GOV_LOG_KEY"] = "brand-new-operator-key"
        os.environ["GOV_LOG_KEY_EPOCH"] = "epoch-2"
        os.environ["GOV_LOG_KEY_ARCHIVE"] = json.dumps(
            {old_epoch: old_key.decode("utf-8")})
        try:
            self.assertTrue(approval_digest_ok(rec))
            done = ex.execute_approved()
            self.assertEqual(len(done), 1)
        finally:
            self._restore_env()
            self._restore_env = _pin_dev_key_env()


# ---------------------------------------------------------------------------
# F39: approval-queue sweep lock
# ---------------------------------------------------------------------------

class TestF39QueueSweepLock(_R10Case):
    """Concurrent execute_approved() sweeps are serialized: each approval
    executes exactly once."""

    def test_concurrent_sweeps_execute_exactly_once(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aids = [_queue_send(ctx, q, ex, principal="p%d" % i)
                for i in range(3)]
        for aid in aids:
            q.decide(aid, True, "ok", decided_by="human-operator")
        results = []
        errors = []

        def sweep():
            try:
                results.append(ex.execute_approved())
            except Exception as e:  # noqa: BLE001 — collected, asserted empty
                errors.append(e)

        threads = [threading.Thread(target=sweep) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        self.assertEqual(errors, [])
        total = sum(len(done) for done in results)
        self.assertEqual(total, 3,
                         "8 concurrent sweeps must execute 3 approvals "
                         "exactly once total, got %d" % total)
        from gov.log import read_entries
        executed = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                    if e.get("decision") == "approved_executed"]
        per_aid = {}
        for e in executed:
            per_aid[e.get("approval_id")] = \
                per_aid.get(e.get("approval_id"), 0) + 1
        self.assertEqual(per_aid, {aid: 1 for aid in aids})

    def test_sequential_resweep_skips(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queue_send(ctx, q, ex)
        q.decide(aid, True, "ok", decided_by="human-operator")
        self.assertEqual(len(ex.execute_approved()), 1)
        # second sweep re-reads under the lock and skips the marked record
        self.assertEqual(ex.execute_approved(), [])
        from gov.log import read_entries
        executed = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                    if e.get("decision") == "approved_executed"
                    and e.get("approval_id") == aid]
        self.assertEqual(len(executed), 1)

    def test_durable_claim_precedes_side_effect(self):
        # F39: the durable claim (executed=True) is written BEFORE
        # _simulate() runs. If the side effect raises, the approval is
        # consumed (a later sweep skips it) instead of being left for
        # a duplicate execution — no duplicate execution is favored
        # over automatic retry.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queue_send(ctx, q, ex)
        q.decide(aid, True, "ok", decided_by="human-operator")

        def _boom(tool, args, _ctx):
            raise RuntimeError("simulated side-effect failure")

        ex._simulate = _boom
        with self.assertRaises(RuntimeError):
            ex.execute_approved()
        rec = q.get(aid)
        self.assertTrue(rec.get("executed"),
                        "durable claim must precede the side effect: a "
                        "crashed/failed side effect must not leave the "
                        "approval executable again")
        # a later sweep skips the consumed approval — no duplicate
        self.assertEqual(ex.execute_approved(), [])

    def test_lock_timeout_refuses_sweep_and_audits(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queue_send(ctx, q, ex)
        q.decide(aid, True, "ok", decided_by="human-operator")
        outcome = {}

        def sweep():
            try:
                outcome["done"] = ex.execute_approved()
            except QueueLockError as e:
                outcome["error"] = e

        with mock.patch("gov.approvals.APPROVAL_QUEUE_LOCK_TIMEOUT_SECS", 1):
            with q._queue_locked():
                t = threading.Thread(target=sweep)
                t.start()
                t.join(60)
        self.assertIn("error", outcome)
        self.assertIsInstance(outcome["error"], QueueLockError)
        # fail-closed: nothing executed while the lock was unavailable
        self.assertNotIn("done", outcome)
        self.assertFalse(q.get(aid).get("executed"))
        from gov.log import read_entries
        entries = read_entries(ctx["run_dir"] / "actions.jsonl")
        self.assertFalse(any(e.get("decision") == "approved_executed"
                             for e in entries))
        refused = [e for e in entries
                   if e.get("event") == "approval_sweep_refused"]
        self.assertTrue(any(e.get("flag") == "queue_lock_timeout"
                            for e in refused),
                        "lock-timeout refusal must be audited")

    def test_queue_lock_primitive_serializes(self):
        ctx = make_run()
        q = ctx["approvals"]
        # a second acquirer times out while the lock is held ...
        with q._queue_locked():
            with self.assertRaises(QueueLockError):
                with q._queue_locked(timeout=1):
                    pass
        # ... and acquires cleanly once released.
        with q._queue_locked(timeout=5):
            pass


# ---------------------------------------------------------------------------
# F40: total foreign-result normalizer
# ---------------------------------------------------------------------------

POISON = "api_key=AKIAIOSFODNN7EXAMPLE"


class _TextBlock:
    def __init__(self, text):
        self.text = text


class _ImageBlock:
    """Object-form image block: no .text, sensitive text in .data."""

    def __init__(self, data):
        self.type = "image"
        self.data = data
        self.mimeType = "image/png"


class _RaisingBlock:
    """Object-form block whose .text property raises."""

    @property
    def text(self):
        raise RuntimeError("block decode failed")


class _ObjectResult:
    def __init__(self, content):
        self.content = content


class _CustomSeq(collections.abc.Sequence):
    """A Sequence that is NOT a list/tuple."""

    def __init__(self, items):
        self._items = list(items)

    def __len__(self):
        return len(self._items)

    def __getitem__(self, i):
        return self._items[i]


class TestF40TotalNormalizer(_R10Case):
    """Every w11 round-2 miss shape now taints; benign shapes stay clean."""

    def _ingest(self, result):
        ctx = make_run()
        ex = ctx["executor"]
        ex.ingest_foreign_result("api_call", result, principal="p")
        return ctx, ex

    def _paraphrase_status(self, ex, ident):
        r = ex.call(ident, "api_call", endpoint="https://x.synthetic.local/",
                    params={"summary": "the results mention a key"})
        return r["status"], r.get("policy_id")

    def test_nested_blocks_taint(self):
        ctx, ex = self._ingest(
            {"content": [{"type": "text", "text": "2 results found"},
                         {"type": "resource",
                          "resource": {"text": "leaked " + POISON}}]})
        ident = ctx["mint_identity"]("mcp", "researcher", "p")
        self.assertTrue(ex._read_sensitive)
        status, pid = self._paraphrase_status(ex, ident)
        self.assertEqual(status, "queued")
        self.assertEqual(pid, "approval-sensitive-read-before-api")

    def test_image_block_data_taints(self):
        ctx, ex = self._ingest(_ObjectResult(
            [_TextBlock("results"), _ImageBlock("leaked " + POISON)]))
        ident = ctx["mint_identity"]("mcp", "researcher", "p")
        self.assertTrue(ex._read_sensitive)
        status, pid = self._paraphrase_status(ex, ident)
        self.assertEqual((status, pid),
                         ("queued", "approval-sensitive-read-before-api"))

    def test_raising_block_does_not_discard_siblings(self):
        # One hostile .text property must not discard the benign
        # sibling's text: the sibling is still extracted into the read
        # store, and the opaque block conservatively taints.
        ctx, ex = self._ingest(_ObjectResult(
            [_TextBlock("benign sibling " + POISON), _RaisingBlock()]))
        self.assertTrue(any("benign sibling" in c
                            for c in ex._read_contents),
                        "hostile block must not discard benign siblings")
        self.assertTrue(ex._read_sensitive)

    def test_custom_sequence_traversed(self):
        ctx, ex = self._ingest(_ObjectResult(_CustomSeq(
            [{"type": "text", "text": "leaked " + POISON}])))
        self.assertTrue(ex._read_sensitive)

    def test_benign_control_ungated(self):
        ctx, ex = self._ingest({"content": "sunny 21C"})
        ident = ctx["mint_identity"]("mcp", "researcher", "p")
        self.assertFalse(ex._read_sensitive)
        r = ex.call(ident, "api_call", endpoint="https://x.synthetic.local/",
                    params={"q": "weather"})
        self.assertEqual(r["status"], "executed")

    def test_content_none_stays_clean(self):
        # result=None: nothing ingested at all. {"content": None}: the
        # dict's VALUES are traversed (keys are schema labels, not
        # foreign text), nothing textual is present — clean, never
        # sensitive-tainted, never tainted at all.
        ctx, ex = self._ingest(None)
        self.assertFalse(ex._read_sensitive)
        self.assertFalse(ex._tainted)
        ctx, ex = self._ingest({"content": None})
        self.assertFalse(ex._read_sensitive)
        self.assertFalse(ex._tainted)

    def test_reference_cycle_bounded(self):
        d = {"content": "hello"}
        d["self"] = d  # reference cycle: must not hang, counts opaque
        blob, opaque = type(make_run()["executor"])._foreign_normalize(d)
        self.assertIn("hello", blob)
        self.assertTrue(opaque)


# ---------------------------------------------------------------------------
# F41: throwaway-resistant cross-principal quorum
# ---------------------------------------------------------------------------

class TestF41ThrowawayQuorum(_R10Case):
    """Two throwaway look-alikes no longer queue a victim's benign call;
    a genuine repeat-emitter campaign still fires."""

    def _frag_call(self, ex, ident, endpoint):
        return ex.call(ident, "api_call", endpoint=endpoint,
                       params={"blob": "A1B2C3D4E5F6G7H8!"})

    def test_two_throwaways_no_longer_queue_victim(self):
        # The w11 F41 attack: victim-org heartbeats (control, executed);
        # atk-1 and atk-2 plant one look-alike each (both execute —
        # pre-R10 the second throwaway queued as the 3rd distinct
        # principal); the victim's NEXT heartbeat was queued pre-R10 as
        # the 3rd distinct principal — now it executes. Fresh random
        # token per call (w11 shape): the per-principal detector stays
        # out of it (victim has only 2 observations), isolating the
        # cross-principal quorum under test.
        import random
        with tempfile.TemporaryDirectory(prefix="govr10-") as td:
            led = str(Path(td) / "ledger.jsonl")
            EP = "https://shard0.collector.synthetic.local/ingest"
            rng = random.Random("r10f41")

            def tok():
                # Fresh random token per call (w11 shape), drawn from a
                # 12-symbol alphabet so per-call values stay distinct for
                # the per-principal detector while staying under F99's
                # high-entropy-payload threshold: this test isolates the
                # F41 cross-principal quorum and must not trip the
                # orthogonal F99 framed-secret control (a 62-alphabet
                # random token would legitimately queue for review).
                return "".join(rng.choice("abcdef012345") for _ in range(32))

            def run_as(principal):
                ctx = make_run(ledger_path=led)
                ex = ctx["executor"]
                ident = ex.mint_identity("a", "researcher", principal)
                return ex, ident

            ex0, id0 = run_as("victim-org")
            self.assertEqual(
                ex0.call(id0, "api_call", endpoint=EP,
                         params={"session": tok()})["status"], "executed")
            for atk in ("atk-1", "atk-2"):
                exa, ida = run_as(atk)
                self.assertEqual(
                    exa.call(ida, "api_call", endpoint=EP,
                             params={"session": tok()})["status"],
                    "executed")
            exv2, idv2 = run_as("victim-org")
            r = exv2.call(idv2, "api_call", endpoint=EP,
                          params={"session": tok()})
            self.assertEqual(r["status"], "executed",
                             "throwaway-planted quorum must not queue the "
                             "victim's benign heartbeat")

    def test_genuine_three_principal_campaign_still_fires(self):
        # Repeat emitters across DISTINCT RUNS: each of 3 principals
        # emits in two separate runs, so F46 multi-run establishment
        # holds — the signal still fires when the 3rd principal's
        # second run joins the quorum.
        with tempfile.TemporaryDirectory(prefix="govr10-") as td:
            led = str(Path(td) / "ledger.jsonl")
            EP = "https://shard0.collector.synthetic.local/ingest"
            st = []
            # Round 1: each principal's first run.
            for run in range(3):
                ctx = make_run(ledger_path=led)
                ex = ctx["executor"]
                ident = ex.mint_identity("a", "researcher",
                                         "rot-%d" % run)
                st.append(self._frag_call(ex, ident, EP)["status"])
            # Round 2: each principal's second run — now each has
            # observations across 2 distinct run IDs (F46 established).
            for run in range(3):
                ctx = make_run(ledger_path=led)
                ex = ctx["executor"]
                ident = ex.mint_identity("a", "researcher",
                                         "rot-%d" % run)
                st.append(self._frag_call(ex, ident, EP)["status"])
            self.assertEqual(st[:4], ["executed"] * 4)
            self.assertIn("queued", st[4:],
                          "F46: multi-run-established principals must "
                          "still form a cross-principal quorum")

    def test_first_seen_trio_does_not_queue(self):
        # Documents the deliberate bar raise: three first-seen
        # principals (one call each) are indistinguishable from the
        # throwaway attack and no longer form a quorum.
        with tempfile.TemporaryDirectory(prefix="govr10-") as td:
            led = str(Path(td) / "ledger.jsonl")
            EP = "https://shard0.collector.synthetic.local/ingest"
            st = []
            for run in range(3):
                ctx = make_run(ledger_path=led)
                ex = ctx["executor"]
                ident = ex.mint_identity("a", "researcher",
                                         "fresh-%d" % run)
                st.append(self._frag_call(ex, ident, EP)["status"])
            self.assertEqual(st, ["executed"] * 3)


if __name__ == "__main__":
    unittest.main()
