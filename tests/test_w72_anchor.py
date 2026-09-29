"""Wave-72 Haber-Stornetta anchoring: focused break/fix tests (2026-09-22).

Load-bearing guarantee under test:
"no undetected rewrite of history prior to the last anchor" -- history
after the last anchor is soft, and the anchor cadence is the security
parameter.

Threat model: the HMAC key-holder (dev key here, the documented attacker
model) can rewrite the chain with valid MACs -- the anchor is what stops
them. Break-first: every attack test asserts the auditor grades
``operator-attested-only`` (never silently ``anchored``).

Hermetic: temp dirs, FakeWitness / recording transports, no network, no
repo mutation. Deterministic except wall-clock ``ts`` (never asserted on).
"""

import base64
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import anchor_backend as _ab  # noqa: E402
from gov import anchorer as _anchorer  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov import log as _log  # noqa: E402
from gov.log import ActionLog  # noqa: E402

_ENV_VARS = ("GOV_ANCHOR_KEY", "GOV_ANCHOR_KEY_FILE", "GOV_DEPLOYMENT_MODE")


def _seed(n):
    return bytes([n & 0xFF]) * 32


def _anchor_key(n=7):
    seed = _seed(n)
    pub = _ab.anchor_pubkey(seed)
    return {"seed": seed, "key_id": _ab.anchor_key_id(pub),
            "pubkey_hex": pub.hex(), "dev": True}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


class W72Base(unittest.TestCase):
    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_VARS}
        self.dirs = []
        self.anchorers = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for a in self.anchorers:
            try:
                a.close(timeout=10)
            except Exception:
                pass
        self.anchorers = []
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def fresh_dir(self):
        d = tempfile.mkdtemp(prefix="test-w72-")
        self.dirs.append(d)
        return Path(d)

    def make_log(self, n=0):
        d = self.fresh_dir()
        lg = ActionLog(str(d / "actions.jsonl"))
        for i in range(1, n + 1):
            lg.append({"event": "tool_call", "n": i, "principal": "p",
                       "agent_id": "a"})
        return lg, d

    def make_anchorer(self, lg, backend, **kw):
        kw.setdefault("policy", _anchorer.AnchorPolicy(
            records_per_epoch=10 ** 9, seconds_per_epoch=None,
            anchor_on_close=False))
        kw.setdefault("clock", _now_iso)
        kw.setdefault("anchor_key", _anchor_key())
        kw.setdefault("warn", lambda m: None)
        a = _anchorer.Anchorer(lg, backend, **kw)
        self.anchorers.append(a)
        return a

    def anchor_now(self, a):
        """Force-close the epoch and drain the worker. Returns the receipt
        record dict, or None when anchoring failed (see unanchored)."""
        self.assertEqual(a.maybe_anchor(force=True), "queued")
        a._queue.join()
        return self._last_receipt(a)

    def _entries(self, d):
        p = d / "actions.jsonl"
        return [json.loads(l) for l in p.read_text(encoding="utf-8")
                .splitlines() if l.strip()]

    def _last_receipt(self, a):
        recs = [e for e in
                self._entries(Path(a._log.path).parent)
                if e.get("event") == _anchorer.ANCHOR_RECEIPT_EVENT]
        return recs[-1] if recs else None

    def _rewrite_with_key(self, d, seq, patch):
        """Key-holder rewrite: patch entry ``seq``, recompute the HMAC
        chain from there (the dev key is the documented attacker model),
        AND reforge the checkpoint sidecar for every checkpoint at/after
        the rewrite point. The key-holder holds the key the checkpoint
        MACs are keyed under, so the design's attacker model (ANCHOR_
        DESIGN.md §1: "the whole chain (plus checkpoints ...) can be
        reforged") includes the sidecar -- a helper that leaves the
        sidecar stale tests the F27 checkpoint mechanism, not the
        anchor, and the verifier rightly reports "log rewritten after
        checkpoint" (closeout fix: 3 tests were red on exactly this)."""
        key, _ = _log._active_key()
        entries = self._entries(d)
        new_hashes = {}
        prev = _log.GENESIS
        for e in entries:
            if e["seq"] == seq:
                e.update(patch)
            if e["seq"] >= seq:
                e["prev_hash"] = prev
                mac = _log._compute_mac(key, e["key_epoch"], prev,
                                        _log._canonical(e))
                e["hash"] = mac
                prev = mac
            else:
                prev = e["hash"]
            new_hashes[e["seq"]] = e["hash"]
        (d / "actions.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=True)
                      for e in entries) + "\n", encoding="utf-8")
        # Reforge the checkpoint sidecar: any checkpoint line whose seq
        # is at/after the rewrite point now vouches for the reforged
        # entry hash, MAC'd under the same key (what a real key-holder
        # would produce). Tip-generation pins ride along unchanged in
        # shape, re-MAC'd under their own domain.
        cp_path = d / "checkpoints.jsonl"
        if cp_path.exists():
            out = []
            for line in cp_path.read_text(
                    encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                cp = json.loads(line)
                cs = cp.get("seq")
                if isinstance(cs, int) and cs >= seq \
                        and cs in new_hashes:
                    cp = dict(cp)
                    cp["hash"] = new_hashes[cs]
                    cp["mac"] = _log._checkpoint_mac(
                        key, cp.get("key_epoch"), cs, new_hashes[cs],
                        _log._pin_gen_of(cp))
                out.append(cp)
            cp_path.write_text(
                "\n".join(json.dumps(c, ensure_ascii=True)
                          for c in out) + "\n", encoding="utf-8")

    def _audit(self, d, backend):
        return _anchorer.audit_anchors(str(d / "actions.jsonl"), backend)


# ----------------------------------------------------------------------
# Epoch mechanics + happy path
# ----------------------------------------------------------------------

class TestEpochMechanics(W72Base):
    def test_epoch_stamping_and_close(self):
        lg, d = self.make_log(n=3)
        for e in self._entries(d):
            self.assertEqual(e["epoch_id"], "e00000001")
        closed, s, e = lg.close_epoch()
        self.assertEqual((closed, s, e), ("e00000001", 1, 3))
        lg.append({"event": "tool_call", "n": 4})
        self.assertEqual(self._entries(d)[-1]["epoch_id"], "e00000004")

    def test_anchor_happy_path_fake_witness(self):
        lg, d = self.make_log(n=4)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        rec = self.anchor_now(a)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["anchored_epoch_id"], "e00000001")
        self.assertEqual(rec["checkpoint_seq"], 4)
        self.assertEqual(rec["grade"], _anchorer.GRADE_ANCHORED)
        # The signed statement stays local, chained in the receipt record.
        stmt = rec["statement"]
        self.assertEqual(stmt["epoch_id"], "e00000001")
        self.assertEqual(stmt["head_hash"], rec["head_hash"])
        ok, reason = _ab.verify_statement_sig(stmt)
        self.assertTrue(ok, reason)
        # The auditor walk: every check True, grade anchored.
        rep = self._audit(d, w)
        self.assertTrue(rep["chain_ok"])
        self.assertEqual(len(rep["epochs"]), 1)
        ep = rep["epochs"][0]
        self.assertEqual(ep["grade"], _anchorer.GRADE_ANCHORED)
        self.assertTrue(all(v is True for v in ep["checks"].values()),
                        ep["checks"])
        for name in ("head_match", "anchor_hash_bind", "statement_sig",
                     "statement_chain", "receipt", "witness_binding",
                     "witness_time_window"):
            self.assertIn(name, ep["checks"])

    def test_two_epochs_chain_prev_anchor(self):
        lg, d = self.make_log(n=2)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        rec1 = self.anchor_now(a)
        lg.append({"event": "tool_call", "n": 3})
        lg.append({"event": "tool_call", "n": 4})
        rec2 = self.anchor_now(a)
        self.assertEqual(rec2["anchored_epoch_id"], "e00000003")
        # The second statement chains from the first anchor hash.
        self.assertEqual(rec2["statement"]["prev_anchor"],
                         rec1["anchor_hash"])
        rep = self._audit(d, w)
        self.assertEqual(
            [e["grade"] for e in rep["epochs"]],
            [_anchorer.GRADE_ANCHORED] * 2)
        self.assertEqual(
            rep["epochs"][1]["checks"]["statement_chain"], True)

    def test_guarantee_sentence_pinned(self):
        self.assertEqual(
            _anchorer.GUARANTEE,
            '"no undetected rewrite of history prior to the last anchor" '
            "-- history after the last anchor is soft, and the anchor "
            "cadence is the security parameter.")

# ----------------------------------------------------------------------
# The key-holder adversary (the whole point of the wave)
# ----------------------------------------------------------------------

class TestKeyholderAdversary(W72Base):
    def test_no_key_walltime_tamper_breaks_mac(self):
        lg, d = self.make_log(n=3)
        entries = self._entries(d)
        entries[1]["ts"] = "2001-01-01T00:00:00+00:00"  # no MAC recompute
        (d / "actions.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=True)
                      for e in entries) + "\n", encoding="utf-8")
        ok, broken, _ = _log.verify_chain(str(d / "actions.jsonl"))
        self.assertFalse(ok)
        self.assertEqual(broken, 2)

    def test_keyholder_rewrite_before_anchor_detected(self):
        # The crown-jewel test: the key-holder rewrites history WITH valid
        # MACs. The HMAC chain alone cannot catch them -- the anchor does.
        lg, d = self.make_log(n=4)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        self.assertIsNotNone(self.anchor_now(a))
        # Attacker rewrites entry 2 (pre-anchor history) with valid MACs.
        self._rewrite_with_key(d, 2, {"n": 999, "note": "forged"})
        # The local chain still verifies -- the key-holder forged it.
        ok, broken, _ = _log.verify_chain(str(d / "actions.jsonl"))
        self.assertTrue(ok, broken)
        # The auditor catches it: anchored head != rewritten chain head.
        rep = self._audit(d, w)
        self.assertTrue(rep["chain_ok"])  # chain is "valid"; anchor disagrees
        ep = rep["epochs"][0]
        self.assertEqual(ep["grade"],
                         _anchorer.GRADE_OPERATOR_ONLY)
        self.assertFalse(ep["checks"]["head_match"])
        self.assertTrue(any("anchored head" in r for r in ep["reasons"]))

    def test_keyholder_walltime_rewrite_after_anchor_detected(self):
        # Backdating: the key-holder moves an anchored entry's wall time.
        lg, d = self.make_log(n=4)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        self.assertIsNotNone(self.anchor_now(a))
        self._rewrite_with_key(d, 3, {"ts": "2001-01-01T00:00:00+00:00"})
        ok, _, _ = _log.verify_chain(str(d / "actions.jsonl"))
        self.assertTrue(ok)  # forged chain verifies...
        rep = self._audit(d, w)
        ep = rep["epochs"][0]
        self.assertEqual(ep["grade"], _anchorer.GRADE_OPERATOR_ONLY)
        self.assertFalse(ep["checks"]["head_match"])

    def test_statement_head_tamper_fails_sig(self):
        # Tamper with the STORED statement (no anchor key): the statement
        # signature and the hash binding both fail.
        lg, d = self.make_log(n=4)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        self.assertIsNotNone(self.anchor_now(a))
        rec_seq = self._last_receipt(a)["seq"]
        self._rewrite_with_key(
            d, rec_seq, {"statement": dict(
                self._last_receipt(a)["statement"],
                head_hash="00" * 32)})
        rep = self._audit(d, w)
        ep = rep["epochs"][0]
        self.assertEqual(ep["grade"], _anchorer.GRADE_OPERATOR_ONLY)
        self.assertFalse(ep["checks"]["statement_sig"])
        self.assertFalse(ep["checks"]["anchor_hash_bind"])

    def test_receipt_proof_tamper_detected(self):
        lg, d = self.make_log(n=4)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        rec = self.anchor_now(a)
        anchor_hash = rec["anchor_hash"]
        # Direct unit checks on the witness first.
        ok, reason = w.verify_receipt(rec["receipt"],
                                      anchor_hash=anchor_hash)
        self.assertTrue(ok, reason)
        bad = dict(rec["receipt"])
        proof = list(bad["inclusion_proof"])
        if proof:
            first = bytearray(bytes.fromhex(proof[0]))
            first[0] ^= 0xFF
            proof[0] = bytes(first).hex()
        else:  # single-leaf tree: tamper the root instead
            bad["log_root"] = "ff" * 32
        bad["inclusion_proof"] = proof
        ok, reason = w.verify_receipt(bad, anchor_hash=anchor_hash)
        self.assertFalse(ok, "tampered proof verified?!")
        # Chained tamper: flip the proof in the log (HMAC key-holder),
        # the auditor must refuse the anchored grade.
        rec_seq = rec["seq"]
        entries = self._entries(d)
        for e in entries:
            if e["seq"] == rec_seq:
                e["receipt"] = bad
        (d / "actions.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=True)
                      for e in entries) + "\n", encoding="utf-8")
        # Recompute the receipt entry's own MAC (key-holder) so the
        # chain still verifies and only the witness check fires.
        self._rewrite_with_key(d, rec_seq, {})
        rep = self._audit(d, w)
        ep = rep["epochs"][0]
        self.assertEqual(ep["grade"], _anchorer.GRADE_OPERATOR_ONLY)
        self.assertFalse(ep["checks"]["receipt"])

    def test_forged_statement_sig_rejected(self):
        seed = _seed(7)
        pub = _ab.anchor_pubkey(seed)
        stmt = _ab.build_statement(
            epoch_id="e00000001", seq=4, start_seq=1,
            head_hash="ab" * 32, merkle_root=None,
            epoch_start_wall=_now_iso(), epoch_close_wall=_now_iso(),
            key_id="k", pubkey_hex=pub.hex(), log_id="x")
        evil = _ab.sign_statement(stmt, _seed(8))  # wrong seed
        ok, reason = _ab.verify_statement_sig(evil)
        self.assertFalse(ok)
        self.assertIn("signature invalid", reason)


# ----------------------------------------------------------------------
# Witness time: backdating and future-dating
# ----------------------------------------------------------------------

class TestWitnessTime(W72Base):
    def test_backdated_witness_time_fails_window(self):
        lg, d = self.make_log(n=4)
        past = (datetime.now(timezone.utc)
                - timedelta(hours=2)).isoformat()
        w = _ab.FakeWitness(clock=lambda: past)
        a = self.make_anchorer(lg, w)
        rec = self.anchor_now(a)
        self.assertIsNotNone(rec)
        # The witness receipt itself is well-formed...
        ok, _ = w.verify_receipt(rec["receipt"],
                                 anchor_hash=rec["anchor_hash"])
        self.assertTrue(ok)
        # ...but the auditor refuses the anchored grade: the witness time
        # is outside the claimed epoch window (backdating detected).
        rep = self._audit(d, w)
        ep = rep["epochs"][0]
        self.assertEqual(ep["grade"], _anchorer.GRADE_OPERATOR_ONLY)
        self.assertFalse(ep["checks"]["witness_time_window"])
        self.assertTrue(any("outside the epoch window" in r
                            for r in ep["reasons"]))

    def test_future_witness_time_rejected(self):
        w = _ab.FakeWitness(clock=_now_iso)
        future = (datetime.now(timezone.utc)
                  + timedelta(hours=2)).isoformat()
        w2 = _ab.FakeWitness(clock=lambda: future)
        ahash = hashlib.sha256(b"x").hexdigest()
        rec = w2.submit(ahash)
        ok, reason = w2.verify_receipt(rec, anchor_hash=ahash)
        self.assertFalse(ok)
        self.assertIn("future", reason)


# ----------------------------------------------------------------------
# The soft window: residual after the last anchor
# ----------------------------------------------------------------------

class TestSoftWindowResidual(W72Base):
    def test_anchored_prefix_passes_soft_window_remains(self):
        lg, d = self.make_log(n=4)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        self.assertIsNotNone(self.anchor_now(a))
        # Post-anchor activity: the soft window.
        lg.append({"event": "tool_call", "n": 5})
        lg.append({"event": "tool_call", "n": 6})
        lg.append({"event": "tool_call", "n": 7})
        rep = self._audit(d, w)
        self.assertEqual(rep["epochs"][0]["grade"],
                         _anchorer.GRADE_ANCHORED)
        open_ep = rep["open_epoch"]
        # 3 new records + the epoch-1 receipt record itself (it anchors
        # with epoch 2) are not yet covered by any anchor.
        self.assertEqual(open_ep["unanchored_records"], 4)
        self.assertEqual(open_ep["grade"], "open (soft window)")

# ----------------------------------------------------------------------
# Privacy: only the hash crosses the witness boundary
# ----------------------------------------------------------------------

class TestPrivacyPin(W72Base):
    def test_submit_interface_is_hash_only(self):
        w = _ab.FakeWitness()
        ahash = hashlib.sha256(b"epoch-bytes").hexdigest()
        # The interface takes a bare hash...
        rec = w.submit(ahash)
        self.assertEqual(rec["anchor_hash"], ahash)
        # ...and rejects anything else, loudly.
        with self.assertRaises(_ab.WitnessError):
            w.submit({"anchor_hash": ahash, "epoch_id": "e00000001"})
        with self.assertRaises(_ab.WitnessError):
            w.submit("not-hex")
        with self.assertRaises(_ab.WitnessError):
            w.submit("ab" * 16)  # wrong length
        ll = _ab.LocalAnchorLog(str(self.fresh_dir() / "a.jsonl"))
        with self.assertRaises(_ab.WitnessError):
            ll.submit({"anchor_hash": ahash})
        # Rekor needs its key material at construction for submit.
        rb = _ab.RekorBackend(transport=lambda req: {"status": 500,
                                                     "body": "{}"})
        with self.assertRaises(_ab.WitnessError):
            rb.submit(ahash)

    def test_rekor_outbound_bytes_are_hash_only(self):
        # Intercept the EXACT outbound bytes: no epoch metadata, no wall
        # times, no record content -- hash + digest sig + pubkey only.
        seed = _seed(9)
        pub = _ab.anchor_pubkey(seed)
        ahash = hashlib.sha256(b"synthetic-epoch").hexdigest()
        seen = {}

        def transport(req):
            seen["body"] = req["body"]
            seen["url"] = req["url"]
            entry = {
                "body": base64.b64encode(json.dumps(
                    {"spec": {"data": {"hash": {
                        "algorithm": "sha512",
                        "value": hashlib.sha512(
                            bytes.fromhex(ahash)).hexdigest()}}}})
                    .encode()).decode(),
                "integratedTime": 1780000000,
                "logIndex": 41,
                "logID": _ab.REKOR_LOG_ID,
                "verification": {
                    "inclusionProof": {
                        "hashes": [], "rootHash": "ab" * 32,
                        "treeSize": 1, "logIndex": 0},
                    "signedEntryTimestamp":
                        base64.b64encode(b"set").decode(),
                },
            }
            return {"status": 201,
                    "body": json.dumps({"uuid-w72-test": entry})}

        rb = _ab.RekorBackend(transport=transport, anchor_seed=seed,
                              anchor_pubkey=pub)
        rb.submit(ahash)
        body = seen["body"]
        low = body.lower()
        for forbidden in ("epoch_id", "wall", "2026", "head_hash",
                          "prev_anchor", "tool_call", "principal"):
            self.assertNotIn(forbidden, low,
                             "outbound bytes leak %r" % forbidden)
        parsed = json.loads(body)
        self.assertEqual(parsed["kind"], "hashedrekord")
        # F203 shape: the envelope declares SHA-512(anchor_hash) --
        # the only declaration Rekor v1.5.x's Ed25519ph verifier
        # accepts -- and the signature is Ed25519ph over the 32-byte
        # anchor hash (never raw Ed25519).
        self.assertEqual(parsed["spec"]["data"]["hash"]["algorithm"],
                         "sha512")
        self.assertEqual(parsed["spec"]["data"]["hash"]["value"],
                         hashlib.sha512(bytes.fromhex(ahash)).hexdigest())
        sig = base64.b64decode(parsed["spec"]["signature"]["content"])
        self.assertTrue(_ed.verify_ph(pub, bytes.fromhex(ahash), sig))
        self.assertFalse(_ed.verify(pub, bytes.fromhex(ahash), sig),
                         "raw-Ed25519 shape must never be emitted")
        self.assertTrue(seen["url"].endswith("/api/v1/log/entries"))

    def test_local_anchor_log_stores_no_statement(self):
        d = self.fresh_dir()
        ll = _ab.LocalAnchorLog(str(d / "anchors.jsonl"))
        ahash = hashlib.sha256(b"e1").hexdigest()
        rec = ll.submit(ahash)
        ok, reason = ll.verify_receipt(rec, anchor_hash=ahash)
        self.assertTrue(ok, reason)
        content = (d / "anchors.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("epoch_id", content)
        self.assertNotIn("statement", content)
        self.assertIn(ahash, content)


# ----------------------------------------------------------------------
# Failure semantics: down -> loud unanchored -> bounded retry -> recover
# ----------------------------------------------------------------------

class TestFailureSemantics(W72Base):
    def test_backend_down_marks_loud_unanchored_chain_continues(self):
        lg, d = self.make_log(n=4)
        warnings = []
        w = _ab.FakeWitness(clock=_now_iso)
        w.down = True
        a = self.make_anchorer(lg, w, warn=warnings.append)
        self.assertEqual(a.maybe_anchor(force=True), "queued")
        a._queue.join()
        # Loud: a chained unanchored record + a stderr-grade warning.
        un = [e for e in self._entries(d)
              if e.get("event") == _anchorer.ANCHOR_UNANCHORED_EVENT]
        self.assertEqual(len(un), 1)
        self.assertEqual(un[0]["anchored_epoch_id"], "e00000001")
        self.assertEqual(un[0]["reason"], "backend-down")
        self.assertEqual(un[0]["grade"],
                         _anchorer.GRADE_OPERATOR_ONLY)
        self.assertTrue(any("failed" in m for m in warnings), warnings)
        # The chain continues: enforcement/appends never block on the
        # witness, and the chain still verifies.
        lg.append({"event": "tool_call", "n": 5})
        ok, _, _ = _log.verify_chain(str(d / "actions.jsonl"))
        self.assertTrue(ok)
        # The auditor grades the epoch operator-attested-only, loudly.
        rep = self._audit(d, w)
        ep = rep["epochs"][0]
        self.assertEqual(ep["grade"], _anchorer.GRADE_OPERATOR_ONLY)
        self.assertIn("no anchor receipt chained", ep["reasons"])

    def test_recover_after_outage_anchors(self):
        lg, d = self.make_log(n=4)
        w = _ab.FakeWitness(clock=_now_iso)
        w.down = True
        a = self.make_anchorer(lg, w)
        a.maybe_anchor(force=True)
        a._queue.join()
        w.down = False
        self.assertEqual(a.recover(), 1)
        a._queue.join()
        recs = [e for e in self._entries(d)
                if e.get("event") == _anchorer.ANCHOR_RECEIPT_EVENT]
        self.assertEqual(len(recs), 1)
        rep = self._audit(d, w)
        self.assertEqual(rep["epochs"][0]["grade"],
                         _anchorer.GRADE_ANCHORED)
        # Recover is idempotent: nothing left to requeue.
        self.assertEqual(a.recover(), 0)

    def test_retry_is_bounded_and_marks_once(self):
        lg, d = self.make_log(n=4)
        warnings = []
        w = _ab.FakeWitness(clock=_now_iso)
        w.down = True  # stays down: retries must exhaust, loudly, once
        a = self.make_anchorer(lg, w, warn=warnings.append,
                               max_attempts=2, backoff_base=0.01,
                               backoff_cap=0.02)
        a.maybe_anchor(force=True)
        a._queue.join()
        import time as _t
        _t.sleep(0.5)  # let both bounded attempts fire
        un = [e for e in self._entries(d)
              if e.get("event") == _anchorer.ANCHOR_UNANCHORED_EVENT]
        self.assertEqual(len(un), 1, "must mark LOUD exactly once")
        self.assertTrue(any("retries exhausted" in m for m in warnings),
                        warnings)

    def test_append_never_blocks_on_witness(self):
        case = self

        class BlockingWitness(_ab.FakeWitness):
            def __init__(self, *args, **kw):
                super().__init__(*args, **kw)
                self.release = threading.Event()

            def submit(self, anchor_hash):
                # NOTE: ``case`` not ``self`` -- the witness is not a
                # TestCase; ``self.assertTrue`` here was an AttributeError
                # that made the worker fail before blocking (closeout
                # fix: the test failed with 0 receipts, not a hang).
                case.assertTrue(
                    self.release.wait(timeout=30), "test deadlock")
                return super().submit(anchor_hash)

        lg, d = self.make_log(n=3)
        w = BlockingWitness(clock=_now_iso)
        a = self.make_anchorer(lg, w)
        self.assertEqual(a.maybe_anchor(force=True), "queued")
        # The worker is now stuck inside submit(); appends must proceed.
        for i in range(4, 9):
            lg.append({"event": "tool_call", "n": i})
        self.assertEqual(self._entries(d)[-1]["seq"], 8)
        w.release.set()
        a._queue.join()
        recs = [e for e in self._entries(d)
                if e.get("event") == _anchorer.ANCHOR_RECEIPT_EVENT]
        self.assertEqual(len(recs), 1)

    def test_close_anchors_open_epoch(self):
        lg, d = self.make_log(n=2)
        w = _ab.FakeWitness(clock=_now_iso)
        a = self.make_anchorer(
            lg, w,
            policy=_anchorer.AnchorPolicy(
                records_per_epoch=10 ** 9, seconds_per_epoch=None,
                anchor_on_close=True))
        a.close(timeout=10)  # run close anchors per the policy
        self.anchorers.remove(a)
        recs = [e for e in self._entries(d)
                if e.get("event") == _anchorer.ANCHOR_RECEIPT_EVENT]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["anchored_epoch_id"], "e00000001")


# ----------------------------------------------------------------------
# Boundaries: sandbox, legacy logs, key custody
# ----------------------------------------------------------------------

class TestBoundaries(W72Base):
    def test_sandbox_has_no_anchor_client(self):
        # The anchor client is executor-side only: importing the sandbox
        # must not pull gov.anchorer / gov.anchor_backend into the
        # process (deny-all egress -- the anchor client lives outside).
        code = ("import sys, gov.sandbox; sys.exit(0 "
                "if 'gov.anchorer' not in sys.modules "
                "and 'gov.anchor_backend' not in sys.modules else 1)")
        r = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, timeout=120,
                           cwd=_REPO_MAIN)
        self.assertEqual(r.returncode, 0, r.stderr.decode()[:500])

    def test_legacy_log_without_epoch_ids_still_verifies(self):
        lg, d = self.make_log(n=4)
        # Simulate a pre-wave-72 log: strip epoch_id, then reforge the
        # chain AND the checkpoint sidecar exactly as the log's own
        # writer would have (a pre-wave-72 writer never stamped
        # epoch_id, so the stripped canonical form IS the original
        # canonical form -- the wave-49/50 lesson: no legitimate-
        # behavior breakage).
        entries = self._entries(d)
        for e in entries:
            e.pop("epoch_id", None)
        (d / "actions.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=True)
                      for e in entries) + "\n", encoding="utf-8")
        self._rewrite_with_key(d, 1, {})
        ok, _, count = _log.verify_chain(str(d / "actions.jsonl"))
        self.assertTrue(ok)
        self.assertEqual(count, 4)
        w = _ab.FakeWitness(clock=_now_iso)
        rep = self._audit(d, w)
        self.assertEqual(rep["epochs"], [])
        self.assertEqual(rep["open_epoch"]["unanchored_records"], 4)

    def test_resolve_anchor_key_refuses_loud_in_every_mode(self):
        # Wave-81: the dev anchor-key fallback is deleted -- unconfigured
        # anchoring refuses loudly in production, staging, dev, and test.
        for mode in ("production", "staging", "dev", "test"):
            os.environ["GOV_DEPLOYMENT_MODE"] = mode
            os.environ.pop("GOV_ANCHOR_KEY", None)
            os.environ.pop("GOV_ANCHOR_KEY_FILE", None)
            with self.assertRaises(_anchorer.NoAnchorKeyError, msg=mode):
                _anchorer.resolve_anchor_key()

    def test_resolve_anchor_key_explicit(self):
        seed_hex = _seed(11).hex()
        got = _anchorer.resolve_anchor_key(explicit=seed_hex)
        self.assertEqual(got["seed"], _seed(11))
        self.assertFalse(got["dev"])
        with self.assertRaises(_anchorer.NoAnchorKeyError):
            _anchorer.resolve_anchor_key(explicit="zz")

    def test_anchor_policy_rejects_nonsense(self):
        with self.assertRaises(ValueError):
            _anchorer.AnchorPolicy(records_per_epoch=0)
        with self.assertRaises(ValueError):
            _anchorer.AnchorPolicy(seconds_per_epoch=-1)


# ----------------------------------------------------------------------
# RFC 6962 inclusion-proof helper: known-answer vectors
# ----------------------------------------------------------------------

class TestRfc6962Root(W72Base):
    def _reference_tree(self, leaves):
        # Independent reference: iterative RFC 6962 root.
        level = [hashlib.sha256(b"\x00" + l).digest() for l in leaves]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level) - 1, 2):
                nxt.append(hashlib.sha256(
                    b"\x01" + level[i] + level[i + 1]).digest())
            if len(level) % 2 == 1:
                nxt.append(level[-1])
            level = nxt
        return level[0]

    def _reference_proof(self, leaves, index):
        # Independent reference: sibling hashes, leaf level first.
        proof = []
        level = [hashlib.sha256(b"\x00" + l).digest() for l in leaves]
        idx = index
        while len(level) > 1:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    proof.append(level[idx + 1])
            else:
                proof.append(level[idx - 1])
            nxt = []
            for i in range(0, len(level) - 1, 2):
                nxt.append(hashlib.sha256(
                    b"\x01" + level[i] + level[i + 1]).digest())
            if len(level) % 2 == 1:
                nxt.append(level[-1])
            level = nxt
            idx //= 2
        return proof

    def test_vectors_against_reference(self):
        for size in range(1, 9):
            leaves = [b"leaf-%d" % i for i in range(size)]
            root = self._reference_tree(leaves)
            for index in range(size):
                proof = self._reference_proof(leaves, index)
                got = _ab._rfc6962_root(leaves[index], index, proof, size)
                self.assertEqual(got, root,
                                 "size=%d index=%d" % (size, index))
                # Hex-string proof elements (Rekor's wire form) too.
                got_hex = _ab._rfc6962_root(
                    leaves[index], index,
                    [p.hex() for p in proof], size)
                self.assertEqual(got_hex, root)

    def test_malformed_inputs_raise(self):
        leaves = [b"a", b"b"]
        proof = self._reference_proof(leaves, 0)
        with self.assertRaises(ValueError):
            _ab._rfc6962_root(leaves[0], 0, proof[:-1], 2)  # short
        with self.assertRaises(ValueError):
            _ab._rfc6962_root(leaves[0], 0, proof + proof, 2)  # long
        with self.assertRaises(ValueError):
            _ab._rfc6962_root(leaves[0], 5, proof, 2)  # bad index
        with self.assertRaises(ValueError):
            _ab._rfc6962_root(leaves[0], 0, ["zz"], 2)  # bad hex


if __name__ == "__main__":
    unittest.main()
