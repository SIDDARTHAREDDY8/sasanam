"""Hardening round-9 regression tests: wave-10 findings F34-F37.

F34 (HIGH): the approval-queue integrity digest is HMAC-keyed to the
active log key (scheme "hmac-sha256-v1") with the key epoch bound in and
verified against the keyring via hmac.compare_digest. Pre-R9 unkeyed
records are refused fail-closed. Residual (tested + documented): under
the public development key a docs-reader can forge — the MAC gives no
forgery resistance without a real key.

F35 (MEDIUM): the approval-history discount never flips an auto-approve
decision. Untrusted-influenced items get NO veteran discount (veterans
score them exactly like unknown agents), and maybe_auto_approve re-scores
history-neutral as a second gate. Benign repeat traffic keeps the
queue-ordering discount.

F36 (MEDIUM): cross-principal campaign correlation — the same
fragment-shaped api_call (domain + param key set) from >= K distinct
principals inside the window queues, catching principal rotation that
the per-principal detectors cannot see. Residuals (tested +
documented): param-key rotation under a single principal still evades;
perfect rotation (fresh principal AND fresh key set per run) is an
identity-layer problem.

F37 (MEDIUM): MCP server results — and the generic adapter's run_body
real bodies — are ingested into the run's provenance/taint store exactly
like native results, so a sensitive server response taints the run and a
follow-up paraphrase api_call hits the sensitive-read-before-api gate.

No network. Forged approval records use a relative 'now' UTC timestamp
so they stay inside the 24h approval TTL (a hard-coded date rotted past
the TTL on 2026-09-22; the forgery residual is what is measured, not
expiry). Otherwise deterministic: key env is pinned in setUp and
restored afterwards.
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import make_run  # noqa: E402
from gov.approvals import (  # noqa: E402
    APPROVAL_DIGEST_SCHEME,
    _security_record_payload,
    approval_digest_ok,
    approval_record_digest,
    record_digest,
)
from gov.policy import PolicyDecision  # noqa: E402

_KEY_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _fresh_utc_z():
    """Relative 'now' UTC timestamp in the Z-suffixed ISO shape forged
    approval records use. Hard-coded 2026-09-21 dates rot past the 24h
    approval TTL (wall-clock rot, fixed 2026-09-22): the forged record
    must be fresher than the TTL for the test to measure the dev-key
    forgery residual rather than expiry."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pin_dev_key_env():
    """Pin the dev flow under R6c: scrub any configured key so the
    harness double opt-in (tests/__init__: in-code enable_dev_keys() +
    GOV_DEV_KEYS=1) resolves the public dev key. Explicitly configuring
    dev material is rejected outright since the KMS milestone (F73)."""
    saved = {n: os.environ.get(n) for n in _KEY_NAMES}
    for n in _KEY_NAMES:
        os.environ.pop(n, None)
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)

    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    return restore


class _R9Case(unittest.TestCase):
    def setUp(self):
        self._restore_env = _pin_dev_key_env()
        self.addCleanup(self._restore_env)

    def _queue_send(self, ctx, q, ex, egress_bytes=5000, agent_id="a1"):
        action = {"tool": "send_email",
                  "args": {"to": "x@synthetic.local", "subject": "s",
                           "body": "b" * 100},
                  "identity": {"agent_id": agent_id, "role": "researcher",
                               "run_id": q.run_dir.name, "principal": "org"},
                  "redactions": [], "agent_justification": None}
        # F42 (R11): queue() requires a minted caller identity; the
        # action["identity"] dict is ignored by the queue.
        return q.queue(action,
                       PolicyDecision("require_approval", "t",
                                      policy_id="approval-outbound-sends",
                                      flag=None),
                       policy_hash=ex.policy.policy_hash,
                       egress_bytes=egress_bytes,
                       caller_identity=ctx["mint_identity"](
                           agent_id, "researcher", "org"))


# ---------------------------------------------------------------------------
# F34: keyed approval-record integrity digest
# ---------------------------------------------------------------------------

class TestF34KeyedApprovalDigest(_R9Case):
    """queue() MACs records under the log key; execute_approved verifies
    with the keyring and refuses anything without the keyed scheme."""

    def test_untampered_keyed_record_executes(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(ctx, q, ex)
        rec = q.get(aid)
        self.assertEqual(rec.get("digest_scheme"), APPROVAL_DIGEST_SCHEME)
        self.assertTrue(approval_digest_ok(rec))
        q.decide(aid, True, "legit", decided_by="ciso")
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(q.get(aid).get("executed"))

    def test_forged_unkeyed_digest_refused(self):
        # The pre-R9 attack: a forger recomputes the UNKEYED digest from
        # public inputs (no key needed) and writes an approved record.
        # F38 (R10): decide() verifies the pending digest before
        # re-MACing, so the forgery fails closed at decision time —
        # fail even earlier than the old execution-time refusal — and
        # the record stays pending, never executed.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(ctx, q, ex)
        q._rewrite(lambda rs: [dict(
            r,
            args_digest=record_digest(r["tool"], r["args"],
                                     r["policy_id"], r["egress_bytes"]),
            digest_scheme=None,
        ) if r["id"] == aid else r for r in rs])
        with self.assertRaisesRegex(ValueError, "integrity verification"):
            q.decide(aid, True, "looks fine", decided_by="ciso")
        done = ex.execute_approved()
        rec = q.get(aid)
        self.assertEqual(done, [])
        self.assertFalse(rec.get("executed"))
        self.assertEqual(rec.get("status"), "pending")

    def test_tampered_args_with_scheme_still_refused(self):
        # The R8 tamper shape under the new scheme: args changed after
        # queueing, scheme marker kept — the MAC no longer verifies.
        # F38 (R10): decide() verifies the pending digest before
        # re-MACing, so the tamper fails closed HERE (fail even earlier
        # than the old execution-time refusal), audit-logged; the
        # record stays pending and never executes.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(ctx, q, ex)
        q._rewrite(lambda rs: [dict(
            r, args=dict(r["args"], body="EVIL" * 100),
        ) if r["id"] == aid else r for r in rs])
        with self.assertRaisesRegex(ValueError, "integrity verification"):
            q.decide(aid, True, "looks fine", decided_by="ciso")
        done = ex.execute_approved()
        rec = q.get(aid)
        self.assertEqual(done, [])
        self.assertEqual(rec.get("status"), "pending")
        self.assertFalse(rec.get("executed"))

    def test_wrong_key_digest_rejected(self):
        # A MAC computed under a key that is not in the keyring never
        # verifies — unit level (no env games with the ledger).
        import gov.log as L
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(ctx, q, ex)
        rec = q.get(aid)
        canon = _security_record_payload(rec)
        forged = L._approval_record_mac(b"wrong-key-bytes", "wrong-epoch",
                                        canon)
        bad = dict(rec, args_digest=forged)
        self.assertFalse(approval_digest_ok(bad))
        self.assertTrue(approval_digest_ok(rec))

    def test_rotation_archive_epoch_still_verifies(self):
        # A record MACed under an archived epoch verifies via the
        # keyring: rotation does not invalidate in-flight approvals.
        import gov.log as L
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(ctx, q, ex)
        rec = q.get(aid)
        old_key, old_epoch = L._active_key()
        # rotate: new active key, old epoch in the archive
        os.environ["GOV_LOG_KEY"] = "brand-new-operator-key"
        os.environ["GOV_LOG_KEY_EPOCH"] = "epoch-2"
        os.environ["GOV_LOG_KEY_ARCHIVE"] = json.dumps(
            {old_epoch: old_key.decode("utf-8")})
        try:
            self.assertTrue(approval_digest_ok(rec))
            # ...but a MAC under a never-configured epoch still fails
            canon = _security_record_payload(rec)
            forged = L._approval_record_mac(b"never-configured",
                                            "epoch-9", canon)
            self.assertFalse(approval_digest_ok(dict(rec, args_digest=forged)))
        finally:
            self._restore_env()
            self._restore_env = _pin_dev_key_env()

    def test_record_without_egress_bytes_rejected_fail_closed(self):
        # F34/F33: approval_digest_ok() NEVER accepts a record without
        # egress_bytes — even carrying the keyed scheme marker. The
        # keyed scheme (hmac-sha256-v1) postdates egress_bytes (F33,
        # wave 9), so no legitimate keyed three-field record ever
        # existed; accepting one would let an attacker strip
        # egress_bytes to dodge the F33 volume binding. And there is
        # NEVER an unkeyed fallback: a correctly recomputed unkeyed
        # digest is rejected with or without the scheme marker.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(ctx, q, ex)
        rec = q.get(aid)
        # sanity: the intact four-field keyed record verifies.
        self.assertTrue(approval_digest_ok(rec))
        # 1. scheme-marked record with egress_bytes stripped -> rejected.
        no_eb = {k: v for k, v in rec.items() if k != "egress_bytes"}
        self.assertFalse(approval_digest_ok(no_eb))
        # 2. no unkeyed fallback: the pre-R9 unkeyed digest, recomputed
        # correctly from public inputs, is rejected both with and
        # without the scheme marker.
        unkeyed = record_digest(rec["tool"], rec["args"],
                                rec["policy_id"], rec["egress_bytes"])
        self.assertFalse(approval_digest_ok(dict(rec, args_digest=unkeyed)))
        self.assertFalse(approval_digest_ok(
            dict(rec, args_digest=unkeyed, digest_scheme=None)))
        # 3. execute_approved() refuses (not crashes on) a
        # scheme-marked record missing egress_bytes. F38 (R10):
        # decide() verifies the pending digest before re-MACing, so
        # the refusal now happens even earlier — at decision time,
        # fail-closed ValueError — and execution is never reached.
        aid2 = self._queue_send(ctx, q, ex)
        q._rewrite(lambda rs: [
            {k: v for k, v in r.items() if k != "egress_bytes"}
            if r["id"] == aid2 else r for r in rs])
        with self.assertRaisesRegex(ValueError, "integrity verification"):
            q.decide(aid2, True, "ok", decided_by="human-operator")
        ex.execute_approved()
        got = q.get(aid2)
        self.assertIsNot(got.get("executed"), True)
        self.assertEqual(got.get("status"), "pending")

    def test_dev_key_forgery_residual_documented(self):        # HONEST RESIDUAL: with GOV_LOG_KEY unset the MAC key is the
        # PUBLIC development key, so a docs-reader CAN mint a valid
        # keyed record. This test pins the residual: keyed forgery under
        # the dev key executes, which is why production MUST set a key.
        for n in _KEY_NAMES:
            os.environ.pop(n, None)
        try:
            ctx = make_run()
            q, ex = ctx["approvals"], ctx["executor"]
            args = {"to": "ops@synthetic.local", "subject": "s",
                    "body": "b" * 10}
            eb = 500
            rec = {
                "id": "devforge1", "ts": _fresh_utc_z(),
                "run_id": q.run_dir.name, "agent_id": "adv-x",
                "role": "support",
                "identity": {"agent_id": "adv-x", "role": "support",
                             "run_id": q.run_dir.name,
                             "principal": "adversary-org"},
                "tool": "send_email", "args": args,
                "redactions_applied": [], "agent_justification": None,
                "provenance": "agent_direct", "preview": "p",
                "delegation_attempted": False,
                "policy_id": "approval-outbound-sends",
                "policy_reason": "forged", "policy_flag": None,
                "policy_hash": ex.policy.policy_hash,
                "digest_scheme": APPROVAL_DIGEST_SCHEME,
                "egress_bytes": eb,
                "status": "approved", "decided_by": "human-operator",
                "decided_at": _fresh_utc_z(),
                "decision_reason": "looks fine", "executed": False,
                "policy_context": {"domain_allowlisted": True},
                "flood_suspect": False, "break_glass": False,
                "break_glass_reason": None,
            }
            # docs-reader computes the KEYED digest: the dev key is
            # public, so this is computable from the docs alone.
            # F38 (R10): the digest binds run_id and decided_by —
            # the forger must bind the TARGET run and a decider,
            # exactly like a legitimate record.
            # F43 (R11): the digest covers the full security payload;
            # the forger passes the whole record.
            rec["args_digest"] = approval_record_digest(rec)
            with open(q.run_dir / "approvals.jsonl", "a",
                       encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=True) + "\n")
            done = ex.execute_approved()
            self.assertEqual(len(done), 1,
                             "dev-key residual: a docs-reader can forge a "
                             "keyed record while GOV_LOG_KEY is unset — "
                             "production MUST configure a real key")
            self.assertTrue(q.get("devforge1").get("executed"))
        finally:
            self._restore_env()
            self._restore_env = _pin_dev_key_env()


# ---------------------------------------------------------------------------
# F35: approval-history discount can never flip auto-approve
# ---------------------------------------------------------------------------

class TestF35HistoryDiscount(_R9Case):
    """Untrusted-influenced items get no veteran discount; auto-approve
    re-scores history-neutral as a second gate; benign repeat traffic
    keeps the queue-ordering discount."""

    def _queue_api(self, ctx, q, ph, agent_id, provenance="agent_direct",
                   pctx=None):
        ident = {"agent_id": agent_id, "role": "support",
                 "run_id": q.run_dir.name, "principal": "p"}
        action = {"tool": "api_call",
                  "args": {"endpoint": "https://api.vendor.example/v1/send",
                           "params": {"q": "x"}},
                  "identity": ident, "redactions": [],
                  "agent_justification": None}
        # F42 (R11): queue() requires a minted caller identity; the
        # action["identity"] dict is ignored by the queue.
        return q.queue(
            action,
            PolicyDecision("require_approval", "r",
                           policy_id="approval-outbound-sends", flag=None),
            provenance, "would call API", policy_hash=ph,
            policy_context=pctx or {},
            caller_identity=ctx["mint_identity"](agent_id, "support", "p"))

    def _veteran(self, ctx, q, ph, agent_id="adv-vet", n=6):
        for _ in range(n):
            aid = self._queue_api(ctx, q, ph, agent_id)
            q.decide(aid, True, "ok", decided_by="ciso")

    def test_untrusted_scores_identical_for_veteran_and_unknown(self):
        ctx = make_run()
        q = ctx["approvals"]
        ph = ctx["executor"].policy.policy_hash
        aid_new = self._queue_api(
            ctx, q, ph, "adv-new", "untrusted_influenced",
            {"source_untrusted": True})
        det_new = q.risk_detail(q.get(aid_new))
        self._veteran(ctx, q, ph)
        aid_vet = self._queue_api(
            ctx, q, ph, "adv-vet", "untrusted_influenced",
            {"source_untrusted": True})
        det_vet = q.risk_detail(q.get(aid_vet))
        self.assertEqual(det_new["score"], det_vet["score"],
                         "F35: history must not discount untrusted items")
        self.assertIn("unknown agent (no prior decisions) +10",
                      det_new["factors"])
        self.assertIn("untrusted provenance: history discount withheld +10",
                      det_vet["factors"])
        self.assertIn("untrusted-influenced provenance +15",
                      det_vet["factors"])

    def test_benign_repeat_traffic_keeps_discount(self):
        ctx = make_run()
        q = ctx["approvals"]
        ph = ctx["executor"].policy.policy_hash
        self._veteran(ctx, q, ph)
        aid_vet = self._queue_api(ctx, q, ph, "adv-vet")
        aid_new = self._queue_api(ctx, q, ph, "adv-new")
        self.assertLess(q.risk(q.get(aid_vet)), q.risk(q.get(aid_new)),
                        "F35: the discount survives for genuinely benign "
                        "repeat traffic (queue ordering only)")

    def test_auto_approve_never_flipped_by_history(self):
        # write_file base 15: the veteran's discounted score (15) fits
        # under a cap of 20, but the history-neutral score (25) does
        # not — the item must stay pending for a human.
        ctx = make_run()
        q = ctx["approvals"]
        ph = ctx["executor"].policy.policy_hash
        self._veteran(ctx, q, ph, agent_id="writer", n=3)
        ident = {"agent_id": "writer", "role": "researcher",
                 "run_id": q.run_dir.name, "principal": "p"}
        aid = q.queue(
            {"tool": "write_file",
             "args": {"path": "notes.txt", "content": "hello"},
             "identity": ident, "redactions": [],
             "agent_justification": None},
            PolicyDecision("require_approval", "r",
                           policy_id="approval-file-writes", flag=None),
            "agent_direct", "would write file", policy_hash=ph,
            caller_identity=ctx["mint_identity"](
                "writer", "researcher", "p"))
        self.assertLessEqual(q.risk(q.get(aid)), 20)
        self.assertGreater(q._risk_no_discount(q.get(aid)), 20)
        decided = q.maybe_auto_approve(
            aid, {"enabled": True, "max_risk_score": 20})
        self.assertIsNone(decided,
                          "F35: history-neutral score exceeds the cap — "
                          "the discount must not flip auto-approve")
        self.assertEqual(q.get(aid)["status"], "pending")

    def test_genuinely_low_risk_still_auto_approves(self):
        # Control: an item that is low-risk even history-neutral still
        # auto-approves under an opt-in cap (the second gate is not a
        # blanket block).
        ctx = make_run()
        q = ctx["approvals"]
        ph = ctx["executor"].policy.policy_hash
        aid = self._queue_api(ctx, q, ph, "adv-new")
        self.assertLessEqual(q._risk_no_discount(q.get(aid)), 25)
        decided = q.maybe_auto_approve(
            aid, {"enabled": True, "max_risk_score": 25})
        self.assertIsNotNone(decided)
        self.assertEqual(decided["status"], "approved")
        self.assertEqual(decided["decided_by"], "auto-approve")


# ---------------------------------------------------------------------------
# F36: cross-principal campaign correlation
# ---------------------------------------------------------------------------

class TestF36CrossPrincipalCampaign(_R9Case):
    """A campaign that mints a fresh principal per run is correlated by
    shape across principals; single-principal behavior is unchanged."""

    def _run_calls(self, ledger_path, principal, n=2, keys=("blob", "seq"),
                   endpoint="https://shard0.collector.synthetic.local/x"):
        ctx = make_run(ledger_path=ledger_path)
        ex = ctx["executor"]
        ident = ex.mint_identity("agent", "researcher", principal)
        statuses = []
        for j in range(n):
            params = {k: ("A1B2C3D4E5F6G7H8!" if k == "blob" else j)
                      for k in keys}
            r = ex.call(ident, "api_call", endpoint=endpoint, params=params)
            statuses.append(r["status"])
        return statuses

    def test_principal_rotation_same_shape_queues(self):
        # F46 (R11): the cross-principal quorum needs K-1 ESTABLISHED
        # principals — multi-run history in permissive mode. rot-0..2
        # are established across two distinct runs each; a fourth fresh
        # principal (rot-3) rotating in with the same campaign shape
        # completes the quorum and queues.
        with tempfile.TemporaryDirectory(prefix="govr9led-") as td:
            led = str(Path(td) / "egress_ledger.jsonl")
            st = []
            for _ in range(2):
                for run in range(3):
                    st += self._run_calls(led, "rot-%d" % run, n=1)
            st += self._run_calls(led, "rot-3", n=1)
            # rot-0..rot-2 establish across their two runs (the quorum
            # fires once K-1 are established); the fresh rot-3 rotation
            # queues.
            self.assertIn("queued", st,
                          "F46: rotation into an established-principal "
                          "campaign must queue: %r" % (st,))
            self.assertEqual(st[-1], "queued",
                             "the fresh rotating principal's call queues")

    def test_allowlisted_attempt_suppressed_from_cross_principal_queue(self):
        # F36/F18: an exact allowlisted (principal, domain, param keys)
        # attempt is suppressed from cross-principal queueing — still
        # ledgered and audit-logged — while the same shape from other
        # (non-allowlisted) principals queues.
        # F41 (R10): the quorum now needs K-1 established principals,
        # so each non-allowlisted principal emits twice (history) and
        # the 3rd distinct principal's calls queue; the allowlisted
        # poller still executes even as the 4th distinct principal.
        with tempfile.TemporaryDirectory(prefix="govr9led-") as td:
            td = Path(td)
            led = str(td / "egress_ledger.jsonl")
            base = Path("policies/default.yaml").read_text()
            pol_allow = base.replace(
                "campaign_allowlist: []",
                "campaign_allowlist:\n"
                "  - [\"poller\", \"synthetic.local\", [\"x\"]]\n")
            pol_path = td / "policy-allow.yaml"
            pol_path.write_text(pol_allow)
            EP = "https://shard0.collector.synthetic.local/x"
            frag_val = "A1B2C3D4E5F6G7H8!"
            st = []
            # F46 (R11): establishment needs 2 DISTINCT RUN IDs per
            # principal — one call in each of two runs (two calls in
            # one run no longer establishes).
            for _ in range(2):
                for p in ("a1", "a2", "a3"):
                    ctx = make_run(ledger_path=led)
                    ex = ctx["executor"]
                    ident = ex.mint_identity("agent", "researcher", p)
                    r = ex.call(ident, "api_call", endpoint=EP,
                                params={"y": frag_val})
                    st.append(r["status"])
            self.assertEqual(st, ["executed"] * 4 + ["queued"] * 2)
            # the allowlisted poller emits the same SHAPE (different key
            # name — the sketch is name-blind) but its exact allowlisted
            # tuple suppresses the queue for its own attempt
            ctxp = make_run(ledger_path=led, policy_path=str(pol_path))
            exp = ctxp["executor"]
            identp = exp.mint_identity("agent", "researcher", "poller")
            rp = exp.call(identp, "api_call", endpoint=EP,
                          params={"x": frag_val})
            self.assertEqual(rp["status"], "executed")
            log_text = (ctxp["run_dir"] / "actions.jsonl").read_text()
            self.assertIn('"event": "campaign_allowlisted"', log_text)

    def test_benign_single_principal_poller_unaffected(self):
        # One principal polling across runs with varying telemetry key
        # sets never trips the cross-principal signal (one principal)
        # nor the structural signal (key set changes per run).
        with tempfile.TemporaryDirectory(prefix="govr9led-") as td:
            led = str(Path(td) / "egress_ledger.jsonl")
            st = []
            for run in range(4):
                ctx = make_run(ledger_path=led)
                ex = ctx["executor"]
                ident = ex.mint_identity("agent", "researcher", "poller")
                r = ex.call(ident, "api_call",
                            endpoint="https://health.vendor.synthetic.local/ping",
                            params={"status": "ok", "m%d" % run: run})
                st.append(r["status"])
            self.assertEqual(st, ["executed"] * 4)

    def test_principal_and_param_key_rotation_queues(self):
        # F36 CLOSURE: rotating the principal AND the param key set per
        # run still queues — correlation is param-name-blind (content
        # shape sketch), so key rotation does not evade the
        # cross-principal signal.
        # F46 (R11): the quorum needs K-1 established principals, so
        # each rotating principal is established across two distinct
        # runs (same-run priming no longer establishes).
        with tempfile.TemporaryDirectory(prefix="govr9led-") as td:
            led = str(Path(td) / "egress_ledger.jsonl")
            EP = "https://shard0.collector.synthetic.local/x"
            frag_val = "A1B2C3D4E5F6G7H8!"
            st = []
            for _ in range(2):
                for run in range(4):
                    ctx = make_run(ledger_path=led)
                    ex = ctx["executor"]
                    ident = ex.mint_identity("agent", "researcher",
                                             "krot-%d" % run)
                    r = ex.call(ident, "api_call", endpoint=EP,
                                params={"k%d" % run: frag_val, "seq": run})
                    st.append(r["status"])
            self.assertEqual(st[:4], ["executed"] * 4)
            self.assertIn("queued", st[4:],
                          "F36: principal + param-key rotation must "
                          "queue via the name-blind shape sketch once "
                          "K-1 principals are multi-run established: %r"
                          % (st,))

    def test_ledger_cross_principal_counts_distinct_principals(self):
        from gov.egress_ledger import EgressLedger

        def _shape(domain="c.example", n=2, sb=32, ent=2.5, frag=True):
            return {"campaign_domain": domain, "n_params": n,
                    "str_bytes": sb, "max_entropy": ent, "fragment": frag}

        def _frag_entry(now, principal, run_id, keys=("blob", "seq")):
            return {"ts": now, "run_id": run_id,
                    "principal": principal, "tool": "api_call",
                    "endpoint": "https://c.example/x",
                    "campaign_domain": "c.example",
                    "n_params": 2, "param_keys": list(keys),
                    "str_bytes": 32, "max_entropy": 2.5,
                    "fragment": True}

        with tempfile.TemporaryDirectory(prefix="govr9led-") as td:
            led = EgressLedger(Path(td) / "egress_ledger.jsonl")
            now = 1700000000.0
            for p in ("p1", "p2"):
                led.append(_frag_entry(now, p, "r-%s" % p))
            self.assertFalse(led.cross_principal_campaign_hit(
                _shape(), now=now, k=3))
            # F41 (R10): three FIRST-SEEN principals no longer form a
            # quorum — the K-1 establishment bar is not met. This is
            # the throwaway-planted shape: cheap fresh principals must
            # not let an attacker queue a victim's call.
            led.append(_frag_entry(now, "p3", "r-p3", keys=("zz", "qq")))
            self.assertFalse(led.cross_principal_campaign_hit(
                _shape(), now=now, k=3))
            # A genuine campaign — each participant emits repeatedly,
            # so K-1 of them are established — still fires. Param-key
            # rotation stays name-blind: p3's different key names still
            # count toward the same shape.
            for p in ("p1", "p2", "p3"):
                led.append(_frag_entry(now, p, "r2-%s" % p))
            self.assertTrue(led.cross_principal_campaign_hit(
                _shape(), now=now, k=3))
            # non-fragment entries never count, even at K principals
            led2 = EgressLedger(Path(td) / "egress_ledger2.jsonl")
            for p in ("p1", "p2", "p3"):
                led2.append({"ts": now, "run_id": "r-%s" % p,
                             "principal": p, "tool": "api_call",
                             "endpoint": "https://c.example/x",
                             "campaign_domain": "c.example",
                             "n_params": 2, "param_keys": ["blob", "seq"],
                             "str_bytes": 5000, "max_entropy": 1.0,
                             "fragment": False})
            self.assertFalse(led2.cross_principal_campaign_hit(
                _shape(frag=False), now=now, k=3))

    def test_non_rotating_campaign_still_queues(self):
        # The original per-principal fragment detector is unchanged: 3
        # thin runs from ONE principal still queue.
        with tempfile.TemporaryDirectory(prefix="govr9led-") as td:
            led = str(Path(td) / "egress_ledger.jsonl")
            st = []
            for run in range(3):
                st += self._run_calls(led, "drip")
            self.assertIn("queued", st[2:],
                          "F36: non-rotating fragment campaign must still "
                          "queue via the per-principal detector: %r" % (st,))


# ---------------------------------------------------------------------------
# F37: MCP / run_body result ingestion into the provenance/taint store
# ---------------------------------------------------------------------------

class TestF37MCPResultIngestion(_R9Case):
    """A sensitive MCP server result taints the run exactly like a
    sensitive native result; benign results leave behavior unchanged."""

    def _mcp_client(self, ex, ident, results, tool="read_file"):
        from gov.adapters.core import GovernedBinding
        from gov.adapters.mcp_adapter import (
            DeterministicFakeSession, GovernedMCPClient)
        binding = GovernedBinding(ex, ident, tool_map={tool: tool})
        return GovernedMCPClient(binding,
                                 DeterministicFakeSession(results=results))

    def test_mcp_sensitive_result_taints_and_gates_followup(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent", "researcher", "p")
        secret = "db password: AKIA1234567890ABCDEF"
        client = self._mcp_client(ex, ident, {"read_file": {"content": secret}})
        res = asyncio.run(client.call_tool("read_file", {"path": "notes.txt"}))
        # the server result is returned verbatim ...
        self.assertEqual(res, {"content": secret})
        # ... but its content entered the taint store
        self.assertTrue(ex._read_sensitive)
        self.assertTrue(any(secret in c for c in ex._read_contents))
        # a follow-up paraphrase api_call (no verbatim overlap) is
        # approval-gated by the sensitive-read-before-api rule
        r2 = ex.call(ident, "api_call", endpoint="https://x.synthetic.local/v1",
                     params={"q": "summarize the db configuration"})
        self.assertEqual(r2["status"], "queued")
        self.assertEqual(r2.get("policy_id"),
                         "approval-sensitive-read-before-api")

    def test_mcp_benign_result_leaves_run_untainted(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent", "researcher", "p")
        client = self._mcp_client(
            ex, ident, {"read_file": {"content": "sunny day, no secrets"}})
        res = asyncio.run(client.call_tool("read_file", {"path": "notes.txt"}))
        self.assertEqual(res, {"content": "sunny day, no secrets"})
        self.assertFalse(ex._read_sensitive)
        r2 = ex.call(ident, "api_call", endpoint="https://x.synthetic.local/v1",
                     params={"q": "hi"})
        self.assertEqual(r2["status"], "executed")

    def test_mcp_string_result_ingested_verbatim(self):
        # Non-dict server results (plain strings) ingest without
        # crashing and are still returned verbatim.
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent", "researcher", "p")
        body = "token: AKIA1234567890ABCDEF"
        client = self._mcp_client(ex, ident, {"read_file": body})
        res = asyncio.run(client.call_tool("read_file", {"path": "notes.txt"}))
        self.assertEqual(res, body)
        self.assertTrue(ex._read_sensitive)

    def test_mcp_content_blocks_ingested(self):
        # MCP CallToolResult-shaped content blocks ([{type, text}]).
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent", "researcher", "p")
        blocks = [{"type": "text",
                   "text": "api key: AKIA1234567890ABCDEF"}]
        client = self._mcp_client(
            ex, ident, {"read_file": {"content": blocks, "isError": False}})
        res = asyncio.run(client.call_tool("read_file", {"path": "n.txt"}))
        self.assertEqual(res["content"], blocks)
        self.assertTrue(ex._read_sensitive)

    def test_mcp_object_content_blocks_ingested(self):
        # Real MCP SDK results are OBJECTS: CallToolResult.content is a
        # list of TextContent objects exposing .text (no ["text"]).
        # Normalization must read each block's .text, ingest it, and
        # return the original object unchanged (assertIs).
        class _TextBlock:
            def __init__(self, text):
                self.type = "text"
                self.text = text

        class _CallToolResult:
            def __init__(self, content):
                self.content = content
                self.isError = False

        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent", "researcher", "p")
        secret = "AIza" + "x" * 35  # synthetic: trips dlp-google-api-key
        blocks = [_TextBlock("hello"),
                  _TextBlock("customer api_key=" + secret)]
        server_result = _CallToolResult(blocks)
        client = self._mcp_client(ex, ident,
                                  {"read_file": server_result})
        res = asyncio.run(client.call_tool("read_file", {"path": "n.txt"}))
        # the exact original object is returned unchanged ...
        self.assertIs(res, server_result)
        # ... but every block's .text entered the taint store
        self.assertTrue(ex._read_sensitive)
        self.assertTrue(any(secret in c for c in ex._read_contents))
        # and a follow-up paraphrase api_call is approval-gated
        r2 = ex.call(ident, "api_call", endpoint="https://x.synthetic.local/v1",
                     params={"q": "summarize the credentials file"})
        self.assertEqual(r2["status"], "queued")
        self.assertEqual(r2.get("policy_id"),
                         "approval-sensitive-read-before-api")

    def test_generic_adapter_run_body_result_ingested(self):
        # The same blind spot in the generic adapter: a run_body=True
        # real body whose result is sensitive taints the run.
        from gov.adapters.core import GovernedBinding
        from gov.adapters.generic import governed
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent", "researcher", "p")
        binding = GovernedBinding(ex, ident)

        @governed(binding, "read_file", run_body=True)
        def read_file(path):
            return {"content": "passwd: AKIA1234567890ABCDEF"}

        out = read_file(path="notes.txt")
        self.assertEqual(out["status"], "executed")
        self.assertIn("body_result", out)
        self.assertTrue(ex._read_sensitive)
        r2 = ex.call(ident, "api_call", endpoint="https://x.synthetic.local/v1",
                     params={"q": "summarize the credentials file"})
        self.assertEqual(r2["status"], "queued")
        self.assertEqual(r2.get("policy_id"),
                         "approval-sensitive-read-before-api")


if __name__ == "__main__":
    unittest.main()
