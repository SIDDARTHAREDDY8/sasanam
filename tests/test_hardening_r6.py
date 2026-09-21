"""Round-6 hardening regressions: F23..F26 CLOSED.

F23 — the egress ledger's stat cache can no longer be evaded by a
      same-length rewrite + mtime restoration (W7-1): the signature
      includes st_ctime_ns (os.utime cannot restore ctime), and the
      cache is bypassed entirely when no real HMAC key is configured
      (the public dev key is not an integrity anchor). Tampering raises
      LedgerUnverifiableError and is audit-logged as ledger-unverifiable.
F24 — security-excluded queue items can never be auto-approved (W7-2):
      maybe_auto_approve returns None for them; batch_decide and
      --confirm-risky already refused, and the exclusion is now pinned on
      all three paths.
F25 — ActionLog.append serializes across processes under a POSIX flock
      (W7-3): concurrent writers linearize — no duplicate seqs, no chain
      fork; lock acquisition failure raises AppendLockError without
      writing.
F26 — break-glass binds to the executor-minted AgentIdentity object,
      not a caller-supplied string (W7-4): ticket and audit log carry
      the authenticated identity/principal; resolve_review refuses the
      same principal (even under an alias agent_id), the same identity,
      strings, and unminted identities.

Determinism: stdlib only; key material is fixed test values restored
after each test class.  No network, no clock dependence (one small
sleep guards filesystem timestamp granularity in the ctime test).
"""

import fcntl
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
import unittest

from gov.approvals import ApprovalQueue
from gov.egress_ledger import EgressLedger, LedgerUnverifiableError
from gov.identity import AgentIdentity, UnmintedIdentityError
from gov.log import ActionLog, AppendLockError, verify_chain
import gov.log as log_mod
from gov.policy import PolicyEngine
from tests.harness import make_run, plant_file

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_POLICY = os.path.join(ROOT, "policies", "default.yaml")

_TEST_KEY = "round6-test-ledger-key-0000000000000001"
_KEY_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
              "GOV_DEV_KEYS")


def _scrub_key_env():
    """Snapshot + clear key env; returns a restore closure."""
    saved = {n: os.environ.get(n) for n in _KEY_NAMES}
    for n in _KEY_NAMES:
        os.environ.pop(n, None)

    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    return restore


def _policy_with(extra_yaml):
    """Copy the default policy to a temp file with extra YAML appended."""
    tmp = tempfile.mkdtemp(prefix="govr6pol-")
    path = os.path.join(tmp, "policy.yaml")
    with open(DEFAULT_POLICY, encoding="utf-8") as f:
        base = f.read()
    with open(path, "w", encoding="utf-8") as f:
        f.write(base)
        f.write("\n" + extra_yaml)
    return path


def _ledger_append(ledger, endpoint, params=None, principal="org"):
    ledger.append({
        "principal": principal,
        "endpoint": endpoint,
        "params": dict(params or {"check": "ping"}),
        "ts": 1700000000,
        "decision": "allow",
    })


def _same_length_rewrite(path, old, new):
    """Rewrite *path* replacing old->new (same length) and restore mtime."""
    assert len(old) == len(new)
    st = os.stat(path)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    assert old in text
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.replace(old, new))
    os.utime(path, ns=(st.st_mtime_ns, st.st_mtime_ns))


# ---------------------------------------------------------------------------
# F23 — ledger stat-cache evasion (W7-1)
# ---------------------------------------------------------------------------

class TestF23LedgerStatCache(unittest.TestCase):
    """The W7-1 rewrite+utime evasion is detected and refused."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.dir = tempfile.mkdtemp(prefix="r6f23-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _warmed_ctx(self, ledger_path, endpoint="https://x.synthetic.local/"):
        """make_run + ledger entry + two executor calls (warm the cache)."""
        ctx = make_run(ledger_path=ledger_path)
        ledger = ctx["executor"]._ledger
        _ledger_append(ledger, endpoint)
        time.sleep(0.02)  # separate the ctime tick from the tamper below
        ident = ctx["mint_identity"]("frag", "researcher", "org")
        plant_file(ctx, "f.txt", "hello")
        ex = ctx["executor"]
        ex.call(ident, "read_file", path="f.txt")
        ex.call(ident, "read_file", path="f.txt")
        return ctx, ident

    def _audit_refusals(self, ctx):
        with open(ctx["run_dir"] / "actions.jsonl",
                  encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()
                    and json.loads(line).get("policy_id")
                    == "ledger-unverifiable"]

    def test_utime_rewrite_detected_without_key(self):
        """Exact W7-1 repro: no GOV_LOG_KEY, warm cache, same-length
        rewrite + mtime restore -> the third call refuses."""
        lp = os.path.join(self.dir, "ledger.jsonl")
        ctx, ident = self._warmed_ctx(lp)
        _same_length_rewrite(lp, "synthetic.local", "synthetic.locax")
        with self.assertRaises(LedgerUnverifiableError):
            ctx["executor"].call(ident, "read_file", path="f.txt")
        refusals = self._audit_refusals(ctx)
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["decision"], "denied")

    def test_dev_key_is_not_an_integrity_anchor(self):
        """With only the public dev key, the stat cache is bypassed:
        _real_key_available() is False and the tamper is detected."""
        from gov.egress_ledger import _real_key_available
        self.assertFalse(_real_key_available())
        lp = os.path.join(self.dir, "ledger.jsonl")
        ctx, ident = self._warmed_ctx(lp)
        _same_length_rewrite(lp, "synthetic.local", "synthetic.locax")
        with self.assertRaises(LedgerUnverifiableError):
            ctx["executor"].call(ident, "read_file", path="f.txt")

    def test_control_mtime_change_still_refuses(self):
        """Control: tamper WITHOUT restoring mtime still refuses (the
        pre-existing size/mtime path is intact)."""
        lp = os.path.join(self.dir, "ledger.jsonl")
        ctx, ident = self._warmed_ctx(lp)
        with open(lp, "r", encoding="utf-8") as f:
            text = f.read()
        with open(lp, "w", encoding="utf-8") as f:
            f.write(text.replace("synthetic.local", "synthetic.locax"))
        with self.assertRaises(LedgerUnverifiableError):
            ctx["executor"].call(ident, "read_file", path="f.txt")

    def test_real_key_ctime_invalidates_cache(self):
        """With a real GOV_LOG_KEY, the ctime-backed signature misses the
        cache after rewrite+utime -> full re-verify -> refuse."""
        os.environ["GOV_LOG_KEY"] = _TEST_KEY
        lp = os.path.join(self.dir, "ledger.jsonl")
        ctx, ident = self._warmed_ctx(lp)
        _same_length_rewrite(lp, "synthetic.local", "synthetic.locax")
        with self.assertRaises(LedgerUnverifiableError):
            ctx["executor"].call(ident, "read_file", path="f.txt")

    def test_real_key_clean_ledger_verifies(self):
        """With a real key and no tamper, repeated verification succeeds
        (the cache path does not false-positive)."""
        os.environ["GOV_LOG_KEY"] = _TEST_KEY
        lp = os.path.join(self.dir, "ledger.jsonl")
        ctx, ident = self._warmed_ctx(lp)
        ledger = ctx["executor"]._ledger
        ledger.require_verified()
        ledger.require_verified()
        ctx["executor"].call(ident, "read_file", path="f.txt")


# ---------------------------------------------------------------------------
# F24 — excluded items can never be auto-approved (W7-2)
# ---------------------------------------------------------------------------

_CAMPAIGN_FRAGMENTS = ["frag-alpha-0001", "frag-beta-0002", "frag-gamma-0003"]


def _campaign_ctxs(policy_path, ledger_path, n=4):
    """n runs sharing one ledger; the later ones queue as a campaign."""
    ctxs = []
    for i in range(n):
        ctx = make_run(policy_path=policy_path, ledger_path=ledger_path)
        ident = ctx["mint_identity"]("frag-%d" % i, "researcher",
                                     "adversary-org")
        r = ctx["executor"].call(
            ident, "api_call", endpoint="https://w7batch.synthetic.local/x",
            params={"seq": i, "fragment": _CAMPAIGN_FRAGMENTS[i % 3]})
        ctxs.append((ctx, r))
    return ctxs


class TestF24ExcludedAutoApprove(unittest.TestCase):
    """Security-excluded items stay pending on every approval shortcut."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.dir = tempfile.mkdtemp(prefix="r6f24-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        with open(DEFAULT_POLICY, encoding="utf-8") as f:
            base = f.read()
        self.auto_policy = os.path.join(self.dir, "auto.yaml")
        with open(self.auto_policy, "w", encoding="utf-8") as f:
            f.write(base.replace(
                "campaign_allowlist: []",
                "campaign_allowlist: []\n\nauto_approve:\n  enabled: true\n"
                "  max_risk_score: 25"))

    def _queued_campaign_item(self):
        ledger = os.path.join(self.dir, "ledger.jsonl")
        ctxs = _campaign_ctxs(self.auto_policy, ledger)
        queued = [(c, r) for c, r in ctxs if r["status"] == "queued"]
        self.assertTrue(queued, "campaign did not queue")
        return queued[0]

    def test_maybe_auto_approve_refuses_excluded(self):
        ctx, r = self._queued_campaign_item()
        q = ctx["approvals"]
        auto_cfg = PolicyEngine(self.auto_policy).auto_approve
        out = q.maybe_auto_approve(r["approval_id"], auto_cfg)
        self.assertIsNone(out)
        rec = q.get(r["approval_id"])
        self.assertEqual(rec["status"], "pending")
        self.assertNotEqual(rec.get("decided_by"), "auto-approve")

    def test_batch_decide_still_excludes(self):
        ctx, r = self._queued_campaign_item()
        q = ctx["approvals"]
        decided, excluded, _ = q.batch_decide(
            [r["approval_id"]], True, "triage", decided_by="human-operator")
        self.assertEqual(decided, [])
        self.assertEqual(len(excluded), 1)
        self.assertEqual(q.get(r["approval_id"])["status"], "pending")

    def test_confirm_risky_cannot_override(self):
        ctx, r = self._queued_campaign_item()
        q = ctx["approvals"]
        decided, excluded, _ = q.batch_decide(
            [r["approval_id"]], True, "triage", decided_by="human-operator",
            confirm_risky=[r["approval_id"]])
        self.assertEqual(decided, [])
        self.assertEqual(len(excluded), 1)
        self.assertEqual(q.get(r["approval_id"])["status"], "pending")

    def test_exact_w7_2_repro_queued_not_executed(self):
        """The filed W7-2 repro: a queued campaign fragment under an
        auto-approve-enabled policy is NOT auto-approved/executed."""
        ledger = os.path.join(self.dir, "ledger2.jsonl")
        ctxs = _campaign_ctxs(self.auto_policy, ledger, n=3)
        ctx, r = ctxs[2]
        self.assertEqual(r["status"], "queued")
        q = ctx["approvals"]
        auto_cfg = PolicyEngine(self.auto_policy).auto_approve
        q.maybe_auto_approve(r["approval_id"], auto_cfg)
        rec = q.get(r["approval_id"])
        self.assertEqual(rec["status"], "pending")
        self.assertNotEqual(rec.get("decided_by"), "auto-approve")

    def test_non_excluded_low_risk_still_auto_approves(self):
        """The fix is categorical, not a blanket auto-approve kill: a
        low-risk non-excluded item still auto-approves under the policy."""
        ctx = make_run(policy_path=self.auto_policy,
                       ledger_path=os.path.join(self.dir, "l3.jsonl"))
        q = ctx["approvals"]
        ident = ctx["mint_identity"]("a1", "researcher", "org")
        aid = q.queue(
            {"tool": "read_file", "args": {"path": "notes.txt"},
             "identity": {"agent_id": "a1", "role": "researcher",
                          "run_id": ctx["run_dir"].name, "principal": "org"},
             "agent_justification": "u"},
            type("D", (), {"policy_id": "p", "reason": "r",
                           "flag": None})(), preview="p",
            caller_identity=ident)
        auto_cfg = PolicyEngine(self.auto_policy).auto_approve
        out = q.maybe_auto_approve(aid, auto_cfg)
        self.assertIsNotNone(out)
        self.assertEqual(q.get(aid)["status"], "approved")
        self.assertEqual(q.get(aid)["decided_by"], "auto-approve")


# ---------------------------------------------------------------------------
# F25 — concurrent ActionLog writers (W7-3)
# ---------------------------------------------------------------------------

def _f25_worker(path, barrier, n, tag):
    log = ActionLog(path)
    barrier.wait()
    for i in range(n):
        log.append({"event": "tool_call", "tool": "api_call",
                    "decision": "executed", "worker": tag, "i": i})


class TestF25ConcurrentAppends(unittest.TestCase):
    """Concurrent appends linearize: no dup seqs, chain verifies."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.dir = tempfile.mkdtemp(prefix="r6f25-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_two_processes_no_duplicates(self):
        path = os.path.join(self.dir, "actions.jsonl")
        n = 100
        barrier = multiprocessing.Barrier(2)
        procs = [multiprocessing.Process(
            target=_f25_worker, args=(path, barrier, n, p))
            for p in range(2)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(120)
            self.assertEqual(p.exitcode, 0)
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 2 * n)
        parsed = [json.loads(line) for line in lines]  # all JSON intact
        seqs = [e["seq"] for e in parsed]
        self.assertEqual(len(set(seqs)), 2 * n)  # zero duplicate seqs
        self.assertEqual(sorted(seqs), list(range(1, 2 * n + 1)))
        ok, broken, count = verify_chain(path)
        self.assertTrue(ok, broken)
        self.assertEqual(count, 2 * n)

    def test_lock_timeout_fails_closed_without_writing(self):
        """If the append lock cannot be acquired, append raises
        AppendLockError and writes nothing (never unlocked)."""
        path = os.path.join(self.dir, "actions.jsonl")
        log = ActionLog(path)
        log.append({"event": "seed"})
        hold = open(path, "a", encoding="utf-8")
        self.addCleanup(hold.close)
        fcntl.flock(hold.fileno(), fcntl.LOCK_EX)  # hold the lock ourselves
        old_timeout = log_mod.APPEND_LOCK_TIMEOUT_SECS
        log_mod.APPEND_LOCK_TIMEOUT_SECS = 1
        self.addCleanup(setattr, log_mod, "APPEND_LOCK_TIMEOUT_SECS",
                        old_timeout)
        with self.assertRaises(AppendLockError):
            log.append({"event": "should-never-land"})
        fcntl.flock(hold.fileno(), fcntl.LOCK_UN)
        with open(path, encoding="utf-8") as f:
            lines = [line for line in f.read().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        with open(path, encoding="utf-8") as f:
            self.assertNotIn("should-never-land", f.read())
        ok, _, _ = verify_chain(path)
        self.assertTrue(ok)


# ---------------------------------------------------------------------------
# F26 — break-glass binds to authenticated identities (W7-4)
# ---------------------------------------------------------------------------

def _file_approval(ctx, endpoint="https://y.synthetic.local/"):
    q = ctx["approvals"]
    # F42 (R11): queue() requires a minted caller identity; the
    # action["identity"] dict is ignored by the queue.
    return q.queue(
        {"tool": "api_call", "args": {"endpoint": endpoint},
         "identity": {"agent_id": "a1", "role": "researcher",
                      "run_id": ctx["run_dir"].name,
                      "principal": "adversary-org"},
         "agent_justification": "u"},
        type("D", (), {"policy_id": "p", "reason": "r",
                       "flag": None})(), preview="p",
        caller_identity=ctx["mint_identity"](
            "a1", "researcher", "adversary-org"))


class TestF26BreakGlassIdentity(unittest.TestCase):
    """Break-glass binds to executor-minted identities; the alias
    self-approve from W7-4 is refused."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        # F49 (R11): break-glass tickets are human-provisioned BEFORE the
        # run starts; make_run seals them into the run-start snapshot.
        self.ctx = make_run(break_glass_tickets=[
            ("BG-R6-1", "alice", "carol"), ("BG-R6-2", "alice", "carol")])
        mint = self.ctx["mint_identity"]
        self.operator = mint("op-alice", "operator", "alice")
        # Same authenticated PRINCIPAL under an alias agent_id: the
        # exact W7-4 evasion shape.
        self.alias = mint("op-bob", "operator", "alice")
        self.reviewer = mint("op-carol", "reviewer", "carol")
        self.q = self.ctx["approvals"]

    def _break_glass(self, endpoint="https://y.synthetic.local/",
                     ticket_id="BG-R6-1"):
        aid = _file_approval(self.ctx, endpoint)
        return self.q.break_glass(aid, "incident",
                                  operator_identity=self.operator,
                                  ticket_id=ticket_id)
    def test_ticket_binds_identity_object(self):
        _, ticket = self._break_glass()
        bound = ticket["operator_identity"]
        self.assertEqual(bound["agent_id"], "op-alice")
        self.assertEqual(bound["role"], "operator")
        self.assertEqual(bound["principal"], "alice")
        self.assertEqual(bound["run_id"], self.ctx["run_dir"].name)

    def test_alias_same_principal_refused(self):
        """Exact W7-4 repro shape: same principal, different agent_id ->
        still refused (principal binding, not name inequality)."""
        _, ticket = self._break_glass()
        with self.assertRaises(ValueError):
            self.q.resolve_review(ticket["ticket_id"], "self-review",
                                  reviewer_identity=self.alias)
        self.assertEqual(self.q.pending_reviews()[0]["status"], "pending")

    def test_same_identity_refused(self):
        _, ticket = self._break_glass()
        with self.assertRaises(ValueError):
            self.q.resolve_review(ticket["ticket_id"], "self-review",
                                  reviewer_identity=self.operator)

    def test_distinct_principal_resolves(self):
        _, ticket = self._break_glass()
        target, entry = self.q.resolve_review(
            ticket["ticket_id"], "reviewed, all clear",
            reviewer_identity=self.reviewer)
        self.assertEqual(target["status"], "resolved")
        self.assertEqual(target["reviewer_identity"]["principal"], "carol")
        self.assertEqual(entry["reviewer_identity"]["principal"], "carol")
        self.assertEqual(entry["decided_by"], "carol")

    def test_string_operator_refused(self):
        aid = _file_approval(self.ctx)
        with self.assertRaises(TypeError):
            self.q.break_glass(aid, "incident", operator_identity="alice")

    def test_string_reviewer_refused(self):
        _, ticket = self._break_glass()
        with self.assertRaises(TypeError):
            self.q.resolve_review(ticket["ticket_id"], "x",
                                  reviewer_identity="carol")

    def test_unminted_identity_refused(self):
        fake = AgentIdentity(agent_id="mallory", role="reviewer",
                             run_id=self.ctx["run_dir"].name,
                             principal="mallory")
        with self.assertRaises(UnmintedIdentityError):
            self.q.break_glass(_file_approval(self.ctx), "incident",
                               operator_identity=fake)

    def test_audit_log_carries_identity(self):
        _, ticket = self._break_glass()
        self.q.resolve_review(ticket["ticket_id"], "reviewed",
                              reviewer_identity=self.reviewer)
        entries = []
        with open(self.ctx["run_dir"] / "actions.jsonl",
                  encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        bg = [e for e in entries
              if e.get("event") == "approval_break_glass"]
        self.assertEqual(len(bg), 1)
        self.assertEqual(bg[0]["operator_identity"]["principal"], "alice")
        self.assertEqual(bg[0]["decided_by"], "alice")
        rv = [e for e in entries
              if e.get("event") == "post_review_resolved"]
        self.assertEqual(len(rv), 1)
        self.assertEqual(rv[0]["reviewer_identity"]["principal"], "carol")
        self.assertEqual(rv[0]["decided_by"], "carol")


if __name__ == "__main__":
    unittest.main()
