"""Hardening round-8 regression tests: wave-9 findings F32 (HIGH), F33 (LOW).

F32: single-key action-log verification must bind every entry's key_epoch
label to the CONFIGURED epoch before checking the MAC (fail closed on
label mismatch), and the audit report must derive its key status from
the VERIFIED binding — never from self-declared labels.

F33: cumulative executed-egress byte budget
(rate_limit.max_egress_bytes_per_run) enforced at every execution
boundary, counting actual payload bytes DLP-independently; approved
sends count exactly once.

No network, no clock dependence. Deterministic: key env is pinned in
setUp and restored afterwards.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import make_run  # noqa: E402

_KEY_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH")


def _pin_dev_key_env():
    """Pin the key flow for the label-forgery tests: provision an EXPLICIT
    test key via the production env path (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH;
    wave-81 deleted the dev key from gov/).

    The configured epoch label is "dev" (operator-chosen label only —
    the key material is fresh random bytes per setUp). The F32 tests
    forge entry/checkpoint *labels* and assert the report derives status
    from the verifier-bound epoch, never from self-declared labels.
    """
    try:
        from tests.keyfixture import provision_test_key
    except ImportError:  # tests/ directly on sys.path
        from keyfixture import provision_test_key
    saved = {n: os.environ.get(n) for n in _KEY_NAMES}
    provision_test_key(epoch="dev")

    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    return restore


class _DevKeyPinnedCase(unittest.TestCase):
    def setUp(self):
        self._restore_env = _pin_dev_key_env()

    def tearDown(self):
        self._restore_env()


def _forge_log(d, entry_epoch, checkpoint_epoch, key=None):
    """Build a 3-entry chained log whose entries/checkpoint carry the
    given key_epoch labels, MAC'd under *key* (default: the explicitly
    provisioned test key from the environment — wave-81 deleted the dev
    key from gov/, so tests forge under their own configured key)."""
    import gov.log as L
    # The env backend uses the GOV_LOG_KEY *string* as UTF-8 bytes
    # (EnvKeyProvider.resolve); forge under exactly those bytes so the
    # forged log verifies against the provisioned key.
    key = key or os.environ["GOV_LOG_KEY"].encode("utf-8")
    prev = L.GENESIS
    entries = []
    for i in (1, 2, 3):
        e = {"seq": i, "ts": "2026-09-21T00:00:0%dZ" % i,
             "prev_hash": prev,
             "format_version": L.FORMAT_VERSION,
             "key_epoch": entry_epoch,
             "event": "tool_call", "decision": "allowed_executed"}
        e["hash"] = L._compute_mac(key, entry_epoch, prev,
                                   L._canonical(e))
        entries.append(e)
        prev = e["hash"]
    lp = str(d / "actions.jsonl")
    Path(lp).write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n",
        encoding="utf-8")
    cp = {"seq": 3, "hash": prev, "key_epoch": checkpoint_epoch,
          "format_version": L.FORMAT_VERSION,
          "mac": L._checkpoint_mac(key, checkpoint_epoch, 3, prev)}
    (d / "checkpoints.jsonl").write_text(json.dumps(cp) + "\n",
                                         encoding="utf-8")
    return lp, entries


# ---------------------------------------------------------------------------
# F32 — label forgery fails closed; report derives status from the binding
# ---------------------------------------------------------------------------

class TestF32LabelForgeryFailClosed(_DevKeyPinnedCase):
    """The wave-9 exact reproduction: entries labeled key_epoch=
    'production' but HMAC'd under the PUBLIC dev key must FAIL the
    single-key verifier — no MAC-mismatch ambiguity, a label-binding
    failure. And the report must render dev status for the configured
    dev key no matter what the labels claim."""

    def test_production_label_dev_key_fails_verify(self):
        import gov.log as L
        d = Path(tempfile.mkdtemp())
        lp, _ = _forge_log(d, "production", "production")
        v = L._verify(lp)
        self.assertFalse(v["ok"],
                         "production-labeled log signed with the public "
                         "dev key must FAIL single-key verification")
        self.assertIn("key_epoch label mismatch", v["error"] or "")
        self.assertIn("production", v["error"] or "")
        self.assertEqual(v["broken_seq"], 1)

    def test_require_verified_raises_typed_error(self):
        import gov.log as L
        d = Path(tempfile.mkdtemp())
        lp, _ = _forge_log(d, "production", "production")
        with self.assertRaises(L.LogUnverifiableError):
            L.require_verified(lp)

    def test_checkpoint_epoch_mismatch_fails(self):
        import gov.log as L
        d = Path(tempfile.mkdtemp())
        # Entries honestly labeled 'dev' (match the configured epoch);
        # the CHECKPOINT claims 'production' with a MAC valid for that
        # label — the label binding must still reject it.
        lp, _ = _forge_log(d, "dev", "production")
        v = L._verify(lp)
        self.assertFalse(v["ok"],
                         "checkpoint labeled with a non-configured epoch "
                         "must fail closed even with a valid MAC")
        self.assertIn("checkpoint key_epoch label mismatch",
                      v["error"] or "")

    def test_genuine_dev_log_still_verifies(self):
        import gov.log as L
        d = Path(tempfile.mkdtemp())
        lp, _ = _forge_log(d, "dev", "dev")
        v = L._verify(lp)
        self.assertTrue(v["ok"], "honest dev-labeled log must verify: %s"
                        % (v["error"],))
        self.assertEqual(v["key_epoch"], "dev")

    def test_report_status_derives_from_verified_epoch(self):
        import gov.log as L
        from demo.make_report import key_status
        d = Path(tempfile.mkdtemp())
        lp, entries = _forge_log(d, "production", "production")
        v = L._verify(lp)
        # The report derives status from the VERIFIED binding (the
        # configured epoch), never from the self-declared labels.
        ks = key_status(entries, v["key_epoch"])
        self.assertEqual(ks["verified_epoch"], "dev")
        self.assertEqual(ks["status"], "dev",
                         "forged production labels under the configured "
                         "dev key must render dev status, never nondev")
        self.assertEqual(ks["label_mismatch"], ["production"])
        self.assertIn("LABEL MISMATCH", ks["banner_line"])
        self.assertNotIn("Operator-configured key",
                         ks["banner_line"].split("LABEL MISMATCH")[0])

    def test_report_genuine_dev_log_renders_dev_clean(self):
        import gov.log as L
        from demo.make_report import key_status
        d = Path(tempfile.mkdtemp())
        lp, entries = _forge_log(d, "dev", "dev")
        v = L._verify(lp)
        ks = key_status(entries, v["key_epoch"])
        self.assertEqual(ks["status"], "dev")
        self.assertEqual(ks["label_mismatch"], [])
        self.assertIn("Non-production epoch label", ks["banner_line"])


# ---------------------------------------------------------------------------
# F33 — cumulative executed-egress byte budget
# ---------------------------------------------------------------------------

def _policy_with_budget(n):
    """Temp copy of the default policy with max_egress_bytes_per_run=n
    (int) or the raw YAML snippet replaced for malformed values."""
    base = (ROOT / "policies" / "default.yaml").read_text()
    if isinstance(n, int):
        text = base.replace("max_egress_bytes_per_run: 262144",
                            "max_egress_bytes_per_run: %d" % n)
    else:
        text = base.replace("max_egress_bytes_per_run: 262144",
                            "max_egress_bytes_per_run: %s" % n)
    tmp = Path(tempfile.mkdtemp()) / "policy.yaml"
    tmp.write_text(text, encoding="utf-8")
    return str(tmp)


def _api_bytes(i=0):
    # Deterministic: endpoint (allowlisted synthetic.local host — F94
    # denies api_call to non-allowlisted destinations) + canonical
    # params JSON.
    ep = "https://telemetry.synthetic.local/v1/x"
    return len(ep) + len(json.dumps({"i": i, "q": "y" * 280}, sort_keys=True,
                              ensure_ascii=False).encode("utf-8"))


class TestF33EgressByteBudget(unittest.TestCase):
    """Cumulative executed egress bytes across send_email/http_post/
    api_call, enforced at the call boundary AND at the approved-execution
    boundary, DLP-independent, approved sends counted exactly once."""

    def test_cumulative_clean_payload_trips_budget(self):
        # budget 1100; one api_call moves exactly _api_bytes() bytes
        # (DLP-clean 'y'*280 params). The 4th call's projection exceeds
        # the budget -> denied at the call boundary.
        run = make_run(policy_path=_policy_with_budget(1100))
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        one = _api_bytes()
        statuses = []
        for i in range(4):
            r = ex.call(ident, "api_call", endpoint="https://telemetry.synthetic.local/v1/x",
                        params={"q": "y" * 280, "i": i})
            statuses.append(r["status"])
        self.assertEqual(statuses[:3], ["executed"] * 3)
        self.assertEqual(statuses[3], "denied")
        last = ex.call(ident, "api_call", endpoint="https://telemetry.synthetic.local/v1/x",
                       params={"q": "y" * 280, "i": 99})
        self.assertEqual(last.get("policy_id"), "volume-guard-egress-bytes")
        self.assertEqual(ex._egress_bytes, 3 * one)
        self.assertEqual(ex._executed.get("api_call"), 3)

    def test_direct_and_approved_share_one_budget(self):
        # 2 direct api_calls (2*302=604 of 1000), then an approved send
        # (218) executes against the SAME budget: 822 total. A further
        # send is denied at the call boundary (822+218 > 1000).
        run = make_run(policy_path=_policy_with_budget(1000))
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        for i in range(2):
            r = ex.call(ident, "api_call", endpoint="https://telemetry.synthetic.local/v1/x",
                        params={"q": "y" * 280, "i": i})
            self.assertEqual(r["status"], "executed")
        send = ex.call(ident, "send_email", to="u@synthetic.local",
                       subject="s", body="z" * 200)
        self.assertEqual(send["status"], "queued")
        run["approvals"].decide(send["approval_id"], True, "ok")
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertEqual(ex._egress_bytes, 2 * _api_bytes() + 218)
        # The budget is shared: one more 218-byte send no longer fits.
        send2 = ex.call(ident, "send_email", to="u@synthetic.local",
                        subject="s", body="z" * 200)
        self.assertEqual(send2["status"], "denied")
        self.assertEqual(send2.get("policy_id"),
                         "volume-guard-egress-bytes")
        self.assertEqual(ex._egress_bytes, 2 * _api_bytes() + 218)

    def test_approved_execution_rechecks_budget_toctou(self):
        # Queue a 218-byte send while the budget is empty; consume 1002
        # via direct api_calls; the approved execution must REFUSE
        # (1002+218 > 1100) — the budget is re-checked at the actual
        # execution boundary, not just at queue time.
        run = make_run(policy_path=_policy_with_budget(1100))
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        send = ex.call(ident, "send_email", to="u@synthetic.local",
                       subject="s", body="z" * 200)
        self.assertEqual(send["status"], "queued")
        for i in range(3):
            r = ex.call(ident, "api_call", endpoint="https://telemetry.synthetic.local/v1/x",
                        params={"q": "y" * 280, "i": i})
            self.assertEqual(r["status"], "executed")
        run["approvals"].decide(send["approval_id"], True, "ok")
        done = ex.execute_approved()
        self.assertEqual(done, [])
        self.assertNotIn("send_email", ex._executed)
        self.assertEqual(ex._egress_bytes, 3 * _api_bytes())
        refused = [e for e in run["read_log"]()
                   if e.get("event") == "approval_execution_refused"]
        self.assertTrue(
            any(e.get("policy_id") == "volume-guard-egress-bytes"
                for e in refused),
            "TOCTOU budget refusal must be audit-logged with the "
            "volume-guard-egress-bytes policy id")

    def test_approved_send_counts_exactly_once(self):
        # The old defect: call() counted the attempt AND execute_approved
        # counted again. Each execution must count exactly once.
        run = make_run(policy_path=_policy_with_budget(100000))
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        send = ex.call(ident, "send_email", to="u@synthetic.local",
                       subject="s", body="hello")
        self.assertEqual(send["status"], "queued")
        run["approvals"].decide(send["approval_id"], True, "ok")
        ex.execute_approved()
        self.assertEqual(ex._executed.get("send_email"), 1)
        self.assertEqual(ex.counters.get("send_email"), 1)

    def test_all_three_egress_tools_covered(self):
        run = make_run(policy_path=_policy_with_budget(100000))
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        # api_call: direct execution path.
        r = ex.call(ident, "api_call", endpoint="https://telemetry.synthetic.local/v1/x",
                    params={"q": "1"})
        self.assertEqual(r["status"], "executed")
        # http_post + send_email: approval path.
        for tool, kw in (
                ("http_post", {"url": "https://synthetic.local/hook",
                               "payload": {"data": "abc"}}),
                ("send_email", {"to": "u@synthetic.local",
                                "subject": "s", "body": "b"})):
            rr = ex.call(ident, tool, **kw)
            self.assertEqual(rr["status"], "queued", tool)
            run["approvals"].decide(rr["approval_id"], True, "ok")
        done = ex.execute_approved()
        self.assertEqual(len(done), 2)
        for tool in ("send_email", "http_post", "api_call"):
            self.assertEqual(ex._executed.get(tool), 1, tool)
        # Byte accounting is exact and deterministic per tool.
        self.assertEqual(
            ex._egress_bytes,
            ex._egress_bytes_for("api_call",
                                 {"endpoint": "https://telemetry.synthetic.local/v1/x",
                                  "params": {"q": "1"}})
            + ex._egress_bytes_for(
                "http_post",
                {"url": "https://synthetic.local/hook",
                 "payload": {"data": "abc"}})
            + ex._egress_bytes_for("send_email",
                                   {"to": "u@synthetic.local",
                                    "subject": "s", "body": "b"}))

    def test_dlp_clean_payload_still_counted(self):
        # DLP-cleanliness must not bypass accounting: a 2000-byte clean
        # body is charged in full (raw bytes at the call boundary), even
        # though the queued redacted form summarizes it as {bytes,...}.
        run = make_run(policy_path=_policy_with_budget(100000))
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        raw = {"to": "u@synthetic.local", "subject": "s",
               "body": "x" * 2000}
        want = ex._egress_bytes_for("send_email", raw)
        self.assertEqual(want, 17 + 1 + 2000)
        send = ex.call(ident, "send_email", **raw)
        self.assertEqual(send["status"], "queued")
        run["approvals"].decide(send["approval_id"], True, "ok")
        ex.execute_approved()
        self.assertEqual(ex._egress_bytes, want,
                         "redacted queue form must not shrink the charge")

    def test_denied_and_queued_consume_no_budget(self):
        run = make_run(policy_path=_policy_with_budget(100000))
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        # Denied: non-allowlisted destination never executes.
        bad = ex.call(ident, "send_email", to="u@evil.example",
                      subject="s", body="b")
        self.assertEqual(bad["status"], "denied")
        # Queued but never approved/executed.
        q = ex.call(ident, "send_email", to="u@synthetic.local",
                    subject="s", body="b")
        self.assertEqual(q["status"], "queued")
        self.assertEqual(ex._egress_bytes, 0)
        self.assertEqual(ex._executed, {})


class TestF33BudgetLint(unittest.TestCase):
    """policy_lint validates max_egress_bytes_per_run: malformed ->
    error, absurdly high -> warning, default policy -> clean."""

    def _lint_cfg(self, snippet):
        tmp = Path(tempfile.mkdtemp()) / "p.yaml"
        tmp.write_text("rate_limit:\n  %s\n" % snippet, encoding="utf-8")
        from gov.policy_lint import lint_file
        return lint_file(str(tmp))

    def test_malformed_budget_is_error(self):
        from gov.policy_lint import lint_file  # noqa: F401
        for snippet in ("max_egress_bytes_per_run: 0",
                        "max_egress_bytes_per_run: -5",
                        'max_egress_bytes_per_run: "abc"',
                        "max_egress_bytes_per_run: true"):
            findings = self._lint_cfg(snippet)
            kinds = [f["kind"] for f in findings
                     if f["severity"] == "error"]
            self.assertIn("invalid_egress_budget", kinds,
                          "snippet %r must be a lint error" % snippet)

    def test_absurd_budget_warns(self):
        findings = self._lint_cfg("max_egress_bytes_per_run: 1073741824")
        kinds = [(f["kind"], f["severity"]) for f in findings]
        self.assertIn(("egress_budget_absurd", "warning"), kinds)

    def test_default_policy_has_no_budget_warning(self):
        from gov.policy_lint import lint_file
        findings = lint_file(str(ROOT / "policies" / "default.yaml"))
        bad = [f for f in findings
               if f["kind"] in ("invalid_egress_budget",
                                "egress_budget_absurd")]
        self.assertEqual(bad, [],
                         "default 256 KiB budget must not warn: %s" % (bad,))

    def test_default_policy_copies_identical(self):
        a = (ROOT / "policies" / "default.yaml").read_bytes()
        b = (ROOT / "gov" / "data" / "default.yaml").read_bytes()
        self.assertEqual(a, b,
                         "policies/default.yaml and gov/data/default.yaml "
                         "must stay byte-identical")


if __name__ == "__main__":
    unittest.main()


class _QueueDecision:
    """Minimal decision-like object for queueing records directly."""

    def __init__(self, policy_id, reason, flag=None):
        self.policy_id = policy_id
        self.reason = reason
        self.flag = flag


class TestF33EgressBytesIntegrityBound(unittest.TestCase):
    """The queued egress_bytes charge is bound by the approval integrity
    digest (record_digest covers tool/args/policy_id/egress_bytes): a
    queue record whose egress_bytes was lowered after queueing must
    refuse execution with approval_integrity_violation — never silently
    under-charge the F33 budget. Control: an untampered record executes
    and charges the full recorded bytes."""

    def _queue_send(self, q, ex, egress_bytes, caller):
        action = {"tool": "send_email",
                  "args": {"to": "x@synthetic.local", "subject": "s",
                           "body": "b" * 100},
                  "identity": {"agent_id": "a1", "role": "researcher",
                               "run_id": q.run_dir.name, "principal": "org"},
                  "redactions": [], "agent_justification": None}
        # F42 (R11): queue() requires a minted caller identity; the
        # action["identity"] dict is ignored by the queue.
        return q.queue(action,
                       _QueueDecision("approval-test", "test queue"),
                       policy_hash=ex.policy.policy_hash,
                       egress_bytes=egress_bytes,
                       caller_identity=caller)

    def _refusal_entries(self, ctx):
        from gov.log import read_entries
        return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_execution_refused"]

    def _all_entries(self, ctx):
        from gov.log import read_entries
        return read_entries(ctx["run_dir"] / "actions.jsonl")

    def test_tampered_egress_bytes_refuses_execution(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(
            q, ex, 5000,
            ctx["mint_identity"]("a1", "researcher", "org"))
        # attacker rewrites the queue record to under-report the charge
        q._rewrite(lambda rs: [dict(r, egress_bytes=1) if r["id"] == aid
                               else r for r in rs])
        # F38 (R10): decide() verifies the PENDING digest before
        # re-MACing, so a pre-decision rewrite can never be laundered by
        # the decision — the tamper fails closed HERE (fail even
        # earlier than the old execution-time refusal), audit-logged.
        with self.assertRaisesRegex(ValueError, "integrity verification"):
            q.decide(aid, True, "looks fine", decided_by="ciso")
        done = ex.execute_approved()
        rec = next(r for r in q.all() if r["id"] == aid)
        self.assertEqual(done, [])
        self.assertFalse(rec.get("executed"))
        self.assertEqual(rec.get("status"), "pending")
        attempts = [e for e in self._all_entries(ctx)
                    if e.get("event") == "approval_decision_attempt"]
        self.assertTrue(any(e.get("decision") == "rejected_attempt"
                            and e.get("approval_id") == aid
                            for e in attempts))
        # the budget was not charged for the refused execution
        self.assertEqual(ex._egress_bytes, 0)

    def test_tampered_egress_bytes_after_decision_refuses_execution(self):
        # F38 (R10) companion: the digest guards everything AFTER the
        # decision too — a rewrite of a DECIDED record still fails
        # closed at execution with approval_integrity_violation.
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(
            q, ex, 5000,
            ctx["mint_identity"]("a1", "researcher", "org"))
        q.decide(aid, True, "looks fine", decided_by="ciso")
        q._rewrite(lambda rs: [dict(r, egress_bytes=1) if r["id"] == aid
                               else r for r in rs])
        done = ex.execute_approved()
        rec = next(r for r in q.all() if r["id"] == aid)
        self.assertEqual(done, [])
        self.assertFalse(rec.get("executed"))
        self.assertIn("integrity digest mismatch",
                      rec.get("execution_refused_reason") or "")
        refusals = self._refusal_entries(ctx)
        self.assertTrue(any(e.get("flag") == "approval_integrity_violation"
                            and e.get("approval_id") == aid
                            for e in refusals))
        self.assertEqual(ex._egress_bytes, 0)

    def test_key_removal_does_not_downgrade_digest(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(
            q, ex, 5000,
            ctx["mint_identity"]("a1", "researcher", "org"))
        # attacker deletes the egress_bytes key entirely: the stored
        # digest was computed WITH it, so the legacy fallback must not
        # match. F38 (R10): decide() verifies the pending digest before
        # re-MACing, so the downgrade attempt fails closed HERE —
        # execution is never reached, and no weaker check is consulted.
        q._rewrite(lambda rs: [dict({k: v for k, v in r.items()
                                     if k != "egress_bytes"})
                               if r["id"] == aid else r for r in rs])
        with self.assertRaisesRegex(ValueError, "integrity verification"):
            q.decide(aid, True, "looks fine", decided_by="ciso")
        done = ex.execute_approved()
        rec = next(r for r in q.all() if r["id"] == aid)
        self.assertEqual(done, [])
        self.assertFalse(rec.get("executed"))
        self.assertEqual(rec.get("status"), "pending")

    def test_untampered_record_executes_and_charges_full_bytes(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._queue_send(
            q, ex, 5000,
            ctx["mint_identity"]("a1", "researcher", "org"))
        q.decide(aid, True, "legit", decided_by="ciso")
        done = ex.execute_approved()
        rec = next(r for r in q.all() if r["id"] == aid)
        self.assertTrue(rec.get("executed"))
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["tool"], "send_email")
        self.assertEqual(ex._egress_bytes, 5000)
