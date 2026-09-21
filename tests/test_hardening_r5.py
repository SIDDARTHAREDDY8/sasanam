"""Round-5 hardening regressions: F17..F22 CLOSED.

F17 — the egress ledger is HMAC-authenticated with HMAC'd checkpoints and
      fails closed on tampering/truncation (LedgerUnverifiableError); the
      executor refuses to act on an unverifiable ledger; principal
      issuance is deployment-controlled via PrincipalRegistry with a
      per-run mint cap.
F18 — campaign_allowlist exempts exact (principal, registered_domain,
      param-key-set) tuples from campaign QUEUEING only; everything is
      still ledgered and the exemption is action-logged.
F19 — ``python -m gov.verify --keyring`` verifies logs that span key
      epochs; tampering still fails.
F20 — registered-domain isolation: IP literals are never bucketed; a
      built-in public-suffix table keeps one registrable label above
      known multi-label suffixes (evil.co.uk vs good.co.uk differ).
F21 — batch approval excludes security-queued records: they stay pending,
      are reported as needs_individual_decision, and --confirm-risky
      cannot override.
F22 — ActionLog appends are O(1) amortized (no full rescan per append);
      log_limits.max_log_bytes makes the log fail closed when full.

Determinism: stdlib only; key material is fixed test values restored
after each test class.  No network, no clock dependence.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from gov.egress_ledger import (
    CAMPAIGN_K, EgressLedger, LedgerUnverifiableError, registered_domain)
from gov.identity import (
    AgentIdentity, IdentityMintLimitError, PrincipalRegistry,
    UnregisteredPrincipalError)
from gov.keys import KeyRing
from gov import keys as keys_mod
from gov.log import ActionLog, LogFullError, verify_chain
from gov.policy import PolicyEngine
from gov.policy_lint import lint_file
from tests.harness import make_run

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_POLICY = os.path.join(ROOT, "policies", "default.yaml")

# Fixed test key material (NOT production keys).  The ledger shares the
# action log's env backend: GOV_LOG_KEY / GOV_LOG_KEY_ARCHIVE.
_TEST_KEY = "round5-test-ledger-key-0000000000000001"
_TEST_KEY2 = "round5-test-ledger-key-0000000000000002"
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
    tmp = tempfile.mkdtemp(prefix="govr5pol-")
    path = os.path.join(tmp, "policy.yaml")
    with open(DEFAULT_POLICY, encoding="utf-8") as f:
        base = f.read()
    with open(path, "w", encoding="utf-8") as f:
        f.write(base)
        f.write("\n" + extra_yaml)
    return path


def _append(ledger, endpoint, params=None, principal="org"):
    ledger.append({
        "principal": principal,
        "endpoint": endpoint,
        "params": dict(params or {"check": "ping"}),
        "ts": 1700000000,
        "decision": "allow",
    })


def _records(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class _Decision:
    """Minimal decision-like object for queueing records directly."""

    def __init__(self, policy_id, reason, flag=None):
        self.policy_id = policy_id
        self.reason = reason
        self.flag = flag


# ---------------------------------------------------------------------------
# F17a — authenticated ledger, fail-closed
# ---------------------------------------------------------------------------

class TestF17aLedgerAuthentication(unittest.TestCase):
    """The ledger is authenticated; tampering fails closed."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        os.environ["GOV_LOG_KEY"] = _TEST_KEY
        os.environ["GOV_LOG_KEY_EPOCH"] = "test-epoch"
        self.tmp = tempfile.mkdtemp(prefix="govr5f17-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _ledger(self, name="egress.jsonl"):
        return EgressLedger(os.path.join(self.tmp, name))

    def test_entries_macd_sequenced_and_checkpointed(self):
        ledger = self._ledger()
        _append(ledger, "https://a.example/x")
        _append(ledger, "https://b.example/y")
        records = _records(ledger.path)
        self.assertEqual(len(records), 2)
        for i, r in enumerate(records, 1):
            self.assertEqual(r["seq"], i)
            self.assertIn("mac", r)
            self.assertEqual(r["key_epoch"], "test-epoch")
        self.assertTrue(os.path.exists(str(ledger.path) + ".checkpoints"))
        self.assertTrue(ledger.verify())
        ledger.require_verified()  # raises LedgerUnverifiableError on failure

    def test_trimmed_tail_raises_not_silent(self):
        # The core F17 defeat: trimming the newest entry used to make
        # taint_active() return False.  Now it raises.
        ledger = self._ledger()
        ledger.taint_mark("org", "run-1")
        self.assertTrue(ledger.taint_active("org"))
        # Trim the newest (taint) entry.
        lines = open(ledger.path, encoding="utf-8").read().splitlines()
        with open(ledger.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[:-1]) + "\n")
        self.assertFalse(ledger.verify())
        with self.assertRaises(LedgerUnverifiableError):
            ledger.require_verified()
        with self.assertRaises(LedgerUnverifiableError):
            ledger.taint_active("org")

    def test_forged_entry_rejected(self):
        ledger = self._ledger()
        _append(ledger, "https://a.example/x")
        _append(ledger, "https://b.example/y")
        records = _records(ledger.path)
        records[0]["endpoint"] = "https://evil.example/x"
        with open(ledger.path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        self.assertFalse(ledger.verify())
        with self.assertRaises(LedgerUnverifiableError):
            ledger.require_verified()

    def test_forged_mac_rejected(self):
        # Even with an intact chain, a wrong MAC is not trusted.
        ledger = self._ledger()
        _append(ledger, "https://a.example/x")
        records = _records(ledger.path)
        records[0]["mac"] = "0" * 64
        with open(ledger.path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        self.assertFalse(ledger.verify())

    def test_unknown_key_epoch_rejected(self):
        ledger = self._ledger()
        _append(ledger, "https://a.example/x")
        records = _records(ledger.path)
        records[0]["key_epoch"] = "attacker-epoch"
        with open(ledger.path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        self.assertFalse(ledger.verify())

    def test_legacy_unmacd_ledger_does_not_verify(self):
        # Pre-F17 entries carried no MAC: they cannot authenticate, so
        # the hardened reader refuses to trust them (documented
        # fail-closed; rotate to a fresh ledger rather than mixing).
        ledger = self._ledger()
        with open(ledger.path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"principal": "org", "seq": 1,
                                "campaign_domain": "example",
                                "endpoint": "https://a.example/x",
                                "params": {}}) + "\n")
        self.assertFalse(ledger.verify())

    def test_checkpoint_sidecar_deletion_fails_closed(self):
        # The sidecar is the tail-truncation anchor: a non-empty ledger
        # whose sidecar is missing fails closed (deleted sidecar, or a
        # crash between the entry write and the checkpoint write).
        # Without this, deleting the sidecar + trimming the tail would
        # verify as a "valid shorter chain".
        ledger = self._ledger()
        _append(ledger, "https://a.example/x")
        _append(ledger, "https://b.example/y")
        os.unlink(str(ledger.path) + ".checkpoints")
        self.assertFalse(ledger.verify())
        with self.assertRaises(LedgerUnverifiableError):
            ledger.require_verified()
        # ...and the trim-then-delete-sidecar attack is caught too.
        ledger2 = self._ledger("egress2.jsonl")
        _append(ledger2, "https://a.example/x")
        _append(ledger2, "https://b.example/y")
        lines = open(ledger2.path, encoding="utf-8").read().splitlines()
        with open(ledger2.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[:-1]) + "\n")
        os.unlink(str(ledger2.path) + ".checkpoints")
        self.assertFalse(ledger2.verify())

    def test_executor_refuses_to_act_on_tampered_ledger(self):
        ctx = make_run(ledger_path=os.path.join(self.tmp, "shared.jsonl"))
        ident = ctx["mint_identity"]("alice", "researcher", "org")
        d = ctx["executor"].call(ident, "api_call",
                                endpoint="https://x.example/ok",
                                params={"check": "ping"})
        self.assertEqual(d["status"], "executed")
        # Attacker forges the ledger file out-of-band.
        records = _records(ctx["executor"]._ledger.path)
        records[0]["endpoint"] = "https://evil.example/x"
        with open(ctx["executor"]._ledger.path, "w",
                  encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        # The next call raises LedgerUnverifiableError — and the refusal
        # itself is recorded as a denial in the action log.
        with self.assertRaises(LedgerUnverifiableError):
            ctx["executor"].call(ident, "api_call",
                                endpoint="https://y.example/ok",
                                params={"check": "ping"})
        denied = [e for e in ctx["read_log"]()
                  if e.get("decision") == "denied"
                  and e.get("policy_id") == "ledger-unverifiable"]
        self.assertTrue(denied)


# ---------------------------------------------------------------------------
# F17b — deployment-controlled principal issuance
# ---------------------------------------------------------------------------

class TestF17bPrincipalRegistry(unittest.TestCase):
    """mint_identity is honest only when the deployment says who exists."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.tmp = tempfile.mkdtemp(prefix="govr5f17b-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _registry(self, *extra):
        # make_run mints its three standard identities at setup, so the
        # registry must cover the harness principals too.
        return PrincipalRegistry(
            ["customer-org", "dev-org", "research-org", "org"] + list(extra))

    def test_unregistered_principal_rejected_in_registry_mode(self):
        ctx = make_run(principal_registry=self._registry())
        alice = ctx["mint_identity"]("alice", "researcher", "org")
        self.assertEqual(alice.principal, "org")
        with self.assertRaises(UnregisteredPrincipalError):
            ctx["mint_identity"]("mallory", "researcher", "fresh-org")

    def test_registry_issuance_is_logged(self):
        ctx = make_run(principal_registry=self._registry())
        ctx["mint_identity"]("alice", "researcher", "org")
        minted = [e for e in ctx["read_log"]()
                  if e.get("event") == "identity_minted"
                  and e.get("agent_id") == "alice"]
        self.assertTrue(minted)
        self.assertEqual(minted[0]["principal"], "org")

    def test_mint_rate_limit_enforced(self):
        ctx = make_run(principal_registry=self._registry())
        executor = ctx["executor"]
        remaining = 64 - executor._mint_count
        self.assertGreater(remaining, 0)
        for i in range(remaining):
            ctx["mint_identity"]("u-%d" % i, "researcher", "org")
        with self.assertRaises(IdentityMintLimitError):
            ctx["mint_identity"]("one-too-many", "researcher", "org")

    def test_registry_mode_blocks_taint_shedding_end_to_end(self):
        # A tainted principal cannot dodge its taint by minting a fresh
        # principal string: the registry refuses the mint.  A
        # confederate under the SAME principal in a FRESH run still
        # queues on sensitive_read_before_api via the ledger's
        # principal-scoped taint.
        from tests.harness import plant_file
        ledger_path = os.path.join(self.tmp, "shared.jsonl")
        ctx1 = make_run(principal_registry=self._registry(),
                        ledger_path=ledger_path)
        alice = ctx1["mint_identity"]("alice", "researcher", "org")
        plant_file(ctx1, "data/c.csv",
                   "id,name,email,phone\n1,Alice,alice@example.com,555-0101\n")
        d = ctx1["executor"].call(alice, "read_file", path="data/c.csv")
        self.assertEqual(d["status"], "executed")
        # Fresh run, same principal: the confederate is still tainted.
        ctx2 = make_run(principal_registry=self._registry(),
                        ledger_path=ledger_path)
        with self.assertRaises(UnregisteredPrincipalError):
            ctx2["mint_identity"]("mallory", "researcher", "org-fresh")
        bob = ctx2["mint_identity"]("bob", "researcher", "org")
        d2 = ctx2["executor"].call(bob, "api_call",
                                  endpoint="https://x.example/out",
                                  params={"check": "ping"})
        self.assertEqual(d2["status"], "queued")
        rec = [r for r in ctx2["approvals"].pending()
               if r["id"] == d2["approval_id"]][0]
        self.assertEqual(rec["policy_flag"], "sensitive_read_before_api")

    def test_permissive_default_allows_any_principal_documented(self):
        # Honest residual: without a registry, arbitrary principal
        # strings still mint (demo/default mode).  Deployments that need
        # principal continuity MUST pass a registry.
        ctx = make_run()
        mallory = ctx["mint_identity"]("mallory", "researcher", "fresh-org")
        self.assertEqual(mallory.principal, "fresh-org")
        minted = [e for e in ctx["read_log"]()
                  if e.get("event") == "identity_minted"]
        self.assertEqual(minted, [])


# ---------------------------------------------------------------------------
# F18 — campaign allowlist
# ---------------------------------------------------------------------------

_ALLOWLIST_POLICY = """
campaign_allowlist:
  - [ops-monitor, vendor.example, [check, region]]
"""

_CAMPAIGN_K = CAMPAIGN_K  # polls beyond this would queue without exemption


class TestF18CampaignAllowlist(unittest.TestCase):
    """Benign repetitive traffic is exempted only by exact tuple match."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.tmp = tempfile.mkdtemp(prefix="govr5f18-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.policy_path = _policy_with(_ALLOWLIST_POLICY)

    def _poll(self, ledger_path, principal, endpoint, params, n,
              policy_path=None):
        decisions = []
        last_ctx = None
        for i in range(n):
            ctx = make_run(policy_path=policy_path or self.policy_path,
                           ledger_path=ledger_path)
            ident = ctx["mint_identity"]("s-%d" % i, "researcher", principal)
            decisions.append(
                ctx["executor"].call(ident, "api_call", endpoint=endpoint,
                                    params=params))
            last_ctx = ctx
        return decisions, last_ctx

    def _queued_flag(self, ctx, approval_id):
        recs = [r for r in ctx["approvals"].pending()
                if r["id"] == approval_id]
        return recs[0]["policy_flag"] if recs else None

    def test_allowlisted_poller_executes_across_runs(self):
        ledger = os.path.join(self.tmp, "shared.jsonl")
        params = {"check": "ping", "region": "us-east"}
        decisions, _ctx = self._poll(
            ledger, "ops-monitor", "https://vendor.example/health",
            params, _CAMPAIGN_K + 2)
        self.assertTrue(all(d["status"] == "executed" for d in decisions),
                        [d["status"] for d in decisions])
        # The exemption is action-logged, not silent: the last run's log
        # records the allowlist event.
        ctx = make_run(policy_path=self.policy_path, ledger_path=ledger)
        ident = ctx["mint_identity"]("probe", "researcher", "ops-monitor")
        ctx["executor"].call(ident, "api_call",
                            endpoint="https://vendor.example/health",
                            params=params)
        allowlisted = [e for e in ctx["read_log"]()
                       if e.get("event") == "campaign_allowlisted"]
        self.assertTrue(allowlisted)
        self.assertEqual(allowlisted[0]["campaign_domain"],
                         "vendor.example")

    def test_non_allowlisted_control_tuple_still_queues(self):
        ledger = os.path.join(self.tmp, "shared.jsonl")
        params = {"check": "ping", "region": "us-east"}
        # Same shape, DIFFERENT principal: not allowlisted -> queues.
        decisions, ctx = self._poll(
            ledger, "mallory", "https://vendor.example/health",
            params, _CAMPAIGN_K)
        self.assertEqual(decisions[-1]["status"], "queued")
        self.assertEqual(
            self._queued_flag(ctx, decisions[-1]["approval_id"]),
            "cross_run_campaign")
        # Same shape, DIFFERENT domain: not allowlisted -> queues.
        ledger2 = os.path.join(self.tmp, "shared2.jsonl")
        decisions2, ctx2 = self._poll(
            ledger2, "ops-monitor", "https://status.evil.example/health",
            params, _CAMPAIGN_K)
        self.assertEqual(decisions2[-1]["status"], "queued")

    def test_allowlist_requires_exact_param_key_set(self):
        ledger = os.path.join(self.tmp, "shared.jsonl")
        # Extra key: shape differs -> not allowlisted -> queues.
        decisions, ctx = self._poll(
            ledger, "ops-monitor", "https://vendor.example/health",
            {"check": "ping", "region": "us-east", "extra": "1"},
            _CAMPAIGN_K)
        self.assertEqual(decisions[-1]["status"], "queued")
        self.assertEqual(
            self._queued_flag(ctx, decisions[-1]["approval_id"]),
            "cross_run_campaign")

    def test_malformed_allowlist_fails_policy_load(self):
        bad = _policy_with("""
campaign_allowlist:
  - [only-two-fields, missing-keys]
""")
        with self.assertRaises(ValueError):
            PolicyEngine(bad)
        bad2 = _policy_with("""
campaign_allowlist:
  - [p, d, []]
""")
        with self.assertRaises(ValueError):
            PolicyEngine(bad2)

    def test_allowlist_lint_reports_and_rejects(self):
        ok = _policy_with("""
campaign_allowlist:
  - [ops-monitor, vendor.example, [check, region]]
""")
        findings = lint_file(ok)
        kinds = [f for f in findings
                 if f["kind"] == "campaign_allowlist_entries"]
        self.assertEqual(len(kinds), 1)
        self.assertEqual(kinds[0]["severity"], "info")
        bad = _policy_with("""
campaign_allowlist:
  - [p, d, []]
""")
        findings = lint_file(bad)
        self.assertTrue(
            any(f["kind"] == "malformed_campaign_allowlist"
                and f["severity"] == "error" for f in findings))

    def test_default_policy_has_no_allowlist(self):
        self.assertEqual(PolicyEngine(DEFAULT_POLICY).campaign_allowlist, ())


# ---------------------------------------------------------------------------
# F19 — rotation-aware verifier CLI
# ---------------------------------------------------------------------------

class TestF19KeyringCLI(unittest.TestCase):
    """``python -m gov.verify --keyring`` verifies across key epochs."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.tmp = tempfile.mkdtemp(prefix="govr5f19-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _run_verify(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "gov.verify"] + list(args),
            cwd=ROOT, capture_output=True, text=True, timeout=60)

    def _rotated_log(self):
        # epoch-1 entries, then the rotation ceremony, then epoch-2.
        ring = KeyRing.generate("epoch-1")
        kr_path = os.path.join(self.tmp, "keyring.json")
        ring.save(kr_path)
        ring.activate()
        log_path = os.path.join(self.tmp, "actions.jsonl")
        log = ActionLog(log_path)
        log.append({"event": "before-rotation", "n": 1})
        ring2, new_epoch = keys_mod.rotate_keyring(
            kr_path, new_epoch="epoch-2", log_path=log_path)
        self.assertEqual(new_epoch, "epoch-2")
        ring2.activate()
        log.append({"event": "after-rotation", "n": 2})
        return kr_path, log_path

    def test_cli_keyring_verifies_across_rotation(self):
        kr_path, log_path = self._rotated_log()
        rc = self._run_verify("--keyring", kr_path, log_path)
        self.assertEqual(rc.returncode, 0, rc.stderr)
        out = json.loads(rc.stdout)
        self.assertTrue(out["ok"])
        self.assertEqual(out["entries"], 2)

    def test_cli_keyring_directory_resolves_to_keyring_json(self):
        kr_path, log_path = self._rotated_log()
        rc = self._run_verify("--keyring", self.tmp, log_path)
        self.assertEqual(rc.returncode, 0, rc.stderr)
        self.assertTrue(json.loads(rc.stdout)["ok"])

    def test_cli_keyring_fails_on_tamper(self):
        kr_path, log_path = self._rotated_log()
        records = _records(log_path)
        records[1]["event"] = "forged"
        with open(log_path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        rc = self._run_verify("--keyring", kr_path, log_path)
        self.assertEqual(rc.returncode, 1)
        out = json.loads(rc.stdout)
        self.assertFalse(out["ok"])

    def test_cli_keyring_fails_on_missing_keyring(self):
        _kr, log_path = self._rotated_log()
        rc = self._run_verify("--keyring",
                             os.path.join(self.tmp, "nope.json"), log_path)
        self.assertEqual(rc.returncode, 1)

    def test_legacy_single_key_path_fails_closed_on_mixed_epochs(self):
        # Without --keyring, the single-key verifier cannot span epochs:
        # it fails closed (documents the old F19 defeat as explicit).
        _kr, log_path = self._rotated_log()
        rc = self._run_verify(log_path)
        self.assertEqual(rc.returncode, 1)


# ---------------------------------------------------------------------------
# F20 — registered-domain isolation (extra edge cases; core in test_hardening_r4)
# ---------------------------------------------------------------------------

class TestF20DomainIsolationEdges(unittest.TestCase):
    """Isolation must not over-merge tenants nor under-merge subdomains."""

    def test_common_multi_label_suffixes_isolate_tenants(self):
        pairs = [
            ("https://a.example.com.au/x", "https://b.example.com.au/x",
             "example.com.au"),
            ("https://a.example.co.jp/x", "https://b.example.co.jp/x",
             "example.co.jp"),
            ("https://a.example.co.in/x", "https://b.example.co.in/x",
             "example.co.in"),
            ("https://a.example.com.br/x", "https://b.example.com.br/x",
             "example.com.br"),
        ]
        for u1, u2, expected in pairs:
            d1, d2 = registered_domain(u1), registered_domain(u2)
            self.assertEqual(d1, expected, u1)
            self.assertEqual(d2, expected, u2)

    def test_ip_literals_never_bucketed(self):
        self.assertEqual(registered_domain("http://192.168.0.1/x"),
                         "192.168.0.1")
        self.assertNotEqual(registered_domain("http://10.0.0.1/x"),
                            registered_domain("http://10.0.0.2/x"))
        self.assertEqual(registered_domain("http://[2001:db8::1]/x"),
                         "2001:db8::1")

    def test_case_and_trailing_dot_normalized(self):
        self.assertEqual(registered_domain("https://A.EXAMPLE.COM./x"),
                         registered_domain("https://a.example.com/x"))

    def test_malformed_hostnames_bucket_fail_safe(self):
        # Unparseable hosts normalize to "": garbage endpoints share the
        # empty bucket.  That is the fail-SAFE direction for a
        # queue-only heuristic (it can only cause queueing, never a
        # bypass); exact endpoints are still in the ledger for forensics.
        self.assertEqual(registered_domain("not a url at all"), "")
        self.assertEqual(registered_domain(""), "")


# ---------------------------------------------------------------------------
# F21 — security-aware batch approval
# ---------------------------------------------------------------------------

class TestF21BatchExclusion(unittest.TestCase):
    """Batch approval can never sweep security-queued records along."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.tmp = tempfile.mkdtemp(prefix="govr5f21-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _queue(self, q, tool, args, policy_id, reason, flag):
        action = {
            "tool": tool, "args": args,
            "identity": {"agent_id": "a1", "role": "researcher",
                         "run_id": q.run_dir.name, "principal": "org"},
            "redactions": [], "agent_justification": None,
        }
        return q.queue(action, _Decision(policy_id, reason, flag=flag),
                       policy_flag=flag)

    def _ctx_with_items(self):
        ctx = make_run()
        q = ctx["approvals"]
        benign = self._queue(q, "read_file", {"path": "notes.txt"},
                            "approval-read", "low risk read", None)
        campaign = self._queue(
            q, "api_call",
            {"endpoint": "https://x.example/o", "params": {"q": "1"}},
            "approval-cross-run-campaign", "campaign", "cross_run_campaign")
        dlp = self._queue(
            q, "send_email",
            {"to": "x@y.z", "body": "AKIAIOSFODNN7EXAMPLE"},
            "approval-dlp", "dlp", "dlp")
        return ctx, benign, campaign, dlp

    def _all(self, ctx):
        return {r["id"]: r for r in ctx["approvals"].all()}

    def test_policy_flag_stored_on_record(self):
        ctx, _b, campaign, _d = self._ctx_with_items()
        rec = [r for r in ctx["approvals"].pending()
               if r["id"] == campaign][0]
        self.assertEqual(rec["policy_flag"], "cross_run_campaign")

    def test_security_items_excluded_from_batch_approve(self):
        ctx, benign, campaign, dlp = self._ctx_with_items()
        decided, excluded, batch = ctx["approvals"].batch_decide(
            [benign, campaign, dlp], True, "morning triage",
            decided_by="ciso")
        decided_ids = {r["id"] for r in decided}
        excluded_ids = {r["id"] for r in excluded}
        self.assertEqual(decided_ids, {benign})
        self.assertEqual(excluded_ids, {campaign, dlp})
        # The benign record was approved...
        self.assertEqual(self._all(ctx)[benign]["status"], "approved")
        # ...the security records are still pending, flagged for review.
        pending_ids = {r["id"] for r in ctx["approvals"].pending()}
        self.assertIn(campaign, pending_ids)
        self.assertIn(dlp, pending_ids)
        for r in excluded:
            self.assertEqual(r["policy_flag"] in
                             ("cross_run_campaign", "dlp"), True)
            self.assertIn(r["policy_flag"], r["batch_exclusion_reason"])
            self.assertIn("individual decision",
                          r["batch_exclusion_reason"])
        self.assertEqual(set(batch["excluded_ids"]), {campaign, dlp})
        self.assertIn("cross_run_campaign",
                      batch["excluded_reasons"][campaign])

    def test_confirm_risky_cannot_override_exclusion(self):
        ctx, benign, campaign, _d = self._ctx_with_items()
        decided, excluded, _batch = ctx["approvals"].batch_decide(
            [benign, campaign], True, "morning triage", decided_by="ciso",
            confirm_risky=[campaign])
        self.assertEqual({r["id"] for r in decided}, {benign})
        self.assertEqual({r["id"] for r in excluded}, {campaign})
        pending_ids = {r["id"] for r in ctx["approvals"].pending()}
        self.assertIn(campaign, pending_ids)

    def test_excluded_item_decided_individually(self):
        ctx, _b, campaign, _d = self._ctx_with_items()
        rec, _entry = ctx["approvals"].decide(
            campaign, True, "reviewed individually", decided_by="ciso")
        self.assertEqual(rec["status"], "approved")
        pending_ids = {r["id"] for r in ctx["approvals"].pending()}
        self.assertNotIn(campaign, pending_ids)

    def test_batch_reject_leaves_excluded_pending(self):
        ctx, benign, campaign, dlp = self._ctx_with_items()
        decided, excluded, _batch = ctx["approvals"].batch_decide(
            [benign, campaign, dlp], False, "reject all",
            decided_by="ciso")
        self.assertEqual({r["id"] for r in decided}, {benign})
        pending_ids = {r["id"] for r in ctx["approvals"].pending()}
        self.assertIn(campaign, pending_ids)
        self.assertIn(dlp, pending_ids)

    def test_unknown_or_decided_ids_abort_with_no_partial_batch(self):
        # Atomicity is enforced by raising: unknown or non-pending ids
        # abort the whole batch, deciding nothing.
        ctx, benign, campaign, _d = self._ctx_with_items()
        ctx["approvals"].decide(benign, True, "first", decided_by="ciso")
        with self.assertRaises(ValueError):
            ctx["approvals"].batch_decide(
                [benign, "req-nope"], True, "second", decided_by="ciso")
        # Nothing was decided by the aborted batch: the campaign record
        # is still pending, and no new batch log entry was written.
        pending_ids = {r["id"] for r in ctx["approvals"].pending()}
        self.assertIn(campaign, pending_ids)
        self.assertEqual(self._all(ctx)[benign]["status"], "approved")

    def test_default_exclusions_cover_known_security_reasons(self):
        policy = PolicyEngine(DEFAULT_POLICY)
        self.assertIn("cross_run_campaign",
                      policy.batch_excluded_queue_reasons)
        self.assertIn("dlp", policy.batch_excluded_queue_reasons)
        self.assertIn("break_glass", policy.batch_excluded_queue_reasons)

    def test_executor_campaign_queue_carries_policy_flag(self):
        # End-to-end: a real campaign-queued record from the executor
        # carries the exclusion flag, so batch_decide excludes it.
        ledger = os.path.join(self.tmp, "shared.jsonl")
        queued_id = None
        for i in range(CAMPAIGN_K):
            ctx = make_run(ledger_path=ledger)
            ident = ctx["mint_identity"]("s-%d" % i, "researcher", "org")
            d = ctx["executor"].call(
                ident, "api_call", endpoint="https://x.example/o",
                params={"fragment": "Zx9qW2!vL"})
            if d["status"] == "queued":
                queued_id = d["approval_id"]
        self.assertIsNotNone(queued_id)
        last = ctx["approvals"]
        pending = last.pending()
        rec = [r for r in pending if r["id"] == queued_id][0]
        self.assertEqual(rec["policy_flag"], "cross_run_campaign")
        decided, excluded, _batch = last.batch_decide(
            [queued_id], True, "morning triage", decided_by="ciso")
        self.assertEqual(decided, [])
        self.assertEqual([r["id"] for r in excluded], [queued_id])


# ---------------------------------------------------------------------------
# F22 — O(1) appends + log size guard
# ---------------------------------------------------------------------------

class TestF22LogGuard(unittest.TestCase):
    """Appends stay O(1); a full log fails closed instead of going dark."""

    def setUp(self):
        self.addCleanup(_scrub_key_env())
        self.tmp = tempfile.mkdtemp(prefix="govr5f22-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_2000_appends_are_fast_and_chain_verifies(self):
        log = ActionLog(os.path.join(self.tmp, "a.jsonl"))
        # F22/R9: the regression property is O(1) per append, NOT an
        # absolute wall-clock bound. Absolute fsync latency is
        # disk-dependent (~37ms on the workspace disk vs ~0.2ms on
        # tmpfs), so a fixed seconds bound is invalid on some disks —
        # the same implementation passes in 0.5s on tmpfs and needs
        # 70s+ on the workspace disk, purely from fsync cost. The
        # pre-F22 implementation rescanned the whole log per append
        # (O(n^2)), making late appends ~10x slower than early ones;
        # comparing an early window against a late window captures the
        # actual regression property on any disk. The bound is 3.0, not
        # 2.0: per-append medians live at ~80us on tmpfs, where a
        # transient VM scheduling hiccup inside one 200-sample window
        # can double a median without any systematic slowdown; the
        # genuine O(n^2) signature was ~10x, so 3.0 keeps full
        # regression sensitivity with noise margin.
        per = []
        t_all = time.time()
        for i in range(2000):
            t0 = time.perf_counter()
            log.append({"event": "bench", "i": i})
            per.append(time.perf_counter() - t0)
        dt = time.time() - t_all
        early = sorted(per[100:300])
        late = sorted(per[1800:2000])
        early_med = early[len(early) // 2]
        late_med = late[len(late) // 2]
        ratio = (late_med + 1e-9) / (early_med + 1e-9)
        self.assertLess(
            ratio, 3.0,
            "append cost grows with log length (O(n^2) regression): "
            "early-window median %.4fs vs late-window median %.4fs "
            "(total %.1fs) — bound is 3.0 (pre-F22 signature was ~10x) "
            "to tolerate transient VM scheduling noise at ~80us "
            "medians" % (early_med, late_med, dt))
        ok, broken, count = verify_chain(log.path)
        self.assertTrue(ok, broken)
        self.assertEqual(count, 2000)
        # Checkpoints verify too (checkpoints.jsonl next to the log).
        cp = json.loads(
            open(os.path.join(self.tmp, "checkpoints.jsonl"),
                 encoding="utf-8").read().splitlines()[-1])
        self.assertEqual(cp["seq"], 2000)

    def test_size_guard_blocks_append_and_chain_stays_valid(self):
        log = ActionLog(os.path.join(self.tmp, "b.jsonl"), max_bytes=300)
        log.append({"event": "first"})
        with self.assertRaises(LogFullError):
            for _ in range(50):
                log.append({"event": "filler", "pad": "x" * 40})
        ok, broken, count = verify_chain(log.path)
        self.assertTrue(ok, broken)
        self.assertGreaterEqual(count, 1)

    def test_size_guard_enforces_projected_size_not_current_size(self):
        # The guard rejects when current + new line would exceed the
        # cap — not only when the current size already exceeds it —
        # and the refusal mutates no chain state (no seq gap).
        log = ActionLog(os.path.join(self.tmp, "d.jsonl"), max_bytes=600)
        log.append({"event": "first", "pad": "x" * 100})
        size = os.path.getsize(log.path)
        self.assertLess(size, 400)
        with self.assertRaises(LogFullError):
            log.append({"event": "second", "pad": "y" * 200})
        ok, broken, count = verify_chain(log.path)
        self.assertTrue(ok, broken)
        self.assertEqual(count, 1)
        # A small entry still fits and continues the chain cleanly.
        log.append({"event": "third"})
        ok, broken, count = verify_chain(log.path)
        self.assertTrue(ok, broken)
        self.assertEqual(count, 2)

    def test_executor_refuses_to_act_when_log_full(self):
        policy_path = _policy_with("""
log_limits:
  max_log_bytes: 64
""")
        ctx = make_run(policy_path=policy_path)
        # Pre-fill the log past the cap with an unguarded handle (the
        # guarded handle would fail closed on the prefill itself):
        # the executor's own guard, wired from the policy, must refuse
        # the next governed action rather than act unlogged.
        unguarded = ActionLog(ctx["log"].path, max_bytes=10 ** 9)
        unguarded.append({"event": "prefill"})
        ident = ctx["mint_identity"]("alice", "researcher", "org")
        target = os.path.join(self.tmp, "must-not-exist.txt")
        with self.assertRaises(LogFullError):
            ctx["executor"].call(ident, "write_file", path=target,
                                content="side effect")
        # The governed side effect did NOT execute.
        self.assertFalse(os.path.exists(target))

    def test_external_writer_visible_without_corruption(self):
        path = os.path.join(self.tmp, "c.jsonl")
        a = ActionLog(path)
        a.append({"event": "from-a"})
        b = ActionLog(path)  # a second instance, same file
        b.append({"event": "from-b"})
        a.append({"event": "from-a-again"})
        ok, broken, count = verify_chain(path)
        self.assertTrue(ok, broken)
        self.assertEqual(count, 3)
        self.assertEqual(a._seq, 3)
        self.assertEqual(b._seq, 2)

    def test_default_policy_has_sane_log_cap(self):
        policy = PolicyEngine(DEFAULT_POLICY)
        cap = policy.log_limits["max_log_bytes"]
        self.assertIsInstance(cap, int)
        self.assertGreaterEqual(cap, 1024 * 1024)

    def test_invalid_log_cap_fails_policy_load(self):
        bad = _policy_with("""
log_limits:
  max_log_bytes: -1
""")
        with self.assertRaises(ValueError):
            PolicyEngine(bad)

    def test_log_limits_lint(self):
        bad = _policy_with("""
log_limits:
  max_log_bytes: nope
""")
        findings = lint_file(bad)
        self.assertTrue(
            any(f["kind"] == "malformed_log_limits"
                and f["severity"] == "error" for f in findings))


if __name__ == "__main__":
    unittest.main()
