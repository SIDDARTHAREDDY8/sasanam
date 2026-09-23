"""Wave-75 governing-the-governors: policy-change control, tiered approvals,
break-glass ceremony, version pinning (2026-09-22).

Load-bearing claims under test (GOVERNORS_DESIGN.md):
- policy changes are first-class governed events: author (Wave-74 human
  key), structured diff, tier approvals, timestamp — chained via
  parent_token_hash, appended as policy_change provenance records
- the nuclear rule: production changes need two DISTINCT roster human
  keys; the same key twice is structurally refused
- the governed path is construction: GovernedPolicyStore.apply is the
  ONLY code path that changes the live engine; a YAML edit on disk
  without a governed event does not move the live engine
- break-glass: time-boxed, purpose-declared, dual-recorded,
  auto-expiring, post-use review REQUIRED by a distinct human
- version pinning: decision records carry the digest of the engine
  that decided them across a swap

Hermetic: temp dirs, dev key via tests/__init__ opt-in, Ed25519 human
stand-ins, no network. Deterministic except wall-clock ts (never
asserted on).
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import policy_change as _pc  # noqa: E402
from gov import provenance as _prov  # noqa: E402
from gov import log as _log  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
import secrets  # noqa: E402

_BASE_POLICY = Path(_REPO_MAIN, "policies", "default.yaml").read_text()
_RULE = ("\n  - id: w75-test-rule\n"
         "    effect: deny\n"
         "    match:\n"
         "      tool: delete_file\n")
_CHANGED = _BASE_POLICY + _RULE


def _human():
    return Ed25519Signer(secrets.token_bytes(32))


def _trust(*humans):
    ax, ux = _human(), _human()
    return DelegationTrust(
        human_keys={h.key_id: h.public_key for h in humans},
        authority_keys={ax.key_id: ax.public_key},
        user_issuer_keys={ux.key_id: ux.public_key})


def _store(mode="dev", trust=None, log=None, humans=2):
    humans_ = [_human() for _ in range(humans)]
    trust = trust or _trust(*humans_)
    store = _pc.GovernedPolicyStore(deployment_mode=mode, trust=trust,
                                    log=log, session_id="sess-w75")
    return store, humans_, trust


def _bootstrap(store, author, purpose="initial", approvers=()):
    return store.bootstrap(_BASE_POLICY, author, "alice",
                          purpose, approver_signers=approvers or (author,))


class TestCanonicalDigest(unittest.TestCase):
    def test_formatting_only_change_is_noop(self):
        # Canonicalization covers enforced meaning, not bytes: a
        # comment-only edit parses identically and is refused as a
        # no-op change — approvals can never bind to cosmetic churn.
        self.assertEqual(_pc.policy_digest(_BASE_POLICY),
                         _pc.policy_digest(_BASE_POLICY + "\n# note\n"))
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        with self.assertRaises(_pc.PolicyChangeError):
            store.propose(_BASE_POLICY + "\n# note\n", h1, "alice",
                          "cosmetic")

    def test_malformed_policy_cannot_be_proposed(self):
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        with self.assertRaises(_pc.PolicyChangeError):
            store.propose("policies: [unclosed", h1, "alice", "bad yaml")

    def test_diff_structure(self):
        diff, digest = _pc.diff_policies(_BASE_POLICY, _CHANGED)
        self.assertEqual(diff["rules_added"], ["w75-test-rule"])
        self.assertEqual(diff["rules_removed"], [])
        self.assertEqual(diff["rules_changed"], {})
        self.assertTrue(len(digest) == 64)
        # changed field
        tweaked = _BASE_POLICY.replace("max_sends_per_run: 10",
                                       "max_sends_per_run: 11")
        diff2, _ = _pc.diff_policies(_BASE_POLICY, tweaked)
        self.assertEqual(diff2["rules_added"], [])
        self.assertIn("rate_limit", diff2["sections_changed"])


class TestAuthorship(unittest.TestCase):
    def test_non_roster_signer_refused_at_propose(self):
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        outsider = _human()
        with self.assertRaises(_pc.AuthorshipError):
            store.propose(_CHANGED, outsider, "mallory", "evil change")

    def test_forged_authorship_token_refused(self):
        store, (h1,), trust = _store(humans=1)
        _bootstrap(store, h1)
        attacker = _human()
        token = _pc.issue_authorship_token(
            attacker, policy_ref="a" * 64, prior_ref="b" * 64,
            parent_token_hash="GENESIS", author="mallory",
            diff_digest="c" * 64, tier="single-human",
            deployment_mode="dev", session_id="s", purpose="x")
        with self.assertRaises(_pc.AuthorshipError):
            _pc.verify_authorship_token(token, trust)

    def test_tampered_token_body_refused(self):
        store, (h1,), trust = _store(humans=1)
        _bootstrap(store, h1)
        token = _pc.issue_authorship_token(
            h1, policy_ref="a" * 64, prior_ref="b" * 64,
            parent_token_hash="GENESIS", author="alice",
            diff_digest="c" * 64, tier="single-human",
            deployment_mode="dev", session_id="s", purpose="x")
        token["claims"]["purpose"] = "rewritten purpose"
        with self.assertRaises(_pc.AuthorshipError):
            _pc.verify_authorship_token(token, trust)

    def test_chain_break_refused(self):
        # parent_token_hash must equal the prior authorship ref —
        # a change cannot be spliced onto a different history.
        store, (h1,), trust = _store(humans=1)
        _bootstrap(store, h1)
        token = _pc.issue_authorship_token(
            h1, policy_ref="a" * 64, prior_ref="b" * 64,
            parent_token_hash="GENESIS", author="alice",
            diff_digest="c" * 64, tier="single-human",
            deployment_mode="dev", session_id="s", purpose="x")
        with self.assertRaises(_pc.AuthorshipError):
            _pc.verify_authorship_token(
                token, trust, expected_parent="f" * 64)

    def test_unknown_deployment_mode_refused(self):
        with self.assertRaises(_pc.PolicyChangeError):
            _pc.required_tier("moon")


class TestTiers(unittest.TestCase):
    def test_dev_single_human_happy_path(self):
        store, (h1,), _ = _store(mode="dev", humans=1)
        _bootstrap(store, h1)
        chg = store.propose(_CHANGED, h1, "alice", "add rule")
        with self.assertRaises(_pc.TierError):
            store.apply(chg.change_id)  # no approvals yet
        store.approve(chg.change_id, h1)
        store.apply(chg.change_id)
        self.assertEqual(chg.status, "applied")

    def test_production_two_person(self):
        store, (h1, h2), _ = _store(mode="production", humans=2)
        _bootstrap(store, h1, approvers=(h1, h2))
        chg = store.propose(_CHANGED, h1, "alice", "prod rule")
        store.approve(chg.change_id, h1)
        with self.assertRaises(_pc.TierError):
            store.apply(chg.change_id)  # single-human on prod: refused
        store.approve(chg.change_id, h2)
        store.apply(chg.change_id)
        self.assertEqual(chg.status, "applied")

    def test_same_key_twice_is_not_two_person(self):
        # Approver impersonation: the author's key twice must not count
        # as the nuclear rule's second person.
        store, (h1, h2), trust = _store(mode="production", humans=2)
        _bootstrap(store, h1, approvers=(h1, h2))
        chg = store.propose(_CHANGED, h1, "alice", "prod rule")
        store.approve(chg.change_id, h1)
        store.approve(chg.change_id, h1)  # same key again
        with self.assertRaises(_pc.TierError):
            store.apply(chg.change_id)

    def test_two_person_requires_author_among_approvers(self):
        store, (h1, h2), _ = _store(mode="production", humans=2)
        _bootstrap(store, h1, approvers=(h1, h2))
        chg = store.propose(_CHANGED, h1, "alice", "prod rule")
        # h2 approves twice is refused by distinctness; h2 + a third
        # human without the author is refused by the author-membership
        # rule — construct directly:
        h3 = _human()
        store2_trust = _trust(h1, h2, h3)
        store2 = _pc.GovernedPolicyStore(
            deployment_mode="production", trust=store2_trust, log=None,
            session_id="sess-w75b")
        store2.bootstrap(_BASE_POLICY, h1, "alice", "init",
                         approver_signers=(h1, h2))
        chg2 = store2.propose(_CHANGED, h1, "alice", "prod rule")
        store2.approve(chg2.change_id, h2)
        store2.approve(chg2.change_id, h3)
        with self.assertRaises(_pc.TierError):
            store2.apply(chg2.change_id)

    def test_approval_binds_to_change_digest(self):
        store, (h1, h2), _ = _store(mode="dev", humans=2)
        _bootstrap(store, h1)
        chg = store.propose(_CHANGED, h1, "alice", "add rule")
        other = store.propose(
            _CHANGED.replace("w75-test-rule", "w75-other-rule"),
            h1, "alice", "other rule")
        # cross-wire: h2's approval for `other` replayed onto `chg`
        ap = _pc.sign_approval(h2, change_id=other.change_id,
                               policy_ref=_pc.policy_digest(other.text))
        chg.approvals.append(ap)
        with self.assertRaises(_pc.TierError):
            store.apply(chg.change_id)


class TestGovernedPath(unittest.TestCase):
    def test_apply_builds_from_artifact_not_file(self):
        # The file is the reference; the change artifact is the pinned
        # digest (the Plugin4Shell lesson). Apply enforces the stored
        # text even if the file on disk says something else.
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        chg = store.propose(_CHANGED, h1, "alice", "add rule")
        store.approve(chg.change_id, h1)
        engine = store.apply(chg.change_id)
        d = engine.evaluate({"tool": "delete_file", "role": "coder"}, {})
        self.assertEqual(d.policy_id, "w75-test-rule")

    def test_no_bootstrap_no_engine(self):
        store, _, _ = _store(humans=1)
        with self.assertRaises(_pc.PolicyChangeError):
            store.current_engine()

    def test_double_apply_refused(self):
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        chg = store.propose(_CHANGED, h1, "alice", "add rule")
        store.approve(chg.change_id, h1)
        store.apply(chg.change_id)
        with self.assertRaises(_pc.PolicyChangeError):
            store.apply(chg.change_id)

    def test_reject(self):
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        chg = store.propose(_CHANGED, h1, "alice", "add rule")
        store.reject(chg.change_id, "not now")
        self.assertEqual(chg.status, "rejected")
        with self.assertRaises(_pc.PolicyChangeError):
            store.apply(chg.change_id)


class TestBreakGlass(unittest.TestCase):
    def setUp(self):
        self.h1, self.h2 = _human(), _human()
        self.trust = _trust(self.h1, self.h2)
        self.bg = _pc.BreakGlass(trust=self.trust, log=None,
                                 session_id="sess-w75")

    def test_happy_path(self):
        d = self.bg.declare("db failover", 3600, self.h1)
        self.assertEqual(d.state, "declared")
        self.bg.activate(d.declaration_id)
        self.bg.use(d.declaration_id, "restarted agent pool")
        self.assertEqual(self.bg.outstanding_reviews(),
                         [d.declaration_id])
        self.bg.review(d.declaration_id, self.h2, "justified, no exfil")
        self.assertEqual(self.bg.outstanding_reviews(), [])

    def test_use_without_declaration_refused(self):
        with self.assertRaises(_pc.BreakGlassError):
            self.bg.use("bg-999999", "sneaky override")

    def test_expired_use_refused_loudly(self):
        t0 = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
        d = self.bg.declare("short window", 60, self.h1, now=t0)
        self.bg.activate(d.declaration_id,
                         now=t0 + timedelta(seconds=30))
        with self.assertRaises(_pc.BreakGlassError):
            self.bg.use(d.declaration_id, "too late",
                        now=t0 + timedelta(seconds=120))
        self.assertEqual(d.state, "expired")

    def test_review_gate_blocks_new_declaration(self):
        d = self.bg.declare("first", 3600, self.h1)
        self.bg.activate(d.declaration_id)
        self.bg.use(d.declaration_id, "did the thing")
        d2 = self.bg.declare("second", 3600, self.h1)
        with self.assertRaises(_pc.BreakGlassError):
            self.bg.activate(d2.declaration_id)
        self.bg.review(d.declaration_id, self.h2, "ok")
        self.bg.activate(d2.declaration_id)  # gate clears
        self.assertEqual(d2.state, "active")

    def test_self_review_refused(self):
        d = self.bg.declare("first", 3600, self.h1)
        self.bg.activate(d.declaration_id)
        self.bg.use(d.declaration_id, "did the thing")
        with self.assertRaises(_pc.BreakGlassError):
            self.bg.review(d.declaration_id, self.h1, "i was fine")

    def test_non_human_cannot_declare(self):
        outsider = _human()
        with self.assertRaises(_pc.BreakGlassError):
            self.bg.declare("evil", 60, outsider)

    def test_ttl_cap(self):
        with self.assertRaises(_pc.BreakGlassError):
            self.bg.declare("standing privilege", 90000, self.h1)

    def test_expire_due_sweeper(self):
        d = self.bg.declare("short", 1, self.h1,
                            now=datetime(2026, 9, 22, 12, 0, 0,
                                         tzinfo=timezone.utc))
        closed = self.bg.expire_due(now=datetime(
            2026, 9, 22, 12, 5, 0, tzinfo=timezone.utc))
        self.assertEqual(closed, [d.declaration_id])
        self.assertEqual(d.state, "expired")


class TestProvenanceRecords(unittest.TestCase):
    def test_policy_change_and_breakglass_records_chain(self):
        tmp = tempfile.mkdtemp(prefix="govred-w75-")
        log = ActionLog(Path(tmp) / "actions.jsonl")
        store, (h1,), _ = _store(humans=1)
        store.log = log
        store.session_open = "2026-09-22T15:00:00+00:00"
        _bootstrap(store, h1)
        chg = store.propose(_CHANGED, h1, "alice", "add rule")
        store.approve(chg.change_id, h1)
        store.apply(chg.change_id)
        bg = _pc.BreakGlass(trust=store.trust, log=log,
                            session_id="sess-w75")
        d = bg.declare("failover", 600, h1)
        bg.activate(d.declaration_id)
        bg.use(d.declaration_id, "restarted pool")
        entries = _log.read_entries(str(Path(tmp) / "actions.jsonl"))
        rtypes = [e["prov"]["record_type"] for e in entries
                  if isinstance(e.get("prov"), dict)]
        self.assertIn("policy_change", rtypes)
        self.assertIn("breakglass", rtypes)
        # every record verifies (chain MACs intact)
        ok, broken, count = _log.verify_chain(
            str(Path(tmp) / "actions.jsonl"))
        self.assertTrue(ok, "chain broken at %r" % broken)
        # the export's governor section lists them with anchor grades
        export = _prov.provenance_export(entries, None)
        kinds = [r["kind"] for r in
                 export["governor_changes"]["records"]]
        self.assertIn("policy_change", kinds)
        self.assertIn("breakglass", kinds)

    def test_policy_change_record_rejects_bad_status(self):
        rec = _pc.build_policy_change_record(
            session_id="s", session_open="2026-09-22T15:00:00+00:00",
            policy_version="v1", change_id="c", new_version="v2",
            prior_version="GENESIS", status="sneaky", tier="two-person",
            author_key_id="k", approver_key_ids=["k"],
            policy_digest="d", prior_digest="p", diff_digest="dd",
            diff_summary={}, purpose="x", authorship_ref="r",
            approvals=[])
        verdict = _prov.validate_provenance({"prov": rec["prov"]})
        self.assertFalse(verdict["ok"])


class TestExecutorGovernedPath(unittest.TestCase):
    def test_silent_yaml_rewrite_does_not_move_live_engine(self):
        # The break-first claim: on the governed path there is no
        # reload-from-disk, so editing the YAML file mid-run is
        # impossible-by-construction — the live engine does not move.
        import tempfile as _tf
        policy_file = Path(_tf.mkdtemp(prefix="govred-w75p-")) / "p.yaml"
        policy_file.write_text(_BASE_POLICY)
        from gov.executor import ToolExecutor
        from gov.approvals import ApprovalQueue
        run_dir = Path(tempfile.mkdtemp(prefix="govred-w75e-"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        engine = PolicyEngine(str(policy_file))
        ex = ToolExecutor(run_dir, engine, log, approvals,
                          policy_store=store,
                          # Wave-85: the governed store is the subject
                          # here; delegation identity is not installed, so
                          # the bypass is declared, not silent.
                          ungoverned_ack=(
                              "governed-policy-store test: the store is "
                              "the subject; delegation identity not "
                              "installed"))
        # rewrite the file on disk to an allow-all shape
        policy_file.write_text(
            "version: 2\nroles:\n  coder: [delete_file]\n"
            "policies:\n  - id: allow-all\n"
            "    effect: allow\n    match:\n      tool: delete_file\n")
        # the governed engine is the store's, not the file's
        self.assertIs(ex._resolve_engine(), store.current_engine())
        d = ex._resolve_engine().evaluate(
            {"tool": "delete_file", "role": "coder"}, {})
        self.assertNotEqual(d.policy_id, "allow-all")

    def test_version_pinning_across_swap_real_calls(self):
        # Honest version-pinning proof: real ToolExecutor.call() verdicts
        # on either side of a store.apply. Each decision entry carries
        # the digest of the engine that decided it, and the verdict
        # itself moves with the version — "which rule decided this"
        # stays answerable across the swap.
        from gov.executor import ToolExecutor
        from gov.approvals import ApprovalQueue
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        run_dir = Path(tempfile.mkdtemp(prefix="govred-w75pincall-"))
        log = ActionLog(run_dir / "actions.jsonl")
        ex = ToolExecutor(run_dir, store.current_engine(), log,
                          ApprovalQueue(run_dir, log), policy_store=store,
                          # Wave-85: the governed store is the subject
                          # here; delegation identity is not installed, so
                          # the bypass is declared, not silent.
                          ungoverned_ack=(
                              "governed-policy-store test: the store is "
                              "the subject; delegation identity not "
                              "installed"))
        ident = ex.mint_identity("a1", "coder", "alice")
        v1_digest = store.current_engine().policy_hash
        r1 = ex.call(ident, "delete_file", path="notes.txt")
        self.assertEqual(r1["status"], "executed")
        chg = store.propose(_CHANGED, h1, "alice", "add deny rule")
        store.approve(chg.change_id, h1)
        store.apply(chg.change_id)
        v2_digest = store.current_engine().policy_hash
        self.assertNotEqual(v1_digest, v2_digest)
        r2 = ex.call(ident, "delete_file", path="notes.txt")
        self.assertEqual(r2["status"], "denied")
        entries = {e["seq"]: e for e in
                   _log.read_entries(run_dir / "actions.jsonl")}
        e1, e2 = entries[r1["seq"]], entries[r2["seq"]]
        self.assertEqual(e1["decision"], "allowed_executed")
        self.assertEqual(e1["policy_id"], "allow-sandbox-deletes")
        self.assertEqual(e1["policy_hash"], v1_digest)
        self.assertEqual(e2["decision"], "denied")
        self.assertEqual(e2["policy_id"], "w75-test-rule")
        self.assertEqual(e2["policy_hash"], v2_digest)
        # every verdict-path entry on both calls carries the stamp —
        # no call-decision entry is anonymous.
        for e in entries.values():
            if e.get("event") == "tool_call":
                self.assertIn("policy_hash", e)


if __name__ == "__main__":
    unittest.main()
