"""Row-7 e1: temporal blast-radius analysis probes (wave-132).

RED-FIRST break battery for ``gov/blast_radius.py``. Every situation runs
against the REAL product surface (default policy, real hash-chained audit
log, real approval queue + sweep, real governed ``spawn_sub_agent``), and
asserts on the REAL analysis output.

Situations:
  s1  approval consumed downstream: the approval's three audit stages
      (queued attempt, sweep authorization, executed action -- all
      carrying the approval id), a same-agent write, a real child
      spawn, and the child's own approved egress must ALL appear in
      the report anchored on the approval (with external effects and
      data touched).
  s2  deleted downstream log entry: removing a middle line (and, separately,
      truncating the tail) must make ``analyze_blast_radius`` raise
      ``BlastRadiusUnverifiable`` -- never return a clean-looking report.
  s3  unrelated concurrent agent: actions by a second agent with no spawn
      link to the anchor agent must be EXCLUDED from the report.
  s4  unknown approval id: ``AnchorNotFound`` (fail closed, no empty report).
  s5  event-seq anchor: anchoring on the write event (not the approval)
      still walks forward and links the later same-agent post.

Hermetic: temp dirs, synthetic Ed25519 keys, no network. Deterministic
except wall-clock iat/exp inside delegation tokens (never asserted on).

Run: ``env -u GOV_DEPLOYMENT_MODE <venv>/python evals/blast_radius_probes.py``
Exit 0 = all situations behaved as specified; exit 1 = a probe failed.
"""

import io
import json
import os
import secrets
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Synthetic HMAC key for the scenario's audit chain (mirrors
# evals/row7_delayed_break.py); never leaves the temp run dir.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "blast-radius-probes")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov import delegation_tokens as _dt  # noqa: E402
from gov import executor as _exec_mod  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.blast_radius import (  # noqa: E402  (RED-FIRST: module lands in wave-132)
    AnchorNotFound,
    BlastRadiusUnverifiable,
    analyze_blast_radius,
)
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries, verify_chain  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

PRINCIPAL = "user-1"
WORKER = "worker-1"
OTHER = "other-1"
CHILD = "child-1"
POST_URL = "https://vendor.synthetic.local/sync"
CHILD_POST_URL = "https://vendor.synthetic.local/child-sync"
OTHER_POST_URL = "https://vendor.synthetic.local/other-sync"
ACK = ("blast_radius_probes: the subject under test is temporal "
       "blast-radius analysis, not the capability gate; declared, not silent")


# --------------------------------------------------------------------------
# Minimal delegation harness (mirrors tests/test_w86_identity.py's trio).
# --------------------------------------------------------------------------

class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, agent_id=WORKER, agent_keys=None):
        keys = {WORKER: self.parent[1]} if agent_keys is None else dict(agent_keys)
        if agent_id not in keys and agent_keys is None:
            keys[agent_id] = self.parent[1]
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys=keys)


_AGENT_SCOPE = ("tool:read_file", "tool:write_file", "tool:http_post",
                "tool:send_email")
_DELEG_SCOPE = ("tool:read_file", "tool:write_file", "tool:http_post",
                "tool:send_email")


def _bound_ctx(keys, session, agent_id=WORKER):
    user_tok = _dt.issue_user_token(keys.idp[0], "alice", _AGENT_SCOPE,
                                    session, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(keys.authority[0], agent_id, "researcher",
                                      "alice", _AGENT_SCOPE, session, ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "alice", user_tok, agent_tok, _DELEG_SCOPE,
        session, "urn:blast-radius:revoke", ttl_s=3600)
    trust = keys.trust(agent_id=agent_id)
    ctx = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=trust, session_id=session).bind()
    return ctx


class _Quiet(object):
    """Swallow the wave-86/wave-100 one-time warnings for clean output."""

    def __enter__(self):
        self._old_aud = _dt._audience_unset_warned
        self._old_rev = _exec_mod._revocation_ttl_only_warned
        _dt._audience_unset_warned = True
        _exec_mod._revocation_ttl_only_warned = True
        self._redir = redirect_stderr(io.StringIO())
        self._redir.__enter__()
        return self

    def __exit__(self, *exc):
        self._redir.__exit__(*exc)
        _dt._audience_unset_warned = self._old_aud
        _exec_mod._revocation_ttl_only_warned = self._old_rev
        return False


class _Scenario(object):
    """One governed run with a real spawn; records the seqs that matter."""

    def __init__(self):
        self._td = tempfile.TemporaryDirectory(prefix="govblast-")
        self.run_dir = Path(self._td.name) / "run"
        self.run_dir.mkdir()
        self.engine = PolicyEngine(str(REPO_ROOT / "policies" / "default.yaml"))
        self.log = ActionLog(self.run_dir / "actions.jsonl")
        self.approvals = ApprovalQueue(self.run_dir, self.log)
        self.keys = _Keys()
        self.log_path = self.run_dir / "actions.jsonl"
        self.seqs = {}

    def close(self):
        self._td.cleanup()

    def build(self):
        session = self.run_dir.name
        with _Quiet():
            ctx = _bound_ctx(self.keys, session)
            # Governed core installed (mirrors tests/test_w86_identity.py):
            # a real policy store so the governed spawn path can construct
            # the child executor without an ungoverned bypass.
            store = _pc.GovernedPolicyStore(
                deployment_mode="dev", trust=self.keys.trust(),
                log=self.log, session_id="sess-blast-store")
            human = self.keys.human[0]
            store.bootstrap(
                (REPO_ROOT / "policies" / "default.yaml").read_text(
                    encoding="utf-8"),
                human, "alice", "blast-radius genesis",
                approver_signers=[human])
            self.ex = ToolExecutor(
                self.run_dir, self.engine, self.log, self.approvals,
                ledger_path=self.run_dir / "egress_ledger.jsonl",
                delegation_context=ctx,
                policy_store=store,
                session_identity=(WORKER, "researcher", PRINCIPAL),
                capability_ungoverned_ack=ACK)
            # The unrelated concurrent agent gets its OWN delegation
            # (separate subject, separate trust) on a second executor
            # sharing the run -- no spawn link to worker-1 by construction.
            ctx2 = _bound_ctx(self.keys, session, agent_id=OTHER)
            self.ex2 = ToolExecutor(
                self.run_dir, self.engine, self.log, self.approvals,
                ledger_path=self.run_dir / "egress_ledger.jsonl",
                delegation_context=ctx2,
                policy_store=store,
                session_identity=(OTHER, "researcher", PRINCIPAL),
                capability_ungoverned_ack=ACK)
        # NOTE: worker-1 is minted twice (coder for write_file, researcher
        # for http_post) because the default role allowlist has no single
        # role holding both tools; audit attribution keys on agent_id.
        self.worker_coder = self.ex.mint_identity(WORKER, "coder", PRINCIPAL)
        self.worker_researcher = self.ex.mint_identity(WORKER, "researcher", PRINCIPAL)
        # other-1 is minted in both executors: ex2 checks its own mint set
        # on call(); the shared queue's verifier is write-once bound to
        # the first executor (F26).
        self.other = self.ex2.mint_identity(OTHER, "researcher", PRINCIPAL)
        self.ex.mint_identity(OTHER, "researcher", PRINCIPAL)
        return self

    def approve_and_sweep(self, record, executor=None):
        assert record.get("status") == "queued", record
        self.approvals.decide(record["approval_id"], True,
                              reason="blast-radius probe approval",
                              decided_by="human-operator")
        # The sweep re-validates the delegation at execution time against
        # the sweeping executor's own delegation context, so a record
        # queued by the child must be swept by the child's executor.
        done = (executor or self.ex).execute_approved()
        assert done, "sweep executed nothing"
        return done

    def run(self):
        ex = self.ex
        # 1. worker-1 http_post -> queued -> approved (A1) -> sweep.
        r = ex.call(self.worker_researcher, "http_post", url=POST_URL,
                    payload={"kind": "parent-sync"})
        approval_a1 = r.get("approval_id")
        assert approval_a1, r
        self.approve_and_sweep(r)
        # 2. worker-1 stages a file AFTER the approval (downstream of the
        #    anchor: agent_lineage edge).
        r = ex.call(self.worker_coder, "write_file", path="staged.txt",
                    content="staged payload for the probe")
        assert r.get("status") == "executed", r
        # 3. worker-1 spawns child-1 through the REAL governed spawn path.
        with _Quiet():
            child_ex = ex.spawn_sub_agent(
                CHILD, ("tool:http_post", "tool:read_file"),
                self.keys.parent[0])
        # 4. child-1 http_post -> queued -> approved (A2) -> sweep.
        # The child mints its own identity in its executor (the
        # provisioned session identity is not directly callable), and
        # the parent mints the same tuple too: the shared approval
        # queue's identity verifier is write-once bound to the parent
        # executor (F26), so the child's queued approval must resolve
        # in the parent's mint set as well.
        self.ex.mint_identity(CHILD, "researcher", "alice")
        child_ident = child_ex.mint_identity(CHILD, "researcher", "alice")
        r = child_ex.call(child_ident, "http_post",
                          url=CHILD_POST_URL, payload={"kind": "child-sync"})
        assert r.get("status") == "queued", r
        self.approve_and_sweep(r, executor=child_ex)
        # 5. unrelated concurrent agent other-1 posts (no spawn link).
        # It acts through its own executor/delegation; its record is
        # swept by its own executor for the same delegation-at-execution
        # reason as the child's.
        r = self.ex2.call(self.other, "http_post", url=OTHER_POST_URL,
                          payload={"kind": "other-sync"})
        assert r.get("status") == "queued", r
        self.approve_and_sweep(r, executor=self.ex2)
        self._index_seqs(approval_a1)
        return approval_a1

    def _index_seqs(self, approval_a1):
        entries = read_entries(self.log_path)
        for e in entries:
            ev, tool = e.get("event"), e.get("tool")
            agent = e.get("agent_id")
            if (ev == "approval_decision" and e.get("approval_id") == approval_a1
                    and e.get("decision") == "approved"):
                self.seqs["approval_a1"] = e["seq"]
            # One approval produces three audit stages, all carrying the
            # approval id: the queued attempt, the sweep's authorization,
            # and the executed action.
            if (ev == "tool_call" and e.get("approval_id") == approval_a1):
                self.seqs["a1_stage_" + str(e.get("decision"))] = e["seq"]
            if (ev == "tool_call" and tool == "write_file"
                    and agent == WORKER and e.get("args", {}).get("path") == "staged.txt"):
                self.seqs["write"] = e["seq"]
            if ev == "agent_spawn" and e.get("sub_agent_id") == CHILD:
                self.seqs["spawn"] = e["seq"]
            if (ev == "tool_call" and tool == "http_post" and agent == CHILD):
                self.seqs["child_post"] = e["seq"]
            if (ev == "tool_call" and tool == "http_post" and agent == OTHER):
                self.seqs["other_post"] = e["seq"]
        self.approval_a1 = approval_a1


# --------------------------------------------------------------------------
# Situations
# --------------------------------------------------------------------------

def _situation(name, fn):
    try:
        detail = fn()
        return {"situation": name, "verdict": "HELD", "detail": detail}
    except AssertionError as exc:
        return {"situation": name, "verdict": "BREAK",
                "detail": "assertion failed: %s" % exc}
    except Exception as exc:  # noqa: BLE001 -- a probe error is a BREAK too
        return {"situation": name, "verdict": "BREAK",
                "detail": "%s: %s" % (type(exc).__name__, exc)}


def sit_approval_consumed_downstream():
    """s1: the report anchored on A1 must include every downstream node."""
    sc = _Scenario().build()
    try:
        a1 = sc.run()
        report = analyze_blast_radius(a1, str(sc.log_path))
        by_seq = {n["seq"]: n for n in report["affected_actions"]}
        # The approval's three audit stages all carry the approval id and
        # must ALL be reported as approval_consumption (strong). The
        # queued stage predates the decision; the module roots the DAG on
        # it explicitly.
        for stage in ("queued_pending", "execution_authorized",
                      "approved_executed"):
            key = "a1_stage_" + stage
            assert key in sc.seqs, "scenario did not record stage %s" % stage
            seq = sc.seqs[key]
            assert seq in by_seq, "missing node for %s (seq %s)" % (key, seq)
            assert by_seq[seq]["edge_kind"] == "approval_consumption", \
                (key, by_seq[seq]["edge_kind"])
            assert by_seq[seq]["strength"] == "strong", (key, seq)
        # The downstream lineage: same-agent write, real spawn, child egress.
        for key in ("write", "spawn", "child_post"):
            seq = sc.seqs[key]
            assert seq in by_seq, "missing node for %s (seq %s)" % (key, seq)
        assert by_seq[sc.seqs["spawn"]]["edge_kind"] == "spawn"
        assert by_seq[sc.seqs["child_post"]]["agent_id"] == CHILD
        # External effects: both egress destinations recorded.
        dests = {fx["destination"] for fx in report["external_effects"]}
        assert POST_URL in dests, dests
        assert CHILD_POST_URL in dests, dests
        # Data touched: the staged file.
        touched = [d["path"] for d in report["data_touched"]]
        assert any("staged.txt" in p for p in touched), touched
        # Containment checklist names the child and the destinations.
        blob = "\n".join(report["containment_checklist"])
        assert CHILD in blob and POST_URL in blob, blob
        return ("report covers %d nodes (%d strong / %d medium); "
                "external effects: %s"
                % (len(report["affected_actions"]), report["counts"]["strong"],
                   report["counts"]["medium"], sorted(dests)))
    finally:
        sc.close()


def sit_deleted_log_entry_fails_closed():
    """s2: a tampered log must raise, never yield a clean report.

    Tampering is done IN PLACE on the original log file: the checkpoint
    sidecar is untouched, so the failure must come from the broken
    chain itself (sequence gap / checkpoint mismatch), never from a
    missing anchor. The intact bytes are restored between cases.
    """
    sc = _Scenario().build()
    try:
        a1 = sc.run()
        raw = Path(sc.log_path).read_bytes()
        lines = raw.decode("utf-8").splitlines()
        assert len(lines) > 8, "scenario too short to tamper meaningfully"
        # Case 1: delete a downstream line (the staged write) in place.
        del_idx = sc.seqs["write"] - 1  # seqs are 1-based, lines 0-based
        assert del_idx > sc.seqs["approval_a1"], "not downstream of anchor"
        try:
            Path(sc.log_path).write_text(
                "\n".join(lines[:del_idx] + lines[del_idx + 1:]) + "\n",
                encoding="utf-8")
            try:
                analyze_blast_radius(a1, str(sc.log_path))
            except BlastRadiusUnverifiable as exc:
                # The sequence gap names the entry AFTER the hole, not a
                # missing checkpoint.
                assert ("broken at seq %d" % (sc.seqs["write"] + 1)) in str(exc), exc
            else:
                raise AssertionError("middle deletion did not fail closed")
            ok, broken, _ = verify_chain(str(sc.log_path))
            assert not ok and broken == sc.seqs["write"] + 1, (ok, broken)
        finally:
            Path(sc.log_path).write_bytes(raw)
        # Case 2: truncate the tail in place.
        try:
            Path(sc.log_path).write_text(
                "\n".join(lines[:-3]) + "\n", encoding="utf-8")
            try:
                analyze_blast_radius(a1, str(sc.log_path))
            except BlastRadiusUnverifiable:
                pass
            else:
                raise AssertionError("tail truncation did not fail closed")
            ok, _broken, _ = verify_chain(str(sc.log_path))
            assert not ok, "truncated log verified clean"
        finally:
            Path(sc.log_path).write_bytes(raw)
        return ("middle-deletion (sequence gap) and tail-truncation "
                "(checkpoint mismatch) both raised BlastRadiusUnverifiable")
    finally:
        sc.close()


def sit_unrelated_agent_excluded():
    """s3: other-1's concurrent actions must not appear in A1's report."""
    sc = _Scenario().build()
    try:
        a1 = sc.run()
        report = analyze_blast_radius(a1, str(sc.log_path))
        node_seqs = {n["seq"] for n in report["affected_actions"]}
        assert sc.seqs["other_post"] not in node_seqs, (
            "unrelated agent's post leaked into the blast radius")
        agents = set(report["agents_involved"])
        assert OTHER not in agents, agents
        assert WORKER in agents and CHILD in agents, agents
        return ("other-1's post (seq %s) excluded; agents_involved=%s"
                % (sc.seqs["other_post"], sorted(agents)))
    finally:
        sc.close()


def sit_unknown_approval_fails_closed():
    """s4: an approval id with no decision event raises AnchorNotFound."""
    sc = _Scenario().build()
    try:
        sc.run()
        try:
            analyze_blast_radius("nope-does-not-exist", str(sc.log_path))
        except AnchorNotFound:
            return "unknown approval id raised AnchorNotFound"
        raise AssertionError("unknown approval id did not raise")
    finally:
        sc.close()


def sit_event_seq_anchor():
    """s5: anchoring on the write event still walks forward to the spawn
    and the child's post; the anchor event itself is the DAG root."""
    sc = _Scenario().build()
    try:
        sc.run()
        report = analyze_blast_radius(sc.seqs["write"], str(sc.log_path))
        by_seq = {n["seq"]: n for n in report["affected_actions"]}
        node_seqs = set(by_seq)
        # The anchor event is the root of its own radius.
        assert by_seq[sc.seqs["write"]]["edge_kind"] == "anchor", by_seq
        assert sc.seqs["spawn"] in node_seqs, node_seqs
        assert sc.seqs["child_post"] in node_seqs, node_seqs
        # The parent's post predates the write anchor: upstream, excluded.
        assert sc.seqs["a1_stage_approved_executed"] not in node_seqs, node_seqs
        assert report["anchor"]["kind"] == "event"
        assert report["anchor"]["seq"] == sc.seqs["write"]
        return ("event anchor at seq %s links forward to the spawn at seq %s "
                "and the child post at seq %s"
                % (sc.seqs["write"], sc.seqs["spawn"],
                   sc.seqs["child_post"]))
    finally:
        sc.close()


def main():
    situations = [
        ("s1_approval_consumed_downstream", sit_approval_consumed_downstream),
        ("s2_deleted_log_entry_fails_closed", sit_deleted_log_entry_fails_closed),
        ("s3_unrelated_agent_excluded", sit_unrelated_agent_excluded),
        ("s4_unknown_approval_fails_closed", sit_unknown_approval_fails_closed),
        ("s5_event_seq_anchor", sit_event_seq_anchor),
    ]
    results = [_situation(name, fn) for name, fn in situations]
    broken = [r for r in results if r["verdict"] != "HELD"]
    print(json.dumps({"results": results}, indent=2))
    print("blast_radius_probes: %d/%d HELD" % (len(results) - len(broken), len(results)))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
