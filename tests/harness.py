"""Shared red-team test harness for the agent-governance product.

CONTRACT (used by every red-team test module):
    ctx = make_run(policy_path=None)

    ctx is a dict with keys:
        executor     ToolExecutor bound to a fresh run directory
        log          ActionLog for the run
        approvals    ApprovalQueue for the run
        policy       PolicyEngine in use
        run_dir      fresh temp-dir Path for this run
        identities   dict role-name -> AgentIdentity for the three standard agents
        mint_identity(agent_id, role, principal) -> AgentIdentity  (executor mint)
        is_minted(identity) -> bool   (True only if minted via this harness)
        read_log()   -> list of stored log entries for this run

Three standard agents (identities minted by the EXECUTOR, never self-claimed
by the simulated agents):
    support:    role "support",    principal "customer-org", tools ["read_file", "send_email"]
    coder:      role "coder",      principal "dev-org",      tools ["read_file", "write_file", "delete_file", "api_call"]
    researcher: role "researcher", principal "research-org", tools ["read_file", "api_call", "http_post", "send_email"]

Tool allowlists are ENFORCED by the executor (R2): the executor rejects any
tool not listed for the caller's role before policy evaluation.

Works against the current executor API:
    ToolExecutor(run_dir, policy, log, approvals, ledger_path=None)
    executor.mint_identity(agent_id, role, principal) -> AgentIdentity
    executor.call(identity, tool, **kwargs) -> {"status": "executed"|"denied"|"queued", ...}
"""

import tempfile
from pathlib import Path

from gov.approvals import (ApprovalQueue, BREAK_GLASS_TICKET_FILENAME,
                            provision_break_glass_ticket)
from gov.executor import ToolExecutor
from gov.log import ActionLog, read_entries
from gov.policy import PolicyEngine

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"

# role -> spec. "tools" is the intended least-privilege allowlist (R2);
# the product does not enforce it yet, so tests asserting refusal FAIL.
STANDARD_AGENTS = {
    "support": {
        "agent_id": "support-1",
        "role": "support",
        "principal": "customer-org",
        "tools": ["read_file", "send_email"],
    },
    "coder": {
        "agent_id": "coder-1",
        "role": "coder",
        "principal": "dev-org",
        "tools": ["read_file", "write_file", "delete_file", "api_call"],
    },
    "researcher": {
        "agent_id": "researcher-1",
        "role": "researcher",
        "principal": "research-org",
        "tools": ["read_file", "api_call", "http_post", "send_email"],
    },
}


def make_run(policy_path=None, ledger_path=None, principal_registry=None,
             break_glass_tickets=(), session_identity=None):
    """Build one isolated governance run: fresh temp dir, policy, log,
    approval queue, executor, and harness-minted identities.

    ``ledger_path`` selects the F10 per-principal egress ledger. Default
    is a ledger INSIDE the run dir, so cross-run campaign detection is
    inert within a single make_run (existing tests stay hermetic). Pass
    an explicit shared path to exercise cross-run behavior.

    ``principal_registry`` (F17b) installs a deployment-controlled
    principal allowlist: minting for an unregistered principal raises.
    Default None = permissive demo mode (any principal string mints).

    ``break_glass_tickets`` (F49, R11): iterable of
    ``(ticket_id, operator_principal, reviewer_principal)`` tuples,
    provisioned into the run's ticket store BEFORE executor
    construction — the run-start snapshot seals exactly these tickets,
    mirroring the out-of-band human provisioning workflow. Default
    empty (no tickets; break_glass without a provisioned ticket is
    refused).

    ``session_identity`` (F55, R13): an
    ``(agent_id, role, principal)`` tuple the deployment provisions
    out-of-band as the session's ONE entitled identity
    (``provenance="provisioned"``). ``ctx["session_identity"]`` returns
    the provisioned ``AgentIdentity`` object (None when not given);
    ``ApprovalQueue.break_glass`` then requires exactly it and refuses
    mid-run minted identities. Default None = pre-R13 dev behavior.
    """
    run_dir = Path(tempfile.mkdtemp(prefix="govred-"))
    policy = PolicyEngine(str(policy_path or DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    # F49: human out-of-band provisioning happens BEFORE the run
    # starts; the executor's run-start snapshot seals this set.
    for ticket_id, operator_principal, reviewer_principal in \
            break_glass_tickets:
        provision_break_glass_ticket(
            run_dir / BREAK_GLASS_TICKET_FILENAME,
            ticket_id, operator_principal, reviewer_principal)
    executor = ToolExecutor(run_dir, policy, log, approvals,
                            ledger_path=(ledger_path
                                         if ledger_path is not None
                                         else run_dir / "egress_ledger.jsonl"),
                            principal_registry=principal_registry,
                            session_identity=session_identity)

    minted = set()

    def mint_identity(agent_id, role, principal):
        # Identities are minted by the EXECUTOR: only identities it issued
        # are honored by executor.call(). The harness keeps its own record
        # for is_minted() introspection.
        ident = executor.mint_identity(agent_id, role, principal)
        minted.add((agent_id, role, run_dir.name, principal))
        return ident

    def is_minted(identity):
        return (
            identity.agent_id,
            identity.role,
            identity.run_id,
            identity.principal,
        ) in minted

    identities = {
        name: mint_identity(spec["agent_id"], spec["role"], spec["principal"])
        for name, spec in STANDARD_AGENTS.items()
    }

    return {
        "executor": executor,
        "log": log,
        "approvals": approvals,
        "policy": policy,
        "run_dir": run_dir,
        "identities": identities,
        "mint_identity": mint_identity,
        "is_minted": is_minted,
        "session_identity": executor._session_identity,
        "read_log": lambda: read_entries(run_dir / "actions.jsonl"),
    }


def plant_file(ctx, relpath, content):
    """Write a file into the run's sandbox (simulating pre-existing data the
    agent can read). Returns the Path."""
    p = ctx["run_dir"] / "sandbox" / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p
