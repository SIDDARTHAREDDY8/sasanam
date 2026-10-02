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

Wave-85: the harness deliberately exercises the RAW (pre-wave-74/75)
pipeline — no policy_store, no delegation_context — so every
make_run() construction carries an explicit, recorded ungoverned_ack.
The bypass is declared and chained per construction (better evidence,
not worse); production-mode runs would refuse it outright.
"""

import os
import shutil
import tempfile
from pathlib import Path

from gov.approvals import (ApprovalQueue, BREAK_GLASS_TICKET_FILENAME,
                            provision_break_glass_ticket)
from gov.executor import ToolExecutor
from gov.log import ActionLog, read_entries
from gov.policy import PolicyEngine

# Wave-24 run-dir hygiene: every run dir make_run() creates is registered
# here (realpath'd, creation order) so the suite runner can remove them
# all at process end. Tests never clean these up individually (344 call
# sites), so without this the canonical suite leaks thousands of
# govred-* dirs per run into TMPDIR (wave-23: ~10.5k dirs filled the
# 512MB /tmp tmpfs -> Errno 28). See cleanup_run_dirs() below.
_RUN_DIR_REGISTRY = []

# Module-alias canonicalization: test modules import this file both as
# top-level ``harness`` (the runner's sys.path[0] is tests/) and as
# ``tests.harness`` (package path). Without this there are TWO module
# objects with TWO registries and cleanup misses the other alias's
# dirs. Whichever alias loads second adopts the first one's registry
# LIST OBJECT, so every make_run() in the process registers into one
# shared list no matter which import path the caller used.
import sys as _sys

for _alias in ("harness", "tests.harness"):
    _mod = _sys.modules.get(_alias)
    if (_mod is not None and _mod is not _sys.modules[__name__]
            and hasattr(_mod, "_RUN_DIR_REGISTRY")):
        _RUN_DIR_REGISTRY = _mod._RUN_DIR_REGISTRY
        break
del _alias, _mod


def _register_run_dir(path):
    _RUN_DIR_REGISTRY.append(os.path.realpath(str(path)))
    return path


# Wave-88: PID-stamped ownership markers. Every run dir make_run()
# creates carries a ``.gov-owner-<pid>`` marker naming the creating
# process. Sweeps that may encounter FOREIGN dirs (run_tests.py's
# backstop, evals/run_evals._sweep_new_tmpdirs) skip markers owned by a
# LIVE other pid -- this makes the wave-87 flake (a concurrent gate's
# sweep removing a live run dir between a test's exists() and open()
# on approvals.jsonl) impossible by construction instead of
# caught-and-swallowed. The /proc fd-liveness scan alone cannot see a
# test that is between file operations (no open fd at the scan
# instant); the marker is the owner saying "I am live".
#
# Markers owned by a DEAD pid are stale and still swept (no leak
# regression). The creating process's OWN registry sweep
# (cleanup_run_dirs) always finalizes its own dirs: its pid is never
# "other", and suite-end cleanup must work despite unclosed fds
# (wave-23's Errno-28 leak). In-process threads must be joined by
# their test before any sweep -- the own-pid exclusion is intentional.
_OWNER_MARKER_PREFIX = ".gov-owner-"


def _mark_run_dir_owned(run_dir):
    """Stamp the creating pid on a fresh run dir.

    Raises OSError if the marker cannot be created: the marker is the
    only thing that protects a live run dir from a foreign sweep, so
    a dir that cannot be marked must not be handed out.
    """
    Path(run_dir).joinpath(
        "%s%d" % (_OWNER_MARKER_PREFIX, os.getpid())).touch()


def _pid_alive(pid):
    """True if pid names a live process. Fail-safe: on any ambiguity
    (EPERM, non-Linux) report alive -- a sweep must never delete a dir
    it cannot prove is unowned."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, we just cannot signal it
    except OSError:
        return True  # fail-safe toward keeping, never toward deleting
    return True


def dir_owned_by_live_other_process(path):
    """Explicit ownership check (wave-88): True if ``path`` carries a
    ``.gov-owner-<pid>`` marker whose pid is alive and is not ours.

    Fail-safe toward keeping: unreadable dirs report False here (the
    callers then apply their own guards), and pid-reuse ambiguity
    keeps the dir -- a stale marker can leak a dead owner's dir, it
    can never cause a live dir's wrongful removal."""
    me = str(os.getpid())
    try:
        names = os.listdir(path)
    except OSError:
        return False
    for name in names:
        if not name.startswith(_OWNER_MARKER_PREFIX):
            continue
        pid_s = name[len(_OWNER_MARKER_PREFIX):]
        if not pid_s.isdigit() or pid_s == me:
            continue
        if _pid_alive(int(pid_s)):
            return True
    return False


def _dir_in_use_by_live_process(path):
    """Liveness guard: True if any live process holds an open fd under
    ``path`` (checked via /proc/<pid>/fd symlinks), so cleanup never
    deletes a directory another live process is still using.

    Fail-safe: if the /proc scan cannot be performed (non-Linux, no
    /proc, permission errors), return True (keep the dir) rather than
    risk deleting a live directory. Our own fds are excluded — the
    cleanup process scanning itself does not count as "another live
    process", but any OTHER live process with an open handle vetoes
    removal.
    """
    me = str(os.getpid())
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return True
    for pid in pids:
        if pid == me:
            continue
        fd_dir = os.path.join("/proc", pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue  # process exited or unreadable: not our concern
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target == path or target.startswith(path + os.sep):
                return True
    return False


def _safe_remove_run_dir(path, stats):
    """Best-effort removal of one registered run dir with the safety
    guards: strictly inside the process temp dir, a real directory (not
    a symlink), and not in use by another live process. Records the
    outcome in ``stats`` and returns True when removed."""
    tmp = os.path.realpath(tempfile.gettempdir())
    p = os.path.realpath(str(path))
    if p == tmp or not p.startswith(tmp + os.sep):
        stats["kept_outside_tmp"] += 1
        return False
    if not os.path.isdir(p) or os.path.islink(p):
        stats["kept_missing"] += 1
        return False
    # Wave-88: never remove a run dir owned by a LIVE other process
    # (concurrent gate under the same TMPDIR). The marker check is
    # structural -- the wave-87 FileNotFoundError flake is impossible
    # by construction, not caught-and-swallowed. Own dirs (our pid)
    # and dead-owner dirs are still finalized.
    if dir_owned_by_live_other_process(p):
        stats["kept_foreign_owned"] = \
            stats.setdefault("kept_foreign_owned", 0) + 1
        return False
    if _dir_in_use_by_live_process(p):
        stats["kept_in_use"] += 1
        return False
    try:
        shutil.rmtree(p)
        stats["removed"] += 1
        return True
    except OSError:
        stats["errors"] += 1
        return False


def _safe_remove_run_file(path, stats):
    """Best-effort removal of one scratch file with the same safety
    guards as _safe_remove_run_dir: strictly inside the process temp
    dir, a regular file (never a symlink/fifo/socket), and not held
    open by another live process."""
    tmp = os.path.realpath(tempfile.gettempdir())
    p = os.path.realpath(str(path))
    if p == tmp or not p.startswith(tmp + os.sep):
        stats["kept_outside_tmp"] += 1
        return False
    if not os.path.isfile(p) or os.path.islink(p):
        stats["kept_missing"] += 1
        return False
    if _dir_in_use_by_live_process(p):
        stats["kept_in_use"] += 1
        return False
    try:
        os.unlink(p)
        stats["removed"] += 1
        return True
    except OSError:
        stats["errors"] += 1
        return False


def cleanup_run_dirs(*, success=True):
    """Remove every run dir this process created via make_run().

    Best-effort: individual removal failures are counted, never raised.
    Safety: only directories strictly inside the process temp dir are
    touched, symlinks are never followed, and a /proc liveness scan
    vetoes any dir another live process still has open.

    Retention policy (env ``GOV_KEEP_RUN_DIRS``):
      * ``GOV_KEEP_RUN_DIRS=1`` -> retain everything (debugging).
      * otherwise on a green run (``success=True``) -> remove all.
      * on a red run (``success=False``) -> retain for debugging,
        unless ``GOV_KEEP_RUN_DIRS=0`` forces cleanup anyway.

    Returns a stats dict; the registry entries for removed dirs are
    dropped so a second call is a no-op for them.
    """
    stats = {"removed": 0, "kept_in_use": 0, "kept_outside_tmp": 0,
             "kept_missing": 0, "errors": 0, "retained": 0,
             "registered": len(_RUN_DIR_REGISTRY),
             "kept_foreign_owned": 0}
    keep_env = os.environ.get("GOV_KEEP_RUN_DIRS")
    if keep_env == "1" or (not success and keep_env != "0"):
        stats["retained"] = len(_RUN_DIR_REGISTRY)
        return stats
    remaining = []
    for path in _RUN_DIR_REGISTRY:
        if _safe_remove_run_dir(path, stats):
            continue
        remaining.append(path)
    del _RUN_DIR_REGISTRY[:]
    _RUN_DIR_REGISTRY.extend(remaining)
    return stats

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
             break_glass_tickets=(), session_identity=None,
             credential_manifest=None, precommit_gate=None,
             trifecta_floor=False, memory_firewall=None,
             lineage_tracker=None, erosion_monitor=None,
             memory_actgate=None,
             # Wave-282 lane 4 (snyk/agent-scan ADAPT): the
             # deployment's discovery-scan registry + attribution
             # maps + sandboxed change-time observation. Default
             # None = pre-wave-282 behavior, zero behavior change.
             discovery_scan=None, discovery_tool_map=None,
             discovery_mcp_map=None, discovery_observe_one=None,
             discovery_pin_path=None):
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

    ``credential_manifest`` (F111, wave-34): a
    ``gov.credential_manifest.CredentialManifest`` the harness uses to
    declare every credential it provisions into the agent's reachable
    scope. The executor identity-binds egress credentials against it
    (``credential_identity_mismatch`` policy signal). Default None =
    an empty manifest is constructed (nothing provisioned).

    ``memory_firewall`` (S1-MEM): a ``gov.memory_provenance.MemoryFirewall``
    installed on the executor. Default None = pre-S1 behavior, zero
    behavior change. Pass a deployment-constructed firewall (owning a
    ledger path OUTSIDE the run dir) to exercise cross-session memory
    provenance; ledger entries persist across make_run() calls that
    share the path.

    ``lineage_tracker`` (S6, F137): a ``gov.lineage.LineageTracker``
    installed on the executor. Default None = pre-wave-90 behavior,
    zero behavior change. When installed, call() refuses unlineaged
    identities fail-closed and file writes/reads are lineage-stamped.
    The battery/harness mints genesis explicitly after make_run().

    ``erosion_monitor`` (row 9, Phase B): a
    ``gov.detection.TrajectoryErosionMonitor`` installed on the
    executor. Default None = pre-wave-119 behavior, zero behavior
    change. When installed, call() feeds it every verdict-path call
    and consults its breaker (allow -> require_approval on high-risk
    tools when the erosion breaker is OPEN -- a breaker input, never a
    verdict).
    """
    run_dir = Path(tempfile.mkdtemp(prefix="govred-"))
    try:
        _mark_run_dir_owned(run_dir)  # wave-88: PID-stamped ownership marker
    except OSError:
        # Unmarkable dirs are unusable: a foreign sweep could delete
        # them mid-run. Remove the fresh dir and fail construction.
        shutil.rmtree(run_dir, ignore_errors=True)
        raise
    _register_run_dir(run_dir)
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
                            session_identity=session_identity,
                            credential_manifest=credential_manifest,
                            precommit_gate=precommit_gate,
                            trifecta_floor=trifecta_floor,
                            memory_firewall=memory_firewall,
                            lineage_tracker=lineage_tracker,
                            erosion_monitor=erosion_monitor,
                            # Wave-173 lane 1 (TMA-NM act-time gate): the
                            # deployment's ActGate. Default None =
                            # pre-wave-173 behavior, zero behavior
                            # change.
                            memory_actgate=memory_actgate,
                            # Wave-282 lane 4 (snyk/agent-scan ADAPT):
                            # discovery-driven tool-definition
                            # registry; None = not installed.
                            discovery_scan=discovery_scan,
                            discovery_tool_map=discovery_tool_map,
                            discovery_mcp_map=discovery_mcp_map,
                            discovery_observe_one=discovery_observe_one,
                            discovery_pin_path=discovery_pin_path,
                            # Wave-85: the harness deliberately exercises
                            # the raw (pre-wave-74/75) pipeline — no
                            # policy_store, no delegation_context — so
                            # the bypass is declared and chained per
                            # construction instead of silent.
                            ungoverned_ack=(
                                "synthetic red-team harness: exercises the "
                                "raw pre-wave-74/75 pipeline by design; "
                                "the bypass is declared and chained, not "
                                "silent"))

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
        "credential_manifest": executor._credential_manifest,
        "read_log": lambda: read_entries(run_dir / "actions.jsonl"),
    }


def plant_file(ctx, relpath, content):
    """Write a file into the run's sandbox (simulating pre-existing data the
    agent can read). Returns the Path."""
    p = ctx["run_dir"] / "sandbox" / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p
