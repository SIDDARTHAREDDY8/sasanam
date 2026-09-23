"""Tool executor: every agent action flows through identity -> policy -> log.

Pipeline for each call (in order):

1. **Identity.** The identity must be an ``AgentIdentity`` *minted by this
   executor* via :meth:`mint_identity` (unforgeable within the process) and
   its ``run_id`` must match this run. A forged or cross-run identity is
   denied and logged; a structurally valid but unminted identity raises
   :class:`UnmintedIdentityError`. F55: when the deployment provisions a
   session identity at construction (``provenance="provisioned"``),
   entitlement-sensitive paths (``break_glass``) require exactly that
   identity — mid-run mints of the same tuple (``provenance="minted"``)
   are refused, closing the operator-minting impersonation.
2. **Role allowlist.** The caller's role must permit the tool at all,
   regardless of what the rules say (least privilege).
3. **DLP.** Credential patterns in arguments deny the call before any
   evaluation or execution. PII is redacted before logging/queueing.
4. **Rate/volume guards.** Per-run caps on sends, writes, deletes and a
   repeated-identical-call (loop) guard.
5. **Policy.** Fail-closed evaluation with deny priority.
6. **Fail-closed logging.** The log is probed writable *before* any side
   effect; the decision is appended, and only then does an allowed action
   execute.
7. **Provenance.** Every executed ``read_file``/``api_call`` taints the run
   (tool output is untrusted input); read content fingerprints let the
   executor detect read-before-send exfiltration. Content tripping DLP
   sensitive patterns sets a ``read_sensitive`` flag (F9), extended to
   ``api_call`` results (F15a) and persisted principal-scoped with a 24h
   TTL so a confederate's fresh run inherits it (F15b): later
   ``api_call`` is approval-gated even for paraphrased payloads. Every
   DLP-clean ``api_call`` attempt is recorded in the per-principal
   egress ledger (F10) for cross-run campaign detection — the fragment
   shape signal keyed on the registered domain (F13) plus a structural
   same-key-set signal (F14) — heuristic, queue-only, fail-safe.
8. **Faithful previews.** The approval preview is built from the same
   redacted args that will execute (F12), with control characters visibly
   escaped (F11), so the approver sees exactly what they authorize.

Simulated tools (no network, no real side effects outside the run directory):
  read_file(path)                  read a file (real read only inside the sandbox)
  write_file(path, content)        write a file (sandbox, or quarantine after approval)
  delete_file(path)                delete a file (sandbox only)
  api_call(endpoint, params)       simulated external API read
  http_post(url, payload)          simulated outbound webhook post
  send_email(to, subject, body)    simulated outbound email (never really sent)

Policy outcomes:
  allow            -> execute now, log "allowed_executed"
  deny             -> do not execute, log "denied"
  require_approval -> do not execute; queue for a human, log "queued_pending".
                     After human approval, execute_approved() re-validates
                     (expiry, integrity, current policy) and logs
                     "approved_executed".
"""

import json
import os
import fcntl
import sys
import time
import collections.abc
import itertools
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import dlp
from . import canary as _canary
from . import delegation_tokens as _delegation_tokens
from . import rules_tiering as _rules_tiering
from . import precommit as _precommit
from . import supplychain_install as sc_install
from .approvals import (DelegationError, DelegationStore,
                        IdentityVerifierAlreadySetError, approval_digest_ok,
                        APPROVAL_DIGEST_SCHEME, record_digest,
                        sanitize_preview_text, QueueLockError,
                        QueueLockInvalidatedError, QueueLockPathError,
                        SessionIdentityAlreadySetError)
# F33 (HARDENING-R8): tools whose execution moves bytes across the trust
# boundary — the byte-budget guard applies to all of them, at every
# execution boundary (direct allow path AND execute_approved).
_EGRESS_TOOLS = ("send_email", "http_post", "api_call")
# F33: conservative default cumulative egress byte budget per run
# (policy key ``rate_limit.max_egress_bytes_per_run``).
_DEFAULT_MAX_EGRESS_BYTES_PER_RUN = 256 * 1024
from .egress_ledger import (
    CAMPAIGN_K,
    CAMPAIGN_WINDOW_SECS,
    FRAGMENT_MAX_BYTES,
    FRAGMENT_MIN_ENTROPY,
    SENSITIVE_TAINT_TTL_SECS,
    EgressLedger,
    LedgerUnverifiableError,
    _ledger_read_locked,
    registered_domain,
)
from .identity import (
    AgentIdentity,
    IdentityMintLimitError,
    UnmintedIdentityError,
    UnregisteredPrincipalError,
    warn_self_asserted_identity_once,
)
from .policy import PolicyDecision
from .tool_ratings import normalize_tool_ratings
from .log import (_verify, newest_refusal_ts_per_flag, read_entries,
                   refusal_ts_within_window, verify_chain_tip,
                   write_chain_tip_from_tail)

_SEND_TOOLS = ("send_email", "http_post")
# S3 (K-041): tools that mutate state outside the run's read view. A
# mutating tool with NO rating (not in the core table, not in the
# deployment dict) is forced to require_approval — never allowed
# silently. api_call is read-classified (F1); read_file is non-mutating.
_MUTATING_TOOLS = ("write_file", "delete_file", "send_email", "http_post")
# S5 (K-052): tools whose executions feed the cross-run velocity ledger
# (sends, writes, egress bytes). delete_file is out of scope: the
# velocity thresholds name sends/writes/egress-bytes.
_VELOCITY_TOOLS = ("send_email", "http_post", "api_call", "write_file")
_MAX_READ_STORE = 256 * 1024  # cap on stored read fingerprints per run


class PolicyPinMismatchError(Exception):
    """F48 (R11): the loaded policy's content hash does not match the
    GOV_POLICY_HASH pin. Raised by ToolExecutor.__init__ — construction
    is refused fail-closed, before any tool can execute."""

# F17b: per-run identity issuance budget. Bounds identity sprawl / mint
# abuse inside one run; deployments that legitimately mint more raise
# the constant.
_MAX_IDENTITY_MINTS_PER_RUN = 64

# Verbatim-match window (chars) for read-before-send correlation. Sends use
# the original 32-char window; api_call params use a shorter 16-char window
# (F1): api_call is the exfil-shaped vector for short payloads (a 28-char
# customer row must trip the correlation), while sub-16-char query tokens
# stay non-matching so ordinary read-shaped api_call usage keeps working.
_CORRELATION_WINDOW_SEND = 32
_CORRELATION_WINDOW_API = 16


class ToolExecutor:
    def __init__(self, run_dir, policy, log, approvals, ledger_path=None,
                 principal_registry=None, session_identity=None,
                 tool_ratings=None, credential_manifest=None,
                 canary_registry=None, delegation_context=None,
                 policy_store=None, detection_monitor=None,
                 recovery=None, lease_verifier=None,
                 lease_gated_tools=(), precommit_gate=None,
                 trifecta_floor=False):
        self.run_dir = Path(run_dir)
        self.run_id = self.run_dir.name
        self.policy = policy
        self.log = log
        self.approvals = approvals
        # Wave-75 (governing the governors): the governed policy path.
        # Opt-in: None = pre-wave-75 behavior, zero behavior change.
        # When installed, call() snapshots the store's CURRENT engine
        # at call start and the verdict path (role check → evaluate →
        # recorded policy_version/hash) runs against that snapshot, so
        # a policy change applied between two calls never mixes
        # versions within one verdict. The store's apply() is the ONLY
        # code path that changes the live engine — there is no
        # reload-from-disk path (a YAML edit on disk without a
        # governed change event does not move the live engine).
        self._policy_store = policy_store
        # Wave-74 (identity): the session's three-token DelegationContext
        # (gov/delegation_tokens.DelegationContext, bound). Opt-in:
        # None = pre-wave-74 behavior, zero behavior change. When
        # installed, call() enforces the permission intersection
        # (user ∩ agent ∩ delegation scope) BEFORE policy evaluation —
        # the check lives in code, not policy text, so no policy YAML
        # edit can disable it (the "agent without delegation" case
        # fails closed BY CONSTRUCTION).
        self._delegation_context = delegation_context
        # Wave-76 (detection): the behavioral circuit-breaker monitor
        # (gov/detection.BehavioralMonitor). Opt-in: None = pre-wave-76
        # behavior, zero behavior change. When installed, call()
        # consults the monitor's breaker on the verdict path: a breaker
        # OPEN for the acting identity downgrades allow verdicts on
        # high-risk tools to require_approval (flag
        # "behavioral_breaker_open"), and stamps the wave-74 token refs
        # on every verdict-path entry so the monitor's per-identity
        # baselines key to the three-token identity. The monitor is
        # read-only and operator-owned; it never executes, approves, or
        # writes queue records.
        self._detection_monitor = detection_monitor
        # Wave-77 (recovery): the recovery controller
        # (gov/recovery.RecoveryController). Opt-in: None = pre-wave-77
        # behavior, zero behavior change. When installed, call()
        # consults the controller's external halt latch on the verdict
        # path BEFORE policy evaluation: a halted identity is refused
        # with RecoveryHaltedError (sticky — catching it and calling
        # again still raises, the canary pattern) and a loud audit
        # entry. The halt does not depend on the agent's cooperation;
        # the latch lives in the operator trust domain, keyed by the
        # agent_id string the operator used at halt time. A controller
        # error is treated as halted (fail closed, loud).
        self._recovery = recovery
        # Wave-78 (supply-chain / leases): the capability-lease verifier
        # (gov/capability_leases.LeaseVerifier, agent side — public keys
        # only). Opt-in: None = pre-wave-78 behavior, zero behavior
        # change. When installed, call() requires a valid presented
        # lease for tools in the lease-gated set on the verdict path
        # BEFORE policy evaluation: the lease is verified at use time
        # (signature, roster, window, revocation, task binding, scope)
        # and any refusal is fail-closed, loud, and audited as
        # lease_refused. The agent holds leases, never raw credentials;
        # the minting authority's private key is never in this process's
        # agent-reachable state (see gov/capability_leases).
        self._lease_verifier = lease_verifier
        self._lease_gated_tools = frozenset(lease_gated_tools or ())
        # Wave-79 (pre-commit): the pre-commit gate for irreversible
        # tools (gov/precommit.PrecommitGate). Opt-in: None =
        # pre-wave-79 behavior, zero behavior change. When installed,
        # an irreversible tool (gov/precommit.IRREVERSIBLE registry)
        # executing on a policy ALLOW verdict must present a bound,
        # unused pre-commit approval for the exact (tool, args) —
        # otherwise the call is denied fail-closed (precommit-required)
        # BEFORE the tool executes. The require_approval path still
        # queues for a human (the queue's MAC-bound approval is the
        # human moment there), but auto-approve is disabled for
        # irreversible tools while the gate is installed: the human
        # moment must be real.
        self._precommit_gate = precommit_gate
        # Wave-79 (rules tiering): the lethal-trifecta approval floor.
        # Opt-in: False = pre-wave-79 behavior, zero behavior change
        # (no tier is computed, no escalation record is chained, the
        # policy's allow/deny/queue verdicts stand exactly as written).
        # When enabled, call() computes the session's oversight tier
        # over its EFFECTIVE grants (role tools ∪ verified delegation
        # scope ∪ lease scope) on the allow path: the first elevated
        # call in a session chains one loud tier_escalated record, and
        # external-communication tools require human approval even when
        # the policy would otherwise allow (the floor overrides allow
        # only — deny still denies, require_approval already queues;
        # the override appends the reserved "trifecta-tier-floor"
        # sentinel to matched_rules). This is a deployment decision:
        # enabling it means every allowlisted external call in a
        # trifecta session (notably api_call for the coder/researcher/
        # scout roles) needs a human — the guarantee is real, and so
        # is the friction.
        self._trifecta_floor = trifecta_floor
        # Sessions that have tripped the elevated trifecta tier this
        # run, so the loud escalation record is chained once per
        # session, not once per call.
        self._trifecta_escalated_sessions = set()
        self._identity_token_refs = None
        if delegation_context is not None:
            try:
                self._identity_token_refs = (
                    _delegation_tokens.hop_token_refs(
                        delegation_context.user_token,
                        delegation_context.agent_token,
                        delegation_context.delegation_token))
            except Exception:
                # Ref stamping is observability, not authority: the
                # delegation GATE above already refused bad contexts.
                # Never let stamping break the verdict path.
                self._identity_token_refs = None
        # Wave-51 P1 egress canaries: the run's canary registry (server-side,
        # outside the jail). Default None = tripwire off, zero behavior
        # change. When set, check_and_trip runs on the egress-attempt path
        # inside call() and halts fail-closed on a hit.
        self.canary_registry = canary_registry
        # Wave-51 P1: persistent run-halt flag. Once a canary trips, the
        # run stays halted server-side: every later call() raises
        # CanaryTripHalt immediately, so catching the exception and
        # retrying cannot resume the run.
        self._canary_halted = False
        # Wave-52 RT19: the halt also survives executor restarts. A
        # trip writes a server-side marker file into the run dir
        # (never the jail); a fresh executor constructed over the same
        # run dir starts halted. Best-effort: the hash-chained
        # canary_trip audit event remains the durable record, and the
        # in-memory flag remains the fast path. A trip is terminal by
        # design — no resume API exists — so no legitimate flow is
        # affected.
        self._canary_halt_marker = self.run_dir / ".canary_halted"
        try:
            if self._canary_halt_marker.exists():
                self._canary_halted = True
        except OSError:
            pass
        # Wave-66 D5: per-run cumulative ack-drain budget. The counter
        # lives on the RUN — in memory here plus a server-side marker
        # file in the run dir (never the jail), so it survives sink
        # replacement (the counter is not on the sink), executor
        # re-creation over the same run dir (marker re-read), and
        # window close/reopen (keyed to run_id, orthogonal to
        # windows). drain_ack_sink is the choke point into the hash
        # chain: every ack record it chains increments the counter;
        # exhaustion refuses LOUD (AckCumulativeBudgetExceeded).
        # Best-effort I/O like the canary marker; the hash-chained
        # control event remains the durable refusal record.
        self._ack_cumulative_marker = self.run_dir / ".ack_cumulative"
        (self._ack_cumulative_used,
         self._ack_budget_hit_audited) = self._read_ack_cumulative()
        # Wave-53 P1 (sterile cockpit): per-run critical-window
        # controller. Opt-in — the policy's ``critical_windows:``
        # block (validated fail-closed at policy load) builds it;
        # absent/None leaves self.sterile None and behavior is
        # byte-identical to wave-52 (pinned by test). The controller's
        # audit events are drained into the run log by _drain_sterile.
        from .sterile import (  # noqa: E402  (local: no import cycle)
            SterileController, WindowPolicy, TOOL_CHANNELS)
        self._sterile_tool_channels = TOOL_CHANNELS
        self._sterile_events = []
        self._sterile_loop = None
        self._sterile_loop_absent_audited = False
        self._sterile_refusals = {}    # window_id -> refusals this run
        self._sterile_enters = {}      # window_id -> enter count
        self._sterile_alerted = set()  # (window_id, enter_count) alerted
        # Wave-53 P1 fix (paper-review round 2): per-window loop-held
        # channels. window_id -> [channels the loop was asked to
        # withhold on entry]. Release on close/expiry touches only
        # channels no other open window still needs (union
        # semantics); a channel already withheld by an outer window
        # is not re-withheld on inner entry.
        self._sterile_withheld = {}
        _cw = getattr(policy, "critical_windows", None)
        self.sterile = (SterileController(WindowPolicy(_cw or []),
                                          audit=self._sterile_events)
                        if _cw else None)
        # First log seq of this run: the lower bound of the sterile
        # entry snapshot_ref range (integration §1.1).
        self._sterile_run_first_seq = (
            int(log.tail_seq) + 1 if self.sterile is not None else None)
        # F111 (wave-34): the run's credential manifest (GTG-50020
        # class). The harness declares every credential it provisions
        # into the agent's reachable scope; the executor identity-binds
        # egress credentials against it. Default: an empty manifest
        # (nothing provisioned, nothing bound).
        from .credential_manifest import CredentialManifest
        self._credential_manifest = (
            credential_manifest if credential_manifest is not None
            else CredentialManifest())
        # F48 (R11): policy pin/load audit. The policy this executor
        # will enforce is pinned at construction: ALWAYS audit
        # ``policy_loaded`` with the normalized source path and the
        # content hash. When the GOV_POLICY_HASH pin is set, the loaded
        # hash MUST match it — on mismatch, audit
        # ``policy_pin_mismatch`` and REFUSE construction fail-closed
        # (PolicyPinMismatchError), before any tool can execute. A
        # swapped policy file can therefore never silently govern a
        # run. Without a pin, an explicit ``policy_pin_absent`` warning
        # is audited — the deployment is knowingly running unpinned.
        _policy_path = getattr(policy, "yaml_path", None)
        try:
            _policy_norm = (str(Path(_policy_path).resolve())
                            if _policy_path else "<unknown>")
        except OSError:
            _policy_norm = str(_policy_path)
        _policy_hash = getattr(policy, "policy_hash", None) or "<unknown>"
        _pin = os.environ.get("GOV_POLICY_HASH")
        self.log.append({
            "event": "policy_loaded",
            "run_id": self.run_id,
            "agent_id": "system",
            "role": "system",
            "decision": "policy_loaded",
            "policy_id": "policy-pin",
            "policy_path": _policy_norm,
            "policy_hash": _policy_hash,
            "pinned": bool(_pin),
            "reason": ("Policy loaded for run %s: %s (sha256 %s)%s."
                       % (self.run_id, _policy_norm, _policy_hash,
                          " — hash pin GOV_POLICY_HASH is set"
                          if _pin else " — NO hash pin set")),
        })
        if _pin:
            if _policy_hash != _pin:
                self.log.append({
                    "event": "policy_pin_mismatch",
                    "run_id": self.run_id,
                    "agent_id": "system",
                    "role": "system",
                    "decision": "refused",
                    "policy_id": "policy-pin",
                    "policy_path": _policy_norm,
                    "policy_hash": _policy_hash,
                    "expected_hash": _pin,
                    "reason": ("Policy pin mismatch: loaded policy "
                               "%s has sha256 %s but GOV_POLICY_HASH "
                               "pins %s — refusing executor "
                               "construction fail-closed." %
                               (_policy_norm, _policy_hash, _pin)),
                })
                raise PolicyPinMismatchError(
                    "policy pin mismatch: loaded policy %s (sha256 %s) "
                    "does not match GOV_POLICY_HASH pin %s; executor "
                    "construction refused" % (_policy_norm, _policy_hash,
                                              _pin))
        else:
            self.log.append({
                "event": "policy_pin_absent",
                "run_id": self.run_id,
                "agent_id": "system",
                "role": "system",
                "decision": "warning",
                "policy_id": "policy-pin",
                "policy_path": _policy_norm,
                "policy_hash": _policy_hash,
                "reason": ("WARNING: GOV_POLICY_HASH is not set — the "
                           "policy governing this run (%s, sha256 %s) "
                           "is NOT pinned. A swapped policy file would "
                           "govern silently. Set GOV_POLICY_HASH in "
                           "production deployments." %
                           (_policy_norm, _policy_hash)),
            })
        self.sandbox = self.run_dir / "sandbox"
        self.quarantine = self.run_dir / "quarantine"
        self.sandbox.mkdir(parents=True, exist_ok=True)
        self._sandbox_resolved = self.sandbox.resolve()
        # F10: per-principal egress ledger for cross-run campaign
        # detection. Default lives NEXT TO the runs directory (shared by
        # all runs of a deployment); pass an explicit path to isolate
        # (tests) or relocate it.
        if ledger_path is None:
            ledger_path = self.run_dir.parent / "egress_ledger.jsonl"
        self._ledger = EgressLedger(ledger_path)
        # F17b: deployment-controlled principal registry. None =
        # permissive demo mode (any principal string mints); a registry
        # instance requires pre-registration. The permissive default is
        # an explicit deployment-trust residual (see gov/identity.py).
        self._principal_registry = principal_registry
        self._mint_count = 0  # F17b: per-run identity issuance budget
        # F18: policy campaign allowlist (normalized by PolicyEngine).
        self._campaign_allowlist = tuple(
            getattr(policy, "campaign_allowlist", None) or ())
        # F21: push the policy's batch-exclusion list into the approval
        # queue (the queue is constructed before the executor, so the
        # executor installs the policy-derived controls here).
        self._batch_excluded = tuple(
            getattr(policy, "batch_excluded_queue_reasons", None) or ())
        if hasattr(approvals, "set_batch_excluded_reasons"):
            approvals.set_batch_excluded_reasons(self._batch_excluded)
        # P10 (wave-26): governed AUTHORITY delegation — agent→agent
        # grants of tool-call authority via DelegationStore
        # (gov/approvals.py). This is a DIFFERENT primitive from
        # D1-core "approval delegation" (human reassignment of approval
        # stewardship) — the A12 terminology guard applies: docs, code,
        # and audit events keep the two distinct. The executor owns one
        # store per run (same run_dir/log discipline as the approval
        # queue) and installs the live-policy probes the store's
        # mint-time no-amplification check needs, plus the
        # executor-minted identity verifier (F26 pattern, write-once).
        # The store is always constructed but inert while the
        # authority-delegation policy section is disabled (spec §7
        # non-goal: no behavior change while disabled).
        self._delegation_store = DelegationStore(
            self.run_dir, self.log,
            config=dict(getattr(self.policy, "authority_delegation",
                                None) or {}),
            principal_registry=self._principal_registry)
        self._delegation_store.set_identity_verifier(
            self._verify_approval_identity)
        self._delegation_store.set_policy_probes(
            self.policy.role_allows, self._delegation_effect_probe)
        # S3 (K-041): tool reversibility/impact ratings. The deployment
        # dict overrides the core-tool defaults per field (see
        # gov/tool_ratings.py); a malformed rating fails construction.
        # A mutating tool with no rating at all is forced to
        # require_approval in call() (never allowed silently).
        self._tool_ratings = normalize_tool_ratings(tool_ratings)
        # F26: the approval queue's break-glass/review paths bind to
        # executor-minted identities; install the mint verifier so the
        # queue authenticates them against this executor's mint set (the
        # queue is constructed before the executor, same pattern as the
        # batch-exclusion list above).
        # F31: the verifier slot is write-once. A second executor sharing
        # this queue (e.g. the sit32 policy-pinning probe) keeps the
        # already-installed verifier instead of replacing it — replacement
        # is refused, so a hostile re-install cannot swap the binding.
        if hasattr(approvals, "set_identity_verifier"):
            try:
                approvals.set_identity_verifier(
                    self._verify_approval_identity)
            except IdentityVerifierAlreadySetError:
                pass
        # F49 (R11): seal the human-provisioned break-glass ticket set
        # at run start (write-once). A second executor sharing this
        # queue keeps the first snapshot — the agent cannot re-open
        # the provisioning window by constructing a fresh executor.
        # Guarded by hasattr: the snapshot exists from R11 on.
        if hasattr(approvals, "snapshot_break_glass_tickets"):
            approvals.snapshot_break_glass_tickets()
        # F22: policy-configurable audit-log size guard (fail-closed).
        log_limits = getattr(policy, "log_limits", None) or {}
        if log_limits.get("max_log_bytes") is not None:
            log.configure_guard(log_limits["max_log_bytes"])
        self.api_calls = 0  # external api_call executions this run
        self.counters = {}  # attempted calls per tool this run
        self._executed = {}  # F33: EXECUTED calls per tool this run —
        # the budget basis for send counts and egress bytes. Incremented
        # exactly once per execution (allow path or execute_approved), so
        # approved-then-executed sends are counted once, not twice.
        self._egress_bytes = 0  # F33: cumulative executed egress bytes
        # this run (actual payload UTF-8 bytes, DLP-independent).
        # S2 (K-018): hard budget accrual. Tokens/spend accrue on the
        # RESULT path only (_ingest_result / ingest_foreign_result via
        # result["_usage"] — never call kwargs, so an agent cannot forge
        # its own usage); _budget_actions counts call() invocations that
        # reach the budget guard.
        self._tokens_used = 0
        self._spend_used = 0.0
        self._budget_actions = 0
        # S4 (K-045): total-step budget. Counts every call() attempt
        # after the F17 ledger gate (denied/queued attempts included —
        # it is a budget on run activity and log growth). Ledger-refused
        # calls never reach here, so they consume no budget.
        self._total_calls = 0
        self._repeats = {}  # (tool, canonical args) -> count
        self._minted = set()  # (agent_id, role, run_id, principal) tuples
        # F55 (R13): the deployment-provisioned session identity. When
        # the deployment passes session_identity=(agent_id, role,
        # principal), the executor creates exactly ONE provisioned
        # identity at construction (provenance="provisioned") and
        # installs it write-once on the approval queue:
        # ApprovalQueue.break_glass() then requires exactly this
        # identity, and mid-run mints of the same tuple (provenance=
        # "minted") are refused — closing the F55 operator-minting
        # impersonation. The provisioned identity does NOT consume
        # mint budget (it is deployment config, not agent issuance).
        # Without it, the pre-R13 F26 behavior is kept (dev mode).
        self._session_identity = None
        # Wave-40 (F115): one-time flag for the loud warning when the
        # credential manifest is non-empty but no session identity was
        # provisioned (identity-bound egress silently unenforced).
        self._credential_binding_unenforced_warned = False
        if session_identity is not None:
            self._session_identity = self._provision_session_identity(
                session_identity)
            if hasattr(approvals, "set_session_identity"):
                try:
                    approvals.set_session_identity(self._session_identity)
                except SessionIdentityAlreadySetError:
                    # F31 pattern: a second executor sharing this queue
                    # keeps the first session identity — the agent
                    # cannot swap the entitlement anchor by constructing
                    # a fresh executor.
                    pass
        # F64 (R14): registry mode WITHOUT a session identity is a
        # silent weak mode for break-glass (the F55 residual with no
        # entitlement checks at all). Tell the queue a registry is
        # configured so break_glass warns loudly (stderr + audited
        # break_glass_unprotected entry) instead of staying silent.
        if principal_registry is not None and hasattr(
                approvals, "note_registry_configured"):
            approvals.note_registry_configured()
        # F51 (R12): lock-refusal audit coalescing — a sustained lock
        # disturbance (e.g. an unlink loop) refuses every sweep; the
        # refusals are fail-closed but the audit entries are
        # rate-limited so the attack cannot flood the tamper-evident
        # log. _lock_refusal_suppressed counts repeats folded into the
        # next audited entry.
        self._lock_refusal_last_audit = 0.0
        self._lock_refusal_suppressed = 0
        # R17: side channel for _log_shows_recent_lock_refusal --
        # when its fallback full chain verification finds the chain
        # BROKEN, the error string lands here (else None) so the
        # caller can audit the tamper loudly with attribution
        # instead of folding it into the normal refusal audit.
        self._r17_tip_forced_error = None
        self._tainted = False  # True once tool output entered this run
        self._taint_sources = []
        self._read_contents = []  # fingerprints of executed read results
        self._read_sensitive = False  # F9: a read returned DLP-sensitive
        # content this run; api_call afterwards is taint-gated.

    # -- identity ---------------------------------------------------------

    def _provision_session_identity(self, spec):
        """F55 (R13): create the ONE deployment-provisioned session identity.

        ``spec`` is an (agent_id, role, principal) tuple from deployment
        configuration — never from agent input. The identity is created
        with ``provenance="provisioned"`` and its tuple is added to the
        minted set (so the F26 verifier and ``call()`` honor it). When
        a principal registry is configured, the tuple must ALSO satisfy
        the registry — a misconfigured session identity fails closed
        here, at construction, before any tool can execute.
        """
        try:
            agent_id, role, principal = spec
        except (TypeError, ValueError):
            raise ValueError(
                "session_identity must be an (agent_id, role, principal) "
                "tuple, got %r" % (spec,))
        for name, value in (("agent_id", agent_id), ("role", role),
                            ("principal", principal)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    "session_identity %s must be a non-empty string, "
                    "got %r" % (name, value))
        if self._principal_registry is not None:
            try:
                self._principal_registry.check_identity(
                    principal, role, agent_id)
            except UnregisteredPrincipalError as e:
                self.log.append({
                    "event": "identity_session_refused",
                    "run_id": self.run_id,
                    "agent_id": agent_id,
                    "role": role,
                    "principal": principal,
                    "decision": "refused",
                    "policy_id": "principal-registry",
                    "reason": ("session_identity refused at construction: "
                               "%s" % e),
                })
                raise
        ident = AgentIdentity(agent_id=agent_id, role=role,
                              run_id=self.run_id, principal=principal,
                              provenance="provisioned")
        self._minted.add((ident.agent_id, ident.role,
                          ident.run_id, ident.principal))
        self.log.append({
            "event": "identity_session_provisioned",
            "run_id": self.run_id,
            "agent_id": agent_id,
            "role": role,
            "principal": principal,
            "decision": "identity_issued",
            "policy_id": "principal-registry",
            "reason": ("Deployment-provisioned session identity "
                       "established for run %s (provenance=provisioned); "
                       "break-glass entitlement is bound to it." %
                       self.run_id),
        })
        return ident

    def mint_identity(self, agent_id, role, principal):
        """Issue the only kind of identity this executor will honor.

        F17b: issuance is rate-limited (per-run cap,
        ``_MAX_IDENTITY_MINTS_PER_RUN``) and — when a principal registry
        is configured — the principal must be pre-registered, otherwise
        ``UnregisteredPrincipalError``. Registry-mode issuance is
        audit-logged (``identity_minted``).

        F50 (R12): the registry is a real trust anchor — in registry
        mode the full (principal, role, agent_id) tuple is checked
        against the registry's per-principal authorization, and any
        pair the registry does not authorize is REFUSED with an
        audited ``identity_mint_refused`` entry (the refusal never
        consumes mint budget). With no registry (permissive demo
        default) any principal/role/agent_id string still mints — an
        explicit deployment-trust residual, now disclosed by a loud
        one-time stderr warning that identity is self-asserted.
        """
        if self._mint_count >= _MAX_IDENTITY_MINTS_PER_RUN:
            raise IdentityMintLimitError(
                "identity mint budget exhausted for run %s (%d)" %
                (self.run_id, _MAX_IDENTITY_MINTS_PER_RUN))
        if self._principal_registry is not None:
            try:
                self._principal_registry.check_identity(
                    principal, role, agent_id)
            except UnregisteredPrincipalError as e:
                # F50: audited refusal — a refused mint never consumes
                # budget and never issues.
                self.log.append({
                    "event": "identity_mint_refused",
                    "run_id": self.run_id,
                    "agent_id": agent_id,
                    "role": role,
                    "principal": principal,
                    "decision": "refused",
                    "policy_id": "principal-registry",
                    "reason": ("identity_mint refused: %s" % e),
                })
                raise
        else:
            # F50: dev mode keeps self-assertion working, but says so
            # loudly, once per process (same disclosure pattern as the
            # dev-key warnings).
            warn_self_asserted_identity_once()
        self._mint_count += 1
        ident = AgentIdentity(agent_id=agent_id, role=role,
                              run_id=self.run_id, principal=principal,
                              provenance="minted")
        self._minted.add((ident.agent_id, ident.role,
                          ident.run_id, ident.principal))
        if self._principal_registry is not None:
            self.log.append({
                "event": "identity_minted",
                "run_id": self.run_id,
                "agent_id": agent_id,
                "role": role,
                "principal": principal,
                "decision": "identity_issued",
                "policy_id": "principal-registry",
                "reason": ("Principal %r is registered; identity issued "
                           "and logged." % principal),
            })
        return ident

    def _check_identity(self, identity):
        """Return None if OK, else a (policy_id, flag, reason) deny triple."""
        if identity.run_id != self.run_id:
            return ("identity-run-mismatch", "identity_rejected",
                    "Identity run_id %r does not match this run %r."
                    % (identity.run_id, self.run_id))
        if (identity.agent_id, identity.role,
                identity.run_id, identity.principal) not in self._minted:
            raise UnmintedIdentityError(
                "Identity %r was not minted by this executor." % (identity,))
        return None

    def _verify_approval_identity(self, identity):
        """F26: authenticate an identity for the approval queue's
        break-glass/review paths. Raises ``UnmintedIdentityError`` unless
        this executor minted it for this run — so a ticket can only bind
        to, and a review can only be resolved by, executor-authenticated
        identities, never hand-built ``AgentIdentity`` objects or
        caller-supplied strings (rejected earlier by the queue's
        ``TypeError`` check)."""
        if (identity.run_id != self.run_id or
                (identity.agent_id, identity.role, identity.run_id,
                 identity.principal) not in self._minted):
            raise UnmintedIdentityError(
                "Identity %r was not minted by this executor for run %r."
                % (identity, self.run_id))
        return True

    def _delegation_effect_probe(self, role, tool):
        """P10: bare-tool policy effect probe for the delegation store's
        mint-time no-amplification check. Mirrors how call() evaluates a
        plain tool invocation, so require_approval flags propagate into
        the grant scope (delegation never bypasses the approval queue).
        Returns the policy effect: "allow" | "require_approval" | "deny".

        The probe assumes the most permissive call-shaped context
        (domain_allowlisted=True): the mint check asks whether the
        delegator could invoke the tool AT ALL under the policy, not
        whether a bare arg-less call would be denied. Conditional,
        arg-dependent denies (the egress domain allowlist) must not
        refuse the mint — the grant covers the tool, and every actual
        invocation is still evaluated with its real args, so no
        authority is amplified. (F94: deny-egress-unallowlisted now
        covers api_call; probing without domain_allowlisted would read
        the fail-closed default as an unconditional deny and wrongly
        refuse grants for a tool the delegator legitimately holds.)
        """
        decision = self.policy.evaluate(
            {"tool": tool, "role": role, "agent_id": "delegation-probe",
             "args": {}},
            {"role": role, "agent": "delegation-probe",
             "domain_allowlisted": True})
        return decision.effect

    def _delegation_store_error(self, _base, identity, tool, exc):
        """P10: fail-closed denial when the delegation store raises an
        unexpected error (anything that is not a DelegationError
        refusal, which carries its own audited reason). The error is
        audited loudly as its own event, then the call is denied: an
        unverifiable delegation state must never read as "no
        delegation claim", and must never crash the call path into an
        unlogged state."""
        self.log.append({
            "event": "delegation_store_error",
            "run_id": identity.run_id,
            "agent_id": identity.agent_id,
            "role": identity.role,
            "principal": identity.principal,
            "tool": tool,
            "decision": "denied",
            "policy_id": "delegation-store-error",
            "flag": "delegation_store_error",
            "reason": ("Delegation store error (%s: %s): refusing the "
                       "call fail-closed rather than executing with "
                       "unverifiable delegation state."
                       % (type(exc).__name__, exc)),
        })
        entry = self.log.append(_base({
            "decision": "denied",
            "policy_id": "delegation-store-error",
            "flag": "delegation_store_error",
            "reason": ("Delegation store error: call refused fail-closed "
                       "(see the delegation_store_error event)."),
        }))
        return {"status": "denied", "reason": entry["reason"],
                "policy_id": "delegation-store-error",
                "seq": entry["seq"]}

    # -- path handling ----------------------------------------------------

    def _resolve(self, path):
        p = Path(path)
        if not p.is_absolute():
            p = self.sandbox / p
        return p

    def _is_outside_sandbox(self, path):
        p = self._resolve(path)
        try:
            rp = p.resolve()
        except OSError:
            rp = Path(os.path.abspath(str(p)))
        return rp != self._sandbox_resolved and self._sandbox_resolved not in rp.parents

    # -- provenance / egress ----------------------------------------------

    def _ingest_result(self, tool, result, principal=None):
        if tool in ("read_file", "api_call"):
            content = result.get("content")
            if content:
                self._read_contents.append(content[:65536])
                total = sum(len(c) for c in self._read_contents)
                while total > _MAX_READ_STORE and self._read_contents:
                    total -= len(self._read_contents.pop(0))
                if self._content_is_sensitive(content):
                    # F9/F15a: taint, not similarity. Content tripping DLP
                    # sensitive patterns (credential regexes or PII) marks
                    # the run: a later api_call is approval-gated even when
                    # the payload shares no verbatim text with the ingested
                    # content (paraphrase/summary exfil). F15a extends the
                    # F9 read_file-only check to ANY ingested content —
                    # the product models api_call as a simulated external
                    # API read, so a sensitive api_call RESULT taints the
                    # run exactly like a sensitive file read. DLP-clean
                    # content does NOT taint.
                    self._read_sensitive = True
                    # F15b: persist principal-scoped, so a confederate's
                    # FRESH run for the same principal inherits the taint
                    # inside the TTL (24h). Different principals stay
                    # isolated. Fail-open: ledger trouble never blocks
                    # the call path.
                    if principal:
                        try:
                            self._ledger.taint_mark(principal, self.run_id)
                        except Exception:
                            pass
            self._tainted = True
            if tool not in self._taint_sources:
                self._taint_sources.append(tool)

    def ingest_foreign_result(self, tool, result, principal=None):
        """F37: ingest a FOREIGN tool result into the provenance/taint store.

        Adapters that execute a real implementation AFTER authorization
        (MCP server results, the generic adapter's ``run_body=True``
        real bodies) must route the REAL result through the same
        ingestion as the executor's own results:
        ``ToolExecutor.call()`` only ingests its SIMULATED result, so
        without this a sensitive server response never taints the run
        and a follow-up paraphrase api_call escapes the
        sensitive-read-before-api approval gate. The result itself is
        NOT modified — ingestion is a side channel into the run's taint
        store. F40 (R10): normalization is TOTAL and recursive —
        nested blocks, arbitrary sequences, and defensive per-property
        probing mean one hostile block cannot discard benign siblings.
        A result with opaque/unparseable parts is conservatively
        treated as sensitive (the taint bit gates a later api_call;
        nothing is fabricated into the read store). ``result=None``
        stays a clean no-op. Fail-open: ingestion trouble never breaks
        the result path (the call already executed; the signal is
        heuristic, like the native path's ledger taint-mark).
        """
        try:
            blob, opaque = self._foreign_normalize(result)
        except Exception:
            return
        if blob:
            try:
                self._ingest_result(tool, {"content": blob}, principal)
            except Exception:
                pass
        if opaque:
            # F40: some part of the result was opaque to the text scan
            # (hostile property, reference cycle, over-deep nesting, a
            # non-text leaf such as bytes, or content missed by a
            # bound). DLP had no text to clear, so conservatively mark
            # the result sensitive AND tainted: a later api_call is
            # approval-gated (read_sensitive) even when the opaque bytes
            # carried nothing, and the run carries source_untrusted
            # provenance. Nothing is fabricated — no text is added to
            # the read store, only the taint bits gate.
            try:
                self._read_sensitive = True
                self._tainted = True
                if tool not in self._taint_sources:
                    self._taint_sources.append(tool)
                if principal:
                    self._ledger.taint_mark(principal, self.run_id)
            except Exception:
                pass

    # F40 (R10): bounds for the total foreign-result normalizer.
    _FOREIGN_BLOB_MAX = 65536  # same cap as the native read path
    _FOREIGN_WALK_MAX_DEPTH = 6  # nesting depth before a node counts opaque
    _FOREIGN_WALK_MAX_FRAGS = 4096  # text fragments before truncating
    _FOREIGN_WALK_MAX_ITEMS = 4096  # container items walked before truncating

    @staticmethod
    def _is_foreign_sequence(node):
        return (isinstance(node, collections.abc.Sequence)
                and not isinstance(node, (str, bytes, bytearray)))

    @classmethod
    def _foreign_normalize(cls, result):
        """F40: TOTAL recursive normalization of a foreign result.

        Returns ``(blob, opaque)``: ``blob`` is the extracted text
        (capped at 64K) or None when nothing textual is present;
        ``opaque`` is True when some part of the result could not be
        textually interpreted (a hostile property, a reference cycle,
        over-deep nesting, a non-text leaf such as bytes, or content
        missed by a bound).

        Total: never raises on arbitrary shapes. Each block and each
        property is probed in its own try/except, so one hostile block
        cannot discard benign siblings. Dicts, ``Mapping``s, and
        arbitrary ``collections.abc.Sequence`` instances (not just
        list/tuple) are traversed — mappings over VALUES ONLY (keys
        are schema labels, not foreign text: ``{"content": None}``
        stays clean); objects are probed for text-bearing attributes
        (content/text/data/resource/body/value/payload/output/result),
        recursing into NESTED blocks — an image block's ``.data``, a
        resource wrapper's text, a dict inside a block's ``content``
        list. Depth, fragment count, per-container item count, and
        reference cycles are bounded; containers are consumed with
        bounded iterators (never an eager ``list()``), and string
        memory is capped WHILE collecting (not only after the join) —
        truncation of any kind marks the result opaque. ``result=None``
        stays a clean ``(None, False)`` boundary; benign strings and
        clean dicts extract text that DLP clears exactly like the
        native path.
        """
        frags = []
        opaque = False
        seen = set()
        blob_len = 0
        _MISS = object()  # sentinel: iterator still had items after the cap

        def emit(text):
            nonlocal opaque, blob_len
            if not isinstance(text, str) or not text:
                return
            # Bound memory WHILE collecting: never hold more than the
            # blob cap (text plus one "\n" separator per fragment, as
            # the final join adds). Truncation means foreign text was
            # missed -> conservative opaque.
            if frags:
                blob_len += 1
            if blob_len >= cls._FOREIGN_BLOB_MAX:
                opaque = True
                return
            chunk = text[:cls._FOREIGN_BLOB_MAX - blob_len]
            frags.append(chunk)
            blob_len += len(chunk)
            if len(chunk) < len(text):
                opaque = True

        def walk(node, depth):
            nonlocal opaque
            if node is None or isinstance(node, (bool, int, float)):
                return
            if isinstance(node, str):
                emit(node)
                return
            if isinstance(node, (bytes, bytearray)):
                # Non-text leaf: unparseable by the DLP text scan.
                opaque = True
                return
            if depth > cls._FOREIGN_WALK_MAX_DEPTH:
                opaque = True
                return
            if len(frags) >= cls._FOREIGN_WALK_MAX_FRAGS:
                opaque = True
                return
            nid = id(node)
            if nid in seen:  # reference cycle: not textually meaningful
                opaque = True
                return
            seen.add(nid)
            try:
                if isinstance(node, collections.abc.Mapping):
                    # VALUES ONLY — see docstring.
                    try:
                        it = iter(node.items())
                    except Exception:
                        opaque = True
                        return
                    for pair in itertools.islice(
                            it, cls._FOREIGN_WALK_MAX_ITEMS):
                        try:
                            _key, value = pair
                        except Exception:
                            opaque = True
                            continue
                        walk(value, depth + 1)
                    try:
                        if next(it, _MISS) is not _MISS:
                            opaque = True  # items missed: truncated
                    except Exception:
                        opaque = True
                    return
                if cls._is_foreign_sequence(node):
                    try:
                        it = iter(node)
                    except Exception:
                        opaque = True
                        return
                    for item in itertools.islice(
                            it, cls._FOREIGN_WALK_MAX_ITEMS):
                        walk(item, depth + 1)
                    try:
                        if next(it, _MISS) is not _MISS:
                            opaque = True  # items missed: truncated
                    except Exception:
                        opaque = True
                    return
                # Object: probe each text-bearing attribute in its own
                # try/except so one hostile property cannot poison the
                # pass; recurse into whatever they return (nested
                # blocks, resource wrappers, image .data, ...).
                got_text_attr = False
                for attr in ("content", "text", "data", "resource",
                             "body", "value", "payload", "output",
                             "result"):
                    try:
                        val = getattr(node, attr, None)
                    except Exception:
                        opaque = True
                        continue
                    if val is not None and val is not node:
                        got_text_attr = True
                        walk(val, depth + 1)
                if not got_text_attr:
                    # No text-bearing attribute at all: the object is
                    # opaque to the text scan.
                    opaque = True
            finally:
                seen.discard(nid)

        try:
            walk(result, 0)
        except Exception:
            # Belt and suspenders: walk() is already total, but the
            # normalizer must never raise into the ingestion path.
            opaque = True
        blob = "\n".join(frags) or None
        return blob, opaque

    @staticmethod
    def _content_is_sensitive(content):
        """True when read content trips DLP sensitive patterns."""
        if dlp.find_credential(content):
            return True
        _redacted, hits = dlp.scrub_pii(content)
        return bool(hits)

    def _carries_read_content(self, tool, args):
        """True when an outbound-shaped payload carries verbatim excerpts of
        content this run previously read (threat T4/R4).

        Covers ``_SEND_TOOLS`` (send_email/http_post) with the original
        32-char window, and ``api_call`` (F1) with a 16-char window over
        ``params`` only: api_call is modeled as a READ tool, but its params
        are an outbound payload to a third-party endpoint, so customer data
        smuggled there must correlate exactly like a send. The ``endpoint``
        is routing (an audit field), not payload, and is excluded from the
        api_call search to avoid flagging destinations.
        """
        if tool == "api_call":
            window = _CORRELATION_WINDOW_API
            # params is the exfil vector; endpoint is routing, not payload.
            search_args = {k: v for k, v in (args or {}).items()
                           if k != "endpoint"}
        elif tool in _SEND_TOOLS:
            window = _CORRELATION_WINDOW_SEND
            search_args = args
        else:
            return False
        if not self._read_contents:
            return False
        # Search the RAW string values (not JSON: json.dumps escapes
        # newlines, which would break verbatim matching of multi-line
        # excerpts).
        parts = []

        def _collect(v):
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict):
                for x in v.values():
                    _collect(x)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    _collect(x)

        _collect(search_args)
        corpus = "\x00".join(parts)
        if len(corpus) < window:
            return False
        for c in self._read_contents:
            if len(c) < window:
                continue
            # Any <window>-char run of the outbound payload appearing
            # verbatim in previously read content counts, even if the agent
            # only exfiltrated an excerpt of a larger file.
            for i in range(len(corpus) - window + 1):
                if corpus[i:i + window] in c:
                    return True
        return False

    def _domain_allowlisted(self, tool, args):
        allow = (self.policy.egress or {}).get("domain_allowlist") or []
        host = None
        if tool == "http_post":
            try:
                host = (urlparse(args.get("url") or "").hostname or "").lower()
            except Exception:
                host = None
        elif tool == "send_email":
            to = args.get("to") or ""
            host = to.rsplit("@", 1)[-1].lower() if "@" in to else None
        elif tool == "api_call":
            # F94: api_call is egress-scoped like the other outbound
            # tools — its destination comes from the ``endpoint`` arg.
            try:
                host = (urlparse(args.get("endpoint") or "").hostname
                        or "").lower()
            except Exception:
                host = None
        if not host:
            return False
        return any(host == d.lower() or host.endswith("." + d.lower())
                   for d in allow)

    def _credential_identity_mismatch(self, args):
        """F111 (wave-34): is a credential on this egress call bound to
        the provisioned session identity?

        Returns True on mismatch (= the ``credential_identity_mismatch``
        policy signal; the policy rule denies + audits). Delegates to
        the run's CredentialManifest; without a provisioned session
        identity there is nothing to bind to (False, documented).

        Wave-40 (F115): "nothing to bind to" used to be SILENT even
        when the manifest held declared credentials -- the deployment
        believed it had identity-bound egress and did not (F64
        precedent: silent weak modes warn loudly). Now a manifest with
        declared credentials and no session identity emits a one-time
        loud warning (stderr + audited ``credential_binding_unenforced``
        entry). Dev-mode runs with an EMPTY manifest stay quiet: there
        is nothing provisioned, so nothing is unenforced.
        """
        sess = self._session_identity
        if sess is None:
            if (len(self._credential_manifest) > 0
                    and not self._credential_binding_unenforced_warned):
                self._credential_binding_unenforced_warned = True
                warn_msg = (
                    "GOVERNANCE WARNING: the run's credential manifest "
                    "declares %d credential(s) but NO session identity "
                    "was provisioned -- identity-bound egress is "
                    "UNENFORCED (F115): credential_id references are not "
                    "bound to any principal and foreign-credential "
                    "references will not be denied. Provision "
                    "session_identity for production deployments; "
                    "manifest-without-session-identity is explicitly "
                    "unsupported." % len(self._credential_manifest))
                print(warn_msg, file=sys.stderr)
                try:
                    self.log.append({
                        "event": "credential_binding_unenforced",
                        "run_id": self.run_id,
                        "agent_id": "system",
                        "role": "governance",
                        "principal": "system",
                        "decision": "warn",
                        "policy_id": "credential-identity-binding",
                        "declared_credentials":
                            len(self._credential_manifest),
                        "reason": ("identity-bound egress evaluated with "
                                   "a non-empty credential manifest and "
                                   "no provisioned session identity "
                                   "(F115): the credential_identity_"
                                   "mismatch signal cannot bind; this "
                                   "configuration is explicitly "
                                   "unsupported for production."),
                    })
                except Exception:
                    pass  # the stderr warning is the control; log best-effort
            return False
        bound = self._credential_manifest.check_egress(
            args or {}, sess.principal)
        return not bound

    def _api_call_shape(self, args):
        """Summarize an api_call attempt for the egress ledger (F10).

        Records the outbound SHAPE (endpoint, param count, string bytes,
        max per-value entropy, fragment flag, timestamp) — never param
        values, so the ledger itself cannot become an exfil store.
        """
        params = args.get("params")
        if not isinstance(params, dict):
            params = {}
        strings = []

        def _collect(v):
            if isinstance(v, str):
                strings.append(v)
            elif isinstance(v, dict):
                for x in v.values():
                    _collect(x)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    _collect(x)

        _collect(params)
        total_bytes = sum(len(s) for s in strings)
        max_entropy = 0.0
        for s in strings:
            if s:
                max_entropy = max(max_entropy, dlp._shannon_entropy(s))
        fragment = (0 < total_bytes <= FRAGMENT_MAX_BYTES
                    and max_entropy >= FRAGMENT_MIN_ENTROPY)
        return {
            "endpoint": args.get("endpoint") or "",
            # F13: the campaign KEY normalizes to the registered domain;
            # the exact endpoint string stays for forensics.
            "campaign_domain": registered_domain(args.get("endpoint") or ""),
            "n_params": len(params),
            # F14: the structural signal keys on the param KEY SET.
            "param_keys": sorted({str(k) for k in params.keys()}),
            "str_bytes": total_bytes,
            "max_entropy": round(max_entropy, 3),
            "fragment": fragment,
        }

    def _api_call_high_entropy_payload(self, args):
        """F99/F106: True when the api_call carries an unknown-format
        high-entropy token the DLP cannot name — in any nested params
        string value (F99) or in the endpoint URL's query values /
        path segments (F106; the F94 allowlist matches hostname only,
        so the URL is a first-class exfil channel).

        Thin wrapper over ``dlp.api_call_high_entropy_payload`` (the
        single source of truth, shared with the simulator's replay
        recomputation). Param KEYS and query keys are not scanned (a
        key named like a token is not outbound content).
        """
        return dlp.api_call_high_entropy_payload(args or {})

    def _campaign_allowlisted(self, principal, campaign_domain, param_keys):
        """F18: True when (principal, domain, param key set) is allowlisted.

        The allowlist is policy, admin-controlled: all three components
        must match exactly (the key set as a set — order-insensitive).
        Exempted traffic is still ledgered; only the campaign QUEUE
        decision is suppressed, and the suppression itself is logged.
        """
        if not principal or not campaign_domain:
            return False
        wanted = tuple(sorted(set(param_keys or ())))
        for ap, ad, ak in self._campaign_allowlist:
            if ap == principal and ad == campaign_domain and ak == wanted:
                return True
        return False

    def _log_campaign_allowlisted(self, tool, principal, campaign_domain,
                                  param_keys):
        """F18: audit-log an allowlist exemption (never a silent bypass)."""
        self.log.append({
            "event": "campaign_allowlisted",
            "run_id": self.run_id,
            "principal": principal,
            "tool": tool,
            "campaign_domain": campaign_domain,
            "param_keys": sorted(set(param_keys or ())),
            "decision": "signal_suppressed",
            "policy_id": "campaign-allowlist",
            "flag": "campaign_allowlisted",
            "reason": ("Repetitive api_call traffic matches the policy "
                       "campaign allowlist (principal=%r, domain=%r); "
                       "exempt from campaign queueing. The attempt is still "
                       "recorded in the egress ledger for forensics."
                       % (principal, campaign_domain)),
        })

    def _check_cross_run_campaign(self, tool, args, principal, shape=None,
                                    agent_id=None):
        """F10/F13: heuristic cross-run campaign detection (fail-safe).

        Records this api_call attempt's shape in the per-principal egress
        ledger, then asks whether K small high-entropy-ish fragments to
        the SAME registered domain (F13: normalized, so subdomain
        rotation lands in one bucket) from the SAME principal across >=
        2 distinct runs fall inside the time window. True -> the policy
        rule queues (never denies). Any ledger failure fails OPEN
        (returns False): this is a heuristic signal, not an authorization
        control.

        F36a: the ledgered entry carries the minted identity's agent_id
        alongside the principal for forensic attribution — the campaign
        KEY stays the principal string because cross-run continuity is
        defined by the principal; stronger identity binding comes from
        the principal registry (F17b) in non-permissive deployments.
        """
        if tool != "api_call" or not principal:
            return False
        shape = shape if shape is not None else self._api_call_shape(args)
        try:
            self._ledger.append({
                "ts": datetime.now(timezone.utc).timestamp(),
                "run_id": self.run_id,
                "principal": principal,
                "agent_id": agent_id,
                "tool": "api_call",
                **shape,
            })
            if not shape["fragment"] or not shape["campaign_domain"]:
                return False
            hit = self._ledger.campaign_hit(
                principal, shape["endpoint"],
                window_secs=CAMPAIGN_WINDOW_SECS, k=CAMPAIGN_K)
            if hit and self._campaign_allowlisted(
                    principal, shape["campaign_domain"],
                    shape.get("param_keys")):
                # F18: benign allowlisted traffic (e.g. a health poller)
                # is exempt from queueing — still ledgered above, and the
                # exemption itself is audit-logged.
                self._log_campaign_allowlisted(
                    tool, principal, shape["campaign_domain"],
                    shape.get("param_keys"))
                return False
            return hit
        except Exception:
            return False

    def _check_cross_principal_campaign(self, tool, shape, principal):
        """F36: principal-rotation campaign signal (fail-safe, queue-only).

        The per-principal detectors never reach K when the attacker mints
        a fresh principal per run, so this correlates the campaign SHAPE
        across principals: >= K distinct principals emitting
        fragment-shaped api_call entries with the same content/shape
        sketch (see ``EgressLedger._shape_sketch`` — domain, param
        count, byte/entropy buckets, fragment flag; param-name-blind)
        inside the window -> True. The attempt was already ledgered by
        ``_check_cross_run_campaign``; this only scans. Never denies;
        ledger failures fail open.

        F41 (R10): throwaway-planted quorum — a bare distinct-principal
        count let an attacker plant two throwaway look-alikes and have
        the VICTIM's next same-shaped call be the Kth, queueing a benign
        call (a false-positive weapon). The quorum now ALSO requires at
        least K-1 ESTABLISHED principals; see
        ``EgressLedger.cross_principal_campaign_hit``.

        F46 (R11): establishment is multi-run continuity (>= 2 distinct
        run IDs) in permissive mode, registry-backed in registry mode
        (the deployment's principal registry is passed through, so
        registered principals count as established). Patient
        throwaways that emit across two runs each can still poison the
        quorum in permissive mode — the cost is raised (distinct runs
        over time) but behavioral history is not identity trust
        (documented residual).

        The F18 allowlist IS applied to the CURRENT attempt: when the
        exact (principal, domain, param key set) is allowlisted, the
        cross-principal queue is suppressed for that attempt (it is
        still ledgered, and the suppression is audit-logged) so
        existing allowlisted monitoring stays green.
        """
        if tool != "api_call" or not principal:
            return False
        if not (shape or {}).get("fragment"):
            return False
        try:
            hit = self._ledger.cross_principal_campaign_hit(
                shape or {},
                window_secs=CAMPAIGN_WINDOW_SECS, k=CAMPAIGN_K,
                # F46 (R11): registry-backed establishment in registry
                # mode; multi-run fallback in permissive mode (None).
                principal_registry=self._principal_registry)
            if hit and self._campaign_allowlisted(
                    principal, (shape or {}).get("campaign_domain"),
                    (shape or {}).get("param_keys")):
                # F18: the current attempt is allowlisted — suppress
                # the cross-principal queue (still ledgered above, and
                # the exemption itself is audit-logged).
                self._log_campaign_allowlisted(
                    tool, principal, (shape or {}).get("campaign_domain"),
                    (shape or {}).get("param_keys"))
                return False
            return hit
        except Exception:
            return False

    def _check_structural_campaign(self, tool, shape, principal):
        """F14: structural low-and-slow signal (fail-safe, queue-only).

        Same principal + same registered domain + same param KEY SET
        across >= K distinct runs inside the window -> True, regardless
        of payload size or entropy. The F10 fragment shape
        (<=64B, >=1.8 bits/char) is attacker-controlled on both axes —
        oversize padding and unary encoding both keep this structural
        signature. Thin-spread only (see
        ``EgressLedger.structural_campaign_hit``). Never denies; ledger
        failures fail open. The attempt was already ledgered by
        ``_check_cross_run_campaign``; this only scans.
        """
        if tool != "api_call" or not principal:
            return False
        try:
            hit = self._ledger.structural_campaign_hit(
                principal, shape.get("campaign_domain") or "",
                shape.get("param_keys") or [],
                window_secs=CAMPAIGN_WINDOW_SECS, k=CAMPAIGN_K)
            if hit and self._campaign_allowlisted(
                    principal, shape.get("campaign_domain") or "",
                    shape.get("param_keys") or []):
                # F18: allowlisted benign structure — exempt from
                # queueing, still ledgered, exemption audit-logged.
                self._log_campaign_allowlisted(
                    tool, principal, shape.get("campaign_domain") or "",
                    shape.get("param_keys") or [])
                return False
            return hit
        except Exception:
            return False

    def _principal_taint_active(self, principal):
        """F15b/F17: is this principal's sensitive-read taint still live?

        A fresh executor for a principal whose run ingested
        DLP-sensitive content inherits ``read_sensitive`` while the
        ledger mark is unexpired (24h TTL). F17: FAIL-CLOSED — ledger
        trouble (tamper, truncation, forgery) raises
        ``LedgerUnverifiableError`` instead of returning False; an
        unverifiable ledger must never read as "no taint".
        """
        if not principal:
            return False
        return self._ledger.taint_active(
            principal, ttl_secs=SENSITIVE_TAINT_TTL_SECS)

    # -- S5 (K-052): cross-run per-principal velocity -----------------------
    # A per-run guard cannot see a low-and-slow campaign spread over many
    # runs: each run stays under its own send/write/egress budgets. The
    # velocity guard keeps cross-run memory in the egress ledger
    # (``kind: "velocity"`` entries, one per execution of a velocity
    # tool) and queues — never denies — when a principal's accrued
    # volume inside the window reaches a configured threshold.
    #
    # F74 REBASE — LOCK DISCIPLINE: these helpers reuse the ledger's own
    # ``_ledger_read_locked`` / ``_ledger_write_locked`` primitives and
    # add NO competing lock. The query holds the shared read lock across
    # verify+scan (mirroring ``EgressLedger.fragments`` — reentrancy
    # makes the nested ``require_verified()`` safe); the record path
    # goes through ``EgressLedger.append``, which holds the write lock
    # across its whole read-modify-write internally. A second lock
    # around the same bytes would reintroduce the F74 fork.

    def _query_velocity(self, principal):
        """True when the principal's velocity thresholds are reached.

        Sums ``kind: "velocity"`` entries for ``principal`` inside the
        configured window. Fail-OPEN with a loud ``velocity_check_skipped``
        audit entry on ANY ledger trouble (lock timeout, unverifiable
        ledger, I/O error): the velocity signal is heuristic — a ledger
        outage must never deny legitimate calls, but it must never be
        silent either. Returns False (not exceeded) when the ``velocity:``
        policy section is absent (unenforced, never zero) or no ledger
        history exists yet.
        """
        velocity = getattr(self.policy, "velocity", None) or {}
        if not velocity or not principal:
            return False
        ledger = self._ledger
        if ledger is None:
            return False
        try:
            if not ledger.path.exists():
                return False  # no history yet: nothing to trip on
            # Reuse the ledger's read lock — no competing lock (F74).
            with _ledger_read_locked(ledger.path):
                # Reentrant under the read hold, exactly like
                # fragments(): the scan cannot tear against a
                # concurrent append.
                ledger.require_verified()
                now = time.time()
                window = float(velocity.get("window_secs",
                                           24.0 * 3600.0))
                sends = 0
                writes = 0
                egress = 0.0
                text = ledger.path.read_text(encoding="utf-8")
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if entry.get("kind") != "velocity":
                        continue
                    if entry.get("principal") != principal:
                        continue
                    try:
                        ts = float(entry.get("ts", 0))
                    except (TypeError, ValueError):
                        continue
                    if now - ts > window:
                        continue
                    try:
                        sends += int(entry.get("sends", 0) or 0)
                    except (TypeError, ValueError):
                        pass
                    try:
                        writes += int(entry.get("writes", 0) or 0)
                    except (TypeError, ValueError):
                        pass
                    try:
                        egress += float(entry.get("egress_bytes", 0) or 0)
                    except (TypeError, ValueError):
                        pass
            max_sends = velocity.get("max_sends")
            if max_sends is not None and sends >= max_sends:
                return True
            max_writes = velocity.get("max_writes")
            if max_writes is not None and writes >= max_writes:
                return True
            max_egress = velocity.get("max_egress_bytes")
            if max_egress is not None and egress >= max_egress:
                return True
            return False
        except Exception as e:
            # Fail open, LOUD. The call is NOT denied — but the missing
            # cross-run signal is audit-visible.
            try:
                self.log.append({
                    "event": "tool_call",
                    "run_id": self.run_id,
                    "agent_id": "system",
                    "role": "system",
                    "principal": principal,
                    "decision": "velocity_check_skipped",
                    "policy_id": "velocity-guard",
                    "flag": "velocity_check_skipped",
                    "reason": ("Cross-run velocity check skipped (fail-open): "
                               "%s: %s. The call proceeds without cross-run "
                               "velocity memory." % (type(e).__name__, e)),
                })
            except Exception:
                pass
            return False

    def _record_velocity(self, tool, principal, agent_id, egress_bytes):
        """Record one execution of a velocity tool in the cross-run ledger.

        Called at the two F33 execution boundaries (direct-allow and
        approved execution). ``EgressLedger.append`` holds the F74 write
        lock across its whole read-modify-write — S5 adds no second
        lock. Fail-OPEN with a loud ``velocity_check_skipped`` audit
        entry on ledger trouble: the call already executed, so a ledger
        outage must not break the result path — but the missing memory
        must be audit-visible. No-op when the ``velocity:`` section is
        absent (unenforced: no history to keep).
        """
        velocity = getattr(self.policy, "velocity", None) or {}
        if not velocity:
            return
        ledger = self._ledger
        if ledger is None:
            return
        try:
            egress = float(egress_bytes or 0)
        except (TypeError, ValueError):
            egress = 0.0
        entry = {
            "kind": "velocity",
            "ts": time.time(),
            "run_id": self.run_id,
            "principal": principal,
            "agent_id": agent_id,
            "tool": tool,
            "sends": 1 if tool in _SEND_TOOLS else 0,
            "writes": 1 if tool == "write_file" else 0,
            "egress_bytes": egress,
        }
        try:
            # The write lock is held inside append (F74) — no second
            # lock here.
            ledger.append(entry)
        except Exception as e:
            # Fail open, LOUD: the execution already happened; audit the
            # missing cross-run memory instead of breaking the result.
            try:
                self.log.append({
                    "event": "tool_call",
                    "run_id": self.run_id,
                    "agent_id": "system",
                    "role": "system",
                    "principal": principal,
                    "tool": tool,
                    "decision": "velocity_check_skipped",
                    "policy_id": "velocity-guard",
                    "flag": "velocity_check_skipped",
                    "reason": ("Cross-run velocity record skipped "
                               "(fail-open): %s: %s. The execution is not "
                               "reflected in cross-run velocity memory."
                               % (type(e).__name__, e)),
                })
            except Exception:
                pass

    def _context(self, tool, args, principal=None, record_ledger=True,
                 agent_id=None):
        ctx = {"api_calls": self.api_calls, "counters": dict(self.counters)}
        if "path" in args:
            ctx["path_outside_sandbox"] = self._is_outside_sandbox(args["path"])
        if tool in _SEND_TOOLS:
            ctx["domain_allowlisted"] = self._domain_allowlisted(tool, args)
            ctx["carries_read_content"] = self._carries_read_content(tool, args)
            # F111 (wave-34): identity-bound egress. A credential on an
            # egress call that is not bound to the provisioned session
            # identity sets credential_identity_mismatch; the policy
            # rule of the same id denies + audits (GTG-50020 class).
            ctx["credential_identity_mismatch"] = (
                self._credential_identity_mismatch(args))
            # P7 (wave-27): raw registry fetch via http_post is denied
            # by policy; the governed install_package tool is the only
            # sanctioned fetch path.
            ctx["package_fetch"] = sc_install.is_package_fetch(
                tool, (args or {}).get("url"))
        elif tool == "api_call":
            # F1: api_call params are an outbound-shaped payload to a
            # third-party endpoint; correlate them against prior reads the
            # same way sends are correlated.
            # F94: api_call destinations ARE allowlisted by policy now —
            # deny-egress-unallowlisted covers api_call, so the
            # destination check runs here exactly as it does for sends.
            ctx["domain_allowlisted"] = self._domain_allowlisted(tool, args)
            ctx["carries_read_content"] = self._carries_read_content(tool, args)
            # P7 (wave-27): raw registry fetch via api_call is denied by
            # policy (deny-ungoverned-package-fetch); the governed
            # install_package tool is the only sanctioned fetch path.
            ctx["package_fetch"] = sc_install.is_package_fetch(
                tool, (args or {}).get("endpoint"))
            # F9/F15: run-scoped taint — this run ingested DLP-sensitive
            # content — OR principal-scoped taint inherited from the
            # ledger: a fresh run for the same principal whose earlier run
            # read sensitive content starts tainted inside the 24h TTL.
            ctx["read_sensitive"] = (
                self._read_sensitive
                or self._principal_taint_active(principal))
            # F111 (wave-34): identity-bound egress (GTG-50020 class).
            # A credential on the call not bound to the provisioned
            # session identity -> credential_identity_mismatch; the
            # policy rule of the same id denies + audits.
            ctx["credential_identity_mismatch"] = (
                self._credential_identity_mismatch(args))
            # F99: keyword-free framed-secret signal — the api_call carries
            # an unknown-format high-entropy token the DLP cannot name
            # (no credential keyword nearby). Scanned per string value,
            # never the cross-field join (the F2/F8 boundary: the
            # entropy tripwire stays on the original text). F106: the
            # endpoint URL's query values and path segments are scanned
            # too (per-segment, so adjacent path parts never join into
            # a phantom run) — the F94 allowlist matches hostname only.
            # Only api_call: send_email/http_post are already
            # blanket-queued by approval-outbound-sends, so they need
            # no such signal.
            ctx["high_entropy_payload"] = (
                self._api_call_high_entropy_payload(args))
            # F10/F13/F14: heuristic cross-run campaign signals
            # (fail-safe). The fragment-shape signal and the structural
            # same-key-set signal (F14) both surface as
            # ``cross_run_campaign`` — one campaign concept, three
            # detectors; the ledger record keeps which shape each entry
            # had for forensics. F36: the cross-principal detector joins
            # here — a campaign that rotates principals per run never
            # trips the per-principal detectors, so the same shape from
            # >= K distinct principals in the window also queues. Not
            # re-recorded on approval re-evaluation: the attempt was
            # already ledgered when first queued.
            if record_ledger:
                shape = self._api_call_shape(args)
                ctx["cross_run_campaign"] = (
                    self._check_cross_run_campaign(
                        tool, args, principal, shape, agent_id=agent_id)
                    or self._check_structural_campaign(
                        tool, shape, principal)
                    or self._check_cross_principal_campaign(
                        tool, shape, principal))
            else:
                ctx["cross_run_campaign"] = False
        elif tool == "install_package":
            # P7 (wave-27): the governed-install gates — allowlist +
            # exact pin + artifact integrity — computed from
            # gov/supplychain_install.py so policy can deny the
            # unallowlisted and integrity-mismatch shapes with distinct
            # policy_ids. install_package is never a raw "package
            # fetch" (it IS the sanctioned path).
            allowlisted, verified, _digest = sc_install.install_context(
                (args or {}).get("name"), (args or {}).get("version"))
            ctx["install_allowlisted"] = allowlisted
            ctx["install_integrity_verified"] = verified
            ctx["package_fetch"] = False
        # S5 (K-052): cross-run per-principal velocity signal for
        # send/write/egress tools. Queried only when record_ledger=True:
        # the approval re-evaluation passes record_ledger=False, so an
        # approved execution is never re-queued by its own velocity
        # record (no approval requeue livelock). Fail-open with a loud
        # velocity_check_skipped audit on ledger trouble (inside
        # _query_velocity) — the signal is heuristic, never a deny.
        if record_ledger and tool in _VELOCITY_TOOLS:
            ctx["velocity_exceeded"] = self._query_velocity(principal)
        else:
            ctx["velocity_exceeded"] = False
        ctx["source_untrusted"] = self._tainted
        return ctx

    # -- simulated tools ---------------------------------------------------

    def _simulate(self, tool, args, ctx):
        # Wave-35 (Docker CVE-2026-77179/79994 class): the
        # path_outside_sandbox verdict in ctx was computed at check
        # time. The filesystem can change between check and use
        # (symlink swap), so re-verify at USE time, fail-closed: a
        # mid-call change quarantines/denies rather than honoring the
        # stale verdict.
        use_outside = (ctx.get("path_outside_sandbox")
                       or ("path" in args
                           and self._is_outside_sandbox(args["path"])))
        if tool == "read_file":
            p = self._resolve(args["path"])
            if not use_outside and p.is_file():
                return {"source": "sandbox",
                        "content": p.read_text(encoding="utf-8")[:4000]}
            return {"source": "simulated", "content": "[synthetic file contents]"}
        if tool == "write_file":
            content = args.get("content", "")
            if use_outside:
                # Even approved, an outside-sandbox write never touches the real
                # path: it is quarantined inside the run directory.
                q = self.quarantine / Path(args["path"]).name
                q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text(content if isinstance(content, str) else str(content),
                             encoding="utf-8")
                return {"path": str(q),
                        "note": "outside sandbox; quarantined inside run dir"}
            p = self._resolve(args["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content if isinstance(content, str) else str(content),
                         encoding="utf-8")
            return {"path": str(p),
                    "bytes": len(content if isinstance(content, str) else str(content))}
        if tool == "delete_file":
            p = self._resolve(args["path"])
            if not use_outside and p.is_file():
                p.unlink()
                return {"deleted": True, "path": str(p)}
            return {"deleted": False, "note": "simulated; no file touched"}
        if tool == "api_call":
            return {"status": 200, "synthetic": True,
                    "endpoint": args.get("endpoint"), "items_returned": 2}
        if tool == "http_post":
            return {"status": 202, "synthetic": True, "url": args.get("url")}
        if tool == "send_email":
            return {"status": "sent (simulated; no real email leaves this machine)",
                    "to": args.get("to")}
        if tool == "install_package":
            # P7 (wave-27): policy already gated this call (allowlisted
            # + integrity-verified) — re-check at execution for
            # fail-closed defense in depth. A refusal here is reported
            # as a refused install, never as a success.
            ok, detail = sc_install.check_install(args.get("name"),
                                                  args.get("version"))
            if not ok:
                return {"installed": False, "refused": detail,
                        "note": "refused at execution: %s" % detail}
            return {"installed": True, "name": args.get("name"),
                    "version": args.get("version"), "sha256": detail,
                    "note": ("simulated install; artifact integrity "
                             "verified against pin")}
        return {"note": "unknown tool; simulated no-op"}

    @staticmethod
    def _summarize(tool, result):
        bits = []
        for k, v in result.items():
            if k == "content":
                continue
            bits.append("%s=%s" % (k, v))
        return "; ".join(bits)[:300]

    @staticmethod
    def _preview(tool, args):
        """Human-facing preview of what the action would do.

        F12: built from the SAME (redacted) args that execute, so the
        preview faithfully represents the authorized action. Payload
        fields are summaries (``{bytes, sha256}``) — the preview says
        so explicitly.
        F11: every interpolated agent-controlled value passes through
        ``sanitize_preview_text`` so ANSI escapes / carriage returns /
        bidi overrides render as visible escapes, never raw glyphs.
        """
        safe = sanitize_preview_text
        if tool == "send_email":
            return "would send email to %s (subject: %r)" % (
                safe(args.get("to")), args.get("subject"))
        if tool == "http_post":
            return "would POST to %s" % safe(args.get("url"))
        if tool == "write_file":
            content = args.get("content", "")
            if isinstance(content, dict) and "bytes" in content:
                return ("would write %d bytes (payload redacted at "
                        "execution) to %s"
                        % (content["bytes"], safe(args.get("path"))))
            n = len(content if isinstance(content, str) else str(content))
            return "would write %d bytes to %s" % (n, safe(args.get("path")))
        if tool == "delete_file":
            return "would delete %s" % safe(args.get("path"))
        if tool == "read_file":
            return "would read %s" % safe(args.get("path"))
        if tool == "api_call":
            return "would call API endpoint %s" % safe(args.get("endpoint"))
        if tool == "install_package":
            return ("would install package %s==%s (governed: allowlist + "
                    "exact pin + artifact integrity)"
                    % (safe(args.get("name")), safe(args.get("version"))))
        return "would invoke %s" % tool

    @staticmethod
    def _egress_bytes_for(tool, args):
        """F33: actual payload UTF-8 bytes this execution would move across
        the trust boundary. Counts the transmitted fields (payload AND
        routing fields such as the recipient/endpoint — they are bytes
        that leave the boundary), computed on the RAW args at the call
        boundary so DLP redaction never reduces the count: a DLP-clean
        payload moves exactly as many bytes as a flagged one. Non-string
        structured payloads are counted as their canonical JSON encoding
        (sort_keys, UTF-8 — the wire form). Tools outside _EGRESS_TOOLS
        contribute 0.
        """
        args = args or {}
        if tool not in _EGRESS_TOOLS:
            return 0

        def _b(value):
            if isinstance(value, (bytes, bytearray)):
                return bytes(value)
            if isinstance(value, str):
                return value.encode("utf-8")
            if isinstance(value, (dict, list)):
                # F128: bytes nested inside a structured payload must not
                # crash the budget counter (uncaught TypeError — F123
                # class). Decoded latin-1 (1 char/byte; non-ASCII bytes
                # may expand under UTF-8, so nested bytes overcount
                # slightly — the conservative direction for a budget).
                def _default(o):
                    if isinstance(o, (bytes, bytearray)):
                        return bytes(o).decode("latin-1")
                    return str(o)
                return json.dumps(value, sort_keys=True,
                                  ensure_ascii=False,
                                  default=_default).encode("utf-8")
            return str(value).encode("utf-8")

        if tool == "send_email":
            parts = (args.get("to", ""), args.get("subject", ""),
                     args.get("body", ""))
        elif tool == "http_post":
            parts = (args.get("url", ""), args.get("payload", ""))
        else:  # api_call
            parts = (args.get("endpoint", ""), args.get("params", ""))
        return sum(len(_b(p)) for p in parts)

    def _max_egress_bytes(self):
        """F33: the configured cumulative egress byte budget for this run."""
        rl = getattr(self.policy, "rate_limit", None) or {}
        try:
            return int(rl.get("max_egress_bytes_per_run",
                             _DEFAULT_MAX_EGRESS_BYTES_PER_RUN))
        except (TypeError, ValueError):
            # Malformed config must not silently disable the budget:
            # policy_lint flags it as an error; the executor fails closed
            # to the conservative default.
            return _DEFAULT_MAX_EGRESS_BYTES_PER_RUN

    @staticmethod
    def _approved_egress_bytes(rec):
        """F33: byte charge for an approved record — the raw count recorded
        at queue time. The redacted queue form of the args may summarize
        large payloads (``{bytes, sha256_prefix}``), so recomputing from
        ``rec["args"]`` would under-count the bytes the approved action
        was authorized to move. Records queued before this field existed
        fall back to the redacted form.
        """
        eb = rec.get("egress_bytes")
        if isinstance(eb, int) and eb >= 0:
            return eb
        return ToolExecutor._egress_bytes_for(rec.get("tool"),
                                              rec.get("args"))

    # -- main entry points --------------------------------------------------

    # -- sterile windows (wave-53 P1) -------------------------------------
    # Executor-side critical-window enforcement. Integration design:
    # workstreams/architect/STERILE_COCKPIT_INTEGRATION.md. Default-off:
    # every method below is a no-op when self.sterile is None.

    def attach_loop_contract(self, loop):
        """Install the deployment-loop contract (sterile.LoopContract).

        The loop owns freeze_context/withhold/release/reissue_reads
        for executor-unmediated channels. Without it the executor
        enforces tool-mediated channels only and declares the gap in
        audit (loop_contract_absent + per-channel
        window_declared_unenforceable) — never a silent partial claim.

        Wave-53 P1 fix (paper-review round 2): explicit capability
        handshake. A loop that inherits any of the four contract
        methods unimplemented (the base raises NotImplementedError)
        is rejected at attach time — a half-implemented loop fails
        loud here, not silently partial at window entry.
        """
        from .sterile import LoopContract
        if not isinstance(loop, LoopContract):
            raise TypeError("loop must be a sterile.LoopContract")
        for meth in ("freeze_context", "withhold", "release",
                     "reissue_reads"):
            if getattr(type(loop), meth) is getattr(LoopContract, meth):
                raise TypeError(
                    "loop must implement LoopContract.%s "
                    "(inherited NotImplementedError stub)" % meth)
        self._sterile_loop = loop
        self.log.append({
            "event": "sterile_loop_attached",
            "run_id": self.run_id, "agent_id": "system",
            "role": "system", "decision": "loop_attached",
            "policy_id": "sterile-loop",
            "reason": "Deployment loop contract attached: C4/C6/C7 "
                      "channels are loop-withheld during windows.",
        })
        # RT21 a6 (wave-54): a loop attached while windows are already
        # open does NOT retro-engage them — the entry-time
        # window_declared_unenforceable declarations for those windows
        # stand. Say so loudly so the gap is visible, not silent.
        if self.sterile is not None:
            open_now = self.sterile.open_windows()
            if open_now:
                self.log.append({
                    "event": "loop_contract_attached_with_windows_open",
                    "run_id": self.run_id, "agent_id": "system",
                    "role": "system", "decision": "declared",
                    "policy_id": "sterile-loop",
                    "windows": list(open_now),
                    "reason": "Loop contract attached while windows %s "
                              "are already open: those windows were NOT "
                              "loop-engaged (their entry-time "
                              "window_declared_unenforceable "
                              "declarations stand). Attach the contract "
                              "before any tool call for full coverage."
                              % (open_now,),
                })

    def _sterile_loop_owned(self, channel):
        """Channels the executor cannot mediate (deployment-loop owned)."""
        from .sterile import CHANNELS
        rec = CHANNELS.get(channel)
        return rec is not None and not rec["executor_mediated"]

    def _sterile_snapshot_ref(self):
        """Entry snapshot reference (integration §1.1).

        The policy hash plus the log-seq range of tool results
        delivered this run so far: "pre-vetted" means "passed the
        content stack when delivered" — the window freezes the
        verdicts, it does not re-prove them.
        """
        try:
            self.log.refresh()
            last = int(self.log.tail_seq)
        except Exception:
            last = 0
        return {
            "policy_hash": getattr(self.policy, "policy_hash", None),
            "log_seq_first": self._sterile_run_first_seq,
            "log_seq_last": last,
        }

    def _sterile_loop_error_audit(self, window, phase, error):
        """A loop-contract call failed: audit loudly, stay degraded.

        Executor-side channel suspension still holds (the executor's
        own gate is unaffected); the loop-side gap is now an audited
        fact, not a silent partial claim. Atomicity across executor
        and loop is the deployment's responsibility — this audit
        records exactly which phase failed so a reviewer can see a
        partially applied entry (e.g. freeze ok, withhold failed).
        """
        self.log.append({
            "event": "loop_contract_error",
            "run_id": self.run_id, "agent_id": "system",
            "role": "system", "decision": "degraded",
            "policy_id": "sterile-loop",
            "window": window, "phase": phase,
            "error": str(error)[:200],
            "reason": "Deployment loop contract call failed during "
                      "%s; executor-side channel suspension still "
                      "holds. Loop-side enforcement is unverified — "
                      "treat this window as executor-side only." % phase,
        })

    def _sterile_loop_engage(self, window_id):
        """Run the deployment loop's entry obligations (integration §1.1).

        freeze_context(snapshot_ref) once per entry; withhold(channel)
        for each suspended loop-owned channel not already withheld by
        an open window. With no loop attached, each suspended
        loop-owned channel is declared unenforceable in audit
        (window_declared_unenforceable) — the gap is visible, not
        silent.
        """
        wdef = self._sterile_window_def(window_id) or {}
        suspended = list(wdef.get("suspend") or [])
        owned = [c for c in suspended if self._sterile_loop_owned(c)]
        if self._sterile_loop is None:
            for ch in owned:
                self.log.append({
                    "event": "window_declared_unenforceable",
                    "run_id": self.run_id, "agent_id": "system",
                    "role": "system", "decision": "declared",
                    "policy_id": "sterile-loop",
                    "window": window_id, "channel": ch,
                    "reason": "Channel %r is suspended by window %r "
                              "but no deployment loop contract is "
                              "attached — the executor cannot withhold "
                              "arrivals on this channel. Declared "
                              "suspended but unenforceable." % (ch,
                                                                window_id),
                })
            return
        ref = self._sterile_snapshot_ref()
        withheld = []
        try:
            self._sterile_loop.freeze_context(ref)
        except Exception as e:
            self._sterile_loop_error_audit(window_id, "freeze_context",
                                           e)
            self._sterile_withheld[window_id] = withheld
            return
        already = set()
        for ws in self._sterile_withheld.values():
            already.update(ws)
        for ch in owned:
            if ch in already:
                continue  # an open window already holds it
            try:
                self._sterile_loop.withhold(ch)
            except Exception as e:
                self._sterile_loop_error_audit(window_id,
                                               "withhold:%s" % ch, e)
                continue
            withheld.append(ch)
            already.add(ch)
        self._sterile_withheld[window_id] = withheld

    def _sterile_loop_release_for(self, window_id, phase):
        """Release loop-held channels for one closing/expiring window.

        Union semantics: a channel is released only when no other
        open window still holds it.
        """
        withheld = self._sterile_withheld.pop(window_id, [])
        if not withheld or self._sterile_loop is None:
            return []
        still_needed = set()
        for wid, ws in self._sterile_withheld.items():
            if wid in self.sterile.open_windows():
                still_needed.update(ws)
        released = []
        for ch in withheld:
            if ch in still_needed:
                continue
            try:
                self._sterile_loop.release(ch)
            except Exception as e:
                self._sterile_loop_error_audit(window_id,
                                               "release:%s" % ch, e)
                continue
            released.append(ch)
        return released

    def _drain_sterile(self, agent_id="system", role="system",
                     enter_snapshot=None):
        """Forward controller audit events into the hash-chained log.

        enter_snapshot, when given, is attached to
        sterile_window_enter events (integration §1.1: the entry
        snapshot reference — policy hash + delivered-result log-seq
        range — rides on the enter event the loop's freeze_context
        pins to).
        """
        while self._sterile_events:
            ev = self._sterile_events.pop(0)
            entry = {"run_id": self.run_id, "agent_id": agent_id,
                     "role": role}
            entry.update(ev)
            if (enter_snapshot is not None
                    and ev.get("event") == "sterile_window_enter"):
                entry["snapshot_ref"] = enter_snapshot
            self.log.append(entry)

    def _read_ack_cumulative(self):
        """Read the wave-66 per-run cumulative ack counter from the
        run-dir marker. Returns (used, budget_hit_audited). A missing
        or corrupt marker degrades to (0, False) — documented
        boundary: the marker is server-side run-dir state, same trust
        class as the run dir itself; the in-memory counter still
        bounds this executor's drains."""
        try:
            data = json.loads(self._ack_cumulative_marker.read_text())
        except (OSError, ValueError):
            return 0, False
        used = data.get("drained", 0) if isinstance(data, dict) else 0
        if isinstance(used, bool) or not isinstance(used, int) \
                or used < 0:
            return 0, False
        hit = bool(data.get("budget_hit", False)) \
            if isinstance(data, dict) else False
        return used, hit

    def _write_ack_cumulative(self):
        """Persist the wave-66 cumulative ack counter (best-effort)."""
        try:
            self._ack_cumulative_marker.write_text(json.dumps(
                {"drained": self._ack_cumulative_used,
                 "budget_hit": self._ack_budget_hit_audited}))
        except OSError:
            pass

    def _audit_ack_budget_hit(self, cap):
        """Chain the one-per-run control event naming the exhausted
        cumulative ack budget. Loud in the audit trail, not just the
        exception. A control event, not an ack record: it does not
        count against the ack budget."""
        if self._ack_budget_hit_audited:
            return
        self.log.append({
            "run_id": self.run_id,
            "agent_id": "system",
            "role": "system",
            "event": "unvetted_ack_cumulative_budget_hit",
            "decision": "refused",
            "budget": cap,
            "drained": self._ack_cumulative_used,
            "note": ("per-run cumulative ack budget exhausted: "
                     "further drain_ack_sink calls refuse fail-closed; "
                     "undrained evidence remains in the sink"),
        })
        self._ack_budget_hit_audited = True
        self._write_ack_cumulative()

    def drain_ack_sink(self, sink, agent_id="system", role="system"):
        """Forward acknowledgment records into the hash-chained log.

        Wave-65 D5: the deployment drains the consumer-owned ack sink
        (an ``AckAuditSink`` or a plain list of ack records) into the
        run log — this is the blessed path answering "should
        acknowledge() sink records feed the hash-chained audit log"
        (yes, via the standing drain convention: sterile.py never owns
        the log; the log owner drains).

        Peek-confirm: each record is appended to the ActionLog BEFORE
        it is popped from the sink, so a failed append
        (LogFullError, AppendLockError, NoKeyConfiguredError) leaves
        the record in the sink — evidence is never silently dropped;
        the exception propagates fail-closed per F22 (the deployment
        must drain before relying on the trail).

        Wave-66 D5: per-RUN cumulative flood budget. The per-sink
        budget bounds one batch before one drain; repeated
        drain/refill cycles are now bounded by a cumulative cap of
        ``_ACK_CUMULATIVE_BATCHES_DEFAULT`` full sink batches
        (default 8 * sink budget, 2048 at the default 256; plain-list
        sinks default to the 256 batch baseline — the cumulative cap
        is their ONLY bound). The counter lives on the run
        (``_ack_cumulative_used`` + the ``.ack_cumulative`` run-dir
        marker), never the sink: replacing the sink mid-run cannot
        reset it. The accounting unit is one chained record
        (individual acks and overflow summaries both count; a
        coalesced record counts once). On exhaustion
        ``AckCumulativeBudgetExceeded`` is raised LOUD — records
        already drained stay chained (exact count), the rest stay in
        the sink, and exactly one
        ``unvetted_ack_cumulative_budget_hit`` control event is
        chained per run. An empty sink drains to 0 with no raise even
        when exhausted.

        Reserved run keys (run_id, agent_id, role) are stamped by the
        executor AFTER the record (log-wins, mirroring ActionLog's
        reserved-metadata rule): a forged ack record cannot override
        the run context at drain time. The ``consumer`` field stays
        caller-asserted — consumer identity is self-attested by
        design (the documented honesty boundary).

        Returns the number of records drained.
        """
        from .sterile import (  # noqa: E402  (local: no import cycle)
            AckCumulativeBudgetExceeded, _ACK_CUMULATIVE_BATCHES_DEFAULT,
            _ACK_BUDGET_DEFAULT)
        if hasattr(sink, "peek_oldest") and hasattr(sink, "pop_oldest"):
            peek, pop = sink.peek_oldest, sink.pop_oldest
            batch = getattr(sink, "max_records", None)
        else:
            # Plain-sequence sink (list): index first, remove only
            # after the log append succeeds.
            def peek():
                return sink[0] if sink else None

            def pop():
                return sink.pop(0) if sink else None

            batch = None
        if isinstance(batch, bool) or not isinstance(batch, int) \
                or batch < 1:
            # Plain list or foreign sink: the cumulative cap is the
            # only bound, keyed to the default batch baseline.
            batch = _ACK_BUDGET_DEFAULT
        cap = _ACK_CUMULATIVE_BATCHES_DEFAULT * batch

        def _refuse():
            try:
                remaining = sink.pending()
            except (AttributeError, TypeError):
                try:
                    remaining = len(sink)
                except TypeError:
                    remaining = "?"
            self._audit_ack_budget_hit(cap)
            raise AckCumulativeBudgetExceeded(
                "per-run cumulative ack budget exhausted: %d ack "
                "records already chained this run (cap %d); %s "
                "record(s) remain in the sink — fail-closed, evidence "
                "retained" % (self._ack_cumulative_used, cap,
                              remaining))

        n = 0
        while True:
            rec = peek()
            if rec is None:
                break
            if not isinstance(rec, dict):
                raise TypeError(
                    "ack sink holds a non-record %r (refusing to drain)"
                    % type(rec).__name__)
            if self._ack_cumulative_used >= cap:
                _refuse()
            entry = {}
            entry.update(rec)
            entry["run_id"] = self.run_id
            entry["agent_id"] = agent_id
            entry["role"] = role
            self.log.append(entry)  # raises -> record stays; fail closed
            pop()
            # Increment ONLY after a successful chain-append + pop: a
            # failed drain re-drains with exact accounting — no
            # double-count (wave-65's no-silent-drops property holds).
            self._ack_cumulative_used += 1
            n += 1
        self._write_ack_cumulative()
        return n

    def _sterile_expire(self, t=None):
        """Expire overdue windows with loop release + reconciliation.

        Wave-53 P1 fix (paper-review round 2): expiry is not just a
        controller pop. For each expired window the executor (a)
        releases loop-withheld channels (union semantics), (b) hands
        the refused-during-window read list to loop.reissue_reads()
        when a loop is attached — the reads were refused, never
        delivered; the loop re-issues them through the full
        content-defense stack, never marked vetted (R4) — and (c)
        emits ONE merged sterile_window_exit event per expired window
        (controller fields + executor reconcile/release fields)
        instead of a bare controller pop.
        """
        if self.sterile is None:
            return []
        # Snapshot per-window entry metadata before tick() pops them.
        detail = {wid: self.sterile.peek(wid)
                  for wid in self.sterile.open_windows()}
        expired = self.sterile.tick(t)
        # Collect (not blind-drain): expired-window exits get merged
        # into one executor-authored event each.
        pending = []
        while self._sterile_events:
            pending.append(self._sterile_events.pop(0))
        for wid in expired:
            info = detail.get(wid) or {}
            refused = list(info.get("refused") or [])
            released = self._sterile_loop_release_for(wid, "expired")
            reissued = None
            if self._sterile_loop is not None and refused:
                try:
                    reissued = self._sterile_loop.reissue_reads(refused)
                except Exception as e:
                    self._sterile_loop_error_audit(wid, "reissue_reads",
                                                   e)
            merged = {"run_id": self.run_id, "agent_id": "system",
                      "role": "system",
                      "event": "sterile_window_exit", "window": wid,
                      "reason": "expired", "task": "incomplete",
                      "decision": "expired",
                      "policy_id": "sterile-close",
                      "reconcile": refused,
                      "reconciled_vetted": False,
                      "reconcile_pending": (not self._sterile_loop
                                            and bool(refused)),
                      "released_channels": released}
            if reissued is not None:
                # Wave-64 D5: the reissue pipe's return crosses wrapped
                # in the typed unvetted marker, stored as its JSON
                # envelope — machine-readable "never vetted" that
                # survives the audit log's JSON serialization (the
                # live Unvetted object would be erased by the log's
                # default=str). reconciled_vetted stays False (R4).
                # Local import: no import cycle (attach_loop_contract
                # idiom); the __init__-local sterile import is not in
                # scope here.
                from .sterile import Unvetted  # noqa: E402
                merged["post_window_delta"] = Unvetted(
                    reissued, origin="reissue_reads",
                    ack_context={"window": wid,
                                 "run_id": self.run_id}).to_envelope()
            self.log.append(merged)
        for ev in pending:
            if (ev.get("event") == "sterile_window_exit"
                    and ev.get("window") in expired
                    and ev.get("reason") == "expired"):
                continue  # merged above
            entry = {"run_id": self.run_id, "agent_id": "system",
                     "role": "system"}
            entry.update(ev)
            self.log.append(entry)
        return expired

    def _sterile_window_def(self, window_id):
        for w in self.sterile.policy.windows:
            if w["id"] == window_id:
                return w
        return None

    def _sterile_loop_absent_audit(self):
        if (self.sterile is not None and self._sterile_loop is None
                and not self._sterile_loop_absent_audited):
            self._sterile_loop_absent_audited = True
            self.log.append({
                "event": "loop_contract_absent",
                "run_id": self.run_id, "agent_id": "system",
                "role": "system", "decision": "degraded",
                "policy_id": "sterile-loop",
                "reason": "No deployment loop contract attached: "
                          "windows enforce executor-mediated channels "
                          "(tool_result, file_read, web_fetch) only; "
                          "user_message/skill_content/summary_state are "
                          "declared suspended but unenforceable.",
            })

    def _sterile_entry_rescan(self, window_id):
        """Wave-53 P1 (integration §2): opt-in entry re-scan.

        Re-runs the CURRENT sensitive-content judgment over retained
        pre-window read content. Catches stale-stack misses, never
        lineage — a hit is audited (content identified by sha256
        prefix only, never logged), never silently remediated.
        """
        wdef = self._sterile_window_def(window_id)
        if not wdef or not wdef.get("entry_rescan"):
            return
        for content in list(getattr(self, "_read_contents", [])):
            try:
                if self._content_is_sensitive(content):
                    import hashlib
                    self.log.append({
                        "event": "window_entry_rescan_hit",
                        "window": window_id, "run_id": self.run_id,
                        "agent_id": "system", "role": "system",
                        "decision": "flagged",
                        "policy_id": "sterile-entry-rescan",
                        "content_sha256_prefix": hashlib.sha256(
                            content.encode("utf-8",
                                           "replace")).hexdigest()[:16],
                        "reason": "Pre-window delivered content trips "
                                  "the current content stack on window "
                                  "entry re-scan (stale-stack check; not "
                                  "lineage — see integration design §2).",
                    })
            except Exception:
                continue

    def _sterile_refusal_accounting(self, window_id):
        n = self._sterile_refusals.get(window_id, 0) + 1
        self._sterile_refusals[window_id] = n
        wdef = self._sterile_window_def(window_id)
        alert_after = (wdef or {}).get("refusal_alert_after")
        if (alert_after is not None and n > alert_after
                and (window_id, self._sterile_enters.get(window_id, 0))
                not in self._sterile_alerted):
            self._sterile_alerted.add(
                (window_id, self._sterile_enters.get(window_id, 0)))
            self.log.append({
                "event": "window_refusal_rate_alert",
                "window": window_id, "run_id": self.run_id,
                "agent_id": "system", "role": "system",
                "decision": "flagged", "policy_id": "sterile-telemetry",
                "refusals": n, "threshold": alert_after,
                "reason": "Refusals for window %r exceeded "
                          "refusal_alert_after=%d — the window is likely "
                          "mis-scoped (too broad/long), not a user "
                          "problem; tune the policy."
                          % (window_id, alert_after),
            })

    def _sterile_gate(self, identity, tool, t=None):
        """Critical-window entry + input-channel refusal for one call.

        Returns an audit-logged refusal dict, or None to continue the
        pipeline. Identity-verified callers only mutate window state.
        """
        if self.sterile is None:
            return None
        # Fail-closed expiry on every call, even quiet runs (with
        # loop release + expiry reconciliation — _sterile_expire).
        self._sterile_expire(t)
        # The close primitive is a governance method, never a tool: a
        # literal tool call with that name is denied loudly, so
        # tool-call parameters can never reach the controller
        # (integration §7: window-escape via parameters).
        if tool == "window_close":
            entry = self.log.append({
                "event": "window_close_denied",
                "run_id": self.run_id, "agent_id": identity.agent_id,
                "role": identity.role, "tool": tool,
                "decision": "denied", "policy_id": "sterile-reserved",
                "reason": "window_close is a governance primitive, not "
                          "a tool — use request_window_close().",
            })
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "sterile-reserved", "seq": entry["seq"]}
        # Unverified callers never mutate window state (their calls are
        # denied at the identity check anyway).
        if self._check_identity(identity) is not None:
            return None
        entered = self.sterile.maybe_open(tool, t)
        enter_snapshot = self._sterile_snapshot_ref()
        self._drain_sterile(agent_id=identity.agent_id,
                            role=identity.role,
                            enter_snapshot=enter_snapshot)
        for ev in entered:
            if ev.get("event") == "sterile_window_enter":
                wid = ev["window"]
                self._sterile_enters[wid] = \
                    self._sterile_enters.get(wid, 0) + 1
                self._sterile_entry_rescan(wid)
                self._sterile_loop_engage(wid)
        self._sterile_loop_absent_audit()
        channel = self._sterile_tool_channels.get(tool, "unknown_tool")
        verdict = self.sterile.check(tool, channel, t)
        self._drain_sterile(agent_id=identity.agent_id,
                            role=identity.role)
        if verdict["allowed"]:
            return None
        wid = verdict["window"]
        self._sterile_refusal_accounting(wid)
        return {
            "status": "window_suspended", "window": wid,
            "channel": channel,
            "reason": ("Input channel %r is suspended while critical "
                       "window %r is open — defer the read until the "
                       "window closes." % (channel, wid)),
            "policy_id": "sterile-window",
        }

    def sterile_tick(self, t=None):
        """Expire overdue windows outside the call path (quiet runs).

        Loop release + expiry reconciliation included (_sterile_expire).
        """
        if self.sterile is None:
            return []
        return self._sterile_expire(t)

    def sterile_refusal_summary(self):
        """Per-window refusal telemetry (integration §4)."""
        if self.sterile is None:
            return {}
        return {wid: {"refusals": self._sterile_refusals.get(wid, 0),
                       "enters": self._sterile_enters.get(wid, 0)}
                for wid in self.sterile.open_windows()
                + [w for w in self._sterile_refusals
                   if w not in self.sterile.open_windows()]}

    def request_window_close(self, identity, window_id=None,
                             approval_id=None):
        """The agent's window_close governance primitive (never a tool).

        agent_declared windows: verifies mechanics (open, innermost,
        caller identity, no pending in-window approvals) and closes,
        returning the refused-during-window read list for the loop to
        re-issue (never marked vetted). human_approval windows: with
        no approval_id, queues a close request and returns
        {"status": "queued", ...}; with approval_id, verifies the
        approval record (approved, same run, window_close type,
        window match, within TTL) before closing.
        """
        from .policy import PolicyDecision
        if self.sterile is None:
            return {"closed": False, "reason": "windows_not_configured"}
        if not isinstance(identity, AgentIdentity):
            raise TypeError("identity must be an AgentIdentity minted "
                            "by this executor")
        id_deny = self._check_identity(identity)
        if id_deny is not None:
            self.log.append({
                "event": "window_close_denied", "run_id": self.run_id,
                "agent_id": "unverified", "role": "unverified",
                "window": window_id, "decision": "denied",
                "policy_id": id_deny[0], "reason": id_deny[2],
            })
            return {"closed": False, "reason": "identity_denied"}
        open_ids = self.sterile.open_windows()
        if not open_ids:
            self.log.append({
                "event": "window_close_denied", "run_id": self.run_id,
                "agent_id": identity.agent_id, "role": identity.role,
                "window": window_id, "decision": "denied",
                "policy_id": "sterile-close",
                "reason": "No window open.",
            })
            return {"closed": False, "reason": "no_window_open"}
        target = window_id or open_ids[-1]
        if target != open_ids[-1]:
            self.log.append({
                "event": "window_close_denied", "run_id": self.run_id,
                "agent_id": identity.agent_id, "role": identity.role,
                "window": target, "decision": "denied",
                "policy_id": "sterile-close",
                "reason": "LIFO: window %r is not innermost (%r is)."
                          % (target, open_ids[-1]),
            })
            return {"closed": False, "reason": "not_innermost"}
        wdef = self._sterile_window_def(target) or {}
        if wdef.get("close_policy") == "human_approval":
            if approval_id is None:
                # Queue the close request through the existing approval
                # queue (F42 caller_identity; the queue's MAC/digest
                # integrity covers the record).
                aid = self.approvals.queue(
                    action={"tool": "window_close",
                            "args": {"type": "window_close",
                                     "window": target},
                            "identity": identity.as_dict(),
                            "agent_justification":
                                "Agent requests close of critical "
                                "window %r." % target},
                    decision=PolicyDecision(
                        "require_approval",
                        "Critical window %r requires human approval to "
                        "close." % target,
                        policy_id="sterile-window-close",
                        flag="sterile_window_close"),
                    provenance=("untrusted_influenced" if self._tainted
                                else "agent_direct"),
                    preview=("Close request for critical window %r "
                             "(human_approval)." % target),
                    policy_hash=self.policy.policy_hash,
                    caller_identity=identity)
                self.log.append({
                    "event": "window_close_queued",
                    "run_id": self.run_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role, "window": target,
                    "decision": "queued_pending",
                    "policy_id": "sterile-window-close",
                    "approval_id": aid,
                    "reason": "Window close queued for human approval.",
                })
                return {"closed": False, "status": "queued",
                        "approval_id": aid, "window": target}
            rec = self.approvals.get(approval_id)
            ok, why = self._verify_close_approval(rec, target)
            if not ok:
                self.log.append({
                    "event": "window_close_denied",
                    "run_id": self.run_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role, "window": target,
                    "decision": "denied",
                    "policy_id": "sterile-window-close",
                    "approval_id": approval_id,
                    "reason": "Close approval invalid: %s" % why,
                })
                return {"closed": False,
                        "reason": "human_approval_invalid: %s" % why}
            human_approved = True
        else:
            human_approved = False
            # Wave-53 P1 fix (paper-review round 2, integration §3.2):
            # agent_declared close verifies mechanics — including that
            # no approval for a call made inside the window is still
            # pending. The agent must not end the quarantine while a
            # consequential action requested under it is unresolved.
            pend = self._sterile_pending_in_window_approvals(target)
            if pend:
                self.log.append({
                    "event": "window_close_denied",
                    "run_id": self.run_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role, "window": target,
                    "decision": "denied",
                    "policy_id": "sterile-close",
                    "approval_ids": pend,
                    "reason": "agent_declared close denied: %d "
                              "approval(s) for calls made inside the "
                              "window are still pending." % len(pend),
                })
                return {"closed": False,
                        "reason": "pending_approval_in_window",
                        "approval_ids": pend}
        result = self.sterile.request_close(target,
                                            human_approved=human_approved)
        if not result.get("closed"):
            self._drain_sterile(agent_id=identity.agent_id,
                                role=identity.role)
            return result
        # Closed: merge the controller's sterile_window_exit into the
        # single executor-authored exit event below (paper-review
        # round 2: the old code logged two same-named events).
        ctl_exit = None
        while self._sterile_events:
            ev = self._sterile_events.pop(0)
            if (ev.get("event") == "sterile_window_exit"
                    and ev.get("window") == target
                    and ctl_exit is None):
                ctl_exit = ev
                continue
            entry = {"run_id": self.run_id,
                     "agent_id": identity.agent_id,
                     "role": identity.role}
            entry.update(ev)
            self.log.append(entry)
        reconcile = result.get("reconcile", [])
        released = self._sterile_loop_release_for(target, "close")
        exit_note = {
            "event": "sterile_window_exit", "run_id": self.run_id,
            "agent_id": identity.agent_id, "role": identity.role,
            "window": target, "decision": "closed",
            "policy_id": "sterile-close",
            "controller_depth": (ctl_exit or {}).get("depth"),
            "reconcile": reconcile,
            # R4 invariant: reconciled reads are NEVER marked vetted.
            # The loop re-issues them through the content stack; the
            # deployment fulfills reconcile_pending when no loop is
            # attached.
            "reconciled_vetted": False,
            "reconcile_pending": (not self._sterile_loop
                                  and bool(reconcile)),
            "released_channels": released,
        }
        if self._sterile_loop and reconcile:
            try:
                reissued = self._sterile_loop.reissue_reads(reconcile)
            except Exception as e:
                self._sterile_loop_error_audit(target, "reissue_reads",
                                               e)
                exit_note["reissue_error"] = str(e)[:200]
            else:
                # Wave-64 D5: see _sterile_expire — the reissue return
                # is wrapped in the typed unvetted marker (envelope
                # form for the JSON audit log), never a bare list.
                # In the else-branch (not the try): the try covers
                # the LOOP call only, so a wrap failure could never
                # be misattributed as a loop_contract_error.
                # Local import (no-cycle idiom): the __init__-local
                # sterile import is not in scope here.
                from .sterile import Unvetted  # noqa: E402
                exit_note["post_window_delta"] = Unvetted(
                    reissued, origin="reissue_reads",
                    ack_context={"window": target,
                                 "run_id": self.run_id}).to_envelope()
        self.log.append(exit_note)
        # F124 (wave-54): consume a presented close approval exactly
        # once the close has succeeded. A denied/failed close does not
        # burn the approval; a second presentation fails closed in
        # _verify_close_approval.
        #
        # Ordering residual (documented, wave-54 review): consumption is
        # a second file write (queue _rewrite) after the window is
        # already closed and the exit audited — there is no transaction
        # spanning the audit log and the queue file. If the rewrite
        # FAILS here, the window stays closed but the approval is
        # unconsumed (replayable). That fault class is crash/disk
        # between two writes, not agent-reachable without run-dir write
        # (F59 family: hostile-in-process is an accepted residual), but
        # it must never be SILENT: on failure we land a LOUD
        # window_close_approval_consumption_failed audit event naming
        # the unconsumed approval, then re-raise fail-closed so the
        # caller sees the close as errored and a reviewer can quarantine
        # the approval manually.
        if approval_id is not None:
            try:
                self._consume_close_approval(approval_id, target)
            except Exception as e:  # noqa: BLE001 - fail LOUD, then up
                self.log.append({
                    "event": "window_close_approval_consumption_failed",
                    "run_id": self.run_id,
                    "agent_id": identity.agent_id, "role": identity.role,
                    "window": target, "approval_id": approval_id,
                    "decision": "consumption_failed",
                    "policy_id": "sterile-window-close",
                    "reason": ("Window %r closed but approval %s was NOT "
                               "consumed (%s: %s) — treat the approval as "
                               "suspect; do not honor a re-presentation "
                               "without fresh human review (F124)."
                               % (target, approval_id,
                                  type(e).__name__, str(e)[:160])),
                })
                raise
        out = {"closed": True, "window": target,
               "reconcile": reconcile,
               "reconciled_vetted": False}
        if approval_id is not None:
            out["approval_id"] = approval_id
        return out

    def _sterile_pending_in_window_approvals(self, window_id):
        """Ids of approvals pending for calls made inside the window.

        Integration §3.2: agent_declared close requires that no
        approval queued at/after window entry (this run) is still
        pending. Records with unparseable created_at are treated as
        in-window (fail closed on the check, not on the record).
        """
        info = self.sterile.peek(window_id)
        if not info:
            return []
        from datetime import datetime, timezone
        entered = datetime.fromtimestamp(info["entered_at"],
                                         tz=timezone.utc)
        out = []
        for rec in self.approvals.pending():
            if rec.get("run_id") != self.run_id:
                continue
            try:
                created = datetime.fromisoformat(
                    str(rec.get("created_at")).replace("Z", "+00:00"))
                in_window = created >= entered
            except Exception:
                in_window = True
            if in_window:
                out.append(rec.get("id"))
        return out

    def _verify_close_approval(self, rec, window_id):
        """Verify a queued window-close approval record. Returns
        (ok, reason)."""
        if rec is None:
            return False, "unknown approval id"
        # F34/F43 invariant: every state-changing path verifies the
        # record's keyed digest. ApprovalQueue.get()/all() do NOT
        # verify MACs on read — the digest is verified at decide()
        # time and re-MACed, but a post-decision rewrite of the queue
        # file would otherwise reach this path unverified. Fail closed
        # here, same as execute_approved(). (Under the public dev key
        # this is forgery-transparent per F29/F34; under a provisioned
        # key it binds the record.)
        if not approval_digest_ok(rec):
            return False, "approval record digest invalid"
        # F124 (wave-54): window-close approvals are single-use. The
        # consumed flag is MAC-bound (see _SECURITY_PAYLOAD_FIELDS),
        # so a second presentation of the same approval id — e.g. to
        # close a NEW entry of the same window without a fresh human
        # decision — fails closed here.
        if rec.get("window_close_consumed"):
            return False, "approval already used to close a window"
        if rec.get("run_id") != self.run_id:
            return False, "approval is for another run"
        if rec.get("status") != "approved":
            return False, "approval not approved (status=%r)" % (
                rec.get("status"),)
        if rec.get("late_decision"):
            return False, "decision recorded after bridge expiry"
        if rec.get("tool") != "window_close":
            return False, "approval is not a window_close request"
        args = rec.get("args") or {}
        if args.get("type") != "window_close":
            return False, "approval args are not a window_close request"
        if args.get("window") != window_id:
            return False, "approval window mismatch"
        # TTL: decided_at within approvals.ttl_hours.
        try:
            from datetime import datetime, timezone, timedelta
            decided = datetime.fromisoformat(
                rec["decided_at"].replace("Z", "+00:00"))
            ttl = getattr(self.policy, "approval_ttl_hours", 24)
            if datetime.now(timezone.utc) - decided > timedelta(
                    hours=ttl):
                return False, "approval expired (TTL)"
        except Exception:
            return False, "unparseable decided_at"
        return True, "ok"

    def _consume_close_approval(self, approval_id, window_id):
        """F124 (wave-54): mark a window-close approval consumed.

        Single-use: after a human_approval close succeeds, the record
        is flagged and re-MACed (F38 pattern — the digest was verified
        by _verify_close_approval immediately before this mutation, so
        the re-MAC seals the flag; flipping it back breaks the MAC and
        is refused, per the F57 ticket-consumption precedent). The
        consumption is crash-atomic via the queue's _rewrite (F83).
        Audited loudly (window_close_approval_consumed) so a reviewer
        can see which human decision closed which window entry.
        """
        from .approvals import (approval_digest_ok,
                                approval_record_digest)
        from datetime import datetime, timezone

        def _mark(records):
            out = []
            for r in records:
                if r.get("id") == approval_id:
                    if not approval_digest_ok(r):
                        raise ValueError(
                            "refusing to consume approval %r: digest "
                            "invalid at consume time" % (approval_id,))
                    r = dict(r)
                    r["window_close_consumed"] = True
                    r["window_close_consumed_at"] = datetime.now(
                        timezone.utc).isoformat()
                    r["window_close_consumed_window"] = window_id
                    r["args_digest"] = approval_record_digest(r)
                out.append(r)
            return out
        self.approvals._rewrite(_mark)
        self.log.append({
            "event": "window_close_approval_consumed",
            "run_id": self.run_id, "agent_id": "system",
            "role": "system", "decision": "consumed",
            "policy_id": "sterile-window-close",
            "approval_id": approval_id, "window": window_id,
            "reason": "Window-close approval %s consumed closing "
                      "window %r (single-use, F124)." % (approval_id,
                                                        window_id),
        })

    def _resolve_engine(self):
        """The policy engine for a new call. On the governed path the
        store owns the live engine (changed only by
        ``GovernedPolicyStore.apply``); otherwise the constructor's
        engine. Never reads the policy file."""
        if self._policy_store is not None:
            return self._policy_store.current_engine()
        return self.policy

    def call(self, identity, tool, **kwargs):
        """Run one tool call through the governance pipeline."""
        if not isinstance(identity, AgentIdentity):
            raise TypeError("identity must be an AgentIdentity minted by "
                            "this executor, got %r" % type(identity).__name__)

        # Wave-75 (governing the governors): snapshot the policy engine
        # at call start. On the governed path this is the store's
        # current engine; the verdict path below runs against this
        # snapshot so a policy applied between two calls never mixes
        # versions within one verdict. Atomic swap in the store means
        # every read sees exactly one version — no torn reads.
        policy = self._resolve_engine()

        # F17: fail-closed ledger. The egress ledger is this run's
        # cross-run taint/campaign memory; if it cannot be authenticated
        # (tampered, forged, truncated past its checkpoint) the executor
        # refuses to proceed — an unverifiable ledger must never read as
        # "no taint". The refusal is audit-logged, then raised: loud, not
        # a silent policy verdict.
        try:
            self._ledger.require_verified()
        except LedgerUnverifiableError as e:
            self.log.append({
                "event": "tool_call",
                "run_id": identity.run_id,
                "agent_id": identity.agent_id,
                "role": identity.role,
                "principal": identity.principal,
                "tool": tool,
                "decision": "denied",
                "policy_id": "ledger-unverifiable",
                "flag": "ledger_unverifiable",
                "policy_version": getattr(policy, "policy_version",
                                         "unversioned"),
                "matched_rules": [],
                "reason": "Refusing to act: %s" % e,
            })
            raise

        # Wave-77 (recovery): external halt latch, checked on the
        # verdict path before anything agent-influenced runs. Sticky
        # (the canary pattern): a halted identity stays refused for
        # every subsequent call. Fail-closed: a controller error reads
        # as halted, never as "no halt".
        if self._recovery is not None:
            try:
                _halted = bool(
                    self._recovery.is_halted(identity.agent_id))
                _halt_err = None
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                _halted = True
                _halt_err = e
            if _halted:
                self.log.append({
                    "event": "tool_call",
                    "run_id": identity.run_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role,
                    "principal": identity.principal,
                    "tool": tool,
                    "decision": "denied",
                    "policy_id": "recovery-halt",
                    "flag": "recovery_halted",
                    "policy_version": getattr(policy, "policy_version",
                                              "unversioned"),
                    "matched_rules": [],
                    "reason": ("Refusing to act: identity is halted by "
                               "the external recovery controller%s"
                               % (" (controller error: %s; treating as "
                                  "halted)" % _halt_err
                                  if _halt_err is not None else "")),
                })
                from .recovery import RecoveryHaltedError
                raise RecoveryHaltedError(
                    "identity %r is halted (external recovery "
                    "controller)" % identity.agent_id)

        # Wave-78 (capability leases): kill ambient authority. When a
        # lease verifier is installed and the tool is lease-gated, the
        # call must present a valid lease — verified AT USE TIME, on
        # this path, before policy evaluation. No lease (or a bad one)
        # is fail-closed and loud: the refusal is audit-logged and
        # raised, never a silent policy verdict. The lease's task_id
        # binding is checked against the task_id framing kwarg the
        # caller asserts (a lease minted for another task is refused).
        if (self._lease_verifier is not None
                and tool in self._lease_gated_tools):
            _lease = kwargs.pop("lease", None)
            _task_id = kwargs.get("task_id")
            try:
                _lease_id = self._lease_verifier.require(
                    _lease, agent_id=identity.agent_id, task_id=_task_id,
                    tool=tool)
                _lease_err = None
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                _lease_id, _lease_err = None, e
            if _lease_err is not None:
                self.log.append({
                    "event": "tool_call",
                    "run_id": identity.run_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role,
                    "principal": identity.principal,
                    "tool": tool,
                    "decision": "denied",
                    "policy_id": "capability-lease",
                    "flag": "lease_refused",
                    "policy_version": getattr(policy, "policy_version",
                                              "unversioned"),
                    "matched_rules": [],
                    "lease_id": (_lease.get("lease_id")
                                 if isinstance(_lease, dict) else None),
                    "reason": ("Refusing to act: capability lease check "
                               "failed: %s" % _lease_err),
                })
                from .capability_leases import LeaseRefused
                raise LeaseRefused(
                    "capability lease refused for tool %r: %s"
                    % (tool, _lease_err))

        # Framing kwargs are agent-supplied metadata, never trusted inputs.
        justification = kwargs.pop("justification", None)
        on_behalf_of = kwargs.pop("on_behalf_of", None)
        delegated_by = kwargs.pop("delegated_by", None)
        # P10: a delegation grant id is a server-side handle, never a
        # tool arg — popped here so it never reaches DLP scanning,
        # policy matching, or the tool itself.
        delegation_grant_id = kwargs.pop("delegation_grant_id", None)
        # Wave-79 (pre-commit): a pre-commit approval id is a
        # server-side handle, never a tool arg — popped here so it
        # never reaches DLP scanning, policy matching, or the tool.
        # The digest binds the REMAINING kwargs (the exact args the
        # tool will receive).
        precommit_approval_id = kwargs.pop("precommit_approval_id", None)
        delegation_attempted = bool(on_behalf_of or delegated_by)
        # P10: the verify_invocation ok-dict for a presented grant,
        # filled by the delegation gate below; drives dual attribution
        # in the audit entry. None = no grant presented (or not yet
        # verified).
        delegation_verified = None

        # Wave-74 (identity): three-token delegation gate. When the
        # deployment installed a DelegationContext (the session's
        # user/agent/delegation tokens), the permission-intersection check
        # runs BEFORE policy evaluation and lives in CODE, not policy
        # text: rewriting the policy YAML to allow-all cannot disable it
        # (pinned by redteam.identity_w74.missing_delegation_fails_closed).
        # Policy text still narrows afterwards — the gate only filters,
        # policy can further deny. The refusal is audit-logged, then
        # raised: loud, never a silent policy verdict.
        if self._delegation_context is not None:
            try:
                _delegation_gate = _delegation_tokens.enforce_tool_call(
                    self._delegation_context, identity, tool)
            except _delegation_tokens.DelegationError as e:
                self.log.append({
                    "event": "tool_call",
                    "run_id": identity.run_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role,
                    "principal": identity.principal,
                    "tool": tool,
                    "decision": "denied",
                    "policy_id": "delegation-required",
                    "flag": "delegation_gate_refused",
                    "policy_version": getattr(policy, "policy_version",
                                              "unversioned"),
                    "matched_rules": [],
                    "reason": ("Refusing to act: %s: %s"
                               % (type(e).__name__, e)),
                })
                raise

        # Wave-51 P1 egress canaries: tripwire on the egress-attempt path,
        # BEFORE the policy decision. A canary is never a legitimate
        # destination or credential, so any use is exfiltration intent by
        # construction — halt fail-closed (CanaryTripHalt), LOUD audit,
        # approval-queue escalation. No-op when canary_registry is None.
        # Persistent halt: once tripped, the run stays halted server-side
        # — catching CanaryTripHalt and calling again still raises — and
        # the halt survives executor restarts via the marker file
        # (wave-52 RT19), so a fresh executor over the same run dir
        # starts halted.
        if getattr(self, "_canary_halted", False):
            raise _canary.CanaryTripHalt(
                "Run halted by canary tripwire: a previous egress attempt "
                "used a planted canary. The run is halted fail-closed and "
                "cannot be resumed by retrying.")
        try:
            _canary.check_and_trip(self, identity, tool, kwargs)
        except _canary.CanaryTripHalt:
            self._canary_halted = True
            try:
                self._canary_halt_marker.write_text("halted\n")
            except OSError:
                pass  # marker is best-effort; the flag + audit stand
            raise

        self.counters[tool] = self.counters.get(tool, 0) + 1
        # S4: every call() attempt that reaches here consumes step budget
        # (denied/queued attempts included).
        self._total_calls += 1
        repeat_key = (tool, json.dumps(kwargs, sort_keys=True, default=str))
        self._repeats[repeat_key] = self._repeats.get(repeat_key, 0) + 1

        blocked, blocking_rule, redacted_args, redactions = dlp.scan_tool_args(
            tool, kwargs)

        # Evaluation-context snapshot (the "decision input"): attached to
        # every downstream decision entry so offline tools (the policy
        # simulator, incident review) can replay exactly what the engine
        # saw, without re-running the run. Mirrors OPA decision logs'
        # (input, result) pairing. Entries logged before policy evaluation
        # (identity/role/DLP/rate-guard rejections) carry None.
        policy_ctx_snapshot = None

        def _base(extra):
            entry = {
                "event": "tool_call",
                "run_id": identity.run_id,
                "agent_id": identity.agent_id,
                "role": identity.role,
                "principal": identity.principal,
                "tool": tool,
                "args": redacted_args,
                "redactions_applied": redactions,
                "provenance": ("untrusted_influenced" if self._tainted
                               else "agent_direct"),
                "delegation_attempted": delegation_attempted,
                # P10 dual attribution (spec §1.4): a verified grant's
                # id, delegator, and scope ride on every tool_call entry
                # for the call. None when no grant was presented.
                "delegation_grant_id": (delegation_verified["grant_id"]
                                        if delegation_verified else None),
                "delegator": (delegation_verified["delegator"]
                              if delegation_verified else None),
                "delegation_scope": (delegation_verified["scope_tools"]
                                     if delegation_verified else None),
                "policy_context": policy_ctx_snapshot,
                # Wave-75 (governing the governors): the digest of the
                # engine that decided this call. The snapshot is taken
                # at call entry (_resolve_engine), so every entry on
                # this call's verdict path — including pre-evaluation
                # rejections — names the exact engine version in force:
                # "which rule decided this" stays answerable across a
                # policy swap. Separate from policy_context (the
                # decision INPUT, None before evaluation).
                "policy_hash": policy.policy_hash,
                # Wave-76 (detection): the wave-74 three-token refs on
                # the live call path, so the monitor's per-identity
                # baselines key to user/agent/delegation refs exactly
                # as the provenance v2 slots do. None when no bound
                # delegation context is installed (the monitor falls
                # back to the agent-side identity key).
                "identity_token_refs": self._identity_token_refs,
                # Wave-79 (totality): every verdict-path entry carries
                # the governing policy version and the list of rules
                # that fired. The default is the honest structural
                # value — no policy rule has fired yet on the
                # pre-evaluation path — and the post-evaluation
                # entries override matched_rules with the decision's
                # list via `extra` (entry.update(extra) below).
                "policy_version": getattr(policy, "policy_version",
                                          "unversioned"),
                "matched_rules": [],
            }
            if self._tainted:
                entry["taint_detail"] = (
                    "source_untrusted: prior tool output (%s) may influence "
                    "this call" % ",".join(self._taint_sources))
            entry.update(extra)
            return entry

        # 1. identity ------------------------------------------------------
        id_deny = self._check_identity(identity)
        if id_deny is not None:
            policy_id, flag, reason = id_deny
            entry = self.log.append(_base({
                "agent_id": "unverified",
                "role": "unverified",
                "principal": "unverified",
                "claimed_identity": {"agent_id": identity.agent_id,
                                     "role": identity.role},
                "decision": "denied",
                "policy_id": policy_id,
                "flag": flag,
                "reason": reason,
            }))
            return {"status": "denied", "reason": reason,
                    "policy_id": policy_id, "seq": entry["seq"]}

        # P10 (wave-26): governed authority delegation. Runs after
        # identity verification (the store's delegatee-match check and
        # its audit attribution need a real minted identity) and before
        # policy evaluation:
        # * a presented grant id is verified against the server-side
        #   store (existence, integrity, expiry, revocation, delegatee
        #   match, scope, chain, run binding, single-use). Any refusal
        #   denies the call fail-closed; the store audits the exact
        #   machine-readable reason (delegation_invocation_refused).
        # * framing kwargs WITHOUT a grant id are policy-governed:
        #   unscoped_delegation: deny refuses them here (policy_id
        #   delegation-unscoped); the flag default keeps today's
        #   label-only behavior (spec §7 non-goal while disabled).
        # A store ERROR (not a refusal) also denies the call
        # fail-closed: an unverifiable delegation state must never
        # read as "no delegation claim".
        if delegation_grant_id is not None:
            try:
                delegation_verified = (
                    self._delegation_store.verify_invocation(
                        delegation_grant_id, identity, tool, kwargs,
                        tainted=self._tainted,
                        taint_sources=self._taint_sources))
            except DelegationError as e:
                entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": "delegation-grant-refused",
                    "flag": "delegation_refused",
                    "reason": ("Delegation grant refused: %s (%s)."
                               % (e, e.reason)),
                    "delegation_refusal_reason": e.reason,
                }))
                return {"status": "denied", "reason": entry["reason"],
                        "policy_id": "delegation-grant-refused",
                        "seq": entry["seq"]}
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                return self._delegation_store_error(_base, identity,
                                                    tool, e)
        elif delegation_attempted:
            try:
                framing = self._delegation_store.check_unscoped_framing(
                    on_behalf_of=on_behalf_of, delegated_by=delegated_by,
                    identity=identity)
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                return self._delegation_store_error(_base, identity,
                                                    tool, e)
            if not framing.get("allowed", True):
                entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": framing.get("policy_id",
                                             "delegation-unscoped"),
                    "flag": framing.get("flag",
                                        "unscoped_delegation_denied"),
                    "reason": framing.get(
                        "reason",
                        "Unscoped delegation framing denied by policy."),
                }))
                return {"status": "denied", "reason": entry["reason"],
                        "policy_id": entry["policy_id"],
                        "seq": entry["seq"]}

        # 1b. sterile windows (wave-53 P1) --------------------------------
        # Executor-side critical-window enforcement: entry on
        # tool-pattern match, input-channel refusal while a window is
        # open. Runs after identity + delegation verification
        # (unverified callers never mutate window state) and before
        # role/DLP/policy evaluation. No critical_windows block =
        # self.sterile is None = zero behavior change.
        sterile_refusal = self._sterile_gate(identity, tool)
        if sterile_refusal is not None:
            return sterile_refusal

        # 2. role allowlist ------------------------------------------------
        if not policy.role_allows(identity.role, tool):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "role-allowlist",
                "flag": "role_allowlist_violation",
                "reason": "Role %r is not allowed to use tool %r "
                          "(least privilege)." % (identity.role, tool),
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "role-allowlist", "seq": entry["seq"]}

        # 3. DLP credential block ------------------------------------------
        if blocked:
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "dlp-credential-block",
                "flag": "credential_block",
                "reason": "Blocked by DLP rule %s: credential-like material "
                          "in tool arguments." % blocking_rule,
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "dlp-credential-block", "seq": entry["seq"]}

        # 4. rate / volume guards ------------------------------------------
        rl = policy.rate_limit or {}
        if self._repeats[repeat_key] > int(rl.get("max_identical_calls", 10)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "loop-guard",
                "flag": "loop_guard",
                "reason": "Repeated identical %s call %d times; possible runaway "
                          "loop." % (tool, self._repeats[repeat_key]),
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "loop-guard", "seq": entry["seq"]}
        # F33 (HARDENING-R8): the send budget counts EXECUTIONS, not
        # attempts — each approved send is counted exactly once, at
        # execution time. Queued-but-unexecuted sends consume no budget
        # (the old code counted an approved send at call() AND at
        # execute_approved(), making the budget unpredictable).
        exec_sends = (self._executed.get("send_email", 0)
                      + self._executed.get("http_post", 0))
        if tool in _SEND_TOOLS and exec_sends >= int(
                rl.get("max_sends_per_run", 10)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "volume-guard-sends",
                "flag": "volume_guard",
                "reason": "Per-run send budget exceeded (%d sends executed)."
                          % exec_sends,
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "volume-guard-sends", "seq": entry["seq"]}
        # F33: cumulative egress byte budget. Enforced on the PROJECTED
        # bytes at the call boundary (before queue/execute) and re-checked
        # at actual execution in execute_approved (TOCTOU guard).
        if tool in _EGRESS_TOOLS:
            budget = self._max_egress_bytes()
            call_bytes = self._egress_bytes_for(tool, kwargs)
            if self._egress_bytes + call_bytes > budget:
                entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": "volume-guard-egress-bytes",
                    "flag": "volume_guard",
                    "reason": ("Per-run egress byte budget exceeded: this "
                               "call would move %d bytes (projected total "
                               "%d > budget %d)."
                               % (call_bytes,
                                  self._egress_bytes + call_bytes, budget)),
                }))
                return {"status": "denied", "reason": entry["reason"],
                        "policy_id": "volume-guard-egress-bytes",
                        "seq": entry["seq"]}
        if tool == "write_file" and self.counters.get("write_file", 0) > int(
                rl.get("max_writes_per_run", 50)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "volume-guard-writes",
                "flag": "volume_guard",
                "reason": "Per-run write budget exceeded.",
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "volume-guard-writes", "seq": entry["seq"]}
        if tool == "delete_file" and self.counters.get("delete_file", 0) > int(
                rl.get("max_deletes_per_run", 20)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "volume-guard-deletes",
                "flag": "volume_guard",
                "reason": "Per-run delete budget exceeded.",
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "volume-guard-deletes", "seq": entry["seq"]}

        # S4 (K-045): total-step budget per run. Counts attempts
        # (denied/queued included) — it is a budget on run activity and
        # log growth, the stated motivation. The `>` (not `>=`) matches
        # the existing write/delete guard convention: exactly N calls
        # are allowed. Absent key = unenforced. Checked before policy
        # evaluation, like every other step-4 guard.
        _run_limits = getattr(policy, "run_limits", None) or {}
        _max_tool_calls = _run_limits.get("max_tool_calls_per_run")
        if (_max_tool_calls is not None
                and self._total_calls > _max_tool_calls):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "step-budget",
                "flag": "step_budget_exceeded",
                "reason": ("Per-run step budget exceeded (%d tool calls, "
                           "max %d)." % (self._total_calls, _max_tool_calls)),
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "step-budget", "seq": entry["seq"]}

        # S2 (K-018): hard spend/token/action budgets — guard 4b. Sits
        # after the F33 guards and before policy evaluation, so no
        # compiled DSL rule or policy allow-rule can override a blown
        # budget. Token/spend accrue on the RESULT path only (never call
        # kwargs); ceilings use >= on the accrued totals: the call that
        # crosses the ceiling completes (you cannot un-call a provider)
        # and the NEXT call is denied. Absent budgets key = unenforced.
        _budgets = getattr(policy, "budgets", None) or {}
        if _budgets:
            # Count every call() invocation that reaches this guard.
            self._budget_actions += 1
            _budget_deny_reason = None
            _max_actions = _budgets.get("max_actions_per_run")
            if (_max_actions is not None
                    and self._budget_actions > _max_actions):
                _budget_deny_reason = (
                    "Per-run action budget exceeded (%d actions, max %d)."
                    % (self._budget_actions, _max_actions))
            _max_tokens = _budgets.get("max_tokens_per_run")
            if (_budget_deny_reason is None and _max_tokens is not None
                    and self._tokens_used >= _max_tokens):
                _budget_deny_reason = (
                    "Per-run token budget reached (%d tokens accrued, max "
                    "%d); the call that crossed the ceiling completed, "
                    "further calls are denied."
                    % (self._tokens_used, _max_tokens))
            _max_spend = _budgets.get("max_spend_per_run")
            if (_budget_deny_reason is None and _max_spend is not None
                    and self._spend_used >= _max_spend):
                _budget_deny_reason = (
                    "Per-run spend budget reached (%.4f accrued, max "
                    "%.4f); the call that crossed the ceiling completed, "
                    "further calls are denied."
                    % (self._spend_used, _max_spend))
            if _budget_deny_reason is not None:
                entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": "budget-exceeded",
                    "flag": "budget_exceeded",
                    "reason": _budget_deny_reason,
                }))
                return {"status": "denied", "reason": entry["reason"],
                        "policy_id": "budget-exceeded", "seq": entry["seq"]}

        # S3 (K-041): an unrated mutating tool is never allowed silently.
        # _MUTATING_TOOLS names the known mutating tools (api_call is
        # read-classified per F1; read_file is non-mutating). A tool the
        # ratings table has never seen is assumed mutating — fail-closed
        # default: a new tool graduates to autonomous only through an
        # explicit deployment rating. Force the existing
        # require_approval path with a synthetic decision (reuses the
        # queue machinery: F12 preview, F21 flag). Core-tool behavior is
        # unchanged (their default ratings preserve today's allow
        # paths, e.g. benign-coder sandbox writes).
        _forced_require_approval = None
        if tool not in self._tool_ratings and (
                tool in _MUTATING_TOOLS
                or tool not in ("read_file", "api_call")):
            _forced_require_approval = PolicyDecision(
                "require_approval",
                "Tool %r is mutating but has no reversibility/impact "
                "rating; human review is required before its first "
                "autonomous use (rate it via the deployment tool_ratings "
                "to graduate it)." % (tool,),
                policy_id="tool-rating-default",
                flag="unrated_mutating_tool",
            )

        # 5. policy evaluation ----------------------------------------------
        action = {"tool": tool, "args": kwargs,
                  "identity": identity.as_dict(),
                  "role": identity.role, "agent_id": identity.agent_id}
        ctx = self._context(tool, kwargs, principal=identity.principal,
                              agent_id=identity.agent_id)
        policy_ctx_snapshot = {
            "path_outside_sandbox": ctx.get("path_outside_sandbox"),
            "domain_allowlisted": ctx.get("domain_allowlisted"),
            "carries_read_content": ctx.get("carries_read_content"),
            "read_sensitive": ctx.get("read_sensitive"),
            "cross_run_campaign": ctx.get("cross_run_campaign"),
            "velocity_exceeded": ctx.get("velocity_exceeded"),
            "source_untrusted": ctx.get("source_untrusted"),
            # F99: the framed-secret signal rides the snapshot so replay
            # sees exactly what the engine saw (None when the tool is not
            # api_call — bool(None) == bool(False), the engine's semantics).
            "high_entropy_payload": ctx.get("high_entropy_payload"),
            # P7 (wave-27): the governed-install gates ride the same
            # snapshot so offline replay sees exactly what the engine
            # saw (None when the tool does not compute them).
            "package_fetch": ctx.get("package_fetch"),
            "install_allowlisted": ctx.get("install_allowlisted"),
            "install_integrity_verified": ctx.get("install_integrity_verified"),
            # F111 (wave-34): the identity-bound egress signal rides the
            # snapshot so offline replay sees exactly what the engine
            # saw (None when the tool is not a send/api_call tool —
            # bool(None) == bool(False), the engine's semantics).
            "credential_identity_mismatch": ctx.get(
                "credential_identity_mismatch"),
            # F110 (wave-34): the harness-initiated platform-egress
            # signal. ToolExecutor._context never sets it (it is set
            # only by gov/platform_egress.py on its own direct policy
            # calls, which are not tool calls and leave no action-log
            # snapshot); None here is the honest snapshot — the engine
            # evaluates it as False for every tool call.
            "platform_egress": ctx.get("platform_egress"),
            "counters": dict(ctx.get("counters") or {}),
        }
        decision = policy.evaluate(action, ctx)

        # S3 (K-041) wired wave-39: S3-GAP-1 closed. An unrated mutating
        # tool must never execute on a policy allow alone — the forced
        # require_approval downgrades an allow to queued human review.
        # Fail-closed direction only: a deny stays denied (already safe)
        # and an existing require_approval is untouched. The audit trail
        # shows policy_id "tool-rating-default" + flag
        # "unrated_mutating_tool" so the forcing is visible in the log.
        if (_forced_require_approval is not None
                and decision.effect == "allow"):
            decision = _forced_require_approval

        # Wave-76 (detection): behavioral circuit breaker. When the
        # monitor's breaker is OPEN for the acting identity, an allow
        # verdict on a high-risk tool is downgraded to require_approval
        # (fail-closed direction only: a deny stays denied, an existing
        # require_approval is untouched). The queued action still
        # carries the agent's own executor-minted identity -- it is the
        # ROUTING that changed. Fail-closed: a monitor error is treated
        # as OPEN (an unverifiable detector must never read as "no
        # drift"). No monitor installed = zero behavior change.
        if (decision.effect == "allow"
                and self._detection_monitor is not None):
            try:
                _route = self._detection_monitor.route_action(
                    identity, tool)
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                _route = "queue"
                self.log.append(_base({
                    "decision": "breaker_fail_closed",
                    "policy_id": "detection-breaker",
                    "flag": "detection_monitor_unreachable",
                    "matched_rules": [],
                    "reason": ("Detection monitor unreachable (%s); "
                               "treating breaker as OPEN." % e),
                }))
            if _route == "queue":
                decision = PolicyDecision(
                    "require_approval",
                    ("Behavioral circuit breaker is OPEN for this "
                     "identity; human review is required before "
                     "execution (wave-76 detection)."),
                    policy_id="detection-breaker",
                    flag="behavioral_breaker_open",
                )
            elif _route == "half_open_probe":
                decision = PolicyDecision(
                    "require_approval",
                    ("Behavioral circuit breaker is HALF-OPEN for this "
                     "identity (human reset); this action is admitted "
                     "as a measured half-open probe (wave-76 "
                     "detection)."),
                    policy_id="detection-breaker",
                    flag="behavioral_breaker_half_open",
                )

        # Wave-79 (rules tiering): lethal-trifecta approval floor.
        # Opt-in via trifecta_floor= (default off: zero behavior
        # change). The session's tier is computed over its EFFECTIVE
        # grants (role tools ∪ verified delegation scope) — the
        # composition rule (design §1(d)): a parent holding two axes
        # whose child adds the third trips elevated at the child's
        # first external call, with wave-74's strict attenuation
        # untouched. When elevated, external-communication tools
        # require human approval even when the policy allows: the floor
        # bites only where the policy would otherwise allow silently
        # (deny still denies; require_approval already queues). The
        # first elevated call in a session chains a loud tier_escalated
        # record (once per session). The override appends the reserved
        # "trifecta-tier-floor" sentinel to matched_rules so the
        # forcing is visible in the log next to the engine's rules.
        if decision.effect == "allow" and self._trifecta_floor:
            _tier_grants = _rules_tiering.effective_grants(
                role_tools=(getattr(policy, "roles", None) or {}).get(
                    identity.role) or (),
                delegation_scope=(delegation_verified["scope_tools"]
                                  if delegation_verified else ()),
            )
            _tier, _tier_axes = _rules_tiering.session_tier(_tier_grants)
            if (_tier == _rules_tiering.TIER_ELEVATED
                    and identity.run_id
                    not in self._trifecta_escalated_sessions):
                self._trifecta_escalated_sessions.add(identity.run_id)
                self.log.append(_base({
                    "decision": "tier_escalated",
                    "policy_id": "trifecta-tier",
                    "flag": "trifecta_tier_escalated",
                    "reason": ("Lethal-trifecta oversight tier: this "
                               "session's effective grants hold all three "
                               "axes (private-data + untrusted-content + "
                               "external-comm); external-communication "
                               "tools now require human approval "
                               "(wave-79 rules tiering)."),
                    "tier": _rules_tiering.TIER_ELEVATED,
                    "tier_axes": sorted(_tier_axes),
                }))
            if _rules_tiering.floor_applies(_tier_grants, tool,
                                            decision.effect):
                decision = PolicyDecision(
                    "require_approval",
                    ("Lethal-trifecta approval floor: this session holds "
                     "the private-data + untrusted-content + "
                     "external-comm trifecta, so the external-"
                     "communication tool %r requires human approval even "
                     "though the policy allows it (wave-79 rules "
                     "tiering)." % tool),
                    policy_id=decision.policy_id,
                    flag="trifecta_floor",
                    matched_rules=(list(decision.matched_rules)
                                   + [_rules_tiering
                                      .TRIFECTA_FLOOR_SENTINEL]),
                )

        # Wave-79 (pre-commit): irreversible tools on the allow path.
        # When the gate is installed, an irreversible tool (the frozen
        # gov/precommit registry) executing on a policy ALLOW must
        # present a bound, unused pre-commit approval for the EXACT
        # (tool, args) — otherwise denied fail-closed BEFORE the tool
        # executes. The digest binds the post-framing-pop kwargs, i.e.
        # exactly what the tool would receive. The require_approval
        # path still queues for a human (the queue's MAC-bound approval
        # is the human moment there); deny is unchanged.
        if (decision.effect == "allow"
                and self._precommit_gate is not None
                and _precommit.is_irreversible(tool)
                and not self._precommit_gate.check(
                    precommit_approval_id, tool, kwargs)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "precommit-required",
                "flag": "precommit_required",
                "matched_rules": [],
                "reason": ("Refusing to act: %r is an irreversible tool "
                           "and no bound, unused pre-commit approval for "
                           "the exact (tool, args) was presented "
                           "(wave-79 pre-commit gate: preview the action, "
                           "get human approval bound to the preview, then "
                           "commit)." % tool),
            }))
            return {"status": "denied",
                    "reason": entry["reason"],
                    "policy_id": "precommit-required",
                    "seq": entry["seq"]}

        if decision.effect == "allow":
            # Write-ahead audit (fail-closed): the authorization is durably
            # logged BEFORE the side effect. If this append raises, the tool
            # is never touched: no log, no side effect.
            auth_entry = self.log.append(_base({
                "decision": "execution_authorized",
                "policy_id": decision.policy_id,
                "matched_rules": decision.matched_rules,
                "reason": decision.reason,
                "flag": decision.flag,
            }))
            # Wave-79 (pre-commit, atomic): irreversible tools with the
            # gate installed consume their bound approval IN the commit
            # that executes them — a single-use ticket. The earlier
            # check() failed fast with a denied record; commit()
            # re-verifies and marks the ticket consumed before running
            # the thunk, so a second call presenting the same approval
            # id is refused (no replay through the executor).
            if (self._precommit_gate is not None
                    and _precommit.is_irreversible(tool)):
                result = self._precommit_gate.commit(
                    precommit_approval_id, tool, kwargs,
                    lambda: self._simulate(tool, kwargs, ctx))
            else:
                result = self._simulate(tool, kwargs, ctx)
            self._ingest_result(tool, result, identity.principal)
            if tool == "api_call":
                self.api_calls += 1
            # F33: charge the execution budgets exactly once, at execution
            # time (the allow path is an execution boundary).
            self._executed[tool] = self._executed.get(tool, 0) + 1
            self._egress_bytes += self._egress_bytes_for(tool, kwargs)
            # S5 (K-052): cross-run velocity memory — record the
            # execution. EgressLedger.append holds the F74 write lock
            # internally; S5 adds no competing lock. Fail-open with a
            # loud velocity_check_skipped audit on ledger trouble (the
            # call already executed).
            if tool in _VELOCITY_TOOLS:
                self._record_velocity(tool, identity.principal,
                                      identity.agent_id,
                                      self._egress_bytes_for(tool, kwargs))
            entry = self.log.append(_base({
                "decision": "allowed_executed",
                "policy_id": decision.policy_id,
                "matched_rules": decision.matched_rules,
                "reason": decision.reason,
                "flag": decision.flag,
                "result_summary": self._summarize(tool, result),
                "authorization_seq": auth_entry["seq"],
            }))
            return {"status": "executed", "result": result, "seq": entry["seq"]}

        if decision.effect == "deny":
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": decision.policy_id,
                "matched_rules": decision.matched_rules,
                "reason": decision.reason,
                "flag": decision.flag,
            }))
            return {"status": "denied", "reason": decision.reason,
                    "policy_id": decision.policy_id, "seq": entry["seq"]}

        # require_approval: queue for a human, do NOT execute.
        provenance = ("untrusted_influenced" if self._tainted
                      else "agent_direct")
        approval_action = {"tool": tool, "args": redacted_args,
                           "identity": identity.as_dict(),
                           "agent_justification": justification,
                           "redactions": redactions}
        approval_id = self.approvals.queue(
            approval_action, decision, provenance,
            # F12: the preview is built from the SAME redacted args that
            # will execute — preview, digest, and execution all agree.
            self._preview(tool, redacted_args),
            policy_hash=policy.policy_hash,
            delegation_attempted=delegation_attempted,
            # F101 (wave-26): a grant-verified call queues under the
            # ACTING (delegatee) identity — the verified grant id and
            # the delegating party ride on the approval record
            # (MAC-bound) so decide()/cast_vote() exclude the
            # intending party alongside the requester. Without this,
            # the delegator could approve the delegatee's queued
            # action by proxy, laundering the D1-core
            # requester-exclusion invariant.
            delegation_grant_id=(delegation_verified["grant_id"]
                                 if delegation_verified else None),
            delegation_delegator=(delegation_verified["delegator"]
                                  if delegation_verified else None),
            # F103 (wave-27): the full delegator lineage (root ->
            # immediate, resolved by verify_invocation from the
            # re-verified ancestor records) rides on the approval
            # record MAC-bound alongside the immediate delegator, so
            # decide()/cast_vote() exclude the whole intending
            # lineage — the F101 single-hop guard re-opens at
            # depth >= 2 without this.
            delegation_delegator_chain=(
                delegation_verified["delegator_chain"]
                if delegation_verified else None),
            policy_context=policy_ctx_snapshot,
            # F21: the queue reason travels with the record so batch
            # approval can refuse security items individually.
            policy_flag=decision.flag,
            # F33: raw outbound payload bytes at queue time (computed on
            # the RAW args at the call boundary — DLP redaction of the
            # queued form must never shrink the budget charge).
            egress_bytes=self._egress_bytes_for(tool, kwargs),
            # F42 (R11): the queue no longer trusts action["identity"]
            # (attacker-controlled dict) — the executor passes the real
            # minted AgentIdentity it received in call(). The queue
            # authenticates it and stamps the record from it.
            caller_identity=identity,
            # Wave-79 (totality): the governing policy version and the
            # rules that fired ride on the ticket, so the human's
            # decision record can name exactly what queued it.
            policy_version=getattr(policy, "policy_version", "unversioned"),
            matched_rules=decision.matched_rules)
        entry = self.log.append(_base({
            "decision": "queued_pending",
            "policy_id": decision.policy_id,
            "matched_rules": decision.matched_rules,
            "reason": decision.reason,
            "flag": decision.flag,
            "approval_id": approval_id,
        }))
        # Low-risk auto-approval: only fires when the ACTIVE policy
        # explicitly opts in (auto_approve.enabled + risk cap). The audit
        # record is identical to a human approval. Wave-79: disabled for
        # irreversible tools while the pre-commit gate is installed —
        # the human moment must be real, never auto-approved.
        auto = None
        if not (self._precommit_gate is not None
                and _precommit.is_irreversible(tool)):
            auto = self.approvals.maybe_auto_approve(
                approval_id, policy.auto_approve)
        if auto is not None:
            executed = self.execute_approved()
            return {"status": "auto_approved_executed",
                    "approval_id": approval_id,
                    "policy_id": decision.policy_id,
                    "reason": auto.get("decision_reason"),
                    "seq": entry["seq"],
                    "executed": [d["seq"] for d in executed]}
        return {"status": "queued", "approval_id": approval_id,
                "policy_id": decision.policy_id,
                "reason": decision.reason, "seq": entry["seq"]}

    # -- approved-action execution ------------------------------------------

    def _approval_expired(self, rec, ttl_hours):
        try:
            decided = datetime.fromisoformat(rec["decided_at"])
        except Exception:
            return True  # unparseable timestamp: fail closed
        if decided.tzinfo is None:
            decided = decided.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - decided).total_seconds()
        return age > ttl_hours * 3600

    def execute_approved(self):
        """Execute approved-but-not-yet-executed actions.

        Each approval is re-validated at execution time: expiry, integrity
        of the queued arguments, the run it was approved for (F38), the
        policy it was approved under, and a fresh policy evaluation. Any
        failure refuses the execution and logs why. Returns the list of
        executed actions.

        D1 bridges (wave-24): records queued via
        ``ApprovalQueue.queue_external`` carry ``bridge_id`` and are
        FOREIGN-EXECUTED — the bridge's runtime executes on its side, so
        this sweep never executes them (bridge_expired ones are refused
        loudly per T12/F85; the rest are skipped after the integrity
        checks).

        F39: the whole sweep runs under the approval queue's exclusive
        lock (``ApprovalQueue._queue_locked``) — the read-claim-
        execute-mark sequence is atomic across threads and processes, so
        a second concurrent sweep re-reads the queue only after the first
        has marked its records and skips them. Lock ordering: queue lock
        (outer) -> action-log lock (inner), never reversed. A lock
        timeout refuses the sweep fail-closed (``QueueLockError``) and is
        audited — the sweep never runs unlocked.
        """
        # F17: an unverifiable ledger refuses even approved executions —
        # the taint/campaign memory the approval was granted under cannot
        # be trusted.
        self._ledger.require_verified()
        try:
            with self.approvals._queue_locked():
                return self._execute_approved_locked()
        except QueueLockPathError as e:
            # F51 (R12): the lock path is not a usable lock file (e.g.
            # a directory swapped in at approvals.lock). Fail closed
            # WITH audit — never an uncaught IsADirectoryError — and
            # absorb as an empty sweep: no exception escapes, approved
            # work waits for the next sweep instead of starving on an
            # unaudited crash.
            self._audit_lock_refusal("queue_lock_invalid",
                                     "execute_approved() refused: %s" % e)
            return []
        except QueueLockInvalidatedError as e:
            # F44 (R11): the lock file was deleted or replaced while we
            # waited — the lock may be guarding a different queue state.
            # Fail closed with a DISTINCT audit event so operators can
            # tell invalidation apart from a mere timeout.
            self._audit_lock_refusal("queue_lock_invalidated",
                                     "execute_approved() refused: %s" % e)
            raise
        except QueueLockError as e:
            # Fail closed AND audited: the sweep is refused, nothing
            # executed, the lock holder keeps its atomicity.
            self._audit_lock_refusal("queue_lock_timeout",
                                     "execute_approved() refused: %s" % e)
            raise

    # F51 (R12): at most one lock-refusal audit entry per
    # _LOCK_REFUSAL_AUDIT_COALESCE_SECS seconds per run; repeats in
    # between are counted, not logged, so a sustained disturbance
    # (unlink loop) cannot flood the tamper-evident log. The next
    # audited entry carries suppressed_repeats, and a storm (>= 10
    # folded repeats) is flagged for the operator.
    #
    # F69 (R16): the F60 fallback's full chain verification is O(log
    # size) per refused sweep -- a CPU amplifier while the sidecar is
    # held corrupt. _log_shows_recent_lock_refusal now verifies
    # incrementally from a MAC-authenticated chain-tip cache
    # (``actions.jsonl.tip.json``); see gov/log.py verify_chain_tip.
    # A missing/corrupt tip, a shrunk log, or any segment failure
    # falls back to full verification (fail-loud, never silent).
    #
    # F60 (R14): the coalescing window is NOT per-instance memory
    # anymore — it lives in a small state file in the run dir
    # (``lock_refusal_coalesce.json``), so it survives executor
    # rotation (a fresh executor per sweep, or multi-process sweeps
    # sharing the run dir). The file is tiny and bounded: one record
    # per known refusal flag. Read-modify-write runs under an
    # exclusive flock on a sibling lock file.
    #
    # A missing/corrupt state file does NOT degrade to "audit once
    # and recreate" anymore — that let a corruption loop re-audit
    # every sweep (F60). Instead the suppression decision is derived
    # from the tamper-evident action log itself (see
    # _log_shows_recent_lock_refusal): a recent
    # ``approval_sweep_refused`` entry for the flag means "already
    # audited within the window" — the sweep still refuses
    # fail-closed, but the re-audit is suppressed and clean state is
    # rewritten best-effort. Only a genuinely fresh run (no recent
    # refusal in the log) audits once. If the shared state is
    # unreachable at all (OSError), the old per-instance coalescing is
    # used as a best-effort fallback, still never raising out of the
    # audit path.
    _LOCK_REFUSAL_AUDIT_COALESCE_SECS = 5.0
    _LOCK_REFUSAL_STORM_THRESHOLD = 10
    _LOCK_REFUSAL_STATE_FILENAME = "lock_refusal_coalesce.json"
    _LOCK_REFUSAL_STATE_LOCK_FILENAME = "lock_refusal_coalesce.lock"
    _LOCK_REFUSAL_KNOWN_FLAGS = ("queue_lock_invalid",
                                 "queue_lock_invalidated",
                                 "queue_lock_timeout")

    def _lock_refusal_state_path(self):
        return self.run_dir / self._LOCK_REFUSAL_STATE_FILENAME

    def _read_lock_refusal_state(self, state_path):
        """Read the shared coalescing state.

        Returns ``(state, usable)``: ``usable`` is False when the file
        is missing, unreadable, unparseable, or not a dict — the F60
        corruption shapes. Bounded: only known refusal flags are kept,
        values are coerced to (last_audit float, suppressed int).
        """
        try:
            raw = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}, False
        if not isinstance(raw, dict):
            return {}, False
        state = {}
        for flag in self._LOCK_REFUSAL_KNOWN_FLAGS:
            rec = raw.get(flag)
            if not isinstance(rec, dict):
                continue
            try:
                last_audit = float(rec.get("last_audit", 0.0))
                suppressed = int(rec.get("suppressed", 0))
            except (TypeError, ValueError):
                continue
            state[flag] = {"last_audit": last_audit,
                           "suppressed": max(0, suppressed)}
        return state, True

    def _write_lock_refusal_state(self, state_path, state):
        """Atomically persist the shared coalescing state (temp file +
        os.replace). Keeps only known flags: tiny and bounded."""
        bounded = {flag: state[flag]
                   for flag in self._LOCK_REFUSAL_KNOWN_FLAGS
                   if flag in state}
        tmp_path = state_path.with_name(state_path.name + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(bounded, ensure_ascii=True,
                               sort_keys=True))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, state_path)

    def _audit_lock_refusal(self, flag, reason):
        """Audit a lock-refusal, coalesced. Returns True when an entry
        was written, False when the refusal was folded into the
        suppressed counter."""
        now = time.monotonic()
        try:
            return self._audit_lock_refusal_shared(flag, reason, now)
        except OSError:
            # F56: the shared state file is unreachable (run dir gone,
            # read-only FS, ...). Degrade to the pre-R13 per-instance
            # coalescing — best effort, never an exception.
            return self._audit_lock_refusal_local(flag, reason, now)

    def _log_shows_recent_lock_refusal(self, flag):
        """F60 (R14) / F60-followup (R15) / F69 (R16): True when the
        tamper-evident action log already holds a CHAIN-VERIFIED
        ``approval_sweep_refused`` entry for ``flag`` inside the
        coalesce window.

        The log is append-only and HMAC-chained — the F52 run-dir
        writer cannot silently erase its refusal entries the way it
        can corrupt the sidecar state file — so a recent entry is a
        trustworthy "already audited" signal for the F60 fallback.

        F60-followup (R15): suppression now requires the log to verify
        (tolerant ``_verify`` with ``_skip_malformed=True``). The R14
        honest residual was real: a run-dir writer could PLANT a
        MAC-invalid ``approval_sweep_refused`` line and corrupt the
        state file to suppress the re-audit. Now a planted line -- or
        any tampered, broken, or otherwise unverifiable chain -- falls
        back to LOUD re-audit (return False here), never silent
        suppression. Malformed physical lines (non-JSON) are SKIPPED
        per the R14 poisoned-log rule: they cannot serve as
        suppression signals (they are not valid entries), so a merely
        corrupt line does not re-audit every sweep -- while a planted
        MAC-invalid line is valid JSON and still fails closed. The
        sweep still refuses fail-closed either way.

        F69 (R16): the full verification above is O(log size) per
        refused sweep while the sidecar is missing/corrupt — a CPU
        amplifier. The first attempt is now incremental
        (``verify_chain_tip``): only entries appended since the cached
        chain tip are re-verified, O(new entries). The tip cache is
        MAC-authenticated under the log key, so a run-dir writer
        cannot forge it; a missing/corrupt tip, a shrunk log, a tip
        mismatch, or any segment failure falls through to the full
        verification below (fail-loud, never silent suppression).
        After a full verification the tip is reseeded so the next
        sweep is incremental again.

        Malformed lines are skipped (F63); entries with unparseable or
        missing timestamps count as no-recent (fail-loud: at most one
        extra audit entry). Future-dated entries never suppress — only
        genuinely recent ones do.
        """
        window = self._LOCK_REFUSAL_AUDIT_COALESCE_SECS
        # R17: reset the tamper side channel on every call — the
        # caller reads it only when this method returns False.
        self._r17_tip_forced_error = None
        # F69 (R16): cheap path first -- verify only the entries since
        # the cached chain tip. verify_chain_tip() returns None for
        # every shape the tip cannot vouch for (missing/corrupt tip,
        # shrunk log, tip mismatch, segment or anchor failure); those
        # fall through to full verification below, never to trust.
        try:
            tip_verdict = verify_chain_tip(
                self.log.path, self._LOCK_REFUSAL_KNOWN_FLAGS)
        except OSError:
            return False
        if tip_verdict is not None:
            return refusal_ts_within_window(
                tip_verdict["refusals"].get(flag), window)
        # tip_verdict is None (tip unusable: missing/corrupt tip, shrunk
        # log, tip mismatch, segment or anchor failure): fall through to
        # the full verification below (fail-loud, never silent
        # suppression). A FAILED full verification records the error on
        # the R17 side channel so the caller audits the tamper loudly
        # with attribution (fail-loud, never folded into the normal
        # refusal coalescing).
        #
        # F63/R14: TOLERANT verification -- malformed physical lines
        # (non-JSON / non-object) are skipped, not failed. A malformed
        # line cannot serve as a suppression signal (it is not a valid
        # entry), so skipping it does not weaken the F60 guarantee;
        # failing on it would re-audit every sweep for a merely corrupt
        # line (the R14 poisoned-log shape). A planted MAC-invalid line
        # is valid JSON and still fails closed here.
        try:
            verdict = _verify(self.log.path, _skip_malformed=True)
        except OSError:
            return False
        if not verdict["ok"]:
            self._r17_tip_forced_error = (
                "chain does not verify (broken_seq=%r)"
                % (verdict.get("broken_seq"),))
            return False
        refusals = newest_refusal_ts_per_flag(
            self.log.path, self._LOCK_REFUSAL_KNOWN_FLAGS)
        try:
            # Seed the tip cache so the next refused sweep verifies
            # incrementally. Best-effort: a failed seed only costs the
            # next sweep a longer segment, never safety.
            write_chain_tip_from_tail(self.log.path, refusals)
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return refusal_ts_within_window(refusals.get(flag), window)

    def _audit_lock_refusal_shared(self, flag, reason, now):
        """F56: file-backed coalescing shared across executor instances
        (and processes) via the run-dir state file."""
        state_path = self._lock_refusal_state_path()
        lock_path = self.run_dir / self._LOCK_REFUSAL_STATE_LOCK_FILENAME
        self.run_dir.mkdir(parents=True, exist_ok=True)
        audited = False
        suppressed_total = 0
        with open(lock_path, "a", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                state, usable = self._read_lock_refusal_state(state_path)
                if not usable:
                    # F60 (R14): missing/corrupt state — the F52
                    # run-dir writer may be running a corruption loop.
                    # Treating "no state" as "never audited" re-audits
                    # every sweep. Derive suppression from the
                    # tamper-evident log instead: a recent refusal for
                    # this flag means "already audited within the
                    # window" — stay silent (the SWEEP still refuses
                    # fail-closed) and rewrite clean state
                    # best-effort so a transient corruption heals.
                    # Only a genuinely fresh run (no recent refusal in
                    # the log) audits once.
                    if self._log_shows_recent_lock_refusal(flag):
                        try:
                            # Record the refusal as already-audited at
                            # `now` so coalescing survives the heal:
                            # the next sweep reads usable state and
                            # folds instead of re-auditing.
                            self._write_lock_refusal_state(
                                state_path,
                                {flag: {"last_audit": now,
                                        "suppressed": 0}})
                        except OSError:
                            pass
                        # Mirror on the instance attrs
                        # (introspection / legacy readers).
                        self._lock_refusal_last_audit = now
                        self._lock_refusal_suppressed = 0
                        return False
                    # R17: the fallback full verification inside
                    # _log_shows_recent_lock_refusal found the chain
                    # BROKEN. Audit LOUD with tamper attribution,
                    # bypassing the normal coalescing below: a broken
                    # chain must never be folded silently, and every
                    # sweep while it stays broken must stay loud.
                    if self._r17_tip_forced_error is not None:
                        self._audit_lock_refusal_write(
                            flag,
                            "execute_approved() refused: fallback "
                            "full chain verification FAILED (%s) -- "
                            "pre-tip tamper suspected; %s"
                            % (self._r17_tip_forced_error, reason),
                            0)
                        self._lock_refusal_last_audit = now
                        self._lock_refusal_suppressed = 0
                        return True
                    rec = {"last_audit": 0.0, "suppressed": 0}
                else:
                    rec = state.get(flag) or {"last_audit": 0.0,
                                              "suppressed": 0}
                if (now - rec["last_audit"]
                        < self._LOCK_REFUSAL_AUDIT_COALESCE_SECS):
                    rec["suppressed"] += 1
                    state[flag] = rec
                    self._write_lock_refusal_state(state_path, state)
                    # Mirror the shared state on the instance attrs
                    # (introspection / legacy readers).
                    self._lock_refusal_last_audit = rec["last_audit"]
                    self._lock_refusal_suppressed = rec["suppressed"]
                    return False
                suppressed_total = rec["suppressed"]
                rec["last_audit"] = now
                rec["suppressed"] = 0
                state[flag] = rec
                self._write_lock_refusal_state(state_path, state)
                self._lock_refusal_last_audit = now
                self._lock_refusal_suppressed = 0
                # The audit entry goes out while the state lock is held
                # (lock order here is always state-lock -> log-lock, and
                # no path takes them in the reverse order), so two
                # racing processes cannot both decide to audit.
                self._audit_lock_refusal_write(
                    flag, reason, suppressed_total)
                audited = True
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        return audited

    def _audit_lock_refusal_write(self, flag, reason, suppressed_total):
        """Append one ``approval_sweep_refused`` audit entry.

        Extracted (R17) so the forced-verification loud path reuses
        the exact same entry shape. Callers hold the state-file lock.
        """
        self.log.append({
            "event": "approval_sweep_refused",
            "run_id": self.run_id,
            "decision": "refused",
            "policy_id": "approval-execution-refused",
            "flag": flag,
            "reason": reason,
            "suppressed_repeats": suppressed_total,
            "refusal_storm":
                suppressed_total >= self._LOCK_REFUSAL_STORM_THRESHOLD,
        })

    def _audit_lock_refusal_local(self, flag, reason, now):
        """Pre-R13 per-instance coalescing (F56 fallback only)."""
        if (now - self._lock_refusal_last_audit
                < self._LOCK_REFUSAL_AUDIT_COALESCE_SECS):
            self._lock_refusal_suppressed += 1
            return False
        suppressed = self._lock_refusal_suppressed
        self._lock_refusal_suppressed = 0
        self._lock_refusal_last_audit = now
        self.log.append({
            "event": "approval_sweep_refused",
            "run_id": self.run_id,
            "decision": "refused",
            "policy_id": "approval-execution-refused",
            "flag": flag,
            "reason": reason,
            "suppressed_repeats": suppressed,
            "refusal_storm": suppressed >= self._LOCK_REFUSAL_STORM_THRESHOLD,
        })
        return True

    def _execute_approved_locked(self):
        """The sweep body; runs under ``ApprovalQueue._queue_locked``.

        Records are re-read from disk AFTER the lock is held, so the
        read-claim-execute-mark sequence is atomic: a concurrent sweep
        can only re-read once this sweep has marked its records.

        F45 (R11): the first step under the lock is
        ``_reconcile_interrupted_executions`` — any record authorized
        and claimed by a previous sweep that crashed before recording
        completion is reset to pending with a loud audit event and an
        explicit may-have-already-happened warning, requiring a NEW
        human decision. Nothing is auto-executed during
        reconciliation.
        """
        # F45: reconcile interrupted executions before sweeping — runs
        # under the queue lock held by execute_approved().
        self.approvals._reconcile_interrupted_executions()
        done = []
        ttl = self.policy.approval_ttl_hours
        for rec in self.approvals.all():
            if rec.get("status") != "approved" or rec.get("executed"):
                continue
            aid = rec["id"]

            def _refuse(reason, flag, policy_id="approval-execution-refused"):
                self.approvals._rewrite(lambda records: [
                    dict(r, execution_refused_reason=reason)
                    if r["id"] == aid else r for r in records])
                self.log.append({
                    "event": "approval_execution_refused",
                    "run_id": self.run_id,
                    "agent_id": rec.get("agent_id"),
                    "role": rec.get("role"),
                    "tool": rec.get("tool"),
                    "approval_id": aid,
                    "decision": "refused",
                    "policy_id": policy_id,
                    "flag": flag,
                    "reason": reason,
                })

            # F85 (D1-core T12): a bridge_expired record can NEVER
            # execute — late human decisions after a bridge timeout are
            # audit-only. The check runs on every sweep BEFORE the TTL
            # check, so a record that becomes bridge_expired between
            # decision and sweep is still refused. Audited
            # approval_execution_refused with flag bridge_expired.
            if rec.get("bridge_expired"):
                _refuse("Approval %s refused: the bridge wait expired "
                        "before the human decision (late_decision=%s) — "
                        "the decision is audit-only and can never "
                        "execute (D1-core T12)."
                        % (aid, rec.get("late_decision")),
                        "bridge_expired")
                continue
            # 1. expiry
            if self._approval_expired(rec, ttl):
                self.approvals._rewrite(lambda records: [
                    dict(r, status="expired") if r["id"] == aid else r
                    for r in records])
                self.log.append({
                    "event": "approval_expired",
                    "run_id": self.run_id,
                    "agent_id": rec.get("agent_id"),
                    "tool": rec.get("tool"),
                    "approval_id": aid,
                    "decision": "refused",
                    "policy_id": "approval-ttl",
                    "flag": "approval_expired",
                    "reason": "Approval %s expired (TTL %sh)." % (aid, ttl),
                })
                continue
            # 2. integrity: queued arguments must be byte-identical. The
            # keyed digest (F34) binds tool, args, policy_id and
            # egress_bytes (F33) under the active log HMAC key with the
            # key epoch bound in; F38 (R10) adds run_id and decided_by
            # to the MAC payload. Verification uses hmac.compare_digest
            # against every epoch in the keyring, so rotation is
            # explicit. Records that predate the keyed scheme (no
            # digest_scheme — the pre-R9 unkeyed digest proved nothing:
            # anyone with run-dir access could mint it) are refused
            # FAIL-CLOSED: queued items must be decided before upgrading.
            # A record that HAS the egress_bytes key is always verified
            # with it — removing the key does not downgrade the check.
            if (rec.get("digest_scheme")
                    != APPROVAL_DIGEST_SCHEME):
                _refuse("Approval %s refused: the record predates the F34 "
                        "keyed approval digest (no digest_scheme) — the "
                        "pre-R9 unkeyed digest could be minted by anyone "
                        "with run-dir access, so it is never trusted. "
                        "Drain or decide queued items before upgrading."
                        % aid,
                        "approval_integrity_violation")
                continue
            if not approval_digest_ok(rec):
                _refuse("Approval %s arguments were modified after queueing; "
                        "integrity digest mismatch (F34 keyed MAC does not "
                        "verify under any key epoch)." % aid,
                        "approval_integrity_violation")
                continue
            # Wave-24 (D1 bridges): bridge-queued records are
            # FOREIGN-EXECUTED — the bridge's runtime executes on its
            # side after our human decides, so our own sweep must never
            # execute them (double execution). The integrity checks
            # above still apply (a tampered foreign record is refused
            # loudly); a healthy foreign record is skipped quietly —
            # bridge_id present is the by-design marker, visible on the
            # record and in the web UI's future bridge:<id> badge. The
            # T12 bridge_expired refusal above runs first, so an
            # expired bridge record is still refused loudly.
            if rec.get("bridge_id"):
                continue
            # F38 (R10): cross-run replay — the record's run_id must
            # match the executing run. The keyed digest binds run_id
            # (so a planted record cannot be re-labeled without the log
            # key), and this check refuses a genuinely-approved record
            # replayed into another run's queue. Fail-closed, audited.
            if rec.get("run_id") != self.run_id:
                _refuse("Approval %s was approved for run %r but is "
                        "being executed in run %r; cross-run replay "
                        "refused." % (aid, rec.get("run_id"), self.run_id),
                        "approval_run_mismatch")
                continue
            # F38 (R10): the embedded identity's run_id must ALSO match
            # the executing run. The keyed digest does not cover the
            # identity dict, so a queue-file writer could rewrite
            # identity.run_id on a genuine record without breaking the
            # MAC — executing it would then attribute the action to the
            # wrong run. queue() always mints both from the same
            # identity, so any mismatch here is tampering or a plant:
            # fail-closed, audited under the CURRENT run.
            if (rec.get("identity") or {}).get("run_id") != self.run_id:
                _refuse("Approval %s carries embedded identity run %r "
                        "but is being executed in run %r; identity/run "
                        "mismatch refused."
                        % (aid, (rec.get("identity") or {}).get("run_id"),
                           self.run_id),
                        "approval_run_mismatch")
                continue
            # 3. policy staleness: approved under a different policy version
            if rec.get("policy_hash") != self.policy.policy_hash:
                _refuse("Approval %s was granted under policy %s but the "
                        "active policy is %s; re-approval required."
                        % (aid, (rec.get("policy_hash") or "")[:12],
                           self.policy.policy_hash[:12]),
                        "approval_policy_stale")
                continue
            # F47 (R11): cross-privilege smuggling — an approval whose
            # recorded role is not allowed the recorded tool is refused
            # BEFORE any policy evaluation or side effect. The role is
            # the F42 session-authenticated attribution (stamped by the
            # queue from the minted identity, never from
            # action["identity"]), so this check binds the approval to
            # the least-privilege contract of the role that actually
            # requested it. A record planted with a victim's approval
            # but an attacker's privileged role/tool pair dies here.
            # Same-role approved actions are unaffected.
            if not self.policy.role_allows(rec["role"], rec["tool"]):
                _refuse("Approval %s refused: role %r is not allowed to "
                        "execute tool %r under the active policy's "
                        "role allowlist (cross-privilege smuggling "
                        "guard)." % (aid, rec["role"], rec["tool"]),
                        "role_allowlist_violation",
                        policy_id="role-allowlist")
                continue
            # 4. fresh policy evaluation (TOCTOU guard)
            ctx = self._context(rec["tool"], rec["args"],
                                principal=(rec.get("identity") or {}).get(
                                    "principal"),
                                record_ledger=False)
            action = {"tool": rec["tool"], "args": rec["args"],
                      "identity": rec.get("identity"),
                      "role": rec.get("role"), "agent_id": rec.get("agent_id")}
            decision = self.policy.evaluate(action, ctx)
            if decision.effect == "deny":
                _refuse("Approval %s no longer permitted: %s"
                        % (aid, decision.reason), decision.flag or "policy_re_eval_deny",
                        policy_id=decision.policy_id or "approval-execution-refused")
                continue

            # F33 (HARDENING-R8): re-check the volume budgets at the actual
            # execution boundary (TOCTOU guard) — the budget may have been
            # consumed by other executions between queue time and approval.
            # Refusals are logged with flag "volume_guard" and the record
            # is left approved-but-unexecuted (fail-safe, retriable).
            _rl = self.policy.rate_limit or {}
            if rec["tool"] in _SEND_TOOLS:
                _exec_sends = (self._executed.get("send_email", 0)
                               + self._executed.get("http_post", 0))
                if _exec_sends >= int(_rl.get("max_sends_per_run", 10)):
                    _refuse("Approval %s refused: per-run send budget "
                            "exhausted (%d sends executed)."
                            % (aid, _exec_sends),
                            "volume_guard", policy_id="volume-guard-sends")
                    continue
            if rec["tool"] in _EGRESS_TOOLS:
                _budget = self._max_egress_bytes()
                _call_bytes = self._approved_egress_bytes(rec)
                if self._egress_bytes + _call_bytes > _budget:
                    _refuse("Approval %s refused: per-run egress byte "
                            "budget exceeded (projected total %d > budget "
                            "%d)." % (aid,
                                       self._egress_bytes + _call_bytes,
                                       _budget),
                            "volume_guard",
                            policy_id="volume-guard-egress-bytes")
                    continue

            # Write-ahead audit (fail-closed): the authorization is durably
            # logged BEFORE the side effect. If this append raises, the tool
            # is never touched.
            _exec_ctx_snapshot = {
                "path_outside_sandbox": ctx.get("path_outside_sandbox"),
                "domain_allowlisted": ctx.get("domain_allowlisted"),
                "carries_read_content": ctx.get("carries_read_content"),
                "read_sensitive": ctx.get("read_sensitive"),
                "cross_run_campaign": ctx.get("cross_run_campaign"),
                "velocity_exceeded": ctx.get("velocity_exceeded"),
                "source_untrusted": ctx.get("source_untrusted"),
                # F99: same snapshot contract as the pre-execution path.
                "high_entropy_payload": ctx.get("high_entropy_payload"),
                "counters": dict(ctx.get("counters") or {}),
            }
            auth_entry = self.log.append({
                "event": "tool_call",
                "run_id": rec.get("run_id", self.run_id),
                "agent_id": rec.get("agent_id"),
                "role": rec.get("role"),
                "principal": (rec.get("identity") or {}).get("principal"),
                "tool": rec["tool"],
                "args": rec["args"],
                "redactions_applied": rec.get("redactions_applied", []),
                "decision": "execution_authorized",
                "policy_id": rec.get("policy_id"),
                "approval_id": aid,
                "policy_context": _exec_ctx_snapshot,
                "reason": "Human approval %s authorized execution." % aid,
            })
            # F39 (R10): DURABLE CLAIM BEFORE SIDE EFFECT. The record is
            # marked executed (queue-file rewrite — the durable claim)
            # BEFORE _simulate() runs. Under the queue sweep lock this
            # makes the read-claim-execute sequence atomic across
            # threads/processes; and if this process crashes after the
            # claim but before/during the side effect, a later sweep
            # re-reads executed=True and skips the record — the approval
            # is consumed without a duplicate execution. This favors no
            # duplicate execution over automatic retry (documented
            # residual). The write-ahead "execution_authorized" audit
            # entry above stays as the forensic marker that the
            # authorization was granted before the claim.
            self.approvals.mark_executed(aid)
            result = self._simulate(rec["tool"], rec["args"], ctx)
            self._ingest_result(rec["tool"], result,
                                (rec.get("identity") or {}).get("principal"))
            if rec["tool"] == "api_call":
                self.api_calls += 1
            # F33: charge the execution budgets exactly once, at execution
            # time. (The old code ALSO bumped self.counters here, so an
            # approved send counted at call() AND here — removed: each
            # execution is now counted exactly once, in _executed.)
            self._executed[rec["tool"]] = self._executed.get(
                rec["tool"], 0) + 1
            self._egress_bytes += self._approved_egress_bytes(rec)
            # S5 (K-052): record the approved execution in the cross-run
            # velocity ledger — same lock discipline as the allow path
            # (the write lock lives inside EgressLedger.append; no
            # second lock here). Fail-open with loud audit on ledger
            # trouble.
            if rec["tool"] in _VELOCITY_TOOLS:
                self._record_velocity(
                    rec["tool"],
                    (rec.get("identity") or {}).get("principal"),
                    rec.get("agent_id"),
                    self._approved_egress_bytes(rec))
            entry = self.log.append({
                "event": "tool_call",
                "run_id": rec.get("run_id", self.run_id),
                "agent_id": rec.get("agent_id"),
                "role": rec.get("role"),
                "principal": (rec.get("identity") or {}).get("principal"),
                "tool": rec["tool"],
                "args": rec["args"],
                "redactions_applied": rec.get("redactions_applied", []),
                "decision": "approved_executed",
                "policy_id": rec.get("policy_id"),
                # Wave-79 (totality): the executed-approval record names
                # the governing policy version and the rules that fired,
                # propagated from the queue ticket.
                "policy_version": rec.get("policy_version", "approvals-d1"),
                "matched_rules": rec.get("matched_rules", []),
                "approval_id": aid,
                "policy_context": _exec_ctx_snapshot,
                "reason": "Executed after human approval %s: %s"
                          % (aid, rec.get("decision_reason")),
                "result_summary": self._summarize(rec["tool"], result),
                "authorization_seq": auth_entry["seq"],
            })
            # F39: the durable claim (mark_executed) happened BEFORE the
            # side effect above — nothing to mark here.
            done.append({"agent_id": rec.get("agent_id"),
                         "tool": rec["tool"], "seq": entry["seq"]})
        return done
