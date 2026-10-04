"""Tool executor: every agent action flows through identity -> policy -> log.

Pipeline for each call (in order):

1. **Identity.** The identity must be an ``AgentIdentity`` *minted by this
   executor* via :meth:`mint_identity` (unforgeable from model-controlled data —
   a hand-built ``AgentIdentity`` with an identical field tuple is accepted by
   the tuple check, which requires executing Python inside the trusted
   deployment process, i.e. process compromise) and
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
                     (expiry, integrity, current policy, capability
                     assessment) and logs "approved_executed".
"""

import json
import os
import fcntl
import sys
import time
import threading
import hashlib
import hmac
import inspect
import collections.abc
import itertools
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import dlp
from . import advisory as _advisory
from . import canary as _canary
from . import goals as _goals
from . import grant_negotiation
from . import sentinel_substitution as _sentinel
from . import attestation_release as _attestation_release
from . import classification as _classification
from . import artifacts as _artifacts
from . import intent_slice as _intent_slice
from . import revoke as _revoke
from . import delegation_tokens as _delegation_tokens
from . import instruction_provenance as _instruction_provenance
from . import drift as _drift
from . import framing as _framing
from . import egress_content as _egress_content
from . import detection_verdicts as _detection_verdicts
from . import exchange_ledger as _exchange_ledger
from . import approval_tokens as _approval_tokens  # wave-313 Row-7 step 3
from . import provenance_sink as _provenance_sink  # wave-314 Row-7 step 5
from . import provenance_labels as _provenance_labels  # wave-317 producer wiring
from . import rules_tiering as _rules_tiering
from . import precommit as _precommit
from . import tool_continuity as _tool_continuity
from . import skill_watch as _skill_watch
from . import discovery_scan as _discovery_scan
# F191 (wave-174): audio-carrier classification for the approval-path
# binding (perceptual channels in tool args ride the queue packet).
from . import audio_carrier as _audio_carrier
from . import invocation_receipts as _receipts
from . import authority_proof as _authority_proof
from . import decision_packet as _decision_packet
from . import decision_bom as _decision_bom
from . import supplychain_install as sc_install
from . import artifact_sweep as _artifact_sweep
from . import target_match as _target_match
# Wave-196 lane C (step-ca steal): the provisioner abstraction + lifetime
# claims envelope (typed issuance authorities with per-issuer TTL / scope /
# role / renewal policy). Read at mint time only when a registry is
# configured; otherwise mint_identity behaves exactly as before.
from . import provisioner as _provisioner
# Wave-198 (graduation ladder): the per-rule-per-window warn digest
# aggregator (R1 warn-fatigue). Stdlib-only, no import cycle.
from . import mode_ledger as _mode_ledger
from .approvals import (DelegationError, DelegationStore,
                        IdentityVerifierAlreadySetError, approval_digest_ok,
                        APPROVAL_DIGEST_SCHEME, record_digest,
                        sanitize_preview_text, QueueLockError,
                        QueueLockInvalidatedError, QueueLockPathError,
                        SessionIdentityAlreadySetError,
                        DecisionHookAlreadySetError,
                        verify_display_execution_preview)
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
    IO_WINDOW_SECS,
    SENSITIVE_TAINT_TTL_SECS,
    EgressLedger,
    LedgerUnverifiableError,
    _ledger_read_locked,
    registered_domain,
)
from .identity import (
    AgentIdentity,
    IdentityMintLimitError,
    IdentityTokenError,
    UnmintedIdentityError,
    UnregisteredPrincipalError,
    warn_self_asserted_identity_once,
)
from .policy import PolicyDecision
from .decision_contract import Request
from . import decision_replay as _decision_replay
from .tool_ratings import normalize_tool_ratings
from .log import (_verify, newest_refusal_ts_per_flag, read_entries,
                   refusal_ts_within_window, verify_chain_tip,
                   write_chain_tip_from_tail)
from .memory_provenance import MemoryQuarantineError, instruction_shaping_reason
from . import citation_provenance as _citation_provenance
from . import capability_gate as _capability_gate
from . import velocity as _velocity

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
# F162 (HIGH): default-enforced ceilings. Absent policy keys are NOT
# "unlimited" — the deployment (policy author) may raise them
# explicitly, but silence can no longer disable the guard. The agent
# can never set these: they come from policy only.
_DEFAULT_MAX_ACTIONS_PER_RUN = 200      # S2 max_actions_per_run default
_DEFAULT_MAX_TOOL_CALLS_PER_RUN = 400   # S4 max_tool_calls_per_run default
# S5 cross-run velocity defaults when the velocity: section is absent
# (conservative: they only ever queue for human review, never deny).
_DEFAULT_VELOCITY = {
    "window_secs": 24.0 * 3600.0,
    "max_sends": 200,
    "max_writes": 500,
    "max_egress_bytes": 2.0 * 1024 * 1024,
}
# F162 per-run tempo tripwire defaults (60s window): machine-speed
# misuse, not human tempo. 30 egress / 60 writes / 300 reads per minute.
_DEFAULT_TEMPO = {
    "window_secs": 60.0,
    "max_read": 300,
    "max_write": 60,
    "max_egress": 30,
}
# F162: the reserved tool name for the run-resume approval record.
_VELOCITY_RESUME_TOOL = "velocity_resume"
_MAX_READ_STORE = 256 * 1024  # cap on stored read fingerprints per run


def _fingerprint_source_key(tool, args):
    """F189: source key for per-source fingerprint quotas.

    The quota rule ("a flood evicts its own oldest entries first; one
    source cannot evict another source's poison link") needs to know
    which origin each fingerprint came from. The key is (tool,
    locator): the locator is the read path for read_file, the
    endpoint for api_call, the url for http_post, the recipient for
    send_email, and "" when unknown (e.g. foreign-result ingestion,
    which carries no args). Two reads of the same path/endpoint share
    a source; distinct paths/endpoints are distinct sources.
    """
    args = args or {}
    if tool == "read_file":
        loc = args.get("path", "")
    elif tool == "api_call":
        loc = args.get("endpoint", "")
    elif tool == "http_post":
        loc = args.get("url", "")
    elif tool == "send_email":
        loc = args.get("to", "")
    else:
        loc = ""
    try:
        loc = str(loc)
    except Exception:
        loc = ""
    return (tool, loc)


# F164 (HIGH): entry count for the exchange-ledger after-phase on the
# agent read_file path. Non-blank lines of the FULL file text — the
# .jsonl analog of the gov.log seam's parsed-entry count — computed
# from the complete content, never from the 4000-char tool-result
# truncation. The guard ignores it for non-exchange paths.
def _exchange_entry_count(text):
    return sum(1 for line in text.splitlines() if line.strip())


class PolicyPinMismatchError(Exception):
    """F48 (R11): the loaded policy's content hash does not match the
    GOV_POLICY_HASH pin. Raised by ToolExecutor.__init__ — construction
    is refused fail-closed, before any tool can execute."""


class UngovernedConstructionError(Exception):
    """Wave-85 (legacy-seam closure): ToolExecutor construction refused
    fail-closed, before anything executes.

    Raised when the governed core (policy_store + delegation_context)
    is absent and no valid ``ungoverned_ack`` declaration is present —
    or when the deployment mode is production (even a valid
    declaration is refused there) or unresolvable (unknown modes fail
    closed toward refusal, never silently toward "no guard").
    """


class DeploymentManifestRequiredError(Exception):
    """Row-12 (wave-158): ToolExecutor construction refused fail-closed,
    before anything executes.

    Raised when the deployment-manifest decision is contradictory (an
    envelope AND an opt-out reason), when the opt-out reason is blank
    (F131 hollow justification), or when the decision is silently
    absent in production. In non-production modes the silent absence
    is instead recorded LOUD as a chained ``deployment_manifest_absent``
    event -- silence is never an acceptable deployment posture for the
    artifact-integrity seam.
    """


def _normalize_declared_write_dirs(declared_write_dirs):
    """Row-12 (wave-162): normalize deployment-declared writable dirs.

    Returns a tuple of sandbox-relative directory prefixes (no
    trailing slash, ``/``-separated). Fail-closed at construction: a
    non-string entry, an empty entry, or an entry that escapes the
    sandbox (``..``) raises ValueError -- a misdeclared writable dir
    must be LOUD at setup, never a silent widening at consult.
    """
    import posixpath
    if declared_write_dirs is None:
        return ()
    if isinstance(declared_write_dirs, str):
        declared_write_dirs = (declared_write_dirs,)
    normed = []
    for entry in declared_write_dirs:
        if not isinstance(entry, str):
            raise ValueError(
                "declared_write_dirs entries must be strings, got %r"
                % (entry,))
        key = _artifacts.normalize_path(entry).replace("\\", "/")
        key = posixpath.normpath(key)
        if not key or key == "." or key.startswith(".."):
            raise ValueError(
                "declared_write_dirs entry %r is empty or escapes the "
                "sandbox" % (entry,))
        key = key.strip("/")
        if not key:
            raise ValueError(
                "declared_write_dirs entry %r normalizes to empty"
                % (entry,))
        normed.append(key)
    return tuple(normed)


def _deployment_manifest_construction_check(run_id, log_append, inventory,
                                            deployment_manifest,
                                            deployment_manifest_opt_out):
    """Row-12 (wave-158): default-on deployment-manifest decision gate.

    The deployment manifest (gov/artifact_inventory_manifest.py) is the
    only record that knows what deployment-critical files are SUPPOSED
    to be. Attachment was opt-in (wave-152/153): a deployment that
    skipped it ran with the artifact-integrity seam silently absent.
    The safe state is the DEFAULT state -- the operator hands over the
    pinned envelope, or explicitly opts out with a recorded reason
    (aviation-checklist idiom, same as the wave-85 ungoverned_ack
    gate: skipping the safe state requires an explicit, recorded
    declaration).

    Returns ``(decision, opt_out_reason)`` where decision is one of
    "attached" / "opt_out" / "absent". Raises
    DeploymentManifestRequiredError on contradiction, on a hollow
    opt-out, and on silent absence in production. A malformed or
    unverifiable envelope raises ValueError from the inventory's
    attach ceremony (fail-loud at setup, never a silent gap at
    consult). NoKeyConfiguredError from the audit write propagates
    unchanged (a key problem is not a declaration problem).
    """
    from . import artifact_inventory_manifest as _manifest
    from .keys import NoKeyConfiguredError

    def _emit(event, decision, reason, **fields):
        record = {"event": event,
                  "run_id": run_id,
                  "agent_id": "system",
                  "role": "system",
                  "decision": decision,
                  "policy_id": "deployment-manifest-seam",
                  "reason": reason}
        record.update(fields)
        log_append(record)

    # Contradictory: an envelope AND an opt-out reason.
    if (deployment_manifest is not None
            and deployment_manifest_opt_out is not None):
        raise DeploymentManifestRequiredError(
            "REFUSED: deployment_manifest and "
            "deployment_manifest_opt_out were both given -- "
            "contradictory. Hand over the pinned envelope OR declare "
            "the opt-out reason, not both.")
    # The envelope: attach now, verified fail-loud at setup by the
    # inventory's attach ceremony (ValueError on malformed / forged /
    # stale envelopes -- never a silent gap).
    if deployment_manifest is not None:
        inventory.attach_deployment_manifest(deployment_manifest)
        pinned = deployment_manifest
        try:
            _emit("deployment_manifest_attached", "attached",
                  "LOUD: deployment manifest attached at construction; "
                  "artifact egress is now checked against the deployment "
                  "pin in addition to the run inventory.",
                  manifest_digest=_manifest.manifest_digest(pinned),
                  key_epoch=pinned.get("key_epoch"),
                  pinned_at=pinned.get("pinned_at"),
                  entry_count=len(pinned.get("manifest", {})))
        except NoKeyConfiguredError:
            raise
        except Exception:
            pass  # the attachment stands; the event is informational
        return "attached", None
    # Explicit opt-out: the reason must be real (F131 -- a
    # whitespace-only justification is hollow). An unrecorded
    # declaration is not a declaration: if the opt-out cannot be
    # chained, the opt-out is refused.
    if deployment_manifest_opt_out is not None:
        reason = deployment_manifest_opt_out
        if not isinstance(reason, str) or not reason.strip():
            raise DeploymentManifestRequiredError(
                "REFUSED: deployment_manifest_opt_out is blank or "
                "whitespace-only -- a hollow justification (F131). "
                "State a real reason (e.g. 'no deployment-critical "
                "files in this deployment') or hand over the pinned "
                "envelope.")
        reason = reason.strip()
        try:
            _emit("deployment_manifest_opt_out", "opt_out",
                  "LOUD: deployment runs WITHOUT a deployment manifest "
                  "under an explicit, recorded opt-out. Declared reason: "
                  "%r. Artifact egress is checked against the run "
                  "inventory only; the cross-run deployment-pin leg is "
                  "absent BY DECLARATION -- audit accordingly." % (reason,),
                  opt_out_reason=reason)
        except NoKeyConfiguredError:
            raise
        except Exception as exc:
            raise DeploymentManifestRequiredError(
                "REFUSED: the deployment_manifest_opt_out declaration "
                "could not be chained (%s) -- an unrecorded declaration "
                "is not a declaration." % (exc,))
        return "opt_out", reason
    # Silent absence: resolve the mode. Unknown/unresolvable modes fail
    # closed TOWARD refusal, never silently toward "no guard" (wave-85
    # idiom: ambiguity defaults to the safe direction).
    from .keyprovider import resolve_deployment_mode
    try:
        mode = resolve_deployment_mode()
    except Exception:
        mode = "production"
    if mode == "production":
        try:
            _emit("deployment_manifest_refused", "refused",
                  "REFUSED: ToolExecutor constructed in production "
                  "without a deployment manifest and without an explicit "
                  "opt-out -- the artifact-integrity seam must never be "
                  "silently absent where the stakes are real.",
                  deployment_mode=mode)
        except NoKeyConfiguredError:
            raise
        except Exception:
            pass  # the refusal stands even if the audit write fails
        raise DeploymentManifestRequiredError(
            "REFUSED: ToolExecutor constructed in production without "
            "deployment_manifest and without deployment_manifest_opt_out "
            "-- hand over the operator-pinned envelope "
            "(gov.artifact_inventory_manifest.pin_manifest) or declare "
            "deployment_manifest_opt_out='<reason>'.")
    try:
        _emit("deployment_manifest_absent", "absent",
              "LOUD: ToolExecutor constructed WITHOUT a deployment "
              "manifest and without an explicit opt-out (deployment "
              "mode: %s). Artifact egress is checked against the run "
              "inventory only; the cross-run deployment-pin leg is "
              "absent -- audit accordingly. Silence is not an "
              "acceptable deployment posture: hand over the pinned "
              "envelope or record an opt-out reason." % (mode,),
              deployment_mode=mode)
    except NoKeyConfiguredError:
        raise
    except Exception as exc:
        raise DeploymentManifestRequiredError(
            "REFUSED: the deployment_manifest_absent declaration could "
            "not be chained (%s) -- silence is not an acceptable "
            "deployment posture." % (exc,))
    return "absent", None


class SpawnBudgetExhaustedError(Exception):
    """Wave-86 (governed spawn): the run's spawn budget is exhausted.

    Fail-closed: a run that has spent its spawn allowance cannot spawn
    further sub-agents. The chained ``agent_spawn`` events are the
    detection story; the budget is the prevention story (swarm
    control at the executor layer, complementing the delegation-depth
    cap in gov/delegation_tokens.py).
    """


class _SpawnBudget:
    """Mutable shared spawn-budget box: one lineage, one budget.

    The box is shared by reference between a parent executor and every
    child executor it spawns, so the budget bounds the whole spawn
    tree, not each executor individually. ``None`` (no box) means
    unlimited — documented, with the chained ``agent_spawn`` events as
    the detection story.
    """

    def __init__(self, total):
        self.total = total
        self.remaining = total


# Wave-86 (GAP 2): one-time loud disclosure that revocation is
# TTL-only — same pattern as warn_self_asserted_identity_once in
# gov/identity.py. Per-process, resettable by tests (poke the module
# attribute).
_revocation_ttl_only_warned = False


def warn_revocation_ttl_only_once():
    """Print the revocation TTL-only warning to stderr, once per
    process. Called by ``ToolExecutor.__init__`` when a delegation
    context is installed but no revocation_checker was provided: a
    revoked token authorizes until expiry on the real path."""
    global _revocation_ttl_only_warned
    if _revocation_ttl_only_warned:
        return
    _revocation_ttl_only_warned = True
    print(
        "GOVERNANCE WARNING: delegation is installed but no "
        "revocation_checker was provided — revocation is TTL-ONLY: a "
        "revoked token still authorizes until its expiry on the "
        "executor's real tool-call path. Pass "
        "revocation_checker=<RevocationLedger or equivalent> for real "
        "deployments; revocation then fails closed (leaf AND ancestors "
        "checked per call, checker errors refuse).",
        file=sys.stderr)


# Wave-85: the GOVERNED CORE — the two opt-in components that are
# load-bearing for the audit questions "who changed the policy" and
# "who acted", and therefore the two whose absence makes a
# construction "ungoverned".
#
#   * policy_store (wave-75): the ONLY governed mutation path for the
#     live engine. Without it, verdicts are pinned to a static file
#     read at construction: policy changes have no chained authorship
#     and "who changed policy" is unanswerable for the run.
#   * delegation_context (wave-74): the three-token identity gate
#     enforced in CODE before policy evaluation. Without it the
#     "agent without delegation" case is open and "who acted, under
#     whose authority" is unanswerable.
#
# Deliberately NOT in the core (they legitimately vary by deployment
# and their absence creates no unattributed action):
#   * detection_monitor (wave-76): behavioral baselines are a
#     risk-profile choice — less detection depth, not a bypass.
#   * recovery (wave-77): the halt latch exists only where a recovery
#     controller is deployed; there is no halt authority to check
#     elsewhere.
#   * lease_verifier (wave-78): meaningful only where a LeaseAuthority
#     mints leases; requiring it where no leases exist would deny
#     every gated tool by deployment shape, not by threat.
#   * precommit_gate / trifecta_floor (wave-79): explicit deployment
#     friction decisions (wave-79 resolved both as opt-in for exactly
#     this reason).
_GOVERNED_CORE_COMPONENTS = ("policy_store", "delegation_context")


def _construction_caller():
    """First stack frame outside gov/executor.py: who skipped the
    checklist. Best-effort: never raises."""
    unknown = {"caller_file": "<unknown>", "caller_line": 0,
               "caller_function": "<unknown>"}
    try:
        here = os.path.realpath(__file__)
    except Exception:
        return dict(unknown)
    try:
        frame = sys._getframe(2)
    except ValueError:
        return dict(unknown)
    while frame is not None:
        try:
            name = os.path.realpath(frame.f_code.co_filename)
        except Exception:
            break
        if name != here:
            try:
                return {
                    "caller_file": os.path.basename(
                        frame.f_code.co_filename),
                    "caller_line": int(frame.f_lineno),
                    "caller_function": str(frame.f_code.co_name),
                }
            except Exception:
                break
        frame = frame.f_back
    return dict(unknown)


def _fail_closed_construction_check(run_id, log, policy_store,
                                    delegation_context, ungoverned_ack,
                                    non_core=()):
    """Wave-85 fail-closed construction gate (aviation checklist: the
    safe state is the DEFAULT state; skipping it requires an explicit,
    recorded declaration — refused outright in production).

    Returns ``(ack_reason_or_None, missing_components)``. Raises
    :class:`UngovernedConstructionError` BEFORE anything executes when
    the governed core is absent and no valid declaration survives the
    checks below. A chained ``ungoverned_bypass_refused`` record is
    attempted best-effort before raising (the attempt itself is
    evidence); audit failure never masks the refusal.

    ``non_core`` is an iterable of ``(name, value)`` for the governed
    components that are deliberately NOT in the core (detection
    monitor, recovery, lease verifier, precommit gate, trifecta
    floor): their absence never invalidates construction, but the
    declaration reports them so the auditor sees the full deployment
    shape, not just the bypass.
    """
    core_vals = {"policy_store": policy_store,
                 "delegation_context": delegation_context}
    missing = [name for name in _GOVERNED_CORE_COMPONENTS
               if core_vals[name] is None]
    absent_non_core = [name for name, val in non_core if not val]
    if not missing:
        return None, []
    caller = _construction_caller()
    # The key layer's fail-closed is MORE fundamental than this gate:
    # without a key no chain can exist at all, so a NoKeyConfiguredError
    # from the audit write propagates UNCHANGED (never masked as a
    # bypass refusal — the deployment has a key problem, not a
    # declaration problem).
    from .keys import NoKeyConfiguredError

    def _refuse(cause, detail):
        try:
            log.append({
                "event": "ungoverned_bypass_refused",
                "run_id": run_id,
                "agent_id": "system",
                "role": "system",
                "decision": "refused",
                "policy_id": "construction-seam",
                "refusal_cause": cause,
                "missing_components": list(missing),
                "absent_non_core_components": list(absent_non_core),
                "reason": detail,
                "caller_file": caller["caller_file"],
                "caller_line": caller["caller_line"],
                "caller_function": caller["caller_function"],
            })
        except NoKeyConfiguredError:
            raise
        except Exception:
            pass  # the refusal stands even if the audit write fails
        raise UngovernedConstructionError(detail)

    # 1. The declaration must exist and be non-blank. F131's lesson:
    #    a whitespace-only justification is hollow — it says nothing
    #    while looking declared.
    if ungoverned_ack is None:
        _refuse(
            "no_ack",
            "REFUSED: ToolExecutor constructed without the governed "
            "core (%s) and without ungoverned_ack — the safe state is "
            "the default state; skipping the checklist requires an "
            "explicit, recorded declaration." % ", ".join(missing))
    if not isinstance(ungoverned_ack, str) or not ungoverned_ack.strip():
        _refuse(
            "blank_ack",
            "REFUSED: ungoverned_ack is blank/whitespace-only — a hollow "
            "justification (F131). The governed core (%s) is absent; "
            "state a real reason or install the core."
            % ", ".join(missing))
    # 2. Resolve the deployment mode (wave-70/81 machinery). Unknown or
    #    unresolvable modes fail closed TOWARD refusal, never silently
    #    toward "no guard".
    from .keyprovider import resolve_deployment_mode
    try:
        mode = resolve_deployment_mode()
    except Exception as exc:
        _refuse(
            "unresolvable_mode",
            "REFUSED: deployment mode unresolvable (%s) — failing "
            "closed toward refusal; an unknown mode never silently "
            "disables the construction guard. Governed core absent: %s."
            % (exc, ", ".join(missing)))
    # 3. Production refuses even a valid declaration: where the stakes
    #    are real, the checklist cannot be skipped by declaration.
    if mode == "production":
        _refuse(
            "production",
            "REFUSED: deployment mode is production — ungoverned "
            "construction is refused even with a declared reason. "
            "Install the governed core (%s) or do not run here."
            % ", ".join(missing))
    # 4. Declared bypass (non-production only): stamp the LOUD chained
    #    declaration FIRST in the run's chain, then proceed. If the
    #    declaration cannot be chained, the bypass is refused — an
    #    unrecorded declaration is not a declaration.
    reason = ungoverned_ack.strip()
    non_core_note = (" Also absent (deployment choices, NOT bypasses — "
                     "they legitimately vary by deployment): %s."
                     % ", ".join(absent_non_core)) if absent_non_core else ""
    try:
        log.append({
            "event": "ungoverned_bypass",
            "run_id": run_id,
            "agent_id": "system",
            "role": "system",
            "decision": "declared",
            "policy_id": "construction-seam",
            "ungoverned_reason": reason,
            "missing_components": list(missing),
            "absent_non_core_components": list(absent_non_core),
            "deployment_mode": mode,
            "reason": (
                "LOUD: ToolExecutor constructed WITHOUT the governed "
                "core (%s) under an explicit, recorded declaration. "
                "Declared reason: %r. Deployment mode: %s. Declared by "
                "%s:%s in %s. This run's verdicts carry NO governed "
                "policy-change lineage and NO delegation-identity gate — "
                "audit accordingly.%s"
                % (", ".join(missing), reason, mode,
                   caller["caller_file"], caller["caller_line"],
                   caller["caller_function"], non_core_note)),
            "caller_file": caller["caller_file"],
            "caller_line": caller["caller_line"],
            "caller_function": caller["caller_function"],
        })
    except NoKeyConfiguredError:
        raise
    except Exception as exc:
        raise UngovernedConstructionError(
            "REFUSED: the ungoverned_bypass declaration could not be "
            "chained (%s) — an unrecorded declaration is not a "
            "declaration." % (exc,))
    return reason, missing


def _capability_gate_construction_check(run_id, log, policy_store,
                                        delegation_context,
                                        capability_gate_binding,
                                        capability_assessment,
                                        capability_ungoverned_ack):
    """Wave-100 (Stream 1): the capability-gate declaration check.

    A deployment that LOOKS governed (governed core installed:
    policy_store + delegation_context) must bind a capability gate or
    explicitly acknowledge ungoverned capability mode. Without this,
    the benchmark's SUFFICIENT grade is a story the runtime never
    checks -- the deployment looks governed while running agents
    against no capability assessment.

    Returns ``(binding_or_None, assessment_or_None,
    ack_reason_or_None)``. Raises
    ``capability_gate.CapabilityGateBindingError`` fail-closed, before
    anything executes, when the core is installed and neither a valid
    binding nor a valid acknowledgement is present, or when the
    declarations are contradictory/malformed. Refusals are chained
    best-effort (the refusal stands even if the audit write fails); an
    accepted acknowledgement MUST chain or the bypass is refused.

    Raw-pipeline deployments (no governed core) are untouched: the
    wave-85 ``ungoverned_ack`` already declares those runs ungoverned,
    and the capability gate does not pretend to govern them.
    """
    from .keys import NoKeyConfiguredError

    def _refuse(cause, detail, code=None):
        try:
            event = {
                "event": "capability_gate_unconfigured_refused",
                "run_id": run_id,
                "agent_id": "system",
                "role": "system",
                "decision": "refused",
                "policy_id": "capability-gate",
                "refusal_cause": cause,
                "reason": detail,
            }
            if code is not None:
                # Wave-219: the registered unsafe-path code rides the
                # audit event itself, not just a source comment.
                event["code"] = code
            log.append(event)
        except NoKeyConfiguredError:
            raise
        except Exception:
            pass  # the refusal stands even if the audit write fails
        raise _capability_gate.CapabilityGateBindingError(detail)

    # Contradictory declarations: binding AND ack is a misconfiguration
    # -- fail closed rather than guess which one the operator meant.
    if (capability_gate_binding is not None
            and capability_ungoverned_ack is not None):
        _refuse(
            "contradictory_declaration",
            "REFUSED: capability_gate_binding AND "
            "capability_ungoverned_ack were both given -- contradictory "
            "declarations. Bind the gate or acknowledge ungoverned "
            "capability mode, not both.")

    binding = None
    if capability_gate_binding is not None:
        try:
            binding = _capability_gate.validate_binding(
                capability_gate_binding)
        except _capability_gate.CapabilityGateError as e:
            _refuse("malformed_binding",
                    "REFUSED: malformed capability_gate_binding: %s" % (e,))

    core_installed = (policy_store is not None
                      and delegation_context is not None)
    if binding is not None:
        # The assessment itself is verified per call/spawn, not here:
        # None just means "not yet installed" (rotation installs it
        # later via update_capability_assessment).
        return binding, capability_assessment, None

    if capability_ungoverned_ack is None:
        if core_installed:
            _refuse(
                # Wave-219 unsafe-path registry: gov.executor.capability_gate_unconfigured_refused
                "no_binding_no_ack",
                "REFUSED: no capability gate configured -- this executor "
                "has the governed core (policy_store + delegation_context) "
                "installed and would LOOK governed while running agents "
                "against no capability assessment. Configure "
                "capability_gate_binding={'harness_id': ..., "
                "'harness_digest': <sha256 of the harness/thresholds "
                "config -- see gov/capability_gate.compute_harness_digest"
                ">, 'freshness_seconds': <max assessment age>, "
                "'trusted_keys': {<key_id>: <Ed25519 public key>}} or "
                "explicitly acknowledge ungoverned capability mode with "
                "capability_ungoverned_ack='<reason>' (a non-blank "
                "reason; refused in production; the declaration is "
                "chained into the audit log).",
                code="gov.executor.capability_gate_unconfigured_refused")
        # Raw pipeline: the wave-85 ungoverned_ack already declares this
        # run ungoverned; the capability gate does not pretend otherwise.
        return None, None, None

    # Explicit acknowledgement: non-blank, recorded, refused outright
    # in production -- the wave-85 posture, applied to the capability
    # gate.
    if (not isinstance(capability_ungoverned_ack, str)
            or not capability_ungoverned_ack.strip()):
        _refuse(
            "blank_ack",
            "REFUSED: capability_ungoverned_ack is blank/whitespace-only "
            "-- a hollow justification. State a real reason or bind the "
            "capability gate.")
    from .keyprovider import resolve_deployment_mode
    try:
        mode = resolve_deployment_mode()
    except Exception as exc:
        _refuse(
            "unresolvable_mode",
            "REFUSED: deployment mode unresolvable (%s) -- failing "
            "closed toward refusal; an unknown mode never silently "
            "disables the capability gate." % (exc,))
    if mode == "production":
        _refuse(
            "production",
            "REFUSED: deployment mode is production -- ungoverned "
            "capability mode is refused even with a declared reason. "
            "Bind the capability gate or do not run here.")
    reason = capability_ungoverned_ack.strip()
    caller = _construction_caller()
    try:
        log.append({
            "event": "capability_gate_ungoverned_declared",
            "run_id": run_id,
            "agent_id": "system",
            "role": "system",
            "decision": "declared",
            "policy_id": "capability-gate",
            "ungoverned_reason": reason,
            "deployment_mode": mode,
            "reason": (
                "LOUD: ToolExecutor constructed with NO capability gate "
                "under an explicit, recorded declaration. Declared "
                "reason: %r. Deployment mode: %s. Declared by %s:%s in "
                "%s. No capability assessment will be required or "
                "verified for this run -- audit accordingly."
                % (reason, mode, caller["caller_file"],
                   caller["caller_line"], caller["caller_function"])),
            "caller_file": caller["caller_file"],
            "caller_line": caller["caller_line"],
            "caller_function": caller["caller_function"],
        })
    except NoKeyConfiguredError:
        raise
    except Exception as exc:
        raise _capability_gate.CapabilityGateBindingError(
            "REFUSED: the capability_gate_ungoverned_declared declaration "
            "could not be chained (%s) -- an unrecorded declaration is "
            "not a declaration." % (exc,))
    return None, None, reason


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


def _type_to_confirm_reference_texts(goal):
    """Wave-145 (row-11): reference scope texts for the type-to-confirm
    ceremony, rendered from the goal's DECLARED scope at queue time.

    The list carries the goal description plus one ``"verb target"``
    text per declared effect atom (wildcard targets included -- the
    ``"*"`` contributes no tokens, so the verb carries the mechanical
    half; a pure-wildcard goal stays approvable, which the wave-135
    "acknowledge its breadth" path requires). The human's typed scope
    is matched against these texts with ``gov.target_match``
    token-tversky at ``DEFAULT_THRESHOLD`` (see
    ``ApprovalQueue.decide``). Deterministic, order-stable,
    de-duplicated; the stamped list is MAC-bound on the review record
    (F38), so the check runs against exactly what the review
    displayed.
    """
    texts = []
    if not isinstance(goal, dict):
        return texts
    desc = goal.get("description")
    if isinstance(desc, str) and desc.strip():
        texts.append(desc.strip())
    for atom in goal.get("effects") or []:
        if isinstance(atom, (tuple, list)) and len(atom) == 2:
            verb, tgt = atom
            s = ("%s %s" % ("" if verb is None else verb,
                            "" if tgt is None else tgt)).strip()
            if s and s not in texts:
                texts.append(s)
    return texts


class ToolExecutor:
    def __init__(self, run_dir, policy, log, approvals, ledger_path=None,
                 principal_registry=None, session_identity=None,
                 tool_ratings=None, credential_manifest=None,
                 canary_registry=None, delegation_context=None,
                 policy_store=None, detection_monitor=None,
                 erosion_monitor=None,
                 recovery=None, lease_verifier=None,
                 lease_gated_tools=(), precommit_gate=None,
                 trifecta_floor=False, ungoverned_ack=None,
                 revocation_checker=None, spawn_budget=None,
                 message_bus=None, memory_firewall=None,
                 tool_inventory=None, trajectory_checkpoint_every=50,
                 lineage_tracker=None, skill_watch=None,
                 skill_tool_map=None, skill_mcp_map=None,
                 skill_pin_path=None,
                 capability_gate_binding=None, capability_assessment=None,
                 capability_ungoverned_ack=None,
                 # Sentinel credential substitution (adapted from
                 # anthropics/sandbox-runtime): appended LAST so no
                 # existing positional caller can misalign.
                 sentinel_registry=None,
                 # Monotonic advisory layer (adapted from
                 # microsoft/agent-governance-toolkit): appended LAST
                 # for the same positional-misalignment reason.
                 # Opt-in: None (default) = zero behavior change.
                 advisors=None,
                 # Cross-run drift detection (row 9, wave-131): appended
                 # LAST for the same positional-misalignment reason.
                 # Opt-in: None (default) = zero behavior change.
                 drift_store=None,
                 # Unlabeled-egress content analysis (row 13, wave-132):
                 # appended LAST for the same positional-misalignment
                 # reason. Opt-in: None (default) = zero behavior change.
                 content_monitor=None,
                 # Post-run artifact sweep (row 12 second half,
                 # wave-133): appended LAST for the same
                 # positional-misalignment reason. Opt-in: None
                 # (default) = zero behavior change.
                 # Shape (wave-136): True = sweep the run sandbox
                 # after execute_approved(); or a dict
                 # {"watch_roots": [(root, baseline_inventory), ...]}
                 # to also sweep operator-configured watch roots
                 # (baselines from artifact_sweep.register_watch_root).
                 # None/False = no sweep at all.
                 artifact_sweep=None,
                 # Cross-run argument-distribution (framing) drift
                 # (row 9, wave-134): appended LAST for the same
                 # positional-misalignment reason. Opt-in: None
                 # (default) = zero behavior change.
                 framing_store=None,
                 # Cross-run intent ledger (row 7, wave-134): appended
                 # LAST for the same positional-misalignment reason.
                 # Opt-in: None (default) = zero behavior change (the
                 # cross-run countermand check in execute_approved is
                 # inert without one).
                 intent_ledger=None,
                 # Population-relative baseline validation (row 9,
                 # wave-134): appended LAST for the same
                 # positional-misalignment reason. Opt-in: None
                 # (default) = zero behavior change (validate_baseline
                 # returns None; check_run_drift never caps).
                 population_store=None,
                 # Rare-token carryover detection (row 13, wave-136):
                 # appended LAST for the same positional-misalignment
                 # reason. Opt-in: None (default) = zero behavior
                 # change (check_rare_token_carryover returns a silent
                 # allow without touching anything).
                 rare_token_tracker=None,
                 # Injection-propagation screening (Row 19, wave-151):
                 # appended LAST for the same positional-misalignment
                 # reason. Opt-in: None (default) = zero behavior
                 # change (check_output_propagation returns a silent
                 # allow without touching anything; note_propagation_input
                 # is a no-op).
                 propagation_tracker=None,
                 # Public-channel propagation refusal (Row 19, wave-245
                 # lane 8): appended LAST for the same
                 # positional-misalignment reason. Opt-in: None
                 # (default) = zero behavior change
                 # (check_public_channel_egress returns a silent allow
                 # without touching anything; note_public_channel_input
                 # is a no-op).
                 propagation_guard=None,
                 # Deployment-pinned artifact manifest (row 12,
                 # wave-158): appended LAST for the same
                 # positional-misalignment reason. DEFAULT-ON: the
                 # deployment hands over the operator-pinned envelope
                 # (dict from
                 # gov.artifact_inventory_manifest.pin_manifest --
                 # attached and verified fail-loud at construction),
                 # or explicitly opts out with a recorded reason
                 # (deployment_manifest_opt_out="<reason>"). Silent
                 # absence (both None) is fail-closed in production
                 # and LOUD (chained deployment_manifest_absent)
                 # elsewhere -- the artifact-integrity seam must never
                 # be silently absent.
                 deployment_manifest=None,
                 deployment_manifest_opt_out=None,
                 # Row-12 undeclared-path write binding (wave-162):
                 # sandbox-relative directory prefixes the deployment
                 # declares as writable scratch/output space, in
                 # ADDITION to the manifest's declared artifact paths.
                 # A write_file whose resolved target is neither a
                 # manifest-declared path nor under one of these dirs
                 # is forced to human approval (never executes on a
                 # policy allow alone). None/empty = manifest paths
                 # only. Appended LAST so no existing positional caller
                 # can misalign. Opt-in: zero behavior change when no
                 # manifest is attached.
                 declared_write_dirs=None,
                 # Memory act-time gate (wave-173 lane 1, TMA-NM):
                 # gov.memory_actgate.ActGate, constructed by the
                 # deployment in the operator trust domain (it owns the
                 # corroboration log path and the trusted-principal
                 # set). Appended LAST so no existing positional caller
                 # can misalign. Opt-in: None (default) = pre-wave-173
                 # behavior, zero behavior change.
                 memory_actgate=None,
                 # Countersigned invocation receipts (wave-175 lane 1,
                 # R7 #7 Sigil shape): explicit 32-byte Ed25519 seed hex
                 # for the executor's countersigning key. Appended LAST
                 # so no existing positional caller can misalign.
                 # None (default) = resolve from GOV_RECEIPT_KEY /
                 # GOV_RECEIPT_KEY_FILE; unconfigured = receipts disabled
                 # with one loud chained event (never silent, never a
                 # dev-key fallback).
                 receipt_key_seed=None,
                 # Wave-176 (OpenShell steal #2, constructive decision
                 # packets): explicit 32-byte hex seed for the
                 # decision-packet signing key. None (default) = resolve
                 # from GOV_DECISION_PACKET_KEY /
                 # GOV_DECISION_PACKET_KEY_FILE; unconfigured = packets
                 # disabled with one loud chained event (never silent,
                 # never a dev-key fallback).
                 packet_key_seed=None,
                 # Wave-196 lane C (step-ca steal): the deployment's
                 # issuance authorities. None (default) = the legacy
                 # mint_identity behavior, byte-for-byte. Configured =
                 # every mint names a provisioner and is checked against
                 # its lifetime-claims envelope (max TTL, scopes, roles,
                 # renewal, per-provisioner budget, break-glass
                 # justification). Built from deployment config, never
                 # from agent input.
                 provisioner_registry=None,
                 # Attestation-conditioned credential release (wave-198,
                 # Trustee KBS mechanism steal): a
                 # gov.attestation_release.AttestationReleaseConfig
                 # holding the trusted issuer keyset, pinned issuers,
                 # live attestation registry, and jti replay cache.
                 # Appended LAST so no existing positional caller can
                 # misalign. Opt-in: None (default) = pre-wave-198
                 # behavior for host-only credentials; attestation-
                 # mandatory credentials REFUSE without one (no silent
                 # fallback to host-only).
                 attestation_config=None,
                 # Cross-policy-set combination (wave-249 wiring):
                 # tuple of additional PolicyEngine instances evaluated
                 # alongside the primary policy, combined with the
                 # forbid-overrides-permit guarantee
                 # (gov/policy_combine.py). Appended LAST so no existing
                 # positional caller can misalign. Opt-in: empty
                 # (default) = pre-wave-249 behavior, zero change.
                 policy_set=(),
                 # Per-call authorization enforcement (wave-260, envoy
                 # ext_authz adaptation): a gov.call_enforcement
                 # CallEnforcer consulted on EVERY sentinel credential
                 # swap at the execution boundary (both the direct path
                 # and the approved sweep). Appended LAST so no existing
                 # positional caller can misalign. Opt-in: None
                 # (default) = pre-wave-260 behavior, zero change; when
                 # set, a deny (or check error/timeout, or no matching
                 # policy) refuses the swap fail-closed with a
                 # callauthz-* machine code and nothing is substituted.
                 call_authorizer=None,
                 # Reconstructed-intent scoring seam (wave-266, F248):
                 # a gov.reconstructed_intent.ReconstructionSeam,
                 # constructed by the deployment in the operator trust
                 # domain (it owns the chunk buffer feeding and the
                 # human-approval queue the hold is queued to).
                 # Appended LAST so no existing positional caller can
                 # misalign. Opt-in: None (default) = pre-wave-266
                 # behavior, zero behavior change
                 # (check_reconstructed_intent returns a quiet verdict
                 # without touching anything; note_read_output does not
                 # buffer chunks).
                 reconstruction_seam=None,
                 # Discovery-driven tool-definition registry (wave-282
                 # lane 4, snyk/agent-scan ADAPT): hash-pinned
                 # observations of discovered tool definitions +
                 # scheduled re-scan (drift = fail-closed hold). A
                 # gov.discovery_scan.ToolDefinitionRegistry,
                 # constructed by the deployment in the operator trust
                 # domain. Appended LAST so no existing positional
                 # caller can misalign. Opt-in: None (default) =
                 # pre-wave-282 behavior, zero behavior change.
                 # discovery_tool_map={tool_name: (scope, agent_host,
                 # component_id)} wins for attribution;
                 # discovery_mcp_map={server_id: (scope, agent_host,
                 # component_id)} attributes the mcp_server framing
                 # kwarg; discovery_observe_one(tool_key) is the
                 # deployment's sandboxed change-time observation and
                 # receives the FULL 4-part tool key (scope,
                 # agent_host, component_id, tool_name) -- F315: the
                 # re-observation binds to the pinned identity, never
                 # the name alone.
                 # discovery_pin_path optionally names the JSON pin
                 # file (existing but corrupt refuses construction
                 # LOUD; stored pins merge into the live registry at
                 # construction). Pins persist automatically after each
                 # run_discovery_scan().
                 discovery_scan=None,
                 discovery_tool_map=None,
                 discovery_mcp_map=None,
                 discovery_observe_one=None,
                 discovery_pin_path=None,
                 # Workload identity (wave-319, SPIFFE-semantics steal):
                 # the attested identity document for this executor's
                 # agent, minted by the deployment's launch path for
                 # audience "governance:approval-queue"
                 # (gov.workload_identity.mint_document), the
                 # launch-path-attested selectors it was minted for,
                 # and a gov.workload_identity.DocumentVerifier bound
                 # to the deployment's issuer keys. Appended LAST so
                 # no existing positional caller can misalign. Opt-in:
                 # all-None (default) = pre-wave-319 behavior, zero
                 # change. When agent_svid is set, the verifier and
                 # selectors are REQUIRED (fail-fast TypeError) and
                 # the verifier is installed write-once on the
                 # approval queue; call() attaches the document at
                 # queue time and the queue stamps the ADVISORY claim
                 # MAC-bound on the record (verified:false never
                 # gates -- the deterministic policy layer stays
                 # canonical).
                 agent_svid=None,
                 agent_svid_selectors=None,
                 attested_identity_verifier=None):
        # Wave-319 (workload identity): fail fast on a half-configured
        # attested-identity wiring -- a document with no verifier (or no
        # attested selectors) would otherwise queue unverifiable claims.
        if agent_svid is not None:
            if attested_identity_verifier is None:
                raise TypeError(
                    "agent_svid requires attested_identity_verifier: a "
                    "gov.workload_identity.DocumentVerifier bound to the "
                    "deployment's issuer keys")
            if not isinstance(agent_svid_selectors, dict):
                raise TypeError(
                    "agent_svid requires agent_svid_selectors: the "
                    "launch-path-attested facts the document was minted "
                    "for")
        self._agent_svid = agent_svid
        self._agent_svid_selectors = agent_svid_selectors
        self._attested_identity_verifier = attested_identity_verifier
        if agent_svid is not None:
            from . import workload_identity as _wi
            approvals.set_attested_identity_verifier(
                attested_identity_verifier,
                _wi.APPROVAL_QUEUE_AUDIENCE)
        # Wave-196 lane C: the provisioner registry (None = legacy
        # issuance behavior) and the per-provisioner mint counters used
        # for max_mints_per_run budgets. Counters live per executor
        # (per run); refusals never increment them. Fail fast on a
        # misconfigured registry: a non-registry value would otherwise
        # explode with AttributeError at mint time.
        if (provisioner_registry is not None
                and not isinstance(
                    provisioner_registry,
                    _provisioner.ProvisionerRegistry)):
            raise ValueError(
                "provisioner_registry must be a "
                "gov.provisioner.ProvisionerRegistry or None, got %r"
                % (provisioner_registry,))
        self._provisioner_registry = provisioner_registry
        self._provisioner_mint_counts = {}
        # Wave-198 (graduation ladder, R1 warn-fatigue): the per-rule
        # per-window warn digest aggregator. Warn-mode decisions are
        # recorded here and flushed as ONE chained operator digest per
        # rule per window -- the agent's verdict path is untouched and
        # warnings never reach the agent as interrupts.
        self._warn_digest_agg = _mode_ledger.WarnDigestAggregator()
        self.run_dir = Path(run_dir)
        self.run_id = self.run_dir.name
        self.policy = policy
        self.log = log
        self.approvals = approvals
        # Wave-249 wiring: cross-policy-set combination. Empty tuple =
        # pre-wave-249 behavior (single-policy verdict, zero change).
        self._policy_set = tuple(policy_set or ())
        # Wave-89 (S2, inter-agent messaging): the governed message bus
        # (gov/messaging.MessageBus), constructed by the deployment in the
        # operator trust domain. Opt-in: None = pre-wave-89 behavior, zero
        # behavior change. When installed, send()/receive() are governed
        # (provenance stamps, steg screening, bandwidth caps) and
        # lineage quarantine is enforced at send/receive/call/spawn.
        self._message_bus = message_bus
        # Wave-85 (legacy-seam closure): fail-closed construction. The
        # governed core (policy_store + delegation_context) is the
        # DEFAULT; constructing without it requires an explicit,
        # non-blank, recorded ungoverned_ack — refused outright in
        # production, and unknown/unresolvable deployment modes fail
        # closed toward refusal. The check runs BEFORE anything
        # executes (no directories created, no audit writes except the
        # gate's own LOUD declaration / best-effort refusal record).
        self._ungoverned_ack, self._ungoverned_missing = (
            _fail_closed_construction_check(
                self.run_id, log, policy_store, delegation_context,
                ungoverned_ack,
                non_core=(("detection_monitor", detection_monitor),
                          ("erosion_monitor", erosion_monitor),
                          ("recovery", recovery),
                          ("lease_verifier", lease_verifier),
                          ("precommit_gate", precommit_gate),
                          ("trifecta_floor", trifecta_floor))))
        # Wave-100 (Stream 1): the capability gate. A deployment that
        # looks governed (governed core installed) must bind a
        # capability gate or explicitly acknowledge ungoverned
        # capability mode -- otherwise the benchmark's SUFFICIENT grade
        # is a story the runtime never checks. Raw-pipeline deployments
        # (no core) are untouched: the wave-85 ack already declares
        # them ungoverned. The binding is normalized here (fail-closed
        # on malformed); the assessment itself is verified per
        # call/spawn so rotation and expiry are always current.
        (self._capability_gate_binding, self._capability_assessment,
         self._capability_ungoverned_ack) = (
            _capability_gate_construction_check(
                self.run_id, log, policy_store, delegation_context,
                capability_gate_binding, capability_assessment,
                capability_ungoverned_ack))
        # Row-12 (wave-158): the deployment manifest is DEFAULT-ON at
        # the deployment ceremony (executor construction). The operator
        # hands over the pinned envelope (attached and verified
        # fail-loud here) or explicitly opts out with a recorded
        # reason; silent absence is fail-closed in production and LOUD
        # (chained deployment_manifest_absent) elsewhere. The decision
        # inputs are kept so spawned children inherit the deployment's
        # manifest posture instead of re-deciding it. This runs with
        # the other construction-time declarations, BEFORE the F22 log
        # size guard is armed below: the declaration is part of the
        # ceremony and must chain even under a tiny test cap (the guard
        # constrains run activity, not the deployment's own declaration).
        # Row-12 (wave-130): run-scoped artifact inventory. Every
        # successful write_file registers (path, sha256, size, agent,
        # label); egress referencing a file is checked against it.
        # Empty by default: no writes, no behavior change.
        self.artifacts = _artifacts.ArtifactInventory()
        (self._deployment_manifest_decision,
         self._deployment_manifest_opt_out_reason) = (
            _deployment_manifest_construction_check(
                self.run_id, log.append, self.artifacts,
                deployment_manifest, deployment_manifest_opt_out))
        self._deployment_manifest_envelope = deployment_manifest
        # Row-12 (wave-162): deployment-declared writable scratch/output
        # dirs for the undeclared-path write binding. Normalized to
        # sandbox-relative prefixes (same normalization as the manifest
        # entries); a malformed entry fails closed at construction.
        self._declared_write_dirs = _normalize_declared_write_dirs(
            declared_write_dirs)
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
        # Wave-86 (GAP 2): the revocation checker wired into the real
        # verdict path. When provided, EVERY tool call checks the leaf
        # AND its ancestors (gov/delegation_tokens.authorize_action
        # implements the seam; a checker that errors fails closed as
        # DelegationRevokedError). When None with delegation installed,
        # revocation is TTL-only — disclosed loudly, once per process:
        # a revoked token authorizes until expiry.
        self._revocation_checker = revocation_checker
        if delegation_context is not None and revocation_checker is None:
            warn_revocation_ttl_only_once()
        # Wave-86 (governed spawn): the run's spawn budget. None =
        # unlimited (documented; the chained agent_spawn events are the
        # detection story). An int bounds the whole spawn lineage —
        # the box is shared by reference with child executors.
        if spawn_budget is None:
            self._spawn_budget = None
        else:
            if (isinstance(spawn_budget, bool)
                    or not isinstance(spawn_budget, int)
                    or spawn_budget < 0):
                raise ValueError(
                    "spawn_budget must be None or a non-negative int, "
                    "got %r" % (spawn_budget,))
            self._spawn_budget = _SpawnBudget(spawn_budget)
        # S1-MEM (memory provenance firewall, memo row 1): opt-in.
        # None (the default) = pre-S1 behavior, zero behavior change.
        # When a gov.memory_provenance.MemoryFirewall is installed,
        # write_file/read_file on deployment-designated memory paths are
        # routed through it: writes are tiered and chained into the
        # per-deployment memory ledger, and reads of untrusted or unknown
        # instruction-shaped entries are quarantined (fail-closed, loud).
        # The firewall instance is deployment-constructed (it owns the
        # ledger path); the executor only routes events through it.
        self._memory_firewall = memory_firewall
        self._mem_scanned_principals = set()
        # Wave-173 lane 1 (TMA-NM act-time gate): the deployment's
        # corroboration-gated memory elevation gate. Opt-in: None =
        # pre-wave-173 behavior, zero behavior change. When attached,
        # governed memory reads are provenance-classified per run
        # (see _memory_firewall_hook), the queue-time snapshot discloses
        # un-elevated reads on the approval record, and the approved
        # sweep refuses executions whose un-elevated reads were never
        # disclosed to the approver.
        self._memory_actgate = memory_actgate
        # Wave-313 (Row 7 step 3): the process-local nonce ledger for
        # capability/argument-bound approval tokens. The sweep verifies
        # a record's token (when present) and consumes its nonce after
        # the durable claim (mark_executed), so a token authorizes at
        # most one execution. Cross-process at-most-once rides the
        # queue lock plus the record-executed marking, like every other
        # sweep check.
        self._approval_token_store = _approval_tokens.TokenConsumeStore()
        # Wave-175 lane 1 (countersigned invocation receipts, R7 #7 Sigil
        # shape): resolve the executor's countersigning key. Fail-closed
        # two-tier:
        #   (a) the deployment EXPRESSED intent (explicit seed, or
        #       GOV_RECEIPT_KEY / GOV_RECEIPT_KEY_FILE set) but custody is
        #       broken/unreadable -> raise NoReceiptKeyError at
        #       construction. No executor exists, so no consequential side
        #       effect can happen. This is the fail-closed behavior.
        #   (b) nothing configured (opt-in off) -> one loud chained
        #       invocation_receipts_disabled event, no receipts, executions
        #       proceed. Never silent, never a dev-key fallback (wave-81
        #       precedent).
        _receipt_intent = (receipt_key_seed is not None
                           or os.environ.get("GOV_RECEIPT_KEY",
                                             "").strip()
                           or os.environ.get("GOV_RECEIPT_KEY_FILE",
                                             "").strip())
        try:
            self._receipt_key = _receipts.resolve_receipt_key(
                explicit=receipt_key_seed)
        except _receipts.NoReceiptKeyError as _rke:
            if _receipt_intent:
                raise
            self._receipt_key = None
            self.log.append({
                # Wave-219 unsafe-path registry: gov.executor.invocation_receipts_disabled
                "event": "invocation_receipts_disabled",
                "code": "gov.executor.invocation_receipts_disabled",
                "run_id": self.run_id,
                "agent_id": "system",
                "role": "system",
                "decision": "absent",
                "policy_id": "invocation-receipt-seam",
                "reason": ("No receipt-signing key configured: %s. "
                           "Consequential invocations will execute WITHOUT "
                           "a countersigned invocation receipt."
                           % (_rke,)),
            })
        else:
            self.log.append({
                "event": "invocation_receipts_enabled",
                "run_id": self.run_id,
                "agent_id": "system",
                "role": "system",
                "decision": "present",
                "policy_id": "invocation-receipt-seam",
                "receipt_key_id": self._receipt_key["key_id"],
                "receipt_pubkey": self._receipt_key["pubkey_hex"],
                "reason": ("Receipt-countersigning key %s configured: "
                           "consequential invocations will carry an "
                           "Ed25519 countersigned invocation receipt."
                           % (self._receipt_key["key_id"],)),
            })
        # Wave-176 (OpenShell steal #2, constructive decision packets):
        # the packet-signing key. Same two-tier custody idiom as the
        # invocation receipts (wave-175 lane 1):
        #   (a) a key was INTENDED (explicit seed or env/file set) but is
        #       broken -> raise LOUD at construction: a deployment that
        #       asked for signed packets must not silently run unsigned.
        #   (b) nothing configured (opt-in off) -> one loud chained
        #       decision_packet_disabled event, no packets, executions
        #       proceed. Never silent, never a dev-key fallback (wave-81
        #       precedent).
        _packet_intent = (packet_key_seed is not None
                          or os.environ.get("GOV_DECISION_PACKET_KEY",
                                            "").strip()
                          or os.environ.get("GOV_DECISION_PACKET_KEY_FILE",
                                            "").strip())
        try:
            self._packet_key = _decision_packet.resolve_packet_key(
                explicit=packet_key_seed)
        except _decision_packet.NoPacketKeyError as _pke:
            if _packet_intent:
                raise
            self._packet_key = None
            self.log.append({
                # Wave-219 unsafe-path registry: gov.executor.decision_packet_disabled
                "event": "decision_packet_disabled",
                "code": "gov.executor.decision_packet_disabled",
                "run_id": self.run_id,
                "agent_id": "system",
                "role": "system",
                "decision": "absent",
                "policy_id": "decision-packet-seam",
                "reason": ("No decision-packet signing key configured: %s. "
                           "Policy decisions will execute WITHOUT a signed "
                           "decision packet." % (_pke,)),
            })
        else:
            self.log.append({
                "event": "decision_packet_enabled",
                "run_id": self.run_id,
                "agent_id": "system",
                "role": "system",
                "decision": "present",
                "policy_id": "decision-packet-seam",
                "packet_key_id": self._packet_key["key_id"],
                "packet_pubkey": self._packet_key["pubkey_hex"],
                "reason": ("Decision-packet signing key %s configured: "
                           "policy decisions will carry a signed, "
                           "self-describing decision packet."
                           % (self._packet_key["key_id"],)),
            })
        # Wave-176 (OpenShell steal #1, AuthorityProof contract): the
        # operator-declared authority boundary. None = the deployment
        # declared no boundary -> the checker runs advisory-only and
        # attaches its proof to the decision record; a declared
        # boundary makes exceeds/unsupported/inconclusive refuse
        # fail-closed at the pre-decision path and the approved sweep.
        # Set post-construction via set_authority_boundary(); the
        # boundary object is immutable and validated at load, so the
        # seam never mutates operator authority mid-flight.
        self._authority_boundary = None
        # Wave-198 lane E: keyset-attested MCP ToolAnnotations registry
        # (gov.mcp_annotations). Default None = legacy MCP behavior,
        # zero behavior change: without a registry the authority
        # proof's MCP scope seam is skipped exactly as before. Set
        # post-construction via set_mcp_tool_registry(); the registry
        # is operator authority (built by
        # gov.mcp_annotations.build_tool_registry over keyset-attested
        # statements), so the agent-facing paths never call it.
        self._mcp_tool_registry = None
        # Wave-319 (grant negotiation): deployment-owned grant registry
        # for the advisory grant check. None (the default) means the
        # check is not-applicable: zero behavior change. Set
        # post-construction via set_grant_registry(); the registry is
        # operator authority, so the agent-facing paths never call it.
        self._grant_registry = None
        # Wave-198 lane E: verified identity-token claim sets, keyed by
        # agent_id, recorded at mint_identity time. The claims were
        # signature-verified by the dex client and claim-policy-checked
        # (iss/aud/exp, sub/role/principal binding) at the mint seam;
        # the authority proof's MCP scope seam reads these at check
        # time and re-validates expiry on every check, so a stale token
        # fails closed. No token presented at mint -> no entry ->
        # scope-required tools fail closed for that agent.
        self._mcp_token_claims = {}
        # Wave-90 (S6, F137 — infection lineage): the lineage substrate
        # (gov.lineage.LineageTracker), constructed by the deployment in
        # the operator trust domain and shared across a spawn lineage by
        # reference. Opt-in: None = pre-wave-90 behavior, zero behavior
        # change. When installed, there is no silent opt-out WITHIN the
        # run: call() refuses unlineaged identities fail-closed,
        # spawn_sub_agent mints a birth certificate for every child
        # (taint is hereditary at birth), and agent-driven file writes
        # are lineage-stamped / reads record lineage contact — so the
        # raw file channel carries the same provenance the S2 bus gives
        # the message channel. The tracker instance is
        # deployment-constructed (it owns run_dir/lineage/); the
        # executor only routes events through it.
        self._lineage_tracker = lineage_tracker
        self._lineage_cert = None  # this executor's birth certificate
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
        # Row-9 Phase B (wave-119): the trajectory-level caution-erosion
        # monitor (gov/detection.TrajectoryErosionMonitor). Opt-in:
        # None = pre-wave-119 behavior, zero behavior change. When
        # installed, call() feeds it every verdict-path call (next to
        # the wave-89 trajectory note) and consults its breaker on the
        # verdict path: an OPEN erosion breaker downgrades allow
        # verdicts on high-risk tools to require_approval (a breaker
        # INPUT, never a verdict -- no single action is denied because
        # of the trajectory signal). The monitor is per-run; its
        # breaker lives and dies with the run (no half-open, no human
        # reset in v1).
        self._erosion_monitor = erosion_monitor
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
        # Sentinel credential substitution (adapted from
        # anthropics/sandbox-runtime credential-sentinel.ts): the run's
        # SentinelVault (operator trust domain, process memory only).
        # Default None = substitution off, zero behavior change. When
        # set, validate_sentinel_binding runs on the egress-attempt
        # path inside call() (binding verified BEFORE the policy
        # decision; mismatch trips SentinelTripHalt fail-closed), and
        # substitute_for_execution swaps sentinels for real values ONLY
        # at the execution boundary (direct-allow path and approved
        # sweep), into an ephemeral copy — the secret never enters the
        # audit path.
        self.sentinel_registry = sentinel_registry
        # Wave-260: per-call authorization enforcer for the sentinel
        # substitution seam (gov.call_enforcement.CallEnforcer or
        # None). Opt-in: None (default) = pre-wave-260 behavior.
        self.call_authorizer = call_authorizer
        # Wave-198: attestation-conditioned release trust anchor
        # (gov.attestation_release.AttestationReleaseConfig or None).
        # Fail fast on a misconfigured value: a non-config would
        # otherwise explode with AttributeError at release time --
        # and a missing anchor must refuse LOUDLY, never silently.
        if (attestation_config is not None
                and not isinstance(
                    attestation_config,
                    _attestation_release.AttestationReleaseConfig)):
            raise ValueError(
                "attestation_config must be a "
                "gov.attestation_release.AttestationReleaseConfig "
                "or None, got %r" % (attestation_config,))
        self.attestation_config = attestation_config
        # Monotonic advisory layer (opt-in). The composer enforces the
        # allow < require_approval < deny lattice: advisors can only
        # tighten the deterministic verdict, never loosen it.
        # _advisory_bom_chain is a shared mutable cell holding the
        # previous BOM digest, so parent and spawned children extend
        # ONE decision-BOM sub-chain in the shared audit log.
        self._advisors = list(advisors) if advisors else None
        # Wave-131 (row 9): cross-run drift store, operator-supplied.
        # Opt-in: None = zero behavior change (check_run_drift returns
        # a silent result without touching anything).
        self.drift_store = drift_store
        # Wave-132 (row 13): unlabeled-egress content monitor,
        # operator-supplied. Opt-in: None = zero behavior change
        # (check_egress_content returns a silent allow without touching
        # anything).
        self.content_monitor = content_monitor
        # Wave-133 (row 12 second half): post-run artifact sweep,
        # operator opt-in. Opt-in: None/False = zero behavior change
        # (execute_approved does not sweep; run_artifact_sweep still
        # works when called directly). Wave-136: True sweeps the run
        # sandbox; {"watch_roots": [...]} also sweeps watch roots.
        # Wave-140: {"declared_inventory": ...} adds the coverage-gap
        # report. Wave-143: {"roots_declaration": <envelope from
        # gov.artifact_sweep.declare_watch_roots>} adds watch-root
        # declaration enforcement (LOUD on out-of-band changes,
        # fail-closed unverified sweep).
        self.artifact_sweep = artifact_sweep
        # Wave-134 (row 9): cross-run framing-drift store,
        # operator-supplied. Opt-in: None = zero behavior change
        # (check_run_framing returns a silent result without touching
        # anything).
        self.framing_store = framing_store
        # Wave-134 (row 7): cross-run intent ledger,
        # operator-supplied. Opt-in: None = zero behavior change
        # (the execution-boundary countermand check is inert without
        # one; record_intent_turn is a no-op returning None).
        self.intent_ledger = intent_ledger
        # Wave-134 (row 9): population-relative baseline store,
        # operator-supplied. Opt-in: None = zero behavior change
        # (validate_baseline returns None; check_run_drift never
        # applies the provisional WARN cap).
        self.population_store = population_store
        # Wave-136 (row 13): rare-token carryover tracker,
        # operator-supplied. Opt-in: None = zero behavior change
        # (check_rare_token_carryover returns a silent allow without
        # touching anything; note_read_output is a no-op).
        self.rare_token_tracker = rare_token_tracker
        # Wave-151 (Row 19): injection-propagation tracker,
        # operator-supplied. Opt-in: None = zero behavior change
        # (check_output_propagation returns a silent allow without
        # touching anything; note_propagation_input is a no-op).
        self.propagation_tracker = propagation_tracker
        # Wave-245 lane 8 (Row 19): public-channel propagation guard,
        # operator-supplied. Opt-in: None = zero behavior change
        # (check_public_channel_egress returns a silent allow without
        # touching anything; note_public_channel_input is a no-op).
        self.propagation_guard = propagation_guard
        # Wave-266 (F248): reconstructed-intent scoring seam,
        # deployment-supplied. Opt-in: None = zero behavior change
        # (check_reconstructed_intent returns a quiet verdict without
        # touching anything; note_read_output does not buffer
        # chunks).
        self.reconstruction_seam = reconstruction_seam
        self._advisory_bom_chain = [""]
        # Guards the BOM sub-chain head read-update plus the advisory
        # audit appends, so concurrent call()s on this executor cannot
        # fork the prev_bom_digest linkage. Scope is the BOM sub-chain
        # only -- it does not make call() as a whole thread-safe.
        # Lazy: only created when advisors are configured, preserving
        # the S5 invariant that an advisor-less executor owns no locks.
        self._advisory_lock = threading.Lock() if advisors else None
        # Wave-316 (F399): one run, one provenance sink. The executor
        # owns a single ProvenanceSink for its instance lifetime and
        # passes it to provenance_gate at the sweep seam, so the
        # REPLAN_BUDGET ratchet, the quarantine set, and the
        # consumed-declassification set accumulate across calls
        # instead of being discarded per call. Per-context isolation
        # is preserved by the sink's ctx_key (tool + influencing
        # segment ids): a fresh re-plan context gets a fresh budget,
        # no cross-context bleed. The sink is dropped with the
        # executor at the end of the run -- state only accumulates on
        # refusals/quarantines/declassifications (one small entry per
        # distinct context), bounded by the run's own activity. The
        # sweep is single-threaded, so the sink is used serially.
        self._pv_sink = _provenance_sink.ProvenanceSink()
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
        # S3 shield (wave-89): cooling-off pause length. Defensive
        # getattr — gov/policy.py may gain a normalized
        # ``cooling_off_seconds`` attr in a later wave; until then the
        # queue default (15 min) stands. Policy file keeps the
        # F90 unknown-key guard, so an un-normalized deployment key is
        # refused loudly rather than silently honored.
        if hasattr(approvals, "set_cooling_off_seconds"):
            approvals.set_cooling_off_seconds(
                getattr(policy, "cooling_off_seconds", None))
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
        # Wave-134 (row-11): approval-decision -> goal-resolution
        # wiring. When a goal_conflict_review item is decided, the
        # decision resolves the underlying conflict (see
        # _on_approval_decision). F31 write-once: a second executor
        # sharing this queue keeps the first hook instead of replacing
        # it — replacement is refused, so a hostile re-install cannot
        # swap the binding. Guarded by hasattr like the verifier.
        if hasattr(approvals, "set_decision_hook"):
            try:
                approvals.set_decision_hook(self._on_approval_decision)
            except DecisionHookAlreadySetError:
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
        # Wave-89 (stream s5-tool): tool-execution continuity. The
        # digest-pinned tool inventory (gov/tool_continuity.ToolInventory)
        # and the trajectory re-verifier (gov/tool_continuity.
        # TrajectoryReverifier). tool_inventory=None builds the default
        # inventory from the built-in tool table (zero behavior change
        # for built-in tools: their digests are stable, so no drift can
        # fire). trajectory_checkpoint_every=50 chains a
        # trajectory_reverified event every 50th call and forces full
        # gate re-verification; 0/None disables the periodic
        # checkpoint (tier-escalation markers still fire — cheap and
        # always on). Existing tests make far fewer than 50 calls per
        # run, so the default changes no suite verdict.
        self._tool_inventory = (
            tool_inventory
            if tool_inventory is not None
            else _tool_continuity.ToolInventory())
        # Wave-92 (stream C): continuous skill/MCP supply-chain
        # verification (gov/skill_watch.SkillWatch). Opt-in: None =
        # pre-integration behavior, zero behavior change. When
        # installed, call() runs check_at_use() on the verdict path for
        # every tool attributed to a skill id (see
        # skill_watch.skill_id_for_tool for the attribution rules); a
        # mutated/unverifiable/unregistered skill — or a watcher
        # error — DENIES the call fail-closed with a loud audit
        # entry, never a warning. An id the watcher never pinned is
        # fail-closed (F143): only the deployment's explicit None
        # map entry ("unattributed") skips the check.
        # Watcher events (install, sweep, mutation, quarantine, re-pin)
        # are chained into the HMAC audit log carrying digests and
        # provenance, never skill content. Attribution is deployment
        # config: skill_tool_map={tool_name: skill_id} wins;
        # skill_mcp_map={server_id: skill_id} attributes the mcp_server
        # framing kwarg (default convention "mcp/<server_id>").
        # skill_pin_path optionally names the JSON pin file: an
        # EXISTING but corrupt pin file refuses construction loudly
        # (fail-closed: never start a pinning deployment over
        # unparseable pins); a missing file is a fresh registry. Pins
        # are persisted automatically after each run_skill_sweep().
        if skill_watch is not None and not isinstance(
                skill_watch, _skill_watch.SkillWatch):
            raise TypeError("skill_watch must be a "
                            "gov.skill_watch.SkillWatch, got %r"
                            % type(skill_watch).__name__)
        self._skill_watch = skill_watch
        self._skill_tool_map = dict(skill_tool_map or {})
        self._skill_mcp_map = dict(skill_mcp_map or {})
        self._skill_pin_path = (Path(skill_pin_path)
                                if skill_pin_path is not None else None)
        self._last_skill_sweep_at = None
        # F184 (row-6/14 wiring lane): the skill handoff slot. The
        # verdict-path gate stores (skill_id, attested_digest,
        # verified_bytes) here — exactly the bytes the watcher's
        # fetch_verified_at_use hashed — so the deployment's consumer
        # can execute the attested bytes instead of re-reading the
        # source. Reset on every call(); valid only for the call that
        # just returned (see verified_skill_bytes).
        self._sw_handoff = None
        if self._skill_watch is not None:
            _sw_log = self.log

            def _sw_emit(event, _log=_sw_log):
                entry = {"event": "skill_watch"}
                entry.update(event)
                _log.append(entry)

            self._skill_watch.set_emit(_sw_emit)
            if self._skill_pin_path is not None \
                    and self._skill_pin_path.exists():
                # Integrity probe only: loading pins (with content
                # sources) is the deployment's job — it owns the
                # source factory. But a pinning deployment must never
                # silently start over a corrupt pin file, so an
                # existing file that fails validation refuses
                # construction LOUD here.
                # H22: the probe verifies the manifest MAC with the
                # operator key — a rewritten pin file refuses
                # construction LOUD (skill_pin_tamper), it is never
                # used silently.
                from . import keyprovider as _kp
                _pin_key, _ = _kp.resolve_active_key()
                _skill_watch.PinStore.peek(self._skill_pin_path,
                                           mac_key=_pin_key)
            # F143: construction-time validation of the attribution
            # maps. Any id the maps reference that the watcher never
            # pinned is a misconfiguration (typo, stale entry, or an
            # MCP default-convention id the deployment never
            # registered): WARN loud on the chained audit log, one
            # entry per distinct id. This does NOT refuse
            # construction — the use-time seam (check_at_use) denies
            # those calls fail-closed. Explicit None entries (the
            # deployment's "unattributed" opt-out) never warn.
            _sw_registered = set(self._skill_watch.registered_skills())
            _sw_map_sources = {}
            for _tool_name, _sid in self._skill_tool_map.items():
                if _sid is not None:
                    _sw_map_sources.setdefault(_sid, []).append(
                        "skill_tool_map")
            for _server_id, _sid in self._skill_mcp_map.items():
                if _sid is not None:
                    _sw_map_sources.setdefault(_sid, []).append(
                        "skill_mcp_map")
            for _sid in sorted(_sw_map_sources):
                if _sid in _sw_registered:
                    continue
                self.log.append({
                    "event": "skill_map_unregistered_id",
                    "run_id": self.run_id,
                    "agent_id": "system",
                    "role": "system",
                    "decision": "warning",
                    "policy_id": "skill-watch",
                    "flag": "skill_map_unregistered_id",
                    "skill_id": _sid,
                    "map_source": ",".join(_sw_map_sources[_sid]),
                    "reason": (
                        "WARNING: the skill attribution map(s) %s "
                        "reference skill id %r, which the skill "
                        "watcher never pinned (F143). Tools "
                        "attributed to it will be DENIED at use time "
                        "by the unregistered-no-pin check — "
                        "attribution without verification is no "
                        "longer a silent pass. Register the skill at "
                        "install (register_skill / PinStore), or add "
                        "an explicit None entry for this tool/server "
                        "to opt it out of skill verification "
                        "(unattributed: the policy decides)."
                        % (", ".join(_sw_map_sources[_sid]), _sid)),
                })
        # Wave-282 lane 4 (snyk/agent-scan ADAPT): discovery-driven
        # tool-definition registry. Opt-in: None = pre-wave-282
        # behavior, zero behavior change. When installed, call() runs
        # the registry's change-time check (check_at_use) on the
        # verdict path for every tool attributed by the deployment
        # maps; a drifted/unverifiable/unregistered tool — or an
        # observer error — DENIES the call fail-closed with a loud
        # audit entry (policy_id "discovery-scan"), never a warning.
        # A tool the registry never pinned is fail-closed (first
        # sighting is never trusted silently): only the deployment's
        # explicit absence from the maps ("unattributed") skips the
        # check. Registry events (drift, unregistered, re-pin) are
        # chained into the HMAC audit log carrying digests only,
        # never definition content (redact-before-emit).
        if discovery_scan is not None and not isinstance(
                discovery_scan,
                _discovery_scan.ToolDefinitionRegistry):
            raise TypeError("discovery_scan must be a "
                            "gov.discovery_scan.ToolDefinitionRegistry, "
                            "got %r" % type(discovery_scan).__name__)
        self._discovery_scan = discovery_scan
        self._discovery_tool_map = dict(discovery_tool_map or {})
        self._discovery_mcp_map = dict(discovery_mcp_map or {})
        self._discovery_observe_one = discovery_observe_one
        self._discovery_pin_path = (Path(discovery_pin_path)
                                    if discovery_pin_path is not None
                                    else None)
        self._last_discovery_scan_at = None
        if self._discovery_scan is not None:
            _ds_log = self.log

            def _ds_emit(event, _log=_ds_log):
                entry = {"event": "discovery_scan"}
                entry.update(event)
                _log.append(entry)

            self._discovery_scan.set_emit(_ds_emit)
            if self._discovery_pin_path is not None \
                    and self._discovery_pin_path.exists():
                # Pin-file bootstrap: an existing pin file that fails
                # validation refuses construction LOUD here (the
                # skill_watch PinStore precedent: never silently start
                # over a corrupt pin file). The stored pins are the
                # last persisted truth: they merge into the live
                # registry (live (re-)registrations win on overlap;
                # quarantine unions, so an unresolved drift hold
                # survives the restart). The deployment may also
                # load+merge itself before construction;
                # merge_stored is idempotent.
                _ds_stored = _discovery_scan.RegistryStore(
                    str(self._discovery_pin_path)).load()
                self._discovery_scan.merge_stored(_ds_stored)
        self._trajectory = _tool_continuity.TrajectoryReverifier(
            checkpoint_every=trajectory_checkpoint_every)
        # S2 (K-018): hard budget accrual. Tokens/spend accrue on the
        # RESULT path only (_ingest_result / ingest_foreign_result via
        # result["_usage"] — never call kwargs, so an agent cannot forge
        # its own usage); _budget_actions counts call() invocations that
        # reach the budget guard.
        self._tokens_used = 0
        self._spend_used = 0.0
        self._budget_actions = 0
        # F162 (HIGH): per-run, per-action-class time-window tempo
        # tripwire. Built from the deployment's policy (never the
        # agent); absent tempo: section = conservative defaults
        # (default-enforced, not opt-in). The clock is monotonic and
        # injectable (self._tempo_clock) so tempo tests are
        # deterministic without sleeps; the wire reads the CURRENT
        # attribute through a lambda so late overrides (tests) take
        # effect. The pause is run-scoped and sticky: a fleet rotating
        # agent ids cannot evade it.
        self._tempo_clock = time.monotonic
        _tempo_cfg = self._tempo_cfg()
        self._tempo_wire = _velocity.TempoWire(
            _tempo_cfg.get("window_secs", 60.0),
            {"read": _tempo_cfg.get("max_read"),
             "write": _tempo_cfg.get("max_write"),
             "egress": _tempo_cfg.get("max_egress")},
            clock=lambda: self._tempo_clock())
        self._tempo_paused = False
        self._tempo_resume_aid = None
        self._tempo_trip_class = None  # class that tripped, if paused
        # F167 (MEDIUM): the pause survives executor rotation (the F60
        # fresh-executor-per-sweep deployment pattern). The pause is
        # derived from the run's own chained log — the trip path chains
        # a ``velocity_paused`` record, the resume path a
        # ``velocity_resumed`` record — so a rotated executor starts
        # paused iff the latest such record is a pause. The wire is
        # deliberately NOT rehydrated: its hit timestamps are
        # monotonic-per-boot and meaningless across a restart (the F166
        # lesson); the pause makes the wire moot until resume, and
        # resume resets the tripped class's window anyway.
        self._rehydrate_tempo_pause()
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
        # F189: parallel source keys for _read_contents, kept in
        # lockstep (same indices). _sync_fingerprint_sources() tolerates
        # direct external appends (tests) by padding unknown sources.
        self._read_content_sources = []
        self._read_sensitive = False  # F9: a read returned DLP-sensitive
        # content this run; api_call afterwards is taint-gated.
        # Row-13 closure: classification-labeled provenance taint. When
        # a read_file returns content from a labeled path, the run is
        # tainted with the label's level (max wins); subsequent egress
        # is gated for human declassification review
        # (approval-classified-egress). Label-based, not content-based:
        # paraphrase cannot shed a label attached to the read event.
        # Run-scoped (no cross-run ledger persistence in v1; documented
        # residual).
        self.classification = _classification.ClassificationRegistry()
        self._read_classification = None  # max level string, or None
        self._read_classification_sources = []  # [(path, level)]
        # Wave-129 (row-7 intent slice): opt-in user-turn context for
        # the intent-slice judge. The executor is a tool executor -- it
        # never sees user messages on its own; the harness/operator
        # provides them via set_intent_context(). When set, queued
        # approvals carry the judge's MAC-bound annotation; when unset
        # the judge is inert (verdict None, queueing unchanged).
        self._intent_user_turns = None

        # Wave-279 (F300): opt-in instruction-provenance context. The
        # executor never sees content ingress on its own; the
        # harness/operator registers labeled content units via
        # set_instruction_provenance() (an IngressLabeler built from
        # operator-supplied {text, label, carrier} triples). When set,
        # queued approvals for consequential actions carry the
        # MAC-bound instruction_provenance section rendered by
        # grant_check/render_provenance_section; when unset the seam
        # is inert (no section, queueing unchanged).
        self._prov_labeler = None

        # Wave-130 (row-11 goal registry): per-run registry of declared
        # agent goals with deterministic conflict detection. Opt-in:
        # with no registrations the detector is inert (zero behavior
        # change). Registrations and conflicts are audit-chained via
        # the registry's own sub-chain; the executor routes conflicts
        # LOUD to the log and the approval queue in register_goal().
        self._goal_registry = _goals.GoalRegistry(audit=self.log.append)

    # Wave-198: attestation-conditioned credential release (Trustee
    # KBS mechanism steal). The attestation service / operator
    # registers the agent's current attestation token here; the
    # execution seam resolves it FRESH per release (never cached from
    # run start -- revocation between attempt and execution is caught
    # at the boundary).

    def register_attestation(self, agent_id, token):
        """Register the current attestation token for an agent id.

        Called by the attestation service / operator in the operator
        trust domain (never by the agent). Requires
        ``attestation_config``; raises
        ``attestation_release.AttestationReleaseError`` without one.
        The token is verified per release at the execution boundary,
        not here.
        """
        if self.attestation_config is None:
            raise _attestation_release.AttestationReleaseError(
                "register_attestation requires attestation_config "
                "(no silent no-op: an unregistered token would fail "
                "closed at release anyway)")
        self.attestation_config.register_attestation(agent_id, token)

    def _resolve_attestation(self, agent_id):
        """The current attestation token for an agent id, or None."""
        if self.attestation_config is None or not agent_id:
            return None
        return self.attestation_config.attestation_for(agent_id)

    def _sync_fingerprint_sources(self):
        """F189: keep _read_content_sources aligned with _read_contents.

        Direct external appends to _read_contents (white-box tests)
        bypass _ingest_result; pad the missing source keys with
        ("unknown", "") so eviction indexing can never desync. Never
        shrinks _read_contents.
        """
        sources = getattr(self, "_read_content_sources", None)
        if sources is None:
            sources = []
            self._read_content_sources = sources
        want = len(self._read_contents)
        if len(sources) < want:
            sources.extend([("unknown", "")] * (want - len(sources)))
        elif len(sources) > want:
            del sources[want:]

    def _eviction_index(self):
        """F189: (index, degenerate) of the eviction victim in
        ``_read_contents`` under store pressure.

        Per-source quotas: the victim comes from the source holding
        the most bytes (first-seen wins ties, deterministic), so a
        flood evicts its own oldest entries first and one source's
        flood can never evict another source's poison link. Within
        the victim source the H26 priority holds: the oldest
        NON-instruction-shaped fingerprint first. Only when every
        entry of the victim source is instruction-shaped does the
        per-source FIFO fallback fire -- that fallback may drop a
        poison link, so it is the degenerate case and the caller
        emits ``memory_pressure_degenerate`` loudly for it.

        This corrects the H26 docstring's unconditional guarantee
        ("instruction-shaped fingerprints survive junk floods"): they
        survive OTHER sources' floods; a source that overfills the
        store with its own shaped bytes evicts its own oldest shaped
        entries, loudly.
        """
        self._sync_fingerprint_sources()
        order = []
        sizes = {}
        for s in self._read_content_sources:
            if s not in sizes:
                sizes[s] = 0
                order.append(s)
        for s, c in zip(self._read_content_sources, self._read_contents):
            sizes[s] += len(c)
        if not order:
            return 0, True
        # max() returns the first maximal element: ties resolve to the
        # first-seen source -- deterministic.
        victim_source = max(order, key=lambda s: sizes[s])
        fallback = None
        for i, (s, c) in enumerate(zip(self._read_content_sources,
                                       self._read_contents)):
            if s != victim_source:
                continue
            if fallback is None:
                fallback = i
            if instruction_shaping_reason(c) is None:
                return i, False
        return fallback, True

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

    # Wave-89 (S2): governed inter-agent messaging. Thin wrappers over
    # the deployment-installed MessageBus; the bus is None unless the
    # deployment opted in (message_bus= kwarg), in which case both
    # methods refuse loudly instead of silently degrading.
    def send_message(self, identity, recipient, msg_type, content,
                     thread=None):
        """Send a governed inter-agent message via the run's MessageBus.

        Requires the deployment-installed bus (opt-in); raises
        MessageBusMissingError when absent. Provenance stamp,
        steg screening, and bandwidth caps run inside bus.send().
        """
        if self._message_bus is None:
            from .messaging import MessageBusMissingError
            raise MessageBusMissingError(
                "send_message refused: no MessageBus installed on this "
                "executor (deployment did not opt in via message_bus=)")
        return self._message_bus.send(self, identity, recipient, msg_type,
                                      content, thread=thread)

    def receive_message(self, identity, msg_id):
        """Read and stamp-validate a governed message. Returns
        (content, stamp, flags). Raises MessageBusMissingError when no
        bus is installed.
        """
        if self._message_bus is None:
            from .messaging import MessageBusMissingError
            raise MessageBusMissingError(
                "receive_message refused: no MessageBus installed on this "
                "executor (deployment did not opt in via message_bus=)")
        return self._message_bus.receive(self, identity, msg_id)

    def _session_delegation_receipt(self):
        """The verified identity-delegation receipt for this session.

        Wave-154 (rows 11/18): mints
        ``gov.delegation_tokens.delegation_receipt`` from the session's
        three-token DelegationContext — the cross-app attribution
        (sub/act/delegator_chain/scope/session_id + token refs) that
        rides on every verdict-path audit entry and approval record.
        Returns None when no delegation context is installed (direct
        execution — stamped as explicit None, never omitted) or when
        the installed context cannot mint (unbound: the delegation
        gate refuses the call fail-closed separately; the receipt is
        observability, not authority). The mint itself is the
        verification: ``delegation_receipt()`` raises fail-closed on
        unbound contexts and malformed principals, so a stamped dict
        always derives from a fully chain-verified context (bind() =
        signatures, links, attenuation, bindings, windows, session).
        Cached per context object (the receipt is session-fixed).
        """
        ctx = getattr(self, "_delegation_context", None)
        if ctx is None:
            return None
        cache = getattr(self, "_delegation_receipt_cache", None)
        if cache is not None and cache[0] is ctx:
            return cache[1]
        receipt = None
        try:
            receipt = _delegation_tokens.delegation_receipt(ctx)
        except _delegation_tokens.DelegationError:
            # Unbound context or malformed principal: the delegation
            # gate refuses the call fail-closed with its own audited
            # reason; stamping stays silent-None rather than masking a
            # gate error with a forged-looking receipt.
            receipt = None
        self._delegation_receipt_cache = (ctx, receipt)
        return receipt

    def _audit_provisioner_refused(self, agent_id, role, principal,
                                     policy_id, reason):
        """Chained audit entry for a provisioner-issuance refusal.

        Same ``identity_mint_refused`` shape as the F50 registry
        refusal (so auditors query one event): a refused mint never
        consumes budget and never issues.
        """
        self.log.append({
            "event": "identity_mint_refused",
            "run_id": self.run_id,
            "agent_id": agent_id,
            "role": role,
            "principal": principal,
            "decision": "refused",
            "policy_id": policy_id,
            "reason": ("identity_mint refused: %s" % reason),
        })

    def mint_identity(self, agent_id, role, principal, token_claims=None,
                      provisioner=None, ttl_seconds=None, scopes=None,
                      justification=None):
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

        Wave-191 (identity token): ``token_claims`` is the OPTIONAL
        verified OIDC claim set the identity is minted from (the dex
        client checked the JWT signature against the deployment's
        pinned issuer JWKS). When supplied, the claim set is strictly
        validated (required claims, types, audience, expiry with 60s
        skew) and must agree with the requested fields
        (sub -> agent_id, role, principal); any failure raises
        ``IdentityTokenError`` and -- like the F50 registry refusal --
        never consumes mint budget and never issues. This is the
        defense-in-depth twin of the packet verifier's token check:
        issuance refuses a bad token even before any packet exists.

        Wave-196 lane C (step-ca steal): when a
        ``provisioner_registry`` is configured, ``provisioner`` names
        the issuance authority and the mint is checked against its
        lifetime-claims envelope (max/min TTL, scopes, roles,
        renewal policy, per-provisioner mint budget, break-glass
        justification). ``ttl_seconds`` requests a lifetime (default:
        the deployment default capped by the provisioner's max TTL);
        ``scopes`` requests grant scopes (a string or a collection);
        ``justification`` is required (and only required) for
        break-glass provisioners. A presented token whose
        (exp - iat) lifetime exceeds the provisioner's max TTL is
        refused, and scopes outside the provisioner's grant are
        refused even when the token claims them. Every refusal raises
        ``ProvisionerRefusedError`` (or a subclass), never consumes
        mint budget, and is audit-logged as
        ``identity_mint_refused`` with ``policy_id``
        ``provisioner:<name>``. Without a configured registry the
        four new arguments are refused fail-closed -- a policy that
        was never configured is never silently honored -- and legacy
        callers see byte-identical behavior.
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
        # Wave-196 lane C (step-ca steal): the provisioner issuance
        # policy. Fail-closed at every step: refusals never consume
        # mint budget, never issue, and are audit-logged via
        # _audit_provisioner_refused.
        _prov = None          # the resolved Provisioner, or None
        _prov_ttl = None      # resolved lifetime in seconds
        _prov_scopes = []     # resolved effective scope list
        _prov_expires = None  # resolved expiry epoch (token exp else
                              # now + ttl)
        if self._provisioner_registry is None:
            if (provisioner is not None or ttl_seconds is not None
                    or scopes is not None or justification is not None):
                # Issuance-policy arguments with no registry to enforce
                # them: fail closed rather than silently honoring a
                # policy the deployment never configured.
                _no_reg_reason = (
                    "issuance-policy arguments passed (provisioner=%r, "
                    "ttl_seconds=%r, scopes=%r, justification=%r) but no "
                    "provisioner_registry is configured on this "
                    "executor" % (provisioner, ttl_seconds, scopes,
                                  justification is not None))
                self._audit_provisioner_refused(
                    agent_id, role, principal, "no-provisioner-registry",
                    _no_reg_reason)
                raise _provisioner.ProvisionerRefusedError(
                    "identity_mint refused: %s" % _no_reg_reason)
        else:
            if provisioner is None:
                _unnamed_reason = (
                    "provisioner_registry is configured: mint_identity "
                    "requires provisioner=<name> (registered: %s)" %
                    self._provisioner_registry.names())
                self._audit_provisioner_refused(
                    agent_id, role, principal, "provisioner:unnamed",
                    _unnamed_reason)
                raise _provisioner.ProvisionerRefusedError(
                    "identity_mint refused: %s" % _unnamed_reason)
            try:
                _prov = self._provisioner_registry.get(provisioner)
            except _provisioner.UnknownProvisionerError as _upe:
                self._audit_provisioner_refused(
                    agent_id, role, principal,
                    "provisioner:%s" % (provisioner,),
                    str(_upe))
                raise
            _prov_policy = "provisioner:%s" % _prov.name

            def _refuse(_reason, _exc=None):
                self._audit_provisioner_refused(
                    agent_id, role, principal, _prov_policy, _reason)
                raise (_exc or _provisioner.ProvisionerRefusedError)(
                    "identity_mint refused: %s" % _reason)

            if _prov.requires_presented_token() and token_claims is None:
                # The OIDC attestation method attests via the
                # dex-issued JWT (the wave-191 verified claim set):
                # with no presented token there is nothing attesting
                # the identity, so the mint is refused fail-closed.
                _refuse("provisioner %r uses the oidc attestation "
                        "method, which requires a presented identity "
                        "token (token_claims)" % _prov.name)

            # Normalize the requested scopes (a single string is one
            # scope); the token's agent_scope is read for the
            # cross-check and for the effective scope set.
            if scopes is None:
                _req_scopes = []
            elif isinstance(scopes, str):
                _req_scopes = [scopes]
            else:
                try:
                    _req_scopes = list(scopes)
                except TypeError:
                    _req_scopes = None
            if _req_scopes is None:
                _refuse("scopes must be a string or a collection of "
                        "strings, got %r" % (scopes,))
            _tok_scopes = []
            if isinstance(token_claims, dict):
                _raw_scope = token_claims.get("agent_scope")
                if isinstance(_raw_scope, str):
                    _tok_scopes = _raw_scope.split()
            if scopes is not None and token_claims is not None:
                # The caller may not mint scopes the presented token
                # does not carry.
                if not set(_req_scopes) <= set(_tok_scopes):
                    _refuse("requested scopes %s exceed the presented "
                            "token's agent_scope %r"
                            % (sorted(set(_req_scopes) - set(_tok_scopes)),
                               token_claims.get("agent_scope")))
            _prov_scopes = (_req_scopes if scopes is not None
                            else list(_tok_scopes))
            _prov_ttl = (_prov.claims.default_ttl()
                         if ttl_seconds is None else ttl_seconds)
            _ok, _why = _prov.authorize_mint(
                _prov_ttl, _prov_scopes, justification, role)
            if not _ok:
                if isinstance(_prov,
                              _provisioner.BreakGlassProvisioner):
                    _refuse(_why,
                            _exc=_provisioner.BreakGlassRefusedError)
                _refuse(_why)
            _budget = _prov.claims.max_mints_per_run
            if (_budget is not None
                    and self._provisioner_mint_counts.get(_prov.name, 0)
                    >= _budget):
                _refuse("provisioner %r mint budget exhausted (%d per "
                        "run)" % (_prov.name, _budget))
        if token_claims is not None:
            # Wave-191 (identity token): the defense-in-depth twin of
            # the packet verifier's token check. The caller presents
            # the VERIFIED claim set (the dex client checked the JWT
            # signature against the deployment's pinned issuer JWKS);
            # this seam enforces claim well-formedness/expiry/audience
            # and requires the claims to agree with the requested
            # identity fields -- a token minted for a different
            # agent/role/principal cannot mint this identity. A refused
            # mint never consumes budget and never issues (same as the
            # F50 registry refusal above).
            tok_ok, tok_reason = _decision_packet.check_token_claims(
                token_claims)
            if not tok_ok:
                raise IdentityTokenError(
                    "identity token rejected: %s" % tok_reason)
            for _claim, _want, _field in (
                    ("sub", agent_id, "agent_id"),
                    ("role", role, "role"),
                    ("principal", principal, "principal")):
                if token_claims.get(_claim) != _want:
                    raise IdentityTokenError(
                        "identity token claim %r is %r, refusing to mint "
                        "identity with %s %r (token-identity mismatch)"
                        % (_claim, token_claims.get(_claim), _field,
                           _want))
            if _prov is not None:
                # Wave-196 lane C: the token's lifetime is issuance
                # policy, not just expiry -- a token that lives longer
                # than the provisioner's max TTL is refused at mint
                # time. (check_token_claims above already validated
                # iat/exp types and ordering.)
                _tok_lifetime = (token_claims["exp"]
                                 - token_claims["iat"])
                if _tok_lifetime > _prov.claims.max_ttl_seconds:
                    _refuse("presented token lifetime %ds exceeds "
                            "provisioner %r max_ttl_seconds %d"
                            % (_tok_lifetime, _prov.name,
                               _prov.claims.max_ttl_seconds))
                _prov_expires = token_claims["exp"]
        if token_claims is not None:
            # Wave-198 lane E: record the VERIFIED claim set for the
            # MCP scope seam, keyed by the minted agent_id. The claims
            # passed check_token_claims above and are bound to this
            # identity (sub/role/principal matched); any refusal
            # raised before this line, so reaching here means valid.
            # Defensive copy: later caller-side mutation of the
            # presented dict cannot alter enforcement.
            self._mcp_token_claims[agent_id] = dict(token_claims)
        else:
            # A re-mint of the same agent_id WITHOUT a token must not
            # inherit a previous mint's claims: drop any stale entry
            # so scope-required tools fail closed for the new
            # tokenless identity (spec review: stale claims surviving
            # a tokenless re-mint would silently violate the "no
            # entry -> fail closed" invariant).
            self._mcp_token_claims.pop(agent_id, None)
        self._mint_count += 1
        ident = AgentIdentity(agent_id=agent_id, role=role,
                              run_id=self.run_id, principal=principal,
                              provenance="minted")
        self._minted.add((ident.agent_id, ident.role,
                          ident.run_id, ident.principal))
        if _prov is not None:
            # Successful mints only: refusals never reach this line, so
            # per-provisioner budgets count issuance, not attempts.
            self._provisioner_mint_counts[_prov.name] = \
                self._provisioner_mint_counts.get(_prov.name, 0) + 1
            if _prov_expires is None:
                _prov_expires = int(time.time()) + _prov_ttl
            _renewable = not _prov.claims.disable_renewal
            _renew_after = None
            if (_renewable
                    and _prov.claims.renewal_window_seconds is not None):
                _renew_after = datetime.fromtimestamp(
                    _prov_expires - _prov.claims.renewal_window_seconds,
                    tz=timezone.utc).isoformat()
            _expires_iso = datetime.fromtimestamp(
                _prov_expires, tz=timezone.utc).isoformat()
            if isinstance(_prov, _provisioner.BreakGlassProvisioner):
                # Loud: break-glass issuance must be unmistakable in
                # the operator's face as well as in the chain.
                print(
                    "GOVERNANCE BREAK-GLASS: identity minted under "
                    "break-glass provisioner %r for agent %r (role %r, "
                    "principal %r), TTL %ds, justification: %s"
                    % (_prov.name, agent_id, role, principal,
                       _prov_ttl, justification),
                    file=sys.stderr)
            # Wave-199: when the provisioner carries a keyset (the JWK
            # attestation method's trust anchor), the mint-budget
            # envelope's trust anchor rides the event as the
            # material-free keyset_info() projection -- key ids +
            # statuses, zero key bytes. Absent when no keyset is
            # attached, so the event stays byte-identical to before.
            _keyset_projection = _prov.keyset_info_projection()
            _minted_event = {
                "event": "identity_minted",
                "run_id": self.run_id,
                "agent_id": agent_id,
                "role": role,
                "principal": principal,
                "decision": "identity_issued",
                "policy_id": ("provisioner:%s" % _prov.name
                              if self._principal_registry is None
                              else "principal-registry"),
                "reason": ("Identity issued under provisioner %r "
                           "(%s); lifetime claims enforced and "
                           "recorded." % (_prov.name,
                                          _prov.provisioner_type)),
                # Wave-196 lane C: the lifetime-claims envelope is
                # signature-covered via the chained audit event (the
                # audit log's hash chain / audit signing is the
                # signature layer; the wave-192 packet section stays
                # byte-identical when this feature is absent). The
                # event records the resolved outcome (ttl, scopes)
                # above; "policy" records the envelope that authorized
                # it, so the decision is reconstructible from the
                # chain alone.
                "provisioner": _prov.name,
                "provisioner_type": _prov.provisioner_type,
                "ttl_seconds": _prov_ttl,
                "expires_at": _expires_iso,
                "scopes": sorted(_prov_scopes),
                "policy": _prov.claims.as_audit_dict(),
                "renewable": _renewable,
                "renew_after": _renew_after,
                "revocation": _prov.claims.revocation,
            }
            if _keyset_projection is not None:
                _minted_event["keyset"] = _keyset_projection
            self.log.append(_minted_event)
            if isinstance(_prov, _provisioner.BreakGlassProvisioner):
                # The dedicated loud event: justification on the chain,
                # separate from the standard issuance event, so a
                # break-glass mint is queryable without parsing
                # reasons.
                self.log.append({
                    "event": "identity_break_glass_minted",
                    "run_id": self.run_id,
                    "agent_id": agent_id,
                    "role": role,
                    "principal": principal,
                    "decision": "break_glass_issued",
                    "policy_id": "provisioner:%s" % _prov.name,
                    "provisioner": _prov.name,
                    "ttl_seconds": _prov_ttl,
                    "expires_at": _expires_iso,
                    "justification": justification,
                    "reason": ("Break-glass identity issued under "
                               "provisioner %r; requires post-hoc "
                               "review." % _prov.name),
                })
        elif self._principal_registry is not None:
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

    # -- governed spawn (wave-86, F133) ---------------------------------

    def _register_spawn_parent_key(self, trust, parent_agent_id,
                                   parent_signer):
        """Register the spawning agent's workload key in the session's
        agent_keys roster (the F133 "session-open agent_keys
        registration" gap: outside tests nothing registered these).

        The parent_signer is deployment/parent-agent custody,
        caller-provided; registering its public key is a deployment act
        performed here, at first spawn, so the child's parent-signed
        token verifies against the roster. A DIFFERENT key already
        registered for the same agent_id is a parent-signature key
        swap — refused fail-closed. Returns True when the key was newly
        registered (chained on the agent_spawn event), False when it
        was already present and matching.
        """
        try:
            pub = bytes(parent_signer.public_key)
        except Exception as e:
            raise _delegation_tokens.DelegationSignatureError(
                "spawn refused: parent_signer exposes no usable "
                "public_key (%s: %s)" % (type(e).__name__, e))
        if len(pub) != 32:
            raise _delegation_tokens.DelegationSignatureError(
                "spawn refused: parent_signer public_key is not a "
                "32-byte Ed25519 key")
        existing = trust.agent_keys.get(parent_agent_id)
        if existing is None:
            trust.agent_keys[parent_agent_id] = pub
            return True
        if bytes(existing) != pub:
            raise _delegation_tokens.DelegationSignatureError(
                "spawn refused: a different key is already registered "
                "for agent %r in the session roster (parent-signature "
                "key swap refused)" % (parent_agent_id,))
        return False

    def spawn_sub_agent(self, sub_agent_id, sub_scope, parent_signer, *,
                        role=None, principal=None, ttl_s=None):
        """Wave-86 (F133): the governed spawn path.

        Spawns a sub-agent under this executor's bound delegation
        context: the child token is issued via
        ``self._delegation_context.spawn(...)`` (per-hop scope
        attenuation and the delegation-depth cap are enforced there;
        the audience is inherited from the parent token — never a
        parameter), the spawning agent's workload key is registered in
        the session's agent_keys roster (fail-closed on key swap), and
        an ``agent_spawn`` event is chained into the shared audit log
        BEFORE returning — parent/child token refs (via token_ref),
        scope, depth, delegator, session, audience — so the hash chain
        covers the lineage.

        ``parent_signer`` is caller-provided (deployment/parent-agent
        custody); the executor never persists it.

        Returns a child ToolExecutor sharing this run's log, policy,
        policy store, approvals queue, canary registry, revocation
        checker, and other governed components, constructed with the
        child's BOUND delegation context and a provisioned session
        identity ``(sub_agent_id, role or parent's role, principal or
        parent's principal)`` — so the F55 provisioned-identity rule
        and the wave-85 constructor gate both hold for the child. The
        child's run_id == the session's run_id (same run_dir), so the
        delegation gate's session binding passes.

        Fail-closed: no (or unbound) parent DelegationContext →
        DelegationRequiredError; exhausted spawn budget →
        SpawnBudgetExhaustedError. ``spawn_budget=None`` (default) is
        unlimited — documented; the chained spawn events are the
        detection story.
        """
        # Wave-100 (Stream 1): the capability gate binds the spawn
        # lineage too -- checked before anything else, so a child
        # executor can never run with a weaker (or no) gate than its
        # parent. The child inherits the binding below.
        _spawner = self._session_identity
        self._check_capability_gate(
            agent_id=(_spawner.agent_id if _spawner is not None
                      else "unknown-spawner"),
            role=(_spawner.role if _spawner is not None else None),
            principal=(_spawner.principal if _spawner is not None
                       else None),
            tool="spawn_sub_agent", run_id=self.run_id)
        ctx = self._delegation_context
        if ctx is None or not ctx.bound:
            raise _delegation_tokens.DelegationRequiredError(
                "spawn refused: this executor has no bound parent "
                "DelegationContext — sub-agents can only be spawned "
                "under a verified three-token delegation (fail closed)")
        # Wave-89 (S2): a quarantined identity cannot spawn -- quarantine
        # escape via fresh children is closed. Fail-closed, loud.
        if (self._message_bus is not None and self._message_bus.is_quarantined(
                ctx.agent_token["claims"]["agent_id"])):
            from .messaging import QuarantineDeniedError
            raise QuarantineDeniedError(
                "spawn refused: spawner %r is quarantined" %
                ctx.agent_token["claims"]["agent_id"])
        budget = self._spawn_budget
        if budget is not None and budget.remaining <= 0:
            raise SpawnBudgetExhaustedError(
                "spawn budget exhausted (%d of %d spawns used): "
                "refusing to spawn %r — the run's spawn budget is a "
                "fail-closed swarm control"
                % (budget.total - budget.remaining, budget.total,
                   sub_agent_id))
        parent_claims = ctx.agent_token["claims"]
        parent_agent_id = parent_claims["agent_id"]
        # Wave-90 (S6, F137): the birth parent is the SPAWNING
        # EXECUTOR's own identity. DelegationContext.spawn keeps the
        # parent's agent_token unchanged down the tree, so past the
        # first hop parent_claims["agent_id"] names the ultimate
        # delegator, NOT the direct spawner — parenting the birth
        # certificate to it would skip a hop in the lineage graph
        # (exactly the F137 gap). The provisioned session identity is
        # per-executor: the child is constructed with
        # session_identity=(sub_agent_id, ...), so it names the true
        # spawner at every hop. Fall back to the delegation claims
        # when no session identity was provisioned.
        _sess = self._session_identity
        spawner_id = (_sess.agent_id if _sess is not None
                      else parent_agent_id)
        key_registered = self._register_spawn_parent_key(
            ctx.trust, parent_agent_id, parent_signer)
        # The child token + bound child context: attenuation, depth,
        # and audience inheritance are enforced inside.
        child_ctx = ctx.spawn(sub_agent_id, sub_scope, parent_signer,
                              ttl_s=ttl_s)
        child_token = child_ctx.delegation_token
        # Wave-90 (S6, F137): mandatory birth certificates. When a
        # lineage tracker is installed, the child's birth certificate
        # is minted here — AFTER the key registration and the child
        # token + bound child context succeeded, so a failed spawn
        # never leaves an orphan birth record, and the certificate
        # carries BOTH token refs. No opt-out within a governed run:
        # birth() fails closed on an unregistered parent, and taint is
        # hereditary — an infected parent's child is born infected,
        # which covers env-var and argument channels that carry no
        # file contact. The budget check above runs first so an
        # exhausted budget never mints a certificate for a child that
        # will not exist.
        lineage_cert = None
        if self._lineage_tracker is not None:
            lineage_cert = self._lineage_tracker.birth(
                spawner_id, sub_agent_id,
                parent_token_ref=_delegation_tokens.token_ref(
                    ctx.delegation_token),
                child_token_ref=_delegation_tokens.token_ref(child_token),
                role=role or parent_claims["role"],
                principal=principal or parent_claims["principal"])
        child_claims = child_token["claims"]
        self.log.append({
            "event": "agent_spawn",
            "run_id": self.run_id,
            "agent_id": parent_agent_id,
            "role": parent_claims["role"],
            "principal": parent_claims["principal"],
            "decision": "spawned",
            "policy_id": "delegation-spawn",
            "sub_agent_id": sub_agent_id,
            "sub_scope": list(child_claims["scope"]),
            "delegation_depth": child_claims["delegation_depth"],
            "delegator": child_claims["delegator"],
            "session_id": child_ctx.session_id,
            "aud": child_token.get("aud"),
            "parent_token_ref": _delegation_tokens.token_ref(
                ctx.delegation_token),
            "child_token_ref": _delegation_tokens.token_ref(child_token),
            "parent_key_registered": key_registered,
            # Wave-90 (S6, F137): bind the spawn event to the lineage
            # substrate — the birth certificate ids join the token refs
            # in the hash chain.
            "lineage_id": (lineage_cert["lineage_id"]
                           if lineage_cert else None),
            "parent_lineage_id": (
                self._lineage_tracker.lineage_id(spawner_id)
                if lineage_cert else None),
            "reason": ("Sub-agent %r spawned by %r at delegation depth "
                       "%d with scope %r (parent token %s... → child "
                       "token %s...; audience %r; parent workload key "
                       "%s in the session roster)."
                       % (sub_agent_id, parent_agent_id,
                          child_claims["delegation_depth"],
                          list(child_claims["scope"]),
                          _delegation_tokens.token_ref(
                              ctx.delegation_token)[:12],
                          _delegation_tokens.token_ref(
                              child_token)[:12],
                          child_token.get("aud"),
                          "newly registered"
                          if key_registered else "already registered")),
        })
        if budget is not None:
            budget.remaining -= 1
        child = ToolExecutor(
            self.run_dir, self.policy, self.log, self.approvals,
            principal_registry=self._principal_registry,
            session_identity=(sub_agent_id,
                              role or parent_claims["role"],
                              principal or parent_claims["principal"]),
            tool_ratings=self._tool_ratings,
            credential_manifest=self._credential_manifest,
            canary_registry=self.canary_registry,
            delegation_context=child_ctx,
            policy_store=self._policy_store,
            detection_monitor=self._detection_monitor,
            erosion_monitor=self._erosion_monitor,
            recovery=self._recovery,
            lease_verifier=self._lease_verifier,
            lease_gated_tools=self._lease_gated_tools,
            precommit_gate=self._precommit_gate,
            trifecta_floor=self._trifecta_floor,
            revocation_checker=self._revocation_checker,
            lineage_tracker=self._lineage_tracker,
            # Wave-100 (Stream 1): one lineage, one capability gate --
            # the child inherits the parent's binding, current
            # assessment, and (if declared) ungoverned acknowledgement,
            # so the child's constructor re-enforces the same gate.
            # In the acknowledged-ungoverned case the declaration
            # chains once per child construction (loud, by design).
            capability_gate_binding=self._capability_gate_binding,
            capability_assessment=self._capability_assessment,
            capability_ungoverned_ack=self._capability_ungoverned_ack,
            # Advisory layer: the child inherits the parent's advisors
            # (spawn must not bypass advisory tightening) and shares
            # the BOM chain cell, so parent and child extend ONE
            # decision-BOM sub-chain in the shared audit log.
            advisors=self._advisors,
            # Row-12 (wave-158): one deployment, one manifest posture --
            # the child inherits the parent's manifest decision (the
            # envelope or the recorded opt-out reason) so a production
            # spawn is not refused for a decision the deployment
            # already made; the child's inventory is then overwritten
            # with the parent's shared registry (row-12, one run one
            # inventory), so the manifest itself is shared by
            # reference. In the absent case the declaration chains once
            # per child construction (loud, by design -- same as the
            # capability acknowledged-ungoverned precedent).
            deployment_manifest=self._deployment_manifest_envelope,
            deployment_manifest_opt_out=(
                self._deployment_manifest_opt_out_reason),
            # Row-12 (wave-162): one deployment, one writable-space
            # declaration -- the child inherits the parent's declared
            # writable dirs so a spawn cannot widen the undeclared-path
            # write binding by construction.
            declared_write_dirs=self._declared_write_dirs)
        child._advisory_bom_chain = self._advisory_bom_chain
        # One sub-chain, one lock: the child shares the parent's BOM
        # head cell, so it must share the guard too.
        child._advisory_lock = self._advisory_lock
        # Wave-319 (grant negotiation): the child inherits the
        # deployment's grant registry by reference (immutable after
        # registration), so a spawn cannot shed the advisory grant
        # check by construction.
        child._grant_registry = self._grant_registry
        # Row-12: one run, one artifact inventory — the child shares
        # the parent's registry by reference, so a child egressing a
        # parent-written artifact sees it as registered (not unknown).
        # Registration order = the shared chain order.
        child.artifacts = self.artifacts
        # Wave-90 (S6, F137): the child carries its birth certificate.
        # One lineage, one tracker: shared by reference like the bus.
        child._lineage_cert = lineage_cert
        # One lineage, one budget: the child shares the parent's
        # budget box by reference.
        child._spawn_budget = self._spawn_budget
        # Wave-89 (S2): one lineage, one bus -- the child shares the
        # parent's message bus by reference, so provenance stamps,
        # quarantine state, and the infection monitor see the whole
        # lineage. None stays None (opt-in preserved down the tree).
        child._message_bus = self._message_bus
        # Wave-316 (F399): one lineage, one provenance sink -- the
        # child shares the parent's run-scoped sink by reference, so a
        # spawned child's refusals count against the same re-plan
        # budget (a spawn cannot dodge the escalate-terminal ratchet).
        # Per-context isolation still holds via the sink's ctx_key.
        child._pv_sink = self._pv_sink
        return child

    def _check_capability_gate(self, *, agent_id, role, principal, tool,
                               run_id):
        """Wave-100 (Stream 1): enforce the capability gate on the run
        path.

        When a binding is installed, the deployment's capability
        assessment is re-verified on every call/spawn -- no caching, so
        rotation and expiry are always current. Fail-closed and loud:
        the refusal is chained into the audit log before raising
        ``capability_gate.CapabilityGateRefusal``. No binding (raw
        pipeline, or acknowledged ungoverned mode) means no check.
        """
        binding = self._capability_gate_binding
        if binding is None:
            return
        try:
            _capability_gate.verify_assessment(
                binding, self._capability_assessment)
        except _capability_gate.CapabilityGateRefusal as e:
            # Best-effort chaining, like the construction seam: the
            # refusal stands even if the audit write fails; the
            # exception the caller catches is always the refusal.
            try:
                self.log.append({
                    "event": "capability_gate_refused",
                    "run_id": run_id,
                    "agent_id": agent_id,
                    "role": role,
                    "principal": principal,
                    "tool": tool,
                    "decision": "refused",
                    "policy_id": "capability-gate",
                    "refusal_cause": e.refusal_cause,
                    "reason": "Refusing to act: %s" % (e,),
                })
            except Exception:
                pass
            raise

    def update_capability_assessment(self, assessment):
        """Wave-100 (Stream 1): rotate the deployment's capability
        assessment without reconstructing the executor.

        The assessment is shape-checked here; full verification
        (freshness, config digest, report digest, seal, verdict)
        happens on the next ``call()`` / ``spawn_sub_agent()`` -- a bad
        rotation is refused at the next run attempt, never silently
        installed. The rotation is chained into the audit log.
        """
        if (assessment is not None
                and not isinstance(assessment, collections.abc.Mapping)):
            raise _capability_gate.CapabilityGateError(
                "capability assessment must be a mapping with 'report' "
                "and 'manifest', or None")
        # The audit record is chained BEFORE the state swap: if the log
        # write fails, the old assessment stays installed and the error
        # propagates -- never a swapped assessment with no chained
        # record of the rotation.
        manifest = (assessment or {}).get("manifest") or {}
        self.log.append({
            "event": "capability_assessment_updated",
            "run_id": self.run_id,
            "agent_id": "system",
            "role": "system",
            "decision": "updated",
            "policy_id": "capability-gate",
            "report_id": manifest.get("report_id"),
            "assessed_at": manifest.get("assessed_at"),
            "reason": ("Deployment installed a new capability assessment "
                       "(report %r); it will be fully verified on the "
                       "next run attempt -- a bad rotation is refused "
                       "there, never silently installed."
                       % (manifest.get("report_id"),)),
        })
        self._capability_assessment = assessment

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
             "domain_allowlisted": True},
            # Wave-198: this is a hypothetical ("could the delegator
            # invoke the tool at all"), not a real enforcement. Its
            # matches must never enter the mode ledger's violation
            # telemetry as graduation evidence.
            record_telemetry=False)
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

    def _resolved_path_for_policy(self, path):
        """Sandbox-relative resolved path for path-based policy matching.

        F146 (PaperCut class): a symlink inside the sandbox can point
        at an operator-excluded zone, so ``path_contains_any`` must be
        evaluated against the resolved target as well as the declared
        path. Shares the fail-safe resolve discipline of
        ``_is_outside_sandbox`` / ``_lineage_real_path`` (OSError ->
        lexical absolute path). Normalized to sandbox-relative when
        the target stays inside the sandbox -- mirroring the memory
        firewall's mem-key normalization -- so substring match keys
        behave exactly as they do on declared relative paths (an
        absolute prefix would let the sandbox's own directory name
        match an exclusion substring: a false-positive factory). A
        target outside the sandbox keeps its absolute form
        (fail-safe: never hidden). On any failure the declared path
        is returned unchanged -- matching then degrades exactly to
        today's declared-only behavior and can never weaken."""
        try:
            real = self._lineage_real_path(path)
        except Exception:
            return str(path)
        try:
            return str(real.relative_to(self._sandbox_resolved))
        except ValueError:
            return str(real)

    # -- provenance / egress ----------------------------------------------

    def _ingest_result(self, tool, result, principal=None, source_key=None):
        # F189: source_key is the _fingerprint_source_key(tool, args)
        # tuple naming the content's origin; None (foreign-result
        # ingestion, which carries no args) defaults to (tool, "").
        if source_key is None:
            source_key = _fingerprint_source_key(tool, None)
        # F144: http_post joins the fingerprinted set. read_file/api_call
        # results were fingerprinted into the run's verbatim-overlap
        # store, but http_post response bodies were not -- the identical
        # imperative poison quarantined via api_call and sailed through
        # via http_post (F140's mirror image: adjacent-tool
        # incompleteness). An http_post response is untrusted external
        # content exactly like an api_call result, so it runs the same
        # machinery: same 64-char verbatim-overlap fingerprints, same
        # 256 KiB FIFO store, same 64 KiB per-result cap.
        # F175: send_email joins the fingerprinted set (F144's documented
        # next step). The product's built-in _simulate returns no content
        # body for send_email -- it is an outbound action -- so the
        # native path ingests nothing and is unaffected. But a
        # response-carrying mail relay / MCP email adapter reply (the
        # F37 ingest_foreign_result path, which routes REAL foreign
        # results through this same method) is untrusted external
        # content exactly like a webhook response: the identical
        # imperative poison quarantined via api_call/http_post and sailed
        # through via send_email (p8 in evals/f143mem_break.py). Same
        # machinery, one tuple element -- mirroring F144.
        if tool in ("read_file", "api_call", "http_post", "send_email"):
            content = result.get("content")
            if content:
                self._read_contents.append(content[:65536])
                self._read_content_sources.append(source_key)
                total = sum(len(c) for c in self._read_contents)
                while total > _MAX_READ_STORE and self._read_contents:
                    # F189: per-source quotas. The victim comes from
                    # the source holding the most bytes, so a flood
                    # evicts its own oldest entries first and can never
                    # evict another source's poison link. The
                    # degenerate case (per-source FIFO fallback evicting
                    # an instruction-shaped fingerprint -- a possible
                    # poison link) is chained loudly, never silently.
                    idx, degenerate = self._eviction_index()
                    victim_source = self._read_content_sources.pop(idx)
                    victim = self._read_contents.pop(idx)
                    total -= len(victim)
                    if degenerate:
                        self.log.append({
                            "event": "memory_pressure_degenerate",
                            "run_id": self.run_id,
                            "tool": tool,
                            "principal": principal,
                            "decision": "executed",
                            "policy_id": "memory-fingerprint-store",
                            "flag": "memory_pressure_degenerate",
                            "reason": (
                                "F189: fingerprint store under pressure; "
                                "per-source FIFO fallback evicted an "
                                "instruction-shaped fingerprint from source "
                                "%r -- a poison link may have been dropped; "
                                "provenance for that source's bytes is no "
                                "longer verifiable." % (victim_source,)),
                        })
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
                    # content does NOT taint. F144: http_post response
                    # bodies run the SAME taint path, not just the
                    # fingerprint path -- splitting them would create a
                    # fresh adjacent-tool gap (sensitive webhook content
                    # followed by paraphrase/summary api_call exfil would
                    # evade the approval gate). The false-positive cost
                    # (a later api_call gated behind approval) is the
                    # same precedent accepted for api_call results.
                    # F175: send_email response bodies run the SAME taint
                    # path for the same reason -- an attacker-influenced
                    # relay reply carrying credential-shaped material
                    # followed by paraphrase/summary api_call exfil is
                    # the F15a shape, and splitting send_email out would
                    # reopen the adjacent-tool gap F144 just closed for
                    # http_post. Routine sends never taint: the built-in
                    # no-content send_email result carries no "content"
                    # key, so this block is skipped entirely; only a
                    # response-carrying relay/adapter reply can trip the
                    # DLP patterns -- and DLP-clean mail replies do NOT
                    # taint, exactly like DLP-clean webhook bodies.
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
            # S1-MEM cross-session lineage: feed instruction-shaped
            # ingestions to the firewall's lineage journal so a LATER
            # session's memory write can carry the lineage flag even
            # when the writing run never re-ingested the poison (the
            # cross-session laundering shape). The journal stores only
            # fingerprint digests and flags, never content. Fail-closed:
            # journal tamper raises loudly and the tool call is refused
            # rather than ingesting with untrusted lineage state.
            fw = self._memory_firewall
            if fw is not None and principal:
                try:
                    fw.note_shaped_ingestion(
                        principal, content, self.run_id)
                except LedgerUnverifiableError as e:
                    self.log.append({
                        "event": "memory_ledger_unverifiable",
                        "run_id": self.run_id,
                        "tool": tool,
                        "principal": principal,
                        "decision": "refused",
                        "policy_id": "memory-provenance",
                        "flag": "memory_ledger_unverifiable",
                        "reason": (
                            "Refusing the tool call: the cross-session "
                            "lineage journal cannot be authenticated: %s"
                            % (e,)),
                    })
                    raise
            self._tainted = True
            if tool not in self._taint_sources:
                self._taint_sources.append(tool)
        # F162 (S2-GAP-1): accrue result-path usage into the per-run
        # meter. _mint_result_usage already stamped result["_usage"]
        # (governed side); foreign results route through
        # ingest_foreign_result which lands here too — F168: with a
        # _usage-less dict, so this line accrues 0 (no-op) and the
        # foreign path's loud accrual is the single metering event.
        self._accrue_result_usage(result)

    def set_intent_context(self, user_turns):
        """Wave-129 (row-7 intent slice): opt-in user-turn context.

        ``user_turns``: list of user message strings, oldest first, or
        None to clear. The intent-slice judge anchors to the LATEST
        turn; when context is set, queued approvals carry the judge's
        MAC-bound ``intent_slice`` annotation for human review. The
        judge is advisory only -- it never denies and never breaks
        queueing. Clearing (None) makes the judge inert.
        """
        if user_turns is None:
            self._intent_user_turns = None
        else:
            self._intent_user_turns = [str(t) for t in user_turns]

    def set_instruction_provenance(self, units):
        """Wave-279 (F300): opt-in instruction-provenance context.

        ``units``: list of ``{"text", "label", "carrier"}`` dicts, or
        None to clear. ``label`` must be one of
        ``instruction_provenance.AUTHORITY_ORDER`` ("SYSTEM" ...
        "RETRIEVED_UNTRUSTED"); anything else is refused LOUD
        (ValueError) -- an unknown label never silently degrades to
        RETRIEVED_UNTRUSTED, since a mislabeled user turn would route
        honest actions to approval and a mislabeled injection would
        launder authority.

        Returns the list of registered unit ids (the ids a plan trace
        passes as ``provenance_driving_units`` on ``call()``). The
        IngressLabeler is run-scoped and never persists labels across
        runs. Clearing (None) makes the seam inert.
        """
        if units is None:
            self._prov_labeler = None
            return None
        if not isinstance(units, (list, tuple)):
            raise ValueError(
                "set_instruction_provenance() refused: units must be a list of "
                "{\"text\", \"label\", \"carrier\"} dicts or None")
        labeler = _instruction_provenance.IngressLabeler()
        ids = []
        for i, u in enumerate(units):
            if not isinstance(u, dict):
                raise ValueError(
                    "set_instruction_provenance() refused: unit %d must be a dict, "
                    "got %s" % (i, type(u).__name__))
            text = u.get("text")
            label = u.get("label")
            carrier = u.get("carrier", "")
            if not isinstance(text, str):
                raise ValueError(
                    "set_instruction_provenance() refused: unit %d text must be str"
                    % (i,))
            if label not in _instruction_provenance.AUTHORITY_ORDER:
                raise ValueError(
                    "set_instruction_provenance() refused: unit %d label must be one "
                    "of %s, got %r" % (
                        i, _instruction_provenance.AUTHORITY_ORDER, label))
            if not isinstance(carrier, str):
                raise ValueError(
                    "set_instruction_provenance() refused: unit %d carrier must be "
                    "str" % (i,))
            unit = labeler.ingest(
                text, _instruction_provenance.label_rank(label), carrier)
            ids.append(unit.unit_id)
        self._prov_labeler = labeler
        return ids

    def record_intent_turn(self, principal, message, verdict=None):
        """Wave-134 (row-7 cross-run intent): record one user turn in
        the cross-run intent ledger.

        ``principal`` is the operator principal whose intent this turn
        expresses; ``message`` the raw user message text; ``verdict``
        an optional judge verdict dict (stored opaquely -- the ledger
        computes countermand-ness itself via the canonical detector).

        Returns the ledger record, or None when no intent_ledger was
        installed at construction (opt-in: zero behavior change).
        The operator harness calls this once per user turn; the
        execution boundary consults the ledger for countermands that
        arrived after an approval was granted.
        """
        if self.intent_ledger is None:
            return None
        return self.intent_ledger.record_intent(
            principal, message, verdict=verdict)

    def register_goal(self, agent_id, description, effects=(),
                      constraints=(), identity=None):
        """Wave-130 (row-11): register an agent's declared goal.

        ``agent_id``/``description`` describe the objective;
        ``effects``/``constraints`` are the structured atoms
        ``gov.goals`` reasons over (see its vocabulary). ``identity``
        is the minted AgentIdentity for the registering agent --
        REQUIRED (F42): a conflicting registration is routed to the
        approval queue, and queue() never trusts caller-supplied
        identity fields.

        Returns ``(goal_dict, [conflict_dicts])``. Registration never
        denies: conflicts are flagged LOUD (``goal_conflict`` audit
        event, already chained by the registry) and a
        ``goal_conflict_review`` item is queued for human resolution.
        A conflicting goal is still registered as active -- the human
        resolves which objective stands; use ``resolve_goal`` to mark
        the outcome.

        Wave-135 (row-11): a VAGUE goal (empty effects, wildcard
        target) registers in ``pending_specificity`` and covers
        NOTHING until a human narrows it (``narrow_goal``) or
        acknowledges its breadth. A ``goal_specificity_review``
        approval item is queued for human resolution -- same
        separation-of-duties as the conflict review: the agent can
        never acknowledge its own vagueness away.
        """
        if identity is None:
            raise TypeError(
                "register_goal() requires identity: an AgentIdentity "
                "minted by the executor for the registering agent "
                "(F42); a conflicting registration is routed to the "
                "approval queue, which never trusts caller-supplied "
                "identity fields")
        goal, conflicts = self._goal_registry.register(
            agent_id, self.run_id, description,
            effects=effects, constraints=constraints)
        if goal.get("status") == "pending_specificity":
            self._queue_specificity_review(goal, agent_id, description,
                                           identity)
        if not conflicts:
            return goal, conflicts
        self._queue_conflict_review(goal, agent_id, description,
                                    conflicts, identity)
        return goal, conflicts

    def _queue_specificity_review(self, goal, agent_id, description,
                                  identity, note=""):
        """Wave-135: queue a ``goal_specificity_review`` approval item
        for a vague (pending_specificity) goal.

        Shared by ``register_goal`` and ``narrow_goal`` so a vague
        goal can never slip through without a human review item --
        the routing cannot drift between the two call sites.
        Separation-of-duties: the agent can never acknowledge its
        own vagueness away. Queue-failure is LOUD (the
        ``goal_specificity_pending`` registry event is already in
        the log, so the signal survives).

        Wave-145 (row-11): the review is stamped with
        ``type_to_confirm_reference`` -- the goal's declared scope
        (description + effect atoms), MAC-bound on the record (F38).
        Approving the review requires the human to TYPE the narrowed
        scope, checked against this reference at token-tversky >=
        DEFAULT_THRESHOLD (``ApprovalQueue.decide``); a bare
        click-approve is refused fail-closed.
        """
        # Wave-135: route the vague goal to a human. A vague goal can
        # also conflict (against active goals); both reviews are
        # queued and both need human attention -- the conflict
        # decision hook noops on a still-pending goal (wave-134
        # attestation path), and the specificity decision is what
        # activates it.
        reasons = goal.get("specificity_reasons") or []
        try:
            self.approvals.queue(
                {"tool": "goal_specificity_review",
                 "args": {"goal_id": goal["goal_id"],
                          "agent_id": agent_id,
                          "description": description,
                          "specificity_reasons": reasons,
                          # Wave-145 (row-11): type-to-confirm
                          # reference scope -- the goal's declared
                          # scope, MAC-bound on the record.
                          "type_to_confirm_reference":
                              _type_to_confirm_reference_texts(goal)},
                 "identity": identity.as_dict(),
                 "agent_justification": None,
                 "redactions": []},
                PolicyDecision(
                    "require_approval",
                    "Vague goal for agent %r held in "
                    "pending_specificity%s: %s"
                    % (agent_id,
                       (" (%s)" % note) if note else "",
                       "; ".join(reasons)),
                    policy_id="goal-registry",
                    flag="goal_specificity"),
                "agent_direct",
                "review vague goal for agent %r" % (agent_id,),
                caller_identity=identity,
                delegation_receipt=self._session_delegation_receipt())
        except Exception:
            self.log.append({
                "event": "goal_specificity_queue_failed",
                "flag": "goal_specificity",
                "run_id": self.run_id,
                "agent_id": agent_id,
                "goal_id": goal["goal_id"],
                "reason": ("goal_specificity_review approval could "
                           "not be queued; the "
                           "goal_specificity_pending audit event "
                           "remains the record -- operator must "
                           "review manually"),
            })

    def _queue_conflict_review(self, goal, agent_id, description,
                               conflicts, identity):
        """Wave-135 refactor: the ``goal_conflict_review`` queueing
        block extracted from ``register_goal`` unchanged, so
        ``narrow_goal`` can route a conflicting narrowed registration
        through the identical path (no drift between call sites)."""
        # LOUD is already in the log (registry chained it); route to
        # humans. Synthetic action (tool "goal_conflict_review") so the
        # queue's separation-of-duties still applies: the agent can
        # never approve its own conflict away.
        detail_lines = "; ".join(
            "%s: %s" % (c["type"], c["explanation"]) for c in conflicts)
        try:
            self.approvals.queue(
                {"tool": "goal_conflict_review",
                 "args": {"goal_id": goal["goal_id"],
                          "agent_id": agent_id,
                          "description": description,
                          "conflicts": conflicts},
                 "identity": identity.as_dict(),
                 "agent_justification": None,
                 "redactions": []},
                PolicyDecision(
                    "require_approval",
                    "Goal conflict for agent %r: %s"
                    % (agent_id, detail_lines),
                    policy_id="goal-registry",
                    flag="goal_conflict"),
                "agent_direct",
                "review goal conflict for agent %r (%d conflict(s))"
                % (agent_id, len(conflicts)),
                caller_identity=identity,
                delegation_receipt=self._session_delegation_receipt())
        except Exception:
            # The LOUD goal_conflict audit events above are the audit
            # trail; the conflict stands flagged even if queueing the
            # review item fails. Fail closed on the signal, never
            # warn-and-continue silently.
            self.log.append({
                "event": "goal_conflict_queue_failed",
                "flag": "goal_conflict",
                "run_id": self.run_id,
                "agent_id": agent_id,
                "goal_id": goal["goal_id"],
                "reason": ("goal_conflict_review approval could not be "
                           "queued; the goal_conflict audit events "
                           "remain the record -- operator must review "
                           "manually"),
            })

    def resolve_goal(self, goal_id, resolution, note=""):
        """Wave-130: record a human's resolution of a goal conflict.

        ``resolution`` is "upheld" (goal stands) or "superseded" (goal
        withdrawn). The goal's status is updated and a
        ``goal_resolved`` event is chained. Unknown goal_id or
        resolution -> ValueError (fail-closed, no silent no-op).
        """
        if resolution not in ("upheld", "superseded"):
            raise ValueError(
                "resolution must be 'upheld' or 'superseded', got %r"
                % (resolution,))
        g = self._goal_registry.set_status(
            goal_id, "active" if resolution == "upheld" else "superseded")
        self.log.append({
            "event": "goal_resolved",
            "run_id": self.run_id,
            "goal_id": goal_id,
            "agent_id": g.get("agent_id"),
            "resolution": resolution,
            "note": str(note),
            "reason": ("human resolved goal %s as %s%s"
                       % (goal_id[:8], resolution,
                          (": " + note) if note else "")),
        })
        return g

    def narrow_goal(self, goal_id, effects=(), constraints=(),
                    identity=None, note=""):
        """Wave-135 (row-11): narrow a vague (pending_specificity) goal.

        The human/operator supplies narrowed ``effects``/``constraints``.
        The pending goal is superseded and a FRESH goal is registered
        with the narrowed atoms (see ``GoalRegistry.narrow``: the
        goal sub-chain is append-only, so narrowing is a new
        registration, never an in-place edit). The fresh registration
        re-runs the specificity check -- a still-vague narrowing
        lands in ``pending_specificity`` again and queues a new
        review; nothing about the check is waived. A conflicting
        narrowing queues a ``goal_conflict_review`` like any
        registration.

        ``identity`` is the minted AgentIdentity for the goal's agent
        -- REQUIRED (F42): narrowed registrations route to the
        approval queue exactly like fresh ones, and queue() never
        trusts caller-supplied identity fields.

        Returns ``(new_goal_dict, [conflict_dicts])``. Unknown goal,
        non-pending goal, malformed atoms, or missing identity ->
        ValueError/TypeError (fail-closed, registry unchanged).
        """
        if identity is None:
            raise TypeError(
                "narrow_goal() requires identity: an AgentIdentity "
                "minted by the executor for the goal's agent (F42); a "
                "narrowed registration is routed to the approval queue "
                "exactly like a fresh one")
        old = self._goal_registry.get_goal(goal_id)
        if old is None:
            raise ValueError("unknown goal_id %r" % (goal_id,))
        agent_id = old.get("agent_id")
        new_goal, conflicts = self._goal_registry.narrow(
            goal_id, effects=effects, constraints=constraints)
        self.log.append({
            "event": "goal_narrowed_by_operator",
            "run_id": self.run_id,
            "agent_id": agent_id,
            "old_goal_id": goal_id,
            "new_goal_id": new_goal["goal_id"],
            "new_status": new_goal["status"],
            "note": str(note),
            "reason": ("operator narrowed goal %s into goal %s (%s%s)"
                       % (goal_id[:8], new_goal["goal_id"][:8],
                          new_goal["status"],
                          (": " + note) if note else "")),
        })
        # A narrowed registration can itself be vague (still pending)
        # or conflicting: route through the same review queueing as a
        # fresh registration so neither review is silently skipped.
        if new_goal.get("status") == "pending_specificity":
            self._queue_specificity_review(
                new_goal, agent_id, new_goal.get("description") or "",
                identity, note="re-narrowed goal still vague")
        if conflicts:
            self._queue_conflict_review(
                new_goal, agent_id, new_goal.get("description") or "",
                conflicts, identity)
        return new_goal, conflicts

    def _on_approval_decision(self, record, approved, reason, decided_by,
                              decision_entry):
        """Wave-134/135 (row-11): post-decision hook installed on the queue.

        When a ``goal_conflict_review`` approval item is DECIDED, the
        human's decision resolves the underlying goal conflict --
        approving the review no longer leaves both goals active:

        * allow: the new (conflicting) goal stands; the conflicting
          existing goal(s) are marked ``superseded``;
        * deny: the new goal is marked ``superseded``.

        Resolution runs through ``gov.goals.apply_approval_resolution``
        (the ``set_status`` path, chained ``goal_status_changed``
        events carrying the approval id). A referenced goal that is
        unknown or already resolved produces a LOUD
        ``goal_resolution_noop`` instead of a silent skip.

        Non-goal records are ignored (this is a filter, not a veto).
        Contract: inner failures PROPAGATE to the queue's LOUD
        ``decision_hook_failed`` handler in ``ApprovalQueue.decide``
        (F180 -- the single LOUD choke point); the human decision
        still stands and ``decide()`` still returns. There is no
        belt-and-braces catch here: a failure that is swallowed
        inside the hook can never be audited LOUD.

        Ceiling (documented, not hidden): this automates the
        mechanics, not the judgment -- a human who allows without
        reading still allows. And the hook is bound to the FIRST
        executor's registry (the hook slot is write-once, F31): a goal
        registered on a different executor sharing this queue
        resolves as ``goal_resolution_noop`` (unknown to this
        registry) rather than silently applying to the wrong record
        set.
        """
        if not isinstance(record, dict):
            return
        tool = record.get("tool")
        if tool == "goal_specificity_review":
            # Wave-135 (row-11): the human's decision on a vague goal.
            # allow = explicitly acknowledge the breadth (goal goes
            # active with broad_scope_acknowledged; its wildcard
            # cover fires LOUD from then on); deny = withdraw the
            # goal (superseded). Unknown/already-resolved goals
            # produce a LOUD goal_specificity_noop inside
            # resolve_specificity -- never a silent skip. Same F180
            # contract as the conflict path: inner failures
            # propagate to the queue's LOUD decision_hook_failed
            # handler; the human decision still stands.
            #
            # Wave-145 (row-11): an allow that passed the
            # type-to-confirm ceremony carries the human's typed
            # scope on the record (stored MAC-bound by
            # ApprovalQueue.decide). It is recorded as the narrowed
            # scope: the audit trail shows what the human claimed to
            # approve, at what match score. Wave-135 semantics are
            # unchanged -- the goal still activates with
            # broad_scope_acknowledged; the typed scope is additive
            # evidence, not a re-narrowing (narrowing stays
            # registry.narrow's append-only job).
            args = record.get("args") or {}
            if not isinstance(args, dict):
                return
            summary = self._goal_registry.resolve_specificity(
                args.get("goal_id"),
                acknowledged=bool(approved),
                approval_id=record.get("id"))
            typed = record.get("typed_scope")
            if (approved and isinstance(typed, str) and typed.strip()
                    and summary.get("decision") == "acknowledged"):
                live = self._goal_registry.get_goal(args.get("goal_id"))
                if live is not None:
                    live["narrowed_scope"] = typed.strip()
                self.log.append({
                    "event": "goal_specificity_scope_typed",
                    "flag": "goal_specificity",
                    "run_id": self.run_id,
                    "agent_id": (live or {}).get("agent_id"),
                    "goal_id": args.get("goal_id"),
                    "approval_id": record.get("id"),
                    "typed_scope": typed.strip(),
                    "match_score": record.get("typed_scope_score"),
                    "match_method": record.get("typed_scope_method"),
                    "reason": ("human typed the narrowed scope for goal "
                               "%r (token-tversky %.3f >= %.2f); recorded "
                               "as the narrowed scope"
                               % (args.get("goal_id"),
                                  record.get("typed_scope_score") or 0.0,
                                  _target_match.DEFAULT_THRESHOLD)),
                })
            return
        if tool != "goal_conflict_review":
            return
        args = record.get("args") or {}
        if not isinstance(args, dict):
            return
        # Shared extractor (gov.goals): the ordered [new, *existing]
        # goal ids, so this view of the conflict cannot drift from
        # the queue's decision-event view.
        ordered = _goals.conflict_review_goal_ids(args)
        new_goal_id = args.get("goal_id")
        existing_ids = [gid for gid in ordered
                        if gid != new_goal_id]
        # F179: re-run the conflict detector at decision time against
        # current registry state and pass the attested existing-goal
        # set through. The F38 MAC on the pending record proves the
        # args were not tampered with AFTER queueing -- it does not
        # prove the conflict was ever detector-attested, so an
        # arg-named but unattested existing goal must never be
        # superseded (it gets a LOUD attestation noop inside
        # apply_approval_resolution). detect_conflict is deterministic
        # and pure (read-only over the goal records), so it is safe
        # to run at decision time. Unknown new goal: pass None,
        # preserving the current unknown-new behavior (out of scope).
        new_goal = (self._goal_registry.get_goal(new_goal_id)
                    if new_goal_id else None)
        if new_goal is not None:
            others = [g for g in self._goal_registry.active_goals()
                      if g.get("goal_id") != new_goal_id]
            attested = {c.get("existing_goal_id")
                        for c in _goals.detect_conflict(new_goal, others)}
        else:
            attested = None
        _goals.apply_approval_resolution(
            self._goal_registry,
            new_goal_id=new_goal_id,
            existing_goal_ids=existing_ids,
            approved=bool(approved),
            approval_id=record.get("id"),
            audit=self.log.append,
            attested_existing_ids=attested)

    def _population_trust(self, agent_id):
        """("trusted"|"provisional", detail) for the agent's baseline.

        A corrupted population file fails closed to provisional: no
        new baseline can be validated, so none is trusted.
        """
        if self.population_store is None:
            return ("trusted", {"no_store": True})
        try:
            return self.population_store.trust_of(str(agent_id))
        except _drift.PopulationCorruptedError:
            return ("provisional", {"population_corrupt": True})

    def validate_baseline(self, agent_id, fingerprint, identity=None):
        """Wave-134 (row 9): population-relative baseline validation.

        Validates ``fingerprint`` as the agent's baseline against the
        peer population, records it in the population store with its
        trust state, and emits a LOUD ``baseline_population_outlier``
        audit event when the baseline is an extreme outlier
        (provisional_untrusted). A corrupted population file fails
        closed: the baseline is treated as provisional and the LOUD
        event records the corruption. With no population_store
        installed this returns None and does nothing (zero behavior
        change).
        """
        if self.population_store is None:
            return None
        principal = (identity.principal if identity is not None
                     else "unknown")
        store = self.population_store
        try:
            peers = [(a, fp) for (a, fp) in store.all_baselines()]
        except _drift.PopulationCorruptedError:
            res = _drift.BaselineValidationResult(
                "provisional_untrusted", agent_id=str(agent_id),
                detail={"reason": "population_corrupt",
                        "note": "population file failed chain "
                                "verification; failing closed"})
            self.log.append({
                "event": "baseline_population_outlier",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "principal": principal,
                "status": res.status,
                "reason": ("population file corrupt: new baseline "
                           "treated as provisional_untrusted"),
            })
            return res
        res = _drift.validate_baseline_against_population(
            str(agent_id), fingerprint, peers)
        store.record_baseline(str(agent_id), principal, fingerprint,
                              audit=self.log.append, validation=res)
        if res.status == "provisional_untrusted":
            self.log.append({
                "event": "baseline_population_outlier",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "principal": principal,
                "status": res.status,
                "threshold": res.threshold,
                "agent_distance": res.agent_distance,
                "n_peers": res.n_peers,
                "reason": ("baseline tool distribution is an extreme "
                           "outlier vs the peer population "
                           "(dist=%.4g > thr=%.4g, n_peers=%d); drift "
                           "verdicts against this baseline are capped "
                           "at WARN until confirmed"
                           % (res.agent_distance, res.threshold,
                              res.n_peers)),
            })
        return res

    def check_run_drift(self, agent_id, fingerprint=None, record=True,
                        identity=None, window=8):
        """Wave-131 (row 9): cross-run drift check for an agent.

        When a ``drift_store`` was installed at construction (opt-in),
        optionally records ``fingerprint`` as the agent's latest run
        and runs ``gov.drift.detect_drift`` over the prior runs. The
        response is graduated:

        - watch: a chained ``drift_watch`` audit event (informational);
        - warn: a LOUD ``drift_warn`` audit event for the operator;
        - hold: a LOUD ``drift_hold`` audit event AND a synthetic
          ``drift_review`` approval is queued for human resolution
          (flag "drift_hold", separation-of-duties: the agent can
          never approve its own hold away). The run is NOT auto-
          denied -- a human resolves.

        ``identity`` is the minted AgentIdentity for the agent under
        check -- REQUIRED when a hold may queue an approval (F42: the
        queue never trusts caller-supplied identity fields). With no
        drift_store installed this returns a silent result and does
        nothing (zero behavior change).
        """
        silent = _drift.DriftResult("silent", agent_id=str(agent_id),
                                    reason="no_drift_store")
        if self.drift_store is None:
            return silent
        if fingerprint is not None and record:
            principal = (identity.principal if identity is not None
                         else "unknown")
            self.drift_store.record_run(
                agent_id, principal, fingerprint, audit=self.log.append)
        res = _drift.detect_drift(self.drift_store, agent_id, window=window)
        # Wave-134 (row 9): a provisional_untrusted baseline cannot be
        # trusted in either direction -- SILENT might be a poisoned
        # baseline hiding badness, HOLD would queue a human review
        # against a possibly-meaningless baseline. Force every
        # verdict to WARN (LOUD operator attention, no review
        # auto-queued) and track convergence toward the population so
        # K conforming runs can auto-confirm the baseline.
        if self.population_store is not None:
            trust, tdetail = self._population_trust(agent_id)
            if trust == "provisional":
                res = _drift.cap_drift_verdict(res)
                self.log.append({
                    "event": "drift_provisional_warn",
                    "run_id": self.run_id,
                    "agent_id": str(agent_id),
                    "level": res.level,
                    "baseline_n": res.baseline_n,
                    "window_n": res.window_n,
                    "trust_detail": tdetail,
                    "signals": [s.to_dict() for s in res.signals],
                    "reason": ("drift verdict capped at WARN: agent "
                               "baseline is provisional_untrusted "
                               "(population-relative validation)"),
                })
                if fingerprint is not None and record:
                    try:
                        peers = [(a, fp)
                                 for (a, fp) in
                                 self.population_store.all_baselines()
                                 if a != str(agent_id)]
                        self.population_store.note_run(
                            str(agent_id), fingerprint, peers,
                            audit=self.log.append)
                    except _drift.PopulationCorruptedError:
                        # Stay provisional; the LOUD drift_provisional_
                        # warn event above is the record.
                        pass
        if res.level == "silent":
            return res
        event = {"watch": "drift_watch", "warn": "drift_warn",
                 "hold": "drift_hold"}[res.level]
        self.log.append({
            "event": event,
            "run_id": self.run_id,
            "agent_id": str(agent_id),
            "level": res.level,
            "baseline_n": res.baseline_n,
            "window_n": res.window_n,
            "signals": [s.to_dict() for s in res.signals],
            "reason": ("cross-run behavioral drift: %s"
                       % "; ".join(s.explanation for s in res.signals)),
        })
        if res.level != "hold":
            return res
        if identity is None:
            raise TypeError(
                "check_run_drift() requires identity when a drift hold "
                "queues a drift_review approval (F42); the approval "
                "queue never trusts caller-supplied identity fields")
        detail = "; ".join("%s (%s): %s"
                           % (s.kind, s.strength, s.explanation)
                           for s in res.signals)
        try:
            self.approvals.queue(
                {"tool": "drift_review",
                 "args": {"agent_id": str(agent_id),
                          "level": "hold",
                          "signals": [s.to_dict() for s in res.signals]},
                 "identity": identity.as_dict(),
                 "agent_justification": None,
                 "redactions": []},
                PolicyDecision(
                    "require_approval",
                    "Cross-run drift HOLD for agent %r: %s"
                    % (agent_id, detail),
                    policy_id="drift-monitor",
                    flag="drift_hold"),
                "agent_direct",
                "review cross-run drift HOLD for agent %r" % (agent_id,),
                caller_identity=identity,
                delegation_receipt=self._session_delegation_receipt())
        except Exception:
            # The LOUD drift_hold audit event above is the record; the
            # hold stands flagged even if queueing the review item
            # fails. Fail closed on the signal, never warn-and-
            # continue silently.
            self.log.append({
                "event": "drift_hold_queue_failed",
                "flag": "drift_hold",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "reason": ("drift_review approval could not be queued; "
                           "the drift_hold audit event remains the "
                           "record -- operator must review manually"),
            })
        return res

    def check_egress_content(self, agent_id, tool, args, payload_text=None,
                             identity=None):
        """Wave-132 (row 13): unlabeled-egress content check.

        When a ``content_monitor`` was installed at construction
        (opt-in), scores the outbound payload with
        ``gov.egress_content``. Graduated response:

        - allow: silent; the payload is recorded into the monitor's
          baseline and nothing else happens.
        - flag: a LOUD ``egress_content_flag`` audit event; execution
          proceeds (the flag is for operator review, not a block).
        - require_approval: a LOUD ``egress_content_hold`` audit event
          AND a synthetic ``content_egress_review`` approval is queued
          for human resolution (flag "egress_content_risk",
          separation-of-duties: the agent can never approve its own
          hold away). ``identity`` is REQUIRED here (F42).

        With no content_monitor installed this returns a silent
        ``allow`` result and does nothing (zero behavior change).

        Honest ceiling: prose-form exfiltration carries no
        structured/dump/entropy signal and scores ``allow`` by design
        (see gov/egress_content.py).
        """
        silent = {"verdict": "allow", "score": 0.0, "reason":
                  "no_content_monitor", "agent_id": str(agent_id)}
        if self.content_monitor is None:
            return silent
        res = self.content_monitor.check(agent_id, tool, args,
                                         payload_text=payload_text)
        verdict = res.get("verdict", "allow")
        if verdict == "allow":
            return res
        signals = res.get("signals", {})
        detail = ("score=%.2f signals=%s"
                  % (res.get("score", 0.0),
                     ",".join("%s=%.2f" % (k, v)
                              for k, v in sorted(signals.items())
                              if isinstance(v, (int, float)))))
        if verdict == "flag":
            self.log.append({
                "event": "egress_content_flag",
                "flag": "egress_content_risk",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "tool": tool,
                "destination": res.get("destination"),
                "detail": detail,
                "reason": ("unlabeled-egress content flag (execution "
                           "proceeds; operator review): %s" % detail),
            })
            return res
        # require_approval.
        self.log.append({
            "event": "egress_content_hold",
            "flag": "egress_content_risk",
            "run_id": self.run_id,
            "agent_id": str(agent_id),
            "tool": tool,
            "destination": res.get("destination"),
            "detail": detail,
            "reason": ("unlabeled-egress content HOLD: %s" % detail),
        })
        if identity is None:
            raise TypeError(
                "check_egress_content() requires identity when a content "
                "hold queues a content_egress_review approval (F42); the "
                "approval queue never trusts caller-supplied identity "
                "fields")
        try:
            self.approvals.queue(
                {"tool": "content_egress_review",
                 "args": {"agent_id": str(agent_id),
                          "tool": tool,
                          "destination": res.get("destination"),
                          "score": res.get("score", 0.0),
                          "signals": signals},
                 "identity": identity.as_dict(),
                 "agent_justification": None,
                 "redactions": []},
                PolicyDecision(
                    "require_approval",
                    "Unlabeled-egress content HOLD for agent %r: %s"
                    % (agent_id, detail),
                    policy_id="egress-content",
                    flag="egress_content_risk"),
                "agent_direct",
                "review unlabeled-egress content HOLD for agent %r"
                % (agent_id,),
                caller_identity=identity,
                delegation_receipt=self._session_delegation_receipt())
        except Exception:
            self.log.append({
                "event": "egress_content_hold_queue_failed",
                "flag": "egress_content_risk",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "reason": ("content_egress_review approval could not be "
                           "queued; the egress_content_hold audit event "
                           "remains the record -- operator must review "
                           "manually"),
            })
        return res

    def note_read_output(self, agent_id, source_id, text):
        """Wave-136 (row 13): record one read source's rare tokens.

        Explicit, minimal read-path wiring for the rare-token
        carryover tracker: the operator/harness calls this when a
        READ-type tool completes (read_file results, etc.). The hot
        tool path is untouched and nothing is double-counted. With
        no tracker installed this is a no-op returning
        ``{"observed": False}`` (zero behavior change). Wave-141:
        a successful governed ``read_file`` ALSO observes itself
        automatically (real sandbox bytes only — see
        ``_rare_token_observe_on_read``); the explicit call stays
        for harness-side reads and replaces the auto observation
        when the source IDs match. Reads that never cross the
        governed tool boundary (direct filesystem access) remain
        invisible to the tracker — the documented coverage ceiling.
        Wave-139: when the tracker has
        a ``taint_ledger`` attached, the read is also recorded
        durably (counts, doc ids, opaque commitments — never token
        strings) so a later run's egress check can consult it.
        """
        if self.reconstruction_seam is not None:
            # Wave-266 (F248): feed the run's untrusted chunk set for
            # act-gate reconstructed-intent scoring. Best-effort
            # buffering (note_chunk ignores malformed notes); the
            # seam validates shapes fail-closed at scoring time.
            # Same coverage ceiling as the rare-token tracker: reads
            # that never cross the governed tool boundary stay
            # invisible.
            self.reconstruction_seam.note_chunk(str(source_id), text)
        if self.rare_token_tracker is None:
            return {"observed": False, "agent_id": str(agent_id),
                    "source_id": str(source_id)}
        return self.rare_token_tracker.observe_read(agent_id, source_id,
                                                    text)

    def note_propagation_input(self, agent_id, source_id, text):
        """Wave-151 (Row 19): observe one input-context segment for the
        injection-propagation tracker.

        Records the instruction spans of ``text`` (tool results,
        retrieved docs, emails, commit summaries -- whatever the
        deployment feeds it) so a later ``check_output_propagation``
        can spot the agent reproducing them into a new output
        channel. With no tracker installed this is a no-op returning
        ``{"observed": False}`` (zero behavior change). Wave-152:
        explicit-only is gone -- a successful governed ``read_file``
        ALSO observes itself automatically (real sandbox bytes only --
        see ``_propagation_observe_on_read``); the explicit call
        stays for harness-side reads and replaces the auto
        observation when the source IDs match (same
        (agent_id, source_id) key -- no double count). Reads that
        never cross the governed tool boundary (direct filesystem
        access) remain invisible -- the documented coverage ceiling.
        """
        if self.propagation_tracker is None:
            return {"observed": False, "agent_id": str(agent_id),
                    "source_id": str(source_id)}
        return self.propagation_tracker.observe_input(agent_id, source_id,
                                                      text)

    def note_public_channel_input(self, agent_id, source_id, text,
                                  provenance):
        """Wave-245 lane 8 (Row 19): observe one input-context segment
        WITH its provenance for the public-channel propagation guard.

        Unlike ``note_propagation_input`` this records where the input
        came from; only trusted provenance (user / operator /
        deployment-policy / deployer) can ever exempt a reproduced
        span from the hop-1 refusal or grant instruction authority.
        With no guard installed this is a no-op returning
        ``{"observed": False}`` (zero behavior change).
        """
        if self.propagation_guard is None:
            return {"observed": False, "agent_id": str(agent_id),
                    "source_id": str(source_id)}
        return self.propagation_guard.observe_input(agent_id, source_id,
                                                    text, provenance)

    def check_output_propagation(self, agent_id, channel, output_text,
                                 user_request=None):
        """Wave-151 (Row 19): output-boundary injection-propagation check.

        When a ``propagation_tracker`` was installed at construction
        (opt-in), scores one boundary-crossing output (``channel`` is
        "file"/"chat"/"code"/... -- recorded for triage, never
        verdict-relevant) for injected-instruction propagation: the
        output reproduces an imperative instruction that was present
        in the observed input context but NOT in the user's original
        request.

        Response is TRIAGE TIER ONLY, like the wave-137
        ``read_then_egress_novel`` flag: on ``propagation_suspect`` a
        LOUD ``injection_propagation_suspect`` audit event is appended
        (flag "injection_propagation", reproduced span(s), source
        ids, channel) and execution PROCEEDS -- no approval is queued,
        nothing is blocked, nothing halts. With no tracker installed
        this returns a silent ``allow`` and does nothing (zero
        behavior change).
        """
        silent = {"verdict": "allow", "spans": [], "channel": str(channel),
                  "agent_id": str(agent_id), "sources": [],
                  "reason": "no_propagation_tracker"}
        if self.propagation_tracker is None:
            return silent
        res = self.propagation_tracker.check_output(agent_id, channel,
                                                    output_text,
                                                    user_request=user_request)
        if res.get("verdict") != "propagation_suspect":
            return res
        detail = ("channel=%s spans=%d sources=%s" % (
            res.get("channel"), len(res.get("spans", [])),
            ",".join(res.get("sources", []))))
        self.log.append({
            "event": "injection_propagation_suspect",
            "flag": "injection_propagation",
            "run_id": self.run_id,
            "agent_id": str(agent_id),
            "channel": res.get("channel"),
            "spans": res.get("spans", []),
            "sources": res.get("sources", []),
            "detail": detail,
            "reason": ("injection-propagation suspect (triage-only, "
                       "execution proceeds; never a block): %s" % detail),
        })
        return res

    def check_public_channel_egress(self, agent_id, channel, content,
                                    user_request=None):
        """Wave-245 lane 8 (Row 19): hop-1 refusal for public-channel
        injection propagation.

        When a ``propagation_guard`` was installed at construction
        (opt-in), reviews one boundary-crossing output destined for a
        PUBLIC channel (email reply, shared doc, public comment, ...).
        On ``refuse`` a LOUD ``egress_propagation_refused`` audit
        event is appended (flag "egress_propagation", decision code,
        reproduced span(s), untrusted source ids, channel) and the
        verdict is returned -- the deployment must NOT let the send
        proceed. This is the hop-1 block the wave-151/152 triage seam
        deliberately does not do: non-public channels stay with the
        triage tier.

        With no guard installed this returns a silent ``allow`` result
        and does nothing (zero behavior change).
        """
        silent = {"verdict": "allow", "channel": str(channel),
                  "agent_id": str(agent_id),
                  "reason": "no_propagation_guard"}
        if self.propagation_guard is None:
            return silent
        res = self.propagation_guard.review_outbound(agent_id, channel,
                                                     content,
                                                     user_request=user_request)
        if res.get("verdict") != "refuse":
            return res
        detail = ("channel=%s code=%s spans=%d sources=%s" % (
            res.get("channel"), res.get("code"),
            len(res.get("spans", [])),
            ",".join(res.get("sources", []))))
        self.log.append({
            "event": "egress_propagation_refused",
            "flag": "egress_propagation",
            "run_id": self.run_id,
            "agent_id": str(agent_id),
            "channel": res.get("channel"),
            "code": res.get("code"),
            "spans": res.get("spans", []),
            "sources": res.get("sources", []),
            "detail": detail,
            "reason": ("public-channel injection-propagation REFUSED "
                       "at hop 1 (execution of the send must not "
                       "proceed): %s" % detail),
        })
        return res

    def check_rare_token_carryover(self, agent_id, tool, args,
                                   payload_text=None, identity=None):
        """Wave-136 (row 13): rare-token carryover check.
        Wave-137 adds the behavioral tier (see gov/rare_token.py).

        When a ``rare_token_tracker`` was installed at construction
        (opt-in), scores one outbound payload for rare-token
        carryover from anything this agent READ this run. Graduated
        response:

        - allow: silent.
        - flag: a LOUD ``rare_token_flag`` audit event; execution
          proceeds (1-2 carryover tokens, or >=K tokens to a
          KNOWN destination — destination novelty amplifies).
        - require_approval: a LOUD ``rare_token_hold`` audit event
          AND a synthetic ``rare_token_review`` approval is queued
          for human resolution (flag "rare_token_carryover",
          separation-of-duties: the agent can never approve its own
          hold away). ``identity`` is REQUIRED here (F42).
        - behavioral_flag: a LOUD ``read_then_egress_novel`` audit
          event (flag "read_then_egress"); execution proceeds, NO
          approval is queued and ``identity`` is not needed — this
          is triage-only by design, never a block. Fires only when
          the content tier found zero overlap AND the agent read
          >=1 token-bearing document (this run, or a prior run when
          the tracker has a ``taint_ledger`` attached — see
          gov/taint_ledger.py) AND the destination is a
          concrete novel one (novelty is per-run, or against
          run-1..N history when the tracker has a
          ``destination_ledger`` attached — see
          gov/destination_ledger.py).

        Every audit event carries counts and doc ids ONLY — token
        strings are never logged (privacy). With no tracker
        installed this returns a silent ``allow`` and does nothing
        (zero behavior change).

        Honest ceilings: a full rewrite that drops every rare token
        is invisible to the CONTENT tier by design; the behavioral
        tier flags the read->novel-egress sequence instead (and WILL
        fire on legitimate read-then-send workflows — the operator
        triages on docs_read + destination). Without a taint ledger
        attached, cross-run read->egress stays invisible (the tracker
        is per-run; opt-in ceiling). With a ledger attached, the
        ledger's ceilings apply (operator TTL, stable identity,
        key-rotation blinding; destination history persists across
        runs when a ``destination_ledger`` is attached, per-run
        otherwise). See gov/rare_token.py and gov/taint_ledger.py.
        """
        silent = {"verdict": "allow", "overlap": 0, "source_id": None,
                  "reason": "no_rare_token_tracker",
                  "agent_id": str(agent_id)}
        if self.rare_token_tracker is None:
            return silent
        res = self.rare_token_tracker.check_egress(agent_id, tool, args,
                                                  payload_text=payload_text)
        verdict = res.get("verdict", "allow")
        if verdict == "allow":
            return res
        if verdict == "behavioral_flag":
            detail = ("docs_read=%d destination=%s novel=%s" % (
                res.get("docs_read", 0), res.get("destination"),
                res.get("destination_novel")))
            self.log.append({
                "event": "read_then_egress_novel",
                "flag": "read_then_egress",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "tool": tool,
                "destination": res.get("destination"),
                "docs_read": res.get("docs_read", 0),
                "source_ids": res.get("source_ids", []),
                "detail": detail,
                "reason": ("read-then-egress behavioral flag "
                           "(triage-only, execution proceeds; never a "
                           "block): %s" % detail),
            })
            return res
        detail = ("overlap=%d source=%s destination=%s novel=%s" % (
            res.get("overlap", 0), res.get("source_id"),
            res.get("destination"), res.get("destination_novel")))
        if verdict == "flag":
            self.log.append({
                "event": "rare_token_flag",
                "flag": "rare_token_carryover",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "tool": tool,
                "destination": res.get("destination"),
                "detail": detail,
                "reason": ("rare-token carryover flag (execution "
                           "proceeds; operator review): %s" % detail),
            })
            return res
        # require_approval.
        self.log.append({
            "event": "rare_token_hold",
            "flag": "rare_token_carryover",
            "run_id": self.run_id,
            "agent_id": str(agent_id),
            "tool": tool,
            "destination": res.get("destination"),
            "detail": detail,
            "reason": ("rare-token carryover HOLD: %s" % detail),
        })
        if identity is None:
            raise TypeError(
                "check_rare_token_carryover() requires identity when a "
                "carryover hold queues a rare_token_review approval "
                "(F42); the approval queue never trusts caller-supplied "
                "identity fields")
        try:
            self.approvals.queue(
                {"tool": "rare_token_review",
                 "args": {"agent_id": str(agent_id),
                          "tool": tool,
                          "destination": res.get("destination"),
                          "overlap": res.get("overlap", 0),
                          "source_id": res.get("source_id"),
                          "destination_novel": res.get("destination_novel")},
                 "identity": identity.as_dict(),
                 "agent_justification": None,
                 "redactions": []},
                PolicyDecision(
                    "require_approval",
                    "Rare-token carryover HOLD for agent %r: %s"
                    % (agent_id, detail),
                    policy_id="rare-token",
                    flag="rare_token_carryover"),
                "agent_direct",
                "review rare-token carryover HOLD for agent %r"
                % (agent_id,),
                caller_identity=identity,
                delegation_receipt=self._session_delegation_receipt())
        except Exception:
            self.log.append({
                "event": "rare_token_hold_queue_failed",
                "flag": "rare_token_carryover",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "reason": ("rare_token_review approval could not be "
                           "queued; the rare_token_hold audit event "
                           "remains the record -- operator must review "
                           "manually"),
            })
        return res

    def check_egress_tiered_verdict(self, agent_id, tool, args,
                                    payload_text=None):
        """Wave-160 (row 13): tiered egress-verdict composition on the
        operational egress path.

        The T1->T2->T3 tiered verdicts (gov/detection_verdicts.py) were
        library-only: neither the content monitor nor the rare-token
        tracker ever ran on the operational egress-attempt path, so a
        T3 paraphrase-footprint egress left no verdict and drew no
        tiered response. This method is the operational seam: it runs
        the installed monitors over one egress payload, composes the
        tiered verdict, records ONE ``egress_tiered_verdict`` audit
        event per analyzed egress (tier, verdict, provenance, triage
        inputs), and returns the composed dict. The egress-attempt
        path in call() applies the graduated response:

        - allow: pass; the recorded event is the evidence.
        - flag: LOUD event (flag "egress_tiered_risk"); execution
          proceeds (the flag is for operator review, not a block).
        - behavioral_flag: LOUD event (flag "read_then_egress", the
          existing triage taxonomy); execution proceeds --
          triage-only by design, never a block.
        - require_approval: LOUD hold event (flag
          "egress_tiered_risk"); the caller forces the standard
          require_approval path -- the action is queued for a human
          and never executes on a policy allow alone (fail-closed).
          The agent can never approve its own hold away
          (separation-of-duties rides the standard queue machinery).

        Opt-in: with neither monitor installed this returns a silent
        allow and does nothing (zero behavior change). Partial
        installation is supported: the missing tier is treated as a
        silent allow, and the composition is monotonic, so a present
        tier's verdict is never weakened by the absent one.

        Provenance privacy: the provenance list carries detector
        labels, signal names, counts, doc ids, destinations, and
        scores -- NEVER token strings or fragment strings (the
        composition module's contract, pinned by its battery).

        Honest ceilings (unchanged): footprint-free prose paraphrase
        stays triage-only under T2; salami drips and destination
        warming remain pinned residuals (see gov/detection_verdicts.py).
        """
        silent = {"tier": "T1", "verdict": "allow", "composed": False,
                  "provenance": [], "reason": "no_egress_monitors",
                  "inputs": {}, "agent_id": str(agent_id)}
        monitor = self.content_monitor
        tracker = self.rare_token_tracker
        if monitor is None and tracker is None:
            return silent
        if monitor is not None:
            t1raw = monitor.check(agent_id, tool, args or {},
                                  payload_text=payload_text)
            t1 = {"verdict": t1raw.get("verdict", "allow"),
                  "score": t1raw.get("score", 0.0),
                  "signals": t1raw.get("signals") or {},
                  # F186: the monitor record's "detail" section
                  # carries the padding-robust absolute presence
                  # legs (structured_lines, suspicious_bytes).
                  # Dropping it here would silently disable those
                  # legs on the operational seam.
                  "detail": t1raw.get("detail") or {}}
        else:
            t1 = {"verdict": "allow", "score": 0.0, "signals": {},
                  "detail": {}}
        if tracker is not None:
            t2raw = tracker.check_egress(agent_id, tool, args or {},
                                         payload_text=payload_text)
            t2 = {"verdict": t2raw.get("verdict", "allow"),
                  "overlap": t2raw.get("overlap", 0),
                  "destination_novel": bool(
                      t2raw.get("destination_novel", False)),
                  "docs_read": t2raw.get("docs_read", 0),
                  "threshold": t2raw.get("threshold", "n/a"),
                  "source_ids": t2raw.get("source_ids", []) or [],
                  "destination": t2raw.get("destination")}
        else:
            t2 = {"verdict": "allow", "overlap": 0,
                  "destination_novel": False, "docs_read": 0,
                  "threshold": "n/a", "source_ids": [],
                  "destination": None}
        res = _detection_verdicts.compose(t1, t2)
        res["inputs"] = {
            "t1_verdict": t1["verdict"],
            "t1_score": t1["score"],
            "t2_verdict": t2["verdict"],
            "overlap": t2["overlap"],
            "destination": t2["destination"],
            "destination_novel": t2["destination_novel"],
        }
        res["agent_id"] = str(agent_id)
        verdict = res.get("verdict", "allow")
        tier = res.get("tier", "T1")
        detail = ("tier=%s verdict=%s%s: %s"
                  % (tier, verdict,
                     " (composed)" if res.get("composed") else "",
                     res.get("reason", "")))
        event = {"event": "egress_tiered_verdict",
                 "run_id": self.run_id,
                 "agent_id": str(agent_id),
                 "tool": tool,
                 "destination": res["inputs"]["destination"],
                 "tier": tier,
                 "verdict": verdict,
                 "composed": bool(res.get("composed", False)),
                 "reason": res.get("reason", ""),
                 "inputs": res["inputs"],
                 "provenance": res.get("provenance", []),
                 "detail": detail}
        if verdict in ("flag", "require_approval"):
            event["flag"] = "egress_tiered_risk"
            event["reason"] = ("TIERED EGRESS %s -- %s"
                               % ("HOLD" if verdict == "require_approval"
                                  else "FLAG", detail))
        elif verdict == "behavioral_flag":
            # The existing triage taxonomy for read->novel-egress
            # sequences (see check_rare_token_carryover): triage-only,
            # execution proceeds, never a block.
            event["flag"] = "read_then_egress"
            event["reason"] = ("TIERED EGRESS FLAG (triage-only) -- %s"
                               % detail)
        self.log.append(event)
        return res

    def check_reconstructed_intent(self, agent_id, tool, args,
                                   chunks=None, user_text="",
                                   justification="", identity=None,
                                   queue_hold=True):
        """Wave-266 (F248): reconstructed-intent scoring seam --
        the operational act-gate entry point.

        Scores the run's untrusted chunk set (Divide-and-Inject
        fragments) plus the planned action via the installed
        ``gov.reconstructed_intent.ReconstructionSeam``. Opt-in:
        with no seam installed this returns a quiet verdict and does
        nothing (zero behavior change). ``chunks=None`` scores the
        seam's buffered per-run chunk set (fed by note_read_output);
        an explicit chunk set is validated fail-closed by the seam.

        Graduated response (the rare_token_hold pattern):

        - quiet: silent; the verdict dict is the record.
        - suspect: a LOUD ``reconstructed_intent_suspect`` audit
          event (args digest, never raw args; built by
          ``gov.reconstructed_intent.suspect_event`` so the journal
          shape cannot drift from the standalone seam path). With
          ``queue_hold=True`` (default) a synthetic
          ``reconintent_review`` approval is also queued for human
          resolution (flag "reconstructed_intent"; ``identity`` is
          REQUIRED here, F42 -- separation of duties rides the
          standard queue machinery: the agent can never approve its
          own hold away). The in-call() act path scores quietly via
          ``score_buffered`` pre-policy and applies the event +
          hold post-policy itself instead (fail-closed direction
          only: a deny stays denied with no dangling event; an
          existing require_approval keeps its record and gains the
          reconintent preview banner). Execution is never blocked
          on the heuristic: the action proceeds per the human
          decision.

        A throwing queue is LOUD (``reconintent_hold_queue_failed``)
        and the suspect verdict is still returned -- the flag is
        never dropped silently.
        """
        from . import reconstructed_intent as _reconintent
        if self.reconstruction_seam is None:
            return {"suspect": False, "score": 0,
                    "confidence": "none", "code": None,
                    "installed": False,
                    "signals": {"chunks_scored": 0}}
        # Score directly: the seam's evaluate() is the standalone
        # deployment path (own journal + queue callable). Here the
        # executor owns the audit log and the approval queue, so the
        # hold rides the standard machinery below -- separation of
        # duties is enforced by gov.approvals, not by a docstring.
        # score_buffered: buffer texts were fingerprinted at note
        # time, so the act path does not re-hash per call.
        if chunks is None:
            verdict = self.reconstruction_seam.score_buffered(
                tool, args, user_text, justification)
        else:
            verdict = _reconintent.score_run(
                chunks, tool, args, user_text, justification)
        verdict["installed"] = True
        if not verdict.get("suspect"):
            return verdict
        self.log.append(_reconintent.suspect_event(
            verdict, agent_id, tool, args, self.run_id))
        if identity is None and queue_hold:
            raise TypeError(
                "check_reconstructed_intent() requires identity when "
                "a reconstructed-intent hold queues a "
                "reconintent_review approval (F42); the approval "
                "queue never trusts caller-supplied identity fields")
        if queue_hold:
            try:
                _hold = _reconintent.hold_request(
                    verdict, agent_id, tool, args, justification)
                self.approvals.queue(
                    {"tool": "reconintent_review",
                     "args": _hold["args"],
                     "identity": identity.as_dict(),
                     "agent_justification": justification or None,
                     "redactions": []},
                    PolicyDecision(
                        "require_approval",
                        "Reconstructed-intent HOLD for agent %r: %s"
                        % (agent_id,
                           _reconintent.preview_banner(verdict)),
                        policy_id="reconintent",
                        flag="reconstructed_intent"),
                    "agent_direct",
                    "review reconstructed-intent HOLD for agent %r"
                    % (agent_id,),
                    caller_identity=identity,
                    delegation_receipt=self._session_delegation_receipt())
            except Exception:
                self.log.append({
                    "event": "reconintent_hold_queue_failed",
                    "code": "reconintent-queue-failed",
                    "flag": "reconstructed_intent",
                    "run_id": self.run_id,
                    "agent_id": str(agent_id),
                    "tool": tool,
                    "reason": ("reconintent_review approval could not "
                               "be queued; the "
                               "reconstructed_intent_suspect audit "
                               "event remains the record -- operator "
                               "must review manually"),
                })
        return verdict

    def check_write_declared_path(self, agent_id, path_resolved,
                                  declared_path=None):
        """Row-12 (wave-162): undeclared-path write binding.

        The deployment manifest declares the deployment-critical
        artifact paths, but the manifest consult only compared hashes
        at egress time -- a path absent from the manifest consulted as
        ``manifest_absent`` with NO flag, so an executor could write
        (and later exfiltrate) files to paths that were never declared.
        This method is the write-time seam: every ``write_file`` whose
        check-time resolved target is inside the sandbox must be either
        a manifest-declared artifact path or under one of the
        deployment-declared writable dirs
        (``declared_write_dirs``); anything else draws a LOUD
        ``write_undeclared_path`` audit event (flag
        ``undeclared_write_path``) and a ``require_approval`` verdict,
        and the call() path forces the standard human-approval queue
        on a policy allow (fail-closed direction only -- a deny stays
        denied, an existing require_approval is untouched).

        Queue (not deny) is the consistent choice: the manifest's own
        documented fail-closed direction is require_approval ("the
        fail-closed direction is require_approval until the operator
        re-pins" -- attach_deployment_manifest), and the unrated-tool,
        tiered-verdict, and deferred-effect seams all force approval
        for suspicious-but-possibly-legitimate actions. An undeclared
        write may be a legitimate new artifact the operator simply did
        not pre-declare; the human reviewer sees the forcing on the
        MAC-bound record and the write never executes without that
        review. Deny is reserved for never-legitimate actions
        (sandbox escape on read, unverifiable ledger, halted identity).

        ``path_resolved`` is the check-time resolved target from
        ``_context`` (``path_resolved`` -- the SAME value the F147
        machinery binds the effect to), sandbox-relative when inside.
        Resolve-then-compare: symlinks are evaluated at their target,
        ``..`` is collapsed lexically, absolute in-sandbox paths are
        compared by their sandbox-relative form, and case variants are
        distinct paths (fail-closed on a case-sensitive filesystem).

        Opt-in: with no manifest effectively attached this returns a
        silent allow and records nothing (zero behavior change;
        no-monitor deployments stay silent-allow by design, wave-160
        precedent). The binding follows the EFFECTIVE manifest -- the
        envelope on the shared artifact inventory, the same one the
        egress consult reads -- so a post-construction attach binds
        writes and a detach releases the binding, exactly matching the
        egress seam (a constructor-attached envelope is on the
        inventory from construction, so the normal path is
        unchanged). Targets resolving outside the sandbox are also a
        silent allow from THIS seam -- the existing
        quarantine-outside-writes policy rule and the _simulate
        quarantine already govern them; double-governing would only
        fork the audit trail.

        The approved sweep calls _simulate directly (never call()), so
        a human-approved undeclared write executes exactly once with
        no re-queue: the human reviewed the MAC-bound record (wave-160
        precedent).

        Returns a dict with ``verdict`` ("allow" | "require_approval"),
        ``declared`` (bool), ``reason``, and the normalized ``path``.
        """
        import posixpath
        silent = {"verdict": "allow", "declared": True,
                  "reason": "no_manifest_binding",
                  "path": (str(path_resolved)
                           if path_resolved is not None else None)}
        envelope = self.artifacts.deployment_manifest_envelope
        if envelope is None:
            return silent
        if not path_resolved or not isinstance(path_resolved, str):
            # No resolved target (non-executor caller, offline replay):
            # no behavior change, matching the F147 discipline.
            return dict(silent, reason="no_resolved_target")
        if Path(path_resolved).is_absolute():
            # Resolves outside the sandbox: the quarantine-outside-writes
            # seam owns this write, not the manifest binding.
            return dict(silent, reason="outside_sandbox")
        rel = posixpath.normpath(
            path_resolved.replace("\\", "/").strip())
        rel = rel.lstrip("/")
        while rel.startswith("./"):
            rel = rel[2:]
        if not rel or rel == "." or rel.startswith(".."):
            return dict(silent, reason="outside_sandbox")
        entries = (envelope.get("manifest") or {})
        declared = rel in entries
        if not declared:
            for prefix in self._declared_write_dirs:
                if rel == prefix or rel.startswith(prefix + "/"):
                    declared = True
                    break
        if declared:
            return {"verdict": "allow", "declared": True,
                    "reason": "declared_path", "path": rel}
        try:
            from . import artifact_inventory_manifest as _manifest
            manifest_digest = _manifest.manifest_digest(envelope)
        except Exception:
            manifest_digest = "unavailable"
        event = {
            "event": "write_undeclared_path",
            "run_id": self.run_id,
            "agent_id": str(agent_id),
            "tool": "write_file",
            "decision": "require_approval",
            "policy_id": "manifest-write-binding",
            "flag": "undeclared_write_path",
            "path": rel,
            "declared_path": (str(declared_path)
                              if declared_path is not None else None),
            "manifest_digest": manifest_digest,
            "reason": ("UNDECLARED WRITE HOLD -- write_file target %r is "
                       "not a manifest-declared artifact path and is not "
                       "under a deployment-declared writable dir: a human "
                       "must review this write before it executes "
                       "(row-12 undeclared-path binding, wave-162)."
                       % (rel,)),
        }
        self.log.append(event)
        return {"verdict": "require_approval", "declared": False,
                "reason": event["reason"], "path": rel}

    def check_run_framing(self, agent_id, fingerprint=None, record=True,
                          identity=None, window=8):
        """Wave-134 (row 9): cross-run framing-drift check for an agent.

        When a ``framing_store`` was installed at construction (opt-in),
        optionally records ``fingerprint`` (a
        ``gov.framing.FramingFingerprint``) as the agent's latest run
        and runs ``gov.framing.detect_framing`` over the prior runs.
        The response is graduated -- the same contract as
        ``check_run_drift``:

        - watch: a chained ``framing_watch`` audit event
          (informational);
        - warn: a LOUD ``framing_warn`` audit event for the operator;
        - hold: a LOUD ``framing_hold`` audit event AND a synthetic
          ``framing_review`` approval is queued for human resolution
          (flag "framing_hold", separation-of-duties: the agent can
          never approve its own hold away). The run is NOT auto-
          denied -- a human resolves.

        ``identity`` is the minted AgentIdentity for the agent under
        check -- REQUIRED when a hold may queue an approval (F42: the
        queue never trusts caller-supplied identity fields). With no
        framing_store installed this returns a silent result and does
        nothing (zero behavior change).

        Honest ceiling: content-level framing (same destination,
        different payload meaning) is invisible to this layer -- see
        ``gov.framing``.
        """
        silent = _framing.FramingResult("silent", agent_id=str(agent_id),
                                        reason="no_framing_store")
        if self.framing_store is None:
            return silent
        if fingerprint is not None and record:
            principal = (identity.principal if identity is not None
                         else "unknown")
            self.framing_store.record_run(
                agent_id, principal, fingerprint, audit=self.log.append)
        res = _framing.detect_framing(self.framing_store, agent_id,
                                      window=window)
        if res.level == "silent":
            return res
        event = {"watch": "framing_watch", "warn": "framing_warn",
                 "hold": "framing_hold"}[res.level]
        self.log.append({
            "event": event,
            "run_id": self.run_id,
            "agent_id": str(agent_id),
            "level": res.level,
            "baseline_n": res.baseline_n,
            "window_n": res.window_n,
            "signals": [s.to_dict() for s in res.signals],
            "reason": ("cross-run framing drift: %s"
                       % "; ".join(s.explanation for s in res.signals)),
        })
        if res.level != "hold":
            return res
        if identity is None:
            raise TypeError(
                "check_run_framing() requires identity when a framing "
                "hold queues a framing_review approval (F42); the "
                "approval queue never trusts caller-supplied identity "
                "fields")
        detail = "; ".join("%s (%s): %s"
                           % (s.kind, s.strength, s.explanation)
                           for s in res.signals)
        try:
            self.approvals.queue(
                {"tool": "framing_review",
                 "args": {"agent_id": str(agent_id),
                          "level": "hold",
                          "signals": [s.to_dict() for s in res.signals]},
                 "identity": identity.as_dict(),
                 "agent_justification": None,
                 "redactions": []},
                PolicyDecision(
                    "require_approval",
                    "Cross-run framing drift HOLD for agent %r: %s"
                    % (agent_id, detail),
                    policy_id="framing-monitor",
                    flag="framing_hold"),
                "agent_direct",
                "review cross-run framing drift HOLD for agent %r"
                % (agent_id,),
                caller_identity=identity,
                delegation_receipt=self._session_delegation_receipt())
        except Exception:
            # The LOUD framing_hold audit event above is the record; the
            # hold stands flagged even if queueing the review item
            # fails. Fail closed on the signal, never warn-and-
            # continue silently.
            self.log.append({
                "event": "framing_hold_queue_failed",
                "flag": "framing_hold",
                "run_id": self.run_id,
                "agent_id": str(agent_id),
                "reason": ("framing_review approval could not be queued; "
                           "the framing_hold audit event remains the "
                           "record -- operator must review manually"),
            })
        return res

    def run_artifact_sweep(self):
        """Run the post-run artifact sweep and audit findings LOUD.

        Row-12 second half (wave-133): walks the run sandbox and
        compares every regular file against the Wave-130 artifact
        inventory (``gov/artifact_sweep.py``). Wave-136: when the
        ``artifact_sweep`` opt-in is a dict with a ``"watch_roots"``
        key, operator-configured watch roots are swept too (same
        never_registered / integrity_violation logic; findings carry
        the resolved ``root``). Each finding is audited as a chained
        ``artifact_sweep_finding`` event; one
        ``artifact_sweep_complete`` event carries the sweep stats as
        evidence the sweep ran. Wave-140: when the ``artifact_sweep``
        opt-in dict carries a non-empty ``"declared_inventory"`` (an
        operator-declared list of egress-capable directories), a
        coverage report compares it against the configured watch
        roots BEFORE the sweep: every inventoried directory with no
        covering watch root is audited LOUD as a chained
        ``artifact_sweep_coverage_gap`` event plus one
        ``artifact_sweep_coverage_complete`` summary. Absent/empty
        inventory = no report, zero behavior change. Wave-143: when
        the ``artifact_sweep`` opt-in dict carries a
        ``"roots_declaration"`` envelope (from
        ``gov.artifact_sweep.declare_watch_roots``), the effective
        watch roots are compared against the last declared set BEFORE
        the sweep: any out-of-band change (roots added/removed,
        config edited directly) is audited LOUD as
        ``artifact_sweep_roots_undeclared_change`` and the sweep is
        treated as unpinned/unverified (fail-closed). The
        ``artifact_sweep_complete`` event always carries
        ``roots_verdict`` (``"declared"`` | ``"undeclared"`` |
        ``"undeclared_change"`` | ``"unverifiable"``) and
        ``roots_verified`` so a sweep is never silently presented as
        a declared-roots sweep.

        Returns the findings list.

        Works whether or not the ``artifact_sweep`` opt-in is
        installed (the opt-in only controls the AUTOMATIC run at the
        end of ``execute_approved()``). Never raises: a sweep failure
        (including a misconfigured watch root, which fails closed
        before anything is walked) is audited, never fatal to the
        caller.
        """
        watch_roots = ()
        if isinstance(self.artifact_sweep, dict):
            watch_roots = self.artifact_sweep.get("watch_roots", ()) or ()
        # Wave-143: no declaration configured = the explicit
        # downgrade (the sweep is not verified against any declared
        # set); never silently presented as declared.
        roots_verdict = "undeclared"
        try:
            if isinstance(self.artifact_sweep, dict):
                declared = self.artifact_sweep.get("declared_inventory") \
                    or ()
                if declared:
                    # Wave-140: coverage report runs BEFORE the sweep
                    # so a blind spot is LOUD even when the sweep
                    # itself is clean. Events ride the chained audit
                    # log (self.log). Inside the try: a malformed
                    # inventory is audited as artifact_sweep_failed
                    # like any other sweep failure (never raises).
                    # Wave-142: the opt-in may carry
                    # "pin_ttl_seconds" -- the operator TTL for pins;
                    # a pin older than the TTL (or made under a
                    # rotated-out key epoch) verifies as
                    # stale_pin_epoch: LOUD, fail-closed full-gap.
                    ttl = self.artifact_sweep.get("pin_ttl_seconds")
                    _artifact_sweep.report_coverage_gaps(
                        declared, watch_roots,
                        audit=lambda ev: self.log.append(ev),
                        run_id=self.run_id,
                        pin_ttl_seconds=ttl)
            if isinstance(self.artifact_sweep, dict):
                roots_decl = self.artifact_sweep.get("roots_declaration")
                if roots_decl:
                    # Wave-143: declaration enforcement runs BEFORE
                    # the sweep so an out-of-band change is LOUD even
                    # when the sweep itself is clean. The effective
                    # roots are compared against the last declared
                    # set; any mismatch is audited LOUD as
                    # artifact_sweep_roots_undeclared_change and the
                    # sweep is treated as unpinned/unverified
                    # (fail-closed). Events ride the chained audit
                    # log (self.log). Inside the try: a bad envelope
                    # is audited as artifact_sweep_failed like any
                    # other sweep failure (never raises).
                    roots_verdict = _artifact_sweep.\
                        check_roots_declaration(
                            watch_roots, roots_decl,
                            audit=lambda ev: self.log.append(ev),
                            run_id=self.run_id)["verdict"]
            findings, stats = _artifact_sweep.sweep_run_dir(
                self.run_dir, self.artifacts, watch_roots=watch_roots)
        except Exception as e:  # noqa: BLE001 - sweep must not break runs
            self.log.append({
                "event": "artifact_sweep_failed",
                "flag": "unregistered_artifact",
                "run_id": self.run_id,
                "reason": ("artifact sweep failed: %s: %s"
                           % (type(e).__name__, e)),
            })
            return []
        for f in findings:
            self.log.append({
                "event": _artifact_sweep.SWEEP_FINDING_EVENT,
                "flag": "unregistered_artifact",
                "run_id": self.run_id,
                "kind": f["kind"],
                "root": f.get("root"),
                "path": f["path"],
                "size": f["size"],
                "sha256": f["sha256"],
                "mtime": f["mtime"],
                "detail": f["detail"],
                # Only present on integrity_violation: the evidence of
                # what the bytes changed FROM.
                "registered_sha256": f.get("registered_sha256"),
            })
        self.log.append({
            "event": _artifact_sweep.SWEEP_COMPLETE_EVENT,
            "run_id": self.run_id,
            "files_seen": stats["files_seen"],
            "files_compared": stats["files_compared"],
            "findings": stats["findings"],
            "skipped_unreadable": stats["skipped_unreadable"],
            "watch_roots": [w["root"] for w in stats["watch_roots"]],
            # Wave-143: declaration-enforcement verdict. "declared" =
            # the effective roots matched the last ceremony;
            # "undeclared" = no declaration configured (explicit
            # downgrade); "undeclared_change" / "unverifiable" = LOUD
            # artifact_sweep_roots_undeclared_change emitted, the
            # sweep is NOT verified against a declaration and must
            # never be read as a declared-roots sweep.
            "roots_verdict": roots_verdict,
            "roots_verified": roots_verdict == "declared",
        })
        return findings

    def _maybe_run_artifact_sweep(self):
        """Automatic post-run sweep hook for ``execute_approved()``.

        Runs only when the ``artifact_sweep`` opt-in was installed at
        construction (None/False = zero behavior change). The sweep needs no
        queue state, so it runs after the queue lock is released.
        """
        if not self.artifact_sweep:
            return
        self.run_artifact_sweep()

    def _intent_slice_verdict(self, tool, args, justification, identity):
        """Wave-129: run the intent-slice judge for a candidate queued
        action. Returns the verdict dict, or None when no intent
        context is set. Never raises: the judge must never break
        queueing (failures degrade to None, i.e. unstamped)."""
        try:
            if not self._intent_user_turns:
                return None
            prior = self._recent_action_steps(limit=20)
            return _intent_slice.judge_queued_action(
                tool=tool,
                args=args,
                justification=justification,
                user_turns=self._intent_user_turns,
                prior_actions=prior)
        except Exception:  # noqa: BLE001 - judge never breaks queueing
            return None

    def _build_provenance_segments(self, justification, identity):
        """Wave-317: the provenance-segment PRODUCER. Origin-grade the
        influencing context this call carries and seal each segment at
        ingestion (trusted infrastructure seals; agents never grade).

        Sources (executor-held context only):
          - each operator user turn (set_intent_context): origin
            ``user`` (USER=100), principal ``user``;
          - the agent's ``justification`` framing kwarg (when
            non-empty): origin ``tool`` (TOOL=50), principal the
            calling agent_id. Agent-authored prose can never alone
            satisfy USER-trust egress -- the honest grade for agent
            framing. A missing agent_id falls back to the literal
            principal ``"unknown-agent"`` (never to a user-graded
            principal); a whitespace-only justification carries no
            framing content and counts as no context.

        Segment ids are content-derived (``pv-`` + sha256 of
        origin|principal|content, truncated) so the sink's ctx_key --
        and therefore the F399 REPLAN_BUDGET ratchet -- accumulates on
        genuine same-context retries instead of resetting on random
        ids. The label nonce stays random per issue (seal freshness);
        only the id is deterministic.

        Returns a list of segment dicts (JSON-native, to_dict form),
        or None when there is no provenance context -- the sweep's
        None-skip then keeps behavior unchanged. Never raises: a
        producer failure degrades to None (the pre-wave-317 dormant
        behavior), never to an unsealed or forged segment -- and the
        degradation is audit-visible via a
        ``provenance_producer_degraded`` event, so a broken sealer
        cannot silently return the sink to dormancy."""
        try:
            segments = []
            turns = self._intent_user_turns or []
            for turn in turns:
                if not isinstance(turn, str) or not turn:
                    continue
                segments.append(self._seal_segment(
                    "user", "user", turn))
            if isinstance(justification, str) and justification.strip():
                principal = getattr(identity, "agent_id", None) \
                    or "unknown-agent"
                segments.append(self._seal_segment(
                    "tool", str(principal), justification))
            if not segments:
                return None
            return [s.to_dict() for s in segments]
        except Exception as exc:  # noqa: BLE001 - producer never breaks queueing
            # A producer failure degrades to None (the pre-wave-317
            # dormant posture -- the standard policy engine still gates
            # the call) but must never be SILENT: the loss of the
            # provenance layer is audit-visible.
            try:
                self.log.append({
                    "event": "provenance_producer_degraded",
                    "run_id": self.run_id,
                    "reason": "segment sealing failed: %s"
                    % type(exc).__name__,
                })
            except Exception:
                pass
            return None

    def _seal_segment(self, origin, principal, content):
        """Seal one segment at ingestion: origin-grade it, issue the
        label, and give it its content-derived id."""
        label = _provenance_labels.issue_label(
            origin, principal, content)
        return _provenance_labels.Segment(
            segment_id=self._provenance_segment_id(
                origin, principal, content),
            label=label, content=content)

    @staticmethod
    def _provenance_segment_id(origin, principal, content):
        return "pv-" + hashlib.sha256(
            ("%s|%s|%s" % (origin, principal, content)).encode(
                "utf-8")).hexdigest()[:16]

    def _provenance_grant_decision(self, tool, args, driving_units):
        """Wave-279 (F300) + wave-281 (F307): run the
        instruction-provenance grant seam for a candidate action.
        Returns ``(req, decision)`` -- the ``ActionRequest`` and the
        ``grant_check`` ``Decision`` -- or ``(None, None)`` when the
        seam is inert (no provenance context installed, or no units
        installed).

        Fail-closed, loud, never raises: routed decisions
        (``provlabel-*``) carry the full provenance chain for the
        approver; malformed framing degrades to a loud
        ``provlabel-malformed`` routed decision; an unexpected internal
        error is audit-chained best-effort and likewise degrades to a
        loud routed ``provlabel-malformed`` decision (the approver
        sees the failure -- a silent drop would hide it).

        Wave-281 (F307): the driving units are derived SERVER-SIDE
        from the operator-installed labeler -- never trusted from the
        agent's plan-trace kwarg verbatim. The agent's kwarg may only
        NARROW the installed set, and every narrowing is audit-logged
        (never silent). When the narrowed set no longer routes while
        the full installed set does, the plan trace dropped a
        routing-relevant driver (the plan-trace omission attack): the
        seam routes LOUD with ``provlabel-omitted-driver`` and the
        server-side provenance chain, so an installed
        injection-shaped driver can never be narrowed away silently.
        """
        if self._prov_labeler is None:
            return None, None
        labeler = self._prov_labeler
        installed = labeler.installed_unit_ids()
        if not installed:
            return None, None
        args_dict = args if isinstance(args, dict) else {}

        def _malformed(detail):
            req = _instruction_provenance.ActionRequest(
                tool, args_dict, True, ())
            decision = _instruction_provenance.Decision(
                False, True, "provlabel-malformed", detail)
            return req, decision

        def _grant(units):
            req = _instruction_provenance.ActionRequest(
                tool, args_dict, True, tuple(units))
            return req, _instruction_provenance.grant_check(req, labeler)

        try:
            if driving_units is None:
                # No plan-trace claim: the candidate driver set is the
                # full server-side installed set (F307 -- the agent
                # cannot dodge the seam by omitting the kwarg).
                claimed = installed
            else:
                if (not isinstance(driving_units, (list, tuple))
                        or not all(isinstance(u, str)
                                   for u in driving_units)):
                    return _malformed(
                        "provenance_driving_units framing was not a list of "
                        "unit-id strings (got %r); the plan trace is "
                        "unverifiable -- approval required"
                        % (type(driving_units).__name__,))
                claimed = tuple(driving_units)
            req_server, dec_server = _grant(installed)
            if set(claimed) == set(installed):
                req_agent, dec_agent = req_server, dec_server
            else:
                req_agent, dec_agent = _grant(claimed)
        except _instruction_provenance.ProvenanceError as e:
            return _malformed(
                "provenance seam input malformed: %s -- approval "
                "required" % (e,))
        except Exception as e:  # noqa: BLE001 - fail closed, loud
            try:
                self.log.append({
                    "event": "instruction_provenance_error",
                    "run_id": self.run_id,
                    "agent_id": "system",
                    "role": "system",
                    "decision": "error",
                    "policy_id": "instruction-provenance",
                    "reason": ("instruction-provenance seam raised "
                               "unexpectedly: %s" % (e,)),
                })
            except Exception:
                pass
            return _malformed(
                "provenance seam raised unexpectedly (%s: %s) -- "
                "approval required" % (type(e).__name__, e))

        if set(claimed) != set(installed):
            # The plan trace narrowed the server-side set. Logged and
            # auditable -- narrowing is never silent (F307 close-when).
            try:
                self.log.append({
                    "event": "instruction_provenance_narrowing",
                    "run_id": self.run_id,
                    "agent_id": "system",
                    "role": "system",
                    "tool": tool,
                    "decision": "narrowed",
                    "policy_id": "instruction-provenance",
                    "reason": (
                        "the plan trace narrowed the operator-installed "
                        "driver set (installed=%d, claimed=%d, omitted=%s); "
                        "server-side verdict %s, narrowed verdict %s"
                        % (len(installed), len(claimed),
                           sorted(set(installed) - set(claimed)),
                           dec_server.code, dec_agent.code)),
                })
            except Exception:
                pass
        if dec_server.routed_to_approval and not dec_agent.routed_to_approval:
            # F307: the narrowing dropped a routing-relevant driver --
            # the plan-trace omission attack. Route LOUD with the
            # server-side chain; never silently allow.
            decision = _instruction_provenance.Decision(
                False, True, "provlabel-omitted-driver",
                "the plan trace narrowed the operator-installed driver "
                "set and the narrowed set no longer routes while the "
                "full installed set does (omitted drivers: %s) -- an "
                "installed injection-shaped driver cannot be narrowed "
                "away silently; approval required"
                % (sorted(set(installed) - set(claimed)),),
                dec_server.provenance_chain)
            return req_server, decision
        return req_agent, dec_agent

    def _recent_action_steps(self, limit=20):
        """Wave-129: the run's recent tool calls as intent-slice steps,
        newest last, from the audit log (source of truth). Malformed or
        unreadable log -> empty list (the judge degrades gracefully)."""
        steps = []
        try:
            entries = read_entries(self.log.path)
        except Exception:  # noqa: BLE001 - degrade to no prior actions
            return steps
        for e in entries:
            if not isinstance(e, dict):
                continue
            if e.get("event") != "tool_call":
                continue
            if e.get("run_id") != self.run_id:
                continue
            steps.append({
                "kind": "agent_action",
                "tool": e.get("tool"),
                "args": e.get("args") or {},
                "agent_id": e.get("agent_id"),
            })
        return steps[-int(limit):]

    def _classification_taint_on_read(self, tool, args, result):
        """Row-13 closure: label-based provenance taint on read_file.

        If a successful read_file returned content from a
        classification-labeled path, taint the run with the label
        (max level wins) and record the source for provenance
        annotation. Called on the execution path after
        ``_ingest_result`` (direct calls and the approved sweep).

        Label-based, not content-based: the taint attaches to the
        read *event*, so paraphrase, restructuring, fragmentation, or
        semantic re-encoding of the content cannot shed it. Only
        fires when the read actually returned content (denied,
        queued, or refused reads taint nothing).
        """
        if tool != "read_file":
            return
        if not isinstance(result, dict) or not result.get("content"):
            return
        path = (args or {}).get("path")
        if not path:
            return
        try:
            rel = self._resolved_path_for_policy(path)
        except Exception:
            return
        level = self.classification.level_for(rel)
        if level is None:
            return
        prev = self._read_classification
        if prev is None or _classification.rank_of(level) > _classification.rank_of(prev):
            self._read_classification = level
        self._read_classification_sources.append((rel, level))
        try:
            self.log.append({
                "event": "classification_taint_set",
                "run_id": self.run_id,
                "path": rel,
                "level": level,
                "max_level": self._read_classification,
            })
        except Exception:
            pass

    def _rare_token_observe_on_read(self, tool, args, result, agent_id):
        """Row-13 (wave-141): automatically observe a real governed
        read's output in the rare-token tracker.

        Called at the single public execution seam after a tool call
        completes (and at the approved-sweep use-time re-execution),
        next to the classification-taint hook. Only fires on a
        successful ``read_file`` whose result is REAL sandbox bytes
        (``result["source"] == "sandbox"``, mirroring the lineage
        guard): synthetic content is never observed — the tracker
        must not learn tokens the agent never actually saw. Reads
        returning no content (denied, queued, refused, escaping)
        observe nothing.

        The auto source ID is ``read:auto:<sandbox-relative-path>``
        (resolved like every other path-keyed hook). An explicit
        ``note_read_output`` for the same document with the same ID
        REPLACES the auto observation — the tracker keys by
        (agent_id, source_id), so explicit + automatic is one
        observation, never a double count (the harness owns the ID
        contract; different IDs are different sources). The auto
        path emits NO audit event (log-spam control, privacy by
        construction): token strings never enter the chain from
        this seam; the tracker's in-memory token sets and the taint
        ledger's opaque commitments are the only stores, as before.

        Never raises and never breaks the read: on any trouble the
        observation is skipped (fail-open on observation — the read
        already succeeded and its bytes were returned; blocking a
        completed read is not a coherent control). The harness's
        explicit ``note_read_output`` keeps its fail-closed ledger
        semantics; the auto path is a best-effort tripwire, not a
        replacement for it. Direct filesystem access outside the
        governed API stays invisible by construction — the executor
        only sees what crosses its boundary.
        """
        if tool != "read_file":
            return
        tracker = getattr(self, "rare_token_tracker", None)
        if tracker is None:
            return
        if not (isinstance(result, dict) and result.get("content")):
            return
        # Real bytes only — never synthetic (mirrors the lineage
        # guard at the file-channel hook).
        if result.get("source") != "sandbox":
            return
        try:
            path = args.get("path") if isinstance(args, dict) else None
            if not path:
                return
            rel = self._resolved_path_for_policy(path) or str(path)
            tracker.observe_read(agent_id, "read:auto:%s" % rel,
                                 str(result["content"]))
        except Exception:
            pass

    def _propagation_observe_on_read(self, tool, args, result, agent_id):
        """Wave-152 (Row 19): automatically observe a real governed
        read's output in the injection-propagation tracker.

        Mirrors ``_rare_token_observe_on_read`` (wave-141) at the same
        call sites: a successful governed ``read_file`` whose result is
        REAL sandbox bytes (``result["source"] == "sandbox"``)
        observes itself into the installed ``PropagationTracker`` --
        the agent verifiably received the bytes through the governed
        tool boundary, so the tracker's propagation check must know
        about them. Synthetic content is never observed. Reads
        returning no content (denied, queued, refused, escaping)
        observe nothing.

        The auto source ID is ``read:auto:<sandbox-relative-path>``,
        exactly like the rare-token hook. The tracker keys by
        (agent_id, source_id), so an explicit
        ``note_propagation_input`` with the same ID replaces the auto
        observation (no double count); different IDs are different
        sources. The auto path emits NO audit event (log-spam
        control): the observed span only enters the chain if the agent
        later reproduces it and the LOUD triage event fires. Never
        raises and never breaks the read (fail-open on observation --
        the read already succeeded). Direct filesystem access outside
        the governed API stays invisible by construction -- the
        executor only sees what crosses its boundary (pinned
        EXPECTED, battery p11).
        """
        if tool != "read_file":
            return
        tracker = getattr(self, "propagation_tracker", None)
        if tracker is None:
            return
        if not (isinstance(result, dict) and result.get("content")):
            return
        # Real bytes only -- never synthetic (mirrors the lineage
        # guard at the file-channel hook).
        if result.get("source") != "sandbox":
            return
        try:
            path = args.get("path") if isinstance(args, dict) else None
            if not path:
                return
            rel = self._resolved_path_for_policy(path) or str(path)
            tracker.observe_input(agent_id, "read:auto:%s" % rel,
                                  str(result["content"]))
        except Exception:
            pass

    def _artifact_register_on_write(self, tool, args, result, agent_id):
        """Row-12: register a successful governed write in the
        artifact inventory.

        Called at the single public execution seam after a tool call
        completes (and at the approved-sweep use-time re-execution),
        next to the classification-taint hook. Only fires on a
        successful ``write_file``: result carries a real path (or a
        quarantine path for outside-sandbox/unexpected-target writes,
        which is inventoried under its actual location). The SHA-256
        is recomputed from the bytes ON DISK — never from the
        caller-supplied content — so a lie in ``content`` cannot
        register a false hash. Never raises and never breaks the write:
        on any trouble the artifact is simply not registered (fail-open
        on the inventory; the write itself already succeeded).
        """
        if tool != "write_file":
            return
        try:
            path = None
            if isinstance(result, dict):
                path = result.get("path")
            if not path:
                return
            rel = self._resolved_path_for_policy(path) or path
            real = self._lineage_real_path(path)
            sha, nbytes = self._lineage_file_digest(real)
            label = self.classification.level_for(rel)
            # F167 ordering: the audit event appends BEFORE the
            # in-memory registration, so a logging failure never
            # leaves a registered-but-unaudited artifact.
            self.log.append({
                "event": "artifact_registered",
                "run_id": self.run_id,
                "agent_id": agent_id,
                "path": rel,
                "sha256": sha,
                "bytes": nbytes,
                "classification": label,
            })
            self.artifacts.register(
                rel, sha256=sha, size=nbytes, agent_id=agent_id,
                run_id=str(self.run_id), classification=label)
        except Exception:
            pass

    # Designated file-reference fields per egress tool. The artifact
    # egress contract (Row-12) reads file references ONLY from these
    # fields (recursively): an arbitrary string that merely mentions
    # a filename is not an artifact egress. This bounds the FP
    # surface — see the c2_fp_phantom_path_clean probe.
    _ARTIFACT_REF_KEYS = {
        "send_email": ("attachments", "attachment"),
        "http_post": ("files", "file", "attachments", "attachment"),
        "api_call": ("file", "files", "attachments", "attachment",
                     "file_path", "filepath", "filename"),
    }

    def _artifact_file_refs(self, tool, args):
        """Extract candidate artifact file references from egress args.

        Returns a list of raw string candidates found under the
        tool's designated file-reference keys (recursively through
        lists/dicts). A candidate becomes a REAL reference only if it
        (a) exactly matches an inventory path, or (b) is path-shaped
        and resolves to an existing file inside the sandbox. Anything
        else is a phantom and is ignored (no FP on mere mentions).
        """
        keys = self._ARTIFACT_REF_KEYS.get(tool, ())
        if not keys or not isinstance(args, dict):
            return []
        # api_call carries its payload one level down (params={...});
        # the other egress tools take the fields at the top level.
        root = args.get("params") if tool == "api_call" else args
        if not isinstance(root, dict):
            return []
        found = []

        def _walk(value):
            if isinstance(value, str):
                found.append(value)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    _walk(item)
            elif isinstance(value, dict):
                for item in value.values():
                    _walk(item)

        for key in keys:
            if key in root:
                _walk(root[key])

        refs = []
        for cand in found:
            if not isinstance(cand, str) or not cand.strip():
                continue
            cand = cand.strip()
            # (a) exact inventory match — always a real reference.
            if self.artifacts.lookup(cand) is not None:
                refs.append(cand)
                continue
            # (b) path-shaped and resolves to a real sandbox file.
            if self._looks_like_path(cand) and self._resolves_to_file(cand):
                refs.append(cand)
        # De-duplicate, preserving order.
        seen = set()
        out = []
        for r in refs:
            if r not in seen:
                seen.add(r)
                out.append(r)
        return out

    @staticmethod
    def _looks_like_path(value):
        """Cheap path-shape test (no I/O)."""
        if "://" in value or value.startswith(("http:", "https:")):
            return False
        if "/" in value or "\\" in value:
            return True
        # Bare filename with an extension: report.txt, weights.bin.
        if "." in value and " " not in value and len(value) < 256:
            head, dot, tail = value.rpartition(".")
            if head and dot and 1 <= len(tail) <= 8 and tail.isalnum():
                return True
        return False

    def _resolves_to_file(self, value):
        """True iff the value resolves to an existing regular file
        inside the sandbox (I/O, fail-closed False)."""
        try:
            if self._is_outside_sandbox(value):
                return False
            real = self._lineage_real_path(value)
            return real.is_file()
        except Exception:
            return False

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
        if result is None:
            # Clean no-op boundary (unchanged).
            return
        # F168: production metering. Mint deterministic usage from the
        # NORMALIZED blob via the governed pure function — never from
        # caller-supplied anything (the foreign adapter's real call
        # args are not visible on this path, so args={}; an
        # adapter-asserted _usage on the input dict is never read, so a
        # compromised adapter cannot forge or deflate its meter) — and
        # accrue it on the RESULT path, exactly like the governed path.
        # Metering is deliberately OUTSIDE the taint fail-open block
        # below: the F168 defect was a silent 0-accrual, so metering
        # failures are loud by design, while taint ingestion keeps its
        # deliberate fail-open posture (the call already executed; the
        # signal is heuristic, like the native path's ledger
        # taint-mark). Opaque-only results (no text blob) accrue the
        # tool's base rate: the execution happened, the content is
        # invisible, the base is the honest minimum.
        metered_src = {"content": blob} if blob else {}
        self._accrue_result_usage(
            self._mint_result_usage(tool, {}, metered_src))
        if blob:
            try:
                # The dict handed to _ingest_result carries no _usage,
                # so its internal _accrue_result_usage reads 0 (a true
                # no-op): the loud accrual above is the single metering
                # event — no double-count.
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

    # -- S1-MEM: memory provenance firewall hooks (opt-in) ---------------

    def _actgate_disclosure(self):
        """Wave-173 lane 1 (TMA-NM act-time gate): the queue-time
        disclosure snapshot -- the run's current un-elevated memory
        reads, JSON-safe. None when the gate is not attached (zero
        behavior change); the empty list when attached but the run has
        no un-elevated reads."""
        ag = self._memory_actgate
        if ag is None:
            return None
        return ag.summarize(self.run_id)

    def _memory_session_scan(self, principal):
        """S1-MEM: once per (executor, principal), scan the memory ledger
        for untrusted, instruction-shaped entries recorded by earlier
        sessions. Flags are chained ``memory_session_flag`` events --
        detection, not denial (enforcement happens at read time). A
        tampered memory ledger fails closed and loud, like F17."""
        fw = self._memory_firewall
        if fw is None or not principal:
            return
        if principal in self._mem_scanned_principals:
            return
        self._mem_scanned_principals.add(principal)
        try:
            # Cross-session lineage: the lineage journal must also be
            # authenticated at session open -- a broken journal chain is
            # fail-closed and loud, never silently consulted.
            fw.verify_lineage_journal()
            flagged = fw.scan_at_session_open(principal)
        except LedgerUnverifiableError as e:
            self.log.append({
                "event": "memory_ledger_unverifiable",
                "run_id": self.run_id,
                "principal": principal,
                "decision": "denied",
                "policy_id": "memory-provenance-firewall",
                "flag": "memory_ledger_unverifiable",
                "reason": ("Refusing to act: the memory provenance "
                           "ledger cannot be authenticated: %s" % e),
            })
            raise
        for mem_key, reason in flagged:
            self.log.append({
                "event": "memory_session_flag",
                "run_id": self.run_id,
                "principal": principal,
                "mem_key": mem_key,
                "instruction_reason": reason,
                "decision": "flagged",
                "policy_id": "memory-provenance-firewall",
                "flag": "memory_session_flag",
                "reason": ("Session-open scan: memory entry %s was "
                           "recorded untrusted-derived and "
                           "instruction-shaped (%s) in an earlier "
                           "session; it will be quarantined on read."
                           % (mem_key, reason)),
            })

    def _memory_firewall_hook(self, tool, args, result,
                              agent_id, role, principal):
        """S1-MEM: route write_file/read_file on memory paths through the
        opt-in firewall. Called between execution and result ingestion so
        a quarantined read never pollutes the run's fingerprint store.
        ``memory_firewall`` None (the default) = immediate no-op."""
        fw = self._memory_firewall
        if fw is None or tool not in ("read_file", "write_file"):
            return
        raw_path = (args or {}).get("path")
        if not isinstance(raw_path, str):
            return
        # Sandbox-relative memory key (mirrors _resolve/_is_outside_sandbox).
        try:
            rp = self._resolve(raw_path).resolve()
        except OSError:
            rp = Path(os.path.abspath(str(self._resolve(raw_path))))
        try:
            rel = rp.relative_to(self._sandbox_resolved)
        except ValueError:
            return
        mem_key = fw.mem_key_for(rel.as_posix())
        if mem_key is None:
            return
        # First memory interaction of the session: run the session-open
        # scan so a poison planted by an earlier session is flagged in
        # the chain before any memory bytes are delivered.
        self._memory_session_scan(principal)
        if tool == "read_file":
            content = (result or {}).get("content")
            if not isinstance(content, str):
                return
            try:
                verdict, reason = fw.check_memory_read(
                    principal, mem_key, content)
            except LedgerUnverifiableError as e:
                self.log.append({
                    "event": "memory_ledger_unverifiable",
                    "run_id": self.run_id,
                    "agent_id": agent_id,
                    "role": role,
                    "principal": principal,
                    "tool": tool,
                    "mem_key": mem_key,
                    "decision": "denied",
                    "policy_id": "memory-provenance-firewall",
                    "flag": "memory_ledger_unverifiable",
                    "reason": ("Refusing to act: the memory provenance "
                               "ledger cannot be authenticated: %s" % e),
                })
                raise
            if verdict == "quarantine":
                self.log.append({
                    "event": "memory_quarantine",
                    "run_id": self.run_id,
                    "agent_id": agent_id,
                    "role": role,
                    "principal": principal,
                    "tool": tool,
                    "mem_key": mem_key,
                    "decision": "denied",
                    "policy_id": "memory-provenance-firewall",
                    "flag": "memory_quarantine",
                    "reason": ("Quarantined memory read: %s is %s; the "
                               "content was not delivered."
                               % (mem_key, reason)),
                })
                raise MemoryQuarantineError(
                    "memory read quarantined: %s (%s)"
                    % (mem_key, reason))
            # Wave-173 lane 1 (TMA-NM act-time gate): provenance-classify
            # every allowed governed read while the gate is attached, so
            # the run's un-elevated reads are known at queue time (the
            # disclosure) and at the approved sweep (the enforcement).
            # Uses the RAW content: the banner below is prepended to
            # result["content"] but the ledger digest binds the raw
            # bytes, and classification must bind the same bytes. A
            # tampered provenance ledger classifies un_elevated
            # (fail-closed toward the gate firing); the tamper itself
            # is chained LOUD here.
            if self._memory_actgate is not None:
                _ag_detail = self._memory_actgate.note_read(
                    self.run_id, principal, mem_key, content)[1]
                if _ag_detail == "provenance_unverifiable":
                    self.log.append({
                        "event": "memory_actgate_unverifiable",
                        "run_id": self.run_id,
                        "agent_id": agent_id,
                        "role": role,
                        "principal": principal,
                        "tool": tool,
                        "mem_key": mem_key,
                        "decision": "executed",
                        "policy_id": "memory-actgate",
                        "flag": "memory_actgate_unverifiable",
                        "reason": ("Memory provenance ledger unverifiable "
                                   "while classifying %s: treating the "
                                   "read as un-elevated (fail-closed)."
                                   % mem_key),
                    })
            # F143-hardening (wave-131, p3 factual-poison layer): allowed
            # reads of untrusted/unknown-tier bytes are delivered WITH
            # their provenance, never silently. The banner names the tier
            # and states factual claims are unverified; the warning is
            # chained so the delivery is auditable. Agent-tiered reads
            # are untouched (the agent's own notes are its business), and
            # operator release re-tiers to agent, lifting the banner.
            banner = fw.provenance_banner(principal, mem_key, content)
            if banner is not None:
                result["content"] = banner + content
                self.log.append({
                    "event": "memory_provenance_warning",
                    "run_id": self.run_id,
                    "agent_id": agent_id,
                    "role": role,
                    "principal": principal,
                    "tool": tool,
                    "mem_key": mem_key,
                    "decision": "executed",
                    "policy_id": "memory-provenance-firewall",
                    "flag": "memory_provenance_warning",
                    "reason": ("Delivered memory with provenance banner: "
                               "%s has no trusted provenance; factual "
                               "claims unverified." % mem_key),
                })
            return
        # write_file: tier, classify, and chain the provenance record for
        # the bytes actually written. The tier is computed from the run's
        # ingested tool-result fingerprints -- never from a caller kwarg.
        content = (args or {}).get("content", "")
        if not isinstance(content, str):
            content = str(content)
        try:
            _record, tier, shaping_reason = fw.record_memory_write(
                principal=principal,
                mem_key=mem_key,
                content=content,
                writer_agent_id=agent_id,
                writer_run_id=self.run_id,
                read_fingerprints=list(getattr(self, "_read_contents", [])),
                tainted_run=bool(getattr(self, "_tainted", False)))
        except LedgerUnverifiableError as e:
            # Cross-session lineage journal (or the memory ledger)
            # tampered: refuse the write rather than recording
            # provenance against untrusted lineage state (fail-closed,
            # loud -- never silently write with a broken chain).
            self.log.append({
                "event": "memory_ledger_unverifiable",
                "run_id": self.run_id,
                "agent_id": agent_id,
                "role": role,
                "principal": principal,
                "tool": tool,
                "mem_key": mem_key,
                "decision": "denied",
                "policy_id": "memory-provenance-firewall",
                "flag": "memory_ledger_unverifiable",
                "reason": ("Refusing to record memory write: provenance "
                           "ledger or lineage journal cannot be "
                           "authenticated: %s" % e),
            })
            raise
        # Detection surface: a chained action-log marker (no raw content)
        # alongside the hash-chained ledger record.
        self.log.append({
            "event": "memory_write_provenance",
            "run_id": self.run_id,
            "agent_id": agent_id,
            "role": role,
            "principal": principal,
            "tool": tool,
            "mem_key": mem_key,
            "trust_tier": tier,
            "instruction_shaped": shaping_reason is not None,
            "instruction_reason": shaping_reason,
            "decision": "executed",
            "policy_id": "memory-provenance-firewall",
            "flag": "memory_write_provenance",
            "reason": ("Memory provenance recorded: %s tiered %s%s."
                       % (mem_key, tier,
                          (" (instruction-shaped: %s)" % shaping_reason)
                          if shaping_reason else "")),
        })

    _FOREIGN_BLOB_MAX = 65536  # same cap as the native read path

    def _lineage_real_path(self, path):
        """Best-effort symlink-resolving path for lineage stamps.

        A write through a symlink must stamp the REAL file: otherwise a
        reader via the real path misses the stamp and the lineage
        breaks at exactly the hop the attacker chose. Mirrors the
        resolve discipline of _is_outside_sandbox."""
        p = self._resolve(path)
        try:
            return p.resolve()
        except OSError:
            return Path(os.path.abspath(str(p)))

    @staticmethod
    def _lineage_file_digest(real_path):
        """SHA-256 hex + byte count of the real file, read in chunks.

        Returns ``(None, 0)`` when the file cannot be read — the hook
        then stays silent rather than flagging bytes it could not see
        (fail-open on unreadable, fail-closed on identity)."""
        try:
            h = hashlib.sha256()
            n = 0
            with open(real_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
                    n += len(chunk)
            return h.hexdigest(), n
        except OSError:
            return None, 0

    def _lineage_file_hook(self, tool, args, result, agent_id):
        """S6 (wave-90, F137): raw-file-channel lineage interposition.

        Opt-in; immediate no-op when the tracker is None. Called
        between execution and result ingestion (mirroring
        _memory_firewall_hook) so stamps and contact records describe
        the bytes actually written/read:

        - write_file -> HMAC lineage stamp next to the written file
          (writer lineage, content hash, taint bit); the content hash
          also feeds the population-level replication watch.
        - read_file (real sandbox reads only) -> stamp lookup: contact
          recorded, taint propagated on infected stamps, forged stamps
          LOUD; unstamped files are informational, never refused.
        - delete_file -> the sidecar is removed with the file.

        Fail-open on stamp mechanics, fail-closed on identity: the
        call() gate already refused unlineaged identities, so a
        LineageError here would be an internal inconsistency — it
        propagates loud rather than being swallowed.
        """
        tracker = self._lineage_tracker
        if tracker is None or not isinstance(agent_id, str):
            return
        args = args or {}
        result = result or {}
        if tool == "write_file":
            raw_path = result.get("path") or args.get("path")
            if not isinstance(raw_path, str):
                return
            content = args.get("content", "")
            if not isinstance(content, str):
                content = str(content)
            content_b = content.encode("utf-8")
            sha = hashlib.sha256(content_b).hexdigest()
            tracker.stamp_write(agent_id, self._lineage_real_path(raw_path),
                                sha, len(content_b))
            tracker.observe_content(sha, agent_id, len(content_b))
        elif tool == "read_file":
            # Simulated reads have no real bytes: nothing to stamp.
            if result.get("source") != "sandbox":
                return
            raw_path = args.get("path")
            if not isinstance(raw_path, str):
                return
            real = self._lineage_real_path(raw_path)
            # Hash the ACTUAL file bytes, not the truncated tool
            # result: _simulate returns only the first 4000 chars,
            # while the write stamp covers the full content — hashing
            # the truncation would false-positive every long file as
            # forged. Chunked so large files stay cheap.
            sha, n = self._lineage_file_digest(real)
            if sha is None:
                return
            tracker.note_read(agent_id, real, sha, n)
            tracker.observe_content(sha, agent_id, n)
        elif tool == "delete_file":
            if result.get("deleted") and isinstance(args.get("path"), str):
                tracker.note_delete(
                    agent_id, self._lineage_real_path(args["path"]))
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
        # Wave-247: all host derivation goes through the shared
        # gov/uri_normalize canonicalizer, so the auth path and the
        # IoC path see the byte-identical host string (W246-4
        # divergence closed). Allowlist entries are normalized through
        # the same function, so unicode/punycode and trailing-dot
        # variants compare correctly. Explicit flips vs. pre-W247 are
        # pinned by evals/w247_uri_normalize_probes.py.
        from gov import uri_normalize as _un
        allow = (self.policy.egress or {}).get("domain_allowlist") or []
        host = None
        if tool == "http_post":
            try:
                host = _un.normalize_url_host(args.get("url") or "")
            except _un.UriNormalizeError:
                host = None
        elif tool == "send_email":
            to = args.get("to") or ""
            try:
                host = _un.normalize_email_host(to) if "@" in to else None
            except _un.UriNormalizeError:
                host = None
        elif tool == "api_call":
            # F94: api_call is egress-scoped like the other outbound
            # tools — its destination comes from the ``endpoint`` arg.
            try:
                host = _un.normalize_url_host(args.get("endpoint") or "")
            except _un.UriNormalizeError:
                host = None
        if not host:
            return False

        def _norm_allow(entry):
            try:
                return _un.normalize_host(entry)
            except _un.UriNormalizeError:
                return None

        return any(
            host == normed or host.endswith("." + normed)
            for entry in allow
            for normed in (_norm_allow(entry),)
            if normed
        )

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

    # -- F162 (HIGH): default-enforced tempo + fail-closed velocity -----

    def _tempo_cfg(self):
        """Effective tempo config: policy values over conservative
        defaults (F162: absent section = default-enforced, never
        disabled)."""
        cfg = dict(_DEFAULT_TEMPO)
        cfg.update(getattr(self.policy, "tempo", None) or {})
        return cfg

    def _velocity_cfg(self):
        """Effective cross-run velocity config: policy values over
        conservative defaults (F162: absent section no longer
        disables the guard)."""
        cfg = dict(_DEFAULT_VELOCITY)
        cfg.update(getattr(self.policy, "velocity", None) or {})
        return cfg

    def _rehydrate_tempo_pause(self):
        """F167: derive the tempo pause from the run's chained log.

        A rotated executor (the F60 fresh-executor-per-sweep deployment
        pattern) starts paused iff the latest ``velocity_paused`` /
        ``velocity_resumed`` record in the run's own chained log is a
        pause. The log is the deployment-owned, HMAC-chained substrate
        — no sidecar file, no new MAC plumbing, and no marker-file
        lifecycle (resume clears the pause automatically via its
        chained ``velocity_resumed`` record).

        Only entries carrying the log's own chain bookkeeping (integer
        ``seq``, string ``hash`` — keys the log sets and strips from
        caller input) are honored: malformed or planted lines are
        skipped, never trusted (F28/F52 convention). The agent cannot
        plant a resume: agent file writes are jailed to the sandbox,
        and forging a chained entry requires the deployment HMAC key.

        The scan reads the log file directly — never through the F163
        exchange-read policy check, which at construction time would
        mis-attribute the executor's own bookkeeping as a cross-run
        read. I/O trouble is best-effort (canary-marker precedent):
        the executor starts unpaused, and a truly unreadable log fails
        closed at the first append anyway. The scan only ever ADDS a
        pause; it cannot clear one (the flag starts False).
        """
        latest_paused = None
        try:
            path = Path(self.log.path)
            if not path.exists():
                return
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(entry, dict):
                    continue
                decision = entry.get("decision")
                if decision not in ("velocity_paused",
                                    "velocity_resumed"):
                    continue
                if not isinstance(entry.get("seq"), int):
                    continue
                if not isinstance(entry.get("hash"), str):
                    continue
                latest_paused = (decision == "velocity_paused")
        except (OSError, ValueError):
            # Best-effort like the canary marker: unreadable log ->
            # start unpaused (fail-closed surfaces at first append).
            # ValueError covers undecodable bytes (F28: never crash on
            # content) as well as malformed JSON handled above.
            return
        if latest_paused:
            self._tempo_paused = True

    def _check_tempo_paused(self, identity, tool):
        """Fail-closed sticky run pause. Raises VelocityRunPausedError
        (never returns a verdict) while the run is paused by a tempo
        trip. The pause is run-scoped: every identity is refused."""
        if self._tempo_paused:
            raise _velocity.VelocityRunPausedError(
                "run %r is paused by a velocity control (tempo trip or "
                "budget exhaustion): no tool calls execute until a "
                "human approves the filed resume request" % self.run_id)

    def _charge_tempo(self, identity, tool, audit_identity=None):
        """Charge one EXECUTION against the per-class tempo wire.

        Called at the two F33 execution boundaries (direct allow path
        and the approved-execution sweep). On trip: pause the run,
        chain the trip record, file a human ``velocity_resume``
        approval, and raise ``VelocityTempoTripError`` fail-closed.
        Tools outside the taxonomy are uncharged (documented residual).

        ``identity`` is the calling AgentIdentity on the call() path.
        On the approved-execution sweep there is no calling identity:
        pass None and ``audit_identity`` (a plain agent-info dict from
        the approval record) for the trip record; the pause still
        stands and resume then requires an operator-filed
        ``velocity_resume`` record (see resume_after_velocity_pause).
        """
        trip_msg = None
        try:
            self._tempo_wire.charge(tool)
            return
        except _velocity.VelocityTempoTripError as trip:
            # NOTE: the ``as`` target is deleted when the except block
            # exits (Python 3), so capture the message here.
            trip_msg = str(trip)
        cls = _velocity.action_class_of(tool)
        snapshot = self._tempo_wire.snapshot()
        cfg = self._tempo_cfg()
        _ai = audit_identity or {}
        trip_entry = {
            "event": "tool_call",
            "run_id": self.run_id,
            "agent_id": (identity.agent_id if identity is not None
                         else _ai.get("agent_id", "system")),
            "role": (identity.role if identity is not None
                     else _ai.get("role", "system")),
            "principal": (identity.principal if identity is not None
                          else _ai.get("principal", "system")),
            "tool": tool,
            "decision": "velocity_paused",
            "policy_id": "velocity-tempo",
            "flag": "velocity_tempo_trip",
            "matched_rules": [],
            "tempo_class": cls,
            "tempo_window_secs": cfg.get("window_secs"),
            "tempo_threshold": cfg.get("max_" + str(cls)),
            "tempo_windowed_count": snapshot.get(cls),
            "reason": ("Tempo tripwire fired: %s-class action rate "
                       "exceeds the deployment threshold; the run is "
                       "paused fail-closed. Resume requires a human "
                       "approval of a velocity_resume request."
                       % cls),
        }
        # F167: chain the trip record BEFORE setting the pause flag —
        # a rotated executor derives the pause from this record, so
        # memory and log must never diverge on an append failure.
        # Fail-closed propagation is preserved: the append error
        # raises and nothing executes.
        self.log.append(trip_entry)
        self._tempo_paused = True
        self._tempo_trip_class = cls
        # File the human re-approval demand. The record is a synthetic
        # action (tool "velocity_resume") so the approval queue's
        # separation-of-duties still applies: the agent can never
        # approve its own resume.
        aid = None
        if identity is not None:
            try:
                aid = self.approvals.queue(
                    {"tool": _VELOCITY_RESUME_TOOL,
                     "args": {"run_id": self.run_id,
                              "tempo_class": cls,
                              "threshold": cfg.get("max_" + str(cls)),
                              "window_secs": cfg.get("window_secs")},
                     "identity": identity.as_dict(),
                     "agent_justification": None,
                     "redactions": []},
                    PolicyDecision(
                        "require_approval",
                        "Velocity tripwire paused run %r: human review "
                        "required before the run may resume."
                        % self.run_id,
                        policy_id="velocity-tempo",
                        flag="velocity_tempo_trip"),
                    "agent_direct",
                    "resume run %r after velocity tempo trip (%s class)"
                    % (self.run_id, cls),
                    caller_identity=identity,
                    delegation_receipt=self._session_delegation_receipt())
            except Exception:
                # The pause stands even if queueing the resume request
                # fails: fail closed, never warn-and-continue. The trip
                # record above is the audit trail; the operator files a
                # manual velocity_resume request to resume.
                aid = None
        self._tempo_resume_aid = aid
        raise _velocity.VelocityTempoTripError(trip_msg)

    def resume_after_velocity_pause(self, approval_id):
        """Resume a tempo-paused run after HUMAN re-approval.

        Two shapes, both fail-closed:
        * call()-path trip: the executor auto-filed a
          ``velocity_resume`` record — ``approval_id`` must be that
          record.
        * approved-sweep trip (no auto-filed record): ``approval_id``
          must be an operator-filed record with
          ``tool == "velocity_resume"`` and
          ``args.run_id == this run``.
        In both cases the record must have ``status == "approved"`` (a
        human decision via ``ApprovalQueue.decide`` — the requesting
        agent can never self-approve) and be unconsumed; it is then
        consumed single-use. Anything else raises and the run stays
        paused.
        """
        if not self._tempo_paused:
            raise _velocity.VelocityError(
                "run %r is not paused by a velocity control" % self.run_id)
        rec = self.approvals.get(approval_id)
        if rec is None:
            raise _velocity.VelocityError(
                "resume refused: approval %r not found" % (approval_id,))
        if self._tempo_resume_aid is not None:
            if approval_id != self._tempo_resume_aid:
                raise _velocity.VelocityError(
                    "resume refused: %r is not this pause's "
                    "velocity_resume approval" % (approval_id,))
        else:
            if rec.get("tool") != _VELOCITY_RESUME_TOOL:
                raise _velocity.VelocityError(
                    "resume refused: approval %r is not a "
                    "velocity_resume request" % (approval_id,))
            if (rec.get("args") or {}).get("run_id") != self.run_id:
                raise _velocity.VelocityError(
                    "resume refused: velocity_resume approval %r is for "
                    "another run" % (approval_id,))
        if rec.get("status") != "approved":
            raise _velocity.VelocityError(
                "resume refused: velocity_resume approval %r is not "
                "human-approved (status %r)"
                % (approval_id, rec.get("status")))
        if rec.get("executed"):
            raise _velocity.VelocityError(
                "resume refused: velocity_resume approval %r already "
                "consumed" % (approval_id,))
        self.approvals.mark_executed(approval_id)
        # F167: chain the resume record BEFORE clearing the pause flag —
        # a rotated executor derives the pause from this record, so
        # memory and log must never diverge on an append failure (the
        # run stays paused, fail-closed, and the operator files a fresh
        # resume demand).
        self.log.append({
            "event": "tool_call",
            "run_id": self.run_id,
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": _VELOCITY_RESUME_TOOL,
            "decision": "velocity_resumed",
            "policy_id": "velocity-tempo",
            "flag": "velocity_resumed",
            "matched_rules": [],
            "approval_id": approval_id,
            "reason": ("Run resumed after human approval of the "
                       "velocity_resume request (F162)."),
        })
        self._tempo_paused = False
        self._tempo_resume_aid = None
        # The human reviewed the burst and authorized continuation:
        # the tripped class starts a fresh window (otherwise the very
        # next call would re-trip inside the still-hot window and the
        # resume would be useless).
        self._tempo_wire.reset(self._tempo_trip_class)
        self._tempo_trip_class = None
        return {"status": "resumed", "approval_id": approval_id}

    def _mint_result_usage(self, tool, args, result):
        """Attach deterministic synthetic usage to an executed result.

        S2-GAP-1 wiring: usage is minted by the GOVERNED side from the
        result (never from call kwargs), so the agent cannot forge or
        deflate its meter. Overwrites any pre-existing ``_usage`` key.
        """
        if not isinstance(result, dict):
            return result
        usage = _velocity.mint_usage(tool, args, result)
        budgets = getattr(self.policy, "budgets", None) or {}
        usage["spend"] = _velocity.spend_for(
            usage["tokens"], budgets.get("price_per_1k_tokens", 0.0))
        result["_usage"] = usage
        return result

    def _accrue_result_usage(self, result):
        """Accrue result-path usage into the per-run meter (S2-GAP-1).

        Called from ``_ingest_result`` / ``ingest_foreign_result`` —
        the RESULT path only. A forged ``_usage`` in CALL kwargs never
        reaches here (``_mint_result_usage`` overwrites it).
        """
        usage = (result.get("_usage") if isinstance(result, dict)
                 else None) or {}
        try:
            tokens = int(usage.get("tokens", 0) or 0)
        except (TypeError, ValueError):
            tokens = 0
        try:
            spend = float(usage.get("spend", 0.0) or 0.0)
        except (TypeError, ValueError):
            spend = 0.0
        if tokens < 0:
            tokens = 0
        if spend < 0:
            spend = 0.0
        self._tokens_used += tokens
        self._spend_used += spend

    def _budget_meter(self):
        """Current per-run meter snapshot for chained entries."""
        return {"tokens_used": self._tokens_used,
                "spend_used": round(self._spend_used, 6),
                "budget_actions": self._budget_actions}
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
        configured window. F162: FAIL-CLOSED on ANY ledger trouble
        (lock timeout, unverifiable ledger, I/O error) — an
        unverifiable ledger must never read as "no velocity". On
        trouble the call is routed to human review (returns True, so
        the ``approval-velocity-guard`` rule queues it) with a loud
        ``velocity_check_failed`` audit entry. Returns False (not
        exceeded) when no ledger history exists yet. The velocity:
        section is default-enforced (conservative thresholds), never
        silently disabled.
        """
        velocity = self._velocity_cfg()
        if not principal:
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
            # F162: fail CLOSED, loud. The ledger is unverifiable, so
            # the call is treated as velocity-exceeded: the
            # approval-velocity-guard rule queues it for human review
            # instead of letting it proceed silently. An unverifiable
            # ledger must never read as "no velocity".
            try:
                self.log.append({
                    "event": "tool_call",
                    "run_id": self.run_id,
                    "agent_id": "system",
                    "role": "system",
                    "principal": principal,
                    "decision": "velocity_check_failed",
                    "policy_id": "velocity-guard",
                    "flag": "velocity_check_failed",
                    "reason": ("Cross-run velocity check FAILED CLOSED: "
                               "%s: %s. The call is routed to human "
                               "review (velocity_exceeded=True) because "
                               "an unverifiable ledger must never read "
                               "as 'no velocity'."
                               % (type(e).__name__, e)),
                })
            except Exception:
                pass
            return True

    def _record_velocity(self, tool, principal, agent_id, egress_bytes):
        """Record one execution of a velocity tool in the cross-run ledger.

        Called at the two F33 execution boundaries (direct-allow and
        approved execution). ``EgressLedger.append`` holds the F74 write
        lock across its whole read-modify-write — S5 adds no second
        lock. Fail-OPEN with a loud ``velocity_check_skipped`` audit
        entry on ledger trouble: the call already executed, so a ledger
        outage must not break the result path — but the missing memory
        must be audit-visible. The velocity: section is
        default-enforced (F162): cross-run memory is kept unless the
        deployment explicitly zeroes every threshold.
        """
        velocity = self._velocity_cfg()
        if not any((velocity.get("max_sends"), velocity.get("max_writes"),
                    velocity.get("max_egress_bytes"))):
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

    def _record_upload(self, tool, redacted_args, principal, agent_id,
                       response_urls=(), content_hashes=None):
        """F139/F140: cross-run upload memory for citation provenance.

        Called at the two execution boundaries for every EXECUTED
        upload-shaped call (direct-allow and approved execution).
        Appends a ``kind: "upload"`` record {url, url_normalized,
        payload_sha256_prefix, payload_bytes, principal, agent_id,
        tool, run_id, ts} to the cross-run EgressLedger, so a later
        ``verify_citation`` can correlate a cited URL with the upload
        that planted it -- within the run (via the chained log) and
        across runs (via this ledger).

        Upload-shaped tools (F140): http_post (url-bearing arg "url",
        payload arg "payload") and api_call (url-bearing arg
        "endpoint", payload arg "params"). For api_call the ledger
        stores the canonical params fingerprint computed the same way
        as the log index (``citation_provenance.
        canonical_params_fingerprint``), so writer and reader agree.

        F142: the record additionally carries ``response_urls``
        (resource URLs minted in the API response, captured at the
        execution boundary and indexed as aliases of this plant) and
        ``content_sha256_set`` (full sha256 digests of the params/
        payload string leaves, for content-keyed correlation).
        H3 (wave-117): ``content_hashes`` (hex digests) is now also
        populated for http_post -- hashed from the RAW payload at the
        execution boundary by the caller, because the redacted form is
        a {bytes, sha256_prefix} summary whose leaves are unrecoverable
        (the approved path recovers them from the MAC-bound approval
        record instead). Both fields are additive -- old readers ignore
        them.

        Uses the REDACTED args: the URL is an audit field (readable by
        design) and the payload is the {bytes, sha256_prefix} summary --
        the same posture as the chained log, so the ledger learns
        nothing the log does not already carry. Scope is upload-shaped
        calls only; send_email is unchanged (not URL-citable). No-op
        when there is no ledger. Fail-open with a loud
        ``upload_record_skipped`` audit entry on ledger trouble -- the
        call already executed, so a ledger outage must not break the
        result path, but the missing memory must be audit-visible.
        """
        if tool not in ("http_post", "api_call"):
            return
        ledger = self._ledger
        if ledger is None:
            return
        args = redacted_args or {}
        # H3 (wave-117): http_post content hashes arrive from the caller
        # (hashed at the execution boundary from the raw payload);
        # renamed so the api_call branch's local below does not shadow
        # the parameter.
        caller_content_hashes = content_hashes
        content_hashes = []
        if tool == "http_post":
            url = args.get("url")
            payload = args.get("payload")
            sha_prefix, nbytes = None, None
            if isinstance(payload, dict):
                sha_prefix = payload.get("sha256_prefix")
                nbytes = payload.get("bytes")
            # H3 (wave-117): content-keyed correlation backstop for
            # http_post -- the redacted payload is a {bytes,
            # sha256_prefix} summary with no string leaves, so the
            # caller hashes the raw payload at the execution boundary
            # (approved path: recovered from the MAC-bound approval
            # record). Deduped + sorted for deterministic records.
            content_hashes = sorted(set(
                h for h in (caller_content_hashes or [])
                if isinstance(h, str) and h))
        else:  # api_call: endpoint is URL-bearing; params carry the
            # payload (scrubbed dict in the redacted args, not a
            # summary) -- fingerprint the canonical form, and hash the
            # string leaves for F142 content-keyed correlation.
            url = args.get("endpoint")
            nbytes, sha_prefix = \
                _citation_provenance.canonical_params_fingerprint(
                    args.get("params"))
            content_hashes = _citation_provenance.payload_content_hashes(
                args.get("params"))
        entry = {
            "kind": "upload",
            "ts": time.time(),
            "run_id": self.run_id,
            "principal": principal,
            "agent_id": agent_id,
            "tool": tool,
            "url": url,
            "url_normalized":
                _citation_provenance.normalize_url(url),
            "payload_sha256_prefix": sha_prefix,
            "payload_bytes": nbytes,
            # F142: response-minted resource URLs (aliases of this
            # plant) and full content hashes of the payload's string
            # leaves (content-keyed correlation backstop).
            "response_urls": [u for u in (response_urls or [])
                              if isinstance(u, str)],
            "content_sha256_set": content_hashes,
        }
        try:
            # The write lock is held inside append (F74) -- no second
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
                    "decision": "upload_record_skipped",
                    "policy_id": "citation-provenance",
                    "flag": "upload_record_skipped",
                    "reason": ("Cross-run upload record skipped "
                               "(fail-open): %s: %s. The execution is not "
                               "reflected in cross-run upload memory; "
                               "citation correlation for this URL will be "
                               "run-log-only." % (type(e).__name__, e)),
                })
            except Exception:
                pass

    # Row-20 (wave-151 lane 2): read/write rendezvous (covert-channel
    # restriction escape, SwarmTraces class) -- triage tier, never
    # blocking. Called at the two execution boundaries AFTER the
    # executed call's audit entry is appended, so the IO record carries
    # the real audit event seq. Content-blind: records routing/metadata
    # only (host, byte counts), never params/bodies/slugs/response
    # text. Same-host write->read pairs emit a LOUD
    # `covert_channel_suspect` audit event (decision
    # flagged_for_review); ledger trouble degrades to a LOUD
    # `covert_channel_check_skipped` event (fail-open -- the execution
    # already happened). Queued-but-never-executed calls are not
    # checked: a queued write is not a rendezvous half.

    @staticmethod
    def _io_direction(tool, args):
        """Classify an executed host-egress call as a channel
        write/read. http_post is always a write. api_call is
        method-driven: GET/HEAD/OPTIONS read; POST/PUT/PATCH/DELETE
        write; a missing or unknown method with non-empty params is a
        write (params are outbound bytes in this engine's model -- see
        _egress_bytes_for); a missing method with empty params is a
        read (a bare fetch). Returns None when the call carries no host
        URL/endpoint (not a host egress call)."""
        if tool == "http_post":
            url = args.get("url")
        elif tool == "api_call":
            url = args.get("endpoint")
        else:
            return None
        if not url:
            return None
        if tool == "http_post":
            return "write"
        method = str(args.get("method") or "").upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return "read"
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return "write"
        return "write" if args.get("params") else "read"

    def _check_covert_channel(self, tool, args, result, principal,
                              agent_id, run_id, event_seq):
        """Row-20 rendezvous check at an execution boundary.

        Records one content-blind egress_io entry in the shared ledger
        (F74 lock discipline lives in the ledger methods), then -- for
        reads -- pairs it with the newest prior same-host write within
        IO_WINDOW_SECS / the last IO_MAX_SCAN IO entries. Each
        completed pair emits one LOUD `covert_channel_suspect` audit
        event keyed by the unique (write_event_id, read_event_id), so a
        second read-back of the same planted write is a second suspect
        event (a second exfil). Same-agent pairs are preferred;
        cross-agent pairs are reported separately (noisier by
        construction: two agents may legitimately share one SaaS API).
        The call itself is never blocked or queued by this check.
        """
        direction = self._io_direction(tool, args or {})
        if direction is None:
            return
        try:
            endpoint = (args.get("endpoint") if tool == "api_call"
                        else args.get("url"))
            host = registered_domain(endpoint or "")
            ts = time.time()
            # Honest byte counts on the RAW args at the boundary so DLP
            # redaction never reduces the count (same contract as
            # _egress_bytes_for's docstring). Values are counted, never
            # logged: the suspect event and the ledger entry carry only
            # the counts.
            bytes_out = self._egress_bytes_for(tool, args or {})
            try:
                bytes_in = len(json.dumps(result, sort_keys=True,
                                          default=str).encode("utf-8"))
            except Exception:
                bytes_in = 0
            self._ledger.record_egress_io(direction, endpoint or "",
                                          principal, agent_id, run_id,
                                          ts, bytes_out, bytes_in,
                                          event_seq)
            if direction != "read" or not host:
                return
            same, cross = self._ledger.io_rendezvous(host, agent_id, ts)
            for pair_kind, write in (("same_agent", same),
                                     ("cross_agent", cross)):
                if write is None:
                    continue
                self.log.append({
                    "event": "covert_channel_suspect",
                    "run_id": run_id,
                    "agent_id": agent_id,
                    "role": "agent",
                    "principal": principal,
                    "tool": tool,
                    "decision": "flagged_for_review",
                    "policy_id": "covert-channel-rendezvous",
                    "flag": "covert_channel_suspect",
                    "severity": "review",
                    "host": host,
                    "pair_kind": pair_kind,
                    "write_event_id": write.get("event_id"),
                    "read_event_id": event_seq,
                    "write_agent_id": write.get("agent_id"),
                    "read_agent_id": agent_id,
                    "write_ts": write.get("ts"),
                    "read_ts": ts,
                    "write_bytes_out": write.get("bytes_out"),
                    "write_bytes_in": write.get("bytes_in"),
                    "read_bytes_out": bytes_out,
                    "read_bytes_in": bytes_in,
                    # Triage-only heuristic: content-blind
                    # write->read rendezvous pairing, never a verdict.
                    "reason": ("Write->read rendezvous on %s within "
                               "%ds: %s write event %s (%s out / %s in "
                               "bytes) paired with %s read event %s "
                               "(%s out / %s in bytes). Heuristic, "
                               "content-blind, triage tier only -- "
                               "does not block or queue the call."
                               % (host, IO_WINDOW_SECS,
                                  pair_kind, write.get("event_id"),
                                  write.get("bytes_out"),
                                  write.get("bytes_in"), agent_id,
                                  event_seq, bytes_out, bytes_in)),
                })
        except Exception as e:
            # Fail open, LOUD: the execution already happened; audit
            # the missing check instead of breaking the result
            # (mirrors _record_upload's upload_record_skipped).
            try:
                self.log.append({
                    "event": "covert_channel_check_skipped",
                    "run_id": run_id,
                    "agent_id": "system",
                    "role": "system",
                    "principal": principal,
                    "tool": tool,
                    "decision": "check_skipped",
                    "policy_id": "covert-channel-rendezvous",
                    "flag": "covert_channel_check_skipped",
                    "reason": ("Read/write rendezvous check skipped "
                               "(fail-open): %s: %s. The execution is "
                               "not reflected in covert-channel IO "
                               "memory; a later read cannot pair with "
                               "this call." % (type(e).__name__, e)),
                })
            except Exception:
                pass

    def _context(self, tool, args, principal=None, record_ledger=True,
                 agent_id=None):
        ctx = {"api_calls": self.api_calls, "counters": dict(self.counters)}
        # Row-13 closure: classification-labeled provenance taint. True
        # once this run read classification-labeled content; the
        # approval-classified-egress policy rule gates subsequent
        # egress for human declassification review. Run-scoped.
        ctx["read_classified"] = self._read_classification is not None
        # Row-12: artifact-aware egress. For the outbound tools,
        # extract file references from the designated fields and check
        # each against the artifact inventory: unknown (never
        # registered), tampered (bytes changed since registration), or
        # restricted (registered + restricted label). The bytes are
        # re-hashed at every check (check-time AND the approved-sweep
        # use-time re-check, because _context is rebuilt there), so a
        # post-approval mutation cannot slip a stale registration past.
        # All False when no file reference is found: zero behavior
        # change for file-less egress. Signal computation never raises:
        # an internal error degrades to "no artifact signal" (fail-open
        # on the artifact layer only — the DLP, canary, and policy
        # layers still apply). Fail-closed here would deny all egress
        # on any artifact-layer bug; the artifact check is
        # defense-in-depth, not the primary boundary.
        ctx["artifact_unknown"] = False
        ctx["artifact_tampered"] = False
        ctx["artifact_restricted"] = False
        ctx["artifact_refs"] = []
        if tool in _SEND_TOOLS or tool == "api_call":
            try:
                for ref in self._artifact_file_refs(tool, args or {}):
                    rel = (self._resolved_path_for_policy(ref) or ref)
                    real = self._lineage_real_path(ref)
                    if not real.is_file():
                        continue  # phantom or deleted: no signal
                    try:
                        sha_now, _nbytes = self._lineage_file_digest(real)
                    except Exception:
                        sha_now = None
                    verdict = self.artifacts.check_egress(
                        rel, sha256_now=sha_now,
                        current_label=self.classification.level_for(rel))
                    ctx["artifact_refs"].append({
                        "path": verdict.get("path"),
                        "status": verdict["status"],
                        "flag": verdict["flag"],
                    })
                    if verdict["status"] == "unknown":
                        ctx["artifact_unknown"] = True
                    elif verdict["status"] == "tampered":
                        ctx["artifact_tampered"] = True
                    elif verdict["status"] == "restricted":
                        ctx["artifact_restricted"] = True
            except Exception:
                pass
        if "path" in args:
            ctx["path_outside_sandbox"] = self._is_outside_sandbox(args["path"])
            # F146 (PaperCut class): the symlink-resolved target of the
            # declared path, sandbox-relative when inside. Policy._matches
            # evaluates path_contains_any against declared OR resolved
            # (fail-safe OR). Set here, it flows to both check-time
            # evaluation (call) and use-time re-evaluation
            # (_execute_approved_locked) through this single seam.
            ctx["path_resolved"] = self._resolved_path_for_policy(args["path"])
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

    def _log_traversal_contained(self, tool, args, ctx, identity, cause):
        """F-RA3 (H2/H120): read-side traversal attempts are LOUD.

        When a ``read_file`` targets an escaping path (``cause ==
        "path_outside_sandbox"``) the read is fail-closed DENIED
        (wave-120: no content returned -- neither real outside bytes
        nor synthetic) and the denial is a first-class chained audit
        event. When the use-time symlink target check flips (``cause ==
        "symlink_target_changed"``, F147) the read is contained to
        synthetic content per F147's close-when, and the containment
        is the chained event. Missing-file in-sandbox reads stay
        quiet: no traversal was attempted, so there is nothing to
        flag.

        Best-effort with a stderr fallback (the denial/containment
        already happened; the event is the audit signal, not the
        control) -- mirrors the credential_binding_unenforced
        convention.

        Exactly-once per (agent, tool, path, cause): the wave-120
        policy seam (quarantine-outside-reads) and the _simulate seam
        (approved sweep / direct use) both call here; the first call
        emits, later ones are suppressed.
        """
        if isinstance(identity, dict):
            agent_id = identity.get("agent_id")
            role = identity.get("role")
            principal = identity.get("principal")
            run_id = identity.get("run_id", self.run_id)
        else:
            agent_id = getattr(identity, "agent_id", None)
            role = getattr(identity, "role", None)
            principal = getattr(identity, "principal", None)
            run_id = getattr(identity, "run_id", None) or self.run_id
        # Exactly-once: the policy-quarantine seam and the _simulate
        # seam both report here; emit only the first per key.
        _tkey = (agent_id, tool, (args or {}).get("path"), cause)
        _emitted = self.__dict__.setdefault("_traversal_events_emitted",
                                            set())
        if _tkey in _emitted:
            return
        _emitted.add(_tkey)
        entry = {
            "event": "sandbox_traversal_contained",
            "run_id": run_id,
            "agent_id": agent_id,
            "role": role,
            "principal": principal,
            "tool": tool,
            "decision": "contained",
            "policy_id": "sandbox-traversal-containment",
            "cause": cause,
            "path": (args or {}).get("path"),
            "reason": (("read_file path %r escaped the sandbox: the read "
                        "was denied (F-RA3) -- no content returned"
                        % (args or {}).get("path"))
                       if cause == "path_outside_sandbox"
                       else ("read_file path %r resolved to a different "
                             "target between policy check and use (F147): "
                             "contained to synthetic content"
                             % (args or {}).get("path"))),
        }
        try:
            self.log.append(entry)
        except Exception as e:  # noqa: BLE001 - log best-effort; the
            # containment already happened. The stderr line is the
            # loud control.
            print("GOVERNANCE WARNING: sandbox_traversal_contained "
                  "audit entry could not be chained (%s: %s); the "
                  "read was still denied/contained."
                  % (type(e).__name__, e), file=sys.stderr)

    def _countersign_invocation(self, *, tool, executed_args_sentinel,
                                holder, challenge, approval_id, policy_id,
                                canonical_target, preview_text, result,
                                via, decision_seq=None):
        """Wave-175 lane 1: mint and chain a countersigned invocation receipt.

        Called AFTER the tool actually executed. ``executed_args_sentinel``
        is the sentinel-bearing args form (the same form the audit path
        records) — substituted secrets never enter the receipt. A signing
        failure is a loud ``invocation_receipt_failed`` event; the
        execution result stands (it cannot un-happen). Returns the chained
        log entry, or None when receipts are disabled.

        ``decision_seq`` (F196) is the audit seq of the decision entry this
        invocation answers; the receipt entry carries it so packet
        verification can pair packet<->receipt on
        (approval_id, decision_seq).
        """
        if self._receipt_key is None:
            return None
        try:
            body = _receipts.build_receipt(
                holder=holder or {},
                challenge=challenge,
                action_tool=tool,
                action_args=executed_args_sentinel,
                canonical_target=canonical_target,
                policy_decision="execution_authorized",
                approval_id=approval_id,
                policy_id=policy_id,
                preview_text=preview_text,
                outcome_status="executed",
                result=result,
                key_id=self._receipt_key["key_id"],
                pubkey_hex=self._receipt_key["pubkey_hex"])
            receipt = _receipts.countersign(body, self._receipt_key["seed"])
        except Exception as e:  # noqa: BLE001 - evidence only, fail loud
            self.log.append({
                "event": "invocation_receipt_failed",
                "run_id": self.run_id,
                "agent_id": (holder or {}).get("agent_id"),
                "role": (holder or {}).get("role"),
                "tool": tool,
                "approval_id": approval_id,
                "decision": "receipt_failed",
                "policy_id": "invocation-receipt-seam",
                "via": via,
                "reason": ("The invocation executed but its countersigned "
                           "receipt could not be minted (%s: %s); the "
                           "execution stands and is recorded without a "
                           "countersignature."
                           % (type(e).__name__, e)),
            })
            return None
        return self.log.append({
            "event": "invocation_receipt",
            "run_id": self.run_id,
            "agent_id": (holder or {}).get("agent_id"),
            "role": (holder or {}).get("role"),
            "tool": tool,
            "approval_id": approval_id,
            # F196: the decision entry this invocation answers, so packet
            # verification can pair packet<->receipt on
            # (approval_id, decision_seq).
            "decision_seq": decision_seq,
            "decision": "receipt_countersigned",
            "policy_id": "invocation-receipt-seam",
            "via": via,
            "receipt": receipt,
            "reason": ("Executor countersigned the executed invocation "
                       "(key %s)." % (self._receipt_key["key_id"],)),
        })

    def _invoke_simulate(self, tool, args, ctx, identity):
        """Call the ``_simulate`` seam, passing ``identity`` only when the
        installed callable accepts it.

        Wave-117/H2 added the ``identity`` kwarg to the seam so the
        executor's own ``_simulate`` can chain the
        ``sandbox_traversal_contained`` event. But ``_simulate`` is a
        documented drop-in point (``gov/sandbox.py::install``,
        test doubles in ``evals/``/``tests/``), and older drop-ins take
        only ``(tool, args, ctx)`` — passing the kwarg unconditionally
        broke them with ``TypeError`` (matrix sit52/57/88). The
        containment reporting itself travels via the
        ``traversal_contained`` result marker, which the executor pops
        and logs with its own identity below — so a drop-in that
        ignores ``identity`` loses nothing.
        """
        sim = self._simulate
        try:
            params = inspect.signature(sim).parameters
        except (TypeError, ValueError):
            params = {}
        accepts_identity = (
            "identity" in params
            or any(p.kind == inspect.Parameter.VAR_KEYWORD
                   for p in params.values())
        )
        if accepts_identity:
            return sim(tool, args, ctx, identity=identity)
        return sim(tool, args, ctx)

    def _simulate(self, tool, args, ctx, identity=None):
        # Wave-35 (Docker CVE-2026-77179/79994 class): the
        # path_outside_sandbox verdict in ctx was computed at check
        # time. The filesystem can change between check and use
        # (symlink swap), so re-verify at USE time, fail-closed: a
        # mid-call change quarantines/denies rather than honoring the
        # stale verdict.
        use_outside = (ctx.get("path_outside_sandbox")
                       or ("path" in args
                           and self._is_outside_sandbox(args["path"])))
        # F147 (PaperCut TOCTOU): the path_resolved verdict in ctx was
        # computed at check time, and F146 evaluates path_contains_any
        # against it. A symlink flipped between the verdict and the
        # effect would let the use-time effect follow a target the
        # policy never evaluated. Bind the check-time resolved target
        # to the verdict: re-resolve at USE time and fail closed on
        # any mismatch -- quarantine/deny rather than honoring the
        # stale verdict. Absent path_resolved (non-executor callers,
        # e.g. offline replay) the recheck is skipped: no behavior
        # change.
        check_resolved = ctx.get("path_resolved")
        use_resolved = (self._resolved_path_for_policy(args["path"])
                        if "path" in args else None)
        target_changed = (check_resolved is not None
                          and use_resolved is not None
                          and check_resolved != use_resolved)
        # Bind the verified target to the effect: when the recheck
        # passes, operate on the resolved absolute path directly and
        # never traverse the declared symlink again -- a flip of the
        # declared link landing between the recheck and the effect
        # then cannot redirect it. (Without a check-time resolved
        # target, fall back to the legacy declared-path behavior: no
        # change.) Irreducible residual: a flip of a PARENT directory
        # component between the re-resolve and the effect is still a
        # race -- the window is one open syscall wide and covers only
        # the directory chain, no longer the declared link itself.
        bound_path = None
        if (not target_changed and check_resolved is not None
                and use_resolved is not None
                and not Path(use_resolved).is_absolute()):
            bound_path = self._sandbox_resolved / use_resolved
        if tool == "read_file":
            p = (bound_path if bound_path is not None
                 else self._resolve(args["path"]))
            if not use_outside and not target_changed and p.is_file():
                # F164 (HIGH): exchange-access guard on the agent read
                # path -- the two-phase pattern, exactly like the
                # gov.log seam. The ambient reader is bound by the
                # execution-boundary caller (call() / the approved
                # sweep) via bind_reader. Before-phase (n_entries=None):
                # policy + replay-tempo tripwire BEFORE any bytes are
                # touched. After-phase: full-trace size tripwire + the
                # extraction record. A denial raises
                # ExchangeAccessDenied: fail-closed, the agent never
                # receives the bytes (the simulated branch below
                # returns no real bytes, so it needs no guard).
                _exchange_ledger.check_exchange_read(str(p))
                text = p.read_text(encoding="utf-8")
                _exchange_ledger.check_exchange_read(
                    str(p), _exchange_entry_count(text))
                return {"source": "sandbox",
                        "content": text[:4000]}
            # F-RA3 (wave-120): an escaping read is FAIL-CLOSED -- no
            # synthetic content is returned. The traversal attempt stays
            # loud (chained sandbox_traversal_contained event, as since
            # H2), but the agent receives a refusal, not fabricated
            # data. Rationale: returning "[synthetic file contents]"
            # lets the agent act on fake data believing it read the real
            # file (integrity risk -- wrong-file sends, etc.). This
            # mirrors the write side: quarantine-outside-writes queues
            # the write and even an approved write is quarantined inside
            # the run dir; here quarantine-outside-reads queues the read
            # and even an approved execution (the approved sweep re-runs
            # _simulate) returns this refusal -- never real outside
            # bytes, never synthetic.
            # F147's contract is deliberately untouched: a mid-call
            # symlink-target flip (target_changed, not an escaping
            # declared path) still contains to synthetic content, per
            # F147's close-when. The discriminator is the CHECK-time
            # verdict: only a declared escaping path
            # (ctx["path_outside_sandbox"]) is denied. A use-time
            # outside resolution with an inside check-time verdict is
            # the F147 flip, not an F-RA3 escape. A missing file inside
            # the sandbox (not a traversal) stays quiet below.
            if ctx.get("path_outside_sandbox"):
                self._log_traversal_contained(
                    tool, args, ctx, identity,
                    cause="path_outside_sandbox")
                return {"refused": True,
                        "note": ("read_file path %r escapes the sandbox: "
                                 "denied (F-RA3); no content returned"
                                 % (args.get("path"),))}
            if target_changed:
                self._log_traversal_contained(
                    tool, args, ctx, identity,
                    cause="symlink_target_changed")
            return {"source": "simulated", "content": "[synthetic file contents]"}
        if tool == "write_file":
            content = args.get("content", "")
            if use_outside or target_changed:
                # Even approved, an outside-sandbox write never touches the real
                # path: it is quarantined inside the run directory. A
                # mid-call target change quarantines for the same reason:
                # the verdict authorized the check-time target, not this one.
                q = self.quarantine / Path(args["path"]).name
                q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text(content if isinstance(content, str) else str(content),
                             encoding="utf-8")
                note = ("outside sandbox; quarantined inside run dir"
                        if use_outside else
                        "symlink target changed between policy check and "
                        "use (F147); quarantined inside run dir")
                return {"path": str(q), "note": note}
            p = (bound_path if bound_path is not None
                 else self._resolve(args["path"]))
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content if isinstance(content, str) else str(content),
                         encoding="utf-8")
            return {"path": str(p),
                    "bytes": len(content if isinstance(content, str) else str(content))}
        if tool == "delete_file":
            p = (bound_path if bound_path is not None
                 else self._resolve(args["path"]))
            if not use_outside and not target_changed and p.is_file():
                p.unlink()
                return {"deleted": True, "path": str(p)}
            return {"deleted": False, "note": "simulated; no file touched"}
        if tool == "api_call":
            resp = {"status": 200, "synthetic": True,
                    "endpoint": args.get("endpoint"), "items_returned": 2}
            # F142: test seam -- mint a deterministic response-minted
            # resource URL when the caller supplies a client-chosen slug,
            # mirroring how real paste APIs mint URLs
            # (https://<host>/bins/<slug>). Lets the synthetic battery
            # exercise response-URL capture with no network.
            params = args.get("params")
            slug = params.get("slug") if isinstance(params, dict) else None
            if isinstance(slug, str) and slug:
                try:
                    host = urlparse(args.get("endpoint") or "").hostname
                except Exception:
                    host = None
                if host:
                    resp["resource_url"] = "https://%s/bins/%s" % (host, slug)
            return resp
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
                    caller_identity=identity,
                    delegation_receipt=self._session_delegation_receipt())
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

    @property
    def is_governed(self):
        """Whether this executor carries the full governed core
        (wave-84 + wave-85).

        True iff BOTH core components are installed: a policy_store
        owns the live engine (wave-84: governed policy-change events
        reach it) AND a delegation_context is bound (wave-74: the
        three-token identity gate). Either one missing means the
        construction was a declared ungoverned bypass (wave-85 refuses
        silent half-core construction), so the executor is not
        governed no matter which half is present. Deployments that
        require governed execution assert this is True.
        """
        return (self._policy_store is not None
                and self._delegation_context is not None)

    def _apply_advisory(self, decision, action, ctx, policy, identity,
                        tool, kwargs, audit_entry):
        """Run the opt-in advisory layer over a deterministic verdict.

        Builds the advisor input snapshot (args digest, never raw args),
        composes advisors monotonically, appends the Decision BOM audit
        entry, and returns the (possibly tightened) PolicyDecision.
        Any infrastructure failure here -- not advisor errors, which the
        composer handles -- fails closed and loud: an unaudited advisory
        state must never decide a call.
        """
        try:
            advisors = self._advisors or []
            if not advisors:
                return decision
            verified = getattr(policy, "verified_digest", None)
            if verified:
                policy_digest = "verified:" + str(verified)
            else:
                # Honest: without the digest-gate load this is a
                # version label, not a content binding.
                policy_digest = "version-label:" + hashlib.sha256(
                    str(getattr(policy, "policy_version",
                                "unversioned")).encode("utf-8")).hexdigest()
            args_digest = hashlib.sha256(
                json.dumps(kwargs, sort_keys=True, separators=(",", ":"),
                           default=repr).encode("utf-8")).hexdigest()
            content_signals = {
                k: bool(ctx.get(k)) for k in (
                    "carries_read_content", "read_sensitive",
                    "read_classified", "source_untrusted",
                    "domain_allowlisted")
            }
            adv_ctx = _advisory.AdvisoryContext(
                tool=tool, args_digest=args_digest,
                agent_id=identity.agent_id, role=identity.role,
                principal=identity.principal, run_id=identity.run_id,
                deterministic_effect=decision.effect,
                policy_version=str(getattr(policy, "policy_version",
                                           "unversioned")),
                policy_digest=policy_digest,
                content_signals=content_signals)
            events = []
            composer = _advisory.AdvisoryComposer(
                advisors, audit=events.append)
            composed = composer.compose(adv_ctx)
            # BOM sub-chain atomicity: the head read-update and the
            # advisory audit appends run under one lock so concurrent
            # call()s cannot fork prev_bom_digest linkage or interleave
            # another decision's BOM between a violation event and its
            # decision_bom record.
            with self._advisory_lock:
                for ev in events:
                    audit_entry(dict(ev, decision="advisory_signal",
                                     policy_id="advisory-layer"))
                bom = _advisory.DecisionBOM.build(
                    tool=tool, agent_id=identity.agent_id, role=identity.role,
                    principal=identity.principal, run_id=identity.run_id,
                    policy_version=adv_ctx.policy_version,
                    policy_digest=policy_digest,
                    deterministic_effect=decision.effect,
                    deterministic_policy_id=decision.policy_id,
                    composed=composed,
                    prev_bom_digest=self._advisory_bom_chain[0])
                self._advisory_bom_chain[0] = bom["bom_digest"]
                audit_entry({
                    "event": "decision_bom",
                    "decision": "advisory_record",
                    "policy_id": "advisory-layer",
                    "matched_rules": [],
                    "bom": bom,
                    "reason": ("Decision BOM: policy %r decided %s; advisory "
                               "composed to %s (%d advisor(s), %d "
                               "violation(s), %d error(s))."
                               % (adv_ctx.policy_version, decision.effect,
                                  composed.final_effect,
                                  len(composed.records),
                                  len(composed.violations),
                                  len(composed.errors))),
                })
            if composed.tightened():
                tightened_by = ", ".join(
                    r.name for r in composed.records
                    if r.note == "tightened")
                return PolicyDecision(
                    composed.final_effect,
                    "%s [advisory: tightened %s->%s by %s]" % (
                        decision.reason, decision.effect,
                        composed.final_effect, tightened_by),
                    policy_id=decision.policy_id,
                    flag=decision.flag,
                    matched_rules=list(decision.matched_rules))
            return decision
        except Exception as e:  # noqa: BLE001 - fail closed, loud
            audit_entry({
                "event": "advisory_failed_closed",
                "decision": "denied",
                "policy_id": "advisory-layer",
                "flag": "advisory_failed_closed",
                "matched_rules": [],
                "reason": ("Advisory layer failed (%s: %s); refusing "
                           "fail-closed rather than proceeding with an "
                           "unaudited advisory state."
                           % (type(e).__name__, e)),
            })
            return PolicyDecision(
                "deny",
                "Advisory layer failure: refusing fail-closed.",
                policy_id="advisory-layer",
                flag="advisory_failed_closed")

    def set_authority_boundary(self, boundary):
        """Install the operator-declared authority boundary (wave-176).

        ``boundary`` must be a gov.authority_proof.AuthorityBoundary
        (build with authority_proof.boundary_from_dict, which validates
        loudly). Pass None to return to advisory mode. The boundary is
        operator authority: the agent-facing paths never call this.
        """
        if boundary is not None and not isinstance(
                boundary, _authority_proof.AuthorityBoundary):
            raise _authority_proof.BoundaryError(
                "set_authority_boundary expects an AuthorityBoundary or "
                "None, got %r" % type(boundary).__name__)
        self._authority_boundary = boundary

    def _surface_warn_digest(self, decision):
        """Aggregate warn-mode telemetry into per-window operator digests.

        Wave-198 (graduation ladder, R1 warn-fatigue): a warn-mode
        rule firing 1000x must produce ONE operator digest, not 1000
        agent interrupts. This hook records the decision's warnings in
        the per-rule-per-window aggregator and chains a ``warn_digest``
        audit entry for each window that rolled. The agent's verdict
        path is untouched -- warnings never reach the agent.

        Telemetry must never break the verdict path: any failure here
        is chained loudly as ``warn_digest_error`` (when a log is
        available) and swallowed, so the decision stands.
        """
        try:
            warnings = tuple(getattr(decision, "warnings", ()) or ())
            if not warnings:
                return
            agg = self._warn_digest_agg
            # Wave-198: the bucket key must match the mode ledger's
            # rule key. ``policy_id`` is the rule's raw "id" (None for
            # id-less rules, legacy compat); the ledger registers
            # id-less rules under the synthetic "rule-N" fallback,
            # which is also what ``deciding_rule.rule_id`` carries.
            # Deriving from diagnostics first keeps the digest
            # attributable to the same rule the ladder tracks.
            diag = getattr(decision, "diagnostics", None)
            deciding = getattr(diag, "deciding_rule", None)
            rule_id = (getattr(deciding, "rule_id", None)
                       or getattr(decision, "policy_id", None)
                       or "unknown")
            nominal = getattr(decision, "nominal_effect", None)
            due = []
            for w in warnings:
                due.extend(agg.record(rule_id=rule_id,
                                      nominal_effect=nominal,
                                      warning=w))
            due.extend(agg.flush_due())
            for digest in due:
                self._chain_warn_digest(digest)
        except Exception as e:
            try:
                if self.log is not None:
                    self.log.append({
                        "event": "warn_digest_error",
                        "decision": "warn_digest_error",
                        "error": "%s: %s" % (type(e).__name__, e),
                    })
            except Exception:
                pass

    def _check_ladder_escalations(self):
        """Route ladder escalations to the operator audit trail.

        Wave-198 (graduation ladder, §§3.4-3.5): two escalation
        conditions exist on the ladder, and both are operational --
        not just queryable:

        * warn-stale: a rule sitting in warn past WARN_MAX_DWELL_SECS
          chains a ``warn_stale`` audit entry (once per warn
          episode) so the operator inbox sees it.
        * emergency-review-overdue: an emergency demotion whose
          24h post-hoc review deadline passed chains an
          ``emergency_review_overdue`` entry (once per demotion).

        Called at the policy-decision seams alongside the warn
        digest hook. Telemetry must never break the verdict path:
        failures are chained loudly as ``ladder_escalation_error``
        (when a log is available) and swallowed.
        """
        try:
            ledger = getattr(getattr(self, "policy", None),
                             "mode_ledger", None)
            if ledger is None:
                return
            for rule_id in ledger.pop_stale_escalations():
                self.log.append({
                    "event": "warn_stale",
                    "decision": "warn_stale",
                    "policy_id": rule_id,
                    "note": ("rule %r sat in warn past the %ds max dwell: "
                             "route to operator review (graduate to deny "
                             "or demote to observe)"
                             % (rule_id,
                                _mode_ledger.WARN_MAX_DWELL_SECS)),
                })
            for pending in ledger.pop_overdue_emergency_reviews():
                self.log.append({
                    "event": "emergency_review_overdue",
                    "decision": "emergency_review_overdue",
                    "policy_id": pending.get("rule_id"),
                    "note": ("emergency demotion of %r by %r missed its "
                             "24h post-hoc review deadline: re-escalating"
                             % (pending.get("rule_id"),
                                 pending.get("operator"))),
                })
        except Exception as e:
            try:
                if self.log is not None:
                    self.log.append({
                        "event": "ladder_escalation_error",
                        "decision": "ladder_escalation_error",
                        "error": "%s: %s" % (type(e).__name__, e),
                    })
            except Exception:
                pass

    def _chain_warn_digest(self, digest):
        """Chain one rolled warn-digest window as an operator entry."""
        # Wave-198 (SPIKE §3.3): the per-mode warning count accrues in
        # the ledger so graduation evidence includes warning volume.
        _ledger = getattr(self.policy, "mode_ledger", None)
        if _ledger is not None:
            _ledger.record_warnings(digest["rule_id"], digest["count"])
        self.log.append({
            "event": "warn_digest",
            "decision": "warn_digest",
            "policy_id": digest["rule_id"],
            "window_start": digest["window_start"],
            "window_end": digest["window_end"],
            "warn_count": digest["count"],
            "nominal_effect": digest["nominal_effect"],
            "warning_samples": digest["samples"],
            "note": ("warn-mode telemetry: %d warning(s) in window; "
                     "operator digest, not an agent interrupt"
                     % (digest["count"],)),
        })

    def flush_warn_digests(self):
        """Flush all open warn-digest windows (operator tooling).

        Chains one ``warn_digest`` audit entry per rule with pending
        warnings and returns the digests. Safe to call at run end or
        on an operator cadence; a no-warning state returns ().
        """
        due = self._warn_digest_agg.flush_all()
        for digest in due:
            self._chain_warn_digest(digest)
        return due

    def record_warning_ack(self, rule_id, *, operator):
        """Operator acknowledges a warn-mode rule's warnings.

        Wave-198: the public seam for the warn->deny graduation bar
        (``min_acknowledged``). Operators review chained
        ``warn_digest`` entries, then attest here; the ledger records
        the attestation. The operator name is recorded verbatim --
        the caller attests it names a human (R3).
        """
        _ledger = getattr(self.policy, "mode_ledger", None)
        if _ledger is None:
            raise RuntimeError(
                "no mode ledger on the policy engine; "
                "cannot record warning ack")
        _ledger.record_warning_ack(rule_id, operator=operator)
        self.log.append({
            "event": "warning_ack",
            "decision": "warning_ack",
            "policy_id": rule_id,
            "operator": operator,
            "note": ("operator-attested warning acknowledgement; "
                     "counts toward warn->deny graduation bar"),
        })
    def set_mcp_tool_registry(self, registry):
        """Install the keyset-attested MCP tool-annotation registry
        (wave-198 lane E).

        ``registry`` must be a mapping built by
        ``gov.mcp_annotations.build_tool_registry`` (exact
        ``server::tool`` keys over keyset-attested statements), or None
        to return to legacy MCP behavior. With a registry installed,
        the authority proof's MCP scope seam enforces each pair's
        attested ``required_scopes`` against the calling agent's
        verified identity-token claims (recorded at ``mint_identity``
        time); a scope miss fails closed as ``exceeds_boundary`` at
        both the pre-decision seam and the approved-sweep re-proof.
        The registry is operator authority: the agent-facing paths
        never call this.
        """
        if registry is not None and not isinstance(
                registry, collections.abc.Mapping):
            raise TypeError(
                "set_mcp_tool_registry expects a mapping built by "
                "gov.mcp_annotations.build_tool_registry or None, got "
                "%r" % type(registry).__name__)
        self._mcp_tool_registry = registry

    def set_grant_registry(self, registry):
        """Install the deployment-owned grant registry (wave-319 lane 1).

        ``registry`` must be a ``gov.grant_negotiation.GrantRegistry``
        (or None to return to no-grant behavior). With a registry
        installed, ``call()`` runs the advisory grant check after the
        deterministic policy verdict passes: a presented grant that
        fails verification refuses with its coded ``grantneg-*``
        refusal (tighten-only); absent registry, unregistered tool, or
        absent grant proceeds exactly as before. The registry is
        operator authority: the agent-facing paths never call this.
        """
        if registry is not None and not isinstance(
                registry, grant_negotiation.GrantRegistry):
            raise TypeError(
                "set_grant_registry expects a "
                "gov.grant_negotiation.GrantRegistry or None, got %r"
                % type(registry).__name__)
        self._grant_registry = registry

    def _mcp_token_claims_for(self, agent_id):
        """Return the recorded verified token claims for ``agent_id``.

        A defensive copy, or None when the agent minted no token (or
        the agent_id is unknown): scope-required MCP tools then fail
        closed at the authority seam. Never raises.
        """
        claims = self._mcp_token_claims.get(agent_id)
        if isinstance(claims, dict):
            return dict(claims)
        return None

    def _emit_decision_packet(self, *, decision, decision_seq, head_digest,
                              tool, redacted_args, policy_decision, policy,
                              policy_ctx_snapshot, identity,
                              skill_id=None, skill_attested_digest=None,
                              approval_id=None):
        """Wave-176 (OpenShell steal #2, constructive decision packet).

        Build, sign, and audit-chain the decision packet for one FINAL
        policy decision ("allow" | "deny" | "queue"; the caller maps
        require_approval -> queue). Additive: the packet composes
        existing bindings by digest (policy decision, preview) rather
        than re-binding them, and rides its own ``decision_packet``
        audit entry chained immediately under the decision's own entry
        (``head_digest`` = that entry's hash).

        Returns the appended audit entry, or None when packets are
        disabled (no key configured). A concurrent writer slipping an
        entry between the decision append and ours is handled by
        rebuild-once under the true head; a second slip raises LOUD --
        the seam never emits a packet that misstates its chain head.
        """
        if self._packet_key is None:
            return None
        _dp = _decision_packet
        _snap = (policy_ctx_snapshot
                 if isinstance(policy_ctx_snapshot, dict) else {})
        _boundary_declared = self._authority_boundary is not None
        _proof = _snap.get("authority_proof")
        # Memory act-gate tier for this decision: the run's un-elevated
        # reads at decision time (the disclosure digest binds the exact
        # list; the packet names the tier, not the contents).
        _disclosure = _snap.get("memory_provenance")
        _disclosure_list = (_disclosure if isinstance(_disclosure, list)
                            else [])
        if self._memory_actgate is None:
            _tier = "gate_not_attached"
        elif _disclosure_list:
            _tier = "un_elevated_reads_present"
        else:
            _tier = "no_un_elevated_reads"
        _mem_carriers = sorted({
            str(r.get("input_carrier")) for r in _disclosure_list
            if isinstance(r, dict) and r.get("input_carrier")})
        _preview_text = self._preview(tool, redacted_args)
        _head = head_digest
        # Wave-180 (Decision BOM): the digest-bound input list for this
        # decision. Built INSIDE the rebuild loop: on a concurrent-
        # writer rebuild the evidence head moves, and the BOM must name
        # the head the packet was actually built under (a stale BOM
        # head would trip the verifier's BOM<->packet consistency
        # check). Policy digest is the engine's policy_hash -- sha256
        # of the EXACT bytes parsed (F53 one-buffer rule), so an
        # auditor re-hashes the bundle to reconstruct. The approval
        # record digest is the HMAC the executor itself verified before
        # consuming the approval; an approval whose record cannot be
        # resolved FAILS CLOSED (BomError) -- the seam refuses to emit
        # a packet that silently drops approval provenance, and the
        # call fails rather than emitting weak evidence.
        from .approvals import approval_record_digest as _ard
        _policy_hash = getattr(policy, "policy_hash", None)
        for _attempt in (0, 1):
            _approval_record_digest = None
            if approval_id is not None:
                _approval_rec = (self.approvals.get(approval_id)
                                 if self.approvals is not None else None)
                if _approval_rec is None:
                    raise _decision_bom.BomError(
                        "approval %r has no resolvable record; refusing "
                        "to emit a decision packet without its digest"
                        % (approval_id,))
                try:
                    _approval_record_digest = _ard(_approval_rec)
                except Exception as e:
                    raise _decision_bom.BomError(
                        "approval record digest failed for %r: %s: %s"
                        % (approval_id, type(e).__name__, e))
            _bom_pins = {}
            if skill_id and skill_attested_digest:
                _bom_pins = {skill_id: skill_attested_digest}
            # Wave-198 (graduation ladder): thread the ladder
            # telemetry into the BOM. The ladder section is included
            # only when it carries information (a warn-mode decision,
            # warnings, or nominal != enforced); mode-absent deny
            # decisions keep byte-identical BOMs. The rule's chained
            # mode history is looked up by the deciding hit's rule id
            # (the same key the mode ledger records under).
            _ladder_kwargs = {}
            _pd_mode = getattr(policy_decision, "mode", "deny")
            _pd_nominal = getattr(policy_decision, "nominal_effect",
                                  None)
            _pd_warnings = tuple(
                getattr(policy_decision, "warnings", ()) or ())
            _deciding_hit = None
            _pdiag = getattr(policy_decision, "diagnostics", None)
            if _pdiag is not None:
                _deciding_hit = _pdiag.deciding_rule
            _history = ()
            if _deciding_hit is not None:
                _ledger = getattr(policy, "mode_ledger", None)
                if _ledger is not None:
                    # Fail closed, never silent: a BOM must never
                    # record an empty history when the decision
                    # rested on a real one (the ledger read is an
                    # in-memory lookup -- failure means something
                    # is deeply wrong).
                    try:
                        _history = _ledger.mode_history(
                            _deciding_hit.rule_id)
                    except Exception as e:
                        raise _decision_bom.BomError(
                            "ladder mode-history lookup failed for "
                            "rule %r: %s: %s -- refusing to build a "
                            "BOM that drops the mode history"
                            % (_deciding_hit.rule_id,
                               type(e).__name__, e))
            # Wave-198: the ladder section rides the BOM whenever the
            # decision's posture is ladder-shaped -- warn/observe
            # routing, warnings, nominal/effect split -- OR the
            # deciding rule has a graduation history. A rule that
            # graduated observe->warn->deny and now denies carries
            # its history so an auditor sees the deny was earned,
            # not just declared. Mode-absent rules (empty history)
            # stay byte-identical (P8).
            if (_pd_mode != "deny" or _pd_warnings
                    or (_pd_nominal is not None
                        and _pd_nominal != policy_decision.effect)
                    or _history):
                _ladder_kwargs = {
                    "decision_mode": _pd_mode,
                    "nominal_effect": _pd_nominal,
                    "decision_warnings": list(_pd_warnings),
                    "rule_mode_history": [dict(h) for h in _history],
                }
            _bom = _decision_bom.build_bom(
                policy_id=policy_decision.policy_id,
                policy_version=getattr(policy, "policy_version",
                                       "unversioned"),
                policy_digest=_policy_hash,
                evidence_head_digest=_head,
                principal={"agent_id": identity.agent_id,
                           "role": identity.role,
                           "principal": identity.principal,
                           "run_id": identity.run_id},
                pin_digests=_bom_pins,
                approval_id=approval_id,
                approval_record_digest=_approval_record_digest,
                **_ladder_kwargs)
            _body = _dp.build_decision_packet(
                decision=decision,
                boundary_declared=_boundary_declared,
                authority_proof=_proof if _boundary_declared else None,
                policy_id=policy_decision.policy_id,
                policy_version=getattr(policy, "policy_version",
                                       "unversioned"),
                matched_rules=policy_decision.matched_rules,
                policy_flag=policy_decision.flag,
                decision_digest=hashlib.sha256(
                    _dp.canonical_bytes(
                        policy_decision.to_dict())).hexdigest(),
                canonical_target=_snap.get("path_resolved"),
                preview_digest=hashlib.sha256(
                    str(_preview_text or "").encode("utf-8")).hexdigest(),
                capability_manifest_digest=skill_attested_digest,
                skill_id=skill_id,
                actgate_tier=_tier,
                actgate_disclosure_digest=hashlib.sha256(
                    _dp.canonical_bytes(
                        _disclosure_list)).hexdigest(),
                attachment_carriers=(_snap.get("attachment_carriers")
                                     or []),
                memory_carriers=_mem_carriers,
                evidence_head_digest=_head,
                identity={"agent_id": identity.agent_id,
                          "role": identity.role,
                          "principal": identity.principal,
                          "run_id": identity.run_id},
                approval_id=approval_id,
                decision_seq=decision_seq,
                policy_reason=policy_decision.reason,
                bill_of_materials=_bom,
                policy_bundle_digest=_policy_hash)
            _packet = _dp.sign_packet(_body, self._packet_key["seed"])
            _entry = self.log.append({
                "event": "decision_packet",
                "run_id": identity.run_id,
                "agent_id": identity.agent_id,
                "role": identity.role,
                "principal": identity.principal,
                "tool": tool,
                "decision": decision,
                "decision_seq": decision_seq,
                "approval_id": approval_id,
                "packet_digest": _dp.packet_digest(_packet),
                "packet": _packet,
                "policy_id": "decision-packet-seam",
            })
            if _entry.get("prev_hash") == _head:
                return _entry
            # Another writer appended between the decision entry and
            # ours: rebuild once under the TRUE head (the prev_hash the
            # log actually chained us under). The stale packet's entry
            # stays in the chain and fails linkage honestly -- it is not
            # rewritten.
            _head = _entry.get("prev_hash")
        raise _dp.PacketError(
            "decision_packet emission: the evidence chain moved twice "
            "under the packet; refusing to emit a stale-head packet")

    def call(self, identity, tool, **kwargs):
        """Run one tool call through the governance pipeline."""
        if not isinstance(identity, AgentIdentity):
            raise TypeError("identity must be an AgentIdentity minted by "
                            "this executor, got %r" % type(identity).__name__)

        # Wave-319 (grant negotiation): reserved kwarg carrying a
        # presented grant (a dict, or a list of dicts forming a
        # delegation chain). Popped BEFORE tool-arg processing so it
        # never reaches the tool implementation. No "grant" string
        # exists anywhere else in this module, so there is no
        # collision with a tool argument.
        _presented_grant = kwargs.pop("grant", None)

        # Wave-100 (Stream 1): the capability gate -- before anything
        # agent-influenced runs. No valid assessment, no execution.
        self._check_capability_gate(
            agent_id=identity.agent_id, role=identity.role,
            principal=identity.principal, tool=tool,
            run_id=identity.run_id)

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

        # Wave-89 (S2): lineage quarantine, checked on the verdict path
        # before anything agent-influenced runs -- mirrors the recovery
        # halt above. A quarantined identity is denied every tool call
        # (sticky, like the halt): quarantine is containment, and
        # containment must not depend on the agent's cooperation. The
        # bus lives in the operator trust domain; a missing bus means
        # pre-wave-89 behavior (zero behavior change when opt-out).
        if self._message_bus is not None and \
                self._message_bus.is_quarantined(identity.agent_id):
            self.log.append({
                "event": "tool_call",
                "run_id": identity.run_id,
                "agent_id": identity.agent_id,
                "role": identity.role,
                "principal": identity.principal,
                "tool": tool,
                "decision": "denied",
                "policy_id": "lineage-quarantine",
                "flag": "quarantine_denied",
                "policy_version": getattr(policy, "policy_version",
                                          "unversioned"),
                "matched_rules": [],
                "reason": ("Refusing to act: identity %r is quarantined "
                           "(lineage quarantine); contained agents cannot "
                           "execute" % identity.agent_id),
            })
            from .messaging import QuarantineDeniedError
            raise QuarantineDeniedError(
                "identity %r is quarantined (lineage quarantine)" %
                identity.agent_id)

        # Wave-90 (S6, F137): mandatory infection lineage. When a
        # lineage tracker is installed, the acting identity must
        # resolve to the run's genesis through birth records — an
        # unlineaged agent (fresh executor outside the spawn tree,
        # hand-rolled identity chain) is refused fail-closed and loud
        # BEFORE anything agent-influenced runs. Mirrors the recovery
        # halt / quarantine gates above. None = pre-wave-90 behavior,
        # zero behavior change.
        if self._lineage_tracker is not None and \
                not self._lineage_tracker.verify(identity.agent_id):
            self.log.append({
                "event": "lineage_unregistered",
                "run_id": identity.run_id,
                "agent_id": identity.agent_id,
                "role": identity.role,
                "principal": identity.principal,
                "tool": tool,
                "decision": "denied",
                "policy_id": "infection-lineage",
                "flag": "lineage_unregistered",
                "reason": ("Refusing to act: identity %r has no birth "
                           "certificate resolving to this run's lineage "
                           "genesis — unlineaged execution is refused "
                           "fail-closed" % identity.agent_id),
            })
            from .lineage import LineageError
            raise LineageError(
                "identity %r is unlineaged: no birth certificate for "
                "this run (fail closed)" % identity.agent_id)

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
        # Wave-279 (F300) + wave-281 (F307): the plan-trace contract for
        # the instruction-provenance seam -- content-unit ids from the
        # operator-installed IngressLabeler that drove this call.
        # Popped here so it never reaches tool args; unresolvable or
        # malformed ids route to approval (fail-closed), never to
        # silent execution. F307: the kwarg is ADVISORY ONLY -- the
        # seam derives the driver set server-side from the installed
        # labeler; the kwarg may only narrow (audit-logged), and
        # narrowing away a routing-relevant driver routes LOUD.
        prov_driving_units = kwargs.pop("provenance_driving_units", None)
        # Wave-279 (F300): run the instruction-provenance grant seam
        # EARLY, before the policy verdict dispatches. A routed
        # decision (provlabel-*) forces the action to the approval
        # queue even when the policy engine would allow it -- the
        # toxic-agent-flow shape is never silently executed. (None,
        # None) when the seam is inert: zero behavior change.
        prov_req, prov_decision = self._provenance_grant_decision(
            tool, kwargs, prov_driving_units)
        on_behalf_of = kwargs.pop("on_behalf_of", None)
        delegated_by = kwargs.pop("delegated_by", None)
        # Wave-92 (stream C): MCP server attribution is a framing hint
        # for skill verification, never a tool arg — popped here so it
        # never reaches DLP scanning, policy matching, or the tool.
        # The binding that makes it trustworthy is the deployment's
        # skill_mcp_map, not the kwarg's value: a lying kwarg can only
        # attribute to a deployment-mapped skill (fail-closed deny at
        # worst), never to an unpinned one.
        mcp_server = kwargs.pop("mcp_server", None)
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
                    self._delegation_context, identity, tool,
                    revocation_checker=self._revocation_checker)
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

        # Sentinel binding validation (adapted from
        # anthropics/sandbox-runtime credential-sentinel.ts): host-gated
        # credential control on the egress-attempt path, BEFORE the
        # policy decision. Opt-in: sentinel_registry None = zero
        # behavior change. This validates the binding only — args pass
        # through UNCHANGED (sentinel-bearing), so DLP, policy,
        # approval, previews, and every audit-bound snapshot see only
        # the sentinel form. A host mismatch raises SentinelTripHalt
        # fail-closed (the secret is unusable outside its authorized
        # channel, and the mismatch is a LOUD trip signal). The real
        # values are substituted ONLY at the execution boundary, into
        # an ephemeral copy, via substitute_for_execution — never into
        # the audit path.
        if getattr(self, "sentinel_registry", None) is not None:
            _sentinel_validated = _sentinel.validate_sentinel_binding(
                self, identity, tool, kwargs)
        else:
            _sentinel_validated = []

        # F162 (HIGH): sticky velocity pause. A tempo trip (or budget
        # exhaustion that pauses) halts the WHOLE run fail-closed — the
        # canary pattern: catching the trip and calling again still
        # raises, for every identity. Only a human-approved resume
        # clears it.
        self._check_tempo_paused(identity, tool)

        self.counters[tool] = self.counters.get(tool, 0) + 1
        # S4: every call() attempt that reaches here consumes step budget
        # (denied/queued attempts included).
        self._total_calls += 1
        repeat_key = (tool, json.dumps(kwargs, sort_keys=True, default=str))
        self._repeats[repeat_key] = self._repeats.get(repeat_key, 0) + 1

        blocked, blocking_rule, redacted_args, redactions = dlp.scan_tool_args(
            tool, kwargs)

        # Sentinel binding marker: the DLP field-redaction summarizes
        # payloads (the approval record never sees the sentinel value
        # itself), so record WHICH credential placeholder is bound for
        # this destination in the redactions channel — the approver and
        # the auditor see "credential vendor-key bound", never the
        # secret. The credential id is an operator label, not secret
        # material.
        if _sentinel_validated:
            redactions = list(redactions) + [
                "sentinel:credential %s bound to this destination" % cid
                for cid in _sentinel_validated]
            # Preserve the validated sentinel placeholders through the
            # DLP payload summary: the summary would otherwise destroy
            # the sentinel before queueing, leaving the approved sweep
            # nothing to substitute. Sentinels are fixed-format
            # vault-minted placeholders (provably not secret
            # material); every non-sentinel string stays summarized.
            redacted_args = _sentinel.preserve_sentinels(
                self.sentinel_registry, redacted_args, kwargs)

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
                # Wave-154 (rows 11/18): the verified identity-delegation
                # receipt for this session (sub/act/delegator_chain/
                # scope/session_id + token refs). Present on EVERY
                # tool_call entry: a dict for delegated executions,
                # explicit None for direct (non-delegated) executions —
                # never ambiguous, never omitted.
                "delegation_receipt": self._session_delegation_receipt(),
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
        # are allowed. F162: default-enforced — absent key is a
        # conservative default, never "unlimited". Checked before
        # policy evaluation, like every other step-4 guard.
        _run_limits = getattr(policy, "run_limits", None) or {}
        _max_tool_calls = _run_limits.get(
            "max_tool_calls_per_run", _DEFAULT_MAX_TOOL_CALLS_PER_RUN)
        if self._total_calls > _max_tool_calls:
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
        # and the NEXT call is denied. F162: max_actions_per_run is
        # default-enforced — an absent budgets: section (or absent key)
        # applies the conservative default, never "unlimited". Token
        # and spend ceilings stay deployment-configured (no meaningful
        # default without a price).
        _budgets = getattr(policy, "budgets", None) or {}
        # Count every call() invocation that reaches this guard.
        self._budget_actions += 1
        _budget_deny_reason = None
        _max_actions = _budgets.get(
            "max_actions_per_run", _DEFAULT_MAX_ACTIONS_PER_RUN)
        if self._budget_actions > _max_actions:
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

        # Wave-160 (row 13): tiered egress-verdict wiring. The
        # T1->T2->T3 composition (gov/detection_verdicts.py) was
        # library-only: neither the content monitor nor the rare-token
        # tracker ever ran on the operational egress-attempt path, so a
        # T3 paraphrase-footprint egress left no verdict and drew no
        # tiered response. Every egress-tool call with a monitor or
        # tracker installed is now analyzed here -- after identity,
        # DLP, and volume guards (denied calls need no analysis and
        # must not pollute monitor baselines), before policy
        # evaluation. Raw kwargs: redaction must not destroy evidence
        # pre-detection (wave-90 idiom). Graduated response: allow /
        # flag / behavioral_flag proceed (the flag tiers are LOUD
        # audit only); require_approval forces the standard
        # require_approval path below (fail-closed direction only -- a
        # deny stays denied, an existing require_approval is
        # untouched). Opt-in: with no monitors installed this is a
        # silent allow (zero behavior change).
        _tiered_egress_hold = None
        if (tool in _EGRESS_TOOLS
                and (self.content_monitor is not None
                     or self.rare_token_tracker is not None)):
            _tiered = self.check_egress_tiered_verdict(
                identity.agent_id, tool, kwargs)
            if _tiered.get("verdict") == "require_approval":
                _tiered_egress_hold = PolicyDecision(
                    "require_approval",
                    ("Tiered egress verdict %s/%s on %r: %s -- a human "
                     "must review this egress before it executes "
                     "(row-13 tiered verdicts, wave-160)."
                     % (_tiered.get("tier"), _tiered.get("verdict"),
                        tool, _tiered.get("reason", ""))),
                    policy_id="egress-tiered-verdict",
                    flag="egress_tiered_risk")

        # Wave-266 (F248): reconstructed-intent scoring seam. Every
        # call for a tool carrying destination slots, with a seam
        # installed and chunks buffered from noted reads, is scored
        # here -- after identity, DLP, and volume guards, before
        # policy evaluation. Denied calls are not scored and journal
        # no suspect event (the denial is already LOUD; a suspect
        # event with no queued record would be a dangling signal).
        # The seam digests args, never journals raw values (wave-90
        # idiom). Scoring is QUIET here: the verdict is stashed and
        # the LOUD event + hold are applied post-policy, so a
        # policy-denied call journals no dangling suspect event with
        # no queued record (Spec review, second pass). Graduated
        # response: quiet proceeds silently; suspect forces the
        # standard require_approval path below (fail-closed
        # direction only -- a deny stays denied, an existing
        # require_approval is untouched but gains the reconintent
        # preview banner on its record; never a silent block on the
        # heuristic). Opt-in: with no seam installed this is skipped
        # entirely (zero behavior change).
        _reconintent_hold = None
        _reconintent_verdict = None
        if self.reconstruction_seam is not None:
            from . import reconstructed_intent as _reconintent
            if (_reconintent.has_critical_destinations(tool, kwargs)
                    and self.reconstruction_seam.has_chunks()):
                _recon_user_text = ""
                if self._intent_user_turns:
                    _recon_user_text = self._intent_user_turns[-1]
                _reconintent_verdict = (
                    self.reconstruction_seam.score_buffered(
                        tool, kwargs, _recon_user_text))
                if _reconintent_verdict.get("suspect"):
                    _reconintent_hold = PolicyDecision(
                        "require_approval",
                        ("Reconstructed-intent HOLD on %r: the run's "
                         "untrusted chunks jointly complete an "
                         "actionable directive no single chunk "
                         "carried (score %d, confidence %s) -- a "
                         "human must review this action before it "
                         "executes (F248, wave-266)."
                         % (tool,
                            _reconintent_verdict.get("score", 0),
                            _reconintent_verdict.get(
                                "confidence", "medium"))),
                        policy_id="reconintent",
                        flag="reconstructed_intent")

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
            # Row-13 classification provenance (2026-09-26): the labeled-
            # read taint rides the snapshot so offline replay sees exactly
            # what the engine saw (None when no labeled file was read —
            # bool(None) == bool(False), the engine's semantics).
            "read_classified": ctx.get("read_classified"),
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
            # F146: the symlink-resolved path target rides the snapshot
            # so offline replay sees exactly what the engine saw (None
            # when the tool takes no path arg — the engine then matches
            # declared-only, the pre-F146 behavior).
            "path_resolved": ctx.get("path_resolved"),
            # Wave-173 lane 1 (TMA-NM act-time gate): the run's
            # un-elevated memory reads at queue time ride the snapshot
            # so the human's decision record names the memory provenance
            # the action may depend on (MAC-bound via policy_context,
            # WYSINWYS-rendered in the packet). None when the gate is
            # not attached -- the sweep treats a missing disclosure as
            # "nothing disclosed" (fail-closed).
            "memory_provenance": self._actgate_disclosure(),
            # F191 (wave-174): audio carriers embedded in the tool args
            # ride the snapshot so the approval record names the
            # perceptual channel the action touches (MAC-bound via
            # policy_context, WYSINWYS-rendered in the packet). [] when
            # none -- pure function of the args, safe to re-derive.
            "attachment_carriers": (
                _audio_carrier.attachment_carriers(kwargs)),
            "counters": dict(ctx.get("counters") or {}),
        }
        # Decision-trace replay lane: capture the full typed Decision
        # rather than the legacy PolicyDecision. Verdict semantics are
        # IDENTICAL -- PolicyEngine.evaluate() is implemented as
        # decide(Request.from_action(action, context))
        # .to_policy_decision(), so this is the same computation with
        # the diagnostics retained for the replayable trace built
        # below. Capture only; no verdict-logic change.

        # Row-12 (wave-162): undeclared-path write binding. The
        # manifest declares the deployment-critical artifact paths;
        # a write_file whose check-time resolved target is inside the
        # sandbox but is neither manifest-declared nor under a
        # deployment-declared writable dir is forced to human approval
        # -- after the guards above (denied calls need no binding
        # check), before policy evaluation. Uses ctx["path_resolved"],
        # the SAME check-time resolved target the F147 machinery binds
        # the effect to, so the binding cannot be split from the
        # containment verdict. Graduated response: require_approval
        # only (fail-closed direction -- a deny stays denied, an
        # existing require_approval is untouched); the LOUD
        # write_undeclared_path event is already in the log.
        _undeclared_write_hold = None
        if tool == "write_file":
            _uw = self.check_write_declared_path(
                identity.agent_id, ctx.get("path_resolved"),
                declared_path=(kwargs or {}).get("path"))
            if _uw.get("verdict") == "require_approval":
                _undeclared_write_hold = PolicyDecision(
                    "require_approval", _uw.get("reason", ""),
                    policy_id="manifest-write-binding",
                    flag="undeclared_write_path")

        _decision_full = policy.decide(Request.from_action(action, ctx))
        decision = _decision_full.to_policy_decision()

        # Wave-249 wiring: cross-policy-set combination
        # (gov/policy_combine.py). When the deployment supplies
        # additional policy engines via policy_set, each is evaluated
        # on the SAME request and the decisions are combined with the
        # structural forbid-overrides-permit guarantee: any forbid in
        # any policy denies, regardless of permits elsewhere. Empty
        # policy_set = pre-wave-249 single-policy verdict, zero change.
        if self._policy_set:
            from gov import policy_combine as _pc
            _set_decisions = [_decision_full]
            for _eng in self._policy_set:
                _set_decisions.append(
                    _eng.decide(Request.from_action(action, ctx)))
            _combined = _pc.combine(_set_decisions)
            decision = _combined.to_policy_decision()

        # Wave-198 (graduation ladder, R1 warn-fatigue): warn-mode
        # decisions carry operator telemetry. Aggregate it into the
        # per-rule-per-window digest here -- the agent's verdict path
        # below is untouched, and warnings are NEVER returned to the
        # agent as interrupts. A telemetry failure is chained loudly
        # but never changes the verdict.
        self._surface_warn_digest(decision)
        # Wave-198 (graduation ladder, §§3.4-3.5): route ladder
        # escalations (warn-stale, overdue emergency reviews) to the
        # operator audit trail at this seam too.
        self._check_ladder_escalations()

        # Wave-176 (OpenShell steal #1, AuthorityProof contract): check
        # the proposed action against the operator-declared authority
        # boundary at the policy pre-decision seam. The proof ALWAYS
        # rides the policy-context snapshot (MAC-bound with the rest of
        # policy_context) so the audit trail names exactly what was
        # checked -- covered vs uncovered domains -- for every action.
        # Enforcing vs advisory (explicit): a DECLARED boundary makes
        # exceeds/unsupported/inconclusive refuse FAIL-CLOSED here,
        # before any side effect, in the fail-closed direction only (a
        # within_boundary proof never upgrades a policy deny). With NO
        # declared boundary the proof is advisory and the policy
        # verdict stands -- refusing every action for a boundary the
        # operator never wrote would be the governor denying its own
        # deployment's legitimate work. check() never raises on
        # hostile action shapes (they become unsupported).
        _ap_ctx = dict(ctx)
        _ap_ctx["sandbox_root"] = str(self._sandbox_resolved)
        _ap_proof = _authority_proof.check(
            action, _ap_ctx, self._authority_boundary,
            # Wave-198 lane E: enforce attested MCP required scopes
            # against the calling agent's verified token claims. With
            # no registry configured the kwargs are ignored by the
            # legacy MCP path (byte-identical behavior).
            mcp_tool_registry=self._mcp_tool_registry,
            token_claims=self._mcp_token_claims_for(identity.agent_id))
        policy_ctx_snapshot["authority_proof"] = _ap_proof.to_dict()
        if (self._authority_boundary is not None
                and _ap_proof.verdict != _authority_proof.WITHIN):
            _ap_entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "authority-boundary",
                "flag": "authority_boundary_refused",
                "matched_rules": [],
                "authority_proof": _ap_proof.to_dict(),
                "reason": ("Refusing to act: authority proof %r for %s "
                           "(%s); the operator-declared boundary does "
                           "not cover this action."
                           % (_ap_proof.verdict, tool,
                              _ap_proof.detail)),
            }))
            return {"status": "denied",
                    "reason": _ap_entry["reason"],
                    "policy_id": "authority-boundary",
                    "seq": _ap_entry["seq"]}

        # Monotonic advisory layer (opt-in, adapted from
        # microsoft/agent-governance-toolkit). Runs AFTER the
        # deterministic verdict: advisors can only move the effect UP
        # the allow < require_approval < deny lattice, never down;
        # monotonicity violations are refused LOUD and every decision
        # records a chained Decision BOM entry. advisors=None (the
        # default) is zero behavior change.
        if getattr(self, "_advisors", None):
            decision = self._apply_advisory(
                decision, action, ctx, policy, identity, tool, kwargs,
                lambda extra: self.log.append(_base(extra)))

        # Wave-319 (grant negotiation): advisory grant check --
        # only-tighten. Runs AFTER the deterministic verdict (and the
        # monotonic advisory layer above), and only when the verdict
        # would otherwise allow: it can only turn an allow into a
        # deny, never a deny into an allow, and it never masks a
        # deterministic denial reason. Absent registry, unregistered
        # tool, or absent grant proceeds exactly as before (the
        # deterministic layer is canonical; advisory failures default
        # to allow). A presented grant that fails verification refuses
        # LOUD with its coded grantneg-* refusal. The
        # require_approval path is out of scope in v1: a presented
        # grant is evaluated on the direct-allow path only, never
        # forwarded into the queued approval.
        _grant_status, _grant_detail = (None, None)
        if decision.effect == "allow":
            _grant_status, _grant_detail = grant_negotiation.advisory_check(
                getattr(self, "_grant_registry", None), tool,
                _presented_grant, identity.agent_id, args=kwargs)
        if _grant_status == "refused":
            _grant_entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "grant-advisory",
                "flag": "grantneg_" + _grant_detail["code"].replace(
                    "-", "_"),
                "matched_rules": [],
                "reason": ("Refusing to act: presented grant failed "
                           "verification (%s): %s"
                           % (_grant_detail["code"],
                              _grant_detail["reason"])),
            }))
            return {"status": "denied",
                    "reason": _grant_entry["reason"],
                    "policy_id": "grant-advisory",
                    "seq": _grant_entry["seq"]}

        # Wave-89 (stream s5-tool): use-time tool-definition
        # verification. The inventory's CURRENT definition digest is
        # compared against the last-seen digest; drift quarantines the
        # tool fail-closed (loud tool_quarantined audit, no execution).
        # Unregistered tools and provider failures do NOT refuse here —
        # the policy's own unknown-tool handling decides those; the
        # inventory refuses to invent a refusal for a tool it never
        # pinned.
        _inv_ok, _inv_prev, _inv_cur = (
            self._tool_inventory.verify_at_use(tool))
        if not _inv_ok:
            _inv_entry = self.log.append(_base({
                "decision": "tool_quarantined",
                "policy_id": "tool-inventory",
                "flag": "tool_quarantined",
                "matched_rules": [],
                "reason": ("Refusing to act: tool %r definition drifted "
                           "(digest %s -> %s); quarantined pending "
                           "deployment re-pin (wave-89 tool continuity)."
                           % (tool, (_inv_prev or "?")[:12],
                              (_inv_cur or "?")[:12])),
            }))
            return {"status": "denied", "reason": _inv_entry["reason"],
                    "policy_id": "tool-inventory", "seq": _inv_entry["seq"]}

        # Wave-92 (stream C): continuous skill verification on the
        # verdict path, AFTER policy evaluation and the tool-inventory
        # gate, BEFORE anything executes. When a skill watcher is
        # installed and this tool attributes to a skill id, the
        # watcher's use-time check runs here: a mutated or
        # unverifiable skill — or ANY watcher/attribution error — or
        # an id the watcher never pinned (F143: fail-closed, no pin
        # means no verification exists) — DENIES the call fail-closed
        # (loud audit entry, no execution). Unattributed tools (the
        # deployment's explicit None opt-out) are NOT refused here:
        # the policy's unknown-skill handling decides those (same
        # precedent as the tool-inventory gate above).
        # F184 (row-6/14 wiring lane): the gate consumes
        # fetch_verified_at_use, not check_at_use. The SAME single
        # read that the pin is checked against is handed back as
        # bytes; the consumer must execute exactly those bytes (see
        # verified_skill_bytes) instead of re-reading the source — a
        # re-read after the check could return different bytes (the
        # V2 window the break round demonstrated at the seam level).
        # F184: handoff locals. Initialized outside the watcher
        # branch because the allow/queue paths below reference them;
        # they stay None unless a skill was attributed AND verified.
        _skill_id = None
        _sw_verified_bytes = None
        _sw_attested_digest = None
        self._sw_handoff = None
        if self._skill_watch is not None:
            try:
                _skill_id = _skill_watch.skill_id_for_tool(
                    tool, tool_to_skill=self._skill_tool_map,
                    mcp_server=mcp_server,
                    mcp_server_to_skill=self._skill_mcp_map)
                if _skill_id is None:
                    _sw_ok, _sw_detail = True, "unattributed"
                    _sw_err = None
                else:
                    (_sw_ok, _sw_verified_bytes,
                     _sw_detail) = self._skill_watch.fetch_verified_at_use(
                         _skill_id)
                    _sw_err = None
                    if _sw_ok and _sw_verified_bytes is not None:
                        _sw_attested_digest = hashlib.sha256(
                            _sw_verified_bytes).hexdigest()
                        # The handoff: exactly the bytes the watcher
                        # hashed. Never hand bytes from a failed check
                        # (fail-closed: the except branch below clears
                        # the slot).
                        self._sw_handoff = (
                            _skill_id, _sw_attested_digest,
                            _sw_verified_bytes)
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                _skill_id = None
                _sw_ok, _sw_detail, _sw_err = False, "watcher-error", e
                _sw_verified_bytes = None
                _sw_attested_digest = None
                self._sw_handoff = None
            if not _sw_ok:
                if _sw_detail == "unregistered-no-pin":
                    _sw_reason = (
                        "Refusing to act: skill %r is attributed by "
                        "the deployment map but was never registered "
                        "with the skill watcher (no pin: F143): "
                        "executing it would run with attribution but "
                        "zero verification. Register the skill at "
                        "install, or add an explicit None opt-out "
                        "entry for this tool/server in the deployment "
                        "map, before use." % (_skill_id,))
                else:
                    _sw_reason = ("Refusing to act: skill %r failed "
                                  "continuous verification (%s%s); "
                                  "quarantined pending explicit re-pin "
                                  "approval."
                                  % (_skill_id, _sw_detail,
                                     (": %s" % _sw_err)
                                     if _sw_err is not None else ""))
                _sw_entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": "skill-watch",
                    "flag": "skill_quarantined",
                    "matched_rules": [],
                    "skill_id": _skill_id,
                    "skill_check": _sw_detail,
                    "reason": _sw_reason,
                }))
                return {"status": "denied",
                        "reason": _sw_entry["reason"],
                        "policy_id": "skill-watch",
                        "seq": _sw_entry["seq"]}

        # Wave-282 lane 4 (snyk/agent-scan ADAPT): discovery-driven
        # tool-definition check on the verdict path, AFTER the
        # skill-watch gate, BEFORE anything executes. When a
        # discovery registry is installed and this tool attributes to
        # a discovered component, the registry's hold binds here (the
        # guard-hook half: diff at change time, not just at scan
        # time). A tool quarantined by the scheduled re-scan is
        # ALWAYS denied; when the deployment installed
        # discovery_observe_one, the change-time diff additionally
        # re-observes the single tool's definition and denies on
        # drift/unobservability. A drifted, unobservable, or
        # unregistered tool — or ANY observer/attribution error —
        # DENIES the call fail-closed (loud audit entry, no
        # execution): drift is evidence of compromise, so the hold
        # stands until a governed re-pin. Unattributed tools (the
        # deployment's explicit opt-out) are NOT refused here: the
        # policy's own unknown-tool handling decides those (the
        # tool-inventory gate precedent). Without
        # discovery_observe_one the deployment runs scheduled-scan
        # mode only: the re-scan quarantine still binds and an
        # attributed-but-never-pinned tool is quarantined
        # fail-closed, but no per-call re-observation happens.
        if self._discovery_scan is not None:
            try:
                _ds_triple = _discovery_scan.discovery_key_for_tool(
                    tool, tool_to_component=self._discovery_tool_map,
                    mcp_server=mcp_server,
                    mcp_server_to_component=self._discovery_mcp_map)
                if _ds_triple is None:
                    _ds_ok, _ds_code, _ds_detail = True, "ok", \
                        "unattributed"
                else:
                    _ds_key = (_ds_triple[0], _ds_triple[1],
                               _ds_triple[2], tool)
                    if self._discovery_observe_one is None:
                        # Scheduled-scan-only mode: the re-scan
                        # quarantine binds, and an attributed tool
                        # with no pin is quarantined fail-closed
                        # (first sighting is never trusted silently
                        # -- the F143 precedent). The change-time
                        # diff needs an observer; without one, the
                        # pin-membership check is the whole gate.
                        (_ds_ok, _ds_code,
                         _ds_detail) = self._discovery_scan.scan_only_check(
                            _ds_key)
                    else:
                        (_ds_ok, _ds_code,
                         _ds_detail) = self._discovery_scan.check_at_use(
                            _ds_key,
                            observe_one=self._discovery_observe_one)
                _ds_err = None
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                _ds_ok, _ds_code, _ds_detail = False, \
                    "discovery-result-malformed", "registry-error"
                # Type name only: the exception text could carry
                # definition content, which must never reach the
                # audit log (redact-before-emit).
                _ds_err = type(e).__name__
            if not _ds_ok:
                _ds_reason = (
                    "Refusing to act: tool %r failed discovery-scan "
                    "definition verification (%s: %s%s); held out of "
                    "the grant graph pending governed re-pin "
                    "(wave-282 discovery-scan: drift = fail-closed "
                    "hold)."
                    % (tool, _ds_code, _ds_detail,
                       (": %s" % _ds_err) if _ds_err is not None
                       else ""))
                _ds_entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": "discovery-scan",
                    "flag": _ds_code.replace("-", "_"),
                    "matched_rules": [],
                    "tool": tool,
                    "discovery_check": _ds_code,
                    "reason": _ds_reason,
                }))
                return {"status": "denied",
                        "reason": _ds_entry["reason"],
                        "policy_id": "discovery-scan",
                        "seq": _ds_entry["seq"]}

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
        # Row-12 (wave-162): undeclared-path write binding. A
        # require_approval from the manifest-path binding downgrades
        # an allow to queued human review -- fail-closed direction
        # only: a deny stays denied, an existing require_approval is
        # untouched (its record keeps the original policy_id/flag;
        # the LOUD write_undeclared_path event is already in the log).
        # The queued record carries policy_id
        # "manifest-write-binding" + flag "undeclared_write_path" so
        # the human reviewer sees the forcing. Precedence: this is an
        # authorization boundary (the write is inside the declared
        # deployment contract or it is not), so it applies AFTER the
        # unrated-tool hold -- an undeclared write through an unrated
        # tool is still queued, and the record shows the deeper
        # manifest-write-binding forcing; it applies BEFORE the
        # tiered-egress hold so the record shows the write's own
        # binding rather than its egress risk when both fire.
        if (_undeclared_write_hold is not None
                and decision.effect == "allow"):
            decision = _undeclared_write_hold
        # Wave-160 (row 13): tiered egress-verdict hold. A
        # require_approval from the T1->T2->T3 composition downgrades
        # an allow to queued human review -- fail-closed direction
        # only: a deny stays denied, an existing require_approval is
        # untouched (its record keeps the original policy_id/flag;
        # the LOUD egress_tiered_verdict hold event is already in the
        # log). The queued record carries policy_id
        # "egress-tiered-verdict" + flag "egress_tiered_risk" so the
        # human reviewer sees the forcing.
        if (_tiered_egress_hold is not None
                and decision.effect == "allow"):
            decision = _tiered_egress_hold
        # Wave-266 (F248): reconstructed-intent hold. A suspect from
        # the run's untrusted chunk set downgrades an allow to queued
        # human review -- fail-closed direction only: a deny stays
        # denied (the denial is already journaled LOUD, so no
        # dangling suspect event is emitted and nothing is queued);
        # an existing require_approval is untouched (its record
        # keeps the original policy_id/flag) but the LOUD
        # reconstructed_intent_suspect event is journaled and the
        # reconintent banner leads the queued record's preview below,
        # so the human reviewer sees the forcing without
        # correlating log-to-queue by hand. The queued record for a
        # forced hold carries policy_id "reconintent" + flag
        # "reconstructed_intent"; separation of duties rides
        # gov.approvals (the agent can never approve its own hold
        # away).
        if (_reconintent_verdict is not None
                and _reconintent_verdict.get("suspect")):
            if decision.effect != "deny":
                # _reconintent is bound by the pre-policy import
                # above: a non-None verdict implies the seam was
                # installed and the import ran.
                self.log.append(_reconintent.suspect_event(
                    _reconintent_verdict, identity.agent_id, tool,
                    kwargs, self.run_id))
            if (_reconintent_hold is not None
                    and decision.effect == "allow"):
                decision = _reconintent_hold
        # Wave-89 (stream s5-tool): deferred-effect (plant-now/harm-later)
        # scan on the raw kwargs. A hit chains a loud
        # deferred_effect_detected event and forces require_approval on
        # the allow path (fail-closed direction only: deny stays denied,
        # an existing require_approval is untouched but still gets the
        # marker stamped on its record). The deferred details ride the
        # approval record MAC-bound, so the human sees WHEN it fires and
        # a later auditor can reconstruct the planted intent — the
        # intent-ledger entry for logic-bomb-shaped actions.
        # Wave-90 (stream s8-redact): the scan still reads RAW kwargs
        # (redaction must not destroy trigger evidence pre-detection),
        # but scan_deferred_effect() now emits structured DESCRIPTORS
        # (shape/position/fingerprint), never raw values — the audit
        # entry and the MAC-bound record below therefore carry no
        # payload content, only the trigger's kind, location, and a
        # correlation fingerprint.
        _deferred = _tool_continuity.scan_deferred_effect(tool, kwargs)
        if _deferred is not None:
            self.log.append(_base({
                "decision": "deferred_effect_detected",
                "policy_id": "deferred-effect",
                "flag": "deferred_effect",
                "matched_rules": [],
                "deferred_effect": _deferred,
                "reason": ("Deferred-effect markers in %r call "
                           "(%s): forcing human review — the action "
                           "plants a trigger that fires later "
                           "(wave-89 tool continuity)."
                           % (tool, ", ".join(
                               sorted({t["kind"]
                                       for t in _deferred["triggers"]})))),
            }))
            if decision.effect == "allow":
                decision = PolicyDecision(
                    "require_approval",
                    ("Deferred-effect markers (%s) in this %r call: it "
                     "plants a trigger that fires later, so a human must "
                     "review WHEN it fires, not just WHAT it does "
                     "(wave-89 tool continuity)."
                     % (", ".join(sorted({t["kind"] for t in
                                          _deferred["triggers"]})), tool)),
                    policy_id="deferred-effect",
                    flag="deferred_effect",
                )

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

        # Row-9 Phase B (wave-119): trajectory-erosion breaker. When the
        # erosion monitor's breaker is OPEN for the acting identity, an
        # allow verdict on a high-risk tool is downgraded to
        # require_approval (fail-closed direction only: a deny stays
        # denied, an existing require_approval is untouched). The
        # trajectory signal is a breaker INPUT, never a verdict: it
        # trips the RUN/trajectory, never any single action. Fail-closed:
        # a monitor error is treated as OPEN. No monitor installed =
        # zero behavior change.
        if (decision.effect == "allow"
                and self._erosion_monitor is not None):
            try:
                _eroute = self._erosion_monitor.route_action(
                    identity, tool)
            except Exception as e:  # noqa: BLE001 - fail closed, loud
                _eroute = "queue"
                self.log.append(_base({
                    "decision": "breaker_fail_closed",
                    "policy_id": "trajectory-erosion",
                    "flag": "erosion_monitor_unreachable",
                    "matched_rules": [],
                    "reason": ("Trajectory-erosion monitor unreachable "
                               "(%s); treating breaker as OPEN." % e),
                }))
            if _eroute == "queue":
                decision = PolicyDecision(
                    "require_approval",
                    ("Trajectory-erosion breaker is OPEN for this "
                     "identity; a caution-erosion signal fired on this "
                     "run's trajectory -- human review is required "
                     "before execution (row-9 Phase B)."),
                    policy_id="trajectory-erosion",
                    flag="erosion_breaker_open",
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

        # Wave-89 (stream s5-tool): trajectory continuity. Every call
        # that reaches a final gate verdict is counted; every Nth call
        # (default 50) chains a loud trajectory_reverified event and
        # forces full gate re-verification (the ledger is re-verified
        # fail-closed; the NEXT call picks up a refreshed policy
        # snapshot at its own call start, so wave-75's within-verdict
        # version pinning is never mixed). A risk-tier escalation
        # (read < mutating < egress < irreversible) chains
        # risk_tier_escalation. Escalation never auto-downgrades
        # allow -> require_approval — a documented design choice (the
        # false-positive cost on legitimate trajectories); the suite is
        # the judge.
        _tier = _tool_continuity.risk_tier_for(tool)
        if _precommit.is_irreversible(tool):
            _tier = _tool_continuity.TIER_IRREVERSIBLE
        (_checkpoint_due, _tier_escalated,
         _prev_tier) = self._trajectory.note_call(_tier)
        if _tier_escalated:
            self.log.append(_base({
                "decision": "risk_tier_escalation",
                "policy_id": "trajectory",
                "flag": "risk_tier_escalation",
                "matched_rules": [],
                "from_tier": _tool_continuity.TIER_NAMES[_prev_tier],
                "to_tier": _tool_continuity.TIER_NAMES[_tier],
                "reason": ("Risk-tier escalation: first %s-tier tool call "
                           "this run (from %s). The trajectory, not just "
                           "the action, is now visible to auditors "
                           "(wave-89 tool continuity)."
                           % (_tool_continuity.TIER_NAMES[_tier],
                              _tool_continuity.TIER_NAMES[_prev_tier])),
            }))
        if _checkpoint_due:
            try:
                self._ledger.require_verified()
            except LedgerUnverifiableError as e:
                _cp_entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": "ledger-unverifiable",
                    "flag": "ledger_unverifiable",
                    "matched_rules": [],
                    "reason": ("Refusing to act at trajectory checkpoint "
                               "%d: %s"
                               % (self._trajectory.calls, e)),
                }))
                raise
            self.log.append(_base({
                "decision": "trajectory_reverified",
                "policy_id": "trajectory",
                "flag": "trajectory_reverified",
                "matched_rules": [],
                "trajectory_calls": self._trajectory.calls,
                "max_tier": _tool_continuity.TIER_NAMES[
                    self._trajectory.max_tier],
                "reason": ("Trajectory checkpoint %d: gate state "
                           "re-verified (ledger authenticated); no drift "
                           "detected (wave-89 tool continuity)."
                           % self._trajectory.calls),
            }))

        # Row-9 Phase B (wave-119): feed the trajectory-erosion monitor.
        # Every call that reaches a final gate verdict is observed;
        # decision.effect here is post-breaker-check, so a queued call
        # counts as queued whichever rule queued it. On a CLOSED->OPEN
        # trip the monitor yields the chained-signal payload, which is
        # appended here (counter values and metadata only -- never raw
        # content or raw params). One signal per open transition.
        # A feed failure is a DETECTION gap, not a verdict failure: the
        # verdict is already decided, so log loudly and continue rather
        # than crashing the run. (The routing check above is the
        # safety-relevant path and fails closed to OPEN.)
        if self._erosion_monitor is not None:
            try:
                _erosion_signal = self._erosion_monitor.note_call(
                    identity, tool, kwargs, decision.effect)
            except Exception as e:  # noqa: BLE001 - loud, then continue
                self.log.append(_base({
                    "decision": "erosion_feed_failed",
                    "policy_id": "trajectory-erosion",
                    "flag": "erosion_feed_failed",
                    "matched_rules": [],
                    "reason": ("Trajectory-erosion feed failed (%s); "
                               "this call went unobserved by the erosion "
                               "monitor -- detection gap, verdict "
                               "unaffected." % e),
                }))
                _erosion_signal = None
            if _erosion_signal is not None:
                self.log.append(_base({
                    "decision": "erosion_signal",
                    "event": "trajectory_caution_erosion",
                    "signal": "trajectory_caution_erosion",
                    "policy_id": "trajectory-erosion",
                    "flag": "trajectory_caution_erosion",
                    "matched_rules": [],
                    "erosion_counter": _erosion_signal.get("counter"),
                    "erosion_detail": {
                        k: _erosion_signal.get(k)
                        for k in ("dlp_rule", "buffered_leaves",
                                  "borderline_calls", "endpoint",
                                  "consecutive_queues", "ascents",
                                  "peak_rank")
                        if _erosion_signal.get(k) is not None
                    },
                    "reason": ("Trajectory-level caution-erosion signal: "
                               "counter %r tripped on this run's "
                               "trajectory (row-9 Phase B). Signal, not "
                               "verdict: the erosion breaker now routes "
                               "high-risk actions to human approval."
                               % (_erosion_signal.get("counter"),)),
                }))

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

        # Decision-trace replay lane: lazily build the replayable
        # decision trace for this call's verdict. Built once, at the
        # first verdict entry, so post_verdict reflects the FINAL
        # effect after every post-policy layer (advisory tightening,
        # tool-rating / deferred-effect / breaker forcing -- whose
        # own policy_id/flag already name the forcing layer). Trace
        # capture never raises into the verdict path: a capture
        # failure degrades to a loud capture-error marker, never a
        # changed verdict.
        _decision_trace_cache = {}

        def _decision_trace():
            if "trace" not in _decision_trace_cache:
                try:
                    _decision_trace_cache["trace"] = (
                        _decision_replay.build_trace(
                            decision=_decision_full,
                            action=action,
                            context=ctx,
                            policy=policy,
                            final_effect=decision.effect,
                            final_policy_id=decision.policy_id,
                            final_flag=decision.flag))
                except Exception as e:  # noqa: BLE001 - evidence only
                    _decision_trace_cache["trace"] = {
                        "trace_version": _decision_replay.TRACE_VERSION,
                        "capture_error": "%s: %s" % (type(e).__name__, e),
                    }
            return _decision_trace_cache["trace"]

        # Wave-279 (F300): provenance-forced queueing. When the
        # instruction-provenance grant seam routed this action
        # (provlabel-*), it queues for a human even if the policy
        # engine allowed it: the toxic-agent-flow shape (user
        # instruction + retrieved injection) is never silently
        # executed. The policy's allow verdict is replaced by a
        # require_approval decision naming the provenance seam, and
        # the rendered section below stamps the chain on the record.
        if (prov_decision is not None
                and prov_decision.routed_to_approval
                and prov_decision.code
                and decision.effect == "allow"):
            decision = PolicyDecision(
                "require_approval",
                "instruction-provenance routed this action to approval: "
                "%s" % (prov_decision.reason,),
                policy_id="instruction-provenance",
                flag=prov_decision.code,
                matched_rules=[])

        if decision.effect == "allow":
            # F162 (HIGH): charge the per-class tempo wire at this
            # execution boundary, BEFORE the side effect. A trip
            # pauses the whole run fail-closed (raises) — the call
            # never executes.
            self._charge_tempo(identity, tool)
            # Write-ahead audit (fail-closed): the authorization is durably
            # logged BEFORE the side effect. If this append raises, the tool
            # is never touched: no log, no side effect.
            auth_entry = self.log.append(_base({
                "decision": "execution_authorized",
                "policy_id": decision.policy_id,
                "matched_rules": decision.matched_rules,
                "reason": decision.reason,
                "flag": decision.flag,
                # Decision-trace replay lane: the replayable trace for
                # this verdict (see gov/decision_replay.py).
                "decision_trace": _decision_trace(),
                # F196 (MATCH re-binding): the exact policy-decision dict
                # the decision packet's decision_digest commits to, so a
                # verifier can re-derive the digest from this chained
                # entry instead of trusting the packet's opaque pointer.
                "policy_decision": decision.to_dict(),
            }))
            # Wave-176 (OpenShell steal #2): the constructive decision
            # packet for the FINAL allow verdict, chained immediately
            # under the write-ahead execution_authorized entry -- the
            # packet's evidence.head_digest names its actual audit
            # parent, and it is emitted BEFORE the side effect.
            self._emit_decision_packet(
                decision="allow",
                decision_seq=auth_entry.get("seq"),
                head_digest=auth_entry.get("hash"),
                tool=tool,
                redacted_args=redacted_args,
                policy_decision=decision,
                policy=policy,
                policy_ctx_snapshot=policy_ctx_snapshot,
                identity=identity,
                skill_id=_skill_id,
                skill_attested_digest=_sw_attested_digest)
            # Wave-79 (pre-commit, atomic): irreversible tools with the
            # gate installed consume their bound approval IN the commit
            # that executes them — a single-use ticket. The earlier
            # check() failed fast with a denied record; commit()
            # re-verifies and marks the ticket consumed before running
            # the thunk, so a second call presenting the same approval
            # id is refused (no replay through the executor).
            # F164 (HIGH): bind the ambient exchange reader around tool
            # execution so the agent read_file path is policy-checked
            # and recorded on the F163 exchange ledger. bind_reader is
            # thread-local and restores the previous binding on exit,
            # so nested/spawned executions attribute to the innermost
            # reader. The pre-commit commit() thunk runs synchronously
            # inside commit(), so the binding covers it too.
            #
            # Sentinel substitution at the execution boundary: the
            # ephemeral substituted copy goes ONLY to the tool
            # invocation. Every audit-bound snapshot (write-ahead
            # entry, usage minting, firewall/lineage hooks below) keeps
            # the sentinel-bearing kwargs — the real credential never
            # enters the audit path. (The pre-commit digest binds the
            # sentinel form: the human approves the placeholder, the
            # trusted layer performs the deterministic host-gated fill
            # afterwards — same model as the upstream design.)
            _exec_kwargs = kwargs
            if getattr(self, "sentinel_registry", None) is not None:
                # Wave-198: thread (identity, attestation) through the
                # execution seam -- the release predicate is evaluated
                # here, authoritatively, per release (the attempt-path
                # pre-check never consumes the token's jti). The
                # attestation is resolved FRESH (TOCTOU guard); every
                # decision is audit-logged without secrets.
                _exec_kwargs = _sentinel.substitute_for_execution(
                    self.sentinel_registry, tool, kwargs,
                    identity=identity,
                    attestation=self._resolve_attestation(
                        identity.agent_id),
                    release_config=self.attestation_config,
                    audit_log=self.log,
                    run_id=self.run_id,
                    # Wave-260: every swap on the direct path goes
                    # through the per-call authorization check.
                    enforcer=getattr(self, "call_authorizer", None))[0]
            with _exchange_ledger.bind_reader(
                    identity.principal, identity.run_id,
                    action_log=self.log):
                if (self._precommit_gate is not None
                        and _precommit.is_irreversible(tool)):
                    result = self._precommit_gate.commit(
                        precommit_approval_id, tool, kwargs,
                        lambda: self._invoke_simulate(tool, _exec_kwargs,
                                                     ctx, identity))
                else:
                    result = self._invoke_simulate(tool, _exec_kwargs, ctx,
                                                  identity)
            # Wave-175 lane 1 (countersigned invocation receipts, R7 #7
            # Sigil shape): a direct-path irreversible-registry tool
            # actually executed — countersign it. Reads and
            # non-irreversible direct tools stay self-attested (the
            # receipt is evidence of consequential execution, not a
            # per-read tax). The challenge binds the write-ahead
            # execution_authorized entry's seq (direct:<seq>); the args
            # digest covers kwargs, the sentinel-bearing form the audit
            # path records — _exec_kwargs (substituted secrets) never
            # enters the receipt.
            if _precommit.is_irreversible(tool):
                self._countersign_invocation(
                    tool=tool,
                    executed_args_sentinel=kwargs,
                    holder={"agent_id": identity.agent_id,
                            "role": identity.role,
                            "principal": identity.principal,
                            "run_id": identity.run_id},
                    challenge="direct:%s" % (auth_entry.get("seq"),),
                    approval_id=None,
                    # F196: pair this receipt with the decision packet
                    # answering the same decision entry.
                    decision_seq=auth_entry.get("seq"),
                    policy_id=decision.policy_id,
                    canonical_target=ctx.get("path_resolved"),
                    preview_text=None,
                    result=result,
                    via="direct_irreversible")
            # H2 (wave-117 audit fix): the SandboxedToolBackend is a
            # drop-in _simulate replacement with no chain writer of its
            # own; it reports a contained escaping read via the
            # "traversal_contained" result marker, and the containment
            # becomes a chained event here. (The plain-executor
            # _simulate logs the event itself, so exactly one path
            # ever fires per contained read.)
            if isinstance(result, dict) and result.pop(
                    "traversal_contained", False):
                self._log_traversal_contained(
                    tool, kwargs, ctx, identity,
                    cause="path_outside_sandbox")
            # F162 (S2-GAP-1): mint deterministic synthetic usage on the
            # result (governed side; overwrites any forged _usage).
            self._mint_result_usage(tool, kwargs, result)
            # S1-MEM: memory provenance firewall (opt-in; no-op when the
            # firewall is None). Runs between execution and result
            # ingestion so a quarantined read never pollutes the run's
            # fingerprint store; may raise MemoryQuarantineError.
            self._memory_firewall_hook(tool, kwargs, result,
                                       identity.agent_id, identity.role,
                                       identity.principal)
            # S6 (wave-90, F137): raw-file-channel lineage interposition
            # (opt-in; no-op when the tracker is None). Stamps
            # agent-driven writes, records read contacts, propagates
            # taint — the file channel carries lineage like the bus.
            self._lineage_file_hook(tool, kwargs, result,
                                    identity.agent_id)
            self._ingest_result(tool, result, identity.principal,
                                source_key=_fingerprint_source_key(
                                    tool, kwargs))
            # Row-13 closure: classification label taint on successful
            # read_file (provenance-based; paraphrase cannot shed it).
            self._classification_taint_on_read(tool, kwargs, result)
            # Wave-141 (row 13): automatic read observation — a real
            # governed read_file observes itself into the rare-token
            # tracker (no explicit note_read_output needed). Real
            # sandbox bytes only; never raises, never breaks the read.
            self._rare_token_observe_on_read(tool, kwargs, result,
                                             identity.agent_id)
            # Wave-152 (row 19): automatic propagation observation -- a
            # real governed read_file observes itself into the
            # injection-propagation tracker (no explicit
            # note_propagation_input needed). Real sandbox bytes only;
            # never raises, never breaks the read.
            self._propagation_observe_on_read(tool, kwargs, result,
                                              identity.agent_id)
            # Row-12: register successful governed writes in the
            # artifact inventory (path, sha256, size, agent, label).
            self._artifact_register_on_write(tool, kwargs, result,
                                             identity.agent_id)
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
            # F139/F140: cross-run upload memory for citation provenance --
            # every executed upload-shaped call (http_post, api_call)
            # leaves a URL-bearing record in the shared ledger (no-op
            # for other tools / no ledger).
            # F142: capture response-minted resource URLs at the
            # execution boundary, so the plant record is indexed under
            # the URLs the API response minted (extraction is
            # fail-open: it never breaks the result path).
            # H3 (F142 Leg-A residual, wave-117): also capture content
            # hashes for http_post. The F12-redaction summary erases the
            # payload's string leaves, so hash the RAW payload (pre-DLP,
            # at the execution boundary) — hashes only, never the raw
            # content; one-way, same as api_call's hashes. Fail-open:
            # hashing must never break the execution path.
            response_urls = ()
            content_hashes = None
            if tool in ("http_post", "api_call"):
                response_urls = _citation_provenance.extract_response_urls(
                    tool, result,
                    endpoint=redacted_args.get(
                        "endpoint" if tool == "api_call" else "url"))
            if tool == "http_post":
                try:
                    content_hashes = _citation_provenance.\
                        payload_content_hashes(kwargs.get("payload"))
                except Exception:  # noqa: BLE001 - fail-open hashing
                    content_hashes = None
            self._record_upload(tool, redacted_args, identity.principal,
                                identity.agent_id,
                                response_urls=response_urls,
                                content_hashes=content_hashes)
            _exec_entry = {
                "decision": "allowed_executed",
                "policy_id": decision.policy_id,
                "matched_rules": decision.matched_rules,
                "reason": decision.reason,
                "flag": decision.flag,
                "result_summary": self._summarize(tool, result),
                "authorization_seq": auth_entry["seq"],
                # F142: response-minted resource URLs captured at the
                # execution boundary (for response-URL alias indexing).
                "response_urls": list(response_urls),
                # F162 (S2-GAP-1): metered accounting, chained and
                # tamper-evident: this execution's minted usage plus
                # the per-run accrued meter.
                "usage": dict((result.get("_usage") or {})),
                "budget_meter": self._budget_meter(),
            }
            if _sw_verified_bytes is not None:
                # F184: the skill handoff, audit-chained. Hash only
                # (F12-safe: one-way); the bytes themselves ride the
                # returned result below, retrievable via
                # verified_skill_bytes(). The consumer MUST execute
                # those bytes — a re-read voids this attestation, and
                # the digest lets an auditor verify the consumer used
                # the attested bytes.
                _exec_entry["skill_id"] = _skill_id
                _exec_entry["skill_attested_digest"] = _sw_attested_digest
            entry = self.log.append(_base(_exec_entry))
            # Row-20 (wave-151 lane 2): read/write rendezvous check at
            # the execution boundary -- triage tier, never blocking.
            # Runs AFTER the audit append so the IO record carries the
            # real event seq; kwargs are the RAW args at the boundary
            # (byte counts are computed, values never logged).
            self._check_covert_channel(tool, kwargs, result,
                                       identity.principal,
                                       identity.agent_id,
                                       identity.run_id, entry["seq"])
            _exec_result = {"status": "executed", "result": result,
                            "seq": entry["seq"]}
            if _sw_verified_bytes is not None:
                # F184 handoff: JSON-safe fields only — the raw bytes
                # stay out of the result dict (run_tool_loop serializes
                # results into the model transcript; bytes would leak
                # as a repr). The consumer retrieves the attested bytes
                # via verified_skill_bytes(skill_id) and MUST execute
                # them instead of re-reading the source.
                _exec_result["skill_id"] = _skill_id
                _exec_result["skill_attested_digest"] = _sw_attested_digest
            return _exec_result

        if decision.effect == "deny":
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": decision.policy_id,
                "matched_rules": decision.matched_rules,
                "reason": decision.reason,
                "flag": decision.flag,
                # Decision-trace replay lane: the replayable trace for
                # this verdict (see gov/decision_replay.py).
                "decision_trace": _decision_trace(),
                # F196 (MATCH re-binding): the exact policy-decision dict
                # the decision packet's decision_digest commits to.
                "policy_decision": decision.to_dict(),
            }))
            # Wave-176 (OpenShell steal #2): the constructive decision
            # packet for the FINAL deny verdict, chained immediately
            # under the denial's own entry. A denied policy decision
            # gets its packet too -- denials are the refusals an
            # auditor needs to reconstruct (counterexample + repair
            # hint included).
            self._emit_decision_packet(
                decision="deny",
                decision_seq=entry.get("seq"),
                head_digest=entry.get("hash"),
                tool=tool,
                redacted_args=redacted_args,
                policy_decision=decision,
                policy=policy,
                policy_ctx_snapshot=policy_ctx_snapshot,
                identity=identity,
                skill_id=_skill_id,
                skill_attested_digest=_sw_attested_digest)
            return {"status": "denied", "reason": decision.reason,
                    "policy_id": decision.policy_id, "seq": entry["seq"]}

        # require_approval: queue for a human, do NOT execute.
        provenance = ("untrusted_influenced" if self._tainted
                      else "agent_direct")
        # F-RA3 (wave-120): an escaping read quarantined by policy is
        # LOUD at the quarantine seam -- the chained
        # sandbox_traversal_contained event fires here (not only at
        # execution), so the traversal attempt is visible even when
        # the approval is denied and _simulate never runs. Deduped
        # against the _simulate seam (approved sweep) via the emitted
        # set: exactly one event per (agent, tool, path, cause).
        if (tool == "read_file"
                and "quarantine-outside-reads"
                in (decision.matched_rules or [])):
            self._log_traversal_contained(
                tool, kwargs, ctx, identity,
                cause="path_outside_sandbox")
        # H3 (F142 Leg-A residual, wave-117): stash http_post payload
        # content hashes at queue time so the approved sweep can bind
        # the upload record to the payload content. Hashes only
        # (hex digests, F12-safe: they are one-way and never show raw
        # content); the approval queue record is HMAC-bound by the
        # ApprovalQueue like the rest of the action dict.
        queued_content_hashes = []
        if tool == "http_post":
            try:
                queued_content_hashes = _citation_provenance.\
                    payload_content_hashes(kwargs.get("payload"))
            except Exception:  # noqa: BLE001 - fail-open hashing
                queued_content_hashes = []
        approval_action = {"tool": tool, "args": redacted_args,
                           "identity": identity.as_dict(),
                           "agent_justification": justification,
                           "redactions": redactions,
                           "content_sha256_set": queued_content_hashes}
        # F184 (queue-time skill attestation) is now carried as
        # explicit queue() parameters below (MAC-bound on the record
        # from birth via _SECURITY_PAYLOAD_FIELDS) rather than in the
        # action dict, which queue() does not preserve. See the
        # skill_id= / skill_attested_digest= kwargs on the queue()
        # call.
        # Wave-129 (row-7 intent slice): run the advisory judge when
        # the operator provided user-turn context. The verdict is
        # stamped MAC-bound on the record for human review; the judge
        # never denies and never breaks queueing (None when inert).
        intent_slice_verdict = self._intent_slice_verdict(
            tool, redacted_args, justification, identity)
        # Wave-266 (F248): the machine-generated reconstructed-intent
        # banner leads the preview when the run's untrusted chunks
        # jointly completed this action's directive (the record keeps
        # the original policy's id/flag; the banner is how the human
        # reviewer sees the forcing -- the wave-89 deferred-effect
        # banner pattern).
        _reconintent_banner = ""
        if (_reconintent_verdict is not None
                and _reconintent_verdict.get("suspect")):
            _reconintent_banner = (
                _reconintent.preview_banner(
                    _reconintent_verdict) + " ")
        # Wave-279 (F300): the instruction-provenance grant seam's
        # rendered section ({"text", "code"}), stamped MAC-bound on the
        # record -- the approver-facing consent surface the F294
        # closure promises. Rendered here from the early grant
        # decision, with the SAME redacted args that will execute
        # (F12: the section never sees unredacted secrets). Inert
        # (None) when the seam allowed the action or was never armed.
        _prov_section = None
        if (prov_decision is not None
                and prov_decision.routed_to_approval
                and prov_decision.code):
            prov_req.args = (dict(redacted_args)
                             if isinstance(redacted_args, dict) else {})
            _prov_section = (
                _instruction_provenance.render_provenance_section(
                    prov_req, prov_decision))
        # Wave-320 (grant wiring): the require_approval path consumes
        # presented grants. The wave-319 advisory check ran only on the
        # direct-allow path; a grant presented with a queued call was
        # silently dropped. Run the same advisory check at queue time
        # (tighten-only, never loosens the deterministic policy):
        #   - "refused" -> deny loudly here, before the human ever sees
        #     the approval request (a forged/stolen/expired/scope-wrong
        #     grant must not reach a human for rubber-stamping);
        #   - "verified" -> bind the grant MAC-covered into the approval
        #     record (presented_grant=) for the sweep-time re-verification;
        #   - "absent"/"not-applicable" -> bind explicit None; the
        #     existing policy path is unchanged (advisory-only-tighten).
        # The presenter is the F42 session-authenticated caller, so a
        # grant presented by a different identity than its audience
        # refuses here (grantneg-audience-mismatch) -- the wave-320
        # residual-(1) closure on the queue path.
        _presented_grant_queue_status = None
        if _presented_grant is not None:
            (_presented_grant_queue_status,
             _presented_grant_queue_detail) = (
                grant_negotiation.advisory_check(
                    getattr(self, "_grant_registry", None), tool,
                    _presented_grant, identity.agent_id, args=kwargs))
            if _presented_grant_queue_status == "refused":
                _grant_deny_entry = self.log.append(_base({
                    "decision": "denied",
                    "policy_id": "grant-advisory",
                    "flag": ("grantneg_"
                             + _presented_grant_queue_detail["code"]
                             .replace("-", "_")),
                    "matched_rules": [],
                    "reason": ("Refusing to queue: the presented grant "
                               "failed verification (%s): %s"
                               % (_presented_grant_queue_detail["code"],
                                  _presented_grant_queue_detail["reason"])),
                }))
                return {"status": "denied",
                        "reason": _grant_deny_entry["reason"],
                        "policy_id": "grant-advisory",
                        "seq": _grant_deny_entry["seq"]}
        approval_id = self.approvals.queue(
            approval_action, decision, provenance,
            # F12: the preview is built from the SAME redacted args that
            # will execute — preview, digest, and execution all agree.
            # Wave-89 (stream s5-tool): the machine-generated
            # deferred-effect banner leads the preview when the call
            # plants a later-firing trigger (agent prose never gets to
            # soften it).
            (_reconintent_banner
             + ((_tool_continuity.deferred_preview_banner(_deferred)
                 + " " + self._preview(tool, redacted_args))
                if _deferred is not None
                else self._preview(tool, redacted_args))),
            policy_hash=policy.policy_hash,
            # Wave-89 (stream s5-tool): the tool-definition digest pinned
            # at queue time and the deferred-effect details ride the
            # record MAC-bound (see _SECURITY_PAYLOAD_FIELDS) — the
            # sweep re-verifies the digest, and a stripped deferred
            # marker breaks the digest.
            tool_digest=self._tool_inventory.digest_for(tool),
            deferred_effect=_deferred,
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
            # Wave-154 (rows 11/18): the session's verified
            # identity-delegation receipt (sub/act/delegator_chain/
            # scope/session_id + token refs) rides on the approval
            # record MAC-bound, so the human's decision record names
            # the delegation path the action runs under. Explicit None
            # for direct (non-delegated) executions — never ambiguous.
            delegation_receipt=self._session_delegation_receipt(),
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
            matched_rules=decision.matched_rules,
            # Wave-129 (row-7 intent slice): the advisory judge's
            # verdict, MAC-bound from birth for the human reviewer.
            intent_slice_verdict=intent_slice_verdict,
            # F185 (row-6/14 approval-time re-verification lane): the
            # queue-time skill attestation rides the record MAC-bound
            # from birth so the approved sweep can re-verify it
            # against CURRENT skill bytes (see _execute_approved_locked).
            # The bytes themselves are NOT attached: they would be
            # stale by approval time.
            skill_id=_skill_id,
            skill_attested_digest=_sw_attested_digest,
            # Wave-279 (F300): the instruction-provenance grant seam's
            # rendered section ({"text", "code"}), MAC-bound from birth
            # -- the approver-facing consent surface. None when the
            # seam is inert or allowed the action.
            instruction_provenance=_prov_section,
            # Wave-317: sealed provenance segments from the
            # producer wiring above (origin-graded at ingestion).
            # MAC-bound from birth; None when the call carried no
            # provenance context (the sweep skips -- unchanged).
            provenance_segments=self._build_provenance_segments(
                justification, identity),
            # Wave-319: the agent's attested workload identity document
            # (advisory claim, MAC-bound; verified:false never gates).
            # None when the deployment carries no workload identity --
            # the queue stamps an explicit None (additive skip).
            attested_identity=(
                {"document": self._agent_svid,
                 "presented_selectors": self._agent_svid_selectors}
                if self._agent_svid is not None else None),
            # Wave-320 (grant wiring): the queue-time verified grant,
            # MAC-bound into the record; None when no grant was
            # presented or the advisory outcome was not verified.
            presented_grant=(
                _presented_grant
                if _presented_grant_queue_status == "verified" else None))
        entry = self.log.append(_base({
            "decision": "queued_pending",
            "policy_id": decision.policy_id,
            "matched_rules": decision.matched_rules,
            "reason": decision.reason,
            "flag": decision.flag,
            "approval_id": approval_id,
            # Decision-trace replay lane: the replayable trace for
            # this verdict (see gov/decision_replay.py).
            "decision_trace": _decision_trace(),
            # F196 (MATCH re-binding): the exact policy-decision dict
            # the decision packet's decision_digest commits to.
            "policy_decision": decision.to_dict(),
        }))
        # Wave-176 (OpenShell steal #2): the constructive decision
        # packet for the FINAL queue verdict, chained immediately under
        # the queued_pending entry and carrying the approval_id the
        # queue just minted. A require_approval is a decision too --
        # the packet names what queued it and why, so the human's
        # decision record is reconstructable offline.
        self._emit_decision_packet(
            decision="queue",
            decision_seq=entry.get("seq"),
            head_digest=entry.get("hash"),
            tool=tool,
            redacted_args=redacted_args,
            policy_decision=decision,
            policy=policy,
            policy_ctx_snapshot=policy_ctx_snapshot,
            identity=identity,
            skill_id=_skill_id,
            skill_attested_digest=_sw_attested_digest,
            approval_id=approval_id)
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

    def persist_skill_pins(self):
        """Persist skill pins to the configured pin file (atomic, 0600).

        No-op when no watcher or no pin path is configured. Raises
        PinStoreError LOUD on write failure — a deployment that cannot
        persist its pins must know, not silently run on memory-only
        pins that a restart would forget.

        H22: the manifest is MAC-authenticated with the operator key
        (same custody as the audit log) — a run-dir writer who
        rewrites pins cannot re-anchor trust silently.
        """
        if self._skill_watch is None or self._skill_pin_path is None:
            return None
        from . import keyprovider as _kp
        _pin_key, _ = _kp.resolve_active_key()
        return _skill_watch.PinStore.save(self._skill_watch,
                                          self._skill_pin_path,
                                          mac_key=_pin_key)

    def verified_skill_bytes(self, skill_id):
        """F184 (row-6/14 wiring lane): the skill handoff accessor.

        Returns the EXACT bytes the watcher's use-time check attested
        for the most recent :meth:`call` that attributed to
        ``skill_id`` — the same bytes object the pin was checked
        against (fetch_verified_at_use: single read, hash, handoff).
        The deployment's consumer MUST execute these bytes instead of
        re-reading the skill source; a re-read after the check can
        return different bytes (the V2 window), voiding the
        attestation. Compare ``hashlib.sha256(returned).hexdigest()``
        against the ``skill_attested_digest`` on the call's result
        and audit record.

        Returns None when no handoff is available: no watcher
        installed, the last call was unattributed, the last call was
        denied/queued, the skill id does not match the last verified
        call, or any later call() has since run (the slot holds only
        the LATEST verification — a consumer must retrieve the bytes
        before its next call). Never raises.
        """
        try:
            h = self._sw_handoff
        except AttributeError:
            return None
        if h is None or h[0] != skill_id:
            return None
        return h[2]

    def run_skill_sweep(self):
        """Run the scheduled skill-content sweep (the periodic trigger).

        This tree has no in-process scheduler: the DEPLOYMENT's
        scheduler/heartbeat calls this method every
        ``skill_watch.SWEEP_INTERVAL_SECONDS`` (300s). The sweep
        re-hashes EVERY registered skill (no stat prefilter — this is
        the backstop that defeats forged mtime/size), quarantines
        mutations/unverifiable skills fail-closed, chains a
        ``skill_sweep_completed`` event into the audit log, persists
        pins, and returns the report dict.

        On mismatch the skill is quarantined: its tool calls are denied
        at use time (see the call() gate) until an explicit operator
        ``request_repin`` + ``approve_repin`` lifts the quarantine.
        There is no silent auto-update, ever.
        """
        if self._skill_watch is None:
            return {"checked": 0, "clean": [], "mutated": [],
                    "unverifiable": [], "watcher": "not-installed"}
        report = self._skill_watch.verify_all()
        self._last_skill_sweep_at = time.time()
        self.persist_skill_pins()
        return report

    def persist_discovery_pins(self):
        """Persist discovery definition pins (atomic JSON).

        No-op when no registry or no pin path is configured. Raises
        RegistryStoreError LOUD on write failure -- a deployment
        that cannot persist its pins must know, not silently run on
        memory-only pins that a restart would forget.
        """
        if self._discovery_scan is None \
                or self._discovery_pin_path is None:
            return None
        return _discovery_scan.RegistryStore(
            str(self._discovery_pin_path)).save(self._discovery_scan)

    def run_discovery_scan(self, observe):
        """Run the scheduled discovery re-scan (the periodic trigger).

        This tree has no in-process scheduler: the DEPLOYMENT's
        scheduler/heartbeat calls this method (recommended: every
        300s, the ``skill_watch`` sweep interval). ``observe`` is the
        deployment's sandboxed discovery function returning the
        currently observed components. The scan re-hashes every
        discovered tool definition and diffs against pins: drift ->
        fail-closed hold (quarantine), first sighting -> hold until
        pinned. Chains a ``discovery_scan_completed`` event into the
        audit log (carrying the coverage matrix), persists pins, and
        returns the report dict.

        Pins persist automatically after each scan; the deployment
        reloads them at startup via ``RegistryStore.load()`` (the
        executor also merges the stored pins into the live registry
        at construction when ``discovery_pin_path`` names an
        existing file).

        On drift the tool is quarantined: its calls are denied at
        use time (see the call() gate) until a governed
        ``request_repin`` + ``approve_repin`` lifts the quarantine.
        There is no silent auto-update, ever.
        """
        if self._discovery_scan is None:
            return {"checked": 0, "clean": [], "drifted": [],
                    "unregistered": [], "withdrawn": [], "held": [],
                    "coverage_matrix": {},
                    "registry": "not-installed"}
        report = self._discovery_scan.run_rescan(observe)
        self._last_discovery_scan_at = time.time()
        self.persist_discovery_pins()
        self.log.append({
            "event": "discovery_scan_completed",
            "run_id": self.run_id,
            "report": {k: (len(v) if isinstance(v, list) else v)
                       for k, v in report.items()
                       if k != "coverage_matrix"},
            "coverage_matrix": report["coverage_matrix"],
        })
        return report

    def execute_approved(self):
        """Execute approved-but-not-yet-executed actions.

        Each approval is re-validated at execution time: expiry, integrity
        of the queued arguments, the run it was approved for (F38), the
        policy it was approved under, the capability assessment (F152),
        and a fresh policy evaluation. Any failure refuses the execution
        and logs why. Returns the list of executed actions.

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
                done = self._execute_approved_locked()
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
        # Row-12 second half (wave-133): the post-run artifact sweep
        # runs AFTER the queue lock is released — it needs no queue
        # state, only the sandbox and the inventory. Opt-in: with no
        # artifact_sweep installed this is a no-op.
        self._maybe_run_artifact_sweep()
        return done

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
        # F162: a tempo-paused run executes nothing — not even
        # human-approved records — until a human approves the resume.
        if self._tempo_paused:
            raise _velocity.VelocityRunPausedError(
                "run %r is paused by a velocity control: approved "
                "executions wait for a human-approved resume"
                % self.run_id)
        done = []
        ttl = self.policy.approval_ttl_hours
        # Wave-131 (row-7 revoke-after-approve): explicit, auditable
        # "revocation honoured" signal. A revoked grant is filtered out
        # of the executable set by the status check below; log one
        # approval_revoked_honoured entry per revoked grant so the
        # audit trail shows the sweep SAW the revocation and OBEYED it
        # (the vocabulary the row-7 delayed-execution battery looks
        # for). Scoped to granted-then-revoked records (decided_by set)
        # so withdrawing an undecided request stays quiet.
        for _rev in self.approvals.all():
            if (_rev.get("status") == "revoked"
                    and _rev.get("decided_by") is not None
                    and not _rev.get("executed")):
                self.log.append({
                    "event": "approval_revoked_honoured",
                    "run_id": self.run_id,
                    "agent_id": _rev.get("agent_id"),
                    "role": _rev.get("role"),
                    "tool": _rev.get("tool"),
                    "approval_id": _rev["id"],
                    "decision": "refused",
                    "policy_id": "revocation-terminal",
                    "delegation_receipt": _rev.get("delegation_receipt"),
                    "revoked_by": _rev.get("revoked_by"),
                    "reason": ("Approval %s not executed: revoked by %r "
                               "(%s); revocation is terminal and the "
                               "sweep honoured it."
                               % (_rev["id"], _rev.get("revoked_by"),
                                  _rev.get("revoked_reason")
                                  or "no reason given")),
                })
        for rec in self.approvals.all():
            if rec.get("status") != "approved" or rec.get("executed"):
                continue
            aid = rec["id"]

            def _refuse(reason, flag, policy_id="approval-execution-refused",
                        extra=None):
                self.approvals._rewrite(lambda records: [
                    dict(r, execution_refused_reason=reason)
                    if r["id"] == aid else r for r in records])
                # Row-7 (wave-136, paraphrase-resistant countermand):
                # similarity revocations carry
                # match_method="token-tversky" and match_score on the
                # refusal so the audit trail distinguishes them from
                # exact/redirect revocations. ``extra`` merges with
                # setdefault so a future base key is never overwritten
                # by caller metadata.
                _event = {
                    "event": "approval_execution_refused",
                    "run_id": self.run_id,
                    "agent_id": rec.get("agent_id"),
                    "role": rec.get("role"),
                    "tool": rec.get("tool"),
                    "approval_id": aid,
                    "decision": "refused",
                    "policy_id": policy_id,
                    "delegation_receipt": rec.get("delegation_receipt"),
                    "flag": flag,
                    "reason": reason,
                }
                if extra:
                    for _k, _v in extra.items():
                        _event.setdefault(_k, _v)
                self.log.append(_event)

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
            # Wave-320 (grant wiring): re-verify the MAC-bound queued
            # grant. The grant was verified at queue time; the sweep
            # re-verifies because (a) the grant may have expired during
            # the human-approval delay (expiry-as-revocation), (b) the
            # human-edited args may have broken scope binding, and
            # (c) the registry may have been withdrawn after queueing.
            # A swapped or stripped grant breaks the F38 MAC above
            # (integrity violation) before this check runs. The
            # presenter is the MAC-bound record agent_id (the queued
            # caller), and the args are the MAC-bound (possibly
            # human-edited) args about to execute. Refuse loudly on
            # any failure -- a queued grant must verify at execution;
            # never silently downgrade to the no-grant path.
            _queued_grant = rec.get("presented_grant")
            if _queued_grant is not None:
                (_grant_sweep_status,
                 _grant_sweep_detail) = grant_negotiation.advisory_check(
                    getattr(self, "_grant_registry", None), rec["tool"],
                    _queued_grant, rec["agent_id"], args=rec["args"])
                if _grant_sweep_status == "refused":
                    _refuse(
                        "Approval %s refused: its queued grant failed "
                        "re-verification at execution (%s: %s) -- the "
                        "grant expired, its scope no longer covers the "
                        "args, or it does not verify; refusing "
                        "fail-closed." % (
                            aid, _grant_sweep_detail["code"],
                            _grant_sweep_detail["reason"]),
                        ("grantneg_"
                         + _grant_sweep_detail["code"].replace("-", "_")),
                        policy_id="grantneg-execution-refused",
                        extra={"code": _grant_sweep_detail["code"]})
                    continue
                if _grant_sweep_status == "not-applicable":
                    # The registry is not installed or the tool is no
                    # longer registered (withdrawn after queue time).
                    # A queued grant must verify at execution; refusing
                    # loudly rather than silently downgrading. Drain the
                    # queue before withdrawing the registry.
                    _refuse(
                        "Approval %s refused: its queued grant cannot be "
                        "re-verified -- the grant registry is not "
                        "installed or the tool is no longer registered "
                        "(grantneg-registry-withdrawn). Drain the queue "
                        "before withdrawing the registry." % aid,
                        "grantneg_registry_withdrawn",
                        policy_id="grantneg-execution-refused",
                        extra={"code": "grantneg-registry-withdrawn"})
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
            # Wave-89 (stream s5-tool): re-verify the tool-definition
            # digest pinned at queue time against the inventory's CURRENT
            # definition. A provider-side description/schema swap between
            # human approval and sweep execution (the MCP rug-pull shape)
            # is refused fail-closed and audited. Bridge records never
            # reach this point (foreign-executed, skipped above); tools
            # the inventory never pinned, and non-tool records
            # (window_close), have nothing to re-verify. Pre-upgrade
            # records fail closed BEFORE this point: the wave-89 fields
            # are MAC-bound from birth, so a record MACed by the old
            # code (payload without these fields) fails
            # approval_digest_ok above with approval_integrity_violation
            # — the same fail-closed-upgrade precedent as
            # F34/F38/R11/D1/wave-24/F101/F103. queue() auto-pins the
            # default inventory's digest when the caller supplies none,
            # so every new record for an inventoried tool carries a pin.
            _pinned_digest = rec.get("tool_digest")
            _current_digest = self._tool_inventory.digest_for(rec["tool"])
            if (_pinned_digest is not None
                    and _current_digest != _pinned_digest):
                _refuse("Approval %s refused: tool %r definition "
                        "changed between approval and execution "
                        "(digest %s -> %s) — possible rug-pull; "
                        "re-approval required under the new "
                        "definition (wave-89 tool continuity)."
                        % (aid, rec["tool"],
                           (_pinned_digest or "?")[:12],
                           (_current_digest or "?")[:12]),
                        "tool_digest_mismatch")
                continue
            # F185 (row-6/14 approval-time re-verification lane):
            # re-verify the skill gate at the actual execution boundary
            # (TOCTOU guard). The verdict-path gate attested the skill
            # bytes at queue time and MAC-bound ``skill_attested_digest``
            # on the approval record for the human reviewer; a mutation
            # of the skill's bytes between approval and this sweep would
            # otherwise execute under an attestation for different
            # bytes. Re-run the watcher's use-time gate against CURRENT
            # bytes: the fetch must succeed AND the digest must still
            # equal the queue-time attestation. Any mismatch — a
            # mutation with no re-pin (quarantined), a reviewed re-pin
            # the approver never saw (digest moved), an unregistered id,
            # or any watcher error — refuses fail-closed, audited. A
            # refused record stays approved-but-unexecuted (fail-safe,
            # retriable): a NEW approval under the current attestation
            # executes. Executors with no skill watcher bound have no
            # gate to re-run and keep today's behavior; records without
            # skill fields (unattributed tools, pre-F184 records) skip.
            _sw_rec_skill = rec.get("skill_id")
            _sw_rec_digest = rec.get("skill_attested_digest")
            if (_sw_rec_skill is not None and _sw_rec_digest is not None
                    and self._skill_watch is not None):
                try:
                    (_sw_exe_ok, _sw_exe_bytes,
                     _sw_exe_detail) = self._skill_watch.\
                        fetch_verified_at_use(_sw_rec_skill)
                    if _sw_exe_ok and _sw_exe_bytes is not None:
                        _sw_exe_digest = hashlib.sha256(
                            _sw_exe_bytes).hexdigest()
                    else:
                        _sw_exe_digest = None
                    _sw_exe_err = None
                except Exception as e:  # noqa: BLE001 - fail closed, loud
                    _sw_exe_ok = False
                    _sw_exe_digest = None
                    _sw_exe_detail = "watcher-error"
                    _sw_exe_err = e
                _sw_exe_match = (
                    _sw_exe_ok and _sw_exe_digest is not None
                    and hmac.compare_digest(
                        str(_sw_exe_digest), str(_sw_rec_digest)))
                if not _sw_exe_match:
                    _refuse(
                        "Approval %s refused: skill %r bytes no longer "
                        "match the queue-time attestation (digest %s -> "
                        "%s; %s%s) — the human approved different bytes "
                        "than would now execute; re-approval required "
                        "under the current attestation (F185 skill "
                        "continuity)."
                        % (aid, _sw_rec_skill,
                           (_sw_rec_digest or "?")[:12],
                           ((_sw_exe_digest or "?"))[:12],
                           _sw_exe_detail,
                           (": %s" % _sw_exe_err)
                           if _sw_exe_err is not None else ""),
                        "skill_attestation_stale",
                        policy_id="skill-continuity-execution-refused")
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
            # Wave-198 (graduation ladder, R1 warn-fatigue): surface
            # warn-mode telemetry at this enforcement seam too. The
            # verdict path below is untouched; warnings aggregate into
            # the per-window operator digest, never agent interrupts.
            self._surface_warn_digest(decision)
            # Wave-198 (graduation ladder, §§3.4-3.5): ladder
            # escalations (warn-stale, overdue emergency reviews) are
            # chained to the operator audit trail here as well.
            self._check_ladder_escalations()
            if decision.effect == "deny":
                _refuse("Approval %s no longer permitted: %s"
                        % (aid, decision.reason), decision.flag or "policy_re_eval_deny",
                        policy_id=decision.policy_id or "approval-execution-refused")
                continue
            # Row-12 TOCTOU: the fresh _context above re-hashes every
            # referenced artifact. If the bytes changed between approval
            # and this sweep, the human approved DIFFERENT bytes than
            # would now leave — refuse, do not execute. (The general
            # sweep only refuses on deny; the artifact layer needs this
            # targeted guard because require_approval is the correct
            # check-time effect for a stale registration.)
            if ctx.get("artifact_tampered"):
                _refuse("Approval %s refused: artifact bytes changed "
                        "since approval (stale registration)." % (aid,),
                        "artifact_tampered",
                        policy_id="approval-tampered-artifact-egress")
                continue
            # F190 (canonical-target TOCTOU): the sweep-time resolved
            # canonical target must equal the queue-time resolved target
            # the receipt MAC-binds (policy_context.path_resolved). The
            # fresh _context above re-resolves through the SAME
            # _resolved_path_for_policy seam as queue time, so a symlink
            # flip (or directory rename) during the human-pending window
            # shows up here as R2 != R1 — executing would act on a
            # different canonical action object than the human approved.
            # Refuse fail-closed; re-approval required under the new
            # target. Records whose tool takes no path arg carry no
            # bound target and skip this check (zero behavior change).
            # This subsumes the wave-162 check_write_declared_path gap
            # on the approved path: a declared→undeclared flip IS a
            # target mismatch and refuses here.
            _f190_bound = (rec.get("policy_context") or {}).get(
                "path_resolved")
            if _f190_bound is not None:
                _f190_sweep = ctx.get("path_resolved")
                try:
                    _f190_match = hmac.compare_digest(str(_f190_sweep),
                                                      str(_f190_bound))
                except TypeError:
                    # Non-ASCII path components: compare_digest only
                    # handles ASCII str. Both values are
                    # governor-computed (never attacker-chosen secrets),
                    # so constant-time is not load-bearing — fall back
                    # to plain equality, still fail-closed on mismatch.
                    _f190_match = (_f190_sweep == _f190_bound)
                if not _f190_match:
                    _refuse("Approval %s refused: the resolved canonical "
                            "target changed between approval and execution "
                            "(%r -> %r) — the human approved a different "
                            "canonical action object than would now "
                            "execute; re-approval required under the new "
                            "target (F190 canonical-target continuity)."
                            % (aid, _f190_bound, _f190_sweep),
                            "canonical_target_mismatch",
                            policy_id="canonical-target-execution-refused")
                    continue
            # Wave-174 lane 2 (display≡execution; OpenClaw CVE-2026-32065):
            # the approver decided on the MAC-bound ``preview`` text. The
            # queue path builds that text with the executor's preview
            # renderer under ``sanitize_preview_text`` (plus the
            # deferred-effect banner when present); re-derive it here from
            # the exact args about to execute, under the same
            # normalization, via the single shared seam
            # (gov.approvals.verify_display_execution_preview). A mismatch
            # means the human approved different bytes than the executor
            # would act on -- trimmed display vs raw execution -- and the
            # record is refused BEFORE any side effect. Records queued
            # through the executor, canary, or sentinel paths all build
            # their preview with the same renderer, so exact re-derivation
            # holds for them; synthetic review records (custom previews,
            # non-invocable tools) are already refused at the
            # role-allowlist check above.
            _disp_ok = verify_display_execution_preview(rec, self._preview)[0]
            if not _disp_ok:
                _refuse("Approval %s refused: the approved preview does "
                        "not match the args about to execute under the "
                        "same normalization (display/execution mismatch); "
                        "the approver did not see what would execute."
                        % (aid,),
                        "display_execution_mismatch",
                        policy_id="display-execution-execution-refused")
                continue
            # Wave-176 (OpenShell steal #1, AuthorityProof contract):
            # authority-boundary continuity at execution time. The
            # boundary is operator authority and may have tightened
            # between approval and sweep (TOCTOU); re-prove the exact
            # args about to execute against the CURRENT boundary.
            # Fail-closed direction only, same as the F190 and display
            # checks above: a declared boundary with a non-within proof
            # refuses; no boundary declared (advisory mode) skips the
            # check entirely. check() never raises on hostile shapes.
            if self._authority_boundary is not None:
                _ap_args = rec.get("args") or {}
                _ap_ctx = {"sandbox_root": str(self._sandbox_resolved)}
                if isinstance(_ap_args.get("path"), str):
                    _ap_ctx["path_resolved"] = (
                        self._resolved_path_for_policy(
                            _ap_args.get("path")))
                _ap_proof = _authority_proof.check(
                    {"tool": rec.get("tool"), "args": _ap_args,
                     "agent_id": rec.get("agent_id"),
                     "role": rec.get("role")},
                    _ap_ctx, self._authority_boundary,
                    # Wave-198 lane E: the sweep re-proof re-enforces
                    # attested MCP required scopes (TOCTOU continuity:
                    # the registry may have been installed and the
                    # token may have expired since approval).
                    mcp_tool_registry=self._mcp_tool_registry,
                    token_claims=self._mcp_token_claims_for(
                        rec.get("agent_id")))
                if _ap_proof.verdict != _authority_proof.WITHIN:
                    _refuse("Approval %s refused: authority proof %r at "
                            "execution time (%s); the operator-declared "
                            "boundary no longer covers this action -- "
                            "re-approval required under the current "
                            "boundary."
                            % (aid, _ap_proof.verdict, _ap_proof.detail),
                            "authority_boundary_exceeded",
                            policy_id=
                            "authority-boundary-execution-refused")
                    continue
                # Wave-178 (F194 closure): record the execution-time
                # re-proof verdict in the chained audit log on success.
                # The re-proof ran fail-closed above (a non-within proof
                # refuses); without this entry an auditor sees only the
                # queue-time proof and must take the sweep-time re-check
                # on faith. Evidence-only: enforcement behavior is
                # unchanged, and advisory mode (no declared boundary)
                # records nothing because no re-proof ran there.
                self.log.append({
                    "event": "authority_proof_execution_reproof",
                    "run_id": self.run_id,
                    "agent_id": rec.get("agent_id"),
                    "role": rec.get("role"),
                    "principal": (rec.get("identity") or {}).get(
                        "principal"),
                    "tool": rec.get("tool"),
                    "approval_id": aid,
                    "decision": "reproof_within",
                    "policy_id": "authority-boundary-execution",
                    "proof": _ap_proof.to_dict(),
                    "reason": ("Execution-time authority re-proof for "
                               "approval %s: verdict %r against the "
                               "current operator boundary (%s v%s) -- the "
                               "boundary still covers this action at "
                               "sweep time."
                               % (aid, _ap_proof.verdict,
                                  _ap_proof.boundary_id,
                                  _ap_proof.boundary_version)),
                })
            # Wave-173 lane 1 (TMA-NM M1 act-time gate): memory-provenance
            # continuity. The human granted this approval under a
            # queue-time disclosure of the run's un-elevated memory reads
            # (policy_context.memory_provenance, MAC-bound and packet-
            # rendered). A run that read un-elevated memory AFTER the
            # disclosure -- during the human-pending window -- would
            # execute on provenance the approver never saw. Refuse
            # fail-closed; re-approval required under the current memory
            # state. A disclosed-then-granted read is informed human
            # authorization and proceeds. Records without a
            # policy_context (executor-internal synthetic approvals,
            # never agent-driven tool calls) carry no disclosure surface
            # and skip this check. Inert when the gate is not attached
            # (zero behavior change).
            if self._memory_actgate is not None:
                _ag_ok, _ag_reason = self._memory_actgate.check_execution(
                    self.run_id, rec)
                if not _ag_ok:
                    _refuse("Approval %s refused: %s"
                            % (aid, _ag_reason),
                            "memory_actgate_un_elevated",
                            policy_id="memory-actgate-execution-refused")
                    continue
            # Row-7 (wave-131, revoke-after-approve): intent re-validation
            # at the execution boundary (TOCTOU guard). The human granted
            # this approval under one intent; a countermand arriving
            # between the grant and this sweep must not execute. Re-run
            # the advisory intent-slice judge against CURRENT intent
            # context: if the action is now judged stale_intent and the
            # MAC-bound queue-time annotation did NOT flag it stale, the
            # intent materially changed after approval — auto-revoke the
            # approval (revoker "intent-system") and refuse the sweep
            # with approval_intent_changed. A human who approved DESPITE
            # a queue-time stale flag keeps their override (the record
            # stays approved). Without intent context the check is inert
            # (opt-in, zero behavior change). The judge is advisory-only:
            # paraphrase-level countermands the heuristic cannot see are
            # the documented ceiling (no re-validation fires for them).
            _intent_verdict = self._intent_slice_verdict(
                rec["tool"], rec["args"], rec.get("agent_justification"),
                None)
            _queue_slice = rec.get("intent_slice") or {}
            if (_intent_verdict is not None
                    and _intent_verdict.get("flagged")
                    and _intent_verdict.get("flag") == "stale_intent"
                    and not _queue_slice.get("flagged")):
                _intent_evidence = "; ".join(
                    str(e) for e in
                    (_intent_verdict.get("evidence") or [])[:2])
                try:
                    _revoke.revoke_approval(
                        self.approvals, aid,
                        "intent changed after approval: the latest user "
                        "message countermands this action (%s); "
                        "re-approval required under the current intent"
                        % (_intent_evidence or "no detail"),
                        _revoke.INTENT_SYSTEM)
                except ValueError as _revoke_err:
                    # Revocation is the enforcement, but the sweep still
                    # refuses fail-closed below even if the revoke
                    # itself could not complete (fail-safe, retriable).
                    _refuse("Approval %s refused: intent changed after "
                            "approval (countermand detected) and "
                            "auto-revocation failed (%s); re-approval "
                            "required under the current intent."
                            % (aid, _revoke_err),
                            "approval_intent_changed",
                            policy_id="intent-revocation")
                    continue
                _refuse("Approval %s refused: intent changed after "
                        "approval — auto-revoked (the latest user message "
                        "countermands this action); re-approval required "
                        "under the current intent." % (aid,),
                        "approval_intent_changed",
                        policy_id="intent-revocation")
                continue
            # Row-7 (wave-134, cross-run intent): consult the durable
            # intent ledger for countermands recorded AFTER this
            # approval was granted -- e.g. the user countermanded in
            # run 2 and the run-1 grant is consumed in run 3. The
            # ledger's messages since decided_at become the current
            # intent context; the same advisory judge, the same
            # queue-time-override guard, and the same auto-revoke /
            # refuse path apply as the in-run check above. Inert
            # without an intent_ledger (opt-in, zero behavior change).
            # A missing/unparseable decided_at or no later messages for
            # this principal means no attribution is possible: the
            # check skips fail-safe (it never invents a countermand).
            # The ledger hands back ALL turns at-or-before the grant
            # PLUS the later turns (F181: prior=None, not prior=1): the
            # judge's countermand detector anchors the latest message
            # against a prior instruction, so the granting turn must
            # travel with the countermand even when chatter intervenes
            # -- prior=1 kept only the immediately preceding turn, so a
            # verbatim post-chatter countermand found nothing to anchor
            # and the grant executed. This is the same context shape as
            # the wave-131 in-run path, which passes the full turn
            # list. Honest tradeoff: judge context grows linearly in
            # per-principal history at this boundary (messages_since,
            # the strictly-after anchor, is unchanged), chosen
            # deliberately -- correctness over the missed-countermand
            # fail-open.
            #
            # Guard, refined from the wave-131 in-run version: the
            # cross-run check fires only on NEW post-grant intent (at
            # least one turn strictly after decided_at). A human who
            # approved DESPITE a queue-time stale flag keeps the
            # override when nothing new was said (no post-grant turns
            # -> skip: re-litigating the seen signal would break the
            # wave-131 contract). But a genuinely new post-grant
            # countermand is information the grantor never saw, so the
            # queue-time flag does NOT suppress it -- the latest
            # instruction wins. (Ordering fidelity assumption: the
            # harness records each turn when the user speaks, so a turn
            # timestamped after decided_at really is new.)
            if self.intent_ledger is not None:
                _xr_principal = rec.get("principal")
                _xr_decided = rec.get("decided_at")
                _xr_after = (self.intent_ledger.messages_since(
                    _xr_principal, _xr_decided)
                    if _xr_principal and _xr_decided else [])
                _xr_turns = (self.intent_ledger.messages_with_context(
                    _xr_principal, _xr_decided, prior=None)
                    if _xr_after else [])
                if _xr_turns:
                    # The queue-time justification is NOT passed: it was
                    # written under the superseded intent, so it cannot
                    # constitute "fresh support" for the post-grant
                    # intent (judge_candidate's escape hatch). A stale
                    # justification sharing vocabulary with the
                    # countermand ("temp files") must not veto the flag.
                    # The action's tool/args slots still participate in
                    # the verdict.
                    _xr_verdict = _intent_slice.judge_queued_action(
                        rec["tool"], rec["args"], None,
                        user_turns=_xr_turns)
                    if (_xr_verdict is not None
                            and _xr_verdict.get("flagged")
                            and _xr_verdict.get("flag") == "stale_intent"):
                        _xr_evidence = "; ".join(
                            str(e) for e in
                            (_xr_verdict.get("evidence") or [])[:2])
                        try:
                            _revoke.revoke_approval(
                                self.approvals, aid,
                                "cross-run intent change: a user "
                                "countermand recorded in the intent "
                                "ledger after this approval was granted "
                                "countermands this action (%s); "
                                "re-approval required under the current "
                                "intent"
                                % (_xr_evidence or "no detail"),
                                _revoke.INTENT_SYSTEM)
                        except ValueError as _xr_revoke_err:
                            _refuse("Approval %s refused: cross-run "
                                    "intent changed after approval "
                                    "(countermand in the intent ledger) "
                                    "and auto-revocation failed (%s); "
                                    "re-approval required under the "
                                    "current intent."
                                    % (aid, _xr_revoke_err),
                                    "approval_intent_changed",
                                    policy_id="intent-revocation-xr")
                            continue
                        _refuse("Approval %s refused: cross-run intent "
                                "changed after approval — auto-revoked "
                                "(a later user message in the intent "
                                "ledger countermands this action); "
                                "re-approval required under the current "
                                "intent." % (aid,),
                                "approval_intent_changed",
                                policy_id="intent-revocation-xr")
                        continue
                # Row-7 (wave-136, paraphrase-resistant countermand):
                # the ledger's negation-gated similarity signal. A
                # post-grant turn carrying a negation cue and scoring
                # at/above the per-message HMAC-derived threshold (wave-138;
                # band [0.4, 0.6), mean 0.5) Tversky similarity against the
                # GRANT-context
                # intent countermands the grant even when the redirect
                # judge above could not see the paraphrase ("Please
                # refrain from sending..." -- "refrain" is a negation
                # word but not a redirect signal). Same auto-revoke /
                # refuse path; the refusal carries
                # match_method="token-tversky" and the match_score so
                # the audit trail distinguishes similarity revocations
                # from exact ones. The anchor-predates-grant guard is
                # load-bearing: similarity_countermands_after returns
                # only post-grant turns anchored to pre-grant intent,
                # so a negated paraphrase of post-grant CHATTER cannot
                # misattribute and revoke an unrelated grant (false
                # revocation). Similarity alone without negation never
                # revokes -- the gate lives in
                # gov.intent_ledger.similarity_countermand, not here.
                if _xr_principal and _xr_decided:
                    _xr_sim_hits = (
                        self.intent_ledger.similarity_countermands_after(
                            _xr_principal, _xr_decided))
                    if _xr_sim_hits:
                        _xr_sim = _xr_sim_hits[0]
                        _xr_sim_score = round(
                            _xr_sim.get("similarity_score") or 0.0, 4)
                        try:
                            _revoke.revoke_approval(
                                self.approvals, aid,
                                "cross-run intent change: a later user "
                                "message paraphrases a countermand of "
                                "the granted intent (negation-gated "
                                "similarity %.3f, method %s); "
                                "re-approval required under the current "
                                "intent"
                                % (_xr_sim_score,
                                   _target_match.MATCH_METHOD),
                                _revoke.INTENT_SYSTEM)
                        except ValueError as _xr_sim_revoke_err:
                            _refuse("Approval %s refused: cross-run "
                                    "paraphrased countermand after "
                                    "approval and auto-revocation "
                                    "failed (%s); re-approval required "
                                    "under the current intent."
                                    % (aid, _xr_sim_revoke_err),
                                    "approval_intent_changed",
                                    policy_id="intent-revocation-xr-sim",
                                    extra={
                                        "match_method":
                                            _target_match.MATCH_METHOD,
                                        "match_score": _xr_sim_score,
                                    })
                            continue
                        _refuse("Approval %s refused: cross-run intent "
                                "changed after approval — auto-revoked "
                                "(a later user message paraphrases a "
                                "countermand of the granted intent: "
                                "negation-gated similarity %.3f); "
                                "re-approval required under the current "
                                "intent." % (aid, _xr_sim_score),
                                "approval_intent_changed",
                                policy_id="intent-revocation-xr-sim",
                                extra={
                                    "match_method":
                                        _target_match.MATCH_METHOD,
                                    "match_score": _xr_sim_score,
                                })
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

            # F135 (wave-88): re-validate the three-token delegation at
            # the actual execution boundary (TOCTOU guard). The call-time
            # gate consults the revocation checker and token expiry per
            # call, but a human approval can land long after queueing: a
            # delegation revoked — or expired — between approval and this
            # sweep must not execute. Re-running enforce_tool_call
            # re-checks revocation (leaf AND ancestors), expiry, scope,
            # and the session/subject binding against CURRENT token
            # state. Refusal is fail-closed and audited like every other
            # execution-time re-validation; the record stays
            # approved-but-unexecuted (fail-safe, retriable — a fresh
            # delegation in a rebuilt executor lets a later sweep
            # execute it: the approval stands, the gate checks CURRENT
            # token state, and the queued record stores no token
            # reference to refresh).
            # Executors without a bound DelegationContext (legacy or
            # harness-ungoverned pipeline) have no gate to re-run and
            # keep today's behavior.
            if self._delegation_context is not None:
                _f135_identity = AgentIdentity(
                    agent_id=rec["agent_id"], role=rec["role"],
                    run_id=self.run_id,
                    principal=(rec.get("identity") or {}).get("principal"),
                    provenance="minted")
                try:
                    _delegation_tokens.enforce_tool_call(
                        self._delegation_context, _f135_identity,
                        rec["tool"],
                        revocation_checker=self._revocation_checker)
                except _delegation_tokens.DelegationRevokedError as e:
                    _refuse("Approval %s refused: the delegation "
                            "authorizing it was revoked after approval "
                            "(%s); revocation is re-checked at the "
                            "execution boundary." % (aid, e),
                            "delegation_revoked_at_execution",
                            policy_id="delegation-execution-refused")
                    continue
                except _delegation_tokens.DelegationExpiredError as e:
                    _refuse("Approval %s refused: the delegation "
                            "authorizing it expired after approval "
                            "(%s); token expiry is re-checked at the "
                            "execution boundary." % (aid, e),
                            "delegation_expired_at_execution",
                            policy_id="delegation-execution-refused")
                    continue
                except _delegation_tokens.DelegationError as e:
                    _refuse("Approval %s refused: the delegation "
                            "authorizing it no longer validates at "
                            "execution (%s)." % (aid, e),
                            "delegation_invalid_at_execution",
                            policy_id="delegation-execution-refused")
                    continue

            # F152 (wave-101): re-verify the capability gate at the
            # actual execution boundary (TOCTOU guard). The call() path
            # verifies the assessment on every call, but this sweep
            # previously executed with no check at all: an assessment
            # removed, expired, or downgraded between approval and the
            # sweep still executed. The gate's contract is current-state
            # verification — assessment exists, fresh, bound to this
            # harness (id + config digest), report digest matching,
            # sealed by a trusted key, aggregate verdict SUFFICIENT —
            # so the same verify_assessment the call path enforces runs
            # here. Like the F135 delegation re-validation above, the
            # queued record stores no assessment reference: a refusal
            # leaves the record approved-but-unexecuted (fail-safe,
            # retriable — a fresh assessment lets a later sweep execute
            # it). Executors with no gate bound (raw pipeline or
            # acknowledged-ungoverned mode) have no gate to re-run and
            # keep today's behavior.
            if self._capability_gate_binding is not None:
                try:
                    _capability_gate.verify_assessment(
                        self._capability_gate_binding,
                        self._capability_assessment)
                except _capability_gate.CapabilityGateRefusal as e:
                    _refuse("Approval %s refused: the capability "
                            "assessment does not verify at the execution "
                            "boundary (%s: %s) — a bound, fresh, sealed "
                            "SUFFICIENT assessment is required for "
                            "governed execution." % (aid, e.refusal_cause,
                                                     e),
                            "capability_gate_failed_at_execution",
                            policy_id="capability-gate-execution-refused")
                    continue

            # F162: charge the per-class tempo wire at this execution
            # boundary too (approved executions are executions). A trip
            # pauses the run fail-closed before the side effect. There
            # is no calling identity on the sweep path: the trip record
            # carries the approval record's agent info, and resume
            # requires an operator-filed velocity_resume approval.
            _rec_identity = rec.get("identity") or {}
            self._charge_tempo(
                None, rec["tool"],
                audit_identity={
                    "agent_id": rec.get("agent_id"),
                    "role": rec.get("role"),
                    "principal": _rec_identity.get("principal"),
                })
            # Wave-313 (Row 7 step 3): capability/argument-bound approval
            # token. decide() mints the token and MAC-binds it on the
            # record; the sweep re-verifies it here as an ADDITIONAL
            # check -- seal, expiry, capability, argument binding, and
            # replay against the nonce ledger. A token minted for
            # (tool, args) never authorizes a different tool or
            # different args, so a decomposed trajectory that reuses
            # step 1's token for step 3's harmful variant is refused
            # here. Records with no token (pre-wave-313 records, or any
            # path that did not mint one) skip this check entirely --
            # existing behavior is unchanged when no token is
            # presented. The nonce is NOT consumed here: consumption
            # happens after the durable claim (mark_executed) below, so
            # a record refused by a later gate keeps its token
            # unconsumed and retriable.
            _ap_token = rec.get("approval_token")
            _ap_token_body = None
            if _ap_token is not None:
                try:
                    _ap_token_body = _approval_tokens.verify_token(
                        _ap_token, capability=rec["tool"],
                        args=rec["args"],
                        consume_store=self._approval_token_store)
                except _approval_tokens.ApprovalTokenError as e:
                    _refuse("Approval %s refused: its capability/argument-"
                            "bound approval token failed verification "
                            "(%s: %s) -- the presented action does not "
                            "match what the token authorizes; re-approval "
                            "required." % (aid, e.code, e),
                            "approval_token_invalid",
                            policy_id="approval-token-execution-refused",
                            extra={"code": e.code})
                    continue
            # Wave-314 (Row 7 step 5): provenance-graded sink policy. An
            # ADDITIONAL check, run only when the record carries labeled
            # provenance segments (rec["provenance_segments"]); records
            # without segments skip it entirely -- existing behavior is
            # unchanged when no provenance context is present (the lane-B
            # token-check discipline). REFUSE/ESCALATE block the call
            # fail-closed; REDACT rewrites the args to opaque refs and
            # the call continues with the redacted form.
            _pv_segments = rec.get("provenance_segments")
            if _pv_segments is not None:
                # Wave-316 (F399): pass the run-scoped sink so the
                # re-plan budget ratchet, quarantine set, and
                # consumed-declassification set persist across calls.
                _pv_verdict = _provenance_sink.provenance_gate(
                    rec["tool"], rec["args"], _pv_segments,
                    sink=self._pv_sink)
                if _pv_verdict is not None and \
                        _pv_verdict.verdict in ("REFUSE", "ESCALATE"):
                    _refuse("Approval %s refused: the provenance-graded "
                            "sink policy %s the call (%s: %s) -- the "
                            "influencing context does not meet the tool's "
                            "required trust; re-plan or declassify."
                            % (aid, _pv_verdict.verdict.lower(),
                               _pv_verdict.code, _pv_verdict.detail),
                            "provenance_sink_refused",
                            policy_id="provenance-sink-execution-refused",
                            extra={"code": _pv_verdict.code})
                    continue
                if _pv_verdict is not None and \
                        _pv_verdict.verdict == "REDACT":
                    rec["args"] = dict(_pv_verdict.redacted_args or {})
                    self.log.append({
                        "event": "provenance_redacted",
                        "run_id": rec.get("run_id", self.run_id),
                        "agent_id": rec.get("agent_id"),
                        "approval_id": aid,
                        "code": _pv_verdict.code,
                    })
            # Write-ahead audit (fail-closed): the authorization is durably
            # logged BEFORE the side effect. If this append raises, the tool
            # is never touched.
            _exec_ctx_snapshot = {
                "path_outside_sandbox": ctx.get("path_outside_sandbox"),
                "domain_allowlisted": ctx.get("domain_allowlisted"),
                "carries_read_content": ctx.get("carries_read_content"),
                "read_sensitive": ctx.get("read_sensitive"),
                # Row-13 classification provenance (2026-09-26): same
                # contract as the pre-execution snapshot path.
                "read_classified": ctx.get("read_classified"),
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
                # Wave-154 (rows 11/18): the receipt rides from the
                # MAC-bound approval record onto the execution entry —
                # the sweep stamps what the human approved, never a
                # re-minted value (explicit None for direct records).
                "delegation_receipt": rec.get("delegation_receipt"),
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
            # Wave-313 (Row 7 step 3): consume the approval token's
            # nonce AFTER the durable claim, BEFORE the side effect.
            # Ordering: verify-first (above) keeps a refused-later
            # record retriable; consume-after-claim keeps a crashed
            # sweep from double-consuming. The claim already guarantees
            # at-most-once across processes; the nonce ledger adds the
            # token-level guarantee. This cannot fail: the nonce was
            # verified unconsumed above, in this process, under the
            # queue lock, with no awaits in between -- a replay here
            # would be an internal bug, and it must be loud, never a
            # silent execution.
            if _ap_token_body is not None:
                self._approval_token_store.consume(
                    _ap_token_body["nonce"])
            # F164 (HIGH): same ambient-reader binding as the direct
            # path -- the approval record carries the acting identity
            # (principal/run_id) for attribution, so approved read_file
            # executions are policy-checked and recorded on the F163
            # exchange ledger too.
            with _exchange_ledger.bind_reader(
                    (rec.get("identity") or {}).get("principal"),
                    rec.get("run_id", self.run_id),
                    action_log=self.log):
                # F-RA3 (H2): the approved sweep carries the acting
                # identity on the record; pass it through so a loud
                # traversal containment names the right agent.
                _approved_identity = {
                    "agent_id": rec.get("agent_id"),
                    "role": rec.get("role"),
                    "principal": (rec.get("identity") or {}).get(
                        "principal"),
                    "run_id": rec.get("run_id", self.run_id),
                }
                # Sentinel substitution at the execution boundary: the
                # record's MAC-bound args are sentinel-bearing (the
                # human approved the placeholder form); the real values
                # go ONLY into this ephemeral copy, re-validated
                # fail-closed against the CURRENT vault bindings. The
                # write-ahead audit entry above already logged the
                # sentinel-bearing args, and every hook below keeps
                # rec["args"] — the secret never enters the audit path.
                _exec_args = rec["args"]
                if getattr(self, "sentinel_registry", None) is not None:
                    # Wave-198: approved path threads (identity,
                    # attestation) too -- the attested session is
                    # re-derived from the approval record (agent id +
                    # run id) and the token resolved FRESH, so an
                    # attestation revoked while the approval was
                    # pending is caught at this boundary.
                    _exec_args = _sentinel.substitute_for_execution(
                        self.sentinel_registry, rec["tool"], rec["args"],
                        identity=_approved_identity,
                        attestation=self._resolve_attestation(
                            _approved_identity.get("agent_id")),
                        release_config=self.attestation_config,
                        audit_log=self.log,
                        run_id=_approved_identity.get(
                            "run_id", self.run_id),
                        # Wave-260: every swap on the approved sweep
                        # goes through the per-call authorization check.
                        enforcer=getattr(self, "call_authorizer", None))[0]
                result = self._invoke_simulate(rec["tool"], _exec_args, ctx,
                                              _approved_identity)
            # Wave-175 lane 1 (countersigned invocation receipts, R7 #7
            # Sigil shape): the approved sweep executed a consequential
            # (human-authorized) invocation — countersign what ACTUALLY
            # executed. The args digest covers rec["args"], the
            # sentinel-bearing MAC-bound form the human approved and the
            # audit path records; _exec_args (substituted secrets) never
            # enters the receipt.
            self._countersign_invocation(
                tool=rec["tool"],
                executed_args_sentinel=rec["args"],
                holder={"agent_id": rec.get("agent_id"),
                        "role": rec.get("role"),
                        "principal": (rec.get("identity") or {}).get(
                            "principal"),
                        "run_id": rec.get("run_id", self.run_id)},
                challenge=aid,
                approval_id=aid,
                policy_id=rec.get("policy_id"),
                canonical_target=(rec.get("policy_context") or {}).get(
                    "path_resolved"),
                preview_text=rec.get("preview"),
                result=result,
                via="approved_sweep")
            # F162 (S2-GAP-1): mint governed-side usage on the result.
            self._mint_result_usage(rec["tool"], rec["args"], result)
            # S1-MEM: memory provenance firewall (opt-in; no-op when None).
            self._memory_firewall_hook(
                rec["tool"], rec["args"], result,
                rec.get("agent_id"), rec.get("role"),
                (rec.get("identity") or {}).get("principal"))
            # S6 (wave-90, F137): raw-file-channel lineage interposition
            # (opt-in; no-op when the tracker is None) — approved
            # executions stamp/contact exactly like direct calls.
            self._lineage_file_hook(
                rec["tool"], rec["args"], result, rec.get("agent_id"))
            self._ingest_result(rec["tool"], result,
                                (rec.get("identity") or {}).get("principal"),
                                source_key=_fingerprint_source_key(
                                    rec["tool"], rec.get("args")))
            # Row-13 closure: classification label taint on successful
            # read_file, mirroring the direct-call path above.
            self._classification_taint_on_read(rec["tool"], rec["args"],
                                               result)
            # Wave-141 (row 13): automatic read observation on the
            # approved path too — an approved read_file observes
            # itself exactly like a direct one.
            self._rare_token_observe_on_read(rec["tool"], rec["args"],
                                             result, rec.get("agent_id"))
            # Wave-152 (row 19): automatic propagation observation on
            # the approved path too -- an approved read_file observes
            # itself exactly like a direct one.
            self._propagation_observe_on_read(rec["tool"], rec["args"],
                                              result, rec.get("agent_id"))
            # Row-12: register successful governed writes, mirroring the
            # direct-call path (an approved write_file enters the
            # inventory exactly like a direct one).
            self._artifact_register_on_write(rec["tool"], rec["args"],
                                             result,
                                             rec.get("agent_id"))
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
            # F139/F140: cross-run upload memory for citation provenance --
            # the approved upload-shaped call leaves a URL-bearing record
            # in the shared ledger (rec["args"] are the redacted approval
            # args).
            # F142: capture response-minted resource URLs at the
            # execution boundary, so the plant record is indexed under
            # the URLs the API response minted (extraction is
            # fail-open: it never breaks the result path).
            # H3 (F142 Leg-A residual, wave-117): http_post payload
            # content hashes ride MAC-bound on the approval record from
            # queue time (gov/approvals.py), so the sweep binds the
            # record to exactly the payload the human approved — the
            # redacted queue form is a summary the hashes cannot be
            # recovered from. .get default: pre-upgrade records.
            approved_response_urls = ()
            approved_content_hashes = None
            if rec["tool"] in ("http_post", "api_call"):
                approved_response_urls = \
                    _citation_provenance.extract_response_urls(
                        rec["tool"], result,
                        endpoint=rec["args"].get(
                            "endpoint" if rec["tool"] == "api_call"
                            else "url"))
            if rec["tool"] == "http_post":
                approved_content_hashes = rec.get("content_sha256_set")
            self._record_upload(rec["tool"], rec["args"],
                                (rec.get("identity") or {}).get("principal"),
                                rec.get("agent_id"),
                                response_urls=approved_response_urls,
                                content_hashes=approved_content_hashes)
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
                # F142: response-minted resource URLs captured at the
                # execution boundary (for response-URL alias indexing).
                "response_urls": list(approved_response_urls),
                # F162 (S2-GAP-1): metered accounting on the chained
                # log (this execution's usage + per-run meter).
                "usage": dict((result.get("_usage") or {})),
                "budget_meter": self._budget_meter(),
            })
            # Row-20 (wave-151 lane 2): read/write rendezvous check at
            # the approved-execution boundary -- triage tier, never
            # blocking. Runs AFTER the audit append so the IO record
            # carries the real event seq; _exec_args are the raw
            # sentinel-substituted execution args (byte counts are
            # computed, values never logged).
            self._check_covert_channel(rec["tool"], _exec_args, result,
                                       (rec.get("identity") or {}).get(
                                           "principal"),
                                       rec.get("agent_id"),
                                       rec.get("run_id", self.run_id),
                                       entry["seq"])
            # F39: the durable claim (mark_executed) happened BEFORE the
            # side effect above — nothing to mark here.
            done.append({"agent_id": rec.get("agent_id"),
                         "tool": rec["tool"], "seq": entry["seq"]})
        return done
