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
import time
import collections.abc
import itertools
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import dlp
from .approvals import (IdentityVerifierAlreadySetError, approval_digest_ok,
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
    registered_domain,
)
from .identity import (
    AgentIdentity,
    IdentityMintLimitError,
    UnmintedIdentityError,
    UnregisteredPrincipalError,
    warn_self_asserted_identity_once,
)
from .log import (newest_refusal_ts_per_flag, read_entries,
                   refusal_ts_within_window, verify_chain,
                   verify_chain_tip, write_chain_tip_from_tail)

_SEND_TOOLS = ("send_email", "http_post")
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
                 principal_registry=None, session_identity=None):
        self.run_dir = Path(run_dir)
        self.run_id = self.run_dir.name
        self.policy = policy
        self.log = log
        self.approvals = approvals
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
        if not host:
            return False
        return any(host == d.lower() or host.endswith("." + d.lower())
                   for d in allow)

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

    def _context(self, tool, args, principal=None, record_ledger=True,
                 agent_id=None):
        ctx = {"api_calls": self.api_calls, "counters": dict(self.counters)}
        if "path" in args:
            ctx["path_outside_sandbox"] = self._is_outside_sandbox(args["path"])
        if tool in _SEND_TOOLS:
            ctx["domain_allowlisted"] = self._domain_allowlisted(tool, args)
            ctx["carries_read_content"] = self._carries_read_content(tool, args)
        elif tool == "api_call":
            # F1: api_call params are an outbound-shaped payload to a
            # third-party endpoint; correlate them against prior reads the
            # same way sends are correlated. (No egress-allowlist check here:
            # api_call destinations are not allowlisted by policy.)
            ctx["carries_read_content"] = self._carries_read_content(tool, args)
            # F9/F15: run-scoped taint — this run ingested DLP-sensitive
            # content — OR principal-scoped taint inherited from the
            # ledger: a fresh run for the same principal whose earlier run
            # read sensitive content starts tainted inside the 24h TTL.
            ctx["read_sensitive"] = (
                self._read_sensitive
                or self._principal_taint_active(principal))
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
        ctx["source_untrusted"] = self._tainted
        return ctx

    # -- simulated tools ---------------------------------------------------

    def _simulate(self, tool, args, ctx):
        if tool == "read_file":
            p = self._resolve(args["path"])
            if not ctx.get("path_outside_sandbox") and p.is_file():
                return {"source": "sandbox",
                        "content": p.read_text(encoding="utf-8")[:4000]}
            return {"source": "simulated", "content": "[synthetic file contents]"}
        if tool == "write_file":
            content = args.get("content", "")
            if ctx.get("path_outside_sandbox"):
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
            if not ctx.get("path_outside_sandbox") and p.is_file():
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
            if isinstance(value, str):
                return value.encode("utf-8")
            if isinstance(value, (dict, list)):
                return json.dumps(value, sort_keys=True,
                                  ensure_ascii=False).encode("utf-8")
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

    def call(self, identity, tool, **kwargs):
        """Run one tool call through the governance pipeline."""
        if not isinstance(identity, AgentIdentity):
            raise TypeError("identity must be an AgentIdentity minted by "
                            "this executor, got %r" % type(identity).__name__)

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
                "reason": "Refusing to act: %s" % e,
            })
            raise

        # Framing kwargs are agent-supplied metadata, never trusted inputs.
        justification = kwargs.pop("justification", None)
        on_behalf_of = kwargs.pop("on_behalf_of", None)
        delegated_by = kwargs.pop("delegated_by", None)
        delegation_attempted = bool(on_behalf_of or delegated_by)

        self.counters[tool] = self.counters.get(tool, 0) + 1
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
                "policy_context": policy_ctx_snapshot,
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

        # 2. role allowlist ------------------------------------------------
        if not self.policy.role_allows(identity.role, tool):
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
        rl = self.policy.rate_limit or {}
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
            "source_untrusted": ctx.get("source_untrusted"),
            "counters": dict(ctx.get("counters") or {}),
        }
        decision = self.policy.evaluate(action, ctx)

        if decision.effect == "allow":
            # Write-ahead audit (fail-closed): the authorization is durably
            # logged BEFORE the side effect. If this append raises, the tool
            # is never touched: no log, no side effect.
            auth_entry = self.log.append(_base({
                "decision": "execution_authorized",
                "policy_id": decision.policy_id,
                "reason": decision.reason,
                "flag": decision.flag,
            }))
            result = self._simulate(tool, kwargs, ctx)
            self._ingest_result(tool, result, identity.principal)
            if tool == "api_call":
                self.api_calls += 1
            # F33: charge the execution budgets exactly once, at execution
            # time (the allow path is an execution boundary).
            self._executed[tool] = self._executed.get(tool, 0) + 1
            self._egress_bytes += self._egress_bytes_for(tool, kwargs)
            entry = self.log.append(_base({
                "decision": "allowed_executed",
                "policy_id": decision.policy_id,
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
            policy_hash=self.policy.policy_hash,
            delegation_attempted=delegation_attempted,
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
            caller_identity=identity)
        entry = self.log.append(_base({
            "decision": "queued_pending",
            "policy_id": decision.policy_id,
            "reason": decision.reason,
            "flag": decision.flag,
            "approval_id": approval_id,
        }))
        # Low-risk auto-approval: only fires when the ACTIVE policy
        # explicitly opts in (auto_approve.enabled + risk cap). The audit
        # record is identical to a human approval.
        auto = self.approvals.maybe_auto_approve(
            approval_id, self.policy.auto_approve)
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

        F60-followup (R15): suppression now requires the log to FULLY
        verify (``verify_chain`` ok). The R14 honest residual was real:
        a run-dir writer could PLANT a MAC-invalid
        ``approval_sweep_refused`` line and corrupt the state file to
        suppress the re-audit. Now a planted line — or any broken,
        invalid, or otherwise unverifiable chain — falls back to LOUD
        re-audit (return False here), never silent suppression. The
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
        try:
            ok, _broken_seq, _n = verify_chain(self.log.path)
        except OSError:
            return False
        if not ok:
            # Broken/unverifiable chain: the "already audited" signal is
            # untrustworthy. Fail LOUD — audit once more.
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
                audited = True
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        return audited

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
                "source_untrusted": ctx.get("source_untrusted"),
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
