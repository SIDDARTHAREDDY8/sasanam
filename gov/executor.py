"""Tool executor: every agent action flows through identity -> policy -> log.

Pipeline for each call (in order):

1. **Identity.** The identity must be an ``AgentIdentity`` *minted by this
   executor* via :meth:`mint_identity` (unforgeable within the process) and
   its ``run_id`` must match this run. A forged or cross-run identity is
   denied and logged; a structurally valid but unminted identity raises
   :class:`UnmintedIdentityError`.
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
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import dlp
from .approvals import record_digest, sanitize_preview_text
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
)

_SEND_TOOLS = ("send_email", "http_post")
_MAX_READ_STORE = 256 * 1024  # cap on stored read fingerprints per run

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
                 principal_registry=None):
        self.run_dir = Path(run_dir)
        self.run_id = self.run_dir.name
        self.policy = policy
        self.log = log
        self.approvals = approvals
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
        if hasattr(approvals, "set_identity_verifier"):
            approvals.set_identity_verifier(self._verify_approval_identity)
        # F22: policy-configurable audit-log size guard (fail-closed).
        log_limits = getattr(policy, "log_limits", None) or {}
        if log_limits.get("max_log_bytes") is not None:
            log.configure_guard(log_limits["max_log_bytes"])
        self.api_calls = 0  # external api_call executions this run
        self.counters = {}  # attempted calls per tool this run
        self._repeats = {}  # (tool, canonical args) -> count
        self._minted = set()  # (agent_id, role, run_id, principal) tuples
        self._tainted = False  # True once tool output entered this run
        self._taint_sources = []
        self._read_contents = []  # fingerprints of executed read results
        self._read_sensitive = False  # F9: a read returned DLP-sensitive
        # content this run; api_call afterwards is taint-gated.

    # -- identity ---------------------------------------------------------

    def mint_identity(self, agent_id, role, principal):
        """Issue the only kind of identity this executor will honor.

        F17b: issuance is rate-limited (per-run cap,
        ``_MAX_IDENTITY_MINTS_PER_RUN``) and — when a principal registry
        is configured — the principal must be pre-registered, otherwise
        ``UnregisteredPrincipalError``. Registry-mode issuance is
        audit-logged (``identity_minted``). With no registry (permissive
        demo default) any principal string mints: an explicit
        deployment-trust residual, documented in ``gov/identity.py``.
        """
        if self._mint_count >= _MAX_IDENTITY_MINTS_PER_RUN:
            raise IdentityMintLimitError(
                "identity mint budget exhausted for run %s (%d)" %
                (self.run_id, _MAX_IDENTITY_MINTS_PER_RUN))
        if self._principal_registry is not None:
            self._principal_registry.check(principal)
        self._mint_count += 1
        ident = AgentIdentity(agent_id=agent_id, role=role,
                              run_id=self.run_id, principal=principal)
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

    def _check_cross_run_campaign(self, tool, args, principal, shape=None):
        """F10/F13: heuristic cross-run campaign detection (fail-safe).

        Records this api_call attempt's shape in the per-principal egress
        ledger, then asks whether K small high-entropy-ish fragments to
        the SAME registered domain (F13: normalized, so subdomain
        rotation lands in one bucket) from the SAME principal across >=
        2 distinct runs fall inside the time window. True -> the policy
        rule queues (never denies). Any ledger failure fails OPEN
        (returns False): this is a heuristic signal, not an authorization
        control.
        """
        if tool != "api_call" or not principal:
            return False
        shape = shape if shape is not None else self._api_call_shape(args)
        try:
            self._ledger.append({
                "ts": datetime.now(timezone.utc).timestamp(),
                "run_id": self.run_id,
                "principal": principal,
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

    def _context(self, tool, args, principal=None, record_ledger=True):
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
            # ``cross_run_campaign`` — one campaign concept, two
            # detectors; the ledger record keeps which shape each entry
            # had for forensics. Not re-recorded on approval
            # re-evaluation: the attempt was already ledgered when first
            # queued.
            if record_ledger:
                shape = self._api_call_shape(args)
                ctx["cross_run_campaign"] = (
                    self._check_cross_run_campaign(
                        tool, args, principal, shape)
                    or self._check_structural_campaign(
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
        sends = self.counters.get("send_email", 0) + self.counters.get("http_post", 0)
        if tool in _SEND_TOOLS and sends > int(rl.get("max_sends_per_run", 10)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "volume-guard-sends",
                "flag": "volume_guard",
                "reason": "Per-run send budget exceeded (%d sends)." % sends,
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "volume-guard-sends", "seq": entry["seq"]}
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
        ctx = self._context(tool, kwargs, principal=identity.principal)
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
            policy_flag=decision.flag)
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
        of the queued arguments, the policy it was approved under, and a
        fresh policy evaluation. Any failure refuses the execution and logs
        why. Returns the list of executed actions.
        """
        # F17: an unverifiable ledger refuses even approved executions —
        # the taint/campaign memory the approval was granted under cannot
        # be trusted.
        self._ledger.require_verified()
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
            # 2. integrity: queued arguments must be byte-identical
            if rec.get("args_digest") != record_digest(
                    rec["tool"], rec["args"], rec.get("policy_id")):
                _refuse("Approval %s arguments were modified after queueing; "
                        "integrity digest mismatch." % aid,
                        "approval_integrity_violation")
                continue
            # 3. policy staleness: approved under a different policy version
            if rec.get("policy_hash") != self.policy.policy_hash:
                _refuse("Approval %s was granted under policy %s but the "
                        "active policy is %s; re-approval required."
                        % (aid, (rec.get("policy_hash") or "")[:12],
                           self.policy.policy_hash[:12]),
                        "approval_policy_stale")
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
            result = self._simulate(rec["tool"], rec["args"], ctx)
            self._ingest_result(rec["tool"], result,
                                (rec.get("identity") or {}).get("principal"))
            if rec["tool"] == "api_call":
                self.api_calls += 1
            self.counters[rec["tool"]] = self.counters.get(rec["tool"], 0) + 1
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
            self.approvals.mark_executed(aid)
            done.append({"agent_id": rec.get("agent_id"),
                         "tool": rec["tool"], "seq": entry["seq"]})
        return done
