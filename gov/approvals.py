"""File-based human approval queue.

When the policy engine returns "require_approval", the action is NOT executed.
It is stored as a pending approval with full context. A human reviews it with:

    python -m gov.approve --rundir <run dir> list
    python -m gov.approve --rundir <run dir> approve <id> --reason "..."
    python -m gov.approve --rundir <run dir> reject <id> --reason "..."

(Use --latest instead of --rundir to target the most recent run.)

Approval hardening:

* **Integrity binding.** Each record stores ``args_digest``, a SHA-256 over
  the queued (redacted) arguments plus the policy id. The executor refuses
  to run an approval whose arguments changed after queueing.
* **Policy pinning.** The record stores the ``policy_hash`` it was queued
  under; execution under a different policy version is refused.
* **Expiry.** Approvals expire ``approvals.ttl_hours`` after the decision
  (default 24h); the executor refuses stale approvals.
* **Separation of duties.** The requesting agent cannot approve its own
  action: ``decide()`` raises if ``decided_by`` equals the agent id.
* **No trust in agent framing.** ``agent_justification`` is stored verbatim
  but labeled UNVERIFIED everywhere it is displayed; the reviewer sees the
  executor-generated ``preview`` (what the action would do) instead.

Every decision is appended to the tamper-evident action log, so the full
lifecycle - queued -> approved/rejected -> executed - is auditable.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .identity import AgentIdentity
from .log import ActionLog


def _utcnow():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def record_digest(tool, args, policy_id):
    """Integrity digest binding a queued approval to its exact arguments."""
    payload = json.dumps({"tool": tool, "args": args, "policy_id": policy_id},
                         sort_keys=True, separators=(",", ":"), default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Preview sanitization (F11).
#
# Preview fields are interpolated from agent-controlled values. Rendering
# them raw lets ANSI escapes / carriage returns / bidi overrides reach the
# approver's terminal, where the DISPLAYED glyphs differ from the TRUE
# bytes the egress check judged (OWASP ASI09). ``sanitize_preview_text``
# makes every control / non-printable character VISIBLE (``\x1b`` shown
# literally) so the displayed bytes cannot differ from the true bytes.
# The egress allowlist still judges the RAW bytes; only the display is
# neutralized. Idempotent: sanitizing an already-sanitized string is a
# no-op (backslashes are printable and pass through untouched).

_SHORT_ESCAPES = {
    "\a": "\\a", "\b": "\\b", "\f": "\\f", "\n": "\\n",
    "\r": "\\r", "\t": "\\t", "\v": "\\v", "\x1b": "\\x1b",
}


def sanitize_preview_text(value):
    """Return *value* with every non-printable character visibly escaped."""
    s = value if isinstance(value, str) else str(value)
    parts = []
    for ch in s:
        if ch in _SHORT_ESCAPES:
            parts.append(_SHORT_ESCAPES[ch])
        elif not ch.isprintable():
            o = ord(ch)
            if o < 0x100:
                parts.append("\\x%02x" % o)
            elif o < 0x10000:
                parts.append("\\u%04x" % o)
            else:
                parts.append("\\U%08x" % o)
        else:
            parts.append(ch)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Risk scoring, flood defense, batching, auto-approval, break-glass
#
# Approval fatigue is the attack this section exists for: a compromised or
# misbehaving agent floods the queue with plausible-looking requests so the
# operator rubber-stamps them. Defenses:
#
# * every pending item carries a deterministic risk score (0-100) and the
#   queue lists highest-risk first, so the dangerous items are reviewed
#   first instead of buried under volume;
# * batch approve refuses high-risk (score >= 60) and flood-suspect items
#   unless each is explicitly confirmed (--confirm-risky);
# * batch reject has no guard: rejecting is always the safe direction;
# * flood detection flags (agent, tool) clusters >= threshold as
#   flood_suspect, requiring individual review;
# * queue-anomaly detection (F4) flags fatigue patterns a per-(agent,tool)
#   threshold misses: bursts of low-risk items from one agent across
#   tools, arrival-rate spikes vs the run's baseline, and unusual tool
#   mix. Findings are advisory only: anomalous items get a risk-score
#   escalation (never a reduction), the queue listing shows a fatigue
#   warning, and batch approve requires per-item confirmation for them.
#   Anomalies never auto-approve;
# * low-risk auto-approval only fires when the ACTIVE policy explicitly
#   opts in (policy file `auto_approve:` section); it still writes the
#   full audit record.
# ---------------------------------------------------------------------------

# Base risk by tool: how much damage the tool can do in one call.
TOOL_RISK = {
    "send_email": 40,   # exfiltration / social engineering surface
    "http_post": 35,    # data leaves the sandbox
    "delete_file": 30,  # destructive
    "write_file": 15,   # persistence / overwrite
    "api_call": 10,     # cost + external side effects
    "read_file": 5,     # read-only, but may touch secrets
    "sleep": 0,
    "log_note": 0,
}
_UNKNOWN_TOOL_RISK = 20

_SECRET_HINTS = ("secret", "token", "passwd", "password", "credential",
                 "api_key", "apikey", ".env", "private_key", "privatekey")

FLOOD_THRESHOLD = 5          # pending items from one (agent, tool) ...
FLOOD_VOLUME_PRESSURE = 3    # ... this many already adds risk pressure
BATCH_RISK_GUARD = 60        # batch approve refuses items at/above this

# F21: conservative built-in batch-exclusion set. Queue reasons that mark
# a security-relevant decision — these may never be batch-decided, even
# via confirm_risky; they need an individual human decision. Used when no
# policy-derived list was installed (direct/CLI construction); the
# default policy ships the same list under
# approvals.batch_excluded_queue_reasons, and ToolExecutor pushes the
# policy's list into the queue at construction.
_DEFAULT_BATCH_EXCLUDED_REASONS = (
    "cross_run_campaign",
    "dlp",
    "sensitive_read_before_api",
    "read_before_send",
    "credential_block",
    "tainted_delete",
    "egress_violation",
    "secret_access_attempt",
    "break_glass",
)

# Queue-anomaly detection (F4: approval fatigue). An attacker floods the
# queue with low-risk approvals to hide one malicious request; the
# defense is a statistical signal that protects the operator's
# attention. All anomaly findings are ADVISORY: they escalate the risk
# score of the clustered items (never lower it) and are surfaced as a
# fatigue warning on the queue listing. They never auto-approve.
ANOMALY_BURST_THRESHOLD = 5   # pending items from one agent in window
ANOMALY_WINDOW_SEC = 600      # ... inside this trailing window (seconds)
ANOMALY_RATE_FACTOR = 3.0     # arrivals >= this x baseline rate ...
ANOMALY_RATE_MIN_COUNT = 4    # ... and at least this many arrivals
ANOMALY_TOOL_MIX_SHARE = 0.5  # a tool is >= this share of pending ...
ANOMALY_TOOL_MIX_HIST = 0.2   # ... while < this share of run history ...
ANOMALY_TOOL_MIX_MIN = 4      # ... and at least this many pending items
ANOMALY_RISK_BUMP = 15        # advisory escalation on anomalous items


def risk_level(score):
    if score < 30:
        return "low"
    if score < 60:
        return "medium"
    if score < 80:
        return "high"
    return "critical"


def _secret_hint_in_args(args):
    try:
        blob = json.dumps(args or {}, ensure_ascii=True,
                          default=str).lower()
    except Exception:
        return False
    return any(h in blob for h in _SECRET_HINTS)


def _base_score(record):
    """Tool base risk only (no context factors): classifies an item as
    low-risk cover traffic vs an inherently riskier request."""
    return TOOL_RISK.get(record.get("tool"), _UNKNOWN_TOOL_RISK)


def _score_factors(record, queue_records, anomaly_ids=()):
    """Return (score, factors) with deterministic, documented factors.

    ``anomaly_ids`` are pending ids in a queue-anomaly cluster (see
    queue_anomalies): the bump is ADVISORY and one-directional — it can
    only raise the score, never lower it, and it never approves.
    """
    factors = []
    tool = record.get("tool")
    score = _base_score(record)
    factors.append("tool %s base %d" % (tool, score))
    ctx = record.get("policy_context") or {}
    if ctx.get("path_outside_sandbox"):
        score += 15
        factors.append("path escapes sandbox +15")
    if (ctx.get("domain_allowlisted") is False
            and tool in ("send_email", "http_post")):
        score += 20
        factors.append("non-allowlisted egress target +20")
    if ctx.get("carries_read_content"):
        score += 10
        factors.append("carries previously-read content +10")
    if (record.get("provenance") == "untrusted_influenced"
            or ctx.get("source_untrusted")):
        score += 15
        factors.append("untrusted-influenced provenance +15")
    if record.get("delegation_attempted"):
        score += 10
        factors.append("delegation framing detected +10")
    if _secret_hint_in_args(record.get("args")):
        score += 20
        factors.append("secret-like material in args +20")
    agent = record.get("agent_id")
    decided_before = [r for r in queue_records
                       if r.get("id") != record.get("id")
                       and r.get("agent_id") == agent
                       and r.get("status") in ("approved", "rejected")]
    if agent and not decided_before:
        score += 10
        factors.append("unknown agent (no prior decisions) +10")
    volume = [r for r in queue_records
              if r.get("id") != record.get("id")
              and r.get("agent_id") == agent
              and r.get("tool") == tool
              and r.get("status") == "pending"]
    if len(volume) >= FLOOD_VOLUME_PRESSURE:
        score += 10
        factors.append("volume pressure: %d sibling pending %s/%s +10"
                       % (len(volume) + 1, agent, tool))
    if anomaly_ids and record.get("id") in anomaly_ids:
        # Advisory escalation only: a fatigue-pattern cluster means the
        # operator cannot tell the benign items from the malicious one,
        # so every item in the cluster gets harder to rubber-stamp.
        score += ANOMALY_RISK_BUMP
        factors.append("queue-anomaly cluster +%d (advisory: review "
                       "individually, never auto-approve)"
                       % ANOMALY_RISK_BUMP)
    return min(100, score), factors


class ApprovalQueueRiskMixin:
    """Mixin for ApprovalQueue: risk, floods, batch, auto-approve,
    break-glass, post-review."""

    # -- risk -----------------------------------------------------------
    def _anomaly_id_set(self, records):
        ids = set()
        for a in self.queue_anomalies(records=records):
            ids.update(a["items"])
        return ids

    def risk(self, record):
        """Deterministic risk score (0-100) for a pending record.

        Includes the advisory anomaly escalation: items inside a
        fatigue-pattern cluster score higher, so they surface first and
        clear the auto-approve gate less easily. Never lowers a score.
        """
        records = self.all()
        score, _ = _score_factors(record, records,
                                  anomaly_ids=self._anomaly_id_set(records))
        return score

    def risk_detail(self, record):
        records = self.all()
        score, factors = _score_factors(
            record, records, anomaly_ids=self._anomaly_id_set(records))
        return {"score": score, "level": risk_level(score),
                "factors": factors}

    def pending_risk_sorted(self):
        """Pending records, highest risk first (then oldest first)."""
        self.refresh_flood_flags()
        records = self.all()
        scored = [(self.risk(r), r.get("ts") or "", r)
                  for r in records if r.get("status") == "pending"]
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [r for _, _, r in scored]

    # -- flood defense ---------------------------------------------------
    def flood_groups(self, threshold=FLOOD_THRESHOLD):
        """Map (agent_id, tool) -> pending records, for groups at/above
        the threshold. These are approval-fatigue attack shapes."""
        groups = {}
        for r in self.pending():
            key = (r.get("agent_id"), r.get("tool"))
            groups.setdefault(key, []).append(r)
        return {k: v for k, v in groups.items() if len(v) >= threshold}

    def refresh_flood_flags(self, threshold=FLOOD_THRESHOLD):
        """Persist flood_suspect flags for the current queue state.

        Flags are recomputed (not sticky): once sibling items are
        decided, the flag clears by itself.
        """
        suspects = set()
        for members in self.flood_groups(threshold).values():
            for r in members:
                suspects.add(r["id"])

        def _apply(records):
            out = []
            for r in records:
                r = dict(r)
                r["flood_suspect"] = r["id"] in suspects
                out.append(r)
            return out
        self._rewrite(_apply)
        return sorted(suspects)

    # -- queue-anomaly detection (F4: approval fatigue) --------------------
    @staticmethod
    def _parse_ts(ts):
        """Parse a queue record timestamp; None when unparseable."""
        try:
            dt = datetime.fromisoformat(str(ts))
        except (TypeError, ValueError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def queue_anomalies(self, records=None, now=None):
        """Advisory queue-anomaly detection (F4: approval fatigue).

        Returns a list of anomaly dicts:
            {"type": "fatigue_burst" | "rate_spike" | "unusual_tool_mix",
             "summary": str, "items": [approval ids], "detail": dict}

        READ-ONLY: never modifies the queue and never auto-decides.
        Callers escalate attention (risk bump, operator warning) — never
        approvals — on the basis of this signal.
        """
        records = list(self.all()) if records is None else list(records)
        pending = [r for r in records if r.get("status") == "pending"]
        if not pending:
            return []
        now = now or datetime.now(timezone.utc)
        anomalies = []
        anomalies.extend(self._burst_anomalies(pending, now))
        anomalies.extend(self._rate_spike_anomalies(records, now))
        anomalies.extend(self._tool_mix_anomalies(pending, records))
        return anomalies

    def anomaly_item_ids(self, records=None):
        """Approval ids belonging to any current anomaly cluster."""
        ids = set()
        for a in self.queue_anomalies(records=records):
            ids.update(a["items"])
        return ids

    def _burst_anomalies(self, pending, now):
        """Bursts of low-risk items from one agent: the classic fatigue
        shape — N plausible requests in minutes, one of them malicious,
        indistinguishable except by individual review."""
        window = ANOMALY_WINDOW_SEC
        by_agent = {}
        for r in pending:
            ts = self._parse_ts(r.get("ts"))
            if ts is None:
                continue
            if 0 <= (now - ts).total_seconds() <= window:
                by_agent.setdefault(r.get("agent_id"), []).append(r)
        out = []
        for agent, members in sorted(by_agent.items()):
            if len(members) < ANOMALY_BURST_THRESHOLD:
                continue
            low = sum(1 for r in members
                      if _base_score(r) < 30)
            out.append({
                "type": "fatigue_burst",
                "summary": ("agent %s queued %d items in the last %d "
                            "minutes (%d of them low-risk): possible "
                            "approval-fatigue flood hiding a malicious "
                            "request — review each item individually"
                            % (agent, len(members), window // 60, low)),
                "items": sorted(r["id"] for r in members),
                "detail": {"agent_id": agent, "count": len(members),
                           "low_risk_count": low,
                           "window_sec": window},
            })
        return out

    def _rate_spike_anomalies(self, records, now):
        """Queue arrival rate in the trailing window vs the run's
        baseline: a dormant agent that suddenly queues is the same
        attack with a different clock."""
        window = ANOMALY_WINDOW_SEC
        now_s = now.timestamp()
        times = [t for t in
                 (self._parse_ts(r.get("ts")) for r in records)
                 if t is not None]
        if not any(t.timestamp() <= now_s - window for t in times):
            return []  # no history before the current window: no baseline
        current = sum(1 for t in times
                      if now_s - window < t.timestamp() <= now_s)
        prior = []
        for k in range(1, 13):
            lo, hi = now_s - (k + 1) * window, now_s - k * window
            prior.append(sum(1 for t in times
                             if lo < t.timestamp() <= hi))
        baseline = sorted(prior)[len(prior) // 2]  # median; zeros included
        baseline = max(1.0, float(baseline))
        if (current >= ANOMALY_RATE_MIN_COUNT
                and current >= ANOMALY_RATE_FACTOR * baseline):
            return [{
                "type": "rate_spike",
                "summary": ("queue arrival rate spiked: %d arrivals in the "
                            "last %d minutes vs a baseline of ~%.1f per "
                            "window — review the queue before approving"
                            % (current, window // 60, baseline)),
                "items": sorted(
                    r["id"] for r in records
                    if r.get("status") == "pending"
                    and (lambda t: t is not None
                         and now_s - window < t.timestamp() <= now_s)(
                             self._parse_ts(r.get("ts")))),
                "detail": {"current": current, "baseline": baseline,
                           "window_sec": window},
            }]
        return []

    def _tool_mix_anomalies(self, pending, records):
        """A tool that dominates the pending queue but is rare in the
        run's history: the malicious request's tool standing out from
        the flood's cover traffic."""
        total_pending = len(pending)
        tool_pending = {}
        for r in pending:
            tool_pending[r.get("tool")] = tool_pending.get(r.get("tool"), 0) + 1
        tool_hist = {}
        for r in records:
            tool_hist[r.get("tool")] = tool_hist.get(r.get("tool"), 0) + 1
        total_hist = sum(tool_hist.values())
        out = []
        for tool in sorted(tool_pending):
            n = tool_pending[tool]
            if n < ANOMALY_TOOL_MIX_MIN:
                continue
            if n / total_pending < ANOMALY_TOOL_MIX_SHARE:
                continue
            hist_share = tool_hist[tool] / total_hist if total_hist else 1.0
            if hist_share >= ANOMALY_TOOL_MIX_HIST:
                continue
            out.append({
                "type": "unusual_tool_mix",
                "summary": ("%s is %d/%d of the pending queue but only "
                            "%.0f%% of this run's history: unusual tool "
                            "mix — check what it is doing here"
                            % (tool, n, total_pending,
                               100.0 * hist_share)),
                "items": sorted(r["id"] for r in pending
                                if r.get("tool") == tool),
                "detail": {"tool": tool, "pending_count": n,
                           "pending_share": n / total_pending,
                           "historical_share": hist_share},
            })
        return out

    # -- batch decisions --------------------------------------------------
    def batch_decide(self, approval_ids, approved, rationale,
                     decided_by="human-operator", confirm_risky=()):
        """Decide many items with one rationale, one audit entry per item.

        Fail-closed: the whole batch aborts (no partial decisions) when
        any id is unknown, not pending, or — for approvals — high-risk /
        flood-suspect / anomalous without explicit per-item confirmation.

        F21: security-excluded items (see ``_batch_blocked_reason``) are
        NEVER batch-decided — not even with per-item ``confirm_risky``;
        they stay pending and are returned as ``excluded``
        (``needs_individual_decision``), decided individually via
        ``decide()``. Skipping them is the safe direction, so exclusions
        do not abort the batch: the atomic no-partial-decision guarantee
        covers the decided set. Rejections are never guarded (refusing is
        always safe), but excluded items are still returned separately
        rather than batch-rejected, so the operator sees they need
        individual review.

        Returns (decided_records, excluded_records, batch_log_entry).
        Excluded records carry ``batch_exclusion_reason``.
        """
        if not rationale or not rationale.strip():
            raise ValueError("a batch rationale is required")
        records = {r["id"]: r for r in self.all()}
        missing = [i for i in approval_ids if i not in records]
        if missing:
            raise ValueError("unknown approval id(s): %s"
                             % ", ".join(missing))
        not_pending = [i for i in approval_ids
                       if records[i].get("status") != "pending"]
        if not_pending:
            raise ValueError("not pending: %s" % ", ".join(not_pending))
        if decided_by and any(records[i].get("agent_id") == decided_by
                              for i in approval_ids):
            raise ValueError(
                "separation of duties: %r requested at least one of these "
                "actions" % decided_by)
        # F21: partition out security-excluded items first — they are
        # never decided here, in either direction.
        excluded = []
        candidates = []
        for i in approval_ids:
            reason = self._batch_blocked_reason(records[i])
            if reason is not None:
                rec = dict(records[i])
                rec["batch_exclusion_reason"] = reason
                excluded.append(rec)
            else:
                candidates.append(i)
        guarded = []
        if approved:
            confirmed = set(confirm_risky or ())
            self.refresh_flood_flags()
            anomaly_ids = self.anomaly_item_ids()
            for i in candidates:
                r = self.get(i)  # re-read after flag refresh
                if r.get("flood_suspect") and i not in confirmed:
                    guarded.append((i, "flood_suspect"))
                elif i in anomaly_ids and i not in confirmed:
                    guarded.append((i, "queue anomaly (fatigue pattern)"))
                elif self.risk(r) >= BATCH_RISK_GUARD and i not in confirmed:
                    guarded.append((i, "risk %d >= %d"
                                    % (self.risk(r), BATCH_RISK_GUARD)))
        if guarded:
            detail = "; ".join("%s (%s)" % g for g in guarded)
            self.log.append({
                "event": "approval_batch_abort",
                "run_id": self.run_dir.name,
                "agent_id": "human-operator",
                "role": "approver",
                "principal": "human-operator",
                "tool": "batch",
                "decision": "aborted",
                "reason": "batch approve refused without per-item "
                          "confirmation: %s" % detail,
                "decided_by": decided_by,
                "approval_ids": list(approval_ids),
            })
            raise ValueError(
                "batch approve refused for: %s. Re-run with "
                "--confirm-risky for each id you have reviewed individually."
                % detail)
        decided = []
        decided_ids = []
        for i in candidates:
            record, _entry = self.decide(
                i, approved, "BATCH [%s]: %s" % (
                    "approve" if approved else "reject", rationale),
                decided_by=decided_by)
            decided.append(record)
            decided_ids.append(i)
        batch_entry = self.log.append({
            "event": "approval_batch",
            "run_id": self.run_dir.name,
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": "batch",
            "decision": "approved" if approved else "rejected",
            "decided_by": decided_by,
            "approval_ids": decided_ids,
            "excluded_ids": [r["id"] for r in excluded],
            "excluded_reasons": {r["id"]: r["batch_exclusion_reason"]
                                 for r in excluded},
            "count": len(decided_ids),
            "reason": rationale,
        })
        return decided, excluded, batch_entry

    # -- low-risk auto-approval -------------------------------------------
    def maybe_auto_approve(self, approval_id, auto_cfg):
        """Auto-approve a low-risk item when the policy explicitly opts in.

        ``auto_cfg`` is the policy file's ``auto_approve:`` section:
        ``{enabled: true, max_risk_score: 25}``. Nothing happens unless
        enabled is true; flood-suspect items are never auto-approved; the
        full audit record is still written (decided_by="auto-approve").
        Returns the decided record, or None when the gate does not fire.
        """
        auto_cfg = auto_cfg or {}
        if not auto_cfg.get("enabled"):
            return None
        try:
            cap = int(auto_cfg.get("max_risk_score", 25))
        except (TypeError, ValueError):
            return None  # malformed config: fail closed, no auto-approve
        cap = max(0, min(100, cap))
        record = self.get(approval_id)
        if record is None or record.get("status") != "pending":
            return None
        self.refresh_flood_flags()
        record = self.get(approval_id)
        if record.get("flood_suspect"):
            return None
        score = self.risk(record)
        if score > cap:
            return None
        decided, _entry = self.decide(
            approval_id, True,
            "AUTO-APPROVED by policy auto_approve (risk score %d <= "
            "policy cap %d; policy explicitly permits low-risk "
            "auto-approval)" % (score, cap),
            decided_by="auto-approve")
        return decided

    # -- break-glass -------------------------------------------------------
    def _reviews_path(self):
        return self.run_dir / "review_queue.jsonl"

    def pending_reviews(self):
        path = self._reviews_path()
        if not path.exists():
            return []
        return [json.loads(line) for line in
                path.read_text(encoding="utf-8").splitlines()
                if line.strip() and
                json.loads(line).get("status") == "pending"]

    def break_glass(self, approval_id, reason, operator="human-operator"):
        """Emergency-approve a pending item with a mandatory post-review.

        * reason must be non-empty (the emergency justification);
        * refused while any post-review ticket is unresolved: stacked
          break-glass without review is not allowed (fail-closed);
        * creates a post-review ticket that keeps the audit status
          UNCLEAN until a different reviewer resolves it.
        Returns (record, ticket).
        """
        if not reason or not reason.strip():
            raise ValueError("break-glass requires a non-empty reason")
        unresolved = self.pending_reviews()
        if unresolved:
            raise ValueError(
                "break-glass refused: %d post-review ticket(s) unresolved "
                "(%s). Resolve reviews before another break-glass."
                % (len(unresolved),
                   ", ".join(t["ticket_id"] for t in unresolved)))
        record, _entry = self.decide(
            approval_id, True,
            "BREAK-GLASS by %s: %s" % (operator, reason.strip()),
            decided_by=operator)
        record["break_glass"] = True
        record["break_glass_reason"] = reason.strip()
        self._rewrite(lambda records: [
            record if r["id"] == record["id"] else r for r in records])
        ticket = {
            "ticket_id": "PRV-%s" % approval_id,
            "approval_id": approval_id,
            "operator": operator,
            "break_glass_reason": reason.strip(),
            "tool": record.get("tool"),
            "agent_id": record.get("agent_id"),
            "status": "pending",
            "created_at": _utcnow(),
            "resolved_at": None,
            "resolved_by": None,
            "resolution": None,
        }
        with open(self._reviews_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(ticket, ensure_ascii=True, default=str)
                    + "\n")
        self.log.append({
            "event": "approval_break_glass",
            "run_id": record.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": record.get("tool"),
            "decision": "approved",
            "approval_id": approval_id,
            "decided_by": operator,
            "reason": "BREAK-GLASS: %s (post-review ticket %s opened)"
                      % (reason.strip(), ticket["ticket_id"]),
            "post_review_ticket": ticket["ticket_id"],
            "audit_note": "audit status UNCLEAN until ticket %s is "
                          "resolved" % ticket["ticket_id"],
        })
        return record, ticket

    def resolve_review(self, ticket_id, resolution, reviewer="human-operator"):
        """Resolve a post-review ticket. The reviewer must differ from the
        operator who pulled the break-glass (separation of duties)."""
        if not resolution or not resolution.strip():
            raise ValueError("a resolution record is required")
        path = self._reviews_path()
        tickets = []
        if path.exists():
            tickets = [json.loads(line) for line in
                       path.read_text(encoding="utf-8").splitlines()
                       if line.strip()]
        target = None
        for t in tickets:
            if t["ticket_id"] == ticket_id:
                target = t
                break
        if target is None:
            raise ValueError("post-review ticket %r not found" % ticket_id)
        if target["status"] != "pending":
            raise ValueError("ticket %s is already %s"
                             % (ticket_id, target["status"]))
        if reviewer == target.get("operator"):
            raise ValueError(
                "separation of duties: the break-glass operator cannot "
                "resolve their own post-review ticket")
        target["status"] = "resolved"
        target["resolved_at"] = _utcnow()
        target["resolved_by"] = reviewer
        target["resolution"] = resolution.strip()
        with open(path, "w", encoding="utf-8") as f:
            for t in tickets:
                f.write(json.dumps(t, ensure_ascii=True, default=str)
                        + "\n")
        entry = self.log.append({
            "event": "post_review_resolved",
            "run_id": target.get("run_id") or self.run_dir.name,
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "decision": "resolved",
            "approval_id": target.get("approval_id"),
            "decided_by": reviewer,
            "reason": "post-review %s resolved: %s"
                      % (ticket_id, resolution.strip()),
            "post_review_ticket": ticket_id,
        })
        return target, entry

    # -- audit status -------------------------------------------------------
    def audit_status(self):
        """Clean only when nothing needs a human: no pending items, no
        flood suspects, no unresolved break-glass post-reviews."""
        self.refresh_flood_flags()
        pending = self.pending()
        floods = [r["id"] for r in pending if r.get("flood_suspect")]
        reviews = self.pending_reviews()
        clean = not pending and not floods and not reviews
        return {
            "clean": clean,
            "pending_count": len(pending),
            "flood_suspect_ids": floods,
            "unresolved_break_glass": [t["ticket_id"] for t in reviews],
        }


class ApprovalQueue(ApprovalQueueRiskMixin):
    def __init__(self, run_dir, log, batch_excluded_reasons=None):
        self.run_dir = Path(run_dir)
        self.log = log
        self.path = self.run_dir / "approvals.jsonl"
        # F21: queue reasons that may never be batch-decided. Explicit
        # policy list wins; otherwise the conservative built-in security
        # set applies (fail closed for direct/CLI construction without a
        # policy). ToolExecutor pushes the policy-derived list via the
        # setter below.
        self.set_batch_excluded_reasons(batch_excluded_reasons)

    def set_batch_excluded_reasons(self, reasons):
        """F21: install the policy-derived batch-exclusion list.

        ``reasons=None`` keeps the conservative built-in default; an
        explicit (possibly empty) list is honored as the deployment's
        choice.
        """
        if reasons is None:
            self._batch_excluded = tuple(_DEFAULT_BATCH_EXCLUDED_REASONS)
        else:
            self._batch_excluded = tuple(r for r in reasons)

    def _batch_blocked_reason(self, record):
        """F21: why this record may never be batch-decided (None = OK).

        Security-excluded queue reasons always need an individual human
        decision — batch approval, even with per-item ``confirm_risky``,
        cannot grant them. Break-glass records are excluded
        structurally: a break-glass bypass must never be laundered
        through a batch. Records queued before ``policy_flag`` existed
        fall back to matching the policy_id (dashes/underscores
        normalized) against the excluded reasons.
        """
        if record.get("break_glass"):
            return "break_glass record: individual review required"
        flag = record.get("policy_flag")
        if flag and flag in self._batch_excluded:
            return ("excluded queue reason %r: individual decision "
                    "required" % flag)
        pid = str(record.get("policy_id") or "")
        if pid and not flag:
            norm = pid.lower().replace("-", "_")
            for reason in self._batch_excluded:
                rnorm = str(reason).lower().replace("-", "_")
                if rnorm and rnorm in norm:
                    return ("excluded queue reason %r (via policy_id %r): "
                            "individual decision required" % (reason, pid))
        return None

    def queue(self, action, decision, provenance="agent_direct", preview="",
              policy_hash=None, delegation_attempted=False,
              policy_context=None, policy_flag=None):
        """Store a pending approval; returns the approval id.

        ``action`` carries tool, redacted args, identity, the agent's
        justification (unverified), and the redaction list.
        ``policy_context`` is the executor's evaluation-context snapshot
        (path_outside_sandbox, domain_allowlisted, carries_read_content,
        source_untrusted, counters); it feeds risk scoring and the
        simulator, never the agent.
        ``policy_flag`` (F21) is the queue reason (the decision's flag,
        e.g. ``cross_run_campaign``); it travels with the record so
        batch approval can refuse security items individually. When not
        passed explicitly it falls back to ``decision.flag``.
        """
        identity = action.get("identity") or {}
        args = action.get("args") or {}
        if policy_flag is None:
            policy_flag = getattr(decision, "flag", None)
        # F11: the stored preview is the approver-facing display surface.
        # Sanitize here (in addition to the executor's _preview) so every
        # record is safe no matter which caller queued it.
        preview = sanitize_preview_text(preview or "")
        record = {
            "id": uuid.uuid4().hex[:8],
            "ts": _utcnow(),
            "run_id": identity.get("run_id"),
            "agent_id": identity.get("agent_id"),
            "role": identity.get("role"),
            "identity": identity,
            "tool": action.get("tool"),
            "args": args,
            "redactions_applied": action.get("redactions") or [],
            "agent_justification": action.get("agent_justification"),
            "provenance": provenance,
            "preview": preview,
            "delegation_attempted": delegation_attempted,
            "policy_id": decision.policy_id,
            "policy_reason": decision.reason,
            "policy_flag": policy_flag,  # F21: queue reason; batch
            # approval refuses security-excluded flags individually.
            "policy_hash": policy_hash,
            "args_digest": record_digest(action.get("tool"), args,
                                         decision.policy_id),
            "status": "pending",
            "decided_by": None,
            "decided_at": None,
            "decision_reason": None,
            "executed": False,
            "policy_context": policy_context or {},
            "flood_suspect": False,
            "break_glass": False,
            "break_glass_reason": None,
        }
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
        return record["id"]

    def all(self):
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def pending(self):
        return [r for r in self.all() if r["status"] == "pending"]

    def get(self, approval_id):
        for r in self.all():
            if r["id"] == approval_id:
                return r
        return None

    def _rewrite(self, fn_or_records):
        """Rewrite the queue file.

        Accepts either a list of records (legacy contract) or a function
        fn(records) -> new_records, so callers can do atomic transforms
        without a read-modify-write race in their own code.
        """
        if callable(fn_or_records):
            records = fn_or_records(self.all())
        else:
            records = fn_or_records
        with open(self.path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=True, default=str) + "\n")

    def decide(self, approval_id, approved, reason, decided_by="human-operator"):
        """Record a human decision and log it. Returns (record, log_entry).

        Rejected decision *attempts* (unknown id, self-approval, or a
        record that is no longer pending) are also appended to the audit
        log before the ValueError propagates, so abuse of the approval
        workflow itself leaves a trace.
        """
        records = self.all()
        target = None
        for r in records:
            if r["id"] == approval_id:
                target = r
                break

        def _log_attempt(outcome, note, agent_id=None, role=None, tool=None):
            try:
                self.log.append({
                    "event": "approval_decision_attempt",
                    "run_id": (target or {}).get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": tool if tool is not None else (target or {}).get("tool"),
                    "decision": outcome,
                    "approval_id": approval_id,
                    "decided_by": decided_by,
                    "related_agent": agent_id if agent_id is not None
                                     else (target or {}).get("agent_id"),
                    "reason": note,
                })
            except Exception:
                # The attempt is rejected regardless; a logging outage must
                # not turn a rejection into an approval.
                pass

        if target is None:
            _log_attempt("rejected_attempt",
                         "decision attempted on unknown approval id")
            raise ValueError("approval id %r not found" % approval_id)
        # Separation of duties: the requesting agent can never approve (or
        # reject) its own action, even via a confused-deputy prompt.
        if decided_by == target.get("agent_id"):
            _log_attempt(
                "rejected_attempt",
                "separation of duties: requesting agent attempted to decide "
                "its own approval",
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError(
                "separation of duties: agent %r cannot decide its own "
                "approval %s" % (decided_by, approval_id))
        if target["status"] != "pending":
            _log_attempt(
                "rejected_attempt",
                "decision attempted on %s approval" % target["status"],
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError("approval %r is already %s" % (approval_id, target["status"]))
        target["status"] = "approved" if approved else "rejected"
        target["decided_by"] = decided_by
        target["decided_at"] = _utcnow()
        target["decision_reason"] = reason
        # NOTE: all() re-parses from disk, so the mutated `target` dict
        # must be spliced into the rewritten records explicitly.
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])

        approver = AgentIdentity(
            agent_id="human-operator",
            role="approver",
            run_id=target.get("run_id") or "",
            principal="human-operator",
        )
        entry = self.log.append({
            "event": "approval_decision",
            "run_id": target.get("run_id"),
            "agent_id": approver.agent_id,
            "role": approver.role,
            "principal": approver.principal,
            "tool": target["tool"],
            "args": target["args"],
            "redactions_applied": target.get("redactions_applied", []),
            "provenance": target.get("provenance", "agent_direct"),
            "preview": target.get("preview", ""),
            "policy_hash": target.get("policy_hash"),
            "decision": "approved" if approved else "rejected",
            "policy_id": target["policy_id"],
            "approval_id": target["id"],
            "reason": reason,
            "decided_by": decided_by,
            "related_agent": target["agent_id"],
        })
        return target, entry

    def mark_executed(self, approval_id):
        self._rewrite(lambda records: [
            dict(r, executed=True) if r["id"] == approval_id else r
            for r in records])


def _resolve_rundir(args):
    root = Path(__file__).resolve().parent.parent
    if args.latest or not args.rundir:
        runs = root / "runs"
        if args.rundir:
            return Path(args.rundir)
        cands = [d for d in runs.iterdir()] if runs.exists() else []
        cands = [d for d in cands if d.is_dir()]
        if not cands:
            raise SystemExit("no runs found; run python demo/run_demo.py first")
        return max(cands, key=lambda d: d.stat().st_mtime)
    return Path(args.rundir)


def _print_records(records, queue=None, anomaly_ids=()):
    if not records:
        print("  (none)")
        return
    for r in records:
        # First line: routing facts only. The agent's justification is NEVER
        # on this line (or anywhere unlabeled): it is unverified input.
        risk_txt = ""
        if queue is not None:
            score = queue.risk(r)
            risk_txt = " | risk: %d (%s)" % (score, risk_level(score))
        flood_txt = " | FLOOD-SUSPECT" if r.get("flood_suspect") else ""
        anom_txt = " | ANOMALY" if r.get("id") in anomaly_ids else ""
        bg_txt = " | BREAK-GLASS" if r.get("break_glass") else ""
        print("  ID: %s | agent: %s | tool: %s | status: %s | policy: %s%s%s%s%s"
              % (r["id"], r["agent_id"], r["tool"], r["status"],
                 r["policy_id"], risk_txt, flood_txt, anom_txt, bg_txt))
        print("    args: %s" % json.dumps(r["args"], ensure_ascii=True,
                                          default=str)[:400])
        print("    provenance: %s" % r.get("provenance", "agent_direct"))
        if queue is not None and r.get("status") == "pending":
            detail = queue.risk_detail(r)
            print("    risk factors: %s" % "; ".join(detail["factors"]))
        if r.get("preview"):
            print("    preview: %s" % r["preview"])
        if r.get("redactions_applied"):
            print("    redactions: %s" % ", ".join(r["redactions_applied"]))
        if r.get("delegation_attempted"):
            print("    WARNING: delegation framing detected "
                  "(on_behalf_of/delegated_by)")
        if r.get("break_glass"):
            print("    BREAK-GLASS: %s" % r.get("break_glass_reason"))
        if r.get("agent_justification"):
            print("    agent justification (UNVERIFIED, do not trust): %s"
                  % r["agent_justification"])
        if r["status"] != "pending":
            print("    decision: %s by %s at %s: %s" % (
                r["status"], r.get("decided_by"), r.get("decided_at"),
                r.get("decision_reason")))


def _print_anomalies(anomalies):
    if not anomalies:
        return
    print("FATIGUE WARNING: this queue shows %d anomal%s — review each "
          "flagged item individually; do not batch-approve without "
          "per-item confirmation." % (
              len(anomalies), "y" if len(anomalies) == 1 else "ies"))
    for a in anomalies:
        print("  [%s] %s" % (a["type"], a["summary"]))
        print("    items: %s" % ", ".join(a["items"]))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="gov.approve",
        description="Review the human approval queue for a governance run.",
    )
    parser.add_argument("--rundir", default=None, help="run directory (default: --latest)")
    parser.add_argument("--latest", action="store_true", help="use the most recent run")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list approvals, highest risk first")

    p_batch = sub.add_parser("batch",
                             help="decide many pending approvals with one "
                                  "rationale (one audit entry per item)")
    p_batch.add_argument("action", choices=["approve", "reject"],
                         help="decision for every listed id")
    p_batch.add_argument("--ids", required=True,
                         help="comma-separated approval ids")
    p_batch.add_argument("--rationale", required=True,
                         help="one rationale covering the whole batch")
    p_batch.add_argument("--by", default="human-operator",
                         help="who is deciding (default: human-operator)")
    p_batch.add_argument("--confirm-risky", default="",
                         help="comma-separated ids the operator reviewed "
                              "individually; required for high-risk or "
                              "flood-suspect items in an approve batch")

    p_auto = sub.add_parser("auto-approve",
                            help="auto-approve low-risk pending items when "
                                 "the policy file explicitly opts in "
                                 "(auto_approve section)")
    p_auto.add_argument("--policy", required=True,
                        help="policy YAML file whose auto_approve section "
                             "governs the gate")

    p_bg = sub.add_parser("break-glass",
                          help="emergency-approve a pending item; opens a "
                               "mandatory post-review ticket and keeps the "
                               "audit UNCLEAN until it is resolved")
    p_bg.add_argument("id", help="approval id")
    p_bg.add_argument("--reason", required=True,
                      help="non-empty emergency justification")
    p_bg.add_argument("--by", default="human-operator",
                      help="operator pulling the break-glass")

    sub.add_parser("reviews", help="list post-review tickets")

    p_rr = sub.add_parser("review-resolve",
                          help="resolve a post-review ticket (reviewer must "
                               "differ from the break-glass operator)")
    p_rr.add_argument("ticket", help="ticket id, e.g. PRV-<approval-id>")
    p_rr.add_argument("--resolution", required=True,
                      help="resolution record")
    p_rr.add_argument("--by", default="human-operator",
                      help="reviewer resolving the ticket")

    sub.add_parser("audit", help="clean/unclean audit status")
    sub.add_parser("floods", help="show approval-fatigue flood clusters")
    sub.add_parser("anomalies",
                   help="show advisory queue-anomaly signals "
                        "(fatigue bursts, rate spikes, unusual tool mix)")

    p_approve = sub.add_parser("approve", help="approve a pending action")
    p_approve.add_argument("id", help="approval id")
    p_approve.add_argument("--reason", required=True, help="why this is approved")
    p_approve.add_argument("--by", default="human-operator",
                           help="who is deciding (default: human-operator)")

    p_reject = sub.add_parser("reject", help="reject a pending action")
    p_reject.add_argument("id", help="approval id")
    p_reject.add_argument("--reason", required=True, help="why this is rejected")
    p_reject.add_argument("--by", default="human-operator",
                          help="who is deciding (default: human-operator)")

    args = parser.parse_args(argv)
    run_dir = _resolve_rundir(args)
    log = ActionLog(run_dir / "actions.jsonl")
    queue = ApprovalQueue(run_dir, log)

    if args.cmd == "list":
        print("Approvals for run %s (pending: highest risk first):"
              % run_dir.name)
        anomalies = queue.queue_anomalies()
        anomaly_ids = set()
        for a in anomalies:
            anomaly_ids.update(a["items"])
        _print_anomalies(anomalies)
        pending = queue.pending_risk_sorted()
        decided = [r for r in queue.all() if r["status"] != "pending"]
        _print_records(pending, queue, anomaly_ids)
        if decided:
            print("Decided:")
            _print_records(decided, queue)
        return 0

    if args.cmd == "anomalies":
        anomalies = queue.queue_anomalies()
        if not anomalies:
            print("no queue-anomaly signals: arrival rate, per-agent "
                  "volume, and tool mix all look normal")
            return 0
        _print_anomalies(anomalies)
        print("advisory only: anomalous items are never auto-approved; "
              "their risk scores are escalated and batch approve requires "
              "per-item confirmation for them.")
        return 0

    if args.cmd == "floods":
        groups = queue.flood_groups()
        if not groups:
            print("no flood clusters (>= %d pending from one agent+tool)"
                  % FLOOD_THRESHOLD)
            return 0
        for (agent, tool), members in sorted(groups.items()):
            print("FLOOD-SUSPECT: agent %s tool %s: %d pending (%s)" % (
                agent, tool, len(members),
                ", ".join(r["id"] for r in members)))
            print("  these items require individual review; batch approve "
                  "refuses them without --confirm-risky per id")
        return 0

    if args.cmd == "audit":
        status = queue.audit_status()
        print("audit status: %s" % ("CLEAN" if status["clean"] else "UNCLEAN"))
        print("  pending approvals: %d" % status["pending_count"])
        if status["flood_suspect_ids"]:
            print("  flood suspects: %s"
                  % ", ".join(status["flood_suspect_ids"]))
        if status["unresolved_break_glass"]:
            print("  unresolved break-glass post-reviews: %s"
                  % ", ".join(status["unresolved_break_glass"]))
        return 0

    if args.cmd == "reviews":
        tickets = queue.pending_reviews()
        if not tickets:
            print("no unresolved post-review tickets")
            return 0
        for t in tickets:
            print("  %s | approval %s | operator %s | reason: %s"
                  % (t["ticket_id"], t["approval_id"], t["operator"],
                     t["break_glass_reason"]))
        return 0

    if args.cmd == "review-resolve":
        try:
            ticket, entry = queue.resolve_review(
                args.ticket, args.resolution, reviewer=args.by)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        print("resolved post-review ticket %s by %s (log seq %d)"
              % (ticket["ticket_id"], args.by, entry["seq"]))
        return 0

    if args.cmd == "break-glass":
        try:
            record, ticket = queue.break_glass(args.id, args.reason,
                                               operator=args.by)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        print("BREAK-GLASS approved %s (%s %s) by %s"
              % (record["id"], record["agent_id"], record["tool"], args.by))
        print("post-review ticket opened: %s" % ticket["ticket_id"])
        print("AUDIT STATUS: UNCLEAN until %s is resolved by a reviewer "
              "other than %s" % (ticket["ticket_id"], args.by))
        print("the action is approved but not yet executed; run the "
              "executor to execute approved actions.")
        return 0

    if args.cmd == "batch":
        ids = [i.strip() for i in args.ids.split(",") if i.strip()]
        confirmed = [i.strip() for i in args.confirm_risky.split(",")
                     if i.strip()]
        try:
            decided, excluded, batch_entry = queue.batch_decide(
                ids, args.action == "approve", args.rationale,
                decided_by=args.by, confirm_risky=confirmed)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        print("%s %d approval(s) by %s (batch log seq %d)"
              % ("Approved" if args.action == "approve" else "Rejected",
                 len(decided), args.by, batch_entry["seq"]))
        for r in decided:
            print("  %s (%s %s)" % (r["id"], r["agent_id"], r["tool"]))
        if excluded:
            # F21: security-excluded items need an individual decision.
            print("needs individual decision (%d):" % len(excluded))
            for r in excluded:
                print("  %s (%s %s): %s"
                      % (r["id"], r["agent_id"], r["tool"],
                         r.get("batch_exclusion_reason", "")))
        if args.action == "approve":
            print("approved actions are not yet executed; run the executor "
                  "to execute approved actions.")
        return 0

    if args.cmd == "auto-approve":
        from .policy import PolicyEngine
        policy = PolicyEngine(args.policy)
        auto_cfg = policy.auto_approve
        if not auto_cfg.get("enabled"):
            print("auto_approve is not enabled in %s; nothing to do"
                  % args.policy)
            return 0
        done = []
        for r in queue.pending_risk_sorted():
            decided = queue.maybe_auto_approve(r["id"], auto_cfg)
            if decided is not None:
                done.append(decided["id"])
        print("auto-approved %d low-risk item(s): %s"
              % (len(done), ", ".join(done) if done else "(none)"))
        print("each auto-approval wrote a full audit record "
              "(decided_by=auto-approve)")
        return 0

    try:
        record, entry = queue.decide(args.id, args.cmd == "approve",
                                     args.reason, decided_by=args.by)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print("%s approval %s (%s %s)" % (
        "Approved" if args.cmd == "approve" else "Rejected",
        record["id"], record["agent_id"], record["tool"]))
    print("decided by: %s" % args.by)
    print("reason: %s" % args.reason)
    print("logged as entry seq %d" % entry["seq"])
    if args.cmd == "approve":
        print("Note: the action is approved but not yet executed; the executor")
        print("runs approved actions separately so execution itself is logged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
