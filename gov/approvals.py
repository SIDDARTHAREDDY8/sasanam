"""File-based human approval queue.

When the policy engine returns "require_approval", the action is NOT executed.
It is stored as a pending approval with full context. A human reviews it with:

    python -m gov.approve --rundir <run dir> list
    python -m gov.approve --rundir <run dir> approve <id> --reason "..."
    python -m gov.approve --rundir <run dir> reject <id> --reason "..."

(Use --latest instead of --rundir to target the most recent run.)

Approval hardening:

* **Integrity binding.** Each record stores ``args_digest``, an HMAC-SHA256
  over the queued (redacted) arguments plus the policy id, keyed to the
  active log HMAC key with the key epoch bound in (F34; scheme
  ``hmac-sha256-v1``). The executor refuses to run an approval whose
  arguments changed after queueing — or whose record predates the keyed
  scheme (fail-closed upgrade). Under the public development key the MAC
  gives no forgery resistance to anyone who read the docs (F29 residual).
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
import contextlib
import fcntl
import hmac
import json
import os
import stat
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .identity import AgentIdentity
from .log import (ActionLog, _active_key, _approval_record_mac,
                  _break_glass_ticket_mac, _canonical, _verify,
                  read_entries, read_entries_with_stats,
                  verify_chain_tip, write_chain_tip_from_tail)
from .egress_ledger import _ledger_keyring


def _utcnow():
    return datetime.now().astimezone().isoformat(timespec="seconds")


_MISSING = object()


def _reconcile_marker_cache_mac(key, key_epoch, body_canonical):
    """R17 (F71): domain-separated MAC for the reconcile
    marker-verdict cache body (everything but ``mac``). The cache
    lives in the run dir, so only the log key keeps the F52 writer
    from forging a "valid" verdict and silencing the loud refusal."""
    msg = ("reconcile-marker-verdict|%s|%s"
           % (key_epoch, body_canonical)).encode("utf-8")
    return hmac.new(key, msg, sha256).hexdigest()


# F39 (R10): how long an execute_approved() sweep waits for the queue's
# exclusive lock before failing closed. Mirrors the F25 action-log
# append lock (gov/log.py): a crashed lock holder's flock is released
# by the kernel on process death, so a timeout means a LIVE sweeper is
# stuck mid-sweep — refusing to sweep unlocked is the safe direction.
APPROVAL_QUEUE_LOCK_TIMEOUT_SECS = 30
_QUEUE_LOCK_POLL_SECS = 0.02


class QueueLockError(OSError):
    """F39: the approval-queue sweep lock could not be acquired in time.

    Raised by ``ApprovalQueue._queue_locked`` when another sweeper
    holds the queue lock past the timeout. The sweep never runs
    unlocked: without the lock two concurrent sweeps can both read a
    record as approved-and-unexecuted and execute it twice (double
    side effect, double budget charge). Callers must treat this as a
    fail-closed refusal and audit it.
    """


class QueueLockInvalidatedError(QueueLockError):
    """F44 (R11): the sweep lock was invalidated mid-acquisition.

    Raised by ``ApprovalQueue._queue_locked`` when the lock file was
    deleted or replaced between open() and flock() (inode/device
    mismatch or unlinked path). A deleted lock file lets a second
    opener lock a DIFFERENT inode while the first sweeper still holds
    the old one — silent double execution. This is a distinct,
    louder failure than a timeout: the executor audits it as
    ``queue_lock_invalidated`` and refuses the sweep. Never retried
    silently.
    """


class QueueLockPathError(QueueLockError):
    """F51 (R12): the lock path itself is unusable — not a regular file.

    Raised by ``ApprovalQueue._queue_locked`` when the lock path
    cannot be opened for locking at all (e.g. a run-dir writer
    swapped ``approvals.lock`` for a DIRECTORY — the old code let the
    resulting ``IsADirectoryError`` escape unaudited) or when the
    opened lock file is not a regular file. A non-file at the lock
    path is fail-closed, never an uncaught exception: the executor
    audits it as ``queue_lock_invalid`` and refuses the sweep.
    """


def record_digest(tool, args, policy_id, egress_bytes=_MISSING):
    """Legacy UNKEYED integrity digest (pre-R9 attacker primitive).

    Kept ONLY so the F34 red-team probe can demonstrate the closed
    attack: a record carrying this unkeyed digest is refused by
    :func:`approval_digest_ok` / ``ToolExecutor.execute_approved``. New
    code must use :func:`approval_record_digest`.
    """
    payload = {"tool": tool, "args": args, "policy_id": policy_id}
    if egress_bytes is not _MISSING:
        payload["egress_bytes"] = egress_bytes
    payload = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


# F34: approval records are MACed, not merely hashed. The MAC is keyed to
# the active log HMAC key (see gov.log._approval_record_mac) with the key
# epoch bound in and verified against the keyring, so key rotation is
# explicit. Anything but the keyed scheme is refused at execution
# (fail-closed upgrade — queued items must be decided before upgrading).
APPROVAL_DIGEST_SCHEME = "hmac-sha256-v1"


def _canonical_json(obj):
    """F43 (R11): deterministic canonical JSON with normalization.

    Dicts sort by key; sets/frozensets become lists sorted by their
    canonical form (``str(set)`` is NOT deterministic across runs —
    hash randomization — so sets must be normalized before hashing);
    tuples are treated as lists; anything else falls back to
    ``str()``. The MAC input is therefore stable for equal security
    records and never depends on in-memory iteration order.
    """
    if isinstance(obj, dict):
        return {str(k): _canonical_json(v)
                for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (set, frozenset)):
        return sorted(
            (_canonical_json(v) for v in obj),
            key=lambda x: json.dumps(x, sort_keys=True,
                                     separators=(",", ":"), default=str,
                                     ensure_ascii=True))
    if isinstance(obj, (list, tuple)):
        return [_canonical_json(v) for v in obj]
    return obj


def _canonical_dumps(obj):
    return json.dumps(_canonical_json(obj), sort_keys=True,
                      separators=(",", ":"), default=str, ensure_ascii=True)


# F43 (R11): every record field that influences the approver's display,
# the risk/auto-approval decision, the policy reason attribution, or the
# identity the action executes as. Tampering with ANY of these between
# queue() and decide()/execute_approved() breaks the MAC. This is the
# single payload definition — _pending_record_content_ok() and
# approval_digest_ok() both verify against it, so the two checks cannot
# drift apart.
_SECURITY_PAYLOAD_FIELDS = (
    "tool", "args", "policy_id", "egress_bytes", "run_id", "decided_by",
    "agent_id", "role", "principal", "identity",
    "preview", "provenance", "policy_context", "policy_flag",
    "delegation_attempted",
)


def _security_record_payload(rec):
    """F43 (R11): extract the canonical security payload from a record.

    Every field in ``_SECURITY_PAYLOAD_FIELDS`` is bound; missing
    fields bind as None (a record that drops a security field does not
    verify against a record that has it — fail closed).
    ``delegation_attempted`` normalizes to bool.
    """
    payload = {f: rec.get(f) for f in _SECURITY_PAYLOAD_FIELDS}
    payload["delegation_attempted"] = bool(rec.get("delegation_attempted"))
    return _canonical_dumps(payload)


def approval_record_digest(rec):
    """F34/F38/F43: HMAC-keyed integrity digest binding a queued approval
    to its full security record.

    R11 changed the payload: beyond (tool, args, policy_id,
    egress_bytes, run_id, decided_by) the MAC now binds the
    authenticated identity (agent_id/role/principal/identity dict),
    the approver-facing ``preview``, ``provenance``,
    ``policy_context``, ``policy_flag``, and ``delegation_attempted``.
    Rewriting the preview, swapping the attribution, or relabeling
    the identity between queue() and decide()/execute_approved()
    breaks the digest. Records MACed under the pre-R11 narrow payload
    fail verification automatically — fail-closed upgrade, same
    precedent as F34/F38. The MAC is computed under the active log key
    with the key epoch bound in; verification tries every epoch in the
    keyring. Under the PUBLIC development key this gives no forgery
    resistance to anyone who read the docs (F29/F34 residual).
    """
    key, key_epoch = _active_key()
    return _approval_record_mac(key, key_epoch,
                                _security_record_payload(rec))


def _pending_record_content_ok(rec):
    """F38 (R10) / F43 (R11): True when a PENDING record's keyed digest
    verifies over the full security payload — with decided_by=None —
    regardless of the digest_scheme label. This is the decide()-time
    tamper check: it detects rewrites of what was approved between
    queue() and decide(), now including preview swaps, provenance or
    policy_context edits, policy_flag changes, and identity
    relabeling. The scheme label itself is deliberately NOT checked
    here — a scheme-label rewrite keeps the documented wave-11
    behavior: decide() proceeds, and the verifier fails closed on the
    unknown scheme at execution (audited as
    approval_integrity_violation; see evals/w11_probes.py::_w11_keyseams
    part (b)). The scheme label is not a MAC input, so rewriting it
    cannot launder tampered content through the decision re-MAC.
    """
    if not isinstance(rec, dict):
        return False
    if "egress_bytes" not in rec:
        return False
    for key_epoch, key in _ledger_keyring().items():
        candidate = _approval_record_mac(
            key, key_epoch, _security_record_payload(rec))
        if hmac.compare_digest(rec.get("args_digest", ""), candidate):
            return True
    return False


# -- F49 (R11): human-provisioned break-glass tickets ----------------------
#
# Break-glass is the emergency path around human approval. Before R11,
# break_glass() authenticated only an executor-minted identity — any
# permissively-minted identity qualified, and the post-review ticket
# could be discharged by a distinct attacker-minted confederate
# (wave-12 sit73). Now break-glass additionally requires a
# HUMAN-PROVISIONED ticket:
#
# * The operator provisions tickets OUT-OF-BAND before the run, via
#   provision_break_glass_ticket() (or the `gov.approve
#   provision-break-glass` CLI): each ticket binds an operator
#   principal and a DISTINCT reviewer principal, is HMAC-signed under
#   the active log key at provisioning time, and is appended to
#   <run_dir>/break_glass_tickets.jsonl.
# * At run start (first ToolExecutor construction) the queue takes a
#   write-once snapshot of the ticket store, verifying every HMAC.
#   Tickets planted AFTER the snapshot — including well-formed ones
#   the agent forges with a compromised dev key — are never in the
#   snapshot and can never authorize break-glass.
# * break_glass() requires a ticket id, verifies it is provisioned,
#   unused, HMAC-valid, and bound to the calling operator's principal;
#   the post-review ticket inherits the PROVISIONED reviewer
#   principal, and resolve_review() refuses anyone else.
# * Honest residual: there is no live human channel in this product —
#   the guarantee is that no ticket the agent minted for itself
#   mid-run can ever authorize break-glass. An attacker who steals the
#   operator's provisioning key (same trust anchor as GOV_LOG_KEY)
#   and constructs a fresh executor mid-run could provision to
#   itself; key custody is the boundary, exactly as for the log key.

BREAK_GLASS_TICKET_FILENAME = "break_glass_tickets.jsonl"
# F54 (R12): dedicated lock file for cross-process break-glass ticket
# consumption. NEVER rewritten — opened only to hold an flock — so the
# lock cannot be invalidated by a replace-write of the ticket store.
_BREAK_GLASS_TICKET_LOCK_FILENAME = "break_glass_tickets.lock"


def _ticket_canonical(ticket_id, operator_principal, reviewer_principal,
                      purpose, created_at, used=False, used_at=None,
                      used_for_approval=None):
    return _canonical_dumps({
        "ticket_id": ticket_id,
        "operator_principal": operator_principal,
        "reviewer_principal": reviewer_principal,
        "purpose": purpose or "",
        "created_at": created_at,
        # F57 (R13): the consumption state rides the HMAC — flipping
        # used=False on a consumed ticket without re-signing (which
        # needs the keyring key) fails verification. used_at /
        # used_for_approval are bound the same way so a consumed
        # ticket's audit trail cannot be scrubbed without the key.
        "used": bool(used),
        "used_at": used_at,
        "used_for_approval": used_for_approval,
    })


def provision_break_glass_ticket(store_path, ticket_id, operator_principal,
                                 reviewer_principal, purpose=""):
    """F49: human-operator provisioning of a break-glass ticket.

    Appends an HMAC-signed ticket to the ticket store. This is the
    ONLY way to create a ticket the queue will honor, and it must run
    out-of-band (operator terminal / deployment tooling) BEFORE the
    run starts — never from agent code, never mid-run. Provisioning
    validates: non-empty ids/principals, operator != reviewer, and
    ticket_id uniqueness (no overwriting an existing ticket).
    Returns the ticket dict.
    """
    if not ticket_id or not str(ticket_id).strip():
        raise ValueError("ticket_id must be non-empty")
    if not operator_principal or not str(operator_principal).strip():
        raise ValueError("operator_principal must be non-empty")
    if not reviewer_principal or not str(reviewer_principal).strip():
        raise ValueError("reviewer_principal must be non-empty")
    if operator_principal == reviewer_principal:
        raise ValueError(
            "separation of duties: the provisioned reviewer principal "
            "must differ from the operator principal")
    store_path = Path(store_path)
    existing = _read_verified_ticket_store(store_path, audit_log=None)
    if ticket_id in existing:
        raise ValueError("ticket_id %r is already provisioned" % ticket_id)
    created_at = _utcnow()
    key, key_epoch = _active_key()
    ticket = {
        "ticket_id": ticket_id,
        "operator_principal": operator_principal,
        "reviewer_principal": reviewer_principal,
        "purpose": purpose or "",
        "created_at": created_at,
        "created_by": "human-operator",
        "key_epoch": key_epoch,
        "used": False,
        "used_at": None,
        "used_for_approval": None,
        "hmac": _break_glass_ticket_mac(
            key, key_epoch,
            _ticket_canonical(ticket_id, operator_principal,
                              reviewer_principal, purpose, created_at)),
    }
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with open(store_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(ticket, ensure_ascii=True, default=str) + "\n")
    return ticket


def _read_verified_ticket_store(store_path, audit_log=None):
    """F49: read the ticket store, verifying every entry's HMAC.

    Returns {ticket_id: entry} for entries with a valid HMAC under a
    keyring epoch. Entries with missing/invalid HMACs are SKIPPED —
    never trusted — and, when audit_log is provided, each is reported
    as a ``break_glass_ticket_invalid`` audit event (loud, not
    silent). Duplicate ticket_ids: the first valid entry wins.
    """
    store_path = Path(store_path)
    if not store_path.exists():
        return {}
    keyring = _ledger_keyring()
    valid = {}
    for line in store_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or "ticket_id" not in entry:
            continue
        canonical = _ticket_canonical(
            entry.get("ticket_id"), entry.get("operator_principal"),
            entry.get("reviewer_principal"), entry.get("purpose"),
            entry.get("created_at"),
            # F57 (R13): the used state is HMAC-bound, so it must be
            # fed back into the canonical — otherwise a legitimately
            # consumed (re-signed) ticket would fail verification.
            used=entry.get("used"), used_at=entry.get("used_at"),
            used_for_approval=entry.get("used_for_approval"))
        ok = False
        for key_epoch, key in keyring.items():
            candidate = _break_glass_ticket_mac(key, key_epoch, canonical)
            if hmac.compare_digest(entry.get("hmac", ""), candidate):
                ok = True
                break
        if not ok:
            if audit_log is not None:
                audit_log.append({
                    "event": "break_glass_ticket_invalid",
                    "run_id": store_path.parent.name,
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "ticket_rejected",
                    "policy_id": "break-glass-ticket",
                    "ticket_id": entry.get("ticket_id"),
                    "reason": ("break-glass ticket store entry failed "
                               "HMAC verification; it is skipped and can "
                               "never authorize break-glass"),
                })
            continue
        valid.setdefault(entry["ticket_id"], entry)
    return valid


def approval_digest_ok(rec):
    """F34/F43: True when an approval record carries a valid keyed digest.

    Fail-closed: anything without ``digest_scheme == "hmac-sha256-v1"``
    (pre-R9 unkeyed records, hand-built forgeries) returns False. A
    record that HAS the ``egress_bytes`` key is always verified with it
    (F33 rule preserved — removing the key does not downgrade the check).
    F38 (R10): the verified payload includes the record's ``run_id``
    and ``decided_by``. F43 (R11): the verified payload is the full
    security record — identity, preview, provenance, policy_context,
    policy_flag, delegation_attempted — so tampering with any of them
    after queue() is detected here at execution time. Pre-R11 digests
    (narrow payload) fail closed automatically.
    """
    if not isinstance(rec, dict):
        return False
    if rec.get("digest_scheme") != APPROVAL_DIGEST_SCHEME:
        return False
    if "egress_bytes" not in rec:
        return False
    for key_epoch, key in _ledger_keyring().items():
        candidate = _approval_record_mac(
            key, key_epoch, _security_record_payload(rec))
        if hmac.compare_digest(rec.get("args_digest", ""), candidate):
            return True
    return False


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


def _score_factors(record, queue_records, anomaly_ids=(), ignore_history=False):
    """Return (score, factors) with deterministic, documented factors.

    ``anomaly_ids`` are pending ids in a queue-anomaly cluster (see
    queue_anomalies): the bump is ADVISORY and one-directional — it can
    only raise the score, never lower it, and it never approves.

    ``ignore_history`` (F35): score as an unknown agent even when the
    agent has prior decisions — the history-neutral score used by
    ``maybe_auto_approve`` so a farmable veteran discount can never flip
    an auto-approve decision.
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
    untrusted = (record.get("provenance") == "untrusted_influenced"
                 or ctx.get("source_untrusted"))
    if untrusted:
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
    if agent and (not decided_before or ignore_history):
        score += 10
        factors.append("unknown agent (no prior decisions) +10")
    elif agent and untrusted:
        # F35: approval history is farmable — an untrusted-influenced
        # item gets NO veteran discount. Benign history must not lower
        # the score of an item whose provenance is untrusted: veterans
        # score untrusted items exactly like unknown agents, so history
        # can never flip an auto-approve decision on untrusted traffic.
        # (Genuinely benign repeat traffic keeps the discount — only
        # untrusted provenance withholds it.)
        score += 10
        factors.append("untrusted provenance: history discount withheld +10")
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

    def _risk_no_discount(self, record):
        """F35: history-neutral risk score (scores as an unknown agent).

        Second gate for ``maybe_auto_approve``: the veteran discount is a
        queue-ordering signal, never an auto-approval justification. When
        this exceeds the cap the item stays pending for a human even
        though the discounted score fits under the cap.
        """
        records = self.all()
        score, _ = _score_factors(
            record, records,
            anomaly_ids=self._anomaly_id_set(records), ignore_history=True)
        return score

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

        F24 (W7-2): security-excluded items (see
        ``_batch_blocked_reason``) can NEVER be auto-approved — the F21
        invariant is "security items need an individual human decision",
        and auto-approve is exactly the zero-human-decision path the
        exclusion exists to block. Excluded items stay pending for a
        human, like every other gate refusal here (silent None).
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
        # F24: the exclusion is categorical — check it before the risk
        # cap, so a low-risk campaign fragment (risk 20 <= cap 25) can
        # never slip through on score alone.
        if self._batch_blocked_reason(record) is not None:
            return None
        self.refresh_flood_flags()
        record = self.get(approval_id)
        if record.get("flood_suspect"):
            return None
        score = self.risk(record)
        if score > cap:
            return None
        # F35: the queue-ordering history discount must never FLIP an
        # auto-approve decision. Re-score history-neutral (as an unknown
        # agent): when that exceeds the cap, the item stays pending for
        # a human even though the discounted score fits under it. (For
        # untrusted-influenced items the discount is already withheld in
        # _score_factors, so the two scores agree there; this gate covers
        # trusted items whose veteran history would otherwise flip them.)
        if self._risk_no_discount(record) > cap:
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

    def _ticket_store_path(self):
        return self.run_dir / BREAK_GLASS_TICKET_FILENAME

    @contextlib.contextmanager
    def _break_glass_ticket_locked(self):
        """F54 (R12): exclusive cross-process lock around break-glass
        ticket consumption (resolve -> validate -> decide -> consume).

        The lock file is dedicated and never rewritten, so holding its
        flock is a sound mutex even though the ticket store itself is
        rewritten in place. Blocking LOCK_EX is safe here: the section
        is bounded (one decide + two file rewrites), and a crashed
        holder's flock is released by the kernel.
        """
        lock_path = self.run_dir / _BREAK_GLASS_TICKET_LOCK_FILENAME
        self.run_dir.mkdir(parents=True, exist_ok=True)
        f = open(lock_path, "a", encoding="utf-8")
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()

    def snapshot_break_glass_tickets(self):
        """F49 (R11): write-once snapshot of the human-provisioned
        break-glass ticket store, taken at run start.

        Called by ``ToolExecutor.__init__`` (guarded by hasattr): the
        first executor to construct seals the ticket set this run will
        honor. Every entry's HMAC is verified here; invalid entries
        are skipped loudly (``break_glass_ticket_invalid`` audit
        events). Tickets provisioned AFTER this snapshot — including
        well-formed tickets the agent forges mid-run — are never in
        the snapshot and can never authorize break-glass. A second
        executor sharing this queue keeps the first snapshot (the
        agent cannot re-open the provisioning window by constructing
        a fresh executor).
        """
        if self._bg_ticket_snapshot is not None:
            return self._bg_ticket_snapshot
        self._bg_ticket_snapshot = _read_verified_ticket_store(
            self._ticket_store_path(), audit_log=self.log)
        return self._bg_ticket_snapshot

    def _resolve_break_glass_ticket(self, ticket_id):
        """F49: resolve a ticket id to its provisioned entry.

        Executor path: from the run-start snapshot (tickets planted
        mid-run are invisible here). CLI path (no executor ever
        constructed — the human operator's terminal): read and verify
        the store file live. Returns None for unknown/invalid/used
        tickets.
        """
        if self._bg_ticket_snapshot is not None:
            entry = self._bg_ticket_snapshot.get(ticket_id)
        else:
            entry = _read_verified_ticket_store(
                self._ticket_store_path(), audit_log=self.log).get(ticket_id)
        if not entry or entry.get("used"):
            return None
        return entry

    def _ticket_consumed_in_log(self, ticket_id):
        """F57 (R13): has this ticket already been consumed, per the
        VERIFIED action log?

        The ticket store alone cannot answer this: a pre-consume store
        snapshot can be replayed over the live store file, making a
        consumed ticket look fresh again. The action log is
        append-only and HMAC-chained, so the ``ticket_consumed`` event
        appended at consumption time survives any store replay. Verify
        the chain BEFORE trusting the markers: a tampered or
        unverifiable log fails CLOSED (treated as consumed), as does a
        missing log handle. Never raises on content problems —
        ``_verify`` reports them as a verdict dict.
        """
        log_path = getattr(self.log, "path", None)
        if log_path is None:
            return True
        verdict = _verify(log_path)
        if not verdict.get("ok"):
            return True
        for entry in read_entries(log_path):
            if (isinstance(entry, dict)
                    and entry.get("event") == "ticket_consumed"
                    and entry.get("ticket_id") == ticket_id):
                return True
        return False

    def _mark_ticket_used(self, ticket_id, approval_id):
        """F49: single-use — mark a ticket consumed in the snapshot and
        persist the used flag to the store file (under the queue lock)
        so a second process/CLI invocation cannot reuse it.

        F57 (R13): the used state is HMAC-bound — the entry is
        RE-SIGNED with used=True / used_at / used_for_approval, so a
        replayed pre-consume store line cannot be spliced back in
        (flipping used=False without the keyring key fails
        verification)."""
        used_at = _utcnow()
        key, key_epoch = _active_key()

        def _resign(entry):
            entry["used"] = True
            entry["used_at"] = used_at
            entry["used_for_approval"] = approval_id
            entry["hmac"] = _break_glass_ticket_mac(
                key, key_epoch,
                _ticket_canonical(
                    entry.get("ticket_id"),
                    entry.get("operator_principal"),
                    entry.get("reviewer_principal"),
                    entry.get("purpose"),
                    entry.get("created_at"),
                    used=True, used_at=used_at,
                    used_for_approval=approval_id))
            return entry

        if self._bg_ticket_snapshot is not None:
            entry = self._bg_ticket_snapshot.get(ticket_id)
            if entry is not None:
                _resign(entry)
        path = self._ticket_store_path()
        if path.exists():
            lines = []
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    lines.append(line)
                    continue
                if isinstance(e, dict) and e.get("ticket_id") == ticket_id:
                    _resign(e)
                    line = json.dumps(e, ensure_ascii=True, default=str)
                lines.append(line)
            with open(path, "w", encoding="utf-8") as f:
                for line in lines:
                    f.write(line + "\n")

    def _refuse_break_glass(self, approval_id, reason, ticket_id=None,
                            operator_principal=None):
        self.log.append({
            "event": "break_glass_refused",
            "run_id": self.run_id,
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "decision": "refused",
            "approval_id": approval_id,
            "policy_id": "break-glass-ticket",
            "ticket_id": ticket_id,
            "operator_principal": operator_principal,
            "reason": reason,
        })

    def break_glass(self, approval_id, reason, operator_identity,
                    ticket_id=None):
        """Emergency-approve a pending item with a mandatory post-review.

        * reason must be non-empty (the emergency justification);
        * refused while any post-review ticket is unresolved: stacked
          break-glass without review is not allowed (fail-closed);
        * F26: the ticket binds to ``operator_identity`` — an
          ``AgentIdentity`` minted by the executor for the caller — not
          to a caller-supplied string. Bare strings are rejected with
          ``TypeError``; when the queue has an executor-installed
          identity verifier, unminted identities raise
          ``UnregisteredPrincipalError``/``UnmintedIdentityError``.
        * F49 (R11): ``ticket_id`` is REQUIRED — a human-provisioned
          break-glass ticket (see ``provision_break_glass_ticket``)
          that pre-existed the run. The ticket must be provisioned
          (in the run-start snapshot, or the live store on the CLI
          path), unused, HMAC-valid, and bound to the calling
          operator's principal. Tickets the agent minted for itself
          mid-run — including well-formed HMACed ones — are refused.
          Refusals are audited as ``break_glass_refused``.
        * F57 (R13): single-use is enforced against the VERIFIED action
          log, not just the ticket store — a replayed pre-consume store
          snapshot cannot resurrect a consumed ticket, because the
          append-only ``ticket_consumed`` event survives the replay.
          The ticket's HMAC binds its used state (re-signed on
          consume).
        * creates a post-review ticket that keeps the audit status
          UNCLEAN until the PROVISIONED reviewer (bound at provisioning
          time, distinct from the operator) resolves it.
        Returns (record, ticket).
        """
        operator_identity = self._authenticate_caller(
            operator_identity, "break_glass")
        # F55 (R13): when the deployment provisioned a session identity,
        # break-glass is entitled ONLY to that identity. The F26
        # verifier checks mintedness, never entitlement — in-process
        # code holding the executor can mint the registered operator
        # tuple mid-run, so a merely-minted operator identity is
        # refused here with an audited entry. Without a provisioned
        # session identity the pre-R13 F26 behavior is kept (dev
        # mode), with the existing self-asserted warnings.
        if self._session_identity is not None:
            # F59 (R14): TRUE OBJECT IDENTITY (``is``, not ``!=``). A
            # separately minted identity with identical
            # (agent_id, role, principal) fields compares structurally
            # equal (``==``) but is a different object — and is NOT
            # entitled. The anchor itself is a read-only property (no
            # setter), so the F59 attribute-swap shape raises
            # AttributeError before reaching here.
            if operator_identity is not self._session_identity:
                self._refuse_break_glass(
                    approval_id,
                    "break-glass refused: operator identity %r is not "
                    "the deployment-provisioned session identity OBJECT "
                    "(F59: identity compared with `is`; provenance=%r, "
                    "want 'provisioned'): mid-run minted identities are "
                    "not entitled to consume break-glass tickets (F55)"
                    % (
                        (operator_identity.agent_id,
                         operator_identity.role,
                         operator_identity.principal),
                        getattr(operator_identity, "provenance",
                                "minted")),
                    ticket_id=ticket_id,
                    operator_principal=operator_identity.principal)
                raise ValueError(
                    "break-glass refused: mid-run minted identities "
                    "are not entitled (F55/F59); the deployment-"
                    "provisioned session identity OBJECT is required")
        elif (self._registry_configured
                and self._break_glass_unprotected_warn_once()):
            # F64 (R14): registry mode WITHOUT a provisioned session
            # identity is a SILENT weak mode — break-glass runs with NO
            # identity entitlement checks (the documented F55
            # residual: any in-process minted operator tuple can consume
            # tickets). Mirror the F50 dev-mode one-time warning:
            # loud on stderr AND an audited entry, once per queue.
            # registry-without-session-identity is explicitly
            # unsupported for production deployments.
            # F67 (R15): the flag lives in ApprovalQueue's name-mangled
            # slot (read-only property, no setter); only the helper
            # below can transition it, exactly once.
            warn_msg = (
                "GOVERNANCE WARNING: PrincipalRegistry is configured "
                "but NO session identity was provisioned — break-glass "
                "is operating WITHOUT identity entitlement checks "
                "(F64): any in-process minted operator identity can "
                "consume break-glass tickets. Provision a session "
                "identity for production deployments; "
                "registry-without-session-identity is explicitly "
                "unsupported.")
            print(warn_msg, file=sys.stderr)
            self.log.append({
                "event": "break_glass_unprotected",
                "run_id": self.run_id,
                "agent_id": "system",
                "role": "governance",
                "principal": "system",
                "decision": "n/a",
                "policy_id": "break-glass-entitlement",
                "operator_principal": operator_identity.principal,
                "ticket_id": ticket_id,
                "reason": ("break-glass invoked in registry mode with "
                           "no provisioned session identity: operating "
                           "WITHOUT identity entitlement checks (F64). "
                           "Any in-process minted operator identity can "
                           "consume break-glass tickets; this "
                           "configuration is explicitly unsupported "
                           "for production."),
            })
        if not reason or not reason.strip():
            raise ValueError("break-glass requires a non-empty reason")
        if not ticket_id:
            self._refuse_break_glass(
                approval_id,
                "break-glass requires a human-provisioned ticket id "
                "(F49): no ticket the agent minted for itself can "
                "authorize break-glass",
                ticket_id=None,
                operator_principal=operator_identity.principal)
            raise ValueError(
                "break-glass requires a human-provisioned ticket id: "
                "provision one out-of-band before the run (F49)")
        # F49: the ticket resolve -> consume sequence is guarded by
        # the cross-thread mutex so two concurrent break_glass calls
        # cannot both observe an unused ticket (single-use atomicity).
        #
        # F54 (R12): the mutex above is a threading.Lock — it does NOT
        # cross fork(). Two sibling processes forked from one run each
        # carry their own STALE run-start ticket snapshot and their own
        # copy of the mutex, so both could resolve an unused ticket
        # from the snapshot and both consume it before either persisted
        # the used flag (one ticket, two emergency approvals). The
        # resolve -> validate -> decide -> consume critical section
        # therefore ALSO holds an exclusive flock on a dedicated lock
        # file, and inside the lock the LIVE ticket store is re-read:
        # the winner's _mark_ticket_used has persisted by the time the
        # loser gets in, and the loser refuses. Lock ordering is always
        # thread-mutex -> file-lock; the section is bounded and a
        # crashed holder's flock is released by the kernel.
        with self._bg_ticket_lock:
            with self._break_glass_ticket_locked():
                ticket_entry = self._resolve_break_glass_ticket(ticket_id)
                if ticket_entry is None:
                    self._refuse_break_glass(
                        approval_id,
                        "unknown, HMAC-invalid, or already-used break-glass "
                        "ticket %r: not provisioned before this run" % ticket_id,
                        ticket_id=ticket_id,
                        operator_principal=operator_identity.principal)
                    raise ValueError(
                        "break-glass refused: ticket %r is not a valid unused "
                        "human-provisioned ticket for this run" % ticket_id)
                # F54: the snapshot only proves the ticket was
                # provisioned BEFORE the run (F49's no-mid-run-ticket
                # rule) — it is a stale per-process copy. Single-use
                # atomicity across forked processes needs the live
                # store, re-read under the cross-process lock.
                live_entry = _read_verified_ticket_store(
                    self._ticket_store_path()).get(ticket_id)
                if live_entry is None or live_entry.get("used"):
                    self._refuse_break_glass(
                        approval_id,
                        "break-glass ticket %r was already consumed by "
                        "another process (single-use; F54 cross-process "
                        "check on the live ticket store)" % ticket_id,
                        ticket_id=ticket_id,
                        operator_principal=operator_identity.principal)
                    raise ValueError(
                        "break-glass refused: ticket %r already used "
                        "(single-use)" % ticket_id)
                # F57 (R13): the AUTHORITATIVE consumed-ticket memory is
                # the verified action log, not the ticket store. A
                # replayed pre-consume store snapshot passes the live
                # check above (the store genuinely says "unused") —
                # but the append-only ticket_consumed event survives
                # the replay and refuses the reuse. Checked under the
                # cross-process lock so the check and the consume below
                # are one critical section.
                if self._ticket_consumed_in_log(ticket_id):
                    self._refuse_break_glass(
                        approval_id,
                        "break-glass ticket %r was already consumed "
                        "according to the verified action log "
                        "(single-use; F57 ticket-store replay check: a "
                        "restored pre-consume store cannot resurrect it)"
                        % ticket_id,
                        ticket_id=ticket_id,
                        operator_principal=operator_identity.principal)
                    raise ValueError(
                        "break-glass refused: ticket %r already consumed "
                        "(verified action log)" % ticket_id)
                if operator_identity.principal != ticket_entry["operator_principal"]:
                    self._refuse_break_glass(
                        approval_id,
                        "ticket %r is provisioned for operator principal %r, "
                        "not %r" % (ticket_id, ticket_entry["operator_principal"],
                                    operator_identity.principal),
                        ticket_id=ticket_id,
                        operator_principal=operator_identity.principal)
                    raise ValueError(
                        "break-glass refused: ticket %r is bound to a different "
                        "operator principal" % ticket_id)
                unresolved = self.pending_reviews()
                if unresolved:
                    raise ValueError(
                        "break-glass refused: %d post-review ticket(s) unresolved "
                        "(%s). Resolve reviews before another break-glass."
                        % (len(unresolved),
                           ", ".join(t["ticket_id"] for t in unresolved)))
                operator_label = operator_identity.principal
                record, _entry = self.decide(
                    approval_id, True,
                    "BREAK-GLASS by %s: %s" % (operator_label, reason.strip()),
                    decided_by=operator_label)
                record["break_glass"] = True
                record["break_glass_reason"] = reason.strip()
                self._rewrite(lambda records: [
                    record if r["id"] == record["id"] else r for r in records])
                # F49: single-use — consume the ticket before opening the
                # post-review ticket, so a crash between the two cannot leave
                # a reusable ticket behind the consumed authorization.
                #
                # F57 (R13): the AUTHORITATIVE consumed marker is the
                # append-only action-log event, and it is appended
                # BEFORE the ticket store is mutated. Ordering matters:
                # if we crash between the log append and the store
                # mutation, the ticket is burned (the log says consumed,
                # the next attempt refuses) — a fail-closed residual.
                # If the order were reversed, a crash would leave the
                # store consumed but the log silent, and a replayed
                # pre-consume store snapshot would resurrect the ticket
                # with no log evidence to refuse it.
                self.log.append({
                    "event": "ticket_consumed",
                    "run_id": record.get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "ticket_consumed",
                    "policy_id": "break-glass-ticket",
                    "ticket_id": ticket_id,
                    "approval_id": approval_id,
                    "operator_principal": operator_label,
                    "provisioned_reviewer_principal":
                        ticket_entry["reviewer_principal"],
                    "reason": ("break-glass ticket %r consumed for "
                               "approval %r (single-use; F57 authoritative "
                               "consumed marker)" % (ticket_id, approval_id)),
                })
                self._mark_ticket_used(ticket_id, approval_id)
        ticket = {
            "ticket_id": "PRV-%s" % approval_id,
            "approval_id": approval_id,
            # F26: the ticket binds to the AUTHENTICATED identity object.
            # "operator" stays as a human-readable label (back-compat for
            # existing ticket files); "operator_identity" is the binding
            # the separation-of-duty check enforces.
            "operator": operator_label,
            "operator_identity": operator_identity.as_dict(),
            # F49: the reviewer is the principal provisioned out-of-band
            # before the run — never whoever happens to hold a minted
            # identity mid-run.
            "provisioned_reviewer_principal":
                ticket_entry["reviewer_principal"],
            "provision_ticket_id": ticket_id,
            "break_glass_reason": reason.strip(),
            "tool": record.get("tool"),
            "agent_id": record.get("agent_id"),
            "status": "pending",
            "created_at": _utcnow(),
            "resolved_at": None,
            "resolved_by": None,
            "reviewer_identity": None,
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
            "decided_by": operator_label,
            # F26: the full authenticated identity rides the audit log.
            "operator_identity": operator_identity.as_dict(),
            # F49: the authorizing provisioned ticket rides the audit log.
            "provision_ticket_id": ticket_id,
            "provisioned_reviewer_principal":
                ticket_entry["reviewer_principal"],
            "reason": "BREAK-GLASS: %s (post-review ticket %s opened)"
                      % (reason.strip(), ticket["ticket_id"]),
            "post_review_ticket": ticket["ticket_id"],
            "audit_note": "audit status UNCLEAN until ticket %s is "
                          "resolved" % ticket["ticket_id"],
        })
        return record, ticket

    def resolve_review(self, ticket_id, resolution, reviewer_identity):
        """Resolve a post-review ticket.

        F26: ``reviewer_identity`` must be an ``AgentIdentity`` minted by
        the executor — bare caller-supplied strings are rejected with
        ``TypeError``. Separation of duties binds to the AUTHENTICATED
        objects: the reviewer's principal (from their minted identity)
        must differ from the break-glass actor's principal (from the
        identity object bound to the ticket at ``break_glass`` time).
        Comparing caller-supplied name strings is not acceptable, so the
        old ``reviewer="bob"`` alias path now fails closed.

        F49 (R11): the reviewer must ADDITIONALLY be the principal
        provisioned out-of-band on the break-glass ticket
        (``provisioned_reviewer_principal``) — a distinct minted
        confederate can no longer discharge the review. Tickets without
        a provisioned reviewer (pre-R11) fail closed.
        """
        reviewer_identity = self._authenticate_caller(
            reviewer_identity, "resolve_review")
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
        # F26: the bound operator identity's principal — never a
        # caller-supplied string. Legacy tickets (pre-F26) carry only the
        # "operator" label; the fail-closed fallback still refuses when
        # the reviewer's authenticated principal matches that label.
        bound = target.get("operator_identity") or {}
        operator_principal = bound.get("principal") or target.get("operator")
        if reviewer_identity.principal == operator_principal:
            raise ValueError(
                "separation of duties: the break-glass operator "
                "(principal %r) cannot resolve their own post-review "
                "ticket — a different authenticated principal must "
                "review" % (operator_principal,))
        # F49: the reviewer must be the principal provisioned
        # out-of-band before the run — a distinct attacker-minted
        # confederate is refused even though it is not the operator.
        provisioned = target.get("provisioned_reviewer_principal")
        if not provisioned:
            self.log.append({
                "event": "post_review_resolve_refused",
                "run_id": target.get("run_id") or self.run_dir.name,
                "agent_id": "human-operator",
                "role": "approver",
                "principal": "human-operator",
                "decision": "refused",
                "approval_id": target.get("approval_id"),
                "post_review_ticket": ticket_id,
                "reviewer_principal": reviewer_identity.principal,
                "reason": ("ticket has no provisioned reviewer "
                           "(pre-R11); fail closed"),
            })
            raise ValueError(
                "post-review ticket %s has no provisioned reviewer "
                "(pre-R11 ticket): fail closed — re-provision through "
                "the break-glass ticket flow" % ticket_id)
        if reviewer_identity.principal != provisioned:
            self.log.append({
                "event": "post_review_resolve_refused",
                "run_id": target.get("run_id") or self.run_dir.name,
                "agent_id": "human-operator",
                "role": "approver",
                "principal": "human-operator",
                "decision": "refused",
                "approval_id": target.get("approval_id"),
                "post_review_ticket": ticket_id,
                "reviewer_principal": reviewer_identity.principal,
                "reason": ("reviewer principal %r is not the provisioned "
                           "reviewer %r"
                           % (reviewer_identity.principal, provisioned)),
            })
            raise ValueError(
                "post-review ticket %s must be resolved by the "
                "provisioned reviewer (principal %r), not %r"
                % (ticket_id, provisioned, reviewer_identity.principal))
        target["status"] = "resolved"
        target["resolved_at"] = _utcnow()
        target["resolved_by"] = reviewer_identity.principal
        target["reviewer_identity"] = reviewer_identity.as_dict()
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
            "decided_by": reviewer_identity.principal,
            # F26: the full authenticated reviewer identity rides the
            # audit log, alongside the bound operator identity already
            # on the ticket.
            "reviewer_identity": reviewer_identity.as_dict(),
            "operator_identity": target.get("operator_identity"),
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


class IdentityVerifierAlreadySetError(Exception):
    """F31: the identity verifier is write-once (deployer-only).

    ``ToolExecutor`` installs its minted-identity check at construction;
    any later ``set_identity_verifier`` call — including the wave-8
    traversal ``...approvals.set_identity_verifier(lambda _: True)`` —
    raises instead of swapping the control out from under the
    break-glass/review paths. The first-installed verifier keeps
    authenticating callers; a swap attempt never takes effect and never
    mutates the installed verifier.
    """


class SessionIdentityAlreadySetError(Exception):
    """F55 (R13): the provisioned session identity is write-once.

    ``ToolExecutor`` installs the deployment-provisioned session
    identity at construction; any later ``set_session_identity`` call
    raises instead of swapping the entitlement anchor out from under
    ``break_glass``. The first-installed session identity stays the
    only identity entitled to consume break-glass tickets.
    """


class ApprovalQueue(ApprovalQueueRiskMixin):
    def __init__(self, run_dir, log, batch_excluded_reasons=None):
        self.run_dir = Path(run_dir)
        # F42 (R11): the queue's authoritative run id — records stamp
        # THIS, never a caller-supplied run_id.
        self.run_id = self.run_dir.name
        self.log = log
        self.path = self.run_dir / "approvals.jsonl"
        # F21: queue reasons that may never be batch-decided. Explicit
        # policy list wins; otherwise the conservative built-in security
        # set applies (fail closed for direct/CLI construction without a
        # policy). ToolExecutor pushes the policy-derived list via the
        # setter below.
        self.set_batch_excluded_reasons(batch_excluded_reasons)
        # F26: optional executor-installed identity verifier for the
        # break-glass/review paths (see set_identity_verifier). None =
        # isinstance check only (the CLI path: terminal-access trust
        # root, documented). F31: write-once — once installed it can
        # never be swapped (see _identity_verifier_sealed).
        self._identity_verifier = None
        self._identity_verifier_sealed = False
        # F55 (R13) / F59 (R14): the deployment-provisioned session
        # identity for entitlement-sensitive paths (break_glass).
        # Installed write-once by ToolExecutor at construction (see
        # set_session_identity). None = no provisioned identity: the
        # pre-R13 behavior (F26 mintedness check) applies, with the
        # existing self-asserted-identity warnings.
        #
        # F59: the anchor is tamper-resistant — a READ-ONLY property
        # with no setter (see _session_identity below), backed by the
        # name-mangled slot __session_identity. Casual in-process
        # ``queue._session_identity = X`` raises AttributeError instead
        # of silently swapping the anchor (the F59 attack shape).
        self.__session_identity = None
        self._session_identity_sealed = False
        # F64 (R14): True once the executor reports a PrincipalRegistry
        # is configured (see note_registry_configured). Lets
        # break_glass warn loudly when it runs in registry mode WITHOUT
        # a provisioned session identity — a silent weak mode otherwise.
        self._registry_configured = False
        # F67 (R15): the weak-mode warning flag lives in the name-mangled
        # slot __break_glass_unprotected_warned and is exposed as a
        # READ-ONLY property (no setter) — see _break_glass_unprotected_warned
        # below. Internal code transitions it False->True exactly once.
        self.__break_glass_unprotected_warned = False
        # F49 (R11): write-once snapshot of the human-provisioned
        # break-glass ticket store, taken at run start (first
        # ToolExecutor construction). None = not yet snapshotted.
        self._bg_ticket_snapshot = None
        # F49 (R11): cross-thread mutex for ticket check-and-consume.
        # The ticket resolve (unused?) -> mark-used sequence must be
        # atomic within the process; without the lock two threads can
        # both observe an unused ticket and both consume it.
        self._bg_ticket_lock = threading.Lock()

    def set_identity_verifier(self, verifier):
        """F26: install the executor's minted-identity check.

        ``verifier(identity)`` must return truthy for identities this
        deployment's executor minted, or raise (``TypeError`` /
        ``UnmintedIdentityError``). ``ToolExecutor`` installs its
        ``_verify_approval_identity`` here at construction; direct/CLI
        queue construction leaves it None.

        F31 WRITE-ONCE: the first call installs the verifier and seals
        the slot; every later call raises
        ``IdentityVerifierAlreadySetError``. A verifier swap —
        including the wave-8 defeat path
        ``tool._binding.executor.approvals.set_identity_verifier(lambda _:
        True)`` — can no longer collapse the F26 identity binding after
        the executor is constructed.
        """
        if getattr(self, "_identity_verifier_sealed", False):
            raise IdentityVerifierAlreadySetError(
                "identity verifier is write-once: a verifier is already "
                "installed; refusing to swap it out")
        if not callable(verifier):
            raise TypeError(
                "identity verifier must be callable, got %r"
                % type(verifier).__name__)
        self._identity_verifier = verifier
        self._identity_verifier_sealed = True

    @property
    def _session_identity(self):
        """F59 (R14): the session-identity anchor as a READ-ONLY property.

        There is deliberately NO setter: ``queue._session_identity = X``
        raises ``AttributeError`` instead of silently swapping the
        break-glass entitlement anchor (the F59 confused-deputy attack
        shape). The value lives in the name-mangled slot
        ``_ApprovalQueue__session_identity``, written exactly twice:
        ``None`` in ``__init__`` and the provisioned identity in the
        write-once ``set_session_identity``.

        Honest residual (documented): an in-process attacker who knows
        the mangled name can still force-write the slot with
        ``object.__setattr__`` — the same class of primitive as
        monkeypatching the module. The anchor covers code with normal
        attribute access (the realistic confused-deputy shape); it is
        not a sandbox boundary against hostile in-process code.
        """
        return self.__session_identity

    @property
    def _break_glass_unprotected_warned(self):
        """F67 (R15): the weak-mode warning flag as a READ-ONLY property.

        There is deliberately NO setter: ``queue._break_glass_unprotected_warned
        = True`` raises ``AttributeError`` instead of silently disarming
        the F64 one-time stderr warning and the ``break_glass_unprotected``
        audit entry while the ticket still consumes (the F67 audit-evasion
        attack shape). The value lives in the name-mangled slot
        ``_ApprovalQueue__break_glass_unprotected_warned``, transitioned
        False->True exactly once by ``break_glass`` itself.

        Honest residual (documented): an in-process attacker who knows
        the mangled name can still force-write the slot with
        ``object.__setattr__`` — the same class of primitive as
        monkeypatching the module, outside the Python-level
        hostile-in-process threat model (see F59 residual).
        """
        return self.__break_glass_unprotected_warned

    def _break_glass_unprotected_warn_once(self):
        """F67 (R15): check-and-set for the weak-mode warning flag.

        Returns True exactly once per queue (the first call transitions
        the name-mangled slot False->True); later calls return False.
        Defined on ApprovalQueue so the mangled slot is unambiguous
        (break_glass itself lives on ApprovalQueueRiskMixin, which
        mangles differently) — this helper is the ONLY writer.
        """
        if self.__break_glass_unprotected_warned:
            return False
        self.__break_glass_unprotected_warned = True
        return True

    def note_registry_configured(self):
        """F64 (R14): record that a PrincipalRegistry is configured.

        Called by ``ToolExecutor`` at construction when a registry is
        present. Idempotent. Lets ``break_glass`` warn loudly when it
        runs in registry mode WITHOUT a provisioned session identity
        (the F64 silent weak mode) instead of taking the pre-R13 path
        silently.
        """
        self._registry_configured = True

    def set_session_identity(self, identity):
        """F55 (R13): install the deployment-provisioned session identity.

        ``identity`` is the ONE ``AgentIdentity`` the deployment
        provisioned out-of-band for this session (``provenance=
        "provisioned"``), created by ``ToolExecutor`` at construction.
        Entitlement-sensitive paths (``break_glass``) require exactly
        this OBJECT — F59 compares with ``is`` (true object identity),
        so a mid-run ``mint_identity`` of the same (agent_id, role,
        principal) tuple (``provenance="minted"``) is refused even
        though it compares structurally equal.

        WRITE-ONCE (same pattern as F31): the first call installs the
        session identity and seals the slot; every later call raises
        ``SessionIdentityAlreadySetError``. A swap attempt never takes
        effect and never mutates the installed identity.
        """
        if getattr(self, "_session_identity_sealed", False):
            raise SessionIdentityAlreadySetError(
                "session identity is write-once: a provisioned identity "
                "is already installed; refusing to swap it out")
        if not isinstance(identity, AgentIdentity):
            raise TypeError(
                "session identity must be an AgentIdentity, got %s"
                % type(identity).__name__)
        if getattr(identity, "provenance", "minted") != "provisioned":
            raise ValueError(
                "session identity must carry provenance='provisioned' "
                "(deployment-provisioned at session start); mid-run "
                "minted identities are never entitled")
        # F59: write the name-mangled slot directly — the public
        # _session_identity name is a read-only property (no setter),
        # so this is the only in-class write path besides __init__.
        self.__session_identity = identity
        self._session_identity_sealed = True

    def _authenticate_caller(self, identity, what):
        """F26: authenticate the caller of a break-glass/review method.

        Rejects anything that is not an ``AgentIdentity`` — notably the
        old caller-supplied operator/reviewer strings (``TypeError``) —
        and, when the executor installed a verifier, rejects identities
        it did not mint (``UnmintedIdentityError``). Returns the
        authenticated identity object the ticket binds to.
        """
        if not isinstance(identity, AgentIdentity):
            raise TypeError(
                "%s requires an AgentIdentity minted by the executor "
                "(got %s); caller-supplied operator/reviewer strings "
                "are not accepted" % (
                    what, type(identity).__name__))
        if self._identity_verifier is not None:
            self._identity_verifier(identity)
        return identity

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
              policy_context=None, policy_flag=None, egress_bytes=None,
              caller_identity=None):
        """Store a pending approval; returns the approval id.

        ``action`` carries tool, redacted args, the agent's
        justification (unverified), and the redaction list.
        ``policy_context`` is the executor's evaluation-context snapshot
        (path_outside_sandbox, domain_allowlisted, carries_read_content,
        source_untrusted, counters); it feeds risk scoring and the
        simulator, never the agent.
        ``policy_flag`` (F21) is the queue reason (the decision's flag,
        e.g. ``cross_run_campaign``); it travels with the record so
        batch approval can refuse security items individually. When not
        passed explicitly it falls back to ``decision.flag``.
        ``egress_bytes`` (F33, HARDENING-R8) is the raw outbound payload
        byte count computed by the executor at queue time: the redacted
        queue form of the args may summarize large payloads
        (``{bytes, sha256_prefix}``), so the execution boundary charges
        the recorded raw count — never a smaller redacted form.

        F42 (R11): ``caller_identity`` is REQUIRED — an
        ``AgentIdentity`` minted by the executor for the calling
        agent, authenticated here against the executor-installed
        verifier (the session binding; installed write-once at
        ``ToolExecutor`` construction). The record's run_id, agent_id,
        role, principal, and identity are stamped from this
        AUTHENTICATED object — ``action["identity"]``, when present,
        is never used as the authority (it was the wave-12 oracle:
        the queue MACed an attacker-supplied run_id). Missing
        identity, a non-AgentIdentity, an unminted identity, or an
        identity for another run is refused fail-closed.
        """
        if caller_identity is None:
            raise TypeError(
                "queue() requires caller_identity: an AgentIdentity "
                "minted by the executor for the calling agent (F42); "
                "caller-supplied identity fields are never trusted")
        if self._identity_verifier is None:
            raise ValueError(
                "queue() refused: no identity verifier installed on "
                "this queue — the executor installs its minted-identity "
                "check at construction (F42 fail-closed)")
        caller = self._authenticate_caller(caller_identity, "queue")
        if caller.run_id != self.run_id:
            raise ValueError(
                "queue() refused: caller identity run_id %r does not "
                "match this queue's run %r" % (caller.run_id, self.run_id))
        args = action.get("args") or {}
        if policy_flag is None:
            policy_flag = getattr(decision, "flag", None)
        # F11: the stored preview is the approver-facing display surface.
        # Sanitize here (in addition to the executor's _preview) so every
        # record is safe no matter which caller queued it.
        preview = sanitize_preview_text(preview or "")
        # F42: every authority field below comes from the authenticated
        # caller object or the queue itself — never from action[].
        record = {
            "id": uuid.uuid4().hex[:8],
            "ts": _utcnow(),
            "run_id": self.run_id,
            "agent_id": caller.agent_id,
            "role": caller.role,
            "principal": caller.principal,
            "identity": caller.as_dict(),
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
            # F38 (R10) / F43 (R11): the keyed digest binds the run this
            # record was queued in (the QUEUE's run_id — never a
            # caller-supplied value) and the decider (None while
            # pending — decide() re-MACs with decided_by bound). F43
            # binds the full security record: identity, preview,
            # provenance, policy_context, policy_flag,
            # delegation_attempted.
            "digest_scheme": APPROVAL_DIGEST_SCHEME,
            # F33: raw outbound payload bytes at queue time; the execution
            # boundary charges this (the redacted queue form may summarize
            # large payloads — it must never shrink the budget charge).
            "egress_bytes": egress_bytes,
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
        # F43: the digest covers the record's security fields, computed
        # here from the stamped record itself.
        record["args_digest"] = approval_record_digest(record)
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

        F38: the pending record's keyed digest is verified BEFORE the
        decision is recorded — a record tampered with after queueing
        can never be decided (fail-closed ValueError, audit-logged);
        the decision then re-MACs the digest with the decider bound.
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
        # F38 (R10): verify the PENDING digest BEFORE re-MACing. The
        # re-MAC below re-seals whatever fields are present at decision
        # time — without this check, tampering between queue() and
        # decide() would be laundered by the decision (the F33
        # egress_bytes binding would no longer catch a pre-decision
        # rewrite). A pending record whose digest does not verify is
        # never decided: fail closed, audit-logged, ValueError — the
        # same rejected-attempt contract as above. The check covers
        # the approved CONTENT only (not the digest_scheme label — a
        # scheme-label rewrite is not content tampering; the verifier
        # still fails closed on it at execution, per the documented
        # wave-11 scheme seam). decide() is the human/policy trust
        # boundary; the digest guards everything after it.
        if not _pending_record_content_ok(target):
            _log_attempt(
                "rejected_attempt",
                "decision refused: the pending record failed integrity "
                "verification (tampered after queueing); re-MAC refused",
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError(
                "approval %r failed integrity verification: the queued "
                "record was tampered with after queueing — decision "
                "refused" % approval_id)
        target["status"] = "approved" if approved else "rejected"
        target["decided_by"] = decided_by
        target["decided_at"] = _utcnow()
        target["decision_reason"] = reason
        # F38 (R10) / F43 (R11): the decision binds the decider into the
        # keyed digest — the approval's integrity now covers WHO decided
        # it, not just what was approved. Re-MAC here (queue time bound
        # decided_by=None); approval_digest_ok() verifies against the
        # record's current decided_by, so pending and decided records
        # each verify exactly one way. F43: the re-MAC covers the full
        # security payload of the (possibly tamper-checked) record.
        target["args_digest"] = approval_record_digest(target)
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

    # R17 (F71): the reconcile marker-verdict cache lives in the run
    # dir next to the log. A forged execution_authorized marker forces
    # the conditional full _verify on EVERY sweep (O(n) CPU per sweep)
    # plus one loud reconciliation_marker_invalid audit entry per
    # sweep while the forgery stands. The full-verify verdict is a
    # pure function of (log bytes, sidecar bytes, key epoch), so a
    # MAC-authenticated cache keyed by the markers' content+position
    # lets later sweeps reuse the "invalid" verdict without
    # re-verifying -- and the loud audit is coalesced to one entry per
    # marker per _RECONCILE_MARKER_INVALID_COALESCE_SECS. Only
    # "invalid" verdicts are cached; any cache miss re-verifies
    # (fail-closed). First occurrence always audits loud.
    _RECONCILE_MARKER_CACHE_FILENAME = "reconcile_marker_verdict.json"
    _RECONCILE_MARKER_INVALID_COALESCE_SECS = 300.0

    def _reconcile_marker_cache_path(self):
        return self.run_dir / self._RECONCILE_MARKER_CACHE_FILENAME

    def _reconcile_markers_key(self, entries, interrupted):
        """Fingerprint of the interrupted-execution markers: content
        hash + log position per marker.

        The entry's stored ``hash`` field is included explicitly
        because ``_canonical`` excludes it -- a genuine MAC repair
        changes exactly that field, so it must change the key. Any
        marker rewrite, or any new/different marker, changes the key
        and forces a fresh full verification. Appends AFTER the
        markers cannot repair a broken chain, so they do not
        invalidate the key; the sidecar pin covers the anchor side.
        """
        by_seq = {}
        for e in entries:
            if isinstance(e, dict) and isinstance(e.get("seq"), int):
                by_seq[e["seq"]] = e
        parts = []
        for aid in sorted(interrupted):
            seq = interrupted[aid]
            e = by_seq.get(seq)
            if e is None:
                parts.append("missing-seq:%d" % seq)
            else:
                parts.append("%d|%s|%s" % (
                    seq, e.get("hash", ""), _canonical(e)))
        return sha256("|".join(parts).encode("utf-8")).hexdigest()

    def _read_reconcile_marker_cache(self):
        """Return the validated verdict-cache dict, or None.

        Never raises and never returns an unvalidated cache: a
        missing file, unparseable JSON, wrong shape, epoch mismatch,
        or MAC failure all yield None (the caller re-verifies --
        slower but safe, never unverified trust).
        """
        try:
            raw = json.loads(
                self._reconcile_marker_cache_path().read_text(
                    encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(raw, dict):
            return None
        try:
            cache = {
                "key_epoch": raw["key_epoch"],
                "markers_key": raw["markers_key"],
                "verdict": raw["verdict"],
                "error": raw["error"],
                "broken_seq": raw["broken_seq"],
                "last_audit": float(raw.get("last_audit", 0.0)),
                "suppressed": int(raw.get("suppressed", 0)),
                "mac": raw["mac"],
            }
        except (KeyError, TypeError, ValueError):
            return None
        if not all(isinstance(cache[k], str) for k in
                   ("key_epoch", "markers_key", "verdict", "error",
                    "mac")):
            return None
        if (cache["broken_seq"] is not None
                and not isinstance(cache["broken_seq"], int)):
            return None
        try:
            key, epoch = _active_key()
        except (OSError, ValueError, KeyError):
            return None
        if cache["key_epoch"] != epoch:
            # Key rotation: the cached verdict was computed under a
            # different key -- do not reuse it.
            return None
        body = {k: v for k, v in cache.items() if k != "mac"}
        expect = _reconcile_marker_cache_mac(
            key, epoch, _canonical(body))
        if not hmac.compare_digest(cache["mac"], expect):
            return None
        return cache

    def _write_reconcile_marker_cache(self, markers_key, error,
                                      broken_seq, last_audit, suppressed):
        """Atomically persist the MAC'd invalid-verdict cache
        (temp file + os.replace). Best-effort: a failed write only
        costs the next sweep a redundant re-verification, never
        safety. The sidecar fingerprint is pinned AFTER our own audit
        append (callers write the cache after appending), so the pin
        covers the checkpoint our audit just wrote.
        """
        try:
            key, epoch = _active_key()
            # Note: the checkpoint sidecar is deliberately NOT pinned.
            # The cached "invalid" verdict is about the ACTION LOG
            # chain (a forged marker); the sidecar does not affect
            # action-log MAC verification, and benign checkpoint
            # appends occur on ordinary sweeps -- pinning the sidecar
            # would invalidate the cache every sweep, defeating F71.
            # A sidecar tamper cannot repair an action-log forgery.
            doc = {
                "key_epoch": epoch,
                "markers_key": markers_key,
                "verdict": "invalid",
                "error": str(error),
                "broken_seq": broken_seq,
                "last_audit": last_audit,
                "suppressed": suppressed,
            }
            doc["mac"] = _reconcile_marker_cache_mac(
                key, epoch, _canonical(doc))
            cache_path = self._reconcile_marker_cache_path()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = cache_path.with_name(cache_path.name + ".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(doc, ensure_ascii=True,
                                   sort_keys=True, default=str))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, cache_path)
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def _reconcile_marker_invalid_coalesced(self, markers_key, error,
                                            broken_seq, cache):
        """R17 (F71b): audit a refused marker reconciliation, coalesced.

        The first invalid verdict for a marker ALWAYS audits loudly
        (fail-closed). Repeats for the same marker bytes within
        _RECONCILE_MARKER_INVALID_COALESCE_SECS are folded into a
        suppressed counter instead of appending another
        reconciliation_marker_invalid entry, so a standing forgery
        cannot grow the tamper-evident log without bound. The next
        audited entry carries the folded count, so the operator still
        sees the repeat volume.
        """
        now = time.monotonic()
        if cache is not None and cache.get("markers_key") == markers_key:
            try:
                last_audit = float(cache.get("last_audit", 0.0))
                suppressed = int(cache.get("suppressed", 0))
            except (TypeError, ValueError):
                last_audit, suppressed = 0.0, 0
        else:
            last_audit, suppressed = 0.0, 0
        if now - last_audit < \
                self._RECONCILE_MARKER_INVALID_COALESCE_SECS:
            self._write_reconcile_marker_cache(
                markers_key, error, broken_seq, last_audit,
                suppressed + 1)
            return
        self.log.append({
            "event": "reconciliation_marker_invalid",
            "run_id": self.run_id,
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "decision": "reconciliation_refused",
            "policy_id": "execution-reconciliation",
            "suppressed_repeats": suppressed,
            "reason": ("interrupted-execution reconciliation REFUSED: "
                       "the action-log chain does not verify (%s) — "
                       "at least one execution_authorized marker "
                       "cannot be authenticated, so none are "
                       "reconciled; approved work is left as-is for "
                       "operator review" % error),
        })
        self._write_reconcile_marker_cache(
            markers_key, error, broken_seq, now, 0)

    def _reconcile_interrupted_executions(self):
        """F45 (R11): reconcile executions interrupted between claim and
        mark — called at sweep start, under the queue lock.

        The execution sequence is: write ``execution_authorized`` to
        the action log, ``mark_executed(aid)`` (durable claim),
        side effect, write ``approved_executed``. A crash between the
        claim and the completion marker leaves ``executed=True`` with
        no ``approved_executed`` — and the old sweep silently skipped
        such records forever (the approval was consumed with no
        verifiable outcome).

        This sweep detects them: for each approval id, the LATEST
        ``execution_authorized`` log seq is compared against the
        latest ``approved_executed`` seq. An authorization strictly
        newer than any completion is an interrupted execution. Each
        is:

        * audited LOUDLY as ``approval_execution_interrupted`` (never
          silently skipped);
        * reset to ``status="pending"``, ``executed=False``, decision
          fields cleared, with an explicit
          ``execution_interrupted_warning`` for the approver — a NEW
          human decision is mandatory. The record is NEVER executed
          automatically here.
        * re-MACed as pending (decided_by=None) ONLY if its approved
          digest still verifies (content intact as approved); a
          tampered record keeps its broken digest, is flagged, and
          stays unexecutable for operator intervention.

        Honest residual: local state cannot tell whether the side
        effect ran before the crash. The warning says so plainly —
        the human must investigate before re-approving, because
        re-approval + re-execution could double-apply the effect.
        ``execution_interrupted_reconciled_seq`` pins each
        reconciliation to the authorization seq it handled, so a
        repeat interruption is reconciled again but a handled one is
        never re-alerted on every sweep.

        F63 (R14): malformed physical lines in the action log (non-JSON
        or valid-JSON-but-not-an-object) no longer crash the sweep.
        They are skipped and counted; the skip is audited ONCE per
        newly observed malformed-count state (derived from the log
        itself, so it survives executor rotation); and the signed
        seq/MAC/checkpoint chain of every VALID entry is still
        verified strictly before any interruption marker is trusted.
        """
        try:
            entries, n_malformed = read_entries_with_stats(self.log.path)
        except OSError:
            return []
        if n_malformed:
            # F63: audit the observation once per newly seen
            # malformed-count state — not once per sweep. The "already
            # audited" signal is read from the log itself (the highest
            # malformed_count previously recorded), so no
            # cross-instance memory is needed across executor rotation.
            already = max(
                (e.get("malformed_count", 0) for e in entries
                 if e.get("event") == "action_log_malformed_lines_skipped"),
                default=0)
            if n_malformed > already:
                self.log.append({
                    "event": "action_log_malformed_lines_skipped",
                    "run_id": self.run_id,
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "n/a",
                    "policy_id": "action-log-integrity",
                    "malformed_count": n_malformed,
                    "reason": ("action log contains %d malformed physical "
                               "line(s) (non-JSON or valid-JSON-but-not-"
                               "an-object); skipped for reconciliation — "
                               "the signed chain of all valid entries is "
                               "still verified below (F63)" % n_malformed),
                })
        auth_seq = {}
        done_seq = {}
        for e in entries:
            if not isinstance(e, dict):
                continue
            if e.get("event") != "tool_call":
                continue
            aid = e.get("approval_id")
            if not aid or not isinstance(e.get("seq"), int):
                continue
            if e.get("decision") == "execution_authorized":
                auth_seq[aid] = max(auth_seq.get(aid, 0), e["seq"])
            elif e.get("decision") == "approved_executed":
                done_seq[aid] = max(done_seq.get(aid, 0), e["seq"])
        interrupted = {aid: s for aid, s in auth_seq.items()
                       if s > done_seq.get(aid, 0)}
        # R17 (F70/F71): the candidate scan above is UNTRUSTED --
        # read_entries() never verifies the chain. The verification
        # gate below MUST run on every sweep, not just when candidates
        # exist: it consumes the F70 forced-verification countdown once
        # per successful-lock sweep (the executor refusal path consumes
        # it on lock-failure sweeps), bounding the silent window for
        # length-preserving pre-tip edits. Skipping verification on
        # idle sweeps would leave that window unbounded.
        #
        # F71a: when candidates exist and the MAC-authenticated
        # invalid verdict matches (marker bytes, checkpoint sidecar,
        # key epoch, and exact log end all unchanged), reuse it to
        # deny immediately -- unverified data is used only to remain
        # fail-closed, never to authorize or reconcile.
        if interrupted:
            markers_key = self._reconcile_markers_key(entries,
                                                      interrupted)
            cache = self._read_reconcile_marker_cache()
            # R17 (F71a): reuse the cached invalid verdict when the
            # marker bytes and key epoch are unchanged. The verdict is
            # a pure function of (marker bytes, key epoch): the
            # action-log chain's invalidity comes from the forged
            # marker, which neither log appends, sidecar appends, nor
            # sidecar tampering can repair. Any marker rewrite,
            # removal, or new marker changes markers_key and forces a
            # fresh verification. Only "invalid" verdicts are cached,
            # so reuse can only deny, never authorize.
            use_cached = (
                cache is not None
                and cache.get("verdict") == "invalid"
                and cache.get("markers_key") == markers_key
            )
        else:
            markers_key, cache, use_cached = None, None, False
        if use_cached:
            verdict_ok = False
            verdict_error = (cache.get("error")
                             or "cached invalid verdict")
            verdict_broken = cache.get("broken_seq")
        else:
            # Verification gate: incremental tip first (O(new bytes),
            # consumes the F70 countdown); full tolerant _verify when
            # the tip is unusable or the countdown is due.
            try:
                tip_verdict = verify_chain_tip(self.log.path)
            except OSError:
                tip_verdict = None
            if (tip_verdict is not None
                    and not tip_verdict["full_verify_due"]):
                verdict_ok, verdict_error = True, ""
                verdict_broken = None
            else:
                # F52 (R12): the write-ahead execution_authorized
                # markers are HMAC-bound at write time, but
                # read_entries() never verifies the chain -- a run-dir
                # writer with no key could plant forged markers and the
                # sweep would "reconcile" them into pending (starvation
                # + alert fatigue). Verify the chain BEFORE trusting any
                # marker: an unverifiable chain means at least one
                # marker cannot be authenticated, so NO marker is
                # reconciled -- fail closed with a loud audited refusal
                # instead of honoring possibly-forged interruptions.
                # F63 (R14): TOLERANT verify -- malformed physical lines
                # are skipped (audited above) while the signed seq/MAC/
                # checkpoint chain of every VALID entry is verified
                # exactly as strictly as the default mode; a malformed
                # line carries no seq and no chain link, so skipping it
                # cannot launder tampering.
                verdict = _verify(self.log.path, _skip_malformed=True)
                verdict_ok = verdict["ok"]
                verdict_error = verdict["error"]
                verdict_broken = verdict.get("broken_seq")
                if verdict_ok:
                    # Reseed the tip so the next sweep verifies
                    # incrementally; restarts the F70 countdown.
                    try:
                        write_chain_tip_from_tail(self.log.path, {})
                    except (OSError, ValueError, KeyError, TypeError):
                        pass
        if not verdict_ok:
            if interrupted:
                # R17 (F71b): audit coalescing -- the first invalid
                # verdict for a marker always audits loud; unchanged
                # repeats are folded into a suppressed counter so a
                # standing forgery cannot grow the log (or burn O(n)
                # per sweep) without bound. The next audited entry
                # carries the folded count.
                self._reconcile_marker_invalid_coalesced(
                    markers_key, verdict_error, verdict_broken, cache)
            else:
                # R17 (F70): the chain does not verify but the
                # (untrusted) scan found no interrupted markers. The
                # scan cannot be trusted -- a broken chain means at
                # least one entry cannot be authenticated -- so audit
                # LOUDLY and reconcile nothing. This is the
                # tamper-loudness backstop for the no-marker path.
                self.log.append({
                    "event": "reconciliation_chain_unverifiable",
                    "run_id": self.run_id,
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "reconciliation_refused",
                    "policy_id": "execution-reconciliation",
                    "broken_seq": verdict_broken,
                    "reason": ("interrupted-execution reconciliation "
                               "REFUSED: the action-log chain does not "
                               "verify (%s) -- no marker is trusted, so "
                               "none are reconciled; approved work is "
                               "left as-is for operator review"
                               % verdict_error),
                })
            return []
        if not interrupted:
            return []
        reconciled = []

        def fix(records):
            for r in records:
                seq = interrupted.get(r["id"])
                if seq is None:
                    continue
                if r.get("execution_interrupted_reconciled_seq") == seq:
                    continue  # already reconciled; do not re-alert
                integrity_ok = bool(approval_digest_ok(r))
                if integrity_ok:
                    r["status"] = "pending"
                    r["executed"] = False
                    r["decided_by"] = None
                    r["decided_at"] = None
                    r["decision_reason"] = None
                    r["break_glass"] = False
                    r["break_glass_reason"] = None
                    r["args_digest"] = approval_record_digest(r)
                r["execution_interrupted_reconciled_seq"] = seq
                r["execution_interrupted_integrity_ok"] = integrity_ok
                r["execution_interrupted_warning"] = (
                    "A previous sweep authorized and claimed this "
                    "approval (log seq %d) but never recorded "
                    "completion — the process may have crashed "
                    "mid-execution. THE SIDE EFFECT MAY ALREADY HAVE "
                    "HAPPENED; local state cannot determine this. "
                    "Investigate before re-approving: re-approval and "
                    "re-execution could apply the effect twice. This "
                    "record will NEVER execute without a new human "
                    "decision." % seq)
                reconciled.append((r["id"], seq, integrity_ok))
            return records

        self._rewrite(fix)
        for aid, seq, integrity_ok in reconciled:
            self.log.append({
                "event": "approval_execution_interrupted",
                "run_id": self.run_id,
                "agent_id": "human-operator",
                "role": "approver",
                "principal": "human-operator",
                "decision": "reconciled" if integrity_ok
                            else "reconciled_integrity_failed",
                "approval_id": aid,
                "policy_id": "execution-reconciliation",
                "authorization_seq": seq,
                "integrity_ok": integrity_ok,
                "reason": (
                    "Interrupted execution reconciled: approval %s was "
                    "authorized (log seq %d) but never marked complete; "
                    "%s. Reset to pending with an explicit warning — a "
                    "new human decision is mandatory; nothing was "
                    "executed automatically."
                    % (aid, seq,
                       "record integrity intact, re-MACed as pending"
                       if integrity_ok else
                       "RECORD INTEGRITY FAILED — left unexecutable "
                       "for operator intervention")),
            })
        return [aid for aid, _, _ in reconciled]

    def _lock_path(self):
        """Sidecar lock file for the queue (mirrors gov/keys.py's
        ``<path>.lock`` pattern). A sidecar — not the queue file
        itself — so queue()/decide() appends and rewrites, which do not
        take this lock, are unaffected."""
        return self.run_dir / "approvals.lock"

    @contextlib.contextmanager
    def _queue_locked(self, timeout=None):
        """F39: hold an exclusive flock on the queue across a sweep.

        Serializes ``execute_approved()`` sweeps (threads and
        processes): the read-claim-execute-mark sequence runs under
        this lock, so a second sweeper re-reads the queue only after
        the first has marked its records and sees ``executed=True``.
        Waits up to ``timeout`` (default
        ``APPROVAL_QUEUE_LOCK_TIMEOUT_SECS``), then raises
        ``QueueLockError`` — the sweep never runs unlocked.

        F44 (R11): after acquiring the flock, the queue verifies the
        locked file is still the path's file: ``os.fstat(fd)`` must
        match ``os.stat(path)`` on (st_dev, st_ino) and the path must
        still be linked (st_nlink > 0). Deleting ``approvals.lock``
        mid-acquisition lets a second opener flock a DIFFERENT inode
        while the first sweeper still holds the old one — silent
        double execution. On mismatch the lock is released, the fd
        closed, and ``QueueLockInvalidatedError`` raised: a loud
        refusal the executor audits as ``queue_lock_invalidated``,
        never a silent double sweep.

        LOCK ORDERING (deadlock avoidance): the queue lock is the OUTER
        lock; the action-log append lock (F25, gov/log.py) is only ever
        taken INSIDE it (execute_approved's audit writes). No code path
        takes the action-log lock and then the queue lock, so the
        order queue -> log is total and cannot deadlock.
        """
        if timeout is None:
            timeout = APPROVAL_QUEUE_LOCK_TIMEOUT_SECS
        self.run_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self._lock_path()
        # F51 (R12): open the lock path so that ANY failure is an
        # audited fail-closed refusal, never a bare exception. The
        # old ``open(lock_path, "a")`` let ``IsADirectoryError`` (a
        # directory swapped in at the lock path) escape unaudited.
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
        except OSError as e:
            raise QueueLockPathError(
                "approval-queue lock path %s is not lockable (%s); "
                "refusing to sweep — a non-file at the lock path is "
                "fail-closed" % (lock_path, e))
        f = os.fdopen(fd, "a", encoding="utf-8")
        try:
            # F51: a non-file at the lock path (directory, FIFO,
            # socket) is fail-closed with audit, never trusted as a
            # lock.
            try:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    raise QueueLockPathError(
                        "approval-queue lock path %s is not a regular "
                        "file; refusing to sweep" % (lock_path,))
            except OSError as e:
                raise QueueLockPathError(
                    "approval-queue lock path %s cannot be inspected "
                    "(%s); refusing to sweep" % (lock_path, e))
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (OSError, BlockingIOError):
                    if time.monotonic() >= deadline:
                        raise QueueLockError(
                            "could not acquire the approval-queue lock on "
                            "%s within %ss; refusing to sweep unlocked"
                            % (lock_path, timeout))
                    time.sleep(_QUEUE_LOCK_POLL_SECS)
            # F44: the lock file may have been deleted/replaced between
            # open() and flock(). Verify the fd we locked is still the
            # path's file — otherwise a second sweeper could hold an
            # exclusive lock on a different inode concurrently.
            try:
                fd_stat = os.fstat(f.fileno())
                path_stat = os.stat(lock_path)
                valid = (fd_stat.st_dev == path_stat.st_dev
                         and fd_stat.st_ino == path_stat.st_ino
                         and path_stat.st_nlink > 0)
            except OSError:
                valid = False
            if not valid:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
                raise QueueLockInvalidatedError(
                    "approval-queue lock invalidated: %s was deleted or "
                    "replaced while acquiring the lock (inode mismatch); "
                    "refusing to sweep — a second sweeper may hold a "
                    "lock on a different inode" % (lock_path,))
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()


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


_DECISION_TARGET_CAP_BYTES = 65536  # F66 (R15): default human-view cap.


def _print_decision_target(r, full=None):
    """F66 (R15): the human decision view, bounded by default.

    Prints the canonical args JSON (the exact bytes the approval
    digest covers and execution will use) plus ``args_sha256`` — the
    sha256 over those exact UTF-8 bytes, ALWAYS computed over the
    full bytes even when the display is truncated, so the operator can
    confirm the content they see is the content that was digested.

    The default view is capped at 64KB (``_DECISION_TARGET_CAP_BYTES``)
    with an explicit TRUNCATED marker stating the shown/total byte
    counts; set ``GOV_FULL_ARGS=1`` (or pass ``full=True``) to render
    the full exact bytes. A marker past the old 400-char cut is
    visible here verbatim in the full view. Any machine/log truncation
    elsewhere must be explicitly LABELLED truncated.
    """
    canon = _canonical_dumps(r["args"])
    raw = canon.encode("utf-8")
    digest = sha256(raw).hexdigest()
    if full is None:
        full = os.environ.get("GOV_FULL_ARGS") == "1"
    if full or len(raw) <= _DECISION_TARGET_CAP_BYTES:
        shown = canon
        truncated = False
    else:
        # Cut on a byte boundary; drop a trailing partial UTF-8
        # sequence so the shown text is always valid and deterministic.
        shown = raw[:_DECISION_TARGET_CAP_BYTES].decode("utf-8",
                                                       errors="ignore")
        truncated = True
    if truncated:
        print("    args (TRUNCATED: showing %d of %d bytes — set "
              "GOV_FULL_ARGS=1 for the full exact content):"
              % (len(shown.encode("utf-8")), len(raw)))
    else:
        print("    args (FULL, untruncated — this exact content is what "
              "the digest covers and execution will use):")
    print("      %s" % shown)
    if truncated:
        print("    [... TRUNCATED — %d bytes shown of %d total; the "
              "args_sha256 below covers the FULL bytes]"
              % (len(shown.encode("utf-8")), len(raw)))
    print("    args_sha256: %s" % digest)


def _find_record_by_id(queue, approval_id):
    """Return the queued record with ``approval_id``, or None."""
    for r in queue.all():
        if r["id"] == approval_id:
            return r
    return None


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
        # F61 (R14) / F66 (R15): the decision view shows the canonical
        # args through the bounded _print_decision_target helper (64KB
        # default cap with explicit marker; GOV_FULL_ARGS=1 for full) —
        # plus args_sha256 over the exact bytes the digest covers. The
        # agent's justification is NEVER on the routing line (or anywhere
        # unlabeled): it is unverified input.
        _print_decision_target(r)
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
    p_bg.add_argument("--ticket", required=True,
                      help="F49: human-provisioned break-glass ticket id "
                           "(provisioned out-of-band BEFORE the run with "
                           "provision-ticket; bound to the operator "
                           "principal)")
    p_bg.add_argument("--by", default="human-operator",
                      help="operator principal pulling the break-glass (bound as the operator identity's principal; the CLI is the terminal-access trust root)")

    p_pt = sub.add_parser(
        "provision-ticket",
        help="F49: provision a human break-glass ticket OUT-OF-BAND "
             "before the run starts (operator terminal only — never "
             "from agent code). The ticket is HMAC-signed and bound to "
             "an operator principal and a DIFFERENT reviewer principal.")
    p_pt.add_argument("--ticket", required=True, help="ticket id, e.g. BG-001")
    p_pt.add_argument("--operator", required=True,
                      help="operator principal authorized to pull "
                           "break-glass with this ticket")
    p_pt.add_argument("--reviewer", required=True,
                      help="provisioned reviewer principal who must "
                           "resolve the post-review ticket (must differ "
                           "from --operator)")
    p_pt.add_argument("--purpose", default="",
                      help="human-readable purpose note")

    sub.add_parser("reviews", help="list post-review tickets")

    p_rr = sub.add_parser("review-resolve",
                          help="resolve a post-review ticket (F49: the "
                               "reviewer's authenticated principal must be "
                               "the provisioned reviewer bound to the "
                               "break-glass ticket, and differ from the "
                               "break-glass operator's principal)")
    p_rr.add_argument("ticket", help="ticket id, e.g. PRV-<approval-id>")
    p_rr.add_argument("--resolution", required=True,
                      help="resolution record")
    p_rr.add_argument("--by", default="human-operator",
                      help="reviewer principal (must differ from the break-glass operator's principal)")

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
        # F26: the CLI is the terminal-access trust root — it binds the
        # human's --by principal into an identity OBJECT so the ticket
        # and audit log carry authenticated identity fields; the
        # separation-of-duty check compares bound-object principals.
        reviewer_ident = AgentIdentity(agent_id="cli", role="reviewer",
                                       run_id=run_dir.name,
                                       principal=args.by)
        try:
            ticket, entry = queue.resolve_review(
                args.ticket, args.resolution,
                reviewer_identity=reviewer_ident)
        except (ValueError, TypeError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        print("resolved post-review ticket %s by principal %s (log seq %d)"
              % (ticket["ticket_id"], args.by, entry["seq"]))
        return 0

    if args.cmd == "provision-ticket":
        # F49: human out-of-band provisioning. The store lives in the
        # run dir so the run-start snapshot seals exactly these
        # tickets; provision BEFORE the run starts.
        try:
            ticket = provision_break_glass_ticket(
                run_dir / BREAK_GLASS_TICKET_FILENAME,
                args.ticket, args.operator, args.reviewer,
                purpose=args.purpose)
        except (ValueError, TypeError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        print("provisioned break-glass ticket %s" % ticket["ticket_id"])
        print("  operator principal: %s" % ticket["operator_principal"])
        print("  reviewer principal: %s (must resolve the post-review)"
              % ticket["reviewer_principal"])
        print("provision this BEFORE the run starts; the run-start "
              "snapshot seals the ticket set.")
        return 0

    if args.cmd == "break-glass":
        operator_ident = AgentIdentity(agent_id="cli", role="operator",
                                       run_id=run_dir.name,
                                       principal=args.by)
        # F61 (R14) / F66 (R15): show the bounded decision target
        # BEFORE the operator commits to the break-glass — the decision
        # is on the content below, exactly as digested.
        target = _find_record_by_id(queue, args.id)
        if target is not None:
            print("decision target:")
            _print_decision_target(target)
        try:
            record, ticket = queue.break_glass(
                args.id, args.reason, operator_identity=operator_ident,
                ticket_id=args.ticket)
        except (ValueError, TypeError) as e:
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
        # F61 (R14) / F66 (R15): show every bounded decision target
        # BEFORE the batch decision — one rationale covers the whole
        # batch, so the operator must see each item's exact content
        # first.
        for i in ids:
            target = _find_record_by_id(queue, i)
            if target is not None:
                print("decision target %s:" % i)
                _print_decision_target(target)
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

    # F61 (R14) / F66 (R15): show the bounded decision target BEFORE
    # the decision is recorded — the decision is on the content below,
    # exactly as digested (a marker past the old 400-char cut is visible
    # in the full view).
    target = _find_record_by_id(queue, args.id)
    if target is not None:
        print("decision target:")
        _print_decision_target(target)
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
