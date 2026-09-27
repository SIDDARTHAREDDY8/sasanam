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
import errno
import fcntl
import hmac
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from .identity import AgentIdentity, UnregisteredPrincipalError
from .log import (ActionLog, _active_key, _approval_record_mac,
                  _break_glass_ticket_mac, _canonical, _marker_sets,
                  _read_tip_cache, _verify,
                  read_entries, read_entries_with_stats,
                  verify_chain_tip, write_chain_tip_from_tail)
from .egress_ledger import _ledger_keyring
from . import approver_shield as _approver_shield
from .target_match import (DEFAULT_THRESHOLD, typed_scope_similarity,
                           TTC_MATCH_METHOD)


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
#
# D1-core extends the payload with the delegation/quorum/bridge fields
# (decision_mode, delegated_to, delegation_chain, quorum, votes,
# bridge_expired, bridge_expired_at, late_decision). FAIL-CLOSED UPGRADE
# (same precedent as F34/F38/R11): records queued BEFORE D1-core lands
# do not carry these fields, so their digests fail verification
# automatically after the upgrade — queued items must be decided or
# drained before upgrading. There is no migration: post-upgrade,
# pre-D1 digests are refused, never silently re-MACed. The wrong
# principal's decision can never be laundered through a re-MAC because
# the re-MAC is refused first (every state-changing method verifies the
# pending digest BEFORE mutating and re-MACs AFTER — the F38 pattern).
_SECURITY_PAYLOAD_FIELDS = (
    "tool", "args", "policy_id", "egress_bytes", "run_id", "decided_by",
    "agent_id", "role", "principal", "identity",
    "preview", "provenance", "policy_context", "policy_flag",
    # Wave-79 (totality): the governing policy version and the rules
    # that fired are integrity-bound from birth alongside policy_id —
    # rewriting them after queueing would let a tampered record lie
    # about which rule queued it on the human's decision record.
    # FAIL-CLOSED UPGRADE (same precedent as F34/F38/R11/D1/wave-24/
    # F101/F103): records queued before this change do not carry these
    # fields, so their digests fail verification after the upgrade —
    # queued items must be decided or drained before upgrading.
    "policy_version", "matched_rules",
    "delegation_attempted", "delegation_grant_id", "delegation_delegator",
    # F101 (wave-26): the grant id and the delegating party are
    # integrity-bound from birth. A grant-verified approval-gated
    # call queues under the ACTING (delegatee) identity, so the
    # requester-exclusion in decide() compares the decider against
    # the delegatee — binding the delegator on the record lets
    # decide()/cast_vote() exclude the intending party too, closing
    # the D1-core requester-exclusion laundering. FAIL-CLOSED
    # UPGRADE (same precedent as F34/F38/R11/D1/wave-24): records
    # queued before this change do not carry these fields, so their
    # digests fail verification after the upgrade — queued items
    # must be decided or drained before upgrading.
    # D1-core: delegation/quorum/bridge state is integrity-bound, not
    # advisory. Rewriting delegated_to reroutes the decision; truncating
    # delegation_chain erases the requester-loop evidence; lowering
    # quorum.min_approvals or editing quorum.eligible_principals launders
    # the M-of-N gate; flipping a vote row edits dissent away; clearing
    # bridge_expired resurrects a timed-out bridge approval; flipping
    # decision_mode quorum->single dodges the vote gate via decide().
    "decision_mode", "delegated_to", "delegation_chain", "quorum", "votes",
    "bridge_expired", "bridge_expired_at", "late_decision",
    # F103 (wave-27): the full delegator lineage (root -> immediate,
    # each {agent_id, role, principal}) is integrity-bound from birth
    # alongside the F101 immediate-delegator field. Truncating the
    # lineage breaks the MAC and is refused, never silently re-MACed
    # (the F101 guard would otherwise degrade to single-hop).
    # FAIL-CLOSED UPGRADE (same precedent as F34/F38/R11/D1/wave-24/
    # F101): records queued BEFORE this change do not carry this
    # field, so their digests fail verification automatically after
    # the upgrade — queued items must be decided or drained before
    # upgrading.
    # Wave-24 (D1 bridges): the foreign-ingress fields are integrity-bound
    # from birth. bridge_id is the web UI's bridge:<id> badge; the
    # external_request_id idempotency key, the foreign request digest, and
    # the foreign version pins are attacker-influenced data — binding
    # them means post-queue tampering (digest swap, id-key rewrite,
    # badge spoof) breaks the MAC and is refused, never silently
    # re-MACed. FAIL-CLOSED UPGRADE (same precedent as F34/F38/R11/D1):
    # records queued BEFORE wave-24 do not carry these fields, so their
    # digests fail verification automatically after the upgrade — queued
    # items must be decided or drained before upgrading.
    "bridge_id", "external_request_id", "bridge_request_digest",
    "bridge_versions",
    "delegation_delegator_chain",
    # F124 (wave-54): window-close approvals are single-use. The
    # consumed flag is integrity-bound from birth (missing binds as
    # None, same as every other field) so flipping it back after a
    # close breaks the MAC and is refused, never silently re-usable
    # (the F57 break-glass ticket precedent: consumption state rides
    # the HMAC). FAIL-CLOSED UPGRADE (same precedent as F34/F38/R11/
    # D1/F101/F103): records queued BEFORE this change do not carry
    # this field, so their digests fail verification automatically
    # after the upgrade — queued items must be decided or drained
    # before upgrading.
    "window_close_consumed",
    # S3 shield (wave-89): the approval-integrity fields are
    # integrity-bound from birth. persuasion_score/markers are computed
    # by the queue (never caller-supplied); packet_digest binds the
    # displayed decision packet (WYSINWYS); cooling_off_until binds the
    # mandatory pause; prose_divergence binds the prose-vs-args signal;
    # packet_risk_score/factors bind the risk snapshot the packet showed.
    # Rewriting any of them after queueing (deflating a persuasion
    # score, swapping the packet, clearing a cooling-off) breaks the
    # MAC and is refused, never silently re-MACed. FAIL-CLOSED UPGRADE
    # (same precedent as F34/F38/R11/D1/wave-24/F101/F103/F124):
    # records queued BEFORE this change do not carry these fields, so
    # their digests fail verification automatically after the upgrade
    # — queued items must be decided or drained before upgrading.
    "persuasion_score", "persuasion_markers", "prose_divergence",
    "packet_digest", "cooling_off_until",
    "packet_risk_score", "packet_risk_factors",
    # GAP-3 approver shield: the capture tier and the capability signal
    # are integrity-bound from birth (same fail-closed upgrade
    # precedent: rewriting them after queueing breaks the MAC).
    "shield_tier", "capability_verdict",
    # Wave-89 (stream s5-tool): the tool-definition digest pinned at
    # queue time and the deferred-effect details are integrity-bound
    # from birth. Rewriting tool_digest after queueing would let a
    # rug-pulled tool definition ride a human's approval for a
    # different tool; stripping deferred_effect would let a
    # plant-now/harm-later action launder its deferred nature off the
    # human's decision record. FAIL-CLOSED UPGRADE (same precedent as
    # F34/F38/R11/D1/F101/F103): records queued BEFORE this change do
    # not carry these fields, so their digests fail verification
    # automatically after the upgrade — queued items must be decided
    # or drained before upgrading.
    "tool_digest", "deferred_effect",
    # H3 (F142 Leg-A residual, wave-117): the http_post payload content
    # hashes (hex digests, F12-safe) are integrity-bound from birth.
    # Rewriting them after queueing would let a tampered record point
    # the citation-correlation content key at different content than
    # the human approved — post-queue hash laundering breaks the MAC
    # and is refused, never silently re-MACed. FAIL-CLOSED UPGRADE
    # (same precedent as F34/F38/R11/D1/F101/F103): records queued
    # BEFORE this change do not carry this field, so their digests
    # fail verification automatically after the upgrade — queued items
    # must be decided or drained before upgrading.
    "content_sha256_set",
    # Wave-129 (row-7 intent slice): the intent-slice judge's verdict
    # annotation is integrity-bound from birth. It is ADVISORY (the
    # judge never denies; a stale_intent flag routes to human review),
    # but stripping or forging it after queueing would let a tampered
    # record lie to the approver about the intent anchoring the human
    # saw at queue time — post-queue verdict laundering breaks the MAC
    # and is refused, never silently re-MACed. FAIL-CLOSED UPGRADE
    # (same precedent as F34/F38/R11/D1/F101/F103/H3): records queued
    # BEFORE this change do not carry this field, so their digests
    # fail verification automatically after the upgrade — queued items
    # must be decided or drained before upgrading.
    "intent_slice",
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


def _serialize_intent_slice_verdict(verdict):
    """Wave-129 (row-7 intent slice): defensively serialize the judge's
    verdict for MAC-bound stamping on the approval record.

    Returns a JSON-safe dict {flagged, flag, confidence, evidence,
    n_in_slice, n_stale, countermand} or None when the judge did not
    run / the value is not verdict-shaped. Never raises: the judge is
    advisory and must never break queueing.
    """
    try:
        if not isinstance(verdict, dict):
            return None
        if "flagged" not in verdict:
            return None
        summary = verdict.get("slice_summary") or {}
        evidence = verdict.get("evidence") or []
        return {
            "flagged": bool(verdict.get("flagged")),
            "flag": (str(verdict.get("flag"))
                     if verdict.get("flag") is not None else None),
            "confidence": float(verdict.get("confidence") or 0.0),
            "evidence": [str(e)[:500] for e in list(evidence)[:4]],
            "n_in_slice": int(summary.get("n_in_slice") or 0),
            "n_stale": int(summary.get("n_stale") or 0),
            "countermand": bool(summary.get("countermand")),
        }
    except Exception:  # noqa: BLE001 - judge serialization never breaks
        return None


def _delegator_lineage_ids(target):
    """F103 (wave-27): the exclusion set for the D1-core
    requester-exclusion invariant on a delegated approval — the
    agent_id and principal of EVERY delegating party in the
    lineage, not just the immediate delegator.

    Sources: the F101 ``delegation_delegator`` (immediate delegator)
    plus each hop of ``delegation_delegator_chain`` (full lineage,
    root -> immediate, stamped at queue time from the verified
    ``verify_invocation`` lineage and MAC-bound). The union keeps
    decide() and cast_vote() from drifting apart; both call this.
    Malformed hop entries are ignored (the MAC would already have
    failed on a tampered record), None values are dropped.
    """
    ids = set()
    _immediate = target.get("delegation_delegator") or {}
    ids |= {_immediate.get("agent_id"), _immediate.get("principal")}
    for _hop in (target.get("delegation_delegator_chain") or []):
        if isinstance(_hop, dict):
            ids |= {_hop.get("agent_id"), _hop.get("principal")}
    ids.discard(None)
    return ids


# ---------------------------------------------------------------------------
# D1-core: delegation + quorum policy normalization.
#
# These normalizers are the ENFORCEMENT point for the
# ``approvals.delegation`` / ``approvals.quorum`` policy sections: invalid
# configs raise ValueError at load (fail closed). ``gov/policy_lint.py``
# mirrors the same rules as advisory findings (L1-L10); ``gov/policy.py``'s
# ``PolicyEngine`` delegates to these functions so the queue and the
# policy loader cannot drift apart.
# ---------------------------------------------------------------------------

# D1-core §11 Q2: the default is a single reassignment. Chains beyond one
# hop let an approver launder responsibility ("I just passed it on") and
# complicate forensics; operators who need chains raise max_hops
# explicitly. The lint ceiling is 5 either way (>5 is a laundering
# vector, not a feature).
DELEGATION_DEFAULT_MAX_HOPS = 1
DELEGATION_MAX_HOPS_CEILING = 5

# D1-core §3.1 / T1(c): the assignee label for unassigned records — the
# principal that would decide() them today (CLI: the terminal trust
# root; web: the session operator). Matches decide()'s decided_by
# default, so delegation on an unassigned record starts exactly where
# today's decision authority sits.
DEFAULT_OPERATOR_LABEL = "human-operator"
# The web console's distinct operator label — mirrors
# gov.approval_web.WEB_DECIDED_BY, defined here so the core does not
# import the web module. Both labels denote the SAME human-operator
# terminal trust root reached through different surfaces; either may
# initiate delegation on an unassigned record (delegation authority
# is exactly co-extensive with decision authority).
WEB_OPERATOR_LABEL = "web/human-operator"
DEFAULT_ASSIGNEE_LABELS = frozenset(
    {DEFAULT_OPERATOR_LABEL, WEB_OPERATOR_LABEL})


def _normalize_delegation_config(cfg):
    """Normalize the ``approvals.delegation:`` policy section (D1-core).

    Returns ``{"enabled": bool, "max_hops": int}``. Absent section =
    ``{"enabled": False, "max_hops": 1}`` — delegation is opt-in, fail
    closed (L2). Malformed sections raise ValueError (L1/L3): the engine
    refuses to load them rather than silently disabling or mis-shaping
    the control.
    """
    out = {"enabled": False, "max_hops": DELEGATION_DEFAULT_MAX_HOPS}
    if cfg is None:
        return out
    if not isinstance(cfg, dict):
        raise ValueError(
            "approvals.delegation must be a mapping when present (L1)")
    if "enabled" in cfg:
        enabled = cfg["enabled"]
        if not isinstance(enabled, bool):
            raise ValueError(
                "approvals.delegation.enabled must be true/false, got %r "
                "(L2: delegation is opt-in; no silent enable)" % (enabled,))
        out["enabled"] = enabled
    if "max_hops" in cfg:
        hops = cfg["max_hops"]
        if (isinstance(hops, bool) or not isinstance(hops, int)
                or not 1 <= hops <= DELEGATION_MAX_HOPS_CEILING):
            raise ValueError(
                "approvals.delegation.max_hops must be an int in 1..%d, "
                "got %r (L3)" % (DELEGATION_MAX_HOPS_CEILING, hops))
        out["max_hops"] = hops
    return out


def _normalize_quorum_config(cfg):
    """Normalize the ``approvals.quorum:`` policy section (D1-core).

    Returns ``{"min_approvals": int, "eligible_principals": tuple[str],
    "deny_veto": True, "flags": tuple[str] | None}`` or None when the
    section is absent (quorum is opt-in). Malformed sections raise
    ValueError (L4-L9), fail closed at load:

    * L7: ``min_approvals > len(eligible_principals)`` is an unreachable
      quorum — silent starvation — so it fails the load instead of
      queueing records no vote pattern can ever decide.
    * L8: ``deny_veto`` must be True or absent. The one-deny veto is
      non-negotiable (§4.3): an M-of-N scheme where dissent can be
      outvoted is a rubber-stamp amplifier, not a safety gate. Any
      non-True value (including explicit false) is a load error —
      never a silent majority-overrides-dissent.
    """
    if cfg is None:
        return None
    if not isinstance(cfg, dict):
        raise ValueError(
            "approvals.quorum must be a mapping when present (L4)")
    min_approvals = cfg.get("min_approvals")
    if (isinstance(min_approvals, bool)
            or not isinstance(min_approvals, int) or min_approvals < 1):
        raise ValueError(
            "approvals.quorum.min_approvals must be an int >= 1, got %r "
            "(L5)" % (min_approvals,))
    eligible = cfg.get("eligible_principals")
    if (not isinstance(eligible, (list, tuple)) or not eligible
            or any(not isinstance(p, str) or not p.strip()
                   for p in eligible)):
        raise ValueError(
            "approvals.quorum.eligible_principals must be a non-empty "
            "list of non-empty strings (L6)")
    eligible = tuple(p.strip() for p in eligible)
    if len(set(eligible)) != len(eligible):
        raise ValueError(
            "approvals.quorum.eligible_principals must list unique "
            "principals (L6: duplicates would let one human fill two "
            "vote slots)")
    if min_approvals > len(eligible):
        raise ValueError(
            "approvals.quorum.min_approvals (%d) exceeds "
            "len(eligible_principals) (%d): the quorum is unreachable — "
            "silent starvation — failing closed at load (L7)"
            % (min_approvals, len(eligible)))
    if "deny_veto" in cfg and cfg["deny_veto"] is not True:
        raise ValueError(
            "approvals.quorum.deny_veto must be true or absent, got %r: "
            "the one-deny veto is non-negotiable (L8)" % (cfg["deny_veto"],))
    flags = cfg.get("flags")
    if flags is not None:
        if (not isinstance(flags, (list, tuple))
                or any(not isinstance(f, str) or not f.strip()
                       for f in flags)):
            raise ValueError(
                "approvals.quorum.flags must be a list of non-empty "
                "strings when present (L9)")
        flags = tuple(f.strip() for f in flags)
    return {"min_approvals": min_approvals,
            "eligible_principals": eligible,
            "deny_veto": True,
            "flags": flags}


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


def _goal_review_goal_ids(record):
    """Wave-134 (row-11): goal ids adjudicated by a decision record.

    For a ``goal_conflict_review`` record this is the new (conflicting)
    goal id followed by the existing goal ids it collided with,
    deduplicated, order-stable. For every other record type this is
    None (the ``approval_decision`` event carries the field only for
    goal reviews; the resolution events carry the approval id back, so
    the trail cross-references both ways). The extraction itself is
    ``gov.goals.conflict_review_goal_ids`` (shared with the
    executor hook and the resolution function).
    """
    if not isinstance(record, dict):
        return None
    if record.get("tool") != "goal_conflict_review":
        return None
    from . import goals as _goals
    ids = _goals.conflict_review_goal_ids(record.get("args") or {})
    return ids or None


def _type_to_confirm_reference(target):
    """Wave-145 (row-11): the type-to-confirm reference scope for a
    pending approval record, or None when the ceremony does not apply.

    The ceremony applies ONLY to ``goal_specificity_review`` records
    carrying the queue-time-stamped ``type_to_confirm_reference`` --
    the goal's declared scope (description + effect atoms), stamped by
    the executor at queue time and MAC-bound on the record (F38), so
    the reference the human's typing is checked against is exactly
    what the review displayed. Every other record type -- and any
    specificity review queued WITHOUT the stamp (pre-wave-145 or
    hand-crafted records) -- returns None: zero behavior change, the
    record is decided exactly as before. A hand-crafted review is
    still attested by the executor's decision hook (goal_specificity
    noop when the goal is unknown), not by this ceremony.
    """
    if not isinstance(target, dict):
        return None
    if target.get("tool") != "goal_specificity_review":
        return None
    args = target.get("args")
    if not isinstance(args, dict):
        return None
    ref = args.get("type_to_confirm_reference")
    if not isinstance(ref, list) or not ref:
        return None
    texts = [t for t in ref if isinstance(t, str) and t.strip()]
    return texts or None


def _type_to_confirm_ok(reference_texts, typed_scope):
    """Wave-145 (row-11): check the human's typed scope against the
    reference scope. Returns ``(ok, score, detail)``.

    ``typed_scope`` must be a non-blank string scoring >=
    ``DEFAULT_THRESHOLD`` (``gov.target_match.typed_scope_similarity``
    -- the synonym-aware token-tversky variant, wave-147: max of raw
    and synonym-canonicalized token-tversky with the destination veto
    and a verb-agreement veto, at the same threshold) against at
    least one reference text. A missing, blank, or non-string typed
    scope is NEVER a match (fail-closed): a bare click cannot
    satisfy the ceremony. The best sub-threshold score is reported
    (not zeroed) so the LOUD refusal event names the actual
    measured mismatch.
    """
    if not isinstance(typed_scope, str) or not typed_scope.strip():
        return (False, 0.0,
                "no typed scope provided: approving a vague/wildcard "
                "goal requires typing the narrowed scope")
    best = 0.0
    for text in reference_texts:
        if not isinstance(text, str) or not text.strip():
            continue
        score = typed_scope_similarity(typed_scope, text)
        if score > best:
            best = score
    if best >= DEFAULT_THRESHOLD:
        return (True, best,
                "typed scope matches the declared scope (token-tversky "
                "+synonym %.3f >= %.2f) %s" % (best, DEFAULT_THRESHOLD,
                                               TTC_MATCH_METHOD))
    return (False, best,
            "typed scope does not match the goal's declared scope "
            "(token-tversky+synonym %.3f < %.2f)"
            % (best, DEFAULT_THRESHOLD))


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


ANOMALY_RISK_BUMP = 15        # advisory escalation on anomalous items


# --- S3 approval-integrity shield (wave-89) ------------------------------
# Deterministic, $0, no-LLM defenses for the HUMAN's decision (memo Part
# D row 3: human-approver persuasion, PARTIAL -> measured). The approval
# queue was machine-blind to manipulation of the approver: agent prose
# passed through untouched, nothing computed divergence between prose
# claims and canonical args, nothing bound what the human SAW, and
# fatigue/velocity signals were advisory-only. This section adds:
#   score_persuasion()      deterministic persuasion-marker scoring
#   prose_divergence()       prose-claim vs canonical-args divergence
#   canonical_packet()       machine-generated, agent-prose-free packet
#   _packet_digest()        digest binding of the displayed packet
# plus queue()/decide() wiring: cooling-off for critical items and
# enforced different-approver escalation for fatigued principals.
# HONEST LIMITS (documented, not claimed away): heuristic scoring is
# bypassable by a careful adversary; a determined, fatigued, or
# complicit approver remains a residual; cooling-off can be waited out;
# second-approver enforcement is only as strong as decided_by identity
# strings. We meter and escalate; we never claim the process is
# human-proof.

# Persuasion marker families: (family, points per distinct marker hit,
# family cap, regexes). Scoring is deterministic and one-directional —
# it can only raise the score, never lower it.
_PERSUASION_MARKERS = (
    ("urgency", 15, 30, (
        r"\burgent\b", r"\basap\b", r"\bimmediately\b",
        r"\bright now\b", r"\bdeadline\b", r"\btime-sensitive\b",
        r"\bemergency\b", r"\bbefore it'?s too late\b", r"\bat once\b",
    )),
    ("authority", 20, 40, (
        r"\bmanager\b.{0,30}\bapproved\b", r"\bceo\b.{0,30}\bapproved\b",
        r"\bverbally approved\b", r"\bper policy\b",
        r"\bauthoriz(?:ed|ation) by\b", r"\bleadership\b.{0,30}\bapproved\b",
        r"\bcompliance requires\b", r"\balready approved\b",
        r"\bsecurity team\b.{0,30}\bapproved\b",
    )),
    ("secrecy", 25, 50, (
        r"\bdon'?t tell\b", r"\bdo not tell\b", r"\bconfidential\b",
        r"\bdon'?t log\b", r"\bdo not log\b", r"\bkeep this quiet\b",
        r"\bbetween us\b", r"\boff the record\b",
        r"\bno need to document\b", r"\bdelete this\b",
    )),
    ("approver_instruction", 30, 60, (
        r"\bjust approve\b", r"\bno need to review\b",
        r"\bdon'?t review\b", r"\bdo not review\b",
        r"\bskip the review\b", r"\bapprove without\b",
        r"\brubber[- ]stamp\b", r"\bdon'?t ask questions\b",
    )),
    ("guilt", 15, 30, (
        r"\byou'?ll be responsible\b", r"\byou will be responsible\b",
        r"\byour fault\b", r"\byour responsibility\b",
        r"\bpeople will suffer\b", r"\bthink of the team\b",
    )),
)
PERSUASION_FLAG_SCORE = 50    # banner threshold: approver is warned
PERSUASION_RISK_SCORE = 70    # risk-bump threshold: feeds cooling-off /
                              # fatigue machinery via _score_factors
PERSUASION_RISK_BUMP = 20     # advisory, one-directional, never lowers

COOLING_OFF_MIN_SCORE = 80         # "critical" tier: mandatory pause
DEFAULT_COOLING_OFF_SECONDS = 900  # 15 minutes; policy-configurable

FATIGUE_WINDOW_SEC = 600            # trailing window for velocity
FATIGUE_DECISION_THRESHOLD = 8      # approves by one principal in window
FATIGUE_ESCALATION_MIN_SCORE = 60   # "high" tier: needs a fresh approver

# Matches address-like tokens, including bare internal hostnames
# (ops@internal) that carry no dot-TLD — the divergence detector must
# see the addresses humans actually write, not just RFC-shaped ones.
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+")


def score_persuasion(text):
    """Deterministic persuasion-marker scoring over agent prose.

    Returns ``(score 0-100, markers [...])`` where markers are
    ``"family:matched-phrase"`` strings. Pure function of the text —
    no LLM, no network, $0. Bypassable by a careful adversary by
    construction (documented limit); it is a tripwire, not a verdict.
    """
    blob = str(text or "")
    lowered = blob.lower()
    markers = []
    total = 0
    for family, points, cap, patterns in _PERSUASION_MARKERS:
        fam_total = 0
        for pat in patterns:
            m = re.search(pat, lowered)
            if m:
                markers.append("%s:%s" % (family, m.group(0).strip()))
                fam_total += points
        total += min(fam_total, cap)
    return min(100, total), markers


def prose_divergence(justification, args):
    """Detect when agent prose claims a DIFFERENT target than the args.

    The decide-A/summarize-A'/execute-A shape: the justification names a
    benign recipient while the canonical args name another. Returns a
    short description string when a specific recipient claim in the
    prose contradicts the action's actual target, else None. Heuristic
    and conservative: prose that names no address never diverges.
    """
    just = str(justification or "")
    claimed = {m.group(0).lower() for m in _EMAIL_RE.finditer(just)}
    if not claimed:
        return None
    args = args or {}
    actual = None
    for key in ("to", "url", "path", "recipient", "destination"):
        val = args.get(key)
        if isinstance(val, str) and val:
            actual = val
            break
    if actual is None:
        return None
    actual_addrs = {m.group(0).lower() for m in _EMAIL_RE.finditer(actual)}
    if actual_addrs and not (claimed & actual_addrs):
        # The prose names concrete address(es) and NONE of them is the
        # actual target — the approver is being told a different story
        # than the action will execute.
        return ("justification names %s but the action targets %s"
                % (sorted(claimed)[0], sorted(actual_addrs)[0]))
    return None


def _packet_target(tool, args):
    """The machine-extracted target of the action (never agent prose)."""
    args = args or {}
    for key in ("to", "url", "path", "window", "recipient", "destination"):
        val = args.get(key)
        if isinstance(val, str) and val:
            return val
    for val in args.values():
        if isinstance(val, str) and val:
            return val[:120]
    return "(no scalar target)"


def _packet_blast_radius(record):
    """Machine-computed blast-radius hints from governor-held fields."""
    hints = []
    ctx = record.get("policy_context") or {}
    tool = record.get("tool")
    if ctx.get("path_outside_sandbox"):
        hints.append("target outside sandbox")
    if ctx.get("domain_allowlisted") is False and tool in (
            "send_email", "http_post", "api_call"):
        hints.append("egress to non-allowlisted destination")
    if ctx.get("carries_read_content"):
        hints.append("carries previously-read content")
    if _secret_hint_in_args(record.get("args")):
        hints.append("secret-like material in arguments")
    if tool == "delete_file":
        hints.append("destructive: deletes data")
    if (record.get("persuasion_score") or 0) >= PERSUASION_RISK_SCORE:
        hints.append("high persuasion markers in agent prose")
    if record.get("prose_divergence"):
        hints.append("agent prose contradicts action target")
    return hints


def canonical_packet(record):
    """Machine-generated, agent-prose-free decision packet.

    The PRIMARY decision basis: action, machine-extracted target, risk
    tier + factors, blast radius, policy citations, persuasion summary.
    Pure function of the stored record — recomputable at decide time,
    so the digest below binds exactly what the human saw.
    """
    score = record.get("packet_risk_score") or 0
    return {
        "packet_version": 2,
        "action": record.get("tool"),
        "target": _packet_target(record.get("tool"), record.get("args")),
        "risk_tier": risk_level(score),
        "risk_score": score,
        "risk_factors": list(record.get("packet_risk_factors") or []),
        "blast_radius": _packet_blast_radius(record),
        # GAP-3: the capture tier is part of what the human saw -- the
        # friction the approver will face at decide time is bound by
        # the same WYSINWYS digest.
        "shield_tier": record.get("shield_tier"),
        "policy": {
            "policy_id": record.get("policy_id"),
            "policy_version": record.get("policy_version"),
            "matched_rules": list(record.get("matched_rules") or []),
            "policy_flag": record.get("policy_flag"),
        },
        "persuasion": {
            "score": record.get("persuasion_score") or 0,
            "markers": list(record.get("persuasion_markers") or []),
        },
        "preview_sha256": sha256(
            str(record.get("preview") or "").encode("utf-8")).hexdigest(),
        "agent": {
            "agent_id": record.get("agent_id"),
            "role": record.get("role"),
            "principal": record.get("principal"),
        },
    }


def _packet_digest(packet):
    """Digest binding of the displayed packet (WYSINWYS)."""
    return sha256(
        _canonical_dumps(packet).encode("utf-8")).hexdigest()


def _packet_digest_ok(record):
    """Recompute the packet from the STORED record and compare.

    The packet is a pure function of stored fields, so any drift
    between what was displayed (queue time) and what is decided —
    rewritten preview, edited persuasion score, swapped risk snapshot —
    breaks the digest. Fail closed.
    """
    stored = record.get("packet_digest")
    if not stored:
        return False
    try:
        return _packet_digest(canonical_packet(record)) == stored
    except Exception:
        return False


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
            and tool in ("send_email", "http_post", "api_call")):
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
    # S3 shield (wave-89): persuasion-shaped items score higher. The
    # bump is advisory and one-directional — it can only raise the
    # score, never lower it — and it feeds the cooling-off (>=80) and
    # fatigue-escalation (>=60) machinery below, plus the batch guards.
    # Records queued before the shield carry no persuasion_score and
    # get no bump (fail-closed upgrade keeps them undecidable anyway).
    _pers = record.get("persuasion_score") or 0
    if _pers >= PERSUASION_RISK_SCORE:
        score += PERSUASION_RISK_BUMP
        factors.append("persuasion markers in agent prose +%d (advisory: "
                       "manipulation-shaped framing detected)"
                       % PERSUASION_RISK_BUMP)
    return min(100, score), factors


class ApprovalQueueRiskMixin:
    """Mixin for ApprovalQueue: risk, floods, batch, auto-approve,
    break-glass, post-review."""

    # Wave-79 (totality): the single choke point for audit-log writes
    # in the approval subsystem (the mixin and ApprovalQueue both
    # route through it — ApprovalQueue inherits this method). Any
    # entry carrying a `decision` key is a decision record and must
    # name the governing policy version and the rules that fired.
    # Explicit values win; otherwise the subsystem fallback
    # ("approvals-d1" / []) applies. decide() passes the ticket's
    # stored values so a human's outcome record names the rule that
    # queued it. Returns the appended entry (seq-bearing), like
    # log.append.
    def _log(self, entry, policy_version=None, matched_rules=None):
        if isinstance(entry, dict) and "decision" in entry:
            entry.setdefault("policy_version",
                             policy_version or "approvals-d1")
            if matched_rules is None:
                matched_rules = []
            entry.setdefault("matched_rules", matched_rules)
        return self.log.append(entry)

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
        # D1-core: exact match on BOTH agent_id and principal (the alias
        # shape) — same invariant as decide()'s SoD check, enforced here
        # up front so the batch fails BEFORE any partial decision.
        if decided_by and any(
                decided_by == records[i].get("agent_id")
                or (records[i].get("principal")
                    and decided_by == records[i].get("principal"))
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
                continue
            # D1-core: delegated records are batch-opaque — the batch's
            # decided_by must EXACTLY match the record's assignee (the
            # T3 guard in decide() enforces this per item too). A batch
            # by anyone else cannot decide them; they stay pending for
            # the assignee. Excluded, not aborted — skipping is the safe
            # direction (F21 pattern).
            assignee = records[i].get("delegated_to")
            if assignee is not None and decided_by != assignee:
                rec = dict(records[i])
                rec["batch_exclusion_reason"] = (
                    "delegated to %r: only the assignee may decide it; "
                    "batch decided_by %r does not match"
                    % (assignee, decided_by))
                excluded.append(rec)
                continue
            # GAP-3 approver shield: capture-tier items need the
            # per-item shield handshake (independent brief view +
            # challenge) that a batch cannot perform. They are excluded
            # from APPROVE batches (F21 safe-direction pattern:
            # skipping is safe). Reject batches are unaffected --
            # refusing is always safe.
            if (approved
                    and _approver_shield.is_capture_tier(records[i])):
                rec = dict(records[i])
                rec["batch_exclusion_reason"] = (
                    "capture-tier (approver shield): approving requires "
                    "the per-item shield handshake (independent brief + "
                    "challenge) -- decide individually via decide()")
                excluded.append(rec)
                continue
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
            self._log({
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
        batch_entry = self._log({
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
        # D1-core: a delegated record's decision stewardship belongs to
        # its assignee — auto-approve is a machine decider and can never
        # be the assignee, so the T3 exact-match guard in decide()
        # would refuse it anyway. Fail closed here with the silent None
        # every other gate refusal returns, instead of letting decide()
        # raise.
        if record.get("delegated_to") is not None:
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
        self._log({
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
            self._log({
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
        # D1-core: quorum-collecting records can NEVER be
        # break-glassed. The M-of-N vote gate is structural: a
        # single-operator emergency bypass cannot stand in for M
        # distinct human votes, and the emergency path must never be
        # the route around a quorum the votes could not reach. Refused
        # BEFORE the ticket lock so a refused attempt never consumes a
        # single-use ticket; audited as break_glass_refused.
        for _bg_rec in self.all():
            if _bg_rec["id"] == approval_id:
                if _bg_rec.get("decision_mode") == "quorum":
                    self._refuse_break_glass(
                        approval_id,
                        "break-glass refused: quorum-collecting records "
                        "can never be break-glassed — the M-of-N vote "
                        "gate is structural and cannot be bypassed by "
                        "the single-operator emergency path",
                        ticket_id=ticket_id,
                        operator_principal=(
                            operator_identity.principal))
                    raise ValueError(
                        "break-glass refused: quorum-collecting records "
                        "can never be break-glassed (D1-core: the M-of-N "
                        "vote gate is structural, not an emergency "
                        "bypass)")
                break
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
                self._log({
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
        self._log({
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
            self._log({
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
            self._log({
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
        entry = self._log({
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
        # D1-core: surface the pending SUBSTATES in the audit report —
        # a pending record is never just "pending" anymore: DELEGATED
        # tells the operator stewardship moved, QUORUM_COLLECTING shows
        # the live tally against the MACed snapshot.
        delegated = [r["id"] for r in pending
                     if r.get("delegated_to") is not None]
        quorum_collecting = []
        for r in pending:
            if r.get("decision_mode") == "quorum":
                quorum = r.get("quorum") or {}
                votes = r.get("votes") or []
                quorum_collecting.append({
                    "id": r["id"],
                    "approvals_cast": sum(
                        1 for v in votes if v.get("approve")),
                    "min_approvals": quorum.get("min_approvals"),
                    "eligible_principals": list(
                        quorum.get("eligible_principals") or []),
                })
        late_decisions = [r["id"] for r in self.all()
                          if r.get("late_decision")]
        return {
            "clean": clean,
            "pending_count": len(pending),
            "flood_suspect_ids": floods,
            "unresolved_break_glass": [t["ticket_id"] for t in reviews],
            "delegated_ids": delegated,
            "quorum_collecting": quorum_collecting,
            "late_decision_ids": late_decisions,
        }


class DecisionHookAlreadySetError(Exception):
    """Wave-134 (row-11): the post-decision hook is write-once
    (deployer-only), same F31 rationale as the identity verifier.

    ``ToolExecutor`` installs its goal-resolution hook at
    construction; any later ``set_decision_hook`` call raises instead
    of swapping the control out from under the deployment."""


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


def _fsync_syncable(fd):
    """F89: fsync, tolerating EINVAL for non-syncable fds.

    ``os.fsync`` raises ``OSError(EINVAL)`` on file descriptors that do
    not support synchronization (character devices such as /dev/null,
    pipes, sockets). The queue/ticket store files live in the run dir,
    which the documented F52 run-dir-writer residual allows an attacker
    to symlink (the w11 sit64 probe pins the /dev/null symlink shape:
    the approval is "accepted" but silently vanishes). The F83
    durability fsync must not turn that documented residual into an
    unhandled ``OSError`` crashing ``queue()`` — EINVAL means "this
    object cannot be synced", not "data was lost": the preceding
    ``write()`` already succeeded. Every other ``OSError`` (EIO,
    ENOSPC, EBADF, ...) still propagates loud, so the F83 durability
    guarantee for real files is unchanged.
    """
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno != errno.EINVAL:
            raise


def _atomic_write_counter():
    """Monotonic counter for unique temp-file names (see below)."""
    _atomic_write_counter.n += 1
    return _atomic_write_counter.n


_atomic_write_counter.n = 0


def _atomic_write_text(path, lines):
    """F83: crash-durable rewrite of a JSONL file.

    Writes ``lines`` (each already newline-terminated) to a temp file
    in the same directory, flushes + fsyncs it, then ``os.replace``s it
    over ``path`` and fsyncs the directory so the rename itself is
    durable. A crash at any point leaves either the complete old file
    or the complete new file — never a truncation. The old code did
    ``open(path, "w")`` (truncate-in-place): a crash mid-write
    destroyed the whole approval queue.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temp name per call: concurrent rewrites (threads) must not
    # collide on the temp path. (Callers serialize via the queue lock;
    # this is defense in depth.)
    tmp = path.with_name("%s.tmp.%d.%d.%d" % (
        path.name, os.getpid(), threading.get_ident(),
        _atomic_write_counter()))
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class ApprovalQueue(ApprovalQueueRiskMixin):
    def __init__(self, run_dir, log, batch_excluded_reasons=None,
                 delegation_config=None, quorum_config=None,
                 principal_registry=None, cooling_off_seconds=None):
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
        # S3 shield (wave-89): cooling-off pause for critical items.
        self.set_cooling_off_seconds(cooling_off_seconds)
        # D1-core: delegation/quorum policy sections, normalized
        # fail-closed at install. The raw shapes are the policy file's
        # ``approvals.delegation`` / ``approvals.quorum`` mappings (or
        # None = feature off); PolicyEngine installs its normalized
        # copies. Direct/CLI construction without a policy keeps both
        # features off — today's single-decider posture.
        self.set_delegation_config(delegation_config)
        self.set_quorum_config(quorum_config)
        # D1-core §11 Q4: the deployment's PrincipalRegistry for the
        # delegatee registration check. None = no registry: principal
        # strings are the terminal trust root (documented
        # localhost-grade limit, same as CLI --by today).
        self._principal_registry = None
        if principal_registry is not None:
            self.set_principal_registry(principal_registry)
        # F26: optional executor-installed identity verifier for the
        # break-glass/review paths (see set_identity_verifier). None =
        # isinstance check only (the CLI path: terminal-access trust
        # root, documented). F31: write-once — once installed it can
        # never be swapped (see _identity_verifier_sealed).
        self._identity_verifier = None
        self._identity_verifier_sealed = False
        # Wave-134 (row-11): executor-installed post-decision hook
        # (see set_decision_hook). None = no hook: decide() behavior
        # unchanged. Write-once, F31 pattern.
        self._decision_hook = None
        self._decision_hook_sealed = False
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

    def set_decision_hook(self, hook):
        """Wave-134 (row-11): install the executor's post-decision hook.

        ``hook(record, approved, reason, decided_by, decision_entry)``
        is called at the end of ``decide()`` for every successfully
        decided record, after the decision is recorded and audited.
        The hook itself filters by record type (the goal-resolution
        wiring only acts on ``goal_conflict_review`` records).

        F31 WRITE-ONCE: the first call installs the hook and seals the
        slot; every later call raises ``DecisionHookAlreadySetError``.
        A hook swap — e.g. an agent replacing the executor's
        goal-resolution wiring with a no-op — is refused. ``decide()``
        never lets a raising hook break the decision: it is audited
        LOUD and swallowed (the decision stands; the hook is
        automation, never a veto).
        """
        if getattr(self, "_decision_hook_sealed", False):
            raise DecisionHookAlreadySetError(
                "decision hook is write-once: a hook is already "
                "installed; refusing to swap it out")
        if not callable(hook):
            raise TypeError(
                "decision hook must be callable, got %r"
                % type(hook).__name__)
        self._decision_hook = hook
        self._decision_hook_sealed = True

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

    def set_cooling_off_seconds(self, seconds):
        """S3 shield (wave-89): install the cooling-off pause length.

        ``seconds=None`` keeps the default (15 minutes); an explicit
        value (possibly 0 = pause disabled) is honored as the
        deployment's choice. Re-set is allowed — this is policy data,
        not an identity anchor.
        """
        if seconds is None:
            self._cooling_off_seconds = DEFAULT_COOLING_OFF_SECONDS
        else:
            self._cooling_off_seconds = max(0, int(seconds))

    def _stamp_approval_integrity(self, record, preview, justification,
                                  args, capability_verdict=None,
                                  intent_slice_verdict=None):
        """S3 shield (wave-89): stamp the approval-integrity fields on a
        freshly-built record, BEFORE its args_digest is computed (they
        are MAC-bound from birth). Called from every queueing path —
        queue() AND queue_external() — so no ingress route produces an
        unstamped record that decide() would then have to refuse.
        Bridge/foreign records get the same shield: their
        agent_justification is explicitly UNVERIFIED foreign prose, the
        highest-value persuasion surface.

        GAP-3 approver shield: also stamps ``shield_tier`` ("capture"
        when manipulation signals are present) and
        ``capability_verdict`` (the executor-supplied capability signal,
        or None). Both are MAC-bound from birth like every other shield
        field.

        Wave-129 (row-7 intent slice): ``intent_slice_verdict`` is the
        intent-slice judge's verdict dict (or None when the judge did
        not run). Stamped MAC-bound from birth as ``record["intent_slice"]``
        (a JSON-safe dict or None). The judge is ADVISORY ONLY -- it
        never denies; a ``stale_intent`` flag is evidence for the human
        reviewer. Serialization is defensive: an unverdict-shaped value
        stamps None rather than breaking queueing.
        """
        _p_score, _p_markers = score_persuasion(
            "%s\n%s" % (preview, justification or ""))
        record["persuasion_score"] = _p_score
        record["persuasion_markers"] = _p_markers
        record["prose_divergence"] = prose_divergence(justification, args)
        # Risk snapshot for the packet and the cooling-off gate,
        # computed pre-insert against the current queue state.
        _p_risk, _p_factors = _score_factors(record, self.all())
        record["packet_risk_score"] = _p_risk
        record["packet_risk_factors"] = _p_factors
        # GAP-3 approver shield: capture tier + capability signal,
        # stamped BEFORE the canonical packet is computed -- the packet
        # binds them (WYSINWYS covers the friction the approver will
        # face), and decide()'s re-verification recomputes the packet
        # from the stored record, so stamping after would break the
        # digest on every record.
        record["capability_verdict"] = (
            str(capability_verdict) if capability_verdict is not None
            else None)
        # Wave-129 (row-7 intent slice): the judge's verdict annotation,
        # MAC-bound from birth. Defensive serialization: only a dict
        # with the expected verdict shape is stamped; anything else
        # stamps None (the judge must never break queueing).
        record["intent_slice"] = _serialize_intent_slice_verdict(
            intent_slice_verdict)
        record["shield_tier"] = _approver_shield.shield_tier(
            record,
            persuasion_risk_score=PERSUASION_RISK_SCORE,
            critical_risk_score=COOLING_OFF_MIN_SCORE)
        _packet = canonical_packet(record)
        record["canonical_packet"] = _packet
        record["packet_digest"] = _packet_digest(_packet)
        # Cooling-off: critical-tier items cannot be approved until the
        # pause elapses — and neither can heavily-manipulated items.
        # A persuasion score >= PERSUASION_RISK_SCORE means the framing
        # is maximally manipulative; the laundering shape works at ANY
        # risk tier (a compliant approver rubber-stamps a medium-risk
        # exfil the same way), so the pause is the manipulation
        # circuit-breaker, not just the criticality gate. Stamped here
        # (MAC-bound); decide() enforces.
        if (_p_risk >= COOLING_OFF_MIN_SCORE
                or _p_score >= PERSUASION_RISK_SCORE):
            _cool_until = (datetime.now(timezone.utc)
                           + timedelta(seconds=self._cooling_off_seconds))
            record["cooling_off_until"] = _cool_until.isoformat()
        else:
            record["cooling_off_until"] = None

    def _principal_fatigued(self, principal):
        """S3 shield (wave-89): is this principal past the decision-
        velocity threshold? Counts APPROVE decisions (the laundering
        direction — rejections don't launder) by the principal inside
        the trailing window, read from the queue file itself so the
        signal survives restarts and cannot drift from the log.

        Honest limit: identity is only as strong as decided_by strings
        (documented localhost-grade limit, same as the D1-core note).
        """
        if not principal:
            return False
        now = datetime.now(timezone.utc)
        count = 0
        for r in self.all():
            if r.get("status") != "approved":
                continue
            if r.get("decided_by") != principal:
                continue
            ts = self._parse_ts(r.get("decided_at"))
            if ts is None:
                continue
            if (now - ts).total_seconds() <= FATIGUE_WINDOW_SEC:
                count += 1
                if count >= FATIGUE_DECISION_THRESHOLD:
                    return True
        return False

    def set_delegation_config(self, cfg):
        """D1-core: install the ``approvals.delegation`` policy section.

        ``cfg`` is the raw policy-file mapping (or None = feature off);
        it is normalized fail-closed by
        :func:`_normalize_delegation_config` — invalid shapes raise
        ValueError here, never silently mis-shape the control. Re-set
        is allowed (policy reloads happen); the F31 write-once pattern
        does not apply — this is policy data, not an identity anchor.
        """
        self._delegation_cfg = _normalize_delegation_config(cfg)

    @property
    def delegation_enabled(self):
        """D1-core: True when the installed ``approvals.delegation``
        policy section enables delegation. Lets read-only surfaces
        (e.g. the web console) render the delegate affordance only
        when the control is actually on."""
        return bool((self._delegation_cfg or {}).get("enabled"))

    def set_quorum_config(self, cfg):
        """D1-core: install the ``approvals.quorum`` policy section.

        ``cfg`` is the raw policy-file mapping (or None = feature off);
        normalized fail-closed by :func:`_normalize_quorum_config`.
        The installed config only affects records queued AFTER the
        install — queued records carry their own MACed snapshot
        (``record["quorum"]``), so a config change can never shrink
        ``min_approvals`` or swap ``eligible_principals`` under a live
        collection (quorum-bypass-by-config-edit is structurally
        impossible).
        """
        self._quorum_cfg = _normalize_quorum_config(cfg)

    def set_principal_registry(self, registry):
        """D1-core §11 Q4: install the deployment's PrincipalRegistry.

        Lets ``delegate()`` refuse unregistered delegatees when a
        registry is configured. Also marks the registry as configured
        (same flag ``note_registry_configured()`` sets).
        """
        self._principal_registry = registry
        self._registry_configured = True

    def _delegatee_registered(self, principal):
        """D1-core §11 Q4: True when *principal* may receive a delegation.

        Without a configured registry, principal strings are the
        terminal trust root (documented localhost-grade limit) and any
        non-empty principal passes. With a registry configured, the
        delegatee must be registry-known; when the registry object
        itself is missing the check cannot run, so it fails closed
        (refuse) rather than silently passing.
        """
        if not self._registry_configured:
            return True
        registry = getattr(self, "_principal_registry", None)
        if registry is None:
            return False
        try:
            registry.check(principal)
        except UnregisteredPrincipalError:
            return False
        return True

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
        # D1-core: quorum-collecting records can never be batch-decided
        # — the M-of-N vote gate is structural, not a batch exclusion
        # list entry (which the policy can edit). Nothing in a batch can
        # stand in for M distinct human votes.
        if record.get("decision_mode") == "quorum":
            return ("quorum-collecting record: decided only by "
                    "cast_vote() finalize — batch cannot stand in for "
                    "M human votes")
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

    def _append_lock_path(self):
        return self.run_dir / "approvals.append.lock"

    @contextlib.contextmanager
    def _append_locked(self, timeout=10):
        """F83: leaf lock serializing the heal+append sequence in
        ``queue()`` across threads and processes.

        This is deliberately NOT the sweep lock (``_queue_locked``):
        sweeps hold that lock across tool execution, so ``queue()``
        must never contend with it (a slow sweep would turn every new
        queue() into a 30s block or a ``QueueLockError``). The append
        lock is a leaf — never nested inside or outside any other
        lock — held only for microseconds around the torn-tail heal,
        the append, and the fsync. ``QueueLockError`` on timeout:
        fail closed, never append unlocked.
        """
        self.run_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self._append_lock_path()
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
        except OSError as e:
            raise QueueLockError(
                "approval-queue append lock path %s is not lockable "
                "(%s); refusing to queue" % (lock_path, e))
        f = os.fdopen(fd, "a", encoding="utf-8")
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(f.fileno(),
                                fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise QueueLockError(
                            "approval-queue append lock unavailable "
                            "after %ds; refusing to queue rather than "
                            "risk a torn append race" % timeout)
                    time.sleep(0.01)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()

    def _heal_torn_tail(self):
        """F83: truncate a torn trailing append before writing.

        If the queue file does not end with ``"\\n"``, the final bytes
        are a torn append from a crash between ``write()`` and fsync
        (our writers always newline-terminate). The torn bytes are
        truncated back to the last newline so the new record cannot
        glue onto them into one unparsable line. Only bytes that were
        never durably queued are removed: every complete record ends
        with ``"\\n"`` and is preserved. Caller must hold
        ``_append_locked``.
        """
        try:
            f = open(self.path, "r+b")
        except FileNotFoundError:
            return
        with f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return
            f.seek(max(0, size - 1))
            if f.read(1) == b"\n":
                return  # well-formed tail: nothing to heal
            # Scan back for the last newline and truncate after it.
            pos = size - 1
            chunk = 4096
            while pos > 0:
                start = max(0, pos - chunk)
                f.seek(start)
                data = f.read(pos - start)
                idx = data.rfind(b"\n")
                if idx != -1:
                    f.truncate(start + idx + 1)
                    f.flush()
                    os.fsync(f.fileno())
                    return
                pos = start
            # No newline at all: the whole file is one torn line from
            # a crash on the very first queue() — nothing durable to
            # keep.
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())

    def queue(self, action, decision, provenance="agent_direct", preview="",
              policy_hash=None, delegation_attempted=False,
              delegation_grant_id=None, delegation_delegator=None,
              delegation_delegator_chain=None,
              policy_context=None, policy_flag=None, egress_bytes=None,
              caller_identity=None, policy_version=None,
              matched_rules=None, tool_digest=None, deferred_effect=None,
              capability_verdict=None, intent_slice_verdict=None):
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

        ``delegation_grant_id`` / ``delegation_delegator`` (F101,
        wave-26): for a grant-verified call, the executor passes the
        verified grant id and the delegating party's
        ``{agent_id, role, principal}`` (as verified by the delegation
        store — never caller-supplied). Both are stamped on the
        record and MAC-bound, so ``decide()``/``cast_vote()`` exclude
        the intending party alongside the requester. Absent (None)
        for non-delegated calls.

        ``delegation_delegator_chain`` (F103, wave-27): the FULL
        delegator lineage for the grant — root ``->`` immediate, each
        ``{agent_id, role, principal}`` as resolved by
        ``DelegationStore.verify_invocation`` from the re-verified
        ancestor records (never caller-supplied). Stamped on the
        record and MAC-bound (see ``_SECURITY_PAYLOAD_FIELDS``) so
        ``decide()``/``cast_vote()`` exclude every intending party in
        the chain, closing the depth->=2 single-hop gap in the F101
        guard. At depth 1 the lineage is just ``[immediate]``. Absent
        (None) for non-delegated calls.

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
        # Wave-89 (stream s5-tool): auto-pin the tool-definition digest
        # when the caller did not supply one. The executor always pins
        # explicitly from its own inventory; direct queue() callers
        # (tests, the canary halt path) get the default inventory's
        # digest so every new record carries a pin and the sweep's
        # re-verification applies uniformly. A deployment with a custom
        # ToolInventory that queues directly (bypassing the executor)
        # should pass tool_digest explicitly — the default pin here is
        # best-effort, and the sweep compares against the EXECUTOR's
        # inventory.
        if tool_digest is None and action.get("tool") is not None:
            from . import tool_continuity as _tool_continuity
            tool_digest = _tool_continuity.ToolInventory().digest_for(
                action.get("tool"))
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
            # H3 (F142 Leg-A residual, wave-117): http_post payload
            # content hashes (hex digests) carried MAC-bound on the
            # record (see _SECURITY_PAYLOAD_FIELDS) so the approved
            # sweep can bind the upload record to the payload content
            # the human actually approved.
            "content_sha256_set": (list(action.get("content_sha256_set"))
                                   if action.get("content_sha256_set")
                                   else []),
            "agent_justification": action.get("agent_justification"),
            "provenance": provenance,
            "preview": preview,
            "delegation_attempted": delegation_attempted,
            # F101 (wave-26): a grant-verified call queues under the
            # ACTING (delegatee) identity — the grant id and the
            # delegating party (agent_id/role/principal, as verified
            # by the delegation store) ride on the record, MAC-bound
            # (see _SECURITY_PAYLOAD_FIELDS), so decide() and
            # cast_vote() can exclude the intending party alongside
            # the requester. None for non-delegated calls.
            "delegation_grant_id": delegation_grant_id,
            "delegation_delegator": (dict(delegation_delegator)
                                     if delegation_delegator else None),
            # F103 (wave-27): the full delegator lineage, root ->
            # immediate, deep-copied per hop so a caller-side mutation
            # after queue() cannot reach the MAC-bound record.
            "delegation_delegator_chain": (
                [dict(hop) for hop in delegation_delegator_chain]
                if delegation_delegator_chain else None),
            "policy_id": decision.policy_id,
            "policy_reason": decision.reason,
            "policy_flag": policy_flag,  # F21: queue reason; batch
            # approval refuses security-excluded flags individually.
            "policy_hash": policy_hash,
            # Wave-79 (totality): the governing policy version and the
            # rules that fired ride on the ticket (the executor passes
            # the queuing verdict's values), so the human's decision
            # record can name exactly what queued it. Fallbacks are the
            # honest subsystem values for tickets queued by non-engine
            # paths.
            "policy_version": policy_version or "approvals-d1",
            "matched_rules": (list(matched_rules)
                              if matched_rules is not None else []),
            # F38 (R10) / F43 (R11): the keyed digest binds the run this
            # record was queued in (the QUEUE's run_id — never a
            # caller-supplied value) and the decider (None while
            # pending — decide() re-MACs with decided_by bound). F43
            # binds the full security record: identity, preview,
            # provenance, policy_context, policy_flag,
            # delegation_attempted.
            # Wave-89 (stream s5-tool): the tool-definition digest
            # pinned at queue time and the deferred-effect details ride
            # on the record MAC-bound (see _SECURITY_PAYLOAD_FIELDS):
            # a post-queue definition swap or a stripped deferred
            # marker breaks the digest and is refused, never silently
            # re-MACed. Deep-copied so caller-side mutation after
            # queue() cannot reach the bound record.
            "tool_digest": tool_digest,
            "deferred_effect": (json.loads(json.dumps(
                deferred_effect, sort_keys=True, default=str))
                if deferred_effect is not None else None),
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
            # D1-core: delegation/quorum/bridge state. DELEGATED and
            # QUORUM_COLLECTING are SUBSTATES of pending, derived from
            # these fields — not new top-level statuses (spec §10,
            # decision 1) — so the sweep, TTL expiry, audit_status(),
            # flood/anomaly detection, the CLI, and the web list keep
            # working untouched. All six fields are MAC-bound (see
            # _SECURITY_PAYLOAD_FIELDS): absent fields bind as None,
            # exactly like §F43.
            "decision_mode": "single",   # "single" | "quorum"
            "delegated_to": None,        # current assignee principal
            "delegation_chain": [],      # append-only [{from,to,at,reason}]
            "quorum": None,              # snapshot {min_approvals,
                                        #   eligible_principals, deny_veto,
                                        #   opened_at} — see _open_quorum
            "votes": [],                 # [{vote_id, voter_principal,
                                        #   voter_identity, approve, reason,
                                        #   ts, nonce}] — final, no retraction
            "bridge_expired": False,     # T10 marker: bridge wait timed out
            "bridge_expired_at": None,
            "late_decision": False,      # T11: decided after bridge_expired
                                         # — audit-only, never executable
            # Wave-24 (D1 bridges): null bridge state on native records.
            # Explicit (not merely absent) so the web UI's read-only
            # foreign-digest/version rendering and the bridge:<id> badge
            # have a stable schema; MAC-bound as None exactly like the
            # D1 fields above (see _SECURITY_PAYLOAD_FIELDS).
            "bridge_id": None,
            "external_request_id": None,
            "bridge_request_digest": None,
            "bridge_versions": None,
        }
        # D1-core T5: when the active quorum config applies to this
        # record, snapshot it onto the record NOW and MAC it. Votes are
        # checked against the snapshot, never the live policy file.
        if self._quorum_applies(policy_flag):
            self._open_quorum(record)
        # S3 shield (wave-89): persuasion scoring + canonical packet,
        # computed by the queue from governor-held fields — never from
        # agent claims about the packet. Shared helper so queue() and
        # queue_external() stamp identically (no unstamped ingress).
        # GAP-3: the executor may pass capability_verdict (the
        # requester's capability signal); absent -> the brief reports
        # explicit "unknown".
        self._stamp_approval_integrity(
            record, preview, action.get("agent_justification"), args,
            capability_verdict=capability_verdict,
            intent_slice_verdict=intent_slice_verdict)
        # F43: the digest covers the record's security fields, computed
        # here from the stamped record itself.
        record["args_digest"] = approval_record_digest(record)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with self._append_locked():
            # F83: heal a torn tail from a crashed append BEFORE
            # writing, so the new record cannot glue onto torn bytes
            # into one unparsable line (which would fail-closed the
            # whole queue on every later read).
            self._heal_torn_tail()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=True,
                                   default=str) + "\n")
                # F83: fsync the append so a queued record is durable
                # once queue() returns — a crash may still tear the
                # final bytes of the line, which all() treats as a torn
                # append (drops exactly that line), never as
                # whole-file corruption.
                f.flush()
                # F89: tolerate EINVAL (non-syncable fd, e.g. the
                # documented /dev/null symlink residual); other
                # fsync errors still propagate loud.
                _fsync_syncable(f.fileno())
        return record["id"]

    def _quorum_applies(self, policy_flag):
        """D1-core T5: does the installed quorum config cover a record
        with this policy_flag? The section applies when present and
        valid AND (no ``flags`` list = all require_approval records, or
        the record's flag is listed)."""
        cfg = getattr(self, "_quorum_cfg", None)
        if cfg is None:
            return False
        flags = cfg.get("flags")
        if flags is None:
            return True
        return policy_flag in flags

    def _open_quorum(self, record):
        """D1-core T5: snapshot the quorum config onto a queued record.

        The snapshot — ``{min_approvals, eligible_principals,
        deny_veto, opened_at}`` — is written onto the record BEFORE its
        digest is computed, so it is MAC-bound from birth. The runtime
        eligibility check runs here: if the configured eligible set
        contains the requesting agent's ``agent_id`` or ``principal``,
        ``queue()`` raises (audited ``quorum_misconfigured``) — fail
        closed, no silent downgrade to single-decider. Lint cannot see
        the requesting agent's identity at policy-load time, so this
        runtime check (spec §10, decision 3) is the real invariant, not
        the config file.
        """
        cfg = self._quorum_cfg
        eligible = set(cfg["eligible_principals"])
        requester_ids = {record.get("agent_id"), record.get("principal")}
        clash = sorted(eligible & requester_ids)
        if clash:
            try:
                self._log({
                    "event": "quorum_misconfigured",
                    "run_id": record.get("run_id"),
                    "agent_id": record.get("agent_id"),
                    "role": record.get("role"),
                    "principal": record.get("principal"),
                    "tool": record.get("tool"),
                    "decision": "refused",
                    "policy_id": record.get("policy_id"),
                    "eligible_principals": list(
                        cfg["eligible_principals"]),
                    "requester_ids": sorted(requester_ids),
                    "reason": ("quorum refused at queue time: the eligible "
                               "set contains the requesting agent %s — the "
                               "requester can never vote on its own action "
                               "and can never be in the eligible set; fix "
                               "the policy, no silent downgrade to "
                               "single-decider" % (clash,)),
                })
            except Exception:
                pass
            raise ValueError(
                "queue() refused: approvals.quorum.eligible_principals "
                "contains the requesting agent %s — the requester can "
                "never be in the eligible set (fail-closed; audited as "
                "quorum_misconfigured)" % (clash,))
        record["decision_mode"] = "quorum"
        record["quorum"] = {
            "min_approvals": cfg["min_approvals"],
            "eligible_principals": list(cfg["eligible_principals"]),
            "deny_veto": True,
            "opened_at": _utcnow(),
        }
        try:
            self._log({
                "event": "quorum_opened",
                "run_id": record.get("run_id"),
                "agent_id": record.get("agent_id"),
                "role": record.get("role"),
                "principal": record.get("principal"),
                "tool": record.get("tool"),
                "decision": "quorum_opened",
                "policy_id": record.get("policy_id"),
                "approval_id": record.get("id"),
                "policy_flag": record.get("policy_flag"),
                "min_approvals": cfg["min_approvals"],
                "eligible_principals": list(cfg["eligible_principals"]),
                "deny_veto": True,
                "reason": ("quorum opened: %d-of-%d authenticated human "
                           "votes required; one deny vetoes (terminal)"
                           % (cfg["min_approvals"],
                              len(cfg["eligible_principals"]))),
            })
        except Exception:
            pass

    def all(self):
        """Read all queue records.

        F83 crash recovery: our writers always terminate every record
        with ``"\\n"`` and fsync. A file that does NOT end with a
        newline whose final line does not parse is a torn append from
        a crash between ``write()`` and fsync — that record was never
        durably queued, so exactly that one line is dropped (it can
        never be trusted: it has no verifiable digest). Any other
        unparsable line — including a torn-looking line in the middle
        of the file — is corruption and still raises ``ValueError``
        (fail closed), so tampering cannot hide behind the recovery.
        """
        if not self.path.exists():
            return []
        try:
            text = self.path.read_bytes().decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(
                "approval queue file is not valid UTF-8: %s" % e)
        if not text:
            return []
        lines = text.split("\n")
        # A well-formed file ends with "\n" (split leaves a trailing
        # ""). Anything else means the last line may be a torn append.
        torn_tail = True
        if lines and lines[-1] == "":
            lines.pop()
            torn_tail = False
        out = []
        last = len(lines) - 1
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                if torn_tail and i == last:
                    # Torn append: drop the single unparseable tail
                    # line; the record was never durably queued.
                    continue
                raise ValueError(
                    "approval queue file corrupt at line %d" % (i + 1))
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

        F83: the rewrite is crash-atomic (temp file + fsync +
        os.replace + directory fsync). A crash mid-rewrite leaves the
        previous complete file in place — the queue is never
        truncated, so a crash during a web/CLI decide, delegate, vote,
        or flood-flag refresh cannot destroy pending approvals.
        """
        if callable(fn_or_records):
            records = fn_or_records(self.all())
        else:
            records = fn_or_records
        _atomic_write_text(
            self.path,
            [json.dumps(r, ensure_ascii=True, default=str) + "\n"
             for r in records])

    def decide(self, approval_id, approved, reason,
               decided_by="human-operator", shield_ack=None,
               challenge_answers=None, typed_scope=None):
        """Record a human decision and log it. Returns (record, log_entry).

        Rejected decision *attempts* (unknown id, self-approval, or a
        record that is no longer pending) are also appended to the audit
        log before the ValueError propagates, so abuse of the approval
        workflow itself leaves a trace.

        Wave-145 (row-11) type-to-confirm: ``typed_scope`` is the
        human's TYPED narrowed scope. It is required -- and checked
        against the record's stamped reference scope with
        ``gov.target_match.typed_scope_similarity`` (synonym-aware
        token-tversky, wave-147) at >= DEFAULT_THRESHOLD --
        when APPROVING a ``goal_specificity_review`` for a vague or
        wildcard-scope goal (a bare click-approve is refused
        fail-closed with a LOUD ``approval_scope_mismatch`` event).
        Denials ignore it; every other record type ignores it
        (zero behavior change).

        F38: the pending record's keyed digest is verified BEFORE the
        decision is recorded — a record tampered with after queueing
        can never be decided (fail-closed ValueError, audit-logged);
        the decision then re-MACs the digest with the decider bound.

        GAP-3 approver shield: on capture-tier records
        (``shield_tier == "capture"`` -- persuasion tripwire, prose
        divergence, or critical risk), an *approve* additionally
        requires ``shield_ack`` equal to the record's ``packet_digest``
        (proof the approver rendered the current independent brief)
        and ``challenge_answers`` that pass the randomized shield
        challenge (proof of engagement with the governor's signals,
        not the agent's framing). Rejections never need the handshake;
        standard-tier records ignore the new arguments.
        """
        records = self.all()
        target = None
        for r in records:
            if r["id"] == approval_id:
                target = r
                break

        def _log_attempt(outcome, note, agent_id=None, role=None, tool=None):
            try:
                self._log({
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
        # D1-core T4: this guard is UNCHANGED by D1 — the spec's
        # requester-exclusion invariant (both aliases) applies at
        # queue()/delegate()/cast_vote() time (§10.3), not here.
        # Wave-49 RT17 probed extending this to the principal alias:
        # REVERTED — break_glass() legitimately calls decide() with
        # decided_by=<operator principal>, and the operator may share
        # a principal with the requester (dev-mode minted operator
        # identity; F55 provisioned session identity). The ticket (F49)
        # + session-identity (F55) authorization on the break-glass
        # path is the control there, not SoD. Keep the single-alias
        # check aligned with the documented call-site invariant.
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
        # F101 (wave-26) + F103 (wave-27): the DELEGATING party is
        # excluded too — and at depth >= 2, EVERY ancestor in the
        # delegator lineage. A grant-verified approval-gated call
        # queues under the ACTING (delegatee) identity, so the check
        # above compares the decider against the delegatee — the
        # delegators, who intended the action, must not be able to
        # approve (or reject) it by proxy, or delegation launders the
        # D1-core requester-exclusion invariant. Both aliases per
        # party, via _delegator_lineage_ids() (shared with
        # cast_vote() so the two exclusion sets cannot drift apart).
        _deleg_ids = _delegator_lineage_ids(target)
        if decided_by is not None and decided_by in _deleg_ids:
            _log_attempt(
                "rejected_attempt",
                "separation of duties: delegating agent attempted to decide "
                "an approval queued under its delegation grant",
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError(
                "separation of duties: delegator %r cannot decide approval "
                "%s (delegation must not launder the requester-exclusion "
                "invariant)" % (decided_by, approval_id))
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
        # D1-core T9: the M-of-N gate cannot be bypassed by the
        # single-decider path. A quorum-collecting record is decided
        # ONLY by cast_vote()'s internal finalize (T7/T8) — decide()
        # always refuses, audited as decision_refused
        # (quorum_direct_decide). There is no downgrade path from
        # quorum to single: flipping decision_mode in the JSONL breaks
        # the MAC, so the tamper check above fires instead.
        if target.get("decision_mode") == "quorum":
            try:
                self._log({
                    "event": "decision_refused",
                    "run_id": target.get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": target.get("tool"),
                    "decision": "refused",
                    "policy_id": target.get("policy_id"),
                    "approval_id": approval_id,
                    "decided_by": decided_by,
                    "related_agent": target.get("agent_id"),
                    "reason": ("quorum_direct_decide: record %s is "
                               "quorum-collecting (M-of-N vote gate); "
                               "decide() cannot bypass it — cast votes "
                               "with cast_vote()" % approval_id),
                })
            except Exception:
                pass
            raise ValueError(
                "decision refused (quorum_direct_decide): approval %r "
                "requires M-of-N human votes; the single-decider path "
                "cannot decide quorum records" % approval_id)
        # D1-core T3: a delegated record may be decided ONLY by its
        # current assignee — exact principal match. No one else,
        # including the original operator, may decide it.
        assignee = target.get("delegated_to")
        if assignee is not None and decided_by != assignee:
            _log_attempt(
                "rejected_attempt",
                "delegated record: decided_by %r is not the current "
                "assignee %r — only the assignee may decide"
                % (decided_by, assignee),
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError(
                "decision refused: approval %r is delegated to %r; only "
                "the assignee may decide it" % (approval_id, assignee))
        # S3 shield (wave-89): packet re-verification (WYSINWYS). The
        # packet is a pure function of the stored record, so any drift
        # between what the human saw at queue time and what is decided
        # now — rewritten preview, deflated persuasion score, swapped
        # risk snapshot — breaks the digest. Fail closed, audited.
        if not _packet_digest_ok(target):
            try:
                self._log({
                    "event": "approval_integrity_violation",
                    "run_id": target.get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": target.get("tool"),
                    "decision": "refused",
                    "policy_id": target.get("policy_id"),
                    "approval_id": approval_id,
                    "decided_by": decided_by,
                    "related_agent": target.get("agent_id"),
                    "reason": ("packet digest mismatch: the displayed "
                               "decision packet drifted between queue "
                               "and decide — decision refused"),
                })
            except Exception:
                pass
            _log_attempt(
                "rejected_attempt",
                "decision refused: the decision packet failed "
                "re-verification (tampered after display)",
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError(
                "approval %r failed packet re-verification: the displayed "
                "packet was tampered with after queueing — decision "
                "refused" % approval_id)
        # GAP-3 approver shield: capture-tier approves require the
        # shield handshake. The ack must equal the packet digest
        # verified above, so a stale or foreign brief cannot satisfy
        # it; the challenge then proves engagement with the
        # governor-computed signals rather than the agent's framing.
        # Rejections skip the handshake (refusing is the safe
        # direction, like every existing gate); standard-tier records
        # are untouched. The handshake itself runs below, AFTER the
        # cooling-off gate (spec: "pause first, then handshake").
        # Audited; the record stays pending.
        _shield_detail = "standard tier: no handshake required"
        if _approver_shield.is_capture_tier(target):
            _shield_detail = ("capture tier: rejection needs no handshake "
                              "(safe direction)")
        if approved:
            # S3 shield (wave-89): cooling-off. A critical-tier approve
            # before the pause elapses is refused — the persuasion
            # laundering shape needs the approver deciding in the same
            # breath as the framing. Rejections are the safe direction
            # and always pass. Audited; the record stays pending.
            _cool_until = self._parse_ts(target.get("cooling_off_until"))
            if _cool_until is not None:
                _now = datetime.now(timezone.utc)
                if _now < _cool_until:
                    try:
                        self._log({
                            "event": "approval_cooling_off",
                            "run_id": target.get("run_id"),
                            "agent_id": "human-operator",
                            "role": "approver",
                            "principal": "human-operator",
                            "tool": target.get("tool"),
                            "decision": "refused",
                            "policy_id": target.get("policy_id"),
                            "approval_id": approval_id,
                            "decided_by": decided_by,
                            "related_agent": target.get("agent_id"),
                            "cooling_off_until":
                                target.get("cooling_off_until"),
                            "reason": ("cooling-off: critical-tier item "
                                       "cannot be approved until %s"
                                       % target.get("cooling_off_until")),
                        })
                    except Exception:
                        pass
                    _log_attempt(
                        "rejected_attempt",
                        "decision refused: cooling-off pause has not "
                        "elapsed for this critical-tier item",
                        agent_id=target.get("agent_id"),
                        role=target.get("role"),
                        tool=target.get("tool"))
                    raise ValueError(
                        "decision refused (cooling_off): approval %r is "
                        "critical-tier and cannot be approved until %s"
                        % (approval_id, target.get("cooling_off_until")))
            # GAP-3 approver shield: capture-tier approves require the
            # shield handshake, AFTER the cooling-off pause (spec:
            # "pause first, then handshake"). The ack must equal the
            # packet digest verified above, so a stale or foreign brief
            # cannot satisfy it; the challenge then proves engagement
            # with the governor-computed signals rather than the
            # agent's framing. Audited; the record stays pending.
            if _approver_shield.is_capture_tier(target):
                if not _approver_shield.shield_ack_ok(target, shield_ack):
                    _shield_detail = (
                        "shield_ack missing or stale: the approver must "
                        "render the current independent brief (ack must "
                        "equal the packet digest)")
                    _log_attempt(
                        "rejected_attempt",
                        "approval_shield_ack_refused: decision refused "
                        "(shield_ack): capture-tier approval requires proof "
                        "the approver viewed the current independent brief",
                        agent_id=target.get("agent_id"),
                        role=target.get("role"), tool=target.get("tool"))
                    raise ValueError(
                        "decision refused (shield_ack): approval %r is "
                        "capture-tier (persuasion/divergence/critical risk); "
                        "approving requires shield_ack equal to the packet "
                        "digest -- render the shield brief first"
                        % (approval_id,))
                _challenge_ok, _challenge_detail = \
                    _approver_shield.grade_challenge(
                        target, challenge_answers,
                        packet=target.get("canonical_packet"))
                if not _challenge_ok:
                    _shield_detail = _challenge_detail
                    _log_attempt(
                        "rejected_attempt",
                        "approval_shield_challenge_failed: decision refused "
                        "(shield_challenge): %s" % _challenge_detail,
                        agent_id=target.get("agent_id"),
                        role=target.get("role"), tool=target.get("tool"))
                    raise ValueError(
                        "decision refused (shield_challenge): approval %r: %s"
                        % (approval_id, _challenge_detail))
                _shield_detail = _challenge_detail
            # S3 shield (wave-89): fatigue escalation. A principal past
            # the decision-velocity threshold cannot solo-approve a
            # high-risk item — a DIFFERENT approver must decide it. This
            # is the enforced form of the F4 advisory signal: the
            # flood-then-smuggle shape dies here instead of getting a
            # risk bump. Audited; the record stays pending.
            if (self.risk(target) >= FATIGUE_ESCALATION_MIN_SCORE
                    and self._principal_fatigued(decided_by)):
                try:
                    self._log({
                        "event": "approval_fatigue_escalation",
                        "run_id": target.get("run_id"),
                        "agent_id": "human-operator",
                        "role": "approver",
                        "principal": "human-operator",
                        "tool": target.get("tool"),
                        "decision": "refused",
                        "policy_id": target.get("policy_id"),
                        "approval_id": approval_id,
                        "decided_by": decided_by,
                        "related_agent": target.get("agent_id"),
                        "reason": ("fatigue escalation: principal %r is "
                                   "past the decision-velocity threshold "
                                   "(%d approves in %ds); this high-risk "
                                   "item requires a different approver"
                                   % (decided_by,
                                      FATIGUE_DECISION_THRESHOLD,
                                      FATIGUE_WINDOW_SEC)),
                    })
                except Exception:
                    pass
                _log_attempt(
                    "rejected_attempt",
                    "decision refused: fatigued principal must escalate "
                    "this high-risk item to a different approver",
                    agent_id=target.get("agent_id"),
                    role=target.get("role"),
                    tool=target.get("tool"))
                raise ValueError(
                    "decision refused (fatigue_escalation): approver %r "
                    "is past the decision-velocity threshold; approval "
                    "%r requires a different approver"
                    % (decided_by, approval_id))
            # Wave-145 (row-11): type-to-confirm for vague/wildcard goals.
            # A goal_specificity_review adjudicates a goal held in
            # pending_specificity (vague or wildcard scope) -- a bare
            # click-approve is too cheap for a careless human. The
            # approver must TYPE the narrowed scope, and the typed text
            # must match the goal's declared scope (stamped MAC-bound on
            # the record at queue time, so the check runs against exactly
            # what the review displayed) at token-tversky >=
            # DEFAULT_THRESHOLD. Missing/blank/mismatched typed scope ->
            # the decision is REFUSED (fail-closed, ValueError, record
            # stays pending) with a LOUD approval_scope_mismatch event.
            # Denials skip the ceremony (rejection is the safe direction,
            # GAP-3 precedent); records without the stamp are decided
            # exactly as before (zero behavior change).
            _ttc_reference = _type_to_confirm_reference(target)
            if _ttc_reference is not None:
                _ttc_ok, _ttc_score, _ttc_detail = _type_to_confirm_ok(
                    _ttc_reference, typed_scope)
                if not _ttc_ok:
                    try:
                        self._log({
                            "event": "approval_scope_mismatch",
                            "flag": "approval_scope_mismatch",
                            "run_id": target.get("run_id"),
                            "agent_id": "human-operator",
                            "role": "approver",
                            "principal": "human-operator",
                            "tool": target["tool"],
                            "decision": "refused",
                            "policy_id": target.get("policy_id"),
                            "approval_id": approval_id,
                            "decided_by": decided_by,
                            "related_agent": target.get("agent_id"),
                            "typed_scope": (typed_scope
                                            if isinstance(typed_scope, str)
                                            else None),
                            "match_score": _ttc_score,
                            "match_threshold": DEFAULT_THRESHOLD,
                            "match_method": TTC_MATCH_METHOD,
                            "goal_id": (target.get("args") or {}).get(
                                "goal_id"),
                            "reason": ("type_to_confirm: %s" % _ttc_detail),
                        })
                    except Exception:
                        pass
                    _log_attempt(
                        "rejected_attempt",
                        "decision refused (type_to_confirm): %s" % _ttc_detail,
                        agent_id=target.get("agent_id"),
                        role=target.get("role"), tool=target.get("tool"))
                    raise ValueError(
                        "decision refused (type_to_confirm): approval %r "
                        "adjudicates a vague/wildcard goal: %s"
                        % (approval_id, _ttc_detail))
                # The ceremony passed: the typed scope rides the record
                # (bound into the re-MAC below) and the decision event, so
                # the audit trail shows what the human claimed to approve.
                target["typed_scope"] = typed_scope
                target["typed_scope_score"] = _ttc_score
                target["typed_scope_method"] = TTC_MATCH_METHOD
        target["status"] = "approved" if approved else "rejected"
        target["decided_by"] = decided_by
        target["decided_at"] = _utcnow()
        target["decision_reason"] = reason
        # D1-core T11: a decision recorded after the bridge wait expired
        # is labeled audit-only HERE and bound into the re-MAC below.
        # It can never execute (T12 sweep refusal keys off
        # bridge_expired, not this flag — flipping late_decision in the
        # JSONL changes nothing executable, and the MAC still binds it
        # for forensics).
        late = bool(target.get("bridge_expired"))
        target["late_decision"] = late
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
        entry = self._log({
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
            # Wave-79 (totality): the human's outcome names the rule
            # that queued the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target["id"],
            "reason": reason,
            "decided_by": decided_by,
            "related_agent": target["agent_id"],
            # S3 shield (wave-89): "what the human saw" rides the
            # decision record — the packet digest binds the displayed
            # decision basis, and the persuasion/divergence signals
            # name what the approver was shown about manipulation.
            "packet_digest": target.get("packet_digest"),
            "persuasion_score": target.get("persuasion_score"),
            "prose_divergence": target.get("prose_divergence"),
            # GAP-3 approver shield: the tier and the handshake outcome
            # ride the decision record -- the evidence trail shows not
            # just what was approved but whether the approver engaged
            # with the independent signals.
            "shield_tier": target.get("shield_tier"),
            "shield_handshake": _shield_detail,
            # Wave-145 (row-11): the human's typed narrowed scope, when
            # the type-to-confirm ceremony ran for this approval (None
            # on every other record -- additive, zero behavior change
            # elsewhere). The goal-resolution events carry the
            # approval id back, so the trail cross-references both
            # ways.
            "typed_scope": target.get("typed_scope"),
            "typed_scope_score": target.get("typed_scope_score"),
            "typed_scope_method": target.get("typed_scope_method"),
            # Wave-134 (row-11): a goal_conflict_review decision names
            # the goals it adjudicates (None for every other record
            # type). The goal-resolution events carry the approval id
            # back, so the audit trail cross-references both ways.
            "goal_ids": _goal_review_goal_ids(target),
        })
        # D1-core T11: the late decision is a second, distinct audit
        # entry — the decision above is recorded, but this entry marks
        # it audit-only. Execution refusal keys off bridge_expired
        # (T12), so this entry is the forensic label, not the gate.
        if late:
            self._log({
                "event": "approval_late_decision",
                "run_id": target.get("run_id"),
                "agent_id": "human-operator",
                "role": "approver",
                "principal": "human-operator",
                "tool": target["tool"],
                "decision": "approved" if approved else "rejected",
                "policy_id": target["policy_id"],
                "approval_id": target["id"],
                "decided_by": decided_by,
                "related_agent": target["agent_id"],
                "bridge_expired_at": target.get("bridge_expired_at"),
                "reason": ("late decision on a bridge_expired record: "
                           "recorded and audited but NEVER executable — "
                           "the bridge wait timed out first (T11/T12)"),
            })
        # Wave-134 (row-11): executor-installed post-decision hook
        # (e.g. goal_conflict_review -> goal resolution). Fires after
        # the decision is recorded and audited. A raising hook is
        # audited LOUD and swallowed — the decision stands; the hook
        # is automation on top of the decision, never a veto on it.
        _hook = self._decision_hook
        if _hook is not None:
            try:
                _hook(target, approved, reason, decided_by, entry)
            except Exception as _hook_err:  # noqa: BLE001 - hook must not break decide()
                try:
                    self._log({
                        "event": "decision_hook_failed",
                        "flag": "decision_hook_failed",
                        "run_id": target.get("run_id"),
                        "agent_id": "human-operator",
                        "role": "approver",
                        "principal": "human-operator",
                        "tool": target.get("tool"),
                        "approval_id": target.get("id"),
                        "decided_by": decided_by,
                        "reason": ("post-decision hook raised %s: %s -- "
                                   "the decision stands; the hook's "
                                   "automation did not run"
                                   % (type(_hook_err).__name__,
                                      _hook_err)),
                    })
                except Exception:
                    pass
        return target, entry

    def revoke(self, approval_id, reason, revoker):
        """Wave-131 (row-7 revoke-after-approve): revoke an approval so
        it can never be consumed.

        Only the granting principal (``record["decided_by"]``) or the
        reserved ``"intent-system"`` principal (the executor's automatic
        intent re-validation) may revoke; everyone else is refused and
        the attempt is audited LOUD. Revocation is terminal: the record
        can never be decided, executed, or re-revoked afterwards.

        Delegates to ``gov.revoke.revoke_approval`` (the shared
        authorization rule also used by the executor's
        execution-boundary intent re-validation).
        """
        from . import revoke as _revoke
        return _revoke.revoke_approval(self, approval_id, reason, revoker)

    def delegate(self, approval_id, to_principal, reason, delegated_by):
        """D1-core: reassign a pending record's decision stewardship.

        On a single-decider record this transfers DECISION power (T1/T2):
        afterwards only ``to_principal`` may decide it (T3 exact-match
        guard). On a quorum-collecting record it transfers one VOTE SLOT
        (T13): the delegatee takes the delegator's place in the
        snapshotted eligible set; M is unchanged.

        Guards (all fail-closed, audited as ``delegation_refused``):

        * the record is pending (``not_pending``);
        * ``approvals.delegation.enabled`` is true (``delegation_disabled``);
        * the pending digest verifies BEFORE any mutation — a tampered
          ``delegated_to``/chain/quorum/votes record is never re-MACed
          (``tamper``; the F38 pattern);
        * the delegatee is never the requesting agent — exact match on
          BOTH ``agent_id`` and ``principal`` (``requester_target``);
        * no self-delegation (``self_delegation``) and no chain loop
          (``delegation_loop``);
        * ``len(chain) + 1 <= max_hops`` (``max_hops_exceeded``);
        * when a PrincipalRegistry is configured, the delegatee is
          registry-known (``unregistered_delegatee``);
        * for single-decider records, ``delegated_by`` is exactly the
          current assignee (``delegated_to``, or the default operator
          label when unassigned) — ``wrong_delegator``;
        * for quorum records, ``delegated_by`` holds an uncast vote slot
          (``wrong_delegator`` / ``vote_already_cast``).

        Refusals never mutate the record (no hop appended, no re-MAC,
        ``delegated_to`` unchanged). Success appends one chain hop,
        sets ``delegated_to`` (single-decider) or swaps the vote slot
        (quorum), re-MACs, and audits ``approval_delegated``.
        """
        records = self.all()
        target = None
        for r in records:
            if r["id"] == approval_id:
                target = r
                break

        def _refuse(code, note):
            try:
                self._log({
                    "event": "delegation_refused",
                    "run_id": (target or {}).get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": (target or {}).get("tool"),
                    "decision": "refused",
                    "policy_id": (target or {}).get("policy_id"),
                    "approval_id": approval_id,
                    "delegated_by": delegated_by,
                    "delegated_to": (to_principal
                                     if isinstance(to_principal, str)
                                     else str(to_principal)),
                    "refusal_code": code,
                    "related_agent": (target or {}).get("agent_id"),
                    "reason": note,
                })
            except Exception:
                # The refusal stands regardless; a logging outage must
                # not turn a refusal into a delegation.
                pass
            raise ValueError("delegation refused (%s): %s" % (code, note))

        if target is None:
            _refuse("not_pending",
                    "delegation attempted on unknown approval id %r"
                    % (approval_id,))
        if target.get("status") != "pending":
            _refuse("not_pending",
                    "delegation attempted on %s approval %r"
                    % (target.get("status"), approval_id))
        if not reason or not str(reason).strip():
            _refuse("empty_reason",
                    "a delegation reason is required (non-empty)")
        if (not isinstance(to_principal, str) or not to_principal.strip()):
            _refuse("invalid_target",
                    "delegatee principal must be a non-empty string")
        # F38 pattern FIRST: verify the pending digest BEFORE any
        # mutation. A tampered delegated_to/chain/quorum/votes record is
        # refused here — the tamper can never be laundered by the
        # delegation's own re-MAC.
        if not _pending_record_content_ok(target):
            _refuse("tamper",
                    "the pending record failed integrity verification "
                    "(tampered after queueing); re-MAC refused")
        cfg = getattr(self, "_delegation_cfg", None) or {}
        if not cfg.get("enabled"):
            _refuse("delegation_disabled",
                    "approvals.delegation.enabled is not true — "
                    "delegation is opt-in (fail closed)")
        # D1-core §3.3: NEVER back to the requesting agent. Exact match
        # on BOTH agent_id and principal: deployments may mint agent
        # identities whose principal string equals the agent id, so
        # checking only one leaves the alias shape open.
        requester_ids = {target.get("agent_id"), target.get("principal")}
        if to_principal in requester_ids:
            _refuse("requester_target",
                    "delegatee %r is the requesting agent "
                    "(agent_id/principal exact match) — stewardship can "
                    "never route back to the agent that queued the action"
                    % (to_principal,))
        if to_principal == delegated_by:
            _refuse("self_delegation",
                    "cannot delegate to yourself — a self-hop would "
                    "launder the chain, so it is refused, not silently "
                    "accepted")
        chain = target.get("delegation_chain") or []
        seen = set()
        for hop in chain:
            if isinstance(hop, dict):
                if hop.get("from"):
                    seen.add(hop["from"])
                if hop.get("to"):
                    seen.add(hop["to"])
        if to_principal in seen:
            _refuse("delegation_loop",
                    "delegatee %r already appears in the delegation "
                    "chain — loops are refused" % (to_principal,))
        max_hops = cfg.get("max_hops", DELEGATION_DEFAULT_MAX_HOPS)
        if len(chain) + 1 > max_hops:
            _refuse("max_hops_exceeded",
                    "delegation chain would exceed max_hops=%d "
                    "(chains beyond one hop launder responsibility)"
                    % (max_hops,))
        # D1-core §11 Q4: when a PrincipalRegistry is configured, the
        # delegatee must be registry-known.
        if (getattr(self, "_registry_configured", False)
                and not self._delegatee_registered(to_principal)):
            _refuse("unregistered_delegatee",
                    "delegatee %r is not registered with this "
                    "deployment's PrincipalRegistry" % (to_principal,))
        if target.get("decision_mode") == "quorum":
            return self._delegate_vote_slot(
                target, to_principal, str(reason).strip(), delegated_by,
                _refuse, max_hops)
        # T1/T2: single-decider delegation — delegation authority is
        # exactly co-extensive with decision authority. The current
        # assignee is delegated_to once delegated; on an unassigned
        # record it is the human-operator trust root, reachable via
        # either the CLI or the web label.
        current_assignee = target.get("delegated_to")
        if current_assignee is None:
            if delegated_by not in DEFAULT_ASSIGNEE_LABELS:
                _refuse("wrong_delegator",
                        "delegated_by %r is not the current assignee — "
                        "on an unassigned record only the human-operator "
                        "trust root (%s) may delegate"
                        % (delegated_by,
                           "/".join(sorted(DEFAULT_ASSIGNEE_LABELS))))
        elif delegated_by != current_assignee:
            _refuse("wrong_delegator",
                    "delegated_by %r is not the current assignee %r — "
                    "only the assignee may delegate"
                    % (delegated_by, current_assignee))
        hop_no = len(chain) + 1
        target["delegation_chain"] = chain + [{
            "from": delegated_by,
            "to": to_principal,
            "at": _utcnow(),
            "reason": str(reason).strip(),
        }]
        target["delegated_to"] = to_principal
        target["args_digest"] = approval_record_digest(target)
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])
        entry = self._log({
            "event": "approval_delegated",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "decision": "delegated",
            "policy_id": target.get("policy_id"),
            # Wave-79 (totality): the outcome names the rule that queued
            # the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target.get("id"),
            "delegated_by": delegated_by,
            "delegated_to": to_principal,
            "hop": hop_no,
            "max_hops": max_hops,
            "transfer": "decision",
            "related_agent": target.get("agent_id"),
            "reason": str(reason).strip(),
        })
        return target, entry

    def _delegate_vote_slot(self, target, to_principal, reason,
                            delegated_by, _refuse, max_hops):
        """D1-core T13: delegate one VOTE SLOT on a quorum record.

        The delegatee takes the delegator's place in the record's
        ``quorum.eligible_principals`` SNAPSHOT; ``min_approvals`` is
        unchanged. The delegator must hold an uncast vote slot — a
        delegator who already voted cannot delegate (their vote stands;
        votes are final). All delegate() guards (d)-(h) — requester,
        self, loop, hops, registry, tamper — were already checked by
        the caller. Re-MACs after the swap; audits ``approval_delegated``
        with ``transfer="vote_slot"``.
        """
        quorum = target.get("quorum") or {}
        eligible = list(quorum.get("eligible_principals") or [])
        votes = target.get("votes") or []
        voted = {v.get("voter_principal") for v in votes
                 if isinstance(v, dict)}
        if delegated_by not in eligible:
            _refuse("wrong_delegator",
                    "delegator %r holds no vote slot on this quorum "
                    "record (not in the snapshotted eligible set)"
                    % (delegated_by,))
        if delegated_by in voted:
            _refuse("vote_already_cast",
                    "delegator %r already voted — votes are final and "
                    "cannot be delegated away; the vote stands"
                    % (delegated_by,))
        chain = target.get("delegation_chain") or []
        hop_no = len(chain) + 1
        target["quorum"] = dict(
            quorum,
            eligible_principals=([p for p in eligible
                                  if p != delegated_by]
                                 + [to_principal]))
        target["delegation_chain"] = chain + [{
            "from": delegated_by,
            "to": to_principal,
            "at": _utcnow(),
            "reason": reason,
            "transfer": "vote_slot",
        }]
        target["args_digest"] = approval_record_digest(target)
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])
        entry = self._log({
            "event": "approval_delegated",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "decision": "delegated",
            "policy_id": target.get("policy_id"),
            # Wave-79 (totality): the outcome names the rule that queued
            # the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target.get("id"),
            "delegated_by": delegated_by,
            "delegated_to": to_principal,
            "hop": hop_no,
            "max_hops": max_hops,
            "transfer": "vote_slot",
            "min_approvals": quorum.get("min_approvals"),
            "related_agent": target.get("agent_id"),
            "reason": reason,
        })
        return target, entry

    def cast_vote(self, approval_id, approve, reason, voter_identity):
        """D1-core T6/T7/T8: cast one authenticated human vote on a
        quorum-collecting record.

        ``voter_identity`` must be an ``AgentIdentity`` (F26 pattern —
        bare principal strings raise TypeError); when the executor
        installed an identity verifier, the identity must pass it
        (minted by this deployment). The vote row stores
        ``voter_principal`` (the eligibility key, compared against the
        snapshotted ``eligible_principals``), the full
        ``voter_identity.as_dict()`` for forensics, ``approve``,
        ``reason`` (non-empty), ``ts``, a fresh ``nonce``, and
        ``vote_id = sha256(record_id + voter_principal + nonce)``.

        Guards (fail-closed, audited as ``quorum_vote_refused``): the
        record is quorum-collecting (pending + ``decision_mode ==
        "quorum"`` — anything else is ``already_finalized`` /
        ``not_quorum``); the pending digest verifies (``tamper``); the
        voter is in the SNAPSHOT's eligible set (``not_eligible``) —
        never the live policy; the voter is not the requesting agent
        (``requester_vote`` — checked on both ``voter_principal`` and
        ``agent_id`` against both record fields); one vote per
        principal (``duplicate_vote`` — votes are final).

        A deny vote finalizes the record as rejected IMMEDIATELY (T7 —
        the one-deny veto is terminal and non-negotiable); the M-th
        approval finalizes it as approved (T8). Finalize re-MACs with
        ``decided_by="quorum:<M>-of-<N>"`` / ``"quorum/veto:<voter>"``
        and audits ``quorum_finalized`` + ``approval_decision``.

        Returns (record, entry): ``entry`` is the ``quorum_vote`` entry,
        or the ``approval_decision`` entry when this vote finalized the
        record.
        """
        if not isinstance(voter_identity, AgentIdentity):
            raise TypeError(
                "cast_vote() requires an AgentIdentity minted by the "
                "executor (got %s); caller-supplied principal strings "
                "are not accepted" % type(voter_identity).__name__)
        # F26: authenticate the voter — isinstance above, plus the
        # executor's minted-identity check when installed.
        voter = self._authenticate_caller(voter_identity, "cast_vote")
        voter_principal = voter.principal

        records = self.all()
        target = None
        for r in records:
            if r["id"] == approval_id:
                target = r
                break

        def _refuse(code, note):
            try:
                self._log({
                    "event": "quorum_vote_refused",
                    "run_id": (target or {}).get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": (target or {}).get("tool"),
                    "decision": "refused",
                    "policy_id": (target or {}).get("policy_id"),
                    "approval_id": approval_id,
                    "voter_principal": voter_principal,
                    "voter_agent_id": voter.agent_id,
                    "refusal_code": code,
                    "related_agent": (target or {}).get("agent_id"),
                    "reason": note,
                })
            except Exception:
                # The refusal stands regardless; a logging outage must
                # not turn a refusal into a vote.
                pass
            raise ValueError("quorum vote refused (%s): %s" % (code, note))

        if target is None:
            _refuse("unknown_approval",
                    "vote attempted on unknown approval id %r"
                    % (approval_id,))
        if target.get("status") != "pending":
            _refuse("already_finalized",
                    "vote attempted on %s approval %r — the record is "
                    "decided; votes cannot be replayed into it"
                    % (target.get("status"), approval_id))
        if target.get("decision_mode") != "quorum":
            _refuse("not_quorum",
                    "approval %r is not quorum-collecting "
                    "(decision_mode=%r) — vote with decide()"
                    % (approval_id, target.get("decision_mode")))
        # F38 pattern: verify the pending digest BEFORE appending the
        # vote — a forged vote row (flipped approve flag, deleted deny)
        # is refused here and can never reach finalize/execution.
        if not _pending_record_content_ok(target):
            _refuse("tamper",
                    "the pending record failed integrity verification "
                    "(vote row or quorum config tampered after "
                    "queueing); vote refused, re-MAC refused")
        quorum = target.get("quorum")
        if not isinstance(quorum, dict):
            _refuse("tamper",
                    "quorum snapshot missing or malformed on a "
                    "quorum-mode record")
        eligible = list(quorum.get("eligible_principals") or [])
        min_approvals = quorum.get("min_approvals")
        if voter_principal not in eligible:
            _refuse("not_eligible",
                    "voter %r is not in the record's snapshotted "
                    "eligible set %s — the snapshot is the authority, "
                    "never the live policy"
                    % (voter_principal, eligible))
        # D1-core §4.2 / §10 decision 3: the requesting agent is
        # excluded TWICE — at queue() time (T5) and here (defense in
        # depth against a record hand-built before the queue-time check
        # existed). Both voter_principal and agent_id are checked
        # against both record fields (the alias shape).
        requester_ids = {target.get("agent_id"), target.get("principal")}
        # F101 (wave-26) + F103 (wave-27): the delegating party is
        # excluded from voting too — and at depth >= 2, EVERY ancestor
        # in the delegator lineage. The same laundering shape as
        # decide(): a grant-verified call queues under the delegatee,
        # so no intending party may vote its own intended action
        # through quorum either. _delegator_lineage_ids() is shared
        # with decide() so the two exclusion sets cannot drift apart.
        requester_ids |= _delegator_lineage_ids(target)
        requester_ids.discard(None)
        if (voter_principal in requester_ids
                or voter.agent_id in requester_ids):
            _refuse("requester_vote",
                    "the requesting agent (agent_id/principal exact "
                    "match) can never vote on its own action")
        votes = target.get("votes") or []
        if any(isinstance(v, dict)
               and v.get("voter_principal") == voter_principal
               for v in votes):
            _refuse("duplicate_vote",
                    "voter %r already cast a vote on this record — "
                    "votes are final (no retraction, no change); a "
                    "re-POSTed vote form is refused here"
                    % (voter_principal,))
        if not reason or not str(reason).strip():
            _refuse("empty_reason",
                    "a vote reason is required (non-empty)")
        nonce = secrets.token_hex(8)
        vote = {
            "vote_id": sha256(
                ("%s|%s|%s" % (target["id"], voter_principal, nonce))
                .encode("utf-8")).hexdigest(),
            "voter_principal": voter_principal,
            "voter_identity": voter.as_dict(),
            "approve": bool(approve),
            "reason": str(reason).strip(),
            "ts": _utcnow(),
            "nonce": nonce,
        }
        votes = votes + [vote]
        target["votes"] = votes
        target["args_digest"] = approval_record_digest(target)
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])
        tally_approve = sum(1 for v in votes if v.get("approve"))
        vote_entry = self._log({
            "event": "quorum_vote",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "decision": "approved" if approve else "denied",
            "policy_id": target.get("policy_id"),
            # Wave-79 (totality): the outcome names the rule that queued
            # the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target.get("id"),
            "voter_principal": voter_principal,
            "voter_identity": voter.as_dict(),
            "vote_id": vote["vote_id"],
            "tally": "%d-of-%d" % (tally_approve, min_approvals),
            "related_agent": target.get("agent_id"),
            "reason": str(reason).strip(),
        })
        # D1-core §4.3: the one-deny veto is terminal. A deny finalizes
        # the record as rejected IMMEDIATELY (T7) — no veto override,
        # no re-open, no retraction. Approval finalize on the M-th
        # approval (T8).
        if not approve:
            return self._finalize_quorum_veto(target, vote)
        if tally_approve >= min_approvals:
            return self._finalize_quorum_approved(
                target, votes, min_approvals, len(eligible))
        return target, vote_entry

    def _finalize_quorum_veto(self, target, vote):
        """D1-core T7: terminal deny-veto finalize.

        ``decided_by="quorum/veto:<voter_principal>"`` — a
        human-operator label (never an agent id), forensically distinct
        from CLI/web single decisions. Re-MACs with the veto bound;
        audits ``quorum_finalized`` (veto) + ``approval_decision``
        (rejected). No further votes are accepted afterwards
        (``already_finalized``).
        """
        target["status"] = "rejected"
        target["decided_by"] = "quorum/veto:%s" % vote["voter_principal"]
        target["decided_at"] = _utcnow()
        target["decision_reason"] = (
            "DENY veto by %s: %s (one-deny veto is terminal; no "
            "override, no re-open)" % (vote["voter_principal"],
                                       vote["reason"]))
        target["args_digest"] = approval_record_digest(target)
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])
        self._log({
            "event": "quorum_finalized",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "decision": "rejected",
            "policy_id": target.get("policy_id"),
            # Wave-79 (totality): the outcome names the rule that queued
            # the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target.get("id"),
            "finalize": "deny_veto",
            "veto_voter": vote["voter_principal"],
            "decided_by": target["decided_by"],
            "related_agent": target.get("agent_id"),
            "reason": ("deny veto by %s: dissent is terminal — the "
                       "record is rejected immediately" %
                       vote["voter_principal"]),
        })
        entry = self._log({
            "event": "approval_decision",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "args": target["args"],
            "redactions_applied": target.get("redactions_applied", []),
            "provenance": target.get("provenance", "agent_direct"),
            "preview": target.get("preview", ""),
            "policy_hash": target.get("policy_hash"),
            "decision": "rejected",
            "policy_id": target.get("policy_id"),
            # Wave-79 (totality): the outcome names the rule that queued
            # the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target.get("id"),
            "reason": target["decision_reason"],
            "decided_by": target["decided_by"],
            "related_agent": target.get("agent_id"),
        })
        return target, entry

    def _finalize_quorum_approved(self, target, votes, min_approvals,
                                  eligible_count):
        """D1-core T8: M-approvals finalize.

        ``decided_by="quorum:<M>-of-<N>"`` bound into the re-MAC; the
        ``approval_decision`` audit reason lists every voter's
        principal. Both labels are human-operator labels (never an
        agent id), so separation-of-duties semantics are unchanged.
        """
        voters = [v.get("voter_principal") for v in votes
                  if isinstance(v, dict)]
        target["status"] = "approved"
        target["decided_by"] = "quorum:%d-of-%d" % (min_approvals,
                                                   eligible_count)
        target["decided_at"] = _utcnow()
        target["decision_reason"] = (
            "quorum approved %d-of-%d by %s" % (
                min_approvals, eligible_count, ", ".join(voters)))
        target["args_digest"] = approval_record_digest(target)
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])
        self._log({
            "event": "quorum_finalized",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "decision": "approved",
            "policy_id": target.get("policy_id"),
            # Wave-79 (totality): the outcome names the rule that queued
            # the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target.get("id"),
            "finalize": "m_approvals",
            "voters": voters,
            "min_approvals": min_approvals,
            "eligible_count": eligible_count,
            "decided_by": target["decided_by"],
            "related_agent": target.get("agent_id"),
            "reason": target["decision_reason"],
        })
        entry = self._log({
            "event": "approval_decision",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "args": target["args"],
            "redactions_applied": target.get("redactions_applied", []),
            "provenance": target.get("provenance", "agent_direct"),
            "preview": target.get("preview", ""),
            "policy_hash": target.get("policy_hash"),
            "decision": "approved",
            "policy_id": target.get("policy_id"),
            # Wave-79 (totality): the outcome names the rule that queued
            # the ticket (stored, MAC-bound, at queue time).
            "policy_version": target.get("policy_version", "approvals-d1"),
            "matched_rules": target.get("matched_rules", []),
            "approval_id": target.get("id"),
            "reason": target["decision_reason"],
            "decided_by": target["decided_by"],
            "related_agent": target.get("agent_id"),
        })
        return target, entry

    def mark_bridge_expired(self, approval_id, bridge_id, reason):
        """D1-core T10 / §6: mark that a bridge's bounded wait timed out.

        Sets the MACed ``bridge_expired``/``bridge_expired_at`` fields
        (re-MACed) and audits ``bridge_wait_expired``. The record stays
        in its substate (pending, or approved-but-unexecuted — the exact
        TOCTOU window). A later human decision is permitted and fully
        audited (T11: ``late_decision=true``, ``approval_late_decision``
        event) but can NEVER execute (T12: the sweep refuses
        ``bridge_expired`` records before the TTL check).

        Fail-closed: the record's digest is verified BEFORE the marker
        is set (pending records via the pending check, decided records
        via ``approval_digest_ok``) — a tampered record is refused, not
        marked. If the record is already executed, the TOCTOU already
        resolved the other way: audit ``bridge_expired_after_execution``
        (anomaly — operator investigates) and change nothing. The marker
        cannot be cleared without the log key, and no API offers
        clearing.
        """
        records = self.all()
        target = None
        for r in records:
            if r["id"] == approval_id:
                target = r
                break
        if target is None:
            raise ValueError("approval id %r not found" % approval_id)
        if target.get("executed"):
            try:
                self._log({
                    "event": "bridge_expired_after_execution",
                    "run_id": target.get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": target.get("tool"),
                    "decision": "anomaly",
                    "policy_id": target.get("policy_id"),
                    "approval_id": approval_id,
                    "bridge_id": bridge_id,
                    "related_agent": target.get("agent_id"),
                    "reason": ("bridge wait expiry reported for an "
                               "ALREADY-EXECUTED record — the TOCTOU "
                               "resolved the other way; operator "
                               "investigates. No state changed."),
                })
            except Exception:
                pass
            return target
        # Integrity pre-check appropriate to the record's state: a
        # tampered record is refused, never marked.
        if target.get("status") == "pending":
            integrity_ok = _pending_record_content_ok(target)
        else:
            integrity_ok = approval_digest_ok(target)
        if not integrity_ok:
            try:
                self._log({
                    "event": "bridge_expired_refused",
                    "run_id": target.get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": target.get("tool"),
                    "decision": "refused",
                    "policy_id": target.get("policy_id"),
                    "approval_id": approval_id,
                    "bridge_id": bridge_id,
                    "related_agent": target.get("agent_id"),
                    "reason": ("mark_bridge_expired refused: the record "
                               "failed integrity verification (tampered "
                               "after queueing); the marker was not set"),
                })
            except Exception:
                pass
            raise ValueError(
                "mark_bridge_expired refused: approval %r failed "
                "integrity verification — marker not set" % approval_id)
        target["bridge_expired"] = True
        target["bridge_expired_at"] = _utcnow()
        target["args_digest"] = approval_record_digest(target)
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])
        entry = self._log({
            "event": "bridge_wait_expired",
            "run_id": target.get("run_id"),
            "agent_id": "human-operator",
            "role": "approver",
            "principal": "human-operator",
            "tool": target.get("tool"),
            "decision": "bridge_wait_expired",
            "policy_id": target.get("policy_id"),
            "approval_id": approval_id,
            "bridge_id": bridge_id,
            "bridge_expired_at": target["bridge_expired_at"],
            "related_agent": target.get("agent_id"),
            "reason": ("bridge wait expired: %s. The record stays %s; a "
                       "later human decision is audit-only and can never "
                       "execute (T11/T12)."
                       % (reason, target.get("status"))),
        })
        return target, entry

    # ------------------------------------------------------------------
    # Wave-24 — D1 bridge surface (A12).
    #
    # The durable queue becomes addressable from foreign runtimes
    # (Microsoft AGT, AWS AgentCore) through thin adapters in
    # gov/bridges/. This section is the ONLY new queue API the bridges
    # may call: queue_external() / wait_for_decision() / get_record()
    # (+ the D1-core mark_bridge_expired() above, which bridges own the
    # timeout call for). Nothing in the existing decision paths changes
    # shape.
    #
    # TERMINOLOGY GUARD (A12, binding): "approval delegation" is the
    # D1-core primitive — a HUMAN reassigning decision stewardship of a
    # queued record (delegate()). "Authority delegation" is the P10
    # primitive — an AGENT granting tool-call authority to another
    # agent. Bridges do NEITHER: they request a human decision and wait
    # for it. No bridge code, doc, or audit field may use "delegation"
    # for bridge behavior.
    #
    # EXECUTION OWNERSHIP: a record carrying bridge_id is
    # FOREIGN-EXECUTED — the bridge's runtime executes on its side after
    # our human decides. Our own execute_approved() sweep NEVER executes
    # bridge records (it refuses bridge_expired ones per T12 and skips
    # the rest); the record is the durable DECISION, not a work item.
    # ------------------------------------------------------------------

    # Wave-24: fail-safe ceiling for wait_for_decision(). A bounded wait
    # longer than this is a bridge design bug (the foreign runtime's
    # own timeout must be longer than OUR wait — e.g. 4 min vs AGT's
    # 5-min CallbackApproval default — and no in-process wait should
    # outlive an hour). Bridges needing longer horizons re-issue waits.
    BRIDGE_WAIT_MAX_TIMEOUT_SECS = 3600.0
    # Wave-24: file-poll cadence for wait_for_decision(). Polling (not
    # an in-process Event) is the correct primitive: the human decides
    # via the CLI or web console, usually in ANOTHER process, so only
    # the queue file is a trustworthy signal.
    BRIDGE_WAIT_POLL_SECS = 0.1

    def queue_external(self, tool, args, policy_id, agent_identity,
                       preview, bridge_id, external_request_id=None,
                       bridge_request_digest=None, bridge_versions=None,
                       agent_justification=None, egress_bytes=None,
                       intent_slice_verdict=None):
        """Wave-24 (A12): queue an approval requested by a FOREIGN runtime.

        This is the bridge ingress: a thin adapter (gov/bridges/) calls
        it when the foreign runtime pauses for a human decision. It
        returns the approval id; the bridge then calls
        wait_for_decision() and returns the human's verdict to its
        runtime, which executes on ITS side. Our executor never
        executes bridge records.

        ``tool`` / ``args`` describe the foreign action (args should
        already be redacted by the bridge — the queue cannot redact
        what it cannot parse). ``policy_id`` is the FOREIGN policy
        reference (a string, e.g. the AGT policy id); our own
        policy_hash pinning does not apply — ``policy_hash`` is None
        and the record is never sweep-executed. ``agent_identity`` is
        an executor-minted AgentIdentity (F42: authenticated exactly
        like queue()'s caller_identity; the bridge mints it in-process
        from the foreign context — foreign caller claims such as
        ``did:agentmesh:…`` are recorded VERBATIM as untrusted
        framing). ``preview`` is the bridge's executor-generated
        summary — the human sees this, never raw foreign framing
        (sanitized here per F11). ``bridge_id`` (e.g. "agt-python") is
        the web UI's future ``bridge:<id>`` badge, MAC-bound.

        ``external_request_id`` is the foreign runtime's request id
        (.NET ``ApprovalRequestId``) and the IDEMPOTENCY key: a second
        queue_external with the same key returns the EXISTING record's
        id — never a second record. The check-and-queue runs under the
        append leaf lock, so concurrent ingress cannot double-queue.
        A key claimed by a DIFFERENT bridge_id is refused fail-closed
        (audited ``bridge_idempotency_conflict``): idempotency keys are
        per-bridge namespaces.

        ``bridge_request_digest`` is the bridge-computed digest of the
        foreign request envelope (opaque string, foreign data). It is
        MAC-BOUND into the record's security payload: post-queue
        tampering breaks the digest and is refused, never silently
        re-MACed. Honest residual: the queue cannot VERIFY the digest
        against the foreign runtime (no shared secret) — the binding
        is tamper-EVIDENCE, not foreign attestation.
        ``bridge_versions`` is an optional {name: version} mapping of
        foreign action/policy/chain versions (.NET schema pinning),
        likewise MAC-bound.

        Bridge records are single-steward (no quorum snapshot): the
        foreign wait is bounded in minutes, so M-of-N collection cannot
        complete in time, and the foreign runtime owns its own
        ceremony. Human decision/delegate/vote surfaces work unchanged.
        """
        # F42 applies unchanged: authority fields come from the
        # authenticated identity, never from foreign-supplied data.
        if agent_identity is None:
            raise TypeError(
                "queue_external() requires agent_identity: an "
                "AgentIdentity minted by the executor for the calling "
                "bridge (F42); foreign-supplied identity fields are "
                "never trusted")
        if self._identity_verifier is None:
            raise ValueError(
                "queue_external() refused: no identity verifier installed "
                "on this queue — the executor installs its minted-identity "
                "check at construction (F42 fail-closed)")
        caller = self._authenticate_caller(agent_identity,
                                           "queue_external")
        if caller.run_id != self.run_id:
            raise ValueError(
                "queue_external() refused: caller identity run_id %r does "
                "not match this queue's run %r"
                % (caller.run_id, self.run_id))
        if not tool or not isinstance(tool, str):
            raise ValueError(
                "queue_external() refused: tool must be a non-empty string")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise TypeError(
                "queue_external() refused: args must be a dict, got %r"
                % type(args).__name__)
        if not policy_id or not isinstance(policy_id, str):
            raise ValueError(
                "queue_external() refused: policy_id must be a non-empty "
                "string (the foreign policy reference)")
        if (not bridge_id or not isinstance(bridge_id, str)
                or not bridge_id.strip() or len(bridge_id) > 64):
            raise ValueError(
                "queue_external() refused: bridge_id must be a non-empty "
                "string (<= 64 chars) — it is the bridge:<id> badge")
        bridge_id = bridge_id.strip()
        if external_request_id is not None:
            if (not isinstance(external_request_id, str)
                    or not external_request_id.strip()
                    or len(external_request_id) > 256):
                raise ValueError(
                    "queue_external() refused: external_request_id must be "
                    "a non-empty string (<= 256 chars) or None")
            external_request_id = external_request_id.strip()
        if bridge_request_digest is not None:
            if (not isinstance(bridge_request_digest, str)
                    or not bridge_request_digest.strip()
                    or len(bridge_request_digest) > 512):
                raise ValueError(
                    "queue_external() refused: bridge_request_digest must "
                    "be a non-empty string (<= 512 chars) or None")
            bridge_request_digest = bridge_request_digest.strip()
        if bridge_versions is not None:
            if (not isinstance(bridge_versions, dict)
                    or not all(isinstance(k, str) and isinstance(v, str)
                               for k, v in bridge_versions.items())):
                raise TypeError(
                    "queue_external() refused: bridge_versions must be a "
                    "{str: str} mapping or None")
            bridge_versions = {str(k): str(v)
                               for k, v in bridge_versions.items()}
        preview = sanitize_preview_text(preview or "")

        def _audit(event, decision, reason, approval_id=None, **extra):
            try:
                fields = {
                    "event": event,
                    "run_id": self.run_id,
                    "agent_id": caller.agent_id,
                    "role": caller.role,
                    "principal": caller.principal,
                    "tool": tool,
                    "decision": decision,
                    "policy_id": policy_id,
                    "approval_id": approval_id,
                    "bridge_id": bridge_id,
                    "external_request_id": external_request_id,
                    "related_agent": caller.agent_id,
                    "reason": reason,
                }
                fields.update(extra)
                self._log(fields)
            except Exception:
                pass

        with self._append_locked():
            # Idempotency: the foreign request id may be replayed
            # (webhook retries). The scan runs inside the append leaf
            # lock, so two concurrent ingresses with the same key
            # serialize — exactly one record is ever queued.
            if external_request_id is not None:
                for r in self.all():
                    if (r.get("external_request_id")
                            == external_request_id):
                        if r.get("bridge_id") != bridge_id:
                            _audit("bridge_idempotency_conflict",
                                   "refused",
                                   "external_request_id %r is already "
                                   "claimed by bridge %r — idempotency "
                                   "keys are per-bridge namespaces; "
                                   "refusing cross-bridge claim"
                                   % (external_request_id,
                                      r.get("bridge_id")),
                                   approval_id=r.get("id"))
                            raise ValueError(
                                "queue_external() refused "
                                "(bridge_idempotency_conflict): "
                                "external_request_id %r is already claimed "
                                "by bridge %r"
                                % (external_request_id, r.get("bridge_id")))
                        _audit("bridge_idempotency_replay", "replayed",
                               "replayed external_request_id returned the "
                               "existing record %s (status %s) — no "
                               "duplicate queued"
                               % (r.get("id"), r.get("status")),
                               approval_id=r.get("id"))
                        return r["id"]
            record = {
                "id": uuid.uuid4().hex[:8],
                "ts": _utcnow(),
                "run_id": self.run_id,
                "agent_id": caller.agent_id,
                "role": caller.role,
                "principal": caller.principal,
                "identity": caller.as_dict(),
                "tool": tool,
                "args": args,
                "redactions_applied": [],
                "agent_justification": agent_justification,
                "provenance": "bridge",
                "preview": preview,
                "delegation_attempted": False,
                "policy_id": policy_id,
                "policy_reason": ("bridge approval request via %s"
                                  % bridge_id),
                "policy_flag": None,
                # Foreign policy: our policy_hash pinning does not
                # apply — the record is never executed by our sweep.
                "policy_hash": None,
                "digest_scheme": APPROVAL_DIGEST_SCHEME,
                "egress_bytes": egress_bytes,
                "status": "pending",
                "decided_by": None,
                "decided_at": None,
                "decision_reason": None,
                "executed": False,
                "policy_context": {},
                "flood_suspect": False,
                "break_glass": False,
                "break_glass_reason": None,
                # D1 state, MAC-bound like native records. Bridge
                # records are single-steward: no quorum snapshot is
                # opened here (the foreign wait is bounded in minutes;
                # the foreign runtime owns its own ceremony).
                "decision_mode": "single",
                "delegated_to": None,
                "delegation_chain": [],
                "quorum": None,
                "votes": [],
                "bridge_expired": False,
                "bridge_expired_at": None,
                "late_decision": False,
                # The bridge badge + MAC-bound foreign data (see
                # _SECURITY_PAYLOAD_FIELDS): tampering with any of
                # these after queueing breaks the digest.
                "bridge_id": bridge_id,
                "external_request_id": external_request_id,
                "bridge_request_digest": bridge_request_digest,
                "bridge_versions": bridge_versions,
            }
            # S3 shield (wave-89): the same approval-integrity stamping
            # as queue() — foreign/bridge ingress is the highest-value
            # persuasion surface (its justification is explicitly
            # UNVERIFIED foreign prose), so it must not produce
            # unstamped records that decide() would refuse.
            self._stamp_approval_integrity(
                record, preview, agent_justification, args,
                intent_slice_verdict=intent_slice_verdict)
            record["args_digest"] = approval_record_digest(record)
            self.run_dir.mkdir(parents=True, exist_ok=True)
            # F83: heal a torn tail before appending (same discipline
            # as queue()).
            self._heal_torn_tail()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=True,
                                   default=str) + "\n")
                f.flush()
                # F89: tolerate EINVAL (non-syncable fd); see queue().
                _fsync_syncable(f.fileno())
        _audit("bridge_external_queued", "queued",
               "foreign approval request queued via bridge %s"
               % bridge_id,
               approval_id=record["id"])
        return record["id"]

    def wait_for_decision(self, approval_id, timeout_s):
        """Wave-24 (A12): bounded wait for a human decision on a bridge record.

        Returns "approved" | "rejected" | "timeout". Polls the queue
        file (the human decides via CLI/web, usually in another
        process — only the file is a trustworthy signal).

        ``timeout_s`` must be positive and within
        BRIDGE_WAIT_MAX_TIMEOUT_SECS. Bridges MUST choose a wait
        strictly shorter than the foreign runtime's own timeout (e.g.
        4 min vs AGT's 5-min CallbackApproval default) — otherwise the
        foreign runtime gives up first and our wait is pointless.

        On timeout: calls mark_bridge_expired() (the record stays
        pending; a later human decision is audit-only and NEVER
        executable — T11/T12) and returns "timeout". The CALLER
        (bridge) returns deny to its runtime on "timeout". A final
        read after the deadline closes the last-gap race: a decision
        that lands in the final poll gap is still honored.
        """
        if (isinstance(timeout_s, bool)
                or not isinstance(timeout_s, (int, float))):
            raise TypeError(
                "wait_for_decision() refused: timeout_s must be a number "
                "of seconds, got %r" % type(timeout_s).__name__)
        if not (timeout_s == timeout_s) or timeout_s in (
                float("inf"), float("-inf")):
            raise ValueError(
                "wait_for_decision() refused: timeout_s must be finite")
        if timeout_s <= 0:
            raise ValueError(
                "wait_for_decision() refused: timeout_s must be positive")
        if timeout_s > self.BRIDGE_WAIT_MAX_TIMEOUT_SECS:
            raise ValueError(
                "wait_for_decision() refused: timeout_s %s exceeds the "
                "fail-safe ceiling of %ss — bridges needing longer "
                "horizons re-issue waits"
                % (timeout_s, self.BRIDGE_WAIT_MAX_TIMEOUT_SECS))
        first = self.get(approval_id)
        if first is None:
            try:
                self._log({
                    "event": "bridge_wait_unknown_id",
                    "run_id": self.run_id,
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "refused",
                    "approval_id": approval_id,
                    "reason": ("wait_for_decision refused: unknown approval "
                               "id %r" % (approval_id,)),
                })
            except Exception:
                pass
            raise ValueError(
                "wait_for_decision() refused: unknown approval id %r"
                % (approval_id,))
        deadline = time.monotonic() + timeout_s
        while True:
            rec = self.get(approval_id)
            if rec is None:
                # The record vanished mid-wait (operator removed the
                # file, torn-tail drop). Fail-closed toward deny: audit
                # loudly, report timeout, never approve what we cannot
                # see.
                try:
                    self._log({
                        "event": "bridge_wait_record_missing",
                        "run_id": self.run_id,
                        "agent_id": "human-operator",
                        "role": "approver",
                        "principal": "human-operator",
                        "decision": "bridge_wait_record_missing",
                        "approval_id": approval_id,
                        "reason": ("bridge record vanished mid-wait; "
                                   "treating as timeout (deny direction)"),
                    })
                except Exception:
                    pass
                return "timeout"
            status = rec.get("status")
            if status == "approved":
                return "approved"
            if status == "rejected":
                return "rejected"
            now = time.monotonic()
            if now >= deadline:
                break
            time.sleep(min(self.BRIDGE_WAIT_POLL_SECS, deadline - now))
        # Last-gap race: re-read once after the deadline before
        # expiring — a decision that landed in the final poll gap is
        # still honored.
        rec = self.get(approval_id)
        if rec is not None and rec.get("status") == "approved":
            return "approved"
        if rec is not None and rec.get("status") == "rejected":
            return "rejected"
        if rec is None:
            try:
                self._log({
                    "event": "bridge_wait_record_missing",
                    "run_id": self.run_id,
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "bridge_wait_record_missing",
                    "approval_id": approval_id,
                    "reason": ("bridge record vanished at the wait "
                               "deadline; treating as timeout (deny "
                               "direction)"),
                })
            except Exception:
                pass
            return "timeout"
        # Timeout: mark the bridge wait expired (record stays pending;
        # late decisions are audit-only, never executable — T11/T12).
        # A tampered record makes mark_bridge_expired raise fail-closed
        # (loud); the bridge maps exceptions to deny.
        self.mark_bridge_expired(
            approval_id, rec.get("bridge_id"),
            "bridge wait timed out after %ss" % timeout_s)
        return "timeout"

    def get_record(self, approval_id):
        """Wave-24 (A12): read-only status view for bridges.

        Returns a DETACHED deep copy of the record (mutating the
        returned dict cannot affect the queue file) or None. Bridges
        must treat every field as informational — the decision flow
        goes through decide()/wait_for_decision(), never through
        editing this copy.
        """
        rec = self.get(approval_id)
        if rec is None:
            return None
        return json.loads(json.dumps(rec, ensure_ascii=True, default=str))

    def mark_executed(self, approval_id):
        # Wave-131 (row-7 revoke-after-approve): belt-and-braces — a
        # revoked approval can never be marked executed, even via this
        # direct durable-claim path. Revocation is terminal.
        try:
            _rec = self.get(approval_id)
        except Exception:  # noqa: BLE001 - unknown ids fail closed below
            _rec = None
        if _rec is not None and _rec.get("status") == "revoked":
            try:
                self._log({
                    "event": "approval_revoke_attempt",
                    "run_id": _rec.get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "rejected_attempt",
                    "approval_id": approval_id,
                    "note": ("mark_executed refused: approval is revoked; "
                             "revocation is terminal"),
                })
            except Exception:  # noqa: BLE001 - refusal stands regardless
                pass
            raise ValueError(
                "cannot mark approval %r executed: it is revoked"
                % (approval_id,))
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
                # F76: a None last_audit means "never audited" -- a
                # 0.0 sentinel breaks on fresh boots, where
                # time.monotonic() < 300 makes now - 0.0 < 300 True
                # and wrongly suppresses the first loud audit.
                raw_audit = cache.get("last_audit")
                last_audit = (None if raw_audit is None
                              else float(raw_audit))
                suppressed = int(cache.get("suppressed", 0))
            except (TypeError, ValueError):
                last_audit, suppressed = None, 0
        else:
            last_audit, suppressed = None, 0
        if last_audit is not None and \
                now - last_audit < \
                self._RECONCILE_MARKER_INVALID_COALESCE_SECS:
            self._write_reconcile_marker_cache(
                markers_key, error, broken_seq, last_audit,
                suppressed + 1)
            return
        self._log({
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
                self._log({
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
        auth_seq, done_seq = _marker_sets(entries)
        interrupted = {aid: s for aid, s in auth_seq.items()
                       if s > done_seq.get(aid, 0)}
        # R18 (F70): the scan above is UNTRUSTED and the incremental
        # gate below only re-checks the new segment -- a
        # length-preserving edit of marker bytes BEFORE the cached tip
        # is invisible to both, so a genuine interrupted marker could
        # be silently missed (recovery defeated with no audit). The
        # tip's MAC'd marker manifest vouches the interrupted set over
        # the verified prefix; compare the scan's prefix-scoped
        # interrupted set against it BEFORE the gate runs. A mismatch
        # is positive evidence of pre-tip marker tamper (or a planted
        # pre-tip marker): audit LOUDLY (coalesced like any standing
        # marker forgery) and discard the incremental verdict -- only
        # a full verification can authenticate the prefix now. This
        # runs under the queue lock, so no concurrent sweep can append
        # a marker between the scan and the tip read: a mismatch is
        # never a benign race.
        manifest_mismatch = False
        try:
            _pre_tip = _read_tip_cache(self.log.path)
        except OSError:
            _pre_tip = None
        if _pre_tip is not None:
            _pauth, _pdone = _marker_sets(
                e for e in entries
                if isinstance(e, dict)
                and isinstance(e.get("seq"), int)
                and e["seq"] <= _pre_tip["seq"])
            _prefix_interrupted = {
                aid: s for aid, s in _pauth.items()
                if s > _pdone.get(aid, 0)}
            if _prefix_interrupted != _pre_tip["markers"]:
                manifest_mismatch = True
                _mkey_src = {
                    "missing_from_scan": sorted(
                        set(_pre_tip["markers"]) - set(_prefix_interrupted)),
                    "extra_in_scan": sorted(
                        set(_prefix_interrupted) - set(_pre_tip["markers"])),
                    "manifest": {a: _pre_tip["markers"][a]
                                 for a in sorted(_pre_tip["markers"])},
                }
                _mismatch_key = sha256(json.dumps(
                    _mkey_src, sort_keys=True).encode("utf-8")).hexdigest()
                self._reconcile_marker_invalid_coalesced(
                    _mismatch_key,
                    "prefix marker-set mismatch (F70): the MAC'd tip "
                    "manifest lists interrupted authorizations %s but "
                    "the log scan finds %s -- the pre-tip prefix's "
                    "marker bytes disagree with the authenticated "
                    "manifest (possible length-preserving marker "
                    "tamper). The unverified scan is REFUSED; the "
                    "incremental verdict is discarded and a full "
                    "verification runs below"
                    % (sorted(_pre_tip["markers"]),
                       sorted(_prefix_interrupted)),
                    None,
                    self._read_reconcile_marker_cache())
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
        # The interrupted set the recovery below reconciles. It is
        # assigned exactly one trusted value per gate outcome -- never
        # the unverified scan after a merely incremental verification
        # (F70).
        trusted = None
        if use_cached:
            verdict_ok = False
            verdict_error = (cache.get("error")
                             or "cached invalid verdict")
            verdict_broken = cache.get("broken_seq")
        else:
            # Verification gate: incremental tip first (O(new bytes));
            # full tolerant _verify when the tip is unusable.
            #
            # R18 (F70): the incremental verdict authenticates the new
            # segment, but the prefix's interrupted set is taken from
            # the tip's MAC'd marker manifest (folded over the whole
            # log by the advance) -- never from the unverified scan.
            # When the pre-gate prefix check above found a mismatch,
            # the incremental verdict is discarded outright: only a
            # full verification can authenticate the prefix now.
            try:
                tip_verdict = verify_chain_tip(self.log.path)
            except OSError:
                tip_verdict = None
            _manifest = (tip_verdict.get("markers")
                         if tip_verdict is not None else None)
            if (tip_verdict is not None and not manifest_mismatch
                    and isinstance(_manifest, dict)):
                verdict_ok, verdict_error = True, ""
                verdict_broken = None
                trusted = dict(_manifest)
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
                    # Every byte just authenticated, so the scan's
                    # interrupted set is trustworthy here -- this is
                    # the ONLY path where the unverified scan becomes
                    # the trusted set. Reseed the tip (with its marker
                    # manifest) so the next sweep verifies
                    # incrementally.
                    trusted = dict(interrupted)
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
                self._log({
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
        if not trusted:
            return []
        reconciled = []

        def fix(records):
            for r in records:
                seq = trusted.get(r["id"])
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
                    # D1-core: the reset voids the DECISION, not the
                    # stewardship history or the world-facts. The
                    # current assignment (delegated_to) is
                    # decision-scoped like decided_by, so it resets to
                    # the default operator pool; the append-only
                    # delegation_chain, the quorum snapshot, and the
                    # final votes stay intact (MACed) for forensics.
                    # bridge_expired/bridge_expired_at are world-facts
                    # about the bridge wait, NOT decision state — they
                    # are preserved, so a re-decision after the expiry
                    # is still late_decision=true and the sweep still
                    # refuses execution (T11/T12). late_decision itself
                    # describes the voided decision, so it resets.
                    r["delegated_to"] = None
                    r["late_decision"] = False
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
            self._log({
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

    def locked(self, timeout=None):
        """Public transaction seam (D1 pluggability).

        Context manager holding the exclusive queue lock across a
        read-modify-write sequence (the F39/F44 lock with the same
        timeout and invalidation semantics as ``_queue_locked``).
        Presentation layers (``gov/approval_web.py``) and external
        queue drivers (e.g. an AGT/AgentCore adapter implementing the
        QueuePort surface) must perform multi-step mutations inside
        ``with queue.locked():`` instead of reaching into the private
        ``_queue_locked``.
        """
        return self._queue_locked(timeout=timeout)


def _default_runs_roots():
    """Candidate run roots, in preference order (packaging: never the
    installed package).

    ``gov-approve`` used to resolve ``runs/`` relative to ``__file__``,
    which lands inside site-packages for a wheel install -- runs would
    be read from (and, worse, suggested to be written to) the installed
    package. The default is now user-scoped: first the current working
    directory (where ``gov-demo`` writes its runs), then the XDG user
    data dir.
    """
    roots = [Path.cwd() / "runs"]
    xdg = os.environ.get("XDG_DATA_HOME") or str(
        Path.home() / ".local" / "share")
    roots.append(Path(xdg) / "agent-governance" / "runs")
    return roots


def _resolve_rundir(args):
    if args.rundir:
        return Path(args.rundir)
    for root in _default_runs_roots():
        cands = [d for d in root.iterdir()] if root.is_dir() else []
        cands = [d for d in cands if d.is_dir()]
        if cands:
            return max(cands, key=lambda d: d.stat().st_mtime)
    raise SystemExit(
        "no runs found in %s; run gov-demo first or pass --rundir <dir>"
        % ", ".join(str(r) for r in _default_runs_roots()))


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


def _print_shield_brief(brief, challenge):
    """GAP-3: render the independent approver brief on the terminal.

    The agent's justification appears ONLY in the labeled quarantine
    zone, after every governor-computed signal. The challenge follows;
    the operator answers it and passes the indices via
    ``approve --challenge-answers`` with ``--shield-ack``.
    """
    action = brief.get("action") or {}
    risk = brief.get("risk") or {}
    cap = brief.get("capability") or {}
    pers = brief.get("persuasion") or {}
    quar = brief.get("quarantine") or {}
    req = action.get("requested_by") or {}
    print("INDEPENDENT SHIELD BRIEF (governor-computed, not agent prose)")
    print("  tier: %s | approval: %s"
          % (brief.get("tier"), brief.get("approval_id")))
    print("  action: %s" % action.get("tool"))
    print("  machine-verified target: %s" % action.get("target"))
    print("  executor preview: %s" % action.get("executor_preview"))
    print("  requested by: %s (%s/%s)"
          % (req.get("agent_id"), req.get("role"), req.get("principal")))
    print("  risk: %s (%s)" % (risk.get("tier"), risk.get("score")))
    for f in risk.get("factors") or []:
        print("    factor: %s" % f)
    for h in risk.get("blast_radius") or []:
        print("    blast radius: %s" % h)
    print("  capability: %s -- %s" % (cap.get("verdict"), cap.get("note")))
    for c in brief.get("citations") or []:
        print("  citation: %s -> %s (%s)"
              % (c.get("url"), c.get("verdict"), c.get("reason")))
    if not brief.get("citations"):
        print("  citations: none cited by the agent")
    print("  persuasion score: %s" % pers.get("score"))
    for m in pers.get("markers") or []:
        print("    marker: %s" % m)
    if pers.get("prose_divergence"):
        print("    DIVERGENCE: %s" % pers.get("prose_divergence"))
    print("  -- %s" % quar.get("label"))
    print("  quarantined justification: %s" % quar.get("justification"))
    print("  brief digest (shield-ack token): %s" % brief.get("packet_digest"))
    if challenge:
        print("SHIELD CHALLENGE -- answer with --challenge-answers i,j,k:")
        for n, q in enumerate(challenge):
            print("  Q%d: %s" % (n + 1, q["question"]))
            for i, opt in enumerate(q["options"]):
                print("    [%d] %s" % (i, opt))


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
        # S3 shield (wave-89): the canonical packet is the PRIMARY
        # decision basis — machine-generated, agent-prose-free. The
        # agent's prose stays segregated and labeled below.
        _pkt = r.get("canonical_packet") or {}
        if _pkt:
            print("    packet: %s -> %s | risk %s (%s)%s" % (
                _pkt.get("action"), _pkt.get("target"),
                _pkt.get("risk_score"), _pkt.get("risk_tier"),
                (" | blast radius: %s" % "; ".join(_pkt.get("blast_radius") or []))
                if _pkt.get("blast_radius") else ""))
            print("    packet digest: %s" % r.get("packet_digest"))
        _ps = r.get("persuasion_score") or 0
        if _ps:
            print("    persuasion score: %d%s" % (
                _ps, (" [%s]" % "; ".join(r.get("persuasion_markers") or []))
                if r.get("persuasion_markers") else ""))
        if r.get("prose_divergence"):
            print("    DIVERGENCE: %s" % r.get("prose_divergence"))
        if r.get("cooling_off_until") and r.get("status") == "pending":
            print("    COOLING-OFF until %s: approve refused before then"
                  % r.get("cooling_off_until"))
        if r.get("preview"):
            print("    preview: %s" % r["preview"])
        if r.get("redactions_applied"):
            print("    redactions: %s" % ", ".join(r["redactions_applied"]))
        if r.get("delegation_attempted"):
            print("    WARNING: delegation framing detected "
                  "(on_behalf_of/delegated_by)")
        if r.get("break_glass"):
            print("    BREAK-GLASS: %s" % r.get("break_glass_reason"))
        # D1-core: pending SUBSTATE labels (spec §10 decision 1) —
        # DELEGATED and QUORUM_COLLECTING are substates of pending, not
        # new statuses, surfaced here for the operator's review.
        if r.get("status") == "pending":
            if r.get("decision_mode") == "quorum":
                quorum = r.get("quorum") or {}
                votes = r.get("votes") or []
                approve_votes = sum(1 for v in votes if v.get("approve"))
                print("    QUORUM COLLECTING: %d-of-%d approvals cast; "
                      "eligible: %s" % (
                          approve_votes,
                          quorum.get("min_approvals", "?"),
                          ", ".join(
                              quorum.get("eligible_principals") or [])))
                for v in votes:
                    print("      vote: %s %s at %s: %s" % (
                        v.get("voter_principal"),
                        "APPROVE" if v.get("approve") else "DENY",
                        v.get("ts"), v.get("reason")))
            elif r.get("delegated_to"):
                chain = r.get("delegation_chain") or []
                print("    DELEGATED to %s (hop %d of chain)" % (
                    r.get("delegated_to"), len(chain)))
        if r.get("bridge_expired"):
            print("    BRIDGE WAIT EXPIRED at %s: later decisions are "
                  "audit-only and can NEVER execute"
                  % r.get("bridge_expired_at"))
        if r.get("late_decision"):
            print("    LATE DECISION (audit-only): decided after the "
                  "bridge wait expired; recorded but not executable")
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
    p_approve.add_argument("--shield-ack", default=None,
                           help="GAP-3: ack token proving the independent "
                                "shield brief was viewed (required for "
                                "capture-tier approves; shown by "
                                "'shield-brief')")
    p_approve.add_argument("--challenge-answers", default=None,
                           help="GAP-3: comma-separated option indices "
                                "answering the shield challenge (required "
                                "for capture-tier approves)")

    p_brief = sub.add_parser(
        "shield-brief",
        help="GAP-3: render the independent approver brief (governor-"
             "computed signals, quarantined agent framing) plus the "
             "shield challenge for a pending approval")
    p_brief.add_argument("id", help="approval id")

    p_reject = sub.add_parser("reject", help="reject a pending action")
    p_reject.add_argument("id", help="approval id")
    p_reject.add_argument("--reason", required=True, help="why this is rejected")
    p_reject.add_argument("--by", default="human-operator",
                          help="who is deciding (default: human-operator)")

    p_delegate = sub.add_parser(
        "delegate",
        help="D1-core: reassign a pending approval's decision stewardship "
             "(single-decider records) or vote slot (quorum records) to "
             "another principal. Never routes back to the requesting "
             "agent; no self-delegation, no loops, max_hops bound.")
    p_delegate.add_argument("id", help="approval id")
    p_delegate.add_argument("--to", required=True,
                            help="delegatee principal")
    p_delegate.add_argument("--reason", required=True,
                            help="why stewardship is being reassigned")
    p_delegate.add_argument("--by", default="human-operator",
                            help="the current assignee delegating "
                                 "(default: human-operator; quorum: the "
                                 "vote-slot holder)")
    p_delegate.add_argument("--policy", required=True,
                            help="policy YAML file whose "
                                 "approvals.delegation section governs "
                                 "this delegation")

    p_vote = sub.add_parser(
        "vote",
        help="D1-core: cast one authenticated human vote on a "
             "quorum-collecting approval. One vote per principal; a deny "
             "vetoes immediately and is terminal. The CLI is the "
             "terminal-access trust root: --by is the minted voter "
             "principal.")
    p_vote.add_argument("id", help="approval id")
    p_vote.add_argument("action", choices=["approve", "deny"],
                        help="the vote")
    p_vote.add_argument("--reason", required=True,
                        help="why this vote is being cast")
    p_vote.add_argument("--by", default="human-operator",
                        help="voter principal (default: human-operator)")

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

    if args.cmd == "delegate":
        # D1-core: the delegation policy section governs. The CLI
        # installs it from the same policy file the run uses, so the
        # terminal operator cannot delegate under a weaker (or
        # hand-written) delegation config than the run enforces.
        from .policy import PolicyEngine
        policy = PolicyEngine(args.policy)
        queue.set_delegation_config(policy.approvals_delegation)
        target = _find_record_by_id(queue, args.id)
        if target is not None:
            print("delegation target:")
            _print_decision_target(target)
        try:
            record, entry = queue.delegate(
                args.id, args.to, args.reason, args.by)
        except (ValueError, TypeError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        print("delegated approval %s (%s %s)" % (
            record["id"], record["agent_id"], record["tool"]))
        if record.get("decision_mode") == "quorum":
            print("vote slot: %s -> %s (quorum M unchanged)"
                  % (args.by, args.to))
        else:
            print("decision stewardship: %s -> %s; only %s may now "
                  "decide it" % (args.by, args.to, args.to))
        print("reason: %s" % args.reason)
        print("logged as entry seq %d" % entry["seq"])
        return 0

    if args.cmd == "vote":
        # F26 / D1-core T6: the CLI is the terminal-access trust root —
        # it binds the voter's --by principal into an identity OBJECT
        # (like the other commands); bare strings are never accepted
        # by cast_vote().
        voter_ident = AgentIdentity(agent_id="cli", role="voter",
                                    run_id=run_dir.name,
                                    principal=args.by)
        target = _find_record_by_id(queue, args.id)
        if target is not None:
            print("vote target:")
            _print_decision_target(target)
            quorum = target.get("quorum") or {}
            votes = target.get("votes") or []
            print("quorum: %d approvals of %d required; %d cast so far"
                  % (quorum.get("min_approvals", "?"),
                     len(quorum.get("eligible_principals") or []),
                     len(votes)))
        try:
            record, entry = queue.cast_vote(
                args.id, args.action == "approve", args.reason,
                voter_ident)
        except (ValueError, TypeError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        if entry.get("event") == "approval_decision":
            print("vote by %s (%s) FINALIZED the quorum: %s"
                  % (args.by, args.action, record["status"]))
            print("decided_by: %s" % record.get("decided_by"))
        else:
            print("vote recorded: %s by %s (log seq %d)"
                  % (args.action, args.by, entry["seq"]))
        print("reason: %s" % args.reason)
        return 0

    # GAP-3: render the independent approver brief + challenge without
    # deciding anything.
    if args.cmd == "shield-brief":
        _bt = _find_record_by_id(queue, args.id)
        if _bt is None:
            print("error: approval id %r not found" % args.id,
                  file=sys.stderr)
            return 1
        try:
            _cindex = _approver_shield.citation_index_for_log(
                queue.log.path)
        except Exception:
            _cindex = None
        _print_shield_brief(
            _approver_shield.shield_brief(_bt, citation_index=_cindex),
            _approver_shield.shield_challenge(_bt))
        return 0

    # F61 (R14) / F66 (R15): show the bounded decision target BEFORE
    # the decision is recorded — the decision is on the content below,
    # exactly as digested (a marker past the old 400-char cut is visible
    # in the full view).
    target = _find_record_by_id(queue, args.id)
    if target is not None:
        print("decision target:")
        _print_decision_target(target)
    # GAP-3: capture-tier approves need the shield handshake. Render
    # the independent brief + challenge here so the operator sees the
    # governor-computed signals (not just the agent's framing) before
    # deciding. The operator must explicitly pass --shield-ack (the
    # brief digest printed by 'shield-brief') and --challenge-answers;
    # the ack is never auto-filled -- the explicit gesture is the
    # proof of engagement the handshake is designed around.
    shield_ack = getattr(args, "shield_ack", None)
    challenge_answers = getattr(args, "challenge_answers", None)
    if (target is not None and args.cmd == "approve"
            and _approver_shield.is_capture_tier(target)):
        try:
            _cindex = _approver_shield.citation_index_for_log(
                queue.log.path)
        except Exception:
            _cindex = None
        _print_shield_brief(
            _approver_shield.shield_brief(target, citation_index=_cindex),
            _approver_shield.shield_challenge(target))
        if challenge_answers:
            try:
                challenge_answers = [
                    int(x) for x in str(challenge_answers).split(",")]
            except (TypeError, ValueError):
                print("error: --challenge-answers must be comma-separated "
                      "option indices (e.g. 1,3,2)", file=sys.stderr)
                return 1
    try:
        record, entry = queue.decide(args.id, args.cmd == "approve",
                                     args.reason, decided_by=args.by,
                                     shield_ack=shield_ack,
                                     challenge_answers=challenge_answers)
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


# ===========================================================================
# P10 (wave-24): governed authority delegation (agent→agent grants).
#
# Terminology (A12, per workstreams/architect/DELEGATION_PRIMITIVE_SPEC.md):
# "authority delegation" here is agent→agent grants of tool-call
# authority. It is a DIFFERENT primitive from D1-core "approval
# delegation" (approvals.delegation: human reassignment of
# approval-queue stewardship) — docs, code, and audit events keep the
# two terms distinct.
#
# Design (spec §0–§3):
# * A delegation grant is a SERVER-SIDE record, MAC-bound under the run
#   log key (F34/F43 discipline), minted ONLY through
#   DelegationStore.delegate_grant() by a verified AgentIdentity —
#   never by self-claimed on_behalf_of/delegated_by framing kwargs.
# * Grants are referenced by id at invocation; the delegatee's identity
#   must EXACTLY match the grant's delegatee (the delegatee_mismatch
#   refusal is load-bearing: the grant id is not a bearer token).
# * Mint enforces no-amplification against the LIVE policy; invocation
#   re-verifies everything (integrity, expiry, revocation, scope,
#   chain, run binding, single-use).
# * require_approval flags propagate into the grant scope: delegation
#   never bypasses the approval queue.
# * Human powers (decide/cast_vote/break_glass) are non-delegable.
# * Unscoped framing (on_behalf_of/delegated_by WITHOUT a grant id) is
#   policy-governed: unscoped_delegation flag|deny (default flag,
#   lint-warned); deny refuses before execution.
#
# EXECUTOR WIRING (LANDED wave-26 in gov/executor.py::ToolExecutor —
# the six steps below are the live call-path integration; this comment
# is kept as the design record of what call() does):
#   1. pop the delegation_grant_id framing kwarg;
#   2. call store.verify_invocation(grant_id, identity, tool, kwargs,
#      tainted=..., taint_sources=...) BEFORE policy evaluation;
#   3. (F101, wave-26 — landed as an equivalent guard, not literal
#      delegator-as-requester routing) the verified grant id and the
#      delegating party (agent_id/role/principal, as verified by the
#      store) are stamped on the approval record at queue time and
#      MAC-bound (see _SECURITY_PAYLOAD_FIELDS); decide() and
#      cast_vote() exclude the delegator alongside the requester
#      (both aliases). Rationale for the guard shape over
#      re-routing: the queue record keeps today's attribution
#      (the ACTING agent is the requester of record — D1-core
#      queue/delegate/vote semantics, the web UI, and the audit
#      trail are untouched), while the SoD invariant now covers
#      the intending party too. Re-routing the record's agent_id
#      to the delegator would additionally let the DELEGATEE (the
#      actor) decide the approval — the guard excludes BOTH, which
#      is strictly stronger for the F101 shape;
#   4. for framing kwargs WITHOUT a grant id, call
#      store.check_unscoped_framing(...) and deny when it says deny;
#   5. taint is per-executor-run state (self._tainted), so a verified
#      grant invocation inherits it automatically — delegation never
#      launders taint (the store's taint_inherited flag echoes the
#      state the executor passed in);
#   6. add delegation_grant_id / delegator / delegation_scope to the
#      tool_call audit entry (dual attribution) — wired via _base().
# While the delegation policy section is disabled, on_behalf_of /
# delegated_by behave as today (label-only) — spec §7 non-goal.
# ===========================================================================

# P10 authority-delegation policy defaults (spec §4). Opt-in: the
# out-of-box posture is today's label-only framing.
AUTHORITY_DELEGATION_DEFAULT_TTL_MINUTES = 60
AUTHORITY_DELEGATION_MAX_TTL_MINUTES = 240
AUTHORITY_DELEGATION_DEFAULT_MAX_DEPTH = 1   # 1 = single hop (A→B), no sub-delegation
AUTHORITY_DELEGATION_MAX_DEPTH_CEILING = 3
# Clock-skew grace on expiry: a grant is refused only once it has been
# expired longer than this. Documented, small, one-directional (it can
# only DELAY refusal by seconds, never extend a grant's life).
DELEGATION_CLOCK_SKEW_SECS = 30
# Human powers that authority grants can NEVER confer (spec §3):
# approval decisions, quorum votes, and break-glass are human-only.
NON_DELEGABLE_POWERS = frozenset({"decide", "cast_vote", "break_glass"})

DELEGATION_GRANT_FILENAME = "delegations.jsonl"
_DELEGATION_LOCK_FILENAME = "delegations.lock"
# F39-pattern append/rewrite lock timeout: a live holder stuck past
# this means fail closed, never mutate unlocked.
_DELEGATION_LOCK_TIMEOUT_SECS = 30

# F34/F43 discipline: every field that influences what the grant
# authorizes is MAC-bound. Missing fields bind as None (fail closed).
_DELEGATION_SECURITY_PAYLOAD_FIELDS = (
    "grant_id", "delegator", "delegatee", "delegatee_kind", "scope",
    "issued_at", "expires_at", "chain", "run_id", "cross_run",
    "single_use", "consumed", "revoked", "nonce",
)

# Scope schema (spec §1.1): v1 allows explicit tool allowlists only —
# no wildcards. Unknown scope keys are refused (fail closed).
_DELEGATION_SCOPE_ALLOWED_KEYS = frozenset(
    {"tools", "max_risk", "arg_constraints", "flags"})


class DelegationError(ValueError):
    """A delegation mint/invocation/revocation refusal.

    Subclasses ValueError (the spec's refusal type) and carries the
    exact machine-readable ``reason`` (e.g. "delegatee_mismatch",
    "scope_amplification") that the audit event records.
    """

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def _normalize_authority_delegation_config(cfg):
    """Normalize the TOP-LEVEL ``delegation:`` policy section (P10).

    This is authority delegation (agent→agent grants) — NOT
    ``approvals.delegation`` (D1-core human approval stewardship;
    see _normalize_delegation_config). Returns a dict with keys
    ``enabled, default_ttl_minutes, max_ttl_minutes, max_depth,
    require_provisioned_for, unscoped_delegation``. Absent section =
    everything off (opt-in, fail closed). Malformed sections raise
    ValueError at load: the engine refuses to load them rather than
    silently mis-shaping the control (same precedent as the D1-core
    normalizers; gov/policy_lint.py mirrors these as advisory
    findings).
    """
    out = {
        "enabled": False,
        "default_ttl_minutes": AUTHORITY_DELEGATION_DEFAULT_TTL_MINUTES,
        "max_ttl_minutes": AUTHORITY_DELEGATION_MAX_TTL_MINUTES,
        "max_depth": AUTHORITY_DELEGATION_DEFAULT_MAX_DEPTH,
        "require_provisioned_for": [],
        "unscoped_delegation": "flag",
    }
    if cfg is None:
        return out
    if not isinstance(cfg, dict):
        raise ValueError(
            "delegation must be a mapping when present (P10 authority "
            "delegation); got %r" % type(cfg).__name__)
    if "enabled" in cfg:
        if not isinstance(cfg["enabled"], bool):
            raise ValueError(
                "delegation.enabled must be true/false, got %r "
                "(opt-in; no silent enable)" % (cfg["enabled"],))
        out["enabled"] = cfg["enabled"]
    for key in ("default_ttl_minutes", "max_ttl_minutes"):
        if key in cfg:
            val = cfg[key]
            if isinstance(val, bool) or not isinstance(val, int) or val < 1:
                raise ValueError(
                    "delegation.%s must be a positive int, got %r"
                    % (key, val))
            out[key] = val
    if out["default_ttl_minutes"] > out["max_ttl_minutes"]:
        raise ValueError(
            "delegation.default_ttl_minutes (%d) exceeds "
            "delegation.max_ttl_minutes (%d)"
            % (out["default_ttl_minutes"], out["max_ttl_minutes"]))
    if "max_depth" in cfg:
        depth = cfg["max_depth"]
        if (isinstance(depth, bool) or not isinstance(depth, int)
                or not 1 <= depth <= AUTHORITY_DELEGATION_MAX_DEPTH_CEILING):
            raise ValueError(
                "delegation.max_depth must be an int in 1..%d, got %r"
                % (AUTHORITY_DELEGATION_MAX_DEPTH_CEILING, depth))
        out["max_depth"] = depth
    if "require_provisioned_for" in cfg:
        rpf = cfg["require_provisioned_for"]
        if (not isinstance(rpf, (list, tuple))
                or any(not isinstance(x, str) or not x.strip()
                       for x in rpf)):
            raise ValueError(
                "delegation.require_provisioned_for must be a list of "
                "non-empty strings, got %r" % (rpf,))
        out["require_provisioned_for"] = [x for x in rpf]
    if "unscoped_delegation" in cfg:
        mode = cfg["unscoped_delegation"]
        if mode not in ("flag", "deny"):
            raise ValueError(
                "delegation.unscoped_delegation must be 'flag' or "
                "'deny', got %r" % (mode,))
        out["unscoped_delegation"] = mode
    return out


def _delegation_grant_mac(key, key_epoch, canonical):
    """P10: domain-separated HMAC for delegation-grant records.

    Grants live outside the action log's hash chain (mutable state:
    revoke/consume transitions), so like the approval queue they get
    their own domain-separated MAC under the SAME active log key.
    The domain string ``delegation-grant`` is distinct from
    ``approval-record`` and ``break-glass-ticket``: a MAC minted for
    one record kind can never verify as another. key_epoch is bound
    in and verified against the keyring. Under the PUBLIC development
    key this gives no forgery resistance to anyone who read the docs
    (F29/F34 residual — the boundary is key custody).
    """
    msg = ("delegation-grant|%s|%s"
           % (key_epoch, canonical)).encode("utf-8")
    return hmac.new(key, msg, sha256).hexdigest()


def _delegation_security_payload(rec):
    payload = {f: rec.get(f)
               for f in _DELEGATION_SECURITY_PAYLOAD_FIELDS}
    return _canonical_dumps(payload)


def _delegation_record_mac(rec):
    key, key_epoch = _active_key()
    return _delegation_grant_mac(
        key, key_epoch, _delegation_security_payload(rec))


def _delegation_record_ok(rec):
    """True when the grant record's keyed digest verifies.

    Tries every epoch in the keyring (rotation-safe); a tampered or
    pre-scheme record fails closed. Mirrors _pending_record_content_ok.
    """
    if not isinstance(rec, dict):
        return False
    for key_epoch, key in _ledger_keyring().items():
        candidate = _delegation_grant_mac(
            key, key_epoch, _delegation_security_payload(rec))
        if hmac.compare_digest(rec.get("grant_mac", ""), candidate):
            return True
    return False


def _delegation_parse_ts(ts):
    try:
        dt = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class DelegationStore:
    """Server-side store for P10 authority-delegation grants.

    Grants are minted only via delegate_grant() by a verified
    AgentIdentity, persisted MAC-bound in <run_dir>/delegations.jsonl,
    and verified at invocation via verify_invocation() — the method
    the executor calls before policy evaluation (see the wiring note
    at the top of this section).

    Construction mirrors ApprovalQueue: run_dir + ActionLog, run id
    stamped from the run dir (F42 — never caller-supplied). The live
    policy probes are installed via set_policy_probes(); without them
    minting is refused (no-amplification cannot be checked against a
    policy the store cannot see — fail closed).
    """

    def __init__(self, run_dir, log, config=None, principal_registry=None,
                 known_agent_ids=None):
        self.run_dir = Path(run_dir)
        self.run_id = self.run_dir.name
        self.log = log
        self.path = self.run_dir / DELEGATION_GRANT_FILENAME
        self._config = _normalize_authority_delegation_config(config)
        self._principal_registry = None
        if principal_registry is not None:
            self.set_principal_registry(principal_registry)
        # Run-known agent ids for the delegatee eligibility check
        # (spec §1.2.5). None = no registry of agents: skip the check.
        self._known_agent_ids = (set(known_agent_ids)
                                 if known_agent_ids is not None else None)
        # F26-pattern: executor-installed minted-identity verifier,
        # write-once (F31). None = isinstance check only (documented
        # localhost-grade limit, same as the queue's CLI path).
        self._identity_verifier = None
        self._identity_verifier_sealed = False
        # Live-policy probes (installed by the executor wiring):
        # role_allows(role, tool) -> bool; effect_probe(role, tool) ->
        # "allow"|"require_approval"|"deny".
        self._role_allows = None
        self._effect_probe = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------ config
    @property
    def config(self):
        return dict(self._config)

    def set_principal_registry(self, registry):
        self._principal_registry = registry

    def set_identity_verifier(self, verifier):
        """Install the executor's minted-identity check (write-once)."""
        if getattr(self, "_identity_verifier_sealed", False):
            raise IdentityVerifierAlreadySetError(
                "delegation identity verifier is write-once: a verifier "
                "is already installed; refusing to swap it out")
        if not callable(verifier):
            raise TypeError(
                "identity verifier must be callable, got %r"
                % type(verifier).__name__)
        self._identity_verifier = verifier
        self._identity_verifier_sealed = True

    def set_policy_probes(self, role_allows, effect_probe):
        """Install the live-policy probes the no-amplification check
        needs. ``role_allows(role, tool)`` mirrors
        PolicyEngine.role_allows; ``effect_probe(role, tool)`` returns
        the policy effect ("allow"/"require_approval"/"deny") for a
        bare tool invocation by that role, used to propagate
        require_approval flags into the grant scope."""
        if not callable(role_allows) or not callable(effect_probe):
            raise TypeError("policy probes must be callable")
        self._role_allows = role_allows
        self._effect_probe = effect_probe

    def _authenticate(self, identity, what):
        if not isinstance(identity, AgentIdentity):
            raise TypeError(
                "%s requires an AgentIdentity minted by the executor "
                "(got %s); bare principal/operator strings are never "
                "accepted" % (what, type(identity).__name__))
        if self._identity_verifier is not None:
            self._identity_verifier(identity)
        return identity

    # ------------------------------------------------------------ store
    @contextlib.contextmanager
    def _store_locked(self):
        """Exclusive inter-process lock around grant-file mutations."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.run_dir / _DELEGATION_LOCK_FILENAME
        with self._lock:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
            except OSError as e:
                raise DelegationError(
                    "store_lock_unavailable",
                    "delegation store lock %s is not lockable (%s); "
                    "refusing to mutate" % (lock_path, e))
            f = os.fdopen(fd, "a", encoding="utf-8")
            try:
                deadline = time.monotonic() + _DELEGATION_LOCK_TIMEOUT_SECS
                while True:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise DelegationError(
                                "store_lock_unavailable",
                                "delegation store lock unavailable after "
                                "%ds; refusing to mutate rather than risk "
                                "a torn race" % _DELEGATION_LOCK_TIMEOUT_SECS)
                        time.sleep(0.01)
                try:
                    yield
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            finally:
                f.close()

    def _read_all(self):
        if not self.path.exists():
            return []
        records = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def _append_record(self, rec):
        with self._store_locked():
            self.run_dir.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=True, default=str)
                        + "\n")
                f.flush()
                # F89: tolerate EINVAL (non-syncable fd); see queue().
                _fsync_syncable(f.fileno())

    def _rewrite_locked(self, records):
        # Crash-atomic rewrite assuming the store lock is already
        # held (the consume path re-reads + mutates + rewrites under
        # one acquisition so two concurrent consumers cannot both
        # observe "unconsumed" — the F39 double-execution shape).
        _atomic_write_text(
            self.path,
            [json.dumps(r, ensure_ascii=True, default=str) + "\n"
             for r in records])

    def _rewrite(self, records):
        """Rewrite the grant file.

        Crash-atomic (F83 pattern): temp file + fsync + os.replace —
        a crash mid-rewrite leaves the previous complete file.
        """
        with self._store_locked():
            self._rewrite_locked(records)

    def _find(self, grant_id):
        for rec in self._read_all():
            if rec.get("grant_id") == grant_id:
                return rec
        return None

    # ------------------------------------------------------------ audit
    def _audit(self, event, **fields):
        entry = {"event": event, "run_id": self.run_id}
        entry.update(fields)
        return self.log.append(entry)

    def _refuse_mint(self, reason, message, **fields):
        self._audit("delegation_refused", reason=reason,
                    detail=message, **fields)
        raise DelegationError(reason, message)

    def _refuse_invocation(self, reason, message, grant_id=None,
                           identity=None, tool=None):
        self._audit(
            "delegation_invocation_refused", reason=reason, detail=message,
            grant_id=grant_id,
            agent_id=getattr(identity, "agent_id", None),
            role=getattr(identity, "role", None),
            principal=getattr(identity, "principal", None),
            tool=tool)
        raise DelegationError(reason, message)

    # ------------------------------------------------------------ mint
    @staticmethod
    def _normalize_scope(scope):
        """Validate the v1 scope schema; returns a normalized copy."""
        if not isinstance(scope, dict):
            return None, "scope must be a mapping"
        unknown = set(scope) - _DELEGATION_SCOPE_ALLOWED_KEYS
        if unknown:
            return None, ("scope carries unknown keys %r (v1 allows %s)"
                          % (sorted(unknown),
                             sorted(_DELEGATION_SCOPE_ALLOWED_KEYS)))
        tools = scope.get("tools")
        if (not isinstance(tools, (list, tuple)) or not tools
                or any(not isinstance(t, str) or not t.strip()
                       for t in tools)):
            return None, "scope.tools must be a non-empty list of tool names"
        if any(t.strip() == "*" for t in tools):
            return None, "scope.tools wildcards are not allowed in v1"
        if len(set(tools)) != len(tools):
            return None, "scope.tools contains duplicates"
        arg_constraints = scope.get("arg_constraints") or {}
        if not isinstance(arg_constraints, dict):
            return None, "scope.arg_constraints must be a mapping"
        for k, v in arg_constraints.items():
            if not isinstance(v, (list, tuple)) or not v:
                return None, ("scope.arg_constraints[%r] must be a "
                              "non-empty list of allowed values" % (k,))
        flags = scope.get("flags") or []
        if (not isinstance(flags, (list, tuple))
                or any(not isinstance(x, str) for x in flags)):
            return None, "scope.flags must be a list of strings"
        max_risk = scope.get("max_risk")
        if max_risk is not None and not isinstance(max_risk, str):
            return None, "scope.max_risk must be a string"
        return {
            "tools": [t.strip() for t in tools],
            "max_risk": max_risk,
            "arg_constraints": {k: list(v)
                                for k, v in arg_constraints.items()},
            "flags": list(flags),
            # Filled by the mint-time propagation below:
            "approval_gated": [],
        }, None

    def delegate_grant(self, delegator_identity, delegatee, scope,
                       ttl_minutes=None, single_use=False, cross_run=False,
                       parent_grant_id=None, delegatee_is_principal=False):
        """Mint a P10 authority-delegation grant (spec §1.2).

        Only a verified AgentIdentity can mint — bare principal
        strings raise TypeError, unminted identities raise. Every
        refusal is audited (delegation_refused) with its exact reason
        and raises DelegationError (a ValueError).
        """
        if not self._config["enabled"]:
            self._refuse_mint(
                "delegation_disabled",
                "authority delegation is not enabled by policy "
                "(delegation.enabled: false); refusing to mint",
                delegatee=delegatee)
        delegator = self._authenticate(delegator_identity, "delegate_grant")
        if delegator.run_id != self.run_id:
            self._refuse_mint(
                "wrong_run_identity",
                "delegate_grant refused: delegator run_id %r does not "
                "match this store's run %r"
                % (delegator.run_id, self.run_id),
                delegator_agent_id=delegator.agent_id)
        if not isinstance(delegatee, str) or not delegatee.strip():
            self._refuse_mint(
                "bad_delegatee", "delegatee must be a non-empty string",
                delegator_agent_id=delegator.agent_id)
        delegatee = delegatee.strip()
        # No self-delegation laundering (D1-core §3.3 alias check,
        # reused): neither the agent id nor the principal may name the
        # delegator itself.
        if delegatee in (delegator.agent_id, delegator.principal):
            self._refuse_mint(
                "self_delegation",
                "delegate_grant refused: delegatee %r names the "
                "delegator itself (agent_id/principal alias check)"
                % delegatee,
                delegator_agent_id=delegator.agent_id,
                delegatee=delegatee)
        norm_scope, scope_err = self._normalize_scope(scope)
        if norm_scope is None:
            self._refuse_mint(
                "bad_scope", "delegate_grant refused: %s" % scope_err,
                delegator_agent_id=delegator.agent_id,
                delegatee=delegatee)
        # Delegatee eligibility (spec §1.2.5).
        if delegatee_is_principal:
            registry = self._principal_registry
            if registry is not None:
                try:
                    registry.check(delegatee)
                except UnregisteredPrincipalError:
                    self._refuse_mint(
                        "unregistered_delegatee",
                        "delegate_grant refused: delegatee principal %r "
                        "is not registered with this deployment"
                        % delegatee,
                        delegator_agent_id=delegator.agent_id,
                        delegatee=delegatee)
        elif self._known_agent_ids is not None:
            if delegatee not in self._known_agent_ids:
                self._refuse_mint(
                    "unknown_delegatee_agent",
                    "delegate_grant refused: delegatee agent id %r is "
                    "not known in this run" % delegatee,
                    delegator_agent_id=delegator.agent_id,
                    delegatee=delegatee)
        # TTL bounds (spec §1.1/§4).
        ttl = (self._config["default_ttl_minutes"]
               if ttl_minutes is None else ttl_minutes)
        if (isinstance(ttl, bool) or not isinstance(ttl, int)
                or not 1 <= ttl <= self._config["max_ttl_minutes"]):
            self._refuse_mint(
                "ttl_out_of_range",
                "delegate_grant refused: ttl_minutes must be an int in "
                "1..%d, got %r"
                % (self._config["max_ttl_minutes"], ttl_minutes),
                delegator_agent_id=delegator.agent_id,
                delegatee=delegatee)
        # require_provisioned_for (spec §1.2.1): high-risk scopes need
        # the F55 provisioned session identity as the delegator.
        needs_provisioned = [
            t for t in norm_scope["tools"]
            if t in self._config["require_provisioned_for"]]
        if needs_provisioned and delegator.provenance != "provisioned":
            self._refuse_mint(
                "provisioned_required",
                "delegate_grant refused: tools %r require a "
                "provisioned session identity as delegator (policy "
                "delegation.require_provisioned_for); got provenance "
                "%r" % (needs_provisioned, delegator.provenance),
                delegator_agent_id=delegator.agent_id,
                delegatee=delegatee)
        # No-amplification against the LIVE policy (spec §1.2.2): every
        # scoped tool must be in the delegator's own authority, and any
        # require_approval effect propagates into the grant scope so
        # the delegatee's invocation still queues approvals.
        if self._role_allows is None or self._effect_probe is None:
            self._refuse_mint(
                "no_amplification_oracle",
                "delegate_grant refused: no live-policy probes "
                "installed on this store — the no-amplification check "
                "cannot run blind (fail closed)",
                delegator_agent_id=delegator.agent_id,
                delegatee=delegatee)
        approval_gated = []
        for tool in norm_scope["tools"]:
            if not self._role_allows(delegator.role, tool):
                self._refuse_mint(
                    "scope_amplification",
                    "delegate_grant refused: role %r is not allowed "
                    "tool %r under the active policy — a grant cannot "
                    "confer authority the delegator does not have"
                    % (delegator.role, tool),
                    delegator_agent_id=delegator.agent_id,
                    delegatee=delegatee, tool=tool)
            effect = self._effect_probe(delegator.role, tool)
            if effect == "deny":
                self._refuse_mint(
                    "scope_amplification",
                    "delegate_grant refused: tool %r is denied to role "
                    "%r by the active policy" % (tool, delegator.role),
                    delegator_agent_id=delegator.agent_id,
                    delegatee=delegatee, tool=tool)
            if effect == "require_approval":
                approval_gated.append(tool)
        norm_scope["approval_gated"] = approval_gated
        # Sub-delegation: narrows only (spec §2).
        chain = []
        parent = None
        if parent_grant_id is not None:
            parent = self._find(parent_grant_id)
            if parent is None:
                self._refuse_mint(
                    "unknown_parent",
                    "delegate_grant refused: parent grant %r not found"
                    % (parent_grant_id,),
                    delegator_agent_id=delegator.agent_id,
                    delegatee=delegatee)
            self._verify_chain_link(parent, delegator, "mint")
            # The sub-delegator must be the parent's delegatee —
            # verified identity match (no hop-skipping).
            if parent.get("delegatee_kind", "agent_id") == "agent_id":
                if delegator.agent_id != parent["delegatee"]:
                    self._refuse_mint(
                        "not_parent_delegatee",
                        "delegate_grant refused: minter %r is not the "
                        "parent grant's delegatee %r"
                        % (delegator.agent_id, parent["delegatee"]),
                        delegator_agent_id=delegator.agent_id,
                        delegatee=delegatee)
            else:
                if delegator.principal != parent["delegatee"]:
                    self._refuse_mint(
                        "not_parent_delegatee",
                        "delegate_grant refused: minter principal %r is "
                        "not the parent grant's delegatee %r"
                        % (delegator.principal, parent["delegatee"]),
                        delegator_agent_id=delegator.agent_id,
                        delegatee=delegatee)
            parent_tools = set((parent.get("scope") or {}).get("tools", []))
            if not set(norm_scope["tools"]) <= parent_tools:
                self._refuse_mint(
                    "scope_widened",
                    "delegate_grant refused: sub-grant tools %r are not "
                    "a subset of the parent grant's tools %r "
                    "(sub-delegation narrows only)"
                    % (norm_scope["tools"], sorted(parent_tools)),
                    delegator_agent_id=delegator.agent_id,
                    delegatee=delegatee)
            parent_constraints = ((parent.get("scope") or {})
                                  .get("arg_constraints", {}) or {})
            for k, allowed in norm_scope["arg_constraints"].items():
                if k not in parent_constraints or not set(allowed) <= set(
                        parent_constraints[k]):
                    self._refuse_mint(
                        "scope_widened",
                        "delegate_grant refused: arg_constraints[%r] "
                        "widens the parent grant's constraint "
                        "(sub-delegation narrows only)" % (k,),
                        delegator_agent_id=delegator.agent_id,
                        delegatee=delegatee)
            new_depth = len(parent.get("chain", [])) + 2
            if new_depth > self._config["max_depth"]:
                self._refuse_mint(
                    "depth_exceeded",
                    "delegate_grant refused: sub-grant depth %d exceeds "
                    "policy delegation.max_depth=%d"
                    % (new_depth, self._config["max_depth"]),
                    delegator_agent_id=delegator.agent_id,
                    delegatee=delegatee)
            chain = list(parent.get("chain", [])) + [{
                "grant_id": parent["grant_id"],
                "delegator": parent["delegator"]["agent_id"],
                "at": _utcnow(),
            }]
        # Depth bound for root grants too (max_depth >= 1 always, so a
        # root grant at depth 1 is always within bound — checked for
        # uniformity with sub-grants).
        if len(chain) + 1 > self._config["max_depth"]:
            self._refuse_mint(
                "depth_exceeded",
                "delegate_grant refused: grant depth %d exceeds policy "
                "delegation.max_depth=%d"
                % (len(chain) + 1, self._config["max_depth"]),
                delegator_agent_id=delegator.agent_id,
                delegatee=delegatee)
        issued_at = _utcnow()
        expires_at = (datetime.fromisoformat(issued_at)
                      + timedelta(minutes=ttl)).isoformat()
        if parent is not None:
            # Sub-grants can only narrow the TTL, never extend it.
            if _delegation_parse_ts(expires_at) > _delegation_parse_ts(
                    parent["expires_at"]):
                self._refuse_mint(
                    "ttl_extended",
                    "delegate_grant refused: sub-grant expiry %s is "
                    "later than the parent grant's expiry %s "
                    "(sub-delegation narrows only)"
                    % (expires_at, parent["expires_at"]),
                    delegator_agent_id=delegator.agent_id,
                    delegatee=delegatee)
        nonce = secrets.token_hex(8)
        grant_id = sha256(
            ("%s|%s|%s" % (delegator.agent_id, delegatee,
                           nonce)).encode("utf-8")).hexdigest()
        rec = {
            "grant_id": grant_id,
            "delegator": delegator.as_dict(),
            "delegatee": delegatee,
            "delegatee_kind": ("principal" if delegatee_is_principal
                               else "agent_id"),
            "scope": norm_scope,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "chain": chain,
            "run_id": self.run_id,
            "cross_run": bool(cross_run),
            "single_use": bool(single_use),
            "consumed": False,
            "revoked": False,
            "nonce": nonce,
        }
        rec["grant_mac"] = _delegation_record_mac(rec)
        self._append_record(rec)
        self._audit(
            "delegation_granted",
            grant_id=grant_id,
            delegator_agent_id=delegator.agent_id,
            delegator_role=delegator.role,
            delegator_principal=delegator.principal,
            delegator_provenance=delegator.provenance,
            delegatee=delegatee,
            delegatee_kind=rec["delegatee_kind"],
            scope_tools=norm_scope["tools"],
            approval_gated=approval_gated,
            ttl_minutes=ttl,
            depth=len(chain) + 1,
            single_use=bool(single_use),
            cross_run=bool(cross_run),
            parent_grant_id=parent_grant_id)
        return rec

    # ------------------------------------------------------------ verify
    def _verify_chain_link(self, rec, identity, where):
        """Re-verify one grant record (integrity/expiry/revocation).

        Used for parent grants at mint time and for every ancestor at
        invocation time. Raises DelegationError on any break.
        """
        gid = rec.get("grant_id")
        if not _delegation_record_ok(rec):
            raise DelegationError(
                "grant_integrity_violation" if where == "invoke"
                else "parent_chain_broken",
                "delegation %s refused: grant %r failed its integrity "
                "check (tampered store)" % (where, gid))
        if rec.get("revoked"):
            raise DelegationError(
                "grant_revoked" if where == "invoke" else "parent_chain_broken",
                "delegation %s refused: grant %r is revoked" % (where, gid))
        exp = _delegation_parse_ts(rec.get("expires_at"))
        now = datetime.now(timezone.utc)
        if exp is None or now > exp + timedelta(
                seconds=DELEGATION_CLOCK_SKEW_SECS):
            raise DelegationError(
                "grant_expired" if where == "invoke" else "parent_chain_broken",
                "delegation %s refused: grant %r is expired" % (where, gid))

    def verify_invocation(self, grant_id, identity, tool, args=None,
                          tainted=False, taint_sources=()):
        """Verify a delegatee's invocation against a grant (spec §1.4).

        Runs BEFORE policy evaluation (the executor calls this first).
        Returns an ok-dict on success; raises DelegationError (audited
        as delegation_invocation_refused) on any refusal. ``tainted``
        lets the caller pass the executor's current taint state so the
        grant invocation INHERITS it for A2 Rule-of-Two purposes —
        delegation is not a clean-room (S16); the returned
        ``taint_inherited`` flag is what the executor's Rule-of-Two
        gate consumes.
        """
        if not isinstance(identity, AgentIdentity):
            raise TypeError(
                "verify_invocation requires an AgentIdentity (got %s); "
                "grant ids are not bearer tokens"
                % type(identity).__name__)
        args = dict(args or {})
        rec = self._find(grant_id)
        if rec is None:
            self._refuse_invocation(
                "unknown_grant",
                "delegation invocation refused: unknown grant id",
                grant_id=grant_id, identity=identity, tool=tool)
        if not _delegation_record_ok(rec):
            self._refuse_invocation(
                "grant_integrity_violation",
                "delegation invocation refused: grant %s failed its "
                "integrity check (tampered store)" % grant_id,
                grant_id=grant_id, identity=identity, tool=tool)
        if rec.get("revoked"):
            self._refuse_invocation(
                "grant_revoked",
                "delegation invocation refused: grant %s is revoked"
                % grant_id,
                grant_id=grant_id, identity=identity, tool=tool)
        exp = _delegation_parse_ts(rec.get("expires_at"))
        now = datetime.now(timezone.utc)
        if exp is None or now > exp + timedelta(
                seconds=DELEGATION_CLOCK_SKEW_SECS):
            self._refuse_invocation(
                "grant_expired",
                "delegation invocation refused: grant %s is expired"
                % grant_id,
                grant_id=grant_id, identity=identity, tool=tool)
        # Human powers are non-delegable, always (spec §3) — checked
        # independent of scope so no scope can ever smuggle them in.
        if tool in NON_DELEGABLE_POWERS:
            self._refuse_invocation(
                "non_delegable_power",
                "delegation invocation refused: %r is a human power and "
                "can never be conferred by an authority grant" % tool,
                grant_id=grant_id, identity=identity, tool=tool)
        # Delegatee match — the load-bearing check (spec decision 1):
        # the grant id is a server-side handle, NOT a bearer token.
        # Presenting it from a non-matching identity is useless.
        if rec.get("delegatee_kind", "agent_id") == "agent_id":
            matched = (identity.agent_id == rec.get("delegatee"))
        else:
            matched = (identity.principal == rec.get("delegatee"))
        if not matched:
            self._refuse_invocation(
                "delegatee_mismatch",
                "delegation invocation refused: grant %s names "
                "delegatee %r; the presenting identity (%r) does not "
                "match — grants are not bearer tokens"
                % (grant_id, rec.get("delegatee"), identity.agent_id),
                grant_id=grant_id, identity=identity, tool=tool)
        scope = rec.get("scope") or {}
        if tool not in (scope.get("tools") or []):
            self._refuse_invocation(
                "scope_exceeded",
                "delegation invocation refused: tool %r is outside the "
                "grant's scope %r" % (tool, scope.get("tools")),
                grant_id=grant_id, identity=identity, tool=tool)
        for k, allowed in (scope.get("arg_constraints") or {}).items():
            if k in args and args[k] not in allowed:
                self._refuse_invocation(
                    "arg_constraint_violated",
                    "delegation invocation refused: arg %r=%r violates "
                    "the grant's constraint (allowed: %r)"
                    % (k, args[k], allowed),
                    grant_id=grant_id, identity=identity, tool=tool)
        # Chain verify: every ancestor re-verified (integrity, expiry,
        # revocation). A broken ancestor invalidates the whole
        # descendant line — revocation propagates downward for free.
        # F103 (wave-27): while walking the verified chain, resolve the
        # FULL delegator lineage (root -> immediate parent), each as
        # {agent_id, role, principal} read from the VERIFIED ancestor
        # record (never from the chain hop's bare agent_id string, and
        # never caller-supplied). The immediate delegator is appended
        # after the loop, so the returned lineage covers every
        # intending party in order.
        resolved_chain = []
        for hop in rec.get("chain", []):
            ancestor = self._find(hop.get("grant_id"))
            if ancestor is None:
                self._refuse_invocation(
                    "chain_broken",
                    "delegation invocation refused: ancestor grant %r "
                    "of %s is missing from the store"
                    % (hop.get("grant_id"), grant_id),
                    grant_id=grant_id, identity=identity, tool=tool)
            try:
                self._verify_chain_link(ancestor, identity, "invoke")
            except DelegationError as e:
                self._refuse_invocation(
                    "chain_broken",
                    "delegation invocation refused: ancestor grant %r "
                    "breaks the chain (%s: %s)"
                    % (hop.get("grant_id"), e.reason, e),
                    grant_id=grant_id, identity=identity, tool=tool)
            _anc_deleg = ancestor.get("delegator") or {}
            resolved_chain.append({
                "agent_id": _anc_deleg.get("agent_id"),
                "role": _anc_deleg.get("role"),
                "principal": _anc_deleg.get("principal"),
            })
        # Run binding (spec §1.4 step 8).
        if identity.run_id != rec.get("run_id") and not rec.get("cross_run"):
            self._refuse_invocation(
                "cross_run_denied",
                "delegation invocation refused: grant %s is bound to "
                "run %r and cross_run was not granted"
                % (grant_id, rec.get("run_id")),
                grant_id=grant_id, identity=identity, tool=tool)
        if rec.get("single_use") and rec.get("consumed"):
            self._refuse_invocation(
                "grant_consumed",
                "delegation invocation refused: grant %s is single-use "
                "and already consumed" % grant_id,
                grant_id=grant_id, identity=identity, tool=tool)
        # Success: consume single-use grants (F38 pattern — verify
        # BEFORE mutate, re-MAC AFTER), then audit dual attribution.
        # The find + re-verify + consume + rewrite happens under ONE
        # lock acquisition with the consumed flag re-checked inside:
        # two concurrent consumers cannot both observe "unconsumed"
        # (the F39 double-execution shape).
        consumed_now = False
        if rec.get("single_use"):
            with self._store_locked():
                records = self._read_all()
                target = None
                for r in records:
                    if r.get("grant_id") == grant_id:
                        target = r
                        break
                if target is None or not _delegation_record_ok(target):
                    self._refuse_invocation(
                        "grant_integrity_violation",
                        "delegation invocation refused: grant %s "
                        "failed its integrity check at consume time"
                        % grant_id,
                        grant_id=grant_id, identity=identity,
                        tool=tool)
                if target.get("consumed"):
                    self._refuse_invocation(
                        "grant_consumed",
                        "delegation invocation refused: grant %s is "
                        "single-use and already consumed" % grant_id,
                        grant_id=grant_id, identity=identity,
                        tool=tool)
                target["consumed"] = True
                target["grant_mac"] = _delegation_record_mac(target)
                self._rewrite_locked(records)
                consumed_now = True
        delegator = rec.get("delegator") or {}
        # F103 (wave-27): the immediate delegator closes the resolved
        # lineage — root -> ... -> immediate. At depth 1 the chain
        # entries above are empty and the lineage is just [immediate],
        # so depth-1 behavior is unchanged.
        resolved_chain.append({
            "agent_id": delegator.get("agent_id"),
            "role": delegator.get("role"),
            "principal": delegator.get("principal"),
        })
        self._audit(
            "delegation_invoked",
            grant_id=grant_id,
            agent_id=identity.agent_id,
            role=identity.role,
            principal=identity.principal,
            delegator_agent_id=delegator.get("agent_id"),
            delegator_principal=delegator.get("principal"),
            delegator_role=delegator.get("role"),
            tool=tool,
            delegation_scope_tools=scope.get("tools"),
            requires_approval=list(scope.get("approval_gated") or []),
            taint_inherited=bool(tainted),
            taint_sources=list(taint_sources),
            single_use_consumed=consumed_now)
        return {
            "ok": True,
            "grant_id": grant_id,
            "delegator": {
                "agent_id": delegator.get("agent_id"),
                "role": delegator.get("role"),
                "principal": delegator.get("principal"),
            },
            # F103 (wave-27): the full delegator lineage, root ->
            # immediate, each {agent_id, role, principal}, resolved
            # from the re-verified ancestor records at invocation
            # time. The executor stamps this on the approval record
            # (MAC-bound) so decide()/cast_vote() exclude the whole
            # intending lineage, not just the last hop.
            "delegator_chain": resolved_chain,
            "scope_tools": list(scope.get("tools") or []),
            "requires_approval": list(scope.get("approval_gated") or []),
            "taint_inherited": bool(tainted),
            "single_use_consumed": consumed_now,
        }

    # ------------------------------------------------------------ revoke
    def revoke_grant(self, grant_id, revoker_identity, reason=""):
        """Revoke a grant (spec §1.6).

        The revoker must be the delegator or the provisioned session
        identity (operator). Revocation is an audited, MACed
        transition; it is checked at every invocation, and descendant
        grants fail chain verification — revocation propagates down
        the chain with no per-descendant bookkeeping.
        """
        revoker = self._authenticate(revoker_identity, "revoke_grant")
        if not isinstance(reason, str):
            raise TypeError("revocation reason must be a string")
        records = self._read_all()
        target = None
        for r in records:
            if r.get("grant_id") == grant_id:
                target = r
                break
        if target is None:
            self._audit("delegation_invocation_refused",
                        reason="unknown_grant",
                        detail="revoke_grant refused: unknown grant id",
                        grant_id=grant_id,
                        agent_id=revoker.agent_id)
            raise DelegationError(
                "unknown_grant",
                "revoke_grant refused: unknown grant id")
        # F38: verify BEFORE mutating.
        if not _delegation_record_ok(target):
            self._audit("delegation_invocation_refused",
                        reason="grant_integrity_violation",
                        detail="revoke_grant refused: grant failed its "
                               "integrity check (tampered store)",
                        grant_id=grant_id, agent_id=revoker.agent_id)
            raise DelegationError(
                "grant_integrity_violation",
                "revoke_grant refused: grant failed its integrity check")
        delegator_id = (target.get("delegator") or {}).get("agent_id")
        is_delegator = (revoker.agent_id == delegator_id)
        is_operator = (revoker.provenance == "provisioned")
        if not (is_delegator or is_operator):
            self._audit("delegation_invocation_refused",
                        reason="revoke_not_authorized",
                        detail="revoke_grant refused: %r is neither the "
                               "delegator nor the provisioned operator"
                               % revoker.agent_id,
                        grant_id=grant_id, agent_id=revoker.agent_id)
            raise DelegationError(
                "revoke_not_authorized",
                "revoke_grant refused: only the delegator or the "
                "provisioned session identity may revoke")
        if target.get("revoked"):
            return target  # idempotent
        target["revoked"] = True
        target["grant_mac"] = _delegation_record_mac(target)
        self._rewrite(records)
        self._audit(
            "delegation_revoked",
            grant_id=grant_id,
            revoker_agent_id=revoker.agent_id,
            revoker_principal=revoker.principal,
            revoker_provenance=revoker.provenance,
            delegator_agent_id=delegator_id,
            reason_text=reason)
        return target

    # ------------------------------------------------------------ unscoped framing
    def check_unscoped_framing(self, on_behalf_of=None, delegated_by=None,
                               delegation_grant_id=None, identity=None):
        """Policy-govern the unscoped framing kwargs (spec §1.5).

        ``on_behalf_of``/``delegated_by`` WITHOUT a grant id are
        untrusted labels. When the authority-delegation feature is
        enabled and ``unscoped_delegation: deny``, such a call is
        DENIED (policy_id "delegation-unscoped") before execution and
        audited. Under the default ``flag`` the call is allowed and
        labeled (today's behavior); the lint warns about the residual.
        With the feature disabled, behavior is unchanged (label-only).
        Returns a verdict dict the executor's call() consumes.
        """
        if delegation_grant_id or not (on_behalf_of or delegated_by):
            return {"unscoped": False, "allowed": True}
        if not self._config["enabled"]:
            # Non-goal (spec §7): no behavior change while disabled.
            return {"unscoped": False, "allowed": True,
                    "mode": "label-only"}
        if self._config["unscoped_delegation"] == "deny":
            self._audit(
                "unscoped_delegation_denied",
                agent_id=getattr(identity, "agent_id", None),
                role=getattr(identity, "role", None),
                principal=getattr(identity, "principal", None),
                on_behalf_of=on_behalf_of,
                delegated_by=delegated_by,
                policy_id="delegation-unscoped",
                flag="unscoped_delegation_denied")
            return {"unscoped": True, "allowed": False,
                    "policy_id": "delegation-unscoped",
                    "flag": "unscoped_delegation_denied",
                    "reason": ("unscoped delegation framing "
                               "(on_behalf_of/delegated_by without a "
                               "grant id) is denied by policy")}
        return {"unscoped": True, "allowed": True, "mode": "flag"}
