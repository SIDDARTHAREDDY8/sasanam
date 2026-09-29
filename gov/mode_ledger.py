"""Per-rule violation telemetry + graduation/demotion ladder (wave-198).

Gatekeeper graduation-discipline steal (ADAPT -- discipline only, no
K8s machinery; see wave-196 lane E SPIKE.md): new policy rules ship in
``observe`` mode, accumulate violation telemetry in a hash-chained
ledger, and graduate to ``warn`` then ``deny`` only on evidence plus a
human quorum. Demotion is never automatic.

Stdlib only. The ledger is hash-chained: every violation, review,
heartbeat, and mode-change record commits to the previous head
(mirroring gov/log.py's tamper-evidence convention), so a tampered
violation count or mode history fails ``verify_chain()``. Evaluation
counters are plain in-memory telemetry (documented, not chained --
they are local counters, not cross-boundary evidence). Deterministic
apart from the clock, which is injectable for tests.

Quorum wiring: graduation/demotion approval evaluation reuses the
policy's normalized ``approvals.quorum`` config (the same dict
``gov/approvals._normalize_quorum_config`` produces --
``min_approvals`` / ``eligible_principals`` / ``deny_veto``), passed in
by the caller (PolicyEngine passes its own ``approvals_quorum``).

Durability (honest v1 boundary): the ModeLedger is IN-MEMORY per
engine instance. Rule posture (mode/pinned) is durable -- it comes
from the policy file and re-registers identically on every load.
Runtime telemetry (evaluation/violation counters) and the mode-change
history do NOT survive a restart: a process restart resets a
runtime-graduated rule to its YAML-declared mode. The durable,
auditor-facing trail for ladder operations is the executor's audit
log (``warn_digest``, ``warn_stale``, ``emergency_review_overdue``
entries), which is hash-chained to disk. Do not represent an
in-memory graduation as durable.
"""

import hashlib
import json
import time

# The ladder. "deny" is the resting state; "observe" and "warn" are
# rollout rungs. Pinned rules (credential-exfil forbids, key-custody)
# are deny-only and never enter the ladder.
LADDER_MODES = ("observe", "warn", "deny")

# Graduation is one rung at a time: observe -> warn -> deny.
_NEXT_RUNG = {"observe": "warn", "warn": "deny"}
_PREV_RUNG = {"deny": "warn", "warn": "observe"}

# Human quorum for every graduation/demotion step (numbers gate
# humans AND humans gate numbers -- R6). When the policy configures
# approvals.quorum, its min_approvals raises the bar (never lowers
# it below 2).
GRADUATION_QUORUM = 2

# observe -> warn evidence bar (§3.4).
OBSERVE_TO_WARN = {
    "min_evaluated": 100,
    "min_violations": 10,
    "min_reviewed": 20,
    "max_fp_rate": 0.05,
}
# warn -> deny evidence bar (§3.4): stricter FP, plus operators must
# have acted on warnings (acknowledged digest count), plus a minimum
# review base so the FP estimate is not noise, plus the "longer
# window": strictly more evidence than the observe->warn bar (2x the
# evaluated/violations minimums).
WARN_TO_DENY = {
    "min_evaluated": 200,
    "min_violations": 20,
    "min_reviewed": 20,
    "max_fp_rate": 0.01,
    "min_acknowledged": 5,
}

# A rule may not sit in warn forever: graduate to deny or demote to
# observe within this window, else it is flagged warn-stale and
# routed to the review inbox (§3.4).
WARN_MAX_DWELL_SECS = 30 * 24 * 3600

# Emergency demotion mandates post-hoc quorum review within 24h;
# failure to review re-escalates (§3.5).
EMERGENCY_REVIEW_SECS = 24 * 3600


class ModeLedgerError(Exception):
    """The ledger refused an operation (loud, fail-closed for callers)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


class ModeLedger:
    """Hash-chained per-rule violation telemetry and ladder state.

    One ledger per policy engine (rule ids are policy-scoped). The
    engine calls :meth:`observe` once per rule per decision; operator
    tooling calls the review/graduation/demotion methods.
    """

    def __init__(self, *, clock=None):
        self._clock = clock or time.time
        self._rules = {}      # rule_id -> stats dict
        self._chain = []      # hash-chained records (oldest first)
        self._head = "GENESIS"
        self._seq = 0
        self._proposals = {}  # proposal_id -> dict
        self._proposal_seq = 0
        # Escalation dedup: rule_ids already escalated for the current
        # stale episode; demotion seqs already escalated for overdue
        # emergency reviews. A mode change (or the post-hoc review)
        # clears the mark so a future episode re-escalates.
        self._stale_escalated = set()
        self._overdue_escalated = set()
        self._emergency_seq = 0
        # Wave-198 §3.2: per-rule chain heads/seqs. Every record joins
        # its rule's own hash chain (rule_seq/rule_prev) in addition
        # to the global chain.
        self._rule_heads = {}   # rule_id -> head digest
        self._rule_seqs = {}    # rule_id -> seq

    # ------------------------------------------------------------ internals

    def _now(self):
        return float(self._clock())

    def _append(self, kind, rule_id, payload):
        """Append one hash-chained record. Returns the record.

        Wave-198 §3.2: every record joins TWO chains -- the global
        ledger chain (``seq``/``prev``) and the rule's OWN chain
        (``rule_seq``/``rule_prev``). A rule's violation history is
        independently verifiable via :meth:`verify_rule_chain`
        without trusting the global interleave.
        """
        self._seq += 1
        rule_seq = self._rule_seqs.get(rule_id, 0) + 1
        self._rule_seqs[rule_id] = rule_seq
        rule_prev = self._rule_heads.get(rule_id, "GENESIS")
        record = {
            "seq": self._seq,
            "prev": self._head,
            "rule_seq": rule_seq,
            "rule_prev": rule_prev,
            "kind": kind,
            "rule_id": rule_id,
            "at": self._now(),
        }
        record.update(payload)
        record["digest"] = _sha256_hex(_canonical(
            {k: v for k, v in record.items() if k != "digest"}))
        self._chain.append(record)
        self._head = record["digest"]
        self._rule_heads[rule_id] = record["digest"]
        return record

    def _stats(self, rule_id, *, create=False):
        st = self._rules.get(rule_id)
        if st is None and create:
            st = {
                "mode": "deny",
                "pinned": False,
                "evaluated": 0,
                "violations": 0,
                "reviewed_correct": 0,
                "reviewed_wrong": 0,
                "warnings_acknowledged": 0,
                "warn_since": None,
                "heartbeats": 0,
                "mode_history": [],
                "pending_emergency_review": None,
            }
            self._rules[rule_id] = st
        return st

    # ------------------------------------------------------------ recording

    def register_rule(self, rule_id, *, mode="deny", pinned=False):
        """Register a rule's ladder posture (called at policy load).

        Unknown mode / pinned+non-deny are refused HERE as well as by
        the policy loader -- defense in depth for programmatic
        construction paths.
        """
        if mode not in LADDER_MODES:
            raise ModeLedgerError(
                "unknown ladder mode %r (must be one of %s)"
                % (mode, LADDER_MODES))
        if not isinstance(pinned, bool):
            raise ModeLedgerError(
                "pinned must be a bool, got %r" % (pinned,))
        if pinned and mode != "deny":
            raise ModeLedgerError(
                "pinned rule %r must use mode 'deny', got %r"
                % (rule_id, mode))
        st = self._stats(rule_id, create=True)
        st["mode"] = mode
        st["pinned"] = pinned
        if mode == "warn" and st["warn_since"] is None:
            st["warn_since"] = self._now()
        return st["mode"]

    def observe(self, rule_id, *, mode, matched, nominal_effect=None,
                request_digest=None):
        """Record one rule evaluation (called by PolicyEngine.decide).

        Every evaluation increments the counter; an observe/warn-mode
        MATCH additionally appends a chained violation record. Deny
        mode is today's behavior and needs no telemetry beyond the
        decision itself.
        """
        if mode not in LADDER_MODES:
            raise ModeLedgerError("unknown ladder mode %r" % (mode,))
        st = self._stats(rule_id, create=True)
        st["evaluated"] += 1
        if matched and mode in ("observe", "warn"):
            st["violations"] += 1
            self._append("violation", rule_id, {
                "mode": mode,
                "nominal_effect": nominal_effect,
                "request_digest": request_digest,
            })

    def record_warnings(self, rule_id, count):
        """Record warnings surfaced for a warn-mode rule (SPIKE §3.3).

        Called by the executor when a warn-digest window rolls: the
        per-mode "warning count" stat accrues here so graduation
        evidence includes how often the rule actually warned.
        """
        if not isinstance(count, int) or count < 0:
            raise ModeLedgerError("count must be a non-negative int")
        st = self._stats(rule_id, create=True)
        st["warnings_surfaced"] = st.get("warnings_surfaced", 0) + count

    def record_review(self, rule_id, *, correct, reviewer):
        """Record one operator-attested review of a violation sample.

        Only operator-attested reviews count toward FP stats --
        agent-generated traffic is NOT a review (R3 demotion-abuse).
        The caller (review inbox / operator tooling) attests the
        human provenance; the ledger records the attestation.
        """
        if not isinstance(reviewer, str) or not reviewer.strip():
            raise ModeLedgerError("reviewer must be a non-empty string")
        st = self._stats(rule_id, create=True)
        if correct:
            st["reviewed_correct"] += 1
        else:
            st["reviewed_wrong"] += 1
        self._append("review", rule_id, {
            "correct": bool(correct),
            "reviewer": reviewer.strip(),
        })

    def record_warning_ack(self, rule_id, *, operator):
        """Record that an operator acknowledged a warn digest."""
        if not isinstance(operator, str) or not operator.strip():
            raise ModeLedgerError("operator must be a non-empty string")
        st = self._stats(rule_id, create=True)
        st["warnings_acknowledged"] += 1
        self._append("warning_ack", rule_id,
                     {"operator": operator.strip()})

    def heartbeat(self, rule_id, *, exercised, detail=""):
        """Heartbeat canary (R2 dryrun-blindness).

        Records that the rule's match shape was exercised (or not) by
        a synthetic canary request, distinguishing "no traffic" from
        "broken rule". The record is chained and queryable via
        ``stats()["heartbeats"]``; scheduling the canary itself is
        operator tooling (like ``flush_warn_digests``) -- the ledger
        records heartbeats, it does not emit synthetic traffic.
        Informational for graduation: graduation still requires real
        violation data; zero violations never graduate.
        """
        st = self._stats(rule_id, create=True)
        st["heartbeats"] += 1
        self._append("heartbeat", rule_id, {
            "exercised": bool(exercised),
            "detail": str(detail),
        })

    # ------------------------------------------------------------ queries

    def rule_ids(self):
        """Registered rule ids (sorted). Public for telemetry
        projection: rules with evaluations but zero violations have
        no chain records, yet the auditor needs their evaluated
        counts (dryrun-blindness evidence)."""
        return sorted(self._rules)

    def stats(self, rule_id):
        """Snapshot of a rule's telemetry (copy; never the live dict)."""
        st = self._stats(rule_id)
        if st is None:
            return None
        out = dict(st)
        out["mode_history"] = [dict(h) for h in st["mode_history"]]
        out["fp_rate"] = self._fp_rate(st)
        out["reviewed_total"] = (st["reviewed_correct"]
                                 + st["reviewed_wrong"])
        return out

    @staticmethod
    def _fp_rate(st):
        total = st["reviewed_correct"] + st["reviewed_wrong"]
        if total == 0:
            return None
        return st["reviewed_wrong"] / total

    def mode_history(self, rule_id):
        """The rule's mode-change history (oldest first)."""
        st = self._stats(rule_id)
        if st is None:
            return ()
        return tuple(dict(h) for h in st["mode_history"])

    def current_mode(self, rule_id):
        """The rule's CURRENT ladder mode (None if unregistered).

        The policy YAML declares the mode at load; graduation /
        demotion move it at runtime and the ledger is the runtime
        source of truth (every move is a chained mode_change record).
        The engine consults this -- not the static rule dict -- when
        routing decisions, so a graduated rule takes effect in the
        running engine before the governed policy-file change lands.
        """
        st = self._stats(rule_id)
        return st["mode"] if st is not None else None

    def warn_stale_rules(self, *, max_dwell_secs=WARN_MAX_DWELL_SECS,
                         now=None):
        """Rules sitting in warn beyond the max dwell (§3.4)."""
        now = float(now) if now is not None else self._now()
        out = []
        for rule_id, st in self._rules.items():
            if st["mode"] == "warn" and st["warn_since"] is not None:
                if now - st["warn_since"] > max_dwell_secs:
                    out.append(rule_id)
        return tuple(sorted(out))

    def pop_stale_escalations(self, *, max_dwell_secs=WARN_MAX_DWELL_SECS,
                             now=None):
        """Newly stale warn rules, for operator escalation (§3.4).

        Returns the stale rule_ids that have NOT been escalated yet
        in the current warn episode, and marks them escalated (so the
        caller -- the executor's per-decision operator-telemetry hook
        -- chains exactly one ``warn_stale`` audit entry per rule per
        episode). A mode change clears the mark (see
        :meth:`_apply_mode_change`).
        """
        fresh = [r for r in self.warn_stale_rules(
            max_dwell_secs=max_dwell_secs, now=now)
            if r not in self._stale_escalated]
        for r in fresh:
            self._stale_escalated.add(r)
        return tuple(fresh)

    def verify_chain(self):
        """Re-derive the hash chain. Returns (ok, reason)."""
        prev = "GENESIS"
        for rec in self._chain:
            if rec.get("prev") != prev:
                return False, ("chain broken at seq %r: prev mismatch"
                               % (rec.get("seq"),))
            digest = rec.get("digest")
            recomputed = _sha256_hex(_canonical(
                {k: v for k, v in rec.items() if k != "digest"}))
            if digest != recomputed:
                return False, ("chain broken at seq %r: digest mismatch "
                               "(tampered record)" % (rec.get("seq"),))
            prev = digest
        if prev != self._head:
            return False, "head mismatch (chain head does not match)"
        return True, "ok (%d records)" % len(self._chain)

    def verify_rule_chain(self, rule_id):
        """Re-derive one rule's own hash chain. Returns (ok, reason).

        Wave-198 §3.2: the per-rule violation ledger is independently
        verifiable -- a rule's records link via rule_seq/rule_prev
        regardless of the global interleave, and each record's digest
        covers the linkage.
        """
        prev = "GENESIS"
        expected_seq = 0
        count = 0
        for rec in self._chain:
            if rec.get("rule_id") != rule_id:
                continue
            expected_seq += 1
            count += 1
            if rec.get("rule_seq") != expected_seq:
                return False, ("rule chain broken for %r at rule_seq "
                               "%r: sequence gap" % (rule_id,
                                                     rec.get("rule_seq")))
            if rec.get("rule_prev") != prev:
                return False, ("rule chain broken for %r at rule_seq "
                               "%r: rule_prev mismatch"
                               % (rule_id, rec.get("rule_seq")))
            digest = rec.get("digest")
            recomputed = _sha256_hex(_canonical(
                {k: v for k, v in rec.items() if k != "digest"}))
            if digest != recomputed:
                return False, ("rule chain broken for %r at rule_seq "
                               "%r: digest mismatch (tampered record)"
                               % (rule_id, rec.get("rule_seq")))
            prev = digest
        if count == 0:
            return False, "no records for rule %r" % (rule_id,)
        if prev != self._rule_heads.get(rule_id):
            return False, ("rule head mismatch for %r (head does not "
                           "match)" % (rule_id,))
        return True, "ok (%d records)" % count

    # ------------------------------------------------------------ quorum

    @staticmethod
    def _check_quorum(approvers, quorum_cfg, *, minimum=GRADUATION_QUORUM):
        """Evaluate human approvers against the approvals quorum.

        ``approvers``: list of principal strings, or (principal, bool)
        vote tuples. ``quorum_cfg``: the policy's normalized
        approvals.quorum dict (or None). Returns (ok, reason).
        Malformed approver entries are a refusal, never an exception.

        Humanness provenance: when ``quorum_cfg`` is present,
        approvers must be in its eligible_principals (agents are
        excludable by simply not listing them). When None, ANY two
        distinct non-empty strings pass -- the CALLER attests they
        are human. The product boundary (PolicyEngine) therefore
        fails closed without a configured approvals.quorum; direct
        ledger use is operator tooling, where the caller is the
        attestation.
        """
        if not isinstance(approvers, (list, tuple)) or not approvers:
            return False, "no approvers supplied"
        votes = []
        for entry in approvers:
            if isinstance(entry, str):
                votes.append((entry, True))
            elif (isinstance(entry, (list, tuple)) and len(entry) == 2
                    and isinstance(entry[0], str)
                    and isinstance(entry[1], bool)):
                votes.append((entry[0], entry[1]))
            else:
                return False, ("malformed approver entry %r: must be a "
                               "principal string or (principal, bool)"
                               % (entry,))
        principals = [p.strip() for p, _ in votes]
        if any(not p for p in principals):
            return False, "empty principal in approvers"
        if len(set(principals)) != len(principals):
            return False, ("duplicate approver: one human fills one "
                           "vote slot")
        # The one-deny veto is non-negotiable (approvals L8): dissent
        # cannot be outvoted.
        for principal, approved in votes:
            if not approved:
                return False, ("deny veto by %r: dissent blocks "
                               "graduation/demotion" % (principal,))
        required = minimum
        if quorum_cfg is not None:
            eligible = quorum_cfg.get("eligible_principals") or ()
            for principal in principals:
                if principal not in eligible:
                    return False, (
                        "approver %r is not an eligible quorum principal"
                        % (principal,))
            cfg_min = quorum_cfg.get("min_approvals") or 0
            required = max(minimum, cfg_min)
        if len(principals) < required:
            return False, ("quorum not met: %d distinct approver(s), "
                           "need %d" % (len(principals), required))
        return True, "quorum met (%d approver(s))" % len(principals)

    # ------------------------------------------------------------ graduation

    def evaluate_graduation(self, rule_id, target_mode, *, approvers,
                            quorum_cfg=None, now=None):
        """Check whether a rule may graduate one rung.

        Returns (ok, reasons: list[str]). Pure evaluation -- applies
        nothing. ``approvers`` go through :meth:`_check_quorum`.
        """
        reasons = []
        st = self._stats(rule_id)
        if st is None:
            return False, ["unknown rule %r" % (rule_id,)]
        if st["pinned"]:
            return False, ["rule %r is pinned: pinned rules are "
                           "deny-only and never enter the ladder"
                           % (rule_id,)]
        current = st["mode"]
        if _NEXT_RUNG.get(current) != target_mode:
            return False, [
                "graduation is one rung at a time: %r -> %r is not a "
                "single rung (current mode %r)"
                % (current, target_mode, current)]
        # Zero violations => never graduate (dryrun-blindness guard).
        if st["violations"] == 0:
            return False, ["zero violations: cannot graduate on zero "
                           "data (dryrun-blindness guard)"]
        fp = self._fp_rate(st)
        reviewed_total = st["reviewed_correct"] + st["reviewed_wrong"]
        if target_mode == "warn":
            bar = OBSERVE_TO_WARN
            if st["evaluated"] < bar["min_evaluated"]:
                reasons.append("evaluated %d < %d"
                               % (st["evaluated"], bar["min_evaluated"]))
            if st["violations"] < bar["min_violations"]:
                reasons.append("violations %d < %d"
                               % (st["violations"], bar["min_violations"]))
            if reviewed_total < bar["min_reviewed"]:
                reasons.append("reviewed %d < %d"
                               % (reviewed_total, bar["min_reviewed"]))
            elif fp is not None and fp >= bar["max_fp_rate"]:
                reasons.append("FP rate %.3f >= %.3f"
                               % (fp, bar["max_fp_rate"]))
        else:  # target_mode == "deny"
            bar = WARN_TO_DENY
            # §3.4 "longer window": warn->deny demands strictly more
            # evidence than observe->warn.
            if st["evaluated"] < bar["min_evaluated"]:
                reasons.append("evaluated %d < %d (longer window)"
                               % (st["evaluated"], bar["min_evaluated"]))
            if st["violations"] < bar["min_violations"]:
                reasons.append("violations %d < %d (longer window)"
                               % (st["violations"], bar["min_violations"]))
            if reviewed_total < bar["min_reviewed"]:
                reasons.append("insufficient review data for FP estimate: "
                               "reviewed %d < %d"
                               % (reviewed_total, bar["min_reviewed"]))
            elif fp is not None and fp >= bar["max_fp_rate"]:
                reasons.append("FP rate %.4f >= %.4f"
                               % (fp, bar["max_fp_rate"]))
            if st["warnings_acknowledged"] < bar["min_acknowledged"]:
                reasons.append(
                    "warnings acknowledged %d < %d: no evidence "
                    "operators acted on warnings"
                    % (st["warnings_acknowledged"],
                       bar["min_acknowledged"]))
            now_f = float(now) if now is not None else self._now()
            if (st["warn_since"] is not None
                    and now_f - st["warn_since"] > WARN_MAX_DWELL_SECS):
                reasons.append(
                    "warn-stale: rule sat in warn beyond the max dwell; "
                    "demote to observe or re-attest before graduating")
        ok, qreason = self._check_quorum(approvers, quorum_cfg)
        if not ok:
            reasons.append(qreason)
        if reasons:
            return False, reasons
        return True, ["graduation %r -> %r approved: %s"
                      % (current, target_mode, qreason)]

    def apply_graduation(self, rule_id, target_mode, *, approvers,
                         quorum_cfg=None, now=None):
        """Evaluate AND apply a graduation (chained audit record)."""
        ok, reasons = self.evaluate_graduation(
            rule_id, target_mode, approvers=approvers,
            quorum_cfg=quorum_cfg, now=now)
        if not ok:
            return False, reasons
        self._apply_mode_change(rule_id, target_mode, approvers,
                                "graduation", {"reasons": reasons})
        return True, reasons

    # ------------------------------------------------------------ demotion

    def propose_demotion(self, rule_id, target_mode, *, reason,
                         requested_by):
        """Open a demotion proposal. Returns the proposal id.

        Demotion is never automatic: an FP spike creates a proposal;
        enforcement changes only on human quorum approval.
        """
        st = self._stats(rule_id)
        if st is None:
            raise ModeLedgerError("unknown rule %r" % (rule_id,))
        if st["pinned"]:
            raise ModeLedgerError(
                "rule %r is pinned: refuses demotion at any quorum"
                % (rule_id,))
        if _PREV_RUNG.get(st["mode"]) != target_mode:
            raise ModeLedgerError(
                "demotion is one rung at a time: %r -> %r is not a "
                "single rung" % (st["mode"], target_mode))
        if not isinstance(reason, str) or not reason.strip():
            raise ModeLedgerError("demotion reason must be a non-empty "
                                  "string")
        if (not isinstance(requested_by, str)
                or not requested_by.strip()):
            raise ModeLedgerError("requested_by must be a non-empty string")
        self._proposal_seq += 1
        pid = "demote-%d" % self._proposal_seq
        self._proposals[pid] = {
            "proposal_id": pid,
            "rule_id": rule_id,
            "from_mode": st["mode"],
            "target_mode": target_mode,
            "reason": reason.strip(),
            "requested_by": requested_by.strip(),
            "status": "open",
            "at": self._now(),
        }
        self._append("demotion_proposed", rule_id, {
            "proposal_id": pid,
            "from_mode": st["mode"],
            "target_mode": target_mode,
            "reason": reason.strip(),
            "requested_by": requested_by.strip(),
        })
        return pid

    def approve_demotion(self, proposal_id, *, approvers, quorum_cfg=None):
        """Quorum-approve a demotion proposal and apply it."""
        prop = self._proposals.get(proposal_id)
        if prop is None:
            return False, ["unknown proposal %r" % (proposal_id,)]
        if prop["status"] != "open":
            return False, ["proposal %r is not open (status %r)"
                           % (proposal_id, prop["status"])]
        rule_id = prop["rule_id"]
        st = self._stats(rule_id)
        if st["pinned"]:
            return False, ["rule %r is pinned: refuses demotion at any "
                           "quorum" % (rule_id,)]
        if st["mode"] != prop["from_mode"]:
            return False, ["rule mode changed since proposal (%r != %r); "
                           "re-propose" % (st["mode"], prop["from_mode"])]
        ok, qreason = self._check_quorum(approvers, quorum_cfg)
        if not ok:
            return False, [qreason]
        prop["status"] = "approved"
        self._apply_mode_change(rule_id, prop["target_mode"], approvers,
                                "demotion", {"proposal_id": proposal_id,
                                             "reason": prop["reason"]})
        return True, ["demotion %r approved: %s" % (proposal_id, qreason)]

    def emergency_demote(self, rule_id, target_mode, *, operator, reason):
        """Single-operator emergency demotion (blocking prod NOW).

        Allowed, but mandates post-hoc quorum review within 24h; both
        the demotion and the review deadline are chained. Returns the
        record.
        """
        st = self._stats(rule_id)
        if st is None:
            raise ModeLedgerError("unknown rule %r" % (rule_id,))
        if st["pinned"]:
            raise ModeLedgerError(
                "rule %r is pinned: refuses demotion at any quorum"
                % (rule_id,))
        if _PREV_RUNG.get(st["mode"]) != target_mode:
            raise ModeLedgerError(
                "demotion is one rung at a time: %r -> %r is not a "
                "single rung" % (st["mode"], target_mode))
        if not isinstance(operator, str) or not operator.strip():
            raise ModeLedgerError("operator must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise ModeLedgerError("reason must be a non-empty string")
        deadline = self._now() + EMERGENCY_REVIEW_SECS
        self._emergency_seq += 1
        st["pending_emergency_review"] = {
            "rule_id": rule_id,
            "demoted_to": target_mode,
            "operator": operator.strip(),
            "deadline": deadline,
            "demotion_seq": self._emergency_seq,
        }
        self._apply_mode_change(rule_id, target_mode, [operator.strip()],
                                "emergency_demotion",
                                {"reason": reason.strip(),
                                 "review_deadline": deadline})
        return dict(st["pending_emergency_review"])

    def check_emergency_reviews(self, *, now=None):
        """Overdue post-hoc reviews (failure to review re-escalates).

        Returns a tuple of pending-review dicts whose deadline passed.
        The caller routes them to the review inbox.
        """
        now_f = float(now) if now is not None else self._now()
        overdue = []
        for rule_id, st in self._rules.items():
            pending = st.get("pending_emergency_review")
            if pending is not None and now_f > pending["deadline"]:
                overdue.append(dict(pending))
        return tuple(overdue)

    def pop_overdue_emergency_reviews(self, *, now=None):
        """Newly overdue post-hoc reviews, for re-escalation (§3.5).

        Returns the overdue pending-review dicts that have NOT been
        escalated yet, and marks them escalated (one
        ``emergency_review_overdue`` audit entry per demotion -- the
        dedup key is the per-demotion seq, so a second emergency
        demotion re-escalates on its own deadline).
        :meth:`resolve_emergency_review` clears the mark.
        """
        fresh = [p for p in self.check_emergency_reviews(now=now)
                 if p.get("demotion_seq") not in self._overdue_escalated]
        for p in fresh:
            if p.get("demotion_seq") is not None:
                self._overdue_escalated.add(p["demotion_seq"])
        return tuple(fresh)

    def resolve_emergency_review(self, rule_id, *, approvers,
                                 quorum_cfg=None):
        """Record the post-hoc quorum review of an emergency demotion."""
        st = self._stats(rule_id)
        if st is None:
            return False, ["unknown rule %r" % (rule_id,)]
        pending = st.get("pending_emergency_review")
        if pending is None:
            return False, ["no pending emergency review for %r"
                           % (rule_id,)]
        ok, qreason = self._check_quorum(approvers, quorum_cfg)
        if not ok:
            return False, [qreason]
        st["pending_emergency_review"] = None
        # The post-hoc review landed: a future emergency demotion of
        # this rule gets a fresh escalation.
        self._overdue_escalated.discard(pending.get("demotion_seq"))
        self._append("emergency_reviewed", rule_id, {
            "approvers": sorted(
                p[0] if isinstance(p, (list, tuple)) else p
                for p in approvers),
        })
        return True, ["emergency demotion of %r reviewed: %s"
                      % (rule_id, qreason)]

    # ------------------------------------------------------------ apply

    def _apply_mode_change(self, rule_id, new_mode, approvers, kind,
                           extra):
        st = self._stats(rule_id, create=True)
        old_mode = st["mode"]
        at = self._now()
        approver_names = sorted(
            (p[0].strip() if isinstance(p, (list, tuple)) else p.strip())
            for p in approvers)
        # §3.5: every mode change is a chained audit event with rule
        # id, old->new mode, approvers, AND the FP stats snapshot --
        # so an auditor replaying the chain sees the evidence the
        # quorum acted on, not just the outcome.
        reviewed_total = st["reviewed_correct"] + st["reviewed_wrong"]
        entry = {
            "old_mode": old_mode,
            "new_mode": new_mode,
            "at": at,
            "approvers": approver_names,
            "kind": kind,
            "stats": {
                "evaluated": st["evaluated"],
                "violations": st["violations"],
                "reviewed": reviewed_total,
                "reviewed_correct": st["reviewed_correct"],
                "reviewed_wrong": st["reviewed_wrong"],
                "fp_rate": self._fp_rate(st),
            },
        }
        entry.update(extra or {})
        st["mode"] = new_mode
        st["mode_history"].append(entry)
        if new_mode == "warn":
            st["warn_since"] = at
        elif old_mode == "warn":
            st["warn_since"] = None
        # A mode change ends any stale episode: a future warn dwell
        # gets a fresh escalation.
        self._stale_escalated.discard(rule_id)
        self._append("mode_change", rule_id, entry)


class WarnDigestAggregator:
    """Per-rule-per-window warn digest (R1 warn-fatigue).

    A warn-mode rule firing 1000x in a window produces ONE operator
    digest, not 1000 interrupts. Pure aggregation (no I/O): the caller
    wires flushed digests to the audit log. Clock-injectable for
    tests. Window rolls on record: a record landing in a new window
    flushes the previous window's digest first.
    """

    def __init__(self, *, window_secs=300, clock=None, max_samples=3):
        if window_secs <= 0:
            raise ModeLedgerError("window_secs must be positive")
        self._window = float(window_secs)
        self._clock = clock or time.time
        self._max_samples = int(max_samples)
        self._buckets = {}  # rule_id -> bucket dict

    def _now(self):
        return float(self._clock())

    def record(self, *, rule_id, nominal_effect, warning, now=None):
        """Record one warning. Returns a list of due digests (0-1).

        A record that lands in a new window flushes the previous
        window's digest for that rule first.
        """
        now_f = float(now) if now is not None else self._now()
        if not isinstance(rule_id, str) or not rule_id:
            raise ModeLedgerError("rule_id must be a non-empty string")
        due = []
        bucket = self._buckets.get(rule_id)
        if bucket is not None and now_f - bucket["window_start"] >= self._window:
            due.append(self._digest(rule_id, bucket))
            del self._buckets[rule_id]
            bucket = None
        if bucket is None:
            bucket = {
                "window_start": now_f,
                "window_end": now_f + self._window,
                "count": 0,
                "nominal_effect": nominal_effect,
                "samples": [],
            }
            self._buckets[rule_id] = bucket
        bucket["count"] += 1
        if len(bucket["samples"]) < self._max_samples:
            bucket["samples"].append(str(warning))
        return due

    def flush_due(self, *, now=None):
        """Flush buckets whose window has rolled. Returns digests."""
        now_f = float(now) if now is not None else self._now()
        due = []
        for rule_id in sorted(self._buckets):
            bucket = self._buckets[rule_id]
            if now_f - bucket["window_start"] >= self._window:
                due.append(self._digest(rule_id, bucket))
                del self._buckets[rule_id]
        return due

    def flush_all(self):
        """Flush every open bucket (operator tooling / tests)."""
        due = [self._digest(rule_id, self._buckets[rule_id])
               for rule_id in sorted(self._buckets)]
        self._buckets.clear()
        return due

    @staticmethod
    def _digest(rule_id, bucket):
        return {
            "rule_id": rule_id,
            "window_start": bucket["window_start"],
            "window_end": bucket["window_end"],
            "count": bucket["count"],
            "nominal_effect": bucket["nominal_effect"],
            "samples": list(bucket["samples"]),
        }
