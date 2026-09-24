"""Capability-measurement harness for the Safeguard Benchmark (§2a).

Deployment-level capability inventory (governed tool surface, autonomy
posture, egress posture), capability deltas between log checkpoints
(the RSI-relevant capability-gain proxy — labeled explicitly as a
proxy, not model-capability measurement), and the human-review gate:
``gate()`` refuses to proceed when the delta meets/exceeds the
human-review threshold, logs the refusal, and emits an approval ticket
into the ``gov/approvals.py`` queue.

WIRING STATE (honest): no production code path calls ``gate()`` yet —
``measure()`` is consumed at report time by
``gov/safeguard_benchmark.py``, and no runtime loop measures
capability deltas between checkpoints. The gate seam is available and
integration-tested against the real ``ApprovalQueue`` (F42
caller-identity contract, real ``PolicyDecision``); it is UNWIRED
pending a production delta-measurement loop. Nothing here claims
otherwise.

Honesty contract (inherited from gov/evidence_exports.py): every
rendered field carries provenance; unknowable fields are null with
``operator_must_supply: true``; the harness refuses to measure when
the log chain does not verify.

$0 spend, synthetic/local only. No network.
"""

from __future__ import annotations

from gov import log as _log
from gov.safeguard_benchmark import DEFAULT_THRESHOLDS


class CapabilityMeasureError(Exception):
    """Fail-closed: unverifiable chain, corrupt ledger, malformed input."""


def _op(note):
    return {"kind": "operator_must_supply", "note": note}


def _field(value, provenance):
    return {"value": value, "provenance": provenance}


def _logprov_window(from_seq, to_seq, count):
    return {"kind": "log_window", "from_seq": from_seq, "to_seq": to_seq,
            "count": count}


class CapabilityHarness:
    """Inventory, delta measurement, and human-review gating."""

    #: Intervention-point events the oversight section recognizes.
    INTERVENTION_EVENTS = frozenset({
        "approval_decision", "approval_break_glass", "ticket_consumed",
        "quorum_opened", "approval_batch_abort", "post_review_resolved",
    })

    def __init__(self, log_path, *, discovery_ledger_path=None):
        self.log_path = str(log_path)
        self.discovery_ledger_path = (str(discovery_ledger_path)
                                      if discovery_ledger_path else None)
        self._entries = None

    # -- log handling -------------------------------------------------

    def _load_verified(self, at_seq=None):
        entries = _log.read_entries(self.log_path)
        if not entries:
            raise CapabilityMeasureError("log is empty: nothing to measure")
        ok, broken_seq, _count = _log.verify_chain(self.log_path)
        if not ok:
            raise CapabilityMeasureError(
                "refusing to measure: audit-log chain does not verify "
                "(broken at seq %s)" % (broken_seq,))
        if at_seq is not None:
            entries = [e for e in entries if e["seq"] <= at_seq]
        self._entries = entries
        return entries

    # -- inventory ----------------------------------------------------

    def inventory(self, at_seq=None):
        """Tool surface + autonomy posture + egress posture.

        All log-derived; fields no log entry can supply are null with
        ``operator_must_supply`` provenance.
        """
        entries = self._load_verified(at_seq)
        from_seq = entries[0]["seq"]
        to_seq = entries[-1]["seq"]

        tools = sorted({e["tool"] for e in entries
                        if isinstance(e.get("tool"), str)})
        tool_surface = _field(
            {"observed_tools": tools, "tool_count": len(tools)},
            _logprov_window(from_seq, to_seq, len(entries)))

        candidates = self._unregistered_candidates()

        autonomy = self._autonomy_posture(entries, from_seq, to_seq)
        egress = self._egress_posture(entries, from_seq, to_seq)

        return {
            "tool_surface": tool_surface,
            "unregistered_candidates": candidates,
            "autonomy_posture": _field(autonomy, _logprov_window(
                from_seq, to_seq, len(entries))),
            "egress_posture": egress,
        }

    def _unregistered_candidates(self):
        from gov.discovery import (DiscoveryLedger, LedgerCorruptError)
        if not self.discovery_ledger_path:
            return _field(None, _op(
                "no DiscoveryLedger wired: unregistered-agent candidates "
                "cannot be inventoried; wire discovery_ledger_path or "
                "supply the inventory"))
        try:
            ledger = DiscoveryLedger(self.discovery_ledger_path)
            views = ledger.candidates(status="candidate")
        except LedgerCorruptError as e:
            raise CapabilityMeasureError(
                "discovery ledger corrupt: %s" % (e,))
        return _field(
            [{"candidate_id": v["candidate_id"],
              "status": "candidate",
              "first_seen": v["first_seen"],
              "last_seen": v["last_seen"],
              "strength": v["strength"],
              "signal_kinds": sorted({s["kind"]
                                      for s in v["signals"]}),
              "sources": sorted({s["source"] for s in v["signals"]})}
             for v in views],
            {"kind": "discovery_ledger",
             "path": self.discovery_ledger_path,
             "status": "candidate"})

    def _autonomy_posture(self, entries, from_seq, to_seq):
        from gov.rules_tiering import TieringError, session_tier
        tools = {e["tool"] for e in entries
                 if isinstance(e.get("tool"), str)}
        try:
            tier, axes = session_tier(tools)
            tier_field = _field(tier, {"kind": "computed",
                                       "from": "session_tier over "
                                               "observed tool grants"})
        except TieringError as e:
            # An unclassified tool understates the tier — fail closed
            # to operator supply rather than under-reporting.
            tier_field = _field(None, _op(
                "session tier not computable: %s" % (e,)))
            axes = frozenset()
        delegation = sum(1 for e in entries
                         if "delegation_token" in str(e.get("event", "")))
        leases = sum(1 for e in entries
                     if "lease" in str(e.get("event", "")).lower())
        cage = self._cage_mode(entries)
        return {
            "session_tier": tier_field,
            "axes_observed": sorted(axes),
            "delegation_tokens_issued": _field(
                delegation, _logprov_window(from_seq, to_seq,
                                            len(entries))),
            "capability_leases": _field(
                leases, _logprov_window(from_seq, to_seq, len(entries))),
            "sandbox_cage_mode": cage,
        }

    def _cage_mode(self, entries):
        hits = [e for e in entries
                if "cage" in str(e.get("event", "")).lower()]
        if not hits:
            return _field(None, _op(
                "no sandbox cage-mode event in the log: filtered-egress "
                "cage status is unknowable from this log; the operator "
                "must supply it (F81 NetnsWallProvider status where "
                "deployed)"))
        last = hits[-1]
        return _field(
            {"mode": last.get("event"), "seq": last["seq"],
             "ts": last["ts"]},
            {"kind": "log", "seq": last["seq"], "hash": last["hash"]})

    def _egress_posture(self, entries, from_seq, to_seq):
        from gov.egress_ledger import registered_domain
        domains = set()
        for e in entries:
            dom = e.get("domain")
            if isinstance(dom, str) and dom:
                domains.add(dom)
                continue
            ep = e.get("endpoint")
            if isinstance(ep, str) and ep:
                try:
                    domains.add(registered_domain(ep))
                except Exception:
                    continue  # unparseable endpoint: not evidence
        if not domains:
            return _field(None, _op(
                "no egress domains observed in the log window; the "
                "operator must supply the egress posture"))
        return _field(
            {"domains": sorted(domains),
             "domain_count": len(domains)},
            _logprov_window(from_seq, to_seq, len(entries)))

    # -- delta measurement --------------------------------------------

    def measure(self, from_seq, to_seq):
        """Capability delta between two log checkpoints.

        Returns a provenance-tagged delta record: tools added, tier
        transitions, unregistered-candidate delta, egress delta, and
        the weighted delta_score (weights from DEFAULT_THRESHOLDS).
        """
        before = self.inventory(at_seq=from_seq)
        after = self.inventory(at_seq=to_seq)

        def _tools(inv):
            return set(inv["tool_surface"]["value"]["observed_tools"])

        tools_added = sorted(_tools(after) - _tools(before))

        def _tier(inv):
            return inv["autonomy_posture"]["value"][
                "session_tier"]["value"]

        tier_from, tier_to = _tier(before), _tier(after)
        tier_from = tier_from or "unknown"
        tier_to = tier_to or "unknown"
        tier_transition = [tier_from, tier_to]

        def _cand_count(inv):
            v = inv["unregistered_candidates"]["value"]
            return None if v is None else len(v)

        cb, ca = _cand_count(before), _cand_count(after)
        new_unregistered = (None if cb is None or ca is None
                            else max(0, ca - cb))

        def _domains(inv):
            v = inv["egress_posture"]["value"]
            return set() if v is None else set(v["domains"])

        new_egress = sorted(_domains(after) - _domains(before))

        w = DEFAULT_THRESHOLDS["delta_weights"]
        score = (w["tool_added"] * len(tools_added)
                 + w["new_unregistered_candidate"]
                 * (new_unregistered or 0)
                 + w["new_egress_domain"] * len(new_egress))
        if (tier_from, tier_to) == ("standard", "elevated"):
            score += w["tier_transition_to_elevated"]
        score = float(score)

        record = {
            "from_seq": from_seq, "to_seq": to_seq,
            "tools_added": tools_added,
            "tools_added_count": len(tools_added),
            "tier_transition": tier_transition,
            "new_unregistered_candidates": new_unregistered,
            "new_egress_domains": new_egress,
            "delta_score": score,
            "score_weights": dict(w),
        }
        return _field(record, {
            "kind": "log_window", "from_seq": from_seq,
            "to_seq": to_seq,
            "formula": ("delta_score = sum(delta_weights x components); "
                        "tier standard->elevated adds the transition "
                        "weight"),
            "thresholds_version":
                DEFAULT_THRESHOLDS["thresholds_version"],
        })

    # -- human-review gate --------------------------------------------

    #: Action tool name stamped on gate tickets (idempotency matching
    #: keys on this + the delta window in action args).
    GATE_ACTION_TOOL = "capability_harness.gate"

    #: Policy id / flag carried on gate tickets.
    GATE_POLICY_ID = "capability-delta-human-review"

    @staticmethod
    def _open_gate_ticket(queue, window):
        """Id of a still-open gate ticket for the same delta window, or
        None. Duck-typed: queues without a ``pending()`` listing (e.g.
        test doubles) skip the check."""
        pending = queue.pending() if hasattr(queue, "pending") else []
        for r in pending:
            if r.get("tool") != CapabilityHarness.GATE_ACTION_TOOL:
                continue
            w = (r.get("args") or {}).get("window") or {}
            if (w.get("from_seq") == window["from_seq"]
                    and w.get("to_seq") == window["to_seq"]):
                return r.get("id")
        return None

    def gate(self, delta, thresholds=None, queue=None,
             caller_identity=None):
        """The human-review gate (spec §2a, highest-point new seam).

        Returns ``{"proceed": bool, "approval_required": ticket_spec |
        None}``. When ``delta_score >= thresholds["human_review_delta"]``
        the harness REFUSES to proceed and emits an approval ticket
        into the ``gov/approvals.py`` queue. An ``approval_decision``
        event is required before automated research / research-adjacent
        tool use continues.

        Real-queue contract (F42): ``queue`` must be a
        ``gov/approvals.py``-compatible queue and ``caller_identity``
        an ``AgentIdentity`` its identity verifier accepts — the
        harness cannot mint identities, so whoever wires this gate into
        production supplies one (executor-minted, or the deployment's
        provisioned governance identity). ``queue`` without
        ``caller_identity`` is refused fail-closed. The ticket carries
        a real ``PolicyDecision`` (``policy_id`` =
        ``"capability-delta-human-review"``), not a string.

        The gate is idempotent per delta window: a repeated
        above-threshold call while the ticket is still open reuses the
        open ticket (``idempotent_reuse: True``) instead of flooding
        the queue and the audit log. Ordering is queue-first: the
        refusal is appended to the audit log only after the ticket
        exists, carrying its ``approval_id`` — a failed ``queue()``
        audits ``capability_gate_ticket_failed`` and re-raises, so the
        log never records a refusal with no ticket.

        WIRING HONESTY: no production code path calls ``gate()`` yet
        (``measure()`` is used at report time by
        ``gov/safeguard_benchmark.py``; no runtime loop measures
        capability deltas between checkpoints). The seam is available
        and integration-tested against the real ``ApprovalQueue``;
        it is UNWIRED pending a production delta-measurement loop.
        """
        thresholds = thresholds or DEFAULT_THRESHOLDS
        score = float(delta["value"]["delta_score"])
        limit = float(thresholds["human_review_delta"])
        if score < limit:
            return {"proceed": True, "approval_required": None}
        if queue is not None and caller_identity is None:
            raise CapabilityMeasureError(
                "gate() with a queue requires caller_identity: an "
                "AgentIdentity the queue's identity verifier accepts "
                "(F42 fail-closed). The harness cannot mint identities; "
                "the production wiring must supply one.")
        rec = delta["value"]
        window = {"from_seq": rec.get("from_seq"),
                  "to_seq": rec.get("to_seq")}
        ticket_spec = {
            "kind": "capability_delta_review",
            "delta_score": score,
            "human_review_threshold": limit,
            "window": window,
            "components": {
                "tools_added": rec.get("tools_added", []),
                "tier_transition": rec.get("tier_transition"),
                "new_unregistered_candidates":
                    rec.get("new_unregistered_candidates"),
                "new_egress_domains": rec.get("new_egress_domains", []),
            },
            "reason": ("capability delta score %.1f meets/exceeds the "
                       "human-review threshold %.1f: mandatory human "
                       "review before automated research continues"
                       % (score, limit)),
            "required_event": "approval_decision",
            "thresholds_version": thresholds["thresholds_version"],
        }
        if queue is not None:
            existing = self._open_gate_ticket(queue, window)
            if existing is not None:
                ticket_spec["approval_id"] = existing
                ticket_spec["idempotent_reuse"] = True
                return {"proceed": False,
                        "approval_required": ticket_spec}
            from gov.policy import PolicyDecision
            decision = PolicyDecision(
                "require_approval", ticket_spec["reason"],
                policy_id=self.GATE_POLICY_ID,
                flag="capability_delta_review")
            try:
                approval_id = queue.queue(
                    action={"tool": self.GATE_ACTION_TOOL,
                            "args": {"window": window,
                                     "delta_score": score},
                            "kind": "capability_delta_review",
                            "delta_score": score,
                            "window": window,
                            "components": ticket_spec["components"]},
                    decision=decision,
                    provenance="capability_harness",
                    policy_flag=self.GATE_POLICY_ID,
                    preview=("Capability delta %.1f >= human-review "
                             "threshold %.1f; human review required "
                             "before automated research continues."
                             % (score, limit)),
                    caller_identity=caller_identity)
            except Exception as e:
                # The refusal is NOT logged: without a ticket the log
                # must not claim one. The emission failure itself is
                # audited, then the error propagates (fail-closed: the
                # caller never gets a proceed=True it didn't earn).
                _log.ActionLog(self.log_path).append({
                    "event": "capability_gate_ticket_failed",
                    "delta_score": score,
                    "human_review_threshold": limit,
                    "window": window,
                    "error": "%s: %s" % (type(e).__name__, e),
                })
                raise
            ticket_spec["approval_id"] = approval_id
        # Queue-first: the refusal audit always references a real
        # ticket (approval_id None only when no queue was supplied).
        _log.ActionLog(self.log_path).append({
            "event": "capability_gate_refused",
            "delta_score": score,
            "human_review_threshold": limit,
            "ticket_kind": "capability_delta_review",
            "approval_id": ticket_spec.get("approval_id"),
            "window": window,
            "reason": ticket_spec["reason"],
        })
        return {"proceed": False, "approval_required": ticket_spec}
