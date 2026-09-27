"""Goal registration + deterministic conflict detection (row 11).

Row 11's pinned gap (H15, wave-122): no standing-goal registration, no
goal-conflict detection -- an agent can pursue an objective that
contradicts another agent's (or the user's) registered objective and
nothing registers or detects the conflict. This module closes the
*registration* half: agents (or the orchestrator on their behalf)
declare structured goals, and the registry deterministically detects
three conflict classes against active goals:

  1. ``contradiction`` -- direct opposition on the same target
     (delete vs preserve/retain), via an explicit opposition table.
  2. ``resource_contention`` -- two claims of exclusive_write on the
     same target, or exclusive_write vs a plain write (exclusivity
     violated by any other writer).
  3. ``constraint_violation`` -- a new goal's effect matches an
     existing goal's ``forbid`` constraint (checked both directions:
     the new goal's constraints against existing goals' effects too).

What this is NOT (honest ceiling):
- Not semantic. The detector reasons over STRUCTURED effect atoms
  ``(verb, target)`` with exact normalized-target matching, plus a
  wave-136 paraphrase-tolerant similarity tier for the cross-run
  laundering cover leg (gov/target_match.py: token-overlap,
  destination-vetoed, threshold 0.5, always auditable via
  match_score/match_method). Full synonym replacement with no shared
  tokens still dodges the matcher by construction -- deterministic
  contradiction != semantic contradiction. The natural-language
  ``description`` is for humans and the audit trail; it is never used
  for matching (matching on prose would be heuristic,
  unexplainable, and FP-prone).
- Cross-run is persistence + history, not intent. ``save``/``load``
  make the registry durable across runs (tamper-evident), and
  ``detect_cross_run_laundering`` flags when a new registration
  legitimizes behavior that violated the agent's own prior
  registration, contradicts its executed history, composes into a
  conflict with a previous run's still-active goal, re-registers
  an identical-but-never-exercised goal across runs (dormant cover),
  or re-mints a denied goal with a fresh ID (wave-139): a new
  registration whose every effect atom matches a same-agent
  superseded (denied/withdrawn, never exercised) prior-run goal's
  atom -- same verb, token-tversky target similarity >=
  FRESH_ID_SIMILARITY_THRESHOLD (gov/target_match.py
  DEFAULT_THRESHOLD, no new similarity) -- is flagged LOUD as
  ``fresh_id_laundering``, regardless of the fresh goal ID. The
  fresh-ID leg is FP-averse by design: silent without observed
  executed history, silent when the prior's run is unobserved,
  silent when the prior was exercised before supersede (the
  legitimate register -> exercise -> resolve flow), and conjunctive
  per-atom (a verb-differing or extra unmatched new atom breaks the
  match, so target similarity alone never condemns).
  Deliberate, FP-averse narrowings (not oversights): the dormant
  signal fires only for goals declaring high-impact effects
  (send/write/delete/exclusive_write) -- a never-exercised
  read-only goal is normal operations, not cover -- and only when
  executed history is supplied (without history, "dormant" is
  indistinguishable from "unobserved", so the signal stays silent
  rather than fire blind).
  What it cannot see: full synonym replacement with no shared
  tokens (token overlap is not semantics -- the wave-136 residual,
  unchanged by the fresh-ID leg), semantic laundering ("archive" in
  run 1 vs "compress" in run 2 meaning the same data), a denied goal
  aged out of the persisted store (recency is bounded by the
  detector's prior-goals scope), and any agent that rotates its
  agent_id every run (cross-run attribution keys on stable agent
  identity -- a fresh identity per run defeats it).
- Not an enforcer. Registration never denies: conflicts are flagged
  LOUD (``goal_conflict`` audit event) and routed to the approval
  queue for human resolution. The executor's ``register_goal`` is the
  wiring point.
- Wave-135 (row-11): vague-goal specificity. A goal whose declared
  effects are empty or carry a ``"*"`` wildcard target registers in
  ``pending_specificity`` -- it covers NOTHING (gov.goal_audit
  treats it as uncovered) until a human narrows it
  (``GoalRegistry.narrow`` -- a fresh registration, since the chain
  is append-only) or explicitly acknowledges its breadth
  (``resolve_specificity`` via a ``goal_specificity_review``
  approval decision, which sets ``broad_scope_acknowledged`` and
  makes every later ``goal_wildcard_cover`` for that goal LOUD).
  The check is structural, not semantic: a specific-looking goal
  that is semantically broad still passes (paraphrase ceiling).
  And a human can acknowledge a maliciously broad goal without
  reading (judgment ceiling -- same as wave-134's wiring).

$0, stdlib only, deterministic. Effect/constraint validation is
fail-closed: unknown verbs raise ValueError rather than being
silently accepted (a silently-unreasoned-about verb would be a gap).

Goal records chain via ``prev_goal_digest`` (SHA-256 over the
canonical record), forming a goal sub-chain: tampering with a
registered goal breaks the chain. The digest deliberately EXCLUDES
the mutable ``status`` field: ``set_status`` changes only live
status (itself audited via ``goal_status_changed`` events), never
the chained history -- a resolved goal must not read as "tampered"
when the registry is verified or reloaded in a later run.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from .target_match import (DEFAULT_THRESHOLD, MATCH_METHOD, match_target,
                          target_similarity)

__all__ = [
    "EFFECT_VERBS",
    "DORMANT_RUN_THRESHOLD",
    "FRESH_ID_SIMILARITY_THRESHOLD",
    "GoalPersistenceError",
    "GoalRegistry",
    "check_specificity",
    "detect_conflict",
    "detect_cross_run_laundering",
    "normalize_target",
]

# The structured effect vocabulary. Verbs outside this set are refused
# at registration (fail-closed): the detector can only reason about
# verbs it understands, and silently accepting an unknown verb would
# create an unreasoned-about gap.
EFFECT_VERBS = (
    "delete",
    "preserve",
    "retain",
    "write",
    "read",
    "exclusive_write",
    "send",
)

# Opposition table (symmetric): verb -> verbs it directly contradicts
# on the SAME normalized target.
_OPPOSES = {
    "delete": frozenset({"preserve", "retain"}),
    "preserve": frozenset({"delete"}),
    "retain": frozenset({"delete"}),
}

_GOAL_VERSION = 1

#: Registrations across this many distinct runs (including the
#: current one) of a materially identical goal that the agent never
#: exercised trigger the dormant-goal signal.
DORMANT_RUN_THRESHOLD = 3

#: Fresh-ID laundering threshold (wave-139, row-11). This is NOT a
#: new similarity: it is gov/target_match.py's DEFAULT_THRESHOLD
#: (0.5), stated here as a named constant so the seam is auditable.
#: A new goal is treated as a fresh-ID re-mint of a same-principal
#: superseded prior-run goal when EVERY declared effect atom of the
#: new goal matches an atom of the prior goal with the same verb and
#: token-tversky target similarity >= this threshold. The 0.5 value
#: carries target_match.py's measured FP/FN tradeoff (battery
#: paraphrase pairs >= 0.571, unrelated pairs <= 0.0, margin on both
#: sides); the fresh-ID battery pins the boundary end-to-end
#: (0.800 and 0.500 caught, 0.400 and 0.000 missed by design).
FRESH_ID_SIMILARITY_THRESHOLD = DEFAULT_THRESHOLD

#: Fields excluded from the goal digest: mutable live state that is
#: itself audited (goal_status_changed events) and must not read as
#: "tampered" when the chain is verified after a status change or a
#: cross-run reload. ``broad_scope_acknowledged`` (wave-135) joins
#: ``status``: it flips from False to True when a human acknowledges
#: a vague goal's breadth via goal_specificity_review, and that flip
#: is chained as a goal_specificity_resolved event -- including it in
#: the digest would read the human's own resolution as tampering.
_MUTABLE_DIGEST_EXCLUSIONS = frozenset({"goal_digest", "status",
                                       "broad_scope_acknowledged"})


class GoalPersistenceError(ValueError):
    """Fail-closed persistence error: the goal store on disk is
    missing, malformed, or tampered with. Subclasses ValueError so
    existing fail-closed handling keeps working."""


def _record_digest(record, prev_digest):
    """Digest over the canonical record minus mutable/excluded fields,
    bound to the previous chain digest."""
    body = {k: v for k, v in record.items()
            if k not in _MUTABLE_DIGEST_EXCLUSIONS}
    return _sha256_hex(_canonical(body) + prev_digest)


def _canonical(obj):
    """Canonical JSON for hashing (stable key order, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=repr)


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_target(target):
    """Normalize a target string for exact matching.

    Lowercase, strip, collapse internal whitespace. Deliberately NOT
    fuzzy: "temp files" != "temp_files" != "temporary storage". The
    detector's contract is exact normalized matching; anything looser
    would be heuristic and unexplainable. Documented, not hidden.
    """
    return " ".join(str(target).lower().split())


def _check_verb_target(atom, what):
    """Shared core for effect/history atom validation: a (verb,
    target) pair whose verb is in the EFFECT_VERBS vocabulary.
    Fail-closed: malformed atoms or unknown verbs raise ValueError."""
    if (not isinstance(atom, (tuple, list))) or len(atom) != 2:
        raise ValueError(
            "%s must be a (verb, target) pair, got %r" % (what, atom))
    verb, target = atom
    if verb not in EFFECT_VERBS:
        raise ValueError(
            "unknown %s verb %r: known verbs are %s"
            % (what, verb, ", ".join(EFFECT_VERBS)))
    return (verb, target)


def _check_effect(atom):
    """Validate one effect atom (verb, target). Returns normalized."""
    verb, target = _check_verb_target(atom, "effect")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("effect target must be a non-empty string, "
                         "got %r" % (target,))
    return (verb, normalize_target(target))


def _check_constraint(atom):
    """Validate one constraint atom ("forbid", verb, target)."""
    if (not isinstance(atom, (tuple, list))) or len(atom) != 3:
        raise ValueError(
            "constraint must be a (\"forbid\", verb, target) triple, "
            "got %r" % (atom,))
    kind, verb, target = atom
    if kind != "forbid":
        raise ValueError("unknown constraint kind %r: only \"forbid\" "
                         "is supported" % (kind,))
    if verb not in EFFECT_VERBS:
        raise ValueError(
            "unknown constraint verb %r: known verbs are %s"
            % (verb, ", ".join(EFFECT_VERBS)))
    if not isinstance(target, str) or not target.strip():
        raise ValueError("constraint target must be a non-empty string, "
                         "got %r" % (target,))
    return ("forbid", verb, normalize_target(target))


def check_specificity(goal):
    """Wave-135 (row-11): registration-time specificity check.

    ``goal`` is a dict (or goal record) with ``"effects"`` -- a list
    of (verb, target) atoms, normalized or not. Returns
    ``(vague, reasons)`` where ``vague`` is True when the declared
    objective is too broad for the detector to reason about:

    * no declared effects at all -- the goal declares nothing the
      coverage auditor can match against;
    * any effect whose target is missing, empty, or the ``"*"``
      wildcard -- an unbounded effect atom.

    Deliberately STRUCTURAL, not semantic: a "specific-looking" goal
    (``("send", "vendor.example.com")`` that in practice means "send
    anything anywhere") passes the check. Semantic laundering is the
    documented paraphrase ceiling -- this check closes the
    *mechanical* vagueness (empty/wildcard), not the semantic kind.

    Never raises on malformed atoms: an unparseable effect is itself
    a vagueness reason (fail-closed toward "vague", since a goal the
    checker cannot parse is a goal the auditor cannot reason about).
    """
    reasons = []
    effects = goal.get("effects") if isinstance(goal, dict) else None
    if not effects:
        reasons.append(
            "no declared effects: the goal declares nothing the "
            "coverage auditor can match an action against")
        return True, reasons
    for atom in effects:
        verb = target = None
        if isinstance(atom, (tuple, list)) and len(atom) == 2:
            verb, target = atom
        t = normalize_target(str(target)) if target is not None else ""
        if not t or t == "*":
            reasons.append(
                "effect (%r %r) is unbounded: a missing, empty, or "
                "\"*\" target covers every action of that verb"
                % (verb, target))
    return (bool(reasons), reasons)


def detect_conflict(new_goal, existing_goals):
    """Detect conflicts between a new goal and existing goals.

    ``new_goal`` and each of ``existing_goals`` are dicts with
    ``"goal_id"``, ``"effects"`` (list of (verb, target) with
    NORMALIZED targets), and ``"constraints"`` (list of
    ("forbid", verb, normalized target)).

    Returns a list of conflict dicts, each with ``type``,
    ``new_goal_id``, ``existing_goal_id``, ``detail``, and a
    human-readable ``explanation``. Empty list = no conflict.
    Deterministic and explainable: every conflict names the exact
    atoms that collided.
    """
    conflicts = []
    new_id = new_goal.get("goal_id", "<unknown>")
    new_effects = new_goal.get("effects") or []
    new_constraints = new_goal.get("constraints") or []

    for existing in existing_goals or []:
        if not isinstance(existing, dict):
            continue
        if existing.get("status", "active") != "active":
            continue
        ex_id = existing.get("goal_id", "<unknown>")
        ex_effects = existing.get("effects") or []
        ex_constraints = existing.get("constraints") or []

        # 1. Direct contradiction on the same target.
        for v1, t1 in new_effects:
            for v2, t2 in ex_effects:
                if t1 == t2 and v2 in _OPPOSES.get(v1, ()):
                    conflicts.append({
                        "type": "contradiction",
                        "new_goal_id": new_id,
                        "existing_goal_id": ex_id,
                        "detail": {
                            "new_effect": [v1, t1],
                            "existing_effect": [v2, t2],
                        },
                        "explanation": (
                            "goal %r wants to %r target %r while goal "
                            "%r wants to %r the same target"
                            % (new_id[:8], v1, t1, ex_id[:8], v2)),
                    })

        # 2. Resource contention: exclusive_write collisions.
        for v1, t1 in new_effects:
            for v2, t2 in ex_effects:
                if t1 != t2:
                    continue
                if v1 == "exclusive_write" and v2 == "exclusive_write":
                    conflicts.append({
                        "type": "resource_contention",
                        "new_goal_id": new_id,
                        "existing_goal_id": ex_id,
                        "detail": {
                            "target": t1,
                            "new_effect": [v1, t1],
                            "existing_effect": [v2, t2],
                        },
                        "explanation": (
                            "goals %r and %r both claim exclusive "
                            "write access to %r"
                            % (new_id[:8], ex_id[:8], t1)),
                    })
                elif ((v1 == "exclusive_write" and v2 == "write")
                      or (v1 == "write" and v2 == "exclusive_write")):
                    conflicts.append({
                        "type": "resource_contention",
                        "new_goal_id": new_id,
                        "existing_goal_id": ex_id,
                        "detail": {
                            "target": t1,
                            "new_effect": [v1, t1],
                            "existing_effect": [v2, t2],
                        },
                        "explanation": (
                            "exclusive_write claim on %r by one goal "
                            "is violated by the other goal's write"
                            % (t1,)),
                    })

        # 3a. Constraint violation: new effect vs existing forbid.
        for v1, t1 in new_effects:
            for _kind, v2, t2 in ex_constraints:
                if v1 == v2 and t1 == t2:
                    conflicts.append({
                        "type": "constraint_violation",
                        "new_goal_id": new_id,
                        "existing_goal_id": ex_id,
                        "detail": {
                            "new_effect": [v1, t1],
                            "existing_constraint": ["forbid", v2, t2],
                        },
                        "explanation": (
                            "goal %r's effect (%r %r) violates goal "
                            "%r's forbid constraint"
                            % (new_id[:8], v1, t1, ex_id[:8])),
                    })

        # 3b. Reverse: new forbid constraint vs existing effect --
        # registering the constraint itself creates the conflict.
        for _kind, v1, t1 in new_constraints:
            for v2, t2 in ex_effects:
                if v1 == v2 and t1 == t2:
                    conflicts.append({
                        "type": "constraint_violation",
                        "new_goal_id": new_id,
                        "existing_goal_id": ex_id,
                        "detail": {
                            "new_constraint": ["forbid", v1, t1],
                            "existing_effect": [v2, t2],
                        },
                        "explanation": (
                            "goal %r's forbid constraint on (%r %r) "
                            "conflicts with goal %r's existing effect"
                            % (new_id[:8], v1, t1, ex_id[:8])),
                    })

    return conflicts


class GoalRegistry(object):
    """Per-run registry of declared agent goals.

    ``audit`` is an optional callable taking one event dict; every
    registration appends ``goal_registered`` and every detected
    conflict appends a LOUD ``goal_conflict`` event. When None, events
    are recorded on the returned records only (never silently
    dropped -- the caller can always inspect them).
    """

    def __init__(self, audit=None):
        self._goals = []
        self._prev_digest = ""
        self.audit = audit

    def _loud(self, event):
        if self.audit is not None:
            self.audit(event)

    def audit_event(self, event):
        """Public hook for module-level analyses (e.g.
        ``detect_cross_run_laundering``) to emit LOUD audit events
        through the registry's audit callable. Same fail-closed
        posture as registration-time events."""
        if not isinstance(event, dict):
            raise ValueError("audit event must be a dict, got %r"
                             % (event,))
        self._loud(event)

    def active_goals(self):
        """All goals with status 'active' (dicts, in registration order)."""
        return [g for g in self._goals if g.get("status") == "active"]

    def register(self, agent_id, run_id, description, effects=(),
                 constraints=()):
        """Register a goal; returns (goal_dict, [conflict_dicts]).

        Validation is fail-closed: empty agent_id/run_id/description,
        malformed atoms, or unknown verbs raise ValueError. The goal
        is ALWAYS registered (registration never denies); conflicts
        are reported LOUD via the audit callable and in the return
        value for the caller (the executor) to route to humans.
        """
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        if not isinstance(description, str) or not description.strip():
            raise ValueError("description must be a non-empty string")
        norm_effects = [_check_effect(a) for a in (effects or ())]
        norm_constraints = [_check_constraint(c)
                            for c in (constraints or ())]

        record = {
            "goal_version": _GOAL_VERSION,
            "goal_id": uuid.uuid4().hex,
            "agent_id": agent_id,
            "run_id": run_id,
            "description": description,
            "effects": [list(e) for e in norm_effects],
            "constraints": [list(c) for c in norm_constraints],
            "status": "active",
            # Wave-135 (row-11): vague-goal specificity. A goal whose
            # declared effects are empty or carry a wildcard target is
            # NOT silently accepted as active: it registers in
            # "pending_specificity", covers nothing, and needs a
            # human to narrow it (registry.narrow) or acknowledge its
            # breadth (resolve_specificity via a
            # goal_specificity_review approval decision) before it can
            # cover actions. Fail-closed: pending goals provide no
            # cover in gov.goal_audit.
            "broad_scope_acknowledged": False,
            "registered_at": _utcnow_iso(),
            "prev_goal_digest": self._prev_digest,
        }
        vague, spec_reasons = check_specificity(record)
        if vague:
            record["status"] = "pending_specificity"
            record["specificity_reasons"] = list(spec_reasons)
        record["goal_digest"] = _record_digest(record, self._prev_digest)

        conflicts = detect_conflict(record, self.active_goals())

        # Audit BEFORE mutating local state: the log append is
        # fail-closed, so if it raises the registry is unchanged and
        # the caller sees the exception -- log and memory never
        # diverge (F167 lesson). List append cannot fail.
        self._loud({
            "event": "goal_registered",
            "goal_id": record["goal_id"],
            "agent_id": agent_id,
            "run_id": run_id,
            "description": description,
            "effects": [list(e) for e in norm_effects],
            "constraints": [list(c) for c in norm_constraints],
            "status": record["status"],
            "broad_scope_acknowledged": False,
            "specificity_reasons": list(spec_reasons),
            "goal_digest": record["goal_digest"],
            "prev_goal_digest": record["prev_goal_digest"],
            "conflict_count": len(conflicts),
            "ts": record["registered_at"],
        })
        if vague:
            # LOUD: a vague goal was registered and is being held in
            # pending_specificity. The executor routes this to a
            # goal_specificity_review approval item; the registry
            # itself never queues (no queue access here).
            self._loud({
                "event": "goal_specificity_pending",
                "flag": "goal_specificity",
                "run_id": run_id,
                "agent_id": agent_id,
                "goal_id": record["goal_id"],
                "specificity_reasons": list(spec_reasons),
                "reason": (
                    "VAGUE GOAL HELD: goal %r declares %s. It is "
                    "registered in pending_specificity and covers "
                    "NOTHING until a human narrows it or explicitly "
                    "acknowledges its breadth."
                    % (record["goal_id"][:8],
                       "; ".join(spec_reasons))),
                "ts": _utcnow_iso(),
            })
        for c in conflicts:
            self._loud({
                "event": "goal_conflict",
                "flag": "goal_conflict",
                "run_id": run_id,
                "new_goal_id": c["new_goal_id"],
                "new_agent_id": agent_id,
                "existing_goal_id": c["existing_goal_id"],
                "conflict_type": c["type"],
                "detail": c["detail"],
                "reason": (
                    "GOAL CONFLICT (%s): %s. A human must resolve "
                    "which objective stands; neither goal is blocked "
                    "by this signal alone."
                    % (c["type"], c["explanation"])),
                "ts": _utcnow_iso(),
            })
        self._goals.append(record)
        self._prev_digest = record["goal_digest"]
        return record, conflicts

    def verify_chain(self):
        """Verify the goal sub-chain. Returns (ok, reason)."""
        prev = ""
        for i, rec in enumerate(self._goals):
            if not isinstance(rec, dict):
                return False, "record %d is not a dict" % i
            if rec.get("prev_goal_digest") != prev:
                return False, ("record %d linkage broken: "
                               "prev_goal_digest mismatch" % i)
            expect = _record_digest(rec, prev)
            if rec.get("goal_digest") != expect:
                return False, ("record %d digest mismatch: payload "
                               "tampered" % i)
            prev = rec["goal_digest"]
        return True, "%d records, chain intact" % len(self._goals)

    def get_goal(self, goal_id):
        """Return the goal record for ``goal_id``, or None if unknown.

        Unlike ``set_status`` this never raises: resolution callers
        need to distinguish "unknown" from "known" to emit the
        fail-closed ``goal_resolution_noop`` instead of crashing.
        """
        for g in self._goals:
            if g.get("goal_id") == goal_id:
                return g
        return None

    def set_status(self, goal_id, status, approval_id=None):
        """Update a goal's status ('active' | 'superseded' |
        'pending_specificity').

        Returns the goal dict. Unknown goal_id or status ->
        ValueError (fail-closed, no silent no-op). Status changes do
        NOT rewrite the chained record (the chain is append-only
        history); the live status lives on the in-memory record and
        in the audit trail.

        ``approval_id`` (wave-134): when the status change is the
        execution of a human's ``goal_conflict_review`` decision, the
        approval id rides the chained ``goal_status_changed`` event so
        the goal trail cross-references the approval trail (the
        ``approval_decision`` event carries the goal ids back).
        """
        if status not in ("active", "superseded", "pending_specificity"):
            raise ValueError(
                "status must be 'active', 'superseded', or "
                "'pending_specificity', got %r" % (status,))
        for g in self._goals:
            if g.get("goal_id") == goal_id:
                g["status"] = status
                self._loud({
                    "event": "goal_status_changed",
                    "goal_id": goal_id,
                    "agent_id": g.get("agent_id"),
                    "run_id": g.get("run_id"),
                    "status": status,
                    "approval_id": approval_id,
                    "ts": _utcnow_iso(),
                })
                return g
        raise ValueError("unknown goal_id %r" % (goal_id,))

    # ------------------------------------------------------------------
    # Wave-135 (row-11): vague-goal specificity resolution
    # ------------------------------------------------------------------

    def resolve_specificity(self, goal_id, acknowledged, approval_id):
        """Wave-135 (row-11): apply a human's ``goal_specificity_review``
        decision to a vague goal.

        A ``goal_specificity_review`` approval item adjudicates one
        goal held in ``pending_specificity``:

        * acknowledged (allow): the human explicitly accepts the
          goal's breadth. The goal becomes ``active`` with
          ``broad_scope_acknowledged=True`` -- and from then on every
          ``goal_wildcard_cover`` finding for it in gov.goal_audit is
          LOUD (severity high), not informational. The breadth was
          human-accepted, so its exercise stays maximally visible.
        * withdrawn (deny): the goal is marked ``superseded``; it
          never covered anything and never will.

        A chained ``goal_specificity_resolved`` event carries the
        approval id, so the goal trail cross-references the approval
        trail.

        Fail-closed: an unknown goal id, or a goal that is no longer
        pending (resolved separately before the human decided), is
        NOT silently skipped -- a LOUD ``goal_specificity_noop``
        event is chained for it, and the decision is still recorded
        by the caller. Nothing is re-applied.

        Honest ceiling: this automates the mechanics, not the
        judgment. A human who acknowledges a maliciously broad goal
        without reading still acknowledges it -- the wiring does not
        second-guess the human.

        Returns a summary dict: ``{"decision", "goal_id", "noop"}``
        where ``decision`` is "acknowledged" | "withdrawn" | "noop".
        """
        goal = self.get_goal(goal_id)

        def _noop(reason):
            self._loud({
                "event": "goal_specificity_noop",
                "flag": "goal_specificity_noop",
                "run_id": (goal or {}).get("run_id"),
                "agent_id": (goal or {}).get("agent_id"),
                "approval_id": approval_id,
                "goal_id": goal_id,
                "reason": reason,
                "ts": _utcnow_iso(),
            })

        if goal is None:
            reason = ("goal %r referenced by approval %r is unknown "
                      "to this registry -- the specificity review "
                      "cannot be resolved against it"
                      % (goal_id, approval_id))
            _noop(reason)
            return {"decision": "noop", "goal_id": goal_id,
                    "noop": [(goal_id, reason)]}
        if goal.get("status") != "pending_specificity":
            reason = ("goal %r is %r, not pending_specificity -- a "
                      "separate resolution already settled it; the "
                      "approval is recorded but nothing is re-applied"
                      % (goal_id, goal.get("status")))
            _noop(reason)
            return {"decision": "noop", "goal_id": goal_id,
                    "noop": [(goal_id, reason)]}

        if acknowledged:
            self.set_status(goal_id, "active", approval_id=approval_id)
            goal["broad_scope_acknowledged"] = True
            decision = "acknowledged"
        else:
            self.set_status(goal_id, "superseded", approval_id=approval_id)
            decision = "withdrawn"
        self._loud({
            "event": "goal_specificity_resolved",
            "flag": "goal_specificity",
            "run_id": goal.get("run_id"),
            "agent_id": goal.get("agent_id"),
            "goal_id": goal_id,
            "decision": decision,
            "status": goal["status"],
            "broad_scope_acknowledged":
                bool(goal.get("broad_scope_acknowledged")),
            "approval_id": approval_id,
            "reason": ("human %s goal_specificity_review %r for goal "
                       "%r: %s"
                       % (decision, approval_id, goal_id[:8], decision)),
            "ts": _utcnow_iso(),
        })
        return {"decision": decision, "goal_id": goal_id, "noop": []}

    def narrow(self, goal_id, effects=(), constraints=()):
        """Wave-135 (row-11): narrow a vague (pending_specificity) goal.

        The human/operator supplies narrowed ``effects``/``constraints``;
        the pending goal is marked ``superseded`` and a FRESH goal is
        registered with the narrowed atoms -- narrowing is a new
        registration, not an in-place edit, because the goal sub-chain
        is append-only: rewriting a chained record's effects would
        break every later link's ``prev_goal_digest`` binding. The
        fresh registration re-runs the specificity check automatically:
        a still-vague narrowing lands in ``pending_specificity``
        again (the check is re-applied, never waived).

        A chained ``goal_narrowed`` event links old_goal_id ->
        new_goal_id. Returns ``(new_goal_dict, [conflict_dicts])``.

        Fail-closed: unknown goal_id, a goal that is not pending
        (only vague goals can be narrowed -- narrowing an active goal
        is a fresh registration by the operator), or malformed atoms
        raise ValueError; the registry is unchanged.
        """
        goal = self.get_goal(goal_id)
        if goal is None:
            raise ValueError("unknown goal_id %r" % (goal_id,))
        if goal.get("status") != "pending_specificity":
            raise ValueError(
                "only a pending_specificity goal can be narrowed, "
                "goal %r is %r" % (goal_id, goal.get("status")))
        # Validate the narrowed atoms BEFORE touching state: register()
        # is fail-closed on malformed atoms, so pre-validate by
        # normalizing here through the same checkers.
        norm_effects = [_check_effect(a) for a in (effects or ())]
        norm_constraints = [_check_constraint(c)
                            for c in (constraints or ())]
        self.set_status(goal_id, "superseded")
        new_goal, conflicts = self.register(
            goal["agent_id"], goal["run_id"], goal["description"],
            effects=[tuple(e) for e in norm_effects],
            constraints=[tuple(c) for c in norm_constraints])
        self._loud({
            "event": "goal_narrowed",
            "flag": "goal_specificity",
            "run_id": goal.get("run_id"),
            "agent_id": goal.get("agent_id"),
            "old_goal_id": goal_id,
            "new_goal_id": new_goal["goal_id"],
            "new_status": new_goal["status"],
            "reason": ("goal %r narrowed to goal %r with %d effect(s); "
                       "new goal is %r"
                       % (goal_id[:8], new_goal["goal_id"][:8],
                          len(norm_effects), new_goal["status"])),
            "ts": _utcnow_iso(),
        })
        return new_goal, conflicts

    # ------------------------------------------------------------------
    # Cross-run persistence
    # ------------------------------------------------------------------

    def save(self, path):
        """Persist the registry to ``path`` (JSONL, tamper-evident).

        Layout: a header line, one line per goal record (in chain
        order, with live statuses), then a footer line carrying
        ``file_digest`` -- SHA-256 over the canonical header +
        records. The in-memory sub-chain continues across ``load``:
        the header's ``chain_tip`` binds the file to the chain state,
        so a store swapped between runs (or truncated) fails closed
        on load. Raises GoalPersistenceError on any I/O problem.
        """
        header = {
            "record_type": "goal_registry_header",
            "goal_version": _GOAL_VERSION,
            "record_count": len(self._goals),
            "chain_tip": self._prev_digest,
            "saved_at": _utcnow_iso(),
        }
        lines = [_canonical(header)]
        for rec in self._goals:
            if not isinstance(rec, dict):
                raise GoalPersistenceError(
                    "cannot persist: record is not a dict")
            lines.append(_canonical(rec))
        footer = {
            "record_type": "goal_registry_footer",
            "file_digest": _sha256_hex("\n".join(lines) + "\n"),
        }
        lines.append(_canonical(footer))
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError as e:
            raise GoalPersistenceError(
                "cannot save goal registry to %r: %s" % (path, e))

    @classmethod
    def load(cls, path, audit=None):
        """Load a registry previously written by ``save``.

        Fail-closed: missing/unreadable file, malformed JSON, a
        wrong record_type sequence, a ``file_digest`` mismatch, a
        ``chain_tip`` mismatch, or a broken goal sub-chain all raise
        GoalPersistenceError -- a damaged store is never silently
        accepted as a clean history. Returns a GoalRegistry whose
        chain continues exactly where the saved one left off, so
        registrations in the new run extend the same tamper-evident
        history.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw_lines = [ln for ln in
                             (l.strip() for l in fh.read().splitlines())
                             if ln]
        except OSError as e:
            raise GoalPersistenceError(
                "cannot load goal registry from %r: %s" % (path, e))
        if len(raw_lines) < 2:
            raise GoalPersistenceError(
                "goal registry file %r is truncated (%d lines)"
                % (path, len(raw_lines)))
        try:
            objs = [json.loads(ln) for ln in raw_lines]
        except ValueError as e:
            raise GoalPersistenceError(
                "goal registry file %r has malformed JSON: %s"
                % (path, e))
        header, records, footer = objs[0], objs[1:-1], objs[-1]
        if not isinstance(header, dict) or \
                header.get("record_type") != "goal_registry_header":
            raise GoalPersistenceError(
                "goal registry file %r: bad or missing header" % (path,))
        if not isinstance(footer, dict) or \
                footer.get("record_type") != "goal_registry_footer":
            raise GoalPersistenceError(
                "goal registry file %r: bad or missing footer" % (path,))
        if header.get("goal_version") != _GOAL_VERSION:
            raise GoalPersistenceError(
                "goal registry file %r: unsupported goal_version %r"
                % (path, header.get("goal_version")))
        if header.get("record_count") != len(records):
            raise GoalPersistenceError(
                "goal registry file %r: header claims %r records, "
                "found %d" % (path, header.get("record_count"),
                              len(records)))
        expect_digest = _sha256_hex(
            "\n".join(_canonical(o) for o in [header] + records) + "\n")
        if footer.get("file_digest") != expect_digest:
            raise GoalPersistenceError(
                "goal registry file %r: file_digest mismatch -- the "
                "store was modified outside save()" % (path,))
        reg = cls(audit=audit)
        reg._goals = records
        reg._prev_digest = (records[-1].get("goal_digest", "")
                            if records else "")
        ok, reason = reg.verify_chain()
        if not ok:
            raise GoalPersistenceError(
                "goal registry file %r: goal sub-chain broken (%s)"
                % (path, reason))
        if header.get("chain_tip") != reg._prev_digest:
            raise GoalPersistenceError(
                "goal registry file %r: chain_tip does not match the "
                "stored chain -- records were added, removed, or "
                "reordered outside save()" % (path,))
        return reg


# ------------------------------------------------------------------
# Cross-run laundering detection
# ------------------------------------------------------------------

def _check_history_atom(atom):
    """Validate one executed-history atom (verb, target)."""
    verb, target = _check_verb_target(atom, "executed-history atom")
    return (verb, normalize_target(str(target)))


def _goal_signature(goal):
    """Material identity of a goal: normalized effect + constraint
    sets. Two goals with the same signature declare the same
    structured objective regardless of prose description.

    Fail-closed like the rest of the module: malformed atoms raise
    ValueError rather than being silently skipped (a skipped atom
    would make two different goals compare "identical")."""
    effects = goal.get("effects") or []
    constraints = goal.get("constraints") or []
    eff = frozenset(_check_effect(list(e)) for e in effects)
    con = frozenset(_check_constraint(list(c)) for c in constraints)
    return (eff, con)


def _covers(effects, verb, target):
    """True if any declared effect covers the executed (verb, target):
    exact match, or a wildcard target."""
    for e in effects or []:
        if not isinstance(e, (list, tuple)) or len(e) != 2:
            continue
        everb, etarget = e[0], normalize_target(str(e[1]))
        if everb == verb and (etarget == target or etarget == "*"):
            return True
    return False


def _similar_covers(effects, verb, target, threshold=DEFAULT_THRESHOLD):
    """Paraphrase-tolerant cover tier (wave-136).

    Returns (matched_effect_target, score) for the best declared
    effect whose verb matches and whose target scores >= threshold
    under gov/target_match.py, or (None, 0.0). Wildcards are excluded
    here -- they are handled by _covers. Verb opposition is NOT
    fuzzed: similarity may excuse, never condemn.

    Best-cover selection is delegated to target_match.match_target
    (the single implementation shared with gov/goal_audit.py); this
    helper only applies the seam's verb/wildcard filtering.
    """
    candidates = []
    for e in effects or []:
        if not isinstance(e, (list, tuple)) or len(e) != 2:
            continue
        everb, etarget = e[0], normalize_target(str(e[1]))
        if everb != verb or etarget == "*":
            continue
        candidates.append((etarget, etarget))
    return match_target(target, candidates, threshold=threshold)


def _prior_violation(prior, verb, target):
    """Did executing (verb, target) violate any prior-run goal?

    Returns ("forbid", goal) or ("opposes", goal), else None. Both
    legs are exact normalized matching: what the agent actually did
    is concrete, so the violation check needs no fuzzing.
    """
    for g in prior:
        for _k, cverb, ctarget in (g.get("constraints") or []):
            if cverb == verb and \
                    normalize_target(str(ctarget)) == target:
                return ("forbid", g)
        for everb, etarget in (g.get("effects") or []):
            if normalize_target(str(etarget)) == target and \
                    everb in _OPPOSES.get(verb, ()):
                return ("opposes", g)
    return None


def _any_atom_covered(effects, atoms):
    """True when any (verb, target) atom in ``atoms`` is covered
    (exact or wildcard) by the declared ``effects``. Shared by the
    dormant exercised-check and the fresh-ID prior-exercised check
    so the two "was this goal lived" definitions cannot drift."""
    for verb, target in atoms:
        if _covers(effects, verb, target):
            return True
    return False


def _prior_exercised(prior, history):
    """Was the prior-run goal lived before it was superseded?

    ``history`` maps run_id -> [(verb, target), ...] of executed
    effects (validated, normalized). True when the prior's own run
    is observed AND at least one executed atom is covered (exact or
    wildcard) by the prior's declared effects -- the legitimate
    register -> exercise -> resolve flow. A superseded goal with no
    covered execution in observed history was denied/withdrawn, not
    lived: the shape the fresh-ID path hunts.
    """
    atoms = history.get(prior.get("run_id"))
    if not atoms:
        return False
    return _any_atom_covered(prior.get("effects") or [], atoms)


def _fresh_id_match(new_goal, prior):
    """Is ``new_goal`` a fresh-ID re-mint of the superseded ``prior``?

    Additive identity path (wave-139): goal IDs are minted fresh on
    every registration, so ID comparison can never see a re-mint --
    this anchors on target/effects similarity instead, reusing
    gov/target_match.py's token-tversky ``target_similarity`` and
    ``FRESH_ID_SIMILARITY_THRESHOLD`` (== DEFAULT_THRESHOLD; no new
    similarity invented). Returns (matched, atom_scores).

    The match rule is deliberately conjunctive (overreach guard):
    EVERY effect atom of the new goal must find a prior-run atom
    with the SAME verb and target_similarity >= the threshold.
    Target similarity alone never condemns -- a verb-differing atom
    or an extra unmatched new atom breaks the match, so the path
    cannot be used to launder a genuinely broader objective into a
    denied one. Wildcard prior targets never match (they tokenize
    empty -> 0.0), so a narrowed re-registration of a wildcard goal
    is not confused with a re-mint by this leg.
    """
    new_effects = [list(e) for e in (new_goal.get("effects") or [])]
    prior_effects = [list(e) for e in (prior.get("effects") or [])]
    if not new_effects or not prior_effects:
        return False, []
    scores = []
    for verb, target in new_effects:
        best = 0.0
        for pverb, ptarget in prior_effects:
            if pverb != verb:
                continue
            score = target_similarity(str(ptarget), str(target))
            if score > best:
                best = score
        if best < FRESH_ID_SIMILARITY_THRESHOLD:
            return False, []
        scores.append(best)
    return True, scores


def detect_cross_run_laundering(registry, new_goal, executed_history=None,
                                prior_goals=None):
    """Flag cross-run goal laundering for a newly registered goal.

    ``registry``: GoalRegistry (ideally loaded from a previous run's
    ``save`` so earlier runs' goals are present). ``new_goal``: the
    goal dict just returned by ``register()`` (normalized effects /
    constraints). ``executed_history``: optional mapping
    ``(agent_id, run_id) -> [(verb, target), ...]`` of effects the
    agent actually executed in previous runs (e.g. reconstructed via
    ``gov.goal_audit.derive_effect`` over audit logs); atoms must use
    the ``EFFECT_VERBS`` vocabulary with normalized targets, else
    ValueError. ``prior_goals``: optional explicit list of previous-
    run goal dicts (defaults to the registry's goals from other
    runs); lets a fresh per-run registry still be checked against a
    supplied history.

    Only the new goal's own agent is considered: cross-run
    attribution keys on stable agent identity, and a fresh agent_id
    per run defeats it (documented ceiling, not a silent pass --
    findings simply do not fire without a matching agent).

    Returns a list of finding dicts (``type``, ``new_goal_id``,
    ``agent_id``, ``severity``, ``detail``, ``explanation``).
    Findings are also emitted LOUD through the registry's audit
    callable as ``goal_cross_run_flag`` events. Detection, not
    prevention: the goal is already registered; the operator acts on
    the flag.

    No double-flagging: when ``new_goal`` was registered through
    ``registry``, ``register()`` already ran ``detect_conflict``
    over every active registry goal, so the composition check here
    covers only priors the registry never saw (explicitly supplied
    ``prior_goals`` absent from the registry, or a never-registered
    candidate ``new_goal``).
    """
    if not isinstance(registry, GoalRegistry):
        raise ValueError("registry must be a GoalRegistry, got %r"
                         % type(registry))
    if not isinstance(new_goal, dict):
        raise ValueError("new_goal must be a goal dict, got %r"
                         % type(new_goal))
    agent_id = new_goal.get("agent_id")
    if not agent_id:
        raise ValueError("new_goal has no agent_id: cross-run "
                         "attribution needs the registering agent")
    new_run = new_goal.get("run_id")
    new_effects = [list(e) for e in (new_goal.get("effects") or [])]
    new_constraints = [list(c) for c in
                       (new_goal.get("constraints") or [])]

    if prior_goals is None:
        prior_goals = [g for g in registry._goals
                       if isinstance(g, dict)
                       and g.get("agent_id") == agent_id
                       and g.get("run_id") != new_run]
    else:
        prior_goals = [g for g in prior_goals
                       if isinstance(g, dict)
                       and g.get("agent_id") == agent_id
                       and g.get("run_id") != new_run]

    history = {}
    for key, atoms in (executed_history or {}).items():
        if (not isinstance(key, (tuple, list))) or len(key) != 2:
            raise ValueError(
                "executed_history keys must be (agent_id, run_id), "
                "got %r" % (key,))
        if key[0] != agent_id or key[1] == new_run:
            continue
        history[key[1]] = [_check_history_atom(a) for a in atoms]

    findings = []

    def _flag(ftype, severity, detail, explanation):
        findings.append({
            "type": ftype,
            "new_goal_id": new_goal.get("goal_id"),
            "agent_id": agent_id,
            "severity": severity,
            "detail": detail,
            "explanation": explanation,
        })
        registry.audit_event({
            "event": "goal_cross_run_flag",
            "flag": "goal_cross_run",
            "run_id": new_run,
            "new_goal_id": new_goal.get("goal_id"),
            "agent_id": agent_id,
            "finding_type": ftype,
            "severity": severity,
            "detail": detail,
            "reason": ("CROSS-RUN GOAL FLAG (%s, %s): %s"
                       % (ftype, severity, explanation)),
        })

    # 1. Composition: the new goal conflicts with a still-active goal
    #    the same agent registered in a previous run -- but ONLY
    #    against priors register() did not already check. When the new
    #    goal was registered through this registry, register() already
    #    ran detect_conflict over every active registry goal (including
    #    loaded prior-run goals) and flagged them LOUD; re-flagging
    #    here would triple-fire one atom pair for a single conflict.
    #    The detector's composition check exists for priors the
    #    registry never saw: explicitly supplied prior_goals against
    #    a fresh per-run registry, or a candidate new_goal that was
    #    never registered.
    new_id = new_goal.get("goal_id")
    registry_ids = set(
        g.get("goal_id") for g in registry._goals
        if isinstance(g, dict))
    registered_here = new_id is not None and new_id in registry_ids
    if registered_here:
        composition_priors = [
            g for g in prior_goals
            if g.get("goal_id") not in registry_ids]
    else:
        composition_priors = list(prior_goals)
    prev_active = [g for g in composition_priors
                   if g.get("status", "active") == "active"]
    for c in detect_conflict(new_goal, prev_active):
        _flag("cross_run_composition_conflict", "high",
              {"conflict": c,
               "prior_goal_id": c["existing_goal_id"],
               "prior_run_id": next(
                   (g.get("run_id") for g in prev_active
                    if g.get("goal_id") == c["existing_goal_id"]),
                   None)},
              "goal %r registered in this run conflicts (%s) with "
              "the same agent's still-active goal from a previous "
              "run: %s" % (new_goal.get("goal_id", "")[:8],
                            c["type"], c["explanation"]))

    # Index prior goals by run for the history signals.
    prior_by_run = {}
    for g in prior_goals:
        prior_by_run.setdefault(g.get("run_id"), []).append(g)

    for run_id, exec_atoms in sorted(history.items()):
        prior = prior_by_run.get(run_id, [])

        # 2a. The new registration legitimizes behavior that violated
        #     the agent's own prior registration: the agent executed
        #     (verb, target) while a prior-run goal forbade it (or
        #     declared the opposite), and the new goal's effects now
        #     cover that same atom. The past violation is being
        #     laundered through a fresh registration.
        #
        #     The cover leg is paraphrase-tolerant (wave-136): a new
        #     goal covering a paraphrase of the executed atom still
        #     launders the violation. The violation leg stays exact --
        #     what the agent actually did is concrete, so it needs no
        #     fuzzing. A similarity cover is flagged with its
        #     match_score and match_method in the detail.
        for verb, target in exec_atoms:
            covered_target, cover_method, cover_score = target, "exact", 1.0
            if not _covers(new_effects, verb, target):
                sim_target, sim_score = _similar_covers(
                    new_effects, verb, target)
                if sim_target is None:
                    continue
                covered_target, cover_method = sim_target, MATCH_METHOD
                cover_score = sim_score
            violated = _prior_violation(prior, verb, target)
            if violated:
                kind, pg = violated
                detail = {"executed": [verb, target],
                          "executed_run_id": run_id,
                          "prior_goal_id": pg.get("goal_id"),
                          "new_effect": [verb, covered_target]}
                explanation = (
                    "agent executed (%s %s) in run %r in violation "
                    "of its own prior goal (%s), and this run's "
                    "registration now covers the same atom -- the "
                    "past violation is being legitimized by a "
                    "fresh registration" % (verb, target, run_id, kind))
                if cover_method != "exact":
                    detail["match_score"] = cover_score
                    detail["match_method"] = cover_method
                    explanation += (
                        " (paraphrase-tolerant cover: %s %.3f)"
                        % (cover_method, cover_score))
                _flag("registration_launders_violation", "high",
                      detail, explanation)

        # 2b. The new registration's own constraints are contradicted
        #     by the agent's executed history: the agent already did
        #     what it now claims to forbid.
        for _k, cverb, ctarget in new_constraints:
            ctarget_n = normalize_target(str(ctarget))
            for verb, target in exec_atoms:
                if verb == cverb and target == ctarget_n:
                    _flag("history_contradicts_registration", "high",
                          {"executed": [verb, target],
                           "executed_run_id": run_id,
                           "new_constraint": ["forbid", cverb,
                                              ctarget_n]},
                          "agent executed (%s %s) in run %r but this "
                          "run's registration forbids it -- the "
                          "declaration is contradicted by the "
                          "agent's own history"
                          % (verb, target, run_id))

    # 3. Dormant goal: materially identical goal registered across
    #    >= DORMANT_RUN_THRESHOLD distinct runs (including this one)
    #    with no executed effect ever covered by its effects in the
    #    observed history. An unexercised standing goal is cheap
    #    cover for later misuse. Without any executed history the
    #    signal cannot distinguish "dormant" from "unobserved", so
    #    it stays silent rather than fire without evidence (FP
    #    aversion: a same-run exercise later in the run is not yet
    #    visible at registration time).
    sig = _goal_signature(new_goal)
    if history and any(v in ("send", "write", "delete",
                             "exclusive_write") for v, _t in sig[0]):
        matching_runs = set()
        for g in prior_goals:
            if _goal_signature(g) == sig and g.get("run_id"):
                matching_runs.add(g.get("run_id"))
        if new_run:
            matching_runs.add(new_run)
        if len(matching_runs) >= DORMANT_RUN_THRESHOLD:
            exercised = _any_atom_covered(
                new_effects,
                [a for atoms in history.values() for a in atoms])
            if not exercised:
                _flag("dormant_goal", "info",
                      {"matching_runs": sorted(matching_runs),
                       "signature_effects": [list(e) for e in sig[0]]},
                      "materially identical goal registered in %d "
                      "distinct runs with no covered execution in "
                      "observed history -- a standing unexercised "
                      "goal is cheap cover"
                      % len(matching_runs))

    # 4. Fresh-ID laundering (wave-139): the new goal re-mints a
    #    prior-run goal of the same agent that was superseded
    #    (denied via goal_conflict_review / goal_specificity_review,
    #    i.e. never lived) -- same objective, fresh goal ID,
    #    possibly paraphrased description. The ID-based path is
    #    intact (fresh uuids evade identity matching by
    #    construction); this additive path anchors on
    #    target/effects similarity via gov/target_match.py
    #    token-tversky (FRESH_ID_SIMILARITY_THRESHOLD, no new
    #    similarity) and treats the re-mint as the same goal for
    #    laundering purposes: flagged LOUD so the operator denies
    #    its coverage. Detection, not prevention -- registration
    #    itself never denies (module invariant).
    #
    #    "Principal" is the goal schema's agent_id: the schema
    #    carries no principal field, and this matches the
    #    detector's existing attribution key (with its documented
    #    rotation ceiling). "Recently" is the detector's
    #    prior-goals scope (loaded persistence + explicit
    #    prior_goals + executed_history): a denied goal aged out
    #    of the persisted store is invisible (honest ceiling).
    #
    #    Deliberate FP-averse narrowings (not oversights): silent
    #    without executed history (unobserved != denied); silent
    #    when the prior's run is unobserved; silent when the prior
    #    was exercised before supersede (the legitimate
    #    register -> exercise -> resolve flow stays silent); and
    #    the conjunctive _fresh_id_match rule (verb must be equal,
    #    every new atom must match) keeps target similarity from
    #    condemning on its own.
    if history:
        for prior in prior_goals:
            if prior.get("status") != "superseded":
                continue
            if prior.get("run_id") not in history:
                continue
            if _prior_exercised(prior, history):
                continue
            matched, atom_scores = _fresh_id_match(new_goal, prior)
            if matched:
                _flag("fresh_id_laundering", "high",
                      {"prior_goal_id": prior.get("goal_id"),
                       "prior_run_id": prior.get("run_id"),
                       "match_method": MATCH_METHOD,
                       "threshold": FRESH_ID_SIMILARITY_THRESHOLD,
                       "atom_scores": [round(s, 3) for s in atom_scores],
                       "prior_effects": [list(e) for e in
                                         (prior.get("effects") or [])],
                       "new_effects": new_effects},
                      "goal %r is a fresh-ID re-mint of the same "
                      "agent's prior-run goal %r (run %r), which was "
                      "superseded without being exercised: every "
                      "declared effect atom matches a prior atom "
                      "(same verb, token-tversky target similarity "
                      ">= %.2f, scores %s) -- the denial is being "
                      "laundered through a new registration"
                      % (new_goal.get("goal_id", "")[:8],
                         (prior.get("goal_id") or "")[:8],
                         prior.get("run_id"),
                         FRESH_ID_SIMILARITY_THRESHOLD,
                         [round(s, 3) for s in atom_scores]))

    return findings


def conflict_review_goal_ids(args):
    """Goal ids adjudicated by a ``goal_conflict_review`` args dict.

    Returns the new (conflicting) goal id followed by the existing
    goal ids it collided with, deduplicated, order-stable. Shared by
    the approval-queue decision event (``_goal_review_goal_ids``), the
    executor's post-decision hook, and ``apply_approval_resolution``
    so the extraction shape cannot drift between the three (wave-134
    review: duplicated-code consolidation).
    """
    ids = []
    if not isinstance(args, dict):
        return ids
    candidates = [args.get("goal_id")]
    conflicts = args.get("conflicts") or []
    if isinstance(conflicts, list):
        for c in conflicts:
            if isinstance(c, dict):
                candidates.append(c.get("existing_goal_id"))
    for gid in candidates:
        if gid and gid not in ids:
            ids.append(gid)
    return ids


def apply_approval_resolution(registry, *, new_goal_id, existing_goal_ids,
                              approved, approval_id, audit=None,
                              attested_existing_ids=None):
    """Wave-134 (row-11): apply a human's ``goal_conflict_review`` decision.

    A ``goal_conflict_review`` approval item adjudicates one conflict:
    ``new_goal_id`` (the just-registered goal that triggered the
    conflict) against ``existing_goal_ids`` (the active goals it
    collided with). When the human DECIDES the item, the decision
    resolves the conflict — approving the review no longer leaves the
    goals untouched:

    * approved (allow): the new goal stands; every conflicting
      existing goal is marked ``superseded`` via the ``set_status``
      path (chained ``goal_status_changed`` events).
    * rejected (deny): the new goal is marked ``superseded``; the
      existing goals stand untouched.

    ``attested_existing_ids`` (F179): when given (not None), an
    arg-named existing goal id that is NOT in the attested set is
    never superseded -- it produces a LOUD ``goal_resolution_noop``
    with an attestation-failure reason instead. The set is the
    conflict detector's verdict re-run at decision time against
    current registry state; it proves the conflict was
    detector-attested, not merely caller-claimed in the approval
    args (the F38 MAC on the pending record proves the args were not
    tampered with *after* queueing, not that the conflict was real).
    When None (default), behavior is exactly as before (backward
    compat for direct callers that already trust the args). Order of
    checks: unknown-id and already-superseded keep their existing
    reasons; attestation gates only known active goals.

    Auditability: every status change chains a ``goal_status_changed``
    event carrying ``approval_id``; the ``approval_decision`` event
    carries the ``goal_ids`` it adjudicated (see
    ``ApprovalQueue.decide``), so the trail cross-references both
    ways. A ``goal_resolution`` summary event records the outcome.

    Fail-closed: a referenced goal that is unknown, or already in the
    target status (the conflict was resolved separately before the
    human decided), is NOT silently skipped — a LOUD
    ``goal_resolution_noop`` event is chained for it. The approval
    decision itself is always recorded; resolution never vetoes it.

    Honest ceiling: this automates the mechanics, not the judgment.
    A human who allows without reading still allows — the wiring does
    not second-guess the human.

    Returns a summary dict: ``{"decision", "new_goal_id",
    "superseded_goal_ids", "standing_goal_ids", "noop": [(goal_id,
    reason), ...]}``.
    """
    if not isinstance(registry, GoalRegistry):
        raise ValueError("registry must be a GoalRegistry, got %r"
                         % type(registry))
    _audit = audit if audit is not None else getattr(registry, "audit",
                                                     None)

    def _emit(event):
        if _audit is not None:
            _audit(event)

    def _noop(goal_id, reason):
        _emit({
            "event": "goal_resolution_noop",
            "flag": "goal_resolution_noop",
            "run_id": _run_id,
            "agent_id": ((registry.get_goal(goal_id) or {})
                         .get("agent_id")),
            "approval_id": approval_id,
            "goal_id": goal_id,
            "reason": reason,
            "ts": _utcnow_iso(),
        })

    new_goal = registry.get_goal(new_goal_id) if new_goal_id else None
    ordered = conflict_review_goal_ids(
        {"goal_id": new_goal_id, "conflicts":
         [{"existing_goal_id": gid} for gid in (existing_goal_ids or [])]})
    existing = [gid for gid in ordered if gid != new_goal_id]

    # run_id for the resolution audit trail: the new goal's run, else
    # the first known existing goal's run, else None (never guessed).
    _run_id = (new_goal or {}).get("run_id")
    if not _run_id:
        for gid in existing:
            _g = registry.get_goal(gid)
            if _g is not None and _g.get("run_id"):
                _run_id = _g.get("run_id")
                break

    superseded = []
    standing = []
    noops = []
    decision = "approved" if approved else "rejected"

    if new_goal is None:
        reason = ("goal %r referenced by approval %r is unknown to "
                  "this registry -- the conflict cannot be resolved "
                  "against it" % (new_goal_id, approval_id))
        _noop(new_goal_id, reason)
        noops.append((new_goal_id, reason))
    elif approved:
        if new_goal.get("status") != "active":
            reason = ("goal %r is already %r -- a separate resolution "
                      "already settled it; the approval is recorded "
                      "but no status is re-applied"
                      % (new_goal_id, new_goal.get("status")))
            _noop(new_goal_id, reason)
            noops.append((new_goal_id, reason))
        else:
            standing.append(new_goal_id)
    else:
        if new_goal.get("status") == "superseded":
            reason = ("goal %r is already superseded -- the denial "
                      "changes nothing" % (new_goal_id,))
            _noop(new_goal_id, reason)
            noops.append((new_goal_id, reason))
        else:
            registry.set_status(new_goal_id, "superseded",
                                approval_id=approval_id)
            superseded.append(new_goal_id)

    if approved:
        for gid in existing:
            g = registry.get_goal(gid)
            if g is None:
                reason = ("goal %r referenced by approval %r is "
                          "unknown to this registry"
                          % (gid, approval_id))
                _noop(gid, reason)
                noops.append((gid, reason))
            elif g.get("status") == "superseded":
                reason = ("goal %r is already superseded -- the "
                          "approval's allow changes nothing for it"
                          % (gid,))
                _noop(gid, reason)
                noops.append((gid, reason))
            elif (attested_existing_ids is not None
                    and gid not in attested_existing_ids):
                reason = ("goal %r was named in the approval args but "
                          "not attested by the conflict detector at "
                          "decision time -- the review is treated as "
                          "forged and the goal is NEVER superseded"
                          % (gid,))
                _noop(gid, reason)
                noops.append((gid, reason))
            else:
                registry.set_status(gid, "superseded",
                                    approval_id=approval_id)
                superseded.append(gid)
    else:
        # Denied: the existing goals stand; they are unaffected, not
        # noops (there was nothing to do for them).
        for gid in existing:
            g = registry.get_goal(gid)
            if g is not None and g.get("status") == "active":
                standing.append(gid)

    _emit({
        "event": "goal_resolution",
        "run_id": _run_id,
        "agent_id": (new_goal or {}).get("agent_id"),
        "approval_id": approval_id,
        "decision": decision,
        "new_goal_id": new_goal_id,
        "superseded_goal_ids": superseded,
        "standing_goal_ids": standing,
        "noop_goal_ids": [gid for gid, _r in noops],
        "reason": ("human %s goal_conflict_review %r: %d goal(s) "
                   "superseded, %d standing, %d noop"
                   % (decision, approval_id, len(superseded),
                      len(standing), len(noops))),
        "ts": _utcnow_iso(),
    })
    return {
        "decision": decision,
        "new_goal_id": new_goal_id,
        "superseded_goal_ids": superseded,
        "standing_goal_ids": standing,
        "noop": noops,
    }
