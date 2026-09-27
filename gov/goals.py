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
  ``(verb, target)`` with exact normalized-target matching. A goal
  that paraphrases its target ("temporary storage" vs "temp files")
  dodges the matcher by construction -- deterministic contradiction
  != semantic contradiction. The natural-language ``description`` is
  for humans and the audit trail; it is never used for matching
  (matching on prose would be heuristic, unexplainable, and FP-prone).
  An operator who wants the paraphrase class must supply target
  aliases or a semantic layer OUTSIDE the trust boundary.
- Not cross-run. The registry is per-executor (per run); goals do
  not persist across runs. Cross-run goal laundering remains open.
- Not an enforcer. Registration never denies: conflicts are flagged
  LOUD (``goal_conflict`` audit event) and routed to the approval
  queue for human resolution. The executor's ``register_goal`` is the
  wiring point.

$0, stdlib only, deterministic. Effect/constraint validation is
fail-closed: unknown verbs raise ValueError rather than being
silently accepted (a silently-unreasoned-about verb would be a gap).

Goal records chain via ``prev_goal_digest`` (SHA-256 over the
canonical record), forming a goal sub-chain: tampering with a
registered goal breaks the chain.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

__all__ = [
    "EFFECT_VERBS",
    "GoalRegistry",
    "detect_conflict",
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


def _check_effect(atom):
    """Validate one effect atom (verb, target). Returns normalized."""
    if (not isinstance(atom, (tuple, list))) or len(atom) != 2:
        raise ValueError(
            "effect must be a (verb, target) pair, got %r" % (atom,))
    verb, target = atom
    if verb not in EFFECT_VERBS:
        raise ValueError(
            "unknown effect verb %r: known verbs are %s"
            % (verb, ", ".join(EFFECT_VERBS)))
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
            "registered_at": _utcnow_iso(),
            "prev_goal_digest": self._prev_digest,
        }
        record["goal_digest"] = _sha256_hex(
            _canonical({k: v for k, v in record.items()
                        if k != "goal_digest"})
            + self._prev_digest)

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
            "goal_digest": record["goal_digest"],
            "prev_goal_digest": record["prev_goal_digest"],
            "conflict_count": len(conflicts),
            "ts": record["registered_at"],
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
            expect = _sha256_hex(
                _canonical({k: v for k, v in rec.items()
                            if k != "goal_digest"})
                + prev)
            if rec.get("goal_digest") != expect:
                return False, ("record %d digest mismatch: payload "
                               "tampered" % i)
            prev = rec["goal_digest"]
        return True, "%d records, chain intact" % len(self._goals)

    def set_status(self, goal_id, status):
        """Update a goal's status ('active' | 'superseded').

        Returns the goal dict. Unknown goal_id or status ->
        ValueError (fail-closed, no silent no-op). Status changes do
        NOT rewrite the chained record (the chain is append-only
        history); the live status lives on the in-memory record and
        in the audit trail.
        """
        if status not in ("active", "superseded"):
            raise ValueError(
                "status must be 'active' or 'superseded', got %r"
                % (status,))
        for g in self._goals:
            if g.get("goal_id") == goal_id:
                g["status"] = status
                self._loud({
                    "event": "goal_status_changed",
                    "goal_id": goal_id,
                    "agent_id": g.get("agent_id"),
                    "run_id": g.get("run_id"),
                    "status": status,
                    "ts": _utcnow_iso(),
                })
                return g
        raise ValueError("unknown goal_id %r" % (goal_id,))
