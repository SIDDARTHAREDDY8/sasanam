"""Monotonic advisory layer + Decision BOM.

Two ideas adapted from ``microsoft/agent-governance-toolkit`` (MIT,
https://github.com/microsoft/agent-governance-toolkit -- upstream HEAD
6b644564d112b879e48183bc1655fcf73c86d23e verified 2026-09-27, license
MIT (c) Microsoft Corporation):

  * ``governance/advisory.py`` — the advisory-can-only-tighten pattern:
    an ML/judge classifier runs AFTER the deterministic allow and can
    only block/flag, never override a deny. "The deterministic layer
    remains the trust boundary; the advisory layer is defense-in-depth."
  * ``governance/decision_bom.py`` — the Decision BOM: a reconstructible
    view of every factor behind a governance decision.

Concept adapted, not cloned. Honest deltas from upstream:

  1. The effect lattice is explicit: ``allow < require_approval < deny``.
     AGT's advisory "blocks or flags"; ours generalizes to the engine's
     full three-rung verdict lattice, so an advisor can also route to
     human review (require_approval), not just deny.
  2. Advisor failure: AGT fails open to allow with ``deterministic:
     false`` logged. We keep the deterministic verdict and log
     ``advisory_error`` LOUD. Rationale: the advisory layer must never
     weaken the deterministic floor -- including through its own
     failure. Because our deterministic layer is already fail-closed,
     "keep the deterministic verdict" IS the fail-closed behavior; an
     advisor crash degrades to "no advisory signal", never to "allow".
  3. Monotonicity violations are refused LOUD (``advisory_monotonicity_
     violation`` audit event), not silently clamped: an advisor
     expressing a floor below the deterministic verdict is attempting
     to cross the trust boundary, and that attempt is itself a signal
     worth recording.
  4. The BOM is recorded at decision time (compact, hash-chained) rather
     than reconstructed on demand from logs/traces. Cheaper to verify,
     harder to tamper with: each BOM record links to the previous via
     ``prev_bom_digest``, forming a decision-scoped sub-chain inside the
     main audit log's hash chain.

What this is NOT:
- Not a content oracle and not an LLM judge. Advisors are operator-
  supplied callables; the composer only enforces monotonicity. A
  "semantic" advisor that needs payload content must be built by the
  operator -- the composer hands advisors an args DIGEST plus a small
  set of boolean content signals, never raw args (privacy: advisors
  are pluggable code and must not become an exfil path for secrets).
- Not a replacement for policy. With no advisors configured the
  verdict path is byte-identical (opt-in, zero behavior change).
- Not cross-run. Composition is per-decision; there is no advisor
  memory across calls (an advisor that needs history keeps its own,
  outside the trust boundary).

Composition rule (the whole security argument): the final effect is
``max(deterministic_effect, advisor_1_floor, ..., advisor_n_floor)``
over the restrictiveness lattice, and flags are a set union. A later
advisor therefore CANNOT undo an earlier advisor's tightening, and no
advisor can express a floor below the deterministic verdict -- the
attempt is refused loud and its output discarded. Advisor ORDER is
irrelevant to the final effect (order-independence is asserted by the
break-first battery).

$0, stdlib only. Deterministic (advisors themselves may be stochastic;
their verdicts are recorded with a ``deterministic`` marker in the BOM).
"""

import hashlib
import json
from datetime import datetime, timezone

__all__ = [
    "EFFECTS",
    "EFFECT_RANK",
    "AdvisoryContext",
    "AdvisorVerdict",
    "Advisor",
    "AdvisorRecord",
    "ComposedAdvisory",
    "AdvisoryComposer",
    "DecisionBOM",
]

# The restrictiveness lattice. Advisors may only move a verdict UP this
# lattice, never down.
EFFECTS = ("allow", "require_approval", "deny")
EFFECT_RANK = {"allow": 0, "require_approval": 1, "deny": 2}

_BOM_VERSION = 1


def _canonical(obj):
    """Canonical JSON for hashing (stable key order, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=repr)


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


class AdvisoryContext(object):
    """The input snapshot handed to every advisor for one decision.

    Privacy: advisors receive ``args_digest`` (SHA-256 over canonical
    JSON of the call args) plus a small set of boolean content signals,
    never raw args. An advisor cannot exfiltrate what it cannot see.
    """

    def __init__(self, *, tool, args_digest, agent_id, role, principal,
                 run_id, deterministic_effect, policy_version,
                 policy_digest, content_signals=None):
        if deterministic_effect not in EFFECT_RANK:
            raise ValueError("unknown deterministic effect: %r"
                             % (deterministic_effect,))
        self.tool = tool
        self.args_digest = args_digest
        self.agent_id = agent_id
        self.role = role
        self.principal = principal
        self.run_id = run_id
        self.deterministic_effect = deterministic_effect
        self.policy_version = policy_version
        self.policy_digest = policy_digest
        self.content_signals = dict(content_signals or {})

    def to_dict(self):
        return {
            "tool": self.tool,
            "args_digest": self.args_digest,
            "agent_id": self.agent_id,
            "role": self.role,
            "principal": self.principal,
            "run_id": self.run_id,
            "deterministic_effect": self.deterministic_effect,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "content_signals": dict(self.content_signals),
        }


class AdvisorVerdict(object):
    """One advisor's output for one decision.

    ``floor`` is the minimum restrictiveness the advisor demands: None
    (no opinion), or one of "require_approval" / "deny" / "allow".
    "allow" is expressible but vacuous-or-hostile: on a verdict
    stricter than allow it is a monotonicity violation (the whitelist-
    after-deny attack); on an allow verdict it is a recorded no-op.
    """

    def __init__(self, floor=None, flags=(), reason="", deterministic=True):
        if floor is not None and floor not in EFFECT_RANK:
            raise ValueError("unknown advisor floor: %r" % (floor,))
        self.floor = floor
        self.flags = tuple(flags)
        for f in self.flags:
            if not isinstance(f, str):
                raise TypeError("advisor flags must be strings, got %r"
                                % (f,))
        self.reason = str(reason)
        self.deterministic = bool(deterministic)

    def to_dict(self):
        return {
            "floor": self.floor,
            "flags": list(self.flags),
            "reason": self.reason,
            "deterministic": self.deterministic,
        }


class Advisor(object):
    """Base class for advisors. Subclass and override advise()."""

    @property
    def name(self):
        return type(self).__name__

    def advise(self, ctx):
        """Return an AdvisorVerdict for ctx. Default: no opinion."""
        return AdvisorVerdict()


class AdvisorRecord(object):
    """How one advisor's verdict was treated by the composer."""

    def __init__(self, *, name, requested_floor, accepted, note,
                 flags_added=(), deterministic=True, input_digest="",
                 output_digest=""):
        self.name = name
        self.requested_floor = requested_floor
        self.accepted = bool(accepted)
        self.note = note
        self.flags_added = tuple(flags_added)
        self.deterministic = bool(deterministic)
        self.input_digest = input_digest
        self.output_digest = output_digest

    def to_dict(self):
        return {
            "name": self.name,
            "requested_floor": self.requested_floor,
            "accepted": self.accepted,
            "note": self.note,
            "flags_added": list(self.flags_added),
            "deterministic": self.deterministic,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
        }


class ComposedAdvisory(object):
    """The result of composing all advisors for one decision."""

    def __init__(self, *, deterministic_effect, final_effect, records,
                 flags, violations, errors):
        self.deterministic_effect = deterministic_effect
        self.final_effect = final_effect
        self.records = tuple(records)
        self.flags = frozenset(flags)
        # violations: advisor tried to go below the deterministic floor
        # (refused LOUD, output discarded). Each is a dict with
        # advisor / attempted_floor / deterministic_effect / reason.
        self.violations = tuple(violations)
        # errors: advisor crashed or returned a malformed verdict
        # (advisory_error LOUD, deterministic verdict kept).
        self.errors = tuple(errors)

    def tightened(self):
        """True when advisory moved the verdict up the lattice."""
        return EFFECT_RANK[self.final_effect] > \
            EFFECT_RANK[self.deterministic_effect]


class AdvisoryComposer(object):
    """Compose ordered advisors monotonically over the effect lattice.

    ``audit`` is an optional callable taking one event dict; violations
    and advisor errors are reported LOUD through it. When None, they
    are recorded on the ComposedAdvisory only (never silently dropped
    -- the caller can always inspect them).
    """

    def __init__(self, advisors, audit=None):
        self.advisors = list(advisors)
        for a in self.advisors:
            if not callable(getattr(a, "advise", None)):
                raise TypeError("advisor %r has no advise() callable"
                                % (a,))
        self.audit = audit

    def _loud(self, event):
        if self.audit is not None:
            self.audit(event)

    def compose(self, ctx):
        det_rank = EFFECT_RANK[ctx.deterministic_effect]
        floor_rank = det_rank
        flags = set()
        records = []
        violations = []
        errors = []
        input_digest = _sha256_hex(_canonical(ctx.to_dict()))

        for advisor in self.advisors:
            name = getattr(advisor, "name", None) or type(advisor).__name__
            try:
                verdict = advisor.advise(ctx)
            except Exception as e:  # noqa: BLE001 - advisor is untrusted code
                errors.append({"advisor": name,
                               "error": "%s: %s" % (type(e).__name__, e)})
                self._loud({
                    "event": "advisory_error",
                    "run_id": ctx.run_id,
                    "agent_id": ctx.agent_id,
                    "tool": ctx.tool,
                    "advisor": name,
                    "error": "%s: %s" % (type(e).__name__, e),
                    "reason": ("Advisor %r raised; its output is "
                               "discarded and the deterministic verdict "
                               "(%s) stands. The advisory layer can never "
                               "weaken the deterministic floor, including "
                               "through its own failure."
                               % (name, ctx.deterministic_effect)),
                })
                records.append(AdvisorRecord(
                    name=name, requested_floor=None, accepted=False,
                    note="advisor-error", input_digest=input_digest))
                continue
            try:
                if not isinstance(verdict, AdvisorVerdict):
                    raise TypeError(
                        "advise() must return AdvisorVerdict, got %r"
                        % type(verdict).__name__)
                # __init__ already validated floor/flags; re-check the
                # attributes in case of a hostile subclass.
                if verdict.floor is not None \
                        and verdict.floor not in EFFECT_RANK:
                    raise ValueError("unknown floor %r"
                                     % (verdict.floor,))
                output_digest = _sha256_hex(_canonical(verdict.to_dict()))
            except (TypeError, ValueError) as e:
                errors.append({"advisor": name,
                               "error": "malformed verdict: %s" % e})
                self._loud({
                    "event": "advisory_error",
                    "run_id": ctx.run_id,
                    "agent_id": ctx.agent_id,
                    "tool": ctx.tool,
                    "advisor": name,
                    "error": "malformed verdict: %s" % e,
                    "reason": ("Advisor %r returned a malformed verdict; "
                               "discarded, deterministic verdict (%s) "
                               "stands." % (name, ctx.deterministic_effect)),
                })
                records.append(AdvisorRecord(
                    name=name, requested_floor=None, accepted=False,
                    note="malformed-verdict", input_digest=input_digest))
                continue

            # Monotonicity gate FIRST: a verdict whose floor sits below
            # the deterministic verdict is a loosen attempt. The WHOLE
            # output -- floor and flags -- is discarded; nothing from a
            # violating advisor may leak into the composed result.
            if verdict.floor is not None:
                req_rank = EFFECT_RANK[verdict.floor]
                if req_rank < det_rank:
                    violations.append({
                        "advisor": name,
                        "attempted_floor": verdict.floor,
                        "deterministic_effect": ctx.deterministic_effect,
                        "reason": verdict.reason,
                    })
                    self._loud({
                        "event": "advisory_monotonicity_violation",
                        "run_id": ctx.run_id,
                        "agent_id": ctx.agent_id,
                        "tool": ctx.tool,
                        "advisor": name,
                        "attempted_floor": verdict.floor,
                        "deterministic_effect": ctx.deterministic_effect,
                        "flag": "advisory_monotonicity_violation",
                        "reason": ("Advisor %r attempted to loosen the "
                                   "deterministic verdict from %r to %r "
                                   "(%s); the attempt was refused and its "
                                   "output discarded. Advisory output can "
                                   "only tighten, never loosen."
                                   % (name, ctx.deterministic_effect,
                                      verdict.floor, verdict.reason)),
                    })
                    records.append(AdvisorRecord(
                        name=name, requested_floor=verdict.floor,
                        accepted=False, note="monotonicity-violation",
                        deterministic=verdict.deterministic,
                        input_digest=input_digest,
                        output_digest=output_digest))
                    continue

            # Accepted from here on: flags union (monotonic -- flags only
            # ever accumulate, never retract).
            flags.update(verdict.flags)
            if verdict.floor is None:
                records.append(AdvisorRecord(
                    name=name, requested_floor=None, accepted=True,
                    note="no-opinion", flags_added=verdict.flags,
                    deterministic=verdict.deterministic,
                    input_digest=input_digest,
                    output_digest=output_digest))
                continue
            req_rank = EFFECT_RANK[verdict.floor]
            if req_rank == det_rank:
                records.append(AdvisorRecord(
                    name=name, requested_floor=verdict.floor,
                    accepted=True, note="subsumed",
                    flags_added=verdict.flags,
                    deterministic=verdict.deterministic,
                    input_digest=input_digest,
                    output_digest=output_digest))
                continue
            # Genuine tightening. Max-composition: a later advisor can
            # never undo this, whatever it returns.
            note = "tightened" if req_rank > floor_rank \
                else "subsumed-by-earlier-tightening"
            if req_rank > floor_rank:
                floor_rank = req_rank
            records.append(AdvisorRecord(
                name=name, requested_floor=verdict.floor, accepted=True,
                note=note, flags_added=verdict.flags,
                deterministic=verdict.deterministic,
                input_digest=input_digest,
                output_digest=output_digest))

        return ComposedAdvisory(
            deterministic_effect=ctx.deterministic_effect,
            final_effect=EFFECTS[floor_rank],
            records=records,
            flags=flags,
            violations=violations,
            errors=errors,
        )


class DecisionBOM(object):
    """Bill of materials for one advisory-augmented policy decision.

    Each record names: the policy version + digest, the deterministic
    verdict, every advisor in order with its input/output digests and
    how its verdict was treated, the composed final effect, flags,
    violations, and a timestamp. Records chain via ``prev_bom_digest``
    (SHA-256 over the canonical previous record), forming a
    decision-scoped sub-chain inside the audit log's hash chain:
    tampering with any recorded BOM payload breaks ``verify_chain``.

    Scope (honest): the BOM covers the policy verdict + advisory
    composition. Deterministic fail-closed checks downstream of the
    advisory point (breaker, inventory, pre-commit, tempo, ...) may
    tighten further and are audited as their own events.
    """

    BOM_VERSION = _BOM_VERSION

    @staticmethod
    def digest(record):
        """SHA-256 over the canonical record, excluding bom_digest."""
        payload = {k: v for k, v in record.items() if k != "bom_digest"}
        return _sha256_hex(_canonical(payload))

    @staticmethod
    def build(*, tool, agent_id, role, principal, run_id,
              policy_version, policy_digest, deterministic_effect,
              deterministic_policy_id, composed, timestamp=None,
              prev_bom_digest=""):
        if not isinstance(composed, ComposedAdvisory):
            raise TypeError("composed must be ComposedAdvisory, got %r"
                            % type(composed).__name__)
        record = {
            "bom_version": _BOM_VERSION,
            "scope": "policy_verdict+advisory",
            "tool": tool,
            "agent_id": agent_id,
            "role": role,
            "principal": principal,
            "run_id": run_id,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "deterministic_effect": deterministic_effect,
            "deterministic_policy_id": deterministic_policy_id,
            "advisors": [r.to_dict() for r in composed.records],
            "final_effect": composed.final_effect,
            "flags": sorted(composed.flags),
            "violations": [dict(v) for v in composed.violations],
            "advisor_errors": [dict(e) for e in composed.errors],
            "timestamp": timestamp or _utcnow_iso(),
            "prev_bom_digest": prev_bom_digest,
        }
        record["bom_digest"] = DecisionBOM.digest(record)
        return record

    @staticmethod
    def verify_chain(records):
        """Verify a BOM sub-chain. Returns (ok, reason).

        Checks: every record is bom_version 1, prev_bom_digest links
        are intact, and every bom_digest matches its payload. Any
        tampering -- field flip, digest recompute, record drop or
        reorder -- fails the chain.
        """
        prev = ""
        n = 0
        for i, rec in enumerate(records or []):
            n += 1
            if not isinstance(rec, dict):
                return False, "record %d is not a dict" % i
            if rec.get("bom_version") != _BOM_VERSION:
                return False, "record %d has wrong bom_version %r" % (
                    i, rec.get("bom_version"))
            if rec.get("prev_bom_digest") != prev:
                return False, ("record %d linkage broken: prev_bom_digest "
                               "mismatch" % i)
            if rec.get("bom_digest") != DecisionBOM.digest(rec):
                return False, ("record %d digest mismatch: payload "
                               "tampered" % i)
            prev = rec["bom_digest"]
        return True, "%d records, chain intact" % n
