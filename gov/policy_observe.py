"""Per-policy observe -> enforce rollout lifecycle (wave-343 lane 5).

Kontext steal #2 (ADAPT -- discipline only; see
``~/workspace/teams/deepdive-kontext/STEAL-BRIEF.md``): every policy
starts in **Observing** mode with would-block counters, then flips to
**Enforced**. Adapted for Sasanam with our fail-closed guarantee
intact:

* Observe mode is an explicit, declared, auditable deployment choice
  for a whole policy -- never a silent fail-open. Kontext's
  documented fail-open-on-policy-evaluation-errors is DROPPED, not
  copied: if the wrapped engine's ``decide()`` raises, the wrapper
  propagates (never converts to allow).
* A policy in observe mode declares ``policy_mode="observe"`` in
  EVERY decision record (``PolicyDecision.to_dict()`` carries it;
  enforce-mode decisions serialize byte-identically, key absent).
* Flips in BOTH directions require an attested human quorum. Mirrors
  the wave-198 attestation gate: without a configured
  ``approvals.quorum`` on the wrapped engine, flips refuse (human
  approvers are unattested without the eligible-principals set).
* Pinned rules (deny-only: credential-exfil forbids, key-custody) are
  never weakened: a policy containing a pinned rule REFUSES
  per-policy observe deployment loudly.
* Would-block counters (evaluated / would_deny /
  would_require_approval / would_allow) accumulate in a hash-chained
  observation ledger and ride the flip record, so the quorum acts on
  evidence, not vibes.

Relationship to the wave-198 per-RULE ladder (gov/mode_ledger.py):
the ladder graduates individual rules observe -> warn -> deny. This
module is the per-POLICY deployment lifecycle: the whole policy
evaluates normally, the nominal verdict is recorded as would-block
telemetry, and no enforcement action is taken until the human flip.
The two compose: an observe-deployed policy still feeds real
evaluations into each rule's mode-ledger telemetry (the graduation
evidence base), because the nominal ``decide()`` runs for real.

Executor integration seam (documented, opt-in): ``PolicyObserveDeployment``
forwards every attribute it does not override to the wrapped engine
(``__getattr__``), so it is a drop-in for ``executor.policy`` -- the
executor's ``policy.decide(...)`` / ``policy.evaluate(...)`` /
``policy.mode_ledger`` / ``policy.policy_hash`` accesses keep working.
Deploy with::

    executor.policy = PolicyObserveDeployment(executor.policy)
    ok, reasons = executor.policy.deploy_observe(approvers=["alice", "bob"])

Honest v1 boundary: the observation ledger is IN-MEMORY per
deployment object (mirrors the mode ledger's documented boundary).
The durable, auditor-facing trail is the executor's hash-chained audit
log, which receives every decision via the normal path -- each
carrying ``policy_mode="observe"`` while observed. Do not represent
an in-memory observation window as durable evidence.

Stdlib only. Deterministic apart from the clock, injectable for tests.
"""

import hashlib
import json
import time
from dataclasses import replace

from .decision_contract import Request
from .mode_ledger import ModeLedger
from .policy import PolicyDecision, PolicyEngine

# Per-policy deployment modes. "enforce" is the resting state;
# "observe" is the rollout rung. Unlike the per-rule ladder there is
# no "warn" rung at policy scope: a whole policy either enforces or
# it declares itself observed.
POLICY_MODES = ("observe", "enforce")


class PolicyObserveError(Exception):
    """The deployment refused an operation (loud, fail-closed)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _request_digest(request):
    """Stable digest of the evaluated request (observation attribution)."""
    action = request.to_action() if hasattr(request, "to_action") else {}
    return _sha256_hex(_canonical({
        "tool": action.get("tool"),
        "args": action.get("args") or {},
        "agent_id": action.get("agent_id"),
        "role": action.get("role"),
    }))


class PolicyObserveDeployment:
    """Per-policy observe -> enforce lifecycle wrapping a PolicyEngine.

    Drop-in for ``executor.policy``: unknown attributes forward to the
    wrapped engine. ``decide()`` / ``evaluate()`` are overridden so an
    observe-deployed policy records the nominal verdict as would-block
    telemetry and returns an explicitly-declared observe decision
    (effect allow, nominal preserved) instead of enforcing.
    """

    def __init__(self, engine, *, clock=None):
        if not isinstance(engine, PolicyEngine):
            raise PolicyObserveError(
                "PolicyObserveDeployment wraps a PolicyEngine, got %r"
                % type(engine).__name__)
        # Bypass __getattr__ for the wrapped engine (set first).
        object.__setattr__(self, "_engine", engine)
        self._clock = clock or time.time
        self._policy_mode = "enforce"
        self._chain = []
        self._head = "GENESIS"
        self._seq = 0
        self._flips = 0
        self._reset_counters()

    # ------------------------------------------------------- delegation
    def __getattr__(self, name):
        # Only fires for attributes the wrapper does not define, so
        # decide/evaluate/policy_mode/stats/... take precedence and
        # everything else (egress, role_allows, mode_ledger,
        # policy_hash, approvals_quorum, ...) forwards to the engine.
        return getattr(object.__getattribute__(self, "_engine"), name)

    # ------------------------------------------------------------ mode
    @property
    def policy_mode(self):
        """Current per-policy deployment mode ("enforce" | "observe")."""
        return self._policy_mode

    def _now(self):
        return float(self._clock())

    def _reset_counters(self):
        self._counters = {
            "evaluated": 0,
            "would_deny": 0,
            "would_require_approval": 0,
            "would_allow": 0,
        }

    def _append(self, kind, payload):
        self._seq += 1
        record = {
            "seq": self._seq,
            "prev": self._head,
            "kind": kind,
            "policy_mode": self._policy_mode,
            "at": self._now(),
        }
        record.update(payload)
        record["digest"] = _sha256_hex(_canonical(
            {k: v for k, v in record.items() if k != "digest"}))
        self._chain.append(record)
        self._head = record["digest"]
        return record

    # ------------------------------------------------------------ quorum
    def _require_human_quorum(self):
        """Attestation gate (mirrors PolicyEngine._require_human_quorum).

        Flips change enforcement for the whole policy; without a
        configured approvals.quorum the approver names are
        self-attested, which is exactly the rubber-stamp the quorum
        exists to prevent. Fail closed.
        """
        if self._engine.approvals_quorum is None:
            return False, [
                "no approvals.quorum configured: human approvers are "
                "unattested without the eligible-principals set; "
                "refusing rather than flipping enforcement on "
                "self-attested names (configure approvals.quorum with "
                "eligible_principals)"]
        return True, []

    def _pinned_rule_ids(self):
        """Rule ids the ladder marks pinned (deny-only, never weakened)."""
        ledger = self._engine.mode_ledger
        return [rid for rid in ledger.rule_ids()
                if (ledger.stats(rid) or {}).get("pinned")]

    # ------------------------------------------------------------ flips
    def deploy_observe(self, *, approvers):
        """Deploy the policy in observe mode. Returns (ok, reasons).

        Loud refusals: already observing; no approvals.quorum
        configured; any pinned rule registered; quorum not met.
        On success the observation window starts fresh (counters
        reset) and the flip is chained with the approvers.
        """
        if self._policy_mode == "observe":
            return False, ["policy is already deployed in observe mode"]
        ok, reasons = self._require_human_quorum()
        if not ok:
            return False, reasons
        pinned = self._pinned_rule_ids()
        if pinned:
            return False, [
                "pinned rule(s) %s are deny-only and never enter "
                "observe: per-policy observe would weaken them; "
                "refusing" % (sorted(pinned),)]
        quorum_cfg = self._engine.approvals_quorum
        ok, qreason = ModeLedger._check_quorum(approvers, quorum_cfg)
        if not ok:
            return False, [qreason]
        self._reset_counters()
        self._policy_mode = "observe"
        self._flips += 1
        approver_names = sorted(
            (p[0] if isinstance(p, (list, tuple)) else p) for p in approvers)
        self._append("mode_change", {
            "old_mode": "enforce",
            "new_mode": "observe",
            "approvers": approver_names,
            "pinned_check": "no pinned rules",
            "counters": dict(self._counters),
        })
        return True, ["observe deployed: %s" % qreason]

    def enforce(self, *, approvers):
        """Flip the policy back to enforcing. Returns (ok, reasons).

        The would-block counters accumulated during the observation
        window ride the flip record, so the quorum's decision is
        evidence-bound. Counters are NOT reset here -- stats() stays
        cumulative for the deployment's life; each flip record carries
        its window snapshot.
        """
        if self._policy_mode == "enforce":
            return False, ["policy is already enforcing"]
        ok, reasons = self._require_human_quorum()
        if not ok:
            return False, reasons
        quorum_cfg = self._engine.approvals_quorum
        ok, qreason = ModeLedger._check_quorum(approvers, quorum_cfg)
        if not ok:
            return False, [qreason]
        self._policy_mode = "enforce"
        self._flips += 1
        approver_names = sorted(
            (p[0] if isinstance(p, (list, tuple)) else p) for p in approvers)
        self._append("mode_change", {
            "old_mode": "observe",
            "new_mode": "enforce",
            "approvers": approver_names,
            # The evidence the quorum acted on: the full observation
            # window's would-block counts.
            "counters": dict(self._counters),
        })
        return True, ["enforce resumed: %s" % qreason]

    # ------------------------------------------------------------ decide
    def decide(self, request, *, record_telemetry=True):
        """Decide a request (drop-in for PolicyEngine.decide).

        Enforce mode: the wrapped engine decides, unchanged.
        Observe mode: the engine still decides for real (feeding the
        per-rule mode-ledger telemetry -- real evaluations, real
        evidence), the nominal verdict is chained as a would-block
        observation, and the RETURNED decision is an explicitly
        declared observe decision: effect allow (no enforcement
        action), nominal_effect preserved, policy_mode "observe" in
        every serialized record.

        Fail-closed: if the engine's decide() raises, the exception
        propagates -- the wrapper never converts an evaluation error
        into an allow (Kontext's fail-open is dropped, not copied).
        A failed evaluation is not counted.
        """
        if self._policy_mode == "enforce":
            return self._engine.decide(request,
                                       record_telemetry=record_telemetry)
        # Observe mode: evaluate for real first. A raise propagates
        # (fail-closed) and is not counted -- only a completed nominal
        # verdict becomes an observation.
        nominal = self._engine.decide(request,
                                      record_telemetry=record_telemetry)
        c = self._counters
        c["evaluated"] += 1
        if nominal.effect == "deny":
            c["would_deny"] += 1
        elif nominal.effect == "require_approval":
            c["would_require_approval"] += 1
        else:
            c["would_allow"] += 1
        self._append("observation", {
            "nominal_effect": nominal.effect,
            "deciding_rule_id": nominal.policy_id,
            "request_digest": _request_digest(request),
            "would_block": nominal.effect == "deny",
        })
        # The observe decision: no enforcement action (allow), but the
        # nominal verdict is preserved and the deployment mode is
        # declared on the record -- never a silent allow.
        return replace(
            nominal,
            effect="allow",
            allowed=True,
            nominal_effect=nominal.effect,
            policy_mode="observe",
            reason=("[observe] nominal %s by %s; no enforcement action "
                    "taken (policy deployed in observe mode)"
                    % (nominal.effect, nominal.policy_id)),
        )

    def evaluate(self, action, context=None, *, record_telemetry=True):
        """Return a PolicyDecision (drop-in for PolicyEngine.evaluate).

        Routes through decide() so observe semantics are identical;
        stamps the policy revision exactly like the engine does.
        """
        decision = self.decide(
            Request.from_action(action, context),
            record_telemetry=record_telemetry).to_policy_decision()
        decision.policy_rev_id = "policy:" + self._engine.policy_version
        decision.policy_digest = self._engine.policy_hash
        return decision

    # ------------------------------------------------------------ queries
    def stats(self):
        """Would-block counters + deployment state (copy)."""
        out = dict(self._counters)
        out["policy_mode"] = self._policy_mode
        out["would_block"] = self._counters["would_deny"]
        out["observations"] = sum(
            1 for r in self._chain if r["kind"] == "observation")
        out["flips"] = self._flips
        out["chain_len"] = len(self._chain)
        out["chain_head"] = self._head
        return out

    def records(self):
        """The chained observation/mode-change records (oldest first)."""
        return tuple(dict(r) for r in self._chain)

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
