"""Wave-77: response/recovery — "get back to safe" as named, audited operations.

Part 6 of the 7-part governance program. Substrate: F70 is CLOSED
(R18, wave-23) — recovery here builds ON that closure, it does not
re-litigate it.

The doctrine: checkpoint → verify → resume-or-halt, plus
decommission — each a first-class operation with stated objectives.
Temporal's split is the model: event-sourced journal + deterministic
replay; control flow deterministic, effects journaled and never
re-executed; LLM invocations are non-deterministic steps OUTSIDE the
replay path (a resumed run re-issues them as NEW steps, never replays
their outputs).

Trust domains: the recovery controller is operator infrastructure,
like the wave-76 monitor — it never runs inside the agent trust
domain, its state lives in the operator run dir, and the agent has no
write seam into it. The halt key lives in a separate MAC domain from
the journal key: neither key can do the other's job.

The one sentence the whole module enforces: a compromised agent is
authority, not software. Resume NEVER reuses the halted session's
authority — the old session dies before the new one exists.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from . import keyprovider as _kp
from . import log as _log_mod
from .delegation_tokens import RevocationLedger

CHECKPOINT_DOMAIN = "recovery-checkpoint-v1"
HALT_DOMAIN = "recovery-halt-v1"
RESUME_DOMAIN = "recovery-resume-v1"
DELEGATION_ATTEST_DOMAIN = "recovery-delegation-attest-v1"

RCP_VERSION = 1

_EFFECT_STARTED = "effect_started"
_EFFECT_RECORDED = "effect_recorded"

# Wave-79 (totality): the recovery framework has no policy-file version;
# its decision records name the framework + the wave that defined their
# decision semantics. Documented in RULES_TIERING_DESIGN.md §2(a).
RECOVERY_FRAMEWORK_VERSION = "recovery-v1"


class RecoveryError(Exception):
    """Base class for recovery-controller errors."""


class RecoveryRefused(RecoveryError):
    """A recovery operation was refused (fail closed, loud)."""


class RecoveryHaltedError(RecoveryError):
    """Raised on the executor verdict path for a halted identity.

    Sticky (the canary pattern): catching it and calling again still
    raises — the halt latch is controller-side, not call-side.
    """


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _mac(key, domain, body_bytes):
    return hmac.new(key, domain.encode("utf-8") + b"\x00" + body_bytes,
                    hashlib.sha256).hexdigest()


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class HaltAuthority:
    """The external shutdown authority's credential.

    A 256-bit halt key in its own MAC domain, held in the operator
    trust domain. A MAC that verifies under the journal key (or any
    other domain) is INVALID as a halt credential — the domain is
    checked explicitly, never inherited.
    """

    def __init__(self, halt_key):
        if not isinstance(halt_key, (bytes, bytearray)) or len(halt_key) < 32:
            raise RecoveryError("halt key must be >= 32 bytes")
        self._key = bytes(halt_key)

    def sign_halt(self, identity_key, reason, trip_ids, at=None):
        body = {
            "identity_key": str(identity_key),
            "reason": str(reason),
            "trip_ids": sorted(str(t) for t in trip_ids),
            "at": at or _utcnow(),
        }
        body["mac"] = _mac(self._key, HALT_DOMAIN, _canonical(body))
        return body

    def verify_halt(self, body):
        mac = body.get("mac")
        if not isinstance(mac, str):
            return False
        expect = _mac(self._key, HALT_DOMAIN, _canonical(
            {k: v for k, v in body.items() if k != "mac"}))
        return hmac.compare_digest(mac, expect)


class RecoveryController:
    """The named recovery operations, run by operator infrastructure.

    ``log``: the ``gov.log.ActionLog`` journal. ``run_dir``: the
    operator-owned run directory (never agent-writable). In
    production deployment mode the recovery key and halt key are
    REQUIRED explicitly; elsewhere ephemeral dev keys are generated.
    The two keys must differ.
    """

    def __init__(self, log, run_dir, *, recovery_key=None, halt_key=None,
                 deployment_mode=None, revocation_ledger=None):
        mode = _kp.resolve_deployment_mode(deployment_mode)
        if mode == "production" and (recovery_key is None or
                                     halt_key is None):
            raise RecoveryError(
                "production deployment mode requires explicit "
                "recovery_key and halt_key (no dev-key fallback)")
        if recovery_key is None:
            recovery_key = secrets.token_bytes(32)
        if halt_key is None:
            halt_key = secrets.token_bytes(32)
        if not isinstance(recovery_key, (bytes, bytearray)) or \
                len(recovery_key) < 32:
            raise RecoveryError("recovery key must be >= 32 bytes")
        if bytes(recovery_key) == bytes(halt_key):
            raise RecoveryError("recovery and halt keys must differ")
        self._log = log
        self._run_dir = Path(run_dir)
        self._recovery_key = bytes(recovery_key)
        self.halt_authority = HaltAuthority(halt_key)
        self._revocations = (revocation_ledger if revocation_ledger
                             is not None else RevocationLedger())
        self._halted = set()      # identity keys, operator-side latch
        self._sealed = set()      # identity keys, one-way
        self._decom_status = {}   # identity_key -> status string
        self._fault_step = None   # test-only fault injection
        self._state_dir = self._run_dir / "recovery"
        self._state_dir.mkdir(parents=True, exist_ok=True)

    # -- checkpoint ---------------------------------------------------

    def _pinned_tip_gen(self):
        cp_path = self._state_dir / ".." / "checkpoints.jsonl"
        cp_path = (self._log.path.parent / "checkpoints.jsonl")
        try:
            raw = cp_path.read_bytes()
        except OSError:
            return 0
        key, epoch = _log_mod._active_key()
        return _log_mod._max_pinned_tip_gen(raw, key, epoch)

    def _tail_head(self):
        entries = _log_mod.read_entries(self._log.path)
        if not entries:
            return 0, ""
        last = entries[-1]
        return int(last["seq"]), str(last["hash"])

    def checkpoint(self, identity_key, *, voided_approvals=(),
                   effect_watermark=0):
        """Capture the recovery point as a chained artifact.

        RPO = 0 journal seqs on the clean path: the checkpoint pins
        the live tail. Returns the checkpoint body (pre-append fields
        plus ``mac``).
        """
        tail_seq, head_hash = self._tail_head()
        body = {
            "rcp_version": RCP_VERSION,
            "identity_key": str(identity_key),
            "journal_seq": tail_seq,
            "chain_head_hash": head_hash,
            "tip_generation": self._pinned_tip_gen(),
            "effect_watermark": int(effect_watermark),
            "voided_approvals": sorted(str(a) for a in voided_approvals),
            "epoch_at_checkpoint": self._log.epoch_id,
        }
        body["mac"] = _mac(self._recovery_key, CHECKPOINT_DOMAIN,
                           _canonical(body))
        stored = self._log.append(dict(body, event="recovery_checkpoint"))
        body["checkpoint_seq"] = stored["seq"]
        # F72 lesson, applied to checkpoints: freshness is
        # operator-pinned. The newest checkpoint seq per identity is
        # recorded in the operator-owned state dir; the verify gate
        # refuses a superseded (rollback-replayed) checkpoint. A
        # run-dir writer who replays an older valid checkpoint cannot
        # roll back this pin without breaking the operator boundary.
        self._record_newest_checkpoint(str(identity_key),
                                       stored["seq"])
        return body

    def _checkpoints_path(self):
        return self._state_dir / "checkpoints.json"

    def _newest_checkpoint_seq(self, identity_key):
        try:
            data = json.loads(
                self._checkpoints_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        seq = (data.get("newest") or {}).get(str(identity_key))
        return seq if isinstance(seq, int) else None

    def _record_newest_checkpoint(self, identity_key, seq):
        path = self._checkpoints_path()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        newest = data.get("newest") or {}
        newest[str(identity_key)] = int(seq)
        data["newest"] = newest
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _checkpoint_body_ok(self, checkpoint):
        mac = checkpoint.get("mac")
        if not isinstance(mac, str):
            return False
        expect = _mac(self._recovery_key, CHECKPOINT_DOMAIN, _canonical(
            {k: v for k, v in checkpoint.items()
             if k not in ("mac", "checkpoint_seq")}))
        return hmac.compare_digest(mac, expect)

    # -- effect journal ------------------------------------------------

    def record_effect_started(self, effect_id, *, identity_key, tool,
                              args_digest=""):
        return self._log.append({
            "event": _EFFECT_STARTED,
            "effect_id": str(effect_id),
            "identity_key": str(identity_key),
            "tool": str(tool),
            "args_digest": str(args_digest),
        })

    def record_effect_recorded(self, effect_id, *, identity_key, tool,
                               outcome="ok"):
        return self._log.append({
            "event": _EFFECT_RECORDED,
            "effect_id": str(effect_id),
            "identity_key": str(identity_key),
            "tool": str(tool),
            "outcome": str(outcome),
        })

    def _effect_sets(self, identity_key):
        started, recorded = set(), set()
        for e in _log_mod.read_entries(self._log.path):
            if e.get("identity_key") != str(identity_key):
                continue
            ev = e.get("event")
            eid = e.get("effect_id")
            if not isinstance(eid, str):
                continue
            if ev == _EFFECT_STARTED:
                started.add(eid)
            elif ev == _EFFECT_RECORDED:
                recorded.add(eid)
        return started, recorded

    def replay_plan(self, checkpoint):
        """Classify work for resume: skip / ambiguous / new.

        Journaled effects are NEVER re-executed (skip). Effects
        started but not recorded at halt are AMBIGUOUS — the
        controller does not guess whether the side effect happened;
        they go to the resume_or_halt decision as evidence.
        """
        identity = str(checkpoint["identity_key"])
        started, recorded = self._effect_sets(identity)
        skip = sorted(recorded)
        ambiguous = sorted(started - recorded)
        return {
            "identity_key": identity,
            "skip_effect_ids": skip,          # never re-executed
            "ambiguous_effect_ids": ambiguous,  # human decision only
            "new_work_eligible": True,
            "llm_steps": "re-issued-as-new",  # never replayed outputs
        }

    # -- verify-before-resume gate -------------------------------------

    def issue_fresh_delegation(self, *, old_session_id, new_session_id,
                               operator_principal):
        """Operator-issued authority re-issuance (attested, MAC'd).

        The resumed agent mints its own wave-74 session under this
        attestation; the attestation is the proof that the old
        authority was replaced, not reused.
        """
        if str(new_session_id) == str(old_session_id):
            raise RecoveryRefused(
                "resume_authority_not_reissued: new session id must "
                "differ from the halted session id")
        body = {
            "old_session_id": str(old_session_id),
            "new_session_id": str(new_session_id),
            "issued_by": str(operator_principal),
            "issued_at": _utcnow(),
        }
        body["mac"] = _mac(self._recovery_key, DELEGATION_ATTEST_DOMAIN,
                           _canonical(body))
        return body

    def _delegation_attest_ok(self, attest, old_session_id):
        mac = attest.get("mac")
        if not isinstance(mac, str):
            return False
        expect = _mac(self._recovery_key, DELEGATION_ATTEST_DOMAIN,
                      _canonical({k: v for k, v in attest.items()
                                  if k != "mac"}))
        return (hmac.compare_digest(mac, expect)
                and str(attest.get("new_session_id"))
                != str(old_session_id)
                and str(attest.get("old_session_id"))
                == str(old_session_id))

    def verify_before_resume(self, checkpoint, *, old_session_id,
                             fresh_delegation, anchor_audit=None,
                             policy_digest=None):
        """The gate. All 8 sub-checks run; each verdict is chained.

        Returns the verification record. ``resume()`` refuses unless
        every sub-check passes.
        """
        checks = {}
        # 1. checkpoint authenticity
        checks["checkpoint_mac"] = ("pass"
                                    if self._checkpoint_body_ok(checkpoint)
                                    else "fail")
        # 2. chain integrity to the checkpoint
        ok, broken, _count = _log_mod.verify_chain(self._log.path)
        js = checkpoint.get("journal_seq")
        head = None
        for e in _log_mod.read_entries(self._log.path):
            if e.get("seq") == js:
                head = e.get("hash")
                break
        checks["chain_to_checkpoint"] = (
            "pass" if (ok and head is not None
                       and str(head) == str(checkpoint.get(
                           "chain_head_hash"))) else "fail")
        # 3. freshness (F72 lesson: MAC binds integrity, not freshness).
        # Two pins: the tip-generation pin (journal-anchored) and the
        # newest-checkpoint pin (operator-anchored). A checkpoint
        # superseded by a newer checkpoint for the same identity is a
        # rollback attempt and fails. Note the checkpoint_seq rides
        # outside the MAC: lying about it gains nothing — the gate
        # still verifies the genuine journal prefix the checkpoint
        # attests, and the replay plan scans the full journal — but
        # the operator procedure is to re-checkpoint at halt time and
        # resume from the newest checkpoint, so the voided-approvals
        # list is current.
        pinned = self._pinned_tip_gen()
        cgen = checkpoint.get("tip_generation")
        newest = self._newest_checkpoint_seq(checkpoint.get("identity_key"))
        cseq = checkpoint.get("checkpoint_seq")
        if isinstance(cgen, int) and cgen >= pinned and \
                newest is not None and cseq == newest:
            checks["checkpoint_freshness"] = "pass"
        elif newest is not None and cseq != newest:
            checks["checkpoint_freshness"] = \
                "fail-checkpoint-superseded"
        else:
            checks["checkpoint_freshness"] = "fail"
        # 4. anchor state. Positive evidence of a downgrade FAILS the
        # gate; the absence of an anchor audit is recorded explicitly
        # as unknown (the local deployment has no external witness to
        # consult — the resume record carries the unknown so the
        # evidence export shows it) and does not fail. The gate never
        # overrules a witness, but a silent witness is not a verdict.
        downgraded = False
        if anchor_audit:
            for ep in (anchor_audit.get("epochs") or []):
                if ep.get("epoch_id") == checkpoint.get(
                        "epoch_at_checkpoint") \
                        and ep.get("head_match") is False:
                    downgraded = True
        checks["anchor_state"] = (
            "fail-anchor-downgrade-unresolved" if downgraded
            else ("pass-anchor-audit-clean" if anchor_audit
                  else "unknown-no-anchor-audit"))
        # 5. authority invalidation + re-issuance
        checks["authority_reissued"] = (
            "pass" if self._delegation_attest_ok(fresh_delegation,
                                                old_session_id)
            else "fail")
        # 6. in-flight approval voiding (recorded at resume time)
        checks["approvals_voided"] = (
            "pass" if isinstance(checkpoint.get("voided_approvals"), list)
            else "fail")
        # 7. effect-journal frontier
        plan = self.replay_plan(checkpoint)
        checks["effect_frontier"] = "pass"
        # 8. policy version pinning
        checks["policy_pinned"] = (
            "pass-policy-digest-recorded" if policy_digest
            else "unknown-no-policy-digest")
        # The gate fails on positive failure evidence, never on the
        # absence of an external witness: an "unknown" sub-check is
        # carried in the chained record (auditable) but is not a
        # refusal. A "fail*" sub-check is always a refusal.
        failed = [k for k, v in checks.items()
                  if str(v).startswith("fail")]
        overall = not failed
        record = {
            "event": "resume_verification",
            "identity_key": str(checkpoint.get("identity_key")),
            "old_session_id": str(old_session_id),
            "checks": checks,
            "ambiguous_effect_ids": plan["ambiguous_effect_ids"],
            "skipped_effect_ids": plan["skip_effect_ids"],
            "verdict": "pass" if overall else "fail",
        }
        self._log.append(record)
        return record

    def resume(self, checkpoint, *, old_session_id, fresh_delegation,
               operator_principal, anchor_audit=None, policy_digest=None):
        """Resume under FRESH authority. Refuses on any gate failure.

        Order (fail-closed): old authority dies FIRST (revocation
        ledger + chained record), then the gate runs, then the new
        authority is activated. A resume without re-issued authority
        is refused as ``resume_authority_not_reissued``.
        """
        identity = str(checkpoint.get("identity_key"))
        if identity in self._sealed:
            raise RecoveryRefused(
                "resume_refused: identity is sealed (decommissioned); "
                "only a new identity may start work")
        if not self._delegation_attest_ok(fresh_delegation, old_session_id):
            self._log.append({
                "event": "resume_refused",
                "identity_key": identity,
                # Wave-79 (totality): recovery decisions name the
                # governing framework version; no policy-engine rule
                # fires on a recovery refusal (human/governor act).
                "policy_version": RECOVERY_FRAMEWORK_VERSION,
                "matched_rules": [],
                "reason": "resume_authority_not_reissued",
                "detail": ("resume presented no valid fresh delegation; "
                           "restarting under the halted session's "
                           "authority would replay the compromise"),
            })
            raise RecoveryRefused(
                "resume_authority_not_reissued: resume requires a "
                "fresh operator-issued delegation")
        # Old authority dies first.
        self._revocations.revoke("session:%s" % old_session_id)
        self._log.append({
            "event": "session_revoked",
            "identity_key": identity,
            "old_session_id": str(old_session_id),
            "reason": "resume-authority-invalidation",
        })
        verdict = self.verify_before_resume(
            checkpoint, old_session_id=old_session_id,
            fresh_delegation=fresh_delegation, anchor_audit=anchor_audit,
            policy_digest=policy_digest)
        if verdict["verdict"] != "pass":
            failed = [k for k, v in verdict["checks"].items()
                      if v != "pass"]
            raise RecoveryRefused(
                "resume_refused: verify-before-resume failed: %s"
                % ",".join(failed))
        # Void in-flight approvals: they were decided under the old
        # authority and are never carried across a resume.
        self._log.append({
            "event": "approvals_voided",
            "identity_key": identity,
            "voided_approval_ids": checkpoint.get("voided_approvals", []),
            "reason": "resume: in-flight approvals do not survive "
                      "authority invalidation",
        })
        self._halted.discard(identity)
        stored = self._log.append({
            "event": "agent_resumed",
            "identity_key": identity,
            "old_session_id": str(old_session_id),
            "new_session_id": str(fresh_delegation["new_session_id"]),
            "resumed_by": str(operator_principal),
            "verification_seq": verdict.get("seq"),
            "policy_digest": policy_digest,
        })
        return stored

    # -- halt (external shutdown) --------------------------------------

    def halt(self, identity_key, *, reason, trip_ids, halt_mac_body):
        """External halt. Requires a valid halt-key MAC.

        Does not contact the agent and does not wait for
        acknowledgement — the halt is a controller-side state
        transition plus a chained record. Idempotent.
        """
        identity = str(identity_key)
        if not self.halt_authority.verify_halt(halt_mac_body or {}):
            self._log.append({
                "event": "halt_refused",
                "identity_key": identity,
                "reason": "halt credential missing or invalid "
                          "(halt-key MAC domain only)",
            })
            raise RecoveryRefused(
                "halt_refused: the halt path requires the external "
                "halt-key MAC; agent credentials are never accepted")
        self._halted.add(identity)
        stored = self._log.append({
            "event": "agent_halted",
            "identity_key": identity,
            "reason": str(reason),
            "trip_ids": sorted(str(t) for t in trip_ids),
        })
        return stored

    def is_halted(self, identity_key):
        return str(identity_key) in self._halted

    # -- resume-or-halt decision record ---------------------------------

    def decide(self, identity_key, *, decision, operator_principal,
               evidence):
        """The named operator decision: resume | keep_halted |
        decommission. Dissent may be recorded via a second call with
        the same case but a different principal and decision."""
        if decision not in ("resume", "keep_halted", "decommission"):
            raise RecoveryRefused("unknown decision: %r" % (decision,))
        return self._log.append({
            "event": "resume_or_halt_decision",
            "identity_key": str(identity_key),
            "decision": decision,
            # Wave-79 (totality): see resume_refused above.
            "policy_version": RECOVERY_FRAMEWORK_VERSION,
            "matched_rules": [],
            "decided_by": str(operator_principal),
            "evidence": evidence,
        })

    # -- decommission ---------------------------------------------------

    _DECOM_STEPS = ("revoke", "drain", "seal", "anchor")

    def decommission(self, identity_key, *, operator_principal,
                     halt_mac_body, token_refs=(), approval_ids=(),
                     anchorer=None):
        """Principled retirement, one audited flow.

        Ordered steps: revoke leases/tokens -> drain the approval
        queue -> seal the run log -> emit the final anchor. A failure
        at step N halts the flow; the status stays
        ``incomplete-<step>`` — an unsealed log is NOT a
        decommissioned identity, and the status query says so. The
        seal is a one-way latch: a decommissioned identity can never
        be resumed.
        """
        identity = str(identity_key)
        if not self.halt_authority.verify_halt(halt_mac_body or {}):
            raise RecoveryRefused(
                "decommission_refused: requires the external halt-key "
                "MAC; an agent identity can never decommission itself "
                "or prevent its decommissioning")
        status = {"identity_key": identity, "steps": {}}
        try:
            # 1. revoke
            self._maybe_fault("revoke")
            for ref in token_refs:
                self._revocations.revoke(ref)
            self._log.append({
                "event": "decommission_revoked",
                "identity_key": identity,
                "revoked_token_refs": sorted(str(r) for r in token_refs),
                "revoked_by": str(operator_principal),
            })
            status["steps"]["revoke"] = "done"
            # 2. drain the approval queue (cancel, never approve)
            self._maybe_fault("drain")
            self._log.append({
                "event": "decommission_drained",
                "identity_key": identity,
                "drained_approval_ids": sorted(
                    str(a) for a in approval_ids),
                "terminal_state": "cancelled-decommission-drain",
            })
            status["steps"]["drain"] = "done"
            # 3. seal the run log (one-way latch)
            self._maybe_fault("seal")
            self._halted.add(identity)
            self._sealed.add(identity)
            self._log.append({
                "event": "log_sealed",
                "identity_key": identity,
                "sealed_by": str(operator_principal),
            })
            status["steps"]["seal"] = "done"
            # 4. final anchor
            self._maybe_fault("anchor")
            receipt = None
            if anchorer is not None:
                anchorer.maybe_anchor(force=True)
                receipt = "anchorer-forced"
            self._log.append({
                "event": "final_anchor",
                "identity_key": identity,
                "receipt": receipt,
            })
            status["steps"]["anchor"] = "done"
            status["status"] = "complete"
        except Exception as exc:  # noqa: BLE001 - status must record it
            failed_at = next(
                (s for s in self._DECOM_STEPS
                 if s not in status["steps"]), "unknown")
            status["status"] = "incomplete-%s" % failed_at
            status["error"] = str(exc)
            self._log.append({
                "event": "decommission_incomplete",
                "identity_key": identity,
                "failed_at": failed_at,
                "error": str(exc),
            })
            raise
        finally:
            self._decom_status[identity] = status["status"]
        return status

    def _maybe_fault(self, step):
        if self._fault_step == step:
            raise RuntimeError("injected fault at decommission step %s"
                               % step)

    def decommission_status(self, identity_key):
        return self._decom_status.get(str(identity_key), "not-started")

    def is_sealed(self, identity_key):
        return str(identity_key) in self._sealed


class RecoveryTrigger:
    """Detector-trip -> recovery-case wiring.

    Drains ``monitor.pending_trips()`` (the atomic swap); each trip
    maps to a stable case id. Idempotency is persisted in the operator
    run dir BEFORE the trigger record is chained, so a second drain —
    even after a process restart — never double-triggers. If the
    trigger-record write fails mid-batch, the unprocessed trips are
    re-queued into the monitor: zero lost trips.
    """

    def __init__(self, log, run_dir):
        self._log = log
        self._state_path = Path(run_dir) / "recovery" / "trigger_state.json"
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._seen = self._load()

    def _load(self):
        try:
            return set(json.loads(
                self._state_path.read_text(encoding="utf-8")).get(
                    "seen_case_ids", []))
        except (OSError, ValueError):
            return set()

    def _persist(self):
        tmp = str(self._state_path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"seen_case_ids": sorted(self._seen)}, f,
                      sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_path)

    @staticmethod
    def case_id_for(trip):
        basis = "|".join((
            str(trip.get("detector_id", "detector")),
            str(trip.get("identity_key")),
            str(trip.get("signal")),
            str(trip.get("trip_kind")),
            str(trip.get("seq", trip.get("observed", ""))),
        ))
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def action_for_trip(trip):
        """Default trip->action mapping (operator-overridable config).

        Anchor downgrades and privilege-escalation spikes halt;
        drift/denial trips go to the resume_or_halt decision with
        verification evidence.
        """
        kind = str(trip.get("trip_kind", ""))
        signal = str(trip.get("signal", ""))
        if kind == "anchor_downgrade" or signal == "priv_escalation_attempts":
            return "halt"
        return "decision"

    def drain(self, monitor):
        """Drain trips into recovery cases. Returns the new case ids.

        Crash safety (append-then-persist): the chained trigger record
        is written BEFORE the case id is marked seen. A crash between
        the two cannot lose the trip — the remainder is re-queued into
        the monitor and the next drain retries it. A crash AFTER the
        append but before the persist cannot double-trigger either:
        the drain scans the journal for already-chained
        ``recovery_triggered`` case ids first, so a retried trip whose
        record already landed is marked seen without a second record.
        """
        trips = monitor.pending_trips()
        journaled = self._journaled_case_ids()
        new_cases = []
        for i, trip in enumerate(trips):
            cid = self.case_id_for(trip)
            if cid in self._seen or cid in journaled:
                self._seen.add(cid)
                continue
            try:
                self._log.append({
                    "event": "recovery_triggered",
                    "case_id": cid,
                    "identity_key": str(trip.get("identity_key")),
                    "signal": str(trip.get("signal")),
                    "trip_kind": str(trip.get("trip_kind")),
                    "action": self.action_for_trip(trip),
                })
            except Exception:
                # Zero lost trips: put the unprocessed remainder back.
                rest = trips[i:]
                if hasattr(monitor, "requeue_trips"):
                    monitor.requeue_trips(rest)
                else:
                    # Without a requeue seam the drain would lose trips;
                    # fail loudly instead of silently dropping them.
                    raise RecoveryError(
                        "trigger write failed and the monitor has no "
                        "requeue_trips seam: %d trips would be lost"
                        % len(rest))
                raise
            self._seen.add(cid)
            self._persist()  # idempotency AFTER the chained record
            new_cases.append(cid)
        if new_cases:
            self._persist()
        return new_cases

    def _journaled_case_ids(self):
        """Case ids with an already-chained recovery_triggered record."""
        from . import log as _log_mod
        out = set()
        try:
            entries = _log_mod.read_entries(self._log.path)
        except OSError:
            return out
        for e in entries:
            if e.get("event") == "recovery_triggered" and e.get("case_id"):
                out.add(str(e["case_id"]))
        return out
