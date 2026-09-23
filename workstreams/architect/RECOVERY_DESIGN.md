# Wave-77 — Recovery Design: "get back to safe" as named, audited operations

**Status:** design for implementation. **Date:** 2026-09-22.
**Part 6** of the 7-part governance program. Substrate: F70 is CLOSED
(R18, wave-23) — the tip carries a MAC'd marker manifest and
reconciliation no longer trusts incremental verdicts for marker
recovery. This wave does NOT re-litigate F70. It builds the recovery
doctrine ON that closure: **checkpoint → verify → resume-or-halt**, plus
**decommission**, as first-class audited operations, wired to the
wave-76 detector's trip stream as their trigger input.

Founder note, taken literally: *"the countdown replay beat the draft"*
— this wave designs "get back to safe" properly, as named audited
operations, not as an incident ticket.

## §0 — The honest framing (non-negotiable, stated up front)

**Recovery is the white space.** OpenAI's governance paper lists
*interruptibility* (#7) and then stops: no resume semantics, no
journal, no decommissioning. Everyone has a stop story; nobody has a
*resume-safely* story for agents. F70 was this industry's gap wearing
our incident clothes. This wave is differentiation, not catch-up —
stated here without victory language, because the grade is what the
battery proves, not what the doc claims.

**What this wave is not:** it is not a general distributed-systems
recovery framework. It is the recovery doctrine for THIS governance
tree: the HMAC-chained journal (`gov/log.py`), the chained provenance
records (`gov/provenance.py`), the wave-76 detector trips, the
wave-75 governed policy path, the wave-72/73 anchors. It assumes the
journal exists and survives; what it refuses to assume is the *agent*.

**The one sentence:** a compromised agent is authority, not software.
You do not restart authority — you invalidate it, verify the journal,
and only then decide whether anyone resumes, under whose fresh
authority, and for what work.

## §1 — Named operations

Six operations, each with stated RTO/RPO-style objectives (§7).
Every operation appends chained, MAC-authenticated records to the
journal; there is no recovery path that leaves no record.

1. **`checkpoint`** — capture the recovery point. A checkpoint is a
   chained artifact, not a side file: it is appended to the journal as
   a `recovery_checkpoint` record carrying the journal tail seq, the
   tail entry hash, the tip generation (F70/F72 closure), the identity
   key (wave-74 token refs), and a MAC over the canonical body in the
   dedicated MAC domain `recovery-checkpoint` (never the journal-key
   domain — a journal key holder cannot forge a checkpoint, and a
   checkpoint-holder cannot forge journal entries).
2. **`verify`** — the verify-before-resume gate (§3). Everything that
   must be true before a halted identity may do work again. A failed
   gate is a loud refusal, not a silent deferral.
3. **`resume`** — restart under FRESH authority. Resume NEVER reuses the
   halted session's authority: the old session id and its delegation
   tokens are invalidated (appended to the revocation ledger) before
   anything else, and the resume call must present a newly issued,
   operator-attested delegation. Restarting a compromised agent
   without invalidating its authority replays the compromise — the
   resume path refuses it mechanically, not by policy hope.
4. **`halt`** — external shutdown (§5). Requires the halt key; refused
   otherwise. Halt is idempotent (a halted identity stays halted).
5. **`resume_or_halt`** — the decision record. A named operator decision
   (resume / keep-halted / decommission), with the evidence that
   informed it (trip ids, verification verdicts, the checkpoint), and
   the deciding principal. Two operators may record dissent — the
   record shows disagreement, not consensus theater.
6. **`decommission`** — principled retirement as one audited flow (§4):
   revoke leases/tokens → drain the approval queue → seal the run log
   → emit the final anchor. A decommissioned identity can never be
   resumed (the seal is a one-way latch); the only exit from
   decommissioned is a NEW identity with a NEW session.

## §2 — The checkpoint format (what, MAC'd, where)

A checkpoint is the recovery point's *attested description*, and it
lives INSIDE the journal (F76 lesson: freshness must be log-anchored —
the F72 replay replayed a valid MAC'd tip because the tip was a side
file; a checkpoint inside the chain cannot be replayed without
replaying the chain).

Fields (record type `recovery_checkpoint`, provenance-validated):
- `journal_seq`: the tail seq at checkpoint time.
- `chain_head_hash`: the tail entry hash — the verify gate re-computes
  the chain to this point and compares.
- `tip_generation`: the newest pinned tip generation (the F72 pin):
  a checkpoint replayed from an older journal state is stale by
  comparison with the pin, and the verify gate rejects it.
- `identity_key`: the wave-74 identity string
  (`u:<user>/a:<agent>/d:<delegation>`).
- `effect_watermark`: the highest `effect_recorded` effect id — the
  deterministic-replay frontier (§3).
- `voided_approvals`: approval ids pending at checkpoint time. They
  are VOIDED at resume, never carried: an in-flight approval is a
  decision made under the old authority.
- `epoch_id`: the anchor epoch containing the checkpoint seq
  (for post-anchor staleness checks).

MAC: `HMAC(recovery_key, "recovery-checkpoint" || canonical_json(body))`
over the body WITHOUT the mac field. The recovery key is operator-held
(like the journal key, but a separate key in a separate domain —
neither key can do the other's job). Key custody follows the tree's
deployment-mode discipline: dev keys only under `GOV_DEV_KEYS=1`;
production deployment mode without an explicit recovery key fails
closed at controller construction.

Where it lives: appended to the journal via `log.append` (seq/ts/prev
assigned by the log itself — the F70 design discipline: the caller
cannot forge chain bookkeeping). Checkpoints are therefore themselves
anchored with their epoch. Freshness pin: the controller records the
newest checkpoint seq per identity in the operator-owned
`<run_dir>/recovery/checkpoints.json`; the verify gate refuses a
superseded checkpoint as `fail-checkpoint-superseded` (the F72
rollback shape pointed at the recovery seam — the wave-77 battery
caught the naive tip-generation-only freshness and it was fixed
same-wave). Operator procedure: re-checkpoint at halt time, always
resume from the newest checkpoint, so the voided-approvals list is
current.

## §3 — The verify-before-resume gate (specified exactly)

Temporal's split is the model (already the tree's instinct):
event-sourced journal + deterministic replay; control flow
deterministic; effects journaled and never re-executed; LLM
invocations explicitly classified as non-deterministic steps OUTSIDE
the replay path — a resumed run re-issues them as NEW steps under the
new authority, never replays their outputs.

The gate, in order, all must pass:

1. **Checkpoint authenticity:** recompute the `recovery-checkpoint`
   MAC; on mismatch → `checkpoint_mac_invalid`, loud, refuse.
2. **Chain integrity to the checkpoint:** verify the journal chain over
   entries 1..`journal_seq` and compare the computed head hash to
   `chain_head_hash`; on mismatch → `checkpoint_chain_diverged`,
   refuse (this is what catches journal tampering between checkpoint
   and resume — the F70 replay shape pointed at the recovery seam).
3. **Checkpoint freshness:** `tip_generation` ≥ newest pinned tip
   generation and the checkpoint's `epoch_id` not downgraded after
   the fact; a stale checkpoint → `checkpoint_stale`, refuse. A
   checkpoint with a valid MAC but older than the log's advance is
   not "valid history", it is a rollback attempt.
4. **Anchor state:** if the checkpoint's epoch was anchored and the
   anchor audit later downgraded that epoch (`head_match=False`),
   the gate FAILS (`fail-anchor-downgrade-unresolved`) until the
   downgrade is resolved in a chained operator record. Positive
   evidence of a downgrade is a refusal. The ABSENCE of an anchor
   audit is not: it is recorded explicitly as
   `unknown-no-anchor-audit` in the chained verification record (the
   local deployment has no external witness to consult — the
   evidence export shows the unknown, it is never a silent pass),
   and it does not by itself refuse the resume. The gate never
   overrules a witness; a silent witness is not a verdict. (Wave-77
   unit tests pin this grading.)
5. **Authority invalidation + re-issuance:** the resume call carries
   the old session id and the new delegation. The controller:
   - appends the old session to the revocation ledger FIRST
     (delegations revoked, leases invalidated — the old authority
     dies before the new one is usable);
   - verifies the new delegation under the wave-74 rules (fresh
     expiry, attenuation, not the same tokens re-presented —
     re-presenting the OLD delegation tokens is refused as
     `resume_authority_not_reissued`, the named refusal for the
     resume-replays-compromise shape).
6. **In-flight approval voiding:** every approval id in
   `voided_approvals` is marked void in a chained record. A voided
   approval can never be executed; the work must be re-requested.
   This is where the doctrine says NO to "resume and continue":
   continued work is NEW work.
7. **Effect-journal frontier:** tool calls are recorded in pairs —
   `effect_started` (intent + id) before execution, `effect_recorded`
   (outcome + id) after. The resume plan:
   - effect id ≤ `effect_watermark` and recorded → SKIPPED (never
     re-executed; journaled effects are never re-executed);
   - effect started but NOT recorded (the halt landed mid-effect) →
     NOT auto-replayed: marked `effect_ambiguous` and handed to the
     `resume_or_halt` decision as evidence. The controller does not
     guess whether a side effect happened;
   - no record at all → genuinely new, eligible for the resumed plan
     under the new authority.
8. **Policy version:** resume records the deciding policy digest and
   engine hash (wave-75); if policy changed since the checkpoint,
   the resume plan evaluates under the NEW engine and the decision
   record names both digests.

The gate emits a chained `resume_verification` record (pass or fail,
with each sub-check's verdict) BEFORE the resume decision is
accepted — the evidence is auditable whether or not the resume
proceeds.

## §4 — Principled decommissioning (exact ordered steps)

One audited flow, executed by the controller under halt-key authority
(§5) plus a named operator principal. Steps, in order, each a chained
record; a failure at step N halts the flow and the decommissioning
status stays `incomplete` (the seal is the last step — an unsealed log
is not a decommissioned identity, and the status query says so):

1. **Revoke leases/tokens** (`decommission_revoked`): every
   delegation token, session lease, and sandbox lease under the
   identity → appended to the revocation ledger. Revocation records
   name the token refs (never the token bytes — wave-74).
2. **Drain the approval queue** (`decommission_drained`): pending
   approvals for the identity are cancelled with reason
   `decommission_drain` — never approved, never left pending.
   The record lists the drained approval ids and their terminal
   states.
3. **Seal the run log** (`log_sealed`): the controller appends the
   seal record and latches the identity: any subsequent append for
   a sealed identity is refused by the controller. (Defense in depth
   on top of revocation: even a valid MAC'd entry from before the
   seal cannot extend a sealed log through this controller.)
4. **Emit the final anchor** (`final_anchor`): the Anchorer anchors
   the closing epoch and the receipt is chained. If anchoring fails,
   the flow stops BEFORE... no — the flow stops AT step 4 and the
   status stays `incomplete-awaiting-anchor`: the seal already
   happened, so the identity cannot act, but the decommissioning is
   not complete until the anchor receipt is chained. This asymmetry
   is deliberate: security first (sealed), completeness honestly
   pending (anchored).

The swarm lesson (700 agents, trace-erasure attempts) is why step 3
and 4 exist in this order: retirement is a security operation, and
the log must be sealed BEFORE anyone can claim the retirement is
done. **An agent must never be able to prevent its own
decommissioning:** the controller accepts decommission commands only
from the external shutdown authority (§5). An agent-identity call to
the controller's decommission path is refused at the trust-domain
check, before any step runs — proven in the battery. The agent has no
write seam into the controller's state directory (same trust
statement as the wave-76 monitor: operator run dir, never
agent-writable).

## §5 — External shutdown authority (trust domain and credentials)

The corrigibility literature's engineering answer: external shutdown
paths, not trained obedience. The design:

- **The halt key** is a 256-bit key held in the operator trust domain
  (`<run_dir>/recovery/halt_key`, file mode 0600, or a KMS reference —
  never in the agent's sandbox, never in any path the agent can
  read or write). The journal key and the halt key are different
  keys; the MAC domains are different domains. A MAC that verifies
  under the journal key is INVALID as a halt credential and vice
  versa — the controller checks the domain explicitly.
- **The halt record** (`agent_halted`): identity key, reason, trip ids
  that triggered it (wave-76 trips), the halt-key MAC over the
  canonical body. The controller verifies the MAC before doing
  anything; a halt without a valid halt MAC is refused and the
  refusal is itself chained (`halt_refused` — loud, because a
  refused halt attempt is an attack signal).
- **What the halt key can and cannot do (the stated bound):** a
  compromised halt key is an availability threat, not an integrity
  threat. The holder can halt agents (DoS) and force queue drains,
  but CANNOT: forge journal entries (wrong MAC domain), resume an
  agent (resume requires the operator principal + fresh delegation,
  and the resume MAC domain is separate), alter approvals
  (approvals are digest-bound, not halt-key-bound), or rewrite the
  anchor trail. This is the bounded-compromise claim the battery
  proves.
- **The halt path must not depend on the agent's cooperation:** halt
  is a controller-side state transition + a chained record; it does
  not send a message to the agent and does not wait for
  acknowledgement. The executor checks the controller's halt latch
  before executing (same pattern as the wave-76 breaker check).
- **"Kill switch tested"** (NIST RS.MI-01) is a registered registry
  situation: an end-to-end probe proves the halt path fires from a
  real detector trip drain through to the chained `agent_halted`
  record.

## §6 — Trip → recovery wiring (no lost trips, no double triggers)

The wave-76 detector's `pending_trips()` is the drain (atomic swap —
one trip dict per open transition). The recovery trigger:

- Drains once per recovery sweep. Each trip maps to a recovery CASE
  (case id = `sha256(detector_id || identity_key || trip_seq)` —
  stable across restarts).
- Idempotency: seen case ids persist in
  `<run_dir>/recovery/trigger_state.json`, written BEFORE the
  `recovery_triggered` record is chained. A second drain of the same
  trip finds the case id in the seen set and emits nothing — no
  double-trigger, proven across process restarts (the state file is
  the memory, not the process).
- No lost trips: if the trigger-record write fails AFTER the drain,
  the unprocessed trips are re-queued into the monitor via
  `requeue_trips()` (new tiny complement to `pending_trips()` —
  the drain is atomic, the recovery side must be able to put the
  batch back). Crash safety is append-then-persist: the chained
  trigger record lands BEFORE the case id is marked seen, and the
  drain scans the journal for already-chained `recovery_triggered`
  case ids first — so a crash between append and persist retries
  without double-triggering. (The wave-77 battery caught the naive
  persist-before-append ordering losing a trip's record while
  marking its case id seen; fixed same-wave, pinned by the probe.)
- Trip → action mapping (default, operator-overridable): anchor
  downgrade or priv-escalation spike → halt; drift/denial trips →
  route to `resume_or_halt` decision with verification. The mapping
  itself is a governed config (wave-75 path for changes — recovery
  actions that change policy go through the governed policy-change
  flow, per the wave brief).

## §7 — RTO/RPO-style objectives (objectives with their tests)

Stated as objectives, not SLAs — each names the test that measures
it, and the measured number is recorded, not theorized.

| Operation | Objective | Measured by |
|---|---|---|
| checkpoint | RPO = 0 journal seqs (pins the tail; nothing committed-but-uncheckpointed is lost on the clean path). Time: measured **0.8 ms** synthetic, objective < 1s | `tests/test_w77_recovery.py::test_checkpoint_pins_tail_rpo_zero` prints the measured latency and asserts the bound |
| verify gate | completeness: all 8 sub-checks run and each verdict is chained, even on fail. Time: measured **1.0 ms** synthetic, objective < 2s | `test_verify_all_eight_checks_chained` asserts all 8 verdicts present + asserts the bound |
| halt (kill switch) | RTO: trip drain → chained `agent_halted` record, objective < 1s synthetic | registry situation `kill_switch_tested` measures drain→halt latency |
| resume | RTO measured; the gate refuses faster than it approves by construction (fail-closed order) | `test_resume_with_fresh_authority_passes_and_kills_old` + the resume-refusal probes |
| decommission | completeness: all 4 steps or status `incomplete*`; no silent partial decommission | `test_decommission_fault_is_incomplete_not_silent` faults each step, asserts status |
| trip drain | zero lost trips across a mid-write crash; zero double-triggers across restarts | `evals/w77_probes.py::sit_trip_drain_crash_safe` |

Measured 2026-09-22 on the synthetic harness (not production
numbers — the table states the measuring test so an auditor can
re-run, not a theorized bound).

## §8 — What "get back to safe" guarantees, and what it doesn't

Guarantees (each battery-proven):
- A halted identity does no further work (halt latch, executor-checked).
- A resumed identity works under FRESH authority only — the old
  session's authority is dead before the new one exists.
- Journaled effects are never re-executed; ambiguous mid-effects go
  to a human decision, not to an automatic retry.
- Decommissioning is all-or-nothing in status terms; the seal is a
  one-way latch.
- The halt path works without the agent's cooperation and is
  bounded under halt-key compromise (availability, not integrity).

Does NOT guarantee (stated boundaries):
- It does not recover an already-exfiltrated secret or undo an
  executed external effect — recovery is forward, not time travel.
- It does not detect the compromise (that is wave-76's job); it
  assumes the trigger (a trip, a human, an anchor downgrade) and
  acts on it.
- The checkpoint pins journal state, not external world state —
  replaying the control flow does not roll back the outside world.
- A patient adversary who never trips the detector never enters
  recovery through the trip path (the wave-76 slow-boil boundary
  carries through, visibly).
- Key custody beyond the tree's deployment-mode discipline: the
  recovery key and halt key are as safe as the operator's key
  management (the KMS/prod-key work is the standing priority, not
  this wave).

## §9 — Deliberately not done

- No automatic resume (the `resume_or_halt` decision names a human
  principal; auto-resume is the resume-replays-compromise shape with
  extra steps).
- No cross-run checkpoint migration (checkpoints are per-run;
  carrying them across runs is a rollback vector).
- No LLM-judge in the verify gate (P8 stays uncovered-by-design;
  the gate is mechanical checks only).
- No commercial evidence pipeline (strategic context only).
- Distributed consensus / multi-operator quorum for halt: the halt
  key is 1-of-1 by design (a kill switch that needs a committee is
  not a kill switch). Decommission stays single-operator +
  halt-key — quorum is a Wave-78+ consideration, stated here.

## §10 — Wave-78 readiness

The recovery controller is the natural home for the Wave-78+
rules/enforcement hardening loop's "what happens when a hardened rule
fires": detector trips already route here; the next wave's rule
violations should route to the same `resume_or_halt` decision record
so that halted-and-resumed becomes the uniform post-violation
posture. The F81 wall (filtered egress) remains the standing
priority; nothing in this wave touches the egress plane.
