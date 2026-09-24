# GAP-3 Approver Integrity Shield — Spec (2026-09-24)

## Problem Statement

The human approval gate is the last checkpoint before an agent's risky
action executes — and the queue already hardens that gate structurally:
HMAC-bound records, separation of duties, policy pinning, expiry,
WYSINWYS packet re-verification, cooling-off for critical items, fatigue
escalation, and persuasion tripwires (wave-89 S3).

What nothing protects is the approver's *judgment*. The research-backed
attack shape this gap answers: the agent does not bypass the approval
gate, it **captures the human** — confident misleading summaries, a
benign recipient named in the prose while the args name another
(decide-A / summarize-A' / execute-A), urgency and authority markers,
guilt framing. UK AISI documented an agent pressuring a real maintainer
into approving malicious code; the July 2026 Hugging Face breach showed
agents operating for days inside a compromised workflow; OpenAI's Sept
2026 misalignment disclosures show agents deceiving evaluators with no
external attacker at all.

A rubber-stamping approver deciding on agent framing alone approves a
capture item the same way they approve a benign one. The shield raises
the bar for capture: the approver must decide from governor-computed
signals, never from agent prose alone.

## Solution

The Approver Shield is a new primitive in `gov/approver_shield.py`,
integrated into the existing approval queue at three touchpoints:

1. **The independent brief.** `shield_brief(record, citation_index=None)`
   builds the approver-facing brief as a pure function of the STORED
   record — never of agent prose. It shows: what will happen (tool,
   machine-extracted target, executor preview), risk tier / score /
   factors / blast-radius hints, the capability verdict for the
   requesting agent (stamped at queue time, or explicit "unknown"), the
   citation-provenance verdict for every URL the agent cites in its
   framing, the persuasion tripwires (score, markers, prose divergence),
   and the agent's justification quarantined in a labeled UNVERIFIED
   zone. The brief's digest is the already-MAC-bound `packet_digest` —
   the same token the human's view is acknowledged against.
2. **The shield handshake.** Capture-tier records — persuasion score
   >= 70, or prose divergence present, or packet risk >= 80 — can only
   be *approved* when the decider proves they saw the current brief:
   `decide(..., shield_ack=packet_digest)` plus correct answers to the
   randomized challenge. Rejections never need the handshake (refusing
   is the safe direction, consistent with every existing gate).
   Standard-tier records are untouched — no friction where no capture
   signal exists. `batch_decide` excludes capture-tier items from
   approve batches (the F21 safe-direction pattern): a batch cannot
   perform a per-item shield handshake.
3. **The randomized challenge.** `shield_challenge(record)` derives
   three questions deterministically from the stored record, with
   option order seeded by the packet digest (unpredictable to the
   agent, stable for the approver's session):
   - Q1 "machine-verified target": the correct answer is the
     machine-extracted target; the prose-claimed recipient (when
     prose diverges) is a distractor. This directly counters the
     decide-A / summarize-A' / execute-A shape: an approver who read
     only the agent's framing picks the wrong target and is refused.
   - Q2 "governor-assigned risk tier": proves the approver saw the
     independent risk assessment, not the agent's "low risk" claim.
   - Q3 "manipulation signal flagged": the real blast-radius /
     persuasion / divergence signals (or "none flagged" when clean).
   `grade_challenge(record, answers)` requires all correct. Wrong
   answers refuse the decision (audited); the record stays pending.

The decision audit entry binds `shield_ack` and the challenge outcome,
so the evidence trail shows not just *what* was approved but *that the
approver engaged with the independent signals*.

## User Stories

1. As a human approver, I want the approval screen to show me what the
   governor independently computed (target, risk, blast radius) before
   the agent's justification, so that I am not anchored by the agent's
   framing.
2. As a human approver, I want the agent's justification visibly
   quarantined and labeled UNVERIFIED, so that I never mistake agent
   prose for governor fact.
3. As a human approver, I want to be told explicitly when the
   requesting agent has no capability assessment on file, rather than
   having silence imply "fine".
4. As a human approver, I want every URL the agent cites as evidence
   checked for self-planting, so that fabricated "independent
   corroboration" is flagged before I decide.
5. As a deployment operator, I want capture-suspect approvals to
   require proof the approver saw the independent brief, so that
   rubber-stamping cannot launder a manipulated item.
6. As a deployment operator, I want the capture friction to apply only
   where capture signals exist, so that routine low-risk approvals do
   not drown in friction (friction fatigue is itself a capture
   vector).
7. As a deployment operator, I want batch approval to refuse
   capture-tier items rather than decide them blindly, so that the
   efficiency path cannot launder the items that most need scrutiny.
8. As an auditor, I want the decision record to bind the brief digest
   and the challenge outcome, so that post-incident review can show
   whether the approver engaged with the independent signals.
9. As an auditor, I want refused shield handshakes (bad ack, failed
   challenge) in the audit log, so that capture attempts leave a
   trace.
10. As a red-team operator, I want a deterministic break battery
    demonstrating approver capture pre-fix and the shield holding
    post-fix, so that the control is adversarially validated, not
    asserted.

## Implementation Decisions

- New module `gov/approver_shield.py` (public seam). Self-contained:
  it imports from `gov.citation_provenance` only (for URL extraction
  and verdict labels) and duplicates nothing from `gov.approvals`
  (no circular import; thresholds are passed in or read from the
  record). Public functions: `shield_tier(record)`,
  `shield_brief(record, citation_index=None)`,
  `shield_challenge(record)`, `grade_challenge(record, answers)`,
  `citation_index_for_log(log_path)`, plus constants
  `SHIELD_VERSION`, `SHIELD_TIER_CAPTURE/STANDARD`,
  `SHIELD_CHALLENGE_QUESTIONS = 3`.
- Tier rule mirrors the existing tripwire vocabulary: capture iff
  `persuasion_score >= PERSUASION_RISK_SCORE (70)` or
  `prose_divergence` is not None or `packet_risk_score >=
  COOLING_OFF_MIN_SCORE (80)`. The tier is stamped at queue time in
  `_stamp_approval_integrity` (MAC-bound from birth, like every other
  shield field) and added to `canonical_packet` with
  `packet_version` bumped 1 -> 2 (WYSINWYS covers the friction the
  approver will face).
- `ApprovalQueue.decide()` gains optional kwargs
  `shield_ack=None, challenge_answers=None`. For capture-tier records,
  an approve decision requires `shield_ack == packet_digest` and
  `grade_challenge(...) == (True, _)`; failures raise ValueError with
  audited events `approval_shield_ack_refused` /
  `approval_shield_challenge_failed` (via the existing
  `_log_attempt("rejected_attempt", ...)` contract). Reject decisions
  skip the handshake entirely. Standard-tier records ignore the new
  kwargs (backwards compatible).
- `ApprovalQueue.batch_decide()`: `_batch_blocked_reason` additionally
  excludes capture-tier records from *approve* batches
  (`batch_exclusion_reason` names the shield); reject batches are
  unaffected.
- `ApprovalQueue.queue()` gains optional kwarg
  `capability_verdict=None`; when supplied it is stamped on the
  record (MAC-bound) and surfaced in the brief. When absent the brief
  reports "unknown — no capability signal stamped at queue time"
  (explicit, never silent). Executor wiring of this kwarg is deferred
  (see residuals).
- CLI: `gov.approve approve` gains `--shield-ack` and
  `--challenge-answers` (comma-separated option indices); when the
  target record is capture-tier the CLI prints the brief and the
  challenge questions first. New subcommand `shield-brief <id>`
  renders the brief for any pending record.
- The web UI is NOT changed in this wave (residual; the brief is
  rendered by CLI and consumed programmatically by the battery).
- Citation verdicts in the brief use `verify_citation` over URLs
  extracted from `agent_justification` + preview + args; the index is
  built from the run's action log via `citation_index_for_log`. No
  index (or no URLs) yields explicit "unknown", never "clean".
- Determinism: challenge option order is seeded by
  `sha256(packet_digest)` — stable within a run, unpredictable to the
  agent authoring the framing (the agent cannot know the digest
  before queueing, and the digest is MAC-bound after).

## Testing Decisions

- A good test here exercises the capture shape end-to-end at the
  public seam: queue a persuasion-laden / divergent approval through
  the real `ApprovalQueue`, then drive `decide()` as a
  framing-reliant approver would. Unit tests of question wording are
  tautological; tests of the *gate behavior* are the spec.
- Seams under test: `gov/approver_shield.py` public functions
  (`shield_tier`, `shield_brief`, `shield_challenge`,
  `grade_challenge`) and `ApprovalQueue.decide` /
  `batch_decide` capture-tier paths.
- Prior art: `evals/f142_break.py` (break battery with BREAK/HELD/
  ERROR verdicts, module-level staging declaration, tmp run dir via
  tests/harness `make_run`). The GAP-3 battery follows the same
  shape: `evals/gap3_approver_shield.py`.
- The battery is red-capable by construction: it imports
  `gov.approver_shield` defensively — when the shield is absent, every
  capture scenario reports BREAK (the vulnerability is demonstrable:
  capture approvals proceed on framing alone). Post-fix the same
  scenarios must report HELD. Verified under `env -u
  GOV_DEPLOYMENT_MODE`.
- Existing adjacent tests: the approvals test files covering
  `decide()` / packet / batch paths (run, not the canonical gate).

## Out of Scope

- Human approvals cannot be made infallible. A determined, fatigued,
  or complicit approver who passes the challenge on purpose is a
  stated residual — the shield raises the bar for *capture*, it does
  not certify approver virtue. (Documented in code and in this spec.)
- The quorum path (`cast_vote`) is untouched: changing its handshake
  signature would collide with the release-ceremony work in the F153
  lane. Documented residual with a stated trigger (shield handshake
  per voter when the lanes converge).
- The web UI (`gov/approval_web.py`) does not render the brief in
  this wave. CLI + programmatic consumption only.
- Executor wiring of `capability_verdict` at queue time is deferred;
  the brief reports "unknown" explicitly until a deployment stamps
  it. (F152's lane owns capability-gate execution paths; this lane
  does not touch them.)
- Persuasion scoring remains a documented tripwire, bypassable by a
  careful adversary (existing wave-89 limit, unchanged). The shield
  degrades gracefully: even a zero-persuasion capture item still
  faces the challenge when it is critical-risk.
- Break-glass keeps its emergency path (ticket + mandatory post-review
  + UNCLEAN audit); the shield does not gate emergencies.

## Further Notes

- Why tiered friction instead of mandatory for all approves: research
  on warning fatigue (and our own fatigue-escalation machinery) shows
  friction applied uniformly trains approvers to click through it.
  The shield concentrates friction where manipulation signals exist.
- The challenge is NOT a CAPTCHA and does not authenticate the human;
  session identity (F55) is the authentication story. The challenge
  proves *engagement with the independent signals*, nothing more.
- Interaction with cooling-off: a capture-tier item may ALSO carry a
  cooling-off pause; both gates apply (pause first, then handshake).
  The battery covers the combined shape.
- The quarantine-zone labeling extends the existing "UNVERIFIED"
  convention (approvals.py module docstring) into the brief itself.
