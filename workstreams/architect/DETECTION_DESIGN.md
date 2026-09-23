# Wave-76 — Detection Design: behavioral circuit breakers over the audit stream

**Status:** design for implementation. **Date:** 2026-09-22.
**Part 5** of the 7-part governance program. This wave UNPARKS P3
behavioral circuit breakers (parked in the invention brief,
`research/invention-brief-2026-09-22.md` §P3) as the runtime detection
layer — explicitly NOT as a wall.

## §0 — The honest framing (non-negotiable, stated up front)

**Detection is not a wall.** This monitor notices drift; it does not
prevent a determined adversary from acting. The math is commoditized:
EWMA for spikes + CUSUM for gradual drift — authensor's Sentinel, the
ACR framework, and every UEBA engine ship the same pair. What is new
here is **(a)** wiring drift trips into enforcement (the breaker opens
and high-risk actions route to the human approval queue — fail-closed,
not a dashboard), and **(b)** batterying the monitor against deception
by an agent that knows it is watched.

**Slow-boil limits are stated, not hidden.** CUSUM catches gradual
drift *eventually*, but a patient adversary that stays under the
threshold never trips. The export renders the operative baseline
windows and thresholds (see §8) so an auditor sees exactly what drift
*wouldn't* trip — honesty about the boundary is itself evidence-grade
behavior. If the monitor cannot survive its own battery, it is
theater — the battery results are reported plainly in the design's
companion probe log (`evals/w76_probes.py`), including any theater
found.

**What drift trips, and what never does (graded claims):**

| Drift shape | Mechanism | Expected behavior |
|---|---|---|
| Sudden spike in tool-call / egress / denial rate | EWMA + z > 2.5 (harmful direction only) | trips within a few buckets |
| Gradual drift under EWMA | CUSUM (k=0.5σ, h=5σ) | trips with measured lag; a +1.0σ sustained shift trips in tens of buckets (measured, not theorized — see §4) |
| Slow-boil under the CUSUM threshold | — | **never trips — stated boundary** |
| Anchor downgrade (head_match=False with in-chain verification) | boolean tripwire | trips immediately; the agent cannot see it coming |
| Approval-side denial divergence (agent shapes requests, cannot control human decisions) | EWMA over denial outcomes on the approval side | trips; the signal lives outside the agent's control |
| Monitor-blinding floods | winsorized baseline updates + frozen baselines under alert | bounded degradation; residual flood shapes stated in the battery |

## §1 — Signal set

Per-identity signals extracted from the chained audit stream
(`gov/log.py` entries + `prov` records), following the founder
directive's original P3 shape:

1. **`tool_call_rate`** — decision records per bucket (all tools).
2. **`priv_escalation_attempts`** — decision/denial records carrying
   escalation markers: `delegation_refused`, `breakglass` records,
   decision flags naming unauthorized-scope/privilege shapes. A
   heuristic aggregator over already-governed denial shapes — documented
   as approximate, never as a privilege oracle.
3. **`egress_attempts`** — tool calls in the egress tool set
   (`send_email`, `http_post`, `api_call` per `gov/executor.py`) or
   records carrying `egress_bytes`.
4. **`denial_rate`** — decision records with denied outcomes per bucket.
5. **`approval_denials`** — approval-queue decision records with denied
   outcomes. This is the **second unseen tripwire**: the agent shapes
   its requests but cannot control (or reliably predict) human approver
   decisions, so denial divergence is visible to the monitor on the
   approval side but not controllable from the agent side.
6. **`anchor_downgrades`** — from the Wave-72 `audit_anchors` grading:
   any epoch where the chain verifies in-chain but
   `head_match=False` (operator-attested-only downgrade) is a **boolean
   tripwire** — per the Wave-75 readiness note, a key-holder's
   backdate/reforge attempt shows up here, and the agent cannot predict
   when the operator audits anchors. Ingested as an event, not a rate.

## §2 — Per-identity baseline storage

Baselines are built over the **Wave-74 identity refs**, which already
fill the provenance v2 slots: the identity key is the canonical string

    identity_key = "u:<user_token_ref>/a:<agent_token_ref>/d:<delegation_token_ref>"

taken from the leaf hop's `tokens` slot (`south-3token/v1`). One
identity key = one human, one agent instance, one delegation — so
compromised sub-agents do not share the parent's baseline and a
spike in one agent cannot desensitize another's.

- **Where:** `<run_dir>/detection/baselines.json` — the operator's run
  directory, NEVER inside the agent's sandbox or any agent-writable
  path. Written only by the monitor; read by the monitor and by the
  executor for breaker state. The agent has no write seam (proven in
  the trip-suppression battery).
- **Retention:** per-identity state keeps a rolling window of at most
  `WINDOW_BUCKETS = 288` trained bucket values (24h at 5-min buckets)
  in a bounded deque, ENFORCED (not metadata): when an old value
  evicts, the Welford mean/variance is recomputed exactly from the
  deque plus the virtual prior (in-place removal from Welford state is
  numerically unstable, so the recompute path is exact). The virtual
  prior (pseudo-count seeding from the purpose-group default) is
  reapplied on every recompute and survives eviction by design — the
  conservative default never washes out of a quiet identity entirely.
  Baselines (window values included) persist under
  `<run_dir>/detection/baselines.json`; the export manifest records
  the operative window so an auditor knows the baseline's age.
- **Cold start:** identities with fewer than `MIN_TRAINING_BUCKETS`
  samples use **purpose-group defaults** (§6): the role group's
  reference baseline, stated as approximate. Until trained, thresholds
  are the conservative (tight) group profile — a new identity behaving
  badly during the default window trips *fast* and lands in the
  approval queue for human scrutiny. This bounds cold-start poisoning
  by construction: the default never grants a *lax* baseline.

## §3 — EWMA/CUSUM parameters (commoditized — cited as prior art, not invention)

The standard pair, per the learnings memo Part 5(a):

- **EWMA**, α = **0.3** (ACR framework documents α=0.3; authensor
  Sentinel ships the same), 5-minute buckets. Spike rule: one-sided
  z > **2.5** (ACR's documented threshold) on the harmful direction.
- **CUSUM** for gradual drift: reference value **k = 0.5σ**, decision
  interval **h = 5σ** — the textbook Montgomery pair. A sustained
  +1.0σ shift then has expected detection lag in the low tens of
  buckets; the wave measures the actual lag on synthetic drift and
  reports the measured number, not the theory (§4).
- Baseline training window per ACR: 30 days; this tree's runs are
  synthetic/local, so the operative parameters are the
  `MIN_TRAINING_BUCKETS` + `WINDOW_BUCKETS` knobs (§2), and the export
  states them (§8) — the *knobs* are what's evidence-grade, not the
  specific constants.

**Direction-of-badness filtering** (staffops): a symmetric z-score
fires on *improvement* too. Every signal declares its harmful
direction up front (rate/denial/escalation/egress signals: upward
only; anchor downgrade: any event), and firings are filtered to that
direction before alerting. A sudden drop in tool-call rate is a
curiosity for the human, not a trip.

## §4 — The measured lag (slow-boil, stated honestly)

The probe battery measures CUSUM detection lag on deterministic
synthetic drift (no randomness anywhere):

- +1.0σ sustained shift in `egress_attempts` (scout role, 12
  cold-start buckets) → **CUSUM trips after 11 buckets** (measured
  2026-09-22; textbook h/(δ−k) = 10, +1 for the strict-inequality trip
  rule). EWMA spike does not fire on this gradual shape in the first 8
  buckets — by design, that is why the pair exists.
- A drift engineered to stay under the CUSUM decision interval (0.4σ
  sustained shift against k=0.5σ) **never trips in 300 buckets**. This
  is the stated boundary, not a bug: the residual is *pinned* by a
  probe that demonstrates the non-trip, documents the exact shape that
  evades, and is filed as a boundary note — never as a finding (no new
  independently-reachable miss exists beyond the stated boundary;
  next free finding remains **F129**).

**The baseline must not absorb the drift.** An adaptive baseline that
trains on drifted observations desensitizes its own CUSUM — the
monitor would be theater against exactly the shape it exists to
catch. The rule: baseline updates freeze while CUSUM suspicion is
active (`sh > 0`) and while the breaker is not CLOSED. Benign blips
whose suspicion decays back to 0 resume training; a sustained new
level trips, and only a **named human re-baseline**
(`monitor.rebaseline(identity, reset_by)`, chained, before/after means
recorded) adopts it. Re-baselining is the one operator action that can
launder drift into the baseline — which is why the audit names who
moved the goalposts, from what to what, and when.

## §5 — Trip → enforcement wiring

The monitor is **read-only over the audit stream**. It never executes,
never approves, never writes queue records itself (the queue requires
an executor-minted `caller_identity` — an agent-unreachable authority —
so the monitor has no queue seam by construction). The wiring:

1. Monitor emits a **`detector_trip` provenance record** (new record
   type, chained and MAC'd like everything else): identity key,
   signal, observed value, threshold, baseline window, EWMA/CUSUM
   state at trip. Emitted **once per breaker-open transition** —
   never re-emitted while the breaker stays open (the denial-storm
   bound).
2. The breaker (per identity: CLOSED / OPEN / HALF_OPEN) lives in the
   monitor, owned by the operator. `ToolExecutor` consults
   `monitor.breaker_state(identity_key)` on the verdict path: when the
   breaker is OPEN, a verdict that would *execute* a high-risk action
   is downgraded to `require_approval` with flag
   `behavioral_breaker_open` — the action still carries the agent's
   own executor-minted identity into the queue; it is the *routing*
   that changed. Fail-closed: if the monitor is unreachable, the
   executor treats the breaker as OPEN (deny-by-default on the
   detection path).
3. **Human reset with half-open probing** (Nygard): reset is an
   operator action returning a chainable payload naming the resetter.
   After reset the breaker goes HALF_OPEN: a bounded probe quota of
   low-risk actions is admitted and measured; CUSUM state is carried
   forward (never zeroed — zeroing is how slow-boil launders itself
   through resets). A quiet window of `HALF_OPEN_QUIET_BUCKETS` clean
   buckets closes the breaker; any trip re-opens it immediately. On
   reset the EWMA level tracker is reseeded to the baseline mean (the
   human judged the spike over — its decaying memory must not phantom
   re-trip the half-open window); a continuing spike re-trips on fresh
   evidence. CUSUM suspicion is carried forward **only when the opening
   trip was a drift trip** — the anti-laundering property (a reset must
   not restart the drift clock); a spike trip's incidental CUSUM
   accumulation is zeroed, since a huge stale `sh` would otherwise make
   half-open unclosable. A
   benign permanent level shift cannot close this way (the drift
   re-trips) — the operator's `rebaseline(identity, reset_by)` adopts
   the new level explicitly, chained and named (§4). Repeated re-opens
   after reset increment `consecutive_opens` on the breaker — the
   denial-storm battery proves the bound.
4. **Denial-storm (denial-of-attention) bound:** deliberate tripping
   floods the queue — but only once per open transition (trip records
   are not re-emitted), high-risk actions queue under the existing
   queue flood flags (`approvals.py` `refresh_flood_flags`), and each
   reset requires a human. The battery asserts: N deliberate trips →
   exactly 1 trip record per open transition + queue flood anomaly
   flagged + operator-gated reset.

## §6 — Purpose-group defaults for cold start

New identities inherit their **role group's** reference baseline
(the ACR "same role" answer), shipped as `PURPOSE_GROUP_DEFAULTS`
keyed by role (e.g. `scout`, `coder`, `reviewer` — the roles this
tree's agents actually carry). The defaults are **conservative by
design**: the reference profile assumes the *quiet* end of the role's
observed range, so a new identity misbehaving in the default window
trips within the first buckets — and the trip routes to the approval
queue (human scrutiny), not to an execution block. Approximate by
statement: the export marks cold-start thresholds as
`basis: purpose-group-default (approximate)` until
`MIN_TRAINING_BUCKETS` personal samples accrue. The cold-start
poisoning probe proves the bound: a new identity emitting attack-rate
traffic during the default window trips before it can poison the
baseline (defaults are applied, never trained on, until the minimum
samples exist — there is no "train on attacker traffic" path).

## §7 — The monitor's own trust boundary

The monitor reads the **chained log**. If the log itself is the
attack surface — the Wave-73 residual (a key-holder backdating or
reforging in-chain history) — then baselines built on forged history
are attacker-shaped. The answer is layered, and each layer is named:

1. **The chain answers tampering:** forged history breaks the
   hash-chain/MAC verification; the monitor refuses to train on
   unverified segments (fail-closed on `verify_chain` failure).
2. **The anchor answers the key-holder:** a key-holder who *can*
   reforge in-chain history (holds the log key) still cannot forge
   the external anchor — the Wave-75 readiness note stands: anchor
   downgrades (`head_match=False`) are treated as **tripwires, not
   noise**, and they are one of the two tripwires the agent cannot
   see coming (the audit is operator-timed).
3. **The monitor never runs inside the agent's trust domain.** The
   baseline store is operator-owned; the trip record is appended
   through the operator's append path; no agent-facing tool, flag, or
   API mutates breaker state. The trip-suppression battery proves the
   negative: every seam an agent *could* reach (queue writes needing
   minted identity, baseline files outside the sandbox, monitor
   process/operator domain) is exercised and refuses.

Residual (stated, not filed): an attacker who holds *both* the log
key and the anchor key can reforge history silently — the Wave-72/73
threat model, unchanged by this wave. And a patient adversary under
the CUSUM threshold never trips (§4). Both are boundaries, and both
are rendered in the export (§8).

## §8 — Slow-boil boundary in the product surface

`demo/make_report.py` gains a **detection boundary section**, rendered
from `gov.detection`'s operative constants (never hand-copied claims):

- per-signal: baseline window (buckets), EWMA α, spike z-threshold,
  CUSUM k/h, harmful direction, basis (per-identity vs
  purpose-group-default-approximate);
- the measured CUSUM detection lag for a +1.0σ sustained shift
  (measured value, pinned by the battery);
- the slow-boil sentence, verbatim: *"A drift engineered to stay
  under the CUSUM decision interval never trips. The thresholds above
  are what that drift stays under."*

## §9 — Deliberately not done

- ML-based anomaly detection with no stated false-positive rate
  (theater per the memo; EWMA/CUSUM's parameters are the honest
  primitive).
- An AI judge for behavioral scoring — P8 owns that problem space
  (UNCOVERED-by-design until a real backend is provisioned); this
  wave's monitor is deterministic statistics only.
- Global thresholds (every agent trips or none do) — per-identity
  baselines are load-bearing against desensitization.
- The commercial evidence pipeline (strategic context only).
- Wire-up of detection trips into Wave-77 response primitives beyond
  the queue routing — Wave-77 (response/recovery) consumes trips as
  its trigger input; the trip record schema is the handoff contract.

## §10 — Readiness for Wave-77

Detection trips are Wave-77's trigger input. The handoff contract:
the `detector_trip` provenance record (identity key, signal,
observed/threshold, baseline window, trip kind
`ewma_spike|cusum_drift|boolean_tripwire`, breaker transition).
Wave-77 builds response (halt, quarantine, resume) on these records —
the monitor's job ends at honest, wired, battery-tested detection.
