# GAP-2 — Agent-to-Agent Message Provenance + Lineage Quarantine

**Status:** spec (2026-09-24). Lane: GAP-2 closure team. Seam-lock: public
surfaces in `gov/` + eval battery files only.

## Problem Statement

Self-replicating prompt infection spreads agent-to-agent (Morris II worm,
"Agent Smith"). Today's controls are single-agent: each hop is individually
policy-benign. The wave-89 S2 governed message bus stamps sender provenance
on messages, and the wave-90 S6 infection-lineage substrate (`gov/lineage.py`)
tracks spawn + raw-file channels with taint propagation and a population
replication watch — but the two are **not joined**. A payload that replicates
through the bus:

- carries no lineage identity in its stamp (no lineage id, no taint bit);
- never feeds the tracker's `observe_content` population watch, so bus-channel
  replication across ≥3 lineages raises no `infection_suspected`;
- never records a `lineage_contact` on read, so taint does not propagate
  sender → recipient and the unified provenance graph has a bus-shaped hole;
- is accepted from unlineaged senders even on a run where the deployment
  installed the tracker (fail-closed gap: `call()` refuses unlineaged
  identities, `send()` does not);
- cannot be distinguished from a file the attacker hand-wrote into the
  operator-side inbox claiming someone else's sender identity (the stamp is
  asserted, never verified against the chained send record).

## Solution

Join the bus to the lineage substrate. `MessageBus` accepts the deployment's
`LineageTracker` (`lineage_tracker=` at construction, or
`attach_lineage_tracker()` for deployment ordering). When attached, the bus
participates in the same provenance graph as spawn + file channels:

- `send()` refuses unlineaged senders (fail closed, chained refusal);
- the stamp carries `sender_lineage_id`, `sender_lineage_depth` (the hop
  count), and the send-time `sender_infected` bit;
- `send()` feeds the tracker's `observe_content` population watch, so
  bus-channel replication across ≥3 distinct lineages fires
  `infection_suspected` and taint-marks the origin lineage;
- `receive()` records a `lineage_contact` (channel `"bus"`) via the new
  public tracker method `note_message()`, propagates taint from an infected
  sender lineage to the recipient (evaluated live, so a sender taint-marked
  *after* sending still taints later readers — the file-channel "live writer
  taint" rule), and feeds the population watch for the recipient lineage;
- `receive()` verifies the stamp against the chained `agent_message` "sent"
  record (sender, seq, content hash, lineage id). A stamp that cannot be tied
  to a chained send — missing lineage fields, unregistered sender, lineage-id
  mismatch, or no chained send record at all — is **forged**: the recipient is
  taint-marked, `bus.quarantine(recipient)` fires (containment; reversible via
  `release()`), a LOUD `lineage_stamp_forged` event is chained, and delivery
  is refused (`MessageFlaggedError`).

Without a tracker attached the bus behaves exactly as before (zero behavior
change; the bus stays opt-in, the tracker stays opt-in at deployment).

## User Stories

1. As a deployment operator, I want every bus message to carry the sender's
   infection-lineage identity, so that message traffic is attributable to a
   birth-certified lineage, not a self-asserted agent id.
2. As a deployment operator, I want an unlineaged agent's `send()` refused
   when the run has a tracker installed, so the bus matches the `call()`
   fail-closed posture instead of being the softer path.
3. As an incident responder, I want a `lineage_contact` event for every bus
   read, so the provenance graph shows message-mediated infection paths the
   same way it shows file-mediated ones.
4. As an incident responder, I want taint to propagate across bus receives,
   so a recipient of an infected sender's message is contained even when the
   message content itself is policy-benign.
5. As a detection engineer, I want bus content to feed the population
   replication watch, so a payload spreading A→B→C over the bus fires
   `infection_suspected` exactly like the same bytes spreading over files.
6. As a detection engineer, I want "live writer taint" on the bus, so a
   sender taint-marked after sending still taints agents that receive its
   earlier messages later.
7. As a deployment operator, I want a forged bus stamp (no chained send
   record, mismatched lineage, unknown sender) to quarantine the recipient
   and refuse delivery, so an attacker cannot hand-write inbox files that
   impersonate other agents.
8. As an auditor, I want the quarantine-on-forgery decision chained with the
   reason, so containment is reviewable and reversible via `release()`.
9. As a deployment operator, I want all of this to stay off unless I wire the
   tracker into the bus, so existing bus deployments see zero behavior change.

## Implementation Decisions

- **Modules:** `gov/lineage.py` gains one public method,
  `LineageTracker.note_message(agent_id, msg_id, stamp)`, mirroring
  `note_read` (returns `("contact"|"tainted"|"forged", detail)`; raises
  `LineageError` for an unlineaged *recipient* — fail closed). `gov/messaging.py`
  gains `lineage_tracker=` on `MessageBus.__init__` plus
  `attach_lineage_tracker(tracker)`. No executor changes: the bus owns the
  wiring, the deployment owns construction (same contract as the tracker's
  deployment wiring section).
- **No new import cycle:** `messaging.py` treats the tracker as a duck-typed
  object exposing the documented public protocol (`is_registered`,
  `lineage_id`, `certificate`, `is_infected`, `note_message`,
  `observe_content`); no `from .lineage import` (the bus must also work in
  deployments that never import lineage).
- **Stamp additions:** `sender_lineage_id`, `sender_lineage_depth`,
  `sender_infected`. These ride the existing chained `agent_message` "sent"
  event, which is the provenance root the receive side verifies against.
- **Receive-side verification order:** identity → quarantine divert → file
  exists → content-hash match (existing) → chained-send-record match (new:
  sender, seq, recipient, msg_type, content hash, lineage id) →
  `note_message` → population watch.
  Forgery anywhere in the new steps = taint-mark recipient + `bus.quarantine`
  + LOUD `lineage_stamp_forged` (channel `"bus"`) + `MessageFlaggedError`
  (refused, never silently dropped). An unlineaged *recipient* fails closed
  via `note_message`'s `LineageError` (mirroring `note_read`); the bus does
  not pre-check — the registry is the single authority on who is lineaged.
- **Delivery posture:** contact/tainted messages are delivered WITH a
  `lineage:contact` / `lineage:tainted` flag (the steg-flag precedent: flagged,
  never silently dropped). Only forged lineage refuses delivery.
- **Population watch reuse:** `observe_content` is called on send (sender
  lineage) and on receive (recipient lineage) — the same ≥64-byte floor and
  ≥3-distinct-lineage threshold as the file channel, so bus and file traffic
  correlate in one graph.
- **Quarantine scope on forgery:** the *recipient* is quarantined (the origin
  is unprovenanced by definition, so `quarantine_origin`'s downstream walk
  cannot attribute). Reversible via the existing `bus.release()`.
- **Backwards compatibility:** `MessageBus(run_dir, log)` unchanged; all new
  behavior is gated on a non-None tracker.

## Testing Decisions

- A good test exercises the real attack shape at the public seam: bus send /
  receive through `ToolExecutor.send_message` / `receive_message` with a real
  `LineageTracker`, asserting on chained audit events and tracker state
  (`is_infected`), not on internals.
- **Battery:** `evals/gap2_buslineage_break.py` (unittest style, following
  `evals/s6repl_break.py`; module-level `GOV_DEPLOYMENT_MODE=staging`,
  verified under `env -u GOV_DEPLOYMENT_MODE`). Fixture follows
  `evals/s2msg_battery.py` (real delegation tokens, bound context, spawned
  children for distinct lineages). Pre-fix the tests asserting post-fix
  properties go RED (the break demonstration); post-fix they go GREEN.
  - B1: infected A → bus → B → bus → C: B and C taint-marked, bus
    `lineage_contact` events chained. Pre-fix: no contact events, B/C clean.
  - B2: identical ≥64B payload sent by 3 distinct lineages via bus:
    tracker `infection_suspected` (policy_id `infection-lineage`) fires,
    origin taint-marked. Pre-fix: silent.
  - B3: unlineaged (minted, never genesis'd) sender `send()` → refused
    (`MessageRefusedError`) + chained refusal. Pre-fix: succeeds.
  - B4: live writer taint — clean send, recipient reads, sender taint-marked
    *after*, second receive taints the recipient. Pre-fix: recipient stays
    clean.
  - B5: hand-forged inbox file (no chained send record) → `MessageFlaggedError`,
    recipient tainted + bus-quarantined, LOUD `lineage_stamp_forged`.
    Pre-fix: delivered with no lineage flag.
  - C1 (control): benign A→B→C chain works, no false taint, no false alarm —
    passes pre- and post-fix.
- Prior art: `evals/s6repl_break.py` (lineage/file channel),
  `evals/s2msg_battery.py` (bus fixture + infection monitor).

## Out of Scope

- Perfect steganography detection is provably impossible; the spec raises
  attack cost (provenance binding, population watch, quarantine) and limits
  channels (typed schemas, bandwidth caps already in the bus). Stated honestly,
  not claimed away.
- Cross-run lineage (the registry is per-run); multi-run correlation is
  follow-up work.
- Automatic bus-wide quarantine on `infection_suspected` from the *tracker*
  watch: the deployment wires `LineageQuarantine.quarantine_origin` to that
  signal explicitly (the bus's own InfectionMonitor already auto-quarantines
  on its signal; the tracker deliberately taint-marks and lets the deployment
  choose containment).
- The bus is not made mandatory and the tracker is not auto-attached by the
  executor: both stay opt-in at deployment, mandatory-within-run once
  installed (the wave-90 design note stands).

## Further Notes

- This closes the bus-shaped hole in the wave-90 unified provenance graph:
  spawn + file + bus now share one lineage substrate.
- Residual: a recipient can be quarantined by a *sender's* forged stamp (the
  recipient is tainted+quarantined, not the forger — attribution is
  impossible). Mitigation: `release()` is one operator call, and the event is
  loud. Documented, not hidden.
- Residual: sub-64-byte bus payloads never trip the population watch (same
  floor as the file channel); per-message taint propagation still applies.
