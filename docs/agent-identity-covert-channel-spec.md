# SPEC — Stream 3: Inter-agent identity binding + covert-channel detection baseline

Owner: Stream 3 (structural-gaps team). Push boundary wave-100.
Status: spec → battery → implement → two-axis review.

## Problem Statement

Inter-agent messages in the governance layer carry a sender name that
nothing cryptographically binds to anything. The existing message bus
stamps the sender as a plain string, the identity system mints identities
per in-process executor with no per-agent signing key, and nothing stops
agent B from sending a message that claims to be from agent A. Receivers
therefore cannot tell who actually sent a message, replaying a captured
message is undetectable at the identity layer, and covert communication
(steganographic fields, unnaturally regular timing, fields the sender's
declared schema never uses) is invisible except for a small set of
cheap syntactic steg signals.

## Solution

Two new standalone primitives, each documented as a baseline, never as
a proof of completeness:

1. **Identity binding**: the governance layer issues a per-agent signing
   key at agent registration (a key-issuance registry; agents never
   self-assert identity). Every inter-agent message carries the sender
   identity signed over the full message body with the sender's issued
   key, plus a nonce and per-sender sequence. Receivers verify the
   signature, the key-to-sender binding, and nonce/sequence freshness,
   and reject unsigned messages, wrong-key messages, and replays —
   fail-closed, with a chained audit event on every rejection. The
   verifier is exposed as a standalone function the executor/messaging
   path would call; the stream does not edit the executor seam (owned
   by Stream 1).

2. **Covert-channel detection baseline**: a per-sender statistical
   monitor that flags anomalous channel usage as incidents for human
   review: entropy spikes in free-text fields vs the sender's baseline,
   inter-message timing too uniform for the declared traffic class, and
   populated fields the agent's declared schema never uses. Reported
   alongside measured false-positive rates on a benign-traffic fixture
   and false-negative rates on seeded covert payloads. Explicitly a
   baseline for human review, not a proof of no-covert-channel.

## User Stories

1. As an operator, I want every inter-agent message to carry a sender
   identity bound to a governance-issued key, so that agents cannot
   impersonate each other.
2. As a receiver of an inter-agent message, I want the signature verified
   over the full message body, so that tampered bodies are rejected.
3. As a receiver, I want unsigned messages rejected, so that plaintext
   forgery is not silently accepted.
4. As a receiver, I want messages signed by a key not registered to the
   claimed sender rejected, so that key substitution is caught.
5. As a receiver, I want replayed messages (duplicate nonce or stale
   sequence) rejected, so that captured messages cannot be re-injected.
6. As an auditor, I want every identity rejection to produce a chained
   audit event, so that spoof attempts are visible in the log.
7. As an operator, I want the verifier to fail closed on malformed
   input (missing fields, bad types), so that parser gaps are not
   bypassable.
8. As a human reviewer, I want entropy spikes in an agent's free-text
   fields flagged as incidents, so that encoded payloads surface.
9. As a human reviewer, I want unnaturally uniform inter-message timing
   flagged, so that timing channels surface.
10. As a human reviewer, I want populated fields outside an agent's
    declared schema flagged, so that off-schema exfiltration surfaces.
11. As a product lead, I want the detector's false-positive rate measured
    on a benign-traffic fixture, so that we ship with honest noise
    numbers instead of marketing claims.
12. As a product lead, I want the detector's false-negative rate measured
    on seeded covert payloads, so that the "misses low-and-slow" ceiling
    is quantified, not hand-waved.
13. As an integrator (Stream 1 / messaging owner), I want a documented
    standalone integration point (one function the messaging path would
    call), so that wiring it in does not require editing my seams.
14. As a red-team reviewer, I want a break-first battery that demonstrates
    the gap on the unmodified tree and proves the control holds after
    the fix, so that the closure is evidence-backed.

## Implementation Decisions

- Two new modules in the governance package: an identity-binding
  primitive and a covert-channel detector baseline. New files only; no
  edits to the executor, the egress launcher, the sandbox, or the
  safeguard benchmark.
- Key issuance registry: the governance layer mints one Ed25519 keypair
  per registered (principal, agent_id) and holds the private half in a
  deployment-trust-domain vault object. Agents receive a signing handle
  that can sign only as their own agent_id — they never see seed
  material and cannot mint or substitute keys.
- Registration is an out-of-band admin act. It may consult the existing
  principal trust anchor for principal-level authorization; an
  unregistered principal or a duplicate agent_id registration is
  refused. The registry itself is a trust anchor (documented residual:
  who guards the minter is a deployment question this primitive does
  not answer).
- Signed envelope: sender identity, issued key id, nonce, per-sender
  sequence, message body; the signature covers the canonical encoding of
  all of them (body tampering invalidates it). Canonical form is
  JSON with sorted keys and tight separators, domain-separated from
  other signature uses.
- Verification RAISES ``IdentityRejection`` (carrying a machine-readable
  ``reason``: unsigned, unknown_key, unbound_key, bad_signature,
  replayed_nonce, stale_sequence, malformed_envelope) instead of
  returning an accept/reject tuple. Deliberate: a returned verdict
  object is truthy-footgun-prone (a caller that forgets to check
  ``.accepted`` would accept everything); raising makes "do not
  deliver" the default path. The messaging path wraps the call in
  try/except. Misuse (non-dict envelope) is itself a
  ``malformed_envelope`` rejection, never an accept; the audit log is
  optional (rejection raises whether or not a log is supplied).
  Every rejection path appends a chained audit event naming the reason
  when a log is given.
- Replay protection is stateful: the verifier takes a replay cache
  (bounded, per-key seen-nonce set + last sequence). The cache is a
  small value object the messaging path owns; the primitive does not
  own global state.
- The detector keeps per-sender baselines: (a) entropy mean/std of each
  free-text field, learned from observed traffic, with a configurable
  z-threshold; (b) inter-message interval mean/std and coefficient of
  variation, flagged when intervals are implausibly uniform over a
  minimum window for the declared traffic class; (c) declared schema
  (the field set an agent claims to use) — any populated field outside
  it is an incident. Incidents are records for human review, never
  verdicts of guilt.
- Benign fixture: synthetic normal agent chatter (status notes, task
  updates, heartbeats) from several agents with jittered timing; the
  battery learns baselines on part of it and measures FP on the rest.
  Covert fixture: seeded payloads — high-entropy encoded blobs in
  free text, a uniform-interval timing channel, and unexpected-field
  usage — plus at least one deliberately low-and-slow channel expected
  to be missed (honest FN).
- The battery runs red against the unmodified tree: with the primitives
  absent it demonstrates the attacks succeeding against the legacy
  trust-the-field behavior (spoof accepted, replay accepted, covert
  payload unflagged by the existing syntactic screen) and exits failing;
  after the fix every probe must hold.

## Testing Decisions

- Seams under test (confirmed by the mission): the verifier function
  (accept/reject envelope), the detector's analyze function (findings
  per message), and the battery runner script. No tests against
  internals (seed bytes, baseline dicts).
- What makes a good test here: attack-shaped inputs with independent
  expectations — "B's key over A's name must be rejected" is derived
  from the spec, not recomputed from the implementation; FP counts
  come from the fixture, not from the detector's own thresholds.
- Anti-patterns to avoid: tautological replay tests (recomputing the
  signature in the test the way the code does); testing through the
  executor (Stream 1's seam) instead of the standalone verifier.
- Prior art for style: the evals break-battery convention
  (BREAK/HELD/CONTROL/ERROR verdicts, deterministic, synthetic/local,
  `GOV_DEPLOYMENT_MODE=staging` at module level, standalone-run under
  a clean env).
- The full canonical suite is not run by this stream (coordination
  rule); only the new tests and the new battery are run.

## Out of Scope

- Editing the executor, the message bus, the egress launcher, the
  sandbox, or the safeguard benchmark — integration is a documented
  function call for the owning lanes.
- Shared-state side channels outside the message path (file channels,
  spawn lineage, tool-mediated channels): named as an explicit
  boundary, not covered.
- Paraphrase-semantic stego and Schelling-point coordination: the
  detector is statistical and will miss them (quantified as FN).
- Key custody production hardening (HSM/Vault wiring): the registry is
  a trust anchor with the deployment-owned minter problem documented
  as a residual.
- Proving the absence of covert channels: the detector is a baseline
  for human review; the spec forbids claiming otherwise.

## Further Notes

- Entropy baselines must be learned per sender, not globally: agents
  have legitimately different text profiles (a coder agent's notes vs
  a greeter's), and a global threshold would drown in FP.
- Timing analysis needs the declared traffic class: a heartbeat agent
  is legitimately regular; a chat agent is not. Regularity is only
  anomalous against a non-periodic declaration.
- Replay cache bounds: unbounded seen-nonce sets are a memory DoS
  vector; the cache is bounded with oldest-first eviction and the
  eviction policy is documented as a residual (very-old replay of an
  evicted nonce would not be caught by nonce alone, but the sequence
  check still holds for in-order senders).
