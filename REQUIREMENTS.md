# Requirements — agent-governance

Derived from `research/` (OWASP LLM Top 10 2025 + Agentic Top 10 2026, NIST AI
RMF 1.0 + AI 600-1 GenAI Profile, OPA/Rego + AWS Cedar design patterns,
Greshake et al. arXiv:2302.12173, Sigstore/Rekor + RFC 6962, SPIFFE/SPIRE).
Priorities: **P0** = product bar (must ship), **P1** = do if time, **P2** =
deferred with an explicit trigger.

## P0 — product bar

- **R1 Fail-closed policy engine.** Default effect deny; deny rules have
  forbid-priority independent of file order (evaluate all denies, then
  require_approval, then allows). Explicit allow rules required.
- **R2 Least-privilege identities.** `match: {role, agent}` in policies;
  per-role tool allowlists enforced in the *executor* (no ambient
  authority); identities minted by the executor/launcher, never self-claimed.
- **R3 Provenance tracking.** Every tool result tagged
  `user | tool_result | retrieved_content | agent_memory`; policy matcher
  `source_untrusted`; actions influenced by untrusted inputs can be
  denied/queued regardless of tool.
- **R4 Egress control.** Domain allowlists for `http_post`/`send_email`;
  read-before-send correlation (read fingerprints per run; outbound payload
  carrying previously-read content to a non-allowlisted host → deny/queue).
- **R5 DLP scan stage.** Credential patterns (AWS keys, ghp_, sk_live,
  private-key blocks, JWT shape, connection strings) → block; PII (email,
  phone, SSN-ish, credit-card+Luhn) → redact; entropy tripwire near
  credential keywords. Wired as a policy effect so hits flow through queue,
  log chain, and reports.
- **R6 Authenticated log.** HMAC-SHA256 chain (`hmac` stdlib, key from env),
  `key_epoch` bound into the MAC, periodic checkpoints (STH-style) defeating
  tail truncation, `format_version` frozen, offline verifier CLI
  (`python -m gov.verify`) with structured verdicts, fail-closed emission
  (log failure ⇒ no execution).
- **R7 Redact-before-log.** Per-tool field allowlists; pattern library +
  entropy tripwire over every logged string; `write_file` content logged as
  `{bytes, sha256_prefix}`; `send_email` bodies never verbatim;
  `redactions_applied: [rule-ids]` per entry; same pass on approval records.
- **R8 Hardened approvals.** Expiry with auto-deny default; dry-run preview
  (what would happen) stored on the queued record; separation of duties
  (`decided_by` must differ from requesting agent); approval/rejection
  recorded as its own chained log entry (non-repudiation); queue display
  shows raw tool call + args + provenance + matched rule — never the
  agent's justification as primary evidence.
- **R9 Policy linting.** `python -m gov.policy_lint policies/*.yaml`:
  unknown tools, unknown match keys, invalid effects, shadowed/unreachable
  rules, contradictory rules.
- **R10 Rate/volume/loop guards.** Per-run caps on outbound sends and
  writes/deletes; loop guard (same tool+args N times → deny); counters in
  policy context (`when:` conditions on numeric args and counters).
- **R11 TOCTOU guard.** `execute_approved` re-runs the *current* policy set
  against *current* arguments; fails closed if policy changed since queueing
  or approval expired.
- **R12 Packaging.** `pyproject.toml`, pip-installable, `README.md`
  quickstart a stranger can run in <5 minutes; synthetic demo runnable with
  zero config.
- **R13 Red-team test suite.** `tests/` with ≥3 distinct agents (different
  toolsets, privilege levels); scenarios for T1–T12; suite is green only when
  controls are implemented; every weakness logged in `WEAKNESSES.md`.
- **R14 Realistic end-to-end scenario** demonstrating the layer catching a
  real attack shape (e.g. malicious tool output → exfiltration attempt).

## P1 — do if time remains

- Rejection feedback loop to the agent; near-miss register + `metrics.json`
  per run (NIST near-miss register, GOVERN 1.5 monitoring).
- Edit-before-approve on queued actions.
- Tool-definition pinning/hashing at startup (ASI04).
- `gov/export.py` air-gapped audit bundle.
- Delegation-chain logging (`parent_agent_id`, `on_behalf_of`).
- Sandbox hardening: case-folding, deny `..` segments even when resolution
  lands inside, approval-gate outside-sandbox reads.

## P2 — deferred, with triggers (documented, not built)

- **ed25519 log signatures** — trigger: an external auditor must verify
  offline without holding the shared HMAC key. (Needs a dependency.)
- **Merkle inclusion/consistency proofs** — trigger: logs large enough that
  full replay is expensive, or third-party per-entry receipts required.
- **Memory write-gating + provenance** (T13) — trigger: product adds memory.
- **Dual-LLM quarantined reads** — trigger: real LLM integration.
- **OPA/Cedar as a dependency** — never; design patterns only.

## Non-requirements

- No network calls, no paid APIs, no real credentials; everything synthetic
  and local. Stdlib preferred; a dependency only with written justification.
- No ML-based PII detection (regex + entropy covers the threat model).
- No transparency-log server / gossip / public anchoring (solves operator
  distrust we don't have yet).
