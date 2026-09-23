# Competitive Teardown Addendum — 2026-09-22 (wave-56)

**Lane:** competitive teardown (user-committed, standing). **Method:** $0,
public sources only. This is a dated addendum to
`research/teardown-wave47-2026-09-22.md` (which built on
`research/differentiation-strategy.md` and
`research/teardown-update-2026-09-22.md`); it records one item — AGT's
admitted Credential Persistence Gap — and what it does to the wedge
verdicts. Zero triggers fired by this item.

**Primary:** `microsoft/agent-governance-toolkit`, `docs/LIMITATIONS.md`
§8 "Credential Persistence Gap" —
https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/LIMITATIONS.md
(section added via PR #1017, relanded in #1125; gap credited to external
analysis by Moltbook —
https://www.moltbook.com/post/c3fdafe4-f58e-4854-9fd6-eec2052b7638).
Fetched 2026-09-22.

## The gap, as AGT states it

"AGT governs **what agents do** with tools. It does **not** manage or
observe the **credentials agents hold** across tasks within a session."
Concretely: AGT blocks an agent from calling a tool it is not authorized
to use, but does **not** track which API keys, OAuth tokens, or secrets
an agent is currently holding; does **not** revoke credentials at task
boundaries within a session; does **not** detect credential accumulation
beyond what the current task needs. Their worked example: an agent
receives an email API token for Task A, moves to Task B (which does not
require email access), the token persists — compromise during Task B
gains email access that should no longer be active. Their mitigations
today: scoped capabilities per task context, short-lived credentials via
external secret managers (Key Vault / Vault) with TTL rotation, trust
decay in AgentMesh. Their roadmap: task-scoped credential lifecycle
hooks, automatic revocation at context switches.

## How our canary program answers it (inward-facing)

Our answer is detection-shaped, not lifecycle-shaped, and the honest
statement of that boundary matters:

- **P1 canaries** (`gov/canary.py::scan_egress_attempt`): high-entropy
  planted secrets in the agent's context trip the moment they egress —
  the *consequence* of credential material leaving, detected
  per-tool-call with near-zero FP (the exactness invariant).
- **Union-registry pattern** (`docs/SWARM_DEPLOYMENT.md`, wave-55): each
  run's minted canaries are `register()`ed into one shared registry
  attached to each executor — cross-task and cross-run trip continuity,
  which is exactly the "credential persists past its task" shape AGT
  discloses. Rotation semantics are documented: last run's canaries
  stop tripping by design.
- Together: an agent carrying a stale credential-equivalent across a
  task boundary and then exfiltrating it trips — where AGT's own
  LIMITATIONS admits they would not observe the holding at all.

## What we still do not do (no victory language)

- We track **our planted canaries**, not the agent's **real**
  credentials. An agent accumulating real API keys across tasks is
  invisible to us until one of *our* values moves.
- We have **no credential inventory, no task-boundary revocation
  hooks, no accumulation detection** — the lifecycle half of AGT's
  gap is unaddressed here, and it is the half their roadmap ("automatic
  revocation at context switches") is aimed at.
- The tripwire detects exfil of planted material; it never prevents
  the holding. A compromised agent in Task B holding Task A's real
  token and using it *within* an allowed destination is outside both
  our tripwire and our (accepted-gap, F81) egress wall.

## Wedge reading: wedge-1 adjacency, not a new wedge

This is a **wedge-1 (durable approval queue / operator UX) adjacency**,
not a new wedge claim. Credential lifecycle governance — task-scoped
visibility into what the agent holds, revocation at boundaries — is an
operator control-surface problem: it belongs to the console/queue layer
that watches runs, not to the enforcement primitives (policy engine,
sandbox, canary tripwire). The differentiation line from wave-55 holds:
they govern tool actions and admit they do not observe credential
holdings; we observe holdings inward-facing via planted secrets plus
union-registry continuity, and we do not claim the lifecycle half. No
new wedge is declared; no trigger fired.

## Watch item

If AGT ships "task-scoped credential lifecycle hooks" (their stated
roadmap), the lifecycle half closes on their side and our remaining
edge is the detection half (planted-secret tripwire + union registry)
— re-evaluate the adjacency then. The honest comparison to re-run at
that point is: lifecycle-prevention (theirs) vs exfil-detection (ours)
— complements, not substitutes.
