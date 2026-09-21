# Threat Model — agent-governance

Scope: a governance layer that mediates **every tool call an AI agent makes**:
identity attribution → policy evaluation → human approval (for risky actions)
→ tamper-evident logging → audit reporting. The demo executor simulates tools
locally; nothing touches real systems or networks.

## Trust boundaries

| Zone | Trust level | Notes |
|---|---|---|
| Agent code / prompts | **Untrusted** | May be steered by injected content; never trusted for authorization decisions |
| Governance layer (`gov/`) | **Trusted** | Complete mediation: no tool executes without passing through it |
| Tool implementations | Semi-trusted | Simulated here; in real deployments, tools are the confused-deputy surface |
| Human approver | Trusted but **socially engineerable** | The approval queue is an attack surface against the human |
| Log store | Integrity-protected, confidentiality-assumed | Attackers may read/append but must not rewrite undetectably |
| Operator (holds log keys) | Trusted | Key custody is out of band |

Explicitly out of scope: jailbreaking the underlying LLM's token generation
(we govern *actions*, not *tokens*); network-level enforcement in production
deployments (the executor here is simulated); public transparency anchoring.

## Threat catalog

**T1 — Indirect prompt injection via tool outputs.**
Attacker plants instructions in data the agent reads (webpage, file, email,
tool result); the agent acts on them as if they were principal instructions.
Real basis: Greshake et al., "Not What You've Signed Up For" (arXiv:2302.12173,
AISec 2023) — attacks with no user in the loop, demonstrated against Bing Chat
and GitHub Copilot, including worming and data theft. OWASP LLM01 (2025) and
ASI01 (2026). *Status: NOT mitigated — no provenance tracking exists.*

**T2 — Confused deputy / missing per-call authorization.**
Agent holds broad ambient authority; a low-privilege request rides the agent's
privileges. Policies match tool name + path substring only — argument values,
caller role, and destination are invisible to policy. OWASP ASI02/ASI03.
*Status: NOT mitigated.*

**T3 — Cross-agent privilege escalation via delegation.**
A low-privilege agent delegates to (or is "freed" by) a higher-privilege one
and inherits its authority. Documented patterns: second-order injection via
ITSM agents (AppOmni/ServiceNow, Nov 2025); agents rewriting each other's
config files (Embrace The Red, Sep 2025). OWASP ASI03/ASI07/ASI08.
*Status: NOT mitigated — no delegation model exists.*

**T4 — Data exfiltration (read-then-send).**
Agent reads sensitive data, then ships it out in one outbound step
(`send_email`/`http_post`). The incident record (EchoLeak, CVE-2025-32711,
M365 Copilot — first weaponized prompt injection in production; Notion AI PDF
exfiltration) shows the loss event is always the *outbound* step. OWASP LLM02.
*Status: NOT mitigated — outbound destinations are unallowlisted, payloads
unscanned, no read/send correlation.*

**T5 — Approval-queue social engineering.**
Attacker crafts the action (or its justification) to look benign so the human
approves. OWASP ASI09 (Human–Agent Trust Exploitation). *Status: NOT
mitigated — queue shows agent-supplied text; no expiry, no preview, no
separation of duties.*

**T6 — Log tampering.**
The chain is an *unkeyed* SHA-256 hash chain: anyone holding the log file can
truncate-and-rebuild it, and tail truncation is undetectable. No offline
verifier artifact exists. *Status: NOT mitigated.*

**T7 — Policy misconfiguration.**
Default effect is **allow** (fail-open); rules are first-match, so one broad
allow above a deny silently defeats the deny. No linting. OPA/Cedar and the
NIST guidance treat fail-open as a design bug. *Status: NOT mitigated.*

**T8 — Time-of-check / time-of-use drift.**
An approval is granted, then policy or arguments change before execution.
*Status: PARTIALLY mitigated — `execute_approved` re-evaluates context, but
not the current policy set, and approvals never expire.*

**T9 — Rate / loop abuse (worming, cascading runaway).**
No budgets on outbound sends, writes, or repeated identical calls.
OWASP LLM10, ASI08; Greshake worming. *Status: NOT mitigated.*

**T10 — Tool-definition / config poisoning.**
Tool descriptions are read by the model every step (MCP tool-poisoning /
rug-pull class); agent config files can be rewritten by other agents.
OWASP ASI04, LLM07. *Status: NOT mitigated (no pinning).*

**T11 — Identity spoofing.**
Agents self-declare `agent_id`/`role`/`principal`; the log trusts the claim.
SPIFFE/SPIRE vocabulary (workload identity, attestation) is the direction;
today we need at least executor-minted identities. *Status: NOT mitigated.*

**T12 — Secrets in logs / approvals.**
Logged args and result summaries can contain credentials; the approval queue
becomes a secret store. *Status: NOT mitigated.*

**T13 — Memory poisoning (DEFERRED).**
AgentPoison (>80% ASR at <0.1% poison rate), MINJA. The product has no memory
yet; when it does, memory writes must be provenance-gated. Recorded here so
the design doesn't foreclose it.

## What already exists (don't reinvent)

- Hash-chained JSONL action log with `verify_chain()` replay — keep, upgrade
  to HMAC (stdlib `hmac`), add checkpoints.
- YAML policy engine with allow/deny/require_approval — keep the shape,
  fix the semantics (deny-by-default, forbid priority, richer matchers).
- File-based approval queue + CLI — keep, harden (expiry, preview, SoD,
  decision-as-log-entry).
- Executor pipeline identity→policy→approval→log — the right architecture;
  add provenance, DLP, redaction, fail-closed logging, executor-minted
  identities.
