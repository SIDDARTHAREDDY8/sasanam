# Prospectus lane: ANTHROPIC (github.com/anthropics)

Scout date: 2026-09-26. Method: GitHub API enumeration + shallow clones to /tmp (no browser UI needed; all repos cloneable). $0 spend.

## Org inventory (public repos touching agent control, oversight, or evidence)

| Repo | What it is | Stars | License | Notes |
|---|---|---|---|---|
| `sandbox-runtime` | OS-level sandbox CLI/library for agents (bubblewrap / sandbox-exec + proxy network filter + credential masking) | ~5.3k | Apache-2.0 | Active (updated 2026-09-26). **Top find.** |
| `cwc-long-running-agents` | Hook primitives for long-running agents: evidence-gated writes, kill switch, fresh-context evaluator | ~680 | Apache-2.0 | Event demo, not maintained — patterns still sharp |
| `claude-agent-sdk-python` | Python SDK for building agents on Claude Code: hooks, permission modes, MCP bridging | ~8.2k | MIT | Active. Permission/hook semantics worth studying |
| `defending-code-reference-harness` | Autonomous vuln-discovery pipeline (recon→find→verify→report→patch) + detection/response skills | ~7.5k | Apache-2.0 | Not maintained, no contributions. Finding-lifecycle contracts reusable |
| `claude-code-security-review` | AI-powered security-review GitHub Action | ~6.3k | MIT | CI-side review pattern; we have our own review lanes |
| `evals` | Anthropic's eval repos (advanced-ai-risk, persona, sycophancy, winogenerated) | ~430 | CC-BY-4.0 | Data license (not code); eval *method* reference only |
| `skills` | Public Agent Skills registry (SKILL.md spec + skills) | ~178k | mixed/NONE | Supply-chain angle: the spec defines what a skill is; inventory/verification target |
| `claude-code-action` | Run Claude in GitHub Actions (MIT) | ~9k | MIT | Agent-in-CI harness pattern |
| `claude-code` | Public repo = plugins + issue tracker only; the CLI itself is NOT open source | ~148k | NONE | Not a source of ideas; issue-tracker workflows only |

Notable non-fits (skipped): `buffa` (protobuf), `jacobian-lens` (interpretability), `hh-rlhf` (training data), `claude-cookbooks` / `courses` / `prompt-eng-interactive-tutorial` (education), all `anthropic-sdk-*` (API clients), `claudes-c-compiler`, `formal-math`, `fermats-last-theorem` (demos).

## Deep dives

### 1. `sandbox-runtime` — VERDICT: STEAL

One line: lightweight sandbox for arbitrary agent processes — native OS primitives (bubblewrap/sandbox-exec) plus a proxy-based network filter with per-destination credential injection and violation monitoring. No container required.

Maturity: ~5,300 stars, commits active through 2026-09-26, Apache-2.0, published as `@anthropic-ai/sandbox-runtime` npm CLI. "Beta Research Preview" but real, tested, documented code.

Steal-worthy ideas:

1. **Per-host-gated sentinel credential substitution** — `src/sandbox/credential-sentinel.ts` (`SentinelRegistry`). The sandboxed agent sees only `fake_value_<uuid4>` placeholders; the host-side proxy swaps sentinel→real value on egress, and substitution is gated *per credential*: a sentinel is injected only when the destination matches THAT credential's `injectHosts` list, so credential A can't be laundered through credential B's allowlisted host. The map lives only in process memory — never written to disk, never logged. Length-matched padding keeps `Content-Length` invariant under body substitution (fail-safe: worst case a wrong *fake* reaches upstream, never a secret). **Plugs into:** our F81 proxy-enforced egress design and the authorized-channel semantic-exfil gap — this is the concrete mechanism for "secrets are unusable outside their authorized channel." Our Egress Canaries could be minted as sentinels, giving us a detection + prevention loop with one primitive.
2. **Explicit fail-closed filter contract** — `src/sandbox/request-filter.ts` (`FilterRequestCallback`): "Throwing or rejecting denies the request. This is the failure contract for a security boundary: a buggy policy fails closed." The proxy also feeds the denial reason back to the agent so it can distinguish a policy block from a network failure. **Plugs into:** our fail-closed policy engine — adopt the same contract verbatim (exception in policy path = deny, and surface the reason in the audit log). It's the cleanest public statement of fail-closed-at-the-seam I've seen; we can cite it in `tests/` close-when criteria.
3. **Sandbox violation evidence store** — `src/sandbox/sandbox-violation-store.ts` (`SandboxViolationStore`): in-memory tail of violation events (seatbelt/seccomp/proxy lines), sanitized to one physical line, per-command queryable (`getViolationsForCommand`), with subscribe/listeners and a total-count that survives `clear()`. **Plugs into:** our hash-chained audit log + evidence pipeline — violation events are exactly the "attempted-but-denied" evidence auditors want; the sanitize-on-ingest + totalCount-survives-clear shape is a good pattern for our own violation journal.
4. Supporting pieces worth a read: `src/sandbox/credential-extract.ts` / `credential-mask-env.ts` / `credential-aws-pairs.ts` (credential discovery incl. AWS key pairs — the inventory half of masking), `src/sandbox/resolved-address-guard.ts` (DNS-rebinding guard — TOCTOU on allowlisted domains), `src/sandbox/domain-pattern.ts` (allowlist pattern matching), `src/sandbox/body-substitution.ts` (stream-safe byte replacement for sentinel swap-in).

Caveat: TypeScript (our stack is Python), and it's a beta preview — but the *designs* (sentinel registry, fail-closed contract, violation store) port directly.

### 2. `cwc-long-running-agents` — VERDICT: STEAL (patterns; tiny, copyable files)

One line: the hook primitives behind Anthropic's "Effective Harnesses for Long-Running Agents" engineering posts — shipped as standalone shell scripts you copy into a project's `.claude/` dir.

Maturity: ~680 stars, Apache-2.0, updated 2026-09-26; explicitly "example ingredients, not a turnkey harness; not maintained." Maturity risk is low because each primitive is one standalone file with no dependencies.

Steal-worthy ideas:

1. **Evidence-gated writes (default-FAIL contract)** — `claude-code-config/.claude/hooks/track-read.sh` + `verify-gate.sh`. Every criterion starts `false`; a PreToolUse hook denies any write to the results file unless the agent has first opened evidence (screenshot/console log) with the Read tool — "The agent can't claim success it hasn't observed." The hook comments honestly list the gaps a production version would close (Bash sed/jq bypasses the Write/Edit hook; basename-only matching). **Plugs into:** our human-approval queue and the "sell evidence, not the engine" strategy — an approval gate that requires *evidence to exist before a claim can be approved* is the product shape. We should implement the production version (hook all mutation paths, per-row evidence binding) as part of our approval pipeline.
2. **File-based human kill switch** — `claude-code-config/.claude/hooks/kill-switch.sh`: a PreToolUse hook that blocks every tool call while `./AGENT_STOP` exists (`touch AGENT_STOP` to engage). Five lines, brutally effective. **Plugs into:** our human-oversight / operator-control surface — a canonical "stop the agent" primitive we should offer in the approval UI (our kill switch is currently implicit; this makes it a named, copyable pattern).
3. **Fresh-context evaluator** — `claude-code-config/.claude/agents/evaluator.md`: a separate subagent with NO Write/Edit tools grades the work from a context window that never saw the build; "the builder shouldn't grade its own work." **Plugs into:** our post-wave closure audit — we already do red-first audits; this gives the pattern a name and a shape (no-write evaluator context) we can standardize.

Also worth noting: `commit-on-stop.sh` (commit at end of every session) is a poor-man's audit-trail habit; `steer.sh` (surface `./STEER.md` once then clear) is a one-shot operator-injection pattern.

### 3. `claude-agent-sdk-python` — VERDICT: STUDY

One line: the official Python SDK for building agents on top of Claude Code (hooks, permission modes, sessions, MCP bridging).

Maturity: ~8,200 stars, MIT, very active (2026-09-26). Not something to fork — something to learn the *semantics* from.

Study-worthy ideas:

1. **Permission decision lattice** — `src/claude_agent_sdk/types.py`: `PreToolUseHookSpecificOutput.permissionDecision` ∈ `{allow, deny, ask, defer}` (note `"approve"` is deprecated — `types.py` line ~571). The `ask` decision carries a `permissionDecisionReason` that is forwarded into the approval prompt (`PermissionContext`, ~line 224). **Plugs into:** our approval-queue design — a four-valued decision (allow/deny/ask/defer) is richer than our current allow/deny/ask, and the reason-forwarding into the human prompt is a UX detail we should adopt. Study `examples/hooks.py` and `examples/tool_permission_callback.py` for the wiring.
2. **Permission evaluation order** — documented in `README.md`: `allowed_tools` (auto-approve allowlist) → `permission_mode` (e.g. `acceptEdits`) → `can_use_tool` callback → hooks. Layered, deterministic, documented precedence. **Plugs into:** our policy engine's rule-evaluation order — worth mirroring the documented-precedence discipline.
3. Changelog honesty (e.g. "hooks dispatch for a given event is concurrent, not sequential") is a caution: our hook/event semantics must document concurrency explicitly too.

### 4. `defending-code-reference-harness` — VERDICT: STUDY (narrow)

One line: Anthropic's reference autonomous vuln-discovery + detection/response pipeline (gVisor-sandboxed agents, ASAN, graded findings).

Maturity: ~7,500 stars, Apache-2.0, but "not maintained and is not accepting contributions."

Study-worthy, narrowly:

1. **Finding-lifecycle data contracts** — `harness/artifacts.py`: frozen `CrashArtifact` dataclass (PoC bytes base64'd, exact reproduction command, exit code, agent's dup-check reasoning) as the find→grade pivot; `GraderVerdict` (passed, score 0–1, per-criterion bools, evidence summary). **Plugs into:** our finding hygiene (B4) and evidence pipeline — a claim artifact that bundles *reproduction command + raw evidence + verdict* is the unit our attestation exports should carry. The "unverified claim vs graded verdict" two-type split is the honest shape.
2. **Agent-sandboxing docs** — `docs/agent-sandbox.md` / `docs/security.md`: gVisor isolation + egress allowlist for every agent, "what not to mount." Worth one read for our real-sandboxing roadmap (priority 3), but gVisor-specific.
3. The `/dnr-hunt` + `/dnr-respond` detection/response skills (`dnr_harness/`, demo target `targets/dnrcanary/`) are a canary-target pattern — adjacent to our Egress Canaries; skim `docs/detection-response.md` if we want a second canary design reference.

Not worth stealing: the pipeline itself is C/C++-memory-vuln-specific; the sibling lane's `lucy` coverage overlaps.

## Verdict summary

| Repo | Verdict | Best single idea |
|---|---|---|
| `sandbox-runtime` | **STEAL** | Per-host-gated sentinel credential substitution (`credential-sentinel.ts`) — secrets unusable outside their authorized channel |
| `cwc-long-running-agents` | **STEAL** | Evidence-gated writes: deny claim-approval until evidence was opened (`verify-gate.sh` + `track-read.sh`) |
| `claude-agent-sdk-python` | STUDY | Four-valued permission decision (allow/deny/ask/defer) with reason forwarded to the human prompt (`types.py`) |
| `defending-code-reference-harness` | STUDY | Claim/grade two-type finding artifact (`harness/artifacts.py`) |
| everything else enumerated | SKIP | — |

## Recommended follow-ups for the build

1. Port the sentinel-registry design into our F81 proxy workstream as the credential-injection mechanism (per-destination host gating is the missing piece in our current egress design).
2. Add an evidence-gated approval rule to our human-approval queue (production-hardened version of `verify-gate.sh`): no approval of a success/result claim without referenced evidence.
3. Adopt the fail-closed filter contract language ("throwing denies") in our policy-engine seam tests.
