# Lane: Security Companies

Prospected 2026-09-26. Method: GitHub org API scans (DataDog, CrowdStrike, PaloAltoNetworks, wiz-sec, sysdig, Snyk) filtered for agent/AI/detection/sandbox keywords + web sweeps for known AI-security repos; shallow clones to `/tmp/secprospect`. All file pointers verified against the clones.

## Top picks

### 1. cisco-ai-defense/mcp-scanner — STEAL
- What it is: Python tool for scanning MCP servers and tools for security findings (YARA + LLM + Cisco AI Defense engines, CLI or REST server).
- Maturity: ★1080, actively pushed (2026-09-19), Apache-2.0.
- Steal-worthy ideas:
  1. **The 10 YARA rule files are a ready-made "Sigma for agents" corpus** — steal and adapt: `mcpscanner/data/yara_rules/tool_poisoning.yara` (hidden secondary-behavior regexes in tool descriptions), `data_exfiltration.yara` (upload/send-to-external + suspicious-domain patterns), `prompt_injection.yara`, `credential_harvesting.yara`, `coercive_injection.yara`, `command_injection.yara`, `code_execution.yara`, `script_injection.yara`, `sql_injection.yara`, `system_manipulation.yara`. Plugs directly into our attack-program gaps **tool poisoning / semantic exfil**: run these against MCP tool descriptions at *registration time* (artifact inventory) and against tool I/O at *check-at-use*. They're plain regexes over text — trivially portable to our Python gate.
  2. **Readiness policies as OPA/Rego gate checks**: `mcpscanner/data/readiness_policies/timeout_required.rego` and `max_capabilities.rego` — "tool must have timeout configured", "max N capabilities per tool". Pattern to steal for our MCP tool registration policy (goal-conflict/least-privilege direction: reject over-scoped tools before they get an approval path).
  3. **Engine wiring**: `mcpscanner/core/analyzers/yara_analyzer.py` shows how to compile and run the YARA set over tool metadata; `mcpscanner/core/scanner.py` orchestrates multi-engine scoring. Use as the shape for our registration-time scanner pipeline.
- Verdict: **STEAL**. Closest match to the "detection rules we could adapt" ask; permissive license; directly fills the tool-poisoning/semantic-exfil detection gap.

### 2. Snyk/agent-scan (Invariant Labs) — STEAL (taxonomy + hook pattern)
- What it is: Security scanner for AI agents, MCP servers and agent skills — discovers installed agents/clients on a machine and scans their MCP configs and skill files for prompt injections and vulnerabilities.
- Maturity: ★3091, pushed 2026-09-26, Apache-2.0. Largest agent-security OSS repo in the vendor set.
- Steal-worthy ideas:
  1. **Risk taxonomy in `docs/risks.md`** — named, scored risk indicators: `prompt_injection_tool_desc`, `untrusted_content`, `private_data`, `destructive_capabilities` (MCP servers); `prompt_injection_skill_instructions`, `suspicious_download_url`, `malicious_code`, `insecure_credential_handling`, `secret_detection`, `direct_money_access`, `third_party_content_exposure`, `unverifiable_dependencies`, `modifying_system_services`. This is the finding-set our supply-chain lane should converge on — steal the taxonomy (names + severity semantics) for our skill/MCP verification findings so we don't invent a weaker vocabulary.
  2. **`src/agent_scan/hook_events.py` — runtime hook-event pattern**: agent hook scripts (`hooks/snyk-agent-guard.sh`) read a JSON payload from stdin and POST it base64-encoded to a monitor endpoint with `X-Agent-Surface` header, per-client session fields (`claude-code` → cwd + session_id). This is exactly the shape our runtime agent-behavior monitor needs: per-tool-call hook events carrying session + surface identity. Steal the envelope design, not the server.
  3. **Agent discovery model**: `src/agent_scan/agents/` (per-client discoverers for Claude Code, Cursor, Codex, Copilot, Windsurf, Kiro...) + `src/agent_scan/inspect.py` — a working map of where agents, MCP servers, and skills live on a machine. Reference for our unknown-agent discovery/inventory lane.
- Caveats: README says CLI output (issue codes, risk names) is experimental and may change; the real scoring is server-side (Snyk Evo). Steal the taxonomy and patterns, don't depend on their API.
- Verdict: **STEAL** (taxonomy + hook-event design). **STUDY** the Evo server-side scoring model if we ever design our own.

### 3. DataDog/rshell — STUDY
- What it is: A default-deny shell interpreter for Go, built for AI agents that need a bounded Bash/POSIX-like command surface.
- Maturity: ★31, pushed 2026-09-25, Apache-2.0. README is explicit: the CLI is a dev/validation tool, not a production security boundary — embed the Go package.
- Steal-worthy ideas:
  1. **Default-deny policy model in `interp/api.go`**: `AllowedCommands([]string{...})`, `AllowedPaths([]string{...})`, `MaxExecutionTime(...)`, `Env(...)` as `RunnerOption`s — a clean way to express "what this agent is allowed to do" that maps onto our policy engine's tool-allowlist direction. Worth studying as the shape of a bounded-execution policy.
  2. **`interp/command_scrub.go`** — secret scrubbing of command lines (keyword-based regexes: password/token/api-key/credential, plus URL-credential handling). Portable idea for our evidence pipeline: scrub secrets from audit log entries before retention/export (evidence-pipeline artifact hygiene).
  3. **`tests/scenarios/` — vuln-hunt YAML corpus**: hundreds of scenario tests including named `vuln_hunt` adversarial cases (e.g. `tests/scenarios/shell/allowed_paths/vuln_hunt/`). Pattern to copy: maintain our sandbox policy as an adversarial scenario corpus, not just unit tests.
- Verdict: **STUDY**. The Go interpreter isn't directly reusable (our runtime is Python), but the allowlist policy shape and the vuln-hunt corpus pattern are worth importing into our sandbox lane.

### 4. CrowdStrike/aidr-mcp-proxy — STUDY (architecture only)
- What it is: stdio wrapper that runs all MCP server I/O through CrowdStrike AIDR — blocks prompt injection, malicious links/IPs/domains, 50 PII types, toxicity filters.
- Maturity: ★3, MIT, last push 2026-08-06.
- Steal-worthy ideas:
  1. **The proxy-wrap architecture** (`src/proxy.ts`): intercept at the stdio boundary by wrapping the MCP server command (`npx aidr-mcp-proxy -- <real server>`), so every tool call's input/output passes through the guard without modifying the server or the client config beyond the wrapper. This is the reference deployment shape for our MCP gateway guard — validate our proxy sits at the same choke point.
- Caveats: the guard logic itself requires a paid CrowdStrike AIDR API token — nothing reusable; it's a thin client. ★3 means no community vetting.
- Verdict: **STUDY** the wrapper architecture; **SKIP** everything else.

## Skipped
- **CrowdStrike/falcon-mcp** (★258, MIT): MCP server connecting agents *to* Falcon for threat hunting — makes agents consumers of Falcon, not agents under governance. Requires Falcon API scopes. SKIP for our build.
- **PaloAltoNetworks/prisma-airs-integrations** (★21) and **panw-api-ollama** (★10): no license on either (per GitHub API) — automatic skip on our Apache-2.0/MIT reusability rule. Both are demo/installer-oriented, not detection-rule sources.
- **sysdig org**: only keyword match was `skills` (agentic AI skills for Sysdig's own product) — no Falco-rules-in-org content; Falco itself is falcosecurity (CNCF, Sysdig-originated) and is syscall/runtime detection, not agent-behavior detection. SKIP for this lane.
- **wiz-sec org**: empty of matching repos. SKIP.
- **DataDog/pup** (★1021): CLI companion giving agents 200+ Datadog commands — an agent *capability* bundle, not governance. SKIP.
- **DataDog/datadog-saist** (★104): AI-native SAST — code scanning, not agent runtime governance. SKIP.

## Bonus (not a security company, but the best rule corpus found)
- **Agent-Threat-Rule/agent-threat-rules** — "Sigma, but for AI agents": open, versioned YAML detection rules (ATR-YYYY-NNNNN scheme), 825 rules across 10 categories (prompt injection, tool poisoning, context exfiltration, MCP attacks), MIT, merged into projects at Microsoft, Cisco, Gen Digital, MISP, FINOS. This is the canonical Sigma-style rule set to adapt for our runtime detection engine. Worth its own lane review.
