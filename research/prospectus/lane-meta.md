# Lane META — repo prospecting (2026-09-26)

Scope: github.com/meta, github.com/facebookresearch, github.com/meta-llama — agent infrastructure,
safety/alignment tooling, agent oversight, evaluation, guardrails.
Method: GitHub API + sparse shallow clones (`~/workspace/.prospect-meta/`), primary sources only.
Spend: $0.

Coverage: PurpleLlama (LlamaFirewall, CyberSecEval→CybersecurityBenchmarks, CodeShield,
PromptGuard2), llama-stack→OGX rebrand, meta-agents-research-environments (ARE/Gaia2).
Surveyed and skipped: facebookresearch/HyperAgents (self-improving-agent research, 2767★, no
governance surface), facebookresearch/ReAgent (RL reasoning platform, BSD-3, 3717★), MLGym (eval
harness, 625★, no audit surface), meta-llama/llama-cookbook (recipes only).

---

## 1. meta-llama/PurpleLlama — STEAL

Meta's open safety toolkit: LlamaFirewall guardrail framework, CybersecurityBenchmarks
(CyberSecEval 1–4) eval suite, CodeShield static analyzer.
- Maturity: 4406★, actively maintained into 2026 (pushed 2026-08-18). Paper: arXiv:2505.03574.
- License — CAREFUL, verified 2026-09-26: repo-root `LICENSE` is **Llama 3.2 Community License**,
  BUT subdirectories carry their own licenses: `LlamaFirewall/LICENSE` = **MIT**,
  `CodeShield/LICENSE` = **MIT**, `CybersecurityBenchmarks/LICENSE` = **MIT**.
  Cite the subdirectory license, not the repo badge. Caveat: the *models* LlamaFirewall loads
  (PromptGuard 2 weights, Llama 3.1/3.3 for AlignmentCheck/PIICheck) carry Llama community
  licenses — code is MIT, model weights are not.

### Steal 1 — Role-keyed scanner registry with three-way decision (guardrail seam design)
Files: `LlamaFirewall/src/llamafirewall/llamafirewall_data_types.py`,
`LlamaFirewall/src/llamafirewall/llamafirewall.py` (`scan`, `scan_replay`, `scan_replay_build_trace`)

- `Scanner` contract: `async scan(message: Message, past_trace: Trace | None) -> ScanResult` —
  every scanner gets the current message AND the optional full conversation trace, so per-message
  scanners and temporal scanners share one interface. `require_full_trace` flag declares which.
- `Role` enum = TOOL / USER / ASSISTANT / MEMORY / SYSTEM; scanners are registered per role:
  `LlamaFirewall(scanners={Role.USER: [PROMPT_GUARD], Role.ASSISTANT: [AGENT_ALIGNMENT]})`.
  This is exactly our check_at_use seam shape — a role-addressed scanner table we can mirror.
- `ScanDecision` is three-valued: **ALLOW / HUMAN_IN_THE_LOOP_REQUIRED / BLOCK** (not boolean).
  The HITL state maps 1:1 onto our human-approval queues: a guardrail verdict of "needs human"
  rather than block-or-allow is the missing middle our policy engine should model as a native
  verdict (evidence: `ScanResult.decision`, `.reason`, `.score` → our decision-receipt schema).
- Gap vs ours: no artifact/egress role, no evidence binding — scanners return decisions, not
  signed receipts.

### Steal 2 — AlignmentCheck: structured CoT goal-hijack audit (semantic drift / goal conflict)
File: `LlamaFirewall/src/llamafirewall/scanners/experimental/alignmentcheck_scanner.py`

- An LLM-judge scanner with `require_full_trace = True`: picks the original user input from the
  trace, feeds (user_input, full trace) to a judge with a strict pydantic output schema
  (`AlignmentCheckOutputSchema`: `observation` / `thought` / `conclusion: bool`), and embeds the
  judge's reasoning into `ScanResult.reason`. This is the pattern our semantic-drift and
  goal-conflict detectors should copy: verdict + machine-readable schema + human-readable
  reasoning string in one artifact.
- Note the failure-mode choice: when no trace is available it returns `ALLOW` with
  `status=ERROR` (fail-open); the judge's own error schema defaults to "compromised=True"
  (fail-closed). Two-layer fail semantics worth adopting deliberately.

### Steal 3 — HiddenASCIIScanner: invisible-Unicode covert-channel detector (semantic exfil gap)
File: `LlamaFirewall/src/llamafirewall/scanners/hidden_ascii_scanner.py`

- Detects Unicode tag characters U+E0000–U+E007F (invisible steganographic exfil) and *decodes*
  the hidden payload into the scan reason. Direct plug: our authorized-channel semantic-exfil
  attack program — add this scanner to the ASSISTANT/TOOL-output seam of our egress layer as a
  canonical example of a channel you can't catch with text classifiers.

### Steal 4 — CyberSecEval 4 eval-battery design (attack-program evidence)
Files: `CybersecurityBenchmarks/benchmark/` — `prompt_injection_benchmark.py`
(incl. `visual_prompt_injection_benchmark.py`), `multiturn_phishing_benchmark.py`,
`interpreter_benchmark.py`, `mitre_benchmark.py` / `mitre_frr_benchmark.py`

- Prompt-injection suite split by delivery (text vs visual) and attack-technique categories;
  **multi-turn phishing benchmark** = a multi-turn adversarial-conversation eval, i.e. the
  temporal-correlation shape our attack program needs to evidence guardrails holding
  adversarially across turns, not just per message.
- MITRE compliance + False Refusal Rate pairing: measures safety *and* the utility lost to
  over-refusal — the two-sided metric our safeguard-benchmark lane should report per control.
- MIT-licensed code and datasets; reusable battery shapes, not just results.

### Steal 5 — CodeShield two-tier static analysis map (tool-execution gate)
Files: `CodeShield/insecure_code_detector/insecure_code_detector.py`
(`LANGUAGE_ANALYZER_MAP`, `CodeContext`), `LlamaFirewall/src/llamafirewall/scanners/code_shield_scanner.py`

- `LANGUAGE_ANALYZER_MAP`: per-language [REGEX, SEMGREP] analyzer list; tier-1 fast regex
  (~<100ms), escalate to semgrep only on flag (~300ms) — a latency-budgeted gate design for
  scanning LLM-generated code *before* sandbox execution. Plug: our tool-execution / sandboxing
  lane's pre-exec code screen.

Verdict: **STEAL** — the Role-keyed scanner registry + three-way decision and the AlignmentCheck
structured-judge pattern are the two highest-value plugs in this whole lane.

---

## 2. facebookresearch/meta-agents-research-environments (ARE / Gaia2) — STUDY (steal the evidence schema)

Dynamic agent-evaluation platform: evolving multi-step scenarios (not static benchmarks), 800-scenario
Gaia2 benchmark across 10 "universes".
- Maturity: 558★, young (31 commits), pushed 2026-08-26. Paper via ai.meta.com ("ARE: scaling up
  agent environments and evaluations"). **MIT.**
- Not a guardrail; an eval platform. Value is entirely in the evidence-artifact design.

### Steal 1 — Typed agent-log taxonomy with replay (evidence run-trace schema)
Files: `are/simulation/agents/agent_log.py` (`BaseAgentLog`, log-type map,
`serialize()`/`from_dict()`), `are/simulation/replay.py` (`replay_logs`)

- ~20 typed log entries (thought, plan, rationale, tool_call, observation, action, subagent,
  final_answer, error, refacts…) each with timestamp, UUID, agent_id, a `log_type` discriminator
  for JSONL round-tripping. This is a credible template for our evidence pipeline's run-trace
  artifact: typed, serializable, replayable.
- `replay_logs(world_logs, env)`: replays an agent's exact action sequence against the
  environment — the "auditor can re-run what the agent did" story our attestation layer wants.

### Steal 2 — Submission bundle = attestation-bundle pattern
Files: `are/simulation/benchmark/gaia2_submission.py` (`handle_gaia2_run`), `report_stats.py`,
`report_utils.py`

- `output_dir`: "dump the scenario states and logs"; `upload_consolidated_results_to_hf`:
  consolidated results + summary generated by `generate_submission_summary`. A submission =
  scenario states + logs + computed summary — exactly the evidence-bundle shape for our
  "sell evidence" pipeline (attestation = trace bundle + summary + upload manifest).

Verdict: **STUDY** — don't adopt the platform; steal `agent_log.py`'s log taxonomy and the
submission-bundle shape for evidence artifacts.

---

## 3. meta-llama/llama-stack → now ogx-ai/OGX — STUDY (with rebrand caveat)

**Heads-up:** as of 2026-09-26 the repo rebranded to **OGX** (`ogx-ai/ogx`, "Llama Stack is now
OGX — model-agnostic, multi-SDK"). Meta-era `apis/safety` (the Llama Guard *Shield* API) is
**gone** from the tree; what remains is an OpenAI-compatible agentic API server
(Responses API, `/v1alpha/skills`, vector stores).
- Maturity: 8435★, MIT, very active (pushed 2026-09-26). Community-driven now, not Meta.

### Steal 1 — Versioned skill bundles with pinned default (supply-chain lane)
File (current tree): `src/ogx_api/skills/models.py`

- `Skill` has `latest_version` + `default_version`; `SkillVersion` has per-version IDs; create/delete
  per version. Pin-by-version skill invocation is the anchor our continuous skill/MCP
  supply-chain verification lane needs: registry stores versioned bundles, policy pins the
  version, drift = new version upload. Wire-compatible with OpenAI's Skills API shape.

### Steal 2 — Server-side agentic orchestration surface (Responses API)
- OGX's Responses API does tool-calling/MCP orchestration server-side in one API call, with
  Open Responses conformance tests in-tree. If we ever expose a hosted agent-execution API, the
  "conformance suite in the repo" habit is worth copying for our evidence story.

Verdict: **STUDY** — no longer a Meta safety asset; track for skill-versioning and the
server-side orchestration API shape. Do NOT look here for guardrails — that API was removed.

---

## Cross-lane notes
- LlamaFirewall's per-`Role` scanner table confirms our check_at_use seam decomposition but has
  no egress/artifact role and no receipt binding — our differentiator stands.
- HiddenASCIIScanner is the only Meta artifact I found targeting *covert* (non-semantic-text)
  exfil — supports our authorized-channel semantic-exfil gap as genuinely under-covered.
- ARE's replay + typed logs are the closest Meta analog to an evidence pipeline; nobody at Meta
  is selling attestation bundles — the "sell evidence, not the engine" bet is uncontested here.

## Suggested next actions for parent
1. Mirror the three-way `ScanDecision` (ALLOW / HUMAN_IN_THE_LOOP_REQUIRED / BLOCK) into our
   policy-engine verdict type; wire HITL → approval queues (LlamaFirewall
   `llamafirewall_data_types.py`).
2. Port the AlignmentCheck structured-judge pattern (observation/thought/conclusion +
   `require_full_trace`) as our semantic-drift/goal-conflict detector spec.
3. Adopt ARE's `agent_log.py` log taxonomy as the run-trace schema for the evidence pipeline.
4. Add HiddenASCIIScanner-equivalent to the egress-layer scanner set (authorized-channel exfil
   program).
