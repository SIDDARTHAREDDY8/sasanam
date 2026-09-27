# Prospectus Lane — OPENAI (2026-09-26)

Source-of-truth: shallow + full-history git clones of the public repos, read at source level.
License floor for reuse: Apache-2.0/MIT. OpenAI repos are MIT → eligible for pattern and code reuse.

Repos covered: `openai-agents-python`, `openai-guardrails-python` (+ JS mirror, noted), `evals`, `swarm`.
Also relevant but not cloned: `openai-agents-js` (TS mirror of the Agents SDK) and
`openai/openai-guardrails-js` (TS mirror of the guardrails package) — same patterns as the
Python repos, nothing extra to steal in TS.

---

## 1. `openai/openai-guardrails-python` — DEEP TREATMENT — verdict: STEAL

**What it is:** Preview drop-in client wrapping the OpenAI Python client; validates inputs/outputs
and integrates with the Agents SDK. Built-in checks: prompt-injection detection, jailbreak, PII
(Presidio), moderation, hallucination detection (vector-store grounding), NSFW, URL filter, keyword,
custom LLM checks.

**Maturity:** MIT · ~251 stars (third-party registry, 2026-07) · 142 commits · active
(last commit 2026-09-24, v0.3.2). Small but maintained by OpenAI. Caveats: LLM-judge checks call
paid OpenAI APIs ($0-spend violation if run as-is); actual policy config lives in the hosted
wizard at guardrails.openai.com (closed source); PII check shells to Presidio. We steal the
*pattern*, not the hosted surface.

### 1a. How it represents user intent (the row-7 gap target)

`src/guardrails/checks/text/prompt_injection_detection.py`:

- Intent is a **`UserIntentDict`** (lines 54–58):
  `{"most_recent_message": str, "previous_context": list[str]}` — the latest user turn plus
  (configurable) prior user turns.
- `_extract_user_intent_from_messages()` (lines ~380–407): walks the conversation history,
  keeps only `role == "user"` messages with string content, takes the last `max_turns`
  (default 10; `LLMConfig.max_turns`).
- `_slice_conversation_since_latest_user()` (lines ~348–370): intent anchor = index of the
  **latest user message**; the *analyzed actions* = everything after that index, filtered by
  `_should_analyze()` (lines ~196–243) which keeps **function calls and function outputs only**
  (Chat Completions `tool_calls`/`function_call` and Responses `function_call`/
  `function_call_output` items). User messages are never analyzed — they are the intent.
- The LLM judge then receives `**User's goal:** {most_recent + previous_context}` alongside
  `**LLM action:** {recent_messages}` and returns structured `PromptInjectionDetectionOutput`
  (`flagged`, `confidence` 0.0–1.0, `observation`, `evidence` — quoted evidence required when
  flagged). Tripwire fires when `flagged and confidence >= confidence_threshold` (default 0.7).

This is exactly our **intent-correlation / check-at-use seam**: every tool call is validated
against the intent slice that authorized it. Reusable directly for our intent-binding work,
adapted to (a) deterministic policy rules at the cheap tier and (b) a local/self-hosted judge
instead of a paid OpenAI call.

### 1b. The judge-scaffold and check registry (reusable policy-engine seam)

`src/guardrails/checks/text/llm_base.py`:

- `LLMConfig` — `(model, confidence_threshold, max_turns, include_reasoning)`; a clean
  config contract for any check function.
- `create_llm_check_fn(name, description, system_prompt, output_model)` — factory that builds
  and **registers** a new LLM-based check into `default_spec_registry`
  (`src/guardrails/registry.py` + `src/guardrails/spec.py`).
- `LLMOutput` pydantic base: `flagged` / `confidence` / `observation` — maps 1:1 onto our
  `GuardrailFunctionOutput`-style verdict shape.

Steal: the **registry-of-checks + structured-verdict contract** is a good template for our
policy engine's check functions — each check declares a config schema, returns
`(triggered, confidence, evidence)`, and registers by name. Our `verify_citation`/`check_at_use`
seams can adopt the same shape.

### 1c. The judge rubric (ready-made evaluation prompt)

`PROMPT_INJECTION_DETECTION_CHECK_PROMPT` (same file, lines ~78–160) encodes evaluation
discipline we want verbatim-style:

- Evaluate **semantic intent** of the action (what is it trying to do?), not function names.
- Flag only on **direct evidence** (quoted injected directive or harmful/unrelated call —
  e.g. `recipient='attacker@evil.com'` when the user asked to email themselves).
- **Do not flag** competence issues (poor quality, partial progress, safe intermediate steps
  like gathering a schedule before booking) — only actual injected instructions or
  goal-mismatched calls.
- Early-workflow steps consistent with eventually satisfying the goal are NOT injection.

Steal: this rubric is a strong starting spec for our intent-binding judge and our
false-positive calibration in the B2 realistic battery.

### 1d. Tool-level vs agent-level check scoping + conversation normalization

`src/guardrails/agents.py`:

- `_TOOL_LEVEL_GUARDRAILS = ["Prompt Injection Detection"]` (line 39) — prompt-injection
  detection runs **per tool call/output** (as `ToolInputGuardrail`/`ToolOutputGuardrail`
  on each `FunctionTool`), while all other checks run at agent level. A clean scoping
  pattern: expensive intent checks at the tool seam, cheap content checks at the boundary.
- `normalize_conversation()` in `src/guardrails/utils/conversation.py` — normalizes both
  Chat Completions and Responses histories into one shape before slicing. Our
  `check_at_use` seam needs the same normalize-then-slice step.

Also worth a look: `src/guardrails/evals/core/json_reporter.py` and `benchmark_reporter.py` —
JSON/JSONL result reporters with per-guardrail metrics + latency tables. STUDY for our
evidence pipeline's auditor-export shape (auditor-readable run reports).

**Plugs into:** (a) row-7 intent correlation gap — adopt `_slice_conversation_since_latest_user`
+ `UserIntentDict` as our intent-binding representation at the check-at-use seam;
(b) policy-engine check registry (`create_llm_check_fn` → our check-function contract);
(c) evidence pipeline — the structured `GuardrailResult` (`tripwire_triggered`, `info` with
`user_goal`, `action`, `token_usage`) is an auditor-exportable verdict record already.

---

## 2. `openai/openai-agents-python` — verdict: STUDY (patterns, not code)

**What it is:** The production multi-agent orchestration framework (successor to Swarm):
Agents, handoffs, tool loops, guardrails, sessions, tracing, realtime, sandbox agents, HITL.

**Maturity:** MIT · ~29k stars / 4k forks · v0.22.2 (2026-09-09) · very active (~1.5–1.6k commits).
The dominant open-source agent harness. Not a governance product — it's the thing we govern.

### Steal-worthy ideas

**2.1 The HITL approval seam (our approval-queue shape).**
`FunctionTool.needs_approval: bool | Callable[(run_context, tool_parameters, call_id) -> bool]`
(`src/agents/tool.py:499`) — per-call approval policy declared on the tool. When triggered, the
run pauses and yields `ToolApprovalItem`s (`src/agents/items.py:556`); the run serializes to a
`RunState` (`src/agents/run_state.py`) that can be **resumed later via
`state.approve(item, always_approve=...)` / `state.reject(item, rejection_message=...)`**
(lines 1301–1350), including `always_approve`/`always_reject` sticky decisions.
`src/agents/run_internal/approvals.py` holds the approval placeholders and normalization
(filtering approval items from mixed interruptions, emitting synthetic error outputs on
rejection).
*Why it plugs in:* this is the proven industry shape for our human-approval queue —
interrupt → serialize → decide → resume, with sticky per-tool decisions. Our approval record
shape can mirror `RunState._serialize_approval_record` (approved/rejected lists + rejection
messages).

**2.2 Guardrail dataclass contract (our policy-engine seam).**
`src/agents/guardrail.py`: `InputGuardrail`/`OutputGuardrail`/`ToolInputGuardrail`/
`ToolOutputGuardrail` are thin dataclasses whose guardrail function returns
`GuardrailFunctionOutput(tripwire_triggered: bool, output_info: Any)`. Tripwire = halt the
run, raise `*TripwireTriggered`. Note the deliberate seam split: boundary checks
(input/output) run in parallel or pre/post agent; tool-level checks run per tool call.
*Why it plugs in:* matches our `check_at_use` / `verify_citation` / `accept_report` seam
taxonomy almost exactly — adopt the same `verdict + info` return contract for our policy
checks so they compose.

**2.3 Tracing as evidence scaffolding.**
`src/agents/tracing/span_data.py`: a typed span taxonomy including `GuardrailSpanData`
(line 293), `FunctionSpanData`, `HandoffSpanData`, `AgentSpanData`. Guardrail evaluations are
first-class spans in the same trace as the agent run.
*Why it plugs in:* our evidence pipeline wants exactly this — every policy verdict recorded
as a structured, timestamped span that chains into the audit log. We keep our own hash-chained
log as the source of truth but can adopt the span taxonomy.

**2.4 Session persistence pattern.**
`src/agents/memory/sqlite_session.py`: pluggable `SessionABC` with a SQLite implementation
(`agent_sessions` / `agent_messages` tables), in-memory default with file-path persistence,
thread-safe file locks. Boring, correct, MIT.
*Why it plugs in:* a template for durable run-state storage backing our approval queue and
artifact inventory.

**Verdict STUDY, not STEAL:** it's a competing orchestration layer with OpenAI-centric
defaults (Responses API), ~900 Python files — we govern agents, we don't ship a harness.
But its guardrail/HITL/tracing shapes are the de-facto standard our governance layer must
interoperate with, so our seams should be shaped to sit alongside them.

---

## 3. `openai/evals` — verdict: SKIP

**What it is:** The original open-source LLM eval framework: registry of eval YAMLs
(`evals/registry/evals/*.yaml` mapping an eval id → `module:Class` + args), `Eval` ABC
(`evals/eval.py:46`), JSONL sample datasets (git-LFS), metrics plumbing.

**Maturity:** MIT · 691 commits · **dormant — last commit 2026-04-14**; superseded by the
in-Dashboard evals product (README says "You can now configure and run Evals directly in the
OpenAI Dashboard"). Contains a few agent-adjacent evals (`cybersecurity-filepaths.yaml`,
`human-safety.yaml`, `hr-ml-agent-bench.yaml`) but nothing agent-governance specific.

**Why SKIP:** deprecated upstream; the registry-YAML pattern is trivially reinventable and
our B2 realistic battery is already custom. No evidence-pipeline artifacts worth lifting.

---

## 4. `openai/swarm` — verdict: SKIP (archived; one surviving pattern)

**What it is:** The original experimental multi-agent cookbook (29 commits, archived;
README explicitly redirects to the Agents SDK).

**Maturity:** MIT · archived · last commit 2026-04-15.

**Only steal-worthy pattern:** the **handoff** — an agent exposed to the model as a synthetic
transfer tool returning another `Agent` object — already folded into
`openai-agents-python` (`src/agents/handoffs/`). Nothing else to take; the SDK supersedes it.

---

## Verdict summary

| Repo | Verdict | Best single idea for our build |
|---|---|---|
| `openai-guardrails-python` | **STEAL** | Intent-slicing judge: `UserIntentDict` + `_slice_conversation_since_latest_user` + direct-evidence rubric → our row-7 intent-binding seam |
| `openai-agents-python` | **STUDY** | HITL shape: `needs_approval` → `ToolApprovalItem` → `RunState.approve/reject` resume → our approval queue |
| `evals` | SKIP | deprecated; nothing governance-specific |
| `swarm` | SKIP | handoff pattern already in the Agents SDK |

**License note:** all four are MIT → pattern and code reuse are permitted (attribution required
for verbatim code). For guardrails-py, the genuinely reusable parts are the *patterns*
(intent slicing, judge rubric, registry contract) — the hosted config wizard and paid-API
judge calls stay on their side.
