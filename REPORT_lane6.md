# Wave-335 Lane 6 (Research Prospecting) — Report (takeover completion)

**Base:** `0fd4f736` (wave-334 merge). **Pin:** 2100. **Footer:** open none / next F417.
**Takeover:** original coordinator completed; 2 of 3 framework-survey scouts were interrupted before delivering §3a/3b. Takeover agent wrote the framework survey directly from primary sources. No fresher `.takeover-claim` existed; claim written at start.

## What was done

1. **Verified the partial prospectus on disk** (`research/prospecting/w335_prospectus.md`): §1 CIMD safe-subset (ADAPT ×3), §2 Sigstore-bundle OCI wiring (ADAPT), §4 Tier-1 competitor delta (Algedonic/EVE WATCH, Bernstein 4 ADAPT patterns + WATCH, Apache-2.0 confirmed) — all complete and sound. §3 framework survey was the only gap.
2. **Completed §3 (real-agent framework integration survey)** from primary sources (framework docs/source, access date 2026-10-05):
   - **Tree check first:** `gov/adapters/` already ships LangChain (`langchain_tools.py`, funnel-pinned, F62-hardened), MCP client (`mcp_adapter.py`, P2 metadata guard), and raw OpenAI loop (`openai_loop.py`). No CrewAI/AutoGen adapter exists.
   - **3a LangChain: SKIP** (built) + **WATCH** the new Agent Middleware `after_model` approval path; legacy `on_tool_start` callbacks are observe-only (exceptions swallowed) — never enforcement.
   - **3b LangGraph: ADAPT** — thin `interrupt()` → our `ApprovalQueue` recipe; mechanical tool path already covered via ToolNode→`_run`.
   - **3c CrewAI: ADAPT** — new `BaseTool` wrapper shim (tools must be `BaseTool`; `human_input` is coarse; sync-execution quirk). MIT.
   - **3d AutoGen/AG2: ADAPT** — hook-based shim (`process_all_messages_before_reply` + `execute_function` wrap); target AG2 (microsoft/autogen in maintenance mode). Apache-2.0.
   - **3e OpenAI Agents SDK: ADAPT** — shim on native `tool_input_guardrails` (v0.14+); **documented residual:** hosted tools, built-in execution tools, handoffs, `Agent.as_tool()` are NOT covered by the SDK's guardrail pipeline (per official docs).
   - **3f MCP clients: SKIP** — our adapter is the most complete surveyed (P2 description-injection guard + pre-dispatch metadata re-validation; Microsoft's toolkit and Vörður do less).
   - **3g Third-party adapter projects: WATCH** — `acp-governance-sdks` (17 framework scouts, the one to watch), intentfence, typed_evals, vordur, agent-security-gate, governed-autonomy-substrate. Thin wrappers; none has a fail-closed engine or offline evidence.
3. **Finalized the verdict table** (all rows resolved; no pendings) and extended build recommendations to **R1–R11** (R8: CrewAI shim, R9: AG2 shim, R10: Agents-SDK shim + residual doc, R11: LangGraph recipe + quarterly adapter re-sweep).

## Verdict counts

- **STEAL:** 1 (Bernstein no-dead-controls CI gate)
- **ADAPT:** 11 (CIMD ×3, Sigstore OCI wiring, Bernstein ×3, LangGraph recipe, CrewAI shim, AG2 shim, Agents-SDK shim)
- **WATCH:** 6 (CIMD request-time fetch, Algedonic, EVE, Bernstein per-hop records, LangChain middleware, third-party adapters)
- **SKIP:** 2 (LangChain classic adapter, MCP client adapter — both already built)

## License checks

All framework licenses permissive (MIT/Apache-2.0), verified via repo LICENSE catalogs 2026-10-05. IETF CIMD draft: patterns only, no encumbrance. No code copied from any source in this lane. Prior traps respected (Teleport AGPL, EmpowerID/Omada proprietary).

## Findings

None filed. No new decision codes; pin unchanged 2100; `evals/FINDINGS.md` untouched.

## Files

- `research/prospecting/w335_prospectus.md` — completed prospectus (§3 added, verdict table finalized, R1–R11)
- `REPORT.md` (this file)

**REPORT AND STOP** — no follow-on work dispatched; wave-335 merge planning returns to the parent.
