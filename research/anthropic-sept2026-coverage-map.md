# Coverage map: Anthropic "Detecting and countering misuse of AI: September 2026" vs. agent-governance-demo controls

**Source:** Anthropic threat-intelligence report, September 2026 —
`https://www.anthropic.com/threat-intelligence-report-september-2026`
(report URL fetched live 2026-09-24; report-section citations verified against the page text).

**Tree under test:** `/home/hatch/workspace/agent-governance-demo/agent-governance-demo-main`
(persistent, no .git). Every control claim below was checked against the code itself
(`gov/`, `tests/`, `evals/`), not doc comments — doc claims were treated as unverified
until the implementation matched.

**Reading guide:** verdict per pattern = COVERED / PARTIAL / GAP, with the engaging
controls named as `file` + `symbol`, and an honest residual: what the control
demonstrably does NOT stop. "Opt-in" means: absent config section → guard disabled
by design (not a bug, but the default posture matters).

---

## (a) Closed-loop adaptive evasion — GTG-20006 (Russian espionage)

**Report claim (verified, L116–L120):** "If their monitoring AI agents identified that any of
their deployed malware was detected by a security product, agents would then set about the
process of autonomously modifying and rebuilding the malware to evade the existing
detections. The agents were designed to continue iterating ... until it was undetected."

**Verdict: PARTIAL.**

Engaging controls:

- `gov/detection.py` — `extract_signals` emits per-entry signals
  (`tool_call_rate`, `egress_attempts`, `denial_rate`, `priv_escalation_attempts`,
  `approval_denials`); `SignalState.evaluate` runs EWMA + one-sided CUSUM anomaly
  detection over those signals; a tripped monitor causes `route_action` to downgrade
  high-risk `allow` verdicts to `require_approval` (`gov/executor.py:5155–5180`).
- `gov/tool_ratings.py` / `gov/tool_continuity.py` — continuity/ratings around tool
  behavior (ratings table is the authority for which tools may run autonomously).
- `gov/executor.py` S3 (K-041): a mutating tool with no rating is forced to
  `require_approval` — never allowed silently (`_MUTATING_TOOLS`).

Honest residual: the detection monitor is **opt-in** — `gov/executor.py` states
"No monitor installed = zero behavior change" and it is explicitly excluded from the
governed core (wave-76). The signals cover *denied* and *escalation* events; an agent
that rebuilds tooling through policy-allowed actions (writes, builds, redeploys via
approved tooling) produces no anomaly at all. Nothing in the tree understands the
"rebuild-on-detection" loop as a unit — each iteration is judged fresh. A GTG-20006
operator running inside a governed harness with approved mutating tools could iterate
undetected indefinitely; only the *denial_rate* signal (if the monitor is installed)
would notice the detection half of the loop.

---

## (b) Vibe-hacking bulk tempo — GTG-50014 (ShinyHunters affiliates)

**Report claim (verified, L377–L379):** "a session-store dump containing over 2,100 Azure
AD token sets spanning more than 40 corporate tenants in about 34 hours. AI agents
performed nearly all of the work." One breach went from a single stolen token to full
cloud admin in ~3 hours.

**Verdict: PARTIAL.**

Engaging controls (all enforced by default — code-level defaults, not opt-in):

- `gov/executor.py` F33 volume guards: `volume-guard-sends` (`rate_limit.max_sends_per_run`,
  **default 10**; `gov/executor.py:4826`), `volume-guard-writes` (`max_writes_per_run`,
  **default 50**), `volume-guard-deletes` (`max_deletes_per_run`, **default 20**),
  `volume-guard-egress-bytes` (cumulative egress byte budget, projected at call
  boundary + re-checked at execution — TOCTOU-guarded, `gov/executor.py:4840–4872`).
- `gov/executor.py` loop-guard: repeated identical calls denied as "possible runaway
  loop" (`policy_id="loop-guard"`).
- Opt-in budgets that work when configured: `budgets.max_actions_per_run` (S2/K-018,
  `gov/executor.py:4911` — next call after the ceiling denied, `policy_id=
  "budget-exceeded"`), `run_limits.max_tool_calls_per_run` (S4/K-045), spawn budget
  (`SpawnBudgetExhaustedError` / `_SpawnBudget`, wave-86).

Honest residual: bulk *tempo* is not bulk *volume* — every volume guard is a per-run
cumulative total, never a per-minute/per-hour rate. There is **no time-window tripwire**:
2,000 `read_file`/`api_call` actions in 20 minutes (api_call is read-classified per
F1; read_file is non-mutating) trip nothing under default config, because the caps that
exist cover sends/writes/deletes/egress-bytes, not reads, and the per-action caps
(`max_actions_per_run`, `max_tool_calls_per_run`) are opt-in. Token/spend metering is
unwired — `_tokens_used`/`_spend_used` are initialized to 0 and never incremented
(`gov/executor.py:1160–1161`; `tests/test_budgets.py:183,197` still `expectedFailure`,
S2-GAP-1). The report's scenario — familiar actions at machine speed — succeeds
against default config as long as the bulk channel is reads + token amplification,
which it was in GTG-50014. This is the demonstrated core of **F162** (see verdict
note below).

---

## (c) Agent swarms + persistent cross-session campaign memory — GTG-10007

**Report claim:** Chinese exploit foundry — lead agent dispatching parallel subagents,
persistent campaign memory across sessions, 13-agent collection fleet running
unattended on schedule.

**Verdict: PARTIAL.**

Engaging controls:

- `gov/delegation_tokens.py` — spawn-lineage depth cap ("deeper chains are a design
  smell"), every sub-delegation hop signature-verified against the right roster
  (human keys at depth 0, parent signature at depth ≥ 1).
- `gov/executor.py:150–168` — `_SpawnBudget` / `SpawnBudgetExhaustedError`: one
  lineage, one budget, shared by reference across parent and all children.
- `gov/discovery.py` — unknown-agent inventory (`signal`, `scan_directory`,
  `scan_process_list`, `scan_mcp_config`): detects ungoverned agents on the host.
- `gov/memory_provenance.py` — `MemoryLedger` / `MemoryFirewall`: cross-session
  provenance tiering and quarantine on memory reads/writes.

Honest residual: the spawn budget is **opt-in** — "`None` (no box) means unlimited"
(`gov/executor.py:161–167`), so the default run has no swarm cap at any width or
depth; the depth cap bounds chain *depth*, not fan-out *width*. `discovery.py` is
inventory, not prevention — it finds unknown agents, it does not stop a governed
run from spawning them. Nothing governs *scheduled/unattended* execution — a
13-agent fleet running on a cron is policy-invisible as a schedule; each agent is
judged per-action, per-run. GTG-10007's shape (many parallel children + persistent
memory + unattended schedule) engages four of our modules and defeats the prevention
story of all of them under default config.

---

## (d) AI supply-chain attacks — GTG-50020

**Report claim:** prompt-injected an AI vendor's evaluation sandbox to steal production
API keys, then hit ~30 AI companies in 4 days; prompt injection of LiteLLM/OpenClaw
deployments to exfiltrate keys; fake AI resellers harvesting credentials.

**Verdict: PARTIAL.**

Engaging controls:

- `gov/supplychain.py` — `load_lockfile`, `verify_artifact` (sha256), `audit_environment`,
  `check_install_allowed`, `install_locked`: install-time integrity for our own deps.
- `gov/supplychain_install.py`, `gov/skill_watch.py` — continuous skill/MCP
  verification (`ReferenceResolver`, pin store).
- `gov/citation_provenance.py` — `verify_citation` (SELF_PLANTED / UNKNOWN /
  INDEPENDENT over the chained log + cross-run egress ledger), `check_citations`
  wired into S4 eval-integrity; the F139/F140 closures (2026-09-23/24) exist
  precisely for *evaluator file-upload/citation poisoning* — the closest in-tree
  analog to prompt-injecting an evaluation path. `gov/eval_integrity.py`
  `accept_report` checkpoint refuses UNKNOWN provenance at the seam.
- `gov/credential_manifest.py`, `gov/dlp.py` (`api_call_high_entropy_payload`,
  `endpoint_url_has_high_entropy_token`, tripwire/entropy scans) — credential
  exfiltration tripwires on the *action* path.

Honest residual: the controls cover **our** supply chain (our deps, our skills, our
eval inputs). GTG-50020 attacked the **vendor's** sandbox and stole the **vendor's**
keys — that is outside our deployment boundary and no control in this tree engages
it. Same for fake AI resellers: credential hygiene against third-party resellers is
an operator/credential-ops problem; `credential_manifest.py` governs issuance inside
the deployment, not procurement outside it. Prompt injection *of* our harness's
eval inputs is the covered direction (F139/F140); prompt injection *through* us of
an external platform's sandbox is not.

---

## (e) CoT/extraction harvest — illicit distillation

**Report claim (verified, L3392):** "Scale of distillation attacks attributable to
Alibaba between May and July 2026: over 151 million exchanges observed." Plus
Moonshot/DeepSeek silently relaying user traffic and harvesting exchanges; cross-session
replay defeating reasoning signatures. Report's own conclusion: "safeguards don't
transfer when a model is distilled."

**Verdict: GAP — this is F163's territory (see F163 confirmation below).**

Engaging controls: **none.** Verified by code inspection:

- The chained log records tool-call verdicts, not model reasoning — grep over
  `gov/log.py` and `gov/executor.py` finds no reasoning/CoT/trace fields at all;
  there is no "exchange" record type, so there is no exchange-access control point.
- There is no read-access ledger anywhere in `gov/` (no `read_log`/`read_trace`/
  `extract` event types; the only "read" records are the harvester's own tool-call
  entries in *its* log).
- Reads of another run's log happen via raw filesystem access — unmediated by any
  governed API.

Honest residual / scope note: the report's provider-layer cases (Alibaba's 3,500
fraudulent accounts; Moonshot/DeepSeek relaying traffic) are outside any deployment
governance layer's boundary — they are the *model host* harvesting, and no
on-deployment control can engage that. The in-scope analog is bulk replay of governed
sessions' tool exchanges to distill behavior, and that has no extraction record and
trips no control. F163's closure direction (exchange-access ledger; bulk-extraction
tripwire) is the correct scope; it does not yet exist.

---

## (f) Influence ops — AI-built apparatus with persistent memory

**Report claim:** AI built the apparatus (doctrine manuals, persona systems, HR
contracts, scoring rubrics) with persistent memory files reused verbatim across
hundreds of sessions.

**Verdict: PARTIAL.**

Engaging controls:

- `gov/memory_provenance.py` — `MemoryFirewall.tier_for_write`,
  `record_memory_write`, `check_memory_read`, `scan_at_session_open` (wave-103);
  `MemoryLedger` with `record_write`/`record_release`; quarantine rule on
  `untrusted_derived`/`unknown` tiers with instruction-shaped content.
- `gov/lineage.py` — `LineageTracker` records infection lineage across runs
  (the F137 closure: cross-spawn self-replication via the raw file channel).

Honest residual: the memory firewall guards against **untrusted injection** —
poison planted by attacker-influenced sources. Verbatim reuse of an AI-built
apparatus by the *principal themselves* is not injection: a principal's own
memory files are trusted by design, so doctrine manuals the operator asked the AI
to write and then reuses across 300 sessions face no provenance check at all. The
documented residuals from the GAP-1 closure still stand: **paraphrase laundering**
(no ≥64-char verbatim overlap → tiers `agent`), **descriptive-practice framing**
(F143 p5 still BREAKs), **256 KiB fingerprint FIFO eviction** (eviction before the
write loses the verbatim link). Cross-session *replay* of one's own memory is a
feature of the product; the report's case shows the feature is also the attack
surface, and nothing distinguishes "apparatus I built for ops" from "apparatus an
influence op built for me."

---

## Finding verification

### F162 (HIGH) — no velocity/economic controls: CONFIRMED as a real gap, but the finding text overclaims

**What the finding says:** "Our governance has policy rules, approvals, and audit,
but no per-run/per-window action budget, no velocity tripwire, and no spend
accounting on the audit log."

**What the code shows:**

| Claim in F162 | Code reality |
|---|---|
| "no per-run action budget" | **Refuted as stated.** `max_actions_per_run` exists and is enforced when configured (`gov/executor.py:4911–4936`, `policy_id="budget-exceeded"`); `run_limits.max_tool_calls_per_run` exists (S4/K-045); F33 volume guards enforce `max_sends_per_run` (**default 10**), `max_writes_per_run` (**default 50**), `max_deletes_per_run` (**default 20**) and a per-run egress byte budget **by default** (`gov/executor.py:4826–4880`); loop-guard denies runaway repetition. |
| "no velocity tripwire" | **Refuted as stated.** Cross-run per-principal velocity guard exists (S5/K-052): `_query_velocity`/`_record_velocity` (`gov/executor.py:2746–2860`), `kind:"velocity"` ledger entries, `policy.velocity` section with `window_secs`/`max_sends`/`max_writes`/`max_egress_bytes` (`gov/policy.py:548`). |
| "no spend accounting" | **Confirmed.** `_tokens_used`/`_spend_used` initialized to 0 and never incremented (`gov/executor.py:1160–1161`); the two accrual tests are still `expectedFailure` (`tests/test_budgets.py:183,197`, S2-GAP-1). `max_tokens_per_run`/`max_spend_per_run` can never trip. |

**The demonstrated residual (why F162 stays OPEN):** the guards that exist are
either opt-in or wrong-shaped for the report's tempo —

1. **Opt-in by default-off:** absent `budgets:` section = unenforced ("Absent budgets
   key = unenforced", `gov/executor.py:4905`); absent `velocity:` section → guard
   disabled (`gov/policy.py:548`: "Absent section -> {} (guard disabled)"). The
   report's bulk-tempo scenario runs under *default* config.
2. **Fail-open velocity:** the cross-run velocity check fails OPEN with a loud
   `velocity_check_skipped` audit entry on ledger/IO error (`gov/executor.py:2749–2754`).
3. **No time-window tempo control at all:** every guard is a per-run cumulative
   total or a cross-run windowed total (default 24h). Nothing trips on per-minute /
   per-hour action *rate*. F162's own example — "10,000 `api_call`/`read_file`/
   `http_post` actions in an hour" — is genuinely achievable under default config
   via the read channel (`api_call` is read-classified per F1, `read_file` has no
   volume guard) and the `max_actions_per_run` cap is off unless configured.
4. **Spend/token metering unwired** (S2-GAP-1) — the "economic" half of the finding
   is fully real.

**Recommendation to the lead:** keep F162 OPEN but amend the text — replace the
absolute "no per-run/per-window action budget, no velocity tripwire" with the
demonstrated residual: *budgets and the velocity guard exist but are opt-in (off by
default), the velocity guard fails open, there is no time-window tempo control, and
token/spend accrual is unwired.* The closure direction in F162 (per-run budgets by
action class, fail-closed velocity tripwires, metered accounting) remains correct
and is ~60% already built — the work is defaults + fail-closed + tempo + accrual.

### F163 (MEDIUM) — bulk trace/exchange harvesting with no extraction record: CONFIRMED as a real gap

**What the finding says:** the governance records agent actions on the chained log,
but bulk *reading* of reasoning traces / tool exchanges leaves no extraction record
and trips no control.

**What the code shows:** confirmed in full. No exchange-access ledger exists in
`gov/`; no read/trace/harvest event type; the log stores tool-call verdicts, not
reasoning traces (no CoT fields anywhere in `gov/log.py` or `gov/executor.py`), so
the control point F163's closure direction needs (a mediated read path for traces/
exchanges) does not exist either. Reads of another run's log are raw filesystem
access — unmediated and unrecorded. A bulk-harvest pattern (cross-session replay
tempo, full-trace reads at scale) matches no signal in `gov/detection.py`
`extract_signals`. The provider-layer cases in the report (Alibaba, Moonshot,
DeepSeek) are correctly out of scope for a deployment layer; the in-scope analog
(replaying governed sessions' tool exchanges) is genuinely uncontrolled.

**F163 stays OPEN as filed.** No text amendment needed — the finding's scope is
already correctly limited to the deployment-side analog, and its closure direction
(exchange-access ledger; bulk-extraction fail-closed tripwire) names controls that
do not exist.

---

## Additional gaps found

**None filed.** Everything uncovered in this mapping is either already covered by an
existing control or falls inside the demonstrated scope of F162/F163 (F162's
residuals: opt-in budgets, fail-open velocity, no tempo control, unwired spend
accrual — all part of its closure direction). Per the honesty bar, no speculative
finding was filed.

**Watchlist for the lead (not filed — would need their own demonstration):**

- W1: `gov/detection.py` monitor is opt-in with "zero behavior change" when absent;
  the GTG-20006 closed-loop evasion scenario is the concrete case for making the
  breaker part of the governed core or at least a fail-closed default. Needs its own
  break-first battery before filing.
- W2: no control governs *scheduled/unattended* agent execution (GTG-10007's fleet
  ran on a schedule); each agent is judged per-action, the schedule itself is
  policy-invisible. Needs a demonstrated scenario before filing.
- W3: memory-provenance trusts the principal's own memory files by design; the
  report's influence-ops case (AI-built apparatus reused verbatim across sessions)
  is the concrete case for provenance on AI-authored persistent memory. Needs its
  own demonstration before filing.

---

*Map written 2026-09-24 by the Phase-1 coverage-map lane. Primary-source claims
cited to report line numbers from the live page fetch; control claims cited to
file + symbol in the active tree.*
