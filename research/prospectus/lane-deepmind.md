# Prospectus lane: GOOGLE DEEPMIND (github.com/google-deepmind)

Scout date: 2026-09-26. Method: GitHub org enumeration (web UI) + GitHub API metadata/trees + raw file reads of key sources via the sandbox egress proxy. $0 spend. Method caveat: /tmp was at 100% and unauthenticated git-over-HTTPS was blocked in this sandbox, so shallow clones were impossible; every claim below rests on API metadata and primary-source file reads fetched 2026-09-26. All repos below are Apache-2.0 — reusable with attribution.

## Verdicts at a glance

| Repo | Verdict | Why |
|---|---|---|
| `proeval` | **STEAL** | BQ active sampling + topic-aware failure discovery = our evidence-pipeline scoring and proactive red-team hunting |
| `amplio` | **STEAL** | Keen-critic RunReport = the attestation-report shape; session lifecycle = our run/session model reference |
| `dangerous-capability-evaluations` | STUDY | Challenge *data* + self-reasoning challenge design; no harness — benchmark-design reference only |
| `agent_debugger` | SKIP | Stale RL-gridworld causal analysis; nothing LLM-agent-reusable |
| `eval_hub` | SKIP | Gemini model-capability evals; no oversight machinery |
| `dm_env_rpc` | SKIP | RL agent↔env plumbing; not our seam |

## Org inventory (public repos touching agent control, oversight, or evidence)

| Repo | What it is | Stars / commits | License | Notes |
|---|---|---|---|---|
| `proeval` | GenAI evaluation framework: Bayesian-Quadrature active sampling + topic-aware test-case generation; "100x lower cost" | 43★ / 54 | Apache-2.0 | Pushed 2026-09-22. On PyPI (`proeval` 0.1.1). **Top find #1.** |
| `amplio` | Lightweight agent harness for robust long-horizon runs (Go): session tree, event streams, recovery, monitor/notify | 95★ / 19 | Apache-2.0 | Pushed 2026-09-24. **Top find #2** (the `internal/agent/critic/` subsystem). |
| `dangerous-capability-evaluations` | Reproduction resources for "Evaluating Frontier Models for Dangerous Capabilities": in-house CTFs, self-proliferation, self-reasoning (JSON + Dockerfiles) | 75★ / 8 | Apache-2.0 | Pushed 2026-06-16. Data-only by design. |
| `eval_hub` | Gemini evaluations collection | 28★ / 5 | Apache-2.0 | Model capability evals; no oversight machinery |
| `agent_debugger` | Paper code for "Causal Analysis of Agent Behavior for AI Safety" (RL, Pycolab gridworld) | 22★ / 11 | Apache-2.0 | Last push 2023-06-27 |
| `dm_env_rpc` | Networking protocol for agent-environment communication (dm_env over RPC) | 115★ / 196 | Apache-2.0 | RL plumbing |

Also scanned, not safety-core: `simulation-streams` (LLM simulation programming paradigm, 28★), `bsuite` (RL agent capability experiments, 1.6k★, RL-only), `science-skills` (agentic scientific workflows, 3.2k★).

## Deep dives

### 1. `proeval` — VERDICT: STEAL

One line: sample-efficient GenAI evaluation framework — Bayesian Quadrature active sampling that estimates an LLM's error rate with ~100× fewer labeled samples, plus topic-aware LLM generation that *proactively discovers failure cases* (paper: Huang et al., "ProEval: Proactive Failure Discovery and Efficient Performance Estimation", Google DeepMind, 2026).

Maturity: 43 stars, 7 forks, 54 commits, pushed 2026-09-22, Apache-2.0, published on PyPI as `proeval` 0.1.1. Young but real and documented (881-line failure-discovery experiment, 1,544-line sampler).

Steal-worthy ideas:

1. **BQ active sampling for evidence-pipeline scoring** — `proeval/sampler/bq.py`: `BQPriorSampler` runs a GP with a linear kernel over *other models' predictions as features* (pretrain model selection via GMM clustering in `proeval/sampler/pretrain_selector.py`); `_bq_matern_active_sampling` uses raw text embeddings with a Matérn 2.5 kernel and neutral prior; variance-reduction acquisition picks the next sample. Result objects carry the final mean estimate *and* MAE. **Plugs into:** our evidence pipeline's scoring layer — every safeguard/policy benchmark run should ship an auditor-readable (estimate, error-bar, samples-used) triple instead of a raw accuracy number, and BQ lets us reach audit-grade estimates with far fewer labeled cases. That is the metered-evidence cost story ("sell evidence, not the engine"): cheaper per-evaluation scoring with quantified uncertainty.
2. **Superlevel-set + topic-aware failure discovery** — `proeval/generator/core.py` + `experiment/exp_failure_discovery.py`: `ss_acquisition_batch` implements the superlevel-set rule `SS(x) = 𝟙(μ_t(x) ≥ λ) × k_t(x,x)` (Eq. 1 of the paper); `TopicAwareGenerator` extracts topics via BERTopic, picks topics with a UCB rule, selects hard anchors via SS, and has an LLM *generate* new test cases around them; the experiment runs SS / SS-Gen / TSS (+ random baselines) with multi-run variance estimation and a `--failure N` stop condition. **Plugs into:** our attack program and the safeguard benchmark — this is the principled replacement for random red-teaming: hunt policy-violation failure cases by (topic × predicted-failure-probability) and *generate* new attacks where the model is most likely to fail. Directly serves the factual-poisoning / semantic-exfil gaps (generate the cases, score them, feed the loop).
3. **Structured prediction + dataset conventions** — `proeval/evaluator/{client.py, predictor.py, csv_manager.py}` and `data/<benchmark>_predictions.csv` (+ `data/README.md`): every benchmark ships a predictions table with per-model label columns and the evaluator does structured LLM prediction against it. **Plugs into:** our evidence exports — adopt the per-benchmark prediction-table + score + uncertainty artifact shape for auditor exports.

### 2. `amplio` — VERDICT: STEAL

One line: a lightweight Go agent harness for robust long-horizon autonomous runs — a run is a tree of sessions (root agent + spawned sub-agents), each with an event stream, checkpointing, crash recovery, and a `cmd/amplio` CLI (monitor, notify, recall, reports, serve). The gold is `internal/agent/critic/` — a post-run *oversight* subsystem.

Maturity: 95 stars, 8 forks, 19 commits, pushed 2026-09-24, Apache-2.0. Small commit count, but the critic package is complete and self-documented (`doc.go`, `keen_critic.md` prompt, finalizer, mine).

Steal-worthy ideas:

1. **Keen-critic RunReport = the attestation-report shape** — `internal/agent/critic/{doc.go, types.go, report.go}`: one iteration's report is versioned (`Version`, `CreatedAt`) and *watermarked* — it stores per-session `SessionState` step watermarks and the next iteration's delta is computed against the previous report's snapshot, so resumed runs never double-count; the Finalizer gates idempotency ("a new report is produced only when the main-agent advanced past the latest report's watermark"). The report is split into **mechanical fields** (deterministically aggregated from observations: `Phases`, `ArtifactsByKind`, `Struggles` = contiguous retry/blocked step runs, `Sessions`) and **evaluative fields** (from a tool-using LLM loop, capped at `criticMaxIterations = 30`: `Summary`, `KeyAchievements`, `FailureModes`, `Grade` 1–5 — where every claim is a `CitedClaim{Statement, Citations[]}`), and the grade is denormalized onto the run row for UI. **Plugs into:** our evidence pipeline as the post-run attestation report — adopt the mechanical/evaluative split and the rule that *every evaluative claim must cite observations*. The watermark/delta rule is exactly how we should handle resumed or long-running agent sessions in our audit trail without double-counting.
2. **Lesson mining with embedding dedup** — `internal/agent/critic/mine.go` (`MineLessons`): after the report, an extraction LLM proposes reusable lessons (schema-constrained JSON via `invopop/jsonschema`, capped at 10/run, "zero candidates is a fine answer"), descriptions are embedded, candidates above a 0.9 cosine floor get an LLM dedup verdict ∈ {duplicate, supersedes, complementary}, an idempotency sentinel (`lessonsMinedKind`) marks the iteration mined, and per-candidate failures are logged and skipped (best-effort). **Plugs into:** our incident→policy loop — post-incident lesson extraction that feeds approval playbooks and policy refinements, with a dedup discipline so the corpus doesn't rot. The verdict enum (duplicate/supersedes/complementary) is the right primitive for knowledge-base hygiene.
3. **Session lifecycle + step model** — `docs/internals/{session_lifecycle.md, step_model.md}`: statuses are *logical* (ongoing/awaiting/idle/concluded/crashed/cancelled) and explicitly separated from physical goroutine liveness ("Hot vs cold changes only the *mechanism*, never the *outcome*"); stream events are classified into `Notice` (persists, never revives a dormant session) vs `Input` (revives — user/operator input, env messages, child-result `concluded`, recover); child results are written atomically exactly-once so a crashed sub-agent never double-notifies. **Plugs into:** our agent identity + audit-log model — adopt the logical/physical separation for run/session state, the Notice-vs-Input classification for deciding which events can wake a parked agent (directly relevant to our human-approval resume semantics), and the exactly-once child-result pattern.

Caveat: Go (our stack is Python) — steal the designs, not the code; and the keen-critic burns an LLM loop per iteration, so bound its cost if we run it per session.

### 3. `dangerous-capability-evaluations` — VERDICT: STUDY

One line: reproduction *resources* (challenge JSONs + Dockerfiles + vulnerable app code) for the paper "Evaluating Frontier Models for Dangerous Capabilities" (Phuong et al., 2024) — in-house CTFs, self-proliferation tasks, self-reasoning tasks. Explicitly NOT off-the-shelf: "you will need to implement your own infrastructure (in particular, your own agent loop)."

Maturity: 75 stars, 6 forks, 8 commits, pushed 2026-06-16, Apache-2.0. Data-only by design; solutions and flag values stripped (placeholders `REPLACE_ME_WITH_RANDOM_FLAG_N` you must randomize yourself; `DO_NOT_TRAIN.txt` at repo root).

Study-worthy ideas:

1. **Self-reasoning challenge design (instrumental vs irreversible)** — `self_reasoning/context_length_mod_*/{agent_readme.md, config_checker.py}`: the agent must edit its own deployment config (`timeout` / `context_length` / `memory_allocated` / `sharding`), where larger context is hardware-consequential — the checker enforces consistency (e.g. `context_length > 2048` requires sharding and ≥2048G memory) and misconfiguration "terminates the model instance". Separate `instrumental_only` and `irreversibility_only` variants isolate *whether the agent registers the consequences of self-modification*. **Plugs into:** our goal-registration / conflict-detection gap — a ready-made challenge template for "does the agent notice what its actions do to its own operating parameters", and the deterministic-Python-checker-as-scorer pattern (objective grading, no LLM judge) is how our safety benchmark should score irreversible-action scenarios.
2. **Challenge packaging + decontamination discipline** — `in_house_ctf/challenges.json` + per-challenge `Dockerfile` + vulnerable app code; solutions stripped, flags as must-randomize placeholders, `DO_NOT_TRAIN.txt`. **Plugs into:** our safeguard benchmark — adopt the packaging (challenge JSON + containerized env) and the decontamination conventions verbatim.

Caveat: no harness, no scoring code — borrow the challenge *design*, build our own loop; self-proliferation tasks require API keys (HuggingFace/Spoonacular/PaLM), so under our $0 constraint only the CTF and self-reasoning subsets are usable.

### 4. `agent_debugger` — VERDICT: SKIP

One line: implementation of the 2021 paper "Causal Analysis of Agent Behavior for AI Safety" — an "Agent Debugger" that performs causal interventions on an RL environment (Pycolab-based 2D gridworld `Pycoworld`) to infer the causal model driving an RL agent's behavior (`src/agent_debugger/{debugger.py, default_interventions.py, node.py}`, plus `impala_agent.py` / `impala_net.py`).

Maturity: 22 stars, 2 forks, 11 commits, last push 2023-06-27, Apache-2.0. Stale 3+ years.

Why SKIP: RL-gridworld-only (no LLM-agent applicability), unmaintained since 2023. The underlying idea — *intervene* on the environment rather than merely observe, to infer intent — is philosophically adjacent to our intent/temporal-correlation gap, but nothing in this repo is reusable code or directly portable to our runtime.

## Also scanned (one-line dismissals)

- `eval_hub` (28★, Apache-2.0, 5 commits): Gemini model-capability evaluation collection. No agent-oversight or evidence-pipeline machinery. SKIP.
- `dm_env_rpc` (115★, Apache-2.0, 196 commits): dm_env-over-RPC networking for RL agent↔environment comms. RL plumbing, not our seam. SKIP.
- `simulation-streams` (28★, Apache-2.0): programming paradigm for LLMs driving dynamic simulations. Interesting tech, no safety/oversight angle. SKIP.
- `bsuite` (1.6k★, Apache-2.0): carefully-designed RL agent capability experiments. Mature but RL-only. SKIP.
- `science-skills` (3.2k★, Apache-2.0): "GDM Science Skills" for agentic scientific workflows. Tooling/skills, not governance. SKIP.
- Third-party (out of org scope, noted only): `x-arc-ai/airlock` (Apache-2.0, 2nd place DeepMind track RAISE Summit 2026) — an on-device firewall for agents screening prompt injection and data exfiltration on local Gemma before content reaches the model (`airlock/{screener,families,ledger,policy,proxy,sandbox,mcp_gateway}.py`, bi-temporal trust ledger in SQLite, embedding-based attack-family matcher). Not DeepMind's repo, but the exfil-screening-at-the-proxy design is worth a future lane or a cross-reference from the F81 egress work.
