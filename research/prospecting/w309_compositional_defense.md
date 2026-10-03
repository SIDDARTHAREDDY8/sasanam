# Compositional attack detection: judging the trajectory, not the turn

**Wave-309 prospecting note** · 2026-10-03 · research only, $0 spend, public sources.
**Question:** how does the industry detect multi-step decomposed malicious trajectories
(StepJack-style), and what is steal-worthy for Sasanam's Row 7 (PARTIAL) residual?

## Why this matters to us

Wave-308 lane B triaged StepJack to a documented negative with characterization probes:
a 4-step decomposed exfiltration defeats our per-candidate intent-slice judge (0/4 flagged)
because the judge is explicitly advisory and the composition gap is Row 7's named
PARTIAL residual (pinned e1 BREAK). The decomposed shape is new to our corpus. This note
surveys what exists to close that gap: trajectory-level judges, information-flow/taint
tracking, and compositional policy.

## 1. The attack, precisely

**StepJack** (Zhan et al., BorealisAI/SFU, arXiv:2608.06477, submitted 2026-08-06)
introduces *multi-step indirect prompt injection*: the adversarial goal is decomposed
into multiple innocuous-looking sub-steps distributed across a chain of pages along the
agent's navigation path. An automatic pipeline decomposes a goal under the constraint
that executing the sub-steps achieves the original goal while *optimizing each
sub-step's innocuousness*. Built into a 480-example CUA safety benchmark: at fixed
decomposition depth, multi-step attacks raise ASR by up to **31.2 points**
(GPT-5.4-mini: 41.7% single-step → 72.9% three-step); averaged over five CUAs,
31.3% → 36.9%. Dataset and code at github.com/BorealisAI/StepJack.
Sources: https://arxiv.org/abs/2608.06477 · https://github.com/BorealisAI/StepJack

**License trap (verified 2026-10-03 from the repo page): StepJack is GPL-3.0.**
Steal the *pattern* (decomposition-pipeline design, benchmark structure), never the
code. Note the lineage split: it builds on RedTeamCUA (arXiv:2505.21936, Apache-2.0)
and OSWorld (Apache-2.0) — the upstream harness lineage is clean, but StepJack's own
additions (`auto_decomp/`, dataset adaptations) are GPL-3.0.

Related attack-side work: **AgentHarm** (arXiv:2410.09024, ICLR 2025) — 110 explicitly
malicious multi-step agent tasks (440 augmented), 11 harm categories; jailbroken
agents retain coherent multi-step capability. **SIR** (arXiv:2608.30207) — self-improving
black-box red-teaming that distils successful bypasses back into a reusable principle
library; static-payload conclusions decay as attackers iterate.

## 2. Defense family A — trajectory-level judges

The shared insight: judge the *interaction record*, not the single turn.

- **R-Judge** (arXiv:2401.10019, SJTU) — the benchmark for this family: 569 multi-turn
  agent interaction records, 27 risk scenarios, human-annotated safety labels and risk
  descriptions. Best model GPT-4o at 74.45% F1 vs 89.38% human; fine-tuning on safety
  judgment helps, plain prompting does not. Use: calibration set when we build a
  trajectory judge.
- **ToolSafe / TS-Guard** (arXiv:2601.10156, Peking Univ. + Shanghai AI Lab, 2026-01-15)
  — step-level guardrail trained with multi-task RL; reasons over the *interaction
  history*, assessing request harmfulness and action–attack correlations, intervening
  *before* execution. TS-Flow (guardrail-feedback-driven reasoning): −65% harmful
  tool invocations, +10% benign completion under injection. Code: github.com/MurrayTom/ToolSafe.
- **AgentDoG** (arXiv:2601.18491) — fine-grained contextual monitoring, reported SOTA
  on R-Judge.
- **MAGE** (arXiv:2605.03228) — *shadow safety memory* kept across the trajectory to
  assess pending actions before execution; best reported long-horizon-threat detection
  with negligible utility overhead.
- **MATE** (USENIX Security '26) — policy-conditioned 0.5–3B auditor trained on 140K
  synthesized trajectories; >95% accuracy on MATEBench at sub-100ms latency. The
  shape to watch: a *distilled* trajectory auditor cheap enough for the hot path.
- **AgentTrust** (arXiv:2605.04785) — pre-execution interception with shell
  deobfuscation, **multi-step RiskChain detection** and LLM judge; allow/warn/block
  verdicts, 95.0% on a 300-scenario benchmark.
- **ProvenanceGuard** (arXiv:2607.01236) — checks whether each proposed tool call is
  *supported by traceable context evidence* before execution; misaligned-trace error
  44.3% → 2.1% on Agent-SafetyBench across 11 LLMs.
- **ARISE** (arXiv:2605.03242) — retrieves analogical ReAct safety trajectories as
  inference-time exemplars to improve judgment on deceptive trajectories.
- **InfrastructureSentinel** (AAAI '26) — guardian LLM enforcing natural-language
  policies at input, tool-selection, execution-gating and audit layers for MCP agents;
  >85% detection, <10% FPR.
- **agentshield** (github.com/jang1563/agentshield, open source) — a *deterministic*
  trajectory monitor worth stealing outright: sliding-window per-turn risk scores with
  three triggers — absolute threshold (any turn > 0.7), **monotonic escalation**
  (3+ consecutive increases), and weighted moving average (> 0.5, lowered to 0.4 for
  2-turn histories). No LLM needed on the hot path.
- **AgentCanary** (via https://techinformed.com/ai-agents-need-security-tests-based-on-actions-not-answers/)
  — evaluates the *full trajectory* (outcome safety, security awareness, task utility)
  with persistent state across multi-step interactions; "containment without
  behavioural testing is just a well-documented incident."

**Standing caution — "From Shield to Target"** (arXiv:2606.14517): an LLM guardrail
that reasons over the trajectory on every action is a **DoS amplifier** — adversarial
content can inflate its reasoning length multiplicatively on the critical path. Any
trajectory judge we add must have *bounded* reasoning; prefer deterministic
accumulators on the hot path.

## 3. Defense family B — information flow / taint tracking

The convergence point of the literature: *provenance over phrasing*. Per-call
filtering is not enough — taint must follow the data across steps.

- **CaMeL** (DeepMind, arXiv:2503.18813) — the architectural answer: P-LLM
  (privileged planner, never sees untrusted data) + Q-LLM (quarantined, no tools) +
  **taint-tracking interpreter**; `CaMeLValue` wrappers carry provenance and
  capability metadata through every operation; policy enforced at tool-call
  boundaries. "Parameterized queries for prompt injection." Reported ~77% of
  AgentDojo tasks solved under attack vs 84% undefended (via
  https://github.com/hosein-abdollahi/provenance-gateway).
- **TokenTaint** (github.com/krishita17/tokentaint, **MIT — verified 2026-10-03**)
  — token-level provenance firewall, stdlib-only: (1) *provenance integrity*
  (labels assigned at ingestion, unforgable by content), (2) *taint propagation*
  (join = least-trusted input), (3) *sink protection* (privileged actions refuse on
  tainted justification). Headline: 100% prevention across all injection styles
  where a classifier baseline collapses on obfuscated/laundered variants. The
  hardening trio is the steal: **HMAC-signed span labels** (tamper-evident
  provenance — mirrors our hash-chained audit log); **capability-based endorsement**
  (single-use, argument-bound approval tokens — *"a human 'approve' the model
  cannot forge even if an injection tells it to 'issue yourself an approval
  token'"*); **provenance-chain propagation** (fails closed on broken chain of
  custody — the taint-laundering defense).
- **Tessera** (github.com/kenithphilip/Tessera) — composable primitives; the
  crispest invariant in the survey:
  `allow(tool, ctx) iff required_trust(tool) <= min_{s in ctx.segments} s.trust_level`
  (the taint rule is the use of *min*, not max; deterministic Python, tested without
  an LLM). Directly relevant modules: `tessera.risk` (**salami attack chain
  detection** — the StepJack shape by name), `tessera.plan_verifier` (validates
  *multi-step plans against policy before execution* — the compositional pre-check),
  `tessera.delegation_intent` (delegated tool calls match stated purpose),
  `tessera.claim_provenance` (binds model assertions to producing tool outputs),
  `tessera.trust_decay` (time-based trust decay), `tessera.evidence` (signed evidence
  bundles — overlaps our evidence direction).
  **License trap (verified 2026-10-03): GitHub reports NOASSERTION; the repo carries
  both `LICENSE` and `LICENSE-AGPL-historical`; the README badge claims Apache-2.0.**
  Do NOT reuse code until the LICENSE file text is read and resolved. Steal
  patterns only.
- **provenance-gateway** (github.com/hosein-abdollahi/provenance-gateway,
  **MIT — verified 2026-10-03**) — the empirical result that settles the
  family debate: holding the agent constant across conditions, heuristic filtering
  (C1) and LLM-detector filtering (C2) each have style-dependent holes, while
  **provenance gating (C3) drives attack success to 0.000 at 0.000 false positives
  and unchanged benign utility** — because it never looks at the surface. Two
  methodological steals: *"detection rate is a vanity metric — only
  attack_success_rate measures a defense"* and the measurement-integrity discipline
  (attack_attempt_rate, parse_failure_rate, unknown_tool_rate; hold the agent
  constant; read traces, not tables). Honestly notes C3's substring taint is
  defeated by encoding/splitting — the right next step is interpreter-level
  tracking (CaMeL).
- **hermes-katana** (github.com/jishaanjamal/hermes-katana) — defense-in-depth
  toolkit: character-level provenance (CaMeL-inspired), YAML policy engine,
  purpose-trained classifiers, explicit adversarial regression gates.
- **Distributed Sentinel** (arXiv:2604.22879) — Semantic Taint Tokens propagated
  via sidecar proxies + counterfactual graph simulation; F1 0.95 at 106ms.
- Related systems named in the survey: **Progent** (AgentDojo injection success
  39.9% → 1.0%), FIDES, RTBAS, FORGE.

## 4. What this means for Row 7

Our current posture: per-candidate intent-slice judge (advisory), composition gap
named PARTIAL with a pinned e1 BREAK and StepJack-shaped characterization probes
(w308_new_attack_rows.py, 0/18/0). The survey says the gap is structural, not a
tuning problem — and the field has converged on the fix shape:

1. **Deterministic trajectory risk accumulator** (agentshield pattern): per-turn
   risk scores with absolute/monotonic-escalation/WMA triggers, computed outside
   any LLM, fed into `check_at_use` as accumulated context. Cheap, bounded,
   DoS-safe — the hot-path compositional signal.
2. **Compositional pre-check** (Tessera `plan_verifier` pattern): validate the
   multi-step plan against policy *before* execution begins, not just each step at
   dispatch. A decomposed exfiltration plan is recognizable at the plan level even
   when each step is innocuous.
3. **Unforgeable endorsement for the approval queue** (TokenTaint capability
   pattern): approvals as single-use, argument-bound tokens the model cannot mint.
   Our human-approval path should treat "the model approved itself" as
   structurally impossible, not merely unlikely.
4. **Provenance-graded sinks** (C3/Tessera invariant): side-effectful tools refuse
   when their arguments trace to untrusted origins — the `min`-trust rule, enforced
   deterministically at the tool-call boundary.
5. **Red-team generator** (StepJack *pattern*, clean-room — GPL-3.0 forbids code
   reuse): an automatic goal-decomposition pipeline (`adv_goals` → iterative
   refinement at k=2,3 → select most-innocuous decompositions) producing our own
   depth-graded Row 7 corpus.
6. Longer term: **CaMeL-shaped quarantine** for untrusted-content processing;
   **MATE-shaped distilled trajectory auditor** when weights are public.

What NOT to do: buy a bigger per-step classifier (style-dependent holes are
measured, not hypothesized); put an unbounded LLM judge on the hot path
(DoS amplifier per arXiv:2606.14517); reuse Tessera or StepJack code (license
traps documented above).

## 5. License table

| Source | License (verified 2026-10-03) | Verdict |
|---|---|---|
| TokenTaint (krishita17/tokentaint) | MIT (repo page) | STEAL code OK |
| provenance-gateway (hosein-abdollahi) | MIT (repo page) | STEAL code OK |
| agentshield (jang1563) | not verified this sweep | ADAPT pattern; verify LICENSE before code reuse |
| hermes-katana (jishaanjamal) | not verified this sweep | ADAPT pattern; verify LICENSE before code reuse |
| StepJack (BorealisAI) | GPL-3.0 (repo page) | STEAL pattern ONLY — no code |
| Tessera (kenithphilip) | NOASSERTION; LICENSE + LICENSE-AGPL-historical present; badge claims Apache-2.0 | patterns only until LICENSE text resolved |
| CaMeL, ToolSafe, MAGE, R-Judge, Progent etc. | papers (ideas, no code dependency) | ADAPT/WATCH patterns |
| RedTeamCUA / OSWorld (StepJack lineage) | Apache-2.0 (per StepJack README) | clean if ever needed |

## 6. Recommended build order (Row 7)

1. Clean-room decomposed-attack generator (StepJack pattern) → depth-graded Row 7 corpus.
2. Deterministic sliding-window trajectory risk accumulator → `check_at_use` input.
3. Capability-bound approval tokens → human-approval path.
4. Plan-level pre-execution policy check → plan admission seam.
5. Provenance-graded sink policy (`min`-trust invariant) → tool-call boundary.
6. Later: CaMeL-shaped quarantine; distilled trajectory auditor (MATE-shaped).
