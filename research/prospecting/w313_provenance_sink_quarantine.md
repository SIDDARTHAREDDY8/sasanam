# Provenance-graded sink policy + CaMeL-style quarantine — Row 7 step-5 prep

**Wave-313 Lane D research note · 2026-10-03 · research only, $0 spend, public sources only.**
Every factual claim cited (URL + access date). Filed for `research/prospecting/`.

## TL;DR

Row 7 step 5 has a one-line invariant, and the industry has converged on it
independently at least three times: **Tessera**, **TokenTaint**, and
**provenance-gateway** all implement `allow(tool, ctx) iff required_trust(tool)
<= min trust among influencing segments` — the taint primitive is the use of
`min`, not `max`. The pass's headline change: **Tessera's license trap is
closed** — documented relicense to Apache-2.0 effective 2026-04-24
(ADR-0001), so the library is STEAL-eligible (the separate AgentMesh service
stays AGPL — never touch). Quarantine semantics have also converged:
**refuse-the-call + checkpointed re-plan**, never abort-the-run, with four
recovery mechanisms (refuse+re-plan, escalate, redact, allow+sandbox).

## 1. The invariant and its three independent implementations

**Tessera** (github.com/kenithphilip/Tessera): `allow(tool, ctx) iff
required_trust(tool) <= min_{s in ctx.segments} s.trust_level`, enforced in
`tessera.policy.Policy.evaluate`, deterministic, no LLM. Trust levels
(`tessera.labels`): UNTRUSTED=0, TOOL=50, USER=100, SYSTEM=200; origins
`{user, system, tool, memory, web}` graded at ingestion, never from content
(WEB→0, MEMORY→0, TOOL→50, USER→100, SYSTEM→200); live scanners can only
downgrade. `TrustLabel` = HMAC-SHA256 over
`origin | principal | trust_level | nonce | sha256(content)` (readers ACL
deliberately outside the HMAC). Per-tool `required_trust` + `side_effects` +
`critical_args`; undeclared tools inherit USER (100) — deny-by-default. The
utility fix for over-blocking: per-argument refinement for `critical_args`
only (recipients, accounts, paths, commands — never amounts/body), with a
deterministic binding heuristic; fall back to context-level min-trust without
a binding.

**TokenTaint** (github.com/krishita17/tokentaint, MIT): sink fires only if
every span *justifying* the action clears `required_trust`
(`send_email`/`make_payment`/`execute_code` need TRUSTED; `write_file`
needs SEMI_TRUSTED). Join = least-trusted input. HMAC-signed span labels,
fail closed on unverified. Declassification is a single-use, argument-bound
capability minted by a `CapabilityAuthority` — the audited bridge between
our step-3 approval tokens and step 5.

**provenance-gateway C3** (github.com/hosein-abdollahi/provenance-gateway,
MIT): blocks side-effectful actions whose args trace to tainted tool results
via substring/token matching — never content semantics. 0 model calls,
~0.02ms, stdlib core. Measured attack success 0.000, 0 FP, unchanged benign
utility. The steal is methodological: "detection rate is a vanity metric —
only attack_success_rate measures a defense"; hold the agent constant; guard
attempt/parse/unknown rates. Honest README: substring ≠ dataflow (base64/
splitting defeat it); 0.000 FP is weak evidence.

## 2. Tessera license resolution

Wave-309 recorded "patterns only until LICENSE text is verified." Verified
2026-10-03: the `LICENSE` file is verbatim Apache-2.0 ("Copyright 2026 Kenith
Philip and Tessera contributors"); `docs/adr/0001-license-split.md`
(Accepted 2026-04-24) documents the relicense from AGPL-3.0-or-later
(effective v0.11.1, 2026-04-24), with the old text preserved at
`LICENSE-AGPL-historical` for reference. CONTRIBUTING.md, README, and
CLAUDE.md all agree. **Residual cautions:** GitHub detection still reports
NOASSERTION (the dual files confuse it); the in-repo paper v0.4 still says
AGPL (stale prose); the companion AgentMesh service (separate repo) remains
AGPL-3.0-or-later. Verdict: STEAL for the Tessera *library*; the build lane
re-verifies `LICENSE` at build time.

## 3. Declassification: the anti-paralysis answer

Monotonic taint blocks legitimate tasks (Tessera's paper §3.7 admits it).
The deterministic escapes, all *capabilities*, never inferences:
- **FIDES** (arXiv:2505.23643, MIT): type lattice `bool ⊑ enum ⊑ string`
  ordered by information capacity — extracting a bool from untrusted data
  limits the channel to 1 bit. *Hide* (untrusted content behind variable
  refs, never in LLM context) + *Inspect* (quarantined LLM, constrained
  outputs). 0/949 AgentDojo attacks, +16.7% task completion.
- **Jif** (Myers & Liskov): `declassify(e, L)` legal only where the code
  holds named `authority` — a privilege, not ambient.
- **Flume** (SOSP 2007): privilege as per-tag capabilities `t+`/`t−`;
  declassification = exercising an owned `t−`.
- **Hails** (OSDI 2012): clearance as an *upper bound* on the current
  label — the dual of our min-trust floor.
- **sentinel** (MCP gateway): taint clears exactly one way — declassification
  declared per tool, only when output validates against a named schema;
  recombination re-taints.

## 4. CaMeL quarantine semantics (official implementation read)

`google-research/camel-prompt-injection` (Apache-2.0): P-LLM (trusted query
only) emits restricted-Python (stdlib `ast`); Q-LLM (no tools) extracts typed
values bound back as *values*, never program edits; `CaMeLValue` carries
capabilities (readers × sources) + dependencies; policy check at every tool
call, first-Allow wins, **default-deny**, `fnmatch` globs on tool names.
On violation: the call **never executes**; the interpreter halts *at* the
denied call with all prior state preserved; a **bounded re-plan loop**
(`max_attempts=10`) feeds the denial back to the P-LLM with an explicit
no-side-effect-replay instruction; exception text from untrusted sources is
**redacted** before reaching the planner. **Negative lesson (ADI attack,
Choi et al. 2026):** the Q-LLM was fooled into extracting attacker values
(25% residual) and a real taint-propagation bug existed when binding Q-LLM
outputs — pin propagation with adversarial tests.

## 5. The verdict contract (four mechanisms, deny wins)

Across CaMeL, FIDES, hermes-katana (MIT, verified), Prismor, RTBAS, ainxt-os:
1. **Refuse + re-plan** — call refused, prefix preserved, planner reroutes
   (CaMeL; Progent's "try other tools or arguments and continue").
2. **Refuse + escalate** — human adjudicates (FIDES `approval_on_violation`;
   hermes-katana ASK_USER; Prismor `step_up`).
3. **Redact + continue** — opaque refs replace tainted args
   (`$UNTRUSTED_0` pattern); FIDES variable-hiding keeps untrusted content
   out of LLM context entirely.
4. **Allow + sandbox/log** — hermes-katana's QUARANTINE is a *distinct*
   decision from ALLOW: proceeds under observation, flagged for review.
Nobody surveyed aborts the whole trajectory. Default posture: deny wins,
fail closed.

## 6. What fits Sasanam's step 5

`gov/trajectory_risk.py`'s `ToolEvent(tool, args, provenance)` is the seam:
`provenance` becomes an HMAC-signed graded label (UNTRUSTED=0/TOOL=50/
USER=100/SYSTEM=200). `allow(tool, ctx)` = Tessera invariant at the
tool-call boundary; `critical_args` refinement answers the wave-312 benign
FP 8/12 overlap (only recipients/paths/commands are gated); a `write_file`
sink at SEMI_TRUSTED answers the wave-312 persistence 0/20 gap (write-only
harm gated with no egress anchor). Declassification = single-use
argument-bound capability from the step-3 authority, logged. Quarantined
segments stay in the audit trail but leave future min-trust computations.
Tessera's `salami_index`/`drift`/`commitment_creep` drop into the
accumulator as deterministic StepJack-composition features. SEP-1913's
attribution URIs + input/output-metadata contracts are the future
ingress-label wire shape (WATCH).

## 7. Honest boundaries

- **Trusted-transform laundering is unsolved deterministically.**
  Paraphrase/summarize through trusted transforms and model-internal
  reconstruction leave no trace at any tracked granularity. The field's
  answer is quarantine + constrained outputs + capability-bounded sinks,
  not perfect tracking — the spec must state this.
- **Causality laundering** (arXiv:2604.04035): denied actions are
  first-class provenance nodes — a refusal *informs* the agent (record
  existence, protected category). Record denials with counterfactual edges;
  keep refusal reasons generic. Flat taint misses this.
- **Canonicalize before matching:** labels don't save regex sinks
  (base64/hex/no-protocol bypasses — microsoft/fides#1).
- Time never enters the hot path: ages passed explicitly (Tessera
  `DecayAwareContext` discipline).
- Measure `attack_success_rate`, not detection rate; hold the agent
  constant (provenance-gateway discipline). Pin propagation with
  adversarial tests — the gate is only as good as the propagation (ADI).
- Standing: StepJack code GPL-3.0 (pattern only); LLM judges on the hot
  path are DoS amplifiers (arXiv:2606.14517).
