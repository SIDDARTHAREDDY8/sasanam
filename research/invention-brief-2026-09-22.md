# Invention Brief — 2026-09-22

**Thesis (founder's):** everything in AI was built by inventing new things from old things — transformers from attention × sequence models, RLHF from RL × human preferences, diffusion from thermodynamics × score matching. This brief does the same for agent governance: mine old ideas (10–50 years, never applied to LLM agents), recombine them into new primitives, and spec what we'd build.

**Method:** $0, public sources only, everything cited. Prior-art checks are honest — where someone already did it, the brief says so and kills or narrows the idea. No marketing claims, no victory language. Grades are blunt.

**Board state this brief targets:** B1 14/16 full (P13 partial-by-design, P8 uncovered-by-design — the two holes); F81 (LOW, accepted) is the **only open finding**; F70/F72/F110 closed. Inventions aim at F81, P8, and the injection-during-execution class. They must strengthen the evidence-as-a-service bet (`research/founder-strategy-2026-09-22.md`), not fork it.

---

## 1. The mine — old ideas surveyed

| # | Old idea | Vintage | Source | Why it's interesting for agents |
|---|----------|---------|--------|---------------------------------|
| 1 | Sterile cockpit rule (no non-essential activity during critical flight phases) | 1981, FAA 14 CFR §121.542 | [aviatize.com](https://www.aviatize.com/glossary/sterile-cockpit), [Wikipedia](https://en.wikipedia.org/wiki/Sterile_flight_deck_rule), [FAA Safety](https://www.faasafety.gov/files/events/GL/GL05/2008/GL0520920/The_Sterile_Cockpit.pdf) | Governs *when* attention may be spent, not *what* is said — a temporal discipline, not a content filter |
| 2 | Circuit breaker pattern (fail-fast on cascading failure) | Formalized by Michael Nygard, *Release It!* (2007); market-wide breakers post-1987 (NYSE Rule 80B) | Cited via [dev.to/zeroshotstudio](https://dev.to/zeroshotstudio/the-circuit-breaker-pattern-why-deterministic-code-hooks-beat-agent-self-correction-in-production-4m5b) | Stateful open/half-open/closed machine with human reset — a *response* primitive, not just a detector score |
| 3 | Statistical process control (Shewhart control charts) | 1920s–1931 | General knowledge (Shewhart, *Economic Control of Quality of Manufactured Product*, 1931) | Breach = process out of control → stop the line. The industrial ancestor of "trip on drift" |
| 4 | Honeypots / honeytokens / canary credentials | Stoll, *The Cuckoo's Egg* (1986); Thinkst Canary (2015) | General knowledge; mechanism described in [reportedip/honeypot-server](https://github.com/reportedip/honeypot-server/blob/HEAD/README.md) ("near-zero false positives… severity 100") | Touching the fake thing *is* the signal — detection without needing a correct allowlist |
| 5 | Linked timestamping (hash-chained time proofs) | Haber & Stornetta, "How to Time-Stamp a Digital Document," *Journal of Cryptology* (1991) | [history-blockchain docs](https://github.com/armanpayandeh/history-blockchain/blob/HEAD/docs/1991/index.md); [Wikitia](https://Wikitia.com/wiki/W._Scott_Stornetta) | The original blockchain — invented to prove *when a document existed*, cited 3× in the Bitcoin whitepaper; Surety printed hashes in the NYT weekly since 1995 |
| 6 | Trusted timestamping (RFC 3161 TSA) | RFC 3161 (2001) | [Sigstore timestamp-authority](https://github.com/sigstore/timestamp-authority/blob/HEAD/README.md); [dev.to explainer](https://dev.to/gentlyding/trusted-timestamps-rfc-3161-how-to-anchor-a-hash-chain-so-no-one-can-rewrite-the-past-8ce) | Third-party vouching: "this hash existed at this time" — the TSA never sees content |
| 7 | Certificate Transparency (append-only log + witnesses) | RFC 6962 (2013) | [Sigstore rekor-spec](https://github.com/sigstore/architecture-docs/blob/HEAD/rekor-spec.md) | Transparency systems are *witnesses*, "antithetical to trust the contents of the log" — verifiable without trusting the operator |
| 8 | Capability-based security (unforgeable tokens, no ambient authority) | Dennis & Van Horn (1966); KeyKOS, seL4 | General knowledge | Tool permission as a *held token*, not a checked identity — the 1970s answer to confused deputy |
| 9 | Just-in-time privileged access (PAM) | 2000s enterprise practice | General knowledge | Standing privilege → ephemeral grant; the lease expires whether or not you remember to revoke it |
| 10 | Dead-man's switch (liveness-gated operation) | Industrial/nuclear safety, old | General knowledge | Silence = halt. The operator must *continuously prove aliveness* to keep authority |
| 11 | Nuclear information barriers (verify without revealing) | UK–Norway Initiative (2000s) | General knowledge | Prove a property of secret data to an inspector who never sees the data — selective disclosure with verification |
| 12 | Indirect prompt injection | Greshake et al., "Not what you've signed up for" (2023) | Referenced in [arxiv 2605.17634](https://arxiv.org/html/2605.17634v1) (Greshake et al., 2023; OWASP #1) | The #1 agent vulnerability: attacker content arrives as *data* and executes as *instruction* |

---

## 2. Candidate primitives

### P1 — Egress Canaries: deception as the exfiltration control

**Old ingredients.** (4) Honeypots/honeytokens — Stoll 1986; Thinkst Canary tokens 2015; the reportedip honeypot-server documents the key property: a honeytoken "only ever existed inside a hidden honeypot response," so any later replay "has near-zero false positives."

**The recombination.** Everyone applies honeytokens to catch *external attackers*. Nobody plants them *inside the agent's own sandbox* to catch *the agent itself*. The new primitive: **the sandbox is seeded per-run with canary credentials, hostnames, and tokens that are never valid** — fake `~/.aws/credentials`, a `canary.internal` host, an `INTERNAL_API_TOKEN` env var. The agent has no legitimate reason to touch them. Any egress attempt or credential use matching the canary registry is proof of exfiltration intent (via injection, bug, or compromise) → immediate fail-closed halt + LOUD audit + approval-queue escalation. This is **detection instead of filtering**: it sidesteps F81's accepted-gap rationale (we deliberately didn't ship filtered egress because we couldn't guarantee correct fail-closed allowlist setup) — a canary needs no allowlist to be correct, because the canary is never a legitimate destination.

**Prior-art check (honest).** Adjacent work exists and bounds the novelty claim:
- A USENIX Security 2025 paper taxonomizes "LLM-specific honeytokens" (T3.2) as a *detection* technique — deception-for-LLMs is already a research area ([cs.wm.edu](https://www.cs.wm.edu/~smherwig/readings/papers/25-sec-cheat.pdf)).
- [Angler](https://github.com/devampatel03/Angler) runs Ghost/Warden MCP servers that generate honeytokens and trigger lockdowns on use — but it is a **chatbot honeypot for external attackers**, not a sandbox primitive.
- [llm-honeypot](https://github.com/romiisromie/llm-honeypot/blob/HEAD/README.md) and Beelzebub-style traps likewise face *outward*.
- **The gap nobody occupies:** canaries as an *inward-facing, first-class sandbox control*, wired into a fail-closed policy engine and a hash-chained audit log, as the primary answer to the filtered-egress problem. Novelty grade: **B+**. The mechanism is old; the placement and the "detection-instead-of-filtering" framing for F81 are new.

**Target.** F81 — the only open finding. Also strengthens the exfiltration family generally (injection-driven exfiltration is the canonical prompt-injection payoff).

**Prototype spec** (docs-only; build loop executes):
- New module `gov/canary.py`:
  - `CanaryMint`: per-run canary set generator (run_id-bound, rotated every run): fake AWS-style key pairs, fake internal hostnames, fake bearer tokens, fake `.env` entries. Realistic formats — a model must not trivially recognize them as canaries.
  - `CanaryRegistry`: server-side record of planted values. The planted artifacts live in the jail (visible to the agent); the registry lives outside it (never in the jail).
  - Planting hook in sandbox setup: writes canaries into jail env, `~/.aws/credentials`, `/etc/hosts`, and one decoy config file.
  - Trip detector on the egress-attempt path (we already audit egress denials): match attempted destination/credential against the registry → emit `canary_trip` audit event (LOUD, distinct type), halt the run fail-closed, escalate to the approval queue with the trip evidence attached.
- Key invariant: **canaries are never valid credentials or reachable hosts** — any use is, by construction, proof of malicious or erroneous intent. Near-zero false positives by design.
- Registry probes to register: (a) injected instruction tells the agent to exfiltrate to the canary host → must trip, halt, and audit; (b) agent does legitimate work with real credentials → no trip; (c) canary value appears in *tool output* (not env) and the agent replays it → trip on use; (d) canary rotation: last run's canaries don't trip this run (no cross-run false positives).
- Evidence fit: every `canary_trip` is an auditor-grade artifact — "exfiltration attempt detected and stopped, timestamped, hash-chained." This is exactly the kind of runtime evidence the evidence-as-a-service bet sells.

**Honest failure mode.** A tripwire is not a wall: an exfiltrator that never touches a canary is not caught (but strict deny-all still blocks real egress — the canary is the *intent signal* for the cases deny-all can't see, e.g., filtered mode or a misconfigured jail). Over-planting risks the agent learning canary patterns; under-planting risks sparse coverage. A model that recognizes canary formats could avoid them — mitigation is format realism + rotation, not secrecy of the concept.

---

### P2 — Sterile Cockpit Windows: temporal input quarantine

**Old ingredients.** (1) FAA sterile cockpit rule, 14 CFR §121.542 (1981): during critical phases of flight (taxi, takeoff, landing, below 10,000 ft), *no non-essential activity* — the rule governs **when** attention may be spent, not **what** may be said. Born from NTSB findings that non-essential conversation (Eastern Air Lines 212, 1974 — crew discussing politics on approach, 72 fatalities) caused distraction-induced error. (12) Indirect prompt injection (Greshake et al., 2023): attacker content arrives as data, executes as instruction.

**The recombination.** Every existing injection defense filters *content* (detectors, classifiers, delimiters, instruction hierarchies). The sterile-cockpit move is orthogonal: govern *time*. Declare **critical windows** — spans during which the agent executes irreversible or high-privilege tools — and during a window, **all untrusted input channels are suspended**: web-fetch results, untrusted file reads, tool outputs from untrusted sources, pasted operator content. The agent operates on a frozen, pre-vetted context snapshot until the window closes. The injection can be as clever as it likes; if it arrives during a sterile window, there is no channel for it to arrive *through*. This is a policy-engine primitive (temporal), not a detector (content).

**Prior-art check (honest).** Searched directly: no one applies the sterile-cockpit concept — or any temporal input-quarantine — to LLM agents. The literature clusters on content defenses: classifiers ([AgentShield-style WAF-for-agents](https://medium.com/@eigenart.filmproduction/how-to-detect-prompt-injection-in-your-llm-agent-python-5-minutes-723d0c4ca6a6)), authority boundaries ([OpenAI's designing-agents-to-resist-prompt-injection](https://github.com/marius-manola/personal-brand/blob/HEAD/content/blog/how-to-prevent-prompt-injection-in-an-ai-agent.mdx)), contextual integrity ([arxiv 2605.17634](https://arxiv.org/html/2605.17634v1)). The temporal dimension is unoccupied. Novelty grade: **A-**.

**Target.** Indirect prompt injection landing *during* privileged execution — the Wiki-incident shape (poisoned content arriving mid-operation defeats a proxy control), and the human-error shape (operator pastes untrusted content into a running critical task). Complements the P13 renderer-side boundary (partial-by-design) from the input-timing side.

**Prototype spec** (docs-only; build loop executes):
- Input-channel registry: every channel the executor exposes (tool result, file read, web fetch, user message, memory recall, skill content) labeled `trusted`/`untrusted` at registration. Default: untrusted. (This taxonomy is the design dependency — it must exist first.)
- New policy block `critical_windows:` mapping tool/capability patterns → window declaration (e.g., `db.drop_table`, `send_email`, `payment.*` open a window).
- Executor integration: on window entry, snapshot the vetted context and suspend untrusted channels (reads return a `WINDOW_SUSPENDED` refusal, audited as `sterile_window_enter/exit`). On exit, resume with an explicit reconciliation read. Window enter/exit are hash-chained audit events — themselves evidence of input discipline.
- Registry probes: (a) poisoned web content fetched *during* a critical window → channel suspended, no injection path, audited; (b) same poison fetched *outside* a window → normal content defenses apply (defense in depth, not replacement); (c) operator message injected mid-window → suspended; (d) nested windows and window-escape attempts (agent tries to close the window early via tool call → denied, audited).

**Honest failure mode.** Three real ones: (i) **pre-positioning** — poison already in context *before* the window opens is unaffected; closing that needs taint tracking, which we don't have — the window is a complement, not a complete answer; (ii) **"critical" is a policy-author judgment** and therefore gameable/over-broad — over-declaring windows destroys usability, under-declaring leaves holes; (iii) **snapshot staleness** — the agent acts on frozen context, so long windows risk acting on outdated facts. This is the most differentiated idea and the biggest build of the three.

---

### P3 — Behavioral Circuit Breakers: the audit stream as a trip signal

**Old ingredients.** (2) Nygard's circuit breaker (*Release It!*, 2007): closed/open/half-open state machine, fail-fast, human-involved recovery. (3) Shewhart control charts (1931): a process breaching control limits is *out of control* → stop the line. Streaming mean/variance estimators make the statistics O(1) per event.

**The recombination.** Existing agent circuit breakers are **reliability** devices: they trip on dead endpoints and retry spirals ([dev.to/samhartley_dev](https://dev.to/samhartley_dev/i-added-a-circuit-breaker-to-my-ai-agent-setup-it-caught-three-outages-this-month-5fhm), [cencori](https://github.com/cencori/cencori/blob/HEAD/content/blog/2026-04-16-circuit-breakers-for-ai-agents.mdx), [Azure AI Hub resiliency guide](https://github.com/azure-samples/ai-hub-gateway-solution-accelerator/blob/HEAD/guides/resiliency-guide.md)). The new application: trip on **adversarial behavioral drift**, computed over the *governance audit stream* (which we already emit for everything). Per-agent-identity rolling baselines over: tool-call rate, failure rate, privilege-escalation attempts, egress attempts, approval denials, injection-quarantine hits. Breach (N-sigma or absolute threshold) → breaker OPENS → all subsequent high-risk actions route to the human approval queue (fail-closed); the breaker stays open until a human resets it, with half-open probing (one low-risk action to test recovery). This is a **detector + response primitive** — and it is, concretely, the behavioral-monitor detector spec that P8's "uncovered-by-design" status says is absent.

**Prior-art check (honest).** The mechanism name is taken for reliability; one [dev.to piece](https://dev.to/zeroshotstudio/the-circuit-breaker-pattern-why-deterministic-code-hooks-beat-agent-self-correction-in-production-4m5b) mentions "stochastic behavioral drift" but only for destructive write loops, not adversarial behavior, and nothing wires a breaker to a governance audit stream with per-identity baselines and approval-queue failover. The *governance* application is new; the *mechanism* will be commoditized by the reliability crowd. Novelty grade: **B** (application), with a short half-life on the mechanism itself.

**Target.** P8 — behavioral anomaly, uncovered-by-design, the largest B1 hole. Also swarm rogue behavior: the HF July swarm (~700 agents) is exactly the shape per-identity breakers trip on.

**Prototype spec** (docs-only; build loop executes):
- New module `gov/breakers.py`: `BreakerBank` consuming the audit event stream; per-agent-identity rolling statistics (streaming mean/variance, O(1)/event); configurable signals and thresholds in policy (`breakers:` block); breaker state machine (closed → open → half-open → closed) with states in the tamper-evident store.
- Executor integration: on open breaker, `decide()` routes high-risk actions to the approval queue with `breaker_open` context; re-admission only via human reset (audited). Breaker trips are audit events — evidence of behavioral oversight for the evidence bet.
- Registry probes: (a) sudden tool-call-rate spike ×20 → trips; (b) privilege-escalation-attempt burst → trips; (c) slow linear drift under the threshold for 10× the window → does NOT trip (documents the slow-boil boundary honestly); (d) attacker deliberately trips another agent's breaker (DoS via breaker) → contained, audited, availability note filed.

**Honest failure mode.** The classic: **slow-boil baseline poisoning** — drift slower than the threshold never trips. Breakers catch fast anomalies, not patient adversaries; they can never be a primary control, only a backstop. False positives on legitimately bursty agents create tuning burden and approval-queue load. Breaker state is itself a new attack surface (breakers as a DoS vector — fail-closed makes DoS the safe direction, but availability still matters; cf. the F25 lock-contention lesson).

---

## 3. Killed in writing — timestamp-anchored evidence

**The idea.** Haber–Stornetta (1991) × RFC 3161 × Certificate Transparency × our HMAC audit chain: third-party-anchor the chain tip with an independent timestamp authority so evidence is not self-attested ("who watches the watcher"), plus selective disclosure in the nuclear-information-barrier style — prove the control operated without revealing proprietary prompts.

**Why it's dead as an invention.** The space is occupied, three times over:
- [luckypipewrench/agent-evidence-levels](https://github.com/luckypipewrench/agent-evidence-levels/blob/HEAD/docs/PRIOR-ART.md) — "Agent Evidence Levels" with a full prior-art register: RFC 5848 signed syslog, CT (RFC 6962/9162), Sigstore/Rekor, RFC 3161, SCITT. Its AEL-3 is *anchoring as a product*.
- [sectum-ai](https://github.com/sectum-ai/sectum-ai/blob/HEAD/docs/evidence-chain.md) — `EvidencePack` with independent anchor (real RFC 3161 timestamp or Rekor inclusion proof); `verify` *refuses* packs missing either.
- [finserv-agent-audit](https://github.com/linus10x/finserv-agent-audit/blob/HEAD/RESEARCH.md) — cites Haber–Stornetta directly for its `AuditChain` and designs witness-anchoring (ADR-0014).

**Verdict: killed as a differentiator, adopted as a commodity.** Anchoring is a feature to adopt later (it strengthens the evidence bet's credibility), not an invention to lead with. The honest differentiator remains the HMAC chain + approval queue + battery *as the evidence source* — nobody else has the corpus. Lesson for the loop: run the prior-art check *before* falling in love with the recombination.

---

## 4. Ranking

**Prototype first: P1 — Egress Canaries.** Four reasons: (1) it targets F81, the *only open finding* on the board — the single red item; (2) smallest honest build, entirely on assets we own (sandbox + egress audit path + policy engine); (3) crispest adversarial validation — the battery already has exfiltration scenarios, and canary-trip probes are deterministic (touch = trip); (4) every trip is a sellable evidence artifact for the evidence-as-a-service bet. The prior-art boundary is defensible: existing deception work traps *external attackers*; we govern *the agent itself*.

**Second: P2 — Sterile Cockpit Windows.** Most differentiated (temporal governance is unoccupied), attacks the #1 vulnerability class. Goes second because it has a design dependency — the input-channel trusted/untrusted taxonomy must be built and argued first — and the "what counts as critical" judgment plus usability cost need a careful policy-design pass, not a rushed prototype.

**Parked: P3 — Behavioral Circuit Breakers.** Closest prior art (the reliability-breaker crowd will commoditize the mechanism), weakest novelty half-life, and the slow-boil evasion means it can never be primary. Park until the P8 detector-spec work starts — at which point this brief *is* the draft spec. Do not let the mechanism's familiarity disguise the fact that the governance application still needs adversarial validation before any claim.

**Also parked (noted, not specced):** capability leases (JIT + dead-man liveness for tool permissions — thin novelty over PAM + existing approval queue); pre-mortem ritual for closures (process improvement, not a primitive — though the red-team loop should steal the *habit*: write the failure postmortem before shipping the closure).

---

## 5. The single most surprising old idea

That the **blockchain was invented in 1991 not for money, but to prove when a document existed** — Haber and Stornetta's "How to Time-Stamp a Digital Document" (*Journal of Cryptology*, Vol. 3, No. 2), cited three times in the Bitcoin whitepaper, whose company Surety has printed hash-chain heads in the *New York Times* every week since 1995. The entire cryptocurrency industry is a side effect of a timestamping scheme for digital records. And it is directly our business: our HMAC audit chain *is* a Haber–Stornetta chain, and the evidence-as-a-service bet is, at its core, selling timestamped proof that something happened. The 35-year-old idea is the product.

---

*Brief prepared 2026-09-22. Docs-only lane: no changes to `gov/`, `evals/`, `tests/`, or any code. Build specs above are for the build loop to execute.*
