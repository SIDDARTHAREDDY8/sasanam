# Prospectus — Trusted-Transform Laundering (Wave-315 Lane 4)

**Question:** How do existing systems handle the case where a *trusted transform*
(summarizer, translator, format converter, sanitizer) deterministically launders
untrusted content — i.e. the transform's output re-enters a sink carrying an
attacker payload the transform was trusted to remove or neutralize?

**Residual it answers:** wave-314 lane 1 (provenance sink/quarantine) documents
"trusted-transform laundering unsolved deterministically" as an explicit residual.
The sink's min-trust invariant stops untrusted data reaching sinks; it does not
constrain what a *trusted* transform may emit.

**Method:** primary sources only (papers, specs, security advisories, source wikis).
Patterns, not code — nothing here is proposed for vendoring.

---

## 1. Zdancewic & Myers — Robust Declassification (CSFW-14, 2001)

- **Source:** Steve Zdancewic and Andrew C. Myers, "Robust Declassification",
  Proc. 14th IEEE Computer Security Foundations Workshop, pp. 15–23,
  Cape Breton, June 2001. Primary PDF: https://www.cs.cornell.edu/zdance/csfw.pdf
- **Claim:** Declassification is only safe when the *release itself* cannot be
  influenced by an attacker. Formal condition: an active attacker must learn no
  more than a passive attacker. Their motivating example is literally
  laundering: a password checker whose transitions are driven by attacker input
  is used to *launder* confidential information out through the intended
  declassification channel.
- **Relevance:** This is the theory of our residual, stated 25 years ago. A
  trusted transform (summarizer, sanitizer) is a declassification point; if the
  attacker's input influences *what the transform releases* beyond the
  transform's declared intent, the channel is being laundered. Robustness
  demands the decision-to-declassify and the released content both be
  attacker-independent.
- **Verdict: STEAL (theory).** Import the robustness condition as the acceptance
  test for any transform policy: no transform may release more, under attacker
  input, than it releases under benign input of the same shape.
- **License:** paper — citation only, no code.

## 2. Sabelfeld & Sands — Declassification: Dimensions and Principles (JCS, 2009)

- **Source:** Andrei Sabelfeld and David Sands, "Declassification: Dimensions
  and Principles", Journal of Computer Security 17(5):517–548, 2009.
  Dimensions: **what** is released, **where** in the program it may be
  released, **who** may observe it, **when** it may be released.
- **Claim:** The *where* dimension controls declassification by code location:
  only annotated program points may release information (Mantel & Sands'
  intransitive noninterference; Askarov & Sabelfeld's localized delimited
  release). The *what* dimension (Sabelfeld & Myers' delimited release, 2003)
  pins down the expressions whose values may escape.
- **Relevance:** Trusted transforms are *where*-points. The fix for laundering
  is not "make the transform smarter" but "enumerate the transform as a
  declared declassification point with a pinned *what*" — the transform's
  output contract (what it may emit) is part of its identity, checked at every
  use.
- **Verdict: STEAL (theory).** Our registry should treat every trusted
  transform as a (where, what) pair: the transform's call sites plus its
  declared output contract. Anything outside the contract is not
  "a bad transform" — it is an undeclared declassification and refuses coded.
- **License:** paper — citation only, no code.

## 3. W3C Trusted Types — the deployed sink/policy model

- **Source:** W3C Trusted Types explainer and spec,
  https://github.com/w3c/trusted-types/blob/HEAD/explainer.md ; MDN
  TrustedHTML reference. Deployed in Chromium; protects Gmail and most Google
  apps (per the project's own 101 deck).
- **Claim:** DOM injection sinks (`innerHTML`, `srcdoc`, script/URL sinks)
  **reject strings** and accept only typed objects (`TrustedHTML`,
  `TrustedScript`, `TrustedScriptURL`). Those objects have no public
  constructor — only named **policies** can create them, and policy creation is
  itself guarded by the CSP `trusted-types` directive. The policy — the trusted
  transform — is the *audit boundary*: "it doesn't add escaping, it makes the
  trust explicit and listable in CSP."
- **Relevance:** This is our problem, solved at web scale. The pattern maps
  1:1 onto Sasanam's sinks: a sink must refuse raw (untyped) content and accept
  only transform-sealed outputs; the transform registry is the named-policy
  list; policy *registration* is the privileged operation (analogous to our
  step-3 approval tokens).
- **Caveat:** Trusted Types does not verify the policy's sanitization is
  *correct* — a passthrough `createHTML: s => s` policy is legal and the
  explainer admits it. Type discipline contains *where* laundering can happen;
  it does not prove the transform is laundering-free.
- **Verdict: STEAL (pattern).** Sink-side type refusal + named-policy registry.
  The correctness gap is closed by source 4's re-verification discipline.
- **License:** W3C Software and Document License for the spec (no code reuse
  proposed — pattern only).

## 4. Cure53 DOMPurify + the mXSS record — the empirical laundering ledger

- **Source:** DOMPurify "Security Goals & Threat Model" wiki,
  https://github.com/cure53/DOMPurify/wiki/Security-Goals-&-Threat-Model ;
  PortSwigger mXSS research,
  http://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss ;
  GHSA-h8r8-wccr-v5f2 (DOMPurify 3.3.1 mXSS via re-contextualization).
- **Claim:** "A large share of modern bypasses are not 'forgot to remove
  `<script>`' but **parse asymmetry** — markup that is inert in the tree the
  sanitizer inspects but becomes active after the output is serialized and
  reparsed." DOMPurify's standing defenses: check every node against its
  parent's **namespace** (HTML/SVG/MathML integrity), `SAFE_FOR_XML`
  attribute-value guards, and a re-parse + `textContent` stability check of the
  serialized output. Residual risk is stated as Medium — "unavoidable given
  browser-parser variability" — and the compensating control is disclosure
  speed, not a stronger filter.
- **Relevance:** This is the longest-running public record of trusted-transform
  laundering. Three transferable disciplines: (a) verify the output against
  the *same interpreter* that will consume it (no second opinion —
  "DOMPurify sanitises using the DOM of the environment it runs in... which
  removes the mutation-XSS gap at its source"); (b) re-verify the emitted
  output against the declared contract *after* the transform (re-parse +
  compare); (c) state the residual honestly when the environment (here: the
  model) is the variable part.
- **Verdict: ADAPT.** Post-transform re-verification against the declared
  output contract, using the same consumer the sink will use, is the
  deterministic counter to laundering. We cannot copy the DOM machinery, but
  the discipline ports directly: every trusted transform's output is
  re-checked against its (where, what) contract before the label is lowered.
- **License:** DOMPurify is dual-licensed Apache-2.0 / MPL-2.0 (per project
  documentation). Pattern-only reuse proposed; no GPL/AGPL trap.

## 5. CaMeL — Defeating Prompt Injections by Design (DeepMind/ETH, 2025)

- **Source:** Edoardo Debenedetti et al., "Defeating Prompt Injections by
  Design", arXiv:2503.18813 (revised June 2025).
  https://arxiv.org/abs/2503.18813v2
- **Claim:** Do not detect malicious text; restructure the agent. A privileged
  LLM plans without seeing untrusted data; a quarantined LLM reads untrusted
  data but cannot act; a custom interpreter executes the plan and enforces
  capability policies at every tool call. 77% of AgentDojo tasks solved with
  provable security (vs 84% undefended).
- **Relevance:** The dual-plane split is the architectural answer to
  transform laundering: **an LLM is never a "trusted transform."** Any
  model-mediated transform (summarizer, translator) runs on the *data plane*;
  its output keeps the minimum input label. Only deterministic, spec'd code
  transforms may be registered as declassification points. CaMeL's capability
  check at tool-call time is exactly where our step-3 single-use tokens
  already sit.
- **Verdict: ADAPT (already in tree; re-cite for the transform angle).**
  Harden the rule: model-output transforms are never label-lowering; only
  registered deterministic transforms with verified output contracts may
  lower a label, and only via a minted declassification capability.
- **License:** paper cite; code at google-research (Apache-2.0, re-verify at
  build time if ever vendored — not proposed here).

## 6. FIDES — channel-capacity lattice (arXiv:2505.23643)

- **Source:** FIDES, "Securing AI Agents with Information-Flow Control",
  arXiv:2505.23643 (already STEAL in the wave-313 prospectus; re-cited here
  for the transform angle).
- **Claim:** Type lattice `bool ⊑ enum ⊑ string` ordered by **information
  capacity** — extracting a bool from untrusted data limits the channel to 1
  bit. *Hide* (untrusted content behind variable refs, never in LLM context)
  + *Inspect* (quarantined LLM, constrained outputs). 0/949 AgentDojo attacks.
- **Relevance:** This is the *what*-dimension made quantitative. A transform's
  laundering capacity is bounded by its output channel: a summarizer emitting
  free text can launder an arbitrary payload; the same task emitting a
  5-valued enum can launder at most ~2.3 bits. The output contract of a trusted
  transform should declare its capacity class, and the sink policy should
  treat capacity as the laundering budget.
- **Verdict: STEAL (already in tree).** Add to the transform registry: each
  registered transform declares an output capacity class (bool/enum/string/
  opaque-ref); string-class transforms never lower labels without a minted
  capability; enum/bool-class transforms lower to a label commensurate with
  the bounded channel.
- **License:** MIT (per prior verification).

## 7. Spotlighting (Hines et al., 2024) — negative evidence

- **Source:** K. Hines et al., "Defending Against Indirect Prompt Injection
  Attacks With Spotlighting", arXiv:2403.14720, 2024.
- **Claim:** Wrap untrusted text in delimiters / encode it (base64) so the
  model treats it as data. Probabilistic by construction. Known bypass
  classes: encoding smuggling (the model decodes what the filter cannot see —
  OWASP AISVS notes "models often act as decoders; a filter that only sees the
  raw string can miss instructions the model later decodes"), fence closure
  (attacker text closes the delimiter and speaks as the system), homoglyph
  and zero-width smuggling.
- **Relevance:** Marking is a *transform* (wrap/encode) that claims to make
  content safe for a sink (the model). It fails exactly the laundering test:
  the transform's output re-enters a sink (the LLM context) carrying the
  payload, because the sink interprets the output differently than the
  transform assumed. Any defense of the form "transform the bytes and trust
  the sink to see them the same way" is laundering-shaped.
- **Verdict: SKIP (as a defense).** Keep as the canonical negative example in
  the build lane's threat model: no byte-marking transform may be registered
  as label-lowering.
- **License:** paper — citation only.

## 8. Greshake et al. — why content judges fail (AISec 2023)

- **Source:** K. Greshake et al., "Not what you've signed up for:
  Compromising Real-World LLM-Integrated Applications with Indirect Prompt
  Injection", Proc. 16th ACM Workshop on AI and Security, pp. 79–90, 2023.
- **Claim:** Real LLM-integrated applications fall to indirect prompt
  injection through ordinary data channels; the injected content steers the
  application's behavior including its own safety checks.
- **Relevance:** A "judge" transform — an LLM asked "is this output safe?" —
  is itself a sink for the untrusted content it judges. The judge's verdict is
  a 1-bit declassification of arbitrarily attacker-influenced content: the
  exact laundering shape (untrusted input → trusted transform → sink), with
  the transform being the least deterministic component available. Judges
  belong in advisory telemetry, never in the label-lowering path.
- **Verdict: SKIP (LLM judges in the enforcement path).** Deterministic
  contract checks only.
- **License:** paper — citation only.

---

## Direction brief for the build lane

**"Deterministic transform-declassification policy"** — what the lane should build
(stdlib-only, TDD red-first, reusing the F34 key ceremony and the step-3 token
machinery; no new crypto):

1. **Transform registry as (where, what) pairs** (Sabelfeld & Sands; Trusted
   Types). Every trusted transform is registered with: identity (module +
   function digest), declared input contract, declared **output contract**
   (shape + capacity class per FIDES: bool/enum/string/opaque-ref), and the
   label-lowering rule it is allowed. Unregistered transforms run on the data
   plane — output keeps `min(input labels)` — and can never lower a label.
2. **Model transforms are never label-lowering** (CaMeL; Greshake). Any
   LLM-mediated transform (summarize, translate, judge) emits at the minimum
   input trust level, always. Lowering requires a deterministic registered
   transform.
3. **Label-lowering only via minted capability** (TokenTaint declassification
   bridge, already in tree). Applying a registered lowering transform at a
   sink requires a single-use, argument-bound declassification token
   (capability `transform-declassify`, exact mode) minted through the existing
   approval path — the *decision to declassify* is a privileged, audited act,
   not a property of the transform.
4. **Post-transform re-verification, deterministically** (DOMPurify
   discipline). After the transform runs, its output is re-checked against
   the declared output contract by a checker that uses the same consumer
   semantics the sink will use. Contract failure → REDACT to opaque ref
   (FIDES *Hide*) or REFUSE + bounded re-plan (CaMeL quarantine), never
   silent pass.
5. **Robustness acceptance test** (Zdancewic & Myers). For each registered
   transform, the battery must show: under attacker-chosen inputs of the same
   shape, the transform releases no more (by the capacity class) than under
   benign inputs. This is the red-first gate for the lane.
6. **Capacity-budgeted string transforms.** A string-emitting transform
   (sanitizer, formatter) may lower a label only to a level commensurate with
   a *verified* contract (allowlist grammar, not denylist regexes — the mXSS
   record is unambiguous that denylists lose). Enum/bool transforms lower
   freely within their bit budget.
7. **No marking transforms in the registry** (Spotlighting negative rule).
   Byte-marking/delimiter transforms are not label-lowering transforms; the
   registry refuses them at registration time with a coded refusal.
8. **Residual honesty.** Where the consumer is an LLM (irreducibly
   interpretive), state the residual as DOMPurify does: Medium, unavoidable
   given model variability; the compensating control is the min-trust sink
   invariant plus disclosure, not a stronger transform.

**Estimated shape:** `gov/transform_registry.py` (registration + contracts),
`gov/transform_policy.py` (allow/lower/redact decisions, token-gated),
`evals/w3XX_transform_probes.py` (robustness batteries per transform +
laundering corpus: mXSS-style parse-asymmetry cases adapted to text
transforms, fence-closure cases, encoding-smuggling cases). New decision
codes: `transform-*` family. Pin moves; footer per base.

**What NOT to build:** an LLM judge of transform outputs; a sanitizer with a
denylist; a marking/delimiter scheme presented as a security boundary.
