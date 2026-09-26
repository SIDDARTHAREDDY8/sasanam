# Semantic Exfiltration over Authorized Channels: What DLP, Covert-Channel Analysis, Human Factors, and Information-Flow Theory Say

**Research date:** 2026-09-26 · **Author:** research subagent · **Status:** findings memo, no product code changed

**Question.** How do real-world DLP and egress-filtering systems handle exfiltration over *authorized* channels where the content is paraphrased or semantically encoded — i.e., the action is legitimate and allowlisted, the exfil lives in the *meaning*, and verbatim/pattern matching fails? What old ideas could be recombined into a new, $0 / local-compute / no-LLM primitive for an AI agent governance product?

**One-line answer.** Nobody in the deployed DLP world has a per-secret paraphrase detector. Enterprise DLP handles "derived" content with document-fingerprint partial matching (defeated by rewording) and statistical document-type classifiers (which classify the *type*, not whether a specific secret survived). The honest lesson from covert-channel theory is bleaker and more useful: a sufficiently careful semantic channel is *provably* undetectable by a content warden, so the winning move is not a better content scanner — it is **bounding the channel** (phase restrictions, capacity caps, usage anomaly) plus **tripwires inside the sensitive content** (canaries) plus **supervised reference patterns** (known exfil shapes, not known strings).

---

## 1. What enterprise DLP actually does about paraphrased/derived exfil

### 1.1 Symantec/Broadcom DLP: fingerprinting + statistics, both pre-semantic

Symantec DLP's detection stack has four content technologies, documented in partner/operational literature:

- **Indexed Document Matching (IDM)** applies fingerprinting to unstructured documents (Office, PDFs, binaries) and "detects 'derived' content, such as text that has been copied from a source document to another file." Deployment practice sets partial-match thresholds around 10–20%: even 10–15% of a sensitive document in inspected content triggers ([oyster-technologies.com](https://oyster-technologies.com/symantec-dlp-benefit/), [SKILL.md operational notes](https://github.com/chrishuffman5/agents/blob/HEAD/skills/security/dlp/symantec-dlp/SKILL.md)).
- **Vector Machine Learning (VML)** protects IP with "subtle characteristics" (financial reports, source code) by "performing statistical analysis on unstructured data and comparing it to similar content or documents" — trained on 50+ positive and 50+ negative example documents ([oyster-technologies.com](https://oyster-technologies.com/symantec-dlp-benefit/), [SKILL.md](https://github.com/chrishuffman5/agents/blob/HEAD/skills/security/dlp/symantec-dlp/SKILL.md)).
- **Exact Data Matching (EDM)** fingerprints structured sources (database exports → hash index); **Described Content Matching (DCM)** is regex + keyword proximity + validators (Luhn etc.).

*Honest reading of the limits.* IDM's partial match is an n-gram/fingerprint overlap test: it catches copy-paste derivatives, but a rewording that pushes shared fingerprint fragments below the 10–20% threshold passes. VML is the closest thing to "semantic" detection in the stack — but it answers "is this document *statistically like* the sensitive examples?" (document-type classification), not "does this text still carry the *meaning* of secret record X?" No Symantec primitive compares a specific egress payload against a specific sensitive record at the meaning level.

### 1.2 Microsoft Purview: classifiers for types, hashes for values, nothing for paraphrase-of-a-record

Microsoft Purview's classification stack is documented on Microsoft Learn:

- **Trainable classifiers** (built-in and custom) identify content *categories*; the accuracy-tuning experience (match / not-a-match feedback, contextual summaries) is available only for SharePoint/OneDrive items and Exchange emails ([learn.microsoft.com](https://learn.microsoft.com/en-us/purview/data-classification-increase-accuracy)).
- **Document fingerprinting SITs** hash an uploaded form and match future content at configurable confidence; Microsoft documents this as strict matching suited to "the entire text of the form" matching the original, with a 150 KB rule-pack limit (~50 fingerprints per tenant) ([learn.microsoft.com training](https://learn.microsoft.com/en-us/training/modules/create-manage-sensitive-information-types/5-implement-document-fingerprint)).
- **Exact Data Match (EDM)** matches content against hashed reference datasets for "very high accuracy, extremely low false positives" — but only when values appear *verbatim*; it is precision-at-the-cost-of-coverage by design (secondary summary of Microsoft docs, [medium.com/@ahmed.monsry](https://medium.com/@ahmed.monsry/understanding-classification-in-microsoft-purview-f5c2cfa52645)).
- Practitioner summaries of the SIT system are explicit that built-in sensitive-information types **cannot "detect document meaning or intent"** — they are pattern engines ([medium.com/@ahmed.monsry](https://medium.com/@ahmed.monsry/understanding-classification-in-microsoft-purview-f5c2cfa52645)).

*Net:* Purview detects *structured values* (verbatim) and *document categories* (statistical). A paraphrase of a specific sensitive record into novel wording is outside every documented primitive.

### 1.3 Proofpoint: LLM classifiers — category-level, self-documented limits

Proofpoint's 2025–2026 direction is LLM-powered pre-trained classifiers that "categorize documents at line speed" with claimed "85% confidence or greater." Proofpoint's own writeup documents the limits of these classifiers: they "rely on static enterprise data and fixed labels, they don't adapt well to evolving threats or changing business contexts or document purposes. They can miss subtle signals, leading to misclassification or false positives" ([proofpoint.com](https://www.proofpoint.com/uk/blog/dspm/ai-data-classification-proactive-data-protection)). And Proofpoint's insider-threat ebook is blunter about ML behavior analytics generally: "the technologies are not yet advanced enough to accurately detect and prevent insider threat incidents" — they fire alerts, they don't stop damage ([proofpoint.com ebook](http://proofpoint.com/sites/default/files/e-books/gtd-pfpt-us-eb-itm-cybersecurity.pdf)).

### 1.4 Nightfall AI: AI-native DLP, still secret-*type* detection

Nightfall markets "AI-powered detectors that go beyond regexes, rules, and search strings," built on pre-trained LLMs/transformers identifying 100+ secret types ([nightfall.ai one-pager via wisdominterface.com](https://www.wisdominterface.com/wp-content/uploads/2024/03/Cloud-Native-Data-Leak-Prevention-for-Github.pdf); research report [thaiaiaudit.com](https://www.thaiaiaudit.com/content/files/2025/09/Nightfall-AI-research-report.pdf)). This is the industry's nearest deployed approach to semantic detection — but it detects *categories of secrets* (API keys, PII types) in free text, not whether a particular sensitive document's meaning was paraphrased into an egress payload. No vendor publishes precision/recall numbers for paraphrase-of-a-specific-secret; the published numbers are about secret-type detection vs. regex baselines (vendor claims, treat as marketing).

### 1.5 The gap, stated plainly

Across Symantec, Purview, Proofpoint, and Nightfall, the deployed primitives are: **verbatim/value matching** (regex, EDM, fingerprints), **derived-copy matching** (IDM partial overlap), and **category classification** (VML, trainable classifiers, LLM secret-type detectors). There is **no deployed "this egress paraphrases record X" primitive** found in any vendor's public documentation. Industry commentary agrees the gap is real and growing: once sensitive content is summarized or paraphrased — the normal shape of LLM/agent output — "a DLP rule looking for a document hash or an exact-match pattern will not find the leaked content" ([linkedin.com](https://www.linkedin.com/pulse/ai-data-loss-prevention-vs-traditional-dlp-why-agents-need-8goec)); internal writeups note "derived/aggregate leakage" where "model-authored summaries … encode sensitive content without triggering word-level scanners" and conclude "DLP on outputs must be paired with query-shape and purpose controls" ([github.com/secure-agentic-framework](https://github.com/secure-agentic-framework/saf-mcp/blob/HEAD/mitigations/SAF-M-72/README.md)).

---

## 2. Covert-channel analysis: the theory that says content-scanning can't win

### 2.1 The prisoners' problem: the semantic channel is the warden's nightmare by definition

G. J. Simmons' "The Prisoners' Problem and the Subliminal Channel" (CRYPTO '83, published 1984) is the founding model: Alice and Bob communicate only through warden Willy, who inspects everything and punishes anything suspicious. Simmons showed a covert channel whose *existence* can be made as hard to detect as the underlying cryptographic algorithm is to break — "subliminal" ([petitcolas.net annotated bibliography](https://petitcolas.net/steganography/bibliography/Annotated_Bibliography.pdf)). The direct analogy to our problem: an agent and an outside receiver communicating through a DLP warden that only inspects *content* can always, in principle, move the signal out of the content and into the encoding (synonym choice, paraphrase structure). A 2026 practitioner writeup makes the same point for LLM agents: "the payload is encoded into structural properties of the text: character choice, spacing, punctuation. The decoded output of a covert channel contains no recognizable pattern" ([dev.to](https://dev.to/rxkov/llm-covert-channels-how-ai-agents-exfiltrate-data-in-plain-sight-359d)).

### 2.2 Detection techniques: regularity vs. shape — and their honest ceilings

The covert-channel detection literature (surveyed e.g. by Zander, Armitage & Branch, IEEE Communications Surveys & Tutorials 9(3), 2007, cited in [ijece.iaescore.com](https://ijece.iaescore.com/index.php/IJECE/article/download/26408/15784)) divides detectors into:

- **Regularity-based tests** — second/higher-order statistics on inter-packet delays (Cabuk's variance tests): a covert timing channel makes traffic *too regular* ([utc.edu paper](https://www.utc.edu/sites/default/files/2021-04/paper-csiirw-wade-covert.pdf)).
- **Shape-based tests** — first-order statistics: Kolmogorov–Smirnov tests, **entropy-based detection** (Naik et al.; Sanders, Valletta, Yuan, Johnson & Lutz, 2012), comparing the distribution shape against legitimate traffic ([ijece.iaescore.com](https://ijece.iaescore.com/index.php/IJECE/article/download/26408/15784), [utc.edu](https://www.utc.edu/sites/default/files/2021-04/paper-csiirw-wade-covert.pdf)).

The honest ceilings, from a TU Wien analytic study of ten published covert-timing techniques (Iglesias Vázquez, Annessi & Zseby, 2017): covert channels "do not occupy low density regions or take extreme values in the problem space, and therefore **are not detectable as strong anomalies**"; they must instead "be identified based on the **similarity to known schemes, using supervised and semi-supervised approaches**" ([journals.riverpublishers.com](https://journals.riverpublishers.com/index.php/JCSANDM/article/download/5245/4583?inline=1)). And a PMC-published statistical study found timing channels become reliably detectable as anomalies only when the induced delay is **≥ ~2× the mean legitimate inter-arrival time** — below that, they hide in the noise ([pmc.ncbi.nlm.nih.gov](https://pmc.ncbi.nlm.nih.gov/articles/PMC7219501/)).

### 2.3 The transferable lesson: bound the channel, don't out-scan it

Shannon's *A Mathematical Theory of Communication* (Bell System Technical Journal, 1948) gives the capacity bound: no coding scheme transmits reliably above channel capacity ([monoskop.org PDF of the paper](https://monoskop.org/images/a/ae/Shannon_Claude_E_A_Mathematical_Theory_of_Communication_1957.pdf)). The covert-channel tradition's mature answer to undetectable channels is not a better warden but **channel-capacity bounding**: limit *when* the channel may be used and *how much* may flow. Kemmerer's "A practical approach to identifying storage and timing channels: twenty years later" (ACSAC 2002) frames the discipline as enumerating and throttling channels at the source rather than detecting them in flight ([ijece.iaescore.com bib](https://ijece.iaescore.com/index.php/IJECE/article/download/26408/15784)).

**For the agent product, the mapping is direct:**
- The *content* warden (regex, fingerprints, entropy checks) is provably insufficient against a paraphrase-capable encoder (Simmons).
- The *usage* warden is where the leverage is: **phase restrictions** (when may this channel be used at all?), **volume caps** (how many bits per window?), and **similarity-to-known-schemes** — i.e., supervised pattern libraries of *known exfil shapes* rather than known strings (Iglesias Vázquez). Our repo's adversarial batteries are already, in embryo, exactly such a supervised reference set.

---

## 3. Human-factors safety: sterile windows and the second pair of eyes

### 3.1 The sterile cockpit rule (FAA, 1981): phase-based restriction

FAR 121.542 / 135.100, introduced by the FAA in **1981** after NTSB analysis of accidents in which non-essential cockpit conversation contributed to crew error (e.g., Eastern Airlines 212, 1974): during *critical phases of flight* — all ground operations involving taxi, takeoff and landing, and all other flight operations below 10,000 feet except cruise — "no flight crewmember may engage in, nor may any pilot in command permit, any activity during a critical phase of flight which could distract any flight crewmember from the performance of his or her duties" ([faasafety.gov](https://www.faasafety.gov/files/events/GL/GL05/2008/GL0520920/The_Sterile_Cockpit.pdf), [wikipedia](https://en.wikipedia.org/wiki/Sterile_flight_deck_rule)). Note the design: the rule does not try to judge *which* conversations are dangerous in real time — it **prohibits a class of activity during a defined phase**.

*Analogy for agent egress:* define a **"sterile window"** as any period in which the agent's working set contains tainted (sensitive-source) content. During the window, the agent may still do its job — but *external egress actions are restricted to pre-registered structured templates* (no free-text http_post bodies, no free-form api_call params). The restriction lifts when the window closes (taint flushed / task boundary). This is a phase-based restriction on the *channel*, exactly parallel to the sterile cockpit's phase-based restriction on *communication*. It needs no semantic understanding — only taint tracking the product already has.

### 3.2 Two-person rule / maker–checker: the approver must see the provenance, not just the intent

The two-person rule (USAF AFI 91-104: no single individual may arm/launch a nuclear weapon; applied to NSA sysadmin access post-Snowden — [nextgov.com](https://www.nextgov.com/cybersecurity/2013/07/why-the-two-man-rule-is-only-the-beginning/211391/?oref=ng-author-river), [entrust.com](https://www.entrust.com/sites/default/files/documentation/solution-briefs/dps-secondary-approval-sb.pdf)) and the fraud world's **maker–checker** control (one person prepares a payment, a *different* person approves it; expenditures over a threshold require two managers — [fraudconference.com (ACFE materials)](https://fraudconference.com/uploadedFiles/Fraud_Conference/Content/Course-Materials/2a-goldmann-cpp.pdf); BEC guidance requires dual approval plus callback verification through an *independent* channel — [adaptivesecurity.com](https://www.adaptivesecurity.com/blog/business-email-compromise-payment-verification)) share one design insight the product can steal:

**The checker's power depends entirely on what the checker can see.** A human approver who sees only the agent's *stated intent* ("sending weekly summary to partner") cannot catch semantic exfil; an approver who sees **provenance** ("this payload was assembled from sources: Q3_forecast.xlsx [tainted], support_tickets [clean]; paraphrase-risk HIGH") is a maker–checker that actually functions. This is also the fraud lesson that urgency must "accelerate review, never bypass it" ([adaptivesecurity.com](https://www.adaptivesecurity.com/blog/business-email-compromise-payment-verification)) — i.e., the approval queue must be unbypassable during sterile windows (no auto-approve fast paths keyed on channel allowlisting).

---

## 4. Information-flow control: what theory says about releasing paraphrased derivatives

### 4.1 Noninterference, declassification, and the four dimensions

Classical information-flow security demands **noninterference** (Goguen & Meseguer, IEEE S&P 1982): no information flow from sensitive to public. Real systems must release *some* information, so the literature studies **declassification** — controlled downgrading. The canonical map is Sabelfeld & Sands, "Declassification: Dimensions and Principles" (CSFW 2005; J. Computer Security 17(5), 2009): declassification policies vary along four dimensions — **what** information may be released, **where** in the program, **who** may release it, and **when** ([staff.itee.uq.edu.au summary](https://staff.itee.uq.edu.au/smith/recent/declass.pdf), [cse.chalmers.se publications](http://www.cse.chalmers.se/~andrei/publications.html)).

### 4.2 Robust declassification: the attacker must not steer the release

Zdancewic & Myers ("Robust Declassification," CSFW 2003) and Myers, Sabelfeld & Zdancewic ("Enforcing Robust Declassification," CSFW 2004; JCS 14(2), 2006) add the key integrity property: a program is *robust* if an attacker's low-integrity inputs **cannot influence what gets declassified** — the declassification mechanism can't be "controlled by attackers to release more information than intended," enforceable by a type-based compile-time analysis ([cs.cornell.edu PDF](http://www.cs.cornell.edu/andru/papers/robdecl-jcs/robdecl-jcs.pdf)).

*The paraphrase sting:* robust declassification assumes the *programmer* has already decided **what** may be released (the "escape hatches" of delimited release — Sabelfeld & Myers, ISSS 2003: `declassify` annotations marking exactly which expressions may flow out; [cse.chalmers.se](https://www.cse.chalmers.se/~andrei/sabelfeld-myers-isss03.pdf)). It says nothing about whether a *paraphrase* of a non-declassified value is "the same information" — the **what-dimension is semantic and is decided by declaration, not by analysis**. For an agent governance product, the honest translation is:

1. Every human approval of an external send is a **declassify annotation** (an escape hatch). Robustness then requires that *the agent must not be able to influence which escape hatch the human thinks they're approving* — i.e., the approval must bind the *actual payload bytes*, not the agent's description of them, and the approver must see the payload's taint provenance (cf. §3.2).
2. There is **no information-theoretic test for "is this paraphrase the same information as that source"** inside the IFC literature — equivalence classes of meaning are declared by policy, not discovered by analysis. Anyone selling an automatic paraphrase-equivalence detector is selling research, not a primitive.

### 4.3 Quantitative information flow: the right math for "how much leaked"

Quantitative Information Flow (QIF) replaces the binary leak/no-leak question with *how much*: for a deterministic program under a uniform prior, **min-entropy leakage = log₂(|image(f)|)** — the log of the number of distinct observable outputs (Smith 2009; [uni-muenster.de slides](https://www.uni-muenster.de/IFIP-WG22/Web/meeting/Lisbon13/boreale.pdf)). The min-entropy leakage is the log of the multiplicative Bayes leakage, comparing adversary prior vs. posterior vulnerability ([trustworthy.systems](https://trustworthy.systems/publications/papers/Alvim_KMMPS_19.pdf)). Relatedly, Alvim et al. showed that ε-differentially-private mechanisms have min-entropy leakage bounded above by a function of ε and the output range size — noise mechanisms *provably cap* leakage ([alvim2015, via QIF lecture notes](https://homepages.dcc.ufmg.br/~msalvim/courses/qif/Lecture06_Chap06-Robustness[still])).

*Product translation:* you cannot measure the semantic leakage of one paraphrased egress, but you **can** bound the *capacity* of the egress channel: cap the number/length of external sends per sterile window (a volume bound on |image(f)|), and the QIF math tells you the worst-case min-entropy leakage of that window is log of the observable output space. This is the theoretical backbone for P1 below.

---

## 5. Semantic-similarity egress checks: what exists, what it costs

### 5.1 Fuzzy hashing (ssdeep, TLSH, Nilsimsa): syntactic similarity, honest numbers

Similarity digests are the deployed technology for "near-duplicate" detection (malware triage, spam):

- Trend Micro's TLSH whitepaper ("TLSH — A Locality Sensitive Hash") reports, on a spam-image corpus: at distance threshold <100, **6.43% false-positive rate with 94.5% detection**; at threshold <30, **0.00181% FP but only 32.2% detection** ([documents.trendmicro.com](https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf)).
- An independent replication found ssdeep/TLSH "reasonably effective" on rotated/stretched images but **ineffective against combined adversarial manipulations**; ssdeep needs ~9–13% common content minimum to register any relation on random files ([github.com/trendmicro/tlsh Attacking_LSH_and_Sim_Dig.pdf](https://github.com/trendmicro/tlsh/raw/refs/tags/5.0.0/Attacking_LSH_and_Sim_Dig.pdf), [arxiv.org DLAM paper](https://arxiv.org/pdf/2208.11367v3.pdf)).

*Honest costs:* these are **byte/n-gram-level** measures. Paraphrase — synonym replacement, reordering, summarization — is *exactly* the adversarial manipulation class they fail on. They are IDM-grade (catch derived copies), not semantic-grade. No published precision/recall exists for adversarial-paraphrase detection with fuzzy hashes, because the primitive doesn't operate at that level.

### 5.2 Embedding-based semantic checks: research-grade, no deployed per-secret precedent found

The only deployed "semantic" egress-adjacent technology found is category-level (Nightfall's LLM secret-type detectors, §1.4). A **per-egress semantic comparison of a specific sensitive record against its suspected paraphrase** — the thing the question asks about — has **no deployed precedent found** in vendor docs, and no published precision/recall for adversarial paraphrase. Academic paraphrase-detection with small embedding models reaches respectable F1 on *non-adversarial* paraphrase corpora but is not evaluated against an adversary optimizing to evade it; per Iglesias Vázquez's finding (§2.2), anomaly-style detectors fail and supervised similarity-to-known-schemes is required. Any embedding-based primitive built pre-freeze must therefore be framed as *weak-signal triage*, never as a verdict.

### 5.3 k-anonymity / differential privacy: the "release shape" alternative

The one old idea that *does* handle "release a derivative of sensitive data" rigorously is to change the release shape: k-anonymity (each released record indistinguishable among k) and differential privacy (bounded leakage per release, cf. Alvim et al. §4.3). For agent egress this suggests *structured-release templates* (P1's sterile-window restriction): if external sends during sensitive windows are limited to pre-registered aggregate/template shapes, the release is analyzable. This is a policy-shape control, not a content detector — and it's the only approach in this section with actual theorems behind it.

---

## 6. Candidate primitives, ranked by pre-freeze viability ($0, local compute, no LLM)

Constraints honored: no paid APIs, no LLM calls, runs on local CPU inside the existing policy engine / audit log.

### P1 — Sterile egress windows (sterile cockpit × covert-channel capacity bounding) ★ highest viability

**The primitive.** A runtime *phase* flag, derived from existing taint tracking: the moment the agent reads a source carrying a sensitive taint, a **sterile window** opens. Inside the window, external egress actions (`http_post`, `api_call`, `send_email`, …) may only fire with **pre-registered structured payload templates** (fixed schema, no free-text bodies) or are diverted to the human approval queue with mandatory provenance display; free-form external sends are denied fail-closed. The window closes at a task boundary or after an egress-quiet cooldown, and closure is chained into the audit log. Optionally, cap sends-per-window (a QIF capacity bound: worst-case min-entropy leakage of the window is log of the observable output space).

**Old ideas recombined.** FAA sterile cockpit rule (phase-based restriction, §3.1) + Shannon/Kemmerer channel-capacity bounding (§2.3) + Sabelfeld & Sands' *when* dimension of declassification (§4.1).

**Why it fits pre-freeze.** Pure policy-engine + taint-flag work; no new detectors, no models, no tuning. It composes with the existing memory-firewall/quarantine machinery.

**Honest ceiling.** It does not *detect* semantic exfil — it *contains the channel*. Legitimate summarize-and-send workflows pay a cost (forced through templates or approval). An agent that paraphrases *before* the window opens (taint laundering across windows) evades it; window-closure criteria must be conservative. False-positive cost is workflow friction, not alerts.

### P2 — Canary-fact tripwires inside sensitive sources (honeytokens × IDM partial matching) ★ high viability

**The primitive.** Plant **synthetic canary records** inside sensitive datasets the agent reads: a fake customer row, a fake credential-shaped token, a fake account number — values that are unique, syntactically valid, and *useless except as tripwires* (the honeytoken/canary-token tradition: any use is proof of compromise because no legitimate flow touches them — [owasp.org](https://github.com/owasp/www-community/blob/HEAD/pages/controls/Web%20Application%20Deception%20Technology.md); CISA's September 2026 guidance now recommends cyber decoys for exactly this "assume breach, catch them inside" posture, reported at [thetechedvocate.org](https://www.thetechedvocate.org/unprecedented-cisas-radical-plan-to-trap-hackers-inside-critical-networks-2/)). At egress, check payloads for the canary values *and* their fuzzy variants (TLSH/Nilsimsa chunk digests à la IDM partial matching, §1.1) — a hit is a near-zero-FP incident: the canary only exists in the sensitive source.

**Old ideas recombined.** Honeytokens/canary tokens + IDM-style derived-content fingerprinting + the covert-channel lesson that you detect the *trap*, not the *encoding*.

**Why it fits pre-freeze.** Data, not code: canary records are planted in fixtures/datasets; the check is the existing verbatim-correlation + a small fuzzy-digest comparison. Near-zero FP by construction.

**Honest ceiling.** Paraphrase defeats fuzzy matching of the canary *sentence* (same limits as §5.1: below ~10% shared n-grams, no signal). The robust core is the **unparaphrasable canary**: identifiers that must appear verbatim to be useful (API-key-shaped strings, UUIDs, account numbers) — paraphrasing them destroys their value, so the exfiltrator must emit them exactly, where the tripwire fires. Canaries detect *that this source's content left*, not *which real record* was paraphrased. Coverage is probabilistic: P(detect) scales with canary density and the adversary's inability to distinguish canary from real (plant enough, plant well).

### P3 — Provenance-annotated declassify approvals (robust declassification × maker–checker) ★ medium-high viability

**The primitive.** Treat every human approval of an external send as a **`declassify` escape hatch** (delimited release, §4.2) and enforce the two halves of robustness: (a) the approval **binds the exact payload bytes** (hash in the approval record; agent cannot substitute after approval — the "attacker must not steer the release" property of Myers/Sabelfeld/Zdancewic); (b) the approval UI **shows the payload's taint provenance** — which sensitive sources were in the agent's working set when the payload was built, plus a paraphrase-risk flag derived from P1's window state. Urgency may accelerate review, never bypass it (the BEC maker–checker rule, §3.2): no auto-approve fast path is valid inside a sterile window.

**Old ideas recombined.** Robust declassification's *who/what* dimensions + ACFE/BEC maker–checker + delimited-release escape hatches.

**Why it fits pre-freeze.** Builds on the existing approval queue; it's UI/record-schema work plus a no-substitution invariant in the executor.

**Honest ceiling.** The human is the weakest link (the Samsung-2023 paste incident class: legitimate users exfiltrate through authorized channels routinely — [nohack.net](https://nohack.net/ai-privacy-risks-enterprise-security-2026/)). Provenance display helps diligent approvers and creates an audit trail; it does not stop a rubber-stamping approver. Measure it as *decision-quality improvement*, not as a detector.

### P4 — IDM-lite: chunk-level similarity digests of sensitive sources at egress (Symantec IDM, rebuilt locally) ★ medium viability

**The primitive.** At index time (when a sensitive source is read), compute per-chunk locality-sensitive digests (TLSH or Nilsimsa over normalized token shingles) and store them in the run's taint record. At external egress, digest the payload's chunks the same way and compare; a chunk pair under the TLSH distance threshold raises a *triage* signal (never a verdict). This is Symantec IDM's "derived content" detection (§1.1) rebuilt with open primitives on local CPU.

**Old ideas recombined.** IDM partial-match fingerprinting + Nilsimsa/TLSH similarity digests (§5.1), with the supervised-reference-set lesson from §2.2 (thresholds tuned against the repo's own red-team paraphrase battery, not against a generic corpus).

**Why it's only medium.** Real engineering: chunking, normalization, digest store, threshold tuning, FP measurement on benign traffic. Pre-freeze it's a stretch goal; post-freeze hardening is more realistic.

**Honest ceiling.** Catches copy-paste derivatives and weak paraphrase; **fails against deliberate rewording** (synonym replacement + reordering pushes chunk digests apart — the documented adversarial-ineffectiveness class of §5.1). Published FP/detection trade-offs (TLSH: 6.43% FP at 94.5% detection on spam corpora — [documents.trendmicro.com](https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf)) are for near-duplicate corpora, *not* paraphrase, and will be worse here. Frame as weak-signal triage feeding P3's provenance display, never as a block verdict.

### P5 — Local small-model semantic scorer (embeddings, CPU) ★ research-grade; do not ship as a control

**The primitive.** A tiny open-weights sentence-embedding model run locally (no API, no LLM calls in the product sense) computing cosine similarity between egress chunks and sensitive-source chunks, thresholded as triage signal.

**Honest ceiling — why it ranks last.** No deployed precedent and no published precision/recall for *adversarial* paraphrase evasion (§5.2); per the covert-channel literature, anomaly-style detectors fail and only supervised similarity-to-known-schemes works (§2.2) — a generic embedding threshold is the anomaly-style approach. Small models are the easiest to evade with targeted rewording, and every threshold is a precision/recall knife-fight on benign traffic (summaries of public docs will light it up). If built at all, build it as a *research battery instrument* (score the red-team's paraphrase corpus, publish the ROC), not as a shipped gate. The $0/local constraint is satisfiable; the *epistemic* constraint is not: we would be shipping a number we cannot defend.

---

## 7. What the recombined design looks like (one paragraph)

Stop trying to out-scan the paraphrase. The warden that inspects *content* loses to a paraphrase-capable encoder by construction (Simmons, §2.1); the enterprise DLP industry has accordingly never shipped a per-secret paraphrase detector (§1). The viable design is a **channel discipline**, not a content oracle: (1) **sterile windows** bound *when* and *how much* may leave once sensitive content is in the working set (P1 — the capacity bound, with QIF math behind it); (2) **canary facts** planted in sensitive sources turn any verbatim-or-near leak into a zero-FP incident (P2 — the tripwire, which needs no semantics because the bait is synthetic); (3) every external send is a **declared declassification** whose approval binds exact bytes and displays taint provenance to the human checker (P3 — robust declassification + maker–checker); (4) chunk-digest similarity runs only as **weak-signal triage** (P4), and embedding-based scoring stays in the **research battery** until someone publishes adversarial precision/recall (P5). Each layer is $0, local, and honest about what it cannot do — which is exactly what the current verbatim-DLP stack cannot say about itself.

---

## Sources

- Microsoft Learn, "Increase classifier accuracy" (trainable-classifier feedback scope & limits). <https://learn.microsoft.com/en-us/purview/data-classification-increase-accuracy>
- Microsoft Learn training, "Implement document fingerprinting" (fingerprint SIT strictness, 150 KB / ~50-fingerprint limit). <https://learn.microsoft.com/en-us/training/modules/create-manage-sensitive-information-types/5-implement-document-fingerprint>
- Proofpoint, "From Reactive to Proactive: Using AI to Classify and Protect Data" (pre-trained LLM classifiers; self-documented limits). <https://www.proofpoint.com/uk/blog/dspm/ai-data-classification-proactive-data-protection>
- Proofpoint, *Insider Threat Management and Cybersecurity Tools* ebook (ML/UBA "not yet advanced enough"). <http://proofpoint.com/sites/default/files/e-books/gtd-pfpt-us-eb-itm-cybersecurity.pdf>
- Oyster Technologies, "Symantec DLP" (IDM derived-content detection, VML statistical analysis, EDM, DCM). <https://oyster-technologies.com/symantec-dlp-benefit/>
- chrishuffman5/agents, Symantec DLP SKILL.md (IDM 10–20% partial thresholds; VML 50+/50+ training docs). <https://github.com/chrishuffman5/agents/blob/HEAD/skills/security/dlp/symantec-dlp/SKILL.md>
- Nightfall AI research report (LLM/transformer secret-type detectors; vendor precision claims). <https://www.thaiaiaudit.com/content/files/2025/09/Nightfall-AI-research-report.pdf>
- Nightfall for GitHub one-pager ("beyond regexes, entropy, and search strings"). <https://www.wisdominterface.com/wp-content/uploads/2024/03/Cloud-Native-Data-Leak-Prevention-for-Github.pdf>
- Simmons, G. J., "The Prisoners' Problem and the Subliminal Channel," CRYPTO '83 (via Petitcolas annotated bibliography). <https://petitcolas.net/steganography/bibliography/Annotated_Bibliography.pdf>
- Shannon, C. E., "A Mathematical Theory of Communication," Bell System Technical Journal, 1948 (channel capacity). <https://monoskop.org/images/a/ae/Shannon_Claude_E_A_Mathematical_Theory_of_Communication_1957.pdf>
- UTC paper, "Network Covert Channels on the Android Platform" (regularity vs. shape detection; Cabuk variance tests; K-S and entropy tests). <https://www.utc.edu/sites/default/files/2021-04/paper-csiirw-wade-covert.pdf>
- Zander/Armitage/Branch survey bib via IJECE (covert-channel countermeasure taxonomy; Kemmerer 2002). <https://ijece.iaescore.com/index.php/IJECE/article/download/26408/15784>
- Iglesias Vázquez, Annessi & Zseby, "Analytic Study of Features for the Detection of Covert Timing Channels" (anomaly detection insufficient; supervised/semi-supervised required). <https://journals.riverpublishers.com/index.php/JCSANDM/article/download/5245/4583?inline=1>
- PMC, "Covert Timing Channel Analysis Either as Cyber Attacks or Confidential Applications" (detectability threshold ≈ 2× mean legitimate inter-arrival). <https://pmc.ncbi.nlm.nih.gov/articles/PMC7219501/>
- FAA, "The Sterile Cockpit" (FAR 121.542/135.100 text; 1981 rule; critical phases incl. below 10,000 ft). <https://www.faasafety.gov/files/events/GL/GL05/2008/GL0520920/The_Sterile_Cockpit.pdf>
- Wikipedia, "Sterile flight deck rule" (rule scope Part 121/135). <https://en.wikipedia.org/wiki/Sterile_flight_deck_rule>
- Nextgov, "Why the 'two-man rule' is only the beginning" (NSA two-man rule; nuclear analogy). <https://www.nextgov.com/cybersecurity/2013/07/why-the-two-man-rule-is-only-the-beginning/211391/?oref=ng-author-river>
- Entrust, "Secondary Approval or 'The Two-Person Rule'" (AFI 91-104; approval workflow). <https://www.entrust.com/sites/default/files/documentation/solution-briefs/dps-secondary-approval-sb.pdf>
- ACFE fraud-conference materials via fraudconference.com (segregation of duties; two-manager authorization). <https://fraudconference.com/uploadedFiles/Fraud_Conference/Content/Course-Materials/2a-goldmann-cpp.pdf>
- Adaptive Security, BEC payment-verification checklist (dual approval; independent-channel callback; urgency accelerates review, never bypasses). <https://www.adaptivesecurity.com/blog/business-email-compromise-payment-verification>
- Myers, Sabelfeld & Zdancewic, "Enforcing Robust Declassification and Qualified Robustness," J. Computer Security 14(2), 2006. <http://www.cs.cornell.edu/andru/papers/robdecl-jcs/robdecl-jcs.pdf>
- Sabelfeld & Sands, "Declassification: Dimensions and Principles," CSFW 2005 / JCS 17(5), 2009 (what/where/who/when; publication record). <http://www.cse.chalmers.se/~andrei/publications.html> and dimension summary <https://staff.itee.uq.edu.au/smith/recent/declass.pdf>
- Sabelfeld & Myers, "A Model for Delimited Information Release," ISSS 2003 (escape hatches). <https://www.cse.chalmers.se/~andrei/sabelfeld-myers-isss03.pdf>
- Boreale, "An introduction to Quantitative Information Flow" (min-entropy leakage = log|image(f)|, Smith 2009). <https://www.uni-muenster.de/IFIP-WG22/Web/meeting/Lisbon13/boreale.pdf>
- Alvim et al., "An Axiomatization of Information Flow Measures" (min-entropy leakage as log of multiplicative Bayes leakage). <https://trustworthy.systems/publications/papers/Alvim_KMMPS_19.pdf>
- Trend Micro, "TLSH — A Locality Sensitive Hash" (threshold/FP/detection trade-offs). <https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf>
- Trend Micro, "Attacking LSH and Sim Dig" (ssdeep/TLSH adversarial-ineffectiveness classes). <https://github.com/trendmicro/tlsh/raw/refs/tags/5.0.0/Attacking_LSH_and_Sim_Dig.pdf>
- OWASP, "Web Application Deception Technology" (honeytoken taxonomy). <https://github.com/owasp/www-community/blob/HEAD/pages/controls/Web%20Application%20Deception%20Technology.md>
- The Tech Edvocate, "CISA's Radical Plan to Trap Hackers Inside Critical Networks" (2026-09-16 CISA cyber-decoy guidance; secondary reporting). <https://www.thetechedvocate.org/unprecedented-cisas-radical-plan-to-trap-hackers-inside-critical-networks-2/>
- LinkedIn, "AI Data Loss Prevention vs. Traditional DLP" (context-window transformation defeats hash/exact-match rules). <https://www.linkedin.com/pulse/ai-data-loss-prevention-vs-traditional-dlp-why-agents-need-8goec>
- SAF-M-72 mitigation notes (derived/aggregate leakage; pair output DLP with query-shape and purpose controls). <https://github.com/secure-agentic-framework/saf-mcp/blob/HEAD/mitigations/SAF-M-72/README.md>
- Medium/@ahmed.monsry, "Understanding Classification in Microsoft Purview" (SITs cannot detect meaning/intent; EDM precision/coverage trade-off — secondary summary of Microsoft docs). <https://medium.com/@ahmed.monsry/understanding-classification-in-microsoft-purview-f5c2cfa52645>
