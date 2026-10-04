# Wave-330 Industry Prospectus: Sandboxing, PQC, Agent-Protocol Auth, Regulator Incident Artifacts

**Date:** 2026-10-04 · **Base:** `8c4f6139` (wave-329 merge, footer open F414 / next F415, pin 2058)
**Method:** four parallel research subagents on primary sources only (spec texts, source code, first-party docs, LICENSE files). Every factual claim carries URL + access date 2026-10-04.
**Standing rule honored:** for every STEAL verdict, the tree was checked first (`grep gov/ evals/`) — a steal of something we already have is a SKIP-with-evidence.

## Prior-prospectus avoidance

Covered before (not repeated here): TUF/in-toto/Sigstore/ORAS/Harbor supply chain (w306, w308, w320, w325); Rekor-pattern witness + monitor loop (w321); offline verifier + auditor UX (w310); threshold custody incl. FROST landscape (w319; Shamir custody landed wave-328 lane 3); agent identity/discovery incl. dex, SPIFFE, keto, Cedar (w318, plus MEMORY.md 2026-09-29); evidence next steps (w317); trusted-transform laundering (w315); provenance-sink quarantine (w313); compositional defense (w309); runtime attestation (w307).

---

## 1. Runtime sandboxing precedents — Landlock is the steal

| Target | Verdict |
|---|---|
| Landlock (Linux LSM, kernel 5.13+) | **STEAL** |
| gVisor seccomp-bpf allowlist pattern | **STEAL** (pattern; SKIP the Sentry) |
| nsjail declarative policy shape | **STEAL** (shape; not the binary) |
| Bubblewrap userns mount-tree | **ADAPT** (phase 2; LGPL-2.1 flag — do not vendor) |
| Firecracker microVMs | **SKIP** (WATCH long-term) |

**Why Landlock wins.** It is a *stackable* LSM letting any *unprivileged* process restrict its own filesystem access via three syscalls: `landlock_create_ruleset` (444), `landlock_add_rule` (445), `landlock_restrict_self` (446) on x86_64 (torvalds/linux `arch/x86/entry/syscalls/syscall_64.tbl`; Landlock kernel docs https://docs.kernel.org/6.6/userspace-api/landlock.html). ABI probe is one syscall (`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns 1..N, ENOSYS = absent). ABI evolution: v1 (5.13+, FS) · v2 (5.19+, REFER) · v3 (6.2+, TRUNCATE) · v4 (6.7+, TCP bind/connect) · v5 (6.10+, IOCTL_DEV) · v6 (6.12+, signal/abstract-socket scoping). Enforcement is **irreversible, inherited by descendants, stackable** (each layer only further restricts).

This directly closes `gov/sandbox.py`'s honestly-documented gap ("temp-dir cwd is NOT a chroot/filesystem jail"): no root, no namespaces, no external binaries, no new dependencies — a plain Python process does it via `ctypes`. Fail-closed: ENOSYS → report `landlock=unsupported` → refuse exec when policy demands it. ABI version + enforcement result go in the audit log (same honest-reporting discipline as our namespace reporting).

**What we'd build:** `gov/landlock.py` (stdlib-only ctypes) + a `RulesetBuilder` on the nsjail-shaped `SandboxPolicy`: `/usr /lib /lib64` read+execute, workdir read+write, `/dev/null|zero|urandom` read, everything else deny-by-default; ABI v4+ TCP `handled_access_net` restricted to declared egress ports (default none) — network teeth without a netns. Enforce in the tool-executor's `preexec_fn`: `prctl(NO_NEW_PRIVS)` → `landlock_restrict_self` → exec; abort + log refusal if enforcement fails. Caveats to pin in tests (from the kernel doc): rules bind path hierarchies via fds (bind mounts propagate, OverlayFS layers are standalone); applies per-thread (apply before spawning workers).

**License:** kernel code is GPL-2.0, but user-space syscall use does not extend GPL obligations (Linux-syscall-note; torvalds/linux `Documentation/process/license-rules.rst`). No code copied — own ctypes binding. No trap.

**Falsifiable next step:** `gov/landlock.py` + break-first battery: child restricted to workdir gets EACCES writing outside; ABI-v4 child with no net rules fails `connect()`; kernel <5.13 reports unsupported and refuses when policy demands. Check `uname -r` on this VM first.

**gVisor (STEAL pattern):** google/gvisor docs (`g3doc/architecture_guide/intro_to_gvisor.md`) show the Sentry itself runs under a restrictive seccomp filter as defense-in-depth — and warn a *generic* allowlist "will result in needing to allow all or most of the kernel surface." The steal: a curated seccomp-bpf allowlist (~30–40 syscalls) installed via `ctypes` `seccomp(2)` in `preexec_fn`, default `SCMP_ACT_ERRNO(EPERM)` (fail-closed), per-tool-profile allowlists not one global policy. Apache-2.0 (LICENSE, accessed 2026-10-04); pattern only, no code. Phase 2 with Landlock.

**nsjail (STEAL shape):** google/nsjail `config.proto` is the right declarative surface — namespace booleans, `MountPt` (src/dst/fstype/options/rw/nosuid/nodev/noexec), rlimits (`resource.setrlimit` in preexec_fn, stdlib), cgroup caps, `no_new_privs`, Kafel seccomp policy field. Mirror as a `SandboxPolicy` dataclass; add `policy_to_report()` dumping it into the audit log — the policy *is* the evidence of declared intent. Apache-2.0 (LICENSE pinned at d6454b4, accessed 2026-10-04). Do not shell out to nsjail (external dep, violates stdlib-only).

**Bubblewrap (ADAPT, phase 2):** userns mount-tree construction is reproducible in our own ctypes, but unprivileged userns is gated by distro hardening (RHEL disables; Ubuntu 24.04+ AppArmor userns profiles). **License FLAG:** LGPL-2.1-or-later (NEWS.md 0.12.0, 2026-08-26) — do not vendor, do not shell out. Optional phase 2 behind a feature probe, fail-closed to Landlock-only.

**Firecracker (SKIP):** needs `/dev/kvm` (absent on our cloud VMs), root for TAP/cgroups, guest kernel+rootfs pipeline, Rust control plane — violates every product constraint. Apache-2.0, no trap, irrelevant. WATCH condition: revisit only if a paying multi-tenant hostile-code tier exists (today: no).

---

## 2. Post-quantum signatures — make the envelope agile, keep the signer classical

| Target | Verdict |
|---|---|
| ML-DSA (FIPS 204, final Aug 2024) | **ADAPT** (algorithm-agility now; signer later) |
| SLH-DSA (FIPS 205) | **SKIP** (signatures 7.8–49.9 KB; diversity hedge only) |
| Hybrid composite signatures (draft-ietf-lamps-pq-composite-sigs) | **ADAPT** (two-slot, both-must-verify pattern) |
| dilithium-py spike | **WATCH** (MIT, KATs pass, but non-constant-time educational code) |
| 2026 PQC CVEs | STEAL the *probe patterns*, not the math |

**The numbers (primary, FIPS-consistent):** ML-DSA-44: sk 2560 / pk 1312 / **sig 2420** bytes; ML-DSA-65: 4032/1952/**3309**; ML-DSA-87: 4896/2592/**4627**. ML-DSA-65 is NIST's recommended default; 44 is Sigstore's consensus choice ("sufficient for PQC signing"). SLH-DSA: pk 32–64 bytes but signatures 7,856 (128s) → 49,856 (256f) — not a daily-signing candidate.

**Sigstore PQC is not production-usable.** sigstore/cosign#4960 (opened 2026-06-21): cosign cannot generate ML-DSA keys, sign, or verify. Done: protobuf-specs ML-DSA enum IDs (21/22/23, *Experimental*); sigstore-go ML-DSA Keypair interface. The w321 note's Tessera/MTC ML-DSA-44 claim was overstated: protobuf-specs commit 5ead98a (2026-03-30) says the witness network is *likely* to use ML-DSA-44 — planned, not deployed. **There is nowhere to ship ML-DSA signatures today** (Rekor would reject ML-DSA entries). Ecosystem: Go 1.27 added `crypto/mldsa` to stdlib; Python has no stdlib PQC — the gap is ours to own.

**Hybrid migration path (ADAPT):** draft-ietf-lamps-pq-composite-sigs (v19, RFC Editor process mid-2026) defines e.g. `COMPSIG-MLDSA65-ED25519-SHA512` (3,373-byte sig; **both components must verify**, protocol-transparent). X-Wing (RFC 9496) is the ratified hybrid *pattern* but is a KEM, not signatures. Confirms our `gov/shamir_custody.py` note: nothing PQ has aggregate/threshold properties — FROST's PQ gap stands (w319).

**2026 CVEs — none PQC-math, all verifier-logic (our threat class):** CVE-2026-22703 (cosign accepted *any* valid Rekor entry not bound to the artifact — fixed 2.6.2/3.0.4); CVE-2026-39395 (`verify-blob-attestation` false "Verified OK" on malformed attestations — fixed 3.0.6/2.6.3); CVE-2026-23831 (Rekor COSE nil-pointer panic); sigstore-java missing `integratedTime`-vs-Fulcio-validity (expired certs verify); liboqs CVE-2026-46344/44518 (OOB read in XMSS verification, parameter-set confusion — the class a hand-rolled ML-DSA port could reproduce). **No ML-DSA-specific CVE in 2026.** Cloudflare's 2026-06-10 ML-DSA outage: PQ rollouts break on policy/profile details (KeyUsage), not the math.

**Pure-Python feasibility:** GiacomoPope/dilithium-py — **MIT verified from the LICENSE file** (github.com/yubozhang/dilithium-py/blob/master/LICENSE), passes final-standard NIST KATs (ACVP-Server 1.1.0.35), stdlib-clean path exists (skip pycryptodome test DRBG via `os.urandom`; `hashlib` shake fallback); benchmarks ~29 ms sign / 8 ms verify (likely with Rust XOF; pure-stdlib estimate 100–300 ms sign — adequate for control-plane rates). **Blockers:** README's explicit "not for cryptographic applications, not constant-time" disclaimer (violates our break-first discipline); needs fail-closed RNG; 2,420-byte sigs are ~38× Ed25519 with nowhere to ship; we own every line of lattice code including side-channel surface. Second candidate dheeraj-1103 (MIT verified, "pure Python, zero-dependency") has weaker provenance.

**Falsifiable next steps:**
1. (This wave, format-only) Add a reserved PQ signature slot to the evidence envelope: classical Ed25519 authoritative, PQ slot reserved, per the composite both-must-verify pattern. Costs nothing; avoids a format break when Sigstore's ML-DSA enums leave "Experimental."
2. (Spike, no product code) GiacomoPope/dilithium-py: pure-stdlib KAT pass + timing-fuzz for secret-dependent branches. Gate: full ACVP KAT set stdlib-only AND bounded constant-time gaps → hardening lane justifiable; else PQ stays WATCH.
3. (Red team) Port CVE-2026-39395 ("false Verified OK") and CVE-2026-22703 ("unbound transparency entry") as probe classes against `gov/sigstore_bundle.py`'s verifier.

---

## 3. Agent-to-agent protocol auth — MCP client OAuth hardening is the lane

Checked against the tree first: `gov/agent_cards.py` (A2A v1.0.0 §8.4 signed-card verifier), `gov/mcp_oauth_binding.py` (sealed issuer binding), `gov/elicitation_contract.py` (MCP elicitation RC adaptation), `gov/delegation_tokens.py` (RFC 8707 internal) — all present. The gaps are what's *new* or *never covered*:

| # | Gap | Verdict |
|---|---|---|
| 1 | RFC 9207 authorization-response `iss` validation on MCP client path — spec 2026-07-28 MUST; our binding validates issuer on discovery but not on the response leg (AS mix-up shape accepted today) | **ADAPT** |
| 2 | RFC 8707 `resource` parameter on MCP OAuth authorization+token requests; servers MUST NOT accept/transit other tokens — zero resource/audience logic in `mcp_oauth_binding.py`/`mcp_invocation_authz.py` | **ADAPT** |
| 3 | A2A client auth-scheme posture: signed cards advertising deprecated `implicit` flow, authz-code without PKCE, oauth2 without `oauth2MetadataUrl` pass our verifier silently (§4.5.4/4.5.7/4.5.8) | **ADAPT** (pairs with future A2A client work) |
| 4 | A2A push-notification webhook security (§13.2): SSRF allowlist + single-purpose per-config tokens + idempotent receiver; reference SDK's sender fetches `pushConfig.url` with zero host validation (guardbee a2a-auditor) | **ADAPT** |
| 5 | A2A in-task auth (§7.6.3): credentials bound to + readable-only-by the originator; our `delegation_tokens.py` has `aud` but no originator-confidentiality/PoP (grep encrypt/cnf/DPoP: empty) | **ADAPT** (mechanism steal) |
| 6 | A2A task authorization scoping (§13.1): check-before-query, one 404 for nonexistent+unauthorized (existence-leak rule) — not pinned anywhere | **ADAPT** (cheap test rule) |
| 7 | MCP elicitation **URL mode** (new in 2026-07-28, after our RC adaptation): sanctioned out-of-band path for secret-bearing flows; our contract pins the negative (no secrets in-band) but offers no legal channel | **ADAPT** |
| 8 | MCP step-up authorization (403 `insufficient_scope` → scope-union → retry-limit) | **ADAPT** (backlog; SHOULD-level) |
| 9 | AP2 (Agent Payments Protocol) v0.2, FIDO Alliance — Verifiable Intent as signed-mandate evidence primitive | **WATCH** (payment-domain; track, don't build) |
| 10 | MCP sampling | **SKIP** (deprecated 2026-07-28; maximally risky) |

Sources: A2A spec v1.0.0 https://a2a-protocol.org/v1.0.0/specification/ (+ v1.0.1 patch 2026-05-26, no security deltas); MCP authorization/elicitation specs rev 2026-07-28 https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization and .../client/elicitation; AP2 https://github.com/google-agentic-commerce/AP2 (Apache-2.0; note ap2-protocol.org/specification/ 404'd 2026-10-04 — use the repo).

**Strongest lane: "MCP client OAuth hardening"** — RFC 9207 `iss` + RFC 8707 `resource` into `mcp_oauth_binding.py` (gaps #1+#2). Both are spec-**MUST**s in the current revision, both absent, both slot into the sealed-issuer module without new architecture, both have crisp falsifiable probes. This is the exact AS-mix-up/token-mis-redemption class our GHSA-qx49 work defends against, left half-covered.

---

## 4. Regulator-accepted incident artifacts — the Art. 73/55 envelope is the steal

| Target | Verdict |
|---|---|
| Commission GPAI serious-incident template fields (Nov 2025) | **STEAL** |
| Art. 73(6) non-alteration duty (freeze-snapshot + notify-before-remediate) | **STEAL** |
| EU SEND CIA-triad submission envelope | **ADAPT** |
| MDF / Annex XI–XII field list (extend `crosswalk.py`) | **ADAPT** |
| Final Art. 73 guidance / NIST AI RMF revision | **WATCH** |
| Own incident portal / own taxonomy | **SKIP** |

**What the law says (official EUR-Lex text, Regulation (EU) 2024/1689, Art. 73, read 2026-10-04).** Who reports: providers of high-risk AI systems; deployers too — Art. 26(5): a deployer that identifies a serious incident must "immediately inform first the provider, and then the importer or distributor and the relevant market surveillance authorities." To whom: the MSA of the Member State *where the incident occurred*. Deadlines: **15 days** general (from awareness, after causal link or its reasonable likelihood); **2 days** for widespread infringement or Art. 3(49)(b) critical-infrastructure disruption; **10 days** for death (once causal relationship established or suspected). Incomplete initial report allowed, complete report follows (Art. 73(5)). Post-report duty (Art. 73(6)): investigate without delay, cooperate, and **no cause-affecting alteration of the system before informing the authorities** — an evidence-preservation rule. MSA acts within 7 days (Art. 73(8)). GPAI systemic-risk (Art. 55(1)(c)): "keep track of, document, and report, **without undue delay**, to the AI Office … relevant information about serious incidents **and possible corrective measures**" — corrective measures are an explicit report element.

**Timing (why this is a build-now asset):** GPAI obligations applied since 2 Aug 2025 (Art. 55 live now). High-risk obligations deferred by the Digital Omnibus on AI, Regulation (EU) 2026/1744 (OJ 24 July 2026): Annex III standalone → 2 Dec 2027, Annex I embedded → 2 Aug 2028.

**Report field shapes exist (no waiting needed):** GPAI serious-incident template published 4 Nov 2025, submitted via **EU SEND** (Commission: SEND "ensures the confidentiality, integrity, and authenticity of the information shared"). High-risk draft guidance + template v1.0.0 (Sept 2025) fields: receiving MSA; report/incident/detection/awareness dates; report type (initial / follow-up / combined / final reportable / final non-reportable); classification (death / health harm / critical-infrastructure management|operation disruption / fundamental-rights / property / environment / other); submitter role (provider / deployer / authorised representative / other) + contact. Final Art. 73 guidance: not found published as of 2026-10-04 (on the Commission's 2026 work programme). MDF (10 July 2025) + Public Summary Template (24 July 2025) are the AI Office's own GPAI documentation shapes. No EU-wide portal for Art. 73 — reports go to national MSAs individually. OECD AI Incidents Monitor is the Commission's alignment target, not a regulator portal.

**Our gaps (checked against the tree):** (1) no Art. 3(49) severity taxonomy → 2/10/15-day clock mapping, no **awareness timestamp** vs **causal-link timestamp** — without both we cannot prove timeliness; (2) no deployer→provider notification chain (Art. 26(5), incl. "deployer unreachable → Art. 73 mutatis mutandis"); (3) no Art. 73(6) freeze-snapshot + notify-before-remediate attestation; (4) no incident-report envelope mapping to the Commission template (report type, classification, submitter role, corrective measures); (5) no regulator-submission envelope (encrypted-to-authority, hash-chained, signed, with receipt); (6) no regime routing (Art. 73(9)–(10)). Annex XI/XII (GPAI) coverage in `crosswalk.py` unconfirmed — treat as gap until checked.

**NIST AI RMF (honest read):** RMF 1.0 (AI 100-1) names outcomes not artifacts — MANAGE 4.3: "Incidents and errors are communicated … processes for tracking, responding to, and recovering from incidents and errors are followed and documented." AI 600-1 (GenAI Profile, §A.1.8 "Incident Disclosure"): "Formal channels do not currently exist to report and document AI incidents" (July 2024). No 1.1/2.0 or public draft as of Sept/Oct 2026; AI 600-1 remains active (updated April 2026). **Implication:** because NIST specifies no artifact shape, *our* evidence bundle can be the shape — an incident-record schema satisfying MANAGE 4.3 that simultaneously emits Art. 73/55 fields is a differentiator, not a compliance risk. The EU side is where artifacts are legally load-bearing.

**Falsifiable next steps:** encode the GPAI template's field list as a JSON schema; red test that a bundle-derived report validates against it; simulate incident → remediation-before-notification must mark a violation (Art. 73(6)); round-trip regulator envelope through schema+signature verification with receipt in the audit log; checklist test asserting every Annex XI §1–§2 item maps to a bundle field or explicit gap.

---

## Prioritized build list (strongest first)

1. **`gov/landlock.py`** — stdlib ctypes Landlock ruleset builder on the nsjail-shaped `SandboxPolicy`, wired into the tool executor's `preexec_fn` (§1). Only candidate that closes an honestly-documented product gap (filesystem jail without chroot) with no root, no deps, honest degradation.
2. **Art. 73/55 incident-report envelope** — severity→clock mapping, awareness + causal-link timestamps, Commission-template field mapping, Art. 73(6) notify-before-alter attestation (§4). The one artifact every in-scope regulator will demand; timeliness is the element our bundle cannot evidence today and the element fines turn on. Ship Art. 55/EU SEND path first (live law), Art. 73 behind the same envelope (bites Dec 2027).
3. **MCP client OAuth hardening** — RFC 9207 `iss` response validation + RFC 8707 `resource` enforcement in `mcp_oauth_binding.py` (§3, gaps #1+#2). Spec-MUSTs, half-covered attack class, crisp probes.
4. **Evidence-envelope PQ slot** — reserved second signature slot, Ed25519 authoritative (§2). Format-only; avoids a future break.
5. **gVisor-pattern seccomp allowlist** — phase 2 with Landlock (§1).
6. **A2A in-task originator-opaque envelope + push-webhook SSRF rules** (§3, gaps #4+#5).
7. **MCP elicitation URL mode** — the sanctioned positive half of our no-secrets-in-band rule (§3, #7).
8. **MDF/Annex XI crosswalk extension** (§4).
9. **dilithium-py spike** (no product code) — pure-stdlib KAT + timing-fuzz gate (§2).
10. **WATCH:** cosign#4960 (Sigstore PQC), final Art. 73 guidance, NIST AI RMF revision, AP2 Verifiable Intent, Firecracker multi-tenant tier trigger.

## Explicit non-steals (tree-checked)

- Rekor-pattern witness (exists 3×: `gov/witness_rekor.py`, `gov/witness_log.py`, `gov/witness_consistency.py`) — SKIP-with-evidence.
- Sigstore bundle distribution (exists 2×: `gov/sigstore_bundle.py`, `gov/evidence_sigstore.py`) — SKIP-with-evidence.
- MCP elicitation form mode, A2A signed-card verification, MCP OAuth issuer binding, EU AI Act Annex III/IV crosswalk — all present; prospectus targets only their gaps.
- FROST threshold signing — deferred per w319 (no audit, no PQ); Shamir custody landed wave-328. No re-litigation.

## Open questions

- Landlock availability on the deployment kernels (`uname -r`; ENOSYS path) — measured in the build lane's first probe.
- Whether `gov/evidence/crosswalk.py` covers Annex XI/XII (GPAI) or only Annex IV — read before building §4 item 8.
- Final Art. 73 guidance publication date — re-run §4 gap analysis when it lands.
- AP2 specification canonical URL (ap2-protocol.org/specification/ 404'd 2026-10-04; GitHub repo is the stable primary source).
