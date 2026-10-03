# Prospectus — Runtime Attestation for Agent Execution Environments (Wave-307)

**Date:** 2026-10-03 · **Base:** `f6248a18` · **Remote verified reachable at start.**
**Theme:** how top companies and OSS projects prove *what code actually ran, in what environment, with what inputs* — and what Sasanam can steal for its "sell evidence, not the engine" thesis.
**Prior sweeps:** wave-303 (continuous authorization / heartbeat leases), wave-306 (skill/MCP supply-chain verification: in-toto+TUF Datadog composition and mpak MCPB format were the top STEALs).

## Ranked verdicts

### 1. SLSA provenance v1.0 + in-toto statements — STEAL (pattern/format)
The industry's converged vocabulary for "what was built from what, by whom, how." Provenance is an in-toto `Statement/v1` with `predicateType: https://slsa.dev/provenance/v1`: `subject` (artifact digests) + `predicate.buildDefinition` (build type, external/internal parameters, resolved dependencies with digests) + `predicate.runDetails` (builder identity, invocation timestamps). Build track runs L1–L3 only (L1 provenance exists; L2 signed; L3 non-falsifiable from a hardened builder).
- **Mechanism:** signed JSON claims about the build, verifiable offline, loggable to transparency logs.
- **Threat closed:** build tampering / artifact substitution — the consumer can check the artifact it received is the artifact the claimed builder produced from the claimed source.
- **Cost:** $0. Software-only. `actions/attest-build-provenance` and `slsa-framework/slsa-github-generator` emit it from CI today; `gh attestation verify` / `cosign verify` consume it.
- **License:** SLSA spec text is openly licensed (CC-BY-style spec license); in-toto is Apache-2.0. No code to vendor — we emit the *shape*.
- **Why STEAL:** our offline evidence bundle already carries integrity/monotonicity/containment claims; re-shaping its envelope as in-toto statements with SLSA predicates makes our evidence interoperable with the entire cosign/Sigstore/GitHub-attestations toolchain. It is the standard wire format for "evidence, not engine."
- **Honest limit:** provenance attests to the *build*, not the *run*. A runtime claim needs a runtime mechanism (see #3–#7).
- Sources: [SLSA v1.0 provenance explainer](https://github.com/yoonation/ai-grounded/blob/HEAD/governance-commons/attestation/slsa-v1.0-provenance.md), [SLSA+Sigstore practical guide](https://dev.to/kamal_namdeo/slsa-sigstore-and-provenance-complete-practical-guide-1bl5) ("in-toto = format of the claim, SLSA = what claims you need, Sigstore = how you sign/verify"), [Aegis-BPF SLSA verification runbook](https://github.com/kernel-guard/aegis-bpf/blob/HEAD/docs/compliance/SLSA_PROVENANCE.md).

### 2. Sigstore Rekor (transparency log) — STEAL (pattern) / ADAPT (instance)
Rekor is an append-only, tamper-evident ledger of signing events with inclusion proofs. The public instance is GA (1.0.0, semver-stable API) with a 99.5% availability SLO, operated as a public good — free to use; 100KB attestation upload limit (self-host for larger). The trust model: Fulcio binds an OIDC identity to an ephemeral keypair via short-lived X.509 (10-minute certs); Rekor witnesses the signature permanently, so verification works long after the cert expires. Crucially, **offline deterministic verification works**: with injected trust material and tlog thresholds at 0, verification is pure ECDSA + DSSE-PAE — no network, no Fulcio, no Rekor.
- **Mechanism:** signed inclusion promises (SCTs) + Merkle inclusion proofs over an append-only log.
- **Threat closed:** equivocation and after-the-fact forgery — a claim witnessed at time T cannot be rewritten or denied later.
- **Cost:** $0 (public instance) or self-hosted (Apache-2.0, raw LICENSE verified).
- **Why STEAL/ADAPT:** our hash-chained audit journal is already a *private* transparency log. The steal is the *witnessing* upgrade: SCT-shaped signed promises at claim time + third-party inclusion proofs for auditors. The offline-verification property matches our offline evidence-bundle philosophy exactly.
- **Honest limit (load-bearing):** a transparency log proves a claim was *registered*, never that it is *true*. As one practitioner README puts it: "a chain-valid, digest-bound attestation proves *which code* ran, never that the code's behavior matches the card's intent" — the semantic residue is permanent. Rekor is also append-only: no redaction, so PII-bearing claims must never go in.
- Sources: [Rekor repo (public instance GA, SLO, 100KB limit)](https://112.cachefly.net/sigstore/rekor), [Sigstore three-component explainer](https://medium.com/@shilu4577/if-you-trust-your-registry-you-have-a-problem-securing-ci-cd-with-sigstore-and-argocd-29ac9f061d6b), [glyph-protocol Sigstore attestation README (offline verification, semantic residue)](https://github.com/monoperro0207/glyph-protocol/blob/HEAD/packages/attestation-sigstore/README.md).

### 3. CNCF Confidential Containers Trustee (KBS/AS/RVPS) + RCAR — STEAL (pattern)
The cleanest OSS articulation of "verify at admission." Trustee has three cooperating services: **KBS** (Key Broker Service — orchestrates the handshake, conditionally releases secrets), **AS** (Attestation Service — verifies hardware evidence against reference values), **RVPS** (Reference Value Provider Service — holds the known-good measurements). The four-step **RCAR** handshake: (1) client posts TEE type + protocol version, (2) KBS returns nonce + session cookie, (3) client posts hardware evidence + ephemeral JWK + nonce bound to the evidence, (4) KBS returns a signed JWT (EAR attestation token); all subsequent resources are JWE-encrypted to the ephemeral key. TEE-agnostic: AMD SEV-SNP, Intel TDX/SGX, Arm CCA, IBM Secure Execution, TPM 2.0. Policy denies by default without valid TEE evidence.
- **Mechanism:** challenge→evidence→token→conditional-release; secrets are only ever released to attested guests, encrypted to keys bound to the evidence.
- **Threat closed:** secret exfiltration to unmeasured environments; operator snooping (the operator never sees plaintext).
- **Cost:** $0 software; real guarantees need TEE silicon.
- **License:** Apache-2.0 — verified from the raw LICENSE file.
- **Why STEAL:** the *protocol shape* is hardware-free and maps 1:1 onto our admission-point philosophy (wave-306 design rule: "verify at admission, not at scan"). Our evidence bundle + verifier can play the AS/RVPS roles; a skill/tool load can run the RCAR shape before receiving capabilities. Also directly composable with the wave-306 in-toto+TUF skill-verification direction: TUF delivers the reference values, Trustee-style handshake gates the release.
- Sources: [NVIDIA CoCo attestation docs (Trustee = KBS+AS+RVPS)](https://github.com/nvidia/cloud-native-docs/blob/HEAD/confidential-containers/attestation.rst), [CoCo blog: RCAR handshake + ai-gatekeeper KBS plugin for AI model endpoints](https://github.com/confidential-containers/confidentialcontainers.org/blob/HEAD/content/en/blog/2026/kbs_external_plugin.md).

### 4. GCP Confidential Space OIDC attestation tokens — ADAPT
Confidential Space runs a container in a confidential VM; measured boot + runtime measurements go into the vTPM's extend-only PCRs (early boot, kernel, container image, plus environment flags like "is a Confidential VM"). The vTPM quotes the PCRs with a certified attestation key; **Google Cloud Attestation verifies the quote, replays the event log, and issues a standard OIDC token** carrying the workload's claims — including `submods.container.image_digest` (an OCI image digest). Downstream, *everything is just CEL attribute conditions on token claims* via Workload Identity Federation: the token gates KMS decryption, service-account impersonation, audit trails. Token lifetime is one hour, auto-refreshed.
- **Mechanism:** measure once (silicon), convert to a standard bearer token (OIDC), enforce policy as data (attribute conditions).
- **Threat closed:** unmeasured workloads accessing confidential resources; confused-deputy via identity spoofing (claims are verifier-issued, not self-asserted).
- **Cost:** needs Confidential VM silicon for the measurements; the *token pattern* is free.
- **Why ADAPT:** "evidence as a token" is our thesis in Google's encoding. The steal is the **separation of measurement from consumption**: one verifier converts raw evidence into standard claims, and every downstream decision is a pure function of claims. Also a sharp fail-closed rule from a practitioner integration: measurements must compare like-with-like (a WCM HashValue is exactly `sha256:<64 hex>`, matching the OCI digest claim shape) — a measurement in any other shape is *refused*, not coerced.
- **Honest limit:** the measurements are only as good as the vTPM + Google's verifier; the token is only as fresh as its 1-hour lifetime.
- Sources: [Confidential Space security overview (attestation process)](https://docs.cloud.google.com/docs/security/confidential-space), [granting access to confidential resources (OIDC token + WIP conditions)](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources), [agentrust WCM↔Confidential Space mapping (measurement shape discipline)](https://github.com/agentrust-io/integrations/blob/HEAD/integrations/wcm-gcp-confidential-space/README.md).

### 5. swtpm + Keylime — STEAL (tooling for the $0 dev/CI loop)
**swtpm** (Stefan Berger's software TPM) speaks the real TPM 2.0 protocol — PCR extend/read, quote under a non-exportable AK with verifier nonce, seal/unseal to PCR policy — on any Linux machine with no TPM hardware. Practitioners document the honest limits precisely: swtpm's EK chains to a *self-signed CA* (no silicon authenticity), PCRs start blank (no real boot measurements unless you extend them yourself), no Secure Boot state, no side-channel resistance. What it *does* cover: quote signature correctness, PCR golden-digest computation, seal-to-PCR flows, verifier code paths, parallel attestation, replay-attack handling. **Keylime** provides the registrar/verifier/agent architecture (push model: agent initiates, egress-only) that consumes TPM quotes at fleet scale, with swtpm as its standard dev mode (`make swtpm` vs `make hwtpm`).
- **Mechanism:** real TPM 2.0 protocol without silicon; standard verifier architecture around it.
- **Threat closed (in dev):** verifier bugs, protocol regressions, policy misconfiguration — everything except hardware-rooted trust.
- **Cost:** $0. Pure software.
- **License:** swtpm is 3-clause BSD (© IBM Corporation) — verified from the raw LICENSE file. Keylime is Apache-2.0 (repo metadata; raw file not fetched this sweep).
- **Why STEAL:** this is the hardware-free on-ramp that keeps our $0-spend constraint honest. Build the verifier side against swtpm *now* (quote/seal/policy flows, nonce freshness, event-log replay), graduate to real TPMs later without changing the verifier. The documented limits double as our own honest-boundary language: "emulated hardware — real protocol, not a real hardware root of trust."
- Sources: [xnode-tpm-attest (emulator-mode coverage table)](https://github.com/johnforfar/xnode-tpm-attest), [swtpm-detector (why swtpm can never fake a vendor EK)](https://github.com/notrequiem/swtpm-detector/blob/HEAD/README.md), [Keylime push-model PoC (swtpm default, hwtpm via QEMU vTPM)](https://github.com/nordix/metal3-clusterapi-docs/blob/HEAD/security/keylime-poc/README.md).

### 6. Cilium Tetragon (eBPF observe-first) — ADAPT (upgraded from wave-178 WATCH)
Tetragon attaches eBPF programs to kernel functions and observes the complete lifecycle of every process execution — process lineage, file access, network connections, syscalls — with <1% overhead, enriched with container/pod identity, and can enforce in-kernel (SIGKILL, signal, or syscall return-value override). The wave-178 verdict was WATCH for v1 with the note "eBPF-observed actual-vs-claimed accesses is the post-v1 answer to static-modeling gaps; adopt its observe-first graduation discipline now." For the runtime-attestation theme this upgrades to ADAPT: when you cannot have silicon, the next-best evidence of "what ran" is the *observed behavior stream* — not a claim about the binary, but kernel-witnessed facts about what it did.
- **Mechanism:** kernel-witnessed execution facts (exec, open, connect, setns…) as an event stream; optional in-kernel enforcement.
- **Threat closed:** claim-vs-reality divergence — the binary says X, the kernel saw Y.
- **Cost:** $0 software; needs Linux 5.4+ (5.10+ recommended) and privileges to load eBPF.
- **License:** Apache-2.0 — verified from the raw LICENSE file. **Trap noted:** the BPF (kernel-side) programs are GPL-2.0; only userspace is Apache-2.0. Vendoring eBPF programs has GPL implications; consuming the event stream does not.
- **Why ADAPT:** emit Tetragon-style execution facts into our evidence journal and the "what ran" story gains a second, independent witness that no userspace attestation can forge without kernel compromise. Start in observe mode (detection), graduate to enforcement — the observe-first discipline.
- Sources: [eBPF tooling landscape (Tetragon enforcement mechanisms)](https://github.com/itsdun1/inferspect/blob/HEAD/docs/research/ebpf-tooling-landscape.md), [Tetragon field guide (interfaces, standalone DaemonSet install)](https://github.com/peopleforrester/unleash_an_agent_watch_it_burn/blob/HEAD/research/20-tetragon-forkbomb-2026.md).

### 7. AWS Nitro Enclaves — WATCH (pattern reference, silicon-bound)
The gold-standard silicon pattern for "prove what ran": the Nitro hypervisor generates a CBOR attestation document containing PCR0 (enclave image file hash), PCR1 (kernel+initramfs), PCR2 (user application), PCR8 (signing key / author identity), a nonce, and an enclave-specific public key — signed by the AWS Nitro PKI (root valid to 2049). AWS KMS key policies gate `Decrypt` on attestation-document values (`kms:RecipientAttestation:PCR0`), so only the exact measured enclave can decrypt. Enclaves have no persistent storage, no SSH, no external network — vsock to the parent only. Attestation generation costs 45–120ms; crypto throughput overhead ~14–23% in independent testing.
- **Mechanism:** hypervisor-signed measurement document; attestation-gated decryption.
- **Threat closed:** host-operator snooping; image substitution (wrong PCR0 = no decrypt).
- **Cost:** requires Nitro EC2 silicon; paid cloud.
- **License:** aws-nitro-enclaves-cli is Apache-2.0 — verified from the raw LICENSE file.
- **Why WATCH, not STEAL:** genuinely needs AWS silicon; attestation requires the NSM handshake (no offline verification); the root of trust is Amazon (contractual + architectural trust in AWS, as one analysis notes: "You trust AWS hasn't compromised the NSM"). For our $0 local-first posture, adopt the **measurement vocabulary** — PCR-indexed claims (image ≠ kernel ≠ app ≠ identity, design rule #4) and the **attestation-gated release** pattern — not the dependency.
- Sources: [Nitro Enclaves concepts (attestation document, PCRs, KMS conditions)](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html), [Turnkey on Nitro key management (CBOR doc fields, P-384, root to 2049)](https://aws.amazon.com/blogs/web3/building-secure-verifiable-blockchain-key-management-on-aws-nitro-enclaves-at-turnkey/), [Nitro vs TDX analysis (overhead numbers, NSM reachability, root-of-trust critique)](https://dev.to/voltagegpu/aws-nitro-enclaves-vs-intel-tdx-why-attestation-root-matters-for-regulated-workloads-56ib).

### 8. Phala Network (TEE AI agents) — WATCH (market proof, not code)
Phala is the closest production proof that *attested agent execution is a sellable product*: TEE workers (Intel SGX, now GPU TEE) run pRuntime, which executes "Phat Contracts" and AI-Agent Contracts (TypeScript agents with tools, memory, secrets); attestations bind results to the measured code and are verified on the parachain, making off-chain AI work auditable. Phala Cloud now ships agent-oriented runbooks — including a step-by-step attestation-verification skill designed to be executed by coding agents — which is the "evidence interface for agents" idea independently arrived at.
- **Mechanism:** SGX/GPU-TEE workers + on-chain attestation verification; sealed secrets; signed action logs.
- **Threat closed (claimed):** operator tampering with agent execution; result forgery.
- **Cost:** their cloud; hardware-bound.
- **License:** phala-blockchain is Apache-2.0 (ecosyste.ms / awesomeopensource metadata — raw LICENSE not fetched); phala-cloud is MIT (repo README). Value here is market validation, not vendored code.
- **Why WATCH:** validates the thesis that customers will pay for "prove what my agent did." Steal the *product shape* (attestation-verification runbook an auditor/agent can execute; sealed credentials; signed action logs), not the chain, the tokenomics, or the SGX dependency. Caution: SGX's vulnerability history, hardware-manufacturer trust, and token-coupled economics are all disclosed limitations.
- Sources: [Phala in the blockchain-AI-agent landscape (architecture, limitations)](https://github.com/axiosdevs/awesome-blockchain-ai-agents), [Polkadot ecosystem atlas: Phat Contracts & AI-Agent Contracts (attestations bind results to measured code; on-chain verifiability)](https://github.com/dablockdao/polkadot-ecosystem/blob/HEAD/dot-atlas/src/content/docs/dapps/ai/phala-network.mdx), [phala-cloud repo (agent runbooks incl. verify-attestation; MIT)](https://github.com/Phala-Network/phala-cloud).

## License table

| Source | License | Verified how |
|---|---|---|
| confidential-containers/trustee | Apache-2.0 | raw LICENSE fetched |
| stefanberger/swtpm | 3-clause BSD (© IBM) | raw LICENSE fetched |
| cilium/tetragon | Apache-2.0 (userspace) / GPL-2.0 (BPF programs) | raw LICENSE fetched; GPL split from project docs |
| sigstore/rekor | Apache-2.0 | raw LICENSE fetched |
| aws/aws-nitro-enclaves-cli | Apache-2.0 | raw LICENSE fetched |
| keylime | Apache-2.0 | repo metadata (raw not fetched) |
| Phala-Network/phala-blockchain | Apache-2.0 | ecosyste.ms + awesomeopensource metadata (raw not fetched) |
| Phala-Network/phala-cloud | MIT | repo README |
| SLSA spec / in-toto | open spec license / Apache-2.0 | spec site + project metadata |

**Traps flagged:** Tetragon's BPF/GPL-2.0 split (consume the event stream, don't vendor the programs, without GPL review); Phala's SGX/tokenomics coupling (take the product shape, not the stack); Rekor's append-only irreversibility (never log PII-bearing claims).

## Design rules extracted

1. **Attestation answers "what ran where" — never "whether it behaved."** The semantic residue is permanent: a valid attestation proves which code ran, not that its behavior was acceptable. Sell the evidence; let the auditor judge the behavior.
2. **Separate measurement from consumption.** Measure once (PCR quote / event-log replay), convert to a standard bearer token (OIDC / EAR / JWT), then make every downstream decision a pure function of token claims. Evidence should be bearer-shaped.
3. **Verify at admission, not at scan** (reaffirmed from wave-306). The KBS releases nothing to unattested guests; the RCAR handshake precedes any resource access.
4. **Structure measurements into named registers.** Nitro's PCR0/1/2/8 (image ≠ kernel ≠ app ≠ identity) is the model: one opaque blob can't be reasoned about; indexed claims can be pinned, compared, and gated independently.
5. **The hardware-free ladder.** Each rung is independently shippable at $0 — do not gate the evidence story on silicon:
   reproducible build (anchor) → SLSA provenance (claim) → transparency log (witness) → swtpm/Keylime (verifier dev loop) → eBPF observation (behavior stream) → real TEE (silicon root).
6. **A transparency log proves registration, not truth.** Inclusion proofs say "this claim was witnessed at time T" — nothing more. Our journal already does this privately; the upgrade is third-party witnessing.
7. **Measurements must compare like-with-like, or refuse.** A digest claim in the wrong shape is a fail-closed refusal, not a coercion (Confidential Space WCM mapping).

## Recommended build order

1. **SLSA-provenance-shaped evidence predicates** — re-envelope our offline evidence bundle as in-toto statements with SLSA predicates. Interoperability with cosign / `gh attestation verify` for free. ($0, software-only)
2. **swtpm-backed verifier dev loop** — build any future measured-boot/quote verifier against swtpm now (Keylime push model as reference architecture); graduate to real TPMs without changing the verifier.
3. **Rekor-pattern witnessing** — SCT-shaped signed inclusion promises for our journal; use the free public Rekor instance for public claims, keep private claims on our own log.
4. **eBPF execution-fact emission** — Tetragon-style kernel-witnessed facts into the evidence journal (observe mode first).
5. **RCAR-shaped admission handshake** for skill/tool loading — composes with the wave-306 in-toto+TUF skill-verification direction (TUF delivers reference values; handshake gates release).
6. **TEE silicon** (Nitro / Confidential Space / CoCo) only when a customer funds the hardware — the vocabulary (PCR-indexed claims, attestation-gated release) is adopted now, the dependency is not.
