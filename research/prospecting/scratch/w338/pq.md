# Wave-338 Lane 6 — Post-quantum signature deployment news (scout D)

Access date for all citations: **2026-10-05**. Spend: $0.
Scope: what's new in ML-DSA/PQ-signature deployment since the prior pass; when (if ever)
the reserved-PQ-slot flip in Sasanam's evidence-bundle format becomes urgent.

**Tree-check (performed 2026-10-05):** `gov/pq_envelope.py` line 61 `PQ_ENABLED = False`;
closed table of 19 pure-PQ identifiers (ML-DSA FIPS 204, Falcon incl. padded variants,
SLH-DSA FIPS 205 SHA2/SHAKE 128/192/256) unchanged. No drift.

---

## 1. Deployments in the wild since the prior pass

### 1a. "0 in 60k" — UNCHANGED

qknot's audit is unchanged: v0.1.1 README and `docs/RESULTS.md` still report **zero
post-quantum signatures across 60,000 sampled artefacts** (HuggingFace, npm, PyPI),
95% Wilson upper bound 0.038% per stratum. Every signature found remains
Shor-breakable (ECDSA P-256 on PyPI/npm attestation paths; RSA/ECDSA elsewhere).
The audit data files (`data/pypi_2026-07-30.jsonl`, npm v2 2026-07-30) were not re-run;
the result is the July-30 audit carried forward as published.

- https://github.com/adityasharma1307/qknot/blob/HEAD/docs/RESULTS.md (accessed 2026-10-05)
- https://github.com/adityasharma1307/qknot/blob/HEAD/README.md (accessed 2026-10-05)

**Vendor deployments are moving (TLS, PKI, firmware), but artifact-signing
ecosystems — the domain our evidence bundles live in — have zero PQ signatures in
the wild.** Deployment is concentrated in TLS key exchange (ML-KEM) and enterprise
PKI; code-signing keys themselves remain classical everywhere publicly visible.

### 1b. New ML-DSA deployments (vendor, primary-source where possible)

| Deployment | What | Status | Date/source |
|---|---|---|---|
| **Altera (Agilex 3/5 FPGAs)** | ML-DSA in Secure Device Manager for secure boot — ships with a PQC-capable trust anchor from the factory, breaking the firmware-update circular dependency | **Shipping in production devices** | postquantum.com, published ~Sept 24 2026; feature effective Sept 8, 2026. https://postquantum.com/security-pqc/altera-ml-dsa-secure-boot-agilex-fpga/ |
| **Microsoft / Windows** | SymCrypt ships ML-KEM + ML-DSA in production across Azure, M365, Windows 11, Windows Server 2025 (Nov 2025 update); ADCS ML-DSA certificate issuance (44/65/87) reached **GA May 2026** — covers code signing; hybrid TLS groups configurable in Schannel (KB5120998, Aug 27 2026) | Production GA | https://techcommunity.microsoft.com/blog/post-quantum-crypto-tech-blog/windows-tls-1-3-and-post-quantum-crypto-faq/4556389 (accessed 2026-10-05); techtimes.com summary of same Microsoft update (2026-07-15) |
| **AWS** | Private CA ML-DSA certificate issuance (CAs, certs, CRLs, OCSP) — GA Nov 2025, incl. code signing use case; Cloud KMS ML-KEM/ML-DSA/SLH-DSA GA (2026) | Production GA | https://aws.amazon.com/about-aws/whats-new/2025/11/aws-private-ca-post-quantum-digital-certificates/ ; https://cloud.google.com/blog/products/identity-security/pqc-in-plaintext-google-clouds-post-quantum-cryptography-roadmap (Google Cloud blog, accessed 2026-10-05) |
| **Cloudflare** | ML-DSA-44 origin authentication (Authenticated Origin Pulls, Custom Origin Trust Store); internal target **full PQ security by 2029**; Automatic Key Exchange ~doubled daily hybrid origin connections after Sept 8, 2026 | Production opt-in | https://www.webpronews.com/cloudflare-deploys-ml-dsa-signatures-for-origin-server-authentication-as-quantum-threats-accelerate/ (accessed 2026-10-05; secondary — company's own blog post per the article) |
| **Google** | Internal target **2029** for full PQC migration (announced March/April 2026); Cloud API endpoints + load balancers with hybrid X25519MLKEM768; Cloud KMS PQC GA; Merkle Tree Certificates as Chrome's route to PQ website authentication — **bootstrapping phase Q1 2027, separate Chrome Quantum-resistant Root Store Q3 2027** | Targeted 2029; MTC experimental | https://cloud.google.com/blog/products/identity-security/pqc-in-plaintext-google-clouds-post-quantum-cryptography-roadmap ; https://www.scworld.com/brief/google-accelerates-post-quantum-cryptography-timeline-to-2029 |
| **Apple** | MTC policy draft goes beyond Chrome CQRP v0.3.0 (Aug 14, 2026): expects **three cosignatures per MTC cert — ML-DSA-44 (issuing) + ECDSA-P256 (issuing) + ML-DSA-44 (mirror)**; uniform 7-day cert validity | Policy draft | https://postquantum.com/security-pqc/apple-mtc-policy-post-quantum/ (accessed 2026-10-05) |
| **NEAR Protocol** | ML-DSA (Dilithium) signing deployed on mainnet | Production | https://www.ainvest.com/news/protocol-implements-quantum-safe-signing-secure-institutional-assets-2608/ (secondary) |
| **FortifyIQ** | NIST CAVP-validated ML-DSA verify-only library for constrained MCUs (secure boot) | Announced Sept 22, 2026 | https://anysilicon.com/news/fortifyiq-announces-cavp-validated-ml-dsa-post-quantum-digital-signature-verification-library/ |

Pattern: ML-DSA is production in **PKI issuance, firmware secure boot, and origin
auth** — i.e. where the verifier is under the vendor's control. **Artifact-signing
in open ecosystems (PyPI/npm/HF Sigstore attestations) remains 100% classical.**

## 2. Regulatory trigger dates (why "urgent" has a calendar now)

NSA **CNSA 2.0** (FAQ v2.1, Dec 2024; scope: US National Security Systems):

- **Immediately**: begin CNSA 2.0 software/firmware signing (LMS/XMSS approved now;
  ML-DSA-87 for signatures)
- **Jan 1, 2027**: new NSS acquisitions must **support** CNSA 2.0
- **2030**: software/firmware signing **exclusively** CNSA 2.0 — the earliest
  per-class hard deadline, and it is a *signing* deadline, directly adjacent to
  our evidence-bundle surface
- **2033**: web/cloud/OS exclusively CNSA 2.0; **Dec 31, 2033**: NSS transition complete
- NSM-10: full quantum resistance by **2035**

Primary: https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
(consistency cross-checked via Entrust https://www.entrust.com/blog/2022/10/nsa-announces-new-post-quantum-resistant-algorithm-suite-2-0-and-transition-timetable
and postquantum.com https://postquantum.com/quantum-policy/nsa-cnsa-2-0-pqc/, both accessed 2026-10-05).

EU (NIS Cooperation Group, June 2025): national PQC strategies + inventories by end
**2026**; critical-infrastructure high-risk migration by **2030**; medium-risk by
**2035**. Source: https://thequantuminsider.com/2026/08/07/post-quantum-cryptography-timelines/.

## 3. Sigstore PQ migration — movement, but design phase

- **cosign#4960** (opened 2026-06-21) tracks ML-DSA keygen/sign/verify in cosign.
  Groundwork merged (protobuf-specs ML-DSA enums 21/22/23 marked Experimental,
  `--signing-algorithm` flag, Fulcio/Rekor client-signing-algorithms flags,
  sigstore-go ML-DSA keypair interface, Trail of Bits agility work). Still
  **open**: no cosign ML-DSA key generation, signing, verification, Fulcio ML-DSA
  issuance, Rekor ML-DSA storage, or hybrid mode. "Cannot generate ML-DSA keys,
  sign with ML-DSA, or verify ML-DSA signatures today."
  https://github.com/sigstore/cosign/issues/4960 (accessed 2026-10-05)
- **Trillian Summit 2026** (Hayden Blauzvern, Google Open Source Security / Sigstore
  maintainer): talk "Simplicity through Transparency: How the PQC Migration is
  Streamlining Sigstore" presents the *design* for PQC Sigstore — ML-DSA key sizes
  as a greenfield to simplify around the transparency log, "keyless" identity-bound
  signatures rooted in transparency, new leaf format for PQC storage overhead.
  Still a design talk, not shipped code.
  https://github.com/google/trillian-website/blob/HEAD/content/summit2026/talks/sigstore.md
- **Open Source SecurityCon Europe 2026** (Red Hat, Conner & Ghanmi):
  "Quantum-Proofing Sigstore: A Tale of Three Approaches" — three layers: (a)
  transparency-log hybrid (PQ-signed SETs/checkpoints), (b) hybrid X.509
  (dual signatures per certificate), (c) Merkle Tree Certificates (batch PQ).
  Presented as design options.
  https://github.com/felipevicens/kubecon2026/blob/HEAD/markdown_output/colocated/Open_Source_SecurityCon/Quantum_Proofing_Sigstore_A_Tale_of_Three_Approaches.md

Verdict: **aspirational → design phase**. Still no ML-DSA issuance anywhere in the
Sigstore chain; when Fulcio starts issuing ML-DSA certs (cosign#4960's "Fulcio
ML-DSA certificate issuance" item), the classical-only attestation sunset for
artifact ecosystems begins.

## 4. qknot — no new version, no new features

- Latest release: **v0.1.1 only** (`['0.1.1']` on PyPI; PyPI JSON confirms version
  field `0.1.1`). License: **MIT** (PyPI classifiers + LICENSE; read 2026-10-05).
- Repo activity is the v0.1.1 release itself (hybrid self-signature, bounded
  revocation search, OIDC-registered ML-DSA-87 key); no v0.2/v1.0 branch or
  changelog since.
- Worth noting the research conclusions remain: hybrid costs **0.28 ms over
  ML-DSA-87 alone** (+Ed25519 side nearly free), binding non-separability, and the
  audit result stands.

Sources: https://pypi.org/project/qknot/ (JSON, accessed 2026-10-05);
https://github.com/adityasharma1307/qknot/blob/HEAD/docs/RELEASE-NOTES-v0.1.1.md.

## 5. Urgency read: is "early and ready" still right?

**Yes — "early and ready" (reserved slot, disabled) remains the correct posture.
But there is now a visible trigger calendar; watch these three:**

1. **CNSA 2.0 2030 software/firmware-signing exclusivity** — our evidence bundles
   are a signing artifact; any federal/NSS-adjacent customer will require
   ML-DSA/LMS/XMSS for *signing* by 2030, three years before the 2033 browser/cloud
   deadline. This is the closest regulatory trigger to our surface.
2. **Sigstore ML-DSA issuance (cosign#4960)** — when Fulcio/Rekor ship PQ, the
   ecosystem default (all PyPI attestations today = ECDSA P-256 via Sigstore
   chains) starts its transition; our flip window opens then, not before.
   Watch item: cosign#4960 "Fulcio ML-DSA certificate issuance" and protobuf-specs
   enum de-Experimentalization.
3. **Chrome MTC Q1/Q3 2027** — not our surface, but it sets the industry drumbeat;
   when WebPKI-adjacent PQ auth ships at scale, PQ-signed artifacts stop looking
   exotic to auditors and customers.

No vendor is sunsetting classical-only verification in the artifact-signing
domain today (PyPI/npm ECDSA P-256 paths are stable; Sigstore's classical chain
is the only one that exists). So there is **no flip trigger firing now** — but the
flip trigger is now named and dated: **Sigstore PQ issuance + 2030 CNSA signing
deadline**. A reasonable internal tripwire: re-evaluate posture when cosign#4960
closes or when any major artifact registry announces an ML-DSA attestation path.

---

## Verdicts

| Item | Verdict | Rationale |
|---|---|---|
| Reserved slot (19-ID closed table, PQ_ENABLED=False) | **ADAPT (keep, no change)** | Tree-check clean; identifiers still match the NIST family set (FIPS 204/205; FIPS 206 FN-DSA not in CNSA 2.0 — no action, keep closed table as-is) |
| Non-separable hybrid rule (both algos sign a commitment to the alg set) | **ADAPT (keep as MUST-rule)** | Industry converges the same way: Apple MTC policy requires ML-DSA+ECDSA cosignatures (hybrid at issuance); Cloudflare/Microsoft GA paths are hybrid-first; qknot's field-deletion attack is the worked example. Our rule matches where the ecosystem is going |
| qknot design (non-separable Ed25519+ML-DSA-87, DSSE PAE, binding-enforced) | **STEAL (study, no copy)** | Keep watching as a design reference for our flip implementation; MIT license confirmed, but no need to adopt code — our envelope is our own |
| CNSA 2.0 Jan-2027 / 2030 / 2033 dates | **WATCH** | No flip today; set re-eval trigger on cosign#4960 resolution or 2030-minus-2 planning |
| Sigstore PQC design (Trillian Summit, OSS SecurityCon 3-approach talks) | **WATCH** | Design phase only; the "leaf format" and hybrid-X.509 options may constrain our future bundle format if we anchor to Sigstore chains |
| FIPS 206 (FN-DSA/Falcon) | **SKIP** | NSA explicitly will not add FN-DSA to CNSA 2.0; our Falcon identifiers are forward-looking only — leave reserved |
| New deployments (Altera secure boot, Cloudflare origin ML-DSA, MSFT ADCS GA, AWS Private CA GA) | **WATCH** | Signals the flip is a *when*, not an *if*; none are artifact-ecosystem flips |

## Bottom line

Since the prior pass: **deployments accelerated materially in controlled-verifier
domains** (PKI issuance, firmware secure boot, origin auth, cloud KMS) but
**artifact-signing ecosystems are unchanged at zero**. Sigstore moved from
aspirational blog to active design work (two 2026 conference talks, cosign#4960
tracking real remaining work) but still cannot sign ML-DSA. The first dated,
legible urgency is **CNSA 2.0's 2030 exclusive-use deadline for software/firmware
signing** — our surface is a signing surface, so that date is ours. "Early and
ready" stays correct; the trigger to start the flip is **Sigstore shipping ML-DSA
issuance (cosign#4960)**, and the deadline that makes it mandatory is **2030**.
