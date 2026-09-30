# NON-CLAIMS.md

Normative. This file lists what Sasanam evidence does **not** prove.
Every entry cites the module that owns the claim, is at most three
sentences, and is machine-checked: `evals/doc_truth.py` verifies that
each cited module's docstring carries the matching non-claim phrase,
and `gov/honest_claims.py` refuses rendered artifacts that emit
reserved claim tokens (`proves-execution`, `tamper-proof`,
`non-repudiation`, `formally-verified`, ...).

1. **Receipts are signed claims, not correctness.** A signed denial
   receipt proves that the emitter signed a claim about a decision
   (verdict, class, rule path, digests). It does not prove the
   decision was correct or that the described event happened.
   Module: `gov/deny_receipts.py`.
   Docstring phrase: "a receipt proves the emitter's signed claim,
   not that the decision was correct".

2. **Seeded denials are anchored denials, not absence.** A seeded
   denial record proves a denial was anchored to the audit log
   outside the denied transaction. It does not prove the denied
   action was absent from the world. Module: `gov/seeded_denials.py`.
   Docstring phrase: "a seeded denial record proves the denial was
   anchored, not that the denied action was absent".

3. **Checkpoints are commitments, not content proof.** An MMR
   checkpoint proves commitment, order, and count over the digest
   list. Fixed-count content substitution is indistinguishable from
   reorder using peaks alone, so it does not prove content
   authenticity. Module: `gov/checkpoints.py`.
   Docstring phrase: "a checkpoint proves commitment and order, not
   content authenticity".

4. **HMAC is authenticity, not non-repudiation.** HMAC evidence
   proves shared-secret authenticity of a record. It is not
   non-repudiation: anyone holding the secret could have produced
   the tag. Module: `gov/alg_registry.py`.
   Docstring phrase: "HMAC evidence proves shared-secret
   authenticity, not non-repudiation".

5. **Registries are in-memory unless anchored.** The policy-revision,
   checkpoint, and registered-key registries are in-memory; they
   prove nothing about persistence, distribution, or what another
   deployment holds. Persistence and distribution are
   deployment-owned. Module: `gov/policy_revisions.py`.
   Docstring phrase: "the revision registry is in-memory; persistence
   and distribution are deployment-owned".

6. **Attestation is ceremony-bound, not runtime-proven.** Attested
   identity binds claims to a key ceremony with no live TPM, cloud,
   or TEE round trip. It does not prove the workload's runtime
   integrity. Module: `gov/attested_identity.py`.
   Docstring phrase: "attested identity has no live TPM round trip".

7. **Negative outcomes classify absence, not search.** Signed
   negative outcomes classify absence (no record found); they do not
   prove a search occurred or that the absent thing never existed.
   Module: `gov/absence.py`.
   Docstring phrase: "signed negative outcomes classify absence, not
   that a search occurred".

8. **Renders prove bytes, not comprehension.** Render and display
   attestations prove the bytes and determinism of the rendered
   artifact. They do not prove a human saw, read, or understood the
   display. Module: `gov/approval_render.py`.
   Docstring phrase: "render attestations prove bytes and determinism,
   not that a human understood the display".

A claim that needs any of the above is outside what this system can
evidence. Saying so loudly is the point of this file.
