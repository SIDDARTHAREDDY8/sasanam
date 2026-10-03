# Prospectus — Wave-306: Supply-chain verification for agent skills and MCP tools

**Date:** 2026-10-03 · **Lane:** wave-306 prospecting (Lane D) · **Base:** `d9554021`
**Theme:** what do top companies and OSS projects do to verify the integrity,
provenance, and update-safety of executable agent extensions (skills, plugins,
MCP servers, tool bundles)?

## Ranked verdicts

### 1. in-toto + TUF, the Datadog composition — STEAL (pattern)

**What it is.** Two complementary mechanisms, proven together in production:
- **in-toto** (Apache-2.0, verified from raw LICENSE, © 2018 NYU): the project
  owner signs a *layout* — the fixed series of supply-chain steps and the
  functionaries authorized to perform each. Every functionary emits signed
  *link* metadata (what was done, when, by whom, input/output digests). The
  end user verifies the links against the layout: the product was built by
  the right parties, in the right order, with no tampering in transit.
- **TUF** (Apache-2.0, CNCF-graduated; python-tuf already in our tree from
  wave-299): secures the *update* half — rollback, freeze, and mix-and-match
  attacks are defeated by the metadata roles (root/timestamp/snapshot/targets),
  with threshold signing, delegation, and compromise-resilient key rotation.
- **The composition (Datadog):** Datadog secures its Agent Integrations — the
  closest real-world analog to agent skills (Python wheels + YAML configs
  installed onto customer machines) — with a 4-step in-toto layout
  (developer signs → CI builds wheels without modifying prior wheels → CI
  signs all wheels via TUF → agent verifies wheels match exactly what
  developers signed), TUF for secure delivery *and* for bootstrapping trust
  in the in-toto layout itself, and developer signing on hardware keys
  (Yubikeys). The Datadog Agent calls the TUF/in-toto libraries transparently
  on the customer's machine at install/update time.
  ([in-toto/friends datadog README](https://github.com/in-toto/friends/blob/HEAD/datadog/README.md);
  [Datadog engineering blog](https://www.datadoghq.com/blog/engineering/secure-publication-of-datadog-agent-integrations-with-tuf-and-in-toto/))

**Threat closed:** CI/build-pipeline compromise (SolarWinds class — BoxBoat
notes Datadog's pipeline "would likely have stopped the SolarWinds attack
dead in its tracks"), artifact tampering in transit, silent insertion of
unreviewed code, rollback/freeze/mix-and-match on updates, key compromise
via TUF's role separation.

**What it costs:** operational overhead — every supply-chain step must emit
link metadata; the layout must be maintained as the pipeline evolves. In
practice teams use in-toto as an envelope with one or two predicates and
keep the DAG implicit in CI design.

**Why STEAL:** this is the exact shape our skill/MCP distribution needs —
a skill bundle is a Datadog integration by another name. The pattern maps
1:1 onto our evidence philosophy: the layout is the *spec*, the links are
the *evidence*, and verification happens at install/update time on the
consumer's machine. python-tuf is already vendored; the in-toto layout/link
pattern can be implemented stdlib-only against our existing hash-chained
evidence journal.

### 2. mpak's MCPB bundle format + MTF trust tiers — STEAL (format/pattern)

**What it is.** [mpak](https://github.com/tarun-bandi/mpak) (Apache-2.0 —
verified from the raw LICENSE file, © 2026 NimbleBrain Inc.; note GitHub's
own metadata says NOASSERTION, the file says Apache-2.0) is an open-source
MCP server registry with three pieces:
- **MCPB**: a standardized bundle format — a ZIP containing `manifest.json`
  (name, version, server type, run commands, declared tools/prompts/resources),
  `src/`, and `deps/` (all dependencies vendored).
- **MTF** (mpak Trust Framework): a scanner scoring every bundle across five
  domains — Supply Chain (SBOM, vuln scan, dep pinning), Code Quality
  (secrets, malicious patterns, static analysis), Artifact Integrity
  (manifest validation, content hashes), Provenance (repo verification,
  author identity), Capability Declaration (tool descriptions, permission
  scopes) — graded L1 (Basic, 5 controls) → L4 (Attested, 25 controls:
  behavioral analysis, reproducible builds, commit linkage).
- **Registry**: self-hostable; publishing goes through GitHub Actions with a
  GitHub OIDC token — every published bundle has a verifiable link back to
  a source repo and CI run; claiming via `mpak.json` in the repo.

**Threat closed:** loose-script distribution (no consistent packaging, no
pre-run verification), dependency confusion via vendored deps, anonymous
publishing.

**What it costs:** young project (created 2026-07-25, 0 stars, single vendor
NimbleBrain Inc.) — do not depend on it; the *format* is the steal.

**Why STEAL:** MCPB is the closest thing in the wild to a standardized
skill/MCP bundle, and its L1–L4 tiers map cleanly onto our evidence tiers.
The GitHub-Actions-OIDC publishing rule ("every bundle links to a source
repo and CI run") is directly reusable as a skill-registry admission rule.

### 3. npm provenance / PyPI attestations (Sigstore SLSA) — ADAPT

**What it is.** `npm publish --provenance` (GA since Oct 2023) generates a
Sigstore-signed SLSA provenance attestation tying the tarball to the exact
GitHub Actions workflow run and commit that produced it, logged in the
public Rekor transparency log; consumers check with `npm audit signatures`
or `npm view <pkg> --json | jq '.dist.attestations'`. PyPI has the same via
PEP 740 (`pypa/gh-action-pypi-publish` attests automatically). Downstream
registries are starting to *require* it — the n8n community-node registry
rejected a package specifically for publishing without provenance.

**Threat closed:** compromised publishing credentials / cache-serving-wrong-
content — a poisoned tarball carries no valid attestation, so tooling flags
the mismatch. (Does NOT close build-pipeline compromise: a valid signature
proves *which* pipeline built it, not that the pipeline was honest.)

**Why ADAPT:** require provenance-shaped attestations on skill bundles at
registry admission; the attestation envelope (in-toto statement + SLSA
predicate) aligns with our existing evidence-bundle direction and the ORAS
OCI-artifact transport from wave-299.

### 4. GitHub artifact attestations — ADAPT

**What it is.** `actions/attest-build-provenance` binds a subject (named
artifact + digest) to a SLSA build-provenance predicate in the in-toto
format, signed with a short-lived Sigstore certificate (public-good instance
for public repos, GitHub's private Sigstore instance for private/internal),
uploaded to GitHub's attestations API, verifiable with `gh attestation
verify`. Honest limitation: private/internal repos need GitHub Enterprise
Cloud — our repo is private, so this is a pattern reference, not a service
we can consume as-is.

**Why ADAPT:** the envelope shape (subject + digest + in-toto SLSA predicate
+ Sigstore signature) is the right evidence primitive for skill-bundle
provenance records in our own journal.

### 5. Sigstore policy-controller / cosign admission verification — ADAPT (pattern)

**What it is.** [policy-controller](https://github.com/sigstore/policy-controller)
(Apache-2.0) is a Kubernetes admission controller enforcing signature and
attestation policy (`ClusterImagePolicy`) *before* a workload runs: unsigned
or wrongly-signed images never schedule. The pattern generalizes: **verify
at admission, not at scan**. A related design note from Google's k8s-aibom
Rekor verifier is worth stealing verbatim in spirit: it emits *facts*
(`verified`, or `claimed` with a recorded failure reason) and explicitly
refuses to emit policy verdicts — "verification outcomes are facts; whether
an unverified model is acceptable is the consumer's decision." That is our
evidence-not-authority philosophy, independently arrived at.

**Threat closed:** compromised registry / stolen registry creds shipping a
malicious artifact to a verifying consumer; tag-overwrite / mirror-MITM.

**Why ADAPT:** skill installation is our admission point — every skill/MCP
bundle load should verify signature + provenance *before* the skill's
instructions enter the agent's context, exactly as the policy-controller
refuses to schedule unsigned images. Honest boundary (from the ecosystem
itself): signing proves *which pipeline* built the artifact, not that the
pipeline was honest — which is why this composes with #1 (in-toto layout),
not a substitute.

### 6. Agent Skills spec (agentskills.io) — ADAPT (format)

**What it is.** The open Agent Skills standard (originated at Anthropic,
released as an open standard): a skill is a folder with `SKILL.md` (name +
description metadata, instructions), optional `scripts/`, `references/`,
`assets/`, loaded via progressive disclosure (discovery → activation →
execution).

**Why ADAPT, not STEAL:** the spec is a *format*, deliberately not a trust
layer — it standardizes how capabilities are *described*, not how they are
*verified*. Align with the format for interoperability (it is what the
ecosystem is converging on), and build the verification layer ourselves on
top. The spec's own `name`/`description`/`license`/`metadata` provenance
fields are the natural anchor points for our provenance records.

### 7. Warg transparency design — WATCH (pattern only)

**What it is.** The Warg protocol (Apache-2.0) designed a transparency-based
package registry: a log-backed map from (registry, package, version) to
digest, so a lying registry is detectable. **However:** the reference
implementation repo ([bytecodealliance/registry](https://github.com/bytecodealliance/registry))
is **archived** — "no longer being actively developed by Bytecode Alliance
members"; work continues on an OCI-based system in
`bytecodealliance/wasm-pkg-tools`.

**Why WATCH:** steal the transparency-log concept (it is the same idea as
Rekor applied to a package namespace), do not depend on the implementation.
If we ever need registry-transparency for skills, build on OCI + Rekor, not
warg.

### 8. The official MCP Registry model — SKIP as a model (WATCH as a warning)

**What it is.** The official MCP Registry
([registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io))
is a *metadata* registry: it maps "weather v1.2.0" to `npm:weather-mcp` and
delegates security scanning downward to package registries. Its
[moderation policy](https://modelcontextprotocol.io/registry/moderation-policy)
states in writing: consumers should "assume minimal-to-no moderation"; it
will **not** remove low-quality, buggy, or vulnerability-carrying servers.

**Why SKIP:** a registry that only does identity is not a trust layer.
Do not replicate this shape. The lesson for our skill registry: namespace
authentication without verification is a discovery service wearing a trust
costume.

## Supporting evidence (not separately ranked)

- **metahub-ai/assay** ([github.com/metahub-ai/assay](https://github.com/metahub-ai/assay)):
  an open trust layer for AI artifacts (skills, MCP servers, agents, plugins)
  — code inspection, sandboxed behavioral audits, verifiable reports, signing.
  WATCH: young, but the "audit artifact, not just code" direction matches our
  realistic-battery posture.
- **Dated counterexamples** (why this matters now): `postmark-mcp` shipped
  15 clean versions then v1.0.16 added a one-line BCC-to-attacker backdoor
  (1,643 downloads before removal); the SmartLoader campaign built fake
  GitHub account networks to manufacture community around trojanized MCP
  servers (~800 posing as Skills/MCP servers); Koi Security's ClawHavoc
  found 341 malicious skills on one marketplace.
- **Trail of Bits / University of Vienna scanner findings**: skill scanners
  check a *snapshot* at install time and issue a *permanent* verdict — no
  rechecks of linked URLs, no hash-over-time verification; 7 scanners agreed
  on 0.12% of flagged skills across 238,180 skills. Structural support for
  our position: **a scanner's verdict is a snapshot; trust needs a stream**
  (continuous re-verification, the heartbeat-lease idea applied to artifacts).
- **Notary v2 / notation** (Apache-2.0, verified from raw LICENSE): OCI-native
  signing. ADAPT-worthy for the OCI evidence-transport half (aligns with the
  ORAS direction from wave-299), not separately ranked here.

## License table (verified from raw LICENSE bytes unless noted)

| Source | License | Verified from |
|---|---|---|
| in-toto | Apache-2.0 | raw LICENSE, © 2018 NYU |
| TUF / python-tuf | Apache-2.0 | prior wave-299 verification; CNCF-graduated |
| Sigstore (cosign, policy-controller) | Apache-2.0 | org standard; license-file metadata 2026-08-14 (not raw bytes this sweep) |
| mpak | Apache-2.0 | raw LICENSE, © 2026 NimbleBrain Inc. (GitHub metadata says NOASSERTION — file wins) |
| notation (Notary v2) | Apache-2.0 | raw LICENSE |
| warg | Apache-2.0 | repo metadata (archived — pattern only) |
| Agent Skills spec | open standard | agentskills.io (format, not code) |
| npm / PyPI / GitHub attestations infra | service | not vendored code |

## Design rules extracted

1. **A registry that only does identity is not a trust layer.** (MCP Registry
   moderation policy — namespace authentication without verification is a
   discovery service wearing a trust costume.)
2. **Verify at admission, not at scan.** (policy-controller pattern — the
   skill load path is our admission point.)
3. **Provenance is a claim about the build; the layout is a claim about the
   process; you need both.** (Datadog — neither in-toto nor TUF alone is
   sufficient.)
4. **A scanner's verdict is a snapshot; trust needs a stream.** (Trail of
   Bits / Vienna study — re-verification over time, the heartbeat idea
   applied to artifacts.)

## Recommended build order for Sasanam

1. **Skill bundle format** (steal MCPB's shape: manifest + vendored deps +
   declared capabilities) — the unit of verification must exist before the
   verification.
2. **in-toto-style layout + link evidence** on our hash-chained journal
   (steal Datadog's 4-step shape: author signs → CI builds → CI signs via
   TUF → consumer verifies) — stdlib-only, no new dependencies.
3. **Admission-time verification at skill load** (adapt policy-controller:
   refuse to load unverifiable bundles; emit facts, not verdicts).
4. **Sigstore-shaped provenance attestations** on bundles (adapt npm/PyPI
   envelope; require at registry admission the way n8n does).
5. **TUF repository for skill updates** (python-tuf already vendored —
   rollback/freeze/mix-match protection on the update half).
