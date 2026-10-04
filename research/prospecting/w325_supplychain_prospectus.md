# Prospectus — Wave-325: Continuous skill/MCP supply-chain verification

**Date:** 2026-10-04 · **Lane:** wave-325 lane 3 (research only — no product code touched) ·
**Base:** `b2562b59` · **$0 spend · public sources only · primary sources (repos, specs, first-party docs)**

**Theme:** what the best teams do CONTINUOUSLY about supply-chain verification —
runtime re-verification, revocation propagation, compromise recovery, policy
distribution — for the 2026-09-23 reallocation stream #2 (skill/MCP supply-chain).

## What is already in the tree (do not re-propose)

The admission-time and event-driven halves are built and break-tested:

- `gov/load_gate.py` — digest-pinned `ArtifactPinset`, `SkillLoader`, verified loads.
- `gov/skill_supply_chain.py` (wave-267) — **event-driven** lifecycle re-verification:
  re-verify a bundle's custody chain on EVERY lifecycle transition
  (publish → fetch → install → update), TUF delegation semantics + in-toto
  lifecycle layouts, single pinned `eval_start` (anti-TOCTOU).
- `gov/bundle_refresh.py` (wave-206) — PULL-based TUF repository metadata
  refresh with rollback floors and trust-changing root-rotation recovery.
- `gov/trust_root_refresh.py` (wave-318) — versioned trust-root chain,
  old-key-signed rotation records, short-lived freshness statements
  (TUF timestamp pattern), chain expiry at bundle-timestamp time.
- `gov/skill_admission.py` — build-time in-toto layout/step/link gate.
- `gov/advisory_binding.py` (W244-6) — advisory INPUT binding: tamper-evident
  pinned snapshots, threshold-signed advisories, `supersede` (newest wins),
  explicit stale verdicts, "a signature proves who signed, never that the
  package is safe."
- `gov/revoke.py`, `gov/bundle_rsl.py`, `gov/bundle_scan.py`.

**The gap this prospectus targets:** everything above is *event-driven* (a
transition happened, a refresh was pulled, an advisory was presented). Nothing
in the tree re-verifies on a **schedule**, on **policy change**, or on **new
knowledge arrival** — and nothing bounds **revocation latency** or distributes
**policy/trust-anchor updates** as a first-class channel. That is the
continuous half. Prior art inside our own research already points at it:
wave-306 design rule #4 — *"A scanner's verdict is a snapshot; trust needs a
stream."*

## Ranked verdicts

### 1. Kyverno background scans — STEAL (pattern)

**What it is.**
[kyverno/kyverno](https://github.com/kyverno/kyverno) (Apache-2.0 — raw LICENSE
verified this sweep) runs two verification modes. Admission webhooks gate new
resources; **background scans** (handled by the reports controller, enabled by
default, hourly `backgroundScanInterval`) *periodically re-apply validate and
`verifyImages` rules to all existing resources* and write the results to
`PolicyReport`/`ClusterPolicyReport` objects. Three triggers, stated plainly in
their dev docs (`docs/dev/reports/README.md`): **resource changes, policy
changes, and regular intervals** — a one-to-one resource↔report relationship,
the same report updated over and over.

Two load-bearing semantics worth stealing verbatim:

- **Background never enforces; it reports.** Even with `failureAction:
  Enforce`, an existing resource that violates a policy is *reported*, never
  blocked — Enforce only ever blocks at admission. The continuous loop is an
  *observation* channel, and a separate mechanism acts on the report.
- **Background cannot use admission-only context.** Rules depending on
  `request.operation` or other admission-time variables simply don't run in
  background mode. The re-verification vocabulary must be restricted to what
  is knowable outside a transition.

**Threat closed:** policy drift and knowledge drift on *already-installed*
artifacts — the skill that was clean at install and became non-compliant
later (new policy, new CVE, rotated-out signer).

**Why STEAL:** our wave-267 lifecycle module is event-driven; Kyverno supplies
the missing trigger set. The composition is exact: `skill_supply_chain`'s
`verify_delegated_authority` + `load_gate` pin checks re-run by a scheduler
against the installed-skill inventory on (a) interval, (b) delegation/policy
document change, (c) new advisory snapshot arrival. Results go to a standing
per-skill report (our `PolicyReport` equivalent), and a *separate* actuator
(quarantine/disable) consumes the report — never the scanner itself, per the
background-never-enforces rule.

**Falsifiable claim:** if we adopt the Kyverno trigger set, then a skill whose
signer key is rotated out of the delegation document is flagged in the
standing report within one scan interval *without any lifecycle transition
occurring*, and the flag carries the specific refusal code the admission path
would have produced.

### 2. Sigstore TrustedRoot-via-TUF distribution — ADAPT (channel)

**What it is.** Sigstore publishes a TUF repository at
`tuf-repo-cdn.sigstore.dev` distributing `trusted_root.json` (Fulcio CA chain,
Rekor keys). Clients (cosign, sigstore-go, third-party verifiers like
samuelpkg/samuel and sigstore-dotnet) **bootstrap from a pinned `root.json`
(trust-on-first-use) and rotate forward**: each root version N is verified by
the keys of version N−1, so Sigstore rotates its root keys continuously
without shipping new binaries. The verifier core stays offline — the network
is reached only through the TUF updater, and the target's length/hashes are
verified before parsing.

The honest trade-off, stated plainly by
[stacklok/toolhive-core](https://github.com/stacklok/toolhive-core/blob/HEAD/container/verifier/tufroots/README.md)
(`container/verifier/tufroots/README.md`), which vendors point-in-time
snapshots for offline verification: **an embedded snapshot cannot see
rotations after its fetch date, in either direction** — a key rotated out
*because of compromise* keeps being trusted by offline verifiers until the
snapshot is refreshed and consumers pick up the release. Consumers that need
timely revocation must use the online refresh path.

**Threat closed:** trust-anchor staleness — verifiers silently trusting
rotated-out (possibly compromised) keys; and the bootstrap problem for
policy distribution (how a consumer securely learns the *current* registry
policy/delegation set).

**Why ADAPT:** we have the rotation *mechanics* (`trust_root_refresh.py`,
`bundle_refresh.py`) but not the *distribution channel*. The steal is the
channel shape: serve the skill registry's delegation documents and the
witness-policy artifacts from a TUF repository (our own `tuf-repo-cdn`
analog), with clients bootstrapping from a pinned root and refreshing on the
Kyverno-style schedule. And adopt toolhive's honest bound as a design rule:
**every offline snapshot carries its fetch date and a max-staleness budget;
exceeding the budget without refresh is a loud stale verdict, never silent
continued trust** — this composes directly with `advisory_binding`'s
explicit-stale verdicts.

**Falsifiable claim:** if we serve delegation documents over a TUF channel,
then a registry compromise that swaps the delegation set is refused by every
consumer whose pinned root predates the attack (chained root verification),
and a consumer that misses N refresh intervals raises `stale` loudly instead
of verifying against a snapshot older than the budget.

### 3. GUAC CertifyBad/CertifyGood — ADAPT (pattern)

**What it is.**
[guacsec/guac](https://github.com/guacsec/guac) (Apache-2.0 — raw LICENSE
verified this sweep, © 2022 The GUAC Authors) continuously ingests SBOMs,
SLSA attestations, OSV data, Scorecards, and VEX statements into a knowledge
graph, and — the mechanism that matters here — lets new *knowledge* attach to
*existing* nodes: `CertifyBad` ("this package/source/artifact should not be
used, with justification, origin, collector, knownSince") and `CertifyGood`.
The canonical incident-response flow in their own docs
([guacsec/guac-docs `guac/supply-chain.md`](https://github.com/guacsec/guac-docs/blob/HEAD/guac/supply-chain.md)):
a vulnerability is disclosed → `guacone certify package` marks the version bad
→ the graph answers "where is this used" (blast radius) → policy forbids the
blast radius. Certifications can only be attached via ingested documents
(origin/collector/justification are mandatory) — trust information is itself
sourced evidence, not a console click.

**Threat closed:** the "artifact didn't change, the knowledge did" class —
postmark-mcp-style delayed backdoors (15 clean versions, then a malicious one),
new CVEs against pinned deps, compromised builders. The artifact's digest is
unchanged; its *standing* flips.

**Why ADAPT:** `advisory_binding.py` binds advisory *inputs*; GUAC supplies
the missing *standing layer*: a per-installed-skill current verdict that
updates as knowledge arrives, with mandatory provenance on every status
change (who said bad, when, why — the `knownSince` discipline). The blast-radius
query ("which installed skills transitively depend on the flagged artifact")
is the incident-response primitive our red-team lanes currently do by hand.
Do not build the graph database — steal the *certification document shape*
(justification + origin + collector + knownSince, ingested not clicked) and
the standing-flip semantics.

**Falsifiable claim:** if we adopt the CertifyBad standing layer, then
ingesting a signed advisory that flags an already-installed skill version
flips that skill's standing to refused within one knowledge-arrival cycle,
the flip cites the advisory's origin/collector/knownSince, and the next
scheduled re-verification (verdict #1's loop) refuses the skill with the
same code the advisory carried — with no lifecycle transition occurring.

### 4. SPIRE SVID rotation — ADAPT (principle)

**What it is.**
[spiffe/spire](https://github.com/spiffe/spire) (Apache-2.0 — raw LICENSE
verified this sweep, © The SPIFFE Project & Scytale, Inc) issues X.509-SVIDs
with short TTLs (default 1 hour) and **rotates them automatically at ~50% of
lifetime** via the Workload API (streaming push; the client library swaps the
certificate in place, no restarts). Revocation is by *non-renewal*: delete the
registration entry and the workload's next SVID request fails. The honest
boundary, stated in multiple practitioner docs: **an SVID already issued stays
valid until its TTL expires — containment is only as fast as the TTL.**
Rotation is hygiene; registration deletion is containment; short TTLs are
what make the gap small. ("Shorten the TTL globally *before* the incident, so
the maximum post-registration-removal exposure is bounded.")

**Threat closed:** stale-trust accumulation — long-lived "verified" standings
that outlive the facts they were based on. The TTL makes trust *perishable by
construction*.

**Why ADAPT (principle only — the w306 verdict on SPIFFE stands):** apply the
TTL discipline to *skill trust standings*, not to workload identity. Every
installed skill's "verified" standing carries an expiry; the continuous
re-verification loop (verdict #1) is what *renews* it. A compromised skill
loses standing in two independent ways: revocation-by-knowledge (verdict #3
flips it actively) and expiry-by-time (the standing simply lapses if the
renewal loop can't re-verify). No CRLs, no revocation lists to distribute —
the wave-303 heartbeat-lease idea, applied to artifacts instead of authority.

**Falsifiable claim:** if skill standings carry TTLs renewed only by
successful re-verification, then severing the re-verification loop (or
deleting the skill's registration) causes the standing to lapse exactly at
TTL expiry, and any execution attempt after lapse is refused with a
`stale`-family code — with the maximum exposure window equal to the TTL, set
in config, auditable in the standing report.

### 5. TUF client-workflow hardening — ADAPT (audit target)

**What it is.** The
[TUF specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
(§5, client workflow) pins three recovery mechanics that go beyond "verify
signatures": (a) **root rotation must be exactly N+1** — any other version is
a rollback, abort loudly; (b) **freeze detection against a fixed update-start
time** — the trusted root's expiry must exceed the time the update cycle
*started*, not "now" (the same anti-TOCTOU discipline as our wave-267
`eval_start`); (c) **fast-forward-attack recovery** — if the timestamp or
snapshot keys have been rotated, the client *deletes its trusted
timestamp/snapshot metadata*, recovering from a compromise in which the
attacker arbitrarily inflated version numbers (the Mercury-paper attack).

**Why ADAPT:** `gov/bundle_refresh.py` already implements rollback floors and
trust-changing root-rotation recovery, but the spec's (b) and (c) are the
audit checklist: does our refresh pin the update-start time for expiry
checks, and does it discard trusted timestamp/snapshot state on key rotation
rather than trying to walk forward from attacker-inflated versions? This is
not a new build — it is a **spec-conformance audit of `bundle_refresh.py`
against TUF §5**, producing either a clean bill or a findings list. The
python-tuf reference implementation
([theupdateframework/python-tuf](https://github.com/theupdateframework/python-tuf),
dual-licensed MIT + Apache-2.0 per its README) is the oracle for disputed
behavior.

**Falsifiable claim:** after the audit, for each of the three mechanics we
can point to the exact function in `bundle_refresh.py` that implements it or
file a finding with a reproduction — no "we handle rollback generally"
hand-waving.

### 6. OSV.dev continuous advisory ingestion — ADAPT (data pattern)

**What it is.** [OSV.dev](https://github.com/google/osv-scanner) (Google;
osv-scanner released under Apache-2.0) is a continuously-updated,
machine-readable vulnerability database (38,000+ advisories across 25+
ecosystems at last count, sourced from GitHub Security Advisories, RustSec,
distro notices). The pattern: advisories are version-range records keyed by
package; `osv-scanner` re-evaluates a project's *unchanged* lockfile/SBOM
against the *current* database. The knowledge moves; the artifact doesn't.

**Threat closed:** silent-vulnerability accumulation in pinned dependencies
— the skill whose vendored `deps/` (mpak's MCPB shape, wave-306 verdict #2)
was clean at install and is flag
...[truncated 11469 chars]