# Supply-chain enforcement — design (wave-78, 2026-09-22)

Theme: **digest-verify every loadable artifact + kill ambient authority
with capability leases.** Incident class: Plugin4Shell (CVE-2026-92104,
disclosed 2026-09-17; intake in
`research/intake-wave78-2026-09-22.md`).

Prior work this builds on (not re-litigated): F75 closed (product
dependency lockfile + env audit, `gov/supplychain.py`); P7 closed
(agent-runtime package install gate, `gov/supplychain_install.py`);
MCP tool-definition pinning (metadata_hash + optional ed25519 server
provenance, `gov/adapters/mcp_adapter.py`); harness credential
compartmentalization (F111, `gov/credential_manifest.py`); the wave-74
three-token delegation system (`gov/delegation_tokens.py`); the wave-75
governed policy-change path (`gov/policy_change.py`).

## (a) Loadable-artifact inventory

Every artifact type the agent can load, its load path, and its
verification state before wave-78:

| # | Artifact | Load path | Verification state (pre-w78) |
|---|----------|-----------|------------------------------|
| 1 | Python dependencies (the product's own venv) | `pip install -r requirements.lock` | **Verified**: sha256 pins for all artifacts, env audit fail-closed (F75 closed) |
| 2 | Agent-runtime packages | `gov/supplychain_install.install_package` | **Verified**: exact pin + sha256 of fetched bytes (P7 closed); raw registry fetches denied by policy |
| 3 | MCP tool definitions | `GovernedMCPClient.list_tools` → per-call re-validation | **Partially verified**: canonical metadata hash pinned at first sight; optional ed25519 server provenance. Gap: the first-sight pin is adapter-local TOFU, not operator-pinned; the pin set is not a governed artifact |
| 4 | Skill content | sterile `skill_content` channel arrivals into model context | **UNVERIFIED**: labeled as supply-chain input, but nothing checks the bytes against anything. The Plugin4Shell shape: a skill "updated" via a mutable reference loads attacker bytes with no check |
| 5 | Policy YAML | `PolicyEngine(yaml_path)` at startup | **UNVERIFIED**: no digest binding between the reviewed policy text and the loaded bytes. Wave-75 governs *changes*; the initial load reads bytes from disk unpinned |
| 6 | Credential material the agent can reach | harness provisioning → `CredentialManifest` | **Scoped, not leased**: F111 asserts non-production, declared, TTL'd; the agent still holds credential-shaped material rather than capabilities |
| 7 | Provenance/audit records themselves | `ActionLog.append` | Integrity is the log's (HMAC chain); the *payload* an agent submits (e.g. skill content) was unverified — see #4 |

Wave-78 closes #4 and #5 with the artifact gate, and #6 with leases.
#3's gap is closed by moving the pin set into the governed artifact
pinset (below). #1/#2 are done; #7 is wave-72's.

The honest boundary: this wave governs the load paths *in this
product*. A deployment that shells out to a real `git` has no in-repo
git call sites (probe `redteam.supplychain.gitspawn_no_git_subprocess_in_repo`
pins that invariant); the host-side variant (GitHub's SHA-like-ref ban)
is not something this layer can rely on — which is exactly why the
gate refuses the ref namespace entirely rather than trying to sanitize
it.

## (b) Digest-verification protocol (`gov/load_gate.py`)

The protocol, stated exactly:

1. **Pins are digests, never references.** A pin is `sha256:<64-hex>`.
   Any attempt to register a pin that is a reference — branch name,
   tag, `latest`, version string, or a 40-hex string that would resolve
   through the ref namespace — is refused at *pin time*. A pinned
   reference is not a pinned artifact; we do not build machinery that
   accepts one.
2. **Resolve → fetch → verify → load.** The loader takes an
   `artifact_id`, fetches the candidate bytes, hashes them, and
   compares to the pin. Match → a `VerifiedArtifact` (bytes + digest)
   is returned. Mismatch → `ArtifactRefused` (fail closed), a
   `artifact_load_refused` provenance record, nothing is loaded.
3. **The ref namespace never enters the load path.** There is a
   simulated `RefResolver` in the module that models the Plugin4Shell
   shapes (branch named as the 40-hex SHA shadowing the commit,
   FETCH_HEAD games, tag-vs-branch confusion) — it exists so the
   break-first probes can replay the attack against a *legacy* loader.
   The governed loader never calls it. Any load request carrying a
   reference instead of a digest is refused as `reference_not_digest`.
4. **TOCTOU binding.** Verification and load are bound to the *same
   in-memory bytes object*: the loader reads once, hashes the bytes it
   holds, and the consumer receives exactly those bytes. There is no
   re-read, no re-fetch, no path the store can swap between the hash
   check and the handoff. A probe swaps the underlying store after
   verification and asserts the consumer still gets the verified bytes.
5. **Freshness, not just integrity.** A digest pin is immutable; pins
   change only through the governed pin-mutation path (§c), each change
   a chained provenance record. A stale-but-valid pin is a deployment
   decision (pin rotation), not a verification failure.

**TUF prior art, scoped honestly.** The Update Framework's core insight
— verify the artifact (targets metadata with hashes), never trust the
transport or the reference — is applied to the agent's load plane.
What is IN: hash-verified targets (our digest pins), a root of trust
for metadata (§c), and fail-closed verification before use. What is
explicitly OUT: multi-role delegation, threshold signing, and snapshot/
timestamp freshness roles. We are not building TUF; we are applying its
one load-bearing idea to tool/skill/policy loading.

## (c) Trust-on-first-use seam

This is the trust root of the whole scheme: if the first pin is
attacker-controlled, everything downstream is theater.

**Decision: there is no TOFU in the governed path.** The loader refuses
unpinned artifacts (`artifact_unpinned` — fail closed, loudly). The
first digest pin is a **policy-grade decision** and goes through the
wave-75 construction: pin mutations require an Ed25519 authorship token
from a roster human key (`DelegationTrust.human_keys`), verified in
code on the only mutation path (`ArtifactPinset.pin`), and each
mutation is a chained provenance record (`artifact_pinned` /
`artifact_unpinned`). Production deployments use the wave-75 tier rule
(two distinct human keys for production); dev/test take single-human —
the same rule, not a new one.

Who holds the seam: **the deployment operator**, via the offline-root
trust model (`gov/signing.py`): public keys are registered out-of-band;
rotation is an audited deployment act. The human-key-roster membership
itself is the seam — the deployment asserts that the registered key
belongs to the human, which is a deployment act, not a cryptographic
proof (same honest boundary as wave-74).

**Boundary note (not a finding):** an operator who pins an
attacker-chosen digest has a compromised *process*, not a compromised
*mechanism*. The governance layer guarantees that the pinning was
authorized by the roster and is auditable; it cannot guarantee the
operator reviewed the right bytes. That review step is a deployment
procedure (out of scope for code).

Refuted shape: "TOFU with a warning the operator must acknowledge."
A warning nobody reads is the `refname is ambiguous` of trust roots —
refused as a design. Unpinned = unloaded.

## (d) Capability leases (`gov/capability_leases.py`)

The agent never holds the developer's/operator's raw credentials. It
holds short-lived, scoped leases minted per task.

**Lease format** (all fields required; JSON-canonicalized for signing):

```
lease_id:      unique id (secrets.token_hex(16))
issuer_key_id: roster authority key id that minted it
agent_id:      the agent the lease is bound to
task_id:       the task the lease is bound to
scope:         {"tools": [...], "resources": {...}} — tool-granular
               (tool:<name> / tool:*), resource-scoped entries optional
not_before / expires_at: ISO-8601 UTC; default TTL 900 s, hard cap
               3600 s (beyond an hour is standing privilege, not a lease)
signature:     Ed25519 over the canonical body, by the minting authority
```

**Minting authority.** Only the deployment's registration-authority
key (`DelegationTrust.authority_keys`) mints, via `LeaseAuthority`
which holds the *private* key operator-side. The agent side holds only
public keys. Minting checks the requested scope against the agent's
registered capabilities (the wave-74 agent token) — a lease cannot
grant what the agent was never registered for. Lease minting reuses the
token/roster machinery (Ed25519, `generate_test_keypair` for tests,
`RevocationLedger` for revocation) but is a **separate token kind**
from delegation tokens: delegation = on-behalf-of authority (human →
agent); lease = per-task credential-shaped authority. Conflating them
would let a delegation's broad scope smuggle standing credentials —
kept separate by construction.

**Verification at use time.** `LeaseVerifier.require(lease, action)` —
called on *every* privileged tool call (the enforcement point the
executor installs; see wiring below) — checks, in order: signature
valid → issuer in roster → within `[not_before - skew, expires_at +
skew]` → not revoked (ledger) → `task_id`/`agent_id` binding matches
the current task → scope covers the action. Any failure raises
fail-closed (`LeaseRefused`, with a named reason code). Verification
uses only public keys; the verifier never touches private key material.

**Revocation.** Reuses `delegation_tokens.RevocationLedger` (the
documented seam). Revocation fails *future* authorizations loud;
propagation to already-issued offline verifiers is the stated wave-74
boundary, restated here, not re-litigated. Default is short TTL —
leases are 15 minutes by default, so TTL is the primary revocation
mechanism and the ledger is the emergency brake.

**Expiry mid-task.** There is no grace execution. The tool call that
lands after expiry is refused (`lease_expired`); the task cannot
proceed until the operator authority mints a fresh lease (the agent
may *request* re-mint; it may not mint). This is the wave-77 lesson
applied: a task that continues past its authority's death replays
compromise with extra steps. The request path is audited
(`lease_remint_requested` / `lease_reminted`).

**Ambient-credential absence mechanism.** Two halves:
1. *Constructive*: the agent's execution environment is built with no
   operator key material — the lease verifier and executor hold only
   public keys; `LeaseAuthority` (private key) is never installed on
   the agent side. A probe asserts the agent-side verifier object graph
   contains no private-key bytes.
2. *Assertive*: at session open, `assert_agent_scope_clean` scans the
   agent-reachable scope (env + manifest-declared paths) with the
   F111 DLP rules — any production-shaped credential material in the
   agent's scope fails the session open closed. Leases are explicitly
   *not* credential-shaped for DLP purposes (they carry no secret), so
   the assertion does not false-positive on the lease itself.

**Executor wiring.** `ToolExecutor(lease_verifier=..., lease_scope=...)`
opt-in, mirroring the wave-77 `recovery=` wiring: when installed, the
verdict path requires a valid presented lease for tools in the
lease-gated set *before* policy evaluation; refusal is fail-closed and
audited as `lease_refused`. Default (no verifier installed) = unchanged
behavior — the 2577-test suite does not move.

**Wave-74 TTL honesty note, restated.** Short TTLs paper over
revocation; true propagation is a stated boundary. Same boundary,
same honesty: leases are 15-minute TTL by default *because* revocation
propagation is bounded.

## (e) Blast-radius claim — stated exactly

**Before wave-78** (measured by the break-first probes against the
unhardened paths):
- A compromised skill (or a skill swapped via a mutable reference)
  loaded attacker bytes into the agent's context with **no check** —
  the sterile channel labeled it, nothing verified it.
- A compromised agent identity inherited the harness's reach: the
  session identity (F55) plus whatever credential-shaped material the
  harness provisioned (F111-scoped but still credentials, still
  reusable by the agent).
- A pinned *reference* (commit hash as a branch name) was honored
  while different bytes loaded — verify ≠ checkout.

**After wave-78** (each clause has a probe):
- A compromised skill yields **nothing**: the loader refuses bytes
  that don't match the operator-pinned digest (`digest_mismatch`
  refused, loudly, chained). The attacker must compromise the
  operator's pinning ceremony — a different, audited, human-keyed
  event — not the skill store.
- A compromised agent identity yields **only its leases**: scoped to
  (task, tools, resources), ≤15 min by default, revocable, and bound
  to the task — a lease stolen to another task, tool, or time window
  is refused *at use time*. There are no standing credentials to
  steal: the agent's scope contains no raw operator credentials (the
  absence mechanism, §d), and the private minting key never crosses
  into agent-reachable memory.
- The Plugin4Shell shape is refused **by construction**: the load path
  has no ref-resolution step, so there is nothing for a shadowing
  branch to shadow. The refname-ambiguity warning is moot — ambiguity
  cannot occur where references are not resolved.

**What this does NOT claim:** un-exfiltration of data already read;
protection against an operator who pins attacker bytes (the §c
boundary); revocation propagation to offline verifiers (the wave-74
boundary); or host-side git behavior on the deployer's own machines
(no in-repo git call sites — the invariant probe keeps it that way).

## Deliberately not done

- No full TUF (no multi-role delegation, no threshold signing, no
  snapshot/timestamp roles) — stated in §b.
- No DPoP/mTLS-bound leases (public intake shows the direction;
  building it is future work, not claimed).
- No automatic lease re-mint (the agent requests; the authority
  mints — auto-minting is the standing-privilege shape with extra
  steps).
- No resource-scoped lease language beyond tool + simple resource
  constraints (v1 scope language, same honesty as wave-74's).
- No commercial evidence pipeline (strategic context only).
- The F81 filtered-egress wall stays a separate, privileged-CI-blocked
  track; nothing here touches egress mechanisms.
