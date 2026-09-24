# GAP-5 — Continuous re-verification of use-time bindings spec

**Gap:** GAP-5 (continuous re-verification against supply-chain rug pulls), wave proposal 5 of
`research/agent-attack-futures-2026-09-23.md` §"Wave proposal 5". Research-backed attack shapes:
postmark-mcp (15 clean releases, then BCC'd every agent-sent email), Cursor MCPoison (trust bound
to server *name*, server swapped silently after approval), SkillJacking dead-link takeovers.

**Existing:** `gov/skill_watch.py` pins skill content digests at install, re-verifies at use time
(`check_at_use`, wired into the executor verdict path) and on schedule (`verify_all`), quarantines
on drift, and requires a governed re-pin approval bound to the observed mutation. F142 Leg B added
referenced-URL content binding (manifest digest was not enough — the URL target could rug-pull
under a byte-identical manifest).

**The remaining hole:** the use-time check binds only the *content digest* (+ referenced URLs).
Two bindings named in the gap directive are missing:

1. **MCP server identity.** Attribution is by server *name* (`skill_id_for_tool` → `mcp/<server_id>`
   from the adapter-declared `mcp_server` kwarg). A swapped server behind the same name passes the
   watcher as long as the deployment's content source is unchanged — the watcher has no observation
   of the live wire identity. This is the MCPoison shape, and the Deadbugz shape (benign first-N,
   hostile after) at the watcher layer.
2. **Version pin.** `origin` may carry a version label, but nothing verifies it at use time. Version
   confusion across approvals/registrations is unbound: the re-pin approval binds `new_digest`
   (+ `new_reference_hashes` since Leg B) but not the version label the operator reviewed.

## Seams (existing, public — no new seams)

- `gov.skill_watch.ContentSource` — the observation seam (+2 optional methods; defaults = unbound).
- `SkillWatch.register_skill` / `check_at_use` / `verify_all` / `request_repin` / `approve_repin`.
- `PinStore.save` / `peek` / `load` (additive schema).
- Executor wiring (`ToolExecutor.call` → `check_at_use`) unchanged — zero new executor code.
- No new modules, no new public classes.

## Design

### Observation: `ContentSource.identity_bytes()` and `ContentSource.version_hint()`

```python
class ContentSource:
    def identity_bytes(self):
        """Canonical live-identity bytes, or None when unbound (default)."""
        return None
    def version_hint(self):
        """Observed version label, or None when unobservable (default)."""
        return None
```

- `identity_bytes()` returns the *live wire identity* as opaque bytes (e.g. canonical JSON of
  `{server_id, instructions_sha256, tools: [{name, metadata_hash}]}` as observed through the
  governed MCP adapter). It is deliberately a separate method from `read_bytes()`: the content
  pin covers the *approved artifact*; the identity pin covers *what the wire claims to be right
  now*. For file-backed skills they coincide; for MCP servers they are different trust objects
  observed through different channels.
- `version_hint()` returns the currently observed version label (registry version, server
  `version` field). `None` = the source cannot observe a version.
- Both are hashed/compared as opaque values, exactly like content bytes. No format is imposed.

### Registration binding (`register_skill`, unchanged signature)

- `version = origin.get("version")`. When present it must be a non-empty string, else
  `SkillWatchError`. A pinned version **requires an observable version**: if
  `source.version_hint()` is `None` at registration while `origin` carries a version, registration
  is refused loudly — a version the deployment cannot observe is a trust hole, not a pin.
- `identity = source.identity_bytes()`. When not `None` it must be non-empty bytes, else
  `SkillWatchError`. A raising `identity_bytes()` refuses registration (fail-closed, mirroring
  unreadable content); a `None` return simply leaves the skill identity-unbound (opt-in binding).
- The pin record stores `pinned_version` (or `None`) and `identity_digest` (sha256 hex, or `None`).

### Use-time and sweep re-verification

`check_at_use` and `verify_all` run the existing manifest (+ references) checks first, then — on
**both** the stat-prefilter fast path and the re-hash slow path (the stat hint covers only the
manifest file; the wire identity and version are independent observations, exactly the Leg B
reasoning for references):

- **Identity bound:** re-read `identity_bytes()`. `None` now (was bound) → quarantine
  (`identity-unverifiable-quarantined`: the observation downgraded — fail closed). Raises →
  quarantine (`identity-unverifiable-quarantined`). Bytes whose digest differs →
  `_handle_identity_drift` → quarantine + `skill_server_identity_drift` event carrying
  `previous_identity_digest` / `observed_identity_digest` + origin (digests, never content).
- **Version pinned:** re-read `version_hint()`. `None` → quarantine
  (`version-unverifiable-quarantined`: pinned but no longer observable). Mismatch →
  quarantine + `skill_version_drift` event carrying `previous_version` / `observed_version`.
- `verify_all` report gains `identity_drift` and `version_drift` lists.

### Governed re-binding (`request_repin` / `approve_repin`)

- `request_repin` records `observed_version` and `observed_identity_digest` alongside the existing
  `observed_digest` / `observed_reference_hashes`.
- `approve_repin` accepts optional `new_version` / `new_identity_digest` in the approval dict. Each
  must equal the **freshly observed** value at approval time; otherwise the approval is refused and
  the skill stays quarantined (bait-and-switch protection, mirroring the manifest digest and Leg B
  reference hashes — the wire must not move under the operator's review).
- On success the pins update, the skill unquarantines, and `skill_repinned` carries the new
  version/identity fields.

### Persistence (`PinStore`)

`pinned_version` and `identity_digest` serialize with each pin record. Schema is additive:
pre-existing pin files load with both `None`. `peek` validates types (`None` or non-empty
string / 64-char hex).

### Quarantine vs fail-closed semantics

| Condition | Verdict |
|---|---|
| Manifest digest drift | quarantine (`mutated-quarantined`) — existing |
| Identity drift (bound) | quarantine (`identity-drift-quarantined`) + `skill_server_identity_drift` |
| Version drift (pinned) | quarantine (`version-drift-quarantined`) + `skill_version_drift` |
| Identity/version unobservable or source raises | quarantine (`...-unverifiable-quarantined`) — a watcher failure never reads as clean |
| Skill id never registered | deny, **no** quarantine invented (F143 — existing) |
| No identity/version bound | manifest check only (opt-in bindings; absence is not failure) |
| Re-pin approval vs fresh observation mismatch | approval refused, stays quarantined |

## Testing

- Break battery `evals/gap5_reverify_break.py` (module-level `GOV_DEPLOYMENT_MODE=staging`,
  verified under `env -u GOV_DEPLOYMENT_MODE`): MCPoison identity-swap, version drift,
  dark wire, unobservable version, executor-level call denial, re-pin bait-and-switch —
  BREAK pre-fix (the seam is unobserved: the rug pull executes), HELD post-fix.
  Baseline probes (manifest swap, unbound skill) stay HELD throughout.
- Unit tests in `tests/test_skill_watch.py` at the existing seams: registration validation,
  use-time identity/version drift + quarantine, fast-path re-check, re-pin binding,
  PinStore round-trip with the new fields, executor wiring denial reason.

## Out of scope

- A compromised registry root-of-trust itself (deployment-responsibility boundary — stated
  honestly; pins authenticate against the registry the deployment chose).
- Semantic/behavioral drift with byte-identical identity (e.g. hostile tool *results* — the
  f145 p2 documented boundary; result content stays out-of-band for the watcher by design).
- Imposing an identity format on MCP servers (opaque bytes; the adapter's canonicalization,
  if any, is deployment-owned).
- Cross-process pin locking (pre-existing residual, unchanged).
