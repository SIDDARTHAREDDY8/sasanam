# Red Team Situation Taxonomy (wave-20)

Canonical taxonomy for classifying adversarial situations probed against
this governance demo. Every situation in a wave probe file and every entry
in `scenarios/registry.yaml` is classified along these dimensions.

## Dimensions

### 1. Actor / error model

Who (or what) performs the hostile or erroneous action.

| Value | Meaning |
|---|---|
| `human-error` | A well-meaning operator or deployer makes a mistake (misconfig, typo, wrong file, skipped step). No malice. |
| `single-agent` | One governed agent acts against policy or is tricked (prompt injection, confused deputy). |
| `swarm` | Two or more agents coordinate (or are coordinated) to defeat a control no single agent could defeat alone: collusion, vote-stuffing, channel fan-out, quorum gaming. |
| `supply-chain` | The attack arrives via a dependency, tool, model, MCP server, or build artifact the deployer trusts. |
| `insider` | A privileged operator or a process with legitimate elevated access (run-dir writer, ceremony participant, console operator) abuses it. |
| `external` | An unauthenticated network party (CSRF origin, token thief, replay). |

### 2. Attack class

The family of the hostile technique, aligned with `THREAT_MODEL.md`.

`prompt-injection` · `channel-confusion` · `crypto-substitution` ·
`key-management` · `policy-evasion` · `approval-abuse` · `session-abuse` ·
`audit-tampering` · `custody-abuse` · `quorum-gaming` · `replay` ·
`truncation` · `equivocation` · `homoglyph` · `configuration-abuse` ·
`availability` · `composition` (two individually-stopped weaknesses that
combine into a break).

### 3. Technique

The concrete mechanism, e.g. `env-var-smuggling`, `epoch-confusion`,
`forged-channel-tag`, `missing-channel-tag`, `unicode-delimiter-evasion`,
`transcript-tail-truncation`, `session-fixation`, `logout-csrf`,
`roster-replay`, `share-equivocation`, `break-glass-ticket-theft`,
`tool-schema-smuggling`.

### 4. Target surface

The subsystem under test: `kms`, `log-chain`, `policy-engine`,
`approvals-queue`, `approval-web`, `executor`, `egress-ledger`,
`adapters-channels`, `adapters-trust`, `custody`, `threshold-checkpoint`,
`realagent-sandbox`, `swarm-channel`.

### 5. Preconditions

What the actor needs first: `none`, `run-dir-write`, `env-write`,
`session-cookie`, `stolen-token`, `compromised-share`, `malicious-tool`,
`hostile-in-process`, `operator-error`, `network-position`.

Preconditions marked `hostile-in-process` are a known accepted residual
class (F59 family): an attacker who can already execute arbitrary Python in
the governance process can equally rewrite the controls themselves, so
bypasses at that layer are recorded as documented residuals, not findings.

### 6. Expected control

The control that should stop the situation, named precisely
(module + function + the invariant), e.g.
`gov.adapters.channels.assert_channel_separation` — tool-role messages
must carry `channel: data`.

### 7. Oracle

How the probe decides stopped vs break. One of:

- `raises` — a typed exception is raised (fail closed).
- `denied` — policy/queue returns a denial decision.
- `quarantined` — content is demoted and flagged, never promoted.
- `detected` — tampering is evident to the verifier.
- `no-op` — the hostile action has no effect (replay of a spent token).
- `flagged` — the action is allowed but carries an explicit audit flag.
- `break` — none of the above: the hostile path completes silently.

### 8. Severity (findings only)

| Level | Meaning |
|---|---|
| HIGH | Bypasses a core guarantee (audit integrity, key secrecy, approval binding) with realistic preconditions. |
| MEDIUM | Weakens a core guarantee, or bypasses it with narrow/strong preconditions. |
| LOW | Detection/audit-signal gap, availability cost, or defense-in-depth hardening with no direct bypass. |

### 9. Lifecycle

`probed` → (`stopped` | `break`) → `filed` (F-number) → `hardened` |
`open` → `closed` (closure probe green). Closure probes live next to the
finding reference in the probe file.

### 10. Variant axes

Each situation may declare variant axes for systematic expansion:
`encoding` (utf-8/utf-16/normalization), `position` (head/middle/tail),
`timing` (immediate/delayed/multi-turn), `multiplicity` (1/n), `channel`
(tool/user/system/developer), `epoch` (current/retired/dev).

## Classes covered by this taxonomy

- **Human error** — the Real Agent workstream's 7 canonical human-error
  scenarios (see registry `ra-human-*`).
- **Single agent** — prompt injection, tool misuse, sandbox escape
  attempts, traversal (F-RA3 family).
- **Swarm** — the 8 canonical swarm scenarios (registry `ra-swarm-*`)
  plus red-team swarm probes over the new channel mechanisms.
- **Supply chain** — malicious tool schemas (F62 family), poisoned MCP
  descriptions, compromised dependencies.
- **Custody / crypto** — KMS resolver, envelope keyring, ceremony
  transcripts, threshold checkpoints, roster lineage.
- **UI / session** — approval web sessions, CSRF, fixation, replay,
  Origin handling, logout.
- **Composition** — pairs of stopped weaknesses whose combination breaks.

## Mapping to THREAT_MODEL.md

The threat catalog's trust boundaries map to preconditions; the catalog's
"controls" map to expected controls. Where this taxonomy names a
situation the threat model does not yet cover, the finding that files it
must propose the threat-model delta.
