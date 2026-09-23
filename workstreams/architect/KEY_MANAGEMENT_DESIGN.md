# Key management: killing the dev-key fallback (Wave-69 design)

**Status:** design + implementation (2026-09-22). Standing priority #1
since 2026-09-21. This is the F29 boundary under everything waves 64–68
built: attribution (wave-67), the evidence export (wave-68), and the
registry all chain under a key. Under the public development key, all of
it is forgeable by anyone who read the docs — the F29 documented
posture. This design answers: what "production" means for keys, how the
code knows, and what happens to every chain written before the answer
existed.

Prior art in-tree: `gov/keys.py` (KeyRing: env + file backends, epochs,
rotation ceremony), `gov/kms.py` (envelope encryption, FakeKmsProvider,
EnvelopeKeyRing), `gov/log.py::_active_key` (F73 strict resolution),
`gov/sandbox.py::_resolve_seccomp_tier` (wave-61 deployment_mode
precedent — explicit declaration, default least-privilege, contradiction
refuses loud). This design formalizes the resolution chokepoint as a
`KeyProvider` interface and adds the one missing guard: **production
mode + dev-key request → refuse loud** (the wave-61 contradiction shape
applied to keys).

## (a) The KeyProvider interface (`gov/keyprovider.py`)

```python
class KeyProvider(abc.ABC):
    provider_name = "abstract"
    @abc.abstractmethod
    def resolve(self): ...      # -> (key_bytes, key_epoch); raises NoKeyConfiguredError
    def describe(self): ...     # safe metadata only — never key material
```

Implementations (all fail closed; none silently substitute another):

- **`DevKeyProvider`** — the existing dev-key path, kept ONLY for
  tests/dev, loudly marked. Requires the double opt-in (in-code
  `enable_dev_keys()` AND `GOV_DEV_KEYS=1`); emits the loud stderr
  banner on resolve; `describe()` reports `{"provider": "dev",
  "warning": "PUBLIC development key — zero integrity"}`. **Refuses
  outright in production mode** (the §(b) contradiction). There is no
  configuration that makes the dev key valid in production: pasting the
  dev bytes into `GOV_LOG_KEY` or naming the epoch `dev` is rejected
  (F73), and smuggling it via `GOV_LOG_KEY_ARCHIVE` is rejected (F77).
- **`EnvKeyProvider`** — `GOV_LOG_KEY` / `GOV_LOG_KEY_EPOCH` /
  `GOV_LOG_KEY_ARCHIVE` backend (the `KeyRing.from_env` shape). Screens
  dev material on resolve (bytes, epoch, archive) — a configured key
  that IS the dev key is not a production key.
- **`FileKeyProvider(path)`** — the local software reference provider:
  a file-backed `KeyRing` (`keys.KeyRing.load`), 0600 enforced on load
  (refuses group/world-readable), atomic 0600 writes on save, rotation
  lock for concurrent ceremonies. This is the least-bad $0 local
  option: no network, no credentials, deterministic, hermetic in CI.
  - Why not the OS keyring (secretstorage/keyring)? Needs dbus, a login
    session, and platform-specific daemons — non-hermetic, untestable in
    this sandbox, and still software custody. It buys nothing here.
  - Why not env-only? Process environments leak to child processes,
    `/proc/<pid>/environ`, and crash dumps; a file with 0600 is the
    narrower carrier.
  - **Why it is still not HSM (honest limits):** the file is readable
    by the uid and by root; backups and disk images exfiltrate it; there
    is no hardware custody, no tamper-evident access logging, and
    in-memory plaintext is protected only by process boundaries. A
    deployment that needs more uses the envelope provider below or real
    KMS custody (§(e)).
- **`EnvelopeKmsProvider(envelope_path, kms_provider)`** — wraps
  `kms.EnvelopeKeyRing`: the persisted file holds wrapped blobs +
  metadata only; plaintext exists only in memory after explicit unwrap.
  The config factory refuses `provider: fake` outside `GOV_DEV_KEYS=1`;
  real cloud adapters are not built in this repo ($0). Operator-driven
  (load → materialize → activate), not auto-detected by the resolver —
  KMS custody is a deployment choice, and auto-detecting it from env
  would add attacker-influenceable surface.

Resolution order in `resolve_active_key(deployment_mode=None)` (the single
chokepoint `gov/log.py::_active_key` delegates to; chain mechanics in
`log.py` untouched):

1. `mode = resolve_deployment_mode(deployment_mode)` — explicit kwarg wins, then
   `GOV_DEPLOYMENT_MODE` env, then default `"production"`
   (least-privilege); unknown mode → `ValueError` fail-fast (wave-61).
2. `GOV_LOG_KEY` set → `EnvKeyProvider` (dev material screened).
3. `GOV_KEYRING_FILE` set → `FileKeyProvider` (0600 enforced, dev
   material screened).
4. Neither configured: production mode → `NoKeyConfiguredError`
   (F73 — refuse to start the chain, loud, never fall back); dev mode
   (`"staging"`/`"dev"`/`"test"`) + double opt-in → `DevKeyProvider`
   (loud warning); dev mode without the opt-in → `NoKeyConfiguredError`.
5. **Contradiction (new, wave-69):** production mode + dev-key request
   (double opt-in present, no configured key) → `NoKeyConfiguredError`
   with a contradiction message naming both signals and how to resolve
   (declare a non-production mode, or configure a real key). This is the
   `_resolve_seccomp_tier` shape: a deployment that declared itself
   production but has dev-key enabling active (stray import of demo/eval
   code + inherited env var) previously got dev-key chains behind a
   stderr warning; now it refuses.

`keys.require_key()` is tightened to the same double opt-in as
`gov/log.py` (in-code call AND env) — its env-only dev fallback had no
production callers but its contract disagreed with the log path's; the
strict path remains `require_production_key()` (no dev fallback at all).

## (b) The fail-closed rule

| deployment_mode | key state | outcome |
|---|---|---|
| production (default) | no key configured | `NoKeyConfiguredError` — refuse to start the chain (F73, unchanged) |
| production | dev bytes / `dev` epoch / dev in archive | `NoKeyConfiguredError` — dev material rejected outright (F73/F77, unchanged) |
| production | dev opt-in present (in-code + env) | **`NoKeyConfiguredError` — contradiction, refuse LOUD (new)** |
| production | real key configured | chain starts under the configured epoch |
| staging/dev/test | double opt-in | dev key, loud warning (test path, loudly marked) |
| staging/dev/test | real key configured | chain starts under the configured epoch |
| any | unknown mode string | `ValueError` fail-fast |

"How does the code know it's production": `GOV_DEPLOYMENT_MODE` (operator
declaration) or the `deployment_mode=` kwarg (authoritative, wins over
env) — the wave-61 precedent verbatim. Wave-70 closes the wave-69
loose end: the kwarg is now wired end-to-end, not just on
`resolve_active_key()`. `ActionLog(..., deployment_mode=...)`
(keyword-only, default `None`) flows the declaration into the
instance's key-resolving operations (`append`, `write_checkpoint`);
`keys.require_key(*, deployment_mode=...)` applies it to the
contradiction check. Unknown modes fail fast at `ActionLog`
construction. Module-level verification helpers keep the default
(env → production): verification must work regardless of a
creation-time declaration. Deliberately NOT wired: `EgressLedger`
— wave-71 resolved the wave-70 follow-up tension ONE way, in favor
of the "SAME key epochs as the action log" contract: the ledger
never declares its own mode (a `deployment_mode=` kwarg would let
the ledger's key epochs fork away from the log's — per-ledger
forking is not expressible, `TypeError` by construction). One
process-level declaration (`GOV_DEPLOYMENT_MODE`) moves the log and
the ledger together; `evals/w71_probes.py` pins all three shapes
(same epoch under one declaration; kwarg rejected; kwarg/env
mismatch refuses loud via the production+dev contradiction, never
silently forks). Deployments using the per-instance `ActionLog`
kwarg alongside the ledger must align via env — documented
operator-alignment boundary, not a finding (not attacker-reachable;
mismatch fails loud as an epoch/contradiction refusal, never
silent). `require_production_key()` (always production by contract
— a mode kwarg would be meaningless), and the explicit provider
selectors (`KeyRing.from_env/from_file`, envelope KMS —
mode-agnostic by design). Unset/empty/garbage defaults to
`"production"`: ambiguity defaults to the safe direction, exactly as the
sandbox tier guard does. The test corpus declares itself non-production
at its entry points (`tests/__init__.py`, `evals/run_evals.py`,
`evals/trial_runner.py`, demo mains, `gov/verify.py --dev`) — synthetic
harnesses saying so explicitly is the wave-61 discipline.

## (c) Migration semantics for existing chains

Old dev-key chains are **NOT re-signed** — rewriting history is the
attack, not the migration. They verify as the **dev-key era**
(`key_epoch: "dev"` bound to the public key), explicitly graded:

- **Dev era** (`dev`): the chain replay is a *consistency check on the
  local copy*, forgeable by anyone who read the docs. Usable for
  functional testing of the pipeline; carries **zero evidentiary
  weight**. The evidence export banners it `PUBLIC/DEVELOPMENT` (F29).
- **Operator era** (any configured epoch): tamper-evident against
  parties *without* the key. Honest limit: HMAC gives no
  non-repudiation between key holders — anyone holding the key could
  have written any entry. Key custody is the trust root; the export
  says "tamper-evident only against parties without the key" (F29).
- **Mixed era** (rotation boundary): each epoch verifies under its own
  key via `KeyRing.verify_log` (retired keys retained); each epoch is
  graded separately; the rotation event itself is chained
  (`record_rotation` logs epoch labels + key_ids, never material). The
  single-key verifier (`gov/log.py::_verify`) fails closed on
  mixed-epoch logs by design (F32) — use the ring verifier.

What an auditor may conclude: the era label tells them *which key* to
ask about, not *who held it*. `key_epoch` labels are self-declared
metadata; the F32 binding (label == configured epoch, else fail closed)
is what stops a dev-key forgery from rendering as production-grade.

## (d) Key rotation

The ceremony exists (`keys.rotate_keyring` / `kms.rotate_envelope_keyring`):
verify the old log with the old ring first (never rotate on top of a
compromised log), mint a fresh epoch + 256-bit key, retain the old key
as `retired`, atomic backup + persist (0600), serialized by the rotation
lock. Wave-69 adds the in-chain rotation event contract: `record_rotation`
appends `{event: key_rotation, new_epoch, new_key_id, retired_epochs[]}`
under the NEW epoch (identifiers only, never material).

- **Old-key verification:** retired keys stay in the ring; `verify_log`
  selects the key per entry epoch. Deleting a retired key orphans every
  entry it signed — the ceremony backs up the pre-rotation ring for
  exactly this reason.
- **In-flight runs:** a running process keeps the epoch it activated at
  start (activation publishes to the process env). Re-activating mid-run
  flips the era mid-chain → the single-key verifier fails closed (F32);
  the deployment procedure is **rotate between runs**, never under one.
  In-flight runs finish their epoch; new processes pick up the new one.
- **Splicing:** the MAC binds `(key_epoch, prev_hash, canonical)` — a
  segment lifted from the old epoch into a new position breaks the
  `prev_hash` link (and the epoch-keyed MAC), so `verify_log` fails
  closed. Break-first probes prove this.
- **Rotation is explicit, never implied by a code fix.** The JFrog
  Artifactory CVE-2026-82329 campaign (Aug–Sep 2026, intake
  `research/intake-wave69-2026-09-22.md`) is the industry case: the
  vendor's patch randomized the default join key but did NOT revoke
  attacker-minted tokens or rotate a captured cluster key — containment
  required four explicit operational steps. Same rule here: closing a
  key compromise means an explicit rotation ceremony; material signed
  under a captured key is treated as suspect, never silently re-signed
  (dev-era chains are never re-signed at all — they stay
  consistency-only). The design's "verify the old log with the old ring
  first" step exists for exactly this reason.

## (e) Out of scope (deployment-owned, reference level only)

- **HSM/KMS custody.** The envelope provider is the seam; which KMS, key
  policies, IAM, and rotation cadence are operator decisions. Real cloud
  adapters are not built here ($0, no credentials, no network).
- **Making the evidence export verify mixed-era logs.** A rotated log
  renders FAILED under the single-key verifier — fail-closed is the
  honest output; the operator re-verifies with `KeyRing.verify_log`.
- **OS-keyring / TPM backends.** Non-hermetic, untestable in this
  sandbox; the file-backed 0600 provider is the reference.
- **The commercial evidence pipeline** (metering, billing, SaaS
  export): strategic context, not build order. This wave hardens the
  enforcement core's key story only.

## Break-first results (summary; full battery in `evals/w69_probes.py`)

- **Fallback resurrection:** `GOV_DEV_KEYS=1` alone → refuse;
  dev bytes in `GOV_LOG_KEY` → refuse; `GOV_LOG_KEY_EPOCH=dev` with a
  real key → refuse; dev key smuggled in `GOV_LOG_KEY_ARCHIVE` → refuse;
  production mode + double opt-in → **refuse LOUD (new contradiction)**;
  staging + double opt-in → dev key with warning (legit path intact).
- **Key confusion:** dev-signed records presented to a prod verifier
  fail with era/label mismatch; prod-signed records presented to a dev
  verifier fail the same way. No cross-era verification, ever.
- **Mixed-key chains:** rotation mid-chain verifies per-epoch via
  `KeyRing.verify_log`; a spliced chain (old-epoch segment swapped into
  a new position) fails closed.
- **Lost-key behavior:** key file deleted/corrupted → `KeyRing.load`
  fails closed; `GOV_LOG_KEY` unset mid-run → next append raises
  `NoKeyConfiguredError` (no silent unsigned continuation); KMS outage
  during lazy unwrap → `KmsError`.
- **Era-marking honesty:** a dev-signed log with forged `production`
  labels fails verification and the export renders dev/FAILED — a prod
  banner over dev-key material is unreachable.
- **Legitimate regression:** the full canonical suite, registry gate,
  matrix, and battery run on the declared-staging dev path; dev-key era
  stays loudly marked (stderr banner, `dev` epoch on every entry).

## Residuals (honest, not findings)

1. Dev-key chains remain forgeable by docs-readers — the F29 documented
   posture, now fenced: dev keys are unreachable in production mode by
   any env/config/argument path the resolver knows.
2. HMAC gives no non-repudiation between key holders; custody is the
   trust root (stated in `gov/keys.py`, unchanged).
3. The contradiction detector keys off the *declared* mode — a
   deployment that lies about its mode defeats it the same way it
   defeats every declared-mode guard (wave-61 boundary, unchanged).
