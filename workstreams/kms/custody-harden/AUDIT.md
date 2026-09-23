# Key-custody audit — wave-81 dev-key deletion verification

Stream 2, 2026-09-23. Scope: the private agent-governance repo
(`agent-governance-demo-main` tree). Claim under test: *"wave-81 deleted
the dev-key provider and every dev-key opt-in from gov/; key resolution
is configured env key → configured keyring file → loud
`NoKeyConfiguredError` in every mode."*

Method: full-text sweep of `gov/`, `tests/`, `examples/`, `demo/`,
`evals/`, `workstreams/` for dev-key/test-key paths, hardcoded key
material, test fixtures importable by `gov/`, env-var backdoors, and
insecure-default key material; targeted code reads of every hit; live
test runs of the key-management suites under `~/workspace/.gov-venv`.

## Verdict on the wave-81 claim: CONFIRMED (with one real gap and doc drift)

The dev key, the dev-key provider, and every dev-key opt-in are gone
from `gov/`. Resolution is exactly as claimed. One REAL-GAP (G1) and
several DOC-DRIFT items were found; no silent dev-key path survives.

---

## CLOSED-by-wave-81 (claim verified live, not just asserted)

- **C1 — `gov/keyprovider.py`.** `DevKeyProvider` deleted; the dev-key
  fallback deleted; `production_contradiction()` and
  `_dev_material_rejected()` deleted. `resolve_active_key()`:
  `GOV_LOG_KEY` → `GOV_KEYRING_FILE` → `NoKeyConfiguredError` in every
  mode. Verified by code read and by `tests/test_w81_no_dev_fallback.py`
  (asserts `DevKeyProvider`, `production_contradiction`,
  `_DEV_KEY_CANONICAL`, `enable_dev_keys`, `GOV_DEV_KEYS` etc. are all
  absent — 42 tests OK with `test_s6_lineage`).
- **C2 — `gov/keys.py`.** Public dev key, `KeyMaterial.dev()`
  constructor, and the dev opt-in env var deleted. `require_key()` /
  `require_production_key()` raise `NoKeyConfiguredError` when
  unconfigured, in every mode.
- **C3 — `gov/kms.py`.** The dev opt-in gate for the fake KMS provider
  deleted. `kms_provider_from_config` refuses `"fake"` unconditionally
  (was: allowed under the dev opt-in) and refuses `"aws"`/`"gcp"`/
  `"azure"` (real adapters not shipped: $0, no network, no credentials).
  `FakeKmsProvider` keeps a fixed test-only wrap secret, is documented
  as zero-production-security, and is never constructible from operator
  config — tests build it directly in code.
- **C4 — `gov/log.py::_active_key`.** Delegates to
  `keyprovider.resolve_active_key`; no dev path on the live-log path.
- **C5 — `gov/anchorer.py::resolve_anchor_key`.** The dev double-opt-in
  branch deleted. Returns `"dev": False` always; unconfigured anchoring
  raises `NoAnchorKeyError` in every mode (chain continues
  operator-attested-only, never silently unanchored).
- **C6 — `gov/egress_ledger.py::_ledger_keyring`.** Delegates to
  `gov.log._active_key()` → fail-closed; the ledger cannot verify (or
  start) without a configured key.
- **C7 — `tests/keyfixture.py`.** Lives in `tests/`, never in `gov/`.
  Provisions fresh `secrets.token_bytes(32)` per call through the
  production env backend. Verified: **zero** `gov/` modules import from
  `tests/` (grep for `from tests` / `import tests` / `keyfixture` in
  `gov/` returns nothing).

## FALSE-ALARM (looked suspicious, verified benign)

- **FA1 — `anchorer.py` `"dev"` dict field.** Dead API residue:
  `resolve_anchor_key()` can never return `True`; the flag only fires a
  stderr warning. The single `"dev": True` occurrence in the tree is
  `tests/test_w72_anchor.py:54`, which explicitly constructs the dict to
  exercise the warning path (the WARNING seen in the regression run is
  that test, expected).
- **FA2 — `delegation_tokens.generate_test_keypair`.** Fresh random seed
  per call; callers are all in `tests/`; `gov/capability_leases.py`
  mentions it only in comments.
- **FA3 — `recovery.py` ephemeral keys in non-production modes.**
  Mode-gated: production *requires* explicit `recovery_key`/`halt_key`
  (`RecoveryError` otherwise); other modes generate fresh random keys
  (unguessable, per-process — not a shared/public dev key). Documented
  behavior.
- **FA4 — `GOV_DEMO_CIPHER_OK` (`gov/platform_egress.py`).** Deliberate
  anti-copy-paste hardening (wave-37): the TEST-ONLY
  `demonstration_cipher` requires explicit passing AND the env var, so a
  production copy-paste of the test call fails LOUD instead of silently
  shipping malleable crypto. A gate, not a backdoor.
- **FA5 — `gov/sterile.py` token/secret assignments.** Verified
  structurally: every assignment RHS is `secrets.token_bytes(32)` (or a
  `bytes(...)` copy) — ephemeral per-instance values, no literals. (The
  `<redacted>` rendering in tool output is the runtime's secret-pattern
  filter, cosmetic.)
- **FA6 — `gov/lineage.py::_load_or_create_key`.** Silently provisions a
  *fresh random* 32-byte run key per tracker dir (0600 on create). Not a
  dev/test key: unguessable, per-directory, not shared. See G1 for the
  missing permission check on *existing* key files.
- **FA7 — demo/examples/evals key provisioning.** All fresh random
  (`secrets.token_hex(32)`) via `os.environ.setdefault` (respects an
  operator-configured key), or explicit harness literals (`"w8key"`) in
  eval code. Not reachable from `gov/`.
- **FA8 — `generate_seed` helpers (`gov/custody.py`, `gov/ed25519.py`).**
  Explicit operator-invoked keygen; never called implicitly.
- **FA9 — hex strings in `evals/llm_redteam/results/`.** Synthetic
  canary/shim artifacts from red-team runs, not governance key material.
- **FA10 — `audit_anchors(key=None)`.** Resolves to "needs-key", never
  generates a key.

## REAL-GAP

- **G1 — Inconsistent permission fail-closed posture across key-loading
  paths (LOW severity, hardening).** Four key-loading paths refuse
  group/world-readable files with `PermissionError`
  (`KeyRing.load`, `EnvelopeKeyRing.load`, `ShareStore.load`,
  `load_root_seed`), but two do not:
  1. `gov/anchorer.py::resolve_anchor_key` — a `GOV_ANCHOR_KEY_FILE`
     with mode 0644 produces only a **stderr warning** and loads anyway.
     On a shared host this leaks the Ed25519 anchor seed to other local
     users; the only signal is a warning that scrolls by.
  2. `gov/lineage.py::_load_or_create_key` — performs **no permission
     check at all** on an existing run-key file; a 0644 key file is
     loaded silently.
  
  Neither is a dev-key path, but both violate the uniform fail-closed
  posture the rest of the key surface already implements, and both guard
  key material an operator never explicitly provisioned (the lineage key
  is auto-created). Prototype fix: `strict_keyfiles.py` in this
  directory — a uniform `require_private_key_file()` plus strict
  anchor-seed and lineage-key loaders, with tests
  (`test_strict_keyfiles.py`). Reference implementation for central
  integration; porting into `gov/` is a behavior change for deployments
  with 0644 anchor key files (they would fail closed on upgrade — needs
  a migration note).

## DOC-DRIFT (main tree untouched per constraints; for central integration)

- **D1 — `docs/DEPLOYMENT.md` documents `GOV_DEV_KEYS` as a LIVE gate**
  (lines 29, 103, 124, 410: "`=1` permits the `FakeKmsProvider` test
  double and the publicly-known development HMAC key"). Both the env var
  and the dev key no longer exist. Actively misleading to operators.
- **D2 — `workstreams/kms/CEREMONY_RUNBOOK.md` rehearsal section**
  (lines 51–62) instructs `GOV_DEV_KEYS=1` then
  `kms_provider_from_config({"provider": "fake", ...})` — this now
  raises `KmsError` unconditionally, so the rehearsal instructions are
  broken, not just stale.
- **D3 — `docs/READINESS_GAPS.md:48`** repeats the stale
  "refused outside `GOV_DEV_KEYS=1`" claim.
- **D4 — `gov/egress_ledger.py` stale dev-key-era docstrings** (module
  docstring ~lines 45–75: "when only the public dev key is configured… a
  T6 attacker knows"; `_ledger_keyring` docstring ~246–247: "dev keys
  require the double opt-in and refuse in production"; `require_verified`
  docstring ~761–768). The code is correct (fail-closed); the prose
  describes the pre-wave-81 world.
- **D5 — Minor:** `gov/kms.py` references `DESIGN.md §2, §9` and
  `workstreams/kms/redteam/attack_kms_impersonator.py`; neither exists in
  the tree.

## Notes (not gaps)

- **N1 — `_real_key_available()`** (`gov/egress_ledger.py`) checks only
  `GOV_LOG_KEY`, not `GOV_KEYRING_FILE`. Fail-safe direction: a
  keyring-file deployment bypasses the stat-signature cache and fully
  re-verifies every decision (slower, never less safe).
- **N2 — `EnvelopeKmsProvider` / `activate()`** publishes materialized
  plaintext epoch keys into process env (`GOV_LOG_KEY*`). Documented,
  deliberate full-materialization path; the KMS provider itself never
  persists plaintext.

## Regression evidence

- `~/workspace/.gov-venv/bin/python -m unittest tests.test_keys
  tests.test_kms tests.test_custody tests.test_w69_key_management
  tests.test_w70_key_management tests.test_w72_anchor` → **196 tests OK**
  (TMPDIR=/tmp/gov-s2-regress).
- `... tests.test_w81_no_dev_fallback tests.test_s6_lineage` → **42
  tests OK** (TMPDIR=/tmp/gov-s2-w81).
- (pytest is not installed in the venv; $0/no-network forbids installing
  it. The repo's canonical runner is unittest-based; used accordingly.)
