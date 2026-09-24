# Spec — F160: KMS config factory transport knobs + error-type contract

Finding: F160 (MEDIUM) — `gov/kms_vault.py` config factory hard-codes the
transport. Filed 2026-09-24 (ship-readiness KMS spike), workstream ship W1.

Note on the tracker: this repo has no configured issue tracker
(`docs/agents/issue-tracker.md` absent), so the spec is published as this
document rather than as a tracker issue.

## Problem Statement

An operator configuring the Vault KMS provider through the documented
operator surface (`kms_provider_from_config` with `provider: vault`,
credentials from `VAULT_ADDR`/`VAULT_TOKEN`) cannot reach a real
deployment:

- Any `http://` `VAULT_ADDR` dies inside transport construction with a
  bare `ValueError`. The module's documented contract is that the
  factory boundary raises `KmsError` — operator tooling catches
  `KmsError` to mean "KMS unusable, fail closed", and a `ValueError`
  escaping means the contract is broken (F160's title bug).
- There are no knobs for `allow_http` / `ca_bundle` / `timeout_s` on the
  config surface, even though the stdlib transport constructor already
  accepts them. Dev/test loopback setups and TLS-terminating deployments
  (custom CA bundle, tuned timeouts) cannot go through the config path
  at all.

## Solution

Expose the three transport knobs on the `provider: vault` config
mapping (`allow_http`, `ca_bundle`, `timeout_s`), plumb them into the
stdlib transport, and translate every operator-input-caused
construction failure at the factory boundary into `KmsError` —
preserving fail-closed behavior (plaintext HTTP stays refused by
default; invalid addresses stay refused loudly).

## User Stories

1. As an operator, I want to point `VAULT_ADDR` at a loopback Vault dev
   server (`http://127.0.0.1:8200`) for a dev/test loop and get a
   working provider by setting `allow_http: true` in config, so that I
   can exercise the real adapter without TLS ceremony.
2. As an operator, I want a plaintext `VAULT_ADDR` **without**
   `allow_http: true` to be refused at config time (not at first
   request), so that a token can never silently cross cleartext.
3. As an operator, I want the refusal of a plaintext address to raise
   the module's typed `KmsError` (not a bare `ValueError`), so that my
   startup code catches one documented exception type for "KMS
   unusable".
4. As an operator, I want to supply a `ca_bundle` path for deployments
   behind a TLS-terminating proxy or private CA, so that HTTPS verifies
   against the right trust roots.
5. As an operator, I want a missing/unreadable `ca_bundle` to fail at
   config time with `KmsError`, so that a broken trust configuration is
   loud at startup rather than at the first wrap call.
6. As an operator, I want to tune `timeout_s` per request, so that a
   slow or distant Vault does not hang startup/rotation ceremonies.
7. As an operator, I want a non-positive or non-numeric `timeout_s` to
   be rejected at config time with `KmsError`, so that a typo cannot
   silently become "wait forever" or "fail instantly".
8. As an operator, I want a non-boolean `allow_http` (e.g. the string
   `"yes"`) to be rejected at config time with `KmsError`, so that
   ambiguous truthiness can never silently permit cleartext tokens.
9. As an operator, I want an invalid `VAULT_ADDR` (bad scheme, garbage)
   to raise `KmsError` with the reason preserved, so that misconfigured
   addresses are diagnosable through the same typed error as every
   other KMS failure.
10. As an operator, I want an invalid `mount` in config to raise
    `KmsError` (not `ValueError`), so that all config-surface mistakes
    share one exception type.
11. As a test author, I want the error-type contract documented —
    `KmsError` for operator config, `ValueError`/`TypeError` for
    programmer misuse of the direct Python API — so that tests assert
    the right type at the right seam.
12. As a runbook reader, I want the key-custody runbook to describe the
    adapter as it actually exists (implemented, live-validated against
    Vault OSS), with the genuinely untested parts (cloud KMS, TLS
    end-to-end, non-token auth, HA, production hardening) marked
    honestly, so that I do not plan a production cutover on fiction.

## Implementation Decisions

- The vault-config parsing moves into the `gov.kms_vault` module as a
  new factory function; the `provider: vault` branch of the existing
  `kms_provider_from_config` in `gov.kms` delegates to it (lazy import,
  as today, to avoid the circular import). The public seam
  `kms_provider_from_config` is unchanged; the new function is the
  single factory boundary where error translation happens.
- New optional config keys for `provider: vault` (defaults preserve
  today's behavior exactly):
  - `allow_http`: strict bool, default `False`. Non-bool → `KmsError`.
  - `ca_bundle`: PEM bundle path (string), default `None` (system
    trust). Non-string/empty or nonexistent path → `KmsError` at
    factory time.
  - `timeout_s`: positive finite number, default 10 (the transport's
    existing default). Bool, non-numeric, non-positive, or
    non-finite → `KmsError`.
  - `mount`: unchanged (default `"transit"`); a bad mount now raises
    `KmsError` at the factory boundary instead of leaking
    `ValueError`.
- Error-type contract (the precise rule):
  - `KmsError` — every failure at the factory boundary caused by
    operator-controlled input: missing/blank `VAULT_ADDR`/`VAULT_TOKEN`
    (already `KmsError` today), unusable address (http without
    `allow_http`, bad scheme), invalid knob values, bad mount. Reason:
    the factory is the operator surface; `KmsError` is the typed
    fail-closed error operator code catches, and the refusal reason is
    preserved in the message.
  - `ValueError`/`TypeError` — direct Python API misuse (programmer
    error), unchanged: non-string `base_url`, bad `mount`, empty token,
    and the transport's own plaintext-HTTP refusal when constructed
    directly. Reason: at the code seam the caller is the wiring author,
    and fail-fast with the stdlib exception type is the correct
    signal; the factory translates it for operators.
- Fail-closed posture is unchanged: plaintext HTTP is refused unless
  `allow_http: true` is set explicitly; no new default weakens
  anything.
- Unknown mapping keys keep today's behavior (ignored); the token is
  still never read from the mapping (env only).
- The stdlib transport constructor itself is untouched (its kwargs and
  its `ValueError` convention for direct construction stay as they
  are).

## Testing Decisions

- Red-first: the new tests are written against the current code and
  must FAIL before the implementation lands, then pass after.
- Seam under test: the public factory `kms_provider_from_config`
  (`provider: vault` branch). Tests observe behavior only through it
  plus stdlib seams — no new seams are introduced.
- Plumbing is observed without reaching into transport internals:
  `allow_http` by construction success/failure of the factory against
  an `http://` address; `ca_bundle` by intercepting the stdlib CA
  context creation; `timeout_s` by intercepting the stdlib request
  call and reading the timeout it was given. (Repo prior art: the
  existing `FactoryTest` class in the Vault unit tests, which already
  asserts provider/transport types and env-only credentials; the live
  battery's `TransportDisciplineTests` for the direct-construction
  `ValueError` convention.)
- A good test here asserts observable factory behavior (built provider
  vs. raised typed error), not internal attribute values; the one
  exception is reusing the repo's existing convention of asserting the
  built provider's transport type.
- The existing live-test expectation that a plaintext `VAULT_ADDR`
  through the factory raises `ValueError` is the filed bug itself —
  it is updated to expect `KmsError` as part of this change.
- New battery file sets the deployment-mode gate at module level per
  repo convention (`os.environ.setdefault("GOV_DEPLOYMENT_MODE",
  "staging")` right after imports) and is verified under both a normal
  environment and `env -u GOV_DEPLOYMENT_MODE`.

## Out of Scope

- Cloud KMS adapters (AWS/GCP/Azure): still refused by design ($0
  spend, no credentials).
- TLS end-to-end validation against a real CA, non-token auth methods
  (AppRole etc.), Vault HA/production hardening — documented as
  UNTESTED in the runbook, not built here.
- Retry/backoff, connection pooling, or request logging changes in the
  transport.
- A ceremony CLI or any change to the envelope keyring protocol.
- Changing the transport's `ValueError` convention for *direct*
  construction.

## Further Notes

- The `allow_http` name matches the transport constructor's existing
  kwarg, so config keys and constructor kwargs stay 1:1.
- `timeout_s` accepts int or float (excluding bool); the value is
  passed straight through to the transport — the factory does not
  clamp or reinterpret it.
- `ca_bundle` validation is existence-at-config-time only; PEM
  well-formedness is left to the TLS handshake (fail-closed there as
  `KmsError` via the transport-error path).
