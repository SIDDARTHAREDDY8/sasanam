# D3 Policy Export — `gov/policy_export.py`

**Status:** built 2026-09-22 (wave-24) · **Translator version:** 1.0.0 ·
**Decision:** A14 (freeze the engine; Cedar export for portability)

YAML v2 policies translate to Cedar (stateless) or Dogwood (stateful).
`deny→forbid` is genuinely aligned (forbid-wins ≡ deny-first;
default-deny ≡ default-deny), which makes the export honest rather than
aspirational. The D2 benchmark's Dogwood target consumes
`translate_for_dogwood()` under the single-translator rule (A13) — this
module is the one place translation lives.

## Usage

```bash
# Auto: Cedar unless a stateful key forces Dogwood
python -m gov.policy_export --policy policies/my.yaml --out my.cedar

# Force a format; plain Cedar REFUSES stateful policies (exit 1, loud)
python -m gov.policy_export --policy policies/my.yaml --format cedar

# Dogwood (handles stateful keys + bridged require_approval)
python -m gov.policy_export --policy policies/my.yaml --format dogwood

# CI mode: non-empty operational sections become hard errors
python -m gov.policy_export --policy policies/my.yaml --strict

# Linter integration
python -m gov.policy_lint --export-check policies/my.yaml [--strict]
```

Every export header pins the source policy's sha256 (drift detection:
re-export and compare bytes). Output is deterministic — no timestamps.

## Mapping table

| YAML v2 | Export | Notes |
|---|---|---|
| `deny` | `forbid` | forbid-wins ≡ deny-first |
| `allow` | `permit` | default-deny ≡ default-deny |
| `roles:` allowlists | `forbid` on `principal.role` + unknown-role catch-all | executor-enforced pre-evaluation; encoded so verdicts align |
| `match.tool` | `AgentCore::Action` | single → scope; multi → `when` disjunction |
| `match.role` / `match.agent` | `principal.role ==` / `principal.agent ==` | |
| `path_contains_any` | `context.path.contains("…")` | substring, same as engine `in` |
| `path_outside_sandbox`, `domain_allowlisted`, `carries_read_content`, `source_untrusted`, `read_sensitive` | typed `context` booleans | schema: `docs/cedar-context-schema.md` |
| `when` comparisons | `context.<path> <op> <literal>` | bool/int/string literals; floats refused |
| `min_external_calls` / `min_writes` / `min_deletes` | `count_within(24h, …::request{ _ })` threshold blocks | Dogwood only |
| `min_sends` | **sum** of `send_email` + `http_post` counts ≥ K | Dogwood only; engine sums both |
| `cross_run_campaign` / `velocity_exceeded` | `formerly within 24h …::"LedgerSignal"::response{…}` | Dogwood only; requires the operator's ledger feed |
| `require_approval` | **ERROR** unless a `bridge:` binding names the D1-AWS approval action → Dogwood temporal `permit` gated on the bridge approval event **plus a forbid companion** ("deny until the bridged approval arrives") | never silently permitted; the companion preserves the engine's pass order (require_approval shadows later allows) — see F88 |
| operational sections (`rate_limit`, `egress`, `approvals.*`, `auto_approve`, `campaign_allowlist`, `log_limits`, `budgets`, `run_limits`, `velocity` config) | **not exported**; listed as EXPORT LIMITATIONS in the header (loud) | `--strict` turns them into errors |

## Fail-closed contract

- Stateful keys in plain-Cedar output → **refused** (not dropped).
- `require_approval` without a `bridge:` binding → **error** (not an
  unconditional permit, not dropped).
- Malformed `bridge:` bindings (bad action name, non-multiple-of-60 TTL,
  unknown match fields, `bridge:` on non-`require_approval`) → **error**.
- Unknown match keys / tools → **error** (inherited from engine load
  validation, double-checked at translation).
- **Never silently permit, never silently drop.**

## Honest limits — what the export does NOT cover

1. **No semantic proof.** Translation correctness is validated by verdict
   parity on a scenario corpus (tests/test_policy_export_parity.py) using
   an in-repo reference evaluator for the documented Cedar/Dogwood
   subset — not the real Dogwood interpreter. Running the export under
   real Dogwood is the D2 validation loop (future wave, A13/A14).
2. **The context schema is a deployment contract.** The operator's gateway
   mapper must populate `context.*` / `context.input.*` faithfully. The
   exporter cannot verify mapper honesty; a lying mapper defeats the
   exported policy exactly as it would defeat any Cedar deployment.
3. **Operational sections don't export.** Rate limits, budgets, run
   limits, velocity config, egress allowlist values, approvals/delegation/
   quorum/auto-approve, campaign allowlist, log limits, and top-level
   `delegation` (P10 agent→agent authority grants, wave-24) are enforced by the
   executor, queue, ledger, delegation machinery, or log — not the authorizer. They are listed
   as EXPORT LIMITATIONS in the header (loud, never silent); `--strict`
   errors. Deploying the export *without* those controls weakens the
   posture — the header says so.
4. **`require_approval` parity is behavioral, not verdict parity.** The
   engine says `require_approval`; the export says "permit iff the bridge
   approval event exists within TTL, else deny". The "else deny" is a
   `forbid` companion (F88), not just default-deny: without it, an
   unconditional `allow` permit for the same tool would fire for a request
   the engine queued for approval, silently weakening the gate. The parity
   suite asserts the conditional shape (permit-with-event, deny-without),
   including with a shadowing allow rule present — never an unconditional
   permit.
5. **Single-use is the queue's job.** Dogwood has no event-consumption
   primitive; the "one approval authorizes one execution" invariant is
   enforced by the D1 queue via `decision_id` (A12), not by the policy.
   Residual, stated plainly: within the bridge TTL, a matching approval
   event in the trajectory can authorize a *repeat* of the same request
   (same correlated `match_fields`). The queue must not emit (or must
   retract) approval events for consumed decisions; the exported policy
   cannot enforce consumption itself. Correlating `decision_id` into the
   temporal (request ↔ event) is future work once the gateway mapper
   carries it in `context.input`.
6. **Ledger-signal events need the ledger feed.** `cross_run_campaign` /
   `velocity_exceeded` blocks never fire without the operator's ledger
   emitting `LedgerSignal` events into the trajectory. For `deny` rules
   keyed on these signals, a missing feed is a fail-open direction for
   that rule.
7. **`when` float thresholds unsupported** (loud error); exotic context
   paths pass through as dynamic attributes.
8. **TTL granularity:** bridge `ttl_seconds` must be a multiple of 60
   (Dogwood `Nm`/`Nh`); anything else fails loudly rather than rounding.
   `count_within` / signal windows are fixed at 24h; custom velocity
   windows are not carried.
9. **Point-in-time artifact.** No hot-reload; drift is detected via the
   header hash pin (re-export and compare), not prevented.
10. **Principal trust is assumed.** `principal.role` must come from the
    provisioned session identity (A9); the export cannot authenticate it.
11. **Missing attribute ⇒ policy doesn't apply** (matches the engine's
    missing-path ⇒ non-match), but a mapper that *omits* attributes the
    policy conditions on silently narrows every such rule — same exposure
    as any Cedar deployment with a sloppy context provider.

## Validation

`tests/test_policy_export_parity.py`: ≥50 scenarios translating policies
and asserting the exported text's verdicts match the engine's
(allow/deny/forbid semantics), including adversarial mutation checks — a
mutant exporter that drops stateful keys, drops the `require_approval`
forbid companion (the F88 regression), drops `deny` rules, or narrows
`min_sends` must FAIL the suite. `tests/test_policy_export.py` covers the
fail-closed contract (refusals, bridge validation, hash pin, determinism).
