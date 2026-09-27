# ToolExecutor Construction-Site Inventory — 2026-09-26 (wave-127 tree)

**Method:** AST parse of every `*.py` under the repo (excluding `.git`,
`__pycache__`, `.gov-venv`), counting `ToolExecutor(...)` call expressions
per call site. Not a text grep — keyword-argument classification per site.

**Headline: the "42/44 legacy sites ungoverned" residual is STALE.**
It describes the pre-wave-85 state (wave-84 text-search census: 44 files,
2 governed, 42 legacy). Wave-85's fail-closed constructor gate closed the
construction seam. Fresh census below.

## Census (119 total sites)

| Bucket | Sites | Construction class |
|---|---|---|
| `evals/` | 71 | acked / refusal-battery fixtures |
| `tests/` | 40 | acked / refusal-battery fixtures |
| `examples/` | 4 | deliberately acked (teaching scaffolds) |
| `demo/` | 3 | deliberately acked (demos) |
| `gov/` | 1 | **full-core governed** |
| `workstreams/` | 0 | — |

### By construction class (all 119)

- **81 ACKED** — `ungoverned_ack=` (or `capability_ungoverned_ack=`)
  declared; construction chains a LOUD `ungoverned_bypass` event with
  reason, missing components, deployment mode, and caller file/line.
- **20 FULL-CORE** — `policy_store=` + `delegation_context=` present
  (the governed core per wave-85). 19 in evals/tests fixtures, 1 in
  `gov/executor.py:1680` (the governed child-spawn path).
- **6 STORE-ONLY+ACK** — `policy_store=` without `delegation_context=`
  plus an ack; all in evals/tests (deliberate half-core fixtures
  asserting the "store-only is a declared bypass, not governed" pin
  from wave-85).
- **12 BARE/`**`** — 9 bare `ToolExecutor(...)` in
  `evals/w84_probes.py`, `evals/w85_probes.py`,
  `tests/test_w85_legacy_seam.py` (the refusal batteries — each asserts
  `UngovernedConstructionError` fires), plus 3 `**kw` test-helper
  `build()` methods (`test_capgate_wiring.py:155`,
  `test_w85_legacy_seam.py:116`, `test_w86_identity.py:176`) whose call
  sites `setdefault` the governed core or the ack.

**Silent (ack-less, non-battery) sites in product code: 0.**

## Product-path sites (the only ones that matter)

| Site | Class | Risk | Governing order |
|---|---|---|---|
| `gov/executor.py:1680` (child spawn) | FULL-CORE | — (already governed) | n/a |

That is the entire product-path list. There is exactly one
`ToolExecutor(...)` site in `gov/`, and it carries the full governed
core (`policy_store`, `delegation_context`, `detection_monitor`,
`recovery`, `lease_verifier`, `precommit_gate`, `trifecta_floor`,
`revocation_checker`, `lineage_tracker`, `capability_gate_binding`).

## Deliberately-acked non-product sites

- `demo/attack_scenario.py:116`, `demo/evidence_demo.py:140`,
  `demo/run_demo.py:131` — demos; ack reason documents the synthetic
  shape; staging only.
- `examples/quickstart_5line.py:86`, `examples/langchain_wrapped.py:75`,
  `examples/mcp_wrapped.py:71`, `examples/openai_loop_wrapped.py:61` —
  teaching scaffolds; each documents "a real integration installs the
  full core and runs in production." Converting them to full-core would
  be churn, not a security improvement (they are not deployed; the ack
  is chained loudly in their own run logs).

These are **pinned by design**, not silent skips. Governing them is
possible but pointless — they exist to show the 5-line shape, and the
ack text itself is the teaching point.

## Red-first verification (2026-09-26, current tree)

Three probes, all HELD:
1. **Ack-less construction refused** — `ToolExecutor(run_dir, policy,
   log, approvals)` with no `policy_store` and no ack raises
   `UngovernedConstructionError`. Wave-85 still holds.
2. **Ack chains loudly** — ack'd construction writes exactly one
   `ungoverned_bypass` event with the reason verbatim.
3. **Production refuses even valid ack** — `GOV_DEPLOYMENT_MODE=production`
   + valid `ungoverned_ack` raises `UngovernedConstructionError`.

## Other direct tool-call paths (bypass check)

- `gov/sandbox.py`, `gov/egress_launcher.py` `subprocess` calls — these
  ARE the enforcement mechanisms (sandboxed execution, governed
  launcher), not bypasses.
- `gov/supplychain.py:279` `subprocess.run` — supply-chain verification
  (git/hash commands), not agent tool dispatch.
- `gov/adapters/mcp_adapter.py`, `gov/adapters/openai_loop.py` —
  mediate every call through `GovernedBinding` first; denials raise
  before the underlying session is touched. Governed by design.
- `workstreams/` — zero tool-execution paths found.

## Conclusion

There are **no ungoverned product-path `ToolExecutor` sites to govern**.
The task's premise (top-5 governing) assumed the stale residual. The
honest action is the fresh census above + correcting the stale
"42/44" line in `docs/READINESS_GAPS.md` (done, with this file as the
evidence). No new findings filed — there is no defect, only a stale doc
line. (Note: F176/F177 were filed the same day by the parallel
adversarial-rerun lane for H22 pin-file breaks — unrelated to this
inventory.)
