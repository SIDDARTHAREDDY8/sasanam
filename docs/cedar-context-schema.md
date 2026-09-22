# Cedar Context Schema — D3 policy export (`gov/policy_export.py`)

**Version:** 1.0.0 (translator `TRANSLATOR_VERSION`) · **Date:** 2026-09-22

This document defines the entity model and the typed `context` attributes
that `gov/policy_export.py` emits. It is a **deployment contract**: the
operator's gateway mapper must populate these attributes faithfully for
every authorization request. The exporter cannot verify mapper honesty —
that is an explicit non-goal (A14) and is listed under Honest limits in
`docs/policy-export.md`.

## Entity model

```
AgentCore::Principal            // the calling agent
  attributes:
    role  : String              // policy role, e.g. "coder", "support"
    agent : String              // agent identity, e.g. "agent-7"

AgentCore::Action               // the tool being invoked
  members: "read_file" | "write_file" | "delete_file"
         | "api_call" | "http_post" | "send_email"

AgentCore::Resource             // placeholder; our policies do not
                                // resource-scope (path scoping is via
                                // context.path, see below)
```

Policies are emitted with the scope
`(principal is AgentCore::Principal, action <constraint>, resource)`.
Role allowlists from the policy's `roles:` section become `forbid`
policies on `principal.role` (plus a catch-all forbid for roles the
policy does not define — the executor rejects those before evaluation,
so the export must deny them too).

`principal.role` is trusted framing: it must come from the provisioned
session identity (A9), not from agent self-assertion. The export cannot
authenticate the principal.

## Context attributes (stateless — Cedar)

| Attribute | Type | Populated from | Notes |
|---|---|---|---|
| `context.path` | String | tool-call `path` argument (`""` when absent) | `path_contains_any` → `context.path.contains("<sub>")` (substring, same as the engine's `in`) |
| `context.path_outside_sandbox` | Bool | sandbox path check | engine: `bool(context["path_outside_sandbox"])` |
| `context.domain_allowlisted` | Bool | `egress.domain_allowlist` membership of the request destination | the allowlist *values* are mapper config and are NOT exported |
| `context.carries_read_content` | Bool | taint tracker | |
| `context.source_untrusted` | Bool | taint tracker | |
| `context.read_sensitive` | Bool | DLP scan of previously read content | |
| `context.high_entropy_payload` | Bool | api_call params scan (`dlp.has_high_entropy_token`) | F99: unknown-format framed secret, keyword-free; queue effect only |
| `context.package_fetch` | Bool | package-install fetch classification (`supplychain_install`) | P7/wave-27: raw package fetch on the agent runtime → denied unless verified install |
| `context.install_allowlisted` | Bool | `supplychain_install.check_install` (host allowlisted, name+version pinned) | P7/wave-27: agent-runtime install gating; F75 closure evidence |
| `context.install_integrity_verified` | Bool | `supplychain_install.check_install` (sha256 pin matches canonical artifact bytes) | P7/wave-27: synthetic artifact in-repo; real deployments must hash real bytes |
| `context.counters` | Record of Long | per-run action counters | keys: `read_file`, `write_file`, `delete_file`, `api_call`, `http_post`, `send_email`; used only by `when` comparisons, e.g. `context.counters.send_email >= 3` |
| `context.input.*` | (see below) | the current request, for temporal correlation | |

`when: [{path, gte|lte|gt|lt|eq|neq}]` conditions become
`context.<path> <op> <literal>` with literals limited to bool / integer /
string (floats are refused loudly). A missing attribute makes the policy
not apply — which matches the engine (`_check_conditions` returns False
when the path is missing).

`context.input` carries the fields a `bridge:` binding correlates between
the approval event and the request:

| Field | Type | Meaning |
|---|---|---|
| `context.input.path` | String | request `path` argument |
| `context.input.domain` | String | request destination domain |
| `context.input.role` | String | request principal role |
| `context.input.agent` | String | request principal agent id |

Only fields listed in the rule's `bridge.match_fields` are correlated
(allowed values: `path`, `domain`, `role`, `agent`).

## Dogwood temporal events (stateful — Dogwood only)

Stateful match keys become `when temporal { … }` blocks over the session
trajectory. Durations use Dogwood's published `Nm`/`Nh` syntax; windows
are capped at 24h (Dogwood's documented cap).

### Counters (`min_*`)

`min_external_calls: K` →
```cedar
when temporal {
    exists (n: Long). ((count_within(24h, AgentCore::Action::"api_call"::request{ _ })) == n && n >= K)
};
```
`min_writes` / `min_deletes` are the same shape over `"write_file"` /
`"delete_file"`. `min_sends: K` counts `send_email` **plus** `http_post`
(the engine sums both):
```cedar
when temporal {
    exists (n1: Long). exists (n2: Long). (
        (count_within(24h, AgentCore::Action::"send_email"::request{ _ })) == n1 &&
        (count_within(24h, AgentCore::Action::"http_post"::request{ _ })) == n2 &&
        n1 + n2 >= K)
};
```
The 24h window covers any run: trajectory events are per-session, exactly
like the engine's per-run counters. The operator's mapper must feed every
tool request into the trajectory as a `::request` event.

### Ledger signals (`cross_run_campaign`, `velocity_exceeded`)

These are booleans computed by our cross-run egress ledger — Dogwood
cannot derive the heuristic from the trajectory. The export conditions on
a **ledger-signal event** the operator's ledger must emit into the
trajectory:

```
AgentCore::Action::"LedgerSignal"::response{
    output.signal: "cross_run_campaign" | "velocity_exceeded",
    output.value: true
}
```

`cross_run_campaign: true` →
```cedar
when temporal {
    formerly within 24h AgentCore::Action::"LedgerSignal"::response{
        output.signal: "cross_run_campaign", output.value: true
    }
};
```
(`false` values negate the block.) **Deployment warning:** if the ledger
feed is absent, these blocks never fire. For `deny` rules keyed on ledger
signals that is a fail-open direction for that rule — deploying the
export without the ledger feed weakens the policy. This is listed as an
honest limit in `docs/policy-export.md`.

## Bridge binding (`require_approval` → Dogwood temporal permit)

A rule with `effect: require_approval` is unmappable to Cedar and is
refused **unless** it carries:

```yaml
bridge:
  approval_action: "ApproveWrite"  # REQUIRED: the customer-named D1-AWS
                                   # approval action (A12 emit_approval_event
                                   # approval_action)
  ttl_seconds: 600                 # REQUIRED: positive int; the approval
                                   # event must be `formerly` within this
                                   # window (multiple of 60 -> Nm/Nh)
  match_fields: [path]             # optional: subset of path|domain|role|agent
  gateway: "https://..."           # optional: operator config, traceability only
```

emitted as:

```cedar
permit (
    principal is AgentCore::Principal,
    action == AgentCore::Action::"write_file",
    resource
)
when {
    context.path_outside_sandbox == true
}
when temporal {
    formerly within 10m AgentCore::Action::"ApproveWrite"::response{
        output.approved: true,
        input.path: context.input.path
    }
};
```

The temporal clause mirrors A12's producer contract: the D1-AWS bridge
calls `emit_approval_event(gateway, approval_action, session_id,
principal, match_fields, decision_id)` through the customer's Gateway;
the approval event is a trajectory `::response` carrying
`output.approved: true`, correlated to the request by `match_fields` in
the same session. Signature status: the `emit_approval_event` signature
is defined by A12 (`workstreams/architect/ADJUDICATIONS.md`); the
producer implementation (`gov/bridges/aws.py`) is sequenced for a later
wave — wave-24 landed the bridge core (`gov/bridges/core.py`,
`gov/bridges/agt.py`) and the queue surface (`queue_external` /
`wait_for_decision` / `get_record`). The export targets the defined
signature, not an implementation that does not exist yet.
Single-use (one approval authorizes one execution) is enforced by the D1
queue via `decision_id` — Dogwood has no event-consumption primitive, so
the policy cannot express it. Without the event the permit does not fire
and the request hits default-deny — the safe direction.

**Forbid companion (F88).** Every bridged `require_approval` rule also
emits a `forbid` that fires exactly when the rule's match conditions hold
**and** no matching bridge approval event is present:

```cedar
forbid (
    principal is AgentCore::Principal,
    action == AgentCore::Action::"write_file",
    resource
)
when {
    context.path_outside_sandbox == true
}
when temporal {
    !(formerly within 10m AgentCore::Action::"ApproveWrite"::response{
        output.approved: true,
        input.path: context.input.path
    })
};
```

Why: the engine evaluates `require_approval` rules *before* `allow`
rules, so a `require_approval` match shadows any later `allow`. Cedar
has no pass order — without the companion, an unconditional `allow`
permit for the same tool would fire for a request the engine queued for
human approval, silently weakening the policy (found as F88 during D3
validation, fixed in wave-24). Forbid-wins restores the shadowing.

## Duration rules

- Bridge `ttl_seconds`: positive int, multiple of 60 → `<m>m`, multiple of
  3600 → `<h>h`. Anything else fails loudly (no silent rounding of the
  approval window).
- `count_within` / ledger-signal windows: fixed `24h`.
