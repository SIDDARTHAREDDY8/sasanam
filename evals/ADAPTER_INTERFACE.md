# Adapter interface reconciliation (TEAM ADVERSARY, 2026-09-21)

**Status: RECONCILED & CLOSED 2026-09-21 ~12:00 EDT.** `gov/adapters/`
is real and importable (`core.py`, `generic.py`, `langchain_tools.py`,
`mcp_adapter.py`, `openai_loop.py`); `gov/adapters/README.md` (10KB) now
documents the `GovernedBinding` contract. `evals/real_adapters.py` wraps
the real adapters in the provisional interface, and `evals/run_evals.py`
runs EVERY matrix cell against BOTH harnesses (`provisional` fallback
column + `real` column). Result: **288/288 GREEN, 144/144 on each
harness** — every expectation holds identically against shipped code.
No cell failed against the real adapters, so the reconciliation
produced zero new findings.

Final mapping (verified by running code, not by reading docs):

| Provisional (this harness) | Real (`gov.adapters`) | Verdict |
|---|---|---|
| `ProvisionalAdapter.call(tool, **kwargs)` returns a result dict | `GovernedBinding.call(tool, on_denied="return", on_queued="return", **kwargs)` returns the executor's dict; `raise` mode surfaces `ToolDeniedError` / `ApprovalRequiredError` carrying `.result` | **Match** — same dict shape (`status`, `reason`, `policy_id`, `seq`, `approval_id`) |
| MCP pinned `registry: {(server, name): tool}`; unregistered denied by the adapter (`adapter-registry-miss`) | Immutable `tool_map` on the binding; unknown names raise `UnregisteredToolError` before the executor is touched | **Match** — same fail-closed design; evals flatten `(server, name)` to `"server:name"` keys |
| Payload-shape refusal (`adapter-payload-shape`) | `MalformedToolCallError` (openai-loop); per-adapter shape checks (langchain schema validation, MCP arguments-dict check) | **Match** — same design, different names |
| OpenAI loop fail-fast on denial | `run_tool_loop` with `on_denied="raise"` stops at first denial (fail closed); the harness uses `"return"` mode and reads tool messages | **Match** — fail-fast is the default |
| Decorator `wrap(tool)` | `gov.adapters.generic.governed` (body never runs by default; `__wrapped__` deleted) | **Match** |
| Honest residual: complete mediation is a deployment boundary | `core.py` documents the same residual ("the adapters remove every *public* path") | **Aligned** |

Reconciliation notes (usage constraints discovered while wiring the
real column — not control defeats):

1. **langchain-core drops undeclared args.** If `args_schema` declares no
   fields, `_to_args_and_kwargs` treats the tool as "no args" and silently
   drops ALL input (verified against langchain-core 1.6.3, installed for
   the evals). The eval shim declares every native-tool kwarg. Fail-closed
   here (empty `to` → egress deny), but tool authors must declare full
   schemas — a partial schema silently narrows what mediation sees.
2. **The executor crashes on `None` kwargs** (`path=None` → `TypeError` in
   `_is_outside_sandbox`, measured). langchain-core's `_parse_input`
   injects `None` for undeclared-at-call-time optional fields, so the eval
   shim strips `None` values before mediation. Tool authors wiring
   LangChain schemas with optional fields need the same guard.
3. **The real MCP adapter returns the server's result verbatim** on
   `"executed"` (no `status` key). The eval shim reports
   `{"status": "executed", "server_result": ...}` so checkers keep working;
   the `DeterministicFakeSession.calls` record proves the session is only
   touched after mediation allows.
4. **langchain-core was missing from the environment** (the real adapter
   fails closed at import with a clear `ImportError`). Installed the
   README-pinned `langchain-core==1.6.3` via pip ($0) so the real column
   runs; re-ran `tests/run_tests.py` after install to confirm no
   regressions.

## Design principle

Every adapter is a **thin shim**: it translates a framework's tool-call
convention into one canonical entry point and performs NO authorization
itself. All mediation happens inside `gov.ToolExecutor.call`, which is the
complete-mediation point. This is what the matrix tests: if a framework
convention can reach a side effect without passing through
`executor.call`, that is a mediation bypass and a ship-blocking finding.

## The interface

```python
class ProvisionalAdapter:
    name: str                      # "decorator" | "langchain" | "mcp" | "openai-loop"

    def __init__(self, executor, identity):
        # executor: gov.executor.ToolExecutor ; identity: executor-minted AgentIdentity

    def call(self, tool, **kwargs) -> dict:
        """Canonical entry: routes straight to executor.call(identity, tool, **kwargs).
        Returns the executor's result dict (status: executed|denied|queued)."""
```

Plus one framework-idiomatic entry point each:

| Adapter | Extra entry | Semantics |
|---|---|---|
| `DecoratorAdapter` | `wrap(tool) -> fn(**kwargs)` | Returns a function the scripted agent calls like a normal tool; the wrapper forwards to `call()`. A *swapped implementation* attack replaces what runs **after** governance authorizes — the residual the matrix tests. |
| `LangChainAdapter` | `ToolShim(name, adapter).invoke(payload)` | Mimics LangChain `Tool.invoke({"args": {...}})`; payload must be a dict with an `"args"` mapping, else the shim refuses (defense against arg-smuggling via payload shape). |
| `MCPAdapter` | `call_tool(server, name, arguments)` | Mimics an MCP client. Tool names are resolved against a **pinned registry** `{(server, name): governed_tool}` supplied at construction. Unregistered names are denied by the adapter itself (ASI04: never trust a server-advertised name). Descriptions/outputs are passed through as data only — governance keys on the resolved tool name and arguments, never on descriptions. |
| `OpenAILoopAdapter` | `run_tool_calls(calls)` | Mimics an OpenAI-style function-calling loop: `calls` is a list of `{"name":..., "arguments": {...}}`. Each call is mediated independently; the loop stops at the first denial and reports it (fail-fast, no partial-blind execution). |

## What the real Mediation API must preserve (reconciliation checklist)

1. One canonical mediated entry that every framework path funnels through.
2. No framework-level caching of authorization decisions (TOCTOU).
3. MCP tool-name resolution pinned operator-side, never server-side.
4. Payload-shape validation before mediation (no arg smuggling around the
   canonical entry).
5. Denials must propagate back to the agent loop (no silent skip-and-continue).
