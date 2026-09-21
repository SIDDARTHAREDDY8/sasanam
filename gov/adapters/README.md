# gov.adapters — complete-mediation framework adapters

Every agent tool call passes through `gov.executor.ToolExecutor` **before**
any underlying implementation runs: identity → role allowlist → DLP →
rate/volume/loop guards → fail-closed policy → tamper-evident audit log.
There is no unmediated fast path in any adapter below.

## Quickstart (~5 lines)

```python
from gov.executor import ToolExecutor  # + PolicyEngine, ActionLog, ApprovalQueue (see tests/harness.py)
from gov.adapters.core import GovernedBinding
from gov.adapters.generic import governed

binding = GovernedBinding(executor, executor.mint_identity("agent-1", "coder", "dev-org"))

@governed(binding, tool="write_file")
def save(path, content): ...

save(path="notes.txt", content="hello")   # mediated; returns the executor's result dict
```

## Modules

### `gov.adapters.core` — the shared contract

| Name | Signature | Behavior |
|---|---|---|
| `GovernedBinding` | `(executor, identity, tool_map=None)` | Pins executor + minted identity + **immutable** framework→native name mapping. `tool_map` merges over `DEFAULT_TOOL_MAP`; every target must be a native tool (`read_file`, `write_file`, `delete_file`, `api_call`, `http_post`, `send_email`) or `ValueError`. |
| `GovernedBinding.resolve` | `(framework_tool) -> str` | Native name, or `UnregisteredToolError` (fail closed, executor untouched). |
| `GovernedBinding.call` | `(framework_tool, on_denied="raise", on_queued="raise", **kwargs) -> dict` | Executor result on `"executed"`. Denied → `ToolDeniedError` (or dict with `on_denied="return"`). Queued → `ApprovalRequiredError` (or dict with `on_queued="return"`). |
| `GovernedBinding.framework_tools` | `() -> list[str]` | Sorted framework-facing names served. |
| `GovernedBinding.tool_map` | property | `MappingProxyType`; immutable after construction. No API extends it — build a new binding. |
| `normalize_result` | `(result: dict) -> str` | Deterministic JSON (sorted keys) of an executor result dict. |
| `DEFAULT_TOOL_MAP` | — | Identity mapping of the six native names. |
| `NATIVE_TOOLS` | — | `frozenset` of the six native names. |

Exceptions: `AdapterError` (base) → `UnregisteredToolError`, `ToolDeniedError`
(`.framework_tool`, `.native_tool`, `.result`), `ApprovalRequiredError`
(`.approval_id`, `.result`), `MalformedToolCallError`.

Notes:
- `framework_tool`, `on_denied`, `on_queued` are adapter control parameters;
  a tool argument with the same name cannot be routed through `binding.call`
  (Python raises `TypeError` on the duplicate keyword — loud, not silent).
  None of the six native tools have such argument names.
- `justification`, `on_behalf_of`, `delegated_by` kwargs pass through to
  `executor.call`, which treats them as agent-supplied (untrusted)
  metadata — see `gov/executor.py`.

### `gov.adapters.generic` — decorator + registry

| Name | Signature | Behavior |
|---|---|---|
| `governed` | `(binding, tool=None, *, on_denied="raise", on_queued="raise", run_body=False, name=None)` | Decorator factory. `tool` defaults to the function's `__name__`. Keyword-only calls; positional args → `AdapterError`. `functools.wraps` metadata preserved; `__wrapped__` is **deleted** so no raw handle leaks. |
| `governed_registry` | `(binding, **kwargs) -> GovernedRegistry` | Context manager. |
| `GovernedRegistry.register` | `(framework_tool=None, fn=None, **governed_kwargs)` | `register("name", fn)` or `register(fn)`. Name must resolve in the binding (**validated at registration**). Double registration → `AdapterError`. |
| `GovernedRegistry.tool` | `(framework_tool=None, **governed_kwargs)` | Decorator form of `register`. |
| `GovernedRegistry.call` | `(framework_tool, **kwargs) -> dict` | Dispatch through the binding. |
| `GovernedRegistry.resolve` / `.tools()` / `.sealed` / `.binding` | — | Introspection; sealed on context exit (registration blocked, dispatch still works). |

**Execution model.** The executor *simulates* tools and accepts no arbitrary
callable. Default (`run_body=False`): the decorated **body never runs** — the
executor's `"executed"` result is the whole outcome, keeping exactly one side
effect inside the write-ahead audit boundary. `run_body=True`: after an
`"executed"` decision the original body runs with the same kwargs and its
return value is attached as `body_result` — a deliberate **split
authorization/execution** boundary (documented in the result's
`execution_note`).

### `gov.adapters.langchain_tools` — LangChain shim (verified: langchain-core 1.6.3)

| Name | Signature | Behavior |
|---|---|---|
| `make_governed_tool` | `(binding, name, description, args_schema, framework_tool=None, on_denied="raise", on_queued="raise", **tool_kwargs) -> GovernedStructuredTool` | `framework_tool` defaults to `name`; unregistered names raise at **construction**. `func=None`, `coroutine=None`: no raw callable exists on the tool. |
| `GovernedStructuredTool` | subclass of `StructuredTool` | `_run`/`_arun` route through the binding and return `normalize_result(...)` JSON. Denied → `ToolDeniedError`; queued → `ApprovalRequiredError`. |

`invoke` → `run` → `_run` and `ainvoke` → `arun` → `_arun` all funnel into the
overridden methods (a test pins this funnel assumption against the installed
langchain-core version and fails loudly on drift). Invalid inputs are rejected
by LangChain's own schema validation before mediation. Mediation is
synchronous in `_arun` (the executor is in-memory); no thread-hopping of the
audit path.

### `gov.adapters.mcp_adapter` — MCP client wrapper

| Name | Signature | Behavior |
|---|---|---|
| `GovernedMCPClient` | `(binding, session)` | `session` needs a coroutine `call_tool`; stored name-mangled, **never exposed** (no public accessor/property; `dir()` shows no `session`). |
| `GovernedMCPClient.call_tool` | `async (name, arguments=None, **session_kwargs) -> CallToolResult` | 1. Resolve via binding (unregistered → `UnregisteredToolError`). 2. Executor mediates. 3. **Only on `"executed"`** is `session.call_tool(name, arguments, **session_kwargs)` invoked; its result is returned verbatim. Denied/queued raise **before the session is touched**. `session_kwargs` (e.g. `read_timeout_seconds`) go only to the session, never the executor. |
| `GovernedMCPClient.list_tools` | `async () -> list` | Read-only passthrough (unmediated metadata; invoke only via `call_tool`). |
| `GovernedMCPClient.framework_tools` / `.binding` | — | Introspection. |
| `DeterministicFakeSession` | `(results=None)` | Test double: coroutine `call_tool`/`list_tools`, deterministic canned results, `.calls` records every `(name, arguments)` received. No network. |

**Execution model:** split authorization/execution — the executor authorizes
and logs; the real MCP server executes. The executor's simulated result is
*not* returned; the server's `CallToolResult` is. Two honest consequences:
(1) nothing reaches the server unless the full pipeline allowed it, and every
attempt is logged; (2) on `"executed"` the executor *also* runs its own
simulation (e.g. an allowed `write_file` writes the executor's sandbox copy
in addition to the server executing) — an artifact of the executor's
simulate-only design, not a second authorization.

### `gov.adapters.openai_loop` — OpenAI-style function-call loop (no API calls)

| Name | Signature | Behavior |
|---|---|---|
| `ParsedToolCall` | `(call_id, name, arguments)` | `.id`, `.name`, `.arguments` (dict). |
| `parse_tool_calls` | `(assistant_message: dict) -> list[ParsedToolCall]` | Strict validation: `tool_calls` a list; each entry a dict with non-empty unique string `id`, `type == "function"`, `function.name` non-empty string, `function.arguments` a JSON-object string (or dict). Any violation → `MalformedToolCallError`, nothing dispatched. |
| `run_tool_loop` | `(binding, messages, respond, max_iterations=8, on_denied="raise", on_queued="raise") -> list[dict]` | Pure orchestration. `respond(transcript) -> dict` supplies the next assistant message (scripted stub in tests; a real client elsewhere). Appends `tool`-role messages `{"role": "tool", "tool_call_id", "name", "content": <JSON>}`. Input `messages` not mutated. Exceeding `max_iterations` → `AdapterError`. |

Default: the first denied/queued call raises and the loop stops (fail closed).
With `on_denied="return"` / `on_queued="return"` the notice becomes a `tool`
message so the model can react and continue.

## Residual limitations (cannot be closed in-process — by design)

1. **Split authorization/execution.** The executor simulates tools; adapters
   that run a real implementation (MCP server, `run_body=True`) execute it
   *after* the `"executed"` decision. The executor's write-ahead audit covers
   the authorization, not the foreign side effect.
2. **Deployment boundary, not code boundary.** In-process Python cannot stop
   hostile code that already holds its own reference to an unmediated object
   (raw MCP session, bare LangChain tool, undecorated function, closure cells
   via `gc`). Adapters remove every *public* path (`__wrapped__` deleted,
   session name-mangled with no accessor, `func=None`); the residual rule is
   operational: **only hand governed objects to agent code.**
3. **Tool-name mapping is explicit.** Framework tool names must be registered
   in the binding's `tool_map`; nothing is guessed. Unmapped names fail
   closed — including typos.
4. **Queued approvals need a human.** `ApprovalRequiredError` carries
   `approval_id`; the action has not executed. Do not retry in a loop while
   waiting (the executor's loop guard will deny it).

## Version notes

- langchain-core **1.6.3** (funnel `invoke→run→_run` verified; drift-pinned
  by `test_funnel_assumption_pinned`).
- MCP Python SDK **2.2.0** (`ClientSession.call_tool` signature; wrapper only
  needs a coroutine `call_tool`, so it is tolerant of SDK drift).
- Everything else is stdlib + the `gov` package itself. `$0` spend, no
  network, deterministic tests.
