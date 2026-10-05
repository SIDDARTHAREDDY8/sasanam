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
langchain-core version and fails loudly on drift). Declared-field violations
(missing/wrongly-typed fields) are rejected by LangChain's own schema
validation before mediation. **F62:** construction fails closed unless the
schema declares `extra="allow"` — with pydantic's default `extra="ignore"`,
langchain-core would silently drop undeclared kwargs *before* `_run`,
so they never reached mediation, the DLP scan, or the approval record.
Mediation is synchronous in `_arun` (the executor is in-memory); no
thread-hopping of the audit path.

### Pre-mediation input audit (F62, R14 follow-up)

Every adapter was audited for the F62 hole — anything that filters or drops
inputs *before* the executor's DLP scan sees them:

| Adapter | Input path | Verdict |
|---|---|---|
| `langchain_tools` | langchain-core `_parse_input` coerces against `args_schema` | **Fixed:** construction (and later reassignment) of `args_schema` raises unless it declares `extra="allow"`; JSON-schema dicts are passed through unchanged by `_parse_input` and are allowed. |
| `core` (`GovernedBinding.call` / `GovernedToolFacade.call`) | `**kwargs` straight to `executor.call` | Clean: no filtering. The executor pops only documented framing kwargs (`justification`, `on_behalf_of`, `delegated_by` — agent-supplied metadata, not tool inputs); the DLP scan runs on the raw remainder. |
| `generic` (`governed` wrapper) | `**kwargs` straight to `binding.call`; positional args raise fail-closed | Clean: no schema coercion, no drop. |
| `mcp_adapter` (`call_tool`) | full `arguments` dict mediated via `binding.call(name, **dict(arguments))` | Clean: no filtering of tool arguments. `session_kwargs` (transport-level, e.g. `read_timeout_seconds`) go only to the session, never the executor — documented above, not a governance drop. |
| `openai_loop` (`run_tool_loop`) | `parse_tool_calls` strictly parses the raw JSON-object arguments; `binding.call(call.name, **call.arguments)` | Clean: malformed shapes raise `MalformedToolCallError` fail-closed; valid arguments pass through unmodified. |
| `openai_agents` (guardrail fn) | SDK passes the RAW arguments string pre-schema-preparation; shim `json.loads`es strictly (must be an object) and calls `binding.call(framework_tool, **parsed)` | Clean: no filtering — malformed input trips the wire fail-closed; every parsed kwarg reaches mediation. `expect_sdk_tool_name` catches guardrail/tool misattachment. |
| `langgraph_hitl` (`governed_tool_call`) | `arguments` must be a dict; passed as `**arguments` to `binding.call` | Clean: no schema coercion, no drop. Interrupt payload deliberately excludes raw arguments (client-channel hygiene; the human decides in the queue UI). |

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

### `gov.adapters.openai_agents` — OpenAI Agents SDK native-guardrail shim (verified: openai-agents 0.23.1)

| Name | Signature | Behavior |
|---|---|---|
| `make_tool_input_guardrail` | `(binding, framework_tool, *, on_denied="raise", on_queued="raise", name=None, expect_sdk_tool_name=None) -> callable` | Returns a guardrail function `(data) -> ToolGuardrailFunctionOutput` for the SDK's native `tool_input_guardrails` pipeline (`ToolInputGuardrail(guardrail_function=...)` or the SDK's `@tool_input_guardrail`). Unregistered `framework_tool` raises at **construction**. Executor `"executed"` → `allow` (coded `output_info`); `"denied"` → `raise_exception` tripwire (SDK raises `ToolGuardrailTripwireTriggered`, halting the run) or `reject_content` with `on_denied="return"`; `"queued"` → `raise_exception` with `output_info["approval_id"]` (human decides via OUR ApprovalQueue; the run is re-invoked) or `reject_content` with `on_queued="return"`. Malformed tool arguments (not JSON / not an object) → `raise_exception` fail-closed. `expect_sdk_tool_name` fails closed on guardrail/tool misattachment. |
| `audit_agent_coverage` | `(agent, *, nested_agent_tools=()) -> dict` | Fail-closed coverage audit (duck-typed; the `agents` package need not be installed). Raises `UncoveredSurfaceError` naming every uncovered surface: handoffs, non-`FunctionTool` tools (hosted/built-in tools never enter the SDK's guardrail pipeline), `Agent.as_tool()` nested tools (SDK's own `_is_agent_tool` marker or declared names — the guardrail sees only the outer input, never nested calls), `FunctionTool`s without a shim-issued guardrail, or `agent=None`. Returns a report dict on success. |
| `sdk_available` | `() -> bool` | True when the `agents` package is importable. |
| `RESIDUAL_SURFACES` | — | The tested honest-boundary contract: hosted tools, built-in execution tools, handoffs, `as_tool()` nested runs are NEVER covered by this shim. |

The `agents` package is optional: with it installed the shim returns the real `ToolGuardrailFunctionOutput`; otherwise a behavior-compatible stand-in (the SDK only reads `behavior["type"]`/`behavior["message"]`). No F62-class hole: the SDK hands guardrails the RAW arguments string before schema preparation, and the shim parses it strictly itself — every parsed kwarg reaches `binding.call` unmodified.

### `gov.adapters.langgraph_hitl` — LangGraph `interrupt()` → ApprovalQueue recipe (verified: langgraph 1.2.12)

| Name | Signature | Behavior |
|---|---|---|
| `governed_tool_call` | `(binding, framework_tool, arguments, *, interrupt, queue=None, prior_approval_id=None, on_denied="raise") -> (outcome, payload)` | Mediates one tool call inside a LangGraph node. `"executed"` → `("executed", result)`, `interrupt` never called. `"denied"` → `ToolDeniedError` (or `("denied", result)` with `on_denied="return"`), `interrupt` never called. `"queued"` → `interrupt(payload)` pauses the graph (raises `GraphInterrupt`); payload carries `approval_id` + tool names, never raw arguments. After the human decides via `ApprovalQueue.decide` and the client resumes (`graph.update_state(..., {"approval_id": aid})` then `Command(resume=...)`), the node re-enters with `prior_approval_id`: `binding.call` is NOT re-run (no duplicate queue entry), `interrupt()` returns the resume value, and the helper returns `("approved", record)` / `("rejected", record)` — the queue is the decision authority. The deployment then runs `executor.execute_approved()`. Resume-path failures are fail-closed: `ApprovalResumeMismatchError` (resume names another approval), `ApprovalRecordMissingError` (vanished record), `ApprovalNotDecidedError` (premature resume — a resume value can never smuggle an approval past the queue). |

`langgraph` is optional: `interrupt` is dependency-injected (`langgraph.types.interrupt` in production, a stand-in in tests); this module never imports `langgraph`.

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
