"""gov.adapters: complete-mediation adapters for agent frameworks.

Every adapter routes agent tool calls through ``gov.executor.ToolExecutor``
*before* any underlying framework implementation runs. The shared contract
lives in :mod:`gov.adapters.core`; the framework shims are:

* :mod:`gov.adapters.generic`    -- decorator + context-manager registry
* :mod:`gov.adapters.langchain_tools` -- LangChain ``StructuredTool`` shim
* :mod:`gov.adapters.mcp_adapter`     -- MCP ``ClientSession`` wrapper
* :mod:`gov.adapters.openai_loop`     -- OpenAI-style function-call loop

See ``gov/adapters/README.md`` for exact public signatures, the residual
limitations that cannot be closed in-process, and the 5-line quickstart.
"""

from .core import (
    DEFAULT_TOOL_MAP,
    NATIVE_TOOLS,
    AdapterError,
    ApprovalRequiredError,
    GovernedBinding,
    MalformedToolCallError,
    ToolDeniedError,
    UnregisteredToolError,
    normalize_result,
)

__all__ = [
    "DEFAULT_TOOL_MAP",
    "NATIVE_TOOLS",
    "AdapterError",
    "ApprovalRequiredError",
    "GovernedBinding",
    "MalformedToolCallError",
    "ToolDeniedError",
    "UnregisteredToolError",
    "normalize_result",
]
