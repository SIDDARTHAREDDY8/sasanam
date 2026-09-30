"""MCP-surface guard: tool-definition quarantine (W243-10b, ADAPT --
pattern only, prose re-derived).

Attacker shape from Langflow CVE-2026-85025 (code execution through
publicly shared MCP project endpoints): a tool definition that carries
*executable content* -- script blobs, shell/python/js fragments, or
code-execution parameter types -- must be quarantined BEFORE any
agent run, not after the agent decides to call it.

``quarantine_tool_definition(tool_def, *, endpoint_public=True)``
inspects the definition structurally and raises
``tool-executable-content`` when executable content is found; returns
``{"verdict": "allow", "tool": name}`` otherwise. Malformed
definitions fail closed with ``tool-definition-malformed``.

Detection rules (all structural, no execution):
* A string property whose schema name is one of the executable-content
  parameter names (``script``, ``command``, ``code``, ``eval``,
  ``exec``, ``shell``, ``python``, ``payload_b64`` with a matching
  description, ...).
* A default/example/description that matches an executable-content
  pattern: import+os.system/subprocess/popen, ``curl ...|sh``,
  ``eval(``/``exec(``, ``__import__``, backtick command substitution,
  ``powershell``/``cmd.exe`` invocation strings.
* An explicit ``"x-executable": true`` marker or an inputSchema
  ``"type"`` of ``code``/``script``.

Refusal vocabulary (domain ``mcp-surface``, all fail-closed):

* ``tool-executable-content`` -- the tool definition carries
  executable content; quarantined before any agent run.
* ``tool-definition-malformed`` -- the definition is not the expected
  shape (name/inputSchema types).

Honest boundaries
-----------------
* This is a *syntactic* quarantine, not a complete shell/semantics
  engine: obfuscated or indirect executable content (encoded blobs,
  multi-hop references) can evade the patterns. The quarantine raises
  the cost of the direct attack; it does not prove a tool safe.
* A definition that passes is "no known executable content", not
  "safe to run" -- authorization still goes through
  ``gov.mcp_invocation_authz`` at call time.
* Malformed input fails closed; an empty tool set is fine (nothing to
  quarantine).

Stdlib only. Deterministic: no clock, no network.
"""

import re

TOOL_EXECUTABLE_CONTENT = "tool-executable-content"
TOOL_DEFINITION_MALFORMED = "tool-definition-malformed"

# Parameter names whose values are code by convention.
_EXEC_PARAM_NAMES = frozenset({
    "script", "command", "cmd", "code", "eval", "exec", "shell",
    "python", "javascript", "js", "bash", "sh", "powershell",
    "run_command", "execute", "system",
})

# Patterns in defaults/examples/descriptions that indicate the value
# is (or instructs) executable content.
_EXEC_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\bos\s*\.\s*system\s*\(",
    r"\bsubprocess\s*\.\s*(Popen|call|run|check_output)\s*\(",
    r"\bos\s*\.\s*popen\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"__import__\s*\(",
    r"import\s+os\b.*os\s*\.\s*system",
    r"curl\b[^|]*\|\s*(ba)?sh\b",
    r"wget\b[^|]*\|\s*(ba)?sh\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"\bpowershell\b.*-(Command|EncodedCommand)\b",
    r"\bcmd\.exe\b",
    r"child_process",
))

_EXEC_TYPES = frozenset({"code", "script", "executable"})


class McpSurfaceGuardError(Exception):
    """Fail-closed MCP-surface guard refusal. ``code`` is the
    vocabulary."""

    def __init__(self, code, detail=""):
        super(McpSurfaceGuardError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


def _malformed(detail):
    raise McpSurfaceGuardError(TOOL_DEFINITION_MALFORMED, detail)


def _quarantine(detail):
    raise McpSurfaceGuardError(TOOL_EXECUTABLE_CONTENT, detail)


def _check_tool_def(tool_def):
    if not isinstance(tool_def, dict):
        _malformed("tool definition must be a mapping")
    name = tool_def.get("name")
    if isinstance(name, bool) or not isinstance(name, str) \
            or not name.strip():
        _malformed("tool.name must be a non-empty string")
    schema = tool_def.get("inputSchema")
    if schema is not None and not isinstance(schema, dict):
        _malformed("tool.inputSchema must be a mapping when present")
    return name, schema or {}


def _scan_string(value, where):
    if not isinstance(value, str):
        return
    for pattern in _EXEC_PATTERNS:
        match = pattern.search(value)
        if match:
            _quarantine(
                "executable content at %s (pattern %r)"
                % (where, match.group(0)[:40]))


def _scan_property(prop_name, prop_schema, path):
    if not isinstance(prop_schema, dict):
        return
    lowered = prop_name.lower()
    if lowered in _EXEC_PARAM_NAMES:
        _quarantine("executable-content parameter name %r at %s"
                    % (prop_name, path))
    ptype = prop_schema.get("type")
    if isinstance(ptype, str) and ptype.lower() in _EXEC_TYPES:
        _quarantine("executable schema type %r at %s" % (ptype, path))
    for field in ("default", "example", "examples", "description"):
        value = prop_schema.get(field)
        if isinstance(value, str):
            _scan_string(value, "%s.%s" % (path, field))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                _scan_string(item, "%s.%s[%d]" % (path, field, i))
    nested = prop_schema.get("properties")
    if isinstance(nested, dict):
        for sub_name, sub_schema in nested.items():
            _scan_property(sub_name, sub_schema,
                           "%s.properties.%s" % (path, sub_name))
    items = prop_schema.get("items")
    if isinstance(items, dict):
        _scan_property(prop_name, items, "%s.items" % path)


def quarantine_tool_definition(tool_def, endpoint_public=True):
    """Quarantine a tool definition that carries executable content.

    ``endpoint_public`` records whether the definition arrived over a
    public endpoint (the Langflow-85025 shape); it is carried in the
    quarantine detail. Raises :class:`McpSurfaceGuardError` on
    executable content; returns the allow record otherwise.
    """
    name, schema = _check_tool_def(tool_def)
    if tool_def.get("x-executable") is True:
        _quarantine("explicit x-executable marker on tool %r" % name)
    _scan_string(tool_def.get("description"), "description")
    props = schema.get("properties")
    if isinstance(props, dict):
        for prop_name, prop_schema in props.items():
            _scan_property(prop_name, prop_schema,
                           "inputSchema.properties.%s" % prop_name)
    return {"verdict": "allow", "tool": name,
            "endpoint_public": bool(endpoint_public)}
