"""Tool-schema ``$ref`` poisoning guard (W246-3).

Threat model (second MCP SDK advisory GHSA-rwrf-2pqf-9j8j shape): a
tool schema whose ``$ref`` points outside the document turns schema
loading into an SSRF fetch, and adversarial ``$ref`` graphs (cycles,
deep chains, sibling ref storms) freeze the resolver's event loop.

Three fail-closed rules, all enforced by one pure function
(``check_tool_schema``): schema dict in, verdict out.

1. No out-of-document references. A ``$ref`` (likewise
   ``$recursiveRef`` / ``$dynamicRef``) whose value does not start
   with ``#`` is refused ``schema-ref-external``. The module has no
   network capability at all -- no urllib/socket/http import
   anywhere -- so "never fetched" holds by construction, and the
   battery additionally proves it at runtime by patching the
   network entry points to raise.
2. Bounded in-document resolution. Every ``#``-pointer hop
   increments the resolution depth; exceeding ``max_ref_depth``
   (or revisiting a pointer already on the current chain, i.e. a
   cycle) refuses ``schema-ref-depth-exceeded``.
3. Bounded CPU budget. Every ``$ref`` resolution consumes one step
   of ``max_resolution_steps``; exhaustion refuses
   ``schema-ref-budget-exhausted``. The budget is a pure step count
   -- no wall-clock dependence, fully deterministic in tests.

Malformed input fails closed ``schema-record-malformed``: a
non-dict schema, a non-string ``$ref`` value, a dangling
in-document pointer, or a cyclic Python container (not a valid
JSON value at all). ``$ref`` siblings are still scanned (draft
2020-12 semantics). A ``$ref`` is in-document if and only if it
starts with ``#`` -- ``""`` and bare relative paths are
out-of-document and refused, never resolved against a base URI
(the guard performs no URI resolution at all).

The guard never mutates its input and returns an allow verdict
carrying resolution statistics (``refs_resolved``,
``max_depth_seen``) so callers can distinguish "resolved cleanly"
from "vacuously allowed".

Honest residuals:
- The guard validates references, not schema semantics: a
  well-formed ``$ref`` graph can still describe a malicious tool.
  Semantic tool-schema review is a separate, deployment-owned
  layer.
- Depth and budget defaults (16 / 1000) are deployment-tunable;
  shrinking them can refuse legitimate large schemas, growing
  them weakens the freeze bound.

Stdlib only. Deterministic. No env reads, no I/O. Fail-closed on
malformed input.
"""

SCHEMA_REF_EXTERNAL = "schema-ref-external"
SCHEMA_REF_DEPTH_EXCEEDED = "schema-ref-depth-exceeded"
SCHEMA_REF_BUDGET_EXHAUSTED = "schema-ref-budget-exhausted"
SCHEMA_RECORD_MALFORMED = "schema-record-malformed"
SCHEMA_REFS_RESOLVED = "schema-refs-resolved"

_REF_KEYS = ("$ref", "$recursiveRef", "$dynamicRef")

DEFAULT_MAX_REF_DEPTH = 16
DEFAULT_MAX_RESOLUTION_STEPS = 1000


class SchemaRefGuardError(Exception):
    """Refusal from the schema-ref guard; ``code`` is the taxonomy id."""

    def __init__(self, code, message):
        super(SchemaRefGuardError, self).__init__(message)
        self.code = code


def _fail(code, message):
    raise SchemaRefGuardError(code, message)


def _resolve_pointer(document, pointer):
    """Resolve a JSON Pointer (RFC 6901) against the document root.

    ``pointer`` is the part after ``#``: "" (whole document) or
    "/a/b". Fails closed ``schema-record-malformed`` on dangling
    pointers.
    """
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        _fail(SCHEMA_RECORD_MALFORMED,
              "unsupported $ref pointer shape: %r" % (pointer,))
    node = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                _fail(SCHEMA_RECORD_MALFORMED,
                      "dangling $ref pointer: %r" % (pointer,))
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit() or int(token) >= len(node):
                _fail(SCHEMA_RECORD_MALFORMED,
                      "dangling $ref pointer: %r" % (pointer,))
            node = node[int(token)]
        else:
            _fail(SCHEMA_RECORD_MALFORMED,
                  "dangling $ref pointer: %r" % (pointer,))
    return node


def check_tool_schema(schema, *, max_ref_depth=DEFAULT_MAX_REF_DEPTH,
                      max_resolution_steps=DEFAULT_MAX_RESOLUTION_STEPS):
    """Validate a tool schema's ``$ref`` graph. Pure: no I/O, no env.

    Returns ``{"decision": "allow", "code": "schema-refs-resolved",
    "refs_resolved": int, "max_depth_seen": int}`` when every
    reference is in-document, acyclic, and within budget; raises
    ``SchemaRefGuardError`` otherwise. Never mutates ``schema``.
    """
    if not isinstance(schema, dict):
        _fail(SCHEMA_RECORD_MALFORMED,
              "tool schema must be a dict, got %s"
              % type(schema).__name__)
    for name, bound in (("max_ref_depth", max_ref_depth),
                        ("max_resolution_steps", max_resolution_steps)):
        if isinstance(bound, bool) or not isinstance(bound, int) \
                or bound < 1:
            _fail(SCHEMA_RECORD_MALFORMED,
                  "%s must be a positive int" % (name,))

    steps = 0
    refs_resolved = 0
    max_depth_seen = 0

    # Explicit stack: (node, ref_depth, chain, path_ids).
    # ref_depth/chain track $ref hops; path_ids guards the
    # structural walk against cyclic Python containers.
    stack = [(schema, 0, (), frozenset())]
    while stack:
        node, ref_depth, chain, path_ids = stack.pop()
        if isinstance(node, dict):
            if id(node) in path_ids:
                _fail(SCHEMA_RECORD_MALFORMED,
                      "cyclic container in schema (not valid JSON)")
            path_ids = path_ids | {id(node)}
            for key, value in node.items():
                if key in _REF_KEYS:
                    if not isinstance(value, str):
                        _fail(SCHEMA_RECORD_MALFORMED,
                              "%s must be a string" % (key,))
                    if not value.startswith("#"):
                        _fail(SCHEMA_REF_EXTERNAL,
                              "out-of-document %s %r is never fetched"
                              % (key, value))
                    pointer = value[1:]
                    if pointer in chain:
                        _fail(SCHEMA_REF_DEPTH_EXCEEDED,
                              "cyclic $ref chain at %r" % (value,))
                    depth = ref_depth + 1
                    if depth > max_ref_depth:
                        _fail(SCHEMA_REF_DEPTH_EXCEEDED,
                              "$ref depth %d exceeds max %d at %r"
                              % (depth, max_ref_depth, value))
                    steps += 1
                    if steps > max_resolution_steps:
                        _fail(SCHEMA_REF_BUDGET_EXHAUSTED,
                              "resolved %d refs, budget is %d"
                              % (steps, max_resolution_steps))
                    target = _resolve_pointer(schema, pointer)
                    refs_resolved += 1
                    if depth > max_depth_seen:
                        max_depth_seen = depth
                    # Fresh structural path: the target is a new
                    # subtree root; carrying the referrer's path
                    # would mislabel self-root refs as cyclic
                    # containers. Termination is still guaranteed:
                    # the structural walk from any node is finite
                    # and ref hops are bounded by chain/depth.
                    stack.append((target, depth, chain + (pointer,),
                                  frozenset()))
                elif isinstance(value, (dict, list)):
                    stack.append((value, ref_depth, chain, path_ids))
        elif isinstance(node, list):
            if id(node) in path_ids:
                _fail(SCHEMA_RECORD_MALFORMED,
                      "cyclic container in schema (not valid JSON)")
            path_ids = path_ids | {id(node)}
            for item in node:
                if isinstance(item, (dict, list)):
                    stack.append((item, ref_depth, chain, path_ids))

    return {"decision": "allow",
            "code": SCHEMA_REFS_RESOLVED,
            "refs_resolved": refs_resolved,
            "max_depth_seen": max_depth_seen}
