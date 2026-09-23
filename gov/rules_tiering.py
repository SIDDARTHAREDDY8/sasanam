"""Lethal-trifecta tiering as a policy primitive (wave-79).

Prior art, stated honestly: the "lethal trifecta" (private data +
untrusted content + external communication) is NIST's threat-model
framing, coined in the prompt-injection literature by Simon Willison.
Every major framework describes it as a *threat note*. What this module
adds — the invention — is making it a **policy primitive with
enforcement wiring**: a classified tool registry, a composition rule
over delegation hops evaluated on *effective* grants, and an automatic
oversight-tier escalation with a policy-independent approval floor.

Design: ``workstreams/architect/RULES_TIERING_DESIGN.md`` §1.

The three axes:
- ``private_data``: the tool can read non-public data (file reads, API
  responses, prior outputs carrying PII/secrets). Read-shaped.
- ``untrusted_content``: the tool ingests content the agent did not
  author (file bodies, fetched pages, downloaded code).
- ``external_comm``: invoking the tool moves bytes/effects outside the
  trust boundary (network sends, email, package fetches).

Labels only ever ESCALATE: no enforcement path consults a label to
permit anything, so a mislabeled tool cannot weaken the read-before-send
/ DLP / egress controls — it can only fail to raise the tier. A tool
labeled clean that behaves dirty is an incident-class probe, fixed by
reclassification through the governed path, never a silent edit.
"""

# The closed tool universe mirrors gov/policy.KNOWN_TOOLS. A tool not in
# this registry cannot execute anyway (the engine rejects unknown tools
# at load, the executor rejects unknown tools at role check), so the
# registry is total by construction. REGISTRY_VERSION is bumped on any
# reclassification; reclassifications ride the wave-75 governed
# policy-change path (see gov/precommit.py for the registry discipline).
REGISTRY_VERSION = "rules-tiering-v1"

AXES = ("private_data", "untrusted_content", "external_comm")
_TRIFECTA = frozenset(AXES)

# Operator-owned classification. The per-axis test (design §1(e)):
# could a NORMAL invocation of this tool exhibit the axis without any
# other tool's help? Notes:
# - api_call alone holds all three: params carry read content (the F1
#   class), responses carry private data, fetches ingest untrusted
#   content, and the call leaves the boundary. An agent with api_call IS
#   the NIST threat-model shape; the registry says so plainly.
# - read_file is private-data + untrusted-content but NOT external:
#   reading cannot exfiltrate by itself.
# - write_file/delete_file hold no axis: local-state mutation is an
#   integrity concern (the irreversible registry, gov/precommit.py),
#   not a trifecta axis.
TOOL_AXES = {
    "read_file": frozenset({"private_data", "untrusted_content"}),
    "write_file": frozenset(),
    "delete_file": frozenset(),
    "api_call": frozenset({"private_data", "untrusted_content",
                           "external_comm"}),
    "http_post": frozenset({"external_comm"}),
    "send_email": frozenset({"external_comm"}),
    "install_package": frozenset({"untrusted_content", "external_comm"}),
}

TIER_STANDARD = "standard"
TIER_ELEVATED = "elevated"

# Reserved sentinel appended to matched_rules when the trifecta floor
# (not a policy rule) determined the queueing. Documented in the design
# doc §1(c)/§2(a); the provenance validator accepts it as a plain
# string, which is all it claims to be.
TRIFECTA_FLOOR_SENTINEL = "trifecta-tier-floor"


class TieringError(ValueError):
    """Fail-closed: a tiering input was malformed."""


def axes_of(tool):
    """The axis set for a registered tool. Unknown tool: fail closed."""
    try:
        return TOOL_AXES[tool]
    except KeyError:
        raise TieringError("tool %r is not classified in TOOL_AXES "
                           "(closed universe; refusing)" % (tool,))


def union_axes(tools):
    """Union of axes over an iterable of tool names."""
    out = set()
    for tool in tools or ():
        out |= set(axes_of(tool))
    return frozenset(out)


def session_tier(granted_tools):
    """Oversight tier for a grant set: 'elevated' iff the axis union
    covers all three (the trifecta), else 'standard'.

    Returns ``(tier, axes_union)``. Pure function of the grant set —
    the composition rule (§1(d)) is just this function applied to the
    session's EFFECTIVE grants (role tools ∪ delegation scope ∪ lease
    scope), so a parent holding two axes whose child adds the third
    trips elevated at the child's first external call without touching
    wave-74's strict attenuation.
    """
    axes = union_axes(granted_tools)
    if _TRIFECTA <= axes:
        return TIER_ELEVATED, axes
    return TIER_STANDARD, axes


def is_trifecta(granted_tools):
    """True iff the grant set holds all three axes."""
    return _TRIFECTA <= union_axes(granted_tools)


def tool_carries_axis(tool, axis):
    """True iff the tool's classification includes the axis."""
    if axis not in AXES:
        raise TieringError("unknown axis %r (known: %s)"
                           % (axis, list(AXES)))
    return axis in axes_of(tool)


def effective_grants(role_tools=(), delegation_scope=(), lease_scope=()):
    """The session's effective grant set: the union the composition rule
    evaluates. Each source is independently governed (roles by policy,
    delegation scope by wave-74 attenuation, leases by wave-78
    verification); the tier composes over the union without weakening
    any of them."""
    grants = set()
    for source in (role_tools, delegation_scope, lease_scope):
        for tool in source or ():
            # Unknown tools fail closed here rather than being silently
            # dropped from the union (a dropped tool would UNDERSTATE
            # the tier — the dangerous direction).
            axes_of(tool)
            grants.add(tool)
    return frozenset(grants)


def floor_applies(granted_tools, tool, engine_effect):
    """Does the trifecta approval floor bite on this call?

    The floor bites iff: the session is elevated (trifecta over effective
    grants) AND the tool carries the external_comm axis AND the engine
    verdict is 'allow' (deny still denies; require_approval already
    queues — the floor only bites where the policy would otherwise allow
    silently).
    """
    if engine_effect != "allow":
        return False
    if not tool_carries_axis(tool, "external_comm"):
        return False
    return is_trifecta(granted_tools)
