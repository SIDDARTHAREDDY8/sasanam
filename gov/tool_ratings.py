"""Tool reversibility / write-access / financial-impact ratings (S3/K-041).

Every tool carries a rating:

* ``reversibility``: reversible | compensatable | irreversible
* ``write_access``: none | own-sandbox | external
* ``financial_impact``: none | low | high

``DEFAULT_TOOL_RATINGS`` covers the seven core tools (the six original
plus ``install_package``, the P7 governed-install tool, which ships in
the default policy). A deployment supplies ``tool_ratings`` (``{tool: {field: value}}``) to rate NEW
tools; deployment entries override the defaults per field. A mutating
tool with NO rating at all (not in the core table, not in the
deployment dict) is forced to ``require_approval`` by the executor —
the safe default applies to new tools, never silently allowing them.

``is_destructive`` (irreversible or high financial impact) drives the
policy-lint warning for destructive-rated tools allowed without an
approval rule.
"""

REVERSIBILITY_VALUES = {"reversible", "compensatable", "irreversible"}
WRITE_ACCESS_VALUES = {"none", "own-sandbox", "external"}
FINANCIAL_IMPACT_VALUES = {"none", "low", "high"}

_FIELDS = {
    "reversibility": REVERSIBILITY_VALUES,
    "write_access": WRITE_ACCESS_VALUES,
    "financial_impact": FINANCIAL_IMPACT_VALUES,
}

DEFAULT_TOOL_RATINGS = {
    "write_file": {"reversibility": "compensatable",
                   "write_access": "own-sandbox",
                   "financial_impact": "none"},
    "delete_file": {"reversibility": "compensatable",
                    "write_access": "own-sandbox",
                    "financial_impact": "none"},
    "send_email": {"reversibility": "irreversible",
                   "write_access": "external",
                   "financial_impact": "low"},
    "http_post": {"reversibility": "irreversible",
                  "write_access": "external",
                  "financial_impact": "low"},
    # api_call is read-classified (F1); read_file is non-mutating.
    "api_call": {"reversibility": "reversible",
                 "write_access": "none",
                 "financial_impact": "none"},
    "read_file": {"reversibility": "reversible",
                  "write_access": "none",
                  "financial_impact": "none"},
    # P7 (wave-39): the governed-install tool ships in the default
    # policy, so it carries a default rating. The governed-install
    # path (allow-verified-install) keeps executing on a verified pin;
    # the S3 unrated-mutating-tool guard (executor wiring, S3-GAP-1
    # closure) still fires for genuinely new, deployment-unrated
    # tools. Installs run in the agent runtime (own-sandbox) and are
    # reversible by uninstall (compensatable); fetching costs
    # bandwidth (low financial impact).
    "install_package": {"reversibility": "compensatable",
                        "write_access": "own-sandbox",
                        "financial_impact": "low"},
}


def normalize_tool_ratings(deployment):
    """Merge deployment ratings over the core defaults (S3).

    ``deployment`` is ``{tool: {field: value}}`` or None. Unknown tool
    names are allowed (that is the graduation path for new tools);
    unknown fields or out-of-set values raise ValueError (fail closed
    at executor construction — a misrated tool must never silently
    govern). Returns a fresh dict; the defaults are never mutated.
    """
    merged = {tool: dict(rating)
              for tool, rating in DEFAULT_TOOL_RATINGS.items()}
    if deployment is None:
        return merged
    if not isinstance(deployment, dict):
        raise ValueError("tool_ratings must be a mapping of "
                         "{tool: {field: value}}, got %r" % (deployment,))
    for tool, rating in deployment.items():
        if not isinstance(tool, str) or not tool.strip():
            raise ValueError("tool_ratings: tool name must be a non-empty "
                             "string, got %r" % (tool,))
        if not isinstance(rating, dict):
            raise ValueError("tool_ratings[%r] must be a mapping of "
                             "{field: value}, got %r" % (tool, rating))
        base = dict(merged.get(tool, {}))
        for field, value in rating.items():
            allowed = _FIELDS.get(field)
            if allowed is None:
                raise ValueError(
                    "tool_ratings[%r]: unknown field %r (known: %s)"
                    % (tool, field, sorted(_FIELDS)))
            if value not in allowed:
                raise ValueError(
                    "tool_ratings[%r][%r] must be one of %s, got %r"
                    % (tool, field, sorted(allowed), value))
            base[field] = value
        # A deployment rating must be complete enough to judge: fill
        # missing fields from the core default when one exists, else
        # fail closed (a partial rating on a brand-new tool is not a
        # rating).
        missing = [f for f in _FIELDS if f not in base]
        if missing:
            raise ValueError(
                "tool_ratings[%r] is missing fields %s; supply a complete "
                "rating." % (tool, missing))
        merged[tool] = base
    return merged


def is_destructive(rating):
    """True when the rating warrants the lint warning: irreversible, or
    high financial impact. (External write access alone is covered by
    the irreversibility of the core tools; deployments that rate a
    tool external+reversible have asserted compensating controls.)"""
    if not isinstance(rating, dict):
        return False
    return (rating.get("reversibility") == "irreversible"
            or rating.get("financial_impact") == "high")
