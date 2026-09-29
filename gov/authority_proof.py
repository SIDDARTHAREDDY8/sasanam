"""AuthorityProof-style authority-boundary contract (OpenShell steal #1).

Reimplements the *contract* from NVIDIA OpenShell's prover
(``crates/openshell-prover/``, Apache-2.0; no code reused, no Z3 --
this checker is deterministic stdlib-only): an explicit proof-result
enum with coverage domains and a counterexample, where
unknown/unsupported/inconclusive fail closed instead of silently
allowing.

Scope is what THIS policy engine actually models:

  * ``filesystem`` -- read/write paths. The checker consumes the same
    check-time resolved target the containment verdict binds
    (``ctx["path_resolved"]``, F146/F147), absolutized against
    ``ctx["sandbox_root"]`` when the engine reports it
    sandbox-relative; it never touches the filesystem itself.
  * ``egress``     -- outbound hosts from ``url``/``endpoint`` (http_post,
    api_call) and the ``to`` domain (send_email). Hostnames are matched
    exactly; they are NEVER resolved (same honest narrowing as
    OpenShell: "hostnames are not resolved").
  * ``process_identity`` -- NOT modeled by this engine (real sandboxing
    is a documented honest v1 boundary). The domain exists in every
    proof's ``uncovered_domains`` so the gap is legible, never silent.
  * ``mcp_tools`` -- MCP server tool calls declared as
    ``{"tool": "mcp_call", "args": {"server": <id>, "name": <tool>,
    "arguments": {...}}}`` (the MCP tools/call wire shape, plus the
    server identity). The checker verifies the server identity and the
    exact ``server::tool`` pair against the operator allowlists, and
    the canonical-JSON byte size of ``arguments`` against the declared
    budget. Exact pair matching (never prefixes) is what defeats
    cross-server tool-name confusion.
  * ``graphql`` -- GraphQL operations declared as
    ``{"tool": "graphql", "args": {"endpoint": <url>, "query": <doc>}}``.
    The checker statically parses the single operation document
    (stdlib-only): operation type, maximum field-selection depth with
    same-document fragments inlined, mutation root-field names against
    the allowlist, and introspection fields (``__*``). The endpoint
    host is covered by the ``egress`` domain as usual.

Verdicts
  ``within_boundary``  every declared access in the covered domains is
                       inside the operator-declared boundary.
  ``exceeds_boundary`` a declared access falls outside the boundary;
                       ``counterexample`` names the exact access, the
                       nearest boundary rule, and why it fails.
  ``unsupported``      the action's shape cannot be modeled (a ``..``
                       escape, a non-absolute path with no sandbox root
                       to resolve it against, an unparseable URL, a
                       wildcard/empty host). Fail-closed: never
                       silently normalized into an allowed verdict.
  ``inconclusive``     the checker cannot decide: no operator boundary
                       was declared at all, or the access budget
                       (``max_accesses``) was exceeded. With a declared
                       boundary this also fails closed at the seam.

What this module does NOT do (blunt residuals, same discipline as the
prospectus):

  * It does not prove the boundary is CORRECT. A permissive boundary
    yields ``within_boundary`` for actions the operator never intended.
    The boundary is operator-written authority, not a task-minimality
    proof ("enough and no more" is marketing; containment is not
    minimality).
  * It does not prove task-minimal authority -- only containment within
    the declared boundary.
  * It does not prove runtime enforcement. The proof is computed over
    the declared/resolved action at the decision seam; a compromised
    executor, an unmediated path to the actuator, or a TOCTOU between
    the check and the side effect can invalidate it. The approved
    sweep re-checks (same fail-closed direction) to narrow the
    approval-to-execution window, not to close it.
  * It does not cover process identity, non-declared tool shapes, or
    any tool whose accesses are not declared in its args. The
    ``mcp_tools``/``graphql`` domains only model the declared
    ``mcp_call``/``graphql`` shapes above.
  * The GraphQL analysis is static document analysis, not a full
    GraphQL engine: same-document fragments are inlined (cycles fail
    closed), but the checker cannot see runtime schema changes, and a
    malicious MCP server that lies about its tool schema defeats the
    proof -- server attestation is out of scope. Persisted-query
    allowlists are the operator's job to write correctly.

Enforcing vs advisory (explicit decision, not ambiguous):

  The checker itself is a pure function -- it never allows or denies.
  At the executor seams (``ToolExecutor.call`` pre-decision path and
  the approved sweep):

  * boundary DECLARED  -> enforcing. ``exceeds_boundary``,
    ``unsupported`` and ``inconclusive`` refuse FAIL-CLOSED (loud
    audit) before any side effect. ``within_boundary`` lets the normal
    policy verdict stand -- it never upgrades a deny.
  * boundary None       -> advisory. The proof (verdict
    ``inconclusive``, all domains uncovered) is attached to the
    decision record and the policy verdict stands. Rationale:
    inventing refusals for a boundary the operator never wrote would
    be the governor denying its own deployment's legitimate work --
    an availability break with zero security gain, since the
    operator's boundary IS the authority being checked. The uncovered
    domains stay legible in the audit trail so the gap is visible to
    discovery/evidence instead of silent.

Determinism: sorted tuples, ``posixpath`` normalization only, no I/O,
no clock, no randomness, no environment reads. ``check()`` never
raises on hostile input -- malformed shapes become ``unsupported``.
Operator-boundary *configuration* errors raise ``BoundaryError`` at
load time instead (fail loud for the operator, never silent for the
auditor).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit
import json
import posixpath
import re

try:
    from . import mcp_annotations as _mcp_annotations
except ImportError:  # standalone/offline: mcp_annotations.py beside this file
    import mcp_annotations as _mcp_annotations

# The four proof verdicts. Only ``within_boundary`` is a passing
# result; every other verdict fails closed at an enforcing seam.
WITHIN = "within_boundary"
EXCEEDS = "exceeds_boundary"
UNSUPPORTED = "unsupported"
INCONCLUSIVE = "inconclusive"
VERDICTS = (WITHIN, EXCEEDS, UNSUPPORTED, INCONCLUSIVE)

# Domains the checker actually evaluates.
COVERED_DOMAINS = ("filesystem", "egress", "mcp_tools", "graphql")
# Domains named in every proof. process_identity is carried as an
# explicit uncovered domain: the engine does not model it, and the
# contract refuses to pretend otherwise. A proof for a tool in
# _REQUIRED_ACCESS_DOMAINS may additionally name "filesystem" or
# "egress" uncovered (in-toto REQUIRE semantics): the tool has real
# effects in that domain which the declared shape did not attest, so
# the proof says exactly what it examined instead of passing
# vacuously.
ALL_DOMAINS = ("filesystem", "egress", "mcp_tools", "graphql",
               "process_identity")

# Tool -> (domain, access-kind) mapping over what the engine models.
_WRITE_TOOLS = ("write_file", "delete_file")
_READ_TOOLS = ("read_file",)
_URL_EGRESS_TOOLS = ("http_post", "api_call", "graphql")
_MAIL_EGRESS_TOOLS = ("send_email",)
# Declared structured-tool shapes (wave-177): the engine has no native
# MCP/GraphQL tools, so these domains model the declared action shapes
# documented in the module docstring.
_MCP_TOOLS = ("mcp_call",)
_GRAPHQL_TOOLS = ("graphql",)

# install_package: the governed install path. It fetches the artifact
# from a package registry (egress), writes files, and installs
# executable code -- real effects in the filesystem and egress
# domains that the per-shape derivations above do not model (its
# declared args carry name/version, not a URL or path).
_INSTALL_TOOL = "install_package"

# in-toto REQUIRE semantics (pattern-steal, Apache-2.0 -- in-toto's
# artifact rules: REQUIRE/MATCH fail closed on absent materials, with
# DISALLOW * as the recommended final rule). Tools with REAL effects
# in a domain that the checker models only conditionally: a proof for
# one of these tools MUST NOT claim the domain covered while deriving
# zero accesses there. check() names such a domain uncovered -- the
# evidence product says exactly what was examined -- instead of
# passing vacuously; materials that cannot be attested at all become
# unsupported (fail closed), never a silent pass. Today only
# install_package needs this: every other engine tool either derives
# its domain accesses from its declared shape (read/write/http/...)
# or genuinely has no effects in the covered domains (window_close,
# goal_specificity_review), for which an empty derivation is honest.
_REQUIRED_ACCESS_DOMAINS = {
    _INSTALL_TOOL: ("egress", "filesystem"),
}

# Default bound on declared accesses per check: evaluation is linear,
# the cap exists so a hostile action dict cannot turn the seam into a
# hang. Exceeding it is ``inconclusive`` (fail-closed when enforcing).
DEFAULT_MAX_ACCESSES = 4096


class BoundaryError(ValueError):
    """Raised when an operator-declared boundary is malformed.

    Configuration errors fail loud at load time: a boundary with a
    relative prefix or a wildcard host must never silently degrade
    into a permissive check.
    """


@dataclass(frozen=True)
class AuthorityBoundary:
    """Operator-declared authority boundary (immutable, validated).

    ``fs_read_prefixes`` / ``fs_write_prefixes`` are absolute,
    normalized POSIX path prefixes. ``egress_hosts`` are exact host
    names (lowercased, IDNA-normalized at load). ``mcp_servers`` are
    exact MCP server identities; ``mcp_tools`` are exact
    ``server::tool`` pairs (both sides must name a listed server, and
    neither side may contain the ``::`` separator itself).
    ``mcp_max_arg_bytes`` bounds the canonical-JSON byte size of a
    call's ``arguments`` object. ``graphql_max_depth`` bounds field
    selection depth; ``graphql_allow_mutations`` gates mutations at
    all; ``graphql_mutation_allowlist`` names the permitted mutation
    root fields; ``graphql_allow_introspection`` gates ``__*`` fields.
    There is deliberately no process-identity field: the engine cannot
    verify it, so the schema refuses to accept a declaration it cannot
    check.
    """

    boundary_id: str
    version: str
    fs_read_prefixes: Tuple[str, ...] = ()
    fs_write_prefixes: Tuple[str, ...] = ()
    egress_hosts: Tuple[str, ...] = ()
    mcp_servers: Tuple[str, ...] = ()
    mcp_tools: Tuple[str, ...] = ()
    mcp_max_arg_bytes: int = 0
    graphql_max_depth: int = 0
    graphql_allow_mutations: bool = False
    graphql_mutation_allowlist: Tuple[str, ...] = ()
    graphql_allow_introspection: bool = False


def _normalize_prefix(raw: Any, field: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise BoundaryError(
            "%s entries must be non-empty strings, got %r" % (field, raw))
    if "\x00" in raw:
        raise BoundaryError("%s entry %r contains NUL" % (field, raw))
    if not raw.startswith("/"):
        raise BoundaryError(
            "%s entry %r is not absolute -- boundaries are declared "
            "as absolute path prefixes" % (field, raw))
    if ".." in raw.split("/"):
        raise BoundaryError(
            "%s entry %r contains '..' -- write normalized prefixes"
            % (field, raw))
    norm = posixpath.normpath(raw)
    if norm != raw:
        raise BoundaryError(
            "%s entry %r is not normalized (normpath gives %r) -- "
            "write normalized prefixes" % (field, raw, norm))
    return norm


def _normalize_host(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        raise BoundaryError(
            "egress_hosts entries must be non-empty strings, got %r"
            % (raw,))
    host = raw.strip().lower()
    for bad, why in (("://", "contains a scheme"), ("*", "is a wildcard"),
                     ("@", "contains userinfo"), (":", "contains a port"),
                     ("/", "contains a path"), (" ", "contains whitespace")):
        if bad in host:
            raise BoundaryError(
                "egress_hosts entry %r %s -- declare exact host names only"
                % (raw, why))
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        raise BoundaryError(
            "egress_hosts entry %r is not IDNA-encodable" % (raw,))
    if not host or "." not in host and host != "localhost":
        # Single-label names are allowed only for localhost; anything
        # else is likely a typo for a dotted name. Fail loud.
        if host != "localhost":
            raise BoundaryError(
                "egress_hosts entry %r is not a dotted host name"
                % (raw,))
    return host


def _normalize_server_id(raw: Any, field: str) -> str:
    """Validate an MCP server identity or tool name (exact match)."""
    if not isinstance(raw, str) or not raw:
        raise BoundaryError(
            "%s entries must be non-empty strings, got %r" % (field, raw))
    if "\x00" in raw:
        raise BoundaryError("%s entry %r contains NUL" % (field, raw))
    if any(c.isspace() for c in raw):
        raise BoundaryError(
            "%s entry %r contains whitespace" % (field, raw))
    if "*" in raw:
        raise BoundaryError(
            "%s entry %r is a wildcard -- declare exact identities only"
            % (field, raw))
    if "::" in raw:
        raise BoundaryError(
            "%s entry %r contains '::' -- that is the pair separator; "
            "an id containing it would let one pair masquerade as "
            "another" % (field, raw))
    return raw


def _normalize_mcp_pair(raw: Any, servers: Tuple[str, ...]) -> str:
    """Validate an exact ``server::tool`` allowlist pair."""
    if not isinstance(raw, str) or not raw:
        raise BoundaryError(
            "mcp_tools entries must be non-empty strings, got %r" % (raw,))
    parts = raw.split("::")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise BoundaryError(
            "mcp_tools entry %r must be exactly 'server::tool'" % (raw,))
    server = _normalize_server_id(parts[0], "mcp_tools server part")
    _normalize_server_id(parts[1], "mcp_tools tool part")
    if server not in servers:
        raise BoundaryError(
            "mcp_tools entry %r names server %r which is not in "
            "mcp_servers -- list the server first" % (raw, server))
    return server + "::" + parts[1]


def _normalize_nonneg_int(raw: Any, field: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise BoundaryError(
            "%s must be an integer, got %r" % (field, raw))
    if raw < 0:
        raise BoundaryError(
            "%s must be non-negative, got %r" % (field, raw))
    return raw


def _normalize_bool(raw: Any, field: str) -> bool:
    if not isinstance(raw, bool):
        raise BoundaryError(
            "%s must be a boolean, got %r" % (field, raw))
    return raw


_GQL_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*\Z")


def _normalize_gql_name(raw: Any, field: str) -> str:
    if not isinstance(raw, str) or not _GQL_NAME_RE.match(raw):
        raise BoundaryError(
            "%s entries must be GraphQL names, got %r" % (field, raw))
    return raw


def boundary_from_dict(d: Mapping[str, Any]) -> AuthorityBoundary:
    """Build a validated AuthorityBoundary from an operator dict.

    Unknown keys are rejected (a typo'd key must not silently drop a
    constraint). Raises BoundaryError on any malformation.
    """
    if not isinstance(d, Mapping):
        raise BoundaryError(
            "boundary must be a mapping, got %r" % type(d).__name__)
    known = {"boundary_id", "version", "fs_read_prefixes",
             "fs_write_prefixes", "egress_hosts",
             "mcp_servers", "mcp_tools", "mcp_max_arg_bytes",
             "graphql_max_depth", "graphql_allow_mutations",
             "graphql_mutation_allowlist", "graphql_allow_introspection"}
    unknown = set(d) - known
    if unknown:
        raise BoundaryError(
            "unknown boundary keys %s -- fix the typo, do not ignore it"
            % sorted(unknown))
    bid = d.get("boundary_id")
    ver = d.get("version")
    if not isinstance(bid, str) or not bid:
        raise BoundaryError("boundary_id must be a non-empty string")
    if not isinstance(ver, str) or not ver:
        raise BoundaryError("version must be a non-empty string")

    def _prefixes(key):
        vals = d.get(key, ())
        if not isinstance(vals, (tuple, list)):
            raise BoundaryError("%s must be a list, got %r" % (key, vals))
        return tuple(sorted(_normalize_prefix(v, key) for v in vals))

    def _ids(key):
        vals = d.get(key, ())
        if not isinstance(vals, (tuple, list)):
            raise BoundaryError("%s must be a list, got %r" % (key, vals))
        return tuple(sorted(_normalize_server_id(v, key) for v in vals))

    hosts = d.get("egress_hosts", ())
    if not isinstance(hosts, (tuple, list)):
        raise BoundaryError("egress_hosts must be a list, got %r" % (hosts,))
    servers = _ids("mcp_servers")
    pairs = d.get("mcp_tools", ())
    if not isinstance(pairs, (tuple, list)):
        raise BoundaryError("mcp_tools must be a list, got %r" % (pairs,))
    muts = d.get("graphql_mutation_allowlist", ())
    if not isinstance(muts, (tuple, list)):
        raise BoundaryError(
            "graphql_mutation_allowlist must be a list, got %r" % (muts,))
    return AuthorityBoundary(
        boundary_id=bid,
        version=ver,
        fs_read_prefixes=_prefixes("fs_read_prefixes"),
        fs_write_prefixes=_prefixes("fs_write_prefixes"),
        egress_hosts=tuple(sorted(_normalize_host(h) for h in hosts)),
        mcp_servers=servers,
        mcp_tools=tuple(sorted(_normalize_mcp_pair(p, servers)
                               for p in pairs)),
        mcp_max_arg_bytes=_normalize_nonneg_int(
            d.get("mcp_max_arg_bytes", 0), "mcp_max_arg_bytes"),
        graphql_max_depth=_normalize_nonneg_int(
            d.get("graphql_max_depth", 0), "graphql_max_depth"),
        graphql_allow_mutations=_normalize_bool(
            d.get("graphql_allow_mutations", False),
            "graphql_allow_mutations"),
        graphql_mutation_allowlist=tuple(
            sorted(_normalize_gql_name(m, "graphql_mutation_allowlist")
                   for m in muts)),
        graphql_allow_introspection=_normalize_bool(
            d.get("graphql_allow_introspection", False),
            "graphql_allow_introspection"),
    )


@dataclass(frozen=True)
class Counterexample:
    """A concrete witness for an exceeds/unsupported verdict.

    ``domain`` is the modeled domain, ``access`` the exact declared
    access that failed, ``nearest_rule`` the boundary entry with the
    longest shared prefix that still does not cover it (None when no
    entry is even close, or when the shape was unmodelable), and
    ``reason`` a human-readable why.
    """

    domain: str
    access: str
    nearest_rule: Optional[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain, "access": self.access,
                "nearest_rule": self.nearest_rule, "reason": self.reason}


@dataclass(frozen=True)
class AuthorityProof:
    """The proof record for one authority-boundary check.

    ``verdict`` is one of the four VERDICTS. ``covered_domains`` names
    the domains the checker actually evaluated;
    ``uncovered_domains`` names the rest (process_identity is always
    here today). ``resolution_source`` says which path signal the
    filesystem accesses were derived from (``path_resolved``,
    ``declared_path``, or ``none``).
    """

    verdict: str
    covered_domains: Tuple[str, ...]
    uncovered_domains: Tuple[str, ...]
    counterexample: Optional[Counterexample]
    boundary_id: Optional[str]
    boundary_version: Optional[str]
    resolution_source: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "covered_domains": list(self.covered_domains),
            "uncovered_domains": list(self.uncovered_domains),
            "counterexample": (self.counterexample.to_dict()
                               if self.counterexample else None),
            "boundary_id": self.boundary_id,
            "boundary_version": self.boundary_version,
            "resolution_source": self.resolution_source,
            "detail": self.detail,
        }


def _nearest_rule(access: str, rules: Tuple[str, ...]) -> Optional[str]:
    """Longest-shared-prefix boundary entry (or None)."""
    best = None
    best_len = -1
    for rule in rules:
        n = len(posixpath.commonprefix([access, rule]))
        if n > best_len:
            best, best_len = rule, n
    return best


def _covered_by_prefix(access: str,
                       rules: Tuple[str, ...]) -> bool:
    return any(access == r or access.startswith(r + "/") for r in rules)


def _resolve_fs_target(args: Mapping[str, Any], ctx: Mapping[str, Any]):
    """Resolve the filesystem target path for a path-shaped tool.

    Returns (norm, unsupported, resolution_source, had_signal):
    ``norm`` is the normalized absolute path (or None); ``unsupported``
    are (raw, reason) pairs; ``resolution_source`` is "path_resolved",
    "declared_path", or "none"; ``had_signal`` is True when any path
    signal was present at all. Prefers ``ctx["path_resolved"]`` -- the
    check-time resolved target the containment verdict binds --
    absolutized against ``ctx["sandbox_root"]`` when the engine
    reports it sandbox-relative; falls back to the declared
    ``args["path"]``.
    """
    declared = args.get("path")
    resolved = ctx.get("path_resolved")
    raw = resolved if isinstance(resolved, str) and resolved else None
    resolution_source = "none"
    had_signal = False
    if raw is not None:
        resolution_source = "path_resolved"
        had_signal = True
    elif isinstance(declared, str) and declared:
        raw = declared
        resolution_source = "declared_path"
        had_signal = True
    if raw is None:
        return None, [], "none", False
    if "\x00" in raw:
        return None, [(raw, "path contains NUL")], resolution_source, True
    if ".." in raw.replace("\\", "/").split("/"):
        # Never silently normalize an escape: without filesystem
        # state the checker cannot attest what ".." resolves through
        # (symlinks), so the shape is unmodelable -> unsupported.
        return None, [(raw, "path contains '..' escape: the resolved "
                             "target cannot be attested without filesystem "
                             "state")], resolution_source, True
    norm = posixpath.normpath(raw.replace("\\", "/"))
    if not norm.startswith("/"):
        root = ctx.get("sandbox_root")
        if isinstance(root, str) and root.startswith("/"):
            norm = posixpath.normpath(
                root.rstrip("/") + "/" + norm.lstrip("/"))
            if ".." in norm.split("/"):
                return None, [(
                    raw, "sandbox-relative path escapes the sandbox root")
                ], resolution_source, True
        else:
            return None, [(
                raw, "non-absolute path with no sandbox_root to resolve "
                     "it against")], resolution_source, True
    return norm, [], resolution_source, True


def _derive_fs_accesses(tool: str, args: Mapping[str, Any],
                        ctx: Mapping[str, Any]):
    """Derive (kind, access) filesystem accesses and unmodelable shapes.

    Returns (accesses, unsupported, resolution_source) where accesses
    are (kind, normalized-absolute-path) with kind in {"read",
    "write"} and unsupported are (raw, reason) pairs. Prefers
    ``ctx["path_resolved"]`` -- the check-time resolved target the
    containment verdict binds -- absolutized against
    ``ctx["sandbox_root"]`` when the engine reports it
    sandbox-relative; falls back to the declared ``args["path"]``.
    """
    accesses = []
    unsupported = []
    resolution_source = "none"
    kinds = []
    if tool in _WRITE_TOOLS:
        kinds.append("write")
    if tool in _READ_TOOLS:
        kinds.append("read")
    if not kinds:
        return accesses, unsupported, resolution_source
    norm, target_unsupported, resolution_source, had_signal = (
        _resolve_fs_target(args, ctx))
    unsupported.extend(target_unsupported)
    if not had_signal:
        unsupported.append((repr(args.get("path")),
                            "no usable path signal for a path tool"))
    if norm is None:
        return accesses, unsupported, resolution_source
    for kind in kinds:
        accesses.append((kind, norm))
    return accesses, unsupported, resolution_source


def _derive_egress_accesses(tool: str, args: Mapping[str, Any]):
    """Derive egress host accesses and unmodelable shapes.

    Returns (hosts, unsupported): hosts are normalized exact host
    names; unsupported are (raw, reason) pairs.
    """
    hosts = []
    unsupported = []
    raws = []
    if tool in _URL_EGRESS_TOOLS:
        for key in ("url", "endpoint"):
            val = args.get(key)
            if isinstance(val, str) and val:
                raws.append(("url", val))
    if tool in _MAIL_EGRESS_TOOLS:
        val = args.get("to")
        if isinstance(val, str) and val:
            raws.append(("to", val))
    for kind, raw in raws:
        if "\x00" in raw or any(c.isspace() for c in raw):
            unsupported.append((raw, "egress target contains NUL/whitespace"))
            continue
        if kind == "to":
            if "@" not in raw:
                unsupported.append(
                    (raw, "send_email 'to' has no '@': domain unattestable"))
                continue
            host = raw.rsplit("@", 1)[1].strip().lower()
        else:
            try:
                parts = urlsplit(raw)
            except Exception:
                unsupported.append((raw, "URL cannot be parsed"))
                continue
            if parts.scheme.lower() not in ("http", "https"):
                unsupported.append(
                    (raw, "egress scheme %r is not http/https: host "
                          "unattestable" % (parts.scheme or None,)))
                continue
            host = (parts.hostname or "").strip().lower()
        if not host or "*" in host:
            unsupported.append(
                (raw, "egress host is empty or a wildcard: unattestable"))
            continue
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            unsupported.append((raw, "egress host is not IDNA-encodable"))
            continue
        hosts.append(host)
    # Deterministic order; duplicates carry no extra meaning.
    return sorted(set(hosts)), unsupported


def _default_registry_hosts():
    """The governed package-registry host set, or None when unknown.

    Lazy import keeps this module importable stdlib-only: the product
    registry set lives in gov.supplychain_install. When it cannot be
    imported (standalone use) the caller fails closed as unsupported --
    an install whose fetch origin cannot be attested must never pass
    vacuously.
    """
    try:
        from .supplychain_install import REGISTRY_HOSTS
    except ImportError:
        try:
            from gov.supplychain_install import REGISTRY_HOSTS
        except ImportError:
            return None
    return REGISTRY_HOSTS


def _derive_install_egress_hosts(tool: str, ctx: Mapping[str, Any]):
    """Derive install_package egress hosts and unmodelable shapes.

    Returns (hosts, unsupported): hosts are normalized exact registry
    host names; unsupported are (raw, reason) pairs. The candidate set
    is ``ctx["registry_hosts"]`` when it is a usable non-empty
    sequence, else the governed ``REGISTRY_HOSTS``. EVERY candidate
    host must be boundary-covered: the checker cannot attest which
    registry a given fetch will hit, so an install is within_boundary
    only when all of them are. Malformed materials fail closed
    (unsupported), never a silent pass.
    """
    hosts = []
    unsupported = []
    if tool != _INSTALL_TOOL:
        return hosts, unsupported
    raw_hosts = ctx.get("registry_hosts")
    candidates = None
    if (isinstance(raw_hosts, (list, tuple, set, frozenset))
            and len(raw_hosts) > 0):
        candidates = list(raw_hosts)
    else:
        default = _default_registry_hosts()
        if default is None:
            unsupported.append(
                ("install_package",
                 "registry host set unattestable: no usable "
                 "ctx['registry_hosts'] and "
                 "gov.supplychain_install.REGISTRY_HOSTS unavailable"))
            return hosts, unsupported
        candidates = list(default)
    for raw in candidates:
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            unsupported.append(
                (repr(raw)[:128],
                 "registry host is not a usable hostname string"))
            continue
        host = raw.strip().lower().rstrip(".")
        if (not host or "*" in host
                or any(c.isspace() for c in host)):
            unsupported.append(
                (raw[:128], "registry host is empty, a wildcard, or "
                            "contains whitespace: unattestable"))
            continue
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            unsupported.append(
                (raw[:128], "registry host is not IDNA-encodable"))
            continue
        hosts.append(host)
    hosts = sorted(set(hosts))
    if not hosts and not unsupported:
        unsupported.append(
            ("install_package",
             "no usable registry hosts: the install fetch origin "
             "cannot be attested"))
    return hosts, unsupported


def _derive_install_fs_write(tool: str, args: Mapping[str, Any],
                             ctx: Mapping[str, Any]):
    """Derive the install_package filesystem write, when declared.

    Returns (accesses, unsupported, resolution_source,
    target_declared): accesses are ("write", normalized-absolute-path)
    for the install target; unsupported are (raw, reason) pairs. The
    target is attested only when the declared shape names it
    (``args["path"]`` / ``ctx["path_resolved"]``, same resolution
    semantics as path tools). An UNDECLARED target is not unsupported
    here -- check() names "filesystem" uncovered for the proof instead
    (in-toto REQUIRE: never claim unexamined coverage). A MALFORMED
    declared target is unsupported: a claimed target that cannot be
    attested fails closed.
    """
    if tool != _INSTALL_TOOL:
        return [], [], "none", False
    norm, target_unsupported, resolution_source, had_signal = (
        _resolve_fs_target(args, ctx))
    if not had_signal:
        return [], [], "none", False
    if norm is None:
        return [], target_unsupported, resolution_source, True
    return [("write", norm)], [], resolution_source, True


def _derive_mcp_accesses(tool: str, args: Mapping[str, Any]):
    """Derive MCP tool-call accesses and unmodelable shapes.

    Returns (accesses, unsupported): accesses are
    ``(server, name, arg_bytes)`` with ``arg_bytes`` the canonical-JSON
    byte size of the ``arguments`` object; unsupported are (raw, reason)
    pairs. The declared shape mirrors the MCP tools/call wire shape:
    ``{"server": <id>, "name": <tool>, "arguments": {...}}``.
    """
    accesses = []
    unsupported = []
    if tool not in _MCP_TOOLS:
        return accesses, unsupported
    server = args.get("server")
    name = args.get("name")
    arguments = args.get("arguments", {})
    if not isinstance(server, str) or not server:
        unsupported.append(
            (repr(server), "mcp_call 'server' must be a non-empty string "
                           "server identity"))
        return accesses, unsupported
    for bad, why in (("\x00", "NUL"), ("::", "the pair separator")):
        if bad in server:
            unsupported.append(
                (server, "mcp_call 'server' contains %s" % why))
            return accesses, unsupported
    if any(c.isspace() for c in server):
        unsupported.append(
            (server, "mcp_call 'server' contains whitespace"))
        return accesses, unsupported
    if not isinstance(name, str) or not name:
        unsupported.append(
            (repr(name), "mcp_call 'name' must be a non-empty string "
                         "tool name"))
        return accesses, unsupported
    for bad, why in (("\x00", "NUL"), ("::", "the pair separator")):
        if bad in name:
            unsupported.append(
                (name, "mcp_call 'name' contains %s" % why))
            return accesses, unsupported
    if any(c.isspace() for c in name):
        unsupported.append(
            (name, "mcp_call 'name' contains whitespace"))
        return accesses, unsupported
    if not isinstance(arguments, Mapping):
        unsupported.append(
            (repr(arguments)[:128], "mcp_call 'arguments' must be a JSON "
                                    "object"))
        return accesses, unsupported
    try:
        blob = json.dumps(arguments, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True)
        arg_bytes = len(blob.encode("utf-8"))
    except Exception:
        unsupported.append(
            ("arguments", "mcp_call 'arguments' are not JSON-serializable"))
        return accesses, unsupported
    accesses.append((server, name, arg_bytes))
    return accesses, unsupported


class _GraphQLShapeError(Exception):
    """A GraphQL document the checker cannot model (fail-closed input)."""


_GQL_NAME_PREFIX = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_GQL_PUNCT = set("{}()[]:!=$@|&")


def _gql_tokenize(src: str):
    """Tokenize a GraphQL document. Kinds: NAME STRING NUMBER PUNCT
    ELLIPSIS EOF. Strings/numbers carry no text (their content never
    affects the proof); comments are stripped. Raises
    _GraphQLShapeError on any lexical malformation."""
    toks = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "#":
            j = src.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c in " \t\r\n,":
            i += 1
            continue
        if c == '"':
            if src.startswith('"""', i):
                j = src.find('"""', i + 3)
                if j < 0:
                    raise _GraphQLShapeError("unterminated block string")
                i = j + 3
            else:
                j = i + 1
                while True:
                    if j >= n:
                        raise _GraphQLShapeError("unterminated string")
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == '"':
                        break
                    j += 1
                i = j + 1
            toks.append(("STRING", ""))
            continue
        if c.isdigit() or (c == "-" and i + 1 < n
                           and (src[i + 1].isdigit()
                                or src[i + 1] == ".")):
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._+-"):
                j += 1
            toks.append(("NUMBER", ""))
            i = j
            continue
        if c == "_" or c.isalpha():
            m = _GQL_NAME_PREFIX.match(src, i)
            toks.append(("NAME", m.group(0)))
            i = m.end()
            continue
        if src.startswith("...", i):
            toks.append(("ELLIPSIS", "..."))
            i += 3
            continue
        if c in _GQL_PUNCT:
            toks.append(("PUNCT", c))
            i += 1
            continue
        raise _GraphQLShapeError(
            "unexpected character %r at offset %d" % (c, i))
    toks.append(("EOF", ""))
    return toks


def _gql_balanced_inner(toks, open_idx):
    """Tokens between a balanced opener and its closer.

    Returns (inner_tokens, index_past_closer). Any imbalance raises
    _GraphQLShapeError (fail-closed, never a guessed structure).
    """
    opener = toks[open_idx][1]
    closer = {"{": "}", "(": ")", "[": "]"}[opener]
    depth = 0
    i, n = open_idx, len(toks)
    while i < n:
        k, t = toks[i]
        if k == "PUNCT":
            if t == opener:
                depth += 1
            elif t == closer:
                depth -= 1
                if depth == 0:
                    return toks[open_idx + 1:i], i + 1
        i += 1
    raise _GraphQLShapeError("unbalanced %r" % opener)


def _gql_skip_directives(toks, i):
    """Skip @directive[(...)] groups; returns the new index."""
    n = len(toks)
    while i < n and toks[i] == ("PUNCT", "@"):
        i += 1
        if i >= n or toks[i][0] != "NAME":
            raise _GraphQLShapeError("malformed directive")
        i += 1
        if i < n and toks[i] == ("PUNCT", "("):
            _, i = _gql_balanced_inner(toks, i)
    return i


def _gql_extract_fragments(toks):
    """Split fragment definitions out of the token stream.

    Returns (op_tokens, {name: inner_tokens}). Duplicate or malformed
    definitions raise _GraphQLShapeError.
    """
    frags = {}
    out = []
    i, n = 0, len(toks)
    while i < n:
        k, t = toks[i]
        if k == "NAME" and t == "fragment":
            if not (i + 2 < n and toks[i + 1][0] == "NAME"
                    and toks[i + 2] == ("NAME", "on")):
                raise _GraphQLShapeError("malformed fragment definition")
            fname = toks[i + 1][1]
            j = i + 3
            if j >= n or toks[j][0] != "NAME":
                raise _GraphQLShapeError("malformed fragment definition")
            j += 1
            j = _gql_skip_directives(toks, j)
            if j >= n or toks[j] != ("PUNCT", "{"):
                raise _GraphQLShapeError("malformed fragment definition")
            inner, j = _gql_balanced_inner(toks, j)
            if fname in frags:
                raise _GraphQLShapeError(
                    "duplicate fragment %r" % fname)
            frags[fname] = inner
            i = j
        else:
            out.append(toks[i])
            i += 1
    return out, frags


def _gql_inline_fragments(toks, frags):
    """Splice named spreads with their fragment bodies.

    Same-document fragments are inlined so depth and field analysis
    see through them. Cyclic spreads and spreads of unknown fragments
    raise _GraphQLShapeError (fail-closed: no hang, no guess).
    """

    def _inline(seq, stack):
        out = []
        i, n = 0, len(seq)
        while i < n:
            k, t = seq[i]
            if k == "ELLIPSIS" and i + 1 < n \
                    and seq[i + 1][0] == "NAME" \
                    and seq[i + 1][1] != "on":
                fname = seq[i + 1][1]
                if fname not in frags:
                    raise _GraphQLShapeError(
                        "spread of unknown fragment %r" % fname)
                if fname in stack:
                    raise _GraphQLShapeError(
                        "cyclic fragment spread %r" % fname)
                out.extend(_inline(frags[fname], stack | {fname}))
                i += 2
                continue
            out.append(seq[i])
            i += 1
        return out

    return _inline(toks, frozenset())


class _GqlSelectionParser:
    """Recursive-descent over the inlined token stream.

    Collects maximum selection-set depth, mutation root-field names,
    and whether any __-prefixed (introspection) field appears.
    Directives that could conditionally exclude fields (@include /
    @skip) are NOT evaluated: the static document is measured as
    written, which can only over-count -- the fail-closed direction.
    """

    def __init__(self, toks):
        self.toks = toks
        self.pos = 0

    def peek(self):
        return self.toks[self.pos]

    def next(self):
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def skip_directives(self):
        self.pos = _gql_skip_directives(self.toks, self.pos)

    def parse_selection_set(self, depth, op_type):
        k, t = self.next()
        if (k, t) != ("PUNCT", "{"):
            raise _GraphQLShapeError("expected '{'")
        max_depth = depth
        mut_roots = []
        has_intro = False
        while True:
            k, t = self.peek()
            if (k, t) == ("PUNCT", "}"):
                self.next()
                return max_depth, mut_roots, has_intro
            if k == "EOF":
                raise _GraphQLShapeError("unterminated selection set")
            if k == "ELLIPSIS":
                # Inline fragment ('... on Type { }' / '... { }');
                # named spreads were inlined away already.
                self.next()
                if self.peek()[0] == "NAME" \
                        and self.peek()[1] == "on":
                    self.next()
                    on_k, _ = self.next()
                    if on_k != "NAME":
                        raise _GraphQLShapeError(
                            "expected type name after 'on'")
                self.skip_directives()
                if self.peek() == ("PUNCT", "{"):
                    d, m, h = self.parse_selection_set(depth + 1,
                                                       op_type)
                    max_depth = max(max_depth, d)
                    mut_roots.extend(m)
                    has_intro = has_intro or h
                continue
            if k != "NAME":
                raise _GraphQLShapeError(
                    "expected field name, got %r" % (t,))
            self.next()
            fname = t
            if self.peek() == ("PUNCT", ":"):
                # alias: the real field name follows the colon.
                self.next()
                k2, t2 = self.next()
                if k2 != "NAME":
                    raise _GraphQLShapeError(
                        "expected field name after alias ':'")
                fname = t2
            if fname.startswith("__"):
                has_intro = True
            if depth == 1 and op_type == "mutation":
                mut_roots.append(fname)
            if self.peek() == ("PUNCT", "("):
                _, self.pos = _gql_balanced_inner(self.toks, self.pos)
            self.skip_directives()
            if self.peek() == ("PUNCT", "{"):
                d, m, h = self.parse_selection_set(depth + 1, op_type)
                max_depth = max(max_depth, d)
                mut_roots.extend(m)
                has_intro = has_intro or h


def _parse_graphql(src: str):
    """Statically analyze one GraphQL operation document.

    Returns (op_type, max_depth, mutation_roots, has_introspection).
    Raises _GraphQLShapeError when the document cannot be modeled:
    zero or multiple operations (the checker cannot attribute which
    operation the caller will run), non-operation definitions,
    fragment cycles, or any lexical/structural malformation.
    """
    toks = _gql_tokenize(src)
    ops_toks, frags = _gql_extract_fragments(toks)
    inlined = _gql_inline_fragments(ops_toks, frags)
    p = _GqlSelectionParser(inlined)
    ops = []
    while p.peek()[0] != "EOF":
        k, t = p.peek()
        if (k, t) == ("PUNCT", "{"):
            ops.append(("query", p.parse_selection_set(1, "query")))
        elif k == "NAME" and t in ("query", "mutation", "subscription"):
            op_type = t
            p.next()
            if p.peek()[0] == "NAME":
                p.next()  # operation name
            if p.peek() == ("PUNCT", "("):
                _, p.pos = _gql_balanced_inner(p.toks, p.pos)
            p.skip_directives()
            if p.peek() != ("PUNCT", "{"):
                raise _GraphQLShapeError("expected selection set")
            ops.append((op_type, p.parse_selection_set(1, op_type)))
        else:
            raise _GraphQLShapeError(
                "not an executable operation document (got %r)" % (t,))
    if len(ops) != 1:
        raise _GraphQLShapeError(
            "expected exactly one operation, found %d: the checker "
            "cannot attribute which operation the caller will run"
            % len(ops))
    op_type, (max_depth, mut_roots, has_intro) = ops[0]
    return op_type, max_depth, tuple(sorted(set(mut_roots))), has_intro


def _derive_graphql_accesses(tool: str, args: Mapping[str, Any]):
    """Derive GraphQL operation accesses and unmodelable shapes.

    Returns (accesses, unsupported): accesses are
    ``(op_type, max_depth, mutation_roots, has_introspection)``;
    unsupported are (raw, reason) pairs. The declared shape is
    ``{"tool": "graphql", "args": {"endpoint": <url>, "query": <doc>}}``;
    the endpoint host is additionally covered by the ``egress`` domain.
    """
    accesses = []
    unsupported = []
    if tool not in _GRAPHQL_TOOLS:
        return accesses, unsupported
    query = args.get("query")
    if not isinstance(query, str) or not query:
        unsupported.append(
            (repr(query)[:128], "graphql 'query' must be a non-empty "
                                "string document"))
        return accesses, unsupported
    if "\x00" in query:
        unsupported.append(
            (query[:128], "graphql query contains NUL"))
        return accesses, unsupported
    try:
        op = _parse_graphql(query)
    except _GraphQLShapeError as e:
        unsupported.append(
            (query[:256], "graphql document unmodelable: %s" % e))
        return accesses, unsupported
    accesses.append(op)
    return accesses, unsupported


def check(action: Mapping[str, Any], ctx: Mapping[str, Any],
          boundary: Optional[AuthorityBoundary],
          max_accesses: int = DEFAULT_MAX_ACCESSES, *,
          mcp_tool_registry: Optional[Mapping[str, Any]] = None,
          token_claims: Optional[Mapping[str, Any]] = None) -> AuthorityProof:
    """Check one proposed action against the operator boundary.

    Pure function: deterministic, stdlib-only, no I/O, no clock. Never
    raises on hostile ``action``/``ctx`` shapes -- unmodelable input
    becomes ``unsupported``, never an exception (the seam must not
    turn a hostile action dict into a crash). ``boundary=None`` means
    the operator declared no boundary: verdict ``inconclusive`` with
    all domains uncovered (advisory at the seam, never a refusal).

    ``mcp_tool_registry`` / ``token_claims`` are the wave-196 MCP
    annotation-attestation seam (see ``gov.mcp_annotations``): when a
    registry is supplied, each authorized ``mcp_call`` is additionally
    checked against the attested ``required_scopes`` for its exact
    ``server::tool`` pair, using the caller's verified identity-token
    claim set (``aud``/``exp`` validated, then ``agent_scope`` matched
    exactly). A scope miss is ``exceeds_boundary`` (fail closed).
    Clock note: the scope path validates token expiry against the wall
    clock (via ``decision_packet.check_token_claims``), so with a
    registry and claims supplied the function is no longer clock-free
    -- two runs straddling a token's expiry boundary can differ;
    otherwise it is deterministic. Without a registry the MCP check
    is exactly the legacy one (boundary allowlist + argument byte
    budget); the new keyword args are additive and ignored by the
    legacy path.
    """
    if not isinstance(action, Mapping):
        action = {}
    if not isinstance(ctx, Mapping):
        ctx = {}
    tool = action.get("tool")
    args = action.get("args")
    if not isinstance(args, Mapping):
        args = {}
    if not isinstance(tool, str):
        tool = ""

    if boundary is None:
        return AuthorityProof(
            verdict=INCONCLUSIVE,
            covered_domains=(),
            uncovered_domains=ALL_DOMAINS,
            counterexample=None,
            boundary_id=None,
            boundary_version=None,
            resolution_source="none",
            detail=("no operator-declared authority boundary: coverage "
                    "cannot be proven; advisory only"),
        )
    if not isinstance(boundary, AuthorityBoundary):
        # A programming error at the seam, not a hostile action: fail
        # closed as inconclusive rather than raising past the verdict
        # path (the executor treats non-within as refusal).
        return AuthorityProof(
            verdict=INCONCLUSIVE,
            covered_domains=(),
            uncovered_domains=ALL_DOMAINS,
            counterexample=None,
            boundary_id=None,
            boundary_version=None,
            resolution_source="none",
            detail="seam error: boundary is not an AuthorityBoundary",
        )
    if mcp_tool_registry is not None and \
            not isinstance(mcp_tool_registry, Mapping):
        # A programming error at the seam (the registry must be built
        # by gov.mcp_annotations.build_tool_registry): fail closed as
        # inconclusive rather than trusting an unshaped registry.
        return AuthorityProof(
            verdict=INCONCLUSIVE,
            covered_domains=(),
            uncovered_domains=ALL_DOMAINS,
            counterexample=None,
            boundary_id=None,
            boundary_version=None,
            resolution_source="none",
            detail="seam error: mcp_tool_registry is not a mapping",
        )

    fs_accesses, fs_unsupported, resolution_source = _derive_fs_accesses(
        tool, args, ctx)
    egress_hosts, egress_unsupported = _derive_egress_accesses(tool, args)
    (install_fs, install_fs_unsupported, install_rs,
     install_target_declared) = _derive_install_fs_write(tool, args, ctx)
    install_hosts, install_egress_unsupported = _derive_install_egress_hosts(
        tool, ctx)
    mcp_accesses, mcp_unsupported = _derive_mcp_accesses(tool, args)
    graphql_accesses, graphql_unsupported = _derive_graphql_accesses(
        tool, args)

    fs_accesses = list(fs_accesses) + install_fs
    egress_hosts = list(egress_hosts) + install_hosts
    if install_target_declared and install_rs != "none":
        # The install target was bound to a resolved/declared path:
        # the proof's resolution binds the filesystem verdict to it.
        resolution_source = install_rs

    # in-toto REQUIRE (pattern-steal): a tool with real effects in a
    # domain must not ride a proof that claims the domain covered
    # while zero accesses were derived there. Such a domain is named
    # uncovered -- the evidence product says exactly what was
    # examined -- instead of passing vacuously. Tools without required
    # domains keep the full coverage claim (their empty derivation is
    # honest: nothing to examine).
    required_domains = _REQUIRED_ACCESS_DOMAINS.get(tool, ())
    narrowed = tuple(
        d for d in ("filesystem", "egress")
        if d in required_domains
        and not (fs_accesses if d == "filesystem" else egress_hosts))
    covered_domains = tuple(
        d for d in COVERED_DOMAINS if d not in narrowed)
    uncovered_domains = narrowed + ("process_identity",)

    total = (len(fs_accesses) + len(egress_hosts) + len(mcp_accesses)
             + len(graphql_accesses))
    if total > max_accesses:
        return AuthorityProof(
            verdict=INCONCLUSIVE,
            covered_domains=covered_domains,
            uncovered_domains=uncovered_domains,
            counterexample=None,
            boundary_id=boundary.boundary_id,
            boundary_version=boundary.version,
            resolution_source=resolution_source,
            detail=("access budget exceeded: %d declared accesses > "
                    "max_accesses=%d" % (total, max_accesses)),
        )

    unsupported = ([("filesystem", raw, reason)
                    for raw, reason in fs_unsupported]
                   + [("filesystem", raw, reason)
                      for raw, reason in install_fs_unsupported]
                   + [("egress", raw, reason)
                      for raw, reason in egress_unsupported]
                   + [("egress", raw, reason)
                      for raw, reason in install_egress_unsupported]
                   + [("mcp_tools", raw, reason)
                      for raw, reason in mcp_unsupported]
                   + [("graphql", raw, reason)
                      for raw, reason in graphql_unsupported])
    if unsupported:
        # Deterministic first offender; str() on the raw access keeps
        # the sort total even for non-string hostile inputs.
        domain, raw, reason = sorted(
            unsupported, key=lambda e: (e[0], str(e[1]), e[2]))[0]
        return AuthorityProof(
            verdict=UNSUPPORTED,
            covered_domains=covered_domains,
            uncovered_domains=uncovered_domains,
            counterexample=Counterexample(
                domain=domain, access=str(raw)[:256], nearest_rule=None,
                reason=reason),
            boundary_id=boundary.boundary_id,
            boundary_version=boundary.version,
            resolution_source=resolution_source,
            detail=("unmodelable action shape: %s" % reason),
        )

    for kind, access in sorted(fs_accesses):
        rules = (boundary.fs_write_prefixes if kind == "write"
                 else boundary.fs_read_prefixes)
        if not _covered_by_prefix(access, rules):
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="filesystem", access=access,
                    nearest_rule=_nearest_rule(access, rules),
                    reason=("%s access %r is outside every declared "
                            "%s prefix" % (kind, access, kind))),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail=("%s access outside the declared boundary" % kind),
            )
    for host in egress_hosts:
        if host not in boundary.egress_hosts:
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="egress", access=host,
                    nearest_rule=_nearest_rule(
                        host, boundary.egress_hosts),
                    reason=("egress host %r is not in the declared "
                            "egress allowlist" % (host,))),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail="egress host outside the declared boundary",
            )
    for server, name, arg_bytes in mcp_accesses:
        # Exact pair matching, never prefixes: "files-backup::read" is
        # not "files::read", and the '::' separator cannot appear inside
        # either side (rejected at boundary load and at derive time),
        # so one pair can never masquerade as another.
        pair = server + "::" + name
        if server not in boundary.mcp_servers:
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="mcp_tools", access=pair,
                    nearest_rule=_nearest_rule(
                        server, boundary.mcp_servers),
                    reason=("MCP server %r is not in the declared "
                            "server allowlist" % (server,))),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail="MCP server outside the declared boundary",
            )
        if pair not in boundary.mcp_tools:
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="mcp_tools", access=pair,
                    nearest_rule=_nearest_rule(
                        pair, boundary.mcp_tools),
                    reason=("MCP tool pair %r is not in the declared "
                            "tool allowlist" % (pair,))),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail="MCP tool pair outside the declared boundary",
            )
        if arg_bytes > boundary.mcp_max_arg_bytes:
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="mcp_tools", access=pair,
                    nearest_rule=None,
                    reason=("MCP arguments for %r are %d bytes, over "
                            "the declared max of %d bytes"
                            % (pair, arg_bytes,
                               boundary.mcp_max_arg_bytes))),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail="MCP argument budget outside the declared boundary",
            )
        if mcp_tool_registry is not None:
            # Attested annotation seam (wave-196): the pair passed the
            # boundary allowlist above; now enforce any attested
            # required scopes against the caller's identity-token
            # claim set. Attestation can only tighten: un-attested
            # pairs require nothing here.
            scope_ok, scope_why = _mcp_annotations.check_required_scopes(
                pair, mcp_tool_registry, token_claims)
            if not scope_ok:
                return AuthorityProof(
                    verdict=EXCEEDS,
                    covered_domains=covered_domains,
                    uncovered_domains=uncovered_domains,
                    counterexample=Counterexample(
                        domain="mcp_tools", access=pair,
                        nearest_rule=None, reason=scope_why),
                    boundary_id=boundary.boundary_id,
                    boundary_version=boundary.version,
                    resolution_source=resolution_source,
                    detail="MCP required-scope check failed for %r" % pair,
                )
    for op_type, max_depth, mut_roots, has_intro in graphql_accesses:
        op_access = "%s depth=%d" % (op_type, max_depth)
        if has_intro and not boundary.graphql_allow_introspection:
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="graphql", access=op_access,
                    nearest_rule=None,
                    reason=("GraphQL introspection fields (__schema / "
                            "__type / __typename) are not allowed by "
                            "this boundary")),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail="GraphQL introspection outside the declared boundary",
            )
        if max_depth > boundary.graphql_max_depth:
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="graphql", access=op_access,
                    nearest_rule=None,
                    reason=("GraphQL selection depth %d exceeds the "
                            "declared max of %d"
                            % (max_depth, boundary.graphql_max_depth))),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail="GraphQL selection depth outside the declared "
                       "boundary",
            )
        if op_type == "mutation":
            if not boundary.graphql_allow_mutations:
                return AuthorityProof(
                    verdict=EXCEEDS,
                    covered_domains=covered_domains,
                    uncovered_domains=uncovered_domains,
                    counterexample=Counterexample(
                        domain="graphql",
                        access="mutation:%s" % ",".join(mut_roots),
                        nearest_rule=None,
                        reason=("GraphQL mutations are not allowed by "
                                "this boundary")),
                    boundary_id=boundary.boundary_id,
                    boundary_version=boundary.version,
                    resolution_source=resolution_source,
                    detail="GraphQL mutation outside the declared boundary",
                )
            for root in mut_roots:
                if root not in boundary.graphql_mutation_allowlist:
                    return AuthorityProof(
                        verdict=EXCEEDS,
                        covered_domains=covered_domains,
                        uncovered_domains=uncovered_domains,
                        counterexample=Counterexample(
                            domain="graphql",
                            access="mutation:%s" % root,
                            nearest_rule=_nearest_rule(
                                root,
                                boundary.graphql_mutation_allowlist),
                            reason=("GraphQL mutation root field %r is "
                                    "not in the declared mutation "
                                    "allowlist" % (root,))),
                        boundary_id=boundary.boundary_id,
                        boundary_version=boundary.version,
                        resolution_source=resolution_source,
                        detail=("GraphQL mutation root outside the "
                                "declared boundary"),
                    )
        elif op_type == "subscription":
            # The boundary schema models query/mutation only; a
            # subscription is a standing channel the operator never
            # declared -- exceeds, never silently allowed.
            return AuthorityProof(
                verdict=EXCEEDS,
                covered_domains=covered_domains,
                uncovered_domains=uncovered_domains,
                counterexample=Counterexample(
                    domain="graphql", access=op_access,
                    nearest_rule=None,
                    reason=("GraphQL subscriptions are outside this "
                            "boundary's schema: only query and mutation "
                            "operations are modeled")),
                boundary_id=boundary.boundary_id,
                boundary_version=boundary.version,
                resolution_source=resolution_source,
                detail="GraphQL subscription outside the declared boundary",
            )
    return AuthorityProof(
        verdict=WITHIN,
        covered_domains=covered_domains,
        uncovered_domains=uncovered_domains,
        counterexample=None,
        boundary_id=boundary.boundary_id,
        boundary_version=boundary.version,
        resolution_source=resolution_source,
        detail=("all %d declared access(es) inside the declared boundary"
                % total),
    )
