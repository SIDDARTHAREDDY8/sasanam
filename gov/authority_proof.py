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
  * It does not cover process identity, GraphQL/MCP-style structured
    egress, or any tool whose accesses are not declared in its args.

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
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit
import posixpath

# The four proof verdicts. Only ``within_boundary`` is a passing
# result; every other verdict fails closed at an enforcing seam.
WITHIN = "within_boundary"
EXCEEDS = "exceeds_boundary"
UNSUPPORTED = "unsupported"
INCONCLUSIVE = "inconclusive"
VERDICTS = (WITHIN, EXCEEDS, UNSUPPORTED, INCONCLUSIVE)

# Domains the checker actually evaluates.
COVERED_DOMAINS = ("filesystem", "egress")
# Domains named in every proof. process_identity is carried as an
# explicit uncovered domain: the engine does not model it, and the
# contract refuses to pretend otherwise.
ALL_DOMAINS = ("filesystem", "egress", "process_identity")

# Tool -> (domain, access-kind) mapping over what the engine models.
_WRITE_TOOLS = ("write_file", "delete_file")
_READ_TOOLS = ("read_file",)
_URL_EGRESS_TOOLS = ("http_post", "api_call")
_MAIL_EGRESS_TOOLS = ("send_email",)

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
    names (lowercased, IDNA-normalized at load). There is deliberately
    no process-identity field: the engine cannot verify it, so the
    schema refuses to accept a declaration it cannot check.
    """

    boundary_id: str
    version: str
    fs_read_prefixes: Tuple[str, ...] = ()
    fs_write_prefixes: Tuple[str, ...] = ()
    egress_hosts: Tuple[str, ...] = ()


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


def boundary_from_dict(d: Mapping[str, Any]) -> AuthorityBoundary:
    """Build a validated AuthorityBoundary from an operator dict.

    Unknown keys are rejected (a typo'd key must not silently drop a
    constraint). Raises BoundaryError on any malformation.
    """
    if not isinstance(d, Mapping):
        raise BoundaryError(
            "boundary must be a mapping, got %r" % type(d).__name__)
    known = {"boundary_id", "version", "fs_read_prefixes",
             "fs_write_prefixes", "egress_hosts"}
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

    hosts = d.get("egress_hosts", ())
    if not isinstance(hosts, (tuple, list)):
        raise BoundaryError("egress_hosts must be a list, got %r" % (hosts,))
    return AuthorityBoundary(
        boundary_id=bid,
        version=ver,
        fs_read_prefixes=_prefixes("fs_read_prefixes"),
        fs_write_prefixes=_prefixes("fs_write_prefixes"),
        egress_hosts=tuple(sorted(_normalize_host(h) for h in hosts)),
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
    declared = args.get("path")
    resolved = ctx.get("path_resolved")
    raw = resolved if isinstance(resolved, str) and resolved else None
    if raw is not None:
        resolution_source = "path_resolved"
    elif isinstance(declared, str) and declared:
        raw = declared
        resolution_source = "declared_path"
    if raw is None:
        unsupported.append((repr(declared),
                            "no usable path signal for a path tool"))
        return accesses, unsupported, resolution_source
    if "\x00" in raw:
        unsupported.append((raw, "path contains NUL"))
        return accesses, unsupported, resolution_source
    if ".." in raw.replace("\\", "/").split("/"):
        # Never silently normalize an escape: without filesystem
        # state the checker cannot attest what ".." resolves through
        # (symlinks), so the shape is unmodelable -> unsupported.
        unsupported.append(
            (raw, "path contains '..' escape: the resolved target cannot "
                  "be attested without filesystem state"))
        return accesses, unsupported, resolution_source
    norm = posixpath.normpath(raw.replace("\\", "/"))
    if not norm.startswith("/"):
        root = ctx.get("sandbox_root")
        if isinstance(root, str) and root.startswith("/"):
            norm = posixpath.normpath(
                root.rstrip("/") + "/" + norm.lstrip("/"))
            if ".." in norm.split("/"):
                unsupported.append(
                    (raw, "sandbox-relative path escapes the sandbox root"))
                return accesses, unsupported, resolution_source
        else:
            unsupported.append(
                (raw, "non-absolute path with no sandbox_root to resolve "
                      "it against"))
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


def check(action: Mapping[str, Any], ctx: Mapping[str, Any],
          boundary: Optional[AuthorityBoundary],
          max_accesses: int = DEFAULT_MAX_ACCESSES) -> AuthorityProof:
    """Check one proposed action against the operator boundary.

    Pure function: deterministic, stdlib-only, no I/O, no clock. Never
    raises on hostile ``action``/``ctx`` shapes -- unmodelable input
    becomes ``unsupported``, never an exception (the seam must not
    turn a hostile action dict into a crash). ``boundary=None`` means
    the operator declared no boundary: verdict ``inconclusive`` with
    all domains uncovered (advisory at the seam, never a refusal).
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

    fs_accesses, fs_unsupported, resolution_source = _derive_fs_accesses(
        tool, args, ctx)
    egress_hosts, egress_unsupported = _derive_egress_accesses(tool, args)

    total = len(fs_accesses) + len(egress_hosts)
    if total > max_accesses:
        return AuthorityProof(
            verdict=INCONCLUSIVE,
            covered_domains=COVERED_DOMAINS,
            uncovered_domains=("process_identity",),
            counterexample=None,
            boundary_id=boundary.boundary_id,
            boundary_version=boundary.version,
            resolution_source=resolution_source,
            detail=("access budget exceeded: %d declared accesses > "
                    "max_accesses=%d" % (total, max_accesses)),
        )

    unsupported = ([("filesystem", raw, reason)
                    for raw, reason in fs_unsupported]
                   + [("egress", raw, reason)
                      for raw, reason in egress_unsupported])
    if unsupported:
        # Deterministic first offender; str() on the raw access keeps
        # the sort total even for non-string hostile inputs.
        domain, raw, reason = sorted(
            unsupported, key=lambda e: (e[0], str(e[1]), e[2]))[0]
        return AuthorityProof(
            verdict=UNSUPPORTED,
            covered_domains=COVERED_DOMAINS,
            uncovered_domains=("process_identity",),
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
                covered_domains=COVERED_DOMAINS,
                uncovered_domains=("process_identity",),
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
                covered_domains=COVERED_DOMAINS,
                uncovered_domains=("process_identity",),
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
    return AuthorityProof(
        verdict=WITHIN,
        covered_domains=COVERED_DOMAINS,
        uncovered_domains=("process_identity",),
        counterexample=None,
        boundary_id=boundary.boundary_id,
        boundary_version=boundary.version,
        resolution_source=resolution_source,
        detail=("all %d declared access(es) inside the declared boundary"
                % total),
    )
