"""Spawn-context and victim-owned-infrastructure exfiltration guard (W245-3).

The s1ngularity shape: a package postinstall script spawns
``claude --dangerously-skip-permissions``; the agent then exfiltrates
data to a repo the VICTIM owns (evading destination-reputation review)
and persists via shell-rc edits.

Three fail-closed rules, layered on gov.config_trust (reused, never
duplicated -- the provenance classification and the
``config-provenance-*`` refusal vocabulary are shared, not
re-implemented):

1. Spawn-context classification. Permission-bypass flags (a closed
   vocabulary, never guessed from substrings) presented through a
   postinstall spawn context are refused
   ``tool-spawn-context-untrusted``. The same flags in a
   user-invoked, deployment-authorized context are a *declared risk*,
   not a refusal (``spawn-context-declared-risk``). Spawn contexts
   are closed-vocabulary; an unknown context is malformed, never
   treated as benign. Provenance is deployment-vouched, never
   agent-asserted: a spawn record that self-declares trust reuses
   ``config-provenance-agent-asserted``, and one with no provenance
   block at all reuses ``config-provenance-untrusted``.

2. Egress review. Destination-ownership NEVER exempts review: exfil
   to a victim-owned repo is flagged exactly like exfil to a foreign
   host (both are ``review-required``). A record that asserts a
   review exemption on ownership grounds -- or claims
   deployment-pinned status for a destination the pinned-destination
   map does not vouch -- is refused
   ``egress-destination-exemption-refused``.

3. Persistence. Shell-rc writes (a closed vocabulary of rc paths,
   matched by basename or full path) from a postinstall or otherwise
   unvouched writer are refused ``persistence-modification-refused``.
   Only deployment-vouched admin sources may modify rc files.

Verification order (fail-closed): shape -> provenance -> rule.

Honest residuals:
- The deployment source maps (who is user-invoked, which
  destinations are pinned, who may touch rc files) are
  deployment-supplied. The module refuses what is NOT vouched; it
  cannot catch a deployment that vouches a lie (the same honest
  boundary as config_trust's pin ceremony).
- ``spawn-context-declared-risk`` is an informational decision code,
  not a refusal: a deployment-authorized user-invoked bypass is
  allowed-but-declared so the audit trail names it.
- The module sees declarations (spawn records, egress records,
  modification records), not live process trees. Binding the record
  to the live process is deployment-owned.

Stdlib only. Deterministic. No env reads, no I/O. Fail-closed on
malformed input.
"""

from gov import config_trust as _ct

SPAWN_CONTEXT_RECORD_MALFORMED = "spawn-context-record-malformed"
TOOL_SPAWN_CONTEXT_UNTRUSTED = "tool-spawn-context-untrusted"
SPAWN_CONTEXT_DECLARED_RISK = "spawn-context-declared-risk"
EGRESS_DESTINATION_EXEMPTION_REFUSED = \
    "egress-destination-exemption-refused"
PERSISTENCE_MODIFICATION_REFUSED = "persistence-modification-refused"

# Closed spawn-context vocabulary. Package lifecycle contexts are
# never treated as user-invoked; unknown contexts fail closed.
SPAWN_POSTINSTALL = "postinstall"
SPAWN_USER_INVOKED = "user-invoked"
_SPAWN_CONTEXTS = frozenset([SPAWN_POSTINSTALL, SPAWN_USER_INVOKED])

# Closed vocabulary of permission-bypass flags. Enumerated, never
# substring-matched: a flag must be exactly one of these to count.
# This is the detection signal for the s1ngularity shape
# (postinstall-spawned CLI with permissions disabled), not a CLI
# reference manual.
_BYPASS_FLAGS = frozenset([
    "--dangerously-skip-permissions",
    "dangerously_skip_permissions",
])

# Closed vocabulary of destination ownership classes.
_OWNERSHIP_CLASSES = frozenset(
    ["victim-owned", "foreign", "deployment-pinned"])

# Closed vocabulary of shell-rc targets (basename or full path).
_RC_PATHS = frozenset([
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/zsh/zprofile",
])


class SpawnContextGuardError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(SpawnContextGuardError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise SpawnContextGuardError(code, detail)


def _non_empty_str(value, what):
    if not isinstance(value, str) or not value:
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "%s must be a non-empty string" % (what,))
    return value


def _str_list(value, what):
    if not isinstance(value, list):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "%s must be a list" % (what,))
    for item in value:
        if not isinstance(item, str) or isinstance(item, bool):
            _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                    "%s items must be strings (bool rejected)" % (what,))
    return value


def _classify_provenance(record, deployment_source_map, what):
    """Provenance via gov.config_trust (reused, not duplicated).

    Self-asserted trust re-raises ``config-provenance-agent-asserted``;
    a missing provenance block is ``config-provenance-untrusted``.
    Returns (provenance_class, source_id).
    """
    if not isinstance(record, dict):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "%s must be a dict" % (what,))
    if not isinstance(deployment_source_map, dict):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "deployment_source_map must be a dict")
    provenance_class, missing = None, False
    try:
        provenance_class, missing = _ct.classify_provenance(
            record, deployment_source_map)
    except _ct.ConfigTrustError as exc:
        # The classification logic is shared, not duplicated; the
        # refusal vocabulary (the taxonomy code) is reused verbatim,
        # but the seam raises this module's own error type so the
        # public contract is one exception class.
        _refuse(exc.code, exc.detail)
    if missing:
        _refuse("config-provenance-untrusted",
                "%s has no provenance block; provenance absence is "
                "not trust" % (what,))
    provenance = record.get("provenance") or {}
    source_id = provenance.get("source_id")
    return provenance_class, source_id


# ------------------------------------------------------------------
# Rule 1: tool launch through a spawn context.
# ------------------------------------------------------------------

def check_tool_launch(launch_record, deployment_source_map,
                      authorized_bypass_contexts):
    """Check a tool launch against its spawn context.

    ``launch_record``: {"context": "postinstall" | "user-invoked",
    "provenance": {...}, "flags": [str], "argv0": str}.

    - Permission-bypass flags through a postinstall context -> refuse
      ``tool-spawn-context-untrusted``.
    - Permission-bypass flags claiming a user-invoked context whose
      source the deployment map does not vouch (or that is not in
      ``authorized_bypass_contexts``) -> refuse
      ``tool-spawn-context-untrusted``. The postinstall that lies
      about being user-invoked is caught here.
    - Permission-bypass flags in a user-invoked, deployment-vouched,
      explicitly authorized context -> {"decision": "declared-risk",
      "code": "spawn-context-declared-risk"} (allowed-but-declared,
      never silent).
    - No bypass flags -> allow (not every spawn is hostile).

    Every refusal raises SpawnContextGuardError with a taxonomy code.
    """
    if not isinstance(launch_record, dict):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "launch record must be a dict")
    if not isinstance(authorized_bypass_contexts, (list, set, tuple,
                                                   frozenset)):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "authorized_bypass_contexts must be a collection")
    argv0 = _non_empty_str(launch_record.get("argv0"), "argv0")
    context = _non_empty_str(launch_record.get("context"), "context")
    if context not in _SPAWN_CONTEXTS:
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "context %r is not in the closed spawn-context "
                "vocabulary" % (context,))
    provenance_class, source_id = _classify_provenance(
        launch_record, deployment_source_map, "launch record")
    flags = _str_list(launch_record.get("flags", []), "flags")
    bypass_flags = sorted(set(flags) & _BYPASS_FLAGS)
    if not bypass_flags:
        return {"decision": "allow", "argv0": argv0, "context": context,
                "provenance": provenance_class}
    # A permission-bypass flag is present. The detection signal is the
    # flag; the context decides the verdict.
    if context == SPAWN_POSTINSTALL:
        _refuse(TOOL_SPAWN_CONTEXT_UNTRUSTED,
                "tool %r launched with permission-bypass flags %s "
                "through a postinstall spawn context; postinstall "
                "contexts are never authorized for permission bypass"
                % (argv0, bypass_flags))
    authorized = provenance_class == _ct.PROVENANCE_DEPLOYMENT_PINNED \
        and source_id in authorized_bypass_contexts
    if not authorized:
        _refuse(TOOL_SPAWN_CONTEXT_UNTRUSTED,
                "tool %r launched with permission-bypass flags %s "
                "claiming context %r from unvouched source %r; the "
                "deployment map does not authorize bypass for this "
                "context" % (argv0, bypass_flags, context, source_id))
    return {"decision": "declared-risk",
            "code": SPAWN_CONTEXT_DECLARED_RISK,
            "argv0": argv0, "context": context,
            "bypass_flags": bypass_flags,
            "provenance": provenance_class}


# ------------------------------------------------------------------
# Rule 2: egress destination review (victim-owned is never exempt).
# ------------------------------------------------------------------

def check_egress_destination(dest_record, pinned_destinations):
    """Check an egress destination against review rules.

    ``dest_record``: {"destination": str, "owner": "victim-owned" |
    "foreign" | "deployment-pinned", "exempt_claim": bool,
    "provenance": {...}}.

    - "victim-owned" and "foreign" destinations -> {"decision":
      "review-required"}: destination-ownership never exempts review,
      so a victim-owned repo is flagged exactly like a foreign host.
    - A record asserting ``exempt_claim`` on ownership grounds, or
      claiming "deployment-pinned" status for a destination the
      pinned map does not vouch -> refuse
      ``egress-destination-exemption-refused``.
    - A destination the pinned map vouches -> {"decision": "exempt"}.
    """
    if not isinstance(dest_record, dict):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "destination record must be a dict")
    if not isinstance(pinned_destinations, (list, set, tuple,
                                            frozenset)):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "pinned_destinations must be a collection")
    destination = _non_empty_str(
        dest_record.get("destination"), "destination")
    owner = _non_empty_str(dest_record.get("owner"), "owner")
    if owner not in _OWNERSHIP_CLASSES:
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "owner %r is not in the closed ownership vocabulary"
                % (owner,))
    exempt_claim = dest_record.get("exempt_claim", False)
    if not isinstance(exempt_claim, bool):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "exempt_claim must be a bool")
    provenance_class, _ = _classify_provenance(
        dest_record, _pinned_destination_map(pinned_destinations),
        "destination record")
    _ = provenance_class  # provenance is classified for the record;
    # the exemption decision below is the binding rule.
    pinned = destination in set(pinned_destinations)
    if owner == "deployment-pinned" or exempt_claim:
        if not pinned:
            _refuse(EGRESS_DESTINATION_EXEMPTION_REFUSED,
                    "destination %r claims exemption (%s) without a "
                    "pinned-destination match; destination-ownership "
                    "never exempts review" % (
                        destination,
                        "deployment-pinned status"
                        if owner == "deployment-pinned"
                        else "ownership-based exemption"))
        return {"decision": "exempt", "destination": destination,
                "pinned": True}
    # victim-owned and foreign destinations: review is required, never
    # exempted by ownership.
    return {"decision": "review-required", "destination": destination,
            "owner": owner}


def _pinned_destination_map(pinned_destinations):
    """Pinned destinations as a deployment source map.

    The pinned-destination set doubles as the deployment-vouch map for
    provenance classification of the destination record itself: a
    destination record arriving from the pinned destination is
    deployment-pinned; anything else is agent-observed.
    """
    return {dest: "deployment-pinned" for dest in pinned_destinations}


# ------------------------------------------------------------------
# Rule 3: shell-rc persistence modifications.
# ------------------------------------------------------------------

def _is_rc_target(target):
    if target in _RC_PATHS:
        return True
    basename = target.rsplit("/", 1)[-1]
    return basename in _RC_PATHS


def check_rc_modification(mod_record, deployment_admin_sources):
    """Check a filesystem write against shell-rc persistence rules.

    ``mod_record``: {"target": str, "writer_source_id": str,
    "provenance": {...}}.

    - A shell-rc target (closed vocabulary, matched by basename or
      full path) written by a source the deployment admin map does not
      vouch -> refuse ``persistence-modification-refused``.
    - The same target written by a deployment-vouched admin source ->
      allow.
    - A non-rc target -> allow with a "not a shell-rc target" note.
    """
    if not isinstance(mod_record, dict):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "modification record must be a dict")
    if not isinstance(deployment_admin_sources, (list, set, tuple,
                                                  frozenset)):
        _refuse(SPAWN_CONTEXT_RECORD_MALFORMED,
                "deployment_admin_sources must be a collection")
    target = _non_empty_str(mod_record.get("target"), "target")
    writer_source_id = _non_empty_str(
        mod_record.get("writer_source_id"), "writer_source_id")
    provenance_class, source_id = _classify_provenance(
        mod_record, {src: "deployment-pinned"
                     for src in deployment_admin_sources},
        "modification record")
    if not _is_rc_target(target):
        return {"decision": "allow", "target": target,
                "note": "not a shell-rc target"}
    if provenance_class == _ct.PROVENANCE_DEPLOYMENT_PINNED and \
            source_id == writer_source_id:
        return {"decision": "allow", "target": target,
                "writer_source_id": writer_source_id,
                "provenance": provenance_class}
    _refuse(PERSISTENCE_MODIFICATION_REFUSED,
            "shell-rc target %r written by unvouched source %r; only "
            "deployment-vouched admin sources may modify rc files"
            % (target, writer_source_id))
    return None  # unreachable; _refuse always raises
