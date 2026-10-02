"""Discovery-driven tool-definition registry + scheduled re-scan
(wave-282 lane 4: snyk/agent-scan ADAPT).

snyk/agent-scan (Apache-2.0; LICENSE bytes verified in the wave-281
prospectus) is a scanner that discovers agent components (MCP servers,
skills, tools, prompts, resources) across four scopes (system / user /
project-workspace / extension-plugin), hashes each discovered tool's
definition (name, description, input schema) at scan time, and compares
across scans: drift = rug pull / unauthorized change. Its v0.4.14+
guard hooks diff the config at change time, not just at scan time.

This module adapts those three mechanisms into Sasanam's
continuous skill/MCP supply-chain verification stream. Pattern-adapted
only -- no agent-scan code is vendored (their harness is not our
engine), stdlib-only, $0 spend, no network calls, no tokens.

Composition (never duplication):

* ``gov.tool_continuity.ToolInventory`` (wave-89): pins
  DEPLOYMENT-CONTROLLED tool definitions (the provider's pinned notion
  of what each tool IS); its trust assumption is that the provider
  cannot rewrite the inventory out-of-band. This module pins
  DISCOVERED definitions: the observation source is UNTRUSTED by
  design, and drift is evidence of compromise (rug pull), not a
  config error. The canonical digest is REUSED byte-for-byte
  (``definition_digest`` delegates to
  ``tool_continuity.tool_definition_digest``), so pins from either
  registry are comparable.
* ``gov.skill_watch.SkillWatch``: pins skill CONTENT bytes with
  scheduled ``verify_all`` sweeps, ``check_at_use`` on the governed
  path, quarantine on mismatch, and governed ``approve_repin`` with
  bait-and-switch protection. This module applies the SAME
  discipline to tool DEFINITIONS (the rug-pull surface is the tool
  shape, not the file bytes) and reuses its precedents: fail-closed
  quarantine, digests (never content) in audit events, re-pin bound
  to the fresh observation, loud corruption of the pin store, and
  NO in-process scheduler (the deployment's scheduler calls
  ``run_rescan`` / ``executor.run_discovery_scan``).
* ``gov.adapters.mcp_adapter``: pins live MCP tool metadata
  (``metadata_hash``) and raises ``MetadataChangedError`` on server-
  side drift. This module is the scope-aware inventory ABOVE the
  adapter: it discovers WHICH components exist in each trust scope
  and pins their definitions before the adapter ever binds them.
* ``gov.mcp_discovery_trust``: the DNS-discovery threat model. The
  four scopes here are the trust scopes that threat model reasons
  about.

Traps honored (from the prospectus):

* v0.6+ needs SNYK_TOKEN against the Snyk cloud -- this module is
  the OFFLINE pattern only: it never calls the network. The
  ``observe`` / ``observe_one`` callables are DEPLOYMENT-SUPPLIED;
  the registry itself performs zero I/O.
* DNS-rebinding window when scanning remote MCP servers -- the
  registry never fetches; scanning untrusted configs MUST run
  inside the deployment's sandbox (see ``gov/sandbox.py``). The
  observation functions are the sandbox boundary, documented here,
  enforced by the deployment.
* Closed to contributions upstream -- we depend on the pattern,
  not the repo.

Offline evidence posture: drift events carry before/after DIGESTS
only (agent-scan's redact-before-emit discipline, changelog 0.5.11).
The definition text never reaches the audit log.

Discovery scope vocabulary (agent-scan's four scopes, closed):

    system     -- machine-wide agent configuration
    user       -- the operator's own agent configuration
    project    -- the checked-out workspace's configuration
    extension  -- plugin/extension-installed configuration

A user-scope skill can shadow a system-scope tool: every discovered
component is tagged ``{scope, agent_host, component_type,
source_path}`` and the four-scope x component-type coverage matrix
is the agent-discovery inventory audit artifact.
"""

import hashlib
import json
import os
import tempfile

from . import tool_continuity as _tc

# ---------------------------------------------------------------------------
# Discovery vocabulary (closed).
# ---------------------------------------------------------------------------

#: The four agent-scan discovery scopes. Closed: an unknown scope
#: fails LOUD (``discovery-scope-unknown``), never silently maps.
SCOPES = ("system", "user", "project", "extension")

#: Component kinds agent-scan scans. Closed vocabulary.
COMPONENT_TYPES = ("mcp_server", "tool", "prompt", "resource", "skill")

#: Version stamp for the persisted pin store.
REGISTRY_STORE_VERSION = 1


class DiscoveryScanError(Exception):
    """Base fail-closed error for the discovery-scan registry.

    Carries the coded verdict as ``.code`` (registered in
    ``gov/decision_codes.py``).
    """


class DiscoveryScopeUnknown(DiscoveryScanError):
    """An observation named a scope outside the closed vocabulary."""

    code = "discovery-scope-unknown"


class DiscoveryDefinitionDrift(DiscoveryScanError):
    """A discovered tool's definition drifted from its pin (rug pull)."""

    code = "discovery-definition-drift"


class DiscoveryDefinitionUnregistered(DiscoveryScanError):
    """A discovered tool has no pin (first sighting held fail-closed)."""

    code = "discovery-definition-unregistered"


class DiscoveryResultMalformed(DiscoveryScanError):
    """A discovery result or pin set is malformed (fail-closed)."""

    code = "discovery-result-malformed"


class DiscoveryEmitFailed(DiscoveryScanError):
    """An audit event (drift/re-pin) could not be emitted to the sink.

    F313: the drift event is chained into the HMAC log by the
    deployment's sink; a dead sink must never read as "no drift".
    Bounded retry, then LOUD fail-closed -- never silent.
    """

    code = "discovery-emit-failed"


def validate_scope(scope):
    """Fail LOUD on a scope outside the closed vocabulary."""
    if scope not in SCOPES:
        raise DiscoveryScopeUnknown(
            "discovery-scope-unknown: scope %r is outside the closed "
            "discovery vocabulary %r" % (scope, list(SCOPES)))
    return scope


def validate_component_type(component_type):
    """Fail LOUD on a component type outside the closed vocabulary."""
    if component_type not in COMPONENT_TYPES:
        raise DiscoveryResultMalformed(
            "component_type %r is outside the closed vocabulary %r"
            % (component_type, list(COMPONENT_TYPES)))
    return component_type


def definition_digest(defn):
    """Pin a tool definition: sha256 over the canonical
    name/description/schema triple.

    Delegates to ``tool_continuity.tool_definition_digest`` so pins
    from the deployment-controlled inventory and this
    discovery-driven registry are byte-for-byte comparable.
    """
    return _tc.tool_definition_digest(defn)


def _require_shape(component):
    """Validate one observation dict; return the normalized record.

    Malformed observations fail LOUD with the existing
    ``discovery-result-malformed`` code (composition, not a new
    code): a result the registry cannot parse must never read as
    clean.
    """
    if not isinstance(component, dict):
        raise DiscoveryResultMalformed(
            "observation must be a dict, got %r"
            % type(component).__name__)
    scope = validate_scope(component.get("scope"))
    ctype = validate_component_type(component.get("component_type"))
    agent_host = component.get("agent_host")
    source_path = component.get("source_path")
    component_id = component.get("component_id")
    for field, value in (("agent_host", agent_host),
                         ("source_path", source_path),
                         ("component_id", component_id)):
        if not isinstance(value, str) or not value:
            raise DiscoveryResultMalformed(
                "observation field %r must be a non-empty string"
                % (field,))
    definitions = component.get("definitions")
    if not isinstance(definitions, list):
        raise DiscoveryResultMalformed(
            "observation field 'definitions' must be a list")
    for d in definitions:
        if not isinstance(d, dict) or not d.get("name"):
            raise DiscoveryResultMalformed(
                "every definition needs a 'name'")
        # F314: observation sources are UNTRUSTED by design, and the
        # pin store joins key parts with "|". A name carrying the
        # separator (or any non-string/empty name) is rejected LOUD at
        # the trust boundary -- one hostile name must never be able
        # to brick RegistryStore.load() for every other pin.
        name = d.get("name")
        if not isinstance(name, str) or not name:
            raise DiscoveryResultMalformed(
                "definition name must be a non-empty string, got %r"
                % (type(name).__name__,))
        if "|" in name:
            raise DiscoveryResultMalformed(
                "definition name %r carries the pin-store separator "
                "'|': rejected at the observation trust boundary"
                % (name,))
    return {"scope": scope, "agent_host": agent_host,
            "component_type": ctype, "source_path": source_path,
            "component_id": component_id, "definitions": definitions}


def _validate_tool_key(tool_key):
    """Validate a 4-part discovery tool key at the trust boundary.

    F314: every part must be a non-empty string and none may carry
    the "|" pin-store separator. A hostile part refuses LOUD here
    instead of corrupting the store for every other pin.
    """
    if (not isinstance(tool_key, tuple) or len(tool_key) != 4
            or not all(isinstance(p, str) and p for p in tool_key)):
        raise DiscoveryResultMalformed(
            "tool key must be a 4-tuple of non-empty strings, got %r"
            % (tool_key,))
    for part in tool_key:
        if "|" in part:
            raise DiscoveryResultMalformed(
                "tool key part %r carries the pin-store separator '|': "
                "rejected at the trust boundary" % (part,))
    return tool_key


def discovery_key_for_tool(tool, tool_to_component=None,
                           mcp_server=None,
                           mcp_server_to_component=None):
    """Attribute a tool name to a discovery component.

    Deployment config, never inferred from tool names (the
    ``skill_watch.skill_id_for_tool`` precedent): ``tool_to_component``
    maps ``{tool_name: (scope, agent_host, component_id)}``; MCP
    servers attribute via ``mcp_server_to_component`` with the
    executor's ``mcp_server`` framing kwarg carrying the adapter's
    server identity. Returns the ``(scope, agent_host, component_id)``
    triple or None when unattributed (the policy's decision, exactly
    like the tool inventory's unknown-tool handling).
    """
    triple = None
    if tool_to_component and tool in tool_to_component:
        triple = tool_to_component[tool]
    elif (mcp_server is not None and mcp_server_to_component
            and mcp_server in mcp_server_to_component):
        triple = mcp_server_to_component[mcp_server]
    if triple is None:
        return None
    return (validate_scope(triple[0]), triple[1], triple[2])


# ---------------------------------------------------------------------------
# Discovery inventory: the four-scope coverage matrix.
# ---------------------------------------------------------------------------

class DiscoveryInventory(object):
    """Agent-discovery inventory over the four-scope matrix.

    Every discovered component is stored tagged ``{scope,
    agent_host, component_type, source_path}``; ``coverage_matrix()``
    returns the scope x component-type counts as the audit artifact
    (agent-scan's per-scope-per-agent detection tables, adapted).
    """

    def __init__(self):
        self._components = []

    def add(self, component):
        """Record one discovered component (validated, LOUD on bad)."""
        rec = _require_shape(component)
        self._components.append(rec)
        return rec

    def components(self, scope=None, component_type=None):
        """All records, optionally filtered by scope / component type."""
        out = self._components
        if scope is not None:
            validate_scope(scope)
            out = [c for c in out if c["scope"] == scope]
        if component_type is not None:
            validate_component_type(component_type)
            out = [c for c in out if c["component_type"] == component_type]
        return list(out)

    def coverage_matrix(self):
        """{scope: {component_type: count}} over the full 4x5 matrix."""
        matrix = {s: {t: 0 for t in COMPONENT_TYPES} for s in SCOPES}
        for c in self._components:
            matrix[c["scope"]][c["component_type"]] += 1
        return matrix


# ---------------------------------------------------------------------------
# Tool-definition registry: hash-pinned observations + scheduled re-scan.
# ---------------------------------------------------------------------------

def _tool_key(scope, agent_host, component_id, tool_name):
    return (scope, agent_host, component_id, tool_name)


class ToolDefinitionRegistry(object):
    """Hash-pinned registry of DISCOVERED tool definitions.

    The agent-scan rug-pull detector: every observation pins
    ``sha256(canonical(tool_definition))`` per
    ``(scope, agent_host, component_id, tool_name)``; the scheduled
    re-scan (``run_rescan``) re-hashes and diffs. Drift -- or a tool
    seen for the first time -- is a FAIL-CLOSED HOLD: the tool is
    held out of the grant graph (``held()`` / ``check_at_use()``
    refuse) until a governed re-pin (``request_repin`` +
    ``approve_repin`` bound to the fresh observation). There is no
    silent auto-update, ever.

    ``observe`` / ``observe_one`` are deployment-supplied callables
    (the sandbox boundary: they run inside the deployment's sandbox,
    never fetched by this registry). ``observe()`` returns an
    iterable of observation dicts (see ``_require_shape``);
    ``observe_one(tool_key)`` receives the FULL 4-part tool key
    ``(scope, agent_host, component_id, tool_name)`` (F315: the
    re-observation binds to the pinned identity, never the name
    alone) and returns one definition dict or None.
    """

    def __init__(self, emit=None):
        self._pins = {}
        self._quarantine = set()
        self._pending_repin = {}
        self._drift_events = []
        self._emit = emit
        # The agent-discovery inventory: every validated observation
        # feeds it, so the four-scope coverage matrix is a live audit
        # artifact of what the scans actually saw (not a dead schema).
        self._inventory = DiscoveryInventory()

    @property
    def inventory(self):
        """The live discovery inventory (fed by every re-scan)."""
        return self._inventory

    # -- plumbing ----------------------------------------------------

    def set_emit(self, emit):
        """Install the audit-event sink (the executor chains drift
        events into the HMAC log)."""
        self._emit = emit

    def _record_event(self, event):
        # The in-memory list is the local record (survives a dead
        # sink); the sink chains the event into the HMAC log. F313:
        # a dead sink is NEVER silent -- one bounded retry, then a
        # LOUD fail-closed refusal. Callers (check_at_use,
        # approve_repin) must let this propagate: drift with no audit
        # trail is a compromise-shaped gap, not a clean bill.
        self._drift_events.append(event)
        if self._emit is not None:
            for _ in range(2):
                try:
                    self._emit(event)
                except Exception:  # noqa: BLE001 - bounded retry, then loud
                    continue
                return
            raise DiscoveryEmitFailed(
                "discovery-emit-failed: audit sink refused the %r event "
                "after a retry; the event is in the in-memory drift list "
                "only and the registry refuses to proceed silently"
                % (event.get("event"),))

    @staticmethod
    def _digest_event(kind, key, before, after):
        # Digests only -- the definition text NEVER reaches the audit
        # log (redact-before-emit, agent-scan changelog 0.5.11).
        return {"event": kind, "scope": key[0], "agent_host": key[1],
                "component_id": key[2], "tool": key[3],
                "before_digest": before, "after_digest": after}

    # -- registration --------------------------------------------------

    def register_observation(self, component):
        """Pin every tool definition in one observation.

        Returns ``[(tool_key, digest)]``. Idempotent: re-pinning an
        unchanged definition keeps the pin and never quarantines.
        """
        rec = _require_shape(component)
        pinned = []
        for d in rec["definitions"]:
            key = _tool_key(rec["scope"], rec["agent_host"],
                            rec["component_id"], d["name"])
            digest = definition_digest(d)
            if key in self._pins and self._pins[key] != digest:
                # Registration-time divergence from an existing pin is
                # a drift, not a silent re-pin (the SkillJacking
                # precedent from skill_watch).
                self._drift(key, self._pins[key], digest)
            else:
                self._pins[key] = digest
            pinned.append((key, digest))
        return pinned

    def registered_tools(self):
        """All pinned tool keys."""
        return sorted(self._pins)

    def pins_snapshot(self):
        """A copy of the pin table (for persistence)."""
        return dict(self._pins)

    def quarantined_keys(self):
        """A copy of the quarantine set (for persistence)."""
        return set(self._quarantine)

    def _replace_state(self, pins, quarantine):
        """Bulk state install (RegistryStore.load only)."""
        self._pins = dict(pins)
        self._quarantine = set(quarantine)

    # -- the scheduled re-scan -----------------------------------------

    def run_rescan(self, observe):
        """The scheduled re-scan: re-hash every discovered tool and
        diff against pins.

        This tree has NO in-process scheduler (the skill_watch
        precedent): the DEPLOYMENT's scheduler/heartbeat calls this
        (recommended interval: 300s, the ``skill_watch`` sweep
        interval). Returns the report dict::

            {"checked": N, "clean": [...], "drifted": [...],
             "unregistered": [...], "withdrawn": [...], "held": [...],
             "coverage_matrix": {scope: {component_type: count}}}

        Drift -> quarantine (fail-closed hold) + ``definition_drift``
        event (digests only). First sighting -> ``unregistered``
        quarantine: never trusted silently (the guard-hook
        contract). A pinned tool absent from the scan is
        ``withdrawn`` (its pin stands; unobservable at use time, it
        fails closed there too).
        """
        clean, drifted, unregistered, withdrawn = [], [], [], []
        seen = set()
        try:
            components = list(observe())
        except Exception as e:  # noqa: BLE001 - fail closed, loud
            raise DiscoveryResultMalformed(
                "the re-scan observation failed: %s"
                % type(e).__name__)
        for component in components:
            rec = _require_shape(component)
            self._inventory.add(rec)  # the matrix sees every scan
            for d in rec["definitions"]:
                key = _tool_key(rec["scope"], rec["agent_host"],
                                rec["component_id"], d["name"])
                seen.add(key)
                digest = definition_digest(d)
                if key not in self._pins:
                    unregistered.append(key)
                    self._quarantine.add(key)
                    self._record_event(self._digest_event(
                        "definition_unregistered", key, None, digest))
                elif self._pins[key] != digest:
                    drifted.append(key)
                    self._drift(key, self._pins[key], digest)
                else:
                    clean.append(key)
        for key in sorted(self._pins):
            if key not in seen:
                withdrawn.append(key)
        report = {"checked": len(seen), "clean": sorted(clean),
                  "drifted": sorted(drifted),
                  "unregistered": sorted(unregistered),
                  "withdrawn": sorted(withdrawn),
                  "held": sorted(self._quarantine),
                  "coverage_matrix": self._inventory.coverage_matrix()}
        return report

    def _drift(self, key, before, after):
        # The pin is deliberately NOT updated to the drifted digest:
        # the drifted definition stays quarantined under the OLD pin
        # until a governed re-pin. No silent re-pin, ever.
        self._quarantine.add(key)
        self._record_event(self._digest_event(
            "definition_drift", key, before, after))

    # -- use-time / change-time check (the guard-hook half) --------------

    def held(self, tool_key):
        """Is this tool currently held out of the grant graph?"""
        return tool_key in self._quarantine

    def is_pinned(self, tool_key):
        """Does this tool have a definition pin (regardless of hold)?"""
        return tool_key in self._pins

    def scan_only_check(self, tool_key):
        """The verdict-path check for scheduled-scan-only mode (no
        change-time observer installed).

        The re-scan quarantine ALWAYS binds; an attributed tool with
        no pin is quarantined fail-closed (first sighting is never
        trusted silently -- the F143 precedent). Returns
        ``(ok, code, detail)``; ``ok=False`` means the executor must
        DENY fail-closed.
        """
        if tool_key in self._quarantine:
            code = ("discovery-definition-drift"
                    if tool_key in self._pins
                    else "discovery-definition-unregistered")
            return (False, code,
                    "tool %r is quarantined pending governed re-pin"
                    % (tool_key[3],))
        if tool_key not in self._pins:
            self._quarantine.add(tool_key)
            return (False, "discovery-definition-unregistered",
                    "tool %r has no definition pin (first sighting "
                    "held fail-closed)" % (tool_key[3],))
        return (True, "ok", "pinned; scheduled-scan mode")

    def merge_stored(self, stored):
        """Merge a persisted registry (post-restart bootstrap).

        Live pins win on overlap (a fresh observation beats a stale
        pin); stored pins fill keys the live registry never
        (re-)registered; quarantine is unioned (an unresolved drift
        hold survives the restart). The deployment reloads via
        ``RegistryStore.load()`` and calls this once at startup.
        """
        live = self._pins
        for key, digest in stored.pins_snapshot().items():
            if key not in live:
                live[key] = digest
        self._quarantine |= stored.quarantined_keys()

    def check_at_use(self, tool_key, observe_one):
        """Change-time diff on the governed call path.

        Re-observes the single tool's definition (agent-scan's guard
        hooks: diff at change time, not just at scan time) and
        compares against the pin. Returns ``(ok, code, detail)``;
        ``ok=False`` means the executor must DENY fail-closed.

        F315: ``observe_one`` receives the FULL 4-part ``tool_key``
        (scope, agent_host, component_id, tool_name), never the name
        alone -- the re-observation binds to the same identity the
        pin was taken under, so a same-name shadow cannot substitute
        a different component's definition. An observed definition
        whose ``name`` does not match the key's tool name refuses
        LOUD (identity mismatch).

        An unobservable tool (``observe_one`` returns None or raises)
        fails CLOSED (``discovery-result-malformed``): a watcher
        failure never reads as clean (the skill_watch precedent).
        """
        _validate_tool_key(tool_key)
        if tool_key in self._quarantine:
            code = ("discovery-definition-drift"
                    if tool_key in self._pins
                    else "discovery-definition-unregistered")
            return (False, code,
                    "tool %r is quarantined pending governed re-pin"
                    % (tool_key[3],))
        if tool_key not in self._pins:
            self._quarantine.add(tool_key)
            return (False, "discovery-definition-unregistered",
                    "tool %r has no definition pin (first sighting "
                    "held fail-closed)" % (tool_key[3],))
        try:
            current = observe_one(tool_key)
        except Exception as e:  # noqa: BLE001 - fail closed, loud
            current = None
            # Type name only: the observer's exception text could
            # carry definition content, which must never reach the
            # audit log (redact-before-emit).
            _obs_err = type(e).__name__
        else:
            _obs_err = None
        if not isinstance(current, dict) or not current.get("name"):
            self._quarantine.add(tool_key)
            return (False, "discovery-result-malformed",
                    "tool %r unobservable at use time%s; held "
                    "fail-closed" % (tool_key[3],
                                     (" (%s)" % _obs_err)
                                     if _obs_err else ""))
        if current.get("name") != tool_key[3]:
            # F315: the observer served a definition for a DIFFERENT
            # tool name than the pinned identity -- a same-name
            # shadow. Quarantine and refuse LOUD.
            self._quarantine.add(tool_key)
            return (False, "discovery-result-malformed",
                    "tool %r identity mismatch at use time: observed "
                    "definition names %r; held fail-closed"
                    % (tool_key[3], current.get("name")))
        digest = definition_digest(current)
        if digest != self._pins[tool_key]:
            self._quarantine.add(tool_key)
            self._record_event(self._digest_event(
                "definition_drift", tool_key,
                self._pins[tool_key], digest))
            return (False, "discovery-definition-drift",
                    "tool %r definition drifted at use time; "
                    "quarantined pending governed re-pin"
                    % (tool_key[3],))
        return (True, "ok", "definition matches pin")

    # -- governed re-pin --------------------------------------------------

    def request_repin(self, tool_key):
        """Open a governed re-pin request for a quarantined tool."""
        _validate_tool_key(tool_key)
        if tool_key not in self._quarantine:
            raise DiscoveryScanError(
                "discovery-result-malformed: re-pin requested for "
                "tool %r which is not quarantined" % (tool_key[3],))
        self._pending_repin[tool_key] = True
        return True

    def approve_repin(self, tool_key, new_digest, observe_one=None):
        """Approve a re-pin. The approval BINDS to the fresh
        observation: ``new_digest`` must equal the digest of what
        ``observe_one`` serves RIGHT NOW (the skill_watch
        bait-and-switch protection). A mismatch refuses and the hold
        stands. On success the pin updates and the hold lifts.

        F315: ``observe_one`` receives the FULL 4-part ``tool_key``,
        and the fresh observation's ``name`` must match the key's
        tool name -- a same-name shadow serving a different
        component's definition refuses LOUD (identity mismatch).

        In scheduled-scan-only deployments (no executor-level
        ``discovery_observe_one``) the operator supplies a one-shot
        ``observe_one`` here: the re-pin still binds to a fresh
        observation, so ``observe_one=None`` always refuses -- the
        bait-and-switch protection is never waived.
        """
        _validate_tool_key(tool_key)
        if tool_key not in self._pending_repin:
            raise DiscoveryScanError(
                "discovery-result-malformed: no pending re-pin "
                "request for tool %r" % (tool_key[3],))
        if not (isinstance(new_digest, str) and len(new_digest) == 64):
            raise DiscoveryScanError(
                "discovery-result-malformed: new_digest must be a "
                "64-hex sha256")
        fresh = None
        if observe_one is not None:
            try:
                fresh = observe_one(tool_key)
            except Exception:  # noqa: BLE001 - unobservable: refuse
                fresh = None
        if (not isinstance(fresh, dict) or not fresh.get("name")
                or fresh.get("name") != tool_key[3]
                or definition_digest(fresh) != new_digest):
            raise DiscoveryScanError(
                "discovery-result-malformed: re-pin for tool %r "
                "refused: new_digest does not match the freshly "
                "observed definition for the pinned identity "
                "(bait-and-switch protection)" % (tool_key[3],))
        self._pins[tool_key] = new_digest
        self._quarantine.discard(tool_key)
        del self._pending_repin[tool_key]
        self._record_event(self._digest_event(
            "definition_repinned", tool_key,
            None, new_digest))
        return True

    @property
    def drift_events(self):
        """Drift/unregistered/re-pin events (digests only)."""
        return list(self._drift_events)


# ---------------------------------------------------------------------------
# Persistent pin store (atomic JSON; loud on corruption).
# ---------------------------------------------------------------------------

class RegistryStoreError(RuntimeError):
    """The pin store exists but cannot be trusted (fail LOUD)."""


class RegistryStore(object):
    """Atomic JSON persistence for the definition registry.

    The skill_watch PinStore precedent: pins are NEVER silently
    forgotten -- a pin file that exists but cannot be parsed fails
    LOUD, and a deployment must not start a pinning deployment over a
    corrupt pin file.
    """

    def __init__(self, path):
        self.path = path

    def save(self, registry):
        """Atomically persist pins + quarantine set.

        Pending re-pin requests are deliberately NOT persisted: a
        human approval must not survive a restart (the operator
        re-opens it against a fresh observation).
        """
        payload = {"version": REGISTRY_STORE_VERSION,
                   "pins": {"|".join(k): v
                            for k, v in registry.pins_snapshot().items()},
                   "quarantine": ["|".join(k)
                                  for k in registry.quarantined_keys()]}
        blob = json.dumps(payload, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        fd, tmp = tempfile.mkstemp(prefix=".discovery-pins-",
                                   dir=os.path.dirname(
                                       os.path.abspath(self.path)))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self):
        """Load a registry; fail LOUD on a corrupt pin file."""
        try:
            with open(self.path, "rb") as fh:
                payload = json.loads(fh.read().decode("utf-8"))
        except (OSError, ValueError) as e:
            raise RegistryStoreError(
                "discovery pin store %r unreadable: %s: %s -- refusing "
                "to start a pinning deployment over a corrupt pin "
                "file" % (self.path, type(e).__name__, e))
        if payload.get("version") != REGISTRY_STORE_VERSION:
            raise RegistryStoreError(
                "discovery pin store %r version %r != %r"
                % (self.path, payload.get("version"),
                   REGISTRY_STORE_VERSION))
        # A parseable file with no pin table is a silent-forget
        # hazard: the deployment would restart believing nothing is
        # pinned. Fail LOUD (the std-7 never-silently-forget rule).
        raw_pins = payload.get("pins")
        if not isinstance(raw_pins, dict):
            raise RegistryStoreError(
                "discovery pin store %r has no pin table"
                % (self.path,))
        registry = ToolDefinitionRegistry()
        pins = {}
        for k, v in raw_pins.items():
            parts = k.split("|")
            if len(parts) != 4 or not (
                    isinstance(v, str) and len(v) == 64):
                raise RegistryStoreError(
                    "discovery pin store %r has a malformed pin entry"
                    % (self.path,))
            pins[tuple(parts)] = v
        quarantine = set()
        for k in payload.get("quarantine", []):
            parts = k.split("|")
            if len(parts) != 4:
                raise RegistryStoreError(
                    "discovery pin store %r has a malformed quarantine "
                    "entry" % (self.path,))
            quarantine.add(tuple(parts))
        registry._replace_state(pins, quarantine)
        return registry
