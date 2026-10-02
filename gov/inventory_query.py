"""osquery-pattern virtual inventory tables + committed query packs.

Pattern lineage: ``osquery/osquery`` (canonical repo; moved from
``facebook/osquery``). Dual license **Apache-2.0 OR GPL-2.0-only** -- this
tree elects **Apache-2.0**. Pattern only: no osquery code is vendored or
ported. Three stolen pieces:

1. **Versioned virtual tables** -- the discovery inventory (wave-282
   ``gov.discovery_scan``) exposed as named tables ``agents``,
   ``agent_tools``, ``mcp_servers``, ``skill_bundles``, each pinned at a
   schema version. Every row carries a content digest (``row_digest``) so
   the table is a tamper-evident inventory, not a dead schema.
2. **The extension-table API as the provider plug-in contract** -- extra
   tables register through a closed provider API (``table_names`` /
   ``fetch`` / optional ``identity_columns``), like osquery's Thrift
   extension tables. Providers crash loud, declare a pinned schema
   version, and cannot rename core tables.
3. **Query packs as scheduled drift=fail-closed audits** -- named,
   committed query packs (structured table + where + columns) whose
   pinned row digests are the admission pins. The deployment's
   scheduler runs them (this tree has no in-process scheduler -- the
   skill_watch/discovery_scan precedent); a pack whose rows drift from
   the pin holds the rows fail-closed (``inventory-pack-drift`` /
   ``inventory-unregistered``), exactly the drift=hold semantics of the
   wave-282 discovery registry.

Stdlib only. No network calls, no tokens. $0.
"""

import hashlib
import json

# ---------------------------------------------------------------------------
# Errors.
# ---------------------------------------------------------------------------


class InventoryError(Exception):
    """Base class for every inventory-query failure.

    All failures are LOUD: there is no silent empty result, no swallowed
    provider crash, no unpinned pack run.
    """


class InventoryPackUnpinned(InventoryError):
    """A query pack with an unpinned query was asked to run.

    Committed packs are pinned data; an unpinned pack refuses rather
    than establishing a new baseline silently.
    """


# ---------------------------------------------------------------------------
# Schema: versioned virtual tables.
# ---------------------------------------------------------------------------

#: The core virtual tables (osquery's built-in tables, adapted).
CORE_TABLES = ("agents", "agent_tools", "mcp_servers", "skill_bundles")

#: The single pinned schema version, tree-wide. Every core table and
#: every registered extension table is pinned at this version; anything
#: else refuses with ``inventory-schema-mismatch``.
PINNED_SCHEMA_VERSION = 1

_TABLE_VERSIONS = {t: PINNED_SCHEMA_VERSION for t in CORE_TABLES}

#: Identity columns per core table: the stable key a pack pin binds to.
_TABLE_IDENTITY = {
    "agents": ("agent_id",),
    "agent_tools": ("agent_host", "tool_name"),
    "mcp_servers": ("component_id", "name"),
    "skill_bundles": ("component_id", "bundle_name"),
}

#: Declared columns per core table (schema version 1). Rows may carry
#: any subset of these; anything else is a malformed row.
_TABLE_COLUMNS = {
    "agents": ("agent_id", "name", "trust_tier"),
    "agent_tools": ("agent_host", "scope", "tool_name",
                    "definition_digest"),
    "mcp_servers": ("scope", "agent_host", "component_id", "name",
                    "definition_digest"),
    "skill_bundles": ("scope", "agent_host", "component_id",
                      "bundle_name", "content_digest"),
}

_ROW_DIGEST_KEY = "row_digest"


def table_schema_version(table_name):
    """The pinned schema version for a table.

    Refuses ``inventory-schema-mismatch`` on unknown tables.
    """
    try:
        return _TABLE_VERSIONS[table_name]
    except KeyError:
        raise InventoryError(
            "inventory-schema-mismatch: unknown table %r" % (table_name,))


# ---------------------------------------------------------------------------
# Row digests: the tamper-evident binding.
# ---------------------------------------------------------------------------

def _canon(value, path):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise InventoryError(
                    "inventory-row-malformed: non-string key at %s"
                    % (path,))
            out[k] = _canon(v, path + "." + k)
        return out
    if isinstance(value, (list, tuple)):
        return [_canon(v, path + "[]") for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise InventoryError(
        "inventory-row-malformed: non-JSON value at %s (%s)"
        % (path, type(value).__name__))


def row_digest(row):
    """sha256 over the canonical row, binding every column.

    A pre-seeded ``row_digest`` key is never trusted: it is stripped
    and recomputed. Malformed rows refuse ``inventory-row-malformed``.
    """
    if not isinstance(row, dict):
        raise InventoryError(
            "inventory-row-malformed: row is %s, not a dict"
            % (type(row).__name__,))
    body = {k: _canon(v, k) for k, v in row.items()
            if k != _ROW_DIGEST_KEY}
    for k in body:
        if not isinstance(k, str):
            raise InventoryError(
                "inventory-row-malformed: non-string key %r" % (k,))
    return hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _validate_core_row(table_name, row):
    declared = _TABLE_COLUMNS[table_name]
    for key in row:
        if key == _ROW_DIGEST_KEY:
            continue
        if key not in declared:
            raise InventoryError(
                "inventory-row-malformed: table %r has no column %r "
                "(schema v%d)" % (table_name, key, PINNED_SCHEMA_VERSION))
    for col in _TABLE_IDENTITY[table_name]:
        if col not in row:
            raise InventoryError(
                "inventory-row-malformed: table %r row missing identity "
                "column %r" % (table_name, col))
    # row_digest raises on any non-JSON value.
    row_digest(row)


# ---------------------------------------------------------------------------
# The query registry: tables + extension providers + query packs.
# ---------------------------------------------------------------------------

def _safe_table_names(provider, table_name):
    """Call ``provider.table_names()`` behind the closed API.

    A crash is LOUD (``inventory-provider-failed``); a non-list
    return is a contract violation (``inventory-schema-mismatch``).
    """
    try:
        names = provider.table_names()
    except Exception as e:  # noqa: BLE001 - closed API: crash is loud
        raise InventoryError(
            "inventory-provider-failed: %r.table_names() raised %s"
            % (table_name, type(e).__name__))
    if not isinstance(names, list):
        raise InventoryError(
            "inventory-schema-mismatch: provider for %r returned a bad "
            "table list %r" % (table_name, names))
    return names


class _ProviderShim(object):
    """Wraps a registered extension provider behind the closed API."""

    def __init__(self, table_name, schema_version, provider):
        self.table_name = table_name
        self.schema_version = schema_version
        self.provider = provider

    def identity_columns(self):
        fn = getattr(self.provider, "identity_columns", None)
        if fn is None:
            return None
        cols = fn(self.table_name)
        if not cols or not all(isinstance(c, str) for c in cols):
            raise InventoryError(
                "inventory-schema-mismatch: provider %r returned bad "
                "identity columns" % (self.table_name,))
        return tuple(cols)

    def fetch_rows(self):
        names = _safe_table_names(self.provider, self.table_name)
        if self.table_name not in names:
            raise InventoryError(
                "inventory-schema-mismatch: provider does not serve "
                "its registered table %r" % (self.table_name,))
        try:
            rows = self.provider.fetch(self.table_name)
        except Exception as e:  # noqa: BLE001 - closed API: crash is loud
            raise InventoryError(
                "inventory-provider-failed: %r.fetch() raised %s"
                % (self.table_name, type(e).__name__))
        if not isinstance(rows, list):
            raise InventoryError(
                "inventory-provider-failed: %r.fetch() did not return "
                "a list" % (self.table_name,))
        return rows


_MISSING = object()


class QueryRegistry(object):
    """Versioned virtual tables, extension providers, query packs.

    Tables are populated by ``register_table_rows`` (deployment data),
    ``register_core_tables_from_discovery`` (the wave-282 inventory
    projection), or ``register_extension`` (the osquery extension-table
    plug-in contract). Queries run through ``run_query``; committed
    packs run through ``run_query_pack`` with drift=fail-closed holds.
    """

    def __init__(self):
        # table_name -> {identity_key: (row, digest)}
        self._tables = {}
        # table_name -> provider shim (extension tables only)
        self._providers = {}
        # held (table_name, hold_key) -> machine code that put it on hold
        self._held = {}
        # (table_name, hold_key) -> identity (for persistence snapshots)
        self._held_identity = {}
        # audit-event sink (set_emit); the deployment chains hold
        # events into the HMAC log, like the discovery registry.
        self._emit = None

    # -- audit plumbing (the wave-282 discovery-registry precedent) --

    def set_emit(self, emit):
        """Install the audit-event sink for hold placements.

        The deployment chains these events into the HMAC audit log.
        The sink must never break a pack run.
        """
        self._emit = emit

    def _record_hold_event(self, event):
        if self._emit is None:
            return
        try:
            self._emit(event)
        except Exception:  # noqa: BLE001 - emit must never break a run
            pass

    @staticmethod
    def _hold_event(code, table, identity, before, after):
        # Digests only -- row content NEVER reaches the audit log
        # (redact-before-emit, the discovery-registry precedent).
        return {"event": code, "table": table, "identity": identity,
                "before_digest": before, "after_digest": after}

    def _place_hold(self, table, hold_key, identity, code, before,
                    after):
        """Record a pack-audit hold and emit the audit event."""
        self._held[hold_key] = code
        self._held_identity[hold_key] = identity
        self._record_hold_event(
            self._hold_event(code, table, identity, before, after))

    def holds_snapshot(self):
        """A JSON-serializable copy of the hold set (for persistence)."""
        return {"held": [
            {"table": table, "identity": self._held_identity[(table, key)],
             "code": code}
            for (table, key), code in sorted(self._held.items())]}

    def merge_snapshot(self, data):
        """Merge a persisted hold set (post-restart bootstrap).

        Unresolved holds are unioned: a drift/unregistered hold
        survives the restart. Malformed snapshots refuse
        ``inventory-row-malformed`` -- a corrupt hold store never
        silently widens trust.
        """
        if not isinstance(data, dict) or not isinstance(
                data.get("held"), list):
            raise InventoryError(
                "inventory-row-malformed: bad holds snapshot")
        for entry in data["held"]:
            if (not isinstance(entry, dict)
                    or not isinstance(entry.get("table"), str)
                    or not entry["table"]
                    or entry.get("code") not in (
                        "inventory-pack-drift", "inventory-unregistered")):
                raise InventoryError(
                    "inventory-row-malformed: bad hold entry %r"
                    % (entry,))
            try:
                json.dumps(entry["identity"])
            except (TypeError, ValueError):
                raise InventoryError(
                    "inventory-row-malformed: hold identity not JSON "
                    "%r" % (entry,))
            table = entry["table"]
            if table not in CORE_TABLES and table not in self._providers:
                raise InventoryError(
                    "inventory-schema-mismatch: snapshot names unknown "
                    "table %r" % (table,))
            hold_key = self._hold_key(table, entry["identity"])
            self._held[hold_key] = entry["code"]
            self._held_identity[hold_key] = entry["identity"]

    # -- table population -------------------------------------------

    def _known(self, table_name):
        return (table_name in CORE_TABLES
                or table_name in self._providers)

    def _identity_columns(self, table_name):
        if table_name in _TABLE_IDENTITY:
            return _TABLE_IDENTITY[table_name]
        cols = self._providers[table_name].identity_columns()
        if cols is not None:
            return cols
        # Extension tables without declared identity: every column
        # except the digest key, sorted (stable, provider-declared).
        return None

    def _identity_of(self, table_name, row):
        cols = self._identity_columns(table_name)
        if cols is None:
            cols = tuple(sorted(k for k in row if k != _ROW_DIGEST_KEY))
        try:
            return {c: row[c] for c in cols}
        except KeyError as e:
            raise InventoryError(
                "inventory-row-malformed: row missing identity "
                "column %r" % (e.args[0],))

    @staticmethod
    def _identity_key(identity):
        return json.dumps(identity, sort_keys=True, separators=(",", ":"))

    def hold_key(self, table_name, identity):
        """Build the opaque hold key for ``(table, identity)``.

        ``held()`` / ``check_use()`` / ``release_hold()`` take this
        key; callers never construct it by hand. ``identity`` is the
        identity dict (e.g. ``{"agent_id": "a1"}``).
        """
        return self._hold_key(table_name, identity)

    @staticmethod
    def _hold_key(table_name, identity):
        vals = list(identity.values())
        if len(vals) == 1 and isinstance(vals[0], str):
            return (table_name, vals[0])
        return (table_name, QueryRegistry._identity_key(identity))

    def registered_schema_version(self, table_name):
        """Schema version for any registered table (core or extension).

        Core tables report the pinned version; extension tables report
        the version their provider declared at registration (which the
        closed API forced to equal the pin). Unknown tables refuse
        ``inventory-schema-mismatch``.
        """
        if table_name in CORE_TABLES:
            return table_schema_version(table_name)
        shim = self._providers.get(table_name)
        if shim is None:
            raise InventoryError(
                "inventory-schema-mismatch: unknown table %r"
                % (table_name,))
        return shim.schema_version

    def register_table_rows(self, table_name, rows):
        """Set a table's rows to exactly ``rows`` (validated, digest-bound).

        Snapshot semantics: each scheduled scan re-registers the FULL
        current observation set, so a pinned identity absent from the
        new set reads as ``withdrawn`` rather than lingering forever.
        """
        if table_name not in CORE_TABLES and table_name not in self._providers:
            raise InventoryError(
                "inventory-schema-mismatch: cannot seed unknown table "
                "%r" % (table_name,))
        if not isinstance(rows, list):
            raise InventoryError(
                "inventory-row-malformed: rows must be a list")
        digests = []
        fresh = {}
        for row in rows:
            if table_name in CORE_TABLES:
                _validate_core_row(table_name, row)
            digest = row_digest(row)
            identity = self._identity_of(table_name, row)
            fresh[self._identity_key(identity)] = (dict(row), digest,
                                                   identity)
            digests.append(digest)
        self._tables[table_name] = fresh
        return digests

    def register_extension(self, table_name, schema_version, provider):
        """Register an extension table (the osquery plug-in contract).

        The provider must expose the closed API ``table_names()`` and
        ``fetch(table_name)`` (plus optional ``identity_columns``).
        The schema version must equal the pinned version; providers
        cannot shadow core tables. Anything else refuses LOUD.
        """
        if not isinstance(schema_version, int) or isinstance(
                schema_version, bool):
            raise InventoryError(
                "inventory-schema-mismatch: schema version must be an "
                "int, got %r" % (schema_version,))
        if schema_version != PINNED_SCHEMA_VERSION:
            raise InventoryError(
                "inventory-schema-mismatch: table %r declares schema "
                "v%s, pinned v%s" % (table_name, schema_version,
                                     PINNED_SCHEMA_VERSION))
        if table_name in CORE_TABLES:
            raise InventoryError(
                "inventory-schema-mismatch: extension cannot shadow "
                "core table %r" % (table_name,))
        if table_name in self._providers:
            raise InventoryError(
                "inventory-schema-mismatch: extension table %r already "
                "registered" % (table_name,))
        if (not hasattr(provider, "table_names")
                or not hasattr(provider, "fetch")):
            raise InventoryError(
                "inventory-schema-mismatch: provider for %r lacks the "
                "closed API (table_names/fetch)" % (table_name,))
        if not isinstance(table_name, str) or not table_name:
            raise InventoryError(
                "inventory-schema-mismatch: bad table name %r"
                % (table_name,))
        offered = _safe_table_names(provider, table_name)
        if (not all(isinstance(t, str) and t for t in offered)
                or table_name not in offered):
            raise InventoryError(
                "inventory-schema-mismatch: provider for %r offered a bad "
                "table list %r" % (table_name, offered))
        self._providers[table_name] = _ProviderShim(
            table_name, schema_version, provider)

    def register_core_tables_from_discovery(self, inventory):
        """Populate the core tables from a discovery inventory.

        The wave-282 ``DiscoveryInventory`` projection: every validated
        component becomes digest-bound virtual-table rows (composition,
        not duplication -- digests reuse the discovery digest seam).
        Snapshot semantics, like ``register_table_rows``: each table is
        set to exactly the projected rows.
        """
        by_table = {}
        for table_name, row in inventory_tables_from_discovery(inventory):
            _validate_core_row(table_name, row)
            by_table.setdefault(table_name, []).append(row)
        for table_name, rows in by_table.items():
            self.register_table_rows(table_name, rows)

    def _extension_rows(self, table_name):
        shim = self._providers[table_name]
        rows = shim.fetch_rows()
        out = {}
        for row in rows:
            digest = row_digest(row)  # malformed -> InventoryError
            identity = self._identity_of(table_name, row)
            out[self._identity_key(identity)] = (dict(row), digest,
                                                 identity)
        return out

    def _snapshot(self, table_name):
        if table_name not in CORE_TABLES and table_name not in self._providers:
            raise InventoryError(
                "inventory-schema-mismatch: unknown table %r"
                % (table_name,))
        if table_name in self._providers:
            return self._extension_rows(table_name)
        return dict(self._tables.get(table_name, {}))

    # -- queries ----------------------------------------------------

    @staticmethod
    def _match(row, where):
        for col, cond in where.items():
            val = row.get(col, _MISSING)
            if isinstance(cond, dict):
                if set(cond) == {"in"}:
                    if val not in cond["in"]:
                        return False
                elif set(cond) == {"prefix"}:
                    if not (isinstance(val, str)
                            and val.startswith(cond["prefix"])):
                        return False
                else:
                    raise InventoryError(
                        "inventory-schema-mismatch: bad where clause "
                        "%r" % (cond,))
            elif val is _MISSING or val != cond:
                return False
        return True

    def run_query(self, query):
        """Run one structured query over a virtual table.

        ``{"table": ..., "where": {col: value | {"in": [...]} |
        {"prefix": ...}}, "columns": [...]}``. Rows are returned sorted
        by ``row_digest`` (deterministic); every row carries
        ``row_digest``. Unknown tables, unknown columns, and provider
        crashes refuse ``inventory-schema-mismatch`` (or
        ``inventory-provider-failed``) LOUD.
        """
        if not isinstance(query, dict):
            raise InventoryError(
                "inventory-schema-mismatch: query must be a dict")
        table_name = query.get("table")
        where = query.get("where", {}) or {}
        columns = query.get("columns", []) or []
        if table_name in _TABLE_COLUMNS:
            declared = _TABLE_COLUMNS[table_name]
            for col in list(where) + list(columns):
                if col not in declared:
                    raise InventoryError(
                        "inventory-schema-mismatch: table %r has no "
                        "column %r (schema v%d)"
                        % (table_name, col, PINNED_SCHEMA_VERSION))
        out = []
        for _ikey, (row, digest, _identity) in self._run_query_full(
                query).items():
            rec = {c: row[c] for c in columns if c in row}
            rec[_ROW_DIGEST_KEY] = digest
            out.append(rec)
        out.sort(key=lambda r: r[_ROW_DIGEST_KEY])
        return out

    # -- query packs: scheduled drift=fail-closed audits --------------

    def pin_query_pack(self, pack):
        """Pin a query pack against current results.

        Returns a NEW pack dict with each query's ``pinned`` list
        filled: ``[{"identity": {...}, "digest": ...}]`` sorted by
        digest. The committed pack is data; this is the pinning step
        the deployment runs once, audited like any pin.
        """
        if not isinstance(pack, dict) or "queries" not in pack:
            raise InventoryPackUnpinned(
                "inventory-pack-unpinned: pack must carry 'queries'")
        queries = []
        for q in pack["queries"]:
            rows = self._run_query_full(q)
            pinned = [{"identity": ident, "digest": dg}
                      for (_ikey, (_row, dg, ident)) in sorted(
                          rows.items(), key=lambda kv: kv[1][1])]
            nq = dict(q)
            nq["pinned"] = pinned
            queries.append(nq)
        return {"pack_name": pack.get("pack_name", "unnamed"),
                "queries": queries}

    def _run_query_full(self, query):
        table_name = query.get("table")
        where = query.get("where", {}) or {}
        snapshot = self._snapshot(table_name)
        out = {}
        for ikey, (row, digest, identity) in snapshot.items():
            if self._match(row, where):
                out[ikey] = (row, digest, identity)
        return out

    def run_query_pack(self, pack):
        """Run a committed (pinned) query pack: the scheduled audit.

        A query without a ``pinned`` list refuses
        ``InventoryPackUnpinned`` LOUD -- packs never establish a new
        baseline silently. Deltas classify per query:

        - ``drifted``: pinned identity, new digest -> the row is HELD
          (``inventory-pack-drift``).
        - ``unregistered``: new identity -> HELD
          (``inventory-unregistered``; first sighting is never
          trusted silently).
        - ``withdrawn``: pinned identity absent from the scan (pin
          stands; reported, not auto-dropped).
        - ``released``: a held row that reads clean against the pin
          again -- the scheduled re-scan lifts the pack-audit hold
          (governed re-admission without a clean re-scan still goes
          through ``release_hold``).

        Hold placements emit digests-only audit events via the
        ``set_emit`` sink (never row content).

        Returns the report dict; ``report["held"]`` is the sorted hold
        set. Deterministic: every list is sorted.
        """
        if not isinstance(pack, dict) or not isinstance(
                pack.get("queries"), list):
            raise InventoryPackUnpinned(
                "inventory-pack-unpinned: pack must carry a 'queries' "
                "list")
        qreps = []
        for q in pack["queries"]:
            pinned = q.get("pinned")
            if not isinstance(pinned, list):
                raise InventoryPackUnpinned(
                    "inventory-pack-unpinned: query %r has no pinned "
                    "list -- packs are committed pinned data"
                    % (q.get("name"),))
            by_ident = {self._identity_key(p["identity"]): p["digest"]
                        for p in pinned}
            seen = self._run_query_full(q)
            drifted, unregistered, withdrawn, released = [], [], [], []
            for ikey, (_row, digest, identity) in seen.items():
                hold_key = self._hold_key(q["table"], identity)
                if ikey not in by_ident:
                    unregistered.append(identity)
                    self._place_hold(q["table"], hold_key, identity,
                                     "inventory-unregistered", None, digest)
                elif by_ident[ikey] != digest:
                    drifted.append({"identity": identity,
                                    "before_digest": by_ident[ikey],
                                    "after_digest": digest})
                    self._place_hold(q["table"], hold_key, identity,
                                     "inventory-pack-drift",
                                     by_ident[ikey], digest)
                elif hold_key in self._held:
                    # Clean against the pin again: the scheduled re-scan
                    # shows the row back at its pinned content, so the
                    # pack-audit hold lifts (the discovery-registry
                    # precedent: "on success the pin updates and the
                    # hold lifts"). Governed re-admission without a
                    # clean re-scan still goes through release_hold.
                    released.append(identity)
                    del self._held[hold_key]
                    self._held_identity.pop(hold_key, None)
            for ikey, pin in ((k, v) for k, v in
                              ((self._identity_key(p["identity"]), p)
                               for p in pinned)):
                if ikey not in seen:
                    withdrawn.append(pin["identity"])
            qreps.append({
                "name": q.get("name", "?"),
                "checked": len(seen),
                "clean": len(seen) - len(drifted) - len(unregistered),
                "drifted": sorted(drifted,
                                  key=lambda d: self._identity_key(
                                      d["identity"])),
                "unregistered": sorted(
                    unregistered, key=self._identity_key),
                "withdrawn": sorted(withdrawn, key=self._identity_key),
                "released": sorted(released, key=self._identity_key),
            })
            for ikey, pin in ((k, v) for k, v in
                              ((self._identity_key(p["identity"]), p)
                               for p in pinned)):
                if ikey not in seen:
                    withdrawn.append(pin["identity"])
            qreps.append({
                "name": q.get("name", "?"),
                "checked": len(seen),
                "clean": len(seen) - len(drifted) - len(unregistered),
                "drifted": sorted(drifted,
                                  key=lambda d: self._identity_key(
                                      d["identity"])),
                "unregistered": sorted(
                    unregistered, key=self._identity_key),
                "withdrawn": sorted(withdrawn, key=self._identity_key),
            })
        return {"pack_name": pack.get("pack_name", "unnamed"),
                "queries": qreps,
                "held": sorted(self._held)}

    # -- use-time hold checks ----------------------------------------

    def held(self, key):
        """Is this hold key currently held fail-closed?

        ``key`` comes from ``hold_key(table_name, identity)``.
        """
        return key in self._held

    def check_use(self, key):
        """The verdict-path check for a held row.

        Returns ``(ok, code, detail)``; ``ok=False`` means the caller
        must DENY fail-closed. Held rows refuse with the machine code
        that put them on hold.
        """
        if key not in self._held:
            return (True, "ok", "row not held")
        return (False, self._held[key],
                "row %r held by the inventory query pack audit" % (key,))

    def release_hold(self, key):
        """Govern re-admission hook (deployment-governed, like re-pin).

        Clears the hold; the deployment records the governance event.
        """
        self._held.pop(key, None)
        self._held_identity.pop(key, None)


# ---------------------------------------------------------------------------
# Discovery composition: the wave-282 inventory as virtual tables.
# ---------------------------------------------------------------------------

def inventory_tables_from_discovery(inventory):
    """Project a ``DiscoveryInventory`` into virtual-table rows.

    Returns ``[(table_name, row), ...]`` covering the ``agents``,
    ``agent_tools``, ``mcp_servers``, and ``skill_bundles`` tables.
    Digests reuse the discovery digest seam
    (``discovery_scan.definition_digest``) byte-for-byte -- there is
    exactly one digest implementation for tool definitions.
    """
    from gov import discovery_scan as DS
    out = []
    seen_hosts = set()
    for comp in inventory.components():
        host = comp.get("agent_host")
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            # The agents virtual table: every agent_host the inventory
            # has observations for. (The discovery plane keys
            # observations by agent_host, so that IS the agent
            # identity here.)
            out.append(("agents", {"agent_id": host}))
        ctype = comp["component_type"]
        for d in comp.get("definitions", []):
            digest = DS.definition_digest(d)
            if ctype == "mcp_server":
                out.append(("mcp_servers", {
                    "scope": comp["scope"],
                    "agent_host": comp["agent_host"],
                    "component_id": comp["source_path"],
                    "name": d["name"],
                    "definition_digest": digest,
                }))
            elif ctype == "skill":
                out.append(("skill_bundles", {
                    "scope": comp["scope"],
                    "agent_host": comp["agent_host"],
                    "component_id": comp["source_path"],
                    "bundle_name": d.get("name") or comp["source_path"],
                    "content_digest": digest,
                }))
            elif ctype == "tool":
                out.append(("agent_tools", {
                    "agent_host": comp["agent_host"],
                    "scope": comp["scope"],
                    "tool_name": d["name"],
                    "definition_digest": digest,
                }))
    return out
