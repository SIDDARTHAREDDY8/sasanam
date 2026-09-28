"""Differential scheduled host queries (osquery pattern, reimplemented).

osquery runs scheduled-query packs of ``{query, interval, removed: true}``
and emits added/removed rows between runs. This module reimplements the
PATTERN in stdlib — no osquery code, no osquery binary, no linking.
(License note: osquery is Apache-2.0 OR GPL-2.0-only; we elect the
pattern only, derived from documentation. Re-verify the dual-license
text before redistributing any osquery binary — we do not.)

Tables use the osquery vocabulary so host facts, pin records, and
AuthorityProof boundaries speak one language:
``processes`` (pid, name, cmdline, exe), ``listening_ports`` (proto,
port, pids), ``apps`` (name, version).

DESIGN (invention-from-old: census, not surveillance):
* **Differentials, not snapshots.** The first poll per query is a
  silent baseline (osquery semantics); every later poll reports only
  what changed. An unchanged host is a quiet host.
* **Inventory-keyed unknown agents.** An *added* process whose exe or
  name is not in the deployment's governed inventory becomes an
  ``unknown_agent`` finding. This closes the gap in
  ``gov.discovery.scan_process_list``, which only signals on processes
  matching KNOWN harness regexes and silently drops a novel agent
  binary (F197). With no inventory wired the module is loud, not
  silent — every addition is a finding, mirroring discovery.py's
  no-registry behavior.
* **Fail-closed.** A collector raising keeps the previous snapshot:
  a failed poll never synthesizes removals and never shrinks state.
  Errors are recorded on the result, never swallowed.
* **Injectable in tests.** All diff logic is pure over injected
  ``{key: record}`` dicts. The live ``/proc`` / ``importlib.metadata``
  collectors are opt-in; tests never touch the live host.
* **Cheap by construction.** Per-query intervals gate re-collection;
  ``poll_loop`` sleeps between polls — no busy wait.

$0 spend, stdlib only, no network.
"""

import os
import time

#: Finding kind for added processes absent from the governed inventory.
UNKNOWN_AGENT_KIND = "unknown_agent"

#: Lifecycle event kind for removed rows.
LIFECYCLE_KIND = "lifecycle"


class DifferentialQuery:
    """One scheduled query: ``{name, interval, removed, unknown_agents}``.

    ``collector`` is a zero-arg callable returning ``{key: record}``.
    ``key`` is the row identity (pid for processes, (proto, port) for
    listening ports, name for apps). ``interval`` is seconds between
    re-collections. ``removed`` mirrors osquery's ``removed: true``:
    when false, removed rows are neither reported nor turned into
    lifecycle events. ``unknown_agents`` enables the inventory check
    on added rows (meaningful for the processes table).
    """

    def __init__(self, name, collector, *, interval=60, removed=True,
                 unknown_agents=False):
        self.name = name
        self.collector = collector
        self.interval = interval
        self.removed = removed
        self.unknown_agents = unknown_agents


class DifferentialResult:
    """One poll's outcome. All lists; empty means quiet."""

    def __init__(self):
        self.added = {}            # query name -> [records]
        self.removed = {}          # query name -> [records]
        self.errors = []           # [{"query": name, "error": str}]
        self.unknown_agents = []   # [finding dicts]
        self.lifecycle_events = []  # [event dicts]


class HostDiffer:
    """Runs a pack of :class:`DifferentialQuery` on a schedule.

    ``inventory`` is the deployment's governed-agent identifiers
    (exe paths and/or process names). ``clock`` is injectable for
    deterministic tests (defaults to ``time.time``).
    """

    def __init__(self, queries, *, inventory=(), clock=None):
        self.queries = list(queries)
        self.inventory = frozenset(inventory)
        self._clock = clock or time.time
        self._prev = {}       # query name -> last good snapshot
        self._last_run = {}   # query name -> last collection timestamp

    def _is_known(self, record):
        return (record.get("exe") in self.inventory or
                record.get("name") in self.inventory)

    def poll(self):
        """Run due queries once and diff. Never raises for collector
        failures — those are recorded on the result and the previous
        snapshot is kept (fail-closed)."""
        now = self._clock()
        result = DifferentialResult()
        for q in self.queries:
            result.added[q.name] = []
            result.removed[q.name] = []
            last = self._last_run.get(q.name)
            if last is not None and now - last < q.interval:
                continue  # not due yet: quiet, no re-collection
            try:
                snap = q.collector()
            except Exception as exc:
                result.errors.append({
                    "query": q.name,
                    "error": "%s: %s" % (type(exc).__name__, exc),
                })
                continue  # keep previous snapshot: never shrink state
            self._last_run[q.name] = now
            prev = self._prev.get(q.name)
            if prev is None:
                # First poll is the silent baseline (osquery semantics).
                self._prev[q.name] = dict(snap)
                continue
            prev_keys, snap_keys = set(prev), set(snap)
            # osquery differential semantics: a CHANGED row (same key,
            # different record) is removed(old) + added(new).
            changed = {k for k in prev_keys & snap_keys
                       if prev[k] != snap[k]}
            added_keys = (snap_keys - prev_keys) | changed
            removed_keys = (prev_keys - snap_keys) | changed
            added = [snap[k] for k in sorted(added_keys, key=repr)]
            removed = [prev[k] for k in sorted(removed_keys, key=repr)]
            result.added[q.name] = added
            if q.removed:
                result.removed[q.name] = removed
                for rec in removed:
                    result.lifecycle_events.append({
                        "kind": LIFECYCLE_KIND,
                        "table": q.name,
                        "transition": "removed",
                        "record": rec,
                        "ts": int(now),
                    })
            if q.unknown_agents:
                for rec in added:
                    if not self._is_known(rec):
                        result.unknown_agents.append({
                            "kind": UNKNOWN_AGENT_KIND,
                            "table": q.name,
                            "pid": rec.get("pid"),
                            "name": rec.get("name"),
                            "cmdline": rec.get("cmdline", ""),
                            "exe": rec.get("exe", ""),
                            "first_seen": int(now),
                        })
            self._prev[q.name] = dict(snap)
        return result

    def poll_loop(self, on_result, *, interval=60, stop_after=None,
                  sleeper=None):
        """Interval-driven scheduled loop. Sleeps ``interval`` seconds
        between polls (per-query intervals gate individual queries) —
        no busy wait. ``stop_after`` caps iterations (tests)."""
        sleeper = sleeper or time.sleep
        n = 0
        while True:
            on_result(self.poll())
            n += 1
            if stop_after is not None and n >= stop_after:
                break
            sleeper(interval)


# ---------------------------------------------------------------------------
# Stdlib live collectors (opt-in; tests inject snapshots instead)
# ---------------------------------------------------------------------------

def snapshot_processes():
    """Live process snapshot via /proc: ``{pid: record}``.

    Racy by nature (processes exit mid-read): per-process OSErrors
    skip that process, never abort the snapshot.
    """
    snap = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return snap
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        base = "/proc/%d" % pid
        try:
            with open(os.path.join(base, "comm"), "rb") as f:
                name = f.read().decode("utf-8", "replace").strip()
        except OSError:
            continue
        try:
            with open(os.path.join(base, "cmdline"), "rb") as f:
                cmdline = (f.read().replace(b"\x00", b" ")
                           .decode("utf-8", "replace").strip())
        except OSError:
            cmdline = ""
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError:
            exe = ""
        snap[pid] = {"pid": pid, "name": name,
                     "cmdline": cmdline, "exe": exe}
    return snap


def _listen_inodes(path, proto):
    """``{(proto, port): {inodes}}`` for LISTEN sockets (state 0A)."""
    out = {}
    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except OSError:
        return out
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 10 or parts[3] != "0A":
            continue
        try:
            port = int(parts[1].rsplit(":", 1)[1], 16)
        except ValueError:
            continue
        out.setdefault((proto, port), set()).add(parts[9])
    return out


def snapshot_listening_ports():
    """Live listening-socket snapshot: ``{(proto, port): record}``.

    Inode -> pid resolution walks /proc/*/fd; sockets whose owner
    cannot be resolved keep ``pid: None`` (recorded, not dropped).
    """
    listen = _listen_inodes("/proc/net/tcp", "tcp")
    for key, inodes in _listen_inodes("/proc/net/tcp6", "tcp6").items():
        listen.setdefault(key, set()).update(inodes)
    inode_pid = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        entries = []
    for entry in entries:
        if not entry.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % entry
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inode_pid[target[8:-1]] = int(entry)
    snap = {}
    for (proto, port), inodes in listen.items():
        pids = sorted({inode_pid[i] for i in inodes
                       if i in inode_pid})
        snap[(proto, port)] = {"proto": proto, "port": port,
                               "pids": pids,
                               "pid": pids[0] if pids else None}
    return snap


def snapshot_apps():
    """Installed distributions via importlib.metadata: ``{name: record}``."""
    snap = {}
    try:
        from importlib import metadata as _md
        dists = _md.distributions()
    except Exception:
        return snap
    for dist in dists:
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except Exception:
            continue
        if name:
            snap[name] = {"name": name, "version": str(version)}
    return snap


# ---------------------------------------------------------------------------
# Bridge to the governed discovery path
# ---------------------------------------------------------------------------

def to_discovery_signals(result):
    """Convert unknown-agent findings to ``gov.discovery`` signals.

    The ``unknown_agent_process`` signal kind (weight 4, same severity
    class as ``agent_process``) keys candidates on pid+name fingerprint
    and flows through ``DiscoveryLedger.note_signals`` ->
    ``unregistered_candidates`` -> ``report_unregistered`` exactly like
    any other discovery signal. Registration stays an explicit
    operator act; the only automatic output is the finding.
    """
    from . import discovery as _discovery  # lazy: keep import graph light
    sigs = []
    for f in result.unknown_agents:
        sigs.append(_discovery.signal(
            "unknown_agent_process",
            "pid:%s" % (f["pid"],),
            {"name": (f["name"] or "")[:120],
             "cmdline": (f["cmdline"] or "")[:200],
             "exe": (f["exe"] or "")[:200],
             "table": f["table"],
             "first_seen": f["first_seen"]}))
    return sigs
