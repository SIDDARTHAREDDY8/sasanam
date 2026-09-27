"""Post-run artifact sweep: catch side-channel writes (row-12 second half).

Row-12 residual: "writes outside the governed executor or through a
compromised executor remain outside the inventory's trust boundary."
The Wave-130 artifact inventory (``gov/artifacts.py``) only sees writes
through the governed ``write_file`` path. An agent that writes a file
by any other means — direct filesystem access from a tool that bypasses
the governed path, a helper process, a pre-staged payload — leaves no
registration, so the inventory (and the egress-time ``unknown`` check,
which only fires when an egress *references* the file) never sees it.

What this module does:
- ``sweep_run_dir(run_dir, inventory)``: walks the run's sandbox
  directory AFTER the run's work is done and compares every regular
  file found on disk against the Wave-130 ``ArtifactInventory``.
  Any file that is not registered, or whose bytes no longer match
  its registration, is reported as an ``unregistered_artifact``
  finding (kind ``never_registered`` or ``integrity_violation``)
  with path, size, SHA-256, and mtime. Read-only: it never modifies
  the sandbox, the inventory, or the audit log.
- Executor wiring (opt-in ``artifact_sweep`` kwarg, appended last like
  ``drift_store``/``content_monitor``): when enabled, ``execute_approved()``
  runs the sweep after the approved sweep completes and audits every
  finding LOUD as a chained ``artifact_sweep_finding`` event, plus one
  ``artifact_sweep_complete`` event carrying the sweep stats (evidence
  the sweep ran, even when clean). Zero behavior change when absent.

What this is NOT (honest ceilings, documented not hidden):
- Not a compromised-executor detector. The sweep runs in the same
  process as the executor: a *sophisticated* compromised executor can
  lie to the sweep (skip files, forge hashes) exactly as it can lie
  to the inventory. This catches the SLOPPY side channel — the tool
  that writes around the governed path without covering its tracks —
  not an adversary that controls the sweeping process itself.
- Not a whole-machine watcher. Only the run's sandbox directory is
  walked. Writes outside the run directory entirely (another /tmp
  path, a socket, a remote mount) are outside the sweep's view by
  construction — see probe p5. OPERATOR-CONFIGURED WATCH ROOTS
  (below) extend the view to named directories, but unconfigured
  roots stay invisible by default: the operator must remember to
  opt them in. The COVERAGE REPORT (wave-140, below) makes that
  opt-in gap LOUD, but it can only compare against the roots the
  operator *declared* — a directory the operator doesn't know
  about stays invisible. The residual mutates from "unconfigured
  roots invisible" to "undeclared roots invisible".
- Not a content oracle. Like the inventory, it keys on file identity
  (path + hash), never on what the bytes mean.
- Symlinks are skipped, never followed: a symlink inside the sandbox
  pointing outside it is not a sandbox write (F146 PaperCut
  discipline), and following it would let the sweep read files it has
  no business reading.
- Unreadable files are skipped fail-open per file (noted in stats),
  mirroring the inventory's fail-open-on-unreadable discipline.

Watch roots (wave-136): ``register_watch_root(root, inventory)``
snapshots the expected state of an operator-owned directory BEFORE
the run into its own ``ArtifactInventory`` baseline (keys are
root-relative, so each watch root needs its OWN inventory instance
— sharing one inventory between the run sandbox and a watch root
would collide on identical relative paths). ``sweep_run_dir`` then
takes ``watch_roots=[(root, baseline), ...]`` and diffs each root
post-run with the same never_registered / integrity_violation
logic; findings carry the resolved ``root``. Fail-closed safety:
``/`` and ``$HOME`` are refused outright; roots must be real
directories; a root that overlaps the run's walked sandbox tree
(ancestor or descendant, either direction) is rejected so no file
is ever double-reported; overlapping watch roots are rejected for
the same reason; the root path itself is resolved (a symlink to
``/`` is still ``/``). Watching a large tree is expensive — watch
roots should be narrow (a data dir, a workspace subdir), never a
whole home directory or filesystem.

Coverage report (wave-140): ``report_coverage_gaps`` takes an
operator-DECLARED inventory of egress-capable directories — an
explicit list, no auto-discovery — and compares it against the
configured watch roots. Every inventoried directory with no
covering watch root is audited LOUD as an
``artifact_sweep_coverage_gap`` evidence event, plus one
``artifact_sweep_coverage_complete`` summary (evidence the report
ran). A watch root covers a declared directory when the root is an
ancestor of (or equal to) it. The report is VISIBILITY, not
prevention: it does not stop a write, it tells the operator a
declared directory is unwatched. The inventory itself is
operator-declared — a directory the operator doesn't know about
stays invisible (undeclared, not unconfigured: the residual
mutated). Same trust boundary as the sweep: a compromised executor
in the same process can skip the report or forge its events —
this catches the careless operator configuration, not the
adversarial one.

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from .artifacts import normalize_path, ArtifactInventory

__all__ = [
    "sweep_run_dir",
    "register_watch_root",
    "compare_coverage",
    "report_coverage_gaps",
    "WatchRootError",
    "SWEEP_FINDING_EVENT",
    "SWEEP_COMPLETE_EVENT",
    "COVERAGE_GAP_EVENT",
    "COVERAGE_COMPLETE_EVENT",
    "NEVER_REGISTERED",
    "INTEGRITY_VIOLATION",
]

SWEEP_FINDING_EVENT = "artifact_sweep_finding"
SWEEP_COMPLETE_EVENT = "artifact_sweep_complete"

#: Wave-140: LOUD evidence event for one inventoried directory with
#: no covering watch root.
COVERAGE_GAP_EVENT = "artifact_sweep_coverage_gap"

#: Wave-140: summary evidence event proving the coverage report ran
#: (declared / covered / gap counts).
COVERAGE_COMPLETE_EVENT = "artifact_sweep_coverage_complete"

NEVER_REGISTERED = "never_registered"
INTEGRITY_VIOLATION = "integrity_violation"

_SANDBOX_SUBDIR = "sandbox"
_CHUNK = 65536


class WatchRootError(ValueError):
    """Fail-closed configuration error for watch roots.

    Raised (never swallowed) when a watch root is not a real
    directory, is ``/`` or ``$HOME``, overlaps the run directory or
    another watch root, or is otherwise unsafe to walk. A
    misconfigured watch root must be LOUD at setup time, not a
    silent gap at sweep time.
    """


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path):
    """SHA-256 of a file's bytes, streamed. Raises OSError on trouble."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_regular_files(root):
    """Yield (absolute_path, DirEntry) for regular files under root.

    Symlinks are never followed and never yielded (a symlink is not a
    write; following one could escape the sandbox — F146 discipline).
    Directories are descended into. Permission errors on a directory
    are skipped (fail-open per directory, counted by the caller via
    the yielded sentinel).
    """
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            it = os.scandir(cur)
        except OSError:
            yield (None, None)  # sentinel: unreadable directory
            continue
        with it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        yield (entry.path, entry)
                    # Anything else (symlink, fifo, socket, device)
                    # is not a file write — skipped by design.
                except OSError:
                    yield (None, None)  # sentinel: stat failed


def _is_ancestor_or_equal(a, b):
    """True when resolved path ``a`` is an ancestor of (or equal to)
    resolved path ``b``. Pure path logic on already-resolved paths."""
    if a == b:
        return True
    return b.startswith(a + os.sep)


def _refuse_unwalkable(root):
    """Fail-closed checks that need no run context: real directory,
    not ``/``, not ``$HOME``. Returns the resolved absolute path."""
    if not isinstance(root, (str, os.PathLike)):
        raise WatchRootError(
            "watch root must be a path, got %r" % (root,))
    resolved = os.path.realpath(os.path.abspath(str(root)))
    if resolved == os.sep:
        raise WatchRootError(
            "watch root %r refused: sweeping the filesystem root is "
            "never allowed" % (str(root),))
    home = os.path.realpath(os.path.expanduser("~"))
    if resolved == home:
        raise WatchRootError(
            "watch root %r refused: sweeping $HOME (%s) is never "
            "allowed -- watch a narrow subdirectory instead"
            % (str(root), home))
    if not os.path.isdir(resolved):
        raise WatchRootError(
            "watch root %r is not a real directory" % (str(root),))
    return resolved


def register_watch_root(root, inventory, *, agent_id="", run_id=""):
    """Snapshot the expected state of a watch root BEFORE the run.

    Walks ``root`` and registers every regular file found into
    ``inventory`` (an ``ArtifactInventory``) as the baseline the
    post-run sweep diffs against. Each watch root needs its OWN
    inventory instance: keys are root-relative, so sharing one
    inventory between two roots (or with the run sandbox) would
    collide on identical relative paths.

    Fail-closed: ``/``, ``$HOME``, non-directories, and non-paths
    raise ``WatchRootError``. Symlinks are never followed (F146
    discipline, same as the sweep). Unreadable files are skipped
    fail-open. Returns the inventory.
    """
    if not isinstance(inventory, ArtifactInventory):
        raise WatchRootError(
            "watch-root baseline must be an ArtifactInventory, got %r"
            % (type(inventory).__name__,))
    resolved = _refuse_unwalkable(root)
    for abspath, entry in _iter_regular_files(resolved):
        if abspath is None:
            continue
        rel = os.path.relpath(abspath, resolved)
        key = normalize_path(rel)
        if not key:
            continue
        try:
            st = entry.stat(follow_symlinks=False)
            digest = _sha256_file(abspath)
        except OSError:
            continue  # fail-open per file, mirrors the sweep
        inventory.register(key, sha256=digest, size=st.st_size,
                           agent_id=agent_id, run_id=run_id,
                           classification="watch_root_baseline")
    return inventory


def _sweep_tree(tree_root, inventory, root_label):
    """Walk one tree and diff against its inventory.

    Shared by the run-sandbox walk and every watch root. Returns
    ``(findings, stats)`` with the same finding shape as
    ``sweep_run_dir``; every finding carries ``"root"`` =
    ``root_label`` (the resolved directory that was walked).
    """
    findings = []
    stats = {"files_seen": 0, "files_compared": 0, "findings": 0,
             "skipped_unreadable": 0, "root": root_label}
    for abspath, entry in _iter_regular_files(tree_root):
        if abspath is None:
            stats["skipped_unreadable"] += 1
            continue
        stats["files_seen"] += 1
        rel = os.path.relpath(abspath, tree_root)
        key = normalize_path(rel)
        if not key:
            continue
        try:
            st = entry.stat(follow_symlinks=False)
            digest = _sha256_file(abspath)
        except OSError:
            stats["skipped_unreadable"] += 1
            continue
        stats["files_compared"] += 1
        rec = inventory.lookup(key) if inventory is not None else None
        if rec is None:
            findings.append({
                "finding": "unregistered_artifact",
                "kind": NEVER_REGISTERED,
                "root": root_label,
                "path": key,
                "size": st.st_size,
                "sha256": digest,
                "mtime": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc).isoformat(),
                "detail": ("File %r exists under watched root %r but "
                           "has no artifact inventory record: it was "
                           "not written through the governed write "
                           "path this run." % (key, root_label)),
            })
        elif digest != rec.sha256:
            findings.append({
                "finding": "unregistered_artifact",
                "kind": INTEGRITY_VIOLATION,
                "root": root_label,
                "path": key,
                "size": st.st_size,
                "sha256": digest,
                "mtime": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc).isoformat(),
                "registered_sha256": rec.sha256,
                "detail": ("File %r under watched root %r is "
                           "registered but the bytes on disk (sha256 "
                           "%s...) no longer match the registration "
                           "(sha256 %s...): modified outside the "
                           "governed write path after registration."
                           % (key, root_label, digest[:12],
                              rec.sha256[:12])),
            })
    stats["findings"] = len(findings)
    return findings, stats


def sweep_run_dir(run_dir, inventory, *, sandbox_subdir=_SANDBOX_SUBDIR,
                  watch_roots=()):
    """Walk the run's sandbox (and any watch roots) and compare
    against the artifact inventory.

    ``run_dir``: the run directory (str or Path). ``inventory``: a
    ``gov.artifacts.ArtifactInventory`` (or any object with
    ``lookup(normalized_path)`` returning a record with ``.sha256``,
    or None).

    ``watch_roots``: optional iterable of ``(root, baseline)``
    tuples, where ``root`` is an operator-owned directory and
    ``baseline`` is the ``ArtifactInventory`` returned by
    ``register_watch_root`` for that root. Each root is walked in
    full and diffed with the same logic as the sandbox. Fail-closed:
    ``/``, ``$HOME``, non-directories, roots overlapping the run's
    walked sandbox tree (either direction), and roots overlapping
    each other all raise ``WatchRootError`` — a misconfigured watch
    root must never silently narrow the sweep.

    Returns ``(findings, stats)``. Each finding is a dict::

        {"finding": "unregistered_artifact",
         "kind": "never_registered" | "integrity_violation",
         "root": <resolved directory walked>,
         "path": <root-relative normalized path>,
         "size": <bytes on disk>,
         "sha256": <sha256 of bytes on disk>,
         "mtime": <ISO-8601 mtime>,
         "detail": <human-readable one-line detail>,
         "registered_sha256": <only for integrity_violation>}

    ``stats`` carries ``files_seen``, ``files_compared``,
    ``findings``, ``skipped_unreadable``, ``sandbox`` (the directory
    actually walked, or None when absent), and ``watch_roots`` (a
    list of per-root stat dicts).

    Never raises on a missing sandbox (returns no findings); never
    modifies anything.
    """
    findings = []
    stats = {"files_seen": 0, "files_compared": 0, "findings": 0,
             "skipped_unreadable": 0, "sandbox": None, "watch_roots": []}
    sandbox = os.path.join(str(run_dir), sandbox_subdir)
    sandbox_resolved = os.path.realpath(os.path.abspath(sandbox))

    # Validate all watch roots BEFORE walking anything: a bad root
    # fails the whole sweep closed rather than sweeping a subset.
    validated = []  # (resolved_root, baseline) in walk order
    seen_roots = []
    for entry in watch_roots or ():
        try:
            wroot, baseline = entry
        except (TypeError, ValueError):
            raise WatchRootError(
                "watch_roots entries must be (root, baseline) tuples, "
                "got %r" % (entry,))
        if not isinstance(baseline, ArtifactInventory):
            raise WatchRootError(
                "watch-root baseline for %r must be an "
                "ArtifactInventory (use register_watch_root), got %r"
                % (wroot, type(baseline).__name__))
        resolved = _refuse_unwalkable(wroot)
        if (_is_ancestor_or_equal(resolved, sandbox_resolved)
                or _is_ancestor_or_equal(sandbox_resolved, resolved)):
            raise WatchRootError(
                "watch root %r overlaps the run's sandbox tree %r: "
                "files would be double-reported" % (resolved,
                                                   sandbox_resolved))
        for prev in seen_roots:
            if (_is_ancestor_or_equal(resolved, prev)
                    or _is_ancestor_or_equal(prev, resolved)):
                raise WatchRootError(
                    "watch root %r overlaps watch root %r: files "
                    "would be double-reported" % (resolved, prev))
        seen_roots.append(resolved)
        validated.append((resolved, baseline))

    if os.path.isdir(sandbox):
        stats["sandbox"] = sandbox
        sf, ss = _sweep_tree(sandbox_resolved, inventory, sandbox_resolved)
        findings.extend(sf)
        for k in ("files_seen", "files_compared", "skipped_unreadable"):
            stats[k] += ss[k]

    for resolved, baseline in validated:
        rf, rs = _sweep_tree(resolved, baseline, resolved)
        findings.extend(rf)
        stats["watch_roots"].append(rs)
        for k in ("files_seen", "files_compared", "skipped_unreadable"):
            stats[k] += rs[k]

    stats["findings"] = len(findings)
    return findings, stats


# ---------------------------------------------------------------------------
# Coverage report (wave-140): operator-declared inventory vs configured
# watch roots. Pure path comparison — no filesystem crawling beyond
# resolving the declared paths (no scandir, no discovery).
# ---------------------------------------------------------------------------

def _coverage_roots(entries):
    """Normalize configured watch roots to resolved paths.

    Accepts the same ``(root, baseline)`` tuples ``sweep_run_dir``
    takes, or plain root paths. Returns the resolved root strings in
    order. A non-path entry raises ValueError fail-closed (a
    mis-shaped configured root must never silently shrink coverage).
    """
    roots = []
    for entry in entries or ():
        root = entry[0] if isinstance(entry, (tuple, list)) else entry
        if not isinstance(root, (str, os.PathLike)):
            raise ValueError(
                "configured watch root must be a path, got %r"
                % (root,))
        roots.append(os.path.realpath(os.path.abspath(str(root))))
    return roots


def compare_coverage(declared_roots, configured_roots):
    """Compare the operator-declared inventory against configured
    watch roots — pure path logic, no filesystem walking.

    ``declared_roots``: the operator's explicit inventory of
    egress-capable directories (str/PathLike entries). An entry
    that is not a path raises ValueError (fail-closed: a malformed
    inventory must be LOUD at setup, not a silent gap). Declared
    roots are resolved (realpath) for comparison only — they are
    NEVER walked or crawled.

    ``configured_roots``: iterable of watch-root paths (already
    resolved or raw; resolved again for comparison).

    A declared directory is COVERED when some configured root is an
    ancestor of (or equal to) it — the sweep walks that root, so
    writes under the declared directory are seen. Otherwise it is
    a GAP.

    Returns an ordered list of dicts::

        {"declared_root": <resolved path>,
         "covering_root": <resolved covering root | None>,
         "exists": <os.path.isdir at report time>}

    Empty ``declared_roots`` -> empty list (silent: no inventory
    declared, nothing to report).
    """
    cfg = _coverage_roots(configured_roots)
    rows = []
    for entry in declared_roots or ():
        if not isinstance(entry, (str, os.PathLike)):
            raise ValueError(
                "declared inventory entries must be paths, got %r"
                % (entry,))
        resolved = os.path.realpath(os.path.abspath(str(entry)))
        covering = None
        for root in cfg:
            if _is_ancestor_or_equal(root, resolved):
                covering = root
                break
        rows.append({"declared_root": resolved,
                     "covering_root": covering,
                     "exists": os.path.isdir(resolved)})
    return rows


def report_coverage_gaps(declared_roots, watch_roots, audit=None,
                         run_id=None):
    """Emit LOUD evidence events for every inventoried directory
    with no covering watch root.

    ``declared_roots``: the operator's explicit inventory (see
    ``compare_coverage``). ``watch_roots``: the same
    ``(root, baseline)`` tuples ``sweep_run_dir`` takes (or plain
    root paths). ``audit``: optional callable taking each event dict
    (e.g. the executor's chained ``log.append``); when None the
    events are only returned. ``run_id``: stamped into each event.

    Each gap is audited as a LOUD ``artifact_sweep_coverage_gap``
    event naming the declared root; one
    ``artifact_sweep_coverage_complete`` summary follows (evidence
    the report ran, even when clean). An empty/None declared
    inventory emits NOTHING — the coverage report is then absent,
    not clean (silent, zero behavior change).

    Returns the report dict::

        {"declared": [...], "covered": [...], "gaps": [...],
         "gap_roots": [...], "covered_roots": [...],
         "events": [gap events..., summary event]}

    The report is visibility, not prevention; the inventory is
    operator-declared (undeclared directories stay invisible).
    """
    rows = compare_coverage(declared_roots, watch_roots)
    report = {"declared": [r["declared_root"] for r in rows],
              "covered": [r["declared_root"] for r in rows
                          if r["covering_root"]],
              "gaps": [r["declared_root"] for r in rows
                       if not r["covering_root"]],
              "gap_roots": [],
              "covered_roots": [],
              "events": []}
    if not rows:
        return report
    events = []
    for row in rows:
        if row["covering_root"] is not None:
            report["covered_roots"].append(
                {"declared_root": row["declared_root"],
                 "covering_root": row["covering_root"]})
            continue
        gap = {"event": COVERAGE_GAP_EVENT,
               "flag": "coverage_gap",
               "run_id": run_id,
               "declared_root": row["declared_root"],
               "covering_root": None,
               "reason": ("COVERAGE GAP: operator-inventoried "
                          "egress-capable directory %r has NO "
                          "covering watch root -- writes there are "
                          "invisible to the artifact sweep. Add a "
                          "watch root or accept the blind spot "
                          "explicitly." % row["declared_root"]),
               "ts": _utcnow_iso()}
        events.append(gap)
        report["gap_roots"].append(row["declared_root"])
    events.append({"event": COVERAGE_COMPLETE_EVENT,
                   "run_id": run_id,
                   "declared": len(report["declared"]),
                   "covered": len(report["covered"]),
                   "gaps": len(report["gaps"]),
                   "gap_roots": report["gap_roots"],
                   "ts": _utcnow_iso()})
    report["events"] = events
    if audit is not None:
        for ev in events:
            audit(ev)
    return report
