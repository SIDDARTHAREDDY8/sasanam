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
  construction — see probe p5.
- Not a content oracle. Like the inventory, it keys on file identity
  (path + hash), never on what the bytes mean.
- Symlinks are skipped, never followed: a symlink inside the sandbox
  pointing outside it is not a sandbox write (F146 PaperCut
  discipline), and following it would let the sweep read files it has
  no business reading.
- Unreadable files are skipped fail-open per file (noted in stats),
  mirroring the inventory's fail-open-on-unreadable discipline.

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from .artifacts import normalize_path

__all__ = [
    "sweep_run_dir",
    "SWEEP_FINDING_EVENT",
    "SWEEP_COMPLETE_EVENT",
    "NEVER_REGISTERED",
    "INTEGRITY_VIOLATION",
]

SWEEP_FINDING_EVENT = "artifact_sweep_finding"
SWEEP_COMPLETE_EVENT = "artifact_sweep_complete"

NEVER_REGISTERED = "never_registered"
INTEGRITY_VIOLATION = "integrity_violation"

_SANDBOX_SUBDIR = "sandbox"
_CHUNK = 65536


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


def sweep_run_dir(run_dir, inventory, *, sandbox_subdir=_SANDBOX_SUBDIR):
    """Walk the run's sandbox and compare against the artifact inventory.

    ``run_dir``: the run directory (str or Path). ``inventory``: a
    ``gov.artifacts.ArtifactInventory`` (or any object with
    ``lookup(normalized_path)`` returning a record with ``.sha256``,
    or None).

    Returns ``(findings, stats)``. Each finding is a dict::

        {"finding": "unregistered_artifact",
         "kind": "never_registered" | "integrity_violation",
         "path": <sandbox-relative normalized path>,
         "size": <bytes on disk>,
         "sha256": <sha256 of bytes on disk>,
         "mtime": <ISO-8601 mtime>,
         "registered_sha256": <only for integrity_violation>}

    ``stats`` carries ``files_seen``, ``files_compared``,
    ``findings``, ``skipped_unreadable``, and ``sandbox`` (the
    directory actually walked, or None when absent).

    Never raises on a missing sandbox (returns no findings); never
    modifies anything.
    """
    findings = []
    stats = {"files_seen": 0, "files_compared": 0, "findings": 0,
             "skipped_unreadable": 0, "sandbox": None}
    sandbox = os.path.join(str(run_dir), sandbox_subdir)
    if not os.path.isdir(sandbox):
        return findings, stats
    stats["sandbox"] = sandbox
    for abspath, entry in _iter_regular_files(sandbox):
        if abspath is None:
            stats["skipped_unreadable"] += 1
            continue
        stats["files_seen"] += 1
        rel = os.path.relpath(abspath, sandbox)
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
                "path": key,
                "size": st.st_size,
                "sha256": digest,
                "mtime": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc).isoformat(),
                "detail": ("File %r exists in the run sandbox but has "
                           "no artifact inventory record: it was not "
                           "written through the governed write path "
                           "this run." % (key,)),
            })
        elif digest != rec.sha256:
            findings.append({
                "finding": "unregistered_artifact",
                "kind": INTEGRITY_VIOLATION,
                "path": key,
                "size": st.st_size,
                "sha256": digest,
                "mtime": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc).isoformat(),
                "registered_sha256": rec.sha256,
                "detail": ("File %r is registered but the bytes on disk "
                           "(sha256 %s...) no longer match the "
                           "registration (sha256 %s...): modified "
                           "outside the governed write path after "
                           "registration."
                           % (key, digest[:12], rec.sha256[:12])),
            })
    stats["findings"] = len(findings)
    return findings, stats
