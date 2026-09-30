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

Pinned declared inventory (wave-141): the wave-140 report compared
whatever inventory it was handed — a compromised executor could
silently SHRINK the declared list so a blind spot never appears as
a gap. ``pin_inventory(declared_roots)`` is the operator pinning
ceremony: the resolved inventory is bound with an HMAC-SHA256 pin
keyed by the deployment key (``gov.keyprovider.resolve_active_key()``,
domain-separated, never hard-coded; an unprovisioned deployment
fails closed at ceremony time). The executor takes the PINNED dict
as ``artifact_sweep={"declared_inventory": pinned}``; the gap
report verifies the pin and recomputes the report from (pinned
inventory, configured roots). A shrunk/tampered/forged inventory
fails verification LOUD (``artifact_sweep_inventory_unverifiable``)
and the report goes fail-closed FULL-GAP (every declared directory
treated as uncovered). No pin configured → the report carries an
explicit ``unpinned`` verdict (documented downgrade, never silently
treated as pinned). Any dict-form inventory claims the pinned
envelope: a dict without a verifiable pin (including a pin-stripped
envelope, F182) fails verification LOUD rather than being
reinterpreted as an unpinned inventory of its keys. Honest ceilings: the pin moves trust to key
custody and the pinning ceremony — a compromised executor WITH
deployment-key access can still pin a malicious inventory; the
ceremony (who pins, when, audited) is the control, not the MAC.
The pin binds the DECLARED inventory; undeclared directories stay
invisible (the row-12 undeclared ceiling persists).

Watch-root declaration ceremony (wave-143): the wave-136 sweep walks
whatever watch roots it is CONFIGURED with -- a compromised operator
path or a direct config edit can silently NARROW the roots and the
sweep stays quiet over the narrowed set. ``declare_watch_roots``
binds each watch-root configuration change to an audited,
HMAC-pinned declaration envelope (operator identity, old root set ->
new root set, reason, declaration digest, key epoch -- the declaration
history is MAC-chained via previous_digest); ``check_roots_declaration``
compares the EFFECTIVE roots against the last declared set, and any
out-of-band change (roots added/removed, config edited directly) is
audited LOUD as ``artifact_sweep_roots_undeclared_change`` with the
sweep treated as unpinned/unverified (fail-closed -- never silently
swept as if declared). The executor's ``run_artifact_sweep`` runs the
check BEFORE the sweep when the opt-in carries ``"roots_declaration"``
and stamps the complete event with ``roots_verdict`` /
``roots_verified``. ``verify_declaration_chained`` is the auditor
path: a tampered ceremony event breaks the chain and fails LOUD.
Honest ceilings: this audits the watch-root *configuration*, not the
sweeping -- a compromised same-process executor can still lie about
what it actually swept (the standing same-process residual); key
custody underpins the ceremony chain like every other chained event
(a key-holder can declare a malicious-but-authorized set); the
declaration binds the CONFIGURED roots, it does not prove the
declared set was wise, and undeclared directories stay invisible.

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from hashlib import sha256

from .artifacts import normalize_path, ArtifactInventory
from . import keyprovider as _keyprovider
from .chained_store import canonical

__all__ = [
    "sweep_run_dir",
    "register_watch_root",
    "compare_coverage",
    "report_coverage_gaps",
    "pin_inventory",
    "verify_inventory_pin",
    "declare_watch_roots",
    "verify_roots_declaration",
    "check_roots_declaration",
    "verify_declaration_chained",
    "declaration_digest",
    "WatchRootError",
    "SWEEP_FINDING_EVENT",
    "SWEEP_COMPLETE_EVENT",
    "COVERAGE_GAP_EVENT",
    "COVERAGE_COMPLETE_EVENT",
    "INVENTORY_UNVERIFIABLE_EVENT",
    "INVENTORY_PINNED_EVENT",
    "ROOTS_DECLARED_EVENT",
    "ROOTS_UNDECLARED_CHANGE_EVENT",
    "ROOTS_DECLARATION_VERSION",
    "EXPLICIT_KEY_EPOCH",
    "inventory_digest",
    "PINNED_INVENTORY_VERSION",
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

#: Wave-141: LOUD evidence event when a pinned declared inventory
#: fails verification. Fail-closed: the report treats every declared
#: directory as uncovered (full-gap) -- a forged inventory must
#: never read as "covered".
INVENTORY_UNVERIFIABLE_EVENT = "artifact_sweep_inventory_unverifiable"

#: Wave-142: evidence event emitted by the pinning ceremony itself.
#: Records the inventory digest, the key epoch the pin was made
#: under, and the pin timestamp -- the auditable "who pinned what,
#: when, under which key" record. Chained by the caller's audit
#: callable (e.g. the executor's log.append); carrying the digest
#: (not the inventory) keeps the event compact while binding it to
#: the exact pinned list.
INVENTORY_PINNED_EVENT = "artifact_sweep_inventory_pinned"

#: Wave-141: pinned-inventory envelope version.
PINNED_INVENTORY_VERSION = "artifact-inventory-pin/1.0"

#: Wave-141: HMAC domain separation for inventory pins. A pin is only
#: ever valid as an inventory pin -- it cannot collide with any other
#: MAC domain in the repo.
_PIN_DOMAIN = b"artifact-inventory-pin-v1"

#: Wave-142: domain separation for the inventory digest carried in
#: the ceremony event. The digest is a public commitment (no key),
#: so it gets its own domain -- it must never collide with the pin
#: MAC domain above.
_DIGEST_DOMAIN = b"artifact-inventory-digest-v1"

#: Wave-142: sentinel epoch recorded on pins made with an explicit
#: ``hmac_key`` override instead of the deployment key. An override
#: carries no key-provider epoch, so staleness cannot be judged
#: against rotation -- two override pins share this label and verify
#: against each other; a pin made via the key provider never matches
#: it (fail-closed: you cannot smuggle a raw-key pin past an
#: epoch check, or vice versa).
EXPLICIT_KEY_EPOCH = "explicit-override"

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


def _sweep_tree(tree_root, inventory, root_label, *, audit=None):
    """Walk one tree and diff against its inventory.

    Shared by the run-sandbox walk and every watch root. Returns
    ``(findings, stats)`` with the same finding shape as
    ``sweep_run_dir``; every finding carries ``"root"`` =
    ``root_label`` (the resolved directory that was walked).

    Wave-219: unreadable files/directories are skipped fail-open per
    file (counted in ``stats["skipped_unreadable"]``) -- the registered
    unsafe path ``gov.artifact_sweep.unreadable_file_skipped``, emitted
    once per call (aggregated with the count) through the audit path
    (``audit``: list or callable) whenever anything was skipped.
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
    if stats["skipped_unreadable"]:
        # Wave-219: the fail-open skip is never silent -- one aggregated
        # emission per tree walked, carrying the count.
        from . import unsafe_paths as _up
        _up.emit(
            "gov.artifact_sweep.unreadable_file_skipped",
            audit=audit,
            detail=("%d unreadable file(s)/director(ies) under watched "
                    "root %r were skipped fail-open (counted, not "
                    "compared)" % (stats["skipped_unreadable"],
                                   root_label)))
    return findings, stats


def sweep_run_dir(run_dir, inventory, *, sandbox_subdir=_SANDBOX_SUBDIR,
                  watch_roots=(), audit=None):
    """Walk the run's sandbox (and any watch roots) and compare
    against the artifact inventory.

    ``run_dir``: the run directory (str or Path). ``inventory``: a
    ``gov.artifacts.ArtifactInventory`` (or any object with
    ``lookup(normalized_path)`` returning a record with ``.sha256``,
    or None).

    ``audit``: optional list/callable receiving the wave-219 unsafe-path
    emissions (``gov.artifact_sweep.unreadable_file_skipped``, one
    aggregated event per walked tree that skipped anything).

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
        sf, ss = _sweep_tree(sandbox_resolved, inventory, sandbox_resolved,
                             audit=audit)
        findings.extend(sf)
        for k in ("files_seen", "files_compared", "skipped_unreadable"):
            stats[k] += ss[k]

    for resolved, baseline in validated:
        rf, rs = _sweep_tree(resolved, baseline, resolved, audit=audit)
        findings.extend(rf)
        stats["watch_roots"].append(rs)
        for k in ("files_seen", "files_compared", "skipped_unreadable"):
            stats[k] += rs[k]

    stats["findings"] = len(findings)
    return findings, stats


# ---------------------------------------------------------------------------
# Pinned declared inventory (wave-141): the wave-140 coverage report
# compared whatever inventory it was handed -- a compromised
# same-process executor could silently SHRINK the declared inventory
# so a blind spot never appears as a gap. The declared inventory must
# now be operator-pinned with an HMAC at configuration time; the gap
# report binds to the pinned inventory, and a verifier recomputes the
# report from (pinned inventory, configured roots). A shrunk/forged
# inventory fails verification LOUD (``artifact_sweep_inventory_unverifiable``,
# fail-closed full-gap). No pin configured -> the report carries an
# explicit ``unpinned`` verdict (documented downgrade, never silently
# treated as pinned).
#
# Honest ceilings (documented, not hidden): the pin moves trust to
# key custody and the pinning ceremony. A compromised executor WITH
# deployment-key access can still pin a malicious inventory -- the
# ceremony (who pins, when, under which key epoch, audited) is the
# control, not the MAC. Wave-142 makes the ceremony auditable:
# ``pin_inventory`` records the key epoch (MAC-bound) and emits a
# chained ``artifact_sweep_inventory_pinned`` event carrying the
# inventory digest, key epoch, and timestamp; a pin presented under a
# rotated-out epoch (or older than an operator TTL) verifies as
# ``stale_pin_epoch`` -- LOUD, fail-closed. The ceremony proves WHEN
# and WHAT was pinned, not that the pinned list was wise: a
# malicious-but-fresh pin by a key-holder is still the operator's
# problem.
# The pin binds the inventory the operator DECLARED; a directory the
# operator doesn't know about stays undeclared (the row-12
# undeclared-directory ceiling persists, pinned not closed).
# ---------------------------------------------------------------------------

def _inventory_pin_mac(key, body):
    """HMAC-SHA256 over the canonical pinned-inventory body.

    Single key-material site in this module (see the w70 HMAC
    chokepoint allowlist): the key is
    ``gov.keyprovider.resolve_active_key()`` output -- the wave-69/81
    guarded chokepoint (explicit provisioning, fail-closed, no dev
    fallback) -- or an explicit caller override; never hard-coded,
    never committed. Domain-separated via ``_PIN_DOMAIN``.
    """
    return hmac.new(key, _PIN_DOMAIN + b"\x00" + body,
                    sha256).hexdigest()


def _pinned_body(version, inventory, pinned_at, key_epoch):
    """Canonical bytes covered by the inventory pin.

    Wave-142: the key epoch the pin was made under is MAC-bound into
    the body -- a pin presented after the epoch rotated cannot be
    freshened by rewriting its ``key_epoch`` field (that breaks the
    MAC). The epoch is checked AFTER MAC verification, when its
    value is authenticated.
    """
    return canonical({"pinned_inventory": version,
                      "inventory": list(inventory),
                      "pinned_at": pinned_at,
                      "key_epoch": key_epoch}).encode("utf-8")


def _inventory_pin_body_digest(body):
    """Domain-separated SHA-256 over the canonical pinned body.

    The public inventory commitment carried in the ceremony event:
    no key material involved, recomputable by any holder of the
    pinned dict.
    """
    return sha256(_DIGEST_DOMAIN + b"\x00" + body).hexdigest()


def inventory_digest(pinned):
    """Recompute the ceremony inventory digest for a pinned dict.

    Raises ValueError on a malformed envelope (fail-fast for
    auditors; this is the recomputation path, not the fail-closed
    verification path). The digest binds the exact (inventory,
    pinned_at, key_epoch) the ceremony committed to.
    """
    if not isinstance(pinned, dict):
        raise ValueError("pinned inventory must be a dict")
    version = pinned.get("pinned_inventory")
    inventory = pinned.get("inventory")
    pinned_at = pinned.get("pinned_at")
    key_epoch = pinned.get("key_epoch")
    if (version != PINNED_INVENTORY_VERSION
            or not isinstance(inventory, list)
            or not all(isinstance(e, str) for e in inventory)
            or not isinstance(pinned_at, str) or not pinned_at
            or not isinstance(key_epoch, str) or not key_epoch):
        raise ValueError("malformed pinned inventory envelope")
    resolved = [_resolve_declared(e) for e in inventory]
    return _inventory_pin_body_digest(
        _pinned_body(version, resolved, pinned_at, key_epoch))


def _resolve_declared(entry):
    """Resolve one declared-inventory entry (path only, never walked)."""
    return os.path.realpath(os.path.abspath(str(entry)))


def pin_inventory(declared_roots, *, hmac_key=None, audit=None,
                run_id=None):
    """Operator pinning ceremony: bind the declared inventory with an HMAC.

    ``declared_roots``: the operator's explicit inventory of
    egress-capable directories (str/PathLike entries). Entries are
    RESOLVED (realpath) for the pin -- they are NEVER walked or
    crawled. A non-path entry raises ValueError fail-closed at
    ceremony time (a malformed inventory must be LOUD at setup, not
    a silent gap at report time).

    ``hmac_key``: explicit key override (bytes); when None, the
    deployment key comes from
    ``gov.keyprovider.resolve_active_key()`` and an unprovisioned
    deployment raises ``NoKeyConfiguredError`` fail-closed -- the
    ceremony requires a key, there is no unsigned pin.

    ``audit``: optional callable taking one event dict (e.g. the
    executor's chained ``log.append``). When given, the ceremony
    emits one ``artifact_sweep_inventory_pinned`` event recording
    the inventory digest, the key epoch, and the pin timestamp --
    the auditable "who pinned what, when, under which key" record.
    ``run_id`` is stamped into the event.

    Wave-142: the pin records the KEY EPOCH it was made under
    (``gov.keyprovider.resolve_active_key()`` epoch, or
    ``"explicit-override"`` for an ``hmac_key`` override), MAC-bound
    into the pin body. A pin presented after the epoch rotated (or
    older than an operator TTL -- see ``verify_inventory_pin``)
    verifies as ``stale_pin_epoch``: LOUD, fail-closed, treated as
    unverifiable by the gap report.

    Returns the pinned inventory dict::

        {"pinned_inventory": "artifact-inventory-pin/1.0",
         "inventory": [<resolved paths>],
         "pinned_at": <ISO-8601>,
         "key_epoch": <epoch at pin time>,
         "pin": <hex HMAC-SHA256>}

    The operator hands this dict (not the bare list) to the executor
    as ``artifact_sweep={"declared_inventory": pinned}``.

    Honest ceiling (documented, not hidden): the ceremony proves
    WHEN and WHAT was pinned and under WHICH key epoch -- not that
    the pinned list was wise. A malicious-but-fresh pin made by a
    key-holder verifies cleanly; that is the operator's problem.
    The control is the ceremony, stated plainly.
    """
    if hmac_key is None:
        key_bytes, key_epoch = _keyprovider.resolve_active_key()
    else:
        key_bytes = bytes(hmac_key)
        if not key_bytes:
            raise ValueError("hmac_key must be non-empty bytes")
        key_epoch = EXPLICIT_KEY_EPOCH
    resolved = []
    for entry in declared_roots or ():
        if not isinstance(entry, (str, os.PathLike)):
            raise ValueError(
                "declared inventory entries must be paths, got %r"
                % (entry,))
        resolved.append(_resolve_declared(entry))
    pinned_at = _utcnow_iso()
    body = _pinned_body(PINNED_INVENTORY_VERSION, resolved, pinned_at,
                        key_epoch)
    pin = _inventory_pin_mac(key_bytes, body)
    pinned = {"pinned_inventory": PINNED_INVENTORY_VERSION,
              "inventory": resolved,
              "pinned_at": pinned_at,
              "key_epoch": key_epoch,
              "pin": pin}
    if audit is not None:
        audit({"event": INVENTORY_PINNED_EVENT,
               "run_id": run_id,
               "inventory_digest": _inventory_pin_body_digest(body),
               "key_epoch": key_epoch,
               "pinned_at": pinned_at,
               "declared_roots": list(resolved),
               "pin_version": PINNED_INVENTORY_VERSION,
               "ts": _utcnow_iso()})
    return pinned


def _pin_age_seconds(pinned_at):
    """Age of a pin in seconds, or None when ``pinned_at`` is
    unparseable. Fail-safe: an unparseable timestamp yields None,
    never an exception and never a fabricated age."""
    try:
        made = datetime.fromisoformat(str(pinned_at))
    except (ValueError, TypeError):
        return None
    if made.tzinfo is None:
        made = made.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - made).total_seconds()


def verify_inventory_pin(pinned, *, hmac_key=None, current_epoch=None,
                         pin_ttl_seconds=None):
    """Verify a pinned declared inventory.

    Returns ``(True, "")`` when the pin recomputes over the presented
    (inventory, pinned_at, key_epoch), the pin's key epoch is the
    CURRENT key epoch, and the pin is within the operator TTL, else
    ``(False, reason)``. NEVER raises on malformed input -- a forged
    or damaged pin is a verification FAILURE (fail-closed, LOUD at
    the report layer), not an exception. A key that cannot be
    resolved (unprovisioned deployment, empty override) also fails
    closed: without the key the pin is unverifiable, never trusted.

    Wave-142 -- staleness is fail-closed: a pin whose ``key_epoch``
    differs from the current epoch, or whose age exceeds
    ``pin_ttl_seconds`` (when given), verifies as ``stale_pin_epoch``
    -- LOUD at the report layer, treated as unverifiable (the gap
    report goes full-gap). The epoch check runs AFTER the MAC check:
    the presented epoch is only trustworthy once the MAC proves the
    pin is genuine. ``current_epoch`` overrides the resolved current
    epoch (tests/probes); when None it is resolved from the key
    provider (or ``"explicit-override"`` for an ``hmac_key``
    override). ``pin_ttl_seconds=None`` (default) disables the TTL
    check -- the TTL is an operator opt-in, not a default.
    """
    if not isinstance(pinned, dict):
        return (False, "pinned inventory must be a dict, got %s"
                % type(pinned).__name__)
    version = pinned.get("pinned_inventory")
    if version != PINNED_INVENTORY_VERSION:
        return (False, "unknown pinned-inventory version %r"
                % (version,))
    inventory = pinned.get("inventory")
    if (not isinstance(inventory, list)
            or not all(isinstance(e, str) for e in inventory)):
        return (False, "pinned inventory list is malformed")
    pinned_at = pinned.get("pinned_at")
    if not isinstance(pinned_at, str) or not pinned_at:
        return (False, "pinned_at is missing")
    key_epoch = pinned.get("key_epoch")
    if not isinstance(key_epoch, str) or not key_epoch:
        return (False, "key_epoch is missing: the pin predates the "
                "wave-142 ceremony audit (or was tampered with) -- "
                "re-pin the inventory")
    pin = pinned.get("pin")
    if not isinstance(pin, str) or not pin:
        return (False, "pin is missing")
    try:
        if hmac_key is None:
            key_bytes, resolved_epoch = _keyprovider.resolve_active_key()
        else:
            key_bytes = bytes(hmac_key)
            if not key_bytes:
                raise ValueError("hmac_key must be non-empty bytes")
            resolved_epoch = EXPLICIT_KEY_EPOCH
    except Exception as e:  # noqa: BLE001 - fail closed, never raise
        return (False, "key unavailable for verification: %s: %s"
                % (type(e).__name__, e))
    resolved = [_resolve_declared(e) for e in inventory]
    expected = _inventory_pin_mac(
        key_bytes, _pinned_body(version, resolved, pinned_at, key_epoch))
    if not hmac.compare_digest(expected, pin):
        return (False, "pin mismatch: the declared inventory does not "
                "match its pin (shrunk, extended, reordered, or forged)")
    # The MAC verified: the presented key_epoch is now authenticated.
    now_epoch = (resolved_epoch if current_epoch is None
                 else current_epoch)
    if key_epoch != now_epoch:
        return (False, "stale_pin_epoch: the pin was made under key "
                "epoch %r but the current key epoch is %r -- the "
                "deployment key rotated (or the pin was moved across "
                "deployments). Re-pin the inventory under the current "
                "key epoch." % (key_epoch, now_epoch))
    if pin_ttl_seconds is not None:
        try:
            ttl = float(pin_ttl_seconds)
        except (TypeError, ValueError):
            return (False, "stale_pin_epoch: the operator TTL %r is "
                    "not a number -- the pin's age cannot be judged; "
                    "fix the configured pin_ttl_seconds"
                    % (pin_ttl_seconds,))
        age = _pin_age_seconds(pinned_at)
        if age is None:
            return (False, "stale_pin_epoch: pinned_at %r is "
                    "unparseable -- the pin's age cannot be judged "
                    "against the operator TTL" % (pinned_at,))
        if age > ttl:
            return (False, "stale_pin_epoch: pin age %.0fs exceeds "
                    "the operator TTL of %.0fs -- re-pin the "
                    "inventory" % (age, ttl))
    return (True, "")


def _is_pinned_form(declared_roots):
    """True when the declared inventory claims the pinned envelope.

    ANY dict claims the pinned form. The documented unpinned form is
    a plain list; a dict without a ``pin`` key is a malformed/forged
    envelope, not an unpinned inventory. (F182: the old
    ``"pin" in declared_roots`` test let a pin-stripped envelope be
    silently reinterpreted as an unpinned inventory of its dict keys
    -- real declared directories dropped from the report with no
    LOUD event. Now every dict goes through ``verify_inventory_pin``
    and a pin-stripped envelope fails LOUD, fail-closed.)
    """
    return isinstance(declared_roots, dict)


def _untrusted_declared_roots(pinned):
    """Best-effort resolved roots from an UNVERIFIED pinned dict.

    Used only to shape the fail-closed full-gap report: entries that
    are not strings are dropped (they cannot be trusted or even
    resolved). Never raises.
    """
    out = []
    try:
        inventory = pinned.get("inventory")
    except AttributeError:
        return out
    if not isinstance(inventory, list):
        return out
    for entry in inventory:
        if isinstance(entry, str) and entry:
            try:
                out.append(_resolve_declared(entry))
            except Exception:  # noqa: BLE001 - drop, never raise
                continue
    return out


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
                         run_id=None, pin_ttl_seconds=None):
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

    Wave-142: ``declared_roots`` may be a pinned inventory dict from
    ``pin_inventory`` instead of a plain list. A pinned inventory is
    VERIFIED before use: a shrunk/tampered/forged pin fails LOUD
    with one ``artifact_sweep_inventory_unverifiable`` event and a
    fail-closed FULL-GAP report (every declared directory treated
    as uncovered -- a forged inventory never reads as "covered").
    A plain (unpinned) list is accepted with an explicit
    ``"unpinned"`` verdict -- the documented downgrade, never
    silently treated as pinned. The returned report carries
    ``"verdict"`` (``"pinned"`` | ``"unpinned"`` |
    ``"unverifiable"``), and the summary event carries
    ``"inventory_verdict"``.

    Wave-142 ceremony audit: ``pin_ttl_seconds`` is the operator TTL
    for pins (None = no TTL enforcement). A pin made under a
    rotated-out key epoch, or older than the TTL, verifies as
    ``stale_pin_epoch`` -- LOUD, fail-closed, treated as
    unverifiable. On a ``"pinned"`` verdict the report (and the
    summary event) surface the pin's ``key_epoch`` and
    ``pin_age_seconds`` -- the "when, under which key" half of the
    ceremony, visible to the verifier.
    """
    pinned_form = _is_pinned_form(declared_roots)
    inventory_verdict = "unpinned"
    declared_list = declared_roots
    pin_key_epoch = None
    pin_age_seconds = None
    presented_key_epoch = None
    if pinned_form:
        if isinstance(declared_roots, dict):
            presented_key_epoch = declared_roots.get("key_epoch")
        ok, reason = verify_inventory_pin(
            declared_roots, pin_ttl_seconds=pin_ttl_seconds)
        if not ok:
            # Fail-closed: the inventory is untrusted. One LOUD
            # event; every declared directory is reported as a gap
            # (full-gap). No coverage_complete summary -- the
            # unverifiable event IS the terminal evidence.
            declared = _untrusted_declared_roots(declared_roots)
            ev = {"event": INVENTORY_UNVERIFIABLE_EVENT,
                  "severity": "LOUD",
                  "flag": "coverage_gap",
                  "run_id": run_id,
                  "declared_roots": declared,
                  "inventory_verdict": "unverifiable",
                  "reason": ("INVENTORY UNVERIFIABLE: the declared "
                             "artifact inventory failed pin "
                             "verification (%s) -- the coverage-gap "
                             "report cannot trust it. Treating every "
                             "declared directory as UNCOVERED "
                             "(fail-closed full-gap). Re-pin the "
                             "inventory at configuration time with "
                             "the deployment key." % reason),
                  "ts": _utcnow_iso()}
            events = [ev]
            if audit is not None:
                audit(ev)
            return {"verdict": "unverifiable",
                    "declared": declared,
                    "covered": [],
                    "gaps": list(declared),
                    "gap_roots": list(declared),
                    "covered_roots": [],
                    "reason": reason,
                    "presented_key_epoch": presented_key_epoch,
                    "events": events}
        inventory_verdict = "pinned"
        declared_list = declared_roots["inventory"]
        pin_key_epoch = declared_roots.get("key_epoch")
        pin_age_seconds = _pin_age_seconds(
            declared_roots.get("pinned_at"))
    rows = compare_coverage(declared_list, watch_roots)
    report = {"verdict": inventory_verdict,
              "declared": [r["declared_root"] for r in rows],
              "covered": [r["declared_root"] for r in rows
                          if r["covering_root"]],
              "gaps": [r["declared_root"] for r in rows
                       if not r["covering_root"]],
              "gap_roots": [],
              "covered_roots": [],
              "key_epoch": pin_key_epoch,
              "pin_age_seconds": pin_age_seconds,
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
               "inventory_verdict": inventory_verdict,
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
                   "inventory_verdict": inventory_verdict,
                   "key_epoch": pin_key_epoch,
                   "pin_age_seconds": pin_age_seconds,
                   "ts": _utcnow_iso()})
    report["events"] = events
    if audit is not None:
        for ev in events:
            audit(ev)
    return report


# ---------------------------------------------------------------------------
# Watch-root declaration ceremony (wave-143): operator-declared watch
# roots vs effective watch roots. The wave-136 sweep walks whatever
# watch roots it is CONFIGURED with -- a compromised operator path or
# a direct config edit can silently NARROW the roots and the sweep
# stays quiet over the narrowed set. The declaration ceremony binds
# each watch-root configuration change to an audited, HMAC-pinned
# declaration (``declare_watch_roots``); the sweep path compares the
# EFFECTIVE roots against the last declared set
# (``check_roots_declaration``), and any out-of-band change (roots
# added/removed, config edited directly) is audited LOUD as
# ``artifact_sweep_roots_undeclared_change`` with the sweep treated
# as unpinned/unverified -- fail-closed, never silently sweeping a
# narrowed set as if it were the declared one. The executor's
# ``run_artifact_sweep`` (the real sweep path) runs the check BEFORE
# the sweep when the ``artifact_sweep`` opt-in carries a
# ``"roots_declaration"`` envelope, and stamps the
# ``artifact_sweep_complete`` event with ``roots_verdict`` /
# ``roots_verified``.
#
# Honest ceilings (documented, not hidden): this audits the watch-root
# *configuration*, not the sweeping. A compromised same-process
# executor can still lie about what it actually swept (pass different
# roots to the sweep than to the declaration check, skip the check,
# or forge either event) -- the standing row-12 same-process
# residual. Key custody underpins the ceremony chain exactly like
# every other chained event: a key-holder can declare a
# malicious-but-authorized set and it verifies cleanly; the ceremony
# (who declared what, when -- audited) is the control, not the MAC.
# The declaration binds the CONFIGURED roots; it does not prove the
# declared set was wise (a narrow set declared honestly is the
# operator's problem), and undeclared directories stay invisible.
# ---------------------------------------------------------------------------

#: Wave-143: chained ceremony event recording one watch-root
#: declaration: operator identity, old root set -> new root set,
#: reason, declaration digest, key epoch, timestamp.
ROOTS_DECLARED_EVENT = "artifact_sweep_roots_declared"

#: Wave-143: LOUD enforcement event when the effective watch-root set
#: differs from the last declared set (roots added/removed
#: out-of-band, config edited directly), or when the declaration
#: envelope itself is unverifiable. Fail-closed: the sweep over the
#: effective roots is treated as unpinned/unverified.
ROOTS_UNDECLARED_CHANGE_EVENT = "artifact_sweep_roots_undeclared_change"

#: Wave-143: roots-declaration envelope version.
ROOTS_DECLARATION_VERSION = "artifact-roots-declaration/1.0"

#: Wave-143: HMAC domain separation for roots declarations. A
#: declaration MAC is only ever valid as a roots declaration -- it
#: cannot collide with the inventory-pin MAC domain or any other MAC
#: domain in the repo.
_ROOTS_DECL_DOMAIN = b"artifact-roots-declaration-v1"

#: Wave-143: domain separation for the declaration digest carried in
#: the ceremony event. The digest is a public commitment (no key),
#: recomputable by any holder of the envelope.
_ROOTS_DIGEST_DOMAIN = b"artifact-roots-declaration-digest-v1"


def _roots_decl_mac(key, body):
    """HMAC-SHA256 over the canonical roots-declaration body.

    Single key-material site for declarations (see the w70 HMAC
    chokepoint allowlist): the key is
    ``gov.keyprovider.resolve_active_key()`` output -- the wave-69/81
    guarded chokepoint (explicit provisioning, fail-closed, no dev
    fallback) -- or an explicit caller override; never hard-coded,
    never committed. Domain-separated via ``_ROOTS_DECL_DOMAIN``.
    """
    return hmac.new(key, _ROOTS_DECL_DOMAIN + b"\x00" + body,
                    sha256).hexdigest()


def _roots_decl_body(version, roots, previous_roots, previous_digest,
                     operator_id, reason, declared_at, key_epoch):
    """Canonical bytes covered by the roots-declaration MAC.

    The old -> new transition is MAC-bound: ``previous_roots`` and
    the ``previous_digest`` (the digest of the prior envelope, ""
    for a first declaration) chain declarations into a
    tamper-evident declaration history -- rewriting history breaks
    the MAC. The key epoch is MAC-bound like the wave-142 inventory
    pins: a declaration presented after the epoch rotated cannot be
    freshened by rewriting its ``key_epoch`` field.
    """
    return canonical({"roots_declaration": version,
                      "roots": list(roots),
                      "previous_roots": list(previous_roots),
                      "previous_digest": previous_digest,
                      "operator_id": operator_id,
                      "reason": reason,
                      "declared_at": declared_at,
                      "key_epoch": key_epoch}).encode("utf-8")


def _roots_decl_body_digest(body):
    """Domain-separated SHA-256 over the canonical declaration body.

    The public declaration commitment carried in the ceremony event:
    no key material involved, recomputable by any holder of the
    envelope.
    """
    return sha256(_ROOTS_DIGEST_DOMAIN + b"\x00" + body).hexdigest()


def declaration_digest(envelope):
    """Recompute the ceremony declaration digest for an envelope.

    Raises ValueError on a malformed envelope (fail-fast for
    auditors; this is the recomputation path, not the fail-closed
    verification path). The digest binds the exact (roots,
    previous_roots, previous_digest, operator, reason, declared_at,
    key_epoch) the ceremony committed to.
    """
    if not isinstance(envelope, dict):
        raise ValueError("roots declaration must be a dict")
    version = envelope.get("roots_declaration")
    roots = envelope.get("roots")
    previous_roots = envelope.get("previous_roots")
    previous_digest = envelope.get("previous_digest")
    operator_id = envelope.get("operator_id")
    reason = envelope.get("reason")
    declared_at = envelope.get("declared_at")
    key_epoch = envelope.get("key_epoch")
    if (version != ROOTS_DECLARATION_VERSION
            or not isinstance(roots, list)
            or not all(isinstance(e, str) for e in roots)
            or not isinstance(previous_roots, list)
            or not all(isinstance(e, str) for e in previous_roots)
            or not isinstance(previous_digest, str)
            or not isinstance(operator_id, str) or not operator_id
            or not isinstance(reason, str)
            or not isinstance(declared_at, str) or not declared_at
            or not isinstance(key_epoch, str) or not key_epoch):
        raise ValueError("malformed roots-declaration envelope")
    resolved = [_resolve_declared(e) for e in roots]
    prev_resolved = [_resolve_declared(e) for e in previous_roots]
    return _roots_decl_body_digest(
        _roots_decl_body(version, resolved, prev_resolved,
                         previous_digest, operator_id, reason,
                         declared_at, key_epoch))


def declare_watch_roots(roots, *, previous=None, operator_id="",
                        reason="", hmac_key=None, audit=None,
                        run_id=None):
    """Declaration ceremony: bind a watch-root configuration change.

    ``roots``: the operator's intended watch-root set (str/PathLike
    entries). Entries are RESOLVED (realpath) for the declaration --
    they are NEVER walked or crawled here. A non-path entry raises
    ValueError fail-closed at ceremony time (a malformed declaration
    must be LOUD at setup, not a silent gap at sweep time).
    Duplicates are dropped (first-seen order kept).

    ``previous``: the prior declaration envelope (or None for a
    first declaration). The old -> new transition (previous roots
    and the previous envelope's digest) is MAC-bound into the new
    declaration, chaining declarations into a tamper-evident
    history. A malformed ``previous`` raises ValueError.

    ``operator_id``: REQUIRED non-empty -- the ceremony records who
    declared. Anonymous declarations are the attack shape this
    ceremony exists to record, so they fail closed at ceremony time.

    ``reason``: recorded verbatim in the envelope and the ceremony
    event (may be empty).

    ``hmac_key``: explicit key override (bytes); when None, the
    deployment key comes from
    ``gov.keyprovider.resolve_active_key()`` and an unprovisioned
    deployment raises ``NoKeyConfiguredError`` fail-closed -- the
    ceremony requires a key, there is no unsigned declaration.

    ``audit``: optional callable taking one event dict (e.g. the
    executor's chained ``log.append``). When given, the ceremony
    emits one ``artifact_sweep_roots_declared`` event recording the
    operator identity, old root set -> new root set (with
    added/removed), reason, declaration digest, key epoch, and
    timestamp. ``run_id`` is stamped into the event.

    Returns the declaration envelope::

        {"roots_declaration": "artifact-roots-declaration/1.0",
         "roots": [<resolved paths>],
         "previous_roots": [<resolved paths>],
         "previous_digest": <digest of the prior envelope | "">,
         "operator_id": <who declared>,
         "reason": <why>,
         "declared_at": <ISO-8601>,
         "key_epoch": <epoch at declaration time>,
         "declaration": <hex HMAC-SHA256>}

    The operator hands this envelope (not the bare list) to the
    executor as ``artifact_sweep={"roots_declaration": envelope,
    "watch_roots": [...]}``.

    Honest ceiling (documented, not hidden): the ceremony proves WHO
    declared WHAT WHEN under WHICH key epoch -- not that the
    declared set was wise. A malicious-but-authorized declaration by
    a key-holder verifies cleanly; that is the operator's problem.
    The control is the ceremony, stated plainly.
    """
    if not isinstance(operator_id, str) or not operator_id.strip():
        raise ValueError(
            "operator_id is required: anonymous watch-root "
            "declarations are the attack shape this ceremony exists "
            "to record")
    if hmac_key is None:
        key_bytes, key_epoch = _keyprovider.resolve_active_key()
    else:
        key_bytes = bytes(hmac_key)
        if not key_bytes:
            raise ValueError("hmac_key must be non-empty bytes")
        key_epoch = EXPLICIT_KEY_EPOCH
    resolved = []
    for entry in roots or ():
        if not isinstance(entry, (str, os.PathLike)):
            raise ValueError(
                "declared watch roots must be paths, got %r"
                % (entry,))
        rp = _resolve_declared(entry)
        if rp not in resolved:
            resolved.append(rp)
    previous_roots = []
    previous_digest = ""
    if previous is not None:
        if (not isinstance(previous, dict)
                or previous.get("roots_declaration")
                != ROOTS_DECLARATION_VERSION):
            raise ValueError(
                "previous must be a prior roots-declaration envelope")
        previous_roots = [_resolve_declared(e)
                          for e in (previous.get("roots") or ())]
        previous_digest = declaration_digest(previous)
    declared_at = _utcnow_iso()
    op = operator_id.strip()
    rsn = reason if isinstance(reason, str) else ""
    body = _roots_decl_body(ROOTS_DECLARATION_VERSION, resolved,
                            previous_roots, previous_digest, op, rsn,
                            declared_at, key_epoch)
    envelope = {"roots_declaration": ROOTS_DECLARATION_VERSION,
                "roots": resolved,
                "previous_roots": previous_roots,
                "previous_digest": previous_digest,
                "operator_id": op,
                "reason": rsn,
                "declared_at": declared_at,
                "key_epoch": key_epoch,
                "declaration": _roots_decl_mac(key_bytes, body)}
    if audit is not None:
        added = [r for r in resolved if r not in previous_roots]
        removed = [r for r in previous_roots if r not in resolved]
        audit({"event": ROOTS_DECLARED_EVENT,
               "run_id": run_id,
               "operator_id": op,
               "old_roots": list(previous_roots),
               "new_roots": list(resolved),
               "added": added,
               "removed": removed,
               "reason": rsn,
               "declared_at": declared_at,
               "key_epoch": key_epoch,
               "declaration_digest": _roots_decl_body_digest(body),
               "declaration_version": ROOTS_DECLARATION_VERSION,
               "ts": _utcnow_iso()})
    return envelope


def verify_roots_declaration(envelope, *, hmac_key=None,
                             current_epoch=None):
    """Verify a roots-declaration envelope.

    Returns ``(True, "")`` when the declaration MAC recomputes over
    the presented (roots, previous_roots, previous_digest,
    operator_id, reason, declared_at, key_epoch) and the
    declaration's key epoch is the CURRENT key epoch, else
    ``(False, reason)``. NEVER raises on malformed input -- a forged
    or damaged declaration is a verification FAILURE (fail-closed,
    LOUD at the check layer), not an exception. A key that cannot be
    resolved (unprovisioned deployment, empty override) also fails
    closed: without the key the declaration is unverifiable, never
    trusted.

    Staleness is fail-closed: a declaration whose ``key_epoch``
    differs from the current epoch verifies as
    ``stale_declaration_epoch`` -- LOUD at the check layer, treated
    as unverifiable. The epoch check runs AFTER the MAC check: the
    presented epoch is only trustworthy once the MAC proves the
    declaration is genuine. ``current_epoch`` overrides the resolved
    current epoch (tests/probes); when None it is resolved from the
    key provider (or ``"explicit-override"`` for an ``hmac_key``
    override).
    """
    if not isinstance(envelope, dict):
        return (False, "roots declaration must be a dict, got %s"
                % type(envelope).__name__)
    version = envelope.get("roots_declaration")
    if version != ROOTS_DECLARATION_VERSION:
        return (False, "unknown roots-declaration version %r"
                % (version,))
    roots = envelope.get("roots")
    if (not isinstance(roots, list)
            or not all(isinstance(e, str) for e in roots)):
        return (False, "declared roots list is malformed")
    declared_at = envelope.get("declared_at")
    if not isinstance(declared_at, str) or not declared_at:
        return (False, "declared_at is missing")
    key_epoch = envelope.get("key_epoch")
    if not isinstance(key_epoch, str) or not key_epoch:
        return (False, "key_epoch is missing: the declaration predates "
                "the wave-143 ceremony (or was tampered with) -- "
                "re-declare the watch roots")
    mac = envelope.get("declaration")
    if not isinstance(mac, str) or not mac:
        return (False, "declaration MAC is missing")
    try:
        if hmac_key is None:
            key_bytes, resolved_epoch = _keyprovider.resolve_active_key()
        else:
            key_bytes = bytes(hmac_key)
            if not key_bytes:
                raise ValueError("hmac_key must be non-empty bytes")
            resolved_epoch = EXPLICIT_KEY_EPOCH
    except Exception as e:  # noqa: BLE001 - fail closed, never raise
        return (False, "key unavailable for verification: %s: %s"
                % (type(e).__name__, e))
    try:
        prev_roots = envelope.get("previous_roots") or []
        body = _roots_decl_body(
            version,
            [_resolve_declared(e) for e in roots],
            [_resolve_declared(e) for e in prev_roots
             if isinstance(e, str)],
            envelope.get("previous_digest") or "",
            envelope.get("operator_id") or "",
            envelope.get("reason") or "",
            declared_at, key_epoch)
    except Exception as e:  # noqa: BLE001 - fail closed, never raise
        return (False, "declaration body malformed: %s: %s"
                % (type(e).__name__, e))
    expected = _roots_decl_mac(key_bytes, body)
    if not hmac.compare_digest(expected, mac):
        return (False, "declaration mismatch: the declared watch roots "
                "do not match their declaration MAC (roots, operator, "
                "reason, or declaration history rewritten -- or "
                "forged)")
    # The MAC verified: the presented key_epoch is now authenticated.
    now_epoch = (resolved_epoch if current_epoch is None
                 else current_epoch)
    if key_epoch != now_epoch:
        return (False, "stale_declaration_epoch: the declaration was "
                "made under key epoch %r but the current key epoch is "
                "%r -- the deployment key rotated (or the declaration "
                "was moved across deployments). Re-declare the watch "
                "roots under the current key epoch."
                % (key_epoch, now_epoch))
    return (True, "")


def _untrusted_declared_watch_roots(envelope):
    """Best-effort resolved roots from an UNVERIFIED declaration.

    Used only to shape the fail-closed report: entries that are not
    strings are dropped (they cannot be trusted or even resolved).
    Never raises.
    """
    out = []
    try:
        roots = envelope.get("roots")
    except AttributeError:
        return out
    if not isinstance(roots, list):
        return out
    for entry in roots:
        if isinstance(entry, str) and entry:
            try:
                out.append(_resolve_declared(entry))
            except Exception:  # noqa: BLE001 - drop, never raise
                continue
    return out


def check_roots_declaration(configured_roots, declaration, *,
                            audit=None, run_id=None, hmac_key=None,
                            current_epoch=None):
    """Enforcement: compare the effective watch-root set against the
    last declared set.

    ``configured_roots``: the watch roots the sweep will actually
    walk -- the same ``(root, baseline)`` tuples ``sweep_run_dir``
    takes (or plain root paths). A non-path entry raises ValueError
    fail-closed (a mis-shaped configured root must never silently
    shrink the comparison).

    ``declaration``: the envelope from ``declare_watch_roots``, or
    None when no declaration is configured. None -> verdict
    ``"undeclared"`` with no events: the explicit downgrade, never
    silently treated as declared.

    Returns a report dict::

        {"verdict": "declared" | "undeclared" | "undeclared_change"
                    | "unverifiable",
         "declared_roots": [...], "effective_roots": [...],
         "added": [...], "removed": [...],
         "reason": <"" when declared/undeclared>,
         "events": [emitted event dicts]}

    - ``"declared"``: the effective set equals the declared set --
      quiet, zero events.
    - ``"undeclared_change"``: roots were added/removed out-of-band
      (or the config was edited directly) -- one LOUD
      ``artifact_sweep_roots_undeclared_change`` event naming the
      added/removed roots. Fail-closed: the sweep over the effective
      roots is unpinned/unverified, never silently swept as if it
      were the declared set.
    - ``"unverifiable"``: the declaration envelope failed
      verification (forged, damaged, stale key epoch, or key
      unavailable) -- one LOUD
      ``artifact_sweep_roots_undeclared_change`` event; the sweep is
      unverified.

    ``audit``: optional callable taking each emitted event dict
    (e.g. the executor's chained ``log.append``); when None the
    events are only returned in the report.
    """
    effective = _coverage_roots(configured_roots)
    if declaration is None:
        return {"verdict": "undeclared",
                "declared_roots": [],
                "effective_roots": list(effective),
                "added": [], "removed": [],
                "reason": ("no watch-root declaration configured: the "
                           "sweep is not verified against any declared "
                           "set"),
                "events": []}
    ok, reason = verify_roots_declaration(
        declaration, hmac_key=hmac_key, current_epoch=current_epoch)
    if not ok:
        declared = _untrusted_declared_watch_roots(declaration)
        ev = {"event": ROOTS_UNDECLARED_CHANGE_EVENT,
              "severity": "LOUD",
              "flag": "undeclared_roots_change",
              "run_id": run_id,
              "declared_roots": declared,
              "effective_roots": list(effective),
              "added": [],
              "removed": [],
              "reason": ("WATCH ROOTS UNVERIFIABLE: the watch-root "
                         "declaration envelope failed verification "
                         "(%s) -- the effective watch-root set cannot "
                         "be checked against a trusted declaration. "
                         "The sweep over these roots is UNVERIFIED "
                         "(fail-closed): it must never be read as a "
                         "declared-roots sweep. Re-declare the watch "
                         "roots through the declaration ceremony."
                         % reason),
              "ts": _utcnow_iso()}
        events = [ev]
        if audit is not None:
            audit(ev)
        return {"verdict": "unverifiable",
                "declared_roots": declared,
                "effective_roots": list(effective),
                "added": [], "removed": [],
                "reason": reason,
                "events": events}
    declared_set = set(declaration["roots"])
    effective_set = set(effective)
    added = sorted(effective_set - declared_set)
    removed = sorted(declared_set - effective_set)
    if not added and not removed:
        return {"verdict": "declared",
                "declared_roots": sorted(declared_set),
                "effective_roots": list(effective),
                "added": [], "removed": [],
                "reason": "",
                "events": []}
    ev = {"event": ROOTS_UNDECLARED_CHANGE_EVENT,
          "severity": "LOUD",
          "flag": "undeclared_roots_change",
          "run_id": run_id,
          "declared_roots": sorted(declared_set),
          "effective_roots": list(effective),
          "added": added,
          "removed": removed,
          "reason": ("WATCH ROOTS UNDECLARED CHANGE: the effective "
                     "watch-root set differs from the last declared "
                     "set (added: %s; removed: %s) -- roots were "
                     "added/removed out-of-band or the configuration "
                     "was edited directly. The sweep over these roots "
                     "is UNVERIFIED (fail-closed): a narrowed set must "
                     "never be swept as if it were the declared one. "
                     "Re-declare through the ceremony or restore the "
                     "declared configuration."
                     % (", ".join(added) if added else "none",
                        ", ".join(removed) if removed else "none")),
          "ts": _utcnow_iso()}
    events = [ev]
    if audit is not None:
        audit(ev)
    return {"verdict": "undeclared_change",
            "declared_roots": sorted(declared_set),
            "effective_roots": list(effective),
            "added": added,
            "removed": removed,
            "reason": ("effective roots differ from declared: added=%s "
                       "removed=%s" % (added, removed)),
            "events": events}


def verify_declaration_chained(log_path, envelope):
    """Auditor path: confirm a declaration's ceremony event is present
    in the chained audit log and the chain verifies end-to-end.

    Returns ``(True, "")`` when a chained
    ``artifact_sweep_roots_declared`` event carrying this
    declaration's digest exists AND the audit chain verifies.
    Returns ``(False, reason)`` -- LOUD, unmissable -- otherwise: a
    tampered or removed ceremony event breaks the chain, so
    tampering fails loudly, never silently. Never raises on
    unreadable or malformed logs: an unreadable log is a
    verification FAILURE (fail-closed), not an exception.
    """
    # Lazy import: gov.log must never import this module (cycle).
    from .log import read_entries, verify_chain
    try:
        digest = declaration_digest(envelope)
    except ValueError as e:
        return (False, "LOUD: cannot confirm a malformed declaration "
                "envelope: %s" % (e,))
    try:
        entries = read_entries(log_path)
    except Exception as e:  # noqa: BLE001 - fail closed, never raise
        return (False, "LOUD: audit log unreadable -- the declaration "
                "ceremony cannot be confirmed: %s: %s"
                % (type(e).__name__, e))
    found = [e for e in entries
             if isinstance(e, dict)
             and e.get("event") == ROOTS_DECLARED_EVENT
             and e.get("declaration_digest") == digest]
    if not found:
        return (False, "LOUD: no chained %s ceremony event matches "
                "declaration digest %s... -- the declaration was never "
                "ceremonially recorded, or the ceremony event was "
                "removed." % (ROOTS_DECLARED_EVENT, digest[:12]))
    try:
        ok, broken_seq, _count = verify_chain(str(log_path))
    except Exception as e:  # noqa: BLE001 - fail closed, never raise
        return (False, "LOUD: audit chain verification errored: %s: %s "
                "-- treating the ceremony as unconfirmed."
                % (type(e).__name__, e))
    if not ok:
        return (False, "LOUD: audit chain BROKEN at seq %s -- the %s "
                "ceremony event (or a later entry) was tampered with "
                "or removed. The declaration is NOT confirmed."
                % (broken_seq, ROOTS_DECLARED_EVENT))
    return (True, "")

