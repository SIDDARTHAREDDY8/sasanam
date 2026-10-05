#!/usr/bin/env python3
"""Test-subject pinning for the dead-controls CI gate (R32).

Bernstein #6073 mechanics, ADAPT pattern only (Apache-2.0; no code
copied -- this module is written from the pattern description).

The dead-controls gate analyzes the tree under test. Without pinning,
a concurrent writer can mutate the tree mid-run (TOCTOU): the gate
verifies one tree and reports on another. This module pins the subject
-- a content hash (sha256) of every file -- before the gate runs, and
the gate asserts the pin is invariant when it finishes. Any drift
(modified / added / removed file) fails the gate with the coded
refusal ``deadctrl-subject-mutated``.

Scope notes:

- The pin covers file CONTENTS only (not mtimes/atimes/ownership):
  a rebuild that reproduces bytes is the same subject.
- ``.git`` and ``__pycache__`` are excluded: version-control metadata
  and bytecode caches are not the subject.
- An unreadable file pins as ``"<unreadable>"`` rather than crashing
  the gate; it becoming readable (or vice versa) is drift.
- If the caller persists the manifest inside the subject root (the
  gate's ``--pin-subject`` flag), that path is excluded from the pin
  so the record itself is not drift.

Stdlib only. $0 spend. No network.
"""

from __future__ import annotations

import hashlib
import json
import os

EXCLUDED_DIRS = frozenset({".git", "__pycache__"})
UNREADABLE = "<unreadable>"


def _relpaths(root):
    """Sorted list of pinned relpaths under root."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            found.append(rel)
    return found


def _hash_file(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return UNREADABLE
    return digest.hexdigest()


def pin_tree(root, exclude=()):
    """Pin the tree: ({relpath: sha256}, digest).

    The digest is sha256 over the canonical ``relpath:hash`` listing,
    so it is deterministic for identical content.
    """
    excluded = set(exclude)
    manifest = {}
    for rel in _relpaths(root):
        if rel in excluded:
            continue
        manifest[rel] = _hash_file(os.path.join(root, rel))
    return manifest, tree_digest(manifest)


def tree_digest(manifest):
    """Deterministic digest of a manifest."""
    canonical = "\n".join("%s:%s" % (rel, manifest[rel])
                          for rel in sorted(manifest))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_tree(root, manifest, exclude=()):
    """[(relpath, kind)] drift vs the manifest.

    kind is one of "modified", "added", "removed". Empty list means
    the subject is invariant.
    """
    excluded = set(exclude)
    current = {}
    for rel in _relpaths(root):
        if rel in excluded:
            continue
        current[rel] = _hash_file(os.path.join(root, rel))
    diffs = []
    for rel in sorted(set(manifest) | set(current)):
        old, new = manifest.get(rel), current.get(rel)
        if old is None:
            diffs.append((rel, "added"))
        elif new is None:
            diffs.append((rel, "removed"))
        elif old != new:
            diffs.append((rel, "modified"))
    return diffs


def write_manifest(path, manifest, digest):
    """Persist a pin record (the gate's --pin-subject output)."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump({"version": 1, "digest": digest, "files": manifest},
                  handle, indent=1, sort_keys=True)
    os.replace(tmp, path)


def read_manifest(path):
    """Read a persisted pin record -> (manifest, digest)."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("version") != 1:
        raise ValueError("unsupported pin manifest version: %r"
                         % (data.get("version"),))
    return data["files"], data["digest"]
