"""Document classification labels for provenance-based egress gating.

Row-13 closure (wave-128 lane). The row-13 residual is authorized-channel
semantic exfiltration: a DLP-clean paraphrase of sensitive meaning
exfiltrated over an allowlisted, human-approved channel. Content-based
mitigation is provably non-viable here — empirically (benign paraphrases
overlap MORE lexically than malicious ones) and theoretically (Simmons'
prisoners' problem: a content-inspecting warden provably loses to a
paraphrase-capable encoder). No DLP vendor ships a per-secret paraphrase
detector.

This module takes the other viable direction: **labels, not content
inspection**. A classification label is a deployment assertion about a
document's sensitivity, attached to the *read event* (provenance), not
inferred from the *bytes*. When a run reads a labeled file, the run is
tainted with the label; subsequent egress is gated for human
declassification review. A paraphrase-capable encoder defeats content
inspection, but it cannot defeat a label — the label travels with the
read provenance, not the payload, so rewording, restructuring,
fragmenting, or re-encoding the meaning does not shed it.

What this is NOT:
- Not a content oracle. It never inspects egress payloads for meaning.
- Not automatic. Labels are deployment inputs (like DLP patterns): an
  unlabeled sensitive document is not protected. That is the honest
  residual, narrowed from "all semantic exfil" to "unlabeled content".
- Not a deny wall. The gate is require_approval (matching the
  F9/F15a ``read_sensitive`` precedent): the human reviews with
  provenance, then declassifies or rejects. Legitimate work is delayed
  by one approval, not blocked.

Levels are ordered: public < internal < restricted. The taint records
the maximum level read; the policy rule fires on any non-public taint.

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

LEVELS = ("public", "internal", "restricted")

_LEVEL_RANK = {name: i for i, name in enumerate(LEVELS)}

__all__ = ["LEVELS", "ClassificationRegistry", "rank_of", "is_valid_level"]


def is_valid_level(level):
    """True for a known classification level name."""
    return isinstance(level, str) and level in _LEVEL_RANK


def rank_of(level):
    """Numeric rank for ordering; unknown levels raise."""
    try:
        return _LEVEL_RANK[level]
    except (KeyError, TypeError):
        raise ValueError("unknown classification level: %r" % (level,))


def _normalize(path):
    """Normalize a sandbox-relative path for label lookup.

    Labels are keyed on the sandbox-relative resolved path (the same
    normalization ``ToolExecutor._resolved_path_for_policy`` produces),
    so a symlink inside the sandbox cannot dodge a label by spelling.
    """
    if path is None:
        return ""
    p = str(path).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    while p.startswith("/"):
        p = p[1:]
    return p


class ClassificationRegistry:
    """Deployment-owned mapping of sandbox-relative paths to labels.

    Lives on the ToolExecutor (``executor.classification``). The
    deployment labels sensitive documents; ``read_file`` consults the
    registry at read time and taints the run. Empty by default: no
    labels, no behavior change.
    """

    def __init__(self):
        self._labels = {}

    def label(self, path, level):
        """Label a sandbox-relative path. Overwrites any prior label."""
        if not is_valid_level(level):
            raise ValueError("unknown classification level: %r" % (level,))
        key = _normalize(path)
        if not key:
            raise ValueError("cannot label an empty path")
        self._labels[key] = level
        return level

    def unlabel(self, path):
        """Remove a label. No-op when unlabeled."""
        self._labels.pop(_normalize(path), None)

    def level_for(self, path):
        """Return the level string for a path, or None when unlabeled."""
        return self._labels.get(_normalize(path))

    def clear(self):
        """Remove all labels (tests)."""
        self._labels.clear()

    def __len__(self):
        return len(self._labels)

    def __repr__(self):
        return "ClassificationRegistry(%d labels)" % len(self._labels)
