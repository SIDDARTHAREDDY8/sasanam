"""Artifact inventory with hash-chained registration and egress verdicts.

Row-12 build (wave-130 lane). The row-12 residual is the missing
artifact layer: no inventory of what artifacts (files) an agent
produced, and no exfil-shaped *outbound* detection tuned to model
artifacts. Content-based detection cannot separate a weight shard
from a benign firmware blob (both are large hex; pinned red by
``evals/row12_weight_exfil_break.py`` e1/e3), so this module takes the
identity-based direction: know every artifact the run produced, and
gate egress that references one.

What it does:
- ``ArtifactInventory``: every file an agent writes via the governed
  ``write_file`` path is registered — sandbox-relative path, SHA-256
  of the bytes actually written, size, creating agent, run id,
  timestamp, and the path's classification label at registration time
  (if any). Registrations form a hash-chained sub-chain
  (``prev_digest`` linkage, mirroring the DecisionBOM pattern): a
  tampered registration breaks ``verify_chain``.
- ``check_egress``: given a file reference found in egress args,
  returns a verdict:
    * not in inventory        -> ``unknown``  (flag unknown_artifact_egress)
    * registered, hash differs -> ``tampered`` (flag artifact_tampered)
    * registered, label restricted -> ``restricted``
      (flag artifact_restricted_egress)
    * otherwise               -> ``clean`` (no signal)

What this is NOT:
- Not a content oracle. It never inspects payload bytes for meaning;
  it keys on file identity (path + hash).
- Not a sandbox escape detector. The inventory only sees writes
  through the governed executor path. A compromised executor, a
  side-channel write (direct disk access outside the tool), or an
  artifact smuggled in before the run is outside the trust boundary —
  though the *egress* half still catches the reference: a file that
  exists on disk but was never registered trips ``unknown`` when an
  egress names it. The honest ceiling is that the inventory cannot
  vouch for bytes it never saw written.
- Not cross-run. The inventory is run-scoped (like the row-13
  classification taint). A deployment-owned persistent manifest
  (path -> sha256 at deployment) is the documented v1 follow-up.

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

__all__ = [
    "ArtifactRecord",
    "ArtifactInventory",
    "normalize_path",
    "UNKNOWN_FLAG",
    "TAMPERED_FLAG",
    "RESTRICTED_FLAG",
]

UNKNOWN_FLAG = "unknown_artifact_egress"
TAMPERED_FLAG = "artifact_tampered"
RESTRICTED_FLAG = "artifact_restricted_egress"

_INVENTORY_VERSION = 1


def _canonical(obj):
    """Canonical JSON for hashing (stable key order, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=repr)


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path):
    """Normalize a sandbox-relative path for inventory keys.

    Same normalization as ``gov.classification._normalize`` (kept
    local so this module has no import cycle): the inventory and the
    label registry must agree on keys, so a labeled path written by
    the agent resolves to the same record the egress check looks up.
    """
    if path is None:
        return ""
    p = str(path).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    while p.startswith("/"):
        p = p[1:]
    return p


class ArtifactRecord(object):
    """One registered artifact."""

    def __init__(self, *, path, sha256, size, agent_id, run_id,
                 classification=None, timestamp=None,
                 prev_digest=""):
        self.path = path
        self.sha256 = sha256
        self.size = size
        self.agent_id = agent_id
        self.run_id = run_id
        self.classification = classification
        self.timestamp = timestamp or _utcnow_iso()
        self.prev_digest = prev_digest
        self.record_digest = self._digest()

    def _payload(self):
        return {
            "inventory_version": _INVENTORY_VERSION,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "classification": self.classification,
            "timestamp": self.timestamp,
            "prev_digest": self.prev_digest,
        }

    def _digest(self):
        return _sha256_hex(_canonical(self._payload()))

    def to_dict(self):
        d = self._payload()
        d["record_digest"] = self.record_digest
        return d

    def __repr__(self):
        return ("ArtifactRecord(path=%r, sha256=%s..., size=%d, "
                "classification=%r)" % (
                    self.path, self.sha256[:12], self.size,
                    self.classification))


class ArtifactInventory(object):
    """Run-scoped registry of agent-produced files.

    Lives on the ToolExecutor (``executor.artifacts``). The executor's
    write hook registers every successful ``write_file``; the egress
    check consults the registry. Empty by default: no writes, no
    behavior change.
    """

    def __init__(self):
        self._records = {}  # normalized path -> latest ArtifactRecord
        # Append-only registration EVENT log (the hash-chained trail).
        # Re-registration appends a new event; _records keeps only the
        # latest per path for lookup. The chain is over events, so a
        # second write to the same path cannot break the linkage.
        self._chain = []
        self._head_digest = ""

    def register(self, path, *, sha256, size, agent_id, run_id,
                 classification=None):
        """Register (or re-register) an artifact.

        Re-registration overwrites: a second governed write to the
        same path is a new artifact version, and the inventory tracks
        the latest bytes (the egress hash check compares against the
        latest registration). Returns the record.
        """
        key = normalize_path(path)
        if not key:
            raise ValueError("cannot register an empty path")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ValueError("sha256 must be a 64-char hex digest")
        rec = ArtifactRecord(
            path=key, sha256=sha256, size=int(size),
            agent_id=agent_id, run_id=run_id,
            classification=classification,
            prev_digest=self._head_digest)
        self._records[key] = rec
        self._chain.append(rec)
        self._head_digest = rec.record_digest
        return rec

    def lookup(self, path):
        """Return the record for a path, or None when unregistered."""
        return self._records.get(normalize_path(path))

    def verify_chain(self):
        """Verify the registration sub-chain. Returns (ok, reason).

        Checks: every registration EVENT's digest matches its payload,
        and the prev_digest linkage is intact in registration order. A
        dropped, reordered, or edited event fails the chain.
        """
        prev = ""
        for i, rec in enumerate(self._chain):
            if rec.record_digest != rec._digest():
                return False, ("event %d (%r) digest mismatch: payload "
                               "tampered" % (i, rec.path))
            if rec.prev_digest != prev:
                return False, ("event %d (%r) linkage broken: prev_digest "
                               "does not match the previous event"
                               % (i, rec.path))
            prev = rec.record_digest
        if prev != self._head_digest:
            return False, "head digest does not match the last event"
        return True, "%d events, chain intact" % len(self._chain)

    def check_egress(self, path, *, sha256_now=None, current_label=None):
        """Verdict for an egress that references ``path``.

        Returns a dict with ``status`` (unknown/tampered/restricted/
        clean), ``flag`` (the audit/policy flag, or None when clean),
        and ``detail``. ``sha256_now`` is the hash of the bytes
        currently on disk (None when the file cannot be read — then
        the tamper check is skipped, fail-open on unreadable, exactly
        like the lineage hook's discipline). ``current_label`` is the
        deployment's *current* label for the path; the verdict uses
        the more restrictive of the registration-time and current
        labels (a label added after the write still gates).
        """
        key = normalize_path(path)
        rec = self._records.get(key)
        if rec is None:
            return {
                "status": "unknown",
                "flag": UNKNOWN_FLAG,
                "path": key,
                "detail": ("Egress references %r, which has no artifact "
                           "inventory record: it was not written through "
                           "the governed write path this run."
                           % (key,)),
            }
        if (sha256_now is not None
                and sha256_now != rec.sha256):
            return {
                "status": "tampered",
                "flag": TAMPERED_FLAG,
                "path": key,
                "detail": ("Egress references %r, but the bytes on disk "
                           "(sha256 %s...) no longer match the registered "
                           "artifact (sha256 %s...): the registration is "
                           "stale."
                           % (key, sha256_now[:12], rec.sha256[:12])),
            }
        label = _more_restrictive(rec.classification, current_label)
        if label == "restricted":
            return {
                "status": "restricted",
                "flag": RESTRICTED_FLAG,
                "path": key,
                "label": label,
                "detail": ("Egress references registered artifact %r "
                           "classified %r." % (key, label)),
            }
        return {
            "status": "clean",
            "flag": None,
            "path": key,
            "label": label,
            "detail": ("Egress references registered artifact %r "
                       "(label %r): no artifact signal." % (key, label)),
        }

    def __len__(self):
        return len(self._records)

    def __repr__(self):
        return "ArtifactInventory(%d records)" % len(self._records)


def _more_restrictive(a, b):
    """Return the more restrictive of two classification labels.

    Levels are public < internal < restricted; None means unlabeled
    (least restrictive). Unknown strings are treated as unlabeled —
    this module never invents a restriction from a label it does not
    understand.
    """
    rank = {"public": 0, "internal": 1, "restricted": 2}
    ra = rank.get(a, -1)
    rb = rank.get(b, -1)
    if ra >= rb:
        return a
    return b
