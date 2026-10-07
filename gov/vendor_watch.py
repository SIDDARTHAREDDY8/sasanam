"""Vendor-update sentinel ("the watcher") — v1.

The pressure-test question is "who tracks silent vendor updates before
they go live?" This module is the named owner of that question.

Watcher v1 keeps approved-state snapshots for governed vendor
artifacts (MCP server configs, skill bundles, tool manifests, policy
packs), diffs them against current state on scan, and fails closed:
every unapproved change routes to the human approval queue as a typed
decision, and the changed artifact's tools are DENIED at pre-execution
until a human approves the new snapshot. An update whose content
cannot be verified fails closed outright.

Design notes
------------
* Stdlib only. Deterministic: no clock (callers pass ``now``), no
  network, no randomness (except uuid4 ids, which are data).
* The watcher never executes anything and never mutates vendor state:
  it detects, holds for approval, and denies. Automatic remediation
  is out of scope.
* Sources are deployment-owned and deployment-vouched
  (``mcp_discovery_trust`` discipline): the watcher checks binding and
  shape, it cannot make a source file honest. A lying deployment (or
  a compromised source) is outside the trust boundary — stated here,
  not hidden.
* Detection vocabulary lives in ``gov/decision_codes.py`` under the
  ``vendor-watch`` domain; this module raises the same code strings
  via the code-first ``VendorWatchError``.

Scheduled scans
---------------
The watcher is scan-triggered; continuous watching is deployment
scheduling. The documented hook point is the ``scan`` subcommand —
exit 0 with a JSON summary on a completed scan (detections are data,
not errors), exit 2 on operational failure (unreadable state dir,
malformed source, evidence misconfiguration). Example cron entry
(hourly, deployment-owned source file)::

    17 * * * * GOV_RUN_ROOT=/var/lib/sasanam \
        GOV_WATCH_SIGN_SEED=$(cat /etc/sasanam/watch-seed.hex) \
        /opt/sasanam/.gov-venv/bin/python -m gov.vendor_watch scan \
        --source /etc/sasanam/vendor-sources.json \
        --audit-log /var/lib/sasanam/audit.jsonl \
        >>/var/log/sasanam/watcher-scan.log 2>&1

Detections route to the human approval queue via
``enqueue_detections`` (the deployment wires queueing + alerting into
its own scheduler hook); the gate denies unapproved tools whether or
not a human has seen the queue yet.

$0 spend, synthetic/local only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Vocabulary (mirrored in gov/decision_codes.py, domain 'vendor-watch').
# ---------------------------------------------------------------------------

VENDOR_UPDATE_DETECTED = "vendor-update-detected"
VENDOR_HASH_DRIFT = "vendor-hash-drift"
VENDOR_ARTIFACT_NEW = "vendor-artifact-new"
VENDOR_ARTIFACT_REMOVED = "vendor-artifact-removed"
VENDOR_UPDATE_UNVERIFIABLE = "vendor-update-unverifiable"

DETECTOR_VERSION = "1.0.0"
DETECTION_DOMAIN = "vendor-watch"

#: Domain separation for signed detection records.
SIG_DOMAIN = b"vendor-watch-detection/v1"

_OUTCOMES = (
    "NO_CHANGE",
    "VERSION_BUMP",
    "HASH_DRIFT",
    "ARTIFACT_NEW",
    "ARTIFACT_REMOVED",
    "UNVERIFIABLE",
)

_OUTCOME_CODE = {
    "VERSION_BUMP": VENDOR_UPDATE_DETECTED,
    "HASH_DRIFT": VENDOR_HASH_DRIFT,
    "ARTIFACT_NEW": VENDOR_ARTIFACT_NEW,
    "ARTIFACT_REMOVED": VENDOR_ARTIFACT_REMOVED,
    "UNVERIFIABLE": VENDOR_UPDATE_UNVERIFIABLE,
}

__all__ = [
    "VENDOR_UPDATE_DETECTED",
    "VENDOR_HASH_DRIFT",
    "VENDOR_ARTIFACT_NEW",
    "VENDOR_ARTIFACT_REMOVED",
    "VENDOR_UPDATE_UNVERIFIABLE",
    "DETECTOR_VERSION",
    "DETECTION_DOMAIN",
    "VendorWatchError",
    "VendorWatchSourceError",
    "ArtifactSource",
    "DictSource",
    "JsonFileSource",
    "VendorWatchStore",
    "canonical_bytes",
    "content_digest",
    "tools_digest",
    "snapshot_artifact",
    "scan",
    "baseline",
    "approve_pending",
    "reject_pending",
    "VendorWatchGate",
    "signed_detection_record",
    "verify_detection_record",
    "log_detection",
    "enqueue_detections",
    "main",
]


class VendorWatchError(Exception):
    """Fail-closed watcher refusal. ``code`` is the vocabulary."""

    def __init__(self, code, detail=""):
        super(VendorWatchError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


class VendorWatchSourceError(Exception):
    """A source could not supply current state (unreachable/malformed)."""


def _refuse(code, detail=""):
    raise VendorWatchError(code, detail)


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

def canonical_bytes(obj):
    """JCS-shaped canonical bytes (same form the offline bundle uses)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def content_digest(content):
    """SHA-256 over canonical JSON of the artifact content.

    Strict: no ``default=str`` coercion — content that is not cleanly
    JSON-serializable is UNVERIFIABLE (fail closed), never silently
    coerced (a str() fallback would hash memory addresses and could
    mask real changes).
    """
    try:
        raw = json.dumps(content, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise VendorWatchSourceError(
            "artifact content is not JSON-serializable: %s" % (exc,))
    return _sha256_hex(raw)


def tools_digest(tools):
    """SHA-256 over the sorted canonical tool list.

    Each tool contributes name + description + schema; a
    "documentation-only" change that rewrites tool semantics is a
    content change here.
    """
    if not isinstance(tools, list):
        raise VendorWatchSourceError("tools must be a list")
    norm = []
    for tool in tools:
        if not isinstance(tool, dict) or not tool.get("name"):
            raise VendorWatchSourceError(
                "each tool must be a mapping with a name")
        norm.append({
            "name": tool["name"],
            "description": tool.get("description", ""),
            "schema": tool.get("schema", {}),
        })
    norm.sort(key=lambda t: json.dumps(t, sort_keys=True))
    return _sha256_hex(canonical_bytes(norm))


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class ArtifactSource(object):
    """Protocol: list_current() -> [artifact mappings].

    Each artifact: {"artifact_id": str, "kind": str, "version": str,
    "content": <JSON>, "tools": [ {"name","description","schema"} ]}.
    """

    def list_current(self):
        raise NotImplementedError


def _check_artifact_shape(artifact):
    if not isinstance(artifact, dict):
        raise VendorWatchSourceError(
            "artifact must be a mapping, got %s" % type(artifact).__name__)
    for field in ("artifact_id", "kind", "version"):
        value = artifact.get(field)
        if not isinstance(value, str) or not value.strip():
            raise VendorWatchSourceError(
                "artifact.%s must be a non-empty string" % field)
    if "content" not in artifact:
        raise VendorWatchSourceError("artifact %r has no content"
                                     % artifact.get("artifact_id"))
    if "tools" not in artifact:
        raise VendorWatchSourceError("artifact %r has no tools list"
                                     % artifact.get("artifact_id"))
    return artifact


class DictSource(ArtifactSource):
    """In-memory source (tests, operators, small deployments)."""

    def __init__(self, artifacts):
        if not isinstance(artifacts, list):
            raise VendorWatchSourceError("artifacts must be a list")
        self._artifacts = [_check_artifact_shape(dict(a))
                           for a in artifacts]

    def list_current(self):
        return [dict(a) for a in self._artifacts]


class JsonFileSource(ArtifactSource):
    """Deployment-owned JSON file: {"artifacts": [...]}.

    The file is deployment-owned and deployment-vouched; the watcher
    checks binding and shape, it cannot make the file honest.
    """

    def __init__(self, path):
        self.path = path

    def list_current(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            raise VendorWatchSourceError(
                "cannot read source %r: %s" % (self.path, exc))
        if not isinstance(data, dict) or not isinstance(
                data.get("artifacts"), list):
            raise VendorWatchSourceError(
                "source %r must be {\"artifacts\": [...]}" % (self.path,))
        seen = set()
        out = []
        for artifact in data["artifacts"]:
            artifact = _check_artifact_shape(artifact)
            if artifact["artifact_id"] in seen:
                raise VendorWatchSourceError(
                    "duplicate artifact_id %r in source"
                    % artifact["artifact_id"])
            seen.add(artifact["artifact_id"])
            out.append(artifact)
        return out


# ---------------------------------------------------------------------------
# Store (atomic file writes; run-dir-scoped state)
# ---------------------------------------------------------------------------

_SNAPSHOTS_FILE = "vendor_watch_snapshots.json"
_PENDING_FILE = "vendor_watch_pending.json"
_META_FILE = "vendor_watch_meta.json"


def _default_state_dir():
    root = os.environ.get("GOV_WATCH_STATE_DIR") or os.path.join(
        os.environ.get("GOV_RUN_ROOT", "/tmp/gov-run"), "vendor_watch")
    return root


def _utcnow_iso(now=None):
    if now is not None:
        return now
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True, indent=2,
                           ensure_ascii=True))
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class VendorWatchStore(object):
    """Snapshot + pending registry backed by atomic JSON files."""

    def __init__(self, state_dir=None):
        self.state_dir = state_dir or _default_state_dir()
        os.makedirs(self.state_dir, exist_ok=True)
        self.snapshots = self._read(_SNAPSHOTS_FILE)
        self.pending = self._read(_PENDING_FILE)
        self.meta = self._read(_META_FILE)
        if "last_scan_status" not in self.meta:
            self.meta["last_scan_status"] = "never"

    def _path(self, name):
        return os.path.join(self.state_dir, name)

    def _read(self, name):
        path = self._path(name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise VendorWatchError(
                VENDOR_UPDATE_UNVERIFIABLE,
                "watcher state file %r unreadable: %s" % (name, exc))
        if not isinstance(data, dict):
            raise VendorWatchError(
                VENDOR_UPDATE_UNVERIFIABLE,
                "watcher state file %r malformed" % (name,))
        return data

    def save(self):
        _atomic_write(self._path(_SNAPSHOTS_FILE), self.snapshots)
        _atomic_write(self._path(_PENDING_FILE), self.pending)
        _atomic_write(self._path(_META_FILE), self.meta)


def snapshot_artifact(artifact, approved_by, approved_at,
                      status="approved"):
    """Build an approved-state snapshot for one artifact."""
    if not approved_by or not isinstance(approved_by, str):
        raise ValueError("approved_by must be a non-empty string")
    return {
        "artifact_id": artifact["artifact_id"],
        "kind": artifact["kind"],
        "version": artifact["version"],
        "content_hash": content_digest(artifact["content"]),
        "tools_digest": tools_digest(artifact["tools"]),
        "approved_by": approved_by,
        "approved_at": approved_at,
        "detector_version": DETECTOR_VERSION,
        "status": status,
    }


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def _diff_tools(old_tools_digest, new_tools_digest):
    return {
        "tools_digest_changed": new_tools_digest != old_tools_digest,
    }


_OPEN_STATUSES = ("pending", "refused")


def _is_open(rec):
    """A pending record still holding the artifact denied."""
    return rec.get("status") in _OPEN_STATUSES


def _diff_one(snapshot, current, now):
    """Classify one artifact; returns (outcome, detection|None)."""
    artifact_id = snapshot["artifact_id"]
    try:
        new_hash = content_digest(current["content"])
        new_tools = current["tools"]
        new_tools_digest = tools_digest(new_tools)  # shape-check now
    except VendorWatchSourceError as exc:
        return "UNVERIFIABLE", _mk_detection(
            artifact_id, snapshot["kind"], "UNVERIFIABLE", now,
            snapshot["version"], snapshot["content_hash"],
            current.get("version"), None,
            {"error": str(exc)})
    version_changed = current["version"] != snapshot["version"]
    hash_changed = new_hash != snapshot["content_hash"]
    tools_changed = new_tools_digest != snapshot["tools_digest"]
    if not version_changed and not hash_changed and not tools_changed:
        return "NO_CHANGE", None
    if version_changed and not hash_changed and not tools_changed:
        outcome = "VERSION_BUMP"
    elif not version_changed and (hash_changed or tools_changed):
        # The silent-update case: same version, new bytes and/or new
        # tool semantics.
        outcome = "HASH_DRIFT"
    else:
        outcome = "VERSION_BUMP"
    summary = {
        "old_version": snapshot["version"],
        "new_version": current["version"],
        "old_content_hash": snapshot["content_hash"],
        "new_content_hash": new_hash,
        "old_tools_digest": snapshot["tools_digest"],
        "new_tools_digest": tools_digest(new_tools),
    }
    summary.update(_diff_tools(snapshot["tools_digest"], new_tools_digest))
    return outcome, _mk_detection(
        artifact_id, snapshot["kind"], outcome, now,
        snapshot["version"], snapshot["content_hash"],
        current["version"], new_hash, summary)


def _detection(artifact_id, kind, outcome, now, old, new, diff_summary):
    return {
        "detection_id": uuid.uuid4().hex,
        "detector": DETECTION_DOMAIN,
        "detector_version": DETECTOR_VERSION,
        "detected_at": _utcnow_iso(now),
        "artifact_id": artifact_id,
        "kind": kind,
        "outcome": outcome,
        "code": _OUTCOME_CODE[outcome],
        "old": old,
        "new": new,
        "diff_summary": diff_summary,
    }


def _mk_detection(artifact_id, kind, outcome, now, old_version, old_hash,
                  new_version, new_hash, diff_summary):
    """Assemble a detection record from version/hash pairs."""
    return _detection(
        artifact_id, kind, outcome, now,
        old={"version": old_version, "content_hash": old_hash},
        new={"version": new_version, "content_hash": new_hash},
        diff_summary=diff_summary)


def _pending_key(detection):
    new = detection.get("new") or {}
    # Spec: artifact_id + new content hash. Hash-absent outcomes
    # (REMOVED, UNVERIFIABLE, source-level) namespace by outcome so
    # they never collide with each other.
    return "%s\x00%s" % (
        detection["artifact_id"],
        new.get("content_hash") or detection["outcome"])


def _check_evidence_args(audit_log, sign_seed):
    if (audit_log is None) != (sign_seed is None):
        raise ValueError(
            "evidence requires both audit_log and sign_seed — "
            "neither is optional")
    return audit_log is not None


def _produce_evidence(detection, audit_log, sign_seed):
    """Sign the detection and append it to the audit log.

    Both artifacts are produced for every detection; neither is
    optional once evidence is enabled. The signature covers the
    detection as-logged (the ``evidence`` attachment is added after
    signing, over a snapshot copy, so verification always checks the
    exact signed bytes).
    """
    envelope = signed_detection_record(dict(detection), sign_seed)
    entry = log_detection(audit_log, detection)
    envelope["log_seq"] = entry.get("seq")
    detection["evidence"] = envelope
    return envelope


def _register_pending(store, detection, now):
    """Idempotent pending registration; returns the pending record."""
    key = _pending_key(detection)
    for pending_id, rec in store.pending.items():
        if rec.get("pending_key") == key and _is_open(rec):
            return rec  # already held — never a second record
    pending_id = uuid.uuid4().hex
    rec = {
        "pending_id": pending_id,
        "pending_key": key,
        "detection": detection,
        "status": "pending",
        "queued": False,
        "registered_at": _utcnow_iso(now),
        "decided_by": None,
        "decided_at": None,
        "reason": None,
    }
    store.pending[pending_id] = rec
    return rec


def _resolve_by_rollback(store, artifact_id, current):
    """A refused/pending artifact matching its snapshot again resolves."""
    snap = store.snapshots.get(artifact_id)
    if snap is None:
        return False
    try:
        if (current["version"] == snap["version"]
                and content_digest(current["content"])
                == snap["content_hash"]
                and tools_digest(current["tools"])
                == snap["tools_digest"]):
            for rec in store.pending.values():
                if (rec["detection"]["artifact_id"] == artifact_id
                        and _is_open(rec)):
                    rec["status"] = "resolved"
                    rec["decided_by"] = "watcher:rollback-observed"
                    rec["reason"] = ("current state matches the approved "
                                     "snapshot again")
            return True
    except VendorWatchSourceError:
        pass
    return False


def scan(store, source, now=None, audit_log=None, sign_seed=None):
    """Diff current state against approved snapshots.

    Returns the list of detections (empty when clean). Every
    non-NO_CHANGE outcome registers an idempotent pending record.
    A source-level failure yields one ``vendor-update-unverifiable``
    detection and marks the scan unverifiable (fail closed — the gate
    denies watched artifacts until a clean scan lands).

    Evidence: when ``audit_log`` and ``sign_seed`` are both given,
    every returned detection is signed and log-appended (neither is
    optional — pass neither to disable evidence).
    """
    want_evidence = _check_evidence_args(audit_log, sign_seed)
    try:
        current = {a["artifact_id"]: a for a in source.list_current()}
    except VendorWatchSourceError as exc:
        store.meta["last_scan_status"] = "unverifiable"
        store.save()
        detection = _mk_detection(
            "*", "source", "UNVERIFIABLE", now, None, None, None,
            None, {"error": str(exc)})
        rec = _register_pending(store, detection, now)
        if want_evidence:
            _produce_evidence(rec["detection"], audit_log, sign_seed)
        store.save()
        return [rec["detection"]]
    detections = []
    for artifact_id, artifact in sorted(current.items()):
        snap = store.snapshots.get(artifact_id)
        if snap is None:
            if _resolve_by_rollback(store, artifact_id, artifact):
                continue
            try:
                new_hash = content_digest(artifact["content"])
                new_td = tools_digest(artifact["tools"])
            except VendorWatchSourceError as exc:
                detection = _mk_detection(
                    artifact_id, artifact["kind"], "UNVERIFIABLE", now,
                    None, None, artifact.get("version"), None,
                    {"error": str(exc)})
            else:
                detection = _mk_detection(
                    artifact_id, artifact["kind"], "ARTIFACT_NEW", now,
                    None, None, artifact["version"], new_hash,
                    {"note": "artifact not in the approved registry",
                     "new_tools_digest": new_td})
            rec = _register_pending(store, detection, now)
            detections.append(rec["detection"])
            continue
        if _resolve_by_rollback(store, artifact_id, artifact):
            continue
        outcome, detection = _diff_one(snap, artifact, now)
        if detection is not None:
            rec = _register_pending(store, detection, now)
            detections.append(rec["detection"])
    for artifact_id, snap in sorted(store.snapshots.items()):
        if artifact_id not in current:
            detection = _mk_detection(
                artifact_id, snap["kind"], "ARTIFACT_REMOVED", now,
                snap["version"], snap["content_hash"], None, None,
                {"note": "artifact vanished from the source"})
            rec = _register_pending(store, detection, now)
            detections.append(rec["detection"])
    store.meta["last_scan_status"] = (
        "clean" if not detections else "detections")
    if want_evidence:
        for detection in detections:
            _produce_evidence(detection, audit_log, sign_seed)
    store.save()
    return detections


def baseline(store, source, now=None, audit_log=None, sign_seed=None):
    """First-run flow: snapshot current state, ALL pending approval.

    Nothing auto-approves. Tools of baselined-but-unapproved artifacts
    are DENIED until a human approves each snapshot. Returns the list
    of pending-baseline detections (one per artifact). Evidence args
    behave as in :func:`scan`.
    """
    want_evidence = _check_evidence_args(audit_log, sign_seed)
    current = source.list_current()  # raises VendorWatchSourceError: loud
    detections = []
    for artifact in current:
        artifact_id = artifact["artifact_id"]
        snap = snapshot_artifact(artifact, approved_by="baseline:unapproved",
                                 approved_at=_utcnow_iso(now),
                                 status="pending-baseline")
        store.snapshots[artifact_id] = snap
        detection = _mk_detection(
            artifact_id, artifact["kind"], "ARTIFACT_NEW", now,
            None, None, artifact["version"], snap["content_hash"],
            {"note": "first-run baseline; held for human approval",
             "new_tools_digest": snap["tools_digest"]})
        rec = _register_pending(store, detection, now)
        detections.append(rec["detection"])
    store.meta["last_scan_status"] = "baseline-pending"
    if want_evidence:
        for detection in detections:
            _produce_evidence(detection, audit_log, sign_seed)
    store.save()
    return detections


def approve_pending(store, pending_id, approved_by, now=None):
    """Human approves a pending change; returns the new snapshot."""
    if not approved_by or not isinstance(approved_by, str):
        raise ValueError("approve_pending requires an explicit approved_by")
    rec = store.pending.get(pending_id)
    if rec is None:
        raise KeyError("unknown pending_id %r" % (pending_id,))
    if not _is_open(rec):
        raise ValueError("pending %r already %s" % (
            pending_id, rec["status"]))
    detection = rec["detection"]
    artifact_id = detection["artifact_id"]
    outcome = detection["outcome"]
    if outcome == "UNVERIFIABLE":
        raise ValueError(
            "approve_pending refused: outcome is UNVERIFIABLE — fix the "
            "source and re-scan so the content can be verified, then "
            "approve the new detection; approving blind content would "
            "bypass fail-closed")
    if outcome == "ARTIFACT_REMOVED":
        # The human confirms the removal: drop the snapshot.
        store.snapshots.pop(artifact_id, None)
        new_snap = None
    else:
        old = store.snapshots.get(artifact_id, {})
        new_snap = {
            "artifact_id": artifact_id,
            "kind": detection["kind"],
            "version": detection["new"]["version"],
            "content_hash": detection["new"]["content_hash"],
            "tools_digest": (detection["diff_summary"].get(
                "new_tools_digest") or old.get("tools_digest", "")),
            "approved_by": approved_by,
            "approved_at": _utcnow_iso(now),
            "detector_version": DETECTOR_VERSION,
            "status": "approved",
        }
        store.snapshots[artifact_id] = new_snap
    rec["status"] = "approved"
    rec["decided_by"] = approved_by
    rec["decided_at"] = _utcnow_iso(now)
    store.save()
    return new_snap


def reject_pending(store, pending_id, decided_by, reason, now=None):
    """Human refuses a pending change; the artifact stays denied until
    its current state matches the approved snapshot again (scan
    auto-resolves on rollback)."""
    if not decided_by or not isinstance(decided_by, str):
        raise ValueError("reject_pending requires an explicit decided_by")
    if not reason or not isinstance(reason, str):
        raise ValueError("reject_pending requires a reason")
    rec = store.pending.get(pending_id)
    if rec is None:
        raise KeyError("unknown pending_id %r" % (pending_id,))
    if not _is_open(rec):
        raise ValueError("pending %r already %s" % (
            pending_id, rec["status"]))
    rec["status"] = "refused"
    rec["decided_by"] = decided_by
    rec["decided_at"] = _utcnow_iso(now)
    rec["reason"] = reason
    store.save()
    return rec


# ---------------------------------------------------------------------------
# Gate (pre-execution seam)
# ---------------------------------------------------------------------------

class VendorWatchGate(object):
    """Pre-execution check: deny tools of changed-unapproved artifacts.

    Wire ``check_tool`` into the invocation path (e.g. alongside
    ``mcp_invocation_authz.authorize``). The gate never executes
    anything; it only refuses.
    """

    def __init__(self, store):
        self.store = store

    def _unresolved_pending(self, artifact_id):
        for rec in self.store.pending.values():
            if (rec["detection"]["artifact_id"] == artifact_id
                    and _is_open(rec)):
                return rec
        return None

    def check_tool(self, artifact_id, tool=None):
        """Allow or refuse a tool call on a watched artifact.

        Returns {"verdict": "allow", ...}; raises VendorWatchError
        (typed decision code) on any unapproved change, removal,
        unverifiable update, or unapproved baseline. Artifacts the
        watcher never saw are NOT governed here (the watcher is not
        the sole authority) — they pass through.
        """
        if self.store.meta.get("last_scan_status") == "unverifiable":
            _refuse(VENDOR_UPDATE_UNVERIFIABLE,
                    "last watcher scan could not verify source state; "
                    "blindness fails closed")
        rec = self._unresolved_pending(artifact_id)
        if rec is not None:
            _refuse(rec["detection"]["code"],
                    "artifact %r has an unresolved %s detection "
                    "(pending_id %s)" % (
                        artifact_id, rec["detection"]["outcome"],
                        rec["pending_id"]))
        snap = self.store.snapshots.get(artifact_id)
        if snap is None:
            # Not watched by this registry: not our verdict.
            return {"verdict": "allow", "watcher": "not-watched"}
        if snap.get("status") == "pending-baseline":
            _refuse(VENDOR_ARTIFACT_NEW,
                    "artifact %r baselined but not yet human-approved"
                    % (artifact_id,))
        return {"verdict": "allow", "artifact_id": artifact_id,
                "version": snap["version"],
                "content_hash": snap["content_hash"]}


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def signed_detection_record(detection, seed):
    """Ed25519-signed detection envelope (domain-separated).

    Signs via ``gov.signing.Ed25519Signer`` when available, else the
    ``gov.ed25519`` primitive directly. ``seed`` is a 32-byte operator
    seed. Returns {"record", "signature", "pubkey"} (hex). The envelope
    is evidence: an auditor verifies it with
    ``verify_detection_record`` without the engine.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    seed = bytes(seed)
    body = SIG_DOMAIN + canonical_bytes(detection)
    try:
        from gov import signing as _signing
        signer = _signing.Ed25519Signer(seed)
        sig, pub = signer.sign(body), signer.public_key
    except ImportError:
        from gov import ed25519 as _ed
        sig, pub = _ed.sign(seed, body), _ed.publickey(seed)
    return {
        "record": detection,
        "signature": sig.hex(),
        "pubkey": pub.hex(),
    }


def verify_detection_record(envelope):
    """Verify a signed detection envelope. True/False, never raises on
    malformed input (fail-closed for verifiers)."""
    try:
        record = envelope["record"]
        sig = bytes.fromhex(envelope["signature"])
        pub = bytes.fromhex(envelope["pubkey"])
    except (KeyError, TypeError, ValueError):
        return False
    try:
        body = SIG_DOMAIN + canonical_bytes(record)
    except (TypeError, ValueError):
        return False
    try:
        from gov import signing as _signing
        return bool(_signing.Ed25519Verifier(pub).verify(body, sig))
    except ImportError:
        from gov import ed25519 as _ed
        return bool(_ed.verify(pub, body, sig))


def log_detection(audit_log, detection):
    """Append the detection to an open audit log.

    The offline evidence bundle exporter includes hash-chained log
    entries, so watcher detections ship to the standalone verifier
    through the existing export chain — no parallel scheme.
    """
    return audit_log.append({
        "event": "vendor-watch-detection",
        "flag": detection["code"],
        "detector": DETECTION_DOMAIN,
        "detector_version": DETECTOR_VERSION,
        "detection": detection,
    })


def enqueue_detections(queue, store, detections, caller_identity):
    """Route detections to the human approval queue (typed decisions).

    ``caller_identity`` is REQUIRED: the deployment mints a system
    identity for the watcher (F42 — the queue never trusts
    self-declared authority). Detections already queued are skipped
    (idempotent across scheduled scans). Returns the list of approval
    ids.
    """
    if caller_identity is None:
        raise TypeError(
            "enqueue_detections requires caller_identity: the deployment "
            "mints a system identity for the watcher")
    from gov.policy import PolicyDecision  # lazy: policy imports approvals
    ids = []
    for detection in detections:
        rec = _pending_for_detection(store, detection)
        if rec is not None and rec.get("queued"):
            continue  # already in the queue — never a second record
        ids.append(_enqueue_one(queue, detection, caller_identity,
                                PolicyDecision))
        if rec is not None:
            rec["queued"] = True
    store.save()
    return ids


def _pending_for_detection(store, detection):
    for rec in store.pending.values():
        if (rec["detection"]["detection_id"]
                == detection["detection_id"]):
            return rec
    return None


def _enqueue_one(queue, detection, caller_identity, PolicyDecision):
    args = {
        "detection_id": detection["detection_id"],
        "artifact_id": detection["artifact_id"],
        "kind": detection["kind"],
        "code": detection["code"],
        "old_version": (detection.get("old") or {}).get("version"),
        "old_hash": (detection.get("old") or {}).get("content_hash"),
        "new_version": (detection.get("new") or {}).get("version"),
        "new_hash": (detection.get("new") or {}).get("content_hash"),
        "diff_summary": detection.get("diff_summary") or {},
    }
    decision = PolicyDecision(
        "require_approval",
        "vendor-watch: %s on %s (%s) held for human approval" % (
            detection["outcome"], detection["artifact_id"],
            detection["code"]),
        policy_id="vendor-watch",
        flag=detection["code"])
    action = {
        "tool": "vendor-watch",
        "args": args,
        "identity": None,
        "agent_justification": None,
        "redactions": [],
    }
    preview = (
        "Vendor update detected by the watcher:\n"
        "  artifact: %s (%s)\n"
        "  outcome:  %s\n"
        "  code:     %s\n"
        "  %s -> %s\n"
        "  old hash: %s\n"
        "  new hash: %s\n"
        "Tools of this artifact are DENIED until this approval is "
        "decided." % (
            detection["artifact_id"], detection["kind"],
            detection["outcome"], detection["code"],
            (detection.get("old") or {}).get("version"),
            (detection.get("new") or {}).get("version"),
            (detection.get("old") or {}).get("content_hash"),
            (detection.get("new") or {}).get("content_hash")))
    return queue.queue(action, decision, provenance="watcher",
                       preview=preview, caller_identity=caller_identity)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser():
    p = argparse.ArgumentParser(
        prog="vendor-watch",
        description="Vendor-update sentinel: diff watched artifacts "
                    "against approved snapshots, fail closed.")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("scan", "baseline"):
        sp = sub.add_parser(name, help="%s watched artifacts" % name)
        sp.add_argument("--state-dir", default=None)
        sp.add_argument("--source", required=True,
                        help="path to a deployment-owned JSON source file")
        sp.add_argument("--audit-log", default=None,
                        help="append detections to the audit log at PATH "
                             "(requires GOV_WATCH_SIGN_SEED)")
        sp.add_argument("--now", default=None,
                        help="ISO-8601 timestamp for deterministic runs")
    return p


class _OperationalError(Exception):
    """The scan/baseline could not run honestly (not a detection)."""


def _read_sign_seed():
    raw = os.environ.get("GOV_WATCH_SIGN_SEED")
    if not raw:
        return None
    try:
        seed = bytes.fromhex(raw.strip())
    except ValueError:
        raise _OperationalError(
            "GOV_WATCH_SIGN_SEED is not hex")
    if len(seed) != 32:
        raise _OperationalError(
            "GOV_WATCH_SIGN_SEED must be 32 bytes (64 hex chars)")
    return seed


def _open_audit_log(path):
    from gov import log as _log
    return _log.open_audit_log(path, deployment_mode="staging")


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        store = VendorWatchStore(state_dir=args.state_dir)
        source = JsonFileSource(args.source)
        seed = _read_sign_seed()
        audit_log = (_open_audit_log(args.audit_log)
                     if args.audit_log else None)
        if (audit_log is None) != (seed is None):
            raise _OperationalError(
                "evidence requires both --audit-log and "
                "GOV_WATCH_SIGN_SEED; neither is optional")
        if args.command == "scan":
            detections = scan(store, source, now=args.now,
                              audit_log=audit_log, sign_seed=seed)
        else:
            detections = baseline(store, source, now=args.now,
                                  audit_log=audit_log, sign_seed=seed)
    except Exception as exc:  # noqa: BLE001 - CLI boundary: every
        # operational failure (bad source, bad state dir, missing key,
        # evidence misconfiguration) is a coded exit-2, never a
        # traceback-as-success and never silence. The type name is
        # preserved in the error payload for triage.
        sys.stderr.write(json.dumps({
            "error": "%s: %s" % (type(exc).__name__, exc),
        }) + "\n")
        return 2
    summary = {
        "command": args.command,
        "detector_version": DETECTOR_VERSION,
        "detections": len(detections),
        "by_outcome": {},
        "detection_ids": [d["detection_id"] for d in detections],
    }
    for d in detections:
        summary["by_outcome"][d["outcome"]] = \
            summary["by_outcome"].get(d["outcome"], 0) + 1
    sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
