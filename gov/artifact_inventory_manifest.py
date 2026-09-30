"""Deployment-pinned artifact manifest: the row-12 cross-run leg.

Row-12 residual this closes (measured, not fully): the run-scoped
``ArtifactInventory`` (gov/artifacts.py) has two blind spots.

1. It is run-scoped. A file the agent wrote in run N is "unknown"
   in run N+1 -- the cross-run exfil-via-artifact leg is invisible
   to it by construction.
2. It is launderable within a run. A governed ``write_file`` of
   hostile bytes REGISTERS those bytes, so a later egress of the
   same path reads "clean" (registered, hash matches). Nothing in
   the run inventory knows what the bytes were SUPPOSED to be.

The deployment manifest is the operator's answer: at deployment, the
operator pins ``{sandbox-relative path: sha256}`` for
deployment-critical files (model weights, frozen configs -- files
whose bytes must never change and must never leave without review).
The pin is an HMAC ceremony (key epoch bound, audited). At every
egress the executor consults the manifest IN ADDITION to the run
inventory:

- bytes differ from the deployment pin -> ``manifest_mismatch``.
  The deployment pin is a cross-run registration, so a mismatch IS
  a stale registration: the executor maps it onto
  ``artifact_tampered`` (the existing, reviewed
  ``approval-tampered-artifact-egress`` rule requires human review,
  and the existing use-time TOCTOU guard refuses an approved-but-
  mismatched execution). The specific ``deployment_manifest_``
  ``mismatch`` signal rides alongside on the approval record's
  policy_context so the reviewer sees the deployment-pin
  comparison, not just "stale".
- envelope fails verification (forged, pin-stripped, stale epoch,
  past TTL) -> ``manifest_unverifiable``, LOUD, fail-closed as
  tampered. An attacked integrity anchor must not silently become
  "no manifest".
- path not listed / bytes match / bytes unreadable -> no manifest
  signal (fail-open on unreadable, the artifact-layer discipline;
  the manifest never clears a run-inventory signal, it only adds).

What this is NOT:
- Not a content oracle (same as the run inventory: identity, not
  meaning -- the e1 hex-payload residual stays red by design).
- Not a substitute for re-pinning on legitimate change: an
  operator who updates a manifest-pinned file without re-running
  the ceremony gets require_approval on every egress of it until
  they re-pin (fail-closed in the safe direction, self-healing).
- Not a wisdom proof: the ceremony proves WHEN/WHAT/WHICH EPOCH
  was pinned, not that the pinned bytes were benign (same honest
  ceiling as every other pin ceremony in this repo).

No new HMAC call site by design: the pin MAC reuses the
wave-141 allowlisted ``gov.artifact_sweep._inventory_pin_mac``
(the w70 chokepoint audit stays green -- the key path is the SAME
guarded ``gov.keyprovider.resolve_active_key`` chokepoint, never
hard-coded, never committed). Domain separation is nested: the
manifest body is prefixed with ``_MANIFEST_PIN_DOMAIN`` before it
is passed as the body, so a manifest pin can never verify as an
inventory pin or a roots-declaration (each verifier reconstructs
its own exact nested body).

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_module  # compare_digest only (no key material here)
from datetime import datetime, timezone

from .artifacts import normalize_path
from . import artifact_sweep as _sweep
from . import keyprovider as _keyprovider

__all__ = [
    "MANIFEST_PINNED_VERSION",
    "MANIFEST_MISMATCH_FLAG",
    "MANIFEST_UNVERIFIABLE_FLAG",
    "MANIFEST_PINNED_EVENT",
    "pin_manifest",
    "verify_manifest_pin",
    "manifest_digest",
    "check_manifest",
]

MANIFEST_PINNED_VERSION = "deployment-manifest-pin/1.0"

MANIFEST_MISMATCH_FLAG = "deployment_manifest_mismatch"
MANIFEST_UNVERIFIABLE_FLAG = "deployment_manifest_unverifiable"
MANIFEST_PINNED_EVENT = "deployment_manifest_pinned"

# Nested domain separation (see module docstring): these bytes are
# prefixed to the canonical body BEFORE it is passed to the
# allowlisted inventory pin MAC, so the manifest pin domain can
# never collide with the inventory-pin or roots-declaration
# domains.
_MANIFEST_PIN_DOMAIN = b"deployment-manifest-pin-v1"
_MANIFEST_DIGEST_DOMAIN = b"deployment-manifest-digest-v1"

_EXPLICIT_KEY_EPOCH = "explicit-override"


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def _resolve_key(hmac_key):
    """Return (key_bytes, key_epoch).

    Explicit override (tests, offline tooling) or the deployment
    key via the guarded chokepoint. An unprovisioned deployment
    raises NoKeyConfiguredError fail-closed: the ceremony requires
    a key, there is no unsigned pin.
    """
    if hmac_key is not None:
        key_bytes = bytes(hmac_key)
        if not key_bytes:
            raise ValueError("hmac_key must be non-empty bytes")
        return key_bytes, _EXPLICIT_KEY_EPOCH
    return _keyprovider.resolve_active_key()


def _manifest_body(version, manifest, pinned_at, key_epoch):
    """Canonical bytes covered by the manifest pin.

    The key epoch is MAC-bound into the body (wave-142 idiom): a
    pin presented after the epoch rotated cannot be freshened by
    rewriting its ``key_epoch`` field (that breaks the MAC). The
    epoch is checked AFTER MAC verification, when its value is
    authenticated. The nested domain prefix keeps this body
    distinct from every other pin body in the repo.
    """
    return (_MANIFEST_PIN_DOMAIN + b"\x00" + _sweep.canonical(
        {"pinned_manifest": version,
         "manifest": {k: manifest[k] for k in sorted(manifest)},
         "pinned_at": pinned_at,
         "key_epoch": key_epoch}).encode("utf-8"))


def _manifest_pin_mac(key, nested_body):
    """Pin MAC via the allowlisted wave-141 site (no new HMAC site).

    ``gov.artifact_sweep._inventory_pin_mac`` is the w70-audited
    call site; the nested domain inside ``nested_body`` keeps the
    manifest pin in its own MAC domain (see module docstring).
    """
    return _sweep._inventory_pin_mac(key, nested_body)


def _coerce_entries(entries):
    """Validate and normalize the operator's manifest entries.

    Returns {normalized_path: lowercase_sha256}. Fail-closed at
    ceremony time: a malformed entry raises ValueError (a malformed
    manifest must be LOUD at setup, not a silent gap at consult).
    """
    if isinstance(entries, dict):
        items = list(entries.items())
    else:
        items = list(entries)
    normed = {}
    for pair in items:
        try:
            path, sha = pair
        except (TypeError, ValueError):
            raise ValueError(
                "manifest entries must be (path, sha256) pairs, got %r"
                % (pair,))
        key = normalize_path(path)
        if not key:
            raise ValueError("manifest entry has an empty path: %r"
                             % (pair,))
        if not isinstance(sha, str):
            raise ValueError(
                "manifest sha256 for %r must be a hex string, got %r"
                % (key, sha))
        digest = sha.strip().lower()
        if (len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError(
                "manifest sha256 for %r must be a 64-char hex digest, "
                "got %r" % (key, sha))
        normed[key] = digest
    if not normed:
        raise ValueError("cannot pin an empty manifest")
    return normed


def pin_manifest(entries, *, hmac_key=None, audit=None, run_id=None):
    """Operator pinning ceremony: bind the deployment manifest.

    ``entries``: {sandbox-relative path: sha256 hex} (or an
    iterable of pairs) -- the bytes each deployment-critical file
    is SUPPOSED to have. Paths are normalized; shas must be 64-char
    hex (fail-closed ValueError otherwise).

    ``hmac_key``: explicit key override (bytes); when None, the
    deployment key comes from
    ``gov.keyprovider.resolve_active_key()`` and an unprovisioned
    deployment raises ``NoKeyConfiguredError`` fail-closed.

    ``audit``: optional callable taking one event dict. When given,
    the ceremony emits one ``deployment_manifest_pinned`` event
    recording the manifest digest, key epoch, pin timestamp and
    entry count -- the auditable "who pinned what, when, under
    which key" record. ``run_id`` is stamped into the event.

    Returns the pinned envelope dict::

        {"pinned_manifest": "deployment-manifest-pin/1.0",
         "manifest": {<path>: <sha256>, ...},
         "pinned_at": <ISO-8601>,
         "key_epoch": <epoch at pin time>,
         "pin": <hex HMAC-SHA256>}

    The operator hands this dict to the executor as
    ``executor.deployment_manifest``.
    """
    key_bytes, key_epoch = _resolve_key(hmac_key)
    normed = _coerce_entries(entries)
    pinned_at = _utcnow_iso()
    body = _manifest_body(MANIFEST_PINNED_VERSION, normed, pinned_at,
                          key_epoch)
    pin = _manifest_pin_mac(key_bytes, body)
    pinned = {"pinned_manifest": MANIFEST_PINNED_VERSION,
              "manifest": normed,
              "pinned_at": pinned_at,
              "key_epoch": key_epoch,
              "pin": pin}
    if audit is not None:
        audit({"event": MANIFEST_PINNED_EVENT,
               "run_id": run_id,
               "manifest_digest": manifest_digest(pinned),
               "key_epoch": key_epoch,
               "pinned_at": pinned_at,
               "entry_count": len(normed)})
    return pinned


def manifest_digest(pinned):
    """Recompute the public manifest commitment for a pinned dict.

    Domain-separated SHA-256 over the nested pin body; no key
    material involved, recomputable by any holder of the envelope.
    Raises ValueError on a malformed envelope (fail-fast for
    auditors; this is the recomputation path, not the fail-closed
    verification path).
    """
    body = _verified_body_parts(pinned)
    return hashlib.sha256(
        _MANIFEST_DIGEST_DOMAIN + b"\x00" + body).hexdigest()


def _verified_body_parts(pinned):
    """Extract and re-canonicalize the body parts of an envelope.

    Raises ValueError when the envelope is malformed (fail-fast;
    callers that need fail-closed semantics use
    ``verify_manifest_pin``).
    """
    if not isinstance(pinned, dict):
        raise ValueError("pinned manifest must be a dict")
    version = pinned.get("pinned_manifest")
    manifest = pinned.get("manifest")
    pinned_at = pinned.get("pinned_at")
    key_epoch = pinned.get("key_epoch")
    pin = pinned.get("pin")
    if version != MANIFEST_PINNED_VERSION:
        raise ValueError("bad pinned_manifest version: %r" % (version,))
    if (not isinstance(manifest, dict) or not manifest
            or not all(isinstance(k, str) and k for k in manifest)
            or not all(isinstance(v, str) and v for v in manifest.values())):
        raise ValueError("malformed manifest entries")
    if not isinstance(pinned_at, str) or not pinned_at:
        raise ValueError("malformed pinned_at")
    if not isinstance(key_epoch, str) or not key_epoch:
        raise ValueError("malformed key_epoch")
    if not isinstance(pin, str) or not pin:
        raise ValueError("malformed pin")
    normed = _coerce_entries(manifest)
    return _manifest_body(version, normed, pinned_at, key_epoch)


def verify_manifest_pin(pinned, *, hmac_key=None, ttl_seconds=None):
    """Verify a pinned manifest envelope. Returns (ok, reason).

    Fail-closed: a malformed envelope, a pin-stripped envelope (the
    F182 shape -- any dict claims the pinned form), a MAC mismatch,
    a rotated-out key epoch, or an expired TTL all return
    ``(False, reason)``. The epoch is checked AFTER MAC
    verification, when its value is authenticated.
    """
    try:
        body = _verified_body_parts(pinned)
        presented_pin = pinned["pin"]
    except ValueError as exc:
        return False, "malformed_manifest_envelope: %s" % (exc,)
    try:
        key_bytes, current_epoch = _resolve_key(hmac_key)
    except Exception as exc:  # noqa: BLE001 -- key failure is a verify failure
        return False, "key_unavailable: %s" % (exc,)
    expected = _manifest_pin_mac(key_bytes, body)
    if not _hmac_module.compare_digest(expected, presented_pin):
        return False, "pin_mismatch"
    pinned_epoch = pinned["key_epoch"]
    if hmac_key is None:
        if pinned_epoch != current_epoch:
            return False, "stale_pin_epoch"
    elif pinned_epoch != _EXPLICIT_KEY_EPOCH:
        return False, "stale_pin_epoch"
    if ttl_seconds is not None:
        try:
            pinned_dt = datetime.fromisoformat(pinned["pinned_at"])
            if pinned_dt.tzinfo is None:
                pinned_dt = pinned_dt.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - pinned_dt).total_seconds()
        except (ValueError, OverflowError):
            return False, "malformed_manifest_envelope: bad pinned_at"
        if age > ttl_seconds:
            return False, "stale_pin_epoch"
    return True, "manifest pin verified"


def check_manifest(path, sha256_now, pinned, *, hmac_key=None,
                   ttl_seconds=None, audit=None):
    """Consult the deployment manifest for one egress file reference.

    Returns a dict with ``status`` (manifest_mismatch /
    manifest_unverifiable / manifest_clean / manifest_absent /
    manifest_unreadable), ``flag`` (the audit flag, or None when
    there is no signal), ``path``, and ``detail``.

    ``sha256_now`` is the hash of the bytes currently on disk (None
    when the file cannot be read -- then the comparison is skipped,
    fail-open on unreadable, exactly like the run inventory's
    discipline). Never raises: consult is defense-in-depth and must
    not break egress on its own errors.

    Wave-219: the unreadable skip is a registered unsafe path --
    ``gov.artifact_inventory_manifest.manifest_unreadable_failopen``
    -- emitted through the audit path (``audit``: list or callable)
    on EVERY execution.
    """
    key = normalize_path(path)
    try:
        ok, reason = verify_manifest_pin(pinned, hmac_key=hmac_key,
                                         ttl_seconds=ttl_seconds)
    except Exception as exc:  # noqa: BLE001 -- never raise from consult
        return {"status": "manifest_unverifiable",
                "flag": MANIFEST_UNVERIFIABLE_FLAG,
                "path": key,
                "detail": ("Deployment manifest consult failed: %s. "
                           "Treating as unverifiable (fail-closed)."
                           % (exc,))}
    if not ok:
        return {"status": "manifest_unverifiable",
                "flag": MANIFEST_UNVERIFIABLE_FLAG,
                "path": key,
                "detail": ("Deployment manifest pin did not verify "
                           "(%s): the integrity anchor itself is "
                           "untrustworthy; treating as unverifiable "
                           "(fail-closed)." % (reason,))}
    entries = pinned["manifest"]
    if key not in entries:
        return {"status": "manifest_absent", "flag": None, "path": key,
                "detail": "Path %r is not in the deployment manifest."
                          % (key,)}
    if sha256_now is None:
        from . import unsafe_paths as _up
        _up.emit(
            "gov.artifact_inventory_manifest.manifest_unreadable_failopen",
            audit=audit,
            detail=("Path %r is manifest-pinned but its bytes could not "
                    "be read; comparison skipped (fail-open on "
                    "unreadable)." % (key,)))
        return {"status": "manifest_unreadable", "flag": None,
                "path": key,
                "detail": ("Path %r is manifest-pinned but its bytes "
                           "could not be read; comparison skipped "
                           "(fail-open on unreadable)." % (key,))}
    expected = entries[key].lower()
    actual = str(sha256_now).strip().lower()
    if actual == expected:
        return {"status": "manifest_clean", "flag": None, "path": key,
                "detail": ("Path %r matches the deployment pin."
                           % (key,))}
    return {"status": "manifest_mismatch",
            "flag": MANIFEST_MISMATCH_FLAG,
            "path": key,
            "detail": ("Path %r bytes on disk (sha256 %s...) do not "
                       "match the deployment pin (sha256 %s...): the "
                       "file is not what deployment pinned."
                       % (key, actual[:12], expected[:12]))}
