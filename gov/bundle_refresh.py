"""TUF-style skill-bundle refresh (wave-206 lane B).

A stdlib-only refresh workflow for signed skill-bundle metadata, adapted
from the python-tuf client discipline (see
``research/`` prospectus: verdict ADAPT -- re-implemented, nothing
vendored):

* **Root chaining with no best-effort path.** A new root ``N+1`` is
  adopted only when it verifies under the old root's root-role
  threshold *and* the new root's own root-role threshold, with the
  exact ``N -> N+1`` version progression. A root that fails either
  threshold suspends the refresher; there is no fallback path.
* **Expiry is not suspension.** Expired metadata is *stale*: the last
  verified chain is still served, loudly, while the refresh is
  retried. A broken signature/version/binding chain *suspends* the
  refresher and refuses to serve anything until a clean refresh
  recovers.
* **Per-role byte caps.** Every fetched envelope is length-checked
  against its role's cap before it is parsed, closing the
  unbounded-download DoS on this seam.
* **Rollback protection.** Metadata older than the last verified
  version -- including a replayed older file served at the current
  version slot -- is refused and suspends.
* **Write-through cache.** Verified metadata is persisted; on reload
  every cached file is re-verified from the pinned root before it is
  trusted. Tampered cache files are discarded, never trusted blindly.
* **Pinned canonicalization.** Payloads and envelopes must be byte
 -identical to :data:`CANONICALIZATION_ID` (OLPC-style canonical
  JSON, *not* RFC 8785 JCS). A correctly-signed payload in any other
  encoding is refused on the canonicalization pin.
* **Opaque key IDs.** Declared key IDs select trusted keys; the
  refresher never requires ``keyid == hash(public_key)`` and never
  re-derives an ID to second-guess the producer.

The transport is caller-provided: ``fetch(role, version) -> bytes``
raises :class:`FetchNotFound` for a clean miss (the normal rollover
stop) and may raise anything else for a transport failure (kept as a
loud warning; the current chain is retained).
"""

import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timezone

from .dsse_envelope import pae
from .signing import Ed25519Verifier

# ---------------------------------------------------------------------------
# Canonicalization pin
# ---------------------------------------------------------------------------

#: The exact canonicalization every payload and envelope on this seam
#: must be byte-identical to. OLPC-style canonical JSON (sorted keys,
#: no insignificant whitespace, integers only, control characters as
#: lowercase ``\\uXXXX``) -- deliberately NOT RFC 8785 JCS, whose short
#: escapes (``\\n``) would verify as different bytes.
CANONICALIZATION_ID = "tuf-olpc-canonical-json/v1"


def _canon_string(text):
    parts = ['"']
    for char in text:
        code = ord(char)
        if char == '"':
            parts.append('\\"')
        elif char == '\\':
            parts.append('\\\\')
        elif code < 0x20:
            # OLPC canonical JSON: control characters use the long
            # lowercase \uXXXX escape -- never the JCS short escapes.
            parts.append('\\u%04x' % code)
        else:
            parts.append(char)
    parts.append('"')
    return ''.join(parts)


def tuf_canonical_json(obj):
    """Encode ``obj`` as OLPC-style canonical JSON bytes.

    Rules (pinned by :data:`CANONICALIZATION_ID`): object keys sorted
    by Unicode code point, no insignificant whitespace, integers only
    (arbitrary precision), strings with ``"``/``\\``/control escapes
    as above, ``true``/``false``/``null`` literals. Floats are refused
    (no canonical float encoding exists here); booleans encode as the
    literals, never as ``1``/``0``; any other type is refused.
    """
    if obj is None:
        return b'null'
    if obj is True:
        return b'true'
    if obj is False:
        return b'false'
    if isinstance(obj, int):
        return str(obj).encode('ascii')
    if isinstance(obj, float):
        raise CanonicalError(
            "floats have no canonical encoding under %s" %
            CANONICALIZATION_ID)
    if isinstance(obj, str):
        return _canon_string(obj).encode('utf-8')
    if isinstance(obj, (list, tuple)):
        return (b'[' + b','.join(tuf_canonical_json(v) for v in obj)
                + b']')
    if isinstance(obj, dict):
        for key in obj:
            if not isinstance(key, str):
                raise CanonicalError(
                    "object keys must be strings, got %s" %
                    type(key).__name__)
        items = sorted(obj.items(), key=lambda kv: kv[0])
        return (b'{' + b','.join(
            _canon_string(k).encode('utf-8') + b':' + tuf_canonical_json(v)
            for k, v in items) + b'}')
    raise CanonicalError("unsupported type %s under %s" %
                         (type(obj).__name__, CANONICALIZATION_ID))


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class RefreshError(Exception):
    """Base for every refresh-workflow failure."""


class _ChainBreak(RefreshError):
    """Internal control flow: the metadata chain broke; suspend."""


class FetchNotFound(RefreshError):
    """The transport's clean miss: no such ``(role, version)``."""


class CapExceeded(_ChainBreak):
    """A fetched envelope exceeded its role's byte cap."""


class RootChainError(_ChainBreak):
    """Root chaining failed (threshold, version, or shape)."""


class RollbackError(_ChainBreak):
    """Metadata older than the last verified version was served."""


class BindingError(_ChainBreak):
    """A child file does not match its parent's version/digest binding."""


class SuspendedError(RefreshError):
    """The refresher is suspended: no verified metadata may be served."""


class CanonicalError(_ChainBreak, ValueError):
    """A document is not byte-identical to :data:`CANONICALIZATION_ID`.

    A chain break (caught by every ``except RefreshError`` /
    ``except _ChainBreak`` handler on the consume path, so a
    mis-canonicalized file is discarded or suspends instead of
    crashing) that also stays a ``ValueError`` for producer-side
    callers of :func:`tuf_canonical_json` / :func:`seal_role`.
    """


# ---------------------------------------------------------------------------
# Envelope + payload types
# ---------------------------------------------------------------------------

#: DSSE payload types bound into every signature via PAE. The type is
#: inside the signed bytes, so a timestamp envelope cannot be replayed
#: as a targets envelope.
PAYLOAD_TYPES = {
    "root": "application/vnd.sasanam.tuf-root+json",
    "timestamp": "application/vnd.sasanam.tuf-timestamp+json",
    "snapshot": "application/vnd.sasanam.tuf-snapshot+json",
    "targets": "application/vnd.sasanam.tuf-targets+json",
}

_ROLES = ("root", "timestamp", "snapshot", "targets")

#: Default per-role maximum download lengths (DoS cap, checked before
#: parsing). Overridable per refresher via ``max_length``.
DEFAULT_MAX_LENGTH = {
    "root": 256 * 1024,
    "timestamp": 64 * 1024,
    "snapshot": 256 * 1024,
    "targets": 1024 * 1024,
}


def seal_role(role, doc, signers):
    """Seal ``doc`` as a signed ``role`` envelope; returns wire bytes.

    ``signers`` is an iterable of ``(declared_key_id, signer)`` tuples
    -- the *declared* (opaque, producer-chosen) key ID is what goes in
    the envelope, never a re-derived one. The payload is
    :data:`CANONICALIZATION_ID` bytes signed via DSSE PAE; the
    envelope itself is canonicalized as the wire format.
    """
    if role not in PAYLOAD_TYPES:
        raise ValueError("unknown role %r" % (role,))
    payload = tuf_canonical_json(doc)
    pae_bytes = pae(PAYLOAD_TYPES[role], payload)
    sigs = []
    for keyid, signer in signers:
        if not isinstance(keyid, str) or not keyid:
            raise ValueError("declared keyid must be a non-empty str")
        sigs.append({"keyid": keyid,
                     "sig": bytes(signer.sign(pae_bytes)).hex()})
    if not sigs:
        raise ValueError("seal_role requires at least one signer")
    envelope = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": PAYLOAD_TYPES[role],
        "signatures": sigs,
    }
    return tuf_canonical_json(envelope)


def _b64_strict(value, where):
    if not isinstance(value, str):
        raise RootChainError("%s: base64 field must be str, got %s"
                             % (where, type(value).__name__))
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise RootChainError("%s: invalid base64: %s" % (where, exc))


def _parse_envelope(role, wire, where, max_length):
    """Parse and canonical-verify one wire envelope.

    Returns ``(envelope_dict, payload_doc, payload_bytes)``. Raises a
    :class:`_ChainBreak` subclass on any defect: over-cap fetch (before
    parsing), non-canonical wire bytes, bad shape, payload-type
    mismatch, or a non-canonical payload.
    """
    cap = max_length[role]
    if len(wire) > cap:
        raise CapExceeded(
            "%s: %d bytes exceeds the per-role download cap of %d "
            "bytes for role %r" % (where, len(wire), cap, role))
    try:
        text = bytes(wire).decode("utf-8")
    except (UnicodeDecodeError, TypeError) as exc:
        raise RootChainError("%s: wire is not UTF-8: %s" % (where, exc))
    try:
        envelope = json.loads(text)
    except ValueError as exc:
        raise RootChainError("%s: wire is not JSON: %s" % (where, exc))
    if not isinstance(envelope, dict):
        raise RootChainError("%s: envelope must be a JSON object" % where)
    if tuf_canonical_json(envelope) != bytes(wire):
        raise CanonicalError(
            "%s: envelope bytes are not %s; re-encoding required"
            % (where, CANONICALIZATION_ID))
    payload_b64 = envelope.get("payload")
    payload_type = envelope.get("payloadType")
    signatures = envelope.get("signatures")
    if payload_type != PAYLOAD_TYPES[role]:
        raise RootChainError(
            "%s: payloadType %r does not match role %r"
            % (where, payload_type, role))
    if not isinstance(signatures, list) or not signatures:
        raise RootChainError("%s: signatures must be a non-empty list"
                             % where)
    payload = _b64_strict(payload_b64, where + ".payload")
    try:
        doc = json.loads(payload.decode("utf-8"))
    except ValueError as exc:
        raise RootChainError("%s: payload is not JSON: %s" % (where, exc))
    if not isinstance(doc, dict):
        raise RootChainError("%s: payload must be a JSON object" % where)
    if tuf_canonical_json(doc) != payload:
        raise CanonicalError(
            "%s: payload bytes are not %s; refusing a correctly-signed "
            "but non-canonical encoding" % (where, CANONICALIZATION_ID))
    if doc.get("_type") != role:
        raise RootChainError("%s: payload _type %r does not match role %r"
                             % (where, doc.get("_type"), role))
    return envelope, doc, payload


# ---------------------------------------------------------------------------
# Threshold verification with opaque key IDs
# ---------------------------------------------------------------------------

def _check_int(value, where):
    if isinstance(value, bool) or not isinstance(value, int):
        raise RootChainError("%s: must be an int, got %s"
                             % (where, type(value).__name__))
    return value


def _validate_root_doc(doc, where):
    """Structural validation of a root document (shape, not trust)."""
    if _check_int(doc.get("version", 0), where + ".version") < 1:
        raise RootChainError("%s: root version must be >= 1" % where)
    if not isinstance(doc.get("expires"), str) or not doc["expires"]:
        raise RootChainError("%s: root expires must be a non-empty str"
                             % where)
    keys = doc.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise RootChainError("%s: root keys must be a non-empty dict"
                             % where)
    roles = doc.get("roles")
    if not isinstance(roles, dict):
        raise RootChainError("%s: root roles must be a dict" % where)
    for role in _ROLES:
        info = roles.get(role)
        if not isinstance(info, dict):
            raise RootChainError("%s: missing role %r" % (where, role))
        keyids = info.get("keyids")
        threshold = info.get("threshold")
        if (not isinstance(keyids, list) or not keyids
                or any(not isinstance(k, str) or not k for k in keyids)):
            raise RootChainError("%s: role %r needs a non-empty keyids list"
                                 % (where, role))
        _check_int(threshold, "%s: role %r threshold" % (where, role))
        if threshold < 1 or threshold > len(keyids):
            raise RootChainError(
                "%s: role %r threshold %r out of range" % (where, role,
                                                           threshold))
        for kid in keyids:
            if kid not in keys:
                raise RootChainError(
                    "%s: role %r references unknown keyid %r"
                    % (where, role, kid))
    # Parse the expiry eagerly so a malformed value fails closed here.
    _parse_time(doc["expires"], where + ".expires")


def _parse_time(value, where):
    try:
        if value.endswith("Z"):
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            return parsed.replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, AttributeError) as exc:
        raise RootChainError("%s: bad expiry timestamp %r: %s"
                             % (where, value, exc))


def _threshold_ok(role, envelope, payload, keys, role_info, where):
    """True when ``role``'s threshold is met by *distinct declared*
    key IDs.

    Key IDs are opaque producer-chosen strings: a signature counts
    only when its ``keyid`` is listed in the role's ``keyids`` *and*
    in ``keys``. Unknown key IDs never attribute, even when the
    underlying key would verify -- and no ID is ever re-derived from
    a public key.
    """
    pae_bytes = pae(PAYLOAD_TYPES[role], payload)
    seen = set()
    for entry in envelope.get("signatures", []):
        if not isinstance(entry, dict):
            continue
        kid = entry.get("keyid")
        if not isinstance(kid, str) or kid in seen:
            continue
        if kid not in role_info["keyids"]:
            continue
        keyinfo = keys.get(kid)
        if not isinstance(keyinfo, dict):
            continue
        if keyinfo.get("keytype") != "ed25519":
            continue
        public_hex = (keyinfo.get("keyval") or {}).get("public")
        sig_hex = entry.get("sig")
        try:
            public = bytes.fromhex(public_hex)
            sig = bytes.fromhex(sig_hex)
        except (TypeError, ValueError):
            continue
        if len(public) != 32 or len(sig) != 64:
            continue
        try:
            if Ed25519Verifier(public, key_id=kid).verify(pae_bytes, sig):
                seen.add(kid)
        except Exception:
            continue
    return len(seen) >= role_info["threshold"]


def _subordinate_trust_changed(old_root, new_root):
    """True when a root rotation changes timestamp/snapshot/targets trust.

    Compares the delegated key IDs, thresholds, and key material for the
    three subordinate roles. The root role itself is excluded: rotating
    only root keys leaves subordinate metadata re-verifiable.
    """
    for role in ("timestamp", "snapshot", "targets"):
        old_info = (old_root.get("roles") or {}).get(role) or {}
        new_info = (new_root.get("roles") or {}).get(role) or {}
        if old_info != new_info:
            return True
        old_keys = old_root.get("keys") or {}
        new_keys = new_root.get("keys") or {}
        for kid in new_info.get("keyids", []):
            if old_keys.get(kid) != new_keys.get(kid):
                return True
    return False


# ---------------------------------------------------------------------------
# Refresh report
# ---------------------------------------------------------------------------

class RefreshReport(object):
    """The outcome of one :meth:`BundleRefresher.refresh` call.

    ``state`` is ``"trusted"`` (clean chain), ``"stale"`` (expired
    metadata: last verified chain still served, loudly), or
    ``"suspended"`` (chain break: nothing is served until a clean
    refresh recovers). ``warnings`` carries the loud expiry/transport
    notes; ``reason`` names the suspension cause, if any.
    """

    def __init__(self, state, warnings, reason=None, versions=None):
        self.state = state
        self.warnings = list(warnings)
        self.reason = reason
        self.versions = dict(versions or {})

    def __repr__(self):
        return ("RefreshReport(state=%r, warnings=%d, reason=%r, "
                "versions=%r)" % (self.state, len(self.warnings),
                                  self.reason, self.versions))


# ---------------------------------------------------------------------------
# Bundle refresher
# ---------------------------------------------------------------------------

class BundleRefresher(object):
    """TUF-style refresh of signed skill-bundle metadata.

    ``trusted_root_wire`` is the pinned trust anchor (root vN bytes).
    ``fetch(role, version)`` returns wire bytes, raising
    :class:`FetchNotFound` on a clean miss. ``cache_dir`` holds the
    write-through cache. ``clock`` returns "now" (defaults to UTC).
    ``max_length`` overrides :data:`DEFAULT_MAX_LENGTH` per role.

    States: ``"trusted"`` serves; ``"stale"`` serves the last verified
    chain with loud warnings (expiry only); ``"suspended"`` refuses
    everything until a clean :meth:`refresh` recovers. ``refresh()``
    is idempotent and safe to retry.
    """

    def __init__(self, trusted_root_wire, fetch, cache_dir, clock=None,
                 max_length=None):
        if not callable(fetch):
            raise TypeError("fetch must be callable")
        self._fetch = fetch
        self._cache_dir = os.path.abspath(cache_dir)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_length = dict(DEFAULT_MAX_LENGTH)
        if max_length:
            for role, cap in max_length.items():
                if role not in _ROLES:
                    raise ValueError("unknown role %r" % (role,))
                self._max_length[role] = cap
        self._warnings = []
        self._state = "suspended"
        self._reason = "uninitialized"
        self._chain = {}  # role -> {"doc", "wire"} for timestamp/snapshot/targets
        # When a root rotation changes subordinate trust, the old chain
        # cannot re-verify under the new root; the next refresh then
        # re-bootstraps subordinate roles from v1 with the pre-rotation
        # versions as the rollback floor. None in the normal path.
        self._rotation_floor = None

        # Pin the trust anchor: canonical form + self-threshold.
        env, doc, payload = self._parse("root", trusted_root_wire,
                                        "pinned root")
        _validate_root_doc(doc, "pinned root")
        self._check_root_self(doc, env, payload, "pinned root")
        self._root = doc
        self._root_version = doc["version"]
        if self._is_expired(doc):
            self._warn("pinned root v%d expired %s: trust anchor is "
                       "stale; cached metadata will be served as stale "
                       "only, and the anchor must be rotated out of band"
                       % (doc["version"], doc["expires"]))

        os.makedirs(self._cache_dir, exist_ok=True)
        pinned_root = self._root
        pre_versions = self._cached_role_versions()
        self._load_cache()
        if (self._root_version != pinned_root["version"]
                and _subordinate_trust_changed(pinned_root, self._root)
                and not self._chain_complete()):
            # The cache replayed a trust-changing root rotation while we
            # were away, and the chain under the new root is incomplete:
            # force the re-bootstrap with the pre-rotation versions as
            # the rollback floor. (A complete chain already verified
            # under the new root is kept as-is.)
            self._rotation_floor = pre_versions
            self._chain = {}
            for name in ("timestamp.json", "snapshot.json",
                         "targets.json"):
                self._cache_remove(name)
            self._warn(
                "cached root advanced to v%d with changed subordinate "
                "trust: re-bootstrapping timestamp/snapshot/targets "
                "under the new root" % self._root_version)
        self._settle_state("init")

    def _cached_role_versions(self):
        """Best-effort versions of cached subordinate metadata.

        Read before the cache is (re-)verified so a trust-changing root
        rotation replayed from cache still leaves a rollback floor.
        Unparseable files simply contribute no floor.
        """
        versions = {}
        for role, name in (("timestamp", "timestamp.json"),
                           ("snapshot", "snapshot.json"),
                           ("targets", "targets.json")):
            path = self._cache_path(name)
            try:
                with open(path, "rb") as handle:
                    wire = handle.read()
                _env, doc, _payload = self._parse(
                    role, wire, "cached " + name)
            except (OSError, RefreshError):
                continue
            if isinstance(doc.get("version"), int):
                versions[role] = doc["version"]
        return versions

    # -- small helpers -------------------------------------------------

    @property
    def state(self):
        """Current state: ``"trusted"``, ``"stale"``, or ``"suspended"``."""
        return self._state

    @property
    def reason(self):
        """Suspension cause, or None."""
        return self._reason

    @property
    def warnings(self):
        """Loud notes accumulated (expiry, transport, cache hygiene)."""
        return tuple(self._warnings)

    def _warn(self, message):
        self._warnings.append(message)

    def _now(self):
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now

    def _is_expired(self, doc):
        return self._now() >= _parse_time(doc["expires"], "expires")

    def _parse(self, role, wire, where):
        return _parse_envelope(role, wire, where, self._max_length)

    def _check_root_self(self, doc, env, payload, where):
        _validate_root_doc(doc, where)
        if not _threshold_ok("root", env, payload, doc["keys"],
                             doc["roles"]["root"], where):
            raise RootChainError(
                "%s: root self-signature threshold not met" % where)

    def _check_role_sig(self, role, env, payload, where):
        if not _threshold_ok(role, env, payload, self._root["keys"],
                             self._root["roles"][role], where):
            raise RootChainError(
                "%s: role %r signature threshold not met "
                "(%d-of-%d required)" % (
                    where, role,
                    self._root["roles"][role]["threshold"],
                    len(self._root["roles"][role]["keyids"])))

    def _note_expiry(self, role, doc):
        if self._is_expired(doc):
            self._warn("%s v%d expired %s: serving the last verified "
                       "chain as STALE, not fresh; retrying upstream"
                       % (role, doc["version"], doc["expires"]))
            return True
        return False

    # -- write-through cache -------------------------------------------

    def _cache_path(self, name):
        return os.path.join(self._cache_dir, name)

    def _cache_write(self, name, wire):
        tmp = self._cache_path(name + ".tmp")
        with open(tmp, "wb") as handle:
            handle.write(bytes(wire))
        os.replace(tmp, self._cache_path(name))

    def _cache_remove(self, name):
        try:
            os.remove(self._cache_path(name))
        except OSError:
            pass

    def _load_cache(self):
        """Reload verified metadata; re-verify everything from the pin.

        Any cached file that fails verification is discarded (never
        trusted blindly); the refresh path re-fetches it.
        """
        # Root chain: replay N -> N+1 from the pinned anchor so a
        # planted higher-versioned root cannot become the anchor.
        versions = []
        for name in os.listdir(self._cache_dir):
            if name.startswith("root.") and name.endswith(".json"):
                try:
                    versions.append(int(name[len("root."):-len(".json")]))
                except ValueError:
                    self._warn("ignoring oddly-named cache file %r" % name)
        for version in sorted(versions):
            if version <= self._root_version:
                continue
            name = "root.%d.json" % version
            try:
                with open(self._cache_path(name), "rb") as handle:
                    wire = handle.read()
                env, doc, payload = self._parse("root", wire,
                                                "cached " + name)
                self._adopt_root_candidate(version, env, doc, payload,
                                            wire, "cached " + name)
            except RefreshError as exc:
                self._warn("discarding unverifiable cached %s: %s"
                           % (name, exc))
                self._cache_remove(name)
                break  # the chain above this point cannot be replayed
        # timestamp -> snapshot -> targets, honoring parent bindings.
        timestamp = self._load_cached_role("timestamp", "timestamp.json")
        if timestamp is None:
            return
        self._chain["timestamp"] = timestamp
        snap_bind = timestamp["doc"].get("snapshot") or {}
        snapshot = self._load_cached_role(
            "snapshot", "snapshot.json",
            bind_version=snap_bind.get("version"),
            bind_wire_via=snap_bind)
        if snapshot is None:
            return
        self._chain["snapshot"] = snapshot
        tgt_bind = (snapshot["doc"].get("meta") or {}).get(
            "targets.json") or {}
        targets = self._load_cached_role(
            "targets", "targets.json",
            bind_version=tgt_bind.get("version"),
            bind_wire_via=tgt_bind)
        if targets is None:
            return
        self._chain["targets"] = targets

    def _load_cached_role(self, role, filename, bind_version=None,
                          bind_wire_via=None):
        path = self._cache_path(filename)
        try:
            with open(path, "rb") as handle:
                wire = handle.read()
        except OSError:
            return None
        where = "cached " + filename
        try:
            env, doc, payload = self._parse(role, wire, where)
            self._validate_role_doc(role, doc, where)
            self._check_role_sig(role, env, payload, where)
            if bind_version is not None and doc["version"] != bind_version:
                raise BindingError(
                    "%s: version v%d does not match the parent binding "
                    "v%s" % (where, doc["version"], bind_version))
            if bind_wire_via:
                self._check_binding(role, wire, bind_wire_via, where)
            expired = self._note_expiry(role, doc)
            return {"doc": doc, "wire": wire, "expired": expired}
        except RefreshError as exc:
            self._warn("discarding unverifiable %s: %s" % (where, exc))
            self._cache_remove(filename)
            return None

    @staticmethod
    def _check_binding(role, wire, binding, where):
        """The parent-declared digest/length must match the wire bytes."""
        want = (binding.get("hashes") or {}).get("sha256")
        if want != hashlib.sha256(bytes(wire)).hexdigest():
            raise BindingError(
                "%s: wire digest does not match the parent's bound "
                "sha256" % where)
        length = binding.get("length")
        if isinstance(length, int) and length != len(wire):
            raise BindingError(
                "%s: wire length %d does not match the parent's bound "
                "length %s" % (where, len(wire), length))

    # -- state ----------------------------------------------------------

    def _chain_complete(self):
        return all(r in self._chain
                   for r in ("timestamp", "snapshot", "targets"))

    def _anything_expired(self):
        if self._is_expired(self._root):
            return True
        return any(entry.get("expired") for entry in self._chain.values())

    def _settle_state(self, _phase):
        if self._chain_complete():
            if self._anything_expired():
                self._state = "stale"
                self._reason = None
            else:
                self._state = "trusted"
                self._reason = None
        else:
            self._state = "suspended"
            if self._reason in (None, "uninitialized"):
                self._reason = "no complete verified metadata chain"

    # -- refresh --------------------------------------------------------

    def refresh(self):
        """Run one full refresh; returns a :class:`RefreshReport`.

        Never raises for metadata problems: chain breaks suspend (the
        report names the cause), expiry goes stale with loud warnings,
        transport errors are warnings that keep the current chain.
        Idempotent and safe to retry.
        """
        self._reason = None
        try:
            self._refresh_roots()
            self._refresh_timestamp()
            self._refresh_snapshot()
            self._refresh_targets()
        except _ChainBreak as exc:
            self._state = "suspended"
            self._reason = str(exc)
        except Exception as exc:  # fail closed on harness bugs, loudly
            self._state = "suspended"
            self._reason = "internal refresh error: %s: %s" % (
                type(exc).__name__, exc)
        else:
            self._settle_state("refresh")
            if self._chain_complete():
                # A completed chain ends any post-rotation bootstrap.
                self._rotation_floor = None
        return RefreshReport(
            self._state, self._warnings, self._reason,
            {role: entry["doc"]["version"]
             for role, entry in self._chain.items()})

    def _fetch_one(self, role, version):
        """Fetch, distinguishing a clean miss from a transport error.

        Returns ``(wire, transport_failed)``: ``(None, False)`` is the
        clean :class:`FetchNotFound` miss (normal rollover stop);
        ``(None, True)`` is a transport failure (loud warning; the
        caller keeps the current chain).
        """
        try:
            return self._fetch(role, version), False
        except FetchNotFound:
            return None, False
        except Exception as exc:
            self._warn("transport error fetching %s v%d (%s: %s); "
                       "keeping the current chain and retrying next "
                       "refresh" % (role, version, type(exc).__name__, exc))
            return None, True

    def _adopt_root_candidate(self, slot, env, doc, payload, wire, where):
        """Adopt a root candidate: exact N+1, dual threshold, fresh."""
        _validate_root_doc(doc, where)
        current = self._root_version
        version = doc["version"]
        if version < current:
            raise RollbackError(
                "%s: root v%d is older than trusted v%d" % (where, version,
                                                             current))
        if version > current + 1:
            raise RootChainError(
                "%s: root v%d skips versions (trusted v%d); refusing"
                % (where, version, current))
        if version == current:
            if slot != current:
                # The repository serves the old root at newer slots:
                # nothing newer; stop probing.
                return False
            # Confirmation (possibly re-signed): self-threshold only.
            self._check_root_self(doc, env, payload, where)
            self._note_expiry("root", doc)
            self._root_wire = bytes(wire)
            self._cache_write("root.%d.json" % version, wire)
            return True  # confirmed; keep probing for N+1
        old_role = self._root["roles"]["root"]
        old_keys = self._root["keys"]
        new_role = doc["roles"]["root"]
        new_keys = doc["keys"]
        old_ok = _threshold_ok("root", env, payload, old_keys, old_role,
                               where + " (old root)")
        new_ok = _threshold_ok("root", env, payload, new_keys, new_role,
                               where + " (new root)")
        if not (old_ok and new_ok):
            raise RootChainError(
                "%s: root v%d dual threshold not met (old root: %s, "
                "new root: %s); no best-effort path"
                % (where, version, old_ok, new_ok))
        if self._is_expired(doc):
            self._warn("%s: root v%d expired %s; refusing to adopt, "
                       "keeping v%d" % (where, version, doc["expires"],
                                        current))
            return False
        self._root = doc
        self._root_wire = bytes(wire)
        self._root_version = version
        self._cache_write("root.%d.json" % version, wire)
        # Prune the superseded root file; the anchor chain replays from
        # the pinned wire plus these files.
        if current != version:
            self._cache_remove("root.%d.json" % current)
        return True

    def _refresh_roots(self):
        # Probe from the trusted version itself: re-fetching the current
        # slot detects rollback-by-replacement (older bytes at the same
        # slot). The candidate stops the probe when nothing is newer.
        old_root = self._root
        try:
            version = self._root_version
            while True:
                wire, _failed = self._fetch_one("root", version)
                if wire is None:
                    return
                env, doc, payload = self._parse("root", wire,
                                                "root v%d fetch" % version)
                before = self._root_version
                keep_going = self._adopt_root_candidate(
                    version, env, doc, payload, wire,
                    "root v%d fetch" % version)
                if not keep_going:
                    return
                version = (self._root_version + 1
                           if self._root_version != before else version + 1)
        finally:
            if (self._root_version != old_root["version"]
                    and _subordinate_trust_changed(old_root, self._root)):
                # Subordinate metadata verified under the old root can no
                # longer be re-verified; drop it and re-bootstrap under
                # the new root on the timestamp step.
                self._begin_post_rotation()

    def _begin_post_rotation(self):
        """Invalidate subordinate state after a trust-changing rotation.

        The old chain verified under the old root; with changed key IDs
        or thresholds it cannot re-verify under the new root, so it must
        not be served. The timestamp step re-bootstraps from v1 with the
        pre-rotation versions as the rollback floor.
        """
        old_versions = {role: entry["doc"]["version"]
                        for role, entry in self._chain.items()}
        self._rotation_floor = old_versions
        self._chain = {}
        for name in ("timestamp.json", "snapshot.json", "targets.json"):
            self._cache_remove(name)
        floor_note = (" (rollback floor %r)" % (old_versions,)
                      if old_versions else "")
        self._warn("root advanced to v%d with changed subordinate trust: "
                   "re-bootstrapping timestamp/snapshot/targets under the "
                   "new root%s"
                   % (self._root_version, floor_note))

    def _refresh_timestamp(self):
        if (self._rotation_floor is not None
                and "timestamp" not in self._chain):
            # Trust-changing root rotation: the old chain is gone and old
            # versions cannot re-verify under the new root; bootstrap.
            self._bootstrap_timestamp_post_rotation()
            return
        known = self._chain.get("timestamp", {}).get("doc", {}).get(
            "version")
        version = known if known is not None else 1
        while True:
            wire, _failed = self._fetch_one("timestamp", version)
            if wire is None:
                if known is None:
                    raise _ChainBreak(
                        "no timestamp metadata available: cannot "
                        "complete the chain")
                return
            env, doc, payload = self._parse(
                "timestamp", wire, "timestamp v%d fetch" % version)
            cont = self._accept_newer("timestamp", version, env, doc,
                                       payload, wire, known)
            if not cont:
                return
            known = doc["version"]
            version = known + 1

    def _bootstrap_timestamp_post_rotation(self):
        """Re-bootstrap timestamp after a trust-changing root rotation.

        Old versions signed under the old root cannot verify under the
        new root, so non-verifying slots are skipped (with loud
        warnings) rather than fatal; the highest verifying version wins,
        subject to the pre-rotation rollback floor. An attacker cannot
        exploit the skipping: only versions signed under the new root's
        keys verify, and anything below the floor is a loud rollback
        refusal. Withholding just suspends (fail closed).
        """
        floor = (self._rotation_floor or {}).get("timestamp")
        version = 1
        best = None
        while True:
            wire, _failed = self._fetch_one("timestamp", version)
            if wire is None:
                break
            where = ("timestamp v%d fetch (post-rotation bootstrap)"
                     % version)
            try:
                env, doc, payload = self._parse("timestamp", wire, where)
                self._validate_role_doc("timestamp", doc, where)
                if doc["version"] != version:
                    raise _ChainBreak(
                        "%s: slot/version mismatch" % where)
                self._check_role_sig("timestamp", env, payload, where)
            except _ChainBreak as exc:
                self._warn("%s: skipped: %s" % (where, exc))
                version += 1
                continue
            if floor is not None and doc["version"] < floor:
                raise RollbackError(
                    "%s: v%d below the pre-rotation v%d; refusing"
                    % (where, doc["version"], floor))
            best = (doc, wire)
            version += 1
        if best is None:
            raise _ChainBreak(
                "post-rotation: no timestamp version verifies under the "
                "new root; cannot complete the chain")
        doc, wire = best
        if self._is_expired(doc):
            raise _ChainBreak(
                "post-rotation timestamp v%d is expired and no verified "
                "chain exists; refusing" % doc["version"])
        self._chain["timestamp"] = {"doc": doc, "wire": bytes(wire),
                                    "expired": False}
        self._cache_write("timestamp.json", wire)

    def _accept_newer(self, role, slot, env, doc, payload, wire, known):
        """Shared confirm-or-advance for timestamp (parent of snapshot).

        Returns True to keep probing higher versions.
        """
        version = doc["version"]
        where = "%s v%d fetch" % (role, slot)
        if known is not None and version < known:
            raise RollbackError(
                "%s: %s v%d is older than trusted v%d"
                % (where, role, version, known))
        if known is not None and version == known and slot != known:
            return False  # repository serves the old version at newer
            # slots: nothing newer; stop probing.
        self._validate_role_doc(role, doc, where)
        self._check_role_sig(role, env, payload, where)
        if known is not None and version > known + 1:
            raise RootChainError(
                "%s: %s v%d skips versions (trusted v%d); refusing"
                % (where, role, version, known))
        if known is not None and version == known:
            # Confirmation of the trusted version (possibly re-signed).
            expired = self._note_expiry(role, doc)
            self._chain[role] = {"doc": doc, "wire": bytes(wire),
                                 "expired": expired}
            self._cache_write(role + ".json", wire)
            return True
        # Advance: version == known + 1, or the first version ever.
        if self._is_expired(doc):
            self._warn("%s: %s v%d expired %s; refusing to advance, "
                       "keeping %s" % (
                           where, role, version, doc["expires"],
                           "v%d" % known if known is not None
                           else "nothing (no chain)"))
            if known is None and role not in self._chain:
                raise _ChainBreak(
                    "%s v%d is expired and no verified %s is cached: "
                    "cannot complete the chain" % (role, version, role))
            return False
        expired = self._note_expiry(role, doc)
        self._chain[role] = {"doc": doc, "wire": bytes(wire),
                             "expired": expired}
        self._cache_write(role + ".json", wire)
        return True

    # -- bound roles: snapshot, targets --------------------------------

    def _refresh_snapshot(self):
        timestamp = self._chain.get("timestamp")
        if timestamp is None:
            raise _ChainBreak(
                "no verified timestamp: cannot refresh snapshot")
        binding = timestamp["doc"].get("snapshot") or {}
        self._refresh_bound("snapshot", binding)

    def _refresh_targets(self):
        snapshot = self._chain.get("snapshot")
        if snapshot is None:
            raise _ChainBreak(
                "no verified snapshot: cannot refresh targets")
        binding = (snapshot["doc"].get("meta") or {}).get(
            "targets.json") or {}
        self._refresh_bound("targets", binding)

    def _refresh_bound(self, role, binding):
        """Refresh a role whose exact version is bound by its parent.

        Two steps: (1) when the parent moved past the cached version,
        re-fetch the cached version's slot to detect
        rollback-by-replacement; (2) fetch exactly the bound version
        and check version, parent digest binding, signature threshold,
        and expiry -- in that order.
        """
        bound_version = binding.get("version")
        if (isinstance(bound_version, bool)
                or not isinstance(bound_version, int)
                or bound_version < 1):
            raise _ChainBreak(
                "parent binds no usable %s version: cannot complete "
                "the chain" % role)
        cached = self._chain.get(role)
        cached_v = cached["doc"]["version"] if cached else None
        if cached_v is not None and bound_version < cached_v:
            raise RollbackError(
                "%s: parent binds v%d, older than trusted v%d"
                % (role, bound_version, cached_v))
        if cached_v is not None and cached_v != bound_version:
            re_wire, _failed = self._fetch_one(role, cached_v)
            if re_wire is not None:
                where = "%s v%d re-confirm" % (role, cached_v)
                env, doc, payload = self._parse(role, re_wire, where)
                self._validate_role_doc(role, doc, where)
                if doc["version"] < cached_v:
                    raise RollbackError(
                        "%s: repository replaced trusted v%d with v%d"
                        % (where, cached_v, doc["version"]))
                if doc["version"] != cached_v:
                    raise _ChainBreak(
                        "%s: version mismatch at the trusted slot" % where)
                self._check_role_sig(role, env, payload, where)
                expired = self._note_expiry(role, doc)
                self._chain[role] = {"doc": doc, "wire": bytes(re_wire),
                                     "expired": expired}
                self._cache_write(role + ".json", re_wire)
        where = "%s v%d fetch" % (role, bound_version)
        wire, transport_failed = self._fetch_one(role, bound_version)
        if wire is None:
            if transport_failed:
                # Transient: keep the cached version (already
                # re-confirmed above when the parent moved on); the
                # warning is recorded by _fetch_one.
                return
            raise _ChainBreak(
                "%s v%d is bound by its parent but unavailable: cannot "
                "complete the chain" % (role, bound_version))
        env, doc, payload = self._parse(role, wire, where)
        self._validate_role_doc(role, doc, where)
        version = doc["version"]
        if version != bound_version:
            if version < bound_version:
                raise RollbackError(
                    "%s: served v%d below the parent-bound v%d"
                    % (where, version, bound_version))
            raise _ChainBreak(
                "%s: served v%d above the parent-bound v%d; refusing"
                % (where, version, bound_version))
        # Parent-declared digest binding first (cheap, mix-and-match
        # discipline), then the signature threshold.
        self._check_binding(role, wire, binding, where)
        self._check_role_sig(role, env, payload, where)
        if self._is_expired(doc):
            self._warn("%s: %s v%d expired %s; refusing to advance, "
                       "keeping %s" % (
                           where, role, version, doc["expires"],
                           "v%d" % cached_v if cached_v is not None
                           else "nothing (no chain)"))
            if cached_v is None and role not in self._chain:
                raise _ChainBreak(
                    "%s v%d is expired and no verified %s is cached: "
                    "cannot complete the chain" % (role, version, role))
            return
        expired = self._note_expiry(role, doc)
        self._chain[role] = {"doc": doc, "wire": bytes(wire),
                             "expired": expired}
        self._cache_write(role + ".json", wire)

    # -- role document shape validation --------------------------------

    def _validate_role_doc(self, role, doc, where):
        if role == "timestamp":
            _validate_timestamp_doc(doc, where)
        elif role == "snapshot":
            _validate_snapshot_doc(doc, where)
        elif role == "targets":
            _validate_targets_doc(doc, where)
        else:
            raise ValueError("unknown role %r" % (role,))

    # -- serving verified target digests --------------------------------

    def target_digest(self, name):
        """Return ``(sha256_hex, length)`` for a verified target.

        Serves only while the refresher is ``"trusted"`` or
        ``"stale"``; raises :class:`SuspendedError` when suspended and
        :class:`KeyError` for an unbound target name.
        """
        if self._state not in ("trusted", "stale") \
                or "targets" not in self._chain:
            raise SuspendedError(
                "bundle refresher is %s%s: refusing to serve target "
                "digests" % (self._state,
                             ": " + self._reason if self._reason else ""))
        targets = self._chain["targets"]["doc"]["targets"]
        entry = targets.get(name)
        if entry is None:
            raise KeyError(name)
        return entry["hashes"]["sha256"], entry["length"]


def _validate_timestamp_doc(doc, where):
    if _check_int(doc.get("version", 0), where + ".version") < 1:
        raise RootChainError("%s: timestamp version must be >= 1" % where)
    if not isinstance(doc.get("expires"), str) or not doc["expires"]:
        raise RootChainError("%s: timestamp expires must be a non-empty "
                             "str" % where)
    _parse_time(doc["expires"], where + ".expires")
    snap = doc.get("snapshot")
    if not isinstance(snap, dict):
        raise RootChainError("%s: timestamp snapshot must be a dict"
                             % where)
    _check_fileinfo(snap, where + ".snapshot")


def _validate_snapshot_doc(doc, where):
    if _check_int(doc.get("version", 0), where + ".version") < 1:
        raise RootChainError("%s: snapshot version must be >= 1" % where)
    if not isinstance(doc.get("expires"), str) or not doc["expires"]:
        raise RootChainError("%s: snapshot expires must be a non-empty "
                             "str" % where)
    _parse_time(doc["expires"], where + ".expires")
    meta = doc.get("meta")
    if not isinstance(meta, dict):
        raise RootChainError("%s: snapshot meta must be a dict" % where)
    entry = meta.get("targets.json")
    if not isinstance(entry, dict):
        raise RootChainError("%s: snapshot meta must bind targets.json"
                             % where)
    _check_fileinfo(entry, where + ".meta.targets.json")


def _validate_targets_doc(doc, where):
    if _check_int(doc.get("version", 0), where + ".version") < 1:
        raise RootChainError("%s: targets version must be >= 1" % where)
    if not isinstance(doc.get("expires"), str) or not doc["expires"]:
        raise RootChainError("%s: targets expires must be a non-empty str"
                             % where)
    _parse_time(doc["expires"], where + ".expires")
    targets = doc.get("targets")
    if not isinstance(targets, dict):
        raise RootChainError("%s: targets must be a dict" % where)
    for name, entry in targets.items():
        if not isinstance(name, str) or not name:
            raise RootChainError("%s: target name must be a non-empty str"
                                 % where)
        if not isinstance(entry, dict):
            raise RootChainError("%s: target %r must be a dict"
                                 % (where, name))
        length = entry.get("length")
        if isinstance(length, bool) or not isinstance(length, int) \
                or length < 0:
            raise RootChainError("%s: target %r length must be a "
                                 "non-negative int" % (where, name))
        digest = (entry.get("hashes") or {}).get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(
                c not in "0123456789abcdef" for c in digest):
            raise RootChainError("%s: target %r needs a 64-char lowercase "
                                 "hex sha256" % (where, name))


def _check_fileinfo(info, where):
    _check_int(info.get("version", 0), where + ".version")
    if info["version"] < 1:
        raise RootChainError("%s: version must be >= 1" % where)
    length = info.get("length")
    if isinstance(length, bool) or not isinstance(length, int) \
            or length < 0:
        raise RootChainError("%s: length must be a non-negative int"
                             % where)
    digest = (info.get("hashes") or {}).get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(
            c not in "0123456789abcdef" for c in digest):
        raise RootChainError("%s: needs a 64-char lowercase hex sha256"
                             % where)
