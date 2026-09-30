"""Durable anti-rollback beyond expiry for versioned policies.

The in-process version floors in :class:`gov.jail_policy.JailPolicyRegistry`
and :class:`gov.measurement_policy.MeasurementPolicyRegistry` die with the
process. A deployment rolled back to an OLDER-YET-STILL-VALID policy bundle
-- or a fresh registry presented with an older policy after a restart --
would accept it: the floor is gone, the window is still open. This module
is the TUF/in-toto anti-rollback ADAPT (idea only; no upstream source
vendored, no conformance claimed): a **durable seen-version registry**
backed by **atomic version manifests**.

* A version manifest pins ``{policy_name: {version, digest}}``. Loading
  is all-or-nothing: a partial or malformed manifest is refused and
  commits nothing (``manifest-refused``).
* The registry records the highest version ever seen per policy name.
  Presenting a lower-but-unexpired version is a loud ``rollback-detected``
  refusal -- distinct from ``policy-expired`` (the candidate's own
  validity window passed) and ``policy-unknown`` (the name was never
  pinned by a manifest).
* A same-version replay is accepted only when the digest matches what
  was pinned/seen (``digest-mismatch`` otherwise).
* The registry starts empty ONLY via an explicit ``bootstrap()``
  ceremony, which writes an audit entry; a second bootstrap is refused
  (``already-bootstrapped``). Manifest updates are atomic and audited;
  a manifest that lowers an expected version is refused distinctly
  (``manifest-downgrade-refused``).
* Manifests are Ed25519-signed under a deployment-pinned manifest key
  (out-of-band pinning is the deployment's job); the domain-separated
  signing bytes bind format + entries. A rogue-key signature is
  ``manifest-refused``, not a quieter error.

Refusal codes are stable, machine-readable, and distinct by design:
``rollback-detected`` (older version presented where a newer was seen),
``policy-expired`` (candidate outside its own validity window),
``policy-unknown`` (name never pinned). Triage must never confuse them.

Digests are the pinned ``sha256:`` + 64-hex shape. The digest binds the
exact bytes the policy issuer signed (e.g. ``sha256`` of
``policy_signing_bytes(normalized_body)``); computing it is the
deployment's job and is documented at each wiring point.
"""

import hashlib
import json
import time

MANIFEST_FORMAT = "sasanam-version-manifest/v1"
_MANIFEST_SIGN_DOMAIN = b"sasanam-version-manifest-sign/v1:"


class VersionManifestError(Exception):
    """Fail-closed refusal with a stable machine-readable code."""

    def __init__(self, code, detail=""):
        super(VersionManifestError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _check_name(name, where):
    if not isinstance(name, str) or not name:
        raise VersionManifestError(
            "manifest-refused", "%s: policy name must be a non-empty str"
            % where)


def _check_version(version, where):
    if isinstance(version, bool) or not isinstance(version, int) \
            or version < 1:
        raise VersionManifestError(
            "manifest-refused", "%s: version must be an int >= 1" % where)


def _check_digest(digest, where):
    if not isinstance(digest, str) or not digest.startswith("sha256:") \
            or len(digest) != 7 + 64:
        raise VersionManifestError(
            "manifest-refused",
            "%s: digest must be 'sha256:' + 64 hex chars" % where)
    try:
        int(digest[7:], 16)
    except ValueError:
        raise VersionManifestError(
            "manifest-refused", "%s: digest hex is malformed" % where)


def _check_entry(name, entry):
    where = "entries[%r]" % (name,)
    if not isinstance(entry, dict) or sorted(entry) != ["digest", "version"]:
        raise VersionManifestError(
            "manifest-refused",
            "%s: entry must be exactly {version, digest}" % where)
    _check_version(entry["version"], where)
    _check_digest(entry["digest"], where)
    return {"version": entry["version"], "digest": entry["digest"]}


def canonical_manifest_bytes(body):
    """The exact bytes a manifest signature covers.

    Domain-separated: ``MANIFEST_SIGN_DOMAIN || sha256(canonical(body))``.
    """
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    return _MANIFEST_SIGN_DOMAIN + digest.encode("ascii")


def make_manifest(entries, signer):
    """Build a signed version manifest from plain data, atomically.

    ``entries`` maps policy name -> ``{"version": int>=1,
    "digest": "sha256:"+64hex}``. Every entry is validated BEFORE
    anything is signed: a single bad entry refuses the whole manifest
    (``manifest-refused``) and nothing partial is ever emitted.

    ``signer`` exposes ``.sign(bytes) -> 64 bytes`` (e.g.
    ``gov.signing.Ed25519Signer``); key custody is the deployment's job.
    Returns ``{"body": {...}, "signature": <hex>}``.
    """
    if not isinstance(entries, dict) or not entries:
        raise VersionManifestError(
            "manifest-refused", "manifest must pin at least one policy")
    normalized = {}
    for name in sorted(entries):
        _check_name(name, "entries")
        normalized[name] = _check_entry(name, entries[name])
    body = {"format": MANIFEST_FORMAT, "entries": normalized}
    try:
        signature = signer.sign(canonical_manifest_bytes(body))
    except VersionManifestError:
        raise
    except Exception as exc:
        raise VersionManifestError(
            "manifest-refused", "signing failed: %s" % exc)
    if not isinstance(signature, (bytes, bytearray)) \
            or len(signature) != 64:
        raise VersionManifestError(
            "manifest-refused", "signer must return 64 signature bytes")
    return {"body": body, "signature": bytes(signature).hex()}


def validate_manifest(signed, issuer_public_key):
    """Validate a signed manifest against the pinned issuer key.

    All-or-nothing: ANY defect -- envelope shape, format tag, entry
    shape, digest shape, or signature (including a rogue-key signature)
    -- raises ``manifest-refused`` and yields nothing. Returns the
    normalized ``{name: {"version", "digest"}}`` mapping on success.
    """
    if not isinstance(signed, dict) or sorted(signed) != ["body", "signature"]:
        raise VersionManifestError(
            "manifest-refused", "manifest must be exactly {body, signature}")
    body = signed["body"]
    if not isinstance(body, dict) or sorted(body) != ["entries", "format"]:
        raise VersionManifestError(
            "manifest-refused", "manifest body must be exactly "
            "{format, entries}")
    if body["format"] != MANIFEST_FORMAT:
        raise VersionManifestError(
            "manifest-refused", "unknown manifest format %r" % (
                body["format"],))
    entries = body["entries"]
    if not isinstance(entries, dict) or not entries:
        raise VersionManifestError(
            "manifest-refused", "manifest must pin at least one policy")
    normalized = {}
    for name in sorted(entries):
        _check_name(name, "entries")
        normalized[name] = _check_entry(name, entries[name])
    if not isinstance(issuer_public_key, (bytes, bytearray)) \
            or len(issuer_public_key) != 32:
        raise VersionManifestError(
            "manifest-refused", "issuer_public_key must be 32 bytes")
    signature = signed["signature"]
    try:
        sig_bytes = bytes.fromhex(signature) \
            if isinstance(signature, str) else bytes(signature)
    except (ValueError, TypeError):
        raise VersionManifestError(
            "manifest-refused", "manifest signature is malformed")
    if len(sig_bytes) != 64:
        raise VersionManifestError(
            "manifest-refused", "manifest signature must be 64 bytes")
    from gov import ed25519 as _ed
    if not _ed.verify(bytes(issuer_public_key),
                      canonical_manifest_bytes(
                          {"format": MANIFEST_FORMAT,
                           "entries": normalized}),
                      sig_bytes):
        raise VersionManifestError(
            "manifest-refused",
            "manifest is not signed by the pinned manifest issuer")
    return normalized


def manifest_digest(signed):
    """``sha256:`` digest of the canonical manifest body (audit pinning)."""
    return "sha256:" + hashlib.sha256(
        _canonical(signed["body"])).hexdigest()


class SeenVersionRegistry:
    """Durable seen-version registry: anti-rollback beyond expiry.

    The deployment creates ONE registry per trust domain, bootstraps it
    from a signed version manifest, and consults it (via the tighten-only
    wiring in the policy registries) before activating any policy
    version. ``highest_seen`` survives as long as the registry object
    does -- the deployment persists the registry (or its audit trail)
    across restarts; that persistence is the deployment's job and is
    documented, not assumed.
    """

    def __init__(self):
        self._expected = {}   # name -> {"version", "digest"}
        self._seen = {}       # name -> highest version ever authorized
        self._seen_digest = {}  # (name, version) -> digest
        self._bootstrapped = False

    # -- introspection -------------------------------------------------

    @property
    def bootstrapped(self):
        return self._bootstrapped

    def expected(self):
        """The currently pinned {name: {version, digest}} mapping."""
        return {name: dict(entry)
                for name, entry in self._expected.items()}

    def highest_seen(self):
        """The highest authorized version per name (rollback floor)."""
        return dict(self._seen)

    # -- audit ----------------------------------------------------------

    @staticmethod
    def _check_audit(audit):
        if audit is not None and not callable(audit) \
                and not isinstance(audit, list):
            raise VersionManifestError(
                "manifest-refused", "audit must be None, a list, or callable")

    @classmethod
    def _audit(cls, audit, event, names, versions, epoch):
        entry = {"event": event, "names": sorted(names),
                 "versions": dict(versions), "at": epoch}
        if audit is None:
            return
        cls._check_audit(audit)
        if callable(audit):
            audit(entry)
        else:
            audit.append(entry)

    # -- lifecycle ------------------------------------------------------

    def bootstrap(self, signed_manifest, issuer_public_key, *, audit=None,
                  now=None):
        """Explicit bootstrap ceremony: the ONLY way to start empty.

        Refuses ``already-bootstrapped`` on a non-empty registry (history
        is append-only; rewriting it requires a fresh registry object,
        which is itself a deployment-visible event). Writes an audit
        entry on success. Returns the pinned mapping.
        """
        if self._bootstrapped:
            raise VersionManifestError(
                "already-bootstrapped",
                "registry already bootstrapped; history cannot be rewritten")
        self._check_audit(audit)
        pinned = validate_manifest(signed_manifest, issuer_public_key)
        self._expected = pinned
        self._bootstrapped = True
        epoch = int(now) if now is not None else int(time.time())
        self._audit(audit, "rollback-guard-bootstrap",
                    pinned.keys(),
                    {n: e["version"] for n, e in pinned.items()}, epoch)
        return self.expected()

    def update_manifest(self, signed_manifest, issuer_public_key, *,
                        audit=None, now=None):
        """Atomically replace the pinned manifest, audited.

        All-or-nothing: a malformed or rogue-signed manifest is refused
        and the previous pinning stays in force. A manifest that LOWERS
        an expected version is refused distinctly
        (``manifest-downgrade-refused``) -- manifests may add names and
        raise versions, never roll back. New names start with a clean
        seen floor. Returns the new pinned mapping.
        """
        if not self._bootstrapped:
            raise VersionManifestError(
                "bootstrap-required",
                "registry must be bootstrapped before manifest updates")
        self._check_audit(audit)
        pinned = validate_manifest(signed_manifest, issuer_public_key)
        for name, entry in pinned.items():
            old = self._expected.get(name)
            if old is not None and entry["version"] < old["version"]:
                raise VersionManifestError(
                    "manifest-downgrade-refused",
                    "manifest lowers %r from v%d to v%d" % (
                        name, old["version"], entry["version"]))
        self._expected = pinned
        epoch = int(now) if now is not None else int(time.time())
        self._audit(audit, "rollback-guard-manifest-update",
                    pinned.keys(),
                    {n: e["version"] for n, e in pinned.items()}, epoch)
        return self.expected()

    # -- the gate -------------------------------------------------------

    def _floor(self, name):
        entry = self._expected[name]
        return max(entry["version"], self._seen.get(name, 0))

    def _check_candidate(self, name, version, digest, epoch, not_after):
        if not self._bootstrapped:
            raise VersionManifestError(
                "bootstrap-required",
                "registry not bootstrapped; refusing all activation")
        # Name shape first: an unhashable name must fail closed with a
        # named code, never a bare TypeError from the dict lookup.
        _check_name(name, "authorize")
        if name not in self._expected:
            raise VersionManifestError(
                "policy-unknown",
                "policy %r was never pinned by a version manifest" % (name,))
        _check_version(version, "authorize")
        _check_digest(digest, "authorize")
        # Expiry is intrinsic to the candidate: checked before history.
        if not_after is not None:
            if isinstance(not_after, bool) or not isinstance(not_after,
                                                             int):
                raise VersionManifestError(
                    "manifest-refused", "not_after must be an int or None")
            if epoch >= not_after:
                raise VersionManifestError(
                    "policy-expired",
                    "policy %r v%d expired at %d" % (name, version,
                                                    not_after))
        # Rollback needs history: anything below the floor is a downgrade.
        floor = self._floor(name)
        if version < floor:
            raise VersionManifestError(
                "rollback-detected",
                "policy %r v%d is older than the highest seen v%d "
                "(rollback refused)" % (name, version, floor))
        # Same-version replay must carry the same bytes.
        key = (name, version)
        expected_digest = self._expected[name]["digest"]
        if version == self._expected[name]["version"] \
                and digest != expected_digest:
            raise VersionManifestError(
                "digest-mismatch",
                "policy %r v%d digest does not match the pinned manifest "
                "digest" % (name, version))
        prior = self._seen_digest.get(key)
        if prior is not None and digest != prior:
            raise VersionManifestError(
                "digest-mismatch",
                "policy %r v%d digest differs from the previously seen "
                "digest" % (name, version))
        return floor

    def authorize_activation(self, name, version, *, digest, now=None,
                             not_after=None):
        """Authorize activating ``(name, version)``, recording history.

        Fail-closed with the distinct codes documented above. On success
        the version is recorded (the floor only ever rises) and a
        report ``{"name", "version", "floor", "replay"}`` is returned.
        ``replay`` is True when this exact version was already seen.

        ``not_after`` is the candidate's own validity bound (int epoch);
        ``None`` skips the expiry check (for versioned objects with no
        validity window, e.g. quorum steps in v1 -- documented, not
        silent: the report carries ``expiry_checked: False``).

        NOTE: authorization records the version immediately. If the
        caller's own subsequent checks then refuse the candidate, the
        floor has still risen -- a later legitimate older version will
        be refused as a rollback. Deployments should call this gate
        AFTER signature verification (so attacker probes cannot poison
        history) and treat a raised floor as the cost of a seen version.
        """
        epoch = int(now) if now is not None else int(time.time())
        floor = self._check_candidate(name, version, digest, epoch,
                                      not_after)
        already_seen = version <= self._seen.get(name, 0)
        pinned_replay = (version == self._expected[name]["version"]
                         and (name, version) in self._seen_digest)
        replay = already_seen or pinned_replay
        self._seen[name] = max(self._seen.get(name, 0), version)
        self._seen_digest.setdefault((name, version), digest)
        return {"name": name, "version": version,
                "floor": self._seen[name], "replay": bool(replay),
                "expiry_checked": not_after is not None}

    def check_use(self, name, version, *, digest=None, now=None,
                  not_after=None):
        """Non-mutating use-time check (for get/check seams).

        Same refusal codes as :meth:`authorize_activation`; records
        nothing. ``digest``, when supplied, is verified against the
        pinned/seen digest.
        """
        epoch = int(now) if now is not None else int(time.time())
        if digest is None:
            # Verify everything except the digest binding.
            if not self._bootstrapped:
                raise VersionManifestError(
                    "bootstrap-required",
                    "registry not bootstrapped; refusing all use")
            _check_name(name, "check_use")
            if name not in self._expected:
                raise VersionManifestError(
                    "policy-unknown",
                    "policy %r was never pinned by a version manifest"
                    % (name,))
            _check_version(version, "check_use")
            if not_after is not None and epoch >= not_after:
                raise VersionManifestError(
                    "policy-expired",
                    "policy %r v%d expired at %d" % (name, version,
                                                    not_after))
            if version < self._floor(name):
                raise VersionManifestError(
                    "rollback-detected",
                    "policy %r v%d is older than the highest seen v%d"
                    % (name, version, self._floor(name)))
            return {"name": name, "version": version,
                    "floor": self._floor(name), "replay": True,
                    "expiry_checked": not_after is not None}
        self._check_candidate(name, version, digest, epoch, not_after)
        return {"name": name, "version": version,
                "floor": self._floor(name), "replay": True,
                "expiry_checked": not_after is not None}
