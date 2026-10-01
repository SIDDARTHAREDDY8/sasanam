"""Install-time skill-update client: the admission gate for skill bundles.

W248-4 (STEAL, build: python-tuf ngclient pattern, re-implemented --
nothing vendored). ``gov/bundle_refresh.py`` (wave-206) already
verifies the repository metadata chain (root/timestamp/snapshot/
targets: signatures, rollback, expiry, thresholds) and serves verified
target pins. This module is the complementary install-time half: the
deployment fetched bundle bytes and must decide install/refuse against

1. the skill record ``{name, version, digest, expires}``,
2. the chain's pinned digest for that skill, and
3. the locally installed version.

A skill that arrived outside the verified metadata chain is
indistinguishable from a plant and is refused at install
(``skill-update-index-untrusted``). Installing on a stale or suspended
chain is refused fail-closed: the refresh path may serve stale metadata
loudly for availability, but the install path is a security boundary
and admits new software only on a trusted chain.

Refusals (domain ``skill-update``, all in ``EXPECTED_CODES``):

- ``skill-update-index-untrusted`` -- no trusted chain pin for this
  skill: the pin is missing/malformed, the chain state is not
  ``"trusted"``, or the skill is unbound from the chain.
- ``skill-update-metadata-expired`` -- the skill record is past its
  expiry (``now >= expires``; expiry is exclusive).
- ``skill-update-record-unpinned`` -- the record's digest does not
  match the chain's pinned digest: mix-and-match of records across
  versions, or a planted record.
- ``skill-update-digest-mismatch`` -- the bundle bytes' sha256 does not
  match the record's digest: tampered or truncated download.
- ``skill-update-version-rollback`` -- the record's version is strictly
  older than the installed version. Same-version reinstall of
  identical bytes is allowed (idempotent); upgrades advance the
  installed state.
- ``skill-update-digest-changed`` -- the record's version equals the
  installed version but the digest differs from the installed digest:
  a same-version reinstall must be of identical bytes (idempotent);
  swapping the bytes under a pinned version is refused.
- ``skill-update-malformed`` -- the record, pin, or bundle input is
  not the expected shape (wrong types, bad digest format, negative
  version, unknown record keys).

Check order is fixed and documented: malformed -> index-untrusted ->
metadata-expired -> record-unpinned -> digest-mismatch ->
version-rollback -> digest-changed. Time (``now``) is an explicit
epoch-int argument; this module reads no clock, performs no I/O,
and makes no network calls. The transport that fetched the bytes is
deployment-owned.

The installed-state map is deployment-owned persistent state: it maps
skill name -> ``(version, digest)`` of the installed bundle. The
client holds it in memory and advances it on each successful install;
the deployment persists it across restarts. Tracking the installed
digest closes F211: a same-version reinstall must carry identical
bytes, and a digest change under a pinned version is refused rather
than silently overwriting the installed bundle.

Stdlib only. Deterministic.
"""

import hashlib

#: The refusal codes this module can raise, pinned by
#: ``evals/w248_skill_update_probes.py``.
EXPECTED_CODES = (
    "skill-update-index-untrusted",
    "skill-update-metadata-expired",
    "skill-update-record-unpinned",
    "skill-update-digest-mismatch",
    "skill-update-version-rollback",
    "skill-update-digest-changed",
    "skill-update-malformed",
)

#: Record keys. Unknown keys are refused: a security gate does not
#: silently accept fields it does not understand.
_RECORD_KEYS = frozenset(("name", "version", "digest", "expires"))

_HEX = frozenset("0123456789abcdef")


class SkillUpdateError(Exception):
    """Fail-closed refusal from the install gate.

    ``code`` is the taxonomy refusal string; ``detail`` is a
    human-readable explanation that never carries secret material.
    """

    def __init__(self, code, detail):
        super(SkillUpdateError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    if code not in EXPECTED_CODES:
        raise AssertionError("unknown refusal code %r" % (code,))
    raise SkillUpdateError(code, detail)


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in _HEX for c in value))


def _check_record(record):
    if not isinstance(record, dict):
        _refuse("skill-update-malformed",
                "skill record must be a dict, got %s"
                % type(record).__name__)
    keys = set(record.keys())
    if keys != _RECORD_KEYS:
        _refuse("skill-update-malformed",
                "skill record keys must be exactly %s"
                % sorted(_RECORD_KEYS))
    name = record["name"]
    version = record["version"]
    digest = record["digest"]
    expires = record["expires"]
    if not isinstance(name, str) or not name:
        _refuse("skill-update-malformed",
                "skill record name must be a non-empty string")
    if (not isinstance(version, int)
            or isinstance(version, bool) or version < 0):
        _refuse("skill-update-malformed",
                "skill record version must be a non-negative int")
    if not _is_hex64(digest):
        _refuse("skill-update-malformed",
                "skill record digest must be 64 lowercase hex chars")
    if (not isinstance(expires, int)
            or isinstance(expires, bool) or expires < 0):
        _refuse("skill-update-malformed",
                "skill record expires must be a non-negative int "
                "epoch")
    return name, version, digest, expires


def _check_pin(pin):
    # The pin is the verified chain's binding for this skill:
    # {"digest": hex64, "chain_state": "trusted"}. Anything else --
    # missing, malformed, stale/suspended chain, unbound skill -- is
    # refused: a skill outside the trusted chain is a plant.
    if not isinstance(pin, dict):
        _refuse("skill-update-index-untrusted",
                "no verified chain pin for this skill")
    digest = pin.get("digest")
    state = pin.get("chain_state")
    if not _is_hex64(digest) or state != "trusted":
        _refuse("skill-update-index-untrusted",
                "chain pin unavailable or chain not trusted "
                "(state=%r)" % (state,))
    return digest


def _check_bundle(bundle):
    if not isinstance(bundle, (bytes, bytearray)):
        _refuse("skill-update-malformed",
                "bundle must be bytes, got %s"
                % type(bundle).__name__)
    if len(bundle) == 0:
        _refuse("skill-update-malformed",
                "bundle must not be empty")
    return bytes(bundle)


def _check_now(now):
    if (not isinstance(now, int)
            or isinstance(now, bool) or now < 0):
        _refuse("skill-update-malformed",
                "now must be a non-negative int epoch")
    return now


class SkillUpdateClient(object):
    """Install-time admission gate for skill bundles.

    ``installed`` maps skill name -> ``(version, digest)`` of the
    installed bundle (a 2-tuple or 2-list; the digest is the sha256 of
    the installed bundle bytes). It is deployment-owned persistent
    state; the client advances it on each successful install and the
    deployment persists it. The digest is tracked so that a
    same-version reinstall must be of identical bytes (F211).
    """

    def __init__(self, installed=None):
        self._installed = {}
        for name, entry in (installed or {}).items():
            if not isinstance(name, str) or not name:
                raise SkillUpdateError(
                    "skill-update-malformed",
                    "installed map keys must be non-empty strings")
            if (not isinstance(entry, (tuple, list))
                    or len(entry) != 2):
                raise SkillUpdateError(
                    "skill-update-malformed",
                    "installed map must be {non-empty str: "
                    "(version int, digest hex64)}")
            version, digest = entry
            if (not isinstance(version, int)
                    or isinstance(version, bool) or version < 0):
                raise SkillUpdateError(
                    "skill-update-malformed",
                    "installed map must be {non-empty str: "
                    "(non-negative int version, digest hex64)}")
            if not _is_hex64(digest):
                raise SkillUpdateError(
                    "skill-update-malformed",
                    "installed map must be {non-empty str: "
                    "(non-negative int version, digest hex64)}")
            self._installed[name] = (version, digest)

    def installed_version(self, name):
        """Return the installed version for ``name``, or None."""
        entry = self._installed.get(name)
        return entry[0] if entry is not None else None

    def installed_digest(self, name):
        """Return the installed digest for ``name``, or None."""
        entry = self._installed.get(name)
        return entry[1] if entry is not None else None

    def install(self, bundle_bytes, record, pin, now):
        """Admit or refuse a skill bundle.

        ``bundle_bytes``: the fetched bundle bytes. ``record``: the
        skill record ``{name, version, digest, expires}``. ``pin``:
        the verified chain's binding ``{"digest": hex, "chain_state":
        "trusted"}`` (e.g. from ``BundleRefresher.target_digest`` plus
        the refresher's report state). ``now``: epoch int.

        Returns the install receipt ``{"name", "version", "digest"}``
        and advances the installed version on success. Raises
        :class:`SkillUpdateError` on any refusal.
        """
        bundle = _check_bundle(bundle_bytes)
        name, version, digest, expires = _check_record(record)
        pinned = _check_pin(pin)
        now = _check_now(now)
        if now >= expires:
            _refuse("skill-update-metadata-expired",
                    "skill record for %r expired at %d (now %d)"
                    % (name, expires, now))
        if digest != pinned:
            _refuse("skill-update-record-unpinned",
                    "skill record digest for %r v%d does not match "
                    "the chain pin" % (name, version))
        actual = hashlib.sha256(bundle).hexdigest()
        if actual != digest:
            _refuse("skill-update-digest-mismatch",
                    "bundle bytes sha256 does not match the skill "
                    "record digest for %r v%d" % (name, version))
        installed = self._installed.get(name)
        if installed is not None and version < installed[0]:
            _refuse("skill-update-version-rollback",
                    "skill %r v%d is older than installed v%d"
                    % (name, version, installed[0]))
        if (installed is not None and version == installed[0]
                and digest != installed[1]):
            _refuse("skill-update-digest-changed",
                    "skill %r v%d digest changed: same-version "
                    "reinstall must be identical bytes (F211)"
                    % (name, version))
        self._installed[name] = (version, digest)
        return {"name": name, "version": version, "digest": digest}


def pin_from_refresher(refresher, name):
    """Build the install pin for ``name`` from a ``BundleRefresher``.

    This is the deployment's one-liner wiring the wave-206 refresh
    chain to the install gate: the refresher vouches the digest, the
    gate enforces the ``"trusted"`` policy.

    Returns ``{"digest": hex, "chain_state": refresher.state}``.
    Raises ``bundle_refresh.SuspendedError`` when the refresher cannot
    serve and ``KeyError`` for an unbound skill name (both propagate;
    the install gate refuses fail-closed on a missing pin).

    A ``"stale"`` chain_state flows through to :meth:`SkillUpdateClient.install`,
    which refuses it as ``skill-update-index-untrusted`` — the install
    path never serves stale, even though the refresh path may.
    """
    digest, _length = refresher.target_digest(name)
    return {"digest": digest, "chain_state": refresher.state}
