"""Key providers for the governance log: what "production" means for keys.

This module is the **key-resolution chokepoint** for ``gov/log.py`` (see
``_active_key``, which delegates here). It answers two questions the
wave-61 deployment_mode precedent demands be explicit:

1. **Which key?** The ``KeyProvider`` ABC with one implementation per
   custody story. Exactly one provider resolves per process; providers
   never silently substitute for each other.
2. **Is this production?** ``resolve_deployment_mode()`` — explicit
   kwarg wins, then ``GOV_DEPLOYMENT_MODE``, then the least-privilege
   default ``"production"``; unknown modes fail fast. In production
   mode the dev-key provider **refuses loud** (the wave-61 contradiction
   shape): a deployment that declared itself production but has dev-key
   enabling active is misconfigured, and starting a dev-keyed chain
   behind a stderr warning is no longer an option.

Providers:

* ``DevKeyProvider`` — the public development key. Tests/dev ONLY:
  requires the double opt-in (in-code ``enable_dev_keys()`` AND
  ``GOV_DEV_KEYS=1``), warns loudly on resolve, and refuses outright in
  production mode. There is no configuration that makes it valid in
  production (dev bytes / ``dev`` epoch / dev in the archive are all
  rejected — F73/F77).
* ``EnvKeyProvider`` — ``GOV_LOG_KEY`` (+ ``GOV_LOG_KEY_EPOCH`` /
  ``GOV_LOG_KEY_ARCHIVE``) backend. Dev material screened on resolve.
* ``FileKeyProvider`` — the local software reference provider: a
  file-backed ``keys.KeyRing`` (0600 enforced on load, atomic 0600
  writes). Least-bad $0 local custody; documented honestly as not-HSM
  (readable by the uid/root, backups exfiltrate, no hardware custody,
  no access logging).
* ``EnvelopeKmsProvider`` — ``kms.EnvelopeKeyRing`` + a ``KmsProvider``:
  the persisted file holds wrapped blobs only; plaintext exists only in
  memory after explicit unwrap. Operator-driven (load → materialize →
  activate), not auto-detected — KMS custody is a deployment choice.

Resolution order in :func:`resolve_active_key`: configured env key →
configured keyring file → (production: refuse / non-production +
double opt-in: dev key, loud). ``gov/log.py`` owns chain mechanics and
is untouched except for delegating resolution here.

$0 spend, synthetic/local only. No credentials, no network.
"""

import abc
import os

from .keys import KeyRing, NoKeyConfiguredError

# Wave-61 precedent (gov/sandbox.py::_resolve_seccomp_tier): explicit
# declaration, default least-privilege, unknown fails fast. The sandbox
# knows ("production", "staging"); the key path additionally accepts the
# "dev"/"test" aliases the test corpus uses — all three are
# non-production and behave identically.
DEPLOYMENT_MODES = ("production", "staging", "dev", "test")
_NON_PROD_MODES = ("staging", "dev", "test")

_ENV_MODE = "GOV_DEPLOYMENT_MODE"
_ENV_KEY = "GOV_LOG_KEY"
_ENV_KEYRING_FILE = "GOV_KEYRING_FILE"


def resolve_deployment_mode(explicit=None):
    """Resolve the deployment mode (wave-61 precedent).

    Precedence: explicit kwarg (authoritative) > ``GOV_DEPLOYMENT_MODE``
    env > ``"production"`` (least-privilege default; ambiguity defaults
    to the safe direction). Unknown modes raise ``ValueError`` fail-fast:
    an unknown mode never silently means "no guard".
    """
    if explicit is not None:
        mode = str(explicit).strip()
    else:
        mode = os.environ.get(_ENV_MODE, "").strip()
    if not mode:
        return "production"
    if mode not in DEPLOYMENT_MODES:
        raise ValueError(
            "unknown deployment_mode %r: must be one of %s (fail-closed; "
            "an unknown mode never silently disables the key guard)"
            % (mode, ", ".join(DEPLOYMENT_MODES)))
    return mode


def production_contradiction(mode):
    """Return the production/dev contradiction exception, or ``None``.

    Wave-69: production mode (explicit or the least-privilege default)
    with BOTH dev-key opt-in factors present — ``gov.log.enable_dev_keys()``
    in code AND ``GOV_DEV_KEYS=1`` in the environment — is a deployment
    contradiction: refuse loudly rather than fall back to the public dev
    key. Shared by ``resolve_active_key()`` and ``keys.require_key()`` so
    both paths apply the same rule.
    """
    from . import log as _logmod
    if (mode == "production" and _logmod.dev_keys_enabled()
            and os.environ.get("GOV_DEV_KEYS") == "1"):
        return NoKeyConfiguredError(_CONTRADICTION_MESSAGE)
    return None


def _dev_material_rejected(key_bytes, epoch, status=None):
    """True when the key material is the public dev key by bytes, epoch
    label, or keyring status. Centralizes the F73/F77 screen so every
    provider applies it identically."""
    # Lazy: gov/log.py imports this module at top level; a top-level
    # import back would be circular. By call time both are initialized.
    from . import log as _logmod
    if key_bytes == _logmod._DEV_KEY:
        return True
    if epoch == "dev":
        return True
    if status == "dev":
        return True
    return False


class KeyProvider(abc.ABC):
    """One custody story for the log's HMAC key. Exactly one resolves
    per process; providers never silently substitute for each other."""

    provider_name = "abstract"

    @abc.abstractmethod
    def resolve(self):
        """Return ``(key_bytes, key_epoch)``. Raises
        :class:`NoKeyConfiguredError` (or ``KmsError`` for KMS-side
        failures) instead of returning a weaker key. Fail-closed."""

    def describe(self):
        """Safe public description — never key material."""
        return {"provider": self.provider_name}


class DevKeyProvider(KeyProvider):
    """The public development key. TESTS/DEV ONLY — loudly marked.

    Requires the double opt-in: the process called
    ``gov.log.enable_dev_keys()`` in code AND ``GOV_DEV_KEYS=1`` is set.
    Emits the loud stderr banner on every resolution (the warning state
    lives in ``gov.log`` so the once-per-process semantics are shared
    with the legacy path). **Refuses outright in production mode** —
    there is no configuration that makes the dev key valid there.
    """

    provider_name = "dev"

    def __init__(self, deployment_mode=None):
        self._mode = resolve_deployment_mode(deployment_mode)

    def resolve(self):
        from . import log as _logmod
        if self._mode == "production":
            raise NoKeyConfiguredError(
                "refusing to resolve the PUBLIC development key in "
                "deployment_mode='production': the process explicitly "
                "opted into dev keys in code (enable_dev_keys()) AND "
                "GOV_DEV_KEYS=1 is set, which contradicts production "
                "mode. Dev keys are never valid in production. Resolve "
                "the contradiction explicitly — declare a non-production "
                "mode (GOV_DEPLOYMENT_MODE=staging) or configure a real "
                "key (GOV_LOG_KEY / GOV_KEYRING_FILE). Fail-closed: no "
                "chain started.")
        if not (_logmod.dev_keys_enabled()
                and os.environ.get("GOV_DEV_KEYS") == "1"):
            raise NoKeyConfiguredError(
                "dev keys require the explicit double opt-in: "
                "gov.log.enable_dev_keys() in code AND GOV_DEV_KEYS=1 in "
                "the environment (test harnesses only).")
        if not _logmod._dev_warned:
            _logmod._dev_warned = True
            import sys
            print(
                "GOVERNANCE KEY WARNING: GOV_DEV_KEYS=1 with explicit "
                "in-code dev-key opt-in; using the PUBLIC development "
                "key. This log is NOT tamper-evident against anyone who "
                "read the docs. Never use for real audit data.",
                file=sys.stderr,
            )
        return _logmod._DEV_KEY, "dev"

    def describe(self):
        return {"provider": self.provider_name,
                "key_epoch": "dev",
                "warning": "PUBLIC development key — zero integrity; "
                           "test/dev only, never production"}


class EnvKeyProvider(KeyProvider):
    """``GOV_LOG_KEY`` backend (epoch from ``GOV_LOG_KEY_EPOCH``).

    Dev material is screened on resolve: a configured key that IS the
    public dev key (bytes, ``dev`` epoch) is rejected outright — pasting
    the dev key into ``GOV_LOG_KEY`` does not make it a production key
    (F73).
    """

    provider_name = "env"

    def resolve(self):
        from . import log as _logmod
        raw = os.environ.get(_ENV_KEY)
        if not raw:
            raise NoKeyConfiguredError("GOV_LOG_KEY is not set")
        epoch = os.environ.get("GOV_LOG_KEY_EPOCH", "env")
        key = raw.encode("utf-8")
        if _dev_material_rejected(key, epoch):
            raise NoKeyConfiguredError(
                "the configured key is the public development key (bytes "
                "or 'dev' epoch); dev keys are rejected on the production "
                "path (F73/R6c)")
        return key, epoch

    def describe(self):
        return {"provider": self.provider_name,
                "epoch": os.environ.get("GOV_LOG_KEY_EPOCH", "env")}


class FileKeyProvider(KeyProvider):
    """Local software reference provider: file-backed ``keys.KeyRing``.

    The keyring file must already exist (operator-created); load enforces
    0600 (refuses group/world-readable). The ACTIVE key's material is
    screened for dev bytes/epoch/status — a keyring seeded with the dev
    key is not a production keyring. Least-bad $0 local custody, and
    honestly not HSM: readable by the uid and root, backups exfiltrate
    it, no hardware custody, no tamper-evident access logging.
    """

    provider_name = "file"

    def __init__(self, path):
        self._path = str(path)

    def resolve(self):
        ring = KeyRing.load(self._path)  # 0600 enforced; may raise
        active = ring.active()
        if _dev_material_rejected(active.key, active.epoch,
                                  active.status):
            raise NoKeyConfiguredError(
                "keyring %s: the active key is the public development key "
                "(bytes, 'dev' epoch, or 'dev' status); dev keys are "
                "rejected on the production path" % (self._path,))
        return active.key, active.epoch

    def describe(self):
        return {"provider": self.provider_name,
                "keyring_file": self._path}


class EnvelopeKmsProvider(KeyProvider):
    """KMS envelope provider: ``kms.EnvelopeKeyRing`` + a ``KmsProvider``.

    The persisted file holds wrapped blobs + metadata only. Resolve
    unwraps the ACTIVE epoch via the KMS API (fail-closed: outage, auth
    failure, unknown/disabled key, tampered blob, or key-id mismatch all
    raise ``KmsError`` — never a weaker key). Operator-driven: construct
    explicitly with a provider; never auto-detected from env, so no
    attacker-influenceable variable can select the KMS story.

    NOTE: resolve() unwraps on every call — deployments should
    ``materialize()`` once and ``activate()`` (publishing to the process
    environment, the ``EnvKeyProvider`` path) rather than resolving per
    append.
    """

    provider_name = "envelope-kms"

    def __init__(self, envelope_path, kms_provider):
        self._path = str(envelope_path)
        self._provider = kms_provider

    def resolve(self):
        # Lazy: gov/kms.py imports gov/keys.py (not this module), so a
        # top-level import would be fine, but lazy keeps import cheap
        # for the common env/dev paths.
        from . import kms as _kmsmod
        ring = _kmsmod.EnvelopeKeyRing.load(self._path)
        materialized = ring.materialize(self._provider)  # may raise KmsError
        active = materialized.active()
        if _dev_material_rejected(active.key, active.epoch,
                                  active.status):
            raise NoKeyConfiguredError(
                "envelope keyring %s: the unwrapped active key is the "
                "public development key; dev keys are rejected on the "
                "production path" % (self._path,))
        return active.key, active.epoch

    def describe(self):
        return {"provider": self.provider_name,
                "envelope_file": self._path,
                "kms_provider": self._provider.provider_name}


# Byte-identical to the pre-wave-69 gov/log.py::_active_key refusal: the
# F73 posture for "no key configured" is unchanged by the mode gate; only
# the new production+dev contradiction adds a message.
_F73_NO_KEY_MESSAGE = (
    "GOV_LOG_KEY is not set and dev keys are not enabled for this "
    "process (F73: no silent dev-key fallback). Configure a production "
    "key, or \u2014 local test harnesses only \u2014 call "
    "gov.log.enable_dev_keys() in code with GOV_DEV_KEYS=1 in the "
    "environment.")

_CONTRADICTION_MESSAGE = (
    "refusing to start the chain in deployment_mode='production': the "
    "process explicitly opted into dev keys in code "
    "(enable_dev_keys()) AND GOV_DEV_KEYS=1 is set, which contradicts "
    "production mode. Dev keys are never valid in production \u2014 a "
    "dev-keyed 'production' chain would be forgeable by anyone who read "
    "the docs (F29). Resolve the contradiction explicitly: declare a "
    "non-production mode (GOV_DEPLOYMENT_MODE=staging) for test/dev "
    "runs, or configure a real key (GOV_LOG_KEY / GOV_KEYRING_FILE). "
    "Fail-closed: no chain started.")


def resolve_active_key(deployment_mode=None):
    """The single key-resolution chokepoint (used by ``gov/log.py``).

    Order: ``GOV_LOG_KEY`` (env provider) → ``GOV_KEYRING_FILE`` (file
    provider) → production: refuse / non-production + double opt-in: dev
    key (loud). The production+dev contradiction refuses LOUD (wave-69);
    every other refusal is the pre-existing F73 posture, unchanged.
    Returns ``(key_bytes, key_epoch)``.
    """
    mode = resolve_deployment_mode(deployment_mode)
    if os.environ.get(_ENV_KEY):
        return EnvKeyProvider().resolve()
    keyring_file = os.environ.get(_ENV_KEYRING_FILE, "").strip()
    if keyring_file:
        return FileKeyProvider(keyring_file).resolve()
    # Wave-69 contradiction (the _resolve_seccomp_tier shape): a deployment
    # that declared itself production but has dev-key enabling active is
    # misconfigured — starting a dev-keyed chain behind a stderr warning is
    # no longer an option.
    contradiction = production_contradiction(mode)
    if contradiction is not None:
        raise contradiction
    # Lazy: gov/log.py imports this module at top level (see _active_key).
    from . import log as _logmod
    if (_logmod.dev_keys_enabled()
            and os.environ.get("GOV_DEV_KEYS") == "1"):
        # Non-production mode: the legacy dev path (loud warning).
        return DevKeyProvider(deployment_mode=mode).resolve()
    raise NoKeyConfiguredError(_F73_NO_KEY_MESSAGE)
