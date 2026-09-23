"""Key providers for the governance log: what "production" means for keys.

This module is the **key-resolution chokepoint** for ``gov/log.py`` (see
``_active_key``, which delegates here). It answers two questions:

1. **Which key?** The ``KeyProvider`` ABC with one implementation per
   custody story. Exactly one provider resolves per process; providers
   never silently substitute for each other.
2. **Is this production?** ``resolve_deployment_mode()`` — explicit
   kwarg wins, then ``GOV_DEPLOYMENT_MODE``, then the least-privilege
   default ``"production"``; unknown modes fail fast. The mode is
   validated but no longer selects a key story: since wave-81,
   provisioning is explicit in every mode — the dev-key provider, the
   public dev key, and every opt-in were deleted from ``gov/``.

Providers:

* ``EnvKeyProvider`` — ``GOV_LOG_KEY`` (+ ``GOV_LOG_KEY_EPOCH`` /
  ``GOV_LOG_KEY_ARCHIVE``) backend. Configured keys are used as-is.
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
configured keyring file → loud ``NoKeyConfiguredError`` in every mode.
Wave-81 deleted the dev-key provider and every dev-key opt-in from
``gov/``: no code path mints, derives, or falls back to a dev key.
``gov/log.py`` owns chain mechanics and is untouched except for
delegating resolution here.

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


# Wave-81: production_contradiction() DELETED. It existed to refuse the
# production-mode + dev-key-opt-in combination; with the dev key and
# every opt-in deleted from gov/, the contradiction is unstatable.


# Wave-81: _dev_material_rejected() DELETED. It screened configured
# keys against the public dev key's bytes/epoch/status; the public dev
# key no longer exists anywhere in gov/, so there is nothing to screen
# for. Configured keys are operator-chosen and used as-is.

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


# Wave-81: DevKeyProvider DELETED — the public dev key, the double
# opt-in, and the production/dev contradiction are gone from gov/
# entirely. Test harnesses provision explicit random keys
# (tests/keyfixture.py) through the EnvKeyProvider backend, like
# production.


class EnvKeyProvider(KeyProvider):
    """``GOV_LOG_KEY`` backend (epoch from ``GOV_LOG_KEY_EPOCH``).

    Configured keys are used as-is: since wave-81 there is no dev key
    in ``gov/`` to screen for, so the retired F73 byte/epoch screen is
    gone. An operator-chosen key is an operator-chosen key.
    """

    provider_name = "env"

    def resolve(self):
        raw = os.environ.get(_ENV_KEY)
        if not raw:
            raise NoKeyConfiguredError("GOV_LOG_KEY is not set")
        epoch = os.environ.get("GOV_LOG_KEY_EPOCH", "env")
        return raw.encode("utf-8"), epoch

    def describe(self):
        return {"provider": self.provider_name,
                "epoch": os.environ.get("GOV_LOG_KEY_EPOCH", "env")}


class FileKeyProvider(KeyProvider):
    """Local software reference provider: file-backed ``keys.KeyRing``.

    The keyring file must already exist (operator-created); load enforces
    0600 (refuses group/world-readable). The ACTIVE key's material is
    used as-is. Least-bad $0 local custody, and honestly not HSM:
    readable by the uid and root, backups exfiltrate it, no hardware
    custody, no tamper-evident access logging.
    """

    provider_name = "file"

    def __init__(self, path):
        self._path = str(path)

    def resolve(self):
        ring = KeyRing.load(self._path)  # 0600 enforced; may raise
        active = ring.active()
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
        return active.key, active.epoch

    def describe(self):
        return {"provider": self.provider_name,
                "envelope_file": self._path,
                "kms_provider": self._provider.provider_name}


# Wave-81: the dev-key fallback is GONE — this is the refusal every
# unprovisioned deployment gets, in every mode.
_NO_KEY_MESSAGE = (
    "no key configured: GOV_LOG_KEY is unset and no keyring file is "
    "configured (F73: no silent fallback). Wave-81 removed the dev key "
    "from gov/ entirely, so there is no fallback in any deployment "
    "mode. Configure a key explicitly: GOV_LOG_KEY (+ GOV_LOG_KEY_EPOCH), "
    "GOV_KEYRING_FILE, or activate a keyring (gov.keys / gov.kms). "
    "Fail-closed: no chain started.")


def resolve_active_key(deployment_mode=None):
    """The single key-resolution chokepoint (used by ``gov/log.py``).

    Order: ``GOV_LOG_KEY`` (env provider) → ``GOV_KEYRING_FILE`` (file
    provider) → loud ``NoKeyConfiguredError`` in EVERY mode. The mode
    is validated (explicit kwarg > ``GOV_DEPLOYMENT_MODE`` env >
    ``"production"`` default; unknown modes fail fast) but no longer
    selects a key story: since wave-81, provisioning is explicit in
    every mode — the dev-key provider and every opt-in are deleted
    from ``gov/``. Returns ``(key_bytes, key_epoch)``.
    """
    resolve_deployment_mode(deployment_mode)  # validate; unknown fails fast
    if os.environ.get(_ENV_KEY):
        return EnvKeyProvider().resolve()
    keyring_file = os.environ.get(_ENV_KEYRING_FILE, "").strip()
    if keyring_file:
        return FileKeyProvider(keyring_file).resolve()
    raise NoKeyConfiguredError(_NO_KEY_MESSAGE)
