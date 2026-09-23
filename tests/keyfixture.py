"""Wave-81: explicit test-key provisioning helper.

``gov/`` no longer contains any dev key or dev-key opt-in (wave-81
deleted the dev key, every opt-in, and every fallback). Tests that need
a working HMAC chain provision an EXPLICIT key through the same env
backend production uses (``GOV_LOG_KEY`` / ``GOV_LOG_KEY_EPOCH`` ->
``EnvKeyProvider``). This helper lives in ``tests/`` -- never in
``gov/`` -- so production code cannot reach it.

The keys are fresh ``secrets.token_bytes(32)`` per call (hex-encoded,
the canonical 64-char form ``KeyRing.generate`` uses), so every test
run gets unique key material: nothing shared, nothing public, and
nothing is a fallback.
"""

import os
import secrets

_KEY_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def provision_test_key(epoch="test", key_bytes=None):
    """Generate a fresh random key and provision it via the EXPLICIT
    production path (``GOV_LOG_KEY``/``GOV_LOG_KEY_EPOCH`` env backend).

    Hermetic: any ambient key env vars are replaced, so the suite never
    depends on operator key material. Returns ``{"key", "epoch",
    "key_hex"}`` where ``key`` is the raw bytes the resolver returns.
    """
    raw = key_bytes if key_bytes is not None else secrets.token_bytes(32)
    key_hex = raw.hex()
    os.environ["GOV_LOG_KEY"] = key_hex
    os.environ["GOV_LOG_KEY_EPOCH"] = epoch
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    return {"key": key_hex.encode("ascii"), "epoch": epoch,
            "key_hex": key_hex}


def scrub_key_env():
    """Remove all key env vars (for no-key refusal tests).

    Returns a ``restore()`` closure that puts the previous values back.
    """
    saved = {name: os.environ.get(name) for name in _KEY_VARS}
    for name in _KEY_VARS:
        os.environ.pop(name, None)

    def restore():
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    return restore
