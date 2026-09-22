"""Governed agent-runtime package installation (P7 / F75 runtime angle).

F75 (MEDIUM, CLOSED wave-23) pinned the *product's own* dependency graph:
``requirements.lock`` + ``gov/supplychain.py`` audit the deployment venv.
This module governs the *agent-runtime* fetch angle the incident probe
``redteam.incident.p7.unpinned_dependency_fetch_allowed`` exercises: an
agent asking the runtime to fetch a package (the P7 supply-chain /
dependency-confusion pattern, Forced Descent-class).

The control has two halves, mirroring the F75 fix direction
(lockfile + allowlist + artifact verification), applied to the agent's
tool surface:

1. ``install_package`` — the ONLY sanctioned install path. It installs
   only an exact name+version pin from ``AGENT_PACKAGE_PINS`` (the
   agent-runtime analog of the lockfile) and verifies the fetched
   artifact's sha256 against the pin before the install is reported as
   successful. Anything else (unlisted name, version drift, ``latest``,
   missing version, hash mismatch) is refused.
2. A policy rule (``deny-ungoverned-package-fetch`` in the default
   policy) that denies raw ``api_call``/``http_post`` fetches to
   ``REGISTRY_HOSTS`` — without this, the governed tool would be
   advisory only: the agent could still fetch the typosquat directly.

The fetch itself is SIMULATED: ``fetch_artifact_bytes`` returns
canonical deterministic bytes derived from (name, version) — no network,
no real pip, no real filesystem mutation. The sha256 comparison is real
code on real bytes, so the integrity mechanism is genuinely exercised
(tests override ``fetch_artifact_bytes`` to simulate a tampered
artifact and assert refusal). A real deployment must additionally ensure
the agent runtime cannot reach a real package manager outside this
surface — that is deployment architecture, documented as a residual in
the F75 finding entry and in the P7 incident-coverage section.

Determinism: pure functions, fixed pins, no I/O, no randomness.
"""

from hashlib import sha256

# Hosts treated as package registries. api_call/http_post to one of
# these is a "package fetch" for policy purposes and is denied unless
# it goes through install_package. registry.synthetic.local is the
# demo's synthetic registry (allowlisted for egress, like a real
# deployment's internal mirror); pypi.org / files.pythonhosted.org /
# registry.npmjs.org are the real-world registries this postures
# against.
REGISTRY_HOSTS = frozenset({
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "registry.synthetic.local",
})

# Agent-runtime package pins: name -> exact version + sha256 of the
# canonical artifact bytes (see _canonical_artifact_bytes). The demo's
# agent-runtime lockfile: only these (name, version) pairs may install.
# Digests were computed over the canonical bytes and are literals here
# so a drifted artifact fails closed.
AGENT_PACKAGE_PINS = {
    "requests": {
        "version": "2.32.3",
        "sha256": "803fb402dc2d4dbe231fdcf64a8539840cf2165a50c3ed5883a222cdcabaed53",
    },
    "pyyaml": {
        "version": "6.0.2",
        "sha256": "a692ae0f941d86ccdfda59f93d4b9b3c2942304b6c9cebb3113a91dcc145f366",
    },
    "pydantic": {
        "version": "2.10.4",
        "sha256": "0c86f10e51efc483a89c4f4dc1da5b8b131af50c538acfa50d5971cb3d5595e9",
    },
}


def _canonical_artifact_bytes(name, version):
    """Deterministic stand-in for "the bytes fetched from the registry".

    The simulation's fetch surface: canonical bytes derived from the
    pinned (name, version). The integrity check below hashes exactly
    these bytes, so the verify path is real code over real bytes.
    """
    return (b"gov-install-artifact:" + str(name).encode("utf-8")
            + b":" + str(version).encode("utf-8"))


def fetch_artifact_bytes(name, version):
    """Return the artifact bytes a registry fetch would yield.

    Module-level indirection (not a closure) so tests can monkeypatch
    it to simulate a tampered artifact without touching the pins.
    """
    return _canonical_artifact_bytes(name, version)


def is_registry_host(host):
    """True when host is (or is a subdomain of) a known registry host."""
    if not host:
        return False
    h = str(host).lower().rstrip(".")
    return any(h == r or h.endswith("." + r) for r in REGISTRY_HOSTS)


def is_package_fetch(tool, endpoint_or_url):
    """True when this is a raw fetch-shaped call to a package registry.

    Used by the executor to populate the ``package_fetch`` policy match
    key for api_call/http_post. The governed install_package tool is
    never a "package fetch" in this sense — it IS the sanctioned path.
    """
    if tool not in ("api_call", "http_post"):
        return False
    if not endpoint_or_url:
        return False
    try:
        from urllib.parse import urlparse
        host = (urlparse(str(endpoint_or_url)).hostname or "").lower()
    except Exception:
        return False
    return is_registry_host(host)


def check_install(name, version):
    """Govern the install: allowlist + exact pin + integrity verification.

    Returns (True, digest) when (name, version) is pinned AND the
    fetched artifact's sha256 matches the pin; otherwise (False,
    reason) where reason is one of "not-allowlisted",
    "version-mismatch" (covers "latest", missing, or drifted versions),
    or "integrity-mismatch". Pure function; deterministic.
    """
    pin = AGENT_PACKAGE_PINS.get(name)
    if pin is None:
        return False, "not-allowlisted"
    if version != pin["version"]:
        # Exact pin only: "latest", None, and drifted versions all
        # refuse here. There is no "resolve latest" in the governed
        # path — resolution is the dependency-confusion vector.
        return False, "version-mismatch"
    digest = sha256(fetch_artifact_bytes(name, version)).hexdigest()
    if digest != pin["sha256"]:
        return False, "integrity-mismatch"
    return True, digest


def install_context(name, version):
    """Policy match-key inputs for an install_package call.

    Returns (install_allowlisted, install_integrity_verified, digest):
    allowlisted = name is pinned and version matches the pin exactly;
    integrity_verified = allowlisted AND the fetched artifact hashes
    to the pin. The split lets policy deny the two failure classes
    with distinct policy_ids (audit precision).
    """
    ok, detail = check_install(name, version)
    if not ok and detail == "not-allowlisted":
        return False, False, None
    if not ok and detail == "version-mismatch":
        return False, False, None
    if not ok:  # integrity-mismatch: the name/version IS allowlisted
        return True, False, None
    return True, True, detail
