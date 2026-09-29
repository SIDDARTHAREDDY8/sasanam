"""Signed capability manifests bound to artifact digests.

Design input: smithmark (sns45/smithmark @ ``23119fe``, Apache-2.0
VERIFIED — license text read from the repo root LICENSE file
2026-09-28; see ``teams/prospecting-r6/PROSPECTUS_R6.md`` §stream-2).
Rebuilt here on this repo's existing Ed25519 seams
(``gov/agent_cards.py``, ``gov/ed25519.py``): no vendored code, no
Fulcio/Rekor, no external transparency service, no new crypto
dependencies, $0.

The gap it closes: ``skill_watch`` pins digests and verifies bytes at
use time, but nothing binds a SIGNED DECLARED-CAPABILITY manifest to
the digest. A skill whose code is byte-identical to its pin can still
exceed its declared network/filesystem scope with no signed statement
to check against. A manifest is the deployment's signed statement:
*these exact bytes* (sha256 artifact digest) are attested to need no
more than *these declared capabilities*.

Two checks, kept separate the way smithmark separates them:

  (a) provenance — the manifest carries >= 1 valid Ed25519 signature
      from the deployment-pinned ``ManifestStore``. ``jku``-style
      remote key fetches are NEVER performed: a protected header
      naming ``jku`` is refused outright (stricter than Agent Cards,
      which allowlist it — there is no key-discovery use case for
      capability manifests, so there is no SSRF surface at all).
  (b) capability surface — a conservative static lint over the verified
      bytes; the detected capability signals must be a subset of the
      declared capabilities. Fail-closed: any mismatch refuses the
      load, never warn-and-continue.

Signature envelope mirrors ``agent_cards.verify_card``: RFC 8785-style
canonical JSON of the manifest minus ``signatures`` (sorted keys, no
whitespace, ``allow_nan=False``), protected header ``{"alg", "kid"}``,
signing input ``b64u(protected) + b"." + b64u(canonical)``.

Capability categories: ``tools``, ``egress``, ``filesystem``, ``exec``,
``env``, ``secrets``. Declared values are lists of grant labels; the
v1 lint is category-granular (any detected signal in a category
requires that category to be declared non-empty) plus name-level for
``env`` (``os.environ["X"]``) and ``tools`` (``tool_*`` defs, framework
constructors). Grant-level enforcement (WHICH hosts, WHICH paths) is a
documented future extension — the lint proves the code stays inside
the *declared categories*, the signature proves the *declaration* is
the one the deployment attested.

Honest residuals (not hidden):
  - The lint is static and best-effort: obfuscated capability use
    (``getattr(os, "sy"+"stem")``, base64-encoded payloads, dynamic
    imports) evades it by construction. The digest binding + signature
    are the hard guarantees; the lint catches the declared-shape
    drift, not a determined obfuscator.
  - Opaque/binary artifacts yield no lint signals (vacuous pass);
    they are still digest-bound and signature-checked.
  - A skill with NO manifest keeps today's behavior; the use emits an
    advisory ``capability_manifest_absent`` event (audit-only adoption
    path). Manifests live in the deployment-controlled
    ``ManifestStore`` — the same trust level as skill pins — so an
    attacker who can delete a manifest already owns the deployment.
"""

import base64
import hashlib
import json
import re

from . import ed25519 as _ed

MANIFEST_VERSION = 1

#: Capability categories, in canonical order.
CATEGORIES = ("tools", "egress", "filesystem", "exec", "env", "secrets")

#: Categories where the lint additionally extracts granted names and
#: checks them against the declared list (name-level, not just
#: category-level).
_NAME_CHECKED = ("env", "tools")


class ManifestVerificationError(Exception):
    """Fail-closed manifest violation. ``code`` is a distinct,
    machine-readable failure mode (mirrors CardVerificationError)."""

    def __init__(self, code, detail=""):
        super(ManifestVerificationError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Canonicalization + base64url (mirrors gov/agent_cards.py)
# ---------------------------------------------------------------------------

def _normalize_numbers(value):
    if isinstance(value, dict):
        return {k: _normalize_numbers(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_numbers(v) for v in value]
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return value
    return value


def canonical_manifest_json(manifest):
    """RFC 8785-style canonical JSON of the manifest minus ``signatures``.

    Raises ManifestVerificationError("canonicalization-failure") on any
    non-object or non-serializable input — never a silent mismatch.
    """
    if not isinstance(manifest, dict):
        raise ManifestVerificationError(
            "canonicalization-failure",
            "manifest body is not a JSON object")
    body = {k: v for k, v in manifest.items()
            if k != "signatures" and v is not None}
    body = _normalize_numbers(body)
    try:
        text = json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ManifestVerificationError(
            "canonicalization-failure",
            "manifest body not canonicalizable: %s" % exc)
    return text.encode("utf-8")


def _b64u_encode(data):
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def _b64u_decode(text):
    if not isinstance(text, str) or not text:
        raise ManifestVerificationError(
            "malformed-signature-entry",
            "protected/signature must be non-empty base64url strings")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise ManifestVerificationError(
            "malformed-signature-entry",
            "base64url decode failed: %s" % exc)


# ---------------------------------------------------------------------------
# Static capability lint (best-effort; see module docstring residuals)
# ---------------------------------------------------------------------------

# Each entry: (compiled regex, human-readable signal label).
_CATEGORY_PATTERNS = {
    "egress": [
        (re.compile(r"\bimport\s+socket\b"), "import socket"),
        (re.compile(r"\bfrom\s+socket\s+import\b"), "from socket import"),
        (re.compile(r"\burllib\.request\b"), "urllib.request"),
        (re.compile(r"\burllib3\b"), "urllib3"),
        (re.compile(r"\bimport\s+requests\b"), "import requests"),
        (re.compile(r"\bfrom\s+requests\s+import\b"), "from requests import"),
        (re.compile(r"\bhttp\.client\b"), "http.client"),
        (re.compile(r"\bhttpx\b"), "httpx"),
        (re.compile(r"\baiohttp\b"), "aiohttp"),
        (re.compile(r"\bwebsocket\b"), "websocket"),
        (re.compile(r"\bcreate_connection\s*\("), "create_connection("),
        (re.compile(r"\bgetaddrinfo\s*\("), "getaddrinfo("),
        (re.compile(r"\bsmtplib\b"), "smtplib"),
    ],
    "filesystem": [
        (re.compile(r"(?<![\w.])open\s*\("), "open("),
        (re.compile(r"\bos\.remove\b"), "os.remove"),
        (re.compile(r"\bos\.unlink\b"), "os.unlink"),
        (re.compile(r"\bos\.mkdir\b"), "os.mkdir"),
        (re.compile(r"\bos\.makedirs\b"), "os.makedirs"),
        (re.compile(r"\bos\.rmdir\b"), "os.rmdir"),
        (re.compile(r"\bos\.rename\b"), "os.rename"),
        (re.compile(r"\bos\.replace\b"), "os.replace"),
        (re.compile(r"\bos\.write\b"), "os.write"),
        (re.compile(r"\bshutil\b"), "shutil"),
        (re.compile(r"\bpathlib\b"), "pathlib"),
        (re.compile(r"\bwrite_text\s*\("), "write_text("),
        (re.compile(r"\bwrite_bytes\s*\("), "write_bytes("),
    ],
    "exec": [
        (re.compile(r"\bsubprocess\b"), "subprocess"),
        (re.compile(r"\bos\.system\b"), "os.system"),
        (re.compile(r"\bos\.popen\b"), "os.popen"),
        (re.compile(r"\bos\.exec[lv]e?\b"), "os.exec*"),
        (re.compile(r"\bos\.spawn\w*\b"), "os.spawn*"),
        (re.compile(r"(?<![\w.])eval\s*\("), "eval("),
        (re.compile(r"(?<![\w.])exec\s*\("), "exec("),
        (re.compile(r"\b__import__\s*\("), "__import__("),
    ],
    "env": [
        (re.compile(r"\bos\.environ\b"), "os.environ"),
        (re.compile(r"(?<![\w.])getenv\s*\("), "getenv("),
    ],
    "secrets": [
        (re.compile(r"\bgetpass\b"), "getpass"),
        (re.compile(r"\bkeyring\b"), "keyring"),
    ],
    "tools": [
        (re.compile(r"@(?:[A-Za-z_]\w*\.)?tool\b"), "@tool decorator"),
        (re.compile(r"(?:FunctionTool|Tool|MCPTool)\s*\("),
         "Tool( constructor"),
    ],
}

_ENV_NAME_RES = [
    re.compile(r"os\.environ\[\s*[\"']([^\"'\\\s]+)[\"']\s*\]"),
    re.compile(r"os\.environ\.get\(\s*[\"']([^\"'\\\s]+)[\"']"),
    re.compile(r"(?<![\w.])getenv\(\s*[\"']([^\"'\\\s]+)[\"']"),
]

_TOOL_NAME_RES = [
    re.compile(r"\bdef\s+(tool_\w+)\s*\("),
    re.compile(
        r"(?:FunctionTool|Tool|MCPTool)\(\s*[\"']([^\"']+)[\"']"),
]


def detect_capabilities(content):
    """Statically detect capability signals in artifact bytes.

    Returns ``{category: {"signals": [...], "names": [...]}}`` for every
    category in CATEGORIES. ``signals`` are human-readable matched
    labels; ``names`` are extracted grant names (env var names, tool
    names) for the name-checked categories. Best-effort by design —
    see the module docstring. Never raises on hostile input.
    """
    if isinstance(content, (bytearray, memoryview)):
        content = bytes(content)
    if not isinstance(content, bytes):
        return {c: {"signals": [], "names": []} for c in CATEGORIES}
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    detected = {}
    for cat in CATEGORIES:
        signals = []
        for rx, label in _CATEGORY_PATTERNS.get(cat, []):
            try:
                if rx.search(text):
                    signals.append(label)
            except Exception:
                continue
        names = []
        if cat == "env":
            for rx in _ENV_NAME_RES:
                try:
                    names.extend(rx.findall(text))
                except Exception:
                    continue
        elif cat == "tools":
            for rx in _TOOL_NAME_RES:
                try:
                    names.extend(rx.findall(text))
                except Exception:
                    continue
        # De-duplicate, preserve order, bound the output (event text).
        seen = set()
        signals = [s for s in signals
                   if not (s in seen or seen.add(s))][:8]
        seen_n = set()
        names = [n for n in names
                 if not (n in seen_n or seen_n.add(n))][:16]
        detected[cat] = {"signals": signals, "names": names}
    return detected


def check_capabilities(declared, detected):
    """Check detected signals against the declared capabilities.

    ``declared``: the manifest's ``capabilities`` mapping (category ->
    list of grant labels). ``detected``: ``detect_capabilities`` output.
    Returns ``(True, "clean")`` or ``(False, <drift detail>)``. The
    detail names the category and the offending signals/names — never
    artifact content. Fail-closed: a malformed declaration is itself a
    drift (refuse, don't guess).
    """
    if declared is None:
        declared = {}
    if not isinstance(declared, dict):
        return False, "capability-drift:malformed-declaration"
    for cat in CATEGORIES:
        det = (detected or {}).get(cat, {})
        signals = det.get("signals", [])
        names = det.get("names", [])
        granted = declared.get(cat)
        if granted is None:
            granted = []
        if not isinstance(granted, list):
            return (False,
                    "capability-drift:%s:malformed-declaration" % cat)
        if (signals or names) and not granted:
            return (False,
                    "capability-drift:%s:undeclared-category "
                    "(signals: %s)"
                    % (cat, ", ".join(signals[:3]) or "n/a"))
        if cat in _NAME_CHECKED and names:
            undeclared = [n for n in names if n not in granted]
            if undeclared:
                return (False,
                        "capability-drift:%s:undeclared-names %s"
                        % (cat, ", ".join(undeclared[:5])))
    return True, "clean"


# ---------------------------------------------------------------------------
# Manifest store (deployment-pinned; offline-root model)
# ---------------------------------------------------------------------------

class ManifestStore(object):
    """The deployment's pinned capability-manifest trust material.

    ``keys``: ``{kid: 32-byte Ed25519 public key}`` — the only keys
    whose signatures verify. ``manifests``: ``{skill_id: manifest}`` —
    the attested declarations. Both are deployment-controlled (the
    same trust level as skill pins): no network fetches, no key
    discovery, no ``jku``. A manifest for an unknown skill id, or a
    signature from an unknown kid, fails closed.
    """

    def __init__(self, keys=None, manifests=None):
        self._keys = {}
        for kid, pub in (keys or {}).items():
            if not isinstance(kid, str) or not kid:
                raise ValueError("manifest store kid must be a "
                                 "non-empty string")
            if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
                raise ValueError("manifest store key %r must be a "
                                 "32-byte Ed25519 public key" % (kid,))
            self._keys[kid] = bytes(pub)
        self._manifests = dict(manifests or {})

    def pubkey_for(self, kid):
        """32-byte public key for ``kid``, or None."""
        return self._keys.get(kid)

    def manifest_for(self, skill_id):
        """The attested manifest for ``skill_id``, or None."""
        return self._manifests.get(skill_id)

    def kids(self):
        return sorted(self._keys)


# ---------------------------------------------------------------------------
# Signing (test helper) + verification
# ---------------------------------------------------------------------------

def sign_manifest(manifest, kid, seed):
    """Test helper: produce a ``signatures[]`` entry for a manifest.

    ``seed`` is the 32-byte Ed25519 seed (test-only; never production
    key material). Production signing goes through the deployment's key
    custody (the key-provider interface); this helper mirrors the
    verifier's canonicalization exactly so the battery tests the
    pipeline, not a signing/verifying skew. Mirrors
    ``agent_cards.sign_card``.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    if not isinstance(kid, str) or not kid:
        raise ValueError("kid must be a non-empty string")
    header = {"alg": "EdDSA", "typ": "JOSE", "kid": kid}
    protected_b64 = _b64u_encode(json.dumps(
        header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    canonical = canonical_manifest_json(manifest)
    signing_input = (protected_b64.encode("ascii") + b"." +
                     _b64u_encode(canonical).encode("ascii"))
    sig = _ed.sign(bytes(seed), signing_input)
    return {"protected": protected_b64, "signature": _b64u_encode(sig)}


def verify_manifest(manifest, store, *, expected_skill_id=None,
                    threshold=1):
    """Verify a signed capability manifest against the pinned store.

    Returns ``{"skill_id": <manifest skill_id>, "kids": [verified kids],
    "artifact_digest": <bound digest>}``. Fail-closed: raises
    ManifestVerificationError with a distinct code on every failure
    mode. Requires at least ``threshold`` valid signatures from
    DISTINCT pinned kids (wave-194: the production pin tier needs two
    distinct-human signatures — pass ``threshold=2``; the default
    ``threshold=1`` preserves the legacy "at least one" contract).
    A protected header naming ``jku`` is refused outright
    (``jku-not-allowed``) — key discovery is never performed. When
    ``expected_skill_id`` is given, the manifest's ``skill_id`` must
    equal it (``skill-id-mismatch``) — a manifest attested for one
    artifact never verifies for another. ``threshold-unmet`` names
    the distinct-kid shortfall.
    """
    if not isinstance(store, ManifestStore):
        raise TypeError("store must be a ManifestStore")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or threshold < 1):
        raise ManifestVerificationError(
            "bad-threshold", "threshold must be an integer >= 1")
    canonical = canonical_manifest_json(manifest)  # type-check first
    skill_id = manifest.get("skill_id")
    if not isinstance(skill_id, str) or not skill_id:
        raise ManifestVerificationError(
            "missing-skill-id", "manifest carries no skill_id")
    if (expected_skill_id is not None
            and skill_id != expected_skill_id):
        raise ManifestVerificationError(
            "skill-id-mismatch",
            "manifest attests %r, presented for %r"
            % (skill_id, expected_skill_id))

    sigs = manifest.get("signatures")
    if not sigs or not isinstance(sigs, list):
        raise ManifestVerificationError(
            "missing-signatures", "manifest carries no signatures[]")

    valid_kids = []
    for entry in sigs:
        if not isinstance(entry, dict):
            raise ManifestVerificationError(
                "malformed-signature-entry",
                "signature entry is not an object")
        protected_b64 = entry.get("protected")
        signature_b64 = entry.get("signature")
        if not protected_b64 or not signature_b64:
            raise ManifestVerificationError(
                "malformed-signature-entry",
                "protected/signature must be non-empty")
        try:
            header = json.loads(
                _b64u_decode(protected_b64).decode("utf-8"))
        except ManifestVerificationError:
            raise
        except Exception as exc:
            raise ManifestVerificationError(
                "malformed-signature-entry",
                "protected header is not JSON: %s" % exc)
        if not isinstance(header, dict):
            raise ManifestVerificationError(
                "malformed-signature-entry",
                "protected header is not an object")
        if header.get("alg") != "EdDSA":
            raise ManifestVerificationError(
                "unsupported-alg",
                "only EdDSA is supported, got %r"
                % (header.get("alg"),))
        if "jku" in header:
            # No key discovery, ever: the store is pinned and offline.
            raise ManifestVerificationError(
                "jku-not-allowed",
                "manifest key discovery is not performed")
        kid = header.get("kid")
        pubkey = store.pubkey_for(kid) if kid else None
        if pubkey is None:
            raise ManifestVerificationError(
                "unknown-kid", "kid %r is not pinned" % (kid,))
        try:
            sig = _b64u_decode(signature_b64)
        except ManifestVerificationError:
            raise ManifestVerificationError(
                "bad-signature", "kid %r: undecodable signature"
                % (kid,))
        signing_input = (protected_b64.encode("ascii") + b"." +
                         _b64u_encode(canonical).encode("ascii"))
        try:
            ok = _ed.verify(pubkey, signing_input, sig)
        except Exception:
            ok = False
        # Distinct kids only: the same key signing twice is one
        # attestation, not two — threshold counts attestations, not
        # signature entries.
        if ok and kid not in valid_kids:
            valid_kids.append(kid)
    if len(valid_kids) < threshold:
        if not valid_kids:
            raise ManifestVerificationError(
                "bad-signature", "no valid signature from a pinned key")
        raise ManifestVerificationError(
            "threshold-unmet",
            "%d of %d required distinct signatures verify"
            % (len(valid_kids), threshold))
    return {"skill_id": skill_id, "kids": valid_kids,
            "artifact_digest": manifest.get("artifact_digest")}


def verify_skill_manifest(skill_id, content, store, *, threshold=1):
    """Full load-time check for one skill's artifact bytes.

    Returns ``(ok, detail)`` — never raises for well-formed inputs:

      * store is None -> ``(True, "no-store")`` (today's behavior).
      * no manifest for skill_id -> ``(True, "manifest-absent")``
        (advisory; the caller emits ``capability_manifest_absent``).
      * bad signature / unknown kid / jku / ... ->
        ``(False, "manifest-<code>")``.
      * fewer than ``threshold`` distinct valid signatures ->
        ``(False, "manifest-threshold-unmet")`` (wave-194: the
        production pin tier needs two distinct-human signatures).
      * manifest for a different skill -> ``(False,
        "manifest-skill-id-mismatch")``.
      * ``artifact_digest`` != sha256(content) -> ``(False,
        "manifest-digest-mismatch")`` (stale attestation / replay).
      * detected capability surface exceeds the declaration ->
        ``(False, "capability-drift:...")``.
      * otherwise -> ``(True, "clean")``.

    ``content`` is the EXACT bytes the watcher hashed (the
    fetch-verified handoff) — there is no second observation for the
    source to equivocate on between check and lint.
    """
    if store is None:
        return True, "no-store"
    if not isinstance(store, ManifestStore):
        raise TypeError("store must be a ManifestStore or None")
    manifest = store.manifest_for(skill_id)
    if manifest is None:
        return True, "manifest-absent"
    try:
        verify_manifest(manifest, store, expected_skill_id=skill_id,
                        threshold=threshold)
    except ManifestVerificationError as exc:
        return False, "manifest-%s" % exc.code
    observed = "sha256:" + hashlib.sha256(bytes(content)).hexdigest()
    if manifest.get("artifact_digest") != observed:
        return False, "manifest-digest-mismatch"
    detected = detect_capabilities(content)
    ok, detail = check_capabilities(manifest.get("capabilities"), detected)
    if not ok:
        return False, detail
    return True, "clean"


def make_manifest(skill_id, content, *, capabilities, kid, seed,
                  issuer="", issued_at=0):
    """Build and sign a manifest for artifact ``content`` (test/helper).

    Binds ``artifact_digest`` = sha256(content) and the declared
    ``capabilities`` under one Ed25519 signature. Production issuers
    sign through the deployment's key custody; the signature math is
    identical.
    """
    digest = "sha256:" + hashlib.sha256(bytes(content)).hexdigest()
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "skill_id": skill_id,
        "artifact_digest": digest,
        "capabilities": {c: list(capabilities.get(c, []))
                         for c in CATEGORIES},
        "issuer": issuer,
        "issued_at": issued_at,
    }
    manifest["signatures"] = [sign_manifest(manifest, kid, seed)]
    return manifest
