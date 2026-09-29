"""Signed, versioned, expiring corpus manifest for the skill-bundle load path.

The TUF steal (wave-193 lane C spike, ``teams/wave193-tuf/SPIKE.md``):
python-tuf's snapshot/targets structure in our own terms — patterns,
not the package (consistent with wave-179's deliberate "Avoid" list:
no four-role ceremony, no delegations, no new dependency).

The gap it closes: ``ArtifactPinset`` pins digests per artifact and
``load_skill_content`` verifies the fetched bytes against the pin, but
no signed corpus-wide binding exists between *pins* — pins are
independent per artifact. A corpus manifest is one signed document
binding ``{artifact_id -> digest}`` for the whole load corpus, with a
monotonic version and an expiry. It closes the TUF mix-and-match
attack at our seam: a pin rotated without the corpus (or a corpus
presented against bytes from another version) refuses at load time,
and corpus rollback (an older manifest re-presented) refuses because
the loader remembers the highest verified version.

Trust model:

* The manifest is signed by the deployment's corpus-signing keyset
  (``keyset_purpose`` pinned in the document, checked at verify), via
  ``ThresholdSigner.sign_all``. Members are a mix of two shapes:

  - ``KeysetSigner`` members (the active primary): the member binds
    ``(key_id, key_version)`` under a member domain, so the manifest
    composes with keyset rotation — a verify-only version still
    verifies old manifests, a revoked version's signature stops
    counting toward the threshold (fail closed).
  - plain ``Signer`` members (deployment keyholders, e.g. the two
    humans of a 2-of-2 ceremony): they sign the common body and are
    verified through the keyset's legacy key-id lookup, so their
    public halves must be pinned as keyset versions (any non-revoked
    status). A deployment reaches 2-of-2 today by rotating human keys
    in as versions (``rotate_keyset``) and minting with their plain
    signers — no new keyset API needed.

  Distinct key ids only: the same key signing twice is one
  attestation, not two.
* The manifest is *metadata about pins*, not a replacement for them:
  ``SkillLoader.load_skill`` still requires the pin and the byte
  check; the corpus check is an ADDITIONAL consistency binding (pin
  digest == manifest digest for the artifact id).
* Signatures are authoritative for the manifest; the manifest is never
  the sole trust anchor for bytes. An attacker who can mint a corpus
  manifest already holds the deployment's corpus-signing keys.

Fail-closed codes (``CorpusManifestError.code``):
``bad-format``, ``bad-version``, ``bad-expiry``, ``bad-artifacts``,
``wrong-purpose``, ``bad-threshold``, ``bad-signature``,
``threshold-unmet``, ``corpus-expired``, ``corpus-stale``,
``corpus-mismatch`` (pin digest != manifest digest),
``corpus-unbound`` (artifact id not in the manifest).

$0 spend, synthetic/local deterministic only. No network.
"""

import json
import re
from datetime import datetime, timezone

from . import ed25519 as _ed
from .keyset import Keyset, KeysetError
from .load_gate import is_digest_pin
from .signing import ThresholdSigner

__all__ = [
    "CORPUS_MANIFEST_FORMAT",
    "KEYSET_PURPOSE_CORPUS_MANIFEST",
    "CorpusManifestError",
    "CorpusManifest",
    "mint_corpus_manifest",
    "verify_corpus_manifest",
    "canonical_corpus_json",
]

#: Manifest document format tag (exact match at verify).
CORPUS_MANIFEST_FORMAT = "sasanam-skill-corpus-manifest/v1"

#: Keyset purpose bound into corpus manifests; a keyset minted for a
#: different purpose can never mint a corpus manifest.
KEYSET_PURPOSE_CORPUS_MANIFEST = "sasanam-corpus-manifest-signing/v1"

#: Fields allowed on a v1 manifest document (unknown fields refused).
_MANIFEST_FIELDS = frozenset({
    "format", "corpus_version", "issued_at", "expires_at",
    "keyset_purpose", "artifacts", "threshold", "signatures",
})

#: Envelope fields per threshold member signature. ``key_version``
#: is present for KeysetSigner members (version-bound member body) and
#: absent for plain-Signer members (common body, legacy key lookup).
_SIG_FIELDS = frozenset({"key_id", "key_version", "sig"})

_CORPUS_DOMAIN = b"sasanam-corpus-manifest/v1\x00"
# Member domain: MUST be byte-identical to the body
# gov.signing.ThresholdSigner.sign_all signs for a versioned member
# (``gov/signing.py::_member_sig_body``): domain + key_id + b"|kv" +
# version + b"\x00" + common. Replicated here so verification recomputes
# the exact signed bytes without reaching into signing's privates.
_MEMBER_DOMAIN = b"sasanam-threshold-member/v1\x00"

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class CorpusManifestError(Exception):
    """Fail-closed corpus-manifest violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        """Build the exception; the message is ``code`` + ``detail``."""
        super(CorpusManifestError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_iso(value, what):
    if not isinstance(value, str) or not _ISO_RE.match(value):
        raise CorpusManifestError(
            "bad-expiry", "%s is not an ISO-8601 UTC timestamp" % what)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise CorpusManifestError(
            "bad-expiry", "%s is not parseable: %r" % (what, value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def canonical_corpus_json(doc):
    """RFC 8785-style canonical JSON of the manifest minus ``signatures``.

    Raises CorpusManifestError("bad-format") on any non-object or
    non-serializable input — never a silent mismatch.
    """
    if not isinstance(doc, dict):
        raise CorpusManifestError(
            "bad-format", "manifest body is not a JSON object")
    body = {k: v for k, v in doc.items() if k != "signatures"}
    try:
        text = json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise CorpusManifestError(
            "bad-format", "manifest body not canonicalizable: %s" % exc)
    return text.encode("utf-8")


def _common_body(doc):
    """The bytes every member signs: domain + canonical JSON."""
    return _CORPUS_DOMAIN + canonical_corpus_json(doc)


def _member_body(common, key_id, key_version):
    """Member-specific body: binds (key_id, key_version) to ``common``
    under a distinct domain so a member signature cannot be
    transplanted onto another member or version."""
    return (_MEMBER_DOMAIN + key_id.encode("utf-8") + b"|kv"
            + str(key_version).encode("ascii") + b"\x00"
            + bytes(common))


class CorpusManifest:
    """A verified corpus manifest: ``{artifact_id -> digest}`` plus the
    version/expiry/threshold that verified.

    Instances only come from :func:`verify_corpus_manifest` — the
    constructor is not a trust boundary.
    """

    __slots__ = ("version", "expires_at", "threshold", "artifacts",
                 "signing_kids")

    def __init__(self, version, expires_at, threshold, artifacts,
                 signing_kids):
        """Store the verified manifest fields (plain value object)."""
        self.version = version
        self.expires_at = expires_at
        self.threshold = threshold
        self.artifacts = dict(artifacts)
        self.signing_kids = list(signing_kids)

    def digest_for(self, artifact_id):
        """The manifest-bound digest for ``artifact_id``, or None."""
        return self.artifacts.get(artifact_id)


def mint_corpus_manifest(keyset, signers, *, artifacts, corpus_version,
                         issued_at, expires_at, threshold):
    """Mint a signed corpus manifest (operator-side).

    ``keyset``: a :class:`Keyset` whose ``purpose`` is
    ``KEYSET_PURPOSE_CORPUS_MANIFEST``. ``signers``: non-empty list of
    :class:`Signer` — ``KeysetSigner`` members (minted via
    ``keyset_signer_for_version``: active primary only, so a
    verify-only or revoked version cannot mint) and/or plain
    ``Signer`` members (deployment keyholders whose public halves are
    pinned as keyset versions). ``threshold``: 1 <= threshold <=
    len(signers); the signatures are produced by
    ``ThresholdSigner.sign_all`` — ``KeysetSigner`` members bind
    ``(key_id, key_version)`` per member, plain members sign the
    common body.
    ``artifacts``: ``{artifact_id: "sha256:<64-hex>"}``.
    ``issued_at`` / ``expires_at``: ISO-8601 UTC strings;
    ``expires_at`` must be after ``issued_at``.
    Returns the manifest dict (JSON-serializable).
    """
    if not isinstance(keyset, Keyset):
        raise TypeError("keyset must be a Keyset")
    if keyset.purpose != KEYSET_PURPOSE_CORPUS_MANIFEST:
        raise CorpusManifestError(
            "wrong-purpose",
            "keyset purpose %r cannot mint corpus manifests"
            % (keyset.purpose,))
    signers = list(signers or [])
    if not signers:
        raise CorpusManifestError("bad-threshold", "no signers")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= len(signers)):
        raise CorpusManifestError(
            "bad-threshold",
            "threshold must satisfy 1 <= k <= %d" % len(signers))
    if (isinstance(corpus_version, bool)
            or not isinstance(corpus_version, int)
            or corpus_version < 1):
        raise CorpusManifestError(
            "bad-version", "corpus_version must be an integer >= 1")
    issued = _parse_iso(issued_at, "issued_at")
    expires = _parse_iso(expires_at, "expires_at")
    if expires <= issued:
        raise CorpusManifestError(
            "bad-expiry", "expires_at must be after issued_at")
    if not isinstance(artifacts, dict):
        raise CorpusManifestError(
            "bad-artifacts", "artifacts must be a mapping")
    for aid, digest in artifacts.items():
        if not isinstance(aid, str) or not aid:
            raise CorpusManifestError(
                "bad-artifacts", "artifact id must be a non-empty string")
        if not is_digest_pin(digest):
            raise CorpusManifestError(
                "bad-artifacts",
                "artifact %r digest is not a sha256 pin" % (aid,))
    doc = {
        "format": CORPUS_MANIFEST_FORMAT,
        "corpus_version": corpus_version,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "keyset_purpose": KEYSET_PURPOSE_CORPUS_MANIFEST,
        "artifacts": {str(a): str(d) for a, d in artifacts.items()},
        "threshold": threshold,
        "signatures": [],
    }
    common = _common_body(doc)
    # ThresholdSigner binds (key_id, key_version) per member; entries
    # are {"key_id", "sig", "key_version"}.
    doc["signatures"] = ThresholdSigner(signers, threshold).sign_all(
        common)
    return doc


def _verify_member(keyset, common, entry):
    """Verify one threshold member entry. Returns the key_id on
    success, None when the member does not verify (unknown, revoked,
    or bad signature — never raises).

    Two member shapes: ``KeysetSigner`` entries carry ``key_version``
    and are verified over the version-bound member body;
    plain-``Signer`` entries carry no version and are verified over
    the common body through the keyset's legacy key-id lookup (their
    public halves must be pinned as keyset versions)."""
    if not isinstance(entry, dict):
        return None
    if set(entry) - _SIG_FIELDS:
        return None
    kid = entry.get("key_id")
    if not isinstance(kid, str) or not kid:
        return None
    try:
        sig = bytes.fromhex(entry.get("sig"))
    except (TypeError, ValueError):
        return None
    if "key_version" in entry:
        kv = entry.get("key_version")
        if isinstance(kv, bool) or not isinstance(kv, int) or kv < 1:
            return None
        keyver, _reason = keyset.find_verifying_key(
            {"sig_key_id": kid, "sig_key_version": kv})
        if keyver is None:
            # Unknown, mismatched, or revoked version: the member does
            # not count. Revocation composes here — a revoked member's
            # signature simply stops counting toward the threshold.
            return None
        body = _member_body(common, kid, kv)
    else:
        # Plain-Signer member: the common body, verified through the
        # keyset's legacy (no-version) lookup. Revoked keys refuse
        # here as well.
        keyver, _reason = keyset.find_verifying_key({"sig_key_id": kid})
        if keyver is None:
            return None
        body = common
    try:
        ok = _ed.verify(keyver.public_key, body, sig)
    except Exception:
        ok = False
    return kid if ok else None


def verify_corpus_manifest(doc, keyset, *, now=None):
    """Verify a corpus manifest against the corpus-signing keyset.

    Returns a :class:`CorpusManifest`. Fail-closed: raises
    :class:`CorpusManifestError` with a distinct code on every failure
    mode. Checks, in order: shape/format, version sanity, purpose
    binding, expiry, threshold sanity, then every member signature
    (distinct key ids only) against the keyset — at least
    ``threshold`` valid members required. A verify-only keyset
    version still verifies (rotation-stable); a revoked version's
    signature does not count.
    """
    if not isinstance(keyset, Keyset):
        raise TypeError("keyset must be a Keyset")
    if not isinstance(doc, dict):
        raise CorpusManifestError(
            "bad-format", "manifest is not a mapping")
    if set(doc) - _MANIFEST_FIELDS:
        raise CorpusManifestError(
            "bad-format", "manifest carries unknown fields: %s"
            % sorted(set(doc) - _MANIFEST_FIELDS))
    if doc.get("format") != CORPUS_MANIFEST_FORMAT:
        raise CorpusManifestError(
            "bad-format", "format must be %r"
            % (CORPUS_MANIFEST_FORMAT,))
    version = doc.get("corpus_version")
    if (isinstance(version, bool) or not isinstance(version, int)
            or version < 1):
        raise CorpusManifestError(
            "bad-version", "corpus_version must be an integer >= 1")
    if doc.get("keyset_purpose") != KEYSET_PURPOSE_CORPUS_MANIFEST:
        raise CorpusManifestError(
            "wrong-purpose",
            "manifest keyset_purpose %r is not the corpus purpose"
            % (doc.get("keyset_purpose"),))
    if keyset.purpose != KEYSET_PURPOSE_CORPUS_MANIFEST:
        raise CorpusManifestError(
            "wrong-purpose",
            "verifying keyset purpose %r is not the corpus purpose"
            % (keyset.purpose,))
    expires = _parse_iso(doc.get("expires_at"), "expires_at")
    _parse_iso(doc.get("issued_at"), "issued_at")
    now = now or _utcnow()
    if now > expires:
        raise CorpusManifestError(
            "corpus-expired",
            "manifest expired at %s" % (doc.get("expires_at"),))
    artifacts = doc.get("artifacts")
    if not isinstance(artifacts, dict):
        raise CorpusManifestError(
            "bad-artifacts", "artifacts must be a mapping")
    for aid, digest in artifacts.items():
        if not isinstance(aid, str) or not aid:
            raise CorpusManifestError(
                "bad-artifacts", "artifact id must be a non-empty string")
        if not is_digest_pin(digest):
            raise CorpusManifestError(
                "bad-artifacts",
                "artifact %r digest is not a sha256 pin" % (aid,))
    threshold = doc.get("threshold")
    sigs = doc.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise CorpusManifestError(
            "bad-threshold", "signatures must be a non-empty list")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= len(sigs)):
        raise CorpusManifestError(
            "bad-threshold",
            "threshold must satisfy 1 <= k <= %d" % len(sigs))
    common = _common_body(doc)
    valid_kids = []
    seen = set()
    for entry in sigs:
        kid = _verify_member(keyset, common, entry)
        if kid is not None and kid not in seen:
            seen.add(kid)
            valid_kids.append(kid)
    if not valid_kids:
        raise CorpusManifestError(
            "bad-signature", "no member signature verifies")
    if len(valid_kids) < threshold:
        raise CorpusManifestError(
            "threshold-unmet",
            "%d of %d required member signatures verify"
            % (len(valid_kids), threshold))
    return CorpusManifest(version, expires, threshold, artifacts,
                          valid_kids)
