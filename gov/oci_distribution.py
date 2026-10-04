"""OCI distribution for Sasanam evidence bundles (wave-321 lane 2).

Build-order step 2 of the wave-320 evidence-distribution prospectus
(``research/prospecting/w320_evidence_distribution.md``): evidence bundles
ship as subject-bearing OCI 1.1 manifests with a Sasanam ``artifactType``;
manifests are deterministic ("same evidence -> same digest"); the client
discovers referrers via ``GET /v2/<repo>/referrers/<digest>`` with the
spec-mandated 404 -> tag-schema fallback; and the registry is treated as
UNTRUSTED storage -- digest-addressed pulls, per-blob digest checks,
subject-digest matching, all client-side, always.

Trust boundary, stated honestly:

- This module verifies TRANSPORT integrity: every byte pulled by digest is
  re-hashed client-side; a manifest whose blobs do not match, or whose
  subject is not the queried digest, is refused with a coded refusal.
- PAYLOAD authenticity is NOT this module's job. The evidence bundle
  carries its own signature (DSSE / Sigstore-bundle shape via
  ``gov.evidence_dsse`` / ``gov.evidence_sigstore``); verify it with those
  modules. ``pull_and_verify`` accepts an optional ``payload_verifier``
  hook so callers can chain the two, but the hook is the caller's -- this
  module never invents key authority.
- The cosign legacy tag scheme (``sha256-<hex>.sig``) is SKIP-as-design:
  it exists here ONLY as the fallback lookup when a registry 404s the
  referrers API, never as the primary discovery path.
- Authentication: registries that need it take a bearer token via
  ``auth_token=`` (Authorization: Bearer). Token ACQUISITION (OAuth2 /
  token service) is out of scope; Harbor deployment policy is a later wave.

Stdlib only (urllib). No timestamps, no nondeterministic fields anywhere
in the manifest path -- determinism is load-bearing for
"same evidence -> same digest".
"""

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

__all__ = [
    "EVIDENCE_ARTIFACT_TYPE",
    "EVIDENCE_MEDIA_TYPE",
    "CONFIG_MEDIA_TYPE",
    "MANIFEST_MEDIA_TYPE",
    "OCIRefusal",
    "OCIError",
    "digest_of",
    "canonical_json",
    "build_evidence_manifest",
    "parse_manifest",
    "fallback_tag_for",
    "OCIRegistryClient",
]

MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
EVIDENCE_ARTIFACT_TYPE = "application/vnd.sasanam.evidence.bundle.v1"
EVIDENCE_MEDIA_TYPE = "application/vnd.sasanam.evidence-bundle.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.sasanam.evidence-config.v1+json"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class OCIRefusal(Exception):
    """Coded fail-closed refusal: the registry (or its content) is untrusted.

    ``code`` is one of the ``oci-*`` decision codes; ``detail`` is human
    context. Refusals are policy/integrity violations, never network errors.
    """

    def __init__(self, code, detail):
        super(OCIRefusal, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class OCIError(Exception):
    """Operational failure talking to the registry (network, HTTP 5xx, ...).

    Distinct from OCIRefusal: the registry may be fine, the transport is
    not. Callers fail closed on this too, but it is not a trust verdict.
    """


def _refuse(code, detail):
    raise OCIRefusal(code, detail)


def digest_of(data):
    """``sha256:<hex>`` digest of bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("digest_of needs bytes, got %s" % type(data).__name__)
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def canonical_json(obj):
    """Deterministic JSON bytes: sorted keys, no whitespace, ASCII.

    The single serialization choke point for manifest building -- every
    digest this module computes flows through here, so "same evidence ->
    same digest" holds by construction.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _check_annotations(annotations):
    if annotations is None:
        return {}
    if not isinstance(annotations, dict):
        raise TypeError("annotations must be a dict or None")
    for k, v in annotations.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise TypeError("annotation keys and values must be strings")
    return dict(annotations)


def build_evidence_manifest(evidence_bytes, *,
                            artifact_type=EVIDENCE_ARTIFACT_TYPE,
                            evidence_media_type=EVIDENCE_MEDIA_TYPE,
                            annotations=None):
    """Build a deterministic subject-bearing OCI 1.1 manifest for evidence.

    The manifest's ``subject`` references the evidence payload descriptor
    by digest; the evidence bytes are also the single layer, so a verifier
    re-hashes exactly what the subject names. Returns
    ``(manifest_bytes, manifest_digest)``.

    Determinism: canonical JSON (sorted keys, compact separators), no
    timestamps, annotation insertion order irrelevant. Building twice from
    the same inputs yields byte-identical output.
    """
    if not isinstance(evidence_bytes, (bytes, bytearray)):
        raise TypeError("evidence_bytes must be bytes")
    evidence_bytes = bytes(evidence_bytes)
    annotations = _check_annotations(annotations)

    evidence_desc = {
        "mediaType": evidence_media_type,
        "digest": digest_of(evidence_bytes),
        "size": len(evidence_bytes),
    }
    config_desc = {
        "mediaType": CONFIG_MEDIA_TYPE,
        "digest": digest_of(b"{}"),
        "size": 2,
    }
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": artifact_type,
        "config": config_desc,
        "layers": [evidence_desc],
        "subject": evidence_desc,
        "annotations": annotations,
    }
    manifest_bytes = canonical_json(manifest)
    return manifest_bytes, digest_of(manifest_bytes)


def parse_manifest(manifest_bytes):
    """Parse and shape-validate a manifest fetched from the registry.

    Refuses coded ``oci-manifest-malformed`` on anything that is not a
    well-formed subject-bearing OCI manifest -- the registry is untrusted,
    so its bytes are validated before any field is trusted.
    """
    try:
        doc = json.loads(manifest_bytes.decode("utf-8"))
    except Exception:  # noqa: BLE001
        _refuse("oci-manifest-malformed", "manifest is not valid JSON")
    if not isinstance(doc, dict):
        _refuse("oci-manifest-malformed", "manifest is not a JSON object")
    if doc.get("schemaVersion") != 2:
        _refuse("oci-manifest-malformed", "schemaVersion must be 2")
    if not isinstance(doc.get("mediaType"), str):
        _refuse("oci-manifest-malformed", "manifest mediaType missing")
    subject = doc.get("subject")
    if not isinstance(subject, dict):
        _refuse("oci-manifest-malformed", "manifest subject missing")
    # F407-hardening (wave-323 lane 1): the digest must be a string
    # BEFORE the regex sees it -- a non-string digest is malformed, not
    # a TypeError.
    if (not isinstance(subject.get("digest"), str)
            or not _DIGEST_RE.match(subject.get("digest"))):
        _refuse("oci-manifest-malformed", "subject digest malformed")
    layers = doc.get("layers")
    if not isinstance(layers, list) or not layers:
        _refuse("oci-manifest-malformed", "manifest layers missing/empty")
    for layer in layers:
        digest = layer.get("digest") if isinstance(layer, dict) else None
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            _refuse("oci-manifest-malformed", "layer descriptor malformed")
    return doc


def fallback_tag_for(subject_digest):
    """Cosign legacy tag for a digest: ``sha256-<hex>.sig``.

    Fallback lookup ONLY (used when the referrers API 404s), never the
    primary discovery path.
    """
    if not _DIGEST_RE.match(subject_digest or ""):
        raise ValueError("malformed subject digest")
    return "sha256-" + subject_digest.split(":", 1)[1] + ".sig"


class OCIRegistryClient(object):
    """OCI distribution-spec client with client-side verification.

    Every pull is digest-addressed and every pulled byte is re-hashed;
    subject matching and artifact-type gating happen client-side. The
    registry is untrusted storage.
    """

    def __init__(self, base_url, repository, *, auth_token=None, timeout=30):
        if not base_url or not repository:
            raise ValueError("base_url and repository are required")
        if ".." in repository or repository.strip("/") != repository:
            raise ValueError("malformed repository")
        self.base_url = base_url.rstrip("/")
        self.repository = repository
        self.auth_token = auth_token
        self.timeout = timeout

    # -- transport ------------------------------------------------------
    def _headers(self, content_type=None):
        h = {"Accept": "%s, %s, application/json"
             % (MANIFEST_MEDIA_TYPE, INDEX_MEDIA_TYPE)}
        if content_type:
            h["Content-Type"] = content_type
        if self.auth_token:
            h["Authorization"] = "Bearer " + self.auth_token
        return h

    def _request(self, method, path, body=None, content_type=None):
        url = self.base_url + path
        req = urllib.request.Request(url, data=body, method=method,
                                     headers=self._headers(content_type))
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return (resp.status,
                        {k.lower(): v for k, v in resp.getheaders()},
                        resp.read())
        except urllib.error.HTTPError as e:
            try:
                ebody = e.read()
            except Exception:  # noqa: BLE001
                ebody = b""
            return (e.code, {k.lower(): v for k, v in (e.headers or {}).items()},
                    ebody)
        except urllib.error.URLError as e:
            raise OCIError("registry unreachable: %s" % (e,))

    def _repo_path(self, *parts):
        return "/v2/" + self.repository + "/" + "/".join(parts)

    # -- push -----------------------------------------------------------
    def push_blob(self, data, *, media_type="application/octet-stream"):
        """Upload a blob; returns its descriptor."""
        data = bytes(data)
        dgst = digest_of(data)
        status, headers, _ = self._request(
            "POST", self._repo_path("blobs", "uploads") + "/")
        if status == 201 and headers.get("docker-content-digest") == dgst:
            return {"mediaType": media_type, "digest": dgst, "size": len(data)}
        if status != 202 or "location" not in headers:
            raise OCIError("blob upload initiation failed: HTTP %d" % status)
        location = urllib.parse.urljoin(
            self.base_url + "/", headers["location"])
        sep = "&" if "?" in location else "?"
        status, _, _ = self._request(
            "PUT", urllib.parse.urlparse(location).path + sep + "digest="
            + urllib.parse.quote(dgst, safe=""),
            body=data, content_type=media_type)
        if status not in (200, 201):
            raise OCIError("blob upload failed: HTTP %d" % status)
        return {"mediaType": media_type, "digest": dgst, "size": len(data)}

    def push_manifest(self, manifest_bytes, reference):
        """Upload a manifest under a reference (digest or tag)."""
        manifest_bytes = bytes(manifest_bytes)
        status, _, _ = self._request(
            "PUT", self._repo_path("manifests", reference),
            body=manifest_bytes, content_type=MANIFEST_MEDIA_TYPE)
        if status not in (200, 201):
            raise OCIError("manifest push failed: HTTP %d" % status)
        return digest_of(manifest_bytes)

    def push_evidence(self, evidence_bytes, *,
                      artifact_type=EVIDENCE_ARTIFACT_TYPE,
                      evidence_media_type=EVIDENCE_MEDIA_TYPE,
                      annotations=None):
        """Push evidence bytes + their subject-bearing manifest.

        The manifest is stored content-addressed (by digest) -- the primary
        discovery path is the referrers API, not tags. Returns
        ``{"blob_digest", "manifest_digest", "subject_digest", "size"}``.
        """
        blob = self.push_blob(evidence_bytes,
                              media_type=evidence_media_type)
        manifest_bytes, manifest_digest = build_evidence_manifest(
            evidence_bytes, artifact_type=artifact_type,
            evidence_media_type=evidence_media_type,
            annotations=annotations)
        self.push_manifest(manifest_bytes, manifest_digest)
        return {"blob_digest": blob["digest"],
                "manifest_digest": manifest_digest,
                "subject_digest": blob["digest"],
                "size": blob["size"]}

    # -- pull -----------------------------------------------------------
    def get_manifest(self, reference):
        """Fetch a manifest by digest or tag; None on 404."""
        status, _, body = self._request(
            "GET", self._repo_path("manifests", reference))
        if status == 200:
            return body
        if status == 404:
            return None
        raise OCIError("manifest fetch failed: HTTP %d" % status)

    def get_blob(self, digest):
        """Fetch a blob by digest; None on 404."""
        if not _DIGEST_RE.match(digest or ""):
            raise ValueError("malformed blob digest")
        status, _, body = self._request(
            "GET", self._repo_path("blobs", digest))
        if status == 200:
            return body
        if status == 404:
            return None
        raise OCIError("blob fetch failed: HTTP %d" % status)

    # -- discovery ------------------------------------------------------
    def discover_referrers(self, subject_digest):
        """Find manifests referring to a subject digest.

        Primary: ``GET /v2/<repo>/referrers/<digest>`` (OCI 1.1). On 404,
        the spec-mandated fallback: the ``sha256-<hex>.sig`` tag. Returns
        ``(descriptors, via)`` where ``via`` is ``"referrers-api"`` or
        ``"tag-fallback"`` -- callers can see which path was used, and the
        fallback is never silently the primary.

        Per-manifest subject matching happens at pull time (the index does
        not carry per-manifest subjects); a referrers response whose own
        subject disagrees with the query is ignored outright.
        """
        if not _DIGEST_RE.match(subject_digest or ""):
            raise ValueError("malformed subject digest")
        status, _, body = self._request(
            "GET", self._repo_path("referrers", subject_digest))
        if status == 200:
            try:
                doc = json.loads(body.decode("utf-8"))
            except Exception:  # noqa: BLE001
                doc = {}
            # F407 (closed wave-323 lane 1): the registry is untrusted
            # storage, so the response shape is validated BEFORE any
            # field is dereferenced. Every violation refuses with the
            # coded oci-referrers-malformed refusal -- no uncoded
            # AttributeError/TypeError may escape to the caller.
            if not isinstance(doc, dict):
                _refuse("oci-referrers-malformed",
                        "referrers response is not a JSON object")
            resp_subject = doc.get("subject") or {}
            if not isinstance(resp_subject, dict):
                _refuse("oci-referrers-malformed",
                        "referrers subject is not an object")
            resp_digest = resp_subject.get("digest")
            if resp_digest is not None and resp_digest != subject_digest:
                return ([], "referrers-api")
            entries = doc.get("manifests")
            if not isinstance(entries, list):
                entries = doc.get("referrers")
            if not isinstance(entries, list):
                entries = []
            descriptors = []
            for e in entries:
                if not isinstance(e, dict):
                    continue
                digest = e.get("digest")
                if digest is not None and not isinstance(digest, str):
                    _refuse("oci-referrers-malformed",
                            "referrers entry digest is not a string")
                if not (isinstance(digest, str)
                        and _DIGEST_RE.match(digest)):
                    continue
                descriptors.append({"mediaType": e.get("mediaType"),
                                    "artifactType": e.get("artifactType"),
                                    "digest": digest,
                                    "size": e.get("size")})
            return (descriptors, "referrers-api")
        if status != 404:
            raise OCIError("referrers lookup failed: HTTP %d" % status)
        # Spec-mandated fallback: tag schema.
        tag = fallback_tag_for(subject_digest)
        status, _, body = self._request("GET", self._repo_path("tags", "list"))
        tags = []
        if status == 200:
            try:
                tags = json.loads(body.decode("utf-8")).get("tags") or []
            except Exception:  # noqa: BLE001
                tags = []
            # F407-hardening (wave-323 lane 1): the tag list is
            # registry-controlled; a non-list is malformed, not a
            # TypeError on `in`.
            if not isinstance(tags, list):
                _refuse("oci-referrers-malformed",
                        "registry tag list is not a list")
        if tag not in tags:
            return ([], "tag-fallback")
        manifest_bytes = self.get_manifest(tag)
        if manifest_bytes is None:
            return ([], "tag-fallback")
        try:
            manifest = parse_manifest(manifest_bytes)
        except OCIRefusal:
            return ([], "tag-fallback")
        return ([{"mediaType": manifest.get("mediaType"),
                  "artifactType": manifest.get("artifactType"),
                  "digest": digest_of(manifest_bytes),
                  "size": len(manifest_bytes)}],
                "tag-fallback")

    # -- verified pull --------------------------------------------------
    def pull_and_verify(self, subject_digest, *,
                        artifact_type=EVIDENCE_ARTIFACT_TYPE,
                        payload_verifier=None):
        """Pull the evidence for a subject digest, verifying everything.

        Fail-closed order: discover -> fetch each candidate manifest ->
        shape-validate -> artifact-type gate -> subject match -> re-hash
        every layer -> return the subject blob's bytes. The first fully
        verified candidate wins; if none verifies, the most specific
        coded refusal is raised (never a silent None).
        """
        refs, _via = self.discover_referrers(subject_digest)
        if not refs:
            _refuse("oci-referrers-unavailable",
                    "no referrer found for %s" % subject_digest)
        saw_malformed = saw_artifact = saw_subject = False
        for ref in refs:
            manifest_bytes = self.get_manifest(ref["digest"])
            if manifest_bytes is None:
                continue
            # The digest used to address the manifest must reproduce.
            if digest_of(manifest_bytes) != ref["digest"]:
                saw_malformed = True
                continue
            try:
                manifest = parse_manifest(manifest_bytes)
            except OCIRefusal:
                saw_malformed = True
                continue
            if (artifact_type is not None
                    and manifest.get("artifactType") != artifact_type):
                saw_artifact = True
                continue
            if manifest["subject"]["digest"] != subject_digest:
                saw_subject = True
                continue
            # Re-hash every layer: the registry is untrusted storage.
            blobs = {}
            ok = True
            for layer in manifest["layers"]:
                blob = self.get_blob(layer["digest"])
                if blob is None or digest_of(blob) != layer["digest"]:
                    ok = False
                    break
                blobs[layer["digest"]] = blob
            if not ok:
                _refuse("oci-blob-digest-mismatch",
                        "layer bytes do not match descriptor in %s"
                        % ref["digest"])
            evidence = blobs.get(manifest["subject"]["digest"])
            if evidence is None:
                _refuse("oci-blob-digest-mismatch",
                        "subject blob %s not served by registry"
                        % manifest["subject"]["digest"])
            if payload_verifier is not None:
                payload_verifier(evidence)
            return evidence
        if saw_artifact:
            _refuse("oci-artifact-type-mismatch",
                    "no candidate manifest carries artifactType %s"
                    % artifact_type)
        if saw_subject:
            _refuse("oci-subject-mismatch",
                    "candidate manifests do not reference subject %s"
                    % subject_digest)
        if saw_malformed:
            _refuse("oci-manifest-malformed",
                    "candidate manifests failed shape validation")
        _refuse("oci-referrers-unavailable",
                "no fetchable referrer for %s" % subject_digest)
