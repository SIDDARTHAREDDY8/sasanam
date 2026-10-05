#!/usr/bin/env python3
"""OCI 1.1 Referrers transport for keyed Sigstore evidence bundles.

Wave-338 lane 4 (R17 of the w337 research prospectus): the transport half
of the "sell evidence" distribution story. Evidence bundles ship as OCI
artifacts with BOM and signature attached; the digest becomes identity.

What this module is
-------------------
- ``attach_keyed_bundle``: PUT a keyed Sigstore bundle
  (``application/vnd.dev.sigstore.bundle.v0.3+json``, sealed by
  :func:`gov.sigstore_bundle.seal_keyed_bundle`) as a blob, then PUT an
  OCI 1.1 referrer manifest whose ``subject.digest`` is the bundle's
  subject digest, whose ``artifactType`` is the bundle media type, and
  whose annotations carry the bundle's VSA predicate type.
- ``discover_keyed_bundles``: ``GET /v2/<repo>/referrers/<digest>``,
  select by ``artifactType``, then bind every selected referrer to the
  queried subject digest (``verify_referrer_binding``).
- ``pull_keyed_bundle``: digest-addressed manifest + blob pull with
  client-side re-hashing.

What this module is NOT
-----------------------
- No implicit I/O. The module builds requests; the deployment's transport
  sends them. ``transport`` is a required caller-supplied callable::

      transport(request) -> (status, headers, body)

  where ``request`` is ``{"method", "url", "headers", "body"}`` and the
  return is ``(int, dict[str, str] (lower-cased), bytes)``.
  :func:`urllib_transport` is a stdlib reference implementation -- it is
  never called implicitly; the caller wires it in explicitly.
- Digest-only by construction. Tags are refused with the coded
  ``oci-tag-refused`` refusal everywhere a reference is taken. There is
  no tag fallback: when the registry 404s/400s the Referrers API the
  module refuses ``oci-referrers-unavailable`` fail-closed (this is the
  deliberate opposite of the spec-mandated 404 -> tag-scheme fallback in
  :mod:`gov.oci_distribution`, which serves a different, tag-tolerant
  discovery story).
- Transport integrity only. Every byte pulled by digest is re-hashed
  client-side; a manifest whose blobs do not match, or whose subject is
  not the queried digest, is refused with a coded refusal. PAYLOAD
  authenticity is the caller's job: verify the pulled bytes with
  :func:`gov.sigstore_bundle.verify_keyed_bundle` (or
  ``gov.evidence_verify_offline`` for evidence bundles). This module
  never invents key authority.
- Stdlib only (``hashlib``, ``json``, ``base64``, ``re``,
  ``urllib.parse``; ``urllib.request`` inside the reference transport
  only). F75 stays clean: no ORAS dependency.

HARBOR DEPLOYMENT CAVEAT (direct-push only)
------------------------------------------
cosign v3 referrer signatures are invisible in the Harbor UI and are
ignored by Harbor's Replication Service: a referrer manifest pushed to a
Harbor origin is NOT replicated to replica registries, and the Harbor UI
never shows referrer-attached signatures as verified. Deployments MUST
therefore push referrers directly to the registry the auditor reads
(direct-push only); reads MUST NOT go through a Harbor replica and MUST
NOT rely on replication to carry referrers.

The auditor's verdict never comes from a registry badge. Every pull here
is digest-addressed and re-hashed client-side, and bundle authenticity is
established by the offline verifier
(:func:`gov.sigstore_bundle.verify_keyed_bundle`), never by anything the
registry displays. A registry-supplied "verified" annotation is not an
input to any verdict in this module -- the battery proves it (tampered
bundle + "verified: true" still refuses; valid bundle + "verified:
false" still passes transport checks).
"""

import base64
import hashlib
import json
import re
import urllib.parse

# ---------------------------------------------------------------------------
# Contract constants.
# ---------------------------------------------------------------------------

OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_EMPTY_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"

# The keyed Sigstore bundle shape sealed by gov.sigstore_bundle.
# (Kept as a literal so this module stays dependency-free; the unit test
# pins it equal to gov.sigstore_bundle.SIGSTORE_BUNDLE_MEDIA_TYPE.)
BUNDLE_LAYER_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
BUNDLE_ARTIFACT_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"

PREDICATE_TYPE_ANNOTATION = "dev.sigstore.bundle.predicate-type"
TITLE_ANNOTATION = "org.opencontainers.image.title"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEXDIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class OCIReferrerRefusal(Exception):
    """Coded fail-closed refusal: the registry (or its content) is untrusted.

    ``code`` is one of the ``oci-*`` decision codes; ``detail`` is human
    context. Refusals are policy/integrity violations, never network
    errors.
    """

    def __init__(self, code, detail):
        super(OCIReferrerRefusal, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class OCIReferrerError(Exception):
    """Operational failure: the transport or registry misbehaved.

    Distinct from OCIReferrerRefusal: the registry may be fine, the
    transport is not (network down, HTTP 5xx, auth failure, malformed
    transport return). Callers fail closed on this too, but it is not a
    trust verdict.
    """


def _refuse(code, detail):
    raise OCIReferrerRefusal(code, detail)


def digest_of(data):
    """``sha256:<hex>`` digest of bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("digest_of needs bytes, got %s" % type(data).__name__)
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def canonical_json(obj):
    """Deterministic JSON bytes: sorted keys, no whitespace, ASCII.

    The single serialization choke point -- every digest this module
    computes flows through here, so "same bundle -> same digest" holds
    by construction.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def is_canonical_digest(ref):
    """True iff ``ref`` is a canonical ``sha256:<hex>`` digest."""
    return isinstance(ref, str) and _DIGEST_RE.match(ref) is not None


def _require_digest(ref, where):
    if not is_canonical_digest(ref):
        _refuse("oci-tag-refused",
                "%s: %r is not a canonical sha256 digest -- digest-only "
                "addressing by construction; tags are mutable and can "
                "never be bundle identity" % (where, ref))
    return ref


def _empty_config_descriptor():
    return {"mediaType": OCI_EMPTY_MEDIA_TYPE,
            "digest": digest_of(b"{}"),
            "size": 2}


def _auth_headers(auth_token):
    if auth_token is None:
        return {}
    if not isinstance(auth_token, str) or not auth_token:
        raise TypeError("auth_token must be a non-empty str or None")
    return {"Authorization": "Bearer " + auth_token}


# ---------------------------------------------------------------------------
# Caller-supplied transport.
# ---------------------------------------------------------------------------

def urllib_transport(*, timeout=30):
    """Reference transport built on stdlib ``urllib.request``.

    The module never calls this implicitly -- the deployment passes the
    returned callable as ``transport`` explicitly. ``request`` is
    ``{"method", "url", "headers", "body"}``; returns
    ``(status, headers, body)`` with lower-cased header names.
    """

    def send(request):
        import urllib.error
        import urllib.request
        try:
            method = request["method"]
            url = request["url"]
            headers = request.get("headers") or {}
            body = request.get("body")
        except (KeyError, TypeError, AttributeError) as exc:
            raise OCIReferrerError("malformed transport request: %r" % (exc,))
        req = urllib.request.Request(url, data=body, method=method,
                                     headers=dict(headers))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return (resp.status,
                        {k.lower(): v for k, v in resp.getheaders()},
                        resp.read())
        except urllib.error.HTTPError as e:
            try:
                ebody = e.read() or b""
            except Exception:  # noqa: BLE001 -- best-effort body capture
                ebody = b""
            return (e.code,
                    {k.lower(): v for k, v in (e.headers or {}).items()},
                    ebody)
        except Exception as exc:  # noqa: BLE001 -- URLError and friends
            raise OCIReferrerError("transport failed: %r" % (exc,))

    return send


def _send(transport, method, url, headers, body):
    """One request through the caller-supplied transport, fail-closed."""
    if not callable(transport):
        raise TypeError("transport must be callable")
    if body is not None and not isinstance(body, (bytes, bytearray)):
        raise TypeError("request body must be bytes or None")
    try:
        result = transport({"method": method, "url": url,
                            "headers": dict(headers), "body": body})
    except OCIReferrerError:
        raise
    except OCIReferrerRefusal:
        raise
    except Exception as exc:  # noqa: BLE001 -- every transport failure fatal
        raise OCIReferrerError("transport raised: %r" % (exc,))
    try:
        status, rheaders, rbody = result
        status = int(status)
        rheaders = {str(k).lower(): str(v)
                    for k, v in dict(rheaders).items()}
        rbody = bytes(rbody)
    except (TypeError, ValueError, AttributeError) as exc:
        raise OCIReferrerError("transport returned malformed result: %r"
                              % (exc,))
    return (status, rheaders, rbody)


def _join(base_url, *parts):
    if not isinstance(base_url, str) or not base_url:
        raise ValueError("base_url must be a non-empty str")
    base = base_url.rstrip("/")
    # Quote each path SEGMENT (safe=":" keeps digest separators literal;
    # segments are split on "/" by the caller, so "/" is never quoted).
    path = "/".join(urllib.parse.quote(str(p).strip("/"), safe=":")
                    for p in parts)
    return base + "/" + path


def _repo_url(base_url, repository, *parts):
    if (not isinstance(repository, str) or not repository
            or ".." in repository or repository.strip("/") != repository):
        raise ValueError("malformed repository: %r" % (repository,))
    return _join(base_url, "v2", *repository.split("/"), *parts)


# ---------------------------------------------------------------------------
# Push side.
# ---------------------------------------------------------------------------

def push_blob(transport, base_url, repository, data, *,
               media_type=BUNDLE_LAYER_MEDIA_TYPE, auth_token=None):
    """Upload a blob; returns its descriptor.

    Standard two-step OCI blob upload (POST uploads/ -> 202 + Location ->
    PUT ?digest=) driven entirely through the caller-supplied transport.
    """
    data = bytes(data)
    dgst = digest_of(data)
    headers = _auth_headers(auth_token)
    url = _repo_url(base_url, repository, "blobs", "uploads") + "/"
    status, rheaders, _ = _send(transport, "POST", url, headers, None)
    if status == 201 and rheaders.get("docker-content-digest") == dgst:
        # Monolithic upload accepted in one step.
        return {"mediaType": media_type, "digest": dgst, "size": len(data)}
    if status != 202 or "location" not in rheaders:
        raise OCIReferrerError("blob upload initiation failed: HTTP %d"
                              % status)
    location = urllib.parse.urljoin(base_url.rstrip("/") + "/",
                                    rheaders["location"])
    parsed = urllib.parse.urlparse(location)
    sep = "&" if parsed.query else "?"
    put_url = (parsed.scheme + "://" + parsed.netloc + parsed.path + sep
               + "digest=" + urllib.parse.quote(dgst, safe=""))
    put_headers = dict(headers)
    put_headers["Content-Type"] = media_type
    put_headers["Content-Length"] = str(len(data))
    status, rheaders, _ = _send(transport, "PUT", put_url, put_headers,
                                data)
    if status not in (200, 201):
        raise OCIReferrerError("blob upload failed: HTTP %d" % status)
    echo = rheaders.get("docker-content-digest")
    if echo is not None and echo != dgst:
        _refuse("oci-blob-digest-mismatch",
                "registry echoed digest %r for uploaded blob %s"
                % (echo, dgst))
    return {"mediaType": media_type, "digest": dgst, "size": len(data)}


def put_referrer_manifest(transport, base_url, repository, manifest_bytes,
                          *, auth_token=None):
    """PUT a referrer manifest content-addressed (by digest). Returns digest."""
    manifest_bytes = bytes(manifest_bytes)
    reference = digest_of(manifest_bytes)
    headers = _auth_headers(auth_token)
    headers["Content-Type"] = OCI_MANIFEST_MEDIA_TYPE
    url = _repo_url(base_url, repository, "manifests", reference)
    status, _, _ = _send(transport, "PUT", url, headers, manifest_bytes)
    if status not in (200, 201):
        raise OCIReferrerError("referrer manifest push failed: HTTP %d"
                              % status)
    return reference


def _extract_predicate_type(bundle_obj):
    """Best-effort VSA predicate type from the sealed statement.

    Advisory only: the value rides as an OCI annotation for index-time
    filtering. Bundle interior discrimination always happens inside the
    bundle (verify_keyed_bundle), never on this annotation. Returns None
    when the statement is not in-toto JSON or carries no predicateType.
    """
    try:
        env = bundle_obj.get("dsseEnvelope") or {}
        payload_b64 = env.get("payload")
        if not isinstance(payload_b64, str):
            return None
        stmt = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
        if not isinstance(stmt, dict):
            return None
        ptype = stmt.get("predicateType")
        return ptype if isinstance(ptype, str) and ptype else None
    except Exception:  # noqa: BLE001 -- advisory extraction, never fatal
        return None


def build_referrer_manifest(layer_descriptor, subject_digest, *,
                            subject_media_type=None, subject_size=None,
                            annotations=None):
    """Build the OCI 1.1 referrer manifest bytes for one keyed bundle."""
    _require_digest(subject_digest, "build_referrer_manifest subject")
    if not isinstance(layer_descriptor, dict):
        raise TypeError("layer_descriptor must be a dict")
    for field in ("mediaType", "digest", "size"):
        if field not in layer_descriptor:
            raise ValueError("layer_descriptor missing %r" % field)
    if layer_descriptor["mediaType"] != BUNDLE_LAYER_MEDIA_TYPE:
        _refuse("oci-layer-media-type-mismatch",
                "layer mediaType %r is not the keyed Sigstore bundle media "
                "type" % (layer_descriptor["mediaType"],))
    subject = {"mediaType": (subject_media_type
                             or OCI_MANIFEST_MEDIA_TYPE),
               "digest": subject_digest}
    if subject_size is not None:
        if (not isinstance(subject_size, int) or subject_size < 0
                or isinstance(subject_size, bool)):
            raise TypeError("subject_size must be a non-negative int")
        subject["size"] = subject_size
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "artifactType": BUNDLE_ARTIFACT_TYPE,
        "config": _empty_config_descriptor(),
        "layers": [dict(layer_descriptor)],
        "subject": subject,
        "annotations": dict(annotations or {}),
    }
    return canonical_json(manifest)


def attach_keyed_bundle(transport, base_url, repository, subject_digest,
                        bundle, *, predicate_type=None, auth_token=None,
                        subject_media_type=None, subject_size=None,
                        title="evidence.sigstore.json"):
    """Attach a keyed Sigstore bundle to a subject digest as an OCI referrer.

    PUTs the bundle bytes as a blob (media type
    ``application/vnd.dev.sigstore.bundle.v0.3+json``), then PUTs the
    referrer manifest content-addressed. ``subject_digest`` is
    digest-only: a tag is refused with ``oci-tag-refused``.

    Returns ``{"bundle_digest", "manifest_digest", "subject_digest",
    "size", "predicate_type", "artifact_type"}``.
    """
    _require_digest(subject_digest, "attach_keyed_bundle subject")
    bundle_bytes = bytes(bundle)
    try:
        bundle_obj = json.loads(bundle_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _refuse("oci-layer-media-type-mismatch",
                "bundle bytes are not JSON: %s" % (exc,))
    if not isinstance(bundle_obj, dict):
        _refuse("oci-layer-media-type-mismatch",
                "bundle is not a JSON object")
    if bundle_obj.get("mediaType") != BUNDLE_LAYER_MEDIA_TYPE:
        _refuse("oci-layer-media-type-mismatch",
                "bundle mediaType %r is not the keyed Sigstore bundle media "
                "type -- refusing to attach non-bundle content as a bundle "
                "referrer" % (bundle_obj.get("mediaType"),))
    # Bernstein #6371 (wave-339 R22, verifiable-only): the builder refuses
    # bundles the offline verifier cannot verify. open_keyed_bundle
    # structurally refuses bundles with tlog/timestamp claims (unverifiable
    # log claims), a messageSignature alongside the envelope, a non-keyed
    # payload type, more or fewer than one signature, a missing DSSE
    # envelope, or malformed verification material -- so attach refuses
    # them too. Never emit a bundle containing a payload the verifier
    # cannot verify. Verifiability, not validity: Ed25519 verification and
    # hint pinning stay the consumer's job. (Imported locally: this
    # module stays dependency-free at import time.)
    from gov.sigstore_bundle import (KeyedBundleError,
                                     check_keyed_bundle_structure)
    try:
        check_keyed_bundle_structure(bundle_obj)
    except KeyedBundleError as exc:
        _refuse("oci-bundle-not-verifiable",
                "bundle is not verifiable by the offline verifier: %s "
                "-- refusing to attach unverifiable evidence"
                % (exc.code,))
    if predicate_type is None:
        predicate_type = _extract_predicate_type(bundle_obj)
    elif not isinstance(predicate_type, str) or not predicate_type:
        raise TypeError("predicate_type must be a non-empty str or None")

    layer = push_blob(transport, base_url, repository, bundle_bytes,
                      media_type=BUNDLE_LAYER_MEDIA_TYPE,
                      auth_token=auth_token)
    annotations = {TITLE_ANNOTATION: title}
    if predicate_type is not None:
        annotations[PREDICATE_TYPE_ANNOTATION] = predicate_type
    manifest_bytes = build_referrer_manifest(
        layer, subject_digest,
        subject_media_type=subject_media_type,
        subject_size=subject_size,
        annotations=annotations)
    manifest_digest = put_referrer_manifest(
        transport, base_url, repository, manifest_bytes,
        auth_token=auth_token)
    return {"bundle_digest": layer["digest"],
            "manifest_digest": manifest_digest,
            "subject_digest": subject_digest,
            "size": layer["size"],
            "predicate_type": predicate_type,
            "artifact_type": BUNDLE_ARTIFACT_TYPE}


# ---------------------------------------------------------------------------
# Discovery + pull side.
# ---------------------------------------------------------------------------

def verify_referrer_binding(index_doc, subject_digest, *,
                            artifact_type=BUNDLE_ARTIFACT_TYPE):
    """Bind every selected referrer to the queried subject digest.

    ``index_doc`` is the parsed ``GET .../referrers/<digest>`` response
    (dict, or its raw bytes). Selects entries whose ``artifactType`` is
    the keyed-bundle artifact type, then refuses ``oci-subject-mismatch``
    unless every selected entry's ``subject.digest`` string-equals
    ``subject_digest``. A registry serving referrers for a *different*
    subject is a confusion attack -- fail closed.

    Returns the selected descriptors.
    """
    _require_digest(subject_digest, "verify_referrer_binding subject")
    if isinstance(index_doc, (bytes, bytearray)):
        try:
            index_doc = json.loads(bytes(index_doc).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            _refuse("oci-referrers-malformed",
                    "referrers response is not JSON")
    if not isinstance(index_doc, dict):
        _refuse("oci-referrers-malformed",
                "referrers response is not a JSON object")
    entries = index_doc.get("referrers")
    if not isinstance(entries, list):
        _refuse("oci-referrers-malformed",
                "referrers response has no 'referrers' list")
    selected = []
    for entry in entries:
        if not isinstance(entry, dict):
            _refuse("oci-referrers-malformed",
                    "referrer entry is not an object")
        if entry.get("artifactType") != artifact_type:
            continue
        entry_digest = entry.get("digest")
        if not is_canonical_digest(entry_digest):
            _refuse("oci-referrers-malformed",
                    "selected referrer entry digest is not canonical")
        subject = entry.get("subject")
        if not isinstance(subject, dict):
            _refuse("oci-subject-mismatch",
                    "selected referrer %s carries no subject binding"
                    % entry_digest)
        if subject.get("digest") != subject_digest:
            _refuse("oci-subject-mismatch",
                    "selected referrer %s is bound to subject %r, not the "
                    "queried subject %s -- possible confusion attack"
                    % (entry_digest, subject.get("digest"),
                       subject_digest))
        selected.append(entry)
    return selected


def discover_keyed_bundles(transport, base_url, repository, subject_digest,
                           *, auth_token=None,
                           artifact_type=BUNDLE_ARTIFACT_TYPE):
    """Discover keyed-bundle referrers for a subject digest.

    ``GET /v2/<repo>/referrers/<digest>``. A 404/400 on the referrers
    endpoint means the registry has no Referrers API -- refused
    ``oci-referrers-unavailable`` fail-closed. The tag scheme is NEVER a
    fallback. Returns the bound descriptors (possibly empty: "no bundles
    attached" is a legitimate answer).
    """
    _require_digest(subject_digest, "discover_keyed_bundles subject")
    headers = dict(_auth_headers(auth_token))
    headers["Accept"] = OCI_INDEX_MEDIA_TYPE
    url = _repo_url(base_url, repository, "referrers", subject_digest)
    status, _, body = _send(transport, "GET", url, headers, None)
    if status in (404, 400):
        _refuse("oci-referrers-unavailable",
                "registry has no Referrers API for %s (HTTP %d) -- "
                "refusing fail-closed; the tag scheme is never a fallback"
                % (subject_digest, status))
    if status != 200:
        raise OCIReferrerError("referrers lookup failed: HTTP %d" % status)
    try:
        index_doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _refuse("oci-referrers-malformed",
                "referrers response is not JSON")
    return verify_referrer_binding(index_doc, subject_digest,
                                   artifact_type=artifact_type)


def pull_keyed_bundle(transport, base_url, repository, descriptor,
                      subject_digest, *, auth_token=None):
    """Pull one keyed bundle by its descriptor, verifying everything.

    Digest-addressed manifest fetch (re-hashed), artifactType gate,
    subject binding check, keyed-bundle layer selection, digest-addressed
    blob fetch (re-hashed). Returns the bundle bytes. Signature
    verification is the caller's job (verify_keyed_bundle).
    """
    if not isinstance(descriptor, dict):
        raise TypeError("descriptor must be a dict")
    manifest_digest = descriptor.get("digest")
    _require_digest(manifest_digest, "pull_keyed_bundle descriptor")
    _require_digest(subject_digest, "pull_keyed_bundle subject")
    headers = dict(_auth_headers(auth_token))
    headers["Accept"] = OCI_MANIFEST_MEDIA_TYPE
    url = _repo_url(base_url, repository, "manifests", manifest_digest)
    status, _, mbody = _send(transport, "GET", url, headers, None)
    if status != 200:
        raise OCIReferrerError("manifest pull failed: HTTP %d" % status)
    if digest_of(mbody) != manifest_digest:
        _refuse("oci-blob-digest-mismatch",
                "manifest bytes pulled by digest %s do not hash to the "
                "requested digest" % manifest_digest)
    try:
        manifest = json.loads(mbody.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _refuse("oci-manifest-malformed",
                "manifest bytes are not JSON")
    if not isinstance(manifest, dict):
        _refuse("oci-manifest-malformed",
                "manifest is not a JSON object")
    if manifest.get("artifactType") != BUNDLE_ARTIFACT_TYPE:
        _refuse("oci-artifact-type-mismatch",
                "manifest artifactType %r is not the keyed-bundle artifact "
                "type" % (manifest.get("artifactType"),))
    subject = manifest.get("subject")
    if not isinstance(subject, dict) or \
            subject.get("digest") != subject_digest:
        _refuse("oci-subject-mismatch",
                "pulled manifest is bound to subject %r, not the queried "
                "subject %s" % ((subject or {}).get("digest"),
                                subject_digest))
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        _refuse("oci-manifest-malformed", "manifest has no layers list")
    layer = None
    for cand in layers:
        if isinstance(cand, dict) and \
                cand.get("mediaType") == BUNDLE_LAYER_MEDIA_TYPE:
            layer = cand
            break
    if layer is None:
        _refuse("oci-layer-media-type-mismatch",
                "referrer manifest carries no keyed-Sigstore-bundle layer")
    layer_digest = layer.get("digest")
    if not is_canonical_digest(layer_digest):
        _refuse("oci-manifest-malformed",
                "bundle layer digest is not canonical")
    bheaders = dict(_auth_headers(auth_token))
    bheaders["Accept"] = BUNDLE_LAYER_MEDIA_TYPE
    burl = _repo_url(base_url, repository, "blobs", layer_digest)
    status, _, bbody = _send(transport, "GET", burl, bheaders, None)
    if status != 200:
        raise OCIReferrerError("blob pull failed: HTTP %d" % status)
    if digest_of(bbody) != layer_digest:
        _refuse("oci-blob-digest-mismatch",
                "bundle blob bytes pulled by digest %s do not hash to the "
                "requested digest -- possible tampering" % layer_digest)
    return bbody
