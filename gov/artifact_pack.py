"""ORAS/OCI-shaped artifact packaging for evidence and skill bundles.

W248-7 (ORAS artifacts lane). The wave-247 prospectus (ADAPT: ORAS/OCI
as the evidence+skill transport; redhat-et/skillimage as ecosystem
confirmation) sets the direction: evidence and skill bundles ship as
OCI artifacts whose digest is their identity. This module is the
local-only, stdlib-only half of that direction: pack a set of named
blobs into an OCI-image-spec-shaped manifest and verify the package
fail-closed. No network, no registry client -- distribution rides the
OCI registry later; this module makes bundles ORAS-pushable from day
one.

OCI mapping (documented, not hidden): each blob becomes one layer
(``mediaType``/``digest``/``size`` per layer); ``artifactType`` is the
OCI artifact type; the artifact digest (sha256 over the canonical
manifest bytes) is the OCI manifest digest. A later transport lane
translates ``blobs`` -> ``layers`` one-to-one.

Digest-is-identity: the artifact digest binds every blob byte. Any
byte flip, blob addition/removal, size lie, or manifest edit changes
the digest or fails verification -- pinned by
``evals/w248_artifact_pack_probes.py``.

Refusal codes (all additive to the taxonomy):
  artifact-blob-extra, artifact-blob-missing, artifact-blob-tampered,
  artifact-manifest-malformed, artifact-manifest-tampered,
  artifact-size-mismatch, artifact-type-unknown

Stdlib only.
"""

import hashlib
import json
import re

ARTIFACT_TYPE_EVIDENCE_BUNDLE = (
    "application/vnd.sasanam.evidence-bundle.v1")
ARTIFACT_TYPE_SKILL_BUNDLE = (
    "application/vnd.sasanam.skill-bundle.v1")

KNOWN_ARTIFACT_TYPES = frozenset([
    ARTIFACT_TYPE_EVIDENCE_BUNDLE,
    ARTIFACT_TYPE_SKILL_BUNDLE,
])

MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
SCHEMA_VERSION = 2

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ArtifactPackError(Exception):
    """Fail-closed refusal from artifact pack/verify.

    ``code`` is the taxonomy refusal string; ``detail`` is a
    human-readable explanation that never carries blob bytes.
    """

    def __init__(self, code, detail):
        super(ArtifactPackError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _fail(code, detail):
    raise ArtifactPackError(code, detail)


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def manifest_digest(manifest):
    """The artifact identity: sha256 over the canonical manifest."""
    return "sha256:" + hashlib.sha256(
        _canonical_bytes(manifest)).hexdigest()


def _blob_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _check_blob_name(name):
    if not isinstance(name, str) or not name:
        _fail("artifact-manifest-malformed",
              "blob name must be a non-empty string")
    if "\x00" in name:
        _fail("artifact-manifest-malformed",
              "blob name %r contains NUL" % (name,))
    if name != name.strip() or ".." in name.split("/"):
        _fail("artifact-manifest-malformed",
              "blob name %r is not a clean relative name" % (name,))


def _check_annotations(annotations):
    if annotations is None:
        return {}
    if not isinstance(annotations, dict):
        _fail("artifact-manifest-malformed",
              "annotations must be a string->string map")
    for key, value in annotations.items():
        if not isinstance(key, str) or not isinstance(value, str):
            _fail("artifact-manifest-malformed",
                  "annotation keys and values must be strings")
    return dict(annotations)


def pack(blobs, artifact_type, annotations=None, media_types=None):
    """Pack named blobs into an artifact manifest.

    ``blobs``: dict name -> bytes. ``artifact_type``: one of
    KNOWN_ARTIFACT_TYPES. Returns ``(manifest, digest)`` where
    ``digest`` is the artifact identity (``sha256:<hex>``).
    Fail-closed on malformed input.
    """
    if artifact_type not in KNOWN_ARTIFACT_TYPES:
        _fail("artifact-type-unknown",
              "unknown artifactType %r" % (artifact_type,))
    if not isinstance(blobs, dict):
        _fail("artifact-manifest-malformed",
              "blobs must be a name->bytes dict")
    checked = {}
    for name, data in blobs.items():
        _check_blob_name(name)
        if not isinstance(data, bytes):
            _fail("artifact-manifest-malformed",
                  "blob %r must be bytes, not %s" % (
                      name, type(data).__name__))
        checked[name] = data
    ann = _check_annotations(annotations)
    media = {}
    if media_types is not None:
        if not isinstance(media_types, dict):
            _fail("artifact-manifest-malformed",
                  "media_types must be a name->mediaType dict")
        for name, mtype in media_types.items():
            if name not in checked:
                _fail("artifact-manifest-malformed",
                      "mediaType for unknown blob %r" % (name,))
            if not isinstance(mtype, str) or not mtype:
                _fail("artifact-manifest-malformed",
                      "mediaType for %r must be a non-empty string"
                      % (name,))
            media[name] = mtype
    entries = []
    for name in sorted(checked):
        data = checked[name]
        entries.append({
            "name": name,
            "digest": _blob_digest(data),
            "size": len(data),
            "mediaType": media.get(name, "application/octet-stream"),
        })
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": artifact_type,
        "blobs": entries,
        "annotations": ann,
    }
    return manifest, manifest_digest(manifest)


def _check_manifest_shape(manifest):
    if not isinstance(manifest, dict):
        _fail("artifact-manifest-malformed",
              "manifest must be a dict")
    for key in ("schemaVersion", "mediaType", "artifactType",
                "blobs", "annotations"):
        if key not in manifest:
            _fail("artifact-manifest-malformed",
                  "manifest missing key %r" % (key,))
    if manifest["schemaVersion"] != SCHEMA_VERSION:
        _fail("artifact-manifest-malformed",
              "unsupported schemaVersion %r" % (
                  manifest["schemaVersion"],))
    if not isinstance(manifest["blobs"], list):
        _fail("artifact-manifest-malformed",
              "manifest blobs must be a list")
    if not isinstance(manifest["annotations"], dict):
        _fail("artifact-manifest-malformed",
              "manifest annotations must be a dict")
    for entry in manifest["blobs"]:
        if not isinstance(entry, dict):
            _fail("artifact-manifest-malformed",
                  "blob entry must be a dict")
        for key in ("name", "digest", "size", "mediaType"):
            if key not in entry:
                _fail("artifact-manifest-malformed",
                      "blob entry missing key %r" % (key,))
        _check_blob_name(entry["name"])
        if not isinstance(entry["digest"], str) or not _DIGEST_RE.match(
                entry["digest"]):
            _fail("artifact-manifest-malformed",
                  "blob %r has a malformed digest" % (entry["name"],))
        if not isinstance(entry["size"], int) or entry["size"] < 0:
            _fail("artifact-manifest-malformed",
                  "blob %r has a malformed size" % (entry["name"],))
        if not isinstance(entry["mediaType"], str):
            _fail("artifact-manifest-malformed",
                  "blob %r has a malformed mediaType"
                  % (entry["name"],))


def verify(manifest, blobs, expected_digest):
    """Verify an artifact package fail-closed. Returns True.

    Checks, in order: manifest shape, artifactType known, manifest
    digest matches ``expected_digest``, every listed blob present with
    matching size and digest, no unlisted blobs. Any failure raises
    ArtifactPackError with the taxonomy code.
    """
    _check_manifest_shape(manifest)
    artifact_type = manifest["artifactType"]
    if artifact_type not in KNOWN_ARTIFACT_TYPES:
        _fail("artifact-type-unknown",
              "unknown artifactType %r" % (artifact_type,))
    if not isinstance(expected_digest, str) or not _DIGEST_RE.match(
            expected_digest):
        _fail("artifact-manifest-tampered",
              "expected digest is not a well-formed sha256 digest")
    if manifest_digest(manifest) != expected_digest:
        _fail("artifact-manifest-tampered",
              "manifest digest does not match; the manifest was "
              "altered after packing")
    if not isinstance(blobs, dict):
        _fail("artifact-manifest-malformed",
              "blobs must be a name->bytes dict")
    for name, data in blobs.items():
        _check_blob_name(name)
        if not isinstance(data, bytes):
            _fail("artifact-manifest-malformed",
                  "blob %r must be bytes" % (name,))
    listed = {}
    for entry in manifest["blobs"]:
        name = entry["name"]
        if name in listed:
            _fail("artifact-manifest-malformed",
                  "duplicate blob entry %r" % (name,))
        listed[name] = entry
        if name not in blobs:
            _fail("artifact-blob-missing",
                  "manifest lists blob %r which was not provided"
                  % (name,))
        data = blobs[name]
        if len(data) != entry["size"]:
            _fail("artifact-size-mismatch",
                  "blob %r: manifest size %d != %d bytes provided"
                  % (name, entry["size"], len(data)))
        if _blob_digest(data) != entry["digest"]:
            _fail("artifact-blob-tampered",
                  "blob %r digest mismatch: content altered after "
                  "packing" % (name,))
    for name in blobs:
        if name not in listed:
            _fail("artifact-blob-extra",
                  "blob %r provided but not listed in the manifest"
                  % (name,))
    return True


def unpack(manifest, blobs, expected_digest):
    """Verify then return a copy of the blob dict."""
    verify(manifest, blobs, expected_digest)
    return dict(blobs)


def pack_evidence_records(records, annotations=None):
    """Wire fn: pack a list of evidence record dicts.

    Standalone: records are serialized to canonical JSON here; this
    does not import the evidence-bundle module. Blob names are
    ``record-%04d.json`` in record order.
    """
    if not isinstance(records, list):
        _fail("artifact-manifest-malformed",
              "records must be a list of dicts")
    blobs = {}
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            _fail("artifact-manifest-malformed",
                  "record %d must be a dict" % (i,))
        blobs["record-%04d.json" % i] = _canonical_bytes(rec)
    return pack(blobs, ARTIFACT_TYPE_EVIDENCE_BUNDLE,
                annotations=annotations,
                media_types={n: "application/json" for n in blobs})


def unpack_evidence_records(manifest, blobs, expected_digest):
    """Verify then return the evidence records in blob order."""
    verify(manifest, blobs, expected_digest)
    records = []
    for entry in sorted(manifest["blobs"],
                        key=lambda e: e["name"]):
        try:
            rec = json.loads(
                blobs[entry["name"]].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            _fail("artifact-blob-tampered",
                  "blob %r is not valid JSON" % (entry["name"],))
        if not isinstance(rec, dict):
            _fail("artifact-blob-tampered",
                  "blob %r does not decode to a record dict"
                  % (entry["name"],))
        records.append(rec)
    return records


def pack_skill_files(files, annotations=None, media_types=None):
    """Wire fn: pack a skill's file tree (name -> bytes)."""
    return pack(files, ARTIFACT_TYPE_SKILL_BUNDLE,
                annotations=annotations, media_types=media_types)
