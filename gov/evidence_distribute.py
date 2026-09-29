"""Evidence distribution over OCI registries (Wave-191 Lane B).

Local-only, stdlib-only. An evidence bundle (see :mod:`gov.evidence_bundle`)
is packed deterministically, pushed as an OCI subject manifest, and the
Decision BOM and the manifest signature ride as same-repository referrers.
The auditor pulls by digest pin -- never by tag mid-audit -- byte-verifies
every fetched blob against its recorded digest, requires the signature
referrer in the referrer graph (a stripped signature is invisible to a
bundle-only verifier), and runs the standalone bundle verifier
(:func:`gov.evidence_verify.verify_bundle`) against operator pins.

The OCI registry client is INJECTED. The product core never imports
oras-py, never opens a socket, and never hand-rolls the registry wire
protocol here -- the client object owns the wire. The required client
protocol (the seam this module depends on)::

    push_blob(repo, data: bytes, media_type: str) -> str
        Content-addressed blob upload. Returns the ``sha256:<hex>`` digest.
    put_manifest(repo, manifest: bytes, tag: str | None) -> str
        Store a manifest document; bind ``tag`` to it when given.
        A manifest carrying a ``subject`` link must become discoverable
        through ``list_referrers`` for that subject (real registries index
        referrers server-side). Returns the ``sha256:<hex>`` digest of the
        exact bytes passed.
    get_manifest(repo, reference: str) -> (dict, str)
        Fetch a manifest by digest (``sha256:...``). Returns the parsed
        manifest and the digest it was stored under.
    pull_blob(repo, digest: str) -> bytes
        Fetch a blob by digest. Must fail when unknown.
    list_referrers(repo, digest: str) -> [dict]
        Referrer manifests for a subject digest. Each entry carries at
        least ``artifactType`` and ``digest``.
    resolve_tag(repo, tag: str) -> str
        Resolve a mutable tag to its current digest. Must fail when the
        tag is unknown. A resolve_tag failure is defined by this
        protocol as "tag unknown": the module treats it as unbound for
        the D5 clobber check. (A genuinely broken registry cannot yield
        a successful push anyway -- every write goes through the
        fail-closed _client_call wrapper.)

Every client failure is converted to :class:`DistributionError`: the
auditor fails closed, never partially. ``requirements.lock`` pins the
gate-test environment; this package is stdlib-only at runtime, so oras-py
is NOT a runtime dependency -- it remains an optional adapter outside
this module.
"""

import hashlib
import io
import json
import os
import tarfile

from . import evidence_verify as _evidence_verify
from .digest_ref import DigestRef


class DistributionError(Exception):
    """Fail-closed error for every distribution/audit failure."""


# ---------------------------------------------------------------------------
# Registry contract: media and artifact types.
# ---------------------------------------------------------------------------
MT_BUNDLE_TAR = "application/vnd.sasanam.evidence-bundle.tar"
MT_BUNDLE_CONFIG = "application/vnd.sasanam.evidence-bundle.config.v1+json"
MT_BOM = "application/vnd.sasanam.decision-bom+json"
MT_SIG = "application/vnd.sasanam.manifest-signature+json"
AT_BOM = "application/vnd.sasanam.decision-bom"
AT_SIG = "application/vnd.sasanam.manifest-signature"

_OCI_MANIFEST_MT = "application/vnd.oci.image.manifest.v1+json"
_HEXDIGITS = frozenset("0123456789abcdef")


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------
def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _digest_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _is_digest(ref):
    return (isinstance(ref, str) and ref.startswith("sha256:")
            and len(ref) == 71
            and all(c in _HEXDIGITS for c in ref[7:]))


def _client_call(desc, fn, *args, **kwargs):
    """Run one client call; convert any failure to DistributionError."""
    try:
        return fn(*args, **kwargs)
    except DistributionError:
        raise
    except Exception as e:  # noqa: BLE001 -- every client failure is fatal
        raise DistributionError("%s: %s" % (desc, e))


# ---------------------------------------------------------------------------
# Packing.
# ---------------------------------------------------------------------------
def pack_bundle(bundle_dir):
    """Deterministic tar of an assembled bundle directory.

    Sorted names, zeroed mtime/uid/gid, empty user/group names, PAX
    format -- the same bytes for the same bundle, every time, so digests
    are reproducible and byte-compare is meaningful.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w",
                      format=tarfile.PAX_FORMAT) as tf:
        for root, dirs, files in os.walk(bundle_dir):
            dirs.sort()
            files.sort()
            for name in files:
                path = os.path.join(root, name)
                arcname = os.path.relpath(path, bundle_dir)
                info = tf.gettarinfo(path, arcname=arcname)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                with open(path, "rb") as fh:
                    tf.addfile(info, fh)
    return buf.getvalue()


def _safe_untar(blob_bytes, outdir):
    """Extract a pulled tar with hostile-member filtering.

    The blob is digest-pinned, but a lying registry (D2) can serve any
    bytes for a digest it answers for -- never trust the member list.
    """
    os.makedirs(outdir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob_bytes), mode="r") as tf:
        for member in tf.getmembers():
            name = member.name
            if (not name or os.path.isabs(name) or ".." in name.split("/")
                    or not member.isfile()):
                raise DistributionError(
                    "refusing to extract hostile tar member: %r" % (name,))
        for member in tf.getmembers():
            target = os.path.join(outdir, member.name)
            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with tf.extractfile(member) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
    return outdir


# ---------------------------------------------------------------------------
# Push path.
# ---------------------------------------------------------------------------
def _subject_manifest(tar_digest, tar_size, config_digest, config_size):
    return {
        "schemaVersion": 2,
        "mediaType": _OCI_MANIFEST_MT,
        "config": {"mediaType": MT_BUNDLE_CONFIG, "digest": config_digest,
                   "size": config_size},
        "layers": [{"mediaType": MT_BUNDLE_TAR, "digest": tar_digest,
                    "size": tar_size}],
        "annotations": {"org.opencontainers.image.title":
                        "evidence-bundle"},
    }


def _require_ref(ref, *, where):
    """Identity positions take :class:`DigestRef`, never ``str``.

    A tag is unrepresentable here by construction: the only way to
    build a DigestRef from a tag-shaped value is
    ``DigestRef.parse``, which refuses it loudly. Accepting ``str``
    would re-admit the tag/digest confusion this module exists to
    kill, so the wrong *kind* of value is a TypeError at the seam,
    not a runtime DistributionError deep inside.
    """
    if not isinstance(ref, DigestRef):
        raise TypeError(
            "%s requires a gov.digest_ref.DigestRef, got %s -- "
            "tags and bare strings are not artifact identity"
            % (where, type(ref).__name__))
    return ref


def push_bundle(bundle_dir, client, repo, tag=None):
    """Push an assembled bundle directory as an OCI subject manifest.

    D5: pushing over a tag that is already bound to a DIFFERENT digest
    is refused loudly -- tags are mutable pointers, never overwrite
    targets. Re-pushing identical bytes to the same tag is idempotent
    and allowed.

    Returns a :class:`DigestRef` (``repo@sha256:<hex>``) -- the pin
    for every later step. The return type is structural: a tag cannot
    be smuggled through the push-then-audit path because the auditor
    seams only accept DigestRef.
    """
    tar_bytes = pack_bundle(bundle_dir)
    config_bytes = _canonical_bytes({"bundle": "evidence-bundle/1.1"})
    manifest_bytes = _canonical_bytes(_subject_manifest(
        _digest_of(tar_bytes), len(tar_bytes),
        _digest_of(config_bytes), len(config_bytes)))
    new_digest = _digest_of(manifest_bytes)

    if tag is not None:
        try:
            existing = client.resolve_tag(repo, tag)
        except Exception:
            existing = None
        if existing is not None and existing != new_digest:
            raise DistributionError(
                "refusing to overwrite tag %r: bound to %s, new bundle "
                "is %s" % (tag, existing, new_digest))

    _client_call("push bundle blob",
                 client.push_blob, repo, tar_bytes, MT_BUNDLE_TAR)
    _client_call("push bundle config",
                 client.push_blob, repo, config_bytes, MT_BUNDLE_CONFIG)
    got = _client_call("put subject manifest",
                       client.put_manifest, repo, manifest_bytes, tag=tag)
    if got != new_digest:
        raise DistributionError(
            "registry returned unexpected manifest digest %r (expected "
            "%r)" % (got, new_digest))
    if tag is not None:
        # Read-your-write: the tag must now resolve to exactly what we
        # pushed; anything else means the registry moved it under us.
        bound = _client_call("re-resolve tag %r" % (tag,),
                             client.resolve_tag, repo, tag)
        if bound != new_digest:
            raise DistributionError(
                "tag %r does not resolve to the pushed bundle %s (got "
                "%s)" % (tag, new_digest, bound))
    # Structural pin: the caller gets a DigestRef, not a string. The
    # auditor path below only accepts DigestRef, so a tag can never
    # flow from push into audit -- it is unrepresentable, not merely
    # checked.
    return DigestRef(repo, new_digest[len("sha256:"):])


def _attach(client, repo, subject, blob_bytes, media_type,
            artifact_type, tag=None):
    """Attach a referrer manifest to a subject digest pin.

    ``subject`` is a :class:`DigestRef` (TypeError otherwise) -- the
    subject of a referrer edge is identity, and a tag there would let
    the edge drift when the tag moves.
    """
    _require_ref(subject, where="attach")
    subject_digest = subject.digest
    blob_digest = _digest_of(blob_bytes)
    config_bytes = _canonical_bytes({"referrer": artifact_type})
    manifest = {
        "schemaVersion": 2,
        "mediaType": _OCI_MANIFEST_MT,
        "artifactType": artifact_type,
        "config": {"mediaType": MT_BUNDLE_CONFIG,
                   "digest": _digest_of(config_bytes),
                   "size": len(config_bytes)},
        "layers": [{"mediaType": media_type, "digest": blob_digest,
                    "size": len(blob_bytes)}],
        "subject": {"mediaType": _OCI_MANIFEST_MT,
                    "digest": subject_digest, "size": 0},
    }
    manifest_bytes = _canonical_bytes(manifest)
    _client_call("push referrer blob",
                 client.push_blob, repo, blob_bytes, media_type)
    _client_call("push referrer config",
                 client.push_blob, repo, config_bytes, MT_BUNDLE_CONFIG)
    return _client_call("put referrer manifest",
                       client.put_manifest, repo, manifest_bytes, tag=tag)


def attach_bom(client, repo, subject, bom_bytes, tag=None):
    """Attach a Decision BOM as a referrer of the subject manifest.

    ``subject`` is a :class:`DigestRef`; a tag is unrepresentable.
    """
    return _attach(client, repo, subject, bom_bytes,
                   MT_BOM, AT_BOM, tag=tag)


def attach_signature(client, repo, subject, sig_bytes, tag=None):
    """Attach a manifest signature as a referrer of the subject manifest.

    ``subject`` is a :class:`DigestRef`; a tag is unrepresentable.
    """
    return _attach(client, repo, subject, sig_bytes,
                   MT_SIG, AT_SIG, tag=tag)


# ---------------------------------------------------------------------------
# Auditor path.
# ---------------------------------------------------------------------------
def resolve_and_pin(client, repo, tag):
    """Resolve a tag to its digest exactly once.

    The returned :class:`DigestRef` is the pin: every later step of
    the audit takes the DigestRef, never the tag, so a tag that moves
    mid-audit (D4) cannot silently switch the bundle under the
    auditor. The tag itself never crosses into the auditor path --
    only the pinned DigestRef does.
    """
    digest = _client_call("resolve tag %r" % (tag,),
                         client.resolve_tag, repo, tag)
    if not _is_digest(digest):
        raise DistributionError(
            "tag %r resolved to a non-digest reference %r" % (tag, digest))
    return DigestRef(repo, digest[len("sha256:"):])


def pull_bundle(client, repo, ref, outdir):
    """Pull a bundle by digest pin into ``outdir``.

    ``ref`` is a :class:`DigestRef` (TypeError otherwise) -- the
    auditor's identity input is structural, not a string that happens
    to look like a digest. A tag is unrepresentable here: there is no
    ``DigestRef`` value for one.

    D2: the registry is not trusted -- every fetched blob is
    byte-compared against the digest recorded in the manifest, and the
    manifest itself is fetched by digest. A lying registry fails closed.
    Tags are never accepted here; resolve with :func:`resolve_and_pin`
    first.
    """
    _require_ref(ref, where="pull_bundle")
    digest = ref.digest
    manifest, resolved = _client_call(
        "fetch subject manifest", client.get_manifest, repo, digest)
    if resolved != digest:
        raise DistributionError(
            "registry returned manifest %r for pinned digest %r"
            % (resolved, digest))
    if not isinstance(manifest, dict):
        raise DistributionError("subject manifest is not an object")
    layers = manifest.get("layers") or []
    if not layers or not isinstance(layers[0], dict):
        raise DistributionError("subject manifest has no layers")
    layer = layers[0]
    if layer.get("mediaType") != MT_BUNDLE_TAR:
        raise DistributionError(
            "unexpected bundle layer media type %r"
            % (layer.get("mediaType"),))
    layer_digest = layer.get("digest")
    if not _is_digest(layer_digest):
        raise DistributionError(
            "bundle layer has no digest: %r" % (layer_digest,))
    blob = _client_call("fetch bundle blob",
                        client.pull_blob, repo, layer_digest)
    if _digest_of(blob) != layer_digest:
        raise DistributionError(
            "bundle bytes do not match pinned digest %s: registry is "
            "lying or corrupt" % (layer_digest,))
    return _safe_untar(blob, outdir)


def audit_bundle(client, repo, ref=None, outdir=None,
                 operator_pins=()):
    """Full auditor workflow for one pinned bundle digest.

    ``ref`` is a :class:`DigestRef` (TypeError otherwise) -- the audit
    is anchored to a structural digest identity, never to a string the
    caller claims is a digest.

    1. Pull by digest pin with byte-compare (:func:`pull_bundle`).
    2. Require the signature referrer in the referrer graph (D1: a
       stripped signature is invisible to a bundle-only verifier), and
       digest-check it -- the referrer manifest must resolve to the
       digest the graph advertised, and its blob must byte-match.
    3. Run the standalone bundle verifier against the operator pins.

    Anything missing, mismatched, or unverifiable raises
    :class:`DistributionError`. Returns a verdict dict on success.
    """
    _require_ref(ref, where="audit_bundle")
    digest = ref.digest
    if not outdir:
        raise DistributionError("audit requires an output directory")
    if not operator_pins:
        raise DistributionError("audit requires operator pins")

    pull_bundle(client, repo, ref, outdir)

    referrers = _client_call("list referrers",
                            client.list_referrers, repo, digest)
    sig_refs = [r for r in referrers
                if isinstance(r, dict) and r.get("artifactType") == AT_SIG]
    if not sig_refs:
        raise DistributionError(
            "no %r referrer for %s: signature stripped or never "
            "attached -- refusing to bless an unsigned bundle"
            % (AT_SIG, digest))
    sig_digest = None
    for ref in sig_refs:
        ref_digest = ref.get("digest")
        if not _is_digest(ref_digest):
            raise DistributionError(
                "signature referrer has no digest: %r" % (ref,))
        manifest, resolved = _client_call(
            "fetch signature referrer manifest",
            client.get_manifest, repo, ref_digest)
        if resolved != ref_digest:
            raise DistributionError(
                "signature referrer manifest digest mismatch: graph "
                "advertised %r, registry served %r"
                % (ref_digest, resolved))
        layers = manifest.get("layers") or []
        if not layers or not isinstance(layers[0], dict):
            raise DistributionError(
                "signature referrer manifest has no layers")
        blob_digest = layers[0].get("digest")
        blob = _client_call("fetch signature blob",
                            client.pull_blob, repo, blob_digest)
        if _digest_of(blob) != blob_digest:
            raise DistributionError(
                "signature blob does not match its recorded digest")
        sig_digest = ref_digest

    bom_digest = None
    for ref in referrers:
        if (isinstance(ref, dict) and ref.get("artifactType") == AT_BOM
                and _is_digest(ref.get("digest"))):
            bom_digest = ref.get("digest")
            break

    code, _checks, _summary = _evidence_verify.verify_bundle(
        outdir, pins=tuple(operator_pins))
    if code != 0:
        raise DistributionError(
            "standalone bundle verification failed (exit %d) for %s"
            % (code, digest))
    return {"digest": digest, "outdir": outdir,
            "signature": sig_digest, "bom": bom_digest,
            "verify_code": code}
