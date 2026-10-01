"""Content-digest revision binding for replay manifests.

The replay manifest's ``tool_digest_pin`` is verified per-manifest,
but it is never *bound* to the chain revision it executed at: a
replay manifest that pins a different tool digest for the same step
verifies structurally, and nothing in the chain says which digest
belongs to which revision. This module hardens the pin block into a
revision binding:

  - ``PinRegistry.register_revision(revision, manifest)`` builds
    ``(revision, tool_id, seq) -> content_digest`` bindings from a
    sealed manifest. Registration runs the manifest through
    ``replay_manifest.verify_manifest`` FIRST -- a tampered manifest
    is refused at registration, never bound.
  - ``verify_replay(manifest, *, revision, registry)`` checks every
    replayed ``tool_call``'s pin against the binding for that
    revision. A mismatch raises
    ``RevisionBindingError("revbind-content-mismatch")`` -- UNLESS the
    manifest carries an explicit ``content_equivalence`` annotation
    link covering ``(tool_id, bound_digest -> presented_digest)``,
    which is accepted and reported as
    ``revbind-equivalence-accepted`` (advisory; a deployment that
    silently swaps tool content gets no cover).
  - A revision with no binding is reported as ``unbound`` -- loudly,
    never refused. First-run bootstrapping is normal; the absence of
    a binding is information, not a refusal.

The "chain revision" is a deployment label (e.g. ``"rev-7"`` or a
release digest). ``ReplayManifestBuilder(..., chain_revision=...)``
records each tool_call's ``revision_binding: {"revision",
"content_digest"}`` block at record time, so the binding is visible
on the link itself; the registry is the cross-manifest authority.
The recorded ``revision`` is informational provenance -- the
binding check keys on the ``revision`` *argument* passed to
``verify_replay``/``register_revision``, never on the recorded
value (a recorded "rev-7" link verifies silently against a "rev-9"
binding when the digests match the rev-9 binding).

Honest limits (read before citing a revision binding as proof):
  - The binding proves the digest recorded for a step at a revision,
    not that the digest was the *right* tool -- garbage in, garbage
    bound. Equivalence annotations are trust statements, not proofs.
  - ``verify_replay`` trusts the registry contents; registry custody
    is deployment-owned.
  - The binding is per ``(revision, tool_id, seq)``: two steps calling
    the same tool at different digests within one revision each bind
    independently.

Stdlib only. Deterministic.
"""

import hashlib
import json

from gov import replay_manifest as _rm


class RevisionBindingError(Exception):
    """Coded, fail-closed revision-binding error. ``code`` is a
    machine code in the ``revbind`` decision-code domain; ``detail``
    is human text."""

    def __init__(self, code, detail):
        super(RevisionBindingError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _tool_id(link):
    """The link's tool id, or a coded refusal. ``verify_manifest``
    guarantees shape for builder-produced manifests; this is the
    second gate for hand-rolled ones (no uncoded KeyError at the
    public seam)."""
    tool_id = link.get("tool_id")
    if not isinstance(tool_id, str) or not tool_id:
        raise RevisionBindingError(
            "revbind-malformed",
            "link seq %r has no usable tool_id"
            % (link.get("seq"),))
    return tool_id


class PinRegistry(object):
    """Append-only registry of ``(revision, tool_id, seq)`` ->
    content-digest bindings, built from sealed, verified manifests."""

    def __init__(self):
        self._bindings = {}
        self._revisions = []

    def register_revision(self, revision, manifest):
        """Verify the manifest (fail closed), then bind every
        ``tool_call`` pin to ``revision``. Returns the registry
        digest covering the new bindings (audit material)."""
        if not isinstance(revision, str) or not revision:
            raise RevisionBindingError(
                "revbind-malformed",
                "revision must be a non-empty string")
        # Verify FIRST: a tampered manifest is refused at
        # registration, never bound.
        report = _rm.verify_manifest(manifest)
        bound = 0
        for link in manifest["links"]:
            if link.get("action") != _rm.ACTION_TOOL_CALL:
                continue
            tool_id = _tool_id(link)
            seq = link["seq"]
            digest = link["tool_digest_pin"]
            recorded = link.get("revision_binding") or {}
            key = (revision, tool_id, seq)
            self._bindings[key] = {
                "revision": revision,
                "tool_id": tool_id,
                "seq": seq,
                "content_digest": digest,
                "manifest_digest": manifest["manifest_digest"],
                "recorded_revision": recorded.get("revision"),
            }
            bound += 1
        if revision not in self._revisions:
            self._revisions.append(revision)
        return {"registry_digest": _sha256_hex(_canonical(
            sorted((list(k) + [v["content_digest"]]
                    for k, v in self._bindings.items())))),
                "revision": revision,
                "bound": bound,
                "manifest_links": report["links"]}

    def bound(self, revision, tool_id, seq):
        """The binding record for ``(revision, tool_id, seq)``, or
        None when this revision never bound that step."""
        return self._bindings.get((revision, tool_id, seq))

    def revisions(self):
        return list(self._revisions)


def _equivalences_in(manifest):
    """Index the manifest's own content_equivalence annotation links:
    ``(tool_id, from_digest, to_digest)`` -> annotation link."""
    out = {}
    for link in manifest.get("links", []):
        if link.get("action") != _rm.ACTION_CONTENT_EQUIVALENCE:
            continue
        out[(_tool_id(link), link["from_digest"],
             link["to_digest"])] = link
    return out


def verify_replay(manifest, *, revision, registry):
    """Verify a replay manifest against the revision binding.

    For every ``tool_call`` link: the presented pin must equal the
    digest bound for ``(revision, tool_id, seq)``. A mismatch raises
    ``revbind-content-mismatch`` unless the manifest carries an
    explicit ``content_equivalence`` link covering
    ``(tool_id, bound_digest -> presented_digest)`` -- the annotation
    is then accepted and reported (never silent).

    Returns ``{"verified": True, "revision", "held",
    "equivalence_accepted", "unbound", "detail"}``. Unbound steps are
    reported, never refused.
    """
    if not isinstance(revision, str) or not revision:
        raise RevisionBindingError(
            "revbind-malformed",
            "revision must be a non-empty string")
    _rm.verify_manifest(manifest)
    equivalences = _equivalences_in(manifest)
    detail = []
    held = 0
    equivalence_accepted = 0
    unbound = 0
    for link in manifest["links"]:
        if link.get("action") != _rm.ACTION_TOOL_CALL:
            continue
        tool_id = _tool_id(link)
        seq = link["seq"]
        presented = link["tool_digest_pin"]
        binding = registry.bound(revision, tool_id, seq)
        if binding is None:
            unbound += 1
            detail.append({"seq": seq, "tool_id": tool_id,
                           "status": "unbound",
                           "note": "revision %r never bound step "
                                   "(tool_id, seq) = (%r, %d); "
                                   "bootstrapping is normal"
                                   % (revision, tool_id, seq)})
            continue
        expected = binding["content_digest"]
        if presented == expected:
            held += 1
            detail.append({"seq": seq, "tool_id": tool_id,
                           "status": "held"})
            continue
        annotation = equivalences.get((tool_id, expected, presented))
        if annotation is not None:
            equivalence_accepted += 1
            detail.append({"seq": seq, "tool_id": tool_id,
                           "status": "equivalence-accepted",
                           "code": "revbind-equivalence-accepted",
                           "from_digest": expected,
                           "to_digest": presented,
                           "reason": annotation["reason"]})
            continue
        raise RevisionBindingError(
            "revbind-content-mismatch",
            "tool %r seq %d: replay pins content digest %s but "
            "revision %r binds %s; no content-equivalence annotation "
            "covers the change (refusing the replay)"
            % (tool_id, seq, presented[:16], revision,
               expected[:16]))
    return {"verified": True,
            "revision": revision,
            "held": held,
            "equivalence_accepted": equivalence_accepted,
            "unbound": unbound,
            "detail": detail}
