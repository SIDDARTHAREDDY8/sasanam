"""Sign-vs-deploy namespace separation (wave-207, Harbor ADAPT).

The Harbor signed-only pattern, reimplemented stdlib-only (Apache-2.0
behavior steal, nothing vendored -- wave-205 prospecting §4):

* "Signed-only" is project policy + **deployment admission**, not
  registry refusal. The registry *records* trust state; the *admission
  point* enforces it. Here the admission point is
  :meth:`NamespaceRegistry.admit_deploy` -- the load/deploy seam.
* The goharbor#22650 lesson: a naive "block all unsigned reads"
  middleware breaks the **signing** operation itself. So signing lives
  in a separate **staging** namespace from the **enforced** namespace.
  Enforcement never bricks signing: staging accepts, signs, and
  promotes; only the enforced namespace refuses unsigned content.
* **Digest-pinned references everywhere.** Production admission uses
  ``sha256:<64-hex>`` pins, never names -- a bare name (or a 40-hex
  git SHA, which is a *reference*, not a digest -- the Plugin4Shell
  lesson) is refused at the enforced seam.

Model
-----

* ``STAGING`` -- bundles are built and signed here. Unsigned content
  may ENTER staging but is loudly labeled ``UNSIGNED`` and can never
  reach enforced.
* ``ENFORCED`` -- the deploy source. Admission requires: a
  digest-pinned reference, a promoted (signed) record, a fresh
  signature re-verification against the pinned verifiers at threshold,
  and a content re-hash matching the pin. Anything else is refused
  loudly -- never silently, never truncated.
* Promotion ``staging -> enforced`` is an audited ceremony: a complete
  valid signature chain over the bundle (DSSE envelope binding
  ``{name, digest}`` with the payload type inside the signed PAE bytes)
  **plus two distinct operator identities** (the repo's standing
  two-operator discipline).
* Every mutation is a hash-chained audit entry (``prev`` links).

The enforced namespace records provenance: which key ids signed
(``signed_by``) and which operators promoted (``promoted_by``) -- the
minimal-identity discipline (scoped identities, not admin).

$0 spend, stdlib-only, no network. Signatures use the product's
Ed25519 via ``gov.dsse_envelope`` (PAE binds the payload type).
"""

import hashlib
import json

from .dsse_envelope import (
    EnvelopeError,
    open_envelope,
    parse_envelope,
    seal,
)

__all__ = [
    "STAGING",
    "ENFORCED",
    "BUNDLE_PAYLOAD_TYPE",
    "NamespaceError",
    "NamespaceRegistry",
]

#: The two namespaces. Deployments come only from ENFORCED.
STAGING = "staging"
ENFORCED = "enforced"

#: Payload type bound into the DSSE PAE bytes: a type-swap on the
#: signature path breaks the signature (wave-204 DSSE lane).
BUNDLE_PAYLOAD_TYPE = "application/vnd.sasanam.bundle/v1"

_DIGEST_PREFIX = "sha256:"
_HEX64_RE_CHARS = set("0123456789abcdef")


class NamespaceError(ValueError):
    """Fail-closed namespace violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(NamespaceError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _check_name(name, where="name"):
    if isinstance(name, bool) or not isinstance(name, str) or not name:
        raise NamespaceError("bad-format",
                             "%s must be a non-empty str" % where)
    return name


def _check_digest_ref(reference):
    """A reference is a pin, never a name: ``sha256:<64-hex>``.

    Bare names, tags, and 40-hex git SHAs (references, not digests --
    the Plugin4Shell lesson) are refused as ``reference-not-digest``.
    """
    if (isinstance(reference, bool) or not isinstance(reference, str)
            or not reference.startswith(_DIGEST_PREFIX)):
        raise NamespaceError("reference-not-digest",
                             "enforced admission requires a digest pin "
                             "(sha256:<64-hex>), got %r" % (reference,))
    hexpart = reference[len(_DIGEST_PREFIX):]
    if len(hexpart) != 64 or set(hexpart) - _HEX64_RE_CHARS:
        raise NamespaceError("reference-not-digest",
                             "malformed digest pin: %r" % (reference,))
    return reference


def _check_operators(operator_ids):
    """Two-operator ceremony: at least two distinct, non-empty,
    non-bool operator identities."""
    if isinstance(operator_ids, bool) or not isinstance(operator_ids, list):
        raise NamespaceError("ceremony-refused",
                             "operator_ids must be a list of at least two "
                             "distinct operator identities")
    cleaned = []
    for op in operator_ids:
        if isinstance(op, bool) or not isinstance(op, str) or not op.strip():
            raise NamespaceError("ceremony-refused",
                                 "operator identities must be non-empty "
                                 "strings, got %r" % (op,))
        cleaned.append(op.strip())
    if len(set(cleaned)) < 2:
        raise NamespaceError("ceremony-refused",
                             "promotion requires at least two DISTINCT "
                             "operators")
    return cleaned


def _statement_bytes(name, digest):
    """The bytes the DSSE envelope signs: canonical JSON binding the
    bundle name to its digest. The payload type is bound separately by
    the PAE construction."""
    return json.dumps({"digest": digest, "name": name},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _audit_hash(entry):
    body = json.dumps({k: entry[k] for k in sorted(entry)
                       if k != "entry_hash"},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


class NamespaceRegistry(object):
    """The trust-state registry for the two namespaces.

    The registry *records*; :meth:`admit_deploy` *enforces*. Signing
    verifiers are pinned at construction and re-checked at every
    promotion and every admission -- trust is never cached from an
    earlier check.
    """

    def __init__(self, *, verifiers, threshold=1):
        verifiers = list(verifiers or [])
        if not verifiers:
            raise NamespaceError("bad-format",
                                 "at least one pinned verifier is required")
        for v in verifiers:
            if not (hasattr(v, "key_id") and hasattr(v, "verify")):
                raise NamespaceError("bad-format",
                                     "verifiers must expose key_id + verify")
        if isinstance(threshold, bool) or not isinstance(threshold, int) \
                or not 1 <= threshold <= len(verifiers):
            raise NamespaceError("bad-format",
                                 "threshold must satisfy 1 <= k <= %d"
                                 % len(verifiers))
        self._verifiers = verifiers
        self._threshold = threshold
        self._staging = {}    # name -> record
        self._enforced = {}   # digest pin -> record
        self.audit = []
        self._log("registry-created",
                  "threshold=%d verifiers=%d" % (threshold, len(verifiers)))

    # -- audit ---------------------------------------------------------
    def _log(self, op, detail, name="", digest=""):
        prev = self.audit[-1]["entry_hash"] if self.audit else "GENESIS"
        entry = {"seq": len(self.audit), "op": op, "name": name,
                 "digest": digest, "detail": detail, "prev": prev}
        entry["entry_hash"] = _audit_hash(entry)
        self.audit.append(entry)

    # -- staging --------------------------------------------------------
    def stage(self, name, content):
        """Enter a bundle into the staging namespace.

        Unsigned content is accepted -- staging is the workspace where
        signing happens -- but the record is loudly labeled UNSIGNED
        and can never be promoted or admitted until signed.
        """
        _check_name(name)
        if not isinstance(content, (bytes, bytearray)):
            raise NamespaceError("bad-format", "content must be bytes")
        content = bytes(content)
        digest = _DIGEST_PREFIX + hashlib.sha256(content).hexdigest()
        record = {
            "name": name,
            "digest": digest,
            "content": content,
            "envelope": None,
            "status": "unsigned",
            "label": ("UNSIGNED -- this bundle has no signature and may "
                      "never enter the enforced namespace"),
        }
        self._staging[name] = record
        self._log("staged", record["label"], name=name, digest=digest)
        return dict(record, content=bytes(content))

    def staging_label(self, name):
        """The loud trust label of a staged bundle."""
        _check_name(name)
        record = self._staging.get(name)
        if record is None:
            raise NamespaceError("unknown-bundle",
                                 "no staged bundle named %r" % (name,))
        return record["label"]

    # -- signing ---------------------------------------------------------
    def sign(self, name, signers):
        """Sign a staged bundle: DSSE envelope over the canonical
        ``{name, digest}`` statement. The signature binds the bundle's
        digest -- swapping the bytes afterwards breaks admission."""
        _check_name(name)
        record = self._staging.get(name)
        if record is None:
            raise NamespaceError("unknown-bundle",
                                 "no staged bundle named %r" % (name,))
        signers = list(signers or [])
        if not signers:
            raise NamespaceError("bad-format",
                                 "at least one signer is required")
        for s in signers:
            if not (hasattr(s, "key_id") and hasattr(s, "sign")):
                raise NamespaceError("bad-format",
                                     "signers must expose key_id + sign")
        statement = _statement_bytes(name, record["digest"])
        try:
            envelope = seal(statement, BUNDLE_PAYLOAD_TYPE, signers)
        except EnvelopeError as exc:
            raise NamespaceError("bad-signature",
                                 "sealing failed: %s" % exc)
        record["envelope"] = envelope
        record["status"] = "signed"
        record["label"] = ("SIGNED (staging) -- not yet promoted; "
                           "admission to enforced requires the "
                           "two-operator promotion ceremony")
        self._log("signed", "envelope sealed by %d signer(s)"
                  % len(signers), name=name, digest=record["digest"])
        return dict(record, content=bytes(record["content"]))

    def _verify_envelope(self, record):
        """Fresh signature verification against the pinned verifiers.

        Re-parses the envelope, re-binds the statement to the record's
        CURRENT bytes (a swap between sign and now is refused), and
        checks the signature threshold. Returns the verified key ids.
        """
        envelope = record.get("envelope")
        if envelope is None:
            raise NamespaceError("unsigned-refused",
                                 "bundle %r is unsigned: it may not enter "
                                 "the enforced namespace" % record["name"])
        try:
            payload, _ptype, _sigs = parse_envelope(envelope)
        except EnvelopeError as exc:
            raise NamespaceError("bad-format",
                                 "envelope does not parse: %s" % exc)
        try:
            statement = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise NamespaceError("bad-format",
                                 "envelope payload is not JSON: %s" % exc)
        # The signature must cover THIS record's bytes *as they are
        # now*: the digest is re-derived from the current content, never
        # trusted from the record. A content swap between sign() and now
        # breaks the binding loudly.
        current_digest = (_DIGEST_PREFIX
                          + hashlib.sha256(record["content"]).hexdigest())
        expected = _statement_bytes(record["name"], current_digest)
        if payload != expected:
            raise NamespaceError("digest-mismatch",
                                 "signed statement does not cover the "
                                 "current bundle bytes (content swapped "
                                 "after signing?)")
        try:
            result = open_envelope(envelope, expected, BUNDLE_PAYLOAD_TYPE,
                                   self._verifiers, threshold=self._threshold)
        except EnvelopeError as exc:
            msg = str(exc)
            if "threshold not met" in msg:
                raise NamespaceError("threshold-unmet", msg)
            raise NamespaceError("bad-signature", msg)
        return result["key_ids"]

    # -- promotion ceremony ----------------------------------------------
    def promote(self, name, *, operator_ids):
        """Promote a signed staged bundle into the enforced namespace.

        Requires the two-operator ceremony AND a fresh signature
        verification at threshold. Records provenance: which key ids
        signed (``signed_by``) and which operators promoted
        (``promoted_by``).
        """
        _check_name(name)
        record = self._staging.get(name)
        if record is None:
            raise NamespaceError("unknown-bundle",
                                 "no staged bundle named %r" % (name,))
        operators = _check_operators(operator_ids)
        key_ids = self._verify_envelope(record)
        promoted = dict(record, content=bytes(record["content"]))
        promoted["status"] = "promoted"
        promoted["signed_by"] = list(key_ids)
        promoted["promoted_by"] = list(operators)
        promoted["label"] = "PROMOTED -- admitted to the enforced namespace"
        self._enforced[record["digest"]] = promoted
        self._log("promoted",
                  "signed_by=%s promoted_by=%s"
                  % (",".join(key_ids), ",".join(operators)),
                  name=name, digest=record["digest"])
        return dict(promoted, content=bytes(promoted["content"]))

    # -- admission control (the enforcement point) -------------------------
    def admit_deploy(self, reference, *, namespace=ENFORCED):
        """The deployment admission controller.

        Deploys come ONLY from the enforced namespace. Admission
        requires a digest-pinned reference, a promoted record, a
        content re-hash matching the pin, and a FRESH signature
        re-verification against the pinned verifiers at threshold.
        Trust from promotion time is never reused.
        """
        if namespace == STAGING:
            raise NamespaceError("bad-namespace",
                                 "staging is not a deploy source: sign and "
                                 "promote first, then deploy from enforced")
        if namespace != ENFORCED:
            raise NamespaceError("bad-namespace",
                                 "unknown namespace %r" % (namespace,))
        digest = _check_digest_ref(reference)
        record = self._enforced.get(digest)
        if record is None:
            raise NamespaceError("unknown-bundle",
                                 "no promoted bundle for pin %s: unsigned "
                                 "content is never admitted to enforced"
                                 % digest)
        # Re-hash the exact bytes being handed out (TOCTOU binding).
        actual = _DIGEST_PREFIX + hashlib.sha256(
            record["content"]).hexdigest()
        if actual != digest:
            raise NamespaceError("digest-mismatch",
                                 "stored bytes do not match the pin")
        key_ids = self._verify_envelope(record)
        self._log("admitted", "signed_by=%s" % ",".join(key_ids),
                  name=record["name"], digest=digest)
        return dict(record, content=bytes(record["content"]),
                    signed_by=list(key_ids))
