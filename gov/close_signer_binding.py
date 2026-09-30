"""Close-record signer binding (wave-236).

A chain's close record is the artifact that seals a session: it states
what the chain contained and who sealed it. This module pins the close
record's signer to the chain-root SESSION-START signer -- the signer
identity of the chain's first record -- and refuses, by name, every
way of slipping a different signer, a re-pointed trust id, or an
unsigned scope claim past the verifier.

The seven machine refusals:

* ``close-signer-mismatch`` -- the close record's signer id differs
  from the session-start signer id. Named with the expected vs
  observed ids. This holds EVEN when the different key is listed in
  the external trust root: being a known key is not being the
  session's key. A rewritten receipt re-presented under a different
  signer fails here, naming the mismatch.
* ``close-trust-repointed`` -- the close record re-points a trust id:
  the same key-id label, but key material that differs from what the
  external trust root pins. The pinning semantics are reused
  additively from ``gov.trust_material`` (imported, not
  re-implemented); only the refusal code is chain-specific.
* ``close-unsigned-scope`` -- verification was asked to rely on a
  scope/authority field outside the close record's signature-covered
  body. Unsigned scope claims are NEVER consulted: the verifier
  refuses fail-closed instead of silently accepting or silently
  ignoring them. The coverage check is ``trust_material``'s
  ``assert_signature_covered``; the code name is the chain seam's.
* ``close-chain-digest-mismatch`` -- the close record's ``chain_digest``
  does not match the digest recomputed over the chain's per-record
  digests. Rewriting any chain record (byte-different, semantically
  equal or not) breaks this binding by construction: the close record
  commits to the chain bytes, never to a re-serialization.
* ``close-record-malformed`` -- the chain or the close record is not
  a well-formed record mapping, a record lacks its digest, or a
  digest is not 64 lowercase hex. Shape violations are refusals,
  never silent skips.
* ``close-signer-absent`` -- the chain's first record carries no
  signer identity, so no session-start signer can be pinned. A chain
  without signer identity cannot be bound; the verifier refuses
  rather than binding to nothing.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads. The module operates on plain record mappings; the
``adapt_log_entries`` adapter maps ``gov.log`` entry dicts onto the
same shape.

* ``close-signature-invalid`` -- with a trust root present, the
  close record's ``ed_sig`` fails Ed25519 verification against the
  PINNED key material from the root. A forged close record that
  merely claims the session signer's id refuses here: the "signed
  by" in the threat model is authenticated, not asserted. Missing
  or malformed ``ed_sig`` with a root present refuses
  ``close-record-malformed``.

What this does NOT do (honest boundaries):
- It does not verify the CHAIN's own entry signatures. The records
  it consumes are the verifier's already-verified observations (e.g.
  the records ``gov.log`` verified on read); this module checks that
  the close record is consistent with them, not that they are
  authentic.
- Without a trust root, the close record's ``ed_sig`` cannot be
  authenticated against anything the verifier trusts: the signer-id
  comparison is then a self-asserted consistency check only. Pass a
  trust root to get real authentication (``close-signature-invalid``
  on forgery). The deployment owns the root-pinning decision, and
  this module documents that residual rather than forcing a breaking
  change. Likewise the ``gov.log`` wiring is opt-in
  (``require_close_binding=False``).
- The session-start signer is the chain's FIRST record by position.
  A chain whose first record is unsigned while later records are
  signed fails closed with ``close-signer-absent``: the binding is
  strict about position, not "first signed record", so a leading
  unsigned record cannot be quietly skipped past.
- Trust-root binding is opt-in (``trust_root=None`` skips it): the
  deployment owns the root-pinning decision, and this module
  documents that residual rather than forcing a breaking change.
  Likewise the ``gov.log`` wiring is opt-in
  (``require_close_binding=False``).
"""

import hashlib
import hmac
import json

from gov import ed25519 as _ed25519

from gov import trust_material as _tm

CLOSE_SIGNER_MISMATCH = "close-signer-mismatch"
CLOSE_TRUST_REPOINTED = "close-trust-repointed"
CLOSE_UNSIGNED_SCOPE = "close-unsigned-scope"
CLOSE_CHAIN_DIGEST_MISMATCH = "close-chain-digest-mismatch"
CLOSE_RECORD_MALFORMED = "close-record-malformed"
CLOSE_SIGNER_ABSENT = "close-signer-absent"
CLOSE_SIGNATURE_INVALID = "close-signature-invalid"

#: Domain separation for the close-record signature body.
_CLOSE_SIG_DOMAIN = b"gov-close-record-sig/v1\x00"

_DIGEST_CHARS = frozenset("0123456789abcdef")


class CloseSignerBindingError(Exception):
    """A close-binding refusal carrying a machine taxonomy code.

    ``code`` is one of the module-level constants above; ``detail``
    is a human sentence. The base exception carries no product
    vocabulary beyond the named refusal (wave-232 lane-A lesson).
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s: %s" % (code, detail) if detail else code)


def _is_digest_shape(value):
    return (isinstance(value, str) and len(value) == 64
            and all(ch in _DIGEST_CHARS for ch in value))


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _require_records(records):
    """Shared chain pre-check: a non-empty list of record mappings."""
    if not isinstance(records, (list, tuple)) or not records:
        raise CloseSignerBindingError(
            CLOSE_RECORD_MALFORMED,
            "chain must be a non-empty list of record mappings")
    return records


def canonical_chain_digest(records):
    """Digest identity of a chain: sha256 over the canonical JSON list
    of the chain's per-record digests, in order.

    The close record commits to this value. Because the commitment is
    over the per-record digests (themselves over record bytes), any
    rewrite of any chain record -- byte-different or re-encoded --
    changes this digest and breaks the close binding by construction.
    Malformed records refuse ``close-record-malformed``.
    """
    records = _require_records(records)
    digests = []
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise CloseSignerBindingError(
                CLOSE_RECORD_MALFORMED,
                "chain record %d is not a mapping" % (idx,))
        digest = rec.get("digest")
        if not _is_digest_shape(digest):
            raise CloseSignerBindingError(
                CLOSE_RECORD_MALFORMED,
                "chain record %d carries no well-formed digest" % (idx,))
        digests.append(digest)
    return hashlib.sha256(_canonical_bytes(digests)).hexdigest()


def session_start_signer(records):
    """The chain-root session-start signer: the FIRST record's signer id.

    Strict about position: a missing or empty signer id on the first
    record refuses ``close-signer-absent`` -- the verifier binds to
    nothing rather than skipping to a later signed record.
    """
    first = _require_records(records)[0]
    if not isinstance(first, dict):
        raise CloseSignerBindingError(
            CLOSE_RECORD_MALFORMED,
            "chain record 0 is not a mapping")
    signer = first.get("signer_id")
    if not isinstance(signer, str) or not signer:
        raise CloseSignerBindingError(
            CLOSE_SIGNER_ABSENT,
            "chain record 0 carries no signer identity; no "
            "session-start signer can be pinned")
    return signer


def _check_close_shape(close_record):
    if not isinstance(close_record, dict):
        raise CloseSignerBindingError(
            CLOSE_RECORD_MALFORMED,
            "close record must be a mapping")
    signer = close_record.get("signer_id")
    if not isinstance(signer, str) or not signer:
        raise CloseSignerBindingError(
            CLOSE_RECORD_MALFORMED,
            "close record carries no signer_id")
    claimed = close_record.get("chain_digest")
    if not _is_digest_shape(claimed):
        raise CloseSignerBindingError(
            CLOSE_RECORD_MALFORMED,
            "close record carries no well-formed chain_digest")
    return signer, claimed


def verify_close_record(chain, close_record, trust_root=None,
                        relied_scope_fields=()):
    """Verify a close record against its chain.

    ``chain`` is a non-empty list of record mappings (``signer_id``,
    ``digest``; see ``adapt_log_entries`` for the ``gov.log`` shape).
    ``close_record`` carries ``signer_id``, ``chain_digest``,
    ``signed_fields`` and, when ``trust_root`` is given,
    ``key_material``.

    Checks, in order (each refuses, none is skipped):

    1. Shape: malformed chain/close record -> ``close-record-malformed``.
    2. Chain binding: ``close_record["chain_digest"]`` must equal
       ``canonical_chain_digest(chain)`` -> else
       ``close-chain-digest-mismatch``.
    3. Signer binding: the close signer must equal the session-start
       signer -> else ``close-signer-mismatch`` (names expected vs
       observed). Listing in the trust root does not excuse a
       different signer.
    4. Trust binding (only when ``trust_root`` is given): the close
       record's (signer id, key material) is bound through the
       external root. A re-pointed trust id refuses
       ``close-trust-repointed``; an unpinned key id refuses
       ``untrusted-key`` (the ``trust_material`` code, reused
       verbatim: the semantics are identical). Then the close
       record's ``ed_sig`` is verified with the PINNED key material
       from the root -- a forged close record that merely claims the
       session signer's id refuses ``close-signature-invalid``. The
       signature is verified with the root's material, never the
       record's own claim. Without a trust root this step is skipped
       and the signer comparison stays a self-asserted consistency
       check (documented residual).
    5. Scope reliance: every field in ``relied_scope_fields`` must be
       inside the close record's ``signed_fields`` -> else
       ``close-unsigned-scope``, fail closed.

    Returns a verdict mapping with ``ok=True`` plus the keys
    ``session_start_signer``, ``close_signer``, and ``chain_digest``
    on success. Never returns ``ok=True`` on an unverified close
    record; never raises on a well-formed refusal -- refusals ARE the
    return path, as ``CloseSignerBindingError``.
    """
    signer, claimed = _check_close_shape(close_record)
    expected_digest = canonical_chain_digest(chain)
    if not _constant_time_eq(claimed, expected_digest):
        raise CloseSignerBindingError(
            CLOSE_CHAIN_DIGEST_MISMATCH,
            "close record commits to chain digest %s but the chain "
            "recomputes to %s; a chain record was rewritten"
            % (claimed, expected_digest))
    start_signer = session_start_signer(chain)
    if signer != start_signer:
        raise CloseSignerBindingError(
            CLOSE_SIGNER_MISMATCH,
            "close record signer %r != session-start signer %r; the "
            "close record was not sealed by the session's key"
            % (signer, start_signer))
    if trust_root is not None:
        try:
            pinned = trust_root.bind_authority(
                signer, close_record.get("key_material"))
        except _tm.TrustMaterialError as exc:
            if exc.code == _tm.KEY_REPOINTED:
                raise CloseSignerBindingError(
                    CLOSE_TRUST_REPOINTED,
                    "close record re-points trust id %r: the label is "
                    "pinned but the record's key material differs from "
                    "the external root's pinned material" % (signer,))
            # untrusted-key and friends keep the trust_material code:
            # identical semantics, no renaming.
            raise CloseSignerBindingError(exc.code, exc.detail)
        # Authenticate the close record's signature with the PINNED
        # material -- never the record's own claim. ed25519.verify is
        # fail-closed (False on any malformed input).
        sig = _normalize_close_sig(close_record.get("ed_sig"))
        if not _ed25519.verify(pinned, close_sig_body(close_record), sig):
            raise CloseSignerBindingError(
                CLOSE_SIGNATURE_INVALID,
                "close record signature fails against the trust root's "
                "pinned material for %r; the record's signer id is "
                "claimed, not authenticated" % (signer,))
    signed_fields = close_record.get("signed_fields", ())
    for field in (relied_scope_fields or ()):
        try:
            _tm.assert_signature_covered(signed_fields, field)
        except _tm.TrustMaterialError as exc:
            raise CloseSignerBindingError(
                CLOSE_UNSIGNED_SCOPE,
                "refusing to rely on %r: %s" % (field, exc.detail))
    return {
        "ok": True,
        "session_start_signer": start_signer,
        "close_signer": signer,
        "chain_digest": expected_digest,
    }


def _constant_time_eq(a, b):
    if not (isinstance(a, str) and isinstance(b, str)):
        return False
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _normalize_close_sig(ed_sig):
    """The close record's ``ed_sig`` as 64 raw bytes.

    Accepts raw 64 bytes or 128 hex chars; anything else refuses
    ``close-record-malformed``.
    """
    if isinstance(ed_sig, (bytes, bytearray)) and len(ed_sig) == 64:
        return bytes(ed_sig)
    if isinstance(ed_sig, str) and len(ed_sig) == 128:
        try:
            return bytes.fromhex(ed_sig)
        except ValueError:
            pass
    raise CloseSignerBindingError(
        CLOSE_RECORD_MALFORMED,
        "close record carries no well-formed ed_sig (64 raw bytes "
        "or 128 hex chars)")


def close_sig_body(close_record):
    """Bytes the close record's Ed25519 signature covers.

    Domain-separated canonical JSON over the record's claims:
    ``signer_id``, the key material as hex, ``chain_digest``, and the
    declared ``signed_fields``. ``ed_sig`` itself is never covered.
    """
    material = close_record.get("key_material")
    if isinstance(material, (bytes, bytearray)):
        material_hex = bytes(material).hex()
    elif isinstance(material, str):
        material_hex = material
    else:
        raise CloseSignerBindingError(
            CLOSE_RECORD_MALFORMED,
            "close record carries no key material for the sig body")
    body = {
        "signer_id": close_record.get("signer_id"),
        "key_material": material_hex,
        "chain_digest": close_record.get("chain_digest"),
        "signed_fields": list(close_record.get("signed_fields", ())),
    }
    return _CLOSE_SIG_DOMAIN + _canonical_bytes(body)


def adapt_log_entries(entries):
    """Adapt ``gov.log`` entry dicts to close-binding records.

    ``signer_id`` is the entry's ``sig_key_id`` (countersigned
    receipts); plain HMAC entries carry no signer identity, so their
    adapted records carry ``signer_id=None`` and the binding fails
    closed with ``close-signer-absent`` -- documented, never silently
    bound. ``digest`` is the entry's chain ``hash`` when present,
    else the sha256 of the entry's canonical JSON. ``key_material``
    is None (log entries do not carry raw key material).
    ``signed_fields`` mirrors the ed_sig-covered body: every entry
    key except the chain ``hash`` and the sig envelope fields
    (``ed_sig``, ``sig_key_id``, ``sig_key_version``), matching
    ``gov.log._canonical``.
    """
    from gov import log as _log  # local: gov.log never imports this module
    envelope = _log._SIG_ENVELOPE_FIELDS | frozenset({"hash"})
    adapted = []
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CloseSignerBindingError(
                CLOSE_RECORD_MALFORMED,
                "log entry %d is not a mapping" % (idx,))
        digest = entry.get("hash")
        if not _is_digest_shape(digest):
            digest = hashlib.sha256(
                _canonical_bytes(entry)).hexdigest()
        signed_fields = tuple(sorted(
            k for k in entry.keys() if k not in envelope))
        adapted.append({
            "signer_id": entry.get("sig_key_id"),
            "digest": digest,
            "key_material": None,
            "signed_fields": signed_fields,
        })
    return adapted
