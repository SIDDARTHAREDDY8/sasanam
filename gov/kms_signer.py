#!/usr/bin/env python3
"""KMS-resident signing for evidence records.

ADAPT of the Dex v2.45.0 Vault/OpenBao JWT signer pattern
(re-derived prose; nothing copied): the private key material
NEVER leaves the key-management boundary. ``sign(key_ref,
message)`` runs inside the KMS and returns only signature
bytes; verification happens by algorithm dispatch against the
public key (or the KMS's own key reference).

The central invariant: **a KMS does not upgrade evidence
semantics.** Signing through a KMS changes key custody, not what
the signature means. A MAC-tier key still produces a MAC-tier
receipt — honestly labeled ``non_repudiation=False`` — no matter
how well-guarded the shared key is.

Key references
--------------
``KeyRef`` is a value object: ``{provider, key_id, algorithm}``.
``algorithm`` must name an algorithm in ``gov/alg_registry.py``
(or the registry a signer was built with); anything else
refuses ``kms-signer-algorithm-refused``. The provider is a
non-empty string naming the KMS operator domain (e.g.
``"vault"``, ``"openbao"``, ``"aws-kms"``); the key id is a
non-empty printable identifier.

Error vocabulary (all raised as :class:`KmsSignerError` with a
machine-readable ``code``):

* ``kms-signer-algorithm-refused`` — the key ref's algorithm is
  not registered in the algorithm registry. Fail closed: never
  degrade to a known scheme.
* ``kms-signer-message-too-large`` — the message exceeds
  ``MAX_MESSAGE_BYTES`` (fail closed on unbounded signing
  inputs; a signing path is a DoS surface).
* ``kms-signer-keyref-invalid`` — the key ref is malformed
  (empty provider, empty/bad key id, non-string algorithm).
* ``kms-signer-refused`` — any other KMS-side refusal (backend
  failure, unknown key id). It never carries key material in its
  message.

``KmsSigner`` is the abstract discipline: concrete signers (the
loopback reference in ``gov/kms_signer_loopback.py``, a future
Vault/OpenBao adapter) implement ``sign`` and ``verify`` and
inherit the key-ref validation, message bound, and honest tier
labeling from here. The abstract class cannot sign anything on
its own — there is no default private key anywhere in this
module.

Stdlib only. No network. $0.
"""

import re

# Maximum signing input: 1 MiB. A KMS signing call is a remote
# round trip in production; unbounded inputs are a DoS surface.
MAX_MESSAGE_BYTES = 1 << 20

# Non-empty, printable identifiers; mirroring the key-id discipline
# of gov/kms.py (re-derived here to keep this module standalone).
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


class KmsSignerError(Exception):
    """Base class for KMS-signer refusals. ``code`` is
    machine-readable. Never carries key material."""

    code = "kms-signer-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class KmsSignerAlgorithmError(KmsSignerError):
    """The key ref names an unregistered algorithm — fail closed,
    never degrade to a known scheme."""

    code = "kms-signer-algorithm-refused"


class KmsSignerMessageTooLargeError(KmsSignerError):
    """The message exceeds MAX_MESSAGE_BYTES."""

    code = "kms-signer-message-too-large"


class KmsSignerKeyRefError(KmsSignerError):
    """The key ref is malformed."""

    code = "kms-signer-keyref-invalid"


class SignReceipt:
    """An honestly labeled signing receipt.

    ``sign_labeled`` returns these instead of bare signature bytes
    when the caller needs the evidence semantics attached to the
    signature: ``algorithm`` is the named tier, ``non_repudiation``
    comes from the algorithm registry's tier labeling (a MAC tier
    is False — a KMS does not upgrade a MAC into a signature).
    Receipts are evidence, never authority.
    """

    __slots__ = ("v", "provider", "key_id", "algorithm", "signature",
                 "non_repudiation")

    def __init__(self, provider, key_id, algorithm, signature,
                 non_repudiation):
        self.v = 1
        self.provider = provider
        self.key_id = key_id
        self.algorithm = algorithm
        self.signature = bytes(signature)
        self.non_repudiation = bool(non_repudiation)

    def describe(self):
        """Safe public description — no key material, ever."""
        return {"v": self.v, "provider": self.provider,
                "key_id": self.key_id, "algorithm": self.algorithm,
                "non_repudiation": self.non_repudiation}


class KeyRef:
    """A value object identifying a KMS-resident key:
    ``{provider, key_id, algorithm}``. Never carries key material."""

    __slots__ = ("provider", "key_id", "algorithm")

    def __init__(self, provider, key_id, algorithm):
        if (not isinstance(provider, str) or not provider.strip()
                or not provider.isprintable()):
            raise KmsSignerKeyRefError(
                "kms-signer-keyref-invalid: provider must be a "
                "non-empty printable string")
        if (not isinstance(key_id, str)
                or not _KEY_ID_RE.match(key_id)):
            raise KmsSignerKeyRefError(
                "kms-signer-keyref-invalid: key_id must be a "
                "non-empty identifier")
        if (not isinstance(algorithm, str) or not algorithm):
            raise KmsSignerKeyRefError(
                "kms-signer-keyref-invalid: algorithm must be a "
                "non-empty string")
        self.provider = provider
        self.key_id = key_id
        self.algorithm = algorithm

    def __repr__(self):
        return "KeyRef(provider=%r, key_id=%r, algorithm=%r)" % (
            self.provider, self.key_id, self.algorithm)

    def __eq__(self, other):
        return (isinstance(other, KeyRef)
                and (self.provider, self.key_id, self.algorithm)
                == (other.provider, other.key_id, other.algorithm))

    def __hash__(self):
        return hash((self.provider, self.key_id, self.algorithm))


class KmsSigner:
    """The KMS-resident signing discipline.

    Concrete signers implement ``_backend_sign(key_ref, message)``
    (the private key never leaves the KMS) and ``_public_key_for``
    (returns the public/authentication key for a key ref). The
    public ``sign`` / ``verify`` / ``sign_labeled`` enforce the
    key-ref validation, the message bound, the algorithm dispatch,
    and the honest tier labeling — so no backend can silently
    widen them.
    """

    def __init__(self, registry=None):
        from .alg_registry import default_registry
        self._registry = registry if registry is not None \
            else default_registry()

    # -- key-ref + input validation (shared discipline) ----------------

    def _validate_key_ref(self, key_ref):
        if not isinstance(key_ref, KeyRef):
            raise KmsSignerKeyRefError(
                "kms-signer-keyref-invalid: expected a KeyRef, got %r"
                % type(key_ref).__name__)
        alg = key_ref.algorithm
        if alg not in self._registry.names():
            raise KmsSignerAlgorithmError(
                "kms-signer-algorithm-refused: %r is not a registered "
                "algorithm" % (alg,))
        return key_ref

    @staticmethod
    def _validate_message(message):
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        message = bytes(message)
        if len(message) > MAX_MESSAGE_BYTES:
            raise KmsSignerMessageTooLargeError(
                "kms-signer-message-too-large: %d bytes exceeds the "
                "%d-byte signing bound"
                % (len(message), MAX_MESSAGE_BYTES))
        return message

    # -- backend surface (implemented by concrete signers) -------------

    def _backend_sign(self, key_ref, message):
        """Sign inside the KMS; return raw signature bytes. The
        private key never crosses this boundary."""
        raise NotImplementedError

    def _public_key_for(self, key_ref):
        """The public (or, for MAC tiers, the authentication) key
        for ``key_ref``. For MAC tiers this is the SHARED key —
        callers must treat it as secret."""
        raise NotImplementedError

    # -- public API -----------------------------------------------------

    def _raw_sign(self, key_ref, message):
        """Validate and sign; return the raw signature bytes."""
        self._validate_key_ref(key_ref)
        message = self._validate_message(message)
        sig = self._backend_sign(key_ref, message)
        if not isinstance(sig, (bytes, bytearray)) or not sig:
            raise KmsSignerError(
                "kms-signer-refused: backend returned no signature")
        return message, bytes(sig)

    def sign(self, key_ref, message):
        """Sign ``message`` inside the KMS; return signature bytes.

        Key-ref and message validation happen here; the backend
        supplies only the signing primitive.
        """
        _, sig = self._raw_sign(key_ref, message)
        return sig

    def sign_labeled(self, key_ref, message):
        """Sign and return an honestly labeled :class:`SignReceipt`.

        The ``non_repudiation`` label comes from the algorithm
        registry's tier labeling for the key ref's algorithm: a
        MAC-tier key yields ``False`` — the KMS does not upgrade
        evidence semantics.
        """
        _, sig = self._raw_sign(key_ref, message)
        tier = self._registry.info(key_ref.algorithm)
        return SignReceipt(key_ref.provider, key_ref.key_id,
                           key_ref.algorithm, sig,
                           tier["non_repudiation"])

    def public_key_for(self, key_ref):
        """The public key for ``key_ref`` (metadata, not material).

        For MAC tiers this is the shared authentication key: treat
        it as secret. Never returns private key material.
        """
        self._validate_key_ref(key_ref)
        return self._public_key_for(key_ref)

    def verify(self, key_ref_or_pubkey, message, signature, *,
               algorithm=None):
        """Verify ``signature`` over ``message``.

        ``key_ref_or_pubkey`` is either a :class:`KeyRef` (the
        algorithm is taken from the ref) or raw public key bytes —
        in which case ``algorithm`` is required. Verification
        dispatches through the named algorithm's registry primitive;
        malformed input verifies False (never raises raw), while an
        unknown algorithm refuses ``kms-signer-algorithm-refused``.
        """
        if not isinstance(message, (bytes, bytearray)):
            return False
        if not isinstance(signature, (bytes, bytearray)):
            return False
        if isinstance(key_ref_or_pubkey, KeyRef):
            self._validate_key_ref(key_ref_or_pubkey)
            alg = key_ref_or_pubkey.algorithm
            key_bytes = self._public_key_for(key_ref_or_pubkey)
        else:
            if not isinstance(algorithm, str) or not algorithm:
                raise KmsSignerAlgorithmError(
                    "kms-signer-algorithm-refused: raw public keys "
                    "require a named algorithm")
            if algorithm not in self._registry.names():
                raise KmsSignerAlgorithmError(
                    "kms-signer-algorithm-refused: %r is not a "
                    "registered algorithm" % (algorithm,))
            alg = algorithm
            key_bytes = bytes(key_ref_or_pubkey)
        try:
            return bool(self._registry.verify(alg, bytes(message),
                                              bytes(signature),
                                              key_bytes))
        except Exception:  # noqa: BLE001 - fail closed, never raw
            return False


# ---------------------------------------------------------------------------
# Receipt-signing discipline (W244-5, ADAPT -- pattern only).
#
# Prose re-derived from the wave-243 prospectus description of
# obsigna (Apache-2.0, direct LICENSE read): receipt signing through
# a KMS protocol boundary (their sdk-py-v0.16.0 ``KMSSigner``-in-
# ``sign_receipt()`` pattern), never with keys living in the agent
# process; offline verification from retained bytes +
# consumer-pinned keys (their ``verify_raw`` / ``hash_raw_receipt``
# forward-compat discipline). No upstream code is read, imported,
# or vendored. This section extends the ``KmsSigner`` discipline
# above -- it reuses ``KmsSigner`` / ``KeyRef`` / ``KmsSignerError``
# and duplicates none of them.
#
# The invariant: the signing key is NEVER in-process. ``sign_receipt``
# takes a DECLARED ``KmsSigner`` adapter handle and a ``KeyRef``;
# raw private-key bytes in ANY input path (bytes passed as the
# signer, key material inside a dict, attributes on the handle,
# values in the declaration config -- including env-derived ones)
# refuse ``signer-key-material-in-process``. A declared handle that
# wraps in-process material refuses ``signer-adapter-tampered``
# (this bites our own ``LoopbackKms`` test double, which honestly
# holds keys in-process: it is refused for production receipts).
# Adapter failure or unavailability fails closed
# (``signer-unavailable``) -- there is NO fallback to in-process
# signing, because this module has no in-process signing capability
# to fall back to. The adapter only ever receives canonical bytes.
# Which adapter signed is recorded in ``SIGNING_LEDGER`` (in-memory;
# persistence is deployment-owned), and a receipt verified against
# a different adapter identity refuses ``signer-identity-mismatch``.
#
# Verification is offline from retained bytes with a consumer-pinned
# verifier callable (bool contract: must return exactly True or
# False -- the wave-243 lesson; a non-bool or a raised exception
# fails closed, never verifies).
#
# Error vocabulary (all raised as :class:`KmsSignerError` with a
# machine-readable ``code``):
#
# * ``signer-key-material-in-process`` -- raw private-key bytes in
#   any input path (signer argument, config, env-derived value).
# * ``signer-adapter-tampered`` -- a declared adapter handle that
#   wraps in-process key material.
# * ``signer-unavailable`` -- the adapter could not be used
#   (unreachable, misconfigured, declared-but-unconnected). Fail
#   closed, never falls back. Distinct from ``kms-signer-refused``
#   (the KMS was reachable and declined).
# * ``signer-identity-mismatch`` -- the receipt was signed under a
#   different adapter identity than the one presented for
#   verification.
# * ``signed-receipt-malformed`` -- the receipt or the signed record
#   is not the shape this discipline speaks (includes post-signing
#   mutation, detected via the canonical digest).
# * ``signed-receipt-signature-invalid`` -- the pinned verifier
#   reported False (or violated the bool contract).
#
# Honest boundaries
# -----------------
# * Key-material detection is layered. The name+shape scan (a slot
#   whose NAME suggests key material -- private/secret/seed/... --
#   AND whose VALUE is key-material-shaped: 16-128 raw bytes, a PEM
#   private-key block, or 16-128 bytes of hex/base64) applies to
#   adapter-handle attributes, where incidental bytes are normal
#   and only suggestive names are suspicious. Declaration inputs
#   (the non-handle signer argument, ``signer_from_config``) get an
#   ADDITIONAL shape-only pass: a declaration must never carry
#   key-length bytes under ANY name -- a forger who names their key
#   ``banana`` is still refused ``signer-key-material-in-process``.
#   The discipline is a custody gate for declared adapters, not a
#   memory scanner.
# * ``SIGNING_LEDGER`` is in-memory; distributed audit remains
#   deployment-owned.
# * Declaration (``signer_from_config``) is not connection: a
#   declared adapter is unconnected until the deployment wires a
#   real backend; signing through it refuses ``signer-unavailable``.
# ---------------------------------------------------------------------------

import base64 as _base64
import hashlib as _hashlib
import json as _json

SIGNER_KEY_MATERIAL_IN_PROCESS = "signer-key-material-in-process"
SIGNER_ADAPTER_TAMPERED = "signer-adapter-tampered"
SIGNER_UNAVAILABLE = "signer-unavailable"
SIGNER_IDENTITY_MISMATCH = "signer-identity-mismatch"
SIGNED_RECEIPT_MALFORMED = "signed-receipt-malformed"
SIGNED_RECEIPT_SIGNATURE_INVALID = "signed-receipt-signature-invalid"

# The audit ledger: which adapter signed what. In-memory; the
# deployment owns persistence.
SIGNING_LEDGER = []

# Attribute-name hints for the key-material scan. Name alone is
# never enough: the value must also be key-material-shaped.
_KEY_MATERIAL_NAME_HINTS = ("private", "secret", "seed", "privkey",
                            "key_material", "d_value")

# A raw private seed/key is 16-128 bytes in this repo's registry
# (Ed25519 seeds are 32, HMAC keys 32; the bound is deliberately
# wider than any legitimate key id or nonce).
_MIN_KEY_BYTES = 16
_MAX_KEY_BYTES = 128


def _canonical_receipt_bytes(receipt):
    """Canonical bytes for a receipt (sorted keys, no whitespace)."""
    return _json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")


def _name_suggests_key_material(name):
    lname = str(name).lower()
    return any(hint in lname for hint in _KEY_MATERIAL_NAME_HINTS)


def _value_shaped_like_key_material(value):
    """True when ``value`` is key-material-shaped: raw bytes of key
    length, a PEM private-key block, or hex/base64 decoding to
    key-length bytes."""
    if isinstance(value, (bytes, bytearray)):
        return _MIN_KEY_BYTES <= len(value) <= _MAX_KEY_BYTES
    if isinstance(value, str):
        text = value.strip()
        if "PRIVATE KEY" in text and "-----BEGIN" in text:
            return True
        # Hex or base64 of key-length bytes. Short identifiers
        # (key ids, nonces) fail the decode or the length check.
        for decoder in (lambda s: bytes.fromhex(s),
                        lambda s: _base64.b64decode(s, validate=True)):
            try:
                raw = decoder(text)
            except Exception:  # noqa: BLE001 - not decodable
                continue
            if _MIN_KEY_BYTES <= len(raw) <= _MAX_KEY_BYTES:
                return True
    return False


def _scan_value(name, value, _depth=0, _seen=None):
    """Return the slot name where key material was found, or None.

    A hit is a slot whose NAME suggests key material (private /
    secret / seed / ...) AND whose VALUE is key-material-shaped
    (16-128 raw bytes, a PEM private-key block, or hex/base64
    decoding to key-length bytes). Recurses into dicts, lists, and
    plain data holders (depth <= 2) to catch adapters that nest
    their material one level down. Never descends into
    KmsSigner/registry/transport machinery: those are protocol,
    not adapter state."""
    if _seen is None:
        _seen = set()
    if _name_suggests_key_material(name) and \
            _value_shaped_like_key_material(value):
        return str(name)
    if _depth >= 2 or id(value) in _seen:
        return None
    _seen.add(id(value))
    children = []
    if isinstance(value, dict):
        children = list(value.items())
    elif isinstance(value, (list, tuple)):
        children = list(enumerate(value))
    else:
        cls_name = type(value).__name__
        if "Registry" in cls_name or "Transport" in cls_name \
                or "Provider" in cls_name:
            return None
        children = list(_own_attributes(value))
    for child_name, child_value in children:
        hit = _scan_value(child_name, child_value, _depth + 1, _seen)
        if hit is not None:
            return hit
    return None


def _scan_shape_only(name, value, _depth=0, _seen=None):
    """Return the slot name where key-material-SHAPED data was found,
    or None. Unlike ``_scan_value``, the slot name is irrelevant: a
    declaration input must never carry key-length bytes under ANY
    name. Same recursion shape and machinery skips as the
    name+shape scan."""
    if _seen is None:
        _seen = set()
    if _value_shaped_like_key_material(value):
        return str(name)
    if _depth >= 2 or id(value) in _seen:
        return None
    _seen.add(id(value))
    children = []
    if isinstance(value, dict):
        children = list(value.items())
    elif isinstance(value, (list, tuple)):
        children = list(enumerate(value))
    else:
        cls_name = type(value).__name__
        if "Registry" in cls_name or "Transport" in cls_name \
                or "Provider" in cls_name:
            return None
        for attr_name, attr_value in _own_attributes(value):
            children.append((attr_name, attr_value))
    for child_name, child_value in children:
        hit = _scan_shape_only(child_name, child_value, _depth + 1,
                               _seen)
        if hit is not None:
            return hit
    return None


def _own_attributes(obj):
    """Yield (name, value) for an object's OWN attributes, tolerating
    ``__slots__``-based classes where ``vars()`` raises TypeError."""
    seen = set()
    try:
        own_dict = vars(obj)
    except TypeError:
        own_dict = {}
    for name, value in own_dict.items():
        seen.add(name)
        yield name, value
    for klass in type(obj).__mro__:
        for slot in getattr(klass, "__slots__", ()):
            if slot in seen:
                continue
            seen.add(slot)
            try:
                yield slot, getattr(obj, slot)
            except AttributeError:
                pass


def _refuse_in_process(where, slot):
    raise KmsSignerError(
        "%s: key material in %s (slot %r)" % (
            SIGNER_KEY_MATERIAL_IN_PROCESS, where, slot),
        code=SIGNER_KEY_MATERIAL_IN_PROCESS)


def _refuse_not_a_handle(signer):
    """Refuse a signer argument that is not a declared ``KmsSigner``
    handle. Both scans run so the refusal names wrapped key material
    when it is present; otherwise the refusal names the real
    problem: the input is not a declared adapter handle."""
    hit = _scan_value("signer", signer)
    if hit is None:
        hit = _scan_shape_only("signer", signer)
    if hit is not None:
        _refuse_in_process("signer argument", hit)
    raise KmsSignerError(
        "%s: signer is %s, not a declared KMS adapter handle" % (
            SIGNER_KEY_MATERIAL_IN_PROCESS, type(signer).__name__),
        code=SIGNER_KEY_MATERIAL_IN_PROCESS)


def _check_signer(signer):
    """Validate the declared adapter handle. Returns the handle.

    Anything that is not a declared ``KmsSigner`` refuses
    ``signer-key-material-in-process`` (a raw value presented as a
    signer is key material in the input path; a non-handle that is
    not key material is refused under the same fail-closed code).
    A declared handle whose own attributes wrap in-process material
    refuses ``signer-adapter-tampered``.
    """
    if isinstance(signer, (bytes, bytearray, str)):
        raise KmsSignerError(
            "%s: signer is raw %s, not a declared KMS adapter handle" % (
                SIGNER_KEY_MATERIAL_IN_PROCESS,
                type(signer).__name__),
            code=SIGNER_KEY_MATERIAL_IN_PROCESS)
    if not isinstance(signer, KmsSigner):
        _refuse_not_a_handle(signer)
    # Scan the handle's OWN attributes for wrapped in-process
    # material. LoopbackKms (the test double) is caught here: its
    # provisioned store holds secrets in-process, so it refuses
    # SIGNER_ADAPTER_TAMPERED for production receipts. That is the
    # discipline working, not a special case.
    for attr_name, attr_value in _own_attributes(signer):
        hit = _scan_value(attr_name, attr_value)
        if hit is not None:
            raise KmsSignerError(
                "%s: declared adapter wraps in-process key material "
                "(slot %r)" % (SIGNER_ADAPTER_TAMPERED, hit),
                code=SIGNER_ADAPTER_TAMPERED)
    return signer


def _key_ref_record(key_ref):
    if not isinstance(key_ref, KeyRef):
        raise KmsSignerError(
            "%s: key_ref must be a KeyRef, got %r" % (
                SIGNED_RECEIPT_MALFORMED, type(key_ref).__name__),
            code=SIGNED_RECEIPT_MALFORMED)
    return {"provider": key_ref.provider, "key_id": key_ref.key_id,
            "algorithm": key_ref.algorithm}


def sign_receipt(receipt, signer, key_ref):
    """Sign ``receipt`` through the declared KMS adapter ``signer``.

    The receipt is canonicalized FIRST; the adapter only ever sees
    the canonical bytes. The signed record carries the key ref
    (adapter identity) and the canonical digest; the signing event
    is appended to ``SIGNING_LEDGER``. Any adapter failure fails
    closed with ``signer-unavailable`` -- there is no fallback to
    in-process signing.
    """
    if not isinstance(receipt, dict):
        raise KmsSignerError(
            "%s: receipt must be a dict" % SIGNED_RECEIPT_MALFORMED,
            code=SIGNED_RECEIPT_MALFORMED)
    try:
        canonical = _canonical_receipt_bytes(receipt)
    except (TypeError, ValueError) as exc:
        raise KmsSignerError(
            "%s: receipt is not canonicalizable: %s" % (
                SIGNED_RECEIPT_MALFORMED, type(exc).__name__),
            code=SIGNED_RECEIPT_MALFORMED)
    handle = _check_signer(signer)
    ref_record = _key_ref_record(key_ref)
    try:
        signature = handle.sign(key_ref, canonical)
    except KmsSignerError as exc:
        raise KmsSignerError(
            "%s: KMS adapter failed (%s); failing closed, no fallback" % (
                SIGNER_UNAVAILABLE, exc.code),
            code=SIGNER_UNAVAILABLE)
    except Exception as exc:  # noqa: BLE001 - fail closed, never raw
        # The backend exception message may carry anything; only
        # the exception TYPE crosses into our error.
        raise KmsSignerError(
            "%s: KMS adapter raised %s; failing closed, no fallback" % (
                SIGNER_UNAVAILABLE, type(exc).__name__),
            code=SIGNER_UNAVAILABLE)
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise KmsSignerError(
            "%s: adapter returned no signature; failing closed" % (
                SIGNER_UNAVAILABLE,),
            code=SIGNER_UNAVAILABLE)
    digest = _hashlib.sha256(canonical).hexdigest()
    signed = {"v": 1, "receipt": receipt, "canonical_sha256": digest,
              "key_ref": ref_record, "signature": bytes(signature).hex()}
    SIGNING_LEDGER.append({"provider": ref_record["provider"],
                           "key_id": ref_record["key_id"],
                           "algorithm": ref_record["algorithm"],
                           "canonical_sha256": digest})
    return signed


def verify_signed_receipt(signed, expected_key_ref, verifier):
    """Offline verification from retained bytes + consumer-pinned key.

    Recomputes the canonical digest (post-signing mutation
    refuses), checks the adapter identity against
    ``expected_key_ref`` (mismatch refuses), then calls the
    consumer-pinned ``verifier(canonical_bytes, signature_bytes,
    key_ref_record)``. The verifier's bool contract is enforced:
    exactly True verifies; exactly False -- or any other return,
    or a raised exception -- refuses. Returns the canonical digest
    on success.
    """
    if not isinstance(signed, dict):
        raise KmsSignerError(
            "%s: signed record must be a dict" % SIGNED_RECEIPT_MALFORMED,
            code=SIGNED_RECEIPT_MALFORMED)
    for field in ("v", "receipt", "canonical_sha256", "key_ref",
                  "signature"):
        if field not in signed:
            raise KmsSignerError(
                "%s: signed record missing %r" % (
                    SIGNED_RECEIPT_MALFORMED, field),
                code=SIGNED_RECEIPT_MALFORMED)
    receipt = signed["receipt"]
    if not isinstance(receipt, dict):
        raise KmsSignerError(
            "%s: embedded receipt malformed" % SIGNED_RECEIPT_MALFORMED,
            code=SIGNED_RECEIPT_MALFORMED)
    try:
        canonical = _canonical_receipt_bytes(receipt)
    except (TypeError, ValueError):
        raise KmsSignerError(
            "%s: embedded receipt not canonicalizable" % (
                SIGNED_RECEIPT_MALFORMED,),
            code=SIGNED_RECEIPT_MALFORMED)
    if _hashlib.sha256(canonical).hexdigest() != \
            signed["canonical_sha256"]:
        raise KmsSignerError(
            "%s: canonical digest mismatch -- the receipt was mutated "
            "after signing" % SIGNED_RECEIPT_MALFORMED,
            code=SIGNED_RECEIPT_MALFORMED)
    ref_record = signed["key_ref"]
    if not isinstance(ref_record, dict):
        raise KmsSignerError(
            "%s: key_ref malformed" % SIGNED_RECEIPT_MALFORMED,
            code=SIGNED_RECEIPT_MALFORMED)
    expected = _key_ref_record(expected_key_ref)
    presented = (ref_record.get("provider"), ref_record.get("key_id"),
                 ref_record.get("algorithm"))
    if presented != (expected["provider"], expected["key_id"],
                     expected["algorithm"]):
        raise KmsSignerError(
            "%s: signed under %s/%s/%s, verified against %s/%s/%s" % (
                SIGNER_IDENTITY_MISMATCH,
                ref_record.get("provider"), ref_record.get("key_id"),
                ref_record.get("algorithm"),
                expected["provider"], expected["key_id"],
                expected["algorithm"]),
            code=SIGNER_IDENTITY_MISMATCH)
    try:
        signature = bytes.fromhex(signed["signature"])
    except (ValueError, TypeError, AttributeError):
        raise KmsSignerError(
            "%s: signature not hex" % SIGNED_RECEIPT_MALFORMED,
            code=SIGNED_RECEIPT_MALFORMED)
    try:
        result = verifier(canonical, signature, ref_record)
    except Exception as exc:  # noqa: BLE001 - fail closed, never raw
        raise KmsSignerError(
            "%s: verifier raised %s" % (
                SIGNED_RECEIPT_SIGNATURE_INVALID, type(exc).__name__),
            code=SIGNED_RECEIPT_SIGNATURE_INVALID)
    # Bool contract: exactly True verifies. Exactly False, None, or
    # any other value refuses -- a verifier that cannot say True
    # does not get to say "verified".
    if result is True:
        return signed["canonical_sha256"]
    raise KmsSignerError(
        "%s: pinned verifier did not return True" % (
            SIGNED_RECEIPT_SIGNATURE_INVALID,),
        code=SIGNED_RECEIPT_SIGNATURE_INVALID)


from collections import namedtuple as _namedtuple

_DeclaredIdentity = _namedtuple(
    "_DeclaredIdentity", ["adapter", "key_id", "algorithm"])


class _DeclaredAdapter(KmsSigner):
    """A declared-but-unconnected adapter.

    ``signer_from_config`` returns these: the deployment has
    DECLARED a KMS adapter kind and key id, but no backend is wired
    in this process. Any signing attempt fails closed with
    ``signer-unavailable`` -- declaration is not connection.
    """

    def __init__(self, adapter, key_id, algorithm):
        super(_DeclaredAdapter, self).__init__()
        self._declared = _DeclaredIdentity(adapter, key_id, algorithm)

    def _backend_sign(self, key_ref, message):
        raise KmsSignerError(
            "%s: declared %s adapter for key %r is not connected; "
            "the deployment must wire a real KMS backend" % (
                SIGNER_UNAVAILABLE, self._declared.adapter,
                self._declared.key_id),
            code=SIGNER_UNAVAILABLE)

    def _public_key_for(self, key_ref):
        raise KmsSignerError(
            "%s: declared adapter is not connected" % SIGNER_UNAVAILABLE,
            code=SIGNER_UNAVAILABLE)


def signer_from_config(config):
    """Declare a KMS adapter from operator config (never key bytes).

    ``config`` is a dict like ``{"adapter": "vault-transit",
    "key_id": "k-1", "algorithm": "ed25519"}``. Every value is
    scanned for key-material shapes FIRST -- the name+shape scan
    and a shape-only pass (a declaration must never carry
    key-length bytes under ANY name, including values derived
    from environment variables); any hit refuses
    ``signer-key-material-in-process`` at declaration time.
    Returns a declared-but-unconnected adapter handle; signing
    through it refuses ``signer-unavailable`` until the deployment
    wires a real backend.
    """
    if not isinstance(config, dict):
        raise KmsSignerError(
            "%s: signer config must be a dict" % SIGNED_RECEIPT_MALFORMED,
            code=SIGNED_RECEIPT_MALFORMED)
    hit = _scan_value("config", config)
    if hit is None:
        hit = _scan_shape_only("config", config)
    if hit is not None:
        _refuse_in_process("signer declaration", hit)
    adapter = config.get("adapter")
    if not isinstance(adapter, str) or not adapter.strip():
        raise KmsSignerError(
            "%s: adapter must be a non-empty string" % (
                SIGNED_RECEIPT_MALFORMED,),
            code=SIGNED_RECEIPT_MALFORMED)
    key_id = config.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise KmsSignerError(
            "%s: key_id must be a non-empty string" % (
                SIGNED_RECEIPT_MALFORMED,),
            code=SIGNED_RECEIPT_MALFORMED)
    algorithm = config.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm:
        raise KmsSignerError(
            "%s: algorithm must be named explicitly" % (
                SIGNED_RECEIPT_MALFORMED,),
            code=SIGNED_RECEIPT_MALFORMED)
    return _DeclaredAdapter(adapter.strip(), key_id.strip(),
                            algorithm.strip())
