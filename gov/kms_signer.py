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
