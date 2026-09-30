"""External trust-material bindings (wave-235).

Trust keys resolve from an EXTERNAL trust root, never from material
carried inside the record being verified. This is the treeship
TS-2026-004 pressure applied to our seams: a record signed by a key
from the package's own keys.json is not trust, and a key-id label
re-pointed to new material does not inherit the old binding.

The three machine refusals:

* ``untrusted-key`` -- the record's signing key id is not pinned in
  the external trust root. Key material supplied inside the record
  (an embedded keys bundle, a self-asserted authority block) can
  never bootstrap trust: the verifier consults the root only.
* ``trust-key-repointed`` -- the key id IS pinned, but the record's
  key material differs from the pinned material. Key ids are pinned
  to KEY MATERIAL (``sha256`` of the raw key bytes), never to labels,
  so re-pointing a label to new material refuses instead of
  inheriting trust.
* ``unsigned-field-ignored`` -- verification was asked to rely on a
  field outside the signature-covered body (for example an
  approval-use limit). Unsigned fields are NEVER consulted: the
  verifier refuses fail-closed instead of silently accepting or
  silently ignoring them.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads.

What this does NOT do (honest boundaries):
- It does not discover trust. The TrustRoot is caller-supplied
  (deployment config): a root pinned to the wrong key fails closed
  against the right key just as hard as the reverse. TrustRoot
  construction with malformed material is a programming error
  (ValueError), not a product refusal.
- Binding is key-id inequality of digests: it detects re-pointed or
  unknown keys, not a key holder's malice. The holder of a pinned
  private key can still sign lies; the signature proves the claim is
  theirs, not that it is true.
- External-root enforcement at the decision-packet seam is opt-in
  (``trust_root=None`` keeps the legacy semantics): the deployment
  owns the root-pinning decision, and this module documents that
  residual rather than forcing a breaking change.
- The 32-byte Ed25519 key shape is this module's key model; other
  key types are out of scope.
"""

import hashlib

UNTRUSTED_KEY = "untrusted-key"
KEY_REPOINTED = "trust-key-repointed"
UNSIGNED_FIELD_IGNORED = "unsigned-field-ignored"
MATERIAL_MALFORMED = "trust-material-malformed"

_KEY_LEN = 32


class TrustMaterialError(Exception):
    """A trust-material refusal carrying a machine taxonomy code.

    ``code`` is one of the module-level constants above; ``detail``
    is a human sentence. The base exception carries no product
    vocabulary beyond the named refusal (wave-232 lane-A lesson).
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s: %s" % (code, detail) if detail else code)


def pin_key_id(pubkey):
    """Pin a key id to key MATERIAL: ``sha256`` of the raw key bytes.

    The pin is a function of the material only -- labels play no
    role, so a label re-pointed to new material cannot keep the pin.
    Malformed material refuses ``trust-material-malformed`` (a
    construction-time refusal, never emitted at verification).
    """
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != _KEY_LEN:
        raise TrustMaterialError(
            MATERIAL_MALFORMED,
            "pubkey must be %d bytes" % (_KEY_LEN,))
    return hashlib.sha256(bytes(pubkey)).hexdigest()


def assert_signature_covered(signed_field_names, field_name):
    """Refuse to rely on a field outside the signature-covered body.

    ``signed_field_names`` is the set of field names the signature
    actually covers; ``field_name`` is the field verification is being
    asked to consult. A field outside the covered set refuses
    ``unsigned-field-ignored`` -- fail closed, never silent accept and
    never silent ignore.
    """
    if field_name not in set(signed_field_names or ()):
        raise TrustMaterialError(
            UNSIGNED_FIELD_IGNORED,
            "field %r is not signature-covered; verification refuses to "
            "consult unsigned fields" % (field_name,))
    return True


class TrustRoot:
    """An externally-pinned {key-id -> key material} trust root.

    Constructed from caller-supplied bindings (deployment config),
    never from the record under verification. The root is consulted
    for every signature check that opts into external trust; a record
    may carry its own keys bundle, but the bundle is never read.
    """

    def __init__(self, bindings):
        """``bindings`` maps key-id labels to raw 32-byte public keys.

        Malformed bindings are a programming error (ValueError): trust
        configuration is deployment-owned and must be validated at
        construction, never deferred to verification time.
        """
        if not isinstance(bindings, dict) or not bindings:
            raise ValueError("bindings must be a non-empty dict")
        pinned = {}
        for kid, pubkey in bindings.items():
            if not isinstance(kid, str) or not kid:
                raise ValueError("key-id labels must be non-empty strings")
            if kid in pinned:
                raise ValueError("duplicate key-id label %r" % (kid,))
            if not isinstance(pubkey, (bytes, bytearray)) \
                    or len(pubkey) != _KEY_LEN:
                raise ValueError(
                    "binding for %r: pubkey must be %d bytes"
                    % (kid, _KEY_LEN))
            pinned[kid] = (bytes(pubkey), pin_key_id(pubkey))
        self._pinned = pinned

    def key_ids(self):
        """The pinned key-id labels (a snapshot; the root is immutable)."""
        return tuple(sorted(self._pinned))

    def bind_authority(self, kid, pubkey):
        """Bind a record-carried (key-id, pubkey) pair to this root.

        Returns the PINNED public-key bytes: verify signatures with
        the root's material, never the record's. Refuses:

        * ``untrusted-key`` -- the key id is not pinned in this root.
          The key is supplied only inside the record (its authority
          block, an embedded keys bundle); external trust does not
          know it, so it cannot be trusted.
        * ``trust-key-repointed`` -- the key id is pinned, but the
          record's key material differs from the pinned material.
        """
        if not isinstance(kid, str) or not kid:
            raise TrustMaterialError(
                UNTRUSTED_KEY,
                "no key id presented; nothing is pinned")
        entry = self._pinned.get(kid)
        if entry is None:
            raise TrustMaterialError(
                UNTRUSTED_KEY,
                "key id %r is not pinned in the external trust root; "
                "record-carried key material is never trusted" % (kid,))
        pinned_pubkey, pinned_digest = entry
        if not isinstance(pubkey, (bytes, bytearray)) \
                or len(pubkey) != _KEY_LEN:
            raise TrustMaterialError(
                UNTRUSTED_KEY,
                "key id %r carries malformed key material" % (kid,))
        if pin_key_id(pubkey) != pinned_digest:
            raise TrustMaterialError(
                KEY_REPOINTED,
                "key id %r is pinned but the record's key material "
                "differs from the pinned material; the label was "
                "re-pointed" % (kid,))
        return pinned_pubkey
