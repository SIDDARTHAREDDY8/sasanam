"""Independent-corroboration consumption (wave-238).

VeritasActa/Acta issue #3 consumption rule, prose re-derived (the drafts
repository carries NOASSERTION licensing, so the issue text is paraphrased,
never quoted): the CONSUMER independently corroborates each evidence item
against its OWN out-of-band trust policy before acting on it.

The rule, in one sentence: an evidence item counts as corroboration only
when its signature verifies under key material the consumer independently
holds, and independent corroboration requires KEY INEQUALITY between
sources -- two items presented as distinct sources but signed under the
same key are not independent witnesses.

Evidence item shape (``evidence[]`` member)::

    {
      "dimension": "policy_applied",        # claim dimension, non-empty str
      "state": "allowed",                  # asserted state, non-empty str
      "source": {
        "source_id": "audit-service-a",    # opaque source label
        "key_id": "<64 hex>",              # sha256(source Ed25519 pubkey)
        "signature": "<128 hex>",          # Ed25519 over canonical item bytes
      },
    }

The signature covers the canonical bytes of
``{"dimension", "state", "source_id", "key_id"}`` (JSON, sorted keys,
compact separators, UTF-8). Ed25519 is the stdlib implementation in
``gov.ed25519``. Signatures are asymmetric by design: with a symmetric
scheme, one "independent" source could forge another's attestation, which
is exactly the failure this module refuses.

The machine refusals, all vocabulary-bound to ``gov/decision_codes.py``:

- ``corroboration-malformed`` -- the envelope or an evidence item is the
  wrong shape (evidence[] missing, bad types, bad hex). Shape violations
  are refusals, never silent skips.
- ``corroboration-unattested`` -- an item's provenance resolves to the
  gated runtime's own key (``policy.runtime_key_id``). The runtime
  attesting its own evidence is self-attestation, even with a valid
  signature; it is refused before any signature check.
- ``corroboration-untrusted-source`` -- the item's key_id is not in the
  consumer's trust policy. The consumer cannot corroborate against key
  material it does not independently hold.
- ``corroboration-signature-invalid`` -- the key_id is policy-held but the
  Ed25519 signature fails: the policy's own material says the item was
  edited after signing.
- ``corroboration-key-inequality`` -- two items presented as distinct
  sources (different source_id) carry the SAME key_id. Presented as
  independent corroboration but provably not key-independent.
- ``corroboration-uncorroborated`` -- a required dimension has fewer than
  ``MIN_INDEPENDENT_KEYS`` distinct corroborating key_ids (including
  zero). A lone source cannot corroborate itself.

``consume`` fail-closes: any item-level failure (malformed, unattested,
untrusted, invalid signature, key-inequality) refuses the whole envelope
immediately -- an envelope that asks the consumer to act on an item the
consumer cannot independently corroborate is refused, not partially
consumed. Required-dimension coverage is checked after all items pass.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env reads.

What this does NOT do (honest boundaries):
- A verified signature proves the item was signed by the holder of the
  key -- it does NOT prove the claimed state is true, the policy is
  correct, or the source is honest. Corroboration here is
  source-independence, not truth.
- ``TrustPolicy`` is in-memory (a plain mapping the deployment builds
  from its own out-of-band provisioning). Key rotation, revocation, and
  persistence are deployment-owned.
- Items whose dimension is not in ``require_dimensions`` are still
  signature-checked (fail-closed), but do not gate consumption.
"""

import hashlib
import json

from gov import ed25519 as _ed25519

CORROBORATION_MALFORMED = "corroboration-malformed"
CORROBORATION_UNATTESTED = "corroboration-unattested"
CORROBORATION_UNTRUSTED_SOURCE = "corroboration-untrusted-source"
CORROBORATION_SIGNATURE_INVALID = "corroboration-signature-invalid"
CORROBORATION_KEY_INEQUALITY = "corroboration-key-inequality"
CORROBORATION_UNCORROBORATED = "corroboration-uncorroborated"

#: Independent corroboration needs at least two key-inequal sources.
MIN_INDEPENDENT_KEYS = 2

_DOMAIN_SEP = b"corroborated-consumption/v1:"
_HEX64 = 64
_HEX128 = 128


class CorroboratedConsumptionError(Exception):
    """A consumption refusal carrying a machine taxonomy code.

    ``code`` is one of the module-level ``CORROBORATION_*`` constants;
    ``detail`` is human context only and never a second code.
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__(
            "%s: %s" % (code, detail) if detail else code)


def _fail(code, detail=""):
    raise CorroboratedConsumptionError(code, detail)


def key_id_of(pubkey):
    """Deterministic key id: sha256 over the raw Ed25519 public key."""
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        _fail(CORROBORATION_MALFORMED,
              "key material is not a 32-byte Ed25519 public key")
    return hashlib.sha256(_DOMAIN_SEP + b"key-id:" + bytes(pubkey)).hexdigest()


def canonical_item_bytes(item):
    """Canonical bytes the source signature covers.

    ``{"dimension", "state", "source_id", "key_id"}`` -- JSON, sorted keys,
    compact separators, UTF-8. The signature field itself is excluded:
    it cannot cover itself.
    """
    try:
        body = {
            "dimension": item["dimension"],
            "state": item["state"],
            "source_id": item["source"]["source_id"],
            "key_id": item["source"]["key_id"],
        }
    except (KeyError, TypeError) as exc:
        _fail(CORROBORATION_MALFORMED,
              "evidence item is missing signed fields: %s" % (exc,))
    if not all(isinstance(v, str) for v in body.values()):
        _fail(CORROBORATION_MALFORMED,
              "evidence item signed fields must be strings")
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


class TrustPolicy:
    """The consumer's own out-of-band trust policy.

    ``trusted_keys`` maps key_id -> 32-byte Ed25519 public key. These are
    provisioned out of band by the DEPLOYMENT, never taken from the
    evidence envelope: the consumer corroborates against what IT trusts,
    not what the envelope asserts. ``runtime_key_id`` is the gated
    runtime's own key id -- evidence provenance resolving to it is
    self-attestation and is refused. ``require_dimensions`` is the set of
    dimensions that must each carry independent corroboration.
    """

    def __init__(self, trusted_keys, runtime_key_id, require_dimensions):
        if not isinstance(trusted_keys, dict) or not trusted_keys:
            _fail(CORROBORATION_MALFORMED,
                  "trust policy holds no key material")
        for kid, pub in trusted_keys.items():
            if (not isinstance(kid, str) or len(kid) != _HEX64
                    or not isinstance(pub, (bytes, bytearray))
                    or len(pub) != 32):
                _fail(CORROBORATION_MALFORMED,
                      "trust policy key entry is the wrong shape")
        if not isinstance(runtime_key_id, str) or len(runtime_key_id) \
                != _HEX64:
            _fail(CORROBORATION_MALFORMED,
                  "trust policy runtime key id is not 64 hex")
        require_dimensions = frozenset(require_dimensions)
        if not require_dimensions:
            _fail(CORROBORATION_MALFORMED,
                  "trust policy requires no corroboration dimensions")
        self.trusted_keys = dict(trusted_keys)
        self.runtime_key_id = runtime_key_id
        self.require_dimensions = require_dimensions


def _is_hex(value, length):
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_item(item, policy):
    """Verify one evidence item against the consumer's trust policy.

    Returns (dimension, key_id) on success. Refuses fail-closed on any
    item-level failure.
    """
    if not isinstance(item, dict):
        _fail(CORROBORATION_MALFORMED, "evidence item is not a mapping")
    dimension = item.get("dimension")
    state = item.get("state")
    source = item.get("source")
    if (not isinstance(dimension, str) or not dimension
            or not isinstance(state, str) or not state
            or not isinstance(source, dict)):
        _fail(CORROBORATION_MALFORMED,
              "evidence item has bad dimension/state/source")
    source_id = source.get("source_id")
    key_id = source.get("key_id")
    signature = source.get("signature")
    if (not isinstance(source_id, str) or not source_id
            or not _is_hex(key_id, _HEX64)
            or not _is_hex(signature, _HEX128)):
        _fail(CORROBORATION_MALFORMED,
              "evidence source has bad source_id/key_id/signature")
    # Self-attestation check BEFORE trust lookup: the runtime's own key
    # is never an independent source, valid signature or not.
    if key_id == policy.runtime_key_id:
        _fail(CORROBORATION_UNATTESTED,
              "item provenance is the gated runtime itself "
              "(source_id %r); not self-attested evidence" % (source_id,))
    pubkey = policy.trusted_keys.get(key_id)
    if pubkey is None:
        _fail(CORROBORATION_UNTRUSTED_SOURCE,
              "key_id %s is not in the consumer's trust policy" % (key_id,))
    if not _ed25519.verify(pubkey, canonical_item_bytes(item),
                           bytes.fromhex(signature)):
        _fail(CORROBORATION_SIGNATURE_INVALID,
              "signature fails under the policy-held key "
              "(source_id %r)" % (source_id,))
    return dimension, key_id, source_id


def consume(envelope, policy):
    """Corroborate an evidence envelope against the consumer's policy.

    Returns a consumption receipt on success::

        {"envelope_id": ..., "corroborated": {dimension: [key_ids...]}}

    Refuses fail-closed (``CorroboratedConsumptionError``) on any
    item-level failure or on missing independent corroboration for a
    required dimension.
    """
    if not isinstance(envelope, dict):
        _fail(CORROBORATION_MALFORMED, "envelope is not a mapping")
    envelope_id = envelope.get("envelope_id")
    evidence = envelope.get("evidence")
    if not isinstance(envelope_id, str) or not envelope_id:
        _fail(CORROBORATION_MALFORMED, "envelope has no envelope_id")
    if not isinstance(evidence, list):
        _fail(CORROBORATION_MALFORMED, "envelope evidence[] is not a list")
    if not isinstance(policy, TrustPolicy):
        _fail(CORROBORATION_MALFORMED, "policy is not a TrustPolicy")

    corroborated = {}  # dimension -> {key_id: source_id}
    for item in evidence:
        dimension, key_id, source_id = _check_item(item, policy)
        seen = corroborated.setdefault(dimension, {})
        first_source = seen.get(key_id)
        if first_source is not None and first_source != source_id:
            # Same key, two different source labels: presented as
            # independent sources but provably not key-independent.
            _fail(CORROBORATION_KEY_INEQUALITY,
                  "dimension %r: source_ids %r and %r share key_id %s"
                  % (dimension, first_source, source_id, key_id))
        seen.setdefault(key_id, source_id)

    for dimension in sorted(policy.require_dimensions):
        keys = corroborated.get(dimension, {})
        if len(keys) < MIN_INDEPENDENT_KEYS:
            _fail(CORROBORATION_UNCORROBORATED,
                  "dimension %r has %d independent key(s), need %d"
                  % (dimension, len(keys), MIN_INDEPENDENT_KEYS))

    receipt = {"envelope_id": envelope_id, "corroborated": {}}
    for dimension in sorted(corroborated):
        receipt["corroborated"][dimension] = sorted(corroborated[dimension])
    return receipt
