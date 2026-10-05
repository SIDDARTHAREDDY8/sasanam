"""Reserved post-quantum evidence-envelope slot (format only).

Wave-335 lane 4. FORMAT ONLY -- no production crypto, identifiers only.

The keyed Sigstore evidence bundle (:mod:`gov.sigstore_bundle`) is
Ed25519-only today. This module reserves the ``pqAlgId`` slot in the
bundle format so a future PQ-capable producer can name the signature
algorithm it used -- WITHOUT any implementation in this build claiming
to verify it.

Identifier provenance: the closed table :data:`PQ_ALG_IDS` is the pure
(non-hybrid) signature-algorithm identifiers from the oqs-provider
``ALGORITHMS.md`` signature list (open-quantum-safe/oqs-provider, MIT
licensed). IDENTIFIERS ONLY -- no code, no parameters, no
implementation is copied or vendored here. The three standardized
families are covered: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon.
Hybrid ``p256_*``/``rsa3072_*`` forms and the MAYO/CROSS/UOV/SNOVA
families are deliberately OUTSIDE the closed table: the slot is for
the standardized pure-PQ signature algorithms, and anything outside
the table refuses ``evidence-pq-unknown-alg``.

Non-separable hybrid rule (the only hybrid shape we will ever accept):

* If a hybrid ever enters this format, it MUST be non-separable: BOTH
  algorithms sign a value committing to the algorithm set. A signature
  over just the payload, with the algorithm names sitting beside it,
  is separable -- a side-by-side JSON hybrid is broken by field deletion:
  an attacker strips the PQ signature field and the verifier
  still accepts the classical one. The cross-binding is what makes the
  two signatures one inseparable statement.
* The ``p256_*``/``rsa3072_*`` hybrid forms in the oqs-provider list
  are separable by this definition and are therefore OUTSIDE the
  closed table, not a precedent for a future hybrid slot.

Reserve-while-disabled semantics (fail-closed):

* :data:`PQ_ENABLED` is ``False``. There is no code path in this build
  that verifies a PQ signature.
* :func:`parse_pq_alg_id` validates an identifier against the closed
  table (unknown -> ``evidence-pq-unknown-alg``). It performs NO
  crypto and enables nothing.
* :func:`pq_use_refused` parses and then ALWAYS refuses
  ``evidence-pq-not-enabled``: any attempt to USE the slot for real
  sealing or verification is refused while the slot is disabled.
* The bundle verifier (:func:`gov.sigstore_bundle.open_keyed_bundle`)
  gates on the slot BEFORE any signature work: a bundle carrying
  ``pqAlgId`` is refused ``evidence-pq-not-enabled`` rather than
  verified down the classical Ed25519 path. Verifying a PQ-claimed
  bundle with the classical verifier would be algorithm confusion --
  the refusal kills that confusion by construction.
* The bundle sealer never emits the slot: sealing with a ``pq_alg_id``
  argument refuses ``evidence-pq-not-enabled`` (a PQ-claimed bundle
  sealed with a classical signature would be a mislabelled bundle).
  Classical seal output is therefore byte-identical with the slot
  present in the format.

Stdlib only. $0 spend. Synthetic/local testing. No network.
"""

from __future__ import annotations

__all__ = [
    "PQ_ENABLED",
    "PQ_ALG_IDS",
    "PQEnvelopeError",
    "parse_pq_alg_id",
    "pq_use_refused",
]

#: The reserved slot is DISABLED in this build. No PQ verification
#: exists; the slot is a format reservation only. Flip to True only
#: when a real PQ verification implementation lands behind it (with
#: its own red-first battery).
PQ_ENABLED = False

#: Closed table of PQ signature-algorithm identifiers. Pure (non-hybrid)
#: identifiers from oqs-provider ALGORITHMS.md (MIT; identifiers only):
#: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon. Anything outside this
#: table -- including oqs-provider hybrid forms and the MAYO/CROSS/UOV/
#: SNOVA families -- is refused by :func:`parse_pq_alg_id`.
PQ_ALG_IDS = frozenset((
    # ML-DSA (FIPS 204).
    "mldsa44",
    "mldsa65",
    "mldsa87",
    # Falcon (incl. padded variants, as listed by oqs-provider).
    "falcon512",
    "falconpadded512",
    "falcon1024",
    "falconpadded1024",
    # SLH-DSA (FIPS 205): SHA2 and SHAKE, 128/192/256, small/fast.
    "slhdsasha2128s",
    "slhdsasha2128f",
    "slhdsasha2192s",
    "slhdsasha2192f",
    "slhdsasha2256s",
    "slhdsasha2256f",
    "slhdsashake128s",
    "slhdsashake128f",
    "slhdsashake192s",
    "slhdsashake192f",
    "slhdsashake256s",
    "slhdsashake256f",
))


class PQEnvelopeError(Exception):
    """Coded refusal for reserved-PQ-slot violations."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _refuse(code, detail):
    raise PQEnvelopeError("%s: %s" % (code, detail), code=code)


def parse_pq_alg_id(value):
    """Validate a ``pqAlgId`` identifier against the closed table.

    Returns the identifier unchanged when it is a member of
    :data:`PQ_ALG_IDS`. Refuses ``evidence-pq-unknown-alg`` for
    anything else -- unknown strings, wrong case, pre-standard names,
    hybrid forms, non-string types. Performs no crypto and enables
    nothing; identifier validation only.
    """
    if not isinstance(value, str) or value not in PQ_ALG_IDS:
        _refuse("evidence-pq-unknown-alg",
                "pqAlgId %r is not in the closed PQ table "
                "(19 identifiers: mldsa44/65/87, falcon512/padded/1024, "
                "12 slh-dsa variants)" % (value,))
    return value


def pq_use_refused(pq_alg_id):
    """Parse ``pq_alg_id``, then ALWAYS refuse ``evidence-pq-not-enabled``.

    The single choke point for every real USE of the reserved slot
    (seal, verify, or any future PQ operation): the identifier must be
    known (else ``evidence-pq-unknown-alg``), and then the use is
    refused because :data:`PQ_ENABLED` is False. Never returns.
    """
    parse_pq_alg_id(pq_alg_id)
    _refuse("evidence-pq-not-enabled",
            "pqAlgId %r names a reserved PQ algorithm, but PQ "
            "verification is not enabled in this build; refusing "
            "fail-closed (no PQ signature was checked)" % (pq_alg_id,))
