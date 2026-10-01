"""Decode trust split: untrusted-decode vs trusted-decode.

Cedar 4.12.0 pattern (``decode`` vs ``decode_unchecked``): every
bundle parser in ``gov/`` exposes TWO decode paths and the split is
mechanical, not documentary.

- **Untrusted decode** (``decode_untrusted_*``): the public seam for
  hostile input. Full shape validation, coded errors, fail-closed.
  Its output is never trusted -- it is data the caller still has to
  verify.
- **Trusted decode** (``decode_trusted_*``): for input that has
  already passed through a verification point (a signature threshold,
  a receipt check, a digest chain). It is *unreachable* from
  unverified input by construction: it requires a
  :class:`TrustEvidence` sealed at the verification point and
  re-checks the digest binding itself before parsing a single byte.

A verification point seals evidence with :func:`seal_evidence`; a
trusted decoder opens it with :func:`require_trust`. The binding is
``sha256(wire_bytes) == evidence.digest`` AND
``evidence.scope == <parser scope>`` -- scope separation stops a
signature verified for one parser being replayed as trust for
another (cross-parser confusion is the failure this prevents).

Refusals are the ``decodetrust-*`` machine codes (global taxonomy):

- ``decodetrust-no-evidence``: the trusted path was called without a
  TrustEvidence (or with ``None``). The input is untrusted; the
  caller must use the untrusted path.
- ``decodetrust-malformed-evidence``: the evidence object is not a
  TrustEvidence with well-formed fields (wrong type, bad digest
  shape, empty scope/kind/signer). Never coerced.
- ``decodetrust-binding-mismatch``: the evidence is well-formed but
  does not bind THESE bytes (digest mismatch) or this parser (scope
  mismatch). A signature verified for other bytes is not trust.

Evidence carries no authority: it is a sealed record that a named
verification event happened over named bytes. Any authority-shaped
use refuses ``decision-code-not-authorization`` by the global rule.
"""

import hashlib

__all__ = [
    "DecodeTrustError",
    "TrustEvidence",
    "seal_evidence",
    "require_trust",
    "EXPECTED_CODES",
]

EXPECTED_CODES = (
    "decodetrust-no-evidence",
    "decodetrust-malformed-evidence",
    "decodetrust-binding-mismatch",
)


class DecodeTrustError(Exception):
    """Coded refusal from the decode-trust seam.

    ``code`` is one of EXPECTED_CODES; ``detail`` is human text for
    the audit trail. Never raised for untrusted-path shape defects --
    those keep their module's own coded errors.
    """

    def __init__(self, code, detail):
        if code not in EXPECTED_CODES:
            raise ValueError("unknown decode-trust code %r" % (code,))
        super(DecodeTrustError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _is_hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


class TrustEvidence(object):
    """Sealed record of a verification event over specific bytes.

    Created ONLY by :func:`seal_evidence` at a verification point
    (after the signature/receipt/digest check has passed). Fields:

    - ``scope``: the parser scope the evidence authorizes
      (e.g. ``"bundle-rsl-rule"``). Scopes are never wildcarded.
    - ``digest``: sha256 hex of the exact verified bytes.
    - ``kind``: the verification kind (``"signature"``,
      ``"receipt"``, ``"chain"``, ``"anchor"``).
    - ``signer``: who/what verified (key id, threshold label, log
      id). Informational only -- never authority.

    Instances are immutable (attribute writes refused) so a sealed
    evidence cannot be re-scoped after the fact.
    """

    __slots__ = ("_scope", "_digest", "_kind", "_signer")

    def __init__(self, *, scope, digest, kind, signer):
        for name, value in (("scope", scope), ("kind", kind),
                            ("signer", signer)):
            if not isinstance(value, str) or not value:
                raise DecodeTrustError(
                    "decodetrust-malformed-evidence",
                    "evidence %s must be a non-empty str" % name)
        if not _is_hex64(digest):
            raise DecodeTrustError(
                "decodetrust-malformed-evidence",
                "evidence digest must be 64 lowercase hex chars")
        object.__setattr__(self, "_scope", scope)
        object.__setattr__(self, "_digest", digest)
        object.__setattr__(self, "_kind", kind)
        object.__setattr__(self, "_signer", signer)

    def __setattr__(self, name, value):
        # A programming error, not a trust refusal: like a frozen
        # dataclass (FrozenInstanceError is an AttributeError
        # subclass), mutating sealed evidence raises AttributeError
        # -- NOT a decodetrust-* code, which would misfile the event.
        raise AttributeError(
            "TrustEvidence is immutable; refusing to set %r" % (name,))

    def __copy__(self):
        # Immutable value type: all fields are immutable scalars, so
        # the identity copy is safe (and keeps copy.copy working
        # despite the __setattr__ guard).
        return self

    def __deepcopy__(self, memo):
        return self

    def __repr__(self):
        return ("TrustEvidence(scope=%r, digest=%r..., kind=%r, "
                "signer=%r)" % (self._scope, self._digest[:16],
                                self._kind, self._signer))

    @property
    def scope(self):
        return self._scope

    @property
    def digest(self):
        return self._digest

    @property
    def kind(self):
        return self._kind

    @property
    def signer(self):
        return self._signer

    def as_dict(self):
        return {"scope": self._scope, "digest": self._digest,
                "kind": self._kind, "signer": self._signer}


def seal_evidence(*, scope, digest, kind, signer):
    """Seal a TrustEvidence at a verification point.

    Call ONLY after the verification the evidence names has
    succeeded (signature threshold met, receipt verified, digest
    chain checked). Sealing is the trust event: everything
    downstream of the returned evidence may use the trusted-decode
    path for ``digest`` bytes under ``scope``.
    """
    return TrustEvidence(scope=scope, digest=digest, kind=kind,
                         signer=signer)


def require_trust(evidence, wire_bytes, *, scope):
    """Open a TrustEvidence for the trusted-decode path.

    ``wire_bytes`` is the exact bytes about to be trusted-decoded;
    ``scope`` is the parser's scope. Raises ``DecodeTrustError``:

    - ``decodetrust-no-evidence`` when evidence is None,
    - ``decodetrust-malformed-evidence`` when it is not a
      TrustEvidence,
    - ``decodetrust-binding-mismatch`` when the digest or the scope
      does not match.

    Returns None on success -- the binding held, decode may proceed.
    """
    if evidence is None:
        raise DecodeTrustError(
            "decodetrust-no-evidence",
            "trusted decode of scope %r called without trust "
            "evidence; the input is untrusted, use the untrusted "
            "decode path" % (scope,))
    if not isinstance(evidence, TrustEvidence):
        raise DecodeTrustError(
            "decodetrust-malformed-evidence",
            "trusted decode of scope %r called with %s, not a "
            "TrustEvidence; refusing rather than coercing"
            % (scope, type(evidence).__name__))
    if evidence.scope != scope:
        raise DecodeTrustError(
            "decodetrust-binding-mismatch",
            "evidence scope %r does not authorize trusted decode "
            "of scope %r (cross-parser evidence replay refused)"
            % (evidence.scope, scope))
    if not isinstance(wire_bytes, (bytes, bytearray)):
        raise DecodeTrustError(
            "decodetrust-malformed-evidence",
            "trusted decode requires bytes, got %s"
            % type(wire_bytes).__name__)
    actual = hashlib.sha256(bytes(wire_bytes)).hexdigest()
    if actual != evidence.digest:
        raise DecodeTrustError(
            "decodetrust-binding-mismatch",
            "evidence binds digest %s... but the presented bytes "
            "hash to %s... (verified-for-other-bytes is not trust)"
            % (evidence.digest[:16], actual[:16]))
    return None
