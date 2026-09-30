#!/usr/bin/env python3
"""Algorithm registry: crypto agility for signed governance records.

ADAPT of the EMILIA PIP-015 crypto-agility direction (re-derived
prose; nothing copied): no governance record should be hard-wired to
a single signing algorithm. ``gov/posture.py``, ``gov/absence.py``
and ``gov/revocation.py`` emit and verify through this registry, so
a new algorithm is a registration away from every record type —
but every tier shift is explicit, named, and honestly labeled.

The registry carries two algorithms out of the box:

* ``ed25519-rfc8032`` — the repo's vendored RFC 8032 Ed25519
  (``gov/ed25519.py``). Asymmetric, non-repudiable:
  ``require_non_repudiation`` passes it.
* ``hmac-sha256-mac`` — a symmetric-key HMAC-SHA256 message
  authentication code. Honest labeling, enforced by the registry
  itself: this tier is marked ``non_repudiation=False`` because a
  MAC IS NOT A SIGNATURE. Anyone who holds the shared key can forge
  a tag, so a MAC-backed record proves authenticity only to
  key-holders and must never be offered as non-repudiation
  evidence; ``require_non_repudiation("hmac-sha256-mac")`` refuses
  ``alg-non-repudiation-refused``. The HMAC tier exists for
  low-trust, symmetric deployments (e.g. two halves of the same
  control plane) where shared-key authenticity suffices and where
  failing closed on an unrecognized scheme would be worse.

Error vocabulary (all raised as :class:`AlgError` with a
machine-readable ``code``):

* ``alg-registration-refused`` — registering with a bad name, a
  non-callable primitive, an empty domain separator, or a name /
  domain separator that is already taken.
* ``alg-unregistered`` — signing (or verifying, or negotiating)
  with an algorithm the registry does not know. Fail closed: an
  unknown scheme never degrades to a known one.
* ``alg-mismatch`` — the record's named algorithm differs from
  the consumer's pinned expectation. Raised from
  :func:`resolve_record_alg` (used by the record modules), never
  by ``sign``/``verify`` themselves. ``verify`` returns a bool so
  consumers decide which refusal code names a signature failure.
* ``alg-no-mutual`` — :meth:`AlgorithmRegistry.negotiate` found no
  algorithm in both the preferred order and the acceptable set.
* ``alg-non-repudiation-refused`` — a MAC-tier algorithm was offered
  where non-repudiation is required.

Domain separation: each registration carries a non-empty, unique
``domain_separator`` (bytes). The separator is bound inside each
algorithm's own signing primitive (the HMAC tier prefixes it to the
message before keyed hashing; the Ed25519 tier relies on the
record-level domain prefixes the repo's records already carry), so
a tag/signature minted for one algorithm cannot be transplanted to
another. Uniqueness is enforced at registration time.

Negotiation: ``negotiate(preferred, acceptable)`` walks the
caller's preference order and returns the first algorithm the peer
also accepts — the highest-preference MUTUAL algorithm, never the
highest-preference one unilaterally. Names the registry does not
know are skipped (they can never be mutual); an empty intersection
refuses ``alg-no-mutual``.

The registry is additive: deployments may ``register`` their own
algorithms (e.g. a future post-quantum scheme) without touching
the record modules. ``default_registry()`` returns the shared
instance carrying the two built-ins.

Stdlib only. No network. $0.
Wave-233 honest-claim discipline (NON-CLAIMS.md): HMAC evidence proves shared-secret authenticity, not non-repudiation. This phrase is machine-checked by evals/doc_truth.py.
"""

import hashlib
import hmac as _hmac
import os

from .ed25519 import generate_seed as _ed_keygen_seed
from .ed25519 import publickey as _ed_pub
from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class AlgError(Exception):
    """Base class for all algorithm-registry refusals. ``code`` is
    machine-readable."""

    code = "alg-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class AlgRegistrationError(AlgError):
    """The registration was invalid: bad name, non-callable
    primitive, empty domain separator, or a name/domain separator
    already taken."""

    code = "alg-registration-refused"


class AlgUnregisteredError(AlgError):
    """The algorithm is not registered — fail closed, never
    degrade to a known scheme."""

    code = "alg-unregistered"


class AlgNoMutualError(AlgError):
    """Negotiation found no mutually acceptable algorithm."""

    code = "alg-no-mutual"


class AlgMismatchError(AlgError):
    """The record's named algorithm differs from the consumer's
    pinned expectation. Raised by consumers (posture / absence /
    revocation), never by the registry's own sign/verify."""

    code = "alg-mismatch"


class AlgNonRepudiationError(AlgError):
    """A MAC-tier algorithm was offered where non-repudiation is
    required. A MAC is not a signature."""

    code = "alg-non-repudiation-refused"


# ----------------------------------------------------------------------
# Built-in algorithm primitives.
# ----------------------------------------------------------------------

ED25519_RFC8032 = "ed25519-rfc8032"
HMAC_SHA256_MAC = "hmac-sha256-mac"

# The default algorithm. Records minted with it carry no "alg"
# field — they are byte-identical to the pre-agility records —
# and legacy records without an "alg" field verify as this.
DEFAULT_ALG = ED25519_RFC8032

_ED25519_DOMAIN = b"sasanam-alg/ed25519-rfc8032:"
_HMAC_DOMAIN = b"sasanam-alg/hmac-sha256-mac:"


def _ed25519_sign(seed, message):
    return _ed_sign(bytes(seed), bytes(message))


def _ed25519_verify(pubkey, message, signature):
    # Fail closed: malformed inputs verify False, never raise raw.
    try:
        return bool(_ed_verify(bytes(pubkey), bytes(message),
                              bytes(signature)))
    except Exception:  # noqa: BLE001 - fail closed, never raw
        return False


def _ed25519_keygen():
    seed = _ed_keygen_seed()
    return seed, _ed_pub(seed)


def _hmac_sign(key, message):
    return _hmac.new(bytes(key), _HMAC_DOMAIN + bytes(message),
                     hashlib.sha256).digest()


def _hmac_verify(key, message, tag):
    # Fail closed: malformed inputs verify False, never raise raw.
    try:
        return _hmac.compare_digest(
            _hmac_sign(key, message), bytes(tag))
    except Exception:  # noqa: BLE001 - fail closed, never raw
        return False


def _symmetric_keygen():
    # A symmetric keygen returns the key once; the "public" slot is
    # unused (there is no public key for a MAC). Callers must treat
    # the returned value as the secret key.
    key = os.urandom(32)
    return key, key


class AlgorithmRegistry:
    """A registry of named signing algorithms for governance
    records.

    Register once; sign/verify/negotiate by name. Registration is
    the only place new algorithms enter — the record modules never
    hard-code a scheme again.
    """

    def __init__(self):
        self._algorithms = {}
        self._domains = {}
        # KMS signer backends (wave-226, additive): algorithm name ->
        # a KMS-style signer object exposing ``sign(key_ref, message)
        # -> bytes`` (see gov/kms_signer.py). Default: none registered;
        # ``sign``/``verify`` behavior is unchanged when empty.
        self._signer_backends = {}

    def register(self, name, *, sign_fn, verify_fn, keygen,
                 domain_separator, non_repudiation=True):
        """Register ``name`` with its signing primitives.

        ``sign_fn(secret, message) -> bytes``,
        ``verify_fn(key, message, signature) -> bool``,
        ``keygen() -> (secret, public)``. ``domain_separator`` is
        bytes, non-empty, and unique across the registry — it is
        the algorithm's domain claim and no two algorithms may
        share it. ``non_repudiation`` must be ``False`` for MAC
        tiers (symmetric); asymmetric signatures leave it ``True``.
        """
        if not isinstance(name, str) or not name:
            raise AlgRegistrationError(
                "alg-registration-refused: algorithm name must be a "
                "non-empty string")
        if name in self._algorithms:
            raise AlgRegistrationError(
                "alg-registration-refused: %r is already registered"
                % (name,))
        for label, fn in (("sign_fn", sign_fn), ("verify_fn", verify_fn),
                          ("keygen", keygen)):
            if not callable(fn):
                raise AlgRegistrationError(
                    "alg-registration-refused: %s must be callable "
                    "for %r" % (label, name))
        if (not isinstance(domain_separator, (bytes, bytearray))
                or not domain_separator):
            raise AlgRegistrationError(
                "alg-registration-refused: domain_separator must be "
                "non-empty bytes for %r" % (name,))
        if bytes(domain_separator) in self._domains:
            raise AlgRegistrationError(
                "alg-registration-refused: domain_separator is "
                "already claimed by %r"
                % (self._domains[bytes(domain_separator)],))
        self._algorithms[name] = {
            "name": name,
            "sign_fn": sign_fn,
            "verify_fn": verify_fn,
            "keygen": keygen,
            "domain_separator": bytes(domain_separator),
            "non_repudiation": bool(non_repudiation),
        }
        self._domains[bytes(domain_separator)] = name

    def names(self):
        """The registered algorithm names, in registration order."""
        return tuple(self._algorithms)

    def info(self, name):
        """A copy of ``name``'s registration metadata (without the
        function objects)."""
        entry = self._algorithms.get(name)
        if entry is None:
            raise AlgUnregisteredError(
                "alg-unregistered: %r is not registered" % (name,))
        return {"name": entry["name"],
                "domain_separator": entry["domain_separator"],
                "non_repudiation": entry["non_repudiation"]}

    def _entry(self, name):
        entry = self._algorithms.get(name)
        if entry is None:
            raise AlgUnregisteredError(
                "alg-unregistered: %r is not registered" % (name,))
        return entry

    def sign(self, alg, message, secret):
        """Sign ``message`` under ``alg``; returns the signature
        bytes. Unknown ``alg`` refuses ``alg-unregistered``."""
        if not isinstance(message, (bytes, bytearray)):
            raise ValueError("message must be bytes")
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise ValueError("secret must be non-empty bytes")
        return self._entry(alg)["sign_fn"](bytes(secret), bytes(message))

    def verify(self, alg, message, signature, key):
        """Verify ``signature`` over ``message`` under ``alg``.

        Returns True/False — never raises raw on malformed input.
        Unknown ``alg`` refuses ``alg-unregistered`` (fail closed).
        """
        if not isinstance(message, (bytes, bytearray)):
            return False
        entry = self._entry(alg)
        try:
            return bool(entry["verify_fn"](bytes(key), bytes(message),
                                           bytes(signature)))
        except Exception:  # noqa: BLE001 - fail closed, never raw
            return False

    def keygen(self, alg):
        """Generate a fresh (secret, public) pair for ``alg``. For
        symmetric MAC tiers the secret IS the key — treat it as
        such and do not publish it."""
        return self._entry(alg)["keygen"]()

    def require_non_repudiation(self, alg):
        """Fail closed when ``alg`` cannot provide non-repudiation.

        Call this wherever a record is offered as non-repudiation
        evidence: MAC-tier records refuse
        ``alg-non-repudiation-refused`` — because a MAC is not a
        signature, and anyone holding the key could have minted it.
        """
        if not self._entry(alg)["non_repudiation"]:
            raise AlgNonRepudiationError(
                "alg-non-repudiation-refused: %r is a MAC tier, not "
                "a signature — it cannot serve as non-repudiation "
                "evidence" % (alg,))
        return True

    # -- KMS signer backends (wave-226; additive, default empty) -------

    def register_signer_backend(self, alg, signer):
        """Bind a KMS-style signer backend to a registered algorithm.

        ``signer`` must expose a callable ``sign(key_ref, message)``
        (the ``gov/kms_signer.KmsSigner`` surface): signing happens
        inside the KMS and only signatures return. ``alg`` must be
        registered — ``alg-unregistered`` otherwise (fail closed).
        Replacing an existing backend is allowed; clearing it is
        ``clear_signer_backend``.
        """
        self._entry(alg)  # alg-unregistered when unknown
        sign = getattr(signer, "sign", None)
        if not callable(sign):
            raise AlgRegistrationError(
                "alg-registration-refused: signer backend for %r must "
                "expose a callable sign(key_ref, message)" % (alg,))
        self._signer_backends[alg] = signer

    def clear_signer_backend(self, alg):
        """Remove the backend for ``alg`` (if any). Unknown ``alg``
        refuses ``alg-unregistered`` — fail closed, never silently
        no-op on a typo'd name."""
        self._entry(alg)
        self._signer_backends.pop(alg, None)

    def has_signer_backend(self, alg):
        """Whether a KMS signer backend is bound for ``alg``."""
        return alg in self._signer_backends

    def sign_via_backend(self, alg, message, key_ref):
        """Sign ``message`` through the backend bound to ``alg``.

        Unknown ``alg`` refuses ``alg-unregistered``; an ``alg``
        with no backend refuses ``alg-unregistered`` too — no
        silent fallback to local signing, ever. Backends enforce
        their own input validation (see ``gov/kms_signer.py``).
        """
        backend = self._signer_backends.get(alg)
        if backend is None:
            # Reuse alg-unregistered: from the caller's view there is
            # no signer scheme available for this algorithm.
            self._entry(alg)  # raises alg-unregistered when unknown
            raise AlgUnregisteredError(
                "alg-unregistered: no signer backend bound for %r"
                % (alg,))
        return backend.sign(key_ref, message)

    def negotiate(self, preferred, acceptable):
        """Return the highest-preference mutually acceptable
        algorithm.

        ``preferred`` is an ordered list of algorithm names (highest
        preference first); ``acceptable`` is the peer's set. Names
        the registry does not know are skipped — they can never be
        mutual, and a peer advertising an unknown algorithm must not
        hard-fail negotiation. No mutual algorithm refuses
        ``alg-no-mutual``.
        """
        try:
            preferred = list(preferred)
        except TypeError:
            raise AlgNoMutualError(
                "alg-no-mutual: preferred is not an iterable")
        try:
            acceptable = set(acceptable)
        except TypeError:
            raise AlgNoMutualError(
                "alg-no-mutual: acceptable is not an iterable")
        if not preferred or not acceptable:
            raise AlgNoMutualError(
                "alg-no-mutual: empty preference or acceptable set")
        acceptable = {name for name in acceptable
                      if isinstance(name, str) and name
                      and name in self._algorithms}
        for name in preferred:
            if not isinstance(name, str) or not name:
                raise AlgUnregisteredError(
                    "alg-unregistered: negotiated name must be a "
                    "non-empty string")
            if name not in self._algorithms:
                continue  # unknown to us: can never be mutual
            if name in acceptable:
                return name
        raise AlgNoMutualError(
            "alg-no-mutual: no algorithm is both preferred %r and "
            "acceptable %r" % (preferred, sorted(acceptable)))


_DEFAULT = None


def default_registry():
    """The shared registry carrying the built-in algorithms:
    ``ed25519-rfc8032`` and ``hmac-sha256-mac``."""
    global _DEFAULT
    if _DEFAULT is None:
        reg = AlgorithmRegistry()
        reg.register(ED25519_RFC8032,
                     sign_fn=_ed25519_sign,
                     verify_fn=_ed25519_verify,
                     keygen=_ed25519_keygen,
                     domain_separator=_ED25519_DOMAIN,
                     non_repudiation=True)
        reg.register(HMAC_SHA256_MAC,
                     sign_fn=_hmac_sign,
                     verify_fn=_hmac_verify,
                     keygen=_symmetric_keygen,
                     domain_separator=_HMAC_DOMAIN,
                     non_repudiation=False)
        _DEFAULT = reg
    return _DEFAULT


def extract_record_alg(record, expect_alg, malformed):
    """Resolve a signed record's algorithm from its ``"alg"`` field.

    ``malformed`` is a zero-arg callable producing the caller's
    malformed-record exception (each record module has its own
    error class). Unknown names refuse ``alg-unregistered``; a
    pinned ``expect_alg`` that differs refuses ``alg-mismatch``.
    """
    raw = record.get("alg")
    if raw is not None and (not isinstance(raw, str) or not raw):
        raise malformed()
    return resolve_record_alg(raw, expect_alg)


def stamp_record_alg(record, alg):
    """Stamp the algorithm name on a record being minted.

    The default tier is left unstamped: default-tier records carry
    no ``"alg"`` field and stay byte-identical to the pre-agility
    format. Non-default tiers are named inside the signed body.
    """
    if alg != DEFAULT_ALG:
        record["alg"] = alg
    return record


def negotiate_algorithms(preferred, acceptable):
    """Negotiate using the default registry: the highest-preference
    mutually acceptable algorithm, or ``alg-no-mutual``."""
    return default_registry().negotiate(preferred, acceptable)


def resolve_record_alg(record_alg, expect_alg=None):
    """Resolve the algorithm a signed record was issued under.

    ``record_alg`` is the record's ``"alg"`` field value, or None
    when the field is absent (legacy records resolve to
    ``ed25519-rfc8032``). The caller validates the field is a
    non-empty string or absent; this function refuses
    ``alg-unregistered`` for names the registry does not know, and
    ``alg-mismatch`` when ``expect_alg`` is pinned and differs.

    The algorithm name is part of the signed record body, so a
    record re-labeled with a different algorithm cannot keep a
    valid signature — re-labeling is tampering, not a mismatch.
    """
    alg = DEFAULT_ALG if record_alg is None else record_alg
    default_registry().info(alg)  # alg-unregistered when unknown
    if expect_alg is not None:
        if not isinstance(expect_alg, str) or not expect_alg:
            raise ValueError(
                "expect_alg must be a non-empty string or None")
        default_registry().info(expect_alg)  # pinned unknown -> fail
        if alg != expect_alg:
            raise AlgMismatchError(
                "alg-mismatch: record uses %r but the consumer "
                "pinned %r" % (alg, expect_alg))
    return alg
