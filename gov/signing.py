"""Public-key signing for the audit log: abstract seams (P2), Ed25519
adapters, and k-of-n threshold checkpoint signing with an offline root
(A5 -- scoped TUF, not TUF wholesale).

Fail-closed throughout: every verify path returns False (never raises)
on malformed input; thresholds count DISTINCT authorized key ids;
unknown key ids never contribute.

P2 interfaces (architect ROADMAP): ``Signer.sign(bytes)->bytes`` and
``Verifier.verify(bytes, sig)->bool``; ``gov/log.py`` programs against
these and keeps the HMAC path the default (``signer=None`` is
byte-identical to today's behavior).

A5 (threshold, scoped): a checkpoint is valid when at least ``k``
DISTINCT roster key ids carry valid Ed25519 signatures over the
checkpoint body. This is TUF-style multi-signature -- n independent
standard Ed25519 signatures -- not a multisig key scheme: no new
cryptography, each signature verifies independently.

Offline root: the checkpoint-signer roster is itself signed by an
offline root key. Verifiers trust exactly one root public key
(distributed out-of-band, e.g. deployment config); every checkpoint
key's authority chains from the roster. Compromising fewer than k
checkpoint keys cannot forge a checkpoint. The root key is the trust
anchor and MUST be kept offline -- the rotation ceremony and
key-custody runbook belong to the KMS workstream (their envelope work
owns key custody); this module defines only the artifact format and
the verification path, so the ceremony has something precise to
operate on.

Role separation (A5): the roster's role is ``"checkpoint-signer"``; the
root key's role is ``"root"``. Rotation authority is a different role
owned by KMS -- nothing here mints or verifies rotation authority.
"""

import hashlib
import json
from abc import ABC, abstractmethod

from . import ed25519

ROSTER_VERSION = 1
ROSTER_ROLE = "checkpoint-signer"
ROOT_ROLE = "root"
GENESIS_ROSTER = "GENESIS"


def ed25519_key_id(pub):
    """Key id for an Ed25519 public key.

    ``sha256(pub).hexdigest()[:16]`` -- the same key-id convention
    ``gov/keys.py`` uses for symmetric keys (``key_id =
    sha256(key).hexdigest()[:16]``), so key ids are uniform across the
    HMAC and signature layers.
    """
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        raise ValueError("pub must be 32 bytes")
    return hashlib.sha256(bytes(pub)).hexdigest()[:16]


def _canonical_body(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


class Signer(ABC):
    """Abstract signing key (P2 seam)."""

    @property
    @abstractmethod
    def key_id(self):
        """Short key identifier (see :func:`ed25519_key_id`)."""

    @property
    @abstractmethod
    def public_key(self):
        """32-byte Ed25519 public key."""

    @abstractmethod
    def sign(self, data):
        """Sign ``data`` (bytes); returns the 64-byte signature."""


class Verifier(ABC):
    """Abstract signature verifier (P2 seam)."""

    @property
    @abstractmethod
    def key_id(self):
        """Key identifier this verifier checks signatures for."""

    @abstractmethod
    def verify(self, data, sig):
        """True iff ``sig`` is valid for ``data``; never raises."""


class Ed25519Signer(Signer):
    """In-memory Ed25519 signer from a 32-byte seed.

    Key custody: the seed lives in process memory while signing. For
    production, KMS backs this interface (their envelope unwraps to
    memory at signing time); this class is the local/test form and the
    shape KMS's provider must satisfy.
    """

    def __init__(self, seed):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._seed = bytes(seed)
        self._pub = ed25519.publickey(self._seed)
        self._key_id = ed25519_key_id(self._pub)

    @property
    def key_id(self):
        return self._key_id

    @property
    def public_key(self):
        return self._pub

    def sign(self, data):
        return ed25519.sign(self._seed, data)


class Ed25519Verifier(Verifier):
    """Ed25519 verifier from a 32-byte public key. Fail-closed."""

    def __init__(self, pub, key_id=None):
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            raise ValueError("pub must be 32 bytes")
        self._pub = bytes(pub)
        self._key_id = key_id or ed25519_key_id(self._pub)

    @property
    def key_id(self):
        return self._key_id

    def verify(self, data, sig):
        try:
            return ed25519.verify(self._pub, data, sig)
        except Exception:
            return False


class ThresholdSigner:
    """k-of-n checkpoint signer (A5).

    Holds n :class:`Signer` objects; :meth:`sign_all` produces one
    Ed25519 signature per key. Per-entry signatures (the non-threshold
    P2 layer) use :attr:`entry_signer` -- defaulting to the first key --
    because threshold-signing every entry would be operationally absurd
    and a perf disaster (A5 adjudication keeps the per-entry path
    single-signature; the HMAC hot path stays untouched).
    """

    def __init__(self, signers, threshold, entry_signer=None):
        signers = list(signers)
        if not signers:
            raise ValueError("need at least one signer")
        ids = [s.key_id for s in signers]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate key ids in threshold set")
        if not (1 <= threshold <= len(signers)):
            raise ValueError("threshold must satisfy 1 <= k <= n")
        self._signers = signers
        self._threshold = threshold
        self._entry_signer = entry_signer or signers[0]
        if self._entry_signer.key_id not in set(ids):
            raise ValueError("entry_signer must be one of the signers")

    @property
    def threshold(self):
        return self._threshold

    @property
    def key_ids(self):
        return [s.key_id for s in self._signers]

    @property
    def entry_signer(self):
        return self._entry_signer

    # Signer-compatible surface for per-entry use.
    @property
    def key_id(self):
        return self._entry_signer.key_id

    @property
    def public_key(self):
        return self._entry_signer.public_key

    def sign(self, data):
        """Single signature (per-entry layer) via the entry signer."""
        return self._entry_signer.sign(data)

    def sign_all(self, data):
        """One signature per key: [{"key_id", "sig" (hex)}]."""
        return [{"key_id": s.key_id, "sig": s.sign(data).hex()}
                for s in self._signers]


def make_roster(signers, threshold, root_signer, prev_roster_hash=None):
    """Build an offline-root-signed checkpoint-signer roster (A5).

    ``signers``: list of :class:`Signer` (public halves published).
    ``root_signer``: the OFFLINE root key -- kept offline per the
    ceremony; only its signature operation is used here.
    Returns the roster dict (JSON-serializable).
    """
    pubs = {}
    for s in signers:
        if not isinstance(s, Signer):
            raise TypeError("roster members must be Signer instances")
        pubs[s.key_id] = s.public_key.hex()
    if not (1 <= threshold <= len(pubs)):
        raise ValueError("threshold must satisfy 1 <= k <= n")
    body = {
        "roster_version": ROSTER_VERSION,
        "role": ROSTER_ROLE,
        "threshold": threshold,
        "keys": pubs,
        "prev_roster_hash": prev_roster_hash or GENESIS_ROSTER,
        "root_key_id": root_signer.key_id,
    }
    body["sig"] = root_signer.sign(_canonical_body(
        {k: v for k, v in body.items() if k != "sig"})).hex()
    return body


def roster_hash(roster):
    """Content hash of a roster (binds the signer set into checkpoints)."""
    body = {k: v for k, v in roster.items() if k != "sig"}
    return hashlib.sha256(_canonical_body(body)).hexdigest()


def verify_roster(roster, trusted_root_pub):
    """Verify a roster against the trusted offline root public key.

    Returns (ok, error). Checks: version, role separation
    (``checkpoint-signer`` -- a root-role roster is rejected), sane
    threshold, well-formed keys, ``root_key_id`` binding, and the
    root's Ed25519 signature. Never raises on malformed input.
    """
    try:
        if not isinstance(roster, dict):
            return False, "roster is not an object"
        if roster.get("roster_version") != ROSTER_VERSION:
            return False, "unsupported roster_version %r" % (
                roster.get("roster_version"),)
        if roster.get("role") != ROSTER_ROLE:
            return False, "roster role %r is not %r (role separation)" % (
                roster.get("role"), ROSTER_ROLE)
        threshold = roster.get("threshold")
        keys = roster.get("keys")
        if not isinstance(keys, dict) or not keys:
            return False, "roster has no keys"
        if (not isinstance(threshold, int) or isinstance(threshold, bool)
                or not (1 <= threshold <= len(keys))):
            return False, "bad threshold %r for %d keys" % (
                threshold, len(keys))
        for kid, pubhex in keys.items():
            try:
                pub = bytes.fromhex(pubhex)
            except (TypeError, ValueError):
                return False, "bad pubkey hex for %r" % (kid,)
            if len(pub) != 32:
                return False, "bad pubkey length for %r" % (kid,)
            if ed25519_key_id(pub) != kid:
                return False, "key id %r does not match its pubkey" % (
                    kid,)
        if not isinstance(trusted_root_pub, (bytes, bytearray)) \
                or len(trusted_root_pub) != 32:
            return False, "trusted root pubkey malformed"
        if roster.get("root_key_id") != ed25519_key_id(
                bytes(trusted_root_pub)):
            return False, "roster root_key_id does not match trusted root"
        sig = bytes.fromhex(roster.get("sig", ""))
        body = {k: v for k, v in roster.items() if k != "sig"}
        if not ed25519.verify(bytes(trusted_root_pub),
                              _canonical_body(body), sig):
            return False, "roster signature invalid (not root-signed)"
        return True, None
    except (TypeError, ValueError, KeyError) as e:
        return False, "malformed roster: %s" % (e,)


def verify_threshold(data, sig_entries, roster, trusted_root_pub):
    """Verify k-of-n checkpoint signatures (A5).

    ``sig_entries``: [{"key_id", "sig" (hex)}] from the checkpoint.
    Returns (ok, error). Steps: (1) the roster must verify under the
    trusted offline root; (2) at least ``threshold`` DISTINCT roster key
    ids must carry valid Ed25519 signatures over ``data``. Unknown key
    ids are ignored (forward compatibility); duplicates never
    double-count. A single compromised checkpoint key contributes at
    most one valid signature -- below threshold the checkpoint is
    rejected, which is the A5 security property.
    """
    ok, err = verify_roster(roster, trusted_root_pub)
    if not ok:
        return False, "roster rejected: %s" % (err,)
    if not isinstance(data, (bytes, bytearray)):
        return False, "data must be bytes"
    data = bytes(data)
    roster_keys = roster["keys"]
    threshold = roster["threshold"]
    good = set()
    try:
        entries = list(sig_entries)
    except TypeError:
        return False, "sig_entries malformed"
    for entry in entries:
        try:
            kid = entry["key_id"]
            sig = bytes.fromhex(entry["sig"])
        except (KeyError, TypeError, ValueError):
            continue  # malformed entry: contributes nothing
        if kid in good or kid not in roster_keys:
            continue  # duplicate or unknown: no double-count
        pub = bytes.fromhex(roster_keys[kid])
        if ed25519.verify(pub, data, sig):
            good.add(kid)
    if len(good) >= threshold:
        return True, None
    return False, "only %d/%d valid distinct signatures" % (
        len(good), threshold)
