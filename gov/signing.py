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


#: Domain separation for the per-member threshold signature body
#: (wave-186). A keyset-aware threshold member does not sign the common
#: checkpoint body directly; it signs ``_member_sig_body(common, kid,
#: version)``, cryptographically binding its keyset version (and key
#: id) to the checkpoint. Unversioned members sign the common body
#: unchanged, so pre-keyset signatures keep verifying.
_THRESHOLD_MEMBER_SIG_DOMAIN = b"sasanam-threshold-member/v1\x00"


def _member_sig_body(common_body, key_id, key_version):
    """Build the member-specific body one threshold member signs.

    Binds ``(key_id, key_version)`` to ``common_body`` under a distinct
    domain. Raises TypeError on malformed inputs (fail closed); the
    ``\\x00`` separates the version claim from the common body so no
    ``(key_id, version, body)`` triple is ambiguous.
    """
    if not isinstance(common_body, (bytes, bytearray)):
        raise TypeError("common_body must be bytes")
    if not isinstance(key_id, str) or not key_id:
        raise TypeError("key_id must be a non-empty string")
    if isinstance(key_version, bool) or not isinstance(
            key_version, int) or key_version < 1:
        raise TypeError("key_version must be an integer >= 1")
    return (_THRESHOLD_MEMBER_SIG_DOMAIN
            + key_id.encode("utf-8") + b"|kv"
            + str(key_version).encode("ascii") + b"\x00"
            + bytes(common_body))


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
        """One signature per key: [{"key_id", "sig" (hex)} (, "key_version")].

        Wave-186: when a member signer exposes a ``key_version``
        (``gov.keyset.KeysetSigner`` does), the member signs a
        member-specific body binding ``(key_id, key_version)`` to
        ``data`` (see ``_member_sig_body``), and the entry carries
        ``"key_version"``. The version claim is therefore
        cryptographically bound, not merely asserted: rewriting or
        stripping it breaks that member's signature, and the entry
        cannot be transplanted onto the common body. Members without
        a version sign ``data`` unchanged (legacy entry shape
        preserved). A malformed version is a programming error in
        the operator's signer set: fail fast (ValueError) rather
        than minting a mis-attested entry.
        """
        out = []
        for s in self._signers:
            kv = getattr(s, "key_version", None)
            entry = {"key_id": s.key_id}
            if kv is None:
                entry["sig"] = s.sign(data).hex()
            else:
                if isinstance(kv, bool) or not isinstance(kv, int) \
                        or kv < 1:
                    raise ValueError(
                        "threshold member %r exposes a malformed "
                        "key_version %r" % (s.key_id, kv))
                entry["sig"] = s.sign(
                    _member_sig_body(data, s.key_id, kv)).hex()
                entry["key_version"] = kv
            out.append(entry)
        return out


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


def verify_threshold(data, sig_entries, roster, trusted_root_pub,
                     keysets=None):
    """Verify k-of-n checkpoint signatures (A5).

    ``sig_entries``: [{"key_id", "sig" (hex)} (, "key_version")] from
    the checkpoint. Returns (ok, error). Steps: (1) the roster must
    verify under the trusted offline root; (2) at least ``threshold``
    DISTINCT roster key ids must carry valid Ed25519 signatures.
    Unknown key ids are ignored (forward compatibility); duplicates
    never double-count. A single compromised checkpoint key
    contributes at most one valid signature -- below threshold the
    checkpoint is rejected, which is the A5 security property.

    Wave-186 version binding: each entry is verified over the body its
    signer actually signed -- a keyset-aware member's member-specific
    body ``_member_sig_body(data, key_id, key_version)`` reconstructed
    from the entry's own ``key_version`` claim, or ``data`` itself for
    unversioned entries. Rewriting or stripping a version claim
    therefore breaks that member's signature cryptographically; the
    claim is self-authenticating and needs no trust. Malformed claims
    contribute nothing (fail closed).

    Wave-186 ``keysets`` (optional): a mapping ``key_id -> Keyset``
    (``gov.keyset.Keyset``) binding each threshold member key to its
    version/status authority. For every entry whose key has a keyset:

    * the entry's ``key_version`` claim (when present) must equal the
      keyset's version for that key id -- version/key_id confusion
      contributes nothing (fail closed);
    * a version whose keyset status is ``revoked`` contributes nothing
      -- a checkpoint signed under a later-revoked version is refused
      even though the key id is still roster-authorized, and stripping
      the claim cannot smuggle it past because revocation is resolved
      from the key id alone;
    * ``verify-only`` (retired, not revoked) versions keep counting --
      rotation never invalidates already-signed checkpoints.

    Entries whose key has no keyset verify exactly as before (no
    version concept; revocation unchecked -- the keyset is public
    trust material the verifier is expected to fetch current, exactly
    like the trusted root key). The status literal ``"revoked"`` is
    written out (not imported) because ``gov.keyset`` imports this
    module -- the cycle forbids a top-level import here.
    """
    ok, err = verify_roster(roster, trusted_root_pub)
    if not ok:
        return False, "roster rejected: %s" % (err,)
    if not isinstance(data, (bytes, bytearray)):
        return False, "data must be bytes"
    if keysets is not None and not isinstance(keysets, dict):
        return False, "keysets must be a mapping key_id -> Keyset"
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
        if not isinstance(kid, str) or kid in good \
                or kid not in roster_keys:
            continue  # malformed / duplicate / unknown: no count
        claimed = entry.get("key_version") if isinstance(
            entry, dict) else None
        if claimed is None:
            body = data
        else:
            try:
                body = _member_sig_body(data, kid, claimed)
            except TypeError:
                continue  # malformed version claim: contributes nothing
        if keysets is not None:
            ks = keysets.get(kid)
            if ks is not None and not _keyset_entry_counts(
                    ks, kid, claimed):
                continue  # revoked / confused / malformed: no count
        pub = bytes.fromhex(roster_keys[kid])
        if ed25519.verify(pub, body, sig):
            good.add(kid)
    if len(good) >= threshold:
        return True, None
    return False, "only %d/%d valid distinct signatures" % (
        len(good), threshold)


def _keyset_entry_counts(keyset, key_id, claimed_version):
    """Whether one threshold sig entry may count, per its keyset.

    Duck-typed against ``gov.keyset.Keyset`` (``by_key_id`` ->
    KeyVersion with ``.version`` / ``.status``); never raises. The
    keyset is the authority: the entry's ``key_version`` claim is
    cross-checked, and revocation is resolved from the key id alone
    so stripping the claim cannot smuggle a revoked version past.
    """
    try:
        by_key_id = getattr(keyset, "by_key_id", None)
        kv = by_key_id(key_id) if callable(by_key_id) else None
    except Exception:
        return False
    if kv is None:
        return False  # keyset does not know this key id
    if claimed_version is not None:
        if isinstance(claimed_version, bool) \
                or not isinstance(claimed_version, int) \
                or claimed_version < 1:
            return False  # malformed claim: contributes nothing
        try:
            kv_version = kv.version
        except Exception:
            return False
        if claimed_version != kv_version:
            return False  # version/key_id confusion: fail closed
    try:
        status = kv.status
    except Exception:
        return False
    # "revoked" == gov.keyset.STATUS_REVOKED (literal: import cycle).
    return status != "revoked"
