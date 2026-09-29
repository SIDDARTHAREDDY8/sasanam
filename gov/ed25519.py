"""Ed25519 digital signatures: vendored pure-Python RFC 8032.

P2 (crypto workstream): public-key signatures for the audit log, so an
external auditor can verify entries and checkpoints WITHOUT holding the
shared HMAC key (cf. ``gov/keys.py``: HMAC gives no non-repudiation
between key holders).

Implementation status -- read before deploying:
* Faithful RFC 8032 sections 5.1.5-5.1.7; validated byte-exact against
  the RFC 8032 section 7.1 TEST 1 and TEST 2 vectors (see
  ``tests/test_crypto_gov.py``). This is the standard wire format, so
  signatures verify across implementations.
* Pure Python: NOT constant-time. CPython bigint operations leak timing
  to a local side-channel attacker. The threat model for the audit-log
  use covers a run-dir writer and a network auditor, not a local
  side-channel observer; where local side channels are in scope,
  replace this module with a constant-time backend (e.g. libsodium via
  PyNaCl) behind the same function signatures -- no wire-format change.
* Deterministic nonces per RFC 8032 section 5.1.6 (no RNG at sign
  time); key generation uses :mod:`secrets`.
* Ed25519ph (RFC 8032 section 5.1, ``sign_ph``/``verify_ph``): the
  prehashed variant. Real Rekor v1.5.x's ``hashedrekord`` type only
  accepts Ed25519ph (SHA-512) for Ed25519 keys (F203) -- raw Ed25519
  is rejected server-side. The domain separator differs from pure
  Ed25519 (flag octet 0x01), so ph signatures are NOT interchangeable
  with pure signatures: ``verify`` rejects ``sign_ph`` output and
  ``verify_ph`` rejects ``sign`` output, by construction.

``verify`` never raises on malformed inputs: malformed is False, never
an exception (fail-closed for verifiers).
"""

import hashlib
import secrets

_Q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)  # sqrt(-1) mod _Q


def _inv(x):
    return pow(x, _Q - 2, _Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv((_D * y * y + 1) % _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
# Base point B in extended coordinates (X, Y, Z, T).
_B = (_BX, _BY, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _add(P, Q):
    """Complete Edwards addition (Hisil et al.), valid for all inputs."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % _Q
    B = ((Y1 + X1) * (Y2 + X2)) % _Q
    C = (T1 * ((2 * _D) % _Q) * T2) % _Q
    Dd = ((2 * Z1) * Z2) % _Q
    E = (B - A) % _Q
    F = (Dd - C) % _Q
    G = (Dd + C) % _Q
    H = (B + A) % _Q
    return ((E * F) % _Q, (G * H) % _Q, (F * G) % _Q, (E * H) % _Q)


def _scalarmult(P, e):
    e %= _L
    Q = _IDENTITY
    for i in range(255, -1, -1):
        Q = _add(Q, Q)
        if (e >> i) & 1:
            Q = _add(Q, P)
    return Q


def _encode_point(P):
    X, Y, Z, _T = P
    zinv = _inv(Z)
    x = (X * zinv) % _Q
    y = (Y * zinv) % _Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(s):
    if len(s) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("y coordinate out of range")
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _Q - x
    if ((-x * x + y * y - 1 - _D * x * x * y * y) % _Q) != 0:
        raise ValueError("point not on curve")
    return (x, y, 1, (x * y) % _Q)


def _clamp(a):
    a &= ~7            # clear lowest three bits (cofactor multiple)
    a &= ~(1 << 255)   # clear highest bit
    a |= (1 << 254)    # set second-highest bit
    return a


def generate_seed():
    """Generate a fresh 32-byte Ed25519 seed (secret key material)."""
    return secrets.token_bytes(32)


def publickey(seed):
    """Derive the 32-byte public key from a 32-byte seed (RFC 8032 5.1.5)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(bytes(seed)).digest()
    a = _clamp(int.from_bytes(h[:32], "little"))
    return _encode_point(_scalarmult(_B, a))


def sign(seed, msg):
    """Sign ``msg`` deterministically (RFC 8032 5.1.6). Returns 64 bytes."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    seed = bytes(seed)
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("msg must be bytes")
    msg = bytes(msg)
    h = hashlib.sha512(seed).digest()
    a = _clamp(int.from_bytes(h[:32], "little"))
    prefix = h[32:]
    A = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(),
                       "little") % _L
    R = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(),
                       "little") % _L
    S = (r + k * a) % _L
    return R + S.to_bytes(32, "little")


def verify(pub, msg, sig):
    """Verify an Ed25519 signature (RFC 8032 5.1.7).

    Returns True/False; never raises on malformed inputs (fail-closed
    for verifiers: malformed is False, never an exception).
    """
    if (not isinstance(pub, (bytes, bytearray)) or len(pub) != 32
            or not isinstance(sig, (bytes, bytearray)) or len(sig) != 64):
        return False
    if not isinstance(msg, (bytes, bytearray)):
        return False
    pub, sig, msg = bytes(pub), bytes(sig), bytes(msg)
    try:
        A = _decode_point(pub)
        R = _decode_point(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(),
                       "little") % _L
    lhs = _scalarmult(_B, s)
    rhs = _add(R, _scalarmult(A, k))
    return _encode_point(lhs) == _encode_point(rhs)


# ---------------------------------------------------------------------------
# Ed25519ph (RFC 8032, section 5.1) -- prehashed Ed25519.
#
# PH(M) = SHA-512(M); the domain separator is
#   dom2(F, C) = "SigEd25519 no Ed25519 collisions" || 0x01 || C
# with the prehash flag octet 0x01 and context C (empty here, matching
# sigstore's WithED25519ph() default). hashedrekord is the reason this
# exists: Rekor v1.5.x constructs the entry's signature verifier with
# signature.LoadVerifier(... WithED25519ph()) and rejects raw Ed25519
# (F203). The empty-context default matches what Rekor expects.

_PH_DOM_PREFIX = b"SigEd25519 no Ed25519 collisions"


def _ph_dom(context):
    if not isinstance(context, (bytes, bytearray)):
        raise TypeError("context must be bytes")
    if len(context) > 255:
        raise ValueError("context must be at most 255 bytes")
    context = bytes(context)
    # RFC 8032, section 2: dom2(x, y) = "SigEd25519 no Ed25519
    # collisions" || octet(x) || octet(OLEN(y)) || y, with x = 1
    # (prehash flag) for Ed25519ph.
    return (_PH_DOM_PREFIX + b"\x01" + bytes([len(context)]) + context)


def sign_ph(seed, msg, context=b""):
    """Sign ``msg`` with Ed25519ph (RFC 8032 5.1). Returns 64 bytes.

    The message is prehashed with SHA-512 internally; callers pass the
    original message (for hashedrekord, the 32-byte artifact digest).
    Deterministic like :func:`sign`. Byte-exact against the RFC 8032
    section 7.3 TEST 1 vector (see ``rfc8032_ph_selftest``).
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    seed = bytes(seed)
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("msg must be bytes")
    msg = bytes(msg)
    dom = _ph_dom(context)
    h = hashlib.sha512(seed).digest()
    a = _clamp(int.from_bytes(h[:32], "little"))
    prefix = h[32:]
    A = _encode_point(_scalarmult(_B, a))
    ph = hashlib.sha512(msg).digest()
    r = int.from_bytes(hashlib.sha512(dom + prefix + ph).digest(),
                       "little") % _L
    R = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(dom + R + A + ph).digest(),
                       "little") % _L
    S = (r + k * a) % _L
    return R + S.to_bytes(32, "little")


def verify_ph(pub, msg, sig, context=b""):
    """Verify an Ed25519ph signature (RFC 8032 5.1).

    Returns True/False; never raises on malformed inputs (fail-closed
    for verifiers: malformed is False, never an exception).
    """
    if (not isinstance(pub, (bytes, bytearray)) or len(pub) != 32
            or not isinstance(sig, (bytes, bytearray)) or len(sig) != 64):
        return False
    if not isinstance(msg, (bytes, bytearray)):
        return False
    try:
        dom = _ph_dom(context)
    except (TypeError, ValueError):
        return False
    pub, sig, msg = bytes(pub), bytes(sig), bytes(msg)
    try:
        A = _decode_point(pub)
        R = _decode_point(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    ph = hashlib.sha512(msg).digest()
    k = int.from_bytes(hashlib.sha512(dom + sig[:32] + pub + ph).digest(),
                       "little") % _L
    lhs = _scalarmult(_B, s)
    rhs = _add(R, _scalarmult(A, k))
    return _encode_point(lhs) == _encode_point(rhs)


# ---------------------------------------------------------------------------
# RFC 8032, section 7.3, TEST 1 for Ed25519ph (empty context).
# (Values cross-checked against the RFC text; the ph self-test below
# pins them byte-exact.)
RFC8032_PH_VECTORS = (
    {
        "sk": "833fe62409237b9d62ec77587520911e"
              "9a759cec1d19755b7da901b96dca3d42",
        "pk": "ec172b93ad5e563bf4932c70e1245034"
              "c35467ef2efd4d64ebf819683467e2bf",
        "msg": "616263",
        "sig": "98a70222f0b8121aa9d30f813d683f80"
               "9e462b469c7ff87639499bb94e6dae41"
               "31f85042463c2a355a2003d062adf5aa"
               "a10b8c61e636062aaad11c2a26083406",
    },
)


def rfc8032_ph_selftest():
    """Validate sign_ph/verify_ph against the RFC 8032 section 7.3
    TEST 1 vector: pubkey derivation, byte-exact deterministic
    signature, and verification (plus a wrong-context refusal)."""
    for i, v in enumerate(RFC8032_PH_VECTORS, 1):
        sk = bytes.fromhex(v["sk"])
        pk = bytes.fromhex(v["pk"])
        msg = bytes.fromhex(v["msg"])
        sig = bytes.fromhex(v["sig"])
        assert publickey(sk) == pk, "PH TEST %d: pubkey mismatch" % i
        got = sign_ph(sk, msg)
        assert got == sig, "PH TEST %d: signature mismatch" % i
        assert verify_ph(pk, msg, sig), "PH TEST %d: verify failed" % i
        # Domain separation is real: a non-empty context must NOT verify
        # a signature minted with the empty context.
        assert not verify_ph(pk, msg, sig, context=b"other"), \
            "PH TEST %d: context not separated" % i
        # ... and ph signatures are not pure signatures.
        assert not verify(pk, msg, sig), \
            "PH TEST %d: pure verifier accepted ph sig" % i
    return True


# ---------------------------------------------------------------------------
# RFC 8032, section 7.1, test vectors for Ed25519 (pages 23-24). Private and
# public keys are 32 octets; signatures 64 octets; hex-encoded in the RFC.
RFC8032_VECTORS = (
    {  # TEST 1 -- empty message
        "sk": "9d61b19deffd5a60ba844af492ec2cc4"
              "4449c5697b326919703bac031cae7f60",
        "pk": "d75a980182b10ab7d54bfed3c964073a"
              "0ee172f3daa62325af021a68f707511a",
        "msg": "",
        "sig": "e5564300c360ac729086e2cc806e828a"
               "84877f1eb8e5d974d873e06522490155"
               "5fb8821590a33bacc61e39701cf9b46b"
               "d25bf5f0595bbe24655141438e7a100b",
    },
    {  # TEST 2 -- 1-byte message 0x72
        "sk": "4ccd089b28ff96da9db6c346ec114e0f"
              "5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pk": "3d4017c3e843895a92b70aa74d1b7ebc"
              "9c982ccf2ec4968cc0cd55f12af4660c",
        "msg": "72",
        "sig": "92a009a9f0d4cab8720e820b5f642540"
               "a2b27b5416503f8fb3762223ebdb69da"
               "085ac1e43e15996e458f3613d0f11d8c"
               "387b2eaeb4302aeeb00d291612bb0c00",
    },
)


def rfc8032_selftest():
    """Validate against the RFC 8032 vectors: pubkey derivation, byte-exact
    deterministic signatures, and verification."""
    for i, v in enumerate(RFC8032_VECTORS, 1):
        sk = bytes.fromhex(v["sk"])
        pk = bytes.fromhex(v["pk"])
        msg = bytes.fromhex(v["msg"])
        sig = bytes.fromhex(v["sig"])
        assert publickey(sk) == pk, "TEST %d: pubkey mismatch" % i
        assert sign(sk, msg) == sig, "TEST %d: signature mismatch" % i
        assert verify(pk, msg, sig), "TEST %d: verify failed" % i
    return True


if __name__ == "__main__":
    rfc8032_selftest()
    print("ed25519: RFC 8032 section 7.1 vectors pass "
          "(pubkey, byte-exact sign, verify)")
