"""Sasanam signer interop: cosign sign-side negative interop pin (W243-1).

cosign's sign-side SHA-256 hardcode (keys.go:163 -- a P-521 ECDSA signer
constructed with HashFunc SHA-256) is a durable, indefinite constraint:
issue #5029 is closed-unmerged (verified 2026-09-30T06:39:41Z), #5018 is
open/frozen, zero replacement fix PRs exist, and #5074 (the Ed25519
sign-side fix champion) is open and unmerged -- tracked, never depended
on. Sasanam pins the constraint itself, loudly, not in silence.
Patterns only; no upstream code is read, imported, or vendored.

Two roles:

1. ``MimicSignerVerifierKeypair`` -- a re-derivation of the upstream
   bug for the battery: the signer is hardcoded to SHA-256. The bundle
   path (the ``WithDigest`` equivalent -- a caller-supplied digest) on
   P-521 with a 64-byte SHA-512 digest fails LOUD with the Go
   crypto/ecdsa text::

       crypto/ecdsa: unexpected length of digest for hash function specified

   (raised by Go's crypto/ecdsa SignASN1 since Go 1.19 when
   ``len(digest) != opts.HashFunc().Size()``). The legacy path (hash
   the payload with SHA-256, sign) succeeds SILENTLY -- the dangerous
   divergence this lane pins. The mimic is a test tripwire: it flips
   when upstream fixes the hardcode.

2. The Sasanam wrapper -- ``sign_payload_paired`` /
   ``sign_digest_paired`` -- which always pairs the ``WithDigest``
   equivalent with the ``WithCryptoSignerOpts`` equivalent and refuses
   LOUDLY, with mapped refusal codes, instead of silently downshifting:

   - ``signer-digest-length-mismatch``: the digest length does not
     match the stated hash's digest size (the exact loud failure).
   - ``signer-hash-downshift-refused``: a (curve, hash) pairing that
     reproduces the bug shape (P-521 with SHA-256) is refused even
     when the length is exact.

   Pairing policy (documented decision, not upstream behavior): P-256
   pairs with SHA-256 only (matches cosign's hardcoded behavior and
   FIPS 186-5 guidance for P-256); P-521 pairs with SHA-384/SHA-512
   (SHA-256 on P-521 is the bug shape -- refused, never silently
   accepted).

Implementation status -- read before deploying:

* The ECDSA here is a TEST-GRADE pure-Python re-derivation written
  solely to reproduce the sign-side failure mode in a $0, stdlib-only
  battery. It is NOT production signing crypto: non-constant-time
  field arithmetic, ``secrets``-drawn (not RFC 6979) nonces, no
  side-channel hardening. It must never be used to produce
  trust-bearing signatures; the product's trust-bearing signatures
  remain Ed25519 via ``gov.ed25519``. Curve parameters were extracted
  from OpenSSL 3.0.13's secp521r1/secp256r1 (authoritative, no
  hand transcription) and the module self-checks them at import
  (on-curve check plus n*G == O for both curves), so a parameter
  error fails closed instead of silently testing the wrong curve.
* Upstream state is pinned as of 2026-09-30 in ``UPSTREAM_STATUS``;
  when upstream moves (#5074 merging, a #5029 replacement), the
  mimic -- not this policy -- must be updated.

Stdlib only. $0 spend. Deterministic apart from fresh key material
(keys are never asserted byte-equal).
"""

import hashlib
import secrets

# ---------------------------------------------------------------------------
# Upstream state (pinned 2026-09-30; the tripwire the battery watches)
# ---------------------------------------------------------------------------

UPSTREAM_STATUS = {
    "#5029": ("closed-unmerged 2026-09-30T06:39:41Z "
              "(sign-side SHA-256 hardcode fix path dead)"),
    "#5018": "open/frozen (non-SHA-256-natural KMS keys; no fix PR)",
    "#5074": ("open/unmerged 2026-09-25 (Ed25519 sign-side fix champion; "
              "track, do not depend)"),
}

#: The Go crypto/ecdsa failure text pinned by this lane.
GO_DIGEST_LENGTH_ERROR = (
    "crypto/ecdsa: unexpected length of digest for hash function specified"
)

#: Upstream bug location pinned by this lane.
UPSTREAM_BUG_LOCATION = "keys.go:163 (P-521 signer hardcoded to SHA-256)"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SignerInteropError(Exception):
    """Fail-closed signer-interop refusal. ``code`` is the vocabulary."""

    def __init__(self, code, detail=""):
        super(SignerInteropError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Test-grade pure-Python ECDSA (P-256, P-521)
#
# NOT production crypto. See the module docstring. The import-time
# self-check (n*G == O) fails closed on any parameter transcription
# error.
# ---------------------------------------------------------------------------

def _hex(s):
    return int(s.replace(" ", ""), 16)


_CURVES = {
    "P-256": {
        "p": _hex("FFFFFFFF00000001000000000000000000000000"
                  "FFFFFFFFFFFFFFFFFFFFFFFF"),
        "a": _hex("FFFFFFFF00000001000000000000000000000000"
                  "FFFFFFFFFFFFFFFFFFFFFFFC"),
        "b": _hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0"
                  "CC53B0F63BCE3C3E27D2604B"),
        "gx": _hex("6B17D1F2E12C4247F8BCE6E563A440F277037D81"
                   "2DEB33A0F4A13945D898C296"),
        "gy": _hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE3357"
                   "6B315ECECBB6406837BF51F5"),
        "n": _hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAAD"
                  "A7179E84F3B9CAC2FC632551"),
    },
    "P-521": {
        "p": _hex(
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffff"
        ),
        "a": _hex(
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffffffc"
        ),
        "b": _hex(
            "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489"
            "918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34"
            "f1ef451fd46b503f00"
        ),
        "gx": _hex(
            "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828"
            "af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a"
            "429bf97e7e31c2e5bd66"
        ),
        "gy": _hex(
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817af"
            "bd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272"
            "c24088be94769fd16650"
        ),
        "n": _hex(
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c"
            "47aebb6fb71e91386409"
        ),
    },
}


def _point_add(P, Q, curve):
    if P is None:
        return Q
    if Q is None:
        return P
    p = curve["p"]
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + curve["a"]) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _scalar_mul(k, P, curve):
    R = None
    while k:
        if k & 1:
            R = _point_add(R, P, curve)
        P = _point_add(P, P, curve)
        k >>= 1
    return R


def _check_curve(name, curve):
    p = curve["p"]
    gx, gy = curve["gx"], curve["gy"]
    # On-curve check.
    assert (gy * gy - (gx * gx * gx + curve["a"] * gx + curve["b"])) \
        % p == 0, "%s generator not on curve" % name
    # Order check: n*G == O.
    assert _scalar_mul(curve["n"], (gx, gy), curve) is None, \
        "%s order check failed" % name


for _name, _curve in _CURVES.items():
    _check_curve(_name, _curve)
del _name, _curve


def _der_encode(r, s):
    def _enc_int(x):
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + _enc_len(len(b)) + b

    def _enc_len(n):
        if n < 128:
            return bytes((n,))
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes((0x80 | len(b),)) + b

    body = _enc_int(r) + _enc_int(s)
    return b"\x30" + _enc_len(len(body)) + body


def _der_decode(sig):
    def _read_len(buf, i):
        first = buf[i]
        i += 1
        if first < 128:
            return first, i
        count = first & 0x7F
        n = int.from_bytes(buf[i:i + count], "big")
        return n, i + count

    def _read_int(buf, i):
        assert buf[i] == 0x02, "DER: expected INTEGER"
        n, i = _read_len(buf, i + 1)
        val = int.from_bytes(buf[i:i + n], "big")
        return val, i + n

    assert sig[0] == 0x30, "DER: expected SEQUENCE"
    total, i = _read_len(sig, 1)
    assert i + total == len(sig), "DER: trailing bytes"
    r, i = _read_int(sig, i)
    s, i = _read_int(sig, i)
    assert i == len(sig), "DER: trailing bytes"
    return r, s


def _keygen(curve_name):
    curve = _CURVES[curve_name]
    n = curve["n"]
    d = secrets.randbelow(n - 1) + 1
    q = _scalar_mul(d, (curve["gx"], curve["gy"]), curve)
    return d, q


def _ecdsa_sign(d, digest, curve_name):
    curve = _CURVES[curve_name]
    n = curve["n"]
    nbits = n.bit_length()
    e = int.from_bytes(digest, "big") >> max(0, 8 * len(digest) - nbits)
    while True:
        k = secrets.randbelow(n - 1) + 1
        x1, _y1 = _scalar_mul(k, (curve["gx"], curve["gy"]), curve)
        r = x1 % n
        if r == 0:
            continue
        s = (pow(k, n - 2, n) * (e + d * r)) % n
        if s == 0:
            continue
        return _der_encode(r, s)


def _ecdsa_verify(q, digest, sig_der, curve_name):
    curve = _CURVES[curve_name]
    n = curve["n"]
    nbits = n.bit_length()
    try:
        r, s = _der_decode(sig_der)
    except (AssertionError, IndexError, ValueError):
        return False
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(digest, "big") >> max(0, 8 * len(digest) - nbits)
    w = pow(s, n - 2, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    g = (curve["gx"], curve["gy"])
    p1 = _scalar_mul(u1, g, curve)
    p2 = _scalar_mul(u2, q, curve)
    pt = _point_add(p1, p2, curve)
    if pt is None:
        return False
    return (pt[0] % n) == r


# ---------------------------------------------------------------------------
# The upstream-bug mimic: SignerVerifierKeypair with the SHA-256 hardcode
# ---------------------------------------------------------------------------

#: The upstream hardcoded hash (keys.go:163), pinned by the mimic.
HARDCODED_HASH = "sha256"

_HASH_DIGEST_SIZE = {"sha256": 32, "sha384": 48, "sha512": 64}

#: Documented pairing policy: which hashes a curve may be signed with.
#: P-256/SHA-256 matches cosign's hardcoded behavior; P-521/SHA-256
#: is the bug shape and is refused, never silently accepted.
_CURVE_HASH_POLICY = {
    "P-256": ("sha256",),
    "P-521": ("sha384", "sha512"),
}


class MimicSignerVerifierKeypair(object):
    """Re-derivation of cosign's sign-side SHA-256 hardcode.

    Test-only tripwire: the bundle path (``sign_with_digest``) fails
    LOUD with the Go crypto/ecdsa text when the digest length does not
    match the hardcoded SHA-256 (32 bytes); the legacy path
    (``sign_legacy``) hashes with SHA-256 and signs SILENTLY. Neither
    path is production crypto (see the module docstring).
    """

    hardcoded_hash = HARDCODED_HASH

    def __init__(self, curve="P-521"):
        if curve not in _CURVES:
            raise ValueError("unknown curve %r" % (curve,))
        self.curve = curve
        self._d, self._q = _keygen(curve)
        # Recorded for the divergence probe: the legacy path's digest.
        self.legacy_digest_hash = HARDCODED_HASH

    def sign_legacy(self, payload):
        """The silent path: hash with hardcoded SHA-256, sign, no error."""
        digest = hashlib.sha256(payload).digest()
        return _ecdsa_sign(self._d, digest, self.curve)

    def verify_legacy(self, payload, sig_der):
        return _ecdsa_verify(self._q, hashlib.sha256(payload).digest(),
                             sig_der, self.curve)

    def sign_with_digest(self, digest):
        """The bundle (WithDigest) path: fails LOUD on length mismatch.

        Reproduces Go's ``crypto/ecdsa: unexpected length of digest
        for hash function specified`` (SignASN1 since Go 1.19).
        """
        expected = _HASH_DIGEST_SIZE[self.hardcoded_hash]
        if len(digest) != expected:
            err = SignerInteropError(
                "mimic-digest-length-mismatch",
                "%s (digest %d bytes, %s expects %d)"
                % (GO_DIGEST_LENGTH_ERROR, len(digest),
                   self.hardcoded_hash, expected))
            err.digest_len = len(digest)
            err.expected_len = expected
            raise err
        return _ecdsa_sign(self._d, digest, self.curve)

    def verify_with_digest(self, digest, sig_der):
        return _ecdsa_verify(self._q, digest, sig_der, self.curve)

    def public_point(self):
        return self._q


# ---------------------------------------------------------------------------
# The Sasanam wrapper: always pair WithDigest with WithCryptoSignerOpts
# ---------------------------------------------------------------------------

def _check_pairing(digest, hash_name, curve):
    """Length gate first (exact Go-shape failure), then pairing gate.

    Raises SignerInteropError with a mapped refusal code. Never
    silently downshifts.
    """
    if hash_name not in _HASH_DIGEST_SIZE:
        raise ValueError("unknown hash %r" % (hash_name,))
    if curve not in _CURVES:
        raise ValueError("unknown curve %r" % (curve,))
    if not isinstance(digest, (bytes, bytearray)):
        raise ValueError("digest must be bytes")
    expected = _HASH_DIGEST_SIZE[hash_name]
    if len(digest) != expected:
        raise SignerInteropError(
            "signer-digest-length-mismatch",
            "%s (digest %d bytes, %s expects %d on %s)"
            % (GO_DIGEST_LENGTH_ERROR, len(digest), hash_name,
               expected, curve))
    if hash_name not in _CURVE_HASH_POLICY[curve]:
        raise SignerInteropError(
            "signer-hash-downshift-refused",
            "%s with %s reproduces the cosign sign-side hardcode shape "
            "(%s); refused loudly, never silently downshifted"
            % (curve, hash_name, UPSTREAM_BUG_LOCATION))


def sign_digest_paired(digest, hash_name, curve="P-521",
                       private_scalar=None):
    """Sign a caller-supplied digest with the stated hash, paired.

    Refuses ``signer-digest-length-mismatch`` when the digest length
    does not match the hash (the loud Go-shape failure), and
    ``signer-hash-downshift-refused`` when the (curve, hash) pairing
    is the bug shape. Returns a signed record.
    """
    _check_pairing(digest, hash_name, curve)
    if private_scalar is None:
        d, q = _keygen(curve)
    else:
        d = private_scalar
        q = _scalar_mul(d, (_CURVES[curve]["gx"], _CURVES[curve]["gy"]),
                        _CURVES[curve])
    sig = _ecdsa_sign(d, bytes(digest), curve)
    return {
        "curve": curve,
        "hash": hash_name,
        "digest_hex": bytes(digest).hex(),
        "sig_der_hex": sig.hex(),
        "pub_x_hex": "%x" % q[0],
        "pub_y_hex": "%x" % q[1],
    }


def sign_payload_paired(payload, hash_name="sha512", curve="P-521",
                        private_scalar=None):
    """Hash the payload with the stated hash and sign, paired.

    The digest length is exact by construction, so only the pairing
    gate can fire: P-521 with SHA-256 refuses
    ``signer-hash-downshift-refused`` loudly instead of silently
    downshifting the way the upstream legacy path does.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("payload must be bytes")
    digest = hashlib.new(hash_name, bytes(payload)).digest()
    return sign_digest_paired(digest, hash_name, curve,
                              private_scalar=private_scalar)


def verify_record(record):
    """Verify a signed record. Returns True/False; never raises."""
    try:
        curve = record["curve"]
        hash_name = record["hash"]
        digest = bytes.fromhex(record["digest_hex"])
        sig = bytes.fromhex(record["sig_der_hex"])
        q = (int(record["pub_x_hex"], 16), int(record["pub_y_hex"], 16))
        if curve not in _CURVES or hash_name not in _HASH_DIGEST_SIZE:
            return False
        if len(digest) != _HASH_DIGEST_SIZE[hash_name]:
            return False
        return _ecdsa_verify(q, digest, sig, curve)
    except (KeyError, ValueError, TypeError, AssertionError):
        return False
