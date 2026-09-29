"""TEE attestation verifiers: AMD SEV-SNP + Intel TDX DCAP.

Offline, stdlib-only verifiers behind the ``GOV_TEE_ATTEST_ENABLED`` flag
(default OFF). Two verifiers:

  SEV-SNP -- parses a fixed 1184-byte ATTESTATION_REPORT (synthetic subset
      of the AMD SEV-SNP Firmware ABI Table 20 layout), chains
      ARK -> ASK -> VCEK to a pinned ARK public key, checks that the VCEK
      certificate binds the report's REPORTED_TCB and CHIP_ID, and verifies
      the P-384 ECDSA report signature over the first 0x2A0 bytes. The
      signature's R and S are 72-byte LITTLE-endian scalars -- a
      big-endian reader gets silently wrong scalars and fails closed.
  Intel TDX -- parses a synthetic DCAP Quote (48-byte header + 584-byte
      quote body + ECDSA-P256 authentication data), enforces the three-hop
      binding: (a) the QE Report is signed by the PCK key, which chains to
      the pinned Intel root; (b) the QE Report's report_data equals
      SHA-256(attestation key || QE auth data) -- without this hop the
      attestation key is an unattached peer-supplied key; (c) the quote
      body is signed by the attestation key. A local 1024-byte TDREPORT
      (MAC-authenticated to the platform only) is refused categorically
      on the remote path, even when its fields match.

REPORT_DATA binding (both): REPORT_DATA = JWK_thumbprint(tee_public_key)
|| random_salt, exactly 64 bytes (RFC 7638 thumbprint). The salt is the
single-use bootstrap challenge nonce, so freshness and key-binding are
one field; the verifier checks the construction byte-exactly.

Trust anchors are pinned keys, never fetched metadata. Collateral
(certificates, TCB info) is caller-supplied bytes -- there is no ambient
network fetch, and a missing collateral bundle refuses loudly. Intel TCB
info carries a validity window that is checked, not assumed.

The ECDSA implementation is test-grade (double-and-add, NOT
constant-time) -- the same honesty as wave-204's stdlib RSA verifier.
It exists so fixtures and verifiers run on stdlib alone; it is not a
hardened cryptographic library.

Composition:
  * ``attested_identity.Attester(tee_verifier=...)`` +
    ``bootstrap_with_tee_report`` mints a tier-1 credential whose claims
    carry the TEE platform/measurement; the REPORT_DATA salt must equal
    the single-use challenge nonce.
  * ``attach_tee_proof`` records "platform:..., measurement:..." on a
    WITHIN AuthorityProof's detail. A TEE proof is *supported* evidence
    only: attaching to any other verdict refuses loudly -- attestation
    never upgrades a denial.
  * ``tee_bom_section`` builds the additive Decision-BOM section binding
    a decision to the TEE evidence digest.

Honest residuals (do not silently rely on more than this):
  - No TEE hardware was touched; every fixture is synthetic and labeled
    as such. Live VCEK/PCK chain interop is unproven.
  - TEE attestation binds platform + image, never workload behavior.
  - The TCB allowlist is operator-owned; a stale list attests old
    firmware. TDX collateral freshness is checked against the
    caller-supplied TCB-info window, which itself must be kept fresh.
  - The P-384/P-256 ECDSA here is not constant-time and not audited;
    production should use a vetted library.
  - AGPL trap respected: no real TDX quote fixtures are copied from
    anywhere (edgelesssys/go-tdx-qpl bytes are AGPL-3.0). All fixtures
    are generated in-process by the make_*_fixture makers below.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time

from dataclasses import replace as _dc_replace

from . import authority_proof as _ap


# ------------------------------------------------------------------ errors

class TeeAttestError(Exception):
    """Base for every TEE-attestation failure. Fail-closed: callers treat
    any subclass as refusal."""


class FlagDisabledError(TeeAttestError):
    """A verify call was made while the TEE_ATTEST flag is off."""


class ReportFormatError(TeeAttestError):
    """Report/quote bytes malformed, wrong size, or a local/self-asserted
    report presented on the remote path."""


class ChainError(TeeAttestError):
    """Certificate chain or signature does not chain to the pinned root."""


class BindingError(TeeAttestError):
    """A key/report binding (QE three-hop, REPORT_DATA) does not hold."""


class PolicyError(TeeAttestError):
    """Measurement, POLICY, TCB allowlist, or collateral freshness check
    failed."""


# ------------------------------------------------------------------ flag gate

#: Environment flag enabling the TEE verifiers. Default OFF; the value
#: must be an explicit opt-in ("1", "true", "yes").
TEE_ATTEST_FLAG = "GOV_TEE_ATTEST_ENABLED"


def _parse_flag(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return False


def is_enabled(explicit=None):
    """Whether TEE attestation verification is enabled.

    ``explicit`` overrides the environment when not None. Defaults to
    OFF: attestation verification must be opted into.
    """
    if explicit is not None:
        return _parse_flag(explicit)
    return _parse_flag(os.environ.get(TEE_ATTEST_FLAG, ""))


def _require_enabled(enabled):
    if not enabled:
        raise FlagDisabledError(
            "TEE attestation is disabled: set %s=1 (or pass enabled=True) "
            "to opt in" % TEE_ATTEST_FLAG)


# ------------------------------------------------------- EC math (test-grade)

class _Curve(object):
    """Short-Weierstrass curve parameters (public domain constants)."""

    def __init__(self, name, p, a, b, gx, gy, n, h, coord_len, hash_name):
        self.name = name
        self.p = p
        self.a = a
        self.b = b
        self.gx = gx
        self.gy = gy
        self.n = n
        self.h = h
        self.coord_len = coord_len
        self.hash_name = hash_name

    @property
    def point_len(self):
        return 1 + 2 * self.coord_len


P256 = _Curve(
    # n cross-checked against OpenSSL's compiled-in prime256v1 table
    # (openssl ecparam -name prime256v1 -param_enc explicit -text).
    "P-256",
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    h=1, coord_len=32, hash_name="sha256")

P384 = _Curve(
    # Parameters from OpenSSL's compiled-in secp384r1 table
    # (openssl ecparam -name secp384r1 -param_enc explicit -text):
    # the generator and b values were previously mistyped from memory
    # (truncated hex) and the on-curve check caught it.
    "P-384",
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    a=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
    b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
    n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
    h=1, coord_len=48, hash_name="sha384")

_CURVES = {"P-256": P256, "P-384": P384}


def _curve(name):
    try:
        return _CURVES[name]
    except KeyError:
        raise TeeAttestError("unknown curve %r" % (name,))


def _point_add(curve, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    p = curve.p
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        return _point_double(curve, P)
    lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _point_double(curve, P):
    if P is None:
        return None
    x1, y1 = P
    p = curve.p
    if y1 % p == 0:
        return None
    lam = ((3 * x1 * x1 + curve.a) * pow(2 * y1, -1, p)) % p
    x3 = (lam * lam - 2 * x1) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _point_mul(curve, k, P):
    """Double-and-add scalar multiplication. NOT constant-time."""
    if k % curve.n == 0 or P is None:
        return None
    R = None
    addend = P
    while k:
        if k & 1:
            R = _point_add(curve, R, addend)
        addend = _point_double(curve, addend)
        k >>= 1
    return R


def _point_on_curve(curve, point):
    try:
        x, y = point
    except (TypeError, ValueError):
        return False
    p = curve.p
    if not (0 <= x < p and 0 <= y < p):
        return False
    return (y * y - (x * x * x + curve.a * x + curve.b)) % p == 0


def _point_from_bytes(curve, raw):
    """Parse an uncompressed point (0x04 || x || y). Fail-closed."""
    raw = bytes(raw)
    if len(raw) != curve.point_len or raw[0] != 0x04:
        raise ReportFormatError(
            "malformed %s public key: expected %d-byte uncompressed point"
            % (curve.name, curve.point_len))
    L = curve.coord_len
    point = (int.from_bytes(raw[1:1 + L], "big"),
             int.from_bytes(raw[1 + L:1 + 2 * L], "big"))
    if not _point_on_curve(curve, point):
        raise ReportFormatError(
            "malformed %s public key: point not on curve" % curve.name)
    return point


def _point_to_bytes(curve, point):
    if not _point_on_curve(curve, point):
        raise TeeAttestError("refusing to encode an off-curve point")
    L = curve.coord_len
    return (b"\x04" + point[0].to_bytes(L, "big")
            + point[1].to_bytes(L, "big"))


def _truncate_digest(curve, digest):
    e = int.from_bytes(bytes(digest), "big")
    excess = len(digest) * 8 - curve.n.bit_length()
    if excess > 0:
        e >>= excess
    return e


def ecdsa_sign(curve, priv, digest):
    """ECDSA sign (fixture-only). ``priv`` is an int, ``digest`` bytes.

    Test-grade: secrets-based random k, not constant-time. The verifier
    under test is :func:`ecdsa_verify`; this exists so fixtures run on
    stdlib alone.
    """
    n = curve.n
    if not isinstance(priv, int) or not 1 <= priv < n:
        raise TeeAttestError("bad ECDSA private key")
    e = _truncate_digest(curve, digest)
    G = (curve.gx, curve.gy)
    while True:
        k = secrets.randbelow(n - 1) + 1
        R = _point_mul(curve, k, G)
        r = R[0] % n
        if r == 0:
            continue
        s = (pow(k, -1, n) * (e + r * priv)) % n
        if s == 0:
            continue
        return (r, s)


def ecdsa_verify(curve, point, digest, r, s):
    """ECDSA verify. Returns bool, never raises: fail-closed predicate."""
    try:
        n = curve.n
        if not isinstance(r, int) or not isinstance(s, int):
            return False
        if not 1 <= r < n or not 1 <= s < n:
            return False
        if not _point_on_curve(curve, point):
            return False
        e = _truncate_digest(curve, digest)
        w = pow(s, -1, n)
        u1 = (e * w) % n
        u2 = (r * w) % n
        G = (curve.gx, curve.gy)
        R = _point_add(curve, _point_mul(curve, u1, G),
                       _point_mul(curve, u2, point))
        if R is None:
            return False
        return R[0] % n == r
    except Exception:
        return False


def gen_keypair(curve_name):
    """Generate a (priv_int, point_bytes) pair. Fixture-only."""
    curve = _curve(curve_name)
    priv = secrets.randbelow(curve.n - 1) + 1
    point = _point_mul(curve, priv, (curve.gx, curve.gy))
    return priv, _point_to_bytes(curve, point)


def _sha256(data):
    return hashlib.sha256(bytes(data)).digest()


def _sha384(data):
    return hashlib.sha384(bytes(data)).digest()


# --------------------------------------------- JWK thumbprint + REPORT_DATA

def _b64u_encode(raw):
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def _canonical_json(doc):
    return json.dumps(doc, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def point_to_jwk(curve_name, point_bytes):
    """Build the RFC 7517 JWK dict for an uncompressed EC point."""
    curve = _curve(curve_name)
    raw = bytes(point_bytes)
    if len(raw) != curve.point_len or raw[0] != 0x04:
        raise ReportFormatError(
            "malformed %s key for JWK conversion" % curve.name)
    L = curve.coord_len
    return {"crv": curve.name, "kty": "EC",
            "x": _b64u_encode(raw[1:1 + L]),
            "y": _b64u_encode(raw[1 + L:1 + 2 * L])}


def jwk_thumbprint(curve_name, point_bytes):
    """RFC 7638 JWK SHA-256 thumbprint (32 bytes)."""
    return _sha256(_canonical_json(point_to_jwk(curve_name, point_bytes)))


def report_data_for(curve_name, tee_point_bytes, salt):
    """The REPORT_DATA construction: JWK_thumbprint(tee_pubkey) || salt.

    Exactly 64 bytes. ``salt`` must be 32 bytes -- in the bootstrap
    ceremony it is the single-use challenge nonce, so freshness and
    key-binding are one field.
    """
    if not isinstance(tee_point_bytes, (bytes, bytearray)):
        raise BindingError("REPORT_DATA tee key must be bytes")
    salt = salt if isinstance(salt, (bytes, bytearray)) else None
    if salt is None or len(salt) != 32:
        raise BindingError(
            "REPORT_DATA salt must be 32 bytes, got %r"
            % (None if salt is None else len(salt)))
    return jwk_thumbprint(curve_name, tee_point_bytes) + bytes(salt)


# ----------------------------------------------------------------- SEV-SNP

#: Fixed ATTESTATION_REPORT size (0x4A0).
SNP_REPORT_SIZE = 1184
#: Bytes covered by the report signature (0x2A0).
SNP_SIGNED_SIZE = 0x2A0
#: Offset of the 512-byte signature blob.
SNP_SIG_OFFSET = 0x2A0
#: Size of the signature blob; R = blob[0:72] LE, S = blob[72:144] LE.
SNP_SIG_BLOB = 512
#: Offset of the 64-byte REPORT_DATA field (Table 20: 0x50).
SNP_REPORT_DATA = 0x50
#: Offset of the 48-byte MEASUREMENT field (Table 20: 0x90).
SNP_MEASUREMENT = 0x90
#: Offset of the 8-byte REPORTED_TCB field (Table 20: 0x180).
SNP_REPORTED_TCB = 0x180
#: Offset of the 64-byte CHIP_ID field (Table 20: 0x1A0).
SNP_CHIP_ID = 0x1A0

#: VERSION value our synthetic reports carry.
SNP_VERSION = 2
#: SIGNATURE_ALGO value meaning ECDSA_P384_SHA384.
SNP_SIG_ALGO_ECDSA_P384_SHA384 = 1


def _b64u_decode_pubkey(curve, encoded, what):
    """Decode a base64url public key from a synthetic cert. Fail-closed:
    malformed encoding refuses as a chain error, never a raw ValueError."""
    if not isinstance(encoded, str):
        raise ChainError("%s certificate pubkey is not a string" % what)
    try:
        raw = base64.urlsafe_b64decode(
            encoded + "=" * (-len(encoded) % 4))
    except (ValueError, TypeError):
        raise ChainError(
            "%s certificate pubkey is not valid base64url" % what)
    return _point_from_bytes(curve, raw)


def _snp_cert_body(subject, point_bytes, tcb, chip_id):
    return {"subject": subject,
            "pubkey": _b64u_encode(point_bytes),
            "tcb": bytes(tcb).hex(),
            "chip_id": bytes(chip_id).hex()}


def _snp_sign_cert(body, issuer_priv):
    digest = _sha384(_canonical_json(body))
    r, s = ecdsa_sign(P384, issuer_priv, digest)
    cert = dict(body)
    cert["sig_r"] = format(r, "x")
    cert["sig_s"] = format(s, "x")
    return cert


def _snp_verify_cert(cert, expected_subject, issuer_point, what):
    if not isinstance(cert, dict):
        raise ChainError("%s certificate malformed: not a dict" % what)
    if cert.get("subject") != expected_subject:
        raise ChainError(
            "%s certificate has wrong subject %r" % (what,
                                                     cert.get("subject")))
    body = {k: cert[k] for k in ("subject", "pubkey", "tcb", "chip_id")
            if k in cert}
    if set(body) != {"subject", "pubkey", "tcb", "chip_id"}:
        raise ChainError("%s certificate missing fields" % what)
    try:
        r = int(cert["sig_r"], 16)
        s = int(cert["sig_s"], 16)
    except (KeyError, ValueError, TypeError):
        raise ChainError("%s certificate has malformed signature" % what)
    digest = _sha384(_canonical_json(body))
    if not ecdsa_verify(P384, issuer_point, digest, r, s):
        raise ChainError(
            "%s certificate signature invalid: does not chain to the "
            "issuer key" % what)
    return body


def make_snp_fixture(*, policy, measurement, tcb, chip_id, salt,
                      ark_priv=None, ark_point=None):
    """Build a synthetic SEV-SNP attestation fixture (labeled synthetic).

    Returns everything the verifier needs plus the trust anchor: the
    1184-byte report, the ASK/VCEK synthetic certificate chain, the
    pinned ARK public key, and the REPORT_DATA-bound TEE key + salt.
    Private keys in the returned dict are fixture-only.
    """
    measurement = bytes(measurement)
    tcb = bytes(tcb)
    chip_id = bytes(chip_id)
    salt = bytes(salt)
    if len(measurement) != 48:
        raise TeeAttestError("SNP measurement must be 48 bytes")
    if len(tcb) != 8:
        raise TeeAttestError("SNP TCB must be 8 bytes")
    if len(chip_id) != 64:
        raise TeeAttestError("SNP chip_id must be 64 bytes")
    if len(salt) != 32:
        raise TeeAttestError("SNP salt must be 32 bytes")
    if not isinstance(policy, int) or isinstance(policy, bool) or policy < 0:
        raise TeeAttestError("SNP policy must be a non-negative int")
    if ark_priv is None:
        if ark_point is not None:
            raise TeeAttestError(
                "ark_point without ark_priv: pass both or neither")
        ark_priv, ark_point = gen_keypair("P-384")
    else:
        if ark_point is None:
            raise TeeAttestError(
                "ark_priv without ark_point: pass both or neither")
        if not isinstance(ark_priv, int):
            raise TeeAttestError("ark_priv must be an int")
        ark_point = bytes(ark_point)
        _point_from_bytes(P384, ark_point)  # validate
    ask_priv, ask_point = gen_keypair("P-384")
    vcek_priv, vcek_point_bytes = gen_keypair("P-384")
    tee_priv, tee_point = gen_keypair("P-384")
    ask_cert = _snp_sign_cert(
        _snp_cert_body("ask", ask_point, tcb, chip_id), ark_priv)
    vcek_cert = _snp_sign_cert(
        _snp_cert_body("vcek", vcek_point_bytes, tcb, chip_id), ask_priv)
    report = bytearray(SNP_REPORT_SIZE)
    struct.pack_into("<I", report, 0, SNP_VERSION)
    struct.pack_into("<I", report, 4, 0)  # GUEST_SVN
    struct.pack_into("<Q", report, 8, policy)  # POLICY
    struct.pack_into("<I", report, 52,
                     SNP_SIG_ALGO_ECDSA_P384_SHA384)  # SIGNATURE_ALGO
    report[SNP_REPORT_DATA:SNP_REPORT_DATA + 64] = report_data_for(
        "P-384", tee_point, salt)
    report[SNP_MEASUREMENT:SNP_MEASUREMENT + 48] = measurement
    report[SNP_REPORTED_TCB:SNP_REPORTED_TCB + 8] = tcb
    report[SNP_CHIP_ID:SNP_CHIP_ID + 64] = chip_id
    digest = _sha384(bytes(report[:SNP_SIGNED_SIZE]))
    r, s = ecdsa_sign(P384, vcek_priv, digest)
    blob = bytearray(SNP_SIG_BLOB)
    blob[0:72] = r.to_bytes(72, "little")
    blob[72:144] = s.to_bytes(72, "little")
    report[SNP_SIG_OFFSET:SNP_SIG_OFFSET + SNP_SIG_BLOB] = blob
    return {"report": bytes(report),
            "ask_cert": ask_cert,
            "vcek_cert": vcek_cert,
            "ark_pubkey": bytes(ark_point),
            "tee_pubkey": bytes(tee_point),
            "salt": salt,
            "policy": policy,
            "measurement": measurement,
            "tcb": tcb,
            "chip_id": chip_id,
            "vcek_point": _point_from_bytes(P384, vcek_point_bytes),
            # Fixture-only private material (never a trust anchor):
            "ark_priv": ark_priv,
            "vcek_priv": vcek_priv,
            "tee_priv": tee_priv}


class SevSnpVerifier(object):
    """Offline SEV-SNP attestation-report verifier (synthetic fixtures).

    ``ark_pubkey`` is the PINNED AMD ARK public key (97-byte uncompressed
    P-384 point): the trust anchor. There is no fetch, no default.
    """

    def __init__(self, *, ark_pubkey, enabled=None):
        self._enabled = is_enabled(enabled)
        self._ark_point = _point_from_bytes(P384, ark_pubkey)

    @property
    def enabled(self):
        return self._enabled

    def verify(self, bundle):
        """Verify a bundle, returning the attested claims dict.

        ``bundle`` carries: ``report`` (1184 bytes), ``ask_cert``,
        ``vcek_cert`` (synthetic cert dicts), ``expected_policy`` (int),
        ``expected_measurement`` (48 bytes), ``tcb_allowlist`` (list of
        8-byte TCB values), ``tee_pubkey`` (97 bytes), ``salt`` (32
        bytes). Raises a :class:`TeeAttestError` subclass on any failure.
        """
        _require_enabled(self._enabled)
        if not isinstance(bundle, dict):
            raise ReportFormatError("SNP bundle must be a dict")
        report = bundle.get("report", b"")
        if not isinstance(report, (bytes, bytearray)):
            raise ReportFormatError("SNP report must be bytes")
        report = bytes(report)
        if len(report) != SNP_REPORT_SIZE:
            raise ReportFormatError(
                "SNP report must be %d bytes, got %d"
                % (SNP_REPORT_SIZE, len(report)))
        version = struct.unpack_from("<I", report, 0)[0]
        if version != SNP_VERSION:
            raise ReportFormatError(
                "SNP report version %d unsupported" % version)
        sig_algo = struct.unpack_from("<I", report, 52)[0]
        if sig_algo != SNP_SIG_ALGO_ECDSA_P384_SHA384:
            raise ReportFormatError(
                "SNP SIGNATURE_ALGO %d unsupported (need ECDSA_P384_SHA384)"
                % sig_algo)
        # Chain: ARK (pinned) -> ASK -> VCEK.
        ask_body = _snp_verify_cert(bundle.get("ask_cert"), "ask",
                                    self._ark_point, "ASK")
        ask_point = _b64u_decode_pubkey(P384, ask_body["pubkey"], "ASK")
        vcek_body = _snp_verify_cert(bundle.get("vcek_cert"), "vcek",
                                     ask_point, "VCEK")
        vcek_point = _b64u_decode_pubkey(P384, vcek_body["pubkey"], "VCEK")
        # The VCEK certificate must bind the report's chip and TCB: a
        # VCEK for another boot is a different key.
        if vcek_body["tcb"] != report[SNP_REPORTED_TCB:
                                      SNP_REPORTED_TCB + 8].hex():
            raise ChainError(
                "VCEK certificate TCB does not match the report's "
                "REPORTED_TCB")
        if vcek_body["chip_id"] != report[SNP_CHIP_ID:SNP_CHIP_ID + 64].hex():
            raise ChainError(
                "VCEK certificate CHIP_ID does not match the report")
        # TCB allowlist: the operator pins which firmware TCBs attest.
        reported_tcb = bytes(report[SNP_REPORTED_TCB:SNP_REPORTED_TCB + 8])
        allow = bundle.get("tcb_allowlist")
        if not isinstance(allow, (list, tuple)) or not allow:
            raise PolicyError("SNP tcb_allowlist must be a non-empty list")
        try:
            allow_bytes = [bytes(t) for t in allow]
        except TypeError:
            raise PolicyError("SNP tcb_allowlist entries must be bytes")
        if not any(t == reported_tcb for t in allow_bytes):
            raise PolicyError(
                "SNP REPORTED_TCB %s not in the operator allowlist "
                "(stale firmware refused)" % reported_tcb.hex())
        # POLICY and MEASUREMENT: exact-match caller expectations.
        policy = struct.unpack_from("<Q", report, 8)[0]
        if policy != bundle.get("expected_policy"):
            raise PolicyError(
                "SNP POLICY 0x%x does not match the expected policy"
                % policy)
        measurement = bytes(report[SNP_MEASUREMENT:SNP_MEASUREMENT + 48])
        expected_measurement = bundle.get("expected_measurement", b"")
        if not isinstance(expected_measurement, (bytes, bytearray)):
            raise PolicyError("SNP expected_measurement must be bytes")
        if not hmac.compare_digest(measurement, bytes(expected_measurement)):
            raise PolicyError("SNP MEASUREMENT does not match the expected "
                              "image measurement")
        # REPORT_DATA binding: JWK_thumbprint(tee_pubkey) || salt.
        expected_rd = report_data_for("P-384", bundle.get("tee_pubkey", b""),
                                      bundle.get("salt", b""))
        if not hmac.compare_digest(
                bytes(report[SNP_REPORT_DATA:SNP_REPORT_DATA + 64]),
                expected_rd):
            raise BindingError(
                "SNP REPORT_DATA does not bind the expected TEE key/salt")
        # Report signature over the first SNP_SIGNED_SIZE bytes. R and S
        # are 72-byte LITTLE-endian scalars; the trailing blob bytes must
        # be zero (strict parse).
        blob = report[SNP_SIG_OFFSET:SNP_SIG_OFFSET + SNP_SIG_BLOB]
        if bytes(blob[144:]) != b"\x00" * (SNP_SIG_BLOB - 144):
            raise ReportFormatError(
                "SNP signature blob has non-zero trailing bytes")
        r = int.from_bytes(bytes(blob[0:72]), "little")
        s = int.from_bytes(bytes(blob[72:144]), "little")
        digest = _sha384(report[:SNP_SIGNED_SIZE])
        if not ecdsa_verify(P384, vcek_point, digest, r, s):
            raise ChainError("SNP report signature invalid: the report "
                             "was not signed by the chained VCEK")
        return {"kind": "sev_snp_attested",
                "platform": "sev-snp",
                "measurement": measurement.hex(),
                "tcb": reported_tcb.hex(),
                "policy": policy,
                "chip_id": bytes(report[SNP_CHIP_ID:SNP_CHIP_ID + 64]).hex(),
                "report_data": bytes(
                    report[SNP_REPORT_DATA:SNP_REPORT_DATA + 64]).hex(),
                "evidence_digest": hashlib.sha256(report).hexdigest()}


# ----------------------------------------------------------------- Intel TDX

#: Quote kind: remote-verifiable DCAP quote.
TDX_KIND_DCAP = 0x01
#: Quote kind: local TDREPORT (platform-MAC only, NOT remotely verifiable).
TDX_KIND_LOCAL = 0x02
#: TEE type value for Intel TDX.
TDX_TEE_TYPE = 0x81

#: DCAP quote header size.
TDX_HEADER_SIZE = 48
#: TD quote body size.
TDX_BODY_SIZE = 584
#: Offset of the quote body.
TDX_BODY_OFFSET = TDX_HEADER_SIZE
#: Offset of MRTD inside the body (real DCAP layout: after the
#: 16-byte TEE_TCB_SVN, MRSEAM/MRSIGNERSEAM, attributes, and XFAM).
TDX_MRTD = 136
#: Offset of RTMR0 inside the body (after MRCONFIGID/MROWNER/
#: MROWNERCONFIG).
TDX_RTMR0 = 328
#: Offset of the 64-byte REPORTDATA inside the body (last field).
TDX_REPORTDATA = 520
#: Offset of the authentication data (right after header+body).
TDX_AUTH_OFFSET = TDX_HEADER_SIZE + TDX_BODY_SIZE
#: Local TDREPORT fixed size.
TDX_LOCAL_SIZE = 1024


def make_pck_cert(pck_priv, pck_point_bytes, *, tcb_hex, issuer_priv):
    """Build a synthetic PCK certificate dict, signed by ``issuer_priv``.

    ``issuer_priv`` is the pinned Intel root key for real chains; passing
    the PCK key itself yields a self-signed (untrusted) cert for negative
    tests.
    """
    body = {"subject": "pck",
            "pubkey": _b64u_encode(pck_point_bytes),
            "tcb": tcb_hex,
            "chip_id": ""}
    digest = _sha256(_canonical_json(body))
    r, s = ecdsa_sign(P256, issuer_priv, digest)
    cert = dict(body)
    cert["sig_r"] = format(r, "x")
    cert["sig_s"] = format(s, "x")
    return cert


def _verify_pck_cert(cert, intel_root_point):
    if not isinstance(cert, dict):
        raise ChainError("PCK certificate malformed: not a dict")
    if cert.get("subject") != "pck":
        raise ChainError("PCK certificate has wrong subject %r"
                         % (cert.get("subject"),))
    body = {k: cert[k] for k in ("subject", "pubkey", "tcb", "chip_id")
            if k in cert}
    if set(body) != {"subject", "pubkey", "tcb", "chip_id"}:
        raise ChainError("PCK certificate missing fields")
    try:
        r = int(cert["sig_r"], 16)
        s = int(cert["sig_s"], 16)
    except (KeyError, ValueError, TypeError):
        raise ChainError("PCK certificate has malformed signature")
    digest = _sha256(_canonical_json(body))
    if not ecdsa_verify(P256, intel_root_point, digest, r, s):
        raise ChainError("PCK certificate signature invalid: does not "
                         "chain to the pinned Intel root")
    return body


def _tdx_qe_report_bytes(qe_report):
    return _canonical_json(qe_report)


def _build_tdx_quote(fx):
    """Serialize the DCAP quote from a fixture dict. Re-signs the QE
    report with the fixture's PCK key and the quote body with the
    fixture's attestation key -- so mutated fixtures rebind honestly."""
    header = bytearray(TDX_HEADER_SIZE)
    header[0] = TDX_KIND_DCAP
    struct.pack_into("<H", header, 1, 4)  # quote version
    struct.pack_into("<I", header, 3, TDX_TEE_TYPE)
    body = bytearray(TDX_BODY_SIZE)
    body[TDX_MRTD:TDX_MRTD + 48] = fx["mrtd"]
    for i in range(4):
        body[TDX_RTMR0 + i * 48:TDX_RTMR0 + (i + 1) * 48] = fx["rtmrs"].get(
            i, b"\x00" * 48)
    body[TDX_REPORTDATA:TDX_REPORTDATA + 64] = report_data_for(
        "P-256", fx["tee_pubkey"], fx["salt"])
    signed = bytes(header) + bytes(body)
    qr, qs = ecdsa_sign(P256, fx["att_priv"], _sha256(signed))
    qe_report_json = _tdx_qe_report_bytes(fx["qe_report"])
    qe_r, qe_s = ecdsa_sign(P256, fx["pck_priv"],
                            _sha256(qe_report_json))
    pck_json = _canonical_json(fx["pck_cert"])
    att_point_bytes = _point_to_bytes(P256, fx["att_point"])
    out = bytearray()
    out += header
    out += body
    out += att_point_bytes
    out += struct.pack("<H", len(fx["qe_auth_data"])) + fx["qe_auth_data"]
    out += struct.pack("<H", len(qe_report_json)) + qe_report_json
    out += qe_r.to_bytes(32, "big") + qe_s.to_bytes(32, "big")
    out += struct.pack("<H", len(pck_json)) + pck_json
    out += qr.to_bytes(32, "big") + qs.to_bytes(32, "big")
    return bytes(out)


def _rebind_tdx_quote(fx):
    """Re-serialize a (possibly mutated) TDX fixture dict into quote
    bytes. Test helper: negative tests mutate qe_report / att_priv /
    att_point and rebuild honestly."""
    return _build_tdx_quote(fx)


def make_tdx_fixture(*, mrtd, rtmrs, tcb_info, salt, now):
    """Build a synthetic TDX DCAP attestation fixture (labeled synthetic).

    Returns the quote bytes, the PCK certificate, the pinned Intel root
    public key, the TCB-info collateral, and the REPORTDATA-bound TEE
    key + salt. Private keys in the returned dict are fixture-only.
    """
    mrtd = bytes(mrtd)
    salt = bytes(salt)
    if len(mrtd) != 48:
        raise TeeAttestError("TDX MRTD must be 48 bytes")
    if len(salt) != 32:
        raise TeeAttestError("TDX salt must be 32 bytes")
    rtmrs = {int(k): bytes(v) for k, v in dict(rtmrs).items()}
    for k, v in rtmrs.items():
        if not 0 <= k <= 3 or len(v) != 48:
            raise TeeAttestError("TDX RTMRs must be {0..3: 48 bytes}")
    tcb_info = dict(tcb_info)
    if not isinstance(tcb_info.get("valid_from"), int) \
            or not isinstance(tcb_info.get("valid_until"), int):
        raise TeeAttestError("TDX tcb_info needs int valid_from/valid_until")
    intel_root_priv, intel_root_point = gen_keypair("P-256")
    pck_priv, pck_point = gen_keypair("P-256")
    att_priv, att_point = gen_keypair("P-256")
    tee_priv, tee_point = gen_keypair("P-256")
    qe_auth = secrets.token_bytes(48)
    pck_cert = make_pck_cert(pck_priv, pck_point, tcb_hex="tcb-fixture",
                             issuer_priv=intel_root_priv)
    fx = {"mrtd": mrtd,
          "rtmrs": rtmrs,
          "tcb_info": tcb_info,
          "salt": salt,
          "now": now,
          "tee_pubkey": tee_point,
          "intel_root_pubkey": intel_root_point,
          "pck_pubkey": pck_point,
          "pck_cert": pck_cert,
          "qe_auth_data": qe_auth,
          "att_point": _point_from_bytes(P256, att_point),
          "qe_report": {"report_data": _sha256(att_point + qe_auth).hex()},
          # Fixture-only private material (never a trust anchor):
          "intel_root_priv": intel_root_priv,
          "pck_priv": pck_priv,
          "att_priv": att_priv,
          "tee_priv": tee_priv}
    fx["quote"] = _build_tdx_quote(fx)
    return fx


def make_synthetic_local_tdreport(*, mrtd, tee_pubkey, salt):
    """Build a synthetic LOCAL TDREPORT (labeled synthetic).

    1024 bytes, kind=TDX_KIND_LOCAL, carrying the same body fields as a
    DCAP quote but authenticated only by a platform MAC that no remote
    verifier can check. The remote TDX verifier must refuse it even
    when every exposed field matches -- self-asserted "I am in a TEE"
    claims never verify on the remote path.
    """
    mrtd = bytes(mrtd)
    if len(mrtd) != 48:
        raise TeeAttestError("TDREPORT MRTD must be 48 bytes")
    buf = bytearray(TDX_LOCAL_SIZE)
    buf[0] = TDX_KIND_LOCAL
    struct.pack_into("<H", buf, 1, 1)
    struct.pack_into("<I", buf, 3, TDX_TEE_TYPE)
    buf[TDX_BODY_OFFSET + TDX_MRTD:TDX_BODY_OFFSET + TDX_MRTD + 48] = mrtd
    buf[TDX_BODY_OFFSET + TDX_REPORTDATA:
        TDX_BODY_OFFSET + TDX_REPORTDATA + 64] = report_data_for(
            "P-256", tee_pubkey, salt)
    mac_key = secrets.token_bytes(32)  # platform-held; remote cannot check
    buf[TDX_LOCAL_SIZE - 32:] = hmac.new(
        mac_key, bytes(buf[:TDX_LOCAL_SIZE - 32]), hashlib.sha256).digest()
    return bytes(buf)


class TdxQuoteVerifier(object):
    """Offline Intel TDX DCAP quote verifier (synthetic fixtures).

    ``intel_root_pubkey`` is the PINNED Intel SGX root CA public key
    (65-byte uncompressed P-256 point): the trust anchor. Collateral
    (PCK cert, TCB info) is caller-supplied on every verify call -- there
    is no ambient network fetch, and missing collateral refuses loudly.
    """

    def __init__(self, *, intel_root_pubkey, enabled=None):
        self._enabled = is_enabled(enabled)
        self._root_point = _point_from_bytes(P256, intel_root_pubkey)

    @property
    def enabled(self):
        return self._enabled

    def _parse_auth(self, quote):
        """Strictly parse the authentication data. Fail-closed."""
        off = TDX_AUTH_OFFSET
        end = len(quote)

        def take(n, what):
            nonlocal off
            if off + n > end:
                raise ReportFormatError(
                    "TDX quote truncated in %s" % what)
            chunk = quote[off:off + n]
            off += n
            return bytes(chunk)

        def take_u16(what):
            return struct.unpack("<H", take(2, what))[0]

        att_point = _point_from_bytes(P256, take(65, "attestation key"))
        qe_auth_len = take_u16("qe_auth_data length")
        qe_auth = take(qe_auth_len, "qe_auth_data")
        qe_report_len = take_u16("qe_report length")
        qe_report_raw = take(qe_report_len, "qe_report")
        try:
            qe_report = json.loads(qe_report_raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ReportFormatError("TDX QE report is not JSON")
        qe_sig = take(64, "qe_report signature")
        pck_len = take_u16("pck_cert length")
        pck_raw = take(pck_len, "pck_cert")
        try:
            pck_cert = json.loads(pck_raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ReportFormatError("TDX PCK cert is not JSON")
        quote_sig = take(64, "quote signature")
        if off != end:
            raise ReportFormatError(
                "TDX quote has %d trailing bytes" % (end - off))
        return {"att_point": att_point,
                "att_point_bytes": quote[TDX_AUTH_OFFSET:
                                         TDX_AUTH_OFFSET + 65],
                "qe_auth_data": qe_auth,
                "qe_report": qe_report,
                "qe_report_raw": qe_report_raw,
                "qe_sig_r": int.from_bytes(qe_sig[0:32], "big"),
                "qe_sig_s": int.from_bytes(qe_sig[32:64], "big"),
                "pck_cert": pck_cert,
                "quote_sig_r": int.from_bytes(quote_sig[0:32], "big"),
                "quote_sig_s": int.from_bytes(quote_sig[32:64], "big")}

    def verify(self, bundle):
        """Verify a bundle, returning the attested claims dict.

        ``bundle`` carries: ``quote`` (DCAP quote bytes), ``pck_cert``
        (dict), ``tcb_info`` ({"valid_from": int, "valid_until": int}),
        ``expected_mrtd`` (48 bytes), ``expected_rtmrs`` (optional
        {0..3: 48 bytes}), ``tee_pubkey`` (65 bytes), ``salt`` (32
        bytes), ``now`` (optional int seconds). Raises a
        :class:`TeeAttestError` subclass on any failure.
        """
        _require_enabled(self._enabled)
        if not isinstance(bundle, dict):
            raise ReportFormatError("TDX bundle must be a dict")
        quote = bundle.get("quote", b"")
        if not isinstance(quote, (bytes, bytearray)):
            raise ReportFormatError("TDX quote must be bytes")
        quote = bytes(quote)
        if len(quote) < 1:
            raise ReportFormatError("TDX quote is empty")
        kind = quote[0]
        # The local/self-asserted path is refused FIRST, before any field
        # is even inspected -- a TDREPORT is MAC'd to the platform quoting
        # component and is not remotely verifiable, even when its exposed
        # fields match.
        if kind == TDX_KIND_LOCAL:
            raise ReportFormatError(
                "local/self-asserted TDX report (TDREPORT) refused on the "
                "remote path: it is platform-MAC'd, not remotely "
                "verifiable")
        if kind != TDX_KIND_DCAP:
            raise ReportFormatError(
                "unknown TDX quote kind 0x%02x" % kind)
        if len(quote) < TDX_AUTH_OFFSET:
            raise ReportFormatError(
                "TDX DCAP quote truncated: %d bytes" % len(quote))
        # Collateral is caller-supplied, never ambiently fetched; missing
        # collateral is a loud refusal (network failure is blocking).
        pck_cert = bundle.get("pck_cert")
        if pck_cert is None:
            raise ChainError("TDX PCK collateral is caller-supplied: none "
                             "provided (no ambient fetch; missing "
                             "collateral refuses)")
        tcb_info = bundle.get("tcb_info")
        if not isinstance(tcb_info, dict):
            raise PolicyError("TDX TCB-info collateral is caller-supplied: "
                              "none provided")
        now = bundle.get("now", int(time.time()))
        if not isinstance(now, int) or isinstance(now, bool):
            raise PolicyError("TDX bundle 'now' must be an int")
        valid_from = tcb_info.get("valid_from")
        valid_until = tcb_info.get("valid_until")
        if not isinstance(valid_from, int) or not isinstance(valid_until,
                                                             int):
            raise PolicyError("TDX tcb_info needs int valid_from/valid_until")
        if not valid_from <= now <= valid_until:
            raise PolicyError(
                "TDX TCB collateral outside its validity window "
                "(valid %d..%d, now %d): freshness must be checked, never "
                "assumed" % (valid_from, valid_until, now))
        # Hop (a): PCK cert chains to the pinned Intel root; the QE
        # Report is signed by the PCK key.
        pck_body = _verify_pck_cert(pck_cert, self._root_point)
        pck_point = _b64u_decode_pubkey(P256, pck_body["pubkey"], "PCK")
        auth = self._parse_auth(quote)
        if not isinstance(auth["qe_report"], dict):
            raise ReportFormatError("TDX QE report malformed")
        if not ecdsa_verify(P256, pck_point,
                            _sha256(auth["qe_report_raw"]),
                            auth["qe_sig_r"], auth["qe_sig_s"]):
            raise ChainError("TDX QE report signature invalid: not signed "
                             "by the chained PCK key")
        # Hop (b): report_data == SHA-256(attestation key || QE auth
        # data). Without this hop the attestation key is an unattached
        # peer-supplied key.
        bound = _sha256(auth["att_point_bytes"] + auth["qe_auth_data"])
        claimed_hex = auth["qe_report"].get("report_data")
        try:
            claimed = bytes.fromhex(claimed_hex) \
                if isinstance(claimed_hex, str) else b""
        except ValueError:
            claimed = b""
        if not hmac.compare_digest(claimed, bound):
            raise BindingError(
                "TDX QE report_data does not bind the attestation key: "
                "SHA-256(attestation key || QE auth data) mismatch (the "
                "attestation key is unattached)")
        # Hop (c): the quote body is signed by the bound attestation key.
        signed = quote[:TDX_AUTH_OFFSET]
        if not ecdsa_verify(P256, auth["att_point"], _sha256(signed),
                            auth["quote_sig_r"], auth["quote_sig_s"]):
            raise BindingError(
                "TDX quote body signature invalid for the QE-bound "
                "attestation key")
        # Measurements and REPORTDATA.
        body = quote[TDX_BODY_OFFSET:TDX_BODY_OFFSET + TDX_BODY_SIZE]
        mrtd = bytes(body[TDX_MRTD:TDX_MRTD + 48])
        expected_mrtd = bundle.get("expected_mrtd", b"")
        if not isinstance(expected_mrtd, (bytes, bytearray)):
            raise PolicyError("TDX expected_mrtd must be bytes")
        if not hmac.compare_digest(mrtd, bytes(expected_mrtd)):
            raise PolicyError("TDX MRTD does not match the expected launch "
                              "measurement")
        rtmrs = {}
        for i in range(4):
            rtmrs[i] = bytes(
                body[TDX_RTMR0 + i * 48:TDX_RTMR0 + (i + 1) * 48]).hex()
        expected_rtmrs = bundle.get("expected_rtmrs") or {}
        if not isinstance(expected_rtmrs, dict):
            raise PolicyError("TDX expected_rtmrs must be a dict")
        for i, want in expected_rtmrs.items():
            if isinstance(i, bool) or not isinstance(i, int) \
                    or not 0 <= i <= 3:
                raise PolicyError(
                    "TDX expected_rtmrs keys must be RTMR indices 0..3")
            if not isinstance(want, (bytes, bytearray)) or len(want) != 48:
                raise PolicyError(
                    "TDX expected RTMR%d must be 48 bytes" % i)
            got = bytes(body[TDX_RTMR0 + i * 48:TDX_RTMR0 + (i + 1) * 48])
            if not hmac.compare_digest(got, bytes(want)):
                raise PolicyError(
                    "TDX RTMR%d does not match the expected runtime "
                    "measurement" % i)
        expected_rd = report_data_for("P-256", bundle.get("tee_pubkey", b""),
                                      bundle.get("salt", b""))
        if not hmac.compare_digest(
                bytes(body[TDX_REPORTDATA:TDX_REPORTDATA + 64]),
                expected_rd):
            raise BindingError(
                "TDX REPORTDATA does not bind the expected TEE key/salt")
        return {"kind": "tdx_attested",
                "platform": "tdx",
                "measurement": mrtd.hex(),
                "rtmrs": rtmrs,
                "report_data": bytes(
                    body[TDX_REPORTDATA:TDX_REPORTDATA + 64]).hex(),
                "evidence_digest": hashlib.sha256(quote).hexdigest()}


# ------------------------------------------------------------ composition

def attach_tee_proof(proof, tee_claims):
    """Attach TEE platform evidence to a WITHIN AuthorityProof.

    Returns a new proof whose detail records
    ``platform:<platform> measurement:<hex>``. A TEE proof is *supported*
    evidence only: attaching to any verdict other than WITHIN refuses
    loudly -- attestation never upgrades a denial.
    """
    if proof.verdict != _ap.WITHIN:
        raise BindingError(
            "TEE attestation never upgrades a denial: refusing to attach "
            "platform evidence to a %s proof" % (proof.verdict,))
    for key in ("platform", "measurement"):
        if not isinstance(tee_claims.get(key), str) or not tee_claims[key]:
            raise BindingError(
                "tee_claims must carry non-empty %r" % (key,))
    detail = "%s | platform:%s measurement:%s" % (
        proof.detail, tee_claims["platform"], tee_claims["measurement"])
    return _dc_replace(proof, detail=detail)


def tee_bom_section(claims):
    """Build the additive Decision-BOM ``tee_attest`` section.

    Binds the decision to the TEE evidence: platform, measurement, and
    the evidence digest of the verified report/quote.
    """
    if not isinstance(claims, dict):
        raise TeeAttestError("tee claims must be a dict")
    for key in ("platform", "measurement", "evidence_digest"):
        value = claims.get(key)
        if not isinstance(value, str) or not value:
            raise TeeAttestError(
                "tee claims must carry non-empty %r" % (key,))
    section = {"platform": claims["platform"],
               "measurement": claims["measurement"],
               "evidence_digest": claims["evidence_digest"]}
    if isinstance(claims.get("report_data"), str):
        section["report_data"] = claims["report_data"]
    if isinstance(claims.get("tcb"), str):
        section["tcb"] = claims["tcb"]
    return section
