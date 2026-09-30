"""Attested agent identity: bind an agent's identity to attested facts.

Two tiers. Smaller number = stronger:

  TIER_ATTESTED (1) -- the agent proved control of an attested platform
      during a fresh, single-use bootstrap ceremony: a TPM 2.0 quote over
      a pinned PCR policy, an AWS-style instance-identity document, or a
      GCP-style JWT. The attester mints a short-lived tier-1 credential,
      Ed25519-signed with the attester's issuer key.
  TIER_KERNEL_FACT (2) -- LOUDLY WEAKER. A kernel-visible claim (cgroup,
      uid, hostname) with *no* cryptographic attestation. Contained to
      ``emit_telemetry`` / ``request_bootstrap``. Never upgrades to
      tier-1; a relabelled tier-2 credential fails signature verification.

Authorization verifies every credential against the attester's PINNED
issuer key. A presented identity carries no issuer key at all: the
spike for this lane caught the draft verifying against a key embedded
in the presented identity, which lets an attacker mint their own
credential and authorize. That shape is structurally impossible here.

Trust anchors are pinned keys, never fetched metadata: the TPM path
pins the AIK (or a trusted EK key that endorsed the AIK); the cloud
paths pin the document/JWT signer key plus account/project/region/zone
allowlists. When no TPM or cloud verifier is configured, the attester
degrades to tier-2 only -- tier-1 bootstrap methods refuse loudly and
tier-1 authority stays unreachable by construction.

Stdlib only. The RSA verifier is the spike's test-grade, non-constant-
time modular-exponentiation verifier (kept for the TPM/cloud evidence
fixtures); attester-issued credentials use the product Ed25519 path
(``gov.ed25519``), consistent with PolicyReport sealing.

Honest residuals (do not silently rely on more than this):
  - No real TPM or cloud metadata was touched; fixtures are synthetic.
  - EK trust is a *pinned EK key*, not a validated EK certificate chain;
    chain validation is unproven.
  - The TPM 2.0 TPMS_ATTEST marshal parser implements the spec layout
    but was never validated against a real TPM -- treat it as the
    riskiest piece.
  - Revocation beyond the short credential TTL is unaddressed; the
    consumed-evidence digest log prevents re-bootstrap, it is not a
    revocation list.
  - Real AWS IID is a PKCS#7 envelope, not a bare signed document; the
    AWS-style verifier here checks the document/signature/allowlist
    shape only.
  - Physical attacks, covert channels, and post-bootstrap key
    exfiltration are out of scope.
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time

from . import ed25519 as _ed25519


# ------------------------------------------------------------------ errors

class AttestedIdentityError(Exception):
    """Base for every attested-identity failure. Fail-closed: callers
    treat any subclass as refusal."""


class RsaError(AttestedIdentityError):
    """Test-grade RSA key parse / parameter failure."""


class QuoteError(AttestedIdentityError):
    """TPM quote malformed, untrusted, or failing policy."""


class IidError(AttestedIdentityError):
    """Cloud instance-identity document/JWT malformed or failing
    policy."""


class IdentityError(AttestedIdentityError):
    """Ceremony, credential, or authorization failure."""


# ------------------------------------------------------------------ tiers

#: Tier 1: cryptographically attested (TPM quote / cloud IID bootstrap).
TIER_ATTESTED = 1
#: Tier 2: kernel-visible claim only. LOUDLY WEAKER -- contained to
#: emit_telemetry / request_bootstrap, never upgrades to tier-1.
TIER_KERNEL_FACT = 2
#: Spec name for tier 2 (the lane brief called it TIER_KERNEL_CLAIM).
#: Both names refer to tier 2; the integer is what crosses seams.
TIER_KERNEL_CLAIM = TIER_KERNEL_FACT

TIER_LABELS = {
    TIER_ATTESTED: "tier-1-attested",
    TIER_KERNEL_FACT: "tier-2-kernel-fact",
}

#: The containment boundary. Maps each action to the STRONGEST tier
#: number allowed to perform it (smaller tier number = stronger).
#: Anything not listed is refused outright -- the policy is closed.
ACTION_POLICY = {
    "emit_telemetry": TIER_KERNEL_FACT,
    "request_bootstrap": TIER_KERNEL_FACT,
    "sign_evidence": TIER_ATTESTED,
    "approve_release": TIER_ATTESTED,
    "endorse_bootstrap": TIER_ATTESTED,
    "rotate_keys": TIER_ATTESTED,
}

TIER_2_NOT_ATTESTED_WARNING = (
    "NOT ATTESTED: this identity is a kernel-visible claim only "
    "(cgroup/uid/hostname). It was NOT cryptographically attested. "
    "Tier-2 is contained to emit_telemetry and request_bootstrap; "
    "it can never authorize tier-1 actions.")

#: Domain separation for attester-issued credential signatures, mirroring
#: the PolicyReport sealing convention (domain || sha256(canonical)).
CRED_DOMAIN = b"sasanam-attested-identity-credential/v1:"
CRED_DOMAIN_STR = CRED_DOMAIN[:-1].decode("ascii")


# ---------------------------------------------------------- canonical JSON

def canonical_json(doc):
    """Canonical JSON bytes: sorted keys, no whitespace, ASCII.

    Raises :class:`IdentityError` on non-dict input so callers never
    sign ambiguous bytes.
    """
    if not isinstance(doc, dict):
        raise IdentityError("canonical_json expects a dict, got %s"
                            % type(doc).__name__)
    try:
        text = json.dumps(doc, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
    except (TypeError, ValueError) as e:
        raise IdentityError("document is not JSON-serializable: %s" % (e,))
    return text.encode("ascii")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _check_tier(tier, what="tier"):
    """Validate a tier int. Bool is rejected explicitly: ``True == 1``
    in Python, so ``tier=True`` would otherwise silently mint or label
    tier-1 -- the one field where the loud-labeling guarantee matters
    most."""
    if isinstance(tier, bool) or tier not in (TIER_ATTESTED,
                                              TIER_KERNEL_FACT):
        raise IdentityError("%s must be 1 (tier-1-attested) or 2 "
                            "(tier-2-kernel-fact), got %r" % (what, tier))
    return tier


# ------------------------------------------------- stdlib RSA (test-grade)
# Carried from the lane spike (verdict ADAPT): a minimal DER/SPKI parser
# plus modular exponentiation. NON-CONSTANT-TIME, for fixture-grade
# evidence verification only. Anything production must use a real RSA
# implementation; this exists so the TPM/cloud verifiers stay stdlib.

_RSA_ENCRYPTION_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7,
                             0x0D, 0x01, 0x01, 0x01])
_SHA256_DER_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420")


def _der_read_tlv(buf, offset):
    """Read one DER TLV at offset. Returns (tag, value, next_offset)."""
    if offset + 2 > len(buf):
        raise RsaError("DER truncated at offset %d" % offset)
    tag = buf[offset]
    first = buf[offset + 1]
    if first & 0x80 == 0:
        length = first
        hdr = 2
    else:
        nbytes = first & 0x7F
        if nbytes == 0 or nbytes > 4:
            raise RsaError("bad DER length encoding")
        if offset + 2 + nbytes > len(buf):
            raise RsaError("DER truncated in length bytes")
        length = int.from_bytes(buf[offset + 2:offset + 2 + nbytes],
                                "big")
        hdr = 2 + nbytes
    end = offset + hdr + length
    if end > len(buf):
        raise RsaError("DER length overruns buffer")
    return tag, bytes(buf[offset + hdr:end]), end


def _der_expect(buf, offset, tag, what):
    got, value, nxt = _der_read_tlv(buf, offset)
    if got != tag:
        raise RsaError("expected DER %s (tag 0x%02x), got 0x%02x"
                       % (what, tag, got))
    return value, nxt


def _der_decode_int(raw):
    if not raw or (raw[0] & 0x80):
        raise RsaError("bad DER INTEGER (empty or negative)")
    if len(raw) > 1 and raw[0] == 0x00 and not (raw[1] & 0x80):
        raise RsaError("non-minimal DER INTEGER encoding")
    return int.from_bytes(raw, "big")


def parse_spki_rsa_pubkey(spki_der):
    """Parse a DER SubjectPublicKeyInfo into (n, e).

    Strict: exact rsaEncryption AlgorithmIdentifier, BIT STRING with
    zero unused bits, exact RSAPublicKey, no trailing bytes, positive
    minimal INTEGERs, e odd and >= 3, n >= 1024 bits (test-grade floor).
    Raises :class:`RsaError` on anything else.
    """
    if not isinstance(spki_der, (bytes, bytearray)):
        raise RsaError("SPKI must be bytes")
    buf = bytes(spki_der)
    outer, off = _der_expect(buf, 0, 0x30, "SEQUENCE (SPKI)")
    if off != len(buf):
        raise RsaError("trailing bytes after SPKI")
    alg_seq, off = _der_expect(outer, 0, 0x30, "SEQUENCE (AlgorithmId)")
    oid, aoff = _der_expect(alg_seq, 0, 0x06, "OBJECT IDENTIFIER")
    if oid != _RSA_ENCRYPTION_OID:
        raise RsaError("SPKI is not rsaEncryption")
    _null, aoff = _der_expect(alg_seq, aoff, 0x05, "NULL")
    if aoff != len(alg_seq):
        raise RsaError("trailing bytes in AlgorithmIdentifier")
    bitstr, off = _der_expect(outer, off, 0x03, "BIT STRING")
    if not bitstr or bitstr[0] != 0x00:
        raise RsaError("BIT STRING has non-zero unused bits")
    if off != len(outer):
        raise RsaError("trailing bytes in SPKI")
    inner, _ = _der_expect(bitstr[1:], 0, 0x30, "SEQUENCE (RSAPubKey)")
    n_raw, ioff = _der_expect(inner, 0, 0x02, "INTEGER (n)")
    e_raw, ioff = _der_expect(inner, ioff, 0x02, "INTEGER (e)")
    if ioff != len(inner):
        raise RsaError("trailing bytes in RSAPublicKey")
    n = _der_decode_int(n_raw)
    e = _der_decode_int(e_raw)
    if e < 3 or e % 2 == 0:
        raise RsaError("RSA exponent e must be odd and >= 3")
    if n.bit_length() < 1024:
        raise RsaError("RSA modulus below 1024-bit test-grade floor")
    return n, e


def verify_rsassa_pkcs1_v1_5_sha256(message, signature, n, e):
    """Verify an RSASSA-PKCS1-v1_5/SHA-256 signature. Returns bool.

    Malformed signatures verify False; malformed KEYS raise RsaError.
    Non-constant-time -- fixture grade only.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise RsaError("message must be bytes")
    if not isinstance(signature, (bytes, bytearray)):
        raise RsaError("signature must be bytes")
    if not isinstance(n, int) or not isinstance(e, int) or n <= 0 \
            or e <= 0:
        raise RsaError("bad RSA parameters")
    k = (n.bit_length() + 7) // 8
    sig = bytes(signature)
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest = hashlib.sha256(bytes(message)).digest()
    expected = (b"\x00\x01" + b"\xff" * (k - len(_SHA256_DER_PREFIX)
                                        - len(digest) - 3)
                + b"\x00" + _SHA256_DER_PREFIX + digest)
    if len(expected) != k:
        return False
    return secrets.compare_digest(em, expected)

# ------------------------------------------------- TPM 2.0 quote marshal
# Real TPM 2.0 layout (TPM 2.0 Library Part 2, Structures):
#   TPMS_ATTEST { magic:UINT32, type:UINT16, qualifiedSigner:TPM2B_NAME,
#                 extraData:TPM2B_DATA, clockInfo:TPMS_CLOCK_INFO,
#                 firmwareVersion:UINT64, attested:TPMU_ATTEST }
# with attested = TPMS_QUOTE_INFO { pcrSelect:TPML_PCR_SELECTION,
#                                   pcrDigest:TPM2B_DIGEST }.
# TPML_PCR_SELECTION = UINT32 count + TPMS_PCR_SELECTION[count]
#   { hash:UINT16, sizeofSelect:UINT8, pcrSelect:BYTE[sizeofSelect] }.
# All integers big-endian. The parser is strict and fail-closed; it was
# never validated against a real TPM (see module docstring).

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018

TPM_ALG_SHA1 = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C
TPM_ALG_SHA512 = 0x000D

_MAX_TPM2B = 1024
_MAX_PCR_SELECTIONS = 8
_MAX_SELECT_BYTES = 16


def _tpm2b(buf):
    if not isinstance(buf, (bytes, bytearray)):
        raise QuoteError("TPM2B field must be bytes")
    if len(buf) > _MAX_TPM2B:
        raise QuoteError("TPM2B field exceeds %d bytes" % _MAX_TPM2B)
    return struct.pack(">H", len(buf)) + bytes(buf)


class _TpmReader(object):
    def __init__(self, buf):
        if not isinstance(buf, (bytes, bytearray)):
            raise QuoteError("quote attested bytes must be bytes")
        self._buf = bytes(buf)
        self._off = 0

    def take(self, size, what):
        end = self._off + size
        if end > len(self._buf):
            raise QuoteError("truncated TPMS_ATTEST in %s" % what)
        out = self._buf[self._off:end]
        self._off = end
        return out

    def u8(self, what):
        return self.take(1, what)[0]

    def u16(self, what):
        return struct.unpack(">H", self.take(2, what))[0]

    def u32(self, what):
        return struct.unpack(">I", self.take(4, what))[0]

    def u64(self, what):
        return struct.unpack(">Q", self.take(8, what))[0]

    def tpm2b(self, what):
        return self.take(self.u16(what), what)

    def end(self):
        if self._off != len(self._buf):
            raise QuoteError("trailing bytes after TPMS_ATTEST (%d)"
                             % (len(self._buf) - self._off,))


def marshal_tpms_attest_quote(*, qualified_signer, extra_data, clock,
                              reset_count, restart_count, safe,
                              firmware_version, pcr_selections,
                              pcr_digest):
    """Marshal a TPMS_ATTEST (quote variant) to wire bytes.

    ``pcr_selections`` is a list of ``(hash_alg_uint16, select_bytes)``.
    Strict validation; raises :class:`QuoteError` on bad inputs.
    """
    for name, value in (("qualified_signer", qualified_signer),
                        ("extra_data", extra_data),
                        ("pcr_digest", pcr_digest)):
        if not isinstance(value, (bytes, bytearray)):
            raise QuoteError("%s must be bytes" % name)
    for name, value in (("clock", clock), ("reset_count", reset_count),
                        ("restart_count", restart_count),
                        ("firmware_version", firmware_version)):
        if not isinstance(value, int) or isinstance(value, bool) \
                or value < 0:
            raise QuoteError("%s must be a non-negative int" % name)
    if safe not in (True, False):
        raise QuoteError("safe must be a bool")
    if not isinstance(pcr_selections, (list, tuple)):
        raise QuoteError("pcr_selections must be a list")
    if len(pcr_selections) > _MAX_PCR_SELECTIONS:
        raise QuoteError("too many PCR selections")
    out = [struct.pack(">I", TPM_GENERATED_VALUE),
           struct.pack(">H", TPM_ST_ATTEST_QUOTE),
           _tpm2b(qualified_signer), _tpm2b(extra_data),
           struct.pack(">QII", clock, reset_count, restart_count),
           bytes([0x01 if safe else 0x00]),
           struct.pack(">Q", firmware_version),
           struct.pack(">I", len(pcr_selections))]
    for alg, select in pcr_selections:
        if not isinstance(alg, int) or isinstance(alg, bool) \
                or not 0 <= alg <= 0xFFFF:
            raise QuoteError("PCR selection alg must be a UINT16")
        if not isinstance(select, (bytes, bytearray)):
            raise QuoteError("PCR selection bytes must be bytes")
        if len(select) > _MAX_SELECT_BYTES:
            raise QuoteError("PCR selection exceeds %d bytes"
                             % _MAX_SELECT_BYTES)
        out.append(struct.pack(">H", alg))
        out.append(bytes([len(select)]))
        out.append(bytes(select))
    out.append(_tpm2b(pcr_digest))
    return b"".join(out)


def parse_tpms_attest_quote(buf):
    """Strictly parse TPMS_ATTEST wire bytes into a field dict.

    Verifies magic/type, rejects truncation and trailing bytes.
    Raises :class:`QuoteError` on anything malformed.
    """
    r = _TpmReader(buf)
    magic = r.u32("magic")
    if magic != TPM_GENERATED_VALUE:
        raise QuoteError("bad attestation magic 0x%08x" % magic)
    qtype = r.u16("type")
    if qtype != TPM_ST_ATTEST_QUOTE:
        raise QuoteError("not a quote attestation (type 0x%04x)" % qtype)
    qualified_signer = r.tpm2b("qualifiedSigner")
    extra_data = r.tpm2b("extraData")
    clock = r.u64("clock")
    reset_count = r.u32("resetCount")
    restart_count = r.u32("restartCount")
    safe = r.u8("safe")
    if safe not in (0, 1):
        raise QuoteError("clockInfo.safe must be 0 or 1")
    firmware_version = r.u64("firmwareVersion")
    count = r.u32("pcrSelect.count")
    if count > _MAX_PCR_SELECTIONS:
        raise QuoteError("pcrSelect count %d exceeds bound" % count)
    pcr_selections = []
    for _ in range(count):
        alg = r.u16("pcrSelect.hash")
        size = r.u8("pcrSelect.sizeofSelect")
        if size > _MAX_SELECT_BYTES:
            raise QuoteError("pcrSelect.sizeofSelect %d exceeds bound"
                             % size)
        select = r.take(size, "pcrSelect.pcrSelect")
        pcr_selections.append((alg, select))
    pcr_digest = r.tpm2b("pcrDigest")
    r.end()
    return {
        "magic": magic,
        "type": qtype,
        "qualified_signer": qualified_signer,
        "extra_data": extra_data,
        "clock": clock,
        "reset_count": reset_count,
        "restart_count": restart_count,
        "safe": safe == 1,
        "firmware_version": firmware_version,
        "pcr_selections": pcr_selections,
        "pcr_digest": pcr_digest,
    }


def make_quote(*, nonce, pcr_digest, pcr_selections=None, signer):
    """Test/fixture helper: build and sign a quote for ``nonce``.

    ``signer`` is a callable taking the attested bytes and returning an
    RSASSA-PKCS1-v1_5/SHA-256 signature (e.g. a TPM or an openssl test
    key). Returns ``{"attested": bytes, "signature": bytes}``.
    """
    if not isinstance(nonce, (bytes, bytearray)) or not nonce:
        raise QuoteError("nonce must be non-empty bytes")
    if pcr_selections is None:
        pcr_selections = [(TPM_ALG_SHA256, b"\xff\xff")]
    attested = marshal_tpms_attest_quote(
        qualified_signer=b"synthetic-aik", extra_data=bytes(nonce),
        clock=0, reset_count=0, restart_count=0, safe=True,
        firmware_version=0, pcr_selections=pcr_selections,
        pcr_digest=bytes(pcr_digest))
    if not callable(signer):
        raise QuoteError("signer must be callable")
    signature = signer(attested)
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise QuoteError("signer returned empty signature")
    return {"attested": attested, "signature": bytes(signature)}


def endorse_aik(aik_pubkey_der, ek_signer):
    """Test/fixture helper: EK endorsement of an AIK public key.

    Returns ``ek_signer(b"endorse:" + aik_pubkey_der)``. The verifier
    checks this endorsement against the TRUSTED EK key -- an attacker
    endorsing with their own EK key verifies False and is refused.
    """
    parse_spki_rsa_pubkey(aik_pubkey_der)  # fail fast on bad AIK bytes
    if not callable(ek_signer):
        raise QuoteError("ek_signer must be callable")
    endorsement = ek_signer(b"endorse:" + bytes(aik_pubkey_der))
    if not isinstance(endorsement, (bytes, bytearray)) \
            or not endorsement:
        raise QuoteError("ek_signer returned empty endorsement")
    return bytes(endorsement)


class QuoteVerifier(object):
    """Verifies TPM 2.0 quotes against pinned trust and PCR policy.

    Trust: the AIK is accepted when its SPKI DER is in
    ``pinned_aik_pubkeys_der``, OR when ``endorsement`` verifies as an
    EK endorsement under one of ``trusted_ek_pubkeys_der``. Both lists
    are pinned keys -- never fetched. At least one trust anchor is
    required.
    """

    def __init__(self, *, trusted_ek_pubkeys_der=None,
                 pinned_aik_pubkeys_der=None,
                 expected_pcr_digest, expected_pcr_selections):
        self._ek_keys = []
        for der in trusted_ek_pubkeys_der or ():
            self._ek_keys.append(parse_spki_rsa_pubkey(der))
        self._pinned_aik = set()
        for der in pinned_aik_pubkeys_der or ():
            parse_spki_rsa_pubkey(der)  # fail fast on bad config
            self._pinned_aik.add(bytes(der))
        if not self._ek_keys and not self._pinned_aik:
            raise QuoteError("no AIK trust anchor configured: pin an AIK "
                             "or trust an EK key")
        if not isinstance(expected_pcr_digest, (bytes, bytearray)) \
                or not expected_pcr_digest:
            raise QuoteError("expected_pcr_digest must be non-empty "
                             "bytes")
        self._expected_pcr_digest = bytes(expected_pcr_digest)
        if not isinstance(expected_pcr_selections, (list, tuple)) \
                or not expected_pcr_selections:
            raise QuoteError("expected_pcr_selections must be a "
                             "non-empty list of (alg, select) pairs")
        norm = []
        for pair in expected_pcr_selections:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise QuoteError("PCR selection must be an (alg, select) "
                                 "pair")
            alg, select = pair
            if not isinstance(alg, int) or isinstance(alg, bool):
                raise QuoteError("PCR selection alg must be an int")
            norm.append((alg, bytes(select)))
        self._expected_pcr_selections = norm

    def verify(self, quote, *, aik_pubkey_der, endorsement=None,
               expected_nonce):
        """Verify a quote dict. Fail-fast order: structure, magic/type,
        AIK trust, signature, nonce, PCR digest, PCR selection.

        Returns the attested claims dict. Raises :class:`QuoteError`
        on any failure.
        """
        if not isinstance(quote, dict):
            raise QuoteError("quote must be a dict")
        attested = quote.get("attested")
        signature = quote.get("signature")
        if not isinstance(attested, (bytes, bytearray)) \
                or not isinstance(signature, (bytes, bytearray)):
            raise QuoteError("quote needs bytes 'attested' and "
                             "'signature'")
        attested = bytes(attested)
        fields = parse_tpms_attest_quote(attested)
        aik_der = bytes(aik_pubkey_der) if isinstance(
            aik_pubkey_der, (bytes, bytearray)) else None
        if aik_der is None:
            raise QuoteError("aik_pubkey_der must be bytes")
        n_aik, e_aik = parse_spki_rsa_pubkey(aik_der)
        if aik_der in self._pinned_aik:
            trusted = True
        elif endorsement is not None and isinstance(
                endorsement, (bytes, bytearray)) and endorsement:
            msg = b"endorse:" + aik_der
            trusted = any(
                verify_rsassa_pkcs1_v1_5_sha256(msg, bytes(endorsement),
                                               n_ek, e_ek)
                for n_ek, e_ek in self._ek_keys)
        else:
            trusted = False
        if not trusted:
            raise QuoteError("AIK not trusted: not pinned and no valid "
                             "EK endorsement")
        if not verify_rsassa_pkcs1_v1_5_sha256(attested, bytes(signature),
                                               n_aik, e_aik):
            raise QuoteError("quote signature invalid for the trusted "
                             "AIK")
        if not isinstance(expected_nonce, (bytes, bytearray)) \
                or not expected_nonce:
            raise QuoteError("expected_nonce must be non-empty bytes")
        if not secrets.compare_digest(fields["extra_data"],
                                       bytes(expected_nonce)):
            raise QuoteError("quote extraData does not match the "
                             "challenge nonce (stale or replayed quote)")
        if not secrets.compare_digest(fields["pcr_digest"],
                                       self._expected_pcr_digest):
            raise QuoteError("PCR digest does not match policy")
        if fields["pcr_selections"] != self._expected_pcr_selections:
            raise QuoteError("PCR selection does not match policy")
        return {
            "kind": "tpm_quote",
            "aik_sha256": _sha256_hex(aik_der),
            "pcr_digest": fields["pcr_digest"].hex(),
            "pcr_selections": [(alg, sel.hex()) for alg, sel
                                in fields["pcr_selections"]],
            "firmware_version": fields["firmware_version"],
            "clock": fields["clock"],
        }

# ------------------------------------------- AWS-style instance identity
# Real AWS IID is a PKCS#7 DER envelope signed by AWS; this verifier
# covers the *document/signature/allowlist* shape used by synthetic
# fixtures and by operators who front the metadata service with their
# own signer. The document carries NO challenge nonce, so a valid
# document re-verifies by design (host identity, not liveness) -- the
# bootstrap ceremony's single-use evidence digest is what makes the
# *bootstrap* fresh, and the short credential TTL bounds the window.

def make_aws_style_doc(*, instance_id, account_id, region,
                       image_id="ami-fixture", signer):
    """Test/fixture helper: build and sign an AWS-style IID bundle.

    Returns ``{"document": dict, "signature": bytes}`` where the
    signature covers the canonical JSON document bytes.
    """
    for name, value in (("instance_id", instance_id),
                        ("account_id", account_id),
                        ("region", region), ("image_id", image_id)):
        if not isinstance(value, str) or not value:
            raise IidError("%s must be a non-empty str" % name)
    if not callable(signer):
        raise IidError("signer must be callable")
    document = {
        "accountId": account_id,
        "imageId": image_id,
        "instanceId": instance_id,
        "region": region,
    }
    signature = signer(canonical_json(document))
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise IidError("signer returned empty signature")
    return {"document": document, "signature": bytes(signature)}


class AwsStyleVerifier(object):
    """Verifies AWS-style IID bundles: signature, account allowlist,
    region allowlist. The signer key is PINNED (never fetched)."""

    def __init__(self, *, signer_pubkey_der, allowed_account_ids,
                 allowed_regions):
        self._n, self._e = parse_spki_rsa_pubkey(signer_pubkey_der)
        for name, allow in (("allowed_account_ids", allowed_account_ids),
                            ("allowed_regions", allowed_regions)):
            if not isinstance(allow, (set, frozenset, list, tuple)) \
                    or not allow:
                raise IidError("%s must be a non-empty collection" % name)
            if any(not isinstance(v, str) or not v for v in allow):
                raise IidError("%s entries must be non-empty str" % name)
        self._accounts = frozenset(allowed_account_ids)
        self._regions = frozenset(allowed_regions)

    def verify(self, bundle):
        """Verify a bundle dict. Returns the identity claims dict.
        Raises :class:`IidError` on any failure."""
        if not isinstance(bundle, dict):
            raise IidError("bundle must be a dict")
        document = bundle.get("document")
        signature = bundle.get("signature")
        if not isinstance(document, dict):
            raise IidError("bundle needs a dict 'document'")
        if not isinstance(signature, (bytes, bytearray)):
            raise IidError("bundle needs bytes 'signature'")
        if not verify_rsassa_pkcs1_v1_5_sha256(
                canonical_json(document), bytes(signature),
                self._n, self._e):
            raise IidError("AWS-style document signature invalid")
        account_id = document.get("accountId")
        region = document.get("region")
        if account_id not in self._accounts:
            raise IidError("accountId %r is not allowlisted" % (account_id,))
        if region not in self._regions:
            raise IidError("region %r is not allowlisted" % (region,))
        return {
            "kind": "aws_iid",
            "instance_id": document.get("instanceId"),
            "account_id": account_id,
            "region": region,
        }


# ------------------------------------------------ GCP-style JWT identity

def _b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text, what):
    if not isinstance(text, str) or not text:
        raise IidError("%s must be a non-empty str" % what)
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        raise IidError("%s is not valid base64url" % what)


def make_gcp_style_jwt(*, instance_id, project_id, zone, audience,
                       signer, kid="gcp-fixture-key-1", lifetime_s=3600,
                       now=None):
    """Test/fixture helper: build and RS256-sign a GCP-style JWT."""
    for name, value in (("instance_id", instance_id),
                        ("project_id", project_id), ("zone", zone),
                        ("audience", audience)):
        if not isinstance(value, str) or not value:
            raise IidError("%s must be a non-empty str" % name)
    if not callable(signer):
        raise IidError("signer must be callable")
    if not isinstance(lifetime_s, int) or isinstance(lifetime_s, bool):
        raise IidError("lifetime_s must be an int")
    now = int(now) if now is not None else int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    payload = {
        "aud": audience,
        "iss": "https://accounts.google.com",
        "sub": instance_id,
        "instance_id": instance_id,
        "project_id": project_id,
        "zone": zone,
        "iat": now,
        "exp": now + lifetime_s,
    }
    signing_input = (_b64u_encode(canonical_json(header)) + "."
                     + _b64u_encode(canonical_json(payload))).encode(
                         "ascii")
    signature = signer(signing_input)
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise IidError("signer returned empty signature")
    return (signing_input.decode("ascii") + "."
            + _b64u_encode(bytes(signature)))


class GcpStyleVerifier(object):
    """Verifies GCP-style JWTs: strict RS256, audience, clock, project
    and zone allowlists. The signer key is PINNED (never fetched)."""

    def __init__(self, *, signer_pubkey_der, expected_audience,
                 allowed_projects, allowed_zones, max_skew_s=60):
        self._n, self._e = parse_spki_rsa_pubkey(signer_pubkey_der)
        if not isinstance(expected_audience, str) or not expected_audience:
            raise IidError("expected_audience must be a non-empty str")
        for name, allow in (("allowed_projects", allowed_projects),
                            ("allowed_zones", allowed_zones)):
            if not isinstance(allow, (set, frozenset, list, tuple)) \
                    or not allow:
                raise IidError("%s must be a non-empty collection" % name)
            if any(not isinstance(v, str) or not v for v in allow):
                raise IidError("%s entries must be non-empty str" % name)
        if not isinstance(max_skew_s, int) or isinstance(max_skew_s, bool) \
                or max_skew_s < 0:
            raise IidError("max_skew_s must be a non-negative int")
        self._audience = expected_audience
        self._projects = frozenset(allowed_projects)
        self._zones = frozenset(allowed_zones)
        self._skew = max_skew_s

    def verify(self, token, *, now=None):
        """Verify a compact JWT string. Returns the claims dict.
        Raises :class:`IidError` on any failure."""
        if not isinstance(token, str):
            raise IidError("token must be a str")
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise IidError("token is not a three-part compact JWT")
        header_b64, payload_b64, sig_b64 = parts
        try:
            header = json.loads(_b64u_decode(header_b64, "header"))
            payload = json.loads(_b64u_decode(payload_b64, "payload"))
        except IidError:
            raise
        except Exception as e:
            raise IidError("JWT header/payload is not JSON: %s" % (e,))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise IidError("JWT header/payload must be JSON objects")
        if header.get("alg") != "RS256":
            raise IidError("JWT alg must be RS256, got %r"
                           % (header.get("alg"),))
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        signature = _b64u_decode(sig_b64, "signature")
        if not verify_rsassa_pkcs1_v1_5_sha256(signing_input, signature,
                                               self._n, self._e):
            raise IidError("JWT signature invalid")
        if payload.get("aud") != self._audience:
            raise IidError("JWT aud %r does not match %r"
                           % (payload.get("aud"), self._audience))
        moment = int(now) if now is not None else int(time.time())
        iat = payload.get("iat")
        exp = payload.get("exp")
        if not isinstance(iat, int) or isinstance(iat, bool):
            raise IidError("JWT iat must be an int")
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise IidError("JWT exp must be an int")
        if iat > moment + self._skew:
            raise IidError("JWT issued in the future")
        if exp <= moment:
            raise IidError("JWT expired")
        project_id = payload.get("project_id")
        zone = payload.get("zone")
        if project_id not in self._projects:
            raise IidError("JWT project_id %r is not allowlisted"
                           % (project_id,))
        if zone not in self._zones:
            raise IidError("JWT zone %r is not allowlisted" % (zone,))
        return {
            "kind": "gcp_jwt",
            "instance_id": payload.get("instance_id"),
            "project_id": project_id,
            "zone": zone,
        }

# ------------------------------------------------- issued credentials

def credential_body(tier, claims, expires_at):
    """Build the unsigned credential body dict (pure function)."""
    _check_tier(tier)
    if not isinstance(claims, dict):
        raise IdentityError("claims must be a dict")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise IdentityError("expires_at must be an int epoch")
    return {
        "domain": CRED_DOMAIN_STR,
        "tier": tier,
        "claims": dict(claims),
        "expires_at": expires_at,
    }


def credential_signing_bytes(body):
    """Bytes the issuer signs: domain || sha256(canonical(body)).

    Mirrors the PolicyReport sealing convention. Auditors re-derive
    these bytes to check a credential against the pinned issuer key.
    """
    if not isinstance(body, dict) or body.get("domain") != CRED_DOMAIN_STR:
        raise IdentityError("not an attested-identity credential body")
    digest = _sha256_hex(canonical_json(body))
    return CRED_DOMAIN + digest.encode("ascii")


def credential_digest_of(body):
    """sha256 hex of the canonical credential body (evidence binding)."""
    if not isinstance(body, dict) or body.get("domain") != CRED_DOMAIN_STR:
        raise IdentityError("not an attested-identity credential body")
    return _sha256_hex(canonical_json(body))


class Identity(object):
    """A presented agent identity: tier + claims + issuer signature.

    Deliberately carries NO issuer key -- authorization verifies the
    signature against the attester's PINNED issuer key, so an attacker
    cannot smuggle in their own key (the C4 attack the spike caught).
    """

    __slots__ = ("tier", "claims", "credential_sig", "expires_at")

    def __init__(self, *, tier, claims, credential_sig, expires_at):
        _check_tier(tier)
        if not isinstance(claims, dict):
            raise IdentityError("claims must be a dict")
        if not isinstance(credential_sig, (bytes, bytearray)) \
                or not credential_sig:
            raise IdentityError("credential_sig must be non-empty bytes")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise IdentityError("expires_at must be an int epoch")
        self.tier = tier
        self.claims = dict(claims)
        self.credential_sig = bytes(credential_sig)
        self.expires_at = expires_at

    @property
    def tier_label(self):
        return TIER_LABELS[self.tier]

    def credential_body(self):
        return credential_body(self.tier, self.claims, self.expires_at)

    def credential_digest(self):
        return credential_digest_of(self.credential_body())

    def __repr__(self):
        return "Identity(tier=%d, label=%s, expires_at=%d)" % (
            self.tier, self.tier_label, self.expires_at)


# ------------------------------------------------- bootstrap ceremony

def _require_issuer_signer(signer):
    sign = getattr(signer, "sign", None)
    public_key = getattr(signer, "public_key", None)
    key_id = getattr(signer, "key_id", None)
    if not callable(sign):
        raise IdentityError("issuer_signer needs a sign(bytes) method")
    if not isinstance(public_key, (bytes, bytearray)) \
            or len(public_key) != 32:
        raise IdentityError("issuer_signer.public_key must be 32 bytes "
                            "(Ed25519)")
    if not isinstance(key_id, str) or not key_id:
        raise IdentityError("issuer_signer.key_id must be a non-empty str")
    return sign, bytes(public_key), key_id


class Attester(object):
    """Runs the bootstrap ceremony and authorizes actions.

    A fresh challenge (single-use ID + 32-byte nonce) is issued per
    bootstrap attempt; verified evidence is hashed into a
    consumed-evidence digest log so the same evidence can never mint a
    second credential; tier-1 credentials are short-lived and
    Ed25519-signed by the pinned issuer key.
    """

    def __init__(self, issuer_signer, *, quote_verifier=None,
                 aws_verifier=None, gcp_verifier=None, tee_verifier=None,
                 credential_ttl_s=600):
        self._sign, self._issuer_pubkey, self._issuer_key_id = \
            _require_issuer_signer(issuer_signer)
        if not isinstance(credential_ttl_s, int) \
                or isinstance(credential_ttl_s, bool) \
                or credential_ttl_s < 0:
            raise IdentityError("credential_ttl_s must be a non-negative "
                                "int")
        self._ttl = credential_ttl_s
        self.quote_verifier = quote_verifier
        self.aws_verifier = aws_verifier
        self.gcp_verifier = gcp_verifier
        self.tee_verifier = tee_verifier
        self._challenges = {}
        self._consumed_evidence = set()
        self.audit = []

    @property
    def issuer_public_key(self):
        """The PINNED issuer public key (32-byte Ed25519)."""
        return self._issuer_pubkey

    @property
    def issuer_key_id(self):
        return self._issuer_key_id

    # -- challenge -------------------------------------------------

    def issue_challenge(self, subject):
        """Issue a fresh single-use challenge for ``subject``.

        Returns ``(challenge_id, nonce)``. The nonce goes into the
        quote's extraData / the ceremony; the challenge ID is consumed
        exactly once by the bootstrap call.
        """
        if not isinstance(subject, str) or not subject:
            raise IdentityError("subject must be a non-empty str")
        challenge_id = "chal-" + secrets.token_hex(8)
        nonce = secrets.token_bytes(32)
        self._challenges[challenge_id] = {"nonce": nonce,
                                          "subject": subject}
        return challenge_id, nonce

    def _consume_challenge(self, challenge_id):
        try:
            entry = self._challenges.pop(challenge_id)
        except KeyError:
            raise IdentityError("unknown or already-used challenge %r"
                                % (challenge_id,))
        return entry["nonce"]

    # -- evidence single-use ----------------------------------------

    def _record_evidence(self, kind, raw):
        digest = _sha256_hex(bytes(raw))
        if digest in self._consumed_evidence:
            raise IdentityError(
                "%s evidence already consumed: each attestation mints at "
                "most one credential (replay refused)" % kind)
        self._consumed_evidence.add(digest)
        return digest

    # -- tier-1 bootstrap --------------------------------------------

    def _mint_tier1(self, *, kind, evidence_digest, claims):
        expires_at = int(time.time()) + self._ttl
        # The ceremony's kind/evidence_digest win over verifier claims:
        # verifier claim dicts also carry a "kind" key (e.g.
        # "tpm_quote") and must not overwrite the ceremony label.
        body_claims = dict(claims)
        body_claims["kind"] = kind
        body_claims["evidence_digest"] = evidence_digest
        body = credential_body(TIER_ATTESTED, body_claims, expires_at)
        sig = self._sign(credential_signing_bytes(body))
        if not isinstance(sig, (bytes, bytearray)) or not sig:
            raise IdentityError("issuer signer returned empty signature")
        ident = Identity(tier=TIER_ATTESTED, claims=body_claims,
                         credential_sig=bytes(sig),
                         expires_at=expires_at)
        self.audit.append({"event": "tier1_issued", "kind": kind,
                           "credential_digest": ident.credential_digest(),
                           "evidence_digest": evidence_digest,
                           "at": int(time.time())})
        return ident

    def bootstrap_with_tpm_quote(self, *, challenge_id, quote,
                                 aik_pubkey_der, endorsement=None):
        """Verify a TPM quote and mint a tier-1 credential."""
        if self.quote_verifier is None:
            raise IdentityError(
                "no TPM quote verifier configured: tier-1 bootstrap is "
                "unavailable on this attester (degraded to tier-2 only)")
        nonce = self._consume_challenge(challenge_id)
        claims = self.quote_verifier.verify(
            quote, aik_pubkey_der=aik_pubkey_der, endorsement=endorsement,
            expected_nonce=nonce)
        evidence_digest = self._record_evidence("tpm_quote",
                                                quote["attested"])
        return self._mint_tier1(kind="tpm_attested",
                                evidence_digest=evidence_digest,
                                claims=claims)

    def bootstrap_with_aws_iid(self, *, challenge_id, bundle):
        """Verify an AWS-style IID bundle and mint a tier-1 credential.

        The document has no verifier nonce (documented AWS property);
        freshness comes from the single-use challenge plus the
        consumed-evidence digest -- the same bundle can never bootstrap
        twice.
        """
        if self.aws_verifier is None:
            raise IdentityError(
                "no AWS IID verifier configured: tier-1 bootstrap is "
                "unavailable on this attester (degraded to tier-2 only)")
        self._consume_challenge(challenge_id)
        claims = self.aws_verifier.verify(bundle)
        raw = canonical_json(bundle["document"]) + bytes(
            bundle["signature"])
        evidence_digest = self._record_evidence("aws_iid", raw)
        return self._mint_tier1(kind="aws_attested",
                                evidence_digest=evidence_digest,
                                claims=claims)

    def bootstrap_with_gcp_jwt(self, *, challenge_id, token):
        """Verify a GCP-style JWT and mint a tier-1 credential."""
        if self.gcp_verifier is None:
            raise IdentityError(
                "no GCP JWT verifier configured: tier-1 bootstrap is "
                "unavailable on this attester (degraded to tier-2 only)")
        self._consume_challenge(challenge_id)
        claims = self.gcp_verifier.verify(token)
        evidence_digest = self._record_evidence(
            "gcp_jwt", token.encode("utf-8")
            if isinstance(token, str) else bytes(token))
        return self._mint_tier1(kind="gcp_attested",
                                evidence_digest=evidence_digest,
                                claims=claims)

    def bootstrap_with_tee_report(self, *, challenge_id, bundle):
        """Verify a TEE (SEV-SNP/TDX) attestation bundle and mint tier-1.

        The bundle is the tee verifier's bundle (report/quote, certs,
        expectations, tee_pubkey, salt). Freshness is cryptographic: the
        REPORT_DATA salt must equal the single-use challenge nonce, so
        the report was generated inside the attested guest after the
        challenge was issued. The same evidence can never mint twice.
        """
        if self.tee_verifier is None:
            raise IdentityError(
                "no TEE verifier configured: tier-1 bootstrap is "
                "unavailable on this attester (degraded to tier-2 only)")
        nonce = self._consume_challenge(challenge_id)
        salt = bundle.get("salt") if isinstance(bundle, dict) else None
        if not isinstance(salt, (bytes, bytearray)) \
                or not hmac.compare_digest(bytes(salt), nonce):
            raise IdentityError(
                "tee bundle salt must equal the single-use challenge "
                "nonce (freshness binding): stale or foreign reports "
                "cannot bootstrap")
        claims = self.tee_verifier.verify(bundle)
        raw = bytes(bundle["report"]) if "report" in bundle \
            else bytes(bundle["quote"])
        evidence_digest = self._record_evidence("tee_report", raw)
        return self._mint_tier1(kind="tee_attested",
                                evidence_digest=evidence_digest,
                                claims=claims)

    # -- tier-2 (contained, never attested) ----------------------------

    def register_kernel_fact_identity(self, *, cgroup, uid, hostname):
        """Register a tier-2 identity from kernel-visible facts.

        LOUDLY WEAKER: no cryptographic attestation. The claims carry
        the NOT-ATTESTED warning; the credential is still
        issuer-signed so its tier label cannot be rewritten (C3), but
        the label only ever says tier-2.
        """
        if not isinstance(cgroup, str) or not cgroup:
            raise IdentityError("cgroup must be a non-empty str")
        if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0:
            raise IdentityError("uid must be a non-negative int")
        if not isinstance(hostname, str) or not hostname:
            raise IdentityError("hostname must be a non-empty str")
        expires_at = int(time.time()) + self._ttl
        claims = {
            "kind": "kernel_fact",
            "cgroup": cgroup,
            "uid": uid,
            "hostname": hostname,
            "warning": TIER_2_NOT_ATTESTED_WARNING,
        }
        body = credential_body(TIER_KERNEL_FACT, claims, expires_at)
        sig = self._sign(credential_signing_bytes(body))
        if not isinstance(sig, (bytes, bytearray)) or not sig:
            raise IdentityError("issuer signer returned empty signature")
        ident = Identity(tier=TIER_KERNEL_FACT, claims=claims,
                         credential_sig=bytes(sig), expires_at=expires_at)
        self.audit.append({"event": "tier2_registered",
                           "credential_digest": ident.credential_digest(),
                           "at": int(time.time())})
        # Wave-219: every tier-2 credential minted is an execution of the
        # degraded path -- the registry code rides the audit trail on
        # EVERY registration, not just at attester construction.
        from . import unsafe_paths as _up
        _up.emit(
            "gov.attested_identity.tier2_only_degradation",
            audit=self.audit,
            detail=("tier-2 kernel-fact credential minted without "
                    "attestation (digest %s)"
                    % ident.credential_digest()))
        return ident

    # -- authorization (pinned issuer key) ------------------------------

    def verify_credential(self, identity):
        """Check an Identity against the PINNED issuer key.

        Returns bool, never raises: this is a verification predicate.
        The identity carries no key -- the only key consulted is the
        attester's pinned issuer public key.
        """
        try:
            if not isinstance(identity, Identity):
                return False
            msg = credential_signing_bytes(identity.credential_body())
            return bool(_ed25519.verify(self._issuer_pubkey, msg,
                                        identity.credential_sig))
        except Exception:
            return False

    def authorize(self, identity, action, *, now=None):
        """Authorize ``action`` for ``identity``. Returns True.

        Fail-closed order: unknown action, tier containment, credential
        signature (pinned issuer key), expiry. Raises
        :class:`IdentityError` on any refusal.
        """
        if action not in ACTION_POLICY:
            raise IdentityError("unknown action %r: the action policy "
                                "is closed" % (action,))
        if not isinstance(identity, Identity):
            raise IdentityError("identity must be an Identity")
        required = ACTION_POLICY[action]
        if identity.tier > required:
            raise IdentityError(
                "tier-%d identity cannot perform %r: requires tier-%d "
                "or stronger (%s). Tier-2 is contained to "
                "emit_telemetry and request_bootstrap."
                % (identity.tier, action, required,
                   TIER_LABELS[required]))
        if not self.verify_credential(identity):
            raise IdentityError(
                "credential signature invalid: not issued by this "
                "attester (issuer key is pinned; presented identities "
                "carry no key)")
        moment = int(now) if now is not None else int(time.time())
        if moment >= identity.expires_at:
            raise IdentityError("credential expired")
        self.audit.append({"event": "authorized", "action": action,
                           "tier": identity.tier,
                           "credential_digest":
                               identity.credential_digest(),
                           "at": moment})
        return True


def degraded_attester(issuer_signer, *, credential_ttl_s=600):
    """Build an attester with NO TPM/cloud verifiers.

    For hosts where attestation is unavailable: tier-1 bootstrap
    methods refuse loudly, tier-2 registration and authorization keep
    working, and tier-1 authority stays unreachable by construction.

    Wave-219: the degradation is a registered unsafe path --
    ``gov.attested_identity.tier2_only_degradation`` -- and its
    construction emits that code into the attester's audit trail, so
    the weaker posture is never silent.
    """
    attester = Attester(issuer_signer, credential_ttl_s=credential_ttl_s)
    from . import unsafe_paths as _up
    _up.emit(
        "gov.attested_identity.tier2_only_degradation",
        audit=attester.audit,
        detail=("attester constructed with no TPM/cloud verifiers: "
                "tier-1 attestation is unreachable; tier-2 kernel-fact "
                "credentials only"))
    return attester


# ------------------------------------------------- evidence-path wiring

def bom_identity_section(identity):
    """Build the Decision-BOM ``inputs.attested_identity`` section.

    Binds the decision to the attested credential: tier, credential
    digest, and the consumed-evidence digest. Tier-1 only -- a tier-2
    identity has no attested evidence to bind, and binding an empty
    digest would be a vacuous proof, so it refuses loudly instead.
    """
    if not isinstance(identity, Identity):
        raise IdentityError("identity must be an Identity")
    _check_tier(identity.tier)
    if identity.tier != TIER_ATTESTED:
        raise IdentityError(
            "the BOM attested_identity section is tier-1 only: tier-2 "
            "carries no attested evidence to bind (an empty "
            "evidence_digest would be a vacuous proof)")
    evidence_digest = identity.claims.get("evidence_digest")
    if not _is_hex64(evidence_digest):
        raise IdentityError("tier-1 identity has no evidence_digest to "
                            "bind")
    return {
        "tier": identity.tier,
        "credential_digest": identity.credential_digest(),
        "evidence_digest": evidence_digest,
    }
