"""Envelope encryption for offline evidence bundles (sops-pattern STEAL).

PATTERN LINEAGE: getsops/sops (MPL-2.0 -- LICENSE bytes verified by the
wave-283 prospecting lane): the envelope-encryption shape -- a fresh
random 256-bit data key per file, the data key wrapped once per
recipient public key (age/PGP/KMS), an integrity MAC over the parsed
values, recipient policy as auditable checked-in config
(``.sops.yaml`` creation rules), and the ``updatekeys`` / ``rotate``
re-keying operations. MPL-2.0 is file-level copyleft only; this is a
clean-room stdlib Python reimplementation of the *mechanisms* -- no
sops code, docs, or prose are vendored here, so MPL exposure is zero.

What this module adds:

* per-bundle fresh 256-bit data key; the bundle SHA-256 digest plus the
  bundle id as associated authenticated data (binds ciphertext to
  bundle identity -- defeats bundle-swapping, the sops "key path as
  AAD" analog);
* per-recipient data-key wraps: ``offline`` recipients via X25519
  (ephemeral-static ECDH, age-style) and ``custody`` recipients via a
  deployment-supplied wrap provider (KMS/Vault-style);
* an integrity MAC over the parsed envelope header keyed by the data
  key (the sops encrypted-MAC analog), on top of per-record
  encrypt-then-MAC;
* Ed25519 authorship signatures over the envelope (the sops-trap fix:
  a MAC proves integrity, not authorship -- an authorized recipient
  could forge; the signature binds the sealer);
* recipient policy as a checked-in, versioned, audited config
  (``make_recipient_policy`` -- the ``.sops.yaml`` creation-rules
  analog; policy registration is an audit event). The policy carries a
  ``policy_digest`` that is recomputed and verified on every use --
  a policy edited after registration is refused. ``bundle_scope`` is
  the creation-rule match (a bundle-id prefix; ``"*"`` covers all).
  ``min_recipients`` is advisory metadata only and is NOT enforced:
  any single listed recipient can unwrap (no Shamir N-of-M here).
* the re-keying ceremony: ``rotate_envelope`` (fresh data key) and
  ``update_wraps`` (same data key, new recipient set), both chained
  into the audit log via the ``set_emit`` sink. All three sealing
  paths enforce the policy's ``bundle_scope`` creation rule
  (``recipient-policy-invalid``).

CRYPTOGRAPHY, STATED HONESTLY (not AES-GCM):

The AEAD here is encrypt-then-MAC over SHA-256: a HMAC-SHA256-CTR
stream cipher plus a 128-bit HMAC-SHA256 tag over
(AAD || nonce || ciphertext) with full domain separation. This is a
legitimate, provable EtM construction, but it is NOT AES-GCM and NOT
NIST/FIPS: there is no hardware acceleration (pure-Python HMAC is
~100x slower than AES-NI), the X25519 ladder below is not
constant-time, and nonce-misuse is catastrophic for confidentiality
(mitigated by 192-bit random nonces -- never reused, never
caller-supplied). It is sized for evidence bundles (kilobytes), not
bulk data. The day a hardware-backed AEAD is available, the
``aead_seal`` / ``aead_open`` seam is the single swap point -- the
envelope shape, wrap protocol, and audit events do not change.

X25519 is implemented in pure Python (Montgomery ladder, RFC 7748
section 5) and pinned against the RFC 7748 section 6.1 test vectors.
The ladder here is NOT constant-time (Python big-int timing leaks);
recipient private keys live in memory only during unwrap, and the
threat model treats the sealing host as trusted -- key exfiltration
from the host is outside this module's model (that is the KMS /
custody story).

Stdlib only ($0 spend). No network.
"""

import hashlib
import hmac
import json
import secrets

from gov import ed25519 as _ed25519
from gov import signing as _signing

ENVELOPE_VERSION = "sasanam-bundle-envelope/1.0"
POLICY_FORMAT = "sasanam-recipient-policy/1.0"

#: Domain separation for every HMAC use in this module.
_DOMAIN = b"sasanam-bundle-envelope/v1\x00"

#: Hard budget: evidence bundles are kilobytes; a larger sealed blob is
#: a deployment smell, not a use case for this module.
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024

#: Machine-readable refusal codes raised as ``EnvelopeError.code``.
#: Registered in gov/decision_codes.py (domain 'envelope').
MALFORMED = "envelope-malformed"                    # structural shape
SEAL_REFUSED = "envelope-seal-refused"               # seal arg validation
AAD_MISMATCH = "envelope-aad-mismatch"              # bundle identity binding
CUSTODY_UNAVAILABLE = "envelope-custody-unavailable"
MAC_FAILED = "envelope-mac-failed"                  # EtM tag / header MAC
REKEY_REFUSED = "envelope-rekey-refused"            # rekey ceremony
SIGNATURE_INVALID = "envelope-signature-invalid"    # authorship
UNWRAP_FAILED = "envelope-unwrap-failed"            # per-recipient unwrap
RECIPIENT_UNKNOWN = "envelope-recipient-unknown"
POLICY_INVALID = "recipient-policy-invalid"


class EnvelopeError(ValueError):
    """Every refusal carries a machine-readable ``code`` (repo
    convention: callers branch on ``code``, never on message text)."""

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def _fail(code, detail):
    raise EnvelopeError(code, detail)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _hex(b):
    return bytes(b).hex()


def _unhex(s, what):
    try:
        return bytes.fromhex(s)
    except (TypeError, ValueError):
        _fail(MALFORMED, "%s is not valid hex" % what)


# ---------------------------------------------------------------------------
# X25519 (RFC 7748 section 5), pinned to the section 6.1 test vectors.
# NOT constant-time -- see the module docstring.
# ---------------------------------------------------------------------------

_X25519_P = 2 ** 255 - 19
_X25519_A24 = 121665  # (486662 - 2) // 4
_X25519_BASE_U = b"\x09" + b"\x00" * 31


def _x25519_clamp(priv):
    b = bytearray(priv)
    b[0] &= 0xF8
    b[31] &= 0x7F
    b[31] |= 0x40
    return int.from_bytes(bytes(b), "little")


def _x25519_ladder(k, u):
    # Montgomery ladder, RFC 7748 section 5 pseudocode, transcribed
    # exactly: differential-add -> (x_3, z_3), doubling -> (x_2, z_2),
    # t = bits-1 down to 0 (255..0 for X25519).
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(255, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % _X25519_P
        aa = (a * a) % _X25519_P
        b = (x2 - z2) % _X25519_P
        bb = (b * b) % _X25519_P
        e = (aa - bb) % _X25519_P
        c = (x3 + z3) % _X25519_P
        d = (x3 - z3) % _X25519_P
        da = (d * a) % _X25519_P
        cb = (c * b) % _X25519_P
        x3 = pow(da + cb, 2, _X25519_P)
        z3 = (x1 * pow(da - cb, 2, _X25519_P)) % _X25519_P
        x2 = (aa * bb) % _X25519_P
        z2 = (e * ((aa + _X25519_A24 * e) % _X25519_P)) % _X25519_P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    if z2 == 0:
        return 0
    return (x2 * pow(z2, _X25519_P - 2, _X25519_P)) % _X25519_P


def x25519(priv, pub):
    """X25519(priv, pub) -> 32-byte shared secret.

    Refuses (fail-closed) on bad lengths and on the all-zero shared
    secret (RFC 7748 section 6.1: small-order input point).
    """
    if not isinstance(priv, (bytes, bytearray)) or len(priv) != 32:
        _fail(SEAL_REFUSED, "x25519 private key must be 32 bytes")
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        _fail(SEAL_REFUSED, "x25519 public key must be 32 bytes")
    # RFC 7748 section 5: mask the MSB of the final byte on receipt.
    u = int.from_bytes(bytes(pub), "little") & ~(1 << 255)
    shared = _x25519_ladder(_x25519_clamp(bytes(priv)), u)
    out = shared.to_bytes(32, "little")
    if out == b"\x00" * 32:
        _fail(SEAL_REFUSED,
              "x25519 shared secret is all zero (small-order input); refused")
    return out


def x25519_pub(priv):
    """The X25519 public key for a 32-byte private key."""
    return x25519(priv, _X25519_BASE_U)


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869) and the EtM AEAD.
# ---------------------------------------------------------------------------

def _hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk, info, length):
    if length <= 0 or length > 255 * 32:
        _fail(SEAL_REFUSED, "hkdf: bad output length")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]),
                     hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf(ikm, salt, info, length=32):
    """HKDF-SHA256 (RFC 5869)."""
    return _hkdf_expand(_hkdf_extract(salt, ikm), info, length)


def _xor_stream(key, nonce, nbytes):
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out += hmac.new(
            key,
            _DOMAIN + b"ctr\x00" + nonce + counter.to_bytes(8, "little"),
            hashlib.sha256).digest()
        counter += 1
    return bytes(out[:nbytes])


def _len_prefix(b):
    return len(b).to_bytes(8, "little")


def aead_seal(key, aad, plaintext):
    """Encrypt-then-MAC seal. Returns (nonce, ciphertext, tag).

    Tag = HMAC-SHA256(key, "tag" || len(aad) || aad || len(nonce) ||
    nonce || len(ct) || ct) truncated to 16 bytes. Nonces are 192-bit
    random and never caller-supplied.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        _fail(SEAL_REFUSED, "aead key must be 32 bytes")
    if not isinstance(aad, (bytes, bytearray)):
        _fail(SEAL_REFUSED, "aead aad must be bytes")
    if not isinstance(plaintext, (bytes, bytearray)):
        _fail(SEAL_REFUSED, "aead plaintext must be bytes")
    key = bytes(key)
    aad = bytes(aad)
    plaintext = bytes(plaintext)
    nonce = secrets.token_bytes(24)
    keystream = _xor_stream(key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream))
    tag = hmac.new(
        key,
        _DOMAIN + b"tag\x00" + _len_prefix(aad) + aad
        + _len_prefix(nonce) + nonce + _len_prefix(ct) + ct,
        hashlib.sha256).digest()[:16]
    return nonce, ct, tag


def aead_open(key, aad, nonce, ct, tag):
    """Verify-then-decrypt. Refuses ``envelope-mac-failed`` on any tag
    mismatch; the plaintext is never returned unverified."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        _fail(MAC_FAILED, "aead key must be 32 bytes")
    key = bytes(key)
    expect = hmac.new(
        key,
        _DOMAIN + b"tag\x00" + _len_prefix(bytes(aad)) + bytes(aad)
        + _len_prefix(bytes(nonce)) + bytes(nonce)
        + _len_prefix(bytes(ct)) + bytes(ct),
        hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expect, bytes(tag)):
        _fail(MAC_FAILED, "aead tag mismatch; refusing")
    keystream = _xor_stream(key, bytes(nonce), len(bytes(ct)))
    return bytes(a ^ b for a, b in zip(bytes(ct), keystream))


# ---------------------------------------------------------------------------
# Audit-event plumbing (the wave-282 discovery-registry precedent):
# digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def set_emit(emit):
    """Install (or clear, with None) the audit-event sink. The
    deployment chains these events into the HMAC audit log."""
    global _EMIT
    _EMIT = emit


def _emit(event):
    if _EMIT is not None:
        _EMIT(dict(event))


def envelope_digest(envelope):
    """Digest of the canonical envelope (identity for audit events)."""
    return hashlib.sha256(_canonical(envelope)).hexdigest()


# ---------------------------------------------------------------------------
# Recipient policy: the .sops.yaml creation-rules analog, as JSON
# (stdlib has no YAML; the schema is YAML-shape-compatible).
# ---------------------------------------------------------------------------

_RECIPIENT_TYPES = ("offline", "custody")


def _check_recipient(rec):
    if not isinstance(rec, dict):
        _fail(POLICY_INVALID, "recipient must be an object")
    rid = rec.get("id")
    if not isinstance(rid, str) or not rid or len(rid) > 128:
        _fail(POLICY_INVALID, "recipient id must be a non-empty string")
    rtype = rec.get("type")
    if rtype not in _RECIPIENT_TYPES:
        _fail(POLICY_INVALID,
              "recipient %r: type must be one of %s, got %r"
              % (rid, _RECIPIENT_TYPES, rtype))
    if rtype == "offline":
        pub_hex = rec.get("x25519_pub")
        if not isinstance(pub_hex, str):
            _fail(POLICY_INVALID,
                  "recipient %r: offline needs x25519_pub hex" % rid)
        pub = _unhex_policy(pub_hex, "x25519_pub")
        if len(pub) != 32:
            _fail(POLICY_INVALID,
                  "recipient %r: x25519_pub must be 32 bytes" % rid)
        if pub == b"\x00" * 32:
            _fail(POLICY_INVALID,
                  "recipient %r: x25519_pub is all zero" % rid)
    else:  # custody
        provider = rec.get("provider")
        key_ref = rec.get("key_ref")
        if not isinstance(provider, str) or not provider:
            _fail(POLICY_INVALID,
                  "recipient %r: custody needs a provider name" % rid)
        if not isinstance(key_ref, str) or not key_ref:
            _fail(POLICY_INVALID,
                  "recipient %r: custody needs a key_ref" % rid)
    return {"id": rid, "type": rtype,
            **({"x25519_pub": rec["x25519_pub"]} if rtype == "offline"
               else {"provider": rec["provider"], "key_ref": rec["key_ref"]})}


def _unhex_policy(s, what):
    try:
        return bytes.fromhex(s)
    except (TypeError, ValueError):
        _fail(POLICY_INVALID, "%s is not valid hex" % what)


def _policy_digest(policy):
    return hashlib.sha256(
        _canonical({k: v for k, v in policy.items()
                    if k != "policy_digest"})).hexdigest()


def make_recipient_policy(recipients, *, version=1, min_recipients=1,
                          bundle_scope="*"):
    """Build and validate a recipient policy.

    The policy is the checked-in, versioned, auditable config naming
    who may unwrap a sealed bundle -- the ``.sops.yaml`` creation-rules
    analog. Registration emits a ``recipient-policy-registered`` audit
    event (digests/ids only); policy changes are therefore visible in
    the audit log by construction.

    ``bundle_scope`` is the sops creation-rule analog: ``"*"`` (the
    default) covers every bundle id; any other value is a prefix and
    ``seal_envelope`` refuses a bundle whose id does not start with it
    (``recipient-policy-invalid``).

    ``min_recipients`` is recorded as policy metadata but is NOT
    enforced: any single listed recipient's wrap opens the envelope.
    True Shamir N-of-M threshold wrapping is not implemented; do not
    read ``min_recipients`` as a threshold guarantee.
    """
    if not isinstance(recipients, list) or not recipients:
        _fail(POLICY_INVALID, "recipients must be a non-empty list")
    if not isinstance(version, int) or isinstance(version, bool) \
            or version < 1:
        _fail(POLICY_INVALID, "policy version must be a positive int")
    if not isinstance(min_recipients, int) \
            or isinstance(min_recipients, bool) or min_recipients < 1:
        _fail(POLICY_INVALID, "min_recipients must be a positive int")
    if min_recipients > len(recipients):
        _fail(POLICY_INVALID,
              "min_recipients exceeds the recipient count")
    if not isinstance(bundle_scope, str) or not bundle_scope:
        _fail(POLICY_INVALID, "bundle_scope must be a non-empty string")
    checked = [_check_recipient(r) for r in recipients]
    ids = [r["id"] for r in checked]
    if len(set(ids)) != len(ids):
        _fail(POLICY_INVALID, "duplicate recipient ids")
    policy = {
        "format": POLICY_FORMAT,
        "version": version,
        "bundle_scope": bundle_scope,
        "min_recipients": min_recipients,
        "recipients": checked,
    }
    policy["policy_digest"] = _policy_digest(policy)
    _emit({"event": "recipient-policy-registered",
           "policy_digest": policy["policy_digest"],
           "version": version,
           "recipient_ids": ids})
    return policy


def _check_policy(policy):
    if not isinstance(policy, dict):
        _fail(POLICY_INVALID, "policy must be an object")
    if policy.get("format") != POLICY_FORMAT:
        _fail(POLICY_INVALID, "policy format must be %r" % POLICY_FORMAT)
    recips = policy.get("recipients")
    if not isinstance(recips, list) or not recips:
        _fail(POLICY_INVALID, "policy has no recipients")
    checked = [_check_recipient(r) for r in recips]
    ids = [r["id"] for r in checked]
    if len(set(ids)) != len(ids):
        _fail(POLICY_INVALID, "duplicate recipient ids")
    scope = policy.get("bundle_scope", "*")
    if not isinstance(scope, str) or not scope:
        _fail(POLICY_INVALID, "bundle_scope must be a non-empty string")
    # The digest binds the policy content at use time: a policy edited
    # after registration (recipients added/removed, scope or version
    # changed) no longer matches its digest and is refused. The only
    # honest way to build a policy is make_recipient_policy.
    want = _policy_digest(policy)
    got = policy.get("policy_digest")
    if not isinstance(got, str) or not hmac.compare_digest(got, want):
        _fail(POLICY_INVALID,
              "policy_digest does not match the policy content; "
              "rebuild the policy via make_recipient_policy")
    return checked


# ---------------------------------------------------------------------------
# Sealing.
# ---------------------------------------------------------------------------

def _bundle_aad(bundle_id, bundle_sha256):
    return (_DOMAIN + b"bundle-aad\x00" + bundle_id.encode("utf-8")
            + b"\x00" + bundle_sha256.encode("ascii"))


def _wrap_aad(recipient_id):
    return _DOMAIN + b"data-key-wrap\x00" + recipient_id.encode("utf-8")


def _check_seal_args(bundle_bytes, bundle_id, signer_seed):
    if not isinstance(bundle_bytes, (bytes, bytearray)) \
            or not bundle_bytes:
        _fail(SEAL_REFUSED, "bundle bytes must be non-empty")
    if len(bundle_bytes) > _MAX_BUNDLE_BYTES:
        _fail(SEAL_REFUSED, "bundle exceeds the %d-byte budget"
              % _MAX_BUNDLE_BYTES)
    if not isinstance(bundle_id, str) or not bundle_id \
            or len(bundle_id) > 256:
        _fail(SEAL_REFUSED, "bundle_id must be a non-empty string")
    if not isinstance(signer_seed, (bytes, bytearray)) \
            or len(signer_seed) != 32:
        _fail(SEAL_REFUSED, "signer_seed must be 32 bytes")


def _wrap_offline(data_key, aad_salt, recipient):
    rid = recipient["id"]
    recip_pub = bytes.fromhex(recipient["x25519_pub"])
    eph_priv = secrets.token_bytes(32)
    eph_pub = x25519_pub(eph_priv)
    shared = x25519(eph_priv, recip_pub)
    wrap_key = hkdf(shared, salt=aad_salt,
                    info=_DOMAIN + b"recipient-wrap\x00"
                    + rid.encode("utf-8") + b"\x00" + eph_pub
                    + b"\x00" + recip_pub)
    wnonce, wct, wtag = aead_seal(wrap_key, _wrap_aad(rid), data_key)
    return {"recipient_id": rid, "type": "offline",
            "eph_pub": _hex(eph_pub),
            "recipient_pub": _hex(recip_pub),
            "wrapped": {"nonce": _hex(wnonce), "ct": _hex(wct),
                        "tag": _hex(wtag)}}


def _seal_with_key(bundle_bytes, bundle_id, recipients, signer_seed,
                   data_key, custody_wrap=None):
    bundle_sha256 = hashlib.sha256(bytes(bundle_bytes)).hexdigest()
    aad = _bundle_aad(bundle_id, bundle_sha256)
    nonce, ct, tag = aead_seal(data_key, aad, bytes(bundle_bytes))
    wraps = []
    for recipient in recipients:
        rid = recipient["id"]
        if recipient["type"] == "offline":
            wraps.append(_wrap_offline(data_key,
                                       bytes.fromhex(bundle_sha256),
                                       recipient))
        else:
            if custody_wrap is None:
                _fail(CUSTODY_UNAVAILABLE,
                      "custody recipient %r has no wrap provider" % rid)
            try:
                wrapped = custody_wrap(rid, data_key)
            except EnvelopeError:
                raise
            except Exception as exc:  # noqa: BLE001 -- provider fault
                _fail(CUSTODY_UNAVAILABLE,
                      "custody provider for %r raised: %s" % (rid, exc))
            if not isinstance(wrapped, dict) \
                    or not all(k in wrapped
                               for k in ("nonce", "ct", "tag")):
                _fail(CUSTODY_UNAVAILABLE,
                      "custody provider for %r returned a bad wrap" % rid)
            # Validate the provider's wrap at seal time (hex-decodable,
            # non-empty, sane sizes) so a malformed provider response is
            # a coded refusal here, not a malformed envelope later. The
            # provider's nonce format is its own business -- only the
            # provider's unwrap must understand it.
            for k in ("nonce", "ct", "tag"):
                try:
                    raw = bytes.fromhex(wrapped[k])
                except (TypeError, ValueError):
                    _fail(CUSTODY_UNAVAILABLE,
                          "custody provider for %r returned non-hex %r"
                          % (rid, k))
                if not raw or len(raw) > 4096:
                    _fail(CUSTODY_UNAVAILABLE,
                          "custody provider for %r returned a bad %r"
                          % (rid, k))
            wraps.append({"recipient_id": rid, "type": "custody",
                          "provider": recipient["provider"],
                          "key_ref": recipient["key_ref"],
                          "wrapped": dict(wrapped)})
    header = {
        "envelope_version": ENVELOPE_VERSION,
        "bundle_id": bundle_id,
        "bundle_sha256": bundle_sha256,
        "payload": {"nonce": _hex(nonce), "ct": _hex(ct),
                    "tag": _hex(tag)},
        "wraps": wraps,
    }
    header_mac = hmac.new(
        data_key, _DOMAIN + b"header-mac\x00" + _canonical(header),
        hashlib.sha256).hexdigest()
    envelope = dict(header)
    envelope["header_mac"] = header_mac
    envelope["sigs"] = []
    signer_pub = _ed25519.publickey(bytes(signer_seed))
    sig = _ed25519.sign(bytes(signer_seed),
                        _canonical({k: v for k, v in envelope.items()
                                    if k != "sigs"}))
    envelope["sigs"] = [{"key_id": _signing.ed25519_key_id(signer_pub),
                         "sig": _hex(sig)}]
    return envelope


def _check_scope_covers(policy, bundle_id):
    """Enforce the creation rule: the policy's ``bundle_scope`` must
    cover the bundle id ("*" covers everything). Refuses LOUD with the
    coded ``recipient-policy-invalid`` emission -- the same contract
    ``seal_envelope`` holds. Every re-sealing path (seal, rotate,
    update_wraps) calls this, so a scope check can never silently drift
    out of one of them again."""
    scope = policy.get("bundle_scope", "*")
    if scope != "*" and not bundle_id.startswith(scope):
        _fail(POLICY_INVALID,
              "bundle_id %r is outside the policy scope %r"
              % (bundle_id, scope))


def seal_envelope(bundle_bytes, *, bundle_id, policy, signer_seed,
                  custody_wrap=None):
    """Seal a bundle for the policy's recipients.

    Fresh random data key (``rotate`` semantics); ``custody_wrap`` is
    the deployment's KMS/Vault wrap callable
    ``(recipient_id, data_key) -> {"nonce","ct","tag"}``. Emits an
    ``envelope-sealed`` audit event (digests/ids only).
    """
    _check_seal_args(bundle_bytes, bundle_id, signer_seed)
    recipients = _check_policy(policy)
    # Creation-rule analog: the policy's bundle_scope must cover the
    # bundle id ("*" covers everything).
    _check_scope_covers(policy, bundle_id)
    data_key = secrets.token_bytes(32)
    envelope = _seal_with_key(bytes(bundle_bytes), bundle_id, recipients,
                              bytes(signer_seed), data_key,
                              custody_wrap=custody_wrap)
    _emit({"event": "envelope-sealed",
           "bundle_id": bundle_id,
           "bundle_sha256": envelope["bundle_sha256"],
           "envelope_digest": envelope_digest(envelope),
           "policy_digest": policy.get("policy_digest"),
           "recipient_ids": [r["id"] for r in recipients]})
    return envelope


# ---------------------------------------------------------------------------
# Opening.
# ---------------------------------------------------------------------------

_TOP_LEVEL_KEYS = frozenset((
    "envelope_version", "bundle_id", "bundle_sha256", "payload",
    "wraps", "header_mac", "sigs"))
_PAYLOAD_KEYS = frozenset(("nonce", "ct", "tag"))
_SIG_KEYS = frozenset(("key_id", "sig"))


def _check_envelope_shape(envelope):
    if not isinstance(envelope, dict):
        _fail(MALFORMED, "envelope must be an object")
    if set(envelope) != set(_TOP_LEVEL_KEYS):
        _fail(MALFORMED, "envelope has unknown or missing top-level keys")
    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        _fail(MALFORMED, "unsupported envelope version")
    if not isinstance(envelope.get("bundle_id"), str) \
            or not envelope["bundle_id"]:
        _fail(MALFORMED, "bundle_id malformed")
    try:
        bundle_sha = bytes.fromhex(envelope.get("bundle_sha256", ""))
    except (TypeError, ValueError):
        _fail(MALFORMED, "bundle_sha256 malformed")
    if len(bundle_sha) != 32:
        _fail(MALFORMED, "bundle_sha256 malformed")
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or set(payload) != set(_PAYLOAD_KEYS):
        _fail(MALFORMED, "payload malformed")
    for k in ("nonce", "ct", "tag"):
        _unhex(payload.get(k), "payload.%s" % k)
    if len(bytes.fromhex(payload["nonce"])) != 24:
        _fail(MALFORMED, "payload nonce must be 24 bytes")
    if len(bytes.fromhex(payload["tag"])) != 16:
        _fail(MALFORMED, "payload tag must be 16 bytes")
    try:
        int(envelope.get("header_mac", ""), 16)
    except (TypeError, ValueError):
        _fail(MALFORMED, "header_mac malformed")
    if len(envelope["header_mac"]) != 64:
        _fail(MALFORMED, "header_mac malformed")
    wraps = envelope.get("wraps")
    if not isinstance(wraps, list) or not wraps:
        _fail(MALFORMED, "wraps malformed")
    for w in wraps:
        if not isinstance(w, dict) or "recipient_id" not in w \
                or "type" not in w or "wrapped" not in w:
            _fail(MALFORMED, "wrap entry malformed")
        if w["type"] not in _RECIPIENT_TYPES:
            _fail(MALFORMED, "wrap has unknown recipient type")
        wrapped = w["wrapped"]
        if not isinstance(wrapped, dict) \
                or not all(k in wrapped for k in ("nonce", "ct", "tag")):
            _fail(MALFORMED, "wrapped key malformed")
        for k in ("nonce", "ct", "tag"):
            _unhex(wrapped.get(k), "wrapped.%s" % k)
        if w["type"] == "offline":
            _unhex(w.get("eph_pub"), "eph_pub")
            if len(bytes.fromhex(w["eph_pub"])) != 32:
                _fail(MALFORMED, "eph_pub must be 32 bytes")
            _unhex(w.get("recipient_pub"), "recipient_pub")
            if len(bytes.fromhex(w["recipient_pub"])) != 32:
                _fail(MALFORMED, "recipient_pub must be 32 bytes")
    sigs = envelope.get("sigs")
    if not isinstance(sigs, list):
        _fail(MALFORMED, "sigs malformed")
    for s in sigs:
        if not isinstance(s, dict) or set(s) != _SIG_KEYS:
            _fail(MALFORMED, "sig entry malformed")
        _unhex(s.get("sig"), "sig")
        if len(bytes.fromhex(s["sig"])) != 64:
            _fail(MALFORMED, "sig must be 64 bytes")


def _verify_signatures(envelope, trusted_signer_pubs):
    sigs = envelope.get("sigs") or []
    if not sigs:
        _fail(SIGNATURE_INVALID, "envelope carries no signatures")
    if not trusted_signer_pubs:
        _fail(SIGNATURE_INVALID, "no trusted signer keys configured")
    body = _canonical({k: v for k, v in envelope.items() if k != "sigs"})
    for entry in sigs:
        sig = bytes.fromhex(entry["sig"])
        for pub in trusted_signer_pubs:
            # Wave-243 lesson: gov.ed25519.verify returns True/False and
            # never raises -- the return MUST be checked.
            try:
                ok = _ed25519.verify(bytes(pub), body, sig)
            except Exception:  # noqa: BLE001 -- a verifier fault is a refusal
                ok = False
            if ok is True:
                return
    _fail(SIGNATURE_INVALID,
          "no envelope signature verifies under a trusted key")


def _unwrap_data_key(wrap, x25519_priv, custody_unwrap, bundle_sha256_hex):
    rid = wrap["recipient_id"]
    if wrap["type"] == "offline":
        if not isinstance(x25519_priv, (bytes, bytearray)) \
                or len(x25519_priv) != 32:
            _fail(UNWRAP_FAILED,
                  "offline unwrap needs the recipient's 32-byte x25519 key")
        eph_pub = bytes.fromhex(wrap["eph_pub"])
        recip_pub = bytes.fromhex(wrap["recipient_pub"])
        try:
            shared = x25519(bytes(x25519_priv), eph_pub)
        except EnvelopeError:
            _fail(UNWRAP_FAILED,
                  "key agreement failed for recipient %r" % rid)
        wrap_key = hkdf(shared, salt=bytes.fromhex(bundle_sha256_hex),
                        info=_DOMAIN + b"recipient-wrap\x00"
                        + rid.encode("utf-8") + b"\x00" + eph_pub
                        + b"\x00" + recip_pub)
        # A cross-recipient unwrap attempt derives a different wrap key
        # (the KDF binds eph_pub, recip_pub, and the recipient id), so
        # the encrypt-then-MAC tag refuses -- pinned by
        # p_recipient_isolation.
        wrapped = wrap["wrapped"]
        try:
            return aead_open(wrap_key, _wrap_aad(rid),
                             bytes.fromhex(wrapped["nonce"]),
                             bytes.fromhex(wrapped["ct"]),
                             bytes.fromhex(wrapped["tag"]))
        except EnvelopeError:
            _fail(UNWRAP_FAILED,
                  "data-key unwrap failed for recipient %r" % rid)
    # custody
    if custody_unwrap is None:
        _fail(CUSTODY_UNAVAILABLE,
              "custody recipient %r has no unwrap provider" % rid)
    try:
        data_key = custody_unwrap(rid, wrap["wrapped"])
    except EnvelopeError:
        raise
    except Exception as exc:  # noqa: BLE001 -- provider failure is a refusal
        _fail(UNWRAP_FAILED,
              "custody unwrap failed for recipient %r: %s" % (rid, exc))
    if not isinstance(data_key, (bytes, bytearray)) or len(data_key) != 32:
        _fail(UNWRAP_FAILED,
              "custody provider returned a bad data key for %r" % rid)
    return bytes(data_key)


def open_envelope(envelope, *, recipient_id, x25519_priv=None,
                  custody_unwrap=None, trusted_signer_pubs,
                  expected_bundle_id=None):
    """Open an envelope for one recipient.

    Order of checks: structural shape -> authorship signatures ->
    recipient wrap -> header MAC -> payload EtM -> bundle-identity
    binding. Every failure is a coded ``EnvelopeError``; the plaintext
    is never returned unverified.
    """
    _check_envelope_shape(envelope)
    _verify_signatures(envelope, trusted_signer_pubs)
    wrap = next((w for w in envelope["wraps"]
                 if w["recipient_id"] == recipient_id), None)
    if wrap is None:
        _fail(RECIPIENT_UNKNOWN,
              "no wrap for recipient %r" % (recipient_id,))
    data_key = _unwrap_data_key(wrap, x25519_priv, custody_unwrap,
                                envelope["bundle_sha256"])
    header = {k: envelope[k] for k in
              ("envelope_version", "bundle_id", "bundle_sha256",
               "payload", "wraps")}
    expect_mac = hmac.new(
        data_key, _DOMAIN + b"header-mac\x00" + _canonical(header),
        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect_mac, envelope["header_mac"]):
        _fail(MAC_FAILED, "envelope header MAC mismatch; refusing")
    bundle_id = envelope["bundle_id"]
    bundle_sha256 = envelope["bundle_sha256"]
    aad = _bundle_aad(bundle_id, bundle_sha256)
    payload = envelope["payload"]
    try:
        plaintext = aead_open(data_key, aad,
                              bytes.fromhex(payload["nonce"]),
                              bytes.fromhex(payload["ct"]),
                              bytes.fromhex(payload["tag"]))
    except EnvelopeError:
        _fail(MAC_FAILED, "payload authentication failed; refusing")
    if hashlib.sha256(plaintext).hexdigest() != bundle_sha256:
        _fail(AAD_MISMATCH, "bundle digest does not match the envelope")
    if expected_bundle_id is not None and bundle_id != expected_bundle_id:
        _fail(AAD_MISMATCH,
              "bundle id %r does not match the expected %r"
              % (bundle_id, expected_bundle_id))
    _emit({"event": "envelope-opened",
           "bundle_id": bundle_id,
           "envelope_digest": envelope_digest(envelope),
           "recipient_id": recipient_id})
    return plaintext


# ---------------------------------------------------------------------------
# Re-keying ceremony: rotate (fresh data key) and updatekeys (same data
# key, new recipient set). Both require opening the old envelope first,
# and the ceremony holder must be BOTH an authorized recipient (to
# unwrap the data key) AND hold the original envelope signer seed (the
# re-sealed envelope is signed with it, and the signature check on the
# old envelope is verified against the seed-derived public key).
# Both ceremonies are audit events carrying digests only.
# ---------------------------------------------------------------------------

def _open_for_rekey(envelope, recipient_id, x25519_priv, custody_unwrap,
                    signer_seed):
    trusted = [_ed25519.publickey(bytes(signer_seed))]
    try:
        return open_envelope(envelope, recipient_id=recipient_id,
                             x25519_priv=x25519_priv,
                             custody_unwrap=custody_unwrap,
                             trusted_signer_pubs=trusted)
    except EnvelopeError as exc:
        _fail(REKEY_REFUSED,
              "rekey refused: the ceremony holder could not open the "
              "envelope -- the ceremony requires an authorized "
              "recipient credential AND the original envelope signer "
              "seed (%s: %s)" % (exc.code, exc))


def rotate_envelope(envelope, *, recipient_id, x25519_priv=None,
                    custody_unwrap=None, policy, signer_seed,
                    custody_wrap=None):
    """Fresh data key, re-encrypt, re-wrap (sops ``rotate``).

    The plaintext bundle is unchanged; the old data key is discarded.
    The ceremony holder must hold the original envelope signer seed
    (in addition to an authorized recipient credential). The new
    policy's ``bundle_scope`` must cover the bundle id (same
    creation-rule contract as ``seal_envelope``); a non-covering
    policy is refused LOUD with ``recipient-policy-invalid``.
    """
    _check_policy(policy)
    plaintext = _open_for_rekey(envelope, recipient_id, x25519_priv,
                                custody_unwrap, signer_seed)
    recipients = _check_policy(policy)
    # Creation-rule analog, same contract as seal_envelope: the new
    # policy's bundle_scope must cover the bundle being re-sealed.
    _check_scope_covers(policy, envelope["bundle_id"])
    new_key = secrets.token_bytes(32)
    new_envelope = _seal_with_key(
        plaintext, envelope["bundle_id"], recipients,
        bytes(signer_seed), new_key, custody_wrap=custody_wrap)
    _emit({"event": "envelope-rotated",
           "bundle_id": envelope["bundle_id"],
           "old_envelope_digest": envelope_digest(envelope),
           "new_envelope_digest": envelope_digest(new_envelope),
           "policy_digest": policy.get("policy_digest")})
    return new_envelope


def update_wraps(envelope, *, recipient_id, x25519_priv=None,
                 custody_unwrap=None, new_policy, signer_seed,
                 custody_wrap=None):
    """Same data key, new recipient set (sops ``updatekeys``).

    Revocation semantics, stated honestly: removing a recipient stops
    FUTURE envelopes from wrapping for them. A recipient who already
    opened an older envelope holds its plaintext -- cryptography cannot
    un-read bytes. The ceremony is audited either way.

    The ceremony holder must hold the original envelope signer seed
    (in addition to an authorized recipient credential). The new
    policy's ``bundle_scope`` must cover the bundle id (same
    creation-rule contract as ``seal_envelope``); a non-covering
    policy is refused LOUD with ``recipient-policy-invalid``.
    """
    _check_envelope_shape(envelope)
    recipients = _check_policy(new_policy)
    plaintext = _open_for_rekey(envelope, recipient_id, x25519_priv,
                                custody_unwrap, signer_seed)
    # Creation-rule analog, same contract as seal_envelope: the new
    # policy's bundle_scope must cover the bundle being re-sealed.
    _check_scope_covers(new_policy, envelope["bundle_id"])
    # Recover the current data key to re-wrap it (not re-encrypt).
    wrap = next(w for w in envelope["wraps"]
                if w["recipient_id"] == recipient_id)
    data_key = _unwrap_data_key(wrap, x25519_priv, custody_unwrap,
                                envelope["bundle_sha256"])
    new_envelope = _seal_with_key(
        plaintext, envelope["bundle_id"], recipients,
        bytes(signer_seed), data_key, custody_wrap=custody_wrap)
    _emit({"event": "envelope-wraps-updated",
           "bundle_id": envelope["bundle_id"],
           "old_envelope_digest": envelope_digest(envelope),
           "new_envelope_digest": envelope_digest(new_envelope),
           "policy_digest": new_policy.get("policy_digest"),
           "recipient_ids": [r["id"] for r in recipients]})
    return new_envelope
