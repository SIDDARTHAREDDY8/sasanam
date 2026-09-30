"""DSSE (Dead Simple Signing Envelope) for Sasanam.

PATTERN LINEAGE: secure-systems-lab/dsse (Apache-2.0) -- the envelope
shape ``{payload, payloadType, signatures}`` with explicit parsing rules
and PAE (Pre-Authentication Encoding). Re-implemented in stdlib Python;
no DSSE code is vendored here, only the pattern. This envelope
SUPERSEDES the age/minisign trusted-comments sketch of
gov.signature_envelope_v2 for envelope FORMAT (wave-203 prospecting,
section 3, verdict STEAL): the payload *type* is inside the signed
bytes, so a signature cannot be transplanted onto a different payload
type -- envelope shape bugs are killed by construction. It also aligns
with Rekor v2, whose typed entries already only accept DSSE shapes.

Envelope JSON::

    {"payload": "<base64>",
     "payloadType": "application/vnd.sasanam.statement+json",
     "signatures": [{"keyid": "<key id>", "sig": "<hex ed25519>"}, ...]}

``payload``, ``payloadType``, ``signature`` and ``signature.sig`` are
REQUIRED; ``signature.keyid`` is OPTIONAL (per the DSSE spec). Unknown
top-level fields are refused fail-closed.

PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body,
signed with the project's Ed25519 ceremony (algorithm agility is by
design in DSSE; our ``gov.signing`` signers drop straight in).

Trusted-comments port (brief section 3): DSSE has no comments field.
The choice made here is to carry the trusted comments -- and the
provenance binding -- INSIDE the signed payload as a canonical-JSON
statement::

    {"payload_sha256": "<hex>",
     "provenance_digest": "<hex>" | null,
     "trusted_comments": ["..."]}

Trade-off, stated honestly: the DSSE payload is a *binding statement*,
not the raw artifact bytes -- the artifact is bound by digest (exactly
as in gov.signature_envelope_v2). An auditor hashes the artifact and
compares to ``payload_sha256`` rather than reading it from the envelope.
What this buys: ONE signature still covers key + payload + provenance +
comments (the wave-202 lane-B discipline, unchanged), while the PAE
additionally binds the payload TYPE into the signed bytes.

Migration: v2 (minisign-pattern) envelopes still verify -- ``open_any``
dispatches on envelope shape and delegates v2 envelopes to
gov.signature_envelope_v2. New envelopes are DSSE-shaped.

Quorum is policy, not format: DSSE carries the signatures; the caller
names the ``threshold`` of distinct keys that must verify. ``threshold``
defaults to 1.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import base64
import binascii
import hashlib
import json

from .signing import Verifier

__all__ = [
    "STATEMENT_PAYLOAD_TYPE",
    "EnvelopeError",
    "pae",
    "seal",
    "parse_envelope",
    "open_envelope",
    "seal_statement",
    "open_statement",
    "detect_envelope",
    "open_any",
]

STATEMENT_PAYLOAD_TYPE = "application/vnd.sasanam.statement+json"

_ENVELOPE_FIELDS = frozenset({"payload", "payloadType", "signatures"})
_SIGNATURE_FIELDS = frozenset({"keyid", "sig"})
_STATEMENT_FIELDS = frozenset({"payload_sha256", "provenance_digest",
                               "trusted_comments"})


class EnvelopeError(ValueError):
    """Raised loudly on any DSSE envelope parse/verify failure.

    Wave-232: carries a machine ``reason`` (the closed refusal code).
    Older raise sites pass no code; ``reason`` then defaults to the
    message, so existing behavior is unchanged.
    """

    def __init__(self, message, code=None):
        super().__init__(message)
        self.reason = code if code is not None else message


def _check_hex_digest(value, where):
    if not isinstance(value, str):
        raise EnvelopeError("%s: digest must be str, got %s"
                            % (where, type(value).__name__))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise EnvelopeError("%s: not a sha256 hex digest: %r"
                            % (where, value))
    return value


def _check_sig_hex(value, where):
    if not isinstance(value, str):
        raise EnvelopeError("%s: signature must be str, got %s"
                            % (where, type(value).__name__))
    if len(value) != 128 or any(c not in "0123456789abcdef" for c in value):
        raise EnvelopeError("%s: signature must be 128 lowercase hex chars"
                            % where)
    return value


def pae(payload_type, payload):
    """Pre-Authentication Encoding: b"DSSEv1" SP LEN(type) SP type SP
    LEN(body) SP body. Length-prefixing kills concatenation ambiguity;
    the type is inside the signed bytes, killing type-swap attacks."""
    if not isinstance(payload_type, str) or not payload_type:
        raise EnvelopeError("payload_type must be a non-empty str")
    if not isinstance(payload, (bytes, bytearray)):
        raise EnvelopeError("payload must be bytes")
    type_bytes = payload_type.encode("utf-8")
    body = bytes(payload)
    return (b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" "
            + type_bytes + b" " + str(len(body)).encode("ascii") + b" "
            + body)


def _b64_decode(value, where):
    if not isinstance(value, str):
        raise EnvelopeError("%s: must be a base64 str, got %s"
                            % (where, type(value).__name__))
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise EnvelopeError("%s: invalid base64: %s" % (where, exc))


def seal(payload, payload_type, signers):
    """Seal ``payload`` bytes into a DSSE envelope, signed by each signer
    in ``signers`` over ``pae(payload_type, payload)``."""
    pae_bytes = pae(payload_type, payload)  # validates type + payload
    signers = list(signers)
    if not signers:
        raise EnvelopeError("seal requires at least one signer")
    sigs = []
    for signer in signers:
        sig = signer.sign(pae_bytes)
        sigs.append({"keyid": signer.key_id, "sig": bytes(sig).hex()})
    return {
        "payload": base64.b64encode(bytes(payload)).decode("ascii"),
        "payloadType": payload_type,
        "signatures": sigs,
    }


def parse_envelope(envelope):
    """Strict-parse a DSSE envelope.

    Returns ``(payload_bytes, payload_type, [(keyid_or_None, sig_bytes)])``.
    Refuses unknown fields, missing fields, bad base64, and malformed
    signature entries -- fail-closed, never defaulted.
    """
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a dict")
    extra = set(envelope) - _ENVELOPE_FIELDS
    if extra:
        raise EnvelopeError("unknown envelope field(s) refused: %s"
                            % sorted(extra))
    missing = _ENVELOPE_FIELDS - set(envelope)
    if missing:
        raise EnvelopeError("envelope missing field(s): %s" % sorted(missing))
    payload_type = envelope["payloadType"]
    if not isinstance(payload_type, str) or not payload_type:
        raise EnvelopeError("payloadType must be a non-empty str")
    payload = _b64_decode(envelope["payload"], "payload")
    sig_entries = envelope["signatures"]
    if not isinstance(sig_entries, list) or not sig_entries:
        raise EnvelopeError("signatures must be a non-empty list")
    parsed = []
    for i, entry in enumerate(sig_entries):
        where = "signatures[%d]" % i
        if not isinstance(entry, dict):
            raise EnvelopeError("%s: must be a dict" % where)
        extra = set(entry) - _SIGNATURE_FIELDS
        if extra:
            raise EnvelopeError("%s: unknown field(s) refused: %s"
                                % (where, sorted(extra)))
        if "sig" not in entry:
            raise EnvelopeError("%s: missing required 'sig'" % where)
        sig = _check_sig_hex(entry["sig"], where + ".sig")
        keyid = entry.get("keyid")
        if keyid is not None and (not isinstance(keyid, str) or not keyid):
            raise EnvelopeError("%s: keyid must be a non-empty str when "
                                "present" % where)
        parsed.append((keyid, bytes.fromhex(sig)))
    return payload, payload_type, parsed


def _verifier_for(keyid, verifiers):
    if keyid is None:
        return None  # keyid-less: try every verifier at open time
    for verifier in verifiers:
        if verifier.key_id == keyid:
            return verifier
    return None


def open_envelope(envelope, expected_payload, payload_type, verifiers,
                  threshold=1, allowed_payload_types=None):
    """Open and verify a DSSE envelope. Raises loudly on any violation.

    Checks, in order: strict parse; payloadType binding against
    ``payload_type``; allowlist (when given); ``threshold`` distinct-key
    signatures over ``pae(payload_type, payload)``; payload-bytes binding
    against ``expected_payload``.

    The signature is checked BEFORE the payload binding: authentication
    precedes binding, so a tampered payload is refused on the signature
    path, not merely on the digest comparison.
    """
    verifiers = list(verifiers)
    if not verifiers:
        raise EnvelopeError("open_envelope requires at least one verifier")
    if not isinstance(threshold, int) or threshold < 1:
        raise EnvelopeError("threshold must be a positive int")
    if not isinstance(payload_type, str) or not payload_type:
        raise EnvelopeError("payload_type must be a non-empty str")
    if not isinstance(expected_payload, (bytes, bytearray)):
        raise EnvelopeError("expected_payload must be bytes")

    payload, got_type, sig_entries = parse_envelope(envelope)
    if got_type != payload_type:
        raise EnvelopeError("payloadType mismatch: envelope carries %r, "
                            "expected %r" % (got_type, payload_type))
    if allowed_payload_types is not None and \
            got_type not in allowed_payload_types:
        raise EnvelopeError("payloadType %r not in allowlist" % got_type)

    pae_bytes = pae(payload_type, payload)
    good_key_ids = set()
    for keyid, sig in sig_entries:
        if keyid is None:
            # keyid-less signature: try every verifier, attribute to the
            # one whose key actually verifies (fail-closed: unverifiable
            # against all verifiers contributes nothing).
            matches = [v for v in verifiers
                       if isinstance(v, Verifier) and v.verify(pae_bytes, sig)]
        else:
            verifier = _verifier_for(keyid, verifiers)
            if verifier is None or not isinstance(verifier, Verifier):
                continue
            matches = [verifier] if verifier.verify(pae_bytes, sig) else []
        for match in matches:
            good_key_ids.add(match.key_id)
    if len(good_key_ids) < threshold:
        raise EnvelopeError("signature threshold not met: %d of %d "
                            "distinct key(s) verified"
                            % (len(good_key_ids), threshold))
    if payload != bytes(expected_payload):
        raise EnvelopeError("payload binding mismatch: envelope payload "
                            "does not equal the expected payload bytes")
    return {
        "key_ids": sorted(good_key_ids),
        "payload_type": got_type,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _statement_bytes(payload_digest, provenance_digest, comments):
    payload_digest = _check_hex_digest(payload_digest, "payload_digest")
    if provenance_digest is not None:
        provenance_digest = _check_hex_digest(provenance_digest,
                                              "provenance_digest")
    comments = list(comments)
    if not comments or not all(isinstance(c, str) and c for c in comments):
        raise EnvelopeError("trusted_comments must be a non-empty list of "
                            "non-empty strings")
    return json.dumps({"payload_sha256": payload_digest,
                       "provenance_digest": provenance_digest,
                       "trusted_comments": comments},
                      sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def seal_statement(payload_digest, provenance_digest, comments, signers,
                   payload_type=STATEMENT_PAYLOAD_TYPE):
    """Seal the trusted-comments + provenance binding statement as a DSSE
    envelope. One signature binds key + payload digest + provenance digest
    + comments (the wave-202 lane-B discipline), with the payload TYPE
    additionally bound by the PAE."""
    return seal(_statement_bytes(payload_digest, provenance_digest,
                                comments),
                payload_type, signers)


def open_statement(envelope, payload_digest, provenance_digest, comments,
                   verifiers, threshold=1,
                   payload_type=STATEMENT_PAYLOAD_TYPE,
                   allowed_payload_types=None):
    """Open a statement envelope and check every binding. Raises loudly.

    ``provenance_digest`` is positional and always explicit: pass None to
    accept a provenance-free statement. There is no silent downgrade from
    a provenance-carrying statement to a provenance-free one.
    """
    if not isinstance(verifiers, list):
        verifiers = list(verifiers)
    payload = _statement_bytes(payload_digest, provenance_digest, comments)
    opened = open_envelope(envelope, payload, payload_type, verifiers,
                           threshold=threshold,
                           allowed_payload_types=allowed_payload_types)
    try:
        stmt = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EnvelopeError("statement payload is not valid JSON: %s" % exc)
    if not isinstance(stmt, dict):
        raise EnvelopeError("statement payload must be a JSON object")
    extra = set(stmt) - _STATEMENT_FIELDS
    if extra:
        raise EnvelopeError("statement has unknown field(s) refused: %s"
                            % sorted(extra))
    missing = _STATEMENT_FIELDS - set(stmt)
    if missing:
        raise EnvelopeError("statement missing field(s): %s" % sorted(missing))
    # Re-derive the canonical bytes from the decoded statement and require
    # byte-equality with the envelope payload: the signature already
    # authenticates the payload, this additionally pins the shape so a
    # non-canonical-but-equivalent JSON cannot slip through.
    rederived = _statement_bytes(stmt["payload_sha256"],
                                stmt["provenance_digest"],
                                stmt["trusted_comments"])
    if rederived != payload:
        raise EnvelopeError("statement is not in canonical form")
    return {
        "key_ids": opened["key_ids"],
        "payload_type": opened["payload_type"],
        "payload_sha256": stmt["payload_sha256"],
        "provenance_digest": stmt["provenance_digest"],
        "trusted_comments": list(stmt["trusted_comments"]),
    }


def detect_envelope(envelope):
    """Identify an envelope's format by shape: "dsse" or "v2". Raises
    loudly on anything else."""
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a dict")
    if {"payload", "payloadType", "signatures"} <= set(envelope):
        return "dsse"
    if envelope.get("format") == "sasanam-envelope/v2":
        return "v2"
    raise EnvelopeError("unrecognized envelope shape: not DSSE and not "
                        "sasanam-envelope/v2")


def open_any(envelope, payload_digest, provenance_digest, comments,
             verifiers):
    """Migration helper: open either a DSSE statement envelope or a legacy
    minisign-pattern v2 envelope. v2 envelopes are delegated to
    gov.signature_envelope_v2 with the provenance expectation passed
    explicitly -- already-sealed envelopes are not stranded."""
    kind = detect_envelope(envelope)
    if kind == "dsse":
        got = open_statement(envelope, payload_digest, provenance_digest,
                             comments, verifiers)
        got["format"] = "dsse"
        return got
    from . import signature_envelope_v2 as _env2
    got = _env2.open_envelope(envelope, payload_digest,
                              _first_verifier(verifiers),
                              expected_provenance_digest=provenance_digest)
    got["format"] = "v2"
    return got


def _first_verifier(verifiers):
    verifiers = list(verifiers)
    if not verifiers:
        raise EnvelopeError("open_any requires at least one verifier")
    return verifiers[0]


# ---------------------------------------------------------------------------
# Wave-232: vendored payload-type namespace, strict PAE decode, plain
# callback interface.
#
# The DSSE PAE already binds (payloadType, payload) into the signed bytes,
# killing envelope-shape bugs by construction (F195 pressure). What it did
# NOT enforce: the payloadType NAMESPACE. A generic "application/json"
# type lets an attacker re-present one artifact's signature under a
# different semantic. These helpers close that: only
# ``application/vnd.sasanam.*+json`` is signable, and a strict
# PAE decoder admits exactly one parse (no leading-zero lengths, no
# trailing bytes, no second attempt).
#
# Curves note (cosign #5029, closed unmerged 2026-09-30): no P-384/P-521
# key ever enters this path; signers here are the project's Ed25519 and
# HMAC-SHA256 tiers only.
# ---------------------------------------------------------------------------

VENDORED_TYPE_PREFIX = "application/vnd.sasanam."
VENDORED_TYPE_SUFFIX = "+json"

_DS_ENVELOPE_FIELDS = frozenset(
    {"payloadType", "payload", "signatures", "signing_input_digest"})
_DS_SIG_FIELDS = frozenset({"keyid", "sig"})

_MAX_PAE_LEN_DIGITS = 12
_MAX_PAE_FIELD_BYTES = 4 * 1024 * 1024

# Wave-233: verifier-domain registry. payloadType -> domain and
# domain -> {payloadType}. Populated by consumer modules (deny_receipts,
# decision_packet) through register_envelope_domain(); a payloadType
# registered to no domain is not a transplant.
_ENVELOPE_DOMAIN_TYPES = {}
_ENVELOPE_DOMAINS = {}


def register_envelope_domain(domain, payload_type):
    """Bind a vendored ``payloadType`` to a verifier module domain.

    Domains let :func:`verify_envelope` name a cross-module transplant:
    an envelope whose payloadType is registered to a DIFFERENT domain
    than the verifier expects refuses ``dsse-envelope-transplant``.
    Registration is idempotent. A payloadType registered to no domain
    is not a transplant -- it falls through to the payloadType binding.

    Honest residual: registration is import-time and in-memory. A
    domain whose module was never imported has no registered types, so
    a transplant from it degrades to ``dsse-payloadtype-mismatch`` --
    the refusal code degrades, the verdict (refuse) never does.
    """
    if not isinstance(domain, str) or not domain:
        raise EnvelopeError("envelope domain must be a non-empty str, "
                            "got %r" % (domain,))
    check_payload_type_namespace(payload_type)
    _ENVELOPE_DOMAIN_TYPES[payload_type] = domain
    _ENVELOPE_DOMAINS.setdefault(domain, set()).add(payload_type)
    return payload_type


def envelope_domain_of(payload_type):
    """Return the domain a payloadType is registered to, or None."""
    return _ENVELOPE_DOMAIN_TYPES.get(payload_type)


def check_payload_type_namespace(payload_type):
    """Refuse any payloadType outside ``application/vnd.sasanam.*+json``.

    Refuses ``dsse-payload-type-refused`` -- a generic type (or an empty
    or non-string one) is a refusal at build time, never a downgrade.
    """
    if not isinstance(payload_type, str) or not payload_type:
        raise EnvelopeError(
            "dsse-payload-type-refused: payloadType must be a non-empty "
            "string, got %r" % (payload_type,),
            code="dsse-payload-type-refused")
    if not (payload_type.startswith(VENDORED_TYPE_PREFIX)
            and payload_type.endswith(VENDORED_TYPE_SUFFIX)):
        raise EnvelopeError(
            "dsse-payload-type-refused: payloadType %r is not in the "
            "vendored namespace application/vnd.sasanam.*+json"
            % (payload_type,),
            code="dsse-payload-type-refused")
    return payload_type


def _malformed(detail):
    raise EnvelopeError("dsse-envelope-malformed: %s" % detail,
                        code="dsse-envelope-malformed")


def _take_len_token(rest):
    """Consume one ``LEN SP`` token from ``rest``; return (n, rest)."""
    if b" " not in rest:
        _malformed("truncated length token")
    token, rest = rest.split(b" ", 1)
    if not token or token.strip(b"0123456789"):
        _malformed("length token is not decimal ASCII: %r" % (token,))
    if len(token) > 1 and token.startswith(b"0"):
        _malformed("length token has a leading zero: %r" % (token,))
    if len(token) > _MAX_PAE_LEN_DIGITS:
        _malformed("length token absurdly long")
    n = int(token)
    if n > _MAX_PAE_FIELD_BYTES:
        _malformed("field length %d exceeds cap" % n)
    return n, rest


def pae_decode(pae_bytes):
    """Strict inverse of :func:`pae`.

    Admits exactly one parse of ``DSSEv1 SP LEN SP type SP LEN SP
    body``: leading-zero lengths, non-decimal lengths, truncated fields,
    and trailing bytes all refuse ``dsse-envelope-malformed``. There is
    no second parse to fall back to.
    """
    if not isinstance(pae_bytes, (bytes, bytearray)):
        _malformed("PAE input must be bytes, got %s"
                   % type(pae_bytes).__name__)
    raw = bytes(pae_bytes)
    if not raw.startswith(b"DSSEv1 "):
        _malformed("wrong domain separator (want b'DSSEv1 ')")
    rest = raw[len(b"DSSEv1 "):]
    type_len, rest = _take_len_token(rest)
    if len(rest) < type_len:
        _malformed("type field truncated")
    payload_type = rest[:type_len]
    rest = rest[type_len:]
    if not rest.startswith(b" "):
        _malformed("missing separator after payloadType")
    rest = rest[1:]
    if not payload_type:
        _malformed("payloadType is empty")
    body_len, rest = _take_len_token(rest)
    if len(rest) < body_len:
        _malformed("payload field truncated")
    body = rest[:body_len]
    rest = rest[body_len:]
    if rest:
        _malformed("trailing bytes after payload: %d byte(s)" % len(rest))
    try:
        payload_type_str = payload_type.decode("utf-8")
    except UnicodeDecodeError:
        _malformed("payloadType is not UTF-8")
    return payload_type_str, body


def envelope(payload, *, payload_type, sign, key_id=None):
    """Sign ``payload`` bytes with a plain ``sign(bytes) -> bytes``
    callback, returning a strict envelope dict.

    ``payload_type`` must be in the vendored namespace
    (``dsse-payload-type-refused`` otherwise). The signature covers the
    PAE bytes ``DSSEv1 SP LEN SP payloadType SP LEN SP payload``; the
    envelope additionally carries ``signing_input_digest`` binding the
    exact bytes the signature covers, so a verifier can check the
    binding before trusting the signature.
    """
    check_payload_type_namespace(payload_type)
    if not isinstance(payload, (bytes, bytearray)):
        _malformed("payload must be bytes, got %s" % type(payload).__name__)
    payload = bytes(payload)
    if len(payload) > _MAX_PAE_FIELD_BYTES:
        _malformed("payload exceeds cap")
    pae_bytes = pae(payload_type, payload)
    try:
        sig = sign(pae_bytes)
    except EnvelopeError:
        raise
    except Exception as exc:
        _malformed("signer callback failed: %s" % (exc,))
    if not isinstance(sig, (bytes, bytearray)) or not sig:
        _malformed("signer callback returned empty/non-bytes")
    sig = bytes(sig)
    try:
        sig_hex = sig.hex()
    except Exception:
        _malformed("signature is not hex-encodable")
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": sig_hex}],
        "signing_input_digest":
            hashlib.sha256(pae_bytes).hexdigest(),
    }


def verify_envelope(env, *, verify, expect_payload_type=None,
                    expected_type=None, expected_domain=None,
                    expected_signatures=None):
    """Verify a strict envelope dict with a plain
    ``verify(pae_bytes, sig_bytes) -> bool`` callback.

    Checks, in order: strict shape (``dsse-envelope-malformed`` on any
    ambiguity); vendored payloadType namespace
    (``dsse-payload-type-refused``); legacy ``expect_payload_type``
    binding (``dsse-payload-type-refused``, unchanged); cross-module
    domain binding -- an envelope whose payloadType is registered to a
    different domain than ``expected_domain`` refuses
    ``dsse-envelope-transplant``; ``expected_type`` binding -- a
    payloadType that differs from the expected one refuses
    ``dsse-payloadtype-mismatch``; signature-count discipline --
    zero signatures refuse ``dsse-envelope-no-signature``, and more
    than one signature refuses ``dsse-envelope-multi-signature``
    UNLESS the caller opts in with keyword-only
    ``expected_signatures=N`` (N>=1 int), in which case the envelope
    must carry exactly N signatures and EVERY listed signature must
    verify (no partial acceptance); ``signing_input_digest`` binding;
    then the callback over the PAE bytes for EVERY listed signature
    (``dsse-signature-invalid`` on any failure).

    Defaults (no new kwargs) are unchanged from wave-232: exactly one
    signature is required, as before.

    Returns ``{"ok": True, "payload": bytes, "payload_type": str,
    "key_id": ...}`` on success.
    """
    if not isinstance(env, dict):
        _malformed("envelope must be a dict, got %s" % type(env).__name__)
    extra = set(env) - _DS_ENVELOPE_FIELDS
    if extra:
        _malformed("unknown envelope field(s) refused: %s" % sorted(extra))
    missing = _DS_ENVELOPE_FIELDS - set(env)
    if missing:
        _malformed("envelope missing field(s): %s" % sorted(missing))
    got_type = env["payloadType"]
    check_payload_type_namespace(got_type)
    if expect_payload_type is not None and got_type != expect_payload_type:
        raise EnvelopeError(
            "dsse-payload-type-refused: envelope carries payloadType %r, "
            "expected %r" % (got_type, expect_payload_type),
            code="dsse-payload-type-refused")
    # Wave-233: cross-module transplant is named before the plain
    # type binding, so a decision-packet envelope presented to a
    # denial-receipt verifier refuses dsse-envelope-transplant rather
    # than the generic mismatch code.
    if expected_domain is not None:
        if not isinstance(expected_domain, str) or not expected_domain:
            _malformed("expected_domain must be a non-empty str, got %r"
                       % (expected_domain,))
        home_domain = _ENVELOPE_DOMAIN_TYPES.get(got_type)
        if home_domain is not None and home_domain != expected_domain:
            raise EnvelopeError(
                "dsse-envelope-transplant: envelope payloadType %r is "
                "registered to domain %r, not the expected domain %r "
                "(cross-module transplant)" % (got_type, home_domain,
                                               expected_domain),
                code="dsse-envelope-transplant")
    if expected_type is not None and got_type != expected_type:
        raise EnvelopeError(
            "dsse-payloadtype-mismatch: envelope carries payloadType %r, "
            "expected %r" % (got_type, expected_type),
            code="dsse-payloadtype-mismatch")
    if expected_signatures is not None:
        if (isinstance(expected_signatures, bool)
                or not isinstance(expected_signatures, int)
                or expected_signatures < 1):
            _malformed("expected_signatures must be an int >= 1, got %r"
                       % (expected_signatures,))
    payload = _b64_decode(env["payload"], "payload")
    sig_entries = env["signatures"]
    if not isinstance(sig_entries, list):
        _malformed("signatures must be a list")
    # Wave-233: exactly-one-signature discipline. A zero-signature
    # envelope was previously refused as malformed; the shape is now
    # named. Default (no opt-in) requires exactly one signature.
    n_sigs = len(sig_entries)
    if n_sigs == 0:
        raise EnvelopeError(
            "dsse-envelope-no-signature: envelope carries no signatures",
            code="dsse-envelope-no-signature")
    want = 1 if expected_signatures is None else expected_signatures
    if n_sigs != want:
        raise EnvelopeError(
            "dsse-envelope-multi-signature: envelope carries %d "
            "signature(s), %s requires exactly %d"
            % (n_sigs,
               "the default discipline" if expected_signatures is None
               else "expected_signatures=%d" % expected_signatures,
               want),
            code="dsse-envelope-multi-signature")
    parsed_sigs = []
    for i, entry in enumerate(sig_entries):
        where = "signatures[%d]" % i
        if not isinstance(entry, dict):
            _malformed("%s: must be a dict" % where)
        extra = set(entry) - _DS_SIG_FIELDS
        if extra:
            _malformed("%s: unknown field(s) refused: %s"
                       % (where, sorted(extra)))
        raw = entry.get("sig")
        if not isinstance(raw, str) or not raw:
            _malformed("%s: sig must be a non-empty string" % where)
        try:
            sig_bytes = bytes.fromhex(raw)
        except ValueError:
            _malformed("%s: sig is not hex" % where)
        if not sig_bytes:
            _malformed("%s: sig is empty" % where)
        parsed_sigs.append((entry.get("keyid"), sig_bytes))
    digest = env["signing_input_digest"]
    if not isinstance(digest, str) or len(digest) != 64 or \
            any(c not in "0123456789abcdef" for c in digest):
        _malformed("signing_input_digest is not a lowercase sha256 hex")
    pae_bytes = pae(got_type, payload)
    if hashlib.sha256(pae_bytes).hexdigest() != digest:
        _malformed("signing_input_digest does not bind the envelope's "
                   "payloadType/payload (envelope fields disagree with "
                   "the bytes the signature must cover)")
    for keyid, sig_bytes in parsed_sigs:
        try:
            ok = verify(pae_bytes, sig_bytes)
        except Exception as exc:
            raise EnvelopeError(
                "dsse-signature-invalid: verifier callback failed: %s"
                % (exc,), code="dsse-signature-invalid")
        if not ok:
            raise EnvelopeError(
                "dsse-signature-invalid: signature does not verify over "
                "the PAE bytes (keyid=%r)" % (keyid,),
                code="dsse-signature-invalid")
    return {
        "ok": True,
        "payload": payload,
        "payload_type": got_type,
        "key_id": parsed_sigs[0][0],
    }


__all__ = __all__ + [
    "check_payload_type_namespace",
    "pae_decode",
    "envelope",
    "verify_envelope",
    "register_envelope_domain",
    "envelope_domain_of",
]
