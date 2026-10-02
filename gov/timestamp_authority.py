"""Timestamp authority: countersigned, auditor-held TSA tokens.

Pattern lineage: this module implements the sigstore/timestamp-authority
pattern (Apache-2.0, https://github.com/sigstore/timestamp-authority),
written clean-room for Sasanam -- no vendored code, no sigstore library
imports, no wire formats copied. The ideas reused are the pattern's
public shape: a trusted third party countersigns over an EXISTING
signature (proof of existence at time T), binds the request with a nonce,
and publishes the token under its own pinned key.

What this is NOT: a network service. This is a local auditor-held TSA:
the TSA signing key (``tsa_seed``) is held by the auditor exactly like
the operator key set (distribution out-of-band), and tokens are issued
in-process against operator signatures the auditor already holds.

Honest threat model:

* The TSA key is the trust anchor. If the TSA signing key is
  compromised, time forgery is total: an attacker can backdate or
  future-date arbitrary tokens. Protect it like the operator key set;
  compromise of the operator key does NOT let the attacker forge time,
  only sign content.
* Inclusion != tree honesty. A token proves "the operator signature
  existed at genTime" -- it says nothing about whether the checkpoint
  root is a real, append-only tree head. Chain validation at the
  claimed time (replay the log from its genesis under the pinned
  operator key) is how the timestamp is *used* honestly.
* Backdate detection requires the auditor's first-observed ledger.
  Without a ``FirstObservedLedger`` the TSA cannot distinguish a
  legitimately late submission from a backdated forgery; the ledger is
  the auditor's memory of when tree heads were first seen.
* The nonce binds the token to the request (no replay of an old token
  as an answer to a new request). It does not add freshness -- the
  freshness claim is the TSA's own genTime under its signature.
* ``verify_timestamped_checkpoint`` does NOT verify the operator's own
  checkpoint signature. The token proves the operator signature
  *existed* at genTime; whether that signature *verifies* belongs to
  ``gov.evidence_anchor``'s verify paths. Callers must verify the
  operator signature separately, and the returned token payload's
  genTime is the reference time downstream time-dependent checks must
  use: chain validation runs at the CLAIMED time, not wall-clock now.
"""

import hashlib
import hmac
import json
import secrets
import time

from gov import ed25519 as _ed25519

TOKEN_FORMAT = "gov/tsa-timestamped-checkpoint/1"
MAX_FUTURE_SKEW_SECONDS = 300
MIN_NONCE_BYTES = 16

_SIG_CONTEXT = "gov/tsa-timestamp/1"
_TOKEN_VERSION = 1

MALFORMED = "tsa-token-malformed"
SIG_INVALID = "tsa-signature-invalid"
GENTIME_INVALID = "tsa-gentime-invalid"
GENTIME_FUTURE = "tsa-gentime-in-future"
GENTIME_BACKDATED = "tsa-gentime-backdated"
NONCE_MISMATCH = "tsa-nonce-mismatch"
IMPRINT_MISMATCH = "tsa-imprint-mismatch"


class TsaError(Exception):
    """Timestamp-authority error with a machine-readable decision code."""

    code = "tsa-token-malformed"

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise TsaError(detail, code)


# ---------------------------------------------------------------------------
# Audit sink: digests and ids only, never key material.
# ---------------------------------------------------------------------------

_EMIT = None


def set_emit(emit):
    """Install the audit sink. ``emit`` takes a dict of digests/ids."""
    global _EMIT
    _EMIT = emit


def _emit(event):
    if _EMIT is None:
        return
    try:
        _EMIT(dict(event))
    except Exception:
        # A broken audit sink must never break timestamp issuance or
        # verification: record the failure mode, not the event. (Same
        # trade-off as gov/governed_exceptions.py, documented there.)
        pass


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


_HEX = frozenset("0123456789abcdefABCDEF")


def _is_hex(s, length):
    return (isinstance(s, str) and len(s) == length
            and all(ch in _HEX for ch in s))


def _check_origin(origin):
    if not isinstance(origin, str) or not origin or len(origin) > 128:
        _fail(MALFORMED, "origin must be a non-empty string of at most "
              "128 characters")
    try:
        origin.encode("utf-8")
    except UnicodeEncodeError:
        _fail(MALFORMED, "origin must be UTF-8 encodable")


def _check_size(size):
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        _fail(MALFORMED, "size must be an int >= 0")
    if size >= 2 ** 64:
        _fail(MALFORMED, "size must fit in 64 bits")


def _check_root_hex(root_hex):
    if not _is_hex(root_hex, 64):
        _fail(MALFORMED, "root_hex must be 64 hex characters")


def _check_operator_sig_hex(operator_sig_hex):
    if not _is_hex(operator_sig_hex, 128):
        _fail(MALFORMED, "operator_sig_hex must be 128 hex characters")


def _check_tsa_seed(tsa_seed):
    if not isinstance(tsa_seed, (bytes, bytearray)) or len(tsa_seed) != 32:
        _fail(MALFORMED, "tsa_seed must be 32 bytes")


def _check_tsa_keyid(tsa_keyid):
    if (not isinstance(tsa_keyid, str) or not tsa_keyid
            or len(tsa_keyid) > 128):
        _fail(MALFORMED, "tsa_keyid must be a non-empty string of at "
              "most 128 characters")


def _check_nonce(nonce):
    """Return the canonical nonce hex. Generates when nonce is None."""
    if nonce is None:
        return secrets.token_bytes(MIN_NONCE_BYTES).hex()
    if not isinstance(nonce, str):
        _fail(MALFORMED, "nonce must be a hex string or None")
    try:
        raw = bytes.fromhex(nonce)
    except ValueError:
        _fail(MALFORMED, "nonce is not valid hex")
    if len(raw) < MIN_NONCE_BYTES:
        _fail(MALFORMED, "nonce must decode to at least %d bytes"
              % MIN_NONCE_BYTES)
    return nonce


def _check_gen_time(gen_time):
    if gen_time is None:
        return int(time.time())
    if isinstance(gen_time, bool) or not isinstance(gen_time, int):
        _fail(MALFORMED, "gen_time must be an int")
    if gen_time <= 0:
        _fail(MALFORMED, "gen_time must be > 0")
    return gen_time


def _compute_imprint(origin, size, root_hex, operator_sig_hex):
    """Bind the TSA token to the OPERATOR'S SIGNATURE.

    imprint = sha256( root_bytes || size.to_bytes(8,"big") ||
                      sha256(origin).digest() || sha256(op_sig).digest() )

    The TSA countersigns OVER the operator's signature, so a valid token
    proves the operator signature existed at genTime -- the operator
    cannot later claim a different signature, and the TSA cannot mint a
    token that was not bound to a specific operator signature.
    """
    root = bytes.fromhex(root_hex)
    size_b = size.to_bytes(8, "big")
    origin_d = hashlib.sha256(origin.encode("utf-8")).digest()
    op_sig = bytes.fromhex(operator_sig_hex)
    op_sig_d = hashlib.sha256(op_sig).digest()
    return hashlib.sha256(root + size_b + origin_d + op_sig_d).hexdigest()


def _sig_structure(protected, payload):
    return _canonical({
        "context": _SIG_CONTEXT,
        "protected": protected,
        "payload": payload,
    })


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------

def issue_token(*, operator_sig_hex, origin, size, root_hex, nonce=None,
                tsa_seed, tsa_keyid, gen_time=None):
    """Issue a TSA timestamp token over an existing operator signature.

    All argument violations fail closed with ``tsa-token-malformed``.
    Returns the token dict (JSON-serializable). Emits
    ``tsa-token-issued`` (digests/ids only).
    """
    _check_operator_sig_hex(operator_sig_hex)
    _check_origin(origin)
    _check_size(size)
    _check_root_hex(root_hex)
    _check_tsa_seed(tsa_seed)
    _check_tsa_keyid(tsa_keyid)
    nonce_hex = _check_nonce(nonce)
    gen_time = _check_gen_time(gen_time)

    imprint = _compute_imprint(origin, size, root_hex, operator_sig_hex)

    protected = {
        "alg": "EdDSA",
        "kid": tsa_keyid,
        "token_format": TOKEN_FORMAT,
    }
    payload = {
        "v": _TOKEN_VERSION,
        "messageImprint": imprint,
        "genTime": gen_time,
        "nonce": nonce_hex,
        "origin": origin,
        "size": size,
        "root": root_hex,
    }
    sig_structure = _sig_structure(protected, payload)
    signature = _ed25519.sign(bytes(tsa_seed), sig_structure).hex()

    token = {
        "token_format": TOKEN_FORMAT,
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }
    _emit({"event": "tsa-token-issued", "origin": origin, "size": size,
           "genTime": gen_time, "kid": tsa_keyid,
           "imprint": imprint})
    return token


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _require_token_shape(token):
    if not isinstance(token, dict):
        _fail(MALFORMED, "token must be a dict")
    if token.get("token_format") != TOKEN_FORMAT:
        _fail(MALFORMED, "token_format must be %r" % TOKEN_FORMAT)
    protected = token.get("protected")
    payload = token.get("payload")
    signature = token.get("signature")
    if not isinstance(protected, dict) or not isinstance(payload, dict):
        _fail(MALFORMED, "protected and payload must be dicts")
    if not _is_hex(signature, 128):
        _fail(MALFORMED, "signature must be 128 hex characters")
    if protected.get("token_format") != TOKEN_FORMAT:
        _fail(MALFORMED, "protected token_format mismatch")
    return protected, payload, signature


def _require_payload_shape(payload):
    if payload.get("v") != _TOKEN_VERSION:
        _fail(MALFORMED, "payload v must be %d" % _TOKEN_VERSION)
    if not _is_hex(payload.get("messageImprint"), 64):
        _fail(MALFORMED, "messageImprint must be 64 hex characters")
    gen_time = payload.get("genTime")
    if isinstance(gen_time, bool) or not isinstance(gen_time, int):
        _fail(MALFORMED, "genTime must be an int")
    nonce = payload.get("nonce")
    if (not isinstance(nonce, str) or not nonce
            or any(ch not in _HEX for ch in nonce) or len(nonce) % 2):
        _fail(MALFORMED, "nonce must be a non-empty even-length hex "
              "string")
    if not isinstance(payload.get("origin"), str):
        _fail(MALFORMED, "origin must be a string")
    size = payload.get("size")
    if isinstance(size, bool) or not isinstance(size, int):
        _fail(MALFORMED, "size must be an int")
    if not _is_hex(payload.get("root"), 64):
        _fail(MALFORMED, "root must be 64 hex characters")
    return gen_time


def verify_token(token, tsa_pubkey_hex, *, expected_nonce=None, now=None,
                 ledger=None):
    """Verify a TSA token under the auditor-pinned TSA public key.

    Checks, in order: shape -> TSA signature over the Sig_structure ->
    genTime sane and not from the future -> nonce binding -> ledger
    backdate check. Returns the token's payload dict on success. Any
    failure raises TsaError with its machine code.
    """
    protected, payload, signature = _require_token_shape(token)
    if not _is_hex(tsa_pubkey_hex, 64):
        _fail(MALFORMED, "tsa_pubkey_hex must be 64 hex characters")
    gen_time = _require_payload_shape(payload)

    sig_structure = _sig_structure(protected, payload)
    ok = _ed25519.verify(bytes.fromhex(tsa_pubkey_hex), sig_structure,
                         bytes.fromhex(signature))
    if ok is not True:
        _fail(SIG_INVALID, "TSA signature does not verify under the "
              "pinned TSA public key")

    if gen_time <= 0:
        _fail(GENTIME_INVALID, "genTime must be > 0")
    if now is None:
        now = int(time.time())
    elif isinstance(now, bool) or not isinstance(now, int) or now <= 0:
        _fail(GENTIME_INVALID, "now must be an int > 0")
    if gen_time > now + MAX_FUTURE_SKEW_SECONDS:
        _fail(GENTIME_FUTURE, "genTime %d is more than %d seconds ahead "
              "of now %d" % (gen_time, MAX_FUTURE_SKEW_SECONDS, now))

    if expected_nonce is not None and payload["nonce"] != expected_nonce:
        _fail(NONCE_MISMATCH, "token nonce does not match the expected "
              "request nonce")

    if ledger is not None:
        if not hasattr(ledger, "first_seen"):
            _fail(MALFORMED, "ledger must expose "
                  "first_seen(origin, size)")
        fs = ledger.first_seen(payload["origin"], payload["size"])
        if fs is not None and gen_time < fs:
            _fail(GENTIME_BACKDATED, "genTime %d predates first observed "
                  "%d for this tree head" % (gen_time, fs))

    return dict(payload)


# ---------------------------------------------------------------------------
# First-observed ledger (the auditor's memory of tree heads)
# ---------------------------------------------------------------------------

class FirstObservedLedger:
    """The auditor's first-seen memory for backdate detection.

    ``record`` keeps the EARLIEST observed_at per (origin, size): a TSA
    token whose genTime predates the first observation of that tree head
    is a backdated forgery. Malformed inputs raise TsaError with
    ``tsa-token-malformed``.
    """

    def __init__(self):
        self._first = {}

    def record(self, origin, size, observed_at):
        _check_origin(origin)
        _check_size(size)
        if (isinstance(observed_at, bool)
                or not isinstance(observed_at, int) or observed_at <= 0):
            _fail(MALFORMED, "observed_at must be an int > 0")
        key = (origin, size)
        prev = self._first.get(key)
        if prev is None or observed_at < prev:
            self._first[key] = observed_at

    def first_seen(self, origin, size):
        _check_origin(origin)
        _check_size(size)
        return self._first.get((origin, size))


# ---------------------------------------------------------------------------
# Checkpoint attach / verify
# ---------------------------------------------------------------------------

def _checkpoint_imprint_fields(checkpoint):
    if not isinstance(checkpoint, dict):
        _fail(MALFORMED, "checkpoint must be a dict")
    origin = checkpoint.get("origin")
    size = checkpoint.get("size")
    root_hex = checkpoint.get("root")
    operator_sig = checkpoint.get("operator_sig")
    _check_origin(origin)
    _check_size(size)
    _check_root_hex(root_hex)
    _check_operator_sig_hex(operator_sig)
    return origin, size, root_hex, operator_sig


def timestamp_checkpoint(checkpoint, tsa_seed, tsa_keyid, *,
                         gen_time=None, nonce=None):
    """Attach a TSA timestamp token to a checkpoint.

    ``checkpoint`` must be a dict with ``origin`` (str), ``size``
    (int), ``root`` (64 hex), ``operator_sig`` (128 hex). Returns a NEW
    dict: a shallow copy of the checkpoint plus ``tsa_token``. The
    original checkpoint is not modified.
    """
    origin, size, root_hex, operator_sig = _checkpoint_imprint_fields(
        checkpoint)
    token = issue_token(operator_sig_hex=operator_sig, origin=origin,
                        size=size, root_hex=root_hex, nonce=nonce,
                        tsa_seed=tsa_seed, tsa_keyid=tsa_keyid,
                        gen_time=gen_time)
    stamped = dict(checkpoint)
    stamped["tsa_token"] = token
    return stamped


def verify_timestamped_checkpoint(checkpoint, operator_pubkey_hex,
                                  tsa_pubkey_hex, *, expected_nonce=None,
                                  now=None, ledger=None):
    """Verify a TSA-timestamped checkpoint.

    FIRST recomputes the imprint from the checkpoint's own
    origin/size/root/operator_sig and constant-time-compares it with the
    token payload's messageImprint (``tsa-imprint-mismatch`` on a
    swapped operator signature or tree head), THEN verifies the token.

    This does NOT verify the operator's own checkpoint signature: the
    token proves the operator signature *existed* at genTime, and
    whether it *verifies* belongs to ``gov.evidence_anchor``'s verify
    paths. Callers must verify the operator signature separately, and
    the returned token payload's genTime is the reference time
    downstream time-dependent checks must use: chain validation runs
    at the CLAIMED time, not wall-clock now.
    """
    if not isinstance(checkpoint, dict):
        _fail(MALFORMED, "checkpoint must be a dict")
    if not _is_hex(operator_pubkey_hex, 64):
        _fail(MALFORMED, "operator_pubkey_hex must be 64 hex characters")
    token = checkpoint.get("tsa_token")
    if token is None:
        _fail(MALFORMED, "checkpoint has no tsa_token")

    origin, size, root_hex, operator_sig = _checkpoint_imprint_fields(
        checkpoint)
    imprint = _compute_imprint(origin, size, root_hex, operator_sig)

    _require_token_shape(token)
    _require_payload_shape(token["payload"])
    if not hmac.compare_digest(token["payload"]["messageImprint"],
                               imprint):
        _fail(IMPRINT_MISMATCH, "token is not bound to this "
              "checkpoint's operator signature")
    return verify_token(token, tsa_pubkey_hex, expected_nonce=expected_nonce,
                        now=now, ledger=ledger)


# ---------------------------------------------------------------------------
# Receipt attach / verify
# ---------------------------------------------------------------------------

def _receipt_imprint_fields(receipt):
    if not isinstance(receipt, dict):
        _fail(MALFORMED, "receipt must be a dict")
    payload = receipt.get("payload")
    signature = receipt.get("signature")
    if not isinstance(payload, dict):
        _fail(MALFORMED, "receipt payload must be a dict")
    origin = payload.get("origin")
    tree_size = payload.get("tree_size")
    root_hex = payload.get("root")
    _check_origin(origin)
    _check_size(tree_size)
    _check_root_hex(root_hex)
    _check_operator_sig_hex(signature)
    return origin, tree_size, root_hex, signature


def timestamp_receipt(receipt, tsa_seed, tsa_keyid, *,
                      gen_time=None, nonce=None):
    """Attach a TSA timestamp token to an inclusion receipt.

    ``receipt`` must be a dict with a dict ``payload`` containing
    ``origin`` (str), ``tree_size`` (int), ``root`` (64 hex), and a
    top-level ``signature`` (128 hex) -- the operator's signature the
    token countersigns. Returns a NEW receipt dict (the payload dict is
    copied too) with ``payload["tsa_token"]`` set; the input is not
    modified.
    """
    origin, tree_size, root_hex, signature = _receipt_imprint_fields(receipt)
    token = issue_token(operator_sig_hex=signature, origin=origin,
                        size=tree_size, root_hex=root_hex, nonce=nonce,
                        tsa_seed=tsa_seed, tsa_keyid=tsa_keyid,
                        gen_time=gen_time)
    stamped = dict(receipt)
    stamped_payload = dict(receipt["payload"])
    stamped_payload["tsa_token"] = token
    stamped["payload"] = stamped_payload
    return stamped


def verify_receipt_with_tsa(receipt, operator_pubkey_hex, tsa_pubkey_hex,
                            *, expected_nonce=None, now=None, ledger=None,
                            witness_policy=None):
    """Verify an inclusion receipt offline, then its TSA timestamp.

    First runs ``evidence_receipt.verify_receipt_offline`` against the
    receipt as the operator signed it -- the ``tsa_token`` is stripped
    from a COPY of the payload first, because the operator's signature
    covers the payload *without* the timestamp token (the token is a
    countersign over that operator signature, not part of it). Its
    errors propagate unchanged. Then checks the TSA token embedded in
    the receipt payload: imprint recomputation against the receipt's
    own origin/tree_size/root/operator signature
    (``tsa-imprint-mismatch``), then full token verification. Returns
    ``{"receipt": <offline result>, "tsa_payload": payload}``.
    """
    from gov import evidence_receipt as _receipts

    if not _is_hex(operator_pubkey_hex, 64):
        _fail(MALFORMED, "operator_pubkey_hex must be 64 hex characters")
    if not isinstance(receipt, dict) or not isinstance(
            receipt.get("payload"), dict):
        _fail(MALFORMED, "receipt must be a dict with a dict payload")

    token = receipt["payload"].get("tsa_token")
    if token is None:
        _fail(MALFORMED, "receipt payload has no tsa_token")

    # The operator signed the payload before the timestamp was
    # attached; verify the receipt exactly as signed.
    unsigned = dict(receipt)
    unsigned_payload = dict(receipt["payload"])
    unsigned_payload.pop("tsa_token", None)
    unsigned["payload"] = unsigned_payload
    offline = _receipts.verify_receipt_offline(
        unsigned, bytes.fromhex(operator_pubkey_hex),
        witness_policy=witness_policy)

    origin, tree_size, root_hex, signature = _receipt_imprint_fields(receipt)
    imprint = _compute_imprint(origin, tree_size, root_hex, signature)
    _require_token_shape(token)
    _require_payload_shape(token["payload"])
    if not hmac.compare_digest(token["payload"]["messageImprint"],
                               imprint):
        _fail(IMPRINT_MISMATCH, "token is not bound to this receipt's "
              "operator signature")
    tsa_payload = verify_token(token, tsa_pubkey_hex,
                               expected_nonce=expected_nonce, now=now,
                               ledger=ledger)
    return {"receipt": offline, "tsa_payload": tsa_payload}
