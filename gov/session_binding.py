"""Session-bound presentation of signed artifacts (stdlib-only).

Design input (ADAPT, pattern-only -- no Oak/CoCo code vendored):
Project Oak's session layer (transcript-hash binding, ``SignatureBinder``
with INFO-string domain separation, verifier-provider indirection) and
Confidential Containers' EHD pattern (``EHD = H(nonce || tee_pubkey)``,
pure hashlib). Both sources are Apache-2.0; the shapes are re-derived
here in Sasanam conventions.

What this module does
---------------------
A *session-bound presentation* wraps an already-signed artifact (a
corroboration receipt, a decision packet, an evidence certificate) **by
digest** and binds that artifact to a live session, so the presentation
cannot be replayed into a different session or repurposed across roles:

1. **Transcript-hash binding.** Both sides append the same session
   records (in order) to a :class:`Transcript`. The presentation
   signature covers ``sha256(transcript)``; a presentation verified
   against a forked transcript refuses ``sessbind-transcript-mismatch``.
2. **SignatureBinder.** The signed bytes are
   ``info || bound || additional`` where ``info`` is a per-role
   INFO string (``sasanam.receipt-present.v1``,
   ``sasanam.approval-present.v1``, ``sasanam.decision-present.v1``)
   and every field is length-prefixed. A receipt presentation presented
   to an approval verifier refuses ``sessbind-domain-mismatch`` -- and
   retargeting the ``info`` field breaks the signature, so there is no
   confused-deputy path either way.
3. **Verifier-provider indirection.** Verification resolves the signer
   key through a :class:`VerifierProvider` (cf. Oak's
   attestation-verifier indirection). An unresolvable key refuses
   ``sessbind-verifier-misconfigured`` fail-closed; the provider never
   raises through the verify path.
4. **EHD.** The token carries ``ehd = sha256(nonce || ephemeral_pubkey)``,
   binding the session to the ephemeral key. The verifier recomputes it
   against the *pinned* verifier key; a transplant refuses
   ``sessbind-ehd-mismatch``. Key-remote verifiers (Vault transit shape)
   deliberately never expose a raw key: the EHD check is then skipped
   **with attribution** in the verdict's ``checked`` trail, never
   silently.
5. **Short-lived tokens.** ``issued_at``/``expires_at`` are enforced
   against an explicit ``now`` parameter (epoch seconds). There is no
   ambient clock anywhere in this module.

Layering
--------
A presentation wraps an artifact **by digest**; it never re-signs the
artifact's semantics. The correct order is: verify the artifact through
its own seam first (e.g. ``gov.corroboration_receipt``'s
chain-then-binding split: ``verify_envelope`` then
``verify_statement_binding``), then ``present()`` the artifact digest,
then ``verify_presentation()``. A presentation says "this artifact was
shown in this session by this key" -- nothing about whether the
artifact itself is true. It composes with the evidence-cert ceremony
spec (``~/workspace/teams/wave268-spec-evcert/SPEC.md``): a
session-bound presentation can carry an evcert-bound artifact digest
without touching certificate semantics.

Bright line
-----------
Software binds *participation*, never trust. This module proves that a
key holder showed an artifact inside a session with a given transcript;
it does not prove hardware attestation, device identity, or that the
transcript reflects reality. Unilateral freshness is theater: expiry
is only as trustworthy as the verifier's clock, and the transcript is
only as honest as the party that appended to it. Every verdict carries
these limits in ``out_of_scope``.
"""

import base64
import binascii
import hashlib
import hmac
import json
from abc import ABC, abstractmethod

# ---------------------------------------------------------------------------
# Machine-coded refusals (also registered in gov/decision_codes.py)
# ---------------------------------------------------------------------------

CODES = (
    "sessbind-ok",
    "sessbind-transcript-mismatch",
    "sessbind-domain-mismatch",
    "sessbind-token-expired",
    "sessbind-verifier-misconfigured",
    "sessbind-malformed",
    "sessbind-signature-invalid",
    "sessbind-ehd-mismatch",
)

INFO_RECEIPT_PRESENT = "sasanam.receipt-present.v1"
INFO_APPROVAL_PRESENT = "sasanam.approval-present.v1"
INFO_DECISION_PRESENT = "sasanam.decision-present.v1"
ALLOWED_INFOS = frozenset((INFO_RECEIPT_PRESENT, INFO_APPROVAL_PRESENT,
                           INFO_DECISION_PRESENT))

FORMAT = "sasanam.session-presentation/v1"

_OUT_OF_SCOPE = (
    "software binding proves key possession and session participation, "
    "not hardware attestation or device identity",
    "transcript integrity depends on both parties appending the same "
    "records in the same order; a lying appender is not detected",
    "unilateral freshness is theater: expiry is only as trustworthy as "
    "the verifier's clock",
    "the presentation attests showing, not truth: verify the artifact "
    "through its own seam first",
)


class SessionBindingError(Exception):
    """Machine-coded refusal. ``code`` is one of :data:`CODES`."""

    def __init__(self, code, detail=""):
        if code not in CODES:
            code = "sessbind-malformed"
        super(SessionBindingError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _hex(b):
    return binascii.hexlify(bytes(b)).decode("ascii")


def _unhex(s, what):
    try:
        return binascii.unhexlify(s.encode("ascii"))
    except (binascii.Error, AttributeError, UnicodeEncodeError):
        raise SessionBindingError(
            "sessbind-malformed", "%s is not valid hex" % (what,))


def _check_sha256_hex(value, what):
    if not isinstance(value, str) or len(value) != 64:
        raise SessionBindingError(
            "sessbind-malformed", "%s must be 64-char hex" % (what,))
    try:
        int(value, 16)
    except ValueError:
        raise SessionBindingError(
            "sessbind-malformed", "%s is not hex" % (what,))
    return value


def _check_now(now):
    """Explicit epoch-seconds clock. There is no ambient time anywhere
    in this module: callers pin ``now`` (tests pin it; deployments pass
    their clock)."""
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise SessionBindingError(
            "sessbind-malformed",
            "now must be epoch seconds (int or float), never ambient")
    return float(now)


# ---------------------------------------------------------------------------
# EHD + SignatureBinder primitives
# ---------------------------------------------------------------------------

def ehd(nonce, party_pubkey):
    """``H(nonce || party_pubkey)`` as hex (CoCo EHD pattern, hashlib)."""
    if not isinstance(nonce, (bytes, bytearray)) or not nonce:
        raise SessionBindingError(
            "sessbind-malformed", "nonce must be non-empty bytes")
    if not isinstance(party_pubkey, (bytes, bytearray)) or \
            len(party_pubkey) != 32:
        raise SessionBindingError(
            "sessbind-malformed", "party_pubkey must be 32 bytes")
    return hashlib.sha256(bytes(nonce) + bytes(party_pubkey)).hexdigest()


def bind_body(info, bound_data, additional_data):
    """SignatureBinder: ``info || len(bound) || bound || len(additional) ||
    additional``. ``info`` is the per-role INFO string; length prefixes
    remove framing ambiguity."""
    if not isinstance(info, str) or info not in ALLOWED_INFOS:
        raise SessionBindingError(
            "sessbind-domain-mismatch",
            "info %r is not a known presentation domain" % (info,))
    for name, data in (("bound_data", bound_data),
                       ("additional_data", additional_data)):
        if not isinstance(data, (bytes, bytearray)):
            raise SessionBindingError(
                "sessbind-malformed", "%s must be bytes" % (name,))
    parts = [info.encode("utf-8"), b"\x00"]
    for data in (bytes(bound_data), bytes(additional_data)):
        parts.append(len(data).to_bytes(8, "big"))
        parts.append(data)
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Transcript
# ---------------------------------------------------------------------------

class Transcript(object):
    """Ordered session transcript. ``digest()`` is sha256 over
    length-prefixed ``(role, payload)`` records; order matters."""

    def __init__(self):
        self._records = []

    def append(self, role, payload):
        if not isinstance(role, str) or not role:
            raise SessionBindingError(
                "sessbind-malformed", "record role must be a non-empty str")
        if not isinstance(payload, (bytes, bytearray)):
            raise SessionBindingError(
                "sessbind-malformed", "record payload must be bytes")
        self._records.append((role, bytes(payload)))

    def digest(self):
        h = hashlib.sha256()
        for role, payload in self._records:
            rb = role.encode("utf-8")
            h.update(len(rb).to_bytes(8, "big"))
            h.update(rb)
            h.update(len(payload).to_bytes(8, "big"))
            h.update(payload)
        return h.hexdigest()

    def records(self):
        return list(self._records)


# ---------------------------------------------------------------------------
# Verifier-provider indirection
# ---------------------------------------------------------------------------

class VerifierProvider(ABC):
    """Resolves a signer key_id to a ``gov.signing.Verifier``. Returning
    ``None`` means "unknown key" and fails closed at verify time."""

    @abstractmethod
    def verifier_for(self, key_id):
        """A verifier for ``key_id``, or ``None``."""


class StaticVerifierProvider(VerifierProvider):
    """In-process provider from an explicit ``{key_id: verifier}`` map."""

    def __init__(self, mapping):
        if not isinstance(mapping, dict):
            raise SessionBindingError(
                "sessbind-malformed",
                "provider mapping must be a dict")
        self._mapping = dict(mapping)

    def verifier_for(self, key_id):
        return self._mapping.get(key_id)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session(object):
    """One side of a bound session. ``signer`` produces presentations;
    ``verifier_provider`` resolves signer keys for verification. The
    ``ephemeral_pubkey`` is the 32-byte key the session is bound to via
    EHD (normally ``signer.public_key``)."""

    def __init__(self, session_id, signer, ephemeral_pubkey,
                 verifier_provider):
        if not isinstance(session_id, str) or not session_id:
            raise SessionBindingError(
                "sessbind-malformed",
                "session_id must be a non-empty str")
        if not callable(getattr(signer, "sign", None)):
            raise SessionBindingError(
                "sessbind-malformed",
                "signer must expose sign()")
        if not isinstance(getattr(signer, "key_id", None), str):
            raise SessionBindingError(
                "sessbind-malformed",
                "signer must expose a str key_id")
        if not isinstance(ephemeral_pubkey, (bytes, bytearray)) or \
                len(ephemeral_pubkey) != 32:
            raise SessionBindingError(
                "sessbind-malformed",
                "ephemeral_pubkey must be 32 bytes")
        if not isinstance(verifier_provider, VerifierProvider):
            raise SessionBindingError(
                "sessbind-malformed",
                "verifier_provider must be a VerifierProvider")
        self.session_id = session_id
        self._signer = signer
        self._ephemeral_pubkey = bytes(ephemeral_pubkey)
        self._provider = verifier_provider
        self._transcript = Transcript()

    def append_record(self, role, payload):
        """Append a ``(role, payload)`` record to the session transcript."""
        self._transcript.append(role, payload)

    def transcript_digest(self):
        """Hex sha256 of the session transcript so far."""
        return self._transcript.digest()

    # -- presentation (producer side; raises on bad input) --

    def present(self, artifact_digest, now, ttl_s, nonce,
                info=INFO_RECEIPT_PRESENT):
        """Mint a session-bound presentation wrapping ``artifact_digest``.

        ``now`` is epoch seconds (explicit; never ambient), ``ttl_s`` the
        token lifetime, ``nonce`` caller-supplied session bytes, ``info``
        the presentation domain. The artifact is wrapped by digest only:
        this signature covers the *showing*, never the artifact's own
        semantics.
        """
        _check_sha256_hex(artifact_digest, "artifact_digest")
        now = _check_now(now)
        if not isinstance(ttl_s, (int, float)) or \
                isinstance(ttl_s, bool) or ttl_s <= 0:
            raise SessionBindingError(
                "sessbind-malformed", "ttl_s must be a positive number")
        if not isinstance(nonce, (bytes, bytearray)) or not nonce:
            raise SessionBindingError(
                "sessbind-malformed", "nonce must be non-empty bytes")
        if info not in ALLOWED_INFOS:
            raise SessionBindingError(
                "sessbind-domain-mismatch",
                "info %r is not a known presentation domain" % (info,))
        nonce_hex = _hex(nonce)
        token = {
            "format": FORMAT,
            "session_id": self.session_id,
            "nonce": nonce_hex,
            "ehd": ehd(bytes(nonce), self._ephemeral_pubkey),
            "transcript_digest": self._transcript.digest(),
            "artifact_digest": artifact_digest,
            "info": info,
            "issued_at": now,
            "expires_at": now + float(ttl_s),
            "signer_key_id": self._signer.key_id,
        }
        body = _canonical(token)
        bound = (bytes.fromhex(token["transcript_digest"])
                 + bytes.fromhex(token["artifact_digest"]))
        sig = self._signer.sign(bind_body(info, bound, body))
        token["signature"] = _hex(sig)
        return token

    # -- verification (never raises; returns a coded verdict) --

    def verify_presentation(self, presentation, artifact_digest, now,
                            info=INFO_RECEIPT_PRESENT):
        """Verify a presentation against this session. Returns a verdict
        dict ``{"ok", "code", "session_id", "transcript_digest",
        "artifact_digest", "info", "checked", "out_of_scope",
        "evidence_digest"}``. Every failure is a coded fail-closed
        verdict; this method never raises."""
        try:
            return self._verify(presentation, artifact_digest, now, info)
        except SessionBindingError as exc:
            return self._verdict(False, exc.code, exc.detail, None, info)
        except Exception:  # fail closed, never leak internals
            return self._verdict(False, "sessbind-malformed",
                                 "internal verification failure", None,
                                 info)

    def _verify(self, presentation, artifact_digest, now, info):
        if not isinstance(presentation, dict):
            raise SessionBindingError(
                "sessbind-malformed", "presentation must be a dict")
        if presentation.get("format") != FORMAT:
            raise SessionBindingError(
                "sessbind-malformed", "presentation format mismatch")
        if presentation.get("session_id") != self.session_id:
            raise SessionBindingError(
                "sessbind-malformed", "presentation is for a different "
                "session")
        token_info = presentation.get("info")
        if token_info != info or info not in ALLOWED_INFOS:
            raise SessionBindingError(
                "sessbind-domain-mismatch",
                "token domain %r != verifier role %r"
                % (token_info, info))
        now = _check_now(now)
        try:
            issued_at = float(presentation["issued_at"])
            expires_at = float(presentation["expires_at"])
        except (KeyError, TypeError, ValueError):
            raise SessionBindingError(
                "sessbind-malformed", "token has no usable validity window")
        if not (issued_at <= now <= expires_at):
            raise SessionBindingError(
                "sessbind-token-expired",
                "now=%r outside [%r, %r]" % (now, issued_at, expires_at))
        token_td = presentation.get("transcript_digest")
        _check_sha256_hex(token_td, "transcript_digest")
        local_td = self._transcript.digest()
        if not hmac.compare_digest(token_td, local_td):
            raise SessionBindingError(
                "sessbind-transcript-mismatch",
                "token transcript does not match this session's transcript")
        _check_sha256_hex(artifact_digest, "artifact_digest")
        token_ad = presentation.get("artifact_digest")
        _check_sha256_hex(token_ad, "token artifact_digest")
        if not hmac.compare_digest(token_ad, artifact_digest):
            raise SessionBindingError(
                "sessbind-malformed",
                "presentation wraps a different artifact")
        nonce_hex = presentation.get("nonce")
        if not isinstance(nonce_hex, str) or not nonce_hex:
            raise SessionBindingError(
                "sessbind-malformed", "token has no nonce")
        nonce = _unhex(nonce_hex, "nonce")
        token_ehd = presentation.get("ehd")
        _check_sha256_hex(token_ehd, "ehd")
        key_id = presentation.get("signer_key_id")
        if not isinstance(key_id, str) or not key_id:
            raise SessionBindingError(
                "sessbind-malformed", "token has no signer_key_id")
        try:
            verifier = self._provider.verifier_for(key_id)
        except Exception:
            verifier = None
        if verifier is None:
            raise SessionBindingError(
                "sessbind-verifier-misconfigured",
                "no verifier configured for signer key %r" % (key_id,))
        checked = ["session-id-bound", "domain-checked:%s" % info,
                   "validity-window-checked", "transcript-bound",
                   "artifact-bound"]
        pub = getattr(verifier, "public_key", None)
        if isinstance(pub, (bytes, bytearray)) and len(pub) == 32:
            expect_ehd = hashlib.sha256(
                bytes(nonce) + bytes(pub)).hexdigest()
            if not hmac.compare_digest(expect_ehd, token_ehd):
                raise SessionBindingError(
                    "sessbind-ehd-mismatch",
                    "EHD does not match H(nonce || pinned verifier key)")
            checked.append("ehd-bound")
        else:
            # Key-remote verifiers (Vault transit shape) deliberately
            # never expose the raw key: skip WITH attribution, never
            # silently.
            checked.append("ehd-check-skipped: verifier is key-remote "
                           "(no public_key)")
        sig_hex = presentation.get("signature")
        if not isinstance(sig_hex, str) or not sig_hex:
            raise SessionBindingError(
                "sessbind-malformed", "token has no signature")
        sig = _unhex(sig_hex, "signature")
        token = dict(presentation)
        del token["signature"]
        bound = bytes.fromhex(token_td) + bytes.fromhex(token_ad)
        signed = bind_body(info, bound, _canonical(token))
        try:
            valid = verifier.verify(signed, sig)
        except Exception:
            valid = False
        if valid is not True:
            raise SessionBindingError(
                "sessbind-signature-invalid",
                "presentation signature does not verify")
        checked.append("signature-verified")
        return self._verdict(True, "sessbind-ok",
                             "presentation verified for this session",
                             checked, info)

    def _verdict(self, ok, code, detail, checked, info=None):
        verdict = {
            "ok": ok,
            "code": code,
            "detail": detail,
            "session_id": self.session_id,
            "transcript_digest": self._transcript.digest(),
            "info": info,
            "checked": list(checked or []),
            "out_of_scope": list(_OUT_OF_SCOPE),
        }
        verdict["evidence_digest"] = hashlib.sha256(
            _canonical({k: v for k, v in verdict.items()
                        if k != "evidence_digest"})).hexdigest()
        return verdict
