"""Independent no-issuer-code recompute checker for decision<->execution pairs.

Wave-241 lane B. Stdlib only (hashlib, json-free hand-rolled canonicalizer).

ADAPT, patterns only, prose re-derived from
``draft-sirkkavaara-vaara-receipt-12`` (28 Sept 2026). The upstream
reference implementation is AGPL-3.0-or-later: no upstream code was read,
imported, vendored, or copied here. Only the *patterns* are adapted:
JCS-canonical digests, a decision+execution receipt pair joined by a
required ``backLink`` (digest+nonce of the predecessor), conformance as
signature-verifies + digests-recompute + backLink-matches, and the
section-10 honest limits.

"Independence" means: this checker never imports any receipt-*issuing*
code. Receipts arrive as plain dicts over the wire format defined below.
The only in-repo import is ``gov.ed25519`` as the checker's *own*
verification primitive (a generic signature algorithm, not an issuer).
The ``issue_*`` helpers below are test-harness conveniences so batteries
can mint fixtures; the verification path (``verify_receipt``,
``check_pair``, ``check_absence``) never touches a seed or a private key.

Wire format (versioned, this module's own):

Decision receipt::

    {"v": 1, "kind": "decision-receipt",
     "decision": "allow" | "deny",
     "action": "<action id>",
     "action_digest": "<64 hex>",
     "nonce": "<hex>",
     "receipt_digest": "<64 hex>",
     "sig": {"alg": "ed25519", "key_id": "<id>",
             "signature": "<128 hex>"}}

Execution receipt::

    {"v": 1, "kind": "execution-receipt",
     "backLink": {"digest": "<64 hex>", "nonce": "<hex>"},
     "evidence_digest": "<64 hex>",
     "outcome": "ok" | "failed",
     "nonce": "<hex>",
     "receipt_digest": "<64 hex>",
     "sig": {...}}

Canonical bytes: ``canonical_json(body)`` where body is the receipt minus
``"sig"`` and minus ``"receipt_digest"``. ``receipt_digest`` is
sha256(canonical bytes), hex. The signature is Ed25519 over the same
canonical bytes. Verification order is structural -> digest -> signature
-> backLink: a receipt whose bytes were edited after digesting fails on
the digest, never on the signature.

Honest limits (draft section 10, enforced here as refusals):
- An ``allow`` decision with no linked execution receipt refuses
  ``recompute-no-execution-link``: an allow proves NOTHING about
  whether anything ran.
- A ``deny`` decision needs no execution receipt: it verifies as
  refusal evidence.
- An *absent* refusal (no receipt at all) is evidence only inside a
  declared coverage boundary. Outside it, ``check_absence`` refuses
  ``recompute-absent-refusal-no-coverage``: absence is not evidence
  where nothing promised to record.
- The checker verifies *claimed* digests recompute and signatures
  verify; it does not vouch for the truth of evidence bytes it never
  saw (``evidence_digest`` is shape-checked, not content-checked).
  Tail truncation is not detectable by contiguity alone -- a coverage
  boundary is a deployment declaration, not a proof.

Refusal codes emitted (all mapped in gov/decision_codes.py, domain
``recompute``): ``recompute-malformed``,
``recompute-digest-mismatch``, ``recompute-signature-invalid``,
``recompute-backlink-mismatch``, ``recompute-no-execution-link``,
``recompute-absent-refusal-no-coverage``.
"""

import hashlib

try:
    from .ed25519 import verify as _ed25519_verify
    from .ed25519 import sign as _ed25519_sign
    from .ed25519 import publickey as _ed25519_publickey
    from .ed25519 import generate_seed as _ed25519_generate_seed
except ImportError:  # pragma: no cover - sibling crypto primitive missing
    _ed25519_verify = None
    _ed25519_sign = None
    _ed25519_publickey = None
    _ed25519_generate_seed = None

# ---------------------------------------------------------------------------
# Refusal codes (machine vocabulary; mapped in gov/decision_codes.py)
# ---------------------------------------------------------------------------

MALFORMED = "recompute-malformed"
DIGEST_MISMATCH = "recompute-digest-mismatch"
SIGNATURE_INVALID = "recompute-signature-invalid"
BACKLINK_MISMATCH = "recompute-backlink-mismatch"
NO_EXECUTION_LINK = "recompute-no-execution-link"
ABSENT_REFUSAL_NO_COVERAGE = "recompute-absent-refusal-no-coverage"


class RecomputeRefusal(Exception):
    """Fail-closed refusal with a machine code."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise RecomputeRefusal(code, detail)


# ---------------------------------------------------------------------------
# JCS canonicalization (RFC 8785 subset)
# ---------------------------------------------------------------------------
# Supported value space: None, bool, int, str, list/tuple, dict with str
# keys. Floats are refused: this subset cannot represent them
# deterministically, and receipts never carry them. Object keys sort by
# UTF-16 code units; no whitespace; '"' and '\\' and U+0000-U+001F escape;
# everything else is raw UTF-8. Duplicate keys cannot occur in a dict.

def _escape_string(text):
    parts = []
    for ch in text:
        if ch == '"':
            parts.append('\\"')
        elif ch == "\\":
            parts.append("\\\\")
        elif ord(ch) < 0x20:
            parts.append("\\u%04x" % ord(ch))
        else:
            parts.append(ch)
    return "".join(parts)


def canonical_json(value):
    """Return JCS-canonical bytes for the supported value space.

    Refuses ``recompute-malformed`` on floats, non-str dict keys, or any
    other unsupported value: the canonical form must be total over the
    receipt schema and fail-closed outside it.
    """
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, str):
        return b'"' + _escape_string(value).encode("utf-8") + b'"'
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(canonical_json(v) for v in value) + b"]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                _refuse(MALFORMED, "object key is not a string")
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        parts = []
        for k, v in items:
            key = b'"' + _escape_string(k).encode("utf-8") + b'":'
            parts.append(key + canonical_json(v))
        return b"{" + b",".join(parts) + b"}"
    _refuse(MALFORMED,
            "value of type %s has no canonical form" % type(value).__name__)


# ---------------------------------------------------------------------------
# Receipt helpers
# ---------------------------------------------------------------------------

_HEX64 = frozenset("0123456789abcdef")


def _is_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(c in _HEX64 for c in value))


def _body_bytes(receipt):
    """Canonical bytes of a receipt minus sig/receipt_digest."""
    body = {k: v for k, v in receipt.items()
            if k not in ("sig", "receipt_digest")}
    return canonical_json(body)


def _digest_of(body_bytes):
    return hashlib.sha256(body_bytes).hexdigest()


def issue_decision_receipt(decision, action, action_digest, nonce, key_id,
                           seed):
    """Mint a decision receipt (TEST/ISSUER-SIDE helper).

    The verification path never calls this; batteries use it to build
    fixtures. ``seed`` is the issuer's Ed25519 seed (32 bytes).
    """
    if _ed25519_sign is None:
        _refuse(MALFORMED, "ed25519 primitive unavailable")
    if decision not in ("allow", "deny"):
        _refuse(MALFORMED, "decision must be allow or deny")
    if not _is_hex(action_digest, 64):
        _refuse(MALFORMED, "action_digest must be 64 lowercase hex")
    receipt = {"v": 1, "kind": "decision-receipt", "decision": decision,
               "action": action, "action_digest": action_digest,
               "nonce": nonce}
    body = _body_bytes(receipt)
    receipt["receipt_digest"] = _digest_of(body)
    receipt["sig"] = {"alg": "ed25519", "key_id": key_id,
                      "signature": _ed25519_sign(seed, body).hex()}
    return receipt


def issue_execution_receipt(backlink_digest, backlink_nonce, evidence_digest,
                            outcome, nonce, key_id, seed):
    """Mint an execution receipt (TEST/ISSUER-SIDE helper)."""
    if _ed25519_sign is None:
        _refuse(MALFORMED, "ed25519 primitive unavailable")
    if not _is_hex(backlink_digest, 64):
        _refuse(MALFORMED, "backlink digest must be 64 lowercase hex")
    if not _is_hex(evidence_digest, 64):
        _refuse(MALFORMED, "evidence_digest must be 64 lowercase hex")
    if outcome not in ("ok", "failed"):
        _refuse(MALFORMED, "outcome must be ok or failed")
    receipt = {"v": 1, "kind": "execution-receipt",
               "backLink": {"digest": backlink_digest,
                            "nonce": backlink_nonce},
               "evidence_digest": evidence_digest, "outcome": outcome,
               "nonce": nonce}
    body = _body_bytes(receipt)
    receipt["receipt_digest"] = _digest_of(body)
    receipt["sig"] = {"alg": "ed25519", "key_id": key_id,
                      "signature": _ed25519_sign(seed, body).hex()}
    return receipt


def _check_sig_shape(sig):
    if not isinstance(sig, dict):
        _refuse(MALFORMED, "sig must be a dict")
    if sig.get("alg") != "ed25519":
        _refuse(MALFORMED, "sig.alg must be ed25519")
    if not isinstance(sig.get("key_id"), str) or not sig["key_id"]:
        _refuse(MALFORMED, "sig.key_id must be a non-empty string")
    if not _is_hex(sig.get("signature"), 128):
        _refuse(MALFORMED, "sig.signature must be 128 lowercase hex")


def verify_receipt(receipt, pubkey):
    """Verify one receipt structurally, by digest, and by signature.

    ``pubkey`` is the *checker's own* trust input (32-byte Ed25519
    public key), never taken from the receipt. Returns the canonical
    body bytes on success. Order: structure -> digest -> signature.
    """
    if not isinstance(receipt, dict):
        _refuse(MALFORMED, "receipt must be a dict")
    kind = receipt.get("kind")
    if kind not in ("decision-receipt", "execution-receipt"):
        _refuse(MALFORMED, "unknown receipt kind")
    if receipt.get("v") != 1:
        _refuse(MALFORMED, "unsupported receipt version")
    if not _is_hex(receipt.get("receipt_digest"), 64):
        _refuse(MALFORMED, "receipt_digest must be 64 lowercase hex")
    if not isinstance(receipt.get("nonce"), str) or not receipt["nonce"]:
        _refuse(MALFORMED, "nonce must be a non-empty string")
    _check_sig_shape(receipt.get("sig"))
    if kind == "decision-receipt":
        if receipt.get("decision") not in ("allow", "deny"):
            _refuse(MALFORMED, "decision must be allow or deny")
        if not isinstance(receipt.get("action"), str) or not receipt["action"]:
            _refuse(MALFORMED, "action must be a non-empty string")
        if not _is_hex(receipt.get("action_digest"), 64):
            _refuse(MALFORMED, "action_digest must be 64 lowercase hex")
    else:
        backlink = receipt.get("backLink")
        if not isinstance(backlink, dict):
            _refuse(MALFORMED, "backLink must be a dict")
        if not _is_hex(backlink.get("digest"), 64):
            _refuse(MALFORMED, "backLink.digest must be 64 lowercase hex")
        if (not isinstance(backlink.get("nonce"), str)
                or not backlink["nonce"]):
            _refuse(MALFORMED, "backLink.nonce must be a non-empty string")
        if not _is_hex(receipt.get("evidence_digest"), 64):
            _refuse(MALFORMED, "evidence_digest must be 64 lowercase hex")
        if receipt.get("outcome") not in ("ok", "failed"):
            _refuse(MALFORMED, "outcome must be ok or failed")

    body = _body_bytes(receipt)
    if _digest_of(body) != receipt["receipt_digest"]:
        _refuse(DIGEST_MISMATCH,
                "recomputed digest does not match receipt_digest")
    if _ed25519_verify is None:
        _refuse(MALFORMED, "ed25519 primitive unavailable")
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        _refuse(MALFORMED, "pubkey must be a 32-byte Ed25519 public key")
    sig_bytes = bytes.fromhex(receipt["sig"]["signature"])
    if not _ed25519_verify(bytes(pubkey), body, sig_bytes):
        _refuse(SIGNATURE_INVALID,
                "Ed25519 signature does not verify over canonical bytes")
    return body


def check_pair(decision, execution, decision_pubkey, execution_pubkey):
    """Acceptance check for one decision<->execution pair.

    Verifies the decision receipt, then (unless the decision is a deny
    with no execution receipt -- refusals need no execution) requires a
    linked execution receipt whose backLink names the decision's
    digest+nonce. Returns a verdict dict on success.

    Honest limit: an ``allow`` with ``execution=None`` refuses
    ``recompute-no-execution-link`` -- an allow proves nothing about
    whether anything ran.
    """
    if not isinstance(decision, dict):
        _refuse(MALFORMED, "decision receipt must be a dict")
    verify_receipt(decision, decision_pubkey)
    if decision.get("kind") != "decision-receipt":
        _refuse(MALFORMED, "first receipt of a pair must be a decision")
    decision_digest = decision["receipt_digest"]

    if execution is None:
        if decision.get("decision") == "allow":
            _refuse(NO_EXECUTION_LINK,
                    "allow decision without a linked execution receipt "
                    "proves nothing about execution")
        return {"verdict": "accept", "decision_digest": decision_digest,
                "refusal_evidence": True,
                "note": "deny verified as refusal evidence; "
                        "no execution receipt required"}

    if not isinstance(execution, dict):
        _refuse(MALFORMED, "execution receipt must be a dict")
    if execution.get("kind") != "execution-receipt":
        _refuse(MALFORMED, "second receipt of a pair must be an execution")
    verify_receipt(execution, execution_pubkey)
    backlink = execution["backLink"]
    if (backlink["digest"] != decision_digest
            or backlink["nonce"] != decision["nonce"]):
        _refuse(BACKLINK_MISMATCH,
                "execution backLink does not name the decision's "
                "digest+nonce")
    return {"verdict": "accept", "decision_digest": decision_digest,
            "execution_digest": execution["receipt_digest"],
            "refusal_evidence": False}


def check_absence(action, coverage):
    """Evaluate an *absent* refusal against a declared coverage boundary.

    ``coverage`` is the deployment's declared set of action ids that
    promise to record a decision receipt for every evaluation. An
    action inside the boundary with no receipt is accepted as
    evidence-of-absence. An action outside the boundary refuses
    ``recompute-absent-refusal-no-coverage``: absence is not evidence
    where nothing promised to record.
    """
    if not isinstance(action, str) or not action:
        _refuse(MALFORMED, "action must be a non-empty string")
    covered = set(coverage) if coverage else set()
    if action in covered:
        return {"verdict": "accept", "action": action,
                "absence_is_evidence": True,
                "note": "action inside declared coverage boundary; "
                        "no receipt recorded"}
    _refuse(ABSENT_REFUSAL_NO_COVERAGE,
            "action is outside the declared coverage boundary; an "
            "absent refusal is not evidence there")
