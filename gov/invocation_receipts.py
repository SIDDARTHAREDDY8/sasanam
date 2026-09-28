"""Countersigned invocation receipts (wave-175 lane 1).

Design input: ``archetech/sigil`` (``docs/invocation.md``, MIT verified —
LICENSE read from the repo root, "Copyright (c) 2026 Archetech"; no
vendored code, the shape is rebuilt here on this repo's existing Ed25519
seam ``gov/ed25519.py``).

Sigil's shape, adapted: an invocation is the agent's committed act; a
*completed* invocation is an attributable record
``{invocation (agent-signed), receipt (resource-server-signed)}`` that a
third party re-verifies offline (``verifyRecord``), recovering who acted
(leaf agent) and under whose authority (root controller) from signatures
alone. Replay is refused via challenge/audience binding.

Our adaptation:
* The *agent-signed act* half is the existing MAC-bound record: the
  approval packet (F34/F38 keyed digest) on the approved path, the
  write-ahead ``execution_authorized`` log entry on the direct path.
  Agents hold no asymmetric keys in this system, so that half stays HMAC.
* The *resource-signed receipt* half is NEW here: the executor — the party
  that actually executed — countersigns what it DID execute (tool, args
  digest over the sentinel-bearing form, canonical target, policy decision,
  preview digest, outcome digest) with the deployment's Ed25519
  receipt-signing key. This is the evidence-grade upgrade the prospectus
  called for: "the agent claims it did X" (self-attested HMAC) vs
  "X happened" (executor countersignature).
* The receipt rides a hash-chained ``invocation_receipt`` audit event, so
  it inherits the ledger's tamper-evidence; the offline evidence bundle
  carries it like any other entry, and ``verify_receipt`` re-verifies it
  without the repository installed (stdlib only).

Which invocations get receipts ("consequential"): every invocation that
actually executes on the approved sweep (human-authorized by
construction), plus direct-path executions of irreversible-registry tools
(``gov/precommit.is_irreversible`` — the codebase's own "consequential"
definition: destructive / external-effect). Denied or refused invocations
get no receipt: nothing happened, and the refusal is already an audited
event. Policy-allowed direct reads and non-irreversible direct writes stay
self-attested — the receipt is evidence, not a gate, and minting it for
every read would tax the hot path for no forensic gain.

Key custody: the keyprovider idiom (explicit 32-byte seed hex >
``GOV_RECEIPT_KEY`` hex > ``GOV_RECEIPT_KEY_FILE`` 0600 file hex). Nothing
configured raises :class:`NoReceiptKeyError`; the executor then logs one
loud ``invocation_receipts_disabled`` event and mints no receipts — loud,
never silently absent. There is no dev-key fallback (wave-81 precedent).

Honest residuals (documented, not claimed away):
* Receipts attest *recorded* executions only — the whole evidence story's
  bound ("integrity is not truth"; an unrecorded execution has no
  receipt and no claim is made about it).
* Key custody is claimed, not proven: a valid countersignature proves the
  signer held the seed, not that the seed lived in an HSM.
* ``issued_at`` is operator wall-clock. Replay protection comes from the
  challenge (approval_id / direct:seq), the audience (run binding), and
  the ledger chain — never from the timestamp.
* The receipt does not prevent anything: it is evidence of what happened,
  minted after execution. A signing failure is a loud
  ``invocation_receipt_failed`` event; the execution result stands (it
  cannot un-happen).
* Pure-Python Ed25519 (``gov/ed25519.py``) is not constant-time; the
  threat model matches the audit-log use (run-dir writer / network
  auditor, not a local side-channel observer).
* Direct-path receipts carry ``preview_digest: None``: the direct path
  has no human-approved preview to bind. The args digest, canonical
  target, and policy decision are still bound; the approved sweep always
  carries a preview digest.

Cost (measured 2026-09-28, synthetic harness, CPython 3.12):
* Receipt body ~900 bytes JSON (the Ed25519 signature is 86 base64url
  chars; everything else is digests, ids, and short strings).
* Minting adds ~7 ms per consequential execution (pure-Python Ed25519
  sign dominates; baseline direct delete_file ~4.5 ms). Consequential
  only — reads and non-irreversible direct tools mint nothing, so there
  is no per-read tax. No batching or async signing: 7 ms is negligible
  next to real tool latency (file, network, model calls).
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from . import ed25519 as _ed
from . import precommit as _precommit

RECEIPT_VERSION = 1
AUDIENCE = "agent-governance-executor"

# Domain separation for the Ed25519 signing input. Distinct from the
# agent-card / capability-manifest JOSE envelopes on purpose: a receipt
# signature must never verify as a card or manifest signature.
_SIGNING_DOMAIN = b"agent-governance/invocation-receipt/v1."


class NoReceiptKeyError(Exception):
    """No receipt-signing key configured (GOV_RECEIPT_KEY /
    GOV_RECEIPT_KEY_FILE). The executor mints no receipts and says so
    loudly; it never falls back to an ephemeral key."""


def _canonical(obj):
    """RFC 8785-style canonical JSON (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _b64u_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text):
    if not isinstance(text, str):
        raise ValueError("base64url must be str")
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_receipt_key(explicit=None):
    """Resolve the Ed25519 receipt-countersigning key (keyprovider idiom).

    Precedence: explicit hex seed > ``GOV_RECEIPT_KEY`` (hex) >
    ``GOV_RECEIPT_KEY_FILE`` (0600 file, hex). Nothing configured raises
    :class:`NoReceiptKeyError`.

    Returns ``{"seed", "key_id", "pubkey_hex"}`` where ``key_id`` is
    ``sha256(pubkey)[:16]`` hex — the same key-id convention as the
    evidence bundle's V5 key envelope.
    """
    seed_hex = (explicit or os.environ.get("GOV_RECEIPT_KEY", "")).strip()
    if seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise NoReceiptKeyError("GOV_RECEIPT_KEY is not hex")
        if len(seed) != 32:
            raise NoReceiptKeyError("GOV_RECEIPT_KEY must be 32 bytes")
        pub = _ed.publickey(seed)
        return {"seed": seed,
                "key_id": hashlib.sha256(pub).digest()[:16].hex(),
                "pubkey_hex": pub.hex()}
    key_file = os.environ.get("GOV_RECEIPT_KEY_FILE", "").strip()
    if key_file:
        from .keyfiles import require_private_key_file
        try:
            require_private_key_file(key_file)
        except (FileNotFoundError, PermissionError) as e:
            raise NoReceiptKeyError(
                "refusing GOV_RECEIPT_KEY_FILE %s: %s" % (key_file, e))
        try:
            seed = bytes.fromhex(
                Path(key_file).read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as e:
            raise NoReceiptKeyError(
                "cannot read GOV_RECEIPT_KEY_FILE: %s" % (e,))
        if len(seed) != 32:
            raise NoReceiptKeyError(
                "receipt key file must hold 32 bytes hex")
        pub = _ed.publickey(seed)
        return {"seed": seed,
                "key_id": hashlib.sha256(pub).digest()[:16].hex(),
                "pubkey_hex": pub.hex()}
    raise NoReceiptKeyError(
        "no receipt-signing key configured (GOV_RECEIPT_KEY / "
        "GOV_RECEIPT_KEY_FILE); invocation receipts are disabled")


def signing_input(receipt_body):
    """The exact bytes the countersignature covers: domain separation +
    canonical JSON of the receipt body (everything except ``signature``).
    """
    return _SIGNING_DOMAIN + _canonical(receipt_body)


def build_receipt(*, holder, challenge, action_tool, action_args,
                  canonical_target, policy_decision, approval_id,
                  policy_id, preview_text, outcome_status, result,
                  key_id, pubkey_hex, issued_at=None):
    """Build the unsigned receipt body (dict, no ``signature`` key).

    ``action_args`` must be the sentinel-bearing form — the same form the
    audit path records — never substituted secrets. ``result`` is digested,
    never embedded.
    """
    args_digest = _precommit.args_digest(action_tool, action_args)
    body = {
        "receipt_version": RECEIPT_VERSION,
        "holder": {
            "agent_id": holder.get("agent_id"),
            "role": holder.get("role"),
            "principal": holder.get("principal"),
            "run_id": holder.get("run_id"),
        },
        "challenge": challenge,
        "audience": AUDIENCE,
        "action": {
            "tool": action_tool,
            "args_digest": args_digest,
            "canonical_target": canonical_target,
        },
        "resource": canonical_target,
        "policy": {
            "decision": policy_decision,
            "approval_id": approval_id,
            "policy_id": policy_id,
        },
        "preview_digest": (hashlib.sha256(
            preview_text.encode("utf-8")).hexdigest()
            if isinstance(preview_text, str) else None),
        "outcome": {
            "status": outcome_status,
            "result_digest": hashlib.sha256(
                _canonical({"result": result})).hexdigest(),
        },
        "authority": {
            "kid": key_id,
            "pubkey": pubkey_hex,
        },
        "issued_at": issued_at or _utcnow_iso(),
    }
    return body


def countersign(receipt_body, seed):
    """Attach the executor's Ed25519 countersignature. Returns a new dict."""
    sig = _ed.sign(bytes(seed), signing_input(receipt_body))
    receipt = dict(receipt_body)
    receipt["signature"] = _b64u_encode(sig)
    return receipt


def verify_receipt(receipt):
    """Offline verification of a countersigned receipt (stdlib only).

    Returns ``(True, "ok")`` or ``(False, reason)``. Never raises on
    malformed input (fail-closed for verifiers: malformed is False, never
    an exception). Checks: required fields present, receipt_version
    supported, authority well-formed (32-byte pubkey, key_id ==
    sha256(pub)[:16]), and the Ed25519 signature verifies over the
    domain-separated canonical body.
    """
    if not isinstance(receipt, dict):
        return False, "receipt is not a dict"
    body = {k: v for k, v in receipt.items() if k != "signature"}
    if receipt.get("receipt_version") != RECEIPT_VERSION:
        return False, "unsupported receipt_version %r" % (
            receipt.get("receipt_version"),)
    for section in ("holder", "action", "policy", "outcome", "authority"):
        if not isinstance(body.get(section), dict):
            return False, "missing section %r" % section
    if not isinstance(body.get("challenge"), str) or not body["challenge"]:
        return False, "missing challenge"
    if body.get("audience") != AUDIENCE:
        return False, "audience mismatch"
    auth = body["authority"]
    try:
        pub = bytes.fromhex(auth.get("pubkey") or "")
    except (ValueError, TypeError):
        return False, "authority.pubkey not hex"
    if len(pub) != 32:
        return False, "authority.pubkey not 32 bytes"
    if auth.get("kid") != hashlib.sha256(pub).digest()[:16].hex():
        return False, "authority.kid does not match pubkey"
    sig_b64 = receipt.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        return False, "missing signature"
    try:
        sig = _b64u_decode(sig_b64)
    except (ValueError, TypeError):
        return False, "signature not base64url"
    if not _ed.verify(pub, signing_input(body), sig):
        return False, "Ed25519 countersignature does not verify"
    return True, "ok"
