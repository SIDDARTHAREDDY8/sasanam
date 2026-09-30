"""Signed denial receipts as first-class outcomes.

Wave-230 lane A. Stdlib only.

Every decision -- PERMIT and DENY alike -- can emit a signed
receipt::

    {verdict PERMIT|DENY, class ok|violation|unavailable, rule_path,
     token_digest, policy_bundle_digest, intent_digest,
     jurisdiction_profile, alg, key_id, non_repudiation, signature}

The signature input is domain-separated
(``gov-deny-receipt/v1`` + canonical JSON of the record body), so a
receipt signature can never be repurposed as another record's
signature. Receipts are EVIDENCE, never authority: any
authority-shaped use refuses ``deny-receipt-not-authorization``.

Design rules (re-derived; nothing copied from the external
spt-txn/deny-receipt literature):

1. Hashes-only: digest fields must be 64-char lowercase hex. A
   decision carrying a raw PII string in a digest field refuses
   ``taxonomy-receipt-missing`` -- the evidence is not
   digest-shaped, so no receipt is formed and no PII enters the
   receipt bytes.
2. Outages are honest: an outage decision carries
   class=unavailable. A permit verdict paired with an unavailable
   class refuses ``deny-receipt-unavailable-as-permit`` -- an
   outage must never default to permit.
3. Receipt keys are caller-chosen: ``emit`` takes an explicit
   :class:`Signer` (algorithm, secret, key id). There is no default
   fallback to the audit-log key; the deployment provisions a
   dedicated receipt key and the receipt names it (``key_id``), so
   key scope is visible in the receipt itself.
4. Recompute, never trust: ``verify`` re-derives the signature
   input from the presented record; a tampered record refuses
   ``deny-receipt-signature-invalid``.
5. MAC tiers honestly labeled: a receipt minted under
   ``hmac-sha256-mac`` verifies but carries
   ``non_repudiation=False`` (per gov/alg_registry.py); only
   ``ed25519-rfc8032`` receipts are non-repudiation evidence.

Composition: :func:`receipt_evidence` returns the digest-linked
evidence record a decision packet or an audit entry may carry; the
packet's keyword-only ``deny_receipt`` kwarg (see
gov/decision_packet.py) attaches it signature-covered and
byte-identical when absent. The audit-log writer chains
``receipt_evidence["digest"]`` like any other evidence digest --
no change to the log format is needed or made.

Registries are in-memory; persistence and distribution are
deployment-owned. A receipt proves the emitter's signed claim
about a decision; it does not prove the underlying decision was
correct or that the described execution occurred (same honest
boundary as the decision codes and receipts this module composes
with).
"""

import hashlib
import json

DENY_RECEIPT_VERSION = 1

_RECEIPT_KIND = "deny-receipt"
_SIGNATURE_DOMAIN = b"gov-deny-receipt/v1"

_VERDICTS = ("PERMIT", "DENY")
_CLASSES = ("ok", "violation", "unavailable")

# Decision-record fields receipt emission needs. "outage" is
# optional; everything else is mandatory.
_REQUIRED_DECISION_FIELDS = (
    "verdict",
    "rule_path",
    "token_digest",
    "policy_bundle_digest",
    "intent_digest",
    "jurisdiction_profile",
)

_DIGEST_FIELDS = ("token_digest", "policy_bundle_digest", "intent_digest")


# -- errors -------------------------------------------------------------

class DenyReceiptError(Exception):
    """Base class for signed-denial-receipt refusals. ``code`` is
    machine-readable and registered in gov/decision_codes.py."""
    code = "deny-receipt-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class DenyReceiptMissing(DenyReceiptError):
    """The decision lacked the digest-shaped evidence a receipt
    needs (missing field or raw non-digest value)."""
    code = "taxonomy-receipt-missing"


class DenyReceiptMalformed(DenyReceiptError):
    """The presented receipt is not a well-formed receipt record."""
    code = "deny-receipt-malformed"


class DenyReceiptInvalid(DenyReceiptError):
    """The presented receipt's signature does not verify."""
    code = "deny-receipt-signature-invalid"


class DenyReceiptUnavailableAsPermit(DenyReceiptError):
    """A permit verdict was paired with an unavailable (outage)
    class. Outages never default to permit."""
    code = "deny-receipt-unavailable-as-permit"


class DenyReceiptNotAuthority(DenyReceiptError):
    """A receipt was offered as authority. Receipts are evidence,
    never authorization."""
    code = "deny-receipt-not-authorization"


# -- signers ------------------------------------------------------------

class Signer:
    """An explicit receipt-signing identity: named algorithm, secret
    bytes, and a key id the receipt names. There is deliberately no
    default signer -- deployments provision a dedicated receipt key
    rather than silently reusing the audit-log key."""
    __slots__ = ("alg", "secret", "key_id")

    def __init__(self, alg, secret, key_id):
        if not isinstance(alg, str) or not alg:
            raise DenyReceiptMalformed("signer alg must be a non-empty string")
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise DenyReceiptMalformed("signer secret must be non-empty bytes")
        if not isinstance(key_id, str) or not key_id:
            raise DenyReceiptMalformed("signer key_id must be a non-empty string")
        self.alg = alg
        self.secret = bytes(secret)
        self.key_id = key_id


# -- internals ----------------------------------------------------------

def _alg_registry():
    try:
        from . import alg_registry as mod
    except ImportError:  # standalone: registry beside this file
        import alg_registry as mod  # noqa: N812
    return mod


def _registry(registry):
    if registry is not None:
        return registry
    return _alg_registry().default_registry()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _is_hex64(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _signing_input(body):
    return _SIGNATURE_DOMAIN + _canonical(body)


def _check_receipt_shape(receipt):
    if not isinstance(receipt, dict):
        raise DenyReceiptMalformed("receipt must be a dict")
    expected = {"v", "kind", "verdict", "class", "rule_path",
                "token_digest", "policy_bundle_digest", "intent_digest",
                "jurisdiction_profile", "alg", "key_id",
                "non_repudiation", "signature"}
    unknown = set(receipt) - expected
    if unknown:
        raise DenyReceiptMalformed(
            "unknown receipt fields: %s" % ",".join(sorted(unknown)))
    missing = expected - set(receipt)
    if missing:
        raise DenyReceiptMalformed(
            "missing receipt fields: %s" % ",".join(sorted(missing)))
    if receipt.get("v") != DENY_RECEIPT_VERSION:
        raise DenyReceiptMalformed("bad receipt version")
    if receipt.get("kind") != _RECEIPT_KIND:
        raise DenyReceiptMalformed("receipt kind mismatch")
    return receipt


# -- public API ---------------------------------------------------------

def emit(decision_record, *, signer, registry=None):
    """Emit a signed denial (or permit) receipt for a decision.

    ``decision_record`` needs ``verdict`` (permit|deny), an optional
    truthy ``outage`` flag, ``rule_path``, the three hex64 digests
    (``token_digest``, ``policy_bundle_digest``, ``intent_digest``),
    and ``jurisdiction_profile`` (opaque profile id, deployment
    vocabulary). Missing or non-digest-shaped evidence refuses
    ``taxonomy-receipt-missing``.

    The class is derived, never trusted: permit -> ok,
    deny -> violation, and any outage -> unavailable. A permit
    verdict on an outage refuses
    ``deny-receipt-unavailable-as-permit``.
    """
    if not isinstance(decision_record, dict):
        raise DenyReceiptMalformed("decision record must be a dict")
    missing = [f for f in _REQUIRED_DECISION_FIELDS
               if decision_record.get(f) in (None, "")]
    if missing:
        raise DenyReceiptMissing(
            "taxonomy-receipt-missing: decision lacks %s"
            % ",".join(sorted(missing)))
    for field in _DIGEST_FIELDS:
        if not _is_hex64(decision_record[field]):
            raise DenyReceiptMissing(
                "taxonomy-receipt-missing: %s is not a digest "
                "(hashes-only: raw values never enter a receipt)" % field)
    raw_verdict = decision_record["verdict"]
    if not isinstance(raw_verdict, str):
        raise DenyReceiptMissing(
            "taxonomy-receipt-missing: verdict is not a string")
    verdict = raw_verdict.strip().upper()
    if verdict not in _VERDICTS:
        raise DenyReceiptMissing(
            "taxonomy-receipt-missing: verdict %r is not a decision"
            % (raw_verdict,))
    outage = bool(decision_record.get("outage"))
    if outage:
        if verdict == "PERMIT":
            raise DenyReceiptUnavailableAsPermit(
                "deny-receipt-unavailable-as-permit: an outage "
                "decision must never be receipted as permit")
        klass = "unavailable"
    elif verdict == "PERMIT":
        klass = "ok"
    else:
        klass = "violation"
    rule_path = decision_record["rule_path"]
    if not isinstance(rule_path, str) or not rule_path.strip():
        raise DenyReceiptMissing(
            "taxonomy-receipt-missing: rule_path is empty")
    profile = decision_record["jurisdiction_profile"]
    if not isinstance(profile, str) or not profile.strip():
        raise DenyReceiptMissing(
            "taxonomy-receipt-missing: jurisdiction_profile is empty")
    if not isinstance(signer, Signer):
        raise DenyReceiptMalformed("signer must be a gov.deny_receipts.Signer")
    reg = _registry(registry)
    try:
        entry_alg = reg._entry(signer.alg)  # fail closed on unregistered
    except Exception as exc:
        raise DenyReceiptMissing(
            "taxonomy-receipt-missing: receipt alg %r unusable: %s"
            % (signer.alg, exc))
    body = {
        "v": DENY_RECEIPT_VERSION,
        "kind": _RECEIPT_KIND,
        "verdict": verdict,
        "class": klass,
        "rule_path": rule_path,
        "token_digest": decision_record["token_digest"],
        "policy_bundle_digest": decision_record["policy_bundle_digest"],
        "intent_digest": decision_record["intent_digest"],
        "jurisdiction_profile": profile,
        "alg": signer.alg,
        "key_id": signer.key_id,
        "non_repudiation": bool(entry_alg["non_repudiation"]),
    }
    sig = reg.sign(signer.alg, _signing_input(body), signer.secret)
    receipt = dict(body)
    receipt["signature"] = sig.hex()
    return receipt


def verify(receipt, *, key, expect_alg=None, registry=None):
    """Verify a presented receipt.

    Shape violations refuse ``deny-receipt-malformed``; a signature
    that does not verify refuses ``deny-receipt-signature-invalid``.
    On success returns the verified claim (verdict, class, rule
    path, key id, non_repudiation, digest). Receipts are evidence,
    never authority.
    """
    _check_receipt_shape(receipt)
    reg = _registry(registry)
    try:
        alg = reg._entry(receipt["alg"])  # fail closed on unregistered
    except Exception:
        raise DenyReceiptInvalid(
            "deny-receipt-signature-invalid: receipt alg %r is "
            "unregistered" % (receipt.get("alg"),))
    if expect_alg is not None and receipt["alg"] != expect_alg:
        raise DenyReceiptInvalid(
            "deny-receipt-signature-invalid: alg %r != pinned %r"
            % (receipt["alg"], expect_alg))
    sig_hex = receipt["signature"]
    if not isinstance(sig_hex, str) or not sig_hex:
        raise DenyReceiptMalformed("receipt signature malformed")
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        raise DenyReceiptMalformed("receipt signature is not hex")
    body = {k: v for k, v in receipt.items() if k != "signature"}
    if not reg.verify(receipt["alg"], _signing_input(body), sig, key):
        raise DenyReceiptInvalid(
            "deny-receipt-signature-invalid: signature does not verify")
    return {
        "ok": True,
        "verdict": receipt["verdict"],
        "class": receipt["class"],
        "rule_path": receipt["rule_path"],
        "key_id": receipt["key_id"],
        "non_repudiation": receipt["non_repudiation"],
        "digest": hashlib.sha256(_signing_input(body)).hexdigest(),
    }


def receipt_evidence(receipt):
    """The digest-linked evidence record a decision packet or audit
    entry carries for a receipt. Shape-checked (``deny-receipt-
    malformed`` on violation); digest recomputed, never trusted."""
    _check_receipt_shape(receipt)
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return {
        "kind": "deny-receipt-evidence",
        "digest": hashlib.sha256(_signing_input(body)).hexdigest(),
        "verdict": receipt["verdict"],
        "class": receipt["class"],
        "key_id": receipt["key_id"],
    }


def evidence_digest(evidence):
    """Recompute the digest identity of a receipt-evidence record."""
    if not isinstance(evidence, dict):
        raise DenyReceiptMalformed("evidence must be a dict")
    return hashlib.sha256(_canonical(evidence)).hexdigest()


def receipt_as_authority(receipt):
    """Always refuses ``deny-receipt-not-authorization``: a receipt
    records a decision; it never confers permission."""
    _check_receipt_shape(receipt)
    raise DenyReceiptNotAuthority(
        "deny-receipt-not-authorization: a signed receipt is "
        "evidence of a decision, never authority to act")
