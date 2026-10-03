"""Routing-slip authority for multi-step agent workflows.

Wave-301 lane 5 (MassTransit Courier ADAPT). Stdlib only. Additive:
this module composes ``gov/ed25519.py`` only and changes no existing
API.

A ROUTING SLIP is a signed itinerary that travels WITH the work --
authority rides along instead of sitting in a central orchestrator.
The slip lists the ordered legs of a workflow; each leg carries its
handler identity, granted rights, and expected input/output digests.
Each leg, before executing, re-verifies the FULL slip (design rule:
"A workflow outlives its runner -- every step is checkpointed, and
every resume re-proves its authority"); after executing it appends a
chained receipt and forwards the re-signed slip to the next leg.

Rules (fail closed, every refusal coded):

* the slip signature always covers the whole body; the signer is the
  issuer while no leg has completed, else the handler that completed
  the last receipt;
* a leg is accepted only if its index equals ``next_leg`` -- legs
  cannot be skipped or reordered;
* the completing handler's key must match the leg's pinned
  ``handler_pubkey_hex`` (key continuity, not label continuity);
* every receipt is chained: ``receipt_digest`` commits to the previous
  receipt, so receipts cannot be truncated or spliced;
* delegation narrows, never widens: forwarded rights must be a subset
  of the leg's granted rights, and every later leg's granted rights
  must be a subset of what the previous leg forwarded.

Threat model: the issuer key is the trust anchor (compromised-host
class); expiry uses caller-supplied instants (deployment-owned
clock); shape failures refuse ``decision-code-malformed``; expiry
refuses ``approval-request-expired``; all slip-integrity failures
refuse ``workflow-routing-slip-tampered`` and all widening failures
refuse ``workflow-routing-rights-widened``.

$0 spend, synthetic/local, deterministic. Stdlib only.
"""

import copy
import hashlib
import json
from collections.abc import Mapping

from gov import ed25519

# ---------------------------------------------------------------------------
# Codes (F351: every refusal carries one). Two are minted by this lane;
# shape/expiry failures reuse existing codes.
# ---------------------------------------------------------------------------

WR_SLIP_TAMPERED = "workflow-routing-slip-tampered"
WR_RIGHTS_WIDENED = "workflow-routing-rights-widened"
_MALFORMED = "decision-code-malformed"
_EXPIRED = "approval-request-expired"

GENESIS_PREV = "0" * 64

_SLIP_FIELDS = frozenset((
    "slip_id", "issuer_id", "issuer_pubkey_hex", "issued_at",
    "expires_at", "legs", "receipts", "next_leg", "signature",
))
_LEG_FIELDS = frozenset((
    "handler_id", "handler_pubkey_hex", "rights", "input_digest",
    "output_digest",
))
_RECEIPT_FIELDS = frozenset((
    "leg_index", "handler_id", "result_digest", "forwarded_rights",
    "prev_receipt_digest", "receipt_digest", "signature",
))


class WorkflowRoutingError(Exception):
    """Code-first exception for routing-slip failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise WorkflowRoutingError(detail, code=code)


# F345-class audit sink: records digests/ids only; never breaks the module.
_SINK = None


def set_sink(fn):
    """Install an audit sink ``fn(record)``; None clears it."""
    global _SINK
    _SINK = fn


def _emit(event, detail=None):
    if _SINK is None:
        return
    try:
        _SINK({"event": event, "detail": detail or {}})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Canonical serialization + signing
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _sign(seed, body):
    return ed25519.sign(seed, _canonical(body)).hex()


def _verify_sig(pubkey_hex, signature_hex, body):
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    return ed25519.verify(pub, _canonical(body), sig) is True


# ---------------------------------------------------------------------------
# Shape checks (closed shapes; decision-code-malformed)
# ---------------------------------------------------------------------------

def _is_hex(s, length):
    return (isinstance(s, str) and len(s) == length
            and all(c in "0123456789abcdef" for c in s))


def _check_leg(leg):
    if not isinstance(leg, Mapping) or set(leg.keys()) != _LEG_FIELDS:
        _fail(_MALFORMED, "leg is not the closed leg shape")
    if not isinstance(leg["handler_id"], str) or not leg["handler_id"]:
        _fail(_MALFORMED, "leg handler_id must be a non-empty string")
    if not _is_hex(leg["handler_pubkey_hex"], 64):
        _fail(_MALFORMED, "leg handler_pubkey_hex must be 64 hex chars")
    if (not isinstance(leg["rights"], (list, tuple))
            or not all(isinstance(r, str) and r for r in leg["rights"])):
        _fail(_MALFORMED, "leg rights must be a non-empty string list")
    for f in ("input_digest", "output_digest"):
        if not _is_hex(leg[f], 64):
            _fail(_MALFORMED, "leg %s must be 64 hex chars" % f)


def _check_receipt(receipt):
    if (not isinstance(receipt, Mapping)
            or set(receipt.keys()) != _RECEIPT_FIELDS):
        _fail(_MALFORMED, "receipt is not the closed receipt shape")
    if not isinstance(receipt["leg_index"], int) or receipt["leg_index"] < 0:
        _fail(_MALFORMED, "receipt leg_index must be a non-negative int")
    if not isinstance(receipt["handler_id"], str) or not receipt["handler_id"]:
        _fail(_MALFORMED, "receipt handler_id must be a non-empty string")
    if not _is_hex(receipt["result_digest"], 64):
        _fail(_MALFORMED, "receipt result_digest must be 64 hex chars")
    if (not isinstance(receipt["forwarded_rights"], (list, tuple))
            or not all(isinstance(r, str) and r
                       for r in receipt["forwarded_rights"])):
        _fail(_MALFORMED, "receipt forwarded_rights must be a string list")
    if not _is_hex(receipt["prev_receipt_digest"], 64):
        _fail(_MALFORMED, "receipt prev_receipt_digest must be 64 hex chars")
    if not _is_hex(receipt["receipt_digest"], 64):
        _fail(_MALFORMED, "receipt receipt_digest must be 64 hex chars")
    if not isinstance(receipt["signature"], str) or not receipt["signature"]:
        _fail(_MALFORMED, "receipt signature must be a non-empty string")


def _check_slip_shape(slip):
    if not isinstance(slip, Mapping) or set(slip.keys()) != _SLIP_FIELDS:
        _fail(_MALFORMED, "slip is not the closed slip shape")
    if not isinstance(slip["slip_id"], str) or not slip["slip_id"]:
        _fail(_MALFORMED, "slip_id must be a non-empty string")
    if not isinstance(slip["issuer_id"], str) or not slip["issuer_id"]:
        _fail(_MALFORMED, "issuer_id must be a non-empty string")
    if not _is_hex(slip["issuer_pubkey_hex"], 64):
        _fail(_MALFORMED, "issuer_pubkey_hex must be 64 hex chars")
    if not isinstance(slip["issued_at"], int):
        _fail(_MALFORMED, "issued_at must be an int")
    if slip["expires_at"] is not None and not isinstance(slip["expires_at"],
                                                         int):
        _fail(_MALFORMED, "expires_at must be an int or null")
    if not isinstance(slip["legs"], list) or not slip["legs"]:
        _fail(_MALFORMED, "legs must be a non-empty list")
    for leg in slip["legs"]:
        _check_leg(leg)
    if not isinstance(slip["receipts"], list):
        _fail(_MALFORMED, "receipts must be a list")
    for receipt in slip["receipts"]:
        _check_receipt(receipt)
    if not isinstance(slip["next_leg"], int) or slip["next_leg"] < 0:
        _fail(_MALFORMED, "next_leg must be a non-negative int")
    if not isinstance(slip["signature"], str) or not slip["signature"]:
        _fail(_MALFORMED, "slip signature must be a non-empty string")


def _receipt_digest(prev_digest, leg_index, handler_id, result_digest,
                    forwarded_rights):
    fr = _hex64(_canonical(sorted(forwarded_rights)).decode("utf-8"))
    return hashlib.sha256(
        (prev_digest + str(leg_index) + handler_id + result_digest
         + fr).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Issue
# ---------------------------------------------------------------------------

def issue_slip(issuer_seed, issuer_id, legs, issued_at, expires_at=None,
               slip_id=None):
    """Issue a signed routing slip over the ordered ``legs``."""
    if not isinstance(issuer_id, str) or not issuer_id:
        _fail(_MALFORMED, "issuer_id must be a non-empty string")
    if not isinstance(issued_at, int):
        _fail(_MALFORMED, "issued_at must be an int")
    if not isinstance(legs, (list, tuple)) or not legs:
        _fail(_MALFORMED, "legs must be a non-empty list")
    for leg in legs:
        _check_leg(leg)
    issuer_pub = ed25519.publickey(issuer_seed).hex()
    body = {
        "slip_id": slip_id or _hex64("slip:%s:%d" % (issuer_id, issued_at)),
        "issuer_id": issuer_id,
        "issuer_pubkey_hex": issuer_pub,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "legs": [dict(l) for l in legs],
        "receipts": [],
        "next_leg": 0,
    }
    slip = dict(body)
    slip["signature"] = _sign(issuer_seed, body)
    _emit("slip_issued", {"slip_id": slip["slip_id"],
                          "legs": len(legs)})
    return slip


# ---------------------------------------------------------------------------
# Verify (re-verifies the FULL chain at every leg)
# ---------------------------------------------------------------------------

def verify_slip(slip, trust_roots, at):
    """Verify the whole slip: shape, expiry, issuer trust, signatures,
    receipt chain, leg order, and rights narrowing. Returns True; raises
    WorkflowRoutingError coded otherwise."""
    _check_slip_shape(slip)
    if slip["expires_at"] is not None and at > slip["expires_at"]:
        _fail(_EXPIRED, "routing slip expired")
    if slip["issuer_pubkey_hex"] not in set(trust_roots or []):
        _fail(WR_SLIP_TAMPERED, "slip issuer is not in the trust roots")

    body = {k: v for k, v in slip.items() if k != "signature"}
    receipts = slip["receipts"]
    legs = slip["legs"]
    if receipts:
        last = receipts[-1]
        signer_key = legs[last["leg_index"]]["handler_pubkey_hex"]
    else:
        signer_key = slip["issuer_pubkey_hex"]
    if not _verify_sig(signer_key, slip["signature"], body):
        _fail(WR_SLIP_TAMPERED, "slip signature invalid for last signer")

    if slip["next_leg"] != len(receipts):
        _fail(WR_SLIP_TAMPERED,
              "next_leg %d does not match %d receipts"
              % (slip["next_leg"], len(receipts)))

    prev = GENESIS_PREV
    for i, receipt in enumerate(receipts):
        if receipt["leg_index"] != i:
            _fail(WR_SLIP_TAMPERED,
                  "receipt %d claims leg_index %d: legs cannot be "
                  "skipped or reordered" % (i, receipt["leg_index"]))
        leg = legs[i]
        if receipt["handler_id"] != leg["handler_id"]:
            _fail(WR_SLIP_TAMPERED,
                  "receipt %d handler does not match leg %d" % (i, i))
        rbody = {k: v for k, v in receipt.items() if k != "signature"}
        if not _verify_sig(leg["handler_pubkey_hex"], receipt["signature"],
                           rbody):
            _fail(WR_SLIP_TAMPERED,
                  "receipt %d signature invalid for leg handler" % i)
        if receipt["prev_receipt_digest"] != prev:
            _fail(WR_SLIP_TAMPERED,
                  "receipt %d breaks the receipt chain" % i)
        expect = _receipt_digest(prev, i, leg["handler_id"],
                                 receipt["result_digest"],
                                 receipt["forwarded_rights"])
        if receipt["receipt_digest"] != expect:
            _fail(WR_SLIP_TAMPERED,
                  "receipt %d digest does not recompute" % i)
        # Delegation narrows, never widens: the leg forwards at most
        # what it was granted...
        if not set(receipt["forwarded_rights"]) <= set(leg["rights"]):
            _fail(WR_RIGHTS_WIDENED,
                  "receipt %d forwards rights the leg was not granted" % i)
        # ...and every later leg is granted at most what was forwarded.
        if i + 1 < len(legs) and not set(legs[i + 1]["rights"]) <= set(
                receipt["forwarded_rights"]):
            _fail(WR_RIGHTS_WIDENED,
                  "leg %d is granted rights never forwarded by leg %d"
                  % (i + 1, i))
        prev = receipt["receipt_digest"]

    _emit("slip_verified", {"slip_id": slip["slip_id"],
                            "receipts": len(receipts)})
    return True


# ---------------------------------------------------------------------------
# Accept + complete a leg
# ---------------------------------------------------------------------------

def accept_leg(slip, leg_index, handler_seed, at, trust_roots):
    """Verify the slip and that ``leg_index`` is the outstanding leg
    completed by the holder of ``handler_seed``. Returns the leg dict."""
    verify_slip(slip, trust_roots, at)
    if leg_index != slip["next_leg"]:
        _fail(WR_SLIP_TAMPERED,
              "leg %d is not the outstanding leg (next_leg=%d)"
              % (leg_index, slip["next_leg"]))
    leg = slip["legs"][leg_index]
    handler_pub = ed25519.publickey(handler_seed).hex()
    if handler_pub != leg["handler_pubkey_hex"]:
        _fail(WR_SLIP_TAMPERED,
              "handler key does not match the leg's pinned handler key")
    if leg_index > 0:
        forwarded = slip["receipts"][leg_index - 1]["forwarded_rights"]
        if not set(leg["rights"]) <= set(forwarded):
            _fail(WR_RIGHTS_WIDENED,
                  "leg %d granted rights never forwarded by leg %d"
                  % (leg_index, leg_index - 1))
    return dict(leg)


def complete_leg(slip, leg_index, handler_seed, result_digest, at,
                 trust_roots, forwarded_rights=None, note=None):
    """Complete ``leg_index`` and forward the re-signed slip. Returns a
    NEW slip; the input is never mutated."""
    leg = accept_leg(slip, leg_index, handler_seed, at, trust_roots)
    if not _is_hex(result_digest, 64):
        _fail(_MALFORMED, "result_digest must be 64 hex chars")
    fr = (list(forwarded_rights) if forwarded_rights is not None
          else list(leg["rights"]))
    if not set(fr) <= set(leg["rights"]):
        _fail(WR_RIGHTS_WIDENED,
              "a leg may attenuate forwarded rights, never widen them")

    prev = (slip["receipts"][-1]["receipt_digest"] if slip["receipts"]
            else GENESIS_PREV)
    rbody = {
        "leg_index": leg_index,
        "handler_id": leg["handler_id"],
        "result_digest": result_digest,
        "forwarded_rights": fr,
        "prev_receipt_digest": prev,
        "receipt_digest": _receipt_digest(prev, leg_index,
                                          leg["handler_id"], result_digest,
                                          fr),
    }
    receipt = dict(rbody)
    receipt["signature"] = _sign(handler_seed, rbody)

    new_slip = copy.deepcopy(slip)
    new_slip["receipts"].append(receipt)
    new_slip["next_leg"] = leg_index + 1
    body = {k: v for k, v in new_slip.items() if k != "signature"}
    new_slip["signature"] = _sign(handler_seed, body)
    _emit("leg_completed", {"slip_id": new_slip["slip_id"],
                            "leg_index": leg_index,
                            "note": note or ""})
    return new_slip
