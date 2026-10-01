"""Bounded delegation: AP2-style open/closed mandates (wave-264 lane 1).

An ADAPT of the *mandate pattern* from google-agentic-commerce/AP2
(Apache-2.0) -- pattern only, never the payment rails, and no AP2 code
or spec text is read, copied, imported, or vendored:

* **Open vs closed mandates.** The approver signs an *open mandate*
  carrying constraints (tool allowlist, spend cap, time window, data
  scopes); the agent executes within it, producing *closed mandates*
  hash-bound to the actual tool calls. The audit seam verifies
  closed ⊆ open. This generalizes the approval queue from "approve each
  action" to "approve the bounds, verify the actions" (the
  human-not-present mode).
* **Verifier-side constraint checking.** Verifiers always receive
  closed mandates; the verifier checks them against the open
  constraints. Only constraints relevant to the presented closed
  mandates are shared with the verifier (selective disclosure).
* **Trusted-surface delegation.** The agent creates mandate content
  (:meth:`MandateIssuer.propose`); the deployment shows it to the user
  on a trusted surface; consent produces the signed mandate
  (:meth:`MandateIssuer.consent`). The open mandate seals the digest of
  the viewed proposal, so a mandate cannot be consented without the
  exact content the user saw.
* **Dispute evidence.** Closed mandates hash-chain to their
  predecessors (signed receipts at each step); :meth:`MandateVerifier.
  receipt` mints a signed receipt suitable for evidence bundles.
* **vct-style versioning.** Mandate types are exact version strings
  (``mandate.open.1``, ``mandate.closed.1``, ``mandate.receipt.1``).
  Implementations MUST match the exact type string; an unknown type --
  even with a valid MAC -- refuses ``mandate-version-mismatch``
  instead of being misinterpreted.

Wire format (documented so deployments can re-verify
cross-implementation): canonical JSON (``sort_keys=True``,
``separators=(",", ":")``, UTF-8); ``mac = HMAC-SHA256(key, DOMAIN +
canonical_bytes(body_without_mac))`` compared with
``hmac.compare_digest``. Domain separation per mandate kind (the w244
house standard):

* ``OPEN_DOMAIN``    -- open mandates
* ``CLOSED_DOMAIN``  -- closed mandates
* ``RECEIPT_DOMAIN`` -- dispute-evidence receipts

Composition (never duplication):

* Approval UX: ``propose``/``consent`` are the content/consent halves
  of the trusted surface; the deployment's approval queue renders the
  proposal (see :func:`summarize`) and collects consent.
* Evidence bundles: :meth:`MandateVerifier.receipt` returns a signed
  receipt record ready to embed in a bundle.
* Decision packets: mandate type strings play the same role as
  ``producer_version`` -- exact-match, fail-closed.

Fail-closed throughout: malformed constraints are refused at issue;
constraint violations, expiry, replays, and tampering are refused at
verification with machine codes; unknown versions are refused before
any interpretation.

Honest residuals: the MAC key is deployment-owned (no key ceremony
here); replay/spend/chain state is in-memory per verifier instance (a
restart loses it -- deployments needing durable replay protection
must persist ``consumed``/``spent``/``last`` or re-verify the full
closed-mandate chain from the journal); raw tool args never leave the
executor (only ``args_digest`` is sealed); ``summarize`` is a display
aid, not a security boundary.
"""

import hashlib
import hmac
import json
import math
import time

OPEN_TYPE = "mandate.open.1"
CLOSED_TYPE = "mandate.closed.1"
RECEIPT_TYPE = "mandate.receipt.1"
PROPOSAL_TYPE = "mandate.proposal.1"

OPEN_DOMAIN = b"gov-mandate-open/v1\x00"
CLOSED_DOMAIN = b"gov-mandate-closed/v1\x00"
RECEIPT_DOMAIN = b"gov-mandate-receipt/v1\x00"

_CONSTRAINT_KEYS = frozenset(
    ["tools", "spend_cap", "not_before", "not_after",
     "data_scopes"])


class MandateError(Exception):
    """Base for all mandate refusals; carries the machine code."""
    code = "mandate-malformed"


class MandateMalformed(MandateError):
    code = "mandate-malformed"


class MandateVersionMismatch(MandateError):
    code = "mandate-version-mismatch"


class MandateTampered(MandateError):
    code = "mandate-tampered"


class MandateUnknown(MandateError):
    code = "mandate-unknown"


class MandateExpired(MandateError):
    code = "mandate-expired"


class MandateConstraintExceeded(MandateError):
    code = "mandate-constraint-exceeded"


class MandateReplay(MandateError):
    code = "mandate-replay"


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise MandateMalformed(
            "mandate-malformed: mandate body is not JSON-canonical: "
            "%s" % (e,))


def seal_body(body, domain, key):
    """MAC a mandate body (dict WITHOUT 'mac') for the wire format."""
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise MandateMalformed(
            "mandate-malformed: mac key must be bytes of >= 16")
    if not isinstance(body, dict) or "mac" in body:
        raise MandateMalformed(
            "mandate-malformed: seal_body takes a mac-less dict")
    return hmac.new(bytes(key), domain + _canonical(body),
                    hashlib.sha256).hexdigest()


def mandate_digest(mandate):
    """Stable digest of a mandate (canonical bytes minus 'mac')."""
    if not isinstance(mandate, dict):
        raise MandateMalformed(
            "mandate-malformed: mandate must be a dict")
    body = {k: v for k, v in mandate.items() if k != "mac"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) \
        and math.isfinite(v)


def _check_constraints(cons):
    if not isinstance(cons, dict):
        raise MandateMalformed(
            "mandate-malformed: constraints must be a dict")
    unknown = set(cons) - _CONSTRAINT_KEYS
    if unknown:
        # A typo'd constraint must never silently do nothing.
        raise MandateMalformed(
            "mandate-malformed: unknown constraint keys: %s"
            % sorted(unknown))
    missing = _CONSTRAINT_KEYS - set(cons)
    if missing:
        raise MandateMalformed(
            "mandate-malformed: missing constraint keys: %s"
            % sorted(missing))
    tools = cons["tools"]
    if not isinstance(tools, list) or not tools or not all(
            isinstance(t, str) and t for t in tools):
        raise MandateMalformed(
            "mandate-malformed: tools must be a non-empty list of "
            "non-empty strings")
    cap = cons["spend_cap"]
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 0:
        raise MandateMalformed(
            "mandate-malformed: spend_cap must be an int >= 0")
    nb, na = cons["not_before"], cons["not_after"]
    if not _is_num(nb) or not _is_num(na) or not nb < na:
        raise MandateMalformed(
            "mandate-malformed: not_before/not_after must be finite "
            "numbers with not_before < not_after")
    scopes = cons["data_scopes"]
    if not isinstance(scopes, list) or not all(
            isinstance(s, str) and s for s in scopes):
        raise MandateMalformed(
            "mandate-malformed: data_scopes must be a list of "
            "non-empty strings")
    return {"tools": list(tools), "spend_cap": cap,
            "not_before": nb, "not_after": na,
            "data_scopes": list(scopes)}


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise MandateMalformed(
            "mandate-malformed: mac key must be bytes of >= 16")
    return bytes(key)


def _verify_open_type_and_mac(open_mandate, key):
    """Shared open-mandate gate: exact type match, then MAC verify,
    then constraint validation. Returns the validated constraints."""
    if not isinstance(open_mandate, dict) or \
            open_mandate.get("type") != OPEN_TYPE:
        raise MandateVersionMismatch(
            "mandate-version-mismatch: unknown open mandate type "
            "%r; implementations MUST match the exact type string"
            % ((open_mandate.get("type")
                if isinstance(open_mandate, dict) else None),))
    mac = open_mandate.get("mac")
    body = {k: v for k, v in open_mandate.items() if k != "mac"}
    if not isinstance(mac, str) or not hmac.compare_digest(
            mac, seal_body(body, OPEN_DOMAIN, key)):
        raise MandateTampered(
            "mandate-tampered: open mandate MAC invalid")
    return _check_constraints(open_mandate.get("constraints"))


def summarize(proposal):
    """One-screen trusted-surface rendering of a mandate proposal.

    Display aid only -- not a security boundary. The consent binds
    the proposal DIGEST, never this text.
    """
    cons = proposal.get("constraints", {})
    lines = ["Mandate proposal for subject %r"
             % (proposal.get("subject"),),
             "  tools: %s" % (", ".join(cons.get("tools", [])),),
             "  spend cap: %s" % (cons.get("spend_cap"),),
             "  window: %s .. %s" % (cons.get("not_before"),
                                     cons.get("not_after")),
             "  data scopes: %s"
             % (", ".join(cons.get("data_scopes", [])) or "-"), ]
    return "\n".join(lines)


class MandateIssuer(object):
    """Approver side: proposes mandate content and signs consent."""

    def __init__(self, mac_key):
        self._key = _check_key(mac_key)

    def propose(self, subject, constraints, now=None):
        """Agent-created mandate content, unsigned, for the trusted
        surface to display."""
        if not isinstance(subject, str) or not subject:
            raise MandateMalformed(
                "mandate-malformed: subject must be a non-empty "
                "string")
        cons = _check_constraints(constraints)
        return {"type": PROPOSAL_TYPE, "subject": subject,
                "constraints": cons,
                "proposed_at": now if now is not None
                else time.time()}

    def consent(self, proposal, now=None):
        """Sign the viewed proposal: the trusted-surface consent."""
        if not isinstance(proposal, dict) or \
                proposal.get("type") != PROPOSAL_TYPE:
            raise MandateMalformed(
                "mandate-malformed: consent takes a mandate proposal")
        subject = proposal.get("subject")
        if not isinstance(subject, str) or not subject:
            raise MandateMalformed(
                "mandate-malformed: proposal subject malformed")
        cons = _check_constraints(proposal.get("constraints"))
        digest = hashlib.sha256(
            _canonical(proposal)).hexdigest()
        return self.issue_open(subject, cons,
                               proposal_digest=digest, now=now)

    def issue_open(self, subject, constraints, proposal_digest=None,
                   now=None):
        """Issue (sign) an open mandate directly."""
        if not isinstance(subject, str) or not subject:
            raise MandateMalformed(
                "mandate-malformed: subject must be a non-empty "
                "string")
        cons = _check_constraints(constraints)
        if proposal_digest is not None and not (
                isinstance(proposal_digest, str)
                and len(proposal_digest) == 64):
            raise MandateMalformed(
                "mandate-malformed: proposal_digest must be a "
                "sha256 hex digest")
        issued_at = now if now is not None else time.time()
        if not _is_num(issued_at):
            raise MandateMalformed(
                "mandate-malformed: issued_at must be a finite "
                "number")
        body = {"type": OPEN_TYPE,
                "subject": subject,
                "constraints": cons,
                "proposal_digest": proposal_digest,
                "issued_at": issued_at}
        body["id"] = "mopen-" + hashlib.sha256(
            _canonical(body)).hexdigest()[:32]
        body["mac"] = seal_body(body, OPEN_DOMAIN, self._key)
        return body


class MandateExecutor(object):
    """Agent side: closes mandates over actual tool calls."""

    def __init__(self, mac_key):
        self._key = _check_key(mac_key)

    def _check_open(self, open_mandate):
        _verify_open_type_and_mac(open_mandate, self._key)

    def close_action(self, open_mandate, tool, args, cost,
                     executed_at=None, prev_digest=None):
        """Seal a closed mandate over one actual tool call. Raw args
        never leave the executor -- only their digest is sealed."""
        self._check_open(open_mandate)
        if not isinstance(tool, str) or not tool:
            raise MandateMalformed(
                "mandate-malformed: tool must be a non-empty string")
        if not isinstance(cost, int) or isinstance(cost, bool) \
                or cost < 0:
            raise MandateMalformed(
                "mandate-malformed: cost must be an int >= 0")
        at = executed_at if executed_at is not None else time.time()
        if not _is_num(at):
            raise MandateMalformed(
                "mandate-malformed: executed_at must be a finite "
                "number")
        if prev_digest is not None and not (
                isinstance(prev_digest, str)
                and len(prev_digest) == 64
                and all(c in "0123456789abcdef"
                        for c in prev_digest)):
            raise MandateMalformed(
                "mandate-malformed: prev_digest must be a sha256 "
                "hex digest or None")
        args_digest = hashlib.sha256(
            _canonical(args)).hexdigest()
        body = {"type": CLOSED_TYPE,
                "open_id": open_mandate["id"],
                "action": {"tool": tool, "args_digest": args_digest,
                           "cost": cost},
                "executed_at": at,
                "prev": prev_digest}
        body["id"] = "mclosed-" + hashlib.sha256(
            _canonical(body)).hexdigest()[:32]
        body["mac"] = seal_body(body, CLOSED_DOMAIN, self._key)
        return body


class MandateVerifier(object):
    """Audit seam: verifies closed ⊆ open. Holds replay/spend/chain
    state in memory (see module honest residuals)."""

    def __init__(self, mac_key):
        self._key = _check_key(mac_key)
        self._consumed = {}  # open_id -> set of closed digests
        self._spent = {}     # open_id -> cumulative cost
        self._last = {}      # open_id -> last closed digest (chain)

    def _check_open(self, open_mandate):
        return _verify_open_type_and_mac(open_mandate, self._key)

    def _check_closed(self, closed_mandate):
        if not isinstance(closed_mandate, dict) or \
                closed_mandate.get("type") != CLOSED_TYPE:
            raise MandateVersionMismatch(
                "mandate-version-mismatch: unknown closed mandate "
                "type %r; implementations MUST match the exact type "
                "string" % ((closed_mandate.get("type")
                             if isinstance(closed_mandate, dict)
                             else None),))
        mac = closed_mandate.get("mac")
        body = {k: v for k, v in closed_mandate.items() if k != "mac"}
        if not isinstance(mac, str) or not hmac.compare_digest(
                mac, seal_body(body, CLOSED_DOMAIN, self._key)):
            raise MandateTampered(
                "mandate-tampered: closed mandate MAC invalid")
        action = closed_mandate.get("action")
        if not isinstance(action, dict):
            raise MandateMalformed(
                "mandate-malformed: closed mandate has no action")
        tool = action.get("tool")
        cost = action.get("cost")
        if not isinstance(tool, str) or not tool:
            raise MandateMalformed(
                "mandate-malformed: closed action tool malformed")
        if not isinstance(cost, int) or isinstance(cost, bool) \
                or cost < 0:
            raise MandateMalformed(
                "mandate-malformed: closed action cost malformed")
        at = closed_mandate.get("executed_at")
        if not _is_num(at):
            raise MandateMalformed(
                "mandate-malformed: executed_at malformed")
        return tool, cost, at

    def verify(self, open_mandate, closed_mandate, now=None):
        """Verify closed ⊆ open. Raises a MandateError subclass on
        any violation; returns a verdict dict on success."""
        at_now = now if now is not None else time.time()
        if not _is_num(at_now):
            raise MandateMalformed(
                "mandate-malformed: now must be a finite number")
        cons = self._check_open(open_mandate)
        tool, cost, at = self._check_closed(closed_mandate)
        open_id = open_mandate["id"]
        if closed_mandate.get("open_id") != open_id:
            raise MandateUnknown(
                "mandate-unknown: closed mandate is bound to a "
                "different open mandate than the one presented")
        nb, na = cons["not_before"], cons["not_after"]
        if not (nb <= at <= na):
            raise MandateExpired(
                "mandate-expired: action executed outside the open "
                "mandate window")
        if at_now > na:
            raise MandateExpired(
                "mandate-expired: open mandate window has closed")
        if at > at_now:
            raise MandateTampered(
                "mandate-tampered: action claims a future execution "
                "time")
        if tool not in cons["tools"]:
            raise MandateConstraintExceeded(
                "mandate-constraint-exceeded: tool %r is not in the "
                "open mandate allowlist" % (tool,))
        digest = mandate_digest(closed_mandate)
        consumed = self._consumed.setdefault(open_id, set())
        if digest in consumed:
            raise MandateReplay(
                "mandate-replay: closed mandate already consumed")
        if closed_mandate.get("prev") != self._last.get(open_id):
            raise MandateTampered(
                "mandate-tampered: closed mandate hash chain is "
                "broken")
        spent = self._spent.get(open_id, 0)
        if spent + cost > cons["spend_cap"]:
            raise MandateConstraintExceeded(
                "mandate-constraint-exceeded: cumulative cost %d "
                "exceeds spend cap %d"
                % (spent + cost, cons["spend_cap"]))
        consumed.add(digest)
        self._spent[open_id] = spent + cost
        self._last[open_id] = digest
        return {"ok": True, "open_id": open_id,
                "closed_id": closed_mandate["id"], "tool": tool,
                "cost": cost, "spent": spent + cost,
                "spend_cap": cons["spend_cap"]}

    def verifier_view(self, open_mandate, closed_mandates):
        """Selective disclosure: only the constraints relevant to the
        presented closed mandates are shared with the verifier. The
        full allowlist never leaves the approver side."""
        cons = self._check_open(open_mandate)
        open_id = open_mandate["id"]
        used = set()
        for closed in closed_mandates or []:
            tool, _cost, _at = self._check_closed(closed)
            if closed.get("open_id") != open_id:
                raise MandateUnknown(
                    "mandate-unknown: closed mandate bound to a "
                    "different open mandate")
            used.add(tool)
        return {"open_id": open_id, "type": OPEN_TYPE,
                "tools": sorted(used),
                "spend_cap": cons["spend_cap"],
                "spent": self._spent.get(open_id, 0),
                "not_before": cons["not_before"],
                "not_after": cons["not_after"],
                "data_scopes": cons["data_scopes"]}

    def receipt(self, open_mandate, closed_mandate, now=None):
        """Mint a signed dispute-evidence receipt for a verified
        action. The pair is verified first: receipts are only minted
        for valid actions."""
        verdict = self.verify(open_mandate, closed_mandate,
                              now=now)
        at_now = now if now is not None else time.time()
        body = {"type": RECEIPT_TYPE,
                "open_id": verdict["open_id"],
                "closed_id": verdict["closed_id"],
                "closed_digest": mandate_digest(closed_mandate),
                "verdict": {"tool": verdict["tool"],
                            "cost": verdict["cost"],
                            "spent": verdict["spent"],
                            "spend_cap": verdict["spend_cap"]},
                "issued_at": at_now}
        body["mac"] = seal_body(body, RECEIPT_DOMAIN, self._key)
        return body
