"""Shared bridge-adapter contract (A12).

README CONTRACT
---------------

A bridge lets a FOREIGN agent runtime ask OUR durable approval queue
for a human decision. Every bridge implements ``BridgeAdapter``:

* ``request_approval(ctx) -> BridgeHandle`` — translate the foreign
  approval context into a ``queue_external()`` call and return a
  handle. Must be side-effect-free beyond queueing (the foreign
  runtime has NOT approved anything yet).
* ``wait_for_decision(handle, timeout_s) -> str`` — bounded wait for
  the human verdict; returns "approved" | "rejected" | "timeout".
  "timeout" and every unexpected failure map to DENY on the foreign
  side (fail-safe). The timeout MUST be strictly shorter than the
  foreign runtime's own approval timeout.
* ``abort(handle, reason)`` — the foreign runtime cancelled the
  request. Best-effort: the queued record cannot be un-queued; the
  abort is audited and any later wait resolves normally.

Shared fail-safe semantics (use the helpers; do not reimplement):

* ``deny_decision(reason)`` — the canonical deny outcome.
* ``bounded_wait(queue, handle, timeout_s)`` — wraps
  ``queue.wait_for_decision()``; ANY exception (unknown id, tamper
  refusal, vanished record) becomes "rejected" + audit. A bridge must
  never let a queue-side failure turn into an approval.
* ``compute_request_digest(envelope)`` — canonical sha256 of the
  foreign request envelope, stored as ``bridge_request_digest`` and
  MAC-bound into the record. Tamper-EVIDENCE, not foreign
  attestation: we cannot verify the digest against the foreign
  runtime (no shared secret).

What bridges MUST NOT do:

* execute anything themselves (the foreign runtime executes);
* bypass the queue's decision paths (no direct status writes);
* blur "approval delegation" (D1-core human stewardship) with
  "authority delegation" (P10 agent-to-agent grants) — bridges do
  neither;
* trust foreign framing: caller DIDs, justifications, and arguments
  are recorded verbatim as UNVERIFIED; the human sees only the
  bridge's generated preview.
"""

import json
from abc import ABC, abstractmethod
from hashlib import sha256


def _canonical_dumps(obj):
    """Deterministic canonical JSON (dicts sorted; sets normalized)."""
    def _norm(o):
        if isinstance(o, dict):
            return {str(k): _norm(v)
                    for k, v in sorted(o.items(), key=lambda kv: str(kv[0]))}
        if isinstance(o, (set, frozenset)):
            return sorted((_norm(v) for v in o),
                          key=lambda x: json.dumps(x, sort_keys=True,
                                                   separators=(",", ":"),
                                                   default=str))
        if isinstance(o, (list, tuple)):
            return [_norm(v) for v in o]
        return o
    return json.dumps(_norm(obj), sort_keys=True, separators=(",", ":"),
                      default=str, ensure_ascii=True)


def compute_request_digest(envelope):
    """Canonical sha256 digest of a foreign approval-request envelope.

    ``envelope`` is a JSON-able dict of the foreign request's
    identity-relevant fields (request id, action, arguments, caller,
    versions). The digest is stored as ``bridge_request_digest`` and
    MAC-bound into the queue record — post-queue tampering is
    detected, never silently accepted. It is NOT verified against the
    foreign runtime (no shared secret exists): tamper-evidence, not
    attestation.
    """
    if not isinstance(envelope, dict):
        raise TypeError(
            "compute_request_digest() requires a dict envelope, got %r"
            % type(envelope).__name__)
    return "sha256:" + sha256(
        _canonical_dumps(envelope).encode("utf-8")).hexdigest()


class BridgeHandle:
    """Opaque handle for one foreign approval request.

    ``approval_id`` is the queue record; ``bridge_id`` the adapter;
    ``external_request_id`` the foreign runtime's idempotency key.
    """

    def __init__(self, approval_id, bridge_id, external_request_id=None):
        if not approval_id or not isinstance(approval_id, str):
            raise ValueError("BridgeHandle requires an approval_id string")
        if not bridge_id or not isinstance(bridge_id, str):
            raise ValueError("BridgeHandle requires a bridge_id string")
        self.approval_id = approval_id
        self.bridge_id = bridge_id
        self.external_request_id = external_request_id

    def to_dict(self):
        return {"approval_id": self.approval_id,
                "bridge_id": self.bridge_id,
                "external_request_id": self.external_request_id}

    def __repr__(self):
        return ("BridgeHandle(approval_id=%r, bridge_id=%r, "
                "external_request_id=%r)" % (
                    self.approval_id, self.bridge_id,
                    self.external_request_id))


class BridgeAdapter(ABC):
    """ABC for D1 bridge adapters (A12). See module docstring for the
    contract."""

    #: Adapter id, also the record's ``bridge_id`` (web UI badge).
    bridge_id = "bridge"

    @abstractmethod
    def request_approval(self, ctx):
        """Translate the foreign approval context; queue; return a
        BridgeHandle. Side-effect-free beyond queue_external()."""
        raise NotImplementedError

    @abstractmethod
    def wait_for_decision(self, handle, timeout_s):
        """Bounded wait -> "approved" | "rejected" | "timeout".

        ``timeout_s`` MUST be strictly shorter than the foreign
        runtime's own approval timeout. "timeout" (and any failure)
        means DENY on the foreign side.
        """
        raise NotImplementedError

    @abstractmethod
    def abort(self, handle, reason):
        """The foreign runtime cancelled the request. Best-effort:
        audited; the queued record stands (it cannot be un-queued)."""
        raise NotImplementedError

    # -- shared fail-safe helpers ------------------------------------

    @staticmethod
    def deny_decision(reason):
        """The canonical deny outcome for a bridge wait.

        Every non-approval (timeout, rejection, queue failure) maps
        here: a bridge NEVER approves on anything but an explicit
        human "approved".
        """
        return "rejected"

    def bounded_wait(self, queue, handle, timeout_s):
        """Fail-safe wrapper around ``queue.wait_for_decision()``.

        Returns "approved" only on an explicit human approval; maps
        "timeout" -> deny and EVERY exception (unknown id, tamper
        refusal, vanished record) -> "rejected" + audit. A bridge must
        never let a queue-side failure become an approval.
        """
        try:
            decision = queue.wait_for_decision(handle.approval_id,
                                              timeout_s)
        except Exception as e:
            try:
                queue.log.append({
                    "event": "bridge_wait_failed",
                    "run_id": queue.run_id,
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "decision": "bridge_wait_failed",
                    "approval_id": handle.approval_id,
                    "bridge_id": self.bridge_id,
                    "external_request_id": handle.external_request_id,
                    "reason": ("bridge wait failed (%s: %s) — mapped to "
                               "deny; a queue-side failure must never "
                               "become an approval"
                               % (type(e).__name__, e)),
                })
            except Exception:
                pass
            return self.deny_decision("bridge wait failed: %s" % e)
        if decision == "approved":
            return "approved"
        # "rejected" and "timeout" are both deny on the foreign side
        # ("timeout" already expired the bridge wait via
        # mark_bridge_expired inside wait_for_decision).
        return self.deny_decision("foreign decision: %s" % decision)

    def audit(self, queue, event, handle=None, reason="", **extra):
        """Append a bridge audit event (best-effort; never raises)."""
        try:
            fields = {
                "event": event,
                "run_id": queue.run_id,
                "agent_id": "human-operator",
                "role": "approver",
                "principal": "human-operator",
                "decision": event,
                "bridge_id": self.bridge_id,
                "reason": reason,
            }
            if handle is not None:
                fields["approval_id"] = handle.approval_id
                fields["external_request_id"] = handle.external_request_id
            fields.update(extra)
            queue.log.append(fields)
        except Exception:
            pass
