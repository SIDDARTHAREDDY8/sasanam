"""In-process bridge shim for AGT-Python (A12, sequencing step 2).

README CONTRACT
---------------

This module lets an AGT-Python agent runtime pause for a human
decision and have that decision served by OUR durable approval queue —
instead of AGT's synchronous pause/resume, the request becomes a
restart-surviving, HMAC-bound queue record with TTL, quorum, and
audit.

Wiring (operator-side; the AGT SDK is NOT vendored here — this module
is stdlib-only per D5 so the queue stays contribution-shaped):

    handler = DurableQueueApprovalHandler(queue, executor)
    agt_engine.set_approval_handler(handler)   # whatever the SDK's
                                               # registration call is

The handler implements AGT-Python's ``ApprovalHandler`` interface
shape — ``request_approval(context) -> decision`` — duck-typed: the
SDK is never imported, so this module loads with or without AGT
installed. Map the returned "approved"/"rejected" strings onto the
SDK's ``ApprovalDecision`` enum at the call site (see
``to_agt_decision``).

Timeout discipline (A12): our bounded wait (default 240s) is STRICTLY
shorter than the foreign runtime's own approval timeout (AGT's
CallbackApproval default is 5 min per A12). On our timeout we expire
the bridge wait and return DENY — the record stays pending and a
later human decision is audit-only, never executable (T11/T12).

Identity mapping (A12): the foreign caller claim (e.g.
``did:agentmesh:…``) is recorded VERBATIM as untrusted framing
(agent_justification, labeled UNVERIFIED everywhere it renders). The
human sees ONLY the bridge-generated preview below — never raw
foreign framing.

Honest limits: the foreign request digest is tamper-EVIDENCE (MAC-
bound into our record), not attestation — we share no secret with the
AGT runtime and cannot verify the digest against it. The shim never
executes anything: the AGT runtime executes on its side after we
return the decision.
"""

from .core import BridgeAdapter, BridgeHandle, compute_request_digest


class DurableQueueApprovalHandler(BridgeAdapter):
    """AGT-Python ``ApprovalHandler`` shim backed by the durable queue.

    ``queue`` is the ApprovalQueue, ``executor`` the ToolExecutor
    (used only to mint the bridge's caller identity in-process —
    never to execute). ``wait_timeout_s`` defaults to 240s (4 min),
    strictly under AGT's 5-min CallbackApproval default (A12).
    """

    bridge_id = "agt-python"

    #: The foreign runtime's own approval timeout (seconds) that our
    #: wait must stay strictly under. Sourced from A12 (AGT's
    #: CallbackApproval default); re-check against the SDK version in
    #: use — if the foreign default ever shrinks, lower
    #: ``wait_timeout_s`` to match.
    FOREIGN_TIMEOUT_SECS = 300.0
    DEFAULT_WAIT_TIMEOUT_SECS = 240.0

    def __init__(self, queue, executor, wait_timeout_s=None):
        if queue is None or executor is None:
            raise ValueError(
                "DurableQueueApprovalHandler requires a queue and an "
                "executor")
        self.queue = queue
        self.executor = executor
        if wait_timeout_s is None:
            wait_timeout_s = self.DEFAULT_WAIT_TIMEOUT_SECS
        if (not isinstance(wait_timeout_s, (int, float))
                or isinstance(wait_timeout_s, bool)
                or not 0 < wait_timeout_s < self.FOREIGN_TIMEOUT_SECS):
            raise ValueError(
                "wait_timeout_s must be positive and STRICTLY shorter "
                "than the foreign runtime's %ss approval timeout "
                "(fail-safe: our wait must lapse first)"
                % self.FOREIGN_TIMEOUT_SECS)
        self.wait_timeout_s = float(wait_timeout_s)

    # -- context normalization ----------------------------------------

    @staticmethod
    def _field(ctx, name, default=None):
        """Read a foreign context field from a dict or an object."""
        if isinstance(ctx, dict):
            return ctx.get(name, default)
        return getattr(ctx, name, default)

    def _normalize_context(self, ctx):
        """Translate the foreign approval context into our envelope.

        Accepts a dict or an object with attributes. Unknown shapes
        raise ValueError (fail-closed) rather than guessing.
        """
        if ctx is None:
            raise ValueError("request_approval() refused: null context")
        action = (self._field(ctx, "action")
                  or self._field(ctx, "tool")
                  or self._field(ctx, "action_name"))
        arguments = (self._field(ctx, "arguments")
                     or self._field(ctx, "args") or {})
        request_id = (self._field(ctx, "request_id")
                      or self._field(ctx, "approval_request_id"))
        caller = (self._field(ctx, "caller")
                  or self._field(ctx, "caller_did")
                  or self._field(ctx, "did")
                  or "unknown-caller")
        policy_id = (self._field(ctx, "policy_id")
                     or self._field(ctx, "policy") or "agt-default")
        if not action or not isinstance(action, str):
            raise ValueError(
                "request_approval() refused: foreign context carries no "
                "action/tool name")
        if not isinstance(arguments, dict):
            raise ValueError(
                "request_approval() refused: foreign arguments must be a "
                "mapping")
        versions = self._field(ctx, "versions") or {}
        if not isinstance(versions, dict):
            versions = {}
        return {
            "action": action,
            "arguments": arguments,
            "request_id": (str(request_id) if request_id is not None
                           else None),
            "caller": str(caller),
            "policy_id": str(policy_id),
            "versions": {str(k): str(v) for k, v in versions.items()},
        }

    def _build_preview(self, envelope):
        """The human-facing summary — generated HERE, never from
        foreign framing. The caller DID is shown labeled UNVERIFIED;
        argument values are truncated reprs (the queue sanitizes
        non-printables per F11)."""
        lines = ["Foreign approval request via AGT-Python bridge:",
                 "  action: %s" % envelope["action"],
                 "  caller: %s (UNVERIFIED foreign claim)"
                 % envelope["caller"],
                 "  foreign policy: %s" % envelope["policy_id"]]
        args = envelope["arguments"]
        if args:
            lines.append("  arguments:")
            for k in sorted(args):
                v = repr(args[k])
                if len(v) > 200:
                    v = v[:200] + "…(truncated)"
                lines.append("    %s: %s" % (k, v))
        else:
            lines.append("  arguments: (none)")
        if envelope["request_id"]:
            lines.append("  foreign request id: %s"
                         % envelope["request_id"])
        return "\n".join(lines)

    # -- BridgeAdapter -------------------------------------------------

    def request_approval(self, ctx):
        """Queue the foreign approval request; return a BridgeHandle."""
        envelope = self._normalize_context(ctx)
        digest = compute_request_digest({
            "bridge": self.bridge_id,
            "request_id": envelope["request_id"],
            "action": envelope["action"],
            "arguments": envelope["arguments"],
            "caller": envelope["caller"],
            "policy_id": envelope["policy_id"],
            "versions": envelope["versions"],
        })
        # In-process identity mint: the foreign caller claim is
        # recorded VERBATIM as untrusted framing (agent_justification);
        # authority fields come from OUR mint, never from the claim.
        identity = self.executor.mint_identity(
            agent_id="agt:%s" % envelope["caller"],
            role="foreign-agent",
            principal=envelope["caller"])
        preview = self._build_preview(envelope)
        justification = (
            "foreign caller claim (UNVERIFIED): %s" % envelope["caller"])
        approval_id = self.queue.queue_external(
            tool="agt:%s" % envelope["action"],
            args=envelope["arguments"],
            policy_id="agt:%s" % envelope["policy_id"],
            agent_identity=identity,
            preview=preview,
            bridge_id=self.bridge_id,
            external_request_id=envelope["request_id"],
            bridge_request_digest=digest,
            bridge_versions=(envelope["versions"] or None),
            agent_justification=justification,
        )
        handle = BridgeHandle(approval_id, self.bridge_id,
                              envelope["request_id"])
        self.audit(self.queue, "bridge_agt_request_queued", handle,
                   "AGT approval request queued; waiting up to %ss for "
                   "a human decision" % self.wait_timeout_s,
                   foreign_action=envelope["action"])
        return handle

    def wait_for_decision(self, handle, timeout_s=None):
        """Bounded wait -> "approved" | "rejected" | "timeout".

        Defaults to the handler's ``wait_timeout_s`` (4 min, strictly
        under the foreign 5-min default). The caller maps the result
        onto the SDK's ApprovalDecision (see ``to_agt_decision``);
        "timeout" and any failure mean DENY.
        """
        if timeout_s is None:
            timeout_s = self.wait_timeout_s
        return self.bounded_wait(self.queue, handle, timeout_s)

    def abort(self, handle, reason):
        """The AGT runtime cancelled the request: audit it.

        Best-effort — the queued record cannot be un-queued, so a
        later human decision is still recorded (and, if the bridge
        wait already timed out, is audit-only per T11/T12).
        """
        self.audit(self.queue, "bridge_aborted", handle,
                   "foreign runtime aborted the approval request: %s "
                   "(queued record stands; any later decision follows "
                   "the normal bridge lifecycle)" % (reason or "no reason"))

    # -- decision mapping ----------------------------------------------

    @staticmethod
    def to_agt_decision(decision):
        """Map our wait outcome onto the AGT ApprovalDecision shape.

        Returns "APPROVED" only for an explicit human "approved";
        EVERYTHING else ("rejected", "timeout", unknown) maps to
        "REJECTED" — the fail-safe direction. Wire these strings onto
        the SDK's ApprovalDecision enum at the call site.
        """
        if decision == "approved":
            return "APPROVED"
        return "REJECTED"
