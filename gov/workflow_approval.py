"""Approval-gated workflow steps: durable steps that execute only under a
valid delegated approval.

Wave-302 lane 6. Stdlib only. Additive: composes ``gov/workflow.py``
(durable step records), ``gov/delegation_approval.py`` (delegated
approval requests binding delegation digests), and
``gov/approval_request.py`` (signed, time-boxed approval envelopes).
Modifies none of them.

An approval-gated step binds the step's identity into a delegated
approval BEFORE execution. ``request_approval`` issues a delegated
approval request (signed by the chain tip holder = the step's actor)
whose context digests carry, in addition to the delegation bindings
(``delegation_chain_digest``, ``delegator_id_digest``,
``delegation_right_digest`` -- digests, never raw chains):

* ``workflow_step_digest`` -- sha256 of {run_id, seq, name,
  input_digest}: the step's identity. The approval envelope's action
  digest is over {"tool": "workflow.step", "args": {run_id, seq, name,
  input_digest}} -- the human approves exactly this step.

``ApprovalGatedWorkflow.run_gated_step`` verifies, in order:

1. the delegated package -- envelope shape/expiry/signature, the
   delegation digest bindings, revocation liveness when a revoker is
   presented (revocation beats approval), and the delegation chain
   itself (the existing ``delegation-*`` / ``approval-request-*``
   codes; no new codes minted for those);
2. that the approval's requester is the step's actor and that the
   authority chain presented for execution is the chain the approval
   bound -- otherwise ``workflow-approval-digest-mismatch``;
3. that the approval's ``workflow_step_digest`` equals the presented
   step's digest -- an approval for different digests, a cross-step
   replay, or a non-gated approval refuses
   ``workflow-approval-digest-mismatch``;

then executes via ``WorkflowStore.run_step``. The approval packet
digest is committed into the step's checkpoint record (the step's
inputs are augmented with the reserved ``_gated_step`` binding, so
``inputs_digest`` commits {inputs, step_digest, approval_digest}),
and a ``step_approval_bound`` notification records the plaintext
evidence trail (which approval authorized which step).

Standing design rule: "A workflow outlives its runner -- every step
is checkpointed, and every resume re-proves its authority." A resumed
gated step re-verifies the SAME approval package (expiry enforced at
resume time: a step whose approval has lapsed refuses
``approval-request-expired`` instead of executing) and the delegation
chain. One step, one approval, time-boxed: presenting a different
approval for an already-recorded step slot is workflow definition
drift (``workflow-step-unauthorized`` from the store).

Threat model: the delegator root key is the trust anchor
(compromised-host class); instants are caller-supplied (deployment
clock); revocation is enforced only when a revoker is presented --
pass one when revocation matters (stack-wide convention; without it
revocation-beats-approval is void). Direct ``WorkflowStore`` access
bypasses the gate (same trust plane); the gate is enforced at this
module's API. The requester key signs the approval request
(compromised requester key = compromised-host class).

$0 spend, synthetic/local, deterministic. Stdlib only.
"""

import hashlib
import json

from gov import approval_request as _ar
from gov import delegation_approval as _da

# ---------------------------------------------------------------------------
# Codes (F351: every refusal carries one). Two are minted by this lane;
# envelope/delegation/chain failures reuse the existing approval-request-*,
# delegation-approval-*, and delegation-* codes.
# ---------------------------------------------------------------------------

WA_DIGEST_MISMATCH = "workflow-approval-digest-mismatch"
WA_BINDING_INVALID = "workflow-approval-binding-invalid"

# Context digest name bound into the delegated request at issue time.
STEP_DIGEST_NAME = "workflow_step_digest"

# Reserved key augmented into the step's inputs so the checkpoint
# record's inputs_digest commits the approval binding. User inputs
# carrying this key refuse WA_BINDING_INVALID (fail closed, never
# silently overwritten).
GATED_INPUTS_KEY = "_gated_step"

# The approval action tool name: the human approves a workflow step.
ACTION_TOOL = "workflow.step"


class WorkflowApprovalError(Exception):
    """Code-first exception for approval-gated step failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise WorkflowApprovalError(detail, code=code)


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as e:
        _fail(WA_BINDING_INVALID,
              "material is not JSON-canonicalizable: %r" % (e,))


def _shahex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def input_digest_for(inputs):
    """Digest binding for a step's inputs (canonical JSON)."""
    return _shahex(_canonical(inputs))


def step_digest_for(run_id, seq, name, inputs):
    """The step's identity digest: sha256 of
    {run_id, seq, name, input_digest}."""
    _check_step_identity(run_id, seq, name)
    return _shahex(_canonical({
        "run_id": run_id,
        "seq": seq,
        "name": name,
        "input_digest": input_digest_for(inputs),
    }))


def approval_digest_for(package):
    """Digest binding for an approval package: sha256 of the canonical
    approval envelope (the signed request + signature)."""
    if not isinstance(package, dict) or "envelope" not in package:
        _fail(WA_BINDING_INVALID,
              "package has no approval envelope to digest")
    return _shahex(_canonical(package["envelope"]))


def _check_step_identity(run_id, seq, name):
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id must be a non-empty string")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    if not isinstance(name, str) or not name or len(name) > 128:
        raise ValueError("name must be a 1-128 char string")


def _check_inputs(inputs):
    if not isinstance(inputs, dict):
        _fail(WA_BINDING_INVALID,
              "gated step inputs must be a dict (the approval binding "
              "is augmented into them); got %r" % (type(inputs),))
    if GATED_INPUTS_KEY in inputs:
        _fail(WA_BINDING_INVALID,
              "inputs must not carry the reserved key %r"
              % (GATED_INPUTS_KEY,))
    # Fail fast on unserializable inputs: the approval cannot bind them.
    _canonical(inputs)
    return inputs


def request_approval(*, chain, delegation_right, run_id, seq, name,
                     inputs=None, requester_agent_id, requester_principal,
                     requester_pubkey_hex, requester_seed,
                     approver_schema, ttl_seconds, issued_at=None):
    """Issue a delegated approval request for one workflow step.

    Binds ``workflow_step_digest`` (the step's identity) alongside the
    delegation digests bound by ``issue_delegated_request``. The
    approval envelope's action is {"tool": "workflow.step", "args":
    {run_id, seq, name, input_digest}} -- the human approves exactly
    this step. Returns the delegation package
    {"envelope", "chain", "delegation_right"} (the approval packet).

    The requester MUST be the chain tip's delegatee (enforced by
    ``issue_delegated_request``) and SHOULD be the workflow run's actor
    (enforced at execution time).
    """
    inputs = {} if inputs is None else inputs
    _check_step_identity(run_id, seq, name)
    _check_inputs(inputs)
    input_digest = input_digest_for(inputs)
    step_digest = step_digest_for(run_id, seq, name, inputs)
    action = {"tool": ACTION_TOOL,
              "args": {"run_id": run_id, "seq": seq, "name": name,
                       "input_digest": input_digest}}
    return _da.issue_delegated_request(
        chain=chain,
        delegation_right=delegation_right,
        action=action,
        requester_agent_id=requester_agent_id,
        requester_principal=requester_principal,
        requester_pubkey_hex=requester_pubkey_hex,
        requester_seed=requester_seed,
        context_digests={STEP_DIGEST_NAME: step_digest},
        approver_schema=approver_schema,
        ttl_seconds=ttl_seconds,
        issued_at=issued_at,
    )


class ApprovalGatedWorkflow:
    """Executes approval-gated steps against a ``WorkflowStore``.

    ``trust_roots`` pins the accepted delegation root keys (hex).
    ``revoker`` (a ``gov/delegation_revocation.DelegationRevoker``)
    enables revocation-beats-approval; without it revocation is not
    checked (stack-wide convention -- pass one when revocation
    matters).
    """

    def __init__(self, store, *, trust_roots, revoker=None):
        self._store = store
        self._trust_roots = list(trust_roots)
        self._revoker = revoker
        self._notified = set()  # (run_id, seq, approval_digest) already bound

    def run_gated_step(self, run_id, seq, name, fn, inputs=None, *,
                       approval_package, authority, at,
                       idempotency_key=None):
        """Execute (or replay) one approval-gated step.

        Verifies the approval package (envelope, delegation bindings,
        expiry AT EXECUTION TIME, revocation when a revoker is set,
        chain authorization), then checks the approval authorizes THIS
        step: same requester as the step's actor, same authority chain
        as the approval bound, same step digest. Only then executes
        via ``WorkflowStore.run_step``.

        Returns {"outputs", "replayed", "approval_digest",
        "step_digest"}. Every refusal is coded.
        """
        inputs = {} if inputs is None else inputs
        _check_step_identity(run_id, seq, name)
        _check_inputs(inputs)
        if not isinstance(at, int) or isinstance(at, bool) or at < 0:
            raise ValueError("at must be a non-negative int instant")
        if not callable(fn):
            raise ValueError("fn must be callable")

        input_digest = input_digest_for(inputs)
        step_digest = step_digest_for(run_id, seq, name, inputs)

        # 1. The delegated approval package: envelope (shape, expiry,
        #    signature -- expiry enforced NOW, at execution time),
        #    delegation digest bindings, revocation liveness (when a
        #    revoker is presented -- revocation beats approval), and
        #    the delegation chain. Existing coded errors propagate.
        verdict = _da.verify_delegated_request(
            approval_package, at=at,
            trust_roots=self._trust_roots, revoker=self._revoker)

        # 2a. The approval's requester must be the step's actor: the
        # human approved THIS agent's step, not someone else's.
        requester = verdict["request"]["requester"]["agent_id"]
        actor = authority.get("actor_id") if isinstance(authority,
                                                       dict) else None
        if requester != actor:
            _fail(WA_DIGEST_MISMATCH,
                  "approval requester %r is not the step's actor %r"
                  % (requester, actor))

        # 2b. The executing authority chain must be the chain the
        # approval bound: executing under a broader (or just
        # different) chain than was approved exceeds the approval.
        auth_chain = authority.get("chain") if isinstance(
            authority, dict) else None
        bound_chain_digest = verdict["request"]["context_digests"][
            _da.CTX_CHAIN_DIGEST]
        if _da.chain_digest(auth_chain) != bound_chain_digest:
            _fail(WA_DIGEST_MISMATCH,
                  "executing authority chain does not match the "
                  "approval's bound delegation chain")

        # 3. The approval must bind THIS step's digest: an approval for
        # different digests, a cross-step replay, or a non-gated
        # (plain delegated) approval refuses here.
        ctx = verdict["request"]["context_digests"]
        if ctx.get(STEP_DIGEST_NAME) != step_digest:
            _fail(WA_DIGEST_MISMATCH,
                  "approval does not authorize this step: bound %r != "
                  "presented step digest %r"
                  % (ctx.get(STEP_DIGEST_NAME), step_digest))

        approval_digest = approval_digest_for(approval_package)

        # Plaintext evidence trail in the same checkpoint store: which
        # approval authorized which step. The step record itself
        # commits the approval digest via inputs_digest below.
        evidence_key = (run_id, seq, approval_digest)
        if evidence_key not in self._notified:
            body = verdict["request"]
            self._store.notify(
                run_id, "step_approval_bound",
                {"seq": seq, "name": name,
                 "step_digest": step_digest,
                 "input_digest": input_digest,
                 "approval_digest": approval_digest,
                 "delegator_id": verdict["delegator_id"],
                 "delegation_right": verdict["delegation_right"],
                 "requester_agent_id": requester,
                 "approval_issued_at": body["issued_at"],
                 "approval_expires_at": (body["issued_at"]
                                         + body["ttl_seconds"])},
                authority=authority, at=at)
            self._notified.add(evidence_key)

        # The approval digest is committed into the step's checkpoint
        # record: inputs_digest covers the augmented inputs. fn sees
        # the original inputs (the reserved key is stripped).
        augmented = dict(inputs)
        augmented[GATED_INPUTS_KEY] = {"step_digest": step_digest,
                                       "approval_digest": approval_digest}

        def _call(aug):
            return fn({k: v for k, v in aug.items()
                       if k != GATED_INPUTS_KEY})

        outputs, replayed = self._store.run_step(
            run_id, seq, name, _call, augmented,
            idempotency_key=idempotency_key, authority=authority, at=at)
        return {"outputs": outputs, "replayed": replayed,
                "approval_digest": approval_digest,
                "step_digest": step_digest}
