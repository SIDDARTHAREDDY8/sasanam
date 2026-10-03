"""First-class decision traces: per-decision evidence with a replay contract.

Pattern lineage: permify/permify (Apache-2.0) -- every authorization
check emits a per-edge decision record (which rule, which outcome, which
reason) so a denied or allowed decision is explainable and auditable
without re-running the engine. Mechanism only; no vendored code; stdlib
only.

A decision trace is the per-edge record of ONE policy evaluation:

* ``decision_id`` -- unique id for this evaluation;
* ``subsystem`` -- which decision procedure produced it
  (``"tool-call-policy"`` today);
* ``policy_version`` + ``snapshot_token`` -- the reproducibility
  contract (wave-294 design-rule corollary): the trace names the exact
  policy version and content snapshot it was evaluated against, so a
  later verifier can tell whether the policy moved under the decision;
* ``edges`` -- the ordered evaluation edges, each
  ``{seq, layer, rule, outcome, reason}``; ``outcome`` is one of
  ``pass`` (layer evaluated, nothing denied), ``no-match`` (a rule was
  examined and did not match), ``deny``, ``allow``, ``would-deny``
  (audit mode: the call would have been denied, nothing was enforced);
* ``inputs_digests`` -- sha256 digests of the canonical inputs the
  decision ran over (identity, tool, operation, args). Digests, NOT raw
  inputs: a trace must not smuggle arguments (which may carry
  secret-shaped values) into long-lived evidence;
* ``final_decision`` -- ``{verdict, code}`` as emitted;
* ``decided_at`` -- integer unix time (freshness, not a trusted clock);
* a signature over the canonical trace body by the deployment's
  trace-signing key.

``verify_trace`` checks the signature (``decision-trace-forgery`` on a
bad signature, ``decision-trace-invalid`` on a malformed trace) and then
REPLAYS the trace: it folds the ordered edges with the documented
v1 fold rule (the last edge carrying outcome deny/allow/would-deny
decides; no such edge means fail-closed DENY) and compares the folded
verdict to the recorded ``final_decision``. Divergence refuses coded
``decision-trace-replay-mismatch`` -- recomputed evidence disagrees
with the claim, the trace's own critical-class condition. When the
verifier passes ``expected_policy_version`` / ``expected_snapshot_token``,
a trace evaluated against a different version or snapshot also refuses
``decision-trace-replay-mismatch``: the decision is not reproducible
against what the verifier trusts.

Composition, not duplication:
* ``gov/tool_call_policy.py`` emits a trace per ``decide`` when a
  :class:`DecisionTracer` is bound (default ON at bind; documented
  opt-out via ``set_trace_enabled(False)``). Emission is additive: an
  unbound policy decides exactly as before, and a broken tracer can
  never break a decision (F345-class trade-off -- emission failures are
  swallowed and the decision stands).
* key-succession and delegation seams were AUDITED and deliberately NOT
  wired: ``key_succession.verify_envelope`` returns a bare boolean and
  ``delegation_chain.verify`` returns a signed receipt or raises a
  coded ``DelegationError`` -- neither seam produces the ordered
  edge record the trace contract requires, and fabricating edges inside
  their internals would duplicate (and could drift from) their
  evaluation logic. When those seams grow edge-structured decisions,
  they can call :meth:`DecisionTracer.emit` directly; the seam is
  public for exactly that.

Honest boundaries (documented, not hidden):
* the trace-signing key is the trust anchor; key custody is
  deployment-owned (the same posture as every other module key);
* ``decided_at`` is freshness, not a trusted clock;
* a trace proves what the engine CLAIMED to decide, not that the
  decision was correct -- replay checks internal consistency
  (edges => verdict) and version binding, not semantic truth;
* the authn-raise path in ``tool_call_policy.decide`` (unauthenticated
  caller) raises before any decision exists, so no trace is emitted
  there -- the raised coded exception is the evidence at that seam.
"""

import hashlib
import json
import time
import uuid

from gov import ed25519 as _ed25519

TRACE_FORMAT = "sasanam-decision-trace/v1"
REPLAY_RULE_V1 = "last-outcome-edge-wins"

FORGERY = "decision-trace-forgery"
INVALID = "decision-trace-invalid"
REPLAY_MISMATCH = "decision-trace-replay-mismatch"

# Outcomes the v1 fold rule understands.
_DENY_OUTCOMES = frozenset({"deny"})
_ALLOW_OUTCOMES = frozenset({"allow", "would-deny"})

_REQUIRED_BODY_FIELDS = (
    "trace_format", "decision_id", "subsystem", "policy_version",
    "snapshot_token", "replay_rule", "edges", "inputs_digests",
    "final_decision", "decided_at",
)


class DecisionTraceError(Exception):
    """Code-first exception for decision-trace failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise DecisionTraceError(detail, code=code)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _check_str(value, what):
    if not isinstance(value, str) or not value:
        _fail(INVALID, "%s must be a non-empty string; got %r"
              % (what, value,))
    return value


def _check_seed(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(bytes(seed)) != 32:
        _fail(INVALID, "tracer seed must be 32 bytes; got %r"
              % (type(seed),))
    return bytes(seed)


def _digest_inputs(inputs):
    """Digest (not copy) the decision inputs. Refuses LOUD on malformed
    input shapes instead of hashing garbage."""
    if not isinstance(inputs, dict):
        _fail(INVALID, "inputs must be a dict of named inputs; got %r"
              % (type(inputs),))
    digests = {}
    for name, value in inputs.items():
        if not isinstance(name, str) or not name:
            _fail(INVALID, "input names must be non-empty strings; got %r"
                  % (name,))
        try:
            digests[name] = hashlib.sha256(_canonical(value)).hexdigest()
        except Exception as e:  # noqa: BLE001 -- _canonical default=str
            # only fails on truly pathological objects; still coded.
            _fail(INVALID, "input %r is not digestible: %s" % (name, e))
    return digests


def _check_edges(edges):
    if not isinstance(edges, list):
        _fail(INVALID, "edges must be a list; got %r" % (type(edges),))
    seen = set()
    for i, edge in enumerate(edges):
        if not isinstance(edge, dict):
            _fail(INVALID, "edge %d must be a dict; got %r" % (i, edge))
        for field in ("seq", "layer", "rule", "outcome"):
            if field not in edge:
                _fail(INVALID, "edge %d missing field %r" % (i, field))
        seq = edge["seq"]
        if not isinstance(seq, int) or seq < 0 or seq in seen:
            _fail(INVALID, "edge %d has a bad or duplicate seq: %r"
                  % (i, seq))
        seen.add(seq)
        if not isinstance(edge["layer"], str) or not edge["layer"]:
            _fail(INVALID, "edge %d layer must be a non-empty string" % i)
        if not isinstance(edge["rule"], str) or not edge["rule"]:
            _fail(INVALID, "edge %d rule must be a non-empty string" % i)
        outcome = edge["outcome"]
        if outcome not in ("pass", "no-match", "deny", "allow",
                           "would-deny"):
            _fail(INVALID, "edge %d has an unknown outcome: %r" % (i, outcome))
        reason = edge.get("reason")
        if reason is not None and not isinstance(reason, str):
            _fail(INVALID, "edge %d reason must be a string or null" % i)
    ordered = sorted(edges, key=lambda e: e["seq"])
    return [{"seq": e["seq"], "layer": e["layer"], "rule": e["rule"],
             "outcome": e["outcome"], "reason": e.get("reason")}
            for e in ordered]


def fold_edges(edges):
    """The v1 replay rule: the last edge carrying outcome deny/allow/
    would-deny decides; no such edge means fail-closed DENY. Public so
    emitters and tests pin the same rule the verifier uses."""
    verdict = "DENY"  # fail-closed default: no outcome edge => DENY
    for edge in sorted(edges, key=lambda e: e["seq"]):
        outcome = edge["outcome"]
        if outcome in _DENY_OUTCOMES:
            verdict = "DENY"
        elif outcome in _ALLOW_OUTCOMES:
            verdict = "ALLOW"
    return verdict


class DecisionTracer:
    """Signs decision traces for one policy. The 32-byte seed is the
    deployment's trace-signing key material; custody is
    deployment-owned."""

    def __init__(self, seed, policy_version, subsystem="tool-call-policy"):
        self._seed = _check_seed(seed)
        self._pubkey = _ed25519.publickey(self._seed)
        _check_str(policy_version, "policy_version")
        _check_str(subsystem, "subsystem")
        self.policy_version = policy_version
        self.subsystem = subsystem

    @property
    def pubkey_hex(self):
        return self._pubkey.hex()

    def sign_body(self, body):
        """Sign a canonical trace body. Public so tests (and future
        subsystems) can sign deliberately inconsistent bodies to prove
        the replay check catches them."""
        if not isinstance(body, dict):
            _fail(INVALID, "trace body must be a dict; got %r"
                  % (type(body),))
        return _ed25519.sign(self._seed, _canonical(body)).hex()

    def emit(self, decision_id, snapshot_token, edges, inputs,
             final_verdict, final_code=None, decided_at=None):
        """Build and sign one trace envelope. ``inputs`` is the named
        input mapping -- only digests land in the trace, never raw
        values."""
        if not isinstance(decision_id, str) or not decision_id:
            decision_id = uuid.uuid4().hex
        _check_str(snapshot_token, "snapshot_token")
        if final_verdict not in ("ALLOW", "DENY"):
            _fail(INVALID, "final_verdict must be ALLOW or DENY; got %r"
                  % (final_verdict,))
        if final_code is not None and not isinstance(final_code, str):
            _fail(INVALID, "final_code must be a string or null; got %r"
                  % (final_code,))
        body = {
            "trace_format": TRACE_FORMAT,
            "decision_id": decision_id,
            "subsystem": self.subsystem,
            "policy_version": self.policy_version,
            "snapshot_token": snapshot_token,
            "replay_rule": REPLAY_RULE_V1,
            "edges": _check_edges(edges),
            "inputs_digests": _digest_inputs(inputs),
            "final_decision": {"verdict": final_verdict,
                               "code": final_code},
            "decided_at": int(decided_at) if decided_at is not None
            else int(time.time()),
        }
        if body["decided_at"] < 0:
            _fail(INVALID, "decided_at must be non-negative")
        return {"trace": body,
                "signature": self.sign_body(body),
                "keyid": "decision-tracer"}


def verify_trace(envelope, signer_pubkey_hex, expected_policy_version=None,
                 expected_snapshot_token=None):
    """Verify a trace envelope. Returns the trace body on success;
    raises coded :class:`DecisionTraceError` otherwise.

    Checks, in order: shape (``decision-trace-invalid``), signature
    (``decision-trace-forgery``), version/snapshot binding and
    edge=>verdict replay (``decision-trace-replay-mismatch``).
    """
    if not isinstance(envelope, dict):
        _fail(INVALID, "trace envelope must be a dict; got %r"
              % (type(envelope),))
    body = envelope.get("trace")
    signature = envelope.get("signature")
    if not isinstance(body, dict):
        _fail(INVALID, "trace envelope has no trace body dict")
    if not isinstance(signature, str) or not signature:
        _fail(INVALID, "trace envelope has no signature")
    for field in _REQUIRED_BODY_FIELDS:
        if field not in body:
            _fail(INVALID, "trace body missing required field %r" % (field,))
    if body["trace_format"] != TRACE_FORMAT:
        _fail(INVALID, "unknown trace format: %r" % (body["trace_format"],))
    if body["replay_rule"] != REPLAY_RULE_V1:
        _fail(INVALID, "unknown replay rule: %r" % (body["replay_rule"],))
    try:
        pubkey = bytes.fromhex(signer_pubkey_hex)
        sig = bytes.fromhex(signature)
    except (TypeError, ValueError):
        _fail(INVALID, "signer pubkey and signature must be hex strings")
    # gov.ed25519.verify returns exact True/False -- check it, never
    # truthiness (wave-243 lesson).
    if _ed25519.verify(pubkey, _canonical(body), sig) is not True:
        _fail(FORGERY, "trace signature does not verify: the trace is "
                       "forged or was signed by a different key")
    # F371: every shape verify_trace dereferences AFTER the signature
    # check must be validated first. A validly-signed malformed trace
    # (compromised signer or buggy alternate signer) must refuse coded
    # decision-trace-invalid, never crash uncoded. _check_edges is the
    # same validator emit() uses -- reused post-signature, no second
    # validation language.
    final_decision = body["final_decision"]
    if not isinstance(final_decision, dict):
        _fail(INVALID, "final_decision must be a dict; got %r"
              % (type(final_decision),))
    if "verdict" not in final_decision:
        _fail(INVALID, "final_decision missing required key 'verdict'")
    edges = _check_edges(body["edges"])
    if expected_policy_version is not None and \
            body["policy_version"] != expected_policy_version:
        _fail(REPLAY_MISMATCH,
              "trace was evaluated against policy version %r, not the "
              "expected %r: not reproducible against the trusted version"
              % (body["policy_version"], expected_policy_version))
    if expected_snapshot_token is not None and \
            body["snapshot_token"] != expected_snapshot_token:
        _fail(REPLAY_MISMATCH,
              "trace snapshot token does not match the expected token: "
              "the policy moved under this decision")
    replayed = fold_edges(edges)
    if replayed != final_decision["verdict"]:
        _fail(REPLAY_MISMATCH,
              "replay divergence: the ordered edges fold to %s but the "
              "trace records %s -- recomputed evidence disagrees with "
              "the claim"
              % (replayed, final_decision["verdict"]))
    return body
